package security

import (
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/loader"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/modzip"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/semver"
	"github.com/slash-mark-dev/go-suite/internal/ui"
)

// CapEvidence explains why a package has a capability.
type CapEvidence struct {
	Capability string `json:"capability"`
	// APIs are the distinct standard library (or x/sys) APIs used, sorted;
	// "import \"unsafe\"" / "import \"C\"" for import-level capabilities.
	APIs []string `json:"apis"`
	// Uses counts references in the package.
	Uses int `json:"uses"`
	// First is the earliest reference.
	First string `json:"first"`
	Pos   string `json:"pos,omitempty"`
}

// PackageCaps is the capability set of one package.
type PackageCaps struct {
	Package      string        `json:"package"`
	Module       string        `json:"module"`
	Version      string        `json:"version,omitempty"`
	Capabilities []string      `json:"capabilities"`
	Evidence     []CapEvidence `json:"evidence"`
}

// ModuleCaps is the union of the capabilities of a module's packages.
type ModuleCaps struct {
	Module       string   `json:"module"`
	Version      string   `json:"version,omitempty"`
	Capabilities []string `json:"capabilities"`
	Packages     int      `json:"packages"`
	// ByCapability lists, per capability, the packages that have it.
	ByCapability map[string][]string `json:"byCapability"`
}

// CapsResult is the result of a project capability scan.
type CapsResult struct {
	Mode     string           `json:"mode"` // "project"
	Modules  []*ModuleCaps    `json:"modules"`
	Packages []*PackageCaps   `json:"packages"`
	Totals   map[string]int   `json:"totals"` // capability -> number of modules
	Denied   []string         `json:"denied,omitempty"`
	Findings []report.Finding `json:"findings"`
	Failing  int              `json:"failing"`
}

// CapChange is a capability added or removed by an upgrade.
type CapChange struct {
	Capability  string          `json:"capability"`
	Severity    report.Severity `json:"severity"`
	Description string          `json:"description"`
	// Packages of the upgraded module that gained (or lost) it, with
	// evidence from the new (or old) version.
	Packages []*PackageCaps `json:"packages,omitempty"`
	// Via lists dependency modules ("path@version") that bring the
	// capability into the upgraded module's dependency closure.
	Via []string `json:"via,omitempty"`
}

// CapsDiffResult is the result of --diff / --upgrade.
type CapsDiffResult struct {
	Mode   string      `json:"mode"` // "diff"
	Module string      `json:"module"`
	From   string      `json:"from"`
	To     string      `json:"to"`
	Old    *ModuleCaps `json:"old"`
	New    *ModuleCaps `json:"new"`
	// Added/Removed compare the module's own packages.
	Added   []*CapChange `json:"added"`
	Removed []*CapChange `json:"removed"`
	// AddedViaDependencies are capabilities the new version's dependency
	// closure has that the old one did not.
	AddedViaDependencies []*CapChange `json:"addedViaDependencies"`
	// NewDependencies are modules in the new closure that were not in the
	// old one.
	NewDependencies []string         `json:"newDependencies"`
	Findings        []report.Finding `json:"findings"`
	Failing         int              `json:"failing"`
}

var capsFlags struct {
	diff, upgrade, tags *string
	deny                cli.StringList
	packages, tests     *bool
	failOn              func() (report.Severity, error)
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "caps",
		Group:   group,
		Summary: "Capability analysis of dependencies and of upgrades",
		Usage:   "sm-go caps [packages] [--diff mod@old..new | --upgrade mod@version] [flags]",
		Help: `Type-checks every dependency package and records which sensitive capabilities its code
uses, from references to standard library (and golang.org/x/sys) APIs and from imports:

  exec       os/exec, os.StartProcess, syscall.Exec/ForkExec
  network    net Dial/Listen/Lookup, net/http clients and servers, net/rpc, net/smtp, crypto/tls
  cgo        import "C" (also found in files excluded by CGO_ENABLED=0)
  unsafe     import "unsafe"
  plugin     plugin.Open and friends
  syscall    raw system calls (syscall, golang.org/x/sys/unix, golang.org/x/sys/windows)
  filesystem os file and directory APIs, io/ioutil, filepath.Walk/Glob
  reflect    reflective calls and pointer forging (Value.Call, MethodByName, NewAt, ...)
  env        os.Getenv/LookupEnv/Environ/Setenv, user directories
  runtime    os/signal, os.Exit, process signalling, runtime/debug settings

Capabilities are reported per module and per package with the APIs used. With --deny,
dependencies using a denied capability fail the run.

--diff mod@vOld..vNew (no project needed) and --upgrade mod@version (against the version your
build list selects; "latest" is accepted) analyse both versions of the module and report the
capabilities the upgrade adds — the key supply-chain signal: a logging library that suddenly
imports os/exec or net deserves a review. Capabilities added through new or changed
dependencies of the module are reported separately. Added capabilities at or above
--fail-on fail the run.`,
		Examples: []string{
			"sm-go caps",
			"sm-go caps --packages --json",
			"sm-go caps --deny exec,plugin,cgo",
			"sm-go caps --upgrade github.com/sirupsen/logrus@latest",
			"sm-go caps --diff golang.org/x/text@v0.14.0..v0.21.0",
		},
		Sources: []string{"Go module proxy", "module source (type-checked)"},
		NeedsGo: true,
		Flags: func(fs *flag.FlagSet) {
			capsFlags.deny = nil
			capsFlags.diff = fs.String("diff", "", "compare two versions: `mod@vOld..vNew`")
			capsFlags.upgrade = fs.String("upgrade", "", "compare the selected version of a module with `mod@version`")
			fs.Var(&capsFlags.deny, "deny", "fail if a dependency uses one of these `capabilities` (comma-separated)")
			capsFlags.packages = fs.Bool("packages", false, "list every package with its evidence")
			capsFlags.tests = fs.Bool("tests", false, "include test dependencies")
			capsFlags.tags = fs.String("tags", "", "comma-separated build `tags`")
			capsFlags.failOn = cli.SeverityFlag(fs, "fail-on", "medium", "minimum `severity` of an added capability that fails the run")
		},
		Run: runCaps,
	})
}

func runCaps(c *cli.Context) error {
	failOn, err := capsFlags.failOn()
	if err != nil {
		return err
	}
	for _, d := range capsFlags.deny {
		if _, ok := capInfo[d]; !ok {
			return cli.Usagef("--deny: unknown capability %q (known: %s)", d, strings.Join(capOrder, ", "))
		}
	}
	if *capsFlags.diff != "" && *capsFlags.upgrade != "" {
		return cli.Usagef("--diff and --upgrade are mutually exclusive")
	}
	if *capsFlags.diff != "" || *capsFlags.upgrade != "" {
		if len(c.Args) > 0 {
			return cli.Usagef("package patterns cannot be combined with --diff/--upgrade")
		}
		path, from, to, err := capsDiffTarget(c)
		if err != nil {
			return err
		}
		res, err := DiffCaps(c, path, from, to)
		if err != nil {
			return err
		}
		for i := range res.Findings {
			if res.Findings[i].Severity.Meets(failOn) {
				res.Failing++
			}
		}
		c.SetResult(res)
		if res.Failing > 0 {
			c.Issues()
		}
		if c.Text() {
			printCapsDiff(c, res, failOn)
		}
		return nil
	}

	pats := c.Args
	if len(pats) == 0 {
		pats = []string{"./..."}
	}
	prog, err := c.Load(loader.Config{Patterns: pats, Tests: *capsFlags.tests, Tags: splitTags(*capsFlags.tags), TypeCheck: true,
		SkipBodies: func(p *loader.Package) bool { return p.Standard }})
	if err != nil {
		return err
	}
	warnLoad(c, prog)
	if len(prog.Roots) == 0 {
		return cli.Usagef("no packages matched %s", strings.Join(pats, " "))
	}
	pf := newPosFormatter(c, prog, projectDir(c))
	pkgs := AnalyzeCaps(prog, pf, func(p *loader.Package) bool { return !p.Standard && !p.InMainModule() })
	res := &CapsResult{Mode: "project", Packages: pkgs, Modules: rollupCaps(pkgs), Totals: map[string]int{}, Denied: capsFlags.deny, Findings: []report.Finding{}}
	deny := map[string]bool{}
	for _, d := range capsFlags.deny {
		deny[d] = true
	}
	for _, m := range res.Modules {
		for _, cp := range m.Capabilities {
			res.Totals[cp]++
			if deny[cp] {
				res.Findings = append(res.Findings, report.Finding{Severity: report.High, Rule: "caps/denied", Module: m.Module, Version: m.Version,
					Title:  fmt.Sprintf("uses denied capability %s", cp),
					Detail: fmt.Sprintf("%s: %s", capInfo[cp].Desc, strings.Join(m.ByCapability[cp], ", ")),
					Data:   map[string]any{"capability": cp, "packages": m.ByCapability[cp]}})
			}
		}
	}
	report.SortFindings(res.Findings)
	res.Failing = len(res.Findings)
	c.SetResult(res)
	if res.Failing > 0 {
		c.Issues()
	}
	if c.Text() {
		printCaps(c, res, *capsFlags.packages)
	}
	return nil
}

func warnLoad(c *cli.Context, prog *loader.Program) {
	for i, e := range prog.Errors {
		if i == 3 {
			c.Warnf("… and %d more package loading problems", len(prog.Errors)-3)
			break
		}
		c.Warnf("%s", e)
	}
}

// capsDiffTarget parses --diff or resolves --upgrade.
func capsDiffTarget(c *cli.Context) (path, from, to string, err error) {
	if d := *capsFlags.diff; d != "" {
		at := strings.LastIndex(d, "@")
		if at <= 0 {
			return "", "", "", cli.Usagef("--diff: want mod@vOld..vNew, got %q", d)
		}
		path = d[:at]
		from, to, ok := strings.Cut(d[at+1:], "..")
		if !ok {
			return "", "", "", cli.Usagef("--diff: want mod@vOld..vNew, got %q", d)
		}
		to = strings.TrimPrefix(to, path+"@")
		if err := module.CheckPath(path); err != nil {
			return "", "", "", cli.Usagef("--diff: %v", err)
		}
		for _, v := range []string{from, to} {
			if !semver.IsValid(v) {
				return "", "", "", cli.Usagef("--diff: %q is not a semantic version", v)
			}
		}
		if from == to {
			return "", "", "", cli.Usagef("--diff: both versions are %s", from)
		}
		return path, from, to, nil
	}
	u := *capsFlags.upgrade
	at := strings.LastIndex(u, "@")
	if at <= 0 {
		return "", "", "", cli.Usagef("--upgrade: want mod@version, got %q", u)
	}
	path, to = u[:at], u[at+1:]
	g, err := c.Graph()
	if err != nil {
		return "", "", "", err
	}
	from = g.Version(path)
	if from == "" || g.IsMain(path) {
		return "", "", "", cli.Usagef("--upgrade: %s is not in the build list", path)
	}
	if to == "latest" {
		to, err = c.Proxy().QueryLatest(c.Ctx, path)
		if err != nil {
			return "", "", "", fmt.Errorf("resolving %s@latest: %w", path, err)
		}
	} else if !semver.IsValid(to) {
		return "", "", "", cli.Usagef("--upgrade: %q is not a semantic version or \"latest\"", to)
	}
	if to == from {
		return "", "", "", cli.Usagef("--upgrade: %s@%s is already selected", path, to)
	}
	return path, from, to, nil
}

// AnalyzeCaps computes capabilities for every type-checked package for
// which include returns true.
func AnalyzeCaps(prog *loader.Program, pf *posFormatter, include func(*loader.Package) bool) []*PackageCaps {
	var out []*PackageCaps
	for _, p := range prog.Packages {
		if p.Info == nil || !include(p) {
			continue
		}
		pc := &PackageCaps{Package: p.ImportPath, Module: p.ModulePath(), Version: p.ModuleVersion(), Capabilities: []string{}, Evidence: []CapEvidence{}}
		type ev struct {
			apis  map[string]bool
			uses  int
			first token.Pos
			api   string
		}
		evs := map[string]*ev{}
		note := func(cp, api string, pos token.Pos) {
			e := evs[cp]
			if e == nil {
				e = &ev{apis: map[string]bool{}}
				evs[cp] = e
			}
			e.apis[api] = true
			e.uses++
			if e.first == token.NoPos || (pos.IsValid() && pos < e.first) {
				e.first, e.api = pos, api
			}
		}
		for _, f := range p.Syntax {
			for _, im := range f.Imports {
				switch path, _ := strconv.Unquote(im.Path.Value); path {
				case "unsafe":
					note(CapUnsafe, `import "unsafe"`, im.Pos())
				case "C":
					note(CapCgo, `import "C"`, im.Pos())
				}
			}
		}
		// Cgo files dropped by CGO_ENABLED=0 (or a cross build) are listed
		// as ignored; the capability exists in other configurations.
		if !hasCap(evs, CapCgo) {
			if pos, ok := ignoredCgo(prog.Fset, p); ok {
				note(CapCgo, `import "C"`, pos)
			}
		}
		for id, obj := range p.Info.Uses {
			for _, cp := range objCaps(obj) {
				note(cp, objKey(obj), id.Pos())
			}
		}
		for cp, e := range evs {
			pc.Capabilities = append(pc.Capabilities, cp)
			var apis []string
			for a := range e.apis {
				apis = append(apis, a)
			}
			sort.Strings(apis)
			pc.Evidence = append(pc.Evidence, CapEvidence{Capability: cp, APIs: apis, Uses: e.uses, First: e.api, Pos: pf.pos(e.first)})
		}
		sortCaps(pc.Capabilities)
		sort.Slice(pc.Evidence, func(i, j int) bool { return capRank(pc.Evidence[i].Capability) < capRank(pc.Evidence[j].Capability) })
		out = append(out, pc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Package < out[j].Package })
	return out
}

func hasCap[T any](m map[string]T, cp string) bool { _, ok := m[cp]; return ok }

// ignoredCgo reports whether one of p's ignored files imports "C".
func ignoredCgo(fset *token.FileSet, p *loader.Package) (token.Pos, bool) {
	for _, name := range p.IgnoredGoFiles {
		fn := name
		if !filepath.IsAbs(fn) {
			fn = filepath.Join(p.Dir, name)
		}
		f, err := parser.ParseFile(fset, fn, nil, parser.ImportsOnly)
		if err != nil || f == nil {
			continue
		}
		if f.Name.Name != p.Name {
			continue
		}
		for _, im := range f.Imports {
			if im.Path.Value == `"C"` {
				return im.Pos(), true
			}
		}
	}
	return token.NoPos, false
}

// rollupCaps groups package results by module.
func rollupCaps(pkgs []*PackageCaps) []*ModuleCaps {
	by := map[string]*ModuleCaps{}
	var order []string
	for _, p := range pkgs {
		key := p.Module + "@" + p.Version
		m := by[key]
		if m == nil {
			m = &ModuleCaps{Module: p.Module, Version: p.Version, Capabilities: []string{}, ByCapability: map[string][]string{}}
			by[key] = m
			order = append(order, key)
		}
		m.Packages++
		for _, cp := range p.Capabilities {
			if len(m.ByCapability[cp]) == 0 {
				m.Capabilities = append(m.Capabilities, cp)
			}
			m.ByCapability[cp] = append(m.ByCapability[cp], p.Package)
		}
	}
	sort.Strings(order)
	out := make([]*ModuleCaps, 0, len(order))
	for _, k := range order {
		sortCaps(by[k].Capabilities)
		out = append(out, by[k])
	}
	return out
}

// moduleVersionProgram downloads path@version from the module proxy,
// extracts it to a temporary directory and loads it as a main module.
func moduleVersionProgram(c *cli.Context, path, version string) (*loader.Program, string, func(), error) {
	data, err := c.Proxy().Zip(c.Ctx, path, version)
	if err != nil {
		return nil, "", nil, fmt.Errorf("downloading %s@%s: %w", path, version, err)
	}
	z, err := modzip.Open(data, path, version)
	if err != nil {
		return nil, "", nil, fmt.Errorf("%s@%s: %w", path, version, err)
	}
	dir, err := os.MkdirTemp("", "smgo-caps-")
	if err != nil {
		return nil, "", nil, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real // go list reports resolved directories
	}
	if err := z.Extract(dir); err != nil {
		cleanup()
		return nil, "", nil, err
	}
	if !z.Has("go.mod") {
		// Pre-module versions have no go.mod; the proxy synthesizes one.
		gomod, err := c.Proxy().GoMod(c.Ctx, path, version)
		if err != nil {
			gomod = []byte("module " + path + "\n")
		}
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), gomod, 0o644); err != nil {
			cleanup()
			return nil, "", nil, err
		}
	}
	flags := strings.TrimSpace(c.Env.Get("GOFLAGS") + " -mod=mod")
	prog, err := c.Load(loader.Config{Dir: dir, Patterns: []string{"./..."}, TypeCheck: true,
		SkipBodies: func(p *loader.Package) bool { return p.Standard },
		ExtraEnv:   []string{"GOFLAGS=" + flags, "GOWORK=off"}})
	if err != nil {
		cleanup()
		return nil, "", nil, fmt.Errorf("loading %s@%s: %w", path, version, err)
	}
	return prog, dir, cleanup, nil
}

// versionCaps analyses one version: the module's own packages (with the
// module version filled in) and its dependency closure by module.
func versionCaps(c *cli.Context, path, version string) (own []*PackageCaps, deps []*ModuleCaps, closure map[string]string, err error) {
	prog, dir, cleanup, err := moduleVersionProgram(c, path, version)
	if err != nil {
		return nil, nil, nil, err
	}
	defer cleanup()
	for _, e := range prog.Errors {
		c.Logf("%s@%s: %s", path, version, e)
	}
	pf := newPosFormatter(c, prog, dir)
	pf.prefix = path + "@" + version
	all := AnalyzeCaps(prog, pf, func(p *loader.Package) bool { return !p.Standard })
	closure = map[string]string{}
	var depPkgs []*PackageCaps
	for _, p := range all {
		if p.Module == path && p.Version == "" {
			p.Version = version
			own = append(own, p)
			continue
		}
		depPkgs = append(depPkgs, p)
	}
	for _, p := range prog.Packages {
		if !p.Standard && p.Module != nil && !p.Module.Main {
			closure[p.Module.Path] = p.Module.Version
		}
	}
	return own, rollupCaps(depPkgs), closure, nil
}

// DiffCaps compares the capabilities of path@from and path@to.
func DiffCaps(c *cli.Context, path, from, to string) (*CapsDiffResult, error) {
	oldOwn, oldDeps, oldClosure, err := versionCaps(c, path, from)
	if err != nil {
		return nil, err
	}
	newOwn, newDeps, newClosure, err := versionCaps(c, path, to)
	if err != nil {
		return nil, err
	}
	res := &CapsDiffResult{Mode: "diff", Module: path, From: from, To: to, Added: []*CapChange{}, Removed: []*CapChange{},
		AddedViaDependencies: []*CapChange{}, NewDependencies: []string{}, Findings: []report.Finding{}}
	res.Old = moduleOf(path, from, oldOwn)
	res.New = moduleOf(path, to, newOwn)
	oldSet, newSet := capSet(res.Old.Capabilities), capSet(res.New.Capabilities)
	for _, cp := range res.New.Capabilities {
		if oldSet[cp] {
			continue
		}
		ch := &CapChange{Capability: cp, Severity: capInfo[cp].Severity, Description: capInfo[cp].Desc}
		for _, p := range newOwn {
			if hasStr(p.Capabilities, cp) {
				ch.Packages = append(ch.Packages, onlyCap(p, cp))
			}
		}
		res.Added = append(res.Added, ch)
		var where []string
		for _, p := range ch.Packages {
			where = append(where, fmt.Sprintf("%s (%s at %s)", p.Package, p.Evidence[0].First, p.Evidence[0].Pos))
		}
		res.Findings = append(res.Findings, report.Finding{Severity: ch.Severity, Rule: "caps/added", Module: path, Version: to,
			Title:  fmt.Sprintf("%s → %s adds capability %s", from, to, cp),
			Detail: capInfo[cp].Desc + "\n" + strings.Join(where, "\n"),
			Fix:    fmt.Sprintf("review the change before upgrading: https://pkg.go.dev/%s@%s", path, to),
			Data:   map[string]any{"capability": cp}})
	}
	for _, cp := range res.Old.Capabilities {
		if newSet[cp] {
			continue
		}
		ch := &CapChange{Capability: cp, Severity: report.Info, Description: capInfo[cp].Desc}
		for _, p := range oldOwn {
			if hasStr(p.Capabilities, cp) {
				ch.Packages = append(ch.Packages, onlyCap(p, cp))
			}
		}
		res.Removed = append(res.Removed, ch)
	}
	// Dependency closure.
	oldDepCaps := map[string]bool{}
	for _, m := range oldDeps {
		for _, cp := range m.Capabilities {
			oldDepCaps[cp] = true
		}
	}
	via := map[string][]string{}
	for _, m := range newDeps {
		for _, cp := range m.Capabilities {
			if !oldDepCaps[cp] && !newSet[cp] {
				via[cp] = append(via[cp], m.Module+"@"+m.Version)
			}
		}
	}
	for _, cp := range capOrder {
		if len(via[cp]) == 0 {
			continue
		}
		sev := capInfo[cp].Severity - 1
		if sev < report.Low {
			sev = report.Low
		}
		res.AddedViaDependencies = append(res.AddedViaDependencies, &CapChange{Capability: cp, Severity: sev, Description: capInfo[cp].Desc, Via: via[cp]})
		res.Findings = append(res.Findings, report.Finding{Severity: sev, Rule: "caps/added-via-dependency", Module: path, Version: to,
			Title:  fmt.Sprintf("%s → %s brings capability %s through dependencies", from, to, cp),
			Detail: capInfo[cp].Desc + "\nvia " + strings.Join(via[cp], ", "),
			Data:   map[string]any{"capability": cp, "via": via[cp]}})
	}
	for p, v := range newClosure {
		if _, ok := oldClosure[p]; !ok {
			res.NewDependencies = append(res.NewDependencies, p+"@"+v)
		}
	}
	sort.Strings(res.NewDependencies)
	report.SortFindings(res.Findings)
	return res, nil
}

func moduleOf(path, version string, own []*PackageCaps) *ModuleCaps {
	ms := rollupCaps(own)
	if len(ms) == 0 {
		return &ModuleCaps{Module: path, Version: version, Capabilities: []string{}, ByCapability: map[string][]string{}}
	}
	return ms[0]
}

func capSet(cs []string) map[string]bool {
	m := map[string]bool{}
	for _, c := range cs {
		m[c] = true
	}
	return m
}

// onlyCap returns a copy of p restricted to one capability's evidence.
func onlyCap(p *PackageCaps, cp string) *PackageCaps {
	q := &PackageCaps{Package: p.Package, Module: p.Module, Version: p.Version, Capabilities: []string{cp}}
	for _, e := range p.Evidence {
		if e.Capability == cp {
			q.Evidence = append(q.Evidence, e)
		}
	}
	return q
}

func printCaps(c *cli.Context, res *CapsResult, packages bool) {
	o := c.Out
	subject := "."
	if p, err := c.Project(); err == nil && p.ModulePath() != "" {
		subject = p.ModulePath()
	}
	o.Title("sm-go caps · " + subject)
	o.Printf("%s\n", o.Dim(fmt.Sprintf("%s · %s analysed (type-checked)", ui.Plural(len(res.Modules), "dependency module", "dependency modules"),
		ui.Plural(len(res.Packages), "package", "packages"))))
	var rows [][]string
	quiet := 0
	for _, m := range res.Modules {
		if len(m.Capabilities) == 0 {
			quiet++
			continue
		}
		var cs []string
		for _, cp := range m.Capabilities {
			cs = append(cs, capLabel(o, cp))
		}
		rows = append(rows, []string{m.Module, m.Version, strings.Join(cs, " ")})
	}
	o.Heading("Capabilities by module")
	if len(rows) == 0 {
		o.OK("no dependency uses a sensitive capability")
	} else {
		o.Table([]string{"MODULE", "VERSION", "CAPABILITIES"}, rows)
	}
	if quiet > 0 {
		o.Printf("%s\n", o.Dim(fmt.Sprintf("%s without sensitive capabilities", ui.Plural(quiet, "module", "modules"))))
	}
	if packages {
		o.Heading("Packages")
		for _, p := range res.Packages {
			if len(p.Capabilities) == 0 {
				continue
			}
			o.Printf("  %s\n", o.Bold(p.Package))
			for _, e := range p.Evidence {
				o.Printf("    %-10s %s %s\n", e.Capability, ui.Truncate(strings.Join(e.APIs, ", "), 70), o.Dim(e.Pos))
			}
		}
	}
	var tot []string
	for _, cp := range capOrder {
		if n := res.Totals[cp]; n > 0 {
			tot = append(tot, fmt.Sprintf("%s %d", cp, n))
		}
	}
	if len(res.Findings) > 0 {
		o.Heading(fmt.Sprintf("Denied capabilities (%d)", len(res.Findings)))
		printFindings(c, res.Findings)
	}
	o.Println()
	if len(tot) == 0 {
		tot = []string{"none"}
	}
	o.Printf("%s modules per capability: %s\n", o.Bold("Summary:"), strings.Join(tot, " · "))
}

func capLabel(o *ui.Printer, cp string) string {
	switch capInfo[cp].Severity {
	case report.High:
		return o.Red(cp)
	case report.Medium:
		return o.Yellow(cp)
	}
	return cp
}

func printCapsDiff(c *cli.Context, res *CapsDiffResult, failOn report.Severity) {
	o := c.Out
	o.Title(fmt.Sprintf("sm-go caps · %s %s → %s", res.Module, res.From, res.To))
	show := func(cs []string) string {
		if len(cs) == 0 {
			return "none"
		}
		return strings.Join(cs, ", ")
	}
	o.KV([2]string{res.From, show(res.Old.Capabilities)}, [2]string{res.To, show(res.New.Capabilities)})
	o.Heading(fmt.Sprintf("Added capabilities (%d)", len(res.Added)))
	if len(res.Added) == 0 {
		o.OK("the upgrade adds no capability to %s", res.Module)
	}
	for _, ch := range res.Added {
		o.Printf("  %s %s  %s\n", o.Sev(ch.Severity), o.Bold(ch.Capability), o.Dim(ch.Description))
		for _, p := range ch.Packages {
			for _, e := range p.Evidence {
				o.Printf("           %s: %s %s\n", p.Package, strings.Join(e.APIs, ", "), o.Dim(e.Pos))
			}
		}
	}
	if len(res.Removed) > 0 {
		o.Heading(fmt.Sprintf("Removed capabilities (%d)", len(res.Removed)))
		for _, ch := range res.Removed {
			o.Printf("  %s %s\n", o.Green("-"), ch.Capability)
		}
	}
	if len(res.AddedViaDependencies) > 0 {
		o.Heading(fmt.Sprintf("Added through dependencies (%d)", len(res.AddedViaDependencies)))
		for _, ch := range res.AddedViaDependencies {
			o.Printf("  %s %s  via %s\n", o.Sev(ch.Severity), o.Bold(ch.Capability), strings.Join(ch.Via, ", "))
		}
	}
	if len(res.NewDependencies) > 0 {
		o.Printf("\n%s %s\n", o.Bold("New dependencies:"), strings.Join(res.NewDependencies, ", "))
	}
	o.Println()
	if res.Failing > 0 {
		o.Bad("%s at or above %s", ui.Plural(res.Failing, "capability change", "capability changes"), failOn)
	} else {
		o.OK("no capability change at or above %s", failOn)
	}
}
