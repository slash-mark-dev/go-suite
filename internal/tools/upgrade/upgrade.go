package upgrade

import (
	"errors"
	"flag"
	"fmt"
	"sort"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/apidiff"
	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/loader"
	"github.com/slash-mark-dev/go-suite/internal/modgraph"
	"github.com/slash-mark-dev/go-suite/internal/modproxy"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/project"
	"github.com/slash-mark-dev/go-suite/internal/semver"
	"github.com/slash-mark-dev/go-suite/internal/vulnscan"
)

var upgradeFlags struct {
	noAPI   *bool
	noVulns *bool
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "upgrade",
		Group:   group,
		Summary: "Upgrade simulator: what `go get module@version` would change, before you run it",
		Usage:   "sm-go upgrade <module@version>... [flags]",
		Help: `Simulates 'go get' on the current module without touching go.mod: the new
build list is computed with Minimum Version Selection (graph pruning,
excludes and replacements included), and requested downgrades (or
module@none removals) downgrade the requirements that force a higher
version, as the go command does.

For the request it reports every module that moves up or down, modules
newly added to (or dropped from) the build list, and whether the go
directive has to be raised (and the toolchain line the go command would
write, or whether GOTOOLCHAIN prevents the upgrade). For every moved module
it checks retractions and deprecations, the vulnerabilities fixed and
introduced (Go vulnerability database) and, for modules whose packages the
project imports, the incompatible API changes between the two versions
restricted to the packages you use, with the file:line of every affected
reference.

Versions may be exact (v1.2.3), latest, upgrade (latest compatible), patch
or none. Exit code 1 means the upgrade introduces a retracted version, a
vulnerability, an API break in code you use, or cannot be applied.`,
		Examples: []string{
			"sm-go upgrade golang.org/x/net@latest",
			"sm-go upgrade github.com/spf13/cobra@v1.8.0 github.com/spf13/pflag@upgrade",
			"sm-go upgrade example.com/lib@v1.1.0 --no-api --json",
		},
		Sources: []string{"Go module proxy", "Go vulnerability database"},
		Flags: func(fs *flag.FlagSet) {
			upgradeFlags.noAPI = fs.Bool("no-api", false, "skip the API compatibility check (no type-checking)")
			upgradeFlags.noVulns = fs.Bool("no-vulns", false, "skip the vulnerability database")
		},
		Run: runUpgrade,
	})
}

// UpgradeRequest is one module@version argument.
type UpgradeRequest struct {
	Path    string `json:"path"`
	Query   string `json:"query"`
	Version string `json:"version"`
	From    string `json:"from,omitempty"`
}

// VulnRef is a vulnerability fixed or introduced by a move.
type VulnRef struct {
	ID       string `json:"id"`
	Summary  string `json:"summary,omitempty"`
	Severity string `json:"severity"`
	FixedIn  string `json:"fixedIn,omitempty"`
	URL      string `json:"url,omitempty"`
}

// APIBreak is an incompatible change in a package the project imports.
type APIBreak struct {
	apidiff.Change
	// UsedAt lists the references in the project that the change breaks;
	// empty if the project does not refer to the changed object.
	UsedAt []string `json:"usedAt"`
}

// ModuleChange is a module whose selected version changes.
type ModuleChange struct {
	Path            string     `json:"path"`
	From            string     `json:"from,omitempty"` // "" if newly added
	To              string     `json:"to,omitempty"`   // "" if removed
	Kind            string     `json:"kind"`           // upgrade, downgrade, added, removed
	Bump            string     `json:"bump,omitempty"` // major, minor, patch, prerelease
	Requested       bool       `json:"requested"`
	Direct          bool       `json:"direct"`
	Retracted       bool       `json:"retracted"`
	RetractReason   string     `json:"retractReason,omitempty"`
	Deprecated      string     `json:"deprecated,omitempty"`
	VulnsFixed      []VulnRef  `json:"vulnsFixed"`
	VulnsIntroduced []VulnRef  `json:"vulnsIntroduced"`
	UsedPackages    []string   `json:"usedPackages,omitempty"`
	APIChecked      bool       `json:"apiChecked"`
	APIBreaks       []APIBreak `json:"apiBreaks"`
	APIAdditions    int        `json:"apiAdditions"`
	Affected        int        `json:"affectedReferences"`
}

// GoChange describes the go and toolchain directive changes.
type GoChange struct {
	From          string `json:"from"`
	To            string `json:"to"`
	RequiredBy    string `json:"requiredBy,omitempty"`
	ToolchainFrom string `json:"toolchainFrom,omitempty"`
	ToolchainTo   string `json:"toolchainTo,omitempty"`
	LocalGo       string `json:"localGo,omitempty"`
	GOTOOLCHAIN   string `json:"gotoolchain,omitempty"`
	// Blocked is set when the local toolchain is too old and GOTOOLCHAIN
	// does not allow switching: 'go get' fails.
	Blocked bool   `json:"blocked"`
	Switch  string `json:"switch,omitempty"` // toolchain the go command would switch to
}

// UpgradeResult is the JSON result of upgrade.
type UpgradeResult struct {
	Module    string           `json:"module"`
	Requests  []UpgradeRequest `json:"requests"`
	Command   string           `json:"command"`
	Changes   []ModuleChange   `json:"changes"`
	Go        GoChange         `json:"go"`
	BuildList []string         `json:"buildList"` // path@version after the upgrade (like go list -m all)
	Before    int              `json:"modulesBefore"`
	After     int              `json:"modulesAfter"`
	Problems  []string         `json:"problems"`
}

func runUpgrade(c *cli.Context) error {
	if len(c.Args) == 0 {
		return cli.Usagef("want at least one module@version")
	}
	p, err := c.Project()
	if err != nil {
		if errors.Is(err, project.ErrNoModule) {
			return cli.Usagef("%v", err)
		}
		return err
	}
	g, err := c.Graph()
	if err != nil {
		return err
	}
	res := &UpgradeResult{Module: p.ModulePath(), Changes: []ModuleChange{}, Problems: []string{}}
	targets := map[string]string{}
	var order []string
	for _, a := range c.Args {
		path, q, err := splitArg(a)
		if err != nil {
			return err
		}
		if g.IsMain(path) {
			return cli.Usagef("%s is a main module", path)
		}
		if _, dup := targets[path]; dup {
			return cli.Usagef("%s requested twice", path)
		}
		cur := g.Version(path)
		v, err := resolveQuery(c, path, q, cur)
		if err != nil {
			return err
		}
		if v != "none" {
			if _, err := c.Proxy().GoMod(c.Ctx, path, v); err != nil {
				if errors.Is(err, modproxy.ErrNotFound) {
					return cli.Usagef("%s@%s: no such module version", path, v)
				}
				return err
			}
		}
		if q == "" {
			q = "latest"
		}
		targets[path] = v
		order = append(order, path)
		res.Requests = append(res.Requests, UpgradeRequest{Path: path, Query: q, Version: v, From: cur})
	}
	var cmd []string
	for _, r := range res.Requests {
		cmd = append(cmd, r.Path+"@"+r.Version)
	}
	res.Command = "go get " + strings.Join(cmd, " ")

	ng, err := simulateGet(c, p, g, targets, order)
	if err != nil {
		var ce *conflictError
		if errors.As(err, &ce) {
			res.Problems = append(res.Problems, ce.Error())
			c.SetResult(res)
			c.Issues()
			if c.Text() {
				c.Out.Title("Upgrade simulation: " + res.Command)
				c.Out.Bad("%s", ce.Error())
			}
			return nil
		}
		return err
	}

	// Moved modules.
	paths := map[string]bool{}
	for p := range g.Selected {
		paths[p] = true
	}
	for p := range ng.Selected {
		paths[p] = true
	}
	var sorted []string
	for p := range paths {
		if !g.IsMain(p) {
			sorted = append(sorted, p)
		}
	}
	sort.Strings(sorted)
	for _, path := range sorted {
		from, to := g.Selected[path], ng.Selected[path]
		if from == to {
			continue
		}
		mc := ModuleChange{Path: path, From: from, To: to, VulnsFixed: []VulnRef{}, VulnsIntroduced: []VulnRef{}, APIBreaks: []APIBreak{}}
		_, mc.Requested = targets[path]
		mc.Direct = ng.IsDirect(path) || g.IsDirect(path)
		switch {
		case from == "":
			mc.Kind = "added"
		case to == "":
			mc.Kind = "removed"
		case semver.Compare(to, from) > 0:
			mc.Kind = "upgrade"
			mc.Bump = semverBump(from, to)
		default:
			mc.Kind = "downgrade"
			mc.Bump = semverBump(to, from)
		}
		res.Changes = append(res.Changes, mc)
	}
	for _, m := range ng.BuildList() {
		res.BuildList = append(res.BuildList, m.String())
	}
	res.Before, res.After = len(g.BuildList()), len(ng.BuildList())

	// Retractions and deprecations of the versions moved to.
	for i := range res.Changes {
		mc := &res.Changes[i]
		if mc.To == "" {
			continue
		}
		meta, err := c.Proxy().Meta(c.Ctx, mc.Path)
		if err != nil {
			if meta == nil {
				return err
			}
			c.Warnf("%s: %v", mc.Path, err)
		}
		mc.Retracted, mc.RetractReason = meta.Retracted(mc.To)
		mc.Deprecated = meta.Deprecated
		if mc.Retracted {
			res.Problems = append(res.Problems, fmt.Sprintf("%s@%s is retracted", mc.Path, mc.To))
		}
	}

	// Vulnerabilities fixed and introduced.
	if !*upgradeFlags.noVulns {
		if err := upgradeVulns(c, res); err != nil {
			return err
		}
	}

	// go directive and toolchain.
	if res.Go, err = goChange(c, p, ng); err != nil {
		return err
	}
	if res.Go.Blocked {
		res.Problems = append(res.Problems, fmt.Sprintf("the upgrade requires go %s but the local toolchain is %s and GOTOOLCHAIN=%s: go get fails",
			res.Go.To, res.Go.LocalGo, res.Go.GOTOOLCHAIN))
	}

	// API compatibility of upgraded modules the project imports.
	if !*upgradeFlags.noAPI {
		if !c.Env.HaveGo() {
			c.Warnf("skipping the API check: %v", apidiff.ErrNoGo)
		} else if err := upgradeAPI(c, p, res); err != nil {
			return err
		}
	}

	c.SetResult(res)
	if len(res.Problems) > 0 {
		c.Issues()
	}
	if c.Text() {
		printUpgrade(c, res)
	}
	return nil
}

type conflictError struct{ msg string }

func (e *conflictError) Error() string { return e.msg }

// simulateGet computes the module graph after `go get targets`.
func simulateGet(c *cli.Context, p *project.Project, g *modgraph.Graph, targets map[string]string, order []string) (*modgraph.Graph, error) {
	roots := applyTargets(g.Roots, targets, order)
	ng, err := loadGraph(c, p, roots)
	if err != nil {
		return nil, err
	}
	// Downgrades and removals: while a target is selected above the
	// requested version (or still present after @none), downgrade the
	// requirements that pull it up to the highest version that does not
	// (mvs.Downgrade), or drop them.
	single := map[module.Version]bool{} // root -> violates
	violates := func(sg *modgraph.Graph) bool {
		for path, v := range targets {
			sel, ok := sg.Selected[path]
			if !ok {
				continue
			}
			if v == "none" || semver.Compare(sel, v) > 0 {
				return true
			}
		}
		return false
	}
	check := func(r module.Version) (bool, error) {
		if v, ok := single[r]; ok {
			return v, nil
		}
		sg, err := loadGraph(c, p, []module.Version{r})
		if err != nil {
			return false, err
		}
		single[r] = violates(sg)
		return single[r], nil
	}
	for iter := 0; violates(ng); iter++ {
		if iter > 50 {
			return nil, &conflictError{"cannot satisfy the requested versions"}
		}
		changed := false
		var next []module.Version
		for _, r := range roots {
			if _, isTarget := targets[r.Path]; isTarget {
				next = append(next, r)
				continue
			}
			bad, err := check(r)
			if err != nil {
				return nil, err
			}
			if !bad {
				next = append(next, r)
				continue
			}
			changed = true
			vs, err := c.Proxy().Versions(c.Ctx, r.Path)
			if err != nil && !errors.Is(err, modproxy.ErrNotFound) {
				return nil, err
			}
			repl := ""
			for i := len(vs) - 1; i >= 0; i-- {
				if semver.Compare(vs[i], r.Version) >= 0 {
					continue
				}
				bad, err := check(module.Version{Path: r.Path, Version: vs[i]})
				if err != nil {
					return nil, err
				}
				if !bad {
					repl = vs[i]
					break
				}
			}
			if repl != "" {
				next = append(next, module.Version{Path: r.Path, Version: repl})
			}
		}
		if !changed {
			var bad []string
			for _, path := range order {
				v := targets[path]
				if sel, ok := ng.Selected[path]; ok && (v == "none" || semver.Compare(sel, v) > 0) {
					chain := ng.Chain(module.Version{Path: path, Version: sel})
					var cs []string
					for _, m := range chain {
						cs = append(cs, m.String())
					}
					bad = append(bad, fmt.Sprintf("%s@%s is required at %s (%s)", path, v, sel, strings.Join(cs, " → ")))
				}
			}
			return nil, &conflictError{"conflicting requirements: " + strings.Join(bad, "; ")}
		}
		roots = next
		if ng, err = loadGraph(c, p, roots); err != nil {
			return nil, err
		}
	}
	return ng, nil
}

func applyTargets(roots []module.Version, targets map[string]string, order []string) []module.Version {
	var out []module.Version
	seen := map[string]bool{}
	for _, r := range roots {
		if v, ok := targets[r.Path]; ok {
			seen[r.Path] = true
			if v != "none" {
				out = append(out, module.Version{Path: r.Path, Version: v})
			}
			continue
		}
		out = append(out, r)
	}
	for _, path := range order {
		if v := targets[path]; !seen[path] && v != "none" {
			out = append(out, module.Version{Path: path, Version: v})
		}
	}
	return out
}

func vulnRefs(vs []*vulnscan.Vuln) map[string]VulnRef {
	out := map[string]VulnRef{}
	for _, v := range vs {
		out[v.Module+" "+v.ID] = VulnRef{ID: v.ID, Summary: v.Summary, Severity: v.Severity.String(), FixedIn: v.FixedIn, URL: v.URL}
	}
	return out
}

func upgradeVulns(c *cli.Context, res *UpgradeResult) error {
	var before, after []module.Version
	for _, mc := range res.Changes {
		if mc.From != "" {
			before = append(before, module.Version{Path: mc.Path, Version: mc.From})
		}
		if mc.To != "" {
			after = append(after, module.Version{Path: mc.Path, Version: mc.To})
		}
	}
	if len(before)+len(after) == 0 {
		return nil
	}
	vb, err := vulnscan.Scan(c.Ctx, c, before)
	if err != nil {
		return fmt.Errorf("vulnerability database: %w", err)
	}
	va, err := vulnscan.Scan(c.Ctx, c, after)
	if err != nil {
		return fmt.Errorf("vulnerability database: %w", err)
	}
	vulnscan.Enrich(c.Ctx, c, append(append([]*vulnscan.Vuln(nil), vb...), va...))
	rb, ra := vulnRefs(vb), vulnRefs(va)
	for i := range res.Changes {
		mc := &res.Changes[i]
		for _, k := range sortedKeys(rb) {
			if strings.HasPrefix(k, mc.Path+" ") {
				if _, still := ra[k]; !still {
					mc.VulnsFixed = append(mc.VulnsFixed, rb[k])
				}
			}
		}
		for _, k := range sortedKeys(ra) {
			if strings.HasPrefix(k, mc.Path+" ") {
				if _, had := rb[k]; !had {
					mc.VulnsIntroduced = append(mc.VulnsIntroduced, ra[k])
					res.Problems = append(res.Problems, fmt.Sprintf("%s@%s is affected by %s", mc.Path, mc.To, ra[k].ID))
				}
			}
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// localGoVersion returns the version of the installed go command
// ("1.24.7"), or "".
func localGoVersion(c *cli.Context) string {
	v := strings.TrimPrefix(c.Env.GoVersion(), "go")
	if i := strings.IndexAny(v, " +"); i >= 0 {
		v = v[:i]
	}
	if v == "" || strings.HasPrefix(v, "devel") {
		return ""
	}
	return v
}

// goChange predicts how `go get` changes the go and toolchain lines: the
// go line is raised to the highest go version required by the new build
// list; when it is raised and the running toolchain is newer, the go
// command records it in the toolchain line.
func goChange(c *cli.Context, p *project.Project, ng *modgraph.Graph) (GoChange, error) {
	gc := GoChange{GOTOOLCHAIN: c.Env.Get("GOTOOLCHAIN"), LocalGo: localGoVersion(c)}
	if gc.GOTOOLCHAIN == "" {
		gc.GOTOOLCHAIN = "auto"
	}
	file := p.GoMod
	if p.Work != nil {
		file = p.Work
	}
	if file != nil {
		gc.From, gc.ToolchainFrom = file.Go, file.Toolchain
	}
	gc.To, gc.ToolchainTo = gc.From, gc.ToolchainFrom
	maxGo, who, err := maxSelectedGo(c, ng)
	if err != nil {
		return gc, err
	}
	if modgraph.CompareGo(maxGo, gc.From) <= 0 {
		return gc, nil
	}
	gc.To, gc.RequiredBy = maxGo, who.String()
	// Can the running toolchain do it?
	if gc.LocalGo != "" && modgraph.CompareGo(gc.LocalGo, maxGo) < 0 {
		mode := gc.GOTOOLCHAIN
		if mode == "local" || strings.HasSuffix(mode, "+local") || (!strings.Contains(mode, "auto") && !strings.Contains(mode, "path")) {
			gc.Blocked = true
			return gc, nil
		}
		gc.Switch = "go" + maxGo
		if isLang(maxGo) && modgraph.CompareGo(maxGo, "1.21") >= 0 {
			gc.Switch += ".0"
		}
		gc.ToolchainTo = ""
		return gc, nil
	}
	local := gc.LocalGo
	tc := strings.TrimPrefix(gc.ToolchainFrom, "go")
	switch {
	case local != "" && modgraph.CompareGo(local, maxGo) > 0 && modgraph.CompareGo(local, tc) > 0:
		gc.ToolchainTo = "go" + local
	case tc != "" && modgraph.CompareGo(tc, maxGo) > 0:
		gc.ToolchainTo = gc.ToolchainFrom
	default:
		gc.ToolchainTo = ""
	}
	return gc, nil
}

// isLang reports whether v is a language version without a patch number
// ("1.22" rather than "1.22.0").
func isLang(v string) bool { return strings.Count(v, ".") == 1 && !strings.ContainsAny(v, "rcbeta") }

// upgradeAPI type-checks the project, finds the packages of upgraded and
// downgraded modules it imports, and diffs their API between the two
// versions.
func upgradeAPI(c *cli.Context, p *project.Project, res *UpgradeResult) error {
	moved := map[string]*ModuleChange{}
	for i := range res.Changes {
		mc := &res.Changes[i]
		if mc.From != "" && mc.To != "" {
			moved[mc.Path] = mc
		}
	}
	if len(moved) == 0 {
		return nil
	}
	c.Logf("type-checking the project")
	prog, err := c.Load(loader.Config{TypeCheck: true, Tests: true,
		SkipBodies: func(pk *loader.Package) bool { return !pk.InMainModule() }})
	if err != nil {
		return err
	}
	modOf := func(path string) string {
		if pk := prog.ByPath[path]; pk != nil && pk.Module != nil && !pk.Module.Main {
			return pk.Module.Path
		}
		return ""
	}
	base := p.ModDir
	if base == "" {
		base = p.Dir
	}
	usage := apidiff.CollectUsage(prog, base, func(path string) bool { return moved[modOf(path)] != nil })
	byMod := map[string]map[string]bool{} // module -> relative package paths used
	for _, pkg := range usage.Used() {
		mp := modOf(pkg)
		if byMod[mp] == nil {
			byMod[mp] = map[string]bool{}
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(pkg, mp), "/")
		byMod[mp][rel] = true
		moved[mp].UsedPackages = append(moved[mp].UsedPackages, pkg)
	}
	// Packages imported but not referenced through any symbol (blank or
	// side-effect imports) still exist-check.
	for _, pk := range prog.Packages {
		if !pk.InMainModule() {
			continue
		}
		for _, imp := range pk.Imports {
			if mp := modOf(imp); moved[mp] != nil {
				if byMod[mp] == nil {
					byMod[mp] = map[string]bool{}
				}
				rel := strings.TrimPrefix(strings.TrimPrefix(imp, mp), "/")
				if !byMod[mp][rel] {
					byMod[mp][rel] = true
					moved[mp].UsedPackages = append(moved[mp].UsedPackages, imp)
				}
			}
		}
	}
	for _, mp := range sortedKeys(byMod) {
		mc := moved[mp]
		sort.Strings(mc.UsedPackages)
		oldAPI, err := loadAPI(c, mp, mc.From)
		if err != nil {
			return err
		}
		newAPI, err := loadAPI(c, mp, mc.To)
		if err != nil {
			return err
		}
		rep := apidiff.CompareModules(oldAPI, newAPI, byMod[mp])
		mc.APIChecked = true
		mc.APIAdditions = len(rep.Compatible)
		for _, ch := range rep.Incompatible {
			b := APIBreak{Change: ch, UsedAt: usage.Affects(ch.Package, ch)}
			if b.UsedAt == nil {
				b.UsedAt = []string{}
			}
			mc.Affected += len(b.UsedAt)
			mc.APIBreaks = append(mc.APIBreaks, b)
		}
		if mc.Affected > 0 {
			res.Problems = append(res.Problems, fmt.Sprintf("%s %s → %s breaks %s in your code", mp, mc.From, mc.To,
				plural(mc.Affected, "reference", "references")))
		}
	}
	return nil
}

func printUpgrade(c *cli.Context, res *UpgradeResult) {
	out := c.Out
	out.Title("Upgrade simulation: " + res.Command)
	out.Printf("%s %s → %s\n", out.Dim("build list:"), plural(res.Before, "module", "modules"), plural(res.After, "module", "modules"))
	if len(res.Changes) == 0 {
		out.Println()
		out.OK("nothing changes: the build list already has these versions")
	} else {
		out.Heading("Module changes")
		var rows [][]string
		for _, mc := range res.Changes {
			kind := mc.Kind
			switch mc.Kind {
			case "upgrade":
				kind = out.Green("↑ " + mc.Bump)
			case "downgrade":
				kind = out.Yellow("↓ " + mc.Bump)
			case "added":
				kind = out.Cyan("+ added")
			case "removed":
				kind = out.Red("- removed")
			}
			from, to := mc.From, mc.To
			if from == "" {
				from = "—"
			}
			if to == "" {
				to = "—"
			}
			var notes []string
			if mc.Requested {
				notes = append(notes, "requested")
			} else if mc.Direct {
				notes = append(notes, "direct")
			}
			if mc.Retracted {
				notes = append(notes, out.Red("retracted"))
			}
			if mc.Deprecated != "" {
				notes = append(notes, out.Yellow("deprecated"))
			}
			if n := len(mc.VulnsFixed); n > 0 {
				notes = append(notes, out.Green(fmt.Sprintf("fixes %d vuln", n)))
			}
			if n := len(mc.VulnsIntroduced); n > 0 {
				notes = append(notes, out.Red(fmt.Sprintf("introduces %d vuln", n)))
			}
			if mc.APIChecked {
				switch {
				case mc.Affected > 0:
					notes = append(notes, out.Red(fmt.Sprintf("%d API breaks affect you", len(mc.APIBreaks))))
				case len(mc.APIBreaks) > 0:
					notes = append(notes, out.Yellow(fmt.Sprintf("%d API breaks (unused)", len(mc.APIBreaks))))
				default:
					notes = append(notes, "API compatible")
				}
			}
			rows = append(rows, []string{mc.Path, from, to, kind, strings.Join(notes, ", ")})
		}
		out.Table([]string{"MODULE", "FROM", "TO", "CHANGE", "NOTES"}, rows)
	}
	gc := res.Go
	if gc.To != gc.From || gc.ToolchainTo != gc.ToolchainFrom {
		out.Heading("Go version")
		if gc.To != gc.From {
			out.Printf("  go %s → %s %s\n", gc.From, gc.To, out.Dim("(required by "+gc.RequiredBy+")"))
		}
		if gc.ToolchainTo != gc.ToolchainFrom {
			from, to := gc.ToolchainFrom, gc.ToolchainTo
			if from == "" {
				from = "none"
			}
			if to == "" {
				to = "none"
			}
			out.Printf("  toolchain %s → %s\n", from, to)
		}
		switch {
		case gc.Blocked:
			out.Bad("local Go %s is too old and GOTOOLCHAIN=%s forbids switching", gc.LocalGo, gc.GOTOOLCHAIN)
		case gc.Switch != "":
			out.Warn("local Go %s is too old: the go command will download and switch to %s (GOTOOLCHAIN=%s)", gc.LocalGo, gc.Switch, gc.GOTOOLCHAIN)
		}
	}
	for _, mc := range res.Changes {
		if len(mc.VulnsFixed)+len(mc.VulnsIntroduced) == 0 && len(mc.APIBreaks) == 0 && !mc.Retracted && mc.Deprecated == "" {
			continue
		}
		out.Heading(mc.Path + " " + mc.From + " → " + mc.To)
		if mc.Retracted {
			reason := mc.RetractReason
			if reason == "" {
				reason = "no reason given"
			}
			out.Bad("%s is retracted: %s", mc.To, reason)
		}
		if mc.Deprecated != "" {
			out.Warn("module deprecated: %s", mc.Deprecated)
		}
		for _, v := range mc.VulnsFixed {
			out.OK("fixes %s %s", v.ID, out.Dim(v.Summary))
		}
		for _, v := range mc.VulnsIntroduced {
			out.Bad("introduces %s [%s] %s", v.ID, v.Severity, out.Dim(v.Summary))
		}
		for _, b := range mc.APIBreaks {
			if len(b.UsedAt) == 0 {
				out.Printf("  %s %s %s\n", out.Yellow("!"), b.Message, out.Dim("(not referenced by your code)"))
				continue
			}
			out.Printf("  %s %s\n", out.Red("✗"), b.Message)
			for _, pos := range b.UsedAt {
				out.Printf("      %s %s\n", out.Dim("used at"), pos)
			}
		}
	}
	out.Println()
	if len(res.Problems) == 0 {
		out.OK("safe to run: %s", res.Command)
		return
	}
	for _, pr := range res.Problems {
		out.Bad("%s", pr)
	}
}
