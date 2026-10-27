package binary

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"go/build"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/loader"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/ui"
)

var defaultTargets = []string{"linux/amd64", "linux/arm64", "darwin/arm64", "windows/amd64"}

var cgoFlags struct {
	targets cli.StringList
	tags    cli.StringList
	verify  *bool
	std     *bool
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "cgo",
		Group:   group,
		Summary: "Cross-compile readiness: cgo use, C libraries and CGO_ENABLED=0 builds per target",
		Usage:   "sm-go cgo [packages] [flags]",
		Help: `Finds every package in the build graph of the project (default ./...) that
uses cgo: Go files importing "C", C/C++/Objective-C sources, .syso
objects. For each it reports the C libraries it links (#cgo LDFLAGS -l and
-framework, pkg-config packages), the build constraints of its cgo and
pure-Go files, and which module it comes from.

For each target in the matrix (default linux/amd64, linux/arm64,
darwin/arm64, windows/amd64) it predicts whether the program builds with
CGO_ENABLED=0 — the usual requirement for static binaries, scratch/
distroless images and cross-compilation without a C cross-toolchain. The
prediction re-evaluates the build constraints of every package in the
graph with cgo disabled, following the imports that remain:

  ok        no cgo anywhere in the build graph
  fallback  cgo is used when enabled, but every such package has a pure-Go
            alternative selected by build tags (e.g. //go:build !cgo)
  fail      a package has no Go files left without cgo, or keeps C/C++
            sources that cannot be compiled without cgo

--verify confirms the prediction by running go build with GOOS, GOARCH
and CGO_ENABLED=0 for each target (compile errors in fallback code are
only found this way). Predicted or verified failures exit 1.`,
		Examples: []string{
			"sm-go cgo",
			"sm-go cgo ./cmd/server --targets linux/amd64,linux/arm64,linux/riscv64",
			"sm-go cgo --verify --json",
			"sm-go cgo --std",
		},
		Sources: []string{"go list", "go build (with --verify)"},
		NeedsGo: true,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&cgoFlags.targets, "targets", "comma-separated GOOS/GOARCH `list` (default "+strings.Join(defaultTargets, ",")+")")
			fs.Var(&cgoFlags.tags, "tags", "build `tags` to apply (comma-separated)")
			cgoFlags.verify = fs.Bool("verify", false, "verify predictions by running go build with CGO_ENABLED=0 for each target")
			cgoFlags.std = fs.Bool("std", false, "list standard-library cgo packages too (they always have pure-Go fallbacks)")
		},
		Run: runCgo,
	})
}

type fileConstraint struct {
	File       string `json:"file"`
	Constraint string `json:"constraint,omitempty"`
	ImportsC   bool   `json:"importsC,omitempty"`
}

type libRef struct {
	Name    string   `json:"name"`
	Kind    string   `json:"kind"` // lib, framework, pkg-config
	Targets []string `json:"targets"`
}

type cgoPackage struct {
	ImportPath  string           `json:"importPath"`
	Module      string           `json:"module,omitempty"`
	Version     string           `json:"version,omitempty"`
	Standard    bool             `json:"standard,omitempty"`
	Dir         string           `json:"dir"`
	CgoFiles    []string         `json:"cgoFiles,omitempty"`
	CFiles      []string         `json:"cFiles,omitempty"`
	CXXFiles    []string         `json:"cxxFiles,omitempty"`
	SFiles      []string         `json:"sFiles,omitempty"`
	SysoFiles   []string         `json:"sysoFiles,omitempty"`
	Libraries   []libRef         `json:"libraries,omitempty"`
	CFLAGS      []string         `json:"cflags,omitempty"`
	LDFLAGS     []string         `json:"ldflags,omitempty"`
	Constraints []fileConstraint `json:"constraints,omitempty"`
	Targets     []string         `json:"targets"` // targets where it uses cgo
	Via         []string         `json:"via,omitempty"`
}

type blocker struct {
	Package string   `json:"package"`
	Module  string   `json:"module,omitempty"`
	Reason  string   `json:"reason"`
	Files   []string `json:"files,omitempty"`
	Via     []string `json:"via,omitempty"` // import chain from a root package
}

type verifyResult struct {
	Command string `json:"command"`
	OK      bool   `json:"ok"`
	Output  string `json:"output,omitempty"`
	Agrees  bool   `json:"agreesWithPrediction"`
}

type targetResult struct {
	Target      string        `json:"target"`
	GOOS        string        `json:"goos"`
	GOARCH      string        `json:"goarch"`
	Prediction  string        `json:"prediction"` // ok, fallback, fail
	CgoPackages []string      `json:"cgoPackages"`
	Fallbacks   []string      `json:"fallbacks"`
	Blockers    []blocker     `json:"blockers"`
	Unresolved  []string      `json:"unresolved,omitempty"`
	CrossCC     bool          `json:"needsCrossCompiler"`
	ListErrors  []string      `json:"listErrors,omitempty"`
	Verify      *verifyResult `json:"verify,omitempty"`
}

type cgoResult struct {
	Dir       string           `json:"dir"`
	Patterns  []string         `json:"patterns"`
	Host      string           `json:"host"`
	Packages  []*cgoPackage    `json:"packages"`
	StdCgo    []string         `json:"stdCgoPackages"`
	Libraries []libRef         `json:"libraries"`
	Targets   []*targetResult  `json:"targets"`
	Findings  []report.Finding `json:"findings"`
}

var targetRE = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9]+$`)

func runCgo(c *cli.Context) error {
	targets := []string(cgoFlags.targets)
	if len(targets) == 0 {
		targets = defaultTargets
	}
	seen := map[string]bool{}
	var tlist []string
	for _, t := range targets {
		if !targetRE.MatchString(t) {
			return cli.Usagef("--targets: %q is not GOOS/GOARCH", t)
		}
		if !seen[t] {
			seen[t] = true
			tlist = append(tlist, t)
		}
	}
	patterns := c.Args
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	proj, err := c.Project()
	if err != nil {
		return cli.Usagef("%v", err)
	}
	dir := proj.ModDir
	if dir == "" {
		dir = proj.Dir
	}
	res := &cgoResult{Dir: dir, Patterns: patterns, Host: c.Env.Get("GOHOSTOS") + "/" + c.Env.Get("GOHOSTARCH"),
		Packages: []*cgoPackage{}, StdCgo: []string{}, Libraries: []libRef{}, Findings: []report.Finding{}}
	if res.Host == "/" {
		res.Host = c.Env.Get("GOOS") + "/" + c.Env.Get("GOARCH")
	}
	pkgs := map[string]*cgoPackage{}
	stdCgo := map[string]bool{}
	for _, t := range tlist {
		goos, goarch, _ := strings.Cut(t, "/")
		c.Logf("listing %s with CGO_ENABLED=1", t)
		prog, err := c.Load(loader.Config{Dir: dir, Patterns: patterns, Tags: cgoFlags.tags, GOOS: goos, GOARCH: goarch, CGO: "1"})
		if err != nil {
			if strings.Contains(err.Error(), "unsupported GOOS/GOARCH") {
				return cli.Usagef("--targets: %s is not a supported GOOS/GOARCH pair", t)
			}
			return err
		}
		if len(prog.Roots) == 0 {
			return cli.Usagef("no packages match %s", strings.Join(patterns, " "))
		}
		tr := predict(c, prog, goos, goarch)
		tr.Target = t
		res.Targets = append(res.Targets, tr)
		// Record cgo packages of this target.
		parents := importParents(prog)
		for _, p := range prog.Packages {
			if !usesCgo(p) {
				continue
			}
			if p.Standard {
				stdCgo[p.ImportPath] = true
				if !*cgoFlags.std {
					continue
				}
			}
			cp := pkgs[p.ImportPath]
			if cp == nil {
				cp = &cgoPackage{ImportPath: p.ImportPath, Module: p.ModulePath(), Version: p.ModuleVersion(),
					Standard: p.Standard, Dir: p.Dir, Via: chain(parents, p.ImportPath)}
				pkgs[p.ImportPath] = cp
			}
			cp.Targets = append(cp.Targets, t)
			cp.CgoFiles = union(cp.CgoFiles, p.CgoFiles)
			cp.CFiles = union(cp.CFiles, p.CFiles)
			cp.CXXFiles = union(cp.CXXFiles, p.CXXFiles)
			cp.SysoFiles = union(cp.SysoFiles, p.SysoFiles)
			if len(p.CgoFiles) > 0 {
				cp.SFiles = union(cp.SFiles, p.SFiles)
			}
			cp.CFLAGS = union(cp.CFLAGS, p.CgoCFLAGS)
			cp.LDFLAGS = union(cp.LDFLAGS, p.CgoLDFLAGS)
			for _, l := range linkLibs(p) {
				cp.Libraries = addLib(cp.Libraries, l, t)
				res.Libraries = addLib(res.Libraries, l, t)
			}
		}
	}
	for _, cp := range pkgs {
		cp.Constraints = constraintsOf(cp.Dir)
		res.Packages = append(res.Packages, cp)
	}
	sort.Slice(res.Packages, func(i, j int) bool { return res.Packages[i].ImportPath < res.Packages[j].ImportPath })
	res.StdCgo = append(res.StdCgo, sortedKeys(stdCgo)...)
	sort.Slice(res.Libraries, func(i, j int) bool { return res.Libraries[i].Name < res.Libraries[j].Name })

	if *cgoFlags.verify {
		tmp, err := os.MkdirTemp("", "smgo-cgo-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		for _, tr := range res.Targets {
			c.Logf("verifying %s with go build", tr.Target)
			tr.Verify = verifyBuild(c.Ctx, c, dir, tmp, tr, patterns)
			if !tr.Verify.Agrees {
				c.Warnf("%s: prediction %q but go build %s", tr.Target, tr.Prediction, map[bool]string{true: "succeeded", false: "failed"}[tr.Verify.OK])
			}
		}
	}
	for _, tr := range res.Targets {
		for _, b := range tr.Blockers {
			res.Findings = append(res.Findings, report.Finding{Severity: report.High, Rule: "cgo-required",
				Package: b.Package, Module: b.Module,
				Title:  fmt.Sprintf("%s cannot be built for %s with CGO_ENABLED=0", b.Package, tr.Target),
				Detail: b.Reason, Fix: "add a pure-Go implementation behind //go:build !cgo, or build this target with cgo and a C cross-compiler",
				Data: map[string]any{"target": tr.Target, "via": b.Via}})
		}
		if tr.Verify != nil && !tr.Verify.OK && len(tr.Blockers) == 0 {
			res.Findings = append(res.Findings, report.Finding{Severity: report.High, Rule: "cgo-verify-failed",
				Title:  fmt.Sprintf("go build for %s with CGO_ENABLED=0 failed", tr.Target),
				Detail: firstLines(tr.Verify.Output, 3), Data: map[string]any{"target": tr.Target}})
		}
	}
	report.SortFindings(res.Findings)
	if len(res.Findings) > 0 {
		c.Issues()
	}
	c.SetResult(res)
	if c.Text() {
		printCgo(c, res)
	}
	return nil
}

func usesCgo(p *loader.Package) bool {
	return len(p.CgoFiles) > 0 || len(p.CFiles) > 0 || len(p.CXXFiles) > 0 || len(p.SysoFiles) > 0
}

func union(a, b []string) []string {
	for _, x := range b {
		found := false
		for _, y := range a {
			if x == y {
				found = true
				break
			}
		}
		if !found {
			a = append(a, x)
		}
	}
	return a
}

// linkLibs extracts the C libraries a package links.
func linkLibs(p *loader.Package) []libRef {
	var out []libRef
	fl := p.CgoLDFLAGS
	for i := 0; i < len(fl); i++ {
		f := fl[i]
		switch {
		case strings.HasPrefix(f, "-l") && len(f) > 2:
			out = append(out, libRef{Name: f[2:], Kind: "lib"})
		case f == "-l" && i+1 < len(fl):
			out = append(out, libRef{Name: fl[i+1], Kind: "lib"})
			i++
		case f == "-framework" && i+1 < len(fl):
			out = append(out, libRef{Name: fl[i+1], Kind: "framework"})
			i++
		case strings.HasPrefix(f, "-Wl,-framework,"):
			out = append(out, libRef{Name: strings.TrimPrefix(f, "-Wl,-framework,"), Kind: "framework"})
		case strings.HasSuffix(f, ".a") || strings.HasSuffix(f, ".so") || strings.Contains(f, ".so."):
			out = append(out, libRef{Name: f, Kind: "lib"})
		}
	}
	for _, pc := range p.CgoPkgConfig {
		if strings.HasPrefix(pc, "-") {
			continue // pkg-config flags such as --static
		}
		out = append(out, libRef{Name: pc, Kind: "pkg-config"})
	}
	return out
}

func addLib(list []libRef, l libRef, target string) []libRef {
	for i := range list {
		if list[i].Name == l.Name && list[i].Kind == l.Kind {
			list[i].Targets = union(list[i].Targets, []string{target})
			return list
		}
	}
	l.Targets = []string{target}
	return append(list, l)
}

// importParents returns, for each package, the first package found to
// import it (breadth-first from the roots), for import chains.
func importParents(prog *loader.Program) map[string]string {
	parent := map[string]string{}
	var queue []string
	for _, r := range prog.Roots {
		parent[r.ImportPath] = ""
		queue = append(queue, r.ImportPath)
	}
	for len(queue) > 0 {
		p := prog.ByPath[queue[0]]
		queue = queue[1:]
		if p == nil {
			continue
		}
		for _, im := range p.Imports {
			if _, ok := parent[im]; !ok {
				parent[im] = p.ImportPath
				queue = append(queue, im)
			}
		}
	}
	return parent
}

func chain(parent map[string]string, p string) []string {
	var out []string
	for i := 0; p != "" && i < 100; i++ {
		out = append([]string{p}, out...)
		next, ok := parent[p]
		if !ok {
			break
		}
		p = next
	}
	return out
}

// buildContext returns a go/build context for target with cgo disabled,
// matching the release tags of the installed toolchain.
func buildContext(c *cli.Context, goos, goarch string) build.Context {
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH = goos, goarch
	ctx.CgoEnabled = false
	ctx.Compiler = "gc"
	if r := c.Env.Get("GOROOT"); r != "" {
		ctx.GOROOT = r
	}
	ctx.BuildTags = append([]string(nil), cgoFlags.tags...)
	// Architecture feature tags (amd64.v2, ...) belong to the host; keep
	// only experiment tags.
	var tool []string
	for _, t := range build.Default.ToolTags {
		if strings.HasPrefix(t, "goexperiment.") {
			tool = append(tool, t)
		}
	}
	ctx.ToolTags = tool
	if v := c.Env.GoVersion(); v != "" {
		if minor := goMinor(v); minor > 0 {
			ctx.ReleaseTags = nil
			for i := 1; i <= minor; i++ {
				ctx.ReleaseTags = append(ctx.ReleaseTags, "go1."+strconv.Itoa(i))
			}
		}
	}
	return ctx
}

func goMinor(v string) int {
	v = strings.TrimPrefix(v, "go")
	if !strings.HasPrefix(v, "1.") {
		return 0
	}
	v = v[2:]
	end := 0
	for end < len(v) && v[end] >= '0' && v[end] <= '9' {
		end++
	}
	n, _ := strconv.Atoi(v[:end])
	return n
}

// predict walks the build graph with cgo disabled.
func predict(c *cli.Context, prog *loader.Program, goos, goarch string) *targetResult {
	tr := &targetResult{GOOS: goos, GOARCH: goarch, CgoPackages: []string{}, Fallbacks: []string{}, Blockers: []blocker{}}
	tr.ListErrors = prog.Errors
	for _, p := range prog.Packages {
		if usesCgo(p) {
			tr.CgoPackages = append(tr.CgoPackages, p.ImportPath)
			if !p.Standard && goos+"/"+goarch != c.Env.Get("GOHOSTOS")+"/"+c.Env.Get("GOHOSTARCH") {
				tr.CrossCC = true
			}
		}
	}
	bctx := buildContext(c, goos, goarch)
	parent := map[string]string{}
	var queue []string
	for _, r := range prog.Roots {
		if _, ok := parent[r.ImportPath]; !ok {
			parent[r.ImportPath] = ""
			queue = append(queue, r.ImportPath)
		}
	}
	unresolved := map[string]bool{}
	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		lp := prog.ByPath[path]
		if lp == nil || lp.Dir == "" {
			unresolved[path] = true
			continue
		}
		if path == "unsafe" || path == "C" {
			continue
		}
		bp, err := bctx.ImportDir(lp.Dir, 0)
		b := blocker{Package: path, Module: lp.ModulePath(), Via: chain(parent, path)}
		var noGo *build.NoGoError
		switch {
		case errors.As(err, &noGo):
			b.Reason = "no Go files remain without cgo: every Go file imports \"C\" or requires the cgo build tag"
			b.Files = lp.CgoFiles
			tr.Blockers = append(tr.Blockers, b)
			continue
		case err != nil:
			b.Reason = "cannot evaluate build constraints: " + err.Error()
			tr.Blockers = append(tr.Blockers, b)
			continue
		}
		var csrc []string
		csrc = append(csrc, bp.CFiles...)
		csrc = append(csrc, bp.CXXFiles...)
		csrc = append(csrc, bp.MFiles...)
		csrc = append(csrc, bp.FFiles...)
		if len(csrc) > 0 {
			b.Reason = "C/C++/Objective-C/Fortran sources cannot be compiled without cgo: " + strings.Join(csrc, " ")
			b.Files = csrc
			tr.Blockers = append(tr.Blockers, b)
			continue
		}
		if usesCgo(lp) {
			tr.Fallbacks = append(tr.Fallbacks, path)
		}
		for _, im := range bp.Imports {
			if im == "C" {
				continue
			}
			if m, ok := lp.ImportMap[im]; ok {
				im = m
			}
			if _, ok := parent[im]; ok {
				continue
			}
			parent[im] = path
			if prog.ByPath[im] == nil {
				unresolved[im] = true
				continue
			}
			queue = append(queue, im)
		}
	}
	tr.Unresolved = sortedKeys(unresolved)
	sort.Strings(tr.Fallbacks)
	sort.Slice(tr.Blockers, func(i, j int) bool { return tr.Blockers[i].Package < tr.Blockers[j].Package })
	switch {
	case len(tr.Blockers) > 0:
		tr.Prediction = "fail"
	case len(tr.CgoPackages) > 0:
		tr.Prediction = "fallback"
	default:
		tr.Prediction = "ok"
	}
	return tr
}

// constraintsOf reads the build constraints of the Go files in dir that
// import "C" or mention cgo in their constraint.
func constraintsOf(dir string) []fileConstraint {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []fileConstraint
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		expr, importsC := goFileHeader(filepath.Join(dir, name))
		if importsC || strings.Contains(expr, "cgo") {
			out = append(out, fileConstraint{File: name, Constraint: expr, ImportsC: importsC})
		}
	}
	return out
}

var importCRE = regexp.MustCompile(`(?m)^\s*import\s+"C"|^\s*"C"\s*$`)

// goFileHeader returns the //go:build expression of a Go file and whether
// it imports "C".
func goFileHeader(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	expr := ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	var header bytes.Buffer
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "//go:build ") && expr == "" {
			expr = strings.TrimSpace(strings.TrimPrefix(line, "//go:build "))
		} else if strings.HasPrefix(line, "// +build ") && expr == "" {
			expr = "+build " + strings.TrimSpace(strings.TrimPrefix(line, "// +build "))
		}
		header.WriteString(sc.Text())
		header.WriteByte('\n')
		// Stop after the import section.
		if strings.HasPrefix(line, "func ") || strings.HasPrefix(line, "type ") || strings.HasPrefix(line, "var ") || strings.HasPrefix(line, "const ") {
			break
		}
	}
	return expr, importCRE.Match(header.Bytes())
}

func verifyBuild(ctx context.Context, c *cli.Context, dir, tmp string, tr *targetResult, patterns []string) *verifyResult {
	out := filepath.Join(tmp, strings.ReplaceAll(tr.Target, "/", "_")) + string(filepath.Separator)
	args := []string{"build", "-o", out}
	if len(cgoFlags.tags) > 0 {
		args = append(args, "-tags="+strings.Join(cgoFlags.tags, ","))
	}
	args = append(args, "--")
	args = append(args, patterns...)
	cmd := exec.CommandContext(ctx, c.Env.GoBin, args...)
	cmd.Dir = dir
	cmd.Env = append(c.Env.EnvironIn(dir), "GOOS="+tr.GOOS, "GOARCH="+tr.GOARCH, "CGO_ENABLED=0")
	output, err := cmd.CombinedOutput()
	vr := &verifyResult{Command: fmt.Sprintf("GOOS=%s GOARCH=%s CGO_ENABLED=0 go %s", tr.GOOS, tr.GOARCH, strings.Join(args[:1], " ")+" "+strings.Join(patterns, " ")),
		OK: err == nil, Output: strings.TrimSpace(firstLines(string(output), 20))}
	vr.Agrees = vr.OK == (tr.Prediction != "fail")
	return vr
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = append(lines[:n], fmt.Sprintf("... (%d more lines)", len(lines)-n))
	}
	return strings.Join(lines, "\n")
}

func printCgo(c *cli.Context, res *cgoResult) {
	p := c.Out
	p.Title(fmt.Sprintf("sm-go cgo — %s (%s)", relPath(c, res.Dir), strings.Join(res.Patterns, " ")))
	p.Heading(fmt.Sprintf("cgo packages (%d)", len(res.Packages)))
	if len(res.Packages) == 0 {
		p.OK("no third-party or project package uses cgo")
	}
	for _, cp := range res.Packages {
		where := cp.Module
		if cp.Version != "" {
			where += "@" + cp.Version
		}
		if cp.Standard {
			where = "standard library"
		}
		p.Printf("  %s %s\n", p.Bold(cp.ImportPath), p.Dim(where))
		var kv [][2]string
		var files []string
		files = append(files, cp.CgoFiles...)
		files = append(files, cp.CFiles...)
		files = append(files, cp.CXXFiles...)
		files = append(files, cp.SysoFiles...)
		kv = append(kv, [2]string{"files", strings.Join(files, " ")})
		if len(cp.Libraries) > 0 {
			var libs []string
			for _, l := range cp.Libraries {
				s := l.Name
				switch l.Kind {
				case "lib":
					s = "-l" + l.Name
				case "framework":
					s = "framework " + l.Name
				case "pkg-config":
					s = "pkg-config " + l.Name
				}
				if len(l.Targets) < len(res.Targets) {
					s += p.Dim(" (" + strings.Join(l.Targets, ", ") + ")")
				}
				libs = append(libs, s)
			}
			kv = append(kv, [2]string{"links", strings.Join(libs, ", ")})
		}
		var cons []string
		for _, f := range cp.Constraints {
			s := f.File
			if f.Constraint != "" {
				s += " [" + f.Constraint + "]"
			}
			if f.ImportsC {
				s += " C"
			}
			cons = append(cons, s)
		}
		if len(cons) > 0 {
			kv = append(kv, [2]string{"constraints", strings.Join(cons, ", ")})
		}
		if len(cp.Targets) < len(res.Targets) {
			kv = append(kv, [2]string{"targets", strings.Join(cp.Targets, ", ")})
		}
		if len(cp.Via) > 1 {
			kv = append(kv, [2]string{"via", strings.Join(cp.Via, " → ")})
		}
		p.KV(kv...)
	}
	if len(res.StdCgo) > 0 && !*cgoFlags.std {
		p.Printf("  %s\n", p.Dim("standard library cgo packages (with pure-Go fallbacks): "+strings.Join(res.StdCgo, ", ")))
	}
	p.Heading("Cross-compile readiness with CGO_ENABLED=0")
	var rows [][]string
	for _, tr := range res.Targets {
		var pred, detail string
		switch tr.Prediction {
		case "ok":
			pred, detail = p.Green("✓ ok"), "pure Go"
		case "fallback":
			pred = p.Green("✓ fallback")
			detail = "pure-Go fallbacks: " + ui.Truncate(strings.Join(tr.Fallbacks, ", "), 70)
		case "fail":
			pred = p.Red("✗ fails")
			var bs []string
			for _, b := range tr.Blockers {
				bs = append(bs, b.Package)
			}
			detail = strings.Join(bs, ", ")
		}
		row := []string{tr.Target, pred}
		if tr.Verify != nil {
			v := p.Green("build ok")
			if !tr.Verify.OK {
				v = p.Red("build failed")
			}
			if !tr.Verify.Agrees {
				v += p.Yellow(" (differs)")
			}
			row = append(row, v)
		}
		rows = append(rows, append(row, detail))
	}
	header := []string{"TARGET", "PREDICTION"}
	if *cgoFlags.verify {
		header = append(header, "VERIFIED")
	}
	p.Table(append(header, "DETAIL"), rows)
	for _, tr := range res.Targets {
		for _, b := range tr.Blockers {
			p.Printf("\n  %s %s %s\n", p.Red("✗"), p.Bold(tr.Target), b.Package)
			p.Printf("    %s\n", b.Reason)
			if len(b.Via) > 1 {
				p.Printf("    %s\n", p.Dim("imported via "+strings.Join(b.Via, " → ")))
			}
		}
		if tr.Verify != nil && !tr.Verify.OK {
			p.Printf("\n  %s %s\n", p.Bold(tr.Target), p.Dim(tr.Verify.Command))
			for _, l := range strings.Split(firstLines(tr.Verify.Output, 6), "\n") {
				p.Printf("    %s\n", p.Dim(l))
			}
		}
		if len(tr.Unresolved) > 0 {
			p.Warn("%s: imports only used without cgo were not analysed: %s (use --verify)", tr.Target, strings.Join(tr.Unresolved, ", "))
		}
	}
	var cross []string
	for _, tr := range res.Targets {
		if tr.CrossCC {
			cross = append(cross, tr.Target)
		}
	}
	if len(cross) > 0 {
		p.Println()
		p.Warn("building with cgo for %s needs a C cross-compiler (set CC, e.g. CC=aarch64-linux-gnu-gcc)", strings.Join(cross, ", "))
	}
	p.Println()
	if len(res.Findings) > 0 {
		p.Bad("%s", ui.Plural(len(res.Findings), "blocker", "blockers")+" for CGO_ENABLED=0 builds")
	} else {
		p.OK("every target builds without cgo")
	}
}
