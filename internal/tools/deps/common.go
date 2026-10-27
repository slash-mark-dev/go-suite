package deps

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/goenv"
	"github.com/slash-mark-dev/go-suite/internal/loader"
	"github.com/slash-mark-dev/go-suite/internal/modfile"
	"github.com/slash-mark-dev/go-suite/internal/modgraph"
	"github.com/slash-mark-dev/go-suite/internal/modproxy"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/par"
	"github.com/slash-mark-dev/go-suite/internal/project"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/ui"
)

const group = "Dependency analysis"

// ---------- project / graph loading ----------

// loadGraph returns the module graph of the current project. Problems
// fetching go.mod files other than "not found" (network failures) are
// returned as errors, so the tool exits with code 3 instead of reasoning
// about an incomplete graph.
func loadGraph(c *cli.Context) (*project.Project, *modgraph.Graph, error) {
	p, err := c.Project()
	if err != nil {
		return nil, nil, err
	}
	g, err := c.Graph()
	if err != nil {
		return nil, nil, err
	}
	if err := fatalGraphError(g); err != nil {
		return nil, nil, err
	}
	return p, g, nil
}

func fatalGraphError(g *modgraph.Graph) error {
	var ms []module.Version
	for m, err := range g.Errors {
		if rep, ok := g.Replacement[m]; ok && rep.Version == "" {
			continue // local replacement problem: reported by the tools, not a network failure
		}
		if !errors.Is(err, modproxy.ErrNotFound) && !errors.Is(err, fs.ErrNotExist) {
			ms = append(ms, m)
		}
	}
	if len(ms) == 0 {
		return nil
	}
	module.Sort(ms)
	return fmt.Errorf("loading module graph: %s: %v", ms[0], g.Errors[ms[0]])
}

// standaloneEnv is the environment with workspace mode disabled.
func standaloneEnv(c *cli.Context) *goenv.Env {
	return c.Env.With(map[string]string{"GOWORK": "off"})
}

// loadStandalone loads the module in dir on its own (GOWORK=off), the way
// `go mod tidy`, `go install m@v` and consumers of the module see it.
func loadStandalone(c *cli.Context, dir string) (*project.Project, *modgraph.Graph, error) {
	p, err := project.Find(dir, standaloneEnv(c))
	if err != nil {
		return nil, nil, err
	}
	g, err := p.Graph(c.Ctx, c.Proxy())
	if err != nil {
		return p, nil, err
	}
	return p, g, fatalGraphError(g)
}

// ---------- package import graph (go list) ----------

// pkgGraph is the package import graph of the main module(s) as reported
// by `go list -deps [-test]`. Test code of a main-module package p is the
// pseudo-node "p.test" (as `go mod why` prints it), imported by p.
type pkgGraph struct {
	pkgs    map[string]*loader.Package // non-test package entries by import path
	imports map[string][]string        // node -> imported nodes (sorted)
	roots   []string                   // main-module packages (sorted)
	tools   []string                   // packages named by tool directives
	tests   bool
	errors  []string
}

// mainPatterns returns go list patterns that match the packages of every
// main module of p, plus "tool" when a main module declares tools.
func mainPatterns(env *goenv.Env, p *project.Project) (dir string, patterns []string, tools map[string]bool) {
	tools = map[string]bool{}
	for _, m := range p.Mains {
		if m.File == nil {
			continue
		}
		for _, t := range m.File.Tool {
			tools[t.Path] = true
		}
	}
	if !p.IsWorkspace() {
		dir, patterns = p.ModDir, []string{"./..."}
	} else {
		dir = p.Dir
		for _, m := range p.Mains {
			patterns = append(patterns, filepath.ToSlash(m.Dir)+"/...")
		}
	}
	if len(tools) > 0 && modgraph.GoAtLeast(strings.TrimPrefix(env.GoVersion(), "go"), "1.24") {
		patterns = append(patterns, "tool")
	}
	return dir, patterns, tools
}

// listPackages runs go list on the main module(s) of p. It never modifies
// the user's go.mod or go.sum: in single-module mode it works on a copy
// passed with -modfile (so untidy modules still load), in vendor mode it
// uses the vendor directory and in workspace mode -mod=readonly.
func listPackages(c *cli.Context, env *goenv.Env, p *project.Project, tests bool) (*pkgGraph, error) {
	dir, pats, tools := mainPatterns(env, p)
	extra := []string{"-deps"}
	if tests {
		extra = append(extra, "-test")
	}
	switch {
	case p.VendorPath != "" && !p.IsWorkspace():
		// default -mod=vendor
	case p.IsWorkspace():
		extra = append(extra, "-mod=readonly")
	default:
		tmp, err := os.MkdirTemp("", "sm-go-modfile-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmp)
		for _, name := range []string{"go.mod", "go.sum"} {
			data, err := os.ReadFile(filepath.Join(p.ModDir, name))
			if err != nil {
				if name == "go.sum" {
					continue
				}
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(tmp, name), data, 0o644); err != nil {
				return nil, err
			}
		}
		extra = append(extra, "-mod=mod", "-modfile="+filepath.Join(tmp, "go.mod"))
	}
	pkgs, err := loader.GoList(c.Ctx, loader.Config{Env: env, Dir: dir, Patterns: pats}, extra...)
	if err != nil {
		return nil, err
	}
	g := &pkgGraph{pkgs: map[string]*loader.Package{}, imports: map[string][]string{}, tests: tests}
	for _, pk := range pkgs {
		if pk.ForTest != "" || strings.HasSuffix(pk.ImportPath, ".test") || strings.Contains(pk.ImportPath, " [") {
			continue
		}
		if _, dup := g.pkgs[pk.ImportPath]; dup {
			continue
		}
		g.pkgs[pk.ImportPath] = pk
		if pk.Error != nil {
			g.errors = append(g.errors, pk.ImportPath+": "+strings.TrimSpace(pk.Error.Err))
		}
	}
	for path, pk := range g.pkgs {
		imps := append([]string(nil), pk.Imports...)
		switch {
		case pk.InMainModule() && !pk.DepOnly:
			g.roots = append(g.roots, path)
			if tests && (len(pk.TestImports) > 0 || len(pk.XTestImports) > 0) {
				t := path + ".test"
				var ti []string
				for _, x := range append(append([]string(nil), pk.TestImports...), pk.XTestImports...) {
					if x != path {
						ti = append(ti, x)
					}
				}
				g.imports[t] = uniqSorted(ti)
				imps = append(imps, t)
			}
		case tools[path]:
			g.tools = append(g.tools, path)
		}
		g.imports[path] = uniqSorted(imps)
	}
	sort.Strings(g.roots)
	sort.Strings(g.tools)
	sort.Strings(g.errors)
	return g, nil
}

func uniqSorted(s []string) []string {
	sort.Strings(s)
	out := s[:0]
	for i, x := range s {
		if i == 0 || x != s[i-1] {
			out = append(out, x)
		}
	}
	return out
}

// modOf returns the module path of a package node ("" for std / unknown).
func (g *pkgGraph) modOf(node string) string {
	pk := g.pkgs[strings.TrimSuffix(node, ".test")]
	if pk == nil || pk.Standard {
		return ""
	}
	return pk.ModulePath()
}

func (g *pkgGraph) isMainPkg(node string) bool {
	pk := g.pkgs[strings.TrimSuffix(node, ".test")]
	return pk != nil && pk.InMainModule()
}

// chainTo returns the shortest import chain from a main-module package to
// a package of module modPath, like `go mod why -m`.
func (g *pkgGraph) chainTo(modPath string) []string {
	return g.chain(func(n string) bool { return !strings.HasSuffix(n, ".test") && g.modOf(n) == modPath })
}

func (g *pkgGraph) chain(match func(string) bool) []string {
	prev := map[string]string{}
	seen := map[string]bool{}
	q := append(append([]string(nil), g.roots...), g.tools...)
	for _, r := range q {
		seen[r] = true
	}
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		if match(cur) {
			var chain []string
			for n := cur; ; {
				chain = append([]string{n}, chain...)
				p, ok := prev[n]
				if !ok {
					break
				}
				n = p
			}
			return chain
		}
		for _, n := range g.imports[cur] {
			if !seen[n] {
				seen[n] = true
				prev[n] = cur
				q = append(q, n)
			}
		}
	}
	return nil
}

// reachableModules returns the module paths of every package reachable
// from the main-module packages and tools. With withTests false, the
// edges into "p.test" nodes are not followed.
func (g *pkgGraph) reachableModules(withTests bool) map[string]bool {
	out := map[string]bool{}
	seen := map[string]bool{}
	q := append(append([]string(nil), g.roots...), g.tools...)
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		if seen[cur] {
			continue
		}
		seen[cur] = true
		if strings.HasSuffix(cur, ".test") {
			if !withTests {
				continue
			}
		} else if m := g.modOf(cur); m != "" && !g.isMainPkg(cur) {
			out[m] = true
		}
		q = append(q, g.imports[cur]...)
	}
	return out
}

// importUse classifies how the main module uses each dependency module.
type importUse struct {
	Direct     map[string]bool // imported by non-test main-module code
	DirectTest map[string]bool // imported by main-module test code
	Provides   map[string]bool // provides a package in "all" (tests of main packages included)
	NonTest    map[string]bool // provides a package needed without tests
}

func (g *pkgGraph) uses() importUse {
	u := importUse{Direct: map[string]bool{}, DirectTest: map[string]bool{},
		Provides: g.reachableModules(true), NonTest: g.reachableModules(false)}
	for _, r := range g.roots {
		for _, imp := range g.imports[r] {
			if strings.HasSuffix(imp, ".test") || g.isMainPkg(imp) {
				continue
			}
			if m := g.modOf(imp); m != "" {
				u.Direct[m] = true
			}
		}
		for _, imp := range g.imports[r+".test"] {
			if g.isMainPkg(imp) {
				continue
			}
			if m := g.modOf(imp); m != "" {
				u.DirectTest[m] = true
			}
		}
	}
	return u
}

// importers returns, for each package, the packages that import it
// (test pseudo-nodes included), sorted.
func (g *pkgGraph) importers() map[string][]string {
	out := map[string][]string{}
	for from, imps := range g.imports {
		for _, to := range imps {
			if strings.HasSuffix(to, ".test") {
				continue
			}
			out[to] = append(out[to], from)
		}
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

// ---------- module graph helpers ----------

// goModOf returns the go.mod of m the way the graph reads it (honouring
// replacements).
func goModOf(ctx context.Context, c *cli.Context, g *modgraph.Graph, m module.Version) ([]byte, error) {
	if r, base := g.FindReplace(m); r != nil {
		if r.IsLocal() {
			dir := r.New.Path
			if !filepath.IsAbs(dir) {
				dir = filepath.Join(base, dir)
			}
			return os.ReadFile(filepath.Join(dir, "go.mod"))
		}
		return c.Proxy().GoMod(ctx, r.New.Path, r.New.Version)
	}
	return c.Proxy().GoMod(ctx, m.Path, m.Version)
}

// goModFiles fetches and parses the go.mod files of mods concurrently.
// Modules whose go.mod could not be fetched are omitted; the first error
// that is not "not found" is returned.
func goModFiles(c *cli.Context, g *modgraph.Graph, mods []module.Version) (map[module.Version]*modfile.File, error) {
	res, errs := par.Map(c.Ctx, 8, mods, func(ctx context.Context, m module.Version) (*modfile.File, error) {
		data, err := goModOf(ctx, c, g, m)
		if err != nil {
			return nil, err
		}
		return modfile.Parse(m.String()+"/go.mod", data), nil
	})
	out := map[module.Version]*modfile.File{}
	var firstErr error
	for i, m := range mods {
		if res[i] != nil {
			out[m] = res[i]
		} else if errs[i] != nil && !errors.Is(errs[i], modproxy.ErrNotFound) && !errors.Is(errs[i], fs.ErrNotExist) && firstErr == nil {
			firstErr = errs[i]
		}
	}
	return out, firstErr
}

// rawRequires returns the requirements of loaded graph nodes as written in
// their go.mod files, including ones dropped by exclude directives.
func rawRequires(c *cli.Context, g *modgraph.Graph) (map[module.Version][]module.Version, error) {
	var nodes []module.Version
	for m := range g.Reqs {
		if m.Version != "" {
			nodes = append(nodes, m)
		}
	}
	module.Sort(nodes)
	files, err := goModFiles(c, g, nodes)
	out := map[module.Version][]module.Version{}
	for _, m := range nodes {
		f := files[m]
		if f == nil {
			out[m] = g.Reqs[m]
			continue
		}
		var reqs []module.Version
		for _, r := range f.Require {
			reqs = append(reqs, r.Mod)
		}
		out[m] = reqs
	}
	for _, m := range g.Mains {
		out[m] = g.Reqs[m]
	}
	return out, err
}

// unloaded returns the graph nodes whose go.mod was not read because of
// graph pruning (their requirements are not part of the graph).
func unloaded(g *modgraph.Graph) []module.Version {
	var out []module.Version
	for _, m := range g.Nodes() {
		if m.Version == "" || m.Version == "none" {
			continue
		}
		if _, ok := g.Reqs[m]; ok {
			continue
		}
		if _, bad := g.Errors[m]; bad {
			continue
		}
		out = append(out, m)
	}
	return out
}

// loaded reports whether the graph read m's go.mod (main modules count as
// loaded).
func loaded(g *modgraph.Graph, m module.Version) bool {
	if m.Version == "" && g.IsMain(m.Path) {
		return true
	}
	_, ok := g.Reqs[m]
	return ok
}

// nodeID renders a graph node like 'go mod graph': the bare path for main
// modules, path@version otherwise (also for other versions of a main
// module's path, which are ordinary graph nodes).
func nodeID(_ *modgraph.Graph, m module.Version) string {
	if m.Version == "" {
		return m.Path
	}
	return m.Path + "@" + m.Version
}

func chainStrings(g *modgraph.Graph, chain []module.Version) []string {
	out := []string{}
	for _, m := range chain {
		out = append(out, nodeID(g, m))
	}
	return out
}

// parseModArg parses "path" or "path@version".
func parseModArg(arg string) (module.Version, error) {
	path, ver, _ := strings.Cut(arg, "@")
	if err := module.CheckPath(path); err != nil {
		return module.Version{}, cli.Usagef("invalid module %q: %v", arg, err)
	}
	if strings.Contains(arg, "@") && ver == "" {
		return module.Version{}, cli.Usagef("invalid module %q: empty version", arg)
	}
	return module.Version{Path: path, Version: ver}, nil
}

// replaceString renders a replacement target.
func replaceString(r module.Version) string {
	if r.Version == "" {
		return r.Path
	}
	return r.Path + " " + r.Version
}

// ---------- findings ----------

// failOnFlag registers --fail-on.
func failOnFlag(fs *flag.FlagSet, def string) func() (report.Severity, error) {
	return cli.SeverityFlag(fs, "fail-on", def, "exit with code 1 when a finding is at least this severe (info, low, medium, high, critical, none)")
}

// finish sorts findings, records the exit status and returns the summary.
func finish(c *cli.Context, fs []report.Finding, failOn report.Severity) severitySummary {
	report.SortFindings(fs)
	s := summarize(fs, failOn)
	if s.Failing > 0 {
		c.Issues()
	}
	return s
}

// printFindings renders findings.
func printFindings(c *cli.Context, fs []report.Finding) {
	for _, f := range fs {
		where := f.Where()
		c.Out.Printf("  %s %s\n", c.Out.Sev(f.Severity), c.Out.Bold(f.Title))
		if where != "" && !strings.Contains(f.Title, where) {
			c.Out.Printf("           %s\n", c.Out.Dim(where))
		}
		if f.Detail != "" {
			for _, line := range wrap(f.Detail, 88) {
				c.Out.Printf("           %s\n", line)
			}
		}
		if f.Fix != "" {
			c.Out.Printf("           %s %s\n", c.Out.Green("fix:"), f.Fix)
		}
	}
}

// wrap splits s into lines of at most n runes on word boundaries.
func wrap(s string, n int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		line := ""
		for _, w := range strings.Fields(para) {
			if line != "" && ui.Width(line)+1+ui.Width(w) > n {
				out = append(out, line)
				line = ""
			}
			if line != "" {
				line += " "
			}
			line += w
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// severitySummary is the summary block shared by finding-based tools.
type severitySummary struct {
	Findings int            `json:"findings"`
	BySev    map[string]int `json:"bySeverity"`
	Max      string         `json:"maxSeverity"`
	FailOn   string         `json:"failOn"`
	Failing  int            `json:"failing"`
}

func summarize(fs []report.Finding, failOn report.Severity) severitySummary {
	s := severitySummary{Findings: len(fs), BySev: report.Counts(fs), Max: report.Max(fs).String(), FailOn: failOn.String()}
	if failOn != report.None {
		s.Failing = len(report.AtLeast(fs, failOn))
	}
	return s
}

// sevLine renders "2 medium · 1 low" (or "no findings").
func sevLine(fs []report.Finding) string {
	counts := report.Counts(fs)
	var parts []string
	for s := report.Critical; s >= report.Info; s-- {
		if n := counts[s.String()]; n > 0 {
			parts = append(parts, strconv.Itoa(n)+" "+s.String())
		}
	}
	if len(parts) == 0 {
		return "no findings"
	}
	return strings.Join(parts, " · ")
}

// printSummaryLine prints the closing line of a finding-based tool.
func printSummaryLine(c *cli.Context, fs []report.Finding, s severitySummary) {
	c.Out.Println()
	switch {
	case len(fs) == 0:
		c.Out.OK("no findings")
	case s.Failing > 0:
		c.Out.Bad("%s (%d at or above --fail-on %s)", sevLine(fs), s.Failing, s.FailOn)
	default:
		c.Out.Warn("%s (none at or above --fail-on %s)", sevLine(fs), s.FailOn)
	}
}

// relTo renders path relative to base for display.
func relTo(base, path string) string {
	if rel, err := filepath.Rel(base, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return path
}
