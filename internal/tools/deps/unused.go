package deps

import (
	"flag"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/modgraph"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/semver"
)

var unusedFlags struct {
	failOn func() (report.Severity, error)
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "unused",
		Group:   group,
		Summary: "Unused, test-only and misplaced // indirect requirements (go mod tidy semantics)",
		Usage:   "sm-go unused [flags]",
		Help: `Compares the main module's require directives with what 'go mod tidy'
would write, without modifying any file.

The package import graph of the main module (all packages, their tests,
and tool directives) is loaded with go list on a temporary copy of go.mod.
Every module that provides a package in that graph is needed; for a
go >= 1.17 module tidy lists all of them, at their selected versions,
marking those imported by a main-module package or test as direct and the
rest // indirect. For go < 1.17 modules only direct requirements and the
indirect ones needed to keep the selected versions are listed.

Findings:
  unused requirement    no package of the main module or its tests imports
                        the module, directly or indirectly (tidy removes it)
  missing requirement   a needed module is not listed (go >= 1.17 builds
                        with -mod=readonly fail), or an import is not
                        provided by any module
  // indirect           marked indirect but imported directly, or the
                        opposite
  below selected        the requirement is lower than the selected version
  test-only             needed only by tests of the main module (info)

In a workspace, the module in the current directory is analysed on its
own (GOWORK=off), as 'go mod tidy' does.`,
		Examples: []string{
			"sm-go unused",
			"sm-go unused --fail-on medium --json",
		},
		Sources: []string{"go list", "Go module proxy (go.mod files)"},
		NeedsGo: true,
		Flags: func(fs *flag.FlagSet) {
			unusedFlags.failOn = failOnFlag(fs, "low")
		},
		Run: runUnused,
	})
}

type unusedReq struct {
	Path     string `json:"path"`
	Version  string `json:"version"`
	Indirect bool   `json:"indirect"`
	Line     int    `json:"line,omitempty"`
	// Status is ok, unused, should-be-indirect, should-be-direct,
	// below-selected, excluded or missing.
	Status   string `json:"status"`
	Needed   bool   `json:"needed"`
	Direct   bool   `json:"direct"`
	TestOnly bool   `json:"testOnly,omitempty"`
	Selected string `json:"selected,omitempty"`
}

type tidyReq struct {
	Path     string `json:"path"`
	Version  string `json:"version"`
	Indirect bool   `json:"indirect"`
}

type unusedResult struct {
	Module       string           `json:"module"`
	GoVersion    string           `json:"goVersion"`
	Pruned       bool             `json:"pruned"`
	Standalone   bool             `json:"standalone,omitempty"`
	Requirements []unusedReq      `json:"requirements"`
	Missing      []unusedReq      `json:"missing"`
	TestOnly     []string         `json:"testOnly"`
	Tidy         []tidyReq        `json:"tidy"`
	ImportErrors []string         `json:"importErrors,omitempty"`
	Findings     []report.Finding `json:"findings"`
	Summary      severitySummary  `json:"summary"`
}

var noModuleRE = regexp.MustCompile(`no required module provides package ([^ ;:]+)`)

func runUnused(c *cli.Context) error {
	failOn, err := unusedFlags.failOn()
	if err != nil {
		return err
	}
	if len(c.Args) > 0 {
		return cli.Usagef("unexpected argument %q", c.Args[0])
	}
	p, err := c.Project()
	if err != nil {
		return err
	}
	env := c.Env
	standalone := false
	var g *modgraph.Graph
	if p.IsWorkspace() {
		standalone = true
		env = standaloneEnv(c)
		p, g, err = loadStandalone(c, p.ModDir)
		if err != nil {
			return err
		}
	} else if p, g, err = loadGraph(c); err != nil {
		return err
	}
	if p.GoMod == nil || p.GoMod.Module == nil {
		return fmt.Errorf("%s: no module directive", p.GoModPath)
	}
	pg, err := listPackages(c, env, p, true)
	if err != nil {
		return err
	}
	u := pg.uses()
	res := unusedResult{Module: p.ModulePath(), GoVersion: p.GoMod.Go, Pruned: g.Pruned, Standalone: standalone,
		Requirements: []unusedReq{}, Missing: []unusedReq{}, TestOnly: []string{}, Tidy: []tidyReq{}, Findings: []report.Finding{}}
	add := func(f report.Finding) { res.Findings = append(res.Findings, f) }
	gomod := p.Rel(p.GoModPath)
	if standalone {
		c.Warnf("workspace mode: analysing %s on its own (GOWORK=off), like 'go mod tidy'", p.ModulePath())
	}

	// Import errors: packages no module provides make the analysis
	// incomplete and break the build.
	for _, e := range pg.errors {
		if m := noModuleRE.FindStringSubmatch(e); m != nil {
			res.ImportErrors = append(res.ImportErrors, e)
			add(report.Finding{Severity: report.Medium, Rule: "missing-module", Package: m[1], File: gomod,
				Title:  fmt.Sprintf("no required module provides package %s", m[1]),
				Detail: "A package of the main module imports it, but no module in the build list provides it; the build fails.",
				Fix:    "go get " + m[1]})
			continue
		}
		res.ImportErrors = append(res.ImportErrors, e)
	}
	if len(res.ImportErrors) > 0 {
		c.Warnf("%s while loading packages; results may be incomplete", plural(len(res.ImportErrors), "error", "errors"))
	}

	needed := map[string]bool{}
	for m := range u.Provides {
		if !g.IsMain(m) {
			needed[m] = true
		}
	}
	direct := func(path string) bool { return u.Direct[path] || u.DirectTest[path] }
	tidy := map[string]tidyReq{}
	if g.Pruned {
		for m := range needed {
			if v := g.Selected[m]; v != "" {
				tidy[m] = tidyReq{Path: m, Version: v, Indirect: !direct(m)}
			}
		}
	} else {
		tidy, err = unprunedTidyRoots(c, p.Mains, g, needed, direct)
		if err != nil {
			return err
		}
	}
	for _, t := range tidy {
		res.Tidy = append(res.Tidy, t)
	}
	sort.Slice(res.Tidy, func(i, j int) bool { return res.Tidy[i].Path < res.Tidy[j].Path })
	for m := range needed {
		if !u.NonTest[m] {
			res.TestOnly = append(res.TestOnly, m)
		}
	}
	sort.Strings(res.TestOnly)

	listed := map[string]bool{}
	for _, r := range p.GoMod.Require {
		listed[r.Mod.Path] = true
		q := unusedReq{Path: r.Mod.Path, Version: r.Mod.Version, Indirect: r.Indirect, Line: r.Line, Needed: needed[r.Mod.Path],
			Direct: direct(r.Mod.Path), Selected: g.Selected[r.Mod.Path]}
		q.TestOnly = q.Needed && !u.NonTest[r.Mod.Path]
		f := report.Finding{Module: r.Mod.Path, Version: r.Mod.Version, File: gomod, Line: r.Line}
		t, keep := tidy[r.Mod.Path]
		switch {
		case p.GoMod.Excluded(r.Mod):
			q.Status = "excluded"
			f.Severity, f.Rule = report.Low, "excluded-requirement"
			f.Title = fmt.Sprintf("requirement %s %s names an excluded version", r.Mod.Path, r.Mod.Version)
			f.Detail = "The go command drops it (\"dropping requirement on excluded version\"); with -mod=readonly the build fails until go.mod is updated."
			f.Fix = "go mod tidy"
		case !keep:
			q.Status = "unused"
			f.Severity, f.Rule = report.Low, "unused-requirement"
			f.Title = fmt.Sprintf("unused requirement %s %s", r.Mod.Path, r.Mod.Version)
			if g.Pruned || !q.Needed {
				f.Detail = fmt.Sprintf("No package of %s or of its tests imports a package of %s, directly or through other modules; 'go mod tidy' removes it.", res.Module, r.Mod.Path)
			} else {
				f.Detail = fmt.Sprintf("Other requirements already select %s at %s; in a go < 1.17 module 'go mod tidy' removes the redundant indirect requirement.", r.Mod.Path, q.Selected)
			}
			f.Fix = "go mod tidy"
		case semver.Compare(r.Mod.Version, t.Version) < 0:
			q.Status = "below-selected"
			f.Severity, f.Rule = report.Low, "requirement-below-selected"
			f.Title = fmt.Sprintf("%s is required at %s but %s is selected", r.Mod.Path, r.Mod.Version, t.Version)
			f.Detail = "Another requirement raises the version; go.mod does not reflect what is built and 'go mod tidy' updates it."
			f.Fix = "go mod tidy"
		case r.Indirect && !t.Indirect:
			q.Status = "should-be-direct"
			f.Severity, f.Rule = report.Low, "wrong-indirect"
			f.Title = fmt.Sprintf("%s is imported directly but marked // indirect", r.Mod.Path)
			f.Detail = fmt.Sprintf("%s imports %s; 'go mod tidy' removes the // indirect comment.", importWho(pg, r.Mod.Path), r.Mod.Path)
			f.Fix = "go mod tidy"
		case !r.Indirect && t.Indirect:
			q.Status = "should-be-indirect"
			f.Severity, f.Rule = report.Low, "missing-indirect"
			f.Title = fmt.Sprintf("%s is not imported by the main module but not marked // indirect", r.Mod.Path)
			f.Detail = "It is needed only by other dependencies; 'go mod tidy' adds the // indirect comment."
			f.Fix = "go mod tidy"
		default:
			q.Status = "ok"
		}
		if q.Status != "ok" {
			add(f)
		}
		res.Requirements = append(res.Requirements, q)
	}
	var missing []string
	for m := range tidy {
		if !listed[m] {
			missing = append(missing, m)
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t := tidy[m]
		q := unusedReq{Path: m, Version: t.Version, Indirect: t.Indirect, Status: "missing", Needed: true, Direct: !t.Indirect, Selected: g.Selected[m], TestOnly: !u.NonTest[m]}
		res.Missing = append(res.Missing, q)
		kind := "indirect"
		if !t.Indirect {
			kind = "direct"
		}
		detail := fmt.Sprintf("%s provides packages the main module needs (selected %s) but go.mod does not list it.", m, t.Version)
		if g.Pruned {
			detail += " A go >= 1.17 go.mod must list every module that provides a package to the build; with -mod=readonly the go command reports \"updates to go.mod needed\"."
		}
		add(report.Finding{Severity: report.Medium, Rule: "missing-requirement", Module: m, Version: t.Version, File: gomod,
			Title: fmt.Sprintf("missing %s requirement %s %s", kind, m, t.Version), Detail: detail, Fix: "go mod tidy"})
	}
	for _, m := range res.TestOnly {
		add(report.Finding{Severity: report.Info, Rule: "test-only", Module: m, Version: g.Selected[m], File: gomod,
			Title:  fmt.Sprintf("%s is needed only by tests", m),
			Detail: fmt.Sprintf("Only test code of %s imports packages of %s (chain: %s); it is not linked into binaries but stays in go.mod and go.sum.", res.Module, m, strings.Join(pg.chainTo(m), " → "))})
	}
	res.Summary = finish(c, res.Findings, failOn)
	c.SetResult(res)
	if c.Text() {
		printUnused(c, res)
	}
	return nil
}

// importWho names the main-module packages importing a module.
func importWho(pg *pkgGraph, mod string) string {
	var who []string
	for _, r := range pg.roots {
		for _, n := range []string{r, r + ".test"} {
			for _, imp := range pg.imports[n] {
				if !strings.HasSuffix(imp, ".test") && pg.modOf(imp) == mod {
					who = append(who, n)
					break
				}
			}
		}
	}
	who = uniqSorted(who)
	if len(who) == 0 {
		return "the main module"
	}
	return ui3(who)
}

// unprunedTidyRoots computes the requirements 'go mod tidy' keeps for a
// go < 1.17 main module: the direct dependencies plus the indirect ones
// needed so that every needed module keeps its selected version.
func unprunedTidyRoots(c *cli.Context, mains []modgraph.Main, g *modgraph.Graph, needed map[string]bool, direct func(string) bool) (map[string]tidyReq, error) {
	out := map[string]tidyReq{}
	for m := range needed {
		if direct(m) && g.Selected[m] != "" {
			out[m] = tidyReq{Path: m, Version: g.Selected[m]}
		}
	}
	for iter := 0; iter < 50; iter++ {
		var roots []module.Version
		for _, t := range out {
			roots = append(roots, module.Version{Path: t.Path, Version: t.Version})
		}
		module.Sort(roots)
		ng, err := modgraph.Load(c.Ctx, modgraph.Config{Mains: mains, Fetch: c.Proxy(), Roots: roots, ForcePruning: "unpruned"})
		if err != nil {
			return nil, err
		}
		if err := fatalGraphError(ng); err != nil {
			return nil, err
		}
		var add []string
		for m := range needed {
			want := g.Selected[m]
			if _, ok := out[m]; ok || want == "" {
				continue
			}
			if got := ng.Selected[m]; got == "" || semver.Compare(got, want) < 0 {
				add = append(add, m)
			}
		}
		if len(add) == 0 {
			return out, nil
		}
		sort.Strings(add)
		// Add one at a time (lowest path first): adding a root can raise
		// other modules, making further indirect roots unnecessary.
		out[add[0]] = tidyReq{Path: add[0], Version: g.Selected[add[0]], Indirect: true}
	}
	return out, nil
}

func printUnused(c *cli.Context, r unusedResult) {
	o := c.Out
	mode := "pruned (go >= 1.17)"
	if !r.Pruned {
		mode = "unpruned (go < 1.17)"
	}
	o.Title(fmt.Sprintf("Requirements of %s · go %s · %s", r.Module, r.GoVersion, mode))
	var rows [][]string
	for _, q := range append(append([]unusedReq(nil), r.Requirements...), r.Missing...) {
		mark := "direct"
		if q.Indirect {
			mark = "// indirect"
		}
		st := q.Status
		switch q.Status {
		case "ok":
			st = o.Green("ok")
		case "missing":
			st = o.Red("missing")
		default:
			st = o.Yellow(st)
		}
		use := "not needed"
		switch {
		case q.TestOnly:
			use = "tests only"
		case q.Direct:
			use = "imported"
		case q.Needed:
			use = "transitive"
		}
		rows = append(rows, []string{q.Path, q.Version, mark, use, st})
	}
	if len(rows) > 0 {
		o.Println()
		o.Table([]string{"MODULE", "VERSION", "MARKED", "USE", "STATUS"}, rows)
	}
	if len(r.Findings) > 0 {
		o.Heading("Findings")
		printFindings(c, r.Findings)
	}
	printSummaryLine(c, r.Findings, r.Summary)
}
