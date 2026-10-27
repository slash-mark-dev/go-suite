package deps

import (
	"flag"
	"fmt"
	"sort"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/modgraph"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/project"
	"github.com/slash-mark-dev/go-suite/internal/semver"
)

var whyFlags struct {
	paths      *int
	noPackages *bool
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "why",
		Group:   group,
		Summary: "MVS explainer: why a module is selected at its version",
		Usage:   "sm-go why <module>[@version] ... [flags]",
		Help: `Explains Minimum Version Selection for one or more modules: every
requirement edge in the module graph that names the module and the version
it asks for, which requirement is the maximum (MVS selects the highest
version required by any module version in the graph, including versions
that are not themselves selected), the requirement paths from the main
module, and how the result is shaped by graph pruning (go >= 1.17: the
requirements of a dependency's dependencies are not loaded), exclude
directives (requirements on excluded versions are dropped) and replace
directives (they change where code and go.mod come from, not the selected
version).

With module@version it explains why that particular version is or is not
the selected one.

When the module provides packages, the shortest package import chain from
the main module (tests included) is shown, exactly like 'go mod why -m'.
A module that is not in the graph is reported like 'go mod why' does
("main module does not need module ..."); the exit code is 0.`,
		Examples: []string{
			"sm-go why golang.org/x/net",
			"sm-go why golang.org/x/text@v0.3.7",
			"sm-go why github.com/a/b github.com/c/d --json",
		},
		Sources: []string{"Go module proxy (go.mod files)", "go list"},
		Flags: func(fs *flag.FlagSet) {
			whyFlags.paths = fs.Int("paths", 3, "show at most `n` requirement paths per module")
			whyFlags.noPackages = fs.Bool("no-packages", false, "skip the package import chain (does not run go list)")
		},
		Run: runWhy,
	})
}

type whyEdge struct {
	From         string `json:"from"`
	FromSelected bool   `json:"fromSelected"`
	Version      string `json:"version"`
	Max          bool   `json:"max,omitempty"`
	Excluded     bool   `json:"excluded,omitempty"`
	Pruned       bool   `json:"pruned,omitempty"`
	Indirect     bool   `json:"indirect,omitempty"`
	// Via names the replacement whose go.mod declared this requirement.
	Via string `json:"via,omitempty"`
}

type whyReplace struct {
	File  string `json:"file"`
	Line  int    `json:"line"`
	Old   string `json:"old"`
	New   string `json:"new"`
	Local bool   `json:"local"`
}

type whyQuery struct {
	Version    string   `json:"version"`
	InGraph    bool     `json:"inGraph"`
	Selected   bool     `json:"selected"`
	RequiredBy []string `json:"requiredBy"`
}

type whyPackages struct {
	Needed bool     `json:"needed"`
	Chain  []string `json:"chain,omitempty"`
	Error  string   `json:"error,omitempty"`
}

type whyModule struct {
	Module       string       `json:"module"`
	InGraph      bool         `json:"inGraph"`
	Main         bool         `json:"main,omitempty"`
	Selected     string       `json:"selected,omitempty"`
	Direct       bool         `json:"direct"`
	Explanation  []string     `json:"explanation"`
	Requirements []whyEdge    `json:"requirements"`
	Ignored      []whyEdge    `json:"ignored"`
	Paths        [][]string   `json:"paths"`
	Replacement  *whyReplace  `json:"replacement,omitempty"`
	Excludes     []string     `json:"excludes,omitempty"`
	Query        *whyQuery    `json:"query,omitempty"`
	Packages     *whyPackages `json:"packages,omitempty"`
}

type whyResult struct {
	Pruned    bool        `json:"pruned"`
	Workspace bool        `json:"workspace"`
	Modules   []whyModule `json:"modules"`
}

// excludedBy reports whether a main module's go.mod excludes m.
func excludedBy(p *project.Project, m module.Version) bool {
	for _, mm := range p.Mains {
		if mm.File != nil && mm.File.Excluded(m) {
			return true
		}
	}
	return false
}

func runWhy(c *cli.Context) error {
	if len(c.Args) == 0 {
		return cli.Usagef("missing module argument")
	}
	if *whyFlags.paths < 0 {
		return cli.Usagef("--paths must be >= 0")
	}
	var targets []module.Version
	for _, a := range c.Args {
		m, err := parseModArg(a)
		if err != nil {
			return err
		}
		if m.Version != "" && !semver.IsValid(m.Version) {
			return cli.Usagef("invalid version %q in %s (want a semantic version such as v1.2.3)", m.Version, a)
		}
		targets = append(targets, m)
	}
	p, g, err := loadGraph(c)
	if err != nil {
		return err
	}
	raw, err := rawRequires(c, g)
	if err != nil {
		return err
	}
	// Requirements ignored because of pruning: those of graph nodes whose
	// go.mod the go command never reads.
	var pruned map[module.Version][]module.Version
	if g.Pruned {
		un := unloaded(g)
		files, err := goModFiles(c, g, un)
		if err != nil {
			return err
		}
		pruned = map[module.Version][]module.Version{}
		for m, f := range files {
			for _, r := range f.Require {
				pruned[m] = append(pruned[m], r.Mod)
			}
		}
	}
	var pg *pkgGraph
	var pkgErr error
	if !*whyFlags.noPackages {
		if !c.Env.HaveGo() {
			pkgErr = fmt.Errorf("the go command is not available")
		} else {
			pg, pkgErr = listPackages(c, c.Env, p, true)
		}
		if pkgErr != nil {
			c.Warnf("package import chains unavailable: %v", pkgErr)
		}
	}
	res := whyResult{Pruned: g.Pruned, Workspace: g.Workspace}
	for _, t := range targets {
		res.Modules = append(res.Modules, explainWhy(c, p, g, raw, pruned, pg, pkgErr, t))
	}
	c.SetResult(res)
	if c.Text() {
		for i, m := range res.Modules {
			if i > 0 {
				c.Out.Println()
			}
			printWhy(c, m)
		}
	}
	return nil
}

func explainWhy(c *cli.Context, p *project.Project, g *modgraph.Graph, raw, pruned map[module.Version][]module.Version,
	pg *pkgGraph, pkgErr error, t module.Version) whyModule {
	w := whyModule{Module: t.Path, Requirements: []whyEdge{}, Ignored: []whyEdge{}, Paths: [][]string{}, Explanation: []string{}}
	say := func(format string, a ...any) { w.Explanation = append(w.Explanation, fmt.Sprintf(format, a...)) }
	if t.Version != "" {
		w.Query = &whyQuery{Version: t.Version, RequiredBy: []string{}}
	}
	if g.IsMain(t.Path) {
		w.InGraph, w.Main = true, true
		say("%s is a main module: it is always selected, its requirements are the roots of the module graph and its replace and exclude directives apply to the whole graph.", t.Path)
		if w.Query != nil {
			say("A main module has no version; %s@%s is never used while %s is a main module.", t.Path, t.Version, t.Path)
		}
		return w
	}
	sel, inGraph := g.Selected[t.Path]
	w.InGraph = inGraph
	w.Direct = g.IsDirect(t.Path)

	// Requirement edges from the main modules (as written) and from every
	// loaded module version.
	for _, mm := range p.Mains {
		if mm.File == nil {
			continue
		}
		from := mm.Path()
		for _, r := range mm.File.Require {
			if r.Mod.Path != t.Path {
				continue
			}
			e := whyEdge{From: from, FromSelected: true, Version: r.Mod.Version, Indirect: r.Indirect, Excluded: excludedBy(p, r.Mod)}
			if e.Excluded {
				w.Ignored = append(w.Ignored, e)
			} else {
				w.Requirements = append(w.Requirements, e)
			}
		}
	}
	// Roots raised by the go command's consistency rules.
	for _, r := range g.Roots {
		if r.Path != t.Path {
			continue
		}
		written := false
		for _, o := range g.OriginalRoots {
			if o == r {
				written = true
			}
		}
		if !written {
			say("The go.mod requirement is inconsistent with the rest of the graph; the go command raises it to %s (go mod tidy writes that).", r.Version)
			w.Requirements = append(w.Requirements, whyEdge{From: g.Mains[0].Path, FromSelected: true, Version: r.Version})
		}
	}
	for from, reqs := range raw {
		if from.Version == "" {
			continue
		}
		for _, r := range reqs {
			if r.Path != t.Path {
				continue
			}
			e := whyEdge{From: nodeID(g, from), FromSelected: g.IsSelected(from), Version: r.Version, Excluded: excludedBy(p, r)}
			if rep, ok := g.Replacement[from]; ok {
				e.Via = replaceString(rep)
			}
			if e.Excluded {
				w.Ignored = append(w.Ignored, e)
			} else {
				w.Requirements = append(w.Requirements, e)
			}
		}
	}
	for from, reqs := range pruned {
		for _, r := range reqs {
			if r.Path == t.Path {
				w.Ignored = append(w.Ignored, whyEdge{From: nodeID(g, from), FromSelected: g.IsSelected(from), Version: r.Version, Pruned: true})
			}
		}
	}
	sortEdges(w.Requirements)
	sortEdges(w.Ignored)
	maxV := ""
	for _, e := range w.Requirements {
		if maxV == "" || semver.Compare(e.Version, maxV) > 0 {
			maxV = e.Version
		}
	}
	for i := range w.Requirements {
		w.Requirements[i].Max = w.Requirements[i].Version == maxV
	}
	for _, mm := range p.Mains {
		if mm.File == nil {
			continue
		}
		for _, e := range mm.File.Exclude {
			if e.Mod.Path == t.Path {
				w.Excludes = append(w.Excludes, e.Mod.Version)
			}
		}
	}

	if !inGraph {
		say("(main module does not need module %s)", t.Path)
		say("No module in the module graph requires %s, so it is not in the build list.", t.Path)
		if len(w.Ignored) > 0 {
			say("Requirements on it exist but are not part of the graph (see ignored requirements).")
		}
		if w.Query != nil {
			say("%s@%s is therefore not used.", t.Path, t.Version)
		}
		explainPackages(&w, pg, pkgErr)
		return w
	}
	w.Selected = sel

	// Main explanation.
	var winners []string
	for _, e := range w.Requirements {
		if e.Max {
			winners = append(winners, e.From)
		}
	}
	say("MVS selects the highest version of %s required anywhere in the module graph: %s, required by %s.", t.Path, sel, strings.Join(winners, ", "))
	if len(w.Requirements) > 1 {
		lower := map[string]bool{}
		for _, e := range w.Requirements {
			if !e.Max {
				lower[e.Version] = true
			}
		}
		if len(lower) > 0 {
			var ls []string
			for v := range lower {
				ls = append(ls, v)
			}
			semver.Sort(ls)
			say("Lower requirements (%s) are satisfied by %s: MVS never downgrades.", strings.Join(ls, ", "), sel)
		}
	}
	allUnselected := len(winners) > 0
	for _, e := range w.Requirements {
		if e.Max && e.FromSelected {
			allUnselected = false
		}
	}
	if allUnselected {
		say("Every module asking for %s is itself a non-selected version; MVS still counts the requirements of every module version in the graph, so %s stays selected even though its requirers were upgraded.", sel, sel)
	}
	if w.Direct {
		for _, mm := range p.Mains {
			if mm.File == nil {
				continue
			}
			for _, r := range mm.File.Require {
				if r.Mod.Path == t.Path && semver.Compare(r.Mod.Version, sel) < 0 && !excludedBy(p, r.Mod) {
					say("The main module requires %s but a dependency requires the higher %s; 'go mod tidy' would update the requirement.", r.Mod.Version, sel)
				}
			}
		}
	}

	// Pruning.
	if g.Pruned {
		higher := ""
		var who []string
		for _, e := range w.Ignored {
			if !e.Pruned || semver.Compare(e.Version, sel) <= 0 {
				continue
			}
			if higher == "" || semver.Compare(e.Version, higher) > 0 {
				higher, who = e.Version, nil
			}
			if e.Version == higher {
				who = append(who, e.From)
			}
		}
		if higher != "" {
			say("Graph pruning matters here: %s requires %s, but its go.mod is pruned out of the graph (go >= 1.17 loads only the requirements of modules the main module requires and of go < 1.17 modules), so that requirement is ignored. Without pruning MVS would select at least %s.",
				strings.Join(who, ", "), higher, higher)
		} else if n := countPruned(w.Ignored); n > 0 {
			say("%s ignored by graph pruning; none asks for a version above %s.", plural(n, "requirement is", "requirements are"), sel)
		}
	}
	// Exclusions.
	if len(w.Excludes) > 0 {
		say("The main go.mod excludes %s@%s: requirements naming excluded versions are dropped from the graph.", t.Path, strings.Join(w.Excludes, ", @"))
	}
	for _, e := range w.Ignored {
		if e.Excluded {
			say("%s requires excluded %s@%s; that requirement is dropped.", e.From, t.Path, e.Version)
		}
	}
	// Replacement.
	if r, base := g.FindReplace(module.Version{Path: t.Path, Version: sel}); r != nil {
		file := ""
		for _, mm := range p.Mains {
			if mm.Dir == base && mm.File != nil {
				file = relFile(c, mm.File.Name)
			}
		}
		if p.IsWorkspace() && base == p.Dir {
			file = relFile(c, p.WorkPath)
		}
		old := r.Old.Path
		if r.Old.Version != "" {
			old += " " + r.Old.Version
		}
		w.Replacement = &whyReplace{File: file, Line: r.Line, Old: old, New: replaceString(r.New), Local: r.IsLocal()}
		scope := "every version"
		if r.Old.Version != "" {
			scope = "version " + r.Old.Version
		}
		say("A replace directive (%s:%d) redirects %s of %s to %s: the source code and the go.mod (and so the requirements) come from the replacement, but the selected version is still %s, chosen by MVS.",
			file, r.Line, scope, t.Path, replaceString(r.New), sel)
	}
	for _, e := range w.Requirements {
		if e.Via != "" {
			say("Requirements of %s are read from its replacement %s.", e.From, e.Via)
		}
	}
	// Query.
	if q := w.Query; q != nil {
		for _, n := range g.Nodes() {
			if n.Path == t.Path && n.Version == q.Version {
				q.InGraph = true
			}
		}
		for _, e := range w.Requirements {
			if e.Version == q.Version {
				q.RequiredBy = append(q.RequiredBy, e.From)
			}
		}
		q.Selected = q.Version == sel
		switch c := semver.Compare(q.Version, sel); {
		case c == 0:
			say("%s@%s is the selected version.", t.Path, q.Version)
		case c < 0 && q.InGraph:
			say("%s@%s is in the module graph (required by %s) but is not selected: %s requires the higher %s.",
				t.Path, q.Version, orNone(q.RequiredBy), strings.Join(winners, ", "), sel)
		case c < 0:
			say("No module in the graph requires %s@%s; the selected %s is higher.", t.Path, q.Version, sel)
		default:
			say("No module in the graph requires %s@%s or higher; it would only be used after 'go get %s@%s'.", t.Path, q.Version, t.Path, q.Version)
		}
	}

	// Requirement paths to the modules that ask for the selected version.
	seen := map[string]bool{}
	for _, e := range w.Requirements {
		if len(w.Paths) >= *whyFlags.paths {
			break
		}
		if !e.Max {
			continue
		}
		var chain []string
		if g.IsMain(e.From) {
			chain = []string{e.From}
		} else {
			path, ver, _ := strings.Cut(e.From, "@")
			chain = chainStrings(g, g.Chain(module.Version{Path: path, Version: ver}))
			if len(chain) == 0 {
				continue
			}
		}
		chain = append(chain, t.Path+"@"+e.Version)
		key := strings.Join(chain, " ")
		if !seen[key] {
			seen[key] = true
			w.Paths = append(w.Paths, chain)
		}
	}
	explainPackages(&w, pg, pkgErr)
	return w
}

func explainPackages(w *whyModule, pg *pkgGraph, pkgErr error) {
	if pkgErr != nil {
		w.Packages = &whyPackages{Error: pkgErr.Error()}
		return
	}
	if pg == nil {
		return
	}
	w.Packages = &whyPackages{}
	if ch := pg.chainTo(w.Module); ch != nil {
		w.Packages.Needed, w.Packages.Chain = true, ch
		w.Explanation = append(w.Explanation, fmt.Sprintf("Packages of %s are imported by the main module (chain of %d packages).", w.Module, len(ch)))
	} else if w.InGraph {
		w.Explanation = append(w.Explanation, fmt.Sprintf("No package of %s is imported by the main module or its tests: it is in the build list only for its requirements (go.mod).", w.Module))
	}
}

func countPruned(es []whyEdge) int {
	n := 0
	for _, e := range es {
		if e.Pruned {
			n++
		}
	}
	return n
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}

func sortEdges(es []whyEdge) {
	sort.SliceStable(es, func(i, j int) bool {
		if c := semver.Compare(es[i].Version, es[j].Version); c != 0 {
			return c > 0
		}
		return es[i].From < es[j].From
	})
}

func printWhy(c *cli.Context, w whyModule) {
	o := c.Out
	switch {
	case w.Main:
		o.Title(w.Module + "  " + o.Green("main module"))
	case !w.InGraph:
		o.Title(w.Module + "  " + o.Yellow("not in the module graph"))
	default:
		direct := "indirect"
		if w.Direct {
			direct = "direct"
		}
		o.Title(fmt.Sprintf("%s  selected %s  %s", w.Module, o.Green(w.Selected), o.Dim("("+direct+")")))
	}
	for _, line := range w.Explanation {
		for i, l := range wrap(line, 92) {
			if i == 0 {
				o.Printf("  • %s\n", l)
			} else {
				o.Printf("    %s\n", l)
			}
		}
	}
	if len(w.Requirements) > 0 {
		o.Heading(fmt.Sprintf("Requirements on %s (%d)", w.Module, len(w.Requirements)))
		var rows [][]string
		for _, e := range w.Requirements {
			note := []string{}
			if e.Max {
				note = append(note, o.Green("max → selected"))
			}
			if !e.FromSelected {
				note = append(note, o.Dim("requirer not selected"))
			}
			if e.Indirect {
				note = append(note, "// indirect")
			}
			if e.Via != "" {
				note = append(note, "via "+e.Via)
			}
			rows = append(rows, []string{e.Version, e.From, strings.Join(note, " · ")})
		}
		o.Table([]string{"VERSION", "REQUIRED BY", "NOTE"}, rows)
	}
	if len(w.Ignored) > 0 {
		o.Heading(fmt.Sprintf("Ignored requirements (%d)", len(w.Ignored)))
		var rows [][]string
		for _, e := range w.Ignored {
			why := "pruned (go.mod not loaded)"
			if e.Excluded {
				why = "excluded"
			}
			rows = append(rows, []string{e.Version, e.From, why})
		}
		o.Table([]string{"VERSION", "REQUIRED BY", "WHY IGNORED"}, rows)
	}
	if len(w.Paths) > 0 {
		o.Heading("Requirement paths from the main module")
		for _, p := range w.Paths {
			o.Printf("  %s\n", strings.Join(p, o.Dim(" → ")))
		}
	}
	if w.Packages != nil {
		o.Heading("Package import chain (go mod why -m)")
		switch {
		case w.Packages.Error != "":
			o.Printf("  %s\n", o.Dim("unavailable: "+w.Packages.Error))
		case w.Packages.Needed:
			for _, p := range w.Packages.Chain {
				o.Printf("  %s\n", p)
			}
		default:
			o.Printf("  %s\n", o.Dim("(main module does not need to import any package of "+w.Module+")"))
		}
	}
}

// relFile renders a file path relative to the project directory.
func relFile(c *cli.Context, path string) string {
	if p, err := c.Project(); err == nil {
		return p.Rel(path)
	}
	return path
}
