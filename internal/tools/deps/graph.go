package deps

import (
	"encoding/json"
	"flag"
	"fmt"
	"sort"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/modgraph"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/project"
)

var graphFlags struct {
	format   *string
	depth    *int
	focus    cli.StringList
	pruned   *bool
	selected *bool
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "graph",
		Group:   group,
		Summary: "Pruned module graph as a tree, go mod graph text, DOT, Mermaid or JSON",
		Usage:   "sm-go graph [--format tree|text|dot|mermaid|json] [--depth n] [--focus module] [flags]",
		Help: `Renders the module requirement graph exactly as the go command builds
it for Minimum Version Selection: with graph pruning for go >= 1.17 main
modules (a dependency's own requirements are recorded, theirs are not
loaded), main-module exclude directives (requirements on excluded versions
are dropped) and replace directives (go.mod files are read from the
replacement).

Every node is a module version: main modules, selected versions (the build
list) and non-selected versions that are still part of the graph. Nodes
carry their depth (shortest requirement distance from a main module) and
whether their requirements were loaded.

Formats:
  tree     indented tree from the main module(s); repeated subtrees are
           marked (*), non-selected versions show the selected one
  text     one "from to" edge per line, identical to 'go mod graph'
           (including go@ and toolchain@ edges)
  dot      Graphviz; non-selected versions dashed, pruned and excluded
           edges styled
  mermaid  Mermaid flowchart
  json     the structured graph (same as the result of --json)

--pruned additionally reads the go.mod of every module whose requirements
were pruned out and draws those requirements as "pruned" edges: they are
ignored by MVS. Excluded requirements are always shown as "excluded"
edges. --focus keeps only the nodes on paths from the main module to the
focused module and the focused module's own requirements; --depth limits
the distance from the main module; --selected hides non-selected versions.`,
		Examples: []string{
			"sm-go graph",
			"sm-go graph --format dot | dot -Tsvg > deps.svg",
			"sm-go graph --format mermaid --depth 2",
			"sm-go graph --focus golang.org/x/net --pruned",
			"sm-go graph --format text | sort",
		},
		Sources: []string{"Go module proxy (go.mod files)"},
		Flags: func(fs *flag.FlagSet) {
			graphFlags.format = fs.String("format", "tree", "output `format`: tree, text, dot, mermaid or json")
			graphFlags.depth = fs.Int("depth", 0, "show nodes at most `n` requirement steps from the main module (0 = unlimited)")
			graphFlags.focus = nil
			fs.Var(&graphFlags.focus, "focus", "keep only paths to `module[@version]` and its requirements (repeatable)")
			graphFlags.pruned = fs.Bool("pruned", false, "also load go.mod files pruned out of the graph and show their requirements as pruned edges")
			graphFlags.selected = fs.Bool("selected", false, "show only selected versions (the build list) and main modules")
		},
		Run: runGraph,
	})
}

type graphNode struct {
	ID          string `json:"id"`
	Path        string `json:"path"`
	Version     string `json:"version,omitempty"`
	Main        bool   `json:"main,omitempty"`
	Selected    bool   `json:"selected"`
	SelectedAs  string `json:"selectedVersion,omitempty"` // selected version when this one is not
	Depth       int    `json:"depth"`
	Loaded      bool   `json:"loaded"`              // requirements are part of the graph
	PrunedOut   bool   `json:"prunedOut,omitempty"` // only reachable through pruned edges
	Excluded    bool   `json:"excluded,omitempty"`
	Go          string `json:"go,omitempty"`
	Replacement string `json:"replacement,omitempty"`
	Error       string `json:"error,omitempty"`
}

type graphEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Pruned   bool   `json:"pruned,omitempty"`
	Excluded bool   `json:"excluded,omitempty"`
}

type graphStats struct {
	Nodes       int `json:"nodes"`
	Edges       int `json:"edges"`
	Selected    int `json:"selected"`
	NotSelected int `json:"notSelected"`
	PrunedEdges int `json:"prunedEdges"`
	Excluded    int `json:"excludedEdges"`
	MaxDepth    int `json:"maxDepth"`
}

type graphResult struct {
	Format    string      `json:"format"`
	Pruned    bool        `json:"pruned"`
	Workspace bool        `json:"workspace"`
	Mains     []string    `json:"mains"`
	Focus     []string    `json:"focus,omitempty"`
	Depth     int         `json:"depthLimit,omitempty"`
	Nodes     []graphNode `json:"nodes"`
	Edges     []graphEdge `json:"edges"`
	Stats     graphStats  `json:"stats"`

	byID map[string]*graphNode
	out  map[string][]graphEdge
	g    *modgraph.Graph
	p    *project.Project
}

func runGraph(c *cli.Context) error {
	format := strings.ToLower(*graphFlags.format)
	switch format {
	case "tree", "text", "dot", "mermaid", "json":
	default:
		return cli.Usagef("unknown --format %q (use tree, text, dot, mermaid or json)", *graphFlags.format)
	}
	if *graphFlags.depth < 0 {
		return cli.Usagef("--depth must be >= 0")
	}
	if len(c.Args) > 0 {
		return cli.Usagef("unexpected argument %q (use --focus to select a module)", c.Args[0])
	}
	var focus []module.Version
	for _, f := range graphFlags.focus {
		m, err := parseModArg(f)
		if err != nil {
			return err
		}
		focus = append(focus, m)
	}
	p, g, err := loadGraph(c)
	if err != nil {
		return err
	}
	r, err := buildGraph(c, p, g, *graphFlags.pruned)
	if err != nil {
		return err
	}
	r.Format = format
	if len(focus) > 0 {
		var ids []string
		for _, f := range focus {
			found := false
			for _, n := range r.Nodes {
				if n.Path == f.Path && (f.Version == "" || n.Version == f.Version) {
					ids = append(ids, n.ID)
					found = true
				}
			}
			if !found {
				return cli.Usagef("--focus %s: module is not in the module graph", f)
			}
			r.Focus = append(r.Focus, f.String())
		}
		r.keep(r.focusSet(ids))
	}
	if *graphFlags.selected {
		keep := map[string]bool{}
		for _, n := range r.Nodes {
			if n.Main || n.Selected {
				keep[n.ID] = true
			}
		}
		r.keep(keep)
	}
	if d := *graphFlags.depth; d > 0 {
		r.Depth = d
		keep := map[string]bool{}
		for _, n := range r.Nodes {
			if n.Depth <= d {
				keep[n.ID] = true
			}
		}
		r.keep(keep)
	}
	r.stats()
	c.SetResult(r)
	if !c.Text() {
		return nil
	}
	switch format {
	case "tree":
		printGraphTree(c, r)
	case "text":
		for _, l := range r.goModGraphLines() {
			c.Out.Println(l)
		}
	case "dot":
		c.Out.Printf("%s", r.dot())
	case "mermaid":
		c.Out.Printf("%s", r.mermaid())
	case "json":
		b, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return err
		}
		c.Out.Printf("%s\n", b)
	}
	return nil
}

// buildGraph converts the module graph into nodes and edges, adding
// excluded requirements and (optionally) requirements pruned out of the
// graph.
func buildGraph(c *cli.Context, p *project.Project, g *modgraph.Graph, withPruned bool) (*graphResult, error) {
	r := &graphResult{Pruned: g.Pruned, Workspace: g.Workspace, Mains: []string{}, byID: map[string]*graphNode{}, g: g, p: p}
	add := func(m module.Version) *graphNode {
		id := nodeID(g, m)
		if n, ok := r.byID[id]; ok {
			return n
		}
		n := &graphNode{ID: id, Path: m.Path, Main: m.Version == "" && g.IsMain(m.Path), Loaded: loaded(g, m), Depth: -1}
		if !n.Main {
			n.Version = m.Version
			n.Selected = g.IsSelected(m)
			if !n.Selected {
				n.SelectedAs = g.Selected[m.Path]
			}
		}
		n.Go = g.GoVersion[m]
		if rep, ok := g.Replacement[m]; ok {
			n.Replacement = replaceString(rep)
		}
		if err, ok := g.Errors[m]; ok {
			n.Error = err.Error()
		}
		r.byID[id] = n
		return n
	}
	for _, m := range g.Mains {
		add(m)
		r.Mains = append(r.Mains, m.Path)
	}
	for _, m := range g.Nodes() {
		add(m)
	}
	var edges []graphEdge
	active := map[[2]string]bool{}
	for _, e := range g.Edges() {
		add(e[0])
		add(e[1])
		k := [2]string{nodeID(g, e[0]), nodeID(g, e[1])}
		if !active[k] {
			active[k] = true
			edges = append(edges, graphEdge{From: k[0], To: k[1]})
		}
	}
	raw, err := rawRequires(c, g)
	if err != nil {
		return nil, err
	}
	for from, reqs := range raw {
		for _, to := range reqs {
			if !excludedBy(p, to) {
				continue
			}
			n := add(to)
			n.Excluded = true
			n.Selected = false
			edges = append(edges, graphEdge{From: nodeID(g, from), To: n.ID, Excluded: true})
		}
	}
	// Requirements written in main go.mod files on excluded versions.
	for _, mm := range p.Mains {
		if mm.File == nil {
			continue
		}
		for _, req := range mm.File.Require {
			if excludedBy(p, req.Mod) {
				n := add(req.Mod)
				n.Excluded, n.Selected = true, false
				e := graphEdge{From: mm.Path(), To: n.ID, Excluded: true}
				dup := false
				for _, x := range edges {
					if x == e {
						dup = true
					}
				}
				if !dup {
					edges = append(edges, e)
				}
			}
		}
	}
	if withPruned && g.Pruned {
		files, err := goModFiles(c, g, unloaded(g))
		if err != nil {
			return nil, err
		}
		var froms []module.Version
		for m := range files {
			froms = append(froms, m)
		}
		module.Sort(froms)
		for _, from := range froms {
			for _, req := range files[from].Require {
				if excludedBy(p, req.Mod) {
					continue
				}
				_, existed := r.byID[nodeID(g, req.Mod)]
				n := add(req.Mod)
				if !existed {
					n.PrunedOut = true
				}
				edges = append(edges, graphEdge{From: nodeID(g, from), To: n.ID, Pruned: true})
			}
		}
	}
	for _, n := range r.byID {
		r.Nodes = append(r.Nodes, *n)
	}
	r.Edges = edges
	r.index()
	// Depth: shortest distance from a main module over active edges first,
	// then over pruned/excluded edges for nodes reachable only that way.
	depth := map[string]int{}
	var q []string
	for _, m := range r.Mains {
		depth[m] = 0
		q = append(q, m)
	}
	bfs := func(allow func(graphEdge) bool) {
		for len(q) > 0 {
			cur := q[0]
			q = q[1:]
			for _, e := range r.out[cur] {
				if !allow(e) {
					continue
				}
				if _, ok := depth[e.To]; !ok {
					depth[e.To] = depth[cur] + 1
					q = append(q, e.To)
				}
			}
		}
	}
	bfs(func(e graphEdge) bool { return !e.Pruned && !e.Excluded })
	for id := range depth {
		q = append(q, id)
	}
	sort.Slice(q, func(i, j int) bool { return depth[q[i]] < depth[q[j]] || depth[q[i]] == depth[q[j]] && q[i] < q[j] })
	bfs(func(graphEdge) bool { return true })
	for i := range r.Nodes {
		if d, ok := depth[r.Nodes[i].ID]; ok {
			r.Nodes[i].Depth = d
		}
	}
	r.sortAll()
	return r, nil
}

func (r *graphResult) index() {
	r.byID = map[string]*graphNode{}
	for i := range r.Nodes {
		r.byID[r.Nodes[i].ID] = &r.Nodes[i]
	}
	r.out = map[string][]graphEdge{}
	for _, e := range r.Edges {
		r.out[e.From] = append(r.out[e.From], e)
	}
}

func (r *graphResult) sortAll() {
	rank := func(n *graphNode) int {
		if n.Main {
			return 0
		}
		return 1
	}
	sort.SliceStable(r.Nodes, func(i, j int) bool {
		a, b := &r.Nodes[i], &r.Nodes[j]
		if rank(a) != rank(b) {
			return rank(a) < rank(b)
		}
		if a.Main {
			return indexOf(r.Mains, a.Path) < indexOf(r.Mains, b.Path)
		}
		return lessMod(module.Version{Path: a.Path, Version: a.Version}, module.Version{Path: b.Path, Version: b.Version})
	})
	r.index()
	order := map[string]int{}
	for i, n := range r.Nodes {
		order[n.ID] = i
	}
	sort.SliceStable(r.Edges, func(i, j int) bool {
		a, b := r.Edges[i], r.Edges[j]
		if order[a.From] != order[b.From] {
			return order[a.From] < order[b.From]
		}
		return order[a.To] < order[b.To]
	})
	r.index()
}

func lessMod(a, b module.Version) bool {
	list := []module.Version{b, a}
	module.Sort(list)
	return list[0] == a && a != b
}

func indexOf(list []string, s string) int {
	for i, x := range list {
		if x == s {
			return i
		}
	}
	return len(list)
}

// focusSet returns the focused nodes, their ancestors and descendants.
func (r *graphResult) focusSet(ids []string) map[string]bool {
	in := map[string][]string{}
	for _, e := range r.Edges {
		in[e.To] = append(in[e.To], e.From)
	}
	keep := map[string]bool{}
	walk := func(start []string, next func(string) []string) {
		seen := map[string]bool{}
		q := append([]string(nil), start...)
		for len(q) > 0 {
			cur := q[0]
			q = q[1:]
			if seen[cur] {
				continue
			}
			seen[cur] = true
			keep[cur] = true
			q = append(q, next(cur)...)
		}
	}
	walk(ids, func(id string) []string { return in[id] })
	walk(ids, func(id string) []string {
		var out []string
		for _, e := range r.out[id] {
			out = append(out, e.To)
		}
		return out
	})
	return keep
}

// keep restricts the graph to the given node IDs.
func (r *graphResult) keep(ids map[string]bool) {
	var nodes []graphNode
	for _, n := range r.Nodes {
		if ids[n.ID] {
			nodes = append(nodes, n)
		}
	}
	var edges []graphEdge
	for _, e := range r.Edges {
		if ids[e.From] && ids[e.To] {
			edges = append(edges, e)
		}
	}
	r.Nodes, r.Edges = nodes, edges
	r.index()
}

func (r *graphResult) stats() {
	if r.Nodes == nil {
		r.Nodes = []graphNode{}
	}
	if r.Edges == nil {
		r.Edges = []graphEdge{}
	}
	s := graphStats{Nodes: len(r.Nodes), Edges: len(r.Edges)}
	for _, n := range r.Nodes {
		switch {
		case n.Main:
		case n.Selected:
			s.Selected++
		default:
			s.NotSelected++
		}
		if n.Depth > s.MaxDepth {
			s.MaxDepth = n.Depth
		}
	}
	for _, e := range r.Edges {
		if e.Pruned {
			s.PrunedEdges++
		}
		if e.Excluded {
			s.Excluded++
		}
	}
	r.Stats = s
}

// goModGraphLines renders the active edges exactly like 'go mod graph',
// following cmd/go's modload rules:
//
//   - a dependency requires go@V only when its go.mod says go >= 1.21;
//   - a single main module requires go@V (1.16 when absent) and its
//     toolchain line; in a workspace each main module is a go.mod summary
//     like any dependency, and go.work's go version is a graph root;
//   - go@V requires toolchain@goV for V >= 1.21;
//   - an unpruned (go < 1.17) main module's requirements are first
//     rewritten to the minimal list preserving the build list (mvs.Req).
func (r *graphResult) goModGraphLines() []string {
	var lines []string
	goNodes := map[string]bool{}
	goEdge := func(from, v string) {
		lines = append(lines, from+" go@"+v)
		goNodes[v] = true
	}
	var unprunedMain []module.Version
	if !r.Workspace && !r.Pruned && len(r.g.Mains) == 1 {
		unprunedMain = unprunedRoots(r.g, r.p)
	}
	for _, n := range r.Nodes {
		if !n.Loaded || n.Excluded || n.PrunedOut {
			continue
		}
		if n.Main && unprunedMain != nil {
			for _, m := range unprunedMain {
				lines = append(lines, n.ID+" "+nodeID(r.g, m))
			}
		} else {
			for _, e := range r.out[n.ID] {
				if !e.Pruned && !e.Excluded {
					lines = append(lines, e.From+" "+e.To)
				}
			}
		}
		switch {
		case n.Main && !r.Workspace:
			v := n.Go
			if v == "" {
				v = "1.16"
			}
			goEdge(n.ID, v)
			if tc := r.g.Toolchain[module.Version{Path: n.Path}]; tc != "" {
				lines = append(lines, n.ID+" toolchain@"+tc)
			}
		case n.Go != "" && modgraph.GoAtLeast(n.Go, "1.21"):
			lines = append(lines, n.ID+" go@"+n.Go)
			// go@V is itself loaded (and requires its toolchain) only
			// when n's requirements were expanded.
			if r.g.Expanded(module.Version{Path: n.Path, Version: n.Version}) || n.Main {
				goNodes[n.Go] = true
			}
		}
	}
	if r.Workspace && r.p != nil && r.p.Work != nil {
		v := r.p.Work.Go
		if v == "" {
			v = "1.18"
		}
		goNodes[v] = true
	}
	var gvs []string
	for v := range goNodes {
		if modgraph.GoAtLeast(v, "1.21") {
			gvs = append(gvs, v)
		}
	}
	sort.Slice(gvs, func(i, j int) bool { return modgraph.CompareGo(gvs[i], gvs[j]) > 0 })
	for _, v := range gvs {
		lines = append(lines, "go@"+v+" toolchain@go"+v)
	}
	return lines
}

// unprunedRoots reproduces updateUnprunedRoots for a go < 1.17 main
// module: roots still at their selected versions and direct requirements
// are kept (raised to their selected versions), then mvs.Req adds whatever
// else is needed to preserve the build list.
func unprunedRoots(g *modgraph.Graph, p *project.Project) []module.Version {
	main := g.Mains[0]
	build := g.BuildList()
	max := map[string]string{}
	for _, m := range build {
		max[m.Path] = m.Version
	}
	direct := map[string]bool{}
	if p != nil && len(p.Mains) == 1 && p.Mains[0].File != nil {
		for _, req := range p.Mains[0].File.Require {
			if !req.Indirect {
				direct[req.Mod.Path] = true
			}
		}
	}
	var base []string
	inBase := map[string]bool{}
	for _, root := range g.Roots {
		if !inBase[root.Path] && max[root.Path] == root.Version {
			base = append(base, root.Path)
			inBase[root.Path] = true
		}
	}
	for _, m := range build {
		if direct[m.Path] && !inBase[m.Path] {
			base = append(base, m.Path)
			inBase[m.Path] = true
		}
	}
	required := func(m module.Version) []module.Version {
		if m == main {
			return build
		}
		return g.Reqs[m]
	}
	// mvs.Req: postorder over the requirement graph...
	var postorder []module.Version
	reqCache := map[module.Version][]module.Version{main: nil}
	var walk func(module.Version)
	walk = func(m module.Version) {
		if _, ok := reqCache[m]; ok {
			return
		}
		rs := required(m)
		reqCache[m] = rs
		for _, m1 := range rs {
			walk(m1)
		}
		postorder = append(postorder, m)
	}
	for _, m := range build {
		walk(m)
	}
	// ...then the base modules, then anything not already implied.
	have := map[module.Version]bool{}
	walk = func(m module.Version) {
		if have[m] {
			return
		}
		have[m] = true
		for _, m1 := range reqCache[m] {
			walk(m1)
		}
	}
	var min []module.Version
	for _, path := range base {
		m := module.Version{Path: path, Version: max[path]}
		min = append(min, m)
		walk(m)
	}
	for i := len(postorder) - 1; i >= 0; i-- {
		m := postorder[i]
		if max[m.Path] != m.Version {
			continue
		}
		if !have[m] {
			min = append(min, m)
			walk(m)
		}
	}
	sort.Slice(min, func(i, j int) bool { return min[i].Path < min[j].Path })
	return min
}

func (n *graphNode) label() string {
	if n.Main {
		return n.Path
	}
	return n.Path + "@" + n.Version
}

func printGraphTree(c *cli.Context, r *graphResult) {
	o := c.Out
	mode := "pruned module graph (go >= 1.17)"
	if !r.Pruned {
		mode = "unpruned module graph (go < 1.17)"
	}
	if r.Workspace {
		mode = "workspace module graph"
	}
	o.Title(fmt.Sprintf("Module graph · %s", mode))
	o.Printf("%s\n\n", o.Dim(fmt.Sprintf("%d nodes · %d selected · %d not selected · %d edges · max depth %d",
		r.Stats.Nodes, r.Stats.Selected, r.Stats.NotSelected, r.Stats.Edges, r.Stats.MaxDepth)))
	expanded := map[string]bool{}
	sawPruned := false // a printed node is marked "requirements pruned"
	var walk func(id, prefix string, depth int, e *graphEdge, last bool)
	walk = func(id, prefix string, depth int, e *graphEdge, last bool) {
		n := r.byID[id]
		if n == nil {
			return
		}
		branch, childPrefix := "", ""
		if e != nil {
			branch = "├── "
			childPrefix = prefix + "│   "
			if last {
				branch = "└── "
				childPrefix = prefix + "    "
			}
		}
		label := n.label()
		var notes []string
		switch {
		case n.Main:
			label = o.Bold(label)
		case n.Excluded:
			label = o.Red(label)
		case !n.Selected:
			label = o.Dim(label)
			if n.SelectedAs != "" {
				notes = append(notes, "selected "+n.SelectedAs)
			}
		}
		if e != nil && e.Pruned {
			notes = append(notes, "pruned requirement")
		}
		if e != nil && e.Excluded {
			notes = append(notes, "excluded")
		}
		if n.Replacement != "" {
			notes = append(notes, "=> "+n.Replacement)
		}
		if !n.Loaded && !n.Excluded && n.Error == "" && !n.Main {
			notes = append(notes, "requirements pruned")
			sawPruned = true
		}
		if n.Error != "" {
			notes = append(notes, o.Red("error: "+n.Error))
		}
		children := r.out[id]
		repeat := expanded[id] && len(children) > 0
		if repeat {
			notes = append(notes, "(*)")
		}
		line := prefix + branch + label
		if len(notes) > 0 {
			line += "  " + o.Dim(strings.Join(notes, " · "))
		}
		o.Println(line)
		if repeat || (e != nil && (e.Pruned || e.Excluded) && !n.Loaded) {
			return
		}
		expanded[id] = true
		for i, ce := range children {
			ce := ce
			walk(ce.To, childPrefix, depth+1, &ce, i == len(children)-1)
		}
	}
	for _, m := range r.Mains {
		if r.byID[m] != nil {
			walk(m, "", 0, nil, true)
		}
	}
	// Focus or filters can leave nodes unreachable from the mains in the
	// kept subgraph; print them as extra roots.
	for _, n := range r.Nodes {
		if !expanded[n.ID] && !n.Main && len(r.out[n.ID]) > 0 {
			hasParent := false
			for _, e := range r.Edges {
				if e.To == n.ID {
					hasParent = true
					break
				}
			}
			if !hasParent {
				walk(n.ID, "", 0, nil, true)
			}
		}
	}
	if sawPruned && !*graphFlags.pruned {
		o.Printf("\n%s\n", o.Dim("Requirements of modules marked \"requirements pruned\" are not part of the graph; --pruned shows them."))
	}
}

func dotQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func (r *graphResult) dot() string {
	var b strings.Builder
	b.WriteString("digraph modules {\n")
	b.WriteString("\trankdir=LR;\n\tnode [shape=box, style=rounded, fontname=\"Helvetica\", fontsize=10];\n\tedge [color=\"#555555\"];\n")
	for _, n := range r.Nodes {
		label := n.Path
		if !n.Main {
			label += "\\n" + n.Version
		}
		attrs := []string{"label=\"" + strings.ReplaceAll(label, `"`, `\"`) + "\""}
		switch {
		case n.Main:
			attrs = append(attrs, "style=\"rounded,filled,bold\"", "fillcolor=\"#dbeafe\"")
		case n.Excluded:
			attrs = append(attrs, "color=red", "fontcolor=red", "style=\"rounded,dotted\"")
		case !n.Selected:
			attrs = append(attrs, "color=gray", "fontcolor=gray", "style=\"rounded,dashed\"")
		default:
			attrs = append(attrs, "style=\"rounded,filled\"", "fillcolor=\"#ecfdf5\"")
		}
		fmt.Fprintf(&b, "\t%s [%s];\n", dotQuote(n.ID), strings.Join(attrs, ", "))
	}
	for _, e := range r.Edges {
		attr := ""
		switch {
		case e.Excluded:
			attr = " [color=red, style=dotted, label=\"excluded\", fontsize=8]"
		case e.Pruned:
			attr = " [color=gray, style=dashed, label=\"pruned\", fontsize=8]"
		}
		fmt.Fprintf(&b, "\t%s -> %s%s;\n", dotQuote(e.From), dotQuote(e.To), attr)
	}
	b.WriteString("}\n")
	return b.String()
}

func (r *graphResult) mermaid() string {
	var b strings.Builder
	b.WriteString("graph LR\n")
	ids := map[string]string{}
	esc := strings.NewReplacer(`"`, "#quot;")
	var mains, unsel, excl []string
	for i, n := range r.Nodes {
		id := fmt.Sprintf("n%d", i)
		ids[n.ID] = id
		fmt.Fprintf(&b, "  %s[\"%s\"]\n", id, esc.Replace(n.label()))
		switch {
		case n.Main:
			mains = append(mains, id)
		case n.Excluded:
			excl = append(excl, id)
		case !n.Selected:
			unsel = append(unsel, id)
		}
	}
	for _, e := range r.Edges {
		switch {
		case e.Excluded:
			fmt.Fprintf(&b, "  %s -. excluded .-> %s\n", ids[e.From], ids[e.To])
		case e.Pruned:
			fmt.Fprintf(&b, "  %s -. pruned .-> %s\n", ids[e.From], ids[e.To])
		default:
			fmt.Fprintf(&b, "  %s --> %s\n", ids[e.From], ids[e.To])
		}
	}
	b.WriteString("  classDef main fill:#dbeafe,stroke:#1d4ed8,font-weight:bold\n")
	b.WriteString("  classDef unselected fill:#f3f4f6,stroke:#9ca3af,color:#6b7280,stroke-dasharray:4 3\n")
	b.WriteString("  classDef excluded fill:#fee2e2,stroke:#dc2626,color:#991b1b,stroke-dasharray:2 2\n")
	for _, cl := range []struct {
		name string
		ids  []string
	}{{"main", mains}, {"unselected", unsel}, {"excluded", excl}} {
		if len(cl.ids) > 0 {
			fmt.Fprintf(&b, "  class %s %s\n", strings.Join(cl.ids, ","), cl.name)
		}
	}
	return b.String()
}
