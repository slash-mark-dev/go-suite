package security

import (
	"fmt"
	"go/token"
	"path/filepath"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/callgraph"
	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/loader"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/ui"
)

const group = "Supply-chain security"

// Frame is one step of a call path.
type Frame struct {
	// Func is the function ("pkg.F", "pkg.T.M" or "pkg (package
	// initialization)"); "…" marks frames elided by compaction.
	Func string `json:"func"`
	// Pos is where the step happens: the declaration of the first frame,
	// or the call site (in the previous frame) of the others.
	Pos string `json:"pos,omitempty"`
}

// posFormatter shortens source positions: files of the project are shown
// relative to it, module cache files as "path@version/file", GOROOT files
// as "$GOROOT/src/...".
type posFormatter struct {
	prog     *loader.Program
	base     string
	modcache string
	goroot   string
	// prefix replaces base in displayed positions ("path@version").
	prefix string
}

func newPosFormatter(c *cli.Context, prog *loader.Program, base string) *posFormatter {
	pf := &posFormatter{prog: prog, base: base}
	if c != nil && c.Env != nil {
		pf.modcache = c.Env.Get("GOMODCACHE")
		pf.goroot = c.Env.Get("GOROOT")
	}
	return pf
}

func (pf *posFormatter) pos(p token.Pos) string {
	if pf == nil || pf.prog == nil || !p.IsValid() {
		return ""
	}
	pos := pf.prog.Fset.Position(p)
	name := pos.Filename
	under := func(dir string) (string, bool) {
		if dir == "" {
			return "", false
		}
		rel, err := filepath.Rel(dir, name)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", false
		}
		return filepath.ToSlash(rel), true
	}
	if rel, ok := under(pf.base); ok {
		name = rel
		if pf.prefix != "" {
			name = pf.prefix + "/" + rel
		}
	} else if rel, ok := under(pf.modcache); ok {
		name = rel
	} else if rel, ok := under(pf.goroot); ok {
		name = "$GOROOT/" + rel
	} else {
		name = filepath.ToSlash(name)
	}
	return fmt.Sprintf("%s:%d", name, pos.Line)
}

// frames converts a reachability path (root, then edges) to frames.
func (pf *posFormatter) frames(root *callgraph.Func, edges []*callgraph.Edge) []Frame {
	var out []Frame
	if root != nil {
		out = append(out, Frame{Func: root.Name(), Pos: pf.pos(root.Pos)})
	}
	for _, e := range edges {
		out = append(out, Frame{Func: e.Callee.Name(), Pos: pf.pos(e.Pos)})
	}
	return out
}

// compactFrames keeps at most max frames: the first max-3, an ellipsis
// and the last two.
func compactFrames(fs []Frame, max int) []Frame {
	if len(fs) <= max || max < 4 {
		return fs
	}
	head := max - 3
	out := append([]Frame{}, fs[:head]...)
	out = append(out, Frame{Func: fmt.Sprintf("… %d more", len(fs)-head-2)})
	return append(out, fs[len(fs)-2:]...)
}

// fullPath returns the frames from an entry point to f using reach.
func fullPath(reach *callgraph.Reach, f *callgraph.Func) (*callgraph.Func, []*callgraph.Edge) {
	edges := reach.Path(f)
	root := f
	if len(edges) > 0 {
		root = edges[0].Caller
	}
	return root, edges
}

// printFrames prints a call path indented.
func printFrames(c *cli.Context, indent string, fs []Frame) {
	w := 0
	for _, f := range fs {
		if n := ui.Width(f.Pos); n > w {
			w = n
		}
	}
	for i, f := range fs {
		arrow := "  "
		if i > 0 {
			arrow = "→ "
		}
		if strings.HasPrefix(f.Func, "…") {
			c.Out.Printf("%s%s%s\n", indent, strings.Repeat(" ", w+2), c.Out.Dim(f.Func))
			continue
		}
		c.Out.Printf("%s%s%s  %s%s\n", indent, c.Out.Dim(f.Pos), strings.Repeat(" ", w-ui.Width(f.Pos)), arrow, f.Func)
	}
}

// pkgOf returns the loaded package of a call graph node.
func pkgOf(prog *loader.Program, f *callgraph.Func) *loader.Package {
	if f.Package != nil {
		return f.Package
	}
	return prog.ByPath[f.Pkg]
}

// isStd reports whether a node belongs to the standard library.
func isStd(prog *loader.Program, f *callgraph.Func) bool {
	if p := pkgOf(prog, f); p != nil {
		return p.Standard
	}
	// Unloaded packages: standard library paths have no dot in the first
	// element.
	first, _, _ := strings.Cut(f.Pkg, "/")
	return !strings.Contains(first, ".")
}

// loadProgram loads and type-checks patterns and builds the call graph.
func loadProgram(c *cli.Context, cfg loader.Config) (*loader.Program, *callgraph.Graph, error) {
	cfg.TypeCheck = true
	prog, err := c.Load(cfg)
	if err != nil {
		return nil, nil, err
	}
	for i, e := range prog.Errors {
		if i == 3 {
			c.Warnf("… and %d more package loading problems", len(prog.Errors)-3)
			break
		}
		c.Warnf("%s", e)
	}
	if len(prog.Roots) == 0 {
		return nil, nil, cli.Usagef("no packages matched %s", strings.Join(cfg.Patterns, " "))
	}
	return prog, callgraph.Build(prog), nil
}

// sevCounts returns counts by severity for summary objects.
func sevCounts(fs []report.Finding) map[string]int {
	m := report.Counts(fs)
	if m == nil {
		m = map[string]int{}
	}
	return m
}

// countLine renders "2 critical, 1 high" for the non-zero severities.
func countLine(m map[string]int) string {
	var parts []string
	for s := report.Critical; s >= report.Info; s-- {
		if n := m[s.String()]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// projectDir returns the main module directory, or the -C dir.
func projectDir(c *cli.Context) string {
	if p, err := c.Project(); err == nil {
		if p.ModDir != "" {
			return p.ModDir
		}
		return p.Dir
	}
	abs, _ := filepath.Abs(c.Dir())
	return abs
}

// printFindings prints findings as a table with details below each.
func printFindings(c *cli.Context, fs []report.Finding) {
	for _, f := range fs {
		c.Out.Printf("  %s %s  %s\n", c.Out.Sev(f.Severity), c.Out.Bold(f.Where()), f.Title)
		if f.Detail != "" {
			for _, line := range strings.Split(f.Detail, "\n") {
				c.Out.Printf("           %s\n", c.Out.Dim(line))
			}
		}
		if f.Fix != "" {
			c.Out.Printf("           fix: %s\n", f.Fix)
		}
	}
}
