package security

import (
	"flag"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/callgraph"
	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/loader"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/ui"
)

// Import-time effect kinds.
const (
	EffNetwork  = "network"
	EffExec     = "exec"
	EffFileW    = "file-write"
	EffEnv      = "env"
	EffRegister = "registration"
	EffMutate   = "global-mutation"
)

var effOrder = []string{EffNetwork, EffExec, EffFileW, EffMutate, EffRegister, EffEnv}

var effInfo = map[string]struct {
	Desc     string
	Severity report.Severity
}{
	EffNetwork:  {"connects to, listens on or resolves the network at import time", report.High},
	EffExec:     {"runs another program at import time", report.High},
	EffFileW:    {"creates, writes, renames or removes files at import time", report.High},
	EffMutate:   {"assigns another package's global variable at import time", report.Medium},
	EffRegister: {"registers global handlers, flags, drivers or codecs at import time", report.Low},
	EffEnv:      {"reads or changes environment variables at import time", report.Low},
}

var initRules = map[string][]string{
	EffNetwork: capRules[CapNetwork],
	EffExec:    capRules[CapExec],
	EffFileW: {
		"os.Create", "os.CreateTemp", "os.OpenFile", "os.WriteFile", "os.Remove", "os.RemoveAll", "os.Rename",
		"os.Mkdir", "os.MkdirAll", "os.MkdirTemp", "os.Chmod", "os.Chown", "os.Lchown", "os.Chtimes", "os.Link",
		"os.Symlink", "os.Truncate", "os.CopyFS", "io/ioutil.WriteFile", "io/ioutil.TempFile", "io/ioutil.TempDir",
	},
	EffEnv: capRules[CapEnv],
	EffRegister: {
		"net/http.Handle", "net/http.HandleFunc", "database/sql.Register", "image.RegisterFormat",
		"encoding/gob.Register", "encoding/gob.RegisterName", "expvar.Publish", "expvar.New*", "crypto.RegisterHash",
		"mime.AddExtensionType", "net/rpc.Register", "net/rpc.RegisterName", "net/rpc.HandleHTTP",
		"flag.Bool", "flag.BoolVar", "flag.BoolFunc", "flag.Int", "flag.IntVar", "flag.Int64", "flag.Int64Var",
		"flag.Uint", "flag.UintVar", "flag.Uint64", "flag.Uint64Var", "flag.String", "flag.StringVar",
		"flag.Float64", "flag.Float64Var", "flag.Duration", "flag.DurationVar", "flag.Var", "flag.Func", "flag.TextVar", "flag.Parse",
		"log.SetOutput", "log.SetFlags", "log.SetPrefix", "runtime/debug.Set*", "os/signal.Notify", "os/signal.Ignore",
	},
}

var initMatcher = newCapMatcher(initRules)

// InitEffect is one kind of side effect of one package's initialization.
type InitEffect struct {
	Package  string          `json:"package"`
	Module   string          `json:"module"`
	Version  string          `json:"version,omitempty"`
	Kind     string          `json:"kind"`
	Severity report.Severity `json:"severity"`
	// APIs are the effectful APIs reached (or "pkg.Var" for mutations).
	APIs []string `json:"apis"`
	// Args are constant string arguments seen at the call sites (URLs,
	// file names, environment variable names).
	Args []string `json:"args,omitempty"`
	// Path is the shortest call path from the package initialization to
	// the first effect.
	Path []Frame `json:"path"`
}

// InitResult is the result of initscan.
type InitResult struct {
	Packages int              `json:"packages"` // dependency packages scanned
	Effects  []*InitEffect    `json:"effects"`
	Counts   map[string]int   `json:"counts"` // kind -> packages
	Findings []report.Finding `json:"findings"`
	Failing  int              `json:"failing"`
}

var initFlags struct {
	includeMain, tests, all *bool
	tags                    *string
	failOn                  func() (report.Severity, error)
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "initscan",
		Group:   group,
		Summary: "Side effects that dependencies run at import time",
		Usage:   "sm-go initscan [packages] [flags]",
		Help: `Code in init functions and package-level variable initializers runs as soon as a package
is imported, before main and without any call from your code. initscan builds the call graph
of every dependency's initialization (following calls into other dependencies, through
interfaces and function values, but not into other packages' own initialization, which is
reported for those packages) and reports what it can reach:

  network          net/http clients and servers, net.Dial/Listen/Lookup, ...      high
  exec             os/exec, os.StartProcess, syscall.Exec                          high
  file-write       os.Create/OpenFile/WriteFile/Remove/Rename/Mkdir/Chmod, ...     high
  global-mutation  assignments to another package's variables (http.DefaultClient) medium
  registration     http.Handle on the default mux, sql.Register, global flags, ... low
  env              os.Getenv/LookupEnv/Environ/Setenv, ...                         low

Each effect shows the shortest call path from the package's initialization and the constant
arguments seen at the call (URLs, file names, variable names). The standard library is not
traversed: its APIs are the effects. Effects at or above --fail-on fail the run.`,
		Examples: []string{
			"sm-go initscan",
			"sm-go initscan ./cmd/server --fail-on medium",
			"sm-go initscan --all --json",
		},
		Sources: []string{"module source (type-checked call graph)"},
		NeedsGo: true,
		Flags: func(fs *flag.FlagSet) {
			initFlags.includeMain = fs.Bool("include-main", false, "also scan the main module's packages")
			initFlags.all = fs.Bool("all", false, "list effects below --fail-on too (default lists registration/env only in JSON)")
			initFlags.tests = fs.Bool("tests", false, "include test dependencies")
			initFlags.tags = fs.String("tags", "", "comma-separated build `tags`")
			initFlags.failOn = cli.SeverityFlag(fs, "fail-on", "high", "minimum `severity` that fails the run")
		},
		Run: runInitscan,
	})
}

func runInitscan(c *cli.Context) error {
	failOn, err := initFlags.failOn()
	if err != nil {
		return err
	}
	pats := c.Args
	if len(pats) == 0 {
		pats = []string{"./..."}
	}
	prog, cg, err := loadProgram(c, loader.Config{Patterns: pats, Tests: *initFlags.tests, Tags: splitTags(*initFlags.tags),
		SkipBodies: func(p *loader.Package) bool { return p.Standard }})
	if err != nil {
		return err
	}
	includeMain := *initFlags.includeMain
	res := ScanInit(c, prog, cg, func(p *loader.Package) bool {
		return !p.Standard && (includeMain || !p.InMainModule())
	})
	for _, f := range res.Findings {
		if f.Severity.Meets(failOn) {
			res.Failing++
		}
	}
	c.SetResult(res)
	if res.Failing > 0 {
		c.Issues()
	}
	if c.Text() {
		printInit(c, res, failOn, *initFlags.all)
	}
	return nil
}

// ScanInit analyses the initialization of every package include accepts.
func ScanInit(c *cli.Context, prog *loader.Program, g *callgraph.Graph, include func(*loader.Package) bool) *InitResult {
	res := &InitResult{Effects: []*InitEffect{}, Counts: map[string]int{}, Findings: []report.Finding{}}
	pf := newPosFormatter(c, prog, projectDir(c))
	idx := newBodyIndex(prog)
	for _, p := range prog.Packages {
		if p.Types == nil || !include(p) {
			continue
		}
		res.Packages++
		effs := scanPackageInit(prog, g, idx, pf, p)
		for _, e := range effs {
			res.Effects = append(res.Effects, e)
			res.Counts[e.Kind]++
			detail := effInfo[e.Kind].Desc + ": " + strings.Join(e.APIs, ", ")
			if len(e.Args) > 0 {
				detail += "\nargs: " + strings.Join(e.Args, ", ")
			}
			var names []string
			for _, f := range e.Path {
				names = append(names, f.Func)
			}
			detail += "\npath: " + strings.Join(names, " → ")
			res.Findings = append(res.Findings, report.Finding{Severity: e.Severity, Rule: "initscan/" + e.Kind, Module: e.Module, Version: e.Version,
				Package: e.Package, Title: fmt.Sprintf("%s: %s at import time", e.Package, e.Kind), Detail: detail,
				Data: map[string]any{"kind": e.Kind, "apis": e.APIs}})
		}
	}
	sort.SliceStable(res.Effects, func(i, j int) bool {
		a, b := res.Effects[i], res.Effects[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		return effRank(a.Kind) < effRank(b.Kind)
	})
	report.SortFindings(res.Findings)
	return res
}

func effRank(k string) int {
	for i, x := range effOrder {
		if x == k {
			return i
		}
	}
	return len(effOrder)
}

// bodyIndex locates the syntax of functions and the constant string
// arguments of calls in the scanned packages.
type bodyIndex struct {
	decls map[*types.Func]*ast.FuncDecl
	// inits holds, per package, its init functions and package-level var
	// initializer expressions.
	inits map[string][]ast.Node
	// args maps a call's position (as recorded on call graph edges) to its
	// first constant string argument.
	args map[token.Pos]string
}

func newBodyIndex(prog *loader.Program) *bodyIndex {
	ix := &bodyIndex{decls: map[*types.Func]*ast.FuncDecl{}, inits: map[string][]ast.Node{}, args: map[token.Pos]string{}}
	for _, p := range prog.Packages {
		if p.Info == nil || p.Standard {
			continue
		}
		for _, f := range p.Syntax {
			for _, d := range f.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					if d.Body == nil {
						continue
					}
					if d.Name.Name == "init" && d.Recv == nil {
						ix.inits[p.ImportPath] = append(ix.inits[p.ImportPath], d)
					} else if fn, ok := p.Info.Defs[d.Name].(*types.Func); ok {
						ix.decls[fn] = d
					}
				case *ast.GenDecl:
					if d.Tok != token.VAR {
						continue
					}
					for _, spec := range d.Specs {
						for _, v := range spec.(*ast.ValueSpec).Values {
							ix.inits[p.ImportPath] = append(ix.inits[p.ImportPath], v)
						}
					}
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				var pos token.Pos
				switch fun := ast.Unparen(call.Fun).(type) {
				case *ast.SelectorExpr:
					pos = fun.Sel.Pos()
				case *ast.Ident:
					pos = fun.Pos()
				default:
					return true
				}
				for _, a := range call.Args {
					if tv, ok := p.Info.Types[a]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
						ix.args[pos] = constant.StringVal(tv.Value)
						break
					}
				}
				return true
			})
		}
	}
	return ix
}

// bodies returns the syntax executed by node f.
func (ix *bodyIndex) bodies(f *callgraph.Func) []ast.Node {
	if f.Init {
		return ix.inits[f.Pkg]
	}
	if f.Obj != nil {
		if d := ix.decls[f.Obj]; d != nil {
			return []ast.Node{d.Body}
		}
	}
	return nil
}

// mutations returns the other-package variables assigned in n, with the
// position of each assignment.
func mutations(p *loader.Package, n ast.Node) map[string]token.Pos {
	out := map[string]token.Pos{}
	check := func(lhs ast.Expr) {
		// Find the root operand: http.DefaultClient.Timeout = ...,
		// http.DefaultServeMux = ..., *pkg.Ptr = ...
		e := lhs
		for {
			switch x := e.(type) {
			case *ast.ParenExpr:
				e = x.X
				continue
			case *ast.StarExpr:
				e = x.X
				continue
			case *ast.IndexExpr:
				e = x.X
				continue
			case *ast.SelectorExpr:
				if v, ok := p.Info.Uses[x.Sel].(*types.Var); ok && v.Pkg() != nil && v.Pkg() != p.Types && v.Parent() == v.Pkg().Scope() {
					if _, isPkg := p.Info.Uses[identOf(x.X)].(*types.PkgName); isPkg {
						key := v.Pkg().Path() + "." + v.Name()
						if _, seen := out[key]; !seen {
							out[key] = x.Sel.Pos()
						}
						return
					}
				}
				e = x.X
				continue
			}
			return
		}
	}
	ast.Inspect(n, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			if s.Tok == token.DEFINE {
				return true
			}
			for _, l := range s.Lhs {
				check(l)
			}
		case *ast.IncDecStmt:
			check(s.X)
		}
		return true
	})
	return out
}

func identOf(e ast.Expr) *ast.Ident {
	id, _ := ast.Unparen(e).(*ast.Ident)
	return id
}

type effAcc struct {
	eff   *InitEffect
	apis  map[string]bool
	args  map[string]bool
	depth int
}

func scanPackageInit(prog *loader.Program, g *callgraph.Graph, ix *bodyIndex, pf *posFormatter, p *loader.Package) []*InitEffect {
	root := g.InitFunc(p.Types.Path())
	// Breadth-first search that does not enter the standard library or
	// other packages' initialization.
	parent := map[*callgraph.Func]*callgraph.Edge{root: nil}
	order := []*callgraph.Func{root}
	for i := 0; i < len(order); i++ {
		f := order[i]
		if f != root && isStd(prog, f) {
			continue
		}
		for _, e := range g.Out[f] {
			if e.Kind == callgraph.InitOrder || e.Callee.Init {
				continue
			}
			if _, ok := parent[e.Callee]; ok {
				continue
			}
			parent[e.Callee] = e
			order = append(order, e.Callee)
		}
	}
	pathTo := func(f *callgraph.Func, last *Frame) []Frame {
		var edges []*callgraph.Edge
		for cur := f; parent[cur] != nil; cur = parent[cur].Caller {
			edges = append([]*callgraph.Edge{parent[cur]}, edges...)
		}
		fs := pf.frames(root, edges)
		if last != nil {
			fs = append(fs, *last)
		}
		return compactFrames(fs, 8)
	}
	acc := map[string]*effAcc{}
	add := func(kind, api, arg string, depth int, path func() []Frame) {
		a := acc[kind]
		if a == nil {
			a = &effAcc{eff: &InitEffect{Package: p.ImportPath, Module: p.ModulePath(), Version: p.ModuleVersion(), Kind: kind,
				Severity: effInfo[kind].Severity}, apis: map[string]bool{}, args: map[string]bool{}, depth: -1}
			acc[kind] = a
		}
		a.apis[api] = true
		if arg != "" {
			a.args[arg] = true
		}
		if a.depth < 0 || depth < a.depth {
			a.depth = depth
			a.eff.Path = path()
		}
	}
	for depth, f := range order { // BFS order: earlier is shallower
		if f == root || !isStd(prog, f) {
			// Assignments to other packages' globals in code run at init.
			owner := pkgOf(prog, f)
			if owner == nil || owner.Info == nil {
				continue
			}
			for _, n := range ix.bodies(f) {
				muts := mutations(owner, n)
				var vars []string
				for v := range muts {
					vars = append(vars, v)
				}
				sort.Strings(vars)
				for _, v := range vars {
					f, v, pos := f, v, muts[v]
					add(EffMutate, v, "", depth, func() []Frame {
						return pathTo(f, &Frame{Func: v + " (assigned)", Pos: pf.pos(pos)})
					})
				}
			}
			continue
		}
		key := f.Pkg + "." + f.Symbol
		for _, kind := range initMatcher.match(key) {
			e := parent[f]
			arg := ""
			if e != nil {
				arg = ix.args[e.Pos]
			}
			f := f
			add(kind, key, arg, depth, func() []Frame { return pathTo(f, nil) })
		}
	}
	var out []*InitEffect
	for _, a := range acc {
		for api := range a.apis {
			a.eff.APIs = append(a.eff.APIs, api)
		}
		sort.Strings(a.eff.APIs)
		for arg := range a.args {
			a.eff.Args = append(a.eff.Args, arg)
		}
		sort.Strings(a.eff.Args)
		if a.eff.Kind == EffRegister {
			for _, api := range a.eff.APIs {
				if api == "net/http.Handle" || api == "net/http.HandleFunc" {
					// Routes on http.DefaultServeMux are served by any
					// program using the default mux.
					a.eff.Severity = report.Medium
				}
			}
		}
		out = append(out, a.eff)
	}
	sort.Slice(out, func(i, j int) bool { return effRank(out[i].Kind) < effRank(out[j].Kind) })
	return out
}

func printInit(c *cli.Context, res *InitResult, failOn report.Severity, all bool) {
	o := c.Out
	subject := "."
	if p, err := c.Project(); err == nil && p.ModulePath() != "" {
		subject = p.ModulePath()
	}
	o.Title("sm-go initscan · " + subject)
	o.Printf("%s\n", o.Dim(fmt.Sprintf("%s scanned: init functions and package-level variable initializers",
		ui.Plural(res.Packages, "dependency package", "dependency packages"))))
	shown, hidden := 0, 0
	o.Heading("Import-time side effects")
	for _, e := range res.Effects {
		if !all && e.Severity < failOn && e.Severity < report.Medium {
			hidden++
			continue
		}
		shown++
		o.Printf("\n  %s %s  %s\n", o.Sev(e.Severity), o.Bold(e.Package), e.Kind)
		ind := "           "
		o.Printf("%s%s\n", ind, ui.Truncate(strings.Join(e.APIs, ", "), 90))
		if len(e.Args) > 0 {
			o.Printf("%s%s %s\n", ind, o.Dim("args:"), ui.Truncate(strings.Join(quoteAll(e.Args), ", "), 84))
		}
		printFrames(c, ind, e.Path)
	}
	if shown == 0 {
		o.OK("no import-time side effects at or above medium")
	}
	if hidden > 0 {
		o.Printf("\n%s\n", o.Dim(fmt.Sprintf("%s (low severity: registration, env) not listed; use --all", ui.Plural(hidden, "effect", "effects"))))
	}
	var parts []string
	for _, k := range effOrder {
		if n := res.Counts[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", k, n))
		}
	}
	if len(parts) == 0 {
		parts = []string{"none"}
	}
	o.Println()
	o.Printf("%s packages per effect: %s\n", o.Bold("Summary:"), strings.Join(parts, " · "))
	if res.Failing > 0 {
		o.Bad("%s at or above %s", ui.Plural(res.Failing, "effect", "effects"), failOn)
	}
}

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = fmt.Sprintf("%q", s)
	}
	return out
}
