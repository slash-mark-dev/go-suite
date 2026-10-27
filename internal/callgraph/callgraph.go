// Package callgraph builds a whole-program call graph from type-checked
// syntax and answers reachability questions.
//
// The analysis is a sound-leaning over-approximation in the style of Class
// Hierarchy Analysis:
//   - a static call or any reference to a function or method (passing it
//     as a value, method values and expressions) is an edge;
//   - a call through an interface (or a type-parameter constraint) is an
//     edge to the method of every type in the program that implements the
//     interface;
//   - function literals are folded into the function that contains them;
//   - package initialization is a synthetic "init" node that calls the
//     package's init functions, the calls in package-level variable
//     initializers, and the init nodes of imported packages.
//
// Calls through reflection are not modelled.
package callgraph

import (
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/loader"
)

// EdgeKind classifies an edge.
type EdgeKind int

const (
	Static    EdgeKind = iota // direct call
	Ref                       // function referenced as a value
	Interface                 // dynamic dispatch through an interface
	InitOrder                 // package initialization
)

func (k EdgeKind) String() string {
	return [...]string{"call", "ref", "interface", "init"}[k]
}

// Func is a node: a declared function or method, or a package's init.
type Func struct {
	// ID is unique: "pkg.Name", "pkg.T.M" or "pkg.init".
	ID string
	// Pkg is the import path; Symbol is the vulndb-style name ("Name" or
	// "T.M"; "init" for the synthetic node).
	Pkg     string
	Symbol  string
	Obj     *types.Func
	Package *loader.Package
	Pos     token.Pos
	Init    bool
}

// Edge is a call graph edge.
type Edge struct {
	Caller *Func
	Callee *Func
	Pos    token.Pos
	Kind   EdgeKind
}

// Graph is the program call graph.
type Graph struct {
	Prog  *loader.Program
	Funcs map[string]*Func
	Out   map[*Func][]*Edge
	byObj map[*types.Func]*Func

	// method index for CHA: method name -> concrete types having it
	methodTypes map[string][]types.Type
	implCache   map[*types.Interface][]types.Type
}

// SymbolOf returns the vulndb-style symbol for a function object.
func SymbolOf(fn *types.Func) string {
	sig, _ := fn.Type().(*types.Signature)
	if sig != nil && sig.Recv() != nil {
		t := sig.Recv().Type()
		if p, ok := t.(*types.Pointer); ok {
			t = p.Elem()
		}
		switch n := t.(type) {
		case *types.Named:
			return n.Obj().Name() + "." + fn.Name()
		case *types.Alias:
			return n.Obj().Name() + "." + fn.Name()
		case *types.Interface:
			return fn.Name()
		}
		return fn.Name()
	}
	return fn.Name()
}

// Build constructs the graph for every type-checked package in prog.
func Build(prog *loader.Program) *Graph {
	g := &Graph{Prog: prog, Funcs: map[string]*Func{}, Out: map[*Func][]*Edge{}, byObj: map[*types.Func]*Func{},
		methodTypes: map[string][]types.Type{}, implCache: map[*types.Interface][]types.Type{}}
	for _, p := range prog.Packages {
		if p.Types == nil || p.Info == nil {
			continue
		}
		g.indexTypes(p)
	}
	for _, p := range prog.Packages {
		if p.Types == nil || p.Info == nil {
			continue
		}
		g.walkPackage(p)
	}
	return g
}

func (g *Graph) indexTypes(p *loader.Package) {
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok || tn.IsAlias() {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok {
			continue
		}
		if _, isIface := named.Underlying().(*types.Interface); isIface {
			continue
		}
		// Generic types are indexed by their origin; CHA on instances is
		// approximated by the origin's methods.
		ms := types.NewMethodSet(types.NewPointer(named))
		seen := map[string]bool{}
		for i := 0; i < ms.Len(); i++ {
			n := ms.At(i).Obj().Name()
			if !seen[n] {
				seen[n] = true
				g.methodTypes[n] = append(g.methodTypes[n], named)
			}
		}
	}
}

func (g *Graph) funcFor(fn *types.Func) *Func {
	fn = fn.Origin()
	if f, ok := g.byObj[fn]; ok {
		return f
	}
	pkgPath := ""
	if fn.Pkg() != nil {
		pkgPath = fn.Pkg().Path()
	}
	sym := SymbolOf(fn)
	id := pkgPath + "." + sym
	f := g.Funcs[id]
	if f == nil {
		f = &Func{ID: id, Pkg: pkgPath, Symbol: sym, Obj: fn, Pos: fn.Pos()}
		if lp := g.Prog.ByPath[pkgPath]; lp != nil {
			f.Package = lp
		}
		g.Funcs[id] = f
	}
	g.byObj[fn] = f
	return f
}

// InitFunc returns the synthetic init node of a package.
func (g *Graph) InitFunc(pkgPath string) *Func {
	id := pkgPath + ".init"
	f := g.Funcs[id]
	if f == nil {
		f = &Func{ID: id, Pkg: pkgPath, Symbol: "init", Init: true, Package: g.Prog.ByPath[pkgPath]}
		g.Funcs[id] = f
	}
	return f
}

func (g *Graph) addEdge(from, to *Func, pos token.Pos, kind EdgeKind) {
	if from == nil || to == nil {
		return
	}
	g.Out[from] = append(g.Out[from], &Edge{Caller: from, Callee: to, Pos: pos, Kind: kind})
}

func (g *Graph) walkPackage(p *loader.Package) {
	initF := g.InitFunc(p.Types.Path())
	for _, imp := range p.Types.Imports() {
		g.addEdge(initF, g.InitFunc(imp.Path()), token.NoPos, InitOrder)
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				obj, _ := p.Info.Defs[d.Name].(*types.Func)
				if obj == nil {
					continue
				}
				var owner *Func
				if d.Name.Name == "init" && d.Recv == nil {
					// Each init function is folded into the package init node.
					owner = initF
				} else {
					owner = g.funcFor(obj)
					owner.Package = p
					owner.Pos = d.Name.Pos()
				}
				if d.Body != nil {
					g.walkBody(p, owner, d.Body)
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					continue
				}
				for _, spec := range d.Specs {
					vs := spec.(*ast.ValueSpec)
					for _, v := range vs.Values {
						g.walkBody(p, initF, v)
					}
				}
			}
		}
	}
}

func (g *Graph) walkBody(p *loader.Package, owner *Func, root ast.Node) {
	info := p.Info
	callFun := map[ast.Expr]bool{}
	var visit func(n ast.Node) bool
	visit = func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.CallExpr:
			fun := ast.Unparen(e.Fun)
			if ix, ok := fun.(*ast.IndexExpr); ok {
				fun = ix.X
			} else if ix, ok := fun.(*ast.IndexListExpr); ok {
				fun = ix.X
			}
			callFun[fun] = true
		case *ast.SelectorExpr:
			kind := Ref
			if callFun[e] {
				kind = Static
			}
			if sel, ok := info.Selections[e]; ok {
				if fn, ok := sel.Obj().(*types.Func); ok {
					if recv := sel.Recv(); isInterfaceLike(recv) {
						g.addDynamic(owner, recv, fn, e.Sel.Pos())
					} else {
						g.addEdge(owner, g.funcFor(fn), e.Sel.Pos(), kind)
					}
				}
			} else if fn, ok := info.Uses[e.Sel].(*types.Func); ok {
				// Qualified identifier pkg.F.
				g.addEdge(owner, g.funcFor(fn), e.Sel.Pos(), kind)
			}
			// Visit the operand but not e.Sel, which was handled above.
			ast.Inspect(e.X, visit)
			return false
		case *ast.Ident:
			if fn, ok := info.Uses[e].(*types.Func); ok {
				sig, _ := fn.Type().(*types.Signature)
				if sig != nil && sig.Recv() != nil {
					// method identifiers appear only via selectors
					return true
				}
				kind := Ref
				if callFun[e] {
					kind = Static
				}
				g.addEdge(owner, g.funcFor(fn), e.Pos(), kind)
			}
		}
		return true
	}
	ast.Inspect(root, visit)
}

func isInterfaceLike(t types.Type) bool {
	switch u := t.(type) {
	case *types.TypeParam:
		return true
	case *types.Pointer:
		return isInterfaceLike(u.Elem())
	}
	_, ok := t.Underlying().(*types.Interface)
	return ok
}

// addDynamic adds CHA edges for a call of method fn through an interface
// or type parameter recv.
func (g *Graph) addDynamic(owner *Func, recv types.Type, fn *types.Func, pos token.Pos) {
	var iface *types.Interface
	switch u := recv.(type) {
	case *types.TypeParam:
		iface, _ = u.Constraint().Underlying().(*types.Interface)
	case *types.Pointer:
		if tp, ok := u.Elem().(*types.TypeParam); ok {
			iface, _ = tp.Constraint().Underlying().(*types.Interface)
		}
	default:
		iface, _ = recv.Underlying().(*types.Interface)
	}
	// The abstract method itself is a node too, so that paths through
	// interfaces stay explainable.
	abstract := g.funcFor(fn)
	g.addEdge(owner, abstract, pos, Interface)
	if iface == nil {
		return
	}
	for _, t := range g.implementations(iface, fn.Name()) {
		obj, _, _ := types.LookupFieldOrMethod(types.NewPointer(t), true, fn.Pkg(), fn.Name())
		m, ok := obj.(*types.Func)
		if !ok {
			continue
		}
		g.addEdge(abstract, g.funcFor(m), pos, Interface)
	}
}

func (g *Graph) implementations(iface *types.Interface, method string) []types.Type {
	if impls, ok := g.implCache[iface]; ok {
		return impls
	}
	var impls []types.Type
	for _, t := range g.methodTypes[method] {
		if types.Implements(t, iface) || types.Implements(types.NewPointer(t), iface) {
			impls = append(impls, t)
			continue
		}
		// Generic types: check the method by name only.
		if n, ok := t.(*types.Named); ok && n.TypeParams().Len() > 0 {
			impls = append(impls, t)
		}
	}
	g.implCache[iface] = impls
	return impls
}

// Lookup returns the node for "pkgpath" and a vulndb symbol ("F" or
// "T.M"), or nil.
func (g *Graph) Lookup(pkgPath, symbol string) *Func {
	return g.Funcs[pkgPath+"."+symbol]
}

// Entrypoints returns the roots of execution for the given packages: for
// main packages, main and package initialization; for libraries, every
// exported function and exported method of an exported type, plus init.
func (g *Graph) Entrypoints(pkgs []*loader.Package) []*Func {
	var out []*Func
	seen := map[*Func]bool{}
	add := func(f *Func) {
		if f != nil && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	for _, p := range pkgs {
		if p.Types == nil {
			continue
		}
		add(g.InitFunc(p.Types.Path()))
		if p.Name == "main" {
			if fn, ok := p.Types.Scope().Lookup("main").(*types.Func); ok {
				add(g.funcFor(fn))
			}
			continue
		}
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if !obj.Exported() {
				continue
			}
			switch o := obj.(type) {
			case *types.Func:
				add(g.funcFor(o))
			case *types.TypeName:
				ms := types.NewMethodSet(types.NewPointer(o.Type()))
				for i := 0; i < ms.Len(); i++ {
					if m, ok := ms.At(i).Obj().(*types.Func); ok && m.Exported() {
						add(g.funcFor(m))
					}
				}
			}
		}
		// Test functions are entry points too when tests were loaded.
		for _, f := range p.Syntax {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Recv != nil {
					continue
				}
				n := fd.Name.Name
				if strings.HasPrefix(n, "Test") || strings.HasPrefix(n, "Benchmark") || strings.HasPrefix(n, "Fuzz") || strings.HasPrefix(n, "Example") {
					if fn, ok := p.Info.Defs[fd.Name].(*types.Func); ok && strings.HasSuffix(g.Prog.Fset.Position(fd.Pos()).Filename, "_test.go") {
						add(g.funcFor(fn))
					}
				}
			}
		}
	}
	return out
}

// Reach is the result of a reachability query: for every reachable node,
// the edge through which it was first reached (nil for roots).
type Reach struct {
	Parent map[*Func]*Edge
	Roots  map[*Func]bool
}

// Reachable computes the nodes reachable from roots (breadth-first, so
// reconstructed paths are shortest).
func (g *Graph) Reachable(roots []*Func) *Reach {
	r := &Reach{Parent: map[*Func]*Edge{}, Roots: map[*Func]bool{}}
	var q []*Func
	for _, f := range roots {
		if _, ok := r.Parent[f]; ok {
			continue
		}
		r.Parent[f] = nil
		r.Roots[f] = true
		q = append(q, f)
	}
	for len(q) > 0 {
		f := q[0]
		q = q[1:]
		edges := g.Out[f]
		for _, e := range edges {
			if _, ok := r.Parent[e.Callee]; ok {
				continue
			}
			r.Parent[e.Callee] = e
			q = append(q, e.Callee)
		}
	}
	return r
}

// Has reports whether f is reachable.
func (r *Reach) Has(f *Func) bool {
	if f == nil {
		return false
	}
	_, ok := r.Parent[f]
	return ok
}

// Path returns the edges from a root to f (empty if f is a root, nil if
// unreachable).
func (r *Reach) Path(f *Func) []*Edge {
	if !r.Has(f) {
		return nil
	}
	var path []*Edge
	for cur := f; ; {
		e := r.Parent[cur]
		if e == nil {
			break
		}
		path = append([]*Edge{e}, path...)
		cur = e.Caller
		if len(path) > 10000 {
			break
		}
	}
	return path
}

// Callees returns the distinct callees of f, sorted by ID.
func (g *Graph) Callees(f *Func) []*Func {
	seen := map[*Func]bool{}
	var out []*Func
	for _, e := range g.Out[f] {
		if !seen[e.Callee] {
			seen[e.Callee] = true
			out = append(out, e.Callee)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Name returns a readable name: "pkg.F", "pkg.T.M" or "pkg init".
func (f *Func) Name() string {
	if f.Init {
		return f.Pkg + " (package initialization)"
	}
	return f.ID
}
