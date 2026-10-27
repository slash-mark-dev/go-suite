package apidiff

import (
	"go/ast"
	"go/types"
	"sort"

	"github.com/slash-mark-dev/go-suite/internal/loader"
)

// Usage records which API elements of other packages the main module's
// code refers to: import path -> object ("F", "T", "T.M", "T.F") ->
// positions ("file:line:col").
type Usage map[string]map[string][]string

func (u Usage) add(pkg, obj, pos string) {
	if u[pkg] == nil {
		u[pkg] = map[string][]string{}
	}
	for _, p := range u[pkg][obj] {
		if p == pos {
			return
		}
	}
	u[pkg][obj] = append(u[pkg][obj], pos)
}

// CollectUsage walks the type-checked packages of the main module(s) in
// prog and records every reference to an object of a package for which
// want returns true. Positions are relative to base.
func CollectUsage(prog *loader.Program, base string, want func(pkgPath string) bool) Usage {
	u := Usage{}
	for _, p := range prog.Packages {
		if !p.InMainModule() || p.Info == nil {
			continue
		}
		pos := func(n ast.Node) string { return prog.Position(n.Pos(), base) }
		named := func(t types.Type) *types.Named {
			t = types.Unalias(t)
			if pt, ok := t.(*types.Pointer); ok {
				t = types.Unalias(pt.Elem())
			}
			n, _ := t.(*types.Named)
			if n != nil {
				n = n.Origin()
			}
			return n
		}
		handled := map[*ast.Ident]bool{}
		for sel, s := range p.Info.Selections {
			n := named(s.Recv())
			if n == nil || n.Obj().Pkg() == nil || !want(n.Obj().Pkg().Path()) {
				continue
			}
			path := n.Obj().Pkg().Path()
			u.add(path, n.Obj().Name()+"."+s.Obj().Name(), pos(sel.Sel))
			u.add(path, n.Obj().Name(), pos(sel.Sel))
			handled[sel.Sel] = true
		}
		for _, f := range p.Syntax {
			ast.Inspect(f, func(node ast.Node) bool {
				lit, ok := node.(*ast.CompositeLit)
				if !ok {
					return true
				}
				tv, ok := p.Info.Types[lit]
				if !ok {
					return true
				}
				n := named(tv.Type)
				if n == nil || n.Obj().Pkg() == nil || !want(n.Obj().Pkg().Path()) {
					return true
				}
				if _, isStruct := n.Underlying().(*types.Struct); !isStruct {
					return true
				}
				path := n.Obj().Pkg().Path()
				u.add(path, n.Obj().Name(), pos(lit))
				for _, e := range lit.Elts {
					if kv, ok := e.(*ast.KeyValueExpr); ok {
						if id, ok := kv.Key.(*ast.Ident); ok {
							u.add(path, n.Obj().Name()+"."+id.Name, pos(id))
							handled[id] = true
						}
					}
				}
				return true
			})
		}
		for id, obj := range p.Info.Uses {
			if handled[id] || obj.Pkg() == nil || !want(obj.Pkg().Path()) {
				continue
			}
			if obj.Parent() == obj.Pkg().Scope() {
				u.add(obj.Pkg().Path(), obj.Name(), pos(id))
			}
		}
	}
	for _, objs := range u {
		for k := range objs {
			sort.Strings(objs[k])
		}
	}
	return u
}

// Affects returns the positions in the main module affected by change c,
// looking up uses of the package usedPath (normally c.Package; it differs
// when the change is reported under a new major version path).
func (u Usage) Affects(usedPath string, c Change) []string {
	objs := u[usedPath]
	if len(objs) == 0 {
		return nil
	}
	if c.Object == "" {
		var all []string
		for _, ps := range objs {
			all = append(all, ps...)
		}
		return uniqSorted(all)
	}
	ps := objs[c.Object]
	// Adding a method to an interface (or a type-level change reported
	// against a method or field) breaks code that implements or names the
	// type itself.
	if c.Kind == Added {
		if t, _, ok := cutDot(c.Object); ok {
			ps = append(append([]string(nil), ps...), objs[t]...)
		}
	}
	return uniqSorted(ps)
}

func cutDot(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

func uniqSorted(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	sort.Strings(s)
	out := s[:1]
	for _, x := range s[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}

// Used reports the packages of the usage set.
func (u Usage) Used() []string { return sortedKeys(u) }
