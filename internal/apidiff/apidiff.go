// Package apidiff compares the exported API of two versions of a Go package
// (or of a whole module) and classifies every difference as compatible or
// incompatible, following the semantics of golang.org/x/exp/apidiff:
//
//   - removing a package or an exported object is incompatible, adding one
//     is compatible;
//   - changing the kind of an object (const, var, func, type) is
//     incompatible;
//   - any change to a function or method signature (parameter or result
//     types, their number, variadic-ness, type parameters) is incompatible;
//   - adding a method to an interface is incompatible, unless the interface
//     has an unexported method (so no other package can implement it);
//     removing an interface method is incompatible;
//   - removing a method from the method set of T or *T (including moving
//     it from a value to a pointer receiver) is incompatible, adding one is
//     compatible;
//   - removing an exported struct field (direct or promoted), changing its
//     type or whether it is embedded is incompatible; adding a field is
//     compatible unless the struct stops being comparable;
//   - changing a constant's type or value, or a variable's type, is
//     incompatible;
//   - changing a type's underlying type, type parameter list or
//     constraints is incompatible.
//
// Packages whose import path contains an "internal" element and main
// packages are not part of a module's importable API and are skipped by
// CompareModules.
package apidiff

import (
	"fmt"
	"go/types"
	"sort"
	"strings"
)

// Change kinds.
const (
	Removed = "removed"
	Changed = "changed"
	Added   = "added"
)

// Change is one API difference.
type Change struct {
	// Package is the import path of the package (the new path when the
	// module path changed, e.g. across major versions).
	Package string `json:"package"`
	// Object names the API element: "F", "T", "T.M" (method) or "T.F"
	// (field); empty for a whole package.
	Object string `json:"object,omitempty"`
	// Kind is "removed", "changed" or "added".
	Kind string `json:"kind"`
	// Message describes the change in one line.
	Message string `json:"message"`
}

// Report lists the differences between two APIs.
type Report struct {
	Incompatible []Change `json:"incompatible"`
	Compatible   []Change `json:"compatible"`
}

// Bump returns the minimum semantic version bump the changes require:
// "major" for incompatible changes, "minor" for additions, else "patch".
func (r Report) Bump() string {
	switch {
	case len(r.Incompatible) > 0:
		return "major"
	case len(r.Compatible) > 0:
		return "minor"
	}
	return "patch"
}

// Merge appends the changes of o.
func (r *Report) Merge(o Report) {
	r.Incompatible = append(r.Incompatible, o.Incompatible...)
	r.Compatible = append(r.Compatible, o.Compatible...)
}

// IsInternal reports whether an import path contains an "internal"
// element (and so cannot be imported from other modules).
func IsInternal(path string) bool {
	return path == "internal" || strings.HasPrefix(path, "internal/") ||
		strings.HasSuffix(path, "/internal") || strings.Contains(path, "/internal/")
}

// Compare compares two versions of one package.
func Compare(old, new *types.Package) Report {
	d := &differ{oldPkg: old, newPkg: new, path: new.Path()}
	d.compare()
	return d.rep
}

// comparePaths compares two packages whose module paths differ (oldMod
// and newMod, e.g. example.com/m and example.com/m/v2): types from
// corresponding packages of the two modules are treated as the same.
func comparePaths(old, new *types.Package, oldMod, newMod string) Report {
	d := &differ{oldPkg: old, newPkg: new, path: new.Path(), oldMod: oldMod, newMod: newMod}
	d.compare()
	return d.rep
}

type differ struct {
	oldPkg, newPkg *types.Package
	oldMod, newMod string
	path           string
	rep            Report
	// corr maps the old package's defined types to the new package's
	// defined types they correspond to. Usually that is the type of the
	// same name, but a type renamed and kept as an alias (type Old = New),
	// or an alias replaced by a defined type, corresponds across names.
	corr map[*types.TypeName]*types.TypeName
}

// buildCorr fills d.corr: first defined types matched by name (resolving
// a new alias to the type it names), then the targets of old aliases.
func (d *differ) buildCorr() {
	d.corr = map[*types.TypeName]*types.TypeName{}
	os, ns := d.oldPkg.Scope(), d.newPkg.Scope()
	newDefined := func(name string) *types.TypeName {
		n, ok := ns.Lookup(name).(*types.TypeName)
		if !ok {
			return nil
		}
		nt, ok := types.Unalias(n.Type()).(*types.Named)
		if !ok || nt.Obj().Pkg() != d.newPkg || nt.TypeArgs().Len() > 0 {
			return nil
		}
		return nt.Obj()
	}
	for _, name := range os.Names() {
		o, ok := os.Lookup(name).(*types.TypeName)
		if !ok || o.IsAlias() {
			continue
		}
		if _, ok := o.Type().(*types.Named); !ok {
			continue
		}
		if n := newDefined(name); n != nil {
			d.corr[o] = n
		}
	}
	for _, name := range os.Names() {
		o, ok := os.Lookup(name).(*types.TypeName)
		if !ok || !o.IsAlias() {
			continue
		}
		ot, ok := types.Unalias(o.Type()).(*types.Named)
		if !ok || ot.Obj().Pkg() != d.oldPkg || ot.TypeArgs().Len() > 0 {
			continue
		}
		if _, done := d.corr[ot.Obj()]; done {
			continue
		}
		if n := newDefined(name); n != nil {
			d.corr[ot.Obj()] = n
		}
	}
}

// corresponds reports whether old and new type names of the compared
// packages denote the same type.
func (d *differ) corresponds(o, n *types.TypeName) bool {
	if c, ok := d.corr[o]; ok {
		return c == n
	}
	return o.Name() == n.Name()
}

func (d *differ) incompatible(obj, kind, format string, a ...any) {
	d.rep.Incompatible = append(d.rep.Incompatible, Change{Package: d.path, Object: obj, Kind: kind, Message: fmt.Sprintf(format, a...)})
}

func (d *differ) compatible(obj, kind, format string, a ...any) {
	d.rep.Compatible = append(d.rep.Compatible, Change{Package: d.path, Object: obj, Kind: kind, Message: fmt.Sprintf(format, a...)})
}

func (d *differ) compare() {
	d.buildCorr()
	os, ns := d.oldPkg.Scope(), d.newPkg.Scope()
	for _, name := range os.Names() {
		o := os.Lookup(name)
		if !o.Exported() {
			continue
		}
		n := ns.Lookup(name)
		if n == nil || !n.Exported() {
			d.incompatible(name, Removed, "%s %s removed", objKind(o), name)
			continue
		}
		d.compareObj(name, o, n)
	}
	for _, name := range ns.Names() {
		n := ns.Lookup(name)
		if !n.Exported() {
			continue
		}
		if o := os.Lookup(name); o == nil || !o.Exported() {
			d.compatible(name, Added, "%s %s added", objKind(n), name)
		}
	}
	// Unexported types reachable from the exported API (for example the
	// result type of an exported constructor) are part of the API too:
	// their exported fields and methods can be used by other packages.
	for _, name := range exposedUnexported(d.oldPkg) {
		o, _ := os.Lookup(name).(*types.TypeName)
		n, _ := ns.Lookup(name).(*types.TypeName)
		if o == nil || n == nil || o.IsAlias() || n.IsAlias() {
			continue
		}
		on, ok1 := o.Type().(*types.Named)
		nn, ok2 := n.Type().(*types.Named)
		if ok1 && ok2 {
			d.compareNamed(name, on, nn)
		}
	}
}

// exposedUnexported returns the names of the unexported package-level
// types of pkg that are reachable from its exported API.
func exposedUnexported(pkg *types.Package) []string {
	seen := map[types.Type]bool{}
	found := map[string]bool{}
	var walk func(t types.Type)
	walkTParams := func(l *types.TypeParamList) {
		for i := 0; i < l.Len(); i++ {
			walk(l.At(i).Constraint())
		}
	}
	walkSig := func(sig *types.Signature) {
		walkTParams(sig.TypeParams())
		for i := 0; i < sig.Params().Len(); i++ {
			walk(sig.Params().At(i).Type())
		}
		for i := 0; i < sig.Results().Len(); i++ {
			walk(sig.Results().At(i).Type())
		}
	}
	walk = func(t types.Type) {
		if t == nil || seen[t] {
			return
		}
		seen[t] = true
		switch t := t.(type) {
		case *types.Alias:
			walk(types.Unalias(t))
		case *types.Named:
			for i := 0; i < t.TypeArgs().Len(); i++ {
				walk(t.TypeArgs().At(i))
			}
			obj := t.Obj()
			if obj.Pkg() != pkg {
				return
			}
			if !obj.Exported() && obj.Parent() == pkg.Scope() {
				found[obj.Name()] = true
			}
			walkTParams(t.TypeParams())
			walk(t.Underlying())
			for i := 0; i < t.NumMethods(); i++ {
				if m := t.Method(i); m.Exported() {
					walkSig(m.Type().(*types.Signature))
				}
			}
		case *types.Pointer:
			walk(t.Elem())
		case *types.Slice:
			walk(t.Elem())
		case *types.Array:
			walk(t.Elem())
		case *types.Chan:
			walk(t.Elem())
		case *types.Map:
			walk(t.Key())
			walk(t.Elem())
		case *types.Signature:
			walkSig(t)
		case *types.Struct:
			for i := 0; i < t.NumFields(); i++ {
				f := t.Field(i)
				switch {
				case f.Embedded():
					// The fields and methods of an embedded type are
					// promoted and compared as part of the outer struct;
					// only look through it.
					et := types.Unalias(f.Type())
					if p, ok := et.(*types.Pointer); ok {
						et = types.Unalias(p.Elem())
					}
					if n, ok := et.(*types.Named); ok && !seen[n] {
						seen[n] = true
						walk(n.Underlying())
						for i := 0; i < n.NumMethods(); i++ {
							if m := n.Method(i); m.Exported() {
								walkSig(m.Type().(*types.Signature))
							}
						}
					} else {
						walk(et)
					}
				case f.Exported():
					walk(f.Type())
				}
			}
		case *types.Interface:
			for i := 0; i < t.NumMethods(); i++ {
				if m := t.Method(i); m.Exported() {
					walkSig(m.Type().(*types.Signature))
				}
			}
			for i := 0; i < t.NumEmbeddeds(); i++ {
				walk(t.EmbeddedType(i))
			}
		case *types.Union:
			for i := 0; i < t.Len(); i++ {
				walk(t.Term(i).Type())
			}
		}
	}
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		if o := scope.Lookup(name); o.Exported() {
			walk(o.Type())
		}
	}
	var out []string
	for n := range found {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func objKind(o types.Object) string {
	switch o := o.(type) {
	case *types.Const:
		return "const"
	case *types.Var:
		if o.IsField() {
			return "field"
		}
		return "var"
	case *types.Func:
		if sig, ok := o.Type().(*types.Signature); ok && sig.Recv() != nil {
			return "method"
		}
		return "func"
	case *types.TypeName:
		return "type"
	}
	return "object"
}

// qualifier prints package names instead of paths and omits the package
// being compared.
func (d *differ) qualifier(p *types.Package) string {
	if p == d.oldPkg || p == d.newPkg {
		return ""
	}
	return p.Name()
}

func (d *differ) str(t types.Type) string { return types.TypeString(t, d.qualifier) }

func (d *differ) compareObj(name string, o, n types.Object) {
	ok, nk := objKind(o), objKind(n)
	if ok != nk {
		d.incompatible(name, Changed, "%s: changed from %s to %s", name, ok, nk)
		return
	}
	switch o := o.(type) {
	case *types.Const:
		n := n.(*types.Const)
		if !d.ident(o.Type(), n.Type()) {
			d.incompatible(name, Changed, "const %s: type changed from %s to %s", name, d.str(o.Type()), d.str(n.Type()))
		} else if o.Val().ExactString() != n.Val().ExactString() {
			d.incompatible(name, Changed, "const %s: value changed from %s to %s", name, o.Val().ExactString(), n.Val().ExactString())
		}
	case *types.Var:
		n := n.(*types.Var)
		if !d.ident(o.Type(), n.Type()) {
			d.incompatible(name, Changed, "var %s: type changed from %s to %s", name, d.str(o.Type()), d.str(n.Type()))
		}
	case *types.Func:
		n := n.(*types.Func)
		if !d.ident(o.Type(), n.Type()) {
			d.incompatible(name, Changed, "func %s: signature changed from %s to %s", name, d.sigStr(o.Type()), d.sigStr(n.Type()))
		}
	case *types.TypeName:
		n := n.(*types.TypeName)
		d.compareTypeName(name, o, n)
	}
}

func (d *differ) sigStr(t types.Type) string {
	s := d.str(t)
	return s
}

func (d *differ) compareTypeName(name string, o, n *types.TypeName) {
	if o.IsAlias() || n.IsAlias() {
		ot, nt := types.Unalias(o.Type()), types.Unalias(n.Type())
		on, oNamed := ot.(*types.Named)
		nn, nNamed := nt.(*types.Named)
		// An alias to a type of this package, a defined type renamed and
		// kept as an alias, or an alias replaced by a defined type: compare
		// the corresponding types (once).
		if oNamed && nNamed && on.Obj().Pkg() == d.oldPkg && nn.Obj().Pkg() == d.newPkg && d.corresponds(on.Obj(), nn.Obj()) {
			if !d.ident(ot, nt) {
				d.incompatible(name, Changed, "type %s: changed from %s to %s", name, d.str(ot), d.str(nt))
				return
			}
			target := on.Obj().Name()
			if on.TypeArgs().Len() == 0 && (target == name || d.newPkg.Scope().Lookup(target) == nil) {
				d.compareNamed(name, on, nn)
			}
			return
		}
		if !d.ident(ot, nt) {
			d.incompatible(name, Changed, "type %s: changed from %s to %s", name, d.str(ot), d.str(nt))
		}
		return
	}
	on, ok1 := o.Type().(*types.Named)
	nn, ok2 := n.Type().(*types.Named)
	if !ok1 || !ok2 {
		return
	}
	d.compareNamed(name, on, nn)
}

func underKind(t types.Type) string {
	switch t.(type) {
	case *types.Struct:
		return "struct"
	case *types.Interface:
		return "interface"
	case *types.Basic:
		return "basic"
	case *types.Pointer:
		return "pointer"
	case *types.Slice:
		return "slice"
	case *types.Array:
		return "array"
	case *types.Map:
		return "map"
	case *types.Chan:
		return "chan"
	case *types.Signature:
		return "func"
	}
	return fmt.Sprintf("%T", t)
}

func (d *differ) compareNamed(name string, o, n *types.Named) {
	// Type parameters.
	otp, ntp := o.TypeParams(), n.TypeParams()
	if otp.Len() != ntp.Len() {
		d.incompatible(name, Changed, "type %s: type parameters changed from %s to %s", name, d.tparamStr(otp), d.tparamStr(ntp))
		return
	}
	for i := 0; i < otp.Len(); i++ {
		if !d.ident(otp.At(i).Constraint(), ntp.At(i).Constraint()) {
			d.incompatible(name, Changed, "type %s: constraint of type parameter %s changed from %s to %s", name,
				otp.At(i).Obj().Name(), d.str(otp.At(i).Constraint()), d.str(ntp.At(i).Constraint()))
		}
	}
	ou, nu := o.Underlying(), n.Underlying()
	if underKind(ou) != underKind(nu) {
		d.incompatible(name, Changed, "type %s: changed from %s to %s", name, d.str(ou), d.str(nu))
		return
	}
	switch ou := ou.(type) {
	case *types.Struct:
		d.compareStruct(name, o, n, ou, nu.(*types.Struct))
	case *types.Interface:
		d.compareInterface(name, ou, nu.(*types.Interface))
		return // interface methods are compared above
	default:
		if !d.ident(ou, nu) {
			d.incompatible(name, Changed, "type %s: underlying type changed from %s to %s", name, d.str(ou), d.str(nu))
		}
	}
	d.compareMethodSets(name, o, n)
}

func (d *differ) tparamStr(l *types.TypeParamList) string {
	if l.Len() == 0 {
		return "none"
	}
	var parts []string
	for i := 0; i < l.Len(); i++ {
		parts = append(parts, l.At(i).Obj().Name()+" "+d.str(l.At(i).Constraint()))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

type fieldInfo struct {
	v        *types.Var
	depth    int
	embedded bool
}

// exportedFields returns the exported fields selectable on a struct,
// including promoted fields (at the shallowest unambiguous depth).
func exportedFields(s *types.Struct) map[string]fieldInfo {
	out := map[string]fieldInfo{}
	ambiguous := map[string]bool{}
	type level struct {
		s     *types.Struct
		depth int
	}
	seen := map[*types.Named]bool{}
	cur := []*types.Struct{s}
	for depth := 0; len(cur) > 0 && depth < 16; depth++ {
		found := map[string]int{}
		var next []*types.Struct
		for _, st := range cur {
			for i := 0; i < st.NumFields(); i++ {
				f := st.Field(i)
				found[f.Name()]++
				if f.Embedded() {
					t := f.Type()
					if p, ok := types.Unalias(t).(*types.Pointer); ok {
						t = p.Elem()
					}
					t = types.Unalias(t)
					if nt, ok := t.(*types.Named); ok {
						if seen[nt] {
							continue
						}
						seen[nt] = true
					}
					if es, ok := t.Underlying().(*types.Struct); ok {
						next = append(next, es)
					}
				}
			}
		}
		for _, st := range cur {
			for i := 0; i < st.NumFields(); i++ {
				f := st.Field(i)
				if _, done := out[f.Name()]; done || ambiguous[f.Name()] {
					continue
				}
				if found[f.Name()] > 1 {
					ambiguous[f.Name()] = true
					continue
				}
				if f.Exported() {
					out[f.Name()] = fieldInfo{v: f, depth: depth, embedded: f.Embedded()}
				}
			}
		}
		cur = next
	}
	return out
}

func (d *differ) compareStruct(name string, on, nn *types.Named, o, n *types.Struct) {
	of, nf := exportedFields(o), exportedFields(n)
	for _, fname := range sortedKeys(of) {
		ofi := of[fname]
		nfi, ok := nf[fname]
		obj := name + "." + fname
		if !ok {
			d.incompatible(obj, Removed, "field %s removed", obj)
			continue
		}
		if !d.ident(ofi.v.Type(), nfi.v.Type()) {
			d.incompatible(obj, Changed, "field %s: type changed from %s to %s", obj, d.str(ofi.v.Type()), d.str(nfi.v.Type()))
			continue
		}
		if ofi.depth == 0 && nfi.depth == 0 && ofi.embedded != nfi.embedded {
			if ofi.embedded {
				d.incompatible(obj, Changed, "field %s is no longer embedded", obj)
			} else {
				d.incompatible(obj, Changed, "field %s is now embedded", obj)
			}
		}
	}
	for _, fname := range sortedKeys(nf) {
		if _, ok := of[fname]; !ok {
			d.compatible(name+"."+fname, Added, "field %s.%s added", name, fname)
		}
	}
	if types.Comparable(on) && !types.Comparable(nn) {
		d.incompatible(name, Changed, "type %s is no longer comparable", name)
	}
}

func sortedKeys[V any](m map[string]V) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func (d *differ) compareInterface(name string, o, n *types.Interface) {
	om, nm := map[string]*types.Func{}, map[string]*types.Func{}
	sealed := false
	for i := 0; i < o.NumMethods(); i++ {
		m := o.Method(i)
		if !m.Exported() {
			sealed = true
			continue
		}
		om[m.Name()] = m
	}
	newSealed := false
	for i := 0; i < n.NumMethods(); i++ {
		if m := n.Method(i); m.Exported() {
			nm[m.Name()] = m
		} else {
			newSealed = true
		}
	}
	if !sealed && newSealed && o.IsMethodSet() {
		d.incompatible(name, Changed, "interface %s gained an unexported method: implementations outside the package no longer satisfy it", name)
	}
	for _, mname := range sortedKeys(om) {
		obj := name + "." + mname
		m2, ok := nm[mname]
		if !ok {
			d.incompatible(obj, Removed, "method %s removed from interface", obj)
			continue
		}
		if !d.ident(om[mname].Type(), m2.Type()) {
			d.incompatible(obj, Changed, "method %s: signature changed from %s to %s", obj, d.str(om[mname].Type()), d.str(m2.Type()))
		}
	}
	for _, mname := range sortedKeys(nm) {
		if _, ok := om[mname]; ok {
			continue
		}
		obj := name + "." + mname
		if sealed {
			d.compatible(obj, Added, "method %s added to interface (it has unexported methods, so only this package can implement it)", obj)
		} else {
			d.incompatible(obj, Added, "method %s added to interface: existing implementations no longer satisfy it", obj)
		}
	}
	if !d.termsIdent(o, n) {
		d.incompatible(name, Changed, "type %s: type constraint changed from %s to %s", name, d.str(o), d.str(n))
	}
}

func (d *differ) compareMethodSets(name string, o, n *types.Named) {
	oval, optr := types.NewMethodSet(o), types.NewMethodSet(types.NewPointer(o))
	nval, nptr := types.NewMethodSet(n), types.NewMethodSet(types.NewPointer(n))
	lookup := func(ms *types.MethodSet, name string) *types.Selection {
		for i := 0; i < ms.Len(); i++ {
			if s := ms.At(i); s.Obj().Name() == name {
				return s
			}
		}
		return nil
	}
	var names []string
	for i := 0; i < optr.Len(); i++ {
		if s := optr.At(i); s.Obj().Exported() {
			names = append(names, s.Obj().Name())
		}
	}
	sort.Strings(names)
	for _, m := range names {
		obj := name + "." + m
		os := lookup(optr, m)
		ns := lookup(nptr, m)
		if ns == nil {
			d.incompatible(obj, Removed, "method %s removed", obj)
			continue
		}
		if !d.ident(os.Obj().Type(), ns.Obj().Type()) {
			d.incompatible(obj, Changed, "method %s: signature changed from %s to %s", obj, d.methodStr(os.Obj()), d.methodStr(ns.Obj()))
			continue
		}
		if lookup(oval, m) != nil && lookup(nval, m) == nil {
			d.incompatible(obj, Changed, "method %s now has a pointer receiver: it is no longer in the method set of %s", obj, name)
		}
	}
	var added []string
	for i := 0; i < nptr.Len(); i++ {
		s := nptr.At(i)
		if s.Obj().Exported() && lookup(optr, s.Obj().Name()) == nil {
			added = append(added, s.Obj().Name())
		}
	}
	sort.Strings(added)
	for _, m := range added {
		d.compatible(name+"."+m, Added, "method %s.%s added", name, m)
	}
}

func (d *differ) methodStr(o types.Object) string {
	sig, ok := o.Type().(*types.Signature)
	if !ok {
		return d.str(o.Type())
	}
	s := types.NewSignatureType(nil, nil, nil, sig.Params(), sig.Results(), sig.Variadic())
	return d.str(s)
}

// ---------- type identity across versions ----------

func (d *differ) samePkg(o, n *types.Package) bool {
	if o == nil || n == nil {
		return o == nil && n == nil
	}
	if o == d.oldPkg && n == d.newPkg {
		return true
	}
	op, np := o.Path(), n.Path()
	if op == np {
		return true
	}
	if d.oldMod != "" && d.newMod != "" {
		if rel(op, d.oldMod) != "\x00" && rel(op, d.oldMod) == rel(np, d.newMod) {
			return true
		}
	}
	return false
}

// rel returns path relative to mod ("" for the module root package) or
// "\x00" if path is not in mod.
func rel(path, mod string) string {
	if path == mod {
		return ""
	}
	if strings.HasPrefix(path, mod+"/") {
		return path[len(mod)+1:]
	}
	return "\x00"
}

func (d *differ) ident(o, n types.Type) bool {
	o, n = types.Unalias(o), types.Unalias(n)
	switch o := o.(type) {
	case *types.Basic:
		n, ok := n.(*types.Basic)
		return ok && o.Kind() == n.Kind()
	case *types.Pointer:
		n, ok := n.(*types.Pointer)
		return ok && d.ident(o.Elem(), n.Elem())
	case *types.Slice:
		n, ok := n.(*types.Slice)
		return ok && d.ident(o.Elem(), n.Elem())
	case *types.Array:
		n, ok := n.(*types.Array)
		return ok && o.Len() == n.Len() && d.ident(o.Elem(), n.Elem())
	case *types.Map:
		n, ok := n.(*types.Map)
		return ok && d.ident(o.Key(), n.Key()) && d.ident(o.Elem(), n.Elem())
	case *types.Chan:
		n, ok := n.(*types.Chan)
		return ok && o.Dir() == n.Dir() && d.ident(o.Elem(), n.Elem())
	case *types.Signature:
		n, ok := n.(*types.Signature)
		return ok && d.sigIdent(o, n)
	case *types.Tuple:
		n, ok := n.(*types.Tuple)
		if !ok || o.Len() != n.Len() {
			return false
		}
		for i := 0; i < o.Len(); i++ {
			if !d.ident(o.At(i).Type(), n.At(i).Type()) {
				return false
			}
		}
		return true
	case *types.Struct:
		n, ok := n.(*types.Struct)
		if !ok || o.NumFields() != n.NumFields() {
			return false
		}
		for i := 0; i < o.NumFields(); i++ {
			of, nf := o.Field(i), n.Field(i)
			if of.Name() != nf.Name() || of.Embedded() != nf.Embedded() || o.Tag(i) != n.Tag(i) || !d.ident(of.Type(), nf.Type()) {
				return false
			}
		}
		return true
	case *types.Interface:
		n, ok := n.(*types.Interface)
		if !ok || o.NumMethods() != n.NumMethods() {
			return false
		}
		for i := 0; i < o.NumMethods(); i++ {
			om, nm := o.Method(i), n.Method(i)
			if om.Name() != nm.Name() || !d.ident(om.Type(), nm.Type()) {
				return false
			}
		}
		return d.termsIdent(o, n)
	case *types.Union:
		n, ok := n.(*types.Union)
		if !ok || o.Len() != n.Len() {
			return false
		}
		for i := 0; i < o.Len(); i++ {
			if o.Term(i).Tilde() != n.Term(i).Tilde() || !d.ident(o.Term(i).Type(), n.Term(i).Type()) {
				return false
			}
		}
		return true
	case *types.Named:
		n, ok := n.(*types.Named)
		if !ok {
			return false
		}
		if o.Obj().Pkg() == d.oldPkg && n.Obj().Pkg() == d.newPkg {
			if !d.corresponds(o.Obj(), n.Obj()) {
				return false
			}
		} else if o.Obj().Name() != n.Obj().Name() || !d.samePkg(o.Obj().Pkg(), n.Obj().Pkg()) {
			return false
		}
		oa, na := o.TypeArgs(), n.TypeArgs()
		if oa.Len() != na.Len() {
			return false
		}
		for i := 0; i < oa.Len(); i++ {
			if !d.ident(oa.At(i), na.At(i)) {
				return false
			}
		}
		return true
	case *types.TypeParam:
		n, ok := n.(*types.TypeParam)
		return ok && o.Index() == n.Index()
	}
	return types.Identical(o, n)
}

// termsIdent compares the non-interface embedded elements (type terms) of
// two interfaces, which define constraint type sets.
func (d *differ) termsIdent(o, n *types.Interface) bool {
	terms := func(i *types.Interface) []types.Type {
		var out []types.Type
		for k := 0; k < i.NumEmbeddeds(); k++ {
			e := i.EmbeddedType(k)
			// Embedded named method-set interfaces are compared through
			// their methods; embedded constraint interfaces (with type
			// terms) define the type set and are compared as terms.
			if ei, isIface := types.Unalias(e).Underlying().(*types.Interface); isIface && ei.IsMethodSet() {
				if _, isNamed := types.Unalias(e).(*types.Named); isNamed {
					continue
				}
			}
			out = append(out, e)
		}
		return out
	}
	ot, nt := terms(o), terms(n)
	if len(ot) != len(nt) {
		return false
	}
	for i := range ot {
		if !d.ident(ot[i], nt[i]) {
			return false
		}
	}
	return o.IsComparable() == n.IsComparable()
}

func (d *differ) sigIdent(o, n *types.Signature) bool {
	if o.Variadic() != n.Variadic() {
		return false
	}
	if o.TypeParams().Len() != n.TypeParams().Len() {
		return false
	}
	for i := 0; i < o.TypeParams().Len(); i++ {
		if !d.ident(o.TypeParams().At(i).Constraint(), n.TypeParams().At(i).Constraint()) {
			return false
		}
	}
	return d.ident(o.Params(), n.Params()) && d.ident(o.Results(), n.Results())
}
