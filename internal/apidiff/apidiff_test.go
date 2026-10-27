package apidiff

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"sort"
	"strings"
	"testing"
)

// typeCheck type-checks single-file packages. srcs maps import path to
// source; packages may import each other (listed dependencies first).
func typeCheck(t *testing.T, order []string, srcs map[string]string) map[string]*types.Package {
	t.Helper()
	fset := token.NewFileSet()
	pkgs := map[string]*types.Package{}
	for _, path := range order {
		f, err := parser.ParseFile(fset, path+"/x.go", srcs[path], 0)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		conf := types.Config{Importer: importerFunc(func(p string) (*types.Package, error) {
			if pk, ok := pkgs[p]; ok {
				return pk, nil
			}
			return nil, fmt.Errorf("no package %s", p)
		})}
		pkg, err := conf.Check(path, fset, []*ast.File{f}, nil)
		if err != nil {
			t.Fatalf("%s: %v\n%s", path, err, srcs[path])
		}
		pkgs[path] = pkg
	}
	return pkgs
}

type importerFunc func(string) (*types.Package, error)

func (f importerFunc) Import(p string) (*types.Package, error) { return f(p) }

func objects(cs []Change) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Object)
	}
	sort.Strings(out)
	return out
}

func TestCompare(t *testing.T) {
	tests := []struct {
		name         string
		old, new     string
		incompatible []string // objects of incompatible changes
		compatible   []string // objects of compatible changes
		msg          string   // substring of the first incompatible message
	}{
		{name: "identical", old: "func F(a int) error { return nil }", new: "func F(b int) error { return nil }"},
		{name: "func removed", old: "func F() {}\nfunc G() {}", new: "func G() {}", incompatible: []string{"F"}, msg: "func F removed"},
		{name: "func unexported", old: "func F() {}", new: "func f() {}", incompatible: []string{"F"}},
		{name: "func added", old: "", new: "func F() {}", compatible: []string{"F"}},
		{name: "unexported changes ignored", old: "func f(int) {}\nvar x int", new: "func f(string) {}\nvar x string"},
		{name: "param type", old: "func F(int) {}", new: "func F(int64) {}", incompatible: []string{"F"}, msg: "signature changed from func(int) to func(int64)"},
		{name: "param added", old: "func F(int) {}", new: "func F(int, string) {}", incompatible: []string{"F"}},
		{name: "variadic added", old: "func F(int) {}", new: "func F(int, ...int) {}", incompatible: []string{"F"}},
		{name: "variadic flag", old: "func F(a []int) {}", new: "func F(a ...int) {}", incompatible: []string{"F"}},
		{name: "result added", old: "func F() {}", new: "func F() error { return nil }", incompatible: []string{"F"}},
		{name: "const value", old: "const C = 1", new: "const C = 2", incompatible: []string{"C"}, msg: "value changed from 1 to 2"},
		{name: "const type", old: "const C int = 1", new: "const C int64 = 1", incompatible: []string{"C"}, msg: "type changed"},
		{name: "const same", old: "const C = 1 + 1", new: "const C = 2"},
		{name: "var type", old: "var V int", new: "var V string", incompatible: []string{"V"}},
		{name: "kind change", old: "const C = 1", new: "var C = 1", incompatible: []string{"C"}, msg: "changed from const to var"},
		{name: "func to var", old: "func F() {}", new: "var F = func() {}", incompatible: []string{"F"}},
		{name: "type underlying", old: "type T int", new: "type T string", incompatible: []string{"T"}},
		{name: "type kind", old: "type T int", new: "type T struct{}", incompatible: []string{"T"}},
		{name: "defined to alias", old: "type T int", new: "type T = int", incompatible: []string{"T"}},
		{name: "alias target", old: "type T = int", new: "type T = string", incompatible: []string{"T"}},
		{name: "alias to own type", old: "type U struct{ A int }\ntype T = U", new: "type U struct{ A int }\ntype T = U"},
		{name: "field removed", old: "type S struct{ A, B int }", new: "type S struct{ A int }", incompatible: []string{"S.B"}, msg: "field S.B removed"},
		{name: "field added", old: "type S struct{ A int }", new: "type S struct{ A, B int }", compatible: []string{"S.B"}},
		{name: "field type", old: "type S struct{ A int }", new: "type S struct{ A uint }", incompatible: []string{"S.A"}},
		{name: "field unexported", old: "type S struct{ A int }", new: "type S struct{ a int }", incompatible: []string{"S.A"}, compatible: nil},
		{name: "unexported field added", old: "type S struct{ A int }", new: "type S struct{ A int; b int }"},
		{name: "no longer comparable", old: "type S struct{ A int }", new: "type S struct{ A int; b []int }", incompatible: []string{"S"}, msg: "no longer comparable"},
		{name: "embedded field promoted removed", old: "type E struct{ X int }\ntype S struct{ E }", new: "type E struct{}\ntype S struct{ E }",
			incompatible: []string{"E.X", "S.X"}},
		{name: "embedding to named field", old: "type E struct{}\ntype S struct{ E }", new: "type E struct{}\ntype S struct{ E E }", incompatible: []string{"S.E"}, msg: "no longer embedded"},
		{name: "promoted via unexported embed", old: "type e struct{ X int }\ntype S struct{ e }", new: "type e struct{}\ntype S struct{ e }", incompatible: []string{"S.X"}},
		{name: "method removed", old: "type T int\nfunc (T) M() {}", new: "type T int", incompatible: []string{"T.M"}, msg: "method T.M removed"},
		{name: "method added", old: "type T int", new: "type T int\nfunc (T) M() {}", compatible: []string{"T.M"}},
		{name: "method signature", old: "type T int\nfunc (T) M(int) {}", new: "type T int\nfunc (T) M(string) {}", incompatible: []string{"T.M"}},
		{name: "value to pointer receiver", old: "type T int\nfunc (T) M() {}", new: "type T int\nfunc (*T) M() {}", incompatible: []string{"T.M"}, msg: "pointer receiver"},
		{name: "pointer to value receiver", old: "type T int\nfunc (*T) M() {}", new: "type T int\nfunc (T) M() {}"},
		{name: "promoted method removed", old: "type E struct{}\nfunc (E) M() {}\ntype S struct{ E }", new: "type E struct{}\ntype S struct{ E }", incompatible: []string{"E.M", "S.M"}},
		{name: "interface method added", old: "type I interface{ M() }", new: "type I interface{ M(); N() }", incompatible: []string{"I.N"}, msg: "added to interface"},
		{name: "sealed interface method added", old: "type I interface{ M(); m() }", new: "type I interface{ M(); N(); m() }", compatible: []string{"I.N"}},
		{name: "interface method removed", old: "type I interface{ M(); N() }", new: "type I interface{ M() }", incompatible: []string{"I.N"}},
		{name: "interface method changed", old: "type I interface{ M() int }", new: "type I interface{ M() string }", incompatible: []string{"I.M"}},
		{name: "interface embedded addition", old: "type J interface{ N() }\ntype I interface{ M() }", new: "type J interface{ N() }\ntype I interface{ M(); J }", incompatible: []string{"I.N"}},
		{name: "self-referential type", old: "type L struct{ Next *L }\nfunc (l *L) Walk(f func(*L)) {}", new: "type L struct{ Next *L }\nfunc (l *L) Walk(f func(*L)) {}"},
		{name: "type params added", old: "type B struct{}", new: "type B[T any] struct{}", incompatible: []string{"B"}},
		{name: "constraint narrowed", old: "type B[T any] struct{ V T }", new: "type B[T comparable] struct{ V T }", incompatible: []string{"B"}, msg: "constraint"},
		{name: "generic func constraint", old: "func F[T any](T) {}", new: "func F[T ~int](T) {}", incompatible: []string{"F"}},
		{name: "generic func same", old: "func F[T any](x T) T { return x }", new: "func F[U any](y U) U { return y }"},
		{name: "constraint terms", old: "type N interface{ ~int | ~int64 }", new: "type N interface{ ~int }", incompatible: []string{"N"}},
		{name: "exposed unexported type", old: "type t struct{ A, B int }\nfunc New() *t { return nil }", new: "type t struct{ A int }\nfunc New() *t { return nil }", incompatible: []string{"t.B"}},
		{name: "unexposed unexported type", old: "type t struct{ A, B int }", new: "type t struct{ A int }"},
		{name: "chan direction", old: "func F(chan int) {}", new: "func F(<-chan int) {}", incompatible: []string{"F"}},
		{name: "array length", old: "var V [2]int", new: "var V [3]int", incompatible: []string{"V"}},
		{name: "map key", old: "var V map[string]int", new: "var V map[int]int", incompatible: []string{"V"}},
		{name: "interface sealed by unexported method", old: "type I interface{ M() }", new: "type I interface{ M(); m() }", incompatible: []string{"I"}, msg: "unexported method"},
		{name: "renamed type kept as alias", old: "type Old struct{ A int }\nfunc F(Old) {}\nfunc (Old) M() {}", new: "type New struct{ A int }\nfunc (New) M() {}\ntype Old = New\nfunc F(Old) {}\nfunc G(New) {}",
			compatible: []string{"G", "New"}},
		{name: "renamed type alias loses field", old: "type Old struct{ A, B int }", new: "type New struct{ A int }\ntype Old = New", incompatible: []string{"Old.B"}, compatible: []string{"New"}},
		{name: "alias replaced by defined type", old: "type U struct{ A int }\ntype T = U\nfunc F(T) {}", new: "type T struct{ A int }\nfunc F(T) {}", incompatible: []string{"U"}},
		{name: "struct tag in unnamed struct", old: "var V struct{ A int `json:\"a\"` }", new: "var V struct{ A int `json:\"b\"` }", incompatible: []string{"V"}},
		{name: "struct tag in named struct", old: "type S struct{ A int `json:\"a\"` }", new: "type S struct{ A int `json:\"b\"` }"},
		{name: "named constraint changed", old: "type A interface{ ~int }\ntype B interface{ ~string }\nfunc F[T A](T) {}", new: "type A interface{ ~int }\ntype B interface{ ~string }\nfunc F[T B](T) {}", incompatible: []string{"F"}},
		{name: "embedded constraint changed", old: "type A interface{ ~int }\ntype B interface{ ~string }\ntype C interface{ A }", new: "type A interface{ ~int }\ntype B interface{ ~string }\ntype C interface{ B }", incompatible: []string{"C"}},
		{name: "generic method receiver", old: "type L[T any] struct{}\nfunc (L[T]) Get() T { var z T; return z }", new: "type L[T any] struct{}\nfunc (*L[T]) Get() T { var z T; return z }", incompatible: []string{"L.Get"}, msg: "pointer receiver"},
		{name: "generic method signature", old: "type L[T any] struct{}\nfunc (L[T]) Get() T { var z T; return z }", new: "type L[T any] struct{}\nfunc (L[T]) Get() []T { return nil }", incompatible: []string{"L.Get"}},
		{name: "generic method same", old: "type L[T any] struct{ v T }\nfunc (l L[T]) Get() (T, L[T]) { return l.v, l }", new: "type L[U any] struct{ v U }\nfunc (l L[U]) Get() (U, L[U]) { return l.v, l }"},
		{name: "generic type param order", old: "type P[K comparable, V any] struct{}\nfunc F[K comparable, V any](P[K, V]) {}", new: "type P[K comparable, V any] struct{}\nfunc F[V any, K comparable](P[K, V]) {}", incompatible: []string{"F"}},
		{name: "generic instantiation arg", old: "type L[T any] struct{}\nvar V L[int]", new: "type L[T any] struct{}\nvar V L[string]", incompatible: []string{"V"}},
		{name: "embedded pointer promotes pointer methods", old: "type E struct{}\nfunc (*E) M() {}\ntype S struct{ *E }", new: "type E struct{}\nfunc (*E) M() {}\ntype S struct{ E }",
			incompatible: []string{"S.E", "S.M"}},
		{name: "promoted field becomes ambiguous", old: "type A struct{ X int }\ntype B struct{ Y int }\ntype S struct{ A; B }", new: "type A struct{ X int }\ntype B struct{ X, Y int }\ntype S struct{ A; B }",
			incompatible: []string{"S.X"}, compatible: []string{"B.X"}},
		{name: "promoted method shadowed by deeper ambiguity", old: "type A struct{}\nfunc (A) M() {}\ntype B struct{}\ntype S struct{ A; B }", new: "type A struct{}\nfunc (A) M() {}\ntype B struct{}\nfunc (B) M() {}\ntype S struct{ A; B }",
			incompatible: []string{"S.M"}, compatible: []string{"B.M"}},
		{name: "exposed unexported constraint", old: "type c interface{ M() }\nfunc F[T c](T) {}", new: "type c interface{ M(); N() }\nfunc F[T c](T) {}", incompatible: []string{"c.N"}},
		{name: "exposed unexported method set", old: "type t struct{}\nfunc (t) M() {}\nvar V t", new: "type t struct{}\nvar V t", incompatible: []string{"t.M"}},
		{name: "generic alias to own type", old: "type U[T any] struct{ A T }\ntype T = U[int]", new: "type U[T any] struct{ A T }\ntype T = U[int]"},
		{name: "alias instantiation changed", old: "type U[T any] struct{ A T }\ntype T = U[int]", new: "type U[T any] struct{ A T }\ntype T = U[string]", incompatible: []string{"T"}},
		{name: "struct tag ignored order", old: "var V struct{ A int }", new: "var V struct{ B int }", incompatible: []string{"V"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := typeCheck(t, []string{"p"}, map[string]string{"p": "package p\n" + tt.old})["p"]
			n := typeCheck(t, []string{"p"}, map[string]string{"p": "package p\n" + tt.new})["p"]
			r := Compare(o, n)
			if got := objects(r.Incompatible); strings.Join(got, ",") != strings.Join(tt.incompatible, ",") {
				t.Errorf("incompatible = %v, want %v\n%+v", got, tt.incompatible, r.Incompatible)
			}
			if got := objects(r.Compatible); strings.Join(got, ",") != strings.Join(tt.compatible, ",") {
				t.Errorf("compatible = %v, want %v\n%+v", got, tt.compatible, r.Compatible)
			}
			if tt.msg != "" && len(r.Incompatible) > 0 && !strings.Contains(r.Incompatible[0].Message, tt.msg) {
				t.Errorf("message %q does not contain %q", r.Incompatible[0].Message, tt.msg)
			}
			for _, c := range append(r.Incompatible, r.Compatible...) {
				if c.Package != "p" || c.Kind == "" || c.Message == "" {
					t.Errorf("bad change %+v", c)
				}
			}
			wantBump := "patch"
			if len(tt.incompatible) > 0 {
				wantBump = "major"
			} else if len(tt.compatible) > 0 {
				wantBump = "minor"
			}
			if r.Bump() != wantBump {
				t.Errorf("Bump = %s, want %s", r.Bump(), wantBump)
			}
		})
	}
}

func TestCompareCrossPackageTypes(t *testing.T) {
	// A type from another package of the module changes identity only if
	// its package path or name changes.
	o := typeCheck(t, []string{"m/a", "m"}, map[string]string{
		"m/a": "package a\ntype A int",
		"m":   "package m\nimport \"m/a\"\nfunc F(a.A) {}",
	})
	n := typeCheck(t, []string{"m/b", "m"}, map[string]string{
		"m/b": "package a\ntype A int",
		"m":   "package m\nimport a \"m/b\"\nfunc F(a.A) {}",
	})
	r := Compare(o["m"], n["m"])
	if len(r.Incompatible) != 1 || r.Incompatible[0].Object != "F" {
		t.Fatalf("moving a parameter type to another package must be incompatible: %+v", r)
	}
}

func TestCompareModulesAcrossMajors(t *testing.T) {
	o := typeCheck(t, []string{"example.com/m/sub", "example.com/m", "example.com/m/gone"}, map[string]string{
		"example.com/m/sub":  "package sub\ntype S struct{ X int }",
		"example.com/m":      "package m\nimport \"example.com/m/sub\"\ntype T struct{}\nfunc New() *T { return nil }\nfunc Use(sub.S) {}\nfunc Old() {}",
		"example.com/m/gone": "package gone",
	})
	n := typeCheck(t, []string{"example.com/m/v2/sub", "example.com/m/v2", "example.com/m/v2/extra"}, map[string]string{
		"example.com/m/v2/sub":   "package sub\ntype S struct{ X int }",
		"example.com/m/v2":       "package m\nimport \"example.com/m/v2/sub\"\ntype T struct{}\nfunc New() *T { return nil }\nfunc Use(sub.S) {}",
		"example.com/m/v2/extra": "package extra",
	})
	om := &Module{Path: "example.com/m", Version: "v1.5.0", Packages: o}
	nm := &Module{Path: "example.com/m/v2", Version: "v2.0.0", Packages: n}
	r := CompareModules(om, nm, nil)
	var inc []string
	for _, c := range r.Incompatible {
		inc = append(inc, c.Package+" "+c.Object)
	}
	sort.Strings(inc)
	want := []string{"example.com/m/v2 Old", "example.com/m/v2/gone "}
	if strings.Join(inc, "|") != strings.Join(want, "|") {
		t.Fatalf("incompatible = %q, want %q", inc, want)
	}
	if len(r.Compatible) != 1 || r.Compatible[0].Package != "example.com/m/v2/extra" {
		t.Fatalf("compatible = %+v", r.Compatible)
	}
	// Restricting to packages.
	r = CompareModules(om, nm, map[string]bool{"sub": true})
	if len(r.Incompatible)+len(r.Compatible) != 0 {
		t.Fatalf("restricted report = %+v", r)
	}
	bp := CompareModules(om, nm, nil).ByPackage()
	if len(bp) != 3 || bp[0].Package != "example.com/m/v2" || bp[0].Incompatible[0].Object != "Old" {
		t.Fatalf("ByPackage = %+v", bp)
	}
	// Same module path: package paths map one to one.
	if r := CompareModules(om, om, nil); len(r.Incompatible)+len(r.Compatible) != 0 {
		t.Fatalf("self-compare = %+v", r)
	}
}

func TestUsageAffects(t *testing.T) {
	u := Usage{}
	u.add("m", "F", "a.go:1:1")
	u.add("m", "I", "a.go:2:1")
	u.add("m", "T.M", "a.go:3:1")
	u.add("m", "T", "a.go:3:1")
	cases := []struct {
		c    Change
		want int
	}{
		{Change{Package: "m", Object: "F", Kind: Removed}, 1},
		{Change{Package: "m", Object: "G", Kind: Removed}, 0},
		{Change{Package: "m", Object: "I.N", Kind: Added}, 1},
		{Change{Package: "m", Object: "T.M", Kind: Changed}, 1},
		{Change{Package: "m", Object: "T.X", Kind: Removed}, 0},
		{Change{Package: "m", Kind: Removed}, 3},
	}
	for _, c := range cases {
		if got := u.Affects("m", c.c); len(got) != c.want {
			t.Errorf("Affects(%+v) = %v, want %d", c.c, got, c.want)
		}
	}
	if IsInternal("a/b") || !IsInternal("a/internal/b") || !IsInternal("internal") || !IsInternal("a/internal") {
		t.Error("IsInternal")
	}
}
