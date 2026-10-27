package deps

import (
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

// compareGoModGraph checks that 'sm-go graph --format text' prints the
// same edges as 'go mod graph' (run on a copy, since -mod=mod may edit
// go.mod).
func compareGoModGraph(t *testing.T, w *testenv.World, dir string, env []string) []string {
	t.Helper()
	r := w.RunEnv(dir, env, "graph", "--format", "text")
	expectCode(t, r, 0)
	got := lines(r.Stdout)
	cp := copyDir(t, dir)
	want := lines(goOut(t, w, cp, env, "mod", "graph"))
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("sm-go graph --format text differs from go mod graph\n--- sm-go\n%s\n--- go\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	return got
}

func TestGraphMatchesGoModGraphPruned(t *testing.T) {
	w := baseWorld(t)
	dir := mainProject(w, nil)
	got := compareGoModGraph(t, w, dir, nil)
	// e's requirement on b v1.3.0 is pruned out: not an edge.
	for _, l := range got {
		if strings.HasPrefix(l, "example.com/e@v1.0.0 ") {
			t.Fatalf("pruned edge printed: %s", l)
		}
	}
}

// oldWorld publishes go 1.16 modules (no pruning in their go.mod):
//
//	o v1.0.0 -> p v1.0.0, q v1.0.0
//	p v1.0.0 -> q v1.1.0
//	q v1.0.0, v1.1.0, v1.2.0
//	r v1.0.0 -> q v1.2.0 (go 1.21, pruned)
func oldWorld(t *testing.T) *testenv.World {
	needGo(t)
	w := testenv.New(t)
	w.AddModule("example.com/o", "v1.0.0", map[string]string{
		"go.mod": testenv.GoModFile("example.com/o", "1.16", "example.com/p@v1.0.0", "example.com/q@v1.0.0"),
		"o.go":   pkgFile("o", "example.com/p"),
	})
	w.AddModule("example.com/p", "v1.0.0", map[string]string{
		"go.mod": testenv.GoModFile("example.com/p", "1.16", "example.com/q@v1.1.0"),
		"p.go":   pkgFile("p", "example.com/q"),
	})
	for _, v := range []string{"v1.0.0", "v1.1.0", "v1.2.0"} {
		w.AddModule("example.com/q", v, map[string]string{"go.mod": "module example.com/q\n\ngo 1.16\n", "q.go": pkgFile("q")})
	}
	w.AddModule("example.com/r", "v1.0.0", map[string]string{
		"go.mod": testenv.GoModFile("example.com/r", "1.21", "example.com/q@v1.2.0"),
		"r.go":   pkgFile("r"),
	})
	return w
}

// A go 1.16 dependency of a pruned main module is expanded transitively.
func TestGraphMatchesGoModGraphOldDependency(t *testing.T) {
	w := oldWorld(t)
	dir := w.Project(map[string]string{
		"go.mod":  testenv.GoModFile("example.com/main", "1.22", "example.com/o@v1.0.0"),
		"main.go": "package main\n\nimport _ \"example.com/o\"\n\nfunc main() {}\n",
	})
	compareGoModGraph(t, w, dir, nil)
}

func TestGraphMatchesGoModGraphUnpruned(t *testing.T) {
	w := oldWorld(t)
	dir := w.Project(map[string]string{
		"go.mod":  testenv.GoModFile("example.com/main", "1.16", "example.com/o@v1.0.0", "example.com/q@v1.0.0"),
		"main.go": "package main\n\nimport _ \"example.com/o\"\n\nfunc main() {}\n",
	})
	compareGoModGraph(t, w, dir, nil)
}

func TestGraphMatchesGoModGraphUnprunedBase(t *testing.T) {
	w := baseWorld(t)
	dir := w.Project(map[string]string{
		"go.mod":  testenv.GoModFile("example.com/main", "1.21", "example.com/a@v1.0.0", "example.com/c@v1.0.0", "example.com/d@v1.0.0"),
		"main.go": "package main\n\nimport (\n\t_ \"example.com/a\"\n\t_ \"example.com/c\"\n\t_ \"example.com/d\"\n)\n\nfunc main() {}\n",
	})
	compareGoModGraph(t, w, dir, nil)
}

func TestGraphMatchesGoModGraphExcludeReplace(t *testing.T) {
	w := baseWorld(t)
	dir := w.Project(map[string]string{
		"go.mod": testenv.GoModFile("example.com/main", "1.22", "example.com/a@v1.0.0", "example.com/c@v1.0.0", "example.com/d@v1.0.0") +
			"\nexclude example.com/b v1.2.0\n\nreplace example.com/d => example.com/d v1.0.0\n",
		"main.go": "package main\n\nimport (\n\t_ \"example.com/a\"\n\t_ \"example.com/c\"\n)\n\nfunc main() {}\n",
	})
	compareGoModGraph(t, w, dir, nil)
}

// The main module requires b below what a dependency requires: the go
// command raises the root.
func TestGraphMatchesGoModGraphInconsistentRoot(t *testing.T) {
	w := baseWorld(t)
	dir := w.Project(map[string]string{
		"go.mod":  testenv.GoModFile("example.com/main", "1.22", "example.com/a@v1.0.0", "example.com/b@v1.0.0"),
		"main.go": "package main\n\nimport (\n\t_ \"example.com/a\"\n\t_ \"example.com/b\"\n)\n\nfunc main() {}\n",
	})
	compareGoModGraph(t, w, dir, nil)
}

// A dependency requiring an old version of the main module.
func TestGraphMatchesGoModGraphMainCycle(t *testing.T) {
	w := baseWorld(t)
	w.AddModule("example.com/main", "v1.0.0", map[string]string{
		"go.mod": testenv.GoModFile("example.com/main", "1.21", "example.com/b@v1.3.0"),
		"m.go":   pkgFile("main2"),
	})
	w.AddModule("example.com/cy", "v1.0.0", map[string]string{
		"go.mod": testenv.GoModFile("example.com/cy", "1.21", "example.com/main@v1.0.0"),
		"cy.go":  pkgFile("cy"),
	})
	dir := w.Project(map[string]string{
		"go.mod":  testenv.GoModFile("example.com/main", "1.22", "example.com/cy@v1.0.0", "example.com/a@v1.0.0"),
		"main.go": "package main\n\nimport (\n\t_ \"example.com/a\"\n\t_ \"example.com/cy\"\n)\n\nfunc main() {}\n",
	})
	compareGoModGraph(t, w, dir, nil)
}

// +incompatible and pseudo-versions.
func TestGraphMatchesGoModGraphIncompatiblePseudo(t *testing.T) {
	w := baseWorld(t)
	w.AddModule("example.com/inc", "v2.0.0+incompatible", map[string]string{"go.mod": "", "inc.go": pkgFile("inc")})
	w.AddModule("example.com/ps", "v0.0.0-20250101000000-abcdefabcdef", map[string]string{
		"go.mod": testenv.GoModFile("example.com/ps", "1.21", "example.com/b@v1.3.0"),
		"ps.go":  pkgFile("ps"),
	})
	dir := w.Project(map[string]string{
		"go.mod":  testenv.GoModFile("example.com/main", "1.22", "example.com/inc@v2.0.0+incompatible", "example.com/ps@v0.0.0-20250101000000-abcdefabcdef", "example.com/a@v1.0.0"),
		"main.go": "package main\n\nimport (\n\t_ \"example.com/a\"\n\t_ \"example.com/inc\"\n\t_ \"example.com/ps\"\n)\n\nfunc main() {}\n",
	})
	compareGoModGraph(t, w, dir, nil)
}

// A local directory replacement.
func TestGraphMatchesGoModGraphLocalReplace(t *testing.T) {
	w := baseWorld(t)
	dir := w.Project(map[string]string{
		"go.mod":         testenv.GoModFile("example.com/main", "1.22", "example.com/a@v1.0.0") + "\nreplace example.com/a => ./local/a\n",
		"main.go":        "package main\n\nimport _ \"example.com/a\"\n\nfunc main() {}\n",
		"local/a/go.mod": testenv.GoModFile("example.com/a", "1.21", "example.com/c@v1.0.0"),
		"local/a/a.go":   pkgFile("a", "example.com/c"),
	})
	compareGoModGraph(t, w, dir, nil)
}

// workspaceWorld writes a go.work with two modules: x requires a, y
// requires c and x at a published version.
func workspaceDir(t *testing.T, w *testenv.World, extra map[string]string) string {
	files := map[string]string{
		"go.work":  "go 1.23\n\nuse (\n\t./x\n\t./y\n)\n",
		"x/go.mod": testenv.GoModFile("example.com/x", "1.22", "example.com/a@v1.0.0"),
		"x/x.go":   pkgFile("x", "example.com/a"),
		"y/go.mod": testenv.GoModFile("example.com/y", "1.22", "example.com/c@v1.0.0", "example.com/b@v1.0.0"),
		"y/y.go":   pkgFile("y", "example.com/c", "example.com/b"),
	}
	for k, v := range extra {
		files[k] = v
	}
	return w.Project(files)
}

func TestGraphMatchesGoModGraphWorkspace(t *testing.T) {
	w := baseWorld(t)
	dir := workspaceDir(t, w, nil)
	compareGoModGraph(t, w, dir, []string{"GOWORK="})
}

// The footnote about "requirements pruned" appears only when a printed
// node carries that mark, and never with --pruned (which shows them).
func TestGraphPrunedFootnote(t *testing.T) {
	w := baseWorld(t)
	dir := mainProject(w, nil)
	// A project whose only dependency has no requirements: nothing is
	// pruned out, so no footnote at all.
	w.AddModule("example.com/leaf", "v1.0.0", map[string]string{"leaf.go": pkgFile("leaf")})
	leaf := w.Project(map[string]string{
		"go.mod":  testenv.GoModFile("example.com/main", "1.22", "example.com/leaf@v1.0.0"),
		"main.go": "package main\n\nimport _ \"example.com/leaf\"\n\nfunc main() {}\n",
	})
	const note = "--pruned shows them"
	for _, args := range [][]string{{"graph"}, {"graph", "--pruned"}, {"graph", "--focus", "example.com/b"}, {"leaf", "graph"}, {"leaf", "graph", "--pruned"}} {
		d := dir
		if args[0] == "leaf" {
			d, args = leaf, args[1:]
		}
		r := w.RunEnv(d, nil, args...)
		expectCode(t, r, 0)
		hasNote := strings.Contains(r.Stdout, note)
		marked := false
		for _, l := range lines(r.Stdout) {
			if !strings.Contains(l, note) && strings.Contains(l, "requirements pruned") {
				marked = true
			}
		}
		want := marked && args[len(args)-1] != "--pruned"
		if hasNote != want {
			t.Errorf("%v: footnote shown=%v, want %v\n%s", args, hasNote, want, r.Stdout)
		}
	}
}
