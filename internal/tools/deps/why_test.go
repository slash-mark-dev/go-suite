package deps

import (
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

func whyOf(t *testing.T, r testenv.Result) whyResult {
	t.Helper()
	var res whyResult
	r.Decode(t, &res)
	return res
}

func TestWhySelectedVersionAndPruning(t *testing.T) {
	w := baseWorld(t)
	dir := mainProject(w, nil)
	r := w.Run(dir, "why", "example.com/b", "--json")
	expectCode(t, r, 0)
	res := whyOf(t, r)
	if !res.Pruned || len(res.Modules) != 1 {
		t.Fatalf("result %+v", res)
	}
	m := res.Modules[0]
	if !m.InGraph || m.Selected != "v1.2.0" || m.Direct {
		t.Fatalf("module %+v", m)
	}
	// Agrees with the go command.
	if out := goOut(t, w, dir, nil, "list", "-m", "example.com/b"); strings.TrimSpace(lines(out)[0]) != "example.com/b v1.2.0" {
		t.Fatalf("go list -m: %s", out)
	}
	if len(m.Requirements) != 2 || m.Requirements[0].From != "example.com/c@v1.0.0" || !m.Requirements[0].Max ||
		m.Requirements[1].From != "example.com/a@v1.0.0" || m.Requirements[1].Max || m.Requirements[1].Version != "v1.1.0" {
		t.Fatalf("requirements %+v", m.Requirements)
	}
	// e's requirement on b v1.3.0 is pruned out.
	if len(m.Ignored) != 1 || !m.Ignored[0].Pruned || m.Ignored[0].From != "example.com/e@v1.0.0" || m.Ignored[0].Version != "v1.3.0" {
		t.Fatalf("ignored %+v", m.Ignored)
	}
	joined := strings.Join(m.Explanation, "\n")
	if !strings.Contains(joined, "Graph pruning matters here") || !strings.Contains(joined, "at least v1.3.0") {
		t.Fatalf("explanation:\n%s", joined)
	}
	if len(m.Paths) != 1 || strings.Join(m.Paths[0], " ") != "example.com/main example.com/c@v1.0.0 example.com/b@v1.2.0" {
		t.Fatalf("paths %v", m.Paths)
	}
	// Package chain identical to `go mod why -m`.
	out := goOut(t, w, dir, nil, "mod", "why", "-m", "example.com/b")
	var want []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l != "" && !strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "go: ") {
			want = append(want, l)
		}
	}
	if m.Packages == nil || !m.Packages.Needed || strings.Join(m.Packages.Chain, " ") != strings.Join(want, " ") {
		t.Fatalf("package chain %+v, go mod why: %v", m.Packages, want)
	}
}

func TestWhyText(t *testing.T) {
	w := baseWorld(t)
	dir := mainProject(w, nil)
	r := w.Run(dir, "why", "example.com/b")
	expectCode(t, r, 0)
	for _, s := range []string{"example.com/b  selected v1.2.0", "max → selected", "Ignored requirements", "pruned (go.mod not loaded)",
		"example.com/main → example.com/c@v1.0.0 → example.com/b@v1.2.0", "go mod why -m"} {
		if !strings.Contains(r.Stdout, s) {
			t.Errorf("text output lacks %q:\n%s", s, r.Stdout)
		}
	}
}

func TestWhyQueryVersion(t *testing.T) {
	w := baseWorld(t)
	dir := mainProject(w, nil)
	res := whyOf(t, w.Run(dir, "why", "example.com/b@v1.1.0", "example.com/b@v1.2.0", "example.com/b@v1.0.0", "--json", "--no-packages"))
	q0, q1, q2 := res.Modules[0].Query, res.Modules[1].Query, res.Modules[2].Query
	if q0 == nil || !q0.InGraph || q0.Selected || len(q0.RequiredBy) != 1 || q0.RequiredBy[0] != "example.com/a@v1.0.0" {
		t.Fatalf("query v1.1.0: %+v", q0)
	}
	if !q1.Selected || !q1.InGraph {
		t.Fatalf("query v1.2.0: %+v", q1)
	}
	if q2.InGraph || q2.Selected || len(q2.RequiredBy) != 0 {
		t.Fatalf("query v1.0.0: %+v", q2)
	}
	if res.Modules[0].Packages != nil {
		t.Fatalf("--no-packages still listed packages")
	}
}

func TestWhyNotInGraphAndMain(t *testing.T) {
	w := baseWorld(t)
	dir := mainProject(w, nil)
	r := w.Run(dir, "why", "example.com/u", "example.com/main", "--json")
	expectCode(t, r, 0)
	res := whyOf(t, r)
	u, m := res.Modules[0], res.Modules[1]
	if u.InGraph || !strings.Contains(strings.Join(u.Explanation, " "), "(main module does not need module example.com/u)") {
		t.Fatalf("u: %+v", u)
	}
	if u.Packages == nil || u.Packages.Needed {
		t.Fatalf("u packages: %+v", u.Packages)
	}
	out := goOut(t, w, dir, nil, "mod", "why", "-m", "example.com/u")
	if !strings.Contains(out, "(main module does not need module example.com/u)") {
		t.Fatalf("go mod why: %s", out)
	}
	if !m.Main || !m.InGraph {
		t.Fatalf("main: %+v", m)
	}
}

func TestWhyExcludeAndReplace(t *testing.T) {
	w := baseWorld(t)
	dir := w.Project(map[string]string{
		"go.mod": testenv.GoModFile("example.com/main", "1.22", "example.com/a@v1.0.0", "example.com/c@v1.0.0") +
			"\nexclude example.com/b v1.2.0\n\nreplace example.com/b v1.3.0 => example.com/b v1.3.0\n",
		"main.go": "package main\n\nimport (\n\t_ \"example.com/a\"\n\t_ \"example.com/c\"\n)\n\nfunc main() {}\n",
	})
	res := whyOf(t, w.Run(dir, "why", "example.com/b", "--json"))
	m := res.Modules[0]
	// c's requirement on the excluded v1.2.0 is dropped: a's v1.1.0 wins.
	if m.Selected != "v1.1.0" {
		t.Fatalf("selected %s: %+v", m.Selected, m)
	}
	if len(m.Excludes) != 1 || m.Excludes[0] != "v1.2.0" {
		t.Fatalf("excludes %v", m.Excludes)
	}
	found := false
	for _, e := range m.Ignored {
		if e.Excluded && e.From == "example.com/c@v1.0.0" && e.Version == "v1.2.0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ignored %+v", m.Ignored)
	}
	if m.Replacement != nil {
		t.Fatalf("replacement of v1.3.0 should not apply to selected v1.1.0: %+v", m.Replacement)
	}
	out := goOut(t, w, dir, nil, "list", "-m", "example.com/b")
	if !strings.Contains(out, "example.com/b v1.1.0") {
		t.Fatalf("go list -m: %s", out)
	}

	// A wildcard replacement applies to the selected version.
	dir2 := w.Project(map[string]string{
		"go.mod":  testenv.GoModFile("example.com/main", "1.22", "example.com/a@v1.0.0") + "\nreplace example.com/b => example.com/b v1.3.0\n",
		"main.go": "package main\n\nimport _ \"example.com/a\"\n\nfunc main() {}\n",
	})
	m2 := whyOf(t, w.Run(dir2, "why", "example.com/b", "--json", "--no-packages")).Modules[0]
	if m2.Selected != "v1.1.0" || m2.Replacement == nil || m2.Replacement.New != "example.com/b v1.3.0" || m2.Replacement.Line == 0 {
		t.Fatalf("replacement: %+v", m2)
	}
}

func TestWhyUsageErrors(t *testing.T) {
	w := baseWorld(t)
	dir := mainProject(w, nil)
	expectCode(t, w.Run(dir, "why"), 2)
	expectCode(t, w.Run(dir, "why", "example.com/b@latest"), 2)
	expectCode(t, w.Run(dir, "why", "Not A Path"), 2)
	expectCode(t, w.Run(dir, "why", "example.com/b", "--paths", "-1"), 2)
	// Outside a module: runtime error.
	expectCode(t, w.Run(t.TempDir(), "why", "example.com/b"), 3)
}

func TestWhyNetworkError(t *testing.T) {
	w := baseWorld(t)
	dir := mainProject(w, nil)
	r := w.RunEnv(dir, []string{"GOPROXY=http://127.0.0.1:1/proxy", "SMGO_CACHE_DIR=" + t.TempDir(), "GOMODCACHE=" + t.TempDir()}, "why", "example.com/b", "--json")
	expectCode(t, r, 3)
	if env := r.JSON(t); env["error"] == nil || env["ok"] != false {
		t.Fatalf("envelope %v", env)
	}
}
