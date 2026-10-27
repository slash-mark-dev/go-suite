package verify

import (
	"context"
	"fmt"
	mrand "math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/goenv"
	"github.com/slash-mark-dev/go-suite/internal/httpx"
	"github.com/slash-mark-dev/go-suite/internal/modfile"
	"github.com/slash-mark-dev/go-suite/internal/modgraph"
	"github.com/slash-mark-dev/go-suite/internal/modproxy"
	"github.com/slash-mark-dev/go-suite/internal/testenv"

	_ "github.com/slash-mark-dev/go-suite/internal/tools/deps" // registers sm-go graph
)

// universe is a random set of published modules m0..mN, each with one to
// four versions whose go.mod files require random versions of the others.
type universe struct {
	nmods    int
	versions map[string][]string
	all      [][2]string
}

func newUniverse(r *mrand.Rand, w *testenv.World, goVers []string) *universe {
	u := &universe{nmods: 3 + r.Intn(7), versions: map[string][]string{}}
	for i := 0; i < u.nmods; i++ {
		p := fmt.Sprintf("example.com/m%d", i)
		for j := 0; j < 1+r.Intn(4); j++ {
			v := fmt.Sprintf("v1.%d.0", j)
			u.versions[p] = append(u.versions[p], v)
			u.all = append(u.all, [2]string{p, v})
		}
	}
	for _, mv := range u.all {
		var reqs []string
		for k := 0; k < r.Intn(4); k++ {
			q := u.pick(r)
			if q == mv[0] {
				continue
			}
			reqs = append(reqs, q+"@"+u.anyVersion(r, q))
		}
		w.AddModule(mv[0], mv[1], map[string]string{
			"go.mod": testenv.GoModFile(mv[0], goVers[r.Intn(len(goVers))], dedupReqs(reqs)...),
			"x.go":   "package " + strings.ReplaceAll(filepath.Base(mv[0]), ".", "") + "\n",
		})
	}
	return u
}

func (u *universe) pick(r *mrand.Rand) string {
	return fmt.Sprintf("example.com/m%d", r.Intn(u.nmods))
}

func (u *universe) anyVersion(r *mrand.Rand, p string) string {
	return u.versions[p][r.Intn(len(u.versions[p]))]
}

func (u *universe) reqs(r *mrand.Rand) []string {
	var out []string
	seen := map[string]bool{}
	for k := 0; k < 1+r.Intn(4); k++ {
		q := u.pick(r)
		if !seen[q] {
			seen[q] = true
			out = append(out, q+"@"+u.anyVersion(r, q))
		}
	}
	return out
}

func (u *universe) dump(w *testenv.World) string {
	var b strings.Builder
	for _, mv := range u.all {
		if m := w.Module(mv[0], mv[1]); m != nil {
			fmt.Fprintf(&b, "== %s@%s\n%s", mv[0], mv[1], m.GoMod())
		}
	}
	return b.String()
}

// goLines returns the non-diagnostic lines of go command output, sorted.
func goLines(out string) []string {
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l == "" || strings.HasPrefix(l, "go: ") {
			continue
		}
		lines = append(lines, l)
	}
	sort.Strings(lines)
	return lines
}

// workspaceScenario writes a go.work with two or three main modules
// w0..w2 requiring random versions from a random universe.
func workspaceScenario(t *testing.T, seed int64) (*testenv.World, *universe, string) {
	r := mrand.New(mrand.NewSource(seed))
	w := testenv.New(t)
	u := newUniverse(r, w, []string{"1.16", "1.17", "1.21"})
	files := map[string]string{}
	work := "go 1.23\n\nuse (\n"
	for i := 0; i < 2+r.Intn(2); i++ {
		p := fmt.Sprintf("example.com/w%d", i)
		gv := []string{"1.16", "1.21", "1.22"}[r.Intn(3)]
		files[fmt.Sprintf("w%d/go.mod", i)] = testenv.GoModFile(p, gv, u.reqs(r)...)
		files[fmt.Sprintf("w%d/x.go", i)] = fmt.Sprintf("package w%d\n", i)
		work += fmt.Sprintf("\t./w%d\n", i)
	}
	files["go.work"] = work + ")\n"
	return w, u, w.Project(files)
}

// TestMVSWorkspaceAgainstGoCommand checks modgraph's build list in
// workspace mode (go.work with several main modules) against
// `go list -m all`.
func TestMVSWorkspaceAgainstGoCommand(t *testing.T) {
	scenarios := 300
	if testing.Short() {
		scenarios = 20
	}
	total := 0
	for s := int64(0); s < int64(scenarios); s++ {
		w, u, dir := workspaceScenario(t, s)
		out, err := w.GoEnv(dir, []string{"GOWORK=", "GOFLAGS=-mod=readonly"}, "list", "-m", "all")
		if err != nil {
			continue
		}
		var theirs []string
		for _, l := range goLines(out) {
			if f := strings.Fields(l); len(f) >= 2 {
				theirs = append(theirs, f[0]+" "+f[1])
			}
		}
		workData, _ := os.ReadFile(filepath.Join(dir, "go.work"))
		work := modfile.ParseWork(filepath.Join(dir, "go.work"), workData)
		var mains []modgraph.Main
		for _, use := range work.Use {
			d := filepath.Join(dir, use.Path)
			data, _ := os.ReadFile(filepath.Join(d, "go.mod"))
			mains = append(mains, modgraph.Main{Dir: d, File: modfile.Parse(filepath.Join(d, "go.mod"), data)})
		}
		env := goenv.New(map[string]string{"GOPROXY": w.URL + "/proxy", "GOMODCACHE": w.ModCache, "HOME": w.Home})
		g, err := modgraph.Load(context.Background(), modgraph.Config{Mains: mains, Work: work, WorkDir: dir, Fetch: modproxy.New(env, httpx.New(httpx.Options{Env: env}))})
		if err != nil {
			t.Fatalf("seed %d: %v", s, err)
		}
		var ours []string
		for _, m := range g.BuildList() {
			ours = append(ours, m.Path+" "+m.Version)
		}
		sort.Strings(ours)
		if strings.Join(ours, "\n") != strings.Join(theirs, "\n") {
			t.Errorf("seed %d: workspace build list differs\ngo.work:\n%s\nours:\n%s\ngo list -m all:\n%s\nuniverse:\n%s", s, workData, strings.Join(ours, "\n"), strings.Join(theirs, "\n"), u.dump(w))
		}
		total += len(theirs)
	}
	count("workspace MVS modules vs go list -m all", total)
}

// TestGraphAgainstGoModGraph compares `sm-go graph --format text` with
// `go mod graph`, edge for edge, on random single-module projects (pruned
// and unpruned) and random workspaces.
func TestGraphAgainstGoModGraph(t *testing.T) {
	scenarios := 300
	if testing.Short() {
		scenarios = 20
	}
	total := 0
	compare := func(kind string, seed int64, w *testenv.World, u *universe, dir string, env []string) {
		out, err := w.GoEnv(dir, env, "mod", "graph")
		if err != nil {
			return
		}
		want := goLines(out)
		res := w.RunEnv(dir, env, "graph", "--format", "text")
		if res.Code != 0 {
			t.Errorf("%s seed %d: sm-go graph exit %d: %s", kind, seed, res.Code, res.Stderr)
			return
		}
		got := goLines(res.Stdout)
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			gomod, _ := os.ReadFile(filepath.Join(dir, "go.mod"))
			gowork, _ := os.ReadFile(filepath.Join(dir, "go.work"))
			t.Errorf("%s seed %d: graph differs\ngo.mod:\n%s\ngo.work:\n%s\nsm-go:\n%s\ngo mod graph:\n%s\nuniverse:\n%s",
				kind, seed, gomod, gowork, strings.Join(got, "\n"), strings.Join(want, "\n"), u.dump(w))
		}
		total += len(want)
	}
	for s := int64(0); s < int64(scenarios); s++ {
		// Single main module, pruned or unpruned.
		r := mrand.New(mrand.NewSource(1000 + s))
		w := testenv.New(t)
		mainGo := []string{"1.16", "1.21", "1.22"}[r.Intn(3)]
		goVers := []string{"1.16", "1.17", "1.21"}
		if mainGo == "1.16" {
			goVers = []string{"1.16"}
		}
		u := newUniverse(r, w, goVers)
		gomod := testenv.GoModFile("example.com/main", mainGo, u.reqs(r)...)
		if r.Intn(3) == 0 {
			gomod += "\ntoolchain go1.23.1\n"
		}
		dir := w.Project(map[string]string{"go.mod": gomod, "main.go": "package main\n\nfunc main() {}\n"})
		// Let go make go.mod consistent first; both tools then read the
		// same file.
		if _, err := w.Go(dir, "list", "-m", "all"); err == nil {
			compare("module", 1000+s, w, u, dir, nil)
		}

		w2, u2, wdir := workspaceScenario(t, 2000+s)
		compare("workspace", 2000+s, w2, u2, wdir, []string{"GOWORK="})
	}
	count("go mod graph edges", total)
}
