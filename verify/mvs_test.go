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
)

// TestMVSAgainstGoCommand builds random module universes (mixing pruned
// go >= 1.17 and unpruned go.mod files, excludes, version and directory
// replacements) and checks that modgraph's build list equals the real
// `go list -m all`.
func TestMVSAgainstGoCommand(t *testing.T) {
	scenarios := 400
	if testing.Short() {
		scenarios = 20
	}
	total := 0
	for s := 0; s < scenarios; s++ {
		total += runScenario(t, int64(s))
	}
	count("MVS modules vs go list -m all", total)
}

func runScenario(t *testing.T, seed int64) int {
	r := mrand.New(mrand.NewSource(seed))
	w := testenv.New(t)
	nmods := 3 + r.Intn(7)
	type ver struct {
		path, v string
	}
	var all []ver
	versions := map[string][]string{}
	for i := 0; i < nmods; i++ {
		p := fmt.Sprintf("example.com/m%d", i)
		nv := 1 + r.Intn(4)
		for j := 0; j < nv; j++ {
			v := fmt.Sprintf("v1.%d.0", j)
			versions[p] = append(versions[p], v)
			all = append(all, ver{p, v})
		}
	}
	// Since Go 1.21 the main module's go line must be at least that of every
	// dependency, so an unpruned (go < 1.17) main module only makes sense
	// with unpruned dependencies.
	mainGo := []string{"1.16", "1.21"}[r.Intn(2)]
	goVers := []string{"1.16", "1.17", "1.21"}
	if mainGo == "1.16" {
		goVers = []string{"1.16"}
	}
	for _, mv := range all {
		var reqs []string
		for k := 0; k < r.Intn(4); k++ {
			q := fmt.Sprintf("example.com/m%d", r.Intn(nmods))
			if q == mv.path {
				continue
			}
			qv := versions[q][r.Intn(len(versions[q]))]
			reqs = append(reqs, q+"@"+qv)
		}
		reqs = dedupReqs(reqs)
		gv := goVers[r.Intn(len(goVers))]
		w.AddModule(mv.path, mv.v, map[string]string{
			"go.mod": testenv.GoModFile(mv.path, gv, reqs...),
			"x.go":   "package " + strings.ReplaceAll(filepath.Base(mv.path), ".", "") + "\n",
		})
	}
	var mainReqs []string
	direct := map[string]bool{}
	for k := 0; k < 1+r.Intn(4); k++ {
		q := fmt.Sprintf("example.com/m%d", r.Intn(nmods))
		if direct[q] {
			continue
		}
		direct[q] = true
		mainReqs = append(mainReqs, q+"@"+versions[q][r.Intn(len(versions[q]))])
	}
	gomod := testenv.GoModFile("example.com/main", mainGo, mainReqs...)
	files := map[string]string{"main.go": "package main\n\nfunc main() {}\n"}
	// excludes of non-direct versions
	if r.Intn(3) == 0 {
		mv := all[r.Intn(len(all))]
		if !direct[mv.path] && mv.v != versions[mv.path][len(versions[mv.path])-1] {
			gomod += fmt.Sprintf("\nexclude %s %s\n", mv.path, mv.v)
		}
	}
	// version replacement
	if r.Intn(3) == 0 {
		mv := all[r.Intn(len(all))]
		to := all[r.Intn(len(all))]
		gomod += fmt.Sprintf("\nreplace %s %s => %s %s\n", mv.path, mv.v, to.path, to.v)
	}
	// directory replacement of a whole module
	if r.Intn(4) == 0 {
		q := fmt.Sprintf("example.com/m%d", r.Intn(nmods))
		other := fmt.Sprintf("example.com/m%d", r.Intn(nmods))
		var reqs []string
		if other != q {
			reqs = append(reqs, other+"@"+versions[other][0])
		}
		files["local/go.mod"] = testenv.GoModFile(q, mainGo, reqs...)
		files["local/x.go"] = "package x\n"
		gomod += fmt.Sprintf("\nreplace %s => ./local\n", q)
	}
	files["go.mod"] = gomod
	dir := w.Project(files)
	out, err := w.Go(dir, "list", "-m", "all")
	if err != nil {
		// Some random graphs are legitimately rejected by go (e.g. a
		// replacement whose go.mod declares another path); skip those.
		return 0
	}
	// go may have rewritten go.mod (roots made consistent); compare
	// against the file as it is now.
	data, _ := os.ReadFile(filepath.Join(dir, "go.mod"))
	f := modfile.Parse(filepath.Join(dir, "go.mod"), data)
	env := goenv.New(map[string]string{"GOPROXY": w.URL + "/proxy", "GOMODCACHE": w.ModCache, "HOME": w.Home})
	hc := httpx.New(httpx.Options{Env: env})
	g, err := modgraph.Load(context.Background(), modgraph.Config{Mains: []modgraph.Main{{Dir: dir, File: f}}, Fetch: modproxy.New(env, hc)})
	if err != nil {
		t.Fatalf("seed %d: %v", seed, err)
	}
	var ours []string
	for _, m := range g.BuildList() {
		ours = append(ours, m.Path+" "+m.Version)
	}
	var theirs []string
	for i, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if i == 0 || strings.HasPrefix(line, "go: ") {
			continue // main module
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			theirs = append(theirs, fields[0]+" "+fields[1])
		}
	}
	sort.Strings(ours)
	sort.Strings(theirs)
	if strings.Join(ours, "\n") != strings.Join(theirs, "\n") {
		var uni strings.Builder
		for _, mv := range all {
			if m := w.Module(mv.path, mv.v); m != nil {
				fmt.Fprintf(&uni, "== %s@%s\n%s", mv.path, mv.v, m.GoMod())
			}
		}
		t.Errorf("seed %d: build list differs\ngo.mod:\n%s\nours:\n%s\ngo list -m all:\n%s\nuniverse:\n%s", seed, data, strings.Join(ours, "\n"), strings.Join(theirs, "\n"), uni.String())
	}
	return len(theirs)
}

func dedupReqs(reqs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range reqs {
		p := strings.Split(r, "@")[0]
		if !seen[p] {
			seen[p] = true
			out = append(out, r)
		}
	}
	return out
}
