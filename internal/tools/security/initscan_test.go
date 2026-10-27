package security_test

import (
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

type initJSON struct {
	Packages int `json:"packages"`
	Effects  []struct {
		Package  string   `json:"package"`
		Module   string   `json:"module"`
		Version  string   `json:"version"`
		Kind     string   `json:"kind"`
		Severity string   `json:"severity"`
		APIs     []string `json:"apis"`
		Args     []string `json:"args"`
		Path     []struct {
			Func string `json:"func"`
			Pos  string `json:"pos"`
		} `json:"path"`
	} `json:"effects"`
	Counts   map[string]int `json:"counts"`
	Findings []struct {
		Severity string `json:"severity"`
		Rule     string `json:"rule"`
	} `json:"findings"`
	Failing int `json:"failing"`
}

func (r *initJSON) effect(pkg, kind string) int {
	for i, e := range r.Effects {
		if e.Package == pkg && e.Kind == kind {
			return i
		}
	}
	return -1
}

func initWorld(t *testing.T) (*testenv.World, string) {
	w := testenv.New(t)
	mods := map[string]string{
		"example.com/beacon": `package beacon

import "net/http"

func init() { report() }

func report() {
	resp, err := http.Get("https://beacon.invalid/ping")
	if err == nil {
		resp.Body.Close()
	}
}

func Hello() string { return "hi" }
`,
		"example.com/dropper": `package dropper

import (
	"os"
	"os/exec"
)

var written = drop()

func drop() bool { return os.WriteFile("/tmp/.dropper", []byte("x"), 0o600) == nil }

func init() {
	_ = exec.Command("sh", "-c", "id").Run()
}

func OK() bool { return written }
`,
		"example.com/envy": `package envy

import "os"

var debug = os.Getenv("ENVY_DEBUG") != ""

func Debug() bool { return debug }
`,
		"example.com/reg": `package reg

import (
	"flag"
	"net/http"
)

var verbose = flag.Bool("reg-verbose", false, "")

func init() {
	http.HandleFunc("/debug/reg", func(w http.ResponseWriter, r *http.Request) {})
}

func V() bool { return *verbose }
`,
		"example.com/mut": `package mut

import (
	"net/http"
	"time"
)

func init() {
	http.DefaultClient.Timeout = time.Second
}

func M() {}
`,
		"example.com/lazy": `package lazy

import "net/http"

func Fetch() { http.Get("https://lazy.invalid") }
`,
	}
	var reqs []string
	for path, src := range mods {
		w.AddModule(path, "v1.0.0", map[string]string{"x.go": src})
		reqs = append(reqs, path+"@v1.0.0")
	}
	w.AddModule("example.com/chain", "v1.0.0", map[string]string{
		"go.mod": testenv.GoModFile("example.com/chain", "1.21", "example.com/lazy@v1.0.0"),
		"chain.go": `package chain

import "example.com/lazy"

var fetched = start()

func start() bool { lazy.Fetch(); return true }

func C() bool { return fetched }
`,
	})
	reqs = append(reqs, "example.com/chain@v1.0.0")
	dir := w.Project(map[string]string{
		"go.mod": testenv.GoModFile("example.com/app", "1.22", reqs...),
		"main.go": `package main

import (
	"os"

	"example.com/beacon"
	"example.com/chain"
	"example.com/dropper"
	"example.com/envy"
	"example.com/mut"
	"example.com/reg"
)

func init() { os.Remove("/tmp/app.lock") }

func main() {
	_ = beacon.Hello()
	_ = chain.C()
	_ = dropper.OK()
	_ = envy.Debug()
	_ = reg.V()
	mut.M()
}
`,
	})
	mustDownload(t, w, dir)
	return w, dir
}

func TestInitscan(t *testing.T) {
	w, dir := initWorld(t)
	r := w.Run(dir, "initscan", "--json")
	expectCode(t, r, 1)
	var res initJSON
	r.Decode(t, &res)
	if res.Packages != 7 {
		t.Errorf("packages = %d, want 7", res.Packages)
	}
	want := map[string]string{
		"example.com/beacon network":      "high",
		"example.com/dropper file-write":  "high",
		"example.com/dropper exec":        "high",
		"example.com/chain network":       "high",
		"example.com/mut global-mutation": "medium",
		"example.com/reg registration":    "medium",
		"example.com/envy env":            "low",
	}
	if len(res.Effects) != len(want) {
		for _, e := range res.Effects {
			t.Logf("effect %s %s %s %v", e.Package, e.Kind, e.Severity, e.APIs)
		}
		t.Fatalf("%d effects, want %d", len(res.Effects), len(want))
	}
	for k, sev := range want {
		pkg, kind, _ := strings.Cut(k, " ")
		i := res.effect(pkg, kind)
		if i < 0 {
			t.Errorf("missing effect %s", k)
			continue
		}
		if res.Effects[i].Severity != sev {
			t.Errorf("%s severity = %s, want %s", k, res.Effects[i].Severity, sev)
		}
	}
	b := res.Effects[res.effect("example.com/beacon", "network")]
	var path []string
	for _, f := range b.Path {
		path = append(path, f.Func)
	}
	if strings.Join(path, " ") != "example.com/beacon (package initialization) example.com/beacon.report net/http.Get" {
		t.Errorf("beacon path = %v", path)
	}
	if strings.Join(b.Args, ",") != "https://beacon.invalid/ping" || b.Path[2].Pos != "example.com/beacon@v1.0.0/x.go:8" {
		t.Errorf("beacon args/pos = %v %+v", b.Args, b.Path)
	}
	ch := res.Effects[res.effect("example.com/chain", "network")]
	if len(ch.Path) != 4 || ch.Path[2].Func != "example.com/lazy.Fetch" || ch.Args[0] != "https://lazy.invalid" {
		t.Errorf("chain path = %+v args %v", ch.Path, ch.Args)
	}
	if res.effect("example.com/lazy", "network") >= 0 {
		t.Errorf("lazy has no init-time effect but was reported")
	}
	m := res.Effects[res.effect("example.com/mut", "global-mutation")]
	if m.APIs[0] != "net/http.DefaultClient" {
		t.Errorf("mutation apis = %v", m.APIs)
	}
	e := res.Effects[res.effect("example.com/envy", "env")]
	if e.Args[0] != "ENVY_DEBUG" {
		t.Errorf("env args = %v", e.Args)
	}
	rg := res.Effects[res.effect("example.com/reg", "registration")]
	if strings.Join(rg.APIs, ",") != "flag.Bool,net/http.HandleFunc" {
		t.Errorf("registration apis = %v", rg.APIs)
	}
	if res.effect("example.com/app", "file-write") >= 0 {
		t.Errorf("main module reported without --include-main")
	}
	if res.Failing != 4 {
		t.Errorf("failing = %d, want 4", res.Failing)
	}

	r = w.Run(dir, "initscan", "--json", "--include-main", "--fail-on", "critical")
	expectCode(t, r, 0)
	res = initJSON{}
	r.Decode(t, &res)
	if res.effect("example.com/app", "file-write") < 0 {
		t.Errorf("--include-main: main module effect missing")
	}

	r = w.Run(dir, "initscan")
	expectCode(t, r, 1)
	contains(t, r.Stdout, "example.com/beacon.report")
	contains(t, r.Stdout, `"https://beacon.invalid/ping"`)
	contains(t, r.Stdout, "1 effect (low severity")
	r = w.Run(dir, "initscan", "--all")
	contains(t, r.Stdout, "ENVY_DEBUG")
	r = w.Run(dir, "initscan", "--fail-on", "urgent")
	expectCode(t, r, 2)
}

func TestInitscanClean(t *testing.T) {
	w := testenv.New(t)
	w.AddModule("example.com/lazy", "v1.0.0", map[string]string{
		"x.go": "package lazy\n\nimport \"net/http\"\n\nfunc Fetch() { http.Get(\"https://lazy.invalid\") }\n",
	})
	dir := w.Project(map[string]string{
		"go.mod":  testenv.GoModFile("example.com/app", "1.22", "example.com/lazy@v1.0.0"),
		"main.go": "package main\n\nimport \"example.com/lazy\"\n\nfunc main() { lazy.Fetch() }\n",
	})
	mustDownload(t, w, dir)
	r := w.Run(dir, "initscan", "--json")
	expectCode(t, r, 0)
	var res initJSON
	r.Decode(t, &res)
	if len(res.Effects) != 0 || res.Packages != 1 {
		t.Fatalf("clean: %+v", res)
	}
	r = w.Run(dir, "initscan")
	contains(t, r.Stdout, "no import-time side effects")
}
