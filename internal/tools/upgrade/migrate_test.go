package upgrade_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
	"github.com/slash-mark-dev/go-suite/internal/tools/upgrade"
)

const fooV1 = `package foo

func Hello() string { return "hello" }

type Client struct{ Addr string }

func (c *Client) Get() string { return c.Addr }

type Handler interface{ Serve() }
`

// fooWorld publishes example.com/foo v1.5.0, example.com/foo/v2 v2.0.0
// (breaking: Hello removed, Client.Get changed, Handler.Close added, util
// renamed to package utils, legacy removed) and example.com/foo/v3 v3.0.0
// (v1 API plus additions).
func fooWorld(t *testing.T) *testenv.World {
	w := testenv.New(t)
	w.AddModule("example.com/foo", "v1.5.0", map[string]string{
		"foo.go":           fooV1,
		"util/util.go":     "package util\n\nfunc U() int { return 1 }\n",
		"legacy/legacy.go": "package legacy\n\nfunc L() {}\n",
	})
	v2 := strings.Replace(fooV1, `func Hello() string { return "hello" }`, `func Hi() string { return "hi" }`, 1)
	v2 = strings.Replace(v2, "func (c *Client) Get() string", "func (c *Client) Get(path string) string", 1)
	v2 = strings.Replace(v2, "type Handler interface{ Serve() }", "type Handler interface {\n\tServe()\n\tClose()\n}", 1)
	w.AddModule("example.com/foo/v2", "v2.0.0", map[string]string{
		"foo.go":       v2,
		"util/util.go": "package utils\n\nfunc U() int { return 2 }\n",
	})
	w.AddModule("example.com/foo/v3", "v3.0.0", map[string]string{
		"foo.go":           fooV1 + "\nfunc New() *Client { return &Client{} }\n",
		"util/util.go":     "package util\n\nfunc U() int { return 3 }\n",
		"legacy/legacy.go": "package legacy\n\nfunc L() {}\n",
	})
	return w
}

const fooMain = `package main

// The foo client.
import (
	"fmt"

	"example.com/foo" // keep this comment
	"example.com/foo/util"
)

type h struct{}

func (h) Serve() {}

var _ foo.Handler = h{}

func main() {
	c := &foo.Client{Addr: "x"}
	fmt.Println(foo.Hello(), c.Get(), util.U())
}
`

func fooProject(w *testenv.World, extra map[string]string) string {
	files := map[string]string{
		"go.mod":  testenv.GoModFile("example.com/app", "1.21", "example.com/foo@v1.5.0"),
		"main.go": fooMain,
	}
	for k, v := range extra {
		files[k] = v
	}
	return w.Project(files)
}

func TestMigratePlanBreaking(t *testing.T) {
	w := fooWorld(t)
	dir := fooProject(w, map[string]string{
		"tools.go":             "//go:build tools\n\npackage main\n\nimport _ \"example.com/foo/legacy\"\n",
		"vendor/x/x.go":        "package x\n\nimport _ \"example.com/foo\"\n",
		"testdata/t/t.go":      "package t\n\nimport _ \"example.com/foo\"\n",
		"nested/go.mod":        "module example.com/nested\n",
		"nested/n.go":          "package n\n\nimport _ \"example.com/foo\"\n",
		"internal/i/i_test.go": "package i\n\nimport (\n\t\"testing\"\n\n\tfoo \"example.com/foo\"\n)\n\nfunc TestI(t *testing.T) { _ = foo.Hello }\n",
	})
	r := w.Run(dir, "migrate", "example.com/foo", "v2", "--json")
	if r.Code != 1 {
		t.Fatalf("exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	var res upgrade.MigrateResult
	r.Decode(t, &res)
	if res.FromVersion != "v1.5.0" || res.ToPath != "example.com/foo/v2" || res.ToVersion != "v2.0.0" || res.Applied {
		t.Fatalf("result %+v", res)
	}
	var imps []string
	for _, im := range res.Imports {
		s := im.File + ":" + itoa(im.Line) + " " + im.New
		if im.Missing {
			s += " missing"
		}
		if im.AddName != "" {
			s += " name=" + im.AddName
		}
		imps = append(imps, s)
	}
	want := []string{
		"internal/i/i_test.go:6 example.com/foo/v2",
		"main.go:7 example.com/foo/v2",
		"main.go:8 example.com/foo/v2/util name=util",
		"tools.go:5 example.com/foo/v2/legacy missing",
	}
	if strings.Join(imps, "|") != strings.Join(want, "|") {
		t.Fatalf("imports\n got %q\nwant %q", imps, want)
	}
	if strings.Join(res.Missing, ",") != "example.com/foo/legacy" {
		t.Fatalf("missing %v", res.Missing)
	}
	if res.GoMod.Line != 6 || res.GoMod.Remove != "require example.com/foo v1.5.0" || res.GoMod.Add != "require example.com/foo/v2 v2.0.0" {
		t.Fatalf("gomod %+v", res.GoMod)
	}
	got := map[string][]string{}
	for _, b := range res.Breaks {
		got[b.Object] = b.UsedAt
	}
	if len(got["Hello"]) != 2 || !strings.HasPrefix(got["Hello"][1], "main.go:19:") || !strings.HasPrefix(got["Hello"][0], "internal/i/i_test.go:") {
		t.Fatalf("Hello breaks %v (all %+v)", got["Hello"], res.Breaks)
	}
	if len(got["Client.Get"]) != 1 || len(got["Handler.Close"]) != 1 || !strings.HasPrefix(got["Handler.Close"][0], "main.go:15:") {
		t.Fatalf("breaks %+v", res.Breaks)
	}
	if res.Affected != 4 {
		t.Fatalf("affected %d", res.Affected)
	}
	// Nothing changed.
	if b, _ := os.ReadFile(filepath.Join(dir, "main.go")); string(b) != fooMain {
		t.Fatal("dry run modified main.go")
	}
	// --apply refuses while packages are missing.
	if r := w.Run(dir, "migrate", "example.com/foo", "v2", "--apply"); r.Code != 2 || !strings.Contains(r.Stderr, "example.com/foo/legacy") {
		t.Fatalf("apply with missing packages: exit %d\n%s", r.Code, r.Stderr)
	}
	// Text output.
	r = w.Run(dir, "migrate", "example.com/foo", "example.com/foo/v2@v2.0.0")
	for _, s := range []string{"main.go:7", "→ example.com/foo/v2/util", "package renamed", "- require example.com/foo v1.5.0", "func Hello removed", "used at main.go:19", "dry run"} {
		if !strings.Contains(r.Stdout, s) {
			t.Errorf("text output lacks %q:\n%s", s, r.Stdout)
		}
	}
}

func TestMigrateApplyCompatible(t *testing.T) {
	w := fooWorld(t)
	dir := fooProject(w, nil)
	// Default target: the newest major version on the proxy (v3).
	r := w.Run(dir, "migrate", "example.com/foo", "--json")
	if r.Code != 0 {
		t.Fatalf("exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	var res upgrade.MigrateResult
	r.Decode(t, &res)
	if res.ToPath != "example.com/foo/v3" || res.ToVersion != "v3.0.0" || len(res.Breaks) != 0 || !res.APIChecked || res.Additions != 1 {
		t.Fatalf("plan %+v", res)
	}
	r = w.Run(dir, "migrate", "example.com/foo", "--apply", "--json")
	if r.Code != 0 {
		t.Fatalf("apply: exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	r.Decode(t, &res)
	if !res.Applied || strings.Join(res.Changed, ",") != "main.go,go.mod" {
		t.Fatalf("applied %+v", res)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "main.go"))
	want := strings.NewReplacer(`"example.com/foo" // keep`, `"example.com/foo/v3" // keep`, `"example.com/foo/util"`, `"example.com/foo/v3/util"`).Replace(fooMain)
	if string(b) != want {
		t.Fatalf("main.go after apply:\n%s", b)
	}
	gm, _ := os.ReadFile(filepath.Join(dir, "go.mod"))
	if !strings.Contains(string(gm), "\texample.com/foo/v3 v3.0.0\n") || strings.Contains(string(gm), "example.com/foo v1.5.0") {
		t.Fatalf("go.mod after apply:\n%s", gm)
	}
	if out, err := w.Go(dir, "mod", "tidy"); err != nil {
		t.Fatalf("go mod tidy: %v\n%s", err, out)
	}
	if out, err := w.Go(dir, "build", "./..."); err != nil {
		t.Fatalf("go build after migration: %v\n%s", err, out)
	}
}

func TestMigrateApplyRenamedPackage(t *testing.T) {
	w := fooWorld(t)
	dir := w.Project(map[string]string{
		"go.mod":  "module example.com/app\n\ngo 1.21\n\nrequire example.com/foo v1.5.0\n",
		"main.go": "package main\n\nimport \"example.com/foo/util\"\n\nfunc main() { println(util.U()) }\n",
	})
	r := w.Run(dir, "migrate", "example.com/foo", "v2", "--apply", "--json")
	if r.Code != 0 {
		t.Fatalf("exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "main.go"))
	if !strings.Contains(string(b), `import util "example.com/foo/v2/util"`) {
		t.Fatalf("main.go:\n%s", b)
	}
	gm, _ := os.ReadFile(filepath.Join(dir, "go.mod"))
	if !strings.Contains(string(gm), "\nrequire example.com/foo/v2 v2.0.0\n") {
		t.Fatalf("go.mod:\n%s", gm)
	}
	if out, err := w.Go(dir, "mod", "tidy"); err != nil {
		t.Fatalf("go mod tidy: %v\n%s", err, out)
	}
	if out, err := w.Go(dir, "run", "."); err != nil || strings.TrimSpace(out) != "2" {
		t.Fatalf("go run: %v\n%s", err, out)
	}
}

func TestMigrateUsageErrors(t *testing.T) {
	w := fooWorld(t)
	w.AddModule("example.com/other/v2", "v2.0.0", nil)
	dir := fooProject(w, nil)
	for _, args := range [][]string{
		{},
		{"example.com/nope"},
		{"example.com/foo@v1.5.0"},
		{"example.com/foo", "example.com/other/v2"},
		{"example.com/foo", "v9"},
		{"example.com/foo", "example.com/foo/v2@v2.9.9"},
		{"example.com/foo", "example.com/foo"},
		{"example.com/foo", "a", "b"},
		{"example.com/app"},
	} {
		r := w.Run(dir, append([]string{"migrate", "--json"}, args...)...)
		if r.Code != 2 {
			t.Errorf("%v: exit %d, want 2\n%s", args, r.Code, r.Stdout)
		}
	}
	// No newer major version.
	w2 := testenv.New(t)
	w2.AddModule("example.com/solo", "v1.0.0", map[string]string{"s.go": "package solo\n"})
	d2 := w2.Project(map[string]string{"go.mod": testenv.GoModFile("example.com/app", "1.21", "example.com/solo@v1.0.0"), "m.go": "package m\n\nimport _ \"example.com/solo\"\n"})
	if r := w2.Run(d2, "migrate", "example.com/solo"); r.Code != 2 || !strings.Contains(r.Stderr, "no newer major version") {
		t.Fatalf("exit %d\n%s", r.Code, r.Stderr)
	}
}

// A +incompatible dependency (v6.15.9+incompatible of a path without a
// major suffix) migrates to the newest /vN on the proxy: the search starts
// after v6, not after v1, and skips a missing major.
func TestMigrateIncompatibleFindsNewestMajor(t *testing.T) {
	w := testenv.New(t)
	src := "package redis\n\nfunc Get(k string) string { return k }\n"
	w.AddModule("example.com/redis", "v6.15.9+incompatible", map[string]string{"go.mod": "", "redis.go": src})
	w.AddModule("example.com/redis/v7", "v7.4.1", map[string]string{"redis.go": src})
	w.AddModule("example.com/redis/v9", "v9.0.0", map[string]string{"redis.go": src})
	dir := w.Project(map[string]string{
		"go.mod":  testenv.GoModFile("example.com/app", "1.21", "example.com/redis@v6.15.9+incompatible"),
		"main.go": "package main\n\nimport \"example.com/redis\"\n\nfunc main() { _ = redis.Get(\"k\") }\n",
	})
	r := w.Run(dir, "migrate", "example.com/redis", "--json")
	if r.Code != 0 {
		t.Fatalf("exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
	}
	var res upgrade.MigrateResult
	r.Decode(t, &res)
	if res.ToPath != "example.com/redis/v9" || res.ToVersion != "v9.0.0" {
		t.Fatalf("target %s@%s, want example.com/redis/v9@v9.0.0", res.ToPath, res.ToVersion)
	}
}
