package upgrade_test

import (
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
	"github.com/slash-mark-dev/go-suite/internal/tools/upgrade"
)

// libWorld publishes example.com/lib v1.0.0 .. v1.2.0 and v2.0.0:
//
//	v1.1.0 adds API (compatible minor release)
//	v1.2.0 breaks API in a minor release (removes Old, changes Parse)
//	v2.0.0 lives at example.com/lib/v2
func libWorld(t *testing.T) *testenv.World {
	w := testenv.New(t)
	v100 := `package lib

// Old is removed in v1.2.0.
func Old() int { return 1 }

// Parse changes signature in v1.2.0.
func Parse(s string) int { return len(s) }

type Config struct {
	Name string
	Size int
}

type Doer interface{ Do() }

const Mode = 1
`
	w.AddModule("example.com/lib", "v1.0.0", map[string]string{
		"lib.go":           v100,
		"sub/sub.go":       "package sub\n\nfunc Sub() {}\n",
		"internal/x/x.go":  "package x\n\nfunc X() {}\n",
		"cmd/tool/main.go": "package main\n\nfunc main() {}\n",
	})
	v110 := v100 + "\n// New is added in v1.1.0.\nfunc New() *Config { return &Config{} }\n"
	w.AddModule("example.com/lib", "v1.1.0", map[string]string{
		"lib.go":          v110,
		"sub/sub.go":      "package sub\n\nfunc Sub() {}\n",
		"internal/x/x.go": "package x\n\nfunc X(int) {}\n", // internal: ignored
	})
	v120 := strings.Replace(v110, "func Old() int { return 1 }", "", 1)
	v120 = strings.Replace(v120, "func Parse(s string) int", "func Parse(s string) (int, error)", 1)
	v120 = strings.Replace(v120, "return len(s) }", "return len(s), nil }", 1)
	w.AddModule("example.com/lib", "v1.2.0", map[string]string{
		"lib.go":     v120,
		"sub/sub.go": "package sub\n\nfunc Sub() {}\n",
	})
	v2 := strings.Replace(v120, "type Doer interface{ Do() }", "type Doer interface {\n\tDo()\n\tUndo()\n}", 1)
	w.AddModule("example.com/lib/v2", "v2.0.0", map[string]string{
		"lib.go":     v2,
		"sub/sub.go": "package sub\n\nfunc Sub() {}\n",
	})
	return w
}

func TestAPIDiffCompatibleMinor(t *testing.T) {
	w := libWorld(t)
	r := w.Run("", "apidiff", "example.com/lib@v1.0.0", "example.com/lib@v1.1.0", "--json")
	if r.Code != 0 {
		t.Fatalf("exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	var res upgrade.APIDiffResult
	r.Decode(t, &res)
	if res.Incompatible != 0 || res.Compatible != 1 || res.SemverBump != "minor" || res.RequiredBump != "minor" || res.Violation {
		t.Fatalf("unexpected result %+v", res)
	}
	if len(res.Packages) != 1 || res.Packages[0].Package != "example.com/lib" || res.Packages[0].Compatible[0].Object != "New" {
		t.Fatalf("packages = %+v", res.Packages)
	}
	env := r.JSON(t)
	if env["tool"] != "apidiff" || env["ok"] != true {
		t.Fatalf("envelope %v", env)
	}
}

func TestAPIDiffBreakingMinor(t *testing.T) {
	w := libWorld(t)
	r := w.Run("", "apidiff", "example.com/lib", "v1.1.0..v1.2.0", "--json")
	if r.Code != 1 {
		t.Fatalf("exit %d, want 1\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	var res upgrade.APIDiffResult
	r.Decode(t, &res)
	if !res.Violation || res.Incompatible != 2 || res.RequiredBump != "major" || res.SemverBump != "minor" {
		t.Fatalf("unexpected result %+v", res)
	}
	var objs []string
	for _, c := range res.Packages[0].Incompatible {
		objs = append(objs, c.Object)
	}
	if strings.Join(objs, ",") != "Old,Parse" {
		t.Fatalf("incompatible objects %v", objs)
	}
	// Text output.
	r = w.Run("", "apidiff", "example.com/lib@v1.1.0", "example.com/lib@v1.2.0", "--all")
	if r.Code != 1 || !strings.Contains(r.Stdout, "func Old removed") || !strings.Contains(r.Stdout, "violates semantic versioning") {
		t.Fatalf("text output (exit %d):\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
}

func TestAPIDiffAcrossMajors(t *testing.T) {
	w := libWorld(t)
	r := w.Run("", "apidiff", "example.com/lib@v1.2.0", "example.com/lib/v2@v2.0.0", "--json")
	if r.Code != 0 {
		t.Fatalf("exit %d (major upgrades may break)\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	var res upgrade.APIDiffResult
	r.Decode(t, &res)
	if res.SemverBump != "major" || res.Incompatible != 1 || res.Packages[0].Incompatible[0].Object != "Doer.Undo" || res.Violation {
		t.Fatalf("unexpected result %+v", res)
	}
	// The sub package exists in both majors with the same API.
	for _, p := range res.Packages {
		if strings.HasSuffix(p.Package, "/sub") {
			t.Fatalf("sub should be unchanged: %+v", p)
		}
	}
}

func TestAPIDiffAgainstWorkingTree(t *testing.T) {
	w := libWorld(t)
	dir := w.Project(map[string]string{
		"go.mod":     "module example.com/lib\n\ngo 1.21\n",
		"lib.go":     "package lib\n\nfunc Parse(s string) int { return 0 }\n\ntype Config struct{ Name string }\n\ntype Doer interface{ Do() }\n\nconst Mode = 2\n",
		"sub/sub.go": "package sub\n\nfunc Sub() {}\n\nfunc More() {}\n",
	})
	r := w.Run(dir, "apidiff", "--against", "v1.0.0", "--json")
	if r.Code != 0 {
		t.Fatalf("exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	var res upgrade.APIDiffResult
	r.Decode(t, &res)
	got := map[string]bool{}
	for _, p := range res.Packages {
		for _, c := range p.Incompatible {
			got[c.Object] = true
		}
	}
	for _, want := range []string{"Old", "Config.Size", "Mode"} {
		if !got[want] {
			t.Errorf("missing incompatible change %s: %+v", want, res.Packages)
		}
	}
	if res.SemverBump != "unreleased" || res.Compatible != 1 || res.Violation {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestAPIDiffUsageErrors(t *testing.T) {
	w := libWorld(t)
	for _, args := range [][]string{
		{"apidiff"},
		{"apidiff", "example.com/lib@v1.0.0"},
		{"apidiff", "example.com/lib", "v1.0.0"},
		{"apidiff", "example.com/lib@v1.0.0", "example.com/lib@v9.9.9"},
		{"apidiff", "example.com/lib@v1.0.0", "example.com/lib@banana"},
		{"apidiff", "example.com/lib@v1.0.0", "example.com/lib"},
		{"apidiff", "--against", "v1.0.0", "example.com/lib@v1.0.0"},
		{"apidiff", "Bad Path@v1.0.0", "example.com/lib@v1.1.0"},
	} {
		r := w.Run("", append(args, "--json")...)
		if r.Code != 2 {
			t.Errorf("%v: exit %d, want 2\n%s", args, r.Code, r.Stdout)
		}
	}
}

func TestAPIDiffNetworkError(t *testing.T) {
	w := libWorld(t)
	r := w.RunEnv("", []string{"GOPROXY=http://127.0.0.1:1/proxy"}, "apidiff", "example.com/lib@v1.0.0", "example.com/lib@v1.1.0", "--json")
	if r.Code != 3 {
		t.Fatalf("exit %d, want 3\n%s", r.Code, r.Stdout)
	}
}
