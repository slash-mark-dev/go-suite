package callgraph_test

import (
	"context"
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/callgraph"
	"github.com/slash-mark-dev/go-suite/internal/goenv"
	"github.com/slash-mark-dev/go-suite/internal/loader"
	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

func TestReachability(t *testing.T) {
	w := testenv.New(t)
	w.AddModule("example.com/lib", "v1.0.0", map[string]string{
		"lib.go": `package lib

import "os/exec"

type Runner interface{ Run(string) error }

type Shell struct{}

func (Shell) Run(cmd string) error { return exec.Command("sh", "-c", cmd).Run() }

type Noop struct{}

func (Noop) Run(string) error { return nil }

func Unused() { _ = exec.Command("x").Run() }

func Apply(r Runner, s string) error { return r.Run(s) }

var registry = map[string]func(){"x": helper}

func helper() {}

func Generic[T Runner](r T) error { return r.Run("g") }
`,
	})
	dir := w.Project(map[string]string{
		"go.mod": testenv.GoModFile("example.com/app", "1.22", "example.com/lib@v1.0.0"),
		"main.go": `package main

import "example.com/lib"

func main() {
	_ = lib.Apply(lib.Noop{}, "ls")
	_ = lib.Generic(lib.Shell{})
}
`,
	})
	if out, err := w.Go(dir, "mod", "download"); err != nil {
		t.Fatal(out)
	}
	env := goenv.Load(context.Background(), w.Env())
	prog, err := loader.Load(context.Background(), loader.Config{Env: env, Dir: dir, TypeCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range prog.Errors {
		t.Logf("load error: %s", e)
	}
	g := callgraph.Build(prog)
	reach := g.Reachable(g.Entrypoints(prog.Roots))
	must := func(pkg, sym string, want bool) {
		t.Helper()
		f := g.Lookup(pkg, sym)
		if got := reach.Has(f); got != want {
			t.Errorf("%s.%s reachable = %v, want %v", pkg, sym, got, want)
		}
	}
	must("example.com/lib", "Shell.Run", true) // via interface dispatch (CHA) and generic constraint
	must("example.com/lib", "Noop.Run", true)
	must("example.com/lib", "Unused", false)
	must("example.com/lib", "helper", true) // referenced from package-level var initializer
	must("os/exec", "Command", true)
	must("os/exec", "Cmd.Run", true)
	path := reach.Path(g.Lookup("os/exec", "Command"))
	var names []string
	for _, e := range path {
		names = append(names, e.Callee.ID)
	}
	if len(path) == 0 || !strings.Contains(strings.Join(names, " "), "example.com/lib.Shell.Run") {
		t.Errorf("unexpected path to exec.Command: %v", names)
	}
}
