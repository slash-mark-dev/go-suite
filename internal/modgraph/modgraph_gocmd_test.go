package modgraph

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/modfile"
	"github.com/slash-mark-dev/go-suite/internal/module"
)

type memFetch map[string]string

func (m memFetch) GoMod(_ context.Context, path, version string) ([]byte, error) {
	if s, ok := m[path+"@"+version]; ok {
		return []byte(s), nil
	}
	return nil, fmt.Errorf("%s@%s: not found", path, version)
}

func mainOf(dir, gomod string) Main {
	return Main{Dir: dir, File: modfile.Parse(dir+"/go.mod", []byte(gomod))}
}

// A dependency requiring an older version of the main module's path pulls
// in that version's requirements: `go list -m all` selects b v1.2.0 here
// (checked against the go command in the deps tool tests).
func TestMainModuleCycleLoadsOldVersion(t *testing.T) {
	fetch := memFetch{
		"example.com/d@v1.0.0": "module example.com/d\n\ngo 1.16\n\nrequire example.com/m v1.0.0\n",
		"example.com/m@v1.0.0": "module example.com/m\n\ngo 1.21\n\nrequire example.com/b v1.2.0\n",
		"example.com/b@v1.0.0": "module example.com/b\n\ngo 1.21\n",
		"example.com/b@v1.2.0": "module example.com/b\n\ngo 1.21\n",
	}
	g, err := Load(context.Background(), Config{Fetch: fetch, Mains: []Main{mainOf("/m",
		"module example.com/m\n\ngo 1.22\n\nrequire (\n\texample.com/d v1.0.0\n\texample.com/b v1.0.0\n)\n")}})
	if err != nil {
		t.Fatal(err)
	}
	if v := g.Selected["example.com/b"]; v != "v1.2.0" {
		t.Fatalf("selected b %s, want v1.2.0", v)
	}
	if v, ok := g.Selected["example.com/m"]; !ok || v != "" {
		t.Fatalf("main module selected as %q", v)
	}
	if len(g.BuildList()) != 2 {
		t.Fatalf("build list %v", g.BuildList())
	}
}

// In a workspace, a module requiring another workspace module at a
// version loads that version's go.mod like the go command does.
func TestWorkspaceModuleRequiresOtherWorkspaceModule(t *testing.T) {
	fetch := memFetch{
		"example.com/x@v1.0.0": "module example.com/x\n\ngo 1.21\n\nrequire example.com/b v1.2.0\n",
		"example.com/b@v1.0.0": "module example.com/b\n\ngo 1.21\n",
		"example.com/b@v1.2.0": "module example.com/b\n\ngo 1.21\n",
	}
	work := modfile.ParseWork("/w/go.work", []byte("go 1.23\n\nuse (\n\t./x\n\t./y\n)\n"))
	g, err := Load(context.Background(), Config{Fetch: fetch, Work: work, WorkDir: "/w", Mains: []Main{
		mainOf("/w/x", "module example.com/x\n\ngo 1.23\n\nrequire example.com/b v1.0.0\n"),
		mainOf("/w/y", "module example.com/y\n\ngo 1.22\n\nrequire example.com/x v1.0.0\n"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if v := g.Selected["example.com/b"]; v != "v1.2.0" {
		t.Fatalf("selected b %s, want v1.2.0", v)
	}
	if v := g.Selected["example.com/x"]; v != "" {
		t.Fatalf("workspace module x selected as %q", v)
	}
	if goV, _ := g.MaxGo(); goV != "1.23" {
		t.Fatalf("MaxGo %s", goV)
	}
}

// A local replacement directory without go.mod is an error, as in the go
// command ("reading <dir>/go.mod: no such file or directory").
func TestLocalReplacementWithoutGoMod(t *testing.T) {
	dir := t.TempDir()
	g, err := Load(context.Background(), Config{Fetch: memFetch{}, Mains: []Main{mainOf(dir,
		"module example.com/m\n\ngo 1.22\n\nrequire example.com/b v1.0.0\n\nreplace example.com/b => ./nob\n")}})
	if err != nil {
		t.Fatal(err)
	}
	e := g.Errors[module.Version{Path: "example.com/b", Version: "v1.0.0"}]
	if e == nil || !strings.Contains(e.Error(), "go.mod") {
		t.Fatalf("want go.mod error, got %v", e)
	}
	if r := g.Replacement[module.Version{Path: "example.com/b", Version: "v1.0.0"}]; r.Path != filepath.Join(dir, "nob") {
		t.Fatalf("replacement %v", r)
	}
}
