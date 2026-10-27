// Package project discovers the main module (or workspace) the user is
// working in and loads go.mod, go.sum, go.work and vendor/modules.txt.
package project

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/slash-mark-dev/go-suite/internal/modfile"
	"github.com/slash-mark-dev/go-suite/internal/modgraph"
)

// Env is the subset of goenv.Env used here.
type Env interface {
	Getenv(string) string
	Lookup(string) (string, bool)
}

// Project is a main module or workspace.
type Project struct {
	// Dir is the main module directory (or the go.work directory).
	Dir string
	// ModDir is the directory of the go.mod nearest to the start dir.
	ModDir    string
	GoModPath string
	GoMod     *modfile.File
	GoSumPath string
	GoSum     *modfile.GoSum
	WorkPath  string
	Work      *modfile.File
	Mains     []modgraph.Main
	// Vendor is the parsed vendor/modules.txt of the main module, if any.
	Vendor     []*modfile.VendorModule
	VendorPath string
}

// ErrNoModule means no go.mod was found.
var ErrNoModule = errors.New("no go.mod found (run inside a Go module or pass -C <dir>)")

// Find locates the project starting at dir, searching upward like the go
// command. GOWORK=off disables workspace mode; GOWORK=<path> selects a
// workspace file explicitly.
func Find(dir string, env Env) (*Project, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	p := &Project{}
	modDir := findUp(abs, "go.mod")
	gowork, set := env.Lookup("GOWORK")
	workPath := ""
	switch {
	case set && gowork == "off":
	case set && gowork != "":
		workPath = gowork
	default:
		if wd := findUp(abs, "go.work"); wd != "" {
			workPath = filepath.Join(wd, "go.work")
		}
	}
	if workPath != "" {
		data, err := os.ReadFile(workPath)
		if err != nil {
			return nil, err
		}
		p.WorkPath = workPath
		p.Work = modfile.ParseWork(workPath, data)
		p.Dir = filepath.Dir(workPath)
		for _, u := range p.Work.Use {
			d := u.Path
			if !filepath.IsAbs(d) {
				d = filepath.Join(p.Dir, d)
			}
			gm := filepath.Join(d, "go.mod")
			data, err := os.ReadFile(gm)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: use %s: %v", workPath, u.Line, u.Path, err)
			}
			f := modfile.Parse(gm, data)
			if f.Module != nil {
				u.ModulePath = f.Module.Path
			}
			p.Mains = append(p.Mains, modgraph.Main{Dir: d, File: f})
		}
		if modDir != "" {
			p.ModDir = modDir
			p.GoModPath = filepath.Join(modDir, "go.mod")
			for _, m := range p.Mains {
				if m.Dir == modDir {
					p.GoMod = m.File
				}
			}
		}
		if p.GoMod == nil && len(p.Mains) > 0 {
			p.GoMod = p.Mains[0].File
			p.ModDir = p.Mains[0].Dir
			p.GoModPath = filepath.Join(p.ModDir, "go.mod")
		}
		p.loadSums()
		return p, nil
	}
	if modDir == "" {
		return nil, ErrNoModule
	}
	p.Dir, p.ModDir = modDir, modDir
	p.GoModPath = filepath.Join(modDir, "go.mod")
	data, err := os.ReadFile(p.GoModPath)
	if err != nil {
		return nil, err
	}
	p.GoMod = modfile.Parse(p.GoModPath, data)
	p.Mains = []modgraph.Main{{Dir: modDir, File: p.GoMod}}
	p.loadSums()
	vp := filepath.Join(modDir, "vendor", "modules.txt")
	if data, err := os.ReadFile(vp); err == nil {
		p.VendorPath = vp
		p.Vendor, _ = modfile.ParseVendorModules(data)
	}
	return p, nil
}

func (p *Project) loadSums() {
	// go.work.sum supplements go.sum in workspace mode.
	var all modfile.GoSum
	paths := []string{}
	if p.ModDir != "" {
		paths = append(paths, filepath.Join(p.ModDir, "go.sum"))
	}
	if p.WorkPath != "" {
		seen := map[string]bool{}
		for _, x := range paths {
			seen[x] = true
		}
		for _, m := range p.Mains {
			gs := filepath.Join(m.Dir, "go.sum")
			if !seen[gs] {
				seen[gs] = true
				paths = append(paths, gs)
			}
		}
		paths = append(paths, p.WorkPath+".sum")
	}
	for i, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if i == 0 {
			p.GoSumPath = path
		}
		gs := modfile.ParseGoSum(data)
		all.Lines = append(all.Lines, gs.Lines...)
		all.Errors = append(all.Errors, gs.Errors...)
	}
	p.GoSum = &all
}

func findUp(dir, name string) string {
	for {
		if fi, err := os.Stat(filepath.Join(dir, name)); err == nil && !fi.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// IsWorkspace reports whether the project is a go.work workspace.
func (p *Project) IsWorkspace() bool { return p.Work != nil }

// ModulePath returns the module path of the (primary) main module.
func (p *Project) ModulePath() string {
	if p.GoMod != nil && p.GoMod.Module != nil {
		return p.GoMod.Module.Path
	}
	return ""
}

// Graph loads the module graph with MVS.
func (p *Project) Graph(ctx context.Context, fetch modgraph.Fetcher) (*modgraph.Graph, error) {
	cfg := modgraph.Config{Mains: p.Mains, Fetch: fetch}
	if p.Work != nil {
		cfg.Work = p.Work
		cfg.WorkDir = p.Dir
	}
	return modgraph.Load(ctx, cfg)
}

// Rel returns path relative to the project dir, for display.
func (p *Project) Rel(path string) string {
	if rel, err := filepath.Rel(p.Dir, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return path
}
