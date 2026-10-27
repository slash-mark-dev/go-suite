package compliance

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/loader"
	"github.com/slash-mark-dev/go-suite/internal/modgraph"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/modzip"
	"github.com/slash-mark-dev/go-suite/internal/report"
)

const group = "Compliance & operations"

// modRef is one module of the build list together with the replacement in
// effect for it.
type modRef struct {
	Path    string
	Version string
	// Replace is the module the code actually comes from (zero if not
	// replaced). Replace.Version == "" means a local directory (Dir).
	Replace module.Version
	Dir     string
	Direct  bool
}

func (m modRef) mod() module.Version { return module.Version{Path: m.Path, Version: m.Version} }

func (m modRef) String() string {
	s := m.Path + "@" + m.Version
	if m.Replace.Path != "" {
		s += " => " + m.Replace.Path
		if m.Replace.Version != "" {
			s += "@" + m.Replace.Version
		}
	}
	return s
}

// isLocal reports whether the module comes from a local directory.
func (m modRef) isLocal() bool { return m.Replace.Path != "" && m.Replace.Version == "" }

// buildRefs returns the build list (main modules excluded) with
// replacements resolved.
func buildRefs(c *cli.Context) ([]modRef, *modgraph.Graph, error) {
	g, err := c.Graph()
	if err != nil {
		return nil, nil, err
	}
	var out []modRef
	for _, m := range g.BuildList() {
		r := modRef{Path: m.Path, Version: m.Version, Direct: g.IsDirect(m.Path)}
		if rep, base := g.FindReplace(m); rep != nil {
			r.Replace = rep.New
			if rep.IsLocal() {
				dir := rep.New.Path
				if !filepath.IsAbs(dir) {
					dir = filepath.Join(base, dir)
				}
				r.Dir = dir
			}
		}
		out = append(out, r)
	}
	return out, g, nil
}

// modSource gives access to the files of a module version.
type modSource interface {
	Files() []string
	ReadFile(name string) ([]byte, error)
}

type dirSource struct {
	dir   string
	files []string
}

func (d *dirSource) Files() []string { return d.files }
func (d *dirSource) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(d.dir, filepath.FromSlash(name)))
}

// openDir lists a local module directory the way a module zip would
// contain it: nested modules, vendor directories and VCS metadata are
// skipped.
func openDir(dir string) (*dirSource, error) {
	d := &dirSource{dir: dir}
	err := filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if e.IsDir() {
			if rel == "." {
				return nil
			}
			name := e.Name()
			if name == ".git" || name == ".hg" || name == ".svn" || name == ".bzr" || rel == "vendor" {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(p, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if e.Type().IsRegular() {
			d.files = append(d.files, rel)
		}
		return nil
	})
	sort.Strings(d.files)
	return d, err
}

// openModule returns the files of m: its zip from the proxy (or module
// cache), or its local replacement directory. zipData is nil for local
// directories.
func openModule(ctx context.Context, c *cli.Context, m modRef) (modSource, []byte, error) {
	if m.isLocal() {
		d, err := openDir(m.Dir)
		return d, nil, err
	}
	path, version := m.Path, m.Version
	if m.Replace.Path != "" {
		path, version = m.Replace.Path, m.Replace.Version
	}
	data, err := c.Proxy().Zip(ctx, path, version)
	if err != nil {
		return nil, nil, err
	}
	z, err := modzip.Open(data, path, version)
	if err != nil {
		return nil, nil, fmt.Errorf("%s@%s: %v", path, version, err)
	}
	return z, data, nil
}

// linkedModules runs `go list -deps` on the patterns and returns the
// module paths (excluding main modules and the standard library) that
// provide at least one package.
func linkedModules(c *cli.Context, patterns []string, tests bool) (map[string]bool, error) {
	if !c.Env.HaveGo() {
		return nil, errors.New("--linked needs the go command (install Go from https://go.dev/dl)")
	}
	p, err := c.Project()
	if err != nil {
		return nil, err
	}
	dir := p.ModDir
	if dir == "" {
		dir = p.Dir
	}
	extra := []string{"-deps"}
	if tests {
		extra = append(extra, "-test")
	}
	pkgs, err := loader.GoList(c.Ctx, loader.Config{Env: c.Env, Dir: dir, Patterns: patterns}, extra...)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, pk := range pkgs {
		if pk.Standard || pk.Module == nil || pk.Module.Main {
			continue
		}
		out[pk.Module.Path] = true
	}
	return out, nil
}

// goModLine returns the line of the require (or replace) directive for
// path in the main go.mod, or 0.
func goModLine(c *cli.Context, path string) int {
	p, err := c.Project()
	if err != nil || p.GoMod == nil {
		return 0
	}
	for _, r := range p.GoMod.Require {
		if r.Mod.Path == path {
			return r.Line
		}
	}
	for _, r := range p.GoMod.Replace {
		if r.Old.Path == path {
			return r.Line
		}
	}
	return 0
}

// goModRel returns the go.mod path relative to the project directory.
func goModRel(c *cli.Context) string {
	p, err := c.Project()
	if err != nil || p.GoModPath == "" {
		return "go.mod"
	}
	return p.Rel(p.GoModPath)
}

// sevCounts counts findings by severity name.
func sevCounts(fs []report.Finding) map[string]int {
	m := report.Counts(fs)
	if m == nil {
		m = map[string]int{}
	}
	return m
}

// countLine renders "2 high, 1 medium" for the non-zero severities.
func countLine(m map[string]int) string {
	var parts []string
	for s := report.Critical; s >= report.Info; s-- {
		if n := m[s.String()]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// printFindings renders findings as a severity table.
func printFindings(c *cli.Context, fs []report.Finding) {
	o := c.Out
	for _, f := range fs {
		where := f.Where()
		if f.Module != "" && f.File != "" {
			where = f.Module
			if f.Version != "" {
				where += "@" + f.Version
			}
			where += " · " + report.Finding{File: f.File, Line: f.Line}.Where()
		}
		line := fmt.Sprintf("  %s %s", o.Sev(f.Severity), f.Title)
		if where != "" {
			line += o.Dim("  " + where)
		}
		o.Println(line)
		if f.Detail != "" {
			o.Println("           " + o.Dim(f.Detail))
		}
		if f.Fix != "" {
			o.Println("           " + o.Green("fix: ") + f.Fix)
		}
	}
}

// writeFile writes data to path creating parent directories.
func writeFile(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0o644)
}
