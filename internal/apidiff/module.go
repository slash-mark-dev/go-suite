package apidiff

import (
	"context"
	"errors"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/goenv"
	"github.com/slash-mark-dev/go-suite/internal/loader"
)

// Module is the importable API of one module version (or of a module
// directory on disk): its type-checked non-internal, non-main packages.
type Module struct {
	Path    string `json:"path"`
	Version string `json:"version,omitempty"` // "" for a local directory
	Dir     string `json:"-"`
	// Packages maps import path to type-checked package.
	Packages map[string]*types.Package `json:"-"`
	// Names maps import path to the declared package name.
	Names map[string]string `json:"-"`
	// Errors lists packages that could not be listed or type-checked
	// completely; their API may be partial.
	Errors []string `json:"errors,omitempty"`
}

// String returns path@version, or path for a directory.
func (m *Module) String() string {
	if m.Version == "" {
		return m.Path
	}
	return m.Path + "@" + m.Version
}

// Rel returns the path of a package relative to the module path ("" for
// the root package), or ok=false if pkg is not in the module.
func (m *Module) Rel(pkg string) (string, bool) {
	r := rel(pkg, m.Path)
	return r, r != "\x00"
}

// PackagePath returns the import path of the package at rel in m.
func (m *Module) PackagePath(rel string) string {
	if rel == "" {
		return m.Path
	}
	return m.Path + "/" + rel
}

// CompareModules compares the APIs of two versions of a module. Packages
// are matched by their path relative to the module path, so the two
// modules may have different paths (example.com/m and example.com/m/v2).
// If only is non-nil, just the packages whose relative path is in only
// are compared.
func CompareModules(old, new *Module, only map[string]bool) Report {
	var rep Report
	oldRel := map[string]string{}
	for p := range old.Packages {
		if r, ok := old.Rel(p); ok {
			oldRel[r] = p
		}
	}
	newRel := map[string]string{}
	for p := range new.Packages {
		if r, ok := new.Rel(p); ok {
			newRel[r] = p
		}
	}
	for _, r := range sortedKeys(oldRel) {
		if only != nil && !only[r] {
			continue
		}
		np, ok := newRel[r]
		if !ok {
			rep.Incompatible = append(rep.Incompatible, Change{Package: new.PackagePath(r), Kind: Removed,
				Message: fmt.Sprintf("package %s removed", new.PackagePath(r))})
			continue
		}
		var pr Report
		if old.Path == new.Path {
			pr = Compare(old.Packages[oldRel[r]], new.Packages[np])
		} else {
			pr = comparePaths(old.Packages[oldRel[r]], new.Packages[np], old.Path, new.Path)
		}
		rep.Merge(pr)
	}
	for _, r := range sortedKeys(newRel) {
		if only != nil && !only[r] {
			continue
		}
		if _, ok := oldRel[r]; !ok {
			rep.Compatible = append(rep.Compatible, Change{Package: newRel[r], Kind: Added,
				Message: fmt.Sprintf("package %s added", newRel[r])})
		}
	}
	return rep
}

// PackageReport is the part of a report about one package.
type PackageReport struct {
	Package      string   `json:"package"`
	Incompatible []Change `json:"incompatible"`
	Compatible   []Change `json:"compatible"`
}

// ByPackage splits a report per package, sorted by package path.
func (r Report) ByPackage() []PackageReport {
	m := map[string]*PackageReport{}
	get := func(p string) *PackageReport {
		if m[p] == nil {
			m[p] = &PackageReport{Package: p, Incompatible: []Change{}, Compatible: []Change{}}
		}
		return m[p]
	}
	for _, c := range r.Incompatible {
		pr := get(c.Package)
		pr.Incompatible = append(pr.Incompatible, c)
	}
	for _, c := range r.Compatible {
		pr := get(c.Package)
		pr.Compatible = append(pr.Compatible, c)
	}
	var out []PackageReport
	for _, p := range sortedKeys(m) {
		out = append(out, *m[p])
	}
	return out
}

// Normalize replaces nil slices by empty ones (for stable JSON).
func (r Report) Normalize() Report {
	if r.Incompatible == nil {
		r.Incompatible = []Change{}
	}
	if r.Compatible == nil {
		r.Compatible = []Change{}
	}
	return r
}

// ---------- loading ----------

// LoadDir type-checks the packages of the module rooted at dir (which
// must contain go.mod) with the go command.
func LoadDir(ctx context.Context, env *goenv.Env, dir string) (*Module, error) {
	data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return nil, fmt.Errorf("%s: no go.mod: %w", dir, err)
	}
	path := modulePath(data)
	if path == "" {
		return nil, fmt.Errorf("%s/go.mod: no module directive", dir)
	}
	m := &Module{Path: path, Dir: dir}
	err = m.load(ctx, env, dir, []string{"./..."}, nil)
	return m, err
}

// ErrNoGo is returned when the go command is not installed.
var ErrNoGo = errors.New("type-checking modules needs the go command; install Go from https://go.dev/dl")

// LoadVersion downloads path@version through GOPROXY (with the go command,
// so checksums are verified against go.sum / GOSUMDB) and type-checks its
// packages as a consumer of the module sees them.
func LoadVersion(ctx context.Context, env *goenv.Env, path, version string) (*Module, error) {
	if env == nil || !env.HaveGo() {
		return nil, ErrNoGo
	}
	tmp, err := os.MkdirTemp("", "smgo-apidiff-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	gomod := fmt.Sprintf("module smgo.invalid/apidiff\n\ngo %s\n\nrequire %s %s\n", goLine(env), path, version)
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte(gomod), 0o644); err != nil {
		return nil, err
	}
	m := &Module{Path: path, Version: version}
	err = m.load(ctx, env, tmp, []string{path + "/..."}, []string{"GOFLAGS=-mod=mod"})
	return m, err
}

var goVersionRE = regexp.MustCompile(`^go(1\.\d+(\.\d+)?)`)

// goLine returns a go directive value for a temporary main module: the
// version of the installed go command, so any dependency it can build is
// accepted.
func goLine(env *goenv.Env) string {
	if m := goVersionRE.FindStringSubmatch(env.GoVersion()); m != nil {
		return m[1]
	}
	return "1.21"
}

func modulePath(gomod []byte) string {
	for _, line := range strings.Split(string(gomod), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "module" {
			return strings.Trim(f[1], "\"`")
		}
	}
	return ""
}

func (m *Module) load(ctx context.Context, env *goenv.Env, dir string, patterns, extraEnv []string) error {
	if env == nil || !env.HaveGo() {
		return ErrNoGo
	}
	prog, err := loader.Load(ctx, loader.Config{
		Env: env, Dir: dir, Patterns: patterns, TypeCheck: true,
		SkipBodies: func(*loader.Package) bool { return true },
		ExtraEnv:   append([]string{"GOWORK=off"}, extraEnv...),
	})
	if err != nil {
		return err
	}
	m.Packages = map[string]*types.Package{}
	m.Names = map[string]string{}
	for _, p := range prog.Roots {
		if p.Module == nil || p.Module.Path != m.Path {
			if p.Error != nil && m.Version != "" && len(prog.Roots) == 1 {
				return fmt.Errorf("%s@%s: %s", m.Path, m.Version, p.Error.Err)
			}
			continue
		}
		if m.Version != "" && p.Module.Version != m.Version {
			return fmt.Errorf("%s@%s: the go command selected %s instead (a dependency requires a newer version)", m.Path, m.Version, p.Module.Version)
		}
		if m.Dir == "" {
			m.Dir = p.Module.Dir
		}
		if p.Name == "main" || IsInternal(p.ImportPath) || p.Types == nil {
			continue
		}
		if p.Error != nil {
			m.Errors = append(m.Errors, fmt.Sprintf("%s: %s", p.ImportPath, p.Error.Err))
		} else if len(p.TypeErrors) > 0 {
			m.Errors = append(m.Errors, fmt.Sprintf("%s: %v", p.ImportPath, p.TypeErrors[0]))
		}
		m.Packages[p.ImportPath] = p.Types
		m.Names[p.ImportPath] = p.Name
	}
	if len(m.Packages) == 0 && len(prog.Errors) > 0 {
		return fmt.Errorf("loading %s: %s", m, prog.Errors[0])
	}
	sort.Strings(m.Errors)
	return nil
}
