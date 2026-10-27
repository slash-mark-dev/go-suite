// Package loader lists packages with the go command and type-checks them
// (dependencies and the standard library included) from source with
// go/types, without golang.org/x/tools.
package loader

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/slash-mark-dev/go-suite/internal/goenv"
)

// Module is the module a package belongs to, as reported by go list.
type Module struct {
	Path      string  `json:"Path"`
	Version   string  `json:"Version,omitempty"`
	Main      bool    `json:"Main,omitempty"`
	Indirect  bool    `json:"Indirect,omitempty"`
	Dir       string  `json:"Dir,omitempty"`
	GoMod     string  `json:"GoMod,omitempty"`
	GoVersion string  `json:"GoVersion,omitempty"`
	Replace   *Module `json:"Replace,omitempty"`
}

// PackageError is a go list error.
type PackageError struct {
	ImportStack []string `json:"ImportStack,omitempty"`
	Pos         string   `json:"Pos,omitempty"`
	Err         string   `json:"Err"`
}

// Package is a listed (and optionally type-checked) package.
type Package struct {
	ImportPath     string            `json:"ImportPath"`
	Name           string            `json:"Name"`
	Dir            string            `json:"Dir"`
	Module         *Module           `json:"Module,omitempty"`
	Standard       bool              `json:"Standard,omitempty"`
	DepOnly        bool              `json:"DepOnly,omitempty"`
	Goroot         bool              `json:"Goroot,omitempty"`
	GoFiles        []string          `json:"GoFiles,omitempty"`
	CgoFiles       []string          `json:"CgoFiles,omitempty"`
	CFiles         []string          `json:"CFiles,omitempty"`
	CXXFiles       []string          `json:"CXXFiles,omitempty"`
	SFiles         []string          `json:"SFiles,omitempty"`
	SysoFiles      []string          `json:"SysoFiles,omitempty"`
	IgnoredGoFiles []string          `json:"IgnoredGoFiles,omitempty"`
	TestGoFiles    []string          `json:"TestGoFiles,omitempty"`
	XTestGoFiles   []string          `json:"XTestGoFiles,omitempty"`
	EmbedFiles     []string          `json:"EmbedFiles,omitempty"`
	CgoCFLAGS      []string          `json:"CgoCFLAGS,omitempty"`
	CgoLDFLAGS     []string          `json:"CgoLDFLAGS,omitempty"`
	CgoPkgConfig   []string          `json:"CgoPkgConfig,omitempty"`
	Imports        []string          `json:"Imports,omitempty"`
	ImportMap      map[string]string `json:"ImportMap,omitempty"`
	Deps           []string          `json:"Deps,omitempty"`
	TestImports    []string          `json:"TestImports,omitempty"`
	XTestImports   []string          `json:"XTestImports,omitempty"`
	ForTest        string            `json:"ForTest,omitempty"`
	Error          *PackageError     `json:"Error,omitempty"`
	DepsErrors     []*PackageError   `json:"DepsErrors,omitempty"`
	Incomplete     bool              `json:"Incomplete,omitempty"`

	// Filled by type-checking.
	Syntax     []*ast.File    `json:"-"`
	Types      *types.Package `json:"-"`
	Info       *types.Info    `json:"-"`
	TypeErrors []error        `json:"-"`
	// IsXTest marks a synthesized external test package ("p_test").
	IsXTest bool `json:"-"`
}

// ModulePath returns the package's module path, "std" for the standard
// library, or "".
func (p *Package) ModulePath() string {
	if p.Standard {
		return "std"
	}
	if p.Module != nil {
		return p.Module.Path
	}
	return ""
}

// ModuleVersion returns the version of the package's module ("" for main
// modules and std).
func (p *Package) ModuleVersion() string {
	if p.Module != nil {
		return p.Module.Version
	}
	return ""
}

// InMainModule reports whether the package belongs to a main module.
func (p *Package) InMainModule() bool { return p.Module != nil && p.Module.Main }

// Config controls loading.
type Config struct {
	Env      *goenv.Env
	Dir      string
	Patterns []string // default "./..."
	Tests    bool     // include _test.go files of root packages
	Tags     []string
	GOOS     string
	GOARCH   string
	CGO      string // "0" or "1" to force CGO_ENABLED
	// TypeCheck parses and type-checks every listed package.
	TypeCheck bool
	// SkipBodies, if set, reports packages whose function bodies need not
	// be type-checked (faster; their call graph edges will be missing).
	SkipBodies func(*Package) bool
	// ExtraEnv is appended to the go command environment.
	ExtraEnv []string
	Stderr   io.Writer
}

// Program is the result of Load.
type Program struct {
	Fset     *token.FileSet
	Packages []*Package          // all packages, dependencies first
	ByPath   map[string]*Package // by import path
	Roots    []*Package          // packages matched by the patterns
	Errors   []string            // go list and type-checking problems
	GOOS     string
	GOARCH   string
}

var listFields = "ImportPath,Name,Dir,Module,Standard,DepOnly,Goroot,GoFiles,CgoFiles,CFiles,CXXFiles,SFiles,SysoFiles,IgnoredGoFiles,TestGoFiles,XTestGoFiles,EmbedFiles,CgoCFLAGS,CgoLDFLAGS,CgoPkgConfig,Imports,ImportMap,Deps,TestImports,XTestImports,ForTest,Error,DepsErrors,Incomplete"

// GoList runs `go list -e -json -deps` (plus extra flags) and decodes the
// package stream.
func GoList(ctx context.Context, cfg Config, extra ...string) ([]*Package, error) {
	if cfg.Env == nil || !cfg.Env.HaveGo() {
		return nil, errors.New("this command needs the go command (install Go from https://go.dev/dl)")
	}
	args := []string{"list", "-e", "-json=" + listFields}
	args = append(args, extra...)
	if len(cfg.Tags) > 0 {
		args = append(args, "-tags="+strings.Join(cfg.Tags, ","))
	}
	pats := cfg.Patterns
	if len(pats) == 0 {
		pats = []string{"./..."}
	}
	args = append(args, "--")
	args = append(args, pats...)
	cmd := exec.CommandContext(ctx, cfg.Env.GoBin, args...)
	cmd.Dir = cfg.Dir
	env := cfg.Env.EnvironIn(cfg.Dir)
	if cfg.GOOS != "" {
		env = append(env, "GOOS="+cfg.GOOS)
	}
	if cfg.GOARCH != "" {
		env = append(env, "GOARCH="+cfg.GOARCH)
	}
	if cfg.CGO != "" {
		env = append(env, "CGO_ENABLED="+cfg.CGO)
	}
	env = append(env, cfg.ExtraEnv...)
	cmd.Env = env
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	runErr := cmd.Run()
	dec := json.NewDecoder(&out)
	var pkgs []*Package
	for {
		var p Package
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			return pkgs, fmt.Errorf("go list: decoding output: %v", err)
		}
		pkgs = append(pkgs, &p)
	}
	if runErr != nil && len(pkgs) == 0 {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = runErr.Error()
		}
		return nil, fmt.Errorf("go list: %s", msg)
	}
	if cfg.Stderr != nil && stderr.Len() > 0 {
		cfg.Stderr.Write(stderr.Bytes())
	}
	return pkgs, nil
}

// Load lists packages and their dependencies and, if cfg.TypeCheck is set,
// parses and type-checks all of them.
func Load(ctx context.Context, cfg Config) (*Program, error) {
	extra := []string{"-deps"}
	pkgs, err := GoList(ctx, cfg, extra...)
	if err != nil {
		return nil, err
	}
	prog := &Program{Fset: token.NewFileSet(), ByPath: map[string]*Package{}, GOOS: cfg.GOOS, GOARCH: cfg.GOARCH}
	if prog.GOOS == "" {
		prog.GOOS = cfg.Env.Get("GOOS")
	}
	if prog.GOARCH == "" {
		prog.GOARCH = cfg.Env.Get("GOARCH")
	}
	for _, p := range pkgs {
		if p.ForTest != "" || strings.HasSuffix(p.ImportPath, ".test") {
			continue
		}
		if _, dup := prog.ByPath[p.ImportPath]; dup {
			continue
		}
		prog.ByPath[p.ImportPath] = p
		prog.Packages = append(prog.Packages, p)
		if !p.DepOnly {
			prog.Roots = append(prog.Roots, p)
		}
		if p.Error != nil {
			prog.Errors = append(prog.Errors, fmt.Sprintf("%s: %s", p.ImportPath, p.Error.Err))
		}
	}
	if cfg.Tests {
		if err := addTests(ctx, cfg, prog); err != nil {
			prog.Errors = append(prog.Errors, err.Error())
		}
	}
	if cfg.TypeCheck {
		prog.typeCheck(cfg)
	}
	return prog, nil
}

// addTests lists the test dependencies of the root packages and merges
// _test.go files into the roots (internal tests) or synthesized "_test"
// packages (external tests).
func addTests(ctx context.Context, cfg Config, prog *Program) error {
	pkgs, err := GoList(ctx, cfg, "-deps", "-test")
	if err != nil {
		return err
	}
	for _, p := range pkgs {
		if p.ForTest != "" || strings.HasSuffix(p.ImportPath, ".test") {
			continue
		}
		if _, ok := prog.ByPath[p.ImportPath]; !ok {
			p.DepOnly = true
			prog.ByPath[p.ImportPath] = p
			// Insert test-only dependencies before the roots that need them.
			prog.Packages = append([]*Package{p}, prog.Packages...)
		}
	}
	for _, r := range append([]*Package(nil), prog.Roots...) {
		if len(r.TestGoFiles) > 0 {
			r.GoFiles = append(append([]string(nil), r.GoFiles...), r.TestGoFiles...)
			r.Imports = mergeImports(r.Imports, r.TestImports)
		}
		if len(r.XTestGoFiles) > 0 {
			x := &Package{ImportPath: r.ImportPath + "_test", Name: r.Name + "_test", Dir: r.Dir, Module: r.Module,
				GoFiles: r.XTestGoFiles, Imports: r.XTestImports, ImportMap: r.ImportMap, IsXTest: true}
			prog.ByPath[x.ImportPath] = x
			prog.Packages = append(prog.Packages, x)
			prog.Roots = append(prog.Roots, x)
		}
	}
	return nil
}

func mergeImports(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string(nil), a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// resolve maps an import path as written in source to a listed package.
func (prog *Program) resolve(from *Package, path string) *Package {
	if from != nil && from.ImportMap != nil {
		if p, ok := from.ImportMap[path]; ok {
			path = p
		}
	}
	return prog.ByPath[path]
}

func (prog *Program) typeCheck(cfg Config) {
	// Topological levels so independent packages check in parallel.
	level := map[*Package]int{}
	var depth func(p *Package, stack map[*Package]bool) int
	depth = func(p *Package, stack map[*Package]bool) int {
		if d, ok := level[p]; ok {
			return d
		}
		if stack[p] {
			return 0
		}
		stack[p] = true
		d := 0
		for _, imp := range p.Imports {
			if q := prog.resolve(p, imp); q != nil && q != p {
				if x := depth(q, stack) + 1; x > d {
					d = x
				}
			}
		}
		delete(stack, p)
		level[p] = d
		return d
	}
	maxL := 0
	for _, p := range prog.Packages {
		if d := depth(p, map[*Package]bool{}); d > maxL {
			maxL = d
		}
	}
	byLevel := make([][]*Package, maxL+1)
	for _, p := range prog.Packages {
		byLevel[level[p]] = append(byLevel[level[p]], p)
	}
	sizes := types.SizesFor("gc", prog.GOARCH)
	if sizes == nil {
		sizes = types.SizesFor("gc", runtime.GOARCH)
	}
	var mu sync.Mutex
	workers := runtime.GOMAXPROCS(0)
	for _, pkgs := range byLevel {
		sem := make(chan struct{}, workers)
		var wg sync.WaitGroup
		for _, p := range pkgs {
			wg.Add(1)
			sem <- struct{}{}
			go func(p *Package) {
				defer wg.Done()
				defer func() { <-sem }()
				prog.checkOne(p, cfg, sizes)
				if len(p.TypeErrors) > 0 && !p.Standard {
					mu.Lock()
					prog.Errors = append(prog.Errors, fmt.Sprintf("%s: %v", p.ImportPath, p.TypeErrors[0]))
					mu.Unlock()
				}
			}(p)
		}
		wg.Wait()
	}
}

func (prog *Program) checkOne(p *Package, cfg Config, sizes types.Sizes) {
	if p.ImportPath == "unsafe" {
		p.Types = types.Unsafe
		return
	}
	files := append(append([]string(nil), p.GoFiles...), p.CgoFiles...)
	for _, name := range files {
		fn := name
		if !filepath.IsAbs(fn) {
			fn = filepath.Join(p.Dir, name)
		}
		f, err := parser.ParseFile(prog.Fset, fn, nil, parser.SkipObjectResolution|parser.ParseComments)
		if f != nil {
			p.Syntax = append(p.Syntax, f)
		}
		if err != nil {
			p.TypeErrors = append(p.TypeErrors, err)
		}
	}
	p.Info = &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
		Instances:  map[*ast.Ident]types.Instance{},
		Implicits:  map[ast.Node]types.Object{},
	}
	tc := &types.Config{
		Importer: importerFunc(func(path string) (*types.Package, error) {
			if path == "unsafe" {
				return types.Unsafe, nil
			}
			q := prog.resolve(p, path)
			if q == nil || q.Types == nil {
				return nil, fmt.Errorf("package %q not loaded", path)
			}
			return q.Types, nil
		}),
		FakeImportC:      true,
		Sizes:            sizes,
		IgnoreFuncBodies: cfg.SkipBodies != nil && cfg.SkipBodies(p),
		Error: func(err error) {
			if len(p.TypeErrors) < 20 {
				p.TypeErrors = append(p.TypeErrors, err)
			}
		},
	}
	if p.Module != nil && p.Module.GoVersion != "" && !p.Standard {
		tc.GoVersion = "go" + p.Module.GoVersion
	}
	path := p.ImportPath
	if p.Name == "main" {
		path = p.ImportPath
	}
	pkg, _ := tc.Check(path, prog.Fset, p.Syntax, p.Info)
	p.Types = pkg
}

type importerFunc func(string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }

// Position returns "file:line:col" for pos with the file relative to base
// when possible.
func (prog *Program) Position(pos token.Pos, base string) string {
	if !pos.IsValid() {
		return ""
	}
	p := prog.Fset.Position(pos)
	name := p.Filename
	if base != "" {
		if rel, err := filepath.Rel(base, name); err == nil && !strings.HasPrefix(rel, "..") {
			name = rel
		}
	}
	return fmt.Sprintf("%s:%d:%d", filepath.ToSlash(name), p.Line, p.Column)
}
