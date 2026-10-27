package upgrade

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/apidiff"
	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/loader"
	"github.com/slash-mark-dev/go-suite/internal/modgraph"
	"github.com/slash-mark-dev/go-suite/internal/modproxy"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/project"
	"github.com/slash-mark-dev/go-suite/internal/semver"
)

var migrateFlags struct {
	apply *bool
	noAPI *bool
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "migrate",
		Group:   group,
		Summary: "Major version migrator: plan (and apply) a move from foo to foo/vN",
		Usage:   "sm-go migrate <module> [vN | module/vN[@version]] [--apply]",
		Help: `Plans the migration of a dependency to a new major version, which in Go is
a different module path (example.com/foo → example.com/foo/v2):

  - every import to rewrite, as file:line, across all .go files of the main
    module (test files and files behind build tags included; vendor,
    testdata and nested modules skipped);
  - imports of packages that no longer exist in the new major version, and
    packages whose name changed (the rewrite adds an import name so the
    code keeps compiling);
  - the go.mod change;
  - the incompatible API changes between the version in use and the new
    major version, restricted to the packages you import, each with the
    file:line of the references it breaks.

The newest major version is found on the module proxy unless a target is
given. By default nothing is changed; --apply rewrites the imports in place
(go/ast + go/format, comments preserved) and the require line in go.mod.
Run 'go mod tidy' afterwards. Exit code 1 when the migration breaks code
(API changes in used symbols or missing packages).`,
		Examples: []string{
			"sm-go migrate github.com/go-redis/redis",
			"sm-go migrate github.com/google/go-github/v60 v62",
			"sm-go migrate example.com/foo example.com/foo/v3@v3.1.0 --apply",
		},
		Sources: []string{"Go module proxy", "checksum database (via the go command)"},
		NeedsGo: true,
		Flags: func(fs *flag.FlagSet) {
			migrateFlags.apply = fs.Bool("apply", false, "rewrite imports and go.mod in place")
			migrateFlags.noAPI = fs.Bool("no-api", false, "skip the API compatibility check")
		},
		Run: runMigrate,
	})
}

// MigrateImport is one import to rewrite.
type MigrateImport struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Old     string `json:"old"`
	New     string `json:"new"`
	AddName string `json:"addName,omitempty"` // import name added because the package name changed
	Missing bool   `json:"missing"`           // the package does not exist in the new major version
}

// GoModEdit is the planned go.mod change.
type GoModEdit struct {
	File   string `json:"file"`
	Line   int    `json:"line,omitempty"` // 0: a new line is appended
	Remove string `json:"remove,omitempty"`
	Add    string `json:"add"`
}

// MigrateResult is the JSON result of migrate.
type MigrateResult struct {
	Module      string          `json:"module"`
	FromPath    string          `json:"fromPath"`
	FromVersion string          `json:"fromVersion"`
	ToPath      string          `json:"toPath"`
	ToVersion   string          `json:"toVersion"`
	Imports     []MigrateImport `json:"imports"`
	Files       []string        `json:"files"`
	GoMod       GoModEdit       `json:"gomod"`
	Missing     []string        `json:"missingPackages"`
	APIChecked  bool            `json:"apiChecked"`
	Breaks      []APIBreak      `json:"apiBreaks"`
	Affected    int             `json:"affectedReferences"`
	Additions   int             `json:"apiAdditions"`
	Applied     bool            `json:"applied"`
	Changed     []string        `json:"changedFiles"`
	NextSteps   []string        `json:"nextSteps"`
}

type parsedFile struct {
	path string
	fset *token.FileSet
	file *ast.File
	mode fs.FileMode
}

func runMigrate(c *cli.Context) error {
	if len(c.Args) < 1 || len(c.Args) > 2 {
		return cli.Usagef("want a module path and optionally a target (vN or module/vN[@version])")
	}
	p, err := c.Project()
	if err != nil {
		if errors.Is(err, project.ErrNoModule) {
			return cli.Usagef("%v", err)
		}
		return err
	}
	g, err := c.Graph()
	if err != nil {
		return err
	}
	oldPath, q, err := splitArg(c.Args[0])
	if err != nil {
		return err
	}
	if q != "" {
		return cli.Usagef("give the module path without a version (the version in use is %s)", g.Version(oldPath))
	}
	oldV := g.Version(oldPath)
	if oldV == "" || g.IsMain(oldPath) {
		return cli.Usagef("%s is not a dependency of %s", oldPath, p.ModulePath())
	}
	newPath, newV, err := migrateTarget(c, oldPath, oldV, c.Args[1:])
	if err != nil {
		return err
	}
	res := &MigrateResult{Module: p.ModulePath(), FromPath: oldPath, FromVersion: oldV, ToPath: newPath, ToVersion: newV,
		Imports: []MigrateImport{}, Files: []string{}, Missing: []string{}, Breaks: []APIBreak{}, Changed: []string{}, NextSteps: []string{}}

	// Imports to rewrite.
	files, err := scanImports(p.ModDir, oldPath, g, res)
	if err != nil {
		return err
	}

	// APIs of both versions.
	c.Logf("type-checking %s@%s and %s@%s", oldPath, oldV, newPath, newV)
	newAPI, err := loadAPI(c, newPath, newV)
	if err != nil {
		return err
	}
	var oldAPI *apidiff.Module
	if !*migrateFlags.noAPI || len(res.Imports) > 0 {
		if oldAPI, err = loadAPI(c, oldPath, oldV); err != nil {
			return err
		}
	}
	missing := map[string]bool{}
	for i := range res.Imports {
		im := &res.Imports[i]
		if _, ok := newAPI.Packages[im.New]; !ok {
			im.Missing = true
			if !missing[im.New] {
				missing[im.New] = true
				res.Missing = append(res.Missing, im.Old)
			}
			continue
		}
		if on, nn := oldAPI.Names[im.Old], newAPI.Names[im.New]; on != "" && nn != "" && on != nn {
			im.AddName = on
		}
	}
	sort.Strings(res.Missing)

	// API changes in the packages the project uses.
	if !*migrateFlags.noAPI && len(res.Imports) > 0 {
		if err := migrateAPI(c, p, oldAPI, newAPI, res); err != nil {
			return err
		}
	}

	// go.mod.
	res.GoMod = goModEdit(p, oldPath, newPath, newV)

	res.NextSteps = append(res.NextSteps, "go mod tidy", "go build ./... && go test ./...")
	if *migrateFlags.apply {
		if len(res.Missing) > 0 {
			return cli.Usagef("not applying: %s no longer %s in %s@%s", strings.Join(res.Missing, ", "),
				pluralWord(len(res.Missing), "exists", "exist"), newPath, newV)
		}
		if err := applyMigration(p, files, res); err != nil {
			return err
		}
		res.Applied = true
	} else {
		res.NextSteps = append([]string{"sm-go migrate " + oldPath + " " + newPath + "@" + newV + " --apply"}, res.NextSteps...)
	}
	c.SetResult(res)
	if res.Affected > 0 || len(res.Missing) > 0 {
		c.Issues()
	}
	if c.Text() {
		printMigrate(c, res)
	}
	return nil
}

// migrateTarget resolves the target module path and version.
func migrateTarget(c *cli.Context, oldPath, oldV string, args []string) (string, string, error) {
	prefix, _, _ := module.SplitPathVersion(oldPath)
	curMajor := module.MajorOf(oldPath)
	var newPath, q string
	if len(args) == 0 {
		// Probe the proxy for the newest major version, starting after
		// the major in use: for a +incompatible version (v6.15.9+incompatible
		// of a path without suffix) that is the version's major, so the
		// first semantic-import major is /v7, not /v2. A single missing
		// major (abandoned or never published) does not end the search.
		n, _ := strconv.Atoi(strings.TrimPrefix(curMajor, "v"))
		if strings.HasSuffix(oldV, "+incompatible") {
			n, _ = strconv.Atoi(strings.TrimPrefix(semver.Major(oldV), "v"))
		}
		misses := 0
		for k := max(n, 1) + 1; k <= max(n, 1)+20 && misses < 2; k++ {
			cand := module.WithMajor(oldPath, "v"+strconv.Itoa(k))
			vs, err := c.Proxy().Versions(c.Ctx, cand)
			if err != nil && !errors.Is(err, modproxy.ErrNotFound) {
				return "", "", err
			}
			if len(vs) == 0 {
				if _, err := c.Proxy().Latest(c.Ctx, cand); err != nil {
					if errors.Is(err, modproxy.ErrNotFound) {
						misses++
						continue
					}
					return "", "", err
				}
			}
			newPath, misses = cand, 0
		}
		if newPath == "" {
			return "", "", cli.Usagef("no newer major version of %s found on the module proxy", oldPath)
		}
	} else {
		t := args[0]
		if semver.IsValid(t) && semver.Major(t) == t {
			newPath = module.WithMajor(oldPath, t)
		} else {
			var err error
			if newPath, q, err = splitArg(t); err != nil {
				return "", "", err
			}
			if np, _, _ := module.SplitPathVersion(newPath); np != prefix {
				return "", "", cli.Usagef("%s is not a major version of %s", newPath, oldPath)
			}
		}
	}
	if newPath == oldPath {
		return "", "", cli.Usagef("%s is already the module in use", newPath)
	}
	if _, pm, ok := module.SplitPathVersion(newPath); !ok || (pm == "" && module.MajorOf(newPath) == "v1" && curMajor == "v1") {
		return "", "", cli.Usagef("invalid target module path %s", newPath)
	}
	v, err := resolveQuery(c, newPath, q, "")
	if err != nil {
		return "", "", err
	}
	if v == "none" {
		return "", "", cli.Usagef("target version none is not allowed")
	}
	if !module.MatchPathMajor(v, majorSuffix(newPath)) {
		return "", "", cli.Usagef("%s@%s: version does not match the module path", newPath, v)
	}
	return newPath, v, nil
}

func majorSuffix(path string) string {
	_, pm, _ := module.SplitPathVersion(path)
	return pm
}

// moduleOf returns the build-list module providing import path imp (the
// longest module path prefix).
func moduleOf(g *modgraph.Graph, imp string) string {
	best := ""
	for p := range g.Selected {
		if (imp == p || strings.HasPrefix(imp, p+"/")) && len(p) > len(best) {
			best = p
		}
	}
	return best
}

// scanImports finds the imports of packages of oldPath in every .go file
// of the main module.
func scanImports(root, oldPath string, g *modgraph.Graph, res *MigrateResult) ([]*parsedFile, error) {
	var files []*parsedFile
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != root {
				if name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
					return filepath.SkipDir
				}
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir // nested module
				}
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parsing %s: %v", path, err)
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		matched := false
		for _, spec := range f.Imports {
			imp, err := strconv.Unquote(spec.Path.Value)
			if err != nil || moduleOf(g, imp) != oldPath {
				continue
			}
			matched = true
			res.Imports = append(res.Imports, MigrateImport{File: rel, Line: fset.Position(spec.Pos()).Line,
				Old: imp, New: res.ToPath + strings.TrimPrefix(imp, oldPath)})
		}
		if matched {
			fi, _ := d.Info()
			mode := fs.FileMode(0o644)
			if fi != nil {
				mode = fi.Mode().Perm()
			}
			files = append(files, &parsedFile{path: path, fset: fset, file: f, mode: mode})
			res.Files = append(res.Files, rel)
		}
		return nil
	})
	return files, err
}

func migrateAPI(c *cli.Context, p *project.Project, oldAPI, newAPI *apidiff.Module, res *MigrateResult) error {
	only := map[string]bool{}
	for _, im := range res.Imports {
		if r, ok := oldAPI.Rel(im.Old); ok {
			only[r] = true
		}
	}
	c.Logf("type-checking the project")
	prog, err := c.Load(loader.Config{TypeCheck: true, Tests: true,
		SkipBodies: func(pk *loader.Package) bool { return !pk.InMainModule() }})
	if err != nil {
		return err
	}
	base := p.ModDir
	usage := apidiff.CollectUsage(prog, base, func(path string) bool {
		pk := prog.ByPath[path]
		return pk != nil && pk.Module != nil && pk.Module.Path == res.FromPath
	})
	rep := apidiff.CompareModules(oldAPI, newAPI, only)
	res.APIChecked = true
	res.Additions = len(rep.Compatible)
	for _, ch := range rep.Incompatible {
		usedPath := res.FromPath + strings.TrimPrefix(ch.Package, res.ToPath)
		b := APIBreak{Change: ch, UsedAt: usage.Affects(usedPath, ch)}
		if b.UsedAt == nil {
			b.UsedAt = []string{}
		}
		res.Affected += len(b.UsedAt)
		res.Breaks = append(res.Breaks, b)
	}
	return nil
}

func goModEdit(p *project.Project, oldPath, newPath, newV string) GoModEdit {
	e := GoModEdit{File: p.Rel(p.GoModPath), Add: "require " + newPath + " " + newV}
	for _, r := range p.GoMod.Require {
		if r.Mod.Path == oldPath {
			e.Line = r.Line
			e.Remove = "require " + r.Mod.Path + " " + r.Mod.Version
			if r.Indirect {
				e.Remove += " // indirect"
			}
			break
		}
	}
	return e
}

// applyMigration rewrites the imports and go.mod.
func applyMigration(p *project.Project, files []*parsedFile, res *MigrateResult) error {
	plan := map[string]MigrateImport{}
	for _, im := range res.Imports {
		plan[im.Old] = im
	}
	for _, pf := range files {
		for _, spec := range pf.file.Imports {
			imp, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				continue
			}
			im, ok := plan[imp]
			if !ok {
				continue
			}
			spec.Path.Value = strconv.Quote(im.New)
			if im.AddName != "" && spec.Name == nil {
				spec.Name = &ast.Ident{Name: im.AddName, NamePos: spec.Path.Pos()}
			}
		}
		var buf bytes.Buffer
		if err := format.Node(&buf, pf.fset, pf.file); err != nil {
			return fmt.Errorf("formatting %s: %v", pf.path, err)
		}
		if err := os.WriteFile(pf.path, buf.Bytes(), pf.mode); err != nil {
			return err
		}
		rel, _ := filepath.Rel(p.ModDir, pf.path)
		res.Changed = append(res.Changed, filepath.ToSlash(rel))
	}
	data, err := os.ReadFile(p.GoModPath)
	if err != nil {
		return err
	}
	lines := strings.SplitAfter(string(data), "\n")
	e := res.GoMod
	if e.Line > 0 && e.Line <= len(lines) {
		old := lines[e.Line-1]
		nl := ""
		if strings.HasSuffix(old, "\n") {
			nl = "\n"
		}
		trim := strings.TrimLeft(old, " \t")
		indent := old[:len(old)-len(trim)]
		repl := newLineFor(res.ToPath, res.ToVersion)
		if strings.HasPrefix(trim, "require") {
			repl = "require " + repl
		}
		lines[e.Line-1] = indent + repl + nl
	} else {
		if len(lines) > 0 && !strings.HasSuffix(lines[len(lines)-1], "\n") {
			lines[len(lines)-1] += "\n"
		}
		lines = append(lines, "\nrequire "+newLineFor(res.ToPath, res.ToVersion)+"\n")
	}
	fi, err := os.Stat(p.GoModPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(p.GoModPath, []byte(strings.Join(lines, "")), fi.Mode().Perm()); err != nil {
		return err
	}
	res.Changed = append(res.Changed, res.GoMod.File)
	return nil
}

func newLineFor(path, version string) string { return path + " " + version }

func printMigrate(c *cli.Context, res *MigrateResult) {
	out := c.Out
	out.Title(fmt.Sprintf("Migration %s@%s → %s@%s", res.FromPath, res.FromVersion, res.ToPath, res.ToVersion))
	if len(res.Imports) == 0 {
		out.Warn("no file imports %s (it may be an indirect dependency)", res.FromPath)
	} else {
		out.Heading(fmt.Sprintf("Imports to rewrite (%s in %s)", plural(len(res.Imports), "import", "imports"), plural(len(res.Files), "file", "files")))
		var rows [][]string
		for _, im := range res.Imports {
			note := ""
			switch {
			case im.Missing:
				note = out.Red("package missing in " + res.ToPath)
			case im.AddName != "":
				note = out.Yellow("package renamed: imported as " + im.AddName)
			}
			rows = append(rows, []string{fmt.Sprintf("%s:%d", im.File, im.Line), im.Old, "→ " + im.New, note})
		}
		out.Table(nil, rows)
	}
	out.Heading("go.mod")
	if res.GoMod.Remove != "" {
		out.Printf("  %s %s\n", out.Red("-"), res.GoMod.Remove)
	}
	out.Printf("  %s %s\n", out.Green("+"), res.GoMod.Add)
	if res.APIChecked {
		out.Heading("API changes in the packages you import")
		if len(res.Breaks) == 0 {
			out.OK("no incompatible changes (%s)", plural(res.Additions, "addition", "additions"))
		}
		for _, b := range res.Breaks {
			if len(b.UsedAt) == 0 {
				out.Printf("  %s %s %s\n", out.Yellow("!"), b.Message, out.Dim("(not referenced by your code)"))
				continue
			}
			out.Printf("  %s %s\n", out.Red("✗"), b.Message)
			for _, pos := range b.UsedAt {
				out.Printf("      %s %s\n", out.Dim("used at"), pos)
			}
		}
	}
	out.Println()
	if res.Applied {
		out.OK("rewrote %s", plural(len(res.Changed), "file", "files"))
	} else {
		out.Printf("%s\n", out.Dim("dry run: nothing was changed"))
	}
	if res.Affected > 0 {
		out.Bad("%s in your code must be updated by hand", plural(res.Affected, "reference", "references"))
	}
	if len(res.Missing) > 0 {
		out.Bad("%s no longer %s in %s", strings.Join(res.Missing, ", "), pluralWord(len(res.Missing), "exists", "exist"), res.ToPath)
	}
	out.Printf("\n%s\n", out.Bold("Next steps"))
	for _, s := range res.NextSteps {
		out.Printf("  %s\n", s)
	}
}
