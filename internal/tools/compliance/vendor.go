package compliance

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/modfile"
	"github.com/slash-mark-dev/go-suite/internal/modgraph"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/modzip"
	"github.com/slash-mark-dev/go-suite/internal/par"
	"github.com/slash-mark-dev/go-suite/internal/project"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/semver"
	"github.com/slash-mark-dev/go-suite/internal/ui"
)

// VendorFile is a vendored file that differs from what `go mod vendor`
// would have written.
type VendorFile struct {
	Path    string `json:"path"` // relative to the module directory, e.g. vendor/example.com/a/a.go
	Module  string `json:"module,omitempty"`
	Version string `json:"version,omitempty"`
	// Status is modified (content differs from the module zip), added (not
	// in the module zip), missing (go mod vendor would have copied it) or
	// extra (in the module zip but not something go mod vendor copies).
	Status string `json:"status"`
}

// VendoredModule is one module of vendor/modules.txt.
type VendoredModule struct {
	Path      string   `json:"path"`
	Version   string   `json:"version"`
	Replace   string   `json:"replace,omitempty"`
	Explicit  bool     `json:"explicit"`
	GoVersion string   `json:"goVersion,omitempty"`
	Packages  []string `json:"packages"`
	// Files is the number of files on disk attributed to the module.
	Files int `json:"files"`
	// Status is ok, tampered, skipped (local replacement or --offline-only),
	// error (zip unavailable) or "no packages".
	Status   string `json:"status"`
	Note     string `json:"note,omitempty"`
	Modified int    `json:"modified"`
	Added    int    `json:"added"`
	Missing  int    `json:"missing"`

	line int
	mod  module.Version
	repl module.Version
}

// VendorResult is the result of the vendor tool.
type VendorResult struct {
	Main    string `json:"main"`
	Present bool   `json:"present"`
	// GoVersion is the main module's go version, which decides what
	// go mod vendor writes (## explicit from 1.14, ## go from 1.17).
	GoVersion string `json:"goVersion"`
	// Consistent is false when `go build -mod=vendor` would refuse the
	// vendor directory; GoErrors are the lines it would print.
	Consistent bool              `json:"consistent"`
	GoErrors   []string          `json:"goErrors"`
	Modules    []*VendoredModule `json:"modules"`
	Files      []VendorFile      `json:"files"`
	Stray      []string          `json:"stray"`
	Verified   int               `json:"verified"` // modules compared with their module zip
	Findings   []report.Finding  `json:"findings"`
	Summary    map[string]int    `json:"summary"`
	Failing    int               `json:"failing"`
}

var vendorFlags struct {
	failOn      func() (report.Severity, error)
	offlineOnly *bool
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "vendor",
		Group:   group,
		Summary: "Verify vendor/ against modules.txt, go.mod, go.sum and the module zips",
		Usage:   "sm-go vendor [flags]",
		Help: `Checks the vendor directory of the main module the way the go command does, and then goes
further: every vendored file is compared with the module zip it was copied from.

Consistency (what 'go build -mod=vendor' refuses, reported with the go command's own wording):
  requirements in go.mod not marked "## explicit" in vendor/modules.txt, missing or at another
  version; replacements missing, different or extra; modules marked explicit but not required.
Beyond the go command:
  "## go" annotations that differ from the vendored module's go.mod (go 1.17 and later), modules
  vendored at a version other than the one the build list selects, packages listed in
  modules.txt but absent on disk, packages the module does not contain, and stray directories
  under vendor/ that belong to no listed module.
Hand edits:
  each vendored module's zip is fetched from GOPROXY (or the module cache), respecting
  replacements, and checked against go.sum. Vendored files are compared byte for byte:
  modified files, added files, and files 'go mod vendor' would have copied (package sources,
  embedded files, LICENSE/NOTICE-style metadata) but that are missing. Local directory
  replacements are not compared. --offline-only skips everything that needs the network.

A project without a vendor directory is reported as such and passes. Findings at or above
--fail-on (default medium) exit with code 1.`,
		Examples: []string{"sm-go vendor", "sm-go vendor --offline-only", "sm-go vendor --fail-on high --json"},
		Sources:  []string{"Go module proxy", "go.sum"},
		Flags: func(fs *flag.FlagSet) {
			vendorFlags.failOn = cli.SeverityFlag(fs, "fail-on", "medium", "minimum `severity` that fails the run")
			vendorFlags.offlineOnly = fs.Bool("offline-only", false, "only local checks: no module zips, go.mod files or build list")
		},
		Run: runVendor,
	})
}

// vendorMeta mirrors the go command's view of a modules.txt module line.
type vendorMeta struct {
	Explicit    bool
	Replacement module.Version
	GoVersion   string
}

// vendorList is vendor/modules.txt as the go command reads it
// (cmd/go/internal/modload.readVendorList).
type vendorList struct {
	meta     map[module.Version]*vendorMeta
	order    []module.Version          // module lines in order (deduplicated)
	list     []module.Version          // modules providing packages
	version  map[string]string         // path -> version providing packages
	replaced []module.Version          // modules with a replacement
	pkgMod   map[string]module.Version // package -> module
	pkgs     map[module.Version][]string
	line     map[module.Version]int
}

func readVendorList(data []byte) *vendorList {
	vl := &vendorList{meta: map[module.Version]*vendorMeta{}, version: map[string]string{},
		pkgMod: map[string]module.Version{}, pkgs: map[module.Version][]string{}, line: map[module.Version]int{}}
	getMeta := func(m module.Version) *vendorMeta {
		x := vl.meta[m]
		if x == nil {
			x = &vendorMeta{}
			vl.meta[m] = x
		}
		return x
	}
	seenRepl := map[module.Version]bool{}
	var mod module.Version
	for i, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "# ") {
			f := strings.Fields(line)
			if len(f) < 3 {
				continue
			}
			switch {
			case semver.IsValid(f[2]):
				mod = module.Version{Path: f[1], Version: f[2]}
				f = f[3:]
			case f[2] == "=>":
				mod = module.Version{Path: f[1]}
				f = f[2:]
			default:
				mod = module.Version{}
				continue
			}
			if _, ok := vl.line[mod]; !ok {
				vl.line[mod] = i + 1
				vl.order = append(vl.order, mod)
			}
			if len(f) >= 2 && f[0] == "=>" {
				meta := getMeta(mod)
				if len(f) == 2 {
					meta.Replacement = module.Version{Path: f[1]}
				} else if len(f) == 3 && semver.IsValid(f[2]) {
					meta.Replacement = module.Version{Path: f[1], Version: f[2]}
				} else {
					continue
				}
				if !seenRepl[mod] {
					seenRepl[mod] = true
					vl.replaced = append(vl.replaced, mod)
				}
			}
			continue
		}
		if mod.Path == "" {
			continue
		}
		if ann, ok := strings.CutPrefix(line, "## "); ok {
			meta := getMeta(mod)
			for _, e := range strings.Split(ann, ";") {
				e = strings.TrimSpace(e)
				if e == "explicit" {
					meta.Explicit = true
				}
				if gv, ok := strings.CutPrefix(e, "go "); ok {
					meta.GoVersion = gv
				}
			}
			continue
		}
		if f := strings.Fields(line); len(f) == 1 && module.CheckImportPath(f[0]) == nil {
			vl.pkgMod[f[0]] = mod
			vl.pkgs[mod] = append(vl.pkgs[mod], f[0])
			if v, ok := vl.version[mod.Path]; !ok || semver.Compare(v, mod.Version) < 0 {
				vl.list = append(vl.list, mod)
				vl.version[mod.Path] = mod.Version
			}
		}
	}
	return vl
}

func (vl *vendorList) metaOf(m module.Version) vendorMeta {
	if x := vl.meta[m]; x != nil {
		return *x
	}
	return vendorMeta{}
}

type vendorCheck struct {
	c       *cli.Context
	p       *project.Project
	res     *VendorResult
	vdir    string // absolute vendor dir
	vl      *vendorList
	mainGo  string
	offline bool
}

func runVendor(c *cli.Context) error {
	failOn, err := vendorFlags.failOn()
	if err != nil {
		return err
	}
	if len(c.Args) > 0 {
		return cli.Usagef("vendor takes no arguments")
	}
	p, err := c.Project()
	if err != nil {
		return err
	}
	if p.IsWorkspace() {
		return cli.Usagef("workspace vendoring ('go work vendor') is not supported; run with GOWORK=off to check a single module")
	}
	vc := &vendorCheck{c: c, p: p, offline: *vendorFlags.offlineOnly, vdir: filepath.Join(p.ModDir, "vendor"),
		res: &VendorResult{Main: p.ModulePath(), Consistent: true, GoErrors: []string{}, Modules: []*VendoredModule{},
			Files: []VendorFile{}, Stray: []string{}, Findings: []report.Finding{}}}
	vc.mainGo = "1.16" // the go command's default for a go.mod without a go line
	if p.GoMod != nil && p.GoMod.Go != "" {
		vc.mainGo = p.GoMod.Go
	}
	vc.res.GoVersion = vc.mainGo
	if err := vc.run(); err != nil {
		return err
	}
	res := vc.res
	report.SortFindings(res.Findings)
	res.Summary = sevCounts(res.Findings)
	res.Failing = len(report.AtLeast(res.Findings, failOn))
	c.SetResult(res)
	if res.Failing > 0 {
		c.Issues()
	}
	if c.Text() {
		printVendor(c, res, failOn)
	}
	return nil
}

func (vc *vendorCheck) add(f report.Finding) { vc.res.Findings = append(vc.res.Findings, f) }

func (vc *vendorCheck) run() error {
	fi, err := os.Stat(vc.vdir)
	if err != nil || !fi.IsDir() {
		vc.add(report.Finding{Severity: report.Info, Rule: "vendor-absent", Title: "no vendor directory",
			Detail: "modules are downloaded from GOPROXY at build time; nothing to verify"})
		return nil
	}
	vc.res.Present = true
	mtPath := filepath.Join(vc.vdir, "modules.txt")
	data, err := os.ReadFile(mtPath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		vc.add(report.Finding{Severity: report.High, Rule: "vendor-modules-txt-missing", File: "vendor/modules.txt",
			Title:  "vendor/ exists but vendor/modules.txt is missing",
			Detail: "the go command cannot use a vendor directory without modules.txt", Fix: "go mod vendor"})
	}
	if _, errs := modfile.ParseVendorModules(data); len(errs) > 0 {
		for _, e := range errs {
			vc.add(report.Finding{Severity: report.Low, Rule: "vendor-modules-txt-syntax", File: "vendor/modules.txt",
				Title: "unreadable line in vendor/modules.txt (ignored by the go command)", Detail: e.Error()})
		}
	}
	vc.vl = readVendorList(data)
	vc.buildModules()
	vc.consistency()
	vc.goVersionsAndStaleness()
	vc.disk()
	vc.res.Consistent = len(vc.res.GoErrors) == 0
	return nil
}

// buildModules fills res.Modules from modules.txt.
func (vc *vendorCheck) buildModules() {
	vl := vc.vl
	for _, m := range vl.order {
		if m.Version == "" {
			continue // wildcard replacement line
		}
		meta := vl.metaOf(m)
		vm := &VendoredModule{Path: m.Path, Version: m.Version, Explicit: meta.Explicit, GoVersion: meta.GoVersion,
			Packages: append([]string{}, vl.pkgs[m]...), line: vl.line[m], mod: m, repl: meta.Replacement}
		sort.Strings(vm.Packages)
		if meta.Replacement.Path != "" {
			vm.Replace = meta.Replacement.Path
			if meta.Replacement.Version != "" {
				vm.Replace += " " + meta.Replacement.Version
			}
		}
		if len(vm.Packages) == 0 {
			vm.Status = "no packages"
		}
		vc.res.Modules = append(vc.res.Modules, vm)
	}
}

func describeMod(m module.Version) string {
	if m.Version == "" {
		return m.Path
	}
	return m.Path + "@" + m.Version
}

// consistency mirrors cmd/go/internal/modload.checkVendorConsistency.
func (vc *vendorCheck) consistency() {
	vl, gm := vc.vl, vc.p.GoMod
	if gm == nil {
		return
	}
	pre114 := modgraph.CompareGo(vc.mainGo, "1.14") < 0
	goErr := func(mod module.Version, sev report.Severity, rule string, line int, title, msg, fix string) {
		full := describeMod(mod) + ": " + msg
		vc.res.GoErrors = append(vc.res.GoErrors, full)
		f := report.Finding{Severity: sev, Rule: rule, Module: mod.Path, Version: mod.Version, Title: title,
			Detail: "go: inconsistent vendoring: " + full, Fix: fix}
		if line > 0 {
			f.File, f.Line = goModRel(vc.c), line
		}
		vc.add(f)
	}
	required := map[module.Version]bool{}
	for _, r := range gm.Require {
		required[r.Mod] = true
		if vl.metaOf(r.Mod).Explicit {
			continue
		}
		if pre114 {
			if vv, ok := vl.version[r.Mod.Path]; ok && vv != r.Mod.Version {
				goErr(r.Mod, report.High, "vendor-version-mismatch", r.Line,
					fmt.Sprintf("go.mod requires %s but %s is vendored", r.Mod.Version, vv),
					fmt.Sprintf("is explicitly required in go.mod, but vendor/modules.txt indicates %s@%s", r.Mod.Path, vv), "go mod vendor")
			}
			continue
		}
		msg := "is explicitly required in go.mod, but not marked as explicit in vendor/modules.txt"
		other := ""
		for _, m := range vl.order {
			if m.Path == r.Mod.Path && m.Version != "" && m.Version != r.Mod.Version {
				other = m.Version
			}
		}
		switch {
		case vl.meta[r.Mod] != nil || vl.pkgs[r.Mod] != nil || vl.line[r.Mod] > 0:
			goErr(r.Mod, report.High, "vendor-not-explicit", r.Line, "required module not marked \"## explicit\" in vendor/modules.txt", msg, "go mod vendor")
		case other != "":
			goErr(r.Mod, report.High, "vendor-version-mismatch", r.Line,
				fmt.Sprintf("go.mod requires %s but vendor/modules.txt has %s", r.Mod.Version, other), msg, "go mod vendor")
		default:
			goErr(r.Mod, report.High, "vendor-module-missing", r.Line, "required module is not in vendor/modules.txt", msg, "go mod vendor")
		}
	}

	mainPath := vc.p.ModulePath()
	replacement := func(m module.Version) (module.Version, *modfile.Replace) {
		if m.Path == mainPath {
			return module.Version{}, nil
		}
		if r := gm.FindReplace(m); r != nil {
			return r.New, r
		}
		return module.Version{}, nil
	}
	seen := map[module.Version]bool{}
	for _, r := range gm.Replace {
		if seen[r.Old] {
			continue
		}
		seen[r.Old] = true
		rNew, _ := replacement(r.Old)
		vr := vl.metaOf(r.Old).Replacement
		if vr == (module.Version{}) {
			if rNew == (module.Version{}) {
				continue
			}
			if pre114 && (r.Old.Version == "" || vl.version[r.Old.Path] != r.Old.Version) {
				continue
			}
			goErr(r.Old, report.High, "vendor-replace-missing", r.Line, "replacement not recorded in vendor/modules.txt",
				"is replaced in go.mod, but not marked as replaced in vendor/modules.txt", "go mod vendor")
		} else if vr != rNew {
			goErr(r.Old, report.High, "vendor-replace-mismatch", r.Line,
				fmt.Sprintf("go.mod replaces with %s but vendor/modules.txt with %s", describeMod(rNew), describeMod(vr)),
				fmt.Sprintf("is replaced by %s in go.mod, but marked as replaced by %s in vendor/modules.txt", describeMod(rNew), describeMod(vr)), "go mod vendor")
		}
	}
	for _, m := range vl.list {
		if vl.metaOf(m).Explicit && !required[m] {
			goErr(m, report.High, "vendor-explicit-not-required", 0, "vendor/modules.txt marks a module explicit that go.mod does not require",
				"is marked as explicit in vendor/modules.txt, but not explicitly required in go.mod", "go mod vendor")
		}
	}
	for _, m := range vl.replaced {
		if r, _ := replacement(m); r == (module.Version{}) {
			goErr(m, report.High, "vendor-replace-extra", 0, "vendor/modules.txt records a replacement that go.mod does not have",
				"is marked as replaced in vendor/modules.txt, but not replaced in go.mod", "go mod vendor")
		}
	}
	// Point findings without a go.mod line at modules.txt.
	for i := range vc.res.Findings {
		f := &vc.res.Findings[i]
		if f.File == "" && strings.HasPrefix(f.Rule, "vendor-") && f.Module != "" {
			if l := vl.line[module.Version{Path: f.Module, Version: f.Version}]; l > 0 {
				f.File, f.Line = "vendor/modules.txt", l
			}
		}
	}
}

// goVersionsAndStaleness checks "## go" annotations against the vendored
// modules' go.mod files and versions against the build list.
func (vc *vendorCheck) goVersionsAndStaleness() {
	if vc.offline || len(vc.res.Modules) == 0 {
		return
	}
	c := vc.c
	if modgraph.CompareGo(vc.mainGo, "1.17") >= 0 {
		var mods []*VendoredModule
		for _, m := range vc.res.Modules {
			if m.Explicit || len(m.Packages) > 0 {
				mods = append(mods, m)
			}
		}
		gvs, errs := par.Map(c.Ctx, 8, mods, func(ctx context.Context, m *VendoredModule) (string, error) {
			var data []byte
			var err error
			switch {
			case m.repl.Path != "" && m.repl.Version == "":
				dir := m.repl.Path
				if !filepath.IsAbs(dir) {
					dir = filepath.Join(vc.p.ModDir, dir)
				}
				data, err = os.ReadFile(filepath.Join(dir, "go.mod"))
			case m.repl.Path != "":
				data, err = c.Proxy().GoMod(ctx, m.repl.Path, m.repl.Version)
			default:
				data, err = c.Proxy().GoMod(ctx, m.Path, m.Version)
			}
			if err != nil {
				return "", err
			}
			return modfile.Parse("go.mod", data).Go, nil
		})
		for i, m := range mods {
			if errs[i] != nil {
				c.Warnf("go.mod of %s: %v", describeMod(m.mod), errs[i])
				continue
			}
			if gvs[i] != m.GoVersion {
				want, got := "go "+gvs[i], "go "+m.GoVersion
				if gvs[i] == "" {
					want = "no go annotation"
				}
				if m.GoVersion == "" {
					got = "none"
				}
				vc.add(report.Finding{Severity: report.Medium, Rule: "vendor-go-version", Module: m.Path, Version: m.Version,
					File: "vendor/modules.txt", Line: m.line,
					Title:  fmt.Sprintf("\"## go\" annotation is %s, the module's go.mod says %s", got, want),
					Detail: "the go command compiles vendored packages with the language version from modules.txt",
					Fix:    "go mod vendor"})
			}
		}
	}
	g, err := c.Graph()
	if err != nil {
		c.Warnf("build list unavailable, vendored versions not compared with it: %v", err)
		return
	}
	for _, m := range vc.vl.list {
		sel := g.Version(m.Path)
		if sel == "" || sel == m.Version {
			continue
		}
		vc.add(report.Finding{Severity: report.Medium, Rule: "vendor-stale", Module: m.Path, Version: m.Version,
			File: "vendor/modules.txt", Line: vc.vl.line[m],
			Title:  fmt.Sprintf("vendored at %s but the build list selects %s", m.Version, sel),
			Detail: "the vendored code is not what go.mod resolves to", Fix: "go mod vendor"})
	}
}

// vendorEntry is a file on disk under vendor/.
type vendorEntry struct {
	rel string // relative to vendor/, slash-separated
	dir string
}

func (vc *vendorCheck) disk() {
	vl := vc.vl
	// Packages missing on disk.
	missingPkg := map[string]bool{}
	var pkgs []string
	for p := range vl.pkgMod {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	for _, p := range pkgs {
		fi, err := os.Stat(filepath.Join(vc.vdir, filepath.FromSlash(p)))
		if err != nil || !fi.IsDir() {
			missingPkg[p] = true
			m := vl.pkgMod[p]
			vc.add(report.Finding{Severity: report.High, Rule: "vendor-package-missing", Module: m.Path, Version: m.Version,
				Package: p, File: "vendor/" + p, Title: "package listed in vendor/modules.txt is missing from vendor/",
				Detail: "builds with -mod=vendor that import it fail", Fix: "go mod vendor"})
		}
	}
	// Files on disk, attributed to modules.
	var entries []vendorEntry
	filepath.WalkDir(vc.vdir, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(vc.vdir, p)
		rel = filepath.ToSlash(rel)
		if rel == "modules.txt" {
			return nil
		}
		entries = append(entries, vendorEntry{rel: rel, dir: path.Dir(rel)})
		return nil
	})
	byMod := map[module.Version][]string{}
	strayDirs := map[string][]string{}
	for _, e := range entries {
		owner, ok := vc.owner(e.dir)
		if !ok {
			strayDirs[e.dir] = append(strayDirs[e.dir], e.rel)
			continue
		}
		byMod[owner] = append(byMod[owner], e.rel)
	}
	vc.reportStray(strayDirs)

	var todo []*VendoredModule
	for _, m := range vc.res.Modules {
		m.Files = len(byMod[m.mod])
		if len(m.Packages) == 0 {
			continue
		}
		switch {
		case m.repl.Path != "" && m.repl.Version == "":
			m.Status, m.Note = "skipped", "local replacement "+m.repl.Path+" (not compared)"
		case vc.offline:
			m.Status, m.Note = "skipped", "--offline-only"
		default:
			todo = append(todo, m)
		}
	}
	type outcome struct {
		files    []VendorFile
		findings []report.Finding
		note     string
	}
	outs, errs := par.Map(vc.c.Ctx, 8, todo, func(ctx context.Context, m *VendoredModule) (*outcome, error) {
		zpath, zver := m.Path, m.Version
		if m.repl.Path != "" {
			zpath, zver = m.repl.Path, m.repl.Version
		}
		data, err := vc.c.Proxy().Zip(ctx, zpath, zver)
		if err != nil {
			return nil, err
		}
		z, err := modzip.Open(data, zpath, zver)
		if err != nil {
			return nil, err
		}
		o := &outcome{}
		if h, err := modzip.HashZip(data); err == nil {
			want := ""
			if vc.p.GoSum != nil {
				want = vc.p.GoSum.Hash(zpath, zver)
			}
			switch {
			case want == "":
				o.findings = append(o.findings, report.Finding{Severity: report.Low, Rule: "vendor-sum-missing", Module: m.Path, Version: m.Version,
					Title:  "go.sum has no hash for " + describeMod(module.Version{Path: zpath, Version: zver}),
					Detail: "the module zip used as the reference could not be checked against go.sum", Fix: "go mod tidy"})
			case want != h:
				o.findings = append(o.findings, report.Finding{Severity: report.Critical, Rule: "vendor-sum-mismatch", Module: m.Path, Version: m.Version,
					File:   "go.sum",
					Title:  "module zip from the proxy does not match go.sum",
					Detail: fmt.Sprintf("go.sum %s, downloaded %s; the comparison below used unverified content", want, h)})
				o.note = "zip does not match go.sum"
			}
		}
		o.files, o.findings = vc.compare(m, z, byMod[m.mod], missingPkg, o.findings)
		return o, nil
	})
	for i, m := range todo {
		if errs[i] != nil {
			m.Status, m.Note = "error", errs[i].Error()
			vc.c.Warnf("%s: module zip unavailable: %v", describeMod(m.mod), errs[i])
			vc.add(report.Finding{Severity: report.Low, Rule: "vendor-unverified", Module: m.Path, Version: m.Version,
				Title: "vendored files not verified: module zip unavailable", Detail: errs[i].Error()})
			continue
		}
		o := outs[i]
		vc.res.Verified++
		m.Note = o.note
		for _, f := range o.files {
			switch f.Status {
			case "modified":
				m.Modified++
			case "added":
				m.Added++
			case "missing":
				m.Missing++
			}
		}
		m.Status = "ok"
		if m.Modified+m.Added+m.Missing > 0 {
			m.Status = "tampered"
		}
		vc.res.Files = append(vc.res.Files, o.files...)
		vc.res.Findings = append(vc.res.Findings, o.findings...)
	}
	sort.Slice(vc.res.Files, func(i, j int) bool { return vc.res.Files[i].Path < vc.res.Files[j].Path })
}

// owner returns the module whose vendored tree contains dir (relative to
// vendor/): the module of the package dir itself, else the listed module
// with the longest path containing it.
func (vc *vendorCheck) owner(dir string) (module.Version, bool) {
	if m, ok := vc.vl.pkgMod[dir]; ok {
		return m, true
	}
	var best module.Version
	for _, m := range vc.vl.list {
		if (dir == m.Path || strings.HasPrefix(dir, m.Path+"/")) && len(m.Path) > len(best.Path) {
			best = m
		}
	}
	return best, best.Path != ""
}

func (vc *vendorCheck) reportStray(dirs map[string][]string) {
	var names []string
	for d := range dirs {
		names = append(names, d)
	}
	sort.Strings(names)
	for _, d := range names {
		files := dirs[d]
		sort.Strings(files)
		hasGo := false
		for i, f := range files {
			files[i] = "vendor/" + f
			vc.res.Stray = append(vc.res.Stray, files[i])
			if strings.HasSuffix(f, ".go") {
				hasGo = true
			}
		}
		sev := report.Low
		if hasGo {
			sev = report.Medium
		}
		disp := "vendor/" + d
		if d == "." {
			disp = "vendor"
		}
		vc.add(report.Finding{Severity: sev, Rule: "vendor-stray", File: disp,
			Title:  fmt.Sprintf("%s in a directory that belongs to no module in vendor/modules.txt", ui.Plural(len(files), "file", "files")),
			Detail: strings.Join(files, ", "), Fix: "go mod vendor (it rewrites vendor/ from scratch)"})
	}
}

// compare checks the files on disk of one module against its zip.
func (vc *vendorCheck) compare(m *VendoredModule, z *modzip.Zip, onDisk []string, missingPkg map[string]bool, finds []report.Finding) ([]VendorFile, []report.Finding) {
	expected, absent := expectedVendorFiles(z, m.Path, m.Packages, vc.mainGo)
	for _, p := range absent {
		finds = append(finds, report.Finding{Severity: report.Medium, Rule: "vendor-package-not-in-module", Module: m.Path, Version: m.Version,
			Package: p, File: "vendor/modules.txt", Line: m.line,
			Title: "vendor/modules.txt lists a package the module does not contain"})
	}
	var out []VendorFile
	addFile := func(rel, status string, sev report.Severity, title, detail string) {
		vp := "vendor/" + m.Path + "/" + rel
		out = append(out, VendorFile{Path: vp, Module: m.Path, Version: m.Version, Status: status})
		finds = append(finds, report.Finding{Severity: sev, Rule: "vendor-file-" + status, Module: m.Path, Version: m.Version,
			File: vp, Title: title, Detail: detail, Fix: "go mod vendor"})
	}
	have := map[string]bool{}
	sort.Strings(onDisk)
	for _, vrel := range onDisk {
		rel := strings.TrimPrefix(vrel, m.Path+"/")
		have[rel] = true
		if !z.Has(rel) {
			sev := report.Medium
			if strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, ".s") || strings.HasSuffix(rel, ".c") {
				sev = report.High
			}
			addFile(rel, "added", sev, "file not in the module zip (hand-added)", "")
			continue
		}
		disk, err := os.ReadFile(filepath.Join(vc.vdir, filepath.FromSlash(vrel)))
		if err != nil {
			continue
		}
		orig, err := z.ReadFile(rel)
		if err != nil {
			continue
		}
		if !bytes.Equal(disk, orig) {
			addFile(rel, "modified", report.High, "vendored file differs from the module zip (hand-edited)", diffSummary(orig, disk))
			continue
		}
		if !expected[rel] {
			addFile(rel, "extra", report.Info, "file from the module zip that go mod vendor does not copy", "")
		}
	}
	var exp []string
	for rel := range expected {
		exp = append(exp, rel)
	}
	sort.Strings(exp)
	for _, rel := range exp {
		if have[rel] {
			continue
		}
		dir := path.Dir(rel)
		pkg := m.Path
		if dir != "." {
			pkg += "/" + dir
		}
		if missingPkg[pkg] {
			continue // reported once for the package
		}
		sev := report.Medium
		if strings.HasSuffix(rel, ".go") {
			sev = report.High
		}
		addFile(rel, "missing", sev, "file go mod vendor would copy is missing", "")
	}
	return out, finds
}

// diffSummary describes where two versions of a file first differ.
func diffSummary(orig, disk []byte) string {
	ol, dl := bytes.Split(orig, []byte("\n")), bytes.Split(disk, []byte("\n"))
	for i := 0; i < len(ol) || i < len(dl); i++ {
		var a, b []byte
		if i < len(ol) {
			a = ol[i]
		}
		if i < len(dl) {
			b = dl[i]
		}
		if !bytes.Equal(a, b) || (i >= len(ol)) != (i >= len(dl)) {
			return fmt.Sprintf("first difference at line %d (%d → %d bytes)", i+1, len(orig), len(disk))
		}
	}
	return fmt.Sprintf("%d → %d bytes", len(orig), len(disk))
}

// expectedVendorFiles returns the module-relative files that `go mod
// vendor` copies for the given packages (cmd/go/internal/modcmd/vendor.go):
// the package directory's files except tests, "ignore"-tagged Go files and
// (go >= 1.17) go.mod/go.sum; embedded files; and metadata files (LICENSE,
// NOTICE, ...) of every parent directory up to the module root. absent
// lists packages with no files in the zip.
func expectedVendorFiles(z modSource, modPath string, pkgs []string, mainGo string) (map[string]bool, []string) {
	byDir := map[string][]string{}
	for _, f := range z.Files() {
		d := path.Dir(f)
		byDir[d] = append(byDir[d], f)
	}
	strip117 := modgraph.CompareGo(mainGo, "1.17") >= 0
	testEmbeds := modgraph.CompareGo(mainGo, "1.22") < 0
	exp := map[string]bool{}
	var absent []string
	for _, pkg := range pkgs {
		dir := "."
		if pkg != modPath {
			if !strings.HasPrefix(pkg, modPath+"/") {
				absent = append(absent, pkg)
				continue
			}
			dir = strings.TrimPrefix(pkg, modPath+"/")
		}
		files := byDir[dir]
		if len(files) == 0 {
			absent = append(absent, pkg)
			continue
		}
		var patterns []string
		haveGo := false
		for _, f := range files {
			name := path.Base(f)
			isGo := strings.HasSuffix(name, ".go")
			var content []byte
			if isGo {
				haveGo = true
				content, _ = z.ReadFile(f)
				if !strings.HasSuffix(name, "_test.go") || testEmbeds {
					patterns = append(patterns, embedPatterns(content)...)
				}
			}
			switch {
			case strings.HasSuffix(name, "_test.go"):
			case strip117 && (name == "go.mod" || name == "go.sum"):
			case isGo && !shouldBuildAnyTags(content):
			default:
				exp[f] = true
			}
		}
		if haveGo {
			for _, f := range resolveEmbeds(z.Files(), dir, patterns) {
				exp[f] = true
			}
		}
		// Metadata of parent directories, up to the module root.
		for d := dir; d != "."; {
			d = path.Dir(d)
			for _, f := range byDir[d] {
				if isMetadataFile(path.Base(f)) {
					exp[f] = true
				}
			}
		}
	}
	return exp, absent
}

var metaPrefixes = []string{"AUTHORS", "CONTRIBUTORS", "COPYLEFT", "COPYING", "COPYRIGHT", "LEGAL", "LICENSE", "NOTICE", "PATENTS"}

func isMetadataFile(name string) bool {
	for _, p := range metaPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// shouldBuildAnyTags reports whether a Go file can be part of some build:
// everything except files whose constraint needs the "ignore" tag
// (cmd/go/internal/imports.ShouldBuild with AnyTags).
func shouldBuildAnyTags(content []byte) bool {
	header, goBuild, ok := goFileHeader(content)
	if !ok {
		return false
	}
	if goBuild != "" {
		x, err := constraint.Parse(goBuild)
		if err != nil {
			return false
		}
		return evalAnyTags(x, true)
	}
	for _, line := range strings.Split(header, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "//") || !strings.Contains(line, "+build") || !constraint.IsPlusBuild(line) {
			continue
		}
		if x, err := constraint.Parse(line); err == nil && !evalAnyTags(x, true) {
			return false
		}
	}
	return true
}

func evalAnyTags(x constraint.Expr, prefer bool) bool {
	switch x := x.(type) {
	case *constraint.TagExpr:
		for _, c := range x.Tag {
			if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '_' && c != '.' {
				return false
			}
		}
		if x.Tag != "" && x.Tag != "ignore" {
			return prefer
		}
		return false
	case *constraint.NotExpr:
		return !evalAnyTags(x.X, !prefer)
	case *constraint.AndExpr:
		return evalAnyTags(x.X, prefer) && evalAnyTags(x.Y, prefer)
	case *constraint.OrExpr:
		return evalAnyTags(x.X, prefer) || evalAnyTags(x.Y, prefer)
	}
	return false
}

// goFileHeader returns the leading comment block where +build lines may
// appear, and the //go:build line (cmd/go/internal/imports.parseFileHeader).
func goFileHeader(content []byte) (header, goBuild string, ok bool) {
	end := 0
	p := content
	ended, inSlashStar := false, false
Lines:
	for len(p) > 0 {
		line := p
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			line, p = line[:i], p[i+1:]
		} else {
			p = p[len(p):]
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 && !ended {
			end = len(content) - len(p)
			continue
		}
		if !bytes.HasPrefix(line, []byte("//")) {
			ended = true
		}
		if !inSlashStar && isGoBuildLine(line) {
			if goBuild != "" {
				return "", "", false
			}
			goBuild = string(line)
		}
	Comments:
		for len(line) > 0 {
			if inSlashStar {
				if i := bytes.Index(line, []byte("*/")); i >= 0 {
					inSlashStar = false
					line = bytes.TrimSpace(line[i+2:])
					continue Comments
				}
				continue Lines
			}
			if bytes.HasPrefix(line, []byte("//")) {
				continue Lines
			}
			if bytes.HasPrefix(line, []byte("/*")) {
				inSlashStar = true
				line = bytes.TrimSpace(line[2:])
				continue Comments
			}
			break Lines
		}
	}
	return string(content[:end]), goBuild, true
}

func isGoBuildLine(line []byte) bool {
	if !bytes.HasPrefix(line, []byte("//go:build")) {
		return false
	}
	rest := line[len("//go:build"):]
	return len(rest) == 0 || len(bytes.TrimSpace(rest)) < len(rest)
}

// embedPatterns returns the //go:embed patterns of a Go file that imports
// "embed" (go/build only records them then).
func embedPatterns(src []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, parser.ImportsOnly)
	if err != nil {
		return nil
	}
	imports := false
	for _, im := range f.Imports {
		if p, _ := strconv.Unquote(im.Path.Value); p == "embed" {
			imports = true
		}
	}
	if !imports {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(src), "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "//go:embed")
		if !ok || rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
			continue
		}
		out = append(out, splitEmbedArgs(strings.TrimSpace(rest))...)
	}
	return out
}

func splitEmbedArgs(s string) []string {
	var out []string
	for s = strings.TrimSpace(s); s != ""; s = strings.TrimSpace(s) {
		switch s[0] {
		case '"', '`':
			q := s[0]
			i := 1
			for i < len(s) && s[i] != q {
				if q == '"' && s[i] == '\\' {
					i++
				}
				i++
			}
			if i >= len(s) {
				return out
			}
			if v, err := strconv.Unquote(s[:i+1]); err == nil {
				out = append(out, v)
			}
			s = s[i+1:]
		default:
			i := strings.IndexAny(s, " \t")
			if i < 0 {
				i = len(s)
			}
			out = append(out, s[:i])
			s = s[i:]
		}
	}
	return out
}

// resolveEmbeds expands //go:embed patterns of the package in dir against
// the module's files: matching files, and the files under matching
// directories except those with a path element starting with "." or "_"
// (unless the pattern has the "all:" prefix).
func resolveEmbeds(files []string, dir string, patterns []string) []string {
	prefix := ""
	if dir != "." {
		prefix = dir + "/"
	}
	var rels []string
	dirs := map[string]bool{}
	for _, f := range files {
		if !strings.HasPrefix(f, prefix) {
			continue
		}
		rel := strings.TrimPrefix(f, prefix)
		rels = append(rels, rel)
		for d := path.Dir(rel); d != "."; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	out := map[string]bool{}
	for _, pat := range patterns {
		all := false
		if p, ok := strings.CutPrefix(pat, "all:"); ok {
			pat, all = p, true
		}
		for _, rel := range rels {
			if ok, _ := path.Match(pat, rel); ok {
				out[prefix+rel] = true
			}
		}
		for d := range dirs {
			if ok, _ := path.Match(pat, d); !ok {
				continue
			}
			for _, rel := range rels {
				sub, ok := strings.CutPrefix(rel, d+"/")
				if !ok {
					continue
				}
				if !all && hiddenElem(sub) {
					continue
				}
				out[prefix+rel] = true
			}
		}
	}
	var list []string
	for f := range out {
		list = append(list, f)
	}
	sort.Strings(list)
	return list
}

func hiddenElem(rel string) bool {
	for _, e := range strings.Split(rel, "/") {
		if strings.HasPrefix(e, ".") || strings.HasPrefix(e, "_") {
			return true
		}
	}
	return false
}

func printVendor(c *cli.Context, res *VendorResult, failOn report.Severity) {
	o := c.Out
	subject := res.Main
	if subject == "" {
		subject = "."
	}
	o.Title("sm-go vendor · " + subject)
	if !res.Present {
		o.OK("no vendor directory: modules come from GOPROXY at build time")
		return
	}
	npk := 0
	for _, m := range res.Modules {
		npk += len(m.Packages)
	}
	o.Printf("vendor/modules.txt: %s, %s · go %s · %d verified against module zips\n",
		ui.Plural(len(res.Modules), "module", "modules"), ui.Plural(npk, "package", "packages"), res.GoVersion, res.Verified)
	if len(res.Modules) > 0 {
		var rows [][]string
		for _, m := range res.Modules {
			st := m.Status
			switch m.Status {
			case "ok":
				st = o.Green("ok")
			case "tampered":
				st = o.Red(fmt.Sprintf("tampered (%d modified, %d added, %d missing)", m.Modified, m.Added, m.Missing))
			case "error":
				st = o.Yellow("error")
			default:
				st = o.Dim(m.Status)
			}
			ver := m.Version
			if m.Replace != "" {
				ver += o.Dim(" => " + m.Replace)
			}
			rows = append(rows, []string{m.Path, ver, fmt.Sprint(len(m.Packages)), fmt.Sprint(m.Files), st})
		}
		o.Println()
		o.Table([]string{"MODULE", "VERSION", "PKGS", "FILES", "STATUS"}, rows)
	}
	if len(res.GoErrors) > 0 {
		o.Heading("go build -mod=vendor would fail")
		for _, e := range res.GoErrors {
			o.Println("  " + e)
		}
	}
	o.Heading("Findings")
	if len(res.Findings) == 0 {
		o.OK("no issues found")
	} else {
		printFindings(c, res.Findings)
	}
	o.Println()
	if res.Failing > 0 {
		o.Bad("%s at or above %s (%s)", ui.Plural(res.Failing, "finding", "findings"), failOn, countLine(res.Summary))
	} else {
		o.OK("vendor directory verified: no findings at or above %s (%s)", failOn, countLine(res.Summary))
	}
}
