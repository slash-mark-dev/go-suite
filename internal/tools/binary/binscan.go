package binary

import (
	"flag"
	"fmt"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/binfile"
	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/feeds"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/semver"
	"github.com/slash-mark-dev/go-suite/internal/ui"
	"github.com/slash-mark-dev/go-suite/internal/vulndb"
	"github.com/slash-mark-dev/go-suite/internal/vulnscan"
)

var binscanFlags struct {
	failOn  func() (report.Severity, error)
	noVuln  *bool
	showAll *bool
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "binscan",
		Group:   group,
		Summary: "Binary auditor: build info, vulnerabilities and hygiene of compiled Go binaries",
		Usage:   "sm-go binscan <binary|dir>... [flags]",
		Help: `Reads the build information embedded in any compiled Go executable
(ELF, Mach-O or PE, for any GOOS/GOARCH) without its source: the Go
version, main module, every dependency with its version and go.sum hash,
and the build settings (CGO_ENABLED, -trimpath, -ldflags, -tags,
GOOS/GOARCH, vcs.revision, vcs.modified, ...; the go command does not
record -ldflags for -trimpath builds).

The module list and the binary's Go version are checked against the Go
vulnerability database (third-party modules and the standard library).
When the binary carries a symbol table or the Go function table (even
binaries stripped with -ldflags=-s keep the latter), matching is done at
symbol level like govulncheck -mode=binary:

  linked    a vulnerable function is linked into the binary
  package   the vulnerable package is linked, its vulnerable functions are not
            (severity lowered to low; inlined functions cannot be seen)
  module    the module is in the build list but the package is not linked (info)
  platform  the vulnerable code is specific to another GOOS/GOARCH (info)
  unknown   no function table: matched at module level only

Also flags Go versions that are no longer supported upstream (from
go.dev/dl), binaries built from a modified working tree (vcs.modified),
builds without -trimpath (absolute paths of the build machine embedded)
and race-detector builds.

Directories are searched recursively for Go executables.`,
		Examples: []string{
			"sm-go binscan ./bin/server",
			"sm-go binscan dist/ --json",
			"sm-go binscan /usr/local/bin --fail-on high",
			"sm-go binscan app.exe --no-vuln",
		},
		Sources: []string{"Go vulnerability database", "go.dev/dl", "CISA KEV", "FIRST EPSS", "GitHub Advisory Database"},
		Flags: func(fs *flag.FlagSet) {
			binscanFlags.failOn = cli.SeverityFlag(fs, "fail-on", "medium", "exit 1 when a finding has at least this `severity`")
			binscanFlags.noVuln = fs.Bool("no-vuln", false, "skip the vulnerability database and go.dev checks (fully offline)")
			binscanFlags.showAll = fs.Bool("deps", false, "list every dependency in text output (always included in --json)")
		},
		Run: runBinscan,
	})
}

// binModule is one module recorded in a binary.
type binModule struct {
	Path    string     `json:"path"`
	Version string     `json:"version,omitempty"`
	Sum     string     `json:"sum,omitempty"`
	Replace *binModule `json:"replace,omitempty"`
}

type buildSetting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type buildSummary struct {
	CGO         *bool  `json:"cgo,omitempty"`
	Trimpath    bool   `json:"trimpath"`
	LDFlags     string `json:"ldflags,omitempty"`
	Tags        string `json:"tags,omitempty"`
	BuildMode   string `json:"buildmode,omitempty"`
	Race        bool   `json:"race,omitempty"`
	VCS         string `json:"vcs,omitempty"`
	Revision    string `json:"revision,omitempty"`
	Time        string `json:"time,omitempty"`
	Modified    *bool  `json:"modified,omitempty"`
	StrippedSym bool   `json:"strippedSymbols"`
	StrippedDWF bool   `json:"strippedDWARF"`
}

type goSupport struct {
	Version   string   `json:"version"`
	Line      string   `json:"line,omitempty"`
	Supported *bool    `json:"supported,omitempty"`
	Latest    string   `json:"latestPatch,omitempty"`
	Current   []string `json:"supportedLines,omitempty"`
}

// binVuln is a vulnerability matched against one binary.
type binVuln struct {
	ID             string           `json:"id"`
	Summary        string           `json:"summary,omitempty"`
	Aliases        []string         `json:"aliases,omitempty"`
	Module         string           `json:"module"`
	Version        string           `json:"version"`
	FixedIn        string           `json:"fixedIn,omitempty"`
	Packages       []string         `json:"packages,omitempty"`
	Reachability   string           `json:"reachability"`
	LinkedSymbols  []string         `json:"linkedSymbols,omitempty"`
	LinkedPackages []string         `json:"linkedPackages,omitempty"`
	Severity       report.Severity  `json:"severity"`
	BaseSeverity   report.Severity  `json:"baseSeverity"`
	SeveritySource string           `json:"severitySource"`
	KEV            *feeds.KEVEntry  `json:"kev,omitempty"`
	EPSS           *feeds.EPSSScore `json:"epss,omitempty"`
	URL            string           `json:"url"`
}

// Reachability values.
const (
	reachLinked   = "linked"
	reachPackage  = "package"
	reachModule   = "module"
	reachPlatform = "platform"
	reachUnknown  = "unknown"
)

type binReport struct {
	Path         string           `json:"path"`
	Format       string           `json:"format"`
	GOOS         string           `json:"goos"`
	GOARCH       string           `json:"goarch"`
	Size         int64            `json:"size"`
	GoVersion    string           `json:"goVersion"`
	Go           goSupport        `json:"go"`
	Main         binModule        `json:"main"`
	Deps         []binModule      `json:"deps"`
	Settings     []buildSetting   `json:"settings"`
	Build        buildSummary     `json:"build"`
	SymbolSource string           `json:"symbolSource"`
	Functions    int              `json:"functions"`
	Vulns        []*binVuln       `json:"vulns"`
	Findings     []report.Finding `json:"findings"`

	file *binfile.File
}

type binscanResult struct {
	Binaries []*binReport   `json:"binaries"`
	Skipped  []skipped      `json:"skipped,omitempty"`
	Summary  binscanSummary `json:"summary"`
}

type binscanSummary struct {
	Binaries   int            `json:"binaries"`
	Vulns      int            `json:"vulns"`
	Linked     int            `json:"linkedVulns"`
	Findings   int            `json:"findings"`
	BySeverity map[string]int `json:"bySeverity"`
	FailOn     string         `json:"failOn"`
}

func runBinscan(c *cli.Context) error {
	failOn, err := binscanFlags.failOn()
	if err != nil {
		return err
	}
	if len(c.Args) == 0 {
		return cli.Usagef("pass at least one Go binary or directory")
	}
	paths, skip, err := collectBinaries(c, c.Args)
	if err != nil {
		return err
	}
	for _, s := range skip {
		c.Warnf("skipping %s: %s", s.Path, s.Reason)
	}
	if len(paths) == 0 {
		return cli.Usagef("no Go binaries found in %s", strings.Join(c.Args, ", "))
	}
	res := &binscanResult{Skipped: skip}
	for _, p := range paths {
		f, err := binfile.Open(p)
		if err != nil {
			c.Warnf("skipping %s: %v", p, err)
			res.Skipped = append(res.Skipped, skipped{Path: p, Reason: err.Error()})
			continue
		}
		res.Binaries = append(res.Binaries, describeBinary(f))
	}
	if len(res.Binaries) == 0 {
		return cli.Usagef("no readable Go binaries found")
	}
	if !*binscanFlags.noVuln {
		if err := scanVulns(c, res.Binaries); err != nil {
			return err
		}
		checkGoSupport(c, res.Binaries)
	}
	res.Summary.BySeverity = map[string]int{}
	res.Summary.FailOn = failOn.String()
	for _, b := range res.Binaries {
		hygiene(b)
		report.SortFindings(b.Findings)
		res.Summary.Binaries++
		res.Summary.Vulns += len(b.Vulns)
		for _, v := range b.Vulns {
			if v.Reachability == reachLinked || v.Reachability == reachUnknown {
				res.Summary.Linked++
			}
		}
		res.Summary.Findings += len(b.Findings)
		for _, f := range b.Findings {
			res.Summary.BySeverity[f.Severity.String()]++
			if f.Severity.Meets(failOn) {
				c.Issues()
			}
		}
	}
	c.SetResult(res)
	if c.Text() {
		printBinscan(c, res)
	}
	return nil
}

func toBinModule(m *debug.Module) binModule {
	b := binModule{Path: m.Path, Version: m.Version, Sum: m.Sum}
	if m.Replace != nil {
		r := toBinModule(m.Replace)
		b.Replace = &r
	}
	return b
}

func describeBinary(f *binfile.File) *binReport {
	bi := f.BuildInfo
	b := &binReport{Path: f.Path, Format: f.Format, GOOS: f.GOOS, GOARCH: f.GOARCH, Size: f.Size,
		GoVersion: bi.GoVersion, Main: toBinModule(&bi.Main), SymbolSource: f.SymbolSource,
		Functions: len(f.Funcs), Deps: []binModule{}, Settings: []buildSetting{}, Vulns: []*binVuln{},
		Findings: []report.Finding{}, file: f}
	b.Go.Version = bi.GoVersion
	for _, d := range bi.Deps {
		b.Deps = append(b.Deps, toBinModule(d))
	}
	for _, s := range bi.Settings {
		b.Settings = append(b.Settings, buildSetting{s.Key, s.Value})
		switch s.Key {
		case "CGO_ENABLED":
			v := s.Value == "1"
			b.Build.CGO = &v
		case "-trimpath":
			b.Build.Trimpath = s.Value == "true"
		case "-ldflags":
			b.Build.LDFlags = s.Value
		case "-tags":
			b.Build.Tags = s.Value
		case "-buildmode":
			b.Build.BuildMode = s.Value
		case "-race":
			b.Build.Race = s.Value == "true"
		case "vcs":
			b.Build.VCS = s.Value
		case "vcs.revision":
			b.Build.Revision = s.Value
		case "vcs.time":
			b.Build.Time = s.Value
		case "vcs.modified":
			v := s.Value == "true"
			b.Build.Modified = &v
		}
	}
	b.Build.StrippedSym = f.Stripped
	b.Build.StrippedDWF = !f.HasDWARF
	return b
}

// effective returns the module version actually built (the replacement
// when there is one); ok is false for local directory replacements and
// development versions, which cannot be matched against the database.
func (m binModule) effective() (module.Version, bool) {
	path, v := m.Path, m.Version
	if m.Replace != nil {
		path, v = m.Replace.Path, m.Replace.Version
	}
	if v == "" || v == "(devel)" || !semver.IsValid(v) {
		return module.Version{}, false
	}
	return module.Version{Path: path, Version: v}, true
}

func scanVulns(c *cli.Context, bins []*binReport) error {
	var mods []module.Version
	seen := map[module.Version]bool{}
	add := func(m module.Version) {
		if !seen[m] {
			seen[m] = true
			mods = append(mods, m)
		}
	}
	for _, b := range bins {
		if m, ok := b.Main.effective(); ok {
			add(m)
		}
		for _, d := range b.Deps {
			if m, ok := d.effective(); ok {
				add(m)
			}
		}
		if m, ok := vulnscan.StdlibModule(b.GoVersion); ok {
			add(m)
		}
	}
	sort.Slice(mods, func(i, j int) bool {
		if mods[i].Path != mods[j].Path {
			return mods[i].Path < mods[j].Path
		}
		return mods[i].Version < mods[j].Version
	})
	vulns, err := vulnscan.Scan(c.Ctx, c, mods)
	if err != nil {
		return fmt.Errorf("Go vulnerability database: %w", err)
	}
	vulnscan.Enrich(c.Ctx, c, vulns)
	byMod := map[module.Version][]*vulnscan.Vuln{}
	for _, v := range vulns {
		k := module.Version{Path: v.Module, Version: v.Version}
		byMod[k] = append(byMod[k], v)
	}
	for _, b := range bins {
		var ix *binfile.FuncIndex
		if len(b.file.Funcs) > 0 {
			ix = b.file.Index()
		}
		check := func(m module.Version) {
			for _, v := range byMod[m] {
				bv := matchVuln(v, b, ix)
				b.Vulns = append(b.Vulns, bv)
				b.Findings = append(b.Findings, vulnFinding(bv))
			}
		}
		if m, ok := b.Main.effective(); ok {
			check(m)
		}
		for _, d := range b.Deps {
			if m, ok := d.effective(); ok {
				check(m)
			}
		}
		if m, ok := vulnscan.StdlibModule(b.GoVersion); ok {
			check(m)
		}
		sort.SliceStable(b.Vulns, func(i, j int) bool {
			if b.Vulns[i].Severity != b.Vulns[j].Severity {
				return b.Vulns[i].Severity > b.Vulns[j].Severity
			}
			return b.Vulns[i].ID < b.Vulns[j].ID
		})
	}
	return nil
}

func platformOK(list []string, v string) bool {
	if len(list) == 0 {
		return true
	}
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// matchVuln decides how much of a vulnerability is present in a binary.
func matchVuln(v *vulnscan.Vuln, b *binReport, ix *binfile.FuncIndex) *binVuln {
	bv := &binVuln{ID: v.ID, Summary: v.Summary, Aliases: v.Aliases, Module: v.Module, Version: v.Version,
		FixedIn: v.FixedIn, Severity: v.Severity, BaseSeverity: v.Severity, SeveritySource: v.SeveritySource,
		KEV: v.KEV, EPSS: v.EPSS, URL: v.URL}
	var imports []vulndb.Import
	for _, a := range v.Entry.Affected {
		if a.Package.Name == v.Module && a.EcosystemSpecific != nil {
			imports = append(imports, a.EcosystemSpecific.Imports...)
		}
	}
	for _, im := range imports {
		bv.Packages = append(bv.Packages, im.Path)
	}
	switch {
	case ix == nil:
		bv.Reachability = reachUnknown
	case len(imports) == 0:
		// No package data: the whole module is affected.
		bv.Reachability = reachUnknown
		mm := binfile.NewModuleMap(b.file.BuildInfo)
		for _, fn := range b.file.Funcs {
			pkg, _ := binfile.SplitSymbol(fn.Name)
			if mm.Module(pkg) == v.Module || v.Module == vulndb.Stdlib {
				bv.Reachability = reachLinked
				break
			}
		}
	default:
		applicable := false
		pkgLinked := map[string]bool{}
		syms := map[string]bool{}
		for _, im := range imports {
			if !platformOK(im.GOOS, b.GOOS) || !platformOK(im.GOARCH, b.GOARCH) {
				continue
			}
			applicable = true
			if !ix.HasPackage(im.Path) {
				continue
			}
			if len(im.Symbols) == 0 {
				pkgLinked[im.Path] = true
				syms[im.Path] = true
				continue
			}
			pkgLinked[im.Path] = true
			for _, s := range im.Symbols {
				if ix.Has(im.Path, s) {
					syms[im.Path+"."+s] = true
				}
			}
		}
		bv.LinkedPackages = sortedKeys(pkgLinked)
		bv.LinkedSymbols = sortedKeys(syms)
		switch {
		case !applicable:
			bv.Reachability = reachPlatform
		case len(syms) > 0:
			bv.Reachability = reachLinked
		case len(pkgLinked) > 0:
			bv.Reachability = reachPackage
		default:
			bv.Reachability = reachModule
		}
	}
	switch bv.Reachability {
	case reachPackage:
		bv.Severity = min(bv.Severity, report.Low)
	case reachModule, reachPlatform:
		bv.Severity = report.Info
	}
	return bv
}

func vulnFinding(v *binVuln) report.Finding {
	f := report.Finding{Severity: v.Severity, Rule: "vuln", Module: v.Module, Version: v.Version, URL: v.URL,
		Title: v.ID + ": " + v.Summary, Data: map[string]any{"id": v.ID, "reachability": v.Reachability}}
	switch v.Reachability {
	case reachLinked:
		if len(v.LinkedSymbols) > 0 {
			f.Detail = "vulnerable code linked into the binary: " + strings.Join(v.LinkedSymbols, ", ")
		} else {
			f.Detail = "vulnerable module code is linked into the binary"
		}
	case reachPackage:
		f.Detail = "package " + strings.Join(v.LinkedPackages, ", ") + " is linked but none of its vulnerable functions were found (they may have been inlined)"
	case reachModule:
		f.Detail = "module is in the build list but the vulnerable packages are not linked"
	case reachPlatform:
		f.Detail = "vulnerable code is specific to other platforms"
	case reachUnknown:
		f.Detail = "no function table in the binary: matched by module version only"
	}
	if v.FixedIn != "" {
		if v.Module == vulndb.Stdlib {
			f.Fix = "rebuild with Go " + strings.TrimPrefix(v.FixedIn, "v") + " or later"
		} else {
			f.Fix = "upgrade " + v.Module + " to " + v.FixedIn + " and rebuild"
		}
	}
	if v.Module == vulndb.Stdlib {
		f.Module = "stdlib"
	}
	return f
}

// checkGoSupport compares each binary's Go version with the supported
// release lines published on go.dev.
func checkGoSupport(c *cli.Context, bins []*binReport) {
	rels, err := feeds.GoReleases(c.Ctx, c.HTTP(), c.Endpoint("godev"))
	if err != nil || len(rels) == 0 {
		if err == nil {
			err = fmt.Errorf("empty release list")
		}
		c.Warnf("go.dev release list unavailable (%v); Go support status not checked", err)
		return
	}
	lines, latest := feeds.SupportedGo(rels)
	for _, b := range bins {
		sv := vulndb.GoToSemver(b.GoVersion)
		if sv == "" {
			continue
		}
		line := "go" + strings.TrimPrefix(semver.MajorMinor(sv), "v")
		b.Go.Line = line
		b.Go.Current = lines
		supported := false
		for _, l := range lines {
			if l == line {
				supported = true
			}
		}
		b.Go.Supported = &supported
		b.Go.Latest = latest[line]
		if !supported {
			newest := ""
			if len(lines) > 0 {
				newest = latest[lines[0]]
			}
			b.Findings = append(b.Findings, report.Finding{Severity: report.High, Rule: "go-eol",
				Title:  fmt.Sprintf("built with %s, which is no longer supported", b.GoVersion),
				Detail: fmt.Sprintf("supported Go releases: %s; unsupported releases get no security fixes", strings.Join(lines, ", ")),
				Fix:    "rebuild with " + newest, URL: "https://go.dev/doc/devel/release#policy"})
		} else if b.Go.Latest != "" && semver.Compare(sv, vulndb.GoToSemver(b.Go.Latest)) < 0 {
			b.Findings = append(b.Findings, report.Finding{Severity: report.Low, Rule: "go-patch",
				Title: fmt.Sprintf("built with %s; %s is available", b.GoVersion, b.Go.Latest),
				Fix:   "rebuild with " + b.Go.Latest})
		}
	}
}

// hygiene adds build-hygiene findings.
func hygiene(b *binReport) {
	if strings.Contains(b.GoVersion, "devel") || vulndb.GoToSemver(b.GoVersion) == "" {
		b.Findings = append(b.Findings, report.Finding{Severity: report.Info, Rule: "go-devel",
			Title: fmt.Sprintf("built with a development toolchain (%s)", b.GoVersion)})
	}
	if b.Build.Modified != nil && *b.Build.Modified {
		f := report.Finding{Severity: report.Medium, Rule: "vcs-modified",
			Title:  "built from a modified working tree (vcs.modified=true)",
			Detail: "the binary does not correspond to any commit, so it cannot be reproduced or audited from source",
			Fix:    "commit or stash local changes and rebuild"}
		if b.Build.Revision != "" {
			f.Detail = fmt.Sprintf("uncommitted changes on top of %s revision %s: %s", b.Build.VCS, short(b.Build.Revision), f.Detail)
		}
		b.Findings = append(b.Findings, f)
	}
	if !b.Build.Trimpath {
		b.Findings = append(b.Findings, report.Finding{Severity: report.Low, Rule: "no-trimpath",
			Title:  "built without -trimpath",
			Detail: "absolute source paths of the build machine are embedded and the build is not reproducible across machines",
			Fix:    "build with go build -trimpath"})
	}
	if b.Build.Race {
		b.Findings = append(b.Findings, report.Finding{Severity: report.Low, Rule: "race-build",
			Title: "race detector enabled (-race)", Detail: "race builds are 2-20x slower and use 5-10x more memory",
			Fix: "build release binaries without -race"})
	}
	for i := range b.Findings {
		if b.Findings[i].File == "" {
			b.Findings[i].File = b.Path
		}
	}
}

func short(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}

func modString(m binModule) string {
	s := m.Path
	if m.Version != "" {
		s += "@" + m.Version
	}
	if m.Replace != nil {
		s += " => " + m.Replace.Path
		if m.Replace.Version != "" {
			s += "@" + m.Replace.Version
		}
	}
	return s
}

func printBinscan(c *cli.Context, res *binscanResult) {
	p := c.Out
	p.Title(fmt.Sprintf("sm-go binscan — %s", ui.Plural(len(res.Binaries), "binary", "binaries")))
	for _, b := range res.Binaries {
		p.Heading(fmt.Sprintf("%s  (%s %s/%s, %s)", relPath(c, b.Path), b.Format, b.GOOS, b.GOARCH, ui.Bytes(b.Size)))
		goLine := b.GoVersion
		if b.Go.Supported != nil {
			if *b.Go.Supported {
				goLine += " " + p.Green("supported")
				if b.Go.Latest != "" && b.Go.Latest != b.GoVersion {
					goLine += p.Dim(" (latest " + b.Go.Latest + ")")
				}
			} else {
				goLine += " " + p.Red("END OF LIFE")
			}
		}
		build := []string{}
		if b.Build.CGO != nil {
			build = append(build, fmt.Sprintf("CGO_ENABLED=%v", map[bool]int{false: 0, true: 1}[*b.Build.CGO]))
		}
		build = append(build, fmt.Sprintf("-trimpath=%v", b.Build.Trimpath))
		if b.Build.BuildMode != "" {
			build = append(build, "-buildmode="+b.Build.BuildMode)
		}
		if b.Build.Tags != "" {
			build = append(build, "-tags="+b.Build.Tags)
		}
		vcs := "none recorded"
		if b.Build.VCS != "" {
			vcs = b.Build.VCS + " " + short(b.Build.Revision)
			if b.Build.Time != "" {
				vcs += " " + b.Build.Time
			}
			if b.Build.Modified != nil && *b.Build.Modified {
				vcs += " " + p.Yellow("(modified)")
			}
		}
		syms := "none"
		switch b.SymbolSource {
		case binfile.SourceSymtab:
			syms = fmt.Sprintf("symbol table, %d functions", b.Functions)
		case binfile.SourcePclntab:
			syms = fmt.Sprintf("stripped; Go function table, %d functions", b.Functions)
		}
		if b.Build.StrippedDWF {
			syms += ", no DWARF"
		}
		kv := [][2]string{
			{"Go", goLine},
			{"Main module", modString(b.Main)},
			{"Platform", b.GOOS + "/" + b.GOARCH},
			{"Build", strings.Join(build, " · ")},
		}
		if b.Build.LDFlags != "" {
			kv = append(kv, [2]string{"ldflags", b.Build.LDFlags})
		}
		kv = append(kv, [2]string{"VCS", vcs}, [2]string{"Symbols", syms},
			[2]string{"Dependencies", fmt.Sprint(len(b.Deps))})
		p.KV(kv...)
		if len(b.Deps) > 0 && (*binscanFlags.showAll || len(b.Deps) <= 15) {
			var rows [][]string
			for _, d := range b.Deps {
				v := d.Version
				if d.Replace != nil {
					v += " => " + d.Replace.Path + " " + d.Replace.Version
				}
				rows = append(rows, []string{d.Path, v, p.Dim(d.Sum)})
			}
			p.Println()
			p.Table([]string{"MODULE", "VERSION", "SUM"}, rows)
		}
		if len(b.Vulns) > 0 {
			p.Printf("\n  %s\n", p.Bold("Vulnerabilities"))
			var rows [][]string
			for _, v := range b.Vulns {
				where := v.Module + "@" + v.Version
				if v.Module == vulndb.Stdlib {
					where = "stdlib " + b.GoVersion
				}
				fix := v.FixedIn
				if fix == "" {
					fix = "no fix"
				}
				detail := v.Reachability
				if len(v.LinkedSymbols) > 0 {
					detail += ": " + ui.Truncate(strings.Join(v.LinkedSymbols, ", "), 60)
				}
				rows = append(rows, []string{p.Sev(v.Severity), v.ID, where, "fixed " + fix, detail})
			}
			p.Table(nil, rows)
		}
		var other []report.Finding
		for _, f := range b.Findings {
			if f.Rule != "vuln" {
				other = append(other, f)
			}
		}
		if len(other) > 0 {
			p.Printf("\n  %s\n", p.Bold("Build hygiene"))
			for _, f := range other {
				p.Printf("  %s %s\n", p.Sev(f.Severity), f.Title)
				if f.Fix != "" {
					p.Printf("  %s %s\n", strings.Repeat(" ", 8), p.Dim("fix: "+f.Fix))
				}
			}
		}
		if len(b.Vulns) == 0 && len(other) == 0 {
			p.Println()
			p.OK("no known vulnerabilities or hygiene problems")
		}
	}
	p.Println()
	s := res.Summary
	line := fmt.Sprintf("%s · %s (%d linked) · %s",
		ui.Plural(s.Binaries, "binary", "binaries"), ui.Plural(s.Vulns, "vulnerability", "vulnerabilities"), s.Linked,
		ui.Plural(s.Findings, "finding", "findings"))
	if c.HasIssues() {
		p.Bad("%s — findings at or above %s", line, s.FailOn)
	} else {
		p.OK("%s", line)
	}
}
