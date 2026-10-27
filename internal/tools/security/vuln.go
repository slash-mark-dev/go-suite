package security

import (
	"flag"
	"fmt"
	"sort"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/callgraph"
	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/loader"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/semver"
	"github.com/slash-mark-dev/go-suite/internal/ui"
	"github.com/slash-mark-dev/go-suite/internal/vulndb"
	"github.com/slash-mark-dev/go-suite/internal/vulnscan"
)

// Vulnerability statuses.
const (
	StatusCalled   = "called"        // a vulnerable symbol is reachable
	StatusImported = "imported"      // the vulnerable package is imported, no symbol reachable
	StatusRequired = "required-only" // only the module is in the build list
	StatusAffected = "affected"      // module mode: version is affected, reachability not analysed
)

// VulnOptions configures AnalyzeVuln.
type VulnOptions struct {
	Patterns  []string
	Mode      string // "source" (default) or "module"
	Tests     bool
	Tags      []string
	GoVersion string // overrides the go command's version for the stdlib scan
	// MinSeverity drops vulnerabilities below it (default info).
	MinSeverity report.Severity
}

// VulnFinding is one vulnerability with its reachability status.
type VulnFinding struct {
	*vulnscan.Vuln
	Status   string  `json:"status"`
	Symbol   string  `json:"symbol,omitempty"` // first reachable vulnerable symbol ("pkg.F")
	CallPath []Frame `json:"callPath,omitempty"`
	Fix      string  `json:"fix"`
	// ReplacementOf is the original module path when the vulnerable module
	// is a replacement (go.mod replace directive).
	ReplacementOf string `json:"replacementOf,omitempty"`
	// Failing marks vulnerabilities that fail the run under --fail-on.
	Failing bool `json:"failing"`
}

// VulnSummary counts findings.
type VulnSummary struct {
	Total      int            `json:"total"`
	Called     int            `json:"called"`
	Imported   int            `json:"imported"`
	Required   int            `json:"required"`
	Affected   int            `json:"affected"`
	BySeverity map[string]int `json:"bySeverity"` // of called (source mode) or affected (module mode) vulns
	Failing    int            `json:"failing"`
	// BelowThreshold counts vulnerabilities dropped by --min-severity.
	BelowThreshold int `json:"belowThreshold"`
}

// VulnResult is the outcome of AnalyzeVuln.
type VulnResult struct {
	Mode        string         `json:"mode"`
	FailOn      string         `json:"failOn,omitempty"`
	MinSeverity string         `json:"minSeverity"`
	GoVersion   string         `json:"goVersion,omitempty"`
	Modules     int            `json:"modules"`
	Packages    int            `json:"packages,omitempty"`
	Vulns       []*VulnFinding `json:"vulns"`
	Summary     VulnSummary    `json:"summary"`
}

// Fail-on levels: the least reachable status that still fails the run.
var failOnLevels = map[string]int{"called": 0, "imported": 1, "any": 2, "none": -1}

var vulnFlags struct {
	mode, goVer, tags, failOn *string
	tests, showAll            *bool
	minSev                    func() (report.Severity, error)
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "vuln",
		Group:   group,
		Summary: "Reachability vulnerability scan with KEV and EPSS context",
		Usage:   "sm-go vuln [packages] [flags]",
		Help: `Matches the build list and the standard library of your Go version against the Go
vulnerability database (with its symbol data), then type-checks the whole program from source
and builds a call graph to classify each vulnerability:

  called         a vulnerable symbol is reachable from your entry points (main, exported API,
                 package initialization); the shortest call path is shown
  imported       a vulnerable package is imported but no vulnerable symbol is reachable
  required-only  the module is in the build list but no vulnerable package is imported

Severity comes from the GitHub Advisory Database (CVSS), raised to critical for CISA KEV
entries and to at least high for EPSS >= 10%. Vulnerabilities below --min-severity are not
reported. By default only called vulnerabilities fail the run (exit 1); --fail-on imported
or any widens that. Replaced modules are scanned at their replacement version; directory
replacements cannot be matched and are skipped. --mode module skips the reachability
analysis and reports every affecting vulnerability as "affected".`,
		Examples: []string{
			"sm-go vuln",
			"sm-go vuln ./cmd/server --show-all",
			"sm-go vuln --min-severity high --fail-on imported",
			"sm-go vuln --mode module --json",
			"sm-go vuln --go go1.22.0",
		},
		Sources: []string{"Go vulnerability database", "GitHub Advisory Database", "CISA KEV", "FIRST EPSS", "Go module proxy"},
		NeedsGo: true,
		Flags: func(fs *flag.FlagSet) {
			vulnFlags.mode = fs.String("mode", "source", "analysis `mode`: source (reachability) or module (build list only)")
			vulnFlags.showAll = fs.Bool("show-all", false, "also list imported and required-only vulnerabilities")
			vulnFlags.minSev = cli.SeverityFlag(fs, "min-severity", "low", "ignore vulnerabilities below this `severity`")
			vulnFlags.failOn = fs.String("fail-on", "called", "fail (exit 1) on vulnerabilities that are `called`, imported (or called), any, or none")
			vulnFlags.goVer = fs.String("go", "", "scan the standard library of this Go `version` (default: installed go)")
			vulnFlags.tags = fs.String("tags", "", "comma-separated build `tags`")
			vulnFlags.tests = fs.Bool("tests", false, "include test files and test dependencies")
		},
		Run: runVuln,
	})
}

func splitTags(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
}

func runVuln(c *cli.Context) error {
	minSev, err := vulnFlags.minSev()
	if err != nil {
		return err
	}
	level, ok := failOnLevels[*vulnFlags.failOn]
	if !ok {
		return cli.Usagef("--fail-on must be called, imported, any or none")
	}
	opts := VulnOptions{Patterns: c.Args, Mode: *vulnFlags.mode, Tests: *vulnFlags.tests, Tags: splitTags(*vulnFlags.tags),
		GoVersion: *vulnFlags.goVer, MinSeverity: minSev}
	res, err := AnalyzeVuln(c, opts)
	if err != nil {
		return err
	}
	res.FailOn = *vulnFlags.failOn
	for _, v := range res.Vulns {
		if vulnFails(v, level) {
			v.Failing = true
			res.Summary.Failing++
		}
	}
	c.SetResult(res)
	if res.Summary.Failing > 0 {
		c.Issues()
	}
	if c.Text() {
		printVuln(c, res, *vulnFlags.showAll)
	}
	return nil
}

// vulnFails reports whether v fails the run at fail-on level (0 called,
// 1 imported, 2 any, -1 none). Module-mode findings have no reachability
// information and fail at every level but none.
func vulnFails(v *VulnFinding, level int) bool {
	if level < 0 {
		return false
	}
	if v.Status == StatusAffected {
		return true
	}
	return statusRank[v.Status] <= level
}

// AnalyzeVuln scans the project for vulnerabilities and classifies them by
// reachability.
func AnalyzeVuln(c *cli.Context, opts VulnOptions) (*VulnResult, error) {
	if opts.Mode == "" {
		opts.Mode = "source"
	}
	if opts.Mode != "source" && opts.Mode != "module" {
		return nil, cli.Usagef("--mode must be source or module")
	}
	if len(opts.Patterns) == 0 {
		opts.Patterns = []string{"./..."}
	}
	if opts.MinSeverity == report.None {
		opts.MinSeverity = report.Info
	}
	g, err := c.Graph()
	if err != nil {
		return nil, err
	}
	// Scan replaced modules at their replacement; remember the mapping so
	// that vulnerable package paths can be translated back to the import
	// paths the program uses.
	var mods []module.Version
	replacedBy := map[string]string{} // replacement path -> original path
	for _, m := range g.BuildList() {
		if r, ok := g.Replacement[m]; ok {
			if r.Version == "" {
				c.Logf("skipping %s: replaced by directory %s", m, r.Path)
				continue
			}
			if r.Path != m.Path {
				replacedBy[r.Path] = m.Path
			}
			mods = append(mods, r)
			continue
		}
		mods = append(mods, m)
	}
	res := &VulnResult{Mode: opts.Mode, Modules: len(mods), Vulns: []*VulnFinding{}, MinSeverity: opts.MinSeverity.String()}
	goVer := opts.GoVersion
	if goVer == "" {
		goVer = c.Env.GoVersion()
	}
	if goVer != "" {
		if !strings.HasPrefix(goVer, "go") {
			goVer = "go" + goVer
		}
		std, ok := vulnscan.StdlibModule(goVer)
		if !ok {
			if opts.GoVersion != "" {
				return nil, cli.Usagef("--go: %q is not a Go release version", opts.GoVersion)
			}
			c.Warnf("cannot map Go version %q; standard library not scanned", goVer)
		} else {
			res.GoVersion = goVer
			mods = append(mods, std)
		}
	}
	vulns, err := vulnscan.Scan(c.Ctx, c, mods)
	if err != nil {
		return nil, fmt.Errorf("Go vulnerability database: %w", err)
	}
	vulnscan.Enrich(c.Ctx, c, vulns)
	for _, v := range vulns {
		if v.Severity < opts.MinSeverity {
			res.Summary.BelowThreshold++
			continue
		}
		f := &VulnFinding{Vuln: v, Status: StatusAffected, Fix: vulnFix(v)}
		if orig, ok := replacedBy[v.Module]; ok {
			f.ReplacementOf = orig
		}
		res.Vulns = append(res.Vulns, f)
	}
	if opts.Mode == "source" && len(res.Vulns) > 0 {
		prog, cg, err := loadProgram(c, loader.Config{Patterns: opts.Patterns, Tests: opts.Tests, Tags: opts.Tags})
		if err != nil {
			return nil, err
		}
		res.Packages = len(prog.Packages)
		classifyVulns(c, prog, cg, res.Vulns, replacedBy)
	}
	sortVulnFindings(res.Vulns)
	s := &res.Summary
	s.BySeverity = map[string]int{}
	for _, v := range res.Vulns {
		s.Total++
		switch v.Status {
		case StatusCalled:
			s.Called++
			s.BySeverity[v.Severity.String()]++
		case StatusImported:
			s.Imported++
		case StatusRequired:
			s.Required++
		case StatusAffected:
			s.Affected++
			s.BySeverity[v.Severity.String()]++
		}
	}
	return res, nil
}

func isGoModule(path string) bool { return path == vulndb.Stdlib || path == vulndb.Toolchain }

func vulnFix(v *vulnscan.Vuln) string {
	if v.FixedIn == "" {
		return "no fixed version available"
	}
	if isGoModule(v.Module) {
		return "upgrade Go to go" + strings.TrimPrefix(semverToGo(v.FixedIn), "go")
	}
	return "go get " + v.Module + "@" + v.FixedIn
}

// semverToGo converts "v1.21.3" to "go1.21.3" and "v1.22.0-rc.1" to
// "go1.22rc1".
func semverToGo(v string) string {
	v = strings.TrimPrefix(v, "v")
	if i := strings.Index(v, "-"); i >= 0 {
		pre := strings.ReplaceAll(v[i+1:], ".", "")
		v = strings.TrimSuffix(v[:i], ".0") + pre
	}
	return "go" + v
}

func classifyVulns(c *cli.Context, prog *loader.Program, g *callgraph.Graph, vs []*VulnFinding, replacedBy map[string]string) {
	reach := g.Reachable(g.Entrypoints(prog.Roots))
	depth := map[*callgraph.Func]int{}
	for f := range reach.Parent {
		depth[f] = len(reach.Path(f))
	}
	// Reachable functions per package, shortest path first and package
	// initialization last, for vulnerabilities without symbol lists.
	byPkg := map[string][]*callgraph.Func{}
	for f := range reach.Parent {
		byPkg[f.Pkg] = append(byPkg[f.Pkg], f)
	}
	for _, fs := range byPkg {
		sort.Slice(fs, func(i, j int) bool {
			a, b := fs[i], fs[j]
			if a.Init != b.Init {
				return !a.Init
			}
			if depth[a] != depth[b] {
				return depth[a] < depth[b]
			}
			return a.ID < b.ID
		})
	}
	pf := newPosFormatter(c, prog, projectDir(c))
	for _, v := range vs {
		v.Status = StatusRequired
		// importPath maps a vulnerable package path to the import path used
		// by the program (they differ for replaced modules).
		modPath := v.Module
		importPath := func(p string) string { return p }
		if orig, ok := replacedBy[v.Module]; ok {
			modPath = orig
			importPath = func(p string) string { return orig + strings.TrimPrefix(p, v.Module) }
		}
		var best *callgraph.Func
		imported := false
		for _, vpkg := range v.Packages {
			pkg := importPath(vpkg)
			if prog.ByPath[pkg] == nil {
				continue
			}
			imported = true
			syms := v.Symbols[vpkg]
			var cands []*callgraph.Func
			if len(syms) == 0 {
				if fs := byPkg[pkg]; len(fs) > 0 {
					cands = fs[:1]
				}
			} else {
				for _, s := range syms {
					if f := g.Lookup(pkg, s); reach.Has(f) {
						cands = append(cands, f)
					}
				}
			}
			for _, f := range cands {
				if best == nil || depth[f] < depth[best] || (depth[f] == depth[best] && f.ID < best.ID) {
					best = f
				}
			}
		}
		if len(v.Packages) == 0 {
			// No package data: the module counts as imported if any of its
			// packages is.
			for _, p := range prog.Packages {
				if p.ModulePath() == modPath || (v.Module == vulndb.Stdlib && p.Standard) {
					imported = true
					break
				}
			}
		}
		switch {
		case best != nil:
			v.Status = StatusCalled
			v.Symbol = best.ID
			root, edges := fullPath(reach, best)
			v.CallPath = compactFrames(pf.frames(root, edges), 8)
		case imported:
			v.Status = StatusImported
		}
	}
}

var statusRank = map[string]int{StatusCalled: 0, StatusAffected: 0, StatusImported: 1, StatusRequired: 2}

func sortVulnFindings(vs []*VulnFinding) {
	sort.SliceStable(vs, func(i, j int) bool {
		a, b := vs[i], vs[j]
		if statusRank[a.Status] != statusRank[b.Status] {
			return statusRank[a.Status] < statusRank[b.Status]
		}
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		return a.ID < b.ID
	})
}

func vulnModVersion(v *VulnFinding) string {
	if isGoModule(v.Module) {
		return "Go standard library " + semverToGo(v.Version)
	}
	return v.Module + "@" + v.Version
}

func printVuln(c *cli.Context, res *VulnResult, showAll bool) {
	subject := "."
	if p, err := c.Project(); err == nil && p.ModulePath() != "" {
		subject = p.ModulePath()
	}
	o := c.Out
	o.Title("sm-go vuln · " + subject)
	scope := ui.Plural(res.Modules, "module", "modules")
	if res.GoVersion != "" {
		scope += " + standard library " + res.GoVersion
	}
	if res.Mode == "source" {
		if res.Packages > 0 {
			scope += fmt.Sprintf(" · %s · reachability analysis", ui.Plural(res.Packages, "package", "packages"))
		} else {
			scope += " · source mode"
		}
	} else {
		scope += " · module mode (no reachability analysis)"
	}
	o.Printf("%s\n", o.Dim("scanned "+scope))

	var groups []struct {
		title  string
		status string
	}
	if res.Mode == "module" {
		groups = append(groups, struct{ title, status string }{"Affected modules", StatusAffected})
	} else {
		groups = append(groups, struct{ title, status string }{"Called vulnerabilities (reachable from your code)", StatusCalled})
		if showAll {
			groups = append(groups, struct{ title, status string }{"Imported but not called", StatusImported})
			groups = append(groups, struct{ title, status string }{"Required modules only (package not imported)", StatusRequired})
		}
	}
	for _, gr := range groups {
		var in []*VulnFinding
		for _, v := range res.Vulns {
			if v.Status == gr.status {
				in = append(in, v)
			}
		}
		o.Heading(fmt.Sprintf("%s (%d)", gr.title, len(in)))
		if len(in) == 0 {
			o.OK("none")
			continue
		}
		for _, v := range in {
			printOneVuln(c, v)
		}
	}
	s := res.Summary
	if res.Mode == "source" {
		var hidden []string
		if !showAll && s.Imported > 0 {
			hidden = append(hidden, fmt.Sprintf("%d imported", s.Imported))
		}
		if !showAll && s.Required > 0 {
			hidden = append(hidden, fmt.Sprintf("%d required-only", s.Required))
		}
		if len(hidden) > 0 {
			o.Printf("\n%s\n", o.Dim("Not listed: "+strings.Join(hidden, ", ")+" (no vulnerable symbol reachable; use --show-all to list)"))
		}
		if s.BelowThreshold > 0 {
			o.Printf("%s\n", o.Dim(fmt.Sprintf("%d below --min-severity %s not reported", s.BelowThreshold, res.MinSeverity)))
		}
	}
	o.Println()
	if res.Mode == "source" {
		o.Printf("%s %d called (%s) · %d imported · %d required-only\n", o.Bold("Summary:"), s.Called, countLine(s.BySeverity), s.Imported, s.Required)
	} else {
		o.Printf("%s %d affecting vulnerabilities (%s)\n", o.Bold("Summary:"), s.Affected, countLine(s.BySeverity))
	}
	// Fix commands for the failing/reachable set.
	var gets []string
	goFix := ""
	seen := map[string]bool{}
	for _, v := range res.Vulns {
		if !v.Failing && v.Status != StatusCalled && v.Status != StatusAffected {
			continue
		}
		if v.FixedIn == "" {
			continue
		}
		if isGoModule(v.Module) {
			if goFix == "" || compareSemver(v.FixedIn, goFix) > 0 {
				goFix = v.FixedIn
			}
			continue
		}
		key := v.Module
		if !seen[key] {
			seen[key] = true
			gets = append(gets, v.Module+"@"+maxFixed(res.Vulns, v.Module))
		}
	}
	if len(gets) > 0 {
		o.Printf("%s go get %s && go mod tidy\n", o.Bold("Fix:"), strings.Join(gets, " "))
	}
	if goFix != "" {
		o.Printf("%s upgrade Go to %s or later\n", o.Bold("Fix:"), semverToGo(goFix))
	}
}

func maxFixed(vs []*VulnFinding, mod string) string {
	best := ""
	for _, v := range vs {
		if v.Module == mod && v.FixedIn != "" && (best == "" || compareSemver(v.FixedIn, best) > 0) {
			best = v.FixedIn
		}
	}
	return best
}

func compareSemver(a, b string) int { return semver.Compare(a, b) }

func printOneVuln(c *cli.Context, v *VulnFinding) {
	o := c.Out
	var badges []string
	if len(v.CVEs) > 0 {
		badges = append(badges, strings.Join(v.CVEs, ","))
	}
	if v.KEV != nil {
		badges = append(badges, o.Red("[KEV: exploited in the wild]"))
	}
	if v.EPSS != nil {
		badges = append(badges, fmt.Sprintf("[EPSS %.1f%%]", v.EPSS.EPSS*100))
	}
	if v.Failing {
		badges = append(badges, o.Red("[fails --fail-on]"))
	}
	o.Printf("\n  %s %s  %s\n", o.Sev(v.Severity), o.Bold(v.ID), strings.Join(badges, " "))
	fixed := "no fix available"
	if v.FixedIn != "" {
		if isGoModule(v.Module) {
			fixed = "fixed in " + semverToGo(v.FixedIn)
		} else {
			fixed = "fixed in " + v.FixedIn
		}
	}
	ind := "           "
	o.Printf("%s%s → %s\n", ind, vulnModVersion(v), fixed)
	if v.ReplacementOf != "" {
		o.Printf("%s%s\n", ind, o.Dim("replacement for "+v.ReplacementOf))
	}
	if v.Summary != "" {
		o.Printf("%s%s\n", ind, ui.Truncate(v.Summary, 88))
	}
	if len(v.CallPath) > 0 {
		o.Printf("%s%s\n", ind, o.Dim("call path:"))
		printFrames(c, ind+"  ", v.CallPath)
	} else if v.Status == StatusImported {
		o.Printf("%s%s\n", ind, o.Dim("package "+strings.Join(v.Packages, ", ")+" is imported; no vulnerable symbol is reachable"))
	}
	o.Printf("%sfix: %s\n", ind, v.Fix)
	if v.URL != "" {
		o.Printf("%s%s\n", ind, o.Dim(v.URL))
	}
}
