package deps

import (
	"flag"
	"fmt"
	"sort"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/modgraph"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/semver"
)

var majorsFlags struct {
	failOn     func() (report.Severity, error)
	noPackages *bool
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "majors",
		Group:   group,
		Summary: "Major-version split detector: foo, foo/v2, gopkg.in/x.vN side by side",
		Usage:   "sm-go majors [flags]",
		Help: `Finds module families present in more than one major version at once:
example.com/foo together with example.com/foo/v2 or /v3, gopkg.in/yaml.v2
with gopkg.in/yaml.v3, or a +incompatible v2 of the bare path next to the
/v2 module. Each major version is a different module to the go command, so
all of them are selected and can be linked into the same binary: the code
is duplicated, package-level state (registries, flags, metrics) exists
twice and types from one major are not assignable to the other.

For every family the tool shows each major's selected version, which
modules require it, and — from the package import graph (go list, tests
of the main module included) — which packages are actually imported and
by whom.

Severity: medium when two or more majors are imported by non-test code
(both end up in binaries), low when the second major is only imported by
tests, info when only the build list contains several majors (no package
of the extra major is imported).`,
		Examples: []string{
			"sm-go majors",
			"sm-go majors --fail-on low --json",
		},
		Sources: []string{"Go module proxy (go.mod files)", "go list"},
		Flags: func(fs *flag.FlagSet) {
			majorsFlags.failOn = failOnFlag(fs, "medium")
			majorsFlags.noPackages = fs.Bool("no-packages", false, "analyse the build list only (does not run go list)")
		},
		Run: runMajors,
	})
}

type majorPkg struct {
	Package    string   `json:"package"`
	ImportedBy []string `json:"importedBy"`
}

type majorMember struct {
	Path       string     `json:"path"`
	Version    string     `json:"version,omitempty"`
	Major      string     `json:"major"`
	Main       bool       `json:"main,omitempty"`
	RequiredBy []string   `json:"requiredBy"`
	Imported   bool       `json:"imported"`
	InBinaries bool       `json:"importedByNonTestCode"`
	Packages   []majorPkg `json:"packages"`
}

type majorFamily struct {
	Family   string          `json:"family"`
	Majors   []string        `json:"majors"`
	Severity report.Severity `json:"severity"`
	Members  []majorMember   `json:"members"`
}

type majorsResult struct {
	Packages bool             `json:"packagesAnalysed"`
	Families []majorFamily    `json:"families"`
	Findings []report.Finding `json:"findings"`
	Summary  severitySummary  `json:"summary"`
}

// familyOf returns the module path without its major-version suffix.
func familyOf(path string) string {
	prefix, _, ok := module.SplitPathVersion(path)
	if !ok {
		return path
	}
	return prefix
}

// majorLabel returns the major version a module path@version stands for.
func majorLabel(path, version string) string {
	_, pm, ok := module.SplitPathVersion(path)
	if ok && pm != "" {
		if m := module.PathMajorPrefix(pm); m != "" {
			return m
		}
	}
	if version != "" && semver.IsValid(version) {
		m := semver.Major(version)
		if semver.Build(version) == "+incompatible" {
			return m + "+incompatible"
		}
		return m
	}
	return "v0/v1"
}

func runMajors(c *cli.Context) error {
	failOn, err := majorsFlags.failOn()
	if err != nil {
		return err
	}
	if len(c.Args) > 0 {
		return cli.Usagef("unexpected argument %q", c.Args[0])
	}
	p, g, err := loadGraph(c)
	if err != nil {
		return err
	}
	var pg *pkgGraph
	if !*majorsFlags.noPackages {
		if !c.Env.HaveGo() {
			c.Warnf("the go command is not available: analysing the build list only")
		} else if pg, err = listPackages(c, c.Env, p, true); err != nil {
			c.Warnf("package import graph unavailable (%v): analysing the build list only", err)
			pg = nil
		}
	}
	res := majorsResult{Packages: pg != nil, Families: []majorFamily{}, Findings: []report.Finding{}}

	// Group the build list (and main modules) by family.
	byFamily := map[string][]module.Version{}
	for _, m := range g.Mains {
		byFamily[familyOf(m.Path)] = append(byFamily[familyOf(m.Path)], m)
	}
	for _, m := range g.BuildList() {
		byFamily[familyOf(m.Path)] = append(byFamily[familyOf(m.Path)], m)
	}
	var fams []string
	for f, ms := range byFamily {
		if len(ms) > 1 {
			fams = append(fams, f)
		}
	}
	sort.Strings(fams)

	var reach, reachNonTest map[string]bool
	var importers map[string][]string
	if pg != nil {
		reach, reachNonTest = pg.reachablePkgs(true), pg.reachablePkgs(false)
		importers = pg.importers()
	}
	for _, f := range fams {
		fam := majorFamily{Family: f}
		for _, m := range byFamily[f] {
			mem := majorMember{Path: m.Path, Version: m.Version, Main: m.Version == "" && g.IsMain(m.Path),
				Major: majorLabel(m.Path, m.Version), RequiredBy: requirersOf(g, m.Path), Packages: []majorPkg{}}
			if mem.Main {
				mem.Major = majorLabel(m.Path, "")
				mem.Imported, mem.InBinaries = true, true
			}
			if pg != nil && !mem.Main {
				var pkgs []string
				for path := range reach {
					if !strings.HasSuffix(path, ".test") && pg.modOf(path) == m.Path {
						pkgs = append(pkgs, path)
					}
				}
				sort.Strings(pkgs)
				for _, pk := range pkgs {
					mp := majorPkg{Package: pk, ImportedBy: []string{}}
					for _, imp := range importers[pk] {
						if reach[imp] && pg.modOf(imp) != m.Path {
							mp.ImportedBy = append(mp.ImportedBy, imp)
						}
					}
					mem.Packages = append(mem.Packages, mp)
					mem.Imported = true
					if reachNonTest[pk] {
						mem.InBinaries = true
					}
				}
			}
			fam.Members = append(fam.Members, mem)
			fam.Majors = append(fam.Majors, mem.Major)
		}
		sort.Slice(fam.Members, func(i, j int) bool { return majorLess(fam.Members[i].Major, fam.Members[j].Major) })
		fam.Majors = fam.Majors[:0]
		for _, m := range fam.Members {
			fam.Majors = append(fam.Majors, m.Major)
		}
		res.Families = append(res.Families, fam)
	}
	for i := range res.Families {
		f := &res.Families[i]
		finding := majorsFinding(f, pg != nil)
		f.Severity = finding.Severity
		res.Findings = append(res.Findings, finding)
	}
	res.Summary = finish(c, res.Findings, failOn)
	c.SetResult(res)
	if c.Text() {
		printMajors(c, res)
	}
	return nil
}

// reachablePkgs returns the package nodes reachable from the main
// packages and tools (following test pseudo-nodes when withTests).
func (g *pkgGraph) reachablePkgs(withTests bool) map[string]bool {
	seen := map[string]bool{}
	q := append(append([]string(nil), g.roots...), g.tools...)
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		if seen[cur] {
			continue
		}
		if strings.HasSuffix(cur, ".test") && !withTests {
			continue
		}
		seen[cur] = true
		q = append(q, g.imports[cur]...)
	}
	return seen
}

// requirersOf lists the main modules and selected versions requiring any
// version of path.
func requirersOf(g *modgraph.Graph, path string) []string {
	out := []string{}
	for _, from := range g.Requirers(module.Version{Path: path}) {
		if (from.Version == "" && g.IsMain(from.Path)) || g.IsSelected(from) {
			out = append(out, nodeID(g, from))
		}
	}
	return out
}

func majorNum(m string) int {
	m = strings.TrimSuffix(m, "+incompatible")
	if m == "v0/v1" || m == "v0" || m == "v1" {
		return 1
	}
	n := 0
	fmt.Sscanf(strings.TrimPrefix(m, "v"), "%d", &n)
	return n
}

func majorLess(a, b string) bool {
	if majorNum(a) != majorNum(b) {
		return majorNum(a) < majorNum(b)
	}
	return a < b
}

func majorsFinding(f *majorFamily, havePkgs bool) report.Finding {
	var inBin, inTests []string
	for _, m := range f.Members {
		switch {
		case m.InBinaries:
			inBin = append(inBin, m.Path)
		case m.Imported:
			inTests = append(inTests, m.Path)
		}
	}
	newest := f.Members[len(f.Members)-1]
	fd := report.Finding{Rule: "major-split", Module: f.Family,
		Data: map[string]any{"majors": f.Majors, "importedByNonTestCode": inBin, "importedByTestsOnly": inTests}}
	var parts []string
	for _, m := range f.Members {
		s := m.Path
		if m.Version != "" {
			s += "@" + m.Version
		}
		if m.Main {
			s += " (main module)"
		}
		parts = append(parts, s)
	}
	detail := fmt.Sprintf("The build list contains %s: %s. Each major version is a separate module, so all of them are selected.", plural(len(f.Members), "module", "major versions of "+f.Family), strings.Join(parts, ", "))
	switch {
	case !havePkgs:
		fd.Severity = report.Low
		fd.Title = fmt.Sprintf("%d major versions of %s in the build list (%s)", len(f.Members), f.Family, strings.Join(f.Majors, ", "))
		detail += " Package imports were not analysed."
	case len(inBin) >= 2:
		fd.Severity = report.Medium
		fd.Title = fmt.Sprintf("%d major versions of %s are compiled in (%s)", len(inBin), f.Family, strings.Join(f.Majors, ", "))
		detail += " Non-test code imports packages of " + strings.Join(inBin, " and ") + ": the code is linked twice, package-level state is duplicated and their types are incompatible."
	case len(inBin)+len(inTests) >= 2:
		fd.Severity = report.Low
		fd.Title = fmt.Sprintf("%d major versions of %s are imported (one only by tests)", len(inBin)+len(inTests), f.Family)
		detail += " " + strings.Join(inTests, ", ") + " is imported only by test code."
	default:
		fd.Severity = report.Info
		fd.Title = fmt.Sprintf("%d major versions of %s in the build list, at most one imported", len(f.Members), f.Family)
		detail += " Only the go.mod of the other majors is used (no package is imported), so binaries are not affected."
	}
	var who []string
	for _, m := range f.Members {
		if m.Path == newest.Path || m.Main {
			continue
		}
		var imps []string
		for _, pk := range m.Packages {
			for _, i := range pk.ImportedBy {
				imps = append(imps, strings.TrimSuffix(i, ".test"))
			}
		}
		imps = uniqSorted(imps)
		if len(imps) > 0 {
			who = append(who, fmt.Sprintf("%s is imported by %s", m.Path, strings.Join(imps, ", ")))
		} else if len(m.RequiredBy) > 0 {
			who = append(who, fmt.Sprintf("%s is required by %s", m.Path, strings.Join(m.RequiredBy, ", ")))
		}
	}
	if len(who) > 0 {
		detail += " " + strings.Join(who, "; ") + "."
	}
	fd.Detail = detail
	fd.Version = newest.Version
	if fd.Severity >= report.Low && !newest.Main {
		fd.Fix = fmt.Sprintf("migrate importers of the older majors to %s (or upgrade the modules that import them)", newest.Path)
	}
	return fd
}

func printMajors(c *cli.Context, r majorsResult) {
	o := c.Out
	o.Title("Major-version split detector")
	if len(r.Families) == 0 {
		o.Println()
		o.OK("no module family appears in more than one major version")
		return
	}
	for _, f := range r.Families {
		o.Heading(fmt.Sprintf("%s  %s  %s", f.Family, strings.Join(f.Majors, " · "), o.Sev(f.Severity)))
		var rows [][]string
		for _, m := range f.Members {
			use := "build list only"
			switch {
			case m.Main:
				use = "main module"
			case m.InBinaries:
				use = o.Red("imported")
			case m.Imported:
				use = o.Yellow("imported by tests")
			case !r.Packages:
				use = "?"
			}
			v := m.Version
			if v == "" {
				v = "-"
			}
			rows = append(rows, []string{m.Major, m.Path, v, use, ui3(m.RequiredBy)})
		}
		o.Table([]string{"MAJOR", "MODULE", "VERSION", "USE", "REQUIRED BY"}, rows)
		for _, m := range f.Members {
			for _, pk := range m.Packages {
				if len(pk.ImportedBy) == 0 {
					continue
				}
				o.Printf("    %s %s %s\n", pk.Package, o.Dim("← imported by"), strings.Join(pk.ImportedBy, ", "))
			}
		}
	}
	o.Heading("Findings")
	printFindings(c, r.Findings)
	printSummaryLine(c, r.Findings, r.Summary)
}

// ui3 joins up to three items, summarising the rest.
func ui3(s []string) string {
	if len(s) <= 3 {
		return strings.Join(s, ", ")
	}
	return strings.Join(s[:3], ", ") + fmt.Sprintf(" +%d", len(s)-3)
}
