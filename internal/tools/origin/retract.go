package origin

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/modfile"
	"github.com/slash-mark-dev/go-suite/internal/modproxy"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/par"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/semver"
	"github.com/slash-mark-dev/go-suite/internal/ui"
)

var retractFlags struct {
	direct       *bool
	noDeprecated *bool
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "retract",
		Group:   group,
		Summary: "Retraction & deprecation watch with the nearest safe upgrade",
		Usage:   "sm-go retract [module[@version]...] [flags]",
		Help: `Checks every module in the build list against what its authors published
in the go.mod of the module's latest version (the go command's rule):

  - retract directives covering the selected version, with their rationale
  - the "// Deprecated:" comment on the module directive

For retracted versions it suggests the nearest version that is not
retracted (the smallest newer release of the same major version, or the
closest older one when no newer release exists). Exits 1 when any selected
version is retracted or any module is deprecated.

Arguments may name modules explicitly (path or path@version; without a
version the latest version is checked).`,
		Examples: []string{
			"sm-go retract",
			"sm-go retract --direct --json",
			"sm-go retract github.com/acme/lib@v1.4.0",
		},
		Sources: []string{"Go module proxy"},
		Flags: func(fs *flag.FlagSet) {
			retractFlags.direct = fs.Bool("direct", false, "check only direct requirements")
			retractFlags.noDeprecated = fs.Bool("no-deprecated", false, "ignore module deprecations")
		},
		Run: runRetract,
	})
}

// RetractModule is the retraction / deprecation status of one module.
type RetractModule struct {
	Dep
	// Latest is the version whose go.mod carries the metadata.
	Latest     string             `json:"latest,omitempty"`
	Retracted  bool               `json:"retracted"`
	Rationale  string             `json:"rationale,omitempty"`
	Retraction *modfile.Retract   `json:"retraction,omitempty"`
	Deprecated string             `json:"deprecated,omitempty"`
	Suggest    string             `json:"suggest,omitempty"`
	SuggestDir string             `json:"suggestDirection,omitempty"` // "upgrade" or "downgrade"
	Retracts   []*modfile.Retract `json:"retracts,omitempty"`
	Error      string             `json:"error,omitempty"`
}

// RetractResult is the JSON result of sm-go retract.
type RetractResult struct {
	Subject  string           `json:"subject"`
	Modules  []RetractModule  `json:"modules"`
	Findings []report.Finding `json:"findings"`
	Summary  struct {
		Modules    int `json:"modules"`
		Retracted  int `json:"retracted"`
		Deprecated int `json:"deprecated"`
		Unchecked  int `json:"unchecked"`
	} `json:"summary"`
}

func runRetract(c *cli.Context) error {
	deps, err := SelectDeps(c, !*retractFlags.direct, c.Args)
	if err != nil {
		return err
	}
	res := &RetractResult{Subject: subject(c, c.Args), Modules: []RetractModule{}, Findings: []report.Finding{}}
	mods, errs := par.Map(c.Ctx, 8, deps, func(ctx context.Context, d Dep) (RetractModule, error) {
		return checkRetract(ctx, c, d)
	})
	if err := par.FirstErr(errs); err != nil {
		return err
	}
	for _, m := range mods {
		res.Modules = append(res.Modules, m)
		if m.Error != "" {
			res.Summary.Unchecked++
			continue
		}
		if m.Retracted {
			res.Summary.Retracted++
			f := report.Finding{Severity: report.High, Rule: "retracted", Module: m.Path, Version: m.Version,
				Title: "selected version is retracted", Detail: retractDetail(m)}
			if securityRationale(m.Rationale) {
				f.Severity = report.Critical
			}
			if m.Suggest != "" {
				f.Fix = "go get " + m.Path + "@" + m.Suggest
			}
			res.Findings = append(res.Findings, f)
		}
		if m.Deprecated != "" && !*retractFlags.noDeprecated {
			res.Summary.Deprecated++
			res.Findings = append(res.Findings, report.Finding{Severity: report.Medium, Rule: "deprecated", Module: m.Path, Version: m.Version,
				Title: "module is deprecated", Detail: m.Deprecated})
		}
	}
	report.SortFindings(res.Findings)
	res.Summary.Modules = len(res.Modules)
	c.SetResult(res)
	if len(res.Findings) > 0 {
		c.Issues()
	}
	if c.Text() {
		printRetract(c, res)
	}
	return nil
}

func retractDetail(m RetractModule) string {
	var b strings.Builder
	if m.Retraction != nil {
		if m.Retraction.Low == m.Retraction.High {
			fmt.Fprintf(&b, "%s retracts %s", m.Latest, m.Retraction.Low)
		} else {
			fmt.Fprintf(&b, "%s retracts [%s, %s]", m.Latest, m.Retraction.Low, m.Retraction.High)
		}
	}
	if m.Rationale != "" {
		fmt.Fprintf(&b, ": %s", m.Rationale)
	} else {
		b.WriteString(" (no rationale given)")
	}
	b.WriteString(".")
	switch {
	case m.Suggest != "" && m.SuggestDir == "downgrade":
		fmt.Fprintf(&b, " No newer version is unretracted; the closest older version is %s.", m.Suggest)
	case m.Suggest != "":
		fmt.Fprintf(&b, " Nearest unretracted upgrade: %s.", m.Suggest)
	default:
		b.WriteString(" Every published version of this major version is retracted.")
	}
	return b.String()
}

// securityRationale reports whether a retraction rationale mentions a
// security problem.
func securityRationale(s string) bool {
	s = strings.ToLower(s)
	for _, k := range []string{"security", "vulnerab", "cve-", "ghsa-", "go-20", "exploit", "malicious", "compromised", "backdoor"} {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func checkRetract(ctx context.Context, c *cli.Context, d Dep) (RetractModule, error) {
	m := RetractModule{Dep: d}
	if d.Local != "" {
		// Built from a directory: the required version (often a
		// placeholder like v0.0.0) is never downloaded, so its
		// retractions do not apply.
		m.Error = "replaced by a local directory"
		return m, nil
	}
	meta, err := c.Proxy().Meta(ctx, d.Path)
	if err != nil {
		if isNotFoundErr(err) {
			c.Warnf("%s: not found on the module proxy; cannot check retractions", d.Path)
			m.Error = "not found on the module proxy"
			return m, nil
		}
		return m, fmt.Errorf("%s: %w", d.Path, err)
	}
	m.Latest = meta.Latest
	m.Deprecated = meta.Deprecated
	m.Retracts = meta.Retract
	if m.Version == "" {
		v, err := c.Proxy().QueryLatest(ctx, d.Path)
		if err != nil {
			return m, fmt.Errorf("%s: %w", d.Path, err)
		}
		m.Version = v
	}
	for _, r := range meta.Retract {
		if r.Contains(m.Version) {
			m.Retracted, m.Rationale, m.Retraction = true, r.Rationale, r
			break
		}
	}
	if m.Retracted {
		m.Suggest, m.SuggestDir = nearestUnretracted(meta, m.Version)
	}
	return m, nil
}

// nearestUnretracted returns the smallest unretracted version above cur
// with the same major version (releases only, unless cur is a prerelease),
// falling back to the largest unretracted version below cur.
func nearestUnretracted(meta *modproxy.Meta, cur string) (string, string) {
	major := semver.Major(cur)
	pre := semver.Prerelease(cur) != "" && !module.IsPseudoVersion(cur)
	up, down := "", ""
	for _, v := range meta.Versions {
		if semver.Major(v) != major || (semver.Prerelease(v) != "" && !pre) {
			continue
		}
		if r, _ := meta.Retracted(v); r {
			continue
		}
		switch c := semver.Compare(v, cur); {
		case c > 0 && (up == "" || semver.Compare(v, up) < 0):
			up = v
		case c < 0 && (down == "" || semver.Compare(v, down) > 0):
			down = v
		}
	}
	if up != "" {
		return up, "upgrade"
	}
	if down != "" {
		return down, "downgrade"
	}
	return "", ""
}

func printRetract(c *cli.Context, res *RetractResult) {
	o := c.Out
	o.Title("Retraction & deprecation watch · " + res.Subject)
	o.Printf("%s\n", o.Dim(fmt.Sprintf("%s checked · %d retracted · %d deprecated", ui.Plural(res.Summary.Modules, "module", "modules"), res.Summary.Retracted, res.Summary.Deprecated)))
	var rows [][]string
	for _, m := range res.Modules {
		switch {
		case m.Retracted:
			why := m.Rationale
			if why == "" {
				why = "no rationale"
			}
			s := m.Suggest
			if s == "" {
				s = "-"
			}
			rows = append(rows, []string{o.Red("RETRACTED"), m.Path, m.Version, s, ui80(why)})
		case m.Deprecated != "" && !*retractFlags.noDeprecated:
			rows = append(rows, []string{o.Yellow("DEPRECATED"), m.Path, m.Version, "-", ui80(m.Deprecated)})
		}
	}
	if len(rows) == 0 {
		o.Println()
		o.OK("no selected version is retracted and no module is deprecated")
		return
	}
	o.Heading("Findings")
	o.Table([]string{"STATUS", "MODULE", "VERSION", "SUGGEST", "REASON"}, rows)
	if fixes := fixCommands(res.Findings, report.Low); len(fixes) > 0 {
		o.Heading("Fix")
		for _, f := range fixes {
			o.Printf("  %s\n", f)
		}
	}
}

func ui80(s string) string { return ui.Truncate(strings.Join(strings.Fields(s), " "), 80) }
