package origin

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/httpx"
	"github.com/slash-mark-dev/go-suite/internal/modproxy"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/project"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/semver"
	"github.com/slash-mark-dev/go-suite/internal/ui"
)

const group = "Origin & trust"

// Dep is a dependency selected for analysis.
type Dep struct {
	Path    string `json:"path"`
	Version string `json:"version,omitempty"`
	Direct  bool   `json:"direct"`
	// Replace is a module replacement in effect: the code comes from there.
	Replace *module.Version `json:"replace,omitempty"`
	// Local is set when the module is replaced by a directory.
	Local string `json:"local,omitempty"`
}

// CodePath returns the module path the code is actually fetched from.
func (d Dep) CodePath() string {
	if d.Replace != nil {
		return d.Replace.Path
	}
	return d.Path
}

// CodeVersion returns the version the code is actually fetched at.
func (d Dep) CodeVersion() string {
	if d.Replace != nil {
		return d.Replace.Version
	}
	return d.Version
}

func (d Dep) String() string {
	if d.Version == "" {
		return d.Path
	}
	return d.Path + "@" + d.Version
}

// ParseModuleArgs parses "path" or "path@version" arguments.
func ParseModuleArgs(args []string) ([]Dep, error) {
	var out []Dep
	for _, a := range args {
		p, v, _ := strings.Cut(a, "@")
		if err := module.CheckPath(p); err != nil {
			return nil, cli.Usagef("invalid module path %q: %v", p, err)
		}
		if v != "" && v != "latest" && !semver.IsValid(v) {
			return nil, cli.Usagef("invalid version %q in %s (use path or path@vX.Y.Z)", v, a)
		}
		if v == "latest" {
			v = ""
		}
		out = append(out, Dep{Path: p, Version: v, Direct: true})
	}
	return out, nil
}

// SelectDeps returns the modules to analyze: the explicit arguments if
// any, else the direct requirements of the main module (all is false) or
// the whole build list.
func SelectDeps(c *cli.Context, all bool, args []string) ([]Dep, error) {
	if len(args) > 0 {
		return ParseModuleArgs(args)
	}
	g, err := c.Graph()
	if err != nil {
		if errors.Is(err, project.ErrNoModule) {
			return nil, cli.Usagef("%v", err)
		}
		return nil, err
	}
	var out []Dep
	for _, m := range g.BuildList() {
		direct := g.IsDirect(m.Path)
		if !all && !direct {
			continue
		}
		d := Dep{Path: m.Path, Version: m.Version, Direct: direct}
		if r, _ := g.FindReplace(m); r != nil {
			if r.IsLocal() {
				d.Local = r.New.Path
			} else {
				nv := r.New
				d.Replace = &nv
			}
		}
		out = append(out, d)
	}
	return out, nil
}

// subject returns the title subject: the main module path or the args.
func subject(c *cli.Context, args []string) string {
	if len(args) > 0 {
		return strings.Join(args, " ")
	}
	if p, err := c.Project(); err == nil && p.ModulePath() != "" {
		return p.ModulePath()
	}
	return c.Dir()
}

// severityCounts fills the per-severity counters of a summary.
type severityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

func countSeverities(fs []report.Finding) severityCounts {
	var s severityCounts
	for _, f := range fs {
		switch f.Severity {
		case report.Critical:
			s.Critical++
		case report.High:
			s.High++
		case report.Medium:
			s.Medium++
		case report.Low:
			s.Low++
		case report.Info:
			s.Info++
		}
	}
	return s
}

func (s severityCounts) String() string {
	var parts []string
	add := func(n int, name string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, name))
		}
	}
	add(s.Critical, "critical")
	add(s.High, "high")
	add(s.Medium, "medium")
	add(s.Low, "low")
	add(s.Info, "info")
	if len(parts) == 0 {
		return "no findings"
	}
	return strings.Join(parts, ", ")
}

// printFindings prints findings with detail, action and fix lines.
func printFindings(c *cli.Context, fs []report.Finding) {
	for _, f := range fs {
		c.Out.Printf("  %s %s  %s\n", c.Out.Sev(f.Severity), c.Out.Bold(f.Where()), f.Title)
		if f.Detail != "" {
			for _, line := range wrap(f.Detail, 88) {
				c.Out.Printf("           %s\n", c.Out.Dim(line))
			}
		}
		if f.Fix != "" {
			c.Out.Printf("           %s %s\n", c.Out.Green("fix:"), f.Fix)
		}
	}
}

// wrap breaks s into lines of at most n runes on word boundaries.
func wrap(s string, n int) []string {
	var lines []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		line := ""
		for _, w := range words {
			if line != "" && ui.Width(line)+1+ui.Width(w) > n {
				lines = append(lines, line)
				line = ""
			}
			if line != "" {
				line += " "
			}
			line += w
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// fixCommands returns the distinct fix commands of findings at or above min.
func fixCommands(fs []report.Finding, min report.Severity) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range fs {
		if f.Severity < min || f.Fix == "" || seen[f.Fix] {
			continue
		}
		seen[f.Fix] = true
		out = append(out, f.Fix)
	}
	sort.Strings(out)
	return out
}

// isNotFoundErr reports whether err means the module (version) does not
// exist on the proxy, as opposed to a network failure.
func isNotFoundErr(err error) bool {
	return errors.Is(err, modproxy.ErrNotFound) || httpx.IsNotFound(err)
}

func maxSeverity(fs []report.Finding) report.Severity { return report.Max(fs) }
