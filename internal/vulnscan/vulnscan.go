// Package vulnscan matches module versions (and Go toolchain versions)
// against the Go vulnerability database and enriches the matches with
// live exploit intelligence: CISA KEV, FIRST EPSS and the GitHub Advisory
// Database severity.
package vulnscan

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/feeds"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/par"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/vulndb"
)

// Vuln is one vulnerability affecting one module version.
type Vuln struct {
	ID             string              `json:"id"`
	Summary        string              `json:"summary,omitempty"`
	Aliases        []string            `json:"aliases,omitempty"`
	CVEs           []string            `json:"cves,omitempty"`
	Module         string              `json:"module"`
	Version        string              `json:"version"`
	FixedIn        string              `json:"fixedIn,omitempty"`
	Packages       []string            `json:"packages,omitempty"`
	Symbols        map[string][]string `json:"symbols,omitempty"` // package -> symbols
	Severity       report.Severity     `json:"severity"`
	SeveritySource string              `json:"severitySource"`
	CVSS           float64             `json:"cvss,omitempty"`
	KEV            *feeds.KEVEntry     `json:"kev,omitempty"`
	EPSS           *feeds.EPSSScore    `json:"epss,omitempty"`
	URL            string              `json:"url"`
	Published      time.Time           `json:"published"`
	Entry          *vulndb.Entry       `json:"-"`
}

// StdlibModule returns the pseudo-module used for the standard library at
// Go version goVersion ("go1.27.3" or "1.27.3"); ok is false if the version
// cannot be mapped.
func StdlibModule(goVersion string) (module.Version, bool) {
	v := vulndb.GoToSemver(goVersion)
	if v == "" {
		return module.Version{}, false
	}
	return module.Version{Path: vulndb.Stdlib, Version: v}, true
}

// Scan returns the vulnerabilities affecting mods. Include
// StdlibModule(...) / {Path: "toolchain"} entries to scan Go itself.
func Scan(ctx context.Context, c *cli.Context, mods []module.Version) ([]*Vuln, error) {
	finds, err := c.VulnDB().ForModules(ctx, mods)
	if err != nil {
		return nil, err
	}
	var out []*Vuln
	for _, f := range finds {
		v := &Vuln{ID: f.ID, Summary: f.Entry.Summary, Aliases: f.Entry.Aliases, CVEs: f.Entry.CVEs(),
			Module: f.Module.Path, Version: f.Module.Version, FixedIn: f.FixedIn, URL: f.Entry.URL(),
			Published: f.Entry.Published, Entry: f.Entry, Severity: report.Medium, SeveritySource: "default"}
		if f.Affected.EcosystemSpecific != nil {
			v.Symbols = map[string][]string{}
			for _, im := range f.Affected.EcosystemSpecific.Imports {
				v.Packages = append(v.Packages, im.Path)
				v.Symbols[im.Path] = im.Symbols
			}
		}
		if v.Summary == "" {
			v.Summary = firstLine(f.Entry.Details)
		}
		out = append(out, v)
	}
	return out, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}

// Enrich adds KEV, EPSS and GitHub advisory severity to vulns and computes
// each Severity:
//   - the GitHub Advisory Database severity of the GHSA alias, if any;
//   - raised to critical if the CVE is in CISA's Known Exploited
//     Vulnerabilities catalog;
//   - raised to at least high if the EPSS probability is >= 0.1.
//
// Sources that cannot be reached produce a warning, not an error.
func Enrich(ctx context.Context, c *cli.Context, vulns []*Vuln) {
	if len(vulns) == 0 {
		return
	}
	var cves []string
	for _, v := range vulns {
		cves = append(cves, v.CVEs...)
	}
	kev, err := feeds.KEV(ctx, c.HTTP(), c.Endpoint("kev"))
	if err != nil {
		c.Warnf("CISA KEV unavailable: %v", err)
	}
	epss, err := feeds.EPSS(ctx, c.HTTP(), c.Endpoint("epss"), cves)
	if err != nil {
		c.Warnf("FIRST EPSS unavailable: %v", err)
	}
	ghsas := map[string]*feeds.Advisory{}
	var ids []string
	for _, v := range vulns {
		for _, a := range v.Entry.GHSAs() {
			if _, ok := ghsas[a]; !ok {
				ghsas[a] = nil
				ids = append(ids, a)
			}
		}
	}
	sort.Strings(ids)
	gh := c.GitHub()
	advs, errs := par.Map(ctx, 4, ids, func(ctx context.Context, id string) (*feeds.Advisory, error) { return gh.Advisory(ctx, id) })
	warned := false
	for i, id := range ids {
		if errs[i] != nil {
			if !warned {
				c.Warnf("GitHub Advisory Database unavailable (%v); set GITHUB_TOKEN for higher rate limits", errs[i])
				warned = true
			}
			continue
		}
		ghsas[id] = advs[i]
	}
	for _, v := range vulns {
		for _, a := range v.Entry.GHSAs() {
			if adv := ghsas[a]; adv != nil {
				if s, err := report.ParseSeverity(adv.Severity); err == nil && s > report.None {
					v.Severity, v.SeveritySource = s, "ghsa"
				}
				if adv.CVSS != nil && adv.CVSS.Score > 0 {
					v.CVSS = adv.CVSS.Score
					if v.SeveritySource == "default" {
						v.Severity, v.SeveritySource = report.CVSSSeverity(adv.CVSS.Score), "cvss"
					}
				}
				break
			}
		}
		for _, cve := range v.CVEs {
			if e, ok := kev[cve]; ok {
				v.KEV = e
			}
			if s, ok := epss[cve]; ok {
				s := s
				if v.EPSS == nil || s.EPSS > v.EPSS.EPSS {
					v.EPSS = &s
				}
			}
		}
		if v.KEV != nil {
			v.Severity, v.SeveritySource = report.Critical, "kev"
		} else if v.EPSS != nil && v.EPSS.EPSS >= 0.1 && v.Severity < report.High {
			v.Severity, v.SeveritySource = report.High, "epss"
		}
	}
}

// Sort orders vulns by severity (highest first), then module and ID.
func Sort(vs []*Vuln) {
	sort.SliceStable(vs, func(i, j int) bool {
		if vs[i].Severity != vs[j].Severity {
			return vs[i].Severity > vs[j].Severity
		}
		if vs[i].Module != vs[j].Module {
			return vs[i].Module < vs[j].Module
		}
		return vs[i].ID < vs[j].ID
	})
}
