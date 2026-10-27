package origin

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/feeds"
	"github.com/slash-mark-dev/go-suite/internal/httpx"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/par"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/semver"
	"github.com/slash-mark-dev/go-suite/internal/source"
	"github.com/slash-mark-dev/go-suite/internal/ui"
)

var healthFlags struct {
	direct   *bool
	minScore *int
	sortBy   *string
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "health",
		Group:   group,
		Summary: "Module health score (0-100) from Scorecard, releases, GitHub, deps.dev and vulns",
		Usage:   "sm-go health [module[@version]...] [flags]",
		Help: `Scores every module in the build list from 0 to 100 and shows how the score
was reached. Positive components (each scaled to the data that is
available, so a missing source does not count against a module):

  security     OpenSSF Scorecard overall score via deps.dev     25 points
  recency      age of the latest release (proxy .info)          15 points
  cadence      releases published in the last 12 months         10 points
  activity     last push to the GitHub repository               10 points
  popularity   deps.dev dependents and GitHub stars             15 points
  maintainers  GitHub contributors (bus factor)                 10 points
  issues       open issues relative to stars                     5 points

Penalties are then subtracted: archived repository (-30), deprecated
module (-30), retracted selected version (-25), source repository missing
(-20) and -10 per known vulnerability affecting the selected version (at
most -40). With --min-score, modules scoring below the threshold are
reported as findings and the exit code is 1.`,
		Examples: []string{
			"sm-go health",
			"sm-go health --direct --min-score 60",
			"sm-go health github.com/spf13/cobra --json",
		},
		Sources: []string{"Go module proxy", "deps.dev (OpenSSF Scorecard, dependents)", "GitHub REST API", "Go vulnerability database"},
		Flags: func(fs *flag.FlagSet) {
			healthFlags.direct = fs.Bool("direct", false, "score only direct requirements")
			healthFlags.minScore = fs.Int("min-score", 0, "exit 1 if any module scores below `n` (0-100)")
			healthFlags.sortBy = fs.String("sort", "score", "order modules by `score` or name")
		},
		Run: runHealth,
	})
}

// HealthComponent is one positive part of the score.
type HealthComponent struct {
	Name      string  `json:"name"`
	Points    float64 `json:"points"`
	Max       float64 `json:"max"`
	Available bool    `json:"available"`
	Detail    string  `json:"detail,omitempty"`
}

// HealthPenalty is a deduction from the score.
type HealthPenalty struct {
	Reason string `json:"reason"`
	Points int    `json:"points"`
}

// HealthSignals are the raw inputs of the score.
type HealthSignals struct {
	Versions         int        `json:"versions"`
	LatestRelease    string     `json:"latestRelease,omitempty"`
	LatestTime       *time.Time `json:"latestReleaseTime,omitempty"`
	ReleasesLastYr   int        `json:"releasesLastYear"`
	Scorecard        *float64   `json:"scorecard,omitempty"`
	ScorecardDate    string     `json:"scorecardDate,omitempty"`
	Dependents       *int       `json:"dependents,omitempty"`
	Repo             string     `json:"repo,omitempty"`
	RepoFound        *bool      `json:"repoFound,omitempty"`
	Stars            *int       `json:"stars,omitempty"`
	OpenIssues       *int       `json:"openIssues,omitempty"`
	Archived         bool       `json:"archived,omitempty"`
	PushedAt         *time.Time `json:"pushedAt,omitempty"`
	Contributors     *int       `json:"contributors,omitempty"`
	TopContributor   *float64   `json:"topContributorShare,omitempty"`
	Deprecated       string     `json:"deprecated,omitempty"`
	Retracted        bool       `json:"retracted,omitempty"`
	RetractRationale string     `json:"retractRationale,omitempty"`
	Vulns            []string   `json:"vulns,omitempty"`
	VulnsChecked     bool       `json:"vulnsChecked"`
}

// HealthModule is the score of one module.
type HealthModule struct {
	Dep
	Score      int               `json:"score"`
	Grade      string            `json:"grade"`
	Base       int               `json:"base"`
	Components []HealthComponent `json:"components"`
	Penalties  []HealthPenalty   `json:"penalties,omitempty"`
	Signals    HealthSignals     `json:"signals"`
	Note       string            `json:"note,omitempty"`
}

// HealthResult is the JSON result of sm-go health.
type HealthResult struct {
	Subject  string           `json:"subject"`
	MinScore int              `json:"minScore,omitempty"`
	Modules  []HealthModule   `json:"modules"`
	Findings []report.Finding `json:"findings"`
	Summary  struct {
		Modules        int     `json:"modules"`
		Average        float64 `json:"average"`
		Lowest         int     `json:"lowest"`
		BelowThreshold int     `json:"belowThreshold"`
	} `json:"summary"`
}

// warnOnce reports a degraded optional source once per run.
type warnOnce struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (w *warnOnce) warn(c *cli.Context, src string, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.seen == nil {
		w.seen = map[string]bool{}
	}
	if w.seen[src] {
		return
	}
	w.seen[src] = true
	c.Warnf("%s unavailable, scores computed without it: %v", src, err)
}

func runHealth(c *cli.Context) error {
	minScore := *healthFlags.minScore
	if minScore < 0 || minScore > 100 {
		return cli.Usagef("--min-score must be between 0 and 100")
	}
	if *healthFlags.sortBy != "score" && *healthFlags.sortBy != "name" {
		return cli.Usagef("--sort must be score or name")
	}
	deps, err := SelectDeps(c, !*healthFlags.direct, c.Args)
	if err != nil {
		return err
	}
	now := time.Now()
	var warn warnOnce

	// Resolve versions for explicit arguments without one.
	for i := range deps {
		if deps[i].Version == "" && deps[i].Local == "" {
			v, err := c.Proxy().QueryLatest(c.Ctx, deps[i].Path)
			if err != nil {
				if isNotFoundErr(err) {
					return cli.Usagef("%s: module not found on the proxy", deps[i].Path)
				}
				return err
			}
			deps[i].Version = v
		}
	}

	// Vulnerabilities for the whole set in one pass.
	vulns := map[string][]string{}
	var mvs []module.Version
	for _, d := range deps {
		if d.Version != "" {
			mvs = append(mvs, module.Version{Path: d.Path, Version: d.Version})
		}
	}
	vulnOK := true
	if fs, err := c.VulnDB().ForModules(c.Ctx, mvs); err != nil {
		vulnOK = false
		warn.warn(c, "Go vulnerability database", err)
	} else {
		for _, f := range fs {
			vulns[f.Module.Path] = append(vulns[f.Module.Path], f.ID)
		}
	}

	mods, errs := par.Map(c.Ctx, 8, deps, func(ctx context.Context, d Dep) (HealthModule, error) {
		return scoreModule(ctx, c, d, vulns[d.Path], vulnOK, now, &warn)
	})
	if err := par.FirstErr(errs); err != nil {
		return err
	}
	res := &HealthResult{Subject: subject(c, c.Args), MinScore: minScore, Modules: mods, Findings: []report.Finding{}}
	if res.Modules == nil {
		res.Modules = []HealthModule{}
	}
	sort.SliceStable(res.Modules, func(i, j int) bool {
		a, b := res.Modules[i], res.Modules[j]
		if *healthFlags.sortBy == "score" && a.Score != b.Score {
			return a.Score < b.Score
		}
		return a.Path < b.Path
	})
	total := 0
	res.Summary.Lowest = 100
	for _, m := range res.Modules {
		total += m.Score
		if m.Score < res.Summary.Lowest {
			res.Summary.Lowest = m.Score
		}
		if minScore > 0 && m.Score < minScore {
			res.Summary.BelowThreshold++
			sev := report.Medium
			if m.Score < minScore/2 {
				sev = report.High
			}
			var why []string
			for _, p := range m.Penalties {
				why = append(why, fmt.Sprintf("%s (%d)", p.Reason, p.Points))
			}
			for _, comp := range m.Components {
				if comp.Available && comp.Points < comp.Max/3 {
					why = append(why, fmt.Sprintf("weak %s: %s", comp.Name, comp.Detail))
				}
			}
			res.Findings = append(res.Findings, report.Finding{Severity: sev, Rule: "low-health", Module: m.Path, Version: m.Version,
				Title: fmt.Sprintf("health score %d is below %d", m.Score, minScore), Detail: strings.Join(why, "; ")})
		}
	}
	res.Summary.Modules = len(res.Modules)
	if len(res.Modules) > 0 {
		res.Summary.Average = math.Round(float64(total)/float64(len(res.Modules))*10) / 10
	} else {
		res.Summary.Lowest = 0
	}
	report.SortFindings(res.Findings)
	c.SetResult(res)
	if len(res.Findings) > 0 {
		c.Issues()
	}
	if c.Text() {
		printHealth(c, res)
	}
	return nil
}

func scoreModule(ctx context.Context, c *cli.Context, d Dep, vulnIDs []string, vulnOK bool, now time.Time, warn *warnOnce) (HealthModule, error) {
	m := HealthModule{Dep: d}
	s := &m.Signals
	s.Vulns, s.VulnsChecked = vulnIDs, vulnOK
	if d.Local != "" {
		m.Note = "replaced by local directory " + d.Local + "; only registry signals scored"
	}
	comp := map[string]*HealthComponent{}
	for _, n := range []struct {
		name string
		max  float64
	}{{"security", 25}, {"recency", 15}, {"cadence", 10}, {"activity", 10}, {"popularity", 15}, {"maintainers", 10}, {"issues", 5}} {
		m.Components = append(m.Components, HealthComponent{Name: n.name, Max: n.max})
	}
	for i := range m.Components {
		comp[m.Components[i].Name] = &m.Components[i]
	}
	set := func(name string, pts float64, detail string) {
		cp := comp[name]
		cp.Available, cp.Points, cp.Detail = true, math.Round(math.Max(0, math.Min(cp.Max, pts))*10)/10, detail
	}

	// --- module proxy: releases, retractions, deprecation ---
	meta, err := c.Proxy().Meta(ctx, d.Path)
	switch {
	case err != nil && isNotFoundErr(err):
		m.Note = strings.TrimPrefix(m.Note+"; not found on the module proxy", "; ")
	case err != nil:
		return m, fmt.Errorf("%s: %w", d.Path, err)
	default:
		s.Versions = len(meta.Versions)
		s.Deprecated = meta.Deprecated
		if d.Version != "" {
			if r, why := meta.Retracted(d.Version); r {
				s.Retracted, s.RetractRationale = true, why
			}
		}
		if err := releaseSignals(ctx, c, d, meta.Versions, s, now); err != nil {
			return m, err
		}
	}
	if s.LatestTime != nil {
		age := int(now.Sub(*s.LatestTime).Hours() / 24)
		var pts float64
		switch {
		case age <= 90:
			pts = 15
		case age <= 180:
			pts = 12
		case age <= 365:
			pts = 8
		case age <= 730:
			pts = 4
		}
		set("recency", pts, fmt.Sprintf("latest release %s, %s ago", s.LatestRelease, dayCount(age)))
		n := s.ReleasesLastYr
		pts = 0
		switch {
		case n >= 4:
			pts = 10
		case n >= 2:
			pts = 7
		case n == 1:
			pts = 4
		}
		set("cadence", pts, fmt.Sprintf("%s in the last 12 months", ui.Plural(n, "release", "releases")))
	}

	// --- repository ---
	r := source.Resolve(ctx, c, d.CodePath())
	ddRepo := ""
	if r.Err == nil && r.URL != "" {
		s.Repo = strings.TrimPrefix(strings.TrimPrefix(r.URL, "https://"), "http://")
	}
	// Private modules are never sent to third-party services: the GitHub
	// API only for github.com/... paths (their own host), no deps.dev.
	private := c.IsPrivate(d.Path) || c.IsPrivate(d.CodePath())
	if r.OnGitHub() && !c.GitHubAPIAllowed(d.CodePath()) {
		m.Note = strings.TrimPrefix(m.Note+"; GitHub skipped: private module", "; ")
		for _, n := range []string{"activity", "maintainers", "issues", "popularity"} {
			comp[n].Detail = feeds.ErrPrivate.Error()
		}
	} else if r.OnGitHub() {
		ghRepo, err := c.GitHub().Repo(ctx, r.Owner, r.Name)
		switch {
		case httpx.IsNotFound(err):
			f := false
			s.RepoFound = &f
		case err != nil:
			warn.warn(c, "GitHub", err)
		default:
			t := true
			s.RepoFound = &t
			s.Repo = "github.com/" + ghRepo.FullName
			ddRepo = s.Repo
			stars, issues := ghRepo.Stars, ghRepo.OpenIssues
			s.Stars, s.OpenIssues, s.Archived = &stars, &issues, ghRepo.Archived
			if !ghRepo.PushedAt.IsZero() {
				p := ghRepo.PushedAt.UTC()
				s.PushedAt = &p
				age := int(now.Sub(p).Hours() / 24)
				var pts float64
				switch {
				case age <= 30:
					pts = 10
				case age <= 90:
					pts = 8
				case age <= 365:
					pts = 5
				case age <= 730:
					pts = 2
				}
				set("activity", pts, fmt.Sprintf("last push %s ago", dayCount(age)))
			}
			ratio := float64(issues) / math.Max(1, float64(stars))
			ipts := 1.0
			switch {
			case ratio < 0.02:
				ipts = 5
			case ratio < 0.1:
				ipts = 3
			}
			set("issues", ipts, fmt.Sprintf("%d open issues, %d stars", issues, stars))
			owner, name, _ := strings.Cut(ghRepo.FullName, "/")
			n, top, err := c.GitHub().Contributors(ctx, owner, name)
			if err != nil && !httpx.IsNotFound(err) {
				warn.warn(c, "GitHub contributors", err)
			} else if err == nil && n > 0 {
				s.Contributors, s.TopContributor = &n, &top
				var pts float64
				switch {
				case n >= 5:
					pts = 10
				case n >= 3:
					pts = 8
				case n == 2:
					pts = 6
				default:
					pts = 3
				}
				detail := ui.Plural(n, "contributor", "contributors")
				if n > 1 && top > 0.9 {
					pts -= 2
					detail += fmt.Sprintf(", top one wrote %.0f%%", top*100)
				}
				set("maintainers", pts, detail)
			}
		}
	}

	// --- deps.dev: Scorecard and dependents ---
	if d.Version != "" && private {
		c.NotePrivate(d.Path)
		m.Note = strings.TrimPrefix(m.Note+"; deps.dev skipped: private module", "; ")
		comp["security"].Detail = feeds.ErrPrivate.Error()
		if !comp["popularity"].Available {
			comp["popularity"].Detail = feeds.ErrPrivate.Error()
		}
	} else if d.Version != "" {
		dd := c.DepsDev()
		if v, err := dd.Version(ctx, d.Path, d.Version); err == nil {
			if sr := v.SourceRepo(); sr != "" {
				ddRepo = sr
			}
		} else if !httpx.IsNotFound(err) && !errors.Is(err, feeds.ErrPrivate) {
			warn.warn(c, "deps.dev", err)
		}
		if ddRepo != "" {
			if p, err := dd.Project(ctx, ddRepo); err == nil && p.Scorecard != nil {
				sc := p.Scorecard.OverallScore
				s.Scorecard, s.ScorecardDate = &sc, p.Scorecard.Date
				set("security", sc*2.5, fmt.Sprintf("OpenSSF Scorecard %.1f/10", sc))
			} else if err != nil && !httpx.IsNotFound(err) && !errors.Is(err, feeds.ErrPrivate) {
				warn.warn(c, "deps.dev", err)
			}
		}
		if total, _, err := dd.Dependents(ctx, d.Path, d.Version); err == nil {
			s.Dependents = &total
		} else if !httpx.IsNotFound(err) && !errors.Is(err, feeds.ErrPrivate) {
			warn.warn(c, "deps.dev", err)
		}
	}
	if s.Dependents != nil || s.Stars != nil {
		var pts float64
		var parts []string
		if s.Dependents != nil {
			pts += 3 * math.Log10(1+float64(*s.Dependents))
			parts = append(parts, ui.Plural(*s.Dependents, "dependent", "dependents"))
		}
		if s.Stars != nil {
			pts += 2 * math.Log10(1+float64(*s.Stars))
			parts = append(parts, fmt.Sprintf("%d stars", *s.Stars))
		}
		set("popularity", pts, strings.Join(parts, ", "))
	}

	// --- penalties ---
	pen := func(reason string, pts int) {
		m.Penalties = append(m.Penalties, HealthPenalty{Reason: reason, Points: -pts})
	}
	if s.Archived {
		pen("repository archived", 30)
	}
	if s.Deprecated != "" {
		pen("module deprecated", 30)
	}
	if s.Retracted {
		pen("selected version retracted", 25)
	}
	if s.RepoFound != nil && !*s.RepoFound {
		pen("source repository not found", 20)
	}
	if n := len(s.Vulns); n > 0 {
		pen(ui.Plural(n, "known vulnerability", "known vulnerabilities"), min(40, 10*n))
	}

	// --- total ---
	var got, avail float64
	for _, cp := range m.Components {
		if cp.Available {
			got += cp.Points
			avail += cp.Max
		}
	}
	base := 50.0 // nothing known: neutral
	if avail > 0 {
		base = 100 * got / avail
	}
	m.Base = int(math.Round(base))
	score := m.Base
	for _, p := range m.Penalties {
		score += p.Points
	}
	m.Score = max(0, min(100, score))
	m.Grade = grade(m.Score)
	return m, nil
}

// releaseSignals fills the latest release and the release count of the
// last year from .info timestamps (newest 24 versions at most).
func releaseSignals(ctx context.Context, c *cli.Context, d Dep, versions []string, s *HealthSignals, now time.Time) error {
	vs := append([]string(nil), versions...)
	semver.Sort(vs)
	// Newest first, releases preferred for "latest".
	for i, j := 0, len(vs)-1; i < j; i, j = i+1, j-1 {
		vs[i], vs[j] = vs[j], vs[i]
	}
	if len(vs) > 24 {
		vs = vs[:24]
	}
	if len(vs) == 0 && d.Version != "" {
		vs = []string{d.Version} // pseudo-version only module
	}
	infos, errs := par.Map(ctx, 8, vs, func(ctx context.Context, v string) (time.Time, error) {
		info, err := c.Proxy().Info(ctx, d.Path, v)
		if err != nil {
			return time.Time{}, err
		}
		return info.Time, nil
	})
	yearAgo := now.AddDate(-1, 0, 0)
	for i, v := range vs {
		if errs[i] != nil {
			if isNotFoundErr(errs[i]) {
				continue
			}
			return fmt.Errorf("%s@%s: %w", d.Path, v, errs[i])
		}
		t := infos[i].UTC()
		if t.IsZero() {
			continue
		}
		if t.After(yearAgo) {
			s.ReleasesLastYr++
		}
		if s.LatestTime == nil || t.After(*s.LatestTime) {
			tt := t
			s.LatestTime, s.LatestRelease = &tt, v
		}
	}
	return nil
}

func grade(score int) string {
	switch {
	case score >= 85:
		return "A"
	case score >= 70:
		return "B"
	case score >= 55:
		return "C"
	case score >= 40:
		return "D"
	}
	return "F"
}

func printHealth(c *cli.Context, res *HealthResult) {
	o := c.Out
	o.Title("Module health · " + res.Subject)
	o.Printf("%s\n", o.Dim(fmt.Sprintf("%d modules · average %.1f · lowest %d", res.Summary.Modules, res.Summary.Average, res.Summary.Lowest)))
	if len(res.Modules) == 0 {
		return
	}
	var rows [][]string
	for _, m := range res.Modules {
		score := fmt.Sprintf("%3d %s", m.Score, m.Grade)
		switch {
		case m.Score >= 70:
			score = o.Green(score)
		case m.Score >= 40:
			score = o.Yellow(score)
		default:
			score = o.Red(score)
		}
		var notes []string
		for _, p := range m.Penalties {
			notes = append(notes, fmt.Sprintf("%s %d", p.Reason, p.Points))
		}
		rows = append(rows, []string{score, ui.Bar(float64(m.Score)/100, 10), m.Path, m.Version, ui.Truncate(strings.Join(notes, ", "), 60)})
	}
	o.Heading("Scores")
	o.Table([]string{"SCORE", "", "MODULE", "VERSION", "PENALTIES"}, rows)
	o.Heading("Breakdown")
	for _, m := range res.Modules {
		o.Printf("  %s %s\n", o.Bold(m.Dep.String()), o.Dim(fmt.Sprintf("base %d", m.Base)))
		for _, cp := range m.Components {
			if !cp.Available {
				o.Printf("    %-12s %s\n", cp.Name, o.Dim(firstNonEmpty(cp.Detail, "no data")))
				continue
			}
			o.Printf("    %-12s %5.1f/%-3.0f %s\n", cp.Name, cp.Points, cp.Max, o.Dim(cp.Detail))
		}
		for _, p := range m.Penalties {
			o.Printf("    %-12s %s\n", "penalty", o.Red(fmt.Sprintf("%d %s", p.Points, p.Reason)))
		}
	}
	if len(res.Findings) > 0 {
		o.Heading(fmt.Sprintf("Below --min-score %d", res.MinScore))
		printFindings(c, res.Findings)
	}
}
