package compliance

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/alert"
	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/feeds"
	"github.com/slash-mark-dev/go-suite/internal/modfile"
	"github.com/slash-mark-dev/go-suite/internal/modproxy"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/project"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/semver"
	"github.com/slash-mark-dev/go-suite/internal/ui"
	"github.com/slash-mark-dev/go-suite/internal/vulndb"
)

// RadarRelease is a new module version seen in the module index.
type RadarRelease struct {
	Module    string    `json:"module"`
	Version   string    `json:"version"`
	Published time.Time `json:"published"`
	// Tracked is the module path being watched when it differs from
	// Module (a new major version path such as example.com/m/v2).
	Tracked string `json:"tracked,omitempty"`
	// Current is the version the project uses ("" when unknown).
	Current string `json:"current,omitempty"`
	Direct  bool   `json:"direct"`
	// Kind is patch, minor, major, older (not above the current version),
	// new (no current version to compare with) or pseudo.
	Kind         string `json:"kind"`
	NewMajorPath bool   `json:"newMajorPath,omitempty"`
	Prerelease   bool   `json:"prerelease,omitempty"`
	Retracted    bool   `json:"retracted,omitempty"`
	RetractNote  string `json:"retractRationale,omitempty"`
	// CurrentRetracted means this release's go.mod retracts the version
	// in use.
	CurrentRetracted bool `json:"currentRetracted,omitempty"`
	// Fixes are vulnerabilities affecting the current version that this
	// release fixes.
	Fixes    []string        `json:"fixes,omitempty"`
	Severity report.Severity `json:"severity"`

	curNote string // rationale of the retraction of Current
}

// RadarResult is the result of the radar tool.
type RadarResult struct {
	Main    string    `json:"main,omitempty"`
	Tracked int       `json:"tracked"`
	Since   time.Time `json:"since"`
	// Cursor is the index position reached (the next poll starts there).
	Cursor   time.Time        `json:"cursor"`
	Complete bool             `json:"complete"` // the index was read to its end
	Polls    int              `json:"polls"`
	Entries  int              `json:"entries"` // index entries read
	Skipped  int              `json:"skippedPseudo"`
	Releases []*RadarRelease  `json:"releases"`
	Alerts   int              `json:"alerts"` // alert messages delivered
	State    string           `json:"state,omitempty"`
	Findings []report.Finding `json:"findings"`
	Summary  map[string]int   `json:"summary"`
	Failing  int              `json:"failing"`
}

var radarFlags struct {
	all, follow, pseudo         *bool
	watch, since, state         *string
	slack, teams, discord, hook *string
	interval                    *time.Duration
	polls, pageSize             *int
	failOn, alertOn             func() (report.Severity, error)
}

// Environment variables used when the alert flags are not given.
const (
	envSlack   = "SMGO_SLACK_WEBHOOK"
	envTeams   = "SMGO_TEAMS_WEBHOOK"
	envDiscord = "SMGO_DISCORD_WEBHOOK"
	envWebhook = "SMGO_WEBHOOK_URL"
)

func init() {
	cli.Register(&cli.Tool{
		Name:    "radar",
		Group:   group,
		Summary: "Live release radar for your dependencies from the Go module index",
		Usage:   "sm-go radar [module paths or patterns] [flags]",
		Help: `Reads index.golang.org for module versions published since --since (a duration such as 24h or
7d, or an RFC 3339 time; default 24h) and reports those of the project's direct dependencies
(--all: the whole build list). Module paths given as arguments or listed in a --watch file (one
per line, # comments) are watched instead; "path" also covers its major-version paths
(path/v2...), "prefix/..." everything below prefix, globs work as in GOPRIVATE, and
"path@version" sets the version to compare with (needed for modules outside the build list).

Each new version is classified against the version in use:
  patch / minor / major    including a new major version path (example.com/m/v2) appearing
  older                    a release below the version in use (backport)
  pre-release, retracted   checked against the newest go.mod's retract directives
  fixes                    vulnerabilities (Go vulnerability database) affecting the version in
                           use that the new version no longer has; such releases are high severity
  current retracted        the new release retracts the version in use (medium)
Pseudo-versions are ignored unless --pseudo.

--follow keeps polling every --interval (default 5m) until interrupted (or --polls N). The index
position is saved in a state file (--state, default under the sm-go cache directory, keyed by
project and watch list) so a restart neither misses nor repeats releases; --state also makes
one-shot runs (e.g. from cron) incremental. When a state file has a position, --since is not used.

Alerts go to --slack, --teams, --discord and --webhook URLs (or $` + envSlack + `, $` + envTeams + `,
$` + envDiscord + `, $` + envWebhook + `) only when there are new releases at or above
--alert-on (default info: all). The state only advances once alerts are delivered.
Releases at or above --fail-on (default high: vulnerability fixes) exit with code 1.`,
		Examples: []string{
			"sm-go radar",
			"sm-go radar --all --since 7d",
			"sm-go radar golang.org/x/... github.com/myorg/",
			"sm-go radar --follow --interval 10m --slack https://hooks.slack.com/services/...",
			"sm-go radar --state radar.json --alert-on low --webhook https://ci.example.com/hook",
		},
		Sources: []string{"Go module index", "Go module proxy", "Go vulnerability database"},
		Flags: func(fs *flag.FlagSet) {
			radarFlags.all = fs.Bool("all", false, "watch the whole build list, not just direct dependencies")
			radarFlags.watch = fs.String("watch", "", "`file` listing module paths or patterns to watch")
			radarFlags.since = fs.String("since", "24h", "start `time`: a duration ago (24h, 7d) or an RFC 3339 time")
			radarFlags.follow = fs.Bool("follow", false, "keep polling the index")
			radarFlags.interval = fs.Duration("interval", 5*time.Minute, "polling `interval` with --follow")
			radarFlags.polls = fs.Int("polls", 0, "with --follow, stop after `n` polls (0: until interrupted)")
			radarFlags.state = fs.String("state", "", "state `file` keeping the index position (default with --follow: in the cache dir)")
			radarFlags.pseudo = fs.Bool("pseudo", false, "include pseudo-versions")
			radarFlags.slack = fs.String("slack", "", "Slack incoming webhook `url`")
			radarFlags.teams = fs.String("teams", "", "Microsoft Teams webhook `url`")
			radarFlags.discord = fs.String("discord", "", "Discord webhook `url`")
			radarFlags.hook = fs.String("webhook", "", "generic JSON webhook `url`")
			radarFlags.alertOn = cli.SeverityFlag(fs, "alert-on", "info", "minimum release `severity` that triggers alerts")
			radarFlags.failOn = cli.SeverityFlag(fs, "fail-on", "high", "minimum release `severity` that fails the run")
			radarFlags.pageSize = fs.Int("page-size", 2000, "index entries per request (`n`, at most 2000)")
		},
		Run: runRadar,
	})
}

// radarTarget is a watched module.
type radarTarget struct {
	Path    string
	Version string // in use ("" unknown)
	Direct  bool
	prefix  string
	major   int
}

// radarState is persisted between runs.
type radarState struct {
	Cursor  time.Time `json:"cursor"`
	Seen    []string  `json:"seen,omitempty"` // index keys at Cursor already processed
	Updated time.Time `json:"updated"`
	Project string    `json:"project,omitempty"`
}

type radar struct {
	c        *cli.Context
	res      *RadarResult
	byPath   map[string]*radarTarget
	byPrefix map[string][]*radarTarget
	patterns []string // prefix and glob patterns
	mains    map[string]bool
	cursor   time.Time
	seen     []string
	targets  []alert.Target
	alertOn  report.Severity
	failOn   report.Severity
	pseudo   bool
	pageSize int
}

const radarMaxPages = 500

func runRadar(c *cli.Context) error {
	failOn, err := radarFlags.failOn()
	if err != nil {
		return err
	}
	alertOn, err := radarFlags.alertOn()
	if err != nil {
		return err
	}
	follow := *radarFlags.follow
	if follow && *radarFlags.interval <= 0 {
		return cli.Usagef("--interval must be positive")
	}
	if *radarFlags.polls < 0 {
		return cli.Usagef("--polls must not be negative")
	}
	since, err := parseSince(*radarFlags.since, time.Now())
	if err != nil {
		return cli.Usagef("--since: %v", err)
	}
	r := &radar{c: c, alertOn: alertOn, failOn: failOn, pseudo: *radarFlags.pseudo, pageSize: *radarFlags.pageSize,
		byPath: map[string]*radarTarget{}, byPrefix: map[string][]*radarTarget{}, mains: map[string]bool{},
		res: &RadarResult{Releases: []*RadarRelease{}, Findings: []report.Finding{}, Since: since}}
	if r.pageSize <= 0 || r.pageSize > 2000 {
		return cli.Usagef("--page-size must be between 1 and 2000")
	}
	r.targets = alert.Targets(firstNonEmpty(*radarFlags.slack, c.Env.Getenv(envSlack)), firstNonEmpty(*radarFlags.teams, c.Env.Getenv(envTeams)),
		firstNonEmpty(*radarFlags.discord, c.Env.Getenv(envDiscord)), firstNonEmpty(*radarFlags.hook, c.Env.Getenv(envWebhook)))
	watch := append([]string{}, c.Args...)
	if *radarFlags.watch != "" {
		w, err := readWatchFile(*radarFlags.watch)
		if err != nil {
			return cli.Usagef("--watch: %v", err)
		}
		watch = append(watch, w...)
	}
	projDir, err := r.loadTargets(watch)
	if err != nil {
		return err
	}
	r.res.Tracked = len(r.byPath)

	statePath := *radarFlags.state
	if statePath == "" && follow {
		statePath = defaultStatePath(c, projDir, watch, *radarFlags.all)
	}
	r.cursor = since
	if statePath != "" {
		r.res.State = statePath
		st, err := loadRadarState(statePath)
		if err != nil {
			return err
		}
		if st != nil && !st.Cursor.IsZero() {
			r.cursor, r.seen = st.Cursor, st.Seen
			r.res.Since = st.Cursor
			c.Logf("resuming from %s (%s)", st.Cursor.Format(time.RFC3339Nano), statePath)
		}
	}
	r.res.Cursor = r.cursor

	if c.Text() {
		o := c.Out
		subject := r.res.Main
		if subject == "" {
			subject = "watched modules"
		}
		o.Title("sm-go radar · " + subject)
		o.Printf("watching %s for releases since %s", ui.Plural(r.res.Tracked, "module", "modules"), r.res.Since.Local().Format("2006-01-02 15:04 MST"))
		if len(r.patterns) > 0 {
			o.Printf(" + %s", ui.Plural(len(r.patterns), "pattern", "patterns"))
		}
		if follow {
			o.Printf(" · polling every %s", *radarFlags.interval)
		}
		o.Println()
	}

	for i := 0; ; i++ {
		complete, err := r.poll(statePath)
		if err != nil {
			if c.Ctx.Err() != nil {
				break
			}
			if !follow {
				return err
			}
			c.Warnf("index poll failed: %v", err)
		}
		if !follow || (*radarFlags.polls > 0 && i+1 >= *radarFlags.polls) {
			break
		}
		if err == nil && !complete {
			continue // not caught up yet: read on immediately
		}
		select {
		case <-c.Ctx.Done():
		case <-time.After(*radarFlags.interval):
		}
		if c.Ctx.Err() != nil {
			break
		}
	}

	res := r.res
	sort.SliceStable(res.Releases, func(i, j int) bool {
		a, b := res.Releases[i], res.Releases[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		return semver.Compare(a.Version, b.Version) < 0
	})
	report.SortFindings(res.Findings)
	res.Summary = sevCounts(res.Findings)
	failing := 0
	for _, rel := range res.Releases {
		if rel.Severity.Meets(failOn) {
			failing++
		}
	}
	res.Failing = failing
	c.SetResult(res)
	if failing > 0 {
		c.Issues()
	}
	if c.Text() {
		printRadarSummary(c, res, failOn)
	}
	return nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// parseSince accepts a duration ("24h", "7d", "1d12h") or an RFC 3339
// time or date.
func parseSince(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}
	d := time.Duration(0)
	rest := s
	if i := strings.Index(rest, "d"); i > 0 {
		n, err := strconv.Atoi(rest[:i])
		if err != nil {
			return time.Time{}, fmt.Errorf("bad time %q (use e.g. 24h, 7d or 2025-06-01T00:00:00Z)", s)
		}
		d = time.Duration(n) * 24 * time.Hour
		rest = rest[i+1:]
	}
	if rest != "" {
		x, err := time.ParseDuration(rest)
		if err != nil {
			return time.Time{}, fmt.Errorf("bad time %q (use e.g. 24h, 7d or 2025-06-01T00:00:00Z)", s)
		}
		d += x
	}
	if d <= 0 {
		return time.Time{}, fmt.Errorf("duration %q must be positive", s)
	}
	return now.Add(-d).UTC(), nil
}

func readWatchFile(name string) ([]string, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		for _, f := range strings.Fields(line) {
			out = append(out, f)
		}
	}
	return out, nil
}

func majorNum(pathMajor string) int {
	s := strings.TrimLeft(pathMajor, "/.v")
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return 1
}

func (r *radar) addTarget(path, version string, direct bool) {
	if t := r.byPath[path]; t != nil {
		if t.Version == "" {
			t.Version = version
		}
		return
	}
	prefix, pm, _ := module.SplitPathVersion(path)
	t := &radarTarget{Path: path, Version: version, Direct: direct, prefix: prefix, major: majorNum(pm)}
	r.byPath[path] = t
	r.byPrefix[prefix] = append(r.byPrefix[prefix], t)
}

func isPattern(p string) bool {
	return strings.HasSuffix(p, "/...") || strings.HasSuffix(p, "/") || strings.ContainsAny(p, "*?[")
}

func matchWatch(pattern, path string) bool {
	switch {
	case strings.HasSuffix(pattern, "/..."):
		base := strings.TrimSuffix(pattern, "/...")
		return path == base || strings.HasPrefix(path, base+"/")
	case isPattern(pattern):
		return module.MatchPrefixPatterns(pattern, path)
	}
	if path == pattern {
		return true
	}
	a, _, _ := module.SplitPathVersion(path)
	b, _, _ := module.SplitPathVersion(pattern)
	return a == b
}

// loadTargets builds the watch list and returns the project directory
// ("" outside a module).
func (r *radar) loadTargets(watch []string) (string, error) {
	c := r.c
	p, perr := c.Project()
	if perr != nil && !(errors.Is(perr, project.ErrNoModule) && len(watch) > 0) {
		if errors.Is(perr, project.ErrNoModule) {
			return "", cli.Usagef("run inside a Go module or name the modules to watch")
		}
		return "", perr
	}
	var explicit []string
	versions := map[string]string{}
	for _, w := range watch {
		path, version, _ := strings.Cut(w, "@")
		if version != "" && !semver.IsValid(version) {
			return "", cli.Usagef("bad version in %q", w)
		}
		if isPattern(path) {
			if _, err := filepathMatchCheck(path); err != nil {
				return "", cli.Usagef("bad pattern %q: %v", path, err)
			}
			r.patterns = append(r.patterns, path)
			continue
		}
		if err := module.CheckPath(path); err != nil {
			return "", cli.Usagef("%v", err)
		}
		explicit = append(explicit, path)
		versions[path] = version
	}
	dir := ""
	if p != nil {
		dir = p.Dir
		r.res.Main = p.ModulePath()
		for _, m := range p.Mains {
			r.mains[m.Path()] = true
		}
		g, err := c.Graph()
		if err != nil {
			return "", err
		}
		for _, m := range g.BuildList() {
			direct := g.IsDirect(m.Path)
			if len(watch) == 0 {
				if direct || *radarFlags.all {
					r.addTarget(m.Path, m.Version, direct)
				}
				continue
			}
			for _, w := range append(append([]string{}, explicit...), r.patterns...) {
				if matchWatch(w, m.Path) {
					r.addTarget(m.Path, m.Version, direct)
					break
				}
			}
		}
	}
	for _, path := range explicit {
		if versions[path] != "" {
			if t := r.byPath[path]; t != nil {
				t.Version = versions[path]
			}
		}
		r.addTarget(path, versions[path], false)
	}
	return dir, nil
}

func filepathMatchCheck(p string) (bool, error) {
	return filepath.Match(strings.TrimSuffix(strings.TrimSuffix(p, "/..."), "/"), "x")
}

func defaultStatePath(c *cli.Context, projDir string, watch []string, all bool) string {
	w := append([]string{}, watch...)
	sort.Strings(w)
	h := sha256.Sum256([]byte(fmt.Sprintf("%s\n%s\n%v", projDir, strings.Join(w, "\n"), all)))
	return filepath.Join(c.Env.CacheDir(), "radar", hex.EncodeToString(h[:8])+".json")
}

func loadRadarState(path string) (*radarState, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st radarState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("state file %s: %v", path, err)
	}
	return &st, nil
}

func saveRadarState(path string, st *radarState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// poll reads the index from the cursor, classifies, alerts and saves the
// state. complete reports whether the index was read to its end.
func (r *radar) poll(statePath string) (bool, error) {
	c := r.c
	ctx := c.Ctx
	page, err := feeds.IndexSince(ctx, c.HTTP(), c.Endpoint("index"), r.cursor, r.seen, r.pageSize, radarMaxPages)
	if err != nil && (page == nil || len(page.Entries) == 0) {
		return false, fmt.Errorf("module index: %v", err)
	}
	if err != nil {
		c.Warnf("module index: %v (continuing with the %d entries read)", err, len(page.Entries))
	}
	r.res.Polls++
	r.res.Entries += len(page.Entries)
	r.res.Complete = page.Complete && err == nil
	if !page.Complete && err == nil {
		c.Warnf("module index not caught up after %d pages; continuing from %s", radarMaxPages, page.Next.Format(time.RFC3339))
	}
	rels := r.classify(page.Entries)
	r.enrich(ctx, rels, page.Entries)
	for _, rel := range rels {
		rel.Severity = releaseSeverity(rel)
	}
	sort.SliceStable(rels, func(i, j int) bool {
		if rels[i].Module != rels[j].Module {
			return rels[i].Module < rels[j].Module
		}
		return semver.Compare(rels[i].Version, rels[j].Version) < 0
	})

	advance := true
	if alertRels := atLeastRel(rels, r.alertOn); len(alertRels) > 0 && len(r.targets) > 0 {
		if err := alert.Send(ctx, c.HTTP(), r.targets, r.message(alertRels)); err != nil {
			c.Warnf("%v (the index position is kept so the next run retries)", err)
			advance = false
		} else {
			r.res.Alerts++
		}
	}
	r.res.Releases = append(r.res.Releases, rels...)
	r.res.Findings = append(r.res.Findings, releaseFindings(rels)...)
	if c.Text() && (len(rels) > 0 || *radarFlags.follow) {
		printRadarPoll(c, rels, page.Next)
	}
	if advance {
		r.cursor, r.seen = page.Next, page.NextSeen
		r.res.Cursor = r.cursor
		if statePath != "" {
			st := &radarState{Cursor: r.cursor, Seen: r.seen, Updated: time.Now().UTC(), Project: r.res.Main}
			if err := saveRadarState(statePath, st); err != nil {
				c.Warnf("saving state: %v", err)
			}
		}
	}
	return page.Complete, nil
}

// classify turns index entries into releases of watched modules.
func (r *radar) classify(entries []feeds.IndexEntry) []*RadarRelease {
	var out []*RadarRelease
	seen := map[string]bool{}
	for _, e := range entries {
		if r.mains[e.Path] || !semver.IsValid(e.Version) || seen[feeds.IndexKey(e)] {
			continue
		}
		seen[feeds.IndexKey(e)] = true
		rel := &RadarRelease{Module: e.Path, Version: e.Version, Published: e.Timestamp,
			Prerelease: semver.Prerelease(e.Version) != "" && !module.IsPseudoVersion(e.Version)}
		if t := r.byPath[e.Path]; t != nil {
			rel.Current, rel.Direct = t.Version, t.Direct
			rel.Kind = versionKind(t.Version, e.Version)
		} else if ts := r.byPrefix[pathPrefix(e.Path)]; len(ts) > 0 {
			// Another major version path of a watched module.
			t := ts[0]
			for _, x := range ts[1:] {
				if x.major > t.major {
					t = x
				}
			}
			_, pm, _ := module.SplitPathVersion(e.Path)
			rel.Tracked, rel.Current, rel.Direct = t.Path, t.Version, t.Direct
			if majorNum(pm) > t.major {
				rel.Kind, rel.NewMajorPath = "major", true
			} else {
				rel.Kind = "older"
			}
		} else if r.matchesPattern(e.Path) {
			rel.Kind = "new"
		} else {
			continue
		}
		if module.IsPseudoVersion(e.Version) {
			if !r.pseudo {
				r.res.Skipped++
				continue
			}
			rel.Kind = "pseudo"
		}
		if rel.Current == e.Version && rel.Tracked == "" {
			continue
		}
		out = append(out, rel)
	}
	return out
}

func pathPrefix(p string) string {
	prefix, _, _ := module.SplitPathVersion(p)
	return prefix
}

func (r *radar) matchesPattern(path string) bool {
	for _, p := range r.patterns {
		if matchWatch(p, path) {
			return true
		}
	}
	return false
}

func versionKind(cur, v string) string {
	switch {
	case cur == "":
		return "new"
	case semver.Compare(v, cur) <= 0:
		return "older"
	case semver.Major(v) != semver.Major(cur):
		return "major"
	case semver.MajorMinor(v) != semver.MajorMinor(cur):
		return "minor"
	}
	return "patch"
}

// enrich adds retraction and vulnerability information.
func (r *radar) enrich(ctx context.Context, rels []*RadarRelease, entries []feeds.IndexEntry) {
	if len(rels) == 0 {
		return
	}
	c := r.c
	// A fresh proxy client per poll: version lists must not be the ones
	// cached by an earlier poll.
	proxy := modproxy.New(c.Env, c.HTTP())
	newVersions := map[string][]string{}
	for _, e := range entries {
		if semver.IsValid(e.Version) && !module.IsPseudoVersion(e.Version) {
			newVersions[e.Path] = append(newVersions[e.Path], e.Version)
		}
	}
	paths := map[string]bool{}
	for _, rel := range rels {
		paths[rel.Module] = true
	}
	retract := map[string][]*modfile.Retract{}
	for p := range paths {
		vs, err := proxy.Versions(ctx, p)
		if err != nil && !errors.Is(err, modproxy.ErrNotFound) {
			c.Warnf("%s: version list: %v", p, err)
		}
		latest := latestRelease(append(vs, newVersions[p]...))
		if latest == "" {
			continue
		}
		gm, err := proxy.GoMod(ctx, p, latest)
		if err != nil {
			c.Warnf("%s@%s: go.mod: %v (retractions not checked)", p, latest, err)
			continue
		}
		retract[p] = modfile.Parse(p+"@"+latest+"/go.mod", gm).Retract
	}
	isRetracted := func(path, v string) (bool, string) {
		for _, x := range retract[path] {
			if x.Contains(v) {
				return true, x.Rationale
			}
		}
		return false, ""
	}
	var mods []module.Version
	seenMod := map[string]bool{}
	for _, rel := range rels {
		rel.Retracted, rel.RetractNote = isRetracted(rel.Module, rel.Version)
		if rel.Tracked == "" && rel.Current != "" {
			rel.CurrentRetracted, rel.curNote = isRetracted(rel.Module, rel.Current)
			if !seenMod[rel.Module] {
				seenMod[rel.Module] = true
				mods = append(mods, module.Version{Path: rel.Module, Version: rel.Current})
			}
		}
	}
	if len(mods) == 0 {
		return
	}
	vf, err := vulndb.New(c.Endpoint("vulndb"), c.HTTP()).ForModules(ctx, mods)
	if err != nil {
		c.Warnf("vulnerability database: %v (vulnerability fixes not checked)", err)
		return
	}
	for _, rel := range rels {
		if rel.Tracked != "" || rel.Current == "" || semver.Compare(rel.Version, rel.Current) <= 0 {
			continue
		}
		for _, f := range vf {
			if f.Module.Path == rel.Module && !f.Affected.AffectsVersion(rel.Version) {
				rel.Fixes = append(rel.Fixes, f.ID)
			}
		}
	}
}

// latestRelease is the version whose go.mod holds a module's retractions:
// the highest release, else the highest pre-release.
func latestRelease(vs []string) string {
	best, bestPre := "", ""
	for _, v := range vs {
		if !semver.IsValid(v) || module.IsPseudoVersion(v) {
			continue
		}
		if semver.Prerelease(v) != "" {
			if bestPre == "" || semver.Compare(v, bestPre) > 0 {
				bestPre = v
			}
		} else if best == "" || semver.Compare(v, best) > 0 {
			best = v
		}
	}
	if best != "" {
		return best
	}
	return bestPre
}

func releaseSeverity(rel *RadarRelease) report.Severity {
	switch {
	case len(rel.Fixes) > 0 && !rel.Retracted:
		return report.High
	case rel.CurrentRetracted || len(rel.Fixes) > 0:
		return report.Medium
	case rel.Kind == "major":
		return report.Low
	}
	return report.Info
}

// releaseFindings summarizes one poll's releases per module: the
// vulnerabilities in the version in use that new releases fix, and new
// releases retracting the version in use.
func releaseFindings(rels []*RadarRelease) []report.Finding {
	var out []report.Finding
	byMod := map[string][]*RadarRelease{}
	var mods []string
	for _, rel := range rels {
		if rel.Tracked != "" || rel.Current == "" {
			continue
		}
		if byMod[rel.Module] == nil {
			mods = append(mods, rel.Module)
		}
		byMod[rel.Module] = append(byMod[rel.Module], rel)
	}
	sort.Strings(mods)
	for _, mod := range mods {
		list := byMod[mod]
		sort.Slice(list, func(i, j int) bool { return semver.Compare(list[i].Version, list[j].Version) < 0 })
		cur := list[0].Current
		var fixing, fixed []string
		seenID := map[string]bool{}
		sev := report.None
		var upgrade, newest *RadarRelease
		for _, rel := range list {
			if !rel.Retracted && (newest == nil || semver.Compare(rel.Version, newest.Version) > 0) {
				newest = rel
			}
			if len(rel.Fixes) == 0 {
				continue
			}
			fixing = append(fixing, rel.Version)
			for _, id := range rel.Fixes {
				if !seenID[id] {
					seenID[id] = true
					fixed = append(fixed, id)
				}
			}
			if rel.Severity > sev {
				sev = rel.Severity
			}
			// Prefer the lowest stable, non-retracted fixing release.
			if !rel.Retracted && (upgrade == nil || (upgrade.Prerelease && !rel.Prerelease)) {
				upgrade = rel
			}
		}
		if len(fixed) > 0 {
			f := report.Finding{Severity: sev, Rule: "radar-vuln-fix", Module: mod, Version: cur,
				Title:  fmt.Sprintf("new %s fix %s affecting %s", map[bool]string{true: "release", false: "releases"}[len(fixing) == 1], strings.Join(fixed, ", "), cur),
				Detail: "fixed in " + strings.Join(fixing, ", "), URL: "https://pkg.go.dev/vuln/" + fixed[0]}
			if upgrade != nil {
				f.Fix = "go get " + mod + "@" + upgrade.Version
			}
			out = append(out, f)
		}
		for _, rel := range list {
			if rel.CurrentRetracted {
				f := report.Finding{Severity: report.Medium, Rule: "radar-current-retracted", Module: mod, Version: cur,
					Title: fmt.Sprintf("the version in use (%s) has been retracted", cur)}
				if rel.curNote != "" {
					f.Detail = "rationale: " + rel.curNote
				}
				if newest != nil {
					f.Fix = "go get " + mod + "@" + newest.Version
				}
				out = append(out, f)
				break
			}
		}
	}
	return out
}

func atLeastRel(rels []*RadarRelease, min report.Severity) []*RadarRelease {
	var out []*RadarRelease
	for _, r := range rels {
		if r.Severity.Meets(min) {
			out = append(out, r)
		}
	}
	return out
}

// describeRelease is the one-line text used in alerts and follow output.
func describeRelease(rel *RadarRelease) string {
	var b strings.Builder
	b.WriteString(rel.Module + " ")
	if rel.Current != "" && rel.Tracked == "" {
		b.WriteString(rel.Current + " → ")
	}
	b.WriteString(rel.Version)
	var tags []string
	tags = append(tags, rel.Kind)
	if rel.NewMajorPath {
		tags[0] = "new major version path of " + rel.Tracked
	}
	if rel.Prerelease {
		tags = append(tags, "pre-release")
	}
	if rel.Retracted {
		tags = append(tags, "retracted")
	}
	if rel.CurrentRetracted {
		tags = append(tags, "retracts "+rel.Current)
	}
	if len(rel.Fixes) > 0 {
		tags = append(tags, "fixes "+strings.Join(rel.Fixes, ", "))
	}
	b.WriteString(" (" + strings.Join(tags, "; ") + ")")
	return b.String()
}

func (r *radar) message(rels []*RadarRelease) alert.Message {
	subject := r.res.Main
	if subject == "" {
		subject = "watched modules"
	}
	m := alert.Message{Title: fmt.Sprintf("sm-go radar: %s for %s", ui.Plural(len(rels), "new release", "new releases"), subject), Data: rels}
	max := report.None
	for _, rel := range rels {
		line := "• " + describeRelease(rel)
		m.Lines = append(m.Lines, line)
		if rel.Severity > max {
			max = rel.Severity
		}
		if len(rel.Fixes) > 0 && m.URL == "" {
			m.URL = "https://pkg.go.dev/vuln/" + rel.Fixes[0]
		}
	}
	m.Severity = max.String()
	return m
}

func printRadarPoll(c *cli.Context, rels []*RadarRelease, cursor time.Time) {
	o := c.Out
	if *radarFlags.follow {
		stamp := o.Dim(time.Now().Format("15:04:05"))
		if len(rels) == 0 {
			o.Printf("%s %s\n", stamp, o.Dim("no new releases (index at "+cursor.Local().Format("15:04:05")+")"))
			return
		}
		for _, rel := range rels {
			o.Printf("%s %s %s\n", stamp, o.Sev(rel.Severity), describeRelease(rel))
		}
		return
	}
	var rows [][]string
	for _, rel := range rels {
		kind := rel.Kind
		if rel.NewMajorPath {
			kind = "major (new path)"
		}
		var notes []string
		if rel.Prerelease {
			notes = append(notes, "pre-release")
		}
		if rel.Retracted {
			notes = append(notes, o.Yellow("retracted"))
		}
		if rel.CurrentRetracted {
			notes = append(notes, o.Yellow("retracts "+rel.Current))
		}
		if len(rel.Fixes) > 0 {
			notes = append(notes, o.Red("fixes "+strings.Join(rel.Fixes, ", ")))
		}
		cur := rel.Current
		if cur == "" {
			cur = "-"
		}
		rows = append(rows, []string{o.Sev(rel.Severity), rel.Module, cur, rel.Version, kind,
			rel.Published.Local().Format("01-02 15:04"), strings.Join(notes, ", ")})
	}
	o.Println()
	o.Table([]string{"", "MODULE", "IN USE", "NEW", "KIND", "PUBLISHED", "NOTES"}, rows)
}

func printRadarSummary(c *cli.Context, res *RadarResult, failOn report.Severity) {
	o := c.Out
	if len(res.Findings) > 0 {
		o.Heading("Findings")
		printFindings(c, res.Findings)
	}
	o.Println()
	extra := ""
	if res.Skipped > 0 {
		extra = fmt.Sprintf(", %s ignored", ui.Plural(res.Skipped, "pseudo-version", "pseudo-versions"))
	}
	if res.Alerts > 0 {
		extra += fmt.Sprintf(", %s sent", ui.Plural(res.Alerts, "alert", "alerts"))
	}
	o.Printf("%s read in %s%s\n", ui.Plural(res.Entries, "index entry", "index entries"), ui.Plural(res.Polls, "poll", "polls"), extra)
	switch {
	case res.Failing > 0:
		o.Bad("%s at or above %s (%s)", ui.Plural(res.Failing, "new release", "new releases"), failOn, countLine(res.Summary))
	case len(res.Releases) > 0:
		o.OK("%s, none at or above the failure threshold", ui.Plural(len(res.Releases), "new release", "new releases"))
	default:
		o.OK("no new releases of watched modules")
	}
}
