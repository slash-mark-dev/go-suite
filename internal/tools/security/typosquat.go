package security

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"sort"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/feeds"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/par"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/semver"
	"github.com/slash-mark-dev/go-suite/internal/ui"
)

// Typosquatting techniques.
const (
	TechOwnDomain     = "own-domain-lookalike" // imitates the project's own domain or GitHub owner
	TechHost          = "host-lookalike"       // githhub.com/spf13/cobra
	TechHostSwap      = "host-swap"            // gitlab.com/spf13/cobra
	TechCase          = "case-variant"         // github.com/Sirupsen/logrus
	TechHomoglyph     = "homoglyph"            // github.com/gorllla/mux (i/l, 0/o, rn/m, ...)
	TechTransposition = "transposition"        // github.com/siruspen/logrus
	TechSeparator     = "separator-variant"    // github.com/spf-13/cobra
	TechEdit          = "edit-distance"        // github.com/gooogle/uuid
	TechOwnerSwap     = "owner-swap"           // github.com/evil/logrus
)

// Suspect is a module path that resembles a popular (or the project's
// own) module path.
type Suspect struct {
	Module    string          `json:"module"`
	Version   string          `json:"version,omitempty"`
	Target    string          `json:"target"`
	Technique string          `json:"technique"`
	Distance  int             `json:"distance"`
	Severity  report.Severity `json:"severity"`
	Detail    string          `json:"detail"`
	// Dependents is the deps.dev dependent count of the suspect, when
	// available.
	Dependents *int `json:"dependents,omitempty"`
	// PopularitySkipped is "skipped: private module" when deps.dev was not
	// asked because the suspect is private (GOPRIVATE, GONOPROXY,
	// GONOSUMDB).
	PopularitySkipped string `json:"popularitySkipped,omitempty"`
}

// TyposquatResult is the result of the typosquat tool.
type TyposquatResult struct {
	Checked   int              `json:"checked"`
	Reference int              `json:"reference"` // popular module paths compared against
	OwnDomain string           `json:"ownDomain,omitempty"`
	Suspects  []*Suspect       `json:"suspects"`
	Findings  []report.Finding `json:"findings"`
	Failing   int              `json:"failing"`
}

var typoFlags struct {
	failOn  func() (report.Severity, error)
	noDeps  *bool
	popular cli.StringList
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "typosquat",
		Group:   group,
		Summary: "Typosquatting and lookalike module paths in the build list",
		Usage:   "sm-go typosquat [module[@version] ...] [flags]",
		Help: `Compares every module path in the build list (or the paths given as arguments) with a
built-in list of widely used Go modules and with the project's own domain or GitHub owner,
looking for the tricks typosquatters use:

  own-domain-lookalike  a dependency on slashmrk.in when your module is slashmark.in/... (critical)
  host-lookalike        githhub.com/spf13/cobra                                         (critical)
  homoglyph             github.com/gorllla/mux, rn/m, 0/o, 1/l, vv/w, cl/d             (high)
  transposition         github.com/siruspen/logrus                                      (high)
  edit-distance         github.com/gooogle/uuid (one edit; two for long paths)          (high/medium)
  case-variant          github.com/Sirupsen/logrus                                      (medium)
  separator-variant     github.com/spf-13/cobra                                         (medium)
  host-swap             gitlab.com/spf13/cobra                                          (medium)
  owner-swap            github.com/someone/logrus (fork or impostor)                    (low)

Paths under the same owner (host/owner on code hosts, the domain elsewhere) as the popular
module are never flagged. When deps.dev is reachable, suspects with many dependents are
downgraded (likely legitimate forks) and those with almost none are marked.`,
		Examples: []string{
			"sm-go typosquat",
			"sm-go typosquat github.com/sirupsen/logrus@v1.9.3 github.com/spf13/cobra",
			"sm-go typosquat --popular example.com/internal/lib --json",
		},
		Sources: []string{"built-in list of popular Go modules", "deps.dev"},
		Flags: func(fs *flag.FlagSet) {
			typoFlags.popular = nil
			fs.Var(&typoFlags.popular, "popular", "extra module `paths` to protect (comma-separated or repeated)")
			typoFlags.noDeps = fs.Bool("no-depsdev", false, "do not query deps.dev for popularity")
			typoFlags.failOn = cli.SeverityFlag(fs, "fail-on", "high", "minimum `severity` that fails the run")
		},
		Run: runTyposquat,
	})
}

func runTyposquat(c *cli.Context) error {
	failOn, err := typoFlags.failOn()
	if err != nil {
		return err
	}
	var cands []module.Version
	for _, a := range c.Args {
		p, v, _ := strings.Cut(a, "@")
		if err := module.CheckPath(p); err != nil {
			return cli.Usagef("%q: %v", a, err)
		}
		if v != "" && !semver.IsValid(v) {
			return cli.Usagef("%q: invalid version %q", a, v)
		}
		cands = append(cands, module.Version{Path: p, Version: v})
	}
	ownPath := ""
	proj, perr := c.Project()
	if perr == nil {
		ownPath = proj.ModulePath()
	}
	mains := map[string]bool{}
	if len(cands) == 0 {
		if perr != nil {
			return perr
		}
		g, err := c.Graph()
		if err != nil {
			return err
		}
		cands = g.BuildList()
		for _, m := range g.Mains {
			mains[m.Path] = true
		}
	}
	ref := append(append([]string(nil), popularModules...), typoFlags.popular...)
	res := &TyposquatResult{Checked: len(cands), Reference: len(ref), Suspects: []*Suspect{}, Findings: []report.Finding{}}
	own := ""
	if ownPath != "" {
		own = authority(normPath(ownPath))
		res.OwnDomain = own
	}
	refSet := map[string]bool{}
	for _, r := range ref {
		refSet[normPath(r)] = true
	}
	for _, m := range cands {
		if mains[m.Path] {
			continue
		}
		if s := classifySquat(m, ref, refSet, own); s != nil {
			res.Suspects = append(res.Suspects, s)
		}
	}
	if !*typoFlags.noDeps && len(res.Suspects) > 0 {
		popularity(c, res.Suspects)
	}
	sort.SliceStable(res.Suspects, func(i, j int) bool {
		a, b := res.Suspects[i], res.Suspects[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		return a.Module < b.Module
	})
	for _, s := range res.Suspects {
		res.Findings = append(res.Findings, report.Finding{Severity: s.Severity, Rule: "typosquat/" + s.Technique, Module: s.Module, Version: s.Version,
			Title:  fmt.Sprintf("%s looks like %s (%s)", s.Module, s.Target, s.Technique),
			Detail: s.Detail,
			Fix:    fmt.Sprintf("confirm you meant %s; if not, replace it and audit what the lookalike's code did", s.Module)})
	}
	for _, f := range res.Findings {
		if f.Severity.Meets(failOn) {
			res.Failing++
		}
	}
	c.SetResult(res)
	if res.Failing > 0 {
		c.Issues()
	}
	if c.Text() {
		printTyposquat(c, res)
	}
	return nil
}

// popularity enriches suspects with deps.dev dependent counts.
func popularity(c *cli.Context, all []*Suspect) {
	// Private modules are never sent to deps.dev.
	var ss []*Suspect
	for _, s := range all {
		if c.SkipPrivate(s.Module) {
			s.PopularitySkipped = feeds.ErrPrivate.Error()
			continue
		}
		ss = append(ss, s)
	}
	dd := c.DepsDev()
	type out struct{ n int }
	res, errs := par.Map(c.Ctx, 4, ss, func(ctx context.Context, s *Suspect) (out, error) {
		v := s.Version
		if v == "" {
			lv, err := c.Proxy().QueryLatest(ctx, s.Module)
			if err != nil {
				return out{}, err
			}
			v = lv
		}
		n, _, err := dd.Dependents(ctx, s.Module, v)
		return out{n}, err
	})
	warned := false
	for i, s := range ss {
		if errors.Is(errs[i], feeds.ErrPrivate) {
			s.PopularitySkipped = errs[i].Error()
			continue
		}
		if errs[i] != nil {
			if !warned {
				c.Warnf("deps.dev popularity unavailable (%v)", errs[i])
				warned = true
			}
			continue
		}
		n := res[i].n
		s.Dependents = &n
		switch {
		case n >= 500 && s.Technique != TechOwnDomain && s.Technique != TechHost:
			s.Severity = report.Info
			s.Detail += fmt.Sprintf("\nwidely used (%d dependents on deps.dev): probably a legitimate fork or alternative", n)
		case n < 5:
			s.Detail += fmt.Sprintf("\nalmost unused (%d dependents on deps.dev)", n)
		}
	}
}

// normPath lowercases nothing but strips the major-version suffix.
func normPath(p string) string {
	prefix, _, ok := module.SplitPathVersion(p)
	if ok {
		return prefix
	}
	return p
}

var codeHosts = map[string]bool{"github.com": true, "gitlab.com": true, "bitbucket.org": true, "gitee.com": true, "codeberg.org": true, "git.sr.ht": true}

// authority is the namespace an author controls: host/owner on code
// hosts, gopkg.in/<owner or package>, and the host elsewhere.
func authority(p string) string {
	elems := strings.Split(p, "/")
	host := elems[0]
	switch {
	case codeHosts[strings.ToLower(host)] && len(elems) >= 2:
		return strings.ToLower(host + "/" + elems[1])
	case host == "gopkg.in" && len(elems) >= 2:
		return "gopkg.in/" + strings.ToLower(strings.SplitN(elems[1], ".v", 2)[0])
	}
	return strings.ToLower(host)
}

func splitHost(p string) (host, rest string) {
	host, rest, _ = strings.Cut(p, "/")
	return host, rest
}

// skeleton folds ASCII confusables.
func skeleton(s string) string {
	s = strings.ToLower(s)
	s = strings.NewReplacer("rn", "m", "vv", "w", "cl", "d").Replace(s)
	return strings.Map(func(r rune) rune {
		switch r {
		case '0':
			return 'o'
		case '1', 'i', '|':
			return 'l'
		case '5':
			return 's'
		case '_':
			return '-'
		}
		return r
	}, s)
}

func stripSeparators(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || r == '.' {
			return -1
		}
		return r
	}, strings.ToLower(s))
}

func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// isTransposition reports whether b is a with two adjacent characters
// swapped.
func isTransposition(a, b string) bool {
	if len(a) != len(b) || a == b {
		return false
	}
	i := 0
	for i < len(a) && a[i] == b[i] {
		i++
	}
	return i+1 < len(a) && a[i] == b[i+1] && a[i+1] == b[i] && a[i+2:] == b[i+2:]
}

var genericRepoNames = map[string]bool{
	"go": true, "api": true, "sdk": true, "cli": true, "lib": true, "utils": true, "util": true, "common": true,
	"core": true, "errors": true, "log": true, "logger": true, "config": true, "client": true, "server": true,
	"mock": true, "uuid": true, "yaml": true, "json": true, "cache": true, "redis": true, "jwt": true, "cron": true,
	"decimal": true, "semver": true, "color": true, "dns": true, "ssh": true, "sftp": true, "mux": true,
}

// similarName applies the confusion techniques to two strings and
// returns the technique and distance, or "".
func similarName(a, b string, minLen int) (string, int) {
	la, lb := strings.ToLower(a), strings.ToLower(b)
	if la == lb {
		return "", 0
	}
	d := levenshtein(la, lb)
	switch {
	case skeleton(la) == skeleton(lb):
		return TechHomoglyph, d
	case isTransposition(la, lb):
		return TechTransposition, d
	case stripSeparators(la) == stripSeparators(lb):
		return TechSeparator, d
	case d == 1 && len(lb) >= minLen:
		return TechEdit, d
	case d == 2 && len(lb) >= 2*minLen:
		return TechEdit, d
	}
	return "", d
}

var techSeverity = map[string]report.Severity{
	TechOwnDomain: report.Critical, TechHost: report.Critical, TechHomoglyph: report.High, TechTransposition: report.High,
	TechCase: report.Medium, TechSeparator: report.Medium, TechHostSwap: report.Medium, TechOwnerSwap: report.Low,
}

func techRank(t string) int {
	return []int{TechOwnDomainRank: 0}[0] // placeholder, replaced below
}

const TechOwnDomainRank = 0

// classifySquat returns the most severe resemblance of m, or nil.
func classifySquat(m module.Version, ref []string, refSet map[string]bool, own string) *Suspect {
	c := normPath(m.Path)
	if refSet[c] {
		return nil
	}
	var best *Suspect
	consider := func(s *Suspect) {
		if s.Severity == report.None {
			s.Severity = techSeverity[s.Technique]
		}
		if best == nil || s.Severity > best.Severity || (s.Severity == best.Severity && s.Distance < best.Distance) {
			best = s
		}
	}
	cAuth := authority(c)
	cHost, cRest := splitHost(c)

	// The project's own namespace.
	if own != "" && cAuth != own {
		oHost, oOwner := splitHost(own)
		switch {
		case oOwner == "" && cHost != oHost:
			if t, d := similarDomain(strings.ToLower(cHost), oHost); t != "" {
				consider(&Suspect{Module: m.Path, Version: m.Version, Target: own, Technique: TechOwnDomain, Distance: d,
					Detail: fmt.Sprintf("host %s imitates your module's domain %s (%s)", cHost, oHost, t)})
			}
		case oOwner != "" && strings.EqualFold(cHost, oHost):
			cOwner, _ := splitHost(cRest)
			if t, d := similarName(cOwner, oOwner, 4); t != "" {
				consider(&Suspect{Module: m.Path, Version: m.Version, Target: own, Technique: TechOwnDomain, Distance: d,
					Detail: fmt.Sprintf("owner %s imitates your owner %s (%s)", cOwner, oOwner, t)})
			}
		}
	}

	for _, r := range ref {
		p := normPath(r)
		if c == p {
			return nil
		}
		if strings.EqualFold(c, p) {
			consider(&Suspect{Module: m.Path, Version: m.Version, Target: r, Technique: TechCase,
				Detail: fmt.Sprintf("differs from %s only in letter case; the go command treats them as different modules", r)})
			continue
		}
		pAuth := authority(p)
		if cAuth == pAuth {
			continue // same author namespace
		}
		pHost, pRest := splitHost(p)
		if !strings.EqualFold(cHost, pHost) {
			if !strings.EqualFold(cRest, pRest) || cRest == "" {
				continue
			}
			if codeHosts[strings.ToLower(cHost)] && codeHosts[strings.ToLower(pHost)] {
				consider(&Suspect{Module: m.Path, Version: m.Version, Target: r, Technique: TechHostSwap,
					Detail: fmt.Sprintf("same path as %s on another code host", r)})
			} else if t, d := similarDomain(strings.ToLower(cHost), strings.ToLower(pHost)); t != "" {
				consider(&Suspect{Module: m.Path, Version: m.Version, Target: r, Technique: TechHost, Distance: d,
					Detail: fmt.Sprintf("host %s imitates %s (%s)", cHost, pHost, t)})
			}
			continue
		}
		// Same host, different namespace.
		if t, d := similarName(cRest, pRest, 6); t != "" {
			sev := techSeverity[t]
			if t == TechEdit && d == 1 {
				sev = report.High
			} else if t == TechEdit {
				sev = report.Medium
			}
			consider(&Suspect{Module: m.Path, Version: m.Version, Target: r, Technique: t, Distance: d, Severity: sev,
				Detail: fmt.Sprintf("%s differs from %s by %s", m.Path, r, describe(t, d))})
			continue
		}
		if codeHosts[strings.ToLower(cHost)] {
			cParts, pParts := strings.Split(cRest, "/"), strings.Split(pRest, "/")
			if len(cParts) >= 2 && len(pParts) >= 2 && strings.EqualFold(cParts[1], pParts[1]) &&
				len(pParts[1]) >= 5 && !genericRepoNames[strings.ToLower(pParts[1])] {
				consider(&Suspect{Module: m.Path, Version: m.Version, Target: r, Technique: TechOwnerSwap,
					Detail: fmt.Sprintf("same repository name as %s under owner %s (a fork or an impostor)", r, cParts[0])})
			}
		}
	}
	return best
}

// similarDomain compares host names: confusables, one or two edits,
// separators, or the same name under another top-level domain.
func similarDomain(a, b string) (string, int) {
	if a == b {
		return "", 0
	}
	if t, d := similarName(a, b, 6); t != "" {
		return t, d
	}
	an, at := cutTLD(a)
	bn, bt := cutTLD(b)
	if an == bn && at != bt && an != "" {
		return "other top-level domain", levenshtein(a, b)
	}
	return "", 0
}

func cutTLD(h string) (name, tld string) {
	i := strings.LastIndex(h, ".")
	if i < 0 {
		return h, ""
	}
	return h[:i], h[i+1:]
}

func describe(t string, d int) string {
	switch t {
	case TechHomoglyph:
		return "look-alike characters"
	case TechTransposition:
		return "two swapped characters"
	case TechSeparator:
		return "separators only"
	}
	return ui.Plural(d, "edit", "edits")
}

func printTyposquat(c *cli.Context, res *TyposquatResult) {
	o := c.Out
	subject := "."
	if p, err := c.Project(); err == nil && p.ModulePath() != "" {
		subject = p.ModulePath()
	}
	o.Title("sm-go typosquat · " + subject)
	line := fmt.Sprintf("%s compared with %d popular module paths", ui.Plural(res.Checked, "module path", "module paths"), res.Reference)
	if res.OwnDomain != "" {
		line += " and your namespace " + res.OwnDomain
	}
	o.Printf("%s\n", o.Dim(line))
	if len(res.Suspects) == 0 {
		o.Println()
		o.OK("no lookalike module paths")
		return
	}
	o.Heading(fmt.Sprintf("Lookalike module paths (%d)", len(res.Suspects)))
	for _, s := range res.Suspects {
		o.Printf("  %s %s\n", o.Sev(s.Severity), o.Bold(s.Module))
		o.Printf("           looks like %s · %s\n", s.Target, s.Technique)
		for _, l := range strings.Split(s.Detail, "\n") {
			o.Printf("           %s\n", o.Dim(l))
		}
	}
	o.Println()
	if res.Failing > 0 {
		o.Bad("%s at or above the --fail-on threshold", ui.Plural(res.Failing, "suspect", "suspects"))
	}
}
