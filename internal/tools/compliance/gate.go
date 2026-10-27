package compliance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/callgraph"
	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/loader"
	"github.com/slash-mark-dev/go-suite/internal/modfile"
	"github.com/slash-mark-dev/go-suite/internal/modproxy"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/par"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/semver"
	"github.com/slash-mark-dev/go-suite/internal/ui"
	"github.com/slash-mark-dev/go-suite/internal/vulndb"
	"github.com/slash-mark-dev/go-suite/internal/vulnscan"
)

// GatePolicy is the schema of .sm-go.json.
type GatePolicy struct {
	Vulnerabilities      *VulnPolicy    `json:"vulnerabilities,omitempty"`
	Licenses             *LicensePolicy `json:"licenses,omitempty"`
	ForbidRetracted      bool           `json:"forbidRetracted,omitempty"`
	ForbidDeprecated     bool           `json:"forbidDeprecated,omitempty"`
	BannedModules        []BannedModule `json:"bannedModules,omitempty"`
	ForbidLocalReplaces  bool           `json:"forbidLocalReplaces,omitempty"`
	RequireGoSumComplete bool           `json:"requireGoSumComplete,omitempty"`
	MaxGoAge             string         `json:"maxGoAge,omitempty"`
}

// VulnPolicy configures the vulnerability rules.
type VulnPolicy struct {
	// MaxSeverity is the highest severity tolerated ("none": any
	// vulnerability fails; the default).
	MaxSeverity   string   `json:"maxSeverity,omitempty"`
	ReachableOnly bool     `json:"reachableOnly,omitempty"`
	ForbidKEV     bool     `json:"forbidKEV,omitempty"`
	IncludeStdlib *bool    `json:"includeStdlib,omitempty"`
	Ignore        []string `json:"ignore,omitempty"`
}

// BannedModule is "path", "path@version" or "path@<version" (also <=, >,
// >=), or an object {"module": ..., "versions": ..., "reason": ...}.
type BannedModule struct {
	Module   string `json:"module"`
	Versions string `json:"versions,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// UnmarshalJSON accepts the string and the object forms.
func (b *BannedModule) UnmarshalJSON(data []byte) error {
	var s string
	if json.Unmarshal(data, &s) == nil {
		mod, ver, _ := strings.Cut(s, "@")
		*b = BannedModule{Module: mod, Versions: ver}
		return nil
	}
	type plain BannedModule
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p plain
	if err := dec.Decode(&p); err != nil {
		return err
	}
	*b = BannedModule(p)
	return nil
}

var constraintRE = regexp.MustCompile(`^(<=|>=|<|>|=)?\s*(v\S+)$`)

func (b BannedModule) validate() error {
	if b.Module == "" {
		return errors.New("bannedModules entry without a module path")
	}
	if b.Versions == "" {
		return nil
	}
	m := constraintRE.FindStringSubmatch(b.Versions)
	if m == nil || !semver.IsValid(m[2]) {
		return fmt.Errorf("bannedModules %s: bad version constraint %q (use v1.2.3, <v1.2.3, <=, > or >=)", b.Module, b.Versions)
	}
	return nil
}

func (b BannedModule) matches(path, version string) bool {
	if !module.MatchPrefixPatterns(b.Module, path) {
		return false
	}
	if b.Versions == "" {
		return true
	}
	m := constraintRE.FindStringSubmatch(b.Versions)
	if m == nil || version == "" {
		return false
	}
	c := semver.Compare(version, m[2])
	switch m[1] {
	case "<":
		return c < 0
	case "<=":
		return c <= 0
	case ">":
		return c > 0
	case ">=":
		return c >= 0
	}
	return c == 0
}

// GateRule is the outcome of one policy rule.
type GateRule struct {
	ID          string           `json:"id"`
	Description string           `json:"description"`
	Status      string           `json:"status"` // pass, fail, skip
	Detail      string           `json:"detail,omitempty"`
	Violations  []report.Finding `json:"violations"`
}

// DefaultGatePolicy is the built-in policy used when there is no policy
// file: fail on called (reachable) vulnerabilities of severity high or
// above, on any CISA KEV vulnerability (called or not) and on retracted
// versions; licenses are reported but not enforced.
func DefaultGatePolicy() *GatePolicy {
	return &GatePolicy{
		Vulnerabilities: &VulnPolicy{MaxSeverity: "medium", ReachableOnly: true, ForbidKEV: true},
		Licenses:        &LicensePolicy{},
		ForbidRetracted: true,
	}
}

// DefaultPolicyName is GateResult.Policy when the built-in policy is used.
const DefaultPolicyName = "(built-in default)"

// defaultPolicyJSON is the starter .sm-go.json written by --init: the
// built-in default policy.
func defaultPolicyJSON() []byte {
	data, err := json.MarshalIndent(DefaultGatePolicy(), "", "  ")
	if err != nil {
		panic(err)
	}
	return append(data, '\n')
}

// GateResult is the result of the gate tool.
type GateResult struct {
	Policy string `json:"policy"`
	// DefaultPolicy is true when no policy file was found and the
	// built-in default policy was applied.
	DefaultPolicy bool        `json:"defaultPolicy,omitempty"`
	Main          string      `json:"main"`
	Passed        bool        `json:"passed"`
	Rules         []*GateRule `json:"rules"`
	Summary       struct {
		Passed     int `json:"passed"`
		Failed     int `json:"failed"`
		Skipped    int `json:"skipped"`
		Violations int `json:"violations"`
	} `json:"summary"`
	SARIF string `json:"sarif,omitempty"`
}

var gateFlags struct {
	policy, sarif *string
	github, init  *bool
}

const gateHelp = `Evaluates the project against a policy file and fails (exit code 1) if any rule is violated.
Use it as a required CI step. Each rule reports pass, fail or skip (not configured).

The policy is read from --policy, or from .sm-go.json in the main module (or workspace)
directory. Without either, the built-in default policy applies:

  {
    "vulnerabilities": {"maxSeverity": "medium", "reachableOnly": true, "forbidKEV": true},
    "licenses": {},
    "forbidRetracted": true
  }

that is: fail on called (reachable) vulnerabilities of severity high or critical, on any
CISA Known Exploited Vulnerability (called or not) and on retracted versions; licenses are
reported but not enforced. Without the go command, every vulnerability in the build list
counts, not only called ones. 'sm-go gate --init' writes this policy to .sm-go.json (or
to --policy FILE) as a starting point; it never overwrites an existing file.

Schema (every key is optional; unknown keys are an error):

  {
    "vulnerabilities": {
      "maxSeverity": "low",        // highest tolerated severity: none (default), low, medium, high, critical
      "reachableOnly": true,       // count only vulnerabilities whose symbols are reachable (needs go)
      "forbidKEV": true,           // fail on any CISA Known Exploited Vulnerability, reachable or not
      "includeStdlib": true,       // also scan the standard library of the installed Go (default true)
      "ignore": ["GO-2024-1234"]   // accepted risks (OSV ids or aliases)
    },
    "licenses": {
      "deny": ["AGPL-3.0", "GPL-*"],          // SPDX ids or globs
      "allow": ["MIT", "Apache-2.0", "BSD-*"],
      "failUnknown": true, "failCopyleft": false
    },
    "forbidRetracted": true,       // no retracted versions in the build list
    "forbidDeprecated": true,      // no modules marked "Deprecated:" by their authors
    "bannedModules": [             // "path", "path@v1.2.3", "path@<v1.5.0" (<, <=, >, >=) or objects
      "github.com/evil/mod",
      {"module": "example.com/lib", "versions": "<v1.4.2", "reason": "data race in v1.4.1"}
    ],
    "forbidLocalReplaces": true,   // no "replace x => ../dir" in go.mod / go.work
    "requireGoSumComplete": true,  // go.sum has every hash needed to build (uses go list if available)
    "maxGoAge": "2y"               // go directive's release no older than this (d, w, mo, y or Go duration)
  }

Paths in bannedModules match path prefixes like GOPRIVATE patterns (globs allowed).

--sarif FILE writes a SARIF 2.1.0 report (GitHub code scanning, GitLab, Azure DevOps).
--github prints GitHub Actions workflow annotations (::error file=go.mod,line=N::...) so
violations show up on the pull request; with --json they go to stderr.`

func init() {
	cli.Register(&cli.Tool{
		Name:    "gate",
		Group:   group,
		Summary: "CI policy gate: vulnerabilities, KEV, licenses, bans, retractions",
		Usage:   "sm-go gate [flags]",
		Help:    gateHelp,
		Examples: []string{
			"sm-go gate",
			"sm-go gate --policy ci/policy.json --sarif sm-go.sarif",
			"sm-go gate --github",
			"sm-go gate --json",
			"sm-go gate --init",
		},
		Sources: []string{"Go vulnerability database", "CISA KEV", "FIRST EPSS", "GitHub Advisory Database", "Go module proxy", "deps.dev"},
		Flags: func(fs *flag.FlagSet) {
			gateFlags.policy = fs.String("policy", "", "policy `file` (default .sm-go.json in the module directory, else the built-in default policy)")
			gateFlags.sarif = fs.String("sarif", "", "write a SARIF 2.1.0 report to `file`")
			gateFlags.github = fs.Bool("github", false, "print GitHub Actions annotations")
			gateFlags.init = fs.Bool("init", false, "write the built-in default policy to .sm-go.json (or the --policy file) and exit; never overwrites")
		},
		Run: runGate,
	})
}

// loadPolicy reads and validates a policy file.
func loadPolicy(path string) (*GatePolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, cli.Usagef("reading policy: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p GatePolicy
	if err := dec.Decode(&p); err != nil {
		return nil, cli.Usagef("policy %s: %v", path, err)
	}
	if v := p.Vulnerabilities; v != nil && v.MaxSeverity != "" {
		if _, err := report.ParseSeverity(v.MaxSeverity); err != nil {
			return nil, cli.Usagef("policy %s: vulnerabilities.maxSeverity: %v", path, err)
		}
	}
	if l := p.Licenses; l != nil {
		for i, a := range l.Allow {
			l.Allow[i] = CanonicalSPDX(a)
		}
		for i, d := range l.Deny {
			l.Deny[i] = CanonicalSPDX(d)
		}
	}
	for _, b := range p.BannedModules {
		if err := b.validate(); err != nil {
			return nil, cli.Usagef("policy %s: %v", path, err)
		}
	}
	if p.MaxGoAge != "" {
		if _, err := parseAge(p.MaxGoAge); err != nil {
			return nil, cli.Usagef("policy %s: maxGoAge: %v", path, err)
		}
	}
	return &p, nil
}

var ageRE = regexp.MustCompile(`^(\d+)\s*(d|w|mo|y)$`)

// parseAge parses "540d", "12w", "18mo", "2y" or a Go duration.
func parseAge(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if m := ageRE.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		day := 24 * time.Hour
		switch m[2] {
		case "d":
			return time.Duration(n) * day, nil
		case "w":
			return time.Duration(n) * 7 * day, nil
		case "mo":
			return time.Duration(n) * 30 * day, nil
		case "y":
			return time.Duration(n) * 365 * day, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("bad age %q (use e.g. 540d, 18mo, 2y)", s)
	}
	return d, nil
}

func runGate(c *cli.Context) error {
	if len(c.Args) > 0 {
		return cli.Usagef("gate takes no arguments")
	}
	p, err := c.Project()
	if err != nil {
		return err
	}
	if *gateFlags.init {
		return initPolicy(c, p.ModDir, p.Dir)
	}
	polPath := *gateFlags.policy
	if polPath == "" {
		for _, d := range []string{p.ModDir, p.Dir} {
			if d == "" {
				continue
			}
			cand := filepath.Join(d, ".sm-go.json")
			if _, err := os.Stat(cand); err == nil {
				polPath = cand
				break
			}
		}
	}
	var pol *GatePolicy
	res := &GateResult{Policy: polPath, Main: p.ModulePath()}
	if polPath == "" {
		pol = DefaultGatePolicy()
		res.Policy, res.DefaultPolicy = DefaultPolicyName, true
		if !c.Env.HaveGo() {
			pol.Vulnerabilities.ReachableOnly = false
			c.Warnf("go command not found: the default policy counts every vulnerability in the build list, not only called ones")
		}
	} else if pol, err = loadPolicy(polPath); err != nil {
		return err
	}
	refs, _, err := buildRefs(c)
	if err != nil {
		return err
	}
	ctx := c.Ctx

	// Vulnerabilities and KEV.
	vulnRule := &GateRule{ID: "vulnerabilities", Description: "known vulnerabilities within the tolerated severity"}
	kevRule := &GateRule{ID: "kev", Description: "no CISA Known Exploited Vulnerabilities"}
	if vp := pol.Vulnerabilities; vp != nil {
		if err := gateVulns(c, vp, refs, vulnRule, kevRule); err != nil {
			return err
		}
	} else {
		vulnRule.Status, kevRule.Status = "skip", "skip"
	}
	if pol.Vulnerabilities != nil && !pol.Vulnerabilities.ForbidKEV {
		kevRule.Status = "skip"
		kevRule.Violations = nil
	}

	// Licenses.
	licRule := &GateRule{ID: "licenses", Description: "license policy (allow/deny lists)"}
	if lp := pol.Licenses; lp != nil {
		mods, err := scanLicenses(c, refs, true)
		if err != nil {
			return err
		}
		fs := applyLicensePolicy(mods, *lp)
		viol := map[string]bool{}
		for _, m := range mods {
			if isViolation(m, *lp) {
				viol[m.Path] = true
			}
		}
		for _, f := range fs {
			if viol[f.Module] && f.Severity >= report.Medium && f.Rule != "license-mismatch" {
				f.File, f.Line = goModRel(c), goModLine(c, f.Module)
				licRule.Violations = append(licRule.Violations, f)
			}
		}
		licRule.Detail = fmt.Sprintf("%s checked", ui.Plural(len(mods), "module", "modules"))
		if bd := licenseBreakdown(mods); bd != "" {
			licRule.Detail += " (" + bd + ")"
		}
		if len(lp.Allow) == 0 && len(lp.Deny) == 0 && !lp.FailUnknown && !lp.FailCopyleft {
			licRule.Description = "licenses (reported, not enforced)"
		}
	} else {
		licRule.Status = "skip"
	}

	// Retracted and deprecated.
	retRule := &GateRule{ID: "retracted", Description: "no retracted module versions"}
	depRule := &GateRule{ID: "deprecated", Description: "no deprecated modules"}
	if pol.ForbidRetracted || pol.ForbidDeprecated {
		metas, err := fetchMetas(ctx, c, refs)
		if err != nil {
			return err
		}
		for i, r := range refs {
			m := metas[i]
			if m == nil {
				continue
			}
			if pol.ForbidRetracted {
				if ok, why := m.Retracted(r.Version); ok {
					detail := "retracted by its author"
					if why != "" {
						detail += ": " + why
					}
					fix := ""
					if latest := pickLatest(m); latest != "" && semver.Compare(latest, r.Version) > 0 {
						fix = "go get " + r.Path + "@" + latest
					}
					retRule.Violations = append(retRule.Violations, report.Finding{Severity: report.High, Rule: "retracted",
						Module: r.Path, Version: r.Version, File: goModRel(c), Line: goModLine(c, r.Path),
						Title: r.Path + "@" + r.Version + " is retracted", Detail: detail, Fix: fix})
				}
			}
			if pol.ForbidDeprecated && m.Deprecated != "" {
				depRule.Violations = append(depRule.Violations, report.Finding{Severity: report.Medium, Rule: "deprecated",
					Module: r.Path, Version: r.Version, File: goModRel(c), Line: goModLine(c, r.Path),
					Title: r.Path + " is deprecated", Detail: m.Deprecated})
			}
		}
	}
	if !pol.ForbidRetracted {
		retRule.Status = "skip"
	}
	if !pol.ForbidDeprecated {
		depRule.Status = "skip"
	}

	// Banned modules.
	banRule := &GateRule{ID: "banned-modules", Description: "no banned modules or versions"}
	if len(pol.BannedModules) > 0 {
		for _, r := range refs {
			for _, b := range pol.BannedModules {
				hit := b.matches(r.Path, r.Version)
				via := ""
				if !hit && r.Replace.Path != "" && r.Replace.Version != "" && b.matches(r.Replace.Path, r.Replace.Version) {
					hit, via = true, " (as replacement "+r.Replace.Path+"@"+r.Replace.Version+")"
				}
				if !hit {
					continue
				}
				what := b.Module
				if b.Versions != "" {
					what += "@" + b.Versions
				}
				detail := "matches banned entry " + what + via
				if b.Reason != "" {
					detail += ": " + b.Reason
				}
				banRule.Violations = append(banRule.Violations, report.Finding{Severity: report.High, Rule: "banned-module",
					Module: r.Path, Version: r.Version, File: goModRel(c), Line: goModLine(c, r.Path),
					Title: r.Path + "@" + r.Version + " is banned", Detail: detail})
				break
			}
		}
	} else {
		banRule.Status = "skip"
	}

	// Local replaces.
	replRule := &GateRule{ID: "local-replaces", Description: "no replace directives pointing at local directories"}
	if pol.ForbidLocalReplaces {
		for _, f := range localReplaces(c) {
			replRule.Violations = append(replRule.Violations, report.Finding{Severity: report.High, Rule: "local-replace",
				Module: f.old, File: f.file, Line: f.line,
				Title:  "local replace " + f.old + " => " + f.dir,
				Detail: "builds outside this checkout differ; the module cannot be consumed by others", Fix: "remove the replace directive or publish the fork"})
		}
	} else {
		replRule.Status = "skip"
	}

	// go.sum completeness.
	sumRule := &GateRule{ID: "go-sum", Description: "go.sum contains every hash needed to build"}
	if pol.RequireGoSumComplete {
		sumRule.Violations, sumRule.Detail = goSumMissing(c, refs)
	} else {
		sumRule.Status = "skip"
	}

	// go directive age.
	ageRule := &GateRule{ID: "go-age", Description: "go directive is recent enough"}
	if pol.MaxGoAge != "" {
		maxAge, _ := parseAge(pol.MaxGoAge)
		goV := ""
		line := 0
		if p.GoMod != nil {
			goV, line = p.GoMod.Go, p.GoMod.GoLine
		}
		if goV == "" {
			goV = "1.16" // the go command's assumption for go.mod files without a go directive
		}
		rel, known := goReleaseDate(goV)
		age := time.Since(rel)
		ageRule.Detail = fmt.Sprintf("go %s released %s", goV, rel.Format("2006-01"))
		if known && age > maxAge {
			ageRule.Violations = append(ageRule.Violations, report.Finding{Severity: report.Medium, Rule: "go-age",
				File: goModRel(c), Line: line,
				Title:  fmt.Sprintf("go directive %s is %s old (policy: %s)", goV, humanAge(age), pol.MaxGoAge),
				Detail: "an old language version keeps newer language and security behaviour (GODEBUG defaults) off",
				Fix:    "raise the go directive (go mod edit -go=<version>) after testing"})
		}
	} else {
		ageRule.Status = "skip"
	}
	res.Rules = []*GateRule{vulnRule, kevRule, licRule, retRule, depRule, banRule, replRule, sumRule, ageRule}
	for _, r := range res.Rules {
		if r.Status == "" {
			if len(r.Violations) > 0 {
				r.Status = "fail"
			} else {
				r.Status = "pass"
			}
		}
		if r.Violations == nil {
			r.Violations = []report.Finding{}
		}
		report.SortFindings(r.Violations)
		switch r.Status {
		case "pass":
			res.Summary.Passed++
		case "fail":
			res.Summary.Failed++
			res.Summary.Violations += len(r.Violations)
		default:
			res.Summary.Skipped++
		}
	}
	res.Passed = res.Summary.Failed == 0
	if *gateFlags.sarif != "" {
		data, err := gateSARIF(res)
		if err != nil {
			return err
		}
		if err := writeFile(*gateFlags.sarif, data); err != nil {
			return err
		}
		res.SARIF = *gateFlags.sarif
	}
	c.SetResult(res)
	if !res.Passed {
		c.Issues()
	}
	if *gateFlags.github {
		w := c.Stdout
		if c.G.JSON {
			w = c.Stderr
		}
		writeAnnotations(w, res)
	}
	if c.Text() {
		printGate(c, res)
	}
	return nil
}

// initPolicy writes the built-in default policy as a starter file.
func initPolicy(c *cli.Context, dirs ...string) error {
	path := *gateFlags.policy
	if path == "" {
		for _, d := range dirs {
			if d != "" {
				path = filepath.Join(d, ".sm-go.json")
				break
			}
		}
	}
	if path == "" {
		return cli.Usagef("--init: no module directory; pass --policy FILE")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, os.ErrExist) {
		return cli.Usagef("--init: %s already exists; not overwriting it", path)
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(defaultPolicyJSON()); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	c.SetResult(map[string]any{"policy": path, "written": true})
	if c.Text() {
		c.Out.OK("wrote the default policy to %s; edit it to customise ('sm-go help gate' documents every key)", path)
	}
	return nil
}

// licenseBreakdown summarises licenses: "5 MIT, 2 Apache-2.0, 1 unknown".
func licenseBreakdown(mods []*ModuleLicense) string {
	count := map[string]int{}
	for _, m := range mods {
		if len(m.Licenses) == 0 {
			count["unknown"]++
			continue
		}
		count[m.Expression]++
	}
	keys := make([]string, 0, len(count))
	for k := range count {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if count[keys[i]] != count[keys[j]] {
			return count[keys[i]] > count[keys[j]]
		}
		return keys[i] < keys[j]
	})
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", count[k], k))
	}
	return strings.Join(parts, ", ")
}

func gateVulns(c *cli.Context, vp *VulnPolicy, refs []modRef, vulnRule, kevRule *GateRule) error {
	maxSev := report.None
	if vp.MaxSeverity != "" {
		maxSev, _ = report.ParseSeverity(vp.MaxSeverity)
	}
	var mods []module.Version
	for _, r := range refs {
		mods = append(mods, r.mod())
	}
	if vp.IncludeStdlib == nil || *vp.IncludeStdlib {
		if gv := c.Env.GoVersion(); gv != "" {
			if std, ok := vulnscan.StdlibModule(gv); ok {
				mods = append(mods, std)
			}
		}
	}
	vulns, err := vulnscan.Scan(c.Ctx, c, mods)
	if err != nil {
		return err
	}
	ignored := map[string]bool{}
	for _, id := range vp.Ignore {
		ignored[id] = true
	}
	var kept []*vulnscan.Vuln
	for _, v := range vulns {
		skip := ignored[v.ID]
		for _, a := range v.Aliases {
			skip = skip || ignored[a]
		}
		if !skip {
			kept = append(kept, v)
		}
	}
	vulnscan.Enrich(c.Ctx, c, kept)
	vulnscan.Sort(kept)
	reachable := map[*vulnscan.Vuln]bool{}
	if vp.ReachableOnly && len(kept) > 0 {
		r, err := reachableVulns(c, kept)
		if err != nil {
			return err
		}
		reachable = r
	}
	counted := 0
	for _, v := range kept {
		if vp.ReachableOnly && !reachable[v] {
			continue
		}
		counted++
		f := vulnFinding(c, v)
		if v.Severity > maxSev {
			vulnRule.Violations = append(vulnRule.Violations, f)
		}
	}
	for _, v := range kept {
		if v.KEV != nil {
			f := vulnFinding(c, v)
			f.Rule, f.Severity = "kev", report.Critical
			f.Title = v.ID + " is actively exploited (CISA KEV): " + v.Summary
			kevRule.Violations = append(kevRule.Violations, f)
		}
	}
	scope := "affecting the build"
	if vp.ReachableOnly {
		scope = "reachable"
	}
	vulnRule.Detail = fmt.Sprintf("%d known vulnerabilities %s, %d ignored, max tolerated severity %s", counted, scope, len(vulns)-len(kept), maxSev)
	return nil
}

func vulnFinding(c *cli.Context, v *vulnscan.Vuln) report.Finding {
	f := report.Finding{Severity: v.Severity, Rule: "vulnerability", Module: v.Module, Version: v.Version,
		Title: v.ID + ": " + v.Summary, URL: v.URL}
	if v.Module == vulndb.Stdlib {
		f.Module = "Go standard library"
	} else {
		f.File, f.Line = goModRel(c), goModLine(c, v.Module)
	}
	if v.FixedIn != "" {
		if v.Module == vulndb.Stdlib {
			f.Fix = "upgrade Go to " + strings.Replace(v.FixedIn, "v", "go", 1)
		} else {
			f.Fix = "go get " + v.Module + "@" + v.FixedIn
		}
	} else {
		f.Fix = "no fixed version available"
	}
	if len(v.CVEs) > 0 {
		f.Detail = strings.Join(v.CVEs, ", ")
	}
	return f
}

// reachableVulns type-checks the program, builds a call graph and reports
// which vulnerabilities have a reachable vulnerable symbol (or, for
// entries without symbol data, an imported vulnerable package).
func reachableVulns(c *cli.Context, vulns []*vulnscan.Vuln) (map[*vulnscan.Vuln]bool, error) {
	if !c.Env.HaveGo() {
		return nil, errors.New("vulnerabilities.reachableOnly needs the go command")
	}
	prog, err := c.Load(loader.Config{Patterns: []string{"./..."}, TypeCheck: true})
	if err != nil {
		return nil, err
	}
	for i, e := range prog.Errors {
		if i == 3 {
			c.Warnf("… and %d more package loading problems", len(prog.Errors)-3)
			break
		}
		c.Warnf("%s", e)
	}
	cg := callgraph.Build(prog)
	reach := cg.Reachable(cg.Entrypoints(prog.Roots))
	out := map[*vulnscan.Vuln]bool{}
	for _, v := range vulns {
		hit := false
		for _, pkg := range v.Packages {
			if prog.ByPath[pkg] == nil {
				continue
			}
			syms := v.Symbols[pkg]
			if len(syms) == 0 {
				hit = true
				break
			}
			for _, s := range syms {
				if reach.Has(cg.Lookup(pkg, s)) {
					hit = true
					break
				}
			}
		}
		if len(v.Packages) == 0 {
			for _, p := range prog.Packages {
				if p.ModulePath() == v.Module || (v.Module == vulndb.Stdlib && p.Standard) {
					hit = true
					break
				}
			}
		}
		out[v] = hit
	}
	return out, nil
}

func fetchMetas(ctx context.Context, c *cli.Context, refs []modRef) ([]*modproxy.Meta, error) {
	metas, errs := par.Map(ctx, 8, refs, func(ctx context.Context, r modRef) (*modproxy.Meta, error) {
		if r.isLocal() {
			return nil, nil
		}
		return c.Proxy().Meta(ctx, r.Path)
	})
	for i, err := range errs {
		if err != nil {
			if errors.Is(err, modproxy.ErrNotFound) {
				metas[i] = nil
				continue
			}
			return nil, fmt.Errorf("%s: %v", refs[i].Path, err)
		}
	}
	return metas, nil
}

// pickLatest returns the highest non-retracted release in m.
func pickLatest(m *modproxy.Meta) string {
	best := ""
	for _, v := range m.Versions {
		if semver.Prerelease(v) != "" {
			continue
		}
		if r, _ := m.Retracted(v); r {
			continue
		}
		if best == "" || semver.Compare(v, best) > 0 {
			best = v
		}
	}
	return best
}

type localRep struct {
	file, old, dir string
	line           int
}

func localReplaces(c *cli.Context) []localRep {
	p, err := c.Project()
	if err != nil {
		return nil
	}
	var out []localRep
	add := func(file string, reps []*modfile.Replace) {
		for _, r := range reps {
			if r.IsLocal() {
				old := r.Old.Path
				if r.Old.Version != "" {
					old += "@" + r.Old.Version
				}
				out = append(out, localRep{file: p.Rel(file), old: old, dir: r.New.Path, line: r.Line})
			}
		}
	}
	if p.Work != nil {
		add(p.WorkPath, p.Work.Replace)
		for _, m := range p.Mains {
			add(filepath.Join(m.Dir, "go.mod"), m.File.Replace)
		}
	} else if p.GoMod != nil {
		add(p.GoModPath, p.GoMod.Replace)
	}
	return out
}

// goSumMissing reports hashes missing from go.sum: the go.mod hash of every
// module in the build list, and (using go list when available) the zip
// hash of every module that provides a package to the build or tests.
func goSumMissing(c *cli.Context, refs []modRef) ([]report.Finding, string) {
	p, _ := c.Project()
	file := "go.sum"
	if p != nil && p.GoSumPath != "" {
		file = p.Rel(p.GoSumPath)
	}
	has := func(path, version string) bool {
		return p != nil && p.GoSum != nil && p.GoSum.Hash(path, version) != ""
	}
	var out []report.Finding
	seen := map[string]bool{}
	missing := func(path, version, kind string) {
		key := path + "@" + version + kind
		if seen[key] {
			return
		}
		seen[key] = true
		what := "module zip hash"
		if kind == "/go.mod" {
			what = "go.mod hash"
		}
		out = append(out, report.Finding{Severity: report.High, Rule: "go-sum-missing", Module: path, Version: version, File: file,
			Title:  "go.sum lacks the " + what + " of " + path + "@" + version,
			Detail: "the go command will refuse to build with -mod=readonly (the CI default)", Fix: "go mod tidy"})
	}
	byPath := map[string]modRef{}
	for _, r := range refs {
		byPath[r.Path] = r
		if r.isLocal() {
			continue
		}
		hp, hv := r.Path, r.Version
		if r.Replace.Path != "" {
			hp, hv = r.Replace.Path, r.Replace.Version
		}
		if !has(hp, hv+"/go.mod") {
			missing(hp, hv, "/go.mod")
		}
	}
	detail := fmt.Sprintf("%s checked", ui.Plural(len(refs), "module", "modules"))
	if !c.Env.HaveGo() {
		c.Warnf("go command not found: only go.mod hashes were checked for go.sum completeness")
		return out, detail
	}
	dir := p.ModDir
	if dir == "" {
		dir = p.Dir
	}
	pkgs, err := loader.GoList(c.Ctx, loader.Config{Env: c.Env, Dir: dir, ExtraEnv: []string{"GOFLAGS=-mod=readonly"}}, "-deps", "-test")
	if err != nil {
		c.Warnf("go list failed (%v); only go.mod hashes were checked", err)
		return out, detail
	}
	for _, pk := range pkgs {
		if pk.Module != nil && !pk.Module.Main && !pk.Standard {
			mp, mv := pk.Module.Path, pk.Module.Version
			if pk.Module.Replace != nil {
				if pk.Module.Replace.Version == "" {
					continue
				}
				mp, mv = pk.Module.Replace.Path, pk.Module.Replace.Version
			}
			if mv != "" && !has(mp, mv) {
				missing(mp, mv, "")
			}
		}
		if pk.Error != nil && strings.Contains(pk.Error.Err, "missing go.sum entry") {
			// The go command could not even resolve the package: report
			// the module named in the error if we can map it.
			for path, r := range byPath {
				if strings.HasPrefix(pk.ImportPath, path+"/") || pk.ImportPath == path {
					hp, hv := r.Path, r.Version
					if r.Replace.Path != "" {
						hp, hv = r.Replace.Path, r.Replace.Version
					}
					if hv != "" && !has(hp, hv) {
						missing(hp, hv, "")
					}
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Title < out[j].Title })
	return out, detail + ", go list -mod=readonly"
}

// goReleaseDate returns the release date of a go directive version
// ("1.21", "1.21.3", "1.22rc1"). Dates after go1.25 follow the
// February/August release cadence. known is false for unparseable values.
func goReleaseDate(v string) (time.Time, bool) {
	m := regexp.MustCompile(`^1\.(\d+)`).FindStringSubmatch(v)
	if m == nil {
		return time.Time{}, false
	}
	minor, _ := strconv.Atoi(m[1])
	if d, ok := goReleases[minor]; ok {
		t, _ := time.Parse("2006-01-02", d)
		return t, true
	}
	if minor < 0 {
		return time.Time{}, false
	}
	// go1.26 in February 2026, go1.27 in August 2026, ...
	year := 2016 + (minor-6)/2
	month := time.February
	if minor%2 == 1 {
		month = time.August
	}
	return time.Date(year, month, 11, 0, 0, 0, 0, time.UTC), true
}

var goReleases = map[int]string{
	0: "2012-03-28", 1: "2013-05-13", 2: "2013-12-01", 3: "2014-06-18", 4: "2014-12-10", 5: "2015-08-19",
	6: "2016-02-17", 7: "2016-08-15", 8: "2017-02-16", 9: "2017-08-24", 10: "2018-02-16", 11: "2018-08-24",
	12: "2019-02-25", 13: "2019-09-03", 14: "2020-02-25", 15: "2020-08-11", 16: "2021-02-16", 17: "2021-08-16",
	18: "2022-03-15", 19: "2022-08-02", 20: "2023-02-01", 21: "2023-08-08", 22: "2024-02-06", 23: "2024-08-13",
	24: "2025-02-11", 25: "2025-08-12",
}

func humanAge(d time.Duration) string {
	days := int(d.Hours() / 24)
	switch {
	case days >= 365:
		y := float64(days) / 365
		return fmt.Sprintf("%.1f years", y)
	case days >= 60:
		return fmt.Sprintf("%d months", days/30)
	}
	return fmt.Sprintf("%d days", days)
}

// ---- SARIF and annotations ----

func gateSARIF(res *GateResult) ([]byte, error) {
	type msg struct {
		Text string `json:"text"`
	}
	type region struct {
		StartLine int `json:"startLine"`
	}
	type artifact struct {
		URI string `json:"uri"`
	}
	type physical struct {
		ArtifactLocation artifact `json:"artifactLocation"`
		Region           *region  `json:"region,omitempty"`
	}
	type location struct {
		PhysicalLocation physical `json:"physicalLocation"`
	}
	type result struct {
		RuleID     string         `json:"ruleId"`
		Level      string         `json:"level"`
		Message    msg            `json:"message"`
		Locations  []location     `json:"locations,omitempty"`
		Properties map[string]any `json:"properties,omitempty"`
	}
	type rule struct {
		ID               string         `json:"id"`
		ShortDescription msg            `json:"shortDescription"`
		HelpURI          string         `json:"helpUri"`
		Properties       map[string]any `json:"properties,omitempty"`
	}
	var rules []rule
	var results []result
	for _, r := range res.Rules {
		rules = append(rules, rule{ID: r.ID, ShortDescription: msg{r.Description}, HelpURI: "https://github.com/slash-mark-dev/go-suite#gate",
			Properties: map[string]any{"status": r.Status}})
		if r.Status != "fail" {
			continue
		}
		for _, f := range r.Violations {
			text := f.Title
			if f.Detail != "" {
				text += " — " + f.Detail
			}
			if f.Fix != "" {
				text += " (fix: " + f.Fix + ")"
			}
			level := "error"
			if f.Severity <= report.Low {
				level = "warning"
			}
			res := result{RuleID: r.ID, Level: level, Message: msg{text}, Properties: map[string]any{"severity": f.Severity.String()}}
			file := f.File
			if file == "" {
				file = "go.mod"
			}
			loc := location{PhysicalLocation: physical{ArtifactLocation: artifact{URI: filepath.ToSlash(file)}}}
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &region{StartLine: f.Line}
			}
			res.Locations = []location{loc}
			if f.Module != "" {
				res.Properties["module"] = f.Module
				if f.Version != "" {
					res.Properties["version"] = f.Version
				}
			}
			results = append(results, res)
		}
	}
	if results == nil {
		results = []result{}
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "sm-go gate", "version": cli.Version, "informationUri": "https://github.com/slash-mark-dev/go-suite",
				"rules": rules,
			}},
			"results": results,
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func escapeData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

func escapeProp(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
}

func writeAnnotations(w interface{ Write([]byte) (int, error) }, res *GateResult) {
	for _, r := range res.Rules {
		if r.Status != "fail" {
			continue
		}
		for _, f := range r.Violations {
			file := f.File
			if file == "" {
				file = "go.mod"
			}
			props := "file=" + escapeProp(filepath.ToSlash(file))
			if f.Line > 0 {
				props += fmt.Sprintf(",line=%d", f.Line)
			}
			props += ",title=" + escapeProp("sm-go gate: "+r.ID)
			text := f.Title
			if f.Fix != "" {
				text += " (fix: " + f.Fix + ")"
			}
			fmt.Fprintf(w, "::error %s::%s\n", props, escapeData(text))
		}
	}
	if res.Passed {
		fmt.Fprintf(w, "::notice title=sm-go gate::all %d policy rules passed\n", res.Summary.Passed)
	}
}

func printGate(c *cli.Context, res *GateResult) {
	o := c.Out
	pol := res.Policy
	if p, err := c.Project(); err == nil && !res.DefaultPolicy {
		pol = p.Rel(pol)
	}
	o.Title(fmt.Sprintf("sm-go gate · %s · policy %s", res.Main, pol))
	if res.DefaultPolicy {
		o.Println("no policy file found; using the built-in default policy — create .sm-go.json to customise")
		o.Println(o.Dim("('sm-go gate --init' writes the default policy as a starter file; 'sm-go help gate' documents it)"))
	}
	o.Println()
	for _, r := range res.Rules {
		name := fmt.Sprintf("%-16s", r.ID)
		switch r.Status {
		case "pass":
			line := name + " " + r.Description
			if r.Detail != "" {
				line += o.Dim(" · " + r.Detail)
			}
			o.OK("%s", line)
		case "fail":
			o.Bad("%s %s", name, o.Red(fmt.Sprintf("%s", ui.Plural(len(r.Violations), "violation", "violations"))))
			printFindings(c, r.Violations)
		default:
			o.Println(o.Dim("- " + name + " skipped (not in policy)"))
		}
	}
	o.Println()
	if res.Passed {
		o.OK("PASSED: %d rules passed, %d skipped", res.Summary.Passed, res.Summary.Skipped)
	} else {
		o.Bad("FAILED: %d of %d rules failed with %s", res.Summary.Failed, res.Summary.Failed+res.Summary.Passed,
			ui.Plural(res.Summary.Violations, "violation", "violations"))
	}
	if res.SARIF != "" {
		o.Println(o.Dim("SARIF report written to " + res.SARIF))
	}
}
