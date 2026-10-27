package compliance

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/feeds"
	"github.com/slash-mark-dev/go-suite/internal/httpx"
	"github.com/slash-mark-dev/go-suite/internal/modzip"
	"github.com/slash-mark-dev/go-suite/internal/par"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/ui"
)

// LicenseFile is a license or notice file found in a module.
type LicenseFile struct {
	Path     string         `json:"path"`
	Kind     string         `json:"kind"` // license or notice
	Licenses []LicenseMatch `json:"licenses,omitempty"`
	Size     int            `json:"size"`
	text     string
}

// ModuleLicense is the license information of one module.
type ModuleLicense struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Replace string `json:"replace,omitempty"`
	Direct  bool   `json:"direct"`
	// Licenses are the SPDX ids that apply (all of them; a module whose
	// files carry several licenses is treated as "A AND B").
	Licenses   []string       `json:"licenses"`
	Expression string         `json:"expression"`
	Source     string         `json:"source"` // files, deps.dev or none
	Files      []*LicenseFile `json:"files,omitempty"`
	DepsDev    []string       `json:"depsDev,omitempty"`
	// DepsDevSkipped is "skipped: private module" when deps.dev was not
	// asked because the module is private (GOPRIVATE, GONOPROXY,
	// GONOSUMDB).
	DepsDevSkipped string `json:"depsDevSkipped,omitempty"`
	Copyleft       string `json:"copyleft,omitempty"`
	Status         string `json:"status"` // ok, denied, not-allowed, unknown, error
	Error          string `json:"error,omitempty"`
	zipHash        string // h1 hash of the downloaded zip
}

// LicenseSummary counts modules.
type LicenseSummary struct {
	Modules    int            `json:"modules"`
	ByLicense  map[string]int `json:"byLicense"`
	Unknown    int            `json:"unknown"`
	Copyleft   int            `json:"copyleft"`
	Violations int            `json:"violations"`
	Mismatches int            `json:"depsDevMismatches"`
}

// LicensePolicy is an allow/deny list of SPDX ids (glob patterns such as
// "GPL-*" are accepted).
type LicensePolicy struct {
	Allow        []string `json:"allow,omitempty"`
	Deny         []string `json:"deny,omitempty"`
	FailUnknown  bool     `json:"failUnknown,omitempty"`
	FailCopyleft bool     `json:"failCopyleft,omitempty"`
}

// LicenseResult is the result of the license tool.
type LicenseResult struct {
	Main     string           `json:"main"`
	Modules  []*ModuleLicense `json:"modules"`
	Summary  LicenseSummary   `json:"summary"`
	Policy   LicensePolicy    `json:"policy"`
	Findings []report.Finding `json:"findings"`
	Notice   string           `json:"notice,omitempty"`
}

var licenseFlags struct {
	allow, deny               cli.StringList
	notice                    *string
	linked, tests, noDepsDev  *bool
	failUnknown, failCopyleft *bool
	showAll                   *bool
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "license",
		Group:   group,
		Summary: "License compliance with SPDX text matching and NOTICE generation",
		Usage:   "sm-go license [packages] [flags]",
		Help: `Downloads every module of the build list (or, with --linked, only the modules that provide
packages linked into the given packages) and identifies the license of each from its LICENSE,
COPYING, UNLICENSE and NOTICE files. Identification is by normalized text similarity against
built-in reference texts (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, GPL-2.0,
GPL-3.0, LGPL-2.1, LGPL-3.0, AGPL-3.0, Unlicense, CC0-1.0, EPL-2.0, Zlib, BSL-1.0): word
3-gram coverage, preferring the most specific license, so BSD-2 and BSD-3, GPL-3.0 and
AGPL-3.0, or a file concatenating two licenses are told apart. SPDX-License-Identifier tags
are used when no text matches. Results are cross-checked with deps.dev, which also fills in
modules without a recognizable license file.

Policy: --allow and --deny take SPDX ids (repeatable or comma-separated; globs like "GPL-*").
A module violates the policy if any of its licenses is denied, or, with an allow list, if any
is not allowed (unknown licenses then count as violations too). Strong and network copyleft
licenses (GPL, AGPL) are reported as warnings; --fail-copyleft makes them violations.
Violations exit with code 1.

--notice FILE writes a third-party notices file with the full text of every license and
NOTICE file, ready to ship with a binary.`,
		Examples: []string{
			"sm-go license",
			"sm-go license --deny GPL-3.0,AGPL-3.0 --fail-unknown",
			"sm-go license --allow MIT,Apache-2.0,BSD-3-Clause,BSD-2-Clause,ISC",
			"sm-go license ./cmd/server --linked --notice THIRD_PARTY_NOTICES.txt",
			"sm-go license --json",
		},
		Sources: []string{"Go module proxy", "deps.dev"},
		Flags: func(fs *flag.FlagSet) {
			licenseFlags.allow, licenseFlags.deny = nil, nil
			fs.Var(&licenseFlags.allow, "allow", "allowed SPDX `ids` (repeatable, comma-separated, globs)")
			fs.Var(&licenseFlags.deny, "deny", "denied SPDX `ids` (repeatable, comma-separated, globs)")
			licenseFlags.notice = fs.String("notice", "", "write a NOTICE / third-party notices `file` with full license texts")
			licenseFlags.linked = fs.Bool("linked", false, "only modules providing packages linked into the given packages (needs go)")
			licenseFlags.tests = fs.Bool("tests", false, "with --linked, include test dependencies")
			licenseFlags.noDepsDev = fs.Bool("no-depsdev", false, "do not cross-check with deps.dev")
			licenseFlags.failUnknown = fs.Bool("fail-unknown", false, "treat modules without an identifiable license as violations")
			licenseFlags.failCopyleft = fs.Bool("fail-copyleft", false, "treat strong and network copyleft licenses as violations")
			licenseFlags.showAll = fs.Bool("all", false, "also list each license file with its match confidence")
		},
		Run: runLicense,
	})
}

func runLicense(c *cli.Context) error {
	pol := LicensePolicy{FailUnknown: *licenseFlags.failUnknown, FailCopyleft: *licenseFlags.failCopyleft}
	for _, a := range licenseFlags.allow {
		pol.Allow = append(pol.Allow, CanonicalSPDX(a))
	}
	for _, d := range licenseFlags.deny {
		pol.Deny = append(pol.Deny, CanonicalSPDX(d))
	}
	for _, p := range append(append([]string{}, pol.Allow...), pol.Deny...) {
		if _, err := path.Match(p, "x"); err != nil {
			return cli.Usagef("bad license pattern %q: %v", p, err)
		}
	}
	for _, a := range pol.Allow {
		for _, d := range pol.Deny {
			if a == d {
				return cli.Usagef("license %s is both allowed and denied", a)
			}
		}
	}
	if len(c.Args) > 0 && !*licenseFlags.linked {
		return cli.Usagef("package patterns are only used with --linked")
	}
	refs, _, err := buildRefs(c)
	if err != nil {
		return err
	}
	if *licenseFlags.linked {
		pats := c.Args
		if len(pats) == 0 {
			pats = []string{"./..."}
		}
		linked, err := linkedModules(c, pats, *licenseFlags.tests)
		if err != nil {
			return err
		}
		var keep []modRef
		for _, r := range refs {
			if linked[r.Path] {
				keep = append(keep, r)
			}
		}
		refs = keep
	}
	mods, err := scanLicenses(c, refs, !*licenseFlags.noDepsDev)
	if err != nil {
		return err
	}
	res := &LicenseResult{Modules: mods, Policy: pol, Findings: []report.Finding{}}
	if p, err := c.Project(); err == nil {
		res.Main = p.ModulePath()
	}
	res.Findings = applyLicensePolicy(mods, pol)
	summarizeLicenses(res)
	if *licenseFlags.notice != "" {
		if err := writeFile(*licenseFlags.notice, buildNotice(res.Main, mods)); err != nil {
			return err
		}
		res.Notice = *licenseFlags.notice
	}
	c.SetResult(res)
	if res.Summary.Violations > 0 {
		c.Issues()
	}
	if c.Text() {
		printLicense(c, res)
	}
	return nil
}

// scanLicenses downloads each module and identifies its licenses; with
// depsdev it cross-checks (and completes) them with deps.dev.
func scanLicenses(c *cli.Context, refs []modRef, depsdev bool) ([]*ModuleLicense, error) {
	ctx := c.Ctx
	mods, errs := par.Map(ctx, 8, refs, func(ctx context.Context, r modRef) (*ModuleLicense, error) {
		return moduleLicense(ctx, c, r)
	})
	for i, err := range errs {
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			// A module that cannot be downloaded is reported, not fatal,
			// unless nothing could be downloaded at all.
			mods[i] = &ModuleLicense{Path: refs[i].Path, Version: refs[i].Version, Direct: refs[i].Direct,
				Status: "error", Error: err.Error(), Source: "none", Licenses: []string{}}
		}
	}
	if len(refs) > 0 {
		failed := 0
		for _, m := range mods {
			if m.Status == "error" {
				failed++
			}
		}
		if failed == len(refs) {
			return nil, fmt.Errorf("could not download any module: %s", mods[0].Error)
		}
		if failed > 0 {
			c.Warnf("%s could not be downloaded; their licenses are unknown", ui.Plural(failed, "module", "modules"))
		}
	}
	if depsdev {
		crossCheckDepsDev(c, refs, mods)
	}
	for _, m := range mods {
		if len(m.Licenses) == 0 && len(m.DepsDev) > 0 {
			m.Licenses = append([]string{}, m.DepsDev...)
			m.Source = "deps.dev"
		}
		if len(m.Licenses) == 0 && m.Source == "" {
			m.Source = "none"
		}
		m.Expression = expression(m.Licenses)
		m.Copyleft = strongestCopyleft(m.Licenses)
	}
	return mods, nil
}

var copyleftRank = map[string]int{"": 0, "weak": 1, "strong": 2, "network": 3}

func strongestCopyleft(ids []string) string {
	best := ""
	for _, id := range ids {
		if cl := Copyleft(id); copyleftRank[cl] > copyleftRank[best] {
			best = cl
		}
	}
	return best
}

func expression(ids []string) string {
	if len(ids) == 0 {
		return "NOASSERTION"
	}
	return strings.Join(ids, " AND ")
}

func moduleLicense(ctx context.Context, c *cli.Context, r modRef) (*ModuleLicense, error) {
	src, data, err := openModule(ctx, c, r)
	if err != nil {
		return nil, err
	}
	ml := &ModuleLicense{Path: r.Path, Version: r.Version, Direct: r.Direct, Licenses: []string{}}
	if data != nil {
		ml.zipHash, _ = modzip.HashZip(data)
	}
	if r.Replace.Path != "" {
		ml.Replace = r.Replace.Path
		if r.Replace.Version != "" {
			ml.Replace += "@" + r.Replace.Version
		}
	}
	seen := map[string]bool{}
	for _, name := range src.Files() {
		kind := licenseFileKind(name)
		if kind == "" {
			continue
		}
		data, err := src.ReadFile(name)
		if err != nil {
			return nil, err
		}
		if len(data) > 1<<20 || bytes.IndexByte(data, 0) >= 0 {
			continue // not a text license file
		}
		f := &LicenseFile{Path: name, Kind: kind, Size: len(data), text: string(data)}
		f.Licenses = IdentifyLicenses(f.text)
		ml.Files = append(ml.Files, f)
		for _, m := range f.Licenses {
			if !seen[m.ID] {
				seen[m.ID] = true
				ml.Licenses = append(ml.Licenses, m.ID)
			}
		}
	}
	sort.Strings(ml.Licenses)
	if len(ml.Licenses) > 0 {
		ml.Source = "files"
	}
	return ml, nil
}

// crossCheckDepsDev records deps.dev's licenses for every module.
func crossCheckDepsDev(c *cli.Context, refs []modRef, mods []*ModuleLicense) {
	dd := c.DepsDev()
	var mu sync.Mutex
	var firstErr error
	par.Each(c.Ctx, 8, indexes(len(refs)), func(ctx context.Context, i int) {
		r := refs[i]
		if r.isLocal() {
			return
		}
		p, v := r.Path, r.Version
		if r.Replace.Path != "" {
			p, v = r.Replace.Path, r.Replace.Version
		}
		mu.Lock()
		stop := firstErr != nil
		mu.Unlock()
		if stop {
			return
		}
		ver, err := dd.Version(ctx, p, v)
		if errors.Is(err, feeds.ErrPrivate) {
			mods[i].DepsDevSkipped = err.Error()
			return
		}
		if err != nil {
			if !httpx.IsNotFound(err) {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
			return
		}
		var ids []string
		for _, l := range ver.Licenses {
			for _, id := range splitSPDXExpr(l) {
				if id != "" && !strings.EqualFold(id, "non-standard") && !strings.EqualFold(id, "NOASSERTION") {
					ids = append(ids, id)
				}
			}
		}
		sort.Strings(ids)
		mods[i].DepsDev = uniqStrings(ids)
	})
	if firstErr != nil {
		c.Warnf("deps.dev unavailable (%v); licenses not cross-checked", firstErr)
	}
}

func indexes(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

func uniqStrings(s []string) []string {
	var out []string
	for i, x := range s {
		if i == 0 || x != s[i-1] {
			out = append(out, x)
		}
	}
	return out
}

func matchLicense(patterns []string, id string) bool {
	for _, p := range patterns {
		if strings.EqualFold(p, id) {
			return true
		}
		if ok, _ := path.Match(strings.ToLower(p), strings.ToLower(id)); ok {
			return true
		}
	}
	return false
}

// applyLicensePolicy sets each module's Status and returns findings.
func applyLicensePolicy(mods []*ModuleLicense, pol LicensePolicy) []report.Finding {
	fs := []report.Finding{}
	for _, m := range mods {
		if m.Status == "error" {
			sev := report.Medium
			if pol.FailUnknown || len(pol.Allow) > 0 {
				sev = report.High
			}
			fs = append(fs, report.Finding{Severity: sev, Rule: "license-unavailable", Module: m.Path, Version: m.Version,
				Title: "module could not be downloaded; license unknown", Detail: m.Error})
			continue
		}
		m.Status = "ok"
		var denied, notAllowed []string
		for _, id := range m.Licenses {
			if matchLicense(pol.Deny, id) {
				denied = append(denied, id)
			} else if len(pol.Allow) > 0 && !matchLicense(pol.Allow, id) {
				notAllowed = append(notAllowed, id)
			}
		}
		switch {
		case len(denied) > 0:
			m.Status = "denied"
			fs = append(fs, report.Finding{Severity: report.High, Rule: "license-denied", Module: m.Path, Version: m.Version,
				Title: "denied license " + strings.Join(denied, ", "), Detail: "license expression: " + m.Expression,
				Fix: "replace or remove " + m.Path})
		case len(notAllowed) > 0:
			m.Status = "not-allowed"
			fs = append(fs, report.Finding{Severity: report.High, Rule: "license-not-allowed", Module: m.Path, Version: m.Version,
				Title: "license " + strings.Join(notAllowed, ", ") + " is not in the allow list", Detail: "license expression: " + m.Expression})
		case len(m.Licenses) == 0:
			m.Status = "unknown"
			sev := report.Medium
			if pol.FailUnknown || len(pol.Allow) > 0 {
				sev = report.High
			}
			detail := "no LICENSE/COPYING file with a recognizable license text"
			if len(m.Files) > 0 {
				var names []string
				for _, f := range m.Files {
					names = append(names, f.Path)
				}
				detail = "license files not recognized: " + strings.Join(names, ", ")
			}
			fs = append(fs, report.Finding{Severity: sev, Rule: "license-unknown", Module: m.Path, Version: m.Version,
				Title: "no identifiable license", Detail: detail, Fix: "review the module's license manually"})
		}
		if m.Status == "ok" {
			switch m.Copyleft {
			case "strong", "network":
				sev := report.Medium
				if pol.FailCopyleft {
					sev = report.High
					m.Status = "copyleft"
				}
				what := "strong copyleft"
				if m.Copyleft == "network" {
					what = "network copyleft (applies to software offered over a network)"
				}
				fs = append(fs, report.Finding{Severity: sev, Rule: "license-copyleft", Module: m.Path, Version: m.Version,
					Title: m.Expression + " is " + what, Detail: "distributing a binary that links this module may require releasing your source under the same license"})
			case "weak":
				fs = append(fs, report.Finding{Severity: report.Info, Rule: "license-weak-copyleft", Module: m.Path, Version: m.Version,
					Title: m.Expression + " is weak copyleft", Detail: "modifications to this module's files must be published under the same license"})
			}
		}
		if len(m.DepsDev) > 0 && m.Source == "files" && !sameIDs(m.DepsDev, m.Licenses) {
			fs = append(fs, report.Finding{Severity: report.Low, Rule: "license-mismatch", Module: m.Path, Version: m.Version,
				Title:  "deps.dev reports " + strings.Join(m.DepsDev, ", ") + ", files say " + m.Expression,
				Detail: "verify which license applies"})
		}
	}
	report.SortFindings(fs)
	return fs
}

func sameIDs(a, b []string) bool {
	set := map[string]bool{}
	for _, x := range a {
		set[CanonicalSPDX(x)] = true
	}
	if len(set) != len(b) {
		return false
	}
	for _, x := range b {
		if !set[CanonicalSPDX(x)] {
			return false
		}
	}
	return true
}

func isViolation(m *ModuleLicense, pol LicensePolicy) bool {
	switch m.Status {
	case "denied", "not-allowed", "copyleft":
		return true
	case "unknown", "error":
		return pol.FailUnknown || len(pol.Allow) > 0
	}
	return false
}

func summarizeLicenses(res *LicenseResult) {
	s := &res.Summary
	s.Modules = len(res.Modules)
	s.ByLicense = map[string]int{}
	for _, m := range res.Modules {
		if len(m.Licenses) == 0 {
			s.Unknown++
			s.ByLicense["unknown"]++
		}
		for _, id := range m.Licenses {
			s.ByLicense[id]++
		}
		if m.Copyleft != "" {
			s.Copyleft++
		}
		if isViolation(m, res.Policy) {
			s.Violations++
		}
	}
	for _, f := range res.Findings {
		if f.Rule == "license-mismatch" {
			s.Mismatches++
		}
	}
}

// buildNotice renders a third-party notices file.
func buildNotice(main string, mods []*ModuleLicense) []byte {
	var b bytes.Buffer
	rule := strings.Repeat("=", 80)
	sub := strings.Repeat("-", 80)
	b.WriteString("THIRD-PARTY SOFTWARE NOTICES AND INFORMATION\n\n")
	if main != "" {
		fmt.Fprintf(&b, "%s includes the following third-party Go modules.\n", main)
	} else {
		b.WriteString("This software includes the following third-party Go modules.\n")
	}
	fmt.Fprintf(&b, "Generated by sm-go license %s on %s.\n\n", cli.Version, time.Now().UTC().Format("2006-01-02"))
	sorted := append([]*ModuleLicense{}, mods...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	for _, m := range sorted {
		fmt.Fprintf(&b, "  %s %s  (%s)\n", m.Path, m.Version, m.Expression)
	}
	for _, m := range sorted {
		fmt.Fprintf(&b, "\n%s\n%s %s\n", rule, m.Path, m.Version)
		if m.Replace != "" {
			fmt.Fprintf(&b, "Replaced by: %s\n", m.Replace)
		}
		fmt.Fprintf(&b, "License: %s\n%s\n", m.Expression, sub)
		wrote := false
		files := append([]*LicenseFile{}, m.Files...)
		sort.SliceStable(files, func(i, j int) bool {
			if files[i].Kind != files[j].Kind {
				return files[i].Kind == "license"
			}
			return files[i].Path < files[j].Path
		})
		for _, f := range files {
			if wrote {
				b.WriteString("\n" + sub + "\n")
			}
			fmt.Fprintf(&b, "%s:\n\n", f.Path)
			b.WriteString(strings.TrimRight(strings.ReplaceAll(f.text, "\r\n", "\n"), "\n\t ") + "\n")
			wrote = true
		}
		if !wrote {
			if len(m.Licenses) > 0 {
				for _, id := range m.Licenses {
					fmt.Fprintf(&b, "No license file is included in the module; the license is %s:\nhttps://spdx.org/licenses/%s.html\n", id, id)
				}
			} else {
				b.WriteString("No license information could be found for this module.\n")
			}
		}
	}
	return b.Bytes()
}

func printLicense(c *cli.Context, res *LicenseResult) {
	o := c.Out
	subject := res.Main
	if subject == "" {
		subject = "."
	}
	o.Title("sm-go license · " + subject)
	var parts []string
	ids := make([]string, 0, len(res.Summary.ByLicense))
	for id := range res.Summary.ByLicense {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := res.Summary.ByLicense[ids[i]], res.Summary.ByLicense[ids[j]]
		if a != b {
			return a > b
		}
		return ids[i] < ids[j]
	})
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("%d %s", res.Summary.ByLicense[id], id))
	}
	o.Printf("%s · %s\n", ui.Plural(res.Summary.Modules, "module", "modules"), strings.Join(parts, ", "))
	if len(res.Modules) > 0 {
		var rows [][]string
		for _, m := range res.Modules {
			lic := m.Expression
			if m.Source == "deps.dev" {
				lic += o.Dim(" (deps.dev)")
			} else if m.DepsDevSkipped != "" && len(m.Licenses) == 0 {
				lic += o.Dim(" (deps.dev " + m.DepsDevSkipped + ")")
			}
			st := m.Status
			switch m.Status {
			case "ok":
				st = o.Green("ok")
				if m.Copyleft == "strong" || m.Copyleft == "network" {
					st = o.Yellow("copyleft")
				}
			case "unknown", "error":
				st = o.Yellow(m.Status)
			default:
				st = o.Red(m.Status)
			}
			rows = append(rows, []string{m.Path, m.Version, lic, st})
			if *licenseFlags.showAll {
				for _, f := range m.Files {
					var ls []string
					for _, l := range f.Licenses {
						ls = append(ls, fmt.Sprintf("%s %.0f%%", l.ID, l.Confidence*100))
					}
					rows = append(rows, []string{o.Dim("  " + f.Path), "", o.Dim(strings.Join(ls, ", ")), ""})
				}
			}
		}
		o.Println()
		o.Table([]string{"MODULE", "VERSION", "LICENSE", "STATUS"}, rows)
	}
	if len(res.Findings) > 0 {
		o.Heading("Findings")
		printFindings(c, res.Findings)
	}
	o.Println()
	if res.Notice != "" {
		o.OK("notices written to %s", res.Notice)
	}
	if res.Summary.Violations > 0 {
		o.Bad("%s violate the license policy", ui.Plural(res.Summary.Violations, "module", "modules"))
	} else {
		o.OK("no license policy violations")
	}
}
