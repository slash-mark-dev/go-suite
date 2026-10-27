package origin

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/endpoints"
	"github.com/slash-mark-dev/go-suite/internal/feeds"
	"github.com/slash-mark-dev/go-suite/internal/httpx"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/par"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/source"
)

var vanityFlags struct {
	direct     *bool
	subpaths   *int
	expiryDays *int
	noRepo     *bool
	failOn     func() (report.Severity, error)
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "vanity",
		Group:   group,
		Summary: "Vanity import auditor: go-import tags, HTTPS, redirects, repo roots, domains",
		Usage:   "sm-go vanity [import-path...] [flags]",
		Help: `Audits the vanity import paths in the build list: every module whose path is
not on GitHub, GitLab or Bitbucket is resolved the way the go command does
in direct mode (GOPROXY=direct, GOPRIVATE, or a proxy cache miss): it
fetches https://<path>?go-get=1 and applies cmd/go's matching rules to the
<meta name="go-import"> tags ("mod" entries win, any other second match is
an error).

Flags:
  - pages that are unreachable, use an invalid certificate, are served over
    plain HTTP or redirect to another host
  - no tag matching the path, a tag for a different prefix, multiple
    matching tags, an unknown VCS or an invalid repository URL
  - a shorter-prefix tag whose own page disagrees with it
  - repository roots that cannot be reached (git smart-HTTP probe, GitHub
    API for GitHub repositories, @v/list for "mod" proxies)
  - package sub-paths (taken from the module zip) whose pages lack a
    matching go-import tag, which breaks "go get <path>/<pkg>"
  - go-source tags for a different prefix
  - vanity domains that expired or expire soon (RDAP)

Arguments may name import paths to audit directly.`,
		Examples: []string{
			"sm-go vanity",
			"sm-go vanity go.uber.org/zap golang.org/x/net",
			"sm-go vanity --subpaths 0 --json",
		},
		Sources: []string{"vanity import pages", "Go module proxy", "GitHub REST API", "RDAP"},
		Flags: func(fs *flag.FlagSet) {
			vanityFlags.direct = fs.Bool("direct", false, "audit only direct requirements")
			vanityFlags.subpaths = fs.Int("subpaths", 2, "probe up to `n` package sub-paths per module (0 disables)")
			vanityFlags.expiryDays = fs.Int("expiry-days", 30, "flag domains expiring within `n` days")
			vanityFlags.noRepo = fs.Bool("no-repo-check", false, "do not probe repository roots")
			vanityFlags.failOn = cli.SeverityFlag(fs, "fail-on", "medium", "exit 1 on findings at or above this `severity`")
		},
		Run: runVanity,
	})
}

// VanitySubpath is the result of probing a package below the module root.
type VanitySubpath struct {
	Path   string           `json:"path"`
	OK     bool             `json:"ok"`
	Match  *source.GoImport `json:"match,omitempty"`
	Status int              `json:"status,omitempty"`
	Error  string           `json:"error,omitempty"`
}

// VanityRepoCheck is the result of probing the repository root.
type VanityRepoCheck struct {
	URL       string `json:"url"`
	Method    string `json:"method"` // "github-api", "git-smart-http", "proxy-list", "http-get"
	Reachable bool   `json:"reachable"`
	Status    int    `json:"status,omitempty"`
	Error     string `json:"error,omitempty"`
	// Skipped explains why the root was not probed ("skipped: private
	// module": a private module's repository on another host).
	Skipped string `json:"skipped,omitempty"`
}

// VanityModule is the audit of one vanity import path.
type VanityModule struct {
	Dep
	ImportPath string             `json:"importPath"`
	Page       *source.VanityInfo `json:"page"`
	Match      *source.GoImport   `json:"match,omitempty"`
	MatchError string             `json:"matchError,omitempty"`
	// PrefixPage is the page of the matched prefix when it is shorter than
	// the import path (the go command fetches it to verify agreement).
	PrefixPage *source.VanityInfo `json:"prefixPage,omitempty"`
	Repo       *VanityRepoCheck   `json:"repo,omitempty"`
	Subpaths   []VanitySubpath    `json:"subpaths,omitempty"`
	Domain     *source.Domain     `json:"domain,omitempty"`
	// DomainSkipped is "skipped: private module" when the RDAP lookup was
	// not made because the module is private.
	DomainSkipped string           `json:"domainSkipped,omitempty"`
	Findings      []report.Finding `json:"findings,omitempty"`
}

// VanityResult is the JSON result of sm-go vanity.
type VanityResult struct {
	Subject  string           `json:"subject"`
	Modules  []VanityModule   `json:"modules"`
	Skipped  int              `json:"skipped"` // code-host and non-network paths in the build list
	Findings []report.Finding `json:"findings"`
	Summary  struct {
		Modules int `json:"modules"`
		Clean   int `json:"clean"`
		severityCounts
	} `json:"summary"`
}

func runVanity(c *cli.Context) error {
	failOn, err := vanityFlags.failOn()
	if err != nil {
		return err
	}
	if *vanityFlags.subpaths < 0 || *vanityFlags.expiryDays < 0 {
		return cli.Usagef("--subpaths and --expiry-days must be >= 0")
	}
	deps, err := SelectDeps(c, !*vanityFlags.direct, c.Args)
	if err != nil {
		return err
	}
	res := &VanityResult{Subject: subject(c, c.Args), Modules: []VanityModule{}, Findings: []report.Finding{}}
	var audit []Dep
	for _, d := range deps {
		p := d.CodePath()
		if d.Local != "" || source.IsCodeHost(p) || !strings.Contains(firstElem(p), ".") {
			if len(c.Args) > 0 && d.Local == "" {
				c.Warnf("%s is not a vanity import path; skipped", p)
			}
			res.Skipped++
			continue
		}
		audit = append(audit, d)
	}
	now := time.Now()
	mods, errs := par.Map(c.Ctx, 8, audit, func(ctx context.Context, d Dep) (VanityModule, error) {
		return auditVanity(ctx, c, d, now), nil
	})
	if err := par.FirstErr(errs); err != nil {
		return err
	}
	for _, m := range mods {
		report.SortFindings(m.Findings)
		if len(m.Findings) == 0 || maxSeverity(m.Findings) <= report.Info {
			res.Summary.Clean++
		}
		res.Modules = append(res.Modules, m)
		res.Findings = append(res.Findings, m.Findings...)
	}
	report.SortFindings(res.Findings)
	res.Summary.Modules = len(res.Modules)
	res.Summary.severityCounts = countSeverities(res.Findings)
	c.SetResult(res)
	if failOn != report.None && len(report.AtLeast(res.Findings, failOn)) > 0 {
		c.Issues()
	}
	if c.Text() {
		printVanity(c, res)
	}
	return nil
}

// noResponse reports whether fetching a vanity page got no HTTP response
// at all (DNS failure, refused or dropped connection), the signature of a
// domain that is gone.
func noResponse(vi *source.VanityInfo) bool {
	return vi != nil && (vi.DNSError || (vi.Status == 0 && !vi.TLSError && vi.Error != ""))
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func firstElem(p string) string {
	h, _, _ := strings.Cut(p, "/")
	return h
}

func auditVanity(ctx context.Context, c *cli.Context, d Dep, now time.Time) VanityModule {
	ip := d.CodePath()
	m := VanityModule{Dep: d, ImportPath: ip}
	add := func(sev report.Severity, rule, title, detail string) {
		m.Findings = append(m.Findings, report.Finding{Severity: sev, Rule: rule, Module: d.Path, Version: d.Version, Title: title, Detail: detail})
	}

	// Domain registration (independent of the page). Private modules are
	// not looked up in the public RDAP service.
	if c.SkipPrivate(ip) {
		m.DomainSkipped = feeds.ErrPrivate.Error()
	} else if dom := source.ModuleDomain(ip); dom != "" {
		if info, err := source.DomainInfo(ctx, c, dom); errors.Is(err, source.ErrPrivate) {
			m.DomainSkipped = err.Error()
		} else if err != nil {
			c.Warnf("%s: RDAP lookup of %s failed: %v", ip, dom, err)
		} else {
			m.Domain = info
		}
	}

	vi := source.FetchVanity(ctx, c, ip, ip)
	m.Page = vi
	switch {
	case vi.TLSError:
		add(report.High, "tls-error", "TLS certificate error on the import page",
			fmt.Sprintf("Fetching %s failed with a certificate error: %s. The go command refuses the page, so direct-mode builds fail.", vi.URL, vi.Error))
	case vi.DNSError:
		add(report.High, "dns-error", "import domain does not resolve",
			fmt.Sprintf("%s does not resolve: %s. If the domain lapses, whoever registers it decides where the module's code comes from.", firstElem(ip), vi.Error))
	case len(vi.Imports) == 0 && vi.Error != "":
		add(report.High, "page-unreachable", "import page is unreachable",
			fmt.Sprintf("GET %s failed: %s.", vi.URL, vi.Error))
	case len(vi.Imports) == 0:
		add(report.High, "no-go-import", "import page has no go-import meta tag",
			fmt.Sprintf("%s (final URL %s) returned a page without <meta name=\"go-import\">; the go command cannot resolve %s directly.", vi.URL, vi.FinalURL, ip))
	}
	if vi.Status >= 400 && len(vi.Imports) > 0 {
		add(report.Low, "error-status", fmt.Sprintf("go-import tags are served with HTTP %d", vi.Status),
			"The go command accepts tags from error pages, but caches, proxies and other tools may not.")
	}
	if vi.FinalURL != "" && !vi.HTTPS && (len(vi.Imports) > 0 || vi.Error == "") {
		add(report.High, "insecure-http", "import page is served over plain HTTP",
			fmt.Sprintf("The page ended at %s. The go command refuses insecure redirects unless GOINSECURE is set; anyone on the network path can substitute the go-import tag.", vi.FinalURL))
	}
	if vi.RedirectHost != "" {
		add(report.Medium, "cross-host-redirect", "import page redirects to "+vi.RedirectHost,
			fmt.Sprintf("%s redirects to %s. Whoever controls %s controls where %s is fetched from.", vi.URL, vi.FinalURL, vi.RedirectHost, ip))
	}

	if len(vi.Imports) > 0 {
		match, err := source.MatchGoImport(vi.Imports, ip)
		if err != nil {
			m.MatchError = err.Error()
			rule, title := "prefix-mismatch", "no go-import tag matches the import path"
			if strings.HasPrefix(err.Error(), "multiple") {
				rule, title = "multiple-matches", "multiple go-import tags match the import path"
			}
			add(report.High, rule, title, fmt.Sprintf("%s: the go command fails with: %v.", vi.URL, err))
		} else {
			m.Match = match
			checkMatch(ctx, c, &m, add)
		}
	}

	if m.Domain != nil {
		domainFindings(add, m.Domain, "vanity import domain "+m.Domain.Name, noResponse(vi), *vanityFlags.expiryDays, now)
	}

	if m.Match != nil && *vanityFlags.subpaths > 0 && d.CodeVersion() != "" {
		probeSubpaths(ctx, c, &m, add)
	}
	return m
}

// checkMatch validates the selected go-import tag.
func checkMatch(ctx context.Context, c *cli.Context, m *VanityModule, add func(report.Severity, string, string, string)) {
	ip, match := m.ImportPath, m.Match
	if !source.KnownVCS[match.VCS] {
		add(report.High, "unknown-vcs", fmt.Sprintf("go-import tag names unknown VCS %q", match.VCS),
			"The go command supports git, hg, svn, bzr, fossil and mod.")
		return
	}
	u, err := url.Parse(match.Repo)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Scheme == "file" {
		add(report.High, "invalid-repo-url", "go-import repository URL is invalid",
			fmt.Sprintf("%q is not a valid repository root URL (the go command requires a scheme and host).", match.Repo))
		return
	}
	switch u.Scheme {
	case "https", "ssh", "git+ssh", "bzr+ssh", "svn+ssh":
	default:
		add(report.Medium, "insecure-repo-url", "repository URL uses an insecure scheme ("+u.Scheme+")",
			fmt.Sprintf("%s is fetched without transport security; the go command refuses it unless GOINSECURE covers %s.", match.Repo, ip))
	}
	if match.Prefix != ip {
		// The go command fetches the prefix's own page and requires it to
		// declare the same tag.
		pp := source.FetchVanity(ctx, c, match.Prefix, match.Prefix)
		m.PrefixPage = pp
		pm, err := source.MatchGoImport(pp.Imports, match.Prefix)
		switch {
		case len(pp.Imports) == 0:
			add(report.High, "prefix-page-missing", "page of the repository root "+match.Prefix+" has no go-import tag",
				fmt.Sprintf("The tag on %s points at prefix %s, but %s does not confirm it (%s). The go command fails to verify the import.", m.Page.URL, match.Prefix, pp.URL, firstNonEmpty(pp.Error, "no tags")))
		case err != nil:
			add(report.High, "prefix-page-mismatch", "page of the repository root "+match.Prefix+" does not match",
				fmt.Sprintf("%s: %v.", pp.URL, err))
		case *pm != *match:
			add(report.High, "prefix-disagree", "repository root page disagrees about go-import",
				fmt.Sprintf("%s says %q but %s says %q; the go command rejects the import.", m.Page.URL, tagString(*match), pp.URL, tagString(*pm)))
		}
	}
	if src := m.Page.Source; src == nil {
		for _, s := range m.Page.Sources {
			if !prefixCovers(s.Prefix, ip) && !prefixCovers(ip, s.Prefix) {
				add(report.Low, "go-source-mismatch", "go-source tag is for a different prefix",
					fmt.Sprintf("go-source declares %s but the go-import prefix is %s.", s.Prefix, match.Prefix))
				break
			}
		}
	}
	if !*vanityFlags.noRepo {
		m.Repo = probeRepo(ctx, c, match, ip)
		if m.Repo != nil && !m.Repo.Reachable && m.Repo.Skipped == "" {
			detail := fmt.Sprintf("%s (%s): %s.", m.Repo.URL, m.Repo.Method, firstNonEmpty(m.Repo.Error, fmt.Sprintf("HTTP %d", m.Repo.Status)))
			add(report.High, "repo-unreachable", "repository root is not reachable", detail)
		}
	}
}

func tagString(g source.GoImport) string {
	s := g.Prefix + " " + g.VCS + " " + g.Repo
	if g.Subdir != "" {
		s += " " + g.Subdir
	}
	return s
}

func prefixCovers(prefix, p string) bool {
	return prefix != "" && (p == prefix || strings.HasPrefix(p, prefix+"/"))
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// probeRepo checks that the repository root of a go-import tag answers.
func probeRepo(ctx context.Context, c *cli.Context, match *source.GoImport, importPath string) *VanityRepoCheck {
	rc := &VanityRepoCheck{URL: match.Repo}
	u, _ := url.Parse(match.Repo)
	// A private module's repository is probed only on the module's own
	// host: anything else (GitHub API, another host, a public proxy) is a
	// third party.
	if c.IsPrivate(importPath) && !strings.EqualFold(u.Hostname(), hostOnly(firstElem(importPath))) {
		c.NotePrivate(importPath)
		rc.Skipped = feeds.ErrPrivate.Error()
		return rc
	}
	switch {
	case match.VCS == "mod":
		rc.Method = "proxy-list"
		esc, err := module.EscapePath(importPath)
		if err != nil {
			esc = importPath
		}
		probe(ctx, c, rc, strings.TrimRight(match.Repo, "/")+"/"+esc+"/@v/list")
	case strings.EqualFold(u.Hostname(), "github.com"):
		rc.Method = "github-api"
		owner, name, _, ok := feeds.SplitGitHub(strings.ToLower(u.Hostname()) + u.Path)
		if !ok {
			rc.Error = "not an owner/repository URL"
			return rc
		}
		_, err := c.GitHub().Repo(ctx, owner, name)
		switch {
		case err == nil:
			rc.Reachable = true
		case httpx.IsNotFound(err):
			rc.Status = 404
			rc.Error = "GitHub repository " + owner + "/" + name + " not found"
		default:
			c.Warnf("%s: GitHub lookup failed: %v", importPath, err)
			return nil
		}
	case match.VCS == "git" && (u.Scheme == "https" || u.Scheme == "http"):
		rc.Method = "git-smart-http"
		probe(ctx, c, rc, strings.TrimRight(match.Repo, "/")+"/info/refs?service=git-upload-pack")
	case u.Scheme == "https" || u.Scheme == "http":
		rc.Method = "http-get"
		probe(ctx, c, rc, match.Repo)
	default:
		return nil // ssh and other transports cannot be probed over HTTP
	}
	return rc
}

func probe(ctx context.Context, c *cli.Context, rc *VanityRepoCheck, u string) {
	resp, err := c.HTTP().Get(ctx, endpoints.VanityFetchURL(c.Env, u), httpx.TTL(time.Hour), httpx.UseNetrc())
	if resp != nil {
		rc.Status = resp.Status
	}
	switch {
	case err == nil:
		rc.Reachable = true
	case rc.Status == 401 || rc.Status == 403:
		// Private repositories answer with an authentication challenge:
		// the root exists.
		rc.Reachable = true
	default:
		rc.Error = err.Error()
	}
}

// probeSubpaths checks that package directories below the module root
// have pages with a go-import tag agreeing with the root's.
func probeSubpaths(ctx context.Context, c *cli.Context, m *VanityModule, add func(report.Severity, string, string, string)) {
	pkgs, err := packageDirs(ctx, c, m.ImportPath, m.CodeVersion())
	if err != nil {
		c.Warnf("%s: cannot list packages for sub-path checks: %v", m.ImportPath, err)
		return
	}
	if len(pkgs) > *vanityFlags.subpaths {
		pkgs = pkgs[:*vanityFlags.subpaths]
	}
	for _, dir := range pkgs {
		sp := m.ImportPath + "/" + dir
		vi := source.FetchVanity(ctx, c, sp, sp)
		s := VanitySubpath{Path: sp, Status: vi.Status}
		match, err := source.MatchGoImport(vi.Imports, sp)
		switch {
		case len(vi.Imports) == 0:
			s.Error = firstNonEmpty(vi.Error, "no go-import tags")
			add(report.Medium, "subpath-missing", "no go-import tag for package "+sp,
				fmt.Sprintf("%s?go-get=1: %s. \"go get %s\" fails in direct mode (GOPROXY=direct, GOPRIVATE) and on proxy cache misses.", sp, s.Error, sp))
		case err != nil:
			s.Error = err.Error()
			add(report.Medium, "subpath-mismatch", "go-import tag for package "+sp+" does not match", fmt.Sprintf("%s?go-get=1: %v.", sp, err))
		case *match != *m.Match:
			s.Match = match
			s.Error = "disagrees with " + m.ImportPath
			add(report.High, "subpath-disagree", "package "+sp+" resolves to a different repository",
				fmt.Sprintf("%s says %q but %s says %q.", sp, tagString(*match), m.ImportPath, tagString(*m.Match)))
		default:
			s.OK, s.Match = true, match
		}
		m.Subpaths = append(m.Subpaths, s)
	}
}

// packageDirs lists the package directories (relative to the module root)
// of a module version, shallowest first, from its zip.
func packageDirs(ctx context.Context, c *cli.Context, modPath, version string) ([]string, error) {
	data, err := c.Proxy().Zip(ctx, modPath, version)
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	prefix := modPath + "@" + version + "/"
	seen := map[string]bool{}
	var dirs []string
	for _, f := range zr.File {
		name := strings.TrimPrefix(f.Name, prefix)
		if name == f.Name || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		dir := path.Dir(name)
		if dir == "." || seen[dir] || skipDir(dir) {
			continue
		}
		seen[dir] = true
		dirs = append(dirs, dir)
	}
	sort.Slice(dirs, func(i, j int) bool {
		di, dj := strings.Count(dirs[i], "/"), strings.Count(dirs[j], "/")
		if di != dj {
			return di < dj
		}
		return dirs[i] < dirs[j]
	})
	return dirs, nil
}

func skipDir(dir string) bool {
	for _, e := range strings.Split(dir, "/") {
		if e == "testdata" || e == "internal" || strings.HasPrefix(e, ".") || strings.HasPrefix(e, "_") {
			return true
		}
	}
	return false
}

func printVanity(c *cli.Context, res *VanityResult) {
	o := c.Out
	o.Title("Vanity import audit · " + res.Subject)
	o.Printf("%s\n", o.Dim(fmt.Sprintf("%d vanity paths audited · %d clean · %d code-host paths skipped", res.Summary.Modules, res.Summary.Clean, res.Skipped)))
	if len(res.Modules) == 0 {
		o.Println()
		o.OK("no vanity import paths in the build list")
		return
	}
	var rows [][]string
	for _, m := range res.Modules {
		status := o.Green("ok")
		if s := maxSeverity(m.Findings); s > report.Info {
			status = o.Sev(s)
		}
		repo := "-"
		if m.Match != nil {
			repo = m.Match.VCS + " " + m.Match.Repo
		}
		https := o.Green("https")
		if m.Page != nil && !m.Page.HTTPS {
			https = o.Red("http")
		}
		if m.Page != nil && m.Page.FinalURL == "" {
			https = "-"
		}
		rows = append(rows, []string{status, m.ImportPath, https, repo})
	}
	o.Heading("Import paths")
	o.Table([]string{"STATUS", "PATH", "PAGE", "REPOSITORY"}, rows)
	if len(res.Findings) == 0 {
		o.Println()
		o.OK("all vanity import paths resolve cleanly")
		return
	}
	o.Heading("Findings")
	printFindings(c, res.Findings)
	o.Printf("\n%s\n", res.Summary.severityCounts.String())
}
