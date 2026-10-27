// Package source resolves Go module paths to the source repositories they
// are fetched from: directly for paths on well-known code hosts, through
// the <meta name="go-import"> tags of vanity import pages for everything
// else. It also looks up domain registration data over RDAP, which the
// origin tools use to spot expiring or expired vanity domains.
package source

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/endpoints"
	"github.com/slash-mark-dev/go-suite/internal/httpx"
)

// Host values of Repo.Host.
const (
	GitHub    = "github.com"
	GitLab    = "gitlab.com"
	Bitbucket = "bitbucket.org"
	Vanity    = "vanity"
	Unknown   = "unknown"
)

// Repo is the source repository a module path resolves to.
type Repo struct {
	// Module is the module path that was resolved.
	Module string `json:"module"`
	// Host says how the path resolved: a code host ("github.com",
	// "gitlab.com", "bitbucket.org"), "vanity" (go-import meta tag) or
	// "unknown" (not a network path).
	Host string `json:"host"`
	// RepoHost is the host of URL ("github.com", "go.googlesource.com", ...).
	RepoHost string `json:"repoHost,omitempty"`
	// Owner and Name are set when the repository is on a known code host.
	Owner  string `json:"owner,omitempty"`
	Name   string `json:"name,omitempty"`
	Subdir string `json:"subdir,omitempty"`
	URL    string `json:"url,omitempty"`
	VCS    string `json:"vcs,omitempty"`
	// WellKnown names a vanity family resolved without a network fetch
	// ("golang.org/x", "gopkg.in").
	WellKnown string      `json:"wellKnown,omitempty"`
	Vanity    *VanityInfo `json:"vanity,omitempty"`
	Err       error       `json:"-"`
	Error     string      `json:"error,omitempty"`
}

// OnGitHub reports whether the repository is a GitHub repository with a
// known owner and name.
func (r *Repo) OnGitHub() bool { return r.RepoHost == GitHub && r.Owner != "" && r.Name != "" }

// Slug returns "owner/name" or "".
func (r *Repo) Slug() string {
	if r.Owner == "" {
		return ""
	}
	return r.Owner + "/" + r.Name
}

// GoImport is one <meta name="go-import" content="prefix vcs repo [subdir]">.
type GoImport struct {
	Prefix string `json:"prefix"`
	VCS    string `json:"vcs"`
	Repo   string `json:"repo"`
	Subdir string `json:"subdir,omitempty"`
}

// GoSource is one <meta name="go-source" content="prefix home dir file">.
type GoSource struct {
	Prefix string `json:"prefix"`
	Home   string `json:"home,omitempty"`
	Dir    string `json:"dir,omitempty"`
	File   string `json:"file,omitempty"`
}

// VanityInfo records how a vanity import page was fetched and what it said.
type VanityInfo struct {
	// ImportPath is the path whose page supplied the answer (the module
	// path or one of its parents).
	ImportPath string `json:"importPath"`
	// URL is the page URL as the go command would fetch it; FinalURL is
	// the URL after redirects (both in https://<path> form even when
	// SMGO_VANITY_BASE redirects fetches elsewhere).
	URL      string `json:"url"`
	FinalURL string `json:"finalUrl,omitempty"`
	// HTTPS is true when the page was served over HTTPS end to end.
	HTTPS bool `json:"https"`
	// RedirectHost is set when the page redirected to another domain.
	RedirectHost string     `json:"redirectHost,omitempty"`
	Imports      []GoImport `json:"imports,omitempty"`
	Sources      []GoSource `json:"sources,omitempty"`
	// Match is the go-import tag selected for the module path.
	Match  *GoImport `json:"match,omitempty"`
	Source *GoSource `json:"source,omitempty"`
	// Conflicts lists go-import tags for the same prefix that disagree
	// with Match.
	Conflicts []GoImport `json:"conflicts,omitempty"`
	Status    int        `json:"status,omitempty"`
	TLSError  bool       `json:"tlsError,omitempty"`
	DNSError  bool       `json:"dnsError,omitempty"`
	Error     string     `json:"error,omitempty"`
}

// IsCodeHost reports whether a module path is on GitHub, GitLab or
// Bitbucket (resolved without go-import tags).
func IsCodeHost(path string) bool {
	h := firstElem(path)
	return h == GitHub || h == GitLab || h == Bitbucket
}

func firstElem(p string) string {
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return p
}

// Resolve maps a module path to its repository. Code-host paths and the
// golang.org/x and gopkg.in families resolve without network access; other
// paths are resolved through their go-import meta tags. Failures are
// recorded in Repo.Err rather than returned.
func Resolve(ctx context.Context, c *cli.Context, modulePath string) *Repo {
	r := &Repo{Module: modulePath}
	if d := direct(modulePath, r); d {
		return r
	}
	if wellKnown(modulePath, r) {
		return r
	}
	return resolveVanity(ctx, c, modulePath, r)
}

// ResolveVanity always resolves modulePath through its vanity import page,
// even for well-known families (used by the vanity auditor).
func ResolveVanity(ctx context.Context, c *cli.Context, modulePath string) *Repo {
	r := &Repo{Module: modulePath}
	if direct(modulePath, r) {
		return r
	}
	return resolveVanity(ctx, c, modulePath, r)
}

func direct(p string, r *Repo) bool {
	host := firstElem(p)
	switch host {
	case GitHub, GitLab, Bitbucket:
	default:
		if !strings.Contains(host, ".") {
			r.Host = Unknown
			r.Err = fmt.Errorf("%s is not a network module path", p)
			r.Error = r.Err.Error()
			return true
		}
		return false
	}
	r.Host, r.RepoHost, r.VCS = host, host, "git"
	f := strings.SplitN(p, "/", 4)
	if len(f) < 3 || f[1] == "" || f[2] == "" {
		r.Err = fmt.Errorf("%s: incomplete %s path", p, host)
		r.Error = r.Err.Error()
		return true
	}
	r.Owner, r.Name = f[1], strings.TrimSuffix(f[2], ".git")
	if len(f) == 4 {
		r.Subdir = f[3]
	}
	r.URL = "https://" + host + "/" + r.Owner + "/" + r.Name
	return true
}

// wellKnown handles cheap vanity families.
func wellKnown(p string, r *Repo) bool {
	switch {
	case strings.HasPrefix(p, "golang.org/x/"):
		f := strings.SplitN(strings.TrimPrefix(p, "golang.org/x/"), "/", 2)
		if f[0] == "" {
			return false
		}
		r.Host, r.RepoHost, r.VCS, r.WellKnown = Vanity, "go.googlesource.com", "git", "golang.org/x"
		r.Name = f[0]
		r.URL = "https://go.googlesource.com/" + f[0]
		if len(f) == 2 {
			r.Subdir = f[1]
		}
		return true
	case strings.HasPrefix(p, "gopkg.in/"):
		f := strings.Split(strings.TrimPrefix(p, "gopkg.in/"), "/")
		var user, pkg string
		switch {
		case len(f) >= 1 && gopkgVersioned(f[0]):
			pkg = gopkgName(f[0])
			user = "go-" + pkg
		case len(f) >= 2 && gopkgVersioned(f[1]):
			user, pkg = f[0], gopkgName(f[1])
		default:
			return false
		}
		r.Host, r.RepoHost, r.VCS, r.WellKnown = Vanity, GitHub, "git", "gopkg.in"
		r.Owner, r.Name = user, pkg
		r.URL = "https://github.com/" + user + "/" + pkg
		return true
	}
	return false
}

func gopkgVersioned(elem string) bool {
	i := strings.LastIndex(elem, ".v")
	if i <= 0 {
		return false
	}
	for _, ch := range elem[i+2:] {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return len(elem) > i+2
}

func gopkgName(elem string) string { return elem[:strings.LastIndex(elem, ".v")] }

func resolveVanity(ctx context.Context, c *cli.Context, modulePath string, r *Repo) *Repo {
	r.Host = Vanity
	var first *VanityInfo
	// Try the module path, then its parents (the go command asks for the
	// full path; servers usually answer for any path below the root).
	for p := modulePath; ; {
		vi := FetchVanity(ctx, c, p, modulePath)
		if first == nil {
			first = vi
		}
		if vi.Match != nil {
			first = vi
			break
		}
		// Only fall back to parents when the page was missing, not when it
		// answered with tags for a different prefix.
		if vi.Status != 404 || len(vi.Imports) > 0 {
			break
		}
		i := strings.LastIndexByte(p, '/')
		if i < 0 {
			break
		}
		p = p[:i]
	}
	r.Vanity = first
	if first.Match == nil {
		msg := first.Error
		if msg == "" {
			msg = "no go-import meta tag matches " + modulePath
		}
		r.Err = errors.New(msg)
		r.Error = msg
		return r
	}
	m := first.Match
	r.VCS = m.VCS
	r.URL = m.Repo
	if m.Subdir != "" {
		r.Subdir = m.Subdir
	}
	if rest := strings.TrimPrefix(modulePath, m.Prefix); rest != modulePath && rest != "" {
		r.Subdir = strings.TrimPrefix(strings.Trim(r.Subdir+rest, "/"), "/")
	}
	if u, err := url.Parse(m.Repo); err == nil {
		r.RepoHost = strings.ToLower(u.Hostname())
		if r.RepoHost == GitHub || r.RepoHost == GitLab || r.RepoHost == Bitbucket {
			f := strings.Split(strings.Trim(u.Path, "/"), "/")
			if len(f) >= 2 {
				r.Owner, r.Name = f[0], strings.TrimSuffix(f[1], ".git")
			}
		}
	}
	return r
}

// FetchVanity fetches the go-get page of importPath and selects the
// go-import tag for modulePath (pass importPath again to audit a path on
// its own).
func FetchVanity(ctx context.Context, c *cli.Context, importPath, modulePath string) *VanityInfo {
	vi := &VanityInfo{ImportPath: importPath, URL: "https://" + importPath + "?go-get=1"}
	raw := endpoints.VanityURL(c.Env, importPath)
	resp, err := c.HTTP().Get(ctx, raw, httpx.TTL(time.Hour), httpx.UseNetrc())
	if resp != nil {
		vi.Status = resp.Status
		vi.FinalURL = logicalURL(c, resp.URL)
	}
	if err != nil {
		vi.Status = max(vi.Status, httpx.StatusCode(err))
		vi.Error = err.Error()
		vi.TLSError = IsTLSError(err)
		vi.DNSError = IsDNSError(err)
		// Like the go command, accept meta tags served with an error status
		// (some hosts put them in their 404 page).
		if resp == nil || len(resp.Body) == 0 {
			return vi
		}
	}
	if vi.FinalURL == "" {
		vi.FinalURL = vi.URL
	}
	if fu, err := url.Parse(vi.FinalURL); err == nil {
		vi.HTTPS = fu.Scheme == "https"
		host := strings.ToLower(fu.Hostname())
		if host != strings.ToLower(hostOnly(firstElem(importPath))) {
			vi.RedirectHost = host
		}
	}
	vi.Imports, vi.Sources = ParseMeta(string(resp.Body))
	vi.Match, vi.Conflicts = SelectImport(vi.Imports, modulePath)
	if vi.Match != nil && vi.Error != "" {
		vi.Error = "" // tags served with an error status are still used
	}
	if vi.Match != nil {
		for i := range vi.Sources {
			s := vi.Sources[i]
			if s.Prefix == vi.Match.Prefix {
				vi.Source = &s
				break
			}
		}
	}
	return vi
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

// logicalURL maps a URL fetched through SMGO_VANITY_BASE back to the
// https://<import path> form the go command would have used. URLs under
// "<SMGO_VANITY_BASE>-http/" stand for plain http://<path> (so tests can
// simulate a downgrade to HTTP).
func logicalURL(c *cli.Context, raw string) string {
	if b := c.Env.Getenv("SMGO_VANITY_BASE"); b != "" {
		b = strings.TrimRight(b, "/")
		if strings.HasPrefix(raw, b+"/") {
			return "https://" + strings.TrimPrefix(raw, b+"/")
		}
		if strings.HasPrefix(raw, b+"-http/") {
			return "http://" + strings.TrimPrefix(raw, b+"-http/")
		}
	}
	return raw
}

// IsDNSError reports whether err looks like a name-resolution failure.
func IsDNSError(err error) bool {
	if err == nil {
		return false
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such host")
}

// IsTLSError reports whether err looks like a TLS / certificate failure.
func IsTLSError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "x509:") || strings.Contains(s, "tls:") || strings.Contains(s, "certificate")
}

// SelectImport returns the go-import tag whose prefix covers modulePath
// (longest prefix wins; "mod" entries are used only when nothing else
// matches) and any tags for the same prefix that disagree with it.
func SelectImport(imports []GoImport, modulePath string) (*GoImport, []GoImport) {
	var best *GoImport
	for i := range imports {
		im := imports[i]
		if !prefixOf(im.Prefix, modulePath) {
			continue
		}
		switch {
		case best == nil,
			len(im.Prefix) > len(best.Prefix),
			len(im.Prefix) == len(best.Prefix) && best.VCS == "mod" && im.VCS != "mod":
			b := im
			best = &b
		}
	}
	if best == nil {
		return nil, nil
	}
	var conflicts []GoImport
	for _, im := range imports {
		if im.Prefix != best.Prefix || im == *best {
			continue
		}
		// A "mod" entry next to a VCS entry is the documented way to serve
		// both a proxy and a repository; it is not a conflict.
		if im.VCS == "mod" || best.VCS == "mod" {
			continue
		}
		conflicts = append(conflicts, im)
	}
	return best, conflicts
}

// KnownVCS lists the go-import VCS values the go command accepts.
var KnownVCS = map[string]bool{"git": true, "hg": true, "svn": true, "bzr": true, "fossil": true, "mod": true}

// MatchGoImport selects the go-import tag for importPath exactly as the go
// command does in module mode: "mod" entries take precedence over VCS
// entries with the same prefix, and more than one remaining tag whose
// prefix covers importPath is an error ("multiple meta tags match import
// path"), even when the prefixes differ in length.
func MatchGoImport(imports []GoImport, importPath string) (*GoImport, error) {
	mods := map[string]bool{}
	var list []GoImport
	for _, im := range imports {
		if im.VCS == "mod" {
			mods[im.Prefix] = true
			list = append(list, im)
		}
	}
	for _, im := range imports {
		if im.VCS != "mod" && !mods[im.Prefix] {
			list = append(list, im)
		}
	}
	match := -1
	var mismatches []string
	for i, im := range list {
		if !prefixOf(im.Prefix, importPath) {
			mismatches = append(mismatches, im.Prefix)
			continue
		}
		if match >= 0 {
			if list[match].VCS == "mod" && im.VCS != "mod" {
				break
			}
			return nil, fmt.Errorf("multiple meta tags match import path %q", importPath)
		}
		match = i
	}
	if match < 0 {
		if len(mismatches) > 0 {
			return nil, fmt.Errorf("meta tags do not match import path %q (found prefixes %s)", importPath, strings.Join(mismatches, ", "))
		}
		return nil, fmt.Errorf("no go-import meta tags for %q", importPath)
	}
	m := list[match]
	return &m, nil
}

func prefixOf(prefix, path string) bool {
	return prefix != "" && (path == prefix || strings.HasPrefix(path, prefix+"/"))
}

// RepoKey normalizes a repository URL for comparison: lower-case host and
// path without scheme, userinfo, ".git" or trailing slash.
func RepoKey(u string) string {
	u = strings.TrimSpace(u)
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.Index(u, "@"); i >= 0 && i < strings.IndexByte(u+"/", '/') {
		u = u[i+1:]
	}
	u = strings.TrimRight(u, "/")
	u = strings.TrimSuffix(u, ".git")
	return strings.ToLower(u)
}
