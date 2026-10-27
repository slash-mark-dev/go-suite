// Package feeds holds clients for the live data sources other than the
// module proxy, checksum database and vulnerability database: CISA KEV,
// FIRST EPSS, deps.dev, the GitHub REST API, the Go module index and the
// go.dev release list.
package feeds

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/httpx"
	"github.com/slash-mark-dev/go-suite/internal/semver"
)

// ---------- CISA Known Exploited Vulnerabilities ----------

// KEVEntry is one entry of the CISA KEV catalog.
type KEVEntry struct {
	CVE                string `json:"cveID"`
	VendorProject      string `json:"vendorProject"`
	Product            string `json:"product"`
	Name               string `json:"vulnerabilityName"`
	DateAdded          string `json:"dateAdded"`
	DueDate            string `json:"dueDate"`
	RequiredAction     string `json:"requiredAction"`
	RansomwareCampaign string `json:"knownRansomwareCampaignUse"`
}

// KEV fetches the catalog keyed by CVE ID.
func KEV(ctx context.Context, hc *httpx.Client, u string) (map[string]*KEVEntry, error) {
	var cat struct {
		Vulnerabilities []*KEVEntry `json:"vulnerabilities"`
	}
	if err := hc.GetJSON(ctx, u, &cat, httpx.TTL(6*time.Hour)); err != nil {
		return nil, err
	}
	m := make(map[string]*KEVEntry, len(cat.Vulnerabilities))
	for _, e := range cat.Vulnerabilities {
		m[e.CVE] = e
	}
	return m, nil
}

// ---------- FIRST EPSS ----------

// EPSSScore is the exploit prediction score of a CVE.
type EPSSScore struct {
	CVE        string  `json:"cve"`
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
}

// EPSS fetches scores for the given CVEs (batched).
func EPSS(ctx context.Context, hc *httpx.Client, base string, cves []string) (map[string]EPSSScore, error) {
	out := map[string]EPSSScore{}
	uniq := map[string]bool{}
	var list []string
	for _, c := range cves {
		if strings.HasPrefix(c, "CVE-") && !uniq[c] {
			uniq[c] = true
			list = append(list, c)
		}
	}
	sort.Strings(list)
	for i := 0; i < len(list); i += 80 {
		j := i + 80
		if j > len(list) {
			j = len(list)
		}
		var resp struct {
			Data []struct {
				CVE        string `json:"cve"`
				EPSS       string `json:"epss"`
				Percentile string `json:"percentile"`
				Date       string `json:"date"`
			} `json:"data"`
		}
		u := base + "?cve=" + strings.Join(list[i:j], ",")
		if err := hc.GetJSON(ctx, u, &resp, httpx.TTL(6*time.Hour)); err != nil {
			return out, err
		}
		for _, d := range resp.Data {
			e, _ := strconv.ParseFloat(d.EPSS, 64)
			p, _ := strconv.ParseFloat(d.Percentile, 64)
			out[d.CVE] = EPSSScore{CVE: d.CVE, EPSS: e, Percentile: p, Date: d.Date}
		}
	}
	return out, nil
}

// ---------- deps.dev ----------

// ErrPrivate is returned, without any request being made, when a lookup
// would send a private module path (GOPRIVATE, GONOPROXY, GONOSUMDB) to a
// third-party service.
var ErrPrivate = errors.New("skipped: private module")

// DepsDev is a deps.dev API v3 client for the Go system.
type DepsDev struct {
	Base string
	HTTP *httpx.Client
	// Private reports whether a module path or project ID
	// ("github.com/owner/repo") is private. Lookups of private names are
	// refused with ErrPrivate and never reach deps.dev.
	Private func(string) bool
	// OnPrivate, if set, is called with each private name refused.
	OnPrivate func(string)
}

func (d *DepsDev) refuse(name string) bool {
	if d.Private == nil || !d.Private(name) {
		return false
	}
	if d.OnPrivate != nil {
		d.OnPrivate(name)
	}
	return true
}

// DDVersion is the deps.dev view of a module version.
type DDVersion struct {
	VersionKey struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"versionKey"`
	PublishedAt  string   `json:"publishedAt"`
	IsDefault    bool     `json:"isDefault"`
	Licenses     []string `json:"licenses"`
	AdvisoryKeys []struct {
		ID string `json:"id"`
	} `json:"advisoryKeys"`
	Links []struct {
		Label string `json:"label"`
		URL   string `json:"url"`
	} `json:"links"`
	RelatedProjects []struct {
		ProjectKey struct {
			ID string `json:"id"`
		} `json:"projectKey"`
		RelationProvenance string `json:"relationProvenance"`
		RelationType       string `json:"relationType"`
	} `json:"relatedProjects"`
}

// SourceRepo returns the related source repository project ID
// ("github.com/owner/repo"), if any.
func (v *DDVersion) SourceRepo() string {
	for _, p := range v.RelatedProjects {
		if p.RelationType == "SOURCE_REPO" {
			return p.ProjectKey.ID
		}
	}
	return ""
}

// DDProject is the deps.dev view of a source repository.
type DDProject struct {
	ProjectKey struct {
		ID string `json:"id"`
	} `json:"projectKey"`
	OpenIssuesCount int    `json:"openIssuesCount"`
	StarsCount      int    `json:"starsCount"`
	ForksCount      int    `json:"forksCount"`
	License         string `json:"license"`
	Description     string `json:"description"`
	Scorecard       *struct {
		Date         string  `json:"date"`
		OverallScore float64 `json:"overallScore"`
		Checks       []struct {
			Name   string  `json:"name"`
			Score  float64 `json:"score"`
			Reason string  `json:"reason"`
		} `json:"checks"`
	} `json:"scorecard"`
}

// Version fetches a module version.
func (d *DepsDev) Version(ctx context.Context, path, version string) (*DDVersion, error) {
	if d.refuse(path) {
		return nil, ErrPrivate
	}
	var v DDVersion
	u := fmt.Sprintf("%s/v3/systems/go/packages/%s/versions/%s", d.Base, url.PathEscape(path), url.PathEscape(version))
	if err := d.HTTP.GetJSON(ctx, u, &v, httpx.TTL(24*time.Hour)); err != nil {
		return nil, err
	}
	return &v, nil
}

// Project fetches a project ("github.com/owner/repo").
func (d *DepsDev) Project(ctx context.Context, id string) (*DDProject, error) {
	if d.refuse(id) {
		return nil, ErrPrivate
	}
	var p DDProject
	u := fmt.Sprintf("%s/v3/projects/%s", d.Base, url.PathEscape(id))
	if err := d.HTTP.GetJSON(ctx, u, &p, httpx.TTL(24*time.Hour)); err != nil {
		return nil, err
	}
	return &p, nil
}

// Dependents returns how many packages depend on the module version.
func (d *DepsDev) Dependents(ctx context.Context, path, version string) (total, direct int, err error) {
	if d.refuse(path) {
		return 0, 0, ErrPrivate
	}
	var r struct {
		DependentCount         int `json:"dependentCount"`
		DirectDependentCount   int `json:"directDependentCount"`
		IndirectDependentCount int `json:"indirectDependentCount"`
	}
	u := fmt.Sprintf("%s/v3alpha/systems/go/packages/%s/versions/%s:dependents", d.Base, url.PathEscape(path), url.PathEscape(version))
	if err := d.HTTP.GetJSON(ctx, u, &r, httpx.TTL(24*time.Hour)); err != nil {
		return 0, 0, err
	}
	return r.DependentCount, r.DirectDependentCount, nil
}

// ---------- GitHub ----------

// GitHub is a minimal GitHub REST client.
type GitHub struct {
	Base string
	HTTP *httpx.Client
}

// Repo is the subset of repository fields sm-go uses.
type Repo struct {
	FullName   string    `json:"full_name"`
	HTMLURL    string    `json:"html_url"`
	Archived   bool      `json:"archived"`
	Disabled   bool      `json:"disabled"`
	Fork       bool      `json:"fork"`
	Private    bool      `json:"private"`
	CreatedAt  time.Time `json:"created_at"`
	PushedAt   time.Time `json:"pushed_at"`
	Default    string    `json:"default_branch"`
	Stars      int       `json:"stargazers_count"`
	OpenIssues int       `json:"open_issues_count"`
	Owner      struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"owner"`
	License *struct {
		SPDX string `json:"spdx_id"`
	} `json:"license"`
	Parent *struct {
		FullName string `json:"full_name"`
	} `json:"parent"`
	// Moved is true when the API redirected (repository renamed or
	// transferred) and FullName differs from the requested name.
	Moved     bool   `json:"-"`
	Requested string `json:"-"`
}

// Repo fetches owner/name. Renames and transfers are detected through the
// API's redirect.
func (g *GitHub) Repo(ctx context.Context, owner, name string) (*Repo, error) {
	r, err := g.HTTP.Get(ctx, fmt.Sprintf("%s/repos/%s/%s", g.Base, url.PathEscape(owner), url.PathEscape(name)), httpx.TTL(time.Hour))
	if err != nil {
		return nil, err
	}
	var repo Repo
	if err := json.Unmarshal(r.Body, &repo); err != nil {
		return nil, err
	}
	repo.Requested = owner + "/" + name
	repo.Moved = !strings.EqualFold(repo.FullName, repo.Requested)
	return &repo, nil
}

// Account is a GitHub user or organization.
type Account struct {
	Login     string    `json:"login"`
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"created_at"`
}

// Account fetches a user or organization; httpx.IsNotFound(err) means the
// login does not exist (deleted, renamed away, or never existed) and may
// be registrable by anyone.
func (g *GitHub) Account(ctx context.Context, login string) (*Account, error) {
	var a Account
	if err := g.HTTP.GetJSON(ctx, fmt.Sprintf("%s/users/%s", g.Base, url.PathEscape(login)), &a, httpx.TTL(time.Hour)); err != nil {
		return nil, err
	}
	return &a, nil
}

// TagCommit resolves a tag to its commit SHA, dereferencing annotated tags.
func (g *GitHub) TagCommit(ctx context.Context, owner, name, tag string) (string, error) {
	var ref struct {
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
	}
	u := fmt.Sprintf("%s/repos/%s/%s/git/ref/tags/%s", g.Base, url.PathEscape(owner), url.PathEscape(name), escapeRef(tag))
	if err := g.HTTP.GetJSON(ctx, u, &ref, httpx.NoCache()); err != nil {
		return "", err
	}
	sha, typ := ref.Object.SHA, ref.Object.Type
	for i := 0; typ == "tag" && i < 5; i++ {
		var t struct {
			Object struct {
				SHA  string `json:"sha"`
				Type string `json:"type"`
			} `json:"object"`
		}
		if err := g.HTTP.GetJSON(ctx, fmt.Sprintf("%s/repos/%s/%s/git/tags/%s", g.Base, owner, name, sha), &t, httpx.Immutable()); err != nil {
			return "", err
		}
		sha, typ = t.Object.SHA, t.Object.Type
	}
	return sha, nil
}

func escapeRef(ref string) string {
	parts := strings.Split(ref, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// CommitExists reports whether a commit SHA (or prefix) exists in the repo.
func (g *GitHub) CommitExists(ctx context.Context, owner, name, sha string) (bool, error) {
	_, err := g.HTTP.Get(ctx, fmt.Sprintf("%s/repos/%s/%s/commits/%s", g.Base, owner, name, sha), httpx.TTL(24*time.Hour))
	if err == nil {
		return true, nil
	}
	if httpx.IsNotFound(err) || httpx.StatusCode(err) == 422 {
		return false, nil
	}
	return false, err
}

// Tag is a tag listing entry.
type Tag struct {
	Name   string `json:"name"`
	Commit struct {
		SHA string `json:"sha"`
	} `json:"commit"`
}

// Tags lists up to max tags.
func (g *GitHub) Tags(ctx context.Context, owner, name string, max int) ([]Tag, error) {
	var all []Tag
	for page := 1; len(all) < max && page <= 10; page++ {
		var tags []Tag
		u := fmt.Sprintf("%s/repos/%s/%s/tags?per_page=100&page=%d", g.Base, owner, name, page)
		if err := g.HTTP.GetJSON(ctx, u, &tags); err != nil {
			return all, err
		}
		all = append(all, tags...)
		if len(tags) < 100 {
			break
		}
	}
	if len(all) > max {
		all = all[:max]
	}
	return all, nil
}

// Contributors returns the number of contributors (up to 100) and the
// share of commits by the top contributor.
func (g *GitHub) Contributors(ctx context.Context, owner, name string) (count int, topShare float64, err error) {
	var cs []struct {
		Login         string `json:"login"`
		Contributions int    `json:"contributions"`
	}
	if err := g.HTTP.GetJSON(ctx, fmt.Sprintf("%s/repos/%s/%s/contributors?per_page=100", g.Base, owner, name), &cs, httpx.TTL(24*time.Hour)); err != nil {
		return 0, 0, err
	}
	total, top := 0, 0
	for _, c := range cs {
		total += c.Contributions
		if c.Contributions > top {
			top = c.Contributions
		}
	}
	if total > 0 {
		topShare = float64(top) / float64(total)
	}
	return len(cs), topShare, nil
}

// SplitGitHub splits a module path or repo URL on github.com into owner,
// repo and the remaining subdirectory.
func SplitGitHub(p string) (owner, repo, subdir string, ok bool) {
	p = strings.TrimPrefix(p, "https://")
	p = strings.TrimPrefix(p, "http://")
	p = strings.TrimSuffix(p, ".git")
	if !strings.HasPrefix(p, "github.com/") {
		return "", "", "", false
	}
	f := strings.SplitN(strings.TrimPrefix(p, "github.com/"), "/", 3)
	if len(f) < 2 || f[0] == "" || f[1] == "" {
		return "", "", "", false
	}
	if len(f) == 3 {
		subdir = f[2]
	}
	return f[0], strings.TrimSuffix(f[1], ".git"), subdir, true
}

// ---------- Go module index ----------

// IndexEntry is one line of index.golang.org.
type IndexEntry struct {
	Path      string    `json:"Path"`
	Version   string    `json:"Version"`
	Timestamp time.Time `json:"Timestamp"`
}

// Index fetches new module versions since t (at most limit per page,
// following pages until now or maxPages). Entries are not repeated across
// page boundaries.
func Index(ctx context.Context, hc *httpx.Client, base string, since time.Time, limit, maxPages int) ([]IndexEntry, error) {
	p, err := IndexSince(ctx, hc, base, since, nil, limit, maxPages)
	if p == nil {
		return nil, err
	}
	return p.Entries, err
}

// IndexPage is the result of IndexSince.
type IndexPage struct {
	Entries []IndexEntry
	// Next is the cursor to resume from: the timestamp of the last entry
	// (or the starting time when there were none).
	Next time.Time
	// NextSeen are the "path@version" keys of the entries whose timestamp
	// equals Next; pass them back as seen when resuming, because the
	// index's since parameter is inclusive.
	NextSeen []string
	// Complete reports whether the index was read up to its end (false
	// when maxPages stopped the loop).
	Complete bool
}

// IndexKey is the identity of an index entry used for deduplication.
func IndexKey(e IndexEntry) string { return e.Path + "@" + e.Version }

// IndexSince reads index.golang.org from since (inclusive, as the real
// index treats it), skipping entries at exactly since whose keys are in
// seen, and follows pages of limit entries until a short page (caught up)
// or maxPages. On error the entries read so far are returned with the
// cursor after them.
func IndexSince(ctx context.Context, hc *httpx.Client, base string, since time.Time, seen []string, limit, maxPages int) (*IndexPage, error) {
	if limit <= 0 || limit > 2000 {
		limit = 2000
	}
	if maxPages <= 0 {
		maxPages = 1
	}
	since = since.UTC()
	boundary := map[string]bool{}
	for _, k := range seen {
		boundary[k] = true
	}
	res := &IndexPage{Next: since}
	for page := 0; page < maxPages; page++ {
		u := fmt.Sprintf("%s/index?since=%s&limit=%d", base, url.QueryEscape(since.Format(time.RFC3339Nano)), limit)
		r, err := hc.Get(ctx, u, httpx.NoCache())
		if err != nil {
			res.NextSeen = keys(boundary)
			return res, err
		}
		n := 0
		sc := bufio.NewScanner(bytes.NewReader(r.Body))
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var e IndexEntry
			if json.Unmarshal(sc.Bytes(), &e) != nil || e.Path == "" {
				continue
			}
			n++
			e.Timestamp = e.Timestamp.UTC()
			if e.Timestamp.Before(since) {
				continue
			}
			k := IndexKey(e)
			if e.Timestamp.Equal(since) {
				if boundary[k] {
					continue
				}
			} else {
				since = e.Timestamp
				boundary = map[string]bool{}
			}
			boundary[k] = true
			res.Entries = append(res.Entries, e)
		}
		res.Next = since
		if n < limit {
			res.Complete = true
			break
		}
		if n > 0 && len(boundary) >= n {
			// A full page sharing one timestamp: asking again with the same
			// since would return the same page. Step past it.
			since = since.Add(time.Nanosecond)
			boundary = map[string]bool{}
			res.Next = since
		}
	}
	res.NextSeen = keys(boundary)
	return res, nil
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------- go.dev releases ----------

// GoRelease is one Go release from go.dev/dl.
type GoRelease struct {
	Version string `json:"version"` // "go1.27.3"
	Stable  bool   `json:"stable"`
}

var relMu sync.Mutex

// GoReleases fetches every Go release, newest first.
func GoReleases(ctx context.Context, hc *httpx.Client, base string) ([]GoRelease, error) {
	relMu.Lock()
	defer relMu.Unlock()
	var rels []GoRelease
	if err := hc.GetJSON(ctx, base+"/dl/?mode=json&include=all", &rels, httpx.TTL(6*time.Hour)); err != nil {
		return nil, err
	}
	sort.SliceStable(rels, func(i, j int) bool {
		return semver.Compare(goSemver(rels[i].Version), goSemver(rels[j].Version)) > 0
	})
	return rels, nil
}

func goSemver(v string) string {
	v = strings.TrimPrefix(v, "go")
	pre := ""
	for _, k := range []string{"rc", "beta"} {
		if i := strings.Index(v, k); i >= 0 {
			pre = "-" + k + "." + v[i+len(k):]
			v = v[:i]
		}
	}
	parts := strings.Split(v, ".")
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	return "v" + strings.Join(parts, ".") + pre
}

// SupportedGo returns the supported major release lines ("go1.27",
// "go1.26": the two newest stable minors) and the latest patch of each.
func SupportedGo(rels []GoRelease) (lines []string, latest map[string]string) {
	latest = map[string]string{}
	for _, r := range rels {
		if !r.Stable {
			continue
		}
		mm := semver.MajorMinor(goSemver(r.Version))
		line := "go" + strings.TrimPrefix(mm, "v")
		if _, ok := latest[line]; !ok {
			latest[line] = r.Version
			lines = append(lines, line)
		}
	}
	if len(lines) > 2 {
		lines = lines[:2]
	}
	return lines, latest
}

// Advisory is the GitHub Advisory Database view of a GHSA.
type Advisory struct {
	GHSA     string `json:"ghsa_id"`
	Severity string `json:"severity"` // low, medium, high, critical
	CVSS     *struct {
		Score  float64 `json:"score"`
		Vector string  `json:"vector_string"`
	} `json:"cvss"`
}

// Advisory fetches a global security advisory by GHSA ID.
func (g *GitHub) Advisory(ctx context.Context, ghsa string) (*Advisory, error) {
	var a Advisory
	if err := g.HTTP.GetJSON(ctx, fmt.Sprintf("%s/advisories/%s", g.Base, url.PathEscape(ghsa)), &a, httpx.TTL(24*time.Hour)); err != nil {
		return nil, err
	}
	return &a, nil
}
