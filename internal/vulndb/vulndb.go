// Package vulndb is a client for the Go vulnerability database
// (vuln.go.dev, OSV format) with symbol-level affected data.
package vulndb

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/httpx"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/par"
	"github.com/slash-mark-dev/go-suite/internal/semver"
)

// Special module names used by the Go vulnerability database.
const (
	Stdlib    = "stdlib"
	Toolchain = "toolchain"
)

// Entry is an OSV vulnerability entry.
type Entry struct {
	ID               string            `json:"id"`
	Published        time.Time         `json:"published"`
	Modified         time.Time         `json:"modified"`
	Withdrawn        *time.Time        `json:"withdrawn,omitempty"`
	Aliases          []string          `json:"aliases,omitempty"`
	Summary          string            `json:"summary,omitempty"`
	Details          string            `json:"details,omitempty"`
	Affected         []Affected        `json:"affected"`
	References       []Reference       `json:"references,omitempty"`
	Credits          []Credit          `json:"credits,omitempty"`
	DatabaseSpecific *DatabaseSpecific `json:"database_specific,omitempty"`
}

type Affected struct {
	Package           Package            `json:"package"`
	Ranges            []Range            `json:"ranges,omitempty"`
	EcosystemSpecific *EcosystemSpecific `json:"ecosystem_specific,omitempty"`
}

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type Range struct {
	Type   string       `json:"type"`
	Events []RangeEvent `json:"events"`
}

type RangeEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type EcosystemSpecific struct {
	Imports []Import `json:"imports,omitempty"`
}

// Import lists the vulnerable symbols of one package.
type Import struct {
	Path    string   `json:"path"`
	GOOS    []string `json:"goos,omitempty"`
	GOARCH  []string `json:"goarch,omitempty"`
	Symbols []string `json:"symbols,omitempty"`
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Credit struct {
	Name string `json:"name"`
}

type DatabaseSpecific struct {
	URL          string `json:"url,omitempty"`
	ReviewStatus string `json:"review_status,omitempty"`
}

// ModuleIndex is one entry of /index/modules.json.
type ModuleIndex struct {
	Path  string `json:"path"`
	Vulns []struct {
		ID       string    `json:"id"`
		Modified time.Time `json:"modified"`
		Fixed    string    `json:"fixed,omitempty"`
	} `json:"vulns"`
}

// Client fetches from a vulndb base URL.
type Client struct {
	Base string
	http *httpx.Client
	mu   sync.Mutex
	idx  map[string]*ModuleIndex
	ents sync.Map
}

// New returns a client for base (e.g. https://vuln.go.dev).
func New(base string, hc *httpx.Client) *Client {
	return &Client{Base: strings.TrimRight(base, "/"), http: hc}
}

// Modules returns the module index, keyed by module path.
func (c *Client) Modules(ctx context.Context) (map[string]*ModuleIndex, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.idx != nil {
		return c.idx, nil
	}
	var list []*ModuleIndex
	if err := c.http.GetJSON(ctx, c.Base+"/index/modules.json", &list); err != nil {
		return nil, err
	}
	c.idx = map[string]*ModuleIndex{}
	for _, m := range list {
		c.idx[m.Path] = m
	}
	return c.idx, nil
}

// Entry fetches one entry by ID.
func (c *Client) Entry(ctx context.Context, id string) (*Entry, error) {
	if e, ok := c.ents.Load(id); ok {
		return e.(*Entry), nil
	}
	var e Entry
	if err := c.http.GetJSON(ctx, c.Base+"/ID/"+id+".json", &e); err != nil {
		return nil, err
	}
	c.ents.Store(id, &e)
	return &e, nil
}

// Finding pairs a module version with an entry affecting it.
type Finding struct {
	Module   module.Version `json:"module"`
	Entry    *Entry         `json:"-"`
	ID       string         `json:"id"`
	Affected *Affected      `json:"-"`
	FixedIn  string         `json:"fixedIn,omitempty"`
}

// ForModules returns, for each module version, the non-withdrawn entries
// that affect it. Use module path "stdlib" with a semver Go version
// (see GoToSemver) to check the standard library.
func (c *Client) ForModules(ctx context.Context, mods []module.Version) ([]Finding, error) {
	idx, err := c.Modules(ctx)
	if err != nil {
		return nil, err
	}
	type want struct {
		mod module.Version
		id  string
	}
	var wants []want
	ids := map[string]bool{}
	for _, m := range mods {
		mi, ok := idx[m.Path]
		if !ok {
			continue
		}
		for _, v := range mi.Vulns {
			wants = append(wants, want{m, v.ID})
			ids[v.ID] = true
		}
	}
	var idList []string
	for id := range ids {
		idList = append(idList, id)
	}
	sort.Strings(idList)
	ents, errs := par.Map(ctx, 8, idList, func(ctx context.Context, id string) (*Entry, error) { return c.Entry(ctx, id) })
	if err := par.FirstErr(errs); err != nil {
		return nil, err
	}
	byID := map[string]*Entry{}
	for i, id := range idList {
		byID[id] = ents[i]
	}
	var out []Finding
	for _, w := range wants {
		e := byID[w.id]
		if e == nil || e.Withdrawn != nil {
			continue
		}
		for i := range e.Affected {
			a := &e.Affected[i]
			if a.Package.Name != w.mod.Path {
				continue
			}
			if a.AffectsVersion(w.mod.Version) {
				out = append(out, Finding{Module: w.mod, Entry: e, ID: e.ID, Affected: a, FixedIn: a.FixedAfter(w.mod.Version)})
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Module.Path != out[j].Module.Path {
			return out[i].Module.Path < out[j].Module.Path
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func addV(v string) string {
	if v == "" || strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}

// AffectsVersion reports whether module version v (with "v" prefix) is in
// the affected ranges. Pseudo-versions are compared by their semver order.
func (a *Affected) AffectsVersion(v string) bool {
	if v == "" {
		return true // unknown version: assume affected
	}
	v = strings.TrimSuffix(v, "+incompatible")
	if len(a.Ranges) == 0 {
		return true
	}
	for _, r := range a.Ranges {
		if r.Type != "SEMVER" {
			continue
		}
		if inRange(r.Events, v) {
			return true
		}
	}
	return false
}

func inRange(events []RangeEvent, v string) bool {
	// Events are sorted by version; walk them tracking state.
	type ev struct {
		v     string
		intro bool
	}
	var evs []ev
	for _, e := range events {
		if e.Introduced != "" {
			iv := e.Introduced
			if iv == "0" {
				iv = "v0.0.0-0"
			} else {
				iv = addV(iv)
			}
			evs = append(evs, ev{iv, true})
		}
		if e.Fixed != "" {
			evs = append(evs, ev{addV(e.Fixed), false})
		}
	}
	sort.SliceStable(evs, func(i, j int) bool { return semver.Compare(evs[i].v, evs[j].v) < 0 })
	affected := false
	for _, e := range evs {
		if semver.Compare(v, e.v) < 0 {
			break
		}
		affected = e.intro
	}
	return affected
}

// FixedAfter returns the lowest fixed version greater than v, or "".
func (a *Affected) FixedAfter(v string) string {
	best := ""
	for _, r := range a.Ranges {
		for _, e := range r.Events {
			if e.Fixed == "" {
				continue
			}
			f := addV(e.Fixed)
			if semver.Compare(f, v) > 0 && (best == "" || semver.Compare(f, best) < 0) {
				best = f
			}
		}
	}
	return best
}

// Packages returns the vulnerable package import paths.
func (a *Affected) Packages() []string {
	if a.EcosystemSpecific == nil {
		return nil
	}
	var out []string
	for _, im := range a.EcosystemSpecific.Imports {
		out = append(out, im.Path)
	}
	return out
}

// CVEs returns the CVE aliases of an entry.
func (e *Entry) CVEs() []string {
	var out []string
	for _, a := range e.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			out = append(out, a)
		}
	}
	return out
}

// GHSAs returns the GitHub advisory aliases of an entry.
func (e *Entry) GHSAs() []string {
	var out []string
	for _, a := range e.Aliases {
		if strings.HasPrefix(a, "GHSA-") {
			out = append(out, a)
		}
	}
	return out
}

// URL returns the pkg.go.dev page for the entry.
func (e *Entry) URL() string {
	if e.DatabaseSpecific != nil && e.DatabaseSpecific.URL != "" {
		return e.DatabaseSpecific.URL
	}
	return "https://pkg.go.dev/vuln/" + e.ID
}

// GoToSemver converts a Go toolchain version ("go1.21.3", "1.21",
// "go1.22rc1") to the semver form used by the database for the standard
// library ("v1.21.3", "v1.21.0", "v1.22.0-rc.1"). It returns "" if v is
// not a Go release version.
func GoToSemver(v string) string {
	v = strings.TrimPrefix(v, "go")
	if v == "" {
		return ""
	}
	// Drop "+..." / " X:..." decorations (e.g. "1.21.3 X:boringcrypto").
	if i := strings.IndexAny(v, " +"); i >= 0 {
		v = v[:i]
	}
	var pre string
	for _, kind := range []string{"rc", "beta", "alpha"} {
		if i := strings.Index(v, kind); i >= 0 {
			pre = "-" + kind + "." + v[i+len(kind):]
			v = v[:i]
			break
		}
	}
	parts := strings.Split(v, ".")
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	if len(parts) > 3 {
		return ""
	}
	s := "v" + strings.Join(parts, ".") + pre
	if !semver.IsValid(s) {
		return ""
	}
	return s
}
