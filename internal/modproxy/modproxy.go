// Package modproxy fetches module metadata the way the go command does:
// through the GOPROXY list (with "," and "|" fallback rules), honouring
// GONOPROXY/GOPRIVATE, reading the local module cache first for immutable
// files, and falling back to the go command itself for "direct" and private
// modules (which reuses the user's VCS credentials).
package modproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/goenv"
	"github.com/slash-mark-dev/go-suite/internal/httpx"
	"github.com/slash-mark-dev/go-suite/internal/modfile"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/semver"
)

// ErrNotFound means no proxy (or the module cache) has the module/version.
var ErrNotFound = errors.New("not found")

// Info is the content of a .info file.
type Info struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
	Origin  *Origin   `json:"Origin,omitempty"`
}

// Origin records where the proxy got a module version from.
type Origin struct {
	VCS    string `json:"VCS,omitempty"`
	URL    string `json:"URL,omitempty"`
	Subdir string `json:"Subdir,omitempty"`
	Hash   string `json:"Hash,omitempty"`
	Ref    string `json:"Ref,omitempty"`
}

type entry struct {
	url      string // "direct", "off" or a base URL
	fallback bool   // true if followed by '|' (fall back on any error)
}

// Proxy is safe for concurrent use.
type Proxy struct {
	http     *httpx.Client
	env      *goenv.Env
	entries  []entry
	modcache string
	noproxy  string
	mods     sync.Map // module.Version -> []byte (go.mod)
	lists    sync.Map // path -> []string
}

// New builds a Proxy from the Go environment.
func New(env *goenv.Env, hc *httpx.Client) *Proxy {
	p := &Proxy{http: hc, env: env, modcache: env.Get("GOMODCACHE"), noproxy: env.Get("GONOPROXY")}
	p.entries = ParseList(env.Get("GOPROXY"))
	return p
}

// ParseList parses a GOPROXY value.
func ParseList(s string) []entry {
	var out []entry
	for s != "" {
		var e string
		sep := byte(0)
		if i := strings.IndexAny(s, ",|"); i >= 0 {
			e, sep, s = s[:i], s[i], s[i+1:]
		} else {
			e, s = s, ""
		}
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if e != "direct" && e != "off" {
			if !strings.Contains(e, "://") {
				e = "https://" + e
			}
			e = strings.TrimRight(e, "/")
		}
		out = append(out, entry{url: e, fallback: sep == '|'})
	}
	if len(out) == 0 {
		out = []entry{{url: "https://proxy.golang.org"}, {url: "direct"}}
	}
	return out
}

// URLs returns the configured proxy base URLs (excluding direct/off).
func (p *Proxy) URLs() []string {
	var out []string
	for _, e := range p.entries {
		if e.url != "direct" && e.url != "off" {
			out = append(out, e.url)
		}
	}
	return out
}

// Private reports whether path bypasses the proxy (GONOPROXY/GOPRIVATE).
func (p *Proxy) Private(path string) bool {
	return module.MatchPrefixPatterns(p.noproxy, path)
}

func (p *Proxy) entriesFor(path string) []entry {
	if p.Private(path) {
		return []entry{{url: "direct"}}
	}
	return p.entries
}

// fetch tries each GOPROXY entry for the given escaped suffix.
func (p *Proxy) fetch(ctx context.Context, path, suffix string, immutable bool, direct func() ([]byte, error)) ([]byte, error) {
	var lastErr error = ErrNotFound
	for _, e := range p.entriesFor(path) {
		switch e.url {
		case "off":
			return nil, fmt.Errorf("module lookup disabled by GOPROXY=off")
		case "direct":
			if direct == nil {
				return nil, lastErr
			}
			b, err := direct()
			if err != nil {
				return nil, err
			}
			return b, nil
		}
		esc, err := module.EscapePath(path)
		if err != nil {
			return nil, err
		}
		opts := []httpx.ReqOpt{httpx.UseNetrc()}
		if immutable {
			opts = append(opts, httpx.Immutable())
		}
		r, err := p.http.Get(ctx, e.url+"/"+esc+"/@"+suffix, opts...)
		if err == nil {
			return r.Body, nil
		}
		lastErr = err
		if httpx.IsNotFound(err) {
			lastErr = fmt.Errorf("%s: %w", path, ErrNotFound)
			continue
		}
		if e.fallback {
			continue
		}
		return nil, err
	}
	return nil, lastErr
}

// Versions returns the tagged versions of path, sorted ascending.
// Pseudo-versions are excluded, matching `go list -m -versions`.
func (p *Proxy) Versions(ctx context.Context, path string) ([]string, error) {
	if v, ok := p.lists.Load(path); ok {
		return v.([]string), nil
	}
	body, err := p.fetch(ctx, path, "v/list", false, func() ([]byte, error) {
		return p.goListVersions(ctx, path)
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			if b, ok := p.cacheList(path); ok {
				body, err = b, nil
			}
		}
		if err != nil {
			return nil, err
		}
	}
	var vs []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(body), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		v := f[0]
		if semver.IsValid(v) && !module.IsPseudoVersion(v) && !seen[v] {
			seen[v] = true
			vs = append(vs, v)
		}
	}
	semver.Sort(vs)
	p.lists.Store(path, vs)
	return vs, nil
}

// Latest returns the @latest info for a module.
func (p *Proxy) Latest(ctx context.Context, path string) (*Info, error) {
	body, err := p.fetch(ctx, path, "latest", false, func() ([]byte, error) {
		return p.goDownloadFile(ctx, path, "latest", "Info")
	})
	if err != nil {
		return nil, err
	}
	var info Info
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("%s@latest: bad info: %v", path, err)
	}
	return &info, nil
}

// Info returns the .info for an exact version.
func (p *Proxy) Info(ctx context.Context, path, version string) (*Info, error) {
	if b, ok := p.fromModcache(path, version, ".info"); ok {
		var info Info
		if json.Unmarshal(b, &info) == nil && info.Version != "" {
			return &info, nil
		}
	}
	ev, err := module.EscapeVersion(version)
	if err != nil {
		return nil, err
	}
	body, err := p.fetch(ctx, path, "v/"+ev+".info", true, func() ([]byte, error) {
		return p.goDownloadFile(ctx, path, version, "Info")
	})
	if err != nil {
		return nil, err
	}
	var info Info
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("%s@%s: bad info: %v", path, version, err)
	}
	return &info, nil
}

// GoMod returns the go.mod file of an exact module version.
func (p *Proxy) GoMod(ctx context.Context, path, version string) ([]byte, error) {
	key := module.Version{Path: path, Version: version}
	if v, ok := p.mods.Load(key); ok {
		return v.([]byte), nil
	}
	if b, ok := p.fromModcache(path, version, ".mod"); ok {
		p.mods.Store(key, b)
		return b, nil
	}
	ev, err := module.EscapeVersion(version)
	if err != nil {
		return nil, err
	}
	body, err := p.fetch(ctx, path, "v/"+ev+".mod", true, func() ([]byte, error) {
		return p.goDownloadFile(ctx, path, version, "GoMod")
	})
	if err != nil {
		return nil, err
	}
	p.mods.Store(key, body)
	return body, nil
}

// Zip returns the module zip of an exact version.
func (p *Proxy) Zip(ctx context.Context, path, version string) ([]byte, error) {
	if b, ok := p.fromModcache(path, version, ".zip"); ok {
		return b, nil
	}
	ev, err := module.EscapeVersion(version)
	if err != nil {
		return nil, err
	}
	return p.fetch(ctx, path, "v/"+ev+".zip", true, func() ([]byte, error) {
		return p.goDownloadFile(ctx, path, version, "Zip")
	})
}

// ModcacheDir returns the extracted source directory of a module version in
// the module cache, or "" if it is not there.
func (p *Proxy) ModcacheDir(path, version string) string {
	if p.modcache == "" {
		return ""
	}
	ep, err1 := module.EscapePath(path)
	ev, err2 := module.EscapeVersion(version)
	if err1 != nil || err2 != nil {
		return ""
	}
	dir := filepath.Join(p.modcache, ep+"@"+ev)
	if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
		return dir
	}
	return ""
}

func (p *Proxy) fromModcache(path, version, ext string) ([]byte, bool) {
	if p.modcache == "" {
		return nil, false
	}
	ep, err1 := module.EscapePath(path)
	ev, err2 := module.EscapeVersion(version)
	if err1 != nil || err2 != nil {
		return nil, false
	}
	b, err := os.ReadFile(filepath.Join(p.modcache, "cache", "download", ep, "@v", ev+ext))
	if err != nil {
		return nil, false
	}
	return b, true
}

func (p *Proxy) cacheList(path string) ([]byte, bool) {
	if p.modcache == "" {
		return nil, false
	}
	ep, err := module.EscapePath(path)
	if err != nil {
		return nil, false
	}
	b, err := os.ReadFile(filepath.Join(p.modcache, "cache", "download", ep, "@v", "list"))
	return b, err == nil
}

// --- go command fallback for direct / private modules ---

type downloadJSON struct {
	Path, Version, Info, GoMod, Zip, Dir, Sum, GoModSum, Error string
}

func (p *Proxy) goDownloadFile(ctx context.Context, path, version, field string) ([]byte, error) {
	if p.http.Offline() {
		return nil, fmt.Errorf("%s@%s: direct fetch: %w", path, version, httpx.ErrOffline)
	}
	if !p.env.HaveGo() {
		return nil, fmt.Errorf("%s@%s: %w (direct fetch needs the go command)", path, version, ErrNotFound)
	}
	dir, err := os.MkdirTemp("", "sm-go-dl-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	cmd := exec.CommandContext(ctx, p.env.GoBin, "mod", "download", "-json", path+"@"+version)
	cmd.Dir = dir
	cmd.Env = append(p.env.Environ(), "GOFLAGS=-mod=mod", "GO111MODULE=on")
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	runErr := cmd.Run()
	var d downloadJSON
	if err := json.Unmarshal(out.Bytes(), &d); err != nil {
		if runErr != nil {
			return nil, fmt.Errorf("go mod download %s@%s: %v: %s", path, version, runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, err
	}
	if d.Error != "" {
		if strings.Contains(d.Error, "not found") || strings.Contains(d.Error, "unknown revision") || strings.Contains(d.Error, "no matching versions") {
			return nil, fmt.Errorf("%s@%s: %w: %s", path, version, ErrNotFound, d.Error)
		}
		return nil, fmt.Errorf("%s@%s: %s", path, version, d.Error)
	}
	var file string
	switch field {
	case "Info":
		file = d.Info
	case "GoMod":
		file = d.GoMod
	case "Zip":
		file = d.Zip
	}
	if file == "" {
		return nil, fmt.Errorf("%s@%s: go mod download returned no %s", path, version, field)
	}
	return os.ReadFile(file)
}

func (p *Proxy) goListVersions(ctx context.Context, path string) ([]byte, error) {
	if p.http.Offline() {
		return nil, fmt.Errorf("%s: direct fetch: %w", path, httpx.ErrOffline)
	}
	if !p.env.HaveGo() {
		return nil, fmt.Errorf("%s: %w (direct fetch needs the go command)", path, ErrNotFound)
	}
	dir, err := os.MkdirTemp("", "sm-go-ls-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module smgo.invalid/tmp\n"), 0o644)
	cmd := exec.CommandContext(ctx, p.env.GoBin, "list", "-m", "-versions", "-json", path+"@latest")
	cmd.Dir = dir
	cmd.Env = append(p.env.Environ(), "GOFLAGS=-mod=mod", "GO111MODULE=on", "GOWORK=off")
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", path, ErrNotFound, strings.TrimSpace(stderr.String()))
	}
	var m struct {
		Version  string
		Versions []string
	}
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		return nil, err
	}
	vs := m.Versions
	if len(vs) == 0 && m.Version != "" && !module.IsPseudoVersion(m.Version) {
		vs = []string{m.Version}
	}
	return []byte(strings.Join(vs, "\n")), nil
}

// --- query helpers ---

// Meta is what the go command learns from a module's latest go.mod:
// retractions and deprecation.
type Meta struct {
	Path       string             `json:"path"`
	Latest     string             `json:"latest"` // version whose go.mod holds the metadata
	Retract    []*modfile.Retract `json:"retract,omitempty"`
	Deprecated string             `json:"deprecated,omitempty"`
	Versions   []string           `json:"versions,omitempty"`
}

// Retracted reports whether v is retracted and why.
func (m *Meta) Retracted(v string) (bool, string) {
	for _, r := range m.Retract {
		if r.Contains(v) {
			return true, r.Rationale
		}
	}
	return false, ""
}

// Meta loads retractions and deprecation for path from the go.mod of its
// latest version, ignoring retractions to pick that version (go's rule).
func (p *Proxy) Meta(ctx context.Context, path string) (*Meta, error) {
	vs, err := p.Versions(ctx, path)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	m := &Meta{Path: path, Versions: vs}
	latest := highest(vs, false)
	if latest == "" {
		latest = highest(vs, true)
	}
	if latest == "" {
		info, err := p.Latest(ctx, path)
		if err != nil {
			return nil, err
		}
		latest = info.Version
	}
	m.Latest = latest
	gm, err := p.GoMod(ctx, path, latest)
	if err != nil {
		return m, err
	}
	f := modfile.Parse(path+"@"+latest+"/go.mod", gm)
	m.Retract = f.Retract
	if f.Module != nil {
		m.Deprecated = f.Module.Deprecated
	}
	return m, nil
}

func highest(vs []string, allowPre bool) string {
	best := ""
	for _, v := range vs {
		if !allowPre && semver.Prerelease(v) != "" {
			continue
		}
		if best == "" || semver.Compare(v, best) > 0 {
			best = v
		}
	}
	return best
}

// QueryLatest resolves "latest" the way `go get m@latest` does: the highest
// non-retracted release, else the highest non-retracted prerelease, else
// the proxy's @latest (usually a pseudo-version).
func (p *Proxy) QueryLatest(ctx context.Context, path string) (string, error) {
	m, err := p.Meta(ctx, path)
	if err != nil && m == nil {
		return "", err
	}
	pick := func(allowPre bool) string {
		best := ""
		for _, v := range m.Versions {
			if !allowPre && semver.Prerelease(v) != "" {
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
	if v := pick(false); v != "" {
		return v, nil
	}
	if v := pick(true); v != "" {
		return v, nil
	}
	return m.Latest, nil
}

// LatestCompatible returns the highest non-retracted release with the same
// major as current that is >= current ("upgrade" query). Prereleases are
// considered only if current is itself a prerelease.
func (p *Proxy) LatestCompatible(ctx context.Context, path, current string, patchOnly bool) (string, error) {
	m, err := p.Meta(ctx, path)
	if err != nil && m == nil {
		return "", err
	}
	best := current
	for _, v := range m.Versions {
		if semver.Major(v) != semver.Major(current) {
			continue
		}
		if patchOnly && semver.MajorMinor(v) != semver.MajorMinor(current) {
			continue
		}
		if semver.Prerelease(v) != "" && semver.Prerelease(current) == "" {
			continue
		}
		if r, _ := m.Retracted(v); r {
			continue
		}
		if semver.Compare(v, best) > 0 {
			best = v
		}
	}
	return best, nil
}
