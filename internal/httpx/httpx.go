// Package httpx is sm-go's HTTP client: a disk cache with a TTL (default 10
// minutes), conditional revalidation, offline mode, retries with backoff,
// a concurrency limit and scoped credentials.
//
// Credentials are never sent to a host they were not issued for: a GitHub
// token is only attached to requests for the GitHub API host, and .netrc
// credentials only to requests that opt in (module proxy traffic) and whose
// host matches the .netrc machine exactly.
package httpx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Version is sent in the User-Agent header.
var Version = "dev"

// Env is the subset of goenv.Env used by the client.
type Env interface {
	Getenv(string) string
	Home() string
}

// Options configures a Client.
type Options struct {
	CacheDir  string        // "" disables the disk cache
	TTL       time.Duration // default 10m
	NoCache   bool          // bypass reads from the cache (responses are still stored)
	Offline   bool          // serve only from cache, any age
	Timeout   time.Duration // per request, default 30s
	Env       Env
	GitHubAPI string // base URL of the GitHub API, for token scoping
	Transport http.RoundTripper
	Log       io.Writer // verbose request log, may be nil
	MaxConc   int       // concurrent requests, default 8
}

// Client is safe for concurrent use.
type Client struct {
	opt   Options
	hc    *http.Client
	sem   chan struct{}
	netrc map[string]netrcEntry
	once  sync.Once
	ghost string
	mu    sync.Mutex
	stats Stats
}

// Stats counts requests, for --verbose output.
type Stats struct {
	Network, CacheHits, Revalidated int
}

// Response is a completed HTTP response.
type Response struct {
	URL    string      `json:"url"` // final URL after redirects
	Status int         `json:"status"`
	Header http.Header `json:"header,omitempty"`
	Body   []byte      `json:"-"`
	Cached bool        `json:"-"`
	Time   time.Time   `json:"time"`
}

// StatusError is returned for HTTP status codes >= 400.
type StatusError struct {
	URL    string
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	msg := strings.TrimSpace(e.Body)
	if len(msg) > 200 {
		msg = msg[:200] + "..."
	}
	if msg != "" {
		return fmt.Sprintf("GET %s: %d %s: %s", redact(e.URL), e.Status, http.StatusText(e.Status), msg)
	}
	return fmt.Sprintf("GET %s: %d %s", redact(e.URL), e.Status, http.StatusText(e.Status))
}

// ErrOffline is returned in offline mode when a response is not cached.
var ErrOffline = errors.New("not available offline (no cached copy)")

// IsNotFound reports whether err is a 404 or 410 response.
func IsNotFound(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && (se.Status == 404 || se.Status == 410)
}

// StatusCode returns the HTTP status in err, or 0.
func StatusCode(err error) int {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Status
	}
	return 0
}

// New creates a client.
func New(opt Options) *Client {
	if opt.TTL == 0 {
		opt.TTL = 10 * time.Minute
	}
	if opt.Timeout == 0 {
		opt.Timeout = 30 * time.Second
	}
	if opt.MaxConc <= 0 {
		opt.MaxConc = 8
	}
	tr := opt.Transport
	if tr == nil {
		tr = http.DefaultTransport
	}
	c := &Client{opt: opt, sem: make(chan struct{}, opt.MaxConc)}
	c.hc = &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		// Never forward credentials to another host.
		if len(via) > 0 && req.URL.Host != via[0].URL.Host {
			req.Header.Del("Authorization")
		}
		return nil
	}}
	if u, err := url.Parse(opt.GitHubAPI); err == nil {
		c.ghost = u.Host
	}
	return c
}

// Stats returns request counters.
func (c *Client) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// Offline reports whether the client is in offline mode.
func (c *Client) Offline() bool { return c.opt.Offline }

type reqOpts struct {
	ttl       time.Duration
	immutable bool
	netrc     bool
	header    http.Header
	noCache   bool
	method    string
	body      []byte
	accept404 bool
}

// ReqOpt customizes a request.
type ReqOpt func(*reqOpts)

// TTL overrides the cache lifetime for this request.
func TTL(d time.Duration) ReqOpt { return func(o *reqOpts) { o.ttl = d } }

// Immutable marks content that never changes once published (module zips,
// go.mod files of exact versions): cached copies never expire.
func Immutable() ReqOpt { return func(o *reqOpts) { o.immutable = true } }

// UseNetrc allows .netrc credentials for this request's host.
func UseNetrc() ReqOpt { return func(o *reqOpts) { o.netrc = true } }

// Header adds a request header.
func Header(k, v string) ReqOpt {
	return func(o *reqOpts) {
		if o.header == nil {
			o.header = http.Header{}
		}
		o.header.Add(k, v)
	}
}

// NoCache skips the cache for this request.
func NoCache() ReqOpt { return func(o *reqOpts) { o.noCache = true } }

// Get fetches url. Status codes >= 400 are returned as *StatusError.
func (c *Client) Get(ctx context.Context, u string, opts ...ReqOpt) (*Response, error) {
	return c.do(ctx, u, opts...)
}

// GetJSON fetches url and decodes the JSON body into v.
func (c *Client) GetJSON(ctx context.Context, u string, v any, opts ...ReqOpt) error {
	r, err := c.do(ctx, u, append(opts, Header("Accept", "application/json"))...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(r.Body, v); err != nil {
		return fmt.Errorf("decoding %s: %v", redact(u), err)
	}
	return nil
}

// PostJSON posts body as JSON and decodes the response into v. Responses
// are cached by URL and body.
func (c *Client) PostJSON(ctx context.Context, u string, body, v any, opts ...ReqOpt) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	opts = append(opts, func(o *reqOpts) { o.method = "POST"; o.body = b },
		Header("Content-Type", "application/json"), Header("Accept", "application/json"))
	r, err := c.do(ctx, u, opts...)
	if err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	if err := json.Unmarshal(r.Body, v); err != nil {
		return fmt.Errorf("decoding %s: %v", redact(u), err)
	}
	return nil
}

// Post sends a body without caching (webhooks and alerts).
func (c *Client) Post(ctx context.Context, u, contentType string, body []byte) (*Response, error) {
	if c.opt.Offline {
		return nil, fmt.Errorf("POST %s: %w", redact(u), ErrOffline)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "sm-go/"+Version)
	return c.send(ctx, req)
}

func (c *Client) do(ctx context.Context, u string, opts ...ReqOpt) (*Response, error) {
	o := reqOpts{method: "GET", ttl: c.opt.TTL}
	for _, f := range opts {
		f(&o)
	}
	authScope := ""
	req, err := http.NewRequestWithContext(ctx, o.method, u, bytes.NewReader(o.body))
	if err != nil {
		return nil, err
	}
	if o.body == nil {
		req.Body = nil
	}
	req.Header.Set("User-Agent", "sm-go/"+Version+" (+https://github.com/slash-mark-dev/go-suite)")
	for k, vs := range o.header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if c.ghost != "" && req.URL.Host == c.ghost && c.opt.Env != nil {
		tok := c.opt.Env.Getenv("GITHUB_TOKEN")
		if tok == "" {
			tok = c.opt.Env.Getenv("GH_TOKEN")
		}
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
			authScope = "gh"
		}
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	}
	if o.netrc && req.Header.Get("Authorization") == "" {
		if e, ok := c.netrcFor(req.URL.Host); ok {
			req.SetBasicAuth(e.login, e.password)
			authScope = "netrc:" + req.URL.Host
		}
	}
	if req.URL.User != nil {
		authScope = "userinfo"
	}
	key := cacheKey(o.method, u, o.body, authScope)
	cached := c.readCache(key)
	if cached != nil && !c.opt.NoCache && !o.noCache {
		fresh := o.immutable || time.Since(cached.Time) < o.ttl
		if fresh || c.opt.Offline {
			c.count(func(s *Stats) { s.CacheHits++ })
			return cached.result(u)
		}
	}
	if c.opt.Offline {
		if cached != nil {
			return cached.result(u)
		}
		return nil, fmt.Errorf("%s %s: %w", o.method, redact(u), ErrOffline)
	}
	if cached != nil && cached.ETag != "" && cached.Status == 200 {
		req.Header.Set("If-None-Match", cached.ETag)
	}
	resp, err := c.send(ctx, req)
	if err != nil {
		if cached != nil && resp == nil {
			// Network failure: serve the stale copy rather than failing.
			return cached.result(u)
		}
		return nil, err
	}
	if resp.Status == http.StatusNotModified && cached != nil {
		cached.Time = time.Now()
		c.writeCache(key, cached)
		c.count(func(s *Stats) { s.Revalidated++ })
		return cached.result(u)
	}
	if resp.Status == 200 || resp.Status == 404 || resp.Status == 410 {
		c.writeCache(key, &entry{URL: resp.URL, Status: resp.Status, Time: time.Now(),
			ETag: resp.Header.Get("ETag"), ContentType: resp.Header.Get("Content-Type"),
			Link: resp.Header.Get("Link"), Body: resp.Body})
	}
	if resp.Status >= 400 {
		return resp, &StatusError{URL: u, Status: resp.Status, Body: string(resp.Body)}
	}
	return resp, nil
}

func (c *Client) count(f func(*Stats)) {
	c.mu.Lock()
	f(&c.stats)
	c.mu.Unlock()
}

func (c *Client) send(ctx context.Context, req *http.Request) (*Response, error) {
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-c.sem }()
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			if req.GetBody != nil {
				req.Body, _ = req.GetBody()
			}
		}
		rctx, cancel := context.WithTimeout(ctx, c.opt.Timeout)
		r := req.Clone(rctx)
		if c.opt.Log != nil {
			fmt.Fprintf(c.opt.Log, "→ %s %s\n", r.Method, redact(r.URL.String()))
		}
		c.count(func(s *Stats) { s.Network++ })
		resp, err := c.hc.Do(r)
		if err != nil {
			cancel()
			lastErr = fmt.Errorf("%s %s: %v", req.Method, redact(req.URL.String()), unwrapURLErr(err))
			if ctx.Err() != nil {
				return nil, lastErr
			}
			sleep(ctx, attempt, "")
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20))
		resp.Body.Close()
		cancel()
		if err != nil {
			lastErr = fmt.Errorf("%s %s: reading body: %v", req.Method, redact(req.URL.String()), err)
			sleep(ctx, attempt, "")
			continue
		}
		out := &Response{URL: resp.Request.URL.String(), Status: resp.StatusCode, Header: resp.Header, Body: body, Time: time.Now()}
		if (resp.StatusCode == 429 || resp.StatusCode >= 500) && attempt < 2 {
			lastErr = &StatusError{URL: req.URL.String(), Status: resp.StatusCode, Body: string(body)}
			sleep(ctx, attempt, resp.Header.Get("Retry-After"))
			continue
		}
		return out, nil
	}
	return nil, lastErr
}

func unwrapURLErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func sleep(ctx context.Context, attempt int, retryAfter string) {
	d := time.Duration(200*(1<<attempt)) * time.Millisecond
	if s, err := strconv.Atoi(retryAfter); err == nil && s > 0 {
		d = time.Duration(s) * time.Second
		if d > 5*time.Second {
			d = 5 * time.Second
		}
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// redact removes userinfo and token-looking query parameters from a URL.
func redact(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	if u.User != nil {
		u.User = url.User("***")
	}
	q := u.Query()
	changed := false
	for k := range q {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "token") || strings.Contains(lk, "key") || strings.Contains(lk, "secret") || lk == "sig" {
			q.Set(k, "***")
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// Redact is exported for tools that print URLs.
func Redact(s string) string { return redact(s) }

// --- cache ---

type entry struct {
	URL         string    `json:"url"`
	Status      int       `json:"status"`
	Time        time.Time `json:"time"`
	ETag        string    `json:"etag,omitempty"`
	ContentType string    `json:"contentType,omitempty"`
	Link        string    `json:"link,omitempty"`
	Body        []byte    `json:"-"`
}

func (e *entry) result(u string) (*Response, error) {
	h := http.Header{}
	if e.ContentType != "" {
		h.Set("Content-Type", e.ContentType)
	}
	if e.Link != "" {
		h.Set("Link", e.Link)
	}
	if e.ETag != "" {
		h.Set("ETag", e.ETag)
	}
	r := &Response{URL: e.URL, Status: e.Status, Header: h, Body: e.Body, Cached: true, Time: e.Time}
	if e.Status >= 400 {
		return r, &StatusError{URL: u, Status: e.Status, Body: string(e.Body)}
	}
	return r, nil
}

func cacheKey(method, u string, body []byte, scope string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n", method, u, scope)
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func (c *Client) cachePath(key string) string {
	return filepath.Join(c.opt.CacheDir, "http", key[:2], key)
}

func (c *Client) readCache(key string) *entry {
	if c.opt.CacheDir == "" {
		return nil
	}
	p := c.cachePath(key)
	meta, err := os.ReadFile(p + ".json")
	if err != nil {
		return nil
	}
	var e entry
	if json.Unmarshal(meta, &e) != nil {
		return nil
	}
	body, err := os.ReadFile(p + ".body")
	if err != nil {
		return nil
	}
	e.Body = body
	return &e
}

func (c *Client) writeCache(key string, e *entry) {
	if c.opt.CacheDir == "" {
		return
	}
	p := c.cachePath(key)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	meta, _ := json.Marshal(e)
	writeAtomic(p+".body", e.Body)
	writeAtomic(p+".json", meta)
}

func writeAtomic(path string, data []byte) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp.Name())
		return
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
	}
}

// ClearCache deletes the HTTP cache. It returns the number of bytes freed.
func ClearCache(dir string) (int64, error) {
	root := filepath.Join(dir, "http")
	var total int64
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			total += fi.Size()
		}
		return nil
	})
	return total, os.RemoveAll(root)
}

// --- .netrc ---

type netrcEntry struct{ login, password string }

func (c *Client) netrcFor(host string) (netrcEntry, bool) {
	c.once.Do(func() {
		c.netrc = map[string]netrcEntry{}
		if c.opt.Env == nil {
			return
		}
		path := c.opt.Env.Getenv("NETRC")
		if path == "" {
			name := ".netrc"
			if os.PathSeparator == '\\' {
				name = "_netrc"
			}
			path = filepath.Join(c.opt.Env.Home(), name)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		c.netrc = ParseNetrc(string(data))
	})
	h := host
	if i := strings.LastIndex(h, ":"); i >= 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	e, ok := c.netrc[h]
	if !ok {
		e, ok = c.netrc[host]
	}
	return e, ok
}

// ParseNetrc parses .netrc content into machine -> credentials. The
// "default" entry is deliberately ignored: sm-go only sends credentials to
// hosts named explicitly.
func ParseNetrc(data string) map[string]netrcEntry {
	out := map[string]netrcEntry{}
	var machine string
	var cur netrcEntry
	flush := func() {
		if machine != "" && (cur.login != "" || cur.password != "") {
			out[machine] = cur
		}
		machine, cur = "", netrcEntry{}
	}
	f := strings.Fields(data)
	for i := 0; i < len(f); i++ {
		switch f[i] {
		case "machine":
			flush()
			if i+1 < len(f) {
				machine = f[i+1]
				i++
			}
		case "default":
			flush()
		case "login":
			if i+1 < len(f) {
				cur.login = f[i+1]
				i++
			}
		case "password":
			if i+1 < len(f) {
				cur.password = f[i+1]
				i++
			}
		case "macdef":
			// skip to end: macros are not supported
			flush()
			return out
		}
	}
	flush()
	return out
}

// NetrcMachines lists the machines in a .netrc file, for auditing.
func NetrcMachines(data string) []string {
	var out []string
	for m := range ParseNetrc(data) {
		out = append(out, m)
	}
	return out
}
