package sumdb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/slash-mark-dev/go-suite/internal/httpx"
	"github.com/slash-mark-dev/go-suite/internal/module"
)

// KnownKeys maps well-known checksum database names to verifier keys
// (from cmd/go/internal/modfetch/key.go).
var KnownKeys = map[string]string{
	"sum.golang.org": "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8",
}

// ErrSecurity reports evidence of a forked or tampered log.
var ErrSecurity = errors.New("SECURITY ERROR")

// Env is the environment needed to configure a client.
type Env interface {
	Get(string) string
	Getenv(string) string
}

// Client talks to one checksum database.
type Client struct {
	Name     string
	verifier *Verifier
	urls     []string
	http     *httpx.Client
	stateDir string
	mu       sync.Mutex
	latest   *Tree
	Disabled bool
}

// Config parses GOSUMDB ("off", "name", "name+hash+key", optionally
// followed by a URL) and returns the database name, verifier key and URL.
func Config(gosumdb string) (name, vkey, url string, err error) {
	if gosumdb == "" {
		gosumdb = "sum.golang.org"
	}
	if gosumdb == "off" {
		return "off", "", "", nil
	}
	f := strings.Fields(gosumdb)
	if len(f) == 0 || len(f) > 2 {
		return "", "", "", fmt.Errorf("invalid GOSUMDB: %q", gosumdb)
	}
	key := f[0]
	if k, ok := KnownKeys[key]; ok {
		key = k
	} else if key == "sum.golang.google.cn" {
		key = KnownKeys["sum.golang.org"]
		url = "https://sum.golang.google.cn"
	}
	v, err := NewVerifier(key)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid GOSUMDB: %v", err)
	}
	name = v.Name
	if len(f) == 2 {
		url = f[1]
		if !strings.Contains(url, "://") {
			url = "https://" + url
		}
	} else if url == "" {
		url = "https://" + name
	}
	return name, key, strings.TrimRight(url, "/"), nil
}

// NewClient builds a client from the Go environment. proxies are GOPROXY
// base URLs to use as fallbacks via their /sumdb/<name>/ endpoints.
func NewClient(env Env, hc *httpx.Client, stateDir string, proxies []string) (*Client, error) {
	name, vkey, url, err := Config(env.Get("GOSUMDB"))
	if err != nil {
		return nil, err
	}
	if name == "off" {
		return &Client{Name: "off", Disabled: true}, nil
	}
	v, err := NewVerifier(vkey)
	if err != nil {
		return nil, err
	}
	c := &Client{Name: name, verifier: v, http: hc, stateDir: stateDir}
	if o := env.Getenv("SMGO_SUMDB_URL"); o != "" {
		c.urls = []string{strings.TrimRight(o, "/")}
	} else {
		c.urls = []string{url}
		for _, p := range proxies {
			c.urls = append(c.urls, p+"/sumdb/"+name)
		}
	}
	return c, nil
}

// Excluded reports whether path is excluded from checksum verification
// by GONOSUMDB, GONOSUMCHECK or GOPRIVATE.
func Excluded(env Env, path string) bool {
	for _, k := range []string{"GONOSUMDB", "GONOSUMCHECK", "GOPRIVATE"} {
		if module.MatchPrefixPatterns(env.Get(k), path) {
			return true
		}
	}
	return false
}

func (c *Client) get(ctx context.Context, path string, immutable bool) ([]byte, error) {
	var lastErr error
	for _, base := range c.urls {
		opts := []httpx.ReqOpt{}
		if immutable {
			opts = append(opts, httpx.Immutable())
		} else {
			opts = append(opts, httpx.NoCache())
		}
		r, err := c.http.Get(ctx, base+"/"+path, opts...)
		if err == nil {
			return r.Body, nil
		}
		lastErr = err
		if httpx.IsNotFound(err) {
			return nil, err
		}
	}
	return nil, lastErr
}

// Latest fetches and verifies the latest signed tree head, checking that
// it is consistent with the last tree head this machine has seen.
func (c *Client) Latest(ctx context.Context) (Tree, []byte, error) {
	if c.Disabled {
		return Tree{}, nil, errors.New("checksum database disabled (GOSUMDB=off)")
	}
	msg, err := c.get(ctx, "latest", false)
	if err != nil {
		return Tree{}, nil, err
	}
	t, err := c.verifyTreeNote(msg)
	if err != nil {
		return Tree{}, nil, err
	}
	if err := c.mergeLatest(ctx, t, msg); err != nil {
		return Tree{}, nil, err
	}
	return t, msg, nil
}

func (c *Client) verifyTreeNote(msg []byte) (Tree, error) {
	n, err := OpenNote(msg, c.verifier)
	if err != nil {
		return Tree{}, fmt.Errorf("verifying tree note: %w", err)
	}
	return ParseTree([]byte(n.Text))
}

func (c *Client) statePath() string {
	if c.stateDir == "" {
		return ""
	}
	return filepath.Join(c.stateDir, "sumdb", c.Name, "latest")
}

// Known returns the newest tree head previously verified on this machine.
func (c *Client) Known() (Tree, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.latest != nil {
		return *c.latest, true
	}
	p := c.statePath()
	if p == "" {
		return Tree{}, false
	}
	msg, err := os.ReadFile(p)
	if err != nil {
		return Tree{}, false
	}
	t, err := c.verifyTreeNote(msg)
	if err != nil {
		return Tree{}, false
	}
	c.latest = &t
	return t, true
}

// mergeLatest checks consistency between t and the stored tree and keeps
// the larger of the two.
func (c *Client) mergeLatest(ctx context.Context, t Tree, msg []byte) error {
	old, ok := c.Known()
	if ok {
		if err := c.CheckConsistency(ctx, old, t); err != nil {
			return err
		}
		if t.N <= old.N {
			return nil
		}
	}
	c.mu.Lock()
	c.latest = &t
	c.mu.Unlock()
	if p := c.statePath(); p != "" {
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, msg, 0o600)
	}
	return nil
}

// CheckConsistency proves that the smaller of a and b is a prefix of the
// larger. A failure is a SECURITY ERROR: the log was forked or rewritten.
func (c *Client) CheckConsistency(ctx context.Context, a, b Tree) error {
	if a.N > b.N {
		a, b = b, a
	}
	if a.N == 0 {
		return nil
	}
	if a.N == b.N {
		if a.Hash != b.Hash {
			return fmt.Errorf("%w: %s has two different tree heads for size %d (%s and %s)", ErrSecurity, c.Name, a.N, a.Hash, b.Hash)
		}
		return nil
	}
	p, err := ProveTree(b.N, a.N, c.reader(ctx, b))
	if err != nil {
		return fmt.Errorf("fetching consistency proof: %w", err)
	}
	if err := CheckTree(p, b.N, b.Hash, a.N, a.Hash); err != nil {
		return fmt.Errorf("%w: %s tree of size %d is not a prefix of tree of size %d: the log has been forked or rewritten", ErrSecurity, c.Name, a.N, b.N)
	}
	return nil
}

// Lookup is a verified checksum database record.
type Lookup struct {
	ID      int64    `json:"id"`
	Path    string   `json:"path"`
	Version string   `json:"version"`
	Lines   []string `json:"lines"`
	ZipHash string   `json:"zipHash,omitempty"`
	ModHash string   `json:"modHash,omitempty"`
	Tree    Tree     `json:"-"`
	TreeN   int64    `json:"treeSize"`
	Proof   int      `json:"proofHashes"`
}

// Lookup fetches the record for path@version and verifies its signature,
// its inclusion in the signed tree, and the tree's consistency with
// previously seen trees.
func (c *Client) Lookup(ctx context.Context, path, version string) (*Lookup, error) {
	if c.Disabled {
		return nil, errors.New("checksum database disabled (GOSUMDB=off)")
	}
	ep, err := module.EscapePath(path)
	if err != nil {
		return nil, err
	}
	ev, err := module.EscapeVersion(version)
	if err != nil {
		return nil, err
	}
	data, err := c.get(ctx, "lookup/"+ep+"@"+ev, false)
	if err != nil {
		return nil, err
	}
	// <id>\n<record>\n<signed tree note>
	i := bytes.IndexByte(data, '\n')
	if i < 0 {
		return nil, errors.New("malformed lookup response")
	}
	id, err := strconv.ParseInt(string(data[:i]), 10, 64)
	if err != nil {
		return nil, errors.New("malformed lookup response: bad record id")
	}
	rest := data[i+1:]
	j := bytes.Index(rest, []byte("\n\n"))
	if j < 0 {
		return nil, errors.New("malformed lookup response")
	}
	record := rest[:j+1]
	treeMsg := rest[j+2:]
	t, err := c.verifyTreeNote(treeMsg)
	if err != nil {
		return nil, err
	}
	if id >= t.N {
		return nil, fmt.Errorf("%w: record %d is beyond the signed tree of size %d", ErrSecurity, id, t.N)
	}
	proof, err := ProveRecord(t.N, id, c.reader(ctx, t))
	if err != nil {
		return nil, fmt.Errorf("fetching inclusion proof: %w", err)
	}
	if err := CheckRecord(proof, t.N, t.Hash, id, RecordHash(record)); err != nil {
		return nil, fmt.Errorf("%w: record for %s@%s is not in the signed tree (inclusion proof failed)", ErrSecurity, path, version)
	}
	if err := c.mergeLatest(ctx, t, treeMsg); err != nil {
		return nil, err
	}
	l := &Lookup{ID: id, Path: path, Version: version, Tree: t, TreeN: t.N, Proof: len(proof)}
	for _, line := range strings.Split(strings.TrimSuffix(string(record), "\n"), "\n") {
		l.Lines = append(l.Lines, line)
		f := strings.Fields(line)
		if len(f) != 3 || f[0] != path {
			return nil, fmt.Errorf("malformed record line %q", line)
		}
		switch f[1] {
		case version:
			l.ZipHash = f[2]
		case version + "/go.mod":
			l.ModHash = f[2]
		default:
			return nil, fmt.Errorf("%w: record for %s@%s contains a line for %s", ErrSecurity, path, version, f[1])
		}
	}
	return l, nil
}

// reader returns a HashReader that fetches tiles for tree t.
func (c *Client) reader(ctx context.Context, t Tree) HashReader {
	const H = 8
	cache := map[Tile][]byte{}
	return HashReaderFunc(func(indexes []int64) ([]Hash, error) {
		out := make([]Hash, len(indexes))
		for i, idx := range indexes {
			tile := TileForIndex(H, idx)
			w := TileWidth(H, tile.L, tile.N, t.N)
			if w < tile.W {
				return nil, fmt.Errorf("index %d not in tree of size %d", idx, t.N)
			}
			tile.W = w
			data, ok := cache[tile]
			if !ok {
				var err error
				data, err = c.fetchTile(ctx, tile)
				if err != nil {
					return nil, err
				}
				cache[tile] = data
			}
			h, err := HashFromTile(tile, data, idx)
			if err != nil {
				return nil, err
			}
			out[i] = h
		}
		return out, nil
	})
}

func (c *Client) fetchTile(ctx context.Context, t Tile) ([]byte, error) {
	data, err := c.get(ctx, t.Path(), true)
	if err != nil && httpx.IsNotFound(err) && t.W < 1<<uint(t.H) {
		full := t
		full.W = 1 << uint(t.H)
		data, err = c.get(ctx, full.Path(), true)
	}
	if err != nil {
		return nil, err
	}
	if len(data) < t.W*HashSize {
		return nil, fmt.Errorf("tile %s: short data (%d bytes)", t.Path(), len(data))
	}
	return data[:t.W*HashSize], nil
}
