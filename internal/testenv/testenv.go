// Package testenv provides a fake "world" for end-to-end tests: one local
// HTTP server that plays the Go module proxy, a signed checksum database
// (real transparency-log tiles), the Go vulnerability database, the
// module index, deps.dev, GitHub, CISA KEV, FIRST EPSS, go.dev release
// list and webhook receivers. World.Env returns an environment that points
// sm-go (and the real go command) at it, so tests run fully offline.
package testenv

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/modzip"
	"github.com/slash-mark-dev/go-suite/internal/semver"
	"github.com/slash-mark-dev/go-suite/internal/sumdb"
	"github.com/slash-mark-dev/go-suite/internal/vulndb"
)

// Mod is a fake published module version.
type Mod struct {
	Path    string
	Version string
	Files   map[string]string // relative to module root; must include go.mod
	Time    time.Time
	Origin  map[string]string // optional .info Origin (VCS, URL, Hash, Ref)
	// Hidden versions are served but not listed in @v/list (like
	// pseudo-versions).
	Hidden bool
}

// GoMod returns the module's go.mod content. An empty go.mod file means
// the module has none (like a +incompatible version): the zip omits it and
// the proxy serves a synthesized "module path" file, as proxy.golang.org
// does.
func (m *Mod) GoMod() string {
	if gm := m.Files["go.mod"]; gm != "" {
		return gm
	}
	return "module " + m.Path + "\n"
}

// Zip returns the module zip.
func (m *Mod) Zip() []byte {
	files := map[string][]byte{}
	for k, v := range m.Files {
		if k == "go.mod" && v == "" {
			continue
		}
		files[k] = []byte(v)
	}
	z, err := modzip.Create(m.Path, m.Version, files)
	if err != nil {
		panic(err)
	}
	return z
}

// Hook records requests made to /hook/<name>.
type Hook struct {
	Name   string
	Bodies [][]byte
}

// World is the fake internet.
type World struct {
	T      testing.TB
	Server *httptest.Server
	URL    string

	mu    sync.Mutex
	mods  map[string]map[string]*Mod
	Vulns []*vulndb.Entry
	// GitHub data: raw JSON per API path ("repos/o/r", "users/x",
	// "repos/o/r/git/ref/tags/v1.0.0", ...). Paths not present are 404.
	GitHub map[string]any
	// GitHubRedirect maps "repos/o/r" to "repos/o2/r2" (renamed repos).
	GitHubRedirect map[string]string
	// GitHubArchives holds binary API responses (zipballs) keyed by API
	// path ("repos/o/r/zipball/<ref>").
	GitHubArchives map[string][]byte
	DepsDev        map[string]any // keyed by API path after /depsdev/
	// RDAP holds RDAP responses keyed by "domain/<name>".
	RDAP map[string]any
	// Vanity holds HTML pages served for import paths ("example.org/x").
	Vanity     map[string]string
	KEV        []map[string]string
	EPSS       map[string][2]float64 // cve -> epss, percentile
	Index      []map[string]any
	GoReleases []map[string]any
	Hooks      map[string]*Hook
	// Extra lets a test serve arbitrary paths (e.g. vanity import pages):
	// key is the URL path ("/vanity/x?go-get=1" matches on path only).
	Extra map[string]http.HandlerFunc
	// SumOverride replaces the go.sum lines served for path@version
	// (simulates a tampered or substituted module).
	SumOverride map[string][]string
	Requests    []string

	// checksum database state
	signer       *sumdb.Signer
	VerifierKey  string
	records      [][]byte
	recordID     map[string]int64
	hashes       []sumdb.Hash // stored hashes in index order
	treeOverride *sumdb.Tree

	Home     string
	CacheDir string
	GoPath   string
	ModCache string
}

// New starts a world. It is closed automatically at test cleanup.
func New(t testing.TB) *World {
	w := &World{T: t, mods: map[string]map[string]*Mod{}, GitHub: map[string]any{}, GitHubRedirect: map[string]string{}, GitHubArchives: map[string][]byte{},
		DepsDev: map[string]any{}, RDAP: map[string]any{}, Vanity: map[string]string{}, EPSS: map[string][2]float64{}, Hooks: map[string]*Hook{},
		Extra: map[string]http.HandlerFunc{}, SumOverride: map[string][]string{}, recordID: map[string]int64{}}
	skey, vkey, err := sumdb.GenerateKey(rand.Reader, "sum.test.invalid")
	if err != nil {
		t.Fatal(err)
	}
	w.signer, _ = sumdb.NewSigner(skey)
	w.VerifierKey = vkey
	w.Server = httptest.NewServer(http.HandlerFunc(w.serve))
	w.URL = w.Server.URL
	t.Cleanup(w.Server.Close)
	base := t.TempDir()
	w.Home = filepath.Join(base, "home")
	w.CacheDir = filepath.Join(base, "smgo-cache")
	w.GoPath = filepath.Join(base, "gopath")
	w.ModCache = filepath.Join(w.GoPath, "pkg", "mod")
	os.MkdirAll(w.Home, 0o755)
	t.Cleanup(func() {
		// The module cache is read-only; make it removable.
		filepath.Walk(w.GoPath, func(p string, fi os.FileInfo, err error) error {
			if err == nil {
				os.Chmod(p, 0o755)
			}
			return nil
		})
	})
	return w
}

// AddModule publishes path@version with the given files. A go.mod is
// generated ("module path\n\ngo 1.21\n") if files lacks one.
func (w *World) AddModule(path, version string, files map[string]string) *Mod {
	w.mu.Lock()
	defer w.mu.Unlock()
	if files == nil {
		files = map[string]string{}
	}
	if _, ok := files["go.mod"]; !ok {
		files["go.mod"] = fmt.Sprintf("module %s\n\ngo 1.21\n", path)
	}
	m := &Mod{Path: path, Version: version, Files: files, Time: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(len(w.allModsLocked())) * time.Hour)}
	if w.mods[path] == nil {
		w.mods[path] = map[string]*Mod{}
	}
	w.mods[path][version] = m
	if module.IsPseudoVersion(version) {
		m.Hidden = true
	}
	return m
}

func (w *World) allModsLocked() []*Mod {
	var out []*Mod
	for _, vs := range w.mods {
		for _, m := range vs {
			out = append(out, m)
		}
	}
	return out
}

// Module returns a published module version, or nil.
func (w *World) Module(path, version string) *Mod {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.mods[path][version]
}

// GoModFile is a helper building go.mod text.
func GoModFile(path, goVersion string, requires ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "module %s\n\ngo %s\n", path, goVersion)
	if len(requires) > 0 {
		b.WriteString("\nrequire (\n")
		for _, r := range requires {
			fmt.Fprintf(&b, "\t%s\n", strings.Replace(r, "@", " ", 1))
		}
		b.WriteString(")\n")
	}
	return b.String()
}

// AddVuln adds a vulnerability entry. Affected ranges use OSV semver
// without the "v" prefix, as vuln.go.dev does.
func (w *World) AddVuln(e *vulndb.Entry) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if e.Modified.IsZero() {
		e.Modified = time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	}
	if e.Published.IsZero() {
		e.Published = e.Modified
	}
	w.Vulns = append(w.Vulns, e)
}

// SimpleVuln builds an entry affecting module mod for versions in
// [introduced, fixed) with the given vulnerable package symbols.
func SimpleVuln(id, mod, introduced, fixed, pkg string, symbols []string, aliases ...string) *vulndb.Entry {
	ev := []vulndb.RangeEvent{{Introduced: strings.TrimPrefix(introduced, "v")}}
	if fixed != "" {
		ev = append(ev, vulndb.RangeEvent{Fixed: strings.TrimPrefix(fixed, "v")})
	}
	a := vulndb.Affected{Package: vulndb.Package{Name: mod, Ecosystem: "Go"}, Ranges: []vulndb.Range{{Type: "SEMVER", Events: ev}}}
	if pkg != "" {
		a.EcosystemSpecific = &vulndb.EcosystemSpecific{Imports: []vulndb.Import{{Path: pkg, Symbols: symbols}}}
	}
	return &vulndb.Entry{ID: id, Summary: "Test vulnerability " + id, Details: "details of " + id, Aliases: aliases,
		Affected: []vulndb.Affected{a}, DatabaseSpecific: &vulndb.DatabaseSpecific{URL: "https://pkg.go.dev/vuln/" + id}}
}

// Hook returns (creating) a webhook receiver; its URL is w.URL+"/hook/"+name.
func (w *World) Hook(name string) *Hook {
	w.mu.Lock()
	defer w.mu.Unlock()
	h := w.Hooks[name]
	if h == nil {
		h = &Hook{Name: name}
		w.Hooks[name] = h
	}
	return h
}

// HookURL returns the URL of a webhook receiver.
func (w *World) HookURL(name string) string {
	w.Hook(name)
	return w.URL + "/hook/" + name
}

// SumDBEnv returns the GOSUMDB value pointing at the fake database.
func (w *World) SumDBEnv() string { return w.VerifierKey + " " + w.URL + "/sumdb" }

// Env returns the environment for running sm-go or go against the world.
func (w *World) Env(extra ...string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + w.Home,
		"GOPATH=" + w.GoPath,
		"GOMODCACHE=" + w.ModCache,
		"GOCACHE=" + goCache(),
		"GOPROXY=" + w.URL + "/proxy",
		"GOSUMDB=" + w.SumDBEnv(),
		"GONOSUMDB=",
		"GOPRIVATE=",
		"GOFLAGS=-mod=mod",
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"GOENV=off",
		"GO111MODULE=on",
		"CGO_ENABLED=0",
		"NO_COLOR=1",
		"SMGO_CACHE_DIR=" + w.CacheDir,
		"SMGO_VULNDB_URL=" + w.URL + "/vulndb",
		"SMGO_INDEX_URL=" + w.URL + "/index",
		"SMGO_DEPSDEV_URL=" + w.URL + "/depsdev",
		"SMGO_GITHUB_API_URL=" + w.URL + "/github",
		"SMGO_KEV_URL=" + w.URL + "/kev.json",
		"SMGO_EPSS_URL=" + w.URL + "/epss",
		"SMGO_GODEV_URL=" + w.URL + "/godev",
		"SMGO_RDAP_URL=" + w.URL + "/rdap",
		"SMGO_VANITY_BASE=" + w.URL + "/vanity",
		"SMGO_PANIC=1",
	}
	// Later entries win.
	m := map[string]int{}
	for i, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		m[k] = i
	}
	for _, kv := range extra {
		k, _, _ := strings.Cut(kv, "=")
		if i, ok := m[k]; ok {
			env[i] = kv
		} else {
			env = append(env, kv)
		}
	}
	return env
}

func goCache() string {
	if d := os.Getenv("GOCACHE"); d != "" {
		return d
	}
	out, err := exec.Command("go", "env", "GOCACHE").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	return filepath.Join(os.TempDir(), "gocache")
}

// Result is the outcome of running sm-go.
type Result struct {
	Stdout string
	Stderr string
	Code   int
}

// JSON decodes stdout as the --json envelope.
func (r Result) JSON(t testing.TB) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(r.Stdout), &m); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s\nstderr:\n%s", err, r.Stdout, r.Stderr)
	}
	return m
}

// Decode decodes the "result" field of the JSON envelope into v.
func (r Result) Decode(t testing.TB, v any) {
	t.Helper()
	var env struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal([]byte(r.Stdout), &env); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s\nstderr:\n%s", err, r.Stdout, r.Stderr)
	}
	if err := json.Unmarshal(env.Result, v); err != nil {
		t.Fatalf("decoding result: %v\n%s", err, env.Result)
	}
}

// Run executes sm-go in-process in dir with the world's environment.
func (w *World) Run(dir string, args ...string) Result {
	return w.RunEnv(dir, nil, args...)
}

// RunEnv is Run with extra environment variables.
func (w *World) RunEnv(dir string, extra []string, args ...string) Result {
	w.T.Helper()
	var out, errb bytes.Buffer
	full := append([]string{}, args...)
	if dir != "" {
		full = append(full, "-C", dir)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	code := cli.Run(ctx, full, w.Env(extra...), &out, &errb)
	return Result{Stdout: out.String(), Stderr: errb.String(), Code: code}
}

// Go runs the real go command in dir with the world's environment.
func (w *World) Go(dir string, args ...string) (string, error) {
	return w.GoEnv(dir, nil, args...)
}

// GoEnv is Go with extra environment variables (e.g. GOOS/GOARCH for
// cross builds, or "GOWORK=" to enable workspace mode, which World.Env
// turns off).
func (w *World) GoEnv(dir string, extra []string, args ...string) (string, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = w.Env(extra...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// WriteFiles writes files (relative path -> content) under dir.
func WriteFiles(t testing.TB, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// Project writes a local main module into a new temp dir and returns it.
func (w *World) Project(files map[string]string) string {
	w.T.Helper()
	dir := w.T.TempDir()
	WriteFiles(w.T, dir, files)
	return dir
}

// ---------------- HTTP ----------------

func (w *World) serve(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	w.Requests = append(w.Requests, r.Method+" "+r.URL.RequestURI())
	w.mu.Unlock()
	p := r.URL.Path
	if h, ok := w.Extra[p]; ok {
		h(rw, r)
		return
	}
	switch {
	case strings.HasPrefix(p, "/proxy/"):
		w.serveProxy(rw, r, strings.TrimPrefix(p, "/proxy/"))
	case strings.HasPrefix(p, "/sumdb/"):
		w.serveSumDB(rw, r, strings.TrimPrefix(p, "/sumdb/"))
	case strings.HasPrefix(p, "/vulndb/"):
		w.serveVulnDB(rw, r, strings.TrimPrefix(p, "/vulndb/"))
	case strings.HasPrefix(p, "/github/"):
		w.serveGitHub(rw, r, strings.TrimPrefix(p, "/github/"))
	case strings.HasPrefix(p, "/rdap/"):
		w.serveMap(rw, w.RDAP, strings.TrimPrefix(p, "/rdap/"))
	case strings.HasPrefix(p, "/vanity/"), strings.HasPrefix(p, "/vanity-http/"):
		// /vanity/<path> plays https://<path>, /vanity-http/<path> plays
		// http://<path> (same pages).
		w.mu.Lock()
		page, ok := w.Vanity[p[strings.Index(p[1:], "/")+2:]]
		w.mu.Unlock()
		if !ok {
			http.NotFound(rw, r)
			return
		}
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.Write([]byte(page))
	case strings.HasPrefix(p, "/depsdev/"):
		w.serveMap(rw, w.DepsDev, strings.TrimPrefix(p, "/depsdev/"))
	case p == "/kev.json":
		w.mu.Lock()
		writeJSON(rw, map[string]any{"title": "CISA KEV (test)", "vulnerabilities": w.KEV})
		w.mu.Unlock()
	case p == "/epss":
		w.serveEPSS(rw, r)
	case p == "/index/index":
		w.serveIndex(rw, r)
	case p == "/godev/dl/":
		w.mu.Lock()
		writeJSON(rw, w.GoReleases)
		w.mu.Unlock()
	case strings.HasPrefix(p, "/hook/"):
		body, _ := io.ReadAll(r.Body)
		h := w.Hook(strings.TrimPrefix(p, "/hook/"))
		w.mu.Lock()
		h.Bodies = append(h.Bodies, body)
		w.mu.Unlock()
		rw.WriteHeader(200)
		rw.Write([]byte("ok"))
	default:
		http.NotFound(rw, r)
	}
}

func writeJSON(rw http.ResponseWriter, v any) {
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(v)
}

func (w *World) serveProxy(rw http.ResponseWriter, r *http.Request, rest string) {
	i := strings.Index(rest, "/@")
	if i < 0 {
		http.NotFound(rw, r)
		return
	}
	path, err := module.UnescapePath(rest[:i])
	if err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}
	what := rest[i+2:]
	w.mu.Lock()
	vs := w.mods[path]
	var list []string
	for v, m := range vs {
		if !m.Hidden {
			list = append(list, v)
		}
	}
	w.mu.Unlock()
	semver.Sort(list)
	switch {
	case what == "v/list":
		rw.Write([]byte(strings.Join(list, "\n")))
		if len(list) > 0 {
			rw.Write([]byte("\n"))
		}
		return
	case what == "latest":
		var best *Mod
		w.mu.Lock()
		for _, m := range vs {
			if best == nil || semver.Compare(m.Version, best.Version) > 0 {
				best = m
			}
		}
		w.mu.Unlock()
		if best == nil {
			http.Error(rw, "not found", 404)
			return
		}
		writeJSON(rw, infoJSON(best))
		return
	case strings.HasPrefix(what, "v/"):
		file := strings.TrimPrefix(what, "v/")
		dot := strings.LastIndex(file, ".")
		if dot < 0 {
			http.NotFound(rw, r)
			return
		}
		ver, err := module.UnescapeVersion(file[:dot])
		if err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		w.mu.Lock()
		m := vs[ver]
		w.mu.Unlock()
		if m == nil {
			http.Error(rw, "not found: "+path+"@"+ver, 404)
			return
		}
		switch file[dot:] {
		case ".info":
			writeJSON(rw, infoJSON(m))
		case ".mod":
			rw.Write([]byte(m.GoMod()))
		case ".zip":
			rw.Header().Set("Content-Type", "application/zip")
			rw.Write(m.Zip())
		default:
			http.NotFound(rw, r)
		}
		return
	}
	http.NotFound(rw, r)
}

func infoJSON(m *Mod) map[string]any {
	info := map[string]any{"Version": m.Version, "Time": m.Time.Format(time.RFC3339)}
	if len(m.Origin) > 0 {
		info["Origin"] = m.Origin
	}
	return info
}

// ---------------- checksum database ----------------

// SumLines returns the go.sum lines for a published module version.
func (w *World) SumLines(path, version string) []string {
	w.mu.Lock()
	if o, ok := w.SumOverride[path+"@"+version]; ok {
		w.mu.Unlock()
		return o
	}
	m := w.mods[path][version]
	w.mu.Unlock()
	if m == nil {
		return nil
	}
	zh, _ := modzip.HashZip(m.Zip())
	mh := modzip.HashGoMod([]byte(m.GoMod()))
	return []string{path + " " + version + " " + zh, path + " " + version + "/go.mod " + mh}
}

// addRecord appends a record to the log (caller holds no lock).
func (w *World) addRecord(key string, data []byte) int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if id, ok := w.recordID[key]; ok {
		return id
	}
	id := int64(len(w.records))
	hashes, err := sumdb.StoredHashes(id, data, sumdb.HashReaderFunc(func(idx []int64) ([]sumdb.Hash, error) {
		out := make([]sumdb.Hash, len(idx))
		for i, x := range idx {
			out[i] = w.hashes[x]
		}
		return out, nil
	}))
	if err != nil {
		panic(err)
	}
	w.hashes = append(w.hashes, hashes...)
	w.records = append(w.records, data)
	w.recordID[key] = id
	return id
}

func (w *World) treeLocked() sumdb.Tree {
	if w.treeOverride != nil {
		return *w.treeOverride
	}
	n := int64(len(w.records))
	h, _ := sumdb.TreeHash(n, sumdb.HashReaderFunc(func(idx []int64) ([]sumdb.Hash, error) {
		out := make([]sumdb.Hash, len(idx))
		for i, x := range idx {
			out[i] = w.hashes[x]
		}
		return out, nil
	}))
	return sumdb.Tree{N: n, Hash: h}
}

// SignedTree returns the current signed tree note.
func (w *World) SignedTree() []byte {
	w.mu.Lock()
	t := w.treeLocked()
	w.mu.Unlock()
	msg, err := w.signer.Sign(string(sumdb.FormatTree(t)))
	if err != nil {
		panic(err)
	}
	return msg
}

// ForkTree makes the database sign a bogus tree head of the current size
// (simulates a forked log).
func (w *World) ForkTree() {
	w.mu.Lock()
	defer w.mu.Unlock()
	t := w.treeLocked()
	t.Hash[0] ^= 0xff
	w.treeOverride = &t
}

// AddSumRecord pre-registers path@version in the log (normally records are
// added on first lookup).
func (w *World) AddSumRecord(path, version string) {
	lines := w.SumLines(path, version)
	if lines == nil {
		w.T.Fatalf("no module %s@%s", path, version)
	}
	w.addRecord(path+"@"+version, []byte(strings.Join(lines, "\n")+"\n"))
}

func (w *World) serveSumDB(rw http.ResponseWriter, r *http.Request, rest string) {
	switch {
	case rest == "latest":
		rw.Write(w.SignedTree())
	case rest == "supported":
		rw.WriteHeader(200)
	case strings.HasPrefix(rest, "lookup/"):
		key := strings.TrimPrefix(rest, "lookup/")
		at := strings.LastIndex(key, "@")
		if at < 0 {
			http.Error(rw, "bad lookup", 400)
			return
		}
		path, err1 := module.UnescapePath(key[:at])
		ver, err2 := module.UnescapeVersion(key[at+1:])
		if err1 != nil || err2 != nil {
			http.Error(rw, "bad lookup", 400)
			return
		}
		lines := w.SumLines(path, ver)
		if lines == nil {
			http.Error(rw, "not found", 404)
			return
		}
		data := []byte(strings.Join(lines, "\n") + "\n")
		id := w.addRecord(path+"@"+ver, data)
		w.mu.Lock()
		rec := w.records[id]
		w.mu.Unlock()
		var buf bytes.Buffer
		fmt.Fprintf(&buf, "%d\n", id)
		buf.Write(rec)
		buf.WriteString("\n")
		buf.Write(w.SignedTree())
		rw.Write(buf.Bytes())
	case strings.HasPrefix(rest, "tile/"):
		t, err := sumdb.ParseTilePath(rest)
		if err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		n := int64(len(w.records))
		if t.L == -1 {
			// data tile: concatenated records
			start := t.N << uint(t.H)
			var buf bytes.Buffer
			for i := start; i < start+int64(t.W); i++ {
				if i >= n {
					http.NotFound(rw, r)
					return
				}
				buf.Write(w.records[i])
				buf.WriteString("\n")
			}
			rw.Write(buf.Bytes())
			return
		}
		if sumdb.TileWidth(t.H, t.L, t.N, n) < t.W {
			http.NotFound(rw, r)
			return
		}
		var buf bytes.Buffer
		for i := 0; i < t.W; i++ {
			idx := sumdb.StoredHashIndex(t.L*t.H, t.N<<uint(t.H)+int64(i))
			if idx >= int64(len(w.hashes)) {
				http.NotFound(rw, r)
				return
			}
			buf.Write(w.hashes[idx][:])
		}
		rw.Write(buf.Bytes())
	default:
		http.NotFound(rw, r)
	}
}

// ---------------- vulndb ----------------

func (w *World) serveVulnDB(rw http.ResponseWriter, r *http.Request, rest string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case rest == "index/db.json":
		writeJSON(rw, map[string]any{"modified": time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)})
	case rest == "index/modules.json":
		byMod := map[string][]map[string]any{}
		for _, e := range w.Vulns {
			for _, a := range e.Affected {
				fixed := ""
				for _, rg := range a.Ranges {
					for _, ev := range rg.Events {
						if ev.Fixed != "" {
							fixed = ev.Fixed
						}
					}
				}
				v := map[string]any{"id": e.ID, "modified": e.Modified}
				if fixed != "" {
					v["fixed"] = fixed
				}
				byMod[a.Package.Name] = append(byMod[a.Package.Name], v)
			}
		}
		var paths []string
		for p := range byMod {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		var out []map[string]any
		for _, p := range paths {
			out = append(out, map[string]any{"path": p, "vulns": byMod[p]})
		}
		if out == nil {
			out = []map[string]any{}
		}
		writeJSON(rw, out)
	case rest == "index/vulns.json":
		var out []map[string]any
		for _, e := range w.Vulns {
			out = append(out, map[string]any{"id": e.ID, "modified": e.Modified, "aliases": e.Aliases})
		}
		writeJSON(rw, out)
	case strings.HasPrefix(rest, "ID/") && strings.HasSuffix(rest, ".json"):
		id := strings.TrimSuffix(strings.TrimPrefix(rest, "ID/"), ".json")
		for _, e := range w.Vulns {
			if e.ID == id {
				writeJSON(rw, e)
				return
			}
		}
		http.NotFound(rw, r)
	default:
		http.NotFound(rw, r)
	}
}

// ---------------- GitHub ----------------

func (w *World) serveGitHub(rw http.ResponseWriter, r *http.Request, rest string) {
	w.mu.Lock()
	if to, ok := w.GitHubRedirect[rest]; ok {
		w.mu.Unlock()
		http.Redirect(rw, r, w.URL+"/github/"+to, http.StatusMovedPermanently)
		return
	}
	if blob, ok := w.GitHubArchives[rest]; ok {
		w.mu.Unlock()
		rw.Header().Set("Content-Type", "application/zip")
		rw.Write(blob)
		return
	}
	key := rest
	if r.URL.RawQuery != "" {
		if _, ok := w.GitHub[rest+"?"+r.URL.RawQuery]; ok {
			key = rest + "?" + r.URL.RawQuery
		}
	}
	v, ok := w.GitHub[key]
	w.mu.Unlock()
	if !ok {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(404)
		rw.Write([]byte(`{"message":"Not Found"}`))
		return
	}
	writeJSON(rw, v)
}

// GitHubRepo registers a repository with sensible defaults; fields
// override them.
func (w *World) GitHubRepo(owner, name string, fields map[string]any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	repo := map[string]any{
		"full_name": owner + "/" + name, "html_url": "https://github.com/" + owner + "/" + name,
		"archived": false, "disabled": false, "fork": false, "private": false,
		"created_at": "2020-01-01T00:00:00Z", "pushed_at": "2025-05-01T00:00:00Z",
		"default_branch": "main", "stargazers_count": 100, "open_issues_count": 3,
		"owner":   map[string]any{"login": owner, "type": "Organization"},
		"license": map[string]any{"spdx_id": "MIT"},
	}
	for k, v := range fields {
		repo[k] = v
	}
	w.GitHub["repos/"+owner+"/"+name] = repo
	if _, ok := w.GitHub["users/"+owner]; !ok {
		w.GitHub["users/"+owner] = map[string]any{"login": owner, "type": "Organization", "created_at": "2019-01-01T00:00:00Z"}
	}
}

// GitHubTag registers a lightweight tag pointing at commit sha.
func (w *World) GitHubTag(owner, name, tag, sha string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.GitHub["repos/"+owner+"/"+name+"/git/ref/tags/"+tag] = map[string]any{
		"ref": "refs/tags/" + tag, "object": map[string]any{"sha": sha, "type": "commit"}}
	w.GitHub["repos/"+owner+"/"+name+"/commits/"+sha] = map[string]any{"sha": sha}
}

// GitHubZipball registers the repository archive served for
// /repos/owner/name/zipball/ref. Like GitHub's, its entries live under a
// "owner-name-<short ref>/" directory. files maps repository paths to
// content.
func (w *World) GitHubZipball(owner, name, ref string, files map[string]string) {
	short := ref
	if len(short) > 7 {
		short = short[:7]
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	top := owner + "-" + name + "-" + short + "/"
	zw.Create(top)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f, err := zw.Create(top + n)
		if err != nil {
			w.T.Fatal(err)
		}
		f.Write([]byte(files[n]))
	}
	if err := zw.Close(); err != nil {
		w.T.Fatal(err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.GitHubArchives["repos/"+owner+"/"+name+"/zipball/"+ref] = buf.Bytes()
}

// ---------------- misc feeds ----------------

func (w *World) serveMap(rw http.ResponseWriter, m map[string]any, key string) {
	w.mu.Lock()
	// keys are stored unescaped; the request path is escaped.
	k, _ := url.PathUnescape(key)
	v, ok := m[k]
	if !ok {
		v, ok = m[key]
	}
	w.mu.Unlock()
	if !ok {
		rw.WriteHeader(404)
		rw.Write([]byte(`{"error":"not found"}`))
		return
	}
	writeJSON(rw, v)
}

func (w *World) serveEPSS(rw http.ResponseWriter, r *http.Request) {
	cves := strings.Split(r.URL.Query().Get("cve"), ",")
	var data []map[string]string
	w.mu.Lock()
	for _, c := range cves {
		if s, ok := w.EPSS[c]; ok {
			data = append(data, map[string]string{"cve": c, "epss": strconv.FormatFloat(s[0], 'f', 5, 64),
				"percentile": strconv.FormatFloat(s[1], 'f', 5, 64), "date": "2025-06-01"})
		}
	}
	w.mu.Unlock()
	writeJSON(rw, map[string]any{"status": "OK", "data": data})
}

func (w *World) serveIndex(rw http.ResponseWriter, r *http.Request) {
	since, _ := time.Parse(time.RFC3339Nano, r.URL.Query().Get("since"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 2000
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	// Like index.golang.org: entries in timestamp order, since inclusive.
	entries := append([]map[string]any(nil), w.Index...)
	stamp := func(e map[string]any) time.Time {
		ts, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(e["Timestamp"]))
		return ts
	}
	sort.SliceStable(entries, func(i, j int) bool { return stamp(entries[i]).Before(stamp(entries[j])) })
	n := 0
	for _, e := range entries {
		if stamp(e).Before(since) {
			continue
		}
		b, _ := json.Marshal(e)
		rw.Write(b)
		rw.Write([]byte("\n"))
		n++
		if n >= limit {
			break
		}
	}
}

// AddIndex appends a module index entry.
func (w *World) AddIndex(path, version string, ts time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.Index = append(w.Index, map[string]any{"Path": path, "Version": version, "Timestamp": ts.UTC().Format(time.RFC3339Nano)})
}
