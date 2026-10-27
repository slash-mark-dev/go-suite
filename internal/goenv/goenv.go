// Package goenv reads the Go environment (go env -json), falling back to
// process environment variables and documented defaults when no Go
// toolchain is installed.
package goenv

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/module"
)

// Env is a snapshot of the Go environment.
type Env struct {
	environ map[string]string // process environment
	goenv   map[string]string // output of `go env -json`, if available
	GoBin   string            // path of the go command, "" if not found
	// offline makes Environ keep go-command subprocesses off the network.
	offline bool
}

var defaults = map[string]string{
	"GOPROXY":     "https://proxy.golang.org,direct",
	"GOSUMDB":     "sum.golang.org",
	"GOTOOLCHAIN": "auto",
	"CGO_ENABLED": "1",
}

// Load builds an Env from environ (KEY=VALUE pairs, normally os.Environ()).
// It runs `go env -json` when the go command is on PATH.
func Load(ctx context.Context, environ []string) *Env {
	e := &Env{environ: map[string]string{}}
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok {
			e.environ[k] = v
		}
	}
	if e.environ["SMGO_NO_GO"] == "1" {
		return e
	}
	gobin := lookPath("go", e.environ["PATH"])
	if gobin == "" {
		return e
	}
	e.GoBin = gobin
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, gobin, "env", "-json")
	cmd.Env = e.Environ()
	// Run outside any module so a broken go.mod cannot make `go env` fail.
	cmd.Dir = os.TempDir()
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		m := map[string]string{}
		if json.Unmarshal(out.Bytes(), &m) == nil {
			e.goenv = m
		}
	}
	return e
}

// New returns an Env built from explicit values, without running go.
func New(vars map[string]string) *Env {
	e := &Env{environ: map[string]string{}}
	for k, v := range vars {
		e.environ[k] = v
	}
	return e
}

func lookPath(name, pathEnv string) string {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			continue
		}
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// HaveGo reports whether a go command was found.
func (e *Env) HaveGo() bool { return e.GoBin != "" }

// Get returns the effective value of a Go environment variable.
func (e *Env) Get(key string) string {
	if v, ok := e.goenv[key]; ok {
		return v
	}
	if v, ok := e.environ[key]; ok && v != "" {
		return v
	}
	switch key {
	case "GOPATH":
		if home := e.Home(); home != "" {
			return filepath.Join(home, "go")
		}
	case "GOMODCACHE":
		gp := e.Get("GOPATH")
		if gp != "" {
			return filepath.Join(filepath.SplitList(gp)[0], "pkg", "mod")
		}
	case "GONOPROXY", "GONOSUMDB":
		return e.Get("GOPRIVATE")
	case "GOOS":
		return runtime.GOOS
	case "GOARCH":
		return runtime.GOARCH
	}
	return defaults[key]
}

// Getenv returns a raw process environment variable (not Go-specific).
func (e *Env) Getenv(key string) string { return e.environ[key] }

// Lookup reports a raw process environment variable and whether it is set.
func (e *Env) Lookup(key string) (string, bool) {
	v, ok := e.environ[key]
	return v, ok
}

// FromGoEnv reports whether key came from `go env` (and so reflects go.env
// files and `go env -w` settings, not just the process environment).
func (e *Env) FromGoEnv(key string) bool {
	_, ok := e.goenv[key]
	return ok
}

// OfflineGoEnv are the settings added to the environment of every go
// command sm-go runs in offline mode, so that it uses the module cache
// only: GOPROXY=off disables the module proxy; GONOPROXY=none stops
// GOPRIVATE/GONOPROXY modules from being fetched directly (go-get pages
// and version control), which GOPROXY=off alone does not; GOSUMDB=off
// stops the checksum database lookups the go command otherwise makes
// directly even with GOPROXY=off (go.sum is still verified); GOVCS=*:off
// forbids every version control tool as a last resort. GOPROXY=off also
// blocks toolchain downloads (GOTOOLCHAIN).
var OfflineGoEnv = []string{"GOPROXY=off", "GONOPROXY=none", "GOSUMDB=off", "GOVCS=*:off"}

// SetOffline turns offline mode on or off for subprocesses: when on,
// Environ appends OfflineGoEnv so that the go command never touches the
// network. Get still reports the user's real settings.
func (e *Env) SetOffline(on bool) { e.offline = on }

// Offline reports whether SetOffline(true) was called.
func (e *Env) Offline() bool { return e.offline }

// Environ returns the process environment as KEY=VALUE pairs, for
// subprocesses. In offline mode it ends with OfflineGoEnv (callers may
// append more variables; for duplicate keys the last one wins).
func (e *Env) Environ() []string {
	out := make([]string, 0, len(e.environ)+len(OfflineGoEnv))
	for k, v := range e.environ {
		out = append(out, k+"="+v)
	}
	if e.offline {
		out = append(out, OfflineGoEnv...)
	}
	return out
}

// PrivatePatterns returns the module path patterns that mark private
// modules: GOPRIVATE, GONOPROXY and GONOSUMDB (each with the go command's
// defaults, so GONOPROXY and GONOSUMDB fall back to GOPRIVATE), joined
// with commas.
func (e *Env) PrivatePatterns() string {
	var ps []string
	for _, k := range []string{"GOPRIVATE", "GONOPROXY", "GONOSUMDB"} {
		if v := strings.Trim(e.Get(k), ","); v != "" {
			ps = append(ps, v)
		}
	}
	return strings.Join(ps, ",")
}

// IsPrivate reports whether a module path is private: it matches
// GOPRIVATE, GONOPROXY or GONOSUMDB with the go command's prefix-glob
// rules (module.MatchPrefixPatterns).
func (e *Env) IsPrivate(path string) bool {
	return path != "" && module.MatchPrefixPatterns(e.PrivatePatterns(), path)
}

// With returns a copy of the environment with extra variables set. The
// copy keeps the go command and the go env snapshot.
func (e *Env) With(kv map[string]string) *Env {
	n := &Env{environ: map[string]string{}, goenv: map[string]string{}, GoBin: e.GoBin, offline: e.offline}
	for k, v := range e.environ {
		n.environ[k] = v
	}
	for k, v := range e.goenv {
		n.goenv[k] = v
	}
	for k, v := range kv {
		n.environ[k] = v
		delete(n.goenv, k)
	}
	return n
}

// Home returns the user's home directory.
func (e *Env) Home() string {
	if h := e.environ["HOME"]; h != "" {
		return h
	}
	if h := e.environ["USERPROFILE"]; h != "" {
		return h
	}
	h, _ := os.UserHomeDir()
	return h
}

// CacheDir returns the directory sm-go uses for its HTTP cache and state.
func (e *Env) CacheDir() string {
	if d := e.environ["SMGO_CACHE_DIR"]; d != "" {
		return d
	}
	if d := e.environ["XDG_CACHE_HOME"]; d != "" {
		return filepath.Join(d, "sm-go")
	}
	if runtime.GOOS == "windows" {
		if d := e.environ["LocalAppData"]; d != "" {
			return filepath.Join(d, "sm-go")
		}
	}
	if h := e.Home(); h != "" {
		return filepath.Join(h, ".cache", "sm-go")
	}
	return filepath.Join(os.TempDir(), "sm-go-cache")
}

// GoVersion returns the installed Go version ("go1.27.3"), or "".
func (e *Env) GoVersion() string { return e.goenv["GOVERSION"] }
