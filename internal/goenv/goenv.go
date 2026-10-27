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
		// Windows lists per-drive directories as "=C:=C:\dir"; skip them.
		if k, v, ok := strings.Cut(kv, "="); ok && k != "" {
			e.environ[envKey(k)] = v
		}
	}
	if e.Getenv("SMGO_NO_GO") == "1" {
		return e
	}
	gobin := e.LookPath("go")
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
		e.environ[envKey(k)] = v
	}
	return e
}

// envKey is the map key of an environment variable: names are
// case-insensitive on Windows ("Path" and "PATH" are one variable).
func envKey(k string) string {
	if runtime.GOOS == "windows" {
		return strings.ToUpper(k)
	}
	return k
}

// LookPath finds an executable on this environment's PATH ("" if absent).
func (e *Env) LookPath(name string) string { return lookPath(name, e.Getenv("PATH")) }

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

// introduced lists Go settings added after Go 1.23 (the oldest Go sm-go
// supports) with the release that added them. `go env -json` lists every
// setting the go command knows, so an older go command that does not list
// one ignores it even when it is set in the environment.
var introduced = map[string]string{"GOAUTH": "1.24", "GOFIPS140": "1.24"}

// Unsupported reports whether key is a setting the installed go command is
// too old to know about (it ignores the variable), and the Go release that
// added it.
func (e *Env) Unsupported(key string) (since string, ok bool) {
	since, versioned := introduced[key]
	if !versioned || len(e.goenv) == 0 {
		return "", false
	}
	_, known := e.goenv[key]
	return since, !known
}

// Get returns the effective value of a Go environment variable.
func (e *Env) Get(key string) string {
	if v, ok := e.goenv[key]; ok {
		return v
	}
	if _, ok := e.Unsupported(key); ok {
		return ""
	}
	if v, ok := e.Lookup(key); ok && v != "" {
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
func (e *Env) Getenv(key string) string { return e.environ[envKey(key)] }

// Lookup reports a raw process environment variable and whether it is set.
func (e *Env) Lookup(key string) (string, bool) {
	v, ok := e.environ[envKey(key)]
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

// EnvironIn is Environ for a command run in dir. It sets PWD to dir, as
// os/exec does when it builds the environment itself: the go command and
// git take the working directory from PWD when it names that directory,
// so the paths they print keep sm-go's spelling (on macOS /var/... rather
// than the resolved /private/var/...).
func (e *Env) EnvironIn(dir string) []string {
	env := e.Environ()
	if abs, err := filepath.Abs(dir); err == nil {
		env = append(env, "PWD="+abs)
	}
	return env
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
		n.environ[envKey(k)] = v
		delete(n.goenv, k)
	}
	return n
}

// Home returns the home directory the go command uses (os.UserHomeDir, for
// .netrc and the default GOPATH): %USERPROFILE% on Windows, $home on Plan
// 9, $HOME elsewhere.
func (e *Env) Home() string {
	key := "HOME"
	switch runtime.GOOS {
	case "windows":
		key = "USERPROFILE"
	case "plan9":
		key = "home"
	}
	if h := e.Getenv(key); h != "" {
		return h
	}
	h, _ := os.UserHomeDir()
	return h
}

// GitHome returns the home directory git uses for ~/.gitconfig and the
// default XDG directory: $HOME, which Git for Windows sets from
// %HOMEDRIVE%%HOMEPATH% (when that is a directory) or %USERPROFILE% if it
// is unset.
func (e *Env) GitHome() string {
	if h := e.Getenv("HOME"); h != "" {
		return h
	}
	if runtime.GOOS == "windows" {
		if d, p := e.Getenv("HOMEDRIVE"), e.Getenv("HOMEPATH"); d != "" && p != "" {
			if fi, err := os.Stat(d + p); err == nil && fi.IsDir() {
				return d + p
			}
		}
		if h := e.Getenv("USERPROFILE"); h != "" {
			return h
		}
	}
	h, _ := os.UserHomeDir()
	return h
}

// CacheDir returns the directory sm-go uses for its HTTP cache and state.
func (e *Env) CacheDir() string {
	if d := e.Getenv("SMGO_CACHE_DIR"); d != "" {
		return d
	}
	if d := e.Getenv("XDG_CACHE_HOME"); d != "" {
		return filepath.Join(d, "sm-go")
	}
	if runtime.GOOS == "windows" {
		if d := e.Getenv("LOCALAPPDATA"); d != "" {
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
