package goenv

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIsPrivate(t *testing.T) {
	for _, c := range []struct {
		vars map[string]string
		path string
		want bool
	}{
		{map[string]string{"GOPRIVATE": "github.com/corp,corp.example.com"}, "github.com/corp/x", true},
		{map[string]string{"GOPRIVATE": "github.com/corp,corp.example.com"}, "corp.example.com/a/b", true},
		{map[string]string{"GOPRIVATE": "github.com/corp,corp.example.com"}, "github.com/corpx/y", false},
		{map[string]string{"GOPRIVATE": "github.com/corp,corp.example.com"}, "example.com/x", false},
		{map[string]string{"GOPRIVATE": "*.corp.example.com"}, "git.corp.example.com/x", true},
		{map[string]string{"GOPRIVATE": "*.corp.example.com"}, "corp.example.com/x", false},
		// GONOPROXY and GONOSUMDB mark modules private on their own, even
		// when GOPRIVATE is set to something else.
		{map[string]string{"GOPRIVATE": "a.example", "GONOPROXY": "b.example"}, "b.example/x", true},
		{map[string]string{"GOPRIVATE": "a.example", "GONOSUMDB": "c.example"}, "c.example/x", true},
		{map[string]string{"GOPRIVATE": "a.example", "GONOSUMDB": "c.example"}, "a.example/x", true},
		{map[string]string{"GONOPROXY": "none"}, "github.com/x/y", false},
		{map[string]string{}, "github.com/x/y", false},
		{map[string]string{"GOPRIVATE": "github.com/corp"}, "", false},
	} {
		if got := New(c.vars).IsPrivate(c.path); got != c.want {
			t.Errorf("%v IsPrivate(%q) = %v, want %v", c.vars, c.path, got, c.want)
		}
	}
}

func TestOfflineEnviron(t *testing.T) {
	e := New(map[string]string{"GOPROXY": "https://proxy.example", "GOPRIVATE": "corp.example.com", "GOFLAGS": "-mod=mod"})
	last := func(env []string, key string) string {
		v := ""
		for _, kv := range env {
			if k, val, _ := strings.Cut(kv, "="); k == key {
				v = val
			}
		}
		return v
	}
	if got := last(e.Environ(), "GOPROXY"); got != "https://proxy.example" {
		t.Errorf("online GOPROXY = %q", got)
	}
	e.SetOffline(true)
	for _, env := range [][]string{e.Environ(), e.With(map[string]string{"GOWORK": "off"}).Environ()} {
		for k, want := range map[string]string{"GOPROXY": "off", "GONOPROXY": "none", "GOSUMDB": "off", "GOVCS": "*:off", "GOPRIVATE": "corp.example.com"} {
			if got := last(env, k); got != want {
				t.Errorf("offline %s = %q, want %q", k, got, want)
			}
		}
	}
	// Get still reports the user's settings (sm-go's own proxy client
	// serves cached responses in offline mode).
	if got := e.Get("GOPROXY"); got != "https://proxy.example" {
		t.Errorf("offline Get(GOPROXY) = %q", got)
	}
}

// A go command older than a setting does not list it in `go env -json` and
// ignores it, even when it is set in the environment.
func TestUnsupportedSettings(t *testing.T) {
	e := &Env{environ: map[string]string{"GOAUTH": "netrc", "GOPROXY": "https://p.example"},
		goenv: map[string]string{"GOVERSION": "go1.23.12", "GOPROXY": "https://p.example"}}
	if v := e.Get("GOAUTH"); v != "" {
		t.Errorf("go1.23 GOAUTH = %q, want \"\"", v)
	}
	if since, ok := e.Unsupported("GOAUTH"); !ok || since != "1.24" {
		t.Errorf("Unsupported(GOAUTH) = %q, %v", since, ok)
	}
	if _, ok := e.Unsupported("GOPROXY"); ok {
		t.Error("GOPROXY unsupported")
	}
	e.goenv["GOAUTH"] = "netrc"
	if _, ok := e.Unsupported("GOAUTH"); ok || e.Get("GOAUTH") != "netrc" {
		t.Errorf("go1.24 GOAUTH = %q", e.Get("GOAUTH"))
	}
	// Without a go command the environment is all there is.
	if v := New(map[string]string{"GOAUTH": "off"}).Get("GOAUTH"); v != "off" {
		t.Errorf("no go: GOAUTH = %q", v)
	}
}

// Environment variable names are case-insensitive on Windows only.
func TestEnvironmentCase(t *testing.T) {
	e := Load(context.Background(), []string{"SMGO_NO_GO=1", "Path=/bin", "=C:=C:\\work", "LocalAppData=/la", "XDG_CACHE_HOME="})
	p, ok := e.Lookup("PATH")
	if runtime.GOOS == "windows" {
		if !ok || p != "/bin" || e.Getenv("path") != "/bin" {
			t.Errorf("windows: PATH = %q, %v", p, ok)
		}
		if got := e.CacheDir(); got != filepath.Join("/la", "sm-go") {
			t.Errorf("windows: CacheDir = %q", got)
		}
	} else if ok || e.Getenv("Path") != "/bin" {
		t.Errorf("PATH = %q, %v; Path = %q", p, ok, e.Getenv("Path"))
	}
	if _, ok := e.Lookup(""); ok {
		t.Error("per-drive directory entry kept")
	}
}

// Home follows os.UserHomeDir (the go command: .netrc, GOPATH); GitHome
// follows git, which prefers HOME on every system.
func TestHome(t *testing.T) {
	e := New(map[string]string{"HOME": "/home/u", "USERPROFILE": `C:\Users\u`})
	want := "/home/u"
	if runtime.GOOS == "windows" {
		want = `C:\Users\u`
	}
	if got := e.Home(); got != want {
		t.Errorf("Home = %q, want %q", got, want)
	}
	if got := e.GitHome(); got != "/home/u" {
		t.Errorf("GitHome = %q", got)
	}
	if runtime.GOOS == "windows" {
		if got := New(map[string]string{"USERPROFILE": `C:\Users\u`}).GitHome(); got != `C:\Users\u` {
			t.Errorf("GitHome without HOME = %q", got)
		}
	}
}
