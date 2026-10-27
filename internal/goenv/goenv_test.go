package goenv

import (
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
