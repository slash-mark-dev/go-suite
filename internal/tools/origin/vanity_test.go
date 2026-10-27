package origin_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

type vanityResult struct {
	Subject string `json:"subject"`
	Skipped int    `json:"skipped"`
	Modules []struct {
		Path       string `json:"path"`
		ImportPath string `json:"importPath"`
		Page       *struct {
			URL          string `json:"url"`
			FinalURL     string `json:"finalUrl"`
			HTTPS        bool   `json:"https"`
			RedirectHost string `json:"redirectHost"`
			Status       int    `json:"status"`
		} `json:"page"`
		Match *struct {
			Prefix string `json:"prefix"`
			VCS    string `json:"vcs"`
			Repo   string `json:"repo"`
		} `json:"match"`
		MatchError string `json:"matchError"`
		Repo       *struct {
			Method    string `json:"method"`
			Reachable bool   `json:"reachable"`
		} `json:"repo"`
		Subpaths []struct {
			Path string `json:"path"`
			OK   bool   `json:"ok"`
		} `json:"subpaths"`
		Domain *struct {
			Name     string `json:"name"`
			NotFound bool   `json:"notFound"`
		} `json:"domain"`
	} `json:"modules"`
	Findings []finding `json:"findings"`
	Summary  struct {
		Modules int `json:"modules"`
		Clean   int `json:"clean"`
	} `json:"summary"`
}

func TestVanityBuildList(t *testing.T) {
	w := testenv.New(t)
	now := time.Now()
	// Clean module with packages whose pages all agree.
	w.AddModule("go.good.example/lib", "v1.0.0", map[string]string{
		"lib.go": "package lib\n", "sub/sub.go": "package sub\n", "sub/deep/deep.go": "package deep\n",
		"internal/x/x.go": "package x\n", "lib_test.go": "package lib\n",
	})
	good := vanityPage("go.good.example/lib", "git", "https://github.com/acme/lib")
	w.Vanity["go.good.example/lib"] = good
	w.Vanity["go.good.example/lib/sub"] = good
	w.Vanity["go.good.example/lib/sub/deep"] = good
	w.GitHubRepo("acme", "lib", nil)
	rdap(w, "good.example", now.Add(200*24*time.Hour))

	// Root page fine, but the package page is missing.
	w.AddModule("go.sub.example/lib", "v0.2.0", map[string]string{"pkg/pkg.go": "package pkg\n"})
	w.Vanity["go.sub.example/lib"] = vanityPage("go.sub.example/lib", "git", "https://github.com/acme/sublib")
	w.GitHubRepo("acme", "sublib", nil)
	rdap(w, "sub.example", now.Add(10*24*time.Hour))

	// GitHub-hosted modules are skipped.
	w.AddModule("github.com/acme/plain", "v1.0.0", nil)

	dir := project(w, "go.good.example/lib@v1.0.0", "go.sub.example/lib@v0.2.0", "github.com/acme/plain@v1.0.0")
	r := w.Run(dir, "vanity", "--json")
	checkEnvelope(t, r, "vanity", 1)
	var res vanityResult
	r.Decode(t, &res)
	if res.Skipped != 1 || res.Summary.Modules != 2 || res.Summary.Clean != 1 {
		t.Fatalf("summary: skipped %d %+v", res.Skipped, res.Summary)
	}
	if got := rules(res.Findings, "go.good.example/lib"); len(got) != 0 {
		t.Errorf("good: %v", got)
	}
	got := rules(res.Findings, "go.sub.example/lib")
	if got["subpath-missing"] != "medium" || got["domain-expiring"] != "medium" || len(got) != 2 {
		t.Errorf("sub: %v", got)
	}
	for _, m := range res.Modules {
		if m.Path != "go.good.example/lib" {
			continue
		}
		if m.Page == nil || !m.Page.HTTPS || m.Page.URL != "https://go.good.example/lib?go-get=1" || m.Match == nil || m.Match.Repo != "https://github.com/acme/lib" {
			t.Errorf("page/match: %+v %+v", m.Page, m.Match)
		}
		if m.Repo == nil || m.Repo.Method != "github-api" || !m.Repo.Reachable {
			t.Errorf("repo: %+v", m.Repo)
		}
		// internal/ and test-only files are skipped; shallow dirs first.
		if len(m.Subpaths) != 2 || m.Subpaths[0].Path != "go.good.example/lib/sub" || m.Subpaths[1].Path != "go.good.example/lib/sub/deep" || !m.Subpaths[0].OK || !m.Subpaths[1].OK {
			t.Errorf("subpaths: %+v", m.Subpaths)
		}
		if m.Domain == nil || m.Domain.Name != "good.example" {
			t.Errorf("domain: %+v", m.Domain)
		}
	}

	// --subpaths 0 and --fail-on high: the remaining medium finding passes.
	r = w.Run(dir, "vanity", "--subpaths", "0", "--fail-on", "high", "--json")
	checkEnvelope(t, r, "vanity", 0)

	r = w.Run(dir, "vanity")
	if r.Code != 1 || !strings.Contains(r.Stdout, "Vanity import audit") || !strings.Contains(r.Stdout, "no go-import tag for package go.sub.example/lib/pkg") {
		t.Errorf("text (code %d):\n%s", r.Code, r.Stdout)
	}
}

func TestVanityProblems(t *testing.T) {
	w := testenv.New(t)
	// Downgrade to plain HTTP.
	w.Vanity["go.http.example/lib"] = vanityPage("go.http.example/lib", "git", "https://github.com/acme/h")
	w.Extra["/vanity/go.http.example/lib"] = func(rw http.ResponseWriter, r *http.Request) {
		http.Redirect(rw, r, w.URL+"/vanity-http/go.http.example/lib?go-get=1", http.StatusFound)
	}
	w.GitHubRepo("acme", "h", nil)
	// Redirect to another host.
	w.Extra["/vanity/go.redir.example/lib"] = func(rw http.ResponseWriter, r *http.Request) {
		http.Redirect(rw, r, w.URL+"/vanity/landing.example/lib?go-get=1", http.StatusMovedPermanently)
	}
	w.Vanity["landing.example/lib"] = vanityPage("go.redir.example/lib", "git", "https://github.com/acme/h")
	// Two tags cover the path: cmd/go fails.
	w.Vanity["go.multi.example/lib"] = metaPage("go.multi.example git https://github.com/acme/h", "go.multi.example/lib git https://github.com/acme/h")
	// Tag for another prefix.
	w.Vanity["go.wrong.example/lib"] = vanityPage("go.wrong.example/other", "git", "https://github.com/acme/h")
	// Self-hosted repository over plain http that does not exist.
	w.Vanity["go.repo.example/lib"] = vanityPage("go.repo.example/lib", "git", w.URL+"/git/missing")
	// Self-hosted repository that answers the git smart-HTTP probe.
	w.Vanity["go.repo2.example/lib"] = vanityPage("go.repo2.example/lib", "git", w.URL+"/git/present")
	w.Extra["/git/present/info/refs"] = func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("service") != "git-upload-pack" {
			http.NotFound(rw, r)
			return
		}
		rw.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		rw.Write([]byte("001e# service=git-upload-pack\n0000"))
	}
	// Shorter prefix whose own page disagrees.
	w.Vanity["go.prefix.example/tools/cmd"] = vanityPage("go.prefix.example/tools", "git", "https://github.com/acme/h")
	w.Vanity["go.prefix.example/tools"] = vanityPage("go.prefix.example/tools", "git", "https://github.com/evil/h")
	// Shorter prefix confirmed by its page.
	w.Vanity["go.prefix2.example/tools/cmd"] = vanityPage("go.prefix2.example/tools", "git", "https://github.com/acme/h")
	w.Vanity["go.prefix2.example/tools"] = vanityPage("go.prefix2.example/tools", "git", "https://github.com/acme/h")
	// "mod" entry next to a git entry: the proxy wins and is probed.
	w.AddModule("go.mod.example/lib", "v1.0.0", nil)
	w.Vanity["go.mod.example/lib"] = metaPage("go.mod.example/lib git https://github.com/gone/h", "go.mod.example/lib mod "+w.URL+"/proxy")
	// Unknown VCS; tags served on a 404 page; no tags at all; unreachable.
	w.Vanity["go.vcs.example/lib"] = vanityPage("go.vcs.example/lib", "cvs", "https://cvs.example/lib")
	w.Extra["/vanity/go.404.example/lib"] = func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(404)
		rw.Write([]byte(vanityPage("go.404.example/lib", "git", "https://github.com/acme/h")))
	}
	w.Vanity["go.empty.example/lib"] = "<html><head><title>hi</title></head></html>"
	// A dead domain: no HTTP response and no registration record.
	w.Extra["/vanity/go.dead.example/lib"] = dropConnection

	args := []string{"vanity", "--json",
		"go.http.example/lib", "go.redir.example/lib", "go.multi.example/lib", "go.wrong.example/lib",
		"go.repo.example/lib", "go.repo2.example/lib", "go.prefix.example/tools/cmd", "go.prefix2.example/tools/cmd",
		"go.mod.example/lib", "go.vcs.example/lib", "go.404.example/lib", "go.empty.example/lib", "go.dead.example/lib",
		"github.com/acme/h"}
	r := w.Run("", args...)
	checkEnvelope(t, r, "vanity", 1)
	var res vanityResult
	r.Decode(t, &res)
	if res.Skipped != 1 || res.Summary.Modules != 13 {
		t.Fatalf("modules %d skipped %d", res.Summary.Modules, res.Skipped)
	}
	want := map[string]map[string]string{
		"go.http.example/lib":          {"insecure-http": "high"},
		"go.redir.example/lib":         {"cross-host-redirect": "medium"},
		"go.multi.example/lib":         {"multiple-matches": "high"},
		"go.wrong.example/lib":         {"prefix-mismatch": "high"},
		"go.repo.example/lib":          {"insecure-repo-url": "medium", "repo-unreachable": "high"},
		"go.repo2.example/lib":         {"insecure-repo-url": "medium"},
		"go.prefix.example/tools/cmd":  {"prefix-disagree": "high"},
		"go.prefix2.example/tools/cmd": {},
		"go.mod.example/lib":           {"insecure-repo-url": "medium"}, // the test proxy is http
		"go.vcs.example/lib":           {"unknown-vcs": "high"},
		"go.404.example/lib":           {"error-status": "low"},
		"go.empty.example/lib":         {"no-go-import": "high"},
		"go.dead.example/lib":          {"page-unreachable": "high", "domain-unregistered": "critical"},
	}
	for mod, rs := range want {
		got := rules(res.Findings, mod)
		delete(got, "domain-no-rdap") // no RDAP records in this world
		if len(got) != len(rs) {
			t.Errorf("%s: findings %v, want %v", mod, got, rs)
			continue
		}
		for rule, sev := range rs {
			if got[rule] != sev {
				t.Errorf("%s: %s = %q, want %q", mod, rule, got[rule], sev)
			}
		}
	}
	for _, m := range res.Modules {
		switch m.ImportPath {
		case "go.http.example/lib":
			if m.Page.HTTPS || m.Page.FinalURL != "http://go.http.example/lib?go-get=1" {
				t.Errorf("http page: %+v", m.Page)
			}
		case "go.redir.example/lib":
			if m.Page.RedirectHost != "landing.example" {
				t.Errorf("redirect: %+v", m.Page)
			}
		case "go.mod.example/lib":
			if m.Match == nil || m.Match.VCS != "mod" || m.Repo == nil || m.Repo.Method != "proxy-list" || !m.Repo.Reachable {
				t.Errorf("mod: %+v %+v", m.Match, m.Repo)
			}
		case "go.repo2.example/lib":
			if m.Repo == nil || m.Repo.Method != "git-smart-http" || !m.Repo.Reachable {
				t.Errorf("git probe: %+v", m.Repo)
			}
		case "go.multi.example/lib":
			if !strings.Contains(m.MatchError, "multiple meta tags match") {
				t.Errorf("match error = %q", m.MatchError)
			}
		}
	}
}

func TestVanityNone(t *testing.T) {
	w := testenv.New(t)
	w.AddModule("github.com/acme/plain", "v1.0.0", nil)
	dir := project(w, "github.com/acme/plain@v1.0.0")
	r := w.Run(dir, "vanity", "--json")
	checkEnvelope(t, r, "vanity", 0)
	var res vanityResult
	r.Decode(t, &res)
	if res.Summary.Modules != 0 || res.Skipped != 1 || res.Modules == nil {
		t.Errorf("%+v", res)
	}
	r = w.Run(dir, "vanity")
	if r.Code != 0 || !strings.Contains(r.Stdout, "no vanity import paths") {
		t.Errorf("text: %s", r.Stdout)
	}
}

// metaPage builds a page with one go-import tag per content string.
func metaPage(contents ...string) string {
	var b strings.Builder
	b.WriteString("<html><head>")
	for _, c := range contents {
		b.WriteString(`<meta name="go-import" content="` + c + `">`)
	}
	b.WriteString("</head><body></body></html>")
	return b.String()
}

// dropConnection closes the connection without a response, like a host
// that does not exist.
func dropConnection(rw http.ResponseWriter, r *http.Request) {
	panic(http.ErrAbortHandler)
}
