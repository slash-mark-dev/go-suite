package origin_test

import (
	"strings"
	"testing"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

type takeoverResult struct {
	Subject string `json:"subject"`
	Modules []struct {
		Path    string `json:"path"`
		Version string `json:"version"`
		Direct  bool   `json:"direct"`
		Status  string `json:"status"`
		Repo    *struct {
			Host  string `json:"host"`
			Owner string `json:"owner"`
			Name  string `json:"name"`
			URL   string `json:"url"`
		} `json:"repo"`
		GitHub *struct {
			Found    bool   `json:"found"`
			Moved    bool   `json:"moved"`
			FullName string `json:"fullName"`
		} `json:"github"`
		Domains []struct {
			Name string `json:"name"`
		} `json:"domains"`
	} `json:"modules"`
	Findings []finding `json:"findings"`
	Summary  struct {
		Modules   int `json:"modules"`
		AtRisk    int `json:"atRisk"`
		Unchecked int `json:"unchecked"`
		Critical  int `json:"critical"`
	} `json:"summary"`
}

func takeoverWorld(t *testing.T) (*testenv.World, string) {
	w := testenv.New(t)
	now := time.Now()
	w.AddModule("github.com/acme/ok", "v1.0.0", map[string]string{
		"go.mod": testenv.GoModFile("github.com/acme/ok", "1.21", "github.com/acme/indirect@v1.0.0"),
	})
	w.AddModule("github.com/acme/indirect", "v1.0.0", nil)
	w.AddModule("github.com/gone/lib", "v1.0.0", nil)
	w.AddModule("github.com/oldname/moved", "v1.2.0", nil)
	w.AddModule("github.com/acme/renamed", "v1.0.0", nil)
	w.AddModule("github.com/acme/archived", "v1.0.0", nil)
	w.AddModule("github.com/acme/recreated", "v1.0.0", nil)
	w.AddModule("go.expired.example/tool", "v0.3.0", nil)
	w.AddModule("go.fine.example/tool", "v0.1.0", nil)

	w.GitHubRepo("acme", "ok", nil)
	w.GitHubRepo("acme", "indirect", nil)
	w.GitHubRepo("acme", "archived", map[string]any{"archived": true})
	w.GitHubRepo("acme", "recreated", map[string]any{"created_at": "2025-06-01T00:00:00Z"})
	// github.com/gone/lib: neither the repo nor the account exists.
	// oldname/moved was transferred to newowner and the login "oldname" is free.
	w.GitHubRepo("newowner", "moved", nil)
	w.GitHubRedirect["repos/oldname/moved"] = "repos/newowner/moved"
	// acme/renamed was renamed within the same account.
	w.GitHubRepo("acme", "renamed-lib", nil)
	w.GitHubRedirect["repos/acme/renamed"] = "repos/acme/renamed-lib"
	w.GitHubRepo("acme", "tool", nil)
	w.GitHubRepo("acme", "fine", nil)

	w.Vanity["go.expired.example/tool"] = vanityPage("go.expired.example/tool", "git", "https://github.com/acme/tool")
	w.Vanity["go.fine.example/tool"] = vanityPage("go.fine.example/tool", "git", "https://github.com/acme/fine")
	rdap(w, "expired.example", now.Add(-48*time.Hour))
	rdap(w, "fine.example", now.Add(400*24*time.Hour))

	dir := project(w, "github.com/acme/ok@v1.0.0", "github.com/gone/lib@v1.0.0", "github.com/oldname/moved@v1.2.0",
		"github.com/acme/renamed@v1.0.0", "github.com/acme/archived@v1.0.0", "github.com/acme/recreated@v1.0.0",
		"go.expired.example/tool@v0.3.0", "go.fine.example/tool@v0.1.0")
	return w, dir
}

func TestTakeover(t *testing.T) {
	w, dir := takeoverWorld(t)
	r := w.Run(dir, "takeover", "--json")
	checkEnvelope(t, r, "takeover", 1)
	var res takeoverResult
	r.Decode(t, &res)
	if res.Subject != "example.com/main" || res.Summary.Modules != 9 {
		t.Fatalf("subject/modules: %+v", res.Summary)
	}
	want := map[string]map[string]string{
		"github.com/gone/lib":       {"owner-deleted": "critical"},
		"github.com/oldname/moved":  {"owner-renamed": "critical"},
		"github.com/acme/renamed":   {"repo-renamed": "low"},
		"github.com/acme/archived":  {"repo-archived": "medium"},
		"github.com/acme/recreated": {"repo-recreated": "high"},
		"go.expired.example/tool":   {"domain-expired": "critical"},
		"github.com/acme/ok":        {},
		"github.com/acme/indirect":  {},
		"go.fine.example/tool":      {},
	}
	for mod, rs := range want {
		got := rules(res.Findings, mod)
		if len(got) != len(rs) {
			t.Errorf("%s: findings %v, want %v", mod, got, rs)
			continue
		}
		for rule, sev := range rs {
			if got[rule] != sev {
				t.Errorf("%s: rule %s = %q, want %q (all: %v)", mod, rule, got[rule], sev, got)
			}
		}
	}
	if res.Summary.AtRisk != 6 || res.Summary.Critical != 3 {
		t.Errorf("summary = %+v", res.Summary)
	}
	for _, m := range res.Modules {
		switch m.Path {
		case "github.com/oldname/moved":
			if m.GitHub == nil || !m.GitHub.Moved || m.GitHub.FullName != "newowner/moved" || m.Status != "risk" {
				t.Errorf("moved: %+v", m.GitHub)
			}
		case "go.fine.example/tool":
			if m.Repo == nil || m.Repo.Host != "vanity" || m.Repo.Owner != "acme" || len(m.Domains) != 1 || m.Domains[0].Name != "fine.example" || m.Status != "ok" {
				t.Errorf("vanity module: %+v", m)
			}
		case "github.com/acme/indirect":
			if m.Direct {
				t.Errorf("indirect marked direct")
			}
		}
	}

	// --direct drops the indirect dependency; --fail-on critical still fails.
	r = w.Run(dir, "takeover", "--direct", "--fail-on", "critical", "--json")
	checkEnvelope(t, r, "takeover", 1)
	r.Decode(t, &res)
	if res.Summary.Modules != 8 {
		t.Errorf("--direct modules = %d", res.Summary.Modules)
	}

	// Text output.
	r = w.Run(dir, "takeover")
	if r.Code != 1 || !strings.Contains(r.Stdout, "Repo takeover risk") || !strings.Contains(r.Stdout, `GitHub account "gone" does not exist`) {
		t.Errorf("text output (code %d):\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
}

func TestTakeoverClean(t *testing.T) {
	w, _ := takeoverWorld(t)
	r := w.Run("", "takeover", "github.com/acme/ok", "go.fine.example/tool@v0.1.0", "--json")
	checkEnvelope(t, r, "takeover", 0)
	var res takeoverResult
	r.Decode(t, &res)
	if len(res.Findings) != 0 || res.Summary.Modules != 2 {
		t.Fatalf("unexpected: %+v", res)
	}
	// Low findings stay below the default threshold.
	r = w.Run("", "takeover", "github.com/acme/renamed@v1.0.0", "--json")
	checkEnvelope(t, r, "takeover", 0)
	r = w.Run("", "takeover", "github.com/acme/renamed@v1.0.0", "--fail-on", "low", "--json")
	checkEnvelope(t, r, "takeover", 1)
	r = w.Run("", "takeover", "github.com/acme/ok")
	if r.Code != 0 || !strings.Contains(r.Stdout, "no takeover risks found") {
		t.Errorf("text: %s", r.Stdout)
	}
}

func TestTakeoverVanityDomain(t *testing.T) {
	w := testenv.New(t)
	now := time.Now()
	// Vanity page gone and the domain is unregistered: claimable.
	w.Extra["/vanity/go.unregistered.example/lib"] = dropConnection
	// Vanity page resolving, domain expiring in 3 days.
	w.Vanity["go.soon.example/x"] = vanityPage("go.soon.example/x", "git", "https://git.soon.example/x")
	rdap(w, "soon.example", now.Add(3*24*time.Hour+time.Hour))
	// Self-hosted repo on another, expired domain.
	w.Vanity["go.ok.example/y"] = vanityPage("go.ok.example/y", "git", "https://code.lapsed.example/y")
	rdap(w, "ok.example", now.Add(300*24*time.Hour))
	rdap(w, "lapsed.example", now.Add(-time.Hour), "redemption period")
	r := w.Run("", "takeover", "go.unregistered.example/lib", "go.soon.example/x", "go.ok.example/y", "--json")
	checkEnvelope(t, r, "takeover", 1)
	var res takeoverResult
	r.Decode(t, &res)
	got := rules(res.Findings, "go.unregistered.example/lib")
	if got["domain-unregistered"] != "critical" || got["vanity-unresolvable"] != "high" {
		t.Errorf("unregistered: %v", got)
	}
	got = rules(res.Findings, "go.soon.example/x")
	if got["domain-expiring"] != "high" || len(got) != 1 {
		t.Errorf("expiring: %v", got)
	}
	got = rules(res.Findings, "go.ok.example/y")
	if got["domain-expired"] != "critical" || len(got) != 1 {
		t.Errorf("repo domain: %v", got)
	}
	for _, f := range res.Findings {
		if f.Module == "go.ok.example/y" && !strings.Contains(f.Title, "repository domain lapsed.example") {
			t.Errorf("title = %q", f.Title)
		}
	}
}

func TestTakeoverGitHubDown(t *testing.T) {
	w := testenv.New(t)
	w.AddModule("github.com/acme/ok", "v1.0.0", nil)
	// GitHub being unreachable degrades to a warning; the module is unchecked.
	r := w.RunEnv("", []string{"SMGO_GITHUB_API_URL=http://127.0.0.1:1/github", "SMGO_CACHE_DIR=" + t.TempDir()}, "takeover", "github.com/acme/ok", "--json", "--timeout", "2s")
	checkEnvelope(t, r, "takeover", 0)
	var res takeoverResult
	r.Decode(t, &res)
	env := r.JSON(t)
	if res.Summary.Unchecked != 1 || env["warnings"] == nil {
		t.Errorf("degraded: %+v %v", res.Summary, env["warnings"])
	}
}
