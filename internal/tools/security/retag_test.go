package security_test

import (
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

type retagJSON struct {
	Checks []struct {
		Module         string `json:"module"`
		Version        string `json:"version"`
		Repo           string `json:"repo"`
		Subdir         string `json:"subdir"`
		Tag            string `json:"tag"`
		RecordedCommit string `json:"recordedCommit"`
		CurrentCommit  string `json:"currentCommit"`
		Method         string `json:"method"`
		ExpectedHash   string `json:"expectedHash"`
		CurrentHash    string `json:"currentHash"`
		HashSource     string `json:"hashSource"`
		Status         string `json:"status"`
		Severity       string `json:"severity"`
		Detail         string `json:"detail"`
	} `json:"checks"`
	Summary  map[string]int `json:"summary"`
	Findings []struct {
		Severity string `json:"severity"`
		Rule     string `json:"rule"`
		Module   string `json:"module"`
	} `json:"findings"`
	Failing int `json:"failing"`
}

func (r *retagJSON) get(t *testing.T, mod string) int {
	t.Helper()
	for i, c := range r.Checks {
		if c.Module == mod {
			return i
		}
	}
	t.Fatalf("no check for %s", mod)
	return -1
}

func sha(c byte) string { return strings.Repeat(string(c), 40) }

func retagWorld(t *testing.T) (*testenv.World, string) {
	w := testenv.New(t)
	origin := func(repo, tag, hash string) map[string]string {
		return map[string]string{"VCS": "git", "URL": "https://github.com/" + repo, "Ref": "refs/tags/" + tag, "Hash": hash}
	}
	var reqs []string
	add := func(path, version string, files map[string]string) *testenv.Mod {
		reqs = append(reqs, path+"@"+version)
		return w.AddModule(path, version, files)
	}
	// Proxy recorded the origin; the tag is unchanged.
	add("github.com/acme/tool", "v1.0.0", nil).Origin = origin("acme/tool", "v1.0.0", sha('a'))
	w.GitHubRepo("acme", "tool", nil)
	w.GitHubTag("acme", "tool", "v1.0.0", sha('a'))
	// The tag was moved.
	add("github.com/acme/moved", "v1.2.0", nil).Origin = origin("acme/moved", "v1.2.0", sha('b'))
	w.GitHubRepo("acme", "moved", nil)
	w.GitHubTag("acme", "moved", "v1.2.0", sha('c'))
	// The tag was deleted.
	add("github.com/acme/gone", "v1.0.0", nil).Origin = origin("acme/gone", "v1.0.0", sha('d'))
	w.GitHubRepo("acme", "gone", nil)
	// No origin recorded: content check against the checksum database.
	same := map[string]string{"x.go": "package notag\n\nfunc X() {}\n"}
	add("github.com/acme/notag", "v1.1.0", same)
	w.GitHubRepo("acme", "notag", nil)
	w.GitHubTag("acme", "notag", "v1.1.0", sha('e'))
	w.GitHubZipball("acme", "notag", sha('e'), map[string]string{
		"go.mod":           "module github.com/acme/notag\n\ngo 1.21\n",
		"x.go":             "package notag\n\nfunc X() {}\n",
		"vendor/v/v.go":    "package v\n",
		"tools/go.mod":     "module github.com/acme/notag/tools\n",
		"tools/t.go":       "package tools\n",
		".hg_archival.txt": "repo: x\n",
	})
	// No origin, tag re-pointed at different content.
	add("github.com/acme/swapped", "v1.0.0", map[string]string{"x.go": "package swapped\n"})
	w.GitHubRepo("acme", "swapped", nil)
	w.GitHubTag("acme", "swapped", "v1.0.0", sha('f'))
	w.GitHubZipball("acme", "swapped", sha('f'), map[string]string{
		"go.mod": "module github.com/acme/swapped\n\ngo 1.21\n",
		"x.go":   "package swapped\n\nfunc init() { steal() }\n\nfunc steal() {}\n",
	})
	// Module in a subdirectory, in its major-version directory, with the
	// repository root LICENSE.
	add("github.com/acme/mono/sub/v2", "v2.1.0", map[string]string{
		"go.mod":  "module github.com/acme/mono/sub/v2\n\ngo 1.21\n",
		"s.go":    "package sub\n",
		"LICENSE": "MIT License\n",
		// x/mod/zip keeps vendor/modules.txt but drops vendored packages.
		"vendor/modules.txt": "# vendored\n",
	})
	w.GitHubRepo("acme", "mono", nil)
	w.GitHubTag("acme", "mono", "sub/v2.1.0", sha('1'))
	w.GitHubZipball("acme", "mono", sha('1'), map[string]string{
		"LICENSE":                   "MIT License\n",
		"README.md":                 "mono\n",
		"sub/go.mod":                "module github.com/acme/mono/sub\n\ngo 1.21\n",
		"sub/old.go":                "package sub\n",
		"sub/v2/go.mod":             "module github.com/acme/mono/sub/v2\n\ngo 1.21\n",
		"sub/v2/s.go":               "package sub\n",
		"sub/v2/nested/go.mod":      "module github.com/acme/mono/sub/v2/nested\n",
		"sub/v2/nested/n.go":        "package nested\n",
		"sub/v2/vendor/x/x.go":      "package x\n",
		"sub/v2/vendor/modules.txt": "# vendored\n",
	})
	// Pseudo-versions: one commit exists, one is gone.
	add("github.com/acme/pseudo", "v0.0.0-20250101000000-abcdefabcdef", nil)
	w.GitHubRepo("acme", "pseudo", nil)
	w.GitHub["repos/acme/pseudo/commits/abcdefabcdef"] = map[string]any{"sha": "abcdefabcdef" + strings.Repeat("0", 28)}
	add("github.com/acme/rewritten", "v0.0.0-20250101000000-123456123456", nil)
	w.GitHubRepo("acme", "rewritten", nil)
	// Vanity path whose origin is on GitHub.
	add("example.org/van", "v1.0.0", nil).Origin = origin("acme/van", "v1.0.0", sha('9'))
	w.GitHubRepo("acme", "van", nil)
	w.GitHubTag("acme", "van", "v1.0.0", sha('9'))
	// Not on GitHub at all.
	add("example.com/elsewhere", "v1.0.0", nil)

	var imports strings.Builder
	dir := w.Project(map[string]string{
		"go.mod": testenv.GoModFile("example.com/app", "1.22", reqs...),
		"app.go": "package app\n" + imports.String(),
	})
	mustDownload(t, w, dir)
	return w, dir
}

func TestRetag(t *testing.T) {
	w, dir := retagWorld(t)
	r := w.Run(dir, "retag", "--json")
	expectCode(t, r, 1)
	var res retagJSON
	r.Decode(t, &res)
	want := map[string][3]string{ // status, method, severity
		"github.com/acme/tool":        {"ok", "origin", "none"},
		"github.com/acme/moved":       {"moved", "origin", "high"},
		"github.com/acme/gone":        {"deleted", "", "medium"},
		"github.com/acme/notag":       {"ok", "content", "none"},
		"github.com/acme/swapped":     {"moved", "content", "high"},
		"github.com/acme/mono/sub/v2": {"ok", "content", "none"},
		"github.com/acme/pseudo":      {"ok", "commit", "none"},
		"github.com/acme/rewritten":   {"commit-missing", "commit", "medium"},
		"example.org/van":             {"ok", "origin", "none"},
		"example.com/elsewhere":       {"skipped", "", "none"},
	}
	if len(res.Checks) != len(want) {
		t.Fatalf("%d checks, want %d", len(res.Checks), len(want))
	}
	for mod, w := range want {
		c := res.Checks[res.get(t, mod)]
		if c.Status != w[0] || c.Method != w[1] || c.Severity != w[2] {
			t.Errorf("%s: status=%s method=%s severity=%s detail=%q, want %v", mod, c.Status, c.Method, c.Severity, c.Detail, w)
		}
	}
	mv := res.Checks[res.get(t, "github.com/acme/moved")]
	if mv.RecordedCommit != sha('b') || mv.CurrentCommit != sha('c') || mv.Tag != "v1.2.0" {
		t.Errorf("moved: %+v", mv)
	}
	sw := res.Checks[res.get(t, "github.com/acme/swapped")]
	if sw.HashSource != "checksum database" || sw.ExpectedHash == "" || sw.CurrentHash == "" || sw.ExpectedHash == sw.CurrentHash {
		t.Errorf("swapped: %+v", sw)
	}
	mono := res.Checks[res.get(t, "github.com/acme/mono/sub/v2")]
	if mono.Tag != "sub/v2.1.0" || mono.Subdir != "sub" || mono.ExpectedHash != mono.CurrentHash {
		t.Errorf("mono: %+v", mono)
	}
	van := res.Checks[res.get(t, "example.org/van")]
	if van.Repo != "acme/van" {
		t.Errorf("vanity repo = %q", van.Repo)
	}
	if res.Failing != 2 || len(res.Findings) != 4 || res.Findings[0].Severity != "high" {
		t.Errorf("failing=%d findings=%+v", res.Failing, res.Findings)
	}

	r = w.Run(dir, "retag", "--json", "--fail-on", "medium")
	res = retagJSON{}
	r.Decode(t, &res)
	if res.Failing != 4 {
		t.Errorf("--fail-on medium: failing = %d", res.Failing)
	}
	r = w.Run(dir, "retag", "--json", "--no-content")
	res = retagJSON{}
	r.Decode(t, &res)
	if c := res.Checks[res.get(t, "github.com/acme/swapped")]; c.Status != "unverified" {
		t.Errorf("--no-content: swapped status %s", c.Status)
	}
	r = w.Run(dir, "retag")
	expectCode(t, r, 1)
	contains(t, r.Stdout, "tag v1.2.0 was moved")
	contains(t, r.Stdout, "GitHub tags")
}

func TestRetagArgsAndOffline(t *testing.T) {
	w, dir := retagWorld(t)
	empty := t.TempDir()
	r := w.Run(empty, "retag", "--json", "github.com/acme/moved@v1.2.0", "github.com/acme/tool@v1.0.0")
	expectCode(t, r, 1)
	var res retagJSON
	r.Decode(t, &res)
	if len(res.Checks) != 2 || res.Summary["moved"] != 1 || res.Summary["ok"] != 1 {
		t.Errorf("args: %+v", res)
	}
	r = w.Run(empty, "retag", "github.com/acme/moved")
	expectCode(t, r, 2)

	// GitHub unreachable: everything degrades to unverified, exit 0.
	r = w.RunEnv(dir, []string{"SMGO_GITHUB_API_URL=http://127.0.0.1:1"}, "retag", "--json", "--timeout", "2s")
	expectCode(t, r, 0)
	res = retagJSON{}
	r.Decode(t, &res)
	if res.Summary["unverified"] != 9 || res.Summary["skipped"] != 1 {
		t.Errorf("offline summary = %v", res.Summary)
	}
	if !strings.Contains(r.Stdout, `"warnings"`) {
		t.Errorf("no warnings in envelope")
	}
}
