package compliance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

// radarWorld publishes a project using example.com/dep v1.0.0 (vulnerable,
// fixed in v1.0.1), example.com/ret v1.0.0 (retracted by v1.2.0) and,
// indirectly, example.com/ind v1.0.0, and seeds the module index with new
// versions published in the last hours.
func radarWorld(t *testing.T) (*testenv.World, string, time.Time) {
	t.Helper()
	w := testenv.New(t)
	for _, v := range []string{"v1.0.0", "v1.0.1", "v1.1.0", "v1.2.0-rc.1", "v1.2.0"} {
		w.AddModule("example.com/dep", v, map[string]string{
			"go.mod": testenv.GoModFile("example.com/dep", "1.21", "example.com/ind@v1.0.0"),
			"dep.go": "package dep\n",
		})
	}
	w.AddModule("example.com/dep/v2", "v2.0.0", map[string]string{"dep.go": "package dep\n"})
	for _, v := range []string{"v1.0.0", "v1.0.5"} {
		w.AddModule("example.com/ind", v, map[string]string{"ind.go": "package ind\n"})
	}
	w.AddModule("example.com/ret", "v1.0.0", map[string]string{"ret.go": "package ret\n"})
	w.AddModule("example.com/ret", "v1.1.0", map[string]string{"ret.go": "package ret\n"})
	w.AddModule("example.com/ret", "v1.2.0", map[string]string{"ret.go": "package ret\n",
		"go.mod": "module example.com/ret\n\ngo 1.21\n\nretract [v1.0.0, v1.1.0] // data loss\n"})
	w.AddModule("other.org/x", "v1.0.0", nil)
	w.AddVuln(testenv.SimpleVuln("GO-2025-0100", "example.com/dep", "v1.0.0", "v1.0.1", "example.com/dep", []string{"F"}))

	now := time.Now().UTC()
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	w.AddIndex("example.com/dep", "v1.0.0", ago(48*time.Hour)) // before --since
	w.AddIndex("example.com/dep", "v1.0.1", ago(3*time.Hour))
	w.AddIndex("example.com/dep", "v1.1.0", ago(2*time.Hour))
	w.AddIndex("example.com/dep/v2", "v2.0.0", ago(2*time.Hour)) // same timestamp
	w.AddIndex("example.com/ret", "v1.1.0", ago(100*time.Minute))
	w.AddIndex("example.com/ret", "v1.2.0", ago(90*time.Minute))
	w.AddIndex("example.com/dep", "v1.2.0-rc.1", ago(60*time.Minute))
	w.AddIndex("example.com/ind", "v1.0.5", ago(30*time.Minute))
	w.AddIndex("example.com/dep", "v1.2.1-0.20250101000000-abcdefabcdef", ago(20*time.Minute))
	w.AddIndex("other.org/x", "v1.0.0", ago(10*time.Minute))

	dir := w.Project(map[string]string{
		"go.mod":  testenv.GoModFile("example.com/main", "1.22", "example.com/dep@v1.0.0", "example.com/ret@v1.0.0"),
		"main.go": "package main\n\nfunc main() {}\n",
	})
	return w, dir, now
}

func relMap(res *RadarResult) map[string]*RadarRelease {
	m := map[string]*RadarRelease{}
	for _, r := range res.Releases {
		m[r.Module+"@"+r.Version] = r
	}
	return m
}

func TestRadarClassify(t *testing.T) {
	w, dir, _ := radarWorld(t)
	r := w.Run(dir, "radar", "--json")
	if r.Code != 1 {
		t.Fatalf("exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	var res RadarResult
	r.Decode(t, &res)
	got := relMap(&res)
	type want struct {
		kind                         string
		pre, retracted, curRetracted bool
		fixes                        string
		sev                          string
	}
	wants := map[string]want{
		"example.com/dep@v1.0.1":      {kind: "patch", fixes: "GO-2025-0100", sev: "high"},
		"example.com/dep@v1.1.0":      {kind: "minor", fixes: "GO-2025-0100", sev: "high"},
		"example.com/dep@v1.2.0-rc.1": {kind: "minor", pre: true, fixes: "GO-2025-0100", sev: "high"},
		"example.com/dep/v2@v2.0.0":   {kind: "major", sev: "low"},
		"example.com/ret@v1.1.0":      {kind: "minor", retracted: true, curRetracted: true, sev: "medium"},
		"example.com/ret@v1.2.0":      {kind: "minor", curRetracted: true, sev: "medium"},
	}
	if len(got) != len(wants) {
		t.Errorf("got %d releases, want %d: %v", len(got), len(wants), keysOf(got))
	}
	for k, wv := range wants {
		g := got[k]
		if g == nil {
			t.Errorf("missing release %s", k)
			continue
		}
		if g.Kind != wv.kind || g.Prerelease != wv.pre || g.Retracted != wv.retracted || g.CurrentRetracted != wv.curRetracted ||
			strings.Join(g.Fixes, ",") != wv.fixes || g.Severity.String() != wv.sev {
			t.Errorf("%s: %+v, want %+v", k, g, wv)
		}
	}
	if g := got["example.com/dep/v2@v2.0.0"]; g != nil && (!g.NewMajorPath || g.Tracked != "example.com/dep" || g.Current != "v1.0.0") {
		t.Errorf("v2 path: %+v", g)
	}
	if res.Skipped != 1 || res.Tracked != 2 || res.Failing != 3 || res.Polls != 1 || !res.Complete || res.Entries != 9 {
		t.Errorf("result: skipped=%d tracked=%d failing=%d polls=%d complete=%v entries=%d", res.Skipped, res.Tracked, res.Failing, res.Polls, res.Complete, res.Entries)
	}
	rules := map[string]int{}
	for _, f := range res.Findings {
		rules[f.Rule]++
	}
	if rules["radar-vuln-fix"] != 1 || rules["radar-current-retracted"] != 1 {
		t.Errorf("findings: %v", rules)
	}
	for _, f := range res.Findings {
		if f.Rule == "radar-vuln-fix" && (f.Fix != "go get example.com/dep@v1.0.1" || f.Detail != "fixed in v1.0.1, v1.1.0, v1.2.0-rc.1") {
			t.Errorf("vuln finding: %+v", f)
		}
		if f.Rule == "radar-current-retracted" && (f.Fix != "go get example.com/ret@v1.2.0" || f.Detail != "rationale: data loss") {
			t.Errorf("retraction finding: %+v", f)
		}
	}

	// --all adds the indirect dependency; --pseudo the pseudo-version.
	r = w.Run(dir, "radar", "--all", "--pseudo", "--json")
	res = RadarResult{}
	r.Decode(t, &res)
	got = relMap(&res)
	if g := got["example.com/ind@v1.0.5"]; g == nil || g.Kind != "patch" || g.Direct {
		t.Errorf("--all: %+v", g)
	}
	if g := got["example.com/dep@v1.2.1-0.20250101000000-abcdefabcdef"]; g == nil || g.Kind != "pseudo" || g.Prerelease {
		t.Errorf("--pseudo: %+v", g)
	}

	// Explicit modules and patterns; --since as a time.
	r = w.Run(dir, "radar", "other.org/...", "example.com/ret@v1.1.0", "--since", time.Now().Add(-95*time.Minute).UTC().Format(time.RFC3339), "--json")
	res = RadarResult{}
	r.Decode(t, &res)
	got = relMap(&res)
	if r.Code != 0 || len(got) != 2 || got["other.org/x@v1.0.0"] == nil || got["other.org/x@v1.0.0"].Kind != "new" ||
		got["example.com/ret@v1.2.0"] == nil || got["example.com/ret@v1.2.0"].Current != "v1.1.0" {
		t.Errorf("explicit: exit %d %v", r.Code, keysOf(got))
	}

	// Outside a module, explicit paths still work.
	r = w.Run(t.TempDir(), "radar", "example.com/dep@v1.0.0", "--json")
	res = RadarResult{}
	r.Decode(t, &res)
	if r.Code != 1 || relMap(&res)["example.com/dep@v1.0.1"] == nil {
		t.Errorf("no module: exit %d %v", r.Code, keysOf(relMap(&res)))
	}

	r = w.Run(dir, "radar")
	mustContain(t, "text output", r.Stdout, "sm-go radar · example.com/main", "example.com/dep", "fixes GO-2025-0100", "major (new path)", "retracted")

	for _, args := range [][]string{{"--since", "yesterday"}, {"--follow", "--interval", "0s"}, {"--page-size", "5000"}, {"example.com/x@1.0"}} {
		if r := w.Run(dir, append([]string{"radar"}, args...)...); r.Code != 2 {
			t.Errorf("%v: exit %d", args, r.Code)
		}
	}
	if r := w.Run(t.TempDir(), "radar"); r.Code != 2 {
		t.Errorf("no module, no args: exit %d", r.Code)
	}
}

func keysOf(m map[string]*RadarRelease) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

// TestRadarPaging reads the index two entries at a time: entries sharing
// a timestamp across a page boundary must be seen exactly once.
func TestRadarPaging(t *testing.T) {
	w, dir, _ := radarWorld(t)
	r := w.Run(dir, "radar", "--all", "--pseudo", "--page-size", "2", "--json")
	var res RadarResult
	r.Decode(t, &res)
	if res.Entries != 9 || len(res.Releases) != 8 || !res.Complete {
		t.Errorf("entries %d releases %d complete %v: %v", res.Entries, len(res.Releases), res.Complete, keysOf(relMap(&res)))
	}
	pages := 0
	for _, q := range w.Requests {
		if strings.Contains(q, "/index/index?") {
			pages++
		}
	}
	if pages < 5 {
		t.Errorf("only %d index requests with --page-size 2", pages)
	}

	// A full page of entries sharing one timestamp does not loop forever.
	w2 := testenv.New(t)
	ts := time.Now().Add(-time.Hour)
	for _, v := range []string{"v1.0.1", "v1.0.2", "v1.0.3"} {
		w2.AddIndex("example.com/same", v, ts)
	}
	w2.AddIndex("example.com/same", "v1.0.4", ts.Add(time.Minute))
	r = w2.Run(t.TempDir(), "radar", "example.com/same@v1.0.0", "--page-size", "3", "--json")
	res = RadarResult{}
	r.Decode(t, &res)
	if len(res.Releases) != 4 || !res.Complete {
		t.Errorf("same timestamp: %v complete=%v\n%s", keysOf(relMap(&res)), res.Complete, r.Stderr)
	}
}

func TestRadarFollowStateAlerts(t *testing.T) {
	w, dir, now := radarWorld(t)
	state := filepath.Join(t.TempDir(), "radar.json")
	slack, hook := w.HookURL("slack"), w.HookURL("generic")
	args := []string{"radar", "--follow", "--polls", "2", "--interval", "10ms", "--state", state, "--slack", slack, "--json"}
	extra := []string{"SMGO_WEBHOOK_URL=" + hook}

	r := w.RunEnv(dir, extra, args...)
	if r.Code != 1 {
		t.Fatalf("first run: exit %d\n%s", r.Code, r.Stderr)
	}
	var res RadarResult
	r.Decode(t, &res)
	if res.Polls != 2 || len(res.Releases) != 6 || res.Alerts != 1 {
		t.Errorf("first run: polls %d releases %d alerts %d", res.Polls, len(res.Releases), res.Alerts)
	}
	if n := len(w.Hook("slack").Bodies); n != 1 {
		t.Fatalf("slack received %d messages, want 1 (nothing new on the second poll)", n)
	}
	var sl struct{ Text string }
	if err := json.Unmarshal(w.Hook("slack").Bodies[0], &sl); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "slack text", sl.Text, "sm-go radar: 6 new releases for example.com/main",
		"• example.com/dep v1.0.0 → v1.0.1 (patch; fixes GO-2025-0100)", "example.com/dep/v2 v2.0.0 (new major version path of example.com/dep)",
		"example.com/ret v1.0.0 → v1.1.0 (minor; retracted; retracts v1.0.0)")
	var gen struct {
		Source, Title, Severity string
		Data                    []RadarRelease
	}
	if err := json.Unmarshal(w.Hook("generic").Bodies[0], &gen); err != nil {
		t.Fatal(err)
	}
	if gen.Source != "sm-go" || gen.Severity != "high" || len(gen.Data) != 6 {
		t.Errorf("webhook payload: %+v", gen)
	}
	st := readFile(t, state)
	var saved radarState
	if err := json.Unmarshal([]byte(st), &saved); err != nil {
		t.Fatal(err)
	}
	// The cursor is the newest index entry, even an unwatched one.
	if want := now.Add(-10 * time.Minute); !saved.Cursor.Equal(want) || len(saved.Seen) != 1 || saved.Seen[0] != "other.org/x@v1.0.0" {
		t.Errorf("state: %s", st)
	}

	// Restart: nothing is repeated, only the new release is reported.
	w.AddIndex("example.com/dep", "v1.2.0", now.Add(-time.Minute))
	r = w.RunEnv(dir, extra, args...)
	res = RadarResult{}
	r.Decode(t, &res)
	if r.Code != 1 || len(res.Releases) != 1 || res.Releases[0].Version != "v1.2.0" || res.Releases[0].Kind != "minor" {
		t.Errorf("restart: exit %d %v", r.Code, keysOf(relMap(&res)))
	}
	if n := len(w.Hook("slack").Bodies); n != 2 {
		t.Fatalf("slack received %d messages, want 2", n)
	}
	if err := json.Unmarshal(w.Hook("slack").Bodies[1], &sl); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "second alert", sl.Text, "1 new release", "example.com/dep v1.0.0 → v1.2.0 (minor; fixes GO-2025-0100)")
	if strings.Contains(sl.Text, "v1.0.1") {
		t.Errorf("second alert repeats old releases:\n%s", sl.Text)
	}

	// Nothing new: no alert, exit 0.
	r = w.RunEnv(dir, extra, "radar", "--state", state, "--slack", slack, "--json")
	if r.Code != 0 || len(w.Hook("slack").Bodies) != 2 {
		t.Errorf("idle run: exit %d, %d slack messages", r.Code, len(w.Hook("slack").Bodies))
	}

	// --alert-on filters what is sent; a failing webhook keeps the cursor.
	w.AddIndex("example.com/dep/v2", "v2.0.1", now.Add(-30*time.Second))
	before := readFile(t, state)
	r = w.RunEnv(dir, nil, "radar", "--state", state, "--webhook", w.URL+"/missing-hook", "--json")
	if r.Code != 0 || readFile(t, state) != before || !strings.Contains(r.Stdout, "next run retries") {
		t.Errorf("failed alert: exit %d, state changed=%v\n%s", r.Code, readFile(t, state) != before, r.Stdout)
	}
	r = w.RunEnv(dir, nil, "radar", "--state", state, "--slack", slack, "--alert-on", "medium", "--json")
	res = RadarResult{}
	r.Decode(t, &res)
	if len(res.Releases) != 1 || res.Alerts != 0 || len(w.Hook("slack").Bodies) != 2 || readFile(t, state) == before {
		t.Errorf("alert-on medium: releases %d alerts %d slack %d", len(res.Releases), res.Alerts, len(w.Hook("slack").Bodies))
	}

	// The default state path lives in the cache directory.
	r = w.Run(dir, "radar", "--follow", "--polls", "1", "--json")
	res = RadarResult{}
	r.Decode(t, &res)
	if !strings.HasPrefix(res.State, filepath.Join(w.CacheDir, "radar")) {
		t.Errorf("default state %q", res.State)
	}
	if _, err := os.Stat(res.State); err != nil {
		t.Error(err)
	}
}

func TestParseSince(t *testing.T) {
	now := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Time{
		"24h":                  now.Add(-24 * time.Hour),
		"7d":                   now.Add(-7 * 24 * time.Hour),
		"1d12h":                now.Add(-36 * time.Hour),
		"2025-06-01":           time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
		"2025-06-01T10:00:00Z": time.Date(2025, 6, 1, 10, 0, 0, 0, time.UTC),
	} {
		got, err := parseSince(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("parseSince(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "x", "-1h", "0d"} {
		if _, err := parseSince(bad, now); err == nil {
			t.Errorf("parseSince(%q) accepted", bad)
		}
	}
}
