package upgrade_test

import (
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/testenv"
	"github.com/slash-mark-dev/go-suite/internal/tools/upgrade"
)

// localGo is the version of the go command running the tests ("1.24.7").
func localGo(t *testing.T) string {
	v := strings.TrimPrefix(runtime.Version(), "go")
	if strings.HasPrefix(v, "devel") {
		t.Skip("devel toolchain")
	}
	return v
}

// toolchainWorld publishes releases around the local Go version L
// (1.L.x): the local line and the next one are supported, the line before
// is not; a newer patch of the local line exists.
func toolchainWorld(t *testing.T) (*testenv.World, string) {
	w := testenv.New(t)
	lv := localGo(t)
	parts := strings.Split(lv, ".")
	minor := atoi(parts[1])
	patch := 0
	if len(parts) > 2 {
		patch = atoi(parts[2])
	}
	line := func(m int) string { return "go1." + itoa(m) }
	w.GoReleases = []map[string]any{
		{"version": line(minor+2) + "rc1", "stable": false},
		{"version": line(minor+1) + ".1", "stable": true},
		{"version": line(minor+1) + ".0", "stable": true},
		{"version": line(minor) + "." + itoa(patch+2), "stable": true},
		{"version": "go" + lv, "stable": true},
		{"version": line(minor-1) + ".12", "stable": true},
	}
	w.AddModule("example.com/dep", "v1.0.0", map[string]string{"go.mod": "module example.com/dep\n\ngo 1.22\n", "dep.go": "package dep\n"})
	w.AddModule("example.com/mid", "v1.0.0", map[string]string{"go.mod": testenv.GoModFile("example.com/mid", "1.20", "example.com/dep@v1.0.0"), "mid.go": "package mid\n"})
	w.AddModule("example.com/future", "v1.0.0", map[string]string{"go.mod": "module example.com/future\n\ngo 1.99\n", "f.go": "package future\n"})
	return w, lv
}

func itoa(n int) string { return strconv.Itoa(n) }

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func rules(fs []report.Finding) map[string]report.Finding {
	m := map[string]report.Finding{}
	for _, f := range fs {
		m[f.Rule] = f
	}
	return m
}

func TestToolchainDepsAndVulns(t *testing.T) {
	w, lv := toolchainWorld(t)
	w.AddVuln(testenv.SimpleVuln("GO-2025-1000", "stdlib", "v1.0.0", "v1.999.0", "net/http", []string{"Serve"}))
	w.AddVuln(testenv.SimpleVuln("GO-2025-1001", "toolchain", "v1.0.0", "v1.999.0", "cmd/go", nil))
	w.AddVuln(testenv.SimpleVuln("GO-2025-1002", "stdlib", "v1.0.0", "v1.1.0", "fmt", nil)) // not affecting
	dir := w.Project(map[string]string{"go.mod": testenv.GoModFile("example.com/app", "1.21", "example.com/mid@v1.0.0")})
	r := w.Run(dir, "toolchain", "--json")
	if r.Code != 1 {
		t.Fatalf("exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	var res upgrade.ToolchainResult
	r.Decode(t, &res)
	if res.Go != "1.21" || res.DepsMaxGo != "1.22" || res.DepsMaxBy != "example.com/dep@v1.0.0" || res.Required != "1.22" {
		t.Fatalf("result %+v", res)
	}
	if strings.Join(res.DepsChain, " ") != "example.com/app example.com/mid@v1.0.0 example.com/dep@v1.0.0" {
		t.Fatalf("chain %v", res.DepsChain)
	}
	if res.Selected != "go"+lv || res.GOTOOLCHAIN != "local" || res.Fails || res.SelectedOK == nil || !*res.SelectedOK {
		t.Fatalf("selection %+v", res)
	}
	if len(res.StdlibVulns) != 2 {
		t.Fatalf("stdlib vulns %+v", res.StdlibVulns)
	}
	got := rules(res.Findings)
	for _, rule := range []string{"go-directive-behind-deps", "go-patch-available", "stdlib-vuln"} {
		if _, ok := got[rule]; !ok {
			t.Errorf("missing finding %s: %+v", rule, res.Findings)
		}
	}
	if len(res.Supported) != 2 {
		t.Fatalf("supported %v", res.Supported)
	}
	// Text output.
	r = w.Run(dir, "toolchain")
	for _, s := range []string{"Toolchain readiness", "GO-2025-1000", "go get go@1.22", "example.com/mid@v1.0.0 → example.com/dep@v1.0.0"} {
		if !strings.Contains(r.Stdout, s) {
			t.Errorf("text output lacks %q:\n%s", s, r.Stdout)
		}
	}
}

func TestToolchainReady(t *testing.T) {
	w, _ := toolchainWorld(t)
	dir := w.Project(map[string]string{"go.mod": testenv.GoModFile("example.com/app", "1.22", "example.com/dep@v1.0.0")})
	// Only a "patch available" (low) finding.
	r := w.Run(dir, "toolchain", "--json")
	if r.Code != 0 {
		t.Fatalf("exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	var res upgrade.ToolchainResult
	r.Decode(t, &res)
	if len(res.Findings) != 1 || res.Findings[0].Rule != "go-patch-available" || len(res.StdlibVulns) != 0 {
		t.Fatalf("findings %+v", res.Findings)
	}
	if r := w.Run(dir, "toolchain", "--fail-on", "low"); r.Code != 1 {
		t.Fatalf("--fail-on low: exit %d", r.Code)
	}
}

func TestToolchainSelection(t *testing.T) {
	w, lv := toolchainWorld(t)
	minor := atoi(strings.Split(lv, ".")[1])
	future := w.Project(map[string]string{"go.mod": testenv.GoModFile("example.com/app", "1.21", "example.com/future@v1.0.0")})

	// GOTOOLCHAIN=local cannot build a module needing go 1.99.
	r := w.Run(future, "toolchain", "--json")
	var res upgrade.ToolchainResult
	r.Decode(t, &res)
	if r.Code != 1 || !res.Fails || rules(res.Findings)["toolchain-too-old"].Severity != report.High {
		t.Fatalf("exit %d result %+v", r.Code, res)
	}
	// GOTOOLCHAIN=auto would switch to go1.99.0, which is not released.
	r = w.RunEnv(future, []string{"GOTOOLCHAIN=auto"}, "toolchain", "--json")
	res = upgrade.ToolchainResult{}
	r.Decode(t, &res)
	if res.Fails || res.Selected != "go1.99.0" || !strings.Contains(res.Selection, "switches to go1.99.0") {
		t.Fatalf("auto: %+v", res)
	}
	if _, ok := rules(res.Findings)["go-unreleased"]; !ok {
		t.Fatalf("auto findings %+v", res.Findings)
	}

	// toolchain line newer than the local Go with GOTOOLCHAIN=auto.
	next := "go1." + itoa(minor+1) + ".1"
	dir := w.Project(map[string]string{"go.mod": "module example.com/app\n\ngo 1.21\n\ntoolchain " + next + "\n"})
	r = w.RunEnv(dir, []string{"GOTOOLCHAIN=auto"}, "toolchain", "--json")
	res = upgrade.ToolchainResult{}
	r.Decode(t, &res)
	if res.Selected != next || r.Code != 0 {
		t.Fatalf("toolchain line: exit %d %+v", r.Code, res)
	}
	// path mode looks in PATH.
	r = w.RunEnv(dir, []string{"GOTOOLCHAIN=path"}, "toolchain", "--json")
	res = upgrade.ToolchainResult{}
	r.Decode(t, &res)
	if res.Selected != next || !strings.Contains(res.Selection, "PATH") {
		t.Fatalf("path: %+v", res)
	}

	// A pinned unsupported toolchain.
	old := "go1." + itoa(minor-1) + ".12"
	r = w.RunEnv(dir, []string{"GOTOOLCHAIN=" + old + "+auto"}, "toolchain", "--json")
	res = upgrade.ToolchainResult{}
	r.Decode(t, &res)
	if res.Selected != next {
		t.Fatalf("pinned+auto with newer toolchain line: %+v", res)
	}
	low := w.Project(map[string]string{"go.mod": "module example.com/app\n\ngo 1.20\n\ntoolchain go1.19.1\n"})
	r = w.RunEnv(low, []string{"GOTOOLCHAIN=" + old}, "toolchain", "--json")
	res = upgrade.ToolchainResult{}
	r.Decode(t, &res)
	got := rules(res.Findings)
	if res.Selected != old || r.Code != 1 || got["go-unsupported"].Severity != report.High {
		t.Fatalf("pinned old: exit %d %+v", r.Code, res)
	}
	if _, ok := got["toolchain-below-go"]; !ok {
		t.Fatalf("toolchain line below go line not reported: %+v", res.Findings)
	}
}

func TestToolchainWorkspace(t *testing.T) {
	w, _ := toolchainWorld(t)
	dir := w.Project(map[string]string{
		"go.work":  "go 1.21\n\nuse (\n\t./a\n\t./b\n)\n",
		"a/go.mod": "module example.com/a\n\ngo 1.21\n",
		"b/go.mod": "module example.com/b\n\ngo 1.22\n",
		"a/a.go":   "package a\n",
		"b/b.go":   "package b\n",
	})
	r := w.RunEnv(dir+"/a", []string{"GOWORK="}, "toolchain", "--json")
	var res upgrade.ToolchainResult
	r.Decode(t, &res)
	if res.File != "go.work" || len(res.Workspace) != 2 || r.Code != 1 {
		t.Fatalf("exit %d %+v", r.Code, res)
	}
	if f, ok := rules(res.Findings)["workspace-go-behind"]; !ok || f.Module != "example.com/b" {
		t.Fatalf("findings %+v", res.Findings)
	}
}

func TestToolchainNoModuleAndErrors(t *testing.T) {
	w, lv := toolchainWorld(t)
	empty := w.Project(map[string]string{"README": "x"})
	r := w.Run(empty, "toolchain", "--json")
	var res upgrade.ToolchainResult
	r.Decode(t, &res)
	if r.Code != 0 || res.Selected != "go"+lv || res.Module != "" {
		t.Fatalf("no module: exit %d %+v\n%s", r.Code, res, r.Stdout)
	}
	if r := w.Run(empty, "toolchain", "extra"); r.Code != 2 {
		t.Fatalf("args: exit %d", r.Code)
	}
	if r := w.Run(empty, "toolchain", "--fail-on", "bogus"); r.Code != 2 {
		t.Fatalf("bad --fail-on: exit %d", r.Code)
	}
	// go.dev unavailable: a warning, not a failure.
	r = w.RunEnv(empty, []string{"SMGO_GODEV_URL=http://127.0.0.1:1"}, "toolchain", "--json")
	if r.Code != 0 || !strings.Contains(r.Stdout, "release list unavailable") {
		t.Fatalf("godev down: exit %d\n%s", r.Code, r.Stdout)
	}
	// The vulnerability database is required.
	r = w.RunEnv(empty, []string{"SMGO_VULNDB_URL=http://127.0.0.1:1"}, "toolchain", "--json")
	if r.Code != 3 {
		t.Fatalf("vulndb down: exit %d\n%s", r.Code, r.Stdout)
	}
}
