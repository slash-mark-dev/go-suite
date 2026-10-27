package upgrade_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/modfile"
	"github.com/slash-mark-dev/go-suite/internal/testenv"
	"github.com/slash-mark-dev/go-suite/internal/tools/upgrade"
)

// upgradeWorld extends libWorld with:
//
//	example.com/lib   v1.3.0 retracts v1.2.0
//	example.com/dep   v1.0.0 (no deps), v1.1.0 (go 1.22; requires lib v1.2.0 and extra v1.0.0),
//	                  v1.2.0 (go 1.99)
//	example.com/extra v1.0.0
//
// and vulnerabilities in lib < v1.1.0 (fixed) and extra (unfixed).
func upgradeWorld(t *testing.T) *testenv.World {
	w := libWorld(t)
	w.AddModule("example.com/lib", "v1.3.0", map[string]string{
		"go.mod":     "module example.com/lib\n\ngo 1.21\n\nretract v1.2.0 // Parse API broken by mistake\n",
		"lib.go":     w.Module("example.com/lib", "v1.1.0").Files["lib.go"],
		"sub/sub.go": "package sub\n\nfunc Sub() {}\n",
	})
	w.AddModule("example.com/dep", "v1.0.0", map[string]string{"dep.go": "package dep\n\nfunc D() {}\n"})
	w.AddModule("example.com/dep", "v1.1.0", map[string]string{
		"go.mod": testenv.GoModFile("example.com/dep", "1.22", "example.com/lib@v1.2.0", "example.com/extra@v1.0.0"),
		"dep.go": "package dep\n\nfunc D() {}\n",
	})
	w.AddModule("example.com/dep", "v1.2.0", map[string]string{
		"go.mod": testenv.GoModFile("example.com/dep", "1.99", "example.com/lib@v1.2.0"),
		"dep.go": "package dep\n\nfunc D() {}\n",
	})
	w.AddModule("example.com/extra", "v1.0.0", map[string]string{"extra.go": "package extra\n"})
	w.AddVuln(testenv.SimpleVuln("GO-2025-0001", "example.com/lib", "v1.0.0", "v1.1.0", "example.com/lib", []string{"Parse"}, "CVE-2025-0001"))
	w.AddVuln(testenv.SimpleVuln("GO-2025-0002", "example.com/extra", "v0.0.0", "", "example.com/extra", nil))
	return w
}

const upgradeMain = `package main

import (
	"fmt"

	"example.com/dep"
	"example.com/lib"
)

func main() {
	dep.D()
	fmt.Println(lib.Old())
	n := lib.Parse("x")
	c := lib.Config{Name: "x"}
	fmt.Println(n, c)
}
`

func upgradeProject(w *testenv.World, requires ...string) string {
	return w.Project(map[string]string{
		"go.mod":  testenv.GoModFile("example.com/app", "1.21", requires...),
		"main.go": upgradeMain,
	})
}

// realGet runs `go get args` in a copy of the project and returns the
// build list (path@version, main module excluded) and the go.mod.
func realGet(t *testing.T, w *testenv.World, args []string, requires ...string) ([]string, *modfile.File, string, error) {
	t.Helper()
	dir := upgradeProject(w, requires...)
	out, err := w.Go(dir, append([]string{"get"}, args...)...)
	if err != nil {
		return nil, nil, out, err
	}
	list, err := w.Go(dir, "list", "-m", "all")
	if err != nil {
		t.Fatalf("go list -m all: %v\n%s", err, list)
	}
	var mods []string
	for i, line := range strings.Split(strings.TrimSpace(list), "\n") {
		if i == 0 {
			continue
		}
		mods = append(mods, strings.Replace(line, " ", "@", 1))
	}
	f, err := modfile.ParseFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	return mods, f, out, nil
}

func change(res *upgrade.UpgradeResult, path string) *upgrade.ModuleChange {
	for i := range res.Changes {
		if res.Changes[i].Path == path {
			return &res.Changes[i]
		}
	}
	return nil
}

func TestUpgradeSafeMinor(t *testing.T) {
	w := upgradeWorld(t)
	reqs := []string{"example.com/dep@v1.0.0", "example.com/lib@v1.0.0"}
	dir := upgradeProject(w, reqs...)
	r := w.Run(dir, "upgrade", "example.com/lib@v1.1.0", "--json")
	if r.Code != 0 {
		t.Fatalf("exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	var res upgrade.UpgradeResult
	r.Decode(t, &res)
	if len(res.Changes) != 1 {
		t.Fatalf("changes = %+v", res.Changes)
	}
	mc := res.Changes[0]
	if mc.Path != "example.com/lib" || mc.Kind != "upgrade" || mc.Bump != "minor" || !mc.Requested || !mc.Direct {
		t.Fatalf("change = %+v", mc)
	}
	if len(mc.VulnsFixed) != 1 || mc.VulnsFixed[0].ID != "GO-2025-0001" || len(mc.VulnsIntroduced) != 0 {
		t.Fatalf("vulns = %+v / %+v", mc.VulnsFixed, mc.VulnsIntroduced)
	}
	if !mc.APIChecked || len(mc.APIBreaks) != 0 || mc.APIAdditions != 1 || strings.Join(mc.UsedPackages, ",") != "example.com/lib" {
		t.Fatalf("api = %+v", mc)
	}
	if res.Go.From != "1.21" || res.Go.To != "1.21" || res.Command != "go get example.com/lib@v1.1.0" {
		t.Fatalf("go = %+v, command %q", res.Go, res.Command)
	}
	want, _, out, err := realGet(t, w, []string{"example.com/lib@v1.1.0"}, reqs...)
	if err != nil {
		t.Fatalf("go get: %v\n%s", err, out)
	}
	if strings.Join(res.BuildList, " ") != strings.Join(want, " ") {
		t.Fatalf("build list\n got %v\nwant %v", res.BuildList, want)
	}
	// go.mod is untouched.
	b, _ := os.ReadFile(filepath.Join(dir, "go.mod"))
	if !strings.Contains(string(b), "example.com/lib v1.0.0") {
		t.Fatalf("go.mod modified:\n%s", b)
	}
	// Text output.
	r = w.Run(dir, "upgrade", "example.com/lib@v1.1.0")
	if r.Code != 0 || !strings.Contains(r.Stdout, "safe to run: go get example.com/lib@v1.1.0") || !strings.Contains(r.Stdout, "fixes GO-2025-0001") {
		t.Fatalf("text output:\n%s\n%s", r.Stdout, r.Stderr)
	}
}

func TestUpgradeTransitiveBreaks(t *testing.T) {
	w := upgradeWorld(t)
	reqs := []string{"example.com/dep@v1.0.0", "example.com/lib@v1.0.0"}
	dir := upgradeProject(w, reqs...)
	r := w.Run(dir, "upgrade", "example.com/dep@v1.1.0", "--json")
	if r.Code != 1 {
		t.Fatalf("exit %d, want 1\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	var res upgrade.UpgradeResult
	r.Decode(t, &res)
	dep, lib, extra := change(&res, "example.com/dep"), change(&res, "example.com/lib"), change(&res, "example.com/extra")
	if dep == nil || lib == nil || extra == nil || len(res.Changes) != 3 {
		t.Fatalf("changes = %+v", res.Changes)
	}
	if lib.To != "v1.2.0" || lib.Requested || !lib.Retracted || lib.RetractReason != "Parse API broken by mistake" {
		t.Fatalf("lib = %+v", lib)
	}
	if extra.Kind != "added" || len(extra.VulnsIntroduced) != 1 || extra.VulnsIntroduced[0].ID != "GO-2025-0002" {
		t.Fatalf("extra = %+v", extra)
	}
	// API: Old removed and Parse changed, both used in main.go.
	got := map[string]string{}
	for _, b := range lib.APIBreaks {
		got[b.Object] = strings.Join(b.UsedAt, ",")
	}
	if !strings.HasPrefix(got["Old"], "main.go:12:") || !strings.HasPrefix(got["Parse"], "main.go:13:") || len(got) != 2 {
		t.Fatalf("api breaks = %+v", lib.APIBreaks)
	}
	if lib.Affected != 2 {
		t.Fatalf("affected = %d", lib.Affected)
	}
	// dep's API is unchanged; extra is not imported.
	if !dep.APIChecked || len(dep.APIBreaks) != 0 || extra.APIChecked {
		t.Fatalf("dep = %+v, extra = %+v", dep, extra)
	}
	// go line raised; toolchain line added with the running toolchain.
	if res.Go.From != "1.21" || res.Go.To != "1.22" || res.Go.RequiredBy != "example.com/dep@v1.1.0" || res.Go.Blocked {
		t.Fatalf("go = %+v", res.Go)
	}
	if len(res.Problems) != 3 {
		t.Fatalf("problems = %q", res.Problems)
	}
	want, f, out, err := realGet(t, w, []string{"example.com/dep@v1.1.0"}, reqs...)
	if err != nil {
		t.Fatalf("go get: %v\n%s", err, out)
	}
	if strings.Join(res.BuildList, " ") != strings.Join(want, " ") {
		t.Fatalf("build list\n got %v\nwant %v", res.BuildList, want)
	}
	if f.Go != res.Go.To || f.Toolchain != res.Go.ToolchainTo {
		t.Fatalf("go get wrote go %s toolchain %s; predicted %s / %s", f.Go, f.Toolchain, res.Go.To, res.Go.ToolchainTo)
	}
	if !strings.Contains(out, "upgraded example.com/lib v1.0.0 => v1.2.0") {
		t.Fatalf("go get output:\n%s", out)
	}
	r = w.Run(dir, "upgrade", "example.com/dep@v1.1.0")
	for _, s := range []string{"v1.2.0 is retracted: Parse API broken by mistake", "func Old removed", "used at main.go:12", "go 1.21 → 1.22", "introduces GO-2025-0002"} {
		if !strings.Contains(r.Stdout, s) {
			t.Errorf("text output lacks %q:\n%s", s, r.Stdout)
		}
	}
}

func TestUpgradeDowngrade(t *testing.T) {
	w := upgradeWorld(t)
	reqs := []string{"example.com/dep@v1.1.0", "example.com/extra@v1.0.0", "example.com/lib@v1.2.0"}
	dir := upgradeProject(w, reqs...)
	for _, args := range [][]string{{"example.com/lib@v1.1.0"}, {"example.com/dep@none"}, {"example.com/lib@v1.0.0", "example.com/extra@none"}} {
		r := w.Run(dir, append([]string{"upgrade", "--no-api"}, append(args, "--json")...)...)
		if r.Code != 0 && r.Code != 1 {
			t.Fatalf("%v: exit %d\n%s\n%s", args, r.Code, r.Stdout, r.Stderr)
		}
		var res upgrade.UpgradeResult
		r.Decode(t, &res)
		want, _, out, err := realGet(t, w, args, reqs...)
		if err != nil {
			t.Fatalf("go get %v: %v\n%s", args, err, out)
		}
		if strings.Join(res.BuildList, " ") != strings.Join(want, " ") {
			t.Fatalf("%v: build list\n got %v\nwant %v\ngo get said:\n%s", args, res.BuildList, want, out)
		}
	}
	// lib@v1.1.0 forces dep down to v1.0.0 (the newest dep not requiring lib v1.2.0).
	r := w.Run(dir, "upgrade", "example.com/lib@v1.1.0", "--no-api", "--json")
	var res upgrade.UpgradeResult
	r.Decode(t, &res)
	if d := change(&res, "example.com/dep"); d == nil || d.Kind != "downgrade" || d.To != "v1.0.0" || d.Requested {
		t.Fatalf("dep change = %+v", d)
	}
	if l := change(&res, "example.com/lib"); l == nil || l.Kind != "downgrade" || l.Bump != "minor" || len(l.VulnsIntroduced) != 0 {
		t.Fatalf("lib change = %+v", l)
	}
}

func TestUpgradeGoToolchainBlocked(t *testing.T) {
	w := upgradeWorld(t)
	reqs := []string{"example.com/dep@v1.0.0", "example.com/lib@v1.0.0"}
	dir := upgradeProject(w, reqs...)
	r := w.Run(dir, "upgrade", "example.com/dep@v1.2.0", "--no-api", "--no-vulns", "--json")
	if r.Code != 1 {
		t.Fatalf("exit %d\n%s", r.Code, r.Stdout)
	}
	var res upgrade.UpgradeResult
	r.Decode(t, &res)
	if !res.Go.Blocked || res.Go.To != "1.99" || res.Go.GOTOOLCHAIN != "local" {
		t.Fatalf("go = %+v", res.Go)
	}
	if _, _, out, err := realGet(t, w, []string{"example.com/dep@v1.2.0"}, reqs...); err == nil || !strings.Contains(out, "requires go >= 1.99") {
		t.Fatalf("real go get should fail: %v\n%s", err, out)
	}
	// With GOTOOLCHAIN=auto the go command would switch toolchains.
	r = w.RunEnv(dir, []string{"GOTOOLCHAIN=auto"}, "upgrade", "example.com/dep@v1.2.0", "--no-api", "--no-vulns", "--json")
	r.Decode(t, &res)
	if res.Go.Blocked || res.Go.Switch != "go1.99.0" {
		t.Fatalf("go = %+v", res.Go)
	}
}

func TestUpgradeQueries(t *testing.T) {
	w := upgradeWorld(t)
	dir := upgradeProject(w, "example.com/dep@v1.0.0", "example.com/lib@v1.0.0")
	r := w.Run(dir, "upgrade", "example.com/lib@latest", "example.com/dep@patch", "--no-api", "--json")
	var res upgrade.UpgradeResult
	r.Decode(t, &res)
	if res.Requests[0].Version != "v1.3.0" || res.Requests[1].Version != "v1.0.0" || res.Requests[0].From != "v1.0.0" {
		t.Fatalf("requests = %+v", res.Requests)
	}
	// lib@upgrade skips the retracted v1.2.0 and picks v1.3.0.
	r = w.Run(dir, "upgrade", "example.com/lib@upgrade", "--no-api", "--no-vulns", "--json")
	r.Decode(t, &res)
	if r.Code != 0 || res.Requests[0].Version != "v1.3.0" {
		t.Fatalf("exit %d requests = %+v", r.Code, res.Requests)
	}
}

func TestUpgradeUsageErrors(t *testing.T) {
	w := upgradeWorld(t)
	dir := upgradeProject(w, "example.com/dep@v1.0.0", "example.com/lib@v1.0.0")
	for _, args := range [][]string{
		{},
		{"example.com/lib@v9.0.0"},
		{"example.com/lib@1.2"},
		{"example.com/app@v1.0.0"},
		{"example.com/lib@v1.1.0", "example.com/lib@v1.0.0"},
		{"example.com/nope@latest"},
	} {
		r := w.Run(dir, append([]string{"upgrade", "--json"}, args...)...)
		if r.Code != 2 {
			t.Errorf("%v: exit %d, want 2\n%s", args, r.Code, r.Stdout)
		}
	}
	empty := w.Project(map[string]string{"README": "no module"})
	if r := w.Run(empty, "upgrade", "example.com/lib@v1.1.0"); r.Code != 2 {
		t.Errorf("no go.mod: exit %d\n%s", r.Code, r.Stderr)
	}
}
