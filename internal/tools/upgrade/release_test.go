package upgrade_test

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
	"github.com/slash-mark-dev/go-suite/internal/tools/upgrade"
)

// libSource is the published API of example.com/lib v1.3.0.
func libSource(w *testenv.World) string { return w.Module("example.com/lib", "v1.3.0").Files["lib.go"] }

const libGoMod = "module example.com/lib\n\ngo 1.21\n\nretract v1.2.0 // Parse API broken by mistake\n"

func releaseProject(w *testenv.World, gomod, src string) string {
	return w.Project(map[string]string{"go.mod": gomod, "lib.go": src, "sub/sub.go": "package sub\n\nfunc Sub() {}\n"})
}

func decodeRelease(t *testing.T, r testenv.Result) upgrade.ReleaseResult {
	t.Helper()
	var res upgrade.ReleaseResult
	r.Decode(t, &res)
	return res
}

func TestReleaseNextVersion(t *testing.T) {
	w := upgradeWorld(t)
	src := libSource(w)
	cases := []struct {
		name, src, bump, next, path string
		code                        int
	}{
		{"patch", src + "\n// comment only\n", "patch", "v1.3.1", "", 0},
		{"minor", src + "\nfunc Extra() {}\n", "minor", "v1.4.0", "", 0},
		{"major", strings.Replace(src, "func Old() int { return 1 }", "", 1), "major", "v2.0.0", "example.com/lib/v2", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := releaseProject(w, libGoMod, tc.src)
			r := w.Run(dir, "release", "--json")
			if r.Code != tc.code {
				t.Fatalf("exit %d, want %d\n%s\n%s", r.Code, tc.code, r.Stdout, r.Stderr)
			}
			res := decodeRelease(t, r)
			if res.Base != "v1.3.0" || res.RequiredBump != tc.bump || res.Suggested != tc.next || res.SuggestedPath != tc.path {
				t.Fatalf("result %+v", res)
			}
			if strings.Join(res.Published, ",") != "v1.0.0,v1.1.0,v1.2.0,v1.3.0" {
				t.Fatalf("published %v", res.Published)
			}
			if res.Commands[0] != "git tag "+tc.next || res.Ready != (tc.code == 0) {
				t.Fatalf("commands %v ready %v", res.Commands, res.Ready)
			}
		})
	}
	// Text output.
	dir := releaseProject(w, libGoMod, src+"\nfunc Extra() {}\n")
	r := w.Run(dir, "release")
	for _, s := range []string{"next version    v1.4.0", "func Extra added", "ready to release v1.4.0", "git tag v1.4.0"} {
		if !strings.Contains(r.Stdout, s) {
			t.Errorf("text output lacks %q:\n%s", s, r.Stdout)
		}
	}
}

func TestReleaseProposedVersion(t *testing.T) {
	w := upgradeWorld(t)
	dir := releaseProject(w, libGoMod, libSource(w)+"\nfunc Extra() {}\n")
	cases := []struct {
		version, rule string
		code          int
	}{
		{"v1.4.0", "", 0},
		{"v1.5.0", "", 0},
		{"v1.3.1", "additions-in-patch", 1},
		{"v1.3.0", "already-published", 1},
		{"v1.2.5", "not-newer", 1},
		{"v2.0.0", "version-path-mismatch", 1},
	}
	for _, tc := range cases {
		r := w.Run(dir, "release", "--version", tc.version, "--json")
		res := decodeRelease(t, r)
		if r.Code != tc.code {
			t.Errorf("%s: exit %d, want %d: %+v", tc.version, r.Code, tc.code, res.Findings)
			continue
		}
		if tc.rule != "" {
			if _, ok := rules(res.Findings)[tc.rule]; !ok {
				t.Errorf("%s: missing %s in %+v", tc.version, tc.rule, res.Findings)
			}
		}
		if res.Version != tc.version {
			t.Errorf("version %s", res.Version)
		}
	}
	// Breaking changes released as a minor version.
	breaking := releaseProject(w, libGoMod, strings.Replace(libSource(w), "func Old() int { return 1 }", "", 1))
	r := w.Run(breaking, "release", "--version", "v1.4.0", "--json")
	if _, ok := rules(decodeRelease(t, r).Findings)["breaking-in-compatible-release"]; !ok || r.Code != 1 {
		t.Fatalf("exit %d\n%s", r.Code, r.Stdout)
	}
	for _, bad := range []string{"1.4.0", "v1.4", "latest"} {
		if r := w.Run(dir, "release", "--version", bad); r.Code != 2 {
			t.Errorf("--version %s: exit %d", bad, r.Code)
		}
	}
	if r := w.Run(dir, "release", "--base", "v9.0.0"); r.Code != 2 {
		t.Errorf("--base v9.0.0: exit %d\n%s", r.Code, r.Stderr)
	}
	// --base compares with an older release.
	r = w.Run(dir, "release", "--base", "v1.0.0", "--json")
	if res := decodeRelease(t, r); res.Base != "v1.0.0" || res.RequiredBump != "minor" || res.Compatible != 2 {
		t.Fatalf("--base: %+v", res)
	}
}

func TestReleaseRetractionHygiene(t *testing.T) {
	w := upgradeWorld(t)
	gomod := "module example.com/lib\n\ngo 1.21\n\nretract v1.0.5\n\nreplace example.com/dep => ../dep\n"
	dir := releaseProject(w, gomod, libSource(w))
	r := w.Run(dir, "release", "--json")
	res := decodeRelease(t, r)
	got := rules(res.Findings)
	if r.Code != 1 {
		t.Fatalf("exit %d", r.Code)
	}
	for _, rule := range []string{"retraction-dropped", "retract-no-rationale", "retract-unpublished", "local-replace"} {
		if _, ok := got[rule]; !ok {
			t.Errorf("missing %s: %+v", rule, res.Findings)
		}
	}
	if f := got["retraction-dropped"]; !strings.Contains(f.Fix, "retract v1.2.0 // Parse API broken by mistake") {
		t.Errorf("fix %q", f.Fix)
	}
	if f := got["retract-unpublished"]; f.File != "go.mod" || f.Line != 5 {
		t.Errorf("position %+v", f)
	}
}

func TestReleaseModulePaths(t *testing.T) {
	w := upgradeWorld(t)
	// A never-published module.
	fresh := w.Project(map[string]string{"go.mod": "module example.com/fresh\n\ngo 1.21\n", "f.go": "package fresh\n"})
	r := w.Run(fresh, "release", "--json")
	res := decodeRelease(t, r)
	if r.Code != 0 || res.Suggested != "v0.1.0" || res.RequiredBump != "initial" || res.Base != "" {
		t.Fatalf("fresh: exit %d %+v", r.Code, res)
	}
	freshV3 := w.Project(map[string]string{"go.mod": "module example.com/fresh/v3\n\ngo 1.21\n", "f.go": "package fresh\n"})
	if res := decodeRelease(t, w.Run(freshV3, "release", "--json")); res.Suggested != "v3.0.0" {
		t.Fatalf("fresh v3: %+v", res)
	}
	// Invalid suffixes.
	for _, path := range []string{"example.com/bad/v1", "gopkg.in/yaml"} {
		dir := w.Project(map[string]string{"go.mod": "module " + path + "\n\ngo 1.21\n", "f.go": "package bad\n"})
		r := w.Run(dir, "release", "--json")
		if _, ok := rules(decodeRelease(t, r).Findings)["bad-major-suffix"]; !ok || r.Code != 1 {
			t.Errorf("%s: exit %d %s", path, r.Code, r.Stdout)
		}
	}
	// +incompatible history.
	w.AddModule("example.com/old", "v2.1.0+incompatible", map[string]string{"go.mod": "module example.com/old\n", "o.go": "package old\n"})
	old := w.Project(map[string]string{"go.mod": "module example.com/old\n\ngo 1.21\n", "o.go": "package old\n"})
	r = w.Run(old, "release", "--json")
	if f, ok := rules(decodeRelease(t, r).Findings)["incompatible-versions"]; !ok || !strings.Contains(f.Title, "example.com/old/v2") {
		t.Errorf("+incompatible: exit %d %s", r.Code, r.Stdout)
	}
	// No go.mod.
	if r := w.Run(w.Project(map[string]string{"x.txt": ""}), "release"); r.Code != 2 {
		t.Errorf("no go.mod: exit %d", r.Code)
	}
	if r := w.Run(fresh, "release", "extra-arg"); r.Code != 2 {
		t.Errorf("args: exit %d", r.Code)
	}
}

func TestReleaseGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	w := upgradeWorld(t)
	repo := w.Project(map[string]string{
		"README":            "repo\n",
		"lib/go.mod":        libGoMod,
		"lib/lib.go":        libSource(w) + "\nfunc Extra() {}\n",
		"lib/sub/sub.go":    "package sub\n\nfunc Sub() {}\n",
		"lib/v2/go.mod":     "module example.com/lib/v2\n\ngo 1.21\n",
		"lib/v2/lib.go":     w.Module("example.com/lib/v2", "v2.0.0").Files["lib.go"],
		"lib/v2/sub/sub.go": "package sub\n\nfunc Sub() {}\n",
	})
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "init.defaultBranch=main"}, args...)...)
		cmd.Dir = repo
		cmd.Env = w.Env()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("add", ".")
	run("commit", "-q", "-m", "init")
	r := w.Run(repo+"/lib", "release", "--json")
	res := decodeRelease(t, r)
	if r.Code != 0 || res.Tag != "lib/v1.4.0" || res.Git == nil || res.Git.Prefix != "lib" || res.Git.Head == "" || len(res.Git.Dirty) != 0 {
		t.Fatalf("exit %d %+v %+v", r.Code, res, res.Git)
	}
	if !strings.HasSuffix(res.Commands[0], " tag lib/v1.4.0") {
		t.Fatalf("commands %v", res.Commands)
	}
	// Major subdirectory: lib/v2 is tagged lib/v2.0.1, not lib/v2/v2.0.1.
	r = w.Run(repo+"/lib/v2", "release", "--json")
	if res := decodeRelease(t, r); res.Tag != "lib/v2.0.1" || res.Suggested != "v2.0.1" {
		t.Fatalf("v2: %+v", res)
	}
	// Existing tag and uncommitted changes.
	run("tag", "lib/v1.4.0")
	testenv.WriteFiles(t, repo, map[string]string{"lib/new.go": "package lib\n"})
	r = w.Run(repo+"/lib", "release", "--json")
	res = decodeRelease(t, r)
	got := rules(res.Findings)
	if _, ok := got["tag-exists"]; !ok || r.Code != 1 {
		t.Fatalf("exit %d findings %+v", r.Code, res.Findings)
	}
	if _, ok := got["uncommitted-changes"]; !ok || strings.Join(res.Git.Dirty, ",") != "lib/new.go" {
		t.Fatalf("dirty %+v findings %+v", res.Git, res.Findings)
	}
	if r := w.Run(repo+"/lib", "release", "--no-git", "--json"); decodeRelease(t, r).Git != nil || r.Code != 0 {
		t.Fatalf("--no-git: exit %d", r.Code)
	}
}
