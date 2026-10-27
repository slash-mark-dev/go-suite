package compliance

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

// vendorWorld publishes modules exercising everything go mod vendor does
// (package files, ignored and test files, embeds, parent-directory
// metadata, version and directory replacements), then runs the real
// `go mod vendor` in a main module.
func vendorWorld(t *testing.T) (*testenv.World, string) {
	t.Helper()
	w := testenv.New(t)
	w.AddModule("example.com/alpha", "v1.0.0", map[string]string{
		"go.mod":  testenv.GoModFile("example.com/alpha", "1.21", "example.com/gamma@v1.2.0"),
		"LICENSE": mdMIT,
		"alpha.go": "package alpha\n\nimport (\n\t_ \"embed\"\n\n\t\"example.com/alpha/sub\"\n\t\"example.com/gamma/inner\"\n)\n\n" +
			"//go:embed version.txt\nvar Version string\n\n//go:embed data\nvar _ string\n\nfunc A() string { return sub.S() + inner.I() + Version }\n",
		"alpha_test.go":    "package alpha\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) {}\n",
		"ignored.go":       "//go:build ignore\n\npackage main\n\nfunc main() {}\n",
		"linux_only.go":    "//go:build linux && !ignore\n\npackage alpha\n",
		"README.md":        "# alpha\n",
		"version.txt":      "1.0.0\n",
		"data/a.txt":       "a\n",
		"data/.hidden":     "h\n",
		"data/_skip.txt":   "s\n",
		"sub/sub.go":       "package sub\n\nfunc S() string { return \"s\" }\n",
		"sub/NOTICE":       "sub notice\n",
		"unused/unused.go": "package unused\n",
	})
	w.AddModule("example.com/alpha", "v1.0.1", map[string]string{
		"go.mod":   testenv.GoModFile("example.com/alpha", "1.21", "example.com/gamma@v1.2.0"),
		"alpha.go": "package alpha\n",
	})
	w.AddModule("example.com/gamma", "v1.2.0", map[string]string{
		"go.mod":         "module example.com/gamma\n\ngo 1.20\n",
		"LICENSE":        mdMIT,
		"COPYING-extra":  "extra terms\n",
		"gamma.go":       "package gamma\n",
		"inner/inner.go": "package inner\n\nfunc I() string { return \"i\" }\n",
	})
	w.AddModule("example.com/betafork", "v1.1.0", map[string]string{
		"go.mod":  "module example.com/beta\n\ngo 1.21\n",
		"beta.go": "package beta\n\nfunc B() string { return \"fork\" }\n",
	})
	dir := w.Project(map[string]string{
		"go.mod": testenv.GoModFile("example.com/main", "1.22",
			"example.com/alpha@v1.0.0", "example.com/beta@v1.0.0", "example.com/local@v0.0.0") +
			"\nreplace example.com/beta => example.com/betafork v1.1.0\n\nreplace example.com/local => ./local\n",
		"local/go.mod": "module example.com/local\n\ngo 1.21\n",
		"local/l.go":   "package local\n\nfunc L() string { return \"l\" }\n",
		"main.go":      "package main\n\nimport (\n\t\"example.com/alpha\"\n\t\"example.com/beta\"\n\t\"example.com/local\"\n)\n\nfunc main() { println(alpha.A(), beta.B(), local.L()) }\n",
	})
	goTidy(t, w, dir)
	if out, err := w.Go(dir, "mod", "vendor"); err != nil {
		t.Fatalf("go mod vendor: %v\n%s", err, out)
	}
	return w, dir
}

func vendorRules(res *VendorResult) map[string]bool {
	m := map[string]bool{}
	for _, f := range res.Findings {
		m[f.Rule+" "+f.File] = true
		m[f.Rule] = true
	}
	return m
}

func vendorMods(res *VendorResult) map[string]*VendoredModule {
	m := map[string]*VendoredModule{}
	for _, x := range res.Modules {
		m[x.Path] = x
	}
	return m
}

func TestVendorClean(t *testing.T) {
	w, dir := vendorWorld(t)
	if out, err := w.Go(dir, "build", "-mod=vendor", "./..."); err != nil {
		t.Fatalf("go build -mod=vendor: %v\n%s", err, out)
	}
	r := w.Run(dir, "vendor", "--json")
	var res VendorResult
	r.Decode(t, &res)
	if r.Code != 0 || len(res.Findings) != 0 {
		t.Fatalf("exit %d, findings %+v\n%s", r.Code, res.Findings, r.Stderr)
	}
	if !res.Present || !res.Consistent || res.Verified != 3 || len(res.Files) != 0 || len(res.Stray) != 0 {
		t.Errorf("result: present=%v consistent=%v verified=%d files=%v stray=%v", res.Present, res.Consistent, res.Verified, res.Files, res.Stray)
	}
	mods := vendorMods(&res)
	want := map[string]string{"example.com/alpha": "ok", "example.com/gamma": "ok", "example.com/beta": "ok", "example.com/local": "skipped"}
	for p, st := range want {
		if mods[p] == nil || mods[p].Status != st {
			t.Errorf("%s: %+v, want status %s", p, mods[p], st)
		}
	}
	if m := mods["example.com/beta"]; m.Replace != "example.com/betafork v1.1.0" || !m.Explicit || m.GoVersion != "1.21" {
		t.Errorf("beta: %+v", m)
	}
	if m := mods["example.com/gamma"]; m.GoVersion != "1.20" || len(m.Packages) != 1 || m.Files != 3 {
		t.Errorf("gamma: %+v", m) // inner/inner.go + LICENSE + COPYING-extra
	}

	// Without the network the same checks pass, but nothing is verified.
	r = w.Run(dir, "vendor", "--offline-only", "--json")
	res = VendorResult{}
	r.Decode(t, &res)
	if r.Code != 0 || res.Verified != 0 || vendorMods(&res)["example.com/alpha"].Status != "skipped" {
		t.Errorf("offline-only: exit %d %+v", r.Code, res)
	}

	r = w.Run(dir, "vendor")
	mustContain(t, "text output", r.Stdout, "sm-go vendor · example.com/main", "example.com/alpha", "vendor directory verified")
}

func TestVendorAbsent(t *testing.T) {
	w := testenv.New(t)
	dir := w.Project(map[string]string{"go.mod": "module example.com/main\n\ngo 1.22\n", "main.go": "package main\n\nfunc main() {}\n"})
	r := w.Run(dir, "vendor", "--json")
	var res VendorResult
	r.Decode(t, &res)
	if r.Code != 0 || res.Present || len(res.Findings) != 1 || res.Findings[0].Rule != "vendor-absent" {
		t.Fatalf("exit %d %+v", r.Code, res)
	}
	if r := w.Run(dir, "vendor", "extra"); r.Code != 2 {
		t.Errorf("argument: exit %d", r.Code)
	}
}

func TestVendorTamper(t *testing.T) {
	w, dir := vendorWorld(t)
	v := func(p string) string { return filepath.Join(dir, "vendor", filepath.FromSlash(p)) }
	alphaGo := readFile(t, v("example.com/alpha/alpha.go"))
	testenv.WriteFiles(t, filepath.Join(dir, "vendor"), map[string]string{
		"example.com/alpha/alpha.go":      alphaGo + "\nfunc init() { println(\"pwned\") }\n",
		"example.com/alpha/backdoor.go":   "package alpha\n",
		"example.com/alpha/alpha_test.go": "package alpha\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) {}\n",
		"example.com/evil/evil.go":        "package evil\n",
	})
	for _, p := range []string{"example.com/alpha/LICENSE", "example.com/alpha/data/a.txt"} {
		if err := os.Remove(v(p)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.RemoveAll(v("example.com/gamma/inner")); err != nil {
		t.Fatal(err)
	}

	r := w.Run(dir, "vendor", "--json")
	if r.Code != 1 {
		t.Fatalf("exit %d\n%s", r.Code, r.Stderr)
	}
	var res VendorResult
	r.Decode(t, &res)
	rules := vendorRules(&res)
	for _, want := range []string{
		"vendor-file-modified vendor/example.com/alpha/alpha.go",
		"vendor-file-added vendor/example.com/alpha/backdoor.go",
		"vendor-file-extra vendor/example.com/alpha/alpha_test.go",
		"vendor-file-missing vendor/example.com/alpha/LICENSE",
		"vendor-file-missing vendor/example.com/alpha/data/a.txt",
		"vendor-package-missing vendor/example.com/gamma/inner",
		"vendor-stray vendor/example.com/evil",
	} {
		if !rules[want] {
			t.Errorf("missing finding %q", want)
		}
	}
	if rules["vendor-file-missing vendor/example.com/gamma/inner/inner.go"] {
		t.Errorf("files of a missing package reported one by one")
	}
	sev := map[string]string{}
	for _, f := range res.Findings {
		sev[f.Rule+" "+f.File] = f.Severity.String()
	}
	if sev["vendor-file-modified vendor/example.com/alpha/alpha.go"] != "high" || sev["vendor-file-added vendor/example.com/alpha/backdoor.go"] != "high" ||
		sev["vendor-stray vendor/example.com/evil"] != "medium" || sev["vendor-file-extra vendor/example.com/alpha/alpha_test.go"] != "info" {
		t.Errorf("severities: %v", sev)
	}
	m := vendorMods(&res)["example.com/alpha"]
	if m.Status != "tampered" || m.Modified != 1 || m.Added != 1 || m.Missing != 2 {
		t.Errorf("alpha: %+v", m)
	}
	if len(res.Stray) != 1 || res.Stray[0] != "vendor/example.com/evil/evil.go" {
		t.Errorf("stray: %v", res.Stray)
	}
	// None of this is visible to the go command's consistency check.
	if !res.Consistent {
		t.Errorf("goErrors: %v", res.GoErrors)
	}
	r = w.Run(dir, "vendor", "--fail-on", "critical")
	if r.Code != 0 {
		t.Errorf("--fail-on critical: exit %d", r.Code)
	}
	mustContain(t, "text output", r.Stdout, "tampered (1 modified, 1 added, 2 missing)", "hand-edited")
}

// goVendorErrors runs `go build -mod=vendor` and returns the inconsistency
// lines it prints.
func goVendorErrors(t *testing.T, w *testenv.World, dir string) []string {
	t.Helper()
	out, err := w.Go(dir, "build", "-mod=vendor", "./...")
	if err == nil {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "\t") && strings.Contains(l, ": is ") {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	if len(lines) == 0 {
		t.Fatalf("go build failed without inconsistency lines: %v\n%s", err, out)
	}
	sort.Strings(lines)
	return lines
}

func TestVendorConsistencyMatchesGo(t *testing.T) {
	w, dir := vendorWorld(t)
	mt := filepath.Join(dir, "vendor", "modules.txt")
	orig := readFile(t, mt)
	gomod := filepath.Join(dir, "go.mod")
	origMod := readFile(t, gomod)

	cases := []struct {
		name       string
		modules    func(string) string
		gomod      func(string) string
		wantRules  []string
		consistent bool
	}{
		{name: "explicit marker removed",
			modules: func(s string) string {
				return strings.Replace(s, "# example.com/alpha v1.0.0\n## explicit; go 1.21", "# example.com/alpha v1.0.0\n## go 1.21", 1)
			},
			wantRules: []string{"vendor-not-explicit"}},
		{name: "replacement changed",
			modules: func(s string) string {
				return strings.Replace(s, "example.com/betafork v1.1.0", "example.com/betafork v1.0.9", -1)
			},
			wantRules: []string{"vendor-replace-mismatch"}},
		{name: "extra replacement and explicit module",
			modules: func(s string) string {
				return s + "# example.com/zzz v1.0.0 => example.com/zzz2 v1.0.0\n# example.com/yyy v1.0.0\n## explicit\nexample.com/yyy\n"
			},
			wantRules: []string{"vendor-replace-extra", "vendor-explicit-not-required"}},
		{name: "module missing",
			modules: func(s string) string {
				i := strings.Index(s, "# example.com/gamma")
				j := strings.Index(s[i+1:], "# ") + i + 1
				return s[:i] + s[j:]
			},
			wantRules: []string{"vendor-module-missing"}},
		{name: "go.mod upgraded without re-vendoring",
			gomod: func(s string) string {
				return strings.Replace(s, "example.com/alpha v1.0.0", "example.com/alpha v1.0.1", 1)
			},
			wantRules: []string{"vendor-version-mismatch", "vendor-stale"}},
		{name: "go.mod replacement removed",
			gomod:     func(s string) string { return strings.Replace(s, "replace example.com/local => ./local\n", "", 1) },
			wantRules: []string{"vendor-replace-extra"}},
		{name: "go annotation edited (not checked by go)",
			modules:    func(s string) string { return strings.Replace(s, "## explicit; go 1.20", "## explicit; go 1.18", 1) },
			wantRules:  []string{"vendor-go-version"},
			consistent: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, g := orig, origMod
			if tc.modules != nil {
				m = tc.modules(orig)
				if m == orig {
					t.Fatalf("modules.txt edit did not apply:\n%s", orig)
				}
			}
			if tc.gomod != nil {
				g = tc.gomod(origMod)
				if g == origMod {
					t.Fatalf("go.mod edit did not apply:\n%s", origMod)
				}
			}
			if err := os.WriteFile(mt, []byte(m), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(gomod, []byte(g), 0o644); err != nil {
				t.Fatal(err)
			}
			defer os.WriteFile(mt, []byte(orig), 0o644)
			defer os.WriteFile(gomod, []byte(origMod), 0o644)

			goLines := goVendorErrors(t, w, dir)
			r := w.Run(dir, "vendor", "--json")
			var res VendorResult
			r.Decode(t, &res)
			if r.Code != 1 {
				t.Errorf("exit %d\n%s", r.Code, r.Stderr)
			}
			ours := append([]string{}, res.GoErrors...)
			sort.Strings(ours)
			if strings.Join(ours, "\n") != strings.Join(goLines, "\n") {
				t.Errorf("go command says:\n%s\nsm-go says:\n%s", strings.Join(goLines, "\n"), strings.Join(ours, "\n"))
			}
			if res.Consistent != tc.consistent {
				t.Errorf("consistent = %v", res.Consistent)
			}
			rules := vendorRules(&res)
			for _, want := range tc.wantRules {
				if !rules[want] {
					t.Errorf("missing rule %s in %+v", want, res.Findings)
				}
			}
		})
	}
}

func TestExpectedVendorFilesRules(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want bool
	}{
		{"package a\n", true},
		{"//go:build ignore\n\npackage a\n", false},
		{"//go:build !ignore\n\npackage a\n", true},
		{"//go:build linux && !linux\n\npackage a\n", true},
		{"// +build ignore\n\npackage a\n", false},
		{"// Copyright\n\n//go:build windows || ignore\n\npackage a\n", true},
		{"/* x */\n//go:build ignore\npackage a\n", false},
		{"package a\n\n//go:build ignore\n", true},
	} {
		if got := shouldBuildAnyTags([]byte(tc.src)); got != tc.want {
			t.Errorf("shouldBuildAnyTags(%q) = %v", tc.src, got)
		}
	}
	files := []string{"p/a.txt", "p/d/x", "p/d/.h", "p/d/_u", "p/d/e/y", "p/q/z"}
	got := resolveEmbeds(files, "p", []string{"*.txt", "d"})
	if strings.Join(got, ",") != "p/a.txt,p/d/e/y,p/d/x" {
		t.Errorf("resolveEmbeds = %v", got)
	}
	got = resolveEmbeds(files, "p", []string{"all:d"})
	if strings.Join(got, ",") != "p/d/.h,p/d/_u,p/d/e/y,p/d/x" {
		t.Errorf("resolveEmbeds all: = %v", got)
	}
	if a := splitEmbedArgs("a.txt \"b c.txt\" `d`"); strings.Join(a, "|") != "a.txt|b c.txt|d" {
		t.Errorf("splitEmbedArgs = %q", a)
	}
}
