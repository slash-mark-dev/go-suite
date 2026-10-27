package deps

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/modfile"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

func needGo(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go command not available")
	}
}

func pkgFile(name string, imports ...string) string {
	var b strings.Builder
	b.WriteString("package " + name + "\n")
	for _, i := range imports {
		b.WriteString("\nimport _ \"" + i + "\"\n")
	}
	return b.String()
}

// baseWorld publishes:
//
//	a v1.0.0  -> b v1.1.0 (a imports b)
//	b v1.0.0 .. v1.3.0
//	c v1.0.0  -> b v1.2.0 (c imports b)
//	d v1.0.0  -> e v1.0.0 (d imports e)
//	e v1.0.0  -> b v1.3.0 (pruned out of graphs of go >= 1.17 main modules)
//	t v1.0.0, u v1.0.0 (no requirements)
func baseWorld(t *testing.T) *testenv.World {
	needGo(t)
	w := testenv.New(t)
	w.AddModule("example.com/a", "v1.0.0", map[string]string{
		"go.mod": testenv.GoModFile("example.com/a", "1.21", "example.com/b@v1.1.0"),
		"a.go":   pkgFile("a", "example.com/b"),
	})
	for _, v := range []string{"v1.0.0", "v1.1.0", "v1.2.0", "v1.3.0"} {
		w.AddModule("example.com/b", v, map[string]string{"b.go": pkgFile("b")})
	}
	w.AddModule("example.com/c", "v1.0.0", map[string]string{
		"go.mod": testenv.GoModFile("example.com/c", "1.21", "example.com/b@v1.2.0"),
		"c.go":   pkgFile("c", "example.com/b"),
	})
	w.AddModule("example.com/d", "v1.0.0", map[string]string{
		"go.mod": testenv.GoModFile("example.com/d", "1.21", "example.com/e@v1.0.0"),
		"d.go":   pkgFile("d", "example.com/e"),
	})
	w.AddModule("example.com/e", "v1.0.0", map[string]string{
		"go.mod": testenv.GoModFile("example.com/e", "1.21", "example.com/b@v1.3.0"),
		"e.go":   pkgFile("e"),
	})
	w.AddModule("example.com/t", "v1.0.0", map[string]string{"t.go": pkgFile("t")})
	w.AddModule("example.com/u", "v1.0.0", map[string]string{"u.go": pkgFile("u")})
	return w
}

// mainProject is a go 1.22 module requiring a, c and d, importing a, c
// and d.
func mainProject(w *testenv.World, extra map[string]string) string {
	files := map[string]string{
		"go.mod":  testenv.GoModFile("example.com/main", "1.22", "example.com/a@v1.0.0", "example.com/c@v1.0.0", "example.com/d@v1.0.0"),
		"main.go": "package main\n\nimport (\n\t_ \"example.com/a\"\n\t_ \"example.com/c\"\n\t_ \"example.com/d\"\n)\n\nfunc main() {}\n",
	}
	for k, v := range extra {
		files[k] = v
	}
	return w.Project(files)
}

func copyDir(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if fi.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// realTidy runs `go mod tidy` on a copy of dir and returns the resulting
// requirements as "path version [indirect]" strings.
func realTidy(t *testing.T, w *testenv.World, dir string) []string {
	t.Helper()
	cp := copyDir(t, dir)
	if out, err := w.Go(cp, "mod", "tidy"); err != nil {
		t.Fatalf("go mod tidy: %v\n%s", err, out)
	}
	f, err := modfile.ParseFile(filepath.Join(cp, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range f.Require {
		s := r.Mod.Path + " " + r.Mod.Version
		if r.Indirect {
			s += " indirect"
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func goOut(t *testing.T, w *testenv.World, dir string, extra []string, args ...string) string {
	t.Helper()
	out, err := w.GoEnv(dir, extra, args...)
	if err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func expectCode(t *testing.T, r testenv.Result, code int) {
	t.Helper()
	if r.Code != code {
		t.Fatalf("exit code %d, want %d\nstdout:\n%s\nstderr:\n%s", r.Code, code, r.Stdout, r.Stderr)
	}
}

func findRule(fs []report.Finding, rule string) []report.Finding {
	var out []report.Finding
	for _, f := range fs {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

func mustRule(t *testing.T, fs []report.Finding, rule string, sev report.Severity) report.Finding {
	t.Helper()
	got := findRule(fs, rule)
	if len(got) == 0 {
		t.Fatalf("no %s finding in %+v", rule, fs)
	}
	if got[0].Severity != sev {
		t.Fatalf("%s severity %s, want %s: %+v", rule, got[0].Severity, sev, got[0])
	}
	return got[0]
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "go: downloading") {
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}
