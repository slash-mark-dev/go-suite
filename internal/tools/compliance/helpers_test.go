package compliance

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

// licenseWorld publishes modules with assorted licenses and returns the
// world and a main module requiring all of them.
func licenseWorld(t *testing.T) (*testenv.World, string) {
	t.Helper()
	w := testenv.New(t)
	w.AddModule("example.com/mitlib", "v1.0.0", map[string]string{
		"LICENSE": mdMIT,
		"mit.go":  "package mitlib\n\nfunc M() string { return \"mit\" }\n",
	})
	w.AddModule("example.com/gpllib", "v1.2.0", map[string]string{
		"COPYING": reflow(licenseTexts["GPL-3.0"][0], 72, ""),
		"gpl.go":  "package gpllib\n\nfunc G() string { return \"gpl\" }\n",
	})
	w.AddModule("example.com/apachelib", "v0.3.0", map[string]string{
		"go.mod":  testenv.GoModFile("example.com/apachelib", "1.21", "example.com/mitlib@v1.0.0"),
		"LICENSE": reflow(licenseTexts["Apache-2.0"][0], 76, "   "),
		"NOTICE":  "Apache Foo\nCopyright 2020 The Foo Authors\n\nThis product includes software developed at Foo.\n",
		"a.go":    "package apachelib\n\nimport \"example.com/mitlib\"\n\nfunc A() string { return mitlib.M() }\n",
	})
	w.AddModule("example.com/nolicense", "v1.0.0", map[string]string{
		"n.go": "package nolicense\n\nfunc N() {}\n",
	})
	w.AddModule("example.com/mystery", "v1.0.0", map[string]string{
		"LICENSE": "Copyright 2024 Acme. All rights reserved.\nThis software is proprietary and confidential.\n",
		"m.go":    "package mystery\n\nfunc X() {}\n",
	})
	w.DepsDev["v3/systems/go/packages/example.com/nolicense/versions/v1.0.0"] = map[string]any{"licenses": []string{"BSD-3-Clause"}}
	w.DepsDev["v3/systems/go/packages/example.com/mitlib/versions/v1.0.0"] = map[string]any{"licenses": []string{"MIT"}}
	dir := w.Project(map[string]string{
		"go.mod": testenv.GoModFile("example.com/main", "1.22",
			"example.com/mitlib@v1.0.0", "example.com/gpllib@v1.2.0", "example.com/apachelib@v0.3.0",
			"example.com/nolicense@v1.0.0", "example.com/mystery@v1.0.0"),
		"main.go": "package main\n\nimport (\n\t\"example.com/apachelib\"\n\t\"example.com/gpllib\"\n)\n\nfunc main() { println(apachelib.A(), gpllib.G()) }\n",
	})
	return w, dir
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustContain(t *testing.T, what, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Errorf("%s does not contain %q:\n%s", what, sub, s)
		}
	}
}

func tempPath(t *testing.T, name string) string {
	return filepath.Join(t.TempDir(), name)
}

// goSum runs `go mod tidy` in dir with the world's environment.
func goTidy(t *testing.T, w *testenv.World, dir string) {
	t.Helper()
	if out, err := w.Go(dir, "mod", "tidy"); err != nil {
		t.Fatalf("go mod tidy: %v\n%s", err, out)
	}
}

func sortStrings(s []string) { sort.Strings(s) }
