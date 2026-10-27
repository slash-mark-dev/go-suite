package verify

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	xmodule "golang.org/x/mod/module"
	xdirhash "golang.org/x/mod/sumdb/dirhash"
	xzip "golang.org/x/mod/zip"

	"github.com/slash-mark-dev/go-suite/internal/tools/security"
)

// TestRepoArchiveMatchesXModZip checks that retag rebuilds module zips from
// repository archives with the same file selection as x/mod/zip (vendored
// packages, the nested-vendor quirk, nested modules, VCS directories).
func TestRepoArchiveMatchesXModZip(t *testing.T) {
	tree := map[string]string{
		"go.mod":                    "module example.com/m\n\ngo 1.21\n",
		"m.go":                      "package m\n",
		"LICENSE":                   "BSD\n",
		"vendor/modules.txt":        "# example.com/v v1.0.0\n",
		"vendor/example.com/v/v.go": "package v\n",
		"vendor/top.go":             "package vendor\n",
		"pkg/vendor/x/x.go":         "package x\n",
		"pkg/vendor/y.go":           "package vendor\n",
		"pkg/a.go":                  "package pkg\n",
		"nested/go.mod":             "module example.com/m/nested\n",
		"nested/n.go":               "package nested\n",
		"nested/deep/d.go":          "package deep\n",
		"testdata/go.mod.txt":       "not a go.mod\n",
		".git/config":               "[core]\n",
		"docs/.svn/entries":         "x\n",
	}
	dir := t.TempDir()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range tree {
		p := filepath.Join(dir, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		w, _ := zw.Create("owner-repo-abcdef0/" + name)
		w.Write([]byte(content))
	}
	zw.Close()

	mv := xmodule.Version{Path: "example.com/m", Version: "v1.0.0"}
	var out bytes.Buffer
	if err := xzip.CreateFromDir(&out, mv, dir); err != nil {
		t.Fatal(err)
	}
	zf := filepath.Join(t.TempDir(), "m.zip")
	os.WriteFile(zf, out.Bytes(), 0o644)
	want, err := xdirhash.HashZip(zf, xdirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	got, err := security.HashRepoArchive(buf.Bytes(), mv.Path, mv.Version, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("HashRepoArchive = %s, x/mod/zip = %s", got, want)
	}
}
