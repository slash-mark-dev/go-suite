package e2e

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

// TestOfflineNoNetwork runs tools that use the go command with --offline
// (and SMGO_OFFLINE=1) against an empty module cache and an empty sm-go
// cache: the fake server must receive no request at all, and each tool
// must either succeed from what is cached or fail cleanly with exit 3.
func TestOfflineNoNetwork(t *testing.T) {
	w := testenv.New(t)
	for _, v := range []string{"v1.0.0", "v1.1.0"} {
		w.AddModule("github.com/pub/util", v, map[string]string{"LICENSE": mitText,
			"util.go": "package util\n\nfunc F() string { return \"" + v + "\" }\n"})
	}
	dir := w.Project(map[string]string{
		"go.mod":  testenv.GoModFile("example.com/app", "1.21", "github.com/pub/util@v1.0.0"),
		"main.go": "package main\n\nimport \"github.com/pub/util\"\n\nfunc main() { println(util.F()) }\n",
	})
	if out, err := w.Go(dir, "mod", "tidy"); err != nil {
		t.Fatalf("go mod tidy: %v\n%s", err, out)
	}

	runs := [][]string{
		{"unused"},
		{"why", "github.com/pub/util"},
		{"license"},
		{"vuln"},
		{"gate"},
		{"caps"},
		{"cgo", "--verify"},
		{"apidiff", "github.com/pub/util@v1.0.0", "github.com/pub/util@v1.1.0"},
		{"initscan"},
	}
	for _, mode := range []string{"--offline", "SMGO_OFFLINE=1"} {
		for _, args := range runs {
			// A fresh, empty module cache and sm-go cache for every run.
			extra := []string{"GOMODCACHE=" + modCacheDir(t), "SMGO_CACHE_DIR=" + t.TempDir()}
			full := append([]string{}, args...)
			if mode == "--offline" {
				full = append(full, "--offline")
			} else {
				extra = append(extra, mode)
			}
			before := len(w.Requests)
			r := w.RunEnv(dir, extra, append(full, "--json")...)
			if r.Code != 0 && r.Code != 1 && r.Code != 3 {
				t.Errorf("%s sm-go %s: exit %d\n%s\n%s", mode, strings.Join(args, " "), r.Code, r.Stdout, r.Stderr)
			}
			r.JSON(t) // a well-formed envelope, even on failure
			if reqs := w.Requests[before:]; len(reqs) > 0 {
				t.Errorf("%s sm-go %s: %d network requests in offline mode:\n%s", mode, strings.Join(args, " "), len(reqs), strings.Join(reqs, "\n"))
			}
		}
	}

	// A populated module cache without checksum database tiles: with
	// GOPROXY=off alone the go command would still ask the checksum
	// database about modules missing from go.sum (apidiff builds a
	// throwaway module without go.sum).
	mc := modCacheDir(t)
	if out, err := w.GoEnv(dir, []string{"GOMODCACHE=" + mc}, "mod", "download", "github.com/pub/util@v1.0.0", "github.com/pub/util@v1.1.0"); err != nil {
		t.Fatalf("go mod download: %v\n%s", err, out)
	}
	if err := os.RemoveAll(filepath.Join(mc, "cache", "download", "sumdb")); err != nil {
		t.Fatal(err)
	}
	before := len(w.Requests)
	r := w.RunEnv(dir, []string{"GOMODCACHE=" + mc, "SMGO_CACHE_DIR=" + t.TempDir()},
		"apidiff", "github.com/pub/util@v1.0.0", "github.com/pub/util@v1.1.0", "--offline")
	if r.Code != 0 {
		t.Errorf("apidiff from the module cache: exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	if reqs := w.Requests[before:]; len(reqs) > 0 {
		t.Errorf("apidiff --offline with a populated cache made requests:\n%s", strings.Join(reqs, "\n"))
	}

	// Private modules: GOPROXY=off alone still lets the go command fetch
	// GOPRIVATE modules directly from their hosts.
	r = w.RunEnv(dir, []string{"GOPRIVATE=corp.example.com", "GOMODCACHE=" + modCacheDir(t), "SMGO_CACHE_DIR=" + t.TempDir()},
		"apidiff", "corp.example.com/lib@v1.0.0", "corp.example.com/lib@v1.1.0", "--offline")
	if r.Code != 3 {
		t.Errorf("apidiff of an uncached private module offline: exit %d, want 3\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	if out := r.Stdout + r.Stderr; strings.Contains(out, "go-get=1") || strings.Contains(out, "https fetch") || strings.Contains(out, "git ") {
		t.Errorf("the go command tried to fetch a private module directly:\n%s", out)
	}
}

// modCacheDir returns a temporary GOMODCACHE. The go command makes module
// cache files read-only, so t.TempDir's cleanup fails for non-root users
// unless the tree is made writable first (cleanups run last-in first-out).
func modCacheDir(t *testing.T) string {
	dir := t.TempDir()
	t.Cleanup(func() {
		filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err == nil {
				mode := os.FileMode(0o644)
				if d.IsDir() {
					mode = 0o755
				}
				os.Chmod(path, mode)
			}
			return nil
		})
	})
	return dir
}
