package security_test

import (
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"

	_ "github.com/slash-mark-dev/go-suite/internal/tools/security"
)

// mustDownload runs `go mod download` (which also writes go.sum) in dir.
func mustDownload(t *testing.T, w *testenv.World, dir string) {
	t.Helper()
	if out, err := w.Go(dir, "mod", "download", "all"); err != nil {
		t.Fatalf("go mod download: %v\n%s", err, out)
	}
}

// expectCode fails the test if r exited with a different code.
func expectCode(t *testing.T, r testenv.Result, want int) {
	t.Helper()
	if r.Code != want {
		t.Fatalf("exit code %d, want %d\nstdout:\n%s\nstderr:\n%s", r.Code, want, r.Stdout, r.Stderr)
	}
}

func contains(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Fatalf("output does not contain %q:\n%s", sub, s)
	}
}
