package origin_test

import (
	"strings"
	"testing"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/testenv"

	_ "github.com/slash-mark-dev/go-suite/internal/tools/origin"
)

// project writes a main module requiring reqs ("path@version").
func project(w *testenv.World, reqs ...string) string {
	return w.Project(map[string]string{"go.mod": testenv.GoModFile("example.com/main", "1.22", reqs...)})
}

// rdap registers an RDAP record expiring at exp.
func rdap(w *testenv.World, domain string, exp time.Time, status ...string) {
	if status == nil {
		status = []string{"active"}
	}
	w.RDAP["domain/"+domain] = map[string]any{
		"ldhName": strings.ToUpper(domain), "status": status,
		"events": []map[string]any{
			{"eventAction": "registration", "eventDate": "2015-03-01T00:00:00Z"},
			{"eventAction": "expiration", "eventDate": exp.UTC().Format(time.RFC3339)},
		},
	}
}

func vanityPage(prefix, vcs, repo string) string {
	return `<!DOCTYPE html><html><head><meta name="go-import" content="` + prefix + ` ` + vcs + ` ` + repo + `"></head><body>go get ` + prefix + `</body></html>`
}

type finding struct {
	Severity string `json:"severity"`
	Rule     string `json:"rule"`
	Module   string `json:"module"`
	Title    string `json:"title"`
	Fix      string `json:"fix"`
}

func rules(fs []finding, module string) map[string]string {
	m := map[string]string{}
	for _, f := range fs {
		if module == "" || f.Module == module {
			m[f.Rule] = f.Severity
		}
	}
	return m
}

func checkEnvelope(t *testing.T, r testenv.Result, tool string, code int) {
	t.Helper()
	if r.Code != code {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", r.Code, code, r.Stdout, r.Stderr)
	}
	env := r.JSON(t)
	if env["tool"] != tool || int(env["exitCode"].(float64)) != code || env["ok"] != (code == 0) {
		t.Fatalf("envelope = %v", env)
	}
}

func TestHelpRegistered(t *testing.T) {
	w := testenv.New(t)
	for _, tool := range []string{"takeover", "vanity", "retract", "health"} {
		r := w.Run("", "help", tool)
		if r.Code != 0 || !strings.Contains(r.Stdout, "sm-go "+tool) || !strings.Contains(r.Stdout, "Examples:") {
			t.Errorf("help %s: code %d\n%s", tool, r.Code, r.Stdout)
		}
	}
	r := w.Run("", "help")
	if !strings.Contains(r.Stdout, "ORIGIN & TRUST") {
		t.Errorf("overview lacks group:\n%s", r.Stdout)
	}
}

func TestNoModuleIsUsageError(t *testing.T) {
	w := testenv.New(t)
	dir := t.TempDir()
	for _, tool := range []string{"takeover", "vanity", "retract", "health"} {
		r := w.Run(dir, tool, "--json")
		checkEnvelope(t, r, tool, 2)
	}
}

func TestBadArgsUsageError(t *testing.T) {
	w := testenv.New(t)
	for _, args := range [][]string{
		{"takeover", "not a path"},
		{"takeover", "--fail-on", "bogus", "github.com/a/b"},
		{"takeover", "--expiry-days", "-1", "github.com/a/b"},
		{"vanity", "example.org/x@notaversion"},
		{"retract", "Bad Path"},
		{"health", "--min-score", "101", "github.com/a/b"},
		{"health", "--min-score", "-1", "github.com/a/b"},
	} {
		r := w.Run("", append(args, "--json")...)
		if r.Code != 2 {
			t.Errorf("%v: exit %d, want 2\n%s%s", args, r.Code, r.Stdout, r.Stderr)
		}
	}
}
