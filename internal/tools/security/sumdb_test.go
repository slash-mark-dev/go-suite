package security_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

type sumdbJSON struct {
	Database string `json:"database"`
	Disabled string `json:"disabled"`
	Tree     *struct {
		Size int64  `json:"size"`
		Hash string `json:"hash"`
	} `json:"tree"`
	Checks []struct {
		Source   string `json:"source"`
		Status   string `json:"status"`
		Previous *struct {
			Size int64 `json:"size"`
		} `json:"previous"`
	} `json:"treeChecks"`
	Entries []struct {
		Module   string `json:"module"`
		Version  string `json:"version"`
		Kind     string `json:"kind"`
		Line     int    `json:"line"`
		Hash     string `json:"hash"`
		LogHash  string `json:"logHash"`
		Status   string `json:"status"`
		RecordID int64  `json:"recordId"`
	} `json:"entries"`
	Summary  map[string]int `json:"summary"`
	Findings []struct {
		Severity string `json:"severity"`
		Rule     string `json:"rule"`
		Module   string `json:"module"`
		Line     int    `json:"line"`
	} `json:"findings"`
	Failing int `json:"failing"`
}

func (r *sumdbJSON) check(source string) string {
	for _, c := range r.Checks {
		if c.Source == source {
			return c.Status
		}
	}
	return ""
}

func (r *sumdbJSON) status(mod, kind string) string {
	for _, e := range r.Entries {
		if e.Module == mod && e.Kind == kind {
			return e.Status
		}
	}
	return ""
}

func sumdbWorld(t *testing.T) (*testenv.World, string) {
	w := testenv.New(t)
	w.AddModule("example.com/a", "v1.0.0", map[string]string{
		"go.mod": testenv.GoModFile("example.com/a", "1.21", "example.com/b@v1.0.0"),
		"a.go":   "package a\n\nimport _ \"example.com/b\"\n",
	})
	w.AddModule("example.com/b", "v1.0.0", map[string]string{"b.go": "package b\n"})
	// Records of other modules make the tree several tiles high.
	for i := 0; i < 40; i++ {
		p := "example.com/filler" + string(rune('a'+i%26)) + strings.Repeat("x", i/26)
		w.AddModule(p, "v1.0.0", nil)
		w.AddSumRecord(p, "v1.0.0")
	}
	dir := w.Project(map[string]string{
		"go.mod": testenv.GoModFile("example.com/app", "1.22", "example.com/a@v1.0.0"),
		"app.go": "package app\n\nimport _ \"example.com/a\"\n",
	})
	mustDownload(t, w, dir)
	return w, dir
}

func editGoSum(t *testing.T, dir string, edit func(string) string) {
	t.Helper()
	p := filepath.Join(dir, "go.sum")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(edit(string(b))), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSumdbVerified(t *testing.T) {
	w, dir := sumdbWorld(t)
	r := w.Run(dir, "sumdb", "--json")
	expectCode(t, r, 0)
	var res sumdbJSON
	r.Decode(t, &res)
	if res.Database != "sum.test.invalid" || res.Tree == nil || res.Tree.Size < 42 {
		t.Fatalf("header: %+v", res)
	}
	if len(res.Entries) != 4 || res.Summary["verified"] != 4 {
		t.Fatalf("entries: %+v", res.Entries)
	}
	for _, e := range res.Entries {
		if e.LogHash != e.Hash || e.Line == 0 {
			t.Errorf("entry %+v", e)
		}
	}
	// First run: no previous sm-go head; the go command cached one when it
	// downloaded the modules.
	if res.check("sm-go") != "none" || res.check("go") != "consistent" {
		t.Errorf("checks = %+v", res.Checks)
	}
	// The log grows; the second run proves the new head extends the old.
	w.AddModule("example.com/late", "v1.0.0", nil)
	w.AddSumRecord("example.com/late", "v1.0.0")
	r = w.Run(dir, "sumdb", "--json")
	expectCode(t, r, 0)
	res = sumdbJSON{}
	r.Decode(t, &res)
	if res.check("sm-go") != "consistent" || res.Checks[0].Previous == nil || res.Checks[0].Previous.Size >= res.Tree.Size {
		t.Errorf("second run checks = %+v tree %+v", res.Checks, res.Tree)
	}
	r = w.Run(dir, "sumdb", "--all")
	expectCode(t, r, 0)
	contains(t, r.Stdout, "append-only since sm-go's previous tree head")
	contains(t, r.Stdout, "4 verified")
	contains(t, r.Stdout, "example.com/b")
}

func TestSumdbMismatchAndMissing(t *testing.T) {
	w, dir := sumdbWorld(t)
	good := w.SumLines("example.com/b", "v1.0.0")
	editGoSum(t, dir, func(s string) string {
		bad := strings.Fields(good[0])[2]
		s = strings.Replace(s, bad, "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", 1)
		return s + "example.com/ghost v1.0.0/go.mod h1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n" +
			"example.com/a v1.0.0/go.mod h2:notreally\n"
	})
	r := w.Run(dir, "sumdb", "--json")
	expectCode(t, r, 1)
	var res sumdbJSON
	r.Decode(t, &res)
	if res.status("example.com/b", "zip") != "mismatch" || res.status("example.com/b", "go.mod") != "verified" {
		t.Errorf("b statuses: %+v", res.Entries)
	}
	if res.status("example.com/ghost", "go.mod") != "missing" {
		t.Errorf("ghost: %+v", res.Entries)
	}
	if res.Summary["unsupported"] != 1 || res.Summary["mismatch"] != 1 || res.Summary["missing"] != 1 {
		t.Errorf("summary = %v", res.Summary)
	}
	if res.Findings[0].Severity != "critical" || res.Findings[0].Rule != "sumdb/mismatch" || res.Findings[0].Line == 0 {
		t.Errorf("first finding = %+v", res.Findings[0])
	}
	if res.Failing != 2 {
		t.Errorf("failing = %d, want 2 (mismatch and missing)", res.Failing)
	}
	r = w.Run(dir, "sumdb")
	contains(t, r.Stdout, "hash differs from the checksum database")
	contains(t, r.Stdout, "is not in the checksum database")

	// GONOSUMDB excludes the unknown module, like the go command.
	r = w.RunEnv(dir, []string{"GONOSUMDB=example.com/ghost"}, "sumdb", "--json")
	res = sumdbJSON{}
	r.Decode(t, &res)
	if res.status("example.com/ghost", "go.mod") != "excluded" {
		t.Errorf("GONOSUMDB: %+v", res.Entries)
	}
	r = w.RunEnv(dir, []string{"GOPRIVATE=example.com/b,example.com/ghost"}, "sumdb", "--json")
	expectCode(t, r, 0)
}

func TestSumdbDisabled(t *testing.T) {
	w, dir := sumdbWorld(t)
	for _, env := range [][]string{{"GOSUMDB=off"}, {"GOFLAGS=-mod=mod -insecure"}} {
		r := w.RunEnv(dir, env, "sumdb", "--json")
		expectCode(t, r, 0)
		var res sumdbJSON
		r.Decode(t, &res)
		if res.Disabled == "" || res.Summary["excluded"] != 4 || len(res.Findings) != 1 || res.Findings[0].Severity != "low" {
			t.Errorf("%v: %+v", env, res)
		}
		if !strings.Contains(r.Stdout, "disabled") {
			t.Errorf("%v: no warning in envelope", env)
		}
	}
	r := w.RunEnv(dir, []string{"GOSUMDB=off"}, "sumdb", "--fail-on", "low")
	expectCode(t, r, 1)
	r = w.RunEnv(dir, []string{"GOSUMDB=bad+key+here"}, "sumdb")
	expectCode(t, r, 2)
	r = w.Run(dir, "sumdb", "extra")
	expectCode(t, r, 2)
}

func TestSumdbForkedLog(t *testing.T) {
	w, dir := sumdbWorld(t)
	r := w.Run(dir, "sumdb", "--json")
	expectCode(t, r, 0)
	w.ForkTree()
	r = w.Run(dir, "sumdb", "--json")
	expectCode(t, r, 1)
	var res sumdbJSON
	r.Decode(t, &res)
	if res.check("sm-go") != "forked" {
		t.Errorf("checks = %+v", res.Checks)
	}
	if res.Findings[0].Rule != "sumdb/forked" || res.Findings[0].Severity != "critical" {
		t.Errorf("findings = %+v", res.Findings)
	}
	if res.Summary["inconsistent"] != 4 {
		t.Errorf("summary = %v", res.Summary)
	}
	r = w.Run(dir, "sumdb")
	contains(t, r.Stdout, "FORKED")
}

func TestSumdbForkedAgainstGoCache(t *testing.T) {
	// sm-go has never seen the log; the go command has.
	w, dir := sumdbWorld(t)
	w.ForkTree()
	r := w.Run(dir, "sumdb", "--json")
	expectCode(t, r, 1)
	var res sumdbJSON
	r.Decode(t, &res)
	if res.check("go") != "forked" || res.check("sm-go") != "none" {
		t.Errorf("checks = %+v", res.Checks)
	}
}

func TestSumdbUnreachable(t *testing.T) {
	w, dir := sumdbWorld(t)
	r := w.RunEnv(dir, []string{"GOSUMDB=" + w.VerifierKey + " http://127.0.0.1:1", "GOPROXY=off"}, "sumdb", "--json", "--timeout", "2s")
	expectCode(t, r, 3)
}
