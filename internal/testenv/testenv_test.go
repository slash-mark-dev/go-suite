package testenv_test

import (
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

// TestRealGoAcceptsWorld checks that the real go command downloads modules
// from the fake proxy and verifies them against the fake checksum
// database (which exercises our transparency-log tiles and note signing
// against cmd/go's own client).
func TestRealGoAcceptsWorld(t *testing.T) {
	w := testenv.New(t)
	w.AddModule("example.com/a", "v1.0.0", map[string]string{
		"go.mod": testenv.GoModFile("example.com/a", "1.21", "example.com/b@v1.1.0"),
		"a.go":   "package a\n\nimport \"example.com/b\"\n\nfunc A() string { return b.B() }\n",
	})
	for i, v := range []string{"v1.0.0", "v1.1.0", "v1.2.0"} {
		_ = i
		w.AddModule("example.com/b", v, map[string]string{"b.go": "package b\n\nfunc B() string { return \"" + v + "\" }\n"})
	}
	// Pre-populate the log with many records so tiles have several levels.
	for i := 0; i < 300; i++ {
		p := "example.com/filler" + strings.Repeat("x", i%7) + string(rune('a'+i%26))
		v := "v1.0." + itoa(i)
		w.AddModule(p, v, nil)
		w.AddSumRecord(p, v)
	}
	dir := w.Project(map[string]string{
		"go.mod":  testenv.GoModFile("example.com/main", "1.22", "example.com/a@v1.0.0"),
		"main.go": "package main\n\nimport (\n\t\"fmt\"\n\t\"example.com/a\"\n)\n\nfunc main() { fmt.Println(a.A()) }\n",
	})
	out, err := w.Go(dir, "run", ".")
	if err != nil {
		t.Fatalf("go run: %v\n%s", err, out)
	}
	if !strings.HasSuffix(strings.TrimSpace(out), "v1.1.0") {
		t.Fatalf("unexpected output %q", out)
	}
	var lookups, tiles int
	for _, r := range w.Requests {
		if strings.Contains(r, "/sumdb/lookup/") {
			lookups++
		}
		if strings.Contains(r, "/sumdb/tile/") {
			tiles++
		}
	}
	if lookups == 0 || tiles == 0 {
		t.Fatalf("go did not verify against the checksum database (lookups=%d tiles=%d)", lookups, tiles)
	}
}

func itoa(i int) string {
	s := ""
	if i == 0 {
		return "0"
	}
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}
