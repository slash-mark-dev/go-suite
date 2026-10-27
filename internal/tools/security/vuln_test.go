package security_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
	"github.com/slash-mark-dev/go-suite/internal/vulndb"
)

type vulnJSON struct {
	Mode        string `json:"mode"`
	FailOn      string `json:"failOn"`
	MinSeverity string `json:"minSeverity"`
	GoVersion   string `json:"goVersion"`
	Modules     int    `json:"modules"`
	Packages    int    `json:"packages"`
	Vulns       []struct {
		ID             string   `json:"id"`
		Module         string   `json:"module"`
		Version        string   `json:"version"`
		FixedIn        string   `json:"fixedIn"`
		Status         string   `json:"status"`
		Severity       string   `json:"severity"`
		SeveritySource string   `json:"severitySource"`
		Symbol         string   `json:"symbol"`
		Failing        bool     `json:"failing"`
		ReplacementOf  string   `json:"replacementOf"`
		CVEs           []string `json:"cves"`
		KEV            *struct {
			CVE string `json:"cveID"`
		} `json:"kev"`
		EPSS *struct {
			EPSS float64 `json:"epss"`
		} `json:"epss"`
		CallPath []struct {
			Func string `json:"func"`
			Pos  string `json:"pos"`
		} `json:"callPath"`
		Fix string `json:"fix"`
	} `json:"vulns"`
	Summary struct {
		Total          int            `json:"total"`
		Called         int            `json:"called"`
		Imported       int            `json:"imported"`
		Required       int            `json:"required"`
		Affected       int            `json:"affected"`
		Failing        int            `json:"failing"`
		BelowThreshold int            `json:"belowThreshold"`
		BySeverity     map[string]int `json:"bySeverity"`
	} `json:"summary"`
}

func (r *vulnJSON) byID(t *testing.T, id string) int {
	t.Helper()
	for i, v := range r.Vulns {
		if v.ID == id {
			return i
		}
	}
	t.Fatalf("vulnerability %s not reported: %+v", id, r.Vulns)
	return -1
}

// vulnWorld publishes:
//
//	example.com/vlib v1.0.0: package vlib (Bad, Good, Unused) and vlib/other
//	example.com/vlib v1.2.0: the fixed version
//	example.com/clean v1.0.0
//
// and four vulnerabilities in the database:
//
//	GO-2025-0001 vlib.Bad      (reached: main -> helper -> vlib.Bad), CVE in KEV
//	GO-2025-0002 vlib.Unused   (vlib imported, Unused unreachable), high EPSS
//	GO-2025-0003 vlib/other    (package not imported)
//	GO-2025-0004 clean         (fixed long ago; not affecting)
func vulnWorld(t *testing.T) (*testenv.World, string) {
	w := testenv.New(t)
	for _, v := range []string{"v1.0.0", "v1.2.0"} {
		w.AddModule("example.com/vlib", v, map[string]string{
			"vlib.go": `package vlib

import "strings"

func Bad(s string) string { return strings.ToUpper(s) }

func Good() int { return 1 }

func Unused() {}

type T struct{}

func (*T) Method() {}
`,
			"other/other.go": "package other\n\nfunc X() {}\n",
		})
	}
	w.AddModule("example.com/clean", "v1.0.0", map[string]string{"clean.go": "package clean\n\nfunc C() {}\n"})
	w.AddVuln(testenv.SimpleVuln("GO-2025-0001", "example.com/vlib", "v0.0.0", "v1.1.0", "example.com/vlib", []string{"Bad"}, "CVE-2025-0001"))
	w.AddVuln(testenv.SimpleVuln("GO-2025-0002", "example.com/vlib", "v0.0.0", "v1.2.0", "example.com/vlib", []string{"Unused", "T.Method"}, "CVE-2025-0002"))
	w.AddVuln(testenv.SimpleVuln("GO-2025-0003", "example.com/vlib", "v1.0.0", "v1.2.0", "example.com/vlib/other", nil))
	w.AddVuln(testenv.SimpleVuln("GO-2025-0004", "example.com/clean", "v0.0.0", "v0.5.0", "example.com/clean", nil))
	w.KEV = append(w.KEV, map[string]string{"cveID": "CVE-2025-0001", "vulnerabilityName": "vlib Bad"})
	w.EPSS["CVE-2025-0002"] = [2]float64{0.42, 0.97}
	dir := w.Project(map[string]string{
		"go.mod": testenv.GoModFile("example.com/app", "1.22", "example.com/vlib@v1.0.0", "example.com/clean@v1.0.0"),
		"main.go": `package main

import (
	"fmt"

	"example.com/clean"
	"example.com/vlib"
)

func main() {
	clean.C()
	fmt.Println(helper(), vlib.Good())
}

func helper() string { return vlib.Bad("x") }
`,
	})
	mustDownload(t, w, dir)
	return w, dir
}

func TestVulnReachability(t *testing.T) {
	w, dir := vulnWorld(t)
	r := w.Run(dir, "vuln", "--json")
	expectCode(t, r, 1)
	var res vulnJSON
	r.Decode(t, &res)
	if res.Mode != "source" || res.FailOn != "called" || res.Packages == 0 {
		t.Fatalf("unexpected header: %+v", res)
	}
	if !strings.HasPrefix(res.GoVersion, "go1.") {
		t.Errorf("goVersion = %q", res.GoVersion)
	}
	v1 := res.Vulns[res.byID(t, "GO-2025-0001")]
	if v1.Status != "called" || v1.Symbol != "example.com/vlib.Bad" || !v1.Failing {
		t.Errorf("GO-2025-0001: %+v", v1)
	}
	if v1.Severity != "critical" || v1.SeveritySource != "kev" || v1.KEV == nil {
		t.Errorf("GO-2025-0001 not raised by KEV: severity=%s source=%s", v1.Severity, v1.SeveritySource)
	}
	var funcs []string
	for _, f := range v1.CallPath {
		funcs = append(funcs, f.Func)
	}
	want := []string{"example.com/app.main", "example.com/app.helper", "example.com/vlib.Bad"}
	if strings.Join(funcs, " ") != strings.Join(want, " ") {
		t.Errorf("call path = %v, want %v", funcs, want)
	}
	if v1.CallPath[1].Pos != "main.go:12" || v1.CallPath[2].Pos != "main.go:15" {
		t.Errorf("call path positions = %+v", v1.CallPath)
	}
	if v1.Fix != "go get example.com/vlib@v1.1.0" {
		t.Errorf("fix = %q", v1.Fix)
	}
	v2 := res.Vulns[res.byID(t, "GO-2025-0002")]
	if v2.Status != "imported" || v2.Failing || len(v2.CallPath) != 0 {
		t.Errorf("GO-2025-0002: %+v", v2)
	}
	if v2.Severity != "high" || v2.SeveritySource != "epss" || v2.EPSS == nil || v2.EPSS.EPSS != 0.42 {
		t.Errorf("GO-2025-0002 not raised by EPSS: %+v", v2)
	}
	v3 := res.Vulns[res.byID(t, "GO-2025-0003")]
	if v3.Status != "required-only" || v3.Failing {
		t.Errorf("GO-2025-0003: %+v", v3)
	}
	for _, v := range res.Vulns {
		if v.ID == "GO-2025-0004" {
			t.Errorf("GO-2025-0004 does not affect clean@v1.0.0 but was reported")
		}
	}
	s := res.Summary
	if s.Called != 1 || s.Imported != 1 || s.Required != 1 || s.Failing != 1 || s.Total != 3 {
		t.Errorf("summary = %+v", s)
	}
	// Called vulnerabilities come first.
	if res.Vulns[0].ID != "GO-2025-0001" {
		t.Errorf("order: first is %s", res.Vulns[0].ID)
	}
}

func TestVulnFailOnAndMinSeverity(t *testing.T) {
	w, dir := vulnWorld(t)

	r := w.Run(dir, "vuln", "--json", "--fail-on", "none")
	expectCode(t, r, 0)

	r = w.Run(dir, "vuln", "--json", "--fail-on", "imported")
	expectCode(t, r, 1)
	var res vulnJSON
	r.Decode(t, &res)
	if res.Summary.Failing != 2 {
		t.Errorf("--fail-on imported: failing = %d, want 2", res.Summary.Failing)
	}

	r = w.Run(dir, "vuln", "--json", "--fail-on", "any")
	res = vulnJSON{}
	r.Decode(t, &res)
	if res.Summary.Failing != 3 {
		t.Errorf("--fail-on any: failing = %d, want 3", res.Summary.Failing)
	}

	// Only the KEV entry is critical.
	r = w.Run(dir, "vuln", "--json", "--min-severity", "critical", "--fail-on", "any")
	expectCode(t, r, 1)
	res = vulnJSON{}
	r.Decode(t, &res)
	if len(res.Vulns) != 1 || res.Vulns[0].ID != "GO-2025-0001" || res.Summary.BelowThreshold != 2 {
		t.Errorf("--min-severity critical: %+v", res)
	}

	// The high EPSS entry is imported only: --min-severity high with the
	// default --fail-on called still fails because of the KEV entry, and
	// passes when only the imported one is left.
	r = w.Run(dir, "vuln", "--json", "--min-severity", "high", "--fail-on", "called")
	expectCode(t, r, 1)

	for _, bad := range [][]string{{"--fail-on", "sometimes"}, {"--min-severity", "urgent"}, {"--mode", "binary"}} {
		r = w.Run(dir, append([]string{"vuln", "--json"}, bad...)...)
		expectCode(t, r, 2)
	}
}

func TestVulnText(t *testing.T) {
	w, dir := vulnWorld(t)
	r := w.Run(dir, "vuln")
	expectCode(t, r, 1)
	contains(t, r.Stdout, "Called vulnerabilities")
	contains(t, r.Stdout, "GO-2025-0001")
	contains(t, r.Stdout, "example.com/app.helper")
	contains(t, r.Stdout, "KEV")
	contains(t, r.Stdout, "Not listed: 1 imported, 1 required-only")
	contains(t, r.Stdout, "go get example.com/vlib@v1.1.0")
	if strings.Contains(r.Stdout, "GO-2025-0003") {
		t.Errorf("required-only vulnerability listed without --show-all")
	}
	r = w.Run(dir, "vuln", "--show-all")
	contains(t, r.Stdout, "Imported but not called")
	contains(t, r.Stdout, "GO-2025-0002")
	contains(t, r.Stdout, "GO-2025-0003")
}

func TestVulnModuleMode(t *testing.T) {
	w, dir := vulnWorld(t)
	r := w.Run(dir, "vuln", "--json", "--mode", "module")
	expectCode(t, r, 1)
	var res vulnJSON
	r.Decode(t, &res)
	if res.Packages != 0 || res.Summary.Affected != 3 {
		t.Fatalf("module mode: %+v", res.Summary)
	}
	for _, v := range res.Vulns {
		if v.Status != "affected" || !v.Failing {
			t.Errorf("%s: status %s failing %v", v.ID, v.Status, v.Failing)
		}
	}
}

func TestVulnStdlibAndReplace(t *testing.T) {
	w := testenv.New(t)
	w.AddModule("example.com/orig", "v1.0.0", map[string]string{"orig.go": "package orig\n\nfunc F() {}\n"})
	w.AddModule("example.com/fork", "v1.5.0", map[string]string{
		"go.mod":  "module example.com/orig\n\ngo 1.21\n",
		"orig.go": "package orig\n\nfunc F() { G() }\n\nfunc G() {}\n",
	})
	w.AddVuln(testenv.SimpleVuln("GO-2025-0100", "example.com/fork", "v1.0.0", "v1.6.0", "example.com/fork", []string{"G"}))
	w.AddVuln(testenv.SimpleVuln("GO-2025-0101", "example.com/orig", "v1.0.0", "v1.1.0", "example.com/orig", []string{"F"}))
	// A standard library vulnerability affecting every Go version.
	w.AddVuln(testenv.SimpleVuln("GO-2025-0200", vulndb.Stdlib, "v1.0.0", "v1.99.0", "net/url", []string{"Parse"}))
	dir := w.Project(map[string]string{
		"go.mod": testenv.GoModFile("example.com/app", "1.22", "example.com/orig@v1.0.0") +
			"\nreplace example.com/orig v1.0.0 => example.com/fork v1.5.0\n",
		"main.go": `package main

import (
	"net/url"

	"example.com/orig"
)

func main() {
	orig.F()
	_, _ = url.Parse("https://example.com")
}
`,
	})
	mustDownload(t, w, dir)
	r := w.Run(dir, "vuln", "--json")
	expectCode(t, r, 1)
	var res vulnJSON
	r.Decode(t, &res)
	fork := res.Vulns[res.byID(t, "GO-2025-0100")]
	if fork.Status != "called" || fork.ReplacementOf != "example.com/orig" || fork.Symbol != "example.com/orig.G" {
		t.Errorf("replacement vuln: %+v", fork)
	}
	for _, v := range res.Vulns {
		if v.ID == "GO-2025-0101" {
			t.Errorf("vulnerability of the replaced (unused) original version reported")
		}
	}
	std := res.Vulns[res.byID(t, "GO-2025-0200")]
	if std.Status != "called" || std.Symbol != "net/url.Parse" || !strings.HasPrefix(std.Fix, "upgrade Go to go1.99") {
		t.Errorf("stdlib vuln: %+v", std)
	}
	// --go selects the standard library version explicitly.
	r = w.Run(dir, "vuln", "--json", "--go", "go1.99.1")
	res = vulnJSON{}
	r.Decode(t, &res)
	for _, v := range res.Vulns {
		if v.ID == "GO-2025-0200" {
			t.Errorf("GO-2025-0200 reported for go1.99.1")
		}
	}
	r = w.Run(dir, "vuln", "--json", "--go", "banana")
	expectCode(t, r, 2)
}

func TestVulnClean(t *testing.T) {
	w := testenv.New(t)
	w.AddModule("example.com/clean", "v1.0.0", map[string]string{"clean.go": "package clean\n\nfunc C() {}\n"})
	dir := w.Project(map[string]string{
		"go.mod":  testenv.GoModFile("example.com/app", "1.22", "example.com/clean@v1.0.0"),
		"main.go": "package main\n\nimport \"example.com/clean\"\n\nfunc main() { clean.C() }\n",
	})
	mustDownload(t, w, dir)
	r := w.Run(dir, "vuln", "--json")
	expectCode(t, r, 0)
	var res vulnJSON
	r.Decode(t, &res)
	if len(res.Vulns) != 0 || res.Summary.Total != 0 {
		t.Fatalf("clean project: %+v", res)
	}
	r = w.Run(dir, "vuln")
	expectCode(t, r, 0)
	contains(t, r.Stdout, "none")
}

// Positions stay relative to the project when it is reached through a
// symbolic link (on macOS the temporary directory /var/... is
// /private/var/...): the go command must see the same working directory.
func TestVulnSymlinkedProject(t *testing.T) {
	w, dir := vulnWorld(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	r := w.Run(link, "vuln", "--json")
	expectCode(t, r, 1)
	var res vulnJSON
	r.Decode(t, &res)
	v1 := res.Vulns[res.byID(t, "GO-2025-0001")]
	if len(v1.CallPath) != 3 || v1.CallPath[1].Pos != "main.go:12" || v1.CallPath[2].Pos != "main.go:15" {
		t.Errorf("call path through %s = %+v", link, v1.CallPath)
	}
}
