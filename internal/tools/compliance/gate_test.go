package compliance

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

// gateWorld publishes modules that violate each rule.
func gateWorld(t *testing.T) (*testenv.World, string) {
	w, _ := licenseWorld(t)
	for _, v := range []string{"v1.0.0", "v1.0.1"} {
		w.AddModule("example.com/vulnlib", v, map[string]string{"LICENSE": mdMIT,
			"v.go": "package vulnlib\n\nfunc F() string { return \"f\" }\n\nfunc Safe() string { return \"s\" }\n"})
	}
	w.AddModule("example.com/unreach", "v1.0.0", map[string]string{"LICENSE": mdMIT,
		"u.go": "package unreach\n\nfunc G() {}\n\nfunc H() string { return \"h\" }\n"})
	w.AddVuln(testenv.SimpleVuln("GO-2025-0001", "example.com/vulnlib", "v0.0.0", "v1.0.1", "example.com/vulnlib", []string{"F"}, "CVE-2025-1111"))
	w.AddVuln(testenv.SimpleVuln("GO-2025-0002", "example.com/unreach", "v0.0.0", "", "example.com/unreach", []string{"G"}, "GHSA-aaaa-bbbb-cccc"))
	w.GitHub["advisories/GHSA-aaaa-bbbb-cccc"] = map[string]any{"ghsa_id": "GHSA-aaaa-bbbb-cccc", "severity": "low"}
	w.KEV = []map[string]string{{"cveID": "CVE-2025-1111", "vendorProject": "Example", "product": "vulnlib", "dateAdded": "2025-07-01"}}

	w.AddModule("example.com/retracted", "v1.1.0", map[string]string{"LICENSE": mdMIT, "r.go": "package retracted\n\nfunc R() {}\n"})
	w.AddModule("example.com/retracted", "v1.2.0", map[string]string{"LICENSE": mdMIT, "r.go": "package retracted\n\nfunc R() {}\n",
		"go.mod": "module example.com/retracted\n\ngo 1.21\n\nretract v1.1.0 // corrupts data\n"})
	w.AddModule("example.com/deprecated", "v1.0.0", map[string]string{"LICENSE": mdMIT, "d.go": "package deprecated\n\nfunc D() {}\n",
		"go.mod": "// Deprecated: use example.com/newer instead.\nmodule example.com/deprecated\n\ngo 1.21\n"})
	w.AddModule("example.com/banned", "v0.1.0", map[string]string{"LICENSE": mdMIT, "b.go": "package banned\n\nfunc B() {}\n"})

	dir := w.Project(map[string]string{
		"go.mod": testenv.GoModFile("example.com/main", "1.21",
			"example.com/vulnlib@v1.0.0", "example.com/unreach@v1.0.0", "example.com/retracted@v1.1.0",
			"example.com/deprecated@v1.0.0", "example.com/banned@v0.1.0", "example.com/gpllib@v1.2.0", "example.com/localdep@v0.0.0") +
			"\nreplace example.com/localdep => ./localdep\n",
		"localdep/go.mod":  "module example.com/localdep\n\ngo 1.21\n",
		"localdep/LICENSE": mdMIT,
		"localdep/l.go":    "package localdep\n\nfunc L() {}\n",
		"main.go": `package main

import (
	"example.com/banned"
	"example.com/deprecated"
	"example.com/gpllib"
	"example.com/localdep"
	"example.com/retracted"
	"example.com/unreach"
	"example.com/vulnlib"
)

func main() {
	println(vulnlib.F(), unreach.H(), gpllib.G())
	banned.B()
	deprecated.D()
	localdep.L()
	retracted.R()
}
`,
	})
	goTidy(t, w, dir)
	return w, dir
}

const fullPolicy = `{
  "vulnerabilities": {"maxSeverity": "low", "forbidKEV": true, "includeStdlib": false},
  "licenses": {"deny": ["GPL-*"]},
  "forbidRetracted": true,
  "forbidDeprecated": true,
  "bannedModules": ["example.com/banned", {"module": "example.com/vulnlib", "versions": "<v1.0.1", "reason": "CVE-2025-1111"}],
  "forbidLocalReplaces": true,
  "requireGoSumComplete": true,
  "maxGoAge": "2y"
}`

func gateRules(res *GateResult) map[string]*GateRule {
	m := map[string]*GateRule{}
	for _, r := range res.Rules {
		m[r.ID] = r
	}
	return m
}

func TestGateFails(t *testing.T) {
	w, dir := gateWorld(t)
	testenv.WriteFiles(t, dir, map[string]string{".sm-go.json": fullPolicy})
	sarif := tempPath(t, "out.sarif")
	r := w.Run(dir, "gate", "--json", "--sarif", sarif)
	if r.Code != 1 {
		t.Fatalf("exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	var res GateResult
	r.Decode(t, &res)
	rules := gateRules(&res)
	wantFail := map[string]string{
		"vulnerabilities": "GO-2025-0001",
		"kev":             "GO-2025-0001",
		"licenses":        "example.com/gpllib",
		"retracted":       "example.com/retracted@v1.1.0 is retracted",
		"deprecated":      "example.com/deprecated is deprecated",
		"banned-modules":  "example.com/banned",
		"local-replaces":  "local replace example.com/localdep => ./localdep",
		"go-age":          "go directive 1.21",
	}
	for id, sub := range wantFail {
		rl := rules[id]
		if rl == nil || rl.Status != "fail" {
			t.Errorf("rule %s: %+v", id, rl)
			continue
		}
		mustContain(t, "rule "+id, toJSON(rl.Violations), sub)
	}
	if rules["go-sum"].Status != "pass" {
		t.Errorf("go-sum should pass after tidy: %+v", rules["go-sum"].Violations)
	}
	// maxSeverity low: the low GHSA vuln in unreach is tolerated.
	if v := rules["vulnerabilities"].Violations; len(v) != 1 {
		t.Errorf("vulnerability violations: %+v", v)
	}
	if len(rules["banned-modules"].Violations) != 2 {
		t.Errorf("banned: %+v", rules["banned-modules"].Violations)
	}
	if rules["retracted"].Violations[0].Fix != "go get example.com/retracted@v1.2.0" {
		t.Errorf("retracted fix: %q", rules["retracted"].Violations[0].Fix)
	}
	if res.Passed || res.Summary.Failed != 8 || res.Summary.Passed != 1 {
		t.Errorf("summary %+v", res.Summary)
	}
	// Findings point into go.mod.
	if v := rules["deprecated"].Violations[0]; v.File != "go.mod" || v.Line == 0 {
		t.Errorf("location %s:%d", v.File, v.Line)
	}

	// SARIF.
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string                `json:"ruleId"`
				Level     string                `json:"level"`
				Message   struct{ Text string } `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string }     `json:"artifactLocation"`
						Region           *struct{ StartLine int } `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(readFile(t, sarif)), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || doc.Runs[0].Tool.Driver.Name != "sm-go gate" || len(doc.Runs[0].Tool.Driver.Rules) != 9 {
		t.Fatalf("sarif header: %+v", doc)
	}
	ruleIDs := map[string]bool{}
	for _, rr := range doc.Runs[0].Tool.Driver.Rules {
		ruleIDs[rr.ID] = true
	}
	if len(doc.Runs[0].Results) != res.Summary.Violations {
		t.Errorf("sarif results %d, violations %d", len(doc.Runs[0].Results), res.Summary.Violations)
	}
	for _, x := range doc.Runs[0].Results {
		if !ruleIDs[x.RuleID] || (x.Level != "error" && x.Level != "warning") || x.Message.Text == "" || len(x.Locations) != 1 {
			t.Errorf("bad sarif result %+v", x)
		}
	}

	// GitHub annotations (text mode: on stdout).
	r = w.Run(dir, "gate", "--github")
	if r.Code != 1 {
		t.Fatalf("exit %d", r.Code)
	}
	mustContain(t, "annotations", r.Stdout, "::error file=go.mod,line=", "title=sm-go gate%3A retracted::example.com/retracted@v1.1.0 is retracted",
		"::error file=go.mod,line=", "FAILED: 8 of 9 rules failed")
	// With --json annotations go to stderr and stdout stays JSON.
	r = w.Run(dir, "gate", "--github", "--json")
	r.JSON(t)
	mustContain(t, "stderr", r.Stderr, "::error file=go.mod")
}

func TestGatePasses(t *testing.T) {
	w, dir := gateWorld(t)
	pol := `{
  "vulnerabilities": {"maxSeverity": "critical", "includeStdlib": false},
  "licenses": {"allow": ["MIT", "GPL-3.0"]},
  "bannedModules": ["example.com/other", "example.com/vulnlib@>=v1.0.1"],
  "requireGoSumComplete": true,
  "maxGoAge": "50y"
}`
	pf := filepath.Join(t.TempDir(), "policy.json")
	testenv.WriteFiles(t, filepath.Dir(pf), map[string]string{"policy.json": pol})
	r := w.Run(dir, "gate", "--policy", pf, "--github")
	if r.Code != 0 {
		t.Fatalf("exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	mustContain(t, "stdout", r.Stdout, "::notice title=sm-go gate::all 5 policy rules passed", "PASSED: 5 rules passed, 4 skipped",
		"skipped (not in policy)")
}

func TestGateReachableAndIgnore(t *testing.T) {
	w, dir := gateWorld(t)
	testenv.WriteFiles(t, dir, map[string]string{".sm-go.json": `{"vulnerabilities": {"maxSeverity": "none", "reachableOnly": true, "includeStdlib": false}}`})
	r := w.Run(dir, "gate", "--json")
	if r.Code != 1 {
		t.Fatalf("exit %d\n%s", r.Code, r.Stderr)
	}
	var res GateResult
	r.Decode(t, &res)
	v := gateRules(&res)["vulnerabilities"].Violations
	// unreach.G is not called (only unreach.H is), so only GO-2025-0001 counts.
	if len(v) != 1 || !strings.HasPrefix(v[0].Title, "GO-2025-0001") {
		t.Errorf("reachable violations: %+v", v)
	}
	if gateRules(&res)["kev"].Status != "skip" {
		t.Errorf("kev should be skipped when forbidKEV is false")
	}

	testenv.WriteFiles(t, dir, map[string]string{".sm-go.json": `{"vulnerabilities": {"maxSeverity": "none", "includeStdlib": false, "ignore": ["CVE-2025-1111", "GO-2025-0002"]}}`})
	r = w.Run(dir, "gate", "--json")
	if r.Code != 0 {
		t.Fatalf("ignored: exit %d\n%s", r.Code, r.Stdout)
	}
}

func TestGateGoSum(t *testing.T) {
	w, _ := licenseWorld(t)
	dir := w.Project(map[string]string{
		"go.mod":      testenv.GoModFile("example.com/main", "1.22", "example.com/apachelib@v0.3.0"),
		"main.go":     "package main\n\nimport \"example.com/apachelib\"\n\nfunc main() { println(apachelib.A()) }\n",
		".sm-go.json": `{"requireGoSumComplete": true}`,
	})
	r := w.Run(dir, "gate", "--json")
	if r.Code != 1 {
		t.Fatalf("no go.sum: exit %d\n%s", r.Code, r.Stdout)
	}
	var res GateResult
	r.Decode(t, &res)
	got := toJSON(gateRules(&res)["go-sum"].Violations)
	mustContain(t, "go-sum violations", got, "go.mod hash of example.com/apachelib@v0.3.0", "go.mod hash of example.com/mitlib@v1.0.0",
		"module zip hash of example.com/apachelib@v0.3.0")
	goTidy(t, w, dir)
	if r := w.Run(dir, "gate"); r.Code != 0 {
		t.Fatalf("after tidy: exit %d\n%s", r.Code, r.Stdout)
	}
	// Agree with the go command: -mod=readonly builds now succeed.
	if out, err := w.Go(dir, "build", "-mod=readonly", "./..."); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
}

func TestGateBadPolicy(t *testing.T) {
	w, dir := licenseWorld(t)
	if r := w.Run(dir, "gate", "--policy", filepath.Join(dir, "missing.json")); r.Code != 2 {
		t.Errorf("missing --policy file: exit %d %s", r.Code, r.Stderr)
	}
	for _, pol := range []string{
		`{"forbidRetracted": true, "typo": 1}`,
		`{"vulnerabilities": {"maxSeverity": "extreme"}}`,
		`{"bannedModules": ["example.com/x@~v1"]}`,
		`{"maxGoAge": "soon"}`,
		`not json`,
	} {
		testenv.WriteFiles(t, dir, map[string]string{".sm-go.json": pol})
		if r := w.Run(dir, "gate", "--json"); r.Code != 2 {
			t.Errorf("policy %s: exit %d", pol, r.Code)
		}
	}
	if r := w.Run(dir, "gate", "extra"); r.Code != 2 {
		t.Errorf("args: exit %d", r.Code)
	}
}

func TestGoReleaseDateAndAge(t *testing.T) {
	if d, ok := goReleaseDate("1.21.3"); !ok || d.Format("2006-01-02") != "2023-08-08" {
		t.Errorf("1.21.3: %v", d)
	}
	if d, ok := goReleaseDate("1.28rc1"); !ok || d.Format("2006-01") != "2027-02" {
		t.Errorf("1.28: %v", d)
	}
	if _, ok := goReleaseDate("2.0"); ok {
		t.Errorf("2.0 should be unknown")
	}
	for in, want := range map[string]float64{"540d": 540, "2w": 14, "18mo": 540, "2y": 730, "48h": 2} {
		d, err := parseAge(in)
		if err != nil || d.Hours()/24 != want {
			t.Errorf("parseAge(%s) = %v, %v", in, d, err)
		}
	}
	b := BannedModule{Module: "example.com/x", Versions: "<=v1.2.0"}
	if !b.matches("example.com/x/sub", "v1.2.0") || b.matches("example.com/x", "v1.2.1") || b.matches("example.com/xy", "v1.0.0") {
		t.Errorf("ban matching")
	}
}

// Without a policy file the built-in default policy applies: called
// vulnerabilities of severity high or above, any KEV vulnerability and
// retracted versions fail; licenses are reported but not enforced.
func TestGateDefaultPolicy(t *testing.T) {
	w, dir := gateWorld(t)
	r := w.Run(dir, "gate")
	if r.Code != 1 {
		t.Fatalf("default policy: exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	mustContain(t, "text output", r.Stdout, "no policy file found; using the built-in default policy — create .sm-go.json to customise",
		"policy (built-in default)")
	r = w.Run(dir, "gate", "--json")
	if r.Code != 1 {
		t.Fatalf("default policy --json: exit %d\n%s", r.Code, r.Stdout)
	}
	var res GateResult
	r.Decode(t, &res)
	if !res.DefaultPolicy || res.Policy != DefaultPolicyName {
		t.Errorf("policy = %q default=%v", res.Policy, res.DefaultPolicy)
	}
	rules := gateRules(&res)
	want := map[string]string{"vulnerabilities": "fail", "kev": "fail", "licenses": "pass", "retracted": "fail",
		"deprecated": "skip", "banned-modules": "skip", "local-replaces": "skip", "go-sum": "skip", "go-age": "skip"}
	for id, st := range want {
		if rules[id] == nil || rules[id].Status != st {
			t.Errorf("rule %s: %+v, want %s", id, rules[id], st)
		}
	}
	// Only the called critical vulnerability counts, not the uncalled low one.
	if v := rules["vulnerabilities"].Violations; len(v) != 1 || v[0].Module != "example.com/vulnlib" {
		t.Errorf("vulnerability violations: %s", toJSON(v))
	}
	// GPL-3.0 is reported, not enforced.
	mustContain(t, "license detail", rules["licenses"].Detail, "GPL-3.0")
	if rules["licenses"].Description != "licenses (reported, not enforced)" {
		t.Errorf("licenses description %q", rules["licenses"].Description)
	}

	// A project with no vulnerabilities or retractions passes.
	lw, ldir := licenseWorld(t)
	if r := lw.Run(ldir, "gate"); r.Code != 0 || !strings.Contains(r.Stdout, "built-in default policy") {
		t.Errorf("clean project, default policy: exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
}

func TestGateInit(t *testing.T) {
	w, dir := licenseWorld(t)
	r := w.Run(dir, "gate", "--init")
	if r.Code != 0 {
		t.Fatalf("--init: exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	path := filepath.Join(dir, ".sm-go.json")
	written := readFile(t, path)
	pol, err := loadPolicy(path)
	if err != nil {
		t.Fatalf("starter policy does not load: %v\n%s", err, written)
	}
	if got, want := toJSON(pol), toJSON(DefaultGatePolicy()); got != want {
		t.Errorf("starter policy = %s, want %s", got, want)
	}
	mustContain(t, "starter file", written, `"maxSeverity": "medium"`, `"reachableOnly": true`, `"forbidKEV": true`, `"licenses": {}`, `"forbidRetracted": true`)
	// Never overwrites.
	testenv.WriteFiles(t, dir, map[string]string{".sm-go.json": `{"forbidDeprecated": true}`})
	if r := w.Run(dir, "gate", "--init"); r.Code != 2 || !strings.Contains(r.Stderr, "already exists") {
		t.Errorf("--init over an existing file: exit %d %s", r.Code, r.Stderr)
	}
	if got := readFile(t, path); got != `{"forbidDeprecated": true}` {
		t.Errorf("existing policy was modified: %s", got)
	}
	// --policy names the file to create.
	other := filepath.Join(dir, "ci", "policy.json")
	if r := w.Run(dir, "gate", "--init", "--policy", other, "--json"); r.Code == 0 {
		t.Errorf("--init into a missing directory should fail")
	}
	other = filepath.Join(dir, "policy.json")
	if r := w.Run(dir, "gate", "--init", "--policy", other, "--json"); r.Code != 0 || readFile(t, other) != written {
		t.Errorf("--init --policy: exit %d %s", r.Code, r.Stdout)
	}
}
