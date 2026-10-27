package compliance

import (
	"strings"
	"testing"
)

func licByPath(res *LicenseResult) map[string]*ModuleLicense {
	m := map[string]*ModuleLicense{}
	for _, x := range res.Modules {
		m[x.Path] = x
	}
	return m
}

func TestLicenseDetect(t *testing.T) {
	w, dir := licenseWorld(t)
	r := w.Run(dir, "license", "--json")
	if r.Code != 0 {
		t.Fatalf("exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	var res LicenseResult
	r.Decode(t, &res)
	by := licByPath(&res)
	want := map[string]struct{ expr, source, status, copyleft string }{
		"example.com/mitlib":    {"MIT", "files", "ok", ""},
		"example.com/gpllib":    {"GPL-3.0", "files", "ok", "strong"},
		"example.com/apachelib": {"Apache-2.0", "files", "ok", ""},
		"example.com/nolicense": {"BSD-3-Clause", "deps.dev", "ok", ""},
		"example.com/mystery":   {"NOASSERTION", "none", "unknown", ""},
	}
	if len(res.Modules) != len(want) {
		t.Fatalf("got %d modules, want %d", len(res.Modules), len(want))
	}
	for p, wv := range want {
		m := by[p]
		if m == nil {
			t.Fatalf("missing %s", p)
		}
		if m.Expression != wv.expr || m.Source != wv.source || m.Status != wv.status || m.Copyleft != wv.copyleft {
			t.Errorf("%s: got expr=%s source=%s status=%s copyleft=%s, want %+v", p, m.Expression, m.Source, m.Status, m.Copyleft, wv)
		}
	}
	if !by["example.com/mitlib"].Direct {
		t.Errorf("mitlib should be direct")
	}
	files := by["example.com/apachelib"].Files
	if len(files) != 2 || files[0].Path != "LICENSE" || files[1].Kind != "notice" {
		t.Errorf("apachelib files: %+v", files)
	}
	if res.Summary.Modules != 5 || res.Summary.Unknown != 1 || res.Summary.Violations != 0 || res.Summary.Copyleft != 1 {
		t.Errorf("summary: %+v", res.Summary)
	}
	rules := map[string]bool{}
	for _, f := range res.Findings {
		rules[f.Rule+" "+f.Module] = true
	}
	if !rules["license-copyleft example.com/gpllib"] || !rules["license-unknown example.com/mystery"] {
		t.Errorf("findings: %+v", res.Findings)
	}
	// JSON envelope basics.
	env := r.JSON(t)
	if env["tool"] != "license" || env["ok"] != true {
		t.Errorf("envelope: %v", env)
	}
}

func TestLicensePolicy(t *testing.T) {
	w, dir := licenseWorld(t)

	r := w.Run(dir, "license", "--deny", "GPL-3.0", "--json")
	if r.Code != 1 {
		t.Fatalf("deny: exit %d\n%s", r.Code, r.Stderr)
	}
	var res LicenseResult
	r.Decode(t, &res)
	if s := licByPath(&res)["example.com/gpllib"].Status; s != "denied" || res.Summary.Violations != 1 {
		t.Errorf("gpllib status %s, violations %d", s, res.Summary.Violations)
	}

	// Globs, and allow lists make unknown licenses violations.
	r = w.Run(dir, "license", "--allow", "MIT,Apache-2.0", "--allow", "BSD-*", "--json")
	if r.Code != 1 {
		t.Fatalf("allow: exit %d\n%s", r.Code, r.Stderr)
	}
	res = LicenseResult{}
	r.Decode(t, &res)
	by := licByPath(&res)
	if by["example.com/gpllib"].Status != "not-allowed" || by["example.com/mystery"].Status != "unknown" ||
		by["example.com/nolicense"].Status != "ok" || res.Summary.Violations != 2 {
		t.Errorf("allow statuses: gpl=%s mystery=%s nolicense=%s violations=%d", by["example.com/gpllib"].Status,
			by["example.com/mystery"].Status, by["example.com/nolicense"].Status, res.Summary.Violations)
	}

	// Allowing everything that is present passes.
	r = w.Run(dir, "license", "--allow", "MIT,Apache-2.0,BSD-3-Clause,GPL-3.0", "--deny", "AGPL-3.0")
	if r.Code != 1 { // mystery is still unknown under an allow list
		t.Fatalf("exit %d\n%s", r.Code, r.Stdout)
	}
	mustContain(t, "text output", r.Stdout, "sm-go license · example.com/main", "example.com/gpllib", "GPL-3.0", "violate the license policy")

	r = w.Run(dir, "license", "--fail-copyleft", "--json")
	if r.Code != 1 {
		t.Fatalf("fail-copyleft: exit %d", r.Code)
	}

	// Usage errors.
	if r := w.Run(dir, "license", "--allow", "MIT", "--deny", "mit"); r.Code != 2 {
		t.Errorf("allow+deny same: exit %d", r.Code)
	}
	if r := w.Run(dir, "license", "--deny", "GPL-[", "--json"); r.Code != 2 {
		t.Errorf("bad glob: exit %d", r.Code)
	}
	if r := w.Run(dir, "license", "./..."); r.Code != 2 {
		t.Errorf("patterns without --linked: exit %d", r.Code)
	}
}

func TestLicenseNoticeAndMismatch(t *testing.T) {
	w, dir := licenseWorld(t)
	w.DepsDev["v3/systems/go/packages/example.com/gpllib/versions/v1.2.0"] = map[string]any{"licenses": []string{"GPL-2.0-only"}}
	notice := tempPath(t, "NOTICE.txt")
	r := w.Run(dir, "license", "--notice", notice, "--json")
	if r.Code != 0 {
		t.Fatalf("exit %d\n%s", r.Code, r.Stderr)
	}
	var res LicenseResult
	r.Decode(t, &res)
	if res.Notice != notice {
		t.Errorf("notice path %q", res.Notice)
	}
	found := false
	for _, f := range res.Findings {
		if f.Rule == "license-mismatch" && f.Module == "example.com/gpllib" {
			found = true
		}
	}
	if !found || res.Summary.Mismatches != 1 {
		t.Errorf("expected a deps.dev mismatch finding: %+v", res.Findings)
	}
	text := readFile(t, notice)
	mustContain(t, "NOTICE", text,
		"THIRD-PARTY SOFTWARE NOTICES", "example.com/main includes",
		"example.com/mitlib v1.0.0", "License: MIT", "Permission is hereby granted",
		"example.com/apachelib v0.3.0", "Apache Foo", "This product includes software developed at Foo.",
		"Grant of Patent License", "GNU GENERAL PUBLIC LICENSE",
		"example.com/nolicense v1.0.0", "https://spdx.org/licenses/BSD-3-Clause.html",
		"example.com/mystery v1.0.0", "proprietary and confidential")
	// The license file comes before the NOTICE file.
	if strings.Index(text, "Grant of Patent License") > strings.Index(text, "Apache Foo") {
		t.Errorf("LICENSE should precede NOTICE")
	}
}

func TestLicenseLinked(t *testing.T) {
	w, dir := licenseWorld(t)
	goTidy(t, w, dir)
	r := w.Run(dir, "license", "--linked", "--json")
	if r.Code != 0 {
		t.Fatalf("exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	var res LicenseResult
	r.Decode(t, &res)
	var got []string
	for _, m := range res.Modules {
		got = append(got, m.Path)
	}
	// main imports apachelib (which imports mitlib) and gpllib only.
	if strings.Join(got, ",") != "example.com/apachelib,example.com/gpllib,example.com/mitlib" {
		t.Errorf("linked modules: %v", got)
	}
}

func TestLicenseErrors(t *testing.T) {
	w, dir := licenseWorld(t)
	r := w.RunEnv(dir, []string{"GOPROXY=http://127.0.0.1:1/proxy", "GOFLAGS="}, "license", "--json", "--timeout", "2s")
	if r.Code != 3 {
		t.Fatalf("proxy down: exit %d\n%s", r.Code, r.Stdout)
	}
	// deps.dev down: warning, still works.
	r = w.RunEnv(dir, []string{"SMGO_DEPSDEV_URL=http://127.0.0.1:1"}, "license", "--json", "--timeout", "2s")
	if r.Code != 0 {
		t.Fatalf("deps.dev down: exit %d\n%s", r.Code, r.Stdout)
	}
	env := r.JSON(t)
	ws, _ := env["warnings"].([]any)
	if len(ws) == 0 || !strings.Contains(ws[0].(string), "deps.dev unavailable") {
		t.Errorf("warnings: %v", ws)
	}
	// Outside a module.
	if r := w.Run(t.TempDir(), "license"); r.Code != 3 {
		t.Errorf("no module: exit %d", r.Code)
	}
}
