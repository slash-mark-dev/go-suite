package compliance

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/modfile"
	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

// sbomWorld extends licenseWorld with a project importing every module,
// a module replaced by another version and a local replacement.
func sbomWorld(t *testing.T) (*testenv.World, string) {
	w, _ := licenseWorld(t)
	w.AddModule("example.com/old", "v1.0.0", map[string]string{"LICENSE": isc, "o.go": "package old\n\nfunc O() int { return 1 }\n"})
	w.AddModule("example.com/fork", "v1.1.0", map[string]string{
		"go.mod":  "module example.com/old\n\ngo 1.21\n",
		"LICENSE": bsd2, "o.go": "package old\n\nfunc O() int { return 2 }\n"})
	dir := w.Project(map[string]string{
		"go.mod": testenv.GoModFile("example.com/main", "1.22",
			"example.com/mitlib@v1.0.0", "example.com/gpllib@v1.2.0", "example.com/apachelib@v0.3.0",
			"example.com/nolicense@v1.0.0", "example.com/mystery@v1.0.0", "example.com/old@v1.0.0", "example.com/local@v0.0.0") +
			"\nreplace example.com/old => example.com/fork v1.1.0\n\nreplace example.com/local => ./local\n",
		"local/go.mod":  "module example.com/local\n\ngo 1.21\n",
		"local/LICENSE": goBSD3,
		"local/l.go":    "package local\n\nfunc L() {}\n",
		"main.go": `package main

import (
	"example.com/apachelib"
	"example.com/gpllib"
	"example.com/local"
	"example.com/mitlib"
	"example.com/mystery"
	"example.com/nolicense"
	"example.com/old"
)

func main() {
	println(apachelib.A(), gpllib.G(), mitlib.M(), old.O())
	local.L()
	mystery.X()
	nolicense.N()
}
`,
	})
	goTidy(t, w, dir)
	return w, dir
}

var (
	hex64RE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	purlRE    = regexp.MustCompile(`^pkg:golang/[A-Za-z0-9.%_~-]+(/[A-Za-z0-9.%_~-]+)*(@[A-Za-z0-9.%_~-]+)?$`)
	spdxIDRE  = regexp.MustCompile(`^SPDXRef-[A-Za-z0-9.-]+$`)
	uuidURNRE = regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// validateCycloneDX checks the structural rules of the CycloneDX 1.5 JSON
// schema that matter for consumers, and returns the components by name.
func validateCycloneDX(t *testing.T, raw []byte) map[string]map[string]any {
	t.Helper()
	var bom map[string]any
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if bom["bomFormat"] != "CycloneDX" || bom["specVersion"] != "1.5" || bom["version"] != float64(1) {
		t.Errorf("header: %v %v %v", bom["bomFormat"], bom["specVersion"], bom["version"])
	}
	if !uuidURNRE.MatchString(bom["serialNumber"].(string)) {
		t.Errorf("serialNumber %v", bom["serialNumber"])
	}
	md := bom["metadata"].(map[string]any)
	if _, err := time.Parse(time.RFC3339, md["timestamp"].(string)); err != nil {
		t.Errorf("timestamp: %v", err)
	}
	tools := md["tools"].(map[string]any)["components"].([]any)
	if tools[0].(map[string]any)["name"] != "sm-go" {
		t.Errorf("tools: %v", tools)
	}
	refs := map[string]bool{}
	mainc := md["component"].(map[string]any)
	refs[mainc["bom-ref"].(string)] = true
	byName := map[string]map[string]any{}
	validTypes := map[string]bool{"application": true, "library": true, "framework": true}
	for _, x := range bom["components"].([]any) {
		c := x.(map[string]any)
		ref, _ := c["bom-ref"].(string)
		if ref == "" || refs[ref] {
			t.Errorf("missing or duplicate bom-ref %q", ref)
		}
		refs[ref] = true
		if !validTypes[c["type"].(string)] || c["name"] == "" {
			t.Errorf("component type/name: %v", c)
		}
		if !purlRE.MatchString(c["purl"].(string)) {
			t.Errorf("bad purl %v", c["purl"])
		}
		if s, ok := c["scope"]; ok && s != "required" && s != "optional" && s != "excluded" {
			t.Errorf("bad scope %v", s)
		}
		for _, h := range asList(c["hashes"]) {
			h := h.(map[string]any)
			if h["alg"] != "SHA-256" || !hex64RE.MatchString(h["content"].(string)) {
				t.Errorf("bad hash %v", h)
			}
		}
		ls := asList(c["licenses"])
		for _, l := range ls {
			l := l.(map[string]any)
			lic, hasLic := l["license"].(map[string]any)
			_, hasExpr := l["expression"]
			if hasLic == hasExpr {
				t.Errorf("license entry must have exactly one of license/expression: %v", l)
			}
			if hasExpr && len(ls) != 1 {
				t.Errorf("an expression must be the only license entry: %v", ls)
			}
			if hasLic && (lic["id"] == nil) == (lic["name"] == nil) {
				t.Errorf("license must have exactly one of id/name: %v", lic)
			}
		}
		byName[c["name"].(string)] = c
	}
	seen := map[string]bool{}
	for _, x := range bom["dependencies"].([]any) {
		d := x.(map[string]any)
		ref := d["ref"].(string)
		if !refs[ref] || seen[ref] {
			t.Errorf("dependency ref %q unknown or duplicated", ref)
		}
		seen[ref] = true
		for _, o := range asList(d["dependsOn"]) {
			if !refs[o.(string)] {
				t.Errorf("dependsOn %q unknown", o)
			}
		}
	}
	for r := range refs {
		if !seen[r] {
			t.Errorf("no dependency entry for %s", r)
		}
	}
	return byName
}

// validateSPDX checks SPDX 2.3 JSON structural rules and returns packages
// by name and the relationships as "A TYPE B" strings (names).
func validateSPDX(t *testing.T, raw []byte) (map[string]map[string]any, map[string]bool) {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if doc["spdxVersion"] != "SPDX-2.3" || doc["dataLicense"] != "CC0-1.0" || doc["SPDXID"] != "SPDXRef-DOCUMENT" || doc["name"] == "" {
		t.Errorf("header: %v", doc)
	}
	ns := doc["documentNamespace"].(string)
	if !strings.HasPrefix(ns, "https://") || strings.Contains(ns, "#") {
		t.Errorf("documentNamespace %q", ns)
	}
	ci := doc["creationInfo"].(map[string]any)
	if _, err := time.Parse(time.RFC3339, ci["created"].(string)); err != nil {
		t.Errorf("created: %v", err)
	}
	for _, c := range ci["creators"].([]any) {
		if !regexp.MustCompile(`^(Tool|Organization|Person): .+`).MatchString(c.(string)) {
			t.Errorf("creator %q", c)
		}
	}
	extracted := map[string]bool{}
	for _, x := range asList(doc["hasExtractedLicensingInfos"]) {
		e := x.(map[string]any)
		id := e["licenseId"].(string)
		if !strings.HasPrefix(id, "LicenseRef-") || e["extractedText"] == "" {
			t.Errorf("extracted license %v", e)
		}
		extracted[id] = true
	}
	ids := map[string]string{"SPDXRef-DOCUMENT": "DOCUMENT"}
	byName := map[string]map[string]any{}
	for _, x := range doc["packages"].([]any) {
		p := x.(map[string]any)
		id := p["SPDXID"].(string)
		if !spdxIDRE.MatchString(id) || ids[id] != "" {
			t.Errorf("bad or duplicate SPDXID %q", id)
		}
		ids[id] = p["name"].(string)
		for _, k := range []string{"name", "downloadLocation", "licenseConcluded", "licenseDeclared", "copyrightText"} {
			if s, _ := p[k].(string); s == "" {
				t.Errorf("package %s: missing %s", id, k)
			}
		}
		if p["filesAnalyzed"] != false {
			t.Errorf("filesAnalyzed must be false without files")
		}
		for _, c := range asList(p["checksums"]) {
			c := c.(map[string]any)
			if c["algorithm"] != "SHA256" || !hex64RE.MatchString(c["checksumValue"].(string)) {
				t.Errorf("bad checksum %v", c)
			}
		}
		for _, tok := range strings.Fields(p["licenseDeclared"].(string)) {
			if strings.HasPrefix(tok, "LicenseRef-") && !extracted[tok] {
				t.Errorf("undeclared %s", tok)
			}
		}
		for _, r := range asList(p["externalRefs"]) {
			r := r.(map[string]any)
			if r["referenceType"] == "purl" && !purlRE.MatchString(r["referenceLocator"].(string)) {
				t.Errorf("bad purl %v", r)
			}
		}
		byName[p["name"].(string)] = p
	}
	rels := map[string]bool{}
	describes := 0
	for _, x := range doc["relationships"].([]any) {
		r := x.(map[string]any)
		a, b := ids[r["spdxElementId"].(string)], ids[r["relatedSpdxElement"].(string)]
		if a == "" || b == "" {
			t.Errorf("relationship references unknown element: %v", r)
		}
		if r["relationshipType"] == "DESCRIBES" {
			describes++
		}
		rels[a+" "+r["relationshipType"].(string)+" "+b] = true
	}
	if describes == 0 {
		t.Errorf("no DESCRIBES relationship")
	}
	return byName, rels
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func goSumHash(t *testing.T, dir, path, version string) string {
	gs := modfile.ParseGoSum([]byte(readFile(t, filepath.Join(dir, "go.sum"))))
	return gs.Hash(path, version)
}

func TestSBOMCycloneDX(t *testing.T) {
	w, dir := sbomWorld(t)
	r := w.Run(dir, "sbom")
	if r.Code != 0 {
		t.Fatalf("exit %d\n%s", r.Code, r.Stderr)
	}
	comps := validateCycloneDX(t, []byte(r.Stdout))
	if len(comps) != 7 {
		t.Fatalf("got %d components, want 7: %v", len(comps), keys(comps))
	}
	mit := comps["example.com/mitlib"]
	if mit["purl"] != "pkg:golang/example.com/mitlib@v1.0.0" || mit["version"] != "v1.0.0" {
		t.Errorf("mitlib: %v", mit)
	}
	want := h1Hex(goSumHash(t, dir, "example.com/mitlib", "v1.0.0"))
	if h := mit["hashes"].([]any)[0].(map[string]any)["content"]; h != want || want == "" {
		t.Errorf("hash %v, want %v", h, want)
	}
	if id := mit["licenses"].([]any)[0].(map[string]any)["license"].(map[string]any)["id"]; id != "MIT" {
		t.Errorf("mitlib license %v", id)
	}
	// Replaced module: identity kept, code (hash, license) from the fork.
	old := comps["example.com/old"]
	if h := old["hashes"].([]any)[0].(map[string]any)["content"]; h != h1Hex(goSumHash(t, dir, "example.com/fork", "v1.1.0")) {
		t.Errorf("old hash %v", h)
	}
	if id := old["licenses"].([]any)[0].(map[string]any)["license"].(map[string]any)["id"]; id != "BSD-2-Clause" {
		t.Errorf("old license %v", id)
	}
	mustContain(t, "old", toJSON(old), `"sm-go:replace"`, `example.com/fork@v1.1.0`, "/example.com/fork/@v/v1.1.0.zip")
	// Local replacement: no hash, license from the directory.
	loc := comps["example.com/local"]
	if loc["hashes"] != nil {
		t.Errorf("local module must not have a hash")
	}
	if id := loc["licenses"].([]any)[0].(map[string]any)["license"].(map[string]any)["id"]; id != "BSD-3-Clause" {
		t.Errorf("local license %v", id)
	}
	if comps["example.com/mystery"]["licenses"] != nil {
		t.Errorf("unknown license should be omitted")
	}
	// Dependency graph.
	var bom cdxBOM
	json.Unmarshal([]byte(r.Stdout), &bom)
	deps := map[string][]string{}
	for _, d := range bom.Dependencies {
		deps[d.Ref] = d.DependsOn
	}
	if got := deps["pkg:golang/example.com/apachelib@v0.3.0"]; len(got) != 1 || got[0] != "pkg:golang/example.com/mitlib@v1.0.0" {
		t.Errorf("apachelib deps %v", got)
	}
	if got := deps["pkg:golang/example.com/main"]; len(got) != 7 {
		t.Errorf("main deps %v", got)
	}
}

func TestSBOMSPDXAndOutputFile(t *testing.T) {
	w, dir := sbomWorld(t)
	out := tempPath(t, "bom.spdx.json")
	r := w.Run(dir, "sbom", "--format", "spdx", "-o", out)
	if r.Code != 0 {
		t.Fatalf("exit %d\n%s", r.Code, r.Stderr)
	}
	mustContain(t, "stdout", r.Stdout, "SPDX 2.3 SBOM of example.com/main with 7 components written to")
	pkgs, rels := validateSPDX(t, []byte(readFile(t, out)))
	if len(pkgs) != 8 {
		t.Errorf("packages: %v", keys(pkgs))
	}
	if pkgs["example.com/gpllib"]["licenseDeclared"] != "GPL-3.0" || pkgs["example.com/mystery"]["licenseDeclared"] != "NOASSERTION" {
		t.Errorf("licenses: %v %v", pkgs["example.com/gpllib"]["licenseDeclared"], pkgs["example.com/mystery"]["licenseDeclared"])
	}
	if !strings.HasSuffix(pkgs["example.com/mitlib"]["downloadLocation"].(string), "/proxy/example.com/mitlib/@v/v1.0.0.zip") {
		t.Errorf("downloadLocation %v", pkgs["example.com/mitlib"]["downloadLocation"])
	}
	for _, rel := range []string{"DOCUMENT DESCRIBES example.com/main", "example.com/main DEPENDS_ON example.com/gpllib",
		"example.com/apachelib DEPENDS_ON example.com/mitlib"} {
		if !rels[rel] {
			t.Errorf("missing relationship %q in %v", rel, rels)
		}
	}
	// --json wraps the document.
	r = w.Run(dir, "sbom", "--format", "spdx", "--no-licenses", "--json")
	var res SBOMResult
	r.Decode(t, &res)
	if res.Format != "spdx" || res.Components != 7 || res.Source != "project" {
		t.Errorf("result %+v", res)
	}
	pkgs, _ = validateSPDX(t, res.Document)
	if pkgs["example.com/mitlib"]["licenseDeclared"] != "NOASSERTION" {
		t.Errorf("--no-licenses should leave licenses unasserted")
	}
}

func TestSBOMLinked(t *testing.T) {
	w, dir := sbomWorld(t)
	testenv.WriteFiles(t, dir, map[string]string{"cmd/tool/main.go": "package main\n\nimport \"example.com/apachelib\"\n\nfunc main() { println(apachelib.A()) }\n"})
	r := w.Run(dir, "sbom", "./cmd/tool", "--linked", "--no-licenses")
	if r.Code != 0 {
		t.Fatalf("exit %d\n%s", r.Code, r.Stderr)
	}
	comps := validateCycloneDX(t, []byte(r.Stdout))
	if strings.Join(keys(comps), ",") != "example.com/apachelib,example.com/mitlib" {
		t.Errorf("linked components: %v", keys(comps))
	}
}

func TestSBOMBinary(t *testing.T) {
	w, dir := sbomWorld(t)
	bin := filepath.Join(t.TempDir(), "app")
	if out, err := w.Go(dir, "build", "-o", bin, "."); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	r := w.Run("", "sbom", "--binary", bin, "--json")
	if r.Code != 0 {
		t.Fatalf("exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	var res SBOMResult
	r.Decode(t, &res)
	if res.Source != "binary" || res.Components != 7 {
		t.Errorf("result: %+v", res)
	}
	comps := validateCycloneDX(t, res.Document)
	if h := comps["example.com/gpllib"]["hashes"].([]any)[0].(map[string]any)["content"]; h != h1Hex(goSumHash(t, dir, "example.com/gpllib", "v1.2.0")) {
		t.Errorf("binary hash %v", h)
	}
	if id := comps["example.com/old"]["licenses"].([]any)[0].(map[string]any)["license"].(map[string]any)["id"]; id != "BSD-2-Clause" {
		t.Errorf("replaced module license from binary: %v", id)
	}
	mustContain(t, "document", string(res.Document), `"sm-go:go-version"`, `"sm-go:build:GOOS"`, `"pkg:golang/example.com/main"`)

	r = w.Run("", "sbom", "--binary", bin, "--format", "spdx", "--no-licenses")
	validateSPDX(t, []byte(r.Stdout))

	// Bad input.
	if r := w.Run("", "sbom", "--binary", filepath.Join(dir, "go.mod")); r.Code != 2 {
		t.Errorf("non-binary: exit %d", r.Code)
	}
	if r := w.Run("", "sbom", "--binary", filepath.Join(dir, "nope")); r.Code != 2 {
		t.Errorf("missing binary: exit %d", r.Code)
	}
	if r := w.Run(dir, "sbom", "--format", "xml"); r.Code != 2 {
		t.Errorf("bad format: exit %d", r.Code)
	}
}

func TestPurlAndH1(t *testing.T) {
	if p := purl("github.com/Foo/bar+baz", "v1.0.0+incompatible"); p != "pkg:golang/github.com/Foo/bar%2Bbaz@v1.0.0%2Bincompatible" {
		t.Errorf("purl %s", p)
	}
	if h := h1Hex("h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="); h != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("h1Hex %s", h)
	}
	if h1Hex("h1:bad") != "" || h1Hex("sha256:x") != "" {
		t.Errorf("invalid hashes must give empty")
	}
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

func toJSON(v any) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	return b.String()
}

// The go command records a directory replacement in the binary as version
// "(devel)": it is local code, not a module to download for its license.
func TestSBOMBinaryLocalReplace(t *testing.T) {
	w, _ := sbomWorld(t)
	dir := w.Project(map[string]string{
		"go.mod":         "module example.com/withlocal\n\ngo 1.22\n\nrequire example.com/localx v0.0.0\n\nreplace example.com/localx => ./localx\n",
		"main.go":        "package main\n\nimport \"example.com/localx\"\n\nfunc main() { localx.X() }\n",
		"localx/go.mod":  "module example.com/localx\n\ngo 1.22\n",
		"localx/x.go":    "package localx\n\nfunc X() { println(1) }\n",
		"localx/LICENSE": "MIT License\n",
	})
	bin := filepath.Join(t.TempDir(), "app")
	if out, err := w.Go(dir, "build", "-o", bin, "."); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	r := w.Run("", "sbom", "--binary", bin, "--json")
	if r.Code != 0 {
		t.Fatalf("exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	if ws := r.JSON(t)["warnings"]; ws != nil {
		t.Errorf("warnings: %v", ws)
	}
	var res SBOMResult
	r.Decode(t, &res)
	if strings.Contains(string(res.Document), "(devel)") {
		t.Errorf("document mentions (devel):\n%s", res.Document)
	}
}
