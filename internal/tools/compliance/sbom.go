package compliance

import (
	"bytes"
	"crypto/rand"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/ui"
)

// sbomComponent is the format-neutral description of one module.
type sbomComponent struct {
	Path      string
	Version   string
	Replace   module.Version // non-zero if replaced; Version "" = local dir
	H1        string         // go.sum "h1:" hash of the code actually used
	Licenses  []string
	Direct    bool
	Main      bool
	DependsOn []string // keys (path@version) of components
}

func (s *sbomComponent) key() string { return s.Path + "@" + s.Version }

// sbomModel is the format-neutral SBOM.
type sbomModel struct {
	Name       string // main module path
	Version    string // main module version ("" if unknown)
	Main       *sbomComponent
	Components []*sbomComponent // dependencies, sorted by path
	Source     string           // "project" or "binary"
	GoVersion  string
	Properties [][2]string
	ProxyURL   string
}

// SBOMResult is the --json result of the sbom tool.
type SBOMResult struct {
	Format     string          `json:"format"`
	Source     string          `json:"source"`
	Output     string          `json:"output,omitempty"`
	Components int             `json:"components"`
	Document   json.RawMessage `json:"document"`
}

var sbomFlags struct {
	format, output, binary          *string
	linked, tests, noLicenses, noDD *bool
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "sbom",
		Group:   group,
		Summary: "CycloneDX 1.5 / SPDX 2.3 SBOM from the build list or a binary",
		Usage:   "sm-go sbom [packages] [flags]",
		Help: `Exports a software bill of materials as CycloneDX 1.5 JSON (default) or SPDX 2.3 JSON.

Project mode lists every module of the build list (or, with --linked, only the modules that
provide packages linked into the given packages), with package URLs (pkg:golang/...), the
SHA-256 digest of the go.sum "h1:" hash, licenses identified from the module's license files
(see 'sm-go help license'; --no-licenses skips the downloads) and the dependency relationships
of the module graph, resolved to the selected versions.

Binary mode (--binary FILE) reads the module information embedded in a Go executable with
debug/buildinfo: the main module, every dependency with its go.sum hash and replacement, and
the build settings. A binary does not record the module graph, so the main module depends on
every listed module.`,
		Examples: []string{
			"sm-go sbom > bom.cdx.json",
			"sm-go sbom --format spdx -o bom.spdx.json",
			"sm-go sbom ./cmd/server --linked -o server.cdx.json",
			"sm-go sbom --binary ./bin/server --format spdx",
		},
		Sources: []string{"Go module proxy", "deps.dev"},
		Flags: func(fs *flag.FlagSet) {
			sbomFlags.format = fs.String("format", "cyclonedx", "output `format`: cyclonedx or spdx")
			sbomFlags.output = fs.String("o", "", "write the SBOM to `file` (default stdout)")
			sbomFlags.binary = fs.String("binary", "", "read modules from a Go `executable` instead of the project")
			sbomFlags.linked = fs.Bool("linked", false, "only modules providing packages linked into the given packages (needs go)")
			sbomFlags.tests = fs.Bool("tests", false, "with --linked, include test dependencies")
			sbomFlags.noLicenses = fs.Bool("no-licenses", false, "do not download modules to identify licenses")
			sbomFlags.noDD = fs.Bool("no-depsdev", false, "do not complete licenses from deps.dev")
		},
		Run: runSBOM,
	})
}

func runSBOM(c *cli.Context) error {
	format := strings.ToLower(*sbomFlags.format)
	switch format {
	case "cyclonedx", "cdx":
		format = "cyclonedx"
	case "spdx":
	default:
		return cli.Usagef("--format must be cyclonedx or spdx")
	}
	var m *sbomModel
	var err error
	if *sbomFlags.binary != "" {
		if len(c.Args) > 0 || *sbomFlags.linked {
			return cli.Usagef("--binary cannot be combined with packages or --linked")
		}
		m, err = sbomFromBinary(c, *sbomFlags.binary)
	} else {
		if len(c.Args) > 0 && !*sbomFlags.linked {
			return cli.Usagef("package patterns are only used with --linked")
		}
		m, err = sbomFromProject(c)
	}
	if err != nil {
		return err
	}
	if urls := c.Proxy().URLs(); len(urls) > 0 {
		m.ProxyURL = urls[0]
	}
	var doc any
	if format == "spdx" {
		doc = buildSPDX(m)
	} else {
		doc = buildCycloneDX(m)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return err
	}
	res := &SBOMResult{Format: format, Source: m.Source, Output: *sbomFlags.output, Components: len(m.Components), Document: buf.Bytes()}
	if *sbomFlags.output != "" {
		if err := writeFile(*sbomFlags.output, buf.Bytes()); err != nil {
			return err
		}
	}
	c.SetResult(res)
	if c.Text() {
		if *sbomFlags.output == "" {
			c.Stdout.Write(buf.Bytes())
		} else {
			name := "CycloneDX 1.5"
			if format == "spdx" {
				name = "SPDX 2.3"
			}
			c.Out.OK("%s SBOM of %s with %s written to %s", name, m.Name, ui.Plural(len(m.Components), "component", "components"), *sbomFlags.output)
		}
	}
	return nil
}

func sbomFromProject(c *cli.Context) (*sbomModel, error) {
	p, err := c.Project()
	if err != nil {
		return nil, err
	}
	refs, g, err := buildRefs(c)
	if err != nil {
		return nil, err
	}
	include := map[string]bool{}
	for _, r := range refs {
		include[r.Path] = true
	}
	if *sbomFlags.linked {
		pats := c.Args
		if len(pats) == 0 {
			pats = []string{"./..."}
		}
		linked, err := linkedModules(c, pats, *sbomFlags.tests)
		if err != nil {
			return nil, err
		}
		include = linked
		var keep []modRef
		for _, r := range refs {
			if linked[r.Path] {
				keep = append(keep, r)
			}
		}
		refs = keep
	}
	lic := map[string]*ModuleLicense{}
	if !*sbomFlags.noLicenses {
		mods, err := scanLicenses(c, refs, !*sbomFlags.noDD)
		if err != nil {
			return nil, err
		}
		for _, ml := range mods {
			lic[ml.Path] = ml
		}
	}
	m := &sbomModel{Name: p.ModulePath(), Source: "project"}
	if p.GoMod != nil && p.GoMod.Go != "" {
		m.Properties = append(m.Properties, [2]string{"sm-go:go-directive", p.GoMod.Go})
	}
	byKey := map[string]*sbomComponent{}
	for _, r := range refs {
		sc := &sbomComponent{Path: r.Path, Version: r.Version, Replace: r.Replace, Direct: r.Direct}
		hp, hv := r.Path, r.Version
		if r.Replace.Path != "" {
			hp, hv = r.Replace.Path, r.Replace.Version
		}
		if !r.isLocal() && p.GoSum != nil {
			sc.H1 = p.GoSum.Hash(hp, hv)
		}
		if ml := lic[r.Path]; ml != nil {
			sc.Licenses = ml.Licenses
			if sc.H1 == "" {
				sc.H1 = ml.zipHash
			}
		}
		m.Components = append(m.Components, sc)
		byKey[sc.key()] = sc
	}
	// Dependency edges between selected versions. Modules left out (by
	// --linked) are traversed so that A -> (excluded B) -> C still
	// yields A -> C.
	selected := func(v module.Version) module.Version {
		return module.Version{Path: v.Path, Version: g.Selected[v.Path]}
	}
	depsOf := func(from module.Version) []string {
		seen := map[module.Version]bool{}
		out := map[string]bool{}
		var walk func(module.Version)
		walk = func(n module.Version) {
			for _, r := range g.Reqs[n] {
				if g.IsMain(r.Path) {
					continue
				}
				s := selected(r)
				if seen[s] {
					continue
				}
				seen[s] = true
				if include[s.Path] {
					out[s.Path+"@"+s.Version] = true
				} else {
					walk(s)
				}
			}
		}
		walk(from)
		var keys []string
		for k := range out {
			if k != from.Path+"@"+from.Version {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		return keys
	}
	mainV := module.Version{Path: m.Name}
	if len(g.Mains) > 0 {
		mainV = g.Mains[0]
	}
	m.Main = &sbomComponent{Path: m.Name, Main: true, DependsOn: depsOf(mainV)}
	for _, sc := range m.Components {
		sc.DependsOn = depsOf(module.Version{Path: sc.Path, Version: sc.Version})
	}
	return m, nil
}

func sbomFromBinary(c *cli.Context, path string) (*sbomModel, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, cli.Usagef("--binary: %v", err)
	}
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil, cli.Usagef("--binary %s: %v", path, err)
	}
	m := &sbomModel{Name: bi.Main.Path, Version: bi.Main.Version, Source: "binary", GoVersion: bi.GoVersion}
	if m.Name == "" {
		m.Name = bi.Path
	}
	if m.Version == "(devel)" {
		m.Version = ""
	}
	m.Properties = append(m.Properties, [2]string{"sm-go:go-version", bi.GoVersion}, [2]string{"sm-go:main-package", bi.Path})
	for _, s := range bi.Settings {
		switch s.Key {
		case "GOOS", "GOARCH", "CGO_ENABLED", "vcs.revision", "vcs.time", "vcs.modified", "-trimpath":
			m.Properties = append(m.Properties, [2]string{"sm-go:build:" + s.Key, s.Value})
		}
	}
	var refs []modRef
	for _, d := range bi.Deps {
		sc := &sbomComponent{Path: d.Path, Version: d.Version, H1: d.Sum}
		r := modRef{Path: d.Path, Version: d.Version}
		if d.Replace != nil {
			rv := d.Replace.Version
			if rv == "(devel)" {
				rv = "" // the go command records directory replacements as (devel)
			}
			sc.Replace = module.Version{Path: d.Replace.Path, Version: rv}
			sc.H1 = d.Replace.Sum
			r.Replace = sc.Replace
			if rv == "" {
				r.Dir = d.Replace.Path
			}
		}
		m.Components = append(m.Components, sc)
		if !r.isLocal() {
			refs = append(refs, r)
		}
	}
	sort.Slice(m.Components, func(i, j int) bool { return m.Components[i].Path < m.Components[j].Path })
	if !*sbomFlags.noLicenses && len(refs) > 0 {
		mods, err := scanLicenses(c, refs, !*sbomFlags.noDD)
		if err != nil {
			c.Warnf("licenses not identified: %v", err)
		} else {
			by := map[string]*ModuleLicense{}
			for _, ml := range mods {
				by[ml.Path] = ml
			}
			for _, sc := range m.Components {
				if ml := by[sc.Path]; ml != nil {
					sc.Licenses = ml.Licenses
				}
			}
		}
	}
	m.Main = &sbomComponent{Path: m.Name, Version: m.Version, Main: true}
	for _, sc := range m.Components {
		m.Main.DependsOn = append(m.Main.DependsOn, sc.key())
	}
	return m, nil
}

// ---- identifiers ----

// purl returns the package URL of a Go module version.
func purl(path, version string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = purlEscape(s)
	}
	p := "pkg:golang/" + strings.Join(segs, "/")
	if version != "" {
		p += "@" + purlEscape(version)
	}
	return p
}

func purlEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '.' || ch == '-' || ch == '_' || ch == '~' {
			b.WriteByte(ch)
		} else {
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}

// h1Hex converts a go.sum "h1:" hash to the hex SHA-256 digest it encodes.
func h1Hex(h1 string) string {
	if !strings.HasPrefix(h1, "h1:") {
		return ""
	}
	b, err := base64.StdEncoding.DecodeString(h1[3:])
	if err != nil || len(b) != 32 {
		return ""
	}
	return hex.EncodeToString(b)
}

func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func proxyZipURL(proxy, path, version string) string {
	if proxy == "" {
		return ""
	}
	ep, err1 := module.EscapePath(path)
	ev, err2 := module.EscapeVersion(version)
	if err1 != nil || err2 != nil {
		return ""
	}
	u, err := url.Parse(proxy)
	if err != nil {
		return ""
	}
	u.User = nil
	return strings.TrimRight(u.String(), "/") + "/" + ep + "/@v/" + ev + ".zip"
}

// knownSPDX reports whether id is an SPDX license list id sm-go
// recognizes (and can therefore be emitted as an id, not a name).
func knownSPDX(id string) bool {
	_, ok := licenseInfo[id]
	return ok || extraSPDX[id]
}

var extraSPDX = map[string]bool{"0BSD": true, "BSD-1-Clause": true, "BSD-4-Clause": true, "MIT-0": true, "Apache-1.1": true,
	"MPL-1.1": true, "EPL-1.0": true, "CDDL-1.0": true, "CC-BY-4.0": true, "CC-BY-SA-4.0": true, "WTFPL": true,
	"PostgreSQL": true, "Python-2.0": true, "Unicode-DFS-2016": true, "BlueOak-1.0.0": true, "GPL-2.0-only": true,
	"GPL-2.0-or-later": true, "GPL-3.0-only": true, "GPL-3.0-or-later": true, "LGPL-2.1-only": true,
	"LGPL-2.1-or-later": true, "LGPL-3.0-only": true, "LGPL-3.0-or-later": true, "AGPL-3.0-only": true, "AGPL-3.0-or-later": true}

// ---- CycloneDX 1.5 ----

type cdxBOM struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	SerialNumber string          `json:"serialNumber"`
	Version      int             `json:"version"`
	Metadata     cdxMetadata     `json:"metadata"`
	Components   []*cdxComponent `json:"components"`
	Dependencies []cdxDependency `json:"dependencies"`
}

type cdxMetadata struct {
	Timestamp string        `json:"timestamp"`
	Tools     cdxTools      `json:"tools"`
	Component *cdxComponent `json:"component,omitempty"`
}

type cdxTools struct {
	Components []cdxToolComponent `json:"components"`
}

type cdxToolComponent struct {
	Type      string `json:"type"`
	Author    string `json:"author,omitempty"`
	Publisher string `json:"publisher,omitempty"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

type cdxComponent struct {
	Type         string        `json:"type"`
	BOMRef       string        `json:"bom-ref"`
	Name         string        `json:"name"`
	Version      string        `json:"version,omitempty"`
	Scope        string        `json:"scope,omitempty"`
	Hashes       []cdxHash     `json:"hashes,omitempty"`
	Licenses     []cdxLicense  `json:"licenses,omitempty"`
	PURL         string        `json:"purl,omitempty"`
	ExternalRefs []cdxExtRef   `json:"externalReferences,omitempty"`
	Properties   []cdxProperty `json:"properties,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxLicense struct {
	License    *cdxLicenseChoice `json:"license,omitempty"`
	Expression string            `json:"expression,omitempty"`
}

type cdxLicenseChoice struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type cdxExtRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

func cdxLicenses(ids []string) []cdxLicense {
	switch {
	case len(ids) == 0:
		return nil
	case len(ids) > 1:
		all := true
		for _, id := range ids {
			all = all && knownSPDX(id)
		}
		if all {
			return []cdxLicense{{Expression: strings.Join(ids, " AND ")}}
		}
	}
	var out []cdxLicense
	for _, id := range ids {
		if knownSPDX(id) {
			out = append(out, cdxLicense{License: &cdxLicenseChoice{ID: id}})
		} else {
			out = append(out, cdxLicense{License: &cdxLicenseChoice{Name: id}})
		}
	}
	return out
}

func buildCycloneDX(m *sbomModel) *cdxBOM {
	bom := &cdxBOM{BOMFormat: "CycloneDX", SpecVersion: "1.5", SerialNumber: "urn:uuid:" + newUUID(), Version: 1,
		Components: []*cdxComponent{}, Dependencies: []cdxDependency{}}
	bom.Metadata.Timestamp = time.Now().UTC().Format(time.RFC3339)
	bom.Metadata.Tools.Components = []cdxToolComponent{{Type: "application", Publisher: "Slash Mark IT Solutions", Name: "sm-go", Version: cli.Version}}
	refOf := map[string]string{}
	mainRef := purl(m.Name, m.Version)
	main := &cdxComponent{Type: "application", BOMRef: mainRef, Name: m.Name, Version: m.Version, PURL: mainRef}
	for _, p := range m.Properties {
		main.Properties = append(main.Properties, cdxProperty{p[0], p[1]})
	}
	bom.Metadata.Component = main
	for _, sc := range m.Components {
		ref := purl(sc.Path, sc.Version)
		refOf[sc.key()] = ref
		comp := &cdxComponent{Type: "library", BOMRef: ref, Name: sc.Path, Version: sc.Version, Scope: "required", PURL: ref,
			Licenses: cdxLicenses(sc.Licenses)}
		if h := h1Hex(sc.H1); h != "" {
			comp.Hashes = []cdxHash{{Alg: "SHA-256", Content: h}}
		}
		if sc.Replace.Path != "" {
			repl := sc.Replace.Path
			if sc.Replace.Version != "" {
				repl += "@" + sc.Replace.Version
			}
			comp.Properties = append(comp.Properties, cdxProperty{"sm-go:replace", repl})
		}
		if sc.Direct {
			comp.Properties = append(comp.Properties, cdxProperty{"sm-go:direct", "true"})
		}
		zp, zv := sc.Path, sc.Version
		if sc.Replace.Path != "" {
			zp, zv = sc.Replace.Path, sc.Replace.Version
		}
		if zv != "" {
			if u := proxyZipURL(m.ProxyURL, zp, zv); u != "" {
				comp.ExternalRefs = append(comp.ExternalRefs, cdxExtRef{Type: "distribution", URL: u})
			}
		}
		bom.Components = append(bom.Components, comp)
	}
	refs := func(keys []string) []string {
		out := []string{}
		for _, k := range keys {
			if r, ok := refOf[k]; ok {
				out = append(out, r)
			}
		}
		return out
	}
	bom.Dependencies = append(bom.Dependencies, cdxDependency{Ref: mainRef, DependsOn: refs(m.Main.DependsOn)})
	for _, sc := range m.Components {
		bom.Dependencies = append(bom.Dependencies, cdxDependency{Ref: refOf[sc.key()], DependsOn: refs(sc.DependsOn)})
	}
	return bom
}

// ---- SPDX 2.3 ----

type spdxDoc struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreation       `json:"creationInfo"`
	Packages          []*spdxPackage     `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
	ExtractedLicenses []spdxExtracted    `json:"hasExtractedLicensingInfos,omitempty"`
}

type spdxCreation struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	Name             string         `json:"name"`
	SPDXID           string         `json:"SPDXID"`
	VersionInfo      string         `json:"versionInfo,omitempty"`
	Supplier         string         `json:"supplier,omitempty"`
	DownloadLocation string         `json:"downloadLocation"`
	FilesAnalyzed    bool           `json:"filesAnalyzed"`
	Checksums        []spdxChecksum `json:"checksums,omitempty"`
	LicenseConcluded string         `json:"licenseConcluded"`
	LicenseDeclared  string         `json:"licenseDeclared"`
	CopyrightText    string         `json:"copyrightText"`
	ExternalRefs     []spdxExtRef   `json:"externalRefs,omitempty"`
	PrimaryPurpose   string         `json:"primaryPackagePurpose,omitempty"`
	Comment          string         `json:"comment,omitempty"`
}

type spdxChecksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"checksumValue"`
}

type spdxExtRef struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	Element string `json:"spdxElementId"`
	Type    string `json:"relationshipType"`
	Related string `json:"relatedSpdxElement"`
}

type spdxExtracted struct {
	LicenseID string `json:"licenseId"`
	Name      string `json:"name"`
	Text      string `json:"extractedText"`
}

var spdxIDBad = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

func buildSPDX(m *sbomModel) *spdxDoc {
	name := m.Name
	if name == "" {
		name = "unknown"
	}
	doc := &spdxDoc{SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: name,
		DocumentNamespace: "https://slashmark.in/spdx/sm-go/" + spdxIDBad.ReplaceAllString(name, "-") + "-" + newUUID(),
		Packages:          []*spdxPackage{}, Relationships: []spdxRelationship{}}
	doc.CreationInfo.Created = time.Now().UTC().Format(time.RFC3339)
	doc.CreationInfo.Creators = []string{"Tool: sm-go-" + cli.Version, "Organization: Slash Mark IT Solutions"}
	used := map[string]bool{"SPDXRef-DOCUMENT": true}
	newID := func(s string) string {
		base := "SPDXRef-Package-" + strings.Trim(spdxIDBad.ReplaceAllString(s, "-"), "-")
		id := base
		for i := 2; used[id]; i++ {
			id = fmt.Sprintf("%s-%d", base, i)
		}
		used[id] = true
		return id
	}
	extracted := map[string]bool{}
	licExpr := func(ids []string) string {
		if len(ids) == 0 {
			return "NOASSERTION"
		}
		var parts []string
		for _, id := range ids {
			if knownSPDX(id) {
				parts = append(parts, id)
				continue
			}
			ref := "LicenseRef-" + strings.Trim(spdxIDBad.ReplaceAllString(id, "-"), "-")
			if !extracted[ref] {
				extracted[ref] = true
				doc.ExtractedLicenses = append(doc.ExtractedLicenses, spdxExtracted{LicenseID: ref, Name: id,
					Text: "License identified as " + id + " (not on the SPDX license list)"})
			}
			parts = append(parts, ref)
		}
		return strings.Join(parts, " AND ")
	}
	mainID := newID(name + "-main")
	mainPkg := &spdxPackage{Name: name, SPDXID: mainID, VersionInfo: m.Version, DownloadLocation: "NOASSERTION",
		LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION", PrimaryPurpose: "APPLICATION",
		ExternalRefs: []spdxExtRef{{"PACKAGE-MANAGER", "purl", purl(name, m.Version)}}}
	if m.Source == "binary" {
		mainPkg.Comment = "SBOM generated from the build information embedded in the executable (" + m.GoVersion + ")"
	}
	doc.Packages = append(doc.Packages, mainPkg)
	doc.Relationships = append(doc.Relationships, spdxRelationship{"SPDXRef-DOCUMENT", "DESCRIBES", mainID})
	idOf := map[string]string{}
	for _, sc := range m.Components {
		id := newID(sc.Path + "-" + sc.Version)
		idOf[sc.key()] = id
		pk := &spdxPackage{Name: sc.Path, SPDXID: id, VersionInfo: sc.Version, DownloadLocation: "NOASSERTION",
			LicenseConcluded: "NOASSERTION", LicenseDeclared: licExpr(sc.Licenses), CopyrightText: "NOASSERTION",
			PrimaryPurpose: "LIBRARY", ExternalRefs: []spdxExtRef{{"PACKAGE-MANAGER", "purl", purl(sc.Path, sc.Version)}}}
		zp, zv := sc.Path, sc.Version
		if sc.Replace.Path != "" {
			zp, zv = sc.Replace.Path, sc.Replace.Version
			if zv != "" {
				pk.Comment = "replaced by " + zp + "@" + zv
			} else {
				pk.Comment = "replaced by local directory " + zp
			}
		}
		if zv != "" {
			if u := proxyZipURL(m.ProxyURL, zp, zv); u != "" {
				pk.DownloadLocation = u
			}
		}
		if h := h1Hex(sc.H1); h != "" {
			pk.Checksums = []spdxChecksum{{"SHA256", h}}
		}
		doc.Packages = append(doc.Packages, pk)
	}
	for _, k := range m.Main.DependsOn {
		if id, ok := idOf[k]; ok {
			doc.Relationships = append(doc.Relationships, spdxRelationship{mainID, "DEPENDS_ON", id})
		}
	}
	for _, sc := range m.Components {
		for _, k := range sc.DependsOn {
			if id, ok := idOf[k]; ok {
				doc.Relationships = append(doc.Relationships, spdxRelationship{idOf[sc.key()], "DEPENDS_ON", id})
			}
		}
	}
	return doc
}
