package compliance

import (
	"regexp"
	"sort"
	"strings"
	"sync"
)

// License identification by normalized text similarity.
//
// Both the reference texts below and the candidate file are normalized
// (lower case, copyright lines and "all rights reserved" removed,
// punctuation, list markers and single-character tokens dropped, British
// spellings unified) and cut into word 3-grams ("shingles"). For each
// reference template t and document d:
//
//	coverage(t) = |S(t) ∩ S(d)| / |S(t)|
//	score(t)    = |S(t) ∩ S(d)| - |S(t) \ S(d)|
//
// A template matches when its coverage reaches minCoverage. Among matches
// the highest score wins, which prefers the most specific license (a
// BSD-3-Clause text covers the BSD-2-Clause template completely, but the
// BSD-3-Clause template scores higher; a BSD-2-Clause text misses the
// third clause of BSD-3-Clause and so scores lower there). Further
// licenses in the same file (dual-licensing files that concatenate two
// texts) are accepted only if most of their matched shingles are not
// already explained by an accepted license.

const (
	shingleN    = 3
	minCoverage = 0.80
)

// LicenseInfo describes an SPDX license known to sm-go.
type LicenseInfo struct {
	ID   string
	Name string
	// Copyleft is "", "weak", "strong" or "network".
	Copyleft string
}

var licenseInfo = map[string]LicenseInfo{
	"MIT":          {"MIT", "MIT License", ""},
	"Apache-2.0":   {"Apache-2.0", "Apache License 2.0", ""},
	"BSD-2-Clause": {"BSD-2-Clause", `BSD 2-Clause "Simplified" License`, ""},
	"BSD-3-Clause": {"BSD-3-Clause", `BSD 3-Clause "New" or "Revised" License`, ""},
	"ISC":          {"ISC", "ISC License", ""},
	"MPL-2.0":      {"MPL-2.0", "Mozilla Public License 2.0", "weak"},
	"GPL-2.0":      {"GPL-2.0", "GNU General Public License v2.0", "strong"},
	"GPL-3.0":      {"GPL-3.0", "GNU General Public License v3.0", "strong"},
	"LGPL-2.1":     {"LGPL-2.1", "GNU Lesser General Public License v2.1", "weak"},
	"LGPL-3.0":     {"LGPL-3.0", "GNU Lesser General Public License v3.0", "weak"},
	"AGPL-3.0":     {"AGPL-3.0", "GNU Affero General Public License v3.0", "network"},
	"Unlicense":    {"Unlicense", "The Unlicense", ""},
	"CC0-1.0":      {"CC0-1.0", "Creative Commons Zero v1.0 Universal", ""},
	"EPL-2.0":      {"EPL-2.0", "Eclipse Public License 2.0", "weak"},
	"Zlib":         {"Zlib", "zlib License", ""},
	"BSL-1.0":      {"BSL-1.0", "Boost Software License 1.0", ""},
}

// spdxAliases maps common non-canonical identifiers (including deprecated
// SPDX ids and the "-only"/"-or-later" forms) to the ids used here.
var spdxAliases = map[string]string{
	"apache2": "Apache-2.0", "apache-2": "Apache-2.0", "apache 2.0": "Apache-2.0",
	"gpl-2.0-only": "GPL-2.0", "gpl-2.0-or-later": "GPL-2.0", "gpl-2.0+": "GPL-2.0", "gplv2": "GPL-2.0",
	"gpl-3.0-only": "GPL-3.0", "gpl-3.0-or-later": "GPL-3.0", "gpl-3.0+": "GPL-3.0", "gplv3": "GPL-3.0",
	"lgpl-2.1-only": "LGPL-2.1", "lgpl-2.1-or-later": "LGPL-2.1", "lgpl-2.1+": "LGPL-2.1",
	"lgpl-3.0-only": "LGPL-3.0", "lgpl-3.0-or-later": "LGPL-3.0", "lgpl-3.0+": "LGPL-3.0",
	"agpl-3.0-only": "AGPL-3.0", "agpl-3.0-or-later": "AGPL-3.0",
	"bsd-2": "BSD-2-Clause", "bsd-3": "BSD-3-Clause", "0bsd": "0BSD",
	"boost": "BSL-1.0", "mpl2": "MPL-2.0", "mpl-2": "MPL-2.0",
}

// CanonicalSPDX normalizes an SPDX identifier ("gpl-3.0-only" ->
// "GPL-3.0"); unknown ids are returned trimmed but otherwise unchanged.
func CanonicalSPDX(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	if a, ok := spdxAliases[strings.ToLower(id)]; ok {
		return a
	}
	for k := range licenseInfo {
		if strings.EqualFold(k, id) {
			return k
		}
	}
	return id
}

// Copyleft returns the copyleft class of an SPDX id ("", weak, strong,
// network).
func Copyleft(id string) string { return licenseInfo[CanonicalSPDX(id)].Copyleft }

type template struct {
	id       string
	shingles map[string]bool
}

var (
	tmplOnce  sync.Once
	templates []*template
)

func loadTemplates() []*template {
	tmplOnce.Do(func() {
		ids := make([]string, 0, len(licenseTexts))
		for id := range licenseTexts {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			for _, text := range licenseTexts[id] {
				templates = append(templates, &template{id: id, shingles: shingles(normalizeLicense(text))})
			}
		}
	})
	return templates
}

var (
	copyrightLineRE = regexp.MustCompile(`(?im)^[\s#/*>-]*(copyright|\(c\)|©)\s*(\(c\)|©|\d{4}|[a-z]+ \d{4}).*$`)
	rightsRE        = regexp.MustCompile(`(?i)all\s+rights\s+reserved\.?`)
	urlSchemeRE     = regexp.MustCompile(`(?i)https?://`)
	wordRE          = regexp.MustCompile(`[a-z0-9]+`)
)

var spellings = map[string]string{
	"licence": "license", "licences": "licenses", "licenced": "licensed",
	"authorised": "authorized", "organisation": "organization", "behaviour": "behavior",
	"nonexclusive": "non exclusive", "noninfringement": "non infringement",
	"acknowledgement": "acknowledgment",
}

// normalizeLicense turns license text into a token list.
func normalizeLicense(text string) []string {
	text = copyrightLineRE.ReplaceAllString(text, " ")
	text = rightsRE.ReplaceAllString(text, " ")
	text = urlSchemeRE.ReplaceAllString(text, " ")
	text = strings.ToLower(text)
	text = strings.NewReplacer("&", " and ", "©", " ", "–", " ", "—", " ", "’", "'", "“", "\"", "”", "\"").Replace(text)
	var out []string
	for _, w := range wordRE.FindAllString(text, -1) {
		if r, ok := spellings[w]; ok {
			out = append(out, strings.Fields(r)...)
			continue
		}
		if len(w) == 1 {
			continue // list markers, single digits, "a"
		}
		out = append(out, w)
	}
	return out
}

func shingles(words []string) map[string]bool {
	s := map[string]bool{}
	for i := 0; i+shingleN <= len(words); i++ {
		s[strings.Join(words[i:i+shingleN], " ")] = true
	}
	return s
}

// LicenseMatch is one license identified in a text.
type LicenseMatch struct {
	ID         string  `json:"spdx"`
	Confidence float64 `json:"confidence"`
	Method     string  `json:"method"` // "text" or "spdx-tag"
}

var spdxTagRE = regexp.MustCompile(`(?m)SPDX-License-Identifier:\s*([^\n*]+?)\s*(?:\*/)?\s*$`)

// IdentifyLicenses identifies the licenses in a license file's text.
func IdentifyLicenses(text string) []LicenseMatch {
	doc := shingles(normalizeLicense(text))
	type cand struct {
		t        *template
		matched  map[string]bool
		coverage float64
		score    int
	}
	var cands []cand
	if len(doc) > 0 {
		for _, t := range loadTemplates() {
			m := map[string]bool{}
			for s := range t.shingles {
				if doc[s] {
					m[s] = true
				}
			}
			cov := float64(len(m)) / float64(len(t.shingles))
			if cov < minCoverage {
				continue
			}
			cands = append(cands, cand{t, m, cov, len(m) - (len(t.shingles) - len(m))})
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		return cands[i].t.id < cands[j].t.id
	})
	var out []LicenseMatch
	explained := map[string]bool{}
	seen := map[string]int{}
	for _, cd := range cands {
		if i, ok := seen[cd.t.id]; ok {
			// Another template of the same license (e.g. the Apache
			// notice): keep the best confidence.
			if cd.coverage > out[i].Confidence {
				out[i].Confidence = round2(cd.coverage)
			}
			for s := range cd.matched {
				explained[s] = true
			}
			continue
		}
		overlap := 0
		for s := range cd.matched {
			if explained[s] {
				overlap++
			}
		}
		if len(out) > 0 && float64(overlap) > 0.5*float64(len(cd.matched)) {
			continue
		}
		for s := range cd.matched {
			explained[s] = true
		}
		seen[cd.t.id] = len(out)
		out = append(out, LicenseMatch{ID: cd.t.id, Confidence: round2(cd.coverage), Method: "text"})
	}
	if len(out) == 0 {
		for _, m := range spdxTagRE.FindAllStringSubmatch(text, -1) {
			for _, id := range splitSPDXExpr(m[1]) {
				if _, dup := seen[id]; dup {
					continue
				}
				seen[id] = len(out)
				out = append(out, LicenseMatch{ID: id, Confidence: 1, Method: "spdx-tag"})
			}
		}
	}
	return out
}

// splitSPDXExpr returns the license ids of an SPDX expression
// ("MIT OR Apache-2.0" -> [MIT Apache-2.0]).
func splitSPDXExpr(expr string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(expr, func(r rune) bool { return r == ' ' || r == '(' || r == ')' }) {
		switch strings.ToUpper(f) {
		case "AND", "OR", "WITH":
			continue
		}
		if strings.Contains(f, "exception") || strings.Contains(f, "Exception") {
			continue
		}
		out = append(out, CanonicalSPDX(f))
	}
	return out
}

func round2(f float64) float64 { return float64(int(f*100+0.5)) / 100 }

var (
	licenseFileRE = regexp.MustCompile(`(?i)^(licen[cs]e|copying|unlicen[cs]e|copyright|mit[-_]licen[cs]e|licen[cs]e[-_](mit|apache|bsd|gpl)[-_.0-9a-z]*)([-._][-._0-9a-z]*)?$`)
	noticeFileRE  = regexp.MustCompile(`(?i)^notice([-._][-._0-9a-z]*)?$`)
)

// licenseFileKind classifies a file name: "license", "notice" or "".
// Files under vendor/ and testdata/ are ignored.
func licenseFileKind(name string) string {
	els := strings.Split(name, "/")
	for _, el := range els[:len(els)-1] {
		if el == "vendor" || el == "testdata" || strings.HasPrefix(el, ".") || strings.HasPrefix(el, "_") {
			return ""
		}
	}
	base := els[len(els)-1]
	if strings.HasSuffix(strings.ToLower(base), ".go") {
		return ""
	}
	switch {
	case licenseFileRE.MatchString(base):
		return "license"
	case noticeFileRE.MatchString(base):
		return "notice"
	}
	return ""
}
