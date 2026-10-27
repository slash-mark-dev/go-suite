package compliance

import (
	"strings"
	"testing"
)

// Real-world shaped license files (owner names, different wrapping,
// bullets instead of numbers, headings, markdown).
const (
	goBSD3 = `Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
`

	mdMIT = "# MIT License\n\nCopyright (c) 2021 Jane Doe <jane@example.com>\n\n" +
		"Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:\n\n" +
		"The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.\n\n" +
		"THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.\n"

	bsd2 = `BSD 2-Clause License

Copyright (c) 2018, Acme Corp
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
`

	isc = `ISC License

Copyright (c) 2015-2020, Some Person <p@example.org>

Permission to use, copy, modify, and/or distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright notice
and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE.
`
)

// reflow rewraps text to the given width and indents it, as many
// projects do.
func reflow(text string, width int, indent string) string {
	var out strings.Builder
	for _, para := range strings.Split(text, "\n\n") {
		words := strings.Fields(para)
		line := indent
		for _, w := range words {
			if len(line)+len(w)+1 > width && strings.TrimSpace(line) != "" {
				out.WriteString(strings.TrimRight(line, " ") + "\n")
				line = indent
			}
			line += w + " "
		}
		out.WriteString(strings.TrimRight(line, " ") + "\n\n")
	}
	return out.String()
}

func ids(ms []LicenseMatch) string {
	var s []string
	for _, m := range ms {
		s = append(s, m.ID)
	}
	return strings.Join(s, ",")
}

func TestIdentifyLicenses(t *testing.T) {
	apacheFull := "\n" + reflow(licenseTexts["Apache-2.0"][0], 76, "   ") +
		"\n   4. Redistribution. You may reproduce and distribute copies of the\n   Work ...\n\n   END OF TERMS AND CONDITIONS\n\n   APPENDIX: How to apply the Apache License to your work.\n\n   Copyright [yyyy] [name of copyright owner]\n\n" +
		reflow(licenseTexts["Apache-2.0"][1], 72, "   ")
	cases := []struct {
		name, text, want string
	}{
		{"go-bsd3", goBSD3, "BSD-3-Clause"},
		{"markdown-mit", mdMIT, "MIT"},
		{"bsd2", bsd2, "BSD-2-Clause"},
		{"isc", isc, "ISC"},
		{"apache-full", apacheFull, "Apache-2.0"},
		{"apache-notice", "Copyright 2020 Foo Inc.\n\n" + reflow(licenseTexts["Apache-2.0"][1], 60, "// "), "Apache-2.0"},
		{"gpl3", "                    " + reflow(licenseTexts["GPL-3.0"][0], 72, "  "), "GPL-3.0"},
		{"agpl3", reflow(licenseTexts["AGPL-3.0"][0], 70, ""), "AGPL-3.0"},
		{"gpl2", reflow(licenseTexts["GPL-2.0"][0], 70, "    "), "GPL-2.0"},
		{"lgpl21", reflow(licenseTexts["LGPL-2.1"][0], 66, ""), "LGPL-2.1"},
		{"lgpl3", reflow(licenseTexts["LGPL-3.0"][0], 66, ""), "LGPL-3.0"},
		{"mpl2", reflow(licenseTexts["MPL-2.0"][0], 80, "  "), "MPL-2.0"},
		{"epl2", reflow(licenseTexts["EPL-2.0"][0], 80, ""), "EPL-2.0"},
		{"cc0", reflow(licenseTexts["CC0-1.0"][0], 75, ""), "CC0-1.0"},
		{"unlicense", reflow(licenseTexts["Unlicense"][0], 70, ""), "Unlicense"},
		{"zlib", "zlib License\n\n(C) 1995-2017 Jean-loup Gailly and Mark Adler\n\n" + licenseTexts["Zlib"][0], "Zlib"},
		{"bsl", reflow(licenseTexts["BSL-1.0"][0], 72, ""), "BSL-1.0"},
		{"dual-mit-apache", "This project is dual licensed.\n\n" + mdMIT + "\n\n---\n\n" + apacheFull, "Apache-2.0,MIT"},
		{"spdx-tag", "SPDX-License-Identifier: MPL-2.0 OR Apache-2.0\n", "MPL-2.0,Apache-2.0"},
		{"spdx-tag-alias", "// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0\n", "GPL-2.0"},
		{"proprietary", "Copyright 2024 Acme. All rights reserved. This software is proprietary and confidential; no license is granted.\n", ""},
		{"half-mit", strings.Join(strings.Fields(mdMIT)[:60], " "), ""},
	}
	for _, tc := range cases {
		got := IdentifyLicenses(tc.text)
		if ids(got) != tc.want {
			t.Errorf("%s: got %q (%+v), want %q", tc.name, ids(got), got, tc.want)
		}
		for _, m := range got {
			if m.Method == "text" && m.Confidence < minCoverage {
				t.Errorf("%s: confidence %v below threshold", tc.name, m.Confidence)
			}
		}
	}
}

// Every reference text must identify as itself and only itself, and must
// not reach the threshold of another license by accident.
func TestTemplatesDistinct(t *testing.T) {
	for id, texts := range licenseTexts {
		for i, text := range texts {
			got := IdentifyLicenses(text)
			if len(got) != 1 || got[0].ID != id {
				t.Errorf("template %s[%d] identified as %+v", id, i, got)
			}
		}
	}
}

func TestLicenseFileKind(t *testing.T) {
	cases := map[string]string{
		"LICENSE": "license", "LICENSE.md": "license", "license.txt": "license", "LICENCE": "license",
		"COPYING": "license", "COPYING.LESSER": "license", "UNLICENSE": "license", "LICENSE-MIT": "license",
		"LICENSE-APACHE": "license", "MIT-LICENSE.txt": "license", "NOTICE": "notice", "NOTICE.txt": "notice",
		"sub/LICENSE": "license", "vendor/x/LICENSE": "", "testdata/LICENSE": "", "license.go": "",
		"README.md": "", "licenses.go": "", ".github/LICENSE": "",
	}
	for name, want := range cases {
		if got := licenseFileKind(name); got != want {
			t.Errorf("licenseFileKind(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestCanonicalSPDX(t *testing.T) {
	for in, want := range map[string]string{"mit": "MIT", "apache-2.0": "Apache-2.0", "GPL-3.0-only": "GPL-3.0",
		"LGPL-2.1-or-later": "LGPL-2.1", "bsd-3-clause": "BSD-3-Clause", "Custom-1": "Custom-1"} {
		if got := CanonicalSPDX(in); got != want {
			t.Errorf("CanonicalSPDX(%q) = %q, want %q", in, got, want)
		}
	}
}
