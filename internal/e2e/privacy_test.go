package e2e

import (
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

const mitText = `MIT License

Copyright (c) 2025 Test

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`

// privateEnv marks github.com/corp and corp.example.com private
// (GOPRIVATE), plus a private look-alike of a popular module through
// GONOSUMDB alone. GONOPROXY=none lets the fake (corporate) proxy serve
// the private modules, as with Athens or Artifactory.
var privateEnv = []string{
	"GOPRIVATE=github.com/corp,corp.example.com",
	"GONOPROXY=none",
	"GONOSUMDB=github.com/corp,corp.example.com,github.com/siruspen",
}

// privateNames are the strings that must never reach a third-party
// service, in any form.
var privateNames = []string{"github.com/corp", "corp.example.com", "github.com/siruspen", "corpinternal", "siruspen"}

// TestPrivateModulesNotLeaked runs every tool that consults third-party
// services on a project with private dependencies and checks, from the
// fake server's request log, that no private module path or domain was
// sent to deps.dev (including Scorecard and dependents), RDAP or OSV, and
// that the GitHub API was asked only about private modules whose path is
// on github.com.
func TestPrivateModulesNotLeaked(t *testing.T) {
	w := testenv.New(t)
	lib := func(pkg string) map[string]string {
		return map[string]string{"LICENSE": mitText, pkg + ".go": "package " + pkg + "\n\nfunc F() string { return \"" + pkg + "\" }\n"}
	}
	w.AddModule("github.com/corp/secretlib", "v1.0.0", lib("secretlib"))
	w.AddModule("github.com/corp/secretlib", "v1.1.0", lib("secretlib"))
	auth := w.AddModule("corp.example.com/internal/auth", "v1.2.0", lib("auth"))
	auth.Origin = map[string]string{"VCS": "git", "URL": "https://github.com/corpinternal/auth", "Ref": "refs/tags/v1.2.0", "Hash": strings.Repeat("a", 40)}
	w.AddModule("github.com/siruspen/logrus", "v1.9.3", lib("logrus"))
	w.AddModule("github.com/pub/util", "v1.0.0", lib("util"))
	w.AddModule("github.com/corp/util-fork", "v1.0.1", map[string]string{"go.mod": "module github.com/pub/util\n\ngo 1.21\n",
		"LICENSE": mitText, "util.go": "package util\n\nfunc F() string { return \"fork\" }\n"})
	w.AddModule("vanity.pub.org/lib", "v0.4.0", lib("lib"))

	w.Vanity["corp.example.com/internal/auth"] = `<meta name="go-import" content="corp.example.com/internal/auth git https://github.com/corpinternal/auth">`
	w.Vanity["vanity.pub.org/lib"] = `<meta name="go-import" content="vanity.pub.org/lib git https://github.com/pub/lib">`
	w.RDAP["domain/pub.org"] = map[string]any{"ldhName": "pub.org", "events": []map[string]string{
		{"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"}, {"eventAction": "expiration", "eventDate": "2099-01-01T00:00:00Z"}}}
	w.DepsDev["v3/systems/go/packages/vanity.pub.org%2Flib/versions/v0.4.0"] = map[string]any{"licenses": []string{"MIT"}}
	w.GitHub["repos/corp/secretlib"] = map[string]any{"full_name": "corp/secretlib", "private": true, "created_at": "2020-01-01T00:00:00Z"}
	w.GitHub["users/corp"] = map[string]any{"login": "corp", "type": "Organization", "created_at": "2015-01-01T00:00:00Z"}
	w.GitHub["repos/pub/util"] = map[string]any{"full_name": "pub/util", "created_at": "2020-01-01T00:00:00Z", "stargazers_count": 10}

	dir := w.Project(map[string]string{
		"go.mod": testenv.GoModFile("example.com/app", "1.21",
			"github.com/corp/secretlib@v1.0.0", "corp.example.com/internal/auth@v1.2.0", "github.com/siruspen/logrus@v1.9.3",
			"github.com/pub/util@v1.0.0", "vanity.pub.org/lib@v0.4.0") +
			"\nreplace github.com/pub/util => github.com/corp/util-fork v1.0.1\n",
		"main.go": `package main

import (
	"corp.example.com/internal/auth"
	"github.com/corp/secretlib"
	"github.com/pub/util"
	"github.com/siruspen/logrus"
	"vanity.pub.org/lib"
)

func main() { println(auth.F(), secretlib.F(), util.F(), logrus.F(), lib.F()) }
`,
	})
	if out, err := w.GoEnv(dir, privateEnv, "mod", "tidy"); err != nil {
		t.Fatalf("go mod tidy: %v\n%s", err, out)
	}
	policy := filepath.Join(t.TempDir(), "policy.json")
	testenv.WriteFiles(t, filepath.Dir(policy), map[string]string{"policy.json": `{"licenses": {"deny": ["GPL-*"]}, "forbidRetracted": true}`})

	runs := [][]string{
		{"license"},
		{"sbom"},
		{"gate", "--policy", policy},
		{"health"},
		{"takeover"},
		{"vanity"},
		{"retag"},
		{"typosquat"},
		{"replace"},
	}
	for _, args := range runs {
		r := w.RunEnv(dir, privateEnv, append(args, "--json")...)
		if r.Code != 0 && r.Code != 1 {
			t.Errorf("sm-go %s: exit %d\n%s\n%s", strings.Join(args, " "), r.Code, r.Stdout, r.Stderr)
		}
		env := r.JSON(t)
		ws, _ := env["warnings"].([]any)
		n := 0
		for _, x := range ws {
			if s, _ := x.(string); strings.Contains(s, "not sent to third-party services") {
				n++
			}
		}
		if n > 1 {
			t.Errorf("sm-go %s: %d private-module warnings, want at most one: %v", args[0], n, ws)
		}
	}

	// Positive controls: the public modules were looked up, so the log
	// is not trivially clean.
	var sawDepsDev, sawRDAP bool
	for _, req := range w.Requests {
		sawDepsDev = sawDepsDev || strings.Contains(req, "/depsdev/") && strings.Contains(req, "vanity.pub.org")
		sawRDAP = sawRDAP || strings.Contains(req, "/rdap/domain/pub.org")
	}
	if !sawDepsDev || !sawRDAP {
		t.Errorf("public modules were not looked up (deps.dev %v, RDAP %v); requests:\n%s", sawDepsDev, sawRDAP, strings.Join(w.Requests, "\n"))
	}

	for _, req := range w.Requests {
		_, uri, _ := strings.Cut(req, " ")
		third := strings.HasPrefix(uri, "/depsdev/") || strings.HasPrefix(uri, "/rdap/") || strings.HasPrefix(uri, "/osv/") ||
			strings.Contains(strings.ToLower(uri), "scorecard")
		if third {
			if leak := leaked(uri, privateNames...); leak != "" {
				t.Errorf("private name %q sent to a third-party service: %s", leak, req)
			}
			// corp.example.com's registrable domain must not be looked up either.
			if strings.HasPrefix(uri, "/rdap/") && leaked(uri, "example.com") != "" {
				t.Errorf("registrable domain of a private module sent to RDAP: %s", req)
			}
		}
		// The GitHub API is the own host of github.com/corp/... only; a
		// private vanity module hosted on GitHub must not be asked about.
		if strings.HasPrefix(uri, "/github/") {
			if leak := leaked(uri, "corpinternal", "corp.example.com"); leak != "" {
				t.Errorf("GitHub API asked about private non-github.com module (%q): %s", leak, req)
			}
		}
	}
}

// leaked returns the first name that occurs in uri raw, path-escaped,
// query-escaped or after unescaping.
func leaked(uri string, names ...string) string {
	low := strings.ToLower(uri)
	dec, err := url.PathUnescape(uri)
	if err != nil {
		dec = uri
	}
	dec = strings.ToLower(dec)
	for _, n := range names {
		n = strings.ToLower(n)
		for _, form := range []string{n, url.PathEscape(n), url.QueryEscape(n), strings.ToLower(url.PathEscape(n))} {
			if strings.Contains(low, strings.ToLower(form)) || strings.Contains(dec, form) {
				return n
			}
		}
	}
	return ""
}
