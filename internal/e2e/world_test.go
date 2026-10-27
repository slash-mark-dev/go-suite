package e2e

import (
	"crypto/sha1"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
	"github.com/slash-mark-dev/go-suite/internal/vulndb"
)

// This file builds the fake world the documented examples run against: a
// realistic application module (example.com/app) and everything it
// depends on, published on the fake proxy, plus the side fixtures some
// examples need (a library checkout, a workspace, a vendored copy and
// compiled binaries).

const mitLicense = `MIT License

Copyright (c) 2020 The Authors

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

const bsd3License = `Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
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

func sha(c byte) string { return strings.Repeat(string(c), 40) }

// fixtures are the directories the examples run in.
type fixtures struct {
	w *testenv.World
	// app is the main module example.com/app (go.mod, go.sum, cmd/server,
	// a nested service/ module, ci/policy.json, built binaries).
	app string
	// lib is a git checkout of github.com/acme/lib with one unreleased
	// API addition (release, apidiff --against).
	lib string
	// ws is a go.work workspace with two modules.
	ws string
	// vendored is a copy of app with vendor/.
	vendored string
}

func mustGo(t *testing.T, w *testenv.World, dir string, extra []string, args ...string) {
	t.Helper()
	if out, err := w.GoEnv(dir, extra, args...); err != nil {
		t.Fatalf("go %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
}

func buildWorld(t *testing.T) *fixtures {
	w := testenv.New(t)
	now := time.Now()
	day := 24 * time.Hour
	origin := func(repo, tag, hash string) map[string]string {
		return map[string]string{"VCS": "git", "URL": "https://github.com/" + repo, "Ref": "refs/tags/" + tag, "Hash": hash}
	}
	add := func(path, version string, files map[string]string) *testenv.Mod {
		if files["LICENSE"] == "" {
			if strings.HasPrefix(path, "golang.org/x/") || strings.HasPrefix(path, "github.com/google/") {
				files["LICENSE"] = bsd3License
			} else {
				files["LICENSE"] = mitLicense
			}
		}
		return w.AddModule(path, version, files)
	}

	// --- golang.org/x ---
	add("golang.org/x/sys", "v0.15.0", map[string]string{
		"unix/unix.go": "package unix\n\nimport \"syscall\"\n\nfunc Getpid() int { return syscall.Getpid() }\n",
	})
	textSrc := "package language\n\n// Tag is a BCP 47 language tag.\ntype Tag string\n\n// Parse parses a tag.\nfunc Parse(s string) (Tag, error) { return Tag(s), nil }\n"
	add("golang.org/x/text", "v0.3.7", map[string]string{"language/language.go": textSrc})
	add("golang.org/x/text", "v0.14.0", map[string]string{"language/language.go": textSrc})
	add("golang.org/x/text", "v0.15.0", map[string]string{"language/language.go": textSrc +
		"\n// MustParse is like Parse but panics on error.\nfunc MustParse(s string) Tag { t, _ := Parse(s); return t }\n"})
	add("golang.org/x/text", "v0.21.0", map[string]string{"language/language.go": textSrc +
		"\nfunc MustParse(s string) Tag { t, _ := Parse(s); return t }\n",
		"language/gen.go": "package language\n\nimport \"os/exec\"\n\nfunc regenerate() error { return exec.Command(\"go\", \"generate\").Run() }\n\nvar _ = regenerate\n"})
	netHTML := "package html\n\nimport \"golang.org/x/text/language\"\n\n// Node is a parsed node.\ntype Node struct{ Lang language.Tag }\n\n// Parse parses HTML.\nfunc Parse(s string) (*Node, error) { t, err := language.Parse(s); return &Node{Lang: t}, err }\n"
	add("golang.org/x/net", "v0.20.0", map[string]string{
		"go.mod":       testenv.GoModFile("golang.org/x/net", "1.18", "golang.org/x/text@v0.14.0"),
		"html/html.go": netHTML,
	})
	add("golang.org/x/net", "v0.21.0", map[string]string{
		"go.mod":       testenv.GoModFile("golang.org/x/net", "1.18", "golang.org/x/text@v0.15.0"),
		"html/html.go": netHTML + "\n// Render renders a node.\nfunc Render(n *Node) string { return string(n.Lang) }\n",
	})

	// --- logrus (tag recorded by the proxy; v1.9.4 adds exec). Like the
	// real logrus it declares go 1.13, so it cannot use any/generics. ---
	logrusSrc := "package logrus\n\nimport (\n\t\"fmt\"\n\t\"os\"\n\n\t\"golang.org/x/sys/unix\"\n)\n\nvar level = \"info\"\n\nfunc init() {\n\tif v := os.Getenv(\"LOGRUS_LEVEL\"); v != \"\" {\n\t\tlevel = v\n\t}\n}\n\n// Info logs at info level.\nfunc Info(args ...interface{}) { fmt.Fprintln(os.Stderr, append([]interface{}{level, unix.Getpid()}, args...)...) }\n"
	add("github.com/sirupsen/logrus", "v1.9.3", map[string]string{
		"go.mod":    testenv.GoModFile("github.com/sirupsen/logrus", "1.13", "golang.org/x/sys@v0.15.0"),
		"logrus.go": logrusSrc,
	}).Origin = origin("sirupsen/logrus", "v1.9.3", sha('a'))
	add("github.com/sirupsen/logrus", "v1.9.4", map[string]string{
		"go.mod":    testenv.GoModFile("github.com/sirupsen/logrus", "1.13", "golang.org/x/sys@v0.15.0"),
		"logrus.go": logrusSrc,
		"hooks.go":  "package logrus\n\nimport \"os/exec\"\n\n// RunHook runs an external hook.\nfunc RunHook(name string) error { return exec.Command(name).Run() }\n",
	}).Origin = origin("sirupsen/logrus", "v1.9.4", sha('b'))
	w.GitHubRepo("sirupsen", "logrus", map[string]any{"stargazers_count": 24000, "pushed_at": now.Add(-20 * 24 * time.Hour).UTC().Format(time.RFC3339)})
	w.GitHubTag("sirupsen", "logrus", "v1.9.3", sha('a'))
	w.GitHubTag("sirupsen", "logrus", "v1.9.4", sha('b'))
	w.GitHub["repos/sirupsen/logrus/contributors?per_page=100"] = []map[string]any{{"login": "sirupsen", "contributions": 400}, {"login": "dgsb", "contributions": 120}, {"login": "x", "contributions": 30}}
	w.DepsDev["v3/projects/github.com/sirupsen/logrus"] = map[string]any{"scorecard": map[string]any{"date": "2026-10-01", "overallScore": 6.1}}

	// --- cobra / pflag ---
	add("github.com/spf13/pflag", "v1.0.5", map[string]string{"flag.go": "package pflag\n\n// String defines a string flag.\nfunc String(name, def, usage string) *string { return &def }\n"})
	add("github.com/spf13/pflag", "v1.0.6", map[string]string{"flag.go": "package pflag\n\nfunc String(name, def, usage string) *string { return &def }\n\nfunc Bool(name string, def bool, usage string) *bool { return &def }\n"})
	cobraSrc := "package cobra\n\nimport \"github.com/spf13/pflag\"\n\n// Command is a CLI command.\ntype Command struct{ Use string }\n\n// Execute runs the command.\nfunc (c *Command) Execute() error { _ = pflag.String(\"x\", \"\", \"\"); return nil }\n"
	add("github.com/spf13/cobra", "v1.7.0", map[string]string{
		"go.mod":   testenv.GoModFile("github.com/spf13/cobra", "1.15", "github.com/spf13/pflag@v1.0.5", "golang.org/x/text@v0.3.7"),
		"cobra.go": cobraSrc,
	})
	add("github.com/spf13/cobra", "v1.8.0", map[string]string{
		"go.mod":   testenv.GoModFile("github.com/spf13/cobra", "1.15", "github.com/spf13/pflag@v1.0.6"),
		"cobra.go": cobraSrc,
	})
	w.GitHubRepo("spf13", "cobra", map[string]any{"stargazers_count": 37000})
	w.GitHubRepo("spf13", "pflag", nil)

	// --- github.com/acme/lib: v1.4.0 vulnerable (Parse) and retracted ---
	acmeSrc := "package lib\n\nimport (\n\t\"fmt\"\n\t\"strconv\"\n\t\"strings\"\n)\n\n// Parse parses a number.\nfunc Parse(s string) (int, error) {\n\ts = strings.TrimSpace(s)\n\tn, err := strconv.Atoi(s)\n\tif err != nil {\n\t\treturn 0, fmt.Errorf(\"lib: parse %q: %w\", s, err)\n\t}\n\treturn n, nil\n}\n\n// Version returns the library version.\nfunc Version() string { return \"1\" }\n"
	add("github.com/acme/lib", "v1.3.0", map[string]string{"lib.go": acmeSrc}).Origin = origin("acme/lib", "v1.3.0", sha('c'))
	add("github.com/acme/lib", "v1.4.0", map[string]string{"lib.go": acmeSrc}).Origin = origin("acme/lib", "v1.4.0", sha('d'))
	add("github.com/acme/lib", "v1.4.1", map[string]string{
		"go.mod": "module github.com/acme/lib\n\ngo 1.21\n\nretract v1.4.0 // Parse accepts out-of-range input (GO-2025-0101)\n",
		"lib.go": acmeSrc,
	}).Origin = origin("acme/lib", "v1.4.1", sha('e'))
	w.GitHubRepo("acme", "lib", nil)
	w.GitHubTag("acme", "lib", "v1.3.0", sha('c'))
	w.GitHubTag("acme", "lib", "v1.4.0", sha('f')) // moved tag
	w.GitHubTag("acme", "lib", "v1.4.1", sha('e'))
	vuln := func(e *vulndb.Entry, summary string) {
		e.Summary, e.Details = summary, summary+"."
		e.Published = now.Add(-60 * 24 * time.Hour).UTC().Truncate(time.Second)
		e.Modified = e.Published
		w.AddVuln(e)
	}
	vuln(testenv.SimpleVuln("GO-2025-0101", "github.com/acme/lib", "v1.4.0", "v1.4.1", "github.com/acme/lib", []string{"Parse"}, "CVE-2025-31337"),
		"Integer overflow in Parse in github.com/acme/lib")
	w.KEV = append(w.KEV, map[string]string{"cveID": "CVE-2025-31337", "vendorProject": "acme", "product": "lib", "vulnerabilityName": "acme lib Parse", "dateAdded": "2025-07-01"})
	w.EPSS["CVE-2025-31337"] = [2]float64{0.87, 0.99}
	// Imported but not called.
	vuln(testenv.SimpleVuln("GO-2025-0102", "golang.org/x/net", "v0.0.0", "v0.21.0", "golang.org/x/net/html", []string{"Render"}, "CVE-2025-40000"),
		"Cross-site scripting in Render in golang.org/x/net/html")
	w.EPSS["CVE-2025-40000"] = [2]float64{0.02, 0.4}
	// Standard library (go1.22.0 and the local toolchain are affected).
	vuln(testenv.SimpleVuln("GO-2025-0201", "stdlib", "v1.0.0", "v1.22.5", "net/http", []string{"Server.Serve"}, "CVE-2025-22871"),
		"Request smuggling in net/http")
	vuln(testenv.SimpleVuln("GO-2025-0202", "toolchain", "v1.0.0", "v1.22.5", "cmd/go", nil, "CVE-2025-22872"),
		"Arbitrary code execution during build in cmd/go")

	// --- deprecated module ---
	add("github.com/old/deprecated", "v1.0.0", map[string]string{"d.go": "package deprecated\n\nfunc D() {}\n"})
	add("github.com/old/deprecated", "v1.1.0", map[string]string{
		"go.mod": "// Deprecated: use github.com/new/thing instead.\nmodule github.com/old/deprecated\n\ngo 1.21\n",
		"d.go":   "package deprecated\n\nfunc D() {}\n",
	})
	w.GitHubRepo("old", "deprecated", map[string]any{"archived": true})

	// --- +incompatible module and its /v8 ---
	redisSrc := "package redis\n\n// Client is a client.\ntype Client struct{}\n\n// NewClient returns a client.\nfunc NewClient() *Client { return &Client{} }\n\n// Get gets a key.\nfunc (c *Client) Get(k string) string { return k }\n"
	add("github.com/go-redis/redis", "v6.15.9+incompatible", map[string]string{"go.mod": "", "redis.go": redisSrc})
	add("github.com/go-redis/redis/v7", "v7.4.1", map[string]string{"redis.go": redisSrc})
	add("github.com/go-redis/redis/v8", "v8.11.5", map[string]string{"redis.go": redisSrc})
	w.GitHubRepo("go-redis", "redis", nil)

	// --- go-github v60 and v62 ---
	ghSrc := "package github\n\n// Client is a GitHub client.\ntype Client struct{}\n\n// NewClient returns a client.\nfunc NewClient() *Client { return &Client{} }\n"
	add("github.com/google/go-github/v60", "v60.0.0", map[string]string{"github/github.go": ghSrc})
	add("github.com/google/go-github/v62", "v62.0.0", map[string]string{"github/github.go": ghSrc})
	w.GitHubRepo("google", "go-github", nil)

	// --- example.com/foo -> /v3 (migrate) ---
	add("example.com/foo", "v1.2.0", map[string]string{"foo.go": "package foo\n\n// Hello greets.\nfunc Hello() string { return \"hi\" }\n"})
	add("example.com/foo/v2", "v2.0.0", map[string]string{"foo.go": "package foo\n\nfunc Hello() string { return \"hi\" }\n"})
	add("example.com/foo/v3", "v3.0.0", map[string]string{"foo.go": "package foo\n\nfunc Hello() string { return \"hi\" }\n"})
	add("example.com/foo/v3", "v3.1.0", map[string]string{"foo.go": "package foo\n\nfunc Hello() string { return \"hi\" }\n\nfunc Bye() string { return \"bye\" }\n"})

	// --- example.com/m and /v2 side by side (majors, apidiff) ---
	add("example.com/m", "v1.9.0", map[string]string{"m.go": "package m\n\n// Do does it.\nfunc Do() error { return nil }\n\n// Name is a name.\nconst Name = \"m\"\n"})
	add("example.com/m/v2", "v2.0.0", map[string]string{"m.go": "package m\n\nimport \"context\"\n\n// Do does it.\nfunc Do(ctx context.Context) error { return ctx.Err() }\n"})

	// --- example.com/lib (upgrade) ---
	add("example.com/lib", "v1.0.0", map[string]string{"lib.go": "package lib\n\nfunc Old() int { return 1 }\n"})
	add("example.com/lib", "v1.1.0", map[string]string{"lib.go": "package lib\n\nfunc Old() int { return 1 }\n\nfunc New() int { return 2 }\n"})

	// --- go-cmp (apidiff with no project) ---
	add("github.com/google/go-cmp", "v0.5.9", map[string]string{"cmp/cmp.go": "package cmp\n\n// Option configures Equal.\ntype Option interface{ apply() }\n\n// Equal reports equality.\nfunc Equal(x, y any, opts ...Option) bool { return x == y }\n\n// Diff diffs.\nfunc Diff(x, y any) string { return \"\" }\n"})
	add("github.com/google/go-cmp", "v0.6.0", map[string]string{"cmp/cmp.go": "package cmp\n\ntype Option interface{ apply() }\n\nfunc Equal(x, y any, opts ...Option) bool { return x == y }\n\n// Diff diffs.\nfunc Diff(x, y any, opts ...Option) string { return \"\" }\n\n// Exporter is new.\nfunc Exporter(f func(any) bool) Option { return nil }\n"})
	w.GitHubRepo("google", "go-cmp", nil)

	// --- vanity module with a renamed repository and an expiring domain ---
	add("go.example.org/tool", "v0.3.0", map[string]string{"tool.go": "package tool\n\n// Run runs the tool.\nfunc Run() {}\n"})
	w.Vanity["go.example.org/tool"] = vanityPage("go.example.org/tool", "git", "https://github.com/example-org/tool")
	w.GitHubRepo("example-org", "tool-v2", nil)
	w.GitHubRedirect["repos/example-org/tool"] = "repos/example-org/tool-v2"
	rdap(w, "example.org", now.Add(20*24*time.Hour))
	add("go.uber.org/zap", "v1.27.0", map[string]string{"zap.go": "package zap\n\nfunc L() {}\n"})
	w.Vanity["go.uber.org/zap"] = vanityPage("go.uber.org/zap", "git", "https://github.com/uber-go/zap")
	w.GitHubRepo("uber-go", "zap", nil)
	rdap(w, "uber.org", now.Add(400*24*time.Hour))
	for _, x := range []string{"net", "text", "sys"} {
		w.Vanity["golang.org/x/"+x] = vanityPage("golang.org/x/"+x, "git", "https://go.googlesource.com/"+x)
		w.GitHubRepo("golang", x, map[string]any{"license": map[string]any{"spdx_id": "BSD-3-Clause"}})
	}
	rdap(w, "golang.org", now.Add(3*365*24*time.Hour))
	// Repository roots of the go.googlesource.com repositories (git smart
	// HTTP, probed by sm-go vanity).
	// golang.org serves the same go-import tag for every package path.
	for _, pkg := range []string{"net/html", "text/language", "sys/unix"} {
		x, _, _ := strings.Cut(pkg, "/")
		w.Vanity["golang.org/x/"+pkg] = vanityPage("golang.org/x/"+x, "git", "https://go.googlesource.com/"+x)
	}
	for _, x := range []string{"net", "text", "sys"} {
		w.Vanity["go.googlesource.com/"+x+"/info/refs"] = "001e# service=git-upload-pack\n0000"
	}
	// The example.com modules are served from GitHub through go-import
	// pages, like any custom-domain module.
	for _, m := range [][2]string{{"example.com/csqlite", "csqlite"}, {"example.com/foo", "foo"}, {"example.com/foo/v2", "foo"},
		{"example.com/foo/v3", "foo"}, {"example.com/lib", "lib"}, {"example.com/m", "m"}, {"example.com/m/v2", "m"},
		{"example.com/patched", "patched"}, {"example.com/localx", "localx"}} {
		root := "example.com/" + m[1]
		w.Vanity[m[0]] = vanityPage(root, "git", "https://github.com/example/"+m[1])
		w.GitHubRepo("example", m[1], map[string]any{"pushed_at": now.Add(-time.Duration(len(m[1])*9) * 24 * time.Hour).UTC().Format(time.RFC3339), "stargazers_count": 40 * len(m[1])})
	}
	rdap(w, "example.com", now.Add(2*365*24*time.Hour))

	// --- replace targets ---
	add("example.com/patched", "v1.0.0", map[string]string{"p.go": "package patched\n\nfunc P() {}\n"})
	add("github.com/me/patched-fork", "v1.0.1", map[string]string{
		"go.mod": "module example.com/patched\n\ngo 1.21\n",
		"p.go":   "package patched\n\nfunc P() {}\n",
	})
	w.GitHubRepo("me", "patched-fork", map[string]any{"fork": true, "pushed_at": "2022-01-01T00:00:00Z"})

	// --- never imported requirement ---
	add("github.com/stale/unused", "v1.0.0", map[string]string{"u.go": "package unused\n"})
	w.GitHubRepo("stale", "unused", nil)

	// --- cgo with a pure-Go fallback ---
	add("example.com/csqlite", "v1.0.0", map[string]string{
		"cgo.go":   "//go:build cgo\n\npackage csqlite\n\n// #include <stdlib.h>\nimport \"C\"\n\nfunc Open() bool { return true }\n",
		"nocgo.go": "//go:build !cgo\n\npackage csqlite\n\nfunc Open() bool { return false }\n",
	})

	// Tags of the GitHub-hosted versions, and the Origin the proxy
	// recorded for them (acme/lib's v1.4.0 was moved, above). Commit
	// hashes are derived from the version.
	for _, mv := range [][3]string{{"github.com/spf13/cobra", "v1.7.0", "spf13/cobra"}, {"github.com/spf13/cobra", "v1.8.0", "spf13/cobra"},
		{"github.com/spf13/pflag", "v1.0.5", "spf13/pflag"}, {"github.com/spf13/pflag", "v1.0.6", "spf13/pflag"},
		{"github.com/go-redis/redis", "v6.15.9+incompatible", "go-redis/redis"}, {"github.com/go-redis/redis/v7", "v7.4.1", "go-redis/redis"},
		{"github.com/go-redis/redis/v8", "v8.11.5", "go-redis/redis"},
		{"github.com/google/go-github/v60", "v60.0.0", "google/go-github"}, {"github.com/google/go-github/v62", "v62.0.0", "google/go-github"},
		{"github.com/google/go-cmp", "v0.5.9", "google/go-cmp"}, {"github.com/google/go-cmp", "v0.6.0", "google/go-cmp"},
		{"github.com/old/deprecated", "v1.0.0", "old/deprecated"}, {"github.com/old/deprecated", "v1.1.0", "old/deprecated"},
		{"github.com/me/patched-fork", "v1.0.1", "me/patched-fork"}, {"github.com/stale/unused", "v1.0.0", "stale/unused"}} {
		tag := strings.TrimSuffix(mv[1], "+incompatible")
		hash := fmt.Sprintf("%x", sha1.Sum([]byte(mv[0]+"@"+mv[1])))
		owner, name, _ := strings.Cut(mv[2], "/")
		w.GitHubTag(owner, name, tag, hash)
		m := w.Module(mv[0], mv[1])
		if m == nil {
			t.Fatalf("tag for unpublished %s@%s", mv[0], mv[1])
		}
		m.Origin = origin(mv[2], tag, hash)
	}
	for repo, fields := range map[string]map[string]any{
		"spf13/cobra":         {"stargazers_count": 37000, "open_issues_count": 280, "pushed_at": now.Add(-4 * day).UTC().Format(time.RFC3339)},
		"spf13/pflag":         {"stargazers_count": 2400, "open_issues_count": 160, "pushed_at": now.Add(-50 * day).UTC().Format(time.RFC3339)},
		"go-redis/redis":      {"stargazers_count": 20000, "open_issues_count": 210, "pushed_at": now.Add(-2 * day).UTC().Format(time.RFC3339)},
		"google/go-github":    {"stargazers_count": 10000, "open_issues_count": 60, "pushed_at": now.Add(-1 * day).UTC().Format(time.RFC3339), "license": map[string]any{"spdx_id": "BSD-3-Clause"}},
		"google/go-cmp":       {"stargazers_count": 4100, "open_issues_count": 30, "pushed_at": now.Add(-90 * day).UTC().Format(time.RFC3339), "license": map[string]any{"spdx_id": "BSD-3-Clause"}},
		"uber-go/zap":         {"stargazers_count": 21000, "open_issues_count": 150, "pushed_at": now.Add(-6 * day).UTC().Format(time.RFC3339)},
		"acme/lib":            {"stargazers_count": 850, "open_issues_count": 12, "pushed_at": now.Add(-30 * day).UTC().Format(time.RFC3339)},
		"stale/unused":        {"stargazers_count": 15, "open_issues_count": 4, "pushed_at": now.Add(-900 * day).UTC().Format(time.RFC3339)},
		"example-org/tool-v2": {"stargazers_count": 300, "pushed_at": now.Add(-120 * day).UTC().Format(time.RFC3339)},
	} {
		owner, name, _ := strings.Cut(repo, "/")
		w.GitHubRepo(owner, name, fields)
		w.GitHub["repos/"+repo+"/contributors?per_page=100"] = []map[string]any{{"login": owner + "-dev", "contributions": 300}, {"login": "a", "contributions": 120}, {"login": "b", "contributions": 60}, {"login": "c", "contributions": 20}, {"login": "d", "contributions": 8}}
	}
	// golang.org/x: deps.dev links them to their GitHub mirrors.
	for _, mv := range [][2]string{{"net", "v0.20.0"}, {"net", "v0.21.0"}, {"text", "v0.14.0"}, {"text", "v0.21.0"}, {"sys", "v0.15.0"}} {
		w.DepsDev["v3/systems/go/packages/golang.org/x/"+mv[0]+"/versions/"+mv[1]] = map[string]any{
			"versionKey": map[string]any{"name": "golang.org/x/" + mv[0], "version": mv[1]}, "licenses": []string{"BSD-3-Clause"},
			"relatedProjects": []map[string]any{{"projectKey": map[string]any{"id": "github.com/golang/" + mv[0]}, "relationProvenance": "GO_ORIGIN", "relationType": "SOURCE_REPO"}}}
		w.DepsDev["v3alpha/systems/go/packages/golang.org/x/"+mv[0]+"/versions/"+mv[1]+":dependents"] = map[string]any{"dependentCount": 40000, "directDependentCount": 9000}
		w.DepsDev["v3/projects/github.com/golang/"+mv[0]] = map[string]any{"scorecard": map[string]any{"date": "2026-10-20", "overallScore": 8.2}}
	}
	for _, p := range []string{"spf13/cobra", "go-redis/redis", "google/go-github", "uber-go/zap"} {
		w.DepsDev["v3/projects/github.com/"+p] = map[string]any{"scorecard": map[string]any{"date": "2026-10-18", "overallScore": 7.4}}
	}
	w.DepsDev["v3alpha/systems/go/packages/github.com/spf13/cobra/versions/v1.7.0:dependents"] = map[string]any{"dependentCount": 18000, "directDependentCount": 12000}

	// deps.dev licenses for a couple of modules.
	w.DepsDev["v3/systems/go/packages/github.com/sirupsen/logrus/versions/v1.9.3"] = map[string]any{"licenses": []string{"MIT"}}

	// Module index (radar).
	w.AddIndex("github.com/spf13/cobra", "v1.8.0", now.Add(-10*24*time.Hour))
	w.AddIndex("golang.org/x/text", "v0.21.0", now.Add(-3*24*time.Hour))
	w.AddIndex("golang.org/x/net", "v0.21.0", now.Add(-2*24*time.Hour))
	w.AddIndex("github.com/sirupsen/logrus", "v1.9.4", now.Add(-5*time.Hour))
	add("github.com/myorg/thing", "v0.1.0", map[string]string{"thing.go": "package thing\n\n// Thing is a thing.\ntype Thing struct{}\n"}).Origin = origin("myorg/thing", "v0.1.0", sha('9'))
	w.GitHubTag("myorg", "thing", "v0.1.0", sha('9'))
	w.GitHubRepo("myorg", "thing", map[string]any{"pushed_at": now.Add(-time.Hour).UTC().Format(time.RFC3339)})
	w.AddIndex("github.com/myorg/thing", "v0.1.0", now.Add(-1*time.Hour))
	w.AddIndex("github.com/unrelated/x", "v1.0.0", now.Add(-30*time.Minute))

	// go.dev release list.
	for _, v := range []string{"go1.25.3", "go1.25.2", "go1.24.9", "go1.24.8", "go1.24.7"} {
		w.GoReleases = append(w.GoReleases, map[string]any{"version": v, "stable": true})
	}

	// Release dates: the proxy .info times of a living ecosystem, relative
	// to now (health, radar, upgrade and replace print them).
	for mv, age := range map[string]time.Duration{
		"golang.org/x/sys@v0.15.0": 40 * day, "golang.org/x/text@v0.3.7": 1500 * day, "golang.org/x/text@v0.14.0": 200 * day,
		"golang.org/x/text@v0.15.0": 120 * day, "golang.org/x/text@v0.21.0": 3 * day,
		"golang.org/x/net@v0.20.0": 150 * day, "golang.org/x/net@v0.21.0": 2 * day,
		"github.com/sirupsen/logrus@v1.9.3": 900 * day, "github.com/sirupsen/logrus@v1.9.4": 5 * time.Hour,
		"github.com/spf13/pflag@v1.0.5": 1800 * day, "github.com/spf13/pflag@v1.0.6": 60 * day,
		"github.com/spf13/cobra@v1.7.0": 400 * day, "github.com/spf13/cobra@v1.8.0": 10 * day,
		"github.com/acme/lib@v1.3.0": 300 * day, "github.com/acme/lib@v1.4.0": 120 * day, "github.com/acme/lib@v1.4.1": 90 * day,
		"github.com/old/deprecated@v1.0.0": 1500 * day, "github.com/old/deprecated@v1.1.0": 700 * day,
		"github.com/go-redis/redis@v6.15.9+incompatible": 1900 * day, "github.com/go-redis/redis/v7@v7.4.1": 1300 * day,
		"github.com/go-redis/redis/v8@v8.11.5":    900 * day,
		"github.com/google/go-github/v60@v60.0.0": 300 * day, "github.com/google/go-github/v62@v62.0.0": 150 * day,
		"example.com/foo@v1.2.0": 500 * day, "example.com/foo/v2@v2.0.0": 400 * day, "example.com/foo/v3@v3.0.0": 200 * day,
		"example.com/foo/v3@v3.1.0": 30 * day, "example.com/m@v1.9.0": 365 * day, "example.com/m/v2@v2.0.0": 200 * day,
		"example.com/lib@v1.0.0": 250 * day, "example.com/lib@v1.1.0": 45 * day,
		"github.com/google/go-cmp@v0.5.9": 1400 * day, "github.com/google/go-cmp@v0.6.0": 1000 * day,
		"go.example.org/tool@v0.3.0": 600 * day, "go.uber.org/zap@v1.27.0": 250 * day,
		"example.com/patched@v1.0.0": 700 * day, "github.com/me/patched-fork@v1.0.1": 600 * day,
		"github.com/stale/unused@v1.0.0": 1000 * day, "example.com/csqlite@v1.0.0": 365 * day,
		"github.com/myorg/thing@v0.1.0": time.Hour,
	} {
		path, version, _ := strings.Cut(mv, "@")
		m := w.Module(path, version)
		if m == nil {
			t.Fatalf("release date for unpublished %s", mv)
		}
		m.Time = now.Add(-age).UTC().Truncate(time.Second)
	}

	f := &fixtures{w: w}
	f.app = buildApp(t, w)
	f.vendored = copyTree(t, f.app, filepath.Join(t.TempDir(), "vendored"))
	mustGo(t, w, f.vendored, nil, "mod", "vendor")
	buildBinaries(t, w, f.app)
	f.lib = buildLib(t, w)
	f.ws = buildWorkspace(t, w)
	return f
}

func vanityPage(prefix, vcs, repo string) string {
	return `<!DOCTYPE html><html><head><meta name="go-import" content="` + prefix + ` ` + vcs + ` ` + repo + `"></head><body>go get ` + prefix + `</body></html>`
}

func rdap(w *testenv.World, domain string, exp time.Time) {
	w.RDAP["domain/"+domain] = map[string]any{
		"ldhName": strings.ToUpper(domain), "status": []string{"active"},
		"events": []map[string]any{
			{"eventAction": "registration", "eventDate": "2005-03-01T00:00:00Z"},
			{"eventAction": "expiration", "eventDate": exp.UTC().Format(time.RFC3339)},
		},
	}
}

const appGoMod = `module example.com/app

go 1.22

require (
	example.com/csqlite v1.0.0
	example.com/foo v1.2.0
	example.com/lib v1.0.0
	example.com/localx v0.0.0
	example.com/m v1.9.0
	example.com/m/v2 v2.0.0
	example.com/patched v1.0.0
	github.com/acme/lib v1.4.0
	github.com/go-redis/redis v6.15.9+incompatible
	github.com/google/go-github/v60 v60.0.0
	github.com/old/deprecated v1.0.0
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.7.0
	go.example.org/tool v0.3.0
	golang.org/x/net v0.20.0
)

replace example.com/patched => github.com/me/patched-fork v1.0.1

replace example.com/localx => ./third_party/localx
`

const appGo = `// Package app wires the application together.
package app

import (
	"fmt"

	"example.com/foo"
	"example.com/lib"
	"example.com/localx"
	"example.com/m"
	mv2 "example.com/m/v2"
	"example.com/patched"
	"github.com/old/deprecated"
	"github.com/google/go-github/v60/github"
	"go.example.org/tool"
	"golang.org/x/text/language"
)

// Start starts the app.
func Start() error {
	deprecated.D()
	patched.P()
	localx.X()
	tool.Run()
	_ = github.NewClient()
	tag, _ := language.Parse("en")
	fmt.Println(foo.Hello(), lib.Old(), tag, m.Name)
	if err := m.Do(); err != nil {
		return err
	}
	return mv2.Do(nil)
}
`

const serverGo = `// Command server is the application server.
package main

import (
	"fmt"
	"net/http"
	"os"

	"example.com/app"
	"example.com/csqlite"
	acme "github.com/acme/lib"
	"github.com/go-redis/redis"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/net/html"
)

func main() {
	if addr := os.Getenv("HEALTH_ADDR"); addr != "" {
		go http.ListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") }))
	}
	n, err := acme.Parse(os.Args[0])
	logrus.Info("parsed", n, err)
	doc, _ := html.Parse("<p>")
	fmt.Println(doc, csqlite.Open(), redis.NewClient().Get("k"))
	cmd := &cobra.Command{Use: "server"}
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
	if err := app.Start(); err != nil {
		os.Exit(1)
	}
}
`

const policyJSON = `{
  "vulnerabilities": {"maxSeverity": "high", "forbidKEV": true, "includeStdlib": false},
  "licenses": {"deny": ["GPL-*", "AGPL-*"]},
  "forbidRetracted": true,
  "forbidDeprecated": false,
  "bannedModules": [{"module": "github.com/go-redis/redis", "reason": "use github.com/go-redis/redis/v8"}],
  "forbidLocalReplaces": false,
  "requireGoSumComplete": true,
  "maxGoAge": "2y"
}
`

// dotPolicy is the project's default gate policy (.sm-go.json), read by a
// bare 'sm-go gate'.
const dotPolicy = `{
  "vulnerabilities": {"maxSeverity": "medium", "forbidKEV": true},
  "licenses": {"allow": ["MIT", "Apache-2.0", "BSD-*", "ISC"], "failCopyleft": true},
  "forbidRetracted": true,
  "forbidDeprecated": true,
  "forbidLocalReplaces": false,
  "requireGoSumComplete": true,
  "maxGoAge": "3y"
}
`

func buildApp(t *testing.T, w *testenv.World) string {
	dir := w.Project(map[string]string{
		"go.mod":                       appGoMod,
		"app.go":                       appGo,
		"cmd/server/main.go":           serverGo,
		"third_party/localx/go.mod":    "module example.com/localx\n\ngo 1.21\n",
		"third_party/localx/localx.go": "package localx\n\nfunc X() {}\n",
		"third_party/localx/LICENSE":   mitLicense,
		"LICENSE":                      mitLicense,
		"ci/policy.json":               policyJSON,
		".sm-go.json":                  dotPolicy,
		// A nested module (toolchain -C ./service).
		"service/go.mod":  "module example.com/app/service\n\ngo 1.23\n\ntoolchain go1.23.4\n",
		"service/main.go": "package main\n\nfunc main() {}\n",
	})
	mustGo(t, w, dir, nil, "mod", "tidy")
	// Someone `go get` a module that is never imported.
	mustGo(t, w, dir, nil, "get", "github.com/stale/unused@v1.0.0")
	return dir
}

// buildBinaries compiles the binaries the binscan / bloat / sbom examples
// name. old/server is the same program built against github.com/acme/lib
// v1.3.0 without stripping, new/server the current one.
func buildBinaries(t *testing.T, w *testenv.World, dir string) {
	mustGo(t, w, dir, nil, "build", "-o", "bin/server", "./cmd/server")
	mustGo(t, w, dir, nil, "build", "-o", "app", "./cmd/server")
	mustGo(t, w, dir, nil, "build", "-o", "new/server", "./cmd/server")
	mustGo(t, w, dir, []string{"GOOS=windows", "GOARCH=amd64"}, "build", "-o", "app.exe", "./cmd/server")
	mustGo(t, w, dir, nil, "build", "-trimpath", "-o", "dist/server-linux-amd64", "./cmd/server")
	mustGo(t, w, dir, []string{"GOOS=darwin", "GOARCH=arm64"}, "build", "-o", "dist/server-darwin-arm64", "./cmd/server")
	// The old build: an older acme/lib, in a scratch copy.
	old := copyTree(t, dir, filepath.Join(t.TempDir(), "old"))
	mustGo(t, w, old, nil, "get", "github.com/acme/lib@v1.3.0")
	out, err := filepath.Abs(filepath.Join(dir, "old", "server"))
	if err != nil {
		t.Fatal(err)
	}
	mustGo(t, w, old, nil, "build", "-o", out, "./cmd/server")
}

const libNext = "\n// Tokens splits s into tokens. (unreleased)\nfunc Tokens(s string) []string { return []string{s} }\n"

func buildLib(t *testing.T, w *testenv.World) string {
	m := w.Module("github.com/acme/lib", "v1.4.1")
	files := map[string]string{}
	for k, v := range m.Files {
		files[k] = v
	}
	files["lib.go"] += libNext
	dir := w.Project(files)
	if _, err := exec.LookPath("git"); err == nil {
		git := func(args ...string) {
			cmd := exec.Command("git", append([]string{"-c", "user.email=dev@example.com", "-c", "user.name=dev", "-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false"}, args...)...)
			cmd.Dir = dir
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v\n%s", args, err, out)
			}
		}
		git("init", "-q")
		git("add", ".")
		git("commit", "-q", "-m", "add Tokens")
		git("tag", "v1.4.1")
	}
	return dir
}

func buildWorkspace(t *testing.T, w *testenv.World) string {
	dir := w.Project(map[string]string{
		"go.work":        "go 1.22\n\nuse (\n\t./api\n\t./worker\n)\n",
		"api/go.mod":     testenv.GoModFile("example.com/ws/api", "1.22", "golang.org/x/text@v0.14.0"),
		"api/api.go":     "package api\n\nimport \"golang.org/x/text/language\"\n\nvar T, _ = language.Parse(\"en\")\n",
		"worker/go.mod":  testenv.GoModFile("example.com/ws/worker", "1.22", "golang.org/x/text@v0.15.0", "example.com/ws/api@v0.0.0"),
		"worker/main.go": "package main\n\nimport (\n\t\"fmt\"\n\n\t\"example.com/ws/api\"\n\t\"golang.org/x/text/language\"\n)\n\nfunc main() { fmt.Println(api.T, language.MustParse(\"de\")) }\n",
		// Not listed in go.work.
		"tools/go.mod": "module example.com/ws/tools\n\ngo 1.22\n",
		"tools/t.go":   "package tools\n",
	})
	testenv.WriteFiles(t, dir, map[string]string{"worker/go.mod": testenv.GoModFile("example.com/ws/worker", "1.22", "golang.org/x/text@v0.15.0", "example.com/ws/api@v0.0.0") + "\nreplace example.com/ws/api => ../api\n"})
	mustGo(t, w, filepath.Join(dir, "api"), nil, "mod", "tidy")
	mustGo(t, w, filepath.Join(dir, "worker"), nil, "mod", "tidy")
	mustGo(t, w, dir, []string{"GOWORK="}, "work", "sync")
	return dir
}

// copyTree copies src to dst. Large files (binaries) are hard-linked.
func copyTree(t *testing.T, src, dst string) string {
	t.Helper()
	err := filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		switch {
		case fi.IsDir():
			return os.MkdirAll(target, 0o755)
		case fi.Mode()&os.ModeSymlink != 0:
			l, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(l, target)
		case fi.Size() > 256<<10:
			if os.Link(p, target) == nil {
				return nil
			}
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, fi.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func readFile(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

var _ = fmt.Sprintf
