package compliance

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/httpx"
	"github.com/slash-mark-dev/go-suite/internal/report"
)

// EnvSetting is one audited variable (secrets redacted).
type EnvSetting struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Source string `json:"source"` // environment, go env, default
}

// NetrcMachine is one .netrc entry (no secrets).
type NetrcMachine struct {
	Host        string `json:"host"`
	Login       string `json:"login,omitempty"` // redacted
	HasPassword bool   `json:"hasPassword"`
}

// NetrcInfo describes the .netrc file.
type NetrcInfo struct {
	Path     string         `json:"path"`
	Mode     string         `json:"mode,omitempty"`
	Machines []NetrcMachine `json:"machines"`
}

// GitRewrite is a git url.<base>.insteadOf rule.
type GitRewrite struct {
	File string `json:"file"`
	Line int    `json:"line"`
	From string `json:"from"` // the prefix being rewritten
	To   string `json:"to"`   // the replacement base (redacted)
}

// EnvResult is the result of the env tool.
type EnvResult struct {
	Settings    []EnvSetting     `json:"settings"`
	Netrc       *NetrcInfo       `json:"netrc,omitempty"`
	GitRewrites []GitRewrite     `json:"gitRewrites"`
	GitConfigs  []string         `json:"gitConfigs"`
	Findings    []report.Finding `json:"findings"`
	Summary     map[string]int   `json:"summary"`
	Failing     int              `json:"failing"`
}

var envFlags struct {
	failOn func() (report.Severity, error)
}

var auditedVars = []string{"GOPROXY", "GOSUMDB", "GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GONOSUMCHECK", "GOINSECURE",
	"GOFLAGS", "GOTOOLCHAIN", "GOVCS", "GOAUTH", "GOENV", "NETRC"}

func init() {
	cli.Register(&cli.Tool{
		Name:    "env",
		Group:   group,
		Summary: "Audit GOPROXY, GOSUMDB, private patterns, .netrc and git rewrites",
		Usage:   "sm-go env [flags]",
		Help: `Audits the Go and git configuration that decides where module code comes from and whether it
is verified. Values come from 'go env' (so go.env files and 'go env -w' settings count) and the
process environment. Checks:

  GOPROXY       off/direct, plain-HTTP proxies, credentials embedded in proxy URLs, "|" fallback
  GOSUMDB       verification disabled (off) or a non-default checksum database
  GOPRIVATE, GONOPROXY, GONOSUMDB, GOINSECURE
                patterns so broad they cover public code ("*", "*.com", "github.com"), which turns
                off checksum verification or HTTPS for everything they match
  GONOSUMCHECK  obsolete variable that is silently ignored
  GOFLAGS       -insecure, -mod=mod (lets builds rewrite go.mod/go.sum), -modcacherw
  GOTOOLCHAIN   automatic toolchain downloads (and unverified ones when GOSUMDB=off)
  GOVCS         allowing every VCS for public modules
  .netrc        plaintext credentials, file permissions, "default" entries sent to every host
  git config    url.<base>.insteadOf rewrites to other hosts, unencrypted transports or URLs with
                embedded tokens; credential.helper=store

Secrets are never printed: passwords and tokens are replaced by *** and logins are shortened.
Findings at or above --fail-on (default medium) exit with code 1.`,
		Examples: []string{"sm-go env", "sm-go env --fail-on high", "sm-go env --json"},
		Sources:  []string{"go env", ".netrc", "git config"},
		Flags: func(fs *flag.FlagSet) {
			envFlags.failOn = cli.SeverityFlag(fs, "fail-on", "medium", "minimum `severity` that fails the run")
		},
		Run: runEnv,
	})
}

func runEnv(c *cli.Context) error {
	failOn, err := envFlags.failOn()
	if err != nil {
		return err
	}
	if len(c.Args) > 0 {
		return cli.Usagef("env takes no arguments")
	}
	a := &envAudit{c: c, res: &EnvResult{GitRewrites: []GitRewrite{}, GitConfigs: []string{}, Findings: []report.Finding{}}}
	for _, k := range auditedVars {
		a.res.Settings = append(a.res.Settings, EnvSetting{Name: k, Value: redactValue(a.get(k)), Source: a.source(k)})
	}
	a.goproxy()
	a.gosumdb()
	a.patterns()
	a.goflags()
	a.toolchain()
	a.govcs()
	a.netrc()
	a.gitConfig()
	report.SortFindings(a.res.Findings)
	a.res.Summary = sevCounts(a.res.Findings)
	a.res.Failing = len(report.AtLeast(a.res.Findings, failOn))
	c.SetResult(a.res)
	if a.res.Failing > 0 {
		c.Issues()
	}
	if c.Text() {
		printEnv(c, a.res, failOn)
	}
	return nil
}

type envAudit struct {
	c   *cli.Context
	res *EnvResult
}

func (a *envAudit) get(k string) string {
	switch k {
	case "GONOSUMCHECK", "NETRC":
		return a.c.Env.Getenv(k)
	}
	return a.c.Env.Get(k)
}

func (a *envAudit) source(k string) string {
	if since, ok := a.c.Env.Unsupported(k); ok {
		if v, set := a.c.Env.Lookup(k); set && v != "" {
			return "environment, ignored: needs Go " + since + " or later"
		}
		return "not supported by this Go version"
	}
	if v, ok := a.c.Env.Lookup(k); ok && v != "" {
		return "environment"
	}
	if a.c.Env.FromGoEnv(k) && a.c.Env.Get(k) != "" {
		return "go env"
	}
	return "default"
}

func (a *envAudit) add(sev report.Severity, rule, title, detail, fix string) {
	a.res.Findings = append(a.res.Findings, report.Finding{Severity: sev, Rule: rule, Title: title, Detail: detail, Fix: fix})
}

func (a *envAudit) addAt(sev report.Severity, rule, file string, line int, title, detail, fix string) {
	a.res.Findings = append(a.res.Findings, report.Finding{Severity: sev, Rule: rule, File: file, Line: line, Title: title, Detail: detail, Fix: fix})
}

// redactValue redacts every URL in a GOPROXY-like list.
func redactValue(v string) string {
	if !strings.Contains(v, "://") && !strings.Contains(v, "@") {
		return v
	}
	var b strings.Builder
	start := 0
	for i := 0; i <= len(v); i++ {
		if i == len(v) || v[i] == ',' || v[i] == '|' || v[i] == ' ' {
			seg := v[start:i]
			// The go command turns "user@host" into https://user@host, so
			// anything before the "@" of a bare entry is userinfo.
			if at := strings.LastIndex(seg, "@"); at > 0 && !strings.Contains(seg, "://") && !strings.Contains(seg[:at], "/") {
				seg = "***" + seg[at:]
			}
			b.WriteString(redactURL(seg))
			if i < len(v) {
				b.WriteByte(v[i])
			}
			start = i + 1
		}
	}
	return b.String()
}

// redactURL removes userinfo and token-like parameters; strings that are
// not URLs but contain "user:secret@" are redacted too.
func redactURL(s string) string {
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			if u.User != nil {
				u.User = url.User("***")
			}
			r := httpx.Redact(u.String())
			return strings.Replace(r, "%2A%2A%2A@", "***@", 1)
		}
	}
	if at := strings.LastIndex(s, "@"); at > 0 && strings.Contains(s[:at], ":") {
		return "***" + s[at:]
	}
	return s
}

func isLoopback(host string) bool {
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func (a *envAudit) goproxy() {
	v := a.get("GOPROXY")
	if strings.TrimSpace(v) == "" {
		return
	}
	entries := splitProxyList(v)
	if len(entries) > 0 && entries[0].url == "off" {
		a.add(report.Info, "goproxy-off", "GOPROXY=off: module downloads are disabled",
			"only modules already in the module cache can be used", "")
		return
	}
	if len(entries) > 0 && entries[0].url == "direct" {
		a.add(report.Medium, "goproxy-direct", "GOPROXY starts with direct: modules are fetched straight from version control",
			"no immutable proxy copy: a force-pushed or deleted tag changes or breaks builds, every fetch runs a VCS client, and module paths are revealed to every code host",
			"use GOPROXY=https://proxy.golang.org,direct (with GOPRIVATE for private modules)")
	}
	for i, e := range entries {
		if e.url == "direct" || e.url == "off" {
			continue
		}
		u, err := url.Parse(e.url)
		if err == nil && u.Scheme == "file" && *u != (url.URL{Scheme: u.Scheme, Path: u.Path, RawPath: u.RawPath}) {
			err = fmt.Errorf("file:// URL with non-path elements")
		}
		if err == nil && u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "file" {
			err = fmt.Errorf("scheme must be https, http or file")
		}
		if err != nil {
			a.add(report.Medium, "goproxy-invalid", "GOPROXY entry "+redactURL(e.url)+" is not a valid proxy URL",
				"the go command rejects the whole GOPROXY list, so every module download fails", "use https://host[/path], http://host or file:///path")
			continue
		}
		if u.Scheme == "file" {
			continue // a local directory
		}
		red := redactURL(e.url)
		if u.User != nil {
			if _, hasPw := u.User.Password(); hasPw || u.User.Username() != "" {
				a.add(report.High, "goproxy-credentials", "GOPROXY contains credentials ("+red+")",
					"credentials in GOPROXY end up in shell history, CI logs and 'go env' output",
					"move them to ~/.netrc (mode 600) or GOAUTH")
			}
		}
		if u.Scheme == "http" {
			if isLoopback(u.Host) {
				a.add(report.Low, "goproxy-http", "GOPROXY uses plain HTTP to a local proxy ("+red+")", "", "")
			} else {
				a.add(report.High, "goproxy-http", "GOPROXY uses plain HTTP ("+red+")",
					"module code can be tampered with in transit; only GOSUMDB verification stands in the way", "use https://")
			}
		}
		host := strings.ToLower(u.Hostname())
		if host != "proxy.golang.org" && host != "goproxy.io" && !isLoopback(u.Host) {
			a.add(report.Info, "goproxy-third-party", "GOPROXY uses "+u.Scheme+"://"+u.Host,
				"this proxy sees every module path you fetch and serves the code you build", "")
		}
		if e.pipe && i+1 < len(entries) && entries[i+1].url == "direct" {
			a.add(report.Low, "goproxy-pipe-fallback", "GOPROXY falls back to direct on any error after "+red,
				"with '|', a proxy outage or a blocked module silently switches to fetching from version control", "use ',' to fall back only on 404/410")
		}
	}
}

type proxyEntry struct {
	url  string
	pipe bool
}

// splitProxyList parses GOPROXY like the go command (modfetch.proxyList):
// entries after "direct" or "off" are never used (nor validated), and only
// entries that contain '.', ':' or '/' but no ":/" and are not absolute
// paths get an implicit "https://"; anything else must be a complete URL.
func splitProxyList(s string) []proxyEntry {
	var out []proxyEntry
	for s != "" {
		var e string
		pipe := false
		if i := strings.IndexAny(s, ",|"); i >= 0 {
			e, pipe, s = s[:i], s[i] == '|', s[i+1:]
		} else {
			e, s = s, ""
		}
		if e = strings.TrimSpace(e); e == "" {
			continue
		}
		if e == "direct" || e == "off" {
			out = append(out, proxyEntry{e, pipe})
			break
		}
		if strings.ContainsAny(e, ".:/") && !strings.Contains(e, ":/") && !filepath.IsAbs(e) && !path.IsAbs(e) {
			e = "https://" + e
		}
		out = append(out, proxyEntry{e, pipe})
	}
	return out
}

func (a *envAudit) gosumdb() {
	v := strings.TrimSpace(a.get("GOSUMDB"))
	switch {
	case v == "off":
		a.add(report.High, "gosumdb-off", "GOSUMDB=off: downloaded modules are not verified against the checksum database",
			"a compromised proxy or VCS host can serve different code for a version than everyone else gets",
			"unset GOSUMDB; list private modules in GOPRIVATE instead")
	case v == "" || v == "sum.golang.org" || v == "sum.golang.google.cn" || strings.HasPrefix(v, "sum.golang.org+") || strings.HasPrefix(v, "sum.golang.google.cn+"):
	default:
		f := strings.Fields(v)
		detail := "checksums are verified against " + f[0] + "; make sure its public key comes from a trusted source"
		sev := report.Medium
		if len(f) > 1 && strings.HasPrefix(f[1], "http://") && !isLoopbackURL(f[1]) {
			sev = report.High
			detail += "; it is contacted over plain HTTP"
		}
		a.add(sev, "gosumdb-custom", "GOSUMDB uses a non-default checksum database ("+f[0]+")", detail, "")
	}
}

func isLoopbackURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && isLoopback(u.Host)
}

// publicHosts are code hosts whose whole namespace is public.
var publicHosts = map[string]bool{"github.com": true, "gitlab.com": true, "bitbucket.org": true, "golang.org": true,
	"google.golang.org": true, "gopkg.in": true, "go.googlesource.com": true, "go.uber.org": true, "k8s.io": true,
	"sigs.k8s.io": true, "gitee.com": true, "codeberg.org": true, "git.sr.ht": true, "launchpad.net": true,
	"cloud.google.com": true, "go.opentelemetry.io": true, "honnef.co": true, "gocloud.dev": true, "go.etcd.io": true}

// patternBreadth classifies a GOPRIVATE-style glob: "all" (matches every
// module path), "tld" (a whole top-level domain), "host" (an entire
// public code host) or "". Like module.MatchPrefixPatterns in the go
// command, patterns are neither trimmed nor case-folded: " github.com" or
// "GitHub.com" match no module path.
func patternBreadth(p string) string {
	p = strings.TrimSuffix(p, "/")
	first, _, hasPath := strings.Cut(p, "/")
	if first == "" {
		return ""
	}
	if strings.Trim(first, "*?") == "" && strings.Contains(first, "*") || first == "*.*" {
		return "all"
	}
	if strings.HasPrefix(first, "*.") && first != "*." && !strings.ContainsAny(first[2:], ".*?[\\") {
		return "tld"
	}
	if !hasPath && publicHosts[first] {
		return "host"
	}
	if hasPath && publicHosts[first] {
		rest := strings.TrimPrefix(p, first+"/")
		if strings.Trim(rest, "*?/") == "" {
			return "host"
		}
	}
	return ""
}

func (a *envAudit) patterns() {
	type spec struct {
		name    string
		broad   report.Severity
		effect  string
		any     report.Severity
		anyText string
	}
	specs := []spec{
		{"GOPRIVATE", report.High, "skips the proxy and checksum verification for", report.None, ""},
		{"GONOSUMDB", report.High, "skips checksum verification for", report.None, ""},
		{"GONOPROXY", report.Medium, "fetches straight from version control (no proxy) for", report.None, ""},
		{"GOINSECURE", report.High, "allows plain HTTP and unverified TLS for", report.Medium,
			"GOINSECURE allows insecure HTTP fetches and skips checksum verification for its modules"},
	}
	explicit := func(k string) bool {
		v, ok := a.c.Env.Lookup(k)
		return ok && v != "" || a.c.Env.FromGoEnv(k) && a.get(k) != ""
	}
	for _, s := range specs {
		v := a.get(s.name)
		if v == "" {
			continue
		}
		// GONOPROXY/GONOSUMDB default to GOPRIVATE; report those once.
		if (s.name == "GONOPROXY" || s.name == "GONOSUMDB") && !explicit(s.name) {
			continue
		}
		if (s.name == "GONOPROXY" || s.name == "GONOSUMDB") && v == a.get("GOPRIVATE") {
			continue
		}
		if s.any > report.None {
			a.add(s.any, strings.ToLower(s.name)+"-set", s.name+"="+v, s.anyText, "remove it once the server supports HTTPS")
		}
		for _, p := range strings.Split(v, ",") {
			b := patternBreadth(p)
			if b == "" {
				continue
			}
			what := map[string]string{"all": "every module", "tld": "every module under " + strings.TrimPrefix(strings.TrimSpace(p), "*"),
				"host": "every module on " + strings.Split(strings.TrimSpace(p), "/")[0]}[b]
			a.add(s.broad, strings.ToLower(s.name)+"-broad", fmt.Sprintf("%s pattern %q is too broad", s.name, strings.TrimSpace(p)),
				fmt.Sprintf("%s %s %s", s.name, s.effect, what),
				"list only your private module prefixes, e.g. github.com/your-org/*")
		}
	}
	if v := a.get("GONOSUMCHECK"); v != "" {
		a.add(report.Low, "gonosumcheck-obsolete", "GONOSUMCHECK="+v+" is obsolete and ignored by the go command",
			"it was renamed GONOSUMDB before Go 1.13; the setting has no effect", "use GONOSUMDB (or GOPRIVATE)")
		for _, p := range strings.Split(v, ",") {
			if patternBreadth(p) != "" {
				a.add(report.Medium, "gonosumcheck-broad", fmt.Sprintf("GONOSUMCHECK pattern %q is too broad", strings.TrimSpace(p)),
					"renaming it to GONOSUMDB would disable checksum verification for public modules", "")
			}
		}
	}
}

func (a *envAudit) goflags() {
	for _, f := range strings.Fields(a.get("GOFLAGS")) {
		name, val, _ := strings.Cut(strings.TrimLeft(f, "-"), "=")
		switch {
		case name == "insecure":
			a.add(report.High, "goflags-insecure", "GOFLAGS contains -insecure",
				"insecure fetching was removed in Go 1.17; on older toolchains it disables HTTPS and checksum verification", "remove -insecure; use GOINSECURE for specific hosts")
		case name == "mod" && val == "mod":
			a.add(report.Medium, "goflags-mod-mod", "GOFLAGS contains -mod=mod",
				"go build/test may silently add requirements and rewrite go.mod and go.sum instead of failing; CI should build exactly what is committed",
				"remove it (the default is -mod=readonly)")
		case name == "modcacherw":
			a.add(report.Low, "goflags-modcacherw", "GOFLAGS contains -modcacherw",
				"files in the module cache stay writable, so they can be modified after verification", "")
		}
	}
}

func (a *envAudit) toolchain() {
	v := a.get("GOTOOLCHAIN")
	auto := v == "" || v == "auto" || strings.HasSuffix(v, "+auto")
	if !auto {
		return
	}
	if strings.TrimSpace(a.get("GOSUMDB")) == "off" {
		a.add(report.High, "gotoolchain-unverified", "GOTOOLCHAIN="+v+" with GOSUMDB=off",
			"a go or toolchain line in any go.mod you build can make the go command download and run a different Go toolchain without checksum verification",
			"set GOTOOLCHAIN=local (or path) or re-enable GOSUMDB")
		return
	}
	a.add(report.Info, "gotoolchain-auto", "GOTOOLCHAIN="+v+": go.mod files can switch the Go toolchain",
		"a module that requires a newer Go makes the go command download and run that toolchain (verified by the checksum database)",
		"pin GOTOOLCHAIN=local in CI for reproducible builds")
}

func (a *envAudit) govcs() {
	for _, rule := range strings.Split(a.get("GOVCS"), ",") {
		pat, vcs, ok := strings.Cut(strings.TrimSpace(rule), ":")
		if !ok {
			continue
		}
		if (pat == "*" || pat == "public") && vcs == "all" {
			a.add(report.Medium, "govcs-all", "GOVCS allows every version control system for public modules ("+rule+")",
				"Bazaar, Subversion and Fossil are disabled by default for public modules because of their history of command-injection bugs",
				"remove the rule or restrict it to private patterns")
		}
	}
}

// netrc audits the .netrc file the go command uses.
func (a *envAudit) netrc() {
	path := a.c.Env.Getenv("NETRC")
	if path == "" {
		name := ".netrc"
		if runtime.GOOS == "windows" {
			name = "_netrc"
		}
		path = filepath.Join(a.c.Env.Home(), name)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		a.add(report.Info, "netrc-unreadable", ".netrc exists but cannot be read", err.Error(), "")
		return
	}
	info := &NetrcInfo{Path: path, Mode: fmt.Sprintf("%04o", fi.Mode().Perm()), Machines: []NetrcMachine{}}
	a.res.Netrc = info
	creds := 0
	for _, m := range parseNetrcAll(string(data)) {
		info.Machines = append(info.Machines, NetrcMachine{Host: m.host, Login: redactLogin(m.login), HasPassword: m.password})
		if !m.password {
			continue
		}
		creds++
		if m.host == "default" {
			a.addAt(report.High, "netrc-default", path, m.line, ".netrc has a \"default\" entry with a password",
				"the go command ignores \"default\" entries, but git and curl, which the go command runs for direct VCS fetches, send these credentials to any host without its own machine entry",
				"replace it with explicit machine entries")
			continue
		}
		a.addAt(report.Medium, "netrc-plaintext", path, m.line, "plaintext credentials for "+m.host+" in .netrc (login "+redactLogin(m.login)+")",
			"anyone who can read the file or its backups gets the credential", "prefer a credential helper or short-lived tokens (GOAUTH)")
	}
	if creds > 0 && runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		a.add(report.High, "netrc-permissions", fmt.Sprintf(".netrc with credentials is readable by other users (mode %04o)", fi.Mode().Perm()),
			path, "chmod 600 "+path)
	}
}

type netrcEntry struct {
	host     string
	login    string
	password bool
	line     int
}

// parseNetrcAll returns every machine (and default) entry without
// keeping passwords.
func parseNetrcAll(data string) []netrcEntry {
	var out []netrcEntry
	var cur *netrcEntry
	sc := bufio.NewScanner(strings.NewReader(data))
	line := 0
	inMacro := false
	for sc.Scan() {
		line++
		text := sc.Text()
		if inMacro {
			if strings.TrimSpace(text) == "" {
				inMacro = false
			}
			continue
		}
		f := strings.Fields(text)
		for i := 0; i < len(f); i++ {
			switch f[i] {
			case "machine":
				if i+1 < len(f) {
					out = append(out, netrcEntry{host: f[i+1], line: line})
					cur = &out[len(out)-1]
					i++
				}
			case "default":
				out = append(out, netrcEntry{host: "default", line: line})
				cur = &out[len(out)-1]
			case "login":
				if i+1 < len(f) && cur != nil {
					cur.login = f[i+1]
				}
				i++
			case "password":
				if i+1 < len(f) && cur != nil {
					cur.password = true
				}
				i++
			case "account":
				i++
			case "macdef":
				inMacro = true
				i = len(f)
			default:
				if strings.HasPrefix(f[i], "#") {
					i = len(f)
				}
			}
		}
	}
	return out
}

func redactLogin(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 2 {
		return "***"
	}
	return s[:1] + "***"
}

// gitConfig audits url.*.insteadOf rewrites and credential helpers in the
// git configuration the go command's git invocations read. git itself
// lists it when installed (system file locations differ between git
// builds: Homebrew, Xcode, Git for Windows); otherwise, or with git older
// than 2.26, sm-go finds the files the way git does (config.c:
// do_git_config_sequence). Without git the go command cannot fetch from
// version control at all, so the configuration has no effect.
func (a *envAudit) gitConfig() {
	if listed, ok := a.gitListConfig(); ok {
		parsed := map[string][]gitConfigEntry{} // file -> its entries, for line numbers
		used := map[string]map[int]bool{}
		for _, l := range listed {
			if l.file != "" {
				if _, seen := parsed[l.file]; !seen {
					a.res.GitConfigs = append(a.res.GitConfigs, l.file)
					parsed[l.file] = nil
					if data, err := os.ReadFile(l.file); err == nil {
						parsed[l.file] = parseGitConfig(data)
					}
					used[l.file] = map[int]bool{}
				}
				for i, e := range parsed[l.file] {
					if !used[l.file][i] && e.section == l.entry.section && e.sub == l.entry.sub && e.key == l.entry.key &&
						e.hasValue == l.entry.hasValue && e.value == l.entry.value {
						used[l.file][i] = true
						l.entry.line = e.line
						break
					}
				}
			}
			a.auditGitEntry(l.origin, l.entry)
		}
		return
	}
	for _, f := range a.gitConfigFiles() {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		a.res.GitConfigs = append(a.res.GitConfigs, f)
		for _, e := range parseGitConfig(data) {
			a.auditGitEntry(f, e)
		}
	}
}

// gitListed is one configuration entry as git lists it.
type gitListed struct {
	file   string // absolute path of a file origin, "" otherwise
	origin string // the file, or a description of a non-file origin
	entry  gitConfigEntry
}

// gitEnvOrigin names configuration from GIT_CONFIG_COUNT/KEY_n/VALUE_n or
// GIT_CONFIG_PARAMETERS, which git lists as "command line:".
const gitEnvOrigin = "environment (GIT_CONFIG_*)"

// gitListConfig runs `git config --list --show-origin --show-scope -z` in
// the project directory, with the audited environment. ok is false when
// git is not installed, older than 2.26, disabled with SMGO_NO_GIT=1, or
// fails.
func (a *envAudit) gitListConfig() ([]gitListed, bool) {
	env := a.c.Env
	if env.Getenv("SMGO_NO_GIT") == "1" {
		return nil, false
	}
	git := env.LookPath("git")
	if git == "" {
		return nil, false
	}
	dir, err := filepath.Abs(a.c.Dir())
	if err != nil {
		return nil, false
	}
	run := func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(a.c.Ctx, 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, git, args...)
		cmd.Dir = dir
		cmd.Env = append(env.EnvironIn(dir), "GIT_TERMINAL_PROMPT=0")
		return cmd.Output()
	}
	out, err := run("config", "--list", "--show-origin", "--show-scope", "-z")
	if err != nil {
		return nil, false
	}
	listed, relative, ok := parseGitList(out)
	if !ok {
		return nil, false
	}
	if relative {
		// Repository files are listed relative to the top of the work tree
		// (git changes to it), or to the git directory of a bare repository.
		base := dir
		if top, err := run("rev-parse", "--show-toplevel"); err == nil && len(bytes.TrimSpace(top)) > 0 {
			base = filepath.FromSlash(string(bytes.TrimSpace(top)))
		} else if gd, err := run("rev-parse", "--absolute-git-dir"); err == nil && len(bytes.TrimSpace(gd)) > 0 {
			base = filepath.FromSlash(string(bytes.TrimSpace(gd)))
		}
		for i := range listed {
			if f := listed[i].file; f != "" && !filepath.IsAbs(f) {
				listed[i].file = filepath.Join(base, f)
				listed[i].origin = listed[i].file
			}
		}
	}
	return listed, true
}

// parseGitList parses `git config --list --show-origin --show-scope -z`:
// NUL-terminated scope, origin ("file:<path>", "command line:", "blob:<id>",
// "standard input:") and "<key>\n<value>" (or a bare "<key>") fields.
// Keys are section[.subsection].name with the section and name in lower
// case. relative reports file origins that are not absolute paths.
func parseGitList(out []byte) (listed []gitListed, relative, ok bool) {
	fields := strings.Split(string(out), "\x00")
	if len(fields) > 0 && fields[len(fields)-1] == "" {
		fields = fields[:len(fields)-1]
	}
	if len(fields)%3 != 0 {
		return nil, false, false
	}
	for i := 0; i < len(fields); i += 3 {
		origin, kv := fields[i+1], fields[i+2]
		var l gitListed
		switch {
		case strings.HasPrefix(origin, "file:"):
			l.file = filepath.FromSlash(strings.TrimPrefix(origin, "file:"))
			l.origin = l.file
			if !filepath.IsAbs(l.file) {
				relative = true
			}
		case strings.HasPrefix(origin, "command line:"):
			l.origin = gitEnvOrigin
		default:
			l.origin = strings.TrimSuffix(origin, ":")
		}
		key, value, hasValue := strings.Cut(kv, "\n")
		first, last := strings.Index(key, "."), strings.LastIndex(key, ".")
		if first <= 0 || last == len(key)-1 {
			continue
		}
		l.entry = gitConfigEntry{section: key[:first], key: key[last+1:], value: value, hasValue: hasValue}
		if last > first {
			l.entry.sub = key[first+1 : last]
		}
		listed = append(listed, l)
	}
	return listed, relative, true
}

// gitConfigFiles lists the system, XDG, global, repository and worktree
// configuration files git reads, in git's order. A GIT_CONFIG_SYSTEM or
// GIT_CONFIG_GLOBAL that is set but empty names no file at all, and
// GIT_CONFIG_GLOBAL replaces both ~/.gitconfig and the XDG file.
func (a *envAudit) gitConfigFiles() []string {
	env := a.c.Env
	var files []string
	if !gitBool(env.Getenv("GIT_CONFIG_NOSYSTEM")) {
		sys, ok := env.Lookup("GIT_CONFIG_SYSTEM")
		if !ok && runtime.GOOS != "windows" {
			sys = "/etc/gitconfig"
		}
		files = append(files, sys)
	}
	if g, ok := env.Lookup("GIT_CONFIG_GLOBAL"); ok {
		files = append(files, g)
	} else {
		if xdg := env.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			files = append(files, filepath.Join(xdg, "git", "config"))
		} else if h := env.GitHome(); h != "" {
			files = append(files, filepath.Join(h, ".config", "git", "config"))
		}
		if h := env.GitHome(); h != "" {
			files = append(files, filepath.Join(h, ".gitconfig"))
		}
	}
	if gitDir := a.gitDir(); gitDir != "" {
		common := gitDir
		if b, err := os.ReadFile(filepath.Join(gitDir, "commondir")); err == nil {
			common = strings.TrimRight(string(b), "\r\n")
			if !filepath.IsAbs(common) {
				common = filepath.Join(gitDir, common)
			}
		}
		local := filepath.Join(common, "config")
		files = append(files, local)
		if data, err := os.ReadFile(local); err == nil {
			for _, e := range parseGitConfig(data) {
				if e.section == "extensions" && e.sub == "" && e.key == "worktreeconfig" && (!e.hasValue || gitBool(e.value)) {
					files = append(files, filepath.Join(gitDir, "config.worktree"))
					break
				}
			}
		}
	}
	out := files[:0]
	for _, f := range files {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// gitBool parses a git boolean like git_parse_maybe_bool: "", "false",
// "no", "off" and 0 are false.
func gitBool(v string) bool {
	switch strings.ToLower(v) {
	case "", "false", "no", "off":
		return false
	case "true", "yes", "on":
		return true
	}
	n, err := strconv.Atoi(v)
	return err != nil || n != 0
}

// gitDir finds the repository git would use from the working directory:
// $GIT_DIR, else the nearest ".git" directory, ".git" file ("gitdir: ..."
// as in linked worktrees and submodules) or bare repository.
func (a *envAudit) gitDir() string {
	dir, err := filepath.Abs(a.c.Dir())
	if err != nil {
		return ""
	}
	if g := a.c.Env.Getenv("GIT_DIR"); g != "" {
		if !filepath.IsAbs(g) {
			g = filepath.Join(dir, g)
		}
		return g
	}
	for {
		g := filepath.Join(dir, ".git")
		if fi, err := os.Stat(g); err == nil {
			if fi.IsDir() && isGitDir(g) {
				return g
			}
			if fi.Mode().IsRegular() {
				if b, err := os.ReadFile(g); err == nil {
					if p, ok := strings.CutPrefix(strings.TrimRight(string(b), "\r\n"), "gitdir: "); ok {
						if !filepath.IsAbs(p) {
							p = filepath.Join(dir, p)
						}
						return p
					}
				}
			}
		}
		if isGitDir(dir) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// isGitDir reports whether dir looks like a git directory (HEAD, objects
// and refs), as git's is_git_directory checks.
func isGitDir(dir string) bool {
	for _, n := range []string{"HEAD", "objects", "refs"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			return false
		}
	}
	return true
}

// auditGitEntry audits one git configuration entry from file (a path, or
// a description of another origin).
func (a *envAudit) auditGitEntry(file string, e gitConfigEntry) {
	switch {
	case e.section == "url" && e.key == "insteadof" && e.hasValue:
		a.auditRewrite(file, e.line, e.sub, e.value)
	case e.section == "credential" && e.key == "helper" && strings.HasPrefix(e.value, "store"):
		a.addAt(report.Low, "git-credential-store", file, e.line, "git credential.helper=store keeps passwords in plaintext",
			"credentials are written unencrypted to ~/.git-credentials", "use a system keychain helper (osxkeychain, manager, libsecret)")
	}
}

// gitConfigEntry is one "key = value" line of a git config file.
type gitConfigEntry struct {
	section  string // lower case
	sub      string // case-sensitive subsection ("" if none)
	key      string // lower case
	value    string
	hasValue bool // false for a bare "key" (boolean true)
	line     int
}

// parseGitConfig parses a git config file like git's config.c
// (git_parse_source): section and key names are case-insensitive,
// subsections are not; values may be quoted, use \" \\ \n \t \b escapes
// and continue on the next line after a backslash; unquoted '#' and ';'
// start a comment; unquoted whitespace is trimmed at the ends. Parsing stops
// at the first syntax error (git then refuses the whole file).
func parseGitConfig(data []byte) []gitConfigEntry {
	var out []gitConfigEntry
	s := string(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")))
	i, line := 0, 1
	section, sub := "", ""
	isKeyChar := func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
	}
	isSpace := func(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f' }
	for i < len(s) {
		c := s[i]
		switch {
		case c == '\n':
			line++
			i++
		case isSpace(c):
			i++
		case c == '#' || c == ';':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '[':
			i++
			start := i
			for i < len(s) && (isKeyChar(s[i]) || s[i] == '.') {
				i++
			}
			if i == start || i >= len(s) {
				return out
			}
			section, sub = strings.ToLower(s[start:i]), ""
			if isSpace(s[i]) {
				for i < len(s) && isSpace(s[i]) {
					i++
				}
				if i >= len(s) || s[i] != '"' {
					return out
				}
				i++
				var b strings.Builder
				for {
					if i >= len(s) || s[i] == '\n' {
						return out
					}
					if s[i] == '"' {
						i++
						break
					}
					if s[i] == '\\' {
						i++
						if i >= len(s) || s[i] == '\n' {
							return out
						}
					}
					b.WriteByte(s[i])
					i++
				}
				sub = b.String()
			} else if dot := strings.Index(section, "."); dot >= 0 {
				// Deprecated [section.subsection] form: lower-cased.
				section, sub = section[:dot], section[dot+1:]
			}
			if i >= len(s) || s[i] != ']' {
				return out
			}
			i++
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			start, keyLine := i, line
			for i < len(s) && isKeyChar(s[i]) {
				i++
			}
			e := gitConfigEntry{section: section, sub: sub, key: strings.ToLower(s[start:i]), line: keyLine}
			for i < len(s) && isSpace(s[i]) {
				i++
			}
			if i < len(s) && s[i] != '\n' && s[i] != '=' {
				return out
			}
			if i < len(s) && s[i] == '=' {
				i++
				var v string
				var ok bool
				v, i, line, ok = parseGitValue(s, i, line)
				if !ok {
					return out
				}
				e.value, e.hasValue = v, true
			}
			if section == "" {
				return out // a key outside any section
			}
			out = append(out, e)
		default:
			return out
		}
	}
	return out
}

// parseGitValue parses a value starting at s[i] (just after '=') up to the
// end of its (logical) line, which it leaves unconsumed.
func parseGitValue(s string, i, line int) (string, int, int, bool) {
	var b strings.Builder
	quote, space := false, 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	for ; i < len(s); i++ {
		c := s[i]
		if c == '\n' {
			if quote {
				return "", i, line, false
			}
			break
		}
		if !quote && (c == ';' || c == '#') {
			for i < len(s) && s[i] != '\n' {
				i++
			}
			break
		}
		if !quote && (c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f') {
			if b.Len() > 0 {
				space++
			}
			continue
		}
		for ; space > 0; space-- {
			b.WriteByte(' ')
		}
		switch c {
		case '\\':
			i++
			if i >= len(s) {
				return "", i, line, false
			}
			switch s[i] {
			case '\n':
				line++
			case 't':
				b.WriteByte('\t')
			case 'b':
				b.WriteByte('\b')
			case 'n':
				b.WriteByte('\n')
			case '\\', '"':
				b.WriteByte(s[i])
			default:
				return "", i, line, false
			}
		case '"':
			quote = !quote
		default:
			b.WriteByte(c)
		}
	}
	if quote {
		return "", i, line, false
	}
	return b.String(), i, line, true
}

// rewriteHost extracts the host of a git URL or scp-like address.
func rewriteHost(s string) (scheme, host string, creds bool) {
	if i := strings.Index(s, "://"); i >= 0 {
		u, err := url.Parse(s)
		if err != nil {
			return s[:i], "", false
		}
		_, pw := u.User.Password()
		tokenUser := u.User != nil && u.User.Username() != "" && u.User.Username() != "git" && len(u.User.Username()) >= 20
		return u.Scheme, strings.ToLower(u.Hostname()), pw || tokenUser
	}
	// scp-like: [user@]host:path
	if at := strings.Index(s, "@"); at >= 0 {
		s = s[at+1:]
	}
	if i := strings.Index(s, ":"); i >= 0 {
		return "ssh", strings.ToLower(s[:i]), false
	}
	return "", "", false
}

func (a *envAudit) auditRewrite(file string, line int, base, prefix string) {
	to := redactURL(base)
	a.res.GitRewrites = append(a.res.GitRewrites, GitRewrite{File: file, Line: line, From: redactURL(prefix), To: to})
	bScheme, bHost, creds := rewriteHost(base)
	_, pHost, _ := rewriteHost(prefix)
	title := fmt.Sprintf("git rewrites %s to %s", redactURL(prefix), to)
	if creds {
		a.addAt(report.High, "git-rewrite-credentials", file, line, title,
			"the rewrite target embeds a token or password in plaintext git configuration", "use a credential helper or GOAUTH instead of credentials in insteadOf")
	}
	switch bScheme {
	case "http", "git":
		if !isLoopback(bHost) {
			a.addAt(report.High, "git-rewrite-insecure", file, line, title,
				"fetches are redirected to an unencrypted "+bScheme+":// transport that anyone on the network can tamper with", "use https:// or ssh")
		}
	}
	if pHost != "" && bHost != "" && pHost != bHost {
		a.addAt(report.Medium, "git-rewrite-host", file, line, title,
			"direct module fetches for "+pHost+" are served by "+bHost+"; that host controls the code (GOSUMDB still verifies public modules)", "")
	} else if bScheme == "ssh" && !creds {
		a.addAt(report.Info, "git-rewrite-ssh", file, line, title, "fetches use SSH keys (common for private modules)", "")
	}
}

func printEnv(c *cli.Context, res *EnvResult, failOn report.Severity) {
	o := c.Out
	o.Title("sm-go env · Go module security configuration")
	o.Heading("Settings")
	var rows [][]string
	for _, s := range res.Settings {
		v := s.Value
		if v == "" {
			v = o.Dim("(unset)")
		}
		rows = append(rows, []string{s.Name, v, o.Dim(s.Source)})
	}
	o.Table([]string{"VARIABLE", "VALUE", "SOURCE"}, rows)
	if res.Netrc != nil {
		o.Heading(".netrc " + o.Dim(res.Netrc.Path+" (mode "+res.Netrc.Mode+")"))
		for _, m := range res.Netrc.Machines {
			cred := "no password"
			if m.HasPassword {
				cred = "password: ***"
			}
			login := m.Login
			if login == "" {
				login = "-"
			}
			o.Printf("  %-28s login %-10s %s\n", m.Host, login, cred)
		}
	}
	if len(res.GitRewrites) > 0 {
		o.Heading("git insteadOf rewrites")
		for _, r := range res.GitRewrites {
			o.Printf("  %s → %s %s\n", r.From, r.To, o.Dim(fmt.Sprintf("(%s:%d)", r.File, r.Line)))
		}
	}
	o.Heading("Findings")
	if len(res.Findings) == 0 {
		o.OK("no issues found")
	} else {
		printFindings(c, res.Findings)
	}
	o.Println()
	if res.Failing > 0 {
		o.Bad("%d %s at or above %s (%s)", res.Failing, map[bool]string{true: "finding", false: "findings"}[res.Failing == 1], failOn, countLine(res.Summary))
	} else {
		o.OK("no findings at or above %s (%s)", failOn, countLine(res.Summary))
	}
}
