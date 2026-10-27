// Package endpoints holds the base URLs of every live data source sm-go
// talks to. Each can be overridden with an environment variable, which is
// how the test suite points the tools at local fake servers and how users
// point them at internal mirrors.
package endpoints

import (
	"net"
	"net/url"
	"strings"
)

// Getenv is satisfied by *goenv.Env.
type Getenv interface{ Getenv(string) string }

type source struct {
	env, def string
}

var sources = map[string]source{
	"vulndb":  {"SMGO_VULNDB_URL", "https://vuln.go.dev"},
	"index":   {"SMGO_INDEX_URL", "https://index.golang.org"},
	"depsdev": {"SMGO_DEPSDEV_URL", "https://api.deps.dev"},
	"github":  {"SMGO_GITHUB_API_URL", "https://api.github.com"},
	"kev":     {"SMGO_KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"},
	"epss":    {"SMGO_EPSS_URL", "https://api.first.org/data/v1/epss"},
	"godev":   {"SMGO_GODEV_URL", "https://go.dev"},
	"rdap":    {"SMGO_RDAP_URL", "https://rdap.org"},
	// The checksum database URL comes from GOSUMDB; this override exists
	// for tests and for sumdb proxies.
	"sumdb": {"SMGO_SUMDB_URL", ""},
}

// URL returns the base URL for the named source, without a trailing slash.
func URL(e Getenv, name string) string {
	s, ok := sources[name]
	if !ok {
		panic("unknown endpoint " + name)
	}
	if e != nil {
		if v := e.Getenv(s.env); v != "" {
			return strings.TrimRight(v, "/")
		}
	}
	return strings.TrimRight(s.def, "/")
}

// EnvVar returns the override variable for a source, for help text.
func EnvVar(name string) string { return sources[name].env }

// VanityURL returns the URL fetched to resolve an import path through its
// <meta name="go-import"> tag: https://<path>?go-get=1. Tests (and users
// behind an inspection proxy) can set SMGO_VANITY_BASE to fetch
// <base>/<path>?go-get=1 instead.
func VanityURL(e Getenv, importPath string) string {
	if e != nil {
		if b := e.Getenv("SMGO_VANITY_BASE"); b != "" {
			return strings.TrimRight(b, "/") + "/" + importPath + "?go-get=1"
		}
	}
	return "https://" + importPath + "?go-get=1"
}

// VanityFetchURL returns the URL to fetch for raw, an http(s) URL on a
// host named by a go-import tag (a repository root probed by sm-go
// vanity). With SMGO_VANITY_BASE set, https://<host>/<path> is fetched
// as <base>/<host>/<path> and http://... as <base>-http/<host>/<path>,
// like the import pages themselves, so tests never reach the network.
// URLs on IP addresses and localhost are fetched as they are.
func VanityFetchURL(e Getenv, raw string) string {
	if e == nil {
		return raw
	}
	b := strings.TrimRight(e.Getenv("SMGO_VANITY_BASE"), "/")
	u, err := url.Parse(raw)
	switch {
	case b == "" || err != nil:
		return raw
	case u.Hostname() == "localhost" || net.ParseIP(u.Hostname()) != nil:
		return raw
	case strings.HasPrefix(raw, "https://"):
		return b + "/" + strings.TrimPrefix(raw, "https://")
	case strings.HasPrefix(raw, "http://"):
		return b + "-http/" + strings.TrimPrefix(raw, "http://")
	}
	return raw
}
