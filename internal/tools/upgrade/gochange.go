package upgrade

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/modgraph"
)

// This file mirrors how the go command updates the toolchain line and picks
// a toolchain to switch to (cmd/go/internal/modload.UpdateGoModFromReqs and
// cmd/go/internal/toolchain.NewerToolchain).

// recordsRunningToolchain reports whether `go get` run by Go version runner
// writes its own version into the toolchain line when it raises the go line.
// Go 1.21 to 1.24 do; Go 1.25 removed that behavior.
func recordsRunningToolchain(runner string) bool {
	return runner != "" && modgraph.CompareGo(runner, "1.21") >= 0 && modgraph.CompareGo(runner, "1.25") < 0
}

// predictToolchain returns the toolchain line `go get` leaves in go.mod when
// it raises the go line to newGo, given the current toolchain line tcLine
// ("go1.x.y" or "") and the version of the go command that runs (runner, ""
// if unknown).
func predictToolchain(newGo, tcLine, runner string) string {
	tc := strings.TrimPrefix(tcLine, "go")
	// Raising the go line raises the toolchain requirement with it; a
	// toolchain equal to the go line is dropped.
	switch {
	case recordsRunningToolchain(runner) && !isLang(runner) &&
		modgraph.CompareGo(newGo, "1.21") >= 0 &&
		modgraph.CompareGo(runner, newGo) > 0 && modgraph.CompareGo(runner, tc) > 0:
		return "go" + runner
	case tc != "" && modgraph.CompareGo(tc, newGo) > 0:
		return tcLine
	}
	return ""
}

// newerToolchain picks the toolchain the go command switches to when it
// needs at least Go version need, from the available versions list (sorted
// ascending): the latest patch release of the newest language family before
// the most recent release family, if that is new enough; otherwise the
// latest release. It returns "" when nothing is new enough.
func newerToolchain(need string, list []string) string {
	latest := ""
	for i := len(list) - 1; i >= 0; i-- {
		v := list[i]
		if modgraph.CompareGo(v, need) < 0 {
			break
		}
		if goLang(latest) == goLang(v) {
			continue
		}
		newer := latest
		latest = v
		if newer != "" && !goPrerelease(newer) {
			break
		}
	}
	if latest == "" {
		return ""
	}
	return "go" + latest
}

// goLang returns the language version of a Go version ("1.22.3" -> "1.22").
func goLang(v string) string {
	v = strings.TrimPrefix(v, "go")
	if i := strings.IndexFunc(v, func(r rune) bool { return r != '.' && (r < '0' || r > '9') }); i >= 0 {
		v = v[:i]
	}
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 || parts[1] == "" || parts[0] == "1" && parts[1] == "0" {
		return parts[0]
	}
	return parts[0] + "." + parts[1]
}

// goPrerelease reports whether v is a prerelease such as "1.22rc1".
func goPrerelease(v string) bool {
	return strings.ContainsAny(strings.TrimPrefix(v, "go"), "abcdefghijklmnopqrstuvwxyz")
}

var goVersionRE = regexp.MustCompile(`^[1-9][0-9]*(\.(0|[1-9][0-9]*)){0,2}((alpha|beta|rc)(0|[1-9][0-9]*))?$`)

// dlToGo converts a golang.org/toolchain module version
// ("v0.0.1-go1.22.3.linux-amd64") to a Go version ("1.22.3").
func dlToGo(v string) (string, bool) {
	_, v, ok := strings.Cut(v, "-")
	if !ok {
		return "", false
	}
	i := strings.LastIndex(v, ".")
	if i < 0 || !strings.Contains(v[i+1:], "-") {
		return "", false
	}
	v = strings.TrimPrefix(v[:i], "go")
	return v, goVersionRE.MatchString(v)
}

// fromToolchainName returns the Go version of a toolchain executable name
// such as "go1.22.3" (custom "-suffix"es are ignored).
func fromToolchainName(name string) string {
	if strings.ContainsAny(name, `\/`) || !strings.HasPrefix(name, "go") {
		return ""
	}
	v := name[2:]
	if i := strings.IndexAny(v, " \t-"); i >= 0 {
		v = v[:i]
	}
	if !goVersionRE.MatchString(v) {
		return ""
	}
	return v
}

// toolchainChoices lists the Go versions the go command could switch to
// under GOTOOLCHAIN mode: published toolchains on the module proxy for
// auto, executables named go1.x.y on PATH for path. local is always
// included, as the go command does.
func toolchainChoices(ctx context.Context, mode, local string, proxyVersions func(context.Context, string) ([]string, error), pathEnv, pathExt string) ([]string, error) {
	have := map[string]bool{}
	var list []string
	add := func(v string) {
		if v != "" && !have[v] {
			have[v] = true
			list = append(list, v)
		}
	}
	switch {
	case mode == "auto" || strings.HasSuffix(mode, "+auto"):
		vs, err := proxyVersions(ctx, "golang.org/toolchain")
		if err != nil {
			return nil, err
		}
		for _, v := range vs {
			if g, ok := dlToGo(v); ok {
				add(g)
			}
		}
	case mode == "path" || strings.HasSuffix(mode, "+path"):
		for _, dir := range filepath.SplitList(pathEnv) {
			if dir == "" || !filepath.IsAbs(dir) {
				continue
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, de := range entries {
				if de.IsDir() || !strings.HasPrefix(de.Name(), "go1.") {
					continue
				}
				if v, ok := pathToolchainVersion(dir, de, pathExt); ok && strings.HasPrefix(v, "1.") {
					add(v)
				}
			}
		}
	}
	add(local)
	sort.Slice(list, func(i, j int) bool { return modgraph.CompareGo(list[i], list[j]) < 0 })
	return list, nil
}

// pathToolchainVersion mirrors the go command's pathVersion: on Windows the
// name must end in a PATHEXT extension, elsewhere the file must be executable.
func pathToolchainVersion(dir string, de os.DirEntry, pathExt string) (string, bool) {
	name := de.Name()
	if runtime.GOOS == "windows" {
		exts := []string{".com", ".exe", ".bat", ".cmd"}
		if pathExt != "" {
			exts = nil
			for _, e := range strings.Split(strings.ToLower(pathExt), ";") {
				if e != "" {
					if e[0] != '.' {
						e = "." + e
					}
					exts = append(exts, e)
				}
			}
		}
		i := strings.LastIndex(name, ".")
		if i < 0 {
			return "", false
		}
		found := false
		for _, e := range exts {
			if strings.EqualFold(name[i:], e) {
				found = true
				break
			}
		}
		if !found {
			return "", false
		}
		name = name[:i]
	} else {
		info, err := de.Info()
		if err != nil || info.Mode()&0o111 == 0 {
			return "", false
		}
	}
	v := fromToolchainName(name)
	return v, v != ""
}
