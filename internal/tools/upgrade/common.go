package upgrade

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/apidiff"
	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/modfile"
	"github.com/slash-mark-dev/go-suite/internal/modgraph"
	"github.com/slash-mark-dev/go-suite/internal/modproxy"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/project"
	"github.com/slash-mark-dev/go-suite/internal/semver"
	"github.com/slash-mark-dev/go-suite/internal/ui"
)

const group = "Upgrade & release"

// loadAPI type-checks path@version, turning an unknown module version
// into a usage error.
func loadAPI(c *cli.Context, path, version string) (*apidiff.Module, error) {
	if !c.Env.HaveGo() {
		return nil, apidiff.ErrNoGo
	}
	if _, err := c.Proxy().Info(c.Ctx, path, version); err != nil {
		if errors.Is(err, modproxy.ErrNotFound) {
			return nil, cli.Usagef("%s@%s: no such module version", path, version)
		}
		return nil, err
	}
	c.Logf("type-checking %s@%s", path, version)
	m, err := apidiff.LoadVersion(c.Ctx, c.Env, path, version)
	if err != nil {
		return nil, err
	}
	for _, e := range m.Errors {
		c.Warnf("%s@%s: %s (API may be incomplete)", path, version, e)
	}
	return m, nil
}

// loadLocalAPI type-checks the module in dir.
func loadLocalAPI(c *cli.Context, dir string) (*apidiff.Module, error) {
	c.Logf("type-checking %s", dir)
	m, err := apidiff.LoadDir(c.Ctx, c.Env, dir)
	if err != nil {
		return nil, err
	}
	for _, e := range m.Errors {
		c.Warnf("%s (API may be incomplete)", e)
	}
	return m, nil
}

// resolveQuery turns a version query into a version: an exact semantic
// version, "latest", or "upgrade"/"patch" relative to current.
func resolveQuery(c *cli.Context, path, query, current string) (string, error) {
	switch query {
	case "", "latest":
		v, err := c.Proxy().QueryLatest(c.Ctx, path)
		if err != nil {
			if errors.Is(err, modproxy.ErrNotFound) {
				return "", cli.Usagef("module %s not found", path)
			}
			return "", err
		}
		if v == "" {
			return "", cli.Usagef("module %s has no versions", path)
		}
		return v, nil
	case "upgrade", "patch":
		if current == "" {
			return resolveQuery(c, path, "latest", "")
		}
		v, err := c.Proxy().LatestCompatible(c.Ctx, path, current, query == "patch")
		if err != nil {
			return "", err
		}
		return v, nil
	case "none":
		return "none", nil
	}
	v := query
	if semver.IsValid(v) {
		cv := semver.Canonical(v)
		if semver.Build(v) == "+incompatible" {
			cv += "+incompatible"
		}
		if cv != v && !module.IsPseudoVersion(v) {
			return "", cli.Usagef("%s@%s: use the canonical version %s", path, v, cv)
		}
		return v, nil
	}
	return "", cli.Usagef("%s@%s: version must be a semantic version (v1.2.3), latest, upgrade, patch or none", path, query)
}

// splitArg splits "path@query".
func splitArg(arg string) (path, query string, err error) {
	path, query, _ = strings.Cut(arg, "@")
	if err := module.CheckPath(path); err != nil {
		return "", "", cli.Usagef("%q: %v", arg, err)
	}
	return path, query, nil
}

// semverBump describes the change between two versions of one module path
// ("major", "minor", "patch", "prerelease", "none" or "downgrade").
func semverBump(from, to string) string {
	switch c := semver.Compare(from, to); {
	case c == 0:
		return "none"
	case c > 0:
		return "downgrade"
	}
	switch {
	case semver.Major(from) != semver.Major(to):
		return "major"
	case semver.MajorMinor(from) != semver.MajorMinor(to):
		return "minor"
	case strings.TrimSuffix(semver.Canonical(from), semver.Prerelease(from)) != strings.TrimSuffix(semver.Canonical(to), semver.Prerelease(to)):
		return "patch"
	}
	return "prerelease"
}

// loadGraph builds the MVS graph of the project with replaced roots.
func loadGraph(c *cli.Context, p *project.Project, roots []module.Version) (*modgraph.Graph, error) {
	cfg := modgraph.Config{Mains: p.Mains, Fetch: c.Proxy(), Roots: roots}
	if p.Work != nil {
		cfg.Work = p.Work
		cfg.WorkDir = p.Dir
	}
	return modgraph.Load(c.Ctx, cfg)
}

// printChanges prints the per-package changes of a report.
func printChanges(c *cli.Context, rep apidiff.Report, all bool, affected func(apidiff.Change) []string) {
	out := c.Out
	for _, pr := range rep.ByPackage() {
		if len(pr.Incompatible) == 0 && (!all || len(pr.Compatible) == 0) {
			continue
		}
		out.Printf("\n  %s\n", out.Bold(pr.Package))
		for _, ch := range pr.Incompatible {
			out.Printf("    %s %s\n", out.Red("✗"), ch.Message)
			if affected != nil {
				for _, pos := range affected(ch) {
					out.Printf("        %s %s\n", out.Dim("used at"), pos)
				}
			}
		}
		if all {
			for _, ch := range pr.Compatible {
				out.Printf("    %s %s\n", out.Green("+"), ch.Message)
			}
		}
	}
}

func plural(n int, one, many string) string { return ui.Plural(n, one, many) }

func modAt(path, version string) string {
	if version == "" {
		return path
	}
	return path + "@" + version
}

func errorf(format string, a ...any) error { return fmt.Errorf(format, a...) }

// maxSelectedGo returns the highest go directive among the selected
// (non-main) modules of g and which module declares it. Unlike
// modgraph.Graph.MaxGo it also reads the go.mod of modules whose
// requirements graph pruning did not load (they are still in the build
// list, as `go list -m all` shows).
func maxSelectedGo(c *cli.Context, g *modgraph.Graph) (string, module.Version, error) {
	best, who := "", module.Version{}
	for _, m := range g.BuildList() {
		v, ok := g.GoVersion[m]
		if !ok {
			var err error
			if v, err = readGoLine(c, g, m); err != nil {
				return "", who, err
			}
		}
		if modgraph.CompareGo(v, best) > 0 {
			best, who = v, m
		}
	}
	return best, who, nil
}

func readGoLine(c *cli.Context, g *modgraph.Graph, m module.Version) (string, error) {
	var data []byte
	var err error
	if r, base := g.FindReplace(m); r != nil {
		if !r.IsLocal() {
			data, err = c.Proxy().GoMod(c.Ctx, r.New.Path, r.New.Version)
		} else {
			dir := r.New.Path
			if !filepath.IsAbs(dir) {
				dir = filepath.Join(base, dir)
			}
			data, err = os.ReadFile(filepath.Join(dir, "go.mod"))
			if os.IsNotExist(err) {
				return "", nil
			}
		}
	} else {
		data, err = c.Proxy().GoMod(c.Ctx, m.Path, m.Version)
	}
	if err != nil {
		return "", err
	}
	return modfile.Parse(m.String()+"/go.mod", data).Go, nil
}
