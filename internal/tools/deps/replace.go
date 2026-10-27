package deps

import (
	"errors"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/feeds"
	"github.com/slash-mark-dev/go-suite/internal/httpx"
	"github.com/slash-mark-dev/go-suite/internal/modfile"
	"github.com/slash-mark-dev/go-suite/internal/modgraph"
	"github.com/slash-mark-dev/go-suite/internal/modproxy"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/project"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/semver"
)

var replaceFlags struct {
	failOn   func() (report.Severity, error)
	noForks  *bool
	staleDay *int
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "replace",
		Group:   group,
		Summary: "Replace & exclude auditor: local paths, stale forks, no-op and ignored directives",
		Usage:   "sm-go replace [flags]",
		Help: `Audits every replace and exclude directive against the go command's rules.

Replace directives of the main module (and go.work in a workspace):
  local path   the replacement is a directory: the module cannot be built
               from its zip, consumers build the original module instead,
               and 'go install module@version' refuses a go.mod with
               replace directives. A missing directory, a directory without
               go.mod or one declaring a different module path breaks the
               build (high).
  fork         the replacement is a different module path: the fork's
               version date is compared with the upstream releases on the
               proxy (and the fork repository on GitHub when available) to
               show how far it is behind upstream.
  version      same path, different version: the code no longer matches
               the version MVS selected (a downgrade is flagged).
  no effect    the replaced module (or the replaced version) is not in the
               module graph; a versioned replace of a non-selected version
               only changes which go.mod is read.
  overridden   in a workspace, go.work replaces the same module path.

Exclude directives: effective when some go.mod in the graph requires
exactly the excluded version (the requirement is dropped); an exclude of a
version above the selected one only stops 'go get -u' from choosing it;
anything else has no effect.

Directives in the go.mod of dependencies are ignored by the go command
(only the main module's replace and exclude apply): they are listed, and
flagged when the dependency relied on a replacement of a module in your
build.`,
		Examples: []string{
			"sm-go replace",
			"sm-go replace --fail-on low",
			"sm-go replace --no-forks --json",
		},
		Sources: []string{"Go module proxy (versions, .info times, go.mod files)", "GitHub API (fork repositories, optional)"},
		Flags: func(fs *flag.FlagSet) {
			replaceFlags.failOn = failOnFlag(fs, "medium")
			replaceFlags.noForks = fs.Bool("no-forks", false, "skip the fork staleness check (no proxy version lists or GitHub)")
			replaceFlags.staleDay = fs.Int("stale-days", 365, "a fork whose newest missing upstream release is `n` days newer than the fork version is medium severity")
		},
		Run: runReplace,
	})
}

type localInfo struct {
	Dir        string `json:"dir"`
	Exists     bool   `json:"exists"`
	HasGoMod   bool   `json:"hasGoMod"`
	ModulePath string `json:"modulePath,omitempty"`
}

type githubInfo struct {
	Repo     string    `json:"repo"`
	Found    bool      `json:"found"`
	Archived bool      `json:"archived,omitempty"`
	Fork     bool      `json:"fork,omitempty"`
	Parent   string    `json:"parent,omitempty"`
	PushedAt time.Time `json:"pushedAt,omitempty"`
}

type forkInfo struct {
	Upstream           string      `json:"upstream"`
	UpstreamFound      bool        `json:"upstreamFound"`
	ForkTime           time.Time   `json:"forkTime,omitempty"`
	UpstreamLatest     string      `json:"upstreamLatest,omitempty"`
	UpstreamLatestTime time.Time   `json:"upstreamLatestTime,omitempty"`
	MissingReleases    []string    `json:"missingReleases"`
	BehindDays         int         `json:"behindDays"`
	GitHub             *githubInfo `json:"github,omitempty"`
}

type replaceEntry struct {
	File      string     `json:"file"`
	Line      int        `json:"line"`
	Old       string     `json:"old"`
	New       string     `json:"new"`
	Kind      string     `json:"kind"`   // local, fork, version
	Effect    string     `json:"effect"` // build, graph, none, overridden, error
	Selected  string     `json:"selected,omitempty"`
	AppliesTo []string   `json:"appliesTo"`
	Local     *localInfo `json:"local,omitempty"`
	Fork      *forkInfo  `json:"fork,omitempty"`
	Error     string     `json:"error,omitempty"`
}

type excludeEntry struct {
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Module     string   `json:"module"`
	Version    string   `json:"version"`
	Effect     string   `json:"effect"` // drops, upgrades-only, none
	Selected   string   `json:"selected,omitempty"`
	RequiredBy []string `json:"requiredBy"`
}

type ignoredEntry struct {
	In        string `json:"in"`
	Directive string `json:"directive"`
	Line      int    `json:"line"`
	Text      string `json:"text"`
	Matters   bool   `json:"matters"`
}

type replaceResult struct {
	Workspace bool             `json:"workspace"`
	Replaces  []replaceEntry   `json:"replaces"`
	Excludes  []excludeEntry   `json:"excludes"`
	Ignored   []ignoredEntry   `json:"ignored"`
	Findings  []report.Finding `json:"findings"`
	Summary   severitySummary  `json:"summary"`
}

// directive is a replace together with the file it came from.
type directive struct {
	r    *modfile.Replace
	file string // display path
	base string // directory relative paths resolve against
	work bool   // from go.work
}

func runReplace(c *cli.Context) error {
	failOn, err := replaceFlags.failOn()
	if err != nil {
		return err
	}
	if len(c.Args) > 0 {
		return cli.Usagef("unexpected argument %q", c.Args[0])
	}
	p, g, err := loadGraph(c)
	if err != nil {
		return err
	}
	res := replaceResult{Workspace: p.IsWorkspace(), Replaces: []replaceEntry{}, Excludes: []excludeEntry{}, Ignored: []ignoredEntry{}, Findings: []report.Finding{}}
	add := func(f report.Finding) { res.Findings = append(res.Findings, f) }

	var dirs []directive
	workPaths := map[string]bool{}
	if p.IsWorkspace() {
		for _, r := range p.Work.Replace {
			dirs = append(dirs, directive{r: r, file: p.Rel(p.WorkPath), base: p.Dir, work: true})
			workPaths[r.Old.Path] = true
		}
	}
	for _, mm := range p.Mains {
		if mm.File == nil {
			continue
		}
		for _, r := range mm.File.Replace {
			dirs = append(dirs, directive{r: r, file: p.Rel(mm.File.Name), base: mm.Dir})
		}
	}
	nodes := g.Nodes()
	for _, d := range dirs {
		e, fs, err := auditReplace(c, p, g, nodes, d, workPaths)
		if err != nil {
			return err
		}
		res.Replaces = append(res.Replaces, e)
		for _, f := range fs {
			add(f)
		}
	}

	// go install m@version refuses replace and exclude directives.
	if !p.IsWorkspace() && p.GoMod != nil && (len(p.GoMod.Replace) > 0 || len(p.GoMod.Exclude) > 0) {
		if cmds := mainPackages(p.ModDir); len(cmds) > 0 {
			add(report.Finding{Severity: report.Low, Rule: "replace-blocks-go-install", Module: p.ModulePath(), File: p.Rel(p.GoModPath),
				Title:  fmt.Sprintf("'go install %s@latest' fails: go.mod has replace or exclude directives", strings.TrimSuffix(cmds[0], "/...")),
				Detail: fmt.Sprintf("The module has %s (%s). 'go install pkg@version' refuses to build a module whose go.mod contains replace or exclude directives, so users cannot install it that way.", plural(len(cmds), "command", "commands"), ui3(cmds)),
				Fix:    "drop the directives before tagging a release (publish forks under their own module path and require them directly)"})
		}
	}

	// Excludes.
	raw, err := rawRequires(c, g)
	if err != nil {
		return err
	}
	for _, mm := range p.Mains {
		if mm.File == nil {
			continue
		}
		for _, ex := range mm.File.Exclude {
			e := excludeEntry{File: p.Rel(mm.File.Name), Line: ex.Line, Module: ex.Mod.Path, Version: ex.Mod.Version, RequiredBy: []string{}, Selected: g.Selected[ex.Mod.Path]}
			for from, reqs := range raw {
				for _, r := range reqs {
					if r == ex.Mod {
						e.RequiredBy = append(e.RequiredBy, nodeID(g, from))
					}
				}
			}
			for _, m2 := range p.Mains {
				if m2.File == nil {
					continue
				}
				for _, r := range m2.File.Require {
					if r.Mod == ex.Mod {
						e.RequiredBy = append(e.RequiredBy, m2.Path())
					}
				}
			}
			e.RequiredBy = uniqSorted(e.RequiredBy)
			f := report.Finding{Rule: "exclude", Module: ex.Mod.Path, Version: ex.Mod.Version, File: e.File, Line: e.Line}
			switch {
			case len(e.RequiredBy) > 0:
				e.Effect = "drops"
				f.Severity = report.Info
				f.Title = fmt.Sprintf("exclude %s %s drops %s", ex.Mod.Path, ex.Mod.Version, plural(len(e.RequiredBy), "requirement", "requirements"))
				f.Detail = fmt.Sprintf("Required by %s; the go command ignores those requirements, so %s resolves to %s.", strings.Join(e.RequiredBy, ", "), ex.Mod.Path, orNone([]string{e.Selected}))
			case g.IsMain(ex.Mod.Path):
				e.Effect = "none"
				f.Severity = report.Low
				f.Title = fmt.Sprintf("exclude of the main module %s has no effect", ex.Mod.Path)
				f.Fix = "remove the exclude directive"
			case e.Selected != "" && semver.Compare(ex.Mod.Version, e.Selected) > 0:
				e.Effect = "upgrades-only"
				f.Severity = report.Info
				f.Title = fmt.Sprintf("exclude %s %s only affects upgrades", ex.Mod.Path, ex.Mod.Version)
				f.Detail = fmt.Sprintf("No go.mod in the graph requires it (selected %s); 'go get -u' and @latest queries skip the excluded version.", e.Selected)
			default:
				e.Effect = "none"
				f.Severity = report.Low
				where := "is not in the module graph"
				if e.Selected != "" {
					where = "is selected at " + e.Selected
				}
				f.Title = fmt.Sprintf("exclude %s %s has no effect", ex.Mod.Path, ex.Mod.Version)
				f.Detail = fmt.Sprintf("No go.mod in the module graph requires %s@%s and %s %s, so the directive changes nothing.", ex.Mod.Path, ex.Mod.Version, ex.Mod.Path, where)
				f.Fix = "remove the exclude directive"
			}
			res.Excludes = append(res.Excludes, e)
			add(f)
		}
	}

	// Directives in dependency go.mod files are ignored.
	var deps []module.Version
	for _, m := range g.BuildList() {
		if _, ok := g.Reqs[m]; ok {
			deps = append(deps, m)
		}
	}
	files, err := goModFiles(c, g, deps)
	if err != nil {
		return err
	}
	for _, m := range deps {
		f := files[m]
		if f == nil || (len(f.Replace) == 0 && len(f.Exclude) == 0) {
			continue
		}
		var matters []string
		for _, r := range f.Replace {
			ie := ignoredEntry{In: nodeID(g, m), Directive: "replace", Line: r.Line, Text: replaceText(r)}
			if sel, ok := g.Selected[r.Old.Path]; ok && !g.IsMain(r.Old.Path) && (r.Old.Version == "" || r.Old.Version == sel) {
				used, _ := g.FindReplace(module.Version{Path: r.Old.Path, Version: sel})
				if used == nil || used.New != r.New || r.IsLocal() {
					ie.Matters = true
					matters = append(matters, fmt.Sprintf("%s (you build %s@%s%s)", replaceText(r), r.Old.Path, sel, usedSuffix(used)))
				}
			}
			res.Ignored = append(res.Ignored, ie)
		}
		for _, x := range f.Exclude {
			ie := ignoredEntry{In: nodeID(g, m), Directive: "exclude", Line: x.Line, Text: x.Mod.Path + " " + x.Mod.Version}
			if g.Selected[x.Mod.Path] == x.Mod.Version {
				ie.Matters = true
				matters = append(matters, fmt.Sprintf("exclude %s %s (selected in your build)", x.Mod.Path, x.Mod.Version))
			}
			res.Ignored = append(res.Ignored, ie)
		}
		n := len(f.Replace) + len(f.Exclude)
		fd := report.Finding{Rule: "ignored-in-dependency", Module: m.Path, Version: m.Version, Severity: report.Info,
			Title:  fmt.Sprintf("%s has %s in its go.mod, ignored as a dependency", nodeID(g, m), plural(n, "replace/exclude directive", "replace/exclude directives")),
			Detail: "The go command applies replace and exclude directives only from the main module (and go.work); in a dependency they have no effect."}
		if len(matters) > 0 {
			fd.Severity = report.Low
			fd.Title = fmt.Sprintf("%s relies on directives your build ignores", nodeID(g, m))
			fd.Detail += " These concern modules in your build, so you compile " + m.Path + " against different code than its authors: " + strings.Join(matters, "; ") + "."
			fd.Fix = "check that " + m.Path + " works with the versions you select, or mirror the needed replace in your go.mod"
		}
		add(fd)
	}
	res.Summary = finish(c, res.Findings, failOn)
	c.SetResult(res)
	if c.Text() {
		printReplace(c, res)
	}
	return nil
}

func usedSuffix(r *modfile.Replace) string {
	if r == nil {
		return ""
	}
	return " => " + replaceString(r.New)
}

func replaceText(r *modfile.Replace) string {
	old := r.Old.Path
	if r.Old.Version != "" {
		old += " " + r.Old.Version
	}
	return old + " => " + replaceString(r.New)
}

func auditReplace(c *cli.Context, p *project.Project, g *modgraph.Graph, nodes []module.Version, d directive, workPaths map[string]bool) (replaceEntry, []report.Finding, error) {
	r := d.r
	e := replaceEntry{File: d.file, Line: r.Line, New: replaceString(r.New), AppliesTo: []string{}}
	e.Old = r.Old.Path
	if r.Old.Version != "" {
		e.Old += " " + r.Old.Version
	}
	switch {
	case r.IsLocal():
		e.Kind = "local"
	case r.New.Path != r.Old.Path:
		e.Kind = "fork"
	default:
		e.Kind = "version"
	}
	var fs []report.Finding
	base := report.Finding{Rule: "replace", Module: r.Old.Path, Version: r.Old.Version, File: d.file, Line: r.Line}
	finding := func(sev report.Severity, rule, title, detail, fix string) {
		f := base
		f.Severity, f.Rule, f.Title, f.Detail, f.Fix = sev, rule, title, detail, fix
		fs = append(fs, f)
	}
	sel, inGraph := g.Selected[r.Old.Path]
	if inGraph && !g.IsMain(r.Old.Path) {
		e.Selected = sel
	}

	// Overridden / main-module replacements.
	if !d.work && workPaths[r.Old.Path] {
		e.Effect = "overridden"
		finding(report.Info, "replace-overridden", fmt.Sprintf("replace %s is overridden by go.work", e.Old),
			"go.work replaces the same module path; replacements in workspace modules' go.mod files for that path are ignored.", "")
		return e, fs, nil
	}
	if g.IsMain(r.Old.Path) {
		if d.work && r.Old.Version == "" {
			e.Effect = "error"
			e.Error = "workspace module is replaced at all versions"
			finding(report.High, "replace-workspace-module", fmt.Sprintf("go.work replaces workspace module %s at all versions", r.Old.Path),
				"The go command refuses this: \"workspace module "+r.Old.Path+" is replaced at all versions in the go.work file\".",
				"remove the replacement from go.work or specify the version to replace")
			return e, fs, nil
		}
		// Other versions of a main module path can be in the graph (cycles).
	}

	// Which graph nodes does this directive apply to?
	var applies []module.Version
	for _, n := range nodes {
		if n.Path != r.Old.Path || n.Version == "" {
			continue
		}
		if r.Old.Version != "" && n.Version != r.Old.Version {
			continue
		}
		if used, _ := g.FindReplace(n); used == r {
			applies = append(applies, n)
		}
	}
	for _, n := range applies {
		e.AppliesTo = append(e.AppliesTo, n.Version)
	}
	selectedHit := false
	for _, n := range applies {
		if g.IsSelected(n) {
			selectedHit = true
		}
		if err, bad := g.Errors[n]; bad {
			e.Effect = "error"
			e.Error = err.Error()
		}
	}
	switch {
	case e.Effect == "error":
	case selectedHit:
		e.Effect = "build"
	case len(applies) > 0:
		e.Effect = "graph"
	default:
		e.Effect = "none"
	}

	// Local directories: checked when the go command reads them.
	if e.Kind == "local" {
		dir := r.New.Path
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(d.base, dir)
		}
		li := &localInfo{Dir: relTo(p.Dir, dir)}
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			li.Exists = true
			if data, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
				li.HasGoMod = true
				li.ModulePath = modfile.ModulePath(data)
			}
		}
		e.Local = li
		switch {
		case e.Effect != "build" && e.Effect != "error":
		case !li.Exists:
			finding(report.High, "replace-missing-dir", fmt.Sprintf("replacement directory %s does not exist", r.New.Path),
				fmt.Sprintf("%s is replaced by %s, which is not a directory: the go command fails (\"replacement directory %s does not exist\").", e.Old, r.New.Path, r.New.Path),
				"fix or remove the replace directive")
			e.Effect = "error"
			return e, fs, nil
		case !li.HasGoMod:
			finding(report.High, "replace-no-gomod", fmt.Sprintf("replacement directory %s has no go.mod", r.New.Path),
				fmt.Sprintf("The go command requires a go.mod in a replacement directory; with %s replaced by %s, loading the module graph fails (\"reading %s/go.mod: no such file or directory\").", e.Old, r.New.Path, r.New.Path),
				"add a go.mod declaring "+r.Old.Path+" to "+r.New.Path)
			e.Effect = "error"
			return e, fs, nil
		case li.ModulePath != r.Old.Path:
			finding(report.High, "replace-path-mismatch", fmt.Sprintf("%s declares module %s, not %s", r.New.Path, orNone([]string{li.ModulePath}), r.Old.Path),
				fmt.Sprintf("The go command rejects the replacement when packages are built (\"module declares its path as: %s but was required as: %s\").", li.ModulePath, r.Old.Path),
				"make the module directive in "+r.New.Path+"/go.mod match "+r.Old.Path)
			e.Effect = "error"
			return e, fs, nil
		}
	}
	if e.Effect == "error" {
		finding(report.High, "replace-unavailable", fmt.Sprintf("replacement %s cannot be loaded", e.New), e.Error, "fix the replacement version or path")
		return e, fs, nil
	}
	if e.Effect == "none" {
		why := r.Old.Path + " is not in the module graph"
		if inGraph && r.Old.Version != "" {
			why = fmt.Sprintf("%s@%s is not in the module graph (selected %s)", r.Old.Path, r.Old.Version, sel)
		}
		if g.IsMain(r.Old.Path) {
			why = r.Old.Path + " is the main module; the go command ignores replacements of it"
		}
		finding(report.Low, "replace-no-effect", fmt.Sprintf("replace %s has no effect", e.Old),
			why+". 'go mod tidy' does not remove unused replace directives.", "remove the replace directive")
		return e, fs, nil
	}
	if e.Effect == "graph" {
		finding(report.Info, "replace-graph-only", fmt.Sprintf("replace %s only affects non-selected versions", e.Old),
			fmt.Sprintf("It applies to %s@%s, which is in the module graph but not selected (%s is): only the go.mod read for MVS changes, not the code that is built.", r.Old.Path, strings.Join(e.AppliesTo, ", @"), sel),
			fmt.Sprintf("replace the selected version (%s) or remove the directive", sel))
	}

	switch e.Kind {
	case "local":
		sev := report.Medium
		detail := fmt.Sprintf("%s@%s is built from the directory %s. That code is not in the module zip: consumers of your module ignore the replace and build %s@%s from the proxy instead, the build is not reproducible from version control of this module alone, and 'go install pkg@version' fails.", r.Old.Path, sel, li(e).Dir, r.Old.Path, sel)
		if d.work {
			sev = report.Info
			detail = fmt.Sprintf("go.work builds %s from %s. Workspace replacements only affect local development.", r.Old.Path, li(e).Dir)
		}
		if e.Effect == "build" {
			finding(sev, "replace-local", fmt.Sprintf("local replace %s => %s", e.Old, r.New.Path), detail,
				"publish the change and require a real version, or keep local development in a git-ignored go.work")
		}
	case "fork":
		if !*replaceFlags.noForks {
			fi, err := forkStaleness(c, r, sel)
			if err != nil {
				return e, fs, err
			}
			e.Fork = fi
			sev, title, detail := forkFinding(r, fi, sel)
			finding(sev, "replace-fork", title, detail, forkFix(fi))
		} else {
			finding(report.Info, "replace-fork", fmt.Sprintf("%s is replaced by fork %s", r.Old.Path, e.New),
				fmt.Sprintf("%s@%s is built from %s.", r.Old.Path, sel, e.New), "")
		}
	case "version":
		if e.Effect == "build" {
			if semver.Compare(r.New.Version, sel) < 0 {
				finding(report.Low, "replace-downgrade", fmt.Sprintf("%s@%s is built from the older %s", r.Old.Path, sel, r.New.Version),
					fmt.Sprintf("MVS selected %s because some module requires it, but the replace makes the build use %s. Modules needing %s's API or fixes may break; 'go list -m' still reports %s.", sel, r.New.Version, sel, sel),
					"remove the replace or pin with a requirement instead")
			} else if r.New.Version != sel {
				finding(report.Info, "replace-version", fmt.Sprintf("%s@%s is built from %s", r.Old.Path, sel, r.New.Version),
					"A same-path replacement changes the code without changing the selected version; a plain require of "+r.New.Version+" would express the same intent.",
					"go get "+r.Old.Path+"@"+r.New.Version+" and drop the replace")
			} else {
				finding(report.Low, "replace-no-effect", fmt.Sprintf("replace %s => %s replaces a version with itself", e.Old, e.New),
					"The replacement is the selected version itself.", "remove the replace directive")
			}
		}
	}
	return e, fs, nil
}

func li(e replaceEntry) *localInfo {
	if e.Local == nil {
		return &localInfo{}
	}
	return e.Local
}

// forkStaleness compares a fork's version date with upstream releases.
func forkStaleness(c *cli.Context, r *modfile.Replace, sel string) (*forkInfo, error) {
	fi := &forkInfo{Upstream: r.Old.Path, MissingReleases: []string{}}
	ctx := c.Ctx
	if info, err := c.Proxy().Info(ctx, r.New.Path, r.New.Version); err == nil {
		fi.ForkTime = info.Time
	} else if !errors.Is(err, modproxy.ErrNotFound) {
		return nil, err
	}
	vs, err := c.Proxy().Versions(ctx, r.Old.Path)
	if err != nil && !errors.Is(err, modproxy.ErrNotFound) {
		return nil, err
	}
	fi.UpstreamFound = len(vs) > 0
	ref := sel
	if ref == "" {
		ref = r.Old.Version
	}
	var cands []string
	for _, v := range vs {
		if semver.Prerelease(v) != "" {
			continue
		}
		if ref != "" && (semver.Major(v) != semver.Major(ref) || semver.Compare(v, ref) <= 0) {
			continue
		}
		cands = append(cands, v)
	}
	semver.Sort(cands)
	if len(cands) > 25 {
		cands = cands[len(cands)-25:]
	}
	for _, v := range cands {
		info, err := c.Proxy().Info(ctx, r.Old.Path, v)
		if err != nil {
			if errors.Is(err, modproxy.ErrNotFound) {
				continue
			}
			return nil, err
		}
		if !fi.ForkTime.IsZero() && !info.Time.After(fi.ForkTime) {
			continue
		}
		fi.MissingReleases = append(fi.MissingReleases, v)
		fi.UpstreamLatest, fi.UpstreamLatestTime = v, info.Time
	}
	if fi.UpstreamLatest != "" && !fi.ForkTime.IsZero() {
		fi.BehindDays = int(fi.UpstreamLatestTime.Sub(fi.ForkTime).Hours() / 24)
	}
	// Only github.com/... fork paths are looked up: the GitHub API is then
	// the fork's own host, so this is allowed for private forks too.
	if owner, repo, _, ok := feeds.SplitGitHub(r.New.Path); ok && c.GitHubAPIAllowed(r.New.Path) {
		gi := &githubInfo{Repo: owner + "/" + repo}
		rp, err := c.GitHub().Repo(ctx, owner, repo)
		switch {
		case err == nil:
			gi.Found, gi.Archived, gi.Fork, gi.PushedAt = true, rp.Archived, rp.Fork, rp.PushedAt
			if rp.Parent != nil {
				gi.Parent = rp.Parent.FullName
			}
			fi.GitHub = gi
		case httpx.IsNotFound(err):
			fi.GitHub = gi
		default:
			c.Warnf("GitHub lookup of %s/%s failed: %v", owner, repo, err)
		}
	}
	return fi, nil
}

func forkFinding(r *modfile.Replace, fi *forkInfo, sel string) (report.Severity, string, string) {
	fork := replaceString(r.New)
	var detail strings.Builder
	fmt.Fprintf(&detail, "%s@%s is built from the fork %s", r.Old.Path, sel, fork)
	if !fi.ForkTime.IsZero() {
		fmt.Fprintf(&detail, " (published %s)", fi.ForkTime.Format("2006-01-02"))
	}
	detail.WriteString(".")
	sev := report.Info
	title := fmt.Sprintf("%s is replaced by fork %s", r.Old.Path, fork)
	switch {
	case !fi.UpstreamFound:
		detail.WriteString(" The upstream module has no releases on the proxy, so staleness cannot be measured.")
	case len(fi.MissingReleases) > 0:
		sev = report.Low
		title = fmt.Sprintf("fork %s is behind upstream %s by %s", fork, r.Old.Path, plural(len(fi.MissingReleases), "release", "releases"))
		fmt.Fprintf(&detail, " Upstream released %s after the fork version", strings.Join(fi.MissingReleases, ", "))
		if fi.BehindDays > 0 {
			fmt.Fprintf(&detail, "; the newest (%s, %s) is %d days newer", fi.UpstreamLatest, fi.UpstreamLatestTime.Format("2006-01-02"), fi.BehindDays)
		}
		detail.WriteString(": fixes, including security fixes, made upstream since then are missing.")
		if fi.BehindDays >= *replaceFlags.staleDay {
			sev = report.Medium
		}
	default:
		detail.WriteString(" No newer upstream release exists.")
	}
	if gh := fi.GitHub; gh != nil {
		switch {
		case !gh.Found:
			fmt.Fprintf(&detail, " The fork repository %s was not found on GitHub.", gh.Repo)
		case gh.Archived:
			fmt.Fprintf(&detail, " The fork repository %s is archived.", gh.Repo)
			if sev < report.Medium {
				sev = report.Medium
			}
		default:
			if gh.Parent != "" {
				fmt.Fprintf(&detail, " GitHub: fork of %s", gh.Parent)
			} else {
				fmt.Fprintf(&detail, " GitHub: %s", gh.Repo)
			}
			if !gh.PushedAt.IsZero() {
				fmt.Fprintf(&detail, ", last push %s", gh.PushedAt.Format("2006-01-02"))
			}
			detail.WriteString(".")
		}
	}
	return sev, title, detail.String()
}

func forkFix(fi *forkInfo) string {
	if len(fi.MissingReleases) == 0 {
		return ""
	}
	return fmt.Sprintf("rebase the fork on %s@%s, or drop the replace if upstream now contains the change", fi.Upstream, fi.UpstreamLatest)
}

// mainPackages returns the import-path-relative directories of the main
// module that contain a non-test "package main".
func mainPackages(root string) []string {
	var out []string
	fset := token.NewFileSet()
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if path != root {
				if name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
					return filepath.SkipDir
				}
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.PackageClauseOnly)
		if err == nil && f.Name.Name == "main" {
			rel, _ := filepath.Rel(root, filepath.Dir(path))
			out = append(out, "./"+filepath.ToSlash(rel))
		}
		return nil
	})
	out = uniqSorted(out)
	for i, s := range out {
		if s == "./." {
			out[i] = "."
		}
	}
	return out
}

func printReplace(c *cli.Context, r replaceResult) {
	o := c.Out
	o.Title("Replace & exclude audit")
	if len(r.Replaces) > 0 {
		o.Heading(fmt.Sprintf("Replace directives (%d)", len(r.Replaces)))
		var rows [][]string
		for _, e := range r.Replaces {
			eff := e.Effect
			switch e.Effect {
			case "build":
				eff = o.Green(eff)
			case "none":
				eff = o.Yellow(eff)
			case "error":
				eff = o.Red(eff)
			}
			rows = append(rows, []string{fmt.Sprintf("%s:%d", e.File, e.Line), e.Old + " => " + e.New, e.Kind, eff, e.Selected})
		}
		o.Table([]string{"WHERE", "DIRECTIVE", "KIND", "EFFECT", "SELECTED"}, rows)
	}
	if len(r.Excludes) > 0 {
		o.Heading(fmt.Sprintf("Exclude directives (%d)", len(r.Excludes)))
		var rows [][]string
		for _, e := range r.Excludes {
			rows = append(rows, []string{fmt.Sprintf("%s:%d", e.File, e.Line), e.Module + " " + e.Version, e.Effect, ui3(e.RequiredBy)})
		}
		o.Table([]string{"WHERE", "DIRECTIVE", "EFFECT", "REQUIRED BY"}, rows)
	}
	if len(r.Ignored) > 0 {
		o.Heading(fmt.Sprintf("Ignored directives in dependencies (%d)", len(r.Ignored)))
		var rows [][]string
		for _, e := range r.Ignored {
			m := ""
			if e.Matters {
				m = o.Yellow("affects your build")
			}
			rows = append(rows, []string{e.In, e.Directive + " " + e.Text, m})
		}
		o.Table([]string{"IN", "DIRECTIVE", ""}, rows)
	}
	if len(r.Replaces)+len(r.Excludes)+len(r.Ignored) == 0 {
		o.Println()
		o.OK("no replace or exclude directives")
		return
	}
	if len(r.Findings) > 0 {
		o.Heading("Findings")
		printFindings(c, r.Findings)
	}
	printSummaryLine(c, r.Findings, r.Summary)
}
