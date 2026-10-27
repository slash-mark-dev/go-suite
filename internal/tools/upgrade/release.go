package upgrade

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/apidiff"
	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/modproxy"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/project"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/semver"
)

var releaseFlags struct {
	version *string
	base    *string
	noGit   *bool
	failOn  func() (report.Severity, error)
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "release",
		Group:   group,
		Summary: "Release checker: next semantic version from the API diff, path rules, retractions, git tag",
		Usage:   "sm-go release [--version vX.Y.Z] [--base vX.Y.Z] [flags]",
		Help: `Checks that the main module is ready to be released and computes the next
version. The working tree is type-checked and its API compared with the
latest published version (from GOPROXY; --base picks another one):
incompatible changes require a new major version (a new minor for v0),
additions a minor release, anything else a patch release.

It enforces the module path rules of the go command: v2+ releases need a
/vN path suffix (gopkg.in paths a .vN suffix), malformed suffixes such as
/v1, published +incompatible versions, and that a proposed --version
matches the path, is new and is a large enough bump. It checks go.mod
hygiene: retractions that the new release would silently drop (the latest
release's go.mod is what the go command reads), retractions without a
rationale or of versions that were never published, and replace directives
that consumers ignore.

In a git repository it checks for uncommitted changes and whether the tag
already exists (with the module's subdirectory prefix, and the major
subdirectory layout), and prints the exact git tag command.

Exit code 1 when a finding reaches --fail-on (default medium).`,
		Examples: []string{
			"sm-go release",
			"sm-go release --version v1.5.0",
			"sm-go release --base v1.3.0 --json",
		},
		Sources: []string{"Go module proxy", "checksum database (via the go command)", "git"},
		NeedsGo: true,
		Flags: func(fs *flag.FlagSet) {
			releaseFlags.version = fs.String("version", "", "check this proposed release `version` instead of the suggested one")
			releaseFlags.base = fs.String("base", "", "compare with this published `version` (default: the latest release)")
			releaseFlags.noGit = fs.Bool("no-git", false, "skip the git checks")
			releaseFlags.failOn = cli.SeverityFlag(fs, "fail-on", "medium", "exit 1 on findings at or above this `severity`")
		},
		Run: runRelease,
	})
}

// GitInfo is what release learned from git.
type GitInfo struct {
	Root      string   `json:"root"`
	Prefix    string   `json:"prefix,omitempty"` // tag prefix (module subdirectory)
	Head      string   `json:"head,omitempty"`
	Dirty     []string `json:"dirty"`
	TagExists bool     `json:"tagExists"`
}

// ReleaseResult is the JSON result of release.
type ReleaseResult struct {
	Module        string                  `json:"module"`
	PathMajor     string                  `json:"pathMajor,omitempty"`
	Published     []string                `json:"published"`
	Base          string                  `json:"base,omitempty"`
	RequiredBump  string                  `json:"requiredBump"` // major, minor, patch, initial
	Suggested     string                  `json:"suggested"`
	SuggestedPath string                  `json:"suggestedPath,omitempty"` // when the module path must change
	Version       string                  `json:"version"`                 // version checked (--version or suggested)
	Tag           string                  `json:"tag,omitempty"`
	Commands      []string                `json:"commands,omitempty"`
	Incompatible  int                     `json:"incompatible"`
	Compatible    int                     `json:"compatible"`
	Packages      []apidiff.PackageReport `json:"packages"`
	Git           *GitInfo                `json:"git,omitempty"`
	Findings      []report.Finding        `json:"findings"`
	Ready         bool                    `json:"ready"`
}

func runRelease(c *cli.Context) error {
	if len(c.Args) > 0 {
		return cli.Usagef("release takes no arguments (run it in the module directory or pass -C)")
	}
	failOn, err := releaseFlags.failOn()
	if err != nil {
		return err
	}
	proposed := *releaseFlags.version
	if proposed != "" && (!semver.IsValid(proposed) || semver.Canonical(proposed) != strings.TrimSuffix(proposed, "+incompatible")) {
		return cli.Usagef("--version %q is not a canonical semantic version (vMAJOR.MINOR.PATCH)", proposed)
	}
	p, err := c.Project()
	if err != nil {
		if errors.Is(err, project.ErrNoModule) {
			return cli.Usagef("%v", err)
		}
		return err
	}
	modPath := p.ModulePath()
	if modPath == "" {
		return cli.Usagef("%s has no module directive", p.Rel(p.GoModPath))
	}
	res := &ReleaseResult{Module: modPath, Published: []string{}, Findings: []report.Finding{}, Packages: []apidiff.PackageReport{}}
	gomodRel := p.Rel(p.GoModPath)
	add := func(sev report.Severity, rule, title, fix string, line int) {
		f := report.Finding{Severity: sev, Rule: rule, Module: modPath, Title: title, Fix: fix}
		if line > 0 {
			f.File, f.Line = gomodRel, line
		}
		res.Findings = append(res.Findings, f)
	}

	// Module path rules.
	pathOK := true
	if err := module.CheckPath(modPath); err != nil {
		add(report.High, "invalid-module-path", fmt.Sprintf("invalid module path: %v", err), "", p.GoMod.Module.Line)
		pathOK = false
	}
	_, pathMajor, ok := module.SplitPathVersion(modPath)
	if !ok {
		fix := "use the path without a suffix for v0/v1, or /v2 and above"
		if strings.HasPrefix(modPath, "gopkg.in/") {
			fix = "gopkg.in paths must end in .vN (gopkg.in/name.v1)"
		}
		add(report.High, "bad-major-suffix", fmt.Sprintf("module path %s has an invalid major version suffix", modPath), fix, p.GoMod.Module.Line)
		pathOK = false
	}
	res.PathMajor = pathMajor
	for _, e := range p.GoMod.Errors {
		add(report.High, "gomod-error", e.Error(), "", 0)
	}
	if p.GoMod.Go == "" {
		add(report.Low, "no-go-directive", "go.mod has no go directive (consumers assume go 1.16)", "go mod tidy", 0)
	}

	// Published versions.
	if pathOK {
		vs, err := c.Proxy().Versions(c.Ctx, modPath)
		if err != nil && !errors.Is(err, modproxy.ErrNotFound) {
			return err
		}
		res.Published = append(res.Published, vs...)
	}
	base := *releaseFlags.base
	if base != "" {
		if !contains(res.Published, base) {
			if _, err := c.Proxy().Info(c.Ctx, modPath, base); err != nil {
				if errors.Is(err, modproxy.ErrNotFound) {
					return cli.Usagef("--base %s: %s@%s is not published", base, modPath, base)
				}
				return err
			}
		}
	} else {
		base = latestRelease(res.Published)
	}
	res.Base = base

	// API diff.
	var rep apidiff.Report
	if base != "" {
		baseAPI, err := loadAPI(c, modPath, base)
		if err != nil {
			return err
		}
		localAPI, err := loadLocalAPI(c, p.ModDir)
		if err != nil {
			return err
		}
		rep = apidiff.CompareModules(baseAPI, localAPI, nil).Normalize()
		res.Incompatible, res.Compatible = len(rep.Incompatible), len(rep.Compatible)
		if bp := rep.ByPackage(); bp != nil {
			res.Packages = bp
		}
		res.RequiredBump = rep.Bump()
	} else {
		res.RequiredBump = "initial"
	}

	// Next version.
	res.Suggested, res.SuggestedPath = nextVersion(modPath, pathMajor, base, res.RequiredBump)
	if res.SuggestedPath != "" {
		add(report.High, "breaking-change-needs-major", fmt.Sprintf("%d incompatible API %s since %s: the next release must be the new major version %s",
			res.Incompatible, pluralWord(res.Incompatible, "change", "changes"), base, res.Suggested),
			fmt.Sprintf("change the module path to %s (and its own imports), or restore compatibility", res.SuggestedPath), p.GoMod.Module.Line)
	}
	if semver.Build(base) == "+incompatible" && pathMajor == "" {
		add(report.High, "incompatible-versions", fmt.Sprintf("%s was published as %s without a go.mod; a go.mod release of %s or later needs the module path %s",
			modPath, base, semver.Major(base), module.WithMajor(modPath, semver.Major(base))),
			"set the module path to "+module.WithMajor(modPath, semver.Major(base)), p.GoMod.Module.Line)
	}
	res.Version = res.Suggested
	if proposed != "" {
		res.Version = proposed
		checkProposed(res, proposed, base, pathMajor, add)
	}
	if pathOK && res.SuggestedPath == "" {
		if err := module.CheckPathMajor(res.Version, pathMajor); err != nil {
			add(report.High, "version-path-mismatch", fmt.Sprintf("%s cannot be released at %s: %v", modPath, res.Version, err),
				"v2 and later need a /vN suffix in the module path", p.GoMod.Module.Line)
		}
	}

	// go.mod hygiene.
	checkRetractions(c, p, res, add)
	for _, r := range p.GoMod.Replace {
		if r.IsLocal() {
			add(report.Medium, "local-replace", fmt.Sprintf("replace %s => %s points to a directory; consumers ignore it and build with %s", r.Old.Path, r.New.Path, r.Old.Path),
				"make sure the release builds without the replacement", r.Line)
		} else {
			add(report.Low, "replace-ignored", fmt.Sprintf("replace %s => %s is ignored by consumers of the module", r.Old.Path, r.New), "", r.Line)
		}
	}

	// git.
	if !*releaseFlags.noGit {
		releaseGit(c, p, res, pathMajor, add)
	}
	if res.Tag == "" {
		res.Tag = res.Version
	}
	res.Commands = []string{"git tag " + res.Tag, "git push origin " + res.Tag}
	if res.Git != nil && res.Git.Root != "" && res.Git.Root != p.ModDir {
		res.Commands[0] = "git -C " + res.Git.Root + " tag " + res.Tag
		res.Commands[1] = "git -C " + res.Git.Root + " push origin " + res.Tag
	}
	report.SortFindings(res.Findings)
	res.Ready = len(report.AtLeast(res.Findings, failOn)) == 0
	c.SetResult(res)
	if !res.Ready {
		c.Issues()
	}
	if c.Text() {
		printRelease(c, res, rep)
	}
	return nil
}

func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// latestRelease returns the highest release (or, if there is none, the
// highest prerelease) of vs.
func latestRelease(vs []string) string {
	best := ""
	for _, pre := range []bool{false, true} {
		for _, v := range vs {
			if (semver.Prerelease(v) != "") != pre {
				continue
			}
			if best == "" || semver.Compare(v, best) > 0 {
				best = v
			}
		}
		if best != "" {
			return best
		}
	}
	return ""
}

func parts(v string) (major, minor, patch int) {
	core := strings.TrimPrefix(semver.Canonical(v), "v")
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	f := strings.Split(core, ".")
	if len(f) == 3 {
		major, _ = strconv.Atoi(f[0])
		minor, _ = strconv.Atoi(f[1])
		patch, _ = strconv.Atoi(f[2])
	}
	return
}

// nextVersion returns the version the next release should have and, when
// the bump needs a new major version of a v1+ module, the new module path.
func nextVersion(modPath, pathMajor, base, bump string) (version, newPath string) {
	if base == "" {
		if m := module.PathMajorPrefix(pathMajor); m != "" && m != "v0" && m != "v1" {
			return m + ".0.0", ""
		}
		return "v0.1.0", ""
	}
	maj, min, pat := parts(base)
	pre := semver.Prerelease(base) != ""
	core := fmt.Sprintf("v%d.%d.%d", maj, min, pat)
	switch bump {
	case "major":
		if maj == 0 {
			return fmt.Sprintf("v0.%d.0", min+1), ""
		}
		nm := fmt.Sprintf("v%d", maj+1)
		return nm + ".0.0", module.WithMajor(modPath, nm)
	case "minor":
		if pre && pat == 0 {
			return core, ""
		}
		return fmt.Sprintf("v%d.%d.0", maj, min+1), ""
	default:
		if pre {
			return core, ""
		}
		return fmt.Sprintf("v%d.%d.%d", maj, min, pat+1), ""
	}
}

func checkProposed(res *ReleaseResult, v, base, pathMajor string, add func(report.Severity, string, string, string, int)) {
	if contains(res.Published, v) {
		add(report.High, "already-published", v+" is already published; module versions are immutable", "pick "+res.Suggested, 0)
		return
	}
	if base == "" {
		return
	}
	if semver.Compare(v, base) <= 0 {
		add(report.High, "not-newer", fmt.Sprintf("%s is not newer than the latest release %s", v, base), "pick "+res.Suggested, 0)
		return
	}
	if semver.Prerelease(v) != "" {
		return
	}
	bump := semverBump(base, v)
	switch {
	case res.RequiredBump == "major" && semver.Major(base) != "v0" && bump != "major":
		add(report.High, "breaking-in-compatible-release", fmt.Sprintf("%s is a %s release but the API has %s", v, bump,
			plural(res.Incompatible, "incompatible change", "incompatible changes")), "release "+res.Suggested+" at "+res.SuggestedPath, 0)
	case res.RequiredBump == "major" && semver.Major(base) == "v0" && bump == "patch":
		add(report.Medium, "breaking-in-patch", fmt.Sprintf("%s is a patch release but the API has incompatible changes", v), "release "+res.Suggested, 0)
	case res.RequiredBump == "minor" && bump == "patch":
		add(report.Medium, "additions-in-patch", fmt.Sprintf("%s is a patch release but the API has %s", v,
			plural(res.Compatible, "addition", "additions")), "release "+res.Suggested, 0)
	}
}

// checkRetractions checks the retract directives of the working go.mod
// against the published versions and the retractions already in effect
// (those in the go.mod of the latest published version).
func checkRetractions(c *cli.Context, p *project.Project, res *ReleaseResult, add func(report.Severity, string, string, string, int)) {
	for _, r := range p.GoMod.Retract {
		what := r.Low
		if r.High != r.Low {
			what = "[" + r.Low + ", " + r.High + "]"
		}
		if r.Rationale == "" {
			add(report.Low, "retract-no-rationale", "retract "+what+" has no rationale comment (shown to users by go list -m -retracted)",
				"add a comment explaining why", r.Line)
		}
		if r.Low == r.High && r.Low != res.Version && !contains(res.Published, r.Low) {
			add(report.Medium, "retract-unpublished", "retract "+what+" names a version that was never published", "check the version", r.Line)
		}
		if r.Contains(res.Version) && r.Low != r.High {
			add(report.Info, "release-retracted", res.Version+" is inside the retracted range "+what+": it can only be a retraction release", "", r.Line)
		}
	}
	if len(res.Published) == 0 {
		return
	}
	meta, err := c.Proxy().Meta(c.Ctx, res.Module)
	if err != nil || meta == nil {
		if err != nil {
			c.Warnf("reading published retractions: %v", err)
		}
		return
	}
	if semver.Compare(res.Version, meta.Latest) < 0 {
		return // the release will not become the latest version
	}
	for _, old := range meta.Retract {
		covered := false
		for _, r := range p.GoMod.Retract {
			if semver.Compare(r.Low, old.Low) <= 0 && semver.Compare(old.High, r.High) <= 0 {
				covered = true
				break
			}
		}
		if !covered {
			what := old.Low
			if old.High != old.Low {
				what = "[" + old.Low + ", " + old.High + "]"
			}
			add(report.High, "retraction-dropped", fmt.Sprintf("%s@%s retracts %s but go.mod does not: releasing would un-retract it", res.Module, meta.Latest, what),
				fmt.Sprintf("add: retract %s // %s", what, old.Rationale), 0)
		}
	}
}

func git(c *cli.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(c.Ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append(c.Env.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", errors.New(msg)
	}
	return strings.TrimRight(out.String(), "\n"), nil
}

func releaseGit(c *cli.Context, p *project.Project, res *ReleaseResult, pathMajor string, add func(report.Severity, string, string, string, int)) {
	if _, err := exec.LookPath("git"); err != nil {
		return
	}
	root, err := git(c, p.ModDir, "rev-parse", "--show-toplevel")
	if err != nil {
		return // not a git repository
	}
	gi := &GitInfo{Root: root, Dirty: []string{}}
	res.Git = gi
	moddir, _ := filepath.EvalSymlinks(p.ModDir)
	rootReal, _ := filepath.EvalSymlinks(root)
	rel, err := filepath.Rel(rootReal, moddir)
	if err != nil || strings.HasPrefix(rel, "..") {
		rel = "."
	}
	rel = filepath.ToSlash(rel)
	if rel == "." {
		rel = ""
	}
	// Major subdirectory layout: example.com/m/v2 in directory v2/ is
	// tagged v2.x.y, not v2/v2.x.y.
	if m := module.PathMajorPrefix(pathMajor); m != "" && strings.HasPrefix(pathMajor, "/") && path.Base(rel) == m {
		rel = strings.TrimSuffix(strings.TrimSuffix(rel, m), "/")
	}
	gi.Prefix = rel
	res.Tag = res.Version
	if rel != "" {
		res.Tag = rel + "/" + res.Version
	}
	if head, err := git(c, p.ModDir, "rev-parse", "HEAD"); err == nil {
		gi.Head = head
	} else {
		add(report.Medium, "no-commits", "the git repository has no commits", "commit the module before tagging", 0)
	}
	if st, err := git(c, p.ModDir, "status", "--porcelain", "--", "."); err == nil && st != "" {
		for _, line := range strings.Split(st, "\n") {
			if len(line) > 3 {
				gi.Dirty = append(gi.Dirty, strings.TrimSpace(line[3:]))
			}
		}
		add(report.Medium, "uncommitted-changes", fmt.Sprintf("%s in the module directory (the tag would not include them)",
			plural(len(gi.Dirty), "uncommitted change", "uncommitted changes")), "commit or stash them", 0)
	}
	if _, err := git(c, p.ModDir, "rev-parse", "-q", "--verify", "refs/tags/"+res.Tag); err == nil {
		gi.TagExists = true
		add(report.High, "tag-exists", "git tag "+res.Tag+" already exists", "pick another version", 0)
	}
}

func printRelease(c *cli.Context, res *ReleaseResult, rep apidiff.Report) {
	out := c.Out
	out.Title("Release check: " + res.Module)
	base := res.Base
	if base == "" {
		base = "(never released)"
	}
	kv := [][2]string{{"latest release", base}, {"published", plural(len(res.Published), "version", "versions")}}
	if res.Base != "" {
		kv = append(kv, [2]string{"API changes", fmt.Sprintf("%d incompatible, %d compatible", res.Incompatible, res.Compatible)})
	}
	kv = append(kv, [2]string{"required bump", res.RequiredBump}, [2]string{"next version", res.Suggested})
	if res.SuggestedPath != "" {
		kv = append(kv, [2]string{"new module path", res.SuggestedPath})
	}
	if res.Version != res.Suggested {
		kv = append(kv, [2]string{"proposed", res.Version})
	}
	if res.Git != nil {
		head := res.Git.Head
		if len(head) > 12 {
			head = head[:12]
		}
		kv = append(kv, [2]string{"git HEAD", head})
	}
	out.KV(kv...)
	if res.Base != "" {
		printChanges(c, rep, true, nil)
	}
	if len(res.Findings) > 0 {
		out.Heading("Findings")
		for _, f := range res.Findings {
			where := ""
			if f.File != "" {
				where = out.Dim(" (" + f.Where() + ")")
			}
			out.Printf("  %s %s%s\n", out.Sev(f.Severity), f.Title, where)
			if f.Fix != "" {
				out.Printf("           %s %s\n", out.Dim("fix:"), f.Fix)
			}
		}
	}
	out.Println()
	if res.Ready {
		out.OK("ready to release %s", res.Version)
		out.Println()
		for _, cmd := range res.Commands {
			out.Printf("  %s\n", cmd)
		}
		return
	}
	out.Bad("not ready to release %s", res.Version)
}
