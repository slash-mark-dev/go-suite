package security

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/feeds"
	"github.com/slash-mark-dev/go-suite/internal/httpx"
	"github.com/slash-mark-dev/go-suite/internal/modfile"
	"github.com/slash-mark-dev/go-suite/internal/modproxy"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/modzip"
	"github.com/slash-mark-dev/go-suite/internal/par"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/semver"
	"github.com/slash-mark-dev/go-suite/internal/sumdb"
	"github.com/slash-mark-dev/go-suite/internal/ui"
)

// Tag check statuses.
const (
	TagOK            = "ok"
	TagMoved         = "moved"          // the tag now points at another commit / other content
	TagDeleted       = "deleted"        // the tag no longer exists
	TagCommitMissing = "commit-missing" // the pseudo-version's commit is gone
	TagUnverified    = "unverified"     // could not be checked (GitHub unreachable, rate limit, ...)
	TagSkipped       = "skipped"        // not hosted on GitHub, or a directory replacement
)

// TagCheck is the result for one module version.
type TagCheck struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	// ReplacementOf is set when the checked module replaces another.
	ReplacementOf string `json:"replacementOf,omitempty"`
	Repo          string `json:"repo,omitempty"` // "owner/name"
	Subdir        string `json:"subdir,omitempty"`
	Tag           string `json:"tag,omitempty"`
	// RecordedCommit is the commit the proxy recorded (.info Origin.Hash),
	// or the pseudo-version's revision.
	RecordedCommit string `json:"recordedCommit,omitempty"`
	// CurrentCommit is the commit the tag points at today.
	CurrentCommit string `json:"currentCommit,omitempty"`
	// Method is "origin" (commit comparison with the proxy's Origin
	// record), "content" (module zip rebuilt from the tag and hashed),
	// "commit" (pseudo-version commit existence) or "".
	Method string `json:"method,omitempty"`
	// ExpectedHash / CurrentHash are the h1 hashes compared by the
	// content method; HashSource says where ExpectedHash came from.
	ExpectedHash string          `json:"expectedHash,omitempty"`
	CurrentHash  string          `json:"currentHash,omitempty"`
	HashSource   string          `json:"hashSource,omitempty"`
	Status       string          `json:"status"`
	Severity     report.Severity `json:"severity"`
	Detail       string          `json:"detail,omitempty"`
}

// RetagResult is the result of the retag tool.
type RetagResult struct {
	Checks   []*TagCheck      `json:"checks"`
	Summary  map[string]int   `json:"summary"`
	Findings []report.Finding `json:"findings"`
	Failing  int              `json:"failing"`
}

var retagFlags struct {
	noContent, direct *bool
	failOn            func() (report.Severity, error)
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "retag",
		Group:   group,
		Summary: "Detect moved or deleted Git tags behind required versions",
		Usage:   "sm-go retag [module@version ...] [flags]",
		Help: `Module proxies and the checksum database pin the content of a version forever, but the Git
tag behind it can be moved or deleted afterwards — a sign of a compromised or careless
maintainer, and a trap for anyone building with GOPROXY=direct or GONOSUMDB.

For every version in the build list (or the module@version arguments) hosted on GitHub
(by path, or by the proxy's recorded origin for vanity paths), retag resolves the tag on
GitHub today and compares:

  origin   the commit the proxy recorded when it first fetched the version (.info Origin.Hash)
  content  when the proxy recorded no origin: the tag's current tree is downloaded, turned into
           a module zip with the go command's rules (subdirectory and major-version directory,
           nested modules and vendored packages excluded, root LICENSE added) and its h1 hash is
           compared with the checksum database (or go.sum, or the proxy's zip)
  commit   pseudo-versions: the commit must still exist

Moved tags are high severity; deleted tags and vanished commits are medium. Set GITHUB_TOKEN
for higher rate limits; without GitHub access versions are reported as unverified.`,
		Examples: []string{
			"sm-go retag",
			"sm-go retag --direct --json",
			"sm-go retag github.com/sirupsen/logrus@v1.9.3",
		},
		Sources: []string{"Go module proxy", "GitHub", "Go checksum database"},
		Flags: func(fs *flag.FlagSet) {
			retagFlags.noContent = fs.Bool("no-content", false, "do not download tag archives to compare content")
			retagFlags.direct = fs.Bool("direct", false, "check only direct requirements")
			retagFlags.failOn = cli.SeverityFlag(fs, "fail-on", "high", "minimum `severity` that fails the run")
		},
		Run: runRetag,
	})
}

type retagTarget struct {
	mod, orig module.Version
	local     bool
}

func runRetag(c *cli.Context) error {
	failOn, err := retagFlags.failOn()
	if err != nil {
		return err
	}
	var targets []retagTarget
	if len(c.Args) > 0 {
		for _, a := range c.Args {
			p, v, ok := strings.Cut(a, "@")
			if !ok || module.CheckPath(p) != nil || !semver.IsValid(v) {
				return cli.Usagef("argument %q: want module@version", a)
			}
			targets = append(targets, retagTarget{mod: module.Version{Path: p, Version: v}})
		}
	} else {
		g, err := c.Graph()
		if err != nil {
			return err
		}
		for _, m := range g.BuildList() {
			if *retagFlags.direct && !g.IsDirect(m.Path) {
				continue
			}
			t := retagTarget{mod: m}
			if r, ok := g.Replacement[m]; ok {
				if r.Version == "" {
					t.local = true
				} else {
					t.mod, t.orig = r, m
				}
			}
			targets = append(targets, t)
		}
	}
	gosum := map[string]string{}
	if p, err := c.Project(); err == nil && p.GoSum != nil {
		for _, l := range p.GoSum.Lines {
			if !l.IsGoMod() {
				gosum[l.Path+"@"+l.Version] = l.Hash
			}
		}
	}
	var sdb *sumdb.Client
	if cl, err := c.SumDB(); err == nil && !cl.Disabled && !insecureFlag(c.Env.Get("GOFLAGS")) {
		sdb = cl
	}
	rc := &retagChecker{c: c, gh: c.GitHub(), sdb: sdb, gosum: gosum, content: !*retagFlags.noContent}
	checks, _ := par.Map(c.Ctx, 4, targets, func(ctx context.Context, t retagTarget) (*TagCheck, error) {
		return rc.check(ctx, t), nil
	})
	res := &RetagResult{Checks: checks, Summary: map[string]int{}, Findings: []report.Finding{}}
	if res.Checks == nil {
		res.Checks = []*TagCheck{}
	}
	warned := 0
	for _, w := range rc.warnings() {
		if warned++; warned <= 3 {
			c.Warnf("%s", w)
		}
	}
	if warned > 3 {
		c.Warnf("… and %d more GitHub problems (set GITHUB_TOKEN for higher rate limits)", warned-3)
	}
	for _, ch := range res.Checks {
		res.Summary[ch.Status]++
		switch ch.Status {
		case TagMoved, TagDeleted, TagCommitMissing:
			title := map[string]string{
				TagMoved:         fmt.Sprintf("tag %s was moved after %s was published", ch.Tag, ch.Version),
				TagDeleted:       fmt.Sprintf("tag %s no longer exists", ch.Tag),
				TagCommitMissing: fmt.Sprintf("commit %s of %s no longer exists", ch.RecordedCommit, ch.Version),
			}[ch.Status]
			res.Findings = append(res.Findings, report.Finding{Severity: ch.Severity, Rule: "retag/" + ch.Status, Module: ch.Module, Version: ch.Version,
				Title: title, Detail: ch.Detail, URL: "https://github.com/" + ch.Repo,
				Fix: "keep building through the proxy and checksum database (never GOPROXY=direct/GONOSUMDB for this module) and ask the maintainers why the history changed"})
		}
	}
	report.SortFindings(res.Findings)
	for _, f := range res.Findings {
		if f.Severity.Meets(failOn) {
			res.Failing++
		}
	}
	c.SetResult(res)
	if res.Failing > 0 {
		c.Issues()
	}
	if c.Text() {
		printRetag(c, res)
	}
	return nil
}

type retagChecker struct {
	c       *cli.Context
	gh      *feeds.GitHub
	sdb     *sumdb.Client
	gosum   map[string]string
	content bool

	mu   sync.Mutex
	warn []string
}

func (rc *retagChecker) warnf(format string, a ...any) {
	rc.mu.Lock()
	rc.warn = append(rc.warn, fmt.Sprintf(format, a...))
	rc.mu.Unlock()
}

func (rc *retagChecker) warnings() []string {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	out := append([]string(nil), rc.warn...)
	sort.Strings(out)
	return out
}

// repoFor locates the GitHub repository, module subdirectory and tag of a
// module version.
func repoFor(m module.Version, info *modproxy.Info) (owner, repo, subdir, tag string, ok bool) {
	var o *modproxy.Origin
	if info != nil {
		o = info.Origin
	}
	if o != nil && o.URL != "" {
		owner, repo, _, ok = feeds.SplitGitHub(o.URL)
		subdir = o.Subdir
	}
	if !ok {
		prefix, _, _ := module.SplitPathVersion(m.Path)
		owner, repo, subdir, ok = feeds.SplitGitHub(prefix)
	}
	if !ok {
		return "", "", "", "", false
	}
	if module.IsPseudoVersion(m.Version) {
		return owner, repo, subdir, "", true
	}
	if o != nil && strings.HasPrefix(o.Ref, "refs/tags/") {
		return owner, repo, subdir, strings.TrimPrefix(o.Ref, "refs/tags/"), true
	}
	tag = strings.TrimSuffix(m.Version, "+incompatible")
	if subdir != "" {
		tag = subdir + "/" + tag
	}
	return owner, repo, subdir, tag, true
}

func (rc *retagChecker) check(ctx context.Context, t retagTarget) *TagCheck {
	m := t.mod
	ch := &TagCheck{Module: m.Path, Version: m.Version, Status: TagSkipped, Severity: report.None}
	if t.orig.Path != "" {
		ch.ReplacementOf = t.orig.Path
	}
	if t.local {
		ch.Detail = "replaced by a local directory"
		return ch
	}
	info, err := rc.c.Proxy().Info(ctx, m.Path, m.Version)
	if err != nil && !errors.Is(err, modproxy.ErrNotFound) {
		rc.warnf("%s: %v", m, err)
	}
	owner, repo, subdir, tag, ok := repoFor(m, info)
	if !ok {
		ch.Detail = "not hosted on GitHub"
		return ch
	}
	// A private module is checked against the GitHub API only when its
	// path is on github.com (the API is then its own host), never because
	// its origin happens to point at GitHub.
	if !rc.c.GitHubAPIAllowed(m.Path) {
		ch.Detail = feeds.ErrPrivate.Error()
		return ch
	}
	ch.Repo, ch.Subdir, ch.Tag = owner+"/"+repo, subdir, tag
	if info != nil && info.Origin != nil {
		ch.RecordedCommit = info.Origin.Hash
	}
	unverified := func(err error) *TagCheck {
		ch.Status, ch.Severity = TagUnverified, report.None
		ch.Detail = err.Error()
		rc.warnf("%s: GitHub: %v", m, err)
		return ch
	}

	if tag == "" {
		// Pseudo-version: the commit must still exist.
		rev := ch.RecordedCommit
		if rev == "" {
			rev, _ = module.PseudoVersionRev(m.Version)
			ch.RecordedCommit = rev
		}
		ch.Method = "commit"
		exists, err := rc.gh.CommitExists(ctx, owner, repo, rev)
		if err != nil {
			return unverified(err)
		}
		if exists {
			ch.Status = TagOK
		} else {
			ch.Status, ch.Severity = TagCommitMissing, report.Medium
			ch.Detail = fmt.Sprintf("commit %s is not in github.com/%s/%s any more: history was rewritten or the repository replaced", rev, owner, repo)
		}
		return ch
	}

	sha, err := rc.gh.TagCommit(ctx, owner, repo, tag)
	if httpx.IsNotFound(err) {
		ch.Status, ch.Severity = TagDeleted, report.Medium
		ch.Detail = fmt.Sprintf("github.com/%s/%s has no tag %s", owner, repo, tag)
		if _, rerr := rc.gh.Repo(ctx, owner, repo); httpx.IsNotFound(rerr) {
			ch.Detail = fmt.Sprintf("the repository github.com/%s/%s no longer exists (its name may be re-registered by anyone)", owner, repo)
		} else if ch.RecordedCommit != "" {
			if ok, cerr := rc.gh.CommitExists(ctx, owner, repo, ch.RecordedCommit); cerr == nil && !ok {
				ch.Detail += fmt.Sprintf("; the recorded commit %s is gone too", ch.RecordedCommit)
			}
		}
		return ch
	}
	if err != nil {
		return unverified(err)
	}
	ch.CurrentCommit = sha

	if ch.RecordedCommit != "" {
		ch.Method = "origin"
		if strings.EqualFold(sha, ch.RecordedCommit) {
			ch.Status = TagOK
		} else {
			ch.Status, ch.Severity = TagMoved, report.High
			ch.Detail = fmt.Sprintf("the proxy recorded commit %s for %s; tag %s now points at %s", ch.RecordedCommit, m.Version, tag, sha)
		}
		return ch
	}
	if !rc.content {
		ch.Status = TagUnverified
		ch.Detail = "no origin recorded by the proxy; content check disabled (--no-content)"
		return ch
	}
	ch.Method = "content"
	want, src, err := rc.expectedHash(ctx, m)
	if err != nil {
		ch.Status, ch.Detail = TagUnverified, "no reference hash: "+err.Error()
		rc.warnf("%s: %v", m, err)
		return ch
	}
	ch.ExpectedHash, ch.HashSource = want, src
	data, err := rc.c.HTTP().Get(ctx, fmt.Sprintf("%s/repos/%s/%s/zipball/%s", rc.gh.Base, owner, repo, sha), httpx.Immutable())
	if err != nil {
		return unverified(err)
	}
	got, err := HashRepoArchive(data.Body, m.Path, m.Version, subdir)
	if err != nil {
		ch.Status, ch.Detail = TagUnverified, err.Error()
		rc.warnf("%s: %v", m, err)
		return ch
	}
	ch.CurrentHash = got
	if got == want {
		ch.Status = TagOK
	} else {
		ch.Status, ch.Severity = TagMoved, report.High
		ch.Detail = fmt.Sprintf("tag %s (commit %s) yields %s, but the %s recorded %s for %s", tag, sha, got, src, want, m.Version)
	}
	return ch
}

// expectedHash returns the h1 hash everyone builds m with: from the
// checksum database, else go.sum, else the proxy's zip.
func (rc *retagChecker) expectedHash(ctx context.Context, m module.Version) (string, string, error) {
	if rc.sdb != nil && !sumdb.Excluded(rc.c.Env, m.Path) {
		if l, err := rc.sdb.Lookup(ctx, m.Path, m.Version); err == nil && l.ZipHash != "" {
			return l.ZipHash, "checksum database", nil
		}
	}
	if h := rc.gosum[m.Path+"@"+m.Version]; h != "" {
		return h, "go.sum", nil
	}
	z, err := rc.c.Proxy().Zip(ctx, m.Path, m.Version)
	if err != nil {
		return "", "", err
	}
	h, err := modzip.HashZip(z)
	return h, "module proxy", err
}

// HashRepoArchive builds the module zip file list of modPath@version from a
// GitHub repository archive the way the go command does for direct VCS
// fetches, and returns its h1 hash.
func HashRepoArchive(data []byte, modPath, version, subdir string) (string, error) {
	files, err := moduleFilesFromArchive(data, modPath, subdir)
	if err != nil {
		return "", err
	}
	prefix := modPath + "@" + version + "/"
	var names []string
	for n := range files {
		names = append(names, prefix+n)
	}
	return modzip.Hash1(names, func(name string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(files[strings.TrimPrefix(name, prefix)])), nil
	})
}

// moduleFilesFromArchive extracts the files of the module at subdir (or
// its major-version subdirectory) from a repository archive whose entries
// share one top-level directory.
func moduleFilesFromArchive(data []byte, modPath, subdir string) (map[string][]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("repository archive: %v", err)
	}
	repo := map[string]*zip.File{}
	for _, f := range zr.File {
		top, rel, ok := strings.Cut(f.Name, "/")
		if !ok || top == "" || rel == "" || strings.HasSuffix(rel, "/") {
			continue
		}
		if !f.Mode().IsRegular() && f.Mode()&fs.ModeType != 0 {
			continue // symlinks are not part of module zips
		}
		repo[rel] = f
	}
	read := func(name string) ([]byte, error) {
		f := repo[name]
		r, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(io.LimitReader(r, 500<<20))
	}
	// A module /vN may live in the vN subdirectory of its code directory.
	dir := strings.Trim(subdir, "/")
	if _, major, ok := module.SplitPathVersion(modPath); ok && strings.HasPrefix(major, "/v") {
		mdir := path.Join(dir, major[1:])
		if f := repo[path.Join(mdir, "go.mod")]; f != nil {
			if b, err := read(path.Join(mdir, "go.mod")); err == nil && modfile.ModulePath(b) == modPath {
				dir = mdir
			}
		}
	}
	under := func(name string) (string, bool) {
		if dir == "" {
			return name, true
		}
		if strings.HasPrefix(name, dir+"/") {
			return name[len(dir)+1:], true
		}
		return "", false
	}
	// Directories (relative to the module root) holding nested modules.
	nested := map[string]bool{}
	for name := range repo {
		if rel, ok := under(name); ok && path.Base(rel) == "go.mod" && rel != "go.mod" {
			nested[path.Dir(rel)] = true
		}
	}
	inNested := func(rel string) bool {
		for d := path.Dir(rel); d != "." && d != "/"; d = path.Dir(d) {
			if nested[d] {
				return true
			}
		}
		return false
	}
	out := map[string][]byte{}
	for name := range repo {
		rel, ok := under(name)
		if !ok || rel == ".hg_archival.txt" || isVendoredPackage(rel) || inNested(rel) || hasVCSDir(rel) {
			continue
		}
		b, err := read(name)
		if err != nil {
			return nil, err
		}
		out[rel] = b
	}
	if _, ok := out["LICENSE"]; !ok && dir != "" {
		if repo["LICENSE"] != nil {
			b, err := read("LICENSE")
			if err != nil {
				return nil, err
			}
			out["LICENSE"] = b
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no files for %s in directory %q of the repository archive", modPath, dir)
	}
	return out, nil
}

// isVendoredPackage matches golang.org/x/mod/zip, including its
// historical quirk for nested vendor directories (which cannot be fixed
// without changing existing checksums).
func isVendoredPackage(name string) bool {
	var i int
	if strings.HasPrefix(name, "vendor/") {
		i += len("vendor/")
	} else if j := strings.Index(name, "/vendor/"); j >= 0 {
		i += len("/vendor/")
	} else {
		return false
	}
	return strings.Contains(name[i:], "/")
}

func hasVCSDir(rel string) bool {
	for _, e := range strings.Split(path.Dir(rel), "/") {
		switch e {
		case ".git", ".hg", ".svn", ".bzr":
			return true
		}
	}
	return false
}

func printRetag(c *cli.Context, res *RetagResult) {
	o := c.Out
	subject := "."
	if p, err := c.Project(); err == nil && p.ModulePath() != "" {
		subject = p.ModulePath()
	}
	o.Title("sm-go retag · " + subject)
	gh := 0
	for _, ch := range res.Checks {
		if ch.Status != TagSkipped {
			gh++
		}
	}
	o.Printf("%s\n", o.Dim(fmt.Sprintf("%s checked, %d on GitHub", ui.Plural(len(res.Checks), "module version", "module versions"), gh)))
	var rows [][]string
	for _, ch := range res.Checks {
		if ch.Status == TagSkipped {
			continue
		}
		st := ch.Status
		switch st {
		case TagOK:
			st = o.Green(st)
		case TagMoved:
			st = o.Red(st)
		case TagDeleted, TagCommitMissing:
			st = o.Yellow(st)
		default:
			st = o.Dim(st)
		}
		ref := ch.Tag
		if ref == "" {
			ref = ch.RecordedCommit
		}
		rows = append(rows, []string{ch.Module, ch.Version, ref, ch.Method, st})
	}
	if len(rows) > 0 {
		o.Heading("GitHub tags")
		o.Table([]string{"MODULE", "VERSION", "TAG/COMMIT", "METHOD", "STATUS"}, rows)
	}
	if len(res.Findings) > 0 {
		o.Heading(fmt.Sprintf("Problems (%d)", len(res.Findings)))
		printFindings(c, res.Findings)
	}
	var sts []string
	for st := range res.Summary {
		sts = append(sts, st)
	}
	sort.Strings(sts)
	var parts []string
	for _, st := range sts {
		parts = append(parts, fmt.Sprintf("%d %s", res.Summary[st], st))
	}
	if len(parts) == 0 {
		parts = []string{"no modules"}
	}
	o.Println()
	o.Printf("%s %s\n", o.Bold("Summary:"), strings.Join(parts, " · "))
}
