package deps

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/modfile"
	"github.com/slash-mark-dev/go-suite/internal/modgraph"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/project"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/semver"
)

var workspaceFlags struct {
	failOn  func() (report.Severity, error)
	noDrift *bool
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "workspace",
		Group:   group,
		Summary: "Workspace (go.work) analyzer: conflicts, drift, go versions, go.work.sum, untracked modules",
		Usage:   "sm-go workspace [flags]",
		Help: `Analyses a go.work workspace the way the go command treats it:

  modules        every 'use' directory with its module path, go and
                 toolchain lines; a module path used twice is an error
  go versions    go.work must declare a go version at least as high as
                 every workspace module's (the go command refuses
                 otherwise); differing toolchain lines are reported
  replacements   replace directives of different workspace modules that
                 disagree for the same module (and version) are an error
                 unless go.work overrides them; go.work replacing a
                 workspace module at all versions is an error
  requirements   dependencies required at different versions by different
                 workspace modules (the workspace selects the highest)
  drift          each module's standalone build list (GOWORK=off, what CI,
                 'go mod tidy' and consumers see) compared with the
                 workspace build list; modules that cannot load outside
                 the workspace are flagged
  go.work.sum    entries, entries already in a module's go.sum, entries
                 for module versions no longer in the graph and checksum
                 conflicts with go.sum files
  untracked      directories under the workspace root with a go.mod that
                 go.work does not use

Run it anywhere inside the workspace (GOWORK selects the file as usual).`,
		Examples: []string{
			"sm-go workspace",
			"sm-go workspace --no-drift --json",
			"GOWORK=/path/to/go.work sm-go workspace",
		},
		Sources: []string{"Go module proxy (go.mod files)"},
		Flags: func(fs *flag.FlagSet) {
			workspaceFlags.failOn = failOnFlag(fs, "medium")
			workspaceFlags.noDrift = fs.Bool("no-drift", false, "skip the standalone build list comparison")
		},
		Run: runWorkspace,
	})
}

type wsModule struct {
	Dir       string    `json:"dir"`
	Path      string    `json:"path"`
	Go        string    `json:"go,omitempty"`
	Toolchain string    `json:"toolchain,omitempty"`
	Requires  int       `json:"requires"`
	Drift     []wsDrift `json:"drift"`
	// Standalone is false when the module's own build list cannot be
	// loaded outside the workspace.
	Standalone      bool     `json:"standaloneLoads"`
	StandaloneError []string `json:"standaloneErrors,omitempty"`
}

type wsDrift struct {
	Path       string `json:"path"`
	Standalone string `json:"standalone"`
	Workspace  string `json:"workspace"` // "" for a workspace module (local code)
}

type wsRequire struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Selected string `json:"selected"`
}

type wsConflict struct {
	Path       string      `json:"path"`
	Selected   string      `json:"selected"`
	Requirers  []wsRequire `json:"requiredBy"`
	Workspaces bool        `json:"workspaceModule,omitempty"`
}

type wsReplaceConflict struct {
	Old     string            `json:"old"`
	Targets map[string]string `json:"targets"` // module path -> replacement
}

type wsSum struct {
	Entries    int      `json:"entries"`
	InGoSum    int      `json:"alsoInGoSum"`
	Stale      []string `json:"stale"`
	Mismatched []string `json:"mismatched"`
}

type workspaceResult struct {
	WorkFile         string              `json:"workFile"`
	Go               string              `json:"go,omitempty"`
	Toolchain        string              `json:"toolchain,omitempty"`
	Modules          []wsModule          `json:"modules"`
	Conflicts        []wsConflict        `json:"conflicts"`
	ReplaceConflicts []wsReplaceConflict `json:"replaceConflicts"`
	Sum              *wsSum              `json:"workSum,omitempty"`
	Untracked        []string            `json:"untracked"`
	Findings         []report.Finding    `json:"findings"`
	Summary          severitySummary     `json:"summary"`
}

func runWorkspace(c *cli.Context) error {
	failOn, err := workspaceFlags.failOn()
	if err != nil {
		return err
	}
	if len(c.Args) > 0 {
		return cli.Usagef("unexpected argument %q", c.Args[0])
	}
	p, err := c.Project()
	if err != nil {
		return err
	}
	if !p.IsWorkspace() {
		if v, ok := c.Env.Lookup("GOWORK"); ok && v == "off" {
			return cli.Usagef("workspace mode is disabled (GOWORK=off); unset GOWORK or point it at a go.work file")
		}
		return cli.Usagef("not in a workspace: no go.work file found in %s or its parents", c.Dir())
	}
	_, g, err := loadGraph(c)
	if err != nil {
		return err
	}
	workFile := p.Rel(p.WorkPath)
	res := workspaceResult{WorkFile: workFile, Go: p.Work.Go, Toolchain: p.Work.Toolchain, Modules: []wsModule{}, Conflicts: []wsConflict{},
		ReplaceConflicts: []wsReplaceConflict{}, Untracked: []string{}, Findings: []report.Finding{}}
	add := func(f report.Finding) { res.Findings = append(res.Findings, f) }

	// Modules, duplicates, go and toolchain lines.
	byPath := map[string][]string{}
	toolchains := map[string][]string{}
	for i, mm := range p.Mains {
		u := p.Work.Use[i]
		m := wsModule{Dir: u.Path, Path: mm.Path(), Drift: []wsDrift{}}
		if mm.File != nil {
			m.Go, m.Toolchain, m.Requires = mm.File.Go, mm.File.Toolchain, len(mm.File.Require)
		}
		byPath[m.Path] = append(byPath[m.Path], u.Path)
		if m.Toolchain != "" {
			toolchains[m.Toolchain] = append(toolchains[m.Toolchain], m.Path)
		}
		if m.Path == "" {
			add(report.Finding{Severity: report.High, Rule: "workspace-no-module", File: workFile, Line: u.Line,
				Title: fmt.Sprintf("use %s: go.mod has no module directive", u.Path)})
		}
		if m.Go != "" && modgraph.CompareGo(m.Go, p.Work.Go) > 0 {
			declared := p.Work.Go
			if declared == "" {
				declared = "none"
			}
			add(report.Finding{Severity: report.High, Rule: "workspace-go-version", Module: m.Path, File: workFile, Line: p.Work.GoLine,
				Title:  fmt.Sprintf("module %s requires go >= %s, but go.work lists go %s", u.Path, m.Go, declared),
				Detail: "The go command refuses to load the workspace (\"module " + u.Path + " listed in go.work file requires go >= " + m.Go + "\").",
				Fix:    "go work use (raises the go line of go.work)"})
		}
		if p.Work.Toolchain != "" && m.Toolchain != "" && modgraph.CompareGo(strings.TrimPrefix(m.Toolchain, "go"), strings.TrimPrefix(p.Work.Toolchain, "go")) > 0 {
			add(report.Finding{Severity: report.Info, Rule: "workspace-toolchain", Module: m.Path, File: workFile,
				Title:  fmt.Sprintf("%s asks for toolchain %s, go.work for %s", m.Path, m.Toolchain, p.Work.Toolchain),
				Detail: "In workspace mode the toolchain line of go.work wins over those of the modules."})
		}
		res.Modules = append(res.Modules, m)
	}
	var dupPaths []string
	for path, dirs := range byPath {
		if len(dirs) > 1 && path != "" {
			dupPaths = append(dupPaths, path)
		}
	}
	sort.Strings(dupPaths)
	for _, path := range dupPaths {
		add(report.Finding{Severity: report.High, Rule: "workspace-duplicate-module", Module: path, File: workFile,
			Title:  fmt.Sprintf("module %s appears multiple times in the workspace (%s)", path, strings.Join(byPath[path], ", ")),
			Detail: "The go command refuses a workspace that uses two directories declaring the same module path.",
			Fix:    "remove one of the use directives"})
	}
	if len(toolchains) > 1 && p.Work.Toolchain == "" {
		var parts []string
		for tc, mods := range toolchains {
			parts = append(parts, tc+" ("+strings.Join(mods, ", ")+")")
		}
		sort.Strings(parts)
		add(report.Finding{Severity: report.Info, Rule: "workspace-toolchain", File: workFile,
			Title:  "workspace modules declare different toolchains",
			Detail: strings.Join(parts, "; ") + ". In workspace mode only go.work's go and toolchain lines select the toolchain.",
			Fix:    "add a toolchain line to go.work"})
	}

	// Replacements: the go command's workspace rules.
	workRepl := map[string]bool{}
	for _, r := range p.Work.Replace {
		workRepl[r.Old.Path] = true
		if g.IsMain(r.Old.Path) && r.Old.Version == "" {
			add(report.Finding{Severity: report.High, Rule: "replace-workspace-module", Module: r.Old.Path, File: workFile, Line: r.Line,
				Title:  fmt.Sprintf("go.work replaces workspace module %s at all versions", r.Old.Path),
				Detail: "The go command refuses this (\"workspace module " + r.Old.Path + " is replaced at all versions in the go.work file\").",
				Fix:    "remove the replacement from go.work or specify the version to replace"})
		}
	}
	type seenRepl struct {
		target string
		from   string
	}
	repl := map[module.Version]seenRepl{}
	conflicts := map[module.Version]*wsReplaceConflict{}
	var conflictKeys []module.Version
	for _, mm := range p.Mains {
		if mm.File == nil {
			continue
		}
		cur := map[module.Version]bool{}
		for _, r := range mm.File.Replace {
			if workRepl[r.Old.Path] {
				continue
			}
			target := r.New
			if target.Version == "" && !filepath.IsAbs(target.Path) {
				target.Path = filepath.Join(mm.Dir, target.Path)
			}
			tstr := replaceString(target)
			if target.Version == "" {
				tstr = relTo(p.Dir, target.Path)
			}
			if prev, ok := repl[r.Old]; ok && !cur[r.Old] && prev.target != tstr {
				rc := conflicts[r.Old]
				if rc == nil {
					old := r.Old.Path
					if r.Old.Version != "" {
						old += "@" + r.Old.Version
					}
					rc = &wsReplaceConflict{Old: old, Targets: map[string]string{prev.from: prev.target}}
					conflicts[r.Old] = rc
					conflictKeys = append(conflictKeys, r.Old)
				}
				rc.Targets[mm.Path()] = tstr
			}
			cur[r.Old] = true
			repl[r.Old] = seenRepl{target: tstr, from: mm.Path()}
			if g.IsMain(r.Old.Path) {
				add(report.Finding{Severity: report.Info, Rule: "replace-of-workspace-module", Module: r.Old.Path, File: p.Rel(mm.File.Name), Line: r.Line,
					Title:  fmt.Sprintf("%s replaces workspace module %s", mm.Path(), r.Old.Path),
					Detail: "In the workspace the local module " + r.Old.Path + " is always used; the replacement only changes which go.mod is read for other versions of it."})
			}
		}
	}
	module.Sort(conflictKeys)
	for _, k := range conflictKeys {
		rc := conflicts[k]
		res.ReplaceConflicts = append(res.ReplaceConflicts, *rc)
		var parts []string
		for mod, t := range rc.Targets {
			parts = append(parts, mod+": "+t)
		}
		sort.Strings(parts)
		add(report.Finding{Severity: report.High, Rule: "workspace-replace-conflict", Module: k.Path, Version: k.Version, File: workFile,
			Title:  fmt.Sprintf("conflicting replacements for %s in workspace modules", rc.Old),
			Detail: strings.Join(parts, "; ") + ". The go command refuses to load the workspace (\"conflicting replacements for " + rc.Old + "\").",
			Fix:    fmt.Sprintf("go work edit -replace %s=<replacement>", rc.Old)})
	}

	// Requirements that differ between workspace modules.
	reqs := map[string][]wsRequire{}
	for _, mm := range p.Mains {
		if mm.File == nil {
			continue
		}
		for _, r := range mm.File.Require {
			reqs[r.Mod.Path] = append(reqs[r.Mod.Path], wsRequire{Module: mm.Path(), Version: r.Mod.Version, Selected: g.Selected[r.Mod.Path]})
		}
	}
	var reqPaths []string
	for path, rs := range reqs {
		vs := map[string]bool{}
		for _, r := range rs {
			vs[r.Version] = true
		}
		if len(vs) > 1 {
			reqPaths = append(reqPaths, path)
		}
	}
	sort.Strings(reqPaths)
	for _, path := range reqPaths {
		rs := reqs[path]
		sort.Slice(rs, func(i, j int) bool { return semver.Compare(rs[i].Version, rs[j].Version) > 0 })
		wc := wsConflict{Path: path, Selected: g.Selected[path], Requirers: rs, Workspaces: g.IsMain(path)}
		res.Conflicts = append(res.Conflicts, wc)
		var parts []string
		for _, r := range rs {
			parts = append(parts, r.Module+" requires "+r.Version)
		}
		sel := wc.Selected
		if wc.Workspaces {
			sel = "the local workspace module"
		}
		add(report.Finding{Severity: report.Info, Rule: "workspace-requirement-mismatch", Module: path, File: workFile,
			Title:  fmt.Sprintf("workspace modules require different versions of %s", path),
			Detail: strings.Join(parts, "; ") + ". The workspace builds all of them with " + sel + "."})
	}

	// Drift: standalone build lists.
	if !*workspaceFlags.noDrift {
		for i := range res.Modules {
			m := &res.Modules[i]
			if err := workspaceDrift(c, g, p.Mains[i], m); err != nil {
				return err
			}
			if !m.Standalone {
				add(report.Finding{Severity: report.Medium, Rule: "workspace-standalone-broken", Module: m.Path, File: p.Rel(filepath.Join(p.Mains[i].Dir, "go.mod")),
					Title:  fmt.Sprintf("%s does not load outside the workspace", m.Path),
					Detail: "With GOWORK=off (CI, 'go mod tidy', consumers) its module graph has errors: " + strings.Join(m.StandaloneError, "; ") + ".",
					Fix:    "require published versions of the other workspace modules"})
			}
			if n := len(m.Drift); n > 0 {
				var parts []string
				for _, d := range m.Drift {
					w := d.Workspace
					if w == "" {
						w = "local"
					}
					parts = append(parts, fmt.Sprintf("%s %s→%s", d.Path, d.Standalone, w))
				}
				add(report.Finding{Severity: report.Low, Rule: "workspace-drift", Module: m.Path, File: p.Rel(filepath.Join(p.Mains[i].Dir, "go.mod")),
					Title:  fmt.Sprintf("%s builds with %s on its own than in the workspace", m.Path, plural(n, "different module version", "different module versions")),
					Detail: "Standalone → workspace: " + strings.Join(parts, ", ") + ". Tests pass in the workspace against code the module's own go.mod does not select.",
					Fix:    "align the requirements (go get in " + m.Dir + "), then go work sync"})
			}
		}
	}

	// go.work.sum.
	if data, err := os.ReadFile(p.WorkPath + ".sum"); err == nil {
		res.Sum = workSumAudit(p, g, modfile.ParseGoSum(data))
		for _, mm := range res.Sum.Mismatched {
			add(report.Finding{Severity: report.High, Rule: "worksum-mismatch", Module: mm, File: workFile + ".sum",
				Title:  fmt.Sprintf("go.work.sum and a module go.sum disagree on %s", mm),
				Detail: "Two different hashes for the same module version: one of them is wrong or the module was tampered with; the go command fails with a checksum mismatch.",
				Fix:    "verify with 'sm-go' checksum tools or 'go mod verify', then remove the wrong line"})
		}
		if n := len(res.Sum.Stale); n > 0 {
			add(report.Finding{Severity: report.Info, Rule: "worksum-stale", File: workFile + ".sum",
				Title:  fmt.Sprintf("go.work.sum has %s for module versions not in the workspace graph", plural(n, "entry", "entries")),
				Detail: ui3(res.Sum.Stale) + ". They are harmless but no longer needed."})
		}
	}

	// Modules under the workspace root not in go.work.
	used := map[string]bool{}
	for _, mm := range p.Mains {
		used[filepath.Clean(mm.Dir)] = true
	}
	for _, dir := range findModules(p.Dir) {
		if used[dir] {
			continue
		}
		rel := "./" + relTo(p.Dir, dir)
		path := ""
		if data, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			path = modfile.ModulePath(data)
		}
		res.Untracked = append(res.Untracked, rel)
		add(report.Finding{Severity: report.Low, Rule: "workspace-untracked-module", Module: path, File: rel + "/go.mod",
			Title:  fmt.Sprintf("module %s at %s is not in go.work", orNone([]string{path}), rel),
			Detail: "Inside the workspace directory but not used: commands run there ignore the workspace (\"directory is outside modules listed in go.work\") and the other modules use its published version.",
			Fix:    "go work use " + rel})
	}
	res.Summary = finish(c, res.Findings, failOn)
	c.SetResult(res)
	if c.Text() {
		printWorkspace(c, res)
	}
	return nil
}

func workspaceDrift(c *cli.Context, g *modgraph.Graph, mm modgraph.Main, m *wsModule) error {
	_, sg, err := loadStandalone(c, mm.Dir)
	if err != nil {
		return err
	}
	m.Standalone = true
	var bad []module.Version
	for n := range sg.Errors {
		bad = append(bad, n)
	}
	module.Sort(bad)
	for _, n := range bad {
		m.Standalone = false
		m.StandaloneError = append(m.StandaloneError, sg.Errors[n].Error())
	}
	for _, bm := range sg.BuildList() {
		ws, ok := g.Selected[bm.Path]
		switch {
		case g.IsMain(bm.Path):
			m.Drift = append(m.Drift, wsDrift{Path: bm.Path, Standalone: bm.Version})
		case !ok || ws != bm.Version:
			m.Drift = append(m.Drift, wsDrift{Path: bm.Path, Standalone: bm.Version, Workspace: ws})
		}
	}
	return nil
}

func workSumAudit(p *project.Project, g *modgraph.Graph, ws *modfile.GoSum) *wsSum {
	s := &wsSum{Entries: len(ws.Lines), Stale: []string{}, Mismatched: []string{}}
	modSums := map[string]string{} // "path version" -> hash
	for _, mm := range p.Mains {
		data, err := os.ReadFile(filepath.Join(mm.Dir, "go.sum"))
		if err != nil {
			continue
		}
		for _, l := range modfile.ParseGoSum(data).Lines {
			modSums[l.Path+" "+l.Version] = l.Hash
		}
	}
	inGraph := map[module.Version]bool{}
	for _, n := range g.Nodes() {
		inGraph[n] = true
	}
	stale := map[string]bool{}
	mismatch := map[string]bool{}
	for _, l := range ws.Lines {
		if h, ok := modSums[l.Path+" "+l.Version]; ok {
			s.InGoSum++
			if h != l.Hash {
				mismatch[l.Path+"@"+l.ModVersion()] = true
			}
		}
		if !inGraph[module.Version{Path: l.Path, Version: l.ModVersion()}] {
			stale[l.Path+"@"+l.ModVersion()] = true
		}
	}
	for k := range stale {
		s.Stale = append(s.Stale, k)
	}
	for k := range mismatch {
		s.Mismatched = append(s.Mismatched, k)
	}
	sort.Strings(s.Stale)
	sort.Strings(s.Mismatched)
	return s
}

// findModules returns the directories under root (root included) that
// contain a go.mod, skipping vendor, testdata, hidden and _ directories.
func findModules(root string) []string {
	var out []string
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (name == "vendor" || name == "testdata" || name == "node_modules" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "go.mod" {
			out = append(out, filepath.Clean(filepath.Dir(path)))
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func printWorkspace(c *cli.Context, r workspaceResult) {
	o := c.Out
	goLine := r.Go
	if goLine == "" {
		goLine = "(none)"
	}
	o.Title(fmt.Sprintf("Workspace %s · go %s", r.WorkFile, goLine))
	var rows [][]string
	for _, m := range r.Modules {
		drift := "-"
		switch {
		case !m.Standalone && len(m.StandaloneError) > 0:
			drift = o.Red("broken standalone")
		case len(m.Drift) > 0:
			drift = o.Yellow(fmt.Sprintf("%d differ", len(m.Drift)))
		case m.Standalone:
			drift = o.Green("none")
		}
		rows = append(rows, []string{m.Dir, m.Path, m.Go, m.Toolchain, fmt.Sprint(m.Requires), drift})
	}
	o.Println()
	o.Table([]string{"USE", "MODULE", "GO", "TOOLCHAIN", "REQUIRES", "DRIFT"}, rows)
	for _, m := range r.Modules {
		if len(m.Drift) == 0 {
			continue
		}
		o.Heading(fmt.Sprintf("%s: standalone vs workspace", m.Path))
		var dr [][]string
		for _, d := range m.Drift {
			w := d.Workspace
			if w == "" {
				w = "local (workspace module)"
			}
			dr = append(dr, []string{d.Path, d.Standalone, w})
		}
		o.Table([]string{"MODULE", "STANDALONE", "WORKSPACE"}, dr)
	}
	if r.Sum != nil {
		o.Heading("go.work.sum")
		o.KV([2]string{"entries", fmt.Sprint(r.Sum.Entries)},
			[2]string{"also in go.sum", fmt.Sprint(r.Sum.InGoSum)},
			[2]string{"stale", fmt.Sprint(len(r.Sum.Stale))},
			[2]string{"mismatched", fmt.Sprint(len(r.Sum.Mismatched))})
	}
	if len(r.Findings) > 0 {
		o.Heading("Findings")
		printFindings(c, r.Findings)
	}
	printSummaryLine(c, r.Findings, r.Summary)
}
