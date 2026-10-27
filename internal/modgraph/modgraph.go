// Package modgraph builds the module requirement graph and the build list
// with Minimum Version Selection, reproducing the go command's rules:
//
//   - graph pruning for main modules at go >= 1.17: the requirements of a
//     go >= 1.17 dependency are recorded but not expanded further, while a
//     dependency whose go.mod is older than 1.17 is expanded transitively;
//   - exclude directives of the main module(s) drop excluded requirements;
//   - replace directives (go.work replacements win) redirect where a
//     module's go.mod is read from without changing its identity;
//   - in a workspace every use'd module is a main module and always wins.
//
// The result matches `go list -m all` (see the differential tests in
// verify/).
package modgraph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/slash-mark-dev/go-suite/internal/modfile"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/par"
	"github.com/slash-mark-dev/go-suite/internal/semver"
)

// Fetcher returns the go.mod content of a module version.
type Fetcher interface {
	GoMod(ctx context.Context, path, version string) ([]byte, error)
}

// Main is a main module: its directory and parsed go.mod.
type Main struct {
	Dir  string
	File *modfile.File
}

// Path returns the module path of the main module.
func (m Main) Path() string {
	if m.File != nil && m.File.Module != nil {
		return m.File.Module.Path
	}
	return ""
}

// Config describes what to load.
type Config struct {
	Mains []Main
	// Work is the parsed go.work in workspace mode (nil otherwise) and
	// WorkDir its directory.
	Work    *modfile.File
	WorkDir string
	Fetch   Fetcher
	// Roots, when non-nil, replaces the main modules' requirements. Used to
	// simulate upgrades.
	Roots []module.Version
	// ForcePruning overrides pruning detection ("pruned"/"unpruned").
	ForcePruning string
}

type pruning int

const (
	pruned pruning = iota
	unpruned
	workspace
)

// Graph is a loaded module graph.
type Graph struct {
	Mains            []module.Version                    `json:"mains"`
	Roots            []module.Version                    `json:"roots"`
	Selected         map[string]string                   `json:"selected"`
	Reqs             map[module.Version][]module.Version `json:"-"`
	GoVersion        map[module.Version]string           `json:"-"`
	Toolchain        map[module.Version]string           `json:"-"`
	Replacement      map[module.Version]module.Version   `json:"-"` // effective replacement used to read go.mod
	Errors           map[module.Version]error            `json:"-"`
	Pruned           bool                                `json:"pruned"`
	Workspace        bool                                `json:"workspace"`
	mainPaths        map[string]bool
	replace          []*modfile.Replace
	replaceBase      map[*modfile.Replace]string
	excluded         map[module.Version]bool
	expanded         map[module.Version]bool
	DroppedByExclude []module.Version `json:"-"`
	// OriginalRoots are the main module requirements as written; Roots are
	// the effective ones after the go command's consistency rules.
	OriginalRoots []module.Version `json:"-"`
}

// IsMain reports whether path is a main module.
// Expanded reports whether the requirements of m were themselves loaded
// (m is a main module, or was reached through an unpruned or workspace
// load), as opposed to merely recorded.
func (g *Graph) Expanded(m module.Version) bool {
	if m.Version == "" && g.mainPaths[m.Path] {
		return true
	}
	return g.expanded[m]
}

func (g *Graph) IsMain(path string) bool { return g.mainPaths[path] }

func cmpVersion(v, w string) int {
	if v == w {
		return 0
	}
	if v == "" {
		return +1
	}
	if w == "" {
		return -1
	}
	if v == "none" {
		return -1
	}
	if w == "none" {
		return +1
	}
	return semver.Compare(v, w)
}

// GoAtLeast reports whether go version v (e.g. "1.21.3", "1.17") is >= w.
func GoAtLeast(v, w string) bool { return CompareGo(v, w) >= 0 }

// CompareGo compares Go language versions such as "1.17", "1.21.0",
// "1.22rc1". The empty string sorts lowest.
func CompareGo(v, w string) int {
	if v == w {
		return 0
	}
	if v == "" {
		return -1
	}
	if w == "" {
		return +1
	}
	pv, pw := parseGo(v), parseGo(w)
	for i := 0; i < 3; i++ {
		if c := cmpNum(pv.num[i], pw.num[i]); c != 0 {
			return c
		}
	}
	// "1.21" < "1.21rc1" < "1.21.0" per gover: language version < prereleases < release.
	if pv.kind != pw.kind {
		if pv.kind < pw.kind {
			return -1
		}
		return +1
	}
	if pv.preKind != pw.preKind {
		if pv.preKind < pw.preKind {
			return -1
		}
		return +1
	}
	return cmpNum(pv.pre, pw.pre)
}

type goVer struct {
	num     [3]string
	kind    int    // 0 = language version "1.21", 1 = prerelease, 2 = release "1.21.0"
	preKind string // "alpha" < "beta" < "rc"
	pre     string
}

func parseGo(v string) goVer {
	v = strings.TrimPrefix(v, "go")
	var g goVer
	g.num = [3]string{"0", "0", "0"}
	// split prerelease suffix like rc1 / beta2
	i := 0
	for i < len(v) && (v[i] >= '0' && v[i] <= '9' || v[i] == '.') {
		i++
	}
	nums, suf := v[:i], v[i:]
	parts := strings.Split(nums, ".")
	for j := 0; j < len(parts) && j < 3; j++ {
		if parts[j] != "" {
			g.num[j] = parts[j]
		}
	}
	switch {
	case suf != "":
		g.kind = 1
		j := 0
		for j < len(suf) && (suf[j] < '0' || suf[j] > '9') {
			j++
		}
		g.preKind, g.pre = suf[:j], suf[j:]
	case len(parts) >= 3:
		g.kind = 2
	default:
		// "1.21" is the language version; for go < 1.21, "1.20" means the release.
		if cmpNum(g.num[0], "1") == 0 && cmpNum(g.num[1], "21") < 0 {
			g.kind = 2
		}
	}
	return g
}

func cmpNum(x, y string) int {
	x = strings.TrimLeft(x, "0")
	y = strings.TrimLeft(y, "0")
	if len(x) != len(y) {
		if len(x) < len(y) {
			return -1
		}
		return +1
	}
	if x < y {
		return -1
	}
	if x > y {
		return +1
	}
	return 0
}

// Load builds the module graph. For a pruned main module whose roots are
// inconsistent with the rest of the graph (a root is not its own selected
// version), the roots are raised to their selected versions and the graph
// is reloaded until it converges — the go command's expandGraph/updateRoots
// behaviour, which can pull in requirements that were previously pruned
// out.
func Load(ctx context.Context, cfg Config) (*Graph, error) {
	g, err := load(ctx, cfg)
	if err != nil || g.Workspace || !g.Pruned || cfg.ForcePruning != "" {
		return g, err
	}
	for iter := 0; iter < 100; iter++ {
		var roots []module.Version
		seen := map[string]bool{}
		changed := false
		for _, r := range g.Roots {
			if seen[r.Path] || g.mainPaths[r.Path] {
				if g.mainPaths[r.Path] {
					changed = true
				}
				continue
			}
			seen[r.Path] = true
			v := g.Selected[r.Path]
			if v != r.Version {
				changed = true
			}
			roots = append(roots, module.Version{Path: r.Path, Version: v})
		}
		if !changed {
			return g, nil
		}
		next := cfg
		next.Roots = roots
		ng, err := load(ctx, next)
		if err != nil {
			return g, err
		}
		ng.DroppedByExclude = g.DroppedByExclude
		ng.OriginalRoots = g.OriginalRoots
		g = ng
	}
	return g, nil
}

func load(ctx context.Context, cfg Config) (*Graph, error) {
	if len(cfg.Mains) == 0 {
		return nil, fmt.Errorf("no main module")
	}
	g := &Graph{
		Selected:    map[string]string{},
		Reqs:        map[module.Version][]module.Version{},
		GoVersion:   map[module.Version]string{},
		Toolchain:   map[module.Version]string{},
		Replacement: map[module.Version]module.Version{},
		Errors:      map[module.Version]error{},
		mainPaths:   map[string]bool{},
		replaceBase: map[*modfile.Replace]string{},
		excluded:    map[module.Version]bool{},
		expanded:    map[module.Version]bool{},
	}
	prune := pruned
	if cfg.Work != nil {
		prune = workspace
		g.Workspace = true
	} else if !GoAtLeast(cfg.Mains[0].File.Go, "1.17") {
		prune = unpruned
	}
	switch cfg.ForcePruning {
	case "pruned":
		prune = pruned
	case "unpruned":
		prune = unpruned
	}
	g.Pruned = prune != unpruned

	// Replacements: go.work replacements override module replacements of the
	// same path; module replacements are relative to their module dir.
	workRepl := map[string]bool{}
	if cfg.Work != nil {
		for _, r := range cfg.Work.Replace {
			g.replace = append(g.replace, r)
			g.replaceBase[r] = cfg.WorkDir
			workRepl[r.Old.Path] = true
		}
	}
	for _, m := range cfg.Mains {
		if m.File == nil {
			continue
		}
		for _, r := range m.File.Replace {
			if workRepl[r.Old.Path] {
				continue
			}
			g.replace = append(g.replace, r)
			g.replaceBase[r] = m.Dir
		}
		for _, e := range m.File.Exclude {
			g.excluded[e.Mod] = true
		}
	}

	var roots []module.Version
	for _, m := range cfg.Mains {
		mv := module.Version{Path: m.Path()}
		g.Mains = append(g.Mains, mv)
		g.mainPaths[mv.Path] = true
		g.Selected[mv.Path] = ""
		if m.File != nil {
			g.GoVersion[mv] = m.File.Go
			g.Toolchain[mv] = m.File.Toolchain
		}
	}
	if cfg.Roots != nil {
		roots = append(roots, cfg.Roots...)
	} else {
		seen := map[module.Version]bool{}
		for _, m := range cfg.Mains {
			if m.File == nil {
				continue
			}
			for _, r := range m.File.Require {
				if g.excluded[r.Mod] {
					g.DroppedByExclude = append(g.DroppedByExclude, r.Mod)
					continue
				}
				if !seen[r.Mod] {
					seen[r.Mod] = true
					roots = append(roots, r.Mod)
				}
			}
		}
	}
	g.Roots = roots
	g.OriginalRoots = roots
	// In a workspace each main module requires what its own go.mod lists
	// (the go command records each main module's summary separately);
	// otherwise the single main module requires the roots.
	mainReqs := map[module.Version][]module.Version{}
	if prune == workspace && cfg.Roots == nil {
		for i, m := range cfg.Mains {
			reqs := []module.Version{}
			if m.File != nil {
				for _, r := range m.File.Require {
					if !g.excluded[r.Mod] {
						reqs = append(reqs, r.Mod)
					}
				}
			}
			mainReqs[g.Mains[i]] = reqs
		}
	}
	for _, mv := range g.Mains {
		if reqs, ok := mainReqs[mv]; ok {
			g.Reqs[mv] = reqs
		} else {
			g.Reqs[mv] = roots
		}
	}
	for _, r := range roots {
		g.note(r)
	}

	type item struct {
		m module.Version
		p pruning
	}
	var mu sync.Mutex
	loadedPruned := map[module.Version]bool{}
	loadedUnpruned := map[module.Version]bool{}
	loadedWorkspace := map[module.Version]bool{}
	summaries := map[module.Version]*summary{}
	var queue []item
	enqueue := func(m module.Version, p pruning) {
		// Other versions of a main module's path (reached through a cycle,
		// or a workspace module requiring another one) are ordinary graph
		// nodes: the go command loads their go.mod too. Only the main
		// modules themselves (version "") are not loaded here.
		if m.Version == "none" || m.Version == "" {
			return
		}
		if p == unpruned {
			if loadedUnpruned[m] {
				return
			}
			loadedUnpruned[m] = true
		} else if p == workspace {
			if loadedWorkspace[m] {
				return
			}
			loadedWorkspace[m] = true
		} else {
			if loadedPruned[m] {
				return
			}
			loadedPruned[m] = true
		}
		queue = append(queue, item{m, p})
	}
	if prune == workspace && cfg.Roots == nil {
		// readModGraph enqueues the main modules themselves at workspace
		// pruning, so their requirements are loaded with each main
		// module's own pruning.
		for i, m := range cfg.Mains {
			p := pruned
			if m.File == nil || !GoAtLeast(m.File.Go, "1.17") {
				p = unpruned
			}
			for _, r := range mainReqs[g.Mains[i]] {
				enqueue(r, p)
			}
		}
	} else {
		for _, r := range roots {
			enqueue(r, prune)
		}
	}
	drain := func() {
		for len(queue) > 0 {
			batch := queue
			queue = nil
			var todo []module.Version
			for _, it := range batch {
				if _, ok := summaries[it.m]; !ok {
					todo = append(todo, it.m)
				}
			}
			// Deduplicate todo.
			sort.Slice(todo, func(i, j int) bool { return todo[i].String() < todo[j].String() })
			todo = uniq(todo)
			res, _ := par.Map(ctx, 16, todo, func(ctx context.Context, m module.Version) (*summary, error) {
				return g.loadSummary(ctx, cfg.Fetch, m), nil
			})
			mu.Lock()
			for i, m := range todo {
				summaries[m] = res[i]
			}
			mu.Unlock()
			for _, it := range batch {
				s := summaries[it.m]
				if s.err != nil {
					g.Errors[it.m] = s.err
					continue
				}
				g.Reqs[it.m] = s.require
				g.GoVersion[it.m] = s.goVersion
				g.Toolchain[it.m] = s.toolchain
				for _, r := range s.require {
					g.note(r)
				}
				if it.p != pruned || s.pruning == unpruned {
					g.expanded[it.m] = true
					next := s.pruning
					if it.p == unpruned {
						next = unpruned
					}
					for _, r := range s.require {
						enqueue(r, next)
					}
				}
			}
		}
	}
	drain()

	// Workspace mode: reload dependencies that are not at their selected
	// versions (the go command's hasDepsInAll loop in readModGraph).
	if prune == workspace {
		hasDepsInAll := map[string]bool{}
		seen := map[module.Version]bool{}
		for _, m := range g.Mains {
			hasDepsInAll[m.Path] = true
			seen[m] = true
		}
		for {
			needs := map[module.Version]bool{}
			for p := range hasDepsInAll {
				m := module.Version{Path: p, Version: g.Selected[p]}
				if !seen[m] {
					needs[m] = true
					continue
				}
				for _, r := range g.Reqs[m] {
					s := module.Version{Path: r.Path, Version: g.Selected[r.Path]}
					if cmpVersion(s.Version, r.Version) > 0 && !seen[s] && !g.mainPaths[s.Path] {
						needs[s] = true
					}
				}
			}
			if len(needs) == 0 {
				break
			}
			var list []module.Version
			for m := range needs {
				list = append(list, m)
			}
			module.Sort(list)
			for _, m := range list {
				enqueue(m, workspace)
				seen[m] = true
				hasDepsInAll[m.Path] = true
			}
			drain()
		}
	}
	return g, nil
}

func uniq(list []module.Version) []module.Version {
	out := list[:0]
	for i, m := range list {
		if i == 0 || m != list[i-1] {
			out = append(out, m)
		}
	}
	return out
}

func (g *Graph) note(r module.Version) {
	if v, ok := g.Selected[r.Path]; !ok || cmpVersion(v, r.Version) < 0 {
		g.Selected[r.Path] = r.Version
	}
}

type summary struct {
	require   []module.Version
	goVersion string
	toolchain string
	pruning   pruning
	err       error
}

// FindReplace returns the replacement in effect for m, if any.
func (g *Graph) FindReplace(m module.Version) (*modfile.Replace, string) {
	var wild *modfile.Replace
	for _, r := range g.replace {
		if r.Old.Path != m.Path {
			continue
		}
		if r.Old.Version == m.Version {
			return r, g.replaceBase[r]
		}
		if r.Old.Version == "" && wild == nil {
			wild = r
		}
	}
	if wild != nil {
		return wild, g.replaceBase[wild]
	}
	return nil, ""
}

func (g *Graph) loadSummary(ctx context.Context, fetch Fetcher, m module.Version) *summary {
	var data []byte
	var err error
	name := m.String() + "/go.mod"
	if r, base := g.FindReplace(m); r != nil {
		if r.IsLocal() {
			dir := r.New.Path
			if !filepath.IsAbs(dir) {
				dir = filepath.Join(base, dir)
			}
			name = filepath.Join(dir, "go.mod")
			// A replacement directory must contain a go.mod: the go
			// command fails with "reading <dir>/go.mod: no such file".
			data, err = os.ReadFile(name)
			if err != nil {
				err = fmt.Errorf("%s (replaced by %s): reading %s: %w", m, r.New.Path, name, err)
			}
			g.setReplacement(m, module.Version{Path: dir})
		} else {
			data, err = fetch.GoMod(ctx, r.New.Path, r.New.Version)
			name = r.New.String() + "/go.mod"
			g.setReplacement(m, r.New)
		}
	} else {
		data, err = fetch.GoMod(ctx, m.Path, m.Version)
	}
	if err != nil {
		return &summary{err: err}
	}
	f := modfile.Parse(name, data)
	s := &summary{goVersion: f.Go, toolchain: f.Toolchain, pruning: unpruned}
	if GoAtLeast(f.Go, "1.17") {
		s.pruning = pruned
	}
	for _, r := range f.Require {
		if g.excluded[r.Mod] {
			continue
		}
		s.require = append(s.require, r.Mod)
	}
	return s
}

var replMu sync.Mutex

func (g *Graph) setReplacement(m, r module.Version) {
	replMu.Lock()
	g.Replacement[m] = r
	replMu.Unlock()
}

// BuildList returns the selected version of every module in the graph
// other than the main modules, sorted by path.
func (g *Graph) BuildList() []module.Version {
	var out []module.Version
	for p, v := range g.Selected {
		if g.mainPaths[p] {
			continue
		}
		out = append(out, module.Version{Path: p, Version: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Version returns the selected version of path, or "".
func (g *Graph) Version(path string) string { return g.Selected[path] }

// IsSelected reports whether m is the selected version of its path.
func (g *Graph) IsSelected(m module.Version) bool {
	v, ok := g.Selected[m.Path]
	return ok && v == m.Version
}

// IsDirect reports whether path is required directly by a main module.
func (g *Graph) IsDirect(path string) bool {
	for _, r := range g.Roots {
		if r.Path == path {
			return true
		}
	}
	return false
}

// Requirers returns the graph nodes that require m (any version of m.Path
// if m.Version is "").
func (g *Graph) Requirers(m module.Version) []module.Version {
	var out []module.Version
	for from, reqs := range g.Reqs {
		for _, r := range reqs {
			if r.Path == m.Path && (m.Version == "" || r.Version == m.Version) {
				out = append(out, from)
				break
			}
		}
	}
	module.Sort(out)
	return out
}

// Chain returns the shortest requirement chain from a main module to
// target (path@version; version "" means the selected version). Only edges
// out of selected versions are followed first; if none exists the search
// falls back to all edges, since MVS considers requirements of every
// version in the graph.
func (g *Graph) Chain(target module.Version) []module.Version {
	if target.Version == "" {
		target.Version = g.Selected[target.Path]
	}
	if c := g.bfs(target, true); c != nil {
		return c
	}
	return g.bfs(target, false)
}

func (g *Graph) bfs(target module.Version, selectedOnly bool) []module.Version {
	prev := map[module.Version]module.Version{}
	seen := map[module.Version]bool{}
	var q []module.Version
	for _, m := range g.Mains {
		q = append(q, m)
		seen[m] = true
	}
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		if cur == target {
			var chain []module.Version
			for c := cur; ; {
				chain = append([]module.Version{c}, chain...)
				p, ok := prev[c]
				if !ok {
					break
				}
				c = p
			}
			return chain
		}
		reqs := g.Reqs[cur]
		sorted := append([]module.Version(nil), reqs...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
		for _, r := range sorted {
			if seen[r] {
				continue
			}
			if selectedOnly && r != target && !g.IsSelected(r) {
				continue
			}
			seen[r] = true
			prev[r] = cur
			q = append(q, r)
		}
	}
	return nil
}

// Edges returns every requirement edge in the graph (from loaded nodes).
func (g *Graph) Edges() [][2]module.Version {
	var out [][2]module.Version
	for from, reqs := range g.Reqs {
		for _, r := range reqs {
			out = append(out, [2]module.Version{from, r})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][0].String() != out[j][0].String() {
			return out[i][0].String() < out[j][0].String()
		}
		return out[i][1].String() < out[j][1].String()
	})
	return out
}

// Nodes returns every module version that appears in the graph.
func (g *Graph) Nodes() []module.Version {
	seen := map[module.Version]bool{}
	for _, m := range g.Mains {
		seen[m] = true
	}
	for from, reqs := range g.Reqs {
		seen[from] = true
		for _, r := range reqs {
			seen[r] = true
		}
	}
	var out []module.Version
	for m := range seen {
		out = append(out, m)
	}
	module.Sort(out)
	return out
}

// MaxGo returns the highest go directive among selected modules and which
// module declares it.
func (g *Graph) MaxGo() (string, module.Version) {
	best, who := "", module.Version{}
	for m, v := range g.GoVersion {
		if !(g.mainPaths[m.Path] && m.Version == "") && !g.IsSelected(m) {
			continue
		}
		if CompareGo(v, best) > 0 {
			best, who = v, m
		}
	}
	return best, who
}
