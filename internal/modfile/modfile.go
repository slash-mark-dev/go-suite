// Package modfile parses go.mod, go.work, go.sum and vendor/modules.txt.
//
// The parser is tolerant: syntax and semantic problems are collected in
// File.Errors instead of aborting, so analysis tools can still report on a
// partially broken file. Directive semantics follow golang.org/x/mod/modfile.
package modfile

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/semver"
)

// File is a parsed go.mod or go.work file.
type File struct {
	Name string `json:"file"`

	Module    *Module    `json:"module,omitempty"`
	Go        string     `json:"go,omitempty"`
	GoLine    int        `json:"goLine,omitempty"`
	Toolchain string     `json:"toolchain,omitempty"`
	Godebug   []*Godebug `json:"godebug,omitempty"`
	Require   []*Require `json:"require,omitempty"`
	Exclude   []*Exclude `json:"exclude,omitempty"`
	Replace   []*Replace `json:"replace,omitempty"`
	Retract   []*Retract `json:"retract,omitempty"`
	Tool      []*Tool    `json:"tool,omitempty"`
	Ignore    []*Ignore  `json:"ignore,omitempty"`
	Use       []*Use     `json:"use,omitempty"` // go.work only
	Errors    []error    `json:"-"`
	Unknown   []string   `json:"unknown,omitempty"`
	IsWork    bool       `json:"isWork,omitempty"`
}

type Module struct {
	Path       string `json:"path"`
	Deprecated string `json:"deprecated,omitempty"`
	Line       int    `json:"line"`
}

type Godebug struct {
	Key, Value string
	Line       int
}

type Require struct {
	Mod      module.Version `json:"mod"`
	Indirect bool           `json:"indirect,omitempty"`
	Line     int            `json:"line"`
}

type Exclude struct {
	Mod  module.Version `json:"mod"`
	Line int            `json:"line"`
}

// Replace is a replace directive. New.Version == "" means New.Path is a
// filesystem directory. Old.Version == "" replaces every version.
type Replace struct {
	Old  module.Version `json:"old"`
	New  module.Version `json:"new"`
	Line int            `json:"line"`
}

// IsLocal reports whether the replacement points at a directory.
func (r *Replace) IsLocal() bool { return r.New.Version == "" }

type Retract struct {
	Low       string `json:"low"`
	High      string `json:"high"`
	Rationale string `json:"rationale,omitempty"`
	Line      int    `json:"line"`
}

// Contains reports whether v falls in the retracted interval.
func (r *Retract) Contains(v string) bool {
	return semver.Compare(r.Low, v) <= 0 && semver.Compare(v, r.High) <= 0
}

type Tool struct {
	Path string `json:"path"`
	Line int    `json:"line"`
}

type Ignore struct {
	Path string `json:"path"`
	Line int    `json:"line"`
}

type Use struct {
	Path       string `json:"path"`
	ModulePath string `json:"modulePath,omitempty"` // filled by the workspace loader
	Line       int    `json:"line"`
}

var (
	goVersionRE  = regexp.MustCompile(`^([1-9][0-9]*)\.(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))?([a-z]+[0-9]+)?$`)
	toolchainRE  = regexp.MustCompile(`^default$|^go1($|\.)`)
	deprecatedRE = regexp.MustCompile(`(?s)(?:^|\n\n)Deprecated: *(.*?)(?:$|\n\n)`)
)

// ParseFile reads and parses a go.mod or go.work file from disk.
func ParseFile(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if filepath.Base(path) == "go.work" {
		return ParseWork(path, data), nil
	}
	return Parse(path, data), nil
}

// Parse parses a go.mod file. It never returns nil.
func Parse(name string, data []byte) *File { return parse(name, data, false) }

// ParseWork parses a go.work file. It never returns nil.
func ParseWork(name string, data []byte) *File { return parse(name, data, true) }

func parse(name string, data []byte, work bool) *File {
	f := &File{Name: name, IsWork: work}
	lines, errs := lexLines(data)
	f.Errors = append(f.Errors, errs...)
	stmts, errs := parseStmts(lines)
	f.Errors = append(f.Errors, errs...)
	for _, s := range stmts {
		f.add(s)
	}
	return f
}

func (f *File) errorf(line int, format string, a ...any) {
	f.Errors = append(f.Errors, fmt.Errorf("%s:%d: %s", f.Name, line, fmt.Sprintf(format, a...)))
}

func canonicalVersion(v string) string {
	c := semver.Canonical(v)
	if c == "" {
		return ""
	}
	if semver.Build(v) == "+incompatible" {
		c += "+incompatible"
	}
	return c
}

func (f *File) add(s stmt) {
	args := s.args
	vals := make([]string, len(args))
	for i, a := range args {
		vals[i] = tokVal(a)
	}
	switch s.verb {
	case "module":
		if f.IsWork {
			f.unknown(s)
			return
		}
		if f.Module != nil {
			f.errorf(s.line, "repeated module statement")
			return
		}
		if len(vals) != 1 {
			f.errorf(s.line, "usage: module module/path")
			return
		}
		m := &Module{Path: vals[0], Line: s.line}
		if mm := deprecatedRE.FindStringSubmatch(s.directiveComment()); mm != nil {
			m.Deprecated = mm[1]
		}
		f.Module = m
	case "go":
		if f.Go != "" {
			f.errorf(s.line, "repeated go statement")
			return
		}
		if len(vals) != 1 {
			f.errorf(s.line, "go directive expects exactly one argument")
			return
		}
		if !goVersionRE.MatchString(vals[0]) {
			f.errorf(s.line, "invalid go version '%s': must match format 1.23.0", vals[0])
		}
		f.Go, f.GoLine = vals[0], s.line
	case "toolchain":
		if f.Toolchain != "" {
			f.errorf(s.line, "repeated toolchain statement")
			return
		}
		if len(vals) != 1 {
			f.errorf(s.line, "toolchain directive expects exactly one argument")
			return
		}
		if !toolchainRE.MatchString(vals[0]) {
			f.errorf(s.line, "invalid toolchain version '%s': must match format go1.23.0 or default", vals[0])
		}
		f.Toolchain = vals[0]
	case "godebug":
		if len(vals) != 1 || strings.ContainsAny(vals[0], "\"`',") {
			f.errorf(s.line, "usage: godebug key=value")
			return
		}
		k, v, ok := strings.Cut(vals[0], "=")
		if !ok {
			f.errorf(s.line, "usage: godebug key=value")
			return
		}
		f.Godebug = append(f.Godebug, &Godebug{Key: k, Value: v, Line: s.line})
	case "require", "exclude":
		if f.IsWork {
			f.unknown(s)
			return
		}
		if len(vals) != 2 {
			f.errorf(s.line, "usage: %s module/path v1.2.3", s.verb)
			return
		}
		p := vals[0]
		v := canonicalVersion(vals[1])
		if v == "" {
			f.errorf(s.line, "%s %s: invalid version %q", s.verb, p, vals[1])
			v = vals[1]
		}
		if s.verb == "require" {
			f.Require = append(f.Require, &Require{Mod: module.Version{Path: p, Version: v}, Indirect: isIndirect(s.suffix), Line: s.line})
		} else {
			f.Exclude = append(f.Exclude, &Exclude{Mod: module.Version{Path: p, Version: v}, Line: s.line})
		}
	case "replace":
		f.parseReplace(s, vals)
	case "retract":
		if f.IsWork {
			f.unknown(s)
			return
		}
		r, ok := parseInterval(vals)
		if !ok {
			f.errorf(s.line, "usage: retract v1.2.3 or retract [v1.0.0, v1.9.9]")
			return
		}
		if semver.IsValid(r.Low) && semver.IsValid(r.High) && semver.Compare(r.Low, r.High) > 0 {
			f.errorf(s.line, "version interval lower bound must be less than upper bound")
		}
		r.Line = s.line
		r.Rationale = s.directiveComment()
		f.Retract = append(f.Retract, r)
	case "tool":
		if f.IsWork || len(vals) != 1 {
			f.unknown(s)
			return
		}
		f.Tool = append(f.Tool, &Tool{Path: vals[0], Line: s.line})
	case "ignore":
		if f.IsWork || len(vals) != 1 {
			f.unknown(s)
			return
		}
		f.Ignore = append(f.Ignore, &Ignore{Path: vals[0], Line: s.line})
	case "use":
		if !f.IsWork || len(vals) != 1 {
			f.unknown(s)
			return
		}
		f.Use = append(f.Use, &Use{Path: vals[0], Line: s.line})
	default:
		f.unknown(s)
	}
}

func (f *File) unknown(s stmt) {
	f.Unknown = append(f.Unknown, s.verb)
	f.errorf(s.line, "unknown directive: %s", s.verb)
}

func (f *File) parseReplace(s stmt, vals []string) {
	arrow := 2
	if len(vals) >= 2 && vals[1] == "=>" {
		arrow = 1
	}
	if len(vals) < arrow+2 || len(vals) > arrow+3 || vals[arrow] != "=>" {
		f.errorf(s.line, "usage: replace module/path [v1.2.3] => other/module v1.4\n\t or replace module/path [v1.2.3] => ../local/directory")
		return
	}
	old := module.Version{Path: vals[0]}
	if arrow == 2 {
		v := canonicalVersion(vals[1])
		if v == "" {
			f.errorf(s.line, "replace %s: invalid version %q", vals[0], vals[1])
			v = vals[1]
		}
		old.Version = v
	}
	nw := module.Version{Path: vals[arrow+1]}
	if len(vals) == arrow+2 {
		if !IsDirectoryPath(nw.Path) {
			if strings.Contains(nw.Path, "@") {
				f.errorf(s.line, "replacement module must match format 'path version', not 'path@version'")
			} else {
				f.errorf(s.line, "replacement directory appears to be Windows path (on a non-windows system) or missing version: %s", nw.Path)
			}
		}
	} else {
		v := canonicalVersion(vals[arrow+2])
		if v == "" {
			f.errorf(s.line, "replace %s: invalid version %q", nw.Path, vals[arrow+2])
			v = vals[arrow+2]
		}
		if IsDirectoryPath(nw.Path) {
			f.errorf(s.line, "replacement module directory path %q cannot have version", nw.Path)
		}
		nw.Version = v
	}
	f.Replace = append(f.Replace, &Replace{Old: old, New: nw, Line: s.line})
}

// parseInterval parses a retract interval. Like x/mod, versions are kept
// as written: the go command validates them later against the module path.
func parseInterval(vals []string) (*Retract, bool) {
	if len(vals) == 1 && vals[0] != "[" {
		return &Retract{Low: vals[0], High: vals[0]}, true
	}
	if len(vals) == 5 && vals[0] == "[" && vals[2] == "," && vals[4] == "]" {
		return &Retract{Low: vals[1], High: vals[3]}, true
	}
	return nil, false
}

func isIndirect(suffix string) bool {
	if suffix == "" {
		return false
	}
	f := strings.Fields(strings.TrimPrefix(suffix, "//"))
	return len(f) == 1 && f[0] == "indirect" || len(f) > 1 && f[0] == "indirect;"
}

// IsDirectoryPath reports whether p looks like a filesystem path rather
// than a module path (the x/mod rule for replacement targets).
func IsDirectoryPath(p string) bool {
	return strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") ||
		strings.HasPrefix(p, `.\`) || strings.HasPrefix(p, `..\`) || strings.HasPrefix(p, `\`) ||
		p == "." || p == ".." ||
		len(p) >= 2 && ('A' <= p[0] && p[0] <= 'Z' || 'a' <= p[0] && p[0] <= 'z') && p[1] == ':'
}

// ModulePath returns the module path declared in go.mod data, or "".
// It is a fast scan used for dependency go.mod files.
func ModulePath(data []byte) string {
	f := Parse("go.mod", data)
	if f.Module == nil {
		return ""
	}
	return f.Module.Path
}

// Retracted reports whether version v is retracted by this go.mod (which
// should be the go.mod of the module's latest version) and the rationale.
func (f *File) Retracted(v string) (bool, string) {
	for _, r := range f.Retract {
		if r.Contains(v) {
			return true, r.Rationale
		}
	}
	return false, ""
}

// RequireMap returns path -> version for require directives.
func (f *File) RequireMap() map[string]string {
	m := make(map[string]string, len(f.Require))
	for _, r := range f.Require {
		m[r.Mod.Path] = r.Mod.Version
	}
	return m
}

// FindReplace returns the replacement for m.Path@m.Version, if any. A
// version-specific replacement wins over a wildcard one.
func (f *File) FindReplace(m module.Version) *Replace {
	var wild *Replace
	for _, r := range f.Replace {
		if r.Old.Path != m.Path {
			continue
		}
		if r.Old.Version == m.Version {
			return r
		}
		if r.Old.Version == "" {
			wild = r
		}
	}
	return wild
}

// Excluded reports whether m is excluded.
func (f *File) Excluded(m module.Version) bool {
	for _, e := range f.Exclude {
		if e.Mod == m {
			return true
		}
	}
	return false
}

// SumLine is one line of go.sum.
type SumLine struct {
	Path    string `json:"path"`
	Version string `json:"version"` // may end in "/go.mod"
	Hash    string `json:"hash"`
	Line    int    `json:"line"`
}

// IsGoMod reports whether the line is the go.mod-only hash.
func (s SumLine) IsGoMod() bool { return strings.HasSuffix(s.Version, "/go.mod") }

// ModVersion returns the module version without a "/go.mod" suffix.
func (s SumLine) ModVersion() string { return strings.TrimSuffix(s.Version, "/go.mod") }

// GoSum is a parsed go.sum.
type GoSum struct {
	Lines  []SumLine
	Errors []error
}

// ParseGoSum parses go.sum content.
func ParseGoSum(data []byte) *GoSum {
	gs := &GoSum{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			gs.Errors = append(gs.Errors, fmt.Errorf("go.sum:%d: malformed line", n))
			continue
		}
		gs.Lines = append(gs.Lines, SumLine{Path: f[0], Version: f[1], Hash: f[2], Line: n})
	}
	return gs
}

// Hash returns the hash recorded for path@version ("v1.2.3" or
// "v1.2.3/go.mod"), or "".
func (g *GoSum) Hash(path, version string) string {
	for _, l := range g.Lines {
		if l.Path == path && l.Version == version {
			return l.Hash
		}
	}
	return ""
}

// VendorModule is one "# path version" section of vendor/modules.txt.
type VendorModule struct {
	Path        string         `json:"path"`
	Version     string         `json:"version"`
	Replace     module.Version `json:"replace,omitempty"`
	Explicit    bool           `json:"explicit"`
	GoVersion   string         `json:"goVersion,omitempty"`
	Packages    []string       `json:"packages"`
	Line        int            `json:"line"`
	WildReplace bool           `json:"wildReplace,omitempty"`
}

// ParseVendorModules parses vendor/modules.txt.
func ParseVendorModules(data []byte) ([]*VendorModule, []error) {
	var mods []*VendorModule
	var errs []error
	var cur *VendorModule
	sc := bufio.NewScanner(bytes.NewReader(data))
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "# "):
			f := strings.Fields(line[2:])
			cur = &VendorModule{Line: n}
			mods = append(mods, cur)
			// "# path version", "# path version => new newversion",
			// "# path => ../dir", "# path version => ../dir"
			if i := indexOf(f, "=>"); i >= 0 {
				left, right := f[:i], f[i+1:]
				if len(left) >= 1 {
					cur.Path = left[0]
				}
				if len(left) >= 2 {
					cur.Version = left[1]
				} else {
					cur.WildReplace = true
				}
				if len(right) >= 1 {
					cur.Replace.Path = right[0]
				}
				if len(right) >= 2 {
					cur.Replace.Version = right[1]
				}
			} else if len(f) >= 2 {
				cur.Path, cur.Version = f[0], f[1]
			} else {
				errs = append(errs, fmt.Errorf("vendor/modules.txt:%d: malformed module line", n))
			}
		case strings.HasPrefix(line, "## "):
			if cur == nil {
				errs = append(errs, fmt.Errorf("vendor/modules.txt:%d: annotation before module", n))
				continue
			}
			for _, a := range strings.Split(line[3:], ";") {
				a = strings.TrimSpace(a)
				switch {
				case a == "explicit":
					cur.Explicit = true
				case strings.HasPrefix(a, "go "):
					cur.GoVersion = strings.TrimPrefix(a, "go ")
				}
			}
		case strings.HasPrefix(line, "#"):
			// other comments
		case strings.TrimSpace(line) == "":
		default:
			if cur == nil {
				errs = append(errs, fmt.Errorf("vendor/modules.txt:%d: package before module", n))
				continue
			}
			cur.Packages = append(cur.Packages, strings.TrimSpace(line))
		}
	}
	return mods, errs
}

func indexOf(list []string, s string) int {
	for i, x := range list {
		if x == s {
			return i
		}
	}
	return -1
}
