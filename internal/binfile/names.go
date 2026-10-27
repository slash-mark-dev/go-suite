package binfile

import (
	"net/url"
	"runtime/debug"
	"sort"
	"strings"
)

// Special buckets for symbols that do not belong to a Go package.
const (
	BucketType    = "<type metadata>"
	BucketString  = "<string data>"
	BucketRuntime = "<runtime metadata>"
	BucketNonGo   = "<non-Go code>" // C, assembly trampolines, linker stubs
)

// IsBucket reports whether pkg is one of the special buckets.
func IsBucket(pkg string) bool { return strings.HasPrefix(pkg, "<") }

var runtimeMeta = []string{
	"go:itab.", "go.itab.", "go:func.", "go.func.", "go:link", "go:buildinfo", "go.buildinfo",
	"go:main.inittasks", "go:fipsinfo", "go:cuint", "go.info.", "go:info.", "go:sym.", "go:runtime.",
	"go:interface", "go.interface", "go:closureptr", "go:map.",
	"runtime.pclntab", "runtime.epclntab", "runtime.findfunctab", "runtime.firstmoduledata",
	"runtime.types", "runtime.etypes", "runtime.rodata", "runtime.erodata", "runtime.noptrdata",
	"runtime.enoptrdata", "runtime.data", "runtime.edata", "runtime.bss", "runtime.ebss",
	"runtime.noptrbss", "runtime.enoptrbss", "runtime.text", "runtime.etext", "runtime.symtab",
	"runtime.esymtab", "runtime.gcdata", "runtime.gcbss", "runtime.itablink", "runtime.typelink",
	"runtime.covctrs", "runtime.ecovctrs", "runtime.end", "runtime.noptrdata",
}

func specialBucket(name string) string {
	switch {
	case strings.HasPrefix(name, "go:string."), strings.HasPrefix(name, "go.string."),
		strings.HasPrefix(name, "go:strings."):
		return BucketString
	case strings.HasPrefix(name, "type:.eq."), strings.HasPrefix(name, "type:.hash."),
		strings.HasPrefix(name, "type..eq."), strings.HasPrefix(name, "type..hash."):
		return "" // generated functions; attributed to the type's package
	case strings.HasPrefix(name, "type:"), strings.HasPrefix(name, "type."), strings.HasPrefix(name, "go:type."),
		strings.HasPrefix(name, "go.type."), strings.HasPrefix(name, "go:typerel"), strings.HasPrefix(name, "typerel."):
		return BucketType
	}
	for _, p := range runtimeMeta {
		if name == p || strings.HasPrefix(name, p) && (strings.HasSuffix(p, ".") || len(name) == len(p) || !isIdent(name[len(p)])) {
			return BucketRuntime
		}
	}
	return ""
}

func isIdent(b byte) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// SplitSymbol splits a Go symbol name into its package path and symbol:
//
//	github.com/a/b.(*T).M      -> "github.com/a/b", "T.M"
//	example.com/x.F[...]       -> "example.com/x", "F"
//	gopkg.in/yaml%2ev3.Marshal -> "gopkg.in/yaml.v3", "Marshal"
//	example.com/x.F.func1      -> "example.com/x", "F.func1"
//
// Type descriptors, string data and linker/runtime tables return one of
// the Bucket* constants as pkg; names that are not Go symbols return
// BucketNonGo.
func SplitSymbol(name string) (pkg, sym string) {
	if b := specialBucket(name); b != "" {
		return b, name
	}
	orig := name
	generated := false
	for _, pre := range []string{"type:.eq.", "type:.hash.", "type..eq.", "type..hash."} {
		if strings.HasPrefix(name, pre) {
			name = trimTypePrefix(name[len(pre):])
			generated = true
			break
		}
	}
	// Local symbols of C or assembly objects linked into a package:
	// "net(.text)", "runtime/cgo(.bss)".
	if i := strings.Index(name, "(."); i > 0 && strings.HasSuffix(name, ")") && !strings.ContainsAny(name[:i], " ()[]") {
		return name[:i], name[i:]
	}
	limit := len(name)
	if i := strings.IndexByte(name, '['); i >= 0 {
		limit = i
	}
	head := name[:limit]
	slash := strings.LastIndexByte(head, '/')
	dot := strings.IndexByte(head[slash+1:], '.')
	if dot < 0 {
		if generated {
			return BucketType, orig
		}
		return BucketNonGo, orig
	}
	pkg = head[:slash+1+dot]
	if pkg == "" || strings.ContainsAny(pkg, " {}*()[];,") {
		if generated {
			return BucketType, orig
		}
		return BucketNonGo, orig
	}
	if strings.Contains(pkg, "%") {
		if u, err := url.PathUnescape(pkg); err == nil {
			pkg = u
		}
	}
	sym = NormalizeSymbol(name[slash+1+dot+1:])
	return pkg, sym
}

// trimTypePrefix removes array, slice, pointer and channel prefixes from
// a type name ("[16]*p.T" -> "p.T") so the element type's package can be
// found.
func trimTypePrefix(s string) string {
	for {
		switch {
		case strings.HasPrefix(s, "*"):
			s = s[1:]
		case strings.HasPrefix(s, "[]"):
			s = s[2:]
		case strings.HasPrefix(s, "["):
			i := strings.IndexByte(s, ']')
			if i < 0 || !allDigits(s[1:i]) {
				return s
			}
			s = s[i+1:]
		case strings.HasPrefix(s, "chan "):
			s = s[5:]
		default:
			return s
		}
	}
}

// NormalizeSymbol turns the symbol part of a Go symbol name into the form
// used by the Go vulnerability database: generic type arguments removed,
// pointer receivers unwrapped ("(*T).M" -> "T.M").
func NormalizeSymbol(s string) string {
	// ABI wrappers of assembly functions: "F.abi0".
	s = strings.TrimSuffix(strings.TrimSuffix(s, ".abi0"), ".abiinternal")
	if strings.IndexByte(s, '[') >= 0 {
		var b strings.Builder
		depth := 0
		for i := 0; i < len(s); i++ {
			switch s[i] {
			case '[':
				depth++
				continue
			case ']':
				if depth > 0 {
					depth--
					continue
				}
			}
			if depth == 0 {
				b.WriteByte(s[i])
			}
		}
		s = b.String()
	}
	if strings.HasPrefix(s, "(") {
		if i := strings.IndexByte(s, ')'); i > 0 {
			s = strings.TrimPrefix(s[1:i], "*") + s[i+1:]
		}
	}
	return s
}

// Owner returns the declared function or method a symbol belongs to:
// closures ("F.func1.2"), go/defer wrappers, method values ("T.M-fm") and
// range-over-func bodies ("F-range1") map to their enclosing function.
func Owner(sym string) string {
	for {
		changed := false
		if i := strings.LastIndexByte(sym, '-'); i > 0 {
			suf := sym[i+1:]
			if suf == "fm" || strings.HasPrefix(suf, "range") && allDigits(suf[5:]) {
				sym, changed = sym[:i], true
			}
		}
		if i := strings.LastIndexByte(sym, '.'); i > 0 {
			suf := sym[i+1:]
			for _, p := range []string{"func", "gowrap", "deferwrap", ""} {
				if strings.HasPrefix(suf, p) && allDigits(suf[len(p):]) && len(suf) > len(p) {
					sym, changed = sym[:i], true
					break
				}
			}
		}
		if !changed {
			return sym
		}
	}
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// Module kinds.
const (
	ModStd     = "std"
	ModUnknown = "(unknown)"
)

// ModuleMap maps package paths to the modules a binary was built from.
type ModuleMap struct {
	Main    string
	paths   []string // longest first
	version map[string]string
}

// NewModuleMap builds a map from a binary's build information.
func NewModuleMap(bi *debug.BuildInfo) *ModuleMap {
	m := &ModuleMap{version: map[string]string{}}
	if bi == nil {
		return m
	}
	m.Main = bi.Main.Path
	if m.Main != "" {
		m.paths = append(m.paths, m.Main)
		m.version[m.Main] = bi.Main.Version
	}
	for _, d := range bi.Deps {
		m.paths = append(m.paths, d.Path)
		m.version[d.Path] = d.Version
	}
	sort.SliceStable(m.paths, func(i, j int) bool { return len(m.paths[i]) > len(m.paths[j]) })
	return m
}

// Module returns the module path providing pkg: a dependency or main
// module path (longest prefix match), ModStd for the standard library,
// the bucket itself for special buckets, or ModUnknown.
func (m *ModuleMap) Module(pkg string) string {
	if IsBucket(pkg) {
		return pkg
	}
	for _, p := range m.paths {
		if pkg == p || strings.HasPrefix(pkg, p+"/") {
			return p
		}
	}
	if pkg == "main" && m.Main != "" {
		return m.Main
	}
	first, _, _ := strings.Cut(pkg, "/")
	if !strings.Contains(first, ".") {
		if pkg == "main" {
			return ModUnknown
		}
		return ModStd
	}
	return ModUnknown
}

// Version returns the version of a module in the build info.
func (m *ModuleMap) Version(mod string) string { return m.version[mod] }

// IsMain reports whether mod is the main module.
func (m *ModuleMap) IsMain(mod string) bool { return mod != "" && mod == m.Main }

// FuncIndex is a set of "package.Symbol" keys present in a binary, with
// closures and wrappers folded into their owners.
type FuncIndex struct {
	syms map[string]bool
	pkgs map[string]bool
}

// Index builds the function index of f.
func (f *File) Index() *FuncIndex {
	ix := &FuncIndex{syms: map[string]bool{}, pkgs: map[string]bool{}}
	for _, fn := range f.Funcs {
		pkg, sym := SplitSymbol(fn.Name)
		if IsBucket(pkg) {
			continue
		}
		ix.pkgs[pkg] = true
		ix.syms[pkg+"."+sym] = true
		ix.syms[pkg+"."+Owner(sym)] = true
	}
	return ix
}

// HasPackage reports whether any function of pkg is linked in.
func (ix *FuncIndex) HasPackage(pkg string) bool { return ix.pkgs[pkg] }

// Has reports whether pkg.sym ("T.M" for methods) is linked in.
func (ix *FuncIndex) Has(pkg, sym string) bool { return ix.syms[pkg+"."+NormalizeSymbol(sym)] }

// Len returns the number of distinct symbols.
func (ix *FuncIndex) Len() int { return len(ix.syms) }
