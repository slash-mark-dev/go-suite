package binfile

import (
	"runtime/debug"
	"testing"
)

func TestSplitSymbol(t *testing.T) {
	tests := []struct{ name, pkg, sym string }{
		{"github.com/a/b.(*T).M", "github.com/a/b", "T.M"},
		{"github.com/a/b.T.M", "github.com/a/b", "T.M"},
		{"example.com/x.F[...]", "example.com/x", "F"},
		{"example.com/x.Map[go.shape.int,go.shape.string]", "example.com/x", "Map"},
		{"internal/sync.(*HashTrieMap[go.shape.string,go.shape.interface {}]).Load", "internal/sync", "HashTrieMap.Load"},
		{"sync/atomic.(*Pointer[net/netip.addrDetail]).Load", "sync/atomic", "Pointer.Load"},
		{"gopkg.in/yaml%2ev3.Marshal", "gopkg.in/yaml.v3", "Marshal"},
		{"example.com/x.F.func1", "example.com/x", "F.func1"},
		{"example.com/x.(*T).M-fm", "example.com/x", "T.M-fm"},
		{"crypto/internal/fips140/sha3.keccakF1600.abi0", "crypto/internal/fips140/sha3", "keccakF1600"},
		{"main.main", "main", "main"},
		{"type:.eq.example.com/x.T", "example.com/x", "T"},
		{"type:.eq.[16]sync/atomic.Pointer[internal/sync.node[interface {},interface {}]]", "sync/atomic", "Pointer"},
		{"type:.hash.*example.com/x.T", "example.com/x", "T"},
		{"type:.eq.struct { a int }", BucketType, "type:.eq.struct { a int }"},
		{"net(.text)", "net", "(.text)"},
		{"type:*", BucketType, "type:*"},
		{"type:example.com/x.T", BucketType, "type:example.com/x.T"},
		{"typerel.*", BucketType, "typerel.*"},
		{"go:itab.*example.com/x.T,io.Reader", BucketRuntime, "go:itab.*example.com/x.T,io.Reader"},
		{"go:string.*", BucketString, "go:string.*"},
		{"go:func.*", BucketRuntime, "go:func.*"},
		{"runtime.pclntab", BucketRuntime, "runtime.pclntab"},
		{"runtime.main", "runtime", "main"},
		{"_cgo_77133bf98b3a_Cfunc_free", BucketNonGo, "_cgo_77133bf98b3a_Cfunc_free"},
		{"x_cgo_init", BucketNonGo, "x_cgo_init"},
		{"cmpbody", BucketNonGo, "cmpbody"},
	}
	for _, tt := range tests {
		pkg, sym := SplitSymbol(tt.name)
		if pkg != tt.pkg || sym != tt.sym {
			t.Errorf("SplitSymbol(%q) = %q, %q; want %q, %q", tt.name, pkg, sym, tt.pkg, tt.sym)
		}
	}
}

func TestOwner(t *testing.T) {
	tests := map[string]string{
		"F":                "F",
		"F.func1":          "F",
		"F.func1.2":        "F",
		"T.M.func3":        "T.M",
		"T.M-fm":           "T.M",
		"F.gowrap1":        "F",
		"F.deferwrap2":     "F",
		"F-range1":         "F",
		"F-range1.func2":   "F",
		"T.funcName":       "T.funcName",
		"init.0":           "init",
		"Server.Serve.fn1": "Server.Serve.fn1",
	}
	for in, want := range tests {
		if got := Owner(in); got != want {
			t.Errorf("Owner(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestModuleMap(t *testing.T) {
	bi := &debug.BuildInfo{Main: debug.Module{Path: "example.com/app", Version: "(devel)"},
		Deps: []*debug.Module{{Path: "example.com/lib", Version: "v1.0.0"}, {Path: "example.com/lib/v2", Version: "v2.1.0"}}}
	m := NewModuleMap(bi)
	tests := map[string]string{
		"main":                     "example.com/app",
		"example.com/app/internal": "example.com/app",
		"example.com/lib":          "example.com/lib",
		"example.com/lib/sub":      "example.com/lib",
		"example.com/lib/v2/x":     "example.com/lib/v2",
		"net/http":                 ModStd,
		"vendor/golang.org/x/net":  ModStd,
		"other.org/x":              ModUnknown,
		BucketType:                 BucketType,
	}
	for pkg, want := range tests {
		if got := m.Module(pkg); got != want {
			t.Errorf("Module(%q) = %q, want %q", pkg, got, want)
		}
	}
	if m.Version("example.com/lib/v2") != "v2.1.0" || !m.IsMain("example.com/app") {
		t.Error("Version/IsMain wrong")
	}
}

func TestNormalizeSymbol(t *testing.T) {
	tests := map[string]string{
		"(*T).M":                   "T.M",
		"T[go.shape.int].M":        "T.M",
		"(*T[go.shape.int]).M":     "T.M",
		"F[go.shape.[]uint8]":      "F",
		"blockAMD64.abi0":          "blockAMD64",
		"(*Reader).Read":           "Reader.Read",
		"Map[...]":                 "Map",
		"(*List[go.shape.int]).Do": "List.Do",
	}
	for in, want := range tests {
		if got := NormalizeSymbol(in); got != want {
			t.Errorf("NormalizeSymbol(%q) = %q, want %q", in, got, want)
		}
	}
}
