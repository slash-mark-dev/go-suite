package binfile

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const testProg = `package main

import (
	"fmt"
	"os"
)

var Table = [4096]byte{1, 2, 3}

type T struct{ n int }

//go:noinline
func (t *T) Get() int { return t.n + int(Table[len(os.Args)]) }

//go:noinline
func Sum[E int | float64](xs []E) E {
	var s E
	for _, x := range xs {
		s += x
	}
	return s
}

func main() {
	t := &T{n: 1}
	f := t.Get
	go func() { fmt.Println(f()) }()
	fmt.Println(Sum([]int{1, 2}), Sum([]float64{1.5}))
}
`

func buildTest(t *testing.T, dir, out string, env []string, flags ...string) string {
	t.Helper()
	bin := filepath.Join(dir, out)
	args := append([]string{"build", "-o", bin}, flags...)
	args = append(args, ".")
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN=local")
	cmd.Env = append(cmd.Env, env...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	return bin
}

func TestOpenFormats(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/p\n\ngo 1.21\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(testProg), 0o644)
	cases := []struct {
		out, goos, goarch, format string
		flags                     []string
		source                    string
		stripped                  bool
	}{
		{"linux", "linux", "amd64", "elf", nil, SourceSymtab, false},
		{"linux-arm64-s", "linux", "arm64", "elf", []string{"-ldflags=-s -w"}, SourcePclntab, true},
		{"darwin", "darwin", "arm64", "macho", nil, SourceSymtab, false},
		{"darwin-s", "darwin", "amd64", "macho", []string{"-ldflags=-s -w"}, SourcePclntab, true},
		{"win.exe", "windows", "amd64", "pe", nil, SourceSymtab, false},
		{"win-s.exe", "windows", "amd64", "pe", []string{"-ldflags=-s"}, SourcePclntab, true},
		{"win386.exe", "windows", "386", "pe", nil, SourceSymtab, false},
	}
	for _, c := range cases {
		t.Run(c.out, func(t *testing.T) {
			bin := buildTest(t, dir, c.out, []string{"GOOS=" + c.goos, "GOARCH=" + c.goarch}, c.flags...)
			f, err := Open(bin)
			if err != nil {
				t.Fatal(err)
			}
			if f.Format != c.format || f.GOOS != c.goos || f.GOARCH != c.goarch {
				t.Errorf("format %s %s/%s, want %s %s/%s", f.Format, f.GOOS, f.GOARCH, c.format, c.goos, c.goarch)
			}
			if f.SymbolSource != c.source || f.Stripped != c.stripped || !f.HasPclntab {
				t.Errorf("source %s stripped %v pclntab %v", f.SymbolSource, f.Stripped, f.HasPclntab)
			}
			if f.BuildInfo == nil || f.BuildInfo.Main.Path != "example.com/p" {
				t.Errorf("build info %+v", f.BuildInfo)
			}
			if f.Setting("GOOS") != c.goos {
				t.Errorf("GOOS setting %q", f.Setting("GOOS"))
			}
			ix := f.Index()
			for _, want := range [][2]string{{"main", "main"}, {"main", "T.Get"}, {"main", "Sum"}, {"runtime", "main"}, {"fmt", "Fprintln"}, {"main", "main.func1"}} {
				if !ix.Has(want[0], want[1]) {
					t.Errorf("index lacks %s.%s", want[0], want[1])
				}
			}
			if ix.Has("main", "Missing") || ix.HasPackage("net/http") {
				t.Error("index has symbols that are not linked")
			}
			if f.SectionTotal(KindText) == 0 || f.SectionTotal(KindPclntab) == 0 && c.format != "pe" {
				t.Errorf("section totals %v", f.Totals())
			}
			if !c.stripped {
				found := false
				for _, s := range f.Data {
					if s.Name == "main.Table" {
						found = true
						if s.Size < 4096 || s.Size > 4096+64 {
							t.Errorf("main.Table size %d", s.Size)
						}
						if k := f.KindAt(s.Addr); k != KindData && k != KindRodata {
							t.Errorf("main.Table in %s section", k)
						}
					}
				}
				if !found {
					t.Error("main.Table not among data symbols")
				}
				if f.StripSavings() == 0 {
					t.Error("no strip savings for unstripped binary")
				}
				if fi, err := os.Stat(bin); err != nil || f.StripSavings() >= uint64(fi.Size()) {
					t.Errorf("strip savings %d not below the file size", f.StripSavings())
				}
			}
			// Sections hold no more bytes than the file (DWARF is
			// compressed in ELF: count the compressed size).
			var onDisk uint64
			for _, k := range f.Totals() {
				onDisk += k
			}
			if fi, err := os.Stat(bin); err != nil || onDisk > uint64(fi.Size()) {
				t.Errorf("sections total %d bytes, more than the file", onDisk)
			}
			var text uint64
			for _, fn := range f.Funcs {
				text += fn.Size
			}
			if text == 0 || text > f.SectionTotal(KindText)+f.SectionTotal(KindOther) {
				t.Errorf("function bytes %d vs text %d", text, f.SectionTotal(KindText))
			}
			if !IsGoBinary(bin) {
				t.Error("IsGoBinary false")
			}
		})
	}
}

func TestOpenErrors(t *testing.T) {
	dir := t.TempDir()
	txt := filepath.Join(dir, "x.txt")
	os.WriteFile(txt, []byte("hello world, not a binary"), 0o644)
	if _, err := Open(txt); !errors.Is(err, ErrFormat) {
		t.Errorf("text file: %v", err)
	}
	if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Errorf("dir: %v", err)
	}
	if _, err := Open(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file opened")
	}
	// A non-Go ELF: a valid header with no Go build information.
	if sh, err := exec.LookPath("sh"); err == nil {
		if real, err := filepath.EvalSymlinks(sh); err == nil {
			if _, err := Open(real); !errors.Is(err, ErrNotGo) && !errors.Is(err, ErrFormat) {
				t.Errorf("%s: %v", real, err)
			}
		}
	}
}
