package binary_test

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
	_ "github.com/slash-mark-dev/go-suite/internal/tools/binary"
	"github.com/slash-mark-dev/go-suite/internal/vulndb"
)

// ---------------- fixtures ----------------

const vulnmodSrc = `package vulnmod

//go:noinline
func Bad(n int) int { return n*7 + 1 }

func Unused() int { return 42 }
`

func bigSrc(n int) string {
	return `package big

// Table is large initialised data.
var Table = [` + strconv.Itoa(n) + `]byte{1, 2, 3}

//go:noinline
func Sum[E int | float64](xs []E) E {
	var s E
	for _, x := range xs {
		s += x
	}
	return s
}

type Box struct{ v int }

//go:noinline
func (b *Box) Get() int { return b.v }

func Use() func() int {
	b := &Box{v: int(Table[0])}
	return b.Get
}
`
}

const appMain = `package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"os"

	"example.com/big"
	"example.com/vulnmod"
)

func main() {
	var b bytes.Buffer
	_ = gob.NewEncoder(&b).Encode(os.Args)
	get := big.Use()
	fmt.Fprintln(os.Stdout, b.Len(), vulnmod.Bad(len(os.Args)), big.Table[len(os.Args)],
		big.Sum([]int{1}), big.Sum([]float64{2}), get())
	if f, err := os.Open("x"); err == nil {
		f.Close()
	}
}
`

// newWorld publishes the fixture modules and vulnerabilities.
func newWorld(t *testing.T) *testenv.World {
	t.Helper()
	w := testenv.New(t)
	for _, v := range []string{"v1.0.0", "v1.1.0"} {
		w.AddModule("example.com/vulnmod", v, map[string]string{
			"vulnmod.go":     vulnmodSrc,
			"other/other.go": "package other\n\nfunc Thing() int { return 1 }\n",
		})
	}
	w.AddModule("example.com/big", "v1.0.0", map[string]string{"big.go": bigSrc(65536)})
	w.AddModule("example.com/big", "v1.1.0", map[string]string{"big.go": bigSrc(262144)})
	return w
}

func addVulns(w *testenv.World) {
	w.AddVuln(testenv.SimpleVuln("GO-2025-0001", "example.com/vulnmod", "0", "1.1.0", "example.com/vulnmod", []string{"Bad"}, "CVE-2025-0001"))
	w.AddVuln(testenv.SimpleVuln("GO-2025-0002", "example.com/vulnmod", "0", "1.1.0", "example.com/vulnmod", []string{"Unused"}))
	w.AddVuln(testenv.SimpleVuln("GO-2025-0003", "example.com/vulnmod", "0", "1.1.0", "example.com/vulnmod/other", []string{"Thing"}))
	// A standard library symbol the compiler can never inline (its body
	// has a defer), so it has its own function table entry in every Go
	// version. (encoding/json.Marshal is inlined by newer compilers.)
	w.AddVuln(testenv.SimpleVuln("GO-2025-1000", vulndb.Stdlib, "0", "1.99.0", "encoding/gob", []string{"Encoder.EncodeValue"}))
	w.AddVuln(testenv.SimpleVuln("GO-2025-1001", vulndb.Stdlib, "0", "1.99.0", "net/smtp", []string{"SendMail"}))
	win := testenv.SimpleVuln("GO-2025-1002", vulndb.Stdlib, "0", "1.99.0", "os", nil)
	win.Affected[0].EcosystemSpecific.Imports[0].GOOS = []string{"windows"}
	w.AddVuln(win)
	// Withdrawn and out-of-range entries must not match.
	old := testenv.SimpleVuln("GO-2025-0004", "example.com/vulnmod", "0", "0.9.0", "example.com/vulnmod", []string{"Bad"})
	w.AddVuln(old)
	w.KEV = []map[string]string{{"cveID": "CVE-2025-0001", "vendorProject": "example", "product": "vulnmod", "vulnerabilityName": "test"}}
}

// app writes the application module requiring the given versions.
func app(t *testing.T, w *testenv.World, vulnVer, bigVer string) string {
	t.Helper()
	dir := w.Project(map[string]string{
		"go.mod":  testenv.GoModFile("example.com/app", "1.21", "example.com/vulnmod@"+vulnVer, "example.com/big@"+bigVer),
		"main.go": appMain,
	})
	if out, err := w.Go(dir, "mod", "tidy"); err != nil {
		t.Fatalf("go mod tidy: %v\n%s", err, out)
	}
	return dir
}

// build compiles the module in dir to dir/out.
func build(t *testing.T, w *testenv.World, dir, out string, env []string, flags ...string) string {
	t.Helper()
	bin := filepath.Join(dir, out)
	args := append([]string{"build", "-o", bin}, flags...)
	args = append(args, ".")
	if o, err := w.GoEnv(dir, env, args...); err != nil {
		t.Fatalf("go %v: %v\n%s", args, err, o)
	}
	return bin
}

func goVersion(t *testing.T, w *testenv.World, dir string) string {
	t.Helper()
	out, err := w.Go(dir, "env", "GOVERSION")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out)
}

// releases makes go.dev list v as the newest patch of the newest line.
func releases(w *testenv.World, versions ...string) {
	w.GoReleases = nil
	for _, v := range versions {
		w.GoReleases = append(w.GoReleases, map[string]any{"version": v, "stable": true})
	}
}

func exit(t *testing.T, r testenv.Result, want int) {
	t.Helper()
	if r.Code != want {
		t.Fatalf("exit code %d, want %d\nstdout:\n%s\nstderr:\n%s", r.Code, want, r.Stdout, r.Stderr)
	}
}
