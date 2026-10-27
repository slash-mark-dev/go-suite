package binary_test

import (
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

type cgoOut struct {
	Dir      string `json:"dir"`
	Packages []struct {
		ImportPath string   `json:"importPath"`
		Module     string   `json:"module"`
		Version    string   `json:"version"`
		Standard   bool     `json:"standard"`
		CgoFiles   []string `json:"cgoFiles"`
		CFiles     []string `json:"cFiles"`
		Libraries  []struct {
			Name    string   `json:"name"`
			Kind    string   `json:"kind"`
			Targets []string `json:"targets"`
		} `json:"libraries"`
		Constraints []struct {
			File       string `json:"file"`
			Constraint string `json:"constraint"`
			ImportsC   bool   `json:"importsC"`
		} `json:"constraints"`
		Targets []string `json:"targets"`
		Via     []string `json:"via"`
	} `json:"packages"`
	StdCgo    []string `json:"stdCgoPackages"`
	Libraries []struct {
		Name, Kind string
		Targets    []string
	} `json:"libraries"`
	Targets []struct {
		Target      string   `json:"target"`
		Prediction  string   `json:"prediction"`
		CgoPackages []string `json:"cgoPackages"`
		Fallbacks   []string `json:"fallbacks"`
		Blockers    []struct {
			Package string   `json:"package"`
			Module  string   `json:"module"`
			Reason  string   `json:"reason"`
			Files   []string `json:"files"`
			Via     []string `json:"via"`
		} `json:"blockers"`
		CrossCC bool `json:"needsCrossCompiler"`
		Verify  *struct {
			Command string `json:"command"`
			OK      bool   `json:"ok"`
			Output  string `json:"output"`
			Agrees  bool   `json:"agreesWithPrediction"`
		} `json:"verify"`
	} `json:"targets"`
	Findings []struct {
		Rule    string `json:"rule"`
		Package string `json:"package"`
	} `json:"findings"`
}

func cgoProject(t *testing.T, w *testenv.World) string {
	t.Helper()
	w.AddModule("example.com/cdep", "v1.0.0", map[string]string{
		"cdep_cgo.go": `//go:build cgo

package cdep

/*
#cgo pkg-config: libpng
#cgo darwin LDFLAGS: -framework CoreFoundation
#include <stdlib.h>
*/
import "C"

func Mode() string { return "cgo" }
`,
		"cdep_pure.go": "//go:build !cgo\n\npackage cdep\n\nfunc Mode() string { return \"pure\" }\n",
	})
	dir := w.Project(map[string]string{
		"go.mod": testenv.GoModFile("example.com/capp", "1.21", "example.com/cdep@v1.0.0"),
		// Fallback by build tag.
		"sqlish/sqlish_cgo.go": `//go:build cgo

package sqlish

/*
#cgo LDFLAGS: -lsqlite3 -lm
#include <stdlib.h>
*/
import "C"

func Name() string { return "cgo" }
`,
		"sqlish/sqlish_pure.go": "//go:build !cgo\n\npackage sqlish\n\nfunc Name() string { return \"pure\" }\n",
		// cgo only: no Go files left without cgo.
		"gpu/gpu.go": `package gpu

/*
#cgo LDFLAGS: -lcuda
int twice(int x);
*/
import "C"

func Twice(x int) int { return int(C.twice(C.int(x))) }
`,
		"gpu/gpu.c": "int twice(int x) { return 2*x; }\n",
		// Pure Go file plus C sources: C files cannot be compiled without cgo.
		"hash/hash.go":     "package hash\n\nfunc Sum(b []byte) int { return len(b) }\n",
		"hash/hash_cgo.go": "package hash\n\n// int fast(void);\nimport \"C\"\n\nfunc Fast() int { return int(C.fast()) }\n",
		"hash/fast.c":      "int fast(void) { return 1; }\n",
		// cgo on Linux only.
		"rt/rt_linux.go": `package rt

/*
#cgo linux LDFLAGS: -lrt
#include <time.h>
*/
import "C"

func Clock() int { return int(C.CLOCK_MONOTONIC) }
`,
		"rt/rt_other.go": "//go:build !linux\n\npackage rt\n\nfunc Clock() int { return 1 }\n",
		"cmd/good/main.go": `package main

import (
	"fmt"

	"example.com/capp/sqlish"
	"example.com/cdep"
)

func main() { fmt.Println(sqlish.Name(), cdep.Mode()) }
`,
		"cmd/bad/main.go": `package main

import (
	"fmt"

	"example.com/capp/gpu"
	"example.com/capp/hash"
)

func main() { fmt.Println(gpu.Twice(1), hash.Sum(nil)) }
`,
		"cmd/linuxonly/main.go": "package main\n\nimport (\n\t\"fmt\"\n\n\t\"example.com/capp/rt\"\n)\n\nfunc main() { fmt.Println(rt.Clock()) }\n",
		"cmd/pure/main.go":      "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hi\") }\n",
	})
	if out, err := w.Go(dir, "mod", "tidy"); err != nil {
		t.Fatalf("go mod tidy: %v\n%s", err, out)
	}
	return dir
}

func targetByName(out cgoOut, name string) int {
	for i, t := range out.Targets {
		if t.Target == name {
			return i
		}
	}
	return -1
}

func TestCgo(t *testing.T) {
	w := testenv.New(t)
	dir := cgoProject(t, w)

	t.Run("fallback", func(t *testing.T) {
		r := w.Run(dir, "cgo", "./cmd/good", "--json")
		exit(t, r, 0)
		var out cgoOut
		r.Decode(t, &out)
		if len(out.Targets) != 4 {
			t.Fatalf("default targets: %+v", out.Targets)
		}
		for _, tr := range out.Targets {
			if tr.Prediction != "fallback" || len(tr.Blockers) != 0 {
				t.Errorf("%s: %s %+v", tr.Target, tr.Prediction, tr.Blockers)
			}
		}
		pk := map[string]int{}
		for i, p := range out.Packages {
			pk[p.ImportPath] = i
			if p.Standard {
				t.Errorf("std package %s listed without --std", p.ImportPath)
			}
		}
		i, ok := pk["example.com/capp/sqlish"]
		if !ok {
			t.Fatalf("packages: %+v", out.Packages)
		}
		sq := out.Packages[i]
		libs := map[string]string{}
		for _, l := range sq.Libraries {
			libs[l.Name] = l.Kind
		}
		if libs["sqlite3"] != "lib" || libs["m"] != "lib" || len(sq.CgoFiles) != 1 || len(sq.Targets) != 4 {
			t.Errorf("sqlish: %+v", sq)
		}
		cons := map[string]string{}
		for _, c := range sq.Constraints {
			cons[c.File] = c.Constraint
		}
		if cons["sqlish_cgo.go"] != "cgo" || cons["sqlish_pure.go"] != "!cgo" {
			t.Errorf("constraints %v", cons)
		}
		if strings.Join(sq.Via, " ") != "example.com/capp/cmd/good example.com/capp/sqlish" {
			t.Errorf("via %v", sq.Via)
		}
		j, ok := pk["example.com/cdep"]
		if !ok {
			t.Fatalf("dependency cgo package missing: %+v", out.Packages)
		}
		cd := out.Packages[j]
		if cd.Module != "example.com/cdep" || cd.Version != "v1.0.0" {
			t.Errorf("cdep: %+v", cd)
		}
		for _, l := range cd.Libraries {
			switch l.Name {
			case "libpng":
				if l.Kind != "pkg-config" || len(l.Targets) != 4 {
					t.Errorf("libpng %+v", l)
				}
			case "CoreFoundation":
				if l.Kind != "framework" || strings.Join(l.Targets, ",") != "darwin/arm64" {
					t.Errorf("CoreFoundation %+v", l)
				}
			default:
				t.Errorf("unexpected library %+v", l)
			}
		}
		lin := out.Targets[targetByName(out, "linux/arm64")]
		if !lin.CrossCC && !strings.HasSuffix(lin.Target, "/amd64") {
			t.Errorf("cross target should need a C cross-compiler: %+v", lin)
		}
	})

	t.Run("blockers", func(t *testing.T) {
		r := w.Run(dir, "cgo", "./cmd/bad", "--targets", "linux/amd64,windows/amd64", "--json")
		exit(t, r, 1)
		var out cgoOut
		r.Decode(t, &out)
		if len(out.Targets) != 2 {
			t.Fatalf("targets %+v", out.Targets)
		}
		for _, tr := range out.Targets {
			if tr.Prediction != "fail" || len(tr.Blockers) != 2 {
				t.Fatalf("%s: %s %+v", tr.Target, tr.Prediction, tr.Blockers)
			}
			gpu, hash := tr.Blockers[0], tr.Blockers[1]
			if gpu.Package != "example.com/capp/gpu" || !strings.Contains(gpu.Reason, "no Go files remain") ||
				strings.Join(gpu.Via, " ") != "example.com/capp/cmd/bad example.com/capp/gpu" {
				t.Errorf("gpu blocker %+v", gpu)
			}
			if hash.Package != "example.com/capp/hash" || !strings.Contains(hash.Reason, "fast.c") || len(hash.Files) != 1 {
				t.Errorf("hash blocker %+v", hash)
			}
		}
		if len(out.Findings) != 4 || out.Findings[0].Rule != "cgo-required" {
			t.Errorf("findings %+v", out.Findings)
		}
	})

	t.Run("per-target", func(t *testing.T) {
		r := w.Run(dir, "cgo", "./cmd/linuxonly", "--targets", "linux/amd64,linux/arm64,darwin/arm64,windows/amd64", "--json")
		exit(t, r, 1)
		var out cgoOut
		r.Decode(t, &out)
		want := map[string]string{"linux/amd64": "fail", "linux/arm64": "fail", "darwin/arm64": "ok", "windows/amd64": "ok"}
		for _, tr := range out.Targets {
			if tr.Prediction != want[tr.Target] {
				t.Errorf("%s: %s, want %s (%+v)", tr.Target, tr.Prediction, want[tr.Target], tr.Blockers)
			}
		}
		if len(out.Packages) != 1 || out.Packages[0].ImportPath != "example.com/capp/rt" || strings.Join(out.Packages[0].Targets, ",") != "linux/amd64,linux/arm64" {
			t.Errorf("packages %+v", out.Packages)
		}
		if len(out.Libraries) != 1 || out.Libraries[0].Name != "rt" {
			t.Errorf("libraries %+v", out.Libraries)
		}
	})

	t.Run("pure", func(t *testing.T) {
		r := w.Run(dir, "cgo", "./cmd/pure", "--targets", "linux/amd64,windows/amd64", "--json")
		exit(t, r, 0)
		var out cgoOut
		r.Decode(t, &out)
		for _, tr := range out.Targets {
			if tr.Prediction != "ok" || len(tr.CgoPackages) != 0 {
				t.Errorf("%s: %s %v", tr.Target, tr.Prediction, tr.CgoPackages)
			}
		}
		if len(out.Packages) != 0 || len(out.Findings) != 0 {
			t.Errorf("pure program: %+v", out)
		}
	})

	t.Run("verify", func(t *testing.T) {
		r := w.Run(dir, "cgo", "./cmd/bad", "./cmd/good", "--targets", "linux/amd64,windows/amd64", "--verify", "--json")
		exit(t, r, 1)
		var out cgoOut
		r.Decode(t, &out)
		for _, tr := range out.Targets {
			if tr.Verify == nil || tr.Verify.OK || !tr.Verify.Agrees || !strings.Contains(tr.Verify.Command, "CGO_ENABLED=0") {
				t.Errorf("%s verify %+v", tr.Target, tr.Verify)
			}
		}
		r = w.Run(dir, "cgo", "./cmd/good", "./cmd/pure", "--targets", "linux/amd64,windows/amd64", "--verify", "--json")
		exit(t, r, 0)
		r.Decode(t, &out)
		for _, tr := range out.Targets {
			if tr.Verify == nil || !tr.Verify.OK || !tr.Verify.Agrees {
				t.Errorf("%s verify %+v", tr.Target, tr.Verify)
			}
		}
	})

	t.Run("text", func(t *testing.T) {
		r := w.Run(dir, "cgo", "./cmd/bad", "./cmd/good", "--targets", "linux/amd64,darwin/arm64")
		exit(t, r, 1)
		for _, s := range []string{"sm-go cgo", "example.com/capp/gpu", "-lcuda", "pkg-config libpng", "✗ fails",
			"no Go files remain", "imported via example.com/capp/cmd/bad → example.com/capp/gpu", "blockers"} {
			if !strings.Contains(r.Stdout, s) {
				t.Errorf("text lacks %q\n%s", s, r.Stdout)
			}
		}
	})

	t.Run("std", func(t *testing.T) {
		r := w.Run(dir, "cgo", "./cmd/good", "--targets", "linux/amd64", "--std", "--json")
		exit(t, r, 0)
		var out cgoOut
		r.Decode(t, &out)
		if len(out.StdCgo) == 0 {
			t.Skip("no standard-library cgo packages for this program")
		}
		std := false
		for _, p := range out.Packages {
			std = std || p.Standard
		}
		if !std {
			t.Errorf("--std did not list std packages: %+v", out.StdCgo)
		}
	})

	t.Run("usage", func(t *testing.T) {
		exit(t, w.Run(dir, "cgo", "--targets", "linux"), 2)
		exit(t, w.Run(dir, "cgo", "./cmd/pure", "--targets", "plan10/amd64"), 2)
		exit(t, w.Run(dir, "cgo", "./nonexistent/..."), 2)
		exit(t, w.Run(t.TempDir(), "cgo"), 2)
	})
}
