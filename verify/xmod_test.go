// Differential tests: sm-go's own implementations versus golang.org/x/mod,
// the code the go command itself uses. Run ./setup.sh first.
package verify

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	xmodfile "golang.org/x/mod/modfile"
	xmodule "golang.org/x/mod/module"
	xsemver "golang.org/x/mod/semver"
	xsumdb "golang.org/x/mod/sumdb"
	xdirhash "golang.org/x/mod/sumdb/dirhash"
	xnote "golang.org/x/mod/sumdb/note"
	xtlog "golang.org/x/mod/sumdb/tlog"

	"context"

	"github.com/slash-mark-dev/go-suite/internal/goenv"
	"github.com/slash-mark-dev/go-suite/internal/httpx"
	"github.com/slash-mark-dev/go-suite/internal/modfile"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/modzip"
	"github.com/slash-mark-dev/go-suite/internal/semver"
	"github.com/slash-mark-dev/go-suite/internal/sumdb"
)

var stats = map[string]int{}

func count(name string, n int) { stats[name] += n }

func TestMain(m *testing.M) {
	code := m.Run()
	if len(stats) > 0 {
		fmt.Println("differential comparisons:")
		total := 0
		for _, k := range sortedKeys(stats) {
			fmt.Printf("  %-28s %9d\n", k, stats[k])
			total += stats[k]
		}
		fmt.Printf("  %-28s %9d\n", "TOTAL", total)
	}
	os.Exit(code)
}

func sortedKeys(m map[string]int) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	for i := range ks {
		for j := i + 1; j < len(ks); j++ {
			if ks[j] < ks[i] {
				ks[i], ks[j] = ks[j], ks[i]
			}
		}
	}
	return ks
}

// ---------- semver ----------

func versionCorpus(r *mrand.Rand) []string {
	base := []string{"", "v", "v0", "v1", "v1.2", "v1.2.3", "v01.2.3", "v1.02.3", "v1.2.03", "v1.2.3-pre", "v1.2.3-pre.1",
		"v1.2.3-pre.01", "v1.2.3-01", "v1.2.3-0", "v1.2.3+build", "v1.2.3-pre+build", "v1.2-pre", "v1-pre", "v1.2+meta",
		"v1.2.3-", "v1.2.3+", "v1.2.3-.", "v1.2.3-a..b", "v1.2.3+a..b", "1.2.3", "v1.2.3.4", "v1.2.3-alpha.beta.1",
		"v1.2.3-rc.1", "v1.2.3-rc.10", "v1.2.3-rc.2", "v2.0.0+incompatible", "v0.0.0-20200101000000-abcdefabcdef",
		"v1.2.4-0.20200101000000-abcdefabcdef", "v1.2.3-pre.0.20200101000000-abcdefabcdef", "v99999999999999999999.0.0",
		"v1.0.0-x-y", "v1.0.0-Ab", "v1.0.0-a-", "v1.0.0+00", "v1.0.0-00a", "v1.0.0-0a", "v1.0.0-a.0", "v1.0.0-1.a",
	}
	alpha := "v0123456789.-+arcbx"
	for i := 0; i < 20000; i++ {
		n := 1 + r.Intn(14)
		var b strings.Builder
		if r.Intn(10) > 0 {
			b.WriteByte('v')
			n--
		}
		for j := 0; j < n; j++ {
			b.WriteByte(alpha[r.Intn(len(alpha))])
		}
		base = append(base, b.String())
	}
	// structured random valid-ish versions
	for i := 0; i < 20000; i++ {
		v := fmt.Sprintf("v%d.%d.%d", r.Intn(3), r.Intn(12), r.Intn(12))
		switch r.Intn(5) {
		case 0:
			v += "-" + []string{"alpha", "beta", "rc", "0", "1", "pre"}[r.Intn(6)]
			if r.Intn(2) == 0 {
				v += fmt.Sprintf(".%d", r.Intn(12))
			}
		case 1:
			v += "+build" + fmt.Sprint(r.Intn(3))
		}
		base = append(base, v)
	}
	return base
}

func TestSemverDifferential(t *testing.T) {
	r := mrand.New(mrand.NewSource(1))
	vs := versionCorpus(r)
	for _, v := range vs {
		if a, b := semver.IsValid(v), xsemver.IsValid(v); a != b {
			t.Errorf("IsValid(%q) = %v, x/mod %v", v, a, b)
		}
		if a, b := semver.Canonical(v), xsemver.Canonical(v); a != b {
			t.Errorf("Canonical(%q) = %q, x/mod %q", v, a, b)
		}
		if a, b := semver.Major(v), xsemver.Major(v); a != b {
			t.Errorf("Major(%q) = %q, x/mod %q", v, a, b)
		}
		if a, b := semver.MajorMinor(v), xsemver.MajorMinor(v); a != b {
			t.Errorf("MajorMinor(%q) = %q, x/mod %q", v, a, b)
		}
		if a, b := semver.Prerelease(v), xsemver.Prerelease(v); a != b {
			t.Errorf("Prerelease(%q) = %q, x/mod %q", v, a, b)
		}
		if a, b := semver.Build(v), xsemver.Build(v); a != b {
			t.Errorf("Build(%q) = %q, x/mod %q", v, a, b)
		}
		count("semver unary", 6)
	}
	for i := 0; i < 400000; i++ {
		v, w := vs[r.Intn(len(vs))], vs[r.Intn(len(vs))]
		if a, b := semver.Compare(v, w), xsemver.Compare(v, w); a != b {
			t.Fatalf("Compare(%q, %q) = %d, x/mod %d", v, w, a, b)
		}
		if a, b := semver.Max(v, w), xsemver.Max(v, w); a != b {
			t.Fatalf("Max(%q, %q) = %q, x/mod %q", v, w, a, b)
		}
		count("semver compare/max", 2)
	}
}

// ---------- module ----------

func pathCorpus(r *mrand.Rand) []string {
	ps := []string{"", "a", "a.b", "example.com", "example.com/x", "Example.com/x", "example.com/X/Y", "example.com/x/v2",
		"example.com/x/v1", "example.com/x/v0", "example.com/x/v2.1", "example.com/x/v02", "gopkg.in/yaml.v2",
		"gopkg.in/yaml.v0", "gopkg.in/yaml.v1", "gopkg.in/check.v1-unstable", "gopkg.in/yaml", "gopkg.in/x.v01",
		"-x.com/y", "x.com/-y", "x.com//y", "x.com/y/", "/x.com", "x.com/.y", "x.com/y.", "x.com/con", "x.com/CON.txt",
		"x.com/a~1", "x.com/a~b", "x.com/a+b", "x.com/a@b", "x_y.com/z", "x.com/ü", "github.com/Azure/azure-sdk",
		"github.com/user/repo/v3/sub", "example.com/v2", "x.com/.../y", "x.com/a b",
	}
	alpha := "abcXYZ019./-_~+.v"
	for i := 0; i < 30000; i++ {
		n := 3 + r.Intn(18)
		var b strings.Builder
		if r.Intn(4) > 0 {
			b.WriteString([]string{"example.com/", "github.com/", "gopkg.in/", "x.org/"}[r.Intn(4)])
		}
		for j := 0; j < n; j++ {
			b.WriteByte(alpha[r.Intn(len(alpha))])
		}
		ps = append(ps, b.String())
	}
	return ps
}

func errEq(a, b error) bool { return (a == nil) == (b == nil) }

func TestModuleDifferential(t *testing.T) {
	r := mrand.New(mrand.NewSource(2))
	for _, p := range pathCorpus(r) {
		if a, b := module.CheckPath(p), xmodule.CheckPath(p); !errEq(a, b) {
			t.Errorf("CheckPath(%q) = %v, x/mod %v", p, a, b)
		}
		if a, b := module.CheckImportPath(p), xmodule.CheckImportPath(p); !errEq(a, b) {
			t.Errorf("CheckImportPath(%q) = %v, x/mod %v", p, a, b)
		}
		e1, err1 := module.EscapePath(p)
		e2, err2 := xmodule.EscapePath(p)
		if e1 != e2 || !errEq(err1, err2) {
			t.Errorf("EscapePath(%q) = %q,%v x/mod %q,%v", p, e1, err1, e2, err2)
		}
		u1, err1 := module.UnescapePath(p)
		u2, err2 := xmodule.UnescapePath(p)
		if u1 != u2 || !errEq(err1, err2) {
			t.Errorf("UnescapePath(%q) = %q,%v x/mod %q,%v", p, u1, err1, u2, err2)
		}
		a1, b1, c1 := module.SplitPathVersion(p)
		a2, b2, c2 := xmodule.SplitPathVersion(p)
		if a1 != a2 || b1 != b2 || c1 != c2 {
			t.Errorf("SplitPathVersion(%q) = %q %q %v, x/mod %q %q %v", p, a1, b1, c1, a2, b2, c2)
		}
		count("module path funcs", 5)
		if c1 {
			for _, v := range []string{"v0.1.0", "v1.0.0", "v2.0.0", "v2.0.0+incompatible", "v3.1.0", "v0.0.0-20200101000000-abcdefabcdef", "v1.0.0-unstable"} {
				if a, b := module.CheckPathMajor(v, b1), xmodule.CheckPathMajor(v, b1); !errEq(a, b) {
					t.Errorf("CheckPathMajor(%q, %q) = %v, x/mod %v", v, b1, a, b)
				}
				count("module CheckPathMajor", 1)
			}
			if a, b := module.PathMajorPrefix(b1), xmodule.PathMajorPrefix(b1); a != b {
				t.Errorf("PathMajorPrefix(%q) = %q, x/mod %q", b1, a, b)
			}
		}
	}
	vs := versionCorpus(r)
	for _, v := range vs {
		e1, err1 := module.EscapeVersion(v)
		e2, err2 := xmodule.EscapeVersion(v)
		if e1 != e2 || !errEq(err1, err2) {
			t.Errorf("EscapeVersion(%q) = %q,%v x/mod %q,%v", v, e1, err1, e2, err2)
		}
		if a, b := module.IsPseudoVersion(v), xmodule.IsPseudoVersion(v); a != b {
			t.Errorf("IsPseudoVersion(%q) = %v, x/mod %v", v, a, b)
		}
		count("module version funcs", 2)
	}
	pseudos := []string{}
	for i := 0; i < 3000; i++ {
		ts := fmt.Sprintf("2%03d%02d%02d%02d%02d%02d", r.Intn(1000), 1+r.Intn(12), 1+r.Intn(28), r.Intn(24), r.Intn(60), r.Intn(60))
		rev := fmt.Sprintf("%012x", r.Int63())
		maj := r.Intn(3)
		switch r.Intn(4) {
		case 0:
			pseudos = append(pseudos, fmt.Sprintf("v%d.0.0-%s-%s", maj, ts, rev))
		case 1:
			pseudos = append(pseudos, fmt.Sprintf("v%d.%d.%d-0.%s-%s", maj, r.Intn(5), 1+r.Intn(20), ts, rev))
		case 2:
			pseudos = append(pseudos, fmt.Sprintf("v%d.%d.%d-rc.%d.0.%s-%s", maj, r.Intn(5), r.Intn(20), r.Intn(3), ts, rev))
		case 3:
			pseudos = append(pseudos, fmt.Sprintf("v%d.%d.%d-0.%s-%s+incompatible", 2+maj, r.Intn(5), 1+r.Intn(20), ts, rev))
		}
	}
	for _, v := range append(pseudos, vs...) {
		b1, err1 := module.PseudoVersionBase(v)
		b2, err2 := xmodule.PseudoVersionBase(v)
		if b1 != b2 || !errEq(err1, err2) {
			t.Errorf("PseudoVersionBase(%q) = %q,%v x/mod %q,%v", v, b1, err1, b2, err2)
		}
		t1, err1 := module.PseudoVersionTime(v)
		t2, err2 := xmodule.PseudoVersionTime(v)
		if !t1.Equal(t2) || !errEq(err1, err2) {
			t.Errorf("PseudoVersionTime(%q) = %v,%v x/mod %v,%v", v, t1, err1, t2, err2)
		}
		r1, err1 := module.PseudoVersionRev(v)
		r2, err2 := xmodule.PseudoVersionRev(v)
		if r1 != r2 || !errEq(err1, err2) {
			t.Errorf("PseudoVersionRev(%q) = %q,%v x/mod %q,%v", v, r1, err1, r2, err2)
		}
		if a, b := module.IsZeroPseudoVersion(v), xmodule.IsZeroPseudoVersion(v); a != b {
			t.Errorf("IsZeroPseudoVersion(%q) = %v, x/mod %v", v, a, b)
		}
		count("module pseudo-version funcs", 4)
	}
	globs := []string{"", "*.corp.com", "rsc.io/private", "example.com/*", "*", "github.com/org/*,gitlab.com", "x.com/a/b/c"}
	for _, g := range globs {
		for _, p := range pathCorpus(r)[:3000] {
			if a, b := module.MatchPrefixPatterns(g, p), xmodule.MatchPrefixPatterns(g, p); a != b {
				t.Errorf("MatchPrefixPatterns(%q, %q) = %v, x/mod %v", g, p, a, b)
			}
			count("module MatchPrefixPatterns", 1)
		}
	}
}

// ---------- modfile ----------

// goModCorpus collects go.mod and go.work files from the Go distribution:
// real go.mod files and the many go.mod sections embedded in cmd/go's
// txtar test scripts.
func goModCorpus(t *testing.T) (mods, works map[string][]byte) {
	goroot := strings.TrimSpace(run(t, "go", "env", "GOROOT"))
	mods, works = map[string][]byte{}, map[string][]byte{}
	filepath.Walk(filepath.Join(goroot, "src"), func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if fi.Name() == "go.mod" {
			data, _ := os.ReadFile(p)
			mods[p] = data
		}
		if strings.HasSuffix(p, ".txt") && strings.Contains(p, filepath.Join("cmd", "go", "testdata")) {
			data, _ := os.ReadFile(p)
			for name, content := range txtarFiles(data) {
				switch filepath.Base(name) {
				case "go.mod", ".mod":
					mods[p+"#"+name] = content
				case "go.work":
					works[p+"#"+name] = content
				}
			}
		}
		return nil
	})
	return
}

func txtarFiles(data []byte) map[string][]byte {
	out := map[string][]byte{}
	lines := strings.SplitAfter(string(data), "\n")
	name := ""
	var buf strings.Builder
	flush := func() {
		if name != "" {
			out[name] = []byte(buf.String())
		}
		buf.Reset()
	}
	for _, l := range lines {
		tl := strings.TrimRight(l, "\r\n")
		if strings.HasPrefix(tl, "-- ") && strings.HasSuffix(tl, " --") && len(tl) > 6 {
			flush()
			name = strings.TrimSpace(tl[3 : len(tl)-3])
			continue
		}
		if name != "" {
			buf.WriteString(l)
		}
	}
	flush()
	return out
}

func run(t *testing.T, name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		t.Fatalf("%s %v: %v", name, args, err)
	}
	return string(out)
}

type modSummary struct {
	Module, Deprecated, Go, Toolchain string
	Require                           []string
	Exclude                           []string
	Replace                           []string
	Retract                           []string
	Godebug                           []string
	Tool                              []string
	Use                               []string
}

func summarizeOurs(f *modfile.File) modSummary {
	var s modSummary
	if f.Module != nil {
		s.Module, s.Deprecated = f.Module.Path, f.Module.Deprecated
	}
	s.Go, s.Toolchain = f.Go, f.Toolchain
	for _, r := range f.Require {
		s.Require = append(s.Require, fmt.Sprintf("%s %s %v", r.Mod.Path, r.Mod.Version, r.Indirect))
	}
	for _, r := range f.Exclude {
		s.Exclude = append(s.Exclude, r.Mod.String())
	}
	for _, r := range f.Replace {
		s.Replace = append(s.Replace, r.Old.String()+" => "+r.New.String())
	}
	for _, r := range f.Retract {
		s.Retract = append(s.Retract, fmt.Sprintf("[%s,%s] %q", r.Low, r.High, r.Rationale))
	}
	for _, g := range f.Godebug {
		s.Godebug = append(s.Godebug, g.Key+"="+g.Value)
	}
	for _, x := range f.Tool {
		s.Tool = append(s.Tool, x.Path)
	}
	for _, u := range f.Use {
		s.Use = append(s.Use, u.Path)
	}
	return s
}

func summarizeX(f *xmodfile.File) modSummary {
	var s modSummary
	if f.Module != nil {
		s.Module, s.Deprecated = f.Module.Mod.Path, f.Module.Deprecated
	}
	if f.Go != nil {
		s.Go = f.Go.Version
	}
	if f.Toolchain != nil {
		s.Toolchain = f.Toolchain.Name
	}
	for _, r := range f.Require {
		s.Require = append(s.Require, fmt.Sprintf("%s %s %v", r.Mod.Path, r.Mod.Version, r.Indirect))
	}
	for _, r := range f.Exclude {
		s.Exclude = append(s.Exclude, r.Mod.String())
	}
	for _, r := range f.Replace {
		s.Replace = append(s.Replace, r.Old.String()+" => "+r.New.String())
	}
	for _, r := range f.Retract {
		s.Retract = append(s.Retract, fmt.Sprintf("[%s,%s] %q", r.Low, r.High, r.Rationale))
	}
	for _, g := range f.Godebug {
		s.Godebug = append(s.Godebug, g.Key+"="+g.Value)
	}
	for _, x := range f.Tool {
		s.Tool = append(s.Tool, x.Path)
	}
	return s
}

func summarizeXWork(f *xmodfile.WorkFile) modSummary {
	var s modSummary
	if f.Go != nil {
		s.Go = f.Go.Version
	}
	if f.Toolchain != nil {
		s.Toolchain = f.Toolchain.Name
	}
	for _, r := range f.Replace {
		s.Replace = append(s.Replace, r.Old.String()+" => "+r.New.String())
	}
	for _, g := range f.Godebug {
		s.Godebug = append(s.Godebug, g.Key+"="+g.Value)
	}
	for _, u := range f.Use {
		s.Use = append(s.Use, u.Path)
	}
	return s
}

func TestModfileDifferential(t *testing.T) {
	mods, works := goModCorpus(t)
	if len(mods) < 500 {
		t.Fatalf("corpus too small: %d go.mod files", len(mods))
	}
	compared, skipped := 0, 0
	for name, data := range mods {
		xf, err := xmodfile.Parse(name, data, nil)
		if err != nil {
			skipped++
			continue
		}
		ours := modfile.Parse(name, data)
		a, b := summarizeOurs(ours), summarizeX(xf)
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s:\n ours %+v\n x/mod %+v\n--- file:\n%s", name, a, b, data)
		}
		if len(ours.Errors) > 0 {
			t.Errorf("%s: x/mod accepts the file but we report %v", name, ours.Errors)
		}
		compared++
	}
	for name, data := range works {
		xf, err := xmodfile.ParseWork(name, data, nil)
		if err != nil {
			skipped++
			continue
		}
		ours := modfile.ParseWork(name, data)
		a, b := summarizeOurs(ours), summarizeXWork(xf)
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s:\n ours %+v\n x/mod %+v", name, a, b)
		}
		compared++
	}
	// Files x/mod rejects must produce at least one error in ours.
	rejectedButAccepted := 0
	for name, data := range mods {
		if _, err := xmodfile.Parse(name, data, nil); err != nil {
			if len(modfile.Parse(name, data).Errors) == 0 {
				rejectedButAccepted++
				t.Logf("x/mod rejects %s (%v) but we report no error", name, err)
			}
		}
	}
	t.Logf("compared %d files (%d skipped because x/mod rejects them; %d of those parse cleanly here)", compared, skipped, rejectedButAccepted)
	count("modfile files", compared)
}

// ---------- tlog ----------

type xHashes []xtlog.Hash

func (h xHashes) ReadHashes(idx []int64) ([]xtlog.Hash, error) {
	out := make([]xtlog.Hash, len(idx))
	for i, x := range idx {
		out[i] = h[x]
	}
	return out, nil
}

func TestTlogDifferential(t *testing.T) {
	r := mrand.New(mrand.NewSource(3))
	var xh xHashes
	var oh []sumdb.Hash
	oread := sumdb.HashReaderFunc(func(idx []int64) ([]sumdb.Hash, error) {
		out := make([]sumdb.Hash, len(idx))
		for i, x := range idx {
			out[i] = oh[x]
		}
		return out, nil
	})
	const N = 1500
	var xroots []xtlog.Hash
	for n := int64(0); n < N; n++ {
		data := []byte(fmt.Sprintf("record %d %d\n", n, r.Int63()))
		xs, err := xtlog.StoredHashes(n, data, xh)
		if err != nil {
			t.Fatal(err)
		}
		os, err := sumdb.StoredHashes(n, data, oread)
		if err != nil {
			t.Fatal(err)
		}
		if len(xs) != len(os) {
			t.Fatalf("StoredHashes(%d): %d hashes vs x/mod %d", n, len(os), len(xs))
		}
		for i := range xs {
			if [32]byte(xs[i]) != [32]byte(os[i]) {
				t.Fatalf("StoredHashes(%d)[%d] differs", n, i)
			}
		}
		xh = append(xh, xs...)
		oh = append(oh, os...)
		if c1, c2 := sumdb.StoredHashCount(n+1), xtlog.StoredHashCount(n+1); c1 != c2 {
			t.Fatalf("StoredHashCount(%d) = %d vs %d", n+1, c1, c2)
		}
		x1, _ := xtlog.TreeHash(n+1, xh)
		o1, _ := sumdb.TreeHash(n+1, oread)
		if [32]byte(x1) != [32]byte(o1) {
			t.Fatalf("TreeHash(%d) differs", n+1)
		}
		xroots = append(xroots, x1)
		count("tlog stored+tree hashes", 3)
	}
	for i := 0; i < 20000; i++ {
		tsize := 1 + r.Int63n(N)
		n := r.Int63n(tsize)
		xp, err1 := xtlog.ProveRecord(tsize, n, xh)
		op, err2 := sumdb.ProveRecord(tsize, n, oread)
		if !errEq(err1, err2) || len(xp) != len(op) {
			t.Fatalf("ProveRecord(%d,%d) mismatch", tsize, n)
		}
		for j := range xp {
			if [32]byte(xp[j]) != [32]byte(op[j]) {
				t.Fatalf("ProveRecord(%d,%d)[%d] differs", tsize, n, j)
			}
		}
		leaf := oh[sumdb.StoredHashIndex(0, n)]
		if err := sumdb.CheckRecord(op, tsize, sumdb.Hash(xroots[tsize-1]), n, leaf); err != nil {
			t.Fatalf("CheckRecord(%d,%d): %v", tsize, n, err)
		}
		// tampered proof must fail
		if len(op) > 0 {
			bad := append(sumdb.RecordProof(nil), op...)
			bad[r.Intn(len(bad))][0] ^= 1
			if sumdb.CheckRecord(bad, tsize, sumdb.Hash(xroots[tsize-1]), n, leaf) == nil {
				t.Fatalf("tampered record proof accepted")
			}
		}
		m := 1 + r.Int63n(tsize)
		xt, err1 := xtlog.ProveTree(tsize, m, xh)
		ot, err2 := sumdb.ProveTree(tsize, m, oread)
		if !errEq(err1, err2) || len(xt) != len(ot) {
			t.Fatalf("ProveTree(%d,%d) mismatch", tsize, m)
		}
		for j := range xt {
			if [32]byte(xt[j]) != [32]byte(ot[j]) {
				t.Fatalf("ProveTree(%d,%d)[%d] differs", tsize, m, j)
			}
		}
		if err := sumdb.CheckTree(ot, tsize, sumdb.Hash(xroots[tsize-1]), m, sumdb.Hash(xroots[m-1])); err != nil {
			t.Fatalf("CheckTree(%d,%d): %v", tsize, m, err)
		}
		if err := xtlog.CheckTree(xt, tsize, xroots[tsize-1], m, xroots[m-1]); err != nil {
			t.Fatalf("x/mod CheckTree(%d,%d): %v", tsize, m, err)
		}
		count("tlog proofs", 6)
	}
	// tiles
	for i := 0; i < 20000; i++ {
		idx := r.Int63n(int64(len(oh)))
		h := 1 + r.Intn(8)
		xt := xtlog.TileForIndex(h, idx)
		ot := sumdb.TileForIndex(h, idx)
		if xt.H != ot.H || xt.L != ot.L || xt.N != ot.N || xt.W != ot.W {
			t.Fatalf("TileForIndex(%d,%d) = %+v, x/mod %+v", h, idx, ot, xt)
		}
		if xt.Path() != ot.Path() {
			t.Fatalf("Tile.Path %q vs %q", ot.Path(), xt.Path())
		}
		pt, err := sumdb.ParseTilePath(xt.Path())
		if err != nil || pt != ot {
			t.Fatalf("ParseTilePath(%q) = %+v, %v", xt.Path(), pt, err)
		}
		data, err := xtlog.ReadTileData(xt, xh)
		if err != nil {
			t.Fatal(err)
		}
		x1, err1 := xtlog.HashFromTile(xt, data, idx)
		o1, err2 := sumdb.HashFromTile(ot, data, idx)
		if !errEq(err1, err2) || [32]byte(x1) != [32]byte(o1) {
			t.Fatalf("HashFromTile mismatch at %d", idx)
		}
		count("tlog tiles", 4)
	}
}

// ---------- notes ----------

func TestNoteDifferential(t *testing.T) {
	for i := 0; i < 50; i++ {
		name := fmt.Sprintf("sum.example%d.org", i)
		xskey, xvkey, err := xnote.GenerateKey(rand.Reader, name)
		if err != nil {
			t.Fatal(err)
		}
		oSigner, err := sumdb.NewSigner(xskey)
		if err != nil {
			t.Fatalf("NewSigner(x/mod key): %v", err)
		}
		oVerifier, err := sumdb.NewVerifier(xvkey)
		if err != nil {
			t.Fatalf("NewVerifier(x/mod key): %v", err)
		}
		text := fmt.Sprintf("go.sum database tree\n%d\nqmzK7AXSFTm2r1RJyJcYb3oYhpx9XN0OUyXvcBUMGqA=\n", i)
		// x/mod signs, we verify
		xs, _ := xnote.NewSigner(xskey)
		msg, err := xnote.Sign(&xnote.Note{Text: text}, xs)
		if err != nil {
			t.Fatal(err)
		}
		n, err := sumdb.OpenNote(msg, oVerifier)
		if err != nil || n.Text != text {
			t.Fatalf("OpenNote(x/mod signed): %v", err)
		}
		// we sign, x/mod verifies
		msg2, err := oSigner.Sign(text)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(msg, msg2) {
			t.Fatalf("signatures differ:\n%s\n%s", msg, msg2)
		}
		xv, _ := xnote.NewVerifier(xvkey)
		if _, err := xnote.Open(msg2, xnote.VerifierList(xv)); err != nil {
			t.Fatalf("x/mod Open(our note): %v", err)
		}
		// tampered text must fail
		bad := bytes.Replace(msg2, []byte("tree\n"), []byte("tree\n1"), 1)
		if _, err := sumdb.OpenNote(bad, oVerifier); err == nil {
			t.Fatalf("tampered note accepted")
		}
		count("note sign/verify", 4)
	}
	// The real sum.golang.org key parses.
	if _, err := sumdb.NewVerifier(sumdb.KnownKeys["sum.golang.org"]); err != nil {
		t.Fatal(err)
	}
}

// ---------- dirhash ----------

func TestDirhashDifferential(t *testing.T) {
	r := mrand.New(mrand.NewSource(4))
	dir := t.TempDir()
	for i := 0; i < 300; i++ {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		nf := 1 + r.Intn(12)
		for j := 0; j < nf; j++ {
			w, _ := zw.Create(fmt.Sprintf("example.com/m@v1.0.%d/dir%d/file%d.go", i, r.Intn(3), j))
			content := make([]byte, r.Intn(5000))
			r.Read(content)
			w.Write(content)
		}
		zw.Close()
		zp := filepath.Join(dir, fmt.Sprintf("%d.zip", i))
		os.WriteFile(zp, buf.Bytes(), 0o644)
		x, err := xdirhash.HashZip(zp, xdirhash.Hash1)
		if err != nil {
			t.Fatal(err)
		}
		o, err := modzip.HashZip(buf.Bytes())
		if err != nil || o != x {
			t.Fatalf("HashZip = %q (%v), x/mod %q", o, err, x)
		}
		gomod := []byte(fmt.Sprintf("module example.com/m\n\ngo 1.%d\n", r.Intn(30)))
		x2, _ := xdirhash.Hash1([]string{"go.mod"}, func(string) (io_ReadCloser, error) { return nopCloser(gomod), nil })
		if o2 := modzip.HashGoMod(gomod); o2 != x2 {
			t.Fatalf("HashGoMod = %q, x/mod %q", o2, x2)
		}
		count("dirhash", 2)
	}
}

// ---------- sumdb client against the reference server ----------

// TestSumDBClientAgainstReferenceServer serves a checksum database with
// golang.org/x/mod/sumdb's own server code and verifies lookups, inclusion
// proofs and consistency proofs with sm-go's client.
func TestSumDBClientAgainstReferenceServer(t *testing.T) {
	skey, vkey, err := xnote.GenerateKey(rand.Reader, "sum.ref.test")
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := xnote.NewSigner(skey)
	records := map[string][]byte{}
	gosum := func(path, vers string) ([]byte, error) {
		key := path + "@" + vers
		if b, ok := records[key]; ok {
			return b, nil
		}
		b := []byte(fmt.Sprintf("%s %s h1:%s=\n%s %s/go.mod h1:%s=\n", path, vers, strings.Repeat("A", 43), path, vers, strings.Repeat("B", 43)))
		records[key] = b
		return b, nil
	}
	srv := httptest.NewServer(xsumdb.NewServer(xsumdb.NewTestServer(skey, gosum)))
	defer srv.Close()
	_ = signer
	env := goenv.New(map[string]string{"GOSUMDB": vkey + " " + srv.URL, "HOME": t.TempDir()})
	hc := httpx.New(httpx.Options{CacheDir: t.TempDir(), Env: env})
	state := t.TempDir()
	c, err := sumdb.NewClient(env, hc, state, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < 400; i++ {
		path := fmt.Sprintf("example.com/m%d", i%37)
		vers := fmt.Sprintf("v1.%d.0", i)
		l, err := c.Lookup(ctx, path, vers)
		if err != nil {
			t.Fatalf("Lookup %s@%s: %v", path, vers, err)
		}
		if l.ZipHash != "h1:"+strings.Repeat("A", 43)+"=" || l.ModHash == "" {
			t.Fatalf("bad hashes %+v", l)
		}
		count("sumdb lookups vs x/mod server", 1)
	}
	if _, _, err := c.Latest(ctx); err != nil {
		t.Fatalf("Latest: %v", err)
	}
}

type io_ReadCloser = io.ReadCloser

func nopCloser(b []byte) io.ReadCloser { return io.NopCloser(bytes.NewReader(b)) }
