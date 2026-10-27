package binary_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type scanOut struct {
	Binaries []struct {
		Path      string `json:"path"`
		Format    string `json:"format"`
		GOOS      string `json:"goos"`
		GOARCH    string `json:"goarch"`
		GoVersion string `json:"goVersion"`
		Go        struct {
			Supported *bool  `json:"supported"`
			Line      string `json:"line"`
			Latest    string `json:"latestPatch"`
		} `json:"go"`
		Main struct {
			Path    string `json:"path"`
			Version string `json:"version"`
		} `json:"main"`
		Deps []struct {
			Path    string `json:"path"`
			Version string `json:"version"`
			Sum     string `json:"sum"`
		} `json:"deps"`
		Settings []struct{ Key, Value string } `json:"settings"`
		Build    struct {
			CGO         *bool  `json:"cgo"`
			Trimpath    bool   `json:"trimpath"`
			LDFlags     string `json:"ldflags"`
			VCS         string `json:"vcs"`
			Revision    string `json:"revision"`
			Modified    *bool  `json:"modified"`
			StrippedSym bool   `json:"strippedSymbols"`
		} `json:"build"`
		SymbolSource string `json:"symbolSource"`
		Functions    int    `json:"functions"`
		Vulns        []struct {
			ID             string   `json:"id"`
			Module         string   `json:"module"`
			Version        string   `json:"version"`
			FixedIn        string   `json:"fixedIn"`
			Reachability   string   `json:"reachability"`
			LinkedSymbols  []string `json:"linkedSymbols"`
			Severity       string   `json:"severity"`
			BaseSeverity   string   `json:"baseSeverity"`
			SeveritySource string   `json:"severitySource"`
			KEV            any      `json:"kev"`
		} `json:"vulns"`
		Findings []struct {
			Severity string `json:"severity"`
			Rule     string `json:"rule"`
			Title    string `json:"title"`
			Fix      string `json:"fix"`
		} `json:"findings"`
	} `json:"binaries"`
	Skipped []struct{ Path, Reason string } `json:"skipped"`
	Summary struct {
		Binaries   int            `json:"binaries"`
		Vulns      int            `json:"vulns"`
		Linked     int            `json:"linkedVulns"`
		Findings   int            `json:"findings"`
		BySeverity map[string]int `json:"bySeverity"`
		FailOn     string         `json:"failOn"`
	} `json:"summary"`
}

func reach(t *testing.T, out scanOut, i int) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, v := range out.Binaries[i].Vulns {
		m[v.ID] = v.Reachability
	}
	return m
}

func rules(out scanOut, i int) map[string]string {
	m := map[string]string{}
	for _, f := range out.Binaries[i].Findings {
		m[f.Rule] = f.Severity
	}
	return m
}

func TestBinscan(t *testing.T) {
	w := newWorld(t)
	addVulns(w)
	dir := app(t, w, "v1.0.0", "v1.0.0")
	gv := goVersion(t, w, dir)
	releases(w, gv)
	linux := build(t, w, dir, "app-linux", []string{"GOOS=linux", "GOARCH=amd64"})
	stripped := build(t, w, dir, "app-stripped", []string{"GOOS=linux", "GOARCH=arm64"}, "-ldflags=-s -w", "-trimpath")
	darwin := build(t, w, dir, "app-darwin", []string{"GOOS=darwin", "GOARCH=arm64"})
	windows := build(t, w, dir, "app.exe", []string{"GOOS=windows", "GOARCH=amd64"})
	winStripped := build(t, w, dir, "app-s.exe", []string{"GOOS=windows", "GOARCH=amd64"}, "-ldflags=-s")

	t.Run("symbol-level", func(t *testing.T) {
		r := w.Run(dir, "binscan", "app-linux", "--json")
		exit(t, r, 1)
		var out scanOut
		r.Decode(t, &out)
		if len(out.Binaries) != 1 {
			t.Fatalf("binaries: %+v", out.Binaries)
		}
		b := out.Binaries[0]
		if b.Path != linux || b.Format != "elf" || b.GOOS != "linux" || b.GOARCH != "amd64" || b.GoVersion != gv {
			t.Errorf("header: %+v", b)
		}
		if b.Main.Path != "example.com/app" || b.SymbolSource != "symtab" || b.Functions < 100 {
			t.Errorf("main %+v source %s funcs %d", b.Main, b.SymbolSource, b.Functions)
		}
		deps := map[string]string{}
		for _, d := range b.Deps {
			deps[d.Path] = d.Version
			if !strings.HasPrefix(d.Sum, "h1:") {
				t.Errorf("dep %s has sum %q", d.Path, d.Sum)
			}
		}
		if deps["example.com/vulnmod"] != "v1.0.0" || deps["example.com/big"] != "v1.0.0" {
			t.Errorf("deps %v", deps)
		}
		settings := map[string]string{}
		for _, s := range b.Settings {
			settings[s.Key] = s.Value
		}
		if settings["CGO_ENABLED"] != "0" || settings["GOOS"] != "linux" || settings["GOARCH"] != "amd64" {
			t.Errorf("settings %v", settings)
		}
		if b.Build.CGO == nil || *b.Build.CGO || b.Build.Trimpath || b.Build.StrippedSym {
			t.Errorf("build %+v", b.Build)
		}
		want := map[string]string{
			"GO-2025-0001": "linked",   // vulnmod.Bad is called
			"GO-2025-0002": "package",  // vulnmod.Unused is dead code
			"GO-2025-0003": "module",   // vulnmod/other is not imported
			"GO-2025-1000": "linked",   // encoding/gob.(*Encoder).EncodeValue
			"GO-2025-1001": "module",   // net/smtp is not linked
			"GO-2025-1002": "platform", // windows-only
		}
		got := reach(t, out, 0)
		for id, wr := range want {
			if got[id] != wr {
				t.Errorf("%s reachability %q, want %q", id, got[id], wr)
			}
		}
		if _, ok := got["GO-2025-0004"]; ok || len(got) != len(want) {
			t.Errorf("unexpected vulns %v", got)
		}
		for _, v := range b.Vulns {
			switch v.ID {
			case "GO-2025-0001":
				if v.Severity != "critical" || v.SeveritySource != "kev" || v.KEV == nil || v.FixedIn != "v1.1.0" {
					t.Errorf("KEV enrichment: %+v", v)
				}
				if len(v.LinkedSymbols) != 1 || v.LinkedSymbols[0] != "example.com/vulnmod.Bad" {
					t.Errorf("linked symbols %v", v.LinkedSymbols)
				}
			case "GO-2025-0002":
				if v.Severity != "low" || v.BaseSeverity != "medium" {
					t.Errorf("package-level severity %s/%s", v.Severity, v.BaseSeverity)
				}
			case "GO-2025-0003", "GO-2025-1001", "GO-2025-1002":
				if v.Severity != "info" {
					t.Errorf("%s severity %s", v.ID, v.Severity)
				}
			case "GO-2025-1000":
				if v.Module != "stdlib" || v.Version != "v"+strings.TrimPrefix(gv, "go") && !strings.HasPrefix(v.Version, "v1.") {
					t.Errorf("stdlib vuln %+v", v)
				}
			}
		}
		rs := rules(out, 0)
		if rs["no-trimpath"] != "low" || rs["vuln"] == "" {
			t.Errorf("findings %v", rs)
		}
		if _, ok := rs["go-eol"]; ok {
			t.Error("supported Go flagged EOL")
		}
		if out.Summary.Binaries != 1 || out.Summary.Vulns != 6 || out.Summary.Linked != 2 || out.Summary.FailOn != "medium" {
			t.Errorf("summary %+v", out.Summary)
		}
	})

	t.Run("stripped", func(t *testing.T) {
		r := w.Run(dir, "binscan", stripped, "--json")
		exit(t, r, 1)
		var out scanOut
		r.Decode(t, &out)
		b := out.Binaries[0]
		if b.SymbolSource != "pclntab" || !b.Build.StrippedSym || !b.Build.Trimpath || b.Build.LDFlags != "" /* omitted with -trimpath */ || b.GOARCH != "arm64" {
			t.Errorf("stripped: source %s build %+v", b.SymbolSource, b.Build)
		}
		got := reach(t, out, 0)
		if got["GO-2025-0001"] != "linked" || got["GO-2025-0002"] != "package" || got["GO-2025-1000"] != "linked" {
			t.Errorf("reachability from pclntab: %v", got)
		}
		if _, ok := rules(out, 0)["no-trimpath"]; ok {
			t.Error("-trimpath build flagged")
		}
	})

	t.Run("cross-platform", func(t *testing.T) {
		r := w.Run(dir, "binscan", darwin, windows, winStripped, "--json")
		exit(t, r, 1)
		var out scanOut
		r.Decode(t, &out)
		if len(out.Binaries) != 3 {
			t.Fatalf("got %d binaries", len(out.Binaries))
		}
		wantFmt := []string{"macho", "pe", "pe"}
		wantSrc := []string{"symtab", "symtab", "pclntab"}
		for i, b := range out.Binaries {
			if b.Format != wantFmt[i] || b.SymbolSource != wantSrc[i] {
				t.Errorf("%s: format %s source %s", b.Path, b.Format, b.SymbolSource)
			}
			got := reach(t, out, i)
			if got["GO-2025-0001"] != "linked" || got["GO-2025-0002"] != "package" {
				t.Errorf("%s: %v", b.Path, got)
			}
			wantOS := "platform"
			if b.GOOS == "windows" {
				wantOS = "linked"
			}
			if got["GO-2025-1002"] != wantOS {
				t.Errorf("%s (%s): windows-only vuln %q, want %q", b.Path, b.GOOS, got["GO-2025-1002"], wantOS)
			}
		}
		if out.Binaries[2].Build.LDFlags != "-s" || !out.Binaries[2].Build.StrippedSym || out.Binaries[1].Build.StrippedSym {
			t.Errorf("windows build flags: %+v / %+v", out.Binaries[1].Build, out.Binaries[2].Build)
		}
		if out.Binaries[0].GOOS != "darwin" || out.Binaries[0].GOARCH != "arm64" || out.Binaries[1].GOOS != "windows" {
			t.Errorf("platforms wrong")
		}
	})

	t.Run("text", func(t *testing.T) {
		r := w.Run(dir, "binscan", "app-linux")
		exit(t, r, 1)
		for _, s := range []string{"sm-go binscan", "example.com/vulnmod", "GO-2025-0001", "CRITICAL", "linked: example.com/vulnmod.Bad",
			"built without -trimpath", "supported", "CGO_ENABLED=0"} {
			if !strings.Contains(r.Stdout, s) {
				t.Errorf("text output lacks %q\n%s", s, r.Stdout)
			}
		}
	})

	t.Run("fail-on", func(t *testing.T) {
		exit(t, w.Run(dir, "binscan", "app-linux", "--fail-on", "none"), 0)
		exit(t, w.Run(dir, "binscan", "app-linux", "--fail-on", "critical"), 1)
		exit(t, w.Run(dir, "binscan", "app-stripped", "--fail-on", "critical"), 1)
		exit(t, w.Run(dir, "binscan", "app-linux", "--fail-on", "bogus"), 2)
	})

	t.Run("directory", func(t *testing.T) {
		bins := t.TempDir()
		for _, b := range []string{linux, windows} {
			data, _ := os.ReadFile(b)
			os.WriteFile(filepath.Join(bins, filepath.Base(b)), data, 0o755)
		}
		os.MkdirAll(filepath.Join(bins, "sub", ".hidden"), 0o755)
		data, _ := os.ReadFile(darwin)
		os.WriteFile(filepath.Join(bins, "sub", "app-darwin"), data, 0o755)
		os.WriteFile(filepath.Join(bins, "sub", ".hidden", "skipme"), data, 0o755)
		os.WriteFile(filepath.Join(bins, "README.txt"), []byte("not a binary"), 0o644)
		if sh, err := exec.LookPath("sh"); err == nil {
			if real, err := filepath.EvalSymlinks(sh); err == nil {
				d, _ := os.ReadFile(real)
				os.WriteFile(filepath.Join(bins, "native-elf"), d, 0o755)
			}
		}
		r := w.Run("", "binscan", bins, "--json", "--fail-on", "none")
		exit(t, r, 0)
		var out scanOut
		r.Decode(t, &out)
		if len(out.Binaries) != 3 {
			var names []string
			for _, b := range out.Binaries {
				names = append(names, b.Path)
			}
			t.Errorf("found %v", names)
		}
	})

	t.Run("no-vuln", func(t *testing.T) {
		r := w.RunEnv(dir, []string{"SMGO_VULNDB_URL=" + w.URL + "/nowhere"}, "binscan", "app-linux", "--no-vuln", "--json")
		exit(t, r, 0)
		var out scanOut
		r.Decode(t, &out)
		if len(out.Binaries[0].Vulns) != 0 || out.Binaries[0].Go.Supported != nil {
			t.Errorf("vulns checked with --no-vuln")
		}
	})

	t.Run("network-error", func(t *testing.T) {
		r := w.RunEnv(dir, []string{"SMGO_VULNDB_URL=" + w.URL + "/nowhere"}, "binscan", "app-linux", "--json")
		exit(t, r, 3)
		if !strings.Contains(r.JSON(t)["error"].(string), "vulnerability database") {
			t.Errorf("error: %s", r.Stdout)
		}
	})

	t.Run("usage", func(t *testing.T) {
		exit(t, w.Run(dir, "binscan"), 2)
		exit(t, w.Run(dir, "binscan", "missing-file"), 2)
		r := w.Run(dir, "binscan", "main.go", "--json")
		exit(t, r, 2)
		if len(r.JSON(t)["warnings"].([]any)) == 0 {
			t.Error("no warning for skipped file")
		}
		empty := t.TempDir()
		exit(t, w.Run(dir, "binscan", empty), 2)
		// A named non-Go file next to a real binary is skipped with a warning.
		r = w.Run(dir, "binscan", "main.go", "app-linux", "--json", "--fail-on", "none")
		exit(t, r, 0)
		var out scanOut
		r.Decode(t, &out)
		if len(out.Binaries) != 1 || len(out.Skipped) != 1 || !strings.HasSuffix(out.Skipped[0].Path, "main.go") {
			t.Errorf("skipped %+v", out.Skipped)
		}
	})
}

func TestBinscanHygiene(t *testing.T) {
	w := newWorld(t)
	dir := app(t, w, "v1.1.0", "v1.0.0")
	gv := goVersion(t, w, dir)

	t.Run("clean", func(t *testing.T) {
		releases(w, gv)
		build(t, w, dir, "clean", nil, "-trimpath")
		r := w.Run(dir, "binscan", "clean", "--json", "--fail-on", "low")
		exit(t, r, 0)
		var out scanOut
		r.Decode(t, &out)
		b := out.Binaries[0]
		if len(b.Vulns) != 0 || len(b.Findings) != 0 || b.Go.Supported == nil || !*b.Go.Supported {
			t.Errorf("clean binary: vulns %v findings %v go %+v", b.Vulns, b.Findings, b.Go)
		}
		r = w.Run(dir, "binscan", "clean")
		exit(t, r, 0)
		if !strings.Contains(r.Stdout, "no known vulnerabilities or hygiene problems") {
			t.Errorf("text:\n%s", r.Stdout)
		}
	})

	t.Run("eol", func(t *testing.T) {
		// Two newer release lines make the toolchain's line unsupported.
		minor := goMinorOf(gv)
		releases(w, "go1."+strconv.Itoa(minor+2)+".1", "go1."+strconv.Itoa(minor+2)+".0", "go1."+strconv.Itoa(minor+1)+".4", gv)
		build(t, w, dir, "eol", nil, "-trimpath")
		r := w.Run(dir, "binscan", "eol", "--json", "--no-cache")
		exit(t, r, 1)
		var out scanOut
		r.Decode(t, &out)
		b := out.Binaries[0]
		if rules(out, 0)["go-eol"] != "high" || b.Go.Supported == nil || *b.Go.Supported {
			t.Errorf("EOL not flagged: %+v %+v", b.Findings, b.Go)
		}
		for _, f := range b.Findings {
			if f.Rule == "go-eol" && f.Fix != "rebuild with go1."+strconv.Itoa(minor+2)+".1" {
				t.Errorf("fix %q", f.Fix)
			}
		}
	})

	t.Run("patch", func(t *testing.T) {
		minor := goMinorOf(gv)
		releases(w, "go1."+strconv.Itoa(minor)+".99", gv)
		build(t, w, dir, "patch", nil, "-trimpath")
		r := w.Run(dir, "binscan", "patch", "--json", "--no-cache")
		exit(t, r, 0) // low is below the default threshold
		var out scanOut
		r.Decode(t, &out)
		if rules(out, 0)["go-patch"] != "low" || out.Binaries[0].Go.Latest != "go1."+strconv.Itoa(minor)+".99" {
			t.Errorf("patch finding: %+v", out.Binaries[0].Findings)
		}
		exit(t, w.Run(dir, "binscan", "patch", "--fail-on", "low", "--no-cache"), 1)
	})

	t.Run("vcs-modified", func(t *testing.T) {
		if _, err := exec.LookPath("git"); err != nil {
			t.Skip("git not installed")
		}
		releases(w, gv)
		git := func(args ...string) {
			t.Helper()
			cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "init.defaultBranch=main"}, args...)...)
			cmd.Dir = dir
			cmd.Env = append(w.Env(), "GIT_CONFIG_NOSYSTEM=1")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v\n%s", args, err, out)
			}
		}
		os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("clean\neol\npatch\nvcs*\n"), 0o644)
		git("init", "-q")
		git("add", ".")
		git("commit", "-q", "-m", "init")
		build(t, w, dir, "vcs-clean", nil, "-trimpath")
		os.WriteFile(filepath.Join(dir, "extra.go"), []byte("package main\n\nvar extra = 1\n"), 0o644)
		build(t, w, dir, "vcs-dirty", nil, "-trimpath")
		r := w.Run(dir, "binscan", "vcs-clean", "vcs-dirty", "--json")
		exit(t, r, 1)
		var out scanOut
		r.Decode(t, &out)
		c, d := out.Binaries[0], out.Binaries[1]
		if c.Build.VCS != "git" || len(c.Build.Revision) != 40 || c.Build.Modified == nil || *c.Build.Modified {
			t.Errorf("clean vcs %+v", c.Build)
		}
		if d.Build.Modified == nil || !*d.Build.Modified || rules(out, 1)["vcs-modified"] != "medium" {
			t.Errorf("dirty vcs %+v %+v", d.Build, d.Findings)
		}
		if _, ok := rules(out, 0)["vcs-modified"]; ok {
			t.Error("clean build flagged modified")
		}
	})
}

func goMinorOf(v string) int {
	v = strings.TrimPrefix(v, "go1.")
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}
