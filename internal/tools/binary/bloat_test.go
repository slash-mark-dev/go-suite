package binary_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type sizeRowOut struct {
	Name     string  `json:"name"`
	Module   string  `json:"module"`
	Version  string  `json:"version"`
	Text     uint64  `json:"text"`
	Rodata   uint64  `json:"rodata"`
	Data     uint64  `json:"data"`
	Total    uint64  `json:"total"`
	Share    float64 `json:"share"`
	Symbols  int     `json:"symbols"`
	Packages int     `json:"packages"`
}

type bloatOut struct {
	Path            string            `json:"path"`
	Format          string            `json:"format"`
	GOOS            string            `json:"goos"`
	FileSize        int64             `json:"fileSize"`
	SymbolSource    string            `json:"symbolSource"`
	Supported       bool              `json:"supported"`
	DataAttribution bool              `json:"dataAttribution"`
	Notes           []string          `json:"notes"`
	Totals          map[string]uint64 `json:"totals"`
	Attributed      uint64            `json:"attributed"`
	StripSavings    uint64            `json:"stripSavings"`
	Modules         []sizeRowOut      `json:"modules"`
	Packages        []sizeRowOut      `json:"packages"`
	TopSymbols      []struct {
		Name, Package, Module, Kind string
		Size                        uint64
	} `json:"topSymbols"`
	OverBudget bool  `json:"overBudget"`
	Budget     int64 `json:"budget"`
	Findings   []struct {
		Rule string `json:"rule"`
	} `json:"findings"`
}

func rowByName(rows []sizeRowOut, name string) *sizeRowOut {
	for i := range rows {
		if rows[i].Name == name {
			return &rows[i]
		}
	}
	return nil
}

func TestBloat(t *testing.T) {
	w := newWorld(t)
	dir := app(t, w, "v1.0.0", "v1.0.0")
	build(t, w, dir, "app", []string{"GOOS=linux", "GOARCH=amd64"})
	build(t, w, dir, "app-s", []string{"GOOS=linux", "GOARCH=amd64"}, "-ldflags=-s -w")
	build(t, w, dir, "app-darwin", []string{"GOOS=darwin", "GOARCH=arm64"})
	build(t, w, dir, "app.exe", []string{"GOOS=windows", "GOARCH=amd64"})
	build(t, w, dir, "app-s.exe", []string{"GOOS=windows", "GOARCH=amd64"}, "-ldflags=-s")

	check := func(t *testing.T, out bloatOut, dataExact bool) {
		t.Helper()
		if !out.Supported || out.FileSize <= 0 || out.Totals["text"] == 0 {
			t.Fatalf("report: %+v", out)
		}
		big := rowByName(out.Modules, "example.com/big")
		mainMod := rowByName(out.Modules, "example.com/app")
		std := rowByName(out.Modules, "std")
		if big == nil || mainMod == nil || std == nil {
			t.Fatalf("modules: %+v", out.Modules)
		}
		if big.Version != "v1.0.0" || mainMod.Version != "(main)" || big.Text == 0 || mainMod.Text == 0 {
			t.Errorf("big %+v main %+v", big, mainMod)
		}
		if std.Total < big.Total || out.Modules[0].Name != "std" {
			t.Errorf("std should dominate: %+v", out.Modules[:3])
		}
		var shares float64
		for _, m := range out.Modules {
			shares += m.Share
			if m.Name == "(unknown)" {
				t.Errorf("unattributed module row %+v", m)
			}
		}
		if shares < 0.99 || shares > 1.01 {
			t.Errorf("shares sum to %f", shares)
		}
		// Generic instantiations, closures and method values belong to
		// their package.
		pkg := rowByName(out.Packages, "example.com/big")
		if pkg == nil || pkg.Symbols < 3 {
			t.Errorf("package example.com/big: %+v", pkg)
		}
		if out.DataAttribution {
			if dataExact && big.Data+big.Rodata < 65536 {
				t.Errorf("big data %d < 64 KiB table", big.Data+big.Rodata)
			}
			found := false
			for _, s := range out.TopSymbols {
				if s.Name == "example.com/big.Table" {
					found = true
					if s.Size < 65536 || s.Module != "example.com/big" || s.Package != "example.com/big" {
						t.Errorf("Table symbol %+v", s)
					}
				}
			}
			if !found {
				t.Errorf("example.com/big.Table not among top symbols: %+v", out.TopSymbols)
			}
		}
		if out.Attributed == 0 || out.Attributed > uint64(out.FileSize) {
			t.Errorf("attributed %d of %d", out.Attributed, out.FileSize)
		}
	}

	t.Run("elf", func(t *testing.T) {
		r := w.Run(dir, "bloat", "app", "--json", "--top", "40")
		exit(t, r, 0)
		var out bloatOut
		r.Decode(t, &out)
		if out.Format != "elf" || out.SymbolSource != "symtab" || !out.DataAttribution || out.StripSavings == 0 || len(out.TopSymbols) != 40 {
			t.Errorf("elf: %s %s data=%v strip=%d top=%d", out.Format, out.SymbolSource, out.DataAttribution, out.StripSavings, len(out.TopSymbols))
		}
		check(t, out, true)
		if rowByName(out.Modules, "<type metadata>") == nil || rowByName(out.Modules, "<string data>") == nil {
			t.Errorf("linker buckets missing: %+v", out.Modules)
		}
	})

	t.Run("stripped", func(t *testing.T) {
		r := w.Run(dir, "bloat", "app-s", "--json")
		exit(t, r, 0)
		var out bloatOut
		r.Decode(t, &out)
		if out.SymbolSource != "pclntab" || out.DataAttribution || len(out.Notes) == 0 || out.Totals["dwarf"] != 0 {
			t.Errorf("stripped: %+v", out)
		}
		check(t, out, false)
	})

	for _, c := range []struct{ name, file, format, source string }{
		{"macho", "app-darwin", "macho", "symtab"},
		{"pe", "app.exe", "pe", "symtab"},
		{"pe-stripped", "app-s.exe", "pe", "pclntab"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := w.Run(dir, "bloat", c.file, "--json", "--top", "40")
			exit(t, r, 0)
			var out bloatOut
			r.Decode(t, &out)
			if out.Format != c.format || out.SymbolSource != c.source {
				t.Errorf("%s: %s %s", c.file, out.Format, out.SymbolSource)
			}
			check(t, out, true)
		})
	}

	t.Run("text", func(t *testing.T) {
		r := w.Run(dir, "bloat", "app", "--top", "5")
		exit(t, r, 0)
		for _, s := range []string{"sm-go bloat", "Sections", "Modules", "example.com/big", "v1.0.0", "Top 5 packages", "Top 5 symbols", "Strip savings"} {
			if !strings.Contains(r.Stdout, s) {
				t.Errorf("text lacks %q\n%s", s, r.Stdout)
			}
		}
	})

	t.Run("budget", func(t *testing.T) {
		r := w.Run(dir, "bloat", "app", "--budget", "100KB", "--json")
		exit(t, r, 1)
		var out bloatOut
		r.Decode(t, &out)
		if !out.OverBudget || out.Budget != 100<<10 || len(out.Findings) != 1 || out.Findings[0].Rule != "size-budget" {
			t.Errorf("budget: %+v %+v", out.OverBudget, out.Findings)
		}
		exit(t, w.Run(dir, "bloat", "app", "--budget", "1GB"), 0)
		exit(t, w.Run(dir, "bloat", "app", "--budget", "lots"), 2)
	})

	t.Run("usage", func(t *testing.T) {
		exit(t, w.Run(dir, "bloat"), 2)
		exit(t, w.Run(dir, "bloat", "app", "app-s"), 2)
		exit(t, w.Run(dir, "bloat", "nope"), 2)
		exit(t, w.Run(dir, "bloat", "."), 2)
		exit(t, w.Run(dir, "bloat", "main.go"), 2)
		exit(t, w.Run(dir, "bloat", "--diff", "app"), 2)
		exit(t, w.Run(dir, "bloat", "app", "--max-growth", "5%"), 2)
		exit(t, w.Run(dir, "bloat", "app", "--top", "-1"), 2)
		exit(t, w.Run(dir, "bloat", "--diff", "app", "app-s", "--max-growth", "x%"), 2)
	})

	t.Run("no-symbols", func(t *testing.T) {
		// Corrupt the function table of a stripped binary: the section
		// sizes are still reported, attribution is unsupported.
		data, err := os.ReadFile(filepath.Join(dir, "app-s.exe"))
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i+6 <= len(data); i++ {
			if data[i] == 0xf1 && data[i+1] == 0xff && data[i+2] == 0xff && data[i+3] == 0xff && data[i+4] == 0 && data[i+5] == 0 {
				data[i] = 0
			}
		}
		bad := filepath.Join(dir, "nosyms.exe")
		os.WriteFile(bad, data, 0o755)
		r := w.Run(dir, "bloat", "nosyms.exe", "--json")
		exit(t, r, 0)
		var out bloatOut
		r.Decode(t, &out)
		if out.Supported || out.SymbolSource != "none" || out.Totals["text"] == 0 {
			t.Errorf("unsupported binary: %+v", out)
		}
		if ws, _ := r.JSON(t)["warnings"].([]any); len(ws) == 0 {
			t.Error("no warning")
		}
	})
}

type deltaOut struct {
	Name   string `json:"name"`
	Old    uint64 `json:"old"`
	New    uint64 `json:"new"`
	Delta  int64  `json:"delta"`
	Status string `json:"status"`
}

type diffOut struct {
	Old            bloatOut   `json:"old"`
	New            bloatOut   `json:"new"`
	FileDelta      int64      `json:"fileDelta"`
	FileDeltaPct   float64    `json:"fileDeltaPercent"`
	Sections       []deltaOut `json:"sections"`
	ModuleVersions []struct {
		Path, Old, New string
	} `json:"moduleVersions"`
	Modules  []deltaOut `json:"modules"`
	Packages []deltaOut `json:"packages"`
	Symbols  []deltaOut `json:"symbols"`
	Findings []struct {
		Rule string `json:"rule"`
	} `json:"findings"`
}

func TestBloatDiff(t *testing.T) {
	w := newWorld(t)
	oldDir := app(t, w, "v1.0.0", "v1.0.0")
	newDir := app(t, w, "v1.0.0", "v1.1.0")
	oldBin := build(t, w, oldDir, "app", nil, "-trimpath")
	newBin := build(t, w, newDir, "app", nil, "-trimpath")

	r := w.Run("", "bloat", "--diff", oldBin, newBin, "--json", "--top", "10")
	exit(t, r, 0)
	var d diffOut
	r.Decode(t, &d)
	if d.FileDelta <= 0 || d.FileDeltaPct <= 0 {
		t.Errorf("file delta %d (%f%%)", d.FileDelta, d.FileDeltaPct)
	}
	if len(d.ModuleVersions) != 1 || d.ModuleVersions[0].Path != "example.com/big" || d.ModuleVersions[0].Old != "v1.0.0" || d.ModuleVersions[0].New != "v1.1.0" {
		t.Errorf("module versions %+v", d.ModuleVersions)
	}
	if len(d.Modules) == 0 || d.Modules[0].Name != "example.com/big" || d.Modules[0].Delta < 196608 {
		t.Errorf("module deltas %+v", d.Modules)
	}
	if len(d.Symbols) == 0 || d.Symbols[0].Name != "example.com/big.Table" || d.Symbols[0].Delta != 196608 {
		t.Errorf("symbol deltas %+v", d.Symbols)
	}
	if len(d.Packages) == 0 || d.Packages[0].Name != "example.com/big" || len(d.Packages) > 10 || len(d.Symbols) > 10 {
		t.Errorf("package deltas %+v", d.Packages)
	}
	if len(d.New.TopSymbols) > 10 || len(d.Old.Packages) > 10 {
		t.Error("embedded reports not trimmed to --top")
	}
	dataGrew := false
	for _, s := range d.Sections {
		if s.Name == "data" && s.Delta >= 196608 {
			dataGrew = true
		}
	}
	if !dataGrew {
		t.Errorf("sections %+v", d.Sections)
	}

	r = w.Run("", "bloat", "--diff", oldBin, newBin, "--max-growth", "1%", "--json")
	exit(t, r, 1)
	r.Decode(t, &d)
	if len(d.Findings) != 1 || d.Findings[0].Rule != "size-growth" {
		t.Errorf("findings %+v", d.Findings)
	}
	exit(t, w.Run("", "bloat", "--diff", oldBin, newBin, "--max-growth", "100KB"), 1)
	exit(t, w.Run("", "bloat", "--diff", oldBin, newBin, "--max-growth", "50MB"), 0)
	exit(t, w.Run("", "bloat", "--diff", oldBin, newBin, "--max-growth", "90%"), 0)
	// Shrinking never trips the growth limit.
	exit(t, w.Run("", "bloat", "--diff", newBin, oldBin, "--max-growth", "0"), 0)
	exit(t, w.Run("", "bloat", "--diff", oldBin, oldBin, "--max-growth", "0"), 0)
	exit(t, w.Run("", "bloat", "--diff", oldBin, newBin, "--budget", "100KB"), 1)

	r = w.Run("", "bloat", "--diff", oldBin, newBin)
	exit(t, r, 0)
	for _, s := range []string{"bloat --diff", "Module versions", "example.com/big", "v1.0.0", "v1.1.0", "+192.0 KB", "example.com/big.Table"} {
		if !strings.Contains(r.Stdout, s) {
			t.Errorf("text lacks %q\n%s", s, r.Stdout)
		}
	}
	r = w.Run("", "bloat", "--diff", oldBin, oldBin)
	exit(t, r, 0)
	if !strings.Contains(r.Stdout, "no size differences") {
		t.Errorf("identical diff:\n%s", r.Stdout)
	}
}
