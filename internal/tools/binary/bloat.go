package binary

import (
	"flag"
	"fmt"
	"sort"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/binfile"
	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/ui"
)

var bloatFlags struct {
	top       *int
	diff      *bool
	budget    *string
	maxGrowth *string
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "bloat",
		Group:   group,
		Summary: "Binary size attribution: bytes per module, package and symbol; compare two builds",
		Usage:   "sm-go bloat <binary> [flags]\n       sm-go bloat --diff <old-binary> <new-binary> [flags]",
		Help: `Attributes the size of a compiled Go executable (ELF, Mach-O or PE) to
the modules and packages it was built from, using the symbol table: code
(text) from function symbols and read-only / writable data from data
symbols, with Go symbol names decoded (generic instantiations, closures,
method values, ABI wrappers, escaped import paths). Packages are mapped to
modules with the binary's own build information. Type descriptors, string
data, itabs and other linker tables are reported as separate buckets.

Binaries stripped with -ldflags=-s have no symbol table; their code is
attributed from the Go function table (pclntab) and data attribution is
reported as unsupported. The section table, the function table size and
the bytes -ldflags="-s -w" would save are always reported.

--diff compares two builds of a program: file and section deltas, module
version changes, and growth per module, package and symbol.

--budget fails (exit 1) when the binary is larger than the given size;
in --diff mode --max-growth fails when the new binary grew by more than a
size or a percentage.`,
		Examples: []string{
			"sm-go bloat ./bin/server",
			"sm-go bloat ./bin/server --top 50 --json",
			"sm-go bloat --diff old/server new/server",
			"sm-go bloat --diff old/server new/server --max-growth 5%",
			"sm-go bloat app --budget 25MB",
		},
		Sources: []string{"the binary's symbol table, Go function table and build information"},
		Flags: func(fs *flag.FlagSet) {
			bloatFlags.top = fs.Int("top", 20, "number of packages and symbols to list (`n`)")
			bloatFlags.diff = fs.Bool("diff", false, "compare two binaries: --diff old new")
			bloatFlags.budget = fs.String("budget", "", "fail when the binary is larger than `size` (e.g. 25MB)")
			bloatFlags.maxGrowth = fs.String("max-growth", "", "with --diff: fail when the binary grew by more than `size` or percent (e.g. 512KB, 5%)")
		},
		Run: runBloat,
	})
}

// sizeRow is the bytes of one module or package.
type sizeRow struct {
	Name     string  `json:"name"`
	Module   string  `json:"module,omitempty"`
	Version  string  `json:"version,omitempty"`
	Text     uint64  `json:"text"`
	Rodata   uint64  `json:"rodata"`
	Data     uint64  `json:"data"`
	BSS      uint64  `json:"bss"`
	Total    uint64  `json:"total"` // text + rodata + data (bytes in the file)
	Share    float64 `json:"share"` // of the attributed file bytes
	Symbols  int     `json:"symbols"`
	Packages int     `json:"packages,omitempty"`
}

func (r *sizeRow) add(kind string, n uint64) {
	switch kind {
	case binfile.KindText:
		r.Text += n
	case binfile.KindRodata:
		r.Rodata += n
	case binfile.KindData:
		r.Data += n
	case binfile.KindBSS:
		r.BSS += n
		r.Symbols++
		return
	default:
		return
	}
	r.Total += n
	r.Symbols++
}

type symRow struct {
	Name    string `json:"name"`
	Package string `json:"package"`
	Module  string `json:"module"`
	Kind    string `json:"kind"`
	Size    uint64 `json:"size"`
}

type sectionRow struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Size     uint64 `json:"size"`
	FileSize uint64 `json:"fileSize"`
}

type bloatReport struct {
	Path            string            `json:"path"`
	Format          string            `json:"format"`
	GOOS            string            `json:"goos"`
	GOARCH          string            `json:"goarch"`
	GoVersion       string            `json:"goVersion"`
	MainModule      string            `json:"mainModule"`
	FileSize        int64             `json:"fileSize"`
	SymbolSource    string            `json:"symbolSource"`
	Supported       bool              `json:"supported"`
	DataAttribution bool              `json:"dataAttribution"`
	Notes           []string          `json:"notes,omitempty"`
	Sections        []sectionRow      `json:"sections"`
	Totals          map[string]uint64 `json:"totals"` // file bytes per section kind
	Attributed      uint64            `json:"attributed"`
	Unattributed    map[string]uint64 `json:"unattributed"` // per kind: section bytes not covered by symbols
	StripSavings    uint64            `json:"stripSavings"`
	Modules         []*sizeRow        `json:"modules"`
	Packages        []*sizeRow        `json:"packages"`
	TopSymbols      []symRow          `json:"topSymbols"`

	modVersions map[string]string
	allSyms     map[string]symRow
	pkgByName   map[string]*sizeRow
	modByName   map[string]*sizeRow
}

func runBloat(c *cli.Context) error {
	top := *bloatFlags.top
	if top < 0 {
		return cli.Usagef("--top must be >= 0")
	}
	var budget int64
	if *bloatFlags.budget != "" {
		b, err := parseSize(*bloatFlags.budget)
		if err != nil {
			return cli.Usagef("--budget: %v", err)
		}
		budget = b
	}
	if *bloatFlags.diff {
		if len(c.Args) != 2 {
			return cli.Usagef("--diff needs exactly two binaries: old and new")
		}
		return runBloatDiff(c, top, budget)
	}
	if *bloatFlags.maxGrowth != "" {
		return cli.Usagef("--max-growth only applies with --diff")
	}
	if len(c.Args) != 1 {
		return cli.Usagef("pass exactly one Go binary (or --diff old new)")
	}
	f, err := openBinary(c, c.Args[0])
	if err != nil {
		return err
	}
	r := attribute(f, top)
	type single struct {
		*bloatReport
		Budget     int64            `json:"budget,omitempty"`
		OverBudget bool             `json:"overBudget,omitempty"`
		Findings   []report.Finding `json:"findings"`
	}
	res := single{bloatReport: r, Budget: budget, Findings: []report.Finding{}}
	if budget > 0 && r.FileSize > budget {
		res.OverBudget = true
		res.Findings = append(res.Findings, report.Finding{Severity: report.High, Rule: "size-budget", File: r.Path,
			Title: fmt.Sprintf("binary is %s, over the %s budget by %s", ui.Bytes(r.FileSize), ui.Bytes(budget), ui.Bytes(r.FileSize-budget))})
		c.Issues()
	}
	if !r.Supported {
		c.Warnf("%s has neither a symbol table nor a Go function table; size attribution is unsupported", r.Path)
	}
	c.SetResult(res)
	if c.Text() {
		printBloat(c, r, top)
		for _, f := range res.Findings {
			c.Out.Println()
			c.Out.Bad("%s", f.Title)
		}
	}
	return nil
}

// attribute computes the size attribution of f.
func attribute(f *binfile.File, top int) *bloatReport {
	mm := binfile.NewModuleMap(f.BuildInfo)
	r := &bloatReport{Path: f.Path, Format: f.Format, GOOS: f.GOOS, GOARCH: f.GOARCH, FileSize: f.Size,
		SymbolSource: f.SymbolSource, Supported: len(f.Funcs) > 0, DataAttribution: len(f.Data) > 0,
		Totals: f.Totals(), Unattributed: map[string]uint64{}, StripSavings: f.StripSavings(),
		Modules: []*sizeRow{}, Packages: []*sizeRow{}, TopSymbols: []symRow{}, Sections: []sectionRow{},
		modVersions: map[string]string{}, allSyms: map[string]symRow{},
		pkgByName: map[string]*sizeRow{}, modByName: map[string]*sizeRow{}}
	if f.BuildInfo != nil {
		r.GoVersion = f.BuildInfo.GoVersion
		r.MainModule = f.BuildInfo.Main.Path
		for _, d := range f.BuildInfo.Deps {
			v := d.Version
			if d.Replace != nil {
				v = d.Replace.Version
				if v == "" {
					v = d.Replace.Path
				}
			}
			r.modVersions[d.Path] = v
		}
	}
	for _, s := range f.Sections {
		r.Sections = append(r.Sections, sectionRow{s.Name, s.Kind, s.Size, s.FileSize})
	}
	switch f.SymbolSource {
	case binfile.SourcePclntab:
		r.Notes = append(r.Notes, "no symbol table (stripped with -ldflags=-s): code attributed from the Go function table; data attribution unsupported")
	case binfile.SourceNone:
		r.Notes = append(r.Notes, "no symbol table and no Go function table found: attribution unsupported")
	}
	if f.Format != "elf" && f.SymbolSource == binfile.SourceSymtab {
		r.Notes = append(r.Notes, f.Format+" symbol tables carry no sizes: data symbol sizes are distances to the next symbol")
	}
	covered := map[string]uint64{}
	addSym := func(s binfile.Symbol, kind string) {
		pkg, _ := binfile.SplitSymbol(s.Name)
		mod := mm.Module(pkg)
		p := r.pkgByName[pkg]
		if p == nil {
			p = &sizeRow{Name: pkg, Module: mod}
			r.pkgByName[pkg] = p
		}
		p.add(kind, s.Size)
		m := r.modByName[mod]
		if m == nil {
			m = &sizeRow{Name: mod, Version: r.modVersions[mod]}
			if mm.IsMain(mod) {
				m.Version = "(main)"
			}
			r.modByName[mod] = m
		}
		m.add(kind, s.Size)
		covered[kind] += s.Size
		if kind != binfile.KindBSS {
			key := s.Name
			if old, ok := r.allSyms[key]; ok {
				old.Size += s.Size
				r.allSyms[key] = old
			} else {
				r.allSyms[key] = symRow{Name: s.Name, Package: pkg, Module: mod, Kind: kind, Size: s.Size}
			}
		}
	}
	for _, s := range f.Funcs {
		addSym(s, binfile.KindText)
	}
	for _, s := range f.Data {
		kind := f.KindAt(s.Addr)
		switch kind {
		case binfile.KindRodata, binfile.KindData, binfile.KindBSS:
			addSym(s, kind)
		}
		// Symbols inside the function table, symbol table or other
		// sections are accounted for by the section totals.
	}
	for _, k := range []string{binfile.KindText, binfile.KindRodata, binfile.KindData} {
		if !r.DataAttribution && k != binfile.KindText {
			continue
		}
		if t := r.Totals[k]; t > covered[k] {
			r.Unattributed[k] = t - covered[k]
		}
		r.Attributed += min(covered[k], r.Totals[k])
	}
	for _, m := range r.modByName {
		r.Modules = append(r.Modules, m)
	}
	for _, p := range r.pkgByName {
		r.Packages = append(r.Packages, p)
		r.modByName[p.Module].Packages++
	}
	var total uint64
	for _, m := range r.Modules {
		total += m.Total
	}
	for _, rows := range [][]*sizeRow{r.Modules, r.Packages} {
		for _, x := range rows {
			if total > 0 {
				x.Share = float64(x.Total) / float64(total)
			}
		}
		sortRows(rows)
	}
	var syms []symRow
	for _, s := range r.allSyms {
		syms = append(syms, s)
	}
	sort.Slice(syms, func(i, j int) bool {
		if syms[i].Size != syms[j].Size {
			return syms[i].Size > syms[j].Size
		}
		return syms[i].Name < syms[j].Name
	})
	if len(syms) > top {
		syms = syms[:top]
	}
	r.TopSymbols = append(r.TopSymbols, syms...)
	return r
}

func sortRows(rows []*sizeRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Total != rows[j].Total {
			return rows[i].Total > rows[j].Total
		}
		return rows[i].Name < rows[j].Name
	})
}

func pct(f float64) string { return fmt.Sprintf("%5.1f%%", f*100) }

func printBloat(c *cli.Context, r *bloatReport, top int) {
	p := c.Out
	p.Title(fmt.Sprintf("sm-go bloat — %s", relPath(c, r.Path)))
	p.KV(
		[2]string{"File", fmt.Sprintf("%s (%s %s/%s, %s)", ui.Bytes(r.FileSize), r.Format, r.GOOS, r.GOARCH, r.GoVersion)},
		[2]string{"Main module", r.MainModule},
		[2]string{"Symbols", r.SymbolSource},
		[2]string{"Strip savings", fmt.Sprintf("%s with -ldflags=\"-s -w\"", ui.Bytes(int64(r.StripSavings)))},
	)
	for _, n := range r.Notes {
		p.Warn("%s", n)
	}
	p.Heading("Sections")
	var rows [][]string
	for _, k := range []string{binfile.KindText, binfile.KindRodata, binfile.KindData, binfile.KindPclntab, binfile.KindSymtab, binfile.KindDWARF, binfile.KindOther} {
		n := r.Totals[k]
		if n == 0 {
			continue
		}
		rows = append(rows, []string{k, ui.Bytes(int64(n)), pct(float64(n) / float64(max(r.FileSize, 1))), ui.Bar(float64(n)/float64(max(r.FileSize, 1)), 20)})
	}
	p.Table([]string{"KIND", "BYTES", "FILE", ""}, rows)
	if !r.Supported {
		return
	}
	p.Heading("Modules")
	rows = nil
	for _, m := range r.Modules {
		rows = append(rows, []string{ui.Truncate(m.Name, 50), m.Version, ui.Bytes(int64(m.Total)), ui.Bytes(int64(m.Text)),
			ui.Bytes(int64(m.Rodata + m.Data)), pct(m.Share), ui.Bar(m.Share, 15)})
	}
	p.Table([]string{"MODULE", "VERSION", "TOTAL", "TEXT", "DATA", "SHARE", ""}, rows)
	if len(r.Unattributed) > 0 {
		var parts []string
		for _, k := range sortedKeys(r.Unattributed) {
			parts = append(parts, fmt.Sprintf("%s %s", k, ui.Bytes(int64(r.Unattributed[k]))))
		}
		p.Printf("  %s\n", p.Dim("not covered by symbols (padding, merged linker data): "+strings.Join(parts, ", ")))
	}
	p.Heading(fmt.Sprintf("Top %d packages", min(top, len(r.Packages))))
	rows = nil
	for i, x := range r.Packages {
		if i >= top {
			break
		}
		rows = append(rows, []string{ui.Truncate(x.Name, 60), ui.Bytes(int64(x.Total)), ui.Bytes(int64(x.Text)), ui.Bytes(int64(x.Rodata + x.Data)), pct(x.Share)})
	}
	p.Table([]string{"PACKAGE", "TOTAL", "TEXT", "DATA", "SHARE"}, rows)
	p.Heading(fmt.Sprintf("Top %d symbols", len(r.TopSymbols)))
	rows = nil
	for _, s := range r.TopSymbols {
		rows = append(rows, []string{ui.Bytes(int64(s.Size)), s.Kind, ui.Truncate(s.Name, 90)})
	}
	p.Table([]string{"SIZE", "KIND", "SYMBOL"}, rows)
}

// ---------------- diff ----------------

type delta struct {
	Name   string `json:"name"`
	Old    uint64 `json:"old"`
	New    uint64 `json:"new"`
	Delta  int64  `json:"delta"`
	Status string `json:"status,omitempty"` // added, removed
}

type versionChange struct {
	Path string `json:"path"`
	Old  string `json:"old,omitempty"`
	New  string `json:"new,omitempty"`
}

type bloatDiff struct {
	Old            *bloatReport     `json:"old"`
	New            *bloatReport     `json:"new"`
	FileDelta      int64            `json:"fileDelta"`
	FileDeltaPct   float64          `json:"fileDeltaPercent"`
	Sections       []delta          `json:"sections"`
	ModuleVersions []versionChange  `json:"moduleVersions"`
	Modules        []delta          `json:"modules"`
	Packages       []delta          `json:"packages"`
	Symbols        []delta          `json:"symbols"`
	MaxGrowth      string           `json:"maxGrowth,omitempty"`
	Findings       []report.Finding `json:"findings"`
}

func runBloatDiff(c *cli.Context, top int, budget int64) error {
	var growBytes int64
	growPct := -1.0
	if g := strings.TrimSpace(*bloatFlags.maxGrowth); g != "" {
		if strings.HasSuffix(g, "%") {
			var v float64
			if _, err := fmt.Sscanf(strings.TrimSuffix(g, "%"), "%g", &v); err != nil || v < 0 {
				return cli.Usagef("--max-growth: invalid percentage %q", g)
			}
			growPct = v
		} else {
			b, err := parseSize(g)
			if err != nil {
				return cli.Usagef("--max-growth: %v", err)
			}
			growBytes = b
			if b == 0 {
				growPct = 0
			}
		}
	}
	of, err := openBinary(c, c.Args[0])
	if err != nil {
		return err
	}
	nf, err := openBinary(c, c.Args[1])
	if err != nil {
		return err
	}
	// Keep every symbol for the comparison; trim afterwards.
	o, n := attribute(of, 1<<62), attribute(nf, 1<<62)
	d := &bloatDiff{Old: o, New: n, FileDelta: n.FileSize - o.FileSize, MaxGrowth: *bloatFlags.maxGrowth,
		ModuleVersions: []versionChange{}, Findings: []report.Finding{}}
	if o.FileSize > 0 {
		d.FileDeltaPct = float64(d.FileDelta) / float64(o.FileSize) * 100
	}
	if o.GOOS != n.GOOS || o.GOARCH != n.GOARCH {
		c.Warnf("comparing binaries for different platforms (%s/%s vs %s/%s)", o.GOOS, o.GOARCH, n.GOOS, n.GOARCH)
	}
	if o.SymbolSource != n.SymbolSource {
		c.Warnf("the binaries have different symbol information (%s vs %s); per-symbol deltas are not comparable", o.SymbolSource, n.SymbolSource)
	}
	kinds := map[string]bool{}
	for k := range o.Totals {
		kinds[k] = true
	}
	for k := range n.Totals {
		kinds[k] = true
	}
	for _, k := range sortedKeys(kinds) {
		if k == binfile.KindBSS {
			continue
		}
		d.Sections = append(d.Sections, mkDelta(k, o.Totals[k], n.Totals[k]))
	}
	sortDeltas(d.Sections)
	// Module versions.
	mods := map[string]bool{}
	for m := range o.modVersions {
		mods[m] = true
	}
	for m := range n.modVersions {
		mods[m] = true
	}
	for _, m := range sortedKeys(mods) {
		ov, nv := o.modVersions[m], n.modVersions[m]
		if ov != nv {
			d.ModuleVersions = append(d.ModuleVersions, versionChange{m, ov, nv})
		}
	}
	d.Modules = diffRows(o.modByName, n.modByName, -1)
	d.Packages = diffRows(o.pkgByName, n.pkgByName, top)
	syms := map[string][2]uint64{}
	for k, s := range o.allSyms {
		v := syms[k]
		v[0] = s.Size
		syms[k] = v
	}
	for k, s := range n.allSyms {
		v := syms[k]
		v[1] = s.Size
		syms[k] = v
	}
	for k, v := range syms {
		if v[0] != v[1] {
			d.Symbols = append(d.Symbols, mkDelta(k, v[0], v[1]))
		}
	}
	sortDeltas(d.Symbols)
	if len(d.Symbols) > top {
		d.Symbols = d.Symbols[:top]
	}
	if d.Symbols == nil {
		d.Symbols = []delta{}
	}
	// Trim the embedded reports to the requested size.
	for _, r := range []*bloatReport{o, n} {
		if len(r.Packages) > top {
			r.Packages = r.Packages[:top]
		}
		if len(r.TopSymbols) > top {
			r.TopSymbols = r.TopSymbols[:top]
		}
	}
	if d.FileDelta > 0 && (growPct >= 0 && d.FileDeltaPct > growPct || growBytes > 0 && d.FileDelta > growBytes) {
		d.Findings = append(d.Findings, report.Finding{Severity: report.High, Rule: "size-growth", File: n.Path,
			Title: fmt.Sprintf("binary grew by %s (%+.1f%%), over the --max-growth %s limit", ui.Bytes(d.FileDelta), d.FileDeltaPct, d.MaxGrowth)})
	}
	if budget > 0 && n.FileSize > budget {
		d.Findings = append(d.Findings, report.Finding{Severity: report.High, Rule: "size-budget", File: n.Path,
			Title: fmt.Sprintf("new binary is %s, over the %s budget", ui.Bytes(n.FileSize), ui.Bytes(budget))})
	}
	if len(d.Findings) > 0 {
		c.Issues()
	}
	c.SetResult(d)
	if c.Text() {
		printBloatDiff(c, d)
	}
	return nil
}

func mkDelta(name string, o, n uint64) delta {
	d := delta{Name: name, Old: o, New: n, Delta: int64(n) - int64(o)}
	switch {
	case o == 0 && n > 0:
		d.Status = "added"
	case o > 0 && n == 0:
		d.Status = "removed"
	}
	return d
}

func sortDeltas(ds []delta) {
	sort.Slice(ds, func(i, j int) bool {
		ai, aj := abs(ds[i].Delta), abs(ds[j].Delta)
		if ai != aj {
			return ai > aj
		}
		return ds[i].Name < ds[j].Name
	})
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func diffRows(o, n map[string]*sizeRow, top int) []delta {
	names := map[string]bool{}
	for k := range o {
		names[k] = true
	}
	for k := range n {
		names[k] = true
	}
	out := []delta{}
	for k := range names {
		var ov, nv uint64
		if r := o[k]; r != nil {
			ov = r.Total
		}
		if r := n[k]; r != nil {
			nv = r.Total
		}
		if ov != nv {
			out = append(out, mkDelta(k, ov, nv))
		}
	}
	sortDeltas(out)
	if top >= 0 && len(out) > top {
		out = out[:top]
	}
	return out
}

func signed(n int64) string {
	if n < 0 {
		return "-" + ui.Bytes(-n)
	}
	return "+" + ui.Bytes(n)
}

func printBloatDiff(c *cli.Context, d *bloatDiff) {
	p := c.Out
	p.Title(fmt.Sprintf("sm-go bloat --diff — %s → %s", relPath(c, d.Old.Path), relPath(c, d.New.Path)))
	color := p.Green
	if d.FileDelta > 0 {
		color = p.Red
	}
	p.KV(
		[2]string{"Old", fmt.Sprintf("%s (%s, %s/%s)", ui.Bytes(d.Old.FileSize), d.Old.GoVersion, d.Old.GOOS, d.Old.GOARCH)},
		[2]string{"New", fmt.Sprintf("%s (%s, %s/%s)", ui.Bytes(d.New.FileSize), d.New.GoVersion, d.New.GOOS, d.New.GOARCH)},
		[2]string{"Change", color(fmt.Sprintf("%s (%+.2f%%)", signed(d.FileDelta), d.FileDeltaPct))},
	)
	table := func(title string, ds []delta) {
		if len(ds) == 0 {
			return
		}
		p.Heading(title)
		var rows [][]string
		for _, x := range ds {
			c := p.Green
			if x.Delta > 0 {
				c = p.Red
			}
			rows = append(rows, []string{c(signed(x.Delta)), ui.Bytes(int64(x.Old)), ui.Bytes(int64(x.New)), ui.Truncate(x.Name, 80), p.Dim(x.Status)})
		}
		p.Table([]string{"DELTA", "OLD", "NEW", "NAME", ""}, rows)
	}
	var changed []delta
	for _, x := range d.Sections {
		if x.Delta != 0 {
			changed = append(changed, x)
		}
	}
	table("Sections", changed)
	if len(d.ModuleVersions) > 0 {
		p.Heading("Module versions")
		var rows [][]string
		for _, m := range d.ModuleVersions {
			o, n := m.Old, m.New
			if o == "" {
				o = p.Dim("(added)")
			}
			if n == "" {
				n = p.Dim("(removed)")
			}
			rows = append(rows, []string{m.Path, o, "→", n})
		}
		p.Table(nil, rows)
	}
	table("Modules", d.Modules)
	table("Packages", d.Packages)
	table("Symbols", d.Symbols)
	if len(d.Modules) == 0 && len(changed) == 0 && d.FileDelta == 0 {
		p.Println()
		p.OK("no size differences")
	}
	for _, f := range d.Findings {
		p.Println()
		p.Bad("%s", f.Title)
	}
}
