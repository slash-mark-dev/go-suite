package upgrade

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/feeds"
	"github.com/slash-mark-dev/go-suite/internal/modgraph"
	"github.com/slash-mark-dev/go-suite/internal/module"
	"github.com/slash-mark-dev/go-suite/internal/project"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/vulndb"
	"github.com/slash-mark-dev/go-suite/internal/vulnscan"
)

var toolchainFlags struct {
	failOn func() (report.Severity, error)
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "toolchain",
		Group:   group,
		Summary: "Toolchain readiness: go/toolchain directives, Go support status and stdlib vulns",
		Usage:   "sm-go toolchain [flags]",
		Help: `Reads the go and toolchain directives of go.mod (and go.work in a workspace),
finds the highest go version required by any dependency in the build list
(and the requirement chain that pulls it in), and works out which Go
toolchain the go command will actually run under the current GOTOOLCHAIN
setting (local, auto, path, goX, goX+auto, goX+path) — or whether the
build fails because switching is not allowed.

The selected and the local Go versions are checked against the release
list from go.dev/dl (a Go release is supported until two newer major
releases exist), the latest patch release of each line, and the Go
vulnerability database entries for the standard library ("stdlib") and the
go command ("toolchain").

Exit code 1 when a finding reaches --fail-on (default medium).`,
		Examples: []string{
			"sm-go toolchain",
			"sm-go toolchain --fail-on high --json",
			"GOTOOLCHAIN=local sm-go toolchain -C ./service",
		},
		Sources: []string{"go.dev/dl release list", "Go vulnerability database", "Go module proxy"},
		Flags: func(fs *flag.FlagSet) {
			toolchainFlags.failOn = cli.SeverityFlag(fs, "fail-on", "medium", "exit 1 on findings at or above this `severity`")
		},
		Run: runToolchain,
	})
}

// WorkModule is a module of a workspace and its go line.
type WorkModule struct {
	Path string `json:"path"`
	Dir  string `json:"dir"`
	Go   string `json:"go"`
}

// ToolchainResult is the JSON result of toolchain.
type ToolchainResult struct {
	Module      string           `json:"module,omitempty"`
	File        string           `json:"file,omitempty"` // file whose go/toolchain lines rule (go.mod or go.work)
	Go          string           `json:"go,omitempty"`
	Toolchain   string           `json:"toolchain,omitempty"`
	Workspace   []WorkModule     `json:"workspace,omitempty"`
	DepsMaxGo   string           `json:"depsMaxGo,omitempty"`
	DepsMaxBy   string           `json:"depsMaxGoBy,omitempty"`
	DepsChain   []string         `json:"depsMaxGoChain,omitempty"`
	Required    string           `json:"required,omitempty"` // minimum Go version needed to build
	LocalGo     string           `json:"localGo,omitempty"`
	GOTOOLCHAIN string           `json:"gotoolchain"`
	Selected    string           `json:"selected,omitempty"` // toolchain the go command runs
	Selection   string           `json:"selection"`
	Fails       bool             `json:"buildFails"`
	Supported   []string         `json:"supportedLines,omitempty"`
	LatestPatch string           `json:"latestPatch,omitempty"` // newest release of the selected line
	Latest      string           `json:"latest,omitempty"`      // newest stable Go release
	SelectedOK  *bool            `json:"selectedSupported,omitempty"`
	LocalOK     *bool            `json:"localSupported,omitempty"`
	StdlibVulns []*vulnscan.Vuln `json:"stdlibVulns"`
	Findings    []report.Finding `json:"findings"`
}

func runToolchain(c *cli.Context) error {
	if len(c.Args) > 0 {
		return cli.Usagef("toolchain takes no arguments")
	}
	failOn, err := toolchainFlags.failOn()
	if err != nil {
		return err
	}
	res := &ToolchainResult{GOTOOLCHAIN: c.Env.Get("GOTOOLCHAIN"), LocalGo: localGoVersion(c),
		StdlibVulns: []*vulnscan.Vuln{}, Findings: []report.Finding{}}
	if res.GOTOOLCHAIN == "" {
		res.GOTOOLCHAIN = "auto"
	}
	add := func(f report.Finding) { res.Findings = append(res.Findings, f) }

	p, err := c.Project()
	switch {
	case errors.Is(err, project.ErrNoModule):
		c.Warnf("no go.mod found: checking the local Go toolchain only")
		p = nil
	case err != nil:
		return err
	}
	if p != nil {
		if err := toolchainProject(c, p, res, add); err != nil {
			return err
		}
	}
	selectToolchain(res, add)

	// Release data.
	rels, err := feeds.GoReleases(c.Ctx, c.HTTP(), c.Endpoint("godev"))
	if err != nil {
		c.Warnf("go.dev release list unavailable: %v", err)
	} else {
		toolchainSupport(res, rels, add)
	}

	// Standard library and go command vulnerabilities.
	if res.Selected != "" {
		var mods []module.Version
		if m, ok := vulnscan.StdlibModule(res.Selected); ok {
			mods = append(mods, m, module.Version{Path: vulndb.Toolchain, Version: m.Version})
		}
		vs, err := vulnscan.Scan(c.Ctx, c, mods)
		if err != nil {
			return fmt.Errorf("vulnerability database: %w", err)
		}
		vulnscan.Enrich(c.Ctx, c, vs)
		vulnscan.Sort(vs)
		res.StdlibVulns = append(res.StdlibVulns, vs...)
		for _, v := range vs {
			fix := ""
			if v.FixedIn != "" {
				fix = "upgrade Go to " + semverToGo(v.FixedIn) + " or later"
			}
			add(report.Finding{Severity: v.Severity, Rule: "stdlib-vuln", Module: v.Module, Version: res.Selected,
				Title: fmt.Sprintf("%s affects %s (%s): %s", v.ID, res.Selected, v.Module, v.Summary), Fix: fix, URL: v.URL,
				Data: map[string]any{"packages": v.Packages}})
		}
	}

	report.SortFindings(res.Findings)
	c.SetResult(res)
	if len(report.AtLeast(res.Findings, failOn)) > 0 {
		c.Issues()
	}
	if c.Text() {
		printToolchain(c, res)
	}
	return nil
}

func toolchainProject(c *cli.Context, p *project.Project, res *ToolchainResult, add func(report.Finding)) error {
	res.Module = p.ModulePath()
	file := p.GoMod
	res.File = p.Rel(p.GoModPath)
	if p.Work != nil {
		file = p.Work
		res.File = p.Rel(p.WorkPath)
	}
	if file != nil {
		res.Go, res.Toolchain = file.Go, file.Toolchain
	}
	goLine := res.Go
	if goLine == "" {
		// No go line: the go command assumes go 1.16 for go.mod (1.18
		// for go.work).
		goLine = "1.16"
		if p.Work != nil {
			goLine = "1.18"
		}
		add(report.Finding{Severity: report.Low, Rule: "no-go-directive", File: res.File,
			Title: "no go directive: the go command assumes go " + goLine + " (no graph pruning, old language semantics)",
			Fix:   "run go mod tidy (or go get go@<version>)"})
	}
	if res.Toolchain != "" && res.Toolchain != "default" {
		tv := strings.TrimPrefix(res.Toolchain, "go")
		if modgraph.CompareGo(tv, goLine) < 0 {
			add(report.Finding{Severity: report.Low, Rule: "toolchain-below-go", File: res.File,
				Title: fmt.Sprintf("toolchain %s is older than go %s and has no effect", res.Toolchain, goLine),
				Fix:   "remove the toolchain line or raise it"})
		}
	}
	if p.Work != nil {
		for _, m := range p.Mains {
			wm := WorkModule{Path: m.Path(), Dir: p.Rel(m.Dir)}
			if m.File != nil {
				wm.Go = m.File.Go
			}
			res.Workspace = append(res.Workspace, wm)
			if modgraph.CompareGo(wm.Go, goLine) > 0 {
				add(report.Finding{Severity: report.Medium, Rule: "workspace-go-behind", File: res.File, Module: wm.Path,
					Title: fmt.Sprintf("go.work says go %s but workspace module %s requires go %s", goLine, wm.Path, wm.Go),
					Fix:   "go work use (or raise the go line of go.work to " + wm.Go + ")"})
			}
		}
	}
	g, err := c.Graph()
	if err != nil {
		return err
	}
	maxGo, who, err := maxSelectedGo(c, g)
	if err != nil {
		return err
	}
	res.DepsMaxGo = maxGo
	res.Required = goLine
	if res.DepsMaxGo != "" {
		res.DepsMaxBy = who.String()
		for _, m := range g.Chain(who) {
			if m.Version == "" {
				res.DepsChain = append(res.DepsChain, m.Path)
			} else {
				res.DepsChain = append(res.DepsChain, m.String())
			}
		}
		if modgraph.CompareGo(res.DepsMaxGo, goLine) > 0 {
			res.Required = res.DepsMaxGo
			add(report.Finding{Severity: report.Medium, Rule: "go-directive-behind-deps", File: res.File, Module: who.Path, Version: who.Version,
				Title: fmt.Sprintf("go %s is lower than go %s required by %s", goLine, res.DepsMaxGo, who),
				Fix:   "go get go@" + res.DepsMaxGo + " (or go mod tidy)"})
		}
	}
	for m, err := range g.Errors {
		c.Warnf("%s: %v", m, err)
	}
	return nil
}

// selectToolchain reproduces the go command's toolchain selection
// (cmd/go/internal/toolchain): GOTOOLCHAIN sets the minimum toolchain and
// whether switching is allowed; with +auto/+path the go command runs the
// newer of the minimum, the go line (as goX.Y.0 for language versions
// >= 1.21), the toolchain line and any dependency's go line.
func selectToolchain(res *ToolchainResult, add func(report.Finding)) {
	mode := res.GOTOOLCHAIN
	min, switching := mode, ""
	if i := strings.Index(mode, "+"); i >= 0 {
		min, switching = mode[:i], mode[i+1:]
	}
	switch min {
	case "auto", "path":
		min, switching = "local", min
	}
	minV := strings.TrimPrefix(min, "go")
	if min == "local" {
		minV = res.LocalGo
	}
	if minV == "" {
		res.Selection = "the local Go version is unknown (go command not found)"
		return
	}
	res.Selected = "go" + minV
	need := res.Required
	if need == "" {
		res.Selection = fmt.Sprintf("GOTOOLCHAIN=%s: no module, runs %s", mode, res.Selected)
		return
	}
	switch switching {
	case "auto", "path":
		target := minV
		if modgraph.CompareGo(need, target) > 0 {
			target = need
			if isLang(need) && modgraph.CompareGo(need, "1.21") >= 0 {
				target += ".0"
			}
		}
		if tc := strings.TrimPrefix(res.Toolchain, "go"); res.Toolchain != "" && res.Toolchain != "default" && modgraph.CompareGo(tc, target) > 0 {
			target = tc
		}
		res.Selected = "go" + target
		if target == minV {
			res.Selection = fmt.Sprintf("GOTOOLCHAIN=%s: runs %s (meets go %s)", mode, res.Selected, need)
			if min == "local" {
				res.Selection = fmt.Sprintf("GOTOOLCHAIN=%s: runs the local %s (meets go %s)", mode, res.Selected, need)
			}
			return
		}
		how := "downloads it from the module proxy (golang.org/toolchain)"
		if switching == "path" {
			how = "looks for it in PATH"
		}
		res.Selection = fmt.Sprintf("GOTOOLCHAIN=%s: switches to %s and %s", mode, res.Selected, how)
		add(report.Finding{Severity: report.Info, Rule: "toolchain-switch", Version: res.Selected,
			Title: fmt.Sprintf("the go command will switch to %s (local go%s is older than required)", res.Selected, res.LocalGo)})
	default:
		if modgraph.CompareGo(need, minV) > 0 {
			res.Fails = true
			res.Selection = fmt.Sprintf("GOTOOLCHAIN=%s: runs %s, which is older than the required go %s: builds fail", mode, res.Selected, need)
			add(report.Finding{Severity: report.High, Rule: "toolchain-too-old", Version: res.Selected,
				Title: fmt.Sprintf("go %s is required but GOTOOLCHAIN=%s pins %s and forbids switching", need, mode, res.Selected),
				Fix:   "install Go " + need + " or later, or set GOTOOLCHAIN=auto"})
			return
		}
		res.Selection = fmt.Sprintf("GOTOOLCHAIN=%s: runs %s (no switching)", mode, res.Selected)
	}
}

func goLineOf(v string) string {
	v = strings.TrimPrefix(v, "go")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return "go" + v
	}
	minor := parts[1]
	for i, r := range minor {
		if r < '0' || r > '9' {
			minor = minor[:i]
			break
		}
	}
	return "go" + parts[0] + "." + minor
}

func semverToGo(v string) string {
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimSuffix(v, ".0-0")
	return "go" + v
}

func toolchainSupport(res *ToolchainResult, rels []feeds.GoRelease, add func(report.Finding)) {
	lines, latest := feeds.SupportedGo(rels)
	res.Supported = lines
	if len(lines) > 0 {
		res.Latest = latest[lines[0]]
	}
	supported := func(v string) bool {
		for _, l := range lines {
			if l == goLineOf(v) {
				return true
			}
		}
		return false
	}
	newest := strings.TrimPrefix(res.Latest, "go")
	if res.Required != "" && newest != "" && modgraph.CompareGo(res.Required, newest) > 0 {
		add(report.Finding{Severity: report.High, Rule: "go-unreleased", File: res.File,
			Title: fmt.Sprintf("go %s is required but the newest Go release is %s", res.Required, res.Latest)})
	}
	if res.Selected != "" && len(lines) > 0 {
		ok := supported(res.Selected)
		res.SelectedOK = &ok
		if !ok {
			add(report.Finding{Severity: report.High, Rule: "go-unsupported", Version: res.Selected,
				Title: fmt.Sprintf("%s is no longer supported: security fixes go only to %s", res.Selected, strings.Join(lines, " and ")),
				Fix:   "upgrade to " + res.Latest})
		}
		if lp := latest[goLineOf(res.Selected)]; lp != "" {
			res.LatestPatch = lp
			if modgraph.CompareGo(strings.TrimPrefix(lp, "go"), strings.TrimPrefix(res.Selected, "go")) > 0 && ok {
				add(report.Finding{Severity: report.Low, Rule: "go-patch-available", Version: res.Selected,
					Title: fmt.Sprintf("%s is available (running %s)", lp, res.Selected), Fix: "upgrade to " + lp})
			}
		}
	}
	if res.LocalGo != "" && len(lines) > 0 {
		ok := supported(res.LocalGo)
		res.LocalOK = &ok
		if !ok && "go"+res.LocalGo != res.Selected {
			add(report.Finding{Severity: report.Medium, Rule: "local-go-unsupported", Version: "go" + res.LocalGo,
				Title: fmt.Sprintf("the installed go%s is no longer supported", res.LocalGo), Fix: "install " + res.Latest})
		}
	}
}

func printToolchain(c *cli.Context, res *ToolchainResult) {
	out := c.Out
	out.Title("Toolchain readiness")
	var kv [][2]string
	if res.Module != "" {
		kv = append(kv, [2]string{"module", res.Module})
	}
	if res.File != "" {
		g := res.Go
		if g == "" {
			g = "(none)"
		}
		kv = append(kv, [2]string{"go directive", g + "  " + out.Dim(res.File)})
		if res.Toolchain != "" {
			kv = append(kv, [2]string{"toolchain", res.Toolchain})
		}
	}
	if res.DepsMaxGo != "" {
		kv = append(kv, [2]string{"deps need", "go " + res.DepsMaxGo + "  " + out.Dim("("+strings.Join(res.DepsChain, " → ")+")")})
	}
	if res.Required != "" {
		kv = append(kv, [2]string{"required", "go " + res.Required})
	}
	local := res.LocalGo
	if local == "" {
		local = "(not installed)"
	} else {
		local = "go" + local
	}
	kv = append(kv, [2]string{"local Go", local}, [2]string{"GOTOOLCHAIN", res.GOTOOLCHAIN})
	if res.Selected != "" {
		kv = append(kv, [2]string{"selected", res.Selected})
	}
	if len(res.Supported) > 0 {
		kv = append(kv, [2]string{"supported", strings.Join(res.Supported, ", ") + "  " + out.Dim("(latest "+res.Latest+")")})
	}
	out.KV(kv...)
	for _, wm := range res.Workspace {
		out.Printf("  %s %s %s\n", out.Dim("use"), wm.Path, out.Dim("go "+wm.Go))
	}
	out.Println()
	if res.Fails {
		out.Bad("%s", res.Selection)
	} else {
		out.Printf("%s %s\n", out.Dim("→"), res.Selection)
	}
	if len(res.Findings) == 0 {
		out.OK("toolchain ready: no problems found")
		return
	}
	out.Heading("Findings")
	for _, f := range res.Findings {
		out.Printf("  %s %s\n", out.Sev(f.Severity), f.Title)
		if f.Fix != "" {
			out.Printf("           %s %s\n", out.Dim("fix:"), f.Fix)
		}
	}
}
