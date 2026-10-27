// Package cli is the command framework shared by every sm-go tool: the
// tool registry, flag parsing (flags may appear before or after
// arguments), global flags, lazily-built services, JSON envelopes and exit
// codes.
//
// Exit codes: 0 ok · 1 issues found · 2 usage error · 3 network/runtime error.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/endpoints"
	"github.com/slash-mark-dev/go-suite/internal/feeds"
	"github.com/slash-mark-dev/go-suite/internal/goenv"
	"github.com/slash-mark-dev/go-suite/internal/httpx"
	"github.com/slash-mark-dev/go-suite/internal/loader"
	"github.com/slash-mark-dev/go-suite/internal/modgraph"
	"github.com/slash-mark-dev/go-suite/internal/modproxy"
	"github.com/slash-mark-dev/go-suite/internal/project"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/sumdb"
	"github.com/slash-mark-dev/go-suite/internal/ui"
	"github.com/slash-mark-dev/go-suite/internal/vulndb"
)

// Version is the sm-go version, set at build time with -ldflags.
var Version = "1.0.0"

// Exit codes.
const (
	ExitOK      = 0
	ExitIssues  = 1
	ExitUsage   = 2
	ExitRuntime = 3
)

// Groups, in display order.
var Groups = []string{
	"Supply-chain security",
	"Origin & trust",
	"Dependency analysis",
	"Binary intelligence",
	"Upgrade & release",
	"Compliance & operations",
}

// Tool is one sm-go command.
type Tool struct {
	Name     string
	Group    string
	Summary  string   // one line, shown in `sm-go help`
	Usage    string   // e.g. "sm-go vuln [packages] [flags]"
	Help     string   // paragraph(s) shown in `sm-go help <tool>`
	Examples []string // example command lines
	// Sources lists the live data sources the tool reads, for help text.
	Sources []string
	// NeedsGo marks tools that run the go command.
	NeedsGo bool
	// Flags registers tool-specific flags.
	Flags func(fs *flag.FlagSet)
	// Run executes the tool.
	Run func(c *Context) error
}

var (
	regMu    sync.Mutex
	registry = map[string]*Tool{}
)

// Register adds a tool. It panics on duplicate names.
func Register(t *Tool) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := registry[t.Name]; dup {
		panic("duplicate tool " + t.Name)
	}
	registry[t.Name] = t
}

// Lookup returns a registered tool.
func Lookup(name string) *Tool {
	regMu.Lock()
	defer regMu.Unlock()
	return registry[name]
}

// Tools returns all tools sorted by group order then name.
func Tools() []*Tool {
	regMu.Lock()
	defer regMu.Unlock()
	gi := map[string]int{}
	for i, g := range Groups {
		gi[g] = i
	}
	var out []*Tool
	for _, t := range registry {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := gi[out[i].Group], gi[out[j].Group]
		if a != b {
			return a < b
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Global holds flags shared by every tool.
type Global struct {
	JSON    bool
	NoColor bool
	NoCache bool
	Offline bool
	Verbose bool
	Dir     string
	Timeout time.Duration
}

// UsageError is returned for bad command lines (exit code 2).
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

// Usagef returns a UsageError.
func Usagef(format string, a ...any) error { return &UsageError{Msg: fmt.Sprintf(format, a...)} }

// Context is passed to Tool.Run.
type Context struct {
	Ctx    context.Context
	Tool   *Tool
	Args   []string
	Flags  *flag.FlagSet
	G      Global
	Stdout io.Writer
	Stderr io.Writer
	Env    *goenv.Env
	Out    *ui.Printer

	issues   bool
	result   any
	warnings []string
	start    time.Time

	privMu      sync.Mutex
	privSkipped map[string]bool // private module paths kept from third parties

	once struct {
		http, proxy, vuln, sum, proj, graph sync.Once
	}
	http    *httpx.Client
	proxy   *modproxy.Proxy
	vuln    *vulndb.Client
	sum     *sumdb.Client
	sumErr  error
	proj    *project.Project
	projErr error
	graph   *modgraph.Graph
	grErr   error
}

// Issues marks that the tool found problems (exit code 1).
func (c *Context) Issues() { c.issues = true }

// HasIssues reports whether Issues was called.
func (c *Context) HasIssues() bool { return c.issues }

// SetResult sets the value emitted under "result" in --json mode.
func (c *Context) SetResult(v any) { c.result = v }

// Warnf records a warning: printed to stderr in text mode and included in
// the JSON envelope.
func (c *Context) Warnf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	c.warnings = append(c.warnings, msg)
	if !c.G.JSON {
		fmt.Fprintf(c.Stderr, "%s %s\n", c.Out.Yellow("warning:"), msg)
	}
}

// Logf prints a progress line to stderr when --verbose is set.
func (c *Context) Logf(format string, a ...any) {
	if c.G.Verbose {
		fmt.Fprintf(c.Stderr, "%s\n", c.Out.Dim(fmt.Sprintf(format, a...)))
	}
}

// Text reports whether human-readable output should be printed.
func (c *Context) Text() bool { return !c.G.JSON }

// Endpoint returns the base URL of a named data source.
func (c *Context) Endpoint(name string) string { return endpoints.URL(c.Env, name) }

// HTTP returns the shared HTTP client.
func (c *Context) HTTP() *httpx.Client {
	c.once.http.Do(func() {
		var log io.Writer
		if c.G.Verbose {
			log = c.Stderr
		}
		ttl := 10 * time.Minute
		if v := c.Env.Getenv("SMGO_CACHE_TTL"); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				ttl = d
			}
		}
		c.http = httpx.New(httpx.Options{
			CacheDir:  c.Env.CacheDir(),
			TTL:       ttl,
			NoCache:   c.G.NoCache,
			Offline:   c.G.Offline,
			Timeout:   c.G.Timeout,
			Env:       c.Env,
			GitHubAPI: c.Endpoint("github"),
			Log:       log,
		})
	})
	return c.http
}

// Proxy returns the module proxy client.
func (c *Context) Proxy() *modproxy.Proxy {
	c.once.proxy.Do(func() { c.proxy = modproxy.New(c.Env, c.HTTP()) })
	return c.proxy
}

// VulnDB returns the Go vulnerability database client.
func (c *Context) VulnDB() *vulndb.Client {
	c.once.vuln.Do(func() { c.vuln = vulndb.New(c.Endpoint("vulndb"), c.HTTP()) })
	return c.vuln
}

// SumDB returns the checksum database client configured by GOSUMDB.
func (c *Context) SumDB() (*sumdb.Client, error) {
	c.once.sum.Do(func() {
		c.sum, c.sumErr = sumdb.NewClient(c.Env, c.HTTP(), c.Env.CacheDir(), c.Proxy().URLs())
	})
	return c.sum, c.sumErr
}

// GitHub returns a GitHub API client (uses GITHUB_TOKEN/GH_TOKEN if set).
func (c *Context) GitHub() *feeds.GitHub {
	return &feeds.GitHub{Base: c.Endpoint("github"), HTTP: c.HTTP()}
}

// DepsDev returns a deps.dev client. It refuses (feeds.ErrPrivate) every
// lookup of a private module path or project, so callers cannot leak them.
func (c *Context) DepsDev() *feeds.DepsDev {
	return &feeds.DepsDev{Base: c.Endpoint("depsdev"), HTTP: c.HTTP(), Private: c.IsPrivate, OnPrivate: c.NotePrivate}
}

// IsPrivate reports whether a module path is private: it matches GOPRIVATE,
// GONOPROXY or GONOSUMDB (module.MatchPrefixPatterns, exactly like the go
// command). Private module paths are never sent to third-party services
// (deps.dev, RDAP, OSV, Scorecard, ...); only the module's own host is
// contacted (its go-import pages, and the GitHub API for github.com/...
// paths), plus the module proxy and checksum database as GONOPROXY and
// GONOSUMDB allow, as the go command does.
func (c *Context) IsPrivate(path string) bool { return c.Env.IsPrivate(path) }

// GitHubAPIAllowed reports whether the GitHub API may be asked about the
// repository of modulePath: always for public modules, and for private
// modules only when the path itself is on github.com (the GitHub API is
// then the module's own host).
func (c *Context) GitHubAPIAllowed(modulePath string) bool {
	if !c.IsPrivate(modulePath) || strings.HasPrefix(modulePath, "github.com/") {
		return true
	}
	c.NotePrivate(modulePath)
	return false
}

// SkipPrivate reports whether modulePath is private, recording it for the
// end-of-run summary when it is. Callers use it to skip a third-party
// lookup.
func (c *Context) SkipPrivate(modulePath string) bool {
	if !c.IsPrivate(modulePath) {
		return false
	}
	c.NotePrivate(modulePath)
	return true
}

// NotePrivate records that a lookup of a private module path (or of a name
// derived from it) was not sent to a third-party service. Run prints one
// warning summarising them.
func (c *Context) NotePrivate(name string) {
	c.privMu.Lock()
	defer c.privMu.Unlock()
	if c.privSkipped == nil {
		c.privSkipped = map[string]bool{}
	}
	c.privSkipped[name] = true
}

func (c *Context) privateSummary() {
	c.privMu.Lock()
	n := len(c.privSkipped)
	c.privMu.Unlock()
	if n == 0 {
		return
	}
	what := "private module (GOPRIVATE/GONOPROXY/GONOSUMDB) was"
	if n > 1 {
		what = "private modules (GOPRIVATE/GONOPROXY/GONOSUMDB) were"
	}
	c.Warnf("%d %s not sent to third-party services; their deps.dev, RDAP and similar lookups were skipped", n, what)
}

// Dir returns the directory the tool operates in (-C, default ".").
func (c *Context) Dir() string {
	if c.G.Dir != "" {
		return c.G.Dir
	}
	return "."
}

// Project returns the main module / workspace.
func (c *Context) Project() (*project.Project, error) {
	c.once.proj.Do(func() { c.proj, c.projErr = project.Find(c.Dir(), c.Env) })
	return c.proj, c.projErr
}

// Graph returns the module graph of the project (MVS, cached).
func (c *Context) Graph() (*modgraph.Graph, error) {
	c.once.graph.Do(func() {
		p, err := c.Project()
		if err != nil {
			c.grErr = err
			return
		}
		c.graph, c.grErr = p.Graph(c.Ctx, c.Proxy())
		if c.grErr == nil {
			for m, err := range c.graph.Errors {
				c.Warnf("could not load go.mod of %s: %v", m, err)
			}
		}
	})
	return c.graph, c.grErr
}

// Load lists and (optionally) type-checks packages of the project.
func (c *Context) Load(cfg loader.Config) (*loader.Program, error) {
	if cfg.Env == nil {
		cfg.Env = c.Env
	}
	if cfg.Dir == "" {
		p, err := c.Project()
		if err != nil {
			return nil, err
		}
		cfg.Dir = p.ModDir
		if cfg.Dir == "" {
			cfg.Dir = p.Dir
		}
	}
	return loader.Load(c.Ctx, cfg)
}

// SeverityFlag registers a severity flag and returns a getter.
func SeverityFlag(fs *flag.FlagSet, name, def, usage string) func() (report.Severity, error) {
	s := fs.String(name, def, usage)
	return func() (report.Severity, error) {
		v, err := report.ParseSeverity(*s)
		if err != nil {
			return 0, Usagef("--%s: %v", name, err)
		}
		return v, nil
	}
}

// StringList is a repeatable / comma-separated flag.
type StringList []string

func (s *StringList) String() string { return strings.Join(*s, ",") }
func (s *StringList) Set(v string) error {
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			*s = append(*s, x)
		}
	}
	return nil
}

// Envelope is the --json output wrapper.
type Envelope struct {
	Tool        string    `json:"tool"`
	Version     string    `json:"version"`
	GeneratedAt time.Time `json:"generatedAt"`
	OK          bool      `json:"ok"`
	ExitCode    int       `json:"exitCode"`
	Result      any       `json:"result,omitempty"`
	Warnings    []string  `json:"warnings,omitempty"`
	Error       string    `json:"error,omitempty"`
}

func registerGlobal(fs *flag.FlagSet, g *Global) {
	fs.BoolVar(&g.JSON, "json", false, "print machine-readable JSON")
	fs.BoolVar(&g.NoColor, "no-color", false, "disable colors (NO_COLOR is also honoured)")
	fs.BoolVar(&g.NoCache, "no-cache", false, "ignore the 10-minute HTTP cache")
	fs.BoolVar(&g.Offline, "offline", false, "use cached data only; never touch the network")
	fs.BoolVar(&g.Verbose, "v", false, "verbose: log every request")
	fs.BoolVar(&g.Verbose, "verbose", false, "verbose: log every request")
	fs.StringVar(&g.Dir, "C", "", "run as if started in `dir`")
	fs.StringVar(&g.Dir, "dir", "", "run as if started in `dir`")
	fs.DurationVar(&g.Timeout, "timeout", 30*time.Second, "per-request network timeout")
}

// parseInterspersed parses flags that may appear anywhere among args.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		if rest[0] == "--" {
			return append(pos, rest[1:]...), nil
		}
		// fs.Parse stops at "--" too; distinguish by checking args.
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// Run executes sm-go with args (without the program name) and returns the
// exit code.
func Run(ctx context.Context, args []string, environ []string, stdout, stderr io.Writer) int {
	httpx.Version = Version
	env := goenv.Load(ctx, environ)
	if len(args) == 0 {
		printOverview(stdout, &ui.Printer{W: stdout, Color: colorOK(env, stdout, false)})
		return ExitOK
	}
	name := args[0]
	switch name {
	case "help", "-h", "--help", "-help":
		p := &ui.Printer{W: stdout, Color: colorOK(env, stdout, false)}
		if len(args) > 1 {
			if t := Lookup(args[1]); t != nil {
				printToolHelp(stdout, p, t)
				return ExitOK
			}
			fmt.Fprintf(stderr, "sm-go: unknown command %q\n", args[1])
			return ExitUsage
		}
		printOverview(stdout, p)
		return ExitOK
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "sm-go %s\n", Version)
		return ExitOK
	case "cache:clear", "cache-clear":
		n, err := httpx.ClearCache(env.CacheDir())
		if err != nil {
			fmt.Fprintf(stderr, "sm-go: %v\n", err)
			return ExitRuntime
		}
		fmt.Fprintf(stdout, "Cleared %s from %s\n", ui.Bytes(n), env.CacheDir())
		return ExitOK
	}
	t := Lookup(name)
	if t == nil {
		fmt.Fprintf(stderr, "sm-go: unknown command %q\nRun 'sm-go help' for the list of tools.\n", name)
		return ExitUsage
	}
	c := &Context{Ctx: ctx, Tool: t, Stdout: stdout, Stderr: stderr, Env: env, start: time.Now()}
	fs := flag.NewFlagSet("sm-go "+t.Name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	registerGlobal(fs, &c.G)
	help := fs.Bool("h", false, "show help")
	fs.BoolVar(help, "help", false, "show help")
	if t.Flags != nil {
		t.Flags(fs)
	}
	c.Flags = fs
	pos, err := parseInterspersed(fs, args[1:])
	c.Out = &ui.Printer{W: stdout, Color: colorOK(env, stdout, c.G.NoColor)}
	if err != nil {
		fmt.Fprintf(stderr, "sm-go %s: %v\nRun 'sm-go help %s' for usage.\n", t.Name, err, t.Name)
		return ExitUsage
	}
	if *help {
		printToolHelp(stdout, c.Out, t)
		return ExitOK
	}
	if c.G.JSON {
		c.Out = &ui.Printer{W: io.Discard}
	}
	c.Args = pos
	if env.Getenv("SMGO_OFFLINE") == "1" {
		c.G.Offline = true
	}
	if c.G.Offline {
		// Every go command sm-go runs inherits GOPROXY=off etc.
		env.SetOffline(true)
	}
	runErr := runTool(c)
	c.privateSummary()
	code := ExitOK
	var ue *UsageError
	switch {
	case runErr == nil && c.issues:
		code = ExitIssues
	case runErr == nil:
	case errors.As(runErr, &ue):
		code = ExitUsage
	case errors.Is(runErr, context.Canceled):
		code = ExitRuntime
	default:
		code = ExitRuntime
	}
	if c.G.JSON {
		env := Envelope{Tool: t.Name, Version: Version, GeneratedAt: time.Now().UTC().Truncate(time.Second),
			OK: code == ExitOK, ExitCode: code, Result: c.result, Warnings: c.warnings}
		if runErr != nil {
			env.Error = runErr.Error()
			env.Result = c.result
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(env); err != nil {
			fmt.Fprintf(stderr, "sm-go: encoding JSON: %v\n", err)
			return ExitRuntime
		}
	} else if runErr != nil {
		if code == ExitUsage {
			fmt.Fprintf(stderr, "sm-go %s: %v\nRun 'sm-go help %s' for usage.\n", t.Name, runErr, t.Name)
		} else {
			fmt.Fprintf(stderr, "sm-go %s: %v\n", t.Name, runErr)
		}
	}
	if c.G.Verbose && c.http != nil {
		s := c.http.Stats()
		fmt.Fprintf(stderr, "%s\n", c.Out.Dim(fmt.Sprintf("requests: %d network, %d cached, %d revalidated · %s",
			s.Network, s.CacheHits, s.Revalidated, time.Since(c.start).Round(time.Millisecond))))
	}
	return code
}

func runTool(c *Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if os.Getenv("SMGO_PANIC") == "1" {
				panic(r)
			}
			err = fmt.Errorf("internal error: %v (please report at https://github.com/slash-mark-dev/go-suite/issues)", r)
		}
	}()
	if c.Tool.NeedsGo && !c.Env.HaveGo() {
		return errors.New("this tool needs the go command; install Go from https://go.dev/dl")
	}
	return c.Tool.Run(c)
}

func colorOK(env *goenv.Env, w io.Writer, noColor bool) bool {
	if noColor {
		return false
	}
	if _, ok := env.Lookup("NO_COLOR"); ok {
		return false
	}
	if env.Getenv("SMGO_FORCE_COLOR") == "1" {
		return true
	}
	return isTerminal(w)
}

func printOverview(w io.Writer, p *ui.Printer) {
	fmt.Fprintf(w, "%s v%s\n", p.Bold("Slash Mark Go Suite"), Version)
	fmt.Fprintln(w, "Go Package Intelligence Suite: 30 advanced tools for Go modules, on live data from the")
	fmt.Fprintln(w, "Go module proxy, sum.golang.org, the module index, the Go vulnerability database (OSV),")
	fmt.Fprintln(w, "deps.dev, CISA KEV, FIRST EPSS and GitHub. Private modules (GOPRIVATE) are never sent")
	fmt.Fprintln(w, "to third-party services.")
	fmt.Fprintf(w, "\n%s sm-go <tool> [arguments] [flags]\n", p.Bold("Usage:"))
	tools := Tools()
	for _, g := range Groups {
		var in []*Tool
		for _, t := range tools {
			if t.Group == g {
				in = append(in, t)
			}
		}
		if len(in) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s\n", p.Bold(p.Cyan(strings.ToUpper(g))))
		for _, t := range in {
			fmt.Fprintf(w, "  %-12s %s\n", t.Name, t.Summary)
		}
	}
	fmt.Fprintf(w, "\n%s\n", p.Bold("Global flags"))
	fmt.Fprintln(w, "  --json        machine-readable output     --no-color   disable colors (or NO_COLOR)")
	fmt.Fprintln(w, "  --no-cache    bypass the 10-minute cache  --offline    cached data only")
	fmt.Fprintln(w, "  -C <dir>      run in another directory    -v           log every request")
	fmt.Fprintf(w, "\n%s 0 ok · 1 issues found · 2 usage error · 3 network/runtime error\n", p.Bold("Exit codes:"))
	fmt.Fprintln(w, "\nRun 'sm-go help <tool>' for details. 'sm-go cache:clear' empties the cache.")
	fmt.Fprintln(w, "Docs: https://github.com/slash-mark-dev/go-suite · https://slashmark.in")
}

func printToolHelp(w io.Writer, p *ui.Printer, t *Tool) {
	fmt.Fprintf(w, "%s — %s\n", p.Bold("sm-go "+t.Name), t.Summary)
	usage := t.Usage
	if usage == "" {
		usage = "sm-go " + t.Name + " [flags]"
	}
	fmt.Fprintf(w, "\n%s %s\n", p.Bold("Usage:"), usage)
	if t.Help != "" {
		fmt.Fprintf(w, "\n%s\n", strings.TrimSpace(t.Help))
	}
	if len(t.Sources) > 0 {
		fmt.Fprintf(w, "\n%s %s\n", p.Bold("Live data:"), strings.Join(t.Sources, ", "))
	}
	fs := flag.NewFlagSet(t.Name, flag.ContinueOnError)
	if t.Flags != nil {
		t.Flags(fs)
	}
	var lines []string
	fs.VisitAll(func(f *flag.Flag) {
		name, usage := flag.UnquoteUsage(f)
		flagStr := "--" + f.Name
		if len(f.Name) == 1 {
			flagStr = "-" + f.Name
		}
		if name != "" {
			flagStr += " " + name
		}
		def := ""
		if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" && f.DefValue != "[]" {
			def = fmt.Sprintf(" (default %s)", f.DefValue)
		}
		lines = append(lines, fmt.Sprintf("  %-24s %s%s", flagStr, usage, def))
	})
	if len(lines) > 0 {
		fmt.Fprintf(w, "\n%s\n%s\n", p.Bold("Flags:"), strings.Join(lines, "\n"))
	}
	fmt.Fprintf(w, "\n%s --json, --no-color, --no-cache, --offline, -C <dir>, -v, --timeout\n", p.Bold("Global:"))
	if len(t.Examples) > 0 {
		fmt.Fprintf(w, "\n%s\n", p.Bold("Examples:"))
		for _, e := range t.Examples {
			fmt.Fprintf(w, "  %s\n", e)
		}
	}
}
