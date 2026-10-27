// Package e2e runs every documented example of every sm-go tool (the
// Examples shown by `sm-go help <tool>`) as a subprocess of the real
// binary against a realistic project in the testenv fake world, so the
// help text users read is proven to work. Examples are read from the cli
// registry: a new example is covered automatically.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/slash-mark-dev/go-suite/internal/cli"

	_ "github.com/slash-mark-dev/go-suite/internal/tools/binary"
	_ "github.com/slash-mark-dev/go-suite/internal/tools/compliance"
	_ "github.com/slash-mark-dev/go-suite/internal/tools/deps"
	_ "github.com/slash-mark-dev/go-suite/internal/tools/origin"
	_ "github.com/slash-mark-dev/go-suite/internal/tools/security"
	_ "github.com/slash-mark-dev/go-suite/internal/tools/upgrade"
)

var smgo string // path of the built sm-go binary

func TestMain(m *testing.M) {
	flag.Parse()
	if _, err := exec.LookPath("go"); err != nil {
		fmt.Println("e2e: go command not available; skipping")
		os.Exit(0)
	}
	tmp, err := os.MkdirTemp("", "smgo-e2e-bin")
	if err != nil {
		panic(err)
	}
	smgo = filepath.Join(tmp, "sm-go")
	out, err := exec.Command("go", "build", "-o", smgo, "github.com/slash-mark-dev/go-suite/cmd/sm-go").CombinedOutput()
	if err != nil {
		fmt.Printf("e2e: building sm-go: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}

// knownNetworked lists examples allowed to exit 3 because they inherently
// need a network resource the fake world cannot play. Keep it empty unless
// there is no way to substitute the resource.
var knownNetworked = map[string]string{}

// substitutions turn placeholders of the documented examples into
// resources of the fake world. {dir} is the example's working directory,
// {hook} a webhook receiver.
var substitutions = []struct{ from, to string }{
	{"github.com/a/b", "github.com/sirupsen/logrus"},
	{"github.com/c/d", "golang.org/x/text"},
	{"/usr/local/bin", "{dir}/dist"},
	{"/path/to/go.work", "{dir}/go.work"},
	{"https://hooks.slack.com/services/...", "{hook}/slack"},
	{"https://ci.example.com/hook", "{hook}/ci"},
}

// example is one parsed documented command line.
type example struct {
	tool    string
	line    string   // as documented
	env     []string // leading VAR=value assignments
	args    []string // after "sm-go"
	stdout  string   // "> file" redirection target
	piped   bool     // output was piped into another command
	follow  bool     // runs until interrupted
	fixture string
}

func parseExample(t *testing.T, tool, line string) example {
	ex := example{tool: tool, line: line}
	toks := strings.Fields(line)
	i := 0
	for ; i < len(toks) && regexp.MustCompile(`^[A-Z_][A-Z0-9_]*=`).MatchString(toks[i]); i++ {
		ex.env = append(ex.env, toks[i])
	}
	if i >= len(toks) || toks[i] != "sm-go" {
		t.Fatalf("%s: example %q does not start with sm-go", tool, line)
	}
	if i+1 >= len(toks) || toks[i+1] != tool {
		t.Errorf("%s: example %q runs another tool", tool, line)
	}
	for _, tok := range toks[i+1:] {
		if tok == "|" {
			ex.piped = true
			break
		}
		if tok == ">" {
			ex.stdout = "next"
			continue
		}
		if ex.stdout == "next" {
			ex.stdout = tok
			continue
		}
		ex.args = append(ex.args, tok)
	}
	for _, a := range ex.args {
		if a == "--follow" {
			ex.follow = true
		}
	}
	// Fixture choice.
	ex.fixture = "app"
	switch tool {
	case "workspace":
		ex.fixture = "ws"
	case "env":
		ex.fixture = "env"
	case "vendor":
		ex.fixture = "vendored"
	case "release":
		ex.fixture = "lib"
	case "apidiff":
		ex.fixture = "empty" // module arguments need no project
		if contains(ex.args, "--against") {
			ex.fixture = "lib"
		}
	case "caps":
		if contains(ex.args, "--diff") {
			ex.fixture = "empty" // "(no project needed)"
		}
	}
	return ex
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// outcome of one run, for the summary table.
type outcome struct {
	tool, name, line, status, detail string
}

var (
	outMu    sync.Mutex
	outcomes []outcome
)

func record(o outcome) {
	outMu.Lock()
	outcomes = append(outcomes, o)
	outMu.Unlock()
}

type runResult struct {
	stdout, stderr string
	code           int
	timedOut       bool
}

func runSmgo(ctx context.Context, dir string, env []string, args ...string) runResult {
	cmd := exec.CommandContext(ctx, smgo, args...)
	cmd.Dir = dir
	cmd.Env = env
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	r := runResult{stdout: out.String(), stderr: errb.String()}
	if ctx.Err() == context.DeadlineExceeded {
		r.timedOut = true
	}
	if ee, ok := err.(*exec.ExitError); ok {
		r.code = ee.ExitCode()
	} else if err != nil && !r.timedOut {
		r.code = -1
		r.stderr += "\nexec: " + err.Error()
	}
	return r
}

func TestExamples(t *testing.T) {
	f := buildWorld(t)
	empty := t.TempDir()
	fixtureDir := map[string]string{"env": f.app, "app": f.app, "lib": f.lib, "ws": f.ws, "vendored": f.vendored, "empty": empty}
	fixtureEnv := map[string][]string{
		"ws":       {"GOWORK="},  // workspace mode as a user has it (World.Env turns it off)
		"vendored": {"GOFLAGS="}, // default -mod=vendor
		"env":      {"GOFLAGS="}, // a developer's shell, not the test harness's -mod=mod
	}

	t.Run("run", func(t *testing.T) {
		for _, tool := range cli.Tools() {
			if len(tool.Examples) == 0 {
				t.Errorf("%s has no examples", tool.Name)
			}
			for i, line := range tool.Examples {
				ex := parseExample(t, tool.Name, line)
				variants := []bool{false}
				if !contains(ex.args, "--json") && !ex.follow && ex.stdout == "" && !ex.piped {
					variants = append(variants, true) // also check the envelope
				}
				for _, addJSON := range variants {
					ex, addJSON := ex, addJSON
					name := fmt.Sprintf("%s/%d", tool.Name, i+1)
					if addJSON {
						name += "+json"
					}
					t.Run(name, func(t *testing.T) {
						t.Parallel()
						runExample(t, f, ex, addJSON, fixtureDir[ex.fixture], fixtureEnv[ex.fixture], name)
					})
				}
			}
		}
	})

	// A bare 'sm-go gate' in a project without .sm-go.json applies the
	// built-in default policy instead of failing with a usage error.
	t.Run("gate-default-policy", func(t *testing.T) {
		dir := copyTree(t, f.app, filepath.Join(t.TempDir(), "w"))
		os.Remove(filepath.Join(dir, ".sm-go.json"))
		env := f.w.Env("SMGO_CACHE_DIR=" + filepath.Join(t.TempDir(), "cache"))
		r := runSmgo(context.Background(), dir, env, "gate")
		if r.code != cli.ExitOK && r.code != cli.ExitIssues {
			t.Fatalf("exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
		}
		if !strings.Contains(r.stdout, "no policy file found; using the built-in default policy") {
			t.Errorf("text output does not say the default policy is used:\n%s", r.stdout)
		}
		r = runSmgo(context.Background(), dir, env, "gate", "--json")
		var envl struct {
			Result struct {
				Policy        string `json:"policy"`
				DefaultPolicy bool   `json:"defaultPolicy"`
			} `json:"result"`
		}
		if err := json.Unmarshal([]byte(r.stdout), &envl); err != nil || !envl.Result.DefaultPolicy {
			t.Errorf("--json: exit %d, %v\n%s", r.code, err, r.stdout)
		}
	})

	// Summary table.
	outMu.Lock()
	defer outMu.Unlock()
	sort.Slice(outcomes, func(i, j int) bool { return outcomes[i].name < outcomes[j].name })
	var b strings.Builder
	fmt.Fprintf(&b, "\n%-16s %-6s %s\n", "example", "status", "command")
	for _, o := range outcomes {
		fmt.Fprintf(&b, "%-16s %-6s %s\n", o.name, o.status, o.line)
		if o.detail != "" {
			fmt.Fprintf(&b, "%22s%s\n", "", strings.ReplaceAll(strings.TrimSpace(o.detail), "\n", "\n                      "))
		}
	}
	t.Log(b.String())
	// SMGO_E2E_REPORT=file saves this table; SMGO_E2E_OUTPUT=dir saves
	// the transcript of every example.
	if p := os.Getenv("SMGO_E2E_REPORT"); p != "" {
		os.WriteFile(p, []byte(b.String()), 0o644)
	}
}

func runExample(t *testing.T, f *fixtures, ex example, addJSON bool, src string, fenv []string, name string) {
	line := ex.line
	if addJSON {
		line += " --json"
	}
	status, detail := "pass", ""
	fail := func(format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		t.Errorf("%s", msg)
		if status == "pass" {
			status = "FAIL"
		}
		detail += msg + "\n"
	}
	defer func() { record(outcome{tool: ex.tool, name: name, line: line, status: status, detail: detail}) }()

	dir := copyTree(t, src, filepath.Join(t.TempDir(), "w"))
	if ex.tool == "gate" && contains(ex.args, "--init") {
		// --init writes .sm-go.json and refuses to overwrite one: run it
		// in a project that has none yet, as a new user would.
		os.Remove(filepath.Join(dir, ".sm-go.json"))
	}
	expand := func(s string) string {
		for _, sub := range substitutions {
			s = strings.ReplaceAll(s, sub.from, sub.to)
		}
		s = strings.ReplaceAll(s, "{dir}", dir)
		return strings.ReplaceAll(s, "{hook}", f.w.URL+"/hook")
	}
	var args []string
	for _, a := range ex.args {
		args = append(args, expand(a))
	}
	if addJSON {
		args = append(args, "--json")
	}
	env := append(append([]string{"SMGO_CACHE_DIR=" + filepath.Join(t.TempDir(), "cache")}, fenv...), nil...)
	for _, e := range ex.env {
		env = append(env, expand(e))
	}

	before := snapshot(dir)
	timeout := 4 * time.Minute
	if ex.follow {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	r := runSmgo(ctx, dir, f.w.Env(env...), args...)
	took := time.Since(start).Round(100 * time.Millisecond)
	if d := os.Getenv("SMGO_E2E_OUTPUT"); d != "" {
		// Keep every transcript, e.g. to review or publish the examples.
		fn := strings.NewReplacer("/", "_", "+", "_").Replace(name) + ".txt"
		os.WriteFile(filepath.Join(d, fn), []byte(fmt.Sprintf("$ %s\n# exit %d\n%s\n# stderr\n%s", line, r.code, r.stdout, r.stderr)), 0o644)
	}
	show := func() string {
		so, se := r.stdout, r.stderr
		if len(so) > 3000 {
			so = so[:3000] + "\n...[truncated]"
		}
		if len(se) > 3000 {
			se = se[:3000] + "\n...[truncated]"
		}
		return fmt.Sprintf("command: %s\n(dir %s)\nexit %d\nstdout:\n%s\nstderr:\n%s", strings.Join(append([]string{"sm-go"}, args...), " "), dir, r.code, so, se)
	}

	switch {
	case strings.Contains(r.stderr, "panic:") && strings.Contains(r.stderr, "goroutine "):
		fail("PANIC\n%s", show())
		return
	case strings.Contains(r.stdout+r.stderr, "dial tcp") || strings.Contains(r.stdout+r.stderr, "no such host"):
		fail("reached for the real network (every data source must come from the fake world)\n%s", show())
		return
	case r.timedOut && ex.follow:
		// --follow polls until interrupted: being alive after the first
		// poll, with output, is the documented behaviour.
		if strings.TrimSpace(r.stdout) == "" {
			fail("--follow printed nothing before being stopped\n%s", show())
		}
		status = "pass(follow)"
		return
	case r.timedOut:
		fail("timed out after %s\n%s", timeout, show())
		return
	case r.code == cli.ExitUsage:
		fail("documented example is a usage error (exit 2)\n%s", show())
		return
	case r.code == cli.ExitRuntime:
		if why, ok := knownNetworked[ex.line]; ok {
			status = "pass(net)"
			detail = why
		} else {
			fail("runtime error (exit 3)\n%s", show())
			return
		}
	case r.code != cli.ExitOK && r.code != cli.ExitIssues:
		fail("unexpected exit code\n%s", show())
		return
	}

	jsonOut := contains(args, "--json")
	switch {
	case jsonOut:
		var env map[string]any
		if err := json.Unmarshal([]byte(r.stdout), &env); err != nil {
			fail("--json output is not JSON: %v\n%s", err, show())
			break
		}
		for _, k := range []string{"tool", "version", "generatedAt", "ok", "exitCode"} {
			if _, ok := env[k]; !ok {
				fail("JSON envelope lacks %q\n%s", k, show())
			}
		}
		if env["tool"] != ex.tool {
			fail("envelope tool %v, want %s", env["tool"], ex.tool)
		}
		if c, _ := env["exitCode"].(float64); int(c) != r.code {
			fail("envelope exitCode %v, process exited %d", env["exitCode"], r.code)
		}
		if ok, _ := env["ok"].(bool); ok != (r.code == 0) {
			fail("envelope ok=%v with exit %d", env["ok"], r.code)
		}
		if r.code != cli.ExitRuntime && env["result"] == nil {
			fail("envelope has no result\n%s", show())
		}
	case ex.stdout != "":
		p := filepath.Join(dir, ex.stdout)
		if err := os.WriteFile(p, []byte(r.stdout), 0o644); err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(r.stdout) == "" {
			fail("redirected output is empty\n%s", show())
		} else if strings.HasSuffix(ex.stdout, ".json") && !json.Valid([]byte(r.stdout)) {
			fail("redirected output %s is not valid JSON\n%s", ex.stdout, show())
		}
	default:
		if strings.TrimSpace(r.stdout) == "" && !writesFile(ex.args) {
			fail("text output is empty\n%s", show())
		}
	}

	// Files the example says it writes.
	for i, a := range ex.args {
		if (a == "-o" || a == "--notice" || a == "--sarif" || a == "--state") && i+1 < len(ex.args) {
			p := filepath.Join(dir, expand(ex.args[i+1]))
			if fi, err := os.Stat(p); err != nil || fi.Size() == 0 {
				fail("%s %s: file not written (%v)\n%s", a, ex.args[i+1], err, show())
			} else if strings.HasSuffix(p, ".json") || strings.HasSuffix(p, ".sarif") {
				if !json.Valid([]byte(readFile(p))) {
					fail("%s is not valid JSON", p)
				}
			}
		}
	}
	// A format the example promises.
	if ex.piped && contains(ex.args, "dot") && !strings.HasPrefix(strings.TrimSpace(r.stdout), "digraph") {
		fail("--format dot output is not a DOT digraph\n%s", show())
	}

	// Read-only examples must not touch the module files.
	if !contains(ex.args, "--apply") {
		if after := snapshot(dir); after != before {
			fail("example modified go.mod/go.sum/go.work:\n--- before\n%s\n--- after\n%s", before, after)
		}
	}
	if status == "pass" && r.code == cli.ExitIssues {
		status = "pass(1)"
	}
	if status != "FAIL" {
		detail = strings.TrimSpace(detail + fmt.Sprintf(" (%s)", took))
	}
}

func writesFile(args []string) bool {
	for _, a := range args {
		switch a {
		case "-o", "--notice", "--sarif":
			return true
		}
	}
	return false
}

func snapshot(dir string) string {
	var b strings.Builder
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if fi.IsDir() && (fi.Name() == "vendor" || fi.Name() == ".git") {
			return filepath.SkipDir
		}
		switch fi.Name() {
		case "go.mod", "go.sum", "go.work", "go.work.sum":
			rel, _ := filepath.Rel(dir, p)
			fmt.Fprintf(&b, "== %s\n%s", rel, readFile(p))
		}
		return nil
	})
	return b.String()
}

// TestHelp checks that every tool's help renders the same through
// `sm-go help <tool>`, `--help` and `-h`, and lists its examples.
func TestHelp(t *testing.T) {
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "NO_COLOR=1", "SMGO_CACHE_DIR=" + t.TempDir()}
	ctx := context.Background()
	over := runSmgo(ctx, ".", env, "help")
	if over.code != 0 {
		t.Fatalf("sm-go help: exit %d\n%s", over.code, over.stderr)
	}
	tools := cli.Tools()
	if len(tools) != 30 {
		t.Errorf("%d tools registered; the overview says 30", len(tools))
	}
	for _, tool := range tools {
		if !regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(tool.Name) + ` `).MatchString(over.stdout) {
			t.Errorf("sm-go help does not list %s", tool.Name)
		}
		h := runSmgo(ctx, ".", env, "help", tool.Name)
		if h.code != 0 || !strings.Contains(h.stdout, "Usage:") {
			t.Errorf("sm-go help %s: exit %d\n%s%s", tool.Name, h.code, h.stdout, h.stderr)
			continue
		}
		for _, alt := range [][]string{{tool.Name, "--help"}, {tool.Name, "-h"}} {
			r := runSmgo(ctx, ".", env, alt...)
			if r.code != 0 || r.stdout != h.stdout {
				t.Errorf("sm-go %s: exit %d, output differs from sm-go help %s:\n%s%s", strings.Join(alt, " "), r.code, tool.Name, r.stdout, r.stderr)
			}
		}
		for _, e := range tool.Examples {
			if !strings.Contains(h.stdout, e) {
				t.Errorf("help %s lacks example %q", tool.Name, e)
			}
		}
		if tool.Summary == "" || tool.Usage == "" || tool.Help == "" {
			t.Errorf("%s: empty summary, usage or help", tool.Name)
		}
		// One style for the overview: sentence case, no final period.
		if r, _ := utf8.DecodeRuneInString(tool.Summary); !unicode.IsUpper(r) || strings.HasSuffix(tool.Summary, ".") {
			t.Errorf("%s: summary %q should start with a capital letter and not end with a period", tool.Name, tool.Summary)
		}
	}
}

var flagRE = regexp.MustCompile(`(^|[\s\[(|,'"\x60])(--?[a-zA-Z][a-zA-Z0-9-]*)`)

// TestDocumentedFlagsExist checks that every flag mentioned in a tool's
// Usage, Help and Examples is a flag of that tool (or a global flag).
func TestDocumentedFlagsExist(t *testing.T) {
	global := flag.NewFlagSet("global", flag.ContinueOnError)
	for _, n := range []string{"json", "no-color", "no-cache", "offline", "v", "verbose", "C", "dir", "timeout", "h", "help"} {
		global.Bool(n, false, "")
	}
	for _, tool := range cli.Tools() {
		fs := flag.NewFlagSet(tool.Name, flag.ContinueOnError)
		if tool.Flags != nil {
			tool.Flags(fs)
		}
		check := func(where, text string, strict bool) {
			for _, m := range flagRE.FindAllStringSubmatch(text, -1) {
				name := m[2]
				bare := strings.TrimLeft(name, "-")
				if !strict && !strings.HasPrefix(name, "--") {
					continue // single-dash words in prose ("-mod=mod", "-trimpath") are go flags
				}
				if fs.Lookup(bare) != nil || global.Lookup(bare) != nil {
					continue
				}
				if !strict && isForeignFlag(text, name) {
					continue
				}
				t.Errorf("%s: %s mentions %s, which is not a flag of sm-go %s", tool.Name, where, name, tool.Name)
			}
		}
		check("Usage", tool.Usage, false)
		check("Help", tool.Help, false)
		for _, e := range tool.Examples {
			_, after, _ := strings.Cut(e, "sm-go "+tool.Name)
			after, _, _ = strings.Cut(after, "|")
			check("example "+strconv(e), after, true)
		}
	}
}

func strconv(s string) string { return fmt.Sprintf("%q", s) }

// isForeignFlag reports whether a --flag in prose belongs to another
// command (go, git, govulncheck, another sm-go tool) rather than the tool.
func isForeignFlag(text, name string) bool {
	for _, line := range strings.Split(text, "\n") {
		i := strings.Index(line, name)
		if i < 0 {
			continue
		}
		pre := line[:i]
		for _, cmd := range []string{"go ", "git ", "govulncheck", "sm-go ", "gh "} {
			if j := strings.LastIndex(pre, cmd); j >= 0 {
				return true
			}
		}
	}
	return false
}
