package security

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/httpx"
	"github.com/slash-mark-dev/go-suite/internal/par"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/sumdb"
	"github.com/slash-mark-dev/go-suite/internal/ui"
)

// go.sum entry statuses.
const (
	SumOK           = "verified"
	SumMismatch     = "mismatch"     // the log records a different hash
	SumMissing      = "missing"      // the log has no record for the version
	SumExcluded     = "excluded"     // GONOSUMDB/GOPRIVATE/GOSUMDB=off/-insecure
	SumUnsupported  = "unsupported"  // not an h1: hash
	SumInconsistent = "inconsistent" // the log failed a proof
	SumError        = "error"        // lookup failed (network)
)

// SumEntry is one go.sum line and its verification.
type SumEntry struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	// Kind is "zip" for the module hash and "go.mod" for the /go.mod hash.
	Kind     string `json:"kind"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Hash     string `json:"hash"`
	LogHash  string `json:"logHash,omitempty"`
	Status   string `json:"status"`
	RecordID int64  `json:"recordId,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// TreeHead is a signed tree head.
type TreeHead struct {
	Size int64  `json:"size"`
	Hash string `json:"hash"`
}

// TreeCheck compares the current log with a tree head seen earlier.
type TreeCheck struct {
	// Source is "sm-go" (sm-go's own cache) or "go" (the go command's
	// $GOPATH/pkg/sumdb cache).
	Source   string    `json:"source"`
	Path     string    `json:"path,omitempty"`
	Previous *TreeHead `json:"previous,omitempty"`
	// Status is "consistent", "forked", "none" (no previous head) or
	// "error".
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// SumdbResult is the result of the sumdb tool.
type SumdbResult struct {
	Database string `json:"database"`
	// Disabled explains why verification is turned off for everything.
	Disabled string           `json:"disabled,omitempty"`
	Tree     *TreeHead        `json:"tree,omitempty"`
	Checks   []TreeCheck      `json:"treeChecks"`
	Entries  []*SumEntry      `json:"entries"`
	Summary  map[string]int   `json:"summary"` // status -> lines
	Findings []report.Finding `json:"findings"`
	Failing  int              `json:"failing"`
}

var sumdbFlags struct {
	failOn func() (report.Severity, error)
	all    *bool
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "sumdb",
		Group:   group,
		Summary: "Verify go.sum against the checksum transparency log",
		Usage:   "sm-go sumdb [flags]",
		Help: `Verifies every go.sum line (module "h1:" hashes and "/go.mod" hashes; go.work.sum too in
workspaces) against the checksum database configured by GOSUMDB, the way the go command does:
each record is fetched with its signed tree head and checked with a Merkle inclusion proof.

Reported problems:
  mismatch      the log records a different hash than go.sum: the module content you
                built with differs from what everyone else got (critical)
  missing       the log has no record of the version (high)
  inconsistent  the log failed an inclusion or consistency proof (critical)

The current signed tree head is also proven consistent (append-only) with the last tree head
sm-go saw and with the one cached by the go command in $GOPATH/pkg/sumdb; a failure means the
log was forked or rewritten and is reported as critical.

Like the go command, modules matching GONOSUMDB or GOPRIVATE are not checked, and nothing is
checked with GOSUMDB=off or the legacy GOFLAGS=-insecure.`,
		Examples: []string{
			"sm-go sumdb",
			"sm-go sumdb --all",
			"GONOSUMDB=corp.example.com sm-go sumdb --json",
		},
		Sources: []string{"Go checksum database (sum.golang.org or GOSUMDB)"},
		Flags: func(fs *flag.FlagSet) {
			sumdbFlags.all = fs.Bool("all", false, "list every go.sum line, not only problems")
			sumdbFlags.failOn = cli.SeverityFlag(fs, "fail-on", "high", "minimum `severity` that fails the run")
		},
		Run: runSumdb,
	})
}

// insecureFlag reports whether GOFLAGS sets the legacy -insecure flag.
func insecureFlag(goflags string) bool {
	for _, f := range strings.Fields(goflags) {
		f = strings.TrimLeft(f, "-")
		if f == "insecure" || f == "insecure=true" || f == "insecure=1" {
			return true
		}
	}
	return false
}

func runSumdb(c *cli.Context) error {
	failOn, err := sumdbFlags.failOn()
	if err != nil {
		return err
	}
	if len(c.Args) > 0 {
		return cli.Usagef("sumdb takes no arguments")
	}
	p, err := c.Project()
	if err != nil {
		return err
	}
	res := &SumdbResult{Checks: []TreeCheck{}, Entries: []*SumEntry{}, Summary: map[string]int{}, Findings: []report.Finding{}}
	gosumdb := c.Env.Get("GOSUMDB")
	name, vkey, _, cfgErr := sumdb.Config(gosumdb)
	if cfgErr != nil {
		return cli.Usagef("%v", cfgErr)
	}
	res.Database = name
	sumFile := "go.sum"
	if p.GoSumPath != "" {
		sumFile = p.Rel(p.GoSumPath)
	}
	for _, l := range p.GoSum.Lines {
		e := &SumEntry{Module: l.Path, Version: l.ModVersion(), Kind: "zip", File: sumFile, Line: l.Line, Hash: l.Hash}
		if l.IsGoMod() {
			e.Kind = "go.mod"
		}
		res.Entries = append(res.Entries, e)
	}
	for _, perr := range p.GoSum.Errors {
		c.Warnf("%v", perr)
	}

	switch {
	case name == "off":
		res.Disabled = "GOSUMDB=off"
	case insecureFlag(c.Env.Get("GOFLAGS")):
		res.Disabled = "GOFLAGS=-insecure"
	}
	if res.Disabled != "" {
		for _, e := range res.Entries {
			e.Status, e.Detail = SumExcluded, res.Disabled
		}
		c.Warnf("checksum verification is disabled by %s; nothing was verified", res.Disabled)
		res.Findings = append(res.Findings, report.Finding{Severity: report.Low, Rule: "sumdb/disabled",
			Title: "checksum database verification is disabled by " + res.Disabled,
			Fix:   "unset it and use GONOSUMDB/GOPRIVATE for private modules only"})
		return finishSumdb(c, res, failOn, 0)
	}

	client, err := c.SumDB()
	if err != nil {
		return cli.Usagef("GOSUMDB: %v", err)
	}
	ctx := c.Ctx

	// Tree heads seen earlier, before anything updates sm-go's cache.
	smPrev, smHad := client.Known()
	goPath, goPrev, goHad, goErr := goCachedTree(c, name, vkey)

	forked := false
	cur, _, err := client.Latest(ctx)
	smCheck := TreeCheck{Source: "sm-go", Path: filepath.Join(c.Env.CacheDir(), "sumdb", name, "latest"), Status: "none"}
	if smHad {
		smCheck.Previous = head(smPrev)
	}
	switch {
	case errors.Is(err, sumdb.ErrSecurity):
		forked = true
		smCheck.Status, smCheck.Detail = "forked", err.Error()
	case err != nil:
		return fmt.Errorf("checksum database %s: %w", name, err)
	case smHad:
		smCheck.Status = "consistent"
	default:
		smCheck.Detail = "first run: tree head recorded for future consistency checks"
	}
	res.Checks = append(res.Checks, smCheck)
	if !forked {
		res.Tree = head(cur)
	}

	goCheck := TreeCheck{Source: "go", Path: goPath, Status: "none"}
	switch {
	case goErr != nil:
		goCheck.Status, goCheck.Detail = "error", goErr.Error()
	case !goHad:
		goCheck.Detail = "the go command has not cached a tree head for " + name
	case forked:
		goCheck.Previous = head(goPrev)
		goCheck.Status, goCheck.Detail = "error", "not checked: the current tree head is already inconsistent"
	default:
		goCheck.Previous = head(goPrev)
		if err := client.CheckConsistency(ctx, goPrev, cur); errors.Is(err, sumdb.ErrSecurity) {
			forked = true
			goCheck.Status, goCheck.Detail = "forked", err.Error()
		} else if err != nil {
			goCheck.Status, goCheck.Detail = "error", err.Error()
			c.Warnf("checking the go command's tree head: %v", err)
		} else {
			goCheck.Status = "consistent"
		}
	}
	res.Checks = append(res.Checks, goCheck)
	for _, ch := range res.Checks {
		if ch.Status == "forked" {
			src := "sm-go's cached tree head"
			if ch.Source == "go" {
				src = "the go command's cached tree head (" + ch.Path + ")"
			}
			res.Findings = append(res.Findings, report.Finding{Severity: report.Critical, Rule: "sumdb/forked",
				Title:  fmt.Sprintf("checksum database %s is inconsistent with %s", name, src),
				Detail: ch.Detail,
				Fix:    "do not trust new go.sum entries; report the inconsistency to the database operator"})
		}
	}

	// Look up every module version that needs verification.
	type key struct{ path, version string }
	var keys []key
	byKey := map[key][]*SumEntry{}
	for _, e := range res.Entries {
		if sumdb.Excluded(c.Env, e.Module) {
			e.Status, e.Detail = SumExcluded, "matched by GONOSUMDB/GOPRIVATE"
			continue
		}
		if !strings.HasPrefix(e.Hash, "h1:") {
			e.Status, e.Detail = SumUnsupported, "only h1: hashes can be verified"
			continue
		}
		if forked {
			e.Status, e.Detail = SumInconsistent, "not verified: the log is inconsistent"
			continue
		}
		k := key{e.Module, e.Version}
		if byKey[k] == nil {
			keys = append(keys, k)
		}
		byKey[k] = append(byKey[k], e)
	}
	looks, errs := par.Map(ctx, 8, keys, func(ctx context.Context, k key) (*sumdb.Lookup, error) {
		return client.Lookup(ctx, k.path, k.version)
	})
	netErrs := 0
	for i, k := range keys {
		l, err := looks[i], errs[i]
		for _, e := range byKey[k] {
			switch {
			case err == nil:
				e.RecordID = l.ID
				e.LogHash = l.ZipHash
				if e.Kind == "go.mod" {
					e.LogHash = l.ModHash
				}
				if e.LogHash == e.Hash {
					e.Status = SumOK
				} else {
					e.Status = SumMismatch
				}
			case httpx.IsNotFound(err):
				e.Status, e.Detail = SumMissing, "the checksum database has no record of this version"
			case errors.Is(err, sumdb.ErrSecurity):
				e.Status, e.Detail = SumInconsistent, err.Error()
			default:
				e.Status, e.Detail = SumError, err.Error()
			}
		}
		if err != nil && !httpx.IsNotFound(err) && !errors.Is(err, sumdb.ErrSecurity) {
			netErrs++
			if netErrs <= 3 {
				c.Warnf("lookup %s@%s: %v", k.path, k.version, err)
			}
		}
	}
	if t, ok := client.Known(); ok && !forked {
		res.Tree = head(t)
	}
	for _, e := range res.Entries {
		where := fmt.Sprintf("%s:%d", e.File, e.Line)
		switch e.Status {
		case SumMismatch:
			res.Findings = append(res.Findings, report.Finding{Severity: report.Critical, Rule: "sumdb/mismatch", Module: e.Module, Version: e.Version,
				File: e.File, Line: e.Line, Title: fmt.Sprintf("%s %s %s hash differs from the checksum database", e.Module, e.Version, e.Kind),
				Detail: fmt.Sprintf("go.sum:   %s\nlog:      %s (record %d)", e.Hash, e.LogHash, e.RecordID),
				Fix:    fmt.Sprintf("delete the line at %s and run go mod download %s@%s; investigate where the other content came from", where, e.Module, e.Version)})
		case SumMissing:
			res.Findings = append(res.Findings, report.Finding{Severity: report.High, Rule: "sumdb/missing", Module: e.Module, Version: e.Version,
				File: e.File, Line: e.Line, Title: fmt.Sprintf("%s %s is not in the checksum database", e.Module, e.Version),
				Detail: "the go command refuses unknown versions of public modules; a private module should be listed in GONOSUMDB/GOPRIVATE",
				Fix:    "check the version exists upstream, or add the module to GOPRIVATE"})
		case SumInconsistent:
			if !forked {
				res.Findings = append(res.Findings, report.Finding{Severity: report.Critical, Rule: "sumdb/proof", Module: e.Module, Version: e.Version,
					File: e.File, Line: e.Line, Title: fmt.Sprintf("record for %s %s failed verification", e.Module, e.Version), Detail: e.Detail})
			}
		case SumUnsupported:
			res.Findings = append(res.Findings, report.Finding{Severity: report.Low, Rule: "sumdb/unsupported", Module: e.Module, Version: e.Version,
				File: e.File, Line: e.Line, Title: fmt.Sprintf("%s %s uses an unsupported hash algorithm", e.Module, e.Version), Detail: e.Hash})
		}
	}
	return finishSumdb(c, res, failOn, netErrs)
}

func finishSumdb(c *cli.Context, res *SumdbResult, failOn report.Severity, netErrs int) error {
	for _, e := range res.Entries {
		res.Summary[e.Status]++
	}
	report.SortFindings(res.Findings)
	for _, f := range res.Findings {
		if f.Severity.Meets(failOn) {
			res.Failing++
		}
	}
	c.SetResult(res)
	if res.Failing > 0 {
		c.Issues()
	}
	if c.Text() {
		printSumdb(c, res, *sumdbFlags.all)
	}
	if netErrs > 0 && res.Failing == 0 {
		return fmt.Errorf("%s could not be verified (checksum database unreachable)", ui.Plural(netErrs, "module version", "module versions"))
	}
	return nil
}

func head(t sumdb.Tree) *TreeHead { return &TreeHead{Size: t.N, Hash: t.Hash.String()} }

// goCachedTree reads the tree head the go command cached for database
// name ($GOPATH/pkg/sumdb/<name>/latest) and verifies its signature.
func goCachedTree(c *cli.Context, name, vkey string) (string, sumdb.Tree, bool, error) {
	gopath := c.Env.Get("GOPATH")
	if gopath == "" {
		return "", sumdb.Tree{}, false, nil
	}
	path := filepath.Join(filepath.SplitList(gopath)[0], "pkg", "sumdb", name, "latest")
	msg, err := os.ReadFile(path)
	if err != nil {
		return path, sumdb.Tree{}, false, nil
	}
	v, err := sumdb.NewVerifier(vkey)
	if err != nil {
		return path, sumdb.Tree{}, false, err
	}
	n, err := sumdb.OpenNote(msg, v)
	if err != nil {
		return path, sumdb.Tree{}, false, fmt.Errorf("%s: %v", path, err)
	}
	t, err := sumdb.ParseTree([]byte(n.Text))
	if err != nil {
		return path, sumdb.Tree{}, false, fmt.Errorf("%s: %v", path, err)
	}
	return path, t, true, nil
}

func printSumdb(c *cli.Context, res *SumdbResult, all bool) {
	o := c.Out
	subject := "."
	if p, err := c.Project(); err == nil && p.ModulePath() != "" {
		subject = p.ModulePath()
	}
	o.Title("sm-go sumdb · " + subject)
	mods := map[string]bool{}
	for _, e := range res.Entries {
		mods[e.Module+"@"+e.Version] = true
	}
	kv := [][2]string{{"database", res.Database}, {"go.sum", fmt.Sprintf("%s for %s", ui.Plural(len(res.Entries), "line", "lines"), ui.Plural(len(mods), "module version", "module versions"))}}
	if res.Tree != nil {
		kv = append(kv, [2]string{"tree", fmt.Sprintf("size %d, hash %s", res.Tree.Size, res.Tree.Hash)})
	}
	o.KV(kv...)
	if res.Disabled != "" {
		o.Println()
		o.Warn("checksum verification disabled by %s: nothing verified", res.Disabled)
		return
	}
	o.Heading("Log consistency")
	for _, ch := range res.Checks {
		who := "sm-go's previous tree head"
		if ch.Source == "go" {
			who = "the go command's cached tree head"
		}
		prev := ""
		if ch.Previous != nil {
			prev = fmt.Sprintf(" (size %d)", ch.Previous.Size)
		}
		switch ch.Status {
		case "consistent":
			o.OK("append-only since %s%s", who, prev)
		case "forked":
			o.Bad("%s %s%s: %s", o.Red("FORKED:"), who, prev, ch.Detail)
		case "none":
			o.Printf("%s %s\n", o.Dim("-"), o.Dim(ch.Detail))
		default:
			o.Warn("%s: %s", who, ch.Detail)
		}
	}
	if all {
		o.Heading("go.sum lines")
		var rows [][]string
		for _, e := range res.Entries {
			st := e.Status
			switch st {
			case SumOK:
				st = o.Green(st)
			case SumMismatch, SumInconsistent, SumMissing:
				st = o.Red(st)
			case SumExcluded:
				st = o.Dim(st)
			}
			rows = append(rows, []string{fmt.Sprintf("%d", e.Line), e.Module, e.Version, e.Kind, st})
		}
		o.Table([]string{"LINE", "MODULE", "VERSION", "KIND", "STATUS"}, rows)
	}
	if len(res.Findings) > 0 {
		o.Heading(fmt.Sprintf("Problems (%d)", len(res.Findings)))
		printFindings(c, res.Findings)
	}
	var parts []string
	var sts []string
	for st := range res.Summary {
		sts = append(sts, st)
	}
	sort.Strings(sts)
	for _, st := range sts {
		parts = append(parts, fmt.Sprintf("%d %s", res.Summary[st], st))
	}
	if len(parts) == 0 {
		parts = []string{"go.sum is empty"}
	}
	o.Println()
	o.Printf("%s %s\n", o.Bold("Summary:"), strings.Join(parts, " · "))
}
