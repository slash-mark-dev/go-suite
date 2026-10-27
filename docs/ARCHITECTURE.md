# sm-go architecture

sm-go is one static binary built from the Go standard library only (no
third-party modules). Every tool is a `cli.Tool` registered from an `init`
function in one of six group packages under `internal/tools/`.

```
cmd/sm-go/                 main: imports the six group packages
internal/cli               tool registry, flags, global options, services, JSON envelope, exit codes
internal/ui                terminal rendering (colors, tables, severity badges)
internal/report            Severity + generic Finding model
internal/semver            Go semver (matches golang.org/x/mod/semver)
internal/module            module paths, escaping, major suffixes, pseudo-versions (matches x/mod/module)
internal/modfile           go.mod / go.work / go.sum / vendor/modules.txt parser (matches x/mod/modfile)
internal/modgraph          module graph + Minimum Version Selection with graph pruning (matches `go list -m all`)
internal/modproxy          GOPROXY client (list/info/mod/zip/latest, retractions, deprecations), module cache, go-command fallback
internal/modzip            module zips and go.sum "h1:" hashes (matches x/mod/sumdb/dirhash)
internal/sumdb             checksum database client: signed notes, tiles, inclusion & consistency proofs
internal/vulndb            Go vulnerability database (vuln.go.dev, OSV) with symbol data
internal/feeds             CISA KEV, FIRST EPSS, deps.dev, GitHub, index.golang.org, go.dev/dl
internal/loader            `go list -deps -json` + go/types type-checking of the whole program from source
internal/callgraph         CHA call graph, entry points, reachability and call paths
internal/project           finds go.mod / go.work, loads go.sum and vendor/modules.txt
internal/source            module path -> source repository (code hosts, go-import vanity pages per cmd/go rules), RDAP domain records
internal/httpx             HTTP client: 10-minute disk cache, revalidation, offline mode, retries, scoped credentials
internal/alert             Slack / Teams / Discord / generic webhook delivery
internal/endpoints         base URLs of every data source (overridable with SMGO_*_URL)
internal/testenv           fake proxy + sumdb + vulndb + GitHub + deps.dev + KEV + EPSS + index for tests
verify/                    differential tests against golang.org/x/mod and the real go command
```

## Writing a tool

```go
func init() {
	cli.Register(&cli.Tool{
		Name:    "example",
		Group:   "Dependency analysis",
		Summary: "one line for `sm-go help`",
		Usage:   "sm-go example [module] [flags]",
		Help:    "Longer description.",
		Examples: []string{"sm-go example", "sm-go example --json"},
		Sources: []string{"Go module proxy"},
		Flags: func(fs *flag.FlagSet) { exampleFlags.max = fs.Int("max", 10, "...") },
		Run:   runExample,
	})
}
```

Inside `Run(c *cli.Context) error`:

- `c.Args` are positional arguments; tool flags are read from the
  variables registered in `Flags` (flags may come before or after args).
- Services: `c.Project()`, `c.Graph()` (MVS build list), `c.Proxy()`,
  `c.VulnDB()`, `c.SumDB()`, `c.GitHub()`, `c.DepsDev()`, `c.HTTP()`,
  `c.Load(loader.Config{...})`, `c.Endpoint("kev")`, `c.Env`.
- Output: always build a result struct and call `c.SetResult(v)`; print
  human output with `c.Out` only when `c.Text()` (in `--json` mode `c.Out`
  discards everything anyway).
- Call `c.Issues()` when problems at or above the failure threshold are
  found (exit code 1). Return `cli.Usagef(...)` for bad input (exit 2) and
  ordinary errors for runtime/network failures (exit 3).
- Optional data sources (GitHub, deps.dev, KEV, EPSS) degrade gracefully:
  `c.Warnf(...)` and continue.

## Private modules

A module is private when its path matches `GOPRIVATE`, `GONOPROXY` or
`GONOSUMDB` (`c.IsPrivate(path)`, `module.MatchPrefixPatterns` rules, with
the go command's defaults). Private module paths are never sent to
third-party services. The only hosts contacted about a private module are
its own: its go-import pages, its repository root when that is on the same
host (`vanity`), and the GitHub API when the path itself is
`github.com/...` (`c.GitHubAPIAllowed(path)`). The module proxy and the
checksum database are used exactly as `GONOPROXY` / `GONOSUMDB` direct, as
the go command does. Enforcement lives in the clients, so new callers
cannot leak: `c.DepsDev()` refuses private module paths and project IDs
with `feeds.ErrPrivate`, and `source.DomainInfo` refuses private domains
(RDAP) with `source.ErrPrivate`. Tools mark skipped data "skipped: private
module", and `cli.Run` prints at most one warning summarising how many
private modules were not sent to third-party services (`c.NotePrivate`).

## Offline mode

`--offline` (or `SMGO_OFFLINE=1`) serves HTTP from the cache only, and
every go command sm-go runs gets `goenv.OfflineGoEnv` appended to its
environment (`c.Env.Environ()`): `GOPROXY=off`, `GONOPROXY=none` (private
modules would otherwise still be fetched directly), `GOSUMDB=off` (the go
command otherwise asks the checksum database directly even with
`GOPROXY=off`; go.sum is still verified) and `GOVCS=*:off`. Tools then use
the module cache only and fail with exit code 3 when something is missing.

## Exit codes

`0` ok · `1` issues found · `2` usage error · `3` network/runtime error

## Testing

`internal/testenv` starts one local server that plays every data source.
`w.Run(dir, "tool", "--json")` runs sm-go in-process with an environment
pointing at it; `w.Go(dir, ...)` runs the real go command against the same
fake proxy and checksum database.

`verify/` compares sm-go's semver, module, modfile, tlog, note, dirhash and
sumdb client with golang.org/x/mod (copied from the local Go installation
by `verify/setup.sh`), and the MVS build list with `go list -m all` on
hundreds of random module graphs.
