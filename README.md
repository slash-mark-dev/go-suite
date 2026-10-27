# Slash Mark Go Suite

**Go Package Intelligence Suite.** 30 advanced tools that explore, analyze and manage Go modules, all in one static binary called `sm-go`.

[![CI](https://github.com/slash-mark-dev/go-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/slash-mark-dev/go-suite/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/slash-mark-dev/go-suite.svg)](https://pkg.go.dev/github.com/slash-mark-dev/go-suite)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Every tool runs on live data: the Go module proxy, the checksum database (sum.golang.org), the module index, the Go vulnerability database (OSV), deps.dev, CISA KEV, FIRST EPSS and GitHub. The suite has no basic lookups. Every tool analyzes, audits, plans or enforces something.

- **Standard library only.** No third-party dependencies, so the auditor adds nothing to your supply chain.
- **Matches the go command.** Semver, module paths, `go.mod` parsing, Minimum Version Selection with graph pruning, `go.sum` hashes and checksum-database proofs are tested against `golang.org/x/mod` and the real `go` command.
- **Built for CI.** Every tool supports `--json` and uses the same exit codes. Most tools take a `--fail-on` threshold; the rest use their own, such as `--min-score`, `--budget` or a gate policy. `gate` also writes SARIF and GitHub annotations.
- **Private code stays private.** Modules matching `GOPRIVATE` are never sent to third-party services.

## Install

```bash
go install github.com/slash-mark-dev/go-suite/cmd/sm-go@latest
```

This needs Go 1.23 or newer. You can also download a prebuilt binary for Linux, macOS or Windows (amd64 or arm64) from the [releases page](https://github.com/slash-mark-dev/go-suite/releases).

## Quick start

Run these inside any Go module:

```bash
sm-go vuln            # vulnerabilities your code actually calls
sm-go sumdb           # prove go.sum against the checksum transparency log
sm-go upgrade golang.org/x/net@latest   # what an upgrade would change, before you run it
sm-go gate            # one CI check, with a built-in default policy (sm-go gate --init to customize)
sm-go help            # all 30 tools
sm-go help <tool>     # flags and examples for one tool
```

## The 30 tools

| # | Tool | Command |
|---|---|---|
| | **Supply-chain security** | |
| 1 | Capability analysis of dependencies and of upgrades | [`caps`](#caps) |
| 2 | Side effects that dependencies run at import time | [`initscan`](#initscan) |
| 3 | Detect moved or deleted Git tags behind required versions | [`retag`](#retag) |
| 4 | Verify go.sum against the checksum transparency log | [`sumdb`](#sumdb) |
| 5 | Typosquatting and lookalike module paths in the build list | [`typosquat`](#typosquat) |
| 6 | Reachability vulnerability scan with KEV and EPSS context | [`vuln`](#vuln) |
| | **Origin & trust** | |
| 7 | Module health score (0-100) from Scorecard, releases, GitHub, deps.dev and vulns | [`health`](#health) |
| 8 | Retraction & deprecation watch with the nearest safe upgrade | [`retract`](#retract) |
| 9 | Repo takeover risk: deleted owners, renamed repos, expiring vanity domains | [`takeover`](#takeover) |
| 10 | Vanity import auditor: go-import tags, HTTPS, redirects, repo roots, domains | [`vanity`](#vanity) |
| | **Dependency analysis** | |
| 11 | Pruned module graph as a tree, go mod graph text, DOT, Mermaid or JSON | [`graph`](#graph) |
| 12 | Major-version split detector: foo, foo/v2, gopkg.in/x.vN side by side | [`majors`](#majors) |
| 13 | Replace & exclude auditor: local paths, stale forks, no-op and ignored directives | [`replace`](#replace) |
| 14 | Unused, test-only and misplaced // indirect requirements (go mod tidy semantics) | [`unused`](#unused) |
| 15 | MVS explainer: why a module is selected at its version | [`why`](#why) |
| 16 | Workspace (go.work) analyzer: conflicts, drift, go versions, go.work.sum, untracked modules | [`workspace`](#workspace) |
| | **Binary intelligence** | |
| 17 | Binary auditor: build info, vulnerabilities and hygiene of compiled Go binaries | [`binscan`](#binscan) |
| 18 | Binary size attribution: bytes per module, package and symbol; compare two builds | [`bloat`](#bloat) |
| 19 | Cross-compile readiness: cgo use, C libraries and CGO_ENABLED=0 builds per target | [`cgo`](#cgo) |
| | **Upgrade & release** | |
| 20 | API break detector: incompatible API changes between two module versions | [`apidiff`](#apidiff) |
| 21 | Major version migrator: plan (and apply) a move from foo to foo/vN | [`migrate`](#migrate) |
| 22 | Release checker: next semantic version from the API diff, path rules, retractions, git tag | [`release`](#release) |
| 23 | Toolchain readiness: go/toolchain directives, Go support status and stdlib vulns | [`toolchain`](#toolchain) |
| 24 | Upgrade simulator: what `go get module@version` would change, before you run it | [`upgrade`](#upgrade) |
| | **Compliance & operations** | |
| 25 | Audit GOPROXY, GOSUMDB, private patterns, .netrc and git rewrites | [`env`](#env) |
| 26 | CI policy gate: vulnerabilities, KEV, licenses, bans, retractions | [`gate`](#gate) |
| 27 | License compliance with SPDX text matching and NOTICE generation | [`license`](#license) |
| 28 | Live release radar for your dependencies from the Go module index | [`radar`](#radar) |
| 29 | CycloneDX 1.5 / SPDX 2.3 SBOM from the build list or a binary | [`sbom`](#sbom) |
| 30 | Verify vendor/ against modules.txt, go.mod, go.sum and the module zips | [`vendor`](#vendor) |

## Tool reference

### Supply-chain security

<a id="caps"></a>
#### `caps`: Capability analysis of dependencies and of upgrades

*Live data: Go module proxy, module source (type-checked)*

```bash
sm-go caps
sm-go caps --packages --json
sm-go caps --deny exec,plugin,cgo
```
<a id="initscan"></a>
#### `initscan`: Side effects that dependencies run at import time

*Live data: module source (type-checked call graph)*

```bash
sm-go initscan
sm-go initscan ./cmd/server --fail-on medium
sm-go initscan --all --json
```
<a id="retag"></a>
#### `retag`: Detect moved or deleted Git tags behind required versions

*Live data: Go module proxy, GitHub, Go checksum database*

```bash
sm-go retag
sm-go retag --direct --json
sm-go retag github.com/sirupsen/logrus@v1.9.3
```
<a id="sumdb"></a>
#### `sumdb`: Verify go.sum against the checksum transparency log

*Live data: Go checksum database (sum.golang.org or GOSUMDB)*

```bash
sm-go sumdb
sm-go sumdb --all
GONOSUMDB=corp.example.com sm-go sumdb --json
```
<a id="typosquat"></a>
#### `typosquat`: Typosquatting and lookalike module paths in the build list

*Live data: built-in list of popular Go modules, deps.dev*

```bash
sm-go typosquat
sm-go typosquat github.com/sirupsen/logrus@v1.9.3 github.com/spf13/cobra
sm-go typosquat --popular example.com/internal/lib --json
```
<a id="vuln"></a>
#### `vuln`: Reachability vulnerability scan with KEV and EPSS context

*Live data: Go vulnerability database, GitHub Advisory Database, CISA KEV, FIRST EPSS, Go module proxy*

```bash
sm-go vuln
sm-go vuln ./cmd/server --show-all
sm-go vuln --min-severity high --fail-on imported
```

### Origin & trust

<a id="health"></a>
#### `health`: Module health score (0-100) from Scorecard, releases, GitHub, deps.dev and vulns

*Live data: Go module proxy, deps.dev (OpenSSF Scorecard, dependents), GitHub REST API, Go vulnerability database*

```bash
sm-go health
sm-go health --direct --min-score 60
sm-go health github.com/spf13/cobra --json
```
<a id="retract"></a>
#### `retract`: Retraction & deprecation watch with the nearest safe upgrade

*Live data: Go module proxy*

```bash
sm-go retract
sm-go retract --direct --json
sm-go retract github.com/acme/lib@v1.4.0
```
<a id="takeover"></a>
#### `takeover`: Repo takeover risk: deleted owners, renamed repos, expiring vanity domains

*Live data: Go module proxy, GitHub REST API, vanity import pages, RDAP*

```bash
sm-go takeover
sm-go takeover --direct --fail-on high
sm-go takeover github.com/acme/lib go.example.org/tool --json
```
<a id="vanity"></a>
#### `vanity`: Vanity import auditor: go-import tags, HTTPS, redirects, repo roots, domains

*Live data: vanity import pages, Go module proxy, GitHub REST API, RDAP*

```bash
sm-go vanity
sm-go vanity go.uber.org/zap golang.org/x/net
sm-go vanity --subpaths 0 --json
```

### Dependency analysis

<a id="graph"></a>
#### `graph`: Pruned module graph as a tree, go mod graph text, DOT, Mermaid or JSON

*Live data: Go module proxy (go.mod files)*

```bash
sm-go graph
sm-go graph --format dot | dot -Tsvg > deps.svg
sm-go graph --format mermaid --depth 2
```
<a id="majors"></a>
#### `majors`: Major-version split detector: foo, foo/v2, gopkg.in/x.vN side by side

*Live data: Go module proxy (go.mod files), go list*

```bash
sm-go majors
sm-go majors --fail-on low --json
```
<a id="replace"></a>
#### `replace`: Replace & exclude auditor: local paths, stale forks, no-op and ignored directives

*Live data: Go module proxy (versions, .info times, go.mod files), GitHub API (fork repositories, optional)*

```bash
sm-go replace
sm-go replace --fail-on low
sm-go replace --no-forks --json
```
<a id="unused"></a>
#### `unused`: Unused, test-only and misplaced // indirect requirements (go mod tidy semantics)

*Live data: go list, Go module proxy (go.mod files)*

```bash
sm-go unused
sm-go unused --fail-on medium --json
```
<a id="why"></a>
#### `why`: MVS explainer: why a module is selected at its version

*Live data: Go module proxy (go.mod files), go list*

```bash
sm-go why golang.org/x/net
sm-go why golang.org/x/text@v0.3.7
sm-go why github.com/a/b github.com/c/d --json
```
<a id="workspace"></a>
#### `workspace`: Workspace (go.work) analyzer: conflicts, drift, go versions, go.work.sum, untracked modules

*Live data: Go module proxy (go.mod files)*

```bash
sm-go workspace
sm-go workspace --no-drift --json
GOWORK=/path/to/go.work sm-go workspace
```

### Binary intelligence

<a id="binscan"></a>
#### `binscan`: Binary auditor: build info, vulnerabilities and hygiene of compiled Go binaries

*Live data: Go vulnerability database, go.dev/dl, CISA KEV, FIRST EPSS, GitHub Advisory Database*

```bash
sm-go binscan ./bin/server
sm-go binscan dist/ --json
sm-go binscan /usr/local/bin --fail-on high
```
<a id="bloat"></a>
#### `bloat`: Binary size attribution: bytes per module, package and symbol; compare two builds

*Live data: the binary's symbol table, Go function table and build information*

```bash
sm-go bloat ./bin/server
sm-go bloat ./bin/server --top 50 --json
sm-go bloat --diff old/server new/server
```
<a id="cgo"></a>
#### `cgo`: Cross-compile readiness: cgo use, C libraries and CGO_ENABLED=0 builds per target

*Live data: go list, go build (with --verify)*

```bash
sm-go cgo
sm-go cgo ./cmd/server --targets linux/amd64,linux/arm64,linux/riscv64
sm-go cgo --verify --json
```

### Upgrade & release

<a id="apidiff"></a>
#### `apidiff`: API break detector: incompatible API changes between two module versions

*Live data: Go module proxy, checksum database (via the go command)*

```bash
sm-go apidiff golang.org/x/text@v0.14.0 golang.org/x/text@v0.15.0
sm-go apidiff github.com/google/go-cmp v0.5.9..v0.6.0 --all
sm-go apidiff example.com/m@v1.9.0 example.com/m/v2@v2.0.0
```
<a id="migrate"></a>
#### `migrate`: Major version migrator: plan (and apply) a move from foo to foo/vN

*Live data: Go module proxy, checksum database (via the go command)*

```bash
sm-go migrate github.com/go-redis/redis
sm-go migrate github.com/google/go-github/v60 v62
sm-go migrate example.com/foo example.com/foo/v3@v3.1.0 --apply
```
<a id="release"></a>
#### `release`: Release checker: next semantic version from the API diff, path rules, retractions, git tag

*Live data: Go module proxy, checksum database (via the go command), git*

```bash
sm-go release
sm-go release --version v1.5.0
sm-go release --base v1.3.0 --json
```
<a id="toolchain"></a>
#### `toolchain`: Toolchain readiness: go/toolchain directives, Go support status and stdlib vulns

*Live data: go.dev/dl release list, Go vulnerability database, Go module proxy*

```bash
sm-go toolchain
sm-go toolchain --fail-on high --json
GOTOOLCHAIN=local sm-go toolchain -C ./service
```
<a id="upgrade"></a>
#### `upgrade`: Upgrade simulator: what `go get module@version` would change, before you run it

*Live data: Go module proxy, Go vulnerability database*

```bash
sm-go upgrade golang.org/x/net@latest
sm-go upgrade github.com/spf13/cobra@v1.8.0 github.com/spf13/pflag@upgrade
sm-go upgrade example.com/lib@v1.1.0 --no-api --json
```

### Compliance & operations

<a id="env"></a>
#### `env`: Audit GOPROXY, GOSUMDB, private patterns, .netrc and git rewrites

*Live data: go env, .netrc, git config*

```bash
sm-go env
sm-go env --fail-on high
sm-go env --json
```
<a id="gate"></a>
#### `gate`: CI policy gate: vulnerabilities, KEV, licenses, bans, retractions

*Live data: Go vulnerability database, CISA KEV, FIRST EPSS, GitHub Advisory Database, Go module proxy, deps.dev*

With no `.sm-go.json` and no `--policy`, gate uses a built-in default policy. It fails on called vulnerabilities of high or critical severity, on any CISA KEV vulnerability and on retracted versions. Licenses are reported but not enforced. `sm-go gate --init` writes that default to `.sm-go.json` so you can customize it.

```bash
sm-go gate
sm-go gate --policy ci/policy.json --sarif sm-go.sarif
sm-go gate --github
sm-go gate --json
sm-go gate --init
```
<a id="license"></a>
#### `license`: License compliance with SPDX text matching and NOTICE generation

*Live data: Go module proxy, deps.dev*

```bash
sm-go license
sm-go license --deny GPL-3.0,AGPL-3.0 --fail-unknown
sm-go license --allow MIT,Apache-2.0,BSD-3-Clause,BSD-2-Clause,ISC
```
<a id="radar"></a>
#### `radar`: Live release radar for your dependencies from the Go module index

*Live data: Go module index, Go module proxy, Go vulnerability database*

```bash
sm-go radar
sm-go radar --all --since 7d
sm-go radar golang.org/x/... github.com/myorg/
```
<a id="sbom"></a>
#### `sbom`: CycloneDX 1.5 / SPDX 2.3 SBOM from the build list or a binary

*Live data: Go module proxy, deps.dev*

```bash
sm-go sbom > bom.cdx.json
sm-go sbom --format spdx -o bom.spdx.json
sm-go sbom ./cmd/server --linked -o server.cdx.json
```
<a id="vendor"></a>
#### `vendor`: Verify vendor/ against modules.txt, go.mod, go.sum and the module zips

*Live data: Go module proxy, go.sum*

```bash
sm-go vendor
sm-go vendor --offline-only
sm-go vendor --fail-on high --json
```

## Global flags

| Flag | Meaning |
|---|---|
| `--json` | Machine-readable output: `{tool, version, generatedAt, ok, exitCode, result, warnings, error}` |
| `--no-color` | Disable colors (`NO_COLOR` is also honored) |
| `--no-cache` | Bypass the HTTP cache (most data is cached for 10 minutes; KEV, EPSS and deps.dev for longer) |
| `--offline` | Use cached data only and never touch the network. The go command runs with `GOPROXY=off` too |
| `-C <dir>` | Run in another directory |
| `-v` | Log every network request |
| `--timeout <d>` | Per-request network timeout (default 30s) |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | OK |
| `1` | Issues found that meet the tool's failure threshold (`--fail-on`, `--min-score`, `--budget`, a gate policy…). `--fail-on none` never fails |
| `2` | Usage error |
| `3` | Network or runtime error |

## Using it in CI

```yaml
# .github/workflows/deps.yml
name: Dependency gate
on: [push, pull_request]
jobs:
  gate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-go@v6
        with:
          go-version: stable
      - run: go install github.com/slash-mark-dev/go-suite/cmd/sm-go@latest
      - run: sm-go gate --github --sarif sm-go.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: sm-go.sarif
```

## Private modules and credentials

sm-go follows the go command's own settings: `GOPROXY`, `GOPRIVATE`, `GONOPROXY`, `GONOSUMDB`, `GOFLAGS` and `.netrc`.

A module is private if its path matches `GOPRIVATE`, `GONOPROXY` or `GONOSUMDB`, using the go command's own matching rules. Private module paths are never sent to third-party services: not to deps.dev (including Scorecard and dependents data), not to domain-registry (RDAP) lookups, and not to any other host that isn't the module's own. sm-go contacts only these hosts about a private module:

- its own go-import pages, and its repository root when that is on the same host;
- the GitHub API, but only when the module path itself starts with `github.com/`;
- the module proxy and checksum database, exactly as `GONOPROXY` and `GONOSUMDB` direct, like the go command.

Lookups skipped for this reason are marked `skipped: private module`.

Credentials are sent only to the host they belong to, and they are dropped on redirects to another host. They are never printed: `--json` output and `-v` logs redact them.

Optional environment variables:

| Variable | Use |
|---|---|
| `GITHUB_TOKEN` or `GH_TOKEN` | Raises GitHub API rate limits (`health`, `takeover`, `vanity`, `retag`, `replace`, and GitHub Advisory lookups in `vuln`, `binscan`, `gate`, `toolchain`, `upgrade`) |
| `SMGO_CACHE_DIR` | Location of the HTTP cache (default `$XDG_CACHE_HOME/sm-go`, else `~/.cache/sm-go`; `%LocalAppData%\sm-go` on Windows) |
| `SMGO_CACHE_TTL` | Default cache lifetime (default `10m`) |
| `SMGO_OFFLINE=1` | Same as `--offline` |
| `SMGO_*_URL` | Override a data source (vulnerability database, deps.dev, KEV, EPSS, GitHub API, module index) for mirrors or air-gapped setups. The module proxy and checksum database follow `GOPROXY` and `GOSUMDB` |

## Development

```bash
go test ./...                              # unit, tool and end-to-end tests (fake data sources, no network)
sh verify/setup.sh && (cd verify && go test ./...)   # differential tests vs golang.org/x/mod and the go command
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the tools are built.

## License

MIT © 2026 [Slash Mark IT Solutions (OPC) Private Limited](https://slashmark.in)
