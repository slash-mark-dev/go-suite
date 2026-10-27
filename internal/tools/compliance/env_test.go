package compliance

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

// envClean is an environment in which `sm-go env` has nothing to report.
// testenv.World.Env points GOPROXY/GOSUMDB at a local fake and sets
// GOFLAGS=-mod=mod, all of which the env tool would (rightly) flag, so
// every test starts from these overrides. HOME is the world's temporary
// home; the system git config is switched off so /etc/gitconfig on the
// test machine cannot leak in. GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM are
// left unset (World.Env does not inherit them): git treats a set but empty
// value as "no file", which would hide ~/.gitconfig.
func envClean(extra ...string) []string {
	return append([]string{
		"GOPROXY=https://proxy.golang.org,direct",
		"GOSUMDB=sum.golang.org",
		"GOFLAGS=",
		"GOTOOLCHAIN=local",
		"GOPRIVATE=",
		"GONOPROXY=",
		"GONOSUMDB=",
		"GOINSECURE=",
		"GOVCS=",
		"GONOSUMCHECK=",
		"NETRC=",
		"GIT_CONFIG_NOSYSTEM=1",
		"XDG_CONFIG_HOME=",
	}, extra...)
}

func envWorld(t *testing.T) (*testenv.World, string) {
	t.Helper()
	w := testenv.New(t)
	return w, t.TempDir()
}

// runEnvJSON runs `sm-go env --json` with envClean plus extra.
func runEnvJSON(t *testing.T, w *testenv.World, dir string, extra []string, args ...string) (testenv.Result, *EnvResult) {
	t.Helper()
	r := w.RunEnv(dir, envClean(extra...), append([]string{"env", "--json"}, args...)...)
	var res EnvResult
	r.Decode(t, &res)
	return r, &res
}

// envRules lists "rule:severity" for findings whose rule starts with one
// of prefixes (all findings when none are given), sorted.
func envRules(res *EnvResult, prefixes ...string) []string {
	out := []string{}
	for _, f := range res.Findings {
		ok := len(prefixes) == 0
		for _, p := range prefixes {
			if strings.HasPrefix(f.Rule, p) {
				ok = true
			}
		}
		if ok {
			out = append(out, f.Rule+":"+f.Severity.String())
		}
	}
	sort.Strings(out)
	return out
}

func rules(s ...string) []string {
	if s == nil {
		s = []string{}
	}
	sort.Strings(s)
	return s
}

func envSetting(res *EnvResult, name string) EnvSetting {
	for _, s := range res.Settings {
		if s.Name == name {
			return s
		}
	}
	return EnvSetting{}
}

// noSecrets fails if any secret appears in the output of the env tool,
// in JSON and in text mode.
func noSecrets(t *testing.T, w *testenv.World, dir string, extra []string, secrets ...string) {
	t.Helper()
	for _, mode := range [][]string{{"env", "--json"}, {"env"}} {
		r := w.RunEnv(dir, envClean(extra...), mode...)
		for _, s := range secrets {
			if strings.Contains(r.Stdout, s) || strings.Contains(r.Stderr, s) {
				t.Errorf("%v output leaks %q:\n%s\n%s", mode, s, r.Stdout, r.Stderr)
			}
		}
	}
}

func TestEnvClean(t *testing.T) {
	w, dir := envWorld(t)
	r, res := runEnvJSON(t, w, dir, nil)
	if r.Code != 0 {
		t.Fatalf("exit %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	if got := envRules(res); len(got) != 0 {
		t.Fatalf("findings: %v", got)
	}

	// JSON shape: the envelope, and empty lists rather than null.
	var env map[string]json.RawMessage
	if err := json.Unmarshal([]byte(r.Stdout), &env); err != nil {
		t.Fatal(err)
	}
	if string(env["tool"]) != `"env"` || string(env["ok"]) != "true" || string(env["exitCode"]) != "0" {
		t.Errorf("envelope: %s", r.Stdout)
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(env["result"], &result); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range result {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if want := []string{"failing", "findings", "gitConfigs", "gitRewrites", "settings", "summary"}; !reflect.DeepEqual(keys, want) {
		t.Errorf("result keys %v, want %v (netrc omitted when there is no .netrc)", keys, want)
	}
	for k, want := range map[string]string{"findings": "[]", "gitConfigs": "[]", "gitRewrites": "[]", "summary": "{}", "failing": "0"} {
		if got := string(result[k]); got != want {
			t.Errorf("%s = %s, want %s", k, got, want)
		}
	}

	// Settings: every audited variable, in order, with its source.
	var names []string
	for _, s := range res.Settings {
		names = append(names, s.Name)
	}
	if !reflect.DeepEqual(names, auditedVars) {
		t.Errorf("settings %v, want %v", names, auditedVars)
	}
	if s := envSetting(res, "GOPROXY"); s.Value != "https://proxy.golang.org,direct" || s.Source != "environment" {
		t.Errorf("GOPROXY setting %+v", s)
	}
	// World.Env sets GOENV=off; `go env GOENV` then reports the (absent)
	// configuration file as "".
	if s := envSetting(res, "GOENV"); s.Value != "" || s.Source != "environment" {
		t.Errorf("GOENV setting %+v", s)
	}
	if s := envSetting(res, "NETRC"); s.Value != "" || s.Source != "default" {
		t.Errorf("NETRC setting %+v", s)
	}

	// Text mode.
	r = w.RunEnv(dir, envClean(), "env")
	if r.Code != 0 {
		t.Fatalf("text exit %d", r.Code)
	}
	mustContain(t, "text output", r.Stdout, "Settings", "GOPROXY", "https://proxy.golang.org,direct", "no issues found",
		"no findings at or above medium (none)")
}

// The settings table reports what `go env` reports.
func TestEnvSettingsMatchGoEnv(t *testing.T) {
	w, dir := envWorld(t)
	extra := []string{"GOPROXY=https://goproxy.cn|https://proxy.golang.org,direct", "GOPRIVATE=*.corp.example,github.com/acme",
		"GONOSUMDB=gitlab.com/acme", "GOINSECURE=git.corp.example", "GOFLAGS=-mod=readonly -trimpath",
		// <version>+auto with the running version: an older one would make
		// every go command (including sm-go's own `go env`) download it.
		"GOTOOLCHAIN=" + runtime.Version() + "+auto",
		"GOVCS=private:all,public:git", "GOAUTH=netrc"}
	_, res := runEnvJSON(t, w, dir, extra)
	vars := []string{"GOPROXY", "GOSUMDB", "GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GOINSECURE", "GOFLAGS", "GOTOOLCHAIN", "GOVCS", "GOAUTH", "GOENV"}
	out, err := w.GoEnv(dir, envClean(extra...), append([]string{"env", "-json"}, vars...)...)
	if err != nil {
		t.Fatalf("go env: %v\n%s", err, out)
	}
	var goenv map[string]string
	if err := json.Unmarshal([]byte(out), &goenv); err != nil {
		t.Fatal(err)
	}
	for _, k := range vars {
		if got := envSetting(res, k).Value; got != goenv[k] {
			t.Errorf("%s = %q, go env says %q", k, got, goenv[k])
		}
	}
	// GONOPROXY is unset, so it defaults to GOPRIVATE like in the go command.
	if goenv["GONOPROXY"] != "*.corp.example,github.com/acme" {
		t.Errorf("go env GONOPROXY = %q", goenv["GONOPROXY"])
	}
}

// Values from a go.env file (GOENV) are attributed to "go env".
func TestEnvGoEnvFile(t *testing.T) {
	w, dir := envWorld(t)
	goenvFile := filepath.Join(t.TempDir(), "go.env")
	os.WriteFile(goenvFile, []byte("GOPRIVATE=github.com\nGOFLAGS=-modcacherw\n"), 0o644)
	extra := []string{"GOENV=" + goenvFile}
	if out, err := w.GoEnv(dir, envClean(extra...), "env", "GOPRIVATE"); err != nil || strings.TrimSpace(out) != "github.com" {
		t.Fatalf("go env GOPRIVATE: %q %v", out, err)
	}
	_, res := runEnvJSON(t, w, dir, extra)
	if s := envSetting(res, "GOPRIVATE"); s.Value != "github.com" || s.Source != "go env" {
		t.Errorf("GOPRIVATE setting %+v", s)
	}
	// GONOSUMDB/GONOPROXY inherit GOPRIVATE: reported once, under GOPRIVATE.
	if got, want := envRules(res), rules("goprivate-broad:high", "goflags-modcacherw:low"); !reflect.DeepEqual(got, want) {
		t.Errorf("rules %v, want %v", got, want)
	}
}

func TestEnvGOPROXY(t *testing.T) {
	w, dir := envWorld(t)
	tests := []struct {
		proxy string
		want  []string
	}{
		{"off", rules("goproxy-off:info")},
		{"direct", rules("goproxy-direct:medium")},
		{"direct,https://proxy.golang.org", rules("goproxy-direct:medium")},
		{"https://proxy.golang.org,direct", rules()},
		{" https://proxy.golang.org , direct ", rules()},
		{"proxy.golang.org", rules()},
		{"https://goproxy.io,direct", rules()},
		{"https://proxy.golang.org,off", rules()},
		{"https://goproxy.cn,direct", rules("goproxy-third-party:info")},
		{"goproxy.cn", rules("goproxy-third-party:info")},
		{"http://proxy.corp.example", rules("goproxy-http:high", "goproxy-third-party:info")},
		{"http://127.0.0.1:3000", rules("goproxy-http:low")},
		{"http://localhost:3000/mod", rules("goproxy-http:low")},
		{"http://[::1]:3000", rules("goproxy-http:low")},
		{"https://alice:s3cret@proxy.corp.example", rules("goproxy-credentials:high", "goproxy-third-party:info")},
		{"https://tok3n@proxy.corp.example", rules("goproxy-credentials:high", "goproxy-third-party:info")},
		{"alice:s3cret@proxy.corp.example", rules("goproxy-credentials:high", "goproxy-third-party:info")},
		{"https://proxy.corp.example|direct", rules("goproxy-third-party:info", "goproxy-pipe-fallback:low")},
		{"https://proxy.golang.org|direct", rules("goproxy-pipe-fallback:low")},
		{"https://proxy.corp.example|https://proxy.golang.org,direct", rules("goproxy-third-party:info")},
		{"https://proxy.corp.example,https://proxy.golang.org|direct", rules("goproxy-third-party:info", "goproxy-pipe-fallback:low")},
		// file:// proxies are valid (go help goproxy) and local.
		{"file:///srv/goproxy,https://proxy.golang.org", rules()},
		// Entries after direct or off are never used by the go command.
		{"https://proxy.golang.org,direct,http://insecure.example", rules()},
		{"https://proxy.golang.org,off,http://insecure.example", rules()},
		// Invalid entries make every go command that downloads fail.
		{"https://proxy.golang.org,goproxy", rules("goproxy-invalid:medium")},
		{"ftp://proxy.example", rules("goproxy-invalid:medium")},
		{"file://host/srv/goproxy", rules("goproxy-invalid:medium")},
		{"/srv/goproxy", rules("goproxy-invalid:medium")},
		{"https://%zz", rules("goproxy-invalid:medium")},
	}
	for _, tt := range tests {
		_, res := runEnvJSON(t, w, dir, []string{"GOPROXY=" + tt.proxy})
		if got := envRules(res, "goproxy-"); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("GOPROXY=%q: %v, want %v", tt.proxy, got, tt.want)
		}
	}

	// An empty GOPROXY means the default.
	_, res := runEnvJSON(t, w, dir, []string{"GOPROXY="})
	if got := envRules(res); len(got) != 0 || envSetting(res, "GOPROXY").Value != "https://proxy.golang.org,direct" {
		t.Errorf("GOPROXY unset: %v %+v", got, envSetting(res, "GOPROXY"))
	}
}

// goRejectsProxy reports whether the go command refuses the GOPROXY list
// itself (as opposed to failing to download from it). Only loopback and
// file URLs are used, so nothing leaves the machine.
func goRejectsProxy(t *testing.T, w *testenv.World, proxy string) bool {
	t.Helper()
	tmp := t.TempDir()
	out, _ := w.GoEnv(tmp, envClean("GOPROXY="+proxy, "GOSUMDB=off", "GOFLAGS=-modcacherw",
		"GOMODCACHE="+filepath.Join(tmp, "modcache")), "mod", "download", "-json", "example.com/m@v1.0.0")
	switch {
	case strings.Contains(out, "invalid proxy URL"), strings.Contains(out, "invalid file:// proxy URL"), strings.Contains(out, `parse \"`):
		return true
	case strings.Contains(out, "connection refused"), strings.Contains(out, "no such file"), strings.Contains(out, "HTTP response to HTTPS client"),
		strings.Contains(out, "server gave HTTP response"), strings.Contains(out, "module lookup disabled"):
		return false
	}
	t.Fatalf("GOPROXY=%q: unexpected go output\n%s", proxy, out)
	return false
}

// goproxy-invalid is reported exactly when the go command rejects the list.
func TestEnvGOPROXYMatchesGo(t *testing.T) {
	w, dir := envWorld(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	hostport := strings.TrimPrefix(srv.URL, "http://")
	fileDir := filepath.ToSlash(t.TempDir())
	for _, proxy := range []string{
		"http://127.0.0.1:1",
		"http://127.0.0.1:1,goproxy",
		"http://127.0.0.1:1,direct,goproxy",
		"http://127.0.0.1:1|off,goproxy",
		"http://127.0.0.1:1,ftp://x.example",
		"http://127.0.0.1:1,file://host/p",
		"file://" + fileDir,
		hostport, // implicit https://
		"/abs/path",
		"http://127.0.0.1:1,%zz",
		"https://%zz",
		"off",
	} {
		_, res := runEnvJSON(t, w, dir, []string{"GOPROXY=" + proxy})
		got := strings.Contains(strings.Join(envRules(res), " "), "goproxy-invalid")
		if want := goRejectsProxy(t, w, proxy); got != want {
			t.Errorf("GOPROXY=%q: sm-go invalid=%v, go command rejects=%v (%v)", proxy, got, want, envRules(res))
		}
	}
}

func TestEnvGOSUMDB(t *testing.T) {
	w, dir := envWorld(t)
	tests := []struct {
		sumdb string
		want  []string
	}{
		{"off", rules("gosumdb-off:high")},
		{"sum.golang.org", rules()},
		{"sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8", rules()},
		{"sum.golang.google.cn", rules()},
		{"sum.golang.google.cn+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8 https://sum.golang.google.cn", rules()},
		{"sum.corp.example+abcd1234+AXXXX", rules("gosumdb-custom:medium")},
		{"sum.corp.example+abcd1234+AXXXX https://sum.corp.example", rules("gosumdb-custom:medium")},
		{"sum.corp.example+abcd1234+AXXXX http://sum.corp.example", rules("gosumdb-custom:high")},
		{"sum.corp.example+abcd1234+AXXXX http://127.0.0.1:8080", rules("gosumdb-custom:medium")},
	}
	for _, tt := range tests {
		_, res := runEnvJSON(t, w, dir, []string{"GOSUMDB=" + tt.sumdb})
		if got := envRules(res, "gosumdb-"); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("GOSUMDB=%q: %v, want %v", tt.sumdb, got, tt.want)
		}
	}
	_, res := runEnvJSON(t, w, dir, []string{"GOSUMDB=sum.corp.example+abcd1234+AXXXX http://sum.corp.example"})
	f := res.Findings[0]
	if f.Title != "GOSUMDB uses a non-default checksum database (sum.corp.example+abcd1234+AXXXX)" || !strings.HasSuffix(f.Detail, "contacted over plain HTTP") {
		t.Errorf("finding %+v", f)
	}
}

func TestEnvPatterns(t *testing.T) {
	w, dir := envWorld(t)
	tests := []struct {
		env  []string
		want []string
	}{
		{[]string{"GOPRIVATE=github.com/acme/*,*.corp.example,golang.org/x"}, rules()},
		{[]string{"GOPRIVATE=*"}, rules("goprivate-broad:high")},
		{[]string{"GOPRIVATE=*.*"}, rules("goprivate-broad:high")},
		{[]string{"GOPRIVATE=*/*"}, rules("goprivate-broad:high")},
		{[]string{"GOPRIVATE=*.com"}, rules("goprivate-broad:high")},
		{[]string{"GOPRIVATE=github.com"}, rules("goprivate-broad:high")},
		{[]string{"GOPRIVATE=github.com/"}, rules("goprivate-broad:high")},
		{[]string{"GOPRIVATE=github.com/*"}, rules("goprivate-broad:high")},
		{[]string{"GOPRIVATE=github.com/*/*"}, rules("goprivate-broad:high")},
		{[]string{"GOPRIVATE=*.github.com"}, rules()},
		{[]string{"GOPRIVATE=corp.example,gitlab.com,*.org"}, rules("goprivate-broad:high", "goprivate-broad:high")},
		// GONOPROXY and GONOSUMDB default to GOPRIVATE and are then not
		// reported a second time.
		{[]string{"GOPRIVATE=*", "GONOPROXY=*", "GONOSUMDB=*"}, rules("goprivate-broad:high")},
		{[]string{"GONOSUMDB=*.org"}, rules("gonosumdb-broad:high")},
		{[]string{"GONOPROXY=gitlab.com"}, rules("gonoproxy-broad:medium")},
		{[]string{"GOPRIVATE=github.com/acme", "GONOPROXY=github.com/*"}, rules("gonoproxy-broad:medium")},
		{[]string{"GOINSECURE=git.corp.example"}, rules("goinsecure-set:medium")},
		{[]string{"GOINSECURE=*"}, rules("goinsecure-set:medium", "goinsecure-broad:high")},
		{[]string{"GONOSUMCHECK=corp.example"}, rules("gonosumcheck-obsolete:low")},
		{[]string{"GONOSUMCHECK=corp.example,*"}, rules("gonosumcheck-obsolete:low", "gonosumcheck-broad:medium")},
	}
	for _, tt := range tests {
		_, res := runEnvJSON(t, w, dir, tt.env)
		if got := envRules(res); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%v: %v, want %v", tt.env, got, tt.want)
		}
	}

	// Messages.
	_, res := runEnvJSON(t, w, dir, []string{"GOPRIVATE=corp.example,*.org", "GONOPROXY=gitlab.com/*", "GOINSECURE=*"})
	byRule := map[string]string{}
	for _, f := range res.Findings {
		byRule[f.Rule] = f.Title + " | " + f.Detail
	}
	want := map[string]string{
		"goprivate-broad":  `GOPRIVATE pattern "*.org" is too broad | GOPRIVATE skips the proxy and checksum verification for every module under .org`,
		"gonoproxy-broad":  `GONOPROXY pattern "gitlab.com/*" is too broad | GONOPROXY fetches straight from version control (no proxy) for every module on gitlab.com`,
		"goinsecure-broad": `GOINSECURE pattern "*" is too broad | GOINSECURE allows plain HTTP and unverified TLS for every module`,
		"goinsecure-set":   `GOINSECURE=* | GOINSECURE allows insecure HTTP fetches and skips checksum verification for its modules`,
	}
	if !reflect.DeepEqual(byRule, want) {
		t.Errorf("findings:\n%v\nwant\n%v", byRule, want)
	}
}

// goSkipsSumDB reports whether the go command treats modPath as matching
// GONOSUMDB=patterns (module.MatchPrefixPatterns): with an unreachable
// checksum database, only modules it skips can be downloaded.
func goSkipsSumDB(t *testing.T, w *testenv.World, patterns, modPath string) bool {
	t.Helper()
	tmp := t.TempDir()
	out, err := w.GoEnv(tmp, []string{"GONOSUMDB=" + patterns, "GOPRIVATE=", "GONOPROXY=", "GOFLAGS=-modcacherw",
		"GOSUMDB=" + w.VerifierKey + " http://127.0.0.1:1", "GOMODCACHE=" + filepath.Join(tmp, "modcache")},
		"mod", "download", "-json", modPath+"@v1.0.0")
	if err == nil {
		return true
	}
	if !strings.Contains(out, "127.0.0.1:1") {
		t.Fatalf("go mod download %s: unexpected failure\n%s", modPath, out)
	}
	return false
}

// A pattern is "too broad" exactly when the go command applies it to a
// public module.
func TestEnvPatternsMatchGo(t *testing.T) {
	w, dir := envWorld(t)
	for _, p := range []string{"github.com/public/lib", "example.com/lib", "gitlab.com/group/lib", "golang.org/x/lib"} {
		w.AddModule(p, "v1.0.0", map[string]string{"lib.go": "package lib\n"})
	}
	tests := []struct {
		patterns string
		public   string // a public module the broad pattern would cover
	}{
		{"*", "github.com/public/lib"},
		{"*.*", "example.com/lib"},
		{"*/*", "gitlab.com/group/lib"},
		{"*.com", "example.com/lib"},
		{"*.com/*", "example.com/lib"},
		{"github.com", "github.com/public/lib"},
		{"github.com/", "github.com/public/lib"},
		{"github.com/*", "github.com/public/lib"},
		{"github.com/*/*", "github.com/public/lib"},
		{"gitlab.com/*/", "gitlab.com/group/lib"},
		{"golang.org", "golang.org/x/lib"},
		{"github.com/acme/*", "github.com/public/lib"},
		{"*.github.com", "github.com/public/lib"},
		{"*.corp.example", "example.com/lib"},
		{"golang.org/x", "github.com/public/lib"},
		// Patterns are case-sensitive and not trimmed by the go command.
		{"GitHub.com", "github.com/public/lib"},
		{"corp.example, github.com", "github.com/public/lib"},
	}
	for _, tt := range tests {
		_, res := runEnvJSON(t, w, dir, []string{"GONOSUMDB=" + tt.patterns})
		broad := len(envRules(res, "gonosumdb-broad")) > 0
		if matched := goSkipsSumDB(t, w, tt.patterns, tt.public); broad != matched {
			t.Errorf("GONOSUMDB=%q: sm-go broad=%v, go command applies it to %s=%v", tt.patterns, broad, tt.public, matched)
		}
	}
}

func TestEnvGOFLAGSToolchainGOVCS(t *testing.T) {
	w, dir := envWorld(t)
	tests := []struct {
		env  []string
		want []string
	}{
		{[]string{"GOFLAGS=-mod=mod"}, rules("goflags-mod-mod:medium")},
		{[]string{"GOFLAGS=--mod=mod -trimpath"}, rules("goflags-mod-mod:medium")},
		{[]string{"GOFLAGS=-mod=readonly"}, rules()},
		{[]string{"GOFLAGS=-mod=vendor -modcacherw"}, rules("goflags-modcacherw:low")},
		{[]string{"GOFLAGS=-insecure"}, rules("goflags-insecure:high")},
		{[]string{"GOFLAGS=-insecure -mod=mod -modcacherw"}, rules("goflags-insecure:high", "goflags-mod-mod:medium", "goflags-modcacherw:low")},

		{[]string{"GOTOOLCHAIN=auto"}, rules("gotoolchain-auto:info")},
		{[]string{"GOTOOLCHAIN=go1.21.0+auto"}, rules("gotoolchain-auto:info")},
		{[]string{"GOTOOLCHAIN=path"}, rules()},
		{[]string{"GOTOOLCHAIN=local"}, rules()},
		{[]string{"GOTOOLCHAIN=auto", "GOSUMDB=off"}, rules("gotoolchain-unverified:high", "gosumdb-off:high")},
		{[]string{"GOTOOLCHAIN=local", "GOSUMDB=off"}, rules("gosumdb-off:high")},

		{[]string{"GOVCS=public:all"}, rules("govcs-all:medium")},
		{[]string{"GOVCS=github.com:git, *:all"}, rules("govcs-all:medium")},
		{[]string{"GOVCS=private:all,public:git|hg"}, rules()},
		{[]string{"GOVCS=*:git"}, rules()},
	}
	for _, tt := range tests {
		_, res := runEnvJSON(t, w, dir, tt.env)
		if got := envRules(res); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%v: %v, want %v", tt.env, got, tt.want)
		}
	}
	// Without a go command the process environment is used directly.
	_, res := runEnvJSON(t, w, dir, []string{"SMGO_NO_GO=1", "GOTOOLCHAIN=", "GOFLAGS=-mod=mod", "GOPRIVATE=*"})
	if got, want := envRules(res), rules("goflags-mod-mod:medium", "goprivate-broad:high", "gotoolchain-auto:info"); !reflect.DeepEqual(got, want) {
		t.Errorf("SMGO_NO_GO: %v, want %v", got, want)
	}
	if s := envSetting(res, "GOTOOLCHAIN"); s.Value != "auto" || s.Source != "default" {
		t.Errorf("SMGO_NO_GO GOTOOLCHAIN %+v", s)
	}
}

func TestEnvNetrc(t *testing.T) {
	w, dir := envWorld(t)
	netrc := filepath.Join(w.Home, ".netrc")
	write := func(content string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(netrc, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(netrc, mode)
	}
	write(`# credentials for the private proxy
machine git.corp.example login alice password hunter2-secret
machine nopw.example login bob
macdef init
password inside-macro
machine fake.example login x password y

machine multi.example
	login carol
	password multi-secret
default login anonymous password default-secret
`, 0o600)
	r, res := runEnvJSON(t, w, dir, nil)
	if r.Code != 1 {
		t.Errorf("exit %d", r.Code)
	}
	if got, want := envRules(res), rules("netrc-plaintext:medium", "netrc-plaintext:medium", "netrc-default:high"); !reflect.DeepEqual(got, want) {
		t.Errorf("rules %v, want %v", got, want)
	}
	if res.Netrc == nil || res.Netrc.Path != netrc || res.Netrc.Mode != "0600" {
		t.Fatalf("netrc %+v", res.Netrc)
	}
	wantMachines := []NetrcMachine{
		{Host: "git.corp.example", Login: "a***", HasPassword: true},
		{Host: "nopw.example", Login: "b***"},
		{Host: "multi.example", Login: "c***", HasPassword: true},
		{Host: "default", Login: "a***", HasPassword: true},
	}
	if !reflect.DeepEqual(res.Netrc.Machines, wantMachines) {
		t.Errorf("machines %+v", res.Netrc.Machines)
	}
	lines := map[string]int{}
	for _, f := range res.Findings {
		if f.File != netrc {
			t.Errorf("finding file %q", f.File)
		}
		lines[f.Title] = f.Line
	}
	wantLines := map[string]int{
		"plaintext credentials for git.corp.example in .netrc (login a***)": 2,
		"plaintext credentials for multi.example in .netrc (login c***)":    8,
		`.netrc has a "default" entry with a password`:                      11,
	}
	if !reflect.DeepEqual(lines, wantLines) {
		t.Errorf("finding lines %v", lines)
	}
	noSecrets(t, w, dir, nil, "hunter2-secret", "multi-secret", "default-secret", "alice", "carol", "anonymous")

	// World-readable with credentials.
	write("machine git.corp.example login alice password hunter2-secret\n", 0o644)
	_, res = runEnvJSON(t, w, dir, nil)
	if runtime.GOOS != "windows" {
		if got, want := envRules(res), rules("netrc-plaintext:medium", "netrc-permissions:high"); !reflect.DeepEqual(got, want) {
			t.Errorf("0644: %v, want %v", got, want)
		}
		for _, f := range res.Findings {
			if f.Rule == "netrc-permissions" && (f.Title != ".netrc with credentials is readable by other users (mode 0644)" || f.Fix != "chmod 600 "+netrc) {
				t.Errorf("permissions finding %+v", f)
			}
		}
	}
	noSecrets(t, w, dir, nil, "hunter2-secret", "alice")

	// World-readable without credentials is fine.
	write("machine a.example login alice\n", 0o644)
	if _, res = runEnvJSON(t, w, dir, nil); len(res.Findings) != 0 || res.Netrc == nil || len(res.Netrc.Machines) != 1 {
		t.Errorf("no password: %v %+v", envRules(res), res.Netrc)
	}

	// NETRC points elsewhere.
	other := filepath.Join(t.TempDir(), "creds")
	os.WriteFile(other, []byte("machine x.example login ab password zz\n"), 0o600)
	_, res = runEnvJSON(t, w, dir, []string{"NETRC=" + other})
	if res.Netrc == nil || res.Netrc.Path != other || !reflect.DeepEqual(res.Netrc.Machines, []NetrcMachine{{Host: "x.example", Login: "***", HasPassword: true}}) {
		t.Errorf("NETRC: %+v", res.Netrc)
	}
	if s := envSetting(res, "NETRC"); s.Value != other || s.Source != "environment" {
		t.Errorf("NETRC setting %+v", s)
	}

	// Unreadable (a directory).
	_, res = runEnvJSON(t, w, dir, []string{"NETRC=" + t.TempDir()})
	if got := envRules(res); !reflect.DeepEqual(got, rules("netrc-unreadable:info")) || res.Netrc != nil {
		t.Errorf("unreadable: %v %+v", got, res.Netrc)
	}

	// No .netrc at all.
	os.Remove(netrc)
	if _, res = runEnvJSON(t, w, dir, nil); res.Netrc != nil || len(res.Findings) != 0 {
		t.Errorf("missing .netrc: %+v %v", res.Netrc, envRules(res))
	}
}

// What the go command does with .netrc entries: machine entries are used,
// a "default" entry is not.
//
// The go command sends credentials only over HTTPS (cmd/go/internal/web)
// and looks them up by the URL's host including any port
// (auth.loadCredential), so the proxy is a local TLS server trusted through
// SSL_CERT_FILE and the machine name is its host:port.
func TestEnvNetrcMatchesGo(t *testing.T) {
	w, dir := envWorld(t)
	var mu sync.Mutex
	var auth []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = append(auth, r.Header.Get("Authorization"))
		mu.Unlock()
		http.NotFound(rw, r)
	}))
	defer srv.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(srv.URL, "https://")
	sent := func(netrc string) bool {
		t.Helper()
		f := filepath.Join(t.TempDir(), "netrc")
		os.WriteFile(f, []byte(netrc), 0o600)
		mu.Lock()
		auth = nil
		mu.Unlock()
		tmp := t.TempDir()
		out, _ := w.GoEnv(tmp, envClean("GOPROXY="+srv.URL, "GOSUMDB=off", "NETRC="+f, "GOFLAGS=-modcacherw", "SSL_CERT_FILE="+caFile,
			"GOMODCACHE="+filepath.Join(tmp, "modcache")), "mod", "download", "-json", "example.com/m@v1.0.0")
		if strings.Contains(out, "certificate") {
			t.Fatalf("the go command does not trust the test server:\n%s", out)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(auth) == 0 {
			t.Fatal("the go command did not contact the proxy")
		}
		for _, a := range auth {
			if a != "" {
				return true
			}
		}
		return false
	}
	if !sent("machine " + host + " login u password p\n") {
		t.Fatalf("the go command did not send credentials for machine %s", host)
	}
	if sent("default login u password p\n") {
		t.Fatal("the go command sent default credentials")
	}

	// The finding says who actually uses default entries.
	os.WriteFile(filepath.Join(w.Home, ".netrc"), []byte("default login u password p\n"), 0o600)
	_, res := runEnvJSON(t, w, dir, nil)
	if len(res.Findings) != 1 || strings.Contains(res.Findings[0].Detail, "the go command and git send") {
		t.Errorf("default finding %+v", res.Findings)
	}
}

const gitconfigFindings = `# rewrites
[url "https://oauth2:glpat-SECRETTOKEN@gitlab.corp.example/"]
	insteadOf = https://gitlab.corp.example/
[url "git@github.com:"]
	insteadOf = https://github.com/
[url "http://mirror.corp.example/"]
	insteadOf = https://golang.org/
[url "git://127.0.0.1/"]
	insteadOf = https://local.example/
[url "https://ghp_abcdefghijklmnopqrstuvwxyz0123@github.com/"]
	InsteadOf = https://github.com/acme/
[url "ssh://git@code.corp.example/"]
	insteadOf = https://code.corp.example/
[url "ssh://git@other.example/"]
	insteadOf = https://code2.corp.example/
[url "https://x-access-token@github.com/"]
	insteadOf = https://github.com/acme2/
[credential]
	helper = store --file ~/.my-credentials
[credential "https://example.com"]
	helper = osxkeychain
`

func TestEnvGitConfig(t *testing.T) {
	w, dir := envWorld(t)
	testenv.WriteFiles(t, w.Home, map[string]string{".gitconfig": gitconfigFindings})
	gc := filepath.Join(w.Home, ".gitconfig")
	r, res := runEnvJSON(t, w, dir, nil)
	if r.Code != 1 {
		t.Errorf("exit %d", r.Code)
	}
	got := map[string][]string{}
	for _, f := range res.Findings {
		if f.File != gc {
			t.Errorf("finding file %s", f.File)
		}
		k := fmt.Sprint(f.Line)
		got[k] = append(got[k], f.Rule+":"+f.Severity.String())
	}
	for _, v := range got {
		sort.Strings(v)
	}
	want := map[string][]string{
		"3":  {"git-rewrite-credentials:high"},
		"5":  {"git-rewrite-ssh:info"},
		"7":  {"git-rewrite-host:medium", "git-rewrite-insecure:high"},
		"9":  {"git-rewrite-host:medium"},
		"11": {"git-rewrite-credentials:high"},
		"13": {"git-rewrite-ssh:info"},
		"15": {"git-rewrite-host:medium"},
		"19": {"git-credential-store:low"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings by line:\n%v\nwant\n%v", got, want)
	}
	if !reflect.DeepEqual(res.GitConfigs, []string{gc}) {
		t.Errorf("gitConfigs %v", res.GitConfigs)
	}
	if len(res.GitRewrites) != 8 {
		t.Fatalf("rewrites %+v", res.GitRewrites)
	}
	if r := res.GitRewrites[0]; r.From != "https://gitlab.corp.example/" || r.To != "https://***@gitlab.corp.example/" || r.Line != 3 || r.File != gc {
		t.Errorf("rewrite 0 %+v", r)
	}
	for _, f := range res.Findings {
		if f.Line == 7 && f.Rule == "git-rewrite-host" && f.Detail != "direct module fetches for golang.org are served by mirror.corp.example; that host controls the code (GOSUMDB still verifies public modules)" {
			t.Errorf("host finding %+v", f)
		}
	}
	noSecrets(t, w, dir, nil, "glpat-SECRETTOKEN", "oauth2", "ghp_abcdefghijklmnopqrstuvwxyz0123")
	r = w.RunEnv(dir, envClean(), "env")
	mustContain(t, "text output", r.Stdout, "git insteadOf rewrites", "https://golang.org/ → http://mirror.corp.example/")
}

// gitOrigins asks git which files define url.*.insteadOf in dir with the
// given environment: file -> "value <- base" entries.
func gitOrigins(t *testing.T, w *testenv.World, dir string, extra []string) map[string][]string {
	t.Helper()
	cmd := exec.Command("git", "config", "--show-origin", "--get-regexp", `^url\..*\.insteadof$`)
	cmd.Dir = dir
	cmd.Env = w.Env(envClean(extra...)...)
	out, err := cmd.Output()
	if err != nil && len(out) != 0 {
		t.Fatalf("git config: %v\n%s", err, out)
	}
	m := map[string][]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		origin, rest, _ := strings.Cut(line, "\t")
		key, val, _ := strings.Cut(rest, " ")
		base := strings.TrimSuffix(strings.TrimPrefix(key, "url."), ".insteadof")
		f := strings.TrimPrefix(origin, "file:")
		if !filepath.IsAbs(f) {
			// git reports repository files relative to the directory it
			// changed into: the top of the working tree.
			f = filepath.Join(gitTop(t, w, dir, extra), f)
		}
		m[f] = append(m[f], val+" <- "+base)
	}
	return m
}

func gitTop(t *testing.T, w *testenv.World, dir string, extra []string) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	cmd.Dir = dir
	cmd.Env = w.Env(envClean(extra...)...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git rev-parse --show-toplevel in %s: %v", dir, err)
	}
	return strings.TrimSpace(string(out))
}

func gitRun(t *testing.T, w *testenv.World, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = w.Env(envClean("GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func smgoOrigins(res *EnvResult) map[string][]string {
	m := map[string][]string{}
	for _, r := range res.GitRewrites {
		m[r.File] = append(m[r.File], r.From+" <- "+r.To)
	}
	return m
}

func requireGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

// sm-go reads the same git configuration files as git.
func TestEnvGitConfigFilesMatchGit(t *testing.T) {
	requireGit(t)
	w, _ := envWorld(t)
	repo := t.TempDir()
	gitRun(t, w, repo, "init", "-q", repo)
	gitRun(t, w, repo, "commit", "-q", "--allow-empty", "-m", "init")
	// A linked worktree has a ".git" file; its config lives in the
	// main repository, and config.worktree is read only with
	// extensions.worktreeConfig.
	wt := filepath.Join(t.TempDir(), "wt")
	gitRun(t, w, repo, "worktree", "add", "-q", "--detach", wt)
	sub := filepath.Join(repo, "sub", "pkg")
	os.MkdirAll(sub, 0o755)
	alt := t.TempDir()
	rw := func(name string) string {
		return fmt.Sprintf("[url \"https://mirror-%s.example/\"]\n\tinsteadOf = https://%s.example/\n", name, name)
	}
	f, _ := os.OpenFile(filepath.Join(repo, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(rw("repo"))
	f.Close()
	testenv.WriteFiles(t, w.Home, map[string]string{".gitconfig": rw("home"), ".config/git/config": rw("xdg")})
	testenv.WriteFiles(t, alt, map[string]string{"git/config": rw("altxdg"), "global": rw("global"), "system": rw("system")})

	for _, tt := range []struct {
		name  string
		dir   string
		extra []string
	}{
		{"default", repo, nil},
		{"subdirectory", sub, nil},
		{"outside repo", t.TempDir(), nil},
		{"XDG_CONFIG_HOME", repo, []string{"XDG_CONFIG_HOME=" + alt}},
		{"GIT_CONFIG_GLOBAL", repo, []string{"GIT_CONFIG_GLOBAL=" + filepath.Join(alt, "global")}},
		{"GIT_CONFIG_SYSTEM", repo, []string{"GIT_CONFIG_NOSYSTEM=", "GIT_CONFIG_SYSTEM=" + filepath.Join(alt, "system")}},
		{"GIT_CONFIG_NOSYSTEM", repo, []string{"GIT_CONFIG_NOSYSTEM=true", "GIT_CONFIG_SYSTEM=" + filepath.Join(alt, "system")}},
		{"GIT_CONFIG_NOSYSTEM=no", repo, []string{"GIT_CONFIG_NOSYSTEM=no", "GIT_CONFIG_SYSTEM=" + filepath.Join(alt, "system")}},
		{"GIT_CONFIG_NOSYSTEM=On", repo, []string{"GIT_CONFIG_NOSYSTEM=On", "GIT_CONFIG_SYSTEM=" + filepath.Join(alt, "system")}},
		// Set but empty: no file at all (and no XDG file for GLOBAL).
		{"empty GIT_CONFIG_GLOBAL", repo, []string{"GIT_CONFIG_GLOBAL="}},
		{"empty GIT_CONFIG_SYSTEM", repo, []string{"GIT_CONFIG_NOSYSTEM=", "GIT_CONFIG_SYSTEM="}},
		{"GIT_DIR", t.TempDir(), []string{"GIT_DIR=" + filepath.Join(repo, ".git")}},
		{"linked worktree", wt, nil},
	} {
		_, res := runEnvJSON(t, w, tt.dir, tt.extra)
		got, want := smgoOrigins(res), gitOrigins(t, w, tt.dir, tt.extra)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\nsm-go %v\ngit   %v", tt.name, got, want)
		}
	}

	// Per-worktree configuration (extensions.worktreeConfig).
	gitRun(t, w, repo, "config", "extensions.worktreeConfig", "true")
	gitRun(t, w, wt, "config", "--worktree", "url.https://mirror-wt.example/.insteadOf", "https://wt.example/")
	for _, d := range []string{wt, repo} {
		_, res := runEnvJSON(t, w, d, nil)
		if got, want := smgoOrigins(res), gitOrigins(t, w, d, nil); !reflect.DeepEqual(got, want) {
			t.Errorf("worktreeConfig in %s:\nsm-go %v\ngit   %v", d, got, want)
		}
	}
}

// insteadOf values are decoded like git does (quotes, comments, case).
func TestEnvGitConfigValuesMatchGit(t *testing.T) {
	requireGit(t)
	w, dir := envWorld(t)
	testenv.WriteFiles(t, w.Home, map[string]string{".gitconfig": `[url "https://mirror.corp.example/"]
	insteadOf = https://a.example/ # trailing comment
	insteadof = "https://b.example/" ; quoted, then a comment
	InsteadOf=https://c.example/
	insteadOf = "https://d.example/#not-a-comment"
	insteadOf =   https://e.example/path
[URL "ssh://git@github.com/"]
	insteadOf = "https://github.com/"
[url "git@gitlab.com:"]
	# insteadOf = https://commented.example/
	; insteadOf = https://commented2.example/
	insteadOf = https://gitlab.com/
`})
	_, res := runEnvJSON(t, w, dir, nil)
	want := map[string][]string{}
	for f, vs := range gitOrigins(t, w, dir, nil) {
		for _, v := range vs {
			val, base, _ := strings.Cut(v, " <- ")
			want[f] = append(want[f], redactURL(val)+" <- "+redactURL(base))
		}
	}
	if got := smgoOrigins(res); !reflect.DeepEqual(got, want) {
		t.Errorf("rewrites:\nsm-go %q\ngit   %q", got, want)
	}
}

func TestEnvSecretsNeverPrinted(t *testing.T) {
	w, dir := envWorld(t)
	secrets := []string{"s3cret-pw", "ghp_proxytoken0123456789", "tok-in-query", "bare-token-user"}
	extra := []string{
		"GOPROXY=https://alice:s3cret-pw@proxy.corp.example/mod?access_token=tok-in-query|https://ghp_proxytoken0123456789@proxy2.corp.example,bare-token-user@proxy3.corp.example,direct",
		"GOSUMDB=sum.corp.example+abcd+AXXX https://alice:s3cret-pw@sum.corp.example",
	}
	r, res := runEnvJSON(t, w, dir, extra)
	if r.Code != 1 {
		t.Errorf("exit %d", r.Code)
	}
	if got := envRules(res, "goproxy-credentials"); len(got) != 3 {
		t.Errorf("credential findings %v", got)
	}
	if v := envSetting(res, "GOPROXY").Value; v != "https://***@proxy.corp.example/mod?access_token=%2A%2A%2A|https://***@proxy2.corp.example,***@proxy3.corp.example,direct" {
		t.Errorf("redacted GOPROXY %q", v)
	}
	noSecrets(t, w, dir, extra, secrets...)

	// A malformed URL with credentials is still redacted.
	extra = []string{"GOPROXY=https://alice:s3cret-pw%zz@proxy.corp.example"}
	_, res = runEnvJSON(t, w, dir, extra)
	if got := envRules(res, "goproxy-"); !reflect.DeepEqual(got, rules("goproxy-invalid:medium")) {
		t.Errorf("malformed: %v", got)
	}
	noSecrets(t, w, dir, extra, "s3cret-pw")
}

func TestEnvExitCodes(t *testing.T) {
	w, dir := envWorld(t)
	info := []string{"GOTOOLCHAIN=auto"}                             // info only
	low := []string{"GOFLAGS=-modcacherw"}                           // low
	medium := []string{"GOFLAGS=-mod=mod"}                           // medium
	high := []string{"GOSUMDB=off"}                                  // high
	mixed := []string{"GOSUMDB=off", "GOFLAGS=-mod=mod -modcacherw"} // high, medium, low
	tests := []struct {
		env     []string
		args    []string
		code    int
		failing int
	}{
		{info, nil, 0, 0},
		{info, []string{"--fail-on", "info"}, 1, 1},
		{low, nil, 0, 0},
		{low, []string{"--fail-on", "low"}, 1, 1},
		{medium, nil, 1, 1},
		{medium, []string{"--fail-on", "high"}, 0, 0},
		{medium, []string{"--fail-on=moderate"}, 1, 1},
		{high, []string{"--fail-on", "critical"}, 0, 0},
		{high, []string{"--fail-on", "high"}, 1, 1},
		{mixed, nil, 1, 2},
		{mixed, []string{"--fail-on", "low"}, 1, 3},
		{mixed, []string{"--fail-on", "none"}, 0, 0},
	}
	for _, tt := range tests {
		r, res := runEnvJSON(t, w, dir, tt.env, tt.args...)
		if r.Code != tt.code || res.Failing != tt.failing {
			t.Errorf("%v %v: exit %d failing %d, want %d %d", tt.env, tt.args, r.Code, res.Failing, tt.code, tt.failing)
		}
	}
	_, res := runEnvJSON(t, w, dir, mixed)
	if !reflect.DeepEqual(res.Summary, map[string]int{"high": 1, "medium": 1, "low": 1}) {
		t.Errorf("summary %v", res.Summary)
	}
	if res.Findings[0].Severity.String() != "high" || res.Findings[2].Severity.String() != "low" {
		t.Errorf("findings not sorted by severity: %v", envRules(res))
	}

	// Usage errors.
	for _, args := range [][]string{{"env", "extra"}, {"env", "--fail-on", "bogus"}, {"env", "--bogus"}} {
		r := w.RunEnv(dir, envClean(), append(args, "--json")...)
		if r.Code != 2 {
			t.Errorf("%v: exit %d, want 2\n%s%s", args, r.Code, r.Stdout, r.Stderr)
		}
	}
	r := w.RunEnv(dir, envClean(), "env", "--json", "extra")
	if m := r.JSON(t); m["ok"] != false || m["exitCode"] != float64(2) || !strings.Contains(fmt.Sprint(m["error"]), "env takes no arguments") {
		t.Errorf("usage envelope %s", r.Stdout)
	}

	// Text summary lines.
	r = w.RunEnv(dir, envClean(mixed...), "env")
	mustContain(t, "text", r.Stdout, "GOSUMDB=off: downloaded modules are not verified", "fix: unset GOSUMDB",
		"2 findings at or above medium (1 high, 1 medium, 1 low)")
	r = w.RunEnv(dir, envClean(medium...), "env")
	mustContain(t, "text", r.Stdout, "1 finding at or above medium (1 medium)")
	r = w.RunEnv(dir, envClean(info...), "env", "--fail-on", "high")
	mustContain(t, "text", r.Stdout, "no findings at or above high (1 info)")
}
