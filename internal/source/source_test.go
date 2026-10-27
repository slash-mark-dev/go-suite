package source_test

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/goenv"
	"github.com/slash-mark-dev/go-suite/internal/source"
	"github.com/slash-mark-dev/go-suite/internal/testenv"
	"github.com/slash-mark-dev/go-suite/internal/ui"
)

func newContext(t *testing.T, w *testenv.World) *cli.Context {
	t.Helper()
	ctx := context.Background()
	return &cli.Context{Ctx: ctx, Env: goenv.Load(ctx, w.Env()), Stdout: io.Discard, Stderr: io.Discard,
		Out: &ui.Printer{W: io.Discard}}
}

func TestParseMeta(t *testing.T) {
	page := `<!DOCTYPE html>
<HTML><HEAD>
<!-- <meta name="go-import" content="commented.out git https://evil.example/x"> -->
<script>var s = '<meta name="go-import" content="in.script git https://evil.example/y">';</script>
<META NAME=go-import CONTENT='example.org/lib git https://github.com/acme/lib'>
<meta name="go-source" content="example.org/lib https://github.com/acme/lib https://github.com/acme/lib/tree/main{/dir} https://github.com/acme/lib/blob/main{/dir}/{file}#L{line}"/>
<meta content="example.org/mod mod https://proxy.example.org" name="go-import">
<meta name="go-import" content="example.org/amp git https://example.org/r?a=1&amp;b=2">
<meta name="go-import" content="too few">
</head>
<body><meta name="go-import" content="after.body git https://evil.example/z"></body></HTML>`
	imports, sources := source.ParseMeta(page)
	want := []source.GoImport{
		{Prefix: "example.org/lib", VCS: "git", Repo: "https://github.com/acme/lib"},
		{Prefix: "example.org/mod", VCS: "mod", Repo: "https://proxy.example.org"},
		{Prefix: "example.org/amp", VCS: "git", Repo: "https://example.org/r?a=1&b=2"},
	}
	if !reflect.DeepEqual(imports, want) {
		t.Fatalf("imports = %+v\nwant %+v", imports, want)
	}
	if len(sources) != 1 || sources[0].Prefix != "example.org/lib" || !strings.Contains(sources[0].File, "{file}") {
		t.Fatalf("sources = %+v", sources)
	}
}

func TestSelectImport(t *testing.T) {
	ims := []source.GoImport{
		{Prefix: "example.org", VCS: "git", Repo: "https://a"},
		{Prefix: "example.org/x", VCS: "mod", Repo: "https://proxy"},
		{Prefix: "example.org/x", VCS: "git", Repo: "https://b"},
		{Prefix: "example.org/x", VCS: "git", Repo: "https://c"},
		{Prefix: "example.org/xy", VCS: "git", Repo: "https://d"},
	}
	m, conf := source.SelectImport(ims, "example.org/x/sub")
	if m == nil || m.Repo != "https://b" {
		t.Fatalf("match = %+v", m)
	}
	if len(conf) != 1 || conf[0].Repo != "https://c" {
		t.Fatalf("conflicts = %+v", conf)
	}
	if m, _ := source.SelectImport(ims, "other.org/x"); m != nil {
		t.Fatalf("unexpected match %+v", m)
	}
}

func TestRegistrableDomain(t *testing.T) {
	for in, want := range map[string]string{
		"go.uber.org":        "uber.org",
		"example.org":        "example.org",
		"pkg.example.co.uk":  "example.co.uk",
		"a.b.example.com.au": "example.com.au",
		"slashmark.co.in":    "slashmark.co.in",
		"example.org:8080":   "example.org",
		"127.0.0.1":          "",
		"localhost":          "",
	} {
		if got := source.RegistrableDomain(in); got != want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveDirectAndWellKnown(t *testing.T) {
	w := testenv.New(t)
	c := newContext(t, w)
	ctx := context.Background()
	cases := []struct {
		path, host, repoHost, owner, name, url, subdir string
	}{
		{"github.com/acme/lib/v2", "github.com", "github.com", "acme", "lib", "https://github.com/acme/lib", "v2"},
		{"gitlab.com/grp/proj", "gitlab.com", "gitlab.com", "grp", "proj", "https://gitlab.com/grp/proj", ""},
		{"golang.org/x/net", "vanity", "go.googlesource.com", "", "net", "https://go.googlesource.com/net", ""},
		{"gopkg.in/yaml.v3", "vanity", "github.com", "go-yaml", "yaml", "https://github.com/go-yaml/yaml", ""},
		{"gopkg.in/alecthomas/kingpin.v2", "vanity", "github.com", "alecthomas", "kingpin", "https://github.com/alecthomas/kingpin", ""},
	}
	for _, tc := range cases {
		r := source.Resolve(ctx, c, tc.path)
		if r.Err != nil || r.Host != tc.host || r.RepoHost != tc.repoHost || r.Owner != tc.owner || r.Name != tc.name || r.URL != tc.url || r.Subdir != tc.subdir {
			t.Errorf("Resolve(%s) = %+v", tc.path, r)
		}
	}
	if len(w.Requests) != 0 {
		t.Errorf("direct resolution made requests: %v", w.Requests)
	}
	if r := source.Resolve(ctx, c, "localmod/x"); r.Host != source.Unknown || r.Err == nil {
		t.Errorf("Resolve(localmod/x) = %+v", r)
	}
}

func TestResolveVanity(t *testing.T) {
	w := testenv.New(t)
	c := newContext(t, w)
	ctx := context.Background()
	// The page is only served for the root; sub-paths 404 and the
	// resolver falls back to parents.
	w.Vanity["example.org/tools"] = `<html><head><meta name="go-import" content="example.org/tools git https://github.com/acme/tools.git"><meta name="go-source" content="example.org/tools https://github.com/acme/tools _ _"></head></html>`
	r := source.Resolve(ctx, c, "example.org/tools/cmd/x")
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if r.Host != "vanity" || r.RepoHost != "github.com" || r.Owner != "acme" || r.Name != "tools" || r.Subdir != "cmd/x" || r.VCS != "git" {
		t.Fatalf("Resolve = %+v", r)
	}
	vi := r.Vanity
	if vi.ImportPath != "example.org/tools" || !vi.HTTPS || vi.RedirectHost != "" || vi.Source == nil || vi.URL != "https://example.org/tools?go-get=1" {
		t.Fatalf("vanity = %+v", vi)
	}

	// Cross-domain redirect is reported.
	w.Vanity["moved.example/new"] = `<meta name="go-import" content="moved.example/lib git https://git.moved.example/lib">`
	w.Extra["/vanity/moved.example/lib"] = func(rw http.ResponseWriter, r *http.Request) {
		http.Redirect(rw, r, w.URL+"/vanity/other.example/landing?go-get=1", http.StatusFound)
	}
	w.Vanity["other.example/landing"] = `<meta name="go-import" content="moved.example/lib git https://git.other.example/lib">`
	r = source.Resolve(ctx, c, "moved.example/lib")
	if r.Vanity == nil || r.Vanity.RedirectHost != "other.example" || r.URL != "https://git.other.example/lib" {
		t.Fatalf("redirect: %+v %+v", r, r.Vanity)
	}

	// Unreachable page.
	r = source.Resolve(ctx, c, "gone.example/lib")
	if r.Err == nil || r.Vanity == nil || r.Vanity.Status != 404 {
		t.Fatalf("missing page: %+v", r)
	}
	if source.RepoKey("https://GitHub.com/Acme/Tools.git/") != "github.com/acme/tools" {
		t.Fatal("RepoKey")
	}
}

func TestDomainInfo(t *testing.T) {
	w := testenv.New(t)
	c := newContext(t, w)
	ctx := context.Background()
	now := time.Now()
	w.RDAP["domain/example.org"] = map[string]any{
		"ldhName": "EXAMPLE.ORG", "status": []string{"client transfer prohibited"},
		"events": []map[string]any{
			{"eventAction": "registration", "eventDate": "2015-03-01T00:00:00Z"},
			{"eventAction": "expiration", "eventDate": now.Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)},
		},
	}
	d, err := source.DomainInfo(ctx, c, "pkg.example.org")
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "example.org" || d.Registered == nil || d.Registered.Year() != 2015 || d.Expired(now) {
		t.Fatalf("domain = %+v", d)
	}
	if days, ok := d.DaysLeft(now); !ok || days < 9 || days > 10 {
		t.Fatalf("days left = %d %v", days, ok)
	}
	w.RDAP["domain/old.example"] = map[string]any{"status": []string{"redemption period"}}
	if d, _ := source.DomainInfo(ctx, c, "old.example"); !d.Expired(now) {
		t.Fatalf("redemption period not expired: %+v", d)
	}
	if d, err := source.DomainInfo(ctx, c, "nobody.example"); err != nil || !d.NotFound {
		t.Fatalf("not found: %+v %v", d, err)
	}
}

func TestMatchGoImport(t *testing.T) {
	git := func(prefix, repo string) source.GoImport {
		return source.GoImport{Prefix: prefix, VCS: "git", Repo: repo}
	}
	mod := func(prefix, repo string) source.GoImport {
		return source.GoImport{Prefix: prefix, VCS: "mod", Repo: repo}
	}
	cases := []struct {
		name    string
		imports []source.GoImport
		path    string
		want    string // repo, or "error:<substring>"
	}{
		{"exact", []source.GoImport{git("example.org/a", "https://r/a")}, "example.org/a", "https://r/a"},
		{"prefix", []source.GoImport{git("example.org/a", "https://r/a")}, "example.org/a/b", "https://r/a"},
		{"not a path prefix", []source.GoImport{git("example.org/a", "https://r/a")}, "example.org/ab", "error:do not match"},
		{"none", nil, "example.org/a", "error:no go-import"},
		{"two lengths", []source.GoImport{git("example.org", "https://r"), git("example.org/a", "https://r/a")}, "example.org/a", "error:multiple meta tags"},
		{"duplicate", []source.GoImport{git("example.org/a", "https://r/a"), git("example.org/a", "https://r/a")}, "example.org/a", "error:multiple meta tags"},
		{"mod wins", []source.GoImport{git("example.org/a", "https://r/a"), mod("example.org/a", "https://proxy")}, "example.org/a", "https://proxy"},
		{"mod then shorter git", []source.GoImport{git("example.org", "https://r"), mod("example.org/a", "https://proxy")}, "example.org/a", "https://proxy"},
		{"two mods", []source.GoImport{mod("example.org", "https://p1"), mod("example.org/a", "https://p2")}, "example.org/a", "error:multiple meta tags"},
		{"unrelated ignored", []source.GoImport{git("other.org/x", "https://o"), git("example.org/a", "https://r/a")}, "example.org/a", "https://r/a"},
	}
	for _, tc := range cases {
		m, err := source.MatchGoImport(tc.imports, tc.path)
		if sub, ok := strings.CutPrefix(tc.want, "error:"); ok {
			if err == nil || !strings.Contains(err.Error(), sub) {
				t.Errorf("%s: got %+v, %v; want error containing %q", tc.name, m, err, sub)
			}
			continue
		}
		if err != nil || m.Repo != tc.want {
			t.Errorf("%s: got %+v, %v; want %s", tc.name, m, err, tc.want)
		}
	}
}

func TestFetchVanityErrorPageAndHTTP(t *testing.T) {
	w := testenv.New(t)
	c := newContext(t, w)
	ctx := context.Background()
	// Tags on a 404 page are used, as the go command does.
	w.Extra["/vanity/nf.example/lib"] = func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(404)
		rw.Write([]byte(`<meta name="go-import" content="nf.example/lib git https://github.com/acme/lib">`))
	}
	vi := source.FetchVanity(ctx, c, "nf.example/lib", "nf.example/lib")
	if vi.Status != 404 || vi.Match == nil || vi.Error != "" || !vi.HTTPS {
		t.Fatalf("404 page: %+v", vi)
	}
	// /vanity-http/ plays plain http.
	w.Vanity["plain.example/lib"] = `<meta name="go-import" content="plain.example/lib git https://github.com/acme/lib">`
	w.Extra["/vanity/plain.example/lib"] = func(rw http.ResponseWriter, r *http.Request) {
		http.Redirect(rw, r, w.URL+"/vanity-http/plain.example/lib?go-get=1", http.StatusFound)
	}
	vi = source.FetchVanity(ctx, c, "plain.example/lib", "plain.example/lib")
	if vi.HTTPS || vi.FinalURL != "http://plain.example/lib?go-get=1" || vi.RedirectHost != "" || vi.Match == nil {
		t.Fatalf("http page: %+v", vi)
	}
}

func TestPrivateDomain(t *testing.T) {
	c := &cli.Context{Env: goenv.New(map[string]string{"GOPRIVATE": "github.com/corp,corp.example.com", "GONOSUMDB": "*.internal.test"})}
	for dom, want := range map[string]bool{
		"corp.example.com":     true,
		"example.com":          true, // registrable domain of a private host
		"other.example.com":    true,
		"github.com":           false, // github.com/corp makes repositories private, not the host
		"git.internal.test":    true,
		"internal.test":        true,
		"public.example.org":   false,
		"corp.example.com:443": true,
	} {
		if got := source.PrivateDomain(c, dom); got != want {
			t.Errorf("PrivateDomain(%q) = %v, want %v", dom, got, want)
		}
	}
	if _, err := source.DomainInfo(context.Background(), c, "corp.example.com"); err != source.ErrPrivate {
		t.Errorf("DomainInfo of a private domain: %v, want ErrPrivate", err)
	}
}
