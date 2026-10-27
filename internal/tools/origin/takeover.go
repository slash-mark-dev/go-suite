package origin

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/feeds"
	"github.com/slash-mark-dev/go-suite/internal/httpx"
	"github.com/slash-mark-dev/go-suite/internal/par"
	"github.com/slash-mark-dev/go-suite/internal/report"
	"github.com/slash-mark-dev/go-suite/internal/source"
)

var takeoverFlags struct {
	direct     *bool
	expiryDays *int
	failOn     func() (report.Severity, error)
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "takeover",
		Group:   group,
		Summary: "Repo takeover risk: deleted owners, renamed repos, expiring vanity domains",
		Usage:   "sm-go takeover [module[@version]...] [flags]",
		Help: `Resolves the source repository of every module in the build list (GitHub
paths directly, other paths through their go-import vanity pages) and flags
the situations in which somebody else could claim the name the go command
fetches from:

  - the GitHub owner account no longer exists (anyone can register it and
    recreate the repository: "repojacking")
  - the repository was renamed or transferred and the old owner name is
    free, or the old name can be recreated by its owner, breaking the
    redirect GitHub currently serves
  - the owner account or repository was created after the version you use
    was published (the name may already have been re-registered)
  - the repository is archived, disabled or gone
  - the vanity import domain (or the domain hosting the repository) has
    expired, is about to expire, has no registration record, or does not
    resolve

Module paths may be given as arguments; by default the whole build list of
the current module is checked (--direct limits it to direct requirements).`,
		Examples: []string{
			"sm-go takeover",
			"sm-go takeover --direct --fail-on high",
			"sm-go takeover github.com/acme/lib go.example.org/tool --json",
		},
		Sources: []string{"Go module proxy", "GitHub REST API", "vanity import pages", "RDAP"},
		Flags: func(fs *flag.FlagSet) {
			takeoverFlags.direct = fs.Bool("direct", false, "check only direct requirements")
			takeoverFlags.expiryDays = fs.Int("expiry-days", 30, "flag domains expiring within `n` days")
			takeoverFlags.failOn = cli.SeverityFlag(fs, "fail-on", "medium", "exit 1 on findings at or above this `severity`")
		},
		Run: runTakeover,
	})
}

// TakeoverGitHub is what GitHub says about a module's repository.
type TakeoverGitHub struct {
	Requested    string     `json:"requested"`
	FullName     string     `json:"fullName,omitempty"`
	Found        bool       `json:"found"`
	Moved        bool       `json:"moved,omitempty"`
	Archived     bool       `json:"archived,omitempty"`
	Disabled     bool       `json:"disabled,omitempty"`
	RepoCreated  *time.Time `json:"repoCreated,omitempty"`
	OwnerExists  *bool      `json:"ownerExists,omitempty"`
	OwnerCreated *time.Time `json:"ownerCreated,omitempty"`
	// OldOwnerExists is set for transferred repositories: whether the
	// login the module path names still exists.
	OldOwnerExists *bool `json:"oldOwnerExists,omitempty"`
}

// TakeoverModule is the takeover assessment of one module.
type TakeoverModule struct {
	Dep
	// Status is "ok", "risk" or "unchecked".
	Status    string           `json:"status"`
	Repo      *source.Repo     `json:"repo,omitempty"`
	Published *time.Time       `json:"published,omitempty"`
	GitHub    *TakeoverGitHub  `json:"github,omitempty"`
	Domains   []*source.Domain `json:"domains,omitempty"`
	Findings  []report.Finding `json:"findings,omitempty"`
	Note      string           `json:"note,omitempty"`
}

// TakeoverResult is the JSON result of sm-go takeover.
type TakeoverResult struct {
	Subject  string           `json:"subject"`
	Modules  []TakeoverModule `json:"modules"`
	Findings []report.Finding `json:"findings"`
	Summary  struct {
		Modules   int `json:"modules"`
		AtRisk    int `json:"atRisk"`
		Unchecked int `json:"unchecked"`
		severityCounts
	} `json:"summary"`
}

func runTakeover(c *cli.Context) error {
	failOn, err := takeoverFlags.failOn()
	if err != nil {
		return err
	}
	if *takeoverFlags.expiryDays < 0 {
		return cli.Usagef("--expiry-days must be >= 0")
	}
	deps, err := SelectDeps(c, !*takeoverFlags.direct, c.Args)
	if err != nil {
		return err
	}
	now := time.Now()
	res := &TakeoverResult{Subject: subject(c, c.Args), Modules: []TakeoverModule{}, Findings: []report.Finding{}}
	mods, errs := par.Map(c.Ctx, 8, deps, func(ctx context.Context, d Dep) (TakeoverModule, error) {
		return assessTakeover(ctx, c, d, now)
	})
	if err := par.FirstErr(errs); err != nil {
		return err
	}
	for _, m := range mods {
		report.SortFindings(m.Findings)
		res.Modules = append(res.Modules, m)
		res.Findings = append(res.Findings, m.Findings...)
		switch m.Status {
		case "risk":
			res.Summary.AtRisk++
		case "unchecked":
			res.Summary.Unchecked++
		}
	}
	report.SortFindings(res.Findings)
	res.Summary.Modules = len(res.Modules)
	res.Summary.severityCounts = countSeverities(res.Findings)
	c.SetResult(res)
	if len(report.AtLeast(res.Findings, failOn)) > 0 && failOn != report.None {
		c.Issues()
	}
	if c.Text() {
		printTakeover(c, res)
	}
	return nil
}

func assessTakeover(ctx context.Context, c *cli.Context, d Dep, now time.Time) (TakeoverModule, error) {
	m := TakeoverModule{Dep: d, Status: "ok"}
	if d.Local != "" {
		m.Status = "unchecked"
		m.Note = "replaced by local directory " + d.Local
		return m, nil
	}
	path, version := d.CodePath(), d.CodeVersion()
	add := func(sev report.Severity, rule, title, detail string) {
		m.Findings = append(m.Findings, report.Finding{Severity: sev, Rule: rule, Module: d.Path, Version: d.Version, Title: title, Detail: detail})
	}
	r := source.Resolve(ctx, c, path)
	m.Repo = r
	if r.Host == source.Unknown {
		m.Status = "unchecked"
		m.Note = "not a network module path"
		return m, nil
	}
	if version != "" {
		if info, err := c.Proxy().Info(ctx, path, version); err == nil && !info.Time.IsZero() {
			t := info.Time.UTC()
			m.Published = &t
		}
	}

	// Vanity domains: the import path's domain and, for self-hosted
	// repositories, the repository host's domain.
	// Private modules: no RDAP lookups (a public third-party service), and
	// the GitHub API only for github.com/... paths (their own host).
	private := c.IsPrivate(path)
	if r.Host == source.Vanity && r.WellKnown == "" && private {
		c.NotePrivate(path)
		m.Note = "domain registration checks skipped: private module"
	}
	if r.Host == source.Vanity && r.WellKnown == "" {
		domains := []string{source.ModuleDomain(path)}
		if private {
			domains = nil
		}
		if r.RepoHost != "" && !source.IsCodeHost(r.RepoHost) {
			if rd := source.RegistrableDomain(r.RepoHost); rd != "" && rd != domains[0] {
				domains = append(domains, rd)
			}
		}
		for i, dom := range domains {
			if dom == "" {
				continue
			}
			info, err := source.DomainInfo(ctx, c, dom)
			if errors.Is(err, source.ErrPrivate) {
				continue
			}
			if err != nil {
				c.Warnf("%s: RDAP lookup of %s failed: %v", d.Path, dom, err)
				continue
			}
			m.Domains = append(m.Domains, info)
			what := "vanity import domain " + dom
			if i > 0 {
				what = "repository domain " + dom
			}
			domainFindings(add, info, what, r.Err != nil && noResponse(r.Vanity), *takeoverFlags.expiryDays, now)
		}
		if r.Err != nil {
			sev := report.High
			detail := fmt.Sprintf("The go command cannot resolve %s through its go-import page: %v. Whoever controls that page decides where the code comes from.", path, r.Err)
			if r.Vanity != nil && r.Vanity.DNSError {
				detail = fmt.Sprintf("%s does not resolve in DNS. If the domain lapses anyone can register it and serve a go-import tag pointing at their own repository.", source.ModuleDomain(path))
			}
			add(sev, "vanity-unresolvable", "vanity import path does not resolve", detail)
		}
	}

	if !r.OnGitHub() {
		if r.Err == nil && len(m.Findings) == 0 && r.RepoHost != "" && r.RepoHost != source.GitHub {
			m.Note = joinNote(m.Note, "repository on "+r.RepoHost+" (account checks are only available for GitHub)")
		}
		finishTakeover(&m)
		return m, nil
	}

	if !c.GitHubAPIAllowed(path) {
		m.Note = joinNote(m.Note, "GitHub checks skipped: private module")
		m.Status = "unchecked"
		finishTakeover(&m)
		return m, nil
	}
	gh := c.GitHub()
	g := &TakeoverGitHub{Requested: r.Slug()}
	m.GitHub = g
	repo, err := gh.Repo(ctx, r.Owner, r.Name)
	switch {
	case httpx.IsNotFound(err):
		exists, created, aerr := accountExists(ctx, gh, r.Owner)
		if aerr != nil {
			c.Warnf("%s: GitHub account lookup failed: %v", d.Path, aerr)
			m.Status = "unchecked"
			return m, nil
		}
		g.OwnerExists, g.OwnerCreated = &exists, created
		if !exists {
			add(report.Critical, "owner-deleted", fmt.Sprintf("GitHub account %q does not exist", r.Owner),
				fmt.Sprintf("Neither github.com/%s nor the account %s exists. Anyone can register %q, create the repository %s and publish code under this module path (repojacking). Builds that bypass the module proxy cache would fetch it.", r.Slug(), r.Owner, r.Owner, r.Name))
		} else {
			add(report.High, "repo-missing", fmt.Sprintf("repository %s is gone (deleted, private or renamed away)", r.Slug()),
				fmt.Sprintf("The owner %s still exists, but %s is not publicly available. Only the module proxy's cached copy remains; the owner (or whoever controls the account) can recreate the name with different content.", r.Owner, r.Slug()))
		}
	case err != nil:
		c.Warnf("%s: GitHub lookup of %s failed: %v", d.Path, r.Slug(), err)
		m.Status = "unchecked"
		return m, nil
	default:
		g.Found = true
		g.FullName, g.Moved, g.Archived, g.Disabled = repo.FullName, repo.Moved, repo.Archived, repo.Disabled
		if !repo.CreatedAt.IsZero() {
			t := repo.CreatedAt.UTC()
			g.RepoCreated = &t
		}
		newOwner, _, _ := strings.Cut(repo.FullName, "/")
		if repo.Moved {
			if !strings.EqualFold(newOwner, r.Owner) {
				exists, created, aerr := accountExists(ctx, gh, r.Owner)
				if aerr != nil {
					c.Warnf("%s: GitHub account lookup failed: %v", d.Path, aerr)
				} else {
					g.OldOwnerExists = &exists
					g.OwnerCreated = created
					if !exists {
						add(report.Critical, "owner-renamed", fmt.Sprintf("%s moved to %s and the login %q is free", r.Slug(), repo.FullName, r.Owner),
							fmt.Sprintf("GitHub redirects %s to %s only until someone registers %q. A new account with that name can create %s and take over the module path.", r.Slug(), repo.FullName, r.Owner, r.Slug()))
					} else {
						add(report.Medium, "repo-transferred", fmt.Sprintf("repository transferred to %s", repo.FullName),
							fmt.Sprintf("%s now redirects to %s. The account %s can create a new %s at any time, which silently replaces the redirect target. Update the module path or pin it with a replace directive.", r.Slug(), repo.FullName, r.Owner, r.Slug()))
					}
				}
			} else {
				add(report.Low, "repo-renamed", fmt.Sprintf("repository renamed to %s", repo.FullName),
					fmt.Sprintf("%s redirects to %s. If %s creates a repository with the old name again, the module path will point at it.", r.Slug(), repo.FullName, r.Owner))
			}
		}
		if repo.Disabled {
			add(report.High, "repo-disabled", "repository is disabled by GitHub", "GitHub disabled "+repo.FullName+" (typically for terms-of-service violations).")
		}
		if repo.Archived {
			add(report.Medium, "repo-archived", "repository is archived", repo.FullName+" is read-only and unmaintained; nobody will ship security fixes or notice a takeover of related names.")
		}
		if m.Published != nil && g.RepoCreated != nil && g.RepoCreated.After(*m.Published) && !repo.Moved {
			add(report.High, "repo-recreated", "repository was created after this version was published",
				fmt.Sprintf("%s was created on %s but %s@%s was published on %s: the repository has been deleted and recreated, possibly by someone else. Compare the code with the checksum in go.sum.", repo.FullName, day(*g.RepoCreated), path, version, day(*m.Published)))
		}
		if !repo.Moved {
			if exists, created, aerr := accountExists(ctx, gh, r.Owner); aerr == nil {
				g.OwnerExists, g.OwnerCreated = &exists, created
			}
		}
	}
	if m.Published != nil && g.OwnerCreated != nil && g.OwnerCreated.After(*m.Published) {
		add(report.High, "owner-recreated", fmt.Sprintf("account %q was registered after this version was published", r.Owner),
			fmt.Sprintf("The account %s was created on %s, after %s@%s was published on %s. The original owner's name has been re-registered, possibly by someone else.", r.Owner, day(*g.OwnerCreated), path, version, day(*m.Published)))
	}
	finishTakeover(&m)
	return m, nil
}

func joinNote(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

func finishTakeover(m *TakeoverModule) {
	if len(m.Findings) > 0 {
		for _, f := range m.Findings {
			if f.Severity >= report.Low {
				m.Status = "risk"
				return
			}
		}
	}
}

// accountExists reports whether a GitHub login exists, with its creation
// time.
func accountExists(ctx context.Context, gh *feeds.GitHub, login string) (bool, *time.Time, error) {
	a, err := gh.Account(ctx, login)
	if httpx.IsNotFound(err) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	if a.CreatedAt.IsZero() {
		return true, nil, nil
	}
	t := a.CreatedAt.UTC()
	return true, &t, nil
}

// domainFindings adds findings for a domain's registration state.
func domainFindings(add func(report.Severity, string, string, string), d *source.Domain, what string, unresolved bool, expiryDays int, now time.Time) {
	switch {
	case d.Expired(now):
		state := "is in a post-expiry registry state (" + strings.Join(d.Status, ", ") + ")"
		if d.Expires != nil && d.Expires.Before(now) {
			state = "expired on " + day(*d.Expires)
		}
		add(report.Critical, "domain-expired", what+" has expired",
			fmt.Sprintf("%s %s. Once released anyone can register it and serve their own go-import tag.", d.Name, state))
	case d.NotFound && unresolved:
		add(report.Critical, "domain-unregistered", what+" has no registration record",
			fmt.Sprintf("RDAP has no record of %s and the import path does not resolve: the domain appears to be unregistered and can be claimed by anyone.", d.Name))
	case d.NotFound:
		add(report.Info, "domain-no-rdap", what+" has no RDAP record",
			fmt.Sprintf("RDAP returned no record for %s (its registry may not offer RDAP); expiry could not be checked.", d.Name))
	default:
		if days, ok := d.DaysLeft(now); ok && days <= expiryDays {
			sev := report.Medium
			if days <= 7 {
				sev = report.High
			}
			add(sev, "domain-expiring", fmt.Sprintf("%s expires in %s", what, dayCount(days)),
				fmt.Sprintf("%s expires on %s. If it is not renewed anyone can register it and serve their own go-import tag.", d.Name, day(*d.Expires)))
		}
	}
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02") }

func dayCount(n int) string {
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}

func printTakeover(c *cli.Context, res *TakeoverResult) {
	o := c.Out
	o.Title(fmt.Sprintf("Repo takeover risk · %s", res.Subject))
	o.Printf("%s\n", o.Dim(fmt.Sprintf("%d modules checked · %d at risk · %d unchecked", res.Summary.Modules, res.Summary.AtRisk, res.Summary.Unchecked)))
	var rows [][]string
	for _, m := range res.Modules {
		where := "-"
		if m.Repo != nil && m.Repo.URL != "" {
			where = strings.TrimPrefix(m.Repo.URL, "https://")
		}
		if m.GitHub != nil && m.GitHub.Moved {
			where += " → " + m.GitHub.FullName
		}
		if strings.Contains(m.Note, "skipped: private module") {
			where += o.Dim(" (skipped: private module)")
		}
		status := o.Green("ok")
		switch m.Status {
		case "risk":
			status = o.Sev(maxSeverity(m.Findings))
		case "unchecked":
			status = o.Dim("unchecked")
		}
		rows = append(rows, []string{status, m.Dep.String(), where})
	}
	if len(rows) > 0 {
		o.Heading("Modules")
		o.Table([]string{"STATUS", "MODULE", "SOURCE"}, rows)
	}
	if len(res.Findings) == 0 {
		o.Println()
		o.OK("no takeover risks found")
		return
	}
	o.Heading("Findings")
	printFindings(c, res.Findings)
	o.Printf("\n%s\n", res.Summary.severityCounts.String())
}
