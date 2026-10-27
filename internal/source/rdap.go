package source

import (
	"context"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/feeds"
	"github.com/slash-mark-dev/go-suite/internal/httpx"
)

// Domain is the RDAP registration record of a domain.
type Domain struct {
	Name       string     `json:"name"`
	Registered *time.Time `json:"registered,omitempty"`
	Expires    *time.Time `json:"expires,omitempty"`
	Status     []string   `json:"status,omitempty"`
	// NotFound is true when the registry has no record (the domain may be
	// unregistered, or its TLD may not offer RDAP).
	NotFound bool `json:"notFound,omitempty"`
}

// Expired reports whether the domain is past its expiration date or in a
// post-expiry registry state (redemption period, pending delete).
func (d *Domain) Expired(now time.Time) bool {
	if d == nil {
		return false
	}
	for _, s := range d.Status {
		s = strings.ToLower(s)
		if strings.Contains(s, "redemption") || strings.Contains(s, "pending delete") || strings.Contains(s, "pendingdelete") {
			return true
		}
	}
	return d.Expires != nil && d.Expires.Before(now)
}

// DaysLeft returns the days until expiry (negative if expired); ok is
// false when the expiration date is unknown.
func (d *Domain) DaysLeft(now time.Time) (days int, ok bool) {
	if d == nil || d.Expires == nil {
		return 0, false
	}
	return int(d.Expires.Sub(now).Hours() / 24), true
}

// twoPartSuffixes are public suffixes with two labels, approximating the
// public suffix list for the registrable-domain computation.
var twoPartSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true, "ltd.uk": true, "plc.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true, "id.au": true,
	"co.in": true, "net.in": true, "org.in": true, "firm.in": true, "gen.in": true, "ind.in": true, "ac.in": true,
	"com.br": true, "net.br": true, "org.br": true, "gov.br": true,
	"co.jp": true, "ne.jp": true, "or.jp": true, "ac.jp": true,
	"co.nz": true, "net.nz": true, "org.nz": true,
	"co.za": true, "org.za": true, "com.cn": true, "net.cn": true, "org.cn": true,
	"com.mx": true, "com.tr": true, "com.sg": true, "com.hk": true, "com.tw": true, "co.kr": true,
	"com.ar": true, "com.co": true, "co.il": true, "com.my": true, "com.ph": true, "com.vn": true,
	"com.ua": true, "co.id": true, "com.pk": true, "com.ng": true, "com.eg": true,
}

// RegistrableDomain approximates the eTLD+1 of host: the last two labels,
// or three for known two-label public suffixes. It returns "" for IP
// addresses and single-label hosts.
func RegistrableDomain(host string) string {
	host = strings.ToLower(strings.TrimSuffix(hostOnly(host), "."))
	if host == "" || net.ParseIP(strings.Trim(host, "[]")) != nil {
		return ""
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return ""
	}
	n := 2
	if len(labels) >= 3 && twoPartSuffixes[strings.Join(labels[len(labels)-2:], ".")] {
		n = 3
	}
	if len(labels) < n {
		return ""
	}
	return strings.Join(labels[len(labels)-n:], ".")
}

// ModuleDomain returns the registrable domain of a module path's host.
func ModuleDomain(modulePath string) string { return RegistrableDomain(firstElem(modulePath)) }

// ErrPrivate is returned by DomainInfo, without contacting the registry,
// for the domain of a private module.
var ErrPrivate = feeds.ErrPrivate

// PrivateDomain reports whether an RDAP lookup of domain could reveal a
// private module: domain (or its registrable domain) matches one of the
// GOPRIVATE/GONOPROXY/GONOSUMDB patterns as a one-element path, or shares
// its registrable domain with a pattern that makes a whole host private
// ("corp.example.com" or "*.corp.example.com" make example.com private;
// "github.com/corp" does not make github.com private).
func PrivateDomain(c *cli.Context, domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(hostOnly(domain), "."))
	if domain == "" {
		return false
	}
	reg := RegistrableDomain(domain)
	if c.IsPrivate(domain) || (reg != "" && c.IsPrivate(reg)) {
		return true
	}
	for _, p := range strings.Split(c.Env.PrivatePatterns(), ",") {
		p = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p), "/"))
		if p == "" || strings.Contains(p, "/") {
			continue
		}
		if pr := RegistrableDomain(p); pr != "" && (pr == reg || pr == domain) {
			return true
		}
	}
	return false
}

// DomainInfo fetches the RDAP record of the registrable domain of domain.
// A registry 404 is reported as Domain.NotFound, not as an error. The
// domains of private modules (see PrivateDomain) are never sent to the
// public RDAP service: DomainInfo returns ErrPrivate instead.
func DomainInfo(ctx context.Context, c *cli.Context, domain string) (*Domain, error) {
	reg := RegistrableDomain(domain)
	if reg == "" {
		reg = strings.ToLower(domain)
	}
	if PrivateDomain(c, domain) {
		return nil, ErrPrivate
	}
	d := &Domain{Name: reg}
	var resp struct {
		LDHName string   `json:"ldhName"`
		Status  []string `json:"status"`
		Events  []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
	}
	err := c.HTTP().GetJSON(ctx, c.Endpoint("rdap")+"/domain/"+url.PathEscape(reg), &resp,
		httpx.TTL(12*time.Hour), httpx.Header("Accept", "application/rdap+json"))
	if httpx.IsNotFound(err) {
		d.NotFound = true
		return d, nil
	}
	if err != nil {
		return nil, err
	}
	d.Status = resp.Status
	for _, e := range resp.Events {
		t, err := time.Parse(time.RFC3339, e.Date)
		if err != nil {
			if t, err = time.Parse("2006-01-02T15:04:05", strings.TrimSuffix(e.Date, "Z")); err != nil {
				continue
			}
		}
		t = t.UTC()
		switch strings.ToLower(e.Action) {
		case "registration":
			d.Registered = &t
		case "expiration":
			d.Expires = &t
		}
	}
	return d, nil
}
