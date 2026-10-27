// Package semver implements comparison of semantic version strings as used by
// Go modules: "v" + MAJOR[.MINOR[.PATCH[-PRERELEASE][+BUILD]]].
//
// The behaviour matches golang.org/x/mod/semver exactly (verified by the
// differential tests in verify/), including the "v1" and "v1.2" shorthands.
package semver

import (
	"sort"
	"strings"
)

type parsed struct {
	major, minor, patch string
	short               string // ".0.0" or ".0" when the input used a shorthand
	prerelease, build   string
}

// IsValid reports whether v is a valid semantic version string.
func IsValid(v string) bool {
	_, ok := parse(v)
	return ok
}

// Canonical returns the canonical formatting of v: "v1" becomes "v1.0.0",
// build metadata is removed and invalid versions return "".
func Canonical(v string) string {
	p, ok := parse(v)
	if !ok {
		return ""
	}
	if p.build != "" {
		return v[:len(v)-len(p.build)]
	}
	if p.short != "" {
		return v + p.short
	}
	return v
}

// Major returns "vMAJOR", or "" if v is invalid.
func Major(v string) string {
	p, ok := parse(v)
	if !ok {
		return ""
	}
	return v[:1+len(p.major)]
}

// MajorMinor returns "vMAJOR.MINOR", or "" if v is invalid.
func MajorMinor(v string) string {
	p, ok := parse(v)
	if !ok {
		return ""
	}
	i := 1 + len(p.major)
	if j := i + 1 + len(p.minor); j <= len(v) && v[i] == '.' && v[i+1:j] == p.minor {
		return v[:j]
	}
	return v[:i] + "." + p.minor
}

// Prerelease returns the prerelease suffix including the leading "-", or "".
func Prerelease(v string) string {
	p, ok := parse(v)
	if !ok {
		return ""
	}
	return p.prerelease
}

// Build returns the build suffix including the leading "+", or "".
func Build(v string) string {
	p, ok := parse(v)
	if !ok {
		return ""
	}
	return p.build
}

// Compare returns -1, 0 or +1. An invalid version is less than every valid
// one and equal to every other invalid one.
func Compare(v, w string) int {
	pv, ok1 := parse(v)
	pw, ok2 := parse(w)
	if !ok1 && !ok2 {
		return 0
	}
	if !ok1 {
		return -1
	}
	if !ok2 {
		return +1
	}
	if c := compareInt(pv.major, pw.major); c != 0 {
		return c
	}
	if c := compareInt(pv.minor, pw.minor); c != 0 {
		return c
	}
	if c := compareInt(pv.patch, pw.patch); c != 0 {
		return c
	}
	return comparePrerelease(pv.prerelease, pw.prerelease)
}

// Max canonicalizes both arguments and returns the greater one.
func Max(v, w string) string {
	v = Canonical(v)
	w = Canonical(w)
	if Compare(v, w) > 0 {
		return v
	}
	return w
}

// ByVersion sorts versions by Compare, breaking ties lexically.
type ByVersion []string

func (vs ByVersion) Len() int      { return len(vs) }
func (vs ByVersion) Swap(i, j int) { vs[i], vs[j] = vs[j], vs[i] }
func (vs ByVersion) Less(i, j int) bool {
	if c := Compare(vs[i], vs[j]); c != 0 {
		return c < 0
	}
	return vs[i] < vs[j]
}

// Sort sorts a list of versions in increasing order.
func Sort(list []string) { sort.Sort(ByVersion(list)) }

// IsIncompatible reports whether v carries the "+incompatible" build suffix.
func IsIncompatible(v string) bool { return strings.HasSuffix(v, "+incompatible") }

func parse(v string) (p parsed, ok bool) {
	if v == "" || v[0] != 'v' {
		return
	}
	var rest string
	p.major, rest, ok = parseInt(v[1:])
	if !ok {
		return
	}
	if rest == "" {
		p.minor, p.patch, p.short = "0", "0", ".0.0"
		return
	}
	if rest[0] != '.' {
		return p, false
	}
	p.minor, rest, ok = parseInt(rest[1:])
	if !ok {
		return
	}
	if rest == "" {
		p.patch, p.short = "0", ".0"
		return
	}
	if rest[0] != '.' {
		return p, false
	}
	p.patch, rest, ok = parseInt(rest[1:])
	if !ok {
		return
	}
	if len(rest) > 0 && rest[0] == '-' {
		p.prerelease, rest, ok = parsePrerelease(rest)
		if !ok {
			return
		}
	}
	if len(rest) > 0 && rest[0] == '+' {
		p.build, rest, ok = parseBuild(rest)
		if !ok {
			return
		}
	}
	if rest != "" {
		return p, false
	}
	return p, true
}

func parseInt(v string) (t, rest string, ok bool) {
	if v == "" || v[0] < '0' || v[0] > '9' {
		return
	}
	i := 1
	for i < len(v) && '0' <= v[i] && v[i] <= '9' {
		i++
	}
	if v[0] == '0' && i != 1 {
		return
	}
	return v[:i], v[i:], true
}

func parsePrerelease(v string) (t, rest string, ok bool) {
	// v starts with '-'
	i := 1
	start := 1
	for i < len(v) && v[i] != '+' {
		if !isIdentChar(v[i]) && v[i] != '.' {
			return
		}
		if v[i] == '.' {
			if start == i || isBadNum(v[start:i]) {
				return
			}
			start = i + 1
		}
		i++
	}
	if start == i || isBadNum(v[start:i]) {
		return
	}
	return v[:i], v[i:], true
}

func parseBuild(v string) (t, rest string, ok bool) {
	i := 1
	start := 1
	for i < len(v) {
		if !isIdentChar(v[i]) && v[i] != '.' {
			return
		}
		if v[i] == '.' {
			if start == i {
				return
			}
			start = i + 1
		}
		i++
	}
	if start == i {
		return
	}
	return v[:i], v[i:], true
}

func isIdentChar(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-'
}

func isBadNum(v string) bool {
	i := 0
	for i < len(v) && '0' <= v[i] && v[i] <= '9' {
		i++
	}
	return i == len(v) && i > 1 && v[0] == '0'
}

func isNum(v string) bool {
	i := 0
	for i < len(v) && '0' <= v[i] && v[i] <= '9' {
		i++
	}
	return i == len(v)
}

func compareInt(x, y string) int {
	if x == y {
		return 0
	}
	if len(x) < len(y) {
		return -1
	}
	if len(x) > len(y) {
		return +1
	}
	if x < y {
		return -1
	}
	return +1
}

func comparePrerelease(x, y string) int {
	// "" > "-anything"
	if x == y {
		return 0
	}
	if x == "" {
		return +1
	}
	if y == "" {
		return -1
	}
	for x != "" && y != "" {
		x = x[1:] // skip - or .
		y = y[1:]
		var dx, dy string
		dx, x = nextIdent(x)
		dy, y = nextIdent(y)
		if dx != dy {
			ix := isNum(dx)
			iy := isNum(dy)
			if ix != iy {
				if ix {
					return -1
				}
				return +1
			}
			if ix {
				if len(dx) < len(dy) {
					return -1
				}
				if len(dx) > len(dy) {
					return +1
				}
			}
			if dx < dy {
				return -1
			}
			return +1
		}
	}
	if x == "" {
		return -1
	}
	return +1
}

func nextIdent(x string) (dx, rest string) {
	i := 0
	for i < len(x) && x[i] != '.' {
		i++
	}
	return x[:i], x[i:]
}
