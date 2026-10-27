// Package module implements Go module path and version rules: path
// validation, major-version suffixes, case escaping for proxy URLs and
// pseudo-version parsing. Behaviour matches golang.org/x/mod/module.
package module

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/slash-mark-dev/go-suite/internal/semver"
)

// Version is a module path and version pair. Version is "" for a main
// module or a filesystem replacement.
type Version struct {
	Path    string `json:"path"`
	Version string `json:"version,omitempty"`
}

func (m Version) String() string {
	if m.Version == "" {
		return m.Path
	}
	return m.Path + "@" + m.Version
}

// Sort sorts by path, then by semantic version.
func Sort(list []Version) {
	sort.Slice(list, func(i, j int) bool {
		mi, mj := list[i], list[j]
		if mi.Path != mj.Path {
			return mi.Path < mj.Path
		}
		vi, vj := mi.Version, mj.Version
		var fi, fj string
		if k := strings.Index(vi, "/"); k >= 0 {
			vi, fi = vi[:k], vi[k:]
		}
		if k := strings.Index(vj, "/"); k >= 0 {
			vj, fj = vj[:k], vj[k:]
		}
		if vi != vj {
			return semver.Compare(vi, vj) < 0
		}
		return fi < fj
	})
}

const (
	kindModule = iota
	kindImport
	kindFile
)

// CheckPath checks that a module path is valid.
func CheckPath(p string) error {
	if err := checkPath(p, kindModule); err != nil {
		return fmt.Errorf("malformed module path %q: %v", p, err)
	}
	i := strings.Index(p, "/")
	if i < 0 {
		i = len(p)
	}
	if i == 0 {
		return fmt.Errorf("malformed module path %q: leading slash", p)
	}
	if !strings.Contains(p[:i], ".") {
		return fmt.Errorf("malformed module path %q: missing dot in first path element", p)
	}
	if p[0] == '-' {
		return fmt.Errorf("malformed module path %q: leading dash in first path element", p)
	}
	for _, r := range p[:i] {
		if !firstPathOK(r) {
			return fmt.Errorf("malformed module path %q: invalid char %q in first path element", p, r)
		}
	}
	if _, _, ok := SplitPathVersion(p); !ok {
		return fmt.Errorf("malformed module path %q: invalid version", p)
	}
	return nil
}

// CheckImportPath checks that an import path is valid.
func CheckImportPath(p string) error {
	if err := checkPath(p, kindImport); err != nil {
		return fmt.Errorf("malformed import path %q: %v", p, err)
	}
	return nil
}

func checkPath(p string, kind int) error {
	if !utf8.ValidString(p) {
		return errors.New("invalid UTF-8")
	}
	if p == "" {
		return errors.New("empty string")
	}
	if p[0] == '-' && kind != kindFile {
		return errors.New("leading dash")
	}
	if strings.Contains(p, "//") {
		return errors.New("double slash")
	}
	if p[len(p)-1] == '/' {
		return errors.New("trailing slash")
	}
	elemStart := 0
	for i, r := range p {
		if r == '/' {
			if err := checkElem(p[elemStart:i], kind); err != nil {
				return err
			}
			elemStart = i + 1
		}
	}
	return checkElem(p[elemStart:], kind)
}

func checkElem(elem string, kind int) error {
	if elem == "" {
		return errors.New("empty path element")
	}
	if strings.Count(elem, ".") == len(elem) {
		return fmt.Errorf("invalid path element %q", elem)
	}
	if elem[0] == '.' && kind == kindModule {
		return errors.New("leading dot in path element")
	}
	if elem[len(elem)-1] == '.' {
		return errors.New("trailing dot in path element")
	}
	for _, r := range elem {
		ok := false
		switch kind {
		case kindModule:
			ok = modPathOK(r)
		case kindImport:
			ok = importPathOK(r)
		case kindFile:
			ok = fileNameOK(r)
		}
		if !ok {
			return fmt.Errorf("invalid char %q", r)
		}
	}
	short := elem
	if i := strings.Index(short, "."); i >= 0 {
		short = short[:i]
	}
	for _, bad := range badWindowsNames {
		if strings.EqualFold(bad, short) {
			return fmt.Errorf("%q disallowed as path element component on Windows", short)
		}
	}
	if kind == kindFile {
		return nil
	}
	if i := strings.LastIndex(short, "~"); i >= 0 && i < len(short)-1 {
		suffix := short[i+1:]
		allDigits := true
		for j := 0; j < len(suffix); j++ {
			if suffix[j] < '0' || suffix[j] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return fmt.Errorf("trailing tilde and digits in path element")
		}
	}
	return nil
}

var badWindowsNames = []string{
	"CON", "PRN", "AUX", "NUL",
	"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
	"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}

func firstPathOK(r rune) bool {
	return r == '-' || r == '.' || '0' <= r && r <= '9' || 'a' <= r && r <= 'z'
}

func modPathOK(r rune) bool {
	if r < utf8.RuneSelf {
		return r == '-' || r == '.' || r == '_' || r == '~' ||
			'0' <= r && r <= '9' || 'A' <= r && r <= 'Z' || 'a' <= r && r <= 'z'
	}
	return false
}

func importPathOK(r rune) bool { return modPathOK(r) || r == '+' }

func fileNameOK(r rune) bool {
	if r < utf8.RuneSelf {
		const allowed = "!#$%&()+,-.=@[]^_{}~ "
		if '0' <= r && r <= '9' || 'A' <= r && r <= 'Z' || 'a' <= r && r <= 'z' {
			return true
		}
		return strings.ContainsRune(allowed, r)
	}
	return unicode.IsLetter(r)
}

// SplitPathVersion splits a module path into prefix and major-version
// suffix ("/v2" or ".v2" for gopkg.in). ok is false for malformed suffixes
// such as "/v1" or "/v0".
func SplitPathVersion(p string) (prefix, pathMajor string, ok bool) {
	if strings.HasPrefix(p, "gopkg.in/") {
		return splitGopkgIn(p)
	}
	i := len(p)
	dot := false
	for i > 0 && ('0' <= p[i-1] && p[i-1] <= '9' || p[i-1] == '.') {
		if p[i-1] == '.' {
			dot = true
		}
		i--
	}
	if i <= 1 || i == len(p) || p[i-1] != 'v' || p[i-2] != '/' {
		return p, "", true
	}
	prefix, pathMajor = p[:i-2], p[i-2:]
	if dot || len(pathMajor) <= 2 || pathMajor[2] == '0' || pathMajor == "/v1" {
		return p, "", false
	}
	return prefix, pathMajor, true
}

func splitGopkgIn(p string) (prefix, pathMajor string, ok bool) {
	if !strings.HasPrefix(p, "gopkg.in/") {
		return p, "", false
	}
	i := len(p)
	if strings.HasSuffix(p, "-unstable") {
		i -= len("-unstable")
	}
	for i > 0 && ('0' <= p[i-1] && p[i-1] <= '9') {
		i--
	}
	if i <= 1 || p[i-1] != 'v' || p[i-2] != '.' {
		return p, "", false
	}
	prefix, pathMajor = p[:i-2], p[i-2:]
	if len(pathMajor) <= 2 || pathMajor[2] == '0' && pathMajor != ".v0" {
		return p, "", false
	}
	return prefix, pathMajor, true
}

// MatchPathMajor reports whether version v is allowed for a module path
// with the given major-version suffix.
func MatchPathMajor(v, pathMajor string) bool { return CheckPathMajor(v, pathMajor) == nil }

// CheckPathMajor returns an error if v is not allowed for pathMajor.
func CheckPathMajor(v, pathMajor string) error {
	if strings.HasPrefix(pathMajor, ".v") && strings.HasSuffix(pathMajor, "-unstable") {
		pathMajor = strings.TrimSuffix(pathMajor, "-unstable")
	}
	if strings.HasPrefix(v, "v0.0.0-") && pathMajor == ".v1" {
		return nil
	}
	m := semver.Major(v)
	if pathMajor == "" {
		if m == "v0" || m == "v1" || semver.Build(v) == "+incompatible" {
			return nil
		}
		pathMajor = "v0 or v1"
	} else if pathMajor[0] == '/' || pathMajor[0] == '.' {
		if m == pathMajor[1:] {
			return nil
		}
		pathMajor = pathMajor[1:]
	}
	return fmt.Errorf("version %s does not match path major %s", v, pathMajor)
}

// PathMajorPrefix returns "v2" for "/v2" or ".v2" (and ".v2-unstable").
func PathMajorPrefix(pathMajor string) string {
	if pathMajor == "" {
		return ""
	}
	if pathMajor[0] != '/' && pathMajor[0] != '.' {
		return ""
	}
	pathMajor = strings.TrimSuffix(pathMajor, "-unstable")
	m := pathMajor[1:]
	if m != semver.Major(m) {
		return ""
	}
	return m
}

// MajorOf returns the major version implied by a module path: "v1" when
// there is no suffix, otherwise the suffix's major ("v2", "v3", ...).
func MajorOf(modPath string) string {
	_, pm, ok := SplitPathVersion(modPath)
	if !ok || pm == "" {
		return "v1"
	}
	if m := PathMajorPrefix(pm); m != "" {
		return m
	}
	return "v1"
}

// WithMajor returns the module path for major version major ("v1", "v2", ...)
// of the module family that modPath belongs to.
func WithMajor(modPath, major string) string {
	prefix, pm, ok := SplitPathVersion(modPath)
	if !ok {
		prefix = modPath
	}
	if strings.HasPrefix(modPath, "gopkg.in/") {
		suf := ""
		if strings.HasSuffix(pm, "-unstable") {
			suf = "-unstable"
		}
		return prefix + "." + major + suf
	}
	if major == "v0" || major == "v1" {
		return prefix
	}
	return prefix + "/" + major
}

// EscapePath returns the case-encoded form of a module path used in proxy
// URLs and the module cache: uppercase letters become "!" + lowercase.
func EscapePath(p string) (string, error) {
	if err := CheckPath(p); err != nil {
		return "", err
	}
	return escapeString(p)
}

// EscapeVersion returns the case-encoded form of a version.
func EscapeVersion(v string) (string, error) {
	if err := checkElem(v, kindFile); err != nil || strings.Contains(v, "!") {
		return "", fmt.Errorf("disallowed version string %q", v)
	}
	return escapeString(v)
}

func escapeString(s string) (string, error) {
	haveUpper := false
	for _, r := range s {
		if r == '!' || r >= utf8.RuneSelf {
			return "", errors.New("internal error: inconsistency in EscapePath")
		}
		if 'A' <= r && r <= 'Z' {
			haveUpper = true
		}
	}
	if !haveUpper {
		return s, nil
	}
	var buf []byte
	for _, r := range s {
		if 'A' <= r && r <= 'Z' {
			buf = append(buf, '!', byte(r+'a'-'A'))
		} else {
			buf = append(buf, byte(r))
		}
	}
	return string(buf), nil
}

// UnescapePath reverses EscapePath.
func UnescapePath(escaped string) (string, error) {
	p, ok := unescapeString(escaped)
	if !ok {
		return "", fmt.Errorf("invalid escaped module path %q", escaped)
	}
	if err := CheckPath(p); err != nil {
		return "", fmt.Errorf("invalid escaped module path %q: %v", escaped, err)
	}
	return p, nil
}

// UnescapeVersion reverses EscapeVersion.
func UnescapeVersion(escaped string) (string, error) {
	v, ok := unescapeString(escaped)
	if !ok {
		return "", fmt.Errorf("invalid escaped version %q", escaped)
	}
	if err := checkElem(v, kindFile); err != nil {
		return "", fmt.Errorf("invalid escaped version %q: %v", v, err)
	}
	return v, nil
}

func unescapeString(escaped string) (string, bool) {
	var buf []byte
	bang := false
	for _, r := range escaped {
		if r >= utf8.RuneSelf {
			return "", false
		}
		if bang {
			bang = false
			if r < 'a' || 'z' < r {
				return "", false
			}
			buf = append(buf, byte(r+'A'-'a'))
			continue
		}
		if r == '!' {
			bang = true
			continue
		}
		if 'A' <= r && r <= 'Z' {
			return "", false
		}
		buf = append(buf, byte(r))
	}
	if bang {
		return "", false
	}
	return string(buf), true
}

// MatchPrefixPatterns reports whether any glob in the comma-separated list
// matches a prefix of target (the GOPRIVATE / GONOPROXY / GONOSUMDB rule).
func MatchPrefixPatterns(globs, target string) bool {
	for globs != "" {
		var glob string
		if i := strings.Index(globs, ","); i >= 0 {
			glob, globs = globs[:i], globs[i+1:]
		} else {
			glob, globs = globs, ""
		}
		glob = strings.TrimSuffix(glob, "/")
		if glob == "" {
			continue
		}
		n := strings.Count(glob, "/")
		prefix := target
		for i := 0; i < len(target); i++ {
			if target[i] == '/' {
				if n == 0 {
					prefix = target[:i]
					break
				}
				n--
			}
		}
		if n > 0 {
			continue
		}
		if matched, _ := path.Match(glob, prefix); matched {
			return true
		}
	}
	return false
}

var pseudoVersionRE = regexp.MustCompile(`^v[0-9]+\.(0\.0-|\d+\.\d+-([^+]*\.)?0\.)\d{14}-[A-Za-z0-9]+(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

// IsPseudoVersion reports whether v is a pseudo-version.
func IsPseudoVersion(v string) bool {
	return strings.Count(v, "-") >= 2 && semver.IsValid(v) && pseudoVersionRE.MatchString(v)
}

// IsZeroPseudoVersion reports whether v is the zero pseudo-version of its
// major version ("vX.0.0-00010101000000-000000000000"), which the go
// command uses for placeholder requirements.
func IsZeroPseudoVersion(v string) bool {
	return v == semver.Major(v)+".0.0-00010101000000-000000000000"
}

// PseudoHasNoBase reports whether v is a pseudo-version not derived from
// any tag (vX.0.0-yyyymmddhhmmss-abcdef123456).
func PseudoHasNoBase(v string) bool {
	if !IsPseudoVersion(v) {
		return false
	}
	base, err := PseudoVersionBase(v)
	return err == nil && base == ""
}

// PseudoVersionTime returns the commit time encoded in a pseudo-version.
func PseudoVersionTime(v string) (time.Time, error) {
	_, timestamp, _, _, err := parsePseudoVersion(v)
	if err != nil {
		return time.Time{}, err
	}
	t, err := time.Parse("20060102150405", timestamp)
	if err != nil {
		return time.Time{}, fmt.Errorf("malformed time %q", timestamp)
	}
	return t, nil
}

// PseudoVersionRev returns the revision identifier of a pseudo-version.
func PseudoVersionRev(v string) (string, error) {
	_, _, rev, _, err := parsePseudoVersion(v)
	return rev, err
}

// PseudoVersionBase returns the canonical version the pseudo-version is
// derived from ("" for vX.0.0-... pseudo-versions with no base tag).
func PseudoVersionBase(v string) (string, error) {
	base, _, _, build, err := parsePseudoVersion(v)
	if err != nil {
		return "", err
	}
	switch pre := semver.Prerelease(base); pre {
	case "":
		if build != "" {
			return "", fmt.Errorf("pseudo-version %q has build metadata but no prerelease", v)
		}
		return "", nil
	case "-0":
		base = strings.TrimSuffix(base, pre)
		i := strings.LastIndexByte(base, '.')
		if i < 0 {
			return "", fmt.Errorf("malformed pseudo-version %q", v)
		}
		minor := base[:i+1]
		patch := base[i+1:]
		dec, ok := decDecimal(patch)
		if !ok {
			return "", fmt.Errorf("malformed pseudo-version %q", v)
		}
		base = minor + dec
	default:
		if !strings.HasSuffix(base, ".0") {
			return "", fmt.Errorf("malformed pseudo-version %q", v)
		}
		base = strings.TrimSuffix(base, ".0")
	}
	return base + build, nil
}

func parsePseudoVersion(v string) (base, timestamp, rev, build string, err error) {
	if !IsPseudoVersion(v) {
		return "", "", "", "", fmt.Errorf("%q is not a pseudo-version", v)
	}
	build = semver.Build(v)
	v = strings.TrimSuffix(v, build)
	j := strings.LastIndex(v, "-")
	v, rev = v[:j], v[j+1:]
	i := strings.LastIndex(v, "-")
	if j := strings.LastIndex(v, "."); j > i {
		base = v[:j] // "vX.Y.Z-pre.0" or "vX.Y.(Z+1)-0"
		timestamp = v[j+1:]
	} else {
		base = v[:i] // "vX.0.0"
		timestamp = v[i+1:]
	}
	return base, timestamp, rev, build, nil
}

func decDecimal(decimal string) (string, bool) {
	if len(decimal) == 0 {
		return "", false
	}
	if decimal == "0" {
		return "", false
	}
	b := []byte(decimal)
	i := len(b) - 1
	for ; i >= 0 && b[i] == '0'; i-- {
		b[i] = '9'
	}
	if i < 0 {
		return "", false
	}
	b[i]--
	if b[i] == '0' && i == 0 && len(b) > 1 {
		b = b[1:]
	}
	return string(b), true
}
