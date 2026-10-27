// Package report defines the shared finding model: severities and a
// generic finding record that most tools emit.
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Severity orders findings.
type Severity int

const (
	None Severity = iota
	Info
	Low
	Medium
	High
	Critical
)

var sevNames = [...]string{"none", "info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(sevNames) {
		return "unknown"
	}
	return sevNames[s]
}

// MarshalJSON encodes the severity as its name.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// UnmarshalJSON decodes a severity name.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	v, err := ParseSeverity(str)
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// ParseSeverity parses "low", "medium", "high", "critical", "info",
// "none" (case-insensitive; "moderate" is accepted for medium).
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "none", "off", "never":
		return None, nil
	case "info", "informational":
		return Info, nil
	case "low":
		return Low, nil
	case "medium", "moderate":
		return Medium, nil
	case "high":
		return High, nil
	case "critical":
		return Critical, nil
	}
	return None, fmt.Errorf("unknown severity %q (use info, low, medium, high or critical)", s)
}

// Finding is a generic issue record.
type Finding struct {
	Severity Severity       `json:"severity"`
	Rule     string         `json:"rule"`
	Module   string         `json:"module,omitempty"`
	Version  string         `json:"version,omitempty"`
	Package  string         `json:"package,omitempty"`
	File     string         `json:"file,omitempty"`
	Line     int            `json:"line,omitempty"`
	Title    string         `json:"title"`
	Detail   string         `json:"detail,omitempty"`
	Fix      string         `json:"fix,omitempty"`
	URL      string         `json:"url,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
}

// Where returns "module@version" or "file:line" for display.
func (f Finding) Where() string {
	switch {
	case f.File != "" && f.Line > 0:
		return fmt.Sprintf("%s:%d", f.File, f.Line)
	case f.File != "":
		return f.File
	case f.Module != "" && f.Version != "":
		return f.Module + "@" + f.Version
	case f.Package != "":
		return f.Package
	}
	return f.Module
}

// SortFindings orders by severity (highest first), then module, then title.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		if fs[i].Module != fs[j].Module {
			return fs[i].Module < fs[j].Module
		}
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		if fs[i].Line != fs[j].Line {
			return fs[i].Line < fs[j].Line
		}
		return fs[i].Title < fs[j].Title
	})
}

// Max returns the highest severity in fs.
func Max(fs []Finding) Severity {
	m := None
	for _, f := range fs {
		if f.Severity > m {
			m = f.Severity
		}
	}
	return m
}

// Counts tallies findings by severity name.
func Counts(fs []Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f.Severity.String()]++
	}
	return m
}

// Meets reports whether s reaches the threshold min. A threshold of None
// ("none", "off", "never") is never met: --fail-on none never fails a run.
func (s Severity) Meets(min Severity) bool { return min > None && s >= min }

// AtLeast filters findings that meet the threshold min (none for min None).
func AtLeast(fs []Finding, min Severity) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Severity.Meets(min) {
			out = append(out, f)
		}
	}
	return out
}

// CVSSSeverity maps a CVSS base score to a severity.
func CVSSSeverity(score float64) Severity {
	switch {
	case score >= 9:
		return Critical
	case score >= 7:
		return High
	case score >= 4:
		return Medium
	case score > 0:
		return Low
	}
	return None
}
