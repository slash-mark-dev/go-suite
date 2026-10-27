// Package ui renders terminal output: colors (respecting --no-color and
// NO_COLOR), headings, aligned tables, key/value blocks and severity badges.
package ui

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/slash-mark-dev/go-suite/internal/report"
)

// Printer writes styled text.
type Printer struct {
	W     io.Writer
	Color bool
}

const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	dim    = "\x1b[2m"
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	blue   = "\x1b[34m"
	purple = "\x1b[35m"
	cyan   = "\x1b[36m"
)

func (p *Printer) wrap(code, s string) string {
	if !p.Color || s == "" {
		return s
	}
	return code + s + reset
}

func (p *Printer) Bold(s string) string   { return p.wrap(bold, s) }
func (p *Printer) Dim(s string) string    { return p.wrap(dim, s) }
func (p *Printer) Red(s string) string    { return p.wrap(red, s) }
func (p *Printer) Green(s string) string  { return p.wrap(green, s) }
func (p *Printer) Yellow(s string) string { return p.wrap(yellow, s) }
func (p *Printer) Blue(s string) string   { return p.wrap(blue, s) }
func (p *Printer) Cyan(s string) string   { return p.wrap(cyan, s) }
func (p *Printer) Purple(s string) string { return p.wrap(purple, s) }

// Printf writes formatted text.
func (p *Printer) Printf(format string, a ...any) { fmt.Fprintf(p.W, format, a...) }

// Println writes a line.
func (p *Printer) Println(a ...any) { fmt.Fprintln(p.W, a...) }

// Title prints the tool banner line.
func (p *Printer) Title(s string) {
	fmt.Fprintf(p.W, "%s\n", p.Bold(s))
}

// Heading prints a section heading.
func (p *Printer) Heading(s string) {
	fmt.Fprintf(p.W, "\n%s\n", p.Bold(p.Cyan(s)))
}

// Sev returns a colored severity label padded to 8 columns.
func (p *Printer) Sev(s report.Severity) string {
	label := strings.ToUpper(s.String())
	pad := strings.Repeat(" ", max(0, 8-len(label)))
	switch s {
	case report.Critical:
		return p.wrap(bold+red, label) + pad
	case report.High:
		return p.Red(label) + pad
	case report.Medium:
		return p.Yellow(label) + pad
	case report.Low:
		return p.Blue(label) + pad
	default:
		return p.Dim(label) + pad
	}
}

// OK prints a green check line.
func (p *Printer) OK(format string, a ...any) {
	fmt.Fprintf(p.W, "%s %s\n", p.Green("✓"), fmt.Sprintf(format, a...))
}

// Warn prints a yellow warning line.
func (p *Printer) Warn(format string, a ...any) {
	fmt.Fprintf(p.W, "%s %s\n", p.Yellow("!"), fmt.Sprintf(format, a...))
}

// Bad prints a red cross line.
func (p *Printer) Bad(format string, a ...any) {
	fmt.Fprintf(p.W, "%s %s\n", p.Red("✗"), fmt.Sprintf(format, a...))
}

// KV prints aligned key/value pairs.
func (p *Printer) KV(pairs ...[2]string) {
	w := 0
	for _, kv := range pairs {
		if n := utf8.RuneCountInString(kv[0]); n > w {
			w = n
		}
	}
	for _, kv := range pairs {
		fmt.Fprintf(p.W, "  %s%s  %s\n", p.Dim(kv[0]), strings.Repeat(" ", w-utf8.RuneCountInString(kv[0])), kv[1])
	}
}

// Width returns the display width of s, ignoring ANSI escapes.
func Width(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			j := strings.IndexByte(s[i:], 'm')
			if j < 0 {
				break
			}
			i += j + 1
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		n++
		i += size
	}
	return n
}

// Table prints rows with aligned columns. Cells may contain color codes.
// The last column is not padded.
func (p *Printer) Table(header []string, rows [][]string) {
	if len(rows) == 0 {
		return
	}
	cols := len(header)
	for _, r := range rows {
		if len(r) > cols {
			cols = len(r)
		}
	}
	widths := make([]int, cols)
	for i, h := range header {
		widths[i] = Width(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if w := Width(c); w > widths[i] {
				widths[i] = w
			}
		}
	}
	line := func(cells []string, style func(string) string) {
		var b strings.Builder
		b.WriteString("  ")
		for i := 0; i < cols; i++ {
			c := ""
			if i < len(cells) {
				c = cells[i]
			}
			if style != nil {
				c = style(c)
			}
			b.WriteString(c)
			if i < cols-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-Width(c)+2))
			}
		}
		fmt.Fprintln(p.W, strings.TrimRight(b.String(), " "))
	}
	if len(header) > 0 {
		line(header, p.Dim)
	}
	for _, r := range rows {
		line(r, nil)
	}
}

// Truncate shortens s to n display runes with an ellipsis.
func Truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n || n < 2 {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// Plural returns "1 thing" / "2 things".
func Plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// Bar renders a simple proportional bar of width w.
func Bar(frac float64, w int) string {
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	n := int(frac*float64(w) + 0.5)
	return strings.Repeat("█", n) + strings.Repeat("░", w-n)
}

// Bytes formats a byte count (1.2 MB).
func Bytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
