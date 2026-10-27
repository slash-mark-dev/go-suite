package modfile

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// physLine is one physical line of a go.mod/go.work file after lexing.
type physLine struct {
	num     int
	tokens  []string
	comment string // "// ..." text if the line has a comment
	blank   bool   // no tokens and no comment
}

func isIdentRune(r rune) bool {
	switch r {
	case ' ', '(', ')', '[', ']', '{', '}', ',':
		return false
	}
	return !unicode.IsSpace(r) && unicode.IsPrint(r)
}

// lexLines splits data into physical lines of tokens. Strings are unquoted.
func lexLines(data []byte) ([]physLine, []error) {
	var lines []physLine
	var errs []error
	text := string(data)
	text = strings.TrimPrefix(text, "\ufeff")
	num := 0
	for len(text) > 0 || num == 0 {
		num++
		var line string
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			line, text = text[:i], text[i+1:]
		} else {
			line, text = text, ""
		}
		line = strings.TrimSuffix(line, "\r")
		pl := physLine{num: num}
		s := line
		for len(s) > 0 {
			r, size := utf8.DecodeRuneInString(s)
			switch {
			case unicode.IsSpace(r):
				s = s[size:]
			case strings.HasPrefix(s, "//"):
				pl.comment = strings.TrimRightFunc(s, unicode.IsSpace)
				s = ""
			case strings.HasPrefix(s, "/*"):
				errs = append(errs, fmt.Errorf("line %d: mod files must use // comments, not /* */ comments", num))
				s = ""
			case r == '(' || r == ')' || r == '[' || r == ']' || r == ',' || r == '{' || r == '}':
				pl.tokens = append(pl.tokens, string(r))
				s = s[size:]
			case r == '"':
				end := 1
				for end < len(s) {
					if s[end] == '\\' && end+1 < len(s) {
						end += 2
						continue
					}
					if s[end] == '"' {
						break
					}
					end++
				}
				if end >= len(s) {
					errs = append(errs, fmt.Errorf("line %d: unterminated quoted string", num))
					s = ""
					continue
				}
				u, err := strconv.Unquote(s[:end+1])
				if err != nil {
					errs = append(errs, fmt.Errorf("line %d: invalid quoted string %s", num, s[:end+1]))
					u = s[1:end]
				}
				pl.tokens = append(pl.tokens, quoteMark+u)
				s = s[end+1:]
			case r == '`':
				end := strings.IndexByte(s[1:], '`')
				if end < 0 {
					errs = append(errs, fmt.Errorf("line %d: unterminated raw string", num))
					s = ""
					continue
				}
				pl.tokens = append(pl.tokens, quoteMark+s[1:end+1])
				s = s[end+2:]
			default:
				i := 0
				for i < len(s) {
					r, sz := utf8.DecodeRuneInString(s[i:])
					if !isIdentRune(r) || strings.HasPrefix(s[i:], "//") {
						break
					}
					i += sz
				}
				if i == 0 {
					errs = append(errs, fmt.Errorf("line %d: unexpected input character %q", num, r))
					s = s[size:]
					continue
				}
				pl.tokens = append(pl.tokens, s[:i])
				s = s[i:]
			}
		}
		pl.blank = len(pl.tokens) == 0 && pl.comment == ""
		lines = append(lines, pl)
		if text == "" {
			break
		}
	}
	return lines, errs
}

// quoteMark prefixes tokens that came from quoted strings so that
// punctuation such as "(" inside quotes is not treated as syntax.
const quoteMark = "\x00"

func tokVal(t string) string { return strings.TrimPrefix(t, quoteMark) }

func isQuoted(t string) bool { return strings.HasPrefix(t, quoteMark) }

// stmt is a logical statement: a verb and its arguments.
type stmt struct {
	verb     string
	args     []string // raw tokens, may carry quoteMark
	line     int
	before   []string // comment lines immediately before
	suffix   string   // trailing comment on the same line
	inBlock  bool
	blockCom []string // comments before the block opener + its suffix
}

// parseStmts groups physical lines into statements, expanding blocks.
func parseStmts(lines []physLine) ([]stmt, []error) {
	var out []stmt
	var errs []error
	var pending []string
	for i := 0; i < len(lines); i++ {
		pl := lines[i]
		if pl.blank {
			pending = nil
			continue
		}
		if len(pl.tokens) == 0 { // comment-only line
			pending = append(pending, pl.comment)
			continue
		}
		toks := pl.tokens
		verb := toks[0]
		if isQuoted(verb) || verb == "(" || verb == ")" {
			errs = append(errs, fmt.Errorf("line %d: unexpected %q", pl.num, tokVal(verb)))
			pending = nil
			continue
		}
		// Block forms: "verb (" ... ")" or "verb ( )" on one line.
		if len(toks) >= 2 && toks[1] == "(" && !isQuoted(toks[1]) {
			blockCom := append([]string{}, pending...)
			if pl.comment != "" {
				blockCom = append(blockCom, pl.comment)
			}
			pending = nil
			if len(toks) == 3 && toks[2] == ")" {
				continue // empty block
			}
			if len(toks) > 2 {
				errs = append(errs, fmt.Errorf("line %d: syntax error (unterminated block started on same line)", pl.num))
				continue
			}
			var inner []string
			closed := false
			for i++; i < len(lines); i++ {
				bl := lines[i]
				if bl.blank {
					inner = nil
					continue
				}
				if len(bl.tokens) == 0 {
					inner = append(inner, bl.comment)
					continue
				}
				if len(bl.tokens) == 1 && bl.tokens[0] == ")" {
					closed = true
					break
				}
				out = append(out, stmt{verb: verb, args: bl.tokens, line: bl.num, before: inner,
					suffix: bl.comment, inBlock: true, blockCom: blockCom})
				inner = nil
			}
			if !closed {
				errs = append(errs, fmt.Errorf("line %d: unterminated block", pl.num))
			}
			continue
		}
		out = append(out, stmt{verb: verb, args: toks[1:], line: pl.num, before: pending, suffix: pl.comment})
		pending = nil
	}
	return out, errs
}

// directiveComment joins the comments attached to a statement, following
// the x/mod rules used for "Deprecated:" and retraction rationales.
func (s stmt) directiveComment() string {
	coms := append([]string{}, s.before...)
	if s.suffix != "" {
		coms = append(coms, s.suffix)
	}
	if s.inBlock && len(coms) == 0 {
		coms = s.blockCom
	}
	var lines []string
	for _, c := range coms {
		if !strings.HasPrefix(c, "//") {
			continue
		}
		lines = append(lines, strings.TrimSpace(strings.TrimPrefix(c, "//")))
	}
	return strings.Join(lines, "\n")
}
