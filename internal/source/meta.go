package source

import (
	"html"
	"strings"
)

// ParseMeta extracts go-import and go-source meta tags from an HTML page.
// Like the go command it stops at <body> or </head>, tolerates sloppy
// markup (unquoted or single-quoted attributes, upper-case names, missing
// <head>), skips comments, scripts and styles, and decodes HTML entities.
func ParseMeta(page string) (imports []GoImport, sources []GoSource) {
	for i := 0; i < len(page); {
		lt := strings.IndexByte(page[i:], '<')
		if lt < 0 {
			break
		}
		i += lt
		if strings.HasPrefix(page[i:], "<!--") {
			end := strings.Index(page[i+4:], "-->")
			if end < 0 {
				break
			}
			i += 4 + end + 3
			continue
		}
		name, attrs, next := parseTag(page, i)
		i = next
		switch name {
		case "body", "/head":
			return
		case "script", "style":
			end := strings.Index(strings.ToLower(page[i:]), "</"+name)
			if end < 0 {
				return
			}
			i += end
		case "meta":
			metaName := strings.ToLower(attrs["name"])
			content := strings.Join(strings.Fields(attrs["content"]), " ")
			f := strings.Fields(content)
			switch metaName {
			case "go-import":
				if len(f) == 3 || len(f) == 4 {
					im := GoImport{Prefix: f[0], VCS: f[1], Repo: f[2]}
					if len(f) == 4 {
						im.Subdir = f[3]
					}
					imports = append(imports, im)
				}
			case "go-source":
				if len(f) >= 1 {
					s := GoSource{Prefix: f[0]}
					if len(f) > 1 {
						s.Home = f[1]
					}
					if len(f) > 2 {
						s.Dir = f[2]
					}
					if len(f) > 3 {
						s.File = f[3]
					}
					sources = append(sources, s)
				}
			}
		}
	}
	return
}

// parseTag parses the tag starting at page[i] == '<' and returns its
// lower-cased name ("/head" for end tags), attributes (names lower-cased,
// values entity-decoded) and the index just past '>'.
func parseTag(page string, i int) (string, map[string]string, int) {
	j := i + 1
	start := j
	for j < len(page) && !isSpace(page[j]) && page[j] != '>' && !(page[j] == '/' && j > start) {
		j++
	}
	name := strings.ToLower(page[start:j])
	attrs := map[string]string{}
	for j < len(page) {
		for j < len(page) && (isSpace(page[j]) || page[j] == '/') {
			j++
		}
		if j >= len(page) {
			break
		}
		if page[j] == '>' {
			return name, attrs, j + 1
		}
		ks := j
		for j < len(page) && !isSpace(page[j]) && page[j] != '=' && page[j] != '>' && page[j] != '/' {
			j++
		}
		key := strings.ToLower(page[ks:j])
		for j < len(page) && isSpace(page[j]) {
			j++
		}
		val := ""
		if j < len(page) && page[j] == '=' {
			j++
			for j < len(page) && isSpace(page[j]) {
				j++
			}
			if j < len(page) && (page[j] == '"' || page[j] == '\'') {
				q := page[j]
				end := strings.IndexByte(page[j+1:], q)
				if end < 0 {
					val, j = page[j+1:], len(page)
				} else {
					val, j = page[j+1:j+1+end], j+1+end+1
				}
			} else {
				vs := j
				for j < len(page) && !isSpace(page[j]) && page[j] != '>' {
					j++
				}
				val = page[vs:j]
			}
		}
		if key != "" {
			if _, dup := attrs[key]; !dup {
				attrs[key] = html.UnescapeString(val)
			}
		} else if j < len(page) && page[j] != '>' {
			j++ // skip a stray character
		}
	}
	return name, attrs, len(page)
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f' }
