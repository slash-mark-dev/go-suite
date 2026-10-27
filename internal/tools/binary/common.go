package binary

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/binfile"
	"github.com/slash-mark-dev/go-suite/internal/cli"
)

const group = "Binary intelligence"

// skipped is an argument (or file found in a directory) that could not be
// analysed.
type skipped struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// resolve makes a command-line path relative to -C.
func resolve(c *cli.Context, p string) string {
	if filepath.IsAbs(p) || c.G.Dir == "" {
		return p
	}
	return filepath.Join(c.G.Dir, p)
}

// collectBinaries expands files and directories (searched recursively,
// skipping hidden directories) into Go executables. Files named
// explicitly that are not Go binaries are reported as skipped; a path
// that does not exist is a usage error.
func collectBinaries(c *cli.Context, args []string) ([]string, []skipped, error) {
	var out []string
	var skip []skipped
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, a := range args {
		p := resolve(c, a)
		fi, err := os.Stat(p)
		if err != nil {
			return nil, nil, cli.Usagef("%s: no such file or directory", a)
		}
		if !fi.IsDir() {
			if err := checkGoBinary(p); err != nil {
				skip = append(skip, skipped{Path: p, Reason: err.Error()})
				continue
			}
			add(p)
			continue
		}
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				skip = append(skip, skipped{Path: path, Reason: err.Error()})
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if path != p && (strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules") {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			if checkGoBinary(path) == nil {
				add(path)
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}
	return out, skip, nil
}

// checkGoBinary cheaply checks the executable magic before reading the
// build information.
func checkGoBinary(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	var magic [4]byte
	_, err = io.ReadFull(f, magic[:])
	f.Close()
	if err != nil || !isExecMagic(magic[:]) {
		return binfile.ErrFormat
	}
	if !binfile.IsGoBinary(path) {
		return binfile.ErrNotGo
	}
	return nil
}

func isExecMagic(m []byte) bool {
	switch {
	case bytes.Equal(m, []byte("\x7fELF")), m[0] == 'M' && m[1] == 'Z':
		return true
	}
	for _, v := range [][]byte{
		{0xfe, 0xed, 0xfa, 0xce}, {0xce, 0xfa, 0xed, 0xfe}, // 32-bit
		{0xfe, 0xed, 0xfa, 0xcf}, {0xcf, 0xfa, 0xed, 0xfe}, // 64-bit
		{0xca, 0xfe, 0xba, 0xbe}, // universal
	} {
		if bytes.Equal(m, v) {
			return true
		}
	}
	return false
}

// openBinary opens a binary named on the command line, turning format
// problems into usage errors.
func openBinary(c *cli.Context, arg string) (*binfile.File, error) {
	p := resolve(c, arg)
	fi, err := os.Stat(p)
	if err != nil {
		return nil, cli.Usagef("%s: no such file", arg)
	}
	if fi.IsDir() {
		return nil, cli.Usagef("%s is a directory; pass a Go executable", arg)
	}
	f, err := binfile.Open(p)
	if err != nil {
		if errors.Is(err, binfile.ErrNotGo) || errors.Is(err, binfile.ErrFormat) {
			return nil, cli.Usagef("%s: %v", arg, err)
		}
		return nil, err
	}
	return f, nil
}

// parseSize parses "12345", "512K", "10MB", "1.5MiB" (binary units).
func parseSize(s string) (int64, error) {
	t := strings.ToUpper(strings.TrimSpace(s))
	t = strings.TrimSuffix(strings.TrimSuffix(t, "IB"), "B")
	mult := 1.0
	if t != "" {
		switch t[len(t)-1] {
		case 'K':
			mult = 1 << 10
		case 'M':
			mult = 1 << 20
		case 'G':
			mult = 1 << 30
		}
		if mult != 1 {
			t = t[:len(t)-1]
		}
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("invalid size %q (use e.g. 25MB, 512KB or a byte count)", s)
	}
	return int64(f * mult), nil
}

// sortedKeys returns the keys of m in order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// relPath shortens p for display relative to the working directory.
func relPath(c *cli.Context, p string) string {
	base, err := filepath.Abs(c.Dir())
	if err != nil {
		return p
	}
	if a, err := filepath.Abs(p); err == nil {
		p = a
	}
	if r, err := filepath.Rel(base, p); err == nil && !strings.HasPrefix(r, "..") {
		return r
	}
	return p
}
