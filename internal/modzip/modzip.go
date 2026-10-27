// Package modzip reads module zip files and computes the "h1:" hashes
// recorded in go.sum (golang.org/x/mod/sumdb/dirhash Hash1).
package modzip

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Hash1 computes the h1 hash of a set of named files.
func Hash1(files []string, open func(string) (io.ReadCloser, error)) (string, error) {
	h := sha256.New()
	files = append([]string(nil), files...)
	sort.Strings(files)
	for _, file := range files {
		if strings.Contains(file, "\n") {
			return "", errors.New("dirhash: filenames with newlines are not supported")
		}
		r, err := open(file)
		if err != nil {
			return "", err
		}
		hf := sha256.New()
		_, err = io.Copy(hf, r)
		r.Close()
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%x  %s\n", hf.Sum(nil), file)
	}
	return "h1:" + base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// HashGoMod returns the go.sum "/go.mod" hash of go.mod content.
func HashGoMod(data []byte) string {
	h, _ := Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	return h
}

// HashZip returns the go.sum hash of a module zip.
func HashZip(data []byte) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", err
	}
	var files []string
	byName := map[string]*zip.File{}
	for _, f := range zr.File {
		files = append(files, f.Name)
		byName[f.Name] = f
	}
	return Hash1(files, func(name string) (io.ReadCloser, error) { return byName[name].Open() })
}

// HashDir hashes the files in dir as if zipped with the given prefix
// ("path@version"), the way the go command verifies an extracted module.
func HashDir(dir, prefix string) (string, error) {
	var files []string
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			rel, _ := filepath.Rel(dir, p)
			files = append(files, filepath.ToSlash(filepath.Join(prefix, rel)))
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return Hash1(files, func(name string) (io.ReadCloser, error) {
		rel := strings.TrimPrefix(name, prefix+"/")
		return os.Open(filepath.Join(dir, filepath.FromSlash(rel)))
	})
}

// Zip is an opened module zip.
type Zip struct {
	Prefix string // "path@version/"
	files  map[string]*zip.File
	names  []string
	Size   int64
}

// Open opens module zip data. Entries outside "path@version/" are
// reported as errors.
func Open(data []byte, path, version string) (*Zip, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	z := &Zip{Prefix: path + "@" + version + "/", files: map[string]*zip.File{}, Size: int64(len(data))}
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, z.Prefix) {
			return nil, fmt.Errorf("zip entry %q is outside %s", f.Name, z.Prefix)
		}
		rel := strings.TrimPrefix(f.Name, z.Prefix)
		if rel == "" || strings.HasSuffix(rel, "/") {
			continue
		}
		z.files[rel] = f
		z.names = append(z.names, rel)
	}
	sort.Strings(z.names)
	return z, nil
}

// Files returns the file names relative to the module root, sorted.
func (z *Zip) Files() []string { return z.names }

// Has reports whether the zip contains name.
func (z *Zip) Has(name string) bool { _, ok := z.files[name]; return ok }

// FileSize returns the uncompressed size of name.
func (z *Zip) FileSize(name string) int64 {
	if f, ok := z.files[name]; ok {
		return int64(f.UncompressedSize64)
	}
	return 0
}

// ReadFile returns the content of name (limited to 64 MiB).
func (z *Zip) ReadFile(name string) ([]byte, error) {
	f, ok := z.files[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	r, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, 64<<20))
}

// Extract writes the zip to dir (which must not exist or be empty).
func (z *Zip) Extract(dir string) error {
	for _, name := range z.names {
		if strings.Contains(name, "..") {
			return fmt.Errorf("unsafe zip entry %q", name)
		}
		dst := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		data, err := z.ReadFile(name)
		if err != nil {
			return err
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// Create builds a module zip from files (name relative to module root ->
// content). Used by tests and the release checker.
func Create(path, version string, files map[string][]byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		w, err := zw.Create(path + "@" + version + "/" + n)
		if err != nil {
			return nil, err
		}
		w.Write(files[n])
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
