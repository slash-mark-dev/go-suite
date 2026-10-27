// Command annotate reads `go test -json` output on standard input, prints
// it as ordinary `go test` output, and reports every failed test as a
// GitHub Actions error annotation, so failures are readable on the run's
// page and through the public checks API without downloading the logs.
//
// Usage (bash, with pipefail so go test's exit status is kept):
//
//	set -o pipefail
//	go test -json ./... 2>&1 | go run .github/ci/annotate.go
//
// It exits 1 when any test or package failed, 0 otherwise.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

type event struct {
	Action     string
	Package    string
	ImportPath string // build-output and build-fail events (Go 1.24+)
	Test       string
	Output     string
}

type failure struct {
	pkg, test string
	output    []string
}

const (
	modulePrefix = "github.com/slash-mark-dev/go-suite/"
	maxPerTest   = 6000 // bytes of output kept in one annotation
	maxNotes     = 9    // GitHub shows 10 error annotations per step
)

var fileLine = regexp.MustCompile(`^\s*([\w./-]+_test\.go|[\w./-]+\.go):(\d+):`)

func main() {
	outputs := map[string][]string{} // pkg + "\x00" + test -> output lines
	failed := map[string]bool{}
	var order []string
	var stray []string // lines that are not JSON (build errors before Go 1.24)
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		line := sc.Text()
		var ev event
		if !strings.HasPrefix(line, "{") || json.Unmarshal([]byte(line), &ev) != nil {
			fmt.Println(line)
			stray = append(stray, line)
			continue
		}
		pkg := ev.Package
		if pkg == "" {
			// "example.com/p [example.com/p.test]" is p's test binary.
			pkg, _, _ = strings.Cut(ev.ImportPath, " [")
		}
		key := pkg + "\x00" + ev.Test
		switch ev.Action {
		case "output", "build-output":
			fmt.Print(ev.Output)
			if _, ok := outputs[key]; !ok {
				order = append(order, key)
			}
			outputs[key] = append(outputs[key], strings.TrimRight(ev.Output, "\n"))
		case "fail", "build-fail":
			failed[key] = true
			if _, ok := outputs[key]; !ok {
				order = append(order, key)
				outputs[key] = nil
			}
		}
	}

	// Report the most specific failures: a test whose subtests failed
	// fails too, and a package fails when any of its tests do.
	var fails []failure
	for _, key := range order {
		if !failed[key] {
			continue
		}
		pkg, test, _ := strings.Cut(key, "\x00")
		covered := false
		for other := range failed {
			opkg, otest, _ := strings.Cut(other, "\x00")
			if other != key && opkg == pkg && (test == "" && otest != "" || otest != test && strings.HasPrefix(otest, test+"/")) {
				covered = true
				break
			}
		}
		if !covered {
			fails = append(fails, failure{pkg, test, outputs[key]})
		}
	}
	if len(fails) == 0 && len(stray) > 0 && len(failed) > 0 {
		fails = append(fails, failure{"", "", stray})
	}
	sort.SliceStable(fails, func(i, j int) bool { return fails[i].pkg < fails[j].pkg })

	for i, f := range fails {
		if i == maxNotes && len(fails) > maxNotes {
			var names []string
			for _, g := range fails[maxNotes:] {
				names = append(names, name(g))
			}
			fmt.Printf("::error title=%s::%s\n", escapeProp(fmt.Sprintf("%d more failures", len(names))), escape(strings.Join(names, "\n")))
			break
		}
		var keep []string
		file, lineNo := "", ""
		for _, l := range f.output {
			t := strings.TrimSpace(l)
			if t == "" || strings.HasPrefix(t, "=== ") || strings.HasPrefix(t, "--- PASS") {
				continue
			}
			if file == "" {
				if m := fileLine.FindStringSubmatch(l); m != nil {
					file, lineNo = m[1], m[2]
					if !strings.Contains(file, "/") && strings.HasPrefix(f.pkg, modulePrefix) {
						file = strings.TrimPrefix(f.pkg, modulePrefix) + "/" + file
					}
				}
			}
			keep = append(keep, l)
		}
		msg := strings.Join(keep, "\n")
		if len(msg) > maxPerTest {
			msg = msg[:maxPerTest] + "\n… (truncated; see the job log)"
		}
		props := "title=" + escapeProp(name(f))
		if file != "" && strings.Contains(file, "/") && !strings.HasPrefix(file, "/") {
			props = "file=" + escapeProp(file) + ",line=" + lineNo + "," + props
		}
		fmt.Printf("::error %s::%s\n", props, escape(msg))
	}
	if len(failed) > 0 {
		os.Exit(1)
	}
}

func name(f failure) string {
	pkg := strings.TrimPrefix(f.pkg, modulePrefix)
	switch {
	case f.test != "":
		return f.test + " (" + pkg + ")"
	case pkg != "":
		return pkg
	}
	return "go test"
}

// escape and escapeProp encode workflow command data and properties.
func escape(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

func escapeProp(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
}
