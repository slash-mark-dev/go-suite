package origin_test

import (
	"strings"
	"testing"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

type retractResult struct {
	Subject string `json:"subject"`
	Modules []struct {
		Path       string `json:"path"`
		Version    string `json:"version"`
		Latest     string `json:"latest"`
		Retracted  bool   `json:"retracted"`
		Rationale  string `json:"rationale"`
		Deprecated string `json:"deprecated"`
		Suggest    string `json:"suggest"`
		SuggestDir string `json:"suggestDirection"`
		Retraction *struct {
			Low  string `json:"low"`
			High string `json:"high"`
		} `json:"retraction"`
		Error string `json:"error"`
	} `json:"modules"`
	Findings []finding `json:"findings"`
	Summary  struct {
		Modules    int `json:"modules"`
		Retracted  int `json:"retracted"`
		Deprecated int `json:"deprecated"`
		Unchecked  int `json:"unchecked"`
	} `json:"summary"`
}

func retractWorld(t *testing.T) *testenv.World {
	w := testenv.New(t)
	for _, v := range []string{"v1.0.0", "v1.1.0", "v1.2.0", "v1.3.0", "v1.4.0-rc.1"} {
		files := map[string]string{}
		if v == "v1.3.0" || v == "v1.4.0-rc.1" {
			files["go.mod"] = "module github.com/acme/r\n\ngo 1.21\n\nretract [v1.1.0, v1.2.0] // data corruption in Encode\n"
		}
		w.AddModule("github.com/acme/r", v, files)
	}
	w.AddModule("github.com/acme/sec", "v1.0.0", nil)
	w.AddModule("github.com/acme/sec", "v1.1.0", map[string]string{
		"go.mod": "module github.com/acme/sec\n\ngo 1.21\n\nretract (\n\tv1.1.0 // Published with a security vulnerability (CVE-2025-0001)\n)\n",
	})
	w.AddModule("github.com/acme/old", "v0.9.0", map[string]string{
		"go.mod": "// Deprecated: use github.com/acme/new instead.\nmodule github.com/acme/old\n\ngo 1.21\n",
	})
	w.AddModule("github.com/acme/clean", "v1.0.0", map[string]string{
		"go.mod": testenv.GoModFile("github.com/acme/clean", "1.21", "github.com/acme/r@v1.1.0"),
	})
	return w
}

func TestRetract(t *testing.T) {
	w := retractWorld(t)
	dir := project(w, "github.com/acme/clean@v1.0.0", "github.com/acme/sec@v1.1.0", "github.com/acme/old@v0.9.0")
	r := w.Run(dir, "retract", "--json")
	checkEnvelope(t, r, "retract", 1)
	var res retractResult
	r.Decode(t, &res)
	if res.Summary.Modules != 4 || res.Summary.Retracted != 2 || res.Summary.Deprecated != 1 {
		t.Fatalf("summary = %+v", res.Summary)
	}
	for _, m := range res.Modules {
		switch m.Path {
		case "github.com/acme/r": // indirect, via clean
			if !m.Retracted || m.Version != "v1.1.0" || m.Latest != "v1.3.0" || m.Suggest != "v1.3.0" || m.SuggestDir != "upgrade" ||
				m.Rationale != "data corruption in Encode" || m.Retraction == nil || m.Retraction.Low != "v1.1.0" || m.Retraction.High != "v1.2.0" {
				t.Errorf("r: %+v", m)
			}
		case "github.com/acme/sec":
			if !m.Retracted || m.Suggest != "v1.0.0" || m.SuggestDir != "downgrade" {
				t.Errorf("sec: %+v", m)
			}
		case "github.com/acme/old":
			if m.Retracted || m.Deprecated != "use github.com/acme/new instead." {
				t.Errorf("old: %+v", m)
			}
		case "github.com/acme/clean":
			if m.Retracted || m.Deprecated != "" {
				t.Errorf("clean: %+v", m)
			}
		}
	}
	got := rules(res.Findings, "github.com/acme/sec")
	if got["retracted"] != "critical" {
		t.Errorf("security retraction severity: %v", got)
	}
	if got := rules(res.Findings, "github.com/acme/r"); got["retracted"] != "high" {
		t.Errorf("r severity: %v", got)
	}
	if got := rules(res.Findings, "github.com/acme/old"); got["deprecated"] != "medium" {
		t.Errorf("old: %v", got)
	}
	for _, f := range res.Findings {
		if f.Module == "github.com/acme/r" && f.Fix != "go get github.com/acme/r@v1.3.0" {
			t.Errorf("fix = %q", f.Fix)
		}
	}

	// --direct skips the indirect retraction; --no-deprecated drops old.
	r = w.Run(dir, "retract", "--direct", "--no-deprecated", "--json")
	checkEnvelope(t, r, "retract", 1)
	r.Decode(t, &res)
	if res.Summary.Modules != 3 || res.Summary.Retracted != 1 || len(res.Findings) != 1 {
		t.Errorf("--direct: %+v %+v", res.Summary, res.Findings)
	}

	r = w.Run(dir, "retract")
	if r.Code != 1 || !strings.Contains(r.Stdout, "RETRACTED") || !strings.Contains(r.Stdout, "go get github.com/acme/r@v1.3.0") || !strings.Contains(r.Stdout, "DEPRECATED") {
		t.Errorf("text (code %d):\n%s", r.Code, r.Stdout)
	}
}

func TestRetractArgs(t *testing.T) {
	w := retractWorld(t)
	// Clean versions exit 0.
	r := w.Run("", "retract", "github.com/acme/r@v1.3.0", "github.com/acme/clean", "--json")
	checkEnvelope(t, r, "retract", 0)
	var res retractResult
	r.Decode(t, &res)
	if len(res.Findings) != 0 || res.Modules[1].Version != "v1.0.0" {
		t.Fatalf("clean: %+v", res)
	}
	// Prerelease of a retracted range: only releases are suggested.
	r = w.Run("", "retract", "github.com/acme/r@v1.2.0", "--json")
	checkEnvelope(t, r, "retract", 1)
	r.Decode(t, &res)
	if res.Modules[0].Suggest != "v1.3.0" {
		t.Errorf("suggest = %q", res.Modules[0].Suggest)
	}
	// Unknown modules degrade to a warning.
	r = w.Run("", "retract", "github.com/nobody/nothing", "--json")
	checkEnvelope(t, r, "retract", 0)
	r.Decode(t, &res)
	if res.Summary.Unchecked != 1 || r.JSON(t)["warnings"] == nil {
		t.Errorf("unknown: %+v", res.Summary)
	}
	r = w.Run("", "retract", "github.com/acme/clean")
	if r.Code != 0 || !strings.Contains(r.Stdout, "no selected version is retracted") {
		t.Errorf("text: %s", r.Stdout)
	}
}

func TestRetractProxyDown(t *testing.T) {
	w := retractWorld(t)
	r := w.RunEnv("", []string{"GOPROXY=http://127.0.0.1:1/proxy"}, "retract", "github.com/acme/r@v1.1.0", "--json", "--timeout", "2s")
	checkEnvelope(t, r, "retract", 3)
}

// A module replaced by a local directory (required as v0.0.0, which the
// proxy does not have) is not looked up and causes no warning; one
// module is counted in the singular.
func TestRetractLocalReplace(t *testing.T) {
	w := retractWorld(t)
	dir := w.Project(map[string]string{
		"go.mod":           "module example.com/app\n\ngo 1.22\n\nrequire example.com/localx v0.0.0\n\nreplace example.com/localx => ./localx\n",
		"main.go":          "package main\n\nimport _ \"example.com/localx\"\n\nfunc main() {}\n",
		"localx/go.mod":    "module example.com/localx\n\ngo 1.22\n",
		"localx/localx.go": "package localx\n",
	})
	r := w.Run(dir, "retract", "--json")
	checkEnvelope(t, r, "retract", 0)
	if r.JSON(t)["warnings"] != nil {
		t.Errorf("unexpected warnings: %v", r.JSON(t)["warnings"])
	}
	r = w.Run("", "retract", "github.com/acme/r@v1.3.0")
	if !strings.Contains(r.Stdout, "1 module checked") {
		t.Errorf("text: %s", r.Stdout)
	}
}
