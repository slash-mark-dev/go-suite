package origin_test

import (
	"strings"
	"testing"
	"time"

	"github.com/slash-mark-dev/go-suite/internal/testenv"
)

type healthResult struct {
	Subject  string `json:"subject"`
	MinScore int    `json:"minScore"`
	Modules  []struct {
		Path       string `json:"path"`
		Version    string `json:"version"`
		Score      int    `json:"score"`
		Grade      string `json:"grade"`
		Base       int    `json:"base"`
		Components []struct {
			Name      string  `json:"name"`
			Points    float64 `json:"points"`
			Max       float64 `json:"max"`
			Available bool    `json:"available"`
			Detail    string  `json:"detail"`
		} `json:"components"`
		Penalties []struct {
			Reason string `json:"reason"`
			Points int    `json:"points"`
		} `json:"penalties"`
		Signals struct {
			Versions       int      `json:"versions"`
			LatestRelease  string   `json:"latestRelease"`
			ReleasesLastYr int      `json:"releasesLastYear"`
			Scorecard      *float64 `json:"scorecard"`
			Dependents     *int     `json:"dependents"`
			Stars          *int     `json:"stars"`
			Contributors   *int     `json:"contributors"`
			Archived       bool     `json:"archived"`
			Deprecated     string   `json:"deprecated"`
			Retracted      bool     `json:"retracted"`
			Vulns          []string `json:"vulns"`
			VulnsChecked   bool     `json:"vulnsChecked"`
			Repo           string   `json:"repo"`
		} `json:"signals"`
	} `json:"modules"`
	Findings []finding `json:"findings"`
	Summary  struct {
		Modules        int     `json:"modules"`
		Average        float64 `json:"average"`
		Lowest         int     `json:"lowest"`
		BelowThreshold int     `json:"belowThreshold"`
	} `json:"summary"`
}

func healthWorld(t *testing.T) (*testenv.World, string) {
	w := testenv.New(t)
	now := time.Now()
	for i, v := range []string{"v1.0.0", "v1.1.0", "v1.2.0", "v1.3.0"} {
		m := w.AddModule("github.com/acme/good", v, nil)
		m.Time = now.Add(-time.Duration(200-i*60) * 24 * time.Hour) // 200, 140, 80, 20 days ago
	}
	w.GitHubRepo("acme", "good", map[string]any{"stargazers_count": 5000, "open_issues_count": 10,
		"pushed_at": now.Add(-5 * 24 * time.Hour).UTC().Format(time.RFC3339)})
	w.GitHub["repos/acme/good/contributors?per_page=100"] = []map[string]any{
		{"login": "a", "contributions": 50}, {"login": "b", "contributions": 30}, {"login": "c", "contributions": 10},
		{"login": "d", "contributions": 5}, {"login": "e", "contributions": 5}, {"login": "f", "contributions": 1},
	}
	w.DepsDev["v3/systems/go/packages/github.com/acme/good/versions/v1.3.0"] = map[string]any{
		"versionKey":      map[string]any{"name": "github.com/acme/good", "version": "v1.3.0"},
		"relatedProjects": []map[string]any{{"projectKey": map[string]any{"id": "github.com/acme/good"}, "relationType": "SOURCE_REPO"}},
	}
	w.DepsDev["v3/projects/github.com/acme/good"] = map[string]any{"scorecard": map[string]any{"date": "2026-10-01", "overallScore": 8.5}}
	w.DepsDev["v3alpha/systems/go/packages/github.com/acme/good/versions/v1.3.0:dependents"] = map[string]any{"dependentCount": 1200, "directDependentCount": 300}

	w.AddModule("github.com/acme/bad", "v0.1.0", map[string]string{
		"go.mod": "// Deprecated: no longer maintained.\nmodule github.com/acme/bad\n\ngo 1.21\n",
	})
	w.GitHubRepo("acme", "bad", map[string]any{"archived": true})
	w.GitHub["repos/acme/bad/contributors?per_page=100"] = []map[string]any{{"login": "solo", "contributions": 40}}
	w.DepsDev["v3/projects/github.com/acme/bad"] = map[string]any{"scorecard": map[string]any{"overallScore": 3.0}}
	w.AddVuln(testenv.SimpleVuln("GO-2025-0001", "github.com/acme/bad", "v0.0.0", "", "github.com/acme/bad", nil, "CVE-2025-1111"))

	w.AddModule("go.nodata.example/lib", "v0.5.0", nil)

	dir := project(w, "github.com/acme/good@v1.3.0", "github.com/acme/bad@v0.1.0", "go.nodata.example/lib@v0.5.0")
	return w, dir
}

func TestHealth(t *testing.T) {
	w, dir := healthWorld(t)
	r := w.Run(dir, "health", "--json")
	checkEnvelope(t, r, "health", 0)
	var res healthResult
	r.Decode(t, &res)
	if res.Summary.Modules != 3 || len(res.Findings) != 0 {
		t.Fatalf("summary: %+v %+v", res.Summary, res.Findings)
	}
	// Sorted by score, lowest first.
	if res.Modules[0].Path != "github.com/acme/bad" || res.Modules[2].Path != "github.com/acme/good" {
		t.Fatalf("order: %s %s %s", res.Modules[0].Path, res.Modules[1].Path, res.Modules[2].Path)
	}
	good, bad, nodata := res.Modules[2], res.Modules[0], res.Modules[1]
	if good.Score < 85 || good.Grade != "A" || len(good.Penalties) != 0 {
		t.Errorf("good: score %d grade %s penalties %+v components %+v", good.Score, good.Grade, good.Penalties, good.Components)
	}
	for _, c := range good.Components {
		if !c.Available {
			t.Errorf("good: component %s unavailable", c.Name)
		}
		if c.Name == "security" && c.Points != 21.3 {
			t.Errorf("security points = %v", c.Points)
		}
		if c.Name == "cadence" && (c.Points != 10 || !strings.Contains(c.Detail, "4 releases")) {
			t.Errorf("cadence = %+v", c)
		}
	}
	sg := good.Signals
	if sg.Versions != 4 || sg.LatestRelease != "v1.3.0" || sg.ReleasesLastYr != 4 || sg.Scorecard == nil || *sg.Scorecard != 8.5 ||
		sg.Dependents == nil || *sg.Dependents != 1200 || sg.Stars == nil || *sg.Stars != 5000 || sg.Contributors == nil || *sg.Contributors != 6 ||
		!sg.VulnsChecked || sg.Repo != "github.com/acme/good" {
		t.Errorf("good signals: %+v", sg)
	}
	if bad.Score != 0 || bad.Grade != "F" || !bad.Signals.Archived || bad.Signals.Deprecated == "" || len(bad.Signals.Vulns) != 1 {
		t.Errorf("bad: %+v", bad)
	}
	reasons := map[string]int{}
	for _, p := range bad.Penalties {
		reasons[p.Reason] = p.Points
	}
	if reasons["repository archived"] != -30 || reasons["module deprecated"] != -30 || reasons["1 known vulnerability"] != -10 {
		t.Errorf("bad penalties: %v", reasons)
	}
	avail := 0
	for _, c := range nodata.Components {
		if c.Available {
			avail++
		}
	}
	if avail != 2 || nodata.Signals.Stars != nil {
		t.Errorf("nodata: %d available, %+v", avail, nodata.Components)
	}

	// Threshold.
	r = w.Run(dir, "health", "--min-score", "60", "--sort", "name", "--json")
	checkEnvelope(t, r, "health", 1)
	r.Decode(t, &res)
	if res.MinScore != 60 || res.Summary.BelowThreshold != 2 || res.Modules[0].Path != "github.com/acme/bad" || res.Modules[1].Path != "github.com/acme/good" {
		t.Errorf("threshold: %+v", res.Summary)
	}
	got := rules(res.Findings, "github.com/acme/bad")
	if got["low-health"] != "high" {
		t.Errorf("findings: %+v", res.Findings)
	}

	// Explicit module, latest version resolved.
	r = w.Run("", "health", "github.com/acme/good", "--min-score", "80", "--json")
	checkEnvelope(t, r, "health", 0)
	r.Decode(t, &res)
	if len(res.Modules) != 1 || res.Modules[0].Version != "v1.3.0" {
		t.Errorf("explicit: %+v", res.Modules)
	}

	r = w.Run(dir, "health", "--min-score", "60")
	if r.Code != 1 || !strings.Contains(r.Stdout, "Module health") || !strings.Contains(r.Stdout, "repository archived -30") || !strings.Contains(r.Stdout, "OpenSSF Scorecard 8.5/10") {
		t.Errorf("text (code %d):\n%s", r.Code, r.Stdout)
	}
}

func TestHealthDegrades(t *testing.T) {
	w, dir := healthWorld(t)
	r := w.RunEnv(dir, []string{"SMGO_DEPSDEV_URL=http://127.0.0.1:1/depsdev"}, "health", "--json", "--timeout", "2s")
	checkEnvelope(t, r, "health", 0)
	env := r.JSON(t)
	warns, _ := env["warnings"].([]any)
	n := 0
	for _, x := range warns {
		if strings.Contains(x.(string), "deps.dev unavailable") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("want one deps.dev warning, got %v", warns)
	}
	var res healthResult
	r.Decode(t, &res)
	for _, m := range res.Modules {
		if m.Signals.Scorecard != nil {
			t.Errorf("%s: scorecard without deps.dev", m.Path)
		}
	}
	// Unknown explicit module is a usage error.
	r = w.Run("", "health", "github.com/nobody/nothing", "--json")
	checkEnvelope(t, r, "health", 2)
	// Proxy down is a runtime error.
	r = w.RunEnv(dir, []string{"GOPROXY=http://127.0.0.1:1/proxy", "SMGO_CACHE_DIR=" + t.TempDir()}, "health", "--json", "--timeout", "2s")
	checkEnvelope(t, r, "health", 3)
}
