package upgrade

import (
	"context"
	"reflect"
	"testing"
)

func TestPredictToolchain(t *testing.T) {
	tests := []struct {
		newGo, tc, runner, want string
	}{
		// Go 1.21 to 1.24 record a newer running toolchain when they raise the go line.
		{"1.22", "", "1.24.7", "go1.24.7"},
		{"1.22", "", "1.21.0", ""}, // runner older than the new go line: the go line wins
		{"1.22", "go1.23.4", "1.24.7", "go1.24.7"},
		{"1.22", "go1.25.0", "1.24.7", "go1.25.0"}, // existing toolchain newer than the runner: kept
		{"1.20", "", "1.24.7", ""},                 // go lines before 1.21 never get a toolchain line
		{"1.22", "", "1.24", ""},                   // a language version is not recorded
		// Go 1.25 and later do not record the running toolchain.
		{"1.22", "", "1.25.1", ""},
		{"1.22", "", "1.27.3", ""},
		{"1.22", "go1.23.4", "1.25.1", "go1.23.4"}, // newer than the go line: kept
		{"1.22", "go1.21.5", "1.25.1", ""},         // older than the new go line: dropped
		{"1.22", "go1.22", "1.27.3", ""},
		// Unknown runner: only the existing line can survive.
		{"1.22", "", "", ""},
		{"1.22", "go1.23.0", "", "go1.23.0"},
	}
	for _, tt := range tests {
		if got := predictToolchain(tt.newGo, tt.tc, tt.runner); got != tt.want {
			t.Errorf("predictToolchain(%q, %q, %q) = %q, want %q", tt.newGo, tt.tc, tt.runner, got, tt.want)
		}
	}
}

func TestNewerToolchain(t *testing.T) {
	rel := []string{"1.39.0", "1.39.1", "1.39.2", "1.40.0", "1.40.1", "1.40.2"}
	rc := []string{"1.38.0", "1.38.1", "1.39.0", "1.39.1", "1.40rc1"}
	tests := []struct {
		need string
		list []string
		want string
	}{
		// The latest patch release before the most recent release family.
		{"1.30", rel, "go1.39.2"},
		{"1.39", rel, "go1.39.2"},
		{"1.39.2", rel, "go1.39.2"},
		// Too new for that: the latest release.
		{"1.39.3", rel, "go1.40.2"},
		{"1.40", rel, "go1.40.2"},
		{"1.41", rel, ""},
		// A prerelease family does not count as the most recent release family.
		{"1.39", rc, "go1.39.1"},
		{"1.30", rc, "go1.38.1"},
		{"1.40rc1", rc, "go1.40rc1"},
		{"1.30", []string{"1.39.0", "1.40.0"}, "go1.39.0"},
		{"1.30", []string{"1.40.0"}, "go1.40.0"},
		{"1.30", nil, ""},
	}
	for _, tt := range tests {
		if got := newerToolchain(tt.need, tt.list); got != tt.want {
			t.Errorf("newerToolchain(%q, %v) = %q, want %q", tt.need, tt.list, got, tt.want)
		}
	}
}

func TestToolchainVersionNames(t *testing.T) {
	for in, want := range map[string]string{
		"v0.0.1-go1.22.3.linux-amd64":    "1.22.3",
		"v0.0.1-go1.21rc2.windows-arm64": "1.21rc2",
		"v0.0.1-go1.22.0.darwin-arm64":   "1.22.0",
		"v0.0.1-go1.22.3":                "",
		"v0.0.1":                         "",
		"v0.0.1-gox.y.linux-amd64":       "",
	} {
		got, ok := dlToGo(in)
		if !ok {
			got = ""
		}
		if got != want {
			t.Errorf("dlToGo(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"go1.22.3":         "1.22.3",
		"go1.22.3-bigcorp": "1.22.3",
		"go1.22rc1":        "1.22rc1",
		"gofmt":            "",
		"go":               "",
		"go1.x":            "",
	} {
		if got := fromToolchainName(in); got != want {
			t.Errorf("fromToolchainName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := goLang("1.22.3"); got != "1.22" {
		t.Errorf("goLang = %q", got)
	}
	if got := goLang("1.22rc1"); got != "1.22" {
		t.Errorf("goLang rc = %q", got)
	}
	if !goPrerelease("1.22rc1") || goPrerelease("1.22.1") {
		t.Error("goPrerelease")
	}
}

func TestToolchainChoices(t *testing.T) {
	list, err := toolchainChoices(context.Background(), "auto", "1.24.7", func(_ context.Context, path string) ([]string, error) {
		if path != "golang.org/toolchain" {
			t.Fatalf("path %q", path)
		}
		return []string{"v0.0.1-go1.25.0.linux-amd64", "v0.0.1-go1.25.0.darwin-arm64", "v0.0.1-go1.24.7.linux-amd64", "v0.0.1-go1.26rc1.linux-amd64"}, nil
	}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"1.24.7", "1.25.0", "1.26rc1"}; !reflect.DeepEqual(list, want) {
		t.Errorf("auto choices = %v, want %v", list, want)
	}
	// local mode lists only the local version.
	list, _ = toolchainChoices(context.Background(), "local", "1.24.7", nil, "", "")
	if !reflect.DeepEqual(list, []string{"1.24.7"}) {
		t.Errorf("local choices = %v", list)
	}
}
