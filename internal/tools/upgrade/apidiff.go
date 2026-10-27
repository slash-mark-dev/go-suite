package upgrade

import (
	"flag"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/apidiff"
	"github.com/slash-mark-dev/go-suite/internal/cli"
	"github.com/slash-mark-dev/go-suite/internal/semver"
)

var apidiffFlags struct {
	against *string
	all     *bool
}

func init() {
	cli.Register(&cli.Tool{
		Name:    "apidiff",
		Group:   group,
		Summary: "API break detector: incompatible API changes between two module versions",
		Usage:   "sm-go apidiff <module@old> <module@new> | <module> <old>..<new> | --against <version>",
		Help: `Downloads both versions of a module through GOPROXY, type-checks every
importable package (internal and main packages are skipped) and diffs the
exported API with the semantics of golang.org/x/exp/apidiff:

  incompatible  removed packages, functions, methods, fields and types;
                changed signatures, field, variable and constant types;
                changed constant values; methods added to interfaces that
                other packages can implement; value-to-pointer receiver
                moves; structs that stop being comparable; changed type
                parameters and constraints
  compatible    added packages, functions, methods, fields and types

Changes are reported per package. Incompatible changes between versions
that semantic versioning says are compatible (a minor or patch release of
v1 or later) are flagged and make the exit code 1. Major version upgrades
may be compared across module paths (example.com/m@v1.9.0
example.com/m/v2@v2.0.0). In a module directory, --against compares the
working tree with a published version of the same module.`,
		Examples: []string{
			"sm-go apidiff golang.org/x/text@v0.14.0 golang.org/x/text@v0.15.0",
			"sm-go apidiff github.com/google/go-cmp v0.5.9..v0.6.0 --all",
			"sm-go apidiff example.com/m@v1.9.0 example.com/m/v2@v2.0.0",
			"sm-go apidiff --against v1.4.0 --json",
		},
		Sources: []string{"Go module proxy", "checksum database (via the go command)"},
		NeedsGo: true,
		Flags: func(fs *flag.FlagSet) {
			apidiffFlags.against = fs.String("against", "", "compare the module in the current directory with this published `version`")
			apidiffFlags.all = fs.Bool("all", false, "also list compatible changes")
		},
		Run: runAPIDiff,
	})
}

// APIDiffResult is the JSON result of apidiff.
type APIDiffResult struct {
	Old          string                  `json:"old"`
	New          string                  `json:"new"`
	OldModule    string                  `json:"oldModule"`
	OldVersion   string                  `json:"oldVersion"`
	NewModule    string                  `json:"newModule"`
	NewVersion   string                  `json:"newVersion,omitempty"` // "" for the working tree
	SemverBump   string                  `json:"semverBump"`           // what the version numbers promise
	RequiredBump string                  `json:"requiredBump"`         // what the API changes require
	Incompatible int                     `json:"incompatible"`
	Compatible   int                     `json:"compatible"`
	Violation    bool                    `json:"violation"`
	Packages     []apidiff.PackageReport `json:"packages"`
	Report       apidiff.Report          `json:"-"`
	Notes        []string                `json:"notes,omitempty"`
}

func runAPIDiff(c *cli.Context) error {
	var oldPath, oldV, newPath, newV string
	local := false
	switch {
	case *apidiffFlags.against != "":
		if len(c.Args) > 0 {
			return cli.Usagef("--against takes no module arguments")
		}
		p, err := c.Project()
		if err != nil {
			return cli.Usagef("--against: %v", err)
		}
		if p.ModulePath() == "" {
			return cli.Usagef("--against: go.mod has no module directive")
		}
		oldPath, newPath, local = p.ModulePath(), p.ModulePath(), true
		v, err := resolveQuery(c, oldPath, *apidiffFlags.against, "")
		if err != nil {
			return err
		}
		oldV = v
	case len(c.Args) == 2 && strings.Contains(c.Args[1], ".."):
		path, _, err := splitArg(c.Args[0])
		if err != nil {
			return err
		}
		a, b, _ := strings.Cut(c.Args[1], "..")
		oldPath, newPath = path, path
		if oldV, err = resolveQuery(c, path, a, ""); err != nil {
			return err
		}
		if newV, err = resolveQuery(c, path, b, ""); err != nil {
			return err
		}
	case len(c.Args) == 2:
		var q1, q2 string
		var err error
		if oldPath, q1, err = splitArg(c.Args[0]); err != nil {
			return err
		}
		if newPath, q2, err = splitArg(c.Args[1]); err != nil {
			return err
		}
		if q1 == "" || q2 == "" {
			return cli.Usagef("both arguments need a version: module@version")
		}
		if oldV, err = resolveQuery(c, oldPath, q1, ""); err != nil {
			return err
		}
		if newV, err = resolveQuery(c, newPath, q2, ""); err != nil {
			return err
		}
	default:
		return cli.Usagef("want two versions: module@old module@new, module old..new, or --against version")
	}
	for _, v := range []string{oldV, newV} {
		if v == "none" {
			return cli.Usagef("version none cannot be compared")
		}
	}

	oldAPI, err := loadAPI(c, oldPath, oldV)
	if err != nil {
		return err
	}
	var newAPI *apidiff.Module
	if local {
		p, _ := c.Project()
		newAPI, err = loadLocalAPI(c, p.ModDir)
	} else {
		newAPI, err = loadAPI(c, newPath, newV)
	}
	if err != nil {
		return err
	}
	rep := apidiff.CompareModules(oldAPI, newAPI, nil).Normalize()
	res := &APIDiffResult{
		Old: modAt(oldPath, oldV), New: modAt(newPath, newV),
		OldModule: oldPath, OldVersion: oldV, NewModule: newPath, NewVersion: newV,
		RequiredBump: rep.Bump(), Incompatible: len(rep.Incompatible), Compatible: len(rep.Compatible),
		Packages: rep.ByPackage(), Report: rep,
	}
	if res.Packages == nil {
		res.Packages = []apidiff.PackageReport{}
	}
	if local {
		res.New = newPath + " (working tree)"
	}
	switch {
	case local:
		res.SemverBump = "unreleased"
	case oldPath != newPath:
		res.SemverBump = "major"
		if semver.Major(oldV) == semver.Major(newV) {
			res.Notes = append(res.Notes, "the module paths differ but the versions have the same major version")
		}
	default:
		res.SemverBump = semverBump(oldV, newV)
	}
	if res.Incompatible > 0 && !local && oldPath == newPath {
		switch res.SemverBump {
		case "minor", "patch", "prerelease":
			if semver.Major(newV) == "v0" {
				res.Notes = append(res.Notes, "v0 versions make no compatibility promise, so incompatible changes are allowed")
			} else if semver.Prerelease(newV) != "" {
				res.Notes = append(res.Notes, "prerelease versions make no compatibility promise")
			} else {
				res.Violation = true
			}
		case "downgrade":
			res.Notes = append(res.Notes, "the new version is older than the old one")
		}
	}
	c.SetResult(res)
	if res.Violation {
		c.Issues()
	}
	if !c.Text() {
		return nil
	}
	out := c.Out
	out.Title("API diff " + res.Old + " → " + res.New)
	out.KV([2]string{"version change", res.SemverBump}, [2]string{"API requires", res.RequiredBump},
		[2]string{"packages", plural(len(newAPI.Packages), "package", "packages") + " in " + newPath})
	printChanges(c, rep, *apidiffFlags.all, nil)
	out.Println()
	switch {
	case res.Incompatible == 0 && res.Compatible == 0:
		out.OK("no API changes")
	case res.Incompatible == 0:
		out.OK("%s, no incompatible changes", plural(res.Compatible, "compatible change", "compatible changes"))
		if !*apidiffFlags.all {
			out.Printf("  %s\n", out.Dim("(use --all to list them)"))
		}
	default:
		out.Printf("%s, %s\n", out.Red(plural(res.Incompatible, "incompatible change", "incompatible changes")),
			plural(res.Compatible, "compatible change", "compatible changes"))
	}
	if res.Violation {
		out.Bad("%s is a %s release of %s but breaks its API: this violates semantic versioning", newV, res.SemverBump, oldV)
	}
	for _, n := range res.Notes {
		out.Printf("%s %s\n", out.Dim("note:"), n)
	}
	return nil
}
