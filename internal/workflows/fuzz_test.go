package workflows

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type fuzzJob struct {
	Name     string `yaml:"name"`
	If       string `yaml:"if"`
	Strategy struct {
		Matrix struct {
			Include []struct {
				Pkg string `yaml:"pkg"`
				Min int    `yaml:"min"`
			} `yaml:"include"`
		} `yaml:"matrix"`
	} `yaml:"strategy"`
}

// fuzzTarget is a fuzz target in a _test.go file, at the start of a line.
var fuzzTarget = regexp.MustCompile(`(?m)^func (Fuzz\w*)\(\w+ \*testing\.F\)`)

// fuzzTargetsByPackage counts the fuzz targets under cmd and internal for each package, as
// "./internal/acl" (the form the workflow and go list use). Every _test.go file counts,
// whatever its build constraints: a target left out of the Linux build would still be one.
func fuzzTargetsByPackage(t *testing.T, root string) map[string]int {
	t.Helper()
	counts := map[string]int{}
	for _, top := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), "_test.go") {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, filepath.Dir(path))
			if err != nil {
				return err
			}
			if n := len(fuzzTarget.FindAllString(string(data), -1)); n > 0 {
				counts["./"+filepath.ToSlash(rel)] += n
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return counts
}

// The nightly run fuzzes one package to a job and fails when fewer targets ran than its entry
// says. So a package with a fuzz target that the matrix lacks would never be fuzzed at night,
// and an entry whose count lags behind its package would stop noticing a target that stopped
// running. The job named fuzz is a required check for pull requests: it keeps its name, and
// the nightly is another job that runs on the schedule only.
func TestTheNightlyFuzzMatrixListsEveryPackageWithFuzzTargets(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/fuzz.yml")
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Jobs map[string]fuzzJob `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatal(err)
	}
	want := fuzzTargetsByPackage(t, "../..")
	if len(want) == 0 {
		t.Fatal("no fuzz targets found: the search is wrong")
	}
	nightly, ok := wf.Jobs["nightly"]
	if !ok {
		t.Fatal("fuzz.yml has no nightly job")
	}
	got := map[string]int{}
	for _, e := range nightly.Strategy.Matrix.Include {
		if _, dup := got[e.Pkg]; dup {
			t.Errorf("%s is in the nightly matrix twice", e.Pkg)
		}
		got[e.Pkg] = e.Min
	}
	for pkg, n := range want {
		if min, ok := got[pkg]; !ok {
			t.Errorf("%s holds %d fuzz target(s) and the nightly matrix does not list it", pkg, n)
		} else if min != n {
			t.Errorf("%s holds %d fuzz target(s) and its nightly entry says min %d", pkg, n, min)
		}
	}
	for pkg := range got {
		if _, ok := want[pkg]; !ok {
			t.Errorf("the nightly matrix lists %s, which holds no fuzz target", pkg)
		}
	}
	// The default of make fuzz is the total, so the pull request job notices a lost target too.
	total := 0
	for _, n := range want {
		total += n
	}
	mk, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^FUZZ_MIN \?= (\d+)$`).FindSubmatch(mk)
	if m == nil {
		t.Fatal("the Makefile has no FUZZ_MIN default")
	}
	if n, _ := strconv.Atoi(string(m[1])); n != total {
		t.Errorf("the Makefile's FUZZ_MIN is %d and the packages hold %d fuzz targets", n, total)
	}

	// The required check keeps its name and runs for pull requests; the nightly runs on the
	// schedule only and is named for its package.
	pr, ok := wf.Jobs["fuzz"]
	if !ok {
		t.Fatal("fuzz.yml has no job named fuzz: renaming it blocks every pull request")
	}
	if pr.Name != "" && pr.Name != "fuzz" {
		t.Errorf("the job fuzz is shown as %q, and the required check is called fuzz", pr.Name)
	}
	if strings.Contains(pr.If, "== 'schedule'") || !strings.Contains(pr.If, "!= 'schedule'") {
		t.Errorf("the job fuzz must not run on the schedule alone: if %q", pr.If)
	}
	if nightly.If != "github.event_name == 'schedule'" || !strings.HasPrefix(nightly.Name, "nightly (") {
		t.Errorf("the nightly job: name %q, if %q", nightly.Name, nightly.If)
	}
}
