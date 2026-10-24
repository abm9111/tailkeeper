package workflows

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// releaseNotesAwk returns the awk command of the release job's step that cuts the notes
// of a tag out of CHANGELOG.md: the command itself, as written in release.yml, so the
// tests below run what the release runs.
func releaseNotesAwk(t *testing.T) string {
	t.Helper()
	wf, _ := loadWorkflow(t)
	for _, s := range wf.Jobs["release"].Steps {
		if s.Name != "Release notes from CHANGELOG.md" {
			continue
		}
		for _, line := range strings.Split(s.Run, "\n") {
			if strings.HasPrefix(line, "awk ") {
				return line
			}
		}
	}
	t.Fatal("the release job of release.yml has no step \"Release notes from CHANGELOG.md\" with an awk command: this test runs that command, so it was renamed or moved; update the test with it")
	return ""
}

// topHeadingVersion returns the first word after "## " of the first level-2 heading of a
// changelog: the version the release of that section would be tagged with, whatever the
// rest of the heading says ("0.6.0" for "## 0.6.0 — unreleased" and for a dated one).
func topHeadingVersion(changelog string) (string, bool) {
	for _, line := range strings.Split(changelog, "\n") {
		if rest, ok := strings.CutPrefix(line, "## "); ok {
			version, _, _ := strings.Cut(rest, " ")
			return version, true
		}
	}
	return "", false
}

// releaseNotes runs the release job's awk command on a changelog, for the tag its top
// heading names, in a directory of its own, and returns the notes file the job would
// write. A changelog with no level-2 heading has no section to cut, so its notes are
// empty.
func releaseNotes(t *testing.T, awk, changelog string) string {
	t.Helper()
	version, ok := topHeadingVersion(changelog)
	if !ok {
		return ""
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "CHANGELOG.md"), []byte(changelog), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", awk)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TAG=v"+version, "RUNNER_TEMP="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the release job's awk command failed: %v\n%s", err, out)
	}
	notes, err := os.ReadFile(filepath.Join(dir, "notes.md"))
	if err != nil {
		t.Fatal(err)
	}
	return string(notes)
}

// The release job refuses a CHANGELOG.md that has an unreleased heading, and cuts the
// notes of the tag out of the section whose heading starts "## <version> ". On main the
// top section says "unreleased" and is dated by the release PR, so the refusal is a
// release-time check and is not tested here. What is tested is the rest: the job's own
// awk command, run on the top section whatever its heading says, must give notes. A top
// section that is empty, or whose heading the command does not match, would otherwise
// show up as a failed release after the signed tag is pushed.
func TestChangelogTopSectionGivesReleaseNotes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the release job's command is a POSIX shell command that runs awk")
	}
	data, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	version, ok := topHeadingVersion(string(data))
	if !ok {
		t.Fatal("CHANGELOG.md has no level-2 heading")
	}
	if notes := releaseNotes(t, releaseNotesAwk(t), string(data)); strings.TrimSpace(notes) == "" {
		t.Errorf("the top section of CHANGELOG.md (version %s) gives the release job empty notes: add the entries that belong under its heading, and keep a space after the version", version)
	}
}

// The check above is run on changelogs that have each fault, and on ones that do not, so
// it cannot pass by cutting nothing.
func TestChangelogNotesCheckFindsAnEmptySection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the release job's command is a POSIX shell command that runs awk")
	}
	awk := releaseNotesAwk(t)
	const below = "## 0.5.0 — 2026-10-16\n\n- An older entry.\n"
	for _, c := range []struct {
		name      string
		changelog string
		wantNotes bool
	}{
		{"an unreleased section with entries", "# Changelog\n\n## 0.6.0 — unreleased\n\n### Fixed\n\n- A fix.\n\n" + below, true},
		{"a dated section with entries", "# Changelog\n\n## 0.6.0 — 2026-11-01\n\n- A fix.\n\n" + below, true},
		{"a heading with nothing under it", "# Changelog\n\n## 0.6.0 — unreleased\n\n" + below, false},
		{"a heading with blank lines only", "# Changelog\n\n## 0.6.0 — unreleased\n\n\n   \n\n" + below, false},
		{"a heading with nothing after the version", "# Changelog\n\n## 0.6.0\n\n- A fix.\n\n" + below, false},
		{"no section heading at all", "# Changelog\n\nSome text.\n", false},
	} {
		notes := releaseNotes(t, awk, c.changelog)
		if got := strings.TrimSpace(notes) != ""; got != c.wantNotes {
			t.Errorf("%s: notes %q, want notes: %v", c.name, notes, c.wantNotes)
		}
		// The notes of the section below are never borrowed for the top one.
		if strings.Contains(notes, "older entry") {
			t.Errorf("%s: the notes hold the entries of the section below: %q", c.name, notes)
		}
	}
}

// bulletStarting returns the changelog bullet that begins with prefix, or "".
func bulletStarting(changelog, prefix string) string {
	for _, line := range strings.Split(changelog, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

// nameLimit reads the longest name a pattern in source allows from its "{0,N}" tail and
// whether its character class holds a dot and an underscore, from the line that declares
// the pattern named varName.
func nameLimit(t *testing.T, path, varName string) (max int, dotsAndUnderscores bool) {
	t.Helper()
	src := readRepoFile(t, path)
	var line string
	for _, l := range strings.Split(src, "\n") {
		if strings.Contains(l, varName+" ") && strings.Contains(l, "regexp.MustCompile") {
			line = l
		}
	}
	m := regexp.MustCompile(`\{0,(\d+)\}`).FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("%s: no declaration of %s with a {0,N} length found in %q", path, varName, line)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	return n + 1, strings.Contains(line, "._")
}

// The changelog says what the starter's refusal asks for and which names the kind probes
// send, as the code does: the hint names the sources and the destinations apart, and the
// limits are those of the patterns.
func TestTheChangelogStatesTheStarterHintAndTheProbeNamesAsTheCodeDoes(t *testing.T) {
	changelog := readRepoFile(t, "../../CHANGELOG.md")

	starter := bulletStarting(changelog, "- `tailkeeper doctor --policy --out FILE`")
	hint := readRepoFile(t, "../../internal/doctor/starter.go")
	if !strings.Contains(hint, "pass --admin-group GROUP (or --with-logins) for the sources and --tag TAG for the destinations") {
		t.Fatal("the starter's refusal no longer says what this test compares the changelog with: update both")
	}
	for _, want := range []string{
		"with a hint to pass `--admin-group` (or `--with-logins`) for the sources and `--tag` for the destinations",
		"`--tag` may be left out when the credential's key has tags",
	} {
		if !strings.Contains(starter, want) {
			t.Errorf("the changelog's starter bullet lacks %q", want)
		}
	}

	probe := bulletStarting(changelog, "- `doctor --probe` also checks")
	tagMax, tagDots := nameLimit(t, "../../internal/doctor/doctor.go", "canaryTagRE")
	hostMax, hostDots := nameLimit(t, "../../internal/doctor/probes_policy.go", "hostAliasRE")
	if tagDots || !hostDots {
		t.Fatalf("the patterns changed shape (a tag with dots: %v, a host alias with dots and underscores: %v): update the changelog and this test", tagDots, hostDots)
	}
	for _, want := range []string{
		"a tag only when its name after `tag:` is letters, digits and hyphens",
		"a host alias only when its name is letters, digits, hyphens, dots and underscores",
		fmt.Sprintf("either name is at most %d characters", min(tagMax, hostMax)),
	} {
		if !strings.Contains(probe, want) {
			t.Errorf("the changelog's probe bullet lacks %q", want)
		}
	}
	if tagMax != hostMax {
		t.Errorf("the tag allows %d characters and the host alias %d: the changelog says one limit for both", tagMax, hostMax)
	}
}
