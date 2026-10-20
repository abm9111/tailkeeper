package workflows

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// changelogEnabled reports whether GoReleaser's changelog stage runs, given the value of
// `changelog.disable` in .goreleaser.yaml: absent, false and the string "false" leave it
// on; true, any other string (GoReleaser reads a string as a template, which this test
// cannot evaluate, so it is not shown to be off) and any other type do not.
func changelogEnabled(disable any) bool {
	switch v := disable.(type) {
	case nil:
		return true
	case bool:
		return !v
	case string:
		return strings.TrimSpace(v) == "false"
	}
	return false
}

// goreleaserChangelogDisable reads `changelog.disable` from a .goreleaser.yaml document.
func goreleaserChangelogDisable(t *testing.T, doc string) any {
	t.Helper()
	var cfg struct {
		Changelog struct {
			Disable any `yaml:"disable"`
		} `yaml:"changelog"`
	}
	if err := yaml.Unmarshal([]byte(doc), &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg.Changelog.Disable
}

// GoReleaser reads the file given with --release-notes in its changelog stage, and
// `changelog: disable: true` skips the whole stage. v0.5.0 was published with only the
// footer for that reason: the release job passed the notes it had cut from CHANGELOG.md
// and GoReleaser never opened the file. The release job passes them, so the stage must
// stay on.
func TestReleaseNotesStageIsNotDisabled(t *testing.T) {
	wf, _ := loadWorkflow(t)
	passes := 0
	for _, j := range wf.Jobs {
		for _, s := range j.Steps {
			if args, _ := s.With["args"].(string); strings.Contains(args, "--release-notes") {
				passes++
			}
		}
	}
	if passes == 0 {
		t.Fatal("no step of release.yml passes --release-notes to GoReleaser: this test guards that flag, so it was removed or renamed; update it with the change")
	}
	data, err := os.ReadFile("../../.goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if disable := goreleaserChangelogDisable(t, string(data)); !changelogEnabled(disable) {
		t.Errorf(".goreleaser.yaml sets changelog.disable to %v while release.yml passes --release-notes: "+
			"GoReleaser reads that file in its changelog stage, so the notes would be dropped and the release published with only its footer", disable)
	}
}

// The reading of `changelog.disable` is checked on the documents that matter, so a
// change to it cannot let the disabled configuration through.
func TestChangelogDisableReading(t *testing.T) {
	for _, c := range []struct {
		name    string
		doc     string
		enabled bool
	}{
		{"no changelog block", "project_name: x\n", true},
		{"an empty block", "changelog: {}\n", true},
		{"disable false", "changelog:\n  disable: false\n", true},
		{"disable the string false", "changelog:\n  disable: \"false\"\n", true},
		{"the 0.5.0 file: disable true", "changelog:\n  disable: true\n", false},
		{"disable the string true", "changelog:\n  disable: \"true\"\n", false},
		{"disable a template", "changelog:\n  disable: \"{{ .IsSnapshot }}\"\n", false},
		{"disable a number", "changelog:\n  disable: 1\n", false},
	} {
		if got := changelogEnabled(goreleaserChangelogDisable(t, c.doc)); got != c.enabled {
			t.Errorf("%s: changelogEnabled = %v, want %v", c.name, got, c.enabled)
		}
	}
}
