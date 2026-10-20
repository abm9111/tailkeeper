package workflows

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// concurrencyGroup reads the concurrency group of a workflow file.
func concurrencyGroup(t *testing.T, file string) string {
	t.Helper()
	data, err := os.ReadFile("../../.github/workflows/" + file)
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Concurrency struct {
			Group string `yaml:"group"`
		} `yaml:"concurrency"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatal(err)
	}
	return wf.Concurrency.Group
}

// A workflow that runs on a push and on a schedule gets the same ref for both
// (refs/heads/main). In one concurrency group, a run that waits behind a running one is
// replaced by the next run that arrives, so a push to main could cancel the weekly run
// that looks for newly published vulnerabilities. The event is part of the group, as the
// fuzz workflow has it.
func TestConcurrencyGroupsNameTheEvent(t *testing.T) {
	for _, file := range []string{"verify.yml", "fuzz.yml"} {
		group := concurrencyGroup(t, file)
		if group == "" {
			t.Errorf("%s has no concurrency group", file)
			continue
		}
		for _, part := range []string{"github.event_name", "github.ref"} {
			if !strings.Contains(group, part) {
				t.Errorf("%s: the concurrency group %q lacks %s", file, group, part)
			}
		}
	}
}

// verify.yml cancels a superseded run only for a pull request: a run on main or on the
// weekly schedule always finishes, since a newer push must not cancel the scheduled
// check for newly published vulnerabilities (its comment says so). Any other value, a
// plain true included, cancels those runs too.
func TestVerifyCancelsOnlyPullRequestRuns(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/verify.yml")
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Concurrency struct {
			Cancel any `yaml:"cancel-in-progress"`
		} `yaml:"concurrency"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatal(err)
	}
	const want = "${{ github.event_name == 'pull_request' }}"
	if got, _ := wf.Concurrency.Cancel.(string); got != want {
		t.Errorf("verify.yml: cancel-in-progress = %v, want %q: runs on main and on the schedule must always finish", wf.Concurrency.Cancel, want)
	}
}
