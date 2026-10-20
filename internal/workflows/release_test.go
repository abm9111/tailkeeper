// Package workflows holds tests of the repository's workflow, release and documentation files; it has no code.
package workflows

import (
	"os"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type step struct {
	Name  string            `yaml:"name"`
	If    string            `yaml:"if"`
	Uses  string            `yaml:"uses"`
	Shell string            `yaml:"shell"`
	Run   string            `yaml:"run"`
	With  map[string]any    `yaml:"with"`
	Env   map[string]string `yaml:"env"`
	// ContinueOnError is a bool or an expression; nil when the key is absent.
	ContinueOnError any `yaml:"continue-on-error"`
}

type job struct {
	If          string            `yaml:"if"`
	Needs       any               `yaml:"needs"`
	Env         map[string]string `yaml:"env"`
	Permissions any               `yaml:"permissions"`
	Steps       []step            `yaml:"steps"`
	// ContinueOnError is a bool or an expression; nil when the key is absent.
	ContinueOnError any `yaml:"continue-on-error"`
}

type workflow struct {
	Env         map[string]string `yaml:"env"`
	Permissions any               `yaml:"permissions"`
	Jobs        map[string]job    `yaml:"jobs"`
}

// loadWorkflow reads release.yml: parsed, and as text.
func loadWorkflow(t *testing.T) (workflow, string) {
	t.Helper()
	data, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	var wf workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatal(err)
	}
	return wf, string(data)
}

const tagVar = "GORELEASER_CURRENT_TAG"

const (
	tagPush   = "github.event_name == 'push'"
	manualRun = "github.event_name == 'workflow_dispatch'"
)

// runsOnlyFor reports whether a step runs for the one event and no other: every condition
// on it and on its job, at least one of them, is that event's condition, written exactly.
// A condition that merely mentions the event ("push || workflow_dispatch", "push && x" or
// "!= 'push'") is not that.
func runsOnlyFor(event string, j job, s step) bool {
	if j.If == "" && s.If == "" {
		return false
	}
	return (j.If == "" || j.If == event) && (s.If == "" || s.If == event)
}

// GoReleaser takes the tag it releases from git (the highest version at HEAD), not from
// the tag the verify job checked: an extra tag on the same commit would be released and
// signed under a name nothing verified. Pinned to the pushed tag's name, wherever the
// build runs for a tag; the manual snapshot runs on a branch, where ref_name is no tag
// and the variable must stay unset. Every job is read, so a GoReleaser step added to any
// of them is held to the same rule. The cache of the Go toolchain action is off in the
// jobs that build what is signed: a restored cache is input to the build.
func TestReleaseWorkflowPinsTheTagAndSkipsTheCache(t *testing.T) {
	wf, text := loadWorkflow(t)
	jobs := wf.Jobs
	names := make([]string, 0, len(jobs))
	for name := range jobs {
		names = append(names, name)
	}
	sort.Strings(names)
	pinned, snapshots := 0, 0
	for _, name := range names {
		j := jobs[name]
		for _, s := range j.Steps {
			if strings.HasPrefix(s.Uses, "goreleaser/goreleaser-action@") || strings.Contains(strings.ToLower(s.Run), "goreleaser") {
				got, has := s.Env["GORELEASER_CURRENT_TAG"]
				switch {
				case runsOnlyFor(tagPush, j, s):
					if got != "${{ github.ref_name }}" {
						t.Errorf("%s job, step %q runs for a tag push, and GORELEASER_CURRENT_TAG = %q, want ${{ github.ref_name }}", name, s.Name, got)
					}
					pinned++
				case runsOnlyFor(manualRun, j, s):
					if has {
						t.Errorf("%s job, step %q is the manual snapshot, and sets GORELEASER_CURRENT_TAG: ref_name is a branch there", name, s.Name)
					}
					snapshots++
				default:
					t.Errorf("%s job, step %q runs GoReleaser on neither event only (job if %q, step if %q)", name, s.Name, j.If, s.If)
				}
			}
		}
	}
	if pinned != 2 || snapshots != 1 {
		t.Errorf("found %d GoReleaser steps for a tag push (want 2: Release (draft) and the rebuild) and %d snapshot steps (want 1)", pinned, snapshots)
	}
	// The Go toolchain action's cache is off wherever it is set up, in the job that gates the
	// release as in the two that build and rebuild what is signed: a restored cache is input.
	for _, name := range []string{"verify", "release", "snapshot", "reproduce"} {
		j, ok := jobs[name]
		if !ok {
			t.Fatalf("release.yml has no %s job", name)
		}
		goSteps := 0
		for _, s := range j.Steps {
			if strings.HasPrefix(s.Uses, "actions/setup-go@") {
				goSteps++
			}
		}
		if goSteps != 1 {
			t.Errorf("%s job: %d setup-go steps, want 1", name, goSteps)
		}
	}
	for _, name := range names {
		for _, s := range jobs[name].Steps {
			if !strings.HasPrefix(s.Uses, "actions/setup-go@") {
				continue
			}
			if c, ok := s.With["cache"].(bool); !ok || c {
				t.Errorf("%s job: setup-go has cache = %v, want false", name, s.With["cache"])
			}
		}
	}
	if got := jobs["reproduce"].If; got != tagPush {
		t.Errorf("the reproduce job's if = %q, want it to run for a tag push only", got)
	}
	// The variable is set on those two steps and nowhere else. At the level of the workflow or
	// of a job it would reach the manual snapshot too, where ref_name is a branch; a step that
	// is not one of the two would carry it into whatever it runs; and a run step could write it
	// to the environment of the steps after it.
	if _, ok := wf.Env[tagVar]; ok {
		t.Errorf("the workflow sets %s for every job", tagVar)
	}
	set := 0
	for _, name := range names {
		j := jobs[name]
		if _, ok := j.Env[tagVar]; ok {
			t.Errorf("%s job sets %s for every step in it", name, tagVar)
		}
		for _, s := range j.Steps {
			if _, ok := s.Env[tagVar]; !ok {
				continue
			}
			set++
			if !strings.HasPrefix(s.Uses, "goreleaser/goreleaser-action@") || !runsOnlyFor(tagPush, j, s) {
				t.Errorf("%s job, step %q sets %s, and is not a GoReleaser step for a tag push", name, s.Name, tagVar)
			}
		}
	}
	if set != 2 {
		t.Errorf("%s is set on %d steps, want 2", tagVar, set)
	}
	if n := strings.Count(text, tagVar); n != 2 {
		t.Errorf("release.yml names %s %d times, want 2: once on each pinned step, and not in a comment, a run step or a with: value", tagVar, n)
	}
}
