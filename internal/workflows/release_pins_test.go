package workflows

import (
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// permissionsOf reads a permissions block: nothing (the job inherits the workflow's),
// a scalar such as write-all (shown under "*"), or a map of scope to level.
func permissionsOf(t *testing.T, where string, v any) map[string]string {
	t.Helper()
	switch p := v.(type) {
	case nil:
		return nil
	case string:
		return map[string]string{"*": p}
	case map[string]any:
		out := map[string]string{}
		for k, level := range p {
			l, ok := level.(string)
			if !ok {
				t.Fatalf("%s: permission %s is %v, not a level", where, k, level)
			}
			out[k] = l
		}
		return out
	}
	t.Fatalf("%s: permissions is %T", where, v)
	return nil
}

// release.yml is the one workflow that writes: its permissions are pinned job by job.
// The workflow reads only; verify and reproduce inherit that; release creates the draft,
// signs keylessly and attests; publish only publishes the draft. A job that gained write
// or id-token access, or a workflow that did at the top (where every job, and any job
// added later, inherits it), would keep every other test green.
func TestReleaseWorkflowPinsEveryPermission(t *testing.T) {
	wf, _ := loadWorkflow(t)
	if got, want := permissionsOf(t, "the workflow", wf.Permissions), map[string]string{"contents": "read"}; !reflect.DeepEqual(got, want) {
		t.Errorf("the workflow's top-level permissions are %v, want %v", got, want)
	}
	want := map[string]map[string]string{
		"verify":    nil,
		"release":   {"contents": "write", "id-token": "write", "attestations": "write"},
		"reproduce": nil,
		"publish":   {"contents": "write"},
	}
	for name, j := range wf.Jobs {
		w, ok := want[name]
		if !ok {
			t.Errorf("job %s has no pinned permissions: add it to this test with the least it needs", name)
			continue
		}
		if got := permissionsOf(t, "job "+name, j.Permissions); !reflect.DeepEqual(got, w) {
			t.Errorf("job %s has permissions %v, want %v", name, got, w)
		}
	}
	for name := range want {
		if _, ok := wf.Jobs[name]; !ok {
			t.Errorf("release.yml has no job %s, which this test pins", name)
		}
	}
}

// The release refuses a private repository, and fails closed: only an explicit "false"
// passes, so a private repository, an empty value and anything else stop it. The step's
// condition, its input and its script are pinned, and the script is run on each value.
func TestReleaseRefusesAnythingButAPublicRepository(t *testing.T) {
	wf, _ := loadWorkflow(t)
	var found []step
	for _, s := range wf.Jobs["verify"].Steps {
		if s.Name == "A release needs a public repository" {
			found = append(found, s)
		}
	}
	if len(found) != 1 {
		t.Fatalf("the verify job has %d steps named \"A release needs a public repository\", want 1", len(found))
	}
	s := found[0]
	if s.If != tagPush {
		t.Errorf("the private-repository check runs when %q, want %q", s.If, tagPush)
	}
	if got := s.Env["PRIVATE"]; got != "${{ github.event.repository.private }}" {
		t.Errorf("the check reads PRIVATE from %q, want the repository's private flag", got)
	}
	if !strings.Contains(s.Run, `[ "$PRIVATE" != false ]`) {
		t.Errorf("the check does not refuse everything that is not false: %q", s.Run)
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Log("no sh on PATH: only the text of the private-repository check is pinned here, not its behaviour")
		return
	}
	for value, wantExit := range map[string]int{"true": 1, "": 1, "null": 1, "True": 1, "0": 1, "false": 0} {
		cmd := exec.Command(sh, "-c", s.Run)
		cmd.Env = append(os.Environ(), "PRIVATE="+value)
		out, err := cmd.CombinedOutput()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		if code != wantExit {
			t.Errorf("PRIVATE=%q: the check exits %d, want %d; output: %s", value, code, wantExit, out)
		}
	}
}
