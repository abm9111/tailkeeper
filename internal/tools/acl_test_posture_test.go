package tools_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

func TestPostureIsGatedWhenThePolicyHasDefaultSrcPostureOrASrcPostureRuleAndNamesThem(t *testing.T) {
	const policy = `{
		"defaultSrcPosture": ["posture:default"],
		"hosts": {"web": "192.0.2.10"},
		"acls": [{"action": "accept", "src": ["tag:ci"], "dst": ["tag:db:22"], "srcPosture": ["posture:acl", "posture:default"]}],
		"grants": [{"src": ["tag:ci"], "dst": ["tag:db"], "ip": ["tcp:22"], "srcPosture": ["posture:grant"]}],
		"ssh": [{"action": "accept", "src": ["tag:ci"], "dst": ["tag:db"], "users": ["root"], "srcPosture": ["posture:ssh"]}]
	}`
	f, reg, env := apiEnv(t)
	f.ServeValidate(apitest.TestsPass())
	servePolicy(f, policy, `"e1"`)
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:db:22"]}`, &out)
	if out.Posture != "gated" || out.PostureNote != "" {
		t.Fatalf("posture %q, note %q", out.Posture, out.PostureNote)
	}
	got := strings.Join(out.PosturesNeeded, ",")
	if got != "posture:acl,posture:default,posture:grant,posture:ssh" {
		t.Errorf("postures = %q", got)
	}
}

func TestPostureIsFalseForAPolicyWithoutAndANoteWhenThePolicyCannotBeRead(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.ServeValidate(apitest.TestsPass())
	servePolicy(f, "{}\n", `"e1"`)
	var plain tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:db:22"]}`, &plain)
	if plain.Posture != "none" || plain.PostureNote != "" || len(plain.PosturesNeeded) != 0 {
		t.Errorf("a policy with no posture: %+v", plain)
	}
	f, reg, env = apiEnv(t)
	f.ServeValidate(apitest.TestsPass())
	f.JSON("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/acl", 500, `{"message":"no"}`)
	var unread tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:db:22"]}`, &unread)
	if unread.Status != "pass" || unread.Posture != "unknown" || unread.PostureNote != "the live policy could not be read, so whether it is posture-sensitive was not checked" {
		t.Errorf("an unreadable policy: status %s, posture %q, note %q", unread.Status, unread.Posture, unread.PostureNote)
	}
	rep := unread.Report()
	if joined := strings.Join(rep.NotChecked, "\n"); !strings.Contains(joined, "leaves unproved") || !strings.Contains(joined, "was not checked") {
		t.Errorf("the text layout does not say what an unknown posture leaves unproved: %q", rep.NotChecked)
	}
	if !slices.Contains(rep.Facts, registry.Fact{Label: "posture", Text: "unknown"}) {
		t.Errorf("the posture is not stated as a fact: %+v", rep.Facts)
	}
	for _, n := range rep.NotChecked {
		if strings.Contains(n, "Evaluated against") {
			t.Errorf("the note is listed as not checked: %q", n)
		}
	}
}

func TestPostureReadsAGuardedPolicyAndSurvivesAMillionLevelsOfNesting(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.ServeValidate(apitest.TestsPass())
	servePolicy(f, strings.Repeat("[", 1<<20), `"e1"`)
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:db:22"]}`, &out)
	if out.Status != "pass" || out.Posture != "unknown" || out.PostureNote != "the live policy could not be read, so whether it is posture-sensitive was not checked" {
		t.Fatalf("status %s, posture %q, note %q; want a pass, unknown posture and the unread note", out.Status, out.Posture, out.PostureNote)
	}
}

// A rule key and a section name are read in any letter case, as the policy reader reads them:
// a srcPosture written srcposture or SrcPosture is still a posture gate, and the result must
// not say posture none for a policy that has one.
func TestPostureReadsASrcPostureKeyAndASectionNameInAnyCase(t *testing.T) {
	const policy = `{
		"DefaultSrcPosture": ["posture:default"],
		"ACLS": [{"action": "accept", "src": ["tag:ci"], "dst": ["tag:db:22"], "srcposture": ["posture:lower"]}],
		"Grants": [{"src": ["tag:ci"], "dst": ["tag:db"], "ip": ["tcp:22"], "SrcPosture": ["posture:mixed"]}]
	}`
	f, reg, env := apiEnv(t)
	f.ServeValidate(apitest.TestsPass())
	servePolicy(f, policy, `"e1"`)
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:db:22"]}`, &out)
	if got := strings.Join(out.PosturesNeeded, ","); out.Posture != "gated" || got != "posture:default,posture:lower,posture:mixed" {
		t.Errorf("posture %q, names %q", out.Posture, got)
	}
}

// A policy that names more posture attributes than a result lists is gated, lists the first
// 64 in order, and says that the list is not whole.
func TestAPolicyThatNamesMorePostureAttributesThanTheResultListsSaysSo(t *testing.T) {
	var names []string
	for i := 0; i < 65; i++ {
		names = append(names, fmt.Sprintf(`"posture:p%02d"`, i))
	}
	policy := `{"acls": [{"action": "accept", "src": ["tag:ci"], "dst": ["tag:db:22"], "srcPosture": [` + strings.Join(names, ",") + `]}]}`
	f, reg, env := apiEnv(t)
	f.ServeValidate(apitest.TestsPass())
	servePolicy(f, policy, `"e1"`)
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:db:22"]}`, &out)
	if out.Posture != "gated" || len(out.PosturesNeeded) != 64 || out.PosturesNeeded[0] != "posture:p00" || out.PosturesNeeded[63] != "posture:p63" {
		t.Fatalf("posture %q, %d names", out.Posture, len(out.PosturesNeeded))
	}
	if out.PostureNote != "the policy names more posture attributes than this result lists" {
		t.Errorf("note %q", out.PostureNote)
	}
	// Exactly 64 names is the whole list and needs no note.
	f, reg, env = apiEnv(t)
	f.ServeValidate(apitest.TestsPass())
	servePolicy(f, `{"acls": [{"action": "accept", "src": ["tag:ci"], "dst": ["tag:db:22"], "srcPosture": [`+strings.Join(names[:64], ",")+`]}]}`, `"e1"`)
	out = tools.ACLTestOutput{}
	mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:db:22"]}`, &out)
	if len(out.PosturesNeeded) != 64 || out.PostureNote != "" {
		t.Errorf("%d names, note %q", len(out.PosturesNeeded), out.PostureNote)
	}
}
