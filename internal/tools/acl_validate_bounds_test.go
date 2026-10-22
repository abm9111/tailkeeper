package tools_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
)

// unknownKeys is a text of n sections this version does not know.
func unknownKeys(n int) string {
	var b strings.Builder
	b.WriteString("{\n")
	for i := range n {
		fmt.Fprintf(&b, "\"k%03d\": 0,\n", i)
	}
	b.WriteString("}\n")
	return b.String()
}

// A text may hold as many unknown sections as the engine accepts, and each is a notice. Every
// way out of a validation cuts the problems to what a result carries and counts the rest: a
// text checked here only, a text that is invalid, and the live policy itself.
func TestTheNoticesOfATextAreCutToTheProblemCapOnEveryPath(t *testing.T) {
	offline := offlineValidate(t, unknownKeys(100))
	if offline.Status != "pass" || len(offline.Notices) != 64 || offline.Omitted != 100-64 {
		t.Errorf("offline: status %q, %d notices, omitted %d; want pass, 64 and 36", offline.Status, len(offline.Notices), offline.Omitted)
	}
	// Errors come first and use the room: a repeated key is an error, and 70 unknown sections
	// after it leave room for 63 notices.
	invalid := offlineValidate(t, "{\n\"groups\": {},\n\"groups\": {},\n"+strings.TrimPrefix(unknownKeys(70), "{\n"))
	if invalid.Status != "invalid" || len(invalid.Errors) != 1 || len(invalid.Notices) != 63 || invalid.Omitted != 70-63 {
		t.Errorf("invalid: status %q, %d errors, %d notices, omitted %d; want invalid, 1, 63 and 7", invalid.Status, len(invalid.Errors), len(invalid.Notices), invalid.Omitted)
	}
	f, _, env := apiEnv(t)
	serveLive(f, unknownKeys(100), nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	live := validateOnline(t, env, `{}`)
	if live.Status != "pass" || len(live.Notices) != 64 || live.Omitted != 100-64 {
		t.Errorf("the live policy: status %q, %d notices, omitted %d; want pass, 64 and 36", live.Status, len(live.Notices), live.Omitted)
	}
}

// Every warning of a reply is classified, the ones past the 64 entries of 64 messages that
// are listed too: a new warning that lies past them is not listed, it is counted, and
// --fail-on warnings counts it. Here the live policy stores the first 69 warnings, and the
// 70th is new.
func TestANewWarningPastTheEntriesListedStillFailsTheGate(t *testing.T) {
	var entries []apitest.Entry
	var stored []string
	for i := range 70 {
		user := fmt.Sprintf("tag:w%02d", i)
		entries = append(entries, apitest.Entry{User: user, Warnings: []string{"tag owns nothing"}})
		if i < 69 {
			stored = append(stored, user+": tag owns nothing")
		}
	}
	f, _, env := apiEnv(t)
	serveLive(f, liveText, stored, nil)
	f.ServeValidate(apitest.TestsWarned(entries...))
	out := validateOnline(t, env, `{"policy":`+jsonString(liveText+"// a comment\n")+`}`)
	if out.Status != "pass" || out.IdenticalToLive {
		t.Fatalf("status %q, identical %v", out.Status, out.IdenticalToLive)
	}
	if len(out.NewWarnings) != 0 || len(out.ExistingWarnings) != 64 || out.NewWarningsOmitted != 1 || out.Omitted != 6 {
		t.Errorf("%d new listed, %d existing listed, %d new not listed, omitted %d; want 0, 64, 1 and 6",
			len(out.NewWarnings), len(out.ExistingWarnings), out.NewWarningsOmitted, out.Omitted)
	}
	if got := out.Findings().NewWarnings; got != 1 {
		t.Errorf("--fail-on warnings counts %d new warnings, want 1", got)
	}
	if v := out.Report().Verdict; !strings.HasPrefix(v, "VALID · 1 new warning (64 existing)") {
		t.Errorf("verdict %q does not count the new warning that is not listed", v)
	}
	// The same past the 64 messages of one entry.
	var many []string
	for range 70 {
		many = append(many, "tag owns nothing")
	}
	f2, _, env2 := apiEnv(t)
	serveLive(f2, liveText, nil, nil)
	f2.ServeValidate(apitest.TestsWarned(apitest.Entry{User: "tag:w", Warnings: many}))
	long := validateOnline(t, env2, `{"policy":`+jsonString(liveText+"// a comment\n")+`}`)
	if len(long.NewWarnings) != 64 || long.NewWarningsOmitted != 6 || long.Findings().NewWarnings != 70 {
		t.Errorf("70 messages of one entry: %d listed, %d not listed, %d counted", len(long.NewWarnings), long.NewWarningsOmitted, long.Findings().NewWarnings)
	}
	// And a text that is the live policy byte for byte has no new warning, listed or not.
	f3, _, env3 := apiEnv(t)
	serveLive(f3, liveText, nil, nil)
	f3.ServeValidate(apitest.TestsWarned(entries...))
	same := validateOnline(t, env3, `{}`)
	if same.Findings().NewWarnings != 0 || same.NewWarningsOmitted != 0 || same.Omitted != 6 {
		t.Errorf("the live policy: %d new warnings counted, %d not listed, omitted %d; want 0, 0 and 6", same.Findings().NewWarnings, same.NewWarningsOmitted, same.Omitted)
	}
}

// The cap on a result cuts the new warnings after the errors and counts the ones it cuts: a
// new warning the result no longer lists is still a new warning to a gate.
func TestANewWarningCutByTheProblemCapIsStillCounted(t *testing.T) {
	var errs []string
	for range 64 {
		errs = append(errs, "user or host is invalid: tag not found")
	}
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.TestsFailed(apitest.Entry{User: "tag:u", Errors: errs, Warnings: []string{"w1", "w2", "w3"}}))
	out := validateOnline(t, env, `{"policy":`+jsonString(liveText+"// a comment\n")+`}`)
	if out.Status != "unresolved" || len(out.Errors) != 64 || len(out.NewWarnings) != 0 || out.NewWarningsOmitted != 3 || out.Findings().NewWarnings != 3 {
		t.Errorf("status %q, %d errors, %d new listed, %d new not listed, %d counted; want unresolved, 64, 0, 3 and 3",
			out.Status, len(out.Errors), len(out.NewWarnings), out.NewWarningsOmitted, out.Findings().NewWarnings)
	}
}

// An empty policy is no policy: a call that gives neither a policy nor a patch validates the
// live policy, and the result says so, since a caller that meant to send a text and sent an
// empty one must not read the pass as the pass of its text.
func TestACallWithNothingToValidateSaysItValidatedTheLivePolicy(t *testing.T) {
	f, _, env := apiEnv(t)
	kenv, _ := keyed(t, env)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	for _, args := range []string{`{}`, `{"policy":""}`, `{"policy":"","patch":""}`} {
		if out := validateOnline(t, kenv, args); !out.ValidatedLive || out.Status != "pass" || !out.IdenticalToLive {
			t.Errorf("%s: validatedLive %v, status %q, identical %v; want the live policy, validated", args, out.ValidatedLive, out.Status, out.IdenticalToLive)
		}
	}
	for name, args := range map[string]string{
		"a policy": `{"policy":` + jsonString(liveText+"// a comment\n") + `}`,
		"a patch":  `{"patch":` + jsonString(`[{"op":"add","path":"/hosts","value":{"edge":"192.0.2.9"}}]`) + `}`,
	} {
		if out := validateOnline(t, kenv, args); out.ValidatedLive {
			t.Errorf("%s: the result says the live policy was validated", name)
		}
	}
	if offlineValidate(t, liveText).ValidatedLive {
		t.Error("a text checked here only is not the live policy")
	}
}
