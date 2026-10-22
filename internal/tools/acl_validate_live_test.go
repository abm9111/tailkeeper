package tools_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// A key written twice in the live policy is a notice, not an error: Tailscale stored the
// policy, and says so when it would refuse it now. The same in a proposal is an error.
func TestARepeatedKeyInTheLivePolicyIsANotice(t *testing.T) {
	f, _, env := apiEnv(t)
	repeated := "{\n\"groups\": {},\n\"groups\": {}\n}\n"
	serveLive(f, repeated, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	out := validateOnline(t, env, `{}`)
	if out.Status != "pass" || len(out.Errors) != 0 || len(out.Notices) != 1 {
		t.Fatalf("status %q, errors %+v, notices %+v", out.Status, out.Errors, out.Notices)
	}
	n := out.Notices[0]
	if n.Kind != "duplicate_key" || n.Severity != "notice" || n.Source != "live" || n.Line != 3 ||
		n.Message != "Tailscale stored this policy with a key written twice here (also at line 2) but would refuse it now" {
		t.Errorf("notice = %+v", n)
	}
	// A section this version does not know is accepted by Tailscale, and said so.
	f2, _, env2 := apiEnv(t)
	serveLive(f2, "{\n\"newThing\": {}\n}\n", nil, nil)
	f2.ServeValidate(apitest.TestsPassEmptyObject())
	unknown := validateOnline(t, env2, `{}`)
	if unknown.Status != "pass" || len(unknown.Notices) != 1 || !strings.Contains(unknown.Notices[0].Message, "accepted the section \"newThing\"") {
		t.Errorf("unknown section in the live policy: %+v", unknown)
	}
}

// A live policy this version cannot read is unknown and nothing is sent: there is nothing
// to compare with.
func TestALivePolicyThatCannotBeReadIsUnknownAndNothingIsSent(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, "[]", nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	out := validateOnline(t, env, `{}`)
	if out.Status != "unknown" || out.ExitCode() != 1 || out.ServerChecked || len(out.Errors) != 1 ||
		!strings.HasPrefix(out.Errors[0].Message, "this version of tailkeeper cannot read the live policy, so nothing was sent: ") {
		t.Errorf("result = %+v", out)
	}
	for _, r := range f.Requests() {
		if r.Method == "POST" {
			t.Error("a validate request was sent")
		}
	}
}

// Stored errors make a validation of the live policy rejected, with them in serverErrors and
// nothing sent; with a proposal they are information and the proposal decides.
func TestStoredErrorsOfLiveMakeAValidateOfLiveRejected(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, []string{"policy no longer parses: tag:gone for amy@example.com"})
	f.ServeValidate(apitest.TestsPassEmptyObject())
	out := validateOnline(t, env, `{}`)
	if out.Status != "rejected" || out.ExitCode() != 2 || out.ServerChecked || len(out.ServerErrors) != 1 ||
		out.ServerErrors[0] != "policy no longer parses: tag:gone for a…@example.com" {
		t.Fatalf("result = %+v", out)
	}
	for _, r := range f.Requests() {
		if r.Method == "POST" {
			t.Error("a validate request was sent for a live policy that has stored errors")
		}
	}
	with := validateOnline(t, env, `{"policy":`+jsonString(liveText+"// proposed\n")+`}`)
	if with.Status != "pass" || len(with.ServerErrors) != 1 {
		t.Errorf("with a proposal: status %q, serverErrors %v", with.Status, with.ServerErrors)
	}
}

// Stored errors short-cut only the live policy itself: a patch is a different text, which may be
// the very change that fixes them, so it is sent, its verdict is returned, and the stored errors
// are still listed.
func TestAPatchAgainstALivePolicyWithStoredErrorsIsSentAndItsVerdictReturned(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, []string{"policy no longer parses: tag:gone"})
	f.ServeValidate(apitest.TestsPassEmptyObject())
	out := validateOnline(t, env, patchCall(`[{"op":"add","path":"/hosts","value":{"edge":"203.0.113.9"}}]`))
	if out.Status != "pass" || !out.ServerChecked || len(out.ServerErrors) != 1 || out.ServerErrors[0] != "policy no longer parses: tag:gone" {
		t.Fatalf("status %q, serverChecked %v, serverErrors %q", out.Status, out.ServerChecked, out.ServerErrors)
	}
	posts := 0
	for _, r := range f.Requests() {
		if r.Method == "POST" {
			posts++
		}
	}
	if posts != 1 {
		t.Errorf("%d validate requests were sent, want 1", posts)
	}
}

// A text that is the live policy byte for byte has no new warnings by definition: its
// warnings are the baseline, whatever the details read called them.
func TestAByteIdenticalTextHasNoNewWarnings(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.TestsWarned(apitest.Entry{User: "tag:ci", Warnings: []string{"tag:ci owns nothing"}}))
	same := validateOnline(t, env, `{"policy":`+jsonString(liveText)+`}`)
	if same.Status != "pass" || !same.IdenticalToLive || len(same.NewWarnings) != 0 || len(same.ExistingWarnings) != 1 {
		t.Errorf("identical: %+v", same)
	}
	changed := validateOnline(t, env, `{"policy":`+jsonString(liveText+"// a comment\n")+`}`)
	if changed.IdenticalToLive || len(changed.NewWarnings) != 1 || len(changed.ExistingWarnings) != 0 {
		t.Errorf("not identical: %+v", changed)
	}
	live := validateOnline(t, env, `{}`)
	if !live.IdenticalToLive || len(live.NewWarnings) != 0 {
		t.Errorf("validating live: %+v", live)
	}
}

// The counts are of the validated text against the live policy, by class, and the tests on
// each side. Adding a wildcard to a source is a widening and a change.
func TestClassCountsAgainstLive(t *testing.T) {
	proposal := strings.Replace(liveText, `"src": ["tag:ci"]`, `"src": ["*"]`, 1)
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	out := validateOnline(t, env, `{"policy":`+jsonString(proposal)+`}`)
	if c := out.Changes; c == nil || c.Widening != 1 || c.Defaults != 0 || c.TestsReduced != 0 || c.TailscaleWritten != 0 {
		t.Fatalf("changes = %+v", out.Changes)
	}
	if got := out.Findings(); got.Widenings != 1 || got.Changes < 1 || got.NewWarnings != 0 {
		t.Errorf("findings = %+v", got)
	}
	rep := out.Report()
	if len(rep.Classes) != 5 || rep.Classes[2].Class != "widening" || rep.Classes[2].Count != 1 || !rep.Classes[3].Expected {
		t.Errorf("classes = %+v", rep.Classes)
	}
	// Removing the only test of the live policy is a reduction of the tests.
	f2, _, env2 := apiEnv(t)
	withTest := strings.Replace(liveText, "\n}\n", "\n\t\"tests\": [{\"src\": \"tag:ci\", \"accept\": [\"tag:ci:22\"]}],\n}\n", 1)
	serveLive(f2, withTest, nil, nil)
	f2.ServeValidate(apitest.TestsPassEmptyObject())
	less := validateOnline(t, env2, `{"policy":`+jsonString(liveText)+`}`)
	if less.Changes.TestsReduced != 1 || less.TestsBefore != 1 || less.TestsAfter != 0 {
		t.Errorf("tests reduced: changes %+v, tests %d to %d", less.Changes, less.TestsBefore, less.TestsAfter)
	}
	// Validating the live policy differs in nothing, and counts its tests on both sides.
	live := validateOnline(t, env2, `{}`)
	if (*live.Changes != tools.ACLChangeCounts{}) || live.TestsBefore != 1 || live.TestsAfter != 1 {
		t.Errorf("live: %+v, tests %d to %d", live.Changes, live.TestsBefore, live.TestsAfter)
	}
}

// What a reply may put in a result is capped: 64 entries of 64 messages are read, a result
// carries 64 problems, and the rest is counted.
func TestAReplyIsCappedAndTheRestIsCounted(t *testing.T) {
	var entries []apitest.Entry
	for i := 0; i < 70; i++ {
		var errs []string
		for j := 0; j < 70; j++ {
			errs = append(errs, "user or host is invalid: tag not found")
		}
		entries = append(entries, apitest.Entry{User: "tag:u", Errors: errs})
	}
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.TestsFailed(entries...))
	out := validateOnline(t, env, `{}`)
	if out.Status != "unresolved" || len(out.Errors) != 64 {
		t.Fatalf("status %q, %d problems; want unresolved and 64", out.Status, len(out.Errors))
	}
	// 804 messages lie past the 64 entries of 64 that are read, and 4,032 of the 4,096 read are
	// past the 64 problems a result carries: every message that is not shown is counted.
	if want := 70*70 - 64; out.Omitted != want {
		t.Errorf("omitted = %d, want %d", out.Omitted, want)
	}
}

// The caps multiply: 64 entries of 64 messages, each quoting a name the proposal holds in 12
// places, is 4,096 messages of 8 problems each. The result carries 64 problems and counts the
// other 32,704, so that a hostile or merely noisy reply cannot make the result undeliverable;
// and the size of what is left is the size of 64 problems.
func TestTheWorstReplyIsCutToTheProblemCapAndStaysSmall(t *testing.T) {
	var b strings.Builder
	b.WriteString("{\n\"hosts\": {\n")
	for i := 0; i < 12; i++ {
		fmt.Fprintf(&b, "\"h%d\": \"tag:a\",\n", i)
	}
	b.WriteString("}\n}\n")
	var entries []apitest.Entry
	for i := 0; i < 64; i++ {
		var errs []string
		for j := 0; j < 64; j++ {
			errs = append(errs, `user or host is invalid: tag not found: "tag:a"`)
		}
		entries = append(entries, apitest.Entry{User: fmt.Sprintf("tag:u%d", i), Errors: errs})
	}
	out := validateProposal(t, apitest.TestsFailed(entries...), b.String())
	if out.Status != "unresolved" || len(out.Errors) != 64 {
		t.Fatalf("status %q, %d problems; want unresolved and 64", out.Status, len(out.Errors))
	}
	if want := 64*64*8 - 64; out.Omitted != want {
		t.Errorf("omitted = %d, want %d: every problem not shown is counted", out.Omitted, want)
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > 64<<10 {
		t.Errorf("the result is %d bytes as JSON; 64 problems of this kind are about 20 KiB", len(encoded))
	}
}

// A failure that lies past the entries a result reads is not a pass, and is not lost: the
// status is unknown, and a note says why. The first 64 entries here hold only warnings.
func TestAFailureOnlyPastTheEntriesReadIsUnknownNeverAPass(t *testing.T) {
	var entries []apitest.Entry
	for i := 0; i < 64; i++ {
		entries = append(entries, apitest.Entry{User: fmt.Sprintf("tag:w%d", i), Warnings: []string{"tag owns nothing"}})
	}
	entries = append(entries, apitest.Entry{User: "tag:late", Errors: []string{`[acl test error]: address "tag:ci:22": want: Accept, got: Drop`}})
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.TestsFailed(entries...))
	out := validateOnline(t, env, `{}`)
	if out.Status != "unknown" || out.ExitCode() != 1 || out.Omitted < 1 {
		t.Fatalf("status %q exit %d omitted %d; want unknown, 1 and a count", out.Status, out.ExitCode(), out.Omitted)
	}
	if len(out.Errors) != 1 || !strings.Contains(out.Errors[0].Message, "past the entries of the reply that are read") {
		t.Errorf("errors = %+v, want one note that says the failure was not read", out.Errors)
	}
}

// A warning is existing only when the live policy's stored warnings hold it word for word, as
// its text or as the element it names, a colon and its text. A warning worded in any other
// way reads as new, the side a gate wants: if Tailscale words a stored warning differently in
// the two places, the gate fails where it should have passed, and never the other way. A text
// that is not the live policy byte for byte is used here, since an identical one reads every
// warning as existing without looking at the stored ones.
func TestAWarningThatMatchesNoStoredWarningWordForWordIsNew(t *testing.T) {
	for name, c := range map[string]struct {
		stored, user, warning string
		existing              bool
	}{
		"the same text":                  {`host alias "old" is unused`, "old", `host alias "old" is unused`, true},
		"the element, a colon, the text": {`old: host alias "old" is unused`, "old", `host alias "old" is unused`, true},
		"another element":                {`old: host alias "old" is unused`, "other", `host alias "old" is unused`, false},
		"a full stop more":               {`host alias "old" is unused.`, "old", `host alias "old" is unused`, false},
		"another case":                   {`Host alias "old" is unused`, "old", `host alias "old" is unused`, false},
		"another spacing":                {`host alias  "old" is unused`, "old", `host alias "old" is unused`, false},
	} {
		f, _, env := apiEnv(t)
		serveLive(f, liveText, []string{c.stored}, nil)
		f.ServeValidate(apitest.TestsWarned(apitest.Entry{User: c.user, Warnings: []string{c.warning}}))
		out := validateOnline(t, env, `{"policy":`+jsonString(liveText+"// a comment\n")+`}`)
		if out.IdenticalToLive {
			t.Fatalf("%s: the text is the live policy, so the baseline was not consulted", name)
		}
		if got := len(out.ExistingWarnings) == 1 && len(out.NewWarnings) == 0; got != c.existing {
			t.Errorf("%s: existing %+v, new %+v; want existing: %v", name, out.ExistingWarnings, out.NewWarnings, c.existing)
		}
		if got := out.Findings().NewWarnings; (got == 0) != c.existing {
			t.Errorf("%s: --fail-on warnings counts %d new warnings", name, got)
		}
	}
}

// Every shape the ledger holds that is not a pass is never a pass through the tool: the
// Assumed ones, which nobody has seen the API send, and the Observed ones that are rejections
// and failures. The two passes, and warnings alone, are passes: without them a tool that
// never passed anything would satisfy the loop.
func TestEveryAssumedAndNonPassObservedShapeIsNeverAPassThroughTheTool(t *testing.T) {
	passes := map[string]bool{"TestsPass": true, "TestsPassEmptyObject": true, "TestsWarned": true}
	seen, passed := 0, 0
	for _, s := range apitest.AllShapes() {
		if s.Endpoint != apitest.EndpointValidate {
			continue
		}
		f, _, env := apiEnv(t)
		serveLive(f, liveText, nil, nil)
		f.ServeValidate(s)
		out, err := call(t, newRegistry(t), env, "acl_validate", `{}`)
		isPass := err == nil && strings.Contains(out, `"status":"pass"`)
		switch {
		case passes[s.Name]:
			passed++
			if !isPass {
				t.Errorf("%s (%s) is a pass and did not read as one: %s %v", s.Name, s.Prov, out, err)
			}
		default:
			seen++
			if isPass {
				t.Errorf("%s (%s) read as a pass through acl_validate", s.Name, s.Prov)
			}
		}
	}
	if seen < 12 || passed != 3 {
		t.Errorf("the loop walked %d shapes that are not passes and %d that are: it is not walking the ledger", seen, passed)
	}
}

// A 500 that comes twice is policy_rejected_or_server_error: the call was retried once, the
// message names the digest of the masked form of what was sent and repeats nothing of the
// reply, and the hint names the target that fails every send.
func TestA500TwiceNamesThePolicyHashAndAutogroupSelf(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.PolicyServerError500())
	proposal := "{\n\"hosts\": {\"edge\": \"203.0.113.9\"},\n\"nodeAttrs\": [{\"target\": [\"autogroup:self\"], \"attr\": [\"x\"]}]\n}\n"
	_, err := call(t, newRegistry(t), env, "acl_validate", `{"policy":`+jsonString(proposal)+`}`)
	e, ok := tkerr.As(err)
	if !ok || e.Code != tkerr.PolicyRejectedOrServerError || tkerr.ExitCode(err) != 1 {
		t.Fatalf("err = %v, want policy_rejected_or_server_error", err)
	}
	sum := sha256.Sum256([]byte(proposal))
	if !strings.Contains(e.Message, "(policy sha256 "+hex.EncodeToString(sum[:])+")") || !strings.Contains(e.Hint, "autogroup:self") {
		t.Errorf("message %q, hint %q", e.Message, e.Hint)
	}
	absent(t, err.Error(), "internal server error", "203.0.113.9", "edge")
	posts := 0
	for _, r := range f.Requests() {
		if r.Method == "POST" {
			posts++
		}
	}
	if posts != 2 {
		t.Errorf("%d POSTs, want 2: sent, retried once", posts)
	}
}

// The digest of what was sent is the one acl_get shows for the same text, the digest of the
// masked form: a digest of the file itself would confirm a guessed address. A live policy that
// holds an address tells the two apart (the policy above holds none, so both digests agree).
func TestThe500DigestIsTheMaskedFormsWhenThePolicyHoldsAnAddress(t *testing.T) {
	withAddress := "{\n\t\"groups\": {\"group:eng\": [\"christopher@example.com\"]},\n}\n"
	f, _, env := apiEnv(t)
	serveLive(f, withAddress, nil, nil)
	f.ServeValidate(apitest.PolicyServerError500())
	_, err := call(t, newRegistry(t), env, "acl_validate", `{}`)
	e, ok := tkerr.As(err)
	if !ok || e.Code != tkerr.PolicyRejectedOrServerError {
		t.Fatalf("err = %v, want policy_rejected_or_server_error", err)
	}
	var get tools.ACLGetOutput
	mustCall(t, newRegistry(t), env, "acl_get", `{"view":"summary"}`, &get)
	raw := sha256.Sum256([]byte(withAddress))
	if get.PolicySHA256 == hex.EncodeToString(raw[:]) {
		t.Fatal("acl_get shows the digest of the file itself, so the test cannot tell the two apart")
	}
	if want := "(policy sha256 " + get.PolicySHA256 + ")"; !strings.Contains(e.Message, want) {
		t.Errorf("message %q does not carry acl_get's digest %s", e.Message, want)
	}
	absent(t, err.Error(), hex.EncodeToString(raw[:]), "christopher")
}

// limitedEnv is an environment whose client takes perMinute validation tokens a minute on a
// clock that does not move, so that the bucket empties and stays empty.
func limitedEnv(t *testing.T, f *apitest.Fake, perMinute int) *registry.Env {
	t.Helper()
	c, err := api.New(context.Background(), apitest.Tailnet,
		creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID, ClientSecret: creds.NewSecret(apitest.ClientSecret), Provider: "env"},
		api.Options{BaseURL: f.URL(), ValidatePerMinute: perMinute, Now: func() time.Time { return now }, Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	return &registry.Env{API: c, Now: func() time.Time { return now }}
}

// The bucket has two tokens at a rate of one a minute; a call takes one for its one policy,
// and a retry inside the call takes none: the third call is the one that waits, and it waits
// sixty seconds.
func TestARetryWithinACallDrawsNoTokenAndAnEmptyBucketSaysHowLong(t *testing.T) {
	f := apitest.New(t)
	serveLive(f, liveText, nil, nil)
	attempts := 0
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, _ *http.Request) {
		if attempts++; attempts == 1 {
			apitest.PolicyServerError500().Write(w)
			return
		}
		apitest.TestsPassEmptyObject().Write(w)
	})
	env := limitedEnv(t, f, 1)
	reg := newRegistry(t)
	for i := 1; i <= 2; i++ {
		if out, err := call(t, reg, env, "acl_validate", `{}`); err != nil || !strings.Contains(out, `"status":"pass"`) {
			t.Fatalf("call %d: %s, %v; want a pass (the first had a 500 and a retry that drew no token)", i, out, err)
		}
	}
	_, err := call(t, reg, env, "acl_validate", `{}`)
	e, ok := tkerr.As(err)
	if !ok || e.Code != tkerr.ValidateRateLimited || e.RetryAfterSeconds != 60 || !strings.Contains(e.Message, "try again in 60 s") || tkerr.ExitCode(err) != 1 {
		t.Fatalf("third call: %v, want validate_rate_limited, 60 seconds, exit 1", err)
	}
}
