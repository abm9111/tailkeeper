package tools_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// invariantsText is an owner's invariants file: a multi-line block with comments, and an SSH
// test. Its failing test is the one on line 5.
const invariantsText = "// the owner's invariants\n" + // 1
	"{\n" + // 2
	"\t\"tests\": [\n" + // 3
	"\t\t// the web tier never reaches ci\n" + // 4
	"\t\t{\n" + // 5
	"\t\t\t\"src\": \"tag:web\",\n" + // 6
	"\t\t\t\"deny\": [\"tag:ci:22\"],\n" + // 7
	"\t\t},\n" + // 8
	"\t\t{\"src\": \"tag:ci\", \"accept\": [\"tag:ci:22\"]},\n" + // 9
	"\t],\n" + // 10
	"\t\"sshTests\": [\n" + // 11
	"\t\t{\"src\": \"tag:ci\", \"dst\": [\"tag:ci\"], \"accept\": [\"root\"]},\n" + // 12
	"\t],\n" + // 13
	"}\n" // 14

var canaryTagRE = regexp.MustCompile(`tag:tailkeeper-canary-[0-9a-f]{8}`)

// canaryLine is how the live API reports the canary's failure: the denial fails when the
// policy has no acls (probe A-9).
const canaryLine = `[acl test error]: address "192.0.2.1:1" (protocol "tcp"): want: Drop, got: Accept`

const failingInvariant = `[acl test error]: address "tag:ci:22": want: Drop, got: Accept`

// serveInvariants models the validate endpoint for a call with invariants: the first POST
// carries the policy's own tests and passes; the second carries a canary, and answer builds
// its reply from the canary's tag.
func serveInvariants(f *apitest.Fake, answer func(canary string) apitest.Shape) {
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		if tag := canaryTagRE.FindString(body.String()); tag != "" {
			answer(tag).Write(w)
			return
		}
		apitest.TestsPassEmptyObject().Write(w)
	})
}

// validateWith validates the live policy with the invariants text, as the command line does.
func validateWith(t *testing.T, env *registry.Env, invariants string, mod ...func(*tools.ACLValidateInput)) (tools.ACLValidateOutput, error) {
	t.Helper()
	return runValidate(t, env, func(in *tools.ACLValidateInput) {
		in.Invariants, in.Operator = invariants, true
		for _, m := range mod {
			m(in)
		}
	})
}

func canaryEntry(tag string) apitest.Entry {
	return apitest.Entry{User: tag, Errors: []string{canaryLine}}
}

func TestLiveWithAPlantedFailingInvariantExits9(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, peoplePolicy, nil, nil)
	serveInvariants(f, func(tag string) apitest.Shape {
		return apitest.TestsFailed(canaryEntry(tag), apitest.Entry{User: "tag:web", Errors: []string{failingInvariant}})
	})
	out, err := validateWith(t, env, invariantsText)
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "fail" || out.ExitCode() != 9 || out.InvariantsApplied != 3 || out.InvariantsSignature != "none" || contains(out.NotChecked, "invariants") {
		t.Fatalf("result = %+v", out)
	}
	if len(out.Errors) != 1 {
		t.Fatalf("errors = %+v, want the one failed invariant and no canary", out.Errors)
	}
	p := out.Errors[0]
	if p.Kind != "invariant" || p.Source != "invariants" || p.Line != 5 || p.Pointer != "/tests/0" || p.Message != failingInvariant || strings.Contains(p.Message, "192.0.2.1") {
		t.Errorf("problem = %+v", p)
	}
	if v := out.Report().Verdict; v != "FAILED · 1 failed assertion · invariants: 3 tests ran" {
		t.Errorf("verdict = %q", v)
	}
	if got := posts(f); got != 2 {
		t.Errorf("%d validation requests, want two: the text, then the text with the invariants", got)
	}
}

// Invariants that pass leave a pass, counted.
func TestInvariantsThatPassAreCounted(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, peoplePolicy, nil, nil)
	serveInvariants(f, func(tag string) apitest.Shape { return apitest.TestsFailed(canaryEntry(tag)) })
	out, err := validateWith(t, env, invariantsText)
	if err != nil || out.Status != "pass" || out.InvariantsApplied != 3 || len(out.Errors) != 0 {
		t.Fatalf("result = %+v, %v", out, err)
	}
	if v := out.Report().Verdict; v != "VALID · 0 new warnings (0 existing) · 2 tests passed · invariants: 3 tests passed" {
		t.Errorf("verdict = %q", v)
	}
}

// The canary is the proof that the invariants ran: a clean pass, a canary that is missing,
// unevaluable, twice, or with a second error, is unknown, never a pass.
func TestAMissingCanaryIsUnknownAndExits1(t *testing.T) {
	for name, answer := range map[string]func(tag string) apitest.Shape{
		"a clean pass": func(string) apitest.Shape { return apitest.TestsPassEmptyObject() },
		"only the failure": func(string) apitest.Shape {
			return apitest.TestsFailed(apitest.Entry{User: "tag:web", Errors: []string{failingInvariant}})
		},
		"the canary unevaluable": func(tag string) apitest.Shape {
			return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{"[acl test error]: user or host is invalid: tag not found"}})
		},
		"the canary twice": func(tag string) apitest.Shape {
			return apitest.TestsFailed(canaryEntry(tag), canaryEntry(tag))
		},
		"the canary with a second error": func(tag string) apitest.Shape {
			return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine, failingInvariant}})
		},
		"the canary with a warning": func(tag string) apitest.Shape {
			return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}, Warnings: []string{"w"}})
		},
	} {
		f, _, env := apiEnv(t)
		serveLive(f, peoplePolicy, nil, nil)
		serveInvariants(f, answer)
		out, err := validateWith(t, env, invariantsText)
		if err != nil || out.Status != "unknown" || out.ExitCode() != 1 || out.InvariantsApplied != 0 {
			t.Errorf("%s: status %q exit %d applied %d, err %v; want unknown, exit 1, none applied", name, out.Status, out.ExitCode(), out.InvariantsApplied, err)
		}
	}
}

// A first answer that makes the second pointless skips it, says so, and gives the token back:
// the bucket of two tokens is left with one, and a call without invariants can still use it.
// Had the token not come back, that call would wait.
func TestTheSecondPostIsSkippedAndRefundedWhenTheFirstIsRejected(t *testing.T) {
	f := apitest.New(t)
	serveLive(f, peoplePolicy, nil, nil)
	f.ServeValidate(apitest.BareMessage200("json: unknown field \"nodeAttr\""))
	env := limitedEnv(t, f, 1)
	out, err := validateWith(t, env, invariantsText)
	if err != nil || out.Status != "rejected" || !contains(out.NotChecked, "invariants") || out.InvariantsApplied != 0 || len(out.Notices) != 1 {
		t.Fatalf("with invariants: %+v, %v; want rejected, the invariants not checked and a notice that says so", out, err)
	}
	if got := posts(f); got != 1 {
		t.Errorf("%d validation requests, want 1: the second is never sent", got)
	}
	plain, err := runValidate(t, env, func(in *tools.ACLValidateInput) { in.NoInvariants, in.Operator = true, true })
	if err != nil || plain.Status != "rejected" {
		t.Fatalf("the call that uses the token that came back: %+v, %v", plain, err)
	}
	_, err = runValidate(t, env, func(in *tools.ACLValidateInput) { in.NoInvariants, in.Operator = true, true })
	if code(err) != tkerr.ValidateRateLimited {
		t.Errorf("a third call: err = %v, want validate_rate_limited: the bucket is empty", err)
	}
}

// A first answer that tailkeeper cannot read as a verdict is not one the invariants can be
// added to: the second request is skipped like the one after a rejection, the result says so,
// and the status stays unknown.
func TestTheSecondPostIsSkippedWhenTheFirstAnswerIsNotOneTailkeeperReads(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, peoplePolicy, nil, nil)
	f.ServeValidate(apitest.ErrorsListAt200("something else"))
	out, err := validateWith(t, env, invariantsText)
	if err != nil || out.Status != "unknown" || out.ExitCode() != 1 || !contains(out.NotChecked, "invariants") || out.InvariantsApplied != 0 {
		t.Fatalf("result = %+v, %v; want unknown, exit 1 and the invariants not checked", out, err)
	}
	if got := posts(f); got != 1 {
		t.Errorf("%d validation requests, want 1: the invariants are not run after an answer that is not read", got)
	}
	if len(out.Notices) != 1 || !strings.Contains(out.Notices[0].Message, "invariants were not run") {
		t.Errorf("notices = %+v, want one that says the invariants were not run", out.Notices)
	}
}

// An invariants file with no tests runs nothing, and the second request that would carry only
// the canary is not sent to find that out.
func TestAnInvariantsFileWithNoTestsSendsOneRequest(t *testing.T) {
	for _, text := range []string{"{}", `{"tests": [], "sshTests": []}`} {
		f, _, env := apiEnv(t)
		serveLive(f, peoplePolicy, nil, nil)
		serveInvariants(f, func(tag string) apitest.Shape { return apitest.TestsFailed(canaryEntry(tag)) })
		out, err := validateWith(t, env, text)
		if err != nil || out.Status != "pass" || out.InvariantsApplied != 0 || len(out.Notices) != 1 || !strings.Contains(out.Notices[0].Message, "holds no tests") {
			t.Fatalf("%s: %+v, %v; want a pass with a notice that no test was run", text, out, err)
		}
		if got := posts(f); got != 1 {
			t.Errorf("%s: %d validation requests, want 1", text, got)
		}
	}
}

// Every call picks the canary's tag at random, so that a policy cannot contain it by accident
// or by design: the tag is eight hexadecimal digits after the prefix, and no two calls share
// one.
func TestEveryCallChoosesAFreshCanaryTag(t *testing.T) {
	var tags []string
	f, _, env := apiEnv(t)
	serveLive(f, peoplePolicy, nil, nil)
	serveInvariants(f, func(tag string) apitest.Shape {
		tags = append(tags, tag)
		return apitest.TestsFailed(canaryEntry(tag))
	})
	for i := 0; i < 3; i++ {
		if out, err := validateWith(t, env, invariantsText); err != nil || out.Status != "pass" {
			t.Fatalf("call %d: %+v, %v", i, out, err)
		}
	}
	whole := regexp.MustCompile(`^tag:tailkeeper-canary-[0-9a-f]{8}$`)
	seen := map[string]bool{}
	for _, tag := range tags {
		if !whole.MatchString(tag) || seen[tag] {
			t.Errorf("tags %v: %q is not eight hexadecimal digits after the prefix, or was used before", tags, tag)
		}
		seen[tag] = true
	}
	if len(tags) != 3 {
		t.Errorf("%d canary tags seen, want 3", len(tags))
	}
}

// --invariants replaces the configured file and --no-invariants removes it: both together
// contradict each other, and a script that passes both is refused, not obeyed in one way.
func TestTheTwoInvariantsFlagsTogetherAreRefused(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, peoplePolicy, nil, nil)
	_, err := validateWith(t, env, invariantsText, func(in *tools.ACLValidateInput) { in.NoInvariants = true })
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ValidationFailed || !strings.Contains(e.Message, "not both") {
		t.Errorf("err = %v, want validation_failed saying not both", err)
	}
	if n := len(f.Requests()); n != 0 {
		t.Errorf("%d requests for a refused call", n)
	}
}

// Two posts take two tokens at once, before the first request: at a rate of one a minute a
// call with invariants empties the bucket of two, and the next call waits two minutes for its
// two.
func TestTwoPostsTakeTwoTokens(t *testing.T) {
	f := apitest.New(t)
	serveLive(f, peoplePolicy, nil, nil)
	serveInvariants(f, func(tag string) apitest.Shape { return apitest.TestsFailed(canaryEntry(tag)) })
	env := limitedEnv(t, f, 1)
	if out, err := validateWith(t, env, invariantsText); err != nil || out.Status != "pass" {
		t.Fatalf("the first call: %+v, %v", out, err)
	}
	_, err := validateWith(t, env, invariantsText)
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ValidateRateLimited || e.RetryAfterSeconds != 120 {
		t.Errorf("the second call: %v, want validate_rate_limited, 120 seconds: two tokens, at one a minute", err)
	}
}

// The text of the second validation is the text that was sent with its own tests taken out and
// a tail added: what the proposal says elsewhere is not touched.
func TestTheSecondPostCarriesTheOriginalTextPlusATail(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, peoplePolicy, nil, nil)
	serveInvariants(f, func(tag string) apitest.Shape { return apitest.TestsFailed(canaryEntry(tag)) })
	proposal := "// proposed\n{\n\t\"tagOwners\": {\"tag:ci\": [\"autogroup:admin\"], \"tag:web\": []},\n" +
		"\t\"acls\": [{\"action\": \"accept\", \"src\": [\"tag:ci\"], \"dst\": [\"tag:ci:22\"]}],\n" +
		"\t\"tests\": [{\"src\": \"tag:ci\", \"accept\": [\"tag:ci:22\"], \"deny\": [\"192.0.2.77:9\"]}],\n}\n"
	out, err := validateWith(t, env, invariantsText, func(in *tools.ACLValidateInput) { in.Policy = proposal })
	if err != nil || out.Status != "pass" {
		t.Fatalf("result = %+v, %v", out, err)
	}
	var first, second []byte
	for _, r := range f.Requests() {
		if r.Method == "POST" {
			if first == nil {
				first = r.Body
			} else {
				second = r.Body
			}
		}
	}
	if string(first) != proposal {
		t.Fatalf("the first POST is not the proposal:\n%s", first)
	}
	s := string(second)
	if !strings.HasPrefix(s, "// proposed\n{\n\t\"tagOwners\": {\"tag:ci\": [\"autogroup:admin\"], \"tag:web\": []") ||
		!strings.Contains(s, `"acls": [{"action": "accept", "src": ["tag:ci"], "dst": ["tag:ci:22"]}]`) {
		t.Errorf("the second POST does not begin with the proposal:\n%s", s)
	}
	if strings.Contains(s, "192.0.2.77") {
		t.Errorf("the proposal's own test is still in the second POST:\n%s", s)
	}
	canary := canaryTagRE.FindString(s)
	if canary == "" || strings.Count(s, canary) != 2 || !strings.Contains(s, `"deny":["192.0.2.1:1"]`) && !strings.Contains(s, `"deny": ["192.0.2.1:1"]`) {
		t.Errorf("the canary is not in the tail exactly as a tag and a test:\n%s", s)
	}
	// The tail holds the invariants' tests with their comments, and its text parses.
	doc, err := acl.Parse(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := acl.Summarise(context.Background(), doc)
	if err != nil || sum.Tests != 3 || sum.SSHTests != 1 || len(doc.Findings()) != 0 || !strings.Contains(s, "// the web tier never reaches ci") {
		t.Errorf("tests %d, ssh %d, findings %v, err %v", sum.Tests, sum.SSHTests, doc.Findings(), err)
	}
}

// The canary's tag joins the tagOwners the text already has under its own spelling, or makes
// one: a second tagOwners would be a repeated key, which Tailscale refuses.
func TestTheCanaryJoinsATagOwnersWrittenInAnotherCaseOrMakesOne(t *testing.T) {
	for name, live := range map[string]string{
		"another case":  "{\n\"TagOwners\": {\"tag:ci\": [\"autogroup:admin\"]},\n\"acls\": []\n}\n",
		"absent":        "{\n\"acls\": []\n}\n",
		"null":          "{\n\"tagOwners\": null,\n\"acls\": []\n}\n",
		"an empty one":  "{\n\"tagOwners\": {},\n\"acls\": []\n}\n",
		"a lower case":  "{\n\"tagowners\": {\"tag:ci\": []}\n}\n",
		"with comments": "{\n// owners\n\"tagOwners\": {\n// ci\n\"tag:ci\": [\"autogroup:admin\"]},\n\"acls\": []\n}\n",
	} {
		f, _, env := apiEnv(t)
		serveLive(f, live, nil, nil)
		serveInvariants(f, func(tag string) apitest.Shape { return apitest.TestsFailed(canaryEntry(tag)) })
		out, err := validateWith(t, env, invariantsText)
		if err != nil || out.Status != "pass" {
			t.Errorf("%s: %+v, %v", name, out, err)
			continue
		}
		second := lastPost(f)
		doc, err := acl.Parse(context.Background(), second)
		if err != nil {
			t.Errorf("%s: the second POST does not parse: %v", name, err)
			continue
		}
		sum, _ := acl.Summarise(context.Background(), doc)
		canary := canaryTagRE.FindString(string(second))
		found := false
		for _, n := range sum.TagOwners {
			found = found || n == canary
		}
		if len(doc.Findings()) != 0 || !found {
			t.Errorf("%s: findings %v, tagOwners %v, canary %q:\n%s", name, doc.Findings(), sum.TagOwners, canary, second)
		}
	}
}

// A text that does not hold exactly the invariants and the canary is not sent. A strip that
// misses a test is refused by the append, which will not write a second tests section; an
// append that adds a test too many is refused by the count of what was built.
func TestTheTestCountGuardRefusesBeforeSending(t *testing.T) {
	extra := []byte(`{"src": "tag:ci", "accept": ["192.0.2.50:5"]}`)
	for name, plant := range map[string]func() func(){
		"a strip that misses a test": func() func() {
			return tools.SetStripTests(func(_ context.Context, text []byte) ([]byte, error) { return text, nil })
		},
		"an append that adds a test": func() func() {
			return tools.SetAppendTests(func(ctx context.Context, text []byte, tests, ssh [][]byte) ([]byte, error) {
				return acl.AppendTests(ctx, text, append(tests, extra), ssh)
			})
		},
	} {
		f, _, env := apiEnv(t)
		serveLive(f, peoplePolicy, nil, nil)
		serveInvariants(f, func(tag string) apitest.Shape { return apitest.TestsFailed(canaryEntry(tag)) })
		restore := plant()
		_, err := validateWith(t, env, invariantsText)
		restore()
		if err == nil || code(err) == "" {
			t.Errorf("%s: err = %v, want a refusal", name, err)
		}
		if got := posts(f); got != 1 {
			t.Errorf("%s: %d validation requests, want only the first", name, got)
		}
		if name == "an append that adds a test" && (code(err) != tkerr.Internal || !strings.Contains(err.Error(), "holds 4 tests and 1 SSH tests, and should hold 3 and 1; nothing was sent")) {
			t.Errorf("%s: err = %v, want the count guard's internal_error", name, err)
		}
	}
}

// A failure of the invariants is placed by its line in the invariants file, however many
// lines the strip took out of the policy.
func TestInvariantFailureLinesMapThroughTheInvariantsFile(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, peoplePolicy, nil, nil)
	ssh := `[ssh test error]: src "tag:ci" at "100.64.0.1", dst "tag:ci" at "100.64.0.2", ssh user "root": want: "accept" got: "deny"`
	serveInvariants(f, func(tag string) apitest.Shape {
		return apitest.TestsFailed(canaryEntry(tag), apitest.Entry{User: "tag:web", Errors: []string{failingInvariant}}, apitest.Entry{User: "tag:ci", Errors: []string{ssh}})
	})
	out, err := validateWith(t, env, invariantsText)
	if err != nil || out.Status != "fail" || len(out.Errors) != 2 {
		t.Fatalf("result = %+v, %v", out, err)
	}
	if a, b := out.Errors[0], out.Errors[1]; a.Line != 5 || a.Pointer != "/tests/0" || a.Source != "invariants" || b.Line != 12 || b.Pointer != "/sshTests/0" || b.Source != "invariants" {
		t.Errorf("problems = %+v, %+v; want lines 5 and 12 of the invariants file", a, b)
	}
}

// What a failed invariant says that no assertion failed is unresolved, and the worse of the
// two validations is the status.
func TestTheStatusOfACallIsTheWorseOfItsTwoValidations(t *testing.T) {
	unevaluable := apitest.Entry{User: "tag:web", Errors: []string{"[acl test error]: user or host is invalid: tag not found"}}
	for name, c := range map[string]struct {
		first  apitest.Shape
		second func(tag string) apitest.Shape
		want   string
	}{
		"an invariant that cannot be evaluated": {apitest.TestsPassEmptyObject(), func(tag string) apitest.Shape { return apitest.TestsFailed(canaryEntry(tag), unevaluable) }, "unresolved"},
		"a failed test and a failed invariant":  {apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{failingInvariant}}), func(tag string) apitest.Shape { return apitest.TestsFailed(canaryEntry(tag), unevaluable) }, "fail"},
		"a failed test and a missing canary":    {apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{failingInvariant}}), func(string) apitest.Shape { return apitest.TestsPassEmptyObject() }, "unknown"},
		"a second rejection":                    {apitest.TestsPassEmptyObject(), func(string) apitest.Shape { return apitest.BareMessage200("json: unknown field \"x\"") }, "rejected"},
	} {
		f, _, env := apiEnv(t)
		serveLive(f, peoplePolicy, nil, nil)
		f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
			body := new(bytes.Buffer)
			_, _ = body.ReadFrom(r.Body)
			if tag := canaryTagRE.FindString(body.String()); tag != "" {
				c.second(tag).Write(w)
				return
			}
			c.first.Write(w)
		})
		out, err := validateWith(t, env, invariantsText)
		if err != nil || out.Status != c.want {
			t.Errorf("%s: status %q, err %v, want %q", name, out.Status, err, c.want)
		}
	}
}

// The configured file is the only source over MCP, and a set path that cannot be read is
// config_invalid on every call that uses it.
func TestMCPAlwaysUsesTheConfiguredInvariants(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invariants.hujson")
	if err := os.WriteFile(path, []byte(invariantsText), 0o600); err != nil {
		t.Fatal(err)
	}
	f, _, env := apiEnv(t)
	env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: path}}}
	serveLive(f, peoplePolicy, nil, nil)
	serveInvariants(f, func(tag string) apitest.Shape {
		return apitest.TestsFailed(canaryEntry(tag), apitest.Entry{User: "tag:web", Errors: []string{failingInvariant}})
	})
	out := validateOnline(t, env, `{}`)
	if out.Status != "fail" || out.InvariantsApplied != 3 || len(out.Errors) != 1 || out.Errors[0].Source != "invariants" || out.Errors[0].Line != 5 {
		t.Errorf("result = %+v", out)
	}
	// The command line's file replaces the configured one, and --no-invariants removes both.
	other := "{\"tests\": [{\"src\": \"tag:ci\", \"accept\": [\"tag:ci:22\"]}]}"
	rep, err := validateWith(t, env, other)
	if err != nil || rep.InvariantsApplied != 1 {
		t.Errorf("--invariants: %+v, %v; want the file's one test and not the configured three", rep, err)
	}
	none, err := runValidate(t, env, func(in *tools.ACLValidateInput) { in.NoInvariants, in.Operator = true, true })
	if err != nil || none.InvariantsApplied != 0 || none.Status != "pass" || contains(none.NotChecked, "invariants") {
		t.Errorf("--no-invariants: %+v, %v", none, err)
	}
	// A path that is set and missing is an error, never a silent none.
	env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: filepath.Join(t.TempDir(), "gone.hujson")}}}
	_, err = call(t, newRegistry(t), env, "acl_validate", `{}`)
	if code(err) != tkerr.ConfigInvalid || tkerr.ExitCode(err) != 6 {
		t.Errorf("a missing file: err = %v, want config_invalid (exit 6)", err)
	}
}

// A file that is not an invariants file is an invalid result, with nothing sent: another
// key, a pseudonym, a syntax error.
func TestAnInvariantsFileThatIsNotOneIsInvalidAndNothingIsSent(t *testing.T) {
	for name, text := range map[string]string{
		"another key":    `{"acls": []}`,
		"a pseudonym":    `{"tests": [{"src": "a…@example.com [p:abcdefghij]", "accept": ["tag:ci:22"]}]}`,
		"a syntax error": "{\"tests\": [\n,]}",
	} {
		f, _, env := apiEnv(t)
		serveLive(f, peoplePolicy, nil, nil)
		serveInvariants(f, func(tag string) apitest.Shape { return apitest.TestsFailed(canaryEntry(tag)) })
		out, err := validateWith(t, env, text)
		if err != nil || out.Status != "invalid" || len(out.Errors) == 0 || out.Errors[0].Source != "invariants" || len(f.Requests()) != 0 {
			t.Errorf("%s: %+v, %v, %d requests", name, out.Status, err, len(f.Requests()))
		}
		if !contains(out.NotChecked, "invariants") {
			t.Errorf("%s: notChecked = %v, want the invariants named, since none ran", name, out.NotChecked)
		}
	}
}

// Where no text is sent the invariants cannot run, and the result says so: a proposal that is
// not valid, and a live policy that Tailscale stored with errors.
func TestWhereNoTextIsSentTheInvariantsAreNamedAsNotChecked(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, peoplePolicy, nil, nil)
	serveInvariants(f, func(tag string) apitest.Shape { return apitest.TestsFailed(canaryEntry(tag)) })
	out, err := validateWith(t, env, invariantsText, func(in *tools.ACLValidateInput) { in.Patch = `[{"op":"remove","path":"/nothing"}]` })
	if err != nil || out.Status != "invalid" || !contains(out.NotChecked, "invariants") || posts(f) != 0 {
		t.Errorf("an invalid patch: status %q, notChecked %v, err %v, %d POSTs", out.Status, out.NotChecked, err, posts(f))
	}
	f2, _, env2 := apiEnv(t)
	serveLive(f2, peoplePolicy, nil, []string{"policy no longer parses: tag:gone"})
	serveInvariants(f2, func(tag string) apitest.Shape { return apitest.TestsFailed(canaryEntry(tag)) })
	out, err = validateWith(t, env2, invariantsText)
	if err != nil || out.Status != "rejected" || !contains(out.NotChecked, "invariants") || posts(f2) != 0 {
		t.Errorf("stored errors: status %q, notChecked %v, err %v, %d POSTs", out.Status, out.NotChecked, err, posts(f2))
	}
}

func TestInvariantsSignatureIsNone(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, peoplePolicy, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	for _, out := range []tools.ACLValidateOutput{validateOnline(t, env, `{}`), offlineValidate(t, goodPolicy)} {
		if out.InvariantsSignature != "none" {
			t.Errorf("invariantsSignature = %q, want none: the file is not signed", out.InvariantsSignature)
		}
	}
}

// The reply to the invariants is read as the first reply is: at most 64 entries of 64 lines,
// the rest counted as omitted, and what is read is what the verdict counts. A reader that took
// every entry would state 70 failed assertions.
func TestTheInvariantsReplyIsReadUpToItsCaps(t *testing.T) {
	manyEntries := func(tag string) apitest.Shape {
		entries := []apitest.Entry{canaryEntry(tag)}
		for i := range 70 {
			entries = append(entries, apitest.Entry{User: fmt.Sprintf("tag:w%02d", i), Errors: []string{failingInvariant}})
		}
		return apitest.TestsFailed(entries...)
	}
	manyLines := func(tag string) apitest.Shape {
		return apitest.TestsFailed(canaryEntry(tag), apitest.Entry{User: "tag:web", Errors: slicesRepeat(failingInvariant, 70)})
	}
	for name, answer := range map[string]func(string) apitest.Shape{"70 entries": manyEntries, "70 lines in one entry": manyLines} {
		f, _, env := apiEnv(t)
		serveLive(f, peoplePolicy, nil, nil)
		serveInvariants(f, answer)
		out, err := validateWith(t, env, invariantsText)
		if err != nil {
			t.Fatal(err)
		}
		if out.Status != "fail" || len(out.Errors) != 64 || out.Omitted != 6 {
			t.Errorf("%s: status %q, %d problems, %d omitted; want fail, 64 and 6", name, out.Status, len(out.Errors), out.Omitted)
		}
		if v := out.Report().Verdict; v != "FAILED · 64 failed assertions · invariants: 3 tests ran" {
			t.Errorf("%s: verdict = %q", name, v)
		}
	}
}

func slicesRepeat(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

// An answer to the invariants that tailkeeper does not read (a list of errors at HTTP 200, the
// shape of no answer observed) leaves nothing known about them: unknown, exit 1, never a pass,
// and no invariant counted as run.
func TestAnAnswerToTheInvariantsThatIsNotRecognisedIsUnknown(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, peoplePolicy, nil, nil)
	serveInvariants(f, func(string) apitest.Shape { return apitest.ErrorsListAt200("tag not found") })
	out, err := validateWith(t, env, invariantsText)
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "unknown" || out.ExitCode() != 1 || out.InvariantsApplied != 0 || len(out.Errors) != 1 ||
		out.Errors[0].Kind != "server_message" || !strings.Contains(out.Errors[0].Message, "to the invariants was not one tailkeeper recognises") {
		t.Errorf("result = %+v", out)
	}
}
