package tools_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// liveRoute models GET .../acl for one test: the details read answers the details object
// and the plain read the text, both of the policy the test holds at that moment, with the
// ETag the API would give that text.
type liveRoute struct {
	mu       sync.Mutex
	text     string
	warnings []string
	errs     []string
	pinned   *string // when set, every read answers this ETag, whatever the policy then holds
}

// serveLive registers the route on f. The returned route's set changes the policy that the
// next read answers.
func serveLive(f *apitest.Fake, text string, warnings, errs []string) *liveRoute {
	r := &liveRoute{text: text, warnings: warnings, errs: errs}
	f.Handle("GET", tailnetPath+"/acl", func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		etag := api.ETagOf([]byte(r.text))
		if r.pinned != nil {
			etag = *r.pinned
		}
		if req.URL.Query().Get("details") == "true" {
			apitest.DetailsOK(r.text, etag, r.warnings, r.errs).Write(w)
			return
		}
		apitest.PolicyText(r.text, etag).Write(w)
	})
	f.JSON("GET", tailnetPath+"/settings", 200, `{"aclsExternallyManagedOn":true,"aclsExternalLink":"https://git.example.com/policy"}`)
	return r
}

func (r *liveRoute) set(text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.text = text
}

// pinETag makes every later read answer etag, whatever the policy then holds; "" sends none.
func (r *liveRoute) pinETag(etag string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pinned = &etag
}

// liveText is a live policy with a test and a rule.
const liveText = "{\n\t\"tagOwners\": {\"tag:ci\": [\"autogroup:admin\"]},\n\t\"acls\": [{\"action\": \"accept\", \"src\": [\"tag:ci\"], \"dst\": [\"tag:ci:22\"]}],\n}\n"

// validateOnline calls acl_validate over MCP with the given arguments.
func validateOnline(t *testing.T, env *registry.Env, args string) tools.ACLValidateOutput {
	t.Helper()
	var out tools.ACLValidateOutput
	mustCall(t, newRegistry(t), env, "acl_validate", args, &out)
	return out
}

// requestLine names a recorded request for an assertion on order: the method, the path
// below the tailnet and the part of the query that matters.
func requestLine(r apitest.Request) string {
	line := r.Method + " " + strings.TrimPrefix(r.Path, tailnetPath)
	if r.Query.Get("details") != "" {
		line += "?details=" + r.Query.Get("details")
	}
	return line
}

func TestValidateLiveSendsDetailsThenPolicyPostThenARecheck(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	out := validateOnline(t, env, `{}`)
	var got []string
	for _, r := range f.Requests() {
		got = append(got, requestLine(r))
	}
	want := "GET /acl?details=true,POST /acl/validate,GET /acl,GET /settings"
	if strings.Join(got, ",") != want {
		t.Errorf("requests = %v, want %s", got, want)
	}
	post := f.Requests()[1]
	if post.ContentType != "application/hujson" || !bytes.Equal(post.Body, []byte(liveText)) {
		t.Errorf("the POST carried %q and %q, want application/hujson and the live text's bytes", post.ContentType, post.Body)
	}
	if out.Status != "pass" || !out.ServerChecked || !out.DependsOnLiveState || out.LiveChanged || out.ExitCode() != 0 {
		t.Errorf("result = %+v", out)
	}
	if out.ExternallyManaged != "true" || out.ExternalLink != "https://git.example.com/policy" || out.CheckedAt != "2026-10-10T12:00:00Z" {
		t.Errorf("external facts %q %q, checked at %q", out.ExternallyManaged, out.ExternalLink, out.CheckedAt)
	}
}

// The proposal goes to Tailscale as the bytes the caller wrote, comments, trailing commas
// and line ends included: nothing is standardized, formatted or re-encoded on the way.
func TestTheProposalGoesAsItsExactBytes(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	proposal := "// proposed\r\n{\r\n\t/* a rule */ \"acls\": [{\"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"*:*\"],},],\r\n}\r\n"
	out := validateOnline(t, env, `{"policy":`+jsonString(proposal)+`}`)
	var post *apitest.Request
	for _, r := range f.Requests() {
		if r.Method == "POST" {
			post = &r
		}
	}
	if post == nil || !bytes.Equal(post.Body, []byte(proposal)) || post.ContentType != "application/hujson" {
		t.Fatalf("the POST = %+v, want the proposal's exact bytes", post)
	}
	if out.Status != "pass" || out.TestsAfter != 0 {
		t.Errorf("result = %+v", out)
	}
	// A proposal that is not an object is invalid here and nothing is sent: an array posted
	// as a policy would run in tests mode against the live policy and read as a pass.
	before := len(f.Requests())
	arr := validateOnline(t, env, `{"policy":"[]"}`)
	if arr.Status != "invalid" || arr.Errors[0].Kind != "structure" || len(f.Requests()) != before {
		t.Errorf("an array proposal: status %q, %d new requests; want invalid and none", arr.Status, len(f.Requests())-before)
	}
}

// Every status is a typed result with the fields a program reads, and the exit code comes
// from the status.
func TestTheTypedResultsOfEveryVerdictCarryTheirFields(t *testing.T) {
	assertion := `[acl test error]: address "tag:ci:22" (protocol "tcp"): want: Accept, got: Drop`
	for _, c := range []struct {
		name      string
		answer    apitest.Shape
		status    string
		exit      int
		kinds     []string
		checked   bool
		verdict   string
		errorText string
	}{
		{"a pass", apitest.TestsPassEmptyObject(), "pass", 0, nil, true, "VALID · 0 new warnings (0 existing) · 0 tests passed · invariants: none", ""},
		{"an assertion that failed", apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{assertion}}), "fail", 9, []string{"assertion_failed"}, true, "FAILED · 1 failed assertion · invariants: none", assertion},
		{"a test that cannot be evaluated", apitest.TestUnevaluable("tag:nowhere"), "unresolved", 2, []string{"test_unevaluable"}, true, "UNRESOLVED · 1 test cannot be evaluated: a name or destination does not resolve", "tag not found"},
		{"a rejection", apitest.BareMessage200("json: unknown field \"nodeAttr\""), "rejected", 2, []string{"server_message"}, true, "REJECTED · Tailscale refused the text (1 message)", "unknown field"},
		{"an answer nobody knows", apitest.ErrorsListAt200("tag not found"), "unknown", 1, []string{"server_message"}, true, "UNKNOWN · the answer could not be established; this is not a pass", "not one tailkeeper recognises"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, _, env := apiEnv(t)
			serveLive(f, liveText, nil, nil)
			f.ServeValidate(c.answer)
			out := validateOnline(t, env, `{}`)
			if out.Status != c.status || out.ExitCode() != c.exit || out.ServerChecked != c.checked {
				t.Fatalf("status %q exit %d serverChecked %v; want %q, %d, %v", out.Status, out.ExitCode(), out.ServerChecked, c.status, c.exit, c.checked)
			}
			var kinds []string
			for _, p := range out.Errors {
				kinds = append(kinds, p.Kind)
				if p.Severity != "error" || p.Source == "from" || !strings.Contains(p.Message, c.errorText) {
					t.Errorf("problem = %+v", p)
				}
			}
			if strings.Join(kinds, ",") != strings.Join(c.kinds, ",") {
				t.Errorf("kinds = %v, want %v", kinds, c.kinds)
			}
			if rep := out.Report(); rep.Verdict != c.verdict {
				t.Errorf("verdict = %q, want %q", rep.Verdict, c.verdict)
			}
			if out.InvariantsSignature != "none" || out.InvariantsApplied != 0 || len(out.NotChecked) == 0 {
				t.Errorf("invariants %q %d, notChecked %v", out.InvariantsSignature, out.InvariantsApplied, out.NotChecked)
			}
		})
	}
}

// A failure is told from an unevaluable test by the want/got grammar, never by a word: a
// rejection whose text holds the grammar's words is a rejection, and a mix is a failure.
func TestFailVerdictsComeFromTheGrammar(t *testing.T) {
	assertion := `[acl test error]: address "tag:ci:22": want: Drop, got: Accept`
	unevaluable := `[acl test error]: user or host is invalid: tag not found: "tag:x"`
	for _, c := range []struct {
		name   string
		answer apitest.Shape
		status string
		exit   int
	}{
		{"an assertion", apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{assertion}}), "fail", 9},
		{"only lines outside the grammar", apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{unevaluable, "port out of range"}}), "unresolved", 2},
		{"a mix", apitest.TestsFailed(apitest.Entry{User: "tag:x", Errors: []string{unevaluable}}, apitest.Entry{User: "tag:ci", Errors: []string{assertion}}), "fail", 9},
		{"an empty line", apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{""}}), "unresolved", 2},
		{"a line that embeds a destination and the verdict words", apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{`user or host is invalid: address "x": want: Accept, got: Drop`}}), "unresolved", 2},
		{"a rejection that holds the words", apitest.BareMessage200(`address "x": want: Accept, got: Drop`), "rejected", 2},
	} {
		f, _, env := apiEnv(t)
		serveLive(f, liveText, nil, nil)
		f.ServeValidate(c.answer)
		out := validateOnline(t, env, `{}`)
		if out.Status != c.status || out.ExitCode() != c.exit {
			t.Errorf("%s: status %q exit %d, want %q and %d", c.name, out.Status, out.ExitCode(), c.status, c.exit)
		}
	}
}

// The baseline of the warnings is the live policy's own, from the details read: a warning
// the live policy already has is existing, the rest are new, and only the new ones count
// for --fail-on warnings.
func TestWarningsBaselineSplitsNewFromExisting(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, liveText, []string{"host alias \"old\" is unused", "group:eng: group:eng has no members"}, nil)
	f.ServeValidate(apitest.TestsWarned(
		apitest.Entry{User: "old", Warnings: []string{"host alias \"old\" is unused"}},
		apitest.Entry{User: "group:eng", Warnings: []string{"group:eng has no members"}},
		apitest.Entry{User: "tag:ci", Warnings: []string{"tag:ci owns nothing"}},
	))
	out := validateOnline(t, env, `{"policy":`+jsonString(liveText+"// proposed\n")+`}`)
	if out.Status != "pass" || len(out.ExistingWarnings) != 2 || len(out.NewWarnings) != 1 {
		t.Fatalf("status %q, existing %+v, new %+v; want a pass with two existing warnings and one new", out.Status, out.ExistingWarnings, out.NewWarnings)
	}
	w := out.NewWarnings[0]
	if w.Kind != "warning" || w.Severity != "warning" || w.Message != "tag:ci: tag:ci owns nothing" || !w.FromTailscale || w.Source != "from" {
		t.Errorf("new warning = %+v", w)
	}
	if got := out.Findings().NewWarnings; got != 1 {
		t.Errorf("--fail-on warnings counts %d, want 1", got)
	}
	if rep := out.Report(); rep.Verdict != "VALID · 1 new warning (2 existing) · 0 tests passed · invariants: none" || rep.Level != registry.LevelWarn {
		t.Errorf("verdict %q level %q", rep.Verdict, rep.Level)
	}
}

// A live policy that changed while the check ran makes a pass unknown, never a pass; a
// failure stays a failure, since a failed test is not undone by a change elsewhere.
func TestALiveChangedDuringTheCallIsUnknownNeverAPass(t *testing.T) {
	for _, c := range []struct {
		name   string
		answer apitest.Shape
		status string
	}{
		{"a pass", apitest.TestsPassEmptyObject(), "unknown"},
		{"a fail", apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{`[acl test error]: address "tag:ci:22": want: Drop, got: Accept`}}), "fail"},
	} {
		f, _, env := apiEnv(t)
		live := serveLive(f, liveText, nil, nil)
		f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, _ *http.Request) {
			live.set(liveText + "// edited in the admin console\n")
			c.answer.Write(w)
		})
		out := validateOnline(t, env, `{}`)
		if out.Status != c.status || !out.LiveChanged {
			t.Errorf("%s: status %q liveChanged %v, want %q and true", c.name, out.Status, out.LiveChanged, c.status)
		}
		if c.status == "unknown" && (out.ExitCode() != 1 || len(out.Errors) != 1 || !strings.Contains(out.Errors[0].Message, "changed while it was being checked")) {
			t.Errorf("%s: exit %d, errors %+v", c.name, out.ExitCode(), out.Errors)
		}
	}
	// The control: a live policy that stays put is a pass, so the test above can tell.
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	if out := validateOnline(t, env, `{}`); out.Status != "pass" || out.LiveChanged {
		t.Errorf("control: status %q liveChanged %v", out.Status, out.LiveChanged)
	}
}

// The live policy has moved when its body differs, even when its ETag says nothing: a body that
// changed under the ETag it had before (a cache that kept the old one), or under none at all,
// is a change all the same, and a pass over it is no pass.
func TestALiveBodyThatMovedUnderTheSameETagIsStillAChange(t *testing.T) {
	for name, pin := range map[string]func(*liveRoute){
		"the same ETag": func(r *liveRoute) { r.pinETag(api.ETagOf([]byte(liveText))) },
		"no ETag":       func(r *liveRoute) { r.pinETag("") },
	} {
		f, _, env := apiEnv(t)
		live := serveLive(f, liveText, nil, nil)
		f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, _ *http.Request) {
			pin(live)
			live.set(liveText + "// edited in the admin console\n")
			apitest.TestsPassEmptyObject().Write(w)
		})
		out := validateOnline(t, env, `{}`)
		if out.Status != "unknown" || !out.LiveChanged || out.ExitCode() != 1 {
			t.Errorf("%s: status %q liveChanged %v exit %d, want unknown, true and 1", name, out.Status, out.LiveChanged, out.ExitCode())
		}
	}
}

// While masking is on, a proposal over MCP may not hold a login: it is refused before
// anything is sent, because a verdict on it would confirm a guess. A file the operator names
// is theirs.
func TestAnMCPProposalWithALoginIsRefusedBeforeAnyRequest(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	text := "{\"groups\": {\"group:eng\": [\"amy@example.com\"]}}"
	_, err := call(t, newRegistry(t), env, "acl_validate", `{"policy":`+jsonString(text)+`}`)
	if code(err) != tkerr.FilterRefused || len(f.Requests()) != 0 {
		t.Fatalf("err = %v with %d requests, want filter_refused and none", err, len(f.Requests()))
	}
	if strings.Contains(err.Error(), "amy@") {
		t.Errorf("the refusal repeats the login: %v", err)
	}
	// With personalData show the owner has opted in.
	if out := validateOnline(t, show(env), `{"policy":`+jsonString(text)+`}`); out.Status != "pass" {
		t.Errorf("with personalData show: status %q", out.Status)
	}
	// The operator's own file goes to Tailscale as it is.
	op, err := runValidate(t, env, func(in *tools.ACLValidateInput) { in.Policy, in.Operator = text, true })
	if err != nil || op.Status != "pass" {
		t.Errorf("operator: status %q, err %v", op.Status, err)
	}
	for _, r := range f.Requests() {
		if r.Method == "POST" && !bytes.Contains(r.Body, []byte("amy@example.com")) {
			t.Errorf("the operator's login did not reach Tailscale: %s", r.Body)
		}
	}
}

// The policy's version and digest follow the masking rules of acl_get: the ETag shows only
// with personalData show, a keyed digest of it with a privacy key, nothing otherwise; the
// SHA-256 is that of the policy as acl_get shows it.
func TestThePolicyVersionAndDigestFollowTheMaskingRules(t *testing.T) {
	f, _, env := apiEnv(t)
	text := "// owner: amy@example.com\n{}\n"
	serveLive(f, text, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	etag := api.ETagOf([]byte(text))

	plain := validateOnline(t, env, `{}`)
	if plain.PolicyVersion != "" {
		t.Errorf("masking on, no key: policyVersion = %q, want none", plain.PolicyVersion)
	}
	masked := "// owner: a…@example.com\n{}\n"
	sum := sha256.Sum256([]byte(masked))
	if plain.PolicySHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("policySha256 = %s, want the digest of the policy as shown", plain.PolicySHA256)
	}
	keyed, k := keyed(t, env)
	if got := validateOnline(t, keyed, `{}`).PolicyVersion; got != k.Digest([]byte(etag)) || strings.Contains(got, strings.Trim(etag, `"`)) {
		t.Errorf("with a key: policyVersion = %q, want the keyed digest of the ETag", got)
	}
	shown := validateOnline(t, show(env), `{}`)
	raw := sha256.Sum256([]byte(text))
	if shown.PolicyVersion != etag || shown.PolicySHA256 != hex.EncodeToString(raw[:]) {
		t.Errorf("with personalData show: %q %q, want the ETag and the digest of the bytes", shown.PolicyVersion, shown.PolicySHA256)
	}
	// acl_get over the same policy (the route above answers the details form it reads)
	// reports the same digest.
	var got tools.ACLGetOutput
	mustCall(t, newRegistry(t), env, "acl_get", `{}`, &got)
	if got.SHA256 != plain.PolicySHA256 {
		t.Errorf("acl_get sha256 %s, acl_validate policySha256 %s: they describe the same masked policy", got.SHA256, plain.PolicySHA256)
	}
}

// Whether the policy is managed elsewhere is advisory: unreadable settings are unknown and
// never hold back the verdict.
func TestUnreadableSettingsAreUnknownAndDoNotHoldBackTheVerdict(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	f.JSON("GET", tailnetPath+"/settings", 403, `{"message":"forbidden"}`)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	out := validateOnline(t, env, `{}`)
	if out.Status != "pass" || out.ExternallyManaged != "unknown" || !strings.Contains(out.ExternallyManagedNote, "scope_missing") {
		t.Errorf("status %q, externally managed %q (%q)", out.Status, out.ExternallyManaged, out.ExternallyManagedNote)
	}
}
