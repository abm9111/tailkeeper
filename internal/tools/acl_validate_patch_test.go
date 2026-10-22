package tools_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// peoplePolicy is a live policy whose tests name two people, as most do.
const peoplePolicy = "{\n" +
	"\t\"groups\": {\"group:eng\": []},\n" +
	"\t\"tagOwners\": {\"tag:ci\": [\"autogroup:admin\"]},\n" +
	"\t\"acls\": [{\"action\": \"accept\", \"src\": [\"tag:ci\"], \"dst\": [\"tag:ci:22\"]}],\n" +
	"\t\"tests\": [\n" +
	"\t\t{\"src\": \"alice@example.com\", \"accept\": [\"tag:ci:22\"]},\n" +
	"\t\t{\"src\": \"bob@example.org\", \"accept\": [\"tag:ci:22\"]},\n" +
	"\t],\n" +
	"}\n"

// patchCall is the arguments of an MCP call that validates a patch.
func patchCall(patch string) string { return `{"patch":` + jsonString(patch) + `}` }

// lastPost is the body of the last validation request the fake saw, or nil.
func lastPost(f *apitest.Fake) []byte {
	var body []byte
	for _, r := range f.Requests() {
		if r.Method == "POST" {
			body = r.Body
		}
	}
	return body
}

func posts(f *apitest.Fake) int {
	n := 0
	for _, r := range f.Requests() {
		if r.Method == "POST" {
			n++
		}
	}
	return n
}

// The common case, end to end: an agent adds one rule to a live policy whose tests name
// people, with the default masking and no privacy key. The patch names no user, so the subject
// rule has nothing to refuse, the users are never read, and the live policy's own logins are
// the live policy's.
func TestAPatchAddsOneRuleToALivePolicyWhoseTestsNamePeople(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, peoplePolicy, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	patch := `[{"op":"add","path":"/grants","value":[{"src":["tag:ci"],"dst":["tag:ci"],"ip":["tcp:443"]}]}]`
	out := validateOnline(t, env, patchCall(patch))
	if out.Status != "pass" || out.ExitCode() != 0 || !out.ServerChecked {
		t.Fatalf("result = %+v", out)
	}
	if usersRequests(f) != 0 {
		t.Error("the users were read for a patch that names no user")
	}
	want, err := acl.ApplyPatch(context.Background(), []byte(peoplePolicy), []byte(patch))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(lastPost(f), want) || out.PatchedBytes != shownBytes(t, env, string(want)) {
		t.Errorf("the POST is not the live text with the patch applied, or patchedBytes %d is not the size acl_get shows for it:\n%s", out.PatchedBytes, lastPost(f))
	}
	if out.Changes == nil || out.Changes.Semantic+out.Changes.Widening < 1 || out.TestsBefore != 2 || out.TestsAfter != 2 {
		t.Errorf("changes %+v, tests %d to %d", out.Changes, out.TestsBefore, out.TestsAfter)
	}
	if strings.Contains(mustJSON(t, out), "alice@") {
		t.Errorf("a live login is in the result: %s", mustJSON(t, out))
	}
}

// shownBytes is the size acl_get reports for text served as the live policy to an environment
// with the privacy key and the settings of like: the size of the policy as shown, which is what
// patchedBytes promises.
func shownBytes(t *testing.T, like *registry.Env, text string) int {
	t.Helper()
	f, reg, env := apiEnv(t)
	env.Privacy, env.Config = like.Privacy, like.Config
	servePolicy(f, text, `"v1"`)
	f.JSON("GET", tailnetPath+"/settings", 200, `{}`)
	var out tools.ACLGetOutput
	mustCall(t, reg, env, "acl_get", `{}`, &out)
	return out.Bytes
}

// patchedBytes is the size of the patched policy as acl_get shows it, not the size of the file:
// the file's own size would tell the caller how long the logins are that masking hides, those of
// the live policy and those a pseudonym of the patch stands for. Two users whose logins differ
// in length and not in their masked forms give one size; with personalData show the owner asked
// for the file's own.
func TestPatchedBytesIsTheSizeAclGetShowsAndTellsNothingOfALoginsLength(t *testing.T) {
	const live = "{\n\t\"groups\": {\"group:eng\": [\"christopher@example.com\", \"bob@example.org\"]},\n}\n"
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "chris@example.com", "christopher.long@example.com"))
	kenv, _ := keyed(t, env)
	serveLive(f, live, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	var sizes, files []int
	for _, id := range []string{"u1", "u2"} {
		patch := `[{"op":"add","path":"/groups/group:ops","value":["` + shownRef(t, reg, kenv, id) + `"]}]`
		out := validateOnline(t, kenv, patchCall(patch))
		if out.Status != "pass" {
			t.Fatalf("%s: %+v", id, out)
		}
		sizes, files = append(sizes, out.PatchedBytes), append(files, len(lastPost(f)))
		if want := shownBytes(t, kenv, string(lastPost(f))); out.PatchedBytes != want {
			t.Errorf("%s: patchedBytes %d, acl_get shows %d for the patched text", id, out.PatchedBytes, want)
		}
	}
	if sizes[0] != sizes[1] || files[0] == files[1] {
		t.Errorf("sizes %v for files of %v bytes: want one size for two files of different sizes", sizes, files)
	}
	if sizes[0] == files[0] {
		t.Errorf("patchedBytes %d is the file's own size, which holds the unmasked logins", sizes[0])
	}
	// The owner who asked to see personal data gets the file's own size.
	shown := validateOnline(t, show(kenv), patchCall(`[{"op":"add","path":"/hosts","value":{}}]`))
	if shown.PatchedBytes != len(lastPost(f)) {
		t.Errorf("with personalData show: patchedBytes %d, the file holds %d", shown.PatchedBytes, len(lastPost(f)))
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A user is named in a patch by the pseudonym a result showed. The login goes to Tailscale in
// the request and appears in nothing the caller gets back; the digest of the patched text's
// normal form is the keyed digest that acl_get's summary shows once the change is applied.
func TestAPatchNamesAUserOnlyByPseudonym(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "amy@example.com", "bob@example.org"))
	kenv, key := keyed(t, env)
	serveLive(f, peoplePolicy, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	ref := shownRef(t, reg, kenv, "u1")
	patch := `[{"op":"add","path":"/groups/group:eng/-","value":"a…@example.com [` + ref + `]"},{"op":"add","path":"/groups/group:ops","value":["` + ref + `"]}]`
	out := validateOnline(t, kenv, patchCall(patch))
	if out.Status != "pass" {
		t.Fatalf("result = %+v", out)
	}
	body := lastPost(f)
	if !bytes.Contains(body, []byte(`"group:eng": ["amy@example.com"]`)) || !bytes.Contains(body, []byte(`"group:ops":["amy@example.com"]`)) || bytes.Contains(body, []byte("[p:")) {
		t.Errorf("the POST does not carry the login in place of the pseudonym:\n%s", body)
	}
	absent(t, mustJSON(t, out), "amy@", "[p:")
	doc, err := acl.Parse(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	nf, err := acl.NormalFormBytes(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if out.PatchedDigest == "" || out.PatchedDigest != key.Digest(nf) || out.PatchedBytes != shownBytes(t, kenv, string(body)) {
		t.Errorf("patchedDigest %q, patchedBytes %d; want the keyed digest of the sent text's normal form and the size acl_get shows for it, %d", out.PatchedDigest, out.PatchedBytes, shownBytes(t, kenv, string(body)))
	}
	// Without a key there is no digest, and a different patch has a different one.
	if plain := validateOnline(t, env, patchCall(`[{"op":"add","path":"/hosts","value":{"edge":"192.0.2.9"}}]`)); plain.PatchedDigest != "" || plain.PatchedBytes == 0 {
		t.Errorf("without a key: digest %q, bytes %d", plain.PatchedDigest, plain.PatchedBytes)
	}
	other := validateOnline(t, kenv, patchCall(`[{"op":"add","path":"/hosts","value":{"edge":"192.0.2.9"}}]`))
	if other.PatchedDigest == "" || other.PatchedDigest == out.PatchedDigest {
		t.Errorf("a different patch has digest %q, the first had %q", other.PatchedDigest, out.PatchedDigest)
	}
}

// The digest of a validated patch is the digest acl_get's summary shows once the live policy
// is the patched text, or says the same in other words: the field promises that pairing, and
// the two tools reach it through one function. The policy before the patch has another digest.
func TestPatchedDigestEqualsTheSummarySemanticDigestOnceApplied(t *testing.T) {
	f, _, env := apiEnv(t)
	kenv, _ := keyed(t, env)
	serveLive(f, peoplePolicy, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	out := validateOnline(t, kenv, patchCall(`[{"op":"add","path":"/hosts","value":{"edge":"192.0.2.9"}}]`))
	patched := string(lastPost(f))
	if out.Status != "pass" || out.PatchedDigest == "" || patched == peoplePolicy {
		t.Fatalf("result = %+v", out)
	}
	summaryDigest := func(live string) string {
		t.Helper()
		g, reg, genv := apiEnv(t)
		genv, _ = keyed(t, genv)
		servePolicy(g, live, `"e1"`)
		var got tools.ACLGetOutput
		mustCall(t, reg, genv, "acl_get", `{"view":"summary"}`, &got)
		if got.Summary == nil {
			t.Fatalf("no summary: %+v", got)
		}
		return got.Summary.SemanticDigest
	}
	if got := summaryDigest(patched); got != out.PatchedDigest {
		t.Errorf("the live policy is the patched text: acl_get semanticDigest %q, acl_validate patchedDigest %q", got, out.PatchedDigest)
	}
	if got := summaryDigest("// applied by the owner\n" + patched); got != out.PatchedDigest {
		t.Errorf("the patched text with a comment added: semanticDigest %q, patchedDigest %q", got, out.PatchedDigest)
	}
	if got := summaryDigest(peoplePolicy); got == out.PatchedDigest {
		t.Errorf("the policy before the patch has the digest of the patched one: %q", got)
	}
}

// The text is replaced after the subject rule has read it, and what is sent is what the
// replacement returned: the POST is exactly the output of SubstituteSubjects on the text that
// was checked.
func TestWhatIsSentIsWhatTheSubstitutionReturned(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "amy@example.com", "bob@example.org"))
	kenv, _ := keyed(t, env)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	ref := shownRef(t, reg, kenv, "u2")
	proposal := "// proposed\n{\"groups\": {\"group:eng\": [\"" + ref + "\", \"[" + ref + "]\"]}, \"hosts\": {\"edge\": \"192.0.2.9\"}}\n"
	out := validateOnline(t, kenv, `{"policy":`+jsonString(proposal)+`}`)
	want, replaced, err := tools.SubstituteSubjects(context.Background(), tools.NewSubjectResolver(kenv), []byte(proposal))
	if err != nil || replaced != 2 {
		t.Fatalf("substitution: %d, %v", replaced, err)
	}
	if out.Status != "pass" || !bytes.Equal(lastPost(f), want) || !bytes.Contains(want, []byte("bob@example.org")) {
		t.Errorf("status %q; the POST is not the substituted text:\n%s", out.Status, lastPost(f))
	}
	absent(t, mustJSON(t, out), "bob@")
	// Two spellings of one user as keys of one object are a key written twice only once the
	// pseudonyms are replaced: invalid, with nothing sent.
	before := posts(f)
	callers := `{"groups": {"` + ref + `": [], "[` + ref + `]": []}}`
	dup := validateOnline(t, kenv, `{"policy":`+jsonString(callers)+`}`)
	if dup.Status != "invalid" || len(dup.Errors) != 1 || dup.Errors[0].Kind != "duplicate_key" || posts(f) != before {
		t.Errorf("status %q, errors %+v, %d new POSTs", dup.Status, dup.Errors, posts(f)-before)
	}
	// Where it is in the text the caller wrote, not in the text with the login in place.
	if want := strings.Index(callers, `"[`+ref+`]"`) + 1; len(dup.Errors) == 1 && (dup.Errors[0].Line != 1 || dup.Errors[0].Column != want) {
		t.Errorf("the repeated key is at %d:%d, in the caller's text it is at 1:%d", dup.Errors[0].Line, dup.Errors[0].Column, want)
	}
}

// A column in a result is a column of the caller's own text. The text that is sent holds a
// login where the caller wrote a pseudonym, so a column read off it is off by the difference
// of the two lengths, and that difference is the length of a login the caller never saw. Two
// users whose logins differ in length must give one column, and it must be the column of the
// caller's text, for a name the reply quotes and for a position the server gives.
func TestAColumnAfterAPseudonymIsAColumnOfTheCallersOwnText(t *testing.T) {
	for _, login := range []string{"chris@example.com", "christopher.longname@subdomain.example.org"} {
		run := func(answer func(sentCol int) apitest.Shape) (out tools.ACLValidateOutput, callerCol int) {
			f, reg, env := apiEnv(t)
			f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, login, "bob@example.org"))
			kenv, _ := keyed(t, env)
			serveLive(f, liveText, nil, nil)
			ref := shownRef(t, reg, kenv, "u1")
			line := `  "groups": {"group:eng": ["` + ref + `", "tag:nowhere"]},`
			callerCol = strings.Index(line, `"tag:nowhere"`) + 1
			sentCol := strings.Index(strings.Replace(line, ref, login, 1), `"tag:nowhere"`) + 1
			if sentCol == callerCol {
				t.Fatalf("%s: the login and the pseudonym are as long, so the test cannot tell the two texts apart", login)
			}
			f.ServeValidate(answer(sentCol))
			return validateOnline(t, kenv, `{"policy":`+jsonString("{\n"+line+"\n}\n")+`}`), callerCol
		}
		for name, answer := range map[string]func(int) apitest.Shape{
			"a quoted name":     func(int) apitest.Shape { return apitest.PolicyTagNotFound("tag:nowhere") },
			"a server position": func(sentCol int) apitest.Shape { return apitest.PolicySyntaxError(2, sentCol, "unexpected") },
		} {
			out, want := run(answer)
			if out.Status != "rejected" || len(out.Errors) != 1 || out.Errors[0].Line != 2 || out.Errors[0].Column != want {
				t.Errorf("%s, a login of %d bytes: status %q, errors %+v; want the problem at 2:%d, as the caller wrote it", name, len(login), out.Status, out.Errors, want)
			}
			// The server's own words name the column it counted, in the text it was sent.
			if name == "a server position" && len(out.Errors) == 1 && !strings.HasPrefix(out.Errors[0].Message, fmt.Sprintf("line 2, column %d: ", want)) {
				t.Errorf("%s, a login of %d bytes: message %q; want it to name column %d", name, len(login), out.Errors[0].Message, want)
			}
		}
	}
}

// While masking is on, a login the caller writes is refused before any request: as a value,
// as an object key, in a path, inside a policy text. A login in a comment is not read by the
// rule, as designed, and the result echoes it nowhere.
func TestALiteralLoginIsRefusedBeforeAnyRequest(t *testing.T) {
	for name, args := range map[string]string{
		"a value of a patch":           patchCall(`[{"op":"add","path":"/groups/group:eng/-","value":"amy@example.com"}]`),
		"a key inside a value":         patchCall(`[{"op":"add","path":"/hosts","value":{"amy@example.com":"192.0.2.1"}}]`),
		"a path":                       patchCall(`[{"op":"add","path":"/groups/amy@example.com","value":[]}]`),
		"a value of a policy":          `{"policy":` + jsonString(`{"groups": {"group:eng": ["amy@example.com"]}}`) + `}`,
		"a key of a policy":            `{"policy":` + jsonString(`{"hosts": {"amy@example.com": "192.0.2.1"}}`) + `}`,
		"a JSON escape of the at sign": patchCall(`[{"op":"add","path":"/groups/group:eng/-","value":"amy` + string(rune(92)) + `u0040example.com"}]`),
	} {
		f, _, env := apiEnv(t)
		serveLive(f, liveText, nil, nil)
		f.ServeValidate(apitest.TestsPassEmptyObject())
		_, err := call(t, newRegistry(t), env, "acl_validate", args)
		if code(err) != tkerr.FilterRefused || len(f.Requests()) != 0 {
			t.Errorf("%s: err = %v with %d requests, want filter_refused and none", name, err, len(f.Requests()))
		} else if strings.Contains(err.Error(), "amy@") {
			t.Errorf("%s: the refusal repeats the login: %v", name, err)
		}
	}
}

func TestACommentWithALoginInAnMCPPatchEchoesNowhere(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.BareMessage200("amy@example.com is not a valid host name"))
	patch := "[\n// ask amy@example.com first\n{\"op\":\"add\",\"path\":\"/hosts\",\"value\":{\"edge\":\"192.0.2.9\"}}]"
	out := validateOnline(t, env, patchCall(patch))
	if out.Status != "rejected" {
		t.Fatalf("status %q", out.Status)
	}
	absent(t, mustJSON(t, out), "amy@")
}

// A prefix before a pseudonym is not a pseudonym, and a pseudonym that names no one is a
// failure of the call, before anything is sent.
func TestThePseudonymPrefixRuleAndAPseudonymThatNamesNoOne(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "amy@example.com", "bob@example.org"))
	kenv, _ := keyed(t, env)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	ref := shownRef(t, reg, kenv, "u1")
	for name, c := range map[string]struct{ args, want string }{
		"a prefix":                   {patchCall(`[{"op":"add","path":"/groups/group:eng","value":["tag:x [` + ref + `]"]}]`), "hold a pseudonym marker without being a pseudonym"},
		"a pseudonym in a path":      {patchCall(`[{"op":"add","path":"/groups/` + ref + `","value":[]}]`), "hold a pseudonym marker without being a pseudonym"},
		"a user that left":           {patchCall(`[{"op":"add","path":"/groups/group:eng","value":["p:abcdefghij"]}]`), "no user has that pseudonym"},
		"in a policy, one to no one": {`{"policy":` + jsonString(`{"groups": {"group:eng": ["p:abcdefghij"]}}`) + `}`, "no user has that pseudonym"},
	} {
		before := posts(f)
		_, err := call(t, newRegistry(t), kenv, "acl_validate", c.args)
		if code(err) != tkerr.ValidationFailed || !strings.Contains(err.Error(), c.want) || posts(f) != before {
			t.Errorf("%s: err = %v, %d new POSTs; want validation_failed saying %q", name, err, posts(f)-before, c.want)
		}
	}
	// Without a privacy key a pseudonym cannot be resolved at all.
	_, err := call(t, newRegistry(t), env, "acl_validate", patchCall(`[{"op":"add","path":"/groups/group:eng","value":["`+ref+`"]}]`))
	if code(err) != tkerr.PrivacyKeyUnavailable {
		t.Errorf("without a key: err = %v, want privacy_key_unavailable", err)
	}
}

func TestNoUsersAreReadWithoutAPseudonym(t *testing.T) {
	f, _, env := apiEnv(t)
	kenv, _ := keyed(t, env)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	validateOnline(t, kenv, patchCall(`[{"op":"add","path":"/hosts","value":{"edge":"192.0.2.9"}}]`))
	validateOnline(t, kenv, `{"policy":`+jsonString(liveText+"// c\n")+`}`)
	validateOnline(t, kenv, `{}`)
	if n := usersRequests(f); n != 0 {
		t.Errorf("%d reads of the users, want none: users:read is optional and used only to resolve a pseudonym", n)
	}
}

// A credential shape in an MCP text is refused before any request, naming where it is and
// never repeating it; the operator's own file is sent as it is.
func TestATripwireMatchInAnMCPProposalIsRefusedBeforeAnyRequestNamingThePointer(t *testing.T) {
	// Tailscale decodes JSON escapes, so a shape spelled with one (an escape for the hyphen or
	// for a letter of the prefix) reaches it as the shape: the escapes are decoded before the
	// text is looked at. The backslash is written as a rune so that no editor or tool turns the
	// escape into the character.
	bs := string(rune(92))
	for name, c := range map[string]struct{ args, where string }{
		"a value with an escaped hyphen": {`{"policy":` + jsonString(`{"hosts": {"edge": "tskey`+bs+`u002dapi-x"}}`) + `}`, "at /hosts/edge"},
		"a key with an escaped letter":   {`{"policy":` + jsonString(`{"hosts": {"`+bs+`u0074skey-api-x": "192.0.2.1"}}`) + `}`, "(credential-shaped) (a key)"},
		"a patch value with an escape":   {patchCall(`[{"op":"add","path":"/groups/group:eng","value":["tag:tskey` + bs + `u002dapi-x"]}]`), "at /0/value/0"},
		"a value":                        {`{"policy":` + jsonString(`{"hosts": {"edge": "tskey-api-x"}}`) + `}`, "at /hosts/edge"},
		"a key":                          {`{"policy":` + jsonString(`{"hosts": {"tskey-api-x": "192.0.2.1"}}`) + `}`, "(credential-shaped) (a key)"},
		"a comment":                      {`{"policy":` + jsonString("{\n// tskey-api-x\n\"hosts\": {}}") + `}`, "in a comment"},
		"a value of a patch":             {patchCall(`[{"op":"add","path":"/groups/group:eng","value":["tag:tskey-api-x"]}]`), "at /0/value/0"},
	} {
		f, _, env := apiEnv(t)
		serveLive(f, liveText, nil, nil)
		f.ServeValidate(apitest.TestsPassEmptyObject())
		_, err := call(t, newRegistry(t), env, "acl_validate", c.args)
		if code(err) != tkerr.ValidationFailed || len(f.Requests()) != 0 || !strings.Contains(err.Error(), c.where) || !strings.Contains(err.Error(), "shaped like a credential") {
			t.Errorf("%s: err = %v with %d requests, want validation_failed naming %q and no request", name, err, len(f.Requests()), c.where)
		}
		absent(t, fmt.Sprint(err), "tskey-api-x", "u002d", "u0074")
	}
}

func TestATagShapedNameInAnOperatorFileIsAccepted(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	text := `{"tagOwners": {"tag:tskey-api-x": []}}`
	out, err := runValidate(t, env, func(in *tools.ACLValidateInput) { in.Policy, in.Operator = text, true })
	if err != nil || out.Status != "pass" || string(lastPost(f)) != text {
		t.Errorf("status %q, err %v, POST %q; want the operator's file sent untouched", out.Status, err, lastPost(f))
	}
	patch := `[{"op":"add","path":"/tagOwners/tag:tskey-api-y","value":[]}]`
	out, err = runValidate(t, env, func(in *tools.ACLValidateInput) { in.Patch, in.Operator = patch, true })
	if err != nil || out.Status != "pass" || !bytes.Contains(lastPost(f), []byte("tag:tskey-api-y")) {
		t.Errorf("a patch file: status %q, err %v", out.Status, err)
	}
}

// An MCP caller may add or replace 64 tests a call, and the cap is on what the caller adds:
// the live policy's stored tests, and entries the proposal repeats from it, do not count.
func TestMoreThan64CallerTestsAreRefused(t *testing.T) {
	entry := func(i int) string {
		return fmt.Sprintf(`{"src": "tag:ci", "accept": ["192.0.2.%d:%d"]}`, i%250, 1000+i)
	}
	entries := func(from, to int) string {
		var parts []string
		for i := from; i < to; i++ {
			parts = append(parts, entry(i))
		}
		return strings.Join(parts, ",\n")
	}
	run := func(live, args string) (sent, requests int, err error) {
		f, _, env := apiEnv(t)
		serveLive(f, live, nil, nil)
		f.ServeValidate(apitest.TestsPassEmptyObject())
		_, err = call(t, newRegistry(t), env, "acl_validate", args)
		return posts(f), len(f.Requests()), err
	}
	withTests := func(n int) string { return "{\n\"tests\": [\n" + entries(0, n) + "\n]\n}\n" }
	refused := func(name string, err error, sent int) {
		t.Helper()
		if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ValidationFailed || !strings.Contains(e.Message, "at most 64") || sent != 0 {
			t.Errorf("%s: err = %v with %d POSTs, want validation_failed (at most 64) and nothing sent", name, err, sent)
		}
	}
	// A policy: 65 new tests against a live policy with none.
	sent, _, err := run(liveText, `{"policy":`+jsonString(withTests(65))+`}`)
	refused("65 new tests in a policy", err, sent)
	// The same cap holds for the SSH tests of a policy.
	sshEntry := `{"src": "tag:ci", "dst": ["tag:ci"], "accept": ["root"]}`
	sentSSH, _, err := run(liveText, `{"policy":`+jsonString("{\n\"sshTests\": [\n"+strings.Repeat(sshEntry+",\n", 65)+"]\n}\n")+`}`)
	refused("65 new SSH tests in a policy", err, sentSSH)
	if sent, _, err := run(liveText, `{"policy":`+jsonString("{\n\"sshTests\": [\n"+strings.Repeat(sshEntry+",\n", 64)+"]\n}\n")+`}`); err != nil || sent != 1 {
		t.Errorf("64 new SSH tests: err %v, %d POSTs, want one POST", err, sent)
	}
	if sent, _, err := run(liveText, `{"policy":`+jsonString(withTests(64))+`}`); err != nil || sent != 1 {
		t.Errorf("64 new tests: err %v, %d POSTs, want one POST", err, sent)
	}
	// Tests the live policy already holds do not count, however they are spelled; 64 new ones
	// on top of 100 stored ones are allowed, and 65 are not.
	live := withTests(100)
	respelled := "{\n\"tests\": [\n" + strings.ReplaceAll(entries(0, 100), `", "`, `",   "`) + ",\n// new\n" + entries(100, 164) + "\n]\n}\n"
	if sent, _, err := run(live, `{"policy":`+jsonString(respelled)+`}`); err != nil || sent != 1 {
		t.Errorf("100 stored tests respelled and 64 new: err %v, %d POSTs", err, sent)
	}
	sent, _, err = run(live, `{"policy":`+jsonString("{\n\"tests\": [\n"+entries(0, 165)+"\n]\n}\n")+`}`)
	refused("65 new tests on top of 100 stored ones", err, sent)
	// A patch is counted from its operations, before any request.
	for name, patch := range map[string]string{
		"an array of 65":                      `[{"op":"add","path":"/tests","value":[` + entries(0, 65) + `]}]`,
		"65 operations":                       "[" + strings.TrimSuffix(strings.Repeat(`{"op":"add","path":"/tests/-","value":`+entry(1)+`},`, 65), ",") + "]",
		"replacing the root":                  `[{"op":"replace","path":"","value":{"tests":[` + entries(0, 65) + `]}}]`,
		"the other section":                   `[{"op":"add","path":"/sshTests","value":[` + strings.Repeat(`{"src":"tag:ci","dst":["tag:ci"],"accept":["root"]},`, 65) + `{"src":"tag:ci","dst":["tag:ci"],"accept":["root"]}]}]`,
		"a section by its name in other case": `[{"op":"add","path":"/TESTS","value":[` + entries(0, 65) + `]}]`,
	} {
		sent, requests, err := run(liveText, patchCall(patch))
		refused(name, err, sent)
		if requests != 0 {
			t.Errorf("%s: %d requests before the cap refused it", name, requests)
		}
	}
	if sent, _, err := run(liveText, patchCall(`[{"op":"add","path":"/tests","value":[`+entries(0, 64)+`]}]`)); err != nil || sent != 1 {
		t.Errorf("64 tests in a patch: err %v, %d POSTs", err, sent)
	}
	// The operations are only a bound. Operations the count does not read as adding tests can
	// still put them there: an add somewhere else, then a move into tests, or a move of a
	// section that holds objects. The cap is on what the patched text holds that the live policy
	// does not, so none of these gets past it, and nothing is sent.
	grants := "[" + strings.TrimSuffix(strings.Repeat(`{"src":["tag:ci"],"dst":["tag:ci"],"ip":["tcp:22"]},`, 65), ",") + "]"
	for name, c := range map[string]struct{ live, patch string }{
		"an add elsewhere and a move into tests": {liveText, `[{"op":"add","path":"/zz","value":[` + entries(0, 65) + `]},{"op":"move","from":"/zz","path":"/tests"}]`},
		"a move of the grants into tests":        {"{\n\"grants\": " + grants + "\n}\n", `[{"op":"move","from":"/grants","path":"/tests"}]`},
		"a move into the SSH tests":              {"{\n\"grants\": " + grants + "\n}\n", `[{"op":"move","from":"/grants","path":"/sshTests"}]`},
	} {
		sent, _, err := run(c.live, patchCall(c.patch))
		refused(name, err, sent)
	}
	// An operator is not held to the cap.
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	if out, err := runValidate(t, env, func(in *tools.ACLValidateInput) { in.Policy, in.Operator = withTests(200), true }); err != nil || out.Status != "pass" {
		t.Errorf("operator with 200 tests: %+v, %v", out.Status, err)
	}
	// Nor is an operator's patch, whether it adds them as an array or moves them into place.
	for name, patch := range map[string]string{
		"an array of 200": `[{"op":"add","path":"/tests","value":[` + entries(0, 200) + `]}]`,
		"a move":          `[{"op":"add","path":"/zz","value":[` + entries(0, 70) + `]},{"op":"move","from":"/zz","path":"/tests"}]`,
	} {
		f, _, env := apiEnv(t)
		serveLive(f, liveText, nil, nil)
		f.ServeValidate(apitest.TestsPassEmptyObject())
		if out, err := runValidate(t, env, func(in *tools.ACLValidateInput) { in.Patch, in.Operator = patch, true }); err != nil || out.Status != "pass" || posts(f) != 1 {
			t.Errorf("operator patch, %s: status %q, err %v, %d POSTs", name, out.Status, err, posts(f))
		}
	}
}

// The engine's own caps on a patch reach the caller as typed results and errors: a patch that
// does not apply is invalid, a copy is refused, more than 256 operations is too_complex.
func TestAPatchOfMoreThan256OperationsOrACopyIsRefused(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	many := "[" + strings.TrimSuffix(strings.Repeat(`{"op":"add","path":"/hosts","value":{"edge":"192.0.2.9"}},`, 257), ",") + "]"
	_, err := call(t, newRegistry(t), env, "acl_validate", patchCall(many))
	if code(err) != tkerr.TooComplex || tkerr.ExitCode(err) != 2 || posts(f) != 0 {
		t.Errorf("257 operations: err = %v, %d POSTs, want too_complex", err, posts(f))
	}
	for name, c := range map[string]struct{ patch, want string }{
		"a copy":                           {`[{"op":"copy","from":"/acls","path":"/grants"}]`, "copy"},
		"not an array":                     {`{"op":"add"}`, "must be a JSON array"},
		"an operation that does not apply": {`[{"op":"remove","path":"/nothing/here"}]`, "does not apply"},
		"syntax":                           {`[{"op":`, ""},
	} {
		out := validateOnline(t, env, patchCall(c.patch))
		if out.Status != "invalid" || len(out.Errors) != 1 || out.Errors[0].Source != "patch" || !strings.Contains(out.Errors[0].Message, c.want) {
			t.Errorf("%s: status %q, errors %+v", name, out.Status, out.Errors)
		}
	}
	if posts(f) != 0 {
		t.Errorf("%d POSTs for patches that were never valid", posts(f))
	}
}

// Problems found in a patched text are placed by a JSON pointer into the patched policy and
// carry no line: the caller wrote operations, not that text.
func TestProblemsInAPatchedTextCarryAPointerAndNoLine(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, peoplePolicy, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	collide := validateOnline(t, env, patchCall(`[{"op":"add","path":"/TagOwners","value":{}}]`))
	if collide.Status != "invalid" || len(collide.Errors) != 1 || collide.Errors[0].Kind != "case_collision" ||
		collide.Errors[0].Source != "patch" || collide.Errors[0].Line != 0 || collide.Errors[0].Pointer != "/TagOwners" {
		t.Fatalf("a patch that writes a key in two cases: %+v", collide)
	}
	if posts(f) != 0 {
		t.Error("an invalid patched text was sent")
	}
	// A failed test of the patched text is placed by its test, by pointer.
	f2, _, env2 := apiEnv(t)
	serveLive(f2, peoplePolicy, nil, nil)
	f2.ServeValidate(apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{`[acl test error]: address "192.0.2.9:80": want: Accept, got: Drop`}}))
	out := validateOnline(t, env2, patchCall(`[{"op":"add","path":"/tests/-","value":{"src":"tag:ci","accept":["192.0.2.9:80"]}}]`))
	if out.Status != "fail" || len(out.Errors) != 1 || out.Errors[0].Source != "patch" || out.Errors[0].Line != 0 || out.Errors[0].Pointer != "/tests/2" {
		t.Errorf("status %q, errors %+v", out.Status, out.Errors)
	}
	// A rejection by position is not placed either: the server counted the lines of a text the
	// caller never wrote.
	f3, _, env3 := apiEnv(t)
	serveLive(f3, peoplePolicy, nil, nil)
	f3.ServeValidate(apitest.PolicySyntaxError(7, 3, "unexpected"))
	pos := validateOnline(t, env3, patchCall(`[{"op":"add","path":"/hosts","value":{"edge":"192.0.2.9"}}]`))
	if pos.Status != "rejected" || len(pos.Errors) != 1 || pos.Errors[0].Line != 0 || pos.Errors[0].Source != "patch" {
		t.Errorf("a positioned rejection of a patched text: %+v", pos.Errors)
	}
}

// A section the patch adds that this version does not know is a notice; the live policy's
// own unknown section is reported once, on the live side.
func TestAnUnknownSectionAddedByAPatchIsANoticeOnce(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, "{\n\"newThing\": {}\n}\n", nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	out := validateOnline(t, env, patchCall(`[{"op":"add","path":"/otherThing","value":{}}]`))
	var names []string
	for _, n := range out.Notices {
		names = append(names, n.Source+":"+n.Kind)
	}
	if out.Status != "pass" || strings.Join(names, ",") != "live:unknown_section,patch:unknown_section" {
		t.Errorf("status %q, notices %v", out.Status, names)
	}
}

// A marker of a pseudonym in a file the operator names is invalid: the file holds logins.
func TestAnOperatorFileWithAPseudonymMarkerIsInvalid(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	text := "{\n\"groups\": {\"group:eng\": [\"a…@example.com [p:abcdefghij]\"]}\n}\n"
	out, err := runValidate(t, env, func(in *tools.ACLValidateInput) { in.Policy, in.Offline, in.Operator = text, true, true })
	if err != nil || out.Status != "invalid" || len(out.Errors) != 1 || out.Errors[0].Line != 2 || out.Errors[0].Kind != "structure" ||
		!strings.Contains(out.Errors[0].Message, "an operator file holds logins") {
		t.Fatalf("a policy file: %+v, %v", out, err)
	}
	patch := `[{"op":"add","path":"/groups/group:eng","value":["[p:abcdefghij]"]}]`
	out, err = runValidate(t, env, func(in *tools.ACLValidateInput) { in.Patch, in.Operator = patch, true })
	if err != nil || out.Status != "invalid" || out.Errors[0].Source != "patch" || len(f.Requests()) != 0 {
		t.Errorf("a patch file: %+v, %v, %d requests", out, err, len(f.Requests()))
	}
}

func TestACLValidateRefusesPolicyAndPatchTogetherAndAnOfflinePatch(t *testing.T) {
	tool, _ := newRegistry(t).Get("acl_validate")
	if _, err := tool.Validate(json.RawMessage(`{"policy":"{}","patch":"[]"}`)); code(err) != tkerr.ValidationFailed {
		t.Errorf("both: err = %v, want validation_failed", err)
	}
	if _, err := tool.Validate(json.RawMessage(`{"patch":"[]"}`)); err != nil {
		t.Errorf("a patch alone: %v", err)
	}
	_, err := runValidate(t, &registry.Env{}, func(in *tools.ACLValidateInput) { in.Patch, in.Offline, in.Operator = "[]", true, true })
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ValidationFailed || !strings.Contains(e.Message, "cannot be checked offline") {
		t.Errorf("an offline patch: %v", err)
	}
}

// An RFC 6902 test operation compares a value with the policy and answers whether it is
// equal, which would confirm a guess at a value masking hides (the host bits of a public
// address), at the rate of the API. An MCP patch may not hold one: the result is invalid and
// names the operation, the same whether the guess is right or wrong, and nothing is sent.
func TestAnMCPPatchMayNotHoldATestOperation(t *testing.T) {
	var results []tools.ACLValidateOutput
	for name, value := range map[string]string{"the right value": `"203.0.113.9"`, "a wrong value": `"203.0.113.10"`} {
		f, _, env := apiEnv(t)
		serveLive(f, "{\n\"hosts\": {\"edge\": \"203.0.113.9\"}\n}\n", nil, nil)
		f.ServeValidate(apitest.TestsPassEmptyObject())
		out := validateOnline(t, env, patchCall(`[{"op":"add","path":"/groups","value":{}},{"op":"test","path":"/hosts/edge","value":`+value+`}]`))
		if out.Status != "invalid" || out.ExitCode() != 2 || len(out.Errors) != 1 {
			t.Fatalf("%s: status %q, errors %+v", name, out.Status, out.Errors)
		}
		p := out.Errors[0]
		if p.Kind != "structure" || p.Source != "patch" || p.Line != 1 || !strings.Contains(p.Message, `operation 2 is "test"`) ||
			!strings.Contains(p.Message, "compares a value the caller cannot see") || strings.Contains(p.Message, "203.0.113") {
			t.Errorf("%s: problem = %+v", name, p)
		}
		if posts(f) != 0 {
			t.Errorf("%s: a validation was sent", name)
		}
		results = append(results, out)
	}
	if len(results) == 2 && !reflect.DeepEqual(results[0].Errors, results[1].Errors) {
		t.Errorf("the answer differs with the guess: %+v and %+v", results[0].Errors, results[1].Errors)
	}
	// The operation is found however its name is spelled, and in any position.
	for _, patch := range []string{`[{"op":"test","path":"/hosts/edge","value":"x"}]`, `[{"path":"/hosts/edge","value":"x","op":"TEST"}]`, `[{"op":"test","path":"/hosts/edge","value":"x"}]`, `[{"op":"add","path":"/groups","value":{},"op":"test"}]`, `[{"OP":"test","path":"/hosts/edge","value":"x"}]`, `[{"Op":"Test","path":"/hosts/edge","value":"x"}]`} {
		f, _, env := apiEnv(t)
		serveLive(f, "{\n\"hosts\": {\"edge\": \"203.0.113.9\"}\n}\n", nil, nil)
		f.ServeValidate(apitest.TestsPassEmptyObject())
		out := validateOnline(t, env, patchCall(patch))
		if out.Status != "invalid" || posts(f) != 0 || len(out.Errors) != 1 || !strings.Contains(out.Errors[0].Message, `is "test", which a patch over MCP may not hold`) {
			t.Errorf("%s: status %q, %d POSTs, errors %+v", patch, out.Status, posts(f), out.Errors)
		}
	}
	// acl_diff reads a patch the same way.
	f, _, env := apiEnv(t)
	serveLive(f, "{\n\"hosts\": {\"edge\": \"203.0.113.9\"}\n}\n", nil, nil)
	diff := diffOnline(t, env, `{"patch":`+jsonString(`[{"op":"test","path":"/hosts/edge","value":"203.0.113.9"}]`)+`}`)
	if diff.Status != "invalid" || len(diff.New.Findings) != 1 || diff.New.Findings[0].Source != "patch" {
		t.Errorf("acl_diff: status %q, findings %+v", diff.Status, diff.New.Findings)
	}
}

// The operator's own patch file keeps the test operation: the operator sees the policy, and a
// patch that asserts what it expects to find is a safe way to edit it.
func TestAnOperatorsPatchKeepsTheTestOperation(t *testing.T) {
	for _, c := range []struct {
		name, value, status string
	}{{"a test that holds", `"203.0.113.9"`, "pass"}, {"a test that does not", `"203.0.113.10"`, "invalid"}} {
		f, _, env := apiEnv(t)
		serveLive(f, "{\n\"hosts\": {\"edge\": \"203.0.113.9\"}\n}\n", nil, nil)
		f.ServeValidate(apitest.TestsPassEmptyObject())
		patch := `[{"op":"test","path":"/hosts/edge","value":` + c.value + `},{"op":"add","path":"/groups","value":{}}]`
		out, err := runValidate(t, env, func(in *tools.ACLValidateInput) { in.Patch, in.Operator = patch, true })
		if err != nil || out.Status != c.status {
			t.Errorf("%s: status %q, err %v, want %q", c.name, out.Status, err, c.status)
		}
	}
}

// The operations the refusal of a test operation offers are operations that apply: a caller who
// follows the advice gets a patch the engine reads, and copy, which it does not apply, is not
// among them.
func TestTheRefusalOfATestOperationOffersOnlyOperationsThatApply(t *testing.T) {
	const live = "{\n\"hosts\": {\"edge\": \"203.0.113.9\"}\n}\n"
	f, _, env := apiEnv(t)
	serveLive(f, live, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	refused := validateOnline(t, env, patchCall(`[{"op":"test","path":"/hosts/edge","value":"x"}]`))
	if len(refused.Errors) != 1 {
		t.Fatalf("errors = %+v", refused.Errors)
	}
	_, advice, ok := strings.Cut(refused.Errors[0].Message, "; use ")
	if !ok {
		t.Fatalf("the refusal gives no advice: %q", refused.Errors[0].Message)
	}
	patches := map[string]string{
		"add":     `[{"op":"add","path":"/groups","value":{}}]`,
		"replace": `[{"op":"replace","path":"/hosts/edge","value":"203.0.113.10"}]`,
		"remove":  `[{"op":"remove","path":"/hosts/edge"}]`,
		"move":    `[{"op":"move","from":"/hosts/edge","path":"/hosts/edge2"}]`,
	}
	named := 0
	for _, word := range strings.FieldsFunc(advice, func(r rune) bool { return r == ' ' || r == ',' }) {
		if word == "or" {
			continue
		}
		named++
		patch, ok := patches[word]
		if !ok {
			t.Errorf("the advice offers %q, which is no operation that applies", word)
			continue
		}
		if out := validateOnline(t, env, patchCall(patch)); out.Status != "pass" {
			t.Errorf("%s: status %q, errors %+v", word, out.Status, out.Errors)
		}
	}
	if named != len(patches) {
		t.Errorf("the advice names %d operations, want the %d that apply: %q", named, len(patches), advice)
	}
	// What the advice leaves out is refused.
	if out := validateOnline(t, env, patchCall(`[{"op":"copy","from":"/hosts/edge","path":"/hosts/edge2"}]`)); out.Status != "invalid" {
		t.Errorf("copy: status %q", out.Status)
	}
}
