package mcpserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/privacy"
)

// aclTestFor is a call that names the user by pseudonym and asks about one tag.
func aclTestFor(ref string) map[string]any {
	return map[string]any{"src": ref, "accept": []string{"tag:web:22"}}
}

// atSpellings is a login as a reply may write it: the text itself, the same text in
// upper case, and each of the five ways Hide reads an at sign.
func atSpellings(login string) []string {
	local, domain, _ := strings.Cut(login, "@")
	bs := string(rune(92))
	return []string{
		login,
		strings.ToUpper(login),
		local + bs + "u0040" + domain,
		local + bs + "u{40}" + domain,
		local + bs + "u{0040}" + domain,
		local + "%40" + domain,
	}
}

func spellingReply(w http.ResponseWriter, login string) {
	apitest.TestsFailed(apitest.Entry{User: login, Errors: atSpellings(login)}).Write(w)
}

func matchedFailReply(w http.ResponseWriter, login string) {
	apitest.TestsFailed(apitest.Entry{User: login, Errors: []string{
		`[acl test error]: address "tag:web:22" (protocol "tcp"): want: Accept, got: Drop`,
		"user or host is invalid: " + strings.ToUpper(login),
	}}).Write(w)
}

func unevaluableReply(w http.ResponseWriter, login string) {
	apitest.TestUnevaluable(login).Write(w)
}

func failuresAt400Reply(w http.ResponseWriter, login string) {
	apitest.TestsFailedIn400(apitest.Entry{User: login, Errors: echoes(login)}).Write(w)
}

func passReply(w http.ResponseWriter, _ string) { apitest.TestsPass().Write(w) }

func passObjectReply(w http.ResponseWriter, _ string) { apitest.TestsPassEmptyObject().Write(w) }

func emptyDataReply(w http.ResponseWriter, _ string) { apitest.TestsEmptyData().Write(w) }

func nullDataReply(w http.ResponseWriter, _ string) { apitest.TestsNullData().Write(w) }

func emptyMessageReply(w http.ResponseWriter, _ string) { apitest.TestsEmptyMessage().Write(w) }

func errorsListReply(w http.ResponseWriter, login string) {
	apitest.ErrorsListAt200(login).Write(w)
}

func syntaxReply(w http.ResponseWriter, login string) {
	apitest.PolicySyntaxError(1, 2, "near "+login).Write(w)
}

func unknownFieldReply(w http.ResponseWriter, login string) {
	apitest.PolicyUnknownField(login).Write(w)
}

func keyRejectedReply(w http.ResponseWriter, login string) {
	apitest.PolicyKeyRejected(login).Write(w)
}

func structuredStatus(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Status
}

// aclTestShape is one answer of the validate endpoint and what the call should do with it.
type aclTestShape struct {
	reply   func(http.ResponseWriter, string)
	isError bool
	masked  bool // the answer echoes the login, so the masked form must be what is shown
}

// The login canary through acl_test. The call names a user by pseudonym, the login goes
// to Tailscale in the tests-mode request, and the reply echoes it back. No field of the
// result, no line of the audit log, no error and no _meta carries the login while masking
// is on. The replies are every tests-mode shape the reader accepts or refuses, and the
// error statuses a call can end in: an error leaves by another road than the result.
func TestALoginAPseudonymStandsForReachesOnlyTheACLTestRequest(t *testing.T) {
	shapes := map[string]aclTestShape{
		"a failed test":         {failureReply, false, true},
		"a failed assertion":    {matchedFailReply, false, true},
		"a pass with warnings":  {warningReply, false, true},
		"a pass":                {passReply, false, false},
		"a pass with an object": {passObjectReply, false, false},
		"an unevaluable test":   {unevaluableReply, false, true},
		"failures at 400":       {failuresAt400Reply, false, true},
		"a rejection":           {rejectionReply, true, true},
		"a rejection at 200":    {rejectionAt200Reply, true, true},
		"a syntax rejection":    {syntaxReply, true, true},
		"an unknown field":      {unknownFieldReply, true, true},
		"a rejected key":        {keyRejectedReply, true, true},
		"an empty data list":    {emptyDataReply, true, false},
		"a null data list":      {nullDataReply, true, false},
		"an empty message":      {emptyMessageReply, true, false},
		"an unknown object":     {errorsListReply, true, false},
		"a 403":                 {errorReply(http.StatusForbidden), true, true},
		"a 404":                 {errorReply(http.StatusNotFound), true, true},
		"a 413":                 {errorReply(http.StatusRequestEntityTooLarge), true, true},
		"a 422":                 {errorReply(http.StatusUnprocessableEntity), true, true},
		"a 429":                 {errorReply(http.StatusTooManyRequests), true, true},
		"a 500":                 {errorReply(http.StatusInternalServerError), true, true},
	}
	for name, shape := range shapes {
		t.Run(name, func(t *testing.T) {
			cs, a, f, ref := canaryServer(t, false, shape.reply)
			servePolicy(f, "{}\n")
			res := callTool(t, cs, "acl_test", aclTestFor(ref))
			all := everything(t, a, res)
			if got := leaks(all); len(got) > 0 {
				t.Errorf("the result, _meta or audit log shows %v:\n%s", got, all)
			}
			if !strings.Contains(all, `"tool":"acl_test"`) {
				t.Errorf("the audit log has no line for the call, so the audit check saw nothing:\n%s", all)
			}
			if res.IsError != shape.isError {
				t.Errorf("isError %v, want %v; text %s", res.IsError, shape.isError, text(res, 0))
			}
			if shape.masked && !strings.Contains(strings.ToLower(all), "o…") {
				t.Errorf("the reply echoed the login and the result shows none of its masked form:\n%s", all)
			}
			if !shape.isError {
				status := structuredStatus(t, res)
				pass := name == "a pass" || name == "a pass with an object" || name == "a pass with warnings"
				if pass && status != "pass" || !pass && (status == "pass" || status == "") {
					t.Errorf("status %q", status)
				}
			}
			assertLoginWasSent(t, f)
		})
	}
}

// A reply that writes the login in upper case, and with each spelling of the at sign,
// is masked on the way out. The request still carries the login as it was resolved.
func TestATailscaleLineThatEchoesAResolvedLoginInAnyCaseIsMasked(t *testing.T) {
	cs, a, f, ref := canaryServer(t, false, spellingReply)
	servePolicy(f, "{}\n")
	res := callTool(t, cs, "acl_test", aclTestFor(ref))
	all := everything(t, a, res)
	if got := leaks(all); len(got) > 0 {
		t.Errorf("the result, _meta or audit log shows %v:\n%s", got, all)
	}
	if !strings.Contains(strings.ToLower(all), "o…") {
		t.Errorf("none of the echoed spellings was shown masked:\n%s", all)
	}
	assertLoginWasSent(t, f)
}

// Two logins of different lengths that mask to one form produce the same result. A cut
// taken on the real text would keep more of the line after the shorter login.
func TestTwoLoginsOfDifferentLengthsMaskToTheSameACLTestResult(t *testing.T) {
	short := "ops/amy@example.com"
	long := "ops/amy-zzzzqqqqmuchlongerlocalpart@example.com"
	for _, reply := range []func(http.ResponseWriter, string){spellingReply, rejectionAt200Reply} {
		a := maskedCall(t, short, reply)
		b := maskedCall(t, long, reply)
		if a != b {
			t.Errorf("the two masked results differ:\n%s\n%s", a, b)
		}
		if strings.Contains(strings.ToLower(a), "amy") {
			t.Errorf("a local part survived: %s", a)
		}
	}
	bare := maskedCall(t, "amy@example.com", func(w http.ResponseWriter, login string) {
		apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{"no such user: amy"}}).Write(w)
	})
	if strings.Contains(bare, "amy") || !strings.Contains(bare, "a…") {
		t.Errorf("a bare local part was not masked: %s", bare)
	}
	// A bare local part with a hyphen masks to the same text as one without.
	var bareResults []string
	for _, local := range []string{"amy", "amy-zzzzqqqqmuchlongerlocalpart", "amy.smith+tag9"} {
		bareResults = append(bareResults, maskedCall(t, local+"@example.com", func(w http.ResponseWriter, login string) {
			apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{"no such user: " + local}}).Write(w)
		}))
	}
	if bareResults[0] != bareResults[1] || bareResults[0] != bareResults[2] {
		t.Errorf("bare local parts of different spelling mask to different results:\n%s\n%s\n%s", bareResults[0], bareResults[1], bareResults[2])
	}
}

// maskedResult is the structured result of one acl_test whose reply echoes login.
func maskedCall(t *testing.T, login string, reply func(http.ResponseWriter, string)) string {
	t.Helper()
	cs, _, _, ref := canaryServerLogin(t, login, reply)
	res := callTool(t, cs, "acl_test", aclTestFor(ref))
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// canaryServerLogin is canaryServer for one login, on a clock that does not move, so two
// calls can be compared byte for byte.
func canaryServerLogin(t *testing.T, login string, reply func(http.ResponseWriter, string)) (*mcp.ClientSession, *app.App, *apitest.Fake, string) {
	t.Helper()
	f := apitest.New(t)
	users, err := json.Marshal(map[string]any{"users": []map[string]string{
		{"id": "u1", "loginName": login, "type": "member", "status": "active"}}})
	if err != nil {
		t.Fatal(err)
	}
	f.JSON("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/users", 200, string(users))
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) { reply(w, login) })
	servePolicy(f, "{}\n")
	a := newApp(t, f)
	key, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		t.Fatal(err)
	}
	a.Env.Privacy = key
	fixed := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	a.Env.Now = func() time.Time { return fixed }
	cs := connect(t, a, Options{Warn: func(s string) { t.Errorf("the server warned: %s", s) }})
	list := callTool(t, cs, "users_list", map[string]any{})
	b, _ := json.Marshal(list.StructuredContent)
	var out struct {
		Users []struct{ ID, LoginName string } `json:"users"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	for _, u := range out.Users {
		if u.ID == "u1" {
			if ref, ok := privacy.Ref(u.LoginName); ok {
				return cs, a, f, ref
			}
		}
	}
	t.Fatalf("users_list did not show a pseudonym for %s: %s", login, b)
	return nil, nil, nil, ""
}

// The live policy's text is read on the same call. A policy that names the resolved
// login does not put that login in the result: the text is not a field of acl_test.
func TestAPolicyThatNamesTheResolvedLoginLeavesNoLogin(t *testing.T) {
	cs, a, f, ref := canaryServer(t, false, passReply)
	servePolicy(f, "{\n\"grants\": [{\"src\": [\""+canaryLogin+"\"], \"dst\": [\"tag:web\"], \"ip\": [\"*\"]}]\n}\n")
	res := callTool(t, cs, "acl_test", aclTestFor(ref))
	all := everything(t, a, res)
	if res.IsError {
		t.Fatalf("isError: %s", text(res, 0))
	}
	if got := leaks(all); len(got) > 0 {
		t.Errorf("the result, _meta or audit log shows %v:\n%s", got, all)
	}
	assertLoginWasSent(t, f)
}

// With personalData show the owner asked for logins, and the result carries them.
func TestWithPersonalDataShownACLTestShowsTheLogin(t *testing.T) {
	cs, a, f, ref := canaryServer(t, true, failureReply)
	servePolicy(f, "{}\n")
	res := callTool(t, cs, "acl_test", aclTestFor(ref))
	if all := everything(t, a, res); !strings.Contains(all, canaryLogin) {
		t.Errorf("with personalData show the result should carry the login:\n%s", all)
	}
}

// A pseudonym that names no one is an error, and the error leaves no login either.
func TestAnUnresolvedPseudonymLeavesNoLoginInACLTest(t *testing.T) {
	cs, a, f, _ := canaryServer(t, false, failureReply)
	servePolicy(f, "{}\n")
	res := callTool(t, cs, "acl_test", aclTestFor("p:abcdefghij"))
	all := everything(t, a, res)
	if !res.IsError || !strings.Contains(text(res, 0), "no user has that pseudonym") {
		t.Errorf("an unknown pseudonym: isError %v, %s", res.IsError, text(res, 0))
	}
	if got := leaks(all); len(got) > 0 {
		t.Errorf("an error shows %v:\n%s", got, all)
	}
	for _, r := range f.Requests() {
		if r.Path == apitest.ValidatePath {
			t.Error("an unresolved pseudonym was sent to Tailscale")
		}
	}
}

// A typed login is refused before any request while masking is on, and the refusal
// does not repeat the login. The canary login itself holds a slash, which the source
// check refuses as a range, so this uses a login the check accepts.
func TestALiteralLoginInACLTestIsRefusedAndLeavesNoLogin(t *testing.T) {
	const login = "amy@example.com"
	cs, a, f, _ := canaryServer(t, false, failureReply)
	for _, args := range []map[string]any{
		{"src": login, "accept": []string{"tag:web:22"}},
		{"src": "tag:web", "accept": []string{login + ":22"}},
	} {
		res := callTool(t, cs, "acl_test", args)
		all := everything(t, a, res)
		if !res.IsError || !strings.Contains(text(res, 0), "filter_refused") {
			t.Errorf("%v: isError %v, %s", args["src"], res.IsError, text(res, 0))
		}
		if got := leaks(all); len(got) > 0 {
			t.Errorf("the refusal shows %v:\n%s", got, all)
		}
	}
	for _, r := range f.Requests() {
		if r.Path == apitest.ValidatePath {
			t.Error("a refused literal was sent")
		}
	}
}
