package mcpserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
)

// servePolicy serves the live policy, in both forms the tool reads, and the settings.
func servePolicy(f *apitest.Fake, text string) { servePolicyWith(f, text, nil, nil) }

// servePolicyWith is servePolicy with the warnings and the errors Tailscale stored with the
// policy, which the details read carries.
func servePolicyWith(f *apitest.Fake, text string, warnings, errs []string) {
	f.Handle("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/acl", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("details") == "true" {
			apitest.DetailsOK(text, api.ETagOf([]byte(text)), warnings, errs).Write(w)
			return
		}
		apitest.PolicyText(text, api.ETagOf([]byte(text))).Write(w)
	})
	f.JSON("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/settings", 200, `{"aclsExternallyManagedOn":false}`)
}

// validatePatchFor is the arguments of a call that names the user by pseudonym in a patch.
func validatePatchFor(ref string) map[string]any {
	return map[string]any{"patch": `[{"op":"add","path":"/groups/group:eng/-","value":"` + ref + `"}]`}
}

// errorReply answers a validation with an error status whose message echoes the login, as an
// API that refuses the call (a missing scope, an unknown tailnet, a body too large, a body it
// cannot process) might. The message is a bare one, so no hand-written validate answer is
// needed.
func errorReply(status int) func(http.ResponseWriter, string) {
	return func(w http.ResponseWriter, login string) {
		body, err := json.Marshal(map[string]string{"message": strings.Join(echoes(login), "; ")})
		if err != nil {
			panic(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}
}

// warningReply answers a validation that passes with warnings that echo the login.
func warningReply(w http.ResponseWriter, login string) {
	apitest.TestsWarned(apitest.Entry{User: login, Warnings: echoes(login)}).Write(w)
}

// The login canary through acl_validate: the patch names a user by pseudonym, the login goes
// to Tailscale in the request, and Tailscale's reply echoes it in each of the ways it might.
// No field of the result, no line of the audit log, no error and no _meta carries the login
// while masking is on. The replies are the results of every kind and the error of every status
// the call can end in, since the error leaves by another road than the result.
func TestALoginAPseudonymStandsForReachesOnlyTheValidateRequest(t *testing.T) {
	for name, reply := range map[string]func(http.ResponseWriter, string){
		"a failed test": failureReply, "a rejection": rejectionReply, "a rejection at 200": rejectionAt200Reply,
		"a pass with warnings": warningReply,
		"a 403":                errorReply(http.StatusForbidden), "a 404": errorReply(http.StatusNotFound),
		"a 413": errorReply(http.StatusRequestEntityTooLarge), "a 422": errorReply(http.StatusUnprocessableEntity),
	} {
		t.Run(name, func(t *testing.T) {
			cs, a, f, ref := canaryServer(t, false, reply)
			servePolicy(f, "{\n\"groups\": {\"group:eng\": []}\n}\n")
			res := callTool(t, cs, "acl_validate", validatePatchFor(ref))
			all := everything(t, a, res)
			if got := leaks(all); len(got) > 0 {
				t.Errorf("the result, _meta or audit log shows %v:\n%s", got, all)
			}
			if !strings.Contains(all, `"tool":"acl_validate"`) {
				t.Errorf("the audit log has no line for the call, so the audit check saw nothing:\n%s", all)
			}
			sent := false
			for _, r := range f.Requests() {
				if r.Path == apitest.ValidatePath && strings.Contains(string(r.Body), canaryLogin) {
					sent = true
				}
			}
			if !sent {
				t.Error("the validation request did not carry the login, so the test checked nothing")
			}
		})
	}
}

// What Tailscale stored with the live policy is shown too, and it may echo a login: the stored
// errors, which acl_validate lists, and the stored warnings, which decide which warnings of the
// reply are the live policy's own. Neither shows the login, nor a pseudonym beside it. Each
// test reaches the validate request: a patch with stored errors is sent, and the request
// carries the login.
func TestAStoredErrorThatEchoesALoginLeavesNoLogin(t *testing.T) {
	cs, a, f, ref := canaryServer(t, false, warningReply)
	servePolicyWith(f, "{\n\"groups\": {\"group:eng\": []}\n}\n", nil, echoes(canaryLogin))
	res := callTool(t, cs, "acl_validate", validatePatchFor(ref))
	all := everything(t, a, res)
	if got := leaks(all); len(got) > 0 {
		t.Errorf("the result, _meta or audit log shows %v:\n%s", got, all)
	}
	if !strings.Contains(all, `"serverErrors"`) || !strings.Contains(all, `"tool":"acl_validate"`) {
		t.Errorf("the result lists no stored error, so the test checked nothing:\n%s", all)
	}
	assertLoginWasSent(t, f)
}

func TestAStoredWarningThatEchoesALoginLeavesNoLogin(t *testing.T) {
	cs, a, f, ref := canaryServer(t, false, warningReply)
	servePolicyWith(f, "{\n\"groups\": {\"group:eng\": []}\n}\n", echoes(canaryLogin), nil)
	res := callTool(t, cs, "acl_validate", validatePatchFor(ref))
	all := everything(t, a, res)
	if got := leaks(all); len(got) > 0 {
		t.Errorf("the result, _meta or audit log shows %v:\n%s", got, all)
	}
	if !strings.Contains(all, `"existingWarnings"`) || !strings.Contains(all, `"tool":"acl_validate"`) {
		t.Errorf("the result lists no existing warning, so the test checked nothing:\n%s", all)
	}
	assertLoginWasSent(t, f)
}

// assertLoginWasSent fails unless a validate request carried the login: the proof that a test
// reached the request it is about.
func assertLoginWasSent(t *testing.T, f *apitest.Fake) {
	t.Helper()
	for _, r := range f.Requests() {
		if r.Path == apitest.ValidatePath && strings.Contains(string(r.Body), canaryLogin) {
			return
		}
	}
	t.Error("no validate request carried the login, so the test did not reach the request it is about")
}

// The control: with personalData show the owner asked for logins, and the result carries them.
func TestWithPersonalDataShownACLValidateShowsTheLogin(t *testing.T) {
	cs, a, f, ref := canaryServer(t, true, failureReply)
	servePolicy(f, "{\n\"groups\": {\"group:eng\": []}\n}\n")
	res := callTool(t, cs, "acl_validate", validatePatchFor(ref))
	if all := everything(t, a, res); !strings.Contains(all, canaryLogin) {
		t.Errorf("with personalData show the result should carry the login:\n%s", all)
	}
}

// A pseudonym that names no one is an error that leaves no login either.
func TestAnUnresolvedPseudonymInAPatchLeavesNoLogin(t *testing.T) {
	cs, a, f, _ := canaryServer(t, false, failureReply)
	servePolicy(f, "{\n\"groups\": {\"group:eng\": []}\n}\n")
	res := callTool(t, cs, "acl_validate", validatePatchFor("p:abcdefghij"))
	all := everything(t, a, res)
	if !res.IsError || !strings.Contains(text(res, 0), "no user has that pseudonym") {
		t.Errorf("an unknown pseudonym: isError %v, %s", res.IsError, text(res, 0))
	}
	if got := leaks(all); len(got) > 0 {
		t.Errorf("an error shows %v:\n%s", got, all)
	}
}
