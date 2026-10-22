package mcpserver

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/config"
)

// The call with invariants is two requests, and the reply to the second is Tailscale's own text
// like the first: it may echo the login the patch names by pseudonym, as a rejection, as a
// failed test, or as a warning. None of it shows the login, nor does the error, the audit line
// or _meta.
func TestAnInvariantsReplyThatEchoesALoginLeavesNoLogin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invariants.hujson")
	if err := os.WriteFile(path, []byte(`{"tests": [{"src": "tag:ci", "accept": ["tag:ci:22"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, second := range map[string]func(http.ResponseWriter, string){
		"a rejection": rejectionReply, "a failed test without the canary": failureReply, "a bare message at 200": rejectionAt200Reply,
		"a 422": errorReply(http.StatusUnprocessableEntity),
	} {
		t.Run(name, func(t *testing.T) {
			posts := 0
			reply := func(w http.ResponseWriter, login string) {
				if posts++; posts == 1 {
					apitest.TestsPassEmptyObject().Write(w)
					return
				}
				second(w, login)
			}
			cs, a, f, ref := canaryServerWith(t, false, reply, func(a *app.App) {
				a.Env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: path}}}
			})
			servePolicy(f, "{\n\"groups\": {\"group:eng\": []}\n}\n")
			res := callTool(t, cs, "acl_validate", validatePatchFor(ref))
			all := everything(t, a, res)
			if got := leaks(all); len(got) > 0 {
				t.Errorf("the result, _meta or audit log shows %v:\n%s", got, all)
			}
			if posts != 2 {
				t.Errorf("%d validation requests, want 2: the text, then the text with the invariants, so the test checked nothing", posts)
			}
			if !strings.Contains(all, `"tool":"acl_validate"`) {
				t.Errorf("the audit log has no line for the call:\n%s", all)
			}
		})
	}
}

// The second reply's failed tests are Tailscale's text too, and they are the lines most likely
// to echo a login: the reply holds the canary's failure, as it must, and failures of the
// invariants that quote the login the patch names by pseudonym. The result lists them as
// invariant failures (so the test reached the code that files them) and none shows the login.
func TestAFailedInvariantThatEchoesALoginLeavesNoLogin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invariants.hujson")
	if err := os.WriteFile(path, []byte(`{"tests": [{"src": "tag:ci", "accept": ["tag:ci:22"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cs, a, f, ref := canaryServerWith(t, false, func(http.ResponseWriter, string) {}, func(a *app.App) {
		a.Env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: path}}}
	})
	servePolicy(f, "{\n\"groups\": {\"group:eng\": []}\n}\n")
	canaryTag := regexp.MustCompile(`tag:tailkeeper-canary-[0-9a-f]{8}`)
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		tag := canaryTag.FindString(string(body))
		if tag == "" {
			apitest.TestsPassEmptyObject().Write(w)
			return
		}
		lines := append([]string{`[acl test error]: address "` + canaryLogin + `:22": want: Drop, got: Accept`}, echoes(canaryLogin)...)
		apitest.TestsFailed(
			apitest.Entry{User: tag, Errors: []string{`[acl test error]: address "192.0.2.1:1" (protocol "tcp"): want: Drop, got: Accept`}},
			apitest.Entry{User: canaryLogin, Errors: lines},
		).Write(w)
	})
	res := callTool(t, cs, "acl_validate", validatePatchFor(ref))
	all := everything(t, a, res)
	if got := leaks(all); len(got) > 0 {
		t.Errorf("the result, _meta or audit log shows %v:\n%s", got, all)
	}
	if !strings.Contains(all, `"kind":"invariant"`) || !strings.Contains(all, `"invariantsApplied":1`) || !strings.Contains(all, `"status":"fail"`) {
		t.Errorf("the result lists no failed invariant, so the test did not reach the code that files them:\n%s", all)
	}
}
