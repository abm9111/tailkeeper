package mcpserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/privacy"
)

// markerRE is a pseudonym marker as a result shows it after a masked value.
var markerRE = regexp.MustCompile(`\[p:[a-z2-7]{10}\]`)

// structuredStrings is every string of the structured content of a result, with its path.
func structuredStrings(t *testing.T, res *mcp.CallToolResult) map[string]string {
	t.Helper()
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case string:
			out[path] = x
		case []any:
			for i, e := range x {
				walk(fmt.Sprintf("%s[%d]", path, i), e)
			}
		case map[string]any:
			for k, e := range x {
				walk(path+"."+k, e)
			}
		}
	}
	walk("$", doc)
	return out
}

// testsOrSSHAnswer answers a tests-mode request (a list of tests) with a pass, and a
// policy-mode request with both canaries and the entries the case adds.
func testsOrSSHAnswer(t *testing.T, extra func() []apitest.Entry) http.HandlerFunc {
	ssh := answerSSHCopy(t, extra)
	return func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if len(b) > 0 && b[0] == '[' {
			apitest.TestsPass().Write(w)
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(b)))
		ssh(w, r)
	}
}

// A user typed as an SSH user, a destination or a source comes back as the caller typed it,
// masked by the text alone. The registry would name it: a pseudonym beside a typed address is
// the one users_list shows for the user who has that address, and the call would confirm a
// guess with no help from Tailscale.
func TestNoFieldThatEchoesTheCallersTextCarriesAPseudonymItDidNotType(t *testing.T) {
	cs, a, f, ref := canaryServer(t, false, failureReply)
	servePolicy(f, "{}\n")
	f.Handle("POST", apitest.ValidatePath, testsOrSSHAnswer(t, nil))
	bob := a.Env.Privacy.APIPseudonym("bob@example.org")
	args := map[string]any{
		"src":  ref,
		"deny": []string{"group:eng@example.com:22"},
		"ssh": []map[string]any{{
			"dst":    []string{"tag:db"},
			"accept": []string{"bob@example.org", "root"},
			"check":  []string{"carol@example.net"},
			"deny":   []string{"dave@example.com"},
		}},
	}
	res := callTool(t, cs, "acl_test", args)
	if res.IsError {
		t.Fatalf("isError: %s", text(res, 0))
	}
	typed := map[string]bool{} // the markers the call carries itself: none
	got := structuredStrings(t, res)
	checked := 0
	for path, s := range got {
		for _, m := range markerRE.FindAllString(s, -1) {
			if !typed[m] {
				t.Errorf("%s = %q carries %s, which the caller did not type", path, s, m)
			}
		}
		checked++
	}
	all := everything(t, a, res)
	if strings.Contains(all, privacy.Suffix(bob)) || strings.Contains(all, bob) {
		t.Errorf("the pseudonym users_list shows for bob is in the result:\n%s", all)
	}
	// The check saw the fields it is about: the denominator.
	want := map[string]string{
		"$.verdicts[0].dst":     "group:eng@example.com:22",
		"$.sshVerdicts[0].user": "b…@example.org",
		"$.sshVerdicts[1].user": "root",
		"$.sshVerdicts[2].user": "c…@example.net",
		"$.sshVerdicts[3].user": "d…@example.com",
	}
	for path, s := range want {
		if got[path] != s {
			t.Errorf("%s = %q, want %q (checked %d strings)", path, got[path], s, checked)
		}
	}
}

// A destination that is a masked value with its pseudonym is the caller's own pseudonym, and
// is shown as typed.
func TestAPseudonymCarrierTheCallerTypedIsShownAsTyped(t *testing.T) {
	cs, a, f, ref := canaryServer(t, false, failureReply)
	servePolicy(f, "{}\n")
	f.Handle("POST", apitest.ValidatePath, testsOrSSHAnswer(t, nil))
	bob := "b…@example.org" + privacy.Suffix(a.Env.Privacy.APIPseudonym("bob@example.org"))
	res := callTool(t, cs, "acl_test", map[string]any{
		"src":    ref,
		"accept": []string{bob + ":22"},
		"ssh":    []map[string]any{{"dst": []string{bob}, "accept": []string{"root"}}},
	})
	if res.IsError {
		t.Fatalf("isError: %s", text(res, 0))
	}
	got := structuredStrings(t, res)
	if got["$.verdicts[0].dst"] != bob+":22" || got["$.sshVerdicts[0].dst"] != bob {
		t.Errorf("the carriers were not shown as typed: %q and %q", got["$.verdicts[0].dst"], got["$.sshVerdicts[0].dst"])
	}
	if status := got["$.status"]; status != "pass" {
		t.Errorf("status %q: %s", status, text(res, 0))
	}
}

// sshUserLine is an SSH failure of one user, in the form probe A-10 printed.
func sshUserLine(src, dst, user string) string {
	return fmt.Sprintf("[ssh test error]: src %q at %q, dst %q at %q, ssh user %q: want: \"accept\" got: \"deny\"", src, "100.64.0.1", dst, "100.64.0.2", user)
}

// echoCall is one acl_test of the user whose login is ops/amy@example.com, with a word of the
// caller's in one place, and a reply that quotes that word back.
type echoCall struct {
	args  func(ref, word string) map[string]any
	reply func(t *testing.T, word string) http.HandlerFunc
}

var echoCalls = map[string]echoCall{
	"a deny destination": {
		args: func(ref, word string) map[string]any {
			return map[string]any{"src": ref, "deny": []string{word + ":22"}}
		},
		reply: func(t *testing.T, word string) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				apitest.TestsFailed(apitest.Entry{User: canaryLogin, Errors: []string{
					`[acl test error]: address "` + word + `:22" (protocol "tcp"): want: Drop, got: Accept`,
					`[acl test error]: address "` + word + `:22" (protocol "udp"): want: Drop, got: Accept`,
				}}).Write(w)
			}
		},
	},
	"a protocol": {
		args: func(ref, word string) map[string]any {
			return map[string]any{"src": ref, "deny": []string{"tag:web:22"}, "proto": word}
		},
		reply: func(t *testing.T, word string) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				apitest.TestsFailed(apitest.Entry{User: canaryLogin, Errors: []string{
					`[acl test error]: address "tag:web:22" (protocol "` + word + `"): want: Drop, got: Accept`,
				}}).Write(w)
			}
		},
	},
	"an SSH user": {
		args: func(ref, word string) map[string]any {
			return map[string]any{"src": ref, "ssh": []map[string]any{{"dst": []string{"tag:db"}, "accept": []string{word}}}}
		},
		reply: func(t *testing.T, word string) http.HandlerFunc {
			return answerSSHCopy(t, func() []apitest.Entry {
				return []apitest.Entry{{User: canaryLogin, Errors: []string{sshUserLine(canaryLogin, "tag:db", word)}}}
			})
		},
	},
	"an SSH destination": {
		args: func(ref, word string) map[string]any {
			return map[string]any{"src": ref, "ssh": []map[string]any{{"dst": []string{word}, "accept": []string{"root"}}}}
		},
		reply: func(t *testing.T, word string) http.HandlerFunc {
			return answerSSHCopy(t, func() []apitest.Entry {
				return []apitest.Entry{{User: canaryLogin, Errors: []string{sshUserLine(canaryLogin, word, "root")}}}
			})
		},
	},
	"a posture value": {
		args: func(ref, word string) map[string]any {
			return map[string]any{"src": ref, "accept": []string{"tag:web:22"}, "srcPostureAttrs": map[string]any{"node:os": word}}
		},
		reply: func(t *testing.T, word string) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				apitest.TestsFailed(apitest.Entry{User: canaryLogin, Errors: []string{
					"[acl test error]: posture attribute node:os has the value " + word,
				}}).Write(w)
			}
		},
	},
}

// echoResult is the structured result of the call, without the time it was made.
func echoResult(t *testing.T, c echoCall, word string) string {
	t.Helper()
	cs, _, f, ref := canaryServerLogin(t, canaryLogin, failureReply)
	f.Handle("POST", apitest.ValidatePath, c.reply(t, word))
	res := callTool(t, cs, "acl_test", c.args(ref, word))
	if res.IsError {
		t.Fatalf("%s: isError: %s", word, text(res, 0))
	}
	var doc map[string]any
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "evaluatedAt")
	b, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A word the caller types is shown as typed, and the result for a word that is a word of a
// resolved login (amy, ops) and the result for one that is not (zed, bob) differ in that
// word and nowhere else. A mask that read the login would tell the caller which of its
// guesses were the local part of the user.
func TestTheResultDoesNotTellWhichTypedWordIsALocalPartOfTheResolvedLogin(t *testing.T) {
	for name, c := range echoCalls {
		t.Run(name, func(t *testing.T) {
			var results []string
			for _, word := range []string{"amy", "ops", "bob", "zed"} {
				got := echoResult(t, c, word)
				if !strings.Contains(got, word) {
					t.Errorf("a typed %q is not shown as typed: %s", word, got)
				}
				results = append(results, strings.ReplaceAll(got, word, "WORD"))
			}
			for i := 1; i < len(results); i++ {
				if results[i] != results[0] {
					t.Errorf("the results differ in more than the typed word:\n%s\n%s", results[0], results[i])
				}
			}
		})
	}
}
