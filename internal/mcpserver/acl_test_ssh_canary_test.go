package mcpserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
)

var (
	testsCanaryTag = regexp.MustCompile(`tag:tailkeeper-canary-[0-9a-f]{8}`)
	sshCanaryTag   = regexp.MustCompile(`tag:tailkeeper-sshcanary-[0-9a-f]{8}`)
)

// testsCanaryLine is the failure the tests canary produces against a policy with no rules.
const testsCanaryLine = `[acl test error]: address "192.0.2.1:1" (protocol "tcp"): want: Drop, got: Accept`

// sshCanaryEntry is the failure of the SSH canary the request carries.
func sshCanaryEntry(t *testing.T, tag string) apitest.Entry {
	t.Helper()
	s := apitest.SSHTestFailed(tag, "192.0.2.1", "192.0.2.1", "192.0.2.1", "canary")
	var body struct {
		Data []struct {
			User   string   `json:"user"`
			Errors []string `json:"errors"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(s.Body), &body); err != nil || len(body.Data) != 1 {
		t.Fatalf("SSH canary shape: %v", err)
	}
	return apitest.Entry{User: body.Data[0].User, Errors: body.Data[0].Errors}
}

// sshLine is an SSH failure for the user root, in the form probe A-10 printed.
func sshLine(src, dst string) string {
	return fmt.Sprintf("[ssh test error]: src %q at %q, dst %q at %q, ssh user %q: want: \"accept\" got: \"deny\"", src, "100.64.0.1", dst, "100.64.0.2", "root")
}

// answerSSHCopy answers a policy-mode validation: both canaries, taken from the request so
// the reader finds them, and then the entries the case adds.
func answerSSHCopy(t *testing.T, extra func() []apitest.Entry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		text := string(b)
		var es []apitest.Entry
		if tag := testsCanaryTag.FindString(text); tag != "" {
			es = append(es, apitest.Entry{User: tag, Errors: []string{testsCanaryLine}})
		}
		if tag := sshCanaryTag.FindString(text); tag != "" {
			es = append(es, sshCanaryEntry(t, tag))
		}
		if extra != nil {
			es = append(es, extra()...)
		}
		apitest.TestsFailed(es...).Write(w)
	}
}

// The login canary through acl_test with ssh. The source is a pseudonym, the login goes to
// Tailscale inside the sshTests of the policy copy, and the reply echoes it. No field of the
// result, no line of the audit log and no _meta carries the login while masking is on.
func TestALoginAPseudonymStandsForReachesOnlyTheSSHRequest(t *testing.T) {
	for name, c := range map[string]struct {
		extra  func() []apitest.Entry
		reply  func(http.ResponseWriter, string) // when set, every request gets this answer instead
		status string
		masked bool
	}{
		"a pass": {status: "pass"},
		"an SSH failure whose line names the login": {
			extra: func() []apitest.Entry {
				return []apitest.Entry{{User: canaryLogin, Errors: []string{sshLine(canaryLogin, "tag:db")}}}
			},
			status: "fail", masked: true,
		},
		"lines of the posted source that echo the login": {
			extra:  func() []apitest.Entry { return []apitest.Entry{{User: canaryLogin, Errors: echoes(canaryLogin)}} },
			status: "unknown", masked: true,
		},
		"an entry of another source that echoes the login": {
			extra:  func() []apitest.Entry { return []apitest.Entry{{User: "tag:other", Errors: echoes(canaryLogin)}} },
			status: "unknown", masked: true,
		},
		"an entry for the login in upper case": {
			extra: func() []apitest.Entry {
				return []apitest.Entry{{User: strings.ToUpper(canaryLogin), Errors: atSpellings(canaryLogin)}}
			},
			status: "unknown", masked: true,
		},
		"a rejection of the copy that echoes the login": {reply: rejectionReply, status: "unknown", masked: false},
		"a rejection at 200 that echoes the login":      {reply: rejectionAt200Reply, status: "unknown", masked: false},
		"a syntax rejection that names the login":       {reply: syntaxReply, status: "unknown", masked: false},
		"an error status that echoes the login (403)":   {reply: errorReply(http.StatusForbidden), status: "error", masked: true},
		"an error status that echoes the login (500)":   {reply: errorReply(http.StatusInternalServerError), status: "error", masked: false},
		"a failure list at 400 that echoes the login":   {reply: failuresAt400Reply, status: "unknown", masked: false},
		"an empty data list, which is no pass":          {reply: emptyDataReply, status: "unknown", masked: false},
	} {
		t.Run(name, func(t *testing.T) {
			cs, a, f, ref := canaryServer(t, false, failureReply)
			servePolicy(f, "{}\n")
			if c.reply != nil {
				f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) { c.reply(w, canaryLogin) })
			} else {
				f.Handle("POST", apitest.ValidatePath, answerSSHCopy(t, c.extra))
			}
			res := callTool(t, cs, "acl_test", map[string]any{"src": ref, "ssh": []map[string]any{{"dst": []string{"tag:db"}, "accept": []string{"root"}}}})
			all := everything(t, a, res)
			if got := leaks(all); len(got) > 0 {
				t.Errorf("the result, _meta or audit log shows %v:\n%s", got, all)
			}
			if !strings.Contains(all, `"tool":"acl_test"`) {
				t.Errorf("the audit log has no line for the call, so the audit check saw nothing:\n%s", all)
			}
			if c.status == "error" {
				if !res.IsError {
					t.Errorf("isError false, want an error; text %s", text(res, 0))
				}
			} else {
				if res.IsError {
					t.Fatalf("isError: %s", text(res, 0))
				}
				if got := structuredStatus(t, res); got != c.status {
					t.Errorf("status %q, want %q:\n%s", got, c.status, all)
				}
			}
			if c.masked && !strings.Contains(strings.ToLower(all), "o…") {
				t.Errorf("the reply echoed the login and the result shows none of its masked form:\n%s", all)
			}
			assertLoginWasSent(t, f)
		})
	}
}

// Two logins of different lengths behind one masked form give the same SSH result, byte for
// byte: a cut or a count that followed the real login would tell its length.
func TestTwoLoginsOfDifferentLengthsMaskToTheSameSSHResultOverMCP(t *testing.T) {
	run := func(login string) string {
		cs, _, f, ref := canaryServerLogin(t, login, nil)
		servePolicy(f, "{}\n")
		f.Handle("POST", apitest.ValidatePath, answerSSHCopy(t, func() []apitest.Entry {
			return []apitest.Entry{{User: login, Errors: append(echoes(login), sshLine(login, "tag:db"))}}
		}))
		res := callTool(t, cs, "acl_test", map[string]any{"src": ref, "ssh": []map[string]any{{"dst": []string{"tag:db"}, "accept": []string{"root"}}}})
		b, err := json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	short, long := run("ops/amy@example.com"), run("ops/amy-zzzzqqqqmuchlongerlocalpart@example.com")
	if short != long {
		t.Errorf("the two masked results differ:\n%s\n%s", short, long)
	}
	if strings.Contains(strings.ToLower(short), "amy") || !strings.Contains(short, "o…") {
		t.Errorf("the result shows a local part, or no masked form: %s", short)
	}
}

// The login canary with the pseudonym in a destination's user part, in tests mode and as an
// SSH destination: the login goes to Tailscale as the destination, the reply names it in
// each way, and the result shows the destination as the caller wrote it and nothing else.
func TestALoginAPseudonymStandsForInADestinationReachesOnlyTheRequest(t *testing.T) {
	quotes := func(login string) apitest.Entry {
		return apitest.Entry{User: "tag:web", Errors: []string{
			`[acl test error]: address "` + login + `:22" (protocol "tcp"): want: Accept, got: Drop`,
		}}
	}
	tests := map[string]struct {
		call   func(ref string) map[string]any
		answer func(t *testing.T) http.HandlerFunc
		status string
	}{
		"tests mode, a line that quotes the destination": {
			call: func(ref string) map[string]any {
				return map[string]any{"src": "tag:web", "accept": []string{ref + ":22"}}
			},
			answer: func(t *testing.T) http.HandlerFunc { return replyWith(apitest.TestsFailed(quotes(canaryLogin))) },
			status: "fail",
		},
		"tests mode, lines that echo the login in every spelling": {
			call: func(ref string) map[string]any {
				return map[string]any{"src": "tag:web", "accept": []string{ref + ":22"}}
			},
			answer: func(t *testing.T) http.HandlerFunc {
				return replyWith(apitest.TestsFailed(apitest.Entry{User: "tag:web", Errors: atSpellings(canaryLogin)}))
			},
			status: "unresolved",
		},
		"tests mode, an assertion line for an address nobody asked about": {
			call: func(ref string) map[string]any {
				return map[string]any{"src": "tag:web", "accept": []string{ref + ":22"}}
			},
			answer: func(t *testing.T) http.HandlerFunc {
				return replyWith(apitest.TestsFailed(apitest.Entry{User: "tag:web", Errors: []string{
					`[acl test error]: address "` + canaryLogin + `:99" (protocol "tcp"): want: Accept, got: Drop`,
				}}))
			},
			status: "unknown",
		},
		"tests mode, a deny destination echoed by another source": {
			call: func(ref string) map[string]any {
				return map[string]any{"src": "tag:web", "deny": []string{ref + ":22"}}
			},
			answer: func(t *testing.T) http.HandlerFunc {
				return replyWith(apitest.TestsFailed(apitest.Entry{User: "tag:other", Errors: echoes(canaryLogin)}))
			},
			status: "pass",
		},
		"tests mode, a pass": {
			call: func(ref string) map[string]any {
				return map[string]any{"src": "tag:web", "accept": []string{ref + ":22"}}
			},
			answer: func(t *testing.T) http.HandlerFunc { return replyWith(apitest.TestsPass()) },
			status: "pass",
		},
		"an SSH destination, a failure that names it": {
			call: func(ref string) map[string]any {
				return map[string]any{"src": "tag:web", "ssh": []map[string]any{{"dst": []string{ref}, "accept": []string{"root"}}}}
			},
			answer: func(t *testing.T) http.HandlerFunc {
				return answerSSHCopy(t, func() []apitest.Entry {
					return []apitest.Entry{{User: "tag:web", Errors: []string{sshLine("tag:web", canaryLogin)}}}
				})
			},
			status: "fail",
		},
		"an SSH destination, lines that echo it": {
			call: func(ref string) map[string]any {
				return map[string]any{"src": "tag:web", "ssh": []map[string]any{{"dst": []string{ref}, "accept": []string{"root"}}}}
			},
			answer: func(t *testing.T) http.HandlerFunc {
				return answerSSHCopy(t, func() []apitest.Entry {
					return []apitest.Entry{{User: "tag:web", Errors: echoes(canaryLogin)}}
				})
			},
			status: "unknown",
		},
	}
	for name, c := range tests {
		t.Run(name, func(t *testing.T) {
			cs, a, f, ref := canaryServer(t, false, failureReply)
			servePolicy(f, "{}\n")
			f.Handle("POST", apitest.ValidatePath, c.answer(t))
			res := callTool(t, cs, "acl_test", c.call(ref))
			all := everything(t, a, res)
			if res.IsError {
				t.Fatalf("isError: %s", text(res, 0))
			}
			if got := leaks(all); len(got) > 0 {
				t.Errorf("the result, _meta or audit log shows %v:\n%s", got, all)
			}
			if got := structuredStatus(t, res); got != c.status {
				t.Errorf("status %q, want %q:\n%s", got, c.status, all)
			}
			if !strings.Contains(all, ref) {
				t.Errorf("the destination is not shown as the caller wrote it (%s):\n%s", ref, all)
			}
			assertLoginWasSent(t, f)
		})
	}
}

func replyWith(s apitest.Shape) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { s.Write(w) }
}
