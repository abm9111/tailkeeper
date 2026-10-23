package tools_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

var pseudonymMarker = regexp.MustCompile(`\[p:[a-z2-7]{10}\]`)

// echoEnv is an environment whose tailnet has two users, one with a slash in the login, and a
// privacy key; it returns the pseudonym of each.
func echoEnv(t *testing.T) (*apitest.Fake, *registry.Registry, *registry.Env, *privacy.Key) {
	t.Helper()
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "ops/amy@example.com", "bob@example.org"))
	env, k := keyed(t, env)
	return f, reg, env, k
}

// jsonStrings is every string of a result, with its path.
func jsonStrings(t *testing.T, doc string) map[string]string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
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
	walk("$", v)
	return out
}

// A user typed as an SSH user, or a name typed as a destination, comes back as typed and masked
// by the text alone: a pseudonym beside it would be the one users_list shows for the user who
// has that address, and the call would confirm a guess with no help from Tailscale.
func TestWhatTheCallerTypedComesBackWithNoPseudonymItDidNotType(t *testing.T) {
	f, reg, env, k := echoEnv(t)
	serveBothHalves(f)
	args := `{"src":` + jsonString(k.APIPseudonym("ops/amy@example.com")) + `,"deny":["group:eng@example.com:22"],"ssh":[` +
		`{"dst":["tag:db"],"accept":["bob@example.org","root","eve [p:abcdefghij]"],"check":["carol@example.net"],"deny":["dave@example.com"]}]}`
	s := mustCall(t, reg, env, "acl_test", args, &tools.ACLTestOutput{})
	got := jsonStrings(t, s)
	for path, text := range got {
		if m := pseudonymMarker.FindString(text); m != "" {
			t.Errorf("%s = %q carries %s, which the caller did not type", path, text, m)
		}
	}
	absent(t, s, k.APIPseudonym("bob@example.org"), k.APIPseudonym("carol@example.net"), k.APIPseudonym("dave@example.com"))
	for path, want := range map[string]string{
		"$.verdicts[0].dst":     "group:eng@example.com:22",
		"$.sshVerdicts[0].user": "b…@example.org",
		"$.sshVerdicts[1].user": "root",
		"$.sshVerdicts[2].user": "eve \\u{005B}p:abcdefghij]",
		"$.sshVerdicts[3].user": "c…@example.net",
		"$.sshVerdicts[4].user": "d…@example.com",
	} {
		if got[path] != want {
			t.Errorf("%s = %q, want %q (%d strings checked)", path, got[path], want, len(got))
		}
	}
}

// With personalData show the owner asked to see, and what was typed comes back as typed.
func TestWhatTheCallerTypedIsShownAsTypedWhilePersonalDataIsShown(t *testing.T) {
	f, reg, env, _ := echoEnv(t)
	serveBothHalves(f)
	env.Config = &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","ssh":[{"dst":["tag:db"],"accept":["bob@example.org"]}]}`, &out)
	if len(out.SSHVerdicts) != 1 || out.SSHVerdicts[0].User != "bob@example.org" {
		t.Errorf("%+v", out.SSHVerdicts)
	}
}

// A destination written as a masked value with its pseudonym is the caller's own pseudonym, in
// each of the three forms a result shows a user in, and comes back as typed.
func TestAPseudonymCarrierTheCallerTypedComesBackAsTyped(t *testing.T) {
	f, reg, env, k := echoEnv(t)
	serveBothHalves(f)
	p := k.APIPseudonym("bob@example.org")
	masked := "b…@example.org" + privacy.Suffix(p)
	for _, dst := range []string{masked, p, "[" + p + "]"} {
		args := `{"src":` + jsonString(k.APIPseudonym("ops/amy@example.com")) + `,"accept":[` + jsonString(dst+":22") + `],"ssh":[{"dst":[` + jsonString(dst) + `],"accept":["root"]}]}`
		var out tools.ACLTestOutput
		mustCall(t, reg, env, "acl_test", args, &out)
		if len(out.Verdicts) != 1 || out.Verdicts[0].Dst != dst+":22" || len(out.SSHVerdicts) != 1 || out.SSHVerdicts[0].Dst != dst {
			t.Errorf("%q came back as %+v and %+v", dst, out.Verdicts, out.SSHVerdicts)
		}
		if out.Status != "pass" {
			t.Errorf("%q: status %s", dst, out.Status)
		}
	}
}

// echoCall is one acl_test from the user whose login is ops/amy@example.com with a word of the
// caller's in one place, and a reply that quotes the word back.
type echoCall struct {
	args  func(ref, word string) string
	reply func(t *testing.T, word string) http.HandlerFunc
}

func sshUserLineFor(src, dst, user string) string {
	return fmt.Sprintf("[ssh test error]: src %q at %q, dst %q at %q, ssh user %q: want: \"accept\" got: \"deny\"", src, "100.64.0.1", dst, "100.64.0.2", user)
}

const echoedUser = "ops/amy@example.com"

var echoCalls = map[string]echoCall{
	"a deny destination": {
		args: func(ref, word string) string {
			return `{"src":` + jsonString(ref) + `,"deny":["` + word + `:22"]}`
		},
		reply: func(t *testing.T, word string) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				apitest.TestsFailed(apitest.Entry{User: echoedUser, Errors: []string{
					`[acl test error]: address "` + word + `:22" (protocol "tcp"): want: Drop, got: Accept`,
					`[acl test error]: address "` + word + `:22" (protocol "udp"): want: Drop, got: Accept`,
				}}).Write(w)
			}
		},
	},
	"a protocol": {
		args: func(ref, word string) string {
			return `{"src":` + jsonString(ref) + `,"deny":["tag:web:22"],"proto":"` + word + `"}`
		},
		reply: func(t *testing.T, word string) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				apitest.TestsFailed(apitest.Entry{User: echoedUser, Errors: []string{
					`[acl test error]: address "tag:web:22" (protocol "` + word + `"): want: Drop, got: Accept`,
				}}).Write(w)
			}
		},
	},
	"an SSH user": {
		args: func(ref, word string) string {
			return `{"src":` + jsonString(ref) + `,"ssh":[{"dst":["tag:db"],"accept":["` + word + `"]}]}`
		},
		reply: func(t *testing.T, word string) http.HandlerFunc {
			return sshAnswer(t, echoedUser, "tag:db", word)
		},
	},
	"an SSH destination": {
		args: func(ref, word string) string {
			return `{"src":` + jsonString(ref) + `,"ssh":[{"dst":["` + word + `"],"accept":["root"]}]}`
		},
		reply: func(t *testing.T, word string) http.HandlerFunc {
			return sshAnswer(t, echoedUser, word, "root")
		},
	},
	"a posture value": {
		args: func(ref, word string) string {
			return `{"src":` + jsonString(ref) + `,"accept":["tag:web:22"],"srcPostureAttrs":{"node:os":"` + word + `"}}`
		},
		reply: func(t *testing.T, word string) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				apitest.TestsFailed(apitest.Entry{User: echoedUser, Errors: []string{"[acl test error]: posture attribute node:os has the value " + word}}).Write(w)
			}
		},
	},
}

// sshAnswer answers a policy-mode request with its canaries and one failed SSH line.
func sshAnswer(t *testing.T, src, dst, user string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		withSSHCanary(apitest.TestsFailed(
			apitest.Entry{User: canaryTagRE.FindString(string(body)), Errors: []string{canaryLine}},
			apitest.Entry{User: src, Errors: []string{sshUserLineFor(src, dst, user)}},
		), sshCanaryTagRE.FindString(string(body))).Write(w)
	}
}

func echoResult(t *testing.T, c echoCall, word string) string {
	t.Helper()
	f, reg, env, k := echoEnv(t)
	servePolicy(f, "{}\n", `"e1"`)
	f.Handle("POST", apitest.ValidatePath, c.reply(t, word))
	s, err := call(t, reg, env, "acl_test", c.args(k.APIPseudonym(echoedUser), word))
	if err != nil {
		t.Fatalf("%s: %v", word, err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "evaluatedAt")
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A word the caller types is shown as typed, and the result for a word that is a word of the
// resolved login (amy, ops) and the result for one that is not (zed, bob) differ in that word
// and nowhere else. A mask that read the login would tell the caller which of its guesses were
// the local part of the user.
func TestTheResultDoesNotTellWhichTypedWordIsALocalPartOfTheResolvedLoginInATool(t *testing.T) {
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
