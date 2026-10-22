package tools_test

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// A server that repeats the members it was sent, as 400 separate logins, gives a message that
// shows the same however long the logins are. The caller sends pseudonyms; tailkeeper puts the
// logins in the text it validates; the reply quotes them; and what the message shows of them
// is cut after they are masked, so that the count of addresses it shows is not the length of a
// login the caller may not see. The four logins share one masked form, so the results are
// equal only if the cut does not depend on the length.
func TestAMessageThatEchoesTheMembersSentShowsTheSameWhateverTheLengthOfTheirLogins(t *testing.T) {
	masked := assertOneMaskedForm(t)
	members := regexp.MustCompile(`"group:eng":\s*(\[[^\]]*\])`)
	var first string
	for _, n := range echoLengths {
		login := echoLogin(n)
		f, reg, env := apiEnv(t)
		f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, login, "bob@example.org"))
		kenv, _ := keyed(t, env)
		serveLive(f, liveText, nil, nil)
		var echoed atomic.Int64
		f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, req *http.Request) {
			body, _ := io.ReadAll(req.Body)
			m := members.FindSubmatch(body)
			if m == nil {
				t.Errorf("the text sent holds no group:eng: %.200s", body)
				apitest.BareMessage200("no members").Write(w)
				return
			}
			echoed.Store(int64(strings.Count(string(m[1]), login)))
			apitest.BareMessage200("invalid members of group:eng: " + string(m[1])).Write(w)
		})
		ref := shownRef(t, reg, kenv, "u1")
		policy := `{"groups": {"group:eng": [` + strings.TrimSuffix(strings.Repeat(`"`+ref+`",`, 400), ",") + `]}}`
		got, err := call(t, reg, kenv, "acl_validate", `{"policy":`+jsonString(policy)+`}`)
		if err != nil {
			t.Fatalf("login of %d bytes: %v", n, err)
		}
		if echoed.Load() != 400 {
			t.Fatalf("login of %d bytes: the server was sent %d logins, want 400", n, echoed.Load())
		}
		absent(t, got, "xxx", "[p:", login)
		if shown := strings.Count(got, masked); shown < 40 {
			t.Errorf("login of %d bytes: %d masked addresses in the result, want at least 40: the case must reach the cut:\n%.600s", n, shown, got)
		}
		if first == "" {
			first = got
		} else if got != first {
			t.Errorf("logins of %d and %d bytes give different results:\n%.700s\n%.700s", echoLengths[0], n, first, got)
		}
	}
}

// The same holds when the server answers with an error status and the message that its error
// carries is the echo: the error leaves through the resolver, and the client keeps the message
// whole, so the number of addresses the error shows is not the length of a login.
func TestAnErrorThatEchoesTheMembersSentShowsTheSameWhateverTheLengthOfTheirLogins(t *testing.T) {
	masked := assertOneMaskedForm(t)
	members := regexp.MustCompile(`"group:eng":\s*(\[[^\]]*\])`)
	var first string
	for _, n := range echoLengths {
		login := echoLogin(n)
		f, reg, env := apiEnv(t)
		f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, login, "bob@example.org"))
		kenv, _ := keyed(t, env)
		serveLive(f, liveText, nil, nil)
		var echoed atomic.Int64
		f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, req *http.Request) {
			body, _ := io.ReadAll(req.Body)
			m := members.FindSubmatch(body)
			if m == nil {
				t.Errorf("the text sent holds no group:eng: %.200s", body)
				return
			}
			echoed.Store(int64(strings.Count(string(m[1]), login)))
			msg, _ := json.Marshal(map[string]string{"message": "invalid members of group:eng: " + string(m[1])})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write(msg)
		})
		ref := shownRef(t, reg, kenv, "u1")
		policy := `{"groups": {"group:eng": [` + strings.TrimSuffix(strings.Repeat(`"`+ref+`",`, 400), ",") + `]}}`
		_, err := call(t, reg, kenv, "acl_validate", `{"policy":`+jsonString(policy)+`}`)
		if code(err) != tkerr.APIError {
			t.Fatalf("login of %d bytes: err = %v, want api_error", n, err)
		}
		if echoed.Load() != 400 {
			t.Fatalf("login of %d bytes: the server was sent %d logins, want 400", n, echoed.Load())
		}
		got := err.Error()
		absent(t, got, "xxx", "[p:", login)
		if shown := strings.Count(got, masked); shown < 40 {
			t.Errorf("login of %d bytes: %d masked addresses in the error, want at least 40: the case must reach the cut:\n%.600s", n, shown, got)
		}
		if first == "" {
			first = got
		} else if got != first {
			t.Errorf("logins of %d and %d bytes give different errors:\n%.700s\n%.700s", echoLengths[0], n, first, got)
		}
	}
}
