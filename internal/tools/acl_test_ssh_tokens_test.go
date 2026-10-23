package tools_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// serveBothHalves answers a tests-mode request with a pass and a policy-mode request with the
// canary a policy with no rules fails.
func serveBothHalves(f *apitest.Fake) {
	servePolicy(f, "{}\n", `"e1"`)
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) > 0 && body[0] == '[' {
			apitest.TestsPass().Write(w)
			return
		}
		withSSHCanary(apitest.TestsFailed(apitest.Entry{User: canaryTagRE.FindString(string(body)), Errors: []string{canaryLine}}), sshCanaryTagRE.FindString(string(body))).Write(w)
	})
}

// tokensLeft counts the tests-mode calls the bucket still grants. Each takes one token, the
// clock does not move, and the call that is refused ends the count.
func tokensLeft(t *testing.T, reg *registry.Registry, env *registry.Env) int {
	t.Helper()
	for n := 0; ; n++ {
		_, err := call(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:web:22"]}`)
		if code(err) == tkerr.ValidateRateLimited {
			return n
		}
		if err != nil || n > 200 {
			t.Fatalf("after %d calls: %v", n, err)
		}
	}
}

// sshForPseudonym is an SSH call from the user whose login is amy@example.com.
func sshForPseudonym(t *testing.T, f *apitest.Fake, perMinute int) (*registry.Registry, *registry.Env, string) {
	t.Helper()
	const login = "amy@example.com"
	serveBothHalves(f)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, login))
	env, k := keyed(t, limitedEnv(t, f, perMinute))
	return newRegistry(t), env, k.APIPseudonym(login)
}

func sshUsersCall(src string, tests ...string) string {
	return `{"src":` + jsonString(src) + `,"ssh":[` + strings.Join(tests, ",") + `]}`
}

func sshTest(dst string, users ...string) string {
	return `{"dst":["` + dst + `"],"accept":["` + strings.Join(users, `","`) + `"]}`
}

// Every distinct SSH user of a call from a pseudonym takes a token of its own, and a call
// from a literal source takes one: a pseudonym source can be guessed at through the SSH users
// a rule accepts, so the guesses stay at the rate of the bucket.
func TestEachDistinctSSHUserOfAPseudonymSourceTakesAValidationToken(t *testing.T) {
	const rate = 12
	f := apitest.New(t)
	reg, env, ref := sshForPseudonym(t, f, rate)
	if _, err := call(t, reg, env, "acl_test", sshUsersCall(ref, sshTest("tag:db", "root", "admin", "deploy"))); err != nil {
		t.Fatal(err)
	}
	if left := tokensLeft(t, reg, env); left != rate-3 {
		t.Errorf("3 users from a pseudonym left %d tokens of %d, want %d", left, rate, rate-3)
	}

	f = apitest.New(t)
	serveBothHalves(f)
	env = limitedEnv(t, f, rate)
	reg = newRegistry(t)
	if _, err := call(t, reg, env, "acl_test", sshUsersCall("tag:ci", sshTest("tag:db", "root", "admin", "deploy"))); err != nil {
		t.Fatal(err)
	}
	if left := tokensLeft(t, reg, env); left != rate-1 {
		t.Errorf("3 users from a literal source left %d tokens of %d, want %d", left, rate, rate-1)
	}

	// A user named twice, in two tests or in two lists, is one user.
	f = apitest.New(t)
	reg, env, ref = sshForPseudonym(t, f, rate)
	twice := `{"dst":["tag:db"],"accept":["root","admin"],"check":["ops"],"deny":["deploy"]}`
	if _, err := call(t, reg, env, "acl_test", sshUsersCall(ref, twice, sshTest("tag:web", "root"))); err != nil {
		t.Fatal(err)
	}
	if left := tokensLeft(t, reg, env); left != rate-4 {
		t.Errorf("4 distinct users (an accept, a check and a deny user among them) named 5 times left %d tokens of %d, want %d", left, rate, rate-4)
	}

	// With a pseudonym source and a call with both halves: 1 for the tests half, 3 for the users.
	f = apitest.New(t)
	reg, env, ref = sshForPseudonym(t, f, rate)
	both := `{"src":` + jsonString(ref) + `,"accept":["tag:web:22"],"ssh":[` + sshTest("tag:db", "root", "admin", "deploy") + `]}`
	if _, err := call(t, reg, env, "acl_test", both); err != nil {
		t.Fatal(err)
	}
	if left := tokensLeft(t, reg, env); left != rate-4 {
		t.Errorf("both halves with 3 users left %d tokens of %d, want %d", left, rate, rate-4)
	}
}

// A call that cannot take them all sends nothing: the bucket keeps what it had.
func TestACallThatCannotTakeAllItsSSHTokensSendsNothingAndKeepsTheBucket(t *testing.T) {
	f := apitest.New(t)
	reg, env, ref := sshForPseudonym(t, f, 5)
	for i := 0; i < 3; i++ {
		if _, err := call(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:web:22"]}`); err != nil {
			t.Fatal(err)
		}
	}
	before := posts(f)
	_, err := call(t, reg, env, "acl_test", sshUsersCall(ref, sshTest("tag:db", "root", "admin", "deploy")))
	if code(err) != tkerr.ValidateRateLimited {
		t.Fatalf("3 users with 2 tokens left: %v, want validate_rate_limited", err)
	}
	if e, _ := tkerr.As(err); e.RetryAfterSeconds <= 0 {
		t.Errorf("retryAfterSeconds = %d: a bucket that will refill says how long", e.RetryAfterSeconds)
	}
	if posts(f) != before {
		t.Errorf("%d validation requests were sent by a call that was refused", posts(f)-before)
	}
	if left := tokensLeft(t, reg, env); left != 2 {
		t.Errorf("the refused call took tokens: %d left, want 2", left)
	}
	// Two users fit.
	f = apitest.New(t)
	reg, env, ref = sshForPseudonym(t, f, 5)
	for i := 0; i < 3; i++ {
		if _, err := call(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:web:22"]}`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := call(t, reg, env, "acl_test", sshUsersCall(ref, sshTest("tag:db", "root", "admin"))); err != nil {
		t.Errorf("2 users with 2 tokens left: %v", err)
	}
}

// More users than the bucket holds can never be granted, and the error does not say to wait.
func TestMoreSSHUsersThanTheBucketHoldsIsRefusedAtOnceWithoutAWait(t *testing.T) {
	f := apitest.New(t)
	reg, env, ref := sshForPseudonym(t, f, 4)
	_, err := call(t, reg, env, "acl_test", sshUsersCall(ref, sshTest("tag:db", "u1", "u2", "u3", "u4", "u5")))
	e, ok := tkerr.As(err)
	if !ok || e.Code != tkerr.ValidateRateLimited || e.RetryAfterSeconds != 0 || !strings.Contains(e.Message, "waiting will not help") {
		t.Fatalf("err = %v, want validate_rate_limited that says waiting will not help", err)
	}
	if posts(f) != 0 {
		t.Errorf("%d validation requests were sent", posts(f))
	}
}
