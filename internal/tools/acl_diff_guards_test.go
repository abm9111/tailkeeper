package tools_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// An error that leaves acl_diff after a user was named is masked by the resolver that named
// them, as acl_validate's is: a login with a slash is not one the registry's own scan hides.
// Nothing in a comparison fails that way today, so the engine is made to fail, with a message
// that quotes the login.
func TestAnErrorOfADiffAfterAUserWasNamedLeavesNoLogin(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "ops/amy@example.com", "bob@example.org"))
	kenv, _ := keyed(t, env)
	serveLive(f, "{\"groups\": {\"group:eng\": []}}\n", nil, nil)
	ref := shownRef(t, reg, kenv, "u1")
	defer tools.SetCompareTexts(func(context.Context, *acl.Doc, *acl.Doc, acl.DiffOptions) (*acl.DiffResult, error) {
		return nil, &acl.Error{Code: acl.CodeInvalid, Message: "cannot compare for ops/amy@example.com"}
	})()
	_, err := call(t, reg, kenv, "acl_diff", `{"policy":`+jsonString("{\"groups\": {\"group:eng\": [\""+ref+"\"]}}\n")+`}`)
	if err == nil {
		t.Fatal("the comparison did not fail")
	}
	if !strings.Contains(err.Error(), "cannot compare for") {
		t.Fatalf("another error: %v", err)
	}
	if s := err.Error(); strings.Contains(s, "ops/") || strings.Contains(s, "amy") {
		t.Errorf("the error shows the login: %v", err)
	}
}

// clientWith is a client of the fake with the given options.
func clientWith(t *testing.T, f *apitest.Fake, opt api.Options) *api.Client {
	t.Helper()
	opt.BaseURL = f.URL()
	opt.Sleep = func(context.Context, time.Duration) error { return nil }
	c, err := api.New(context.Background(), apitest.Tailnet,
		creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID, ClientSecret: creds.NewSecret(apitest.ClientSecret), Provider: "env"}, opt)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The deadline of a validate call covers the read that checks the live policy did not move,
// as it covers the sends: a read that hangs ends the call at the deadline, and does not wait
// for the request's own, longer, timeout.
func TestTheRecheckOfTheLivePolicyEndsAtTheDeadlineOfTheCall(t *testing.T) {
	f := apitest.New(t)
	text := "{\n\"groups\": {\"group:eng\": []}\n}\n"
	f.Handle("GET", tailnetPath+"/acl", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("details") == "true" {
			apitest.DetailsOK(text, api.ETagOf([]byte(text)), nil, nil).Write(w)
			return
		}
		// The re-check: hang until the request is given up, or for a few seconds.
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
		apitest.PolicyText(text, api.ETagOf([]byte(text))).Write(w)
	})
	f.JSON("GET", tailnetPath+"/settings", 200, `{"aclsExternallyManagedOn":false}`)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	env := &registry.Env{API: clientWith(t, f, api.Options{ValidateDeadline: 150 * time.Millisecond, Timeout: 30 * time.Second, Retries: -1}), Now: func() time.Time { return now }}
	start := time.Now()
	_, err := call(t, newRegistry(t), env, "acl_validate", patchCall(`[{"op":"add","path":"/hosts","value":{}}]`))
	if err == nil {
		t.Fatalf("the call waited %v for the re-check and succeeded: the deadline of the call does not cover it", time.Since(start))
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("the call took %v to fail: the deadline did not end the re-check", d)
	}
}
