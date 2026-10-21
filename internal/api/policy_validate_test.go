package api_test

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// send is the policy-mode send of the client for these tests.
func send(c *api.Client, body string) (api.PolicyValidation, error) {
	return api.ValidatePolicyForTest(c, context.Background(), []byte(body))
}

const emptyPolicy = "{}"

// The body goes out as the caller wrote it: comments, trailing commas and CRLF are the
// owner's, and the answer is about those bytes (A-11).
func TestAPolicyPostCarriesTheExactBytes(t *testing.T) {
	policy := "// the owner's comment\r\n{\r\n\t\"tagOwners\": {},\r\n\t\"acls\": [],\r\n}\r\n"
	f := apitest.New(t)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	v, err := send(f.Client(t), policy)
	if err != nil || v.Status != api.PolicyPass {
		t.Fatalf("= %+v, %v", v, err)
	}
	reqs := f.Requests()
	if len(reqs) != 1 {
		t.Fatalf("%d requests", len(reqs))
	}
	if r := reqs[0]; r.Method != "POST" || r.Path != apitest.ValidatePath || r.ContentType != "application/hujson" || r.Accept != "application/json" || string(r.Body) != policy {
		t.Errorf("request = %s %s %q %q %q", r.Method, r.Path, r.ContentType, r.Accept, r.Body)
	}
}

// A body that is not an object would run in tests mode (an array) or be no policy at all:
// it is never sent, because a pass for it would be a pass for a policy never validated (A-2).
func TestValidatePolicyRefusesANonObjectBody(t *testing.T) {
	for _, body := range []string{"[]", "", "   ", "null", `"x"`, "1", "\xef\xbb\xbf{}", "// only a comment\n", "/* never closed {}", "[{}]"} {
		f := apitest.New(t)
		f.ServeValidate(apitest.TestsPassEmptyObject())
		_, err := send(f.Client(t), body)
		if e, ok := tkerr.As(err); !ok || e.Code != tkerr.Internal || !strings.Contains(e.Message, "top-level object") {
			t.Errorf("%q: err = %v, want internal_error", body, err)
		}
		if n := len(f.Requests()); n != 0 {
			t.Errorf("%q: %d requests reached the API", body, n)
		}
	}
	for _, body := range []string{"{}", "  {}", "// c\n{}", "/* c */ {}", "// a\n/* b */\n\t{\"acls\": []}"} {
		f := apitest.New(t)
		f.ServeValidate(apitest.TestsPassEmptyObject())
		if _, err := send(f.Client(t), body); err != nil {
			t.Errorf("%q: %v", body, err)
		}
	}
}

// answers serves the validate endpoint with the given shapes, one for each request, the
// last one for every request after that, and counts the requests.
func answers(f *apitest.Fake, shapes ...apitest.Shape) *atomic.Int32 {
	var calls atomic.Int32
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, _ *http.Request) {
		n := int(calls.Add(1))
		shapes[min(n, len(shapes))-1].Write(w)
	})
	return &calls
}

func TestFiveHundredIsRetriedOnceThenPolicyRejectedOrServerError(t *testing.T) {
	f := apitest.New(t)
	f.ServeValidate(apitest.PolicyServerError500())
	v, err := send(f.Client(t), emptyPolicy)
	e, ok := tkerr.As(err)
	if !ok || e.Code != tkerr.PolicyRejectedOrServerError || e.Status != 500 || tkerr.ExitCode(err) != 1 {
		t.Fatalf("= %+v, %#v", v, err)
	}
	if n := len(f.Requests()); n != 2 {
		t.Errorf("%d requests, want 2: the first and one retry", n)
	}
	if !strings.Contains(e.Hint, "remove sections") || !strings.Contains(e.Hint, "autogroup:self") {
		t.Errorf("hint = %q", e.Hint)
	}
	// The error's hint and the program hint of the code give one instruction about running
	// the call again: it is safe, and it fails the same way until sections are removed.
	for _, h := range []string{e.Hint, tkerr.ProgramHint(tkerr.PolicyRejectedOrServerError)} {
		if !strings.Contains(h, "fails the same way") {
			t.Errorf("a hint that does not say that running it again fails the same way: %q", h)
		}
	}
	if strings.Contains(e.Message, "internal server error") || e.Message != "Tailscale answered HTTP 500 twice to this policy" {
		t.Errorf("message = %q, want tailkeeper's words and none of the server's", e.Message)
	}
}

func TestASecondAttemptThatSucceedsAfterA500IsUsed(t *testing.T) {
	f := apitest.New(t)
	calls := answers(f, apitest.PolicyServerError500(), apitest.TestsPassEmptyObject())
	v, err := send(f.Client(t), emptyPolicy)
	if err != nil || v.Status != api.PolicyPass || calls.Load() != 2 {
		t.Errorf("= %+v, %v after %d requests", v, err, calls.Load())
	}
}

func TestOtherServerErrorsRetryLikeReads(t *testing.T) {
	for _, status := range []int{429, 502, 503, 504} {
		f := apitest.New(t)
		down := apitest.Shape{Endpoint: apitest.EndpointValidate, Status: status, Header: map[string]string{"Content-Type": "application/json"}, Body: `{"message":"down"}`}
		calls := answers(f, down, down, down, apitest.TestsPassEmptyObject())
		v, err := send(f.Client(t), emptyPolicy)
		if err != nil || v.Status != api.PolicyPass || calls.Load() != 4 {
			t.Errorf("HTTP %d three times, then a pass: %+v, %v after %d requests, want a pass after 4", status, v, err, calls.Load())
		}
	}
	f := apitest.New(t)
	f.JSON("POST", apitest.ValidatePath, 503, `{"message":"down"}`)
	_, err := send(f.Client(t), emptyPolicy)
	if tkerr.From(err).Code != tkerr.UpstreamUnavailable || len(f.Requests()) != 4 {
		t.Errorf("503 every time: %v after %d requests, want upstream_unavailable after 4", err, len(f.Requests()))
	}
}

// The one retry belongs to the 500, not to the call: a 500 that comes after other server
// errors is still retried once.
func TestA500AfterOtherErrorsIsStillRetriedOnce(t *testing.T) {
	unavailable := apitest.Shape{Endpoint: apitest.EndpointValidate, Status: 503, Header: map[string]string{"Content-Type": "application/json"}, Body: `{"message":"down"}`}
	f := apitest.New(t)
	calls := answers(f, unavailable, apitest.PolicyServerError500())
	_, err := send(f.Client(t), emptyPolicy)
	if tkerr.From(err).Code != tkerr.PolicyRejectedOrServerError || calls.Load() != 3 {
		t.Errorf("503, 500, 500: %v after %d requests, want policy_rejected_or_server_error after 3", err, calls.Load())
	}
}

// A 500 is not retried at all by a client whose retries are off, and the message does not
// claim a second try.
func TestAClientWithoutRetriesSendsOnceAndSaysSo(t *testing.T) {
	f := apitest.New(t)
	f.ServeValidate(apitest.PolicyServerError500())
	c := newClient(t, f, api.Options{Retries: -1})
	_, err := send(c, emptyPolicy)
	if e := tkerr.From(err); e.Code != tkerr.PolicyRejectedOrServerError || e.Message != "Tailscale answered HTTP 500 to this policy" || len(f.Requests()) != 1 {
		t.Errorf("= %v after %d requests", err, len(f.Requests()))
	}
}

func TestA400WithABareMessageIsRejectedAndAnyOther400IsUnknown(t *testing.T) {
	for _, c := range []struct {
		shape apitest.Shape
		want  api.PolicyStatus
	}{
		{apitest.Rejected400("invalid test"), api.PolicyRejected},
		{apitest.TestsFailedIn400(apitest.Entry{User: "tag:p", Errors: []string{"e"}}), api.PolicyUnknown},
	} {
		f := apitest.New(t)
		f.ServeValidate(c.shape)
		v, err := send(f.Client(t), emptyPolicy)
		if err != nil || v.Status != c.want || v.HTTP != 400 || len(f.Requests()) != 1 {
			t.Errorf("%s: %+v, %v after %d requests", c.shape.Name, v, err, len(f.Requests()))
		}
	}
}

func TestOtherStatusesMapLikeAnyRead(t *testing.T) {
	for status, want := range map[int]tkerr.Code{401: tkerr.TokenRejected, 403: tkerr.ScopeMissing, 404: tkerr.NotFound, 418: tkerr.APIError} {
		f := apitest.New(t)
		f.JSON("POST", apitest.ValidatePath, status, `{"message":"no"}`)
		_, err := send(f.Client(t), emptyPolicy)
		if tkerr.From(err).Code != want || len(f.Requests()) != 1 {
			t.Errorf("HTTP %d: %v after %d requests, want %s after 1", status, err, len(f.Requests()), want)
		}
	}
}

// A reply is read up to 1 MiB: an answer is a few messages, so more is not Tailscale's.
func TestAReplyOverOneMiBIsRefused(t *testing.T) {
	for _, c := range []struct {
		size int
		ok   bool
	}{{1 << 20, true}, {1<<20 + 1, false}} {
		f := apitest.New(t)
		f.Raw("POST", apitest.ValidatePath, 200, "{}"+strings.Repeat(" ", c.size-2), nil)
		v, err := send(f.Client(t), emptyPolicy)
		switch {
		case c.ok && (err != nil || v.Status != api.PolicyPass):
			t.Errorf("%d bytes: %+v, %v", c.size, v, err)
		case !c.ok && (tkerr.From(err).Code != tkerr.APIError || !strings.Contains(err.Error(), "longer than 1 MiB")):
			t.Errorf("%d bytes: %+v, %v", c.size, v, err)
		}
	}
}

func TestA413GetsThePolicyTooLargeHint(t *testing.T) {
	f := apitest.New(t)
	f.JSON("POST", apitest.ValidatePath, 413, `{"message":"request entity too large"}`)
	_, err := send(f.Client(t), emptyPolicy)
	e, ok := tkerr.As(err)
	if !ok || e.Code != tkerr.APIError || e.Status != 413 || !strings.Contains(e.Hint, "policy_too_large") || len(f.Requests()) != 1 {
		t.Errorf("= %#v after %d requests", err, len(f.Requests()))
	}
}

// The size hint belongs to the validate endpoint and to no other: a 413, or a 400 whose
// message speaks of size, from POST .../acl/validate has it, and the same words from a
// device query, or a 413 from a read, do not: they are not about a policy.
func TestTheSizeHintIsGivenToTheValidateEndpointOnly(t *testing.T) {
	ctx := context.Background()
	getDevices := func(cl *api.Client) error { return cl.Get(ctx, cl.TailnetPath("/devices"), nil, &devicesResp{}) }
	getPolicy := func(cl *api.Client) error { _, err := cl.GetPolicyDetails(ctx); return err }
	validateTests := func(cl *api.Client) error {
		_, err := cl.ValidateTests(ctx, []api.PolicyTest{{Src: "tag:p", Accept: []string{"tag:p:22"}}})
		return err
	}
	for _, c := range []struct {
		name, method, path string
		status             int
		message            string
		call               func(*api.Client) error
		hint               bool
	}{
		{"a device query, 400 about size", "GET", devicesPath, 400, "request body too large", getDevices, false},
		{"a device query, 400 with another size word", "GET", devicesPath, 400, "payload exceeds the limit", getDevices, false},
		{"a device query, 413", "GET", devicesPath, 413, "request entity too large", getDevices, false},
		{"a policy read, 413", "GET", aclPath, 413, "request entity too large", getPolicy, false},
		{"tests mode, 400 about size", "POST", apitest.ValidatePath, 400, "request body too large", validateTests, true},
		{"tests mode, 400 with another size word", "POST", apitest.ValidatePath, 400, "payload exceeds the limit", validateTests, true},
		{"tests mode, 400 about something else", "POST", apitest.ValidatePath, 400, "invalid test", validateTests, false},
		{"tests mode, 413", "POST", apitest.ValidatePath, 413, "request entity too large", validateTests, true},
	} {
		f := apitest.New(t)
		f.JSON(c.method, c.path, c.status, `{"message":"`+c.message+`"}`)
		err := c.call(f.Client(t))
		if e, ok := tkerr.As(err); !ok || e.Status != c.status || strings.Contains(e.Hint, "policy_too_large") != c.hint {
			t.Errorf("%s: %#v, want the size hint: %v", c.name, err, c.hint)
		}
	}
}

// In policy mode a 400 with a message is a rejection, and it stays one: the send adds the
// size hint to it when the message speaks of size, and the reader on its own never does.
func TestAPolicyModeRejectionThatSpeaksOfSizeCarriesTheHint(t *testing.T) {
	for _, c := range []struct {
		message string
		hint    bool
	}{{"request body too large", true}, {"payload exceeds the limit", true}, {"invalid test", false}} {
		shape := apitest.Rejected400(c.message)
		if v := api.ReadPolicyValidation(shape.Status, []byte(shape.Body)); v.Hint != "" {
			t.Errorf("%q: the reader set a hint: %q", c.message, v.Hint)
		}
		f := apitest.New(t)
		f.ServeValidate(shape)
		v, err := send(f.Client(t), emptyPolicy)
		if err != nil || v.Status != api.PolicyRejected || v.HTTP != 400 || strings.Contains(v.Hint, "policy_too_large") != c.hint || len(f.Requests()) != 1 {
			t.Errorf("%q: %+v, %v after %d requests", c.message, v, err, len(f.Requests()))
		}
	}
}

// Every Assumed or Observed shape that is not a pass, sent through the client, is an error
// or a result that is not a pass: the client's send joins the loops of shapes_test.go.
func TestNoShapeThatIsNotAPassReadsAsAPassThroughTheClient(t *testing.T) {
	passes := map[string]bool{"TestsPass": true, "TestsPassEmptyObject": true, "TestsWarned": true}
	n := 0
	for _, s := range apitest.AllShapes() {
		if s.Endpoint != apitest.EndpointValidate || passes[s.Name] {
			continue
		}
		n++
		f := apitest.New(t)
		f.ServeValidate(s)
		if v, err := send(f.Client(t), emptyPolicy); err == nil && v.Status == api.PolicyPass {
			t.Errorf("%s (%s) was read as a pass by the client", s.Name, s.Prov)
		}
	}
	if n < 15 {
		t.Errorf("only %d shapes walked", n)
	}
	for _, s := range []apitest.Shape{apitest.TestsPass(), apitest.TestsPassEmptyObject(), apitest.TestsWarned(apitest.Entry{User: "group:p", Warnings: []string{"w"}})} {
		f := apitest.New(t)
		f.ServeValidate(s)
		if v, err := send(f.Client(t), emptyPolicy); err != nil || v.Status != api.PolicyPass {
			t.Errorf("%s: %+v, %v", s.Name, v, err)
		}
	}
}
