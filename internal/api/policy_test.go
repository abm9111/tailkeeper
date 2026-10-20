package api_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// The probes exist to see what the API says to a request that fails, so every status
// comes back as data, and none is retried: a second attempt would be a second
// request the probe did not plan.
func TestValidatePolicyReturnsEveryStatusAsDataAndNeverRetries(t *testing.T) {
	for _, status := range []int{200, 400, 403, 404, 429, 500, 502, 503} {
		f := apitest.New(t)
		f.Raw("POST", apitest.ValidatePath, status, `{"note":"x"}`, map[string]string{"ETag": `"e1"`})
		c := f.Client(t)
		got, err := c.ValidatePolicy(context.Background(), []byte(`{"acls":[]}`), "application/hujson")
		if err != nil {
			t.Fatalf("HTTP %d: %v", status, err)
		}
		if got.Status != status || string(got.Body) != `{"note":"x"}` || got.ETag != `"e1"` {
			t.Errorf("HTTP %d: got %+v", status, got)
		}
		if n := len(f.Requests()); n != 1 {
			t.Errorf("HTTP %d: %d requests, want exactly one", status, n)
		}
	}
}

// The body and the content type go out exactly as given: the endpoint picks its mode
// from them, and the policy-mode probes depend on the bytes being untouched.
func TestValidatePolicySendsTheBytesAndTheContentTypeAsGiven(t *testing.T) {
	policy := "// a comment\r\n{\r\n\t\"acls\": [],\r\n}\r\n"
	for _, c := range []struct {
		name, contentType, body string
		permit                  bool
	}{
		{"policy mode, comments and CRLF", "application/hujson", policy, false},
		{"tests mode", "application/json", `[{"src":"tag:p","accept":["tag:p:22"]}]`, false},
		{"an empty body", "application/hujson", ``, true},
		{"a byte order mark", "application/hujson", "\xef\xbb\xbf{}", true},
		{"an array sent as HuJSON", "application/hujson", `[]`, true},
	} {
		f := apitest.New(t)
		if c.permit {
			f.PermitProbeRequests()
		}
		f.Raw("POST", apitest.ValidatePath, 200, "", nil)
		cl := f.Client(t)
		if _, err := cl.ValidatePolicy(context.Background(), []byte(c.body), c.contentType); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		reqs := f.Requests()
		if len(reqs) != 1 {
			t.Fatalf("%s: %d requests", c.name, len(reqs))
		}
		if r := reqs[0]; r.Method != "POST" || r.Path != apitest.ValidatePath || r.ContentType != c.contentType || string(r.Body) != c.body || r.Accept != "application/json" {
			t.Errorf("%s: request = %s %s %q %q %q", c.name, r.Method, r.Path, r.ContentType, r.Accept, r.Body)
		}
	}
}

// ValidatePolicy is bound by the same bounds as every call: a body over the client's
// limit is an error naming the limit, and a dead connection is a transport error.
func TestValidatePolicyBoundsAndTransportErrors(t *testing.T) {
	f := apitest.New(t)
	f.Raw("POST", apitest.ValidatePath, 200, strings.Repeat("x", 600), nil)
	c := f.Client(t)
	if _, err := c.WithMaxBody(512).ValidatePolicy(context.Background(), []byte(`{}`), "application/hujson"); err == nil || !strings.Contains(err.Error(), "exceeded 512 bytes") {
		t.Errorf("over the limit: %v", err)
	}
	f.Server.Close()
	if _, err := c.ValidatePolicy(context.Background(), []byte(`{}`), "application/hujson"); tkerr.From(err).Code != tkerr.UpstreamUnavailable {
		t.Errorf("a closed server: err = %v, want upstream_unavailable", err)
	}
}

// GetPolicy asks exactly what it is told to: details=true only with Details, an
// Accept header only when given, If-None-Match verbatim, and the answer's status and
// ETag with the body untouched. The fake answers If-None-Match as the live API does
// (A-8): a 200 with the whole policy, never a 304.
func TestGetPolicySendsOnlyWhatItIsToldTo(t *testing.T) {
	f := apitest.New(t)
	var calls atomic.Int32
	f.Handle("GET", aclPath, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		// The live endpoint does not honour If-None-Match (A-8): it answers 200 with the whole policy.
		w.Header().Set("ETag", `"abc"`)
		_, _ = w.Write([]byte("{\n}\n"))
	})
	c := f.Client(t)
	for _, tc := range []struct {
		name       string
		get        func() (api.RawResponse, error)
		wantQuery  string
		wantAccept string
		wantINM    string
		wantStatus int
		wantBody   string
	}{
		{"plain", func() (api.RawResponse, error) { return c.GetPolicy(context.Background(), api.PolicyGet{}) }, "", "", "", 200, "{\n}\n"},
		{"details", func() (api.RawResponse, error) {
			return c.GetPolicy(context.Background(), api.PolicyGet{Details: true})
		}, "details=true", "", "", 200, "{\n}\n"},
		{"accept", func() (api.RawResponse, error) {
			return c.GetPolicy(context.Background(), api.PolicyGet{Accept: "application/hujson"})
		}, "", "application/hujson", "", 200, "{\n}\n"},
		{"if-none-match", func() (api.RawResponse, error) {
			return c.GetPolicy(context.Background(), api.PolicyGet{Details: true, IfNoneMatch: `"abc"`})
		}, "details=true", "", `"abc"`, 200, "{\n}\n"},
	} {
		before := len(f.Requests())
		got, err := tc.get()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		reqs := f.Requests()
		if len(reqs) != before+1 {
			t.Fatalf("%s: %d new requests, want one", tc.name, len(reqs)-before)
		}
		r := reqs[len(reqs)-1]
		if r.Query.Encode() != tc.wantQuery || r.Accept != tc.wantAccept || r.IfNoneMatch != tc.wantINM || r.Method != "GET" {
			t.Errorf("%s: request = %s ?%s accept %q if-none-match %q", tc.name, r.Method, r.Query.Encode(), r.Accept, r.IfNoneMatch)
		}
		if got.Status != tc.wantStatus || string(got.Body) != tc.wantBody || got.ETag != `"abc"` {
			t.Errorf("%s: got %d %q etag %q", tc.name, got.Status, got.Body, got.ETag)
		}
	}
}

// Like ValidatePolicy, GetPolicy returns a failing status as data and tries once.
func TestGetPolicyReturnsFailuresAsDataAndTriesOnce(t *testing.T) {
	f := apitest.New(t)
	f.JSON("GET", aclPath, 503, `{"message":"down"}`)
	c := f.Client(t)
	got, err := c.GetPolicy(context.Background(), api.PolicyGet{})
	if err != nil || got.Status != 503 || string(got.Body) != `{"message":"down"}` {
		t.Fatalf("GetPolicy = %+v, %v", got, err)
	}
	if n := len(f.Requests()); n != 1 {
		t.Errorf("%d requests, want exactly one", n)
	}
}

// GetOnce returns every status as data and never retries: a 429 or a 5xx is one request,
// with its query sent as given, no Accept header, and a path with a ".." segment refused.
func TestGetOnceReturnsEveryStatusAsDataAndNeverRetries(t *testing.T) {
	for _, status := range []int{200, 400, 403, 404, 429, 500, 502, 503, 504} {
		f := apitest.New(t)
		f.Raw("GET", aclPath, status, `{"note":"x"}`, map[string]string{"ETag": `"e1"`})
		c := f.Client(t)
		got, err := c.GetOnce(context.Background(), c.TailnetPath("/acl"), url.Values{"details": {"true"}})
		if err != nil {
			t.Fatalf("HTTP %d: %v", status, err)
		}
		if got.Status != status || string(got.Body) != `{"note":"x"}` || got.ETag != `"e1"` {
			t.Errorf("HTTP %d: got %+v", status, got)
		}
		reqs := f.Requests()
		if len(reqs) != 1 {
			t.Fatalf("HTTP %d: %d requests, want exactly one", status, len(reqs))
		}
		if reqs[0].Method != "GET" || reqs[0].Query.Get("details") != "true" || reqs[0].Accept != "" {
			t.Errorf("HTTP %d: sent %+v", status, reqs[0])
		}
	}
	f := apitest.New(t)
	c := f.Client(t)
	if _, err := c.GetOnce(context.Background(), "/api/v2/tailnet/x/../acl", nil); tkerr.From(err).Code != tkerr.ValidationFailed {
		t.Errorf("a path with a .. segment: %v", err)
	}
	if n := len(f.Requests()); n != 0 {
		t.Errorf("%d requests for a refused path", n)
	}
	f.Server.Close()
	if _, err := c.GetOnce(context.Background(), c.TailnetPath("/acl"), nil); tkerr.From(err).Code != tkerr.UpstreamUnavailable {
		t.Errorf("a closed server: %v", err)
	}
}
