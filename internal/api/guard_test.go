package api

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/creds"
)

type recordingTransport struct{ sent []string }

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.sent = append(r.sent, req.Method+" "+req.URL.EscapedPath())
	return &http.Response{StatusCode: 200, Body: http.NoBody, Header: http.Header{}, Request: req}, nil
}

// The read client sends GET, and POST to its own tailnet's validate path; the
// guard refuses everything else before it leaves the process.
func TestGuardAllowsOnlyGETAndTheValidatePOST(t *testing.T) {
	rec := &recordingTransport{}
	g := &guard{next: rec, validate: "/api/v2/tailnet/T1234CNTRL/acl/validate"}
	for _, c := range []struct {
		method, path string
		allowed      bool
	}{
		{"GET", "/api/v2/tailnet/T1234CNTRL/devices", true},
		{"POST", "/api/v2/tailnet/T1234CNTRL/acl/validate", true},
		{"POST", "/api/v2/tailnet/T1234CNTRL/acl", false},
		{"POST", "/api/v2/tailnet/OTHER/acl/validate", false},
		{"POST", "/api/v2/tailnet/T1234CNTRL/acl/validate/x", false},
		{"PUT", "/api/v2/tailnet/T1234CNTRL/acl/validate", false},
		{"DELETE", "/api/v2/device/n1", false},
		{"PATCH", "/api/v2/tailnet/T1234CNTRL/settings", false},
		{"HEAD", "/api/v2/tailnet/T1234CNTRL/devices", false},
	} {
		req, err := http.NewRequest(c.method, "https://api.example.test"+c.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		before := len(rec.sent)
		resp, err := g.RoundTrip(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if sent := len(rec.sent) > before; sent != c.allowed || (err == nil) != c.allowed {
			t.Errorf("%s %s: sent %v, err %v", c.method, c.path, sent, err)
		}
		if !c.allowed && (err == nil || !strings.Contains(err.Error(), "refuses")) {
			t.Errorf("%s %s: err = %v", c.method, c.path, err)
		}
	}
}

// scripted answers token requests and API reads, and records every request that
// reaches it, below the guard.
type scripted struct{ seen []string }

func (s *scripted) RoundTrip(req *http.Request) (*http.Response, error) {
	s.seen = append(s.seen, req.Method+" "+req.URL.EscapedPath())
	body := `{}`
	if strings.HasSuffix(req.URL.Path, "/oauth/token") || strings.HasSuffix(req.URL.Path, "/oauth/token-exchange") {
		body = `{"access_token":"test-access-token","token_type":"Bearer","expires_in":3600}`
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{"Content-Type": {"application/json"}}, Request: req}, nil
}

// New must put the guard in front of every credential kind's client: a client
// built without it would send a policy write with the read credential.
func TestNewInstallsTheGuardForEveryCredentialKind(t *testing.T) {
	for _, cred := range []creds.Read{
		{Kind: creds.KindOAuth, ClientID: "test-client-id", ClientSecret: creds.NewSecret("test-client-secret")},
		{Kind: creds.KindAPIKey, APIKey: creds.NewSecret("test-api-key")},
		{Kind: creds.KindFederated, ClientID: "test-fed-client-id", IDToken: func(context.Context) (string, error) { return "test-id-token", nil }},
	} {
		s := &scripted{}
		c, err := New(context.Background(), "T1234CNTRL", cred, Options{BaseURL: "https://api.example.test", Transport: s, Retries: -1})
		if err != nil {
			t.Fatal(err)
		}
		noop := func(io.Reader, *http.Response) error { return nil }
		for _, m := range []string{"POST /acl", "DELETE /acl", "PUT /settings", "PATCH /settings", "POST /acl/validate/x"} {
			method, path, _ := strings.Cut(m, " ")
			err := c.do(context.Background(), method, "https://api.example.test"+c.TailnetPath(path), []byte("{}"), "application/json", "application/json", false, noop)
			if err == nil || !strings.Contains(err.Error(), "refuses") {
				t.Errorf("kind %v: %s: err = %v", cred.Kind, m, err)
			}
		}
		// The validate POST passes the guard (the federated token exchange may still
		// fail against this stub; that is not what this test checks).
		if err := c.do(context.Background(), "POST", "https://api.example.test"+c.TailnetPath("/acl/validate"), []byte("[]"), "application/json", "application/json", false, noop); err != nil && strings.Contains(err.Error(), "refuses") {
			t.Errorf("kind %v: the validate POST was refused: %v", cred.Kind, err)
		}
		for _, r := range s.seen {
			if !strings.HasPrefix(r, "GET ") && r != "POST /api/v2/tailnet/T1234CNTRL/acl/validate" && !strings.HasSuffix(r, "/oauth/token") && !strings.HasSuffix(r, "/oauth/token-exchange") {
				t.Errorf("kind %v: %q got past the guard", cred.Kind, r)
			}
		}
	}
}
