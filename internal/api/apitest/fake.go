// Package apitest is a fake Tailscale API for tests. It serves the OAuth token
// endpoint, requires the bearer token it issued, records every request, and
// answers registered routes. It contains no credential-shaped strings.
package apitest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/creds"
)

// Fixed test identities. They are deliberately not shaped like real keys.
const (
	ClientID     = "test-client-id"
	ClientSecret = "test-client-secret"
	AccessToken  = "test-access-token"
	Tailnet      = "T1234CNTRL"
	// FedClientID is the federated identity the token-exchange route accepts.
	FedClientID = "test-fed-client-id"
)

// Request is one recorded request.
type Request struct {
	Method      string
	Path        string // escaped path, e.g. /api/v2/tailnet/T1234CNTRL/devices
	Query       url.Values
	Auth        string
	Accept      string
	ContentType string
	Body        []byte
}

// ValidatePath is the only path tailkeeper may send a request other than GET to:
// policy validation, which never changes the policy.
const ValidatePath = "/api/v2/tailnet/" + Tailnet + "/acl/validate"

// Fake is a running fake API server.
type Fake struct {
	Server *httptest.Server
	// Scope is returned in the token response's "scope" field.
	Scope string
	// ExpiresIn is the token lifetime in seconds the OAuth token route grants; 0
	// grants an hour.
	ExpiresIn int
	// NumberTokens makes the OAuth token route issue AccessToken-1, AccessToken-2,
	// ... in turn; API routes then accept only the newest.
	NumberTokens bool

	t         testing.TB
	mu        sync.Mutex
	requests  []Request
	routes    map[string]http.HandlerFunc
	fallback  http.HandlerFunc // answers a path no route handles; nil answers 404
	tokens    int
	latest    string // the newest numbered token
	idToken   string // the identity token the exchange accepts; "" accepts none
	failures  []int  // statuses the next exchanges return, in order
	exchanges int
}

// AcceptIDToken makes the token-exchange route accept tok for FedClientID.
func (f *Fake) AcceptIDToken(tok string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.idToken = tok
}

// FailExchanges makes the next exchanges return these statuses, in order.
func (f *Fake) FailExchanges(statuses ...int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures = append(f.failures, statuses...)
}

// ExchangeRequests returns how many times the token-exchange endpoint was called.
func (f *Fake) ExchangeRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.exchanges
}

// exchange mirrors Tailscale's token exchange: a form POST of client_id and jwt.
func (f *Fake) exchange(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.exchanges++
	fail := 0
	if len(f.failures) > 0 {
		fail, f.failures = f.failures[0], f.failures[1:]
	}
	want := f.idToken
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if fail != 0 {
		w.WriteHeader(fail)
		_, _ = w.Write([]byte(`{"message":"exchange failed"}`))
		return
	}
	if err := r.ParseForm(); err != nil || r.PostForm.Get("client_id") != FedClientID || want == "" || r.PostForm.Get("jwt") != want {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"identity token refused"}`))
		return
	}
	_, _ = w.Write([]byte(`{"access_token":"` + AccessToken + `","token_type":"Bearer","expires_in":3600}`))
}

// New starts a fake API and stops it when the test ends.
func New(t testing.TB) *Fake {
	f := &Fake{t: t, routes: map[string]http.HandlerFunc{}, Scope: "devices:core:read dns:read"}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Server.Close)
	return f
}

// URL is the base URL to pass as api.Options.BaseURL.
func (f *Fake) URL() string { return f.Server.URL }

// Handle registers a handler for method and escaped path.
func (f *Fake) Handle(method, path string, h http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[method+" "+path] = h
}

// Fallback registers a handler for every path that has no route of its own. The
// request is recorded and its bearer token checked first, as for any other.
func (f *Fake) Fallback(h http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fallback = h
}

// Raw registers a fixed response with any body (also empty) and extra headers,
// such as an ETag or a content type other than JSON.
func (f *Fake) Raw(method, path string, status int, body string, headers map[string]string) {
	f.Handle(method, path, func(w http.ResponseWriter, _ *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
}

// JSON registers a fixed JSON response.
func (f *Fake) JSON(method, path string, status int, body string) {
	f.Handle(method, path, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
}

// Requests returns the API requests recorded so far (token requests excluded).
func (f *Fake) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Request(nil), f.requests...)
}

// TokenRequests returns how many times the token endpoint was called.
func (f *Fake) TokenRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == "/api/v2/oauth/token" {
		f.token(w, r)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/v2/oauth/token-exchange" {
		f.exchange(w, r)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	// A spy over every test that uses the fake: tailkeeper's read client may send
	// nothing but GET, and POST to the validate path.
	if r.Method != http.MethodGet && !(r.Method == http.MethodPost && r.URL.EscapedPath() == ValidatePath) {
		f.t.Errorf("tailkeeper sent %s %s: the read client may send only GET, and POST %s", r.Method, r.URL.EscapedPath(), ValidatePath)
	}
	f.mu.Lock()
	f.requests = append(f.requests, Request{Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.Query(), Auth: r.Header.Get("Authorization"),
		Accept: r.Header.Get("Accept"), ContentType: r.Header.Get("Content-Type"), Body: body})
	h := f.routes[r.Method+" "+r.URL.EscapedPath()]
	if h == nil {
		h = f.fallback
	}
	want := "Bearer " + AccessToken
	if f.NumberTokens {
		want = "Bearer " + f.latest
	}
	f.mu.Unlock()
	if r.Header.Get("Authorization") != want {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
		return
	}
	if h == nil {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"no fake route for ` + r.Method + ` ` + r.URL.EscapedPath() + `"}`))
		return
	}
	h(w, r)
}

func (f *Fake) token(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.tokens++
	scope, expires, tok := f.Scope, f.ExpiresIn, AccessToken
	if f.NumberTokens {
		tok += "-" + strconv.Itoa(f.tokens)
	}
	f.mu.Unlock()
	if expires == 0 {
		expires = 3600
	}
	if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "client_credentials" ||
		r.PostForm.Get("client_id") != ClientID || r.PostForm.Get("client_secret") != ClientSecret {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
		return
	}
	f.mu.Lock()
	f.latest = tok
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"access_token":"` + tok + `","token_type":"Bearer","expires_in":` + strconv.Itoa(expires) + `,"scope":"` + scope + `"}`))
}

// Client returns an api.Client for the fake's tailnet using the fake OAuth client,
// with retries sleeping zero time.
func (f *Fake) Client(t testing.TB) *api.Client {
	t.Helper()
	c, err := api.New(context.Background(), Tailnet,
		creds.Read{Kind: creds.KindOAuth, ClientID: ClientID, ClientSecret: creds.NewSecret(ClientSecret), Provider: "env"},
		api.Options{BaseURL: f.URL(), Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	return c
}
