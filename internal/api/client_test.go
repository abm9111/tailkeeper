package api_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

type devicesResp struct {
	Devices []struct {
		NodeID string `json:"nodeId"`
	} `json:"devices"`
}

func code(err error) tkerr.Code {
	if e, ok := tkerr.As(err); ok {
		return e.Code
	}
	return ""
}

func TestOAuthTokenReusedAndScopesRecorded(t *testing.T) {
	f := apitest.New(t)
	f.Scope = "devices:core:read users:read"
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/devices", 200, `{"devices":[{"nodeId":"n1CNTRL"}]}`)
	c := f.Client(t)
	if _, known := c.GrantedScopes(); known {
		t.Fatal("scopes known before any token was fetched")
	}
	for i := 0; i < 3; i++ {
		var out devicesResp
		if err := c.Get(context.Background(), c.TailnetPath("/devices"), nil, &out); err != nil {
			t.Fatal(err)
		}
		if out.Devices[0].NodeID != "n1CNTRL" {
			t.Fatalf("decoded %+v", out)
		}
	}
	if n := f.TokenRequests(); n != 1 {
		t.Fatalf("token requests = %d, want 1 (token must be reused)", n)
	}
	scopes, known := c.GrantedScopes()
	if !known || strings.Join(scopes, " ") != "devices:core:read users:read" {
		t.Fatalf("GrantedScopes = %v, %v", scopes, known)
	}
}

func TestOAuthTokenRefetchedOnceExpired(t *testing.T) {
	f := apitest.New(t)
	// One second is inside oauth2's ten-second expiry margin, so every request
	// must find the token expired and fetch a new one before it is sent.
	f.ExpiresIn = 1
	f.NumberTokens = true // a stale bearer is then refused, so each request must carry the new one
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/devices", 200, `{"devices":[{"nodeId":"n1CNTRL"}]}`)
	c := f.Client(t)
	for i := 0; i < 3; i++ {
		var out devicesResp
		if err := c.Get(context.Background(), c.TailnetPath("/devices"), nil, &out); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.TokenRequests(); n != 3 {
		t.Fatalf("token requests = %d, want 3 (an expired token must be replaced)", n)
	}
	var bearers []string
	for _, r := range f.Requests() {
		if r.Path == "/api/v2/tailnet/T1234CNTRL/devices" {
			bearers = append(bearers, strings.TrimPrefix(r.Auth, "Bearer "+apitest.AccessToken))
		}
	}
	if strings.Join(bearers, " ") != "-1 -2 -3" {
		t.Fatalf("API requests carried tokens %q, want each request's freshly fetched one: -1 -2 -3", bearers)
	}
}

func TestStatusMapping(t *testing.T) {
	cases := map[int]tkerr.Code{
		400: tkerr.ValidationFailed,
		401: tkerr.TokenRejected,
		402: tkerr.PaymentRequired,
		403: tkerr.ScopeMissing,
		404: tkerr.NotFound,
		409: tkerr.Conflict,
		501: tkerr.UnsupportedTarget,
		418: tkerr.APIError,
	}
	for status, want := range cases {
		f := apitest.New(t)
		f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/devices", status, `{"message":"nope`+"\\u001b"+`[31m"}`)
		c := f.Client(t)
		var out devicesResp
		err := c.Get(context.Background(), c.TailnetPath("/devices"), nil, &out)
		e, ok := tkerr.As(err)
		if !ok || e.Code != want || e.Status != status {
			t.Errorf("status %d: err = %v, want %s", status, err, want)
			continue
		}
		if strings.ContainsRune(e.Message, 0x1B) {
			t.Errorf("status %d: API message not sanitized: %q", status, e.Message)
		}
		if n := len(f.Requests()); n != 1 {
			t.Errorf("status %d: %d requests, want 1 (not retryable)", status, n)
		}
	}
}

func TestRetriesTransientThenSucceeds(t *testing.T) {
	f := apitest.New(t)
	var mu sync.Mutex
	calls := 0
	f.Handle("GET", "/api/v2/tailnet/T1234CNTRL/devices", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(429)
			return
		}
		if n == 2 {
			w.WriteHeader(504)
			return
		}
		_, _ = w.Write([]byte(`{"devices":[]}`))
	})
	var slept []time.Duration
	c, err := api.New(context.Background(), apitest.Tailnet,
		creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID, ClientSecret: creds.NewSecret(apitest.ClientSecret)},
		api.Options{BaseURL: f.URL(), Sleep: func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	var out devicesResp
	if err := c.Get(context.Background(), c.TailnetPath("/devices"), nil, &out); err != nil {
		t.Fatalf("Get after transient errors: %v", err)
	}
	if calls != 3 || len(slept) != 2 || slept[0] != 2*time.Second {
		t.Fatalf("calls=%d slept=%v; want 3 calls and a first sleep of 2s (Retry-After)", calls, slept)
	}
}

func TestRetriesAreBounded(t *testing.T) {
	f := apitest.New(t)
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/devices", 502, `{"message":"bad gateway"}`)
	c := f.Client(t)
	var out devicesResp
	err := c.Get(context.Background(), c.TailnetPath("/devices"), nil, &out)
	if code(err) != tkerr.UpstreamUnavailable {
		t.Fatalf("err = %v", err)
	}
	if n := len(f.Requests()); n != 4 {
		t.Fatalf("requests = %d, want 4 (1 + 3 retries)", n)
	}
}

func TestBadClientSecret(t *testing.T) {
	f := apitest.New(t)
	c, err := api.New(context.Background(), apitest.Tailnet,
		creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID, ClientSecret: creds.NewSecret("wrong")},
		api.Options{BaseURL: f.URL(), Retries: -1})
	if err != nil {
		t.Fatal(err)
	}
	var out devicesResp
	if err := c.Get(context.Background(), c.TailnetPath("/devices"), nil, &out); code(err) != tkerr.TokenRejected {
		t.Fatalf("err = %v, want token_rejected", err)
	}
}

func TestAPIKeyBearer(t *testing.T) {
	f := apitest.New(t)
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/devices", 200, `{"devices":[]}`)
	c, err := api.New(context.Background(), apitest.Tailnet,
		creds.Read{Kind: creds.KindAPIKey, APIKey: creds.NewSecret(apitest.AccessToken)}, api.Options{BaseURL: f.URL()})
	if err != nil {
		t.Fatal(err)
	}
	var out devicesResp
	if err := c.Get(context.Background(), c.TailnetPath("/devices"), nil, &out); err != nil {
		t.Fatal(err)
	}
	if _, known := c.GrantedScopes(); known {
		t.Fatal("API key scopes should be unknown")
	}
	if f.TokenRequests() != 0 {
		t.Fatal("API key must not call the token endpoint")
	}
}

func TestMaxBody(t *testing.T) {
	f := apitest.New(t)
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/devices", 200, `{"devices":[`+strings.Repeat(`{"nodeId":"n"},`, 200)+`{"nodeId":"n"}]}`)
	c, err := api.New(context.Background(), apitest.Tailnet,
		creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID, ClientSecret: creds.NewSecret(apitest.ClientSecret)},
		api.Options{BaseURL: f.URL(), MaxBody: 512})
	if err != nil {
		t.Fatal(err)
	}
	var out devicesResp
	err = c.Get(context.Background(), c.TailnetPath("/devices"), nil, &out)
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.APIError || !strings.Contains(e.Message, "exceeded") {
		t.Fatalf("err = %v, want api_error about size", err)
	}
}

func TestWithMaxBodyLimitsOnlyTheCopy(t *testing.T) {
	f := apitest.New(t)
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/devices", 200, `{"devices":[`+strings.Repeat(`{"nodeId":"n"},`, 200)+`{"nodeId":"n"}]}`)
	c, err := api.New(context.Background(), apitest.Tailnet,
		creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID, ClientSecret: creds.NewSecret(apitest.ClientSecret)},
		api.Options{BaseURL: f.URL()})
	if err != nil {
		t.Fatal(err)
	}
	var out devicesResp
	if err := c.WithMaxBody(512).Get(context.Background(), c.TailnetPath("/devices"), nil, &out); err == nil || !strings.Contains(err.Error(), "exceeded 512 bytes") {
		t.Fatalf("limited copy: err = %v, want the 512-byte limit", err)
	}
	if err := c.Get(context.Background(), c.TailnetPath("/devices"), nil, &out); err != nil || len(out.Devices) != 201 {
		t.Fatalf("original: %d devices, err = %v", len(out.Devices), err)
	}
	// It only lowers a limit.
	if err := c.WithMaxBody(512).WithMaxBody(1<<20).Get(context.Background(), c.TailnetPath("/devices"), nil, &out); err == nil || !strings.Contains(err.Error(), "exceeded 512 bytes") {
		t.Fatalf("raised copy: err = %v, want the 512-byte limit kept", err)
	}
}

func TestPathEscaping(t *testing.T) {
	if got := api.Path("device/%s/routes", "n1/../x"); got != "/api/v2/device/n1%2F..%2Fx/routes" {
		t.Fatalf("Path = %q", got)
	}
	f := apitest.New(t)
	c, err := api.New(context.Background(), "user@example.com",
		creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID, ClientSecret: creds.NewSecret(apitest.ClientSecret)}, api.Options{BaseURL: f.URL()})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.TailnetPath("/devices"); got != "/api/v2/tailnet/user@example.com/devices" {
		t.Fatalf("TailnetPath = %q", got)
	}
	// Escaping keeps the slash inside one segment, and Get still refuses the
	// segment: an ID never contains a slash, and some servers decode %2F first.
	var out map[string]any
	if err := c.Get(context.Background(), api.Path("device/%s/routes", "n1/../x"), nil, &out); code(err) != tkerr.ValidationFailed {
		t.Fatalf("an ID containing a slash: err = %v, want validation_failed", err)
	}
	if n := len(f.Requests()); n != 0 {
		t.Fatalf("%d requests reached the API", n)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer other.Close()
	f := apitest.New(t)
	f.Handle("GET", "/api/v2/tailnet/T1234CNTRL/devices", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/collect", http.StatusFound)
	})
	c := f.Client(t)
	err := c.Get(context.Background(), c.TailnetPath("/devices"), nil, &devicesResp{})
	if code(err) != tkerr.APIError {
		t.Errorf("err = %v, want api_error", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the redirect was followed: %d request(s) reached the other host", n)
	}
}

func TestRetryableStatusesMapToUpstream(t *testing.T) {
	for _, status := range []int{500, 502, 503, 504} {
		f := apitest.New(t)
		f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/devices", status, `{"message":"down"}`)
		c := f.Client(t)
		err := c.Get(context.Background(), c.TailnetPath("/devices"), nil, &devicesResp{})
		if code(err) != tkerr.UpstreamUnavailable {
			t.Errorf("status %d: err = %v, want upstream_unavailable", status, err)
		}
		if n := len(f.Requests()); n != 4 {
			t.Errorf("status %d: %d requests, want 4 (retried)", status, n)
		}
	}
}

func TestClientTimeoutIsRetried(t *testing.T) {
	f := apitest.New(t)
	var calls atomic.Int32
	f.Handle("GET", "/api/v2/tailnet/T1234CNTRL/devices", func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			time.Sleep(300 * time.Millisecond) // longer than the client timeout
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"devices":[]}`))
	})
	c, err := api.New(context.Background(), apitest.Tailnet,
		creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID, ClientSecret: creds.NewSecret(apitest.ClientSecret), Provider: "env"},
		api.Options{BaseURL: f.URL(), Timeout: 100 * time.Millisecond, Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), c.TailnetPath("/devices"), nil, &devicesResp{}); err != nil {
		t.Fatalf("a client timeout was not retried: %v", err)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("%d calls, want 2", n)
	}
}

func TestCallerCancellationIsNotRetried(t *testing.T) {
	f := apitest.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.Handle("GET", "/api/v2/tailnet/T1234CNTRL/devices", func(w http.ResponseWriter, r *http.Request) {
		cancel()
		time.Sleep(50 * time.Millisecond)
	})
	c := f.Client(t)
	if err := c.Get(ctx, c.TailnetPath("/devices"), nil, &devicesResp{}); err == nil {
		t.Fatal("a cancelled request succeeded")
	}
	if n := len(f.Requests()); n != 1 {
		t.Errorf("%d requests, want 1 (cancellation is not retried)", n)
	}
}

func TestTokenRequestsStopWhenTheClientContextEnds(t *testing.T) {
	// A token endpoint that never answers: only the client's context ends the wait.
	// The handler drains the body so the server notices the client hanging up, and
	// returns when the test ends.
	stop := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-stop:
		}
	}))
	defer hung.Close()
	defer close(stop)
	ctx, cancel := context.WithCancel(context.Background())
	// Without the client's context the request would end only at the 3 s timeout.
	c, err := api.New(ctx, apitest.Tailnet,
		creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID, ClientSecret: creds.NewSecret(apitest.ClientSecret)},
		api.Options{BaseURL: hung.URL, Timeout: 3 * time.Second, Retries: -1, Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	if err := c.Get(context.Background(), c.TailnetPath("/devices"), nil, &devicesResp{}); err == nil {
		t.Fatal("a request without a token succeeded")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Get took %v after the client's context ended", d)
	}
}

func TestFederatedIdentityTokenStopsWhenTheClientContextEnds(t *testing.T) {
	f := apitest.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	// The identity token never arrives unless the client's context ends; the 3 s
	// fallback only keeps a regression from hanging the suite.
	idToken := func(ctx context.Context) (string, error) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(3 * time.Second):
			return "", fmt.Errorf("the client's context never ended")
		}
	}
	c, err := api.New(ctx, apitest.Tailnet,
		creds.Read{Kind: creds.KindFederated, ClientID: apitest.FedClientID, Provider: "oidc", IDToken: idToken},
		api.Options{BaseURL: f.URL(), Timeout: 10 * time.Second, Retries: -1, Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	if err := c.Get(context.Background(), c.TailnetPath("/devices"), nil, &devicesResp{}); err == nil {
		t.Fatal("a request without an identity token succeeded")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Get took %v after the client's context ended", d)
	}
}

func TestCredentialRequestsNeverFollowRedirects(t *testing.T) {
	// A 307 keeps method and body: a followed token or exchange POST would hand the
	// client secret or identity token to the host the response names, and a
	// followed API GET would carry the bearer there.
	for _, cred := range []creds.Read{
		{Kind: creds.KindOAuth, ClientID: apitest.ClientID, ClientSecret: creds.NewSecret(apitest.ClientSecret)},
		{Kind: creds.KindFederated, ClientID: apitest.FedClientID, Provider: "oidc",
			IDToken: func(context.Context) (string, error) { return testIDToken(), nil }},
		{Kind: creds.KindAPIKey, APIKey: creds.NewSecret(apitest.AccessToken)},
	} {
		var hits atomic.Int32
		other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
		redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+"/collect", http.StatusTemporaryRedirect)
		}))
		c, err := api.New(context.Background(), apitest.Tailnet, cred, api.Options{BaseURL: redirecting.URL, Retries: -1})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Get(context.Background(), c.TailnetPath("/devices"), nil, &devicesResp{}); err == nil {
			t.Errorf("%s: a redirected request succeeded", cred.Kind)
		}
		if n := hits.Load(); n != 0 {
			t.Errorf("%s: the redirect was followed: %d request(s) reached the other host", cred.Kind, n)
		}
		redirecting.Close()
		other.Close()
	}
}

func TestGetRefusesPathsThatEscapeTheirEndpoint(t *testing.T) {
	f := apitest.New(t)
	c := f.Client(t)
	for _, p := range []string{api.Path("device/%s/routes", ".."), api.Path("device/%s", "."),
		"/api/v2/device//routes", api.Path("device/%s", "a/b"), api.Path("device/%s", `a\b`)} {
		if err := c.Get(context.Background(), p, nil, &devicesResp{}); code(err) != tkerr.ValidationFailed {
			t.Errorf("%s: err = %v, want validation_failed", p, err)
		}
	}
	if n := len(f.Requests()); n != 0 {
		t.Errorf("%d requests reached the API", n)
	}
}

// testIDToken returns a JWT-shaped identity token with a future expiry, assembled
// at run time so that no literal in the repository looks like a credential.
func testIDToken() string {
	enc := base64.RawURLEncoding.EncodeToString
	header := enc([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := enc([]byte(fmt.Sprintf(`{"sub":"test","exp":%d}`, time.Now().Add(time.Hour).Unix())))
	return header + "." + payload + "." + enc([]byte("test-signature"))
}

func federatedClient(t *testing.T, f *apitest.Fake, tok string) *api.Client {
	t.Helper()
	c, err := api.New(context.Background(), apitest.Tailnet,
		creds.Read{Kind: creds.KindFederated, ClientID: apitest.FedClientID, Provider: "oidc",
			IDToken: func(context.Context) (string, error) { return tok, nil }},
		api.Options{BaseURL: f.URL(), Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFederatedExchange(t *testing.T) {
	cases := []struct {
		name      string
		accept    bool
		failures  []int
		want      tkerr.Code // "" means success
		exchanges int
	}{
		{"accepted", true, nil, "", 1},
		{"identity token refused", false, nil, tkerr.CredentialUnavailable, 1},
		{"rate limited, then accepted", true, []int{429}, "", 2},
		{"server error, then accepted", true, []int{503}, "", 2},
		{"server error every time", true, []int{500, 500, 500, 500}, tkerr.UpstreamUnavailable, 4},
	}
	for _, tc := range cases {
		f := apitest.New(t)
		tok := testIDToken()
		if tc.accept {
			f.AcceptIDToken(tok)
		}
		f.FailExchanges(tc.failures...)
		f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/devices", 200, `{"devices":[]}`)
		c := federatedClient(t, f, tok)
		err := c.Get(context.Background(), c.TailnetPath("/devices"), nil, &devicesResp{})
		if code(err) != tc.want || (tc.want == "" && err != nil) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
		if n := f.ExchangeRequests(); n != tc.exchanges {
			t.Errorf("%s: %d exchanges, want %d", tc.name, n, tc.exchanges)
		}
		if err != nil && strings.Contains(err.Error(), "exchange failed") {
			t.Errorf("%s: the exchange response body reached the error text: %v", tc.name, err)
		}
	}
}

// An error keeps the whole message the server sent, as far as the error body is read: a cut
// made on the real text would let the length of what the message quotes decide how much of
// the rest is shown. What a result shows is cut after the message is masked.
func TestAnErrorKeepsAMessageLongerThan4KiBWhole(t *testing.T) {
	for _, size := range []int{4097, 20000, 60000} {
		msg := strings.Repeat("word ", (size+4)/5)
		f := apitest.New(t)
		f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/devices", 422, `{"message":"`+msg+`"}`)
		c := f.Client(t)
		var out devicesResp
		err := c.Get(context.Background(), c.TailnetPath("/devices"), nil, &out)
		e, ok := tkerr.As(err)
		if !ok || e.Code != tkerr.APIError || e.Status != 422 {
			t.Fatalf("size %d: err = %v, want api_error with status 422", size, err)
		}
		if e.Message != msg {
			t.Errorf("size %d: the message is %d bytes, want the %d the server sent", size, len(e.Message), len(msg))
		}
	}
}

// A body that fills what is read ends before its object does: the message is kept as far as it
// goes, a prefix of what the server sent, not dropped for the status text. A message that
// vanished when it was long would show how long what it quotes is. An escape the end cuts
// through is left out; a backslash in the message is kept.
func TestAnErrorBodyCutOffKeepsTheMessageAsFarAsItGoes(t *testing.T) {
	for _, unit := range []string{"word ", "ab\\u00e9\\\\", "\\u0041", "q\\\"x"} {
		raw := strings.Repeat(unit, 100000/len(unit))
		var want string
		if err := json.Unmarshal([]byte(`"`+raw+`"`), &want); err != nil {
			t.Fatal(err)
		}
		f := apitest.New(t)
		f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/devices", 422, `{"message":"`+raw+`","other":1}`)
		c := f.Client(t)
		var out devicesResp
		e, ok := tkerr.As(c.Get(context.Background(), c.TailnetPath("/devices"), nil, &out))
		if !ok || e.Code != tkerr.APIError {
			t.Fatalf("unit %q: err = %v, want api_error", unit, e)
		}
		if len(e.Message) < len(want)/4 || !strings.HasPrefix(want, e.Message) {
			t.Errorf("unit %q: the message is %d bytes and not a prefix of the %d the server sent", unit, len(e.Message), len(want))
		}
	}
	f := apitest.New(t)
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/devices", 422, strings.Repeat(" ", 70000)+`{"message":"late"}`)
	c := f.Client(t)
	var out devicesResp
	if e, ok := tkerr.As(c.Get(context.Background(), c.TailnetPath("/devices"), nil, &out)); !ok || e.Message != "Unprocessable Entity" {
		t.Errorf("a body with no message in what is read: %v, want the status text", e)
	}
}
