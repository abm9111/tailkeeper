package api_test

import (
	"context"
	"net/http"
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

const devicesPath = "/api/v2/tailnet/" + apitest.Tailnet + "/devices"

// newClient is Fake.Client with the options a test chooses: Fake.Client sleeps zero time
// and keeps the default limits, so a test of the waits or of the limits builds its own.
func newClient(t *testing.T, f *apitest.Fake, opt api.Options) *api.Client {
	t.Helper()
	opt.BaseURL = f.URL()
	c, err := api.New(context.Background(), apitest.Tailnet,
		creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID, ClientSecret: creds.NewSecret(apitest.ClientSecret), Provider: "env"}, opt)
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	return c
}

// sleeps records every wait a client asks for and returns at once.
type sleeps struct {
	mu  sync.Mutex
	got []time.Duration
}

func (s *sleeps) sleep(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, d)
	return nil
}

func (s *sleeps) all() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.got...)
}

// answers429Once makes the devices route answer 429 with retryAfter the first time and
// an empty device list after that.
func answers429Once(f *apitest.Fake, retryAfter string) *atomic.Int32 {
	var calls atomic.Int32
	f.Handle("GET", devicesPath, func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", retryAfter)
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"devices":[]}`))
	})
	return &calls
}

// A Retry-After of billions of seconds overflowed time.Duration into a negative number,
// which backoff took for "no header" and replaced by the half-second default; one of more
// digits than any int holds was read as no header too. The server asked for a long wait;
// the cap of backoff is what it gets.
func TestARetryAfterOfBillionsOfSecondsWaitsTheCap(t *testing.T) {
	for _, header := range []string{"9300000000", "9223372036854775808", "99999999999999999999"} {
		f := apitest.New(t)
		answers429Once(f, header)
		s := &sleeps{}
		c := newClient(t, f, api.Options{Sleep: s.sleep})
		if err := c.Get(context.Background(), c.TailnetPath("/devices"), nil, &devicesResp{}); err != nil {
			t.Fatalf("%s: %v", header, err)
		}
		if got := s.all(); len(got) != 1 || got[0] != 30*time.Second {
			t.Errorf("Retry-After %s: waits = %v, want exactly one of 30s", header, got)
		}
	}
}

func TestAnHTTPDateRetryAfterIsHonouredUpToTheCapAndAPastOneIsIgnored(t *testing.T) {
	for _, c := range []struct {
		name   string
		ahead  time.Duration
		lo, hi time.Duration
	}{
		{"ten seconds ahead", 10 * time.Second, 5 * time.Second, 10 * time.Second},
		{"a day ahead", 24 * time.Hour, 30 * time.Second, 30 * time.Second},
		// A date in the past says nothing: the wait is the exponential default, 500 to 750 ms.
		{"an hour ago", -time.Hour, 500 * time.Millisecond, 750 * time.Millisecond},
	} {
		f := apitest.New(t)
		answers429Once(f, time.Now().Add(c.ahead).UTC().Format(http.TimeFormat))
		s := &sleeps{}
		cl := newClient(t, f, api.Options{Sleep: s.sleep})
		if err := cl.Get(context.Background(), cl.TailnetPath("/devices"), nil, &devicesResp{}); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := s.all()
		if len(got) != 1 || got[0] < c.lo || got[0] > c.hi {
			t.Errorf("%s: waits = %v, want one between %v and %v", c.name, got, c.lo, c.hi)
		}
	}
}

// Four 429s are the first try and the three retries: the call ends with the rate-limit
// code, the status and the last Retry-After the server sent, after three waits of it.
func TestTheFinalErrorAfterRetriesOnA429IsRateLimitedAndKeepsRetryAfter(t *testing.T) {
	f := apitest.New(t)
	f.Handle("GET", devicesPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"message":"slow down"}`))
	})
	s := &sleeps{}
	c := newClient(t, f, api.Options{Sleep: s.sleep})
	err := c.Get(context.Background(), c.TailnetPath("/devices"), nil, &devicesResp{})
	e, ok := tkerr.As(err)
	if !ok || e.Code != tkerr.APIRateLimited || e.Status != 429 || e.RetryAfter != 7*time.Second {
		t.Fatalf("err = %#v, want api_rate_limited, status 429, retry-after 7s", err)
	}
	if n := len(f.Requests()); n != 4 {
		t.Errorf("%d requests, want 4", n)
	}
	got := s.all()
	if len(got) != 3 {
		t.Fatalf("waits = %v, want 3", got)
	}
	for _, d := range got {
		if d != 7*time.Second {
			t.Errorf("waits = %v, want 7s each (the server's Retry-After)", got)
			break
		}
	}
}

// A caller that gives up while the client waits between two tries ends the call at
// once, with the one request made so far.
func TestCancellationDuringTheBackoffSleepEndsTheRetries(t *testing.T) {
	f := apitest.New(t)
	f.JSON("GET", devicesPath, 503, `{"message":"down"}`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	c := newClient(t, f, api.Options{Sleep: func(ctx context.Context, _ time.Duration) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}})
	go func() {
		select {
		case <-entered:
			cancel()
		case <-ctx.Done():
		}
	}()
	err := c.Get(ctx, c.TailnetPath("/devices"), nil, &devicesResp{})
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.APIError || e.Message != "request cancelled" {
		t.Fatalf("err = %v, want api_error \"request cancelled\"", err)
	}
	if n := len(f.Requests()); n != 1 {
		t.Errorf("%d requests, want 1", n)
	}
}

// An error body that is not the API's JSON never reaches the message: the status text
// does, and the status still decides the code.
func TestNonJSONErrorBodiesFallBackToTheStatusText(t *testing.T) {
	for _, c := range []struct {
		name   string
		status int
		body   string
		ctype  string
		want   tkerr.Code
	}{
		{"an HTML 502", 502, "<html><body>bad gateway</body></html>", "text/html", tkerr.UpstreamUnavailable},
		{"an empty 404", 404, "", "", tkerr.NotFound},
		{"a plain-text 403", 403, "denied by the proxy", "text/plain", tkerr.ScopeMissing},
	} {
		f := apitest.New(t)
		hdr := map[string]string{}
		if c.ctype != "" {
			hdr["Content-Type"] = c.ctype
		}
		f.Raw("GET", devicesPath, c.status, c.body, hdr)
		cl := newClient(t, f, api.Options{Retries: -1})
		err := cl.Get(context.Background(), cl.TailnetPath("/devices"), nil, &devicesResp{})
		e, ok := tkerr.As(err)
		if !ok || e.Code != c.want || e.Status != c.status || e.Message != http.StatusText(c.status) {
			t.Errorf("%s: err = %#v, want %s with the message %q", c.name, err, c.want, http.StatusText(c.status))
		}
	}
}

// The decoder stops at the end of the JSON value and may leave the rest of the body
// unread, so a body one byte over the limit passed when the value ended before the limit.
// The limit is above the decoder's first read and the padding follows the value, so the
// bytes past the value are only seen by the drain that follows the decode.
func TestGetRefusesABodyOneByteOverTheLimitAndAcceptsExactlyTheLimit(t *testing.T) {
	const limit = 4096
	value := `{"devices":[]}`
	for _, c := range []struct {
		name string
		size int
		ok   bool
	}{
		{"exactly the limit", limit, true},
		{"one byte over", limit + 1, false},
	} {
		f := apitest.New(t)
		f.JSON("GET", devicesPath, 200, value+strings.Repeat(" ", c.size-len(value)))
		cl := newClient(t, f, api.Options{MaxBody: limit})
		err := cl.Get(context.Background(), cl.TailnetPath("/devices"), nil, &devicesResp{})
		if c.ok && err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if !c.ok && (err == nil || !strings.Contains(err.Error(), "exceeded 4096 bytes")) {
			t.Errorf("%s: err = %v, want the 4096-byte limit", c.name, err)
		}
	}
}
