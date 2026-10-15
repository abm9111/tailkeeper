package apitest

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// recordingTB keeps what the fake reports instead of failing the test.
type recordingTB struct {
	testing.TB
	errs []string
}

func (r *recordingTB) Errorf(format string, args ...any) { r.errs = append(r.errs, format) }
func (r *recordingTB) Helper()                           {}

// The fake's spy fails any test whose code sends a request other than GET and
// the validate POST, so a read client that lost its guard cannot stay green.
func TestSpyReportsEveryOtherRequest(t *testing.T) {
	for _, c := range []struct {
		method, path string
		spied        bool
	}{
		{"GET", "/api/v2/tailnet/" + Tailnet + "/devices", false},
		{"POST", ValidatePath, false},
		{"POST", "/api/v2/tailnet/" + Tailnet + "/acl", true},
		{"DELETE", "/api/v2/device/n1", true},
		{"PUT", ValidatePath, true},
		{"PATCH", "/api/v2/tailnet/" + Tailnet + "/settings", true},
		{"POST", "/api/v2/tailnet/OTHER/acl/validate", true},
	} {
		rec := &recordingTB{TB: t}
		f := New(rec)
		req, err := http.NewRequest(c.method, f.URL()+c.path, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if spied := len(rec.errs) > 0; spied != c.spied {
			t.Errorf("%s %s: spy reported %v, want %v", c.method, c.path, spied, c.spied)
		}
	}
}

// A fallback answers the paths with no route of their own, after recording them
// and checking the bearer token like any other request; a route still wins.
func TestFallbackAnswersUnroutedPathsOnly(t *testing.T) {
	f := New(t)
	f.JSON("GET", "/api/v2/routed", 200, `{"from":"route"}`)
	f.Fallback(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"from":"fallback ` + r.URL.Path + `"}`))
	})
	c := f.Client(t)
	for path, want := range map[string]string{"/api/v2/routed": `"route"`, "/api/v2/other": `"fallback /api/v2/other"`} {
		var out struct{ From string }
		if err := c.Get(context.Background(), path, nil, &out); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if got := strconv.Quote(out.From); got != want {
			t.Errorf("%s = %s, want %s", path, got, want)
		}
	}
	if n := len(f.Requests()); n != 2 {
		t.Errorf("%d requests recorded, want 2", n)
	}
}

// The fallback sits behind the bearer check: a wrong token on a path only the
// fallback would answer gets 401, and the fallback handler never runs.
func TestFallbackRejectsWrongBearerToken(t *testing.T) {
	f := New(t)
	reached := false
	f.Fallback(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		_, _ = w.Write([]byte(`{"from":"fallback"}`))
	})
	req, err := http.NewRequest("GET", f.URL()+"/api/v2/unrouted", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer not-the-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong token on a fallback path: status %d, want 401", resp.StatusCode)
	}
	if reached {
		t.Error("the fallback handler ran for a request with a wrong bearer token")
	}
}
