package apitest

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// A validate POST's content type selects the mode on the server, so the fake fails any
// test whose request names one mode and carries the other's body.
func TestValidateMismatch(t *testing.T) {
	for _, c := range []struct {
		name, contentType, body string
		bad                     bool
	}{
		{"tests mode: an array", "application/json", `[{"src":"tag:p","accept":["tag:p:22"]}]`, false},
		{"tests mode: an empty array, spaced", "application/json", " \n[ ]\n", false},
		{"tests mode with a charset", "application/json; charset=utf-8", `[]`, false},
		{"policy mode: an object", "application/hujson", `{"acls": []}`, false},
		{"policy mode: comments, CRLF, trailing commas", "application/hujson", "// c\r\n/* d */ {\r\n\t\"acls\": [],\r\n}\r\n", false},
		{"policy mode: only a comment in the object", "application/hujson", `{/* c */}`, false},

		{"an object sent as JSON", "application/json", `{"acls":[]}`, true},
		{"a broken array sent as JSON", "application/json", `[{"src":`, true},
		{"an empty body sent as JSON", "application/json", ``, true},
		{"an array sent as HuJSON", "application/hujson", `[{"src":"tag:p"}]`, true},
		{"an array after a comment sent as HuJSON", "application/hujson", "// c\n[]", true},
		{"an empty body sent as HuJSON", "application/hujson", ``, true},
		{"null sent as HuJSON", "application/hujson", `null`, true},
		{"a byte order mark sent as HuJSON", "application/hujson", "\xef\xbb\xbf{\"acls\":[]}", true},
		{"only comments sent as HuJSON", "application/hujson", "// c\n/* d */", true},
		{"an unterminated comment sent as HuJSON", "application/hujson", "/* c {}", true},
		{"no content type", "", `{"acls":[]}`, true},
		{"plain text", "text/plain", `{"acls":[]}`, true},
		{"a content type that does not parse", "application/", `{"acls":[]}`, true},
	} {
		if got := validateMismatch(c.contentType, []byte(c.body)); (got != "") != c.bad {
			t.Errorf("%s: validateMismatch = %q, want a mismatch: %v", c.name, got, c.bad)
		}
	}
}

// The spy runs on the live path of the fake: a mismatched POST fails the test that
// sent it, and PermitProbeRequests (the probe harness only) lets it through.
func TestSpyReportsAMismatchedValidatePost(t *testing.T) {
	for _, c := range []struct {
		name, contentType, body string
		permit, spied           bool
	}{
		{"agreeing tests mode", "application/json", `[]`, false, false},
		{"agreeing policy mode", "application/hujson", `{}`, false, false},
		{"an array sent as HuJSON", "application/hujson", `[]`, false, true},
		{"an object sent as JSON", "application/json", `{}`, false, true},
		{"an array sent as HuJSON, permitted", "application/hujson", `[]`, true, false},
		{"an empty body, permitted", "application/hujson", ``, true, false},
	} {
		rec := &recordingTB{TB: t}
		f := New(rec)
		if c.permit {
			f.PermitProbeRequests()
		}
		req, err := http.NewRequest("POST", f.URL()+ValidatePath, strings.NewReader(c.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", c.contentType)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if spied := len(rec.errs) > 0; spied != c.spied {
			t.Errorf("%s: spy reported %v (%q), want %v", c.name, spied, rec.errs, c.spied)
		}
	}
}

// A body over the fake's cap fails the test rather than being cut: a cut body would
// make a comparison of exact bytes pass or fail for the wrong reason.
func TestSpyReportsABodyOverTheCap(t *testing.T) {
	rec := &recordingTB{TB: t}
	f := New(rec)
	req, err := http.NewRequest("POST", f.URL()+ValidatePath, strings.NewReader("["+strings.Repeat("0,", maxRequestBody/2)+"0]"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(rec.errs) == 0 {
		t.Error("a request body over the cap was accepted")
	}
}

// A handler can read the request body: the fake gives it the bytes it recorded.
func TestHandlerReadsTheRecordedBody(t *testing.T) {
	f := New(t)
	var seen string
	f.Handle("POST", ValidatePath, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = string(b)
		w.WriteHeader(204)
	})
	req, err := http.NewRequest("POST", f.URL()+ValidatePath, strings.NewReader(`{"acls":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/hujson")
	req.Header.Set("Authorization", "Bearer "+AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if seen != `{"acls":[]}` || string(f.Requests()[0].Body) != seen {
		t.Errorf("handler saw %q, recorded %q", seen, f.Requests()[0].Body)
	}
}
