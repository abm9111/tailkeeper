package probe

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/tailscale/hujson"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
)

var canaryRE = regexp.MustCompile(`tag:tailkeeper-canary-[0-9a-f]{8}`)

// world is a model of the API as the probe table (docs/design.md §22) expects it to behave, built from
// the ledger's shapes. A probe run against it must find every expectation true. The
// model is not the API: it is the table's guess made executable, so that a probe whose
// computation is wrong (a check that cannot come out true, a path that never matches)
// shows here, before the owner's run.
type world struct {
	t         *testing.T
	f         *apitest.Fake
	etag      string
	text      string           // the live policy's text; liveText unless a test serves another
	auditLogs []map[string]any // the audit log's entries
	auditCode int              // the audit log's status; 0 is 200
	warnings  []string         // the warnings the live policy's details carry
	// detailsFail, when set, is the status and body a details read answers with instead of the policy.
	detailsFail *struct {
		code int
		body string
	}
	// override, when set, answers a policy-mode request instead of the model; it returns false to fall through.
	override func(body string) (apitest.Shape, bool)
}

func newWorld(t *testing.T) *world {
	t.Helper()
	f := apitest.New(t)
	f.PermitProbeRequests() // the probes send arrays as HuJSON, an empty body and a BOM, on purpose
	w := &world{t: t, f: f, etag: etagOfLive(t), text: liveText, warnings: []string{liveWarning}}
	f.Handle("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/acl", w.policy)
	f.Handle("POST", apitest.ValidatePath, w.validate)
	f.Handle("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/logging/configuration", w.audit)
	return w
}

// serveText makes text the live policy, with the ETag the model derives from it.
func (w *world) serveText(text string) {
	w.t.Helper()
	f, err := hujson.Format([]byte(text))
	if err != nil {
		w.t.Fatal(err)
	}
	sum := sha256.Sum256(f)
	w.text = text
	w.etag = `"` + hex.EncodeToString(sum[:]) + `"`
	w.warnings = nil
}

func (w *world) policy(rw http.ResponseWriter, r *http.Request) {
	switch {
	case r.Header.Get("If-None-Match") == w.etag:
		// The table's guess for A-8, which the live run refuted: the real endpoint answers 200 with the whole policy.
		rw.Header().Set("ETag", w.etag)
		rw.WriteHeader(http.StatusNotModified)
	case r.URL.Query().Get("details") == "true" && w.detailsFail != nil:
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(w.detailsFail.code)
		_, _ = rw.Write([]byte(w.detailsFail.body))
	case r.URL.Query().Get("details") == "true":
		apitest.DetailsOK(w.text, w.etag, w.warnings, nil).Write(rw)
	default:
		apitest.PolicyText(w.text, w.etag).Write(rw)
	}
}

func (w *world) audit(rw http.ResponseWriter, r *http.Request) {
	if w.auditCode != 0 {
		rw.WriteHeader(w.auditCode)
		_, _ = rw.Write([]byte(`{}`))
		return
	}
	if r.URL.Query().Get("event") != "TAILNET.UPDATE.ACL" || r.URL.Query().Get("start") == "" || r.URL.Query().Get("end") == "" {
		w.t.Errorf("the audit request lacks its window or its event: %s", r.URL.RawQuery)
	}
	rw.Header().Set("Content-Type", "application/json")
	b, _ := json.Marshal(map[string]any{"logs": w.auditLogs})
	_, _ = rw.Write(b)
}

func (w *world) validate(rw http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if w.override != nil {
		if s, ok := w.override(string(body)); ok {
			s.Write(rw)
			return
		}
	}
	var s apitest.Shape
	if r.Header.Get("Content-Type") == "application/json" {
		s = testsMode(body)
	} else {
		s = policyMode(string(body))
	}
	s.Write(rw)
}

// testsMode answers an array of tests against the model's live policy, which allows everything.
func testsMode(body []byte) apitest.Shape {
	var tests []struct {
		Src    string   `json:"src"`
		Proto  string   `json:"proto"`
		Accept []string `json:"accept"`
		Deny   []string `json:"deny"`
	}
	if json.Unmarshal(body, &tests) != nil {
		return apitest.Rejected400("cannot read the tests")
	}
	var entries []apitest.Entry
	for _, tc := range tests {
		e := apitest.Entry{User: tc.Src}
		if tc.Src != "tag:live" && tc.Src != "lee@example.com" && tc.Src != "group:eng" {
			e.Errors = []string{"user or host is invalid: tag not found"}
			entries = append(entries, e)
			continue
		}
		for _, dst := range tc.Deny {
			if strings.Contains(dst, "/") || strings.HasPrefix(dst, "autogroup:") {
				e.Errors = append(e.Errors, "user or host is invalid: tag not found")
				continue
			}
			line := `address "` + dst + `"`
			if tc.Proto != "" {
				line += ` (protocol "` + tc.Proto + `")`
			}
			e.Errors = append(e.Errors, line+": want: Drop, got: Accept")
		}
		if len(e.Errors) > 0 {
			entries = append(entries, e)
		}
	}
	if len(entries) == 0 {
		return apitest.TestsPass()
	}
	return apitest.TestsFailed(entries...)
}

// guessedRejection is the table's guess for a well-formed document the server cannot
// accept: HTTP 400 and a bare message. The run of 20 Oct 2026 refuted it (A-3, A-5: the
// live API answers 200, which the ledger's PolicySyntaxError, PolicyUnknownField and
// PolicyTagNotFound now say). The model keeps the guess because each probe's expectation
// is that guess, and TestEveryProbeFindsTheSpecsWorld checks the harness against it;
// TestA3AndA5ReportDiffersAgainstTheLiveForm checks the harness against the live form.
func guessedRejection(message string) apitest.Shape { return apitest.Rejected400(message) }

// policyMode answers a policy object.
func policyMode(b string) apitest.Shape {
	trimmed := strings.TrimSpace(b)
	switch {
	case strings.HasPrefix(b, "\xef\xbb\xbf"):
		return apitest.Rejected400("invalid character looking for beginning of value")
	case trimmed == "" || trimmed == "null":
		return apitest.Rejected400("unexpected end of JSON input")
	case strings.HasPrefix(trimmed, "["):
		return testsMode([]byte(trimmed))
	case strings.Contains(b, "invalidtext"):
		return guessedRejection("line 3, column 13: invalid literal: invalidtext")
	case strings.Contains(b, "unknownsection"):
		return guessedRejection("json: unknown field " + strconv.Quote("unknownsection"))
	case strings.Contains(b, `"nodeAttr"`):
		return guessedRejection("json: unknown field " + strconv.Quote("nodeAttr"))
	case strings.Contains(b, "autogroup:self"):
		return apitest.PolicyServerError500()
	case strings.Contains(b, `"app":{}`):
		return apitest.Rejected400("ip and app can not both be empty")
	case b == liveText:
		return apitest.TestsWarned(apitest.Entry{User: "group:eng", Warnings: []string{liveWarning}})
	case strings.Contains(b, "tailkeeper-canary"):
		tag := canaryRE.FindString(b)
		if strings.Contains(b, `"acls":[],`) {
			return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{`address "192.0.2.1:1": want: Accept, got: Drop`}})
		}
		return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{`address "192.0.2.1:1": want: Drop, got: Accept`}})
	case strings.Contains(b, `"sshTests":[{`):
		if strings.Contains(b, "nobody") {
			return apitest.SSHTestFailed("tag:p", "100.64.0.1", "tag:p", "100.64.0.2", "nobody")
		}
		return apitest.TestsPass()
	case strings.Contains(b, `"probe-a:22"`):
		if strings.Contains(b, `"acls":[],`) {
			return apitest.TestsPass()
		}
		return apitest.TestsFailed(apitest.Entry{User: "tag:p", Errors: []string{`address "probe-a:22": want: Drop, got: Accept`}})
	case strings.Contains(b, `"src":["tag:p"],"dst":["tag:p:22"]}]}`) && !strings.Contains(b, "tagOwners"):
		return guessedRejection("tag not found: " + strconv.Quote("tag:p"))
	case strings.Contains(b, `"acls":[],"tests"`):
		return apitest.TestsPass()
	case strings.Contains(b, `"acls":[{"action":"accept","src":["tag:p"]}],"tests"`):
		// A repeated acls array replaces the earlier one whole, as the probe table reads it: the one
		// rule left has no dst, so it allows nothing: the accept of tag:q:22 fails and the deny of tag:q:80 holds. The
		// model cannot parse a policy; it recognises A-4's document by the text of its second block.
		return apitest.TestsFailed(apitest.Entry{User: "tag:p", Errors: []string{`address "tag:q:22": want: Accept, got: Drop`}})
	}
	return apitest.TestsPass()
}
