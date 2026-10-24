package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/audit"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/registry"
)

const kindPolicy = "{\"tagOwners\":{\"tag:ci\":[]},\"hosts\":{\"db\":\"192.0.2.10\"},\"acls\":[]}\n"

// serveKindWorld answers the policy reads and each validate from the document it was sent.
func serveKindWorld(t *testing.T, f *apitest.Fake, policy string, tests apitest.Shape) {
	t.Helper()
	f.Handle("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/acl", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("details") == "true" {
			apitest.DetailsOK(policy, `"e1"`, nil, nil).Write(w)
			return
		}
		apitest.PolicyText(policy, `"e1"`).Write(w)
	})
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read: %v", err)
			return
		}
		switch {
		case bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")):
			tests.Write(w)
		case bytes.Contains(body, []byte(`"nodeAttr"`)):
			apitest.PolicyUnknownField("nodeAttr").Write(w)
		case bytes.Contains(body, []byte(`"sshTests"`)):
			apitest.SSHTestFailed("tag:tailkeeper-probe", "100.64.0.1", "192.0.2.1", "192.0.2.1", "canary").Write(w)
		case bytes.Contains(body, []byte("tag:tailkeeper-canary-")):
			apitest.CanaryFailed(probeCanaryTag(body), true).Write(w)
		default:
			apitest.PolicyUnknownField("nodeAttr").Write(w)
		}
	})
}

func probeCanaryTag(body []byte) string {
	const p = "tag:tailkeeper-canary-"
	i := bytes.Index(body, []byte(p))
	if i < 0 {
		return ""
	}
	rest := body[i:]
	j := bytes.IndexByte(rest, '"')
	if j < 0 {
		return string(rest)
	}
	return string(rest[:j])
}

func kindLine(body []byte) apitest.Shape {
	var tests []struct {
		Src    string   `json:"src"`
		Accept []string `json:"accept"`
		Proto  string   `json:"proto"`
	}
	if json.Unmarshal(body, &tests) != nil || len(tests) != 1 || len(tests[0].Accept) != 1 {
		return apitest.TestsPass()
	}
	proto := tests[0].Proto
	if proto == "" {
		proto = "tcp"
	}
	line := fmt.Sprintf(`[acl test error]: address %q (protocol %q): want: Accept, got: Drop`, tests[0].Accept[0], proto)
	return apitest.TestsFailed(apitest.Entry{User: tests[0].Src, Errors: []string{line}})
}

func TestEveryKindProbeMapsToAllowedOrDenied(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	f.Handle("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/acl", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("details") == "true" {
			apitest.DetailsOK(kindPolicy, `"e1"`, nil, nil).Write(w)
			return
		}
		apitest.PolicyText(kindPolicy, `"e1"`).Write(w)
	})
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read: %v", err)
			return
		}
		if bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
			kindLine(body).Write(w)
			return
		}
		if bytes.Contains(body, []byte(`"sshTests"`)) {
			apitest.SSHTestFailed("tag:tailkeeper-probe", "100.64.0.1", "192.0.2.1", "192.0.2.1", "canary").Write(w)
			return
		}
		if bytes.Contains(body, []byte("tag:tailkeeper-canary-")) {
			apitest.CanaryFailed(probeCanaryTag(body), true).Write(w)
			return
		}
		apitest.PolicyUnknownField("nodeAttr").Write(w)
	})
	r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
	for _, name := range []string{"probe tag", "probe host alias", "probe IPv4 address", "probe IPv6 address", "probe ICMP, port 0"} {
		if got := status(r, name); len(got) != 1 || got[0] != OK {
			t.Errorf("%s = %v", name, got)
		}
	}
	for _, c := range r.Checks {
		if c.Name == "probe kinds refused" && (c.Status != Info || !strings.Contains(c.Detail, "svc") || !strings.Contains(c.Detail, "CIDR") || !strings.Contains(c.Detail, "autogroup:internet")) {
			t.Errorf("refused kinds = %+v", c)
		}
	}
}

func TestAKindWithNoSourceOrAliasIsNAAndNamed(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	serveKindWorld(t, f, "{\"acls\":[]}\n", apitest.TestsPass())
	r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
	for _, name := range []string{"probe tag", "probe host alias", "probe IPv4 address", "probe IPv6 address", "probe ICMP, port 0"} {
		if got := status(r, name); len(got) != 1 || got[0] != NA {
			t.Errorf("%s = %v, want n/a when the policy defines no tag", name, got)
		}
		if c := rowOf(t, r, name); !strings.Contains(c.Detail, "defines no tag") {
			t.Errorf("%s does not say why it was not probed: %q", name, c.Detail)
		}
	}
	f2, a2 := newApp(t, allReadScopes(t))
	f2.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	f2.Handle("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/acl", func(w http.ResponseWriter, r *http.Request) {
		const policy = "{\"tagOwners\":{\"tag:ci\":[]},\"acls\":[]}\n"
		if r.URL.Query().Get("details") == "true" {
			apitest.DetailsOK(policy, `"e1"`, nil, nil).Write(w)
			return
		}
		apitest.PolicyText(policy, `"e1"`).Write(w)
	})
	f2.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
			kindLine(body).Write(w)
			return
		}
		apitest.PolicyUnknownField("nodeAttr").Write(w)
	})
	r = Run(context.Background(), Input{App: a2, Now: now, Probe: true})
	if got := status(r, "probe host alias"); len(got) != 1 || got[0] != NA {
		t.Errorf("probe host alias = %v, want n/a", got)
	}
	if c := rowOf(t, r, "probe host alias"); !strings.Contains(c.Detail, "defines no host alias") {
		t.Errorf("probe host alias does not say why it was not probed: %q", c.Detail)
	}
	if got := status(r, "probe tag"); len(got) != 1 || got[0] != OK {
		t.Errorf("probe tag = %v, want ok from the tag the policy defines", got)
	}
}

func TestAKindProbeThatReadsUnknownOrUnresolvedIsAWarningNotOK(t *testing.T) {
	for _, c := range []struct {
		name  string
		shape apitest.Shape
		want  Status
	}{
		{"unresolved", apitest.TestUnevaluable("tag:ci"), Warn},
		// A pass-shaped body on a destination listed both ways has no line, so the
		// verdict is unknown. That is a warning. A status of pass is a failure, and
		// ClassifyKind is what says so.
		{"a pass body", apitest.TestsPass(), Warn},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, a := newApp(t, allReadScopes(t))
			f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
			serveKindWorld(t, f, kindPolicy, c.shape)
			r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
			if got := status(r, "probe tag"); len(got) != 1 || got[0] != c.want {
				t.Fatalf("probe tag = %v, want %s", got, c.want)
			}
			if c.want != OK {
				for _, ch := range r.Checks {
					if ch.Name == "probe tag" && ch.Status == OK {
						t.Fatalf("probe tag was ok: %+v", ch)
					}
				}
			}
		})
	}
}

func TestProbeErrorsAreMaskedWithoutAPseudonym(t *testing.T) {
	got := map[int]string{}
	for _, n := range []int{8, 40} {
		login := strings.Repeat("a", n) + "@example.com"
		msg, err := json.Marshal("server failed for " + login)
		if err != nil {
			t.Fatal(err)
		}
		body := `{"message":` + string(msg) + `}`
		f, a := newApp(t, allReadScopes(t))
		f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
		f.JSON("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/acl", 500, body)
		f.JSON("POST", apitest.ValidatePath, 500, body)
		r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
		var details []string
		for _, c := range r.Checks {
			if strings.Contains(c.Detail, login) || strings.Contains(c.Hint, login) || strings.Contains(c.Detail, "[p:") || strings.Contains(c.Hint, "[p:") {
				t.Fatalf("n=%d shows the login or a pseudonym: %+v", n, c)
			}
			if strings.Contains(c.Detail, "example.com") || strings.Contains(c.Hint, "example.com") {
				details = append(details, c.Name+" "+c.Detail+" "+c.Hint)
			}
		}
		got[n] = strings.Join(details, "\n")
	}
	if got[8] == "" || got[8] != got[40] {
		t.Fatalf("the masked lines differ or are missing:\n%s\n%s", got[8], got[40])
	}
}

func TestTheProbesDrawAtMostEightValidateTokensAndSendOnlyTheMeteredCall(t *testing.T) {
	fixed := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	posts := func(rate int) (n int, rep Report) {
		t.Helper()
		f, a := newApp(t, allReadScopes(t))
		f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
		f.Handle("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/acl", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("details") == "true" {
				apitest.DetailsOK(kindPolicy, `"e1"`, nil, nil).Write(w)
				return
			}
			apitest.PolicyText(kindPolicy, `"e1"`).Write(w)
		})
		f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
				kindLine(body).Write(w)
				return
			}
			if bytes.Contains(body, []byte(`"sshTests"`)) {
				apitest.SSHTestFailed("tag:tailkeeper-probe", "100.64.0.1", "192.0.2.1", "192.0.2.1", "canary").Write(w)
				return
			}
			if bytes.Contains(body, []byte("tag:tailkeeper-canary-")) {
				apitest.CanaryFailed(probeCanaryTag(body), true).Write(w)
				return
			}
			apitest.PolicyUnknownField("nodeAttr").Write(w)
		})
		c, err := api.New(context.Background(), apitest.Tailnet,
			creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID, ClientSecret: creds.NewSecret(apitest.ClientSecret), Provider: "env"},
			api.Options{BaseURL: f.URL(), ValidatePerMinute: rate, Now: func() time.Time { return fixed },
				Sleep: func(context.Context, time.Duration) error { return nil }})
		if err != nil {
			t.Fatal(err)
		}
		a.Env.API = c
		rep = Run(context.Background(), Input{App: a, Now: now, Probe: true})
		for _, req := range f.Requests() {
			if req.Method == "POST" && req.Path == apitest.ValidatePath {
				n++
			}
		}
		return n, rep
	}
	// A bucket of one token a minute holds two. An unmetered send would post every
	// document; the metered path stops after the two tokens.
	n, rep := posts(1)
	if n != 2 {
		t.Fatalf("%d validate posts at one token a minute, want 2", n)
	}
	if !reportHas(rep, "validate_rate_limited") {
		t.Fatal("the probes past the bucket were not validate_rate_limited")
	}
	// The new probes are three policy-mode sends and five kind sends. The tests-mode
	// canary is one more. Two runs in the same minute stay under the default of 30.
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	f.Handle("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/acl", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("details") == "true" {
			apitest.DetailsOK(kindPolicy, `"e1"`, nil, nil).Write(w)
			return
		}
		apitest.PolicyText(kindPolicy, `"e1"`).Write(w)
	})
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
			kindLine(body).Write(w)
			return
		}
		if bytes.Contains(body, []byte(`"sshTests"`)) {
			apitest.SSHTestFailed("tag:tailkeeper-probe", "100.64.0.1", "192.0.2.1", "192.0.2.1", "canary").Write(w)
			return
		}
		if bytes.Contains(body, []byte("tag:tailkeeper-canary-")) {
			apitest.CanaryFailed(probeCanaryTag(body), true).Write(w)
			return
		}
		apitest.PolicyUnknownField("nodeAttr").Write(w)
	})
	c, err := api.New(context.Background(), apitest.Tailnet,
		creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID, ClientSecret: creds.NewSecret(apitest.ClientSecret), Provider: "env"},
		api.Options{BaseURL: f.URL(), Now: func() time.Time { return fixed },
			Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	a.Env.API = c
	first := Run(context.Background(), Input{App: a, Now: now, Probe: true})
	mid := 0
	for _, req := range f.Requests() {
		if req.Method == "POST" && req.Path == apitest.ValidatePath {
			mid++
		}
	}
	second := Run(context.Background(), Input{App: a, Now: now, Probe: true})
	total := 0
	hujson, jsonPosts := 0, 0
	for _, req := range f.Requests() {
		if req.Method != "POST" || req.Path != apitest.ValidatePath {
			continue
		}
		total++
		if req.ContentType == "application/hujson" {
			hujson++
		}
		if strings.HasPrefix(req.ContentType, "application/json") {
			jsonPosts++
		}
	}
	if mid != 9 || total != 18 {
		t.Fatalf("posts: first %d, both %d; want 9 and 18", mid, total)
	}
	if hujson != 6 || jsonPosts != 12 {
		t.Fatalf("hujson %d, json %d; want 6 and 12 over two runs", hujson, jsonPosts)
	}
	// Three policy-mode sends and five kind sends, twice. The sixth json send of a
	// run is the tests-mode canary that was already there.
	if hujson/2+(jsonPosts/2-1) != 8 {
		t.Fatalf("new sends per run = %d, want 8", hujson/2+(jsonPosts/2-1))
	}
	if reportHas(first, "validate_rate_limited") || reportHas(second, "validate_rate_limited") {
		t.Fatal("two probes in the same minute did not fit under 30")
	}
}

func reportHas(r Report, s string) bool {
	for _, c := range r.Checks {
		if strings.Contains(c.Detail, s) || strings.Contains(c.Hint, s) || strings.Contains(string(c.Status), s) {
			return true
		}
	}
	return false
}

func TestEveryDirectCallOfDoctorIsRecordedInTheAuditLog(t *testing.T) {
	const marker = "marker-7f3c"
	policy := "// " + marker + "\n" + kindPolicy
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	f.Handle("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/acl", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("details") == "true" {
			apitest.DetailsOK(policy, `"e1"`, nil, nil).Write(w)
			return
		}
		apitest.PolicyText(policy, `"e1"`).Write(w)
	})
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
			kindLine(body).Write(w)
			return
		}
		if bytes.Contains(body, []byte(`"sshTests"`)) {
			apitest.SSHTestFailed("tag:tailkeeper-probe", "100.64.0.1", "192.0.2.1", "192.0.2.1", "canary").Write(w)
			return
		}
		if bytes.Contains(body, []byte("tag:tailkeeper-canary-")) {
			apitest.CanaryFailed(probeCanaryTag(body), true).Write(w)
			return
		}
		apitest.PolicyUnknownField("nodeAttr").Write(w)
	})
	_ = Run(context.Background(), Input{App: a, Now: now, Probe: true})
	raw, err := os.ReadFile(a.Audit.Path())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(marker)) || bytes.Contains(raw, []byte("tag:tailkeeper-probe")) || bytes.Contains(raw, []byte("nodeAttr")) {
		t.Fatal("the audit log holds text the probes sent")
	}
	lines, err := audit.Tail(a.Audit.Path(), 80)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"v": true, "seq": true, "ts": true, "prev": true, "event": true, "hash": true,
		"tool": true, "tier": true, "requester": true, "ms": true, "status": true, "code": true, "bytes": true,
		"context": true, "tailnet": true}
	want := []string{"doctor.probe policy rejection", "doctor.probe details keys", "doctor.probe invariants canary", "doctor.probe ssh tests", "doctor.probe kind source"}
	seen := map[string]bool{}
	for _, line := range lines {
		tool, _ := line["tool"].(string)
		for k := range line {
			if !allowed[k] {
				t.Errorf("audit line %q has %s", tool, k)
			}
		}
		for _, name := range want {
			if tool == name {
				seen[name] = true
			}
		}
	}
	for _, name := range want {
		if !seen[name] {
			t.Errorf("no audit line for %s", name)
		}
	}
}

func TestAMissingOptionalScopeNamesTheFeatureOfTheRightTool(t *testing.T) {
	// users:read is optional on the policy tools and required on users_list, so a token
	// without it leaves the policy tools able to run and names the feature that is off.
	scope := strings.ReplaceAll(allReadScopes(t), "users:read", "")
	f, a := newApp(t, scope)
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
	if got := status(r, "probe policy rejection"); len(got) != 1 {
		t.Fatalf("probe policy rejection = %v", got)
	}
	if r.Failed != 0 {
		t.Fatalf("failed %d: %+v", r.Failed, r.Checks)
	}
	var detail string
	for _, c := range r.Checks {
		if c.Status == Fail {
			t.Errorf("check failed: %+v", c)
		}
		if c.Name == "optional scopes" {
			if c.Status != Info {
				t.Fatalf("optional scopes = %+v, want info", c)
			}
			detail = c.Detail
		}
	}
	if detail == "" {
		t.Fatal("no optional scopes row")
	}
	for _, tool := range a.Registry.All() {
		if tool.Meta.Stage == registry.StageAlpha {
			continue
		}
		for _, o := range tool.Meta.OptionalScopes {
			if o.Scope != "users:read" {
				continue
			}
			feature := tool.Meta.Name + " (" + o.Reason + ")"
			if strings.Count(detail, feature) != 1 {
				t.Errorf("%s appears %d times in %q", feature, strings.Count(detail, feature), detail)
			}
		}
	}
	for _, feature := range []string{
		"acl_test (resolve a pseudonym in src or a destination)",
		"acl_validate (resolve a pseudonym in a proposal or patch)",
		"acl_diff (resolve a pseudonym in a text or patch)",
	} {
		if strings.Count(detail, feature) != 1 {
			t.Errorf("missing %s in %q", feature, detail)
		}
	}
}

// auditStatuses returns the status of each doctor probe line in the audit log, by tool.
func auditStatuses(t *testing.T, path string) map[string]string {
	t.Helper()
	lines, err := audit.Tail(path, 200)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, line := range lines {
		tool, _ := line["tool"].(string)
		if !strings.HasPrefix(tool, "doctor.probe ") {
			continue
		}
		st, _ := line["status"].(string)
		if _, dup := got[tool]; dup {
			t.Errorf("two audit lines for %s", tool)
		}
		got[tool] = st
	}
	return got
}

// rowCode is the error code a probe row's detail starts with.
func rowCode(t *testing.T, r Report, name string) string {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name {
			code, _, ok := strings.Cut(c.Detail, ": ")
			if !ok {
				t.Fatalf("%s detail has no code: %q", name, c.Detail)
			}
			return code
		}
	}
	t.Fatalf("no %s row", name)
	return ""
}

func TestAProbeThatFailedIsRecordedWithItsErrorsCodeAndOneNeverSentIsNotRecorded(t *testing.T) {
	t.Run("the details read and every send fail", func(t *testing.T) {
		f, a := newApp(t, allReadScopes(t))
		f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
		f.JSON("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/acl", 500, `{"message":"down"}`)
		f.JSON("POST", apitest.ValidatePath, 500, `{"message":"down"}`)
		r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
		got := auditStatuses(t, a.Audit.Path())
		for _, name := range []string{"probe policy rejection", "probe details keys", "probe ssh tests"} {
			code := rowCode(t, r, name)
			if got["doctor."+name] != code || code == "ok" {
				t.Errorf("%s: audit status %q, row code %q", name, got["doctor."+name], code)
			}
		}
		if st, ok := got["doctor.probe invariants canary"]; ok {
			t.Errorf("the canary was never sent but the audit log has a line for it: status %q", st)
		}
		if c := rowOf(t, r, "probe invariants canary"); !strings.Contains(c.Detail, "was not sent") {
			t.Errorf("canary row = %+v, want it to say nothing was sent", c)
		}
		for _, req := range f.Requests() {
			if req.Method == "POST" && strings.Contains(string(req.Body), "tailkeeper-canary-") {
				t.Errorf("a canary was sent although the live policy could not be read: %s", req.Body)
			}
		}
	})
	t.Run("the details read answers and every send fails", func(t *testing.T) {
		f, a := newApp(t, allReadScopes(t))
		f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
		f.Handle("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/acl", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("details") == "true" {
				apitest.DetailsOK(kindPolicy, `"e1"`, nil, nil).Write(w)
				return
			}
			apitest.PolicyText(kindPolicy, `"e1"`).Write(w)
		})
		f.JSON("POST", apitest.ValidatePath, 500, `{"message":"down"}`)
		r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
		got := auditStatuses(t, a.Audit.Path())
		if got["doctor.probe details keys"] != "ok" {
			t.Errorf("details read answered, audit status %q", got["doctor.probe details keys"])
		}
		for _, name := range []string{"probe policy rejection", "probe invariants canary", "probe ssh tests"} {
			code := rowCode(t, r, name)
			if got["doctor."+name] != code || code == "ok" {
				t.Errorf("%s: audit status %q, row code %q", name, got["doctor."+name], code)
			}
		}
	})
}

// kindWorld serves a live policy and answers every test with a failure the way the
// kind probes read it, keeping the body of each test it was sent.
func kindWorld(t *testing.T, f *apitest.Fake, policy string) *[]string {
	t.Helper()
	var mu sync.Mutex
	var tests []string
	f.Handle("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/acl", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("details") == "true" {
			apitest.DetailsOK(policy, `"e1"`, nil, nil).Write(w)
			return
		}
		apitest.PolicyText(policy, `"e1"`).Write(w)
	})
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
			mu.Lock()
			tests = append(tests, string(body))
			mu.Unlock()
			kindLine(body).Write(w)
			return
		}
		if bytes.Contains(body, []byte(`"sshTests"`)) {
			apitest.SSHTestFailed("tag:tailkeeper-probe", "100.64.0.1", "192.0.2.1", "192.0.2.1", "canary").Write(w)
			return
		}
		if bytes.Contains(body, []byte("tag:tailkeeper-canary-")) {
			apitest.CanaryFailed(probeCanaryTag(body), true).Write(w)
			return
		}
		apitest.PolicyUnknownField("nodeAttr").Write(w)
	})
	return &tests
}

func TestAServiceTheLivePolicyNamesIsProbedAndOneItDoesNotNameIsNot(t *testing.T) {
	const withSvc = "{\"tagOwners\":{\"tag:ci\":[]},\"grants\":[{\"src\":[\"tag:ci\"],\"dst\":[\"svc:web\"],\"ip\":[\"tcp:443\"]}]}\n"
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	tests := kindWorld(t, f, withSvc)
	r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
	if got := status(r, "probe svc"); len(got) != 1 || got[0] != OK {
		t.Fatalf("probe svc = %v: %+v", got, r.Checks)
	}
	found := false
	for _, body := range *tests {
		found = found || strings.Contains(body, `"accept":["svc:web:22"]`)
	}
	if !found {
		t.Errorf("no test was sent to svc:web:22: %v", *tests)
	}
	if c := rowOf(t, r, "probe kinds refused"); strings.HasPrefix(c.Detail, "svc") {
		t.Errorf("svc is probed but the refused row says it is not: %q", c.Detail)
	}

	f2, a2 := newApp(t, allReadScopes(t))
	f2.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	kindWorld(t, f2, kindPolicy)
	r2 := Run(context.Background(), Input{App: a2, Now: now, Probe: true})
	if got := status(r2, "probe svc"); len(got) != 0 {
		t.Errorf("probe svc = %v with no service in the policy", got)
	}
	if c := rowOf(t, r2, "probe kinds refused"); !strings.HasPrefix(c.Detail, "svc") {
		t.Errorf("refused row = %q, want svc named", c.Detail)
	}
}

func TestTheICMPKindIsSentWithItsProtocolAndPortZero(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	tests := kindWorld(t, f, kindPolicy)
	Run(context.Background(), Input{App: a, Now: now, Probe: true})
	found := false
	for _, body := range *tests {
		if strings.Contains(body, `"accept":["192.0.2.10:0"]`) {
			found = strings.Contains(body, `"proto":"icmp"`)
		}
	}
	if !found {
		t.Errorf("no ICMP test with its protocol was sent: %v", *tests)
	}
}

func TestAKindProbeNeverSendsANameTheSummaryCutOrTheMaskerWouldRewrite(t *testing.T) {
	long := "tag:" + strings.Repeat("a", 150)
	policy := `{"tagOwners":{"` + long + `":[],"tag:ci":[]},"hosts":{"bob@example.com":"192.0.2.9","db":"192.0.2.10"},"acls":[]}` + "\n"
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	tests := kindWorld(t, f, policy)
	r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
	if len(*tests) == 0 {
		t.Fatal("no test was sent")
	}
	for _, body := range *tests {
		if strings.Contains(body, strings.Repeat("a", 20)) || strings.Contains(body, "@") {
			t.Errorf("a name that is cut or masked was sent: %.120s", body)
		}
		if !strings.Contains(body, `"src":"tag:ci"`) {
			t.Errorf("the source is not the tag with a plain name: %s", body)
		}
	}
	found := false
	for _, body := range *tests {
		found = found || strings.Contains(body, `"accept":["db:22"]`)
	}
	if !found {
		t.Errorf("the host alias with a plain name was not probed: %v", *tests)
	}
	if got := status(r, "probe host alias"); len(got) != 1 || got[0] != OK {
		t.Errorf("probe host alias = %v", got)
	}
}

func TestAFailedDetailsReadForTheKindProbesIsRecordedWithItsCode(t *testing.T) {
	// Many reads of the policy are details reads. A first run counts them; each later run
	// fails one, and the run that fails the read the kind probes make for a service
	// records it with its code.
	run := func(failAt int) (map[string]string, int) {
		f, a := newApp(t, allReadScopes(t))
		f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
		reads := 0
		f.Handle("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/acl", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("details") == "true" {
				reads++
				if failAt > 0 && reads >= failAt {
					w.WriteHeader(500)
					return
				}
				apitest.DetailsOK(kindPolicy, `"e1"`, nil, nil).Write(w)
				return
			}
			apitest.PolicyText(kindPolicy, `"e1"`).Write(w)
		})
		f.ServeValidate(apitest.PolicyUnknownField("nodeAttr"))
		Run(context.Background(), Input{App: a, Now: now, Probe: true})
		return auditStatuses(t, a.Audit.Path()), reads
	}
	healthy, reads := run(0)
	if healthy["doctor.probe kind source"] != "ok" {
		t.Fatalf("a healthy run records the kind source as %q", healthy["doctor.probe kind source"])
	}
	for n := 1; n <= reads; n++ {
		if st := func() string { got, _ := run(n); return got["doctor.probe kind source"] }(); st != "" && st != "ok" {
			return
		}
	}
	t.Errorf("no failed details read was recorded for the kind source in %d runs", reads)
}

func TestAProbeTheValidationLimitRefusedIsInTheReportButNotInTheAuditLog(t *testing.T) {
	fixed := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	serveKindWorld(t, f, kindPolicy, apitest.TestsPass())
	c, err := api.New(context.Background(), apitest.Tailnet,
		creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID, ClientSecret: creds.NewSecret(apitest.ClientSecret), Provider: "env"},
		api.Options{BaseURL: f.URL(), ValidatePerMinute: 1, Now: func() time.Time { return fixed },
			Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	a.Env.API = c
	r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
	got := auditStatuses(t, a.Audit.Path())
	// A bucket of one token a minute holds two: the tests-mode canary and the rejection
	// document take them, and the in-band canary and the SSH document are refused before
	// they are sent.
	for _, name := range []string{"probe invariants canary", "probe ssh tests"} {
		if code := rowCode(t, r, name); code != "validate_rate_limited" {
			t.Fatalf("%s row code = %q, want validate_rate_limited: %+v", name, code, r.Checks)
		}
		if st, ok := got["doctor."+name]; ok {
			t.Errorf("%s was never sent but the audit log has a line for it: status %q", name, st)
		}
	}
	for _, name := range []string{"probe policy rejection", "probe details keys"} {
		if got["doctor."+name] != "ok" {
			t.Errorf("%s was sent and answered, audit status %q", name, got["doctor."+name])
		}
	}
}

// A kind probe runs as an acl_test call, so one the validation limit refuses is recorded as an
// acl_test line with the code validate_rate_limited, where a policy probe the limit refused
// writes nothing: nothing was sent for either, and the audit log shows which kind it was.
func TestAKindProbeTheValidationLimitRefusedIsRecordedAsAnACLTestCall(t *testing.T) {
	fixed := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	serveKindWorld(t, f, kindPolicy, apitest.TestsPass())
	c, err := api.New(context.Background(), apitest.Tailnet,
		creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID, ClientSecret: creds.NewSecret(apitest.ClientSecret), Provider: "env"},
		api.Options{BaseURL: f.URL(), ValidatePerMinute: 1, Now: func() time.Time { return fixed },
			Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	a.Env.API = c
	r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
	lines, err := audit.Tail(a.Audit.Path(), 200)
	if err != nil {
		t.Fatal(err)
	}
	refused := 0
	for _, line := range lines {
		if line["tool"] == "acl_test" && line["status"] == "error" && line["code"] == "validate_rate_limited" {
			refused++
		}
	}
	kinds := 0
	for _, name := range []string{"probe tag", "probe host alias", "probe IPv4 address", "probe IPv6 address", "probe ICMP, port 0"} {
		if rowCode(t, r, name) == "validate_rate_limited" {
			kinds++
		}
	}
	if kinds != 5 || refused != kinds {
		t.Errorf("%d kind probes the limit refused, and %d acl_test lines with validate_rate_limited in the audit log: want 5 and 5", kinds, refused)
	}
}

func TestAServiceNameFollowsTheRuleOfATagAndOfAHostAlias(t *testing.T) {
	policyWith := func(names ...string) string {
		dst := make([]string, len(names))
		for i, n := range names {
			dst[i] = `"svc:` + n + `"`
		}
		return `{"tagOwners":{"tag:ci":[]},"grants":[{"src":["tag:ci"],"dst":[` + strings.Join(dst, ",") + `],"ip":["tcp:443"]}]}` + "\n"
	}
	hundred := strings.Repeat("a", 100)
	cases := []struct {
		name     string
		policy   string
		wantSent string // the accept the svc test must carry, or "" when none may be sent
	}{
		{"a name of 100 characters is sent whole", policyWith(hundred), "svc:" + hundred + ":22"},
		{"a name of 101 characters is not sent", policyWith(hundred + "a"), ""},
		{"a name of 1000 characters is not sent", policyWith(strings.Repeat("a", 1000)), ""},
		{"a name with a dot is not sent", policyWith("web.example"), ""},
		{"a name with an at sign is not sent", policyWith("bob@example.com"), ""},
		{"a name that starts with a hyphen is not sent", policyWith("-web"), ""},
		{"a name that starts with a dot is not sent", policyWith(".web"), ""},
		{"a name with an underscore is not sent", policyWith("web_1"), ""},
		{"the first plain name is sent when an earlier one is not plain", policyWith(strings.Repeat("a", 150), "web"), "svc:web:22"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, a := newApp(t, allReadScopes(t))
			f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
			tests := kindWorld(t, f, c.policy)
			r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
			sent := ""
			for _, body := range *tests {
				if strings.Contains(body, `"accept":["svc:`) {
					sent = body
				}
			}
			if c.wantSent == "" {
				if sent != "" {
					t.Errorf("a service test was sent: %.200s", sent)
				}
				rows := 0
				for _, ch := range r.Checks {
					if ch.Name != "probe svc" {
						continue
					}
					rows++
					if ch.Status != NA || !strings.Contains(ch.Detail, "name") || !strings.Contains(ch.Detail, "not probed") {
						t.Errorf("probe svc row = %+v, want n/a saying the name could not be sent", ch)
					}
					if strings.Contains(ch.Detail, "@") || strings.Contains(ch.Detail, strings.Repeat("a", 20)) {
						t.Errorf("probe svc row repeats the name: %q", ch.Detail)
					}
				}
				if rows != 1 {
					t.Errorf("%d probe svc rows, want one n/a row that says why", rows)
				}
				return
			}
			if !strings.Contains(sent, `"accept":["`+c.wantSent+`"]`) {
				t.Errorf("no test was sent to %s: %v", c.wantSent, *tests)
			}
			if got := status(r, "probe svc"); len(got) != 1 || got[0] != OK {
				t.Errorf("probe svc = %v", got)
			}
		})
	}
}
