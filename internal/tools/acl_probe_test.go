package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

func probeRow(rows []PolicyProbe, name string) PolicyProbe {
	for _, p := range rows {
		if p.Name == name {
			return p
		}
	}
	return PolicyProbe{}
}

func probeEnv(t *testing.T, f *apitest.Fake) *registry.Env {
	t.Helper()
	return &registry.Env{API: f.Client(t)}
}

func serveDetails(f *apitest.Fake, policy string) {
	f.ServeDetails(apitest.DetailsOK(policy, `"e1"`, nil, nil))
}

// TestThePolicyRejectionProbeIsOKWhenAMalformedDocumentIsRejectedAndWarnsWhenItIsAccepted
// is the rejection probe. Acceptance is a warning: the server took the field, so the
// document no longer proves that a rejection is read as one, and the run is not a failure.
func TestThePolicyRejectionProbeIsOKWhenAMalformedDocumentIsRejectedAndWarnsWhenItIsAccepted(t *testing.T) {
	for _, c := range []struct {
		name  string
		shape apitest.Shape
		want  ProbeStatus
	}{
		{"rejected", apitest.PolicyUnknownField("nodeAttr"), ProbeOK},
		{"accepted", apitest.TestsPassEmptyObject(), ProbeWarn},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := apitest.New(t)
			serveDetails(f, "{}\n")
			f.ServeValidate(c.shape)
			got := probeRow(ProbePolicyMode(context.Background(), probeEnv(t, f)), probeRejection)
			if got.Status != c.want {
				t.Fatalf("status %s, detail %q; want %s", got.Status, got.Detail, c.want)
			}
			if c.want == ProbeOK && got.Detail == "" {
				t.Fatal("an ok row with no detail")
			}
		})
	}
}

func TestThePolicyRejectionProbeWarnsOnAnUnrecognisedAnswer(t *testing.T) {
	f := apitest.New(t)
	serveDetails(f, "{}\n")
	f.ServeValidate(apitest.ErrorsListAt200("tag not found"))
	got := probeRow(ProbePolicyMode(context.Background(), probeEnv(t, f)), probeRejection)
	if got.Status != ProbeWarn {
		t.Fatalf("status %s, detail %q; an unrecognised answer is a warning, never ok", got.Status, got.Detail)
	}
}

func TestTheDetailsProbeWarnsWithTheRemedyWhenTheReaderRefusesTheAnswer(t *testing.T) {
	f := apitest.New(t)
	f.Handle("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/acl", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("details") != "true" {
			t.Errorf("details=%q", r.URL.Query().Get("details"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		type extra struct {
			ACL      string   `json:"acl"`
			Warnings []string `json:"warnings"`
			Errors   []string `json:"errors"`
			Extra    int      `json:"extra"`
		}
		b, err := json.Marshal(extra{ACL: "e30K", Extra: 1})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(b)
	})
	f.ServeValidate(apitest.PolicyUnknownField("nodeAttr"))
	got := probeRow(ProbePolicyMode(context.Background(), probeEnv(t, f)), probeDetails)
	if got.Status != ProbeWarn {
		t.Fatalf("status %s; want a warning", got.Status)
	}
	for _, word := range []string{"acl_get", "acl_validate", "acl_diff"} {
		if !bytes.Contains([]byte(got.Detail), []byte(word)) {
			t.Errorf("detail %q does not name %s", got.Detail, word)
		}
	}
}

func TestTheInBandCanaryProbeIsOKWhenTheCanaryFailsOnceFailsWhenItPassesAndWarnsWhenItIsMissing(t *testing.T) {
	const denyAll = "{\"acls\":[]}\n"
	const allowAll = "{\"tagOwners\":{\"tag:ci\":[]}}\n"
	for _, c := range []struct {
		name    string
		policy  string
		reply   func(tag string) apitest.Shape
		want    ProbeStatus
		wantRow string
	}{
		{"deny-all, the acceptance fails", denyAll, func(tag string) apitest.Shape { return apitest.CanaryFailed(tag, true) }, ProbeOK, probeCanary},
		{"allow-all, the denial fails", allowAll, func(tag string) apitest.Shape { return apitest.CanaryFailed(tag, false) }, ProbeOK, probeCanary},
		{"a pass", denyAll, func(string) apitest.Shape { return apitest.TestsPassEmptyObject() }, ProbeFail, probeCanary},
		{"the canary is missing", denyAll, func(string) apitest.Shape {
			return apitest.TestsFailed(apitest.Entry{User: "tag:other", Errors: []string{`[acl test error]: address "192.0.2.1:1" (protocol "tcp"): want: Accept, got: Drop`}})
		}, ProbeWarn, probeCanary},
		{"the direction is the other default's", denyAll, func(tag string) apitest.Shape { return apitest.CanaryFailed(tag, false) }, ProbeWarn, probeCanary},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := apitest.New(t)
			serveDetails(f, c.policy)
			f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
				body := readBody(t, r)
				if bytes.Contains(body, []byte("tag:tailkeeper-canary-")) {
					c.reply(canaryTag(body)).Write(w)
					return
				}
				apitest.PolicyUnknownField("nodeAttr").Write(w)
			})
			got := probeRow(ProbePolicyMode(context.Background(), probeEnv(t, f)), c.wantRow)
			if got.Status != c.want {
				t.Fatalf("status %s, detail %q; want %s", got.Status, got.Detail, c.want)
			}
		})
	}
}

func TestTheSSHProbeIsOKWhenSSHTestsRunAndFailsWhenTheyAreSilentlyNotEvaluated(t *testing.T) {
	for _, c := range []struct {
		name  string
		shape apitest.Shape
		want  ProbeStatus
	}{
		{"sshTests run", apitest.SSHTestFailed("tag:tailkeeper-probe", "100.64.0.1", "192.0.2.1", "192.0.2.1", "canary"), ProbeOK},
		{"a pass, so sshTests were not evaluated", apitest.TestsPassEmptyObject(), ProbeFail},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := apitest.New(t)
			serveDetails(f, "{}\n")
			f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
				body := readBody(t, r)
				if bytes.Contains(body, []byte(`"sshTests"`)) {
					c.shape.Write(w)
					return
				}
				apitest.PolicyUnknownField("nodeAttr").Write(w)
			})
			got := probeRow(ProbePolicyMode(context.Background(), probeEnv(t, f)), probeSSH)
			if got.Status != c.want {
				t.Fatalf("status %s, detail %q; want %s", got.Status, got.Detail, c.want)
			}
		})
	}
}

func TestClassifyKindReadsUnknownAndUnresolvedAsWarnings(t *testing.T) {
	for _, c := range []struct {
		status   string
		verdicts []string
		want     ProbeStatus
	}{
		{"fail", []string{"denied"}, ProbeOK},
		{"fail", []string{"allowed"}, ProbeOK},
		{"fail", []string{verdictUnknown, "allowed"}, ProbeWarn},
		{"fail", []string{"allowed", verdictUnresolved}, ProbeWarn},
		{"fail", []string{verdictUnknown}, ProbeWarn},
		{"fail", []string{verdictUnresolved}, ProbeWarn},
		{"unknown", []string{verdictUnknown}, ProbeWarn},
		{"unresolved", nil, ProbeWarn},
		{"pass", nil, ProbeFail},
		{"fail", nil, ProbeWarn},
	} {
		st, detail, _ := func() (st ProbeStatus, detail, fix string) {
			// A guard that is gone must fail this test by its answer, not by a panic.
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("%s %v panicked: %v", c.status, c.verdicts, p)
					st, detail = ProbeOK, "panicked"
				}
			}()
			return ClassifyKind(c.status, c.verdicts)
		}()
		if st != c.want {
			t.Errorf("%s %v = %s, want %s", c.status, c.verdicts, st, c.want)
		}
		if c.want != ProbeOK && (st == ProbeOK || detail == "") {
			t.Errorf("%s %v was established: %s %q", c.status, c.verdicts, st, detail)
		}
	}
}

func readBody(t *testing.T, r *http.Request) []byte {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func canaryTag(body []byte) string {
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

func TestAProbeCarriesTheCodeOfItsFailedCallAndASkippedCanaryIsNotACall(t *testing.T) {
	f := apitest.New(t)
	f.JSON("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/acl", 500, `{"message":"down"}`)
	f.JSON("POST", apitest.ValidatePath, 500, `{"message":"down"}`)
	rows := ProbePolicyMode(context.Background(), probeEnv(t, f))
	for _, name := range []string{probeRejection, probeDetails, probeSSH} {
		got := probeRow(rows, name)
		if !got.Called || got.Code == "" || !strings.HasPrefix(got.Detail, string(got.Code)+": ") {
			t.Errorf("%s: called %v, code %q, detail %q", name, got.Called, got.Code, got.Detail)
		}
	}
	if got := probeRow(rows, probeCanary); got.Called || got.Code != "" {
		t.Errorf("the canary was not sent: called %v, code %q", got.Called, got.Code)
	}
}

func TestAProbeThatAnsweredCarriesNoCode(t *testing.T) {
	f := apitest.New(t)
	serveDetails(f, "{}\n")
	f.ServeValidate(apitest.PolicyUnknownField("nodeAttr"))
	got := probeRow(ProbePolicyMode(context.Background(), probeEnv(t, f)), probeRejection)
	if !got.Called || got.Code != "" || got.Status != ProbeOK {
		t.Fatalf("rejection probe = %+v", got)
	}
}

// A login longer than the cap, and another of a different length behind the same
// masked form, give one row: the masked text is cut, never the raw one, so no login
// loses its "@" to the cut and is shown.
func TestProbeErrMasksTheMessageAndTheHintBeforeItCutsThem(t *testing.T) {
	rows := map[int]PolicyProbe{}
	for _, n := range []int{1100, 1300} {
		login := strings.Repeat("a", n) + "@example.com"
		rows[n] = probeErr(probeDetails, tkerr.New(tkerr.APIError, "server failed for "+login+" today", "ask "+login+" to retry"))
	}
	for n, row := range rows {
		for field, text := range map[string]string{"detail": row.Detail, "fix": row.Fix} {
			if strings.Contains(text, strings.Repeat("a", 20)) || strings.Count(text, "@") != 1 || !strings.Contains(text, "a\u2026@example.com") {
				t.Errorf("n=%d %s (%d bytes) = %.60q, want the masked form once and no run of the local part", n, field, len(text), text)
			}
		}
	}
	if rows[1100] != rows[1300] {
		t.Fatalf("the row tells the length of the login:\n%+v\n%+v", rows[1100], rows[1300])
	}
}

func TestACanaryThatCannotBeBuiltIsNotACall(t *testing.T) {
	f := apitest.New(t)
	serveDetails(f, "this is not a policy {")
	f.ServeValidate(apitest.PolicyUnknownField("nodeAttr"))
	got := probeRow(ProbePolicyMode(context.Background(), probeEnv(t, f)), probeCanary)
	if got.Status != ProbeWarn || got.Called || got.Code != "" {
		t.Fatalf("canary = %+v, want a warning that made no call", got)
	}
	for _, req := range f.Requests() {
		if req.Method == "POST" && bytes.Contains(req.Body, []byte("tailkeeper-canary-")) {
			t.Errorf("a canary was sent: %s", req.Body)
		}
	}
}

func TestProbesOfARunWithNoCredentialMakeNoCall(t *testing.T) {
	rows := ProbePolicyMode(context.Background(), &registry.Env{APIErr: tkerr.New(tkerr.CredentialUnavailable, "no read credential is configured", "")})
	if len(rows) != 4 {
		t.Fatalf("%d rows, want 4", len(rows))
	}
	for _, row := range rows {
		if row.Called || row.Status != ProbeWarn {
			t.Errorf("%s = %+v, want a warning that made no call", row.Name, row)
		}
	}
}

// A send tailkeeper's own validation limit refused never reached Tailscale: the row says
// the limit refused it, and it is not a call, so it carries no code for an audit line.
func TestAProbeTheValidationLimitRefusedIsNotACall(t *testing.T) {
	f := apitest.New(t)
	serveDetails(f, "{\"acls\":[]}\n")
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
		body := readBody(t, r)
		switch {
		case bytes.Contains(body, []byte(`"sshTests"`)):
			apitest.SSHTestFailed("tag:tailkeeper-probe", "100.64.0.1", "192.0.2.1", "192.0.2.1", "canary").Write(w)
		case bytes.Contains(body, []byte("tag:tailkeeper-canary-")):
			apitest.CanaryFailed(canaryTag(body), true).Write(w)
		default:
			apitest.PolicyUnknownField("nodeAttr").Write(w)
		}
	})
	fixed := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	c, err := api.New(context.Background(), apitest.Tailnet,
		creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID, ClientSecret: creds.NewSecret(apitest.ClientSecret), Provider: "env"},
		api.Options{BaseURL: f.URL(), ValidatePerMinute: 1, Now: func() time.Time { return fixed },
			Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	rows := ProbePolicyMode(context.Background(), &registry.Env{API: c})
	// A bucket of one token a minute holds two: the rejection and the canary are sent.
	for _, name := range []string{probeRejection, probeDetails, probeCanary} {
		if got := probeRow(rows, name); !got.Called || got.Status != ProbeOK {
			t.Errorf("%s = %+v, want an ok call", name, got)
		}
	}
	got := probeRow(rows, probeSSH)
	if got.Status != ProbeWarn || !strings.HasPrefix(got.Detail, string(tkerr.ValidateRateLimited)+": ") {
		t.Fatalf("ssh row = %+v, want a warning that names the limit", got)
	}
	if got.Called || got.Code != "" {
		t.Errorf("a send the limit refused is recorded as a call: called %v, code %q", got.Called, got.Code)
	}
	posts := 0
	for _, req := range f.Requests() {
		if req.Method == "POST" && bytes.Contains(req.Body, []byte(`"sshTests"`)) {
			posts++
		}
	}
	if posts != 0 {
		t.Errorf("%d ssh documents were sent past the limit", posts)
	}
}

// The SSH known positive is exactly one failure, in the SSH form. Two failures in one
// entry, or one in each of two entries, are not what the document should produce, so the
// probe does not call them a sign that sshTests ran.
func TestTheSSHProbeNeedsExactlyOneFailureInTheSSHForm(t *testing.T) {
	const line = `[ssh test error]: src "tag:tailkeeper-probe" at "100.64.0.1", dst "192.0.2.1" at "192.0.2.1", ssh user "canary": want: "accept" got: "deny"`
	for _, c := range []struct {
		name  string
		shape apitest.Shape
		want  ProbeStatus
	}{
		{"one failure", apitest.TestsFailed(apitest.Entry{User: "tag:tailkeeper-probe", Errors: []string{line}}), ProbeOK},
		{"two failures in one entry", apitest.TestsFailed(apitest.Entry{User: "tag:tailkeeper-probe", Errors: []string{line, line}}), ProbeWarn},
		{"one failure in each of two entries", apitest.TestsFailed(
			apitest.Entry{User: "tag:tailkeeper-probe", Errors: []string{line}},
			apitest.Entry{User: "tag:tailkeeper-other", Errors: []string{line}}), ProbeWarn},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := apitest.New(t)
			serveDetails(f, "{}\n")
			f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
				if bytes.Contains(readBody(t, r), []byte(`"sshTests"`)) {
					c.shape.Write(w)
					return
				}
				apitest.PolicyUnknownField("nodeAttr").Write(w)
			})
			got := probeRow(ProbePolicyMode(context.Background(), probeEnv(t, f)), probeSSH)
			if got.Status != c.want {
				t.Fatalf("status %s, detail %q; want %s", got.Status, got.Detail, c.want)
			}
		})
	}
}
