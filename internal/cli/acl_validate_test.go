package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// validateJSON decodes the JSON of a validate command.
func validateJSON(t *testing.T, stdout string) tools.ACLValidateOutput {
	t.Helper()
	var out tools.ACLValidateOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("stdout is not acl_validate's JSON: %q (%v)", stdout, err)
	}
	return out
}

const cliPolicy = "// a proposal\n{\n\t\"tagOwners\": {\"tag:ci\": [\"autogroup:admin\"]},\n\t\"acls\": [{\"action\": \"accept\", \"src\": [\"tag:ci\"], \"dst\": [\"tag:ci:22\"]}],\n}\n"

// --offline checks the file here: no credential is needed, none is looked for, and the
// result says that nothing was sent.
func TestACLValidateOfflineNeedsNoCredential(t *testing.T) {
	h, builds := execHarness(t)
	path := writeFile(t, "policy.hujson", cliPolicy)
	if code := h.run("--json", "acl", "validate", "--offline", "--from", path); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	if h.reexecProvider != nil || *builds != 1 {
		t.Errorf("the wrapper started (%v) or Build ran %d times; want no wrapper and one Build", h.reexecProvider != nil, *builds)
	}
	if out := validateJSON(t, h.out.String()); out.Status != "pass" || out.ServerChecked || out.TestsAfter != 0 {
		t.Errorf("result = %+v", out)
	}
	// The text layout opens with a verdict that says the file was not sent.
	h, _ = execHarness(t)
	if code := h.run("acl", "validate", "--offline", "--from", path); code != 0 || !strings.HasPrefix(h.out.String(), "VALID, CHECKED HERE ONLY, NOT SENT TO TAILSCALE") {
		t.Errorf("exit %d, output %q", code, h.out)
	}
	// --quiet prints nothing when the command succeeds.
	h, _ = execHarness(t)
	if code := h.run("acl", "validate", "--offline", "--quiet", "--from", path); code != 0 || h.out.Len() != 0 {
		t.Errorf("--quiet: exit %d, output %q", code, h.out)
	}
}

// --quiet hides the result on exit 0 and still writes the audit warning when the
// line cannot be recorded. The warning is not an exit of its own.
func TestQuietOnExitZeroStillWarnsWhenTheReadWasNotAudited(t *testing.T) {
	h, _ := execHarness(t)
	h.app.Audit, h.app.AuditErr = nil, tkerr.New(tkerr.AuditUnavailable, "cannot open the audit log", "")
	path := writeFile(t, "policy.hujson", cliPolicy)
	if code := h.run("acl", "validate", "--offline", "--quiet", "--from", path); code != 0 || h.out.Len() != 0 {
		t.Fatalf("--quiet exit %d, stdout %q", code, h.out)
	}
	if !strings.Contains(h.err.String(), "this read was not audited: cannot open the audit log") {
		t.Fatalf("stderr = %q", h.err)
	}
}

// An invalid file is a typed result with exit 2, found without a credential, with its place
// in the file the command line was given.
func TestACLValidateOfflineReportsAnInvalidFile(t *testing.T) {
	h, _ := execHarness(t)
	path := writeFile(t, "policy.hujson", "{\r\n\"acls\": [\r\n{,}\r\n]\r\n}")
	if code := h.run("acl", "validate", "--offline", "--from", path); code != 2 {
		t.Fatalf("exit %d, want 2: %s", code, h.err)
	}
	lines := strings.Split(h.out.String(), "\n")
	if lines[0] != "INVALID · 1 problem found before anything was sent to Tailscale" || !strings.Contains(h.out.String(), "policy.hujson:3:2: error: invalid character") ||
		!strings.Contains(h.out.String(), "Lines are counted by line feed and columns in bytes") {
		t.Errorf("output:\n%s", h.out)
	}
	bom := writeFile(t, "bom.hujson", "\xef\xbb\xbf{}")
	h, _ = execHarness(t)
	if code := h.run("--json", "acl", "validate", "--offline", "--from", bom); code != 2 || validateJSON(t, h.out.String()).Errors[0].Kind != "encoding" {
		t.Errorf("a byte order mark: exit %d, %s", code, h.out)
	}
}

// An empty file, or empty standard input, is no text. The tool reads an empty field as "validate
// the live policy" (--from, and --patch once it exists) or "no invariants" (--invariants), so a CI step whose render
// produced nothing would go green. Every file flag refuses it with exit 2 and sends no request,
// online as offline.
func TestACLValidateRefusesAnEmptyTextOnEveryFileFlag(t *testing.T) {
	empty := writeFile(t, "empty.hujson", "")
	for name, args := range map[string][]string{
		"--from":                   {"--from", empty},
		"--invariants":             {"--invariants", empty},
		"--from on standard input": {"--from", "-"},
		"--offline --from":         {"--offline", "--from", empty},
	} {
		f := apitest.New(t)
		h := newHarness(t, f)
		h.r.Stdin = strings.NewReader("")
		if code := h.run(append([]string{"acl", "validate"}, args...)...); code != 2 || !strings.Contains(h.err.String(), " is empty; ") {
			t.Errorf("%s: exit %d, stderr %q; want 2 and a refusal that says the text is empty", name, code, h.err)
		}
		if h.out.Len() != 0 || len(f.Requests()) != 0 {
			t.Errorf("%s: stdout %q, %d requests; want none", name, h.out, len(f.Requests()))
		}
	}
}

// Without --offline a missing credential is credential_unavailable and exit 5.
func TestACLValidateWithoutACredentialExits5(t *testing.T) {
	h := newHarness(t, nil)
	path := writeFile(t, "policy.hujson", cliPolicy)
	if code := h.run("acl", "validate", "--from", path); code != 5 || !strings.HasPrefix(h.err.String(), "tailkeeper: credential_unavailable: ") {
		t.Errorf("exit %d, stderr %q; want 5 and credential_unavailable", code, h.err)
	}
	if h.out.Len() != 0 {
		t.Errorf("stdout: %q", h.out)
	}
}

// The command line's file is the operator's own: a login in it goes to Tailscale, as it is.
func TestACLValidateSendsAnOperatorFileAsItIs(t *testing.T) {
	f := apitest.New(t)
	live := "{}\n"
	f.Handle("GET", "/api/v2/tailnet/T1234CNTRL/acl", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("details") == "true" {
			apitest.DetailsOK(live, api.ETagOf([]byte(live)), nil, nil).Write(w)
			return
		}
		apitest.PolicyText(live, api.ETagOf([]byte(live))).Write(w)
	})
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/settings", 200, `{"aclsExternallyManagedOn":false}`)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	h := newHarness(t, f)
	text := "{\"groups\": {\"group:eng\": [\"amy@example.com\"]}}\n"
	path := writeFile(t, "policy.hujson", text)
	if code := h.run("--json", "acl", "validate", "--from", path); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	var post []byte
	for _, r := range f.Requests() {
		if r.Method == "POST" {
			post = r.Body
		}
	}
	if string(post) != text {
		t.Errorf("the POST carried %q, want the file's bytes", post)
	}
	if out := validateJSON(t, h.out.String()); out.Status != "pass" || !out.ServerChecked || out.ExternallyManaged != "false" {
		t.Errorf("result = %+v", out)
	}
	if strings.Contains(h.out.String(), "amy@") {
		t.Errorf("the login is in the result: %s", h.out)
	}
}

// limitedHarness is a harness whose client takes perMinute validation tokens a minute on a
// clock that does not move: the bucket holds two tokens at a rate of one, and stays empty
// once they are used.
func limitedHarness(t *testing.T, f *apitest.Fake, perMinute int) *harness {
	t.Helper()
	h := newHarness(t, f)
	fixed := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	c, err := api.New(context.Background(), apitest.Tailnet,
		creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID, ClientSecret: creds.NewSecret(apitest.ClientSecret), Provider: "env"},
		api.Options{BaseURL: f.URL(), ValidatePerMinute: perMinute, Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatal(err)
	}
	h.app.Env.API = c
	return h
}

// An empty bucket is validate_rate_limited on the command line: exit 1, and the text a
// person reads names the seconds, as does the JSON a script reads.
func TestTheBucketIsExhaustedOnTheCommandLine(t *testing.T) {
	f := apitest.New(t)
	serveLiveFor(f, "{}\n")
	f.ServeValidate(apitest.TestsPassEmptyObject())
	h := limitedHarness(t, f, 1)
	for i := 1; i <= 2; i++ {
		if code := h.run("--json", "acl", "validate"); code != 0 {
			t.Fatalf("call %d: exit %d: %s", i, code, h.err)
		}
	}
	h.err.Reset()
	if code := h.run("acl", "validate"); code != 1 || !strings.HasPrefix(h.err.String(), "tailkeeper: validate_rate_limited: ") || !strings.Contains(h.err.String(), "try again in 60 s") {
		t.Errorf("text: exit %d, stderr %q", code, h.err)
	}
	h.out.Reset()
	h.err.Reset()
	if code := h.run("--json", "acl", "validate"); code != 1 {
		t.Fatalf("json: exit %d", code)
	}
	var doc struct {
		Error struct {
			Code              string `json:"code"`
			Message           string `json:"message"`
			RetryAfterSeconds int    `json:"retryAfterSeconds"`
		} `json:"error"`
	}
	if err := json.Unmarshal(h.out.Bytes(), &doc); err != nil || doc.Error.Code != "validate_rate_limited" || doc.Error.RetryAfterSeconds != 60 || !strings.Contains(doc.Error.Message, "try again in 60 s") {
		t.Errorf("json error = %+v (%v) from %s", doc, err, h.out)
	}
}

// serveLiveFor serves the live policy, both reads, and the settings.
func serveLiveFor(f *apitest.Fake, text string) {
	f.Handle("GET", "/api/v2/tailnet/T1234CNTRL/acl", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("details") == "true" {
			apitest.DetailsOK(text, api.ETagOf([]byte(text)), nil, nil).Write(w)
			return
		}
		apitest.PolicyText(text, api.ETagOf([]byte(text))).Write(w)
	})
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/settings", 200, `{"aclsExternallyManagedOn":false}`)
}

// invariantsFile is an invariants file whose first test fails on the fake below.
const invariantsFile = "// the owner's invariants\n{\n\t\"tests\": [\n\t\t{\"src\": \"tag:web\", \"deny\": [\"tag:ci:22\"]},\n\t],\n}\n"

// serveInvariantsFor answers the first validation with a pass and the second, the one with a
// canary, with the canary's failure and the failure of the invariants' one test.
func serveInvariantsFor(f *apitest.Fake) {
	canaryRE := regexp.MustCompile(`tag:tailkeeper-canary-[0-9a-f]{8}`)
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		tag := canaryRE.FindString(string(body))
		if tag == "" {
			apitest.TestsPassEmptyObject().Write(w)
			return
		}
		apitest.TestsFailed(
			apitest.Entry{User: tag, Errors: []string{`[acl test error]: address "192.0.2.1:1" (protocol "tcp"): want: Drop, got: Accept`}},
			apitest.Entry{User: "tag:web", Errors: []string{`[acl test error]: address "tag:ci:22": want: Drop, got: Accept`}},
		).Write(w)
	})
}

// A failing invariant exits 9 and is placed at its line in the file the command line named.
func TestACLValidateChecksTheInvariantsOfTheCommandLine(t *testing.T) {
	f := apitest.New(t)
	serveLiveFor(f, "{}\n")
	serveInvariantsFor(f)
	h := newHarness(t, f)
	path := writeFile(t, "invariants.hujson", invariantsFile)
	if code := h.run("acl", "validate", "--invariants", path); code != 9 {
		t.Fatalf("exit %d, want 9: %s %s", code, h.out, h.err)
	}
	lines := strings.Split(h.out.String(), "\n")
	if lines[0] != "FAILED · 1 failed assertion · invariants: 1 test ran" || !strings.Contains(h.out.String(), "invariants.hujson:4:3: error: /tests/0: [acl test error]: address \"tag:ci:22\"") {
		t.Errorf("output:\n%s", h.out)
	}
	// --no-invariants: the same live policy, nothing else to check.
	h = newHarness(t, f)
	if code := h.run("--json", "acl", "validate", "--no-invariants"); code != 0 || validateJSON(t, h.out.String()).InvariantsApplied != 0 {
		t.Errorf("--no-invariants: exit %d, %s", code, h.out)
	}
}
