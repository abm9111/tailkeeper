package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

func TestOutIsRequiredNeverStandardOutputAndTheFlagsNeedPolicy(t *testing.T) {
	cases := [][]string{
		{"doctor", "--out", "invariants.hujson"},
		{"doctor", "--tag", "tag:web"},
		{"doctor", "--admin-group", "group:admins"},
		{"doctor", "--with-logins"},
		{"doctor", "--policy"},
		{"doctor", "--policy", "--out", "-"},
		{"doctor", "--policy", "--probe", "--out", "invariants.hujson"},
	}
	for _, args := range cases {
		h, builds := execHarness(t)
		if exit := h.run(args...); exit != 2 {
			t.Errorf("%v: exit %d, want 2 (%s)", args, exit, h.err)
		}
		if *builds != 0 || h.reexecProvider != nil {
			t.Errorf("%v: configuration loaded %d times, wrapper %v", args, *builds, h.reexecProvider != nil)
		}
		if h.out.Len() != 0 {
			t.Errorf("%v: wrote to stdout: %s", args, h.out)
		}
		if !strings.Contains(h.err.String(), "usage") {
			t.Errorf("%v: stderr = %q", args, h.err)
		}
	}
}

func TestLoginsAreWrittenOnlyWithWithLoginsAndNeverPrinted(t *testing.T) {
	const short, long = "o@example.com", "administrator.with.a.longer.login@example.com"
	one := func(login string, with bool) (printed, file string) {
		t.Helper()
		f := apitest.New(t)
		f.Scope = "devices:core:read users:read oauth_keys:read"
		f.JSON("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/keys/"+apitest.ClientID, 200, `{"id":"test-client-id","keyType":"client","tags":["tag:web"]}`)
		f.Handle("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/users", func(w http.ResponseWriter, r *http.Request) {
			body := `{"users":[]}`
			if r.URL.Query().Get("role") == "owner" {
				body = `{"users":[{"loginName":"` + login + `","role":"owner"}]}`
			}
			if r.URL.Query().Get("role") == "admin" {
				body = `{"users":[{"loginName":"` + login + `","role":"admin"}]}`
			}
			_, _ = w.Write([]byte(body))
		})
		h := newHarness(t, f)
		h.app.KeyID = apitest.ClientID
		h.app.CredKind = creds.KindOAuth
		dir := t.TempDir()
		path := filepath.Join(dir, "invariants.hujson")
		args := []string{"--json", "doctor", "--policy", "--out", path, "--tag", "tag:ci", "--admin-group", "group:admins"}
		if with {
			args = append(args, "--with-logins")
		}
		if code := h.run(args...); code != 0 {
			t.Fatalf("%s with=%v json: exit %d: %s", login, with, code, h.err)
		}
		if strings.Contains(h.out.String(), login) || strings.Contains(h.err.String(), login) || strings.Contains(h.out.String(), "@") {
			t.Fatalf("json printed a login:\nstdout %s\nstderr %s", h.out, h.err)
		}
		printed = withoutPath(t, h.out.String(), path)
		h.out.Reset()
		h.err.Reset()
		textPath := filepath.Join(dir, "text.hujson")
		textArgs := []string{"doctor", "--policy", "--out", textPath, "--tag", "tag:ci", "--admin-group", "group:admins"}
		if with {
			textArgs = append(textArgs, "--with-logins")
		}
		if code := h.run(textArgs...); code != 0 {
			t.Fatalf("%s with=%v text: exit %d: %s", login, with, code, h.err)
		}
		if strings.Contains(h.out.String(), login) || strings.Contains(h.err.String(), login) || strings.Contains(h.out.String(), "@") {
			t.Fatalf("text printed a login:\nstdout %s\nstderr %s", h.out, h.err)
		}
		printed += withoutPath(t, h.out.String(), textPath)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return printed, string(b)
	}
	shortPrinted, shortFile := one(short, true)
	longPrinted, longFile := one(long, true)
	if shortPrinted != longPrinted {
		t.Fatalf("stdout depends on the login:\n%s\n%s", shortPrinted, longPrinted)
	}
	if !strings.Contains(shortFile, short) || !strings.Contains(longFile, long) {
		t.Fatalf("file missing the login:\n%s\n%s", shortFile, longFile)
	}
	_, plain := one(short, false)
	if strings.Contains(plain, short) || strings.Contains(plain, "@") {
		t.Fatalf("login written without --with-logins:\n%s", plain)
	}
}

// policyHarness is a harness on a fake API whose configuration loads are counted.
func policyHarness(t *testing.T, f *apitest.Fake) (*harness, *int) {
	t.Helper()
	h := newHarness(t, f)
	h.app.KeyID = apitest.ClientID
	h.app.CredKind = creds.KindOAuth
	builds := 0
	h.r.Build = func(context.Context, string) (*app.App, error) { builds++; return h.app, nil }
	return h, &builds
}

func TestAStarterTheCommandCannotWriteIsRefusedBeforeTheCredentialIsAsked(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing.hujson")
	if err := os.WriteFile(existing, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(dir, "fresh.hujson")
	for name, args := range map[string][]string{
		"an existing file":      {"doctor", "--policy", "--out", existing, "--tag", "tag:web", "--admin-group", "group:admins"},
		"a directory":           {"doctor", "--policy", "--out", dir, "--tag", "tag:web", "--admin-group", "group:admins"},
		"a bad tag":             {"doctor", "--policy", "--out", fresh, "--tag", "web", "--admin-group", "group:admins"},
		"a bad group":           {"doctor", "--policy", "--out", fresh, "--tag", "tag:web", "--admin-group", "admins"},
		"no source of a test":   {"doctor", "--policy", "--out", fresh, "--tag", "tag:web"},
		"no source, only a tag": {"--json", "doctor", "--policy", "--out", fresh, "--tag", "tag:web"},
	} {
		t.Run(name, func(t *testing.T) {
			f := apitest.New(t)
			h, builds := policyHarness(t, f)
			if exit := h.run(args...); exit != 2 {
				t.Errorf("exit %d, want 2 (%s)", exit, h.err)
			}
			if *builds != 0 || h.reexecProvider != nil {
				t.Errorf("configuration loaded %d times, wrapper %v", *builds, h.reexecProvider != nil)
			}
			if n := len(f.Requests()) + f.TokenRequests(); n != 0 {
				t.Errorf("%d token or API requests were made", n)
			}
			if _, err := os.Stat(fresh); !os.IsNotExist(err) {
				t.Errorf("a file was written: %v", err)
			}
			if b, err := os.ReadFile(existing); err != nil || string(b) != "{}\n" {
				t.Errorf("the existing file was changed: %q %v", b, err)
			}
			if !strings.Contains(h.err.String()+h.out.String(), "usage") {
				t.Errorf("stderr = %q, stdout = %q", h.err, h.out)
			}
		})
	}
}

func TestAStarterWithNoTagIsRefusedWithAHintAndNoFile(t *testing.T) {
	f := apitest.New(t)
	f.Scope = "devices:core:read oauth_keys:read"
	f.JSON("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/keys/"+apitest.ClientID, 200, `{"id":"test-client-id","keyType":"client"}`)
	h, _ := policyHarness(t, f)
	path := filepath.Join(t.TempDir(), "invariants.hujson")
	exit := h.run("doctor", "--policy", "--out", path, "--admin-group", "group:admins")
	if exit == 0 {
		t.Fatal("a starter with no test exited 0")
	}
	if !strings.Contains(h.err.String(), "--tag") {
		t.Errorf("stderr does not tell the owner to pass --tag: %q", h.err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("a file was written: %v", err)
	}
}

func TestAUsersReadErrorShowsNoLoginOnStandardErrorWhateverTheStatus(t *testing.T) {
	masked := "a…@example.com"
	for _, status := range []int{500, 404, 400, 409} {
		for _, asJSON := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d json=%v", status, asJSON), func(t *testing.T) {
				got := map[int]string{}
				for _, n := range []int{1100, 1300} {
					login := strings.Repeat("a", n) + "@example.com"
					f := apitest.New(t)
					f.Scope = "devices:core:read users:read oauth_keys:read"
					f.JSON("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/keys/"+apitest.ClientID, 200, `{"id":"test-client-id","keyType":"client"}`)
					f.JSON("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/users", status, `{"message":"user `+login+` cannot be listed"}`)
					h, _ := policyHarness(t, f)
					args := []string{"doctor", "--policy", "--out", filepath.Join(t.TempDir(), "i.hujson"), "--tag", "tag:ci", "--admin-group", "group:a", "--with-logins"}
					if asJSON {
						args = append([]string{"--json"}, args...)
					}
					if exit := h.run(args...); exit == 0 {
						t.Fatal("exit 0")
					}
					out := h.out.String() + h.err.String()
					if strings.Contains(out, strings.Repeat("a", 20)) || strings.Contains(out, "[p:") || strings.Count(out, "@") != 1 || !strings.Contains(out, masked) {
						t.Fatalf("n=%d: output (%d bytes) = %.200q, want the masked login once", n, len(out), out)
					}
					got[n] = out
				}
				if got[1100] != got[1300] {
					t.Fatalf("the output tells the length of the login:\n%.300s\n%.300s", got[1100], got[1300])
				}
			})
		}
	}
}

// probeHelp is what `doctor --probe` says it sends. The test below runs the probe and counts
// what it sent, so the words and the requests cannot drift apart.
const probeHelp = "also call read endpoints whose scope or availability is unverified, and send to POST .../acl/validate, which changes nothing: " +
	"the canary test, two synthetic documents, the live policy with an in-band canary, and one test for each destination kind the live policy can name"

func TestTheProbeHelpSaysWhatTheProbeSends(t *testing.T) {
	h := newHarness(t, nil)
	if code := h.run("doctor", "-h"); code != 0 {
		t.Fatalf("doctor -h: exit %d, stderr %q", code, h.err)
	}
	help := strings.Join(strings.Fields(h.err.String()), " ")
	if !strings.Contains(help, "-probe "+probeHelp) {
		t.Errorf("the --probe help is not the pinned sentence:\n%s", help)
	}
	if strings.Contains(help, "one synthetic document") {
		t.Errorf("the --probe help still says one synthetic document:\n%s", help)
	}

	const policy = "{\"tagOwners\":{\"tag:ci\":[]},\"hosts\":{\"db\":\"192.0.2.10\"},\"acls\":[]}\n"
	f := apitest.New(t)
	f.Scope = "devices:core:read oauth_keys:read policy_file:read"
	f.JSON("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/keys/"+apitest.ClientID, 200, `{"id":"test-client-id","keyType":"client"}`)
	f.Handle("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/acl", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("details") == "true" {
			apitest.DetailsOK(policy, `"e1"`, nil, nil).Write(w)
			return
		}
		apitest.PolicyText(policy, `"e1"`).Write(w)
	})
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")):
			apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{`[acl test error]: address "192.0.2.10:22" (protocol "tcp"): want: Accept, got: Drop`}}).Write(w)
		case bytes.Contains(body, []byte(`"sshTests"`)):
			apitest.SSHTestFailed("tag:tailkeeper-probe", "100.64.0.1", "192.0.2.1", "192.0.2.1", "canary").Write(w)
		case bytes.Contains(body, []byte("tag:tailkeeper-canary-")):
			re := regexp.MustCompile(`tag:tailkeeper-canary-[0-9a-f]{8}`)
			apitest.CanaryFailed(re.FindString(string(body)), true).Write(w)
		default:
			apitest.PolicyUnknownField("nodeAttr").Write(w)
		}
	})
	h2, _ := policyHarness(t, f)
	h2.app.Loaded = &config.Loaded{Source: config.SourceUser, Path: "/home/u/config.hujson"}
	h2.app.Credential = creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID, Provider: "env"}.String()
	h2.run("doctor", "--probe")
	var tests, rejection, ssh, live int
	for _, req := range f.Requests() {
		if req.Method != "POST" {
			continue
		}
		if req.Path != apitest.ValidatePath {
			t.Errorf("a POST went to %s", req.Path)
		}
		switch body := string(req.Body); {
		case strings.HasPrefix(strings.TrimSpace(body), "["):
			tests++
		case strings.Contains(body, `"nodeAttr"`):
			rejection++
		case strings.Contains(body, `"sshTests"`):
			ssh++
		case strings.Contains(body, "tag:tailkeeper-canary-") && strings.Contains(body, "tag:ci"):
			live++
		default:
			t.Errorf("a document of a kind the help does not name: %.200s", body)
		}
	}
	// The canary test and one test for each of the five destination kinds; two synthetic
	// documents; the live policy with its canary.
	if tests != 6 || rejection != 1 || ssh != 1 || live != 1 {
		t.Errorf("sent: %d tests, %d rejection, %d ssh, %d live-policy documents; the help names 6 tests, 2 synthetic documents and 1 live policy", tests, rejection, ssh, live)
	}
}

// The hint of an error the users read raised can name a login too: the command masks it
// whatever the hint says, with the login's length no part of what is printed.
func TestAUsersReadErrorShowsNoLoginInItsHintOnStandardError(t *testing.T) {
	masked := "a…@example.com"
	for _, asJSON := range []bool{false, true} {
		t.Run(fmt.Sprintf("json=%v", asJSON), func(t *testing.T) {
			got := map[int]string{}
			for _, n := range []int{1100, 1300} {
				login := strings.Repeat("a", n) + "@example.com"
				f := apitest.New(t)
				h, _ := policyHarness(t, f)
				h.app.KeyID = ""
				h.app.Env.API = nil
				h.app.Env.APIErr = tkerr.New(tkerr.CredentialUnavailable, "no read credential is configured", "ask "+login+" for a credential")
				args := []string{"doctor", "--policy", "--out", filepath.Join(t.TempDir(), "i.hujson"), "--tag", "tag:ci", "--admin-group", "group:a", "--with-logins"}
				if asJSON {
					args = append([]string{"--json"}, args...)
				}
				if exit := h.run(args...); exit == 0 {
					t.Fatal("exit 0")
				}
				out := h.out.String() + h.err.String()
				if strings.Contains(out, strings.Repeat("a", 20)) || strings.Count(out, "@") != 1 || !strings.Contains(out, masked) {
					t.Fatalf("n=%d: output (%d bytes) = %.300q, want the masked login once", n, len(out), out)
				}
				got[n] = out
			}
			if got[1100] != got[1300] {
				t.Fatalf("the output tells the length of the login:\n%.300s\n%.300s", got[1100], got[1300])
			}
		})
	}
}

// withoutPath replaces path in out with PATH, both as typed and as a JSON string
// holds it: a Windows path's backslashes are escaped in the JSON layout.
func withoutPath(t *testing.T, out, path string) string {
	t.Helper()
	quoted, err := json.Marshal(path)
	if err != nil {
		t.Fatal(err)
	}
	out = strings.ReplaceAll(out, string(quoted[1:len(quoted)-1]), "PATH")
	return strings.ReplaceAll(out, path, "PATH")
}
