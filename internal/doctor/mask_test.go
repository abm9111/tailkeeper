package doctor

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// maskedLogin is what the masker leaves of a login whatever its length.
const maskedLogin = "a…@example.com"

// loginOf returns a login whose local part is n bytes long: longer than the cap on
// a row, so a cut made before masking drops its "@" and shows what is left.
func loginOf(n int) string { return strings.Repeat("a", n) + "@example.com" }

// checkTwoLogins runs show for two logins of different lengths, both longer than the
// cap, and requires every text it returns to hold the masked form once and no run of
// the local part, and the two runs to be byte-identical.
func checkTwoLogins(t *testing.T, show func(login string) map[string]string) {
	t.Helper()
	got := map[int]map[string]string{}
	for _, n := range []int{1100, 1300} {
		got[n] = show(loginOf(n))
		for field, text := range got[n] {
			if strings.Contains(text, strings.Repeat("a", 20)) || strings.Count(text, "@") != 1 || !strings.Contains(text, maskedLogin) {
				t.Errorf("n=%d %s (%d bytes) = %.80q, want the masked login once and no run of the local part", n, field, len(text), text)
			}
		}
	}
	for field, text := range got[1100] {
		if got[1300][field] != text {
			t.Errorf("%s tells the length of the login", field)
		}
	}
}

func rowOf(t *testing.T, r Report, name string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %s row", name)
	return Check{}
}

func TestMaskRowMasksBeforeItCuts(t *testing.T) {
	checkTwoLogins(t, func(login string) map[string]string {
		return map[string]string{"row": maskRow("failed for " + login + " today")}
	})
}

func TestARowFromAnErrorShowsNoLoginInTheMessageOrTheHint(t *testing.T) {
	for name, add := range map[string]func(r *Report, err error){
		"addErr":     func(r *Report, err error) { r.addErr("row", Warn, err) },
		"addReadErr": func(r *Report, err error) { r.addReadErr("row", err) },
	} {
		t.Run(name, func(t *testing.T) {
			checkTwoLogins(t, func(login string) map[string]string {
				var r Report
				add(&r, tkerr.New(tkerr.APIError, "failed for "+login+" today", "ask "+login+" to retry"))
				c := rowOf(t, r, "row")
				return map[string]string{"detail": c.Detail, "hint": c.Hint}
			})
		})
	}
}

func TestTheKeyRecordRowShowsNoLoginInTheMessageOrTheHint(t *testing.T) {
	checkTwoLogins(t, func(login string) map[string]string {
		var r Report
		r.addKeyReadErr(apitest.Tailnet, tkerr.New(tkerr.APIError, "failed for "+login+" today", "ask "+login+" to retry"))
		c := rowOf(t, r, "key record")
		return map[string]string{"detail": c.Detail, "hint": c.Hint}
	})
}

func TestTheKeyRecordRowNamesTheTailnetByItsStartWhenTheRecordIsNotFound(t *testing.T) {
	var r Report
	r.addKeyReadErr(apitest.Tailnet, tkerr.New(tkerr.NotFound, "no such key", "a login hint"))
	c := rowOf(t, r, "key record")
	if c.Status != Fail || !strings.Contains(c.Hint, "tailnetId T123…") || strings.Contains(c.Hint, apitest.Tailnet) {
		t.Fatalf("key record = %+v", c)
	}
}

func TestTheCanaryRefusedBeforeSendingShowsNoLoginInItsMessage(t *testing.T) {
	checkTwoLogins(t, func(login string) map[string]string {
		st, detail, _, ok := canaryVerdict(tools.ACLTestOutput{}, tkerr.New(tkerr.ValidationFailed, "the test names "+login, ""))
		if !ok || st != Fail {
			t.Fatalf("status %s ok %v", st, ok)
		}
		return map[string]string{"detail": detail}
	})
}

func TestTheAuditLogRowShowsNoLoginFromAFailureToRecord(t *testing.T) {
	_, a := newApp(t, allReadScopes(t))
	checkTwoLogins(t, func(login string) map[string]string {
		var r Report
		auditChecks(&r, a, tkerr.New(tkerr.AuditUnavailable, "cannot append for "+login+" today", "ask "+login+" to retry"))
		c := rowOf(t, r, "audit log")
		if c.Status != Warn {
			t.Fatalf("audit log = %+v", c)
		}
		// The path is the one text the row holds that is not the error's.
		return map[string]string{"detail": strings.ReplaceAll(c.Detail, a.Audit.Path(), "PATH"), "hint": c.Hint}
	})
}

// The login reaches the rows of the policy-mode probes (which mask the error themselves),
// of the kind probes and of the plain reads, whatever the status the answers carry. A status
// that the probes read as a server failure never shows the text, so each status names the
// rows it must reach: a run in which none of them held the login would prove nothing.
func TestEveryProbeReadThatFailsShowsNoLoginInTheReport(t *testing.T) {
	for _, c := range []struct {
		status int
		rows   []string
	}{
		{500, []string{"probe acl_get", "probe details keys", "probe tag", "probe IPv4 address"}},
		{404, []string{"probe acl_get", "probe policy rejection", "probe details keys", "probe ssh tests", "probe tag", "probe IPv4 address"}},
		{409, []string{"probe policy rejection", "probe details keys", "probe ssh tests", "probe host alias"}},
		{403, []string{"probe policy rejection", "probe details keys", "probe ssh tests", "probe ICMP, port 0"}},
	} {
		t.Run(http.StatusText(c.status), func(t *testing.T) {
			checkTwoLogins(t, func(login string) map[string]string {
				f, a := newApp(t, allReadScopes(t))
				f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
				body := `{"message":"server failed for ` + login + ` today"}`
				f.JSON("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/acl", c.status, body)
				f.JSON("POST", apitest.ValidatePath, c.status, body)
				r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
				out := map[string]string{}
				for _, ch := range r.Checks {
					if strings.Contains(ch.Detail, "example.com") || strings.Contains(ch.Hint, "example.com") {
						out[ch.Name] = ch.Detail + "\n" + ch.Hint
					}
				}
				for _, name := range c.rows {
					if _, ok := out[name]; !ok {
						t.Fatalf("the row %q does not carry the login: the test proves nothing about it", name)
					}
				}
				raw, err := os.ReadFile(a.Audit.Path())
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(raw), "aaaaaaaaaaaaaaaaaaaa") {
					t.Error("the audit log holds the login")
				}
				return out
			})
		})
	}
}

func TestAUsersReadErrorShowsNoLoginInItsMessageWhateverTheStatus(t *testing.T) {
	for _, status := range []int{500, 404, 400, 409} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			checkTwoLogins(t, func(login string) map[string]string {
				f, a := newApp(t, allReadScopes(t))
				serveKey(f, `{"id":"test-client-id","keyType":"client"}`)
				f.JSON("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/users", status, `{"message":"user `+login+` cannot be listed"}`)
				_, err := WriteStarter(context.Background(), a, StarterInput{Out: starterPath(t), Tags: []string{"tag:web"}, AdminGroups: []string{"group:eng"}, WithLogins: true})
				if err == nil {
					t.Fatal("no error")
				}
				return map[string]string{"message": tkerr.From(err).Message}
			})
		})
	}
}

func TestAUsersReadErrorShowsNoLoginInItsHint(t *testing.T) {
	checkTwoLogins(t, func(login string) map[string]string {
		err := maskUsersErr(tkerr.New(tkerr.APIError, "failed for "+login+" today", "ask "+login+" to retry"))
		e := tkerr.From(err)
		return map[string]string{"message": e.Message, "hint": e.Hint}
	})
}

func TestACredentialErrorOfTheUsersReadShowsNoLogin(t *testing.T) {
	_, a := newApp(t, allReadScopes(t))
	checkTwoLogins(t, func(login string) map[string]string {
		a.Env.API = nil
		a.Env.APIErr = tkerr.New(tkerr.CredentialUnavailable, "no credential for "+login+" today", "ask "+login+" to retry")
		_, err := adminLogins(context.Background(), a)
		e := tkerr.From(err)
		return map[string]string{"message": e.Message, "hint": e.Hint}
	})
}

// The key record row is built by Run from the failed read, not only by the function that
// words it: a failed read is a failing row (not a warning, and not absent), and the text of
// the answer it shows is masked and cut in that order.
func TestAFailedKeyRecordReadIsAFailingRowThatShowsNoLogin(t *testing.T) {
	for _, status := range []int{500, 400, 409} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			checkTwoLogins(t, func(login string) map[string]string {
				f, a := newApp(t, allReadScopes(t))
				f.JSON("GET", keyPath, status, `{"message":"key read failed for `+login+` today"}`)
				r := Run(context.Background(), Input{App: a, Now: now})
				c := rowOf(t, r, "key record")
				if c.Status != Fail {
					t.Fatalf("key record = %+v, want a failing row", c)
				}
				return map[string]string{"detail": c.Detail}
			})
		})
	}
}
