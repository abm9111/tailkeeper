package tools_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

func TestACLTestReportsPassFailAndWarnings(t *testing.T) {
	for _, c := range []struct {
		shape    apitest.Shape
		status   string
		failures int
		warnings int
	}{
		{apitest.TestsPass(), "pass", 0, 0},
		{apitest.TestsPassEmptyObject(), "pass", 0, 0},
		{apitest.TestsFailed(apitest.Entry{User: "amy@example.com", Errors: []string{`address "203.0.113.9:22": want: Accept, got: Drop for amy@example.com`}}), "fail", 1, 0},
		{apitest.TestsWarned(apitest.Entry{User: "amy@example.com", Warnings: []string{`host alias "lab" unused`}}), "pass", 0, 1},
	} {
		f, reg, env := apiEnv(t)
		f.ServeValidate(c.shape)
		var out tools.ACLTestOutput
		s := mustCall(t, reg, env, "acl_test", `{"src":"amy@example.com","accept":["203.0.113.9:22"],"deny":["tag:db:5432"],"proto":"tcp"}`, &out)
		if out.Status != c.status || len(out.Failures) != c.failures || len(out.Warnings) != c.warnings || out.Note == "" || out.EvaluatedAt == "" {
			t.Errorf("%s: %+v", c.shape.Name, out)
		}
		if want := map[string]int{"pass": 0, "fail": 9}[c.status]; out.ExitCode() != want {
			t.Errorf("%s: exit code %d, want %d", c.shape.Name, out.ExitCode(), want)
		}
		absent(t, s, "amy@")
		if c.failures > 0 && !strings.Contains(s, "203.0.113.9:22") {
			t.Errorf("the failing destination must stay whole: %s", s)
		}
		var sent []map[string]any
		if r := f.Requests()[0]; r.Method != "POST" || json.Unmarshal(r.Body, &sent) != nil || len(sent) != 1 || sent[0]["src"] != "amy@example.com" || sent[0]["proto"] != "tcp" {
			t.Errorf("request = %s %s %s", r.Method, r.Path, r.Body)
		}
	}
}

func TestACLTestChecksItsInput(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.Raw("POST", "/api/v2/tailnet/T1234CNTRL/acl/validate", 200, "", nil)
	many := make([]string, 33)
	for i := range many {
		many[i] = fmt.Sprintf(`"tag:t%d:22"`, i)
	}
	for args, want := range map[string]string{
		`{"src":"tag:ci"}`: "at least one destination",
		`{"src":"a…@example.com","accept":["tag:prod:22"]}`:                       "masked value",
		`{"src":"tag:ci","accept":["b…@example.com:22"]}`:                         "masked value",
		`{"src":"tag:ci","accept":["*:22"]}`:                                      "wildcards",
		`{"src":"tag:ci","accept":["10.0.0.0/8:22"]}`:                             "CIDR",
		`{"src":"tag:ci","accept":["tag:prod:70000"]}`:                            "port",
		`{"src":"tag:ci","accept":["tag:prod:ssh"]}`:                              "port",
		`{"src":"tag:ci","accept":["tag:prod"]}`:                                  "port",
		`{"src":"tag:ci","accept":["fd7a:115c:a1e0::5:22"]}`:                      "brackets",
		`{"src":"tag:ci","accept":["[fd7a:115c:a1e0::5]22"]}`:                     "[address]:port",
		`{"src":"tag:ci","accept":["tag:prod:22"],"proto":"TCP"}`:                 "proto",
		`{"src":"tag:ci","accept":["tag:prod:22"],"proto":"256"}`:                 "between 1 and 255",
		`{"src":"tag:ci","accept":["tag:prod:22"],"proto":"icmp"}`:                "port 0",
		`{"src":"tag:ci","accept":[` + strings.Join(many, ",") + `]}`:             "at most 32",
		`{"src":"tag:` + strings.Repeat("c", 300) + `","accept":["tag:prod:22"]}`: "longer than 300 bytes",
		`{"src":"tag:ci\u001b[2J","accept":["tag:prod:22"]}`:                      "invisible",
		`{"src":"10.0.0.0/8","accept":["tag:prod:22"]}`:                           "no CIDR",
		`{"src":"tag:ci tag:cd","accept":["tag:prod:22"]}`:                        "no spaces",
		`{"src":"   ","accept":["tag:prod:22"]}`:                                  "src is required",
		`{"src":"tag:ci","accept":["tag:prod:22"],"proto":"1"}`:                   "ICMP tests use port 0",
		`{"src":"tag:ci","accept":["tag:prod:22"],"proto":"58"}`:                  "ICMP tests use port 0",
	} {
		if _, err := call(t, reg, env, "acl_test", args); code(err) != tkerr.ValidationFailed || !strings.Contains(err.Error(), want) {
			t.Errorf("%.60s: err = %v, want %q", args, err, want)
		}
	}
	if n := len(f.Requests()); n != 0 {
		t.Errorf("%d requests sent for refused input", n)
	}
	for _, args := range []string{
		`{"src":"tag:ci","accept":["tag:prod:22","group:eng:443","autogroup:internet:443","[fd7a:115c:a1e0::5]:22","100.64.0.5:443","edge:80","amy@example.com:22"]}`,
		`{"src":"group:eng","deny":["tag:db:5432"],"proto":"6"}`,
		`{"src":"100.64.0.5","accept":["tag:prod:0"],"proto":"icmp"}`,
	} {
		if _, err := call(t, reg, env, "acl_test", args); err != nil {
			t.Errorf("%.60s: %v", args, err)
		}
	}
}

// No fallback to sending the whole policy: a missing scope is reported as one,
// after exactly one request.
func TestACLTestReportsAMissingScope(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("POST", "/api/v2/tailnet/T1234CNTRL/acl/validate", 403, `{"message":"forbidden"}`)
	if _, err := call(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:prod:22"]}`); code(err) != tkerr.ScopeMissing {
		t.Errorf("err = %v, want scope_missing", err)
	}
	if n := len(f.Requests()); n != 1 {
		t.Errorf("%d requests, want the one POST", n)
	}
}

// Validation errors name the entry, not its value: errors are masked like free
// text, and a public address echoed back would read as a range.
func TestACLTestErrorsNameTheEntry(t *testing.T) {
	_, reg, env := apiEnv(t)
	_, err := call(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:prod:22","203.0.113.9:70000"]}`)
	if code(err) != tkerr.ValidationFailed || !strings.Contains(err.Error(), "accept[1]: the port") || strings.Contains(err.Error(), "203.0.113") {
		t.Errorf("err = %v", err)
	}
}
