package tools_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

func serveSSH(f *apitest.Fake, policy string, answer func(tag string) apitest.Shape) {
	serveSSHCanary(f, policy, answer, func(sshTag string) []apitest.Entry {
		return []apitest.Entry{sshCanaryEntryOf(sshTag)}
	})
}

// serveSSHCanary is serveSSH with the entries that stand for the SSH canary chosen by the
// test: none, a canary that is not the canary, or two of them.
func serveSSHCanary(f *apitest.Fake, policy string, answer func(tag string) apitest.Shape, canary func(sshTag string) []apitest.Entry) {
	servePolicy(f, policy, `"e1"`)
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		text := string(body)
		shape := answer(canaryTagRE.FindString(text))
		if sshTag := sshCanaryTagRE.FindString(text); sshTag != "" {
			shape = withEntries(shape, canary(sshTag)...)
		}
		shape.Write(w)
	})
}

var sshCanaryTagRE = regexp.MustCompile(`tag:tailkeeper-sshcanary-[0-9a-f]{8}`)

// sshCanaryEntryOf is the failure the SSH canary of the request produces: the line probe
// A-10 printed, for the canary's user on its destination.
func sshCanaryEntryOf(sshTag string) apitest.Entry {
	line := apitest.SSHTestFailed(sshTag, "192.0.2.1", "192.0.2.1", "192.0.2.1", "canary")
	var one struct {
		Data []struct {
			User   string   `json:"user"`
			Errors []string `json:"errors"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(line.Body), &one); err != nil || len(one.Data) != 1 {
		panic("the SSH canary's shape is not an entry")
	}
	return apitest.Entry{User: one.Data[0].User, Errors: one.Data[0].Errors}
}

// withSSHCanary appends the SSH canary's failure when the answer already carries
// a data array. A pass has no data, so a missing tests canary stays missing its
// SSH canary too.
func withSSHCanary(s apitest.Shape, sshTag string) apitest.Shape {
	return withEntries(s, sshCanaryEntryOf(sshTag))
}

// withEntries appends entries to the data array of an answer that has one.
func withEntries(s apitest.Shape, entries ...apitest.Entry) apitest.Shape {
	if !strings.Contains(s.Body, `"data"`) {
		return s
	}
	var body struct {
		Message string `json:"message"`
		Data    []struct {
			User     string   `json:"user"`
			Errors   []string `json:"errors,omitempty"`
			Warnings []string `json:"warnings,omitempty"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(s.Body), &body); err != nil {
		return s
	}
	for _, e := range entries {
		body.Data = append(body.Data, struct {
			User     string   `json:"user"`
			Errors   []string `json:"errors,omitempty"`
			Warnings []string `json:"warnings,omitempty"`
		}{User: e.User, Errors: e.Errors, Warnings: e.Warnings})
	}
	b, err := json.Marshal(body)
	if err != nil {
		return s
	}
	s.Body = string(b)
	return s
}

func sshCall(dst, user, list string) string {
	return `{"src":"tag:db","ssh":[{"dst":["` + dst + `"],"` + list + `":["` + user + `"]}]}`
}

func sshFailedEntry(t *testing.T, src, dst, user string) apitest.Entry {
	t.Helper()
	s := apitest.SSHTestFailed(src, "100.64.0.1", dst, "100.64.0.2", user)
	var body struct {
		Data []struct {
			User   string   `json:"user"`
			Errors []string `json:"errors"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(s.Body), &body); err != nil || len(body.Data) != 1 {
		t.Fatalf("SSHTestFailed: %v", err)
	}
	return apitest.Entry{User: body.Data[0].User, Errors: body.Data[0].Errors}
}

func sshCheckLine(t *testing.T) string {
	t.Helper()
	s := apitest.SSHCheckFailed("tag:db", "100.64.0.1", "tag:db", "100.64.0.2", "root")
	var body struct {
		Data []struct {
			Errors []string `json:"errors"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(s.Body), &body); err != nil || len(body.Data) != 1 || len(body.Data[0].Errors) != 1 {
		t.Fatalf("SSHCheckFailed: %v %+v", err, body)
	}
	return body.Data[0].Errors[0]
}

func TestAnSSHTestThatPassesIsAllowed(t *testing.T) {
	f, reg, env := apiEnv(t)
	serveSSH(f, "{}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}})
	})
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", sshCall("tag:db", "root", "accept"), &out)
	if out.Status != "pass" || out.ExitCode() != 0 || len(out.SSHVerdicts) != 1 {
		t.Fatalf("%+v", out)
	}
	if out.SSHVerdicts[0].Dst != "tag:db" || out.SSHVerdicts[0].User != "root" || out.SSHVerdicts[0].Expect != "accept" || out.SSHVerdicts[0].Verdict != "allowed" {
		t.Fatalf("verdict %+v", out.SSHVerdicts[0])
	}
	if posts(f) != 1 {
		t.Fatalf("%d validate requests, want 1", posts(f))
	}
}

func TestAnSSHTestThatFailsReadsFromTheSSHFormAndExitsNine(t *testing.T) {
	f, reg, env := apiEnv(t)
	serveSSH(f, "{}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(
			apitest.Entry{User: tag, Errors: []string{canaryLine}},
			sshFailedEntry(t, "tag:db", "tag:c", "root"),
		)
	})
	args := `{"src":"tag:db","ssh":[{"dst":["tag:a"],"accept":["root"]},{"dst":["tag:b"],"accept":["root"]},{"dst":["tag:c"],"accept":["root"]}]}`
	var out tools.ACLTestOutput
	s := mustCall(t, reg, env, "acl_test", args, &out)
	if out.Status != "fail" || out.ExitCode() != 9 || len(out.SSHVerdicts) != 3 {
		t.Fatalf("%+v", out)
	}
	if out.SSHVerdicts[2].Dst != "tag:c" || out.SSHVerdicts[2].Verdict != "denied" || out.SSHVerdicts[0].Verdict != "allowed" {
		t.Fatalf("verdicts %+v", out.SSHVerdicts)
	}
	if !strings.Contains(s, "ssh[2]") || strings.Contains(s, "line 41") {
		t.Fatalf("the failure is not placed at the caller's test: %s", s)
	}
}

func TestADenyUserWithNoLineIsDenied(t *testing.T) {
	f, reg, env := apiEnv(t)
	serveSSH(f, "{}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}})
	})
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", sshCall("tag:db", "root", "deny"), &out)
	if out.Status != "pass" || out.ExitCode() != 0 || len(out.SSHVerdicts) != 1 || out.SSHVerdicts[0].Verdict != "denied" || out.SSHVerdicts[0].Expect != "deny" {
		t.Fatalf("%+v", out)
	}
}

func TestACheckUserWithNoLineIsUnknownNotAllowed(t *testing.T) {
	f, reg, env := apiEnv(t)
	serveSSH(f, "{}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}})
	})
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", sshCall("tag:db", "root", "check"), &out)
	if out.Status != "unknown" || out.ExitCode() != 1 || len(out.SSHVerdicts) != 1 || out.SSHVerdicts[0].Verdict != "unknown" {
		t.Fatalf("%+v", out)
	}
	if out.SSHVerdicts[0].Verdict == "allowed" || out.Status == "pass" {
		t.Fatalf("a silent check user was allowed: %+v", out)
	}
}

func TestACheckFailureLineInTheUnobservedShapeIsNeverAPass(t *testing.T) {
	f, reg, env := apiEnv(t)
	line := sshCheckLine(t)
	serveSSH(f, "{}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(
			apitest.Entry{User: tag, Errors: []string{canaryLine}},
			apitest.Entry{User: "tag:db", Errors: []string{line}},
		)
	})
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", sshCall("tag:db", "root", "accept"), &out)
	if out.Status != "unknown" || out.ExitCode() != 1 {
		t.Fatalf("%+v", out)
	}
	for _, v := range out.SSHVerdicts {
		if v.Verdict == "allowed" || v.Verdict == "pass" {
			t.Fatalf("the unobserved check line was a pass: %+v", out.SSHVerdicts)
		}
	}
}

// The reply holds an entry for the posted source in another spelling: an SSH test that
// failed, or no line at all. Neither is a pass.
func TestAnSSHReplyForAnotherSpellingOfTheSourceIsUnknownNeverAPass(t *testing.T) {
	for name, entry := range map[string]func() apitest.Entry{
		"a failed SSH test":  func() apitest.Entry { return sshFailedEntry(t, "TAG:DB", "tag:db", "root") },
		"a trailing space":   func() apitest.Entry { return apitest.Entry{User: "tag:db ", Errors: []string{"test(s) failed"}} },
		"an upper-case user": func() apitest.Entry { return apitest.Entry{User: "TAG:DB", Errors: []string{"test(s) failed"}} },
	} {
		f, reg, env := apiEnv(t)
		serveSSH(f, "{}\n", func(tag string) apitest.Shape {
			return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}}, entry())
		})
		var out tools.ACLTestOutput
		mustCall(t, reg, env, "acl_test", sshCall("tag:db", "root", "accept"), &out)
		if out.Status != "unknown" || out.ExitCode() != 1 || len(out.SSHVerdicts) != 1 || out.SSHVerdicts[0].Verdict != "unknown" || len(out.Unmatched) != 1 {
			t.Errorf("%s: %+v", name, out)
		}
	}
}

func TestTheBuiltDocumentIsTheLivePolicyWithoutItsTestsPlusTheCallersSSHTestsAndTheCanary(t *testing.T) {
	const live = `{"tagOwners":{"tag:db":[]},"hosts":{"db":"100.64.0.2"},"tests":[{"src":"tag:db","accept":["tag:db:22"]}],"sshTests":[{"src":"tag:db","dst":["tag:db"],"accept":["stored-user"]}]}`
	f, reg, env := apiEnv(t)
	serveSSH(f, live, func(tag string) apitest.Shape {
		return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}})
	})
	if _, err := call(t, reg, env, "acl_test", sshCall("tag:db", "root", "accept")); err != nil {
		t.Fatal(err)
	}
	body := postBody(t, f)
	if strings.Contains(body, "stored-user") || strings.Contains(body, "tag:db:22") {
		t.Fatalf("the live tests are still in the copy:\n%s", body)
	}
	if !strings.Contains(body, "100.64.0.2") || !strings.Contains(body, `"root"`) || !strings.Contains(body, "192.0.2.1:1") {
		t.Fatalf("the copy dropped the policy or the caller's test:\n%s", body)
	}
	if !strings.HasPrefix(strings.TrimSpace(body), "{") {
		t.Fatalf("the copy is not the policy object: %s", body)
	}
	doc, err := acl.Parse(context.Background(), []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	sum, err := acl.Summarise(context.Background(), doc)
	if err != nil || sum.Tests != 1 || sum.SSHTests != 2 {
		t.Fatalf("tests %d ssh %d err %v; want the caller's SSH test and the SSH canary", sum.Tests, sum.SSHTests, err)
	}
	if !strings.Contains(body, "tag:tailkeeper-sshcanary-") || !strings.Contains(body, `"canary"`) {
		t.Fatalf("the SSH canary is not in the copy:\n%s", body)
	}
}

func TestAMissingOrUnevaluableOrDoubledCanaryIsUnknownNeverAPass(t *testing.T) {
	for _, c := range []struct {
		name   string
		answer func(tag string) apitest.Shape
	}{
		{"missing", func(string) apitest.Shape { return apitest.TestsPassEmptyObject() }},
		{"unevaluable", func(tag string) apitest.Shape {
			return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{"[acl test error]: user or host is invalid: tag not found"}})
		}},
		{"doubled", func(tag string) apitest.Shape {
			return apitest.TestsFailed(
				apitest.Entry{User: tag, Errors: []string{canaryLine}},
				apitest.Entry{User: tag, Errors: []string{canaryLine}},
			)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, reg, env := apiEnv(t)
			serveSSH(f, "{}\n", c.answer)
			var out tools.ACLTestOutput
			mustCall(t, reg, env, "acl_test", sshCall("tag:db", "root", "accept"), &out)
			if out.Status != "unknown" || out.ExitCode() != 1 || out.Status == "pass" {
				t.Fatalf("%+v", out)
			}
			for _, v := range out.SSHVerdicts {
				if v.Verdict == "allowed" {
					t.Fatalf("canary %s left an allowed verdict: %+v", c.name, out.SSHVerdicts)
				}
				if v.Why != "the SSH tests were not shown to have run" {
					t.Errorf("canary %s: why %q names a cause the call did not meet", c.name, v.Why)
				}
			}
		})
	}
}

func TestACanaryWithTheWrongDestinationOrDirectionIsNotTheCanary(t *testing.T) {
	wrongDst := `[acl test error]: address "192.0.2.9:1" (protocol "tcp"): want: Drop, got: Accept`
	denyAllLine := `[acl test error]: address "192.0.2.1:1" (protocol "tcp"): want: Accept, got: Drop`
	for _, c := range []struct {
		name, policy, line string
	}{
		{"wrong destination", "{}\n", wrongDst},
		{"allow-all answered as deny-all", "{}\n", denyAllLine},
		{"deny-all answered as allow-all", `{"acls":[]}` + "\n", canaryLine},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, reg, env := apiEnv(t)
			serveSSH(f, c.policy, func(tag string) apitest.Shape {
				return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{c.line}})
			})
			var out tools.ACLTestOutput
			mustCall(t, reg, env, "acl_test", sshCall("tag:db", "root", "accept"), &out)
			if out.Status != "unknown" || out.ExitCode() != 1 {
				t.Fatalf("%s: %+v", c.name, out)
			}
		})
	}
	f, reg, env := apiEnv(t)
	serveSSH(f, "{\"acls\":[]}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{denyAllLine}})
	})
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", sshCall("tag:db", "root", "accept"), &out)
	if out.Status != "pass" || out.SSHVerdicts[0].Verdict != "allowed" {
		t.Fatalf("the deny-all direction was not the canary: %+v", out)
	}
}

func TestTheUnmodifiedLivePolicyFailingValidateIsSaidToBeTheLivePolicy(t *testing.T) {
	const live = "{\"acls\":[]}\n"
	f, reg, env := apiEnv(t)
	n := 0
	servePolicy(f, live, `"e1"`)
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			apitest.PolicyUnknownField("nodeAttr").Write(w)
			return
		}
		apitest.PolicyUnknownField("nodeAttr").Write(w)
	})
	var out tools.ACLTestOutput
	s := mustCall(t, reg, env, "acl_test", sshCall("tag:db", "root", "accept"), &out)
	if out.Status != "unknown" || !strings.Contains(s, "the live policy does not validate") || strings.Contains(s, "your SSH tests were refused") {
		t.Fatalf("%s", s)
	}
	if posts(f) != 2 {
		t.Fatalf("%d validate requests, want 2", posts(f))
	}
	var second string
	seen := 0
	for _, r := range f.Requests() {
		if r.Method == "POST" {
			seen++
			if seen == 2 {
				second = string(r.Body)
			}
		}
	}
	if second != live {
		t.Fatalf("the second send is not the unmodified live policy:\n%s", second)
	}

	f, reg, env = apiEnv(t)
	n = 0
	servePolicy(f, live, `"e1"`)
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			apitest.PolicyUnknownField("nodeAttr").Write(w)
			return
		}
		apitest.TestsPassEmptyObject().Write(w)
	})
	s = mustCall(t, reg, env, "acl_test", sshCall("tag:db", "root", "accept"), &out)
	if !strings.Contains(s, "your SSH tests were refused") || strings.Contains(s, "the live policy does not validate") {
		t.Fatalf("%s", s)
	}
	if posts(f) != 2 {
		t.Fatalf("refused path drew %d validate requests, want 2", posts(f))
	}
}

func TestARejectionOfTheBuiltDocumentShowsNoLineOfIt(t *testing.T) {
	var b strings.Builder
	b.WriteString("{\n\t\"tagOwners\": {\"tag:db\": []},\n\t\"tests\": [\n")
	for i := 0; i < 40; i++ {
		comma := ","
		if i == 39 {
			comma = ""
		}
		b.WriteString("\t\t{\"src\": \"tag:db\", \"accept\": [\"tag:db:22\"]}" + comma + "\n")
	}
	b.WriteString("\t]\n}\n")
	f, reg, env := apiEnv(t)
	n := 0
	servePolicy(f, b.String(), `"e1"`)
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			apitest.PolicySyntaxError(41, 3, "unexpected token").Write(w)
			return
		}
		apitest.TestsPassEmptyObject().Write(w)
	})
	s, err := call(t, reg, env, "acl_test", sshCall("tag:db", "root", "accept"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s, "line 41") || strings.Contains(s, "column 3") || !strings.Contains(s, "your SSH tests were refused") {
		t.Fatalf("the built document's position reached the result:\n%s", s)
	}
}

func TestSSHFailureMessagesKeepDeviceAddressesWhole(t *testing.T) {
	const login = "amy@example.com"
	f, reg, env := apiEnv(t)
	k, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		t.Fatal(err)
	}
	env.Privacy = k
	line := `[ssh test error]: src "` + login + `" at "100.64.0.5", dst "tag:db" at "100.64.0.6", ssh user "root": want: "accept" got: "deny"`
	f.JSON("GET", tailnetPath+"/users", 200, `{"users":[{"id":"u1","loginName":"`+login+`","type":"member"}]}`)
	serveSSH(f, "{}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(
			apitest.Entry{User: tag, Errors: []string{canaryLine}},
			apitest.Entry{User: login, Errors: []string{line}},
		)
	})
	s, err := call(t, reg, env, "acl_test", `{"src":`+jsonString(k.APIPseudonym(login))+`,"ssh":[{"dst":["tag:db"],"accept":["root"]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "100.64.0.5") || !strings.Contains(s, "100.64.0.6") {
		t.Fatalf("a device address was masked:\n%s", s)
	}
	absent(t, s, login, "amy@")
	if !strings.Contains(s, "a…@example.com") {
		t.Fatalf("the login was not masked: %s", s)
	}
}

func TestTwoLoginsOfDifferentLengthsBehindOneMaskAreTheSameSSHResult(t *testing.T) {
	results := map[int]string{}
	for _, n := range []int{3, 40} {
		login := "a" + strings.Repeat("m", n) + "@example.com"
		f, reg, env := apiEnv(t)
		k, err := privacy.Parse(strings.Repeat("5a", 32))
		if err != nil {
			t.Fatal(err)
		}
		env.Privacy = k
		line := `[ssh test error]: src "` + login + `" at "100.64.0.5", dst "tag:db" at "100.64.0.6", ssh user "root": want: "accept" got: "deny"`
		f.JSON("GET", tailnetPath+"/users", 200, `{"users":[{"id":"u1","loginName":`+jsonString(login)+`,"type":"member"}]}`)
		serveSSH(f, "{}\n", func(tag string) apitest.Shape {
			return apitest.TestsFailed(
				apitest.Entry{User: tag, Errors: []string{canaryLine}},
				apitest.Entry{User: login, Errors: []string{line}},
			)
		})
		s, err := call(t, reg, env, "acl_test", `{"src":`+jsonString(k.APIPseudonym(login))+`,"ssh":[{"dst":["tag:db"],"accept":["root"]}]}`)
		if err != nil {
			t.Fatal(err)
		}
		absent(t, s, login)
		if !strings.Contains(s, "100.64.0.5") {
			t.Fatalf("the address is gone: %s", s)
		}
		results[n] = s
	}
	if results[3] != results[40] {
		t.Errorf("the result tells the length of a login:\n%.500s\n%.500s", results[3], results[40])
	}
}

func TestAGroupSourceIsAcceptedWithANoteAndAnAutogroupSourceIsRefusedBeforeAnyRequest(t *testing.T) {
	f, reg, env := apiEnv(t)
	_, err := call(t, reg, env, "acl_test", `{"src":"autogroup:member","ssh":[{"dst":["tag:db"],"accept":["root"]}]}`)
	if code(err) != tkerr.ValidationFailed {
		t.Fatalf("autogroup: %v", err)
	}
	if len(f.Requests()) != 0 {
		t.Fatalf("autogroup sent %d requests", len(f.Requests()))
	}
	f, reg, env = apiEnv(t)
	serveSSH(f, "{}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}})
	})
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", `{"src":"group:eng@example.com","ssh":[{"dst":["tag:db"],"accept":["root"]}]}`, &out)
	if out.Status != "pass" || len(out.Caveats) != 1 || !strings.Contains(out.Caveats[0], "group: source") {
		t.Fatalf("%+v", out)
	}
	if posts(f) != 1 {
		t.Fatalf("a group source sent %d validate requests", posts(f))
	}
}

func TestBothPartsInOneCallCombineTheirStatusesAndDrawTwoTokens(t *testing.T) {
	f, reg, env := apiEnv(t)
	servePolicy(f, "{}\n", `"e1"`)
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) > 0 && body[0] == '[' {
			apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{
				`[acl test error]: address "tag:other:22" (protocol "tcp"): want: Accept, got: Drop`,
			}}).Write(w)
			return
		}
		tag := canaryTagRE.FindString(string(body))
		apitest.TestsFailed(
			apitest.Entry{User: tag, Errors: []string{canaryLine}},
			sshFailedEntry(t, "tag:ci", "tag:db", "root"),
		).Write(w)
	})
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:db:22"],"ssh":[{"dst":["tag:db"],"accept":["root"]}]}`, &out)
	if out.Status != "unknown" || out.ExitCode() != 1 {
		t.Fatalf("combined %+v", out)
	}
	if posts(f) != 2 {
		t.Fatalf("%d validate requests, want 2", posts(f))
	}
}

// A call with both halves is as bad as its worse half, whichever half it is. The halves
// are answered by two requests: the tests-mode one is a list of tests, the SSH one a policy.
func TestACallWithBothHalvesTakesTheWorseStatusOfTheTwo(t *testing.T) {
	failedSSH := func(tag string) []apitest.Entry {
		return []apitest.Entry{sshFailedEntry(t, "tag:ci", "tag:db", "root")}
	}
	for name, c := range map[string]struct {
		testsHalf apitest.Shape
		sshHalf   func(tag string) []apitest.Entry
		args      string
		status    string
		exit      int
	}{
		"tests pass, SSH test failed": {apitest.TestsPass(), failedSSH, `"accept":["tag:db:22"],"ssh":[{"dst":["tag:db"],"accept":["root"]}]`, "fail", 9},
		"tests failed, SSH passes": {apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{
			`[acl test error]: address "tag:db:22" (protocol "tcp"): want: Accept, got: Drop`}}), nil, `"accept":["tag:db:22"],"ssh":[{"dst":["tag:db"],"accept":["root"]}]`, "fail", 9},
		"tests pass, SSH check user silent": {apitest.TestsPass(), nil, `"accept":["tag:db:22"],"ssh":[{"dst":["tag:db"],"check":["root"]}]`, "unknown", 1},
		"tests unresolved, SSH passes":      {apitest.TestUnevaluable("tag:ci"), nil, `"accept":["tag:db:22"],"ssh":[{"dst":["tag:db"],"accept":["root"]}]`, "unresolved", 2},
		"tests pass, SSH passes":            {apitest.TestsPass(), nil, `"accept":["tag:db:22"],"ssh":[{"dst":["tag:db"],"accept":["root"]}]`, "pass", 0},
	} {
		f, reg, env := apiEnv(t)
		servePolicy(f, "{}\n", `"e1"`)
		f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if len(body) > 0 && body[0] == '[' {
				c.testsHalf.Write(w)
				return
			}
			entries := []apitest.Entry{{User: canaryTagRE.FindString(string(body)), Errors: []string{canaryLine}}}
			if c.sshHalf != nil {
				entries = append(entries, c.sshHalf("")...)
			}
			withSSHCanary(apitest.TestsFailed(entries...), sshCanaryTagRE.FindString(string(body))).Write(w)
		})
		var out tools.ACLTestOutput
		mustCall(t, reg, env, "acl_test", `{"src":"tag:ci",`+c.args+`}`, &out)
		if out.Status != c.status || out.ExitCode() != c.exit {
			t.Errorf("%s: status %q, exit %d, want %q and %d (%+v)", name, out.Status, out.ExitCode(), c.status, c.exit, out)
		}
		if posts(f) != 2 {
			t.Errorf("%s: %d validate requests, want 2", name, posts(f))
		}
	}
}

// sshWideArgs is the widest call the input bounds allow: 8 tests of 32 destinations and 16
// users, which is 4,096 verdicts. Every destination is its own, so a line pairs with one.
func sshWideArgs(t *testing.T) string {
	t.Helper()
	var tests []map[string]any
	for i := 0; i < 8; i++ {
		var dst, users []string
		for d := 0; d < 32; d++ {
			dst = append(dst, fmt.Sprintf("tag:t%d-d%02d", i, d))
		}
		for u := 0; u < 16; u++ {
			users = append(users, fmt.Sprintf("user%02d", u))
		}
		tests = append(tests, map[string]any{"dst": dst, "accept": users})
	}
	b, err := json.Marshal(map[string]any{"src": "tag:ci", "ssh": tests})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The verdicts a result lists are bounded, whatever the call holds, and the ones not as
// asked come first: a failure in the last test is listed, and the status is read from all.
func TestSSHVerdictsInAResultAreCappedTheOnesNotAsAskedFirstAndTheRestCounted(t *testing.T) {
	args := sshWideArgs(t)
	f, reg, env := apiEnv(t)
	serveSSH(f, "{}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}})
	})
	var out tools.ACLTestOutput
	s := mustCall(t, reg, env, "acl_test", args, &out)
	if out.Status != "pass" || len(out.SSHVerdicts) != 256 || out.Omitted != 4096-256 {
		t.Fatalf("status %s, %d verdicts listed, %d omitted", out.Status, len(out.SSHVerdicts), out.Omitted)
	}
	if len(s) > 100<<10 {
		t.Errorf("the result is %d bytes", len(s))
	}
	if line := out.Report().Verdict; line != "PASS · 4096 SSH users as asked" {
		t.Errorf("the verdict line counts only the listed verdicts: %q", line)
	}
	var said []string
	for _, f := range out.Report().Facts {
		said = append(said, f.Label+": "+f.Text)
	}
	if notes := strings.Join(said, "\n"); !strings.Contains(notes, "omitted: 3840 SSH verdicts not listed") {
		t.Errorf("the report does not say verdicts were left out: %q", notes)
	}

	// One user of the last destination of the last test is denied: it is listed.
	f, reg, env = apiEnv(t)
	serveSSH(f, "{}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(
			apitest.Entry{User: tag, Errors: []string{canaryLine}},
			sshFailedEntry(t, "tag:ci", "tag:t7-d31", "user15"),
		)
	})
	out = tools.ACLTestOutput{}
	mustCall(t, reg, env, "acl_test", args, &out)
	if out.Status != "fail" || out.ExitCode() != 9 || len(out.SSHVerdicts) != 256 || out.Omitted != 4096-256 {
		t.Fatalf("status %s, %d verdicts listed, %d omitted", out.Status, len(out.SSHVerdicts), out.Omitted)
	}
	var listed []tools.ACLSSHVerdict
	for _, v := range out.SSHVerdicts {
		if v.Verdict == "denied" {
			listed = append(listed, v)
		}
	}
	if len(listed) != 1 || listed[0].Dst != "tag:t7-d31" || listed[0].User != "user15" {
		t.Errorf("the failed verdict is not listed: %+v", listed)
	}
	// Under the cap nothing is left out.
	f, reg, env = apiEnv(t)
	serveSSH(f, "{}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}})
	})
	out = tools.ACLTestOutput{}
	mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","ssh":[{"dst":["tag:a","tag:b"],"accept":["root","admin"]}]}`, &out)
	if len(out.SSHVerdicts) != 4 || out.Omitted != 0 {
		t.Errorf("%d verdicts, %d omitted", len(out.SSHVerdicts), out.Omitted)
	}
}

// 32 destinations and 3,000 users in one SSH test are refused before any request: the
// result would hold a verdict for each pair.
func TestThousandsOfSSHUsersAreRefusedBeforeAnyRequest(t *testing.T) {
	f, reg, env := apiEnv(t)
	var dst, users []string
	for d := 0; d < 32; d++ {
		dst = append(dst, fmt.Sprintf("tag:d%02d", d))
	}
	for u := 0; u < 3000; u++ {
		users = append(users, fmt.Sprintf("user%04d", u))
	}
	b, err := json.Marshal(map[string]any{"src": "tag:ci", "ssh": []map[string]any{{"dst": dst, "accept": users}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = call(t, reg, env, "acl_test", string(b))
	if code(err) != tkerr.ValidationFailed || !strings.Contains(err.Error(), "at most 16 SSH users per SSH test") {
		t.Fatalf("err = %v", err)
	}
	if len(f.Requests()) != 0 {
		t.Errorf("%d requests sent", len(f.Requests()))
	}
}

func TestSSHOnlyCallSendsNoTestsModeRequest(t *testing.T) {
	f, reg, env := apiEnv(t)
	serveSSH(f, "{}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}})
	})
	if _, err := call(t, reg, env, "acl_test", sshCall("tag:db", "root", "accept")); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range f.Requests() {
		if r.Method != "POST" {
			continue
		}
		n++
		if len(r.Body) == 0 || r.Body[0] == '[' {
			t.Fatalf("tests-mode body: %s", r.Body)
		}
	}
	if n != 1 {
		t.Fatalf("%d POSTs, want 1", n)
	}
}

func TestAPseudonymSourceInAnSSHTestIsResolvedAndTheLoginStaysOutOfTheResult(t *testing.T) {
	const amy = "ops/amy@example.com"
	f, reg, env := apiEnv(t)
	k, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		t.Fatal(err)
	}
	env.Privacy = k
	f.JSON("GET", tailnetPath+"/users", 200, `{"users":[{"id":"u1","loginName":"`+amy+`","type":"member"}]}`)
	serveSSH(f, "{}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}})
	})
	s, err := call(t, reg, env, "acl_test", `{"src":`+jsonString(k.APIPseudonym(amy))+`,"ssh":[{"dst":["tag:db"],"accept":["root"]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	body := postBody(t, f)
	if !strings.Contains(body, amy) {
		t.Fatalf("the request does not carry the login: %s", body)
	}
	absent(t, s, "ops/", "amy@")
}

func TestSSHUsersAreNotSubjectToTheLoginRule(t *testing.T) {
	in := tools.ACLTestInput{Src: "tag:web", SSH: []tools.ACLSSHTestInput{{
		Dst: []string{"tag:db"}, Accept: []string{"root", "autogroup:nonroot"},
	}}}
	if err := in.Check(); err != nil {
		t.Fatal(err)
	}
	in.SSH[0].Accept = []string{"100.64.0.8"}
	if err := in.Check(); err != nil {
		t.Fatalf("an address-shaped SSH user: %v", err)
	}
	f, reg, env := apiEnv(t)
	serveSSH(f, "{}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}})
	})
	_, err := call(t, reg, env, "acl_test", `{"src":"tag:web","ssh":[{"dst":["tag:db"],"accept":["amy@example.com"]}]}`)
	if code(err) == tkerr.FilterRefused {
		t.Fatalf("an SSH user was filter_refused: %v", err)
	}
	if posts(f) != 1 {
		t.Fatalf("the user was refused before the request: %d POSTs, err %v", posts(f), err)
	}
}

// A call with only SSH tests masks the posture names of the policy too.
func TestPostureNamesOfAnSSHOnlyCallAreMasked(t *testing.T) {
	const login = "amy-zzzzqqqqmuchlongerlocalpart@example.com"
	f, reg, env := apiEnv(t)
	k, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		t.Fatal(err)
	}
	env.Privacy = k
	f.JSON("GET", tailnetPath+"/users", 200, `{"users":[{"id":"u1","loginName":"`+login+`","type":"member"}]}`)
	serveSSH(f, `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"],"srcPosture":["amy-zzzzqqqqmuchlongerlocalpart","`+login+`"]}]}`+"\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}})
	})
	var out tools.ACLTestOutput
	s := mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","ssh":[{"dst":["`+k.APIPseudonym(login)+`"],"accept":["root"]}]}`, &out)
	absent(t, s, "amy", "zzzz")
	if out.Posture != "gated" || len(out.PosturesNeeded) != 2 {
		t.Fatalf("posture %q, names %q", out.Posture, out.PosturesNeeded)
	}
}

// The SSH canary proves that sshTests ran, so it is read whole: its entry, its user, its
// destination and its form. An answer without it, or with another line in its place, or
// with two of it, proves nothing, and no verdict of the call may read as a pass.
func TestTheSSHCanaryIsCheckedWholeAndAnythingElseIsUnknownNeverAPass(t *testing.T) {
	canaryOf := func(tag, dst, user string) apitest.Entry {
		return sshFailedEntry(t, tag, dst, user)
	}
	for _, c := range []struct {
		name   string
		canary func(tag string) []apitest.Entry
	}{
		{"missing", func(string) []apitest.Entry { return nil }},
		{"unevaluable", func(tag string) []apitest.Entry {
			return []apitest.Entry{{User: tag, Errors: []string{"[acl test error]: user or host is invalid: tag not found"}}}
		}},
		{"another user", func(tag string) []apitest.Entry { return []apitest.Entry{canaryOf(tag, "192.0.2.1", "root")} }},
		{"another destination", func(tag string) []apitest.Entry { return []apitest.Entry{canaryOf(tag, "192.0.2.9", "canary")} }},
		{"a line of the tests form", func(tag string) []apitest.Entry {
			return []apitest.Entry{{User: tag, Errors: []string{canaryLine}}}
		}},
		{"doubled", func(tag string) []apitest.Entry {
			return []apitest.Entry{canaryOf(tag, "192.0.2.1", "canary"), canaryOf(tag, "192.0.2.1", "canary")}
		}},
		{"two lines", func(tag string) []apitest.Entry {
			e := canaryOf(tag, "192.0.2.1", "canary")
			return []apitest.Entry{{User: tag, Errors: append(e.Errors, e.Errors...)}}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, reg, env := apiEnv(t)
			serveSSHCanary(f, "{}\n", func(tag string) apitest.Shape {
				return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}})
			}, c.canary)
			var out tools.ACLTestOutput
			mustCall(t, reg, env, "acl_test", sshCall("tag:db", "root", "accept"), &out)
			if out.Status != "unknown" || out.ExitCode() != 1 {
				t.Fatalf("status %q, exit %d: %+v", out.Status, out.ExitCode(), out)
			}
			if len(out.SSHVerdicts) != 1 || out.SSHVerdicts[0].Verdict != "unknown" || out.SSHVerdicts[0].Why != "the SSH tests were not shown to have run" {
				t.Errorf("verdicts %+v: a canary that is not the canary left a verdict", out.SSHVerdicts)
			}
		})
	}
	// The control: the canary as the request carries it is taken off, and the verdict is read.
	f, reg, env := apiEnv(t)
	serveSSH(f, "{}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}})
	})
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", sshCall("tag:db", "root", "accept"), &out)
	if out.Status != "pass" || len(out.SSHVerdicts) != 1 || out.SSHVerdicts[0].Verdict != "allowed" {
		t.Errorf("the control: %+v", out)
	}
}

// A literal login as an SSH destination is refused before anything is sent, as it is as a
// source and as a destination of accept and deny, in every spelling the masker reads. Only
// personalData show passes it.
func TestALiteralLoginAsAnSSHDestinationIsRefusedBeforeAnyRequest(t *testing.T) {
	for _, dst := range []string{"bob@example.org", "BOB@EXAMPLE.ORG", "x bob@example.org", "bob%40example.org", "bob@example.org,carol@example.net"} {
		f, reg, env := apiEnv(t)
		serveSSH(f, "{}\n", func(tag string) apitest.Shape {
			return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}})
		})
		_, err := call(t, reg, env, "acl_test", sshCall(dst, "root", "accept"))
		if code(err) != tkerr.FilterRefused {
			t.Errorf("%q as an SSH destination: %v, want filter_refused", dst, err)
		}
		if len(f.Requests()) != 0 {
			t.Errorf("%q: %d requests were sent before the refusal", dst, len(f.Requests()))
		}
		if err != nil {
			absent(t, err.Error(), "bob", "BOB", "carol")
		}
	}
	f, reg, env := apiEnv(t)
	serveSSH(f, "{}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}})
	})
	env.Config = &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}
	if _, err := call(t, reg, env, "acl_test", sshCall("bob@example.org", "root", "accept")); err != nil {
		t.Errorf("with personalData show: %v", err)
	}
	if posts(f) != 1 {
		t.Errorf("with personalData show %d validation requests were sent, want 1", posts(f))
	}
}

// A user who is listed to be accepted in one test and denied in another, on one destination,
// gets the one line that belongs to the first: the other test does not read it as its own.
func TestALineOfAnAcceptTestIsNotTheAnswerOfADenyTestOfTheSameUser(t *testing.T) {
	f, reg, env := apiEnv(t)
	serveSSH(f, "{}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(
			apitest.Entry{User: tag, Errors: []string{canaryLine}},
			sshFailedEntry(t, "tag:db", "tag:db", "root"),
		)
	})
	args := `{"src":"tag:db","ssh":[{"dst":["tag:db"],"accept":["root"]},{"dst":["tag:db"],"deny":["root"]}]}`
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", args, &out)
	if len(out.SSHVerdicts) != 2 {
		t.Fatalf("%+v", out)
	}
	if v := out.SSHVerdicts[0]; v.Expect != "accept" || v.Verdict != "denied" {
		t.Errorf("the accept test: %+v", v)
	}
	if v := out.SSHVerdicts[1]; v.Expect != "deny" || v.Verdict != "unknown" || v.Why != "the lines for this SSH user do not agree" {
		t.Errorf("the deny test read a line that asked for an accept: %+v", v)
	}
	if out.Status != "unknown" {
		t.Errorf("status %q: a verdict that could not be read must not leave a fail or a pass", out.Status)
	}
}

// A check user that a line names, because an accept test of the same user holds the same
// destination, has an unknown verdict, in its own verdict and not only in the status: the
// form of a check failure was not seen, and a verdict that said allowed would be a claim.
func TestACheckUserWithALineHasAnUnknownVerdictWhateverTheStatusSays(t *testing.T) {
	f, reg, env := apiEnv(t)
	serveSSH(f, "{}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(
			apitest.Entry{User: tag, Errors: []string{canaryLine}},
			sshFailedEntry(t, "tag:db", "tag:db", "root"),
		)
	})
	args := `{"src":"tag:db","ssh":[{"dst":["tag:db"],"check":["root"]},{"dst":["tag:db"],"accept":["root"]}]}`
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", args, &out)
	if len(out.SSHVerdicts) != 2 {
		t.Fatalf("%+v", out)
	}
	if v := out.SSHVerdicts[0]; v.Expect != "check" || v.Verdict != "unknown" || v.Why != "a line of this SSH test is not in the grammar" {
		t.Errorf("a check user with a line: %+v", v)
	}
	if v := out.SSHVerdicts[1]; v.Expect != "accept" || v.Verdict != "denied" {
		t.Errorf("the accept user of the same line: %+v", v)
	}
	if out.Status != "unknown" {
		t.Errorf("status %q", out.Status)
	}
}

// More SSH verdicts are not as asked than the result lists: the headline counts them all.
func TestTheHeadlineCountsEverySSHVerdictNotAsAskedNotOnlyTheListedOnes(t *testing.T) {
	const bad = 300
	var entries []apitest.Entry
	for i := 0; i < bad; i++ {
		entries = append(entries, sshFailedEntry(t, "tag:ci", fmt.Sprintf("tag:t%d-d%02d", (i%256)/32, i%32), fmt.Sprintf("user%02d", i/256)))
	}
	f, reg, env := apiEnv(t)
	serveSSH(f, "{}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(append([]apitest.Entry{{User: tag, Errors: []string{canaryLine}}}, entries...)...)
	})
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", sshWideArgs(t), &out)
	if out.Status != "fail" || len(out.SSHVerdicts) != 256 || out.Omitted != 4096-256 {
		t.Fatalf("status %s, %d listed, %d omitted", out.Status, len(out.SSHVerdicts), out.Omitted)
	}
	if out.SSHNotAsked != bad {
		t.Errorf("sshNotAsked = %d, want %d", out.SSHNotAsked, bad)
	}
	if line := out.Report().Verdict; line != "FAILED · 300 SSH users not as asked" {
		t.Errorf("the headline counts the listed verdicts only: %q", line)
	}
}

// The SSH half of a call that also has destinations cannot run: the tests half was answered
// and its token is spent, so it is kept, and the SSH verdicts read unknown. The call is
// never a pass, and the status is the worse of the halves.
func TestACallWhoseSSHHalfCannotRunKeepsItsTestsHalf(t *testing.T) {
	const login = "amy@example.com"
	both := func(ref string) string {
		return `{"src":` + jsonString(ref) + `,"deny":["tag:web:22"],"ssh":[` + sshTest("tag:db", "root", "admin", "deploy") + `]}`
	}
	for name, c := range map[string]struct {
		testsHalf  apitest.Shape
		status     string
		exit       int
		wantErr    string
		sshHalf    func(w http.ResponseWriter)
		perMinute  int
		failedLine bool
	}{
		"rate limited, tests half passed": {testsHalf: apitest.TestsPass(), status: "unknown", exit: 1, wantErr: "validate_rate_limited", perMinute: 3},
		"rate limited, tests half failed": {testsHalf: apitest.TestsFailed(apitest.Entry{User: login, Errors: []string{`[acl test error]: address "tag:web:22" (protocol "tcp"): want: Drop, got: Accept`}}), status: "unknown", exit: 1, wantErr: "validate_rate_limited", perMinute: 3, failedLine: true},
		"the server failed, tests half passed": {testsHalf: apitest.TestsPass(), status: "unknown", exit: 1, wantErr: "policy_rejected_or_server_error", perMinute: 30,
			sshHalf: func(w http.ResponseWriter) { apitest.PolicyServerError500().Write(w) }},
	} {
		t.Run(name, func(t *testing.T) {
			f := apitest.New(t)
			servePolicy(f, "{}\n", `"e1"`)
			f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, login))
			f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if len(body) > 0 && body[0] == '[' {
					c.testsHalf.Write(w)
					return
				}
				if c.sshHalf == nil {
					t.Error("the SSH request was sent")
					return
				}
				c.sshHalf(w)
			})
			env, k := keyed(t, limitedEnv(t, f, c.perMinute))
			reg := newRegistry(t)
			var out tools.ACLTestOutput
			mustCall(t, reg, env, "acl_test", both(k.APIPseudonym(login)), &out)
			if out.Status != c.status || out.ExitCode() != c.exit || out.Status == "pass" {
				t.Fatalf("status %q, exit %d: %+v", out.Status, out.ExitCode(), out)
			}
			if !strings.HasPrefix(out.SSHError, c.wantErr+": ") {
				t.Errorf("sshError %q does not name %s", out.SSHError, c.wantErr)
			}
			absent(t, out.SSHError, login, "amy@")
			if len(out.Verdicts) != 1 || out.Verdicts[0].Dst != "tag:web:22" || out.Verdicts[0].Verdict == "unknown" {
				t.Errorf("the tests half was not kept: %+v", out.Verdicts)
			}
			if c.failedLine && (len(out.Failures) != 1 || out.Verdicts[0].Verdict != "allowed") {
				t.Errorf("the failure of the tests half was not kept: %+v %+v", out.Failures, out.Verdicts)
			}
			if len(out.SSHVerdicts) != 3 {
				t.Fatalf("%d SSH verdicts, want 3: %+v", len(out.SSHVerdicts), out.SSHVerdicts)
			}
			for _, v := range out.SSHVerdicts {
				if v.Verdict != "unknown" || v.Why != "the SSH tests were not shown to have run" {
					t.Errorf("an SSH verdict of a half that did not run: %+v", v)
				}
			}
			if out.SSHNotAsked != 3 || out.Report().Verdict != "UNKNOWN · the answer could not be established; this is not a pass" {
				t.Errorf("not asked %d, headline %q", out.SSHNotAsked, out.Report().Verdict)
			}
			found := false
			for _, fnd := range out.Report().Findings {
				found = found || strings.HasPrefix(fnd.Message, "the SSH tests did not run: "+c.wantErr)
			}
			if !found {
				t.Errorf("the report does not say why the SSH tests did not run: %+v", out.Report().Findings)
			}
		})
	}
	// Nothing was answered when the call is SSH only: the error is the result.
	f := apitest.New(t)
	serveBothHalves(f)
	env, k := keyed(t, limitedEnv(t, f, 2))
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, login))
	_, err := call(t, newRegistry(t), env, "acl_test", sshUsersCall(k.APIPseudonym(login), sshTest("tag:db", "a", "b", "c")))
	if code(err) != tkerr.ValidateRateLimited {
		t.Errorf("an SSH-only call that cannot run: %v", err)
	}
}

// With personalData show the owner asked to see, and what the caller typed comes back as it
// was typed.
func TestWithPersonalDataShownWhatTheCallerTypedComesBackAsTyped(t *testing.T) {
	f, reg, env := apiEnv(t)
	serveSSH(f, "{}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}})
	})
	env.Config = &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", sshCall("tag:db", "bob@example.org", "accept"), &out)
	if len(out.SSHVerdicts) != 1 || out.SSHVerdicts[0].User != "bob@example.org" {
		t.Errorf("%+v", out.SSHVerdicts)
	}
}
