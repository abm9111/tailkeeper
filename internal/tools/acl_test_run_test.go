package tools_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

func servePass(f *apitest.Fake) {
	f.ServeValidate(apitest.TestsPass())
	servePolicy(f, "{}\n", `"e1"`)
}

func TestAUnresolvableSourceIsUnresolvedNotAFailureAndExitsTwo(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.ServeValidate(apitest.TestUnevaluable("tag:missing"))
	servePolicy(f, "{}\n", `"e1"`)
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", `{"src":"tag:missing","accept":["tag:db:22"],"deny":["tag:web:80"]}`, &out)
	if out.Status != "unresolved" || out.ExitCode() != 2 {
		t.Fatalf("status %s, exit %d, want unresolved and 2", out.Status, out.ExitCode())
	}
	if len(out.Verdicts) != 2 {
		t.Fatalf("verdicts = %+v", out.Verdicts)
	}
	for _, v := range out.Verdicts {
		if v.Verdict != "unresolved" {
			t.Errorf("verdict %s is %s, want unresolved", v.Dst, v.Verdict)
		}
	}
}

func TestAMixedTestReportsEachDestinationAndExitsNineOnAnAssertion(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.ServeValidate(apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{
		`[acl test error]: address "tag:blocked:22" (protocol "tcp"): want: Accept, got: Drop`,
	}}))
	servePolicy(f, "{}\n", `"e1"`)
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","proto":"tcp","accept":["tag:blocked:22","tag:open:22"]}`, &out)
	if out.Status != "fail" || out.ExitCode() != 9 || len(out.Verdicts) != 2 || len(out.Failures) != 1 {
		t.Fatalf("%+v", out)
	}
	if out.Verdicts[0].Dst != "tag:blocked:22" || out.Verdicts[0].Verdict != "denied" || out.Verdicts[1].Verdict != "allowed" {
		t.Errorf("verdicts = %+v", out.Verdicts)
	}
	if len(out.Failures[0].Errors) != 1 || !strings.Contains(out.Failures[0].Errors[0], "tag:blocked:22") {
		t.Errorf("failures = %+v", out.Failures)
	}
}

func TestAPassHasVerdictsAndNoFailures(t *testing.T) {
	f, reg, env := apiEnv(t)
	servePass(f)
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:db:22"]}`, &out)
	if out.Status != "pass" || out.ExitCode() != 0 || len(out.Failures) != 0 || len(out.Verdicts) != 1 || out.Verdicts[0].Verdict != "allowed" {
		t.Fatalf("%+v", out)
	}
}

func TestAnUnmatchedLineIsUnknownAndExitsOne(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.ServeValidate(apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{
		`[acl test error]: address "tag:other:22" (protocol "tcp"): want: Accept, got: Drop`,
	}}))
	servePolicy(f, "{}\n", `"e1"`)
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:db:22"]}`, &out)
	if out.Status != "unknown" || out.ExitCode() != 1 || len(out.Unmatched) != 1 {
		t.Fatalf("status %s, exit %d, unmatched %v", out.Status, out.ExitCode(), out.Unmatched)
	}
	if len(out.Verdicts) != 1 || out.Verdicts[0].Verdict != "unknown" {
		t.Errorf("verdict = %+v", out.Verdicts)
	}
}

func TestOtherTestsAreReportedApartAndDoNotFailTheCall(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.ServeValidate(apitest.TestsFailed(apitest.Entry{User: "tag:stored", Errors: []string{
		`[acl test error]: address "tag:db:22" (protocol "tcp"): want: Accept, got: Drop`,
	}}))
	servePolicy(f, "{}\n", `"e1"`)
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:web:80"]}`, &out)
	if out.Status != "pass" || out.ExitCode() != 0 || len(out.Failures) != 0 || len(out.OtherTests) != 1 {
		t.Fatalf("status %s, failures %+v, other %+v", out.Status, out.Failures, out.OtherTests)
	}
	if out.OtherTests[0].Src != "tag:stored" || len(out.OtherTests[0].Errors) != 1 {
		t.Errorf("other = %+v", out.OtherTests)
	}
}

// The reply echoes the posted source in another case, or with a space at an edge, and its
// lines quote nothing the call asked about. It is not another test, and it is never a pass.
func TestAReplyForAnotherSpellingOfTheSourceIsUnknownThroughTheTool(t *testing.T) {
	for _, echoed := range []string{"TAG:CI", "tag:ci ", " tag:ci"} {
		f, reg, env := apiEnv(t)
		f.ServeValidate(apitest.TestsFailed(apitest.Entry{User: echoed, Errors: []string{
			`[acl test error]: address autogroup:internet:22: is not a valid address`,
		}}))
		servePolicy(f, "{}\n", `"e1"`)
		var out tools.ACLTestOutput
		mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:db:22"],"deny":["tag:web:80"]}`, &out)
		if out.Status != "unknown" || out.ExitCode() != 1 || len(out.OtherTests) != 0 || len(out.Unmatched) != 1 {
			t.Errorf("%q: status %s, exit %d, other %+v, unmatched %v", echoed, out.Status, out.ExitCode(), out.OtherTests, out.Unmatched)
		}
		for _, v := range out.Verdicts {
			if v.Verdict != "unknown" {
				t.Errorf("%q: verdict %+v, want unknown", echoed, v)
			}
		}
	}
}

func TestAPseudonymSourceAndDestinationAreResolvedAndTheLoginReachesOnlyTheRequest(t *testing.T) {
	const amy, bob = "ops/amy@example.com", "bob@example.org"
	f, reg, env := apiEnv(t)
	k, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		t.Fatal(err)
	}
	env.Privacy = k
	f.JSON("GET", tailnetPath+"/users", 200, `{"users":[{"id":"u1","loginName":"`+amy+`","type":"member"},{"id":"u2","loginName":"`+bob+`","type":"member"}]}`)
	f.ServeValidate(apitest.TestsFailed(apitest.Entry{User: amy, Errors: []string{
		`[acl test error]: address "` + bob + `:22" (protocol "tcp"): want: Accept, got: Drop`,
	}}))
	servePolicy(f, "{}\n", `"e1"`)
	args := `{"src":` + jsonString(k.APIPseudonym(amy)) + `,"accept":[` + jsonString(k.APIPseudonym(bob)+":22") + `]}`
	s, err := call(t, reg, env, "acl_test", args)
	if err != nil {
		t.Fatal(err)
	}
	body := postBody(t, f)
	if !strings.Contains(body, `"src":"`+amy+`"`) || !strings.Contains(body, bob+`:22`) {
		t.Fatalf("the request does not carry the logins: %s", body)
	}
	absent(t, s, "ops/", "amy@", "bob@")
	if !strings.Contains(s, "o…") || !strings.Contains(s, "b…@example.org") {
		t.Errorf("the masked forms are not in the result: %s", s)
	}
	var out tools.ACLTestOutput
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Verdicts) != 1 || out.Verdicts[0].Dst != k.APIPseudonym(bob)+":22" {
		t.Errorf("the destination is not the form the caller wrote: %+v", out.Verdicts)
	}
}

func TestASrcPostureAttrsMapIsSentAsGiven(t *testing.T) {
	f, reg, env := apiEnv(t)
	servePass(f)
	args := `{"src":"tag:ci","accept":["tag:db:22"],"srcPostureAttrs":{"node:os":"macos","node:n":3,"node:ok":true}}`
	if _, err := call(t, reg, env, "acl_test", args); err != nil {
		t.Fatal(err)
	}
	body := postBody(t, f)
	if !strings.Contains(body, `"node:os":"macos"`) || !strings.Contains(body, `"node:n":3`) || !strings.Contains(body, `"node:ok":true`) {
		t.Fatalf("attributes were not sent as given: %s", body)
	}
	f, reg, env = apiEnv(t)
	servePass(f)
	if _, err := call(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:db:22"]}`); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(postBody(t, f), "srcPostureAttrs") {
		t.Fatalf("an omitted map was sent: %s", postBody(t, f))
	}
}

func TestALiteralLoginIsFilterRefusedBeforeAnyRequestWhileMaskingAndAcceptedWithShow(t *testing.T) {
	f, reg, env := apiEnv(t)
	_, err := call(t, reg, env, "acl_test", `{"src":"amy@example.com","accept":["tag:db:22"]}`)
	if code(err) != tkerr.FilterRefused {
		t.Fatalf("masking: %v, want filter_refused", err)
	}
	if n := len(f.Requests()); n != 0 {
		t.Fatalf("%d requests, want none", n)
	}
	_, err = call(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["amy@example.com:22"]}`)
	if code(err) != tkerr.FilterRefused || len(f.Requests()) != 0 {
		t.Fatalf("destination: %v, requests %d", err, len(f.Requests()))
	}
	f, reg, env = apiEnv(t)
	servePass(f)
	shown := *env
	shown.Config = &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}
	if _, err := call(t, reg, &shown, "acl_test", `{"src":"amy@example.com","accept":["tag:db:22"]}`); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(postBody(t, f), `"src":"amy@example.com"`) {
		t.Fatalf("with personalData show the login was not sent: %s", postBody(t, f))
	}
}

func TestAReplyThatEchoesAResolvedLoginIsCutAfterMasking(t *testing.T) {
	results := map[int]string{}
	for _, n := range []int{3, 40} {
		login := "a" + strings.Repeat("m", n) + "@example.com"
		f, reg, env := apiEnv(t)
		k, err := privacy.Parse(strings.Repeat("5a", 32))
		if err != nil {
			t.Fatal(err)
		}
		env.Privacy = k
		f.JSON("GET", tailnetPath+"/users", 200, `{"users":[{"id":"u1","loginName":`+jsonString(login)+`,"type":"member"}]}`)
		line := login + " " + strings.Repeat("Z", 4000)
		f.ServeValidate(apitest.TestsFailed(apitest.Entry{User: login, Errors: []string{line}}))
		servePolicy(f, "{}\n", `"e1"`)
		ref := k.APIPseudonym(login)
		s, err := call(t, reg, env, "acl_test", `{"src":`+jsonString(ref)+`,"accept":["tag:db:22"]}`)
		if err != nil {
			t.Fatal(err)
		}
		absent(t, s, login, "mmm")
		results[n] = s
	}
	if results[3] != results[40] {
		t.Errorf("the result tells the length of a login:\n%.400s\n%.400s", results[3], results[40])
	}
	if !strings.Contains(results[3], "a…@example.com") || !strings.Contains(results[3], "Z") {
		t.Fatalf("the masked line is not in the result: %s", results[3])
	}
}

func postBody(t *testing.T, f *apitest.Fake) string {
	t.Helper()
	for _, r := range f.Requests() {
		if r.Method == "POST" {
			return string(r.Body)
		}
	}
	t.Fatal("no POST")
	return ""
}
