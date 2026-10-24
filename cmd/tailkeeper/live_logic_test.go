package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abm9111/tailkeeper/internal/probe"
)

// These tests exercise the logic around the live calls (how an outcome is named,
// what the checks find, how an ID is found, what scripts/live-check.sh refuses)
// without the network and without a tailnet, so `make verify` runs them. None of
// them is named TestLive…, which is what `make live` selects: the live run counts
// exactly three passes (TestLiveReads, TestLiveMCP and TestLivePolicy).

// stubBinary writes a POSIX shell script that stands in for the tailkeeper binary.
func stubBinary(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in binary is a POSIX shell script")
	}
	path := filepath.Join(t.TempDir(), "tailkeeper")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

var stubEnv = []string{"PATH=/usr/bin:/bin"}

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }

func TestOutcomeOf(t *testing.T) {
	listed := map[string]bool{"network_flow_logs": true}
	cases := []struct {
		name, tool, code string
		uncovered        map[string]bool
		want             string
	}{
		{"scope error, listed", "network_flow_logs", "scope_missing", listed, outcomeUnavailable},
		{"plan error, listed", "network_flow_logs", "feature_unavailable", listed, outcomeUnavailable},
		{"payment error, listed", "network_flow_logs", "payment_required", listed, outcomeUnavailable},
		{"scope error, not listed", "devices_list", "scope_missing", listed, outcomeFail},
		{"scope error, nothing listed", "network_flow_logs", "scope_missing", nil, outcomeFail},
		{"scope error, empty list", "network_flow_logs", "scope_missing", map[string]bool{}, outcomeFail},
		{"another code, listed", "network_flow_logs", "api_error", listed, outcomeFail},
		{"no code, listed", "network_flow_logs", "", listed, outcomeFail},
		{"validation, listed", "network_flow_logs", "validation_failed", listed, outcomeFail},
	}
	for _, c := range cases {
		if got := outcomeOf(c.tool, c.code, c.uncovered); got != c.want {
			t.Errorf("%s: outcome %q, want %q", c.name, got, c.want)
		}
	}
}

// TestNoToolPassesAsUnavailableUnlessListed is the D-03 rule over the whole
// registry: whichever tool a coverage error comes from, it is a failure unless that
// very tool is listed, and a listed tool excuses only coverage errors.
func TestNoToolPassesAsUnavailableUnlessListed(t *testing.T) {
	all := liveRegistry().All()
	if len(all) == 0 {
		t.Fatal("the registry holds no tools, so nothing was checked")
	}
	for _, tool := range all {
		name := tool.Meta.Name
		for code := range coverageCodes {
			if got := outcomeOf(name, code, nil); got != outcomeFail {
				t.Errorf("%s, %s, nothing listed: %q", name, code, got)
			}
			if got := outcomeOf(name, code, map[string]bool{"some_other_tool": true}); got != outcomeFail {
				t.Errorf("%s, %s, another tool listed: %q", name, code, got)
			}
			if got := outcomeOf(name, code, map[string]bool{name: true}); got != outcomeUnavailable {
				t.Errorf("%s, %s, listed: %q", name, code, got)
			}
		}
		if got := outcomeOf(name, "upstream_unavailable", map[string]bool{name: true}); got != outcomeFail {
			t.Errorf("%s: a listed tool's non-coverage error was %q", name, got)
		}
	}
}

func TestParseUncovered(t *testing.T) {
	known := func(s string) bool { return s == "network_flow_logs" || s == "oauth_apps_list" }
	set, unknown := parseUncovered(" network_flow_logs, oauth_apps_list ,,", known)
	if len(set) != 2 || !set["network_flow_logs"] || !set["oauth_apps_list"] || len(unknown) != 0 {
		t.Errorf("set %v, unknown %v", set, unknown)
	}
	set, unknown = parseUncovered("", known)
	if len(set) != 0 || len(unknown) != 0 {
		t.Errorf("an empty list gave set %v, unknown %v", set, unknown)
	}
	set, unknown = parseUncovered("network_flow_logs,zeta,alpha", known)
	if len(set) != 1 || strings.Join(unknown, ",") != "alpha,zeta" {
		t.Errorf("a typo must be reported, not dropped: set %v, unknown %v", set, unknown)
	}
	// The names the real registry holds are accepted.
	reg := liveRegistry()
	set, unknown = parseUncovered("network_flow_logs,oauth_apps_list,oauth_app_get", func(s string) bool { _, ok := reg.Get(s); return ok })
	if len(set) != 3 || len(unknown) != 0 {
		t.Errorf("the documented list: set %v, unknown %v", set, unknown)
	}
}

func TestSafeCode(t *testing.T) {
	for in, want := range map[string]string{"scope_missing": "scope_missing", "": "", "Scope": "unrecognised",
		"a b": "unrecognised", "x\ny": "unrecognised", strings.Repeat("a", 41): "unrecognised"} {
		if got := safeCode(in); got != want {
			t.Errorf("safeCode(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestChecksFindPlantedProblems plants what the checks exist to find, so a clean
// result means something: each check is shown to fire before a zero is believed.
func TestChecksFindPlantedProblems(t *testing.T) {
	const name, email = "Pat Example", "pat@example.com"
	credential := "tskey" + "-auth-" + strings.Repeat("A", 12)
	personal := []string{"devices[].user"}

	cases := []struct {
		name string
		raw  string
		want int
	}{
		{"unmasked personal field", `{"devices":[{"user":"` + name + `"}]}`, 1},
		{"whole email in a personal field", `{"devices":[{"user":"` + email + `"}]}`, 2},
		{"whole email in free text", `{"devices":[{"user":"P…","name":"` + email + `"}]}`, 1},
		{"one-character local part", `{"devices":[{"user":"P…","name":"a@example.com"}]}`, 1},
		{"credential shape", `{"devices":[{"user":"P…","name":"` + credential + `"}]}`, 1},
		{"masked", `{"devices":[{"user":"P…@example.com"}]}`, 0},
		{"masked with a pseudonym", `{"devices":[{"user":"P…@example.com [p:k7x2m9qd4a]"}]}`, 0},
		{"masked name", `{"devices":[{"user":"P…"}]}`, 0},
		{"tagged devices", `{"devices":[{"user":"tagged-devices"},{"user":"Tagged Devices"},{"user":""}]}`, 0},
	}
	for _, c := range cases {
		var doc map[string]any
		if err := jsonUnmarshal(c.raw, &doc); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		problems, _ := checks([]byte(c.raw), doc, personal)
		if len(problems) != c.want {
			t.Errorf("%s: %d problems %q, want %d", c.name, len(problems), problems, c.want)
		}
		for _, p := range problems {
			// A problem names a path or a kind, never the value.
			for _, secret := range []string{name, email, credential, "a@example.com"} {
				if strings.Contains(p, secret) {
					t.Errorf("%s: a problem repeats the value: %q", c.name, p)
				}
			}
		}
	}
}

func TestValuesAt(t *testing.T) {
	var doc map[string]any
	if err := jsonUnmarshal(`{"devices":[{"user":"a"},{"user":"b"},{"x":1}],"account":{"email":"c"},
		"entries":[{"actor":{"loginName":"d"}},{"actor":null}],"names":["e","f"]}`, &doc); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		"devices[].user":            "a,b",
		"account.email":             "c",
		"entries[].actor.loginName": "d",
		"names":                     "e,f",
		"missing.path":              "",
		"devices[].missing":         "",
		"account.email.deeper":      "",
	} {
		if got := strings.Join(valuesAt(doc, path), ","); got != want {
			t.Errorf("valuesAt(%q) = %q, want %q", path, got, want)
		}
	}
	if got := valuesAt(nil, "devices[].user"); got != nil {
		t.Errorf("valuesAt(nil) = %v", got)
	}
}

func TestDiscovery(t *testing.T) {
	var doc map[string]any
	if err := jsonUnmarshal(`{"devices":[{"id":"1"},{"nodeId":"n1CNTRL"},{"nodeId":"n2CNTRL"}],"empty":[],
		"addresses":["","100.64.0.1"],"self":{"dnsName":"node.example.ts.net."}}`, &doc); err != nil {
		t.Fatal(err)
	}
	if d := pick(doc, "devices", "nodeId"); d.id != "n1CNTRL" || d.rows != 3 {
		t.Errorf("pick = %+v", d)
	}
	if d := pick(doc, "devices", "name"); d.id != "" || d.rows != 3 {
		t.Errorf("a path that finds nothing must still count its rows: %+v", d)
	}
	if d := pick(doc, "empty", "nodeId"); d.id != "" || d.rows != 0 {
		t.Errorf("an empty list = %+v", d)
	}
	if d := pick(doc, "absent", "nodeId"); d.rows != 0 {
		t.Errorf("an absent list = %+v", d)
	}
	if d := pick(nil, "devices", "nodeId"); d != (discovery{}) {
		t.Errorf("no result = %+v", d)
	}
	if d := pickString(doc, "addresses"); d.id != "100.64.0.1" || d.rows != 2 {
		t.Errorf("pickString = %+v", d)
	}
	if d := selfDNSName(doc); d.id != "node.example.ts.net." || d.rows != 1 {
		t.Errorf("selfDNSName = %+v", d)
	}
	if d := selfDNSName(map[string]any{}); d.id != "" || d.rows != 1 {
		t.Errorf("a status with no self name must count as a candidate that found nothing: %+v", d)
	}
	if d := selfDNSName(nil); d != (discovery{}) {
		t.Errorf("no status = %+v", d)
	}

	status := func(peers string) map[string]any {
		var s map[string]any
		if err := jsonUnmarshal(`{"peers":`+peers+`}`, &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	cases := []struct {
		name  string
		peers string
		want  discovery
	}{
		{"an online peer", `[{"online":false,"tailscaleIps":["100.64.0.9"]},{"online":true,"tailscaleIps":["100.64.0.2","fd7a::2"]}]`, discovery{"100.64.0.2", 1}},
		{"nobody online", `[{"online":false,"tailscaleIps":["100.64.0.9"]}]`, discovery{"", 0}},
		{"no peers", `[]`, discovery{"", 0}},
		{"online with no address", `[{"online":true,"tailscaleIps":[]}]`, discovery{"", 1}},
		{"peers that never say", `[{"tailscaleIps":["100.64.0.9"]},{"status":"up"}]`, discovery{"", 2}},
	}
	for _, c := range cases {
		if got := onlinePeer(status(c.peers)); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
	if got := onlinePeer(nil); got != (discovery{}) {
		t.Errorf("no status = %+v", got)
	}
}

// TestGetWithoutAnIDIsNoneOnlyWithoutCandidates is the guard against a discovery
// path that silently yields no IDs: with candidates and no ID it is a failure.
func TestGetWithoutAnIDIsNoneOnlyWithoutCandidates(t *testing.T) {
	l := newLiveRun("/nonexistent/tailkeeper", nil, nil)
	l.get("device_get", discovery{})
	l.get("user_get", discovery{rows: 4})
	if len(l.results) != 2 || l.calls != 0 {
		t.Fatalf("results %+v, calls %d", l.results, l.calls)
	}
	if r := l.results[0]; r.tool != "device_get" || r.outcome != outcomeNone {
		t.Errorf("no candidates: %+v", r)
	}
	if r := l.results[1]; r.tool != "user_get" || r.outcome != outcomeFail || r.code != "no_id" {
		t.Errorf("candidates and no ID: %+v", r)
	}
	if len(l.problems) != 1 || !strings.HasPrefix(l.problems[0], "user_get: ") {
		t.Errorf("problems %q", l.problems)
	}
	if !l.ran["device_get"] || !l.ran["user_get"] {
		t.Error("both tools count as exercised")
	}
}

// TestIDsAreNeverReadAsFlags runs the real binary: "--" before the ID reaches the
// tool's argument, so an ID that starts with a dash is not a flag either. With no
// configuration the call stops at config_missing, after the arguments parsed.
func TestIDsAreNeverReadAsFlags(t *testing.T) {
	for _, id := range []string{"n1CNTRL", "-x", "--json"} {
		stdout, _, code := run(t, "--json", "devices", "get", "--", id)
		if code != 6 || !strings.Contains(stdout, "config_missing") {
			t.Errorf("id %q: exit %d, stdout %q", id, code, stdout)
		}
	}
}

// TestHarnessWithNothingToAnswer runs the whole harness against the real binary
// with an empty home, a credential provider that has no credential, and a Tailscale
// CLI that always fails: no tool can answer. Every call must be a failure; none may
// read as ok, unavailable or skipped, and no tool may be left out. The CLI is a
// stand-in on purpose: local tools need no configuration, so without it they would
// run against the Tailscale on whichever machine runs the gate.
func TestHarnessWithNothingToAnswer(t *testing.T) {
	failing := stubBinary(t, "exit 1\n")
	env := isolated(t)
	writeConfig(t, env, `{"contexts": {"e2e": {"tailnetId": "T1234CNTRL", "credentials": {"read": {"provider": "env"}}}},
		"local": {"tailscaleBinary": `+strconv.Quote(failing)+`}}`)
	l := newLiveRun(bin, env, nil)
	l.all()
	counts := l.counts()
	if total := len(l.results); total != len(liveRegistry().All()) {
		t.Errorf("%d results for %d tools", total, len(liveRegistry().All()))
	}
	if counts[outcomeOK] != 0 || counts[outcomeUnavailable] != 0 {
		t.Errorf("with nothing to answer, %d ok and %d unavailable", counts[outcomeOK], counts[outcomeUnavailable])
	}
	if counts[outcomeFail] == 0 || counts[outcomeFail] != l.calls {
		t.Errorf("%d fail for %d calls", counts[outcomeFail], l.calls)
	}
	for _, r := range l.results {
		if r.outcome == outcomeFail && r.code != "credential_unavailable" && !strings.HasPrefix(r.code, "local_") {
			t.Errorf("%s failed with code %q, want credential_unavailable or a local_ code", r.tool, r.code)
		}
	}
	if len(l.problems) < counts[outcomeFail] {
		t.Errorf("%d problems for %d failures", len(l.problems), counts[outcomeFail])
	}
	for _, name := range []string{"devices_list", "local_status", "acl_test", "oauth_apps_list", "network_flow_logs"} {
		if !l.ran[name] {
			t.Errorf("%s was not run", name)
		}
	}
}

// TestHarnessCredentialWithoutScope is the D-03 rule through the whole harness
// (preflight D-03): a credential that no tool accepts answers every call with
// scope_missing. Unless the owner lists a tool, that is a failure.
func TestHarnessCredentialWithoutScope(t *testing.T) {
	stub := stubBinary(t, `printf '{"error":{"code":"scope_missing","message":"m","hint":"h"}}\n'
exit 5
`)
	var every []string
	for _, tool := range liveRegistry().All() {
		every = append(every, tool.Meta.Name)
	}

	none := newLiveRun(stub, stubEnv, nil)
	none.all()
	c := none.counts()
	if c[outcomeOK] != 0 || c[outcomeUnavailable] != 0 {
		t.Errorf("nothing listed: %d ok, %d unavailable", c[outcomeOK], c[outcomeUnavailable])
	}
	if c[outcomeFail] == 0 || c[outcomeFail] != none.calls || len(none.problems) < none.calls {
		t.Errorf("nothing listed: %d fail, %d calls, %d problems", c[outcomeFail], none.calls, len(none.problems))
	}

	set, unknown := parseUncovered(strings.Join(every, ","), func(s string) bool { _, ok := liveRegistry().Get(s); return ok })
	if len(unknown) != 0 {
		t.Fatalf("unknown %v", unknown)
	}
	all := newLiveRun(stub, stubEnv, set)
	all.all()
	c = all.counts()
	// The doctor probe is not a tool: the scope error it meets is its own failure.
	const doctorFailure = `doctor: probe printed an error document, code "scope_missing" (exit 5)`
	if c[outcomeFail] != 0 || len(all.problems) != 1 || all.problems[0] != doctorFailure || c[outcomeUnavailable] != all.calls || c[outcomeOK] != 0 {
		t.Errorf("every tool listed: %d fail, %d unavailable, problems %q, %d calls", c[outcomeFail], c[outcomeUnavailable], all.problems, all.calls)
	}

	one := newLiveRun(stub, stubEnv, map[string]bool{"network_flow_logs": true})
	one.all()
	c = one.counts()
	if c[outcomeUnavailable] != 1 || c[outcomeFail] != one.calls-1 {
		t.Errorf("one tool listed: %d unavailable, %d fail, %d calls", c[outcomeUnavailable], c[outcomeFail], one.calls)
	}
}

// TestHarnessFailsWhenDiscoveryFindsNoID: the list answers with rows that carry no
// nodeId. Every tool named from them fails, instead of reading as "none" and passing.
func TestHarnessFailsWhenDiscoveryFindsNoID(t *testing.T) {
	log := filepath.Join(t.TempDir(), "calls")
	stub := stubBinary(t, `echo "$*" >> "$STUB_LOG"
case "$*" in
"--json devices list") printf '{"devices":[{"id":"1"}]}\n' ;;
"--json users list") printf '{"users":[{"id":"u1"}]}\n' ;;
*) printf '{}\n' ;;
esac
`)
	l := newLiveRun(stub, append([]string{"STUB_LOG=" + log}, stubEnv...), nil)
	l.all()
	byTool := map[string]liveOutcome{}
	for _, r := range l.results {
		byTool[r.tool] = r
	}
	for _, name := range []string{"device_get", "device_routes", "device_posture_attributes", "device_invites_list", "local_dns_query"} {
		if r := byTool[name]; r.outcome != outcomeFail || r.code != "no_id" {
			t.Errorf("%s = %+v, want a no_id failure", name, r)
		}
	}
	// Empty answers are the tailnet having nothing to name: none, not a failure.
	for _, name := range []string{"key_get", "webhook_get", "device_invite_get", "local_ping", "local_whois"} {
		if r := byTool[name]; r.outcome != outcomeNone {
			t.Errorf("%s = %+v, want none", name, r)
		}
	}
	// A tool named from a list that did carry an ID was called with it, after "--".
	if r := byTool["user_get"]; r.outcome != outcomeOK {
		t.Errorf("user_get = %+v", r)
	}
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "--json users get -- u1\n") {
		t.Errorf("user_get was not called with its ID after --:\n%s", b)
	}
	if strings.Contains(string(b), "devices get") {
		t.Error("device_get was called without an ID")
	}
}

// TestHarnessRunsTheTwoPolicyToolsWithTheSmallestHonestCalls: acl_validate is called with
// no argument, so it validates the live policy, and acl_diff is called against a file that
// holds an empty object, which the harness writes for the call and removes after it. Each
// answers as its tool does when the policy is as it should be.
func TestHarnessRunsTheTwoPolicyToolsWithTheSmallestHonestCalls(t *testing.T) {
	dir := t.TempDir()
	calls, kept := filepath.Join(dir, "calls"), filepath.Join(dir, "against")
	stub := stubBinary(t, `echo "$*" >> "$STUB_LOG"
case "$*" in
"--json acl validate") printf '{"status":"pass","serverChecked":true}\n' ;;
"--json acl diff --against "*) cat "$5" > "$STUB_AGAINST"; echo "$5" >> "$STUB_LOG"; printf '{"status":"equal"}\n' ;;
*) printf '{}\n' ;;
esac
`)
	l := newLiveRun(stub, append([]string{"STUB_LOG=" + calls, "STUB_AGAINST=" + kept}, stubEnv...), nil)
	l.all()
	log, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(log)), "\n")
	var diffAt int
	for i, line := range lines {
		if strings.HasPrefix(line, "--json acl diff --against ") {
			diffAt = i
		}
	}
	if !slices.Contains(lines, "--json acl validate") || diffAt == 0 || len(lines) <= diffAt+1 {
		t.Fatalf("the calls were:\n%s", log)
	}
	if document, err := os.ReadFile(kept); err != nil || string(document) != "{}\n" {
		t.Errorf("acl_diff was given %q (%v), want an empty object", document, err)
	}
	if _, err := os.Stat(lines[diffAt+1]); !os.IsNotExist(err) {
		t.Errorf("the file given to acl_diff is still there: %v", err)
	}
	byTool := map[string]liveOutcome{}
	for _, r := range l.results {
		byTool[r.tool] = r
	}
	for _, name := range []string{"acl_validate", "acl_diff"} {
		if r := byTool[name]; r.outcome != outcomeOK {
			t.Errorf("%s = %+v, want an answer", name, r)
		}
	}
}

// TestACLTestFailureIsAnAnswer: acl_test exits 9 when the policy answers that the
// test fails. That is the tool working, not the tool failing.
func TestACLTestFailureIsAnAnswer(t *testing.T) {
	stub := stubBinary(t, `case "$*" in
"--json acl test"*) printf '{"status":"fail","evaluatedAt":"2026-10-13T00:00:00Z","note":"n"}\n'; exit 9 ;;
*) printf '{}\n' ;;
esac
`)
	l := newLiveRun(stub, stubEnv, nil)
	l.call("acl_test", "203.0.113.5", "--deny", "198.51.100.7:1")
	if len(l.results) != 1 || l.results[0].outcome != outcomeOK || len(l.problems) != 0 {
		t.Errorf("results %+v, problems %q", l.results, l.problems)
	}
	// A tool whose output carries no exit status is not excused by a non-zero exit.
	bad := stubBinary(t, `printf '{}\n'
exit 9
`)
	l = newLiveRun(bad, stubEnv, nil)
	l.call("dns_get")
	if len(l.results) != 1 || l.results[0].outcome != outcomeFail || len(l.problems) != 1 {
		t.Errorf("results %+v, problems %q", l.results, l.problems)
	}
}

// TestChecksCountWhatTheyExamine: the live log shows how many personal values the
// masking check looked at, so a path that matches nothing cannot pass unseen.
func TestChecksCountWhatTheyExamine(t *testing.T) {
	var doc map[string]any
	raw := `{"devices":[{"user":"P…"},{"user":""},{"user":"tagged-devices"},{"user":"Pat Example"},{"user":"Sam Example"}]}`
	if err := jsonUnmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	problems, examined := checks([]byte(raw), doc, []string{"devices[].user"})
	if examined != 4 {
		t.Errorf("%d values examined, want 4 (the empty one is not a value)", examined)
	}
	if len(problems) != 1 {
		t.Errorf("%d problems %q, want one for the path, not one per value", len(problems), problems)
	}
	// A path that matches nothing (a wrong name) examines nothing, and says so.
	if problems, examined := checks([]byte(raw), doc, []string{"devices[].owner", "people[].user"}); examined != 0 || len(problems) != 0 {
		t.Errorf("a path that matches nothing: %d examined, problems %q", examined, problems)
	}
	if _, examined := checks([]byte(`{}`), map[string]any{}, nil); examined != 0 {
		t.Errorf("no personal paths: %d examined", examined)
	}
}

// docStub is a stand-in binary that prints $STUB_DOC and exits with $STUB_EXIT; the
// environment docEnv builds says which, so one file serves every case of a test.
func docStub(t *testing.T) string {
	t.Helper()
	return stubBinary(t, "printf '%s\\n' \"$STUB_DOC\"\nexit \"$STUB_EXIT\"\n")
}

func docEnv(doc string, exit int) []string {
	return append([]string{"STUB_DOC=" + doc, "STUB_EXIT=" + strconv.Itoa(exit)}, stubEnv...)
}

// TestAnErrorDocumentThatExitsZeroIsAProblem: a tool that prints an error document
// and exits 0 contradicts itself. Even when the owner listed the tool as not covered,
// that is a failure, not "unavailable".
func TestAnErrorDocumentThatExitsZeroIsAProblem(t *testing.T) {
	const doc = `{"error":{"code":"scope_missing","message":"m"}}`
	listed := map[string]bool{"devices_list": true}

	// The control: the same document with the exit status an error has is unavailable.
	stub := docStub(t)
	l := newLiveRun(stub, docEnv(doc, 5), listed)
	l.call("devices_list")
	if r := l.results[0]; r.outcome != outcomeUnavailable || len(l.problems) != 0 {
		t.Fatalf("control: %+v, problems %q", r, l.problems)
	}

	l = newLiveRun(stub, docEnv(doc, 0), listed)
	l.call("devices_list")
	if r := l.results[0]; r.outcome != outcomeFail || r.code != "scope_missing" {
		t.Errorf("an error document and exit 0: %+v", r)
	}
	if len(l.problems) != 1 || !strings.Contains(l.problems[0], "exited 0") {
		t.Errorf("problems %q", l.problems)
	}
}

// TestACredentialShapeInAnErrorDocumentIsCaught: errors are output too. A credential
// shape or a whole address in one fails the call, whatever its code and whether or
// not the owner listed the tool as not covered.
func TestACredentialShapeInAnErrorDocumentIsCaught(t *testing.T) {
	listed := map[string]bool{"devices_list": true}
	errorDoc := func(message string) string {
		return `{"error":{"code":"scope_missing","message":"` + message + `"}}`
	}

	stub := docStub(t)
	l := newLiveRun(stub, docEnv(errorDoc("m"), 5), listed)
	l.call("devices_list")
	if r := l.results[0]; r.outcome != outcomeUnavailable || len(l.problems) != 0 {
		t.Fatalf("control: %+v, problems %q", r, l.problems)
	}

	credential := "tskey" + "-auth-" + strings.Repeat("A", 12)
	for name, c := range map[string]struct{ message, want, secret string }{
		"a credential shape": {credential, "the tripwire matched the output", credential},
		"a whole address":    {"pat@example.com", "1 whole email addresses", "pat@example.com"},
	} {
		l := newLiveRun(stub, docEnv(errorDoc(c.message), 5), listed)
		l.call("devices_list")
		if r := l.results[0]; r.outcome != outcomeFail {
			t.Errorf("%s: outcome %q, want fail", name, r.outcome)
		}
		if len(l.problems) != 1 || !strings.Contains(l.problems[0], c.want) {
			t.Errorf("%s: problems %q, want %q", name, l.problems, c.want)
		}
		for _, p := range l.problems {
			if strings.Contains(p, c.secret) {
				t.Errorf("%s: a problem repeats the value: %q", name, p)
			}
		}
	}
}

// TestAnExitMustBeTheOneTheResultSays: a result is an answer only when the process
// exited as the result says. acl_test's output carries its own status (fail is 9);
// every other tool's is 0. A crash that exits 1 yet still prints a document fails.
func TestAnExitMustBeTheOneTheResultSays(t *testing.T) {
	const (
		failing = `{"status":"fail","evaluatedAt":"2026-10-13T00:00:00Z","note":"n"}`
		passing = `{"status":"pass","evaluatedAt":"2026-10-13T00:00:00Z","note":"n"}`
	)
	cases := []struct {
		name, tool, doc string
		exit            int
		outcome, code   string
	}{
		{"a failing test exits 9", "acl_test", failing, 9, outcomeOK, ""},
		{"a passing test exits 0", "acl_test", passing, 0, outcomeOK, ""},
		{"a crash exits 1 after printing a failing result", "acl_test", failing, 1, outcomeFail, "exit_mismatch"},
		{"a failing test exits 0", "acl_test", failing, 0, outcomeFail, "exit_mismatch"},
		{"a passing test exits 9", "acl_test", passing, 9, outcomeFail, "exit_mismatch"},
		{"a result that does not decode", "acl_test", `{"status":["fail"]}`, 0, outcomeFail, "undecodable"},
		{"an ordinary tool exits 0", "dns_get", `{}`, 0, outcomeOK, ""},
		{"an ordinary tool exits 1 with a result", "dns_get", `{}`, 1, outcomeFail, "exit_mismatch"},
		{"an ordinary tool exits 9 with a result", "dns_get", `{}`, 9, outcomeFail, "exit_mismatch"},
	}
	stub := docStub(t)
	for _, c := range cases {
		l := newLiveRun(stub, docEnv(c.doc, c.exit), nil)
		l.call(c.tool)
		if len(l.results) != 1 || l.results[0].outcome != c.outcome || l.results[0].code != c.code {
			t.Errorf("%s: results %+v", c.name, l.results)
		}
		if (c.outcome == outcomeFail) != (len(l.problems) > 0) {
			t.Errorf("%s: problems %q", c.name, l.problems)
		}
	}
}

// TestEveryToolMustBeExercised is the guard against a tool that the run leaves out:
// one added to the registry with no line in liveRun.all, or run twice.
func TestEveryToolMustBeExercised(t *testing.T) {
	complete := func() *liveRun {
		l := newLiveRun("/nonexistent/tailkeeper", nil, nil)
		for _, tool := range l.reg.All() {
			l.ran[tool.Meta.Name] = true
			l.results = append(l.results, liveOutcome{tool: tool.Meta.Name, outcome: outcomeNone})
		}
		return l
	}
	total := len(liveRegistry().All())

	l := complete()
	l.verifyCoverage()
	if len(l.problems) != 0 {
		t.Errorf("a complete run: problems %q", l.problems)
	}

	l = newLiveRun("/nonexistent/tailkeeper", nil, nil)
	l.verifyCoverage()
	if len(l.problems) != total+1 {
		t.Errorf("a run that did nothing: %d problems for %d tools", len(l.problems), total)
	}

	l = complete()
	delete(l.ran, "dns_get")
	l.results = l.results[:len(l.results)-1]
	l.verifyCoverage()
	if len(l.problems) != 2 || !slices.ContainsFunc(l.problems, func(p string) bool {
		return strings.HasPrefix(p, "dns_get: was not exercised")
	}) {
		t.Errorf("one tool left out: problems %q", l.problems)
	}

	l = complete()
	l.results = append(l.results, liveOutcome{tool: "dns_get", outcome: outcomeNone})
	l.verifyCoverage()
	if len(l.problems) != 1 || !strings.Contains(l.problems[0], "results for") {
		t.Errorf("one tool run twice: problems %q", l.problems)
	}
}

// TestAuditGrowthIsALowerBound: the audit log must grow by at least one line per
// call. More is fine, since the owner's own MCP server can append during the run.
func TestAuditGrowthIsALowerBound(t *testing.T) {
	cases := []struct {
		before, after, calls int
		problem              bool
	}{
		{10, 38, 28, false},
		{10, 40, 28, false}, // another process appended too
		{10, 37, 28, true},
		{10, 10, 1, true},
		{10, 5, 1, true}, // the log was cut or rotated
		{10, 10, 0, false},
	}
	for _, c := range cases {
		got := auditGrowthProblem(c.before, c.after, c.calls)
		if (got != "") != c.problem {
			t.Errorf("before %d, after %d, %d calls: %q", c.before, c.after, c.calls, got)
		}
	}
	if got := auditGrowthProblem(10, 37, 28); got != "the audit log grew by 27 lines for 28 calls" {
		t.Errorf("message %q", got)
	}
}

// TestCheckDevicesResult is the check on devices_list over MCP: what it finds in a
// result, and that it does so by the registry's own list of personal fields.
func TestCheckDevicesResult(t *testing.T) {
	tool, ok := liveRegistry().Get("devices_list")
	if !ok || !slices.Contains(tool.PersonalFields, "devices[].user") {
		t.Fatalf("devices_list personal fields: %v", tool.PersonalFields)
	}
	device := func(user string) map[string]any {
		return map[string]any{"devices": []any{map[string]any{"nodeId": "n1CNTRL", "user": user}}}
	}
	cases := []struct {
		name string
		res  *mcp.CallToolResult
		want []string
	}{
		{"masked", &mcp.CallToolResult{StructuredContent: device("P…@example.com [p:k7x2m9qd4a]")}, nil},
		{"unmasked", &mcp.CallToolResult{StructuredContent: device("Pat Example")}, []string{"the personal field devices[].user is not masked"}},
		{"a tool error", &mcp.CallToolResult{IsError: true, StructuredContent: map[string]any{"error": map[string]any{"code": "scope_missing"}}},
			[]string{`returned a tool error, code "scope_missing"`}},
		{"an error with a code that is not one", &mcp.CallToolResult{IsError: true, StructuredContent: map[string]any{"error": map[string]any{"code": "Pat Example"}}},
			[]string{`returned a tool error, code "unrecognised"`}},
		{"no structured result", &mcp.CallToolResult{}, []string{"the result is not one JSON document"}},
		{"not a document", &mcp.CallToolResult{StructuredContent: []any{"x"}}, []string{"the result is not one JSON document"}},
	}
	for _, c := range cases {
		got, size, examined := checkDevicesResult(c.res)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
		if c.want == nil && size == 0 {
			t.Errorf("%s: no size", c.name)
		}
		if c.name == "masked" || c.name == "unmasked" {
			if examined != 1 {
				t.Errorf("%s: %d personal values examined, want 1", c.name, examined)
			}
		}
	}
}

// TestMCPSessionAgainstTheBinary runs the live MCP session's own steps (start the
// server, list its tools, call devices_list) against the real binary with an empty
// home: devices_list answers config_missing, and the check names that code.
func TestMCPSessionAgainstTheBinary(t *testing.T) {
	advertised, res := mcpDevicesList(t, bin, isolated(t))
	reads, err := liveRegistry().Profile("reads", false)
	if err != nil {
		t.Fatal(err)
	}
	if advertised != len(reads) {
		t.Errorf("%d tools advertised, the reads profile holds %d", advertised, len(reads))
	}
	problems, size, _ := checkDevicesResult(res)
	if len(problems) != 1 || problems[0] != `returned a tool error, code "config_missing"` || size == 0 {
		t.Errorf("problems %q, size %d", problems, size)
	}
}

// TestAuditGrowsByOneLinePerCall holds the assumption behind the live run's audit
// check: every CLI call, a failed one and a local one too, adds exactly one line.
func TestAuditGrowsByOneLinePerCall(t *testing.T) {
	failing := stubBinary(t, "exit 1\n")
	env := isolated(t)
	writeConfig(t, env, `{"contexts": {"e2e": {"tailnetId": "T1234CNTRL", "credentials": {"read": {"provider": "env"}}}},
		"local": {"tailscaleBinary": `+strconv.Quote(failing)+`}}`)
	l := newLiveRun(bin, env, nil)
	l.call("devices_list") // the first call creates the log
	before := auditLinesOf(t, bin, env)
	l.call("dns_get")
	l.call("local_version")
	l.call("acl_test", "203.0.113.5", "--deny", "198.51.100.7:1")
	if l.calls != 4 {
		t.Fatalf("%d calls", l.calls)
	}
	if after := auditLinesOf(t, bin, env); after-before != 3 {
		t.Errorf("the log grew by %d lines for 3 calls", after-before)
	}
}

// TestCheckScriptJudgesALiveRun runs scripts/live-check.sh, the judge of a `make live` run,
// against canned logs: it must refuse a skip and a missing pass, accept a clean
// run, hand on go test's status, and print nothing but the lines it is meant to.
func TestCheckScriptJudgesALiveRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the check is a POSIX shell script")
	}
	script, err := filepath.Abs("../../scripts/live-check.sh")
	if err != nil {
		t.Fatal(err)
	}
	const good = `=== RUN   TestLiveReads
    live_test.go:401: tools allowed to be unavailable (make live LIVE_UNAVAILABLE=…): 1: network_flow_logs
    live_test.go:421: summary: 43 tools: 25 ok, 1 unavailable, 17 none, 0 fail
    live_test.go:422: personal values examined: 57, at 9 declared paths
--- PASS: TestLiveReads (21.40s)
=== RUN   TestLiveMCP
    live_test.go:470: mcp: 41 tools advertised
    live_test.go:495: mcp: devices_list: 1234 bytes, checks passed (3 personal values examined)
--- PASS: TestLiveMCP (1.02s)
=== RUN   TestLivePolicy
    live_policy_test.go:40: self-check: 9 checks, all held
--- PASS: TestLivePolicy (1.02s)
PASS
ok  	github.com/abm9111/tailkeeper/cmd/tailkeeper	22.5s
`
	swap := func(from, to string) string {
		if !strings.Contains(good, from) {
			t.Fatalf("the canned log has no %q", from)
		}
		return strings.Replace(good, from, to, 1)
	}
	const sentinel = "TAILNET-VALUE-SENTINEL"
	cases := []struct {
		name   string
		log    string
		status string
		exit   int
		out    string // must appear
	}{
		{"a clean run", good, "0", 0, "summary: 43 tools"},
		{"TestLiveMCP skipped", swap("--- PASS: TestLiveMCP (1.02s)", "--- SKIP: TestLiveMCP (0.00s)"), "0", 1, "skipped, so it checked nothing"},
		{"TestLiveReads skipped", swap("--- PASS: TestLiveReads (21.40s)", "--- SKIP: TestLiveReads (0.00s)"), "0", 1, "skipped, so it checked nothing"},
		{"every live test skipped, as without TAILKEEPER_LIVE", `=== RUN   TestLiveReads
    live_test.go:35: reads the configured tailnet; run with ` + "`make live`" + `
--- SKIP: TestLiveReads (0.00s)
=== RUN   TestLiveMCP
    live_test.go:35: reads the configured tailnet; run with ` + "`make live`" + `
--- SKIP: TestLiveMCP (0.00s)
PASS
ok  	github.com/abm9111/tailkeeper/cmd/tailkeeper	0.3s
`, "0", 1, "skipped, so it checked nothing"},
		{"no live test ran", "testing: warning: no tests to run\nPASS\nok  \tgithub.com/abm9111/tailkeeper/cmd/tailkeeper\t0.2s\n", "0", 1, "TestLiveReads did not pass"},
		{"TestLiveMCP never ran", strings.SplitAfter(good, "--- PASS: TestLiveReads (21.40s)\n")[0] + "PASS\n", "0", 1, "TestLiveMCP did not pass"},
		{"a pass line twice", good + "--- PASS: TestLiveMCP (1.02s)\n", "0", 1, "TestLiveMCP did not pass"},
		{"TestLiveReads failed", swap("--- PASS: TestLiveReads (21.40s)", "--- FAIL: TestLiveReads (21.40s)"), "1", 1, "TestLiveReads did not pass"},
		{"no summary line", swap("    live_test.go:421: summary: 43 tools: 25 ok, 1 unavailable, 17 none, 0 fail\n", ""), "0", 1, "no summary line"},
		{"no closing MCP line", swap("    live_test.go:495: mcp: devices_list: 1234 bytes, checks passed (3 personal values examined)\n", ""), "0", 1, "no closing line"},
		{"go test's status is handed on", good, "3", 3, "summary: 43 tools"},
		{"a status that is not a number", good, "x", 1, "not a number"},
		{"no status", good, "", 1, "not a number"},
		{"output outside the framework and live_test.go is withheld", good + "panic: " + sentinel + "\ngoroutine 1 [running]:\n\tcmd/tailkeeper/other_test.go:9 " + sentinel + "\n", "0", 0, "summary: 43 tools"},
	}
	for _, c := range cases {
		logPath := filepath.Join(t.TempDir(), "log")
		if err := os.WriteFile(logPath, []byte(c.log), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("sh", script, logPath, c.status).CombinedOutput()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if code != c.exit {
			t.Errorf("%s: exit %d, want %d; output:\n%s", c.name, code, c.exit, out)
		}
		if !strings.Contains(string(out), c.out) {
			t.Errorf("%s: output lacks %q:\n%s", c.name, c.out, out)
		}
		if strings.Contains(string(out), sentinel) {
			t.Errorf("%s: the script printed a line it must withhold", c.name)
		}
	}
	// A log that does not exist is not a pass.
	out, err := exec.Command("sh", script, filepath.Join(t.TempDir(), "absent"), "0").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "no log") {
		t.Errorf("a missing log: err %v, output %q", err, out)
	}
}

// answeringStub is a stand-in that gives every list an id, acl_validate a pass that is
// not the live policy, and doctor a report in which every probe reads ok.
func answeringStub(t *testing.T) string {
	t.Helper()
	return stubBinary(t, answeringScript("false", false))
}

// maximalStub is answeringStub for a run that starts the most processes: the settings say
// the policy is managed outside the console, and the first baseline patch is refused as
// invalid, so the run tries the second spelling.
func maximalStub(t *testing.T) string {
	t.Helper()
	return stubBinary(t, answeringScript("true", true))
}

func answeringScript(managed string, refuseFirstBaseline bool) string {
	refuse := "0"
	if refuseFirstBaseline {
		refuse = "1"
	}
	return "REFUSE_FIRST_BASELINE=" + refuse + "\nMANAGED=" + managed + "\n" + `echo "$*" >> "$STUB_LOG"
case "$*" in
*"doctor --probe --json"*)
	printf '%s\n' '` + doctorReportJSON(0, nil) + `'
	exit 0 ;;
*"acl validate"*)
	if [ "$REFUSE_FIRST_BASELINE" = 1 ] && grep -q '/hosts/tk-live-check' "$5" 2>/dev/null; then
		printf '%s\n' '{"status":"invalid"}'
		exit 2
	else
		printf '%s\n' '{"status":"pass","serverChecked":true,"identicalToLive":false,"invariantsApplied":0}'
	fi ;;
*"acl diff"*)
	printf '%s\n' '{"status":"equal"}' ;;
*"acl history"*)
	printf '%s\n' '{"versions":[{"version":"v1.example"}]}' ;;
*"acl get"*)
	printf '%s\n' '{"warnings":[]}' ;;
*"dns get"*)
	printf '%s\n' '{"policyOverridesAnalysed":true}' ;;
*"settings get"*)
	printf '{"externallyManaged":"%s"}\n' "$MANAGED" ;;
*"users list"*)
	printf '%s\n' '{"users":[{"id":"u1","loginName":"a…@example.com [p:abcdefghij]"}]}' ;;
*"devices list"*)
	printf '%s\n' '{"devices":[{"nodeId":"n1"}]}' ;;
*"keys list"*)
	printf '%s\n' '{"keys":[{"id":"k1"}]}' ;;
*"webhooks list"*)
	printf '%s\n' '{"webhooks":[{"endpointId":"w1"}]}' ;;
*"services list"*)
	printf '%s\n' '{"services":[{"name":"svc:web"}]}' ;;
*"posture list"*)
	printf '%s\n' '{"integrations":[{"id":"p1"}]}' ;;
*"invites users"*|*"invites devices"*)
	printf '%s\n' '{"invites":[{"id":"i1"}]}' ;;
*"oauth-apps list"*)
	printf '%s\n' '{"apps":[{"id":"a1"}]}' ;;
*"local ip"*)
	printf '%s\n' '{"addresses":["100.64.0.1"]}' ;;
*"local status"*)
	printf '%s\n' '{"self":{"dnsName":"self.example.com"},"peers":[{"online":true,"tailscaleIps":["100.64.0.2"]}]}' ;;
*"acl test"*)
	printf '%s\n' '{"status":"unresolved","evaluatedAt":"2026-10-13T00:00:00Z","note":"n","verdicts":[{"verdict":"unresolved"}],"unmatched":["line"]}'
	exit 2 ;;
*)
	printf '{}\n' ;;
esac
`
}

func TestAnExtraCallCountsTowardTheAuditLowerBoundButAddsNoRow(t *testing.T) {
	stub := stubBinary(t, "printf '{}\n'\n")
	l := newLiveRun(stub, stubEnv, nil)
	l.call("dns_get")
	rows, calls := len(l.results), l.calls
	l.extraCall("dns_get")
	if l.calls != calls+1 || len(l.results) != rows {
		t.Errorf("calls %d (was %d), rows %d (was %d)", l.calls, calls, len(l.results), rows)
	}
}

func TestAFieldCheckNamesThePathAndNeverTheValue(t *testing.T) {
	l := newLiveRun("/nonexistent/tailkeeper", nil, nil)
	const secret = "secret-value"
	l.field("acl_get", map[string]any{"warnings": secret}, "warnings", "0")
	if len(l.problems) != 1 || l.problems[0] != "acl_get: field warnings is not 0" {
		t.Fatalf("problems %q", l.problems)
	}
	if strings.Contains(l.problems[0], secret) {
		t.Errorf("the problem repeats the value: %q", l.problems[0])
	}
}

// doctorStub stands in for the binary where doctor --probe and the audit log are concerned:
// `audit verify` prints the line count held in the file STUB_AUDIT, and doctor --probe adds
// STUB_LINES to it and prints STUB_OUT, exiting STUB_EXIT.
func doctorStub(t *testing.T) string {
	t.Helper()
	return stubBinary(t, `n=$(cat "$STUB_AUDIT" 2>/dev/null || echo 0)
case "$*" in
"audit verify") printf 'audit.log: %s lines, chain intact\n' "$n" ;;
*"doctor --probe --json"*)
	echo $((n + STUB_LINES)) > "$STUB_AUDIT"
	printf '%s' "$STUB_OUT"
	exit "$STUB_EXIT" ;;
*) printf '{}\n' ;;
esac
`)
}

func doctorRun(t *testing.T, out string, exit, lines int) *liveRun {
	t.Helper()
	env := append([]string{
		"STUB_AUDIT=" + filepath.Join(t.TempDir(), "audit"),
		"STUB_OUT=" + out, "STUB_EXIT=" + strconv.Itoa(exit), "STUB_LINES=" + strconv.Itoa(lines),
	}, stubEnv...)
	l := newLiveRun(doctorStub(t), env, nil)
	l.doctorProbe()
	return l
}

// doctorReportJSON is a report of doctor --probe --json in which every probe row reads ok, the
// way a healthy tailnet gives it, with the status of the named rows changed (a name that is
// not a row of the report adds one) and the first detail, when given, written in the first row.
// failed is what the report says its count is.
func doctorReportJSON(failed int, status map[string]string, detail ...string) string {
	type row struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	}
	var rows []row
	add := func(name, st string) {
		if over, ok := status[name]; ok {
			st = over
		}
		rows = append(rows, row{Name: name, Status: st, Detail: "a detail"})
	}
	add("read credential", "ok")
	add("security contact", "warn") // a warning outside the probes is not the probes' to judge
	add(canaryTestRow, "ok")
	for _, name := range append(append([]string{}, policyProbeRows...), kindProbeRows...) {
		add(name, "ok")
	}
	add("probe kinds refused", "info")
	add("audit protection", "info")
	extra := make([]string, 0, len(status))
	for name := range status {
		extra = append(extra, name)
	}
	sort.Strings(extra)
	for _, name := range extra {
		found := false
		for _, r := range rows {
			found = found || r.Name == name
		}
		if !found {
			add(name, "ok")
		}
	}
	if len(detail) > 0 {
		rows[0].Detail = detail[0]
	}
	b, err := json.Marshal(map[string]any{"checks": rows, "failed": failed, "warned": 0})
	if err != nil {
		panic(err)
	}
	return string(b)
}

// doctorReportWithout is doctorReportJSON with the named rows left out.
func doctorReportWithout(names ...string) string {
	var doc struct {
		Checks []map[string]any `json:"checks"`
		Failed int              `json:"failed"`
		Warned int              `json:"warned"`
	}
	if err := json.Unmarshal([]byte(doctorReportJSON(0, nil)), &doc); err != nil {
		panic(err)
	}
	kept := doc.Checks[:0]
	for _, c := range doc.Checks {
		if !slices.Contains(names, c["name"].(string)) {
			kept = append(kept, c)
		}
	}
	doc.Checks = kept
	b, _ := json.Marshal(doc)
	return string(b)
}

// The live run judges the rows of the probe, not only its count: each of the four policy
// probes must read ok, a warning on a probe row names the row, a kind the tailnet has no
// source for is a note, and any failing row is a problem. Only fixed words reach a line: never a
// detail of a row.
func TestTheDoctorProbeJudgesTheRowsAndNotOnlyTheCount(t *testing.T) {
	const secretDetail = "marker of a row detail"
	probeWarn := map[string]string{}
	for _, name := range policyProbeRows {
		probeWarn[name] = "warn"
	}
	probeWarn["probe tag"] = "n/a"
	cases := []struct {
		name     string
		out      string
		exit     int
		problems []string // each is a problem the run must hold
		notes    []string // each is a note the run must hold
		clean    bool     // no problem at all
	}{
		{name: "every probe reads ok", out: doctorReportJSON(0, nil), notes: []string{"doctor: 0 failing checks"}, clean: true},
		{
			name: "four policy probes warn and one kind has no source",
			out:  doctorReportJSON(0, probeWarn),
			problems: []string{
				"doctor: probe policy rejection reads warn", "doctor: probe details keys reads warn",
				"doctor: probe invariants canary reads warn", "doctor: probe ssh tests reads warn",
			},
			notes: []string{"doctor: probe tag not probed: no source in the tailnet"},
		},
		{
			name:  "a kind with no source in the tailnet is a note",
			out:   doctorReportJSON(0, map[string]string{"probe host alias": "n/a"}),
			notes: []string{"doctor: probe host alias not probed: no source in the tailnet", "doctor: 0 failing checks"},
			clean: true,
		},
		{
			name:     "a policy probe with no credential reads n/a",
			out:      doctorReportJSON(0, map[string]string{"probe ssh tests": "n/a"}),
			problems: []string{"doctor: probe ssh tests reads n/a"},
		},
		{
			name:     "a policy probe reads info",
			out:      doctorReportJSON(0, map[string]string{"probe details keys": "info"}),
			problems: []string{"doctor: probe details keys reads info"},
		},
		{
			name:     "a kind probe warns",
			out:      doctorReportJSON(0, map[string]string{"probe IPv6 address": "warn"}),
			problems: []string{"doctor: probe IPv6 address reads warn"},
		},
		{
			name:     "a probe row fails and the process exits 8",
			out:      doctorReportJSON(1, map[string]string{"probe tag": "fail"}),
			exit:     8,
			problems: []string{"doctor: probe tag reads fail"},
		},
		{
			name:     "a row outside the probes fails and the process exits 8",
			out:      doctorReportJSON(1, map[string]string{"key record": "fail"}),
			exit:     8,
			problems: []string{"doctor: key record reads fail"},
		},
		{
			name:     "a policy probe row is missing",
			out:      doctorReportWithout("probe invariants canary"),
			problems: []string{"doctor: probe invariants canary is absent"},
		},
		{
			name:     "a kind probe row is missing",
			out:      doctorReportWithout("probe ICMP, port 0"),
			problems: []string{"doctor: probe ICMP, port 0 is absent"},
		},
		{
			name:     "the canary test row is missing",
			out:      doctorReportWithout("probe acl_test"),
			problems: []string{"doctor: probe acl_test is absent"},
		},
		{
			name:     "the canary test reads info",
			out:      doctorReportJSON(0, map[string]string{"probe acl_test": "info"}),
			problems: []string{"doctor: probe acl_test reads info"},
		},
		{
			name:     "the canary test warns",
			out:      doctorReportJSON(0, map[string]string{"probe acl_test": "warn"}),
			problems: []string{"doctor: probe acl_test reads warn"},
		},
		{
			name:  "the canary test has no tag to use",
			out:   doctorReportJSON(0, map[string]string{"probe acl_test": "n/a"}),
			notes: []string{"doctor: probe acl_test not probed: the live policy defines no tag", "doctor: 0 failing checks"},
			clean: true,
		},
		{
			name:     "a report with no rows",
			out:      `{"failed":0,"checks":[]}`,
			problems: []string{"doctor: probe policy rejection is absent", "doctor: probe tag is absent"},
		},
		{
			name:     "a status the report does not use",
			out:      doctorReportJSON(0, map[string]string{"probe details keys": secretDetail}),
			problems: []string{"doctor: probe details keys reads an unknown status"},
		},
		{
			name:     "the count says two failing and one row fails",
			out:      doctorReportJSON(2, map[string]string{"probe tag": "fail"}),
			exit:     8,
			problems: []string{"doctor: probe tag reads fail", "doctor: the count of failing checks is 2 and 1 rows fail"},
		},
		{
			name:     "the count says one failing and no row fails",
			out:      doctorReportJSON(1, nil),
			exit:     8,
			problems: []string{"doctor: the count of failing checks is 1 and 0 rows fail"},
		},
		{
			name:     "a row named with something other than a fixed word",
			out:      doctorReportJSON(1, map[string]string{"probe pat@example.com": "fail"}),
			exit:     8,
			problems: []string{"doctor: a row reads fail"},
		},
	}
	for _, c := range cases {
		l := doctorRun(t, c.out, c.exit, 1)
		for _, want := range c.problems {
			if !slices.Contains(l.problems, want) {
				t.Errorf("%s: problems %q lack %q", c.name, l.problems, want)
			}
		}
		for _, want := range c.notes {
			if !slices.Contains(l.notes, want) {
				t.Errorf("%s: notes %q lack %q", c.name, l.notes, want)
			}
		}
		if c.clean && len(l.problems) != 0 {
			t.Errorf("%s: problems %q", c.name, l.problems)
		}
		if !c.clean && len(l.problems) == 0 {
			t.Errorf("%s: the run holds no problem", c.name)
		}
		for _, line := range append(append([]string{}, l.notes...), l.problems...) {
			for _, leak := range []string{secretDetail, "a detail", "pat@example.com"} {
				if strings.Contains(line, leak) {
					t.Errorf("%s: a line repeats %q: %q", c.name, leak, line)
				}
			}
		}
	}
	// A detail is never repeated, whatever the row reads.
	l := doctorRun(t, doctorReportJSON(0, map[string]string{"probe tag": "warn"}, secretDetail), 0, 1)
	for _, line := range append(append([]string{}, l.notes...), l.problems...) {
		if strings.Contains(line, secretDetail) {
			t.Errorf("a line repeats a detail: %q", line)
		}
	}
}

// The rows the live run reads by name are the rows the doctor writes: a row renamed in the
// doctor would otherwise read as absent in a run nobody is watching, or never be read.
func TestTheRowsTheLiveRunReadsAreTheOnesTheDoctorWrites(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "../../internal/doctor/probes_policy.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	ast.Inspect(f, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || spec.Names[0].Name != "policyProbeNames" || len(spec.Values) != 1 {
			return true
		}
		lit, ok := spec.Values[0].(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, e := range lit.Elts {
			if b, ok := e.(*ast.BasicLit); ok {
				v, err := strconv.Unquote(b.Value)
				if err != nil {
					t.Fatal(err)
				}
				names = append(names, v)
			}
		}
		return false
	})
	read := append(append([]string{}, policyProbeRows...), kindProbeRows...)
	read = append(read, "probe kinds refused")
	if len(names) == 0 || !slices.Equal(names, read) {
		t.Errorf("the doctor writes the probe rows %q; the live run reads %q", names, read)
	}
	// The canary test's row is written in another file of the doctor.
	src, err := os.ReadFile("../../internal/doctor/doctor.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `r.add("`+canaryTestRow+`", NA,`) || !strings.Contains(string(src), `names = append(names, "`+canaryTestRow+`")`) {
		t.Errorf("the doctor does not write the row %q that the live run reads", canaryTestRow)
	}
}

func TestTheDoctorProbeJudgesItsOutputAndItsExit(t *testing.T) {
	credential := "tskey" + "-auth-" + strings.Repeat("A", 12)
	cases := []struct {
		name    string
		out     string
		exit    int
		wantErr string // the problem; "" for none
		note    string // the note, when there is no problem
	}{
		{"no failing checks", doctorReportJSON(0, nil), 0, "", "doctor: 0 failing checks"},
		{"empty output, exit 0", ``, 0, "probe printed no JSON document (0 bytes, exit 0)", ""},
		{"empty output, exit 8", ``, 8, "probe printed no JSON document (0 bytes, exit 8)", ""},
		{"text, exit 0", `all good`, 0, "probe printed no JSON document (8 bytes, exit 0)", ""},
		{"an error document, exit 1", `{"error":{"code":"forbidden"}}`, 1, `probe printed an error document, code "forbidden" (exit 1)`, ""},
		{"an error document, exit 0", `{"error":{"code":"forbidden"}}`, 0, `probe printed an error document, code "forbidden" (exit 0)`, ""},
		{"a report and exit 1", doctorReportJSON(0, nil), 1, "probe exit 1", ""},
		{"a report and exit 2", doctorReportJSON(0, nil), 2, "probe exit 2", ""},
		{"a count that is not a number", `{"failed":"x"}`, 8, "probe printed no count of failing checks", ""},
		{"no count", `{"checks":[]}`, 0, "probe printed no count of failing checks", ""},
		{"a negative count", `{"failed":-1}`, 8, "probe printed no count of failing checks", ""},
		{"failures and exit 0", doctorReportJSON(2, map[string]string{"probe tag": "fail", "key record": "fail"}), 0, "probe exited 0 but reports 2 failing checks", ""},
		{"none failing and exit 8", doctorReportJSON(0, nil), 8, "probe exited 8 but reports 0 failing checks", ""},
		{"a whole address in a check", doctorReportJSON(0, nil, "pat@example.com"), 0, "1 whole email addresses", ""},
		{"a credential in a check", doctorReportJSON(0, nil, credential), 0, "the tripwire matched the output", ""},
	}
	for _, c := range cases {
		l := doctorRun(t, c.out, c.exit, 1)
		if c.wantErr == "" {
			if len(l.problems) != 0 || !slices.Contains(l.notes, c.note) {
				t.Errorf("%s: problems %q, notes %q", c.name, l.problems, l.notes)
			}
			continue
		}
		if !slices.Contains(l.problems, "doctor: "+c.wantErr) {
			t.Errorf("%s: problems %q lack %q", c.name, l.problems, c.wantErr)
		}
		// The scan of a report that is otherwise fine fails it and still counts its checks.
		scanned := c.wantErr == "1 whole email addresses" || c.wantErr == "the tripwire matched the output"
		for _, line := range append(l.notes, l.problems...) {
			if strings.Contains(line, "pat@example.com") || strings.Contains(line, credential) {
				t.Errorf("%s: a line repeats the check: %q", c.name, line)
			}
		}
		for _, line := range l.notes {
			if !scanned && strings.Contains(line, "failing checks") {
				t.Errorf("%s: a failed probe is also a count: %q", c.name, line)
			}
		}
	}
}

func TestTheDoctorProbeCountsItsAuditLinesAndFailsWhenItWroteNone(t *testing.T) {
	l := doctorRun(t, doctorReportJSON(0, nil), 0, 3)
	if len(l.problems) != 0 || l.probeLines != 3 || l.probeRuns != 1 {
		t.Fatalf("problems %q, probe lines %d, runs %d", l.problems, l.probeLines, l.probeRuns)
	}
	l.calls = 10
	if l.auditLowerBound() != 13 || l.maxProcesses() != 11 {
		t.Errorf("lower bound %d, processes %d", l.auditLowerBound(), l.maxProcesses())
	}

	none := doctorRun(t, doctorReportJSON(0, nil), 0, 0)
	if !slices.Contains(none.problems, "doctor: the probe wrote no audit line") || none.probeLines != 0 {
		t.Errorf("a probe that wrote none: problems %q, lines %d", none.problems, none.probeLines)
	}
	// A report that is fine does not excuse the missing lines.
	if slices.Contains(none.notes, "doctor: 0 failing checks") == false {
		t.Errorf("the report was not read after the audit check: %q", none.notes)
	}

	// Without a log to count, the run says so: it is not a pass of the check.
	l = newLiveRun(stubBinary(t, "printf '%s' '"+doctorReportJSON(0, nil)+"'\n"), stubEnv, nil)
	l.doctorProbe()
	if !slices.Contains(l.notes, "doctor: audit lines not measured") || l.probeLines != 0 {
		t.Errorf("notes %q, lines %d", l.notes, l.probeLines)
	}
}

func TestTheGitOpsOracleSaysNotRequestedWhenTheVariableIsUnsetAndItIsNotASkippedTest(t *testing.T) {
	stub := stubBinary(t, "printf '{}\n'\n")
	l := newLiveRun(stub, stubEnv, nil)
	l.all()
	if !slices.Contains(l.notes, "GitOps oracle: not requested") {
		t.Fatalf("notes %q", l.notes)
	}
	script, err := filepath.Abs("../../scripts/live-check.sh")
	if err != nil {
		t.Fatal(err)
	}
	log := `=== RUN   TestLiveReads
    live_test.go:1: GitOps oracle: not requested
    live_test.go:2: summary: 46 tools: 46 ok, 0 unavailable, 0 none, 0 fail
--- PASS: TestLiveReads (1.00s)
=== RUN   TestLiveMCP
    live_test.go:3: mcp: devices_list: 2 bytes, checks passed (1 personal values examined)
--- PASS: TestLiveMCP (1.00s)
=== RUN   TestLivePolicy
    live_policy_test.go:40: self-check: 9 checks, all held
--- PASS: TestLivePolicy (1.00s)
ok  cmd/tailkeeper
`
	path := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(path, []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", script, path, "0").CombinedOutput()
	if err != nil {
		t.Fatalf("the oracle line was read as a skip: %v\n%s", err, out)
	}
}

func TestTheGitOpsOracleIsNotRunWhenThePolicyIsNotExternallyManagedAndItPrintsNoPath(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "policy.hujson")
	if err := os.WriteFile(src, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "calls")
	stub := stubBinary(t, `echo "$*" >> "$STUB_LOG"
case "$*" in
*"settings get"*) printf '%s\n' '{"externallyManaged":"false"}' ;;
*"acl validate"*) printf '%s\n' '{"status":"pass","serverChecked":true,"identicalToLive":false,"invariantsApplied":0}' ;;
*) printf '{}\n' ;;
esac
`)
	l := newLiveRun(stub, append([]string{"STUB_LOG=" + log, "TAILKEEPER_LIVE_POLICY_SOURCE=" + src}, stubEnv...), nil)
	l.all()
	if !slices.Contains(l.notes, "GitOps oracle: not run") {
		t.Fatalf("notes %q", l.notes)
	}
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "acl diff --against "+src) {
		t.Errorf("the oracle called acl diff on the file though the policy is not managed outside the console:\n%s", b)
	}
	for _, line := range append(l.notes, l.problems...) {
		if strings.Contains(line, src) {
			t.Errorf("the path was printed: %q", line)
		}
	}
}

// oracleRun runs the GitOps oracle against a stand-in whose acl diff answers diff, and returns
// the run, the calls the stand-in logged and the path of the owner's file.
func oracleRun(t *testing.T, diff string) (l *liveRun, calls, src string) {
	t.Helper()
	dir := t.TempDir()
	src = filepath.Join(dir, "policy.hujson")
	if err := os.WriteFile(src, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "calls")
	stub := stubBinary(t, `echo "$*" >> "$STUB_LOG"
case "$*" in
*"settings get"*) printf '%s\n' '{"externallyManaged":"true"}' ;;
*"acl diff"*) printf '%s\n' "$STUB_DIFF" ;;
*) printf '{}\n' ;;
esac
`)
	l = newLiveRun(stub, append([]string{"STUB_LOG=" + log, "STUB_DIFF=" + diff, "TAILKEEPER_LIVE_POLICY_SOURCE=" + src}, stubEnv...), nil)
	l.results = append(l.results,
		liveOutcome{tool: "settings_get", outcome: outcomeOK},
		liveOutcome{tool: "acl_diff", outcome: outcomeOK})
	l.gitopsOracle(map[string]any{"externallyManaged": "true"})
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("the stand-in logged no call: %v", err)
	}
	return l, string(b), src
}

func TestTheGitOpsOracleDiffsTheOwnersFileAgainstTheLivePolicyAndHoldsWhenEqual(t *testing.T) {
	l, calls, src := oracleRun(t, `{"status":"equal"}`)
	if slices.Contains(l.notes, "GitOps oracle: not run") || slices.Contains(l.notes, "GitOps oracle: not requested") {
		t.Fatalf("the oracle did not run: %q", l.notes)
	}
	if len(l.problems) != 0 {
		t.Errorf("an equal file is a problem: %q", l.problems)
	}
	if want := "--json acl diff --against " + src; !strings.Contains(calls, want) {
		t.Errorf("the oracle did not diff the owner's file; calls:\n%s", calls)
	}
	for _, line := range append(l.notes, l.problems...) {
		if strings.Contains(line, src) {
			t.Errorf("the path was printed: %q", line)
		}
	}
}

func TestTheGitOpsOracleFailsWhenTheOwnersFileIsNotTheLivePolicy(t *testing.T) {
	for _, status := range []string{"changed", "", "equals"} {
		l, _, src := oracleRun(t, `{"status":"`+status+`"}`)
		if !slices.Contains(l.problems, "acl_diff: field status is not equal") {
			t.Errorf("status %q: problems %q", status, l.problems)
		}
		for _, line := range append(l.notes, l.problems...) {
			if strings.Contains(line, src) || strings.Contains(line, "changed") {
				t.Errorf("status %q: a line repeats what was found: %q", status, line)
			}
		}
	}
}

func TestEveryRegisteredToolHasARowInTheLiveRunIncludingACLHistory(t *testing.T) {
	stub := answeringStub(t)
	l := newLiveRun(stub, append([]string{"STUB_LOG=" + filepath.Join(t.TempDir(), "calls")}, stubEnv...), nil)
	l.all()
	if !l.ran["acl_history"] {
		t.Fatal("acl_history was not run")
	}
	for _, p := range l.problems {
		if strings.Contains(p, "was not exercised") {
			t.Errorf("%s", p)
		}
	}
	if len(l.results) != len(l.reg.All()) {
		t.Errorf("%d results for %d tools", len(l.results), len(l.reg.All()))
	}
}

func TestAnACLTestExitMustMatchItsStatus(t *testing.T) {
	const (
		passing    = `{"status":"pass","evaluatedAt":"2026-10-13T00:00:00Z","note":"n"}`
		failing    = `{"status":"fail","evaluatedAt":"2026-10-13T00:00:00Z","note":"n"}`
		unresolved = `{"status":"unresolved","evaluatedAt":"2026-10-13T00:00:00Z","note":"n"}`
		unknown    = `{"status":"unknown","evaluatedAt":"2026-10-13T00:00:00Z","note":"n"}`
	)
	cases := []struct {
		name, doc string
		exit      int
		outcome   string
	}{
		{"pass exits 0", passing, 0, outcomeOK},
		{"fail exits 9", failing, 9, outcomeOK},
		{"unresolved exits 2", unresolved, 2, outcomeOK},
		{"unknown exits 1", unknown, 1, outcomeOK},
		{"unresolved exiting 9", unresolved, 9, outcomeFail},
		{"unknown exiting 0", unknown, 0, outcomeFail},
	}
	stub := docStub(t)
	for _, c := range cases {
		l := newLiveRun(stub, docEnv(c.doc, c.exit), nil)
		l.call("acl_test")
		if len(l.results) != 1 || l.results[0].outcome != c.outcome {
			t.Errorf("%s: %+v", c.name, l.results)
		}
	}
}

func TestTheWarningsBaselineValidatesACopyThatIsNotTheLivePolicy(t *testing.T) {
	dir := t.TempDir()
	kept := filepath.Join(dir, "patches")
	stub := stubBinary(t, `case "$*" in
*"--patch "*|*"--invariants "*)
	printf '%s\n' "$4" >> "$STUB_KEPT"
	cat "$5" >> "$STUB_KEPT"
	printf '\n' >> "$STUB_KEPT"
	printf '%s\n' '{"status":"pass","serverChecked":true,"identicalToLive":false,"invariantsApplied":0,"existingWarnings":[{"message":"kept"}]}' ;;
*"acl validate"*)
	printf '%s\n' '{"status":"pass","serverChecked":true,"identicalToLive":true,"invariantsApplied":0}' ;;
*)
	printf '{}\n' ;;
esac
`)
	l := newLiveRun(stub, append([]string{"STUB_KEPT=" + kept}, stubEnv...), nil)
	l.call("acl_validate")
	l.call("acl_get")
	l.policyCopies(1)
	body, err := os.ReadFile(kept)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), baselinePatch) || !strings.Contains(string(body), emptyPatch) {
		t.Fatalf("the copies were:\n%s", body)
	}
	if strings.Contains(string(body), "--invariants") {
		t.Errorf("an invariants file was sent:\n%s", body)
	}
	if !slices.Contains(l.notes, "acl_validate: baseline stored 1, existing 1, new 0, spelling matched") {
		t.Fatalf("notes %q", l.notes)
	}
	if len(l.problems) != 0 {
		t.Errorf("problems %q", l.problems)
	}
}

// copiesStub answers every copy sent with --patch with the document patch and the exit the
// tool makes for its status, and the live policy itself with a pass that is identical to it.
func copiesStub(t *testing.T, patch string, exit int) *liveRun {
	t.Helper()
	stub := stubBinary(t, `case "$*" in
*"--patch "*) printf '%s\n' "$STUB_PATCH"; exit "$STUB_EXIT" ;;
*"acl validate"*) printf '%s\n' '{"status":"pass","serverChecked":true,"identicalToLive":true,"invariantsApplied":0}' ;;
*) printf '{}\n' ;;
esac
`)
	l := newLiveRun(stub, append([]string{"STUB_PATCH=" + patch, "STUB_EXIT=" + strconv.Itoa(exit)}, stubEnv...), nil)
	l.call("acl_validate")
	l.call("acl_get")
	l.policyCopies(0)
	return l
}

func TestACopyThatIsTheLivePolicyByteForByteFailsTheBaselineCheck(t *testing.T) {
	l := copiesStub(t, `{"status":"pass","serverChecked":true,"identicalToLive":true,"invariantsApplied":0}`, 0)
	if !slices.Contains(l.problems, "acl_validate: field identicalToLive is not false") {
		t.Fatalf("problems %q", l.problems)
	}
	ok := copiesStub(t, `{"status":"pass","serverChecked":true,"identicalToLive":false,"invariantsApplied":0}`, 0)
	if len(ok.problems) != 0 {
		t.Errorf("a copy that is not the live policy: problems %q", ok.problems)
	}
}

func TestATailnetWhoseOwnTestsFailIsANoteAndTheCopyCheckIsNotMade(t *testing.T) {
	// A copy that fails the tailnet's own tests: not a failure of the harness, and not a pass.
	l := copiesStub(t, `{"status":"fail","serverChecked":true,"identicalToLive":true,"invariantsApplied":0}`, 9)
	if len(l.problems) != 0 {
		t.Fatalf("problems %q", l.problems)
	}
	for _, want := range []string{
		"acl_validate: patch copy check not made: the tailnet's own tests answered fail",
		"acl_validate: baseline copy check not made: the tailnet's own tests answered fail",
	} {
		if !slices.Contains(l.notes, want) {
			t.Errorf("notes %q lack %q", l.notes, want)
		}
	}
	for _, n := range l.notes {
		if strings.HasPrefix(n, "acl_validate: baseline stored") {
			t.Errorf("the baseline was classified though the check was not made: %q", n)
		}
	}
	// Any other status that is not a pass is still a problem.
	for status, exit := range map[string]int{"invalid": 2, "rejected": 2, "unresolved": 2, "unknown": 1} {
		bad := copiesStub(t, `{"status":"`+status+`","identicalToLive":false}`, exit)
		if !slices.Contains(bad.problems, "acl_validate: field status is not pass") {
			t.Errorf("status %s: problems %q", status, bad.problems)
		}
		for _, n := range bad.notes {
			if strings.HasPrefix(n, "acl_validate: baseline stored") {
				t.Errorf("status %s: the baseline was classified though the copy did not pass: %q", status, n)
			}
		}
	}
}

func TestTheInvariantsCheckIsRecordedAsNotRunAndSendsNoEmptyFile(t *testing.T) {
	log := filepath.Join(t.TempDir(), "calls")
	stub := stubBinary(t, `echo "$*" >> "$STUB_LOG"
case "$*" in
*"acl validate"*) printf '%s\n' '{"status":"pass","serverChecked":true,"identicalToLive":false,"invariantsApplied":0}' ;;
*) printf '{}\n' ;;
esac
`)
	l := newLiveRun(stub, append([]string{"STUB_LOG=" + log}, stubEnv...), nil)
	l.call("acl_validate")
	l.policyCopies(0)
	want := "acl_validate: invariants not run: no test is known to hold on the live policy, and an empty file proves nothing"
	if !slices.Contains(l.notes, want) {
		t.Errorf("notes %q", l.notes)
	}
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "--invariants") {
		t.Errorf("an invariants file was sent:\n%s", b)
	}
	for _, p := range l.problems {
		if strings.Contains(p, "invariantsApplied") {
			t.Errorf("an applied count is asserted though nothing was applied: %q", p)
		}
	}
}

func TestTheCallCountInTheMakefileCommentIsTheMostProcessesARunCanStart(t *testing.T) {
	// The most: the oracle runs (the policy is managed outside the console), the first baseline
	// spelling is refused so the second is sent, and doctor --probe runs.
	dir := t.TempDir()
	src := filepath.Join(dir, "policy.hujson")
	if err := os.WriteFile(src, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "calls")
	l := newLiveRun(maximalStub(t), append([]string{"STUB_LOG=" + log, "TAILKEEPER_LIVE_POLICY_SOURCE=" + src}, stubEnv...), nil)
	l.all()
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	// Every process the stand-in saw is one the run started, and the count is of those; the
	// reads of the audit log's length are not tool calls and write no line.
	started, diffs, patches := 0, 0, 0
	for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if line == "audit verify" {
			continue
		}
		started++
		if strings.Contains(line, "acl diff --against "+src) {
			diffs++
		}
		if strings.Contains(line, "acl validate --patch") {
			patches++
		}
	}
	if started != l.maxProcesses() {
		t.Fatalf("the stand-in saw %d processes; the run counts %d", started, l.maxProcesses())
	}
	if diffs != 1 || patches != 3 {
		t.Fatalf("the oracle ran %d times and %d patches were sent, want 1 and 3 (empty, baseline, its second spelling)", diffs, patches)
	}
	mk, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	const mark = "Each of the "
	i := strings.Index(string(mk), mark)
	if i < 0 {
		t.Fatal("the live comment does not count the calls")
	}
	rest := string(mk)[i+len(mark):]
	n, _, ok := strings.Cut(rest, " calls")
	if !ok {
		t.Fatal("the live comment has no call count")
	}
	if n != strconv.Itoa(l.maxProcesses()) {
		t.Errorf("the comment says %s calls; the most a run can start is %d", n, l.maxProcesses())
	}
}

// TestTheLiveLogicCountsTheThirdTestAndItsClosingLine is the judge's view of
// TestLivePolicy: a canned log passes with its closing line, and fails when the
// test did not pass, was skipped, or never logged that every check held.
func TestTheLiveLogicCountsTheThirdTestAndItsClosingLine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the check is a POSIX shell script")
	}
	script, err := filepath.Abs("../../scripts/live-check.sh")
	if err != nil {
		t.Fatal(err)
	}
	const three = `=== RUN   TestLiveReads
    live_test.go:421: summary: 43 tools: 25 ok, 1 unavailable, 17 none, 0 fail
--- PASS: TestLiveReads (21.40s)
=== RUN   TestLiveMCP
    live_test.go:495: mcp: devices_list: 1234 bytes, checks passed
--- PASS: TestLiveMCP (1.02s)
=== RUN   TestLivePolicy
    live_policy_test.go:40: self-check: 9 checks, all held
--- PASS: TestLivePolicy (1.02s)
PASS
`
	run := func(log, status string) (string, int) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "log")
		if err := os.WriteFile(path, []byte(log), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("sh", script, path, status).CombinedOutput()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return string(out), code
	}
	if out, code := run(three, "0"); code != 0 || !strings.Contains(out, "self-check: 9 checks, all held") {
		t.Fatalf("a complete log: exit %d\n%s", code, out)
	}
	noPass := strings.Replace(three, "--- PASS: TestLivePolicy (1.02s)\n", "", 1)
	if out, code := run(noPass, "0"); code != 1 || !strings.Contains(out, "TestLivePolicy did not pass") {
		t.Fatalf("no pass line: exit %d\n%s", code, out)
	}
	skipped := strings.Replace(three, "--- PASS: TestLivePolicy (1.02s)", "--- SKIP: TestLivePolicy (0.00s)", 1)
	if out, code := run(skipped, "0"); code != 1 || !strings.Contains(out, "skipped, so it checked nothing") {
		t.Fatalf("a skip: exit %d\n%s", code, out)
	}
	noClose := strings.Replace(three, "    live_policy_test.go:40: self-check: 9 checks, all held\n", "", 1)
	if out, code := run(noClose, "0"); code != 1 || !strings.Contains(out, "no closing line") {
		t.Fatalf("no closing line: exit %d\n%s", code, out)
	}
	// The closing line is the policy test's own: the same words logged by another test do not count.
	elsewhere := strings.Replace(three, "live_policy_test.go:40: self-check: 9 checks, all held", "live_test.go:40: self-check: 9 checks, all held", 1)
	if out, code := run(elsewhere, "0"); code != 1 || !strings.Contains(out, "no closing line") {
		t.Fatalf("a closing line from another file: exit %d\n%s", code, out)
	}
}

// TestNothingButMakeLiveReachesTheLiveRun: the live run reads a real tailnet, so neither the
// gate nor the workflows may reach it.
func TestNothingButMakeLiveReachesTheLiveRun(t *testing.T) {
	mk, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	var verify, live string
	for _, line := range strings.Split(string(mk), "\n") {
		switch {
		case strings.HasPrefix(line, "verify:"):
			verify = line
		case strings.HasPrefix(line, "live:") && !strings.Contains(line, "export"):
			live = line
		}
	}
	if verify == "" || live == "" {
		t.Fatalf("the Makefile's verify line %q or live line %q was not found", verify, live)
	}
	if strings.Contains(verify, "live") {
		t.Errorf("verify depends on live: %q", verify)
	}
	// Every go test line of the Makefile either drops the caller's TAILKEEPER_LIVE,
	// is the live target's own, or runs no test: an ambient TAILKEEPER_LIVE=1 must
	// never send make verify (or make cover) to the tailnet.
	liveRuns := 0
	for _, line := range strings.Split(string(mk), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") || !strings.Contains(line, "$(GO) test") {
			continue
		}
		switch {
		case strings.Contains(line, "TAILKEEPER_LIVE=1"):
			liveRuns++
			if !strings.Contains(line, "-run '^TestLive'") {
				t.Errorf("the live run does not select the live tests: %q", line)
			}
		case strings.Contains(line, "env -u TAILKEEPER_LIVE $(GO) test"):
		case strings.Contains(line, "-run '^$$'") || strings.Contains(line, "-list"):
		default:
			t.Errorf("a go test line keeps the caller's TAILKEEPER_LIVE: %q", line)
		}
	}
	if liveRuns != 1 {
		t.Errorf("%d lines set TAILKEEPER_LIVE=1 on a go test, want the live target's one", liveRuns)
	}
	flows, err := filepath.Glob("../../.github/workflows/*")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range flows {
		if fi, err := os.Stat(f); err != nil {
			t.Fatal(err)
		} else if fi.IsDir() {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "TAILKEEPER_LIVE") || strings.Contains(string(b), "make live") {
			t.Errorf("%s reaches the live run", filepath.Base(f))
		}
	}
}

// selfCheckOutput is the output of a self-check that holds everything, as the probe prints it:
// the four policy checks and the five shapes, and the closing count.
const selfCheckOutput = `self-check: reformat held 2
self-check: round-trip held 0
self-check: summary held 12 (not compared: 1 unknown)
self-check: etag held 1
shape: A-1 same
shape: A-8 same (not compared: the form of the policy text, warnings and errors)
shape: A-9 same (not compared: a tag, a host alias, a user, a service)
shape: A-10 same (not compared: the ssh fallback)
shape: H-1 same
self-check: 9 checks, all held
`

func TestTheSelfCheckIsJudgedOnEveryLineItPrintsAndTheNumberOfChecksItMakes(t *testing.T) {
	const want = 9
	if got := probe.SelfCheckCount(); got != want {
		t.Fatalf("the probe makes %d checks, this test expects %d", got, want)
	}
	lines, problems := judgeSelfCheck([]byte("tailkeeper: probe-acl: A-1\n"+selfCheckOutput), 0, want)
	if len(problems) != 0 || len(lines) != 10 {
		t.Fatalf("a complete run: %d lines, problems %q", len(lines), problems)
	}

	// A failing run still shows every line, before it fails on the exit code.
	failing := strings.Replace(selfCheckOutput, "shape: A-9 same (not compared: a tag, a host alias, a user, a service)", "shape: A-9 differs: 1 paths (not compared: a tag, a host alias, a user, a service)", 1)
	failing = strings.Replace(failing, "self-check: 9 checks, all held", "self-check: 9 checks, 1 not held", 1)
	lines, problems = judgeSelfCheck([]byte(failing), 1, want)
	if len(lines) != 10 || !slices.Contains(lines, "shape: A-9 differs: 1 paths (not compared: a tag, a host alias, a user, a service)") {
		t.Errorf("a failing run hides lines: %q", lines)
	}
	for _, want := range []string{"self-check exit 1", "1 checks did not hold"} {
		if !slices.Contains(problems, want) {
			t.Errorf("problems %q lack %q", problems, want)
		}
	}

	// A run that dropped the shape checks has fewer checks than it must make, whatever it says.
	dropped := "self-check: reformat held 2\nself-check: round-trip held 0\nself-check: summary held 12\nself-check: etag held 1\nself-check: 4 checks, all held\n"
	_, problems = judgeSelfCheck([]byte(dropped), 0, want)
	if !slices.Contains(problems, "the self-check made 4 checks, and the run must make 9") {
		t.Errorf("dropped checks: problems %q", problems)
	}
	// A closing count that is not the number of lines printed.
	short := strings.Replace(selfCheckOutput, "shape: H-1 same\n", "", 1)
	_, problems = judgeSelfCheck([]byte(short), 0, want)
	if !slices.Contains(problems, "the closing count is 9, and 8 checks were printed") {
		t.Errorf("a short run: problems %q", problems)
	}
	// No closing line at all.
	_, problems = judgeSelfCheck([]byte(strings.Replace(selfCheckOutput, "self-check: 9 checks, all held\n", "", 1)), 0, want)
	if !slices.Contains(problems, "the self-check printed no closing count") {
		t.Errorf("no closing line: problems %q", problems)
	}
	// A line that is not of the forms the self-check prints is a problem and is not logged.
	lines, problems = judgeSelfCheck([]byte(selfCheckOutput+"leaked 198.51.100.7\n"), 0, want)
	if !slices.Contains(problems, "a self-check line is not a count, a boolean or a probe name") || slices.Contains(lines, "leaked 198.51.100.7") {
		t.Errorf("a stray line: problems %q, lines %q", problems, lines)
	}
}

// recorder is a reporter that keeps, in order, what the live run would log and fail on.
type recorder struct{ events []string }

func (r *recorder) Helper() {}

func (r *recorder) Log(args ...any) { r.events = append(r.events, "log: "+fmt.Sprint(args...)) }

func (r *recorder) Error(args ...any) { r.events = append(r.events, "error: "+fmt.Sprint(args...)) }

func (r *recorder) Fatal(args ...any) { r.events = append(r.events, "fatal") }

// errorsOf is the problems a recorder was told of.
func (r *recorder) errorsOf() []string {
	var out []string
	for _, e := range r.events {
		if after, ok := strings.CutPrefix(e, "error: "); ok {
			out = append(out, after)
		}
	}
	return out
}

// livePolicyRun runs checkLivePolicy against a stand-in for the tagged binary that writes
// stderr then out and exits exit, and returns what the run reported and the arguments the
// stand-in was started with.
func livePolicyRun(t *testing.T, out string, exit int, timeout time.Duration) (*recorder, string) {
	t.Helper()
	log := filepath.Join(t.TempDir(), "args")
	bin := stubBinary(t, `echo "$*" >> "$STUB_LOG"
printf 'tailkeeper: probe-acl: A-1\n' >&2
printf '%s' "$STUB_OUT"
if [ -n "$STUB_SLEEP" ]; then exec sleep "$STUB_SLEEP"; fi
exit "$STUB_EXIT"
`)
	env := append([]string{"STUB_LOG=" + log, "STUB_OUT=" + out, "STUB_EXIT=" + strconv.Itoa(exit)}, stubEnv...)
	if timeout < time.Second {
		env = append(env, "STUB_SLEEP=30")
	}
	r := &recorder{}
	checkLivePolicy(r, bin, env, "/captures/observed", timeout)
	b, _ := os.ReadFile(log)
	return r, string(b)
}

// TestLivePolicy is only glue around checkLivePolicy, and runs only for a live run; these are
// the wiring's own tests: that the self-check is run on the captures, judged on its output
// and its exit, and that every line it prints is logged before the run fails.
func TestTheLivePolicyRunStartsTheSelfCheckAndJudgesIt(t *testing.T) {
	r, args := livePolicyRun(t, selfCheckOutput, 0, time.Minute)
	if args != "probe-acl --self-check --against /captures/observed\n" {
		t.Errorf("the stand-in was started with %q", args)
	}
	if len(r.errorsOf()) != 0 || len(r.events) != 10 {
		t.Errorf("a complete run: %d events, problems %q", len(r.events), r.errorsOf())
	}
	for _, e := range r.events {
		if strings.Contains(e, "probe-acl: A-1") {
			t.Errorf("a progress line of the probe is logged: %q", e)
		}
	}

	// Nothing printed and exit 0: a run whose self-check was dropped is not a pass.
	r, _ = livePolicyRun(t, "", 0, time.Minute)
	if !slices.Contains(r.errorsOf(), "the self-check printed no closing count") {
		t.Errorf("a silent self-check: %q", r.events)
	}

	// The probe makes SelfCheckCount() checks; a run that made fewer fails.
	dropped := "self-check: reformat held 2\nself-check: round-trip held 0\nself-check: summary held 12\nself-check: etag held 1\nself-check: 4 checks, all held\n"
	r, _ = livePolicyRun(t, dropped, 0, time.Minute)
	if !slices.Contains(r.errorsOf(), "the self-check made 4 checks, and the run must make 9") {
		t.Errorf("a self-check without its shapes: %q", r.events)
	}

	// A failing run logs every line before it fails, and fails on the exit and the check.
	failing := strings.Replace(selfCheckOutput, "shape: H-1 same", "shape: H-1 differs: 3 paths", 1)
	failing = strings.Replace(failing, "self-check: 9 checks, all held", "self-check: 9 checks, 1 not held", 1)
	r, _ = livePolicyRun(t, failing, 1, time.Minute)
	firstError := slices.IndexFunc(r.events, func(e string) bool { return strings.HasPrefix(e, "error: ") })
	if firstError != 10 || !slices.Contains(r.events, "log: shape: H-1 differs: 3 paths") {
		t.Errorf("the lines were not all logged before the first problem (at %d): %q", firstError, r.events)
	}
	for _, want := range []string{"self-check exit 1", "1 checks did not hold"} {
		if !slices.Contains(r.errorsOf(), want) {
			t.Errorf("problems %q lack %q", r.errorsOf(), want)
		}
	}

	// A self-check that does not finish in time is a problem, and so is its exit.
	r, _ = livePolicyRun(t, "", 0, 300*time.Millisecond)
	if !slices.Contains(r.errorsOf(), "the self-check did not finish in time") {
		t.Errorf("a self-check that ran out of time: %q", r.events)
	}

	// A binary that cannot be started is fatal, not a pass of nothing.
	r = &recorder{}
	checkLivePolicy(r, filepath.Join(t.TempDir(), "absent"), stubEnv, "/captures/observed", time.Minute)
	if !slices.Contains(r.events, "fatal") || len(r.events) != 1 {
		t.Errorf("a binary that cannot start: %q", r.events)
	}
}

// TestLivePolicy runs only for a live run, so no test can run it: this one reads its body and
// holds it to the one thing it is for, to hand the tagged binary, the owner's environment and
// the committed captures to checkLivePolicy. The captures are the files the shapes are
// compared with, one for each shape the probe checks.
func TestTheLivePolicyTestRunsTheSelfCheckOnTheCommittedCaptures(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "live_policy_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var calls []*ast.CallExpr
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "TestLivePolicy" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "checkLivePolicy" {
					calls = append(calls, c)
				}
			}
			return true
		})
	}
	if len(calls) != 1 || len(calls[0].Args) != 5 {
		t.Fatalf("TestLivePolicy makes %d calls of checkLivePolicy", len(calls))
	}
	args := calls[0].Args
	if id, ok := args[1].(*ast.Ident); !ok || id.Name != "probeBin" {
		t.Errorf("TestLivePolicy does not run the tagged binary")
	}
	if c, ok := args[2].(*ast.CallExpr); !ok || fmt.Sprint(c.Fun) != "liveEnv" {
		t.Errorf("TestLivePolicy does not run it in the owner's environment")
	}
	if id, ok := args[3].(*ast.Ident); !ok || id.Name != "against" {
		t.Errorf("TestLivePolicy does not compare the shapes with captures")
	}
	dir, err := capturesDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"A-1", "A-8", "A-9", "A-10", "H-1"} {
		if _, err := os.Stat(filepath.Join(dir, id+".json")); err != nil {
			t.Errorf("the capture of %s is not in the captures directory: %v", id, err)
		}
	}
}

func TestVersionPairDiffsTheLastRowOfThePageWithItself(t *testing.T) {
	log := filepath.Join(t.TempDir(), "calls")
	stub := stubBinary(t, `echo "$*" >> "$STUB_LOG"
printf '%s\n' '{"status":"equal"}'
`)
	l := newLiveRun(stub, append([]string{"STUB_LOG=" + log}, stubEnv...), nil)
	l.results = append(l.results, liveOutcome{tool: "acl_history", outcome: outcomeOK}, liveOutcome{tool: "acl_diff", outcome: outcomeOK})
	l.versionPair(map[string]any{"versions": []any{
		map[string]any{"version": "v-first.example"}, map[string]any{"version": "v-middle.example"}, map[string]any{"version": "v-last.example"},
	}})
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if want := "--json acl diff --from-version v-last.example --to-version v-last.example\n"; string(b) != want {
		t.Errorf("calls %q, want %q", b, want)
	}
	if len(l.problems) != 0 {
		t.Errorf("problems %q", l.problems)
	}
	if got := lastVersion(map[string]any{"versions": []any{map[string]any{"version": "a"}, map[string]any{"version": "b"}}}); got != "b" {
		t.Errorf("lastVersion %q, want the last row of the page", got)
	}
	// An empty history names nothing: none, not a failure, and no call.
	empty := newLiveRun(stub, append([]string{"STUB_LOG=" + filepath.Join(t.TempDir(), "none")}, stubEnv...), nil)
	empty.results = append(empty.results, liveOutcome{tool: "acl_history", outcome: outcomeOK})
	empty.versionPair(map[string]any{"versions": []any{}})
	if !slices.Contains(empty.notes, "acl_diff: version pair none") || empty.calls != 0 {
		t.Errorf("notes %q, calls %d", empty.notes, empty.calls)
	}
}

// A version compared with itself must come back equal: a pair that comes back changed, or
// as anything else, fails the run, and the problem names the field, not what was found.
func TestAVersionPairThatIsNotEqualIsAProblem(t *testing.T) {
	for _, status := range []string{"changed", "invalid", "unknown", ""} {
		stub := stubBinary(t, "printf '%s\\n' \"$STUB_DIFF\"\n")
		l := newLiveRun(stub, append([]string{`STUB_DIFF={"status":"` + status + `"}`}, stubEnv...), nil)
		l.results = append(l.results, liveOutcome{tool: "acl_history", outcome: outcomeOK})
		l.versionPair(map[string]any{"versions": []any{map[string]any{"version": "v-one.example"}}})
		if !slices.Contains(l.problems, "acl_diff: field status is not equal") {
			t.Errorf("status %q: problems %q", status, l.problems)
		}
		for _, line := range append(l.notes, l.problems...) {
			if status != "" && strings.Contains(line, status) || strings.Contains(line, "v-one.example") {
				t.Errorf("status %q: a line repeats what was found: %q", status, line)
			}
		}
	}
}

// dnsAndPseudonymRun runs every tool against a stand-in that answers dns get with dns and
// acl test with test, exiting exit, and logs each call to log.
func dnsAndPseudonymRun(t *testing.T, log, dns, test string, exit int) *liveRun {
	t.Helper()
	stub := stubBinary(t, `echo "$*" >> "$STUB_LOG"
case "$*" in
*"dns get"*) printf '%s\n' "$STUB_DNS" ;;
*"acl test"*) printf '%s\n' "$STUB_TEST"; exit "$STUB_EXIT" ;;
*"acl get"*) printf '{"warnings":[]}\n' ;;
*"users list"*) printf '%s\n' '{"users":[{"id":"u1","loginName":"a…@example.com [p:abcdefghij]"}]}' ;;
*) printf '{}\n' ;;
esac
`)
	l := newLiveRun(stub, append([]string{"STUB_LOG=" + log, "STUB_DNS=" + dns, "STUB_TEST=" + test, "STUB_EXIT=" + strconv.Itoa(exit)}, stubEnv...), nil)
	l.all()
	return l
}

func TestTheDNSAndPseudonymChecksAreMadeOnTheAnswer(t *testing.T) {
	const passing = `{"status":"pass","evaluatedAt":"2026-10-13T00:00:00Z","note":"n"}`
	log := filepath.Join(t.TempDir(), "calls")
	good := dnsAndPseudonymRun(t, log, `{"policyOverridesAnalysed":true}`, passing, 0)
	if slices.Contains(good.problems, "dns_get: field policyOverridesAnalysed is not true") || slices.Contains(good.problems, "acl_test: field status is not a typed status") {
		t.Errorf("a good run has problems %q", good.problems)
	}
	if b, _ := os.ReadFile(log); !strings.Contains(string(b), "--json acl test p:abcdefghij --deny 192.0.2.1:1\n") {
		t.Errorf("acl_test was not asked about the pseudonym users_list showed:\n%s", b)
	}
	bad := dnsAndPseudonymRun(t, filepath.Join(t.TempDir(), "calls"), `{"policyOverridesAnalysed":false}`, passing, 0)
	if !slices.Contains(bad.problems, "dns_get: field policyOverridesAnalysed is not true") {
		t.Errorf("a policy that was not analysed passed: %q", bad.problems)
	}
	// The status acl_test answers for a user is one of four; anything else is a problem.
	odd := dnsAndPseudonymRun(t, filepath.Join(t.TempDir(), "calls"), `{"policyOverridesAnalysed":true}`, `{"status":"bogus","evaluatedAt":"2026-10-13T00:00:00Z","note":"n"}`, 1)
	if !slices.Contains(odd.problems, "acl_test: field status is not a typed status") {
		t.Errorf("an untyped status passed: %q", odd.problems)
	}
}
