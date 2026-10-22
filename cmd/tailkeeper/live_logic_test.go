package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// These tests exercise the logic around the live calls (how an outcome is named,
// what the checks find, how an ID is found, what scripts/live-check.sh refuses)
// without the network and without a tailnet, so `make verify` runs them. None of
// them is named TestLive…, which is what `make live` selects: the live run counts
// exactly two passes.

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
	if c[outcomeFail] != 0 || len(all.problems) != 0 || c[outcomeUnavailable] != all.calls || c[outcomeOK] != 0 {
		t.Errorf("every tool listed: %d fail, %d unavailable, %d problems, %d calls", c[outcomeFail], c[outcomeUnavailable], len(all.problems), all.calls)
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
