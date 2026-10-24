package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tools"
	"github.com/abm9111/tailkeeper/internal/tripwire"
)

// The live tests read the tailnet the user configuration names, with the
// owner's real credential, through the built binary. They run only with
// TAILKEEPER_LIVE=1 (`make live`) and never print a value from the tailnet:
// only tool names, outcomes, error codes, sizes and counts. Everything a live
// test logs or reports is composed in this file from those five kinds of text,
// and scripts/live-check.sh prints nothing else from the run.
//
// The logic around the calls (how an outcome is named, what the checks look for,
// how an ID is found) is exercised without the network by live_logic_test.go, in
// `make verify`.

func liveOnly(t *testing.T) {
	t.Helper()
	if os.Getenv("TAILKEEPER_LIVE") != "1" {
		t.Skip("reads the configured tailnet; run with `make live`")
	}
}

// liveEnv is the caller's own environment: the real configuration, credential
// provider and audit log, without the coverage directory a -cover run adds.
func liveEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GOCOVERDIR=") {
			env = append(env, kv)
		}
	}
	return env
}

// callTimeout bounds one CLI call.
const callTimeout = 90 * time.Second

// The four outcomes of a tool. None of them comes from the tailnet.
const (
	outcomeOK          = "ok"          // answered, and every check held
	outcomeUnavailable = "unavailable" // the credential or plan does not cover it, as the owner said
	outcomeNone        = "none"        // nothing to name: the list that would name it was empty
	outcomeFail        = "fail"        // anything else
)

// liveOutcome is one tool's result. None of its fields comes from the tailnet.
type liveOutcome struct {
	tool    string
	outcome string
	code    string // the error code, for unavailable and fail
	bytes   int
	paths   int // personal-field paths the tool declares
	values  int // non-empty personal values the checks examined at those paths
}

// coverageCodes are the error codes that mean the credential's scopes or the
// tailnet's plan do not cover a tool. not_found is one only because the owner lists
// the tool: Tailscale has answered 404 to documented list paths (user invites, OAuth
// apps) on a tailnet whose plan has neither, and for a tool nobody listed a 404 is
// still a failure, since it can also mean a wrong path.
var coverageCodes = map[string]bool{"scope_missing": true, "feature_unavailable": true, "payment_required": true, "not_found": true}

// outcomeOf names the outcome of a call of tool that ended in the error code code.
// A coverage code makes a tool unavailable only when the owner listed it as not
// covered (`make live LIVE_UNAVAILABLE=…`); for any other tool it is a failure, so a
// credential with no usable scope cannot pass by being "unavailable" everywhere.
func outcomeOf(tool, code string, uncovered map[string]bool) string {
	if coverageCodes[code] && uncovered[tool] {
		return outcomeUnavailable
	}
	return outcomeFail
}

// parseUncovered reads the comma list in TAILKEEPER_LIVE_UNAVAILABLE. Names that
// are not tools are returned apart: a typo must not silently fail to excuse
// anything, nor look like it did.
func parseUncovered(list string, known func(string) bool) (set map[string]bool, unknown []string) {
	set = map[string]bool{}
	for _, name := range strings.Split(list, ",") {
		switch name = strings.TrimSpace(name); {
		case name == "":
		case !known(name):
			unknown = append(unknown, name)
		default:
			set[name] = true
		}
	}
	sort.Strings(unknown)
	return set, unknown
}

// codeRE is the shape of an error code. A "code" in a child's output that does not
// have it is not shown.
var codeRE = regexp.MustCompile(`^[a-z][a-z_]{0,39}$`)

// safeCode returns code if it has the shape of an error code, and a fixed word if not.
func safeCode(code string) string {
	if code == "" || codeRE.MatchString(code) {
		return code
	}
	return "unrecognised"
}

// emailRE finds an email address. A masked one keeps one character, then "…", then
// the domain: the character before its at sign is the ellipsis, which is not in the
// class, so a masked address is not found and a whole one is, whatever its length.
var emailRE = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+`)

// valuesAt returns the strings at a registry path such as "devices[].user".
func valuesAt(v any, path string) []string {
	if path == "" {
		switch x := v.(type) {
		case string:
			return []string{x}
		case []any:
			var out []string
			for _, e := range x {
				out = append(out, valuesAt(e, "")...)
			}
			return out
		}
		return nil
	}
	head, rest, _ := strings.Cut(path, ".")
	list := strings.HasSuffix(head, "[]")
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	next := m[strings.TrimSuffix(head, "[]")]
	if !list {
		return valuesAt(next, rest)
	}
	items, _ := next.([]any)
	var out []string
	for _, it := range items {
		out = append(out, valuesAt(it, rest)...)
	}
	return out
}

// checks are what every result must satisfy with the default configuration. A
// problem names the path or the kind of problem, never the value that caused it.
// examined counts the non-empty personal values it looked at: a count of zero for a
// tool that declares personal paths shows a path that matched nothing, which would
// otherwise look like a masking check that passed.
func checks(raw []byte, doc map[string]any, personal []string) (problems []string, examined int) {
	if tripwire.Check(raw) != nil {
		problems = append(problems, "the tripwire matched the output")
	}
	for _, p := range personal {
		flagged := false
		for _, v := range valuesAt(doc, p) {
			if v == "" {
				continue
			}
			examined++
			if !flagged && !strings.Contains(v, "…") && !sanitize.IsTaggedDevices(v) {
				problems = append(problems, "the personal field "+p+" is not masked")
				flagged = true
			}
		}
	}
	if n := len(emailRE.FindAll(raw, -1)); n > 0 {
		problems = append(problems, fmt.Sprintf("%d whole email addresses", n))
	}
	return problems, examined
}

// discovery is what an earlier result yields for a tool that needs one thing named:
// the first usable value, and how many candidates the result held. A tool with no
// value is "none" only when there were no candidates; with candidates and no value,
// the path that was read is wrong, and that is a failure, not a pass.
type discovery struct {
	id   string
	rows int
}

// pick returns the first non-empty string at field in the rows of the list at key.
func pick(doc map[string]any, key, field string) discovery {
	rows, _ := doc[key].([]any)
	d := discovery{rows: len(rows)}
	for _, r := range rows {
		if m, ok := r.(map[string]any); ok {
			if s, ok := m[field].(string); ok && s != "" {
				d.id = s
				break
			}
		}
	}
	return d
}

// pickString returns the first non-empty string of the list of strings at key.
func pickString(doc map[string]any, key string) discovery {
	items, _ := doc[key].([]any)
	d := discovery{rows: len(items)}
	for _, it := range items {
		if s, ok := it.(string); ok && s != "" {
			d.id = s
			break
		}
	}
	return d
}

// selfDNSName returns this node's MagicDNS name from local_status: a name the
// default configuration lets local_dns_query resolve. A status that came back
// without it is a wrong path, not an absence (a running node always has one).
func selfDNSName(status map[string]any) discovery {
	if status == nil {
		return discovery{}
	}
	self, _ := status["self"].(map[string]any)
	s, _ := self["dnsName"].(string)
	return discovery{id: s, rows: 1}
}

// onlinePeer returns a tailnet address of the first online peer, for local_ping.
// With no peer online there is nothing to ping; but peers that say nothing about
// being online mean the path is wrong, and count as candidates.
func onlinePeer(status map[string]any) discovery {
	peers, _ := status["peers"].([]any)
	var d discovery
	saysOnline := false
	for _, p := range peers {
		m, _ := p.(map[string]any)
		online, has := m["online"].(bool)
		saysOnline = saysOnline || has
		if !online {
			continue
		}
		d.rows++
		if d.id == "" {
			if ips, _ := m["tailscaleIps"].([]any); len(ips) > 0 {
				d.id, _ = ips[0].(string)
			}
		}
	}
	if !saysOnline && len(peers) > 0 {
		d.rows = len(peers)
	}
	return d
}

// exitCode returns the exit status of a command that ended in err: 0 for none, -1
// when it did not exit (it could not start, or a signal ended it).
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// wantedExit returns the exit status the tool's result says the process should have
// had: 0, unless the tool's output type carries its own status (ExitCode: a failed
// acl test exits 9), which is then read from the document the process printed.
// ok is false when the document does not decode as the tool's output.
func wantedExit(tool registry.Tool, raw []byte) (want int, ok bool) {
	if _, carries := tool.OutputType.MethodByName("ExitCode"); !carries {
		return 0, true
	}
	v := reflect.New(tool.OutputType)
	if json.Unmarshal(raw, v.Interface()) != nil {
		return 0, false
	}
	ec, isEC := v.Elem().Interface().(interface{ ExitCode() int })
	if !isEC {
		return 0, false
	}
	return ec.ExitCode(), true
}

// exitText names how a command that ended in err ended, without its output.
func exitText(err error) string {
	if err == nil {
		return "exit 0"
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return "exit " + strconv.Itoa(ee.ExitCode())
	}
	return "did not run"
}

// why names a failed client call by its kind. The text of such an error can echo
// what the server said, so it is not shown.
func why(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timed out"
	}
	return "failed"
}

// liveRun runs every tool once through the binary bin and records what happened.
// It never keeps or prints a tool's output, only the outcome.
type liveRun struct {
	bin       string
	env       []string
	reg       *registry.Registry
	uncovered map[string]bool
	results   []liveOutcome
	problems  []string // "<tool>: <kind of problem>", fit to print
	notes     []string // counts and fixed sentences, fit to print
	calls     int      // tool processes started: each appends one line to the audit log
	probeRuns int      // doctor --probe processes started: each appends at least one line
	// probeLines is the lines the doctor probe added to the audit log, as the log counted them
	// before and after it. They count toward the audit lower bound with calls.
	probeLines int
	ran        map[string]bool
}

// auditLowerBound is the audit lines the run is known to have written: one for each tool
// call, and the lines the doctor probe wrote.
func (l *liveRun) auditLowerBound() int { return l.calls + l.probeLines }

// maxProcesses is how many processes the run has started.
func (l *liveRun) maxProcesses() int { return l.calls + l.probeRuns }

func liveRegistry() *registry.Registry {
	reg := registry.New()
	tools.Register(reg)
	return reg
}

func newLiveRun(binary string, env []string, uncovered map[string]bool) *liveRun {
	return &liveRun{bin: binary, env: env, reg: liveRegistry(), uncovered: uncovered, ran: map[string]bool{}}
}

func (l *liveRun) problem(tool, kind string) { l.problems = append(l.problems, tool+": "+kind) }

func (l *liveRun) note(s string) { l.notes = append(l.notes, s) }

// answered reports whether the tool's own row was an answer. A further call is made
// only then: a credential that no tool accepts must not grow the call count past the rows.
func (l *liveRun) answered(name string) bool {
	for i := len(l.results) - 1; i >= 0; i-- {
		if l.results[i].tool == name {
			return l.results[i].outcome == outcomeOK
		}
	}
	return false
}

// callWithFile runs the tool's CLI command with a flag that names a file holding content.
func (l *liveRun) callWithFile(name, content, flag string) map[string]any {
	return l.invokeFile(name, content, flag, true)
}

// extraCallWithFile is callWithFile for a tool that already has its row.
func (l *liveRun) extraCallWithFile(name, content, flag string) map[string]any {
	if !l.answered(name) {
		return nil
	}
	return l.invokeFile(name, content, flag, false)
}

func (l *liveRun) invokeFile(name, content, flag string, record bool) map[string]any {
	dir, err := os.MkdirTemp("", "tailkeeper-live-")
	if err != nil {
		l.problem(name, "cannot make a directory for its input file")
		return nil
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "input.hujson")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		l.problem(name, "cannot write its input file")
		return nil
	}
	return l.invoke(name, record, flag, path)
}

// call runs the tool's CLI command with extra arguments. It returns the result
// document when the tool answered, and nil otherwise.
func (l *liveRun) call(name string, extra ...string) map[string]any {
	return l.invoke(name, true, extra...)
}

// extraCall is a further call of a tool that already has its row. It counts toward
// the audit lower bound and adds no result row. It runs only when that row answered.
func (l *liveRun) extraCall(name string, extra ...string) map[string]any {
	if !l.answered(name) {
		return nil
	}
	return l.invoke(name, false, extra...)
}

func (l *liveRun) invoke(name string, record bool, extra ...string) map[string]any {
	tool, ok := l.reg.Get(name)
	if !ok {
		l.problem(name, "is not a registered tool")
		return nil
	}
	l.ran[name] = true
	l.calls++
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, l.bin, append([]string{"--json", tool.Meta.Area, tool.Meta.Verb}, extra...)...)
	cmd.Env = l.env
	var stdout strings.Builder
	cmd.Stdout = &stdout // stderr is discarded: it can quote the tailnet
	err := cmd.Run()
	raw := []byte(stdout.String())
	res := liveOutcome{tool: name, bytes: len(raw), outcome: outcomeFail}
	defer func() {
		if record {
			l.results = append(l.results, res)
		}
	}()

	if ctx.Err() != nil {
		res.code = "timeout"
		l.problem(name, "did not finish in time")
		return nil
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		res.code = "not JSON"
		l.problem(name, fmt.Sprintf("stdout is not one JSON document (%d bytes, %s)", len(raw), exitText(err)))
		return nil
	}
	if e, isErr := doc["error"].(map[string]any); isErr {
		code, _ := e["code"].(string)
		res.code = safeCode(code)
		res.outcome = outcomeOf(name, res.code, l.uncovered)
		if err == nil {
			res.outcome = outcomeFail
			l.problem(name, "printed an error document and exited 0")
		} else if res.outcome == outcomeFail {
			l.problem(name, fmt.Sprintf("failed with code %q (%s)", res.code, exitText(err)))
		}
		// An error is output too: the same checks (no credential shape, no whole
		// address) apply, though it has no personal fields.
		problems, _ := checks(raw, doc, nil)
		for _, p := range problems {
			res.outcome = outcomeFail
			l.problem(name, p)
		}
		return nil
	}
	// A result is an answer only if the process exited as the result says. Most
	// tools exit 0; a tool whose output carries its own status (a failed acl test
	// exits 9) must exit with that status. A crash that exits 1 and still prints a
	// document, or a failed test that exits 0, is not an answer.
	want, decoded := wantedExit(tool, raw)
	if !decoded {
		res.code = "undecodable"
		l.problem(name, "its result does not decode as its output type")
		return nil
	}
	if got := exitCode(err); got != want {
		res.code = "exit_mismatch"
		l.problem(name, fmt.Sprintf("exited %d, but its result says %d", got, want))
		return nil
	}
	res.outcome = outcomeOK
	problems, examined := checks(raw, doc, tool.PersonalFields)
	res.paths, res.values = len(tool.PersonalFields), examined
	for _, p := range problems {
		res.outcome = outcomeFail
		l.problem(name, p)
	}
	return doc
}

// get runs a tool that reads one thing, named by an earlier result. With nothing
// to name, the outcome is "none" (nothing was called) when there were no
// candidates, and a failure when there were: a discovery path that reads the
// wrong field must not make every get-tool pass as "none".
func (l *liveRun) get(name string, d discovery) map[string]any {
	if d.id != "" {
		return l.call(name, "--", d.id) // "--": an ID is never read as a flag
	}
	l.ran[name] = true
	if d.rows > 0 {
		l.results = append(l.results, liveOutcome{tool: name, outcome: outcomeFail, code: "no_id"})
		l.problem(name, fmt.Sprintf("the result it is named from held %d candidates, and the path read found no ID", d.rows))
		return nil
	}
	l.results = append(l.results, liveOutcome{tool: name, outcome: outcomeNone})
	return nil
}

// The copies sent to acl_validate besides the live policy. An empty patch is a no-op.
// The baseline patch adds one documentation host so the text is not the live policy byte
// for byte: a byte-identical text treats every warning as existing without reading the
// baseline.
const (
	emptyPatch       = "[]\n"
	baselinePatch    = "[{\"op\":\"add\",\"path\":\"/hosts/tk-live-check\",\"value\":\"192.0.2.1\"}]\n"
	baselineNewHosts = "[{\"op\":\"add\",\"path\":\"/hosts\",\"value\":{\"tk-live-check\":\"192.0.2.1\"}}]\n"
)

// all runs every tool once and checks that none was left out.
func (l *liveRun) all() {
	devices := l.call("devices_list")
	users := l.call("users_list")
	keys := l.call("keys_list")
	hooks := l.call("webhooks_list")
	services := l.call("services_list")
	posture := l.call("posture_integrations_list")
	userInvites := l.call("user_invites_list")
	apps := l.call("oauth_apps_list")
	aclGet := l.call("acl_get")
	history := l.call("acl_history")
	l.call("acl_validate")
	dns := l.call("dns_get")
	settings := l.call("settings_get")
	for _, name := range []string{"contacts_get", "audit_log", "network_flow_logs",
		"local_dns_status", "local_funnel_status", "local_lock_status", "local_metrics", "local_netcheck", "local_prefs",
		"local_serve_status", "local_syspolicy", "local_version", "local_whoami"} {
		l.call(name)
	}
	// acl_diff needs a side that is not the live policy: an empty object is the smallest
	// honest one, written to a file the command names.
	l.callWithFile("acl_diff", "{}\n", "--against")
	// Documentation addresses: the source exists nowhere. Tailscale may answer that
	// the test passes or that it fails (it cannot resolve the source); both are
	// its answer, read by the tool, and either exits as the tool says.
	tested := l.call("acl_test", "203.0.113.5", "--deny", "198.51.100.7:1")
	l.call("log_streaming_get", "configuration")
	ip := l.call("local_ip")
	status := l.call("local_status", "--peers")

	device := pick(devices, "devices", "nodeId")
	l.get("device_get", device)
	l.get("device_routes", device)
	l.get("device_posture_attributes", device)
	invites := l.get("device_invites_list", device)
	l.get("device_invite_get", pick(invites, "invites", "id"))
	l.get("user_get", pick(users, "users", "id"))
	l.get("key_get", pick(keys, "keys", "id"))
	l.get("webhook_get", pick(hooks, "webhooks", "endpointId"))
	l.get("service_get", pick(services, "services", "name"))
	l.get("posture_integration_get", pick(posture, "integrations", "id"))
	l.get("user_invite_get", pick(userInvites, "invites", "id"))
	l.get("oauth_app_get", pick(apps, "apps", "id"))
	l.get("local_whois", pickString(ip, "addresses"))
	l.get("local_ping", onlinePeer(status))
	// A name under this node's own MagicDNS suffix: the default configuration
	// lets local_dns_query resolve it.
	l.get("local_dns_query", selfDNSName(status))

	if l.answered("dns_get") && !l.uncovered["dns_get"] {
		l.field("dns_get", dns, "policyOverridesAnalysed", "true")
	}
	l.note(fmt.Sprintf("acl_get: stored warnings %d", countAt(aclGet, "warnings")))
	l.note(verdictNote(tested))
	l.policyCopies(countAt(aclGet, "warnings"))
	l.versionPair(history)
	l.pseudonymTest(users)
	l.gitopsOracle(settings)
	l.doctorProbe()

	l.verifyCoverage()
}

// policyCopies validates the live policy two further ways, neither of them a new row: an
// empty patch, and a copy that is not the live policy byte for byte so the warnings
// baseline is actually read. A copy whose own tests fail on the tailnet is a note: the
// tailnet's tests are the owner's, and the copy check was not made. The invariants path is
// not exercised: an empty file applies nothing, and no test is known to hold on the live
// policy, so the run says it was not run.
func (l *liveRun) policyCopies(stored int) {
	if !l.answered("acl_validate") {
		return
	}
	patched := l.extraCallWithFile("acl_validate", emptyPatch, "--patch")
	l.copyPassed(patched, "patch")
	l.note(fmt.Sprintf("acl_validate: patch new warnings %d", countAt(patched, "newWarnings")))

	l.note("acl_validate: invariants not run: no test is known to hold on the live policy, and an empty file proves nothing")

	baseline := l.extraCallWithFile("acl_validate", baselinePatch, "--patch")
	if got, _ := scalarAt(baseline, "status"); got == "invalid" {
		baseline = l.extraCallWithFile("acl_validate", baselineNewHosts, "--patch")
	}
	if l.copyPassed(baseline, "baseline") {
		l.field("acl_validate", baseline, "identicalToLive", "false")
		l.note(baselineNote(stored, baseline))
	}
}

// copyPassed reports whether a validated copy passed. A copy the tailnet's own tests fail
// (status fail) is a note naming the check that was not made: neither a failure of the
// harness nor a pass of the check. Any other status but pass is a problem.
func (l *liveRun) copyPassed(doc map[string]any, what string) bool {
	got, ok := scalarAt(doc, "status")
	if ok && got == "fail" {
		l.note("acl_validate: " + what + " copy check not made: the tailnet's own tests answered fail")
		return false
	}
	l.field("acl_validate", doc, "status", "pass")
	return ok && got == "pass"
}

// versionPair compares the last row of the first page acl_history returned with itself.
// The history is oldest first, so with more than one page that row is not the newest; a
// comparison of a version with itself is equal whichever row it is, so the check proves
// that a stored version can be read and diffed, not which one. An empty history names
// nothing, which is none, not a failure.
func (l *liveRun) versionPair(history map[string]any) {
	if !l.answered("acl_history") {
		return
	}
	version := lastVersion(history)
	if version == "" {
		l.note("acl_diff: version pair none")
		return
	}
	diff := l.extraCall("acl_diff", "--from-version", version, "--to-version", version)
	l.field("acl_diff", diff, "status", "equal")
}

// pseudonymTest asks acl_test about one user by the pseudonym users_list showed.
// With no pseudonym in the list there is nothing to ask, which is none, not a failure.
func (l *liveRun) pseudonymTest(users map[string]any) {
	if !l.answered("users_list") {
		l.note("acl_test: pseudonym none")
		return
	}
	ref := pseudonymOf(users)
	if ref == "" {
		l.note("acl_test: pseudonym none")
		return
	}
	doc := l.extraCall("acl_test", ref, "--deny", "192.0.2.1:1")
	got, ok := scalarAt(doc, "status")
	switch {
	case ok && (got == "pass" || got == "fail" || got == "unresolved" || got == "unknown"):
	default:
		l.problem("acl_test", "field status is not a typed status")
	}
}

// gitopsOracle compares the owner's policy file with the live policy when the owner
// asked and the settings say the policy is managed outside the admin console. The
// path is never printed. Without the variable the run says it was not requested.
func (l *liveRun) gitopsOracle(settings map[string]any) {
	src := envValue(l.env, "TAILKEEPER_LIVE_POLICY_SOURCE")
	if src == "" {
		l.note("GitOps oracle: not requested")
		return
	}
	managed, _ := scalarAt(settings, "externallyManaged")
	if !l.answered("settings_get") || managed != "true" {
		l.note("GitOps oracle: not run")
		return
	}
	diff := l.extraCall("acl_diff", "--against", src)
	l.field("acl_diff", diff, "status", "equal")
}

// doctorProbe runs doctor --probe. Exit 0, or 8 with a count of failing checks, is the
// probe's answer, and the rows are judged (judgeDoctorRows): the checks themselves are not
// printed, because a detail can quote the tailnet. An error document, any other exit, an
// output that is not one JSON document or holds no count is a failure, and so is output the
// other live checks would refuse. The probe writes audit lines of its own; they count toward
// the audit lower bound, and a probe that wrote none is a failure.
func (l *liveRun) doctorProbe() {
	before, measured := l.auditNow()
	l.probeRuns++
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, l.bin, "doctor", "--probe", "--json")
	cmd.Env = l.env
	var stdout strings.Builder
	cmd.Stdout = &stdout
	err := cmd.Run()
	timedOut := ctx.Err() != nil
	after, measuredAfter := l.auditNow()
	switch {
	case !measured || !measuredAfter:
		l.note("doctor: audit lines not measured")
	case after-before < 1:
		l.problem("doctor", "the probe wrote no audit line")
	default:
		l.probeLines += after - before
	}
	if timedOut {
		l.problem("doctor", "probe did not finish in time")
		return
	}
	l.doctorReport([]byte(stdout.String()), err)
}

// The rows of the doctor's report the live run reads by name. The four policy probes must
// read ok; a kind probe may read n/a, because a tailnet with no source for a kind (no tag, no
// host alias) has nothing to ask. The names are fixed words.
var (
	policyProbeRows = []string{"probe policy rejection", "probe details keys", "probe invariants canary", "probe ssh tests"}
	kindProbeRows   = []string{"probe tag", "probe host alias", "probe IPv4 address", "probe IPv6 address", "probe ICMP, port 0"}
)

// canaryTestRow is the row of the canary test, a test no policy can pass. It must be there, and
// it reads n/a only when the live policy defines no tag to build the test with.
const canaryTestRow = "probe acl_test"

// doctorReport judges the output of doctor --probe --json and the way the process ended.
func (l *liveRun) doctorReport(raw []byte, err error) {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		doc = nil
	}
	problems, _ := checks(raw, doc, nil)
	for _, p := range problems {
		l.problem("doctor", p)
	}
	if doc == nil {
		l.problem("doctor", fmt.Sprintf("probe printed no JSON document (%d bytes, %s)", len(raw), exitText(err)))
		return
	}
	if _, isErr := doc["error"].(map[string]any); isErr {
		code, _ := scalarAt(doc, "error.code")
		l.problem("doctor", fmt.Sprintf("probe printed an error document, code %q (%s)", safeCode(code), exitText(err)))
		return
	}
	exit := exitCode(err)
	if exit != 0 && exit != 8 {
		l.problem("doctor", fmt.Sprintf("probe exit %d", exit))
		return
	}
	failed, ok := scalarAt(doc, "failed")
	n, convErr := strconv.Atoi(failed)
	if !ok || convErr != nil || n < 0 {
		l.problem("doctor", "probe printed no count of failing checks")
		return
	}
	if (exit == 0) != (n == 0) {
		l.problem("doctor", fmt.Sprintf("probe exited %d but reports %d failing checks", exit, n))
		return
	}
	// A read probe is excused only for a tool whose own row came out unavailable: listed by
	// the owner and answered with a coverage code. A listed tool that failed another way is
	// not, so an api_error behind its probe's warning still fails the run.
	unavailable := map[string]bool{}
	for _, r := range l.results {
		if r.outcome == outcomeUnavailable {
			unavailable[r.tool] = true
		}
	}
	problems, notes := judgeDoctorRows(doc, n, unavailable)
	for _, p := range problems {
		l.problem("doctor", p)
	}
	for _, note := range notes {
		l.note("doctor: " + note)
	}
	l.note("doctor: " + failed + " failing checks")
}

// rowNameRE is a row name fit to print: the fixed words the doctor names its rows with. Any
// other name, which could carry a value from the tailnet, is printed as "a row".
var rowNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9 ,_-]{0,40}$`)

// judgeDoctorRows reads the rows of a doctor report. failed is the count the report states.
// A row that fails is a problem, and so is a count that is not the number of rows that fail.
// The canary test and each of the four policy probes must read ok, and the canary test may
// read n/a when the live policy defines no tag, which is a note. A kind probe must read ok, or
// n/a when the tailnet has no source for the kind, which is a note. A row named probe that warns is a
// problem, and so is a probe row that is absent: a reading not established is never a pass. The
// one exception is the read probe of a tool whose own row came out unavailable (listed by the
// owner and answered with a coverage code): its warning is a note, since that row already says
// the tool is not covered; the canary test,
// the policy probes and the kind probes are never excused. A warning on any other row is the
// owner's to read in doctor, not the probe's. Every line names a row and its status, never its
// detail.
func judgeDoctorRows(doc map[string]any, failed int, unavailable map[string]bool) (problems, notes []string) {
	rows, _ := doc["checks"].([]any)
	seen := map[string]bool{}
	failing := 0
	for _, raw := range rows {
		row, _ := raw.(map[string]any)
		name, _ := row["name"].(string)
		status, _ := row["status"].(string)
		seen[name] = true
		label := "a row"
		if rowNameRE.MatchString(name) {
			label = name
		}
		isPolicy, isKind, isCanary := slices.Contains(policyProbeRows, name), slices.Contains(kindProbeRows, name), name == canaryTestRow
		reads := func() string { return label + " reads " + status }
		switch status {
		case "ok":
		case "info":
			if isPolicy || isKind || isCanary {
				problems = append(problems, reads())
			}
		case "n/a":
			switch {
			case isPolicy:
				problems = append(problems, reads())
			case isKind:
				notes = append(notes, label+" not probed: no source in the tailnet")
			case isCanary:
				notes = append(notes, label+" not probed: the live policy defines no tag")
			}
		case "warn":
			switch {
			case !strings.HasPrefix(name, "probe "):
			case !isPolicy && !isKind && !isCanary && unavailable[strings.TrimPrefix(name, "probe ")]:
				notes = append(notes, reads()+": the tool is listed as unavailable")
			default:
				problems = append(problems, reads())
			}
		case "fail":
			failing++
			problems = append(problems, reads())
		default:
			problems = append(problems, label+" reads an unknown status")
		}
	}
	for _, name := range append(append([]string{canaryTestRow}, policyProbeRows...), kindProbeRows...) {
		if !seen[name] {
			problems = append(problems, name+" is absent")
		}
	}
	if failing != failed {
		problems = append(problems, fmt.Sprintf("the count of failing checks is %d and %d rows fail", failed, failing))
	}
	return problems, notes
}

// auditNow counts the lines of the audit log of the run's environment. ok is false when the
// count could not be read.
func (l *liveRun) auditNow() (n int, ok bool) {
	n, err := auditCountOf(l.bin, l.env)
	return n, err == nil
}

// field checks one scalar in a result. The problem names the path and the wanted
// value, never the value that was there.
func (l *liveRun) field(tool string, doc map[string]any, path, want string) {
	got, ok := scalarAt(doc, path)
	if !ok || got != want {
		l.problem(tool, "field "+path+" is not "+want)
	}
}

// scalarAt reads a dotted path of object keys. A missing path is not a value.
func scalarAt(doc map[string]any, path string) (string, bool) {
	var cur any = doc
	for _, part := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[part]
			if !ok {
				return "", false
			}
			cur = next
		default:
			return "", false
		}
	}
	switch v := cur.(type) {
	case string:
		return v, true
	case bool:
		return strconv.FormatBool(v), true
	case float64:
		return strconv.FormatInt(int64(v), 10), true
	default:
		return "", false
	}
}

// countAt is the length of the array at path, or 0 when the path is absent.
func countAt(doc map[string]any, path string) int {
	var cur any = doc
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return 0
		}
		cur = m[part]
	}
	rows, _ := cur.([]any)
	return len(rows)
}

// lastVersion is the version of the last row of the page: the newest only when the history
// fits on one page.
func lastVersion(doc map[string]any) string {
	rows, _ := doc["versions"].([]any)
	if len(rows) == 0 {
		return ""
	}
	last, _ := rows[len(rows)-1].(map[string]any)
	s, _ := last["version"].(string)
	return s
}

func pseudonymOf(doc map[string]any) string {
	rows, _ := doc["users"].([]any)
	for _, row := range rows {
		m, _ := row.(map[string]any)
		s, _ := m["loginName"].(string)
		if ref, ok := privacy.Ref(s); ok {
			return ref
		}
	}
	return ""
}

func verdictNote(doc map[string]any) string {
	var allowed, denied, unresolved, unknown int
	rows, _ := doc["verdicts"].([]any)
	for _, row := range rows {
		m, _ := row.(map[string]any)
		switch m["verdict"] {
		case "allowed":
			allowed++
		case "denied":
			denied++
		case "unresolved":
			unresolved++
		case "unknown":
			unknown++
		}
	}
	return fmt.Sprintf("acl_test: verdicts allowed %d, denied %d, unresolved %d, unknown %d, unmatched %d",
		allowed, denied, unresolved, unknown, countAt(doc, "unmatched"))
}

// baselineNote records how the word-for-word warning rule classified the copy.
// The warning text is not part of the line.
func baselineNote(stored int, doc map[string]any) string {
	existing := countAt(doc, "existingWarnings")
	newer := countAt(doc, "newWarnings")
	var spelling string
	switch {
	case stored == 0:
		spelling = "none"
	case existing > 0:
		spelling = "matched"
	default:
		spelling = "differed"
	}
	return fmt.Sprintf("acl_validate: baseline stored %d, existing %d, new %d, spelling %s", stored, existing, newer, spelling)
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			return kv[len(prefix):]
		}
	}
	return ""
}

// verifyCoverage adds a problem for every registered tool the run did not exercise,
// and one if the results are not exactly one per tool. A tool added to the registry
// without a line in all() is caught here, not left out of the acceptance run unseen.
func (l *liveRun) verifyCoverage() {
	all := l.reg.All()
	for _, tool := range all {
		if !l.ran[tool.Meta.Name] {
			l.problem(tool.Meta.Name, "was not exercised: add it to liveRun.all")
		}
	}
	if len(l.results) != len(all) {
		l.problem("all", fmt.Sprintf("%d results for %d tools", len(l.results), len(all)))
	}
}

// auditGrowthProblem compares the audit log's line count before and after a run that
// started calls processes, each of which appends one line. The check is a lower
// bound: other tailkeeper processes (the owner's own MCP server, in an agent
// session) can append during the run, so more growth than calls is fine; less means
// some calls went unaudited, or the log was cut or rotated meanwhile. "" means none.
func auditGrowthProblem(before, after, calls int) string {
	if after-before >= calls {
		return ""
	}
	return fmt.Sprintf("the audit log grew by %d lines for %d calls", after-before, calls)
}

// counts tallies the outcomes.
func (l *liveRun) counts() map[string]int {
	c := map[string]int{}
	for _, r := range l.results {
		c[r.outcome]++
	}
	return c
}

// names returns the tools with the outcome, sorted.
func (l *liveRun) names(outcome string) []string {
	var out []string
	for _, r := range l.results {
		if r.outcome == outcome {
			out = append(out, r.tool)
		}
	}
	sort.Strings(out)
	return out
}

// dash shows an empty cell.
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// auditRE reads the first line `tailkeeper audit verify` prints: the live log,
// then the archives it continues, each on a line of its own.
var auditRE = regexp.MustCompile(`^[^\n]*: (\d+) lines, chain intact\n`)

// auditCountOf returns how many lines the audit log of the environment env holds, from the
// first line `tailkeeper audit verify` (run as binary) prints. It is an error when the chain
// is not intact or the log cannot be read.
func auditCountOf(binary string, env []string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "audit", "verify")
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("tailkeeper audit verify failed (%s)", exitText(err))
	}
	m := auditRE.FindSubmatch(out)
	if m == nil {
		return 0, errors.New("tailkeeper audit verify did not report an intact chain on its first line")
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return 0, errors.New("tailkeeper audit verify printed a line count that is not a number")
	}
	return n, nil
}

// auditLinesOf is auditCountOf that fails the test when the count cannot be read.
func auditLinesOf(t *testing.T, binary string, env []string) int {
	t.Helper()
	n, err := auditCountOf(binary, env)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// auditLines is auditLinesOf for the live environment.
func auditLines(t *testing.T) int {
	t.Helper()
	return auditLinesOf(t, bin, liveEnv())
}

func TestLiveReads(t *testing.T) {
	liveOnly(t)
	reg := liveRegistry()
	uncovered, unknown := parseUncovered(os.Getenv("TAILKEEPER_LIVE_UNAVAILABLE"), func(name string) bool { _, ok := reg.Get(name); return ok })
	if len(unknown) > 0 {
		t.Fatalf("TAILKEEPER_LIVE_UNAVAILABLE names %d entries that are not tools: %q", len(unknown), unknown)
	}
	listed := make([]string, 0, len(uncovered))
	for name := range uncovered {
		listed = append(listed, name)
	}
	sort.Strings(listed)
	t.Logf("tools allowed to be unavailable (make live LIVE_UNAVAILABLE=…): %d: %s", len(listed), dash(strings.Join(listed, ", ")))

	l := newLiveRun(bin, liveEnv(), uncovered)
	before := auditLines(t)
	l.all()
	for _, n := range l.notes {
		t.Log(n)
	}
	for _, p := range l.problems {
		t.Errorf("%s", p)
	}
	for _, r := range l.results {
		t.Logf("%-28s %-11s %-22s %8d bytes %2d personal paths %5d personal values examined",
			r.tool, r.outcome, dash(r.code), r.bytes, r.paths, r.values)
	}
	counts := l.counts()
	t.Logf("summary: %d tools: %d ok, %d unavailable, %d none, %d fail",
		len(l.results), counts[outcomeOK], counts[outcomeUnavailable], counts[outcomeNone], counts[outcomeFail])
	var paths, values int
	for _, r := range l.results {
		paths += r.paths
		values += r.values
	}
	t.Logf("personal values examined: %d, at %d declared paths", values, paths)
	if none := l.names(outcomeNone); len(none) > 0 {
		t.Logf("none, so nothing was called for: %s", strings.Join(none, ", "))
	}
	var answered []string
	for _, name := range l.names(outcomeOK) {
		if uncovered[name] {
			answered = append(answered, name)
		}
	}
	if len(answered) > 0 {
		t.Logf("listed as unavailable, yet answered: %s", strings.Join(answered, ", "))
	}
	// The audit check is a lower bound (see auditGrowthProblem).
	if p := auditGrowthProblem(before, auditLines(t), l.auditLowerBound()); p != "" {
		t.Errorf("%s", p)
	}
}

// mcpDevicesList starts `mcp` as binary in env, lists the tools it advertises, and
// calls devices_list once. It returns how many tools were advertised and the result.
func mcpDevicesList(t *testing.T, binary string, env []string) (advertised int, res *mcp.CallToolResult) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.Command(binary, "mcp")
	cmd.Env = env
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "live", Version: "1"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("mcp: connect %s", why(err))
	}
	defer func() { _ = cs.Close() }()
	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("mcp: tools/list %s", why(err))
	}
	found := false
	for _, tl := range list.Tools {
		found = found || tl.Name == "devices_list"
	}
	if !found {
		t.Fatalf("mcp: devices_list is not among the %d tools advertised", len(list.Tools))
	}
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "devices_list", Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("mcp: devices_list %s", why(err))
	}
	return len(list.Tools), res
}

func TestLiveMCP(t *testing.T) {
	liveOnly(t)
	advertised, res := mcpDevicesList(t, bin, liveEnv())
	t.Logf("mcp: %d tools advertised", advertised)
	problems, size, examined := checkDevicesResult(res)
	for _, p := range problems {
		t.Errorf("mcp: devices_list: %s", p)
	}
	if len(problems) == 0 {
		t.Logf("mcp: devices_list: %d bytes, checks passed (%d personal values examined)", size, examined)
	}
}

// checkDevicesResult applies the checks of every result to devices_list's answer
// over MCP, and returns the problems and the size of the result.
func checkDevicesResult(res *mcp.CallToolResult) (problems []string, size, examined int) {
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		return []string{"the result cannot be encoded"}, 0, 0
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil || doc == nil {
		return []string{"the result is not one JSON document"}, len(raw), 0
	}
	if res.IsError {
		e, _ := doc["error"].(map[string]any)
		code, _ := e["code"].(string)
		return []string{fmt.Sprintf("returned a tool error, code %q", safeCode(code))}, len(raw), 0
	}
	tool, _ := liveRegistry().Get("devices_list")
	problems, examined = checks(raw, doc, tool.PersonalFields)
	return problems, len(raw), examined
}
