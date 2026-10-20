package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/tailscale/hujson"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
)

func runAll(t *testing.T, w *world, o Options) []Result {
	t.Helper()
	return Run(context.Background(), w.f.Client(t), All(), o)
}

// The probe table (docs/design.md §22) is registered whole and in order, each row with its three texts.
func TestAppendixBIsRegistered(t *testing.T) {
	want := []string{"A-1", "A-2", "A-3", "A-4", "A-5", "A-6", "A-7", "A-8", "A-9", "A-10", "A-11", "A-12", "A-13", "A-14", "H-1"}
	all := All()
	if len(all) != len(want) || len(registered) != len(want) {
		t.Fatalf("%d probes and %d registered rows, want %d", len(all), len(registered), len(want))
	}
	for i, p := range all {
		if p.ID != want[i] {
			t.Errorf("probe %d is %s, want %s", i, p.ID, want[i])
		}
		if p.Title == "" || p.Sends == "" || p.Expected == "" || p.Branch == "" || p.Run == nil {
			t.Errorf("%s is incomplete: %+v", p.ID, p)
		}
	}
}

// The pre-registered expectations are the table's, quoted. A few anchors from each end of
// the table catch a row that was edited or shifted when it was copied.
func TestRegisteredRowsAreTheSpecsText(t *testing.T) {
	for id, sub := range map[string][]string{
		"A-1":  {"If the control passes, the probe does not discriminate", "Policy mode, `{\"tagOwners\":{\"tag:p\":[]}", "is redesigned before any reading"},
		"A-4":  {"whose second rule has no `dst`", "replaces whole, with no element-wise merge", "the server merges repeated arrays element-wise"},
		"A-6":  {"500 both times", "The retry-once rule and its hint"},
		"A-9":  {"CIDR and `autogroup:internet` come back unevaluable", "the canary yields one `assertion_failed` line with its `src`"},
		"A-13": {"Equal", "\"Identical to live\" without a request"},
		"H-1":  {"Yes (the documentation promises a full diff)", "`acl_history` in 0.6.0 or metadata in 0.7.0"},
	} {
		r := registered[id]
		all := r.Sends + "\n" + r.Expected + "\n" + r.Branch
		for _, s := range sub {
			if !strings.Contains(all, s) {
				t.Errorf("%s lacks %q", id, s)
			}
		}
	}
}

// registeredRef finds what a public reader cannot look up: a review ID (bare or in
// brackets), the word spec, an appendix of the private document, a section sign with a
// number, a section number in brackets, and the section numbers the rows once carried
// in running text.
var registeredRef = regexp.MustCompile(`(?i)\b(?:SR|PL|SEM|MNT|ADV|USR|OWN)-[A-Z]*[0-9]+|\bspec\b|Appendix [AB]\b|§\s*[0-9]|\([0-9]+\.[0-9]+(?:\.[0-9]+)?\)|\bthe [0-9]\.[0-9] |\b(?:in|of) [0-9]\.[0-9]+;`)

// The rows carry the table's text without its review IDs, its section numbers and its
// appendix names: a public reader has no document to look them up in.
func TestRegisteredRowsCarryNoReviewIDSpecOrSectionReference(t *testing.T) {
	for id, r := range registered {
		if m := registeredRef.FindString(r.Sends + "\n" + r.Expected + "\n" + r.Branch); m != "" {
			t.Errorf("%s still carries %q", id, m)
		}
	}
	// The detector can fail, and leaves version numbers and addresses alone.
	// (The samples are written in two pieces so that this file carries none of what it looks for.)
	for text, hit := range map[string]bool{
		"x (SR" + "-M10)": true, "x SR" + "-M10": true, "x [SR" + "-M10]": true, "x (§2" + ".3)": true, "x § 2": true, "x (2" + ".3.1)": true,
		"x (2" + ".3)": true, "x per spec" + " 2" + ".3": true, "x (PL" + "-4)": true, "x PL" + "-4": true, "x (Appendix" + " B)": true,
		"Appendix" + " A": true, "x in 2" + ".1; y": true, "x (0" + ".6.0)": true,
		"in 0.6.0 or metadata in 0.7.0": false, "dst 100.64.0.1:22": false, "a specific row": false,
		"a hospital-4 row": false, "an SR- prefix": false,
	} {
		if got := registeredRef.MatchString(text); got != hit {
			t.Errorf("%q: matched %v, want %v", text, got, hit)
		}
	}
}

// In the world the probe table expects, every probe runs, nothing is skipped, and every
// expectation the harness can test holds. A check that cannot come out true, or a path
// that never matches, shows here.
func TestEveryProbeFindsTheSpecsWorld(t *testing.T) {
	w := newWorld(t)
	w.auditLogs = []map[string]any{
		{"eventTime": "2026-10-01T00:00:00Z", "action": "UPDATE", "old": liveText, "new": strings.Replace(liveText, "tag:live", "tag:live2", 1)},
		{"eventTime": "2026-10-02T00:00:00Z", "action": "UPDATE", "old": "{\"acls\": []}", "new": "{\"acls\": [], \"hosts\": {}}"},
	}
	rs := runAll(t, w, opts())
	if len(rs) != 15 {
		t.Fatalf("%d results", len(rs))
	}
	for _, r := range rs {
		if r.Error != "" || r.NotRun || len(r.Skipped) > 0 {
			t.Errorf("%s: error %q, not run %v, skipped %v", r.ID, r.Error, r.NotRun, r.Skipped)
		}
		if len(r.Observations) == 0 {
			t.Errorf("%s: no observations", r.ID)
		}
		for _, o := range r.Observations {
			if o.Error != "" || o.Result == nil || o.Result.Status == 0 {
				t.Errorf("%s: %q has no answer: %+v", r.ID, o.Label, o)
			}
		}
		// A-12 cannot decide anything on a policy with no stored test, which the model's has
		// not (TestA12ChecksOnlyWhenAStoredTestCouldFail); every other probe has checks.
		if len(r.Checks) == 0 && r.ID != "A-12" {
			t.Errorf("%s: no checks", r.ID)
		}
		for _, c := range r.Checks {
			if !c.Matches() {
				t.Errorf("%s: %q: expected %v, observed %v", r.ID, c.Name, c.Want, c.Got)
			}
		}
	}
	if n := len(w.f.Requests()); n > 80 || n < 40 {
		t.Errorf("%d requests, want between 40 and 80", n)
	}
}

// The plain read of the policy (A-8, A-13) answers 200 with the policy's own HuJSON. Its
// skeleton is a status and a type: a template of the text would print the policy's
// comments, strings and the words of its grammar.
func TestAPolicyReadThatSucceededRecordsNoTemplate(t *testing.T) {
	w := newWorld(t)
	rs := runAll(t, w, opts())
	plain := 0
	for _, r := range rs {
		for _, o := range r.Observations {
			if o.Result == nil || o.Result.Status >= 400 || o.Result.Body != "text" {
				continue
			}
			if len(o.Result.Texts) != 0 {
				t.Errorf("%s: %q answered %d and recorded the texts %q", r.ID, o.Label, o.Result.Status, o.Result.Texts)
			}
			if (r.ID == "A-8" || r.ID == "A-13") && o.Result.Status == 200 {
				plain++
			}
		}
	}
	if plain != 2 {
		t.Errorf("%d plain reads of the policy answered 200 with a text body, want 2 (A-8 and A-13): the test would prove nothing", plain)
	}
}

// requestCounts is the number of POSTs and GETs each probe sends in the model world, read
// from the fake (so a request the run records and a request the fake saw agree) and from
// what each probe recorded.
type requestCounts struct{ posts, gets int }

// runModel runs every probe against the model world. withAudit gives the audit log an
// entry in its first window; fallback makes the model refuse sshTests, so that A-10 tries
// its fallback from the live policy. It returns each probe's requests and the fake's totals.
func runModel(t *testing.T, withAudit, fallback bool) (map[string]requestCounts, requestCounts, *world) {
	t.Helper()
	w := newWorld(t)
	if withAudit {
		w.auditLogs = []map[string]any{{"eventTime": "2026-10-01T00:00:00Z", "action": "UPDATE", "old": liveText, "new": strings.Replace(liveText, "tag:live", "tag:live2", 1)}}
	}
	if fallback {
		w.override = func(body string) (apitest.Shape, bool) {
			if strings.Contains(body, "probe-nobody") {
				return apitest.SSHTestFailed("tag:live", "100.64.0.1", "tag:live", "100.64.0.2", "probe-nobody-aaaaaaaa"), true
			}
			if strings.Contains(body, "sshTests") {
				return apitest.PolicyUnknownField("sshTests"), true
			}
			return apitest.Shape{}, false
		}
	}
	per := map[string]requestCounts{}
	for _, r := range runAll(t, w, opts()) {
		var c requestCounts
		for _, o := range r.Observations {
			switch {
			case strings.HasPrefix(o.Request, "POST"):
				c.posts++
			case strings.HasPrefix(o.Request, "GET"):
				c.gets++
			}
		}
		per[r.ID] = c
	}
	var total requestCounts
	for _, q := range w.f.Requests() {
		if q.Method == "POST" {
			total.posts++
		} else {
			total.gets++
		}
	}
	return per, total, w
}

// The run sends exactly these requests, no more. A probe that sends a document twice, a
// window that is read once too often, or a ceiling that is raised show here as a number.
func TestTheModelWorldSendsExactlyTheseRequests(t *testing.T) {
	want := map[string]requestCounts{
		"A-1": {5, 0}, "A-2": {4, 0}, "A-3": {4, 0}, "A-4": {5, 0}, "A-5": {4, 0}, "A-6": {2, 0}, "A-7": {1, 1},
		"A-8": {0, 5}, "A-9": {13, 0}, "A-10": {2, 0}, "A-11": {3, 0}, "A-12": {1, 0}, "A-13": {0, 1}, "A-14": {6, 0}, "H-1": {0, 1},
	}
	per, total, _ := runModel(t, true, false)
	for _, p := range All() {
		if per[p.ID] != want[p.ID] {
			t.Errorf("%s sends %d POSTs and %d GETs, want %d and %d", p.ID, per[p.ID].posts, per[p.ID].gets, want[p.ID].posts, want[p.ID].gets)
		}
	}
	// 50 POSTs and 8 GETs make 58 when the audit log has an entry in its first window. With
	// an empty audit log H-1 reads all three windows (two more GETs): 60. A fallback in
	// A-10 adds one POST to either: 59, and 61 as the most a run sends.
	if total != (requestCounts{50, 8}) {
		t.Errorf("a run with an audit entry sends %d POSTs and %d GETs, want 50 and 8 (58)", total.posts, total.gets)
	}
	_, empty, _ := runModel(t, false, false)
	if empty != (requestCounts{50, 10}) {
		t.Errorf("a run with an empty audit log sends %d POSTs and %d GETs, want 50 and 10 (60)", empty.posts, empty.gets)
	}
	per, fb, _ := runModel(t, true, true)
	if per["A-10"] != (requestCounts{3, 0}) || fb != (requestCounts{51, 8}) {
		t.Errorf("with A-10's fallback: A-10 %+v, run %+v, want 3 POSTs for A-10 and 51 POSTs and 8 GETs (59)", per["A-10"], fb)
	}
	_, most, _ := runModel(t, false, true)
	if most != (requestCounts{51, 10}) {
		t.Errorf("the most a run sends is %d POSTs and %d GETs, want 51 and 10 (61)", most.posts, most.gets)
	}
}

// The files a run writes are named the way the ledger looks them up, <ID>.json, so a
// capture the owner commits is one the ledger finds. The lookup is apitest's own.
func TestEveryWrittenFileIsOneTheLedgerFinds(t *testing.T) {
	w := newWorld(t)
	rs := runAll(t, w, opts())
	dir := t.TempDir()
	names, err := WriteFiles(dir, rs, "2026-10-20")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != len(All()) {
		t.Fatalf("%d files written for %d probes", len(names), len(All()))
	}
	for _, r := range rs {
		want := apitest.CaptureFile(dir, r.ID)
		if _, err := os.Stat(want); err != nil {
			t.Errorf("%s: the ledger would look for %s: %v", r.ID, want, err)
		}
		if !contains(names, want) {
			t.Errorf("%s: WriteFiles reported %q, not the ledger's %q", r.ID, names, want)
		}
	}
}

// With nothing in the audit log H-1 reads three 31-day windows and no more: the API caps
// a request at 31 days, and the row asks for the last 90.
func TestH1ReadsThreeWindowsOfAnEmptyAuditLog(t *testing.T) {
	w := newWorld(t)
	rs := Run(context.Background(), w.f.Client(t), All()[14:], opts())
	if len(rs) != 1 || rs[0].ID != "H-1" {
		t.Fatalf("results = %+v", rs)
	}
	reads := 0
	for _, q := range w.f.Requests() {
		if q.Method == "GET" && strings.HasSuffix(q.Path, "/logging/configuration") {
			reads++
		}
	}
	if reads != 3 || len(rs[0].Observations) != 3 {
		t.Errorf("%d reads of the configuration log and %d observations, want 3 and 3", reads, len(rs[0].Observations))
	}
	if n := len(w.f.Requests()); n != 3 {
		t.Errorf("H-1 sent %d requests, want only the 3 reads", n)
	}
}

// The checks can come out false. Where the API ignores the difference the control is
// meant to show, the control passes and A-1 says so, and the printed report says DIFFERS.
func TestAProbeTheWorldContradictsReportsDiffers(t *testing.T) {
	w := newWorld(t)
	w.override = func(string) (apitest.Shape, bool) { return apitest.TestsPass(), true }
	rs := Run(context.Background(), w.f.Client(t), All()[:1], opts())
	var differing []string
	for _, c := range rs[0].Checks {
		if !c.Matches() {
			differing = append(differing, c.Name)
		}
	}
	if len(differing) < 4 {
		t.Errorf("only %d checks differ in a world where everything passes: %v", len(differing), differing)
	}
	var out bytes.Buffer
	Render(&out, rs)
	if !strings.Contains(out.String(), "DIFFERS the control fails with want Drop, got Accept (expected true, observed false)") {
		t.Errorf("the report does not say the control passed:\n%s", out.String())
	}
	if m, d, _, _ := Tally(rs); d != len(differing) || m+d != len(rs[0].Checks) {
		t.Errorf("Tally = %d match, %d differ", m, d)
	}
}

// Live data never reaches the output: not in the printed report, not in the files, whatever
// the probes sent to Tailscale. Positive controls: the report does show the grammar, the
// statuses and the ETag form.
func TestNoValueFromTheTailnetIsPrinted(t *testing.T) {
	w := newWorld(t)
	w.auditLogs = []map[string]any{{"eventTime": "2026-10-01T00:00:00Z", "old": liveText, "new": liveText}}
	rs := runAll(t, w, opts())
	var out bytes.Buffer
	Render(&out, rs)
	dir := t.TempDir()
	names, err := WriteFiles(dir, rs, "2026-10-20")
	if err != nil {
		t.Fatal(err)
	}
	all := out.String()
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		all += "\n" + string(b)
	}
	for _, tok := range liveTokens {
		if strings.Contains(all, tok) {
			t.Errorf("the output holds %q, a name from the live policy", tok)
		}
	}
	if etag := strings.Trim(etagOfLive(t), `"`); strings.Contains(all, etag[:16]) {
		t.Error("the output holds part of the ETag")
	}
	for _, want := range []string{"want: Drop, got: Accept", "ETag quoted-hex64", "HTTP 400", "ssh user", "line <n>, column <n>"} {
		if !strings.Contains(all, want) {
			t.Errorf("the output lacks %q", want)
		}
	}
	// The counts and booleans the live probes print are there, as numbers.
	if !strings.Contains(all, "details warnings: 1") || !strings.Contains(all, "fact      hujson.Format accepted the body: true") {
		t.Errorf("the live probes printed no counts:\n%s", out.String())
	}
}

var (
	ipv4RE  = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	runRE   = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*`) // a run with two colons: a candidate IPv6 address
	emailRE = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+`)
	nameRE  = regexp.MustCompile(`\b(?:tag|group|autogroup|svc):[A-Za-z0-9-]+`)

	// What a synthetic document may name. Anything else in it is either a live value or a
	// name nobody reviewed.
	allowedNames = regexp.MustCompile(`^(?:tag:(?:p|q)|tag:tailkeeper-canary-[0-9a-f]{8}|group:(?:one|two|p)|autogroup:(?:internet|self))$`)
	allowedHosts = regexp.MustCompile(`^(?:probe-a|nobody-[0-9a-f]{8}@example\.com)$`)
	allowedMails = regexp.MustCompile(`^(?:amy|bob|nobody-[0-9a-f]{8})@example\.com$`)
)

// liveMarkers are values of the model tailnet; none may appear in a synthetic document.
var liveMarkers = []string{"tag:live", "live-host", "lee@", "group:eng", "svc:db", "198.51.100.77", "5432"}

// syntheticProblems says what is wrong with a document a probe sends that is not built
// from the live policy: an address outside 192.0.2.0/24 and 2001:db8::/32 (plus the one
// 100.64.0.1 that A-1 names), a tag, group, service, host key or login the probes do not
// use, or a live value. The model world's own addresses are outside these ranges, so a
// live value in a synthetic document cannot pass for a documentation address.
func syntheticProblems(doc string) []string {
	var problems []string
	_, doc4, _ := net.ParseCIDR("192.0.2.0/24")
	_, doc6, _ := net.ParseCIDR("2001:db8::/32")
	for _, ip := range ipv4RE.FindAllString(doc, -1) {
		if ip != "100.64.0.1" && !doc4.Contains(net.ParseIP(ip)) {
			problems = append(problems, "the address "+ip)
		}
	}
	for _, run := range runRE.FindAllString(doc, -1) {
		if ip := net.ParseIP(run); ip != nil && ip.To4() == nil && !doc6.Contains(ip) {
			problems = append(problems, "the IPv6 address "+run)
		}
	}
	for _, e := range emailRE.FindAllString(doc, -1) {
		if !allowedMails.MatchString(e) {
			problems = append(problems, "the login "+e)
		}
	}
	for _, n := range nameRE.FindAllString(doc, -1) {
		if !allowedNames.MatchString(n) {
			problems = append(problems, "the name "+n)
		}
	}
	if std, err := hujson.Standardize([]byte(doc)); err == nil {
		var parsed struct {
			Hosts map[string]json.RawMessage `json:"hosts"`
		}
		if json.Unmarshal(std, &parsed) == nil {
			for key := range parsed.Hosts {
				if !allowedHosts.MatchString(key) {
					problems = append(problems, "the host key "+key)
				}
			}
		}
	}
	for _, bad := range append([]string{"ts.net", "tskey", "tail"}, liveMarkers...) {
		if strings.Contains(strings.ReplaceAll(doc, "tailkeeper-canary", ""), bad) {
			problems = append(problems, "the text "+bad)
		}
	}
	return problems
}

func TestSyntheticProblemsFindsWhatItShould(t *testing.T) {
	for doc, bad := range map[string]bool{
		`{"hosts":{"probe-a":"100.64.0.1","b":"192.0.2.1"},"tagOwners":{"tag:p":[]}}`:   true, // host key b
		`{"hosts":{"probe-a":"100.64.0.1"},"x":"192.0.2.1","y":"[2001:db8::1]:22"}`:     false,
		`{"groups":{"group:p":["nobody-aaaaaaaa@example.com","amy@example.com"]}}`:      false,
		`{"acls":[{"dst":["tag:tailkeeper-canary-aaaaaaaa:22","autogroup:internet"]}]}`: false,
		`{"hosts":{"probe-a":"100.101.102.103"}}`:                                       true,
		`{"hosts":{"probe-a":"203.0.113.9"}}`:                                           true,
		`{"hosts":{"probe-a":"198.51.100.9"}}`:                                          true, // the live range, not a synthetic one
		`{"hosts":{"probe-a":"2001:4860::1"}}`:                                          true,
		`{"hosts":{"probe-a":"fd7a:115c:a1e0::1"}}`:                                     true,
		`{"groups":{"group:p":["amy@example.org"]}}`:                                    true,
		`{"groups":{"group:p":["lee@example.com"]}}`:                                    true,
		`{"acls":[{"src":["tag:live"]}]}`:                                               true,
		`{"acls":[{"src":["group:eng"]}]}`:                                              true,
		`{"acls":[{"dst":["svc:db"]}]}`:                                                 true,
		`{"hosts":{"live-host":"192.0.2.1"}}`:                                           true,
		`{"hosts":{"probe-a":"host1.tail1234.ts.net"}}`:                                 true,
		`{"a":"tskey-api-k"}`:                                                           true,
	} {
		if got := syntheticProblems(doc); (len(got) > 0) != bad {
			t.Errorf("%s: problems %v, want bad=%v", doc, got, bad)
		}
	}
}

// Every document the probes send is synthetic, apart from the ones built from the live
// policy: the live text itself (A-7), and the tests-mode arrays that name live objects.
// A policy-mode document other than the live text holds no live value; a tests-mode array
// that holds none is checked as a synthetic one.
func TestEverySentDocumentIsSyntheticOrLive(t *testing.T) {
	w := newWorld(t)
	runAll(t, w, opts())
	liveBodies, synthetic := 0, 0
	for _, r := range w.f.Requests() {
		if r.Method != "POST" {
			continue
		}
		body := string(r.Body)
		if body == liveText {
			liveBodies++
			continue
		}
		derived := false
		for _, m := range liveMarkers {
			derived = derived || strings.Contains(body, m)
		}
		if derived && r.ContentType == "application/json" {
			continue // a tests-mode array built from the live policy
		}
		if derived {
			t.Errorf("a policy-mode document that is not the live text holds a live value: %q", body)
			continue
		}
		synthetic++
		if p := syntheticProblems(body); len(p) > 0 {
			t.Errorf("%s: %v", body, p)
		}
	}
	if liveBodies != 1 {
		t.Errorf("the live text was sent %d times, want once (A-7)", liveBodies)
	}
	if synthetic < 30 {
		t.Errorf("only %d synthetic documents were checked", synthetic)
	}
}

// The request line of a body built from the live policy shows no size; a synthetic body keeps its size.
func TestRequestLinesOfLiveBodiesShowNoSize(t *testing.T) {
	w := newWorld(t)
	live := map[string]bool{"A-7": true, "A-12": true}
	for _, r := range runAll(t, w, opts()) {
		for _, o := range r.Observations {
			if !strings.HasPrefix(o.Request, "POST") {
				continue
			}
			isLive := live[r.ID] || (r.ID == "A-9" && strings.Contains(o.Request, "application/json"))
			if has := strings.Contains(o.Request, "bytes"); has == isLive {
				t.Errorf("%s: %q: size shown = %v, live-derived = %v", r.ID, o.Request, has, isLive)
			}
		}
	}
}

// Probes send what their rows say. These are the exact bodies of the first rows and the
// shape of the others; a drift between probes.go and the probe table shows as a body that changed.
func TestTheExactRequestsOfSomeRows(t *testing.T) {
	w := newWorld(t)
	Run(context.Background(), w.f.Client(t), All()[:3], opts())
	var bodies []string
	for _, r := range w.f.Requests() {
		if r.Method == "POST" {
			bodies = append(bodies, string(r.Body))
			if r.ContentType != "application/hujson" {
				t.Errorf("%s was sent as %s", r.Body, r.ContentType)
			}
		}
	}
	want := []string{
		`{"tagOwners":{"tag:p":[]},"hosts":{"probe-a":"100.64.0.1"},"tests":[{"src":"tag:p","deny":["probe-a:22"]}]}`,
		`{"tagOwners":{"tag:p":[]},"hosts":{"probe-a":"100.64.0.1"},"acls":[],"tests":[{"src":"tag:p","deny":["probe-a:22"]}]}`,
		`{"tagOwners":{"tag:p":[]},"hosts":{"probe-a":"100.64.0.1"},"acls":null,"tests":[{"src":"tag:p","deny":["probe-a:22"]}]}`,
		`{"tagOwners":{"tag:p":[]},"hosts":{"probe-a":"100.64.0.1"},"grants":[],"tests":[{"src":"tag:p","deny":["probe-a:22"]}]}`,
		`{"tagOwners":{"tag:p":[]},"hosts":{"probe-a":"100.64.0.1"},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],"tests":[{"src":"tag:p","deny":["probe-a:22"]}]}`,
		`[]`,
		`[{"src":"tag:p","accept":["tag:p:22"]}]`,
		``,
		`null`,
	}
	if len(bodies) < len(want) {
		t.Fatalf("%d bodies, want at least %d", len(bodies), len(want))
	}
	for i, w := range want {
		if bodies[i] != w {
			t.Errorf("body %d = %q, want %q", i, bodies[i], w)
		}
	}
}

// H-1 reads the audit log in memory and prints counts only; each way it can go wrong is a
// check that differs or a fact, never a panic.
func TestH1Outcomes(t *testing.T) {
	policyOld, policyNew := `{"acls": []}`, `{"acls": [], "hosts": {}}`
	for _, c := range []struct {
		name    string
		logs    []map[string]any
		code    int
		entries int
		strs    bool // old and new are JSON strings
		got     bool
	}{
		{"strings with a known section", []map[string]any{{"old": policyOld, "new": policyNew}}, 0, 1, true, true},
		{"objects, not strings", []map[string]any{{"old": map[string]any{"acls": []any{}}, "new": map[string]any{"Hosts": map[string]any{}}}}, 0, 1, false, false},
		{"one string and one object", []map[string]any{{"old": policyOld, "new": map[string]any{"hosts": map[string]any{}}}}, 0, 1, false, false},
		{"entries without old and new", []map[string]any{{"eventTime": "2026-10-01T00:00:00Z"}}, 0, 1, false, false},
		{"a summary instead of a text", []map[string]any{{"old": "removed group", "new": "added group"}}, 0, 1, true, false},
		{"an object with no known section", []map[string]any{{"old": `{"x": 1}`, "new": `{"y": 2}`}}, 0, 1, true, false},
		{"null for old and new", []map[string]any{{"old": nil, "new": nil}}, 0, 1, false, false},
		{"one string entry and one object entry", []map[string]any{{"old": policyOld, "new": policyNew}, {"old": map[string]any{"acls": []any{}}, "new": map[string]any{"acls": []any{}}}}, 0, 2, false, false},
		{"no entries", nil, 0, 0, false, false},
		{"an error status", nil, 403, 0, false, false},
	} {
		w := newWorld(t)
		w.auditLogs, w.auditCode = c.logs, c.code
		rs := Run(context.Background(), w.f.Client(t), All()[14:], opts())
		r := rs[0]
		if c.code != 0 {
			if r.Facts["the audit log answered 200"] || len(r.Checks) != 0 {
				t.Errorf("%s: %+v", c.name, r)
			}
			continue
		}
		if r.Counts["ACL update entries seen"] != c.entries || len(r.Checks) != 1 || r.Checks[0].Got != c.got || r.Facts["old and new are JSON strings"] != c.strs {
			t.Errorf("%s: counts %v facts %v checks %+v", c.name, r.Counts, r.Facts, r.Checks)
		}
	}
}

// When the server does not know sshTests, A-10 builds a test from the live policy's first
// ssh rule and sends the live text with it; the answer shows only as a fact.
func TestA10FallsBackToTheLivePolicy(t *testing.T) {
	w := newWorld(t)
	w.override = func(body string) (apitest.Shape, bool) {
		if strings.Contains(body, "sshTests") && !strings.Contains(body, "probe-nobody") {
			return apitest.PolicyUnknownField("sshTests"), true
		}
		if strings.Contains(body, "probe-nobody") {
			return apitest.SSHTestFailed("tag:live", "100.64.0.1", "tag:live", "100.64.0.2", "probe-nobody-aaaaaaaa"), true
		}
		return apitest.Shape{}, false
	}
	rs := Run(context.Background(), w.f.Client(t), All()[9:10], opts())
	r := rs[0]
	if !r.Facts["the fallback shows the SSH form"] || len(r.Skipped) != 0 {
		t.Errorf("fallback: facts %v skipped %v", r.Facts, r.Skipped)
	}
	var sent string
	for _, q := range w.f.Requests() {
		if q.Method == "POST" && strings.Contains(string(q.Body), "probe-nobody") {
			sent = string(q.Body)
		}
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal([]byte(sent), &doc) != nil || !strings.Contains(string(doc["sshTests"]), `"src":"tag:live"`) || doc["TagOwners"] == nil {
		t.Errorf("the fallback body: %s", sent)
	}
	if last := r.Observations[len(r.Observations)-1]; strings.Contains(last.Request, "bytes") || !strings.Contains(last.Request, "live policy") {
		t.Errorf("the fallback's request line shows a size: %q", last.Request)
	}
	var out bytes.Buffer
	Render(&out, rs)
	if strings.Contains(out.String(), "probe-nobody") || strings.Contains(out.String(), "tag:live") {
		t.Errorf("the fallback printed live names:\n%s", out.String())
	}
	// No usable ssh rule: skipped, not guessed.
	l := &Live{SSH: []SSHRule{{Src: []string{"autogroup:member"}, Dst: []string{"tag:live"}}, {Src: []string{"tag:live"}}}}
	if _, ok := sshFallback(l, "aaaaaaaa"); ok {
		t.Error("a fallback was built from rules that cannot make a test")
	}
}

// Without a tag in the live policy, A-9 and A-12 skip the requests that need one and say so.
func TestProbesSkipWhatTheLivePolicyCannotSupply(t *testing.T) {
	f := apitest.New(t)
	f.PermitProbeRequests()
	f.Serve("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/acl", apitest.DetailsOK("{\"acls\": []}\n", `"e"`, nil, nil))
	f.Serve("POST", apitest.ValidatePath, apitest.TestsFailed(apitest.Entry{User: "tag:tailkeeper-canary-aaaaaaaa", Errors: []string{`address "192.0.2.1:1": want: Drop, got: Accept`}}))
	rs := Run(context.Background(), f.Client(t), []Probe{All()[8], All()[11]}, opts())
	if len(rs[0].Skipped) != 1 || len(rs[1].Skipped) != 1 || len(rs[0].Checks) != 4 {
		t.Errorf("A-9: skipped %v checks %d; A-12: skipped %v", rs[0].Skipped, len(rs[0].Checks), rs[1].Skipped)
	}
}

// testsModeSources returns the src of every tests-mode request the fake received.
func testsModeSources(t *testing.T, f *apitest.Fake) []string {
	t.Helper()
	var out []string
	for _, r := range f.Requests() {
		if r.Method != "POST" || r.ContentType != "application/json" {
			continue
		}
		var tests []struct {
			Src string `json:"src"`
		}
		if json.Unmarshal(r.Body, &tests) != nil || len(tests) != 1 {
			t.Fatalf("a tests-mode body that is not one test: %q", r.Body)
		}
		out = append(out, tests[0].Src)
	}
	return out
}

// A-9 and A-12 take their src from a tag, else a login, else a group of the live policy,
// as the row says ("a tag or user from live"), and skip only when the policy has none.
func TestA9AndA12TakeASourceFromATagALoginOrAGroup(t *testing.T) {
	for _, c := range []struct{ name, policy, src string }{
		{"a tag, a login and a group", `{"tagOwners":{"tag:zed":[]},"groups":{"group:g":["amy@example.com"]}}`, "tag:zed"},
		{"a login and a group", `{"groups":{"group:g":["amy@example.com"]}}`, "amy@example.com"},
		{"a group", `{"groups":{"group:g":["bob"]}}`, "group:g"},
	} {
		f := apitest.New(t)
		f.PermitProbeRequests()
		f.Serve("GET", aclPath, apitest.DetailsOK(c.policy, `"e"`, nil, nil))
		f.Serve("POST", apitest.ValidatePath, apitest.TestsFailed(apitest.Entry{User: c.src, Errors: []string{`address "192.0.2.1:1": want: Drop, got: Accept`}}))
		rs := Run(context.Background(), f.Client(t), []Probe{All()[8], All()[11]}, opts())
		for _, r := range rs {
			if r.Error != "" {
				t.Errorf("%s: %s: error %q", c.name, r.ID, r.Error)
			}
		}
		srcs := testsModeSources(t, f)
		if len(srcs) < 6 {
			t.Errorf("%s: %d tests-mode requests, want A-9's and A-12's", c.name, len(srcs))
		}
		for _, got := range srcs {
			if got != c.src {
				t.Errorf("%s: a tests-mode request has the src %q, want %q", c.name, got, c.src)
			}
		}
		if len(rs[1].Checks) != 0 || rs[1].Facts["the live policy has stored tests"] {
			t.Errorf("%s: A-12 ran %d checks with stored tests %v; these policies have none, so it records the fact and no check", c.name, len(rs[1].Checks), rs[1].Facts)
		}
	}
}

// "No entry names another source" can only match on a tailnet whose policy has no stored
// test (nothing can fail), so A-12 records that as a fact and runs the check only when a
// stored test exists. Either way it sends its one request and records its count.
func TestA12ChecksOnlyWhenAStoredTestCouldFail(t *testing.T) {
	const fact = "the live policy has stored tests"
	const head = `{"tagOwners":{"tag:live":[]},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]`
	for _, c := range []struct {
		name, policy string
		stored       bool
	}{
		{"the model world, no tests section", "", false},
		{"an empty tests section", head + `,"tests":[]}`, false},
		{"a null tests section", head + `,"tests":null}`, false},
		{"one stored test", head + `,"tests":[{"src":"tag:live","accept":["192.0.2.1:22"]}]}`, true},
	} {
		w := newWorld(t)
		if c.policy != "" {
			w.serveText(c.policy)
		}
		r := Run(context.Background(), w.f.Client(t), All()[11:12], opts())[0]
		if r.Error != "" || len(r.Skipped) != 0 {
			t.Fatalf("%s: error %q, skipped %v", c.name, r.Error, r.Skipped)
		}
		if got, ok := r.Facts[fact]; !ok || got != c.stored {
			t.Errorf("%s: fact %q = %v (recorded %v), want %v", c.name, fact, got, ok, c.stored)
		}
		if _, ok := r.Counts["data entries for another source"]; !ok {
			t.Errorf("%s: the count of other entries is missing", c.name)
		}
		if want := map[bool]int{false: 0, true: 1}[c.stored]; len(r.Checks) != want {
			t.Errorf("%s: %d checks, want %d", c.name, len(r.Checks), want)
		}
		if c.stored && (len(r.Checks) != 1 || r.Checks[0].Name != "no entry names another source" || !r.Checks[0].Matches()) {
			t.Errorf("%s: checks = %+v", c.name, r.Checks)
		}
		var posts int
		for _, q := range w.f.Requests() {
			if q.Method == "POST" {
				posts++
			}
		}
		if posts != 1 {
			t.Errorf("%s: A-12 sent %d POSTs, want 1", c.name, posts)
		}
	}
}

// A-9's canary does not need the live policy: when the read fails, the canary still runs
// and only the tests-mode half is skipped.
func TestA9RunsItsCanaryWhenTheLivePolicyCannotBeRead(t *testing.T) {
	f := apitest.New(t)
	f.PermitProbeRequests()
	f.Serve("GET", aclPath, apitest.Forbidden403())
	f.Serve("POST", apitest.ValidatePath, apitest.TestsFailed(apitest.Entry{User: "tag:tailkeeper-canary-aaaaaaaa", Errors: []string{`address "192.0.2.1:1": want: Drop, got: Accept`}}))
	r := Run(context.Background(), f.Client(t), All()[8:9], opts())[0]
	if r.Error != "" || len(r.Skipped) != 1 || len(r.Checks) != 4 || len(r.Observations) != 3 {
		t.Errorf("error %q, skipped %v, %d checks, %d observations", r.Error, r.Skipped, len(r.Checks), len(r.Observations))
	}
	if len(testsModeSources(t, f)) != 0 {
		t.Error("a tests-mode request was sent without a source")
	}
}

// The destination kinds A-9 sends: the row's list, with ICMP port 0 both with and without proto.
func TestA9SendsOneRequestPerKindIncludingICMPWithoutProto(t *testing.T) {
	w := newWorld(t)
	r := Run(context.Background(), w.f.Client(t), All()[8:9], opts())[0]
	n, icmpNoProto, icmpProto := 0, 0, 0
	for _, q := range w.f.Requests() {
		if q.Method != "POST" {
			continue
		}
		n++
		if q.ContentType == "application/json" && strings.Contains(string(q.Body), `"192.0.2.1:0"`) {
			if strings.Contains(string(q.Body), `"proto":"icmp"`) {
				icmpProto++
			} else {
				icmpNoProto++
			}
		}
	}
	if n != 13 || icmpProto != 1 || icmpNoProto != 1 || len(r.Checks) != 15 {
		t.Errorf("%d requests (want 13), ICMP with proto %d, without %d, %d checks", n, icmpProto, icmpNoProto, len(r.Checks))
	}
}

func checkNamed(t *testing.T, r Result, name string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("%s has no check %q", r.ID, name)
	return Check{}
}

// A-14 notices a position that is rejected while the others are accepted, and rejections that differ.
func TestA14NoticesPositionsThatAnswerDifferently(t *testing.T) {
	const varies, same, warned = "acceptance does not vary across the six positions", "every rejection is the same rejection", "an accepted position exists and none carries a warning about the login"
	w := newWorld(t)
	w.override = func(body string) (apitest.Shape, bool) {
		if strings.Contains(body, `"groups":{"group:p"`) {
			return apitest.Rejected400("user not found"), true
		}
		return apitest.Shape{}, false
	}
	r := Run(context.Background(), w.f.Client(t), All()[13:14], opts())[0]
	if c := checkNamed(t, r, varies); c.Matches() {
		t.Error("one rejected position among five accepted reads as MATCH")
	}
	if !checkNamed(t, r, same).Matches() || !checkNamed(t, r, warned).Matches() {
		t.Errorf("checks: %+v", r.Checks)
	}
	// Six rejections that are not the same rejection.
	w = newWorld(t)
	w.override = func(body string) (apitest.Shape, bool) {
		if strings.Contains(body, `"groups":{"group:p"`) {
			return apitest.Rejected400("line 1, column 2: bad"), true
		}
		return apitest.Rejected400("user not found"), true
	}
	r = Run(context.Background(), w.f.Client(t), All()[13:14], opts())[0]
	if !checkNamed(t, r, varies).Matches() || checkNamed(t, r, same).Matches() {
		t.Errorf("two kinds of rejection: %+v", r.Checks)
	}
	// Accepted positions with a warning about the login.
	w = newWorld(t)
	w.override = func(string) (apitest.Shape, bool) {
		return apitest.TestsWarned(apitest.Entry{User: "group:p", Warnings: []string{liveWarning}}), true
	}
	r = Run(context.Background(), w.f.Client(t), All()[13:14], opts())[0]
	if checkNamed(t, r, warned).Matches() || !checkNamed(t, r, varies).Matches() {
		t.Errorf("warnings: %+v", r.Checks)
	}
}

// Against the form the live API answered on 20 Oct 2026 (a rejection arrives as HTTP 200 and a bare
// message), A-3 and A-5 report DIFFERS for the expectations of the table, and name no other check.
func TestA3AndA5ReportDiffersAgainstTheLiveForm(t *testing.T) {
	w := newWorld(t)
	w.override = func(body string) (apitest.Shape, bool) {
		switch {
		case strings.Contains(body, "invalidtext"):
			return apitest.PolicySyntaxError(3, 13, "invalid literal: invalidtext"), true
		case strings.Contains(body, "unknownsection"):
			return apitest.PolicyUnknownField("unknownsection"), true
		case strings.Contains(body, `"nodeAttr"`):
			return apitest.PolicyUnknownField("nodeAttr"), true
		case strings.Contains(body, `"src":["tag:p"],"dst":["tag:p:22"]}]}`) && !strings.Contains(body, "tagOwners"):
			return apitest.PolicyTagNotFound("tag:p"), true
		}
		return apitest.Shape{}, false
	}
	rs := Run(context.Background(), w.f.Client(t), []Probe{All()[2], All()[4]}, opts())
	differs := map[string]bool{}
	for _, r := range rs {
		for _, c := range r.Checks {
			if !c.Matches() {
				differs[r.ID+": "+c.Name] = true
			}
		}
	}
	for _, name := range []string{
		"A-3: a syntax error answers 400 with a bare message and no data",
		"A-3: an unknown field answers 400 with a bare message and no data",
		"A-3: an unknown tag answers 400 with a bare message and no data",
		"A-5: nodeAttr is rejected as an unknown field",
	} {
		if !differs[name] {
			t.Errorf("%q reads MATCH against the live form", name)
		}
	}
	if len(differs) != 4 {
		t.Errorf("%d checks differ, want the four above: %v", len(differs), differs)
	}
}

// A-5 reads the rejection of nodeAttr by "unknown field", whatever precedes it.
func TestA5ReadsUnknownFieldWhateverPrecedesIt(t *testing.T) {
	w := newWorld(t)
	w.override = func(body string) (apitest.Shape, bool) {
		if strings.Contains(body, `"nodeAttr":`) {
			return apitest.Rejected400(`unknown field "nodeAttr"`), true
		}
		return apitest.Shape{}, false
	}
	r := Run(context.Background(), w.f.Client(t), All()[4:5], opts())[0]
	if !checkNamed(t, r, "nodeAttr is rejected as an unknown field").Matches() {
		t.Errorf("checks: %+v", r.Checks)
	}
}

// When every endpoint answers 403, nothing the probes observed matches what the probe table
// expects: no check reads MATCH on a failed request.
func TestNoCheckMatchesWhenEveryEndpointAnswers403(t *testing.T) {
	f := apitest.New(t)
	f.PermitProbeRequests()
	f.Fallback(func(w http.ResponseWriter, _ *http.Request) { apitest.Forbidden403().Write(w) })
	rs := Run(context.Background(), f.Client(t), All(), opts())
	checks := 0
	for _, r := range rs {
		if r.NotRun {
			t.Errorf("%s did not run", r.ID)
		}
		for _, c := range r.Checks {
			checks++
			if c.Matches() {
				t.Errorf("%s: %q reads MATCH when every answer is a 403", r.ID, c.Name)
			}
		}
	}
	if checks < 30 {
		t.Errorf("only %d checks ran, so the test says little", checks)
	}
}

// With the policy readable and every POST and the audit log answered 403, the probes that
// depend on those answers have no check that reads MATCH. A-8 and A-13 only read the policy.
func TestNoCheckMatchesWhenEveryPostAnswers403(t *testing.T) {
	w := newWorld(t)
	w.warnings = nil // so that "no warnings both ways" cannot be true by accident
	w.auditCode = 403
	w.override = func(string) (apitest.Shape, bool) { return apitest.Forbidden403(), true }
	checks := 0
	for _, r := range runAll(t, w, opts()) {
		for _, c := range r.Checks {
			if r.ID == "A-8" || r.ID == "A-13" {
				continue
			}
			checks++
			if c.Matches() {
				t.Errorf("%s: %q reads MATCH when every POST is a 403", r.ID, c.Name)
			}
		}
	}
	if checks < 40 {
		t.Errorf("only %d checks ran, so the test says little", checks)
	}
}

// A 200 that carries an error line is neither a pass nor the same rejection: A-14 counts it in neither bucket.
func TestA14DoesNotCountA200WithAnErrorAsAccepted(t *testing.T) {
	w := newWorld(t)
	w.override = func(body string) (apitest.Shape, bool) {
		if strings.Contains(body, `"tests":[{"src":"nobody-`) {
			return apitest.TestsFailed(apitest.Entry{User: "nobody-aaaaaaaa@example.com", Errors: []string{"user or host is invalid: user not found"}}), true
		}
		return apitest.Shape{}, false
	}
	r := Run(context.Background(), w.f.Client(t), All()[13:14], opts())[0]
	if checkNamed(t, r, "acceptance does not vary across the six positions").Matches() {
		t.Errorf("one position answered 200 with an error line and the check reads MATCH: %+v", r.Checks)
	}
}

// A-5 reads "rejected": an answer that mentions the phrase with a 200 is not one.
func TestA5NeedsARejectionNotJustThePhrase(t *testing.T) {
	w := newWorld(t)
	w.override = func(body string) (apitest.Shape, bool) {
		if strings.Contains(body, `"nodeAttr":`) {
			return apitest.TestsWarned(apitest.Entry{User: "group:p", Warnings: []string{"unknown field nodeAttr"}}), true
		}
		return apitest.Shape{}, false
	}
	r := Run(context.Background(), w.f.Client(t), All()[4:5], opts())[0]
	if checkNamed(t, r, "nodeAttr is rejected as an unknown field").Matches() {
		t.Error("a 200 with the phrase in a warning reads as a rejection")
	}
}

// A-2's array with a test must be accepted: a 500 with no body, or a proxy's HTML page, is not.
func TestA2ArrayWithATestMustBeAccepted(t *testing.T) {
	for name, shape := range map[string]apitest.Shape{
		"a 500 with an empty body": {Name: "x", Endpoint: apitest.EndpointValidate, Status: 500},
		"a 200 HTML page":          {Name: "x", Endpoint: apitest.EndpointValidate, Status: 200, Body: "<html>"},
	} {
		w := newWorld(t)
		w.override = func(body string) (apitest.Shape, bool) {
			if strings.HasPrefix(body, `[{"src"`) {
				return shape, true
			}
			return apitest.Shape{}, false
		}
		r := Run(context.Background(), w.f.Client(t), All()[1:2], opts())[0]
		if checkNamed(t, r, "an array with a test is not rejected as a policy").Matches() {
			t.Errorf("%s reads MATCH", name)
		}
	}
}

// A-4's second-rule case tells a repeated acls array that replaces the earlier one from
// one that is decoded into the earlier array's elements. The document's second block holds
// one rule with no dst; only the element-wise reading lets it keep the first block's dst,
// so only that reading passes the test. The model world answers the replacing reading
// (the one rule has no dst, so the test fails); a world that merges answers the check false.
func TestA4TellsAReplacedArrayOfRulesFromAnElementWiseMerge(t *testing.T) {
	const name = "a repeated acls array replaces its rules whole (no element-wise merge)"
	const fact = "the second acls block kept the first block's dst (element-wise merge)"
	const doc = `{"tagOwners":{"tag:p":[],"tag:q":[]},"acls":[{"action":"accept","src":["tag:p"],"dst":["tag:q:22"]}],"acls":[{"action":"accept","src":["tag:p"]}],"tests":[{"src":"tag:p","accept":["tag:q:22"],"deny":["tag:q:80"]}]}`
	// answers replaces whatever the model says about the document with a fixed shape.
	answers := func(s apitest.Shape) func(string) (apitest.Shape, bool) {
		return func(body string) (apitest.Shape, bool) { return s, body == doc }
	}
	for _, c := range []struct {
		name     string
		override func(string) (apitest.Shape, bool)
		replaces bool
		answered bool // false: the server did not answer the question, so no fact is recorded
	}{
		{"the model world: the later array replaces, the test fails", nil, true, true},
		{"a server that rejects the rule without a dst", answers(apitest.Rejected400("rule has no dst")), true, true},
		{"a server that merges element-wise: the rule keeps its dst and both assertions pass", answers(apitest.TestsPass()), false, true},
		{"a server that reads a rule with no dst as allowing everything: the deny on tag:q:80 fails",
			answers(apitest.TestsFailed(apitest.Entry{User: "tag:p", Errors: []string{`address "tag:q:80": want: Drop, got: Accept`}})), true, true},
		{"a refused request: the check is false and no fact claims a negative", answers(apitest.Forbidden403()), false, false},
	} {
		w := newWorld(t)
		w.override = c.override
		rs := Run(context.Background(), w.f.Client(t), All()[3:4], opts())
		r := rs[0]
		if r.ID != "A-4" || r.Error != "" {
			t.Fatalf("%s: %s, error %q", c.name, r.ID, r.Error)
		}
		var found []Check
		for _, ck := range r.Checks {
			if ck.Name == name {
				found = append(found, ck)
			}
		}
		if len(found) != 1 {
			t.Errorf("%s: %d checks named %q, want 1", c.name, len(found), name)
			continue
		}
		if !found[0].Want || found[0].Got != c.replaces || found[0].Matches() != c.replaces {
			t.Errorf("%s: check %+v, want Want true and Got %v", c.name, found[0], c.replaces)
		}
		if v, ok := r.Facts[fact]; ok != c.answered || (c.answered && v == c.replaces) {
			t.Errorf("%s: fact %q = %v (recorded %v), want recorded %v and, if so, %v", c.name, fact, v, ok, c.answered, !c.replaces)
		}
		sent := 0
		for _, q := range w.f.Requests() {
			if q.Method == "POST" && string(q.Body) == doc {
				sent++
			}
		}
		if sent != 1 {
			t.Errorf("%s: the document was sent %d times, want once, byte for byte", c.name, sent)
		}
	}
}
