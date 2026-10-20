package probe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/hujson"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/skeleton"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// liveText is the model tailnet's policy. Its names (tag:live, live-host, lee, group:eng,
// svc:db, 198.51.100.77) appear nowhere in the probes: if one reaches the output, a value
// from the tailnet was printed.
const liveText = "// the model tailnet\n{\n\t\"TagOwners\": {\"tag:live\": [\"group:eng\"],},\n\t\"groups\": {\"group:eng\": [\"lee@example.com\"]},\n" +
	"\t\"hosts\": {\"live-host\": \"198.51.100.77\"},\n" +
	"\t\"acls\": [{\"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"*:*\"]}],\n" +
	"\t\"ssh\": [{\"action\": \"accept\", \"src\": [\"tag:live\"], \"dst\": [\"tag:live\"], \"users\": [\"root\"]}],\n" +
	"\t\"grants\": [{\"src\": [\"tag:live\"], \"dst\": [\"svc:db\"], \"ip\": [\"tcp:5432\"]}],\n}\n"

// liveWarning is the one warning the model tailnet's policy has.
const liveWarning = `group:eng: user not found: "lee@example.com"`

// liveTokens are the names in liveText that no probe output may show.
var liveTokens = []string{"tag:live", "live-host", "lee", "group:eng", "svc:db", "198.51.100.77", "5432", "model tailnet", "eng"}

const aclPath = "/api/v2/tailnet/" + apitest.Tailnet + "/acl"

// etagOfLive is the model's ETag: the SHA-256 of the formatted policy, as the probe table (docs/design.md §22) infers.
func etagOfLive(t *testing.T) string {
	t.Helper()
	f, err := hujson.Format([]byte(liveText))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(f)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func fixedHex(n int) string { return strings.Repeat("a", n) }

// opts is a run with no pacing and a fixed random source.
func opts() Options { return Options{Hex: fixedHex} }

// tiny is a probe of the test's own.
func tiny(id string, run func(ctx context.Context, x *Exec) error) Probe {
	return Probe{ID: id, Title: "title " + id, Sends: "sends " + id, Expected: "expected " + id, Branch: "branch " + id, Run: run}
}

// post sends doc in policy mode, the way every tiny probe does.
func post(ctx context.Context, x *Exec, label, doc string) (Seen, error) {
	return x.PostPolicy(ctx, Step{Label: label, Expect: "e"}, doc)
}

// Every request is recorded with its skeleton and nothing else, and what the probe computes
// from the answer is recorded beside it.
func TestRunRecordsEachRequestAsASkeleton(t *testing.T) {
	f := apitest.New(t)
	f.ServeValidate(apitest.TestsFailed(apitest.Entry{User: "tag:p", Errors: []string{`address "probe-a:22": want: Drop, got: Accept`}}))
	f.ServeDetails(apitest.DetailsOK("{}\n", `"e1"`, nil, nil))
	p := tiny("T-1", func(ctx context.Context, x *Exec) error {
		s, err := post(ctx, x, "a failing test", `{"acls":[]}`)
		if err != nil {
			return err
		}
		if _, err := x.GetPolicy(ctx, Step{Label: "details"}, api.PolicyGet{Details: true, Accept: "application/hujson", IfNoneMatch: `"e1"`}); err != nil {
			return err
		}
		x.Check("the answer is in the grammar", true, s.Grammar() == 1)
		x.Check("a check that differs", true, false)
		x.Fact("a fact", true)
		x.Count("a count", 3)
		x.Skip("a reason")
		return nil
	})
	rs := Run(context.Background(), f.Client(t), []Probe{p}, opts())
	r := rs[0]
	if len(rs) != 1 || r.ID != "T-1" || r.Sends != "sends T-1" || r.Expected != "expected T-1" || r.Branch != "branch T-1" || r.Error != "" {
		t.Fatalf("result = %+v", r)
	}
	if len(r.Observations) != 2 {
		t.Fatalf("%d observations", len(r.Observations))
	}
	o := r.Observations[0]
	if o.Label != "a failing test" || o.Expect != "e" || o.Request != "POST validate, application/hujson, 11 bytes" || o.Result.Status != 200 || o.Result.Body != "json" {
		t.Errorf("observation 0 = %+v", o)
	}
	if len(o.Result.Texts) == 0 || !strings.Contains(strings.Join(o.Result.Texts, "|"), `address "<s>-<s>:<n>": want: Drop, got: Accept`) {
		t.Errorf("texts = %q", o.Result.Texts)
	}
	if o2 := r.Observations[1]; o2.Request != "GET policy, details=true, Accept application/hujson, If-None-Match set" || o2.ETag != "quoted-hex" {
		t.Errorf("observation 1 = %+v", o2)
	}
	if len(r.Checks) != 2 || !r.Checks[0].Matches() || r.Checks[1].Matches() || !r.Facts["a fact"] || r.Counts["a count"] != 3 || len(r.Skipped) != 1 {
		t.Errorf("checks %+v facts %v counts %v skipped %v", r.Checks, r.Facts, r.Counts, r.Skipped)
	}
	if m, d, e, n := Tally(rs); m != 1 || d != 1 || e != 0 || n != 0 {
		t.Errorf("Tally = %d %d %d %d", m, d, e, n)
	}
}

// What a probe may look at in an answer.
func TestSeenReadsAnAnswer(t *testing.T) {
	f := apitest.New(t)
	answers := map[string]apitest.Shape{
		"fail":    apitest.TestsFailed(apitest.Entry{User: "tag:p", Errors: []string{`address "x:1": want: Accept, got: Drop`, "user or host is invalid: tag not found"}, Warnings: []string{"w1"}}),
		"ssh":     apitest.SSHTestFailed("tag:p", "100.64.0.1", "tag:p", "100.64.0.2", "root"),
		"pass":    apitest.TestsPass(),
		"bare":    apitest.Rejected400("no"),
		"warned":  apitest.TestsWarned(apitest.Entry{User: "group:g", Warnings: []string{"w1", "w2"}}),
		"notjson": {Name: "x", Endpoint: apitest.EndpointValidate, Status: 200, Body: "<html>"},
	}
	got := map[string]Seen{}
	p := tiny("T-1", func(ctx context.Context, x *Exec) error {
		for name, s := range answers {
			f.ServeValidate(s)
			seen, err := post(ctx, x, name, `{}`)
			if err != nil {
				return err
			}
			got[name] = seen
		}
		return nil
	})
	Run(context.Background(), f.Client(t), []Probe{p}, opts())
	type want struct {
		grammar, errorLines, warnings int
		passes, accepted, bare        bool
	}
	for name, w := range map[string]want{
		"fail":    {1, 2, 1, false, true, false},
		"ssh":     {1, 1, 0, false, true, false},
		"pass":    {0, 0, 0, true, true, false},
		"bare":    {0, 0, 0, false, false, true},
		"warned":  {0, 0, 2, true, true, false},
		"notjson": {0, 0, 0, false, false, false}, // a 200 that is not JSON (a proxy's HTML page) is no pass
	} {
		s := got[name]
		if s.Grammar() != w.grammar || s.ErrorLines() != w.errorLines || len(s.WarningLines()) != w.warnings || s.Passes() != w.passes || s.Accepted() != w.accepted || s.Bare() != w.bare {
			t.Errorf("%s: grammar %d lines %d warnings %d passes %v accepted %v bare %v", name, s.Grammar(), s.ErrorLines(), len(s.WarningLines()), s.Passes(), s.Accepted(), s.Bare())
		}
	}
	if !got["fail"].TextHas("want: Accept, got: Drop") || got["fail"].TextHas("nonsense") || !got["fail"].HasPath("data[].errors[]") || got["pass"].HasPath("data") {
		t.Error("TextHas or HasPath")
	}
	if es := got["fail"].Entries(); len(es) != 1 || es[0].User != "tag:p" || got["notjson"].Entries() != nil {
		t.Errorf("Entries = %+v", es)
	}
	if got["fail"].signature() == got["pass"].signature() {
		t.Error("signature")
	}
	if fmt.Sprintf("%v %+v %#v", got["fail"], got["fail"], got["fail"]) != "<seen> <seen> <seen>" || fmt.Sprintf("%v %+v %#v %v", Live{Tags: []string{"tag:x"}}, &Live{}, Live{}, []*Live{{}}[0]) != "<live> <live> <live> <live>" {
		t.Error("Seen or Live prints its contents")
	}
	if !isJSONObject([]byte(" {} ")) || isJSONObject([]byte("[]")) || isJSONObject([]byte("{")) || isJSONObject(nil) {
		t.Error("isJSONObject")
	}
}

// A request the API answers 429 stops the run: the probe that got it records the code and
// the probes after it are marked not run, with no further request sent.
func TestARateLimitStopsTheRun(t *testing.T) {
	f := apitest.New(t)
	var n atomic.Int32
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) == 2 {
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	})
	three := func(ctx context.Context, x *Exec) error {
		for i := 0; i < 3; i++ {
			if _, err := post(ctx, x, "a request", `{}`); err != nil {
				return err
			}
		}
		return nil
	}
	rs := Run(context.Background(), f.Client(t), []Probe{tiny("T-1", three), tiny("T-2", three)}, opts())
	if rs[0].Error != "rate_limited" || len(rs[0].Observations) != 2 || rs[0].Observations[1].Result.Status != 429 {
		t.Errorf("T-1: error %q after %d observations", rs[0].Error, len(rs[0].Observations))
	}
	if !rs[1].NotRun || len(rs[1].Observations) != 0 {
		t.Errorf("T-2 ran after a 429: %+v", rs[1])
	}
	if got := len(f.Requests()); got != 2 {
		t.Errorf("%d requests, want 2: none after the 429", got)
	}
}

// The request ceiling stops the run the same way.
func TestTheRequestBudgetStopsTheRun(t *testing.T) {
	f := apitest.New(t)
	f.ServeValidate(apitest.TestsPass())
	three := func(ctx context.Context, x *Exec) error {
		for i := 0; i < 3; i++ {
			if _, err := post(ctx, x, "a request", `{}`); err != nil {
				return err
			}
		}
		return nil
	}
	o := opts()
	o.Budget = 4
	rs := Run(context.Background(), f.Client(t), []Probe{tiny("T-1", three), tiny("T-2", three), tiny("T-3", three)}, o)
	if got := len(f.Requests()); got != 4 {
		t.Errorf("%d requests, want exactly the budget", got)
	}
	if rs[0].Error != "" || rs[1].Error != "request_budget" || !rs[2].NotRun {
		t.Errorf("errors %q %q, not run %v", rs[0].Error, rs[1].Error, rs[2].NotRun)
	}
}

// A run that sets no ceiling stops at 80 requests, and DefaultBudget says so.
func TestTheDefaultBudgetIs80(t *testing.T) {
	if DefaultBudget != 80 {
		t.Errorf("DefaultBudget = %d, want 80", DefaultBudget)
	}
	f := apitest.New(t)
	f.ServeValidate(apitest.TestsPass())
	many := func(ctx context.Context, x *Exec) error {
		for {
			if _, err := post(ctx, x, "a request", `{}`); err != nil {
				return err
			}
		}
	}
	rs := Run(context.Background(), f.Client(t), []Probe{tiny("T-1", many)}, opts())
	if got := len(f.Requests()); got != 80 || rs[0].Error != "request_budget" {
		t.Errorf("%d requests, error %q; want 80 and request_budget", got, rs[0].Error)
	}
}

// Requests are paced: a pause before every request but the first, of the gap asked for.
func TestRequestsArePaced(t *testing.T) {
	f := apitest.New(t)
	f.ServeValidate(apitest.TestsPass())
	var pauses []time.Duration
	o := opts()
	o.Gap = 2 * time.Second
	o.Sleep = func(_ context.Context, d time.Duration) error { pauses = append(pauses, d); return nil }
	two := func(ctx context.Context, x *Exec) error {
		for i := 0; i < 2; i++ {
			if _, err := post(ctx, x, "a request", `{}`); err != nil {
				return err
			}
		}
		return nil
	}
	Run(context.Background(), f.Client(t), []Probe{tiny("T-1", two), tiny("T-2", two)}, o)
	if len(pauses) != 3 {
		t.Errorf("%d pauses for 4 requests, want 3", len(pauses))
	}
	for _, d := range pauses {
		if d != 2*time.Second {
			t.Errorf("a pause of %s", d)
		}
	}
	// A pause cut short by the context ends the probe.
	o.Sleep = func(context.Context, time.Duration) error { return context.Canceled }
	if rs := Run(context.Background(), f.Client(t), []Probe{tiny("T-1", two)}, o); rs[0].Error != "cancelled" || len(rs[0].Observations) != 1 {
		t.Errorf("a cancelled pause: %+v", rs[0])
	}
}

// Only selects probes; a cancelled context marks everything not run.
func TestOnlyAndCancellation(t *testing.T) {
	f := apitest.New(t)
	f.ServeValidate(apitest.TestsPass())
	one := func(ctx context.Context, x *Exec) error { _, err := post(ctx, x, "a request", `{}`); return err }
	all := []Probe{tiny("T-1", one), tiny("T-2", one), tiny("T-3", one)}
	o := opts()
	o.Only = []string{"T-1", "T-3"}
	rs := Run(context.Background(), f.Client(t), all, o)
	if len(rs) != 2 || rs[0].ID != "T-1" || rs[1].ID != "T-3" {
		t.Fatalf("results: %+v", rs)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, r := range Run(ctx, f.Client(t), all, opts()) {
		if !r.NotRun {
			t.Errorf("%s ran under a cancelled context", r.ID)
		}
	}
}

// A dead connection is recorded as a code, not as text, and the next probe still runs.
func TestATransportErrorIsRecordedByCode(t *testing.T) {
	f := apitest.New(t)
	c := f.Client(t)
	f.Server.Close()
	one := func(ctx context.Context, x *Exec) error { _, err := post(ctx, x, "a request", `{}`); return err }
	rs := Run(context.Background(), c, []Probe{tiny("T-1", one), tiny("T-2", one)}, opts())
	for _, r := range rs {
		if r.Error != "upstream_unavailable" || r.NotRun || len(r.Observations) != 1 || r.Observations[0].Error != "upstream_unavailable" || r.Observations[0].Result != nil {
			t.Errorf("%s: %+v", r.ID, r)
		}
	}
	var out bytes.Buffer
	Render(&out, rs)
	if strings.Contains(out.String(), "127.0.0.1") || !strings.Contains(out.String(), "no answer (upstream_unavailable)") || !strings.Contains(out.String(), "ERROR     the probe stopped: upstream_unavailable") {
		t.Errorf("report:\n%s", out.String())
	}
}

// The report shows, for each probe, what the probe table sends and expects, each request beside its
// answer, and each check as MATCH or DIFFERS.
func TestRenderShowsExpectedAgainstObserved(t *testing.T) {
	f := apitest.New(t)
	f.ServeValidate(apitest.TestsFailed(apitest.Entry{User: "tag:p", Errors: []string{`address "probe-a:22": want: Drop, got: Accept`}}))
	f.Serve("GET", aclPath, apitest.PolicyText("// c\n{}\n", `"`+strings.Repeat("ab", 32)+`"`))
	p := tiny("T-1", func(ctx context.Context, x *Exec) error {
		if _, err := post(ctx, x, "the request", `{}`); err != nil {
			return err
		}
		if _, err := x.GetPolicy(ctx, Step{Label: "the read"}, api.PolicyGet{}); err != nil {
			return err
		}
		x.Check("it fails", true, true)
		x.Check("it passes", true, false)
		x.Fact("a fact", false)
		x.Count("a count", 7)
		x.Skip("nothing to skip")
		return nil
	})
	rs := Run(context.Background(), f.Client(t), []Probe{p}, opts())
	rs = append(rs, Result{ID: "T-2", Title: "later", Sends: "s", Expected: "e", Branch: "b", NotRun: true})
	var out bytes.Buffer
	Render(&out, rs)
	text := out.String()
	for _, want := range []string{
		"\nT-1  title T-1\n", "  sends:    sends T-1\n", "  expected: expected T-1\n", "  branch:   branch T-1\n",
		"  - the request\n      expect:   e\n      request:  POST validate, application/hujson, 2 bytes\n      observed: HTTP 200, body json\n",
		"      paths:    $: object; data: array; data[]: object; data[].errors: array; data[].errors[]: string; data[].user: string; message: string\n",
		"      text:     address \"<s>-<s>:<n>\": want: Drop, got: Accept\n",
		"      text:     test(s) failed\n",
		"  - the read\n      request:  GET policy\n      observed: HTTP 200, body text, ETag quoted-hex64\n",
		"  MATCH   it fails (expected true, observed true)\n", "  DIFFERS it passes (expected true, observed false)\n",
		"  fact      a fact: false\n", "  count     a count: 7\n", "  skipped   nothing to skip\n",
		"\nT-2  later\n", "  NOT RUN: an earlier request stopped the run\n",
		"\nprobes: 1 checks match, 1 differ, 0 probes stopped by an error, 1 not run\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the report lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, strings.Repeat("ab", 8)) {
		t.Errorf("the report shows part of the ETag:\n%s", text)
	}
}

// OnStart is called once for each probe that starts, in order, before its first request;
// a probe that does not run because an earlier request stopped the run is not announced.
func TestRunAnnouncesEachProbeThatStarts(t *testing.T) {
	f := apitest.New(t)
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(429) })
	var events []string
	probes := []Probe{
		tiny("T-1", func(ctx context.Context, x *Exec) error { _, err := post(ctx, x, "r", `{}`); return err }),
		tiny("T-2", func(ctx context.Context, x *Exec) error { return nil }),
	}
	o := opts()
	o.OnStart = func(id string) { events = append(events, fmt.Sprintf("%s after %d requests", id, len(f.Requests()))) }
	rs := Run(context.Background(), f.Client(t), probes, o)
	if len(rs) != 2 || !rs[1].NotRun {
		t.Fatalf("results = %+v", rs)
	}
	if got := strings.Join(events, "; "); got != "T-1 after 0 requests" {
		t.Errorf("announcements = %q, want only T-1, before its request", got)
	}
}

// The tally's line agrees in number with its count: "1 probe", not "1 probes".
func TestRenderTallyAgreesInNumber(t *testing.T) {
	failed := func(id string) Result { return Result{ID: id, Title: id, Error: "error"} }
	for _, c := range []struct {
		rs   []Result
		want string
	}{
		{nil, "0 probes stopped by an error, 0 not run"},
		{[]Result{failed("T-1")}, "1 probe stopped by an error, 0 not run"},
		{[]Result{failed("T-1"), failed("T-2")}, "2 probes stopped by an error, 0 not run"},
	} {
		var out bytes.Buffer
		Render(&out, c.rs)
		if !strings.HasSuffix(out.String(), c.want+"\n") {
			t.Errorf("the tally for %d errored probes is %q, want it to end with %q", len(c.rs), out.String(), c.want)
		}
	}
}

// Live reads the model tailnet's names, once, and only into memory.
func TestLiveReadsTheNamesOnce(t *testing.T) {
	f := apitest.New(t)
	f.ServeDetails(apitest.DetailsOK(liveText, etagOfLive(t), []string{liveWarning}, nil))
	var live *Live
	p := tiny("T-1", func(ctx context.Context, x *Exec) error {
		var err error
		if live, err = x.Live(ctx); err != nil {
			return err
		}
		again, err := x.Live(ctx)
		if err != nil || again != live {
			t.Errorf("the second Live read gave %v, %v", again, err)
		}
		return nil
	})
	rs := Run(context.Background(), f.Client(t), []Probe{p}, opts())
	for name, got := range map[string][]string{"tags": live.Tags, "hosts": live.Hosts, "groups": live.Groups, "logins": live.Logins, "services": live.Services} {
		want := map[string]string{"tags": "tag:live", "hosts": "live-host", "groups": "group:eng", "logins": "lee@example.com", "services": "svc:db"}[name]
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s = %v, want [%s]", name, got, want)
		}
	}
	if !live.Parsed || len(live.SSH) != 1 || live.SSH[0].Users[0] != "root" || live.ETag != etagOfLive(t) || string(live.Text) != liveText || len(live.Warnings) != 1 {
		t.Errorf("live = %+v", live)
	}
	if n := len(f.Requests()); n != 1 || f.Requests()[0].Query.Get("details") != "true" || f.Requests()[0].Accept != "" {
		t.Errorf("the live policy was read %d times, as %+v", n, f.Requests()[0])
	}
	if len(rs[0].Observations) != 1 {
		t.Errorf("the read is not recorded once: %d observations", len(rs[0].Observations))
	}
	var out bytes.Buffer
	Render(&out, rs)
	for _, tok := range liveTokens {
		if strings.Contains(out.String(), tok) {
			t.Errorf("the report shows %q from the model tailnet:\n%s", tok, out.String())
		}
	}
	rs[0].ID = "A-1" // WriteFiles takes only a real probe ID
	files, err := WriteFiles(t.TempDir(), rs, "2026-10-20")
	if err != nil || len(files) != 1 {
		t.Fatalf("WriteFiles = %v, %v", files, err)
	}
	b, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range liveTokens {
		if strings.Contains(string(b), tok) {
			t.Errorf("the file shows %q from the model tailnet:\n%s", tok, b)
		}
	}
}

// A live policy the probe cannot read as it expects is reported with a code, and the same
// failure is returned to every probe that asks.
func TestLiveRefusals(t *testing.T) {
	for name, s := range map[string]apitest.Shape{
		"a failing status":   apitest.Rejected400("no"),
		"not a details body": apitest.PolicyText(liveText, `"e"`),
		"an empty policy":    apitest.DetailsOK("", `"e"`, nil, nil),
		"bad base64":         {Name: "x", Endpoint: apitest.EndpointPolicy, Status: 200, Body: `{"acl":"!!!"}`},
	} {
		f := apitest.New(t)
		f.Serve("GET", aclPath, s)
		asks := func(ctx context.Context, x *Exec) error { _, err := x.Live(ctx); return err }
		rs := Run(context.Background(), f.Client(t), []Probe{tiny("T-1", asks), tiny("T-2", asks)}, opts())
		if rs[0].Error != "api_error" || rs[1].Error != "api_error" || len(f.Requests()) != 1 {
			t.Errorf("%s: errors %q %q after %d requests", name, rs[0].Error, rs[1].Error, len(f.Requests()))
		}
	}
	// Policy text that will not parse still gives a Live, with no names.
	l, err := parseDetails(Seen{Status: 200, Body: []byte(`{"acl":"Ig=="}`)}) // the text "
	if err != nil || l.Parsed || len(l.Tags) != 0 {
		t.Errorf("unparsable text: %+v, %v", l, err)
	}
}

// The files are the skeletons, one per probe, 0600, valid JSON, dated; a probe that did not run has none.
func TestWriteFiles(t *testing.T) {
	sk := func(id string, notRun bool) Result {
		return Result{ID: id, Title: "t", Sends: "s", Expected: "does not discriminate", Branch: "b", NotRun: notRun,
			Observations: []Observation{{Label: "l", Request: "r"}}, Checks: []Check{{Name: "c", Want: true, Got: true}}}
	}
	rs := []Result{sk("A-1", false), sk("A-2", false), sk("H-1", true)}
	dir := filepath.Join(t.TempDir(), "observed")
	names, err := WriteFiles(dir, rs, "2026-10-20")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("%d files, want 2", len(names))
	}
	if _, err := os.Stat(filepath.Join(dir, "H-1.json")); !os.IsNotExist(err) {
		t.Error("a probe that did not run was written")
	}
	b, err := os.ReadFile(filepath.Join(dir, "A-1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		ObservedOn   string `json:"observedOn"`
		Probe        string `json:"probe"`
		Expected     string `json:"expected"`
		Observations []struct{ Label string }
		Checks       []Check
	}
	if err := json.Unmarshal(b, &got); err != nil || got.ObservedOn != "2026-10-20" || got.Probe != "A-1" || got.Expected != "does not discriminate" || len(got.Observations) != 1 || len(got.Checks) != 1 {
		t.Errorf("A-1.json: %+v, %v", got, err)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(filepath.Join(dir, "A-1.json")); info.Mode().Perm() != 0o600 {
			t.Errorf("mode %v", info.Mode().Perm())
		}
	}
	if _, err := WriteFiles(filepath.Join(dir, "A-1.json"), rs, "2026-10-20"); err == nil {
		t.Error("a directory that is a file was accepted")
	}
}

// obsStatus is an observation that saw an answer with this status.
func obsStatus(status int) Observation {
	return Observation{Label: "l", Request: "r", Result: &skeleton.Skeleton{Status: status}}
}

// A probe is refused only when it has observations and every one of them saw a 401 or 403.
func TestRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		obs  []Observation
		want bool
	}{
		{"no observations", nil, false},
		{"every observation 403", []Observation{obsStatus(403), obsStatus(403)}, true},
		{"every observation 401", []Observation{obsStatus(401), obsStatus(401)}, true},
		{"a 401 and a 403", []Observation{obsStatus(403), obsStatus(401)}, true},
		{"one 403 and one 200", []Observation{obsStatus(403), obsStatus(200)}, false},
		{"one 403 and one 500", []Observation{obsStatus(403), obsStatus(500)}, false},
		{"every observation 400", []Observation{obsStatus(400), obsStatus(400)}, false},
	} {
		if got := refused(Result{Observations: tc.obs}); got != tc.want {
			t.Errorf("%s: refused = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A refused probe does not overwrite the file an earlier run left, is not counted, and does
// not stop the probes after it from being written.
func TestWriteFilesKeepsTheFileOfARefusedProbe(t *testing.T) {
	dir := t.TempDir()
	old := []byte("the capture of an earlier run\n")
	if err := os.WriteFile(filepath.Join(dir, "A-1.json"), old, 0o600); err != nil {
		t.Fatal(err)
	}
	sk := func(id string, obs ...Observation) Result {
		return Result{ID: id, Title: "t", Sends: "s", Expected: "e", Branch: "b", Observations: obs}
	}
	rs := []Result{sk("A-1", obsStatus(403), obsStatus(401)), sk("A-2", obsStatus(200))}
	names, err := WriteFiles(dir, rs, "2026-10-20")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "A-1.json")); err != nil || !bytes.Equal(got, old) {
		t.Errorf("A-1.json after a refused probe: %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "A-2.json")); err != nil {
		t.Errorf("A-2.json: %v", err)
	}
	if len(names) != 1 || names[0] != filepath.Join(dir, "A-2.json") {
		t.Errorf("names = %q, want A-2.json only", names)
	}
}

func TestHelpers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	if err := sleep(ctx, 0); err != nil {
		t.Errorf("sleep(0) = %v", err)
	}
	if err := sleep(ctx, time.Millisecond); err != nil {
		t.Errorf("sleep(1ms) = %v", err)
	}
	cancel()
	if err := sleep(ctx, time.Hour); err == nil {
		t.Error("sleep did not honour a cancelled context")
	}
	if err := sleep(ctx, 0); err == nil {
		t.Error("sleep(0) ignored a cancelled context")
	}
	if a, b := randomHex(8), randomHex(7); len(a) != 8 || len(b) != 7 || strings.Trim(a+b, "0123456789abcdef") != "" {
		t.Errorf("randomHex = %q, %q", a, b)
	}
	if first, second := randomHex(16), randomHex(16); first == second {
		t.Error("randomHex repeated itself")
	}
	for err, want := range map[error]string{ErrRateLimited: "rate_limited", ErrBudget: "request_budget", context.Canceled: "cancelled",
		context.DeadlineExceeded: "cancelled", os.ErrNotExist: "error", tkerr.New(tkerr.NotFound, "x", ""): "not_found"} {
		if got := errorCode(err); got != want {
			t.Errorf("errorCode(%v) = %q, want %q", err, got, want)
		}
	}
	// A set, not a multiset: the row asks for "the same warning set", so a repeated warning is one warning.
	if !sameSet([]string{"a", "b", "a"}, []string{"a", "b"}) || !sameSet([]string{"a", "a"}, []string{"a"}) || sameSet([]string{"a"}, []string{"b"}) || sameSet([]string{"a"}, nil) || sameSet([]string{"a", "a"}, []string{"a", "b"}) || !sameSet(nil, nil) {
		t.Error("sameSet")
	}
}

// The probes use the API only through this interface, so the real client satisfies it.
var _ API = (*api.Client)(nil)

// The probes make one attempt per request: a 429 that a retrying client would follow with a
// 200 is seen, stops the run, and is the only request sent.
func TestGetJSONMakesOneAttempt(t *testing.T) {
	f := apitest.New(t)
	var n atomic.Int32
	path := "/api/v2/tailnet/" + apitest.Tailnet + "/devices"
	f.Handle("GET", path, func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) == 1 {
			w.WriteHeader(429)
			return
		}
		_, _ = w.Write([]byte(`{"devices":[]}`))
	})
	var s Seen
	read := func(ctx context.Context, x *Exec) error {
		var err error
		s, err = x.GetJSON(ctx, Step{Label: "devices"}, "/devices", nil)
		if err != nil {
			return err
		}
		_, err = x.GetJSON(ctx, Step{Label: "devices again"}, "/devices", nil)
		return err
	}
	rs := Run(context.Background(), f.Client(t), []Probe{tiny("T-1", read), tiny("T-2", read)}, opts())
	if s.Status != 429 || len(f.Requests()) != 1 || rs[0].Error != "rate_limited" || !rs[1].NotRun {
		t.Errorf("status %d after %d requests; errors %q, T-2 not run %v", s.Status, len(f.Requests()), rs[0].Error, rs[1].NotRun)
	}
	// Any other status is data too, with its body's skeleton, and counts against the budget.
	f2 := apitest.New(t)
	f2.JSON("GET", path, 403, `{"message":"no"}`)
	o := opts()
	o.Budget = 1
	rs = Run(context.Background(), f2.Client(t), []Probe{tiny("T-1", read)}, o)
	if len(rs[0].Observations) != 1 || rs[0].Observations[0].Result == nil || rs[0].Observations[0].Result.Status != 403 || rs[0].Error != "request_budget" {
		t.Errorf("a 403 read: %+v", rs[0])
	}
}

// A stop during a probe marks that probe, whether or not the probe passed the error on, and
// the files of a probe cut short are not written: an earlier complete file stays as it was.
func TestAnInterruptedProbeIsMarkedAndNotWritten(t *testing.T) {
	f := apitest.New(t)
	var n atomic.Int32
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) == 2 {
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	})
	one := func(ctx context.Context, x *Exec) error { _, err := post(ctx, x, "a request", `{}`); return err }
	swallow := func(ctx context.Context, x *Exec) error { _, _ = post(ctx, x, "a request", `{}`); return nil } // ignores the 429
	rs := Run(context.Background(), f.Client(t), []Probe{tiny("A-1", one), tiny("A-2", swallow), tiny("A-3", one)}, opts())
	if rs[0].Error != "" || rs[1].Error != "rate_limited" || !rs[2].NotRun {
		t.Fatalf("errors %q %q, A-3 not run %v", rs[0].Error, rs[1].Error, rs[2].NotRun)
	}
	dir := t.TempDir()
	earlier := filepath.Join(dir, "A-2.json")
	if err := os.WriteFile(earlier, []byte("earlier run\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	names, err := WriteFiles(dir, rs, "2026-10-20")
	if err != nil || len(names) != 1 || filepath.Base(names[0]) != "A-1.json" {
		t.Fatalf("WriteFiles = %v, %v", names, err)
	}
	if b, _ := os.ReadFile(earlier); string(b) != "earlier run\n" {
		t.Errorf("the earlier A-2.json was overwritten: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "A-3.json")); !os.IsNotExist(err) {
		t.Error("a probe that did not run was written")
	}
	var out bytes.Buffer
	Render(&out, rs)
	if !strings.Contains(out.String(), "ERROR     the probe stopped: rate_limited") {
		t.Errorf("Render hides the stop:\n%s", out.String())
	}
}

// A 429 on the live read is rate_limited, not api_error.
func TestARateLimitedLiveReadIsRateLimited(t *testing.T) {
	f := apitest.New(t)
	f.Raw("GET", aclPath, 429, ``, nil)
	asks := func(ctx context.Context, x *Exec) error { _, err := x.Live(ctx); return err }
	rs := Run(context.Background(), f.Client(t), []Probe{tiny("T-1", asks), tiny("T-2", asks)}, opts())
	if rs[0].Error != "rate_limited" || !rs[1].NotRun || len(f.Requests()) != 1 {
		t.Errorf("%q, T-2 not run %v, %d requests", rs[0].Error, rs[1].NotRun, len(f.Requests()))
	}
}

// A panic inside a probe is recorded without its value, and the next probe runs.
func TestAPanickingProbeIsRecordedAndTheRunGoesOn(t *testing.T) {
	f := apitest.New(t)
	f.ServeValidate(apitest.TestsPass())
	boom := func(ctx context.Context, x *Exec) error {
		if _, err := post(ctx, x, "a request", `{}`); err != nil {
			return err
		}
		panic("tag:live is a name from the tailnet")
	}
	ok := func(ctx context.Context, x *Exec) error { _, err := post(ctx, x, "a request", `{}`); return err }
	rs := Run(context.Background(), f.Client(t), []Probe{tiny("A-1", boom), tiny("A-2", ok)}, opts())
	if rs[0].Error != "panic" || len(rs[0].Observations) != 1 || rs[1].Error != "" || rs[1].NotRun || len(rs[1].Observations) != 1 {
		t.Fatalf("results: %+v", rs)
	}
	var out bytes.Buffer
	Render(&out, rs)
	if strings.Contains(out.String(), "tag:live") || !strings.Contains(out.String(), "the probe stopped: panic") {
		t.Errorf("report:\n%s", out.String())
	}
}

// The files hold the templates as written: <s>, <n> and <key> are not HTML-escaped. A
// result whose ID is not a probe ID gives no path.
func TestWriteFilesKeepsTemplatesReadableAndRefusesOtherIDs(t *testing.T) {
	r := Result{ID: "A-1", Title: "t", Sends: "s", Expected: "e", Branch: "b",
		Observations: []Observation{{Label: "l", Request: "r", Result: &skeleton.Skeleton{Status: 200, Body: "json",
			Paths: []skeleton.Path{{Path: "<key>", Type: "string"}}, Texts: []string{`address "<s>-<s>:<n>": want: Drop, got: Accept`}}}}}
	dir := t.TempDir()
	names, err := WriteFiles(dir, []Result{r}, "2026-10-20")
	if err != nil || len(names) != 1 {
		t.Fatalf("WriteFiles = %v, %v", names, err)
	}
	b, err := os.ReadFile(names[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `address \"<s>-<s>:<n>\": want`) || !strings.Contains(string(b), `"path": "<key>"`) || strings.Contains(string(b), `\u003c`) {
		t.Errorf("the file is escaped:\n%s", b)
	}
	if !strings.HasSuffix(string(b), "}\n") || strings.HasSuffix(string(b), "}\n\n") {
		t.Errorf("the file does not end in exactly one newline: %q", b[len(b)-3:])
	}
	for _, id := range []string{"../x", "A-", "a-1", "A-1/x", "", "A-1\n", "T-1", "AA-1"} {
		bad := r
		bad.ID = id
		d := t.TempDir()
		if names, err := WriteFiles(d, []Result{bad}, "2026-10-20"); err == nil || len(names) != 0 {
			t.Errorf("ID %q was accepted: %v", id, names)
		}
		if entries, _ := os.ReadDir(d); len(entries) != 0 {
			t.Errorf("ID %q left files behind", id)
		}
	}
}
