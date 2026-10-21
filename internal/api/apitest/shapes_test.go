package apitest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/skeleton"
)

// hasCapture reports whether CaptureDir holds the capture a shape names.
func hasCapture(source string) bool {
	_, err := os.Stat(CaptureFile(CaptureDir, source))
	return err == nil
}

// Every shape the ledger holds is complete, and an Observed one has a date and names a
// capture that exists (TestCheckLedgerFindsEveryDefect shows that the check can fail).
func TestTheLedgerIsComplete(t *testing.T) {
	if problems := checkLedger(AllShapes(), hasCapture); len(problems) > 0 {
		t.Errorf("the ledger: %s", strings.Join(problems, "; "))
	}
}

// provenanceOf is every builder's provenance kind, written out. A shape that moves from
// Assumed to Documented or Observed becomes an answer the readers may trust, and nothing
// else would show it: the loops over Assumed shapes simply stop visiting it. Change a row
// only when Tailscale's API documentation, or a capture committed by make probe-acl, says
// so, and let the diff of this table be what a reviewer reads.
var provenanceOf = map[string]Kind{
	"TestsWarned":  Documented,
	"Forbidden403": Documented,

	"Rejected400":          Observed,
	"TestsPass":            Observed,
	"TestsPassEmptyObject": Observed,
	"TestsFailed":          Observed,
	"BareMessage200":       Observed,
	"PolicySyntaxError":    Observed,
	"PolicyUnknownField":   Observed,
	"PolicyTagNotFound":    Observed,
	"PolicyServerError500": Observed,
	"PolicyDuplicateKey":   Observed,
	"PolicyKeyRejected":    Observed,
	"CanaryFailed":         Observed,
	"SSHTestFailed":        Observed,
	"TestUnevaluable":      Observed,
	"DetailsOK":            Observed,
	"PolicyText":           Observed,

	"TestsFailedIn400": Assumed,
	"ErrorsListAt200":  Assumed,
}

// observedBy is the probe whose capture each Observed shape names, written out: a shape
// promoted from the wrong skeleton would pass checkLedger as long as that file exists.
var observedBy = map[string]string{
	"Rejected400": "A-2", "TestsPass": "A-12", "TestsPassEmptyObject": "A-1", "TestsFailed": "A-1",
	"BareMessage200": "A-3", "PolicySyntaxError": "A-3", "PolicyUnknownField": "A-3", "PolicyTagNotFound": "A-3",
	"PolicyServerError500": "A-6", "SSHTestFailed": "A-10", "TestUnevaluable": "A-2",
	"PolicyDuplicateKey": "A-4", "PolicyKeyRejected": "A-14", "CanaryFailed": "A-9",
	"DetailsOK": "A-8", "PolicyText": "A-13",
}

func TestEveryShapesProvenanceIsPinned(t *testing.T) {
	const how = "update provenanceOf only when the API documentation or a capture committed by make probe-acl says so"
	if len(provenanceOf) != 20 {
		t.Fatalf("the table holds %d builders, want 20", len(provenanceOf))
	}
	inLedger := map[string]bool{}
	for _, s := range AllShapes() {
		inLedger[s.Name] = true
		want, ok := provenanceOf[s.Name]
		switch {
		case !ok:
			t.Errorf("%s is in the ledger but not in provenanceOf; add its row (%s)", s.Name, how)
		case s.Prov.Kind != want:
			t.Errorf("%s is %s, the table says %s: %s", s.Name, s.Prov.Kind, want, how)
		case want == Observed && s.Prov.Source != observedBy[s.Name]:
			t.Errorf("%s names the capture %q, the table says %q: %s", s.Name, s.Prov.Source, observedBy[s.Name], how)
		}
	}
	for name := range observedBy {
		if provenanceOf[name] != Observed {
			t.Errorf("observedBy names %s, which provenanceOf does not call Observed", name)
		}
	}
	for name := range provenanceOf {
		if !inLedger[name] {
			t.Errorf("provenanceOf names %s, which is not in AllShapes", name)
		}
	}
	for _, b := range shapeBuilders(t) {
		if _, ok := provenanceOf[b]; !ok {
			t.Errorf("the builder %s has no row in provenanceOf", b)
		}
	}
}

// A builder of an Observed shape must answer in the structure the capture recorded: the
// status, the key paths with their types and the grammar of each text. A body that
// differs would make the reader pass every test against the fake and fail on the real
// API. The three shapes added with the strict policy reader are tied to
// the observation they stand for; the label names it in the capture.
func TestTheNewObservedShapesMatchTheirCapture(t *testing.T) {
	for _, c := range []struct {
		shape        Shape
		probe, label string
	}{
		{PolicyDuplicateKey(2, 3, 5, 3), "A-4", "two groups blocks"},
		{CanaryFailed("tag:canary-one-two", false), "A-9", "the canary, acls absent (allow-all)"},
		{CanaryFailed("tag:canary-one-two", true), "A-9", "the canary, acls [] (deny-all)"},
		{PolicyKeyRejected("nobody-aaaaaaaa@example.com"), "A-14", "a login that cannot exist, as an object key (in hosts)"},
	} {
		raw, err := os.ReadFile(CaptureFile(CaptureDir, c.probe))
		if err != nil {
			t.Fatal(err)
		}
		var capture struct {
			Observations []struct {
				Label  string
				Result skeleton.Skeleton
			}
		}
		if err := json.Unmarshal(raw, &capture); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, o := range capture.Observations {
			if o.Label != c.label {
				continue
			}
			found = true
			if got := skeleton.Of(c.shape.Status, []byte(c.shape.Body), skeleton.DefaultOptions()); !reflect.DeepEqual(got, o.Result) {
				t.Errorf("%s does not match the observation %q of %s:\n got  %+v\n want %+v", c.shape.Name, c.label, c.probe, got, o.Result)
			}
		}
		if !found {
			t.Errorf("%s has no observation %q: the capture or the label changed", c.probe, c.label)
		}
	}
}

// The check can fail: each defect below is reported, and a clean ledger with a real
// capture is not.
func TestCheckLedgerFindsEveryDefect(t *testing.T) {
	good := TestsPass()
	bad := []struct {
		name  string
		shape Shape
		want  string
	}{
		{"no name", Shape{Endpoint: EndpointValidate, Prov: documented("x")}, "has no name"},
		{"no source", Shape{Name: "A", Endpoint: EndpointValidate, Prov: Provenance{Kind: Documented}}, "does not say where it comes from"},
		{"observed without a date", Shape{Name: "B", Endpoint: EndpointValidate, Prov: observed("", "A-1")}, "without a date"},
		{"observed without a capture", Shape{Name: "C", Endpoint: EndpointValidate, Prov: observed("2026-10-20", "A-99")}, "has no capture named A-99"},
		{"an unknown kind", Shape{Name: "D", Endpoint: EndpointValidate, Prov: Provenance{Kind: "Guessed", Source: "x"}}, `the kind "Guessed"`},
		{"no endpoint", Shape{Name: "E", Prov: documented("x")}, "answers no known endpoint"},
	}
	for _, c := range bad {
		got := strings.Join(checkLedger([]Shape{good, c.shape}, func(string) bool { return false }), "; ")
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: problems = %q, want %q", c.name, got, c.want)
		}
	}
	if got := checkLedger([]Shape{good, good}, hasCapture); len(got) != 1 || !strings.Contains(got[0], "twice") {
		t.Errorf("a repeated name: %v", got)
	}
	ok := Shape{Name: "F", Endpoint: EndpointValidate, Prov: observed("2026-10-20", "A-1")}
	if got := checkLedger([]Shape{ok}, func(s string) bool { return s == "A-1" }); len(got) != 0 {
		t.Errorf("an Observed shape with its capture: %v", got)
	}
}

func TestProvenanceString(t *testing.T) {
	for p, want := range map[Provenance]string{
		documented("x"): "Documented", assumed("x"): "Assumed",
		observed("2026-10-20", "A-1"): "Observed(2026-10-20)",
	} {
		if got := p.String(); got != want {
			t.Errorf("%+v = %q, want %q", p, got, want)
		}
	}
}

// JSON shapes are JSON, and the details body carries the policy in base64.
func TestShapesAreWellFormed(t *testing.T) {
	for _, s := range AllShapes() {
		if s.Header["Content-Type"] == "application/json" && !json.Valid([]byte(s.Body)) {
			t.Errorf("%s: the body is not JSON: %q", s.Name, s.Body)
		}
	}
	d := DetailsOK("// c\n{}\n", `"e1"`, nil, []string{"boom"})
	var got struct {
		ACL      string
		Warnings []string
		Errors   []string
	}
	if err := json.Unmarshal([]byte(d.Body), &got); err != nil {
		t.Fatal(err)
	}
	text, err := base64.StdEncoding.DecodeString(got.ACL)
	if err != nil || string(text) != "// c\n{}\n" || got.Warnings != nil || len(got.Errors) != 1 || d.Header["ETag"] != `"e1"` {
		t.Errorf("details = %+v (%q, %v), header %v", got, text, err, d.Header)
	}
	if !strings.Contains(d.Body, `"warnings":null`) {
		t.Errorf("no warnings must encode as null: %s", d.Body)
	}
}

func get(t *testing.T, url string) (int, string, http.Header) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

// A details answer is served only to a details read, and a plain one only to a plain
// read: the other request fails the test that sent it.
func TestServeDetailsAndServePolicySpyOnTheQuery(t *testing.T) {
	for _, c := range []struct {
		name   string
		serve  func(f *Fake)
		query  string
		spied  bool
		status int
	}{
		{"details, asked for", func(f *Fake) { f.ServeDetails(DetailsOK("{}\n", `"e1"`, nil, nil)) }, "?details=true", false, 200},
		{"details, not asked for", func(f *Fake) { f.ServeDetails(DetailsOK("{}\n", `"e1"`, nil, nil)) }, "", true, 200},
		{"details, asked for as 1", func(f *Fake) { f.ServeDetails(DetailsOK("{}\n", `"e1"`, nil, nil)) }, "?details=1", true, 200},
		{"plain, asked for", func(f *Fake) { f.ServePolicy(PolicyText("{}\n", `"e1"`)) }, "", false, 200},
		{"plain, details asked for", func(f *Fake) { f.ServePolicy(PolicyText("{}\n", `"e1"`)) }, "?details=true", true, 200},
	} {
		rec := &recordingTB{TB: t}
		f := New(rec)
		c.serve(f)
		status, _, hdr := get(t, f.URL()+aclPath+c.query)
		if status != c.status || hdr.Get("ETag") != `"e1"` {
			t.Errorf("%s: status %d etag %q", c.name, status, hdr.Get("ETag"))
		}
		if spied := len(rec.errs) > 0; spied != c.spied {
			t.Errorf("%s: spy reported %v, want %v", c.name, spied, c.spied)
		}
		if q := f.Requests()[0].Query; c.query == "" && len(q) != 0 {
			t.Errorf("%s: the fake recorded the query %v", c.name, q)
		}
	}
}

// The live policy endpoint does not honour If-None-Match (A-8): a plain read that carries
// the current ETag is answered 200 with the whole policy and the same ETag, not 304. The
// fake answers so too, and records the header, so a caller that waits for a 304 cannot
// pass against it.
func TestAPolicyReadWithIfNoneMatchIsAnsweredInFull(t *testing.T) {
	f := New(t)
	f.ServePolicy(PolicyText("{}\n", `"e1"`))
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, f.URL()+aclPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+AccessToken)
	req.Header.Set("If-None-Match", `"e1"`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "{}\n" || resp.Header.Get("ETag") != `"e1"` {
		t.Errorf("status %d, body %q, etag %q", resp.StatusCode, body, resp.Header.Get("ETag"))
	}
	if reqs := f.Requests(); len(reqs) != 1 || reqs[0].IfNoneMatch != `"e1"` {
		t.Errorf("the fake recorded %+v", reqs)
	}
}

// ServeValidate refuses a shape of the other endpoint, so a details body cannot be
// served as a validate answer by mistake.
func TestServeValidateRefusesAShapeOfAnotherEndpoint(t *testing.T) {
	rec := &fatalRecorder{TB: t}
	f := New(rec)
	func() {
		defer func() { _ = recover() }() // Fatalf on the recorder panics to stop the call
		f.ServeValidate(DetailsOK("{}\n", `"e1"`, nil, nil))
	}()
	if len(rec.fatals) != 1 {
		t.Errorf("%d fatal reports, want 1", len(rec.fatals))
	}
}

// fatalRecorder keeps Fatalf instead of ending the test, and stops the caller with a panic.
type fatalRecorder struct {
	testing.TB
	fatals []string
}

func (r *fatalRecorder) Fatalf(format string, args ...any) {
	r.fatals = append(r.fatals, format)
	panic("fatal")
}
func (r *fatalRecorder) Helper() {}
