package apitest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
)

// The shape ledger. Every validate and details answer a test serves is built here, by
// a named builder that says where the shape comes from. A test may not write
// such JSON by hand (TestNoHandWrittenValidateJSON), so the fake cannot drift from the
// API without a ledger entry saying how far it is known to be true.
//
//   - Documented: Tailscale's OpenAPI document or its documentation pages say so.
//   - Observed(date): `make probe-acl` saw it on the real API on that date; the
//     capture is internal/api/apitest/testdata/observed/<probe>.json. A shape is
//     promoted here only together with that file (checkLedger).
//   - Assumed: it comes from a third-party capture, a design note or a guess. The
//     reader must answer "unknown" for it, never "pass" (TestAssumedValidateShapes...).
//
// The OpenAPI document's own example for the validate request (a string with a syntax
// error) is not a source: shapes come from probes and documentation.

// Kind says how well a shape is known.
type Kind string

// The three kinds a shape can be.
const (
	Documented Kind = "Documented"
	Observed   Kind = "Observed"
	Assumed    Kind = "Assumed"
)

// Provenance is a shape's kind and where it comes from.
type Provenance struct {
	Kind   Kind
	Date   string // Observed only: YYYY-MM-DD of the run
	Source string // a document, a capture, or the probe that saw it
}

func (p Provenance) String() string {
	if p.Kind == Observed {
		return "Observed(" + p.Date + ")"
	}
	return string(p.Kind)
}

func documented(source string) Provenance { return Provenance{Kind: Documented, Source: source} }
func assumed(source string) Provenance    { return Provenance{Kind: Assumed, Source: source} }

// CaptureDir is where the ledger looks for the capture an Observed shape names, relative
// to this package: the skeleton files that make probe-acl writes (its PROBE_OUT) are
// committed here. A test ties the Makefile's PROBE_OUT to this directory, so a run cannot
// write its captures where the ledger does not look.
const CaptureDir = "testdata/observed"

// CaptureFile is the path of the capture of the probe id below dir (CaptureDir for the
// ledger, a temporary directory for a test of the writer): <id>.json.
func CaptureFile(dir, id string) string { return filepath.Join(dir, id+".json") }

// observed is the provenance of a shape the probe named by probe (its capture is
// testdata/observed/<probe>.json) saw on the real API on date (YYYY-MM-DD).
func observed(date, probe string) Provenance {
	return Provenance{Kind: Observed, Date: date, Source: probe}
}

// runOf20Oct is the date of the first run of make probe-acl against the real API.
const runOf20Oct = "2026-10-20"

// Endpoint is the call a shape answers.
type Endpoint string

// The two endpoints the ledger covers.
const (
	EndpointValidate Endpoint = "validate" // POST .../acl/validate, either mode
	EndpointPolicy   Endpoint = "policy"   // GET .../acl, with or without details=true
)

// Shape is one answer of the API: a status, headers and a body, with its provenance.
type Shape struct {
	Name     string
	Endpoint Endpoint
	Prov     Provenance
	Status   int
	Header   map[string]string
	Body     string
}

// Entry is one element of the data array of a validate answer.
type Entry struct {
	User     string   // the test's src; for a policy warning, the policy element it names
	Errors   []string // omitted when empty
	Warnings []string // omitted when empty
}

const (
	docOpenAPI   = "Tailscale OpenAPI document, validateAndTestPolicyFile"
	docForbidden = "Tailscale OpenAPI document: the 403 status; the body {\"message\":\"forbidden\"} is the repository's existing test's (internal/api/acl_test.go), not the document's"
)

var jsonHeader = map[string]string{"Content-Type": "application/json"}

func entryBody(message string, es []Entry) string {
	type entry struct {
		User     string   `json:"user"`
		Errors   []string `json:"errors,omitempty"`
		Warnings []string `json:"warnings,omitempty"`
	}
	data := make([]entry, 0, len(es))
	for _, e := range es {
		data = append(data, entry(e))
	}
	b, err := json.Marshal(struct {
		Message string  `json:"message"`
		Data    []entry `json:"data"`
	}{message, data})
	if err != nil {
		panic(err) // strings and slices of strings always encode
	}
	return string(b)
}

func messageBody(message string) string {
	b, err := json.Marshal(struct {
		Message string `json:"message"`
	}{message})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func validate(name string, p Provenance, status int, h map[string]string, body string) Shape {
	return Shape{Name: name, Endpoint: EndpointValidate, Prov: p, Status: status, Header: h, Body: body}
}

// TestsPass is a pass: HTTP 200 and an empty body ("An empty response body implies passing").
// Tests mode (a JSON array of tests) answered so on 20 Oct 2026 (A-12); policy mode
// answered {} (TestsPassEmptyObject).
func TestsPass() Shape {
	return validate("TestsPass", observed(runOf20Oct, "A-12"), 200, nil, "")
}

// TestsPassEmptyObject is the pass the OpenAPI document gives as its example: HTTP 200 and {}.
// Policy mode (the policy object as HuJSON) answered so on 20 Oct 2026 (A-1, A-5, A-11);
// tests mode answered an empty body (TestsPass).
func TestsPassEmptyObject() Shape {
	return validate("TestsPassEmptyObject", observed(runOf20Oct, "A-1"), 200, jsonHeader, `{}`)
}

// TestsEmptyData is HTTP 200 and {"data":[]}. The tests-mode pass seen on 20 Oct 2026
// was an empty body (A-12), not an empty list, so this stays Assumed and is not a pass.
func TestsEmptyData() Shape {
	return validate("TestsEmptyData", assumed("an empty data list; a tests-mode pass was an empty body"), 200, jsonHeader, `{"data":[]}`)
}

// TestsNullData is HTTP 200 and {"data":null}. A null list is not an empty body and
// was not seen on 20 Oct 2026, so this stays Assumed and is not a pass.
func TestsNullData() Shape {
	return validate("TestsNullData", assumed("a null data field; a tests-mode pass was an empty body"), 200, jsonHeader, `{"data":null}`)
}

// TestsEmptyMessage is HTTP 200 and {"message":""}. An empty message with no entries
// was not seen on 20 Oct 2026, so this stays Assumed and is not a pass.
func TestsEmptyMessage() Shape {
	return validate("TestsEmptyMessage", assumed("an empty message and no entries; a tests-mode pass was an empty body"), 200, jsonHeader, `{"message":""}`)
}

// TestsFailed is a failed test: HTTP 200, the message "test(s) failed" and one data
// entry per source with its errors. The same body carries a policy-mode failure. The
// live error lines read `[acl test error]: address "<dst>" (protocol "<p>"): want: <V>,
// got: <V>` (A-1, A-9); the entries a caller passes are its own.
func TestsFailed(es ...Entry) Shape {
	return validate("TestsFailed", observed(runOf20Oct, "A-1"), 200, jsonHeader, entryBody("test(s) failed", es))
}

// TestsWarned is a pass with warnings: HTTP 200, the message "warning(s) found" and
// one data entry per warning, whose user is the policy element it names.
func TestsWarned(es ...Entry) Shape {
	return validate("TestsWarned", documented(docOpenAPI), 200, jsonHeader, entryBody("warning(s) found", es))
}

// Rejected400 is a bare message with HTTP 400: the OpenAPI document's 400 has no data.
// The live API answered this form for a body that is not a policy at all (an empty array, an
// empty body, null, a byte order mark: A-2, A-11) and answered a well-formed document
// it rejects with HTTP 200 instead (BareMessage200, A-3).
func Rejected400(message string) Shape {
	return validate("Rejected400", observed(runOf20Oct, "A-2"), 400, jsonHeader, messageBody(message))
}

// Forbidden403 is HTTP 403 with a message: the credential lacks the scope.
func Forbidden403() Shape {
	return validate("Forbidden403", documented(docForbidden), 403, jsonHeader, messageBody("forbidden"))
}

// TestsFailedIn400 is the failure of TestsFailed with HTTP 400. The documentation
// answers failed tests with 200, and so did every failure of the run of 20 Oct 2026
// (A-1, A-9, A-10); no 400 carried data, so this stays a stand-in.
func TestsFailedIn400(es ...Entry) Shape {
	return validate("TestsFailedIn400", assumed("api.ValidateTests reads it; no 400 with data was seen on 20 Oct 2026"), 400, jsonHeader, entryBody("test(s) failed", es))
}

// BareMessage200 is a bare message with HTTP 200, no data: how the live API rejects a
// well-formed document it cannot accept (A-3, A-4, A-5; a syntax error, an unknown field,
// an unknown tag, a duplicate key). Only a body that is no policy at all is a 400.
func BareMessage200(message string) Shape {
	return validate("BareMessage200", observed(runOf20Oct, "A-3"), 200, jsonHeader, messageBody(message))
}

// ErrorsListAt200 is an answer that names none of the documented fields: a top-level
// errors list. It is not a known shape; it stands for "anything else".
func ErrorsListAt200(errs ...string) Shape {
	b, err := json.Marshal(struct {
		Errors []string `json:"errors"`
	}{errs})
	if err != nil {
		panic(err)
	}
	return validate("ErrorsListAt200", assumed("a stand-in for any answer the reader does not know"), 200, jsonHeader, string(b))
}

// PolicySyntaxError is a syntax error in policy mode: HTTP 200 and a bare message that
// starts with the position (A-3), not an HTTP 400.
func PolicySyntaxError(line, column int, detail string) Shape {
	return validate("PolicySyntaxError", observed(runOf20Oct, "A-3"), 200, jsonHeader,
		messageBody("line "+strconv.Itoa(line)+", column "+strconv.Itoa(column)+": "+detail))
}

// PolicyUnknownField is the server's strict decoder rejecting a section it does not know:
// HTTP 200 and a bare message (A-3, A-5), not an HTTP 400.
func PolicyUnknownField(name string) Shape {
	return validate("PolicyUnknownField", observed(runOf20Oct, "A-3"), 200, jsonHeader,
		messageBody("json: unknown field "+strconv.Quote(name)))
}

// PolicyTagNotFound is a rule whose src names a tag the policy does not define: HTTP 200
// and a bare message that starts with the field, `src=tag not found: "<tag>"` (A-3).
func PolicyTagNotFound(tag string) Shape {
	return validate("PolicyTagNotFound", observed(runOf20Oct, "A-3"), 200, jsonHeader, messageBody("src=tag not found: "+strconv.Quote(tag)))
}

// PolicyServerError500 is the 500 the SaaS returns for a nodeAttrs entry that targets
// autogroup:self: a bare message of three words, the same both times it was sent (A-6).
func PolicyServerError500() Shape {
	return validate("PolicyServerError500", observed(runOf20Oct, "A-6"), 500, jsonHeader, messageBody("internal server error"))
}

// PolicyDuplicateKey is a policy that writes a key twice: HTTP 200 and a bare message that
// names the key and both positions (A-4). The server rejects every repeated key, a case
// collision included, and merges nothing. The capture records the grammar of the text,
// not its words; this wording has that grammar (TestTheNewObservedShapesMatchTheirCapture).
func PolicyDuplicateKey(line1, col1, line2, col2 int) Shape {
	return validate("PolicyDuplicateKey", observed(runOf20Oct, "A-4"), 200, jsonHeader,
		messageBody(fmt.Sprintf("duplicate key %q seen twice (first %d:%d and %d:%d)", "groups", line1, col1, line2, col2)))
}

// CanaryFailed is the answer to a policy that holds the canary of acl_validate: HTTP 200,
// "test(s) failed" and one entry whose user is the canary's src and whose one error is
// in the want/got grammar (A-9). The canary accepts and denies the same destination, so
// exactly one of the two fails: with no acls (allow-all) the denial fails (want Drop, got
// Accept), with acls [] (deny-all) the acceptance does (want Accept, got Drop).
func CanaryFailed(src string, wantAccept bool) Shape {
	want, got := "Drop", "Accept"
	if wantAccept {
		want, got = got, want
	}
	text := fmt.Sprintf(`[acl test error]: address "192.0.2.1:1" (protocol "tcp"): want: %s, got: %s`, want, got)
	return validate("CanaryFailed", observed(runOf20Oct, "A-9"), 200, jsonHeader,
		entryBody("test(s) failed", []Entry{{User: src, Errors: []string{text}}}))
}

// PolicyKeyRejected is a rejection that echoes an object key: HTTP 200 and a bare message
// that quotes the key, as the server did for a login used as a key of hosts (A-14). The
// echo is Tailscale text like any other and is masked as such. The capture records the
// grammar of the text, not its words.
func PolicyKeyRejected(key string) Shape {
	return validate("PolicyKeyRejected", observed(runOf20Oct, "A-14"), 200, jsonHeader,
		messageBody(fmt.Sprintf("hosts[%q]: host names may only hold letters, digits, dashes, dots and the underscore", key)))
}

// SSHTestFailed is a failed sshTests entry. Policy mode runs sshTests and the line has this
// form (A-10); the entry's user is the test's src.
func SSHTestFailed(src, srcAddr, dst, dstAddr, user string) Shape {
	text := fmt.Sprintf("[ssh test error]: src %q at %q, dst %q at %q, ssh user %q: want: \"accept\" got: \"deny\"", src, srcAddr, dst, dstAddr, user)
	return validate("SSHTestFailed", observed(runOf20Oct, "A-10"), 200, jsonHeader,
		entryBody("test(s) failed", []Entry{{User: src, Errors: []string{text}}}))
}

// SSHCheckFailed is a guess at the line a check user would produce. No probe has seen a
// check failure, so the words want "check" and got "accept" stay Assumed, and a reader
// must not turn the line into a pass.
func SSHCheckFailed(src, srcAddr, dst, dstAddr, user string) Shape {
	text := fmt.Sprintf("[ssh test error]: src %q at %q, dst %q at %q, ssh user %q: want: \"check\" got: \"accept\"", src, srcAddr, dst, dstAddr, user)
	return validate("SSHCheckFailed", assumed("a check user; probe A-10 saw only accept and deny"), 200, jsonHeader,
		entryBody("test(s) failed", []Entry{{User: src, Errors: []string{text}}}))
}

// TestUnevaluable is a test whose src is a tag the policy does not define: an error entry
// that is not in the want/got grammar (A-2). The line carries the `[acl test error]: `
// heading and names the tag again, `user or host is invalid: tag not found: "<tag>"`.
func TestUnevaluable(src string) Shape {
	return validate("TestUnevaluable", observed(runOf20Oct, "A-2"), 200, jsonHeader,
		entryBody("test(s) failed", []Entry{{User: src, Errors: []string{"[acl test error]: user or host is invalid: tag not found: " + strconv.Quote(src)}}}))
}

// DetailsOK is GET .../acl?details=true: the policy text in base64, the warnings and
// the errors (null when there are none), and the ETag header. The live API answered 200
// with these three fields, both null for a clean policy, and the plain GET's ETag
// whether or not Accept asked for HuJSON (A-7, A-8). The skeleton does not record the
// Content-Type, and the run saw no warning (null); a list of strings is the documented form.
func DetailsOK(policy, etag string, warnings, errs []string) Shape {
	b, err := json.Marshal(struct {
		ACL      string   `json:"acl"`
		Warnings []string `json:"warnings"`
		Errors   []string `json:"errors"`
	}{base64.StdEncoding.EncodeToString([]byte(policy)), warnings, errs})
	if err != nil {
		panic(err)
	}
	return Shape{Name: "DetailsOK", Endpoint: EndpointPolicy, Prov: observed(runOf20Oct, "A-8"), Status: 200,
		Header: map[string]string{"Content-Type": "application/json", "ETag": etag}, Body: string(b)}
}

// PolicyText is GET .../acl without details: the policy as HuJSON, with its ETag. The live
// ETag is the quoted sha256 of the body as sent, and of hujson.Format of it (A-13).
func PolicyText(policy, etag string) Shape {
	return Shape{Name: "PolicyText", Endpoint: EndpointPolicy, Prov: observed(runOf20Oct, "A-13"), Status: 200,
		Header: map[string]string{"Content-Type": "application/hujson", "ETag": etag}, Body: policy}
}

// AllShapes returns one instance of every builder, for the tests that walk the ledger.
func AllShapes() []Shape {
	return []Shape{
		TestsPass(), TestsPassEmptyObject(),
		TestsEmptyData(), TestsNullData(), TestsEmptyMessage(),
		TestsFailed(Entry{User: "tag:p", Errors: []string{`[acl test error]: address "tag:p:22" (protocol "tcp"): want: Accept, got: Drop`}}),
		TestsWarned(Entry{User: "group:p", Warnings: []string{`host alias "p" unused`}}),
		Rejected400("invalid test"), Forbidden403(),
		TestsFailedIn400(Entry{User: "tag:p", Errors: []string{`[acl test error]: address "tag:p:22" (protocol "tcp"): want: Accept, got: Drop`}}),
		BareMessage200("line 1, column 1: invalid"), ErrorsListAt200("tag not found"),
		PolicySyntaxError(3, 5, "invalid literal: invalidtext"), PolicyUnknownField("nodeAttr"), PolicyTagNotFound("tag:p"),
		PolicyServerError500(), PolicyDuplicateKey(2, 3, 5, 3), PolicyKeyRejected("nobody-aaaaaaaa@example.com"),
		CanaryFailed("tag:canary-one-two", false),
		SSHTestFailed("tag:p", "100.64.0.1", "tag:p", "100.64.0.2", "root"),
		SSHCheckFailed("tag:p", "100.64.0.1", "tag:p", "100.64.0.2", "root"), TestUnevaluable("tag:p"),
		DetailsOK("{}\n", `"e1"`, []string{`host alias "p" unused`}, nil), PolicyText("{}\n", `"e1"`),
	}
}

var dateRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// checkLedger returns what is wrong with a list of shapes: a missing or repeated name,
// an unknown kind, and an Observed shape without a date or without the capture it
// names (hasCapture says whether testdata/observed/<source>.json exists).
func checkLedger(shapes []Shape, hasCapture func(source string) bool) []string {
	var problems []string
	seen := map[string]bool{}
	for _, s := range shapes {
		switch {
		case s.Name == "":
			problems = append(problems, "a shape has no name")
		case seen[s.Name]:
			problems = append(problems, s.Name+" is in the ledger twice")
		}
		seen[s.Name] = true
		switch s.Prov.Kind {
		case Documented, Assumed:
			if s.Prov.Source == "" {
				problems = append(problems, s.Name+" does not say where it comes from")
			}
		case Observed:
			if !dateRE.MatchString(s.Prov.Date) {
				problems = append(problems, s.Name+" is Observed without a date")
			}
			if !hasCapture(s.Prov.Source) {
				problems = append(problems, s.Name+" is Observed but testdata/observed has no capture named "+s.Prov.Source)
			}
		default:
			problems = append(problems, s.Name+" has the kind "+strconv.Quote(string(s.Prov.Kind)))
		}
		if s.Endpoint != EndpointValidate && s.Endpoint != EndpointPolicy {
			problems = append(problems, s.Name+" answers no known endpoint")
		}
	}
	return problems
}
