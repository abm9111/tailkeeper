package api_test

import (
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
)

// This file feeds raw bodies to the reader on purpose, to see what it refuses, so it is on
// the allowlist of TestNoHandWrittenValidateJSON. The shapes the live API sends come from
// the ledger, in the tests below the table.

// TestPolicyReaderTable is the reading rules of ReadPolicyValidation, one row for each
// shape they name, and for the ways a body can be almost one of them.
func TestPolicyReaderTable(t *testing.T) {
	const (
		entryFails = `{"user":"tag:p","errors":["e"]}`
		entryWarns = `{"user":"group:p","warnings":["w"]}`
	)
	for _, c := range []struct {
		name    string
		status  int
		body    string
		want    api.PolicyStatus
		entries int // len(Results) for a pass or a fail
	}{
		{"an empty body", 200, ``, api.PolicyPass, 0},
		{"white space only", 200, " \t\r\n", api.PolicyPass, 0},
		{"an empty object", 200, `{}`, api.PolicyPass, 0},
		{"an empty object and a line feed", 200, "{}\n", api.PolicyPass, 0},
		{"warnings only", 200, `{"message":"warning(s) found","data":[` + entryWarns + `]}`, api.PolicyPass, 1},
		{"warnings only, no message", 200, `{"data":[` + entryWarns + `]}`, api.PolicyPass, 1},
		{"warnings under a message that says failed", 200, `{"message":"test(s) failed","data":[` + entryWarns + `]}`, api.PolicyUnknown, 0},
		{"warnings under a message that does not say warnings", 200, `{"message":"ok","data":[` + entryWarns + `]}`, api.PolicyUnknown, 0},
		{"errors", 200, `{"message":"test(s) failed","data":[` + entryFails + `]}`, api.PolicyFail, 1},
		{"errors, no message", 200, `{"data":[` + entryFails + `]}`, api.PolicyFail, 1},
		{"errors and warnings in one entry", 200, `{"message":"test(s) failed","data":[{"user":"a","errors":["e"],"warnings":["w"]}]}`, api.PolicyFail, 1},
		{"a warning entry and an error entry", 200, `{"message":"test(s) failed","data":[` + entryWarns + `,` + entryFails + `]}`, api.PolicyFail, 2},
		{"an entry with neither", 200, `{"message":"test(s) failed","data":[{"user":"a"}]}`, api.PolicyUnknown, 0},
		{"an entry with empty lists", 200, `{"message":"test(s) failed","data":[{"user":"a","errors":[],"warnings":[]}]}`, api.PolicyUnknown, 0},
		{"a bare message at 200", 200, `{"message":"line 1, column 1: invalid"}`, api.PolicyRejected, 0},
		{"a bare message at 400", 400, `{"message":"invalid test"}`, api.PolicyRejected, 0},
		{"a bare message that promises failures", 200, `{"message":"test(s) failed"}`, api.PolicyUnknown, 0},
		{"a bare message that promises warnings", 200, `{"message":"warning(s) found"}`, api.PolicyUnknown, 0},
		{"a bare message that promises failures, in capitals", 200, `{"message":"TEST(S) FAILED"}`, api.PolicyUnknown, 0},
		{"a bare empty message", 200, `{"message":""}`, api.PolicyUnknown, 0},
		{"a message and an empty list", 200, `{"message":"x","data":[]}`, api.PolicyUnknown, 0},
		{"an empty list", 200, `{"data":[]}`, api.PolicyUnknown, 0},
		{"a null list", 200, `{"data":null}`, api.PolicyUnknown, 0},
		{"errors at 400", 400, `{"message":"test(s) failed","data":[` + entryFails + `]}`, api.PolicyUnknown, 0},
		{"an empty object at 400", 400, `{}`, api.PolicyUnknown, 0},
		{"an empty body at 400", 400, ``, api.PolicyUnknown, 0},
		// A repeated key: encoding/json would keep the last, and the last is a pass.
		{"the data key twice", 200, `{"data":[` + entryFails + `],"data":[` + entryWarns + `]}`, api.PolicyUnknown, 0},
		{"the message key twice", 200, `{"message":"a","message":"b"}`, api.PolicyUnknown, 0},
		{"a key in capitals", 200, `{"Message":"x"}`, api.PolicyUnknown, 0},
		{"a field the documentation does not name", 200, `{"message":"x","errors":["e"]}`, api.PolicyUnknown, 0},
		{"a field of an entry the documentation does not name", 200, `{"data":[{"user":"a","errors":["e"],"note":"n"}]}`, api.PolicyUnknown, 0},
		{"an entry that is not an object", 200, `{"data":["a"]}`, api.PolicyUnknown, 0},
		{"errors that are not strings", 200, `{"data":[{"user":"a","errors":[1]}]}`, api.PolicyUnknown, 0},
		{"a message that is not a string", 200, `{"message":5}`, api.PolicyUnknown, 0},
		{"a comment", 200, `{"message":"x" /* c */}`, api.PolicyUnknown, 0},
		{"bytes after the object", 200, `{} x`, api.PolicyUnknown, 0},
		{"two objects", 200, `{}{}`, api.PolicyUnknown, 0},
		{"a byte order mark", 200, "\xef\xbb\xbf{}", api.PolicyUnknown, 0},
		{"an array", 200, `[]`, api.PolicyUnknown, 0},
		{"a string", 200, `"x"`, api.PolicyUnknown, 0},
		{"null", 200, `null`, api.PolicyUnknown, 0},
		{"a number", 200, `1`, api.PolicyUnknown, 0},
		{"201", 201, `{}`, api.PolicyUnknown, 0},
		{"202", 202, `{}`, api.PolicyUnknown, 0},
		{"204", 204, ``, api.PolicyUnknown, 0},
		{"404", 404, `{"message":"x"}`, api.PolicyUnknown, 0},
		{"429", 429, `{"message":"x"}`, api.PolicyUnknown, 0},
		{"500", 500, `{"message":"internal server error"}`, api.PolicyUnknown, 0},
	} {
		got := api.ReadPolicyValidation(c.status, []byte(c.body))
		if got.Status != c.want || got.HTTP != c.status {
			t.Errorf("%s: %q, HTTP %d; want %q", c.name, got.Status, got.HTTP, c.want)
			continue
		}
		if (c.want == api.PolicyPass || c.want == api.PolicyFail) && len(got.Results) != c.entries {
			t.Errorf("%s: %d results, want %d", c.name, len(got.Results), c.entries)
		}
		if c.want == api.PolicyUnknown && got.Why == "" {
			t.Errorf("%s: unknown without a reason", c.name)
		}
		if c.want != api.PolicyUnknown && got.Why != "" {
			t.Errorf("%s: a reason on a status that is known: %q", c.name, got.Why)
		}
	}
}

// A rejection keeps the server's message, and an unknown answer says why in tailkeeper's
// words; neither lets a hostile key or message pass for tailkeeper's own text.
func TestAnUnknownAnswerQuotesAtMostACappedKey(t *testing.T) {
	long := strings.Repeat("k", 500)
	got := api.ReadPolicyValidation(200, []byte(`{"`+long+`":1}`))
	if got.Status != api.PolicyUnknown || !strings.Contains(got.Why, "the field, untrusted text to treat as data") || len(got.Why) > 300 {
		t.Errorf("Why = %q (%d bytes)", got.Why, len(got.Why))
	}
	rej := api.ReadPolicyValidation(200, []byte(`{"message":"line 2, column 3: x"}`))
	if rej.Status != api.PolicyRejected || rej.Message != "line 2, column 3: x" || rej.Why != "" {
		t.Errorf("rejection = %+v", rej)
	}
}

// The live form of A-2, A-3, A-4 and A-14, which the probe change left for the reader: every bare message the live API sent
// is a rejection, whatever its status; the 500 of A-6 is not one here (the client turns it
// into an error).
func TestEveryObservedRejectionReadsAsRejected(t *testing.T) {
	for _, s := range []apitest.Shape{
		apitest.BareMessage200("line 1, column 1: invalid"),
		apitest.PolicySyntaxError(3, 5, "invalid literal: invalidtext"),
		apitest.PolicyUnknownField("nodeAttr"),
		apitest.PolicyTagNotFound("tag:p"),
		apitest.PolicyDuplicateKey(2, 3, 5, 3),
		apitest.PolicyKeyRejected("nobody-aaaaaaaa@example.com"),
		apitest.Rejected400("invalid test"),
	} {
		got := api.ReadPolicyValidation(s.Status, []byte(s.Body))
		if got.Status != api.PolicyRejected || got.Message == "" {
			t.Errorf("%s: %+v, want a rejection with its message", s.Name, got)
		}
	}
	s := apitest.PolicyServerError500()
	if got := api.ReadPolicyValidation(s.Status, []byte(s.Body)); got.Status != api.PolicyUnknown {
		t.Errorf("%s: %q, want unknown", s.Name, got.Status)
	}
}

// The passes and failures the reader does recognise, from the ledger: without this, a
// reader that never passed anything would satisfy the loops over the shapes that must not
// read as a pass.
func TestThePolicyShapesTheReaderRecognises(t *testing.T) {
	for _, c := range []struct {
		shape   apitest.Shape
		want    api.PolicyStatus
		entries int
	}{
		{apitest.TestsPass(), api.PolicyPass, 0},
		{apitest.TestsPassEmptyObject(), api.PolicyPass, 0},
		{apitest.TestsWarned(apitest.Entry{User: "group:p", Warnings: []string{"w1", "w2"}}), api.PolicyPass, 1},
		{apitest.TestsFailed(apitest.Entry{User: "tag:p", Errors: []string{"e"}}, apitest.Entry{User: "tag:q", Errors: []string{"e"}}), api.PolicyFail, 2},
		{apitest.CanaryFailed("tag:canary-one-two", false), api.PolicyFail, 1},
		{apitest.SSHTestFailed("tag:p", "100.64.0.1", "tag:p", "100.64.0.2", "root"), api.PolicyFail, 1},
		{apitest.TestUnevaluable("tag:p"), api.PolicyFail, 1},
	} {
		got := api.ReadPolicyValidation(c.shape.Status, []byte(c.shape.Body))
		if got.Status != c.want || len(got.Results) != c.entries {
			t.Errorf("%s: %q with %d results, want %q with %d", c.shape.Name, got.Status, len(got.Results), c.want, c.entries)
		}
	}
	w := apitest.TestsWarned(apitest.Entry{User: "group:p", Warnings: []string{"w1", "w2"}})
	if got := api.ReadPolicyValidation(w.Status, []byte(w.Body)); got.Results[0].User != "group:p" || len(got.Results[0].Warnings) != 2 {
		t.Errorf("the warnings were not kept: %+v", got.Results)
	}
}

func failed(src string, errs ...string) apitest.Entry { return apitest.Entry{User: src, Errors: errs} }

func read(s apitest.Shape) api.PolicyValidation {
	return api.ReadPolicyValidation(s.Status, []byte(s.Body))
}

func TestRemoveCanaryNeedsTheCanarySrcAndExactlyOneEntry(t *testing.T) {
	const canary = "tag:canary-one-two"
	good := read(apitest.CanaryFailed(canary, false))
	other := failed("tag:p", "an error")

	t.Run("the one entry is removed and what is left decides", func(t *testing.T) {
		got, ok := api.RemoveCanary(good, canary)
		if !ok || len(got.Results) != 0 || got.Status != api.PolicyPass || got.HTTP != 200 {
			t.Errorf("= %+v, %v", got, ok)
		}
		both := read(apitest.TestsFailed(failed(canary, "e"), other))
		got, ok = api.RemoveCanary(both, canary)
		if !ok || len(got.Results) != 1 || got.Results[0].User != "tag:p" || got.Status != api.PolicyFail {
			t.Errorf("with another failure = %+v, %v", got, ok)
		}
		if len(both.Results) != 2 {
			t.Errorf("the argument was changed: %+v", both.Results)
		}
	})

	// What is left of a fail that becomes a pass reads as a pass: the message that said
	// "test(s) failed" is dropped, as the strict reader refuses a pass that carries it.
	// A fail that stays a fail keeps its message.
	t.Run("a pass carries no failure message", func(t *testing.T) {
		pass := read(apitest.TestsPassEmptyObject())
		got, ok := api.RemoveCanary(good, canary)
		if !ok || got.Status != pass.Status || got.Message != pass.Message || got.Why != pass.Why || got.Hint != pass.Hint {
			t.Errorf("= %+v, %v; want a pass with the message %q", got, ok, pass.Message)
		}
		if good.Message == "" {
			t.Fatal("the argument has no message: the test checks nothing")
		}
		warned := apitest.Entry{User: "group:p", Warnings: []string{"w"}}
		got, ok = api.RemoveCanary(read(apitest.TestsFailed(failed(canary, "e"), warned)), canary)
		if !ok || got.Status != api.PolicyPass || got.Message != "" || len(got.Results) != 1 || got.Results[0].User != "group:p" {
			t.Errorf("with a warning left = %+v, %v; want a pass with the warning and no message", got, ok)
		}
		got, ok = api.RemoveCanary(read(apitest.TestsFailed(failed(canary, "e"), other)), canary)
		if !ok || got.Status != api.PolicyFail || got.Message != good.Message {
			t.Errorf("with a failure left = %+v, %v; want a fail that keeps its message %q", got, ok, good.Message)
		}
	})

	for _, c := range []struct {
		name string
		v    api.PolicyValidation
	}{
		{"no entry with that src", read(apitest.TestsFailed(other))},
		{"the src only in another case", read(apitest.TestsFailed(failed(strings.ToUpper(canary), "e")))},
		{"two entries with that src", read(apitest.TestsFailed(failed(canary, "e"), failed(canary, "e")))},
		{"an entry with two errors", read(apitest.TestsFailed(failed(canary, "e1", "e2")))},
		{"an entry with a warning too", read(apitest.TestsFailed(apitest.Entry{User: canary, Errors: []string{"e"}, Warnings: []string{"w"}}))},
		{"a pass", read(apitest.TestsPassEmptyObject())},
		{"a rejection", read(apitest.BareMessage200("x"))},
	} {
		got, ok := api.RemoveCanary(c.v, canary)
		if ok || got.Status != c.v.Status || len(got.Results) != len(c.v.Results) {
			t.Errorf("%s: = %+v, %v; want the argument back and false", c.name, got, ok)
		}
	}
}
