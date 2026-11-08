package advisory

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/security"
)

// The limits of Decode are the design's numbers. The tests that use them elsewhere take
// them from the constants; these use the numbers, so a change to a limit is a change here.
func TestDecodeLimitsAreTheDesignsNumbers(t *testing.T) {
	if maxBytes != 4194304 || maxDepth != 32 {
		t.Fatalf("limits %d bytes and %d levels, want 4194304 and 32", maxBytes, maxDepth)
	}
	base := string(catalogOf(record("R1")))
	pad := func(n int) []byte { return []byte(base + strings.Repeat(" ", n-len(base))) }
	mustDecode(t, pad(4194304))
	if _, err := Decode(pad(4194305)); err == nil || err.Error() != "catalog is larger than 4194304 bytes" {
		t.Fatalf("one byte over 4 MiB: %v", err)
	}
	// records, record and id use three levels; the nested value on top of them makes 32, then 33.
	nested := func(depth int) []byte {
		return []byte(`{"schema_version":1,"revision":1,"issued_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","records":[{"id":` +
			strings.Repeat("[", depth) + strings.Repeat("]", depth) + `}]}`)
	}
	if _, err := Decode(nested(29)); err == nil || strings.Contains(err.Error(), "nests deeper") {
		t.Fatalf("32 levels must pass the pre-scan: %v", err)
	}
	if _, err := Decode(nested(30)); err == nil || err.Error() != "catalog nests deeper than 32 levels" {
		t.Fatalf("33 levels: %v", err)
	}
	if _, err := Decode([]byte("{\"a\":\"\xff\"}")); err == nil || err.Error() != "catalog is not valid UTF-8" {
		t.Fatalf("invalid UTF-8: %v", err)
	}
}

// Every member that is required is required on its own, and every member that is optional
// may be left out.
func TestDecodeRequiresEachMandatoryMemberAndOnlyThose(t *testing.T) {
	without := func(t *testing.T, doc []byte, path []string, key string) []byte {
		t.Helper()
		var top map[string]any
		if err := json.Unmarshal(doc, &top); err != nil {
			t.Fatal(err)
		}
		node := top
		for _, p := range path {
			if p == "records" {
				node = node["records"].([]any)[0].(map[string]any)
			}
		}
		delete(node, key)
		out, err := json.Marshal(top)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	doc := catalogOf(record("R1"))
	for _, key := range []string{"schema_version", "revision", "issued_at", "expires_at", "records"} {
		if _, err := Decode(without(t, doc, nil, key)); err == nil || err.Error() != "missing field "+key {
			t.Errorf("without %s: %v", key, err)
		}
	}
	for _, key := range []string{"id", "revision", "component", "version_role", "source", "severity", "reviewed_at", "review_expires_at", "review_state"} {
		if _, err := Decode(without(t, doc, []string{"records"}, key)); err == nil || err.Error() != "records: record 0: missing field "+key {
			t.Errorf("record without %s: %v", key, err)
		}
	}
	// ranges is optional too: a pending rule need not have one.
	pending := strings.Replace(strings.Replace(record("R1"), `"approved"`, `"pending"`, 1), `,"ranges":[{"fixed":"1.32.3"}]`, ``, 1)
	mustDecode(t, catalogOf(pending))
}

// The messages of a refusal, in full: where the input stopped or went wrong, and what the
// program says about it. A message that is not the one of its own check is a different check.
func TestDecodeMessagesAreExact(t *testing.T) {
	head := `{"schema_version":1,"revision":1,"issued_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","records":`
	for _, tc := range []struct{ name, in, want string }{
		{"empty input", ``, `unexpected EOF`},
		{"cut inside the document's first member", `{"schema_version"`, `schema_version: unexpected EOF`},
		{"cut after a key", `{"schema_version":`, `schema_version: unexpected EOF`},
		{"cut after a value", `{"schema_version":1`, `unexpected end of JSON input`},
		{"cut inside a time", `{"schema_version":1,"revision":1,"issued_at":"2026-01`, `issued_at: unexpected EOF`},
		{"cut before the records", head, `records: unexpected EOF`},
		{"cut after the start of the records", head + `[`, `records: record 0: unexpected end of JSON input`},
		{"cut after a key of a record", head + `[{"id"`, `records: record 0: id: unexpected EOF`},
		{"cut after a record's id", head + `[{"id":"R1"`, `records: record 0: unexpected end of JSON input`},
		{"cut after the key of the ranges", head + `[{"id":"R1","ranges"`, `records: record 0: ranges: unexpected EOF`},
		{"cut after the start of the ranges", head + `[{"id":"R1","ranges":[`, `records: record 0: ranges: range 0: unexpected end of JSON input`},
		{"cut after a range key", head + `[{"id":"R1","ranges":[{"fixed"`, `records: record 0: ranges: range 0: fixed: unexpected EOF`},
		{"cut after the first range", head + `[{"id":"R1","ranges":[{"fixed":"1.2.0"}`, `records: record 0: ranges: range 1: unexpected end of JSON input`},
		{"cut after the start of the features", head + `[{"id":"R1","required_features":[`, `records: record 0: required_features: required feature 0: unexpected end of JSON input`},
		{"cut after the first feature", head + `[{"id":"R1","required_features":["a"`, `records: record 0: required_features: required feature 1: unexpected end of JSON input`},
		{"cut inside a feature", head + `[{"id":"R1","required_features":["a`, `records: record 0: required_features: required feature 0: unexpected EOF`},
		{"a closer that does not match the document", `{"schema_version":1]`, `invalid character ']' after object key:value pair`},
		{"a closer that does not match a record", head + `[{"id":"R1"]`, `records: record 0: invalid character ']' after object key:value pair`},
		{"a closer that does not match a range", head + `[{"id":"R1","ranges":[{"fixed":"1.2.0"]}]}`, `records: record 0: ranges: range 0: invalid character ']' after object key:value pair`},
		{"a member with no colon", `{"schema_version" 1}`, `schema_version: invalid character '1' after object key`},
		{"a record of the wrong type", head + `["x"]}`, `records: record 0: expected {`},
		{"a record field of the wrong type", head + `[{"id":"R1","revision":"1","component":5}]}`, `records: record 0: component: json: cannot unmarshal number into Go value of type string`},
		{"a range field of the wrong type", head + `[{"id":"R1","ranges":[{"fixed":5}]}]}`, `records: record 0: ranges: range 0: fixed: json: cannot unmarshal number into Go value of type string`},
		{"a feature of the wrong type", head + `[{"id":"R1","required_features":[5]}]}`, `records: record 0: required_features: required feature 0: json: cannot unmarshal number into Go value of type string`},
		{"a range of the wrong type", head + `[{"id":"R1","ranges":[1]}]}`, `records: record 0: ranges: range 0: expected {`},
		{"a revision of the wrong type", `{"schema_version":1,"revision":"x"}`, `revision: json: cannot unmarshal string into Go value of type uint64`},
		{"records that are not an array", head + `5}`, `records: expected [`},
		{"records that are null", head + `null}`, `records: expected [`},
		{"ranges that are not an array", head + `[{"id":"R1","ranges":5}]}`, `records: record 0: ranges: expected [`},
		{"features that are not an array", head + `[{"id":"R1","required_features":5}]}`, `records: record 0: required_features: expected [`},
		{"trailing text", string(catalogOf(record("R1"))) + ` x`, `trailing catalog data`},
		{"a second document", string(catalogOf(record("R1"))) + ` {}`, `trailing catalog data`},
		{"an unknown member", strings.Replace(string(catalogOf(record("R1"))), `"revision":1,`, `"revision":1,"extra":1,`, 1), `unknown field "extra"`},
		{"a repeated member", strings.Replace(string(catalogOf(record("R1"))), `"revision":1,`, `"revision":1,"revision":1,`, 1), `duplicate field "revision"`},
		{"a null value", strings.Replace(string(catalogOf(record("R1"))), `"revision":1,`, `"revision":null,`, 1), `revision: null is not allowed`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Decode([]byte(tc.in))
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if c.Records != nil || c.Digest != "" {
				t.Fatalf("a part-filled catalog came back with the error: %+v", c)
			}
		})
	}
}

// A key of exactly 40 bytes is echoed whole; one byte more is cut at 40 and marked.
func TestDecodeEchoesAKeyOfFortyBytesWhole(t *testing.T) {
	for _, tc := range []struct{ key, want string }{
		{strings.Repeat("k", 39), `"` + strings.Repeat("k", 39) + `"`},
		{strings.Repeat("k", 40), `"` + strings.Repeat("k", 40) + `"`},
		{strings.Repeat("k", 41), `"` + strings.Repeat("k", 40) + `"...`},
	} {
		in := bytes.Replace(catalogOf(record("R1")), []byte(`"revision":1,`), []byte(`"revision":1,"`+tc.key+`":1,`), 1)
		if _, err := Decode(in); err == nil || err.Error() != "unknown field "+tc.want {
			t.Errorf("key of %d bytes: %v, want unknown field %s", len(tc.key), err, tc.want)
		}
	}
}

// An accepted catalog still has every record and range it was given, in order.
func TestDecodeKeepsEverythingItWasGiven(t *testing.T) {
	c := mustDecode(t, catalogOf(record("R1"), record("R2")))
	if len(c.Records) != 2 || c.Records[0].ID != "R1" || c.Records[1].ID != "R2" || c.Revision != 1 || c.SchemaVersion != security.SchemaVersion {
		t.Fatalf("%+v", c)
	}
}
