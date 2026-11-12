package security

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testReport() Report {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return Report{SchemaVersion: 1, Context: "context-a", GeneratedAt: now, Snapshot: Snapshot{Context: "context-a", ObservedAt: now}, Status: ReportPartial}
}

func TestReportRoundTripRetainsUnknownAndPresence(t *testing.T) {
	r := testReport()
	f, tr := false, true
	evidence := func(freshness Freshness) EvidenceRef {
		return EvidenceRef{Context: r.Context, Asset: "asset-a", AcquiredAt: r.GeneratedAt, Origin: OriginAPI, Freshness: freshness}
	}
	r.Snapshot.Features = []FeatureFact{{Name: "absent", Evidence: evidence(FreshnessUnknown)}, {Name: "false", Value: &f, Evidence: evidence(FreshnessFresh)}, {Name: "true", Value: &tr, Evidence: evidence(FreshnessFresh)}, {Name: "stale", Value: &tr, Evidence: evidence(FreshnessStale)}}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var got Report
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if err := ValidateReport(got); err != nil {
		t.Fatal(err)
	}
	if got.Snapshot.Features[0].Value != nil || got.Snapshot.Features[1].Value == nil || *got.Snapshot.Features[1].Value || got.Snapshot.Features[2].Value == nil || !*got.Snapshot.Features[2].Value || got.Snapshot.Features[3].Evidence.Freshness != FreshnessStale {
		t.Fatal("presence or freshness lost")
	}
}

func TestNetworkExpectationPostureScalarRoundTrip(t *testing.T) {
	input := `{"id":"test","src":"tag:client","src_posture_attrs":{"bool":false,"number":12345678901234567890.12300e+20,"string":"linux"}}`
	var expectation NetworkExpectation
	if err := json.Unmarshal([]byte(input), &expectation); err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(expectation)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != input {
		t.Fatalf("posture types or number spelling lost: %s", got)
	}
}

func TestNetworkExpectationRejectsUnsupportedPostureValues(t *testing.T) {
	for _, value := range []string{"null", "[]", "{}"} {
		t.Run(value, func(t *testing.T) {
			var expectation NetworkExpectation
			if err := json.Unmarshal([]byte(`{"src_posture_attrs":{"attr":`+value+`}}`), &expectation); err == nil {
				t.Fatalf("accepted %s", value)
			}
		})
	}
}

func TestPostureScalarsRoundTripAndRejectInvalid(t *testing.T) {
	var n NetworkExpectation
	input := `{"src":"tag:test","src_posture_attrs":{"enabled":true,"count":3,"label":"value"}}`
	if err := json.Unmarshal([]byte(input), &n); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	var round NetworkExpectation
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatal(err)
	}
	if round.SourcePostureAttributes["enabled"].Kind != ScalarBool || round.SourcePostureAttributes["count"].Number != "3" || round.SourcePostureAttributes["label"].String != "value" {
		t.Fatal("scalar type/value lost")
	}
	for _, value := range []string{`null`, `[]`, `{}`, `1e9999`} {
		var v NetworkExpectation
		if json.Unmarshal([]byte(`{"src_posture_attrs":{"x":`+value+`}}`), &v) == nil {
			t.Fatalf("accepted %s", value)
		}
	}
	var dup NetworkExpectation
	if json.Unmarshal([]byte(`{"src_posture_attrs":{"x":true,"x":false}}`), &dup) == nil {
		t.Fatal("accepted duplicate attribute")
	}
}

func TestReportTimestampJSONRange(t *testing.T) {
	r := testReport()
	r.GeneratedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	r.Snapshot.ObservedAt = r.GeneratedAt
	if err := ValidateReport(r); err == nil || !strings.Contains(err.Error(), "invalid timestamp") {
		t.Fatalf("an unencodable year: %v", err)
	}
	// The earliest accepted time is the floor of the shared time check (2019-01-01T00:00:00Z);
	// TestReportTimeFloor pins the rejection of anything earlier.
	r = testReport()
	r.GeneratedAt = time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	r.Snapshot.ObservedAt = r.GeneratedAt
	if err := ValidateReport(r); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var got Report
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if err := ValidateReport(got); err != nil {
		t.Fatal(err)
	}
}

func TestScalarRejectsAmbiguousAndInvalidText(t *testing.T) {
	for _, scalar := range []Scalar{
		{Kind: ScalarString, String: "text", Number: "1"},
		{Kind: ScalarString, String: "text", Bool: true},
		{Kind: ScalarNumber, Number: "1", String: "text"},
		{Kind: ScalarNumber, Number: "1", Bool: true},
		{Kind: ScalarBool, Bool: true, String: "text"},
		{Kind: ScalarBool, Bool: true, Number: "1"},
		{Kind: ScalarString, String: strings.Repeat("a", MaxTextBytes+1)},
		{Kind: ScalarString, String: string([]byte{0xff})},
	} {
		if _, err := json.Marshal(scalar); err == nil {
			t.Fatalf("accepted invalid scalar %#v", scalar)
		}
	}
	var scalar Scalar
	if err := json.Unmarshal([]byte(`"`+strings.Repeat("a", MaxTextBytes+1)+`"`), &scalar); err == nil {
		t.Fatal("accepted oversized scalar string")
	}
}

func TestPostureAttributesRejectInvalidAndOversizedData(t *testing.T) {
	for _, data := range [][]byte{
		append([]byte(`{"x":"`), append([]byte{0xff}, []byte(`"}`)...)...),
		append([]byte(`{"`), append([]byte{0xff}, []byte(`":true}`)...)...),
	} {
		var attrs PostureAttributes
		if err := json.Unmarshal(data, &attrs); err == nil {
			t.Fatal("accepted invalid UTF-8")
		}
	}
	attrs := make(PostureAttributes, MaxObservations+1)
	for i := 0; i <= MaxObservations; i++ {
		attrs[strconv.Itoa(i)] = Scalar{Kind: ScalarBool}
	}
	if _, err := json.Marshal(attrs); err == nil {
		t.Fatal("accepted oversized attributes")
	}
	var encoded strings.Builder
	encoded.WriteByte('{')
	for i := 0; i <= MaxObservations; i++ {
		if i != 0 {
			encoded.WriteByte(',')
		}
		encoded.WriteString(`"` + strconv.Itoa(i) + `":true`)
	}
	encoded.WriteByte('}')
	var decoded PostureAttributes
	if err := json.Unmarshal([]byte(encoded.String()), &decoded); err == nil {
		t.Fatal("accepted oversized attributes")
	}
	if _, err := json.Marshal(PostureAttributes{string([]byte{0xff}): {Kind: ScalarBool}}); err == nil {
		t.Fatal("accepted invalid attribute name")
	}
}
