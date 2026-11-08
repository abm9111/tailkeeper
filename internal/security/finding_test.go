package security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// The expected identities are the SHA-256 of the exact length-prefixed text in
// "encoded". The digests were computed outside this repository with shasum, and the
// test recomputes each from its text, so a wrong digest cannot hide behind a wrong
// implementation.
func TestFindingIDKnownAnswers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		context string
		scope   Scope
		asset   string
		ruleID  string
		encoded string
		want    string
	}{
		{"fleet", "context-a", ScopeFleet, "asset-a", "rule-a", "9:context-a5:fleet7:asset-a6:rule-a", "577d06de67ed91166757814d3dac6c4eb84e3cccfb519eb8e169e55b9512dda7"},
		{"local", "context-a", ScopeLocal, "asset-a", "rule-a", "9:context-a5:local7:asset-a6:rule-a", "33cb2794c6a69b500cbb91cf06a692127bb51a172d6e864122479a08c8cd5314"},
		{"empty asset", "context-a", ScopeLocal, "", "rule-a", "9:context-a5:local0:6:rule-a", "ad3c61a6f2ec56fffb101f39f6cd4e61c555f97f51f5b33e15e968d718db9965"},
		{"lengths count bytes", "céntext", ScopeFleet, "ä", "rule", "8:céntext5:fleet2:ä4:rule", "0f93bc9c2e2bdba1c0cfcbce481fc248c5bedd277aac4879dc843beb7c5cfe49"},
		{"all empty", "", "", "", "", "0:0:0:0:", "8538098a725acce2a400276987f134753b5125003e70c7d36420d4e1e50a036c"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sum := sha256.Sum256([]byte(tc.encoded))
			if hex.EncodeToString(sum[:]) != tc.want {
				t.Fatalf("fixture digest does not belong to its encoded text %q", tc.encoded)
			}
			if got := FindingID(tc.context, tc.scope, tc.asset, tc.ruleID); got != tc.want {
				t.Fatalf("FindingID(%q, %q, %q, %q) = %s, want %s", tc.context, tc.scope, tc.asset, tc.ruleID, got, tc.want)
			}
		})
	}
}

func TestFindingIDIsLowercaseHexSHA256(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, id := range []string{FindingID("c", ScopeFleet, "a", "r"), FindingID("", "", "", ""), FindingID(strings.Repeat("x", MaxTextBytes), ScopeLocal, "a", "r")} {
		if !re.MatchString(id) {
			t.Fatalf("not 64 lowercase hex characters: %q", id)
		}
	}
}

// Each tuple below differs from every other in one field, or moves a character across a
// field boundary, or fakes a length prefix. All must give distinct identities, and each
// must give the same identity every time.
func TestFindingIDSeparatesEveryField(t *testing.T) {
	type tuple struct {
		context string
		scope   Scope
		asset   string
		ruleID  string
	}
	tuples := []tuple{
		{"ab", ScopeFleet, "c", "r"},
		{"a", ScopeFleet, "bc", "r"},
		{"a", ScopeFleet, "b", "cr"},
		{"a", ScopeLocal, "bc", "r"},
		{"a", ScopeFleet, "b", "c"},
		{"a", ScopeFleet, "b", "c "},
		{"a", ScopeFleet, "b ", "c"},
		{"1:a", ScopeFleet, "", "r"},
		{"", ScopeFleet, "1:a", "r"},
		{"a", ScopeFleet, "", "1:br"},
		{"a", ScopeFleet, "1:b", "r"},
		{"a", "", "fleet", "r"},
		{"a", ScopeFleet, "r", "r"},
		{"r", ScopeFleet, "a", "r"},
	}
	seen := map[string]tuple{}
	for _, tu := range tuples {
		id := FindingID(tu.context, tu.scope, tu.asset, tu.ruleID)
		if again := FindingID(tu.context, tu.scope, tu.asset, tu.ruleID); again != id {
			t.Fatalf("not deterministic for %+v", tu)
		}
		if other, dup := seen[id]; dup {
			t.Fatalf("%+v and %+v share identity %s", tu, other, id)
		}
		seen[id] = tu
	}
}

func TestUnknownReasonVocabularyIsClosed(t *testing.T) {
	want := []string{
		"catalog_expired", "review_expired", "review_pending", "no_version", "evidence_error",
		"stale_evidence", "version_conflict", "unrecognised_build", "channel_unknown",
		"unstable_track", "os_unrecognised", "os_unknown", "feature_unknown", "runtime_unobserved",
	}
	constants := []UnknownReason{
		ReasonCatalogExpired, ReasonReviewExpired, ReasonReviewPending, ReasonNoVersion, ReasonEvidenceError,
		ReasonStaleEvidence, ReasonVersionConflict, ReasonUnrecognisedBuild, ReasonChannelUnknown,
		ReasonUnstableTrack, ReasonOSUnrecognised, ReasonOSUnknown, ReasonFeatureUnknown, ReasonRuntimeUnobserved,
	}
	if len(constants) != len(want) {
		t.Fatalf("%d constants, want %d", len(constants), len(want))
	}
	for i, c := range constants {
		if string(c) != want[i] {
			t.Errorf("constant %d is %q, want %q", i, c, want[i])
		}
		if !validReason(c) {
			t.Errorf("%q is not valid", c)
		}
	}
	if len(unknownReasons) != len(want) {
		t.Fatalf("the closed set holds %d reasons, want %d", len(unknownReasons), len(want))
	}
	for i, r := range unknownReasons {
		if string(r) != want[i] {
			t.Errorf("closed set entry %d is %q, want %q", i, r, want[i])
		}
	}
	for _, bad := range []UnknownReason{"", " ", "Catalog_Expired", "catalog_expired ", "stale", "unknown", "other", "runtime-unobserved"} {
		if validReason(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestFindingReasonJSON(t *testing.T) {
	f := Finding{ID: "f", Context: "c", RuleID: "r", RuleRevision: "1", Applicability: ApplicabilityUnknown, Reason: ReasonStaleEvidence}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"reason":"stale_evidence"`) {
		t.Fatalf("reason not encoded: %s", b)
	}
	f.Reason = ""
	if b, err = json.Marshal(f); err != nil || strings.Contains(string(b), `"reason"`) {
		t.Fatalf("empty reason must be omitted: %s %v", b, err)
	}
	var got Finding
	if err := json.Unmarshal([]byte(`{"id":"f","reason":"unstable_track"}`), &got); err != nil || got.Reason != ReasonUnstableTrack {
		t.Fatalf("reason not decoded: %+v %v", got, err)
	}
}

func TestCoverageCountsJSON(t *testing.T) {
	target := CoverageTarget{Dimension: CoverageCatalog, Scope: ScopeFleet}
	full := Coverage{Target: target, Context: "c", Source: "advisory catalog", Status: ReportPartial, Counts: &CoverageCounts{Rules: 1, Withdrawn: 2, Assets: 3, Findings: 4, Unknown: 5, Potential: 6}}
	b, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"counts":{"rules":1,"withdrawn":2,"assets":3,"findings":4,"unknown":5,"potential":6}`) {
		t.Fatalf("counts not encoded with snake_case keys in order: %s", b)
	}
	var got Coverage
	if err := json.Unmarshal(b, &got); err != nil || got.Counts == nil || *got.Counts != *full.Counts {
		t.Fatalf("counts lost in a round trip: %+v %v", got, err)
	}
	zero := Coverage{Target: target, Context: "c", Source: "advisory catalog", Status: ReportComplete, Counts: &CoverageCounts{}}
	if b, err = json.Marshal(zero); err != nil || !strings.Contains(string(b), `"counts":{"rules":0,"withdrawn":0,"assets":0,"findings":0,"unknown":0,"potential":0}`) {
		t.Fatalf("zero counts must be present, not omitted: %s %v", b, err)
	}
	none := Coverage{Target: target, Context: "c", Source: "advisory catalog", Status: ReportComplete}
	if b, err = json.Marshal(none); err != nil || strings.Contains(string(b), `"counts"`) {
		t.Fatalf("absent counts must be omitted: %s %v", b, err)
	}
}

// The length prefix is the length in decimal, whatever the length: the identity of fields
// of 9, 10, 11, 99, 100, 101, 255 and 1000 bytes is the digest of text built here with fmt.
func TestFindingIDLengthPrefixIsDecimal(t *testing.T) {
	for _, n := range []int{9, 10, 11, 99, 100, 101, 255, 1000} {
		field := strings.Repeat("a", n)
		encoded := fmt.Sprintf("%d:%s%d:%s%d:%s%d:%s", n, field, len("fleet"), "fleet", n, field, n, field)
		sum := sha256.Sum256([]byte(encoded))
		if got := FindingID(field, ScopeFleet, field, field); got != hex.EncodeToString(sum[:]) {
			t.Errorf("fields of %d bytes: identity %s does not belong to %q", n, got, encoded[:12])
		}
	}
}
