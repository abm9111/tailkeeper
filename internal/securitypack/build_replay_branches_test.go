package securitypack

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/security"
)

func factsFixture() security.Snapshot {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	observed := at.Add(-time.Second)
	value, flag := "1.30.0", true
	evidence := security.EvidenceRef{Context: "ctx-local-only", Scope: security.ScopeLocal, Asset: "synthetic", Origin: security.OriginLocal, AcquiredAt: at, ObservedAt: &observed, Freshness: security.FreshnessFresh, Error: "none"}
	return security.Snapshot{
		Context: "ctx-local-only", KeyEpoch: "epoch", Scope: security.ScopeLocal, ObservedAt: at,
		Versions:  []security.VersionFact{{Name: "client", Role: security.VersionRunningDaemon, Channel: security.ChannelStable, Value: &value, Evidence: evidence}},
		Platforms: []security.PlatformFact{{OS: "linux", Variant: "x", Evidence: evidence}},
		Features:  []security.FeatureFact{{Name: "tailscale_ssh", Value: &flag, Evidence: evidence}},
		Policies:  []security.PolicyFact{{Name: "posture", Value: &value, Evidence: evidence}},
	}
}

// Every fact list and every field of a fact is bound: the report's snapshot must be the one scanned.
func TestSameSnapshotComparesEveryFact(t *testing.T) {
	if !sameSnapshot(factsFixture(), factsFixture()) {
		t.Fatal("identical snapshots differ")
	}
	other := "other"
	later := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	off := false
	cases := []struct {
		name   string
		change func(*security.Snapshot)
	}{
		{"context", func(s *security.Snapshot) { s.Context = "ctx-0123456789abcdef" }},
		{"key epoch", func(s *security.Snapshot) { s.KeyEpoch = "other" }},
		{"scope", func(s *security.Snapshot) { s.Scope = security.ScopeFleet }},
		{"observed at", func(s *security.Snapshot) { s.ObservedAt = later }},
		{"version count", func(s *security.Snapshot) { s.Versions = nil }},
		{"version role", func(s *security.Snapshot) { s.Versions[0].Role = security.VersionAPIReported }},
		{"version channel", func(s *security.Snapshot) { s.Versions[0].Channel = security.ChannelUnstable }},
		{"version name", func(s *security.Snapshot) { s.Versions[0].Name = "other" }},
		{"version value", func(s *security.Snapshot) { s.Versions[0].Value = &other }},
		{"version value presence", func(s *security.Snapshot) { s.Versions[0].Value = nil }},
		{"platform count", func(s *security.Snapshot) { s.Platforms = nil }},
		{"platform os", func(s *security.Snapshot) { s.Platforms[0].OS = "macos" }},
		{"platform variant", func(s *security.Snapshot) { s.Platforms[0].Variant = "y" }},
		{"feature count", func(s *security.Snapshot) { s.Features = nil }},
		{"feature name", func(s *security.Snapshot) { s.Features[0].Name = "other" }},
		{"feature value", func(s *security.Snapshot) { s.Features[0].Value = &off }},
		{"feature value presence", func(s *security.Snapshot) { s.Features[0].Value = nil }},
		{"policy count", func(s *security.Snapshot) { s.Policies = nil }},
		{"policy name", func(s *security.Snapshot) { s.Policies[0].Name = "other" }},
		{"policy value", func(s *security.Snapshot) { s.Policies[0].Value = &other }},
		{"policy value presence", func(s *security.Snapshot) { s.Policies[0].Value = nil }},
		{"evidence context", func(s *security.Snapshot) { s.Versions[0].Evidence.Context = "other" }},
		{"evidence asset", func(s *security.Snapshot) { s.Platforms[0].Evidence.Asset = "other" }},
		{"evidence scope", func(s *security.Snapshot) { s.Features[0].Evidence.Scope = security.ScopeFleet }},
		{"evidence origin", func(s *security.Snapshot) { s.Policies[0].Evidence.Origin = security.OriginAPI }},
		{"evidence acquired", func(s *security.Snapshot) { s.Versions[0].Evidence.AcquiredAt = later }},
		{"evidence freshness", func(s *security.Snapshot) { s.Versions[0].Evidence.Freshness = security.FreshnessStale }},
		{"evidence error", func(s *security.Snapshot) { s.Versions[0].Evidence.Error = "other" }},
		{"evidence observed value", func(s *security.Snapshot) { s.Versions[0].Evidence.ObservedAt = &later }},
		{"evidence observed presence", func(s *security.Snapshot) { s.Versions[0].Evidence.ObservedAt = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := factsFixture()
			tc.change(&changed)
			if sameSnapshot(factsFixture(), changed) || sameSnapshot(changed, factsFixture()) {
				t.Fatal("a changed snapshot compared equal")
			}
		})
	}
	// An absent observation on both sides is equal, and so are two present, equal instants.
	a, b := factsFixture(), factsFixture()
	a.Versions[0].Evidence.ObservedAt, b.Versions[0].Evidence.ObservedAt = nil, nil
	if !sameSnapshot(a, b) {
		t.Fatal("two absent observations differ")
	}
}

func TestDigestFormNamesPlainAndKeyedDigests(t *testing.T) {
	hex := strings.Repeat("0123456789abcdef", 4)
	for _, tc := range []struct {
		name   string
		intent *security.IntentSet
		want   tokenForm
		err    error
	}{
		{"absent", nil, "", nil},
		{"empty digest", &security.IntentSet{}, "", nil},
		{"plain", &security.IntentSet{Digest: "sha256:" + hex}, "plain", nil},
		{"keyed", &security.IntentSet{Digest: "hmac-sha256:" + hex}, "keyed", nil},
		{"uppercase", &security.IntentSet{Digest: "hmac-sha256:" + strings.ToUpper(hex)}, "", ErrInvalidPack},
		{"unknown prefix", &security.IntentSet{Digest: "md5:" + hex}, "", ErrInvalidPack},
	} {
		got, err := digestForm(tc.intent)
		if got != tc.want || !errors.Is(err, tc.err) {
			t.Errorf("%s: got %q %v want %q %v", tc.name, got, err, tc.want, tc.err)
		}
	}
}

func fleetAccessBuildInput(t *testing.T) BuildInput {
	t.Helper()
	in := replayFixture(t)
	in.Input.Snapshot.Scope = security.ScopeFleet
	in.Input.Snapshot.Context = "ctx-0123456789abcdef"
	in.Input.Snapshot.Versions[0].Evidence.Scope = security.ScopeFleet
	in.Input.Snapshot.Versions[0].Evidence.Context = in.Input.Snapshot.Context
	intent := security.IntentSet{SchemaVersion: security.SchemaVersion, Network: []security.NetworkExpectation{{ID: "network-1", Source: "synthetic", Accept: []string{"tag:service:443"}}}}
	in.Input.Intent = &intent
	var err error
	in.Report, err = security.Evaluate(context.Background(), in.Input)
	if err != nil {
		t.Fatal(err)
	}
	in.Access = &AccessEvidence{Context: in.Input.Snapshot.Context, Selected: []string{"network-1"}, Input: security.AccessInput{Intent: intent, EvaluatedAt: in.Input.Now}}
	return in
}

func TestBuildRefusesAccessEvidenceThatDoesNotJudge(t *testing.T) {
	in := fleetAccessBuildInput(t)
	control := *in.Access
	if _, replayed, err := Build(context.Background(), in, nil); err != nil || replayed.Reproduction.Status != "reproduced" || replayed.AccessReport == nil {
		t.Fatalf("control: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*security.AccessInput)
	}{
		{"policy version in no known form", func(a *security.AccessInput) { a.PolicyVersion = "not a policy token" }},
		{"witness for a pair nobody asked about", func(a *security.AccessInput) {
			a.Witnesses = []security.AccessWitness{{Expectation: "network-1", Cell: security.AccessCell{Expect: "accept", Destination: "unplanned:1"}, Observed: security.ObservedAllowed}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evidence := control
			tc.change(&evidence.Input)
			var pi packInput
			if err := addBuildAccess(&pi, &evidence); !errors.Is(err, ErrInvalidPack) {
				t.Fatalf("addBuildAccess: %v", err)
			}
			in.Access = &evidence
			data, replayed, err := Build(context.Background(), in, nil)
			if !errors.Is(err, ErrInvalidPack) || data != nil || replayed.Reproduction.Status != "" {
				t.Fatalf("Build: %v", err)
			}
		})
	}
	var none packInput
	if err := addBuildAccess(&none, nil); err != nil || none.Access != nil || none.Expected.Access != nil {
		t.Fatalf("no access evidence: %v", err)
	}
}

func TestReplayErrorMappingsAreSpecific(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{"canceled", context.Canceled, context.Canceled},
		{"deadline", context.DeadlineExceeded, context.DeadlineExceeded},
		{"wrapped cancellation", errors.Join(errors.New("detail"), context.Canceled), context.Canceled},
		{"anything else", errors.New("evaluator failure"), ErrInvalidPack},
	} {
		got := replayEvaluationError(tc.err)
		if !errors.Is(got, tc.want) || (errors.Is(tc.want, ErrInvalidPack) && errors.Is(got, context.Canceled)) {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
	if !errors.Is(hashError(errCanonTooLarge), ErrReportTooLarge) || !errors.Is(hashError(errCanonInvalid), ErrInvalidPack) || !errors.Is(hashError(errors.New("other")), ErrInvalidPack) {
		t.Fatal("hash error mapping")
	}
}

func TestExpectedReportAndAccessRefuseWhatTheyCannotSummarize(t *testing.T) {
	snapshot := factsFixture()
	report := security.Report{Context: snapshot.Context, GeneratedAt: snapshot.ObservedAt, Findings: []security.Finding{{ID: "id", Context: snapshot.Context, RuleID: "rule", RuleRevision: "1", Applicability: security.ApplicabilityAffected}}}
	got, err := expectedReport(snapshot, report)
	if err != nil || got.Report.Affected != 1 || got.Counts.Versions != 1 {
		t.Fatalf("control: %+v %v", got, err)
	}
	report.Findings[0].Applicability = "invented"
	if _, err := expectedReport(snapshot, report); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("unknown applicability: %v", err)
	}
	access := security.AccessReport{SchemaVersion: 1, Status: security.AccessIncomplete, EvaluatedAt: snapshot.ObservedAt}
	summary, err := expectedAccess(access)
	if err != nil || summary.Status != "incomplete" || len(summary.SHA256) != 64 {
		t.Fatalf("access control: %+v %v", summary, err)
	}
	access.PolicyVersion = "\xff"
	if _, err := expectedAccess(access); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("access text the hash refuses: %v", err)
	}
}

func TestReplayChecksThePackAgainBeforeUsingIt(t *testing.T) {
	_, pack, _ := built(t, replayFixture(t), nil)
	// Replay checks the pack again before it trusts the embedded inputs.
	tampered := pack
	tampered.envelope.Integrity = "sha256:" + strings.Repeat("0", 64)
	if _, err := Replay(context.Background(), tampered, security.WorkBudget{}); !errors.Is(err, ErrIntegrityMismatch) {
		t.Fatalf("tampered integrity: %v", err)
	}
}
