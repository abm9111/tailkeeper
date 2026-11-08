package securitypack

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/security"
)

func validPackInput() packInput {
	at := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	source := syntheticSource("ordinary")
	return packInput{Snapshot: security.Snapshot{Context: "ctx-local-only", Scope: security.ScopeLocal, ObservedAt: at}, Sources: []advisory.Source{{Name: source.Name, Data: source.Data}}, CatalogDigest: strings.Repeat("a", 64), EvaluationAt: at, EvaluatorVersion: security.EvaluatorVersion, Expected: packExpected{Report: packExpectedReport{SHA256: strings.Repeat("b", 64), Status: "partial"}}}
}

func TestPackCodecRoundTripAndOwnership(t *testing.T) {
	in := validPackInput()
	valid := "hmac-sha256:" + strings.Repeat("c", 64)
	seal := func([]byte) string { return valid }
	pack, err := newPack(in, seal)
	if err != nil {
		t.Fatalf("new pack: %v", err)
	}
	encoded, err := Encode(pack)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	in.Sources[0].Data[0] = 'x'
	again, err := Encode(pack)
	if err != nil || !bytes.Equal(again, encoded) {
		t.Fatal("producer mutation affected pack")
	}
	decoded, reading, err := Decode(encoded, seal)
	if err != nil || reading.Seal != SealValid || decoded.reading != reading {
		t.Fatalf("decode state %v, error %v", reading.Seal, err)
	}
	copy, err := packInputOf(decoded)
	if err != nil {
		t.Fatalf("pack input: %v", err)
	}
	copy.Sources[0].Data[0] = 'x'
	again, err = Encode(decoded)
	if err != nil || !bytes.Equal(again, encoded) {
		t.Fatal("consumer mutation affected pack")
	}
	if _, err := Encode(EvidencePack{}); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("zero pack: %v", err)
	}
	_, reading, err = Decode(encoded, nil)
	if err != nil || reading.Seal != SealNotChecked {
		t.Fatalf("unchecked: %v, %v", reading.Seal, err)
	}
	wrong := func([]byte) string { return "hmac-sha256:" + strings.Repeat("d", 64) }
	if _, reading, err := Decode(encoded, wrong); !errors.Is(err, ErrSealMismatch) || reading != (Reading{}) {
		t.Fatalf("wrong seal: %v, %v", reading.Seal, err)
	}
}

func TestPackAccessRoundTrip(t *testing.T) {
	in := validPackInput()
	intent := security.IntentSet{SchemaVersion: 1, Network: []security.NetworkExpectation{{ID: "network-1", Source: "group", Accept: []string{"destination"}}}}
	in.Intent = &intent
	in.Access = &accessInput{Context: "ctx-0123456789abcdef", Selected: []string{"network-1"}, Input: security.AccessInput{Intent: intent, EvaluatedAt: in.EvaluationAt, Candidates: map[string]security.AccessCandidates{"network-1": {Rules: []security.RuleRef{{Section: "acls", Index: 1, Destination: "destination"}}}}, Owners: []security.AccessOwner{{Source: "group", Tags: []string{"tag"}}}}}
	in.Expected.Access = &packExpectedAccess{SHA256: strings.Repeat("c", 64), Status: "incomplete"}
	pack, err := newPack(in, nil)
	if err != nil {
		t.Fatalf("new pack: %v", err)
	}
	encoded, err := Encode(pack)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, err := Decode(encoded, nil)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	out, err := packInputOf(decoded)
	if err != nil || out.Access == nil || !sameIntent(out.Access.Input.Intent, intent) {
		t.Fatalf("access round trip: %v", err)
	}
}

func TestPackRichConversion(t *testing.T) {
	in := validPackInput()
	observed := in.EvaluationAt
	version, policy, enabled := "1.2.3", "", false
	ev := security.EvidenceRef{Context: in.Snapshot.Context, Asset: "asset", Scope: security.ScopeLocal, Origin: security.OriginLocal, AcquiredAt: in.EvaluationAt, ObservedAt: &observed, Freshness: security.FreshnessFresh}
	in.Snapshot.Versions = []security.VersionFact{{Role: security.VersionRunningDaemon, Channel: security.ChannelStable, Name: "client", Value: &version, Evidence: ev}}
	in.Snapshot.Platforms = []security.PlatformFact{{OS: "linux", Variant: "test", Evidence: ev}}
	in.Snapshot.Features = []security.FeatureFact{{Name: "feature", Value: &enabled, Evidence: ev}}
	in.Snapshot.Policies = []security.PolicyFact{{Name: "policy", Value: &policy, Evidence: ev}}
	in.Collected = []security.Coverage{{Context: in.Snapshot.Context, Source: "synthetic", Status: security.ReportPartial, Target: security.CoverageTarget{Dimension: security.CoverageVersions, Scope: security.ScopeLocal}, Counts: &security.CoverageCounts{Assets: 1}}}
	in.Expected.Counts = packExpectedCounts{Devices: 1, Features: 1, Platforms: 1, Policies: 1, Versions: 1}
	digest := strings.Repeat("a", 64)
	intent := security.IntentSet{SchemaVersion: 1, Digest: "sha256:" + digest, Revision: digest[:12], Network: []security.NetworkExpectation{{ID: "network-1", Source: "group", Accept: []string{"destination"}, SourcePostureAttributes: security.PostureAttributes{"a": {Kind: security.ScalarString, String: ""}, "b": {Kind: security.ScalarBool, Bool: false}, "c": {Kind: security.ScalarNumber, Number: "1.50"}}}}, SSH: []security.SSHExpectation{{ID: "ssh-1", Source: "group", Destinations: []string{"destination"}, Accept: []string{"user"}}}}
	in.Intent, in.IntentDigestForm = &intent, "plain"
	in.Access = &accessInput{Context: "ctx-0123456789abcdef", Selected: []string{"ssh-1", "network-1"}, PolicyVersionForm: "plain", Input: security.AccessInput{Intent: intent, EvaluatedAt: in.EvaluationAt, PolicyVersion: `"` + digest + `"`, Witnesses: []security.AccessWitness{{Expectation: "network-1", Cell: security.AccessCell{Expect: "accept", Destination: "destination"}, Observed: security.ObservedAllowed, Proof: security.AccessProof{Canary: true, LiveUnchanged: true}}}, Limits: map[string][]security.AccessLimit{"network-1": {security.LimitRules, security.LimitPosture, security.LimitRules}}}}
	in.Expected.Access = &packExpectedAccess{SHA256: strings.Repeat("c", 64), Status: "incomplete"}
	pack, err := newPack(in, nil)
	if err != nil {
		t.Fatalf("rich pack: %v", err)
	}
	encoded, err := Encode(pack)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, err := Decode(encoded, nil)
	if err != nil {
		t.Fatalf("rich decode: %v", err)
	}
	out, err := packInputOf(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if out.Snapshot.Features[0].Value == nil || *out.Snapshot.Features[0].Value || out.Snapshot.Policies[0].Value == nil || *out.Snapshot.Policies[0].Value != "" {
		t.Fatal("optional zero values lost")
	}
	if out.Intent.Network[0].SourcePostureAttributes["c"].Number != "1.50" {
		t.Fatal("number spelling lost")
	}
	if len(out.Access.Input.Limits["network-1"]) != 2 {
		t.Fatal("limits not compacted")
	}
	*out.Snapshot.Features[0].Value = true
	out.Intent.Network[0].SourcePostureAttributes["c"] = security.Scalar{Kind: security.ScalarBool, Bool: true}
	out.Collected[0].Counts.Assets = 99
	after, err := Encode(decoded)
	if err != nil || !bytes.Equal(encoded, after) {
		t.Fatal("decoded output shares mutable values")
	}
}

func TestPackDecodeIntegrityAndVersions(t *testing.T) {
	pack, err := newPack(validPackInput(), nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := Encode(pack)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	sealer := func([]byte) string { calls++; return "hmac-sha256:" + strings.Repeat("a", 64) }
	_, reading, err := Decode(data, sealer)
	if err != nil || reading.Seal != SealAbsentKeyLoaded || calls != 0 {
		t.Fatalf("absent keyed seal: %s %v calls %d", reading.Seal, err, calls)
	}
	envelope := pack.envelope
	envelope.Body.Catalog.Digest = strings.Repeat("c", 64)
	data, err = encodePackEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decode(data, sealer); !errors.Is(err, ErrIntegrityMismatch) || calls != 0 {
		t.Fatalf("tampered body: %v, calls %d", err, calls)
	}
	for _, tc := range []struct {
		name   string
		change func(*packBody)
		want   error
	}{
		{"pack", func(b *packBody) { b.PackSchemaVersion = 2 }, ErrUnsupportedPackSchema},
		{"catalog", func(b *packBody) { b.CatalogSchemaVersion = 2 }, ErrUnsupportedCatalogSchema},
		{"report", func(b *packBody) { b.ReportSchemaVersion = 2 }, ErrUnsupportedReportSchema},
	} {
		t.Run(tc.name, func(t *testing.T) {
			envelope := pack.envelope
			tc.change(&envelope.Body)
			data, err := encodePackEnvelope(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := Decode(data, nil); !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
	envelope = pack.envelope
	envelope.Body.EvaluatorVersion = 0
	_, envelope.Integrity, err = packSealInput(envelope.Body)
	if err != nil {
		t.Fatal(err)
	}
	data, err = encodePackEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, err := Decode(data, nil)
	if err != nil {
		t.Fatalf("zero evaluator: %v", err)
	}
	out, err := packInputOf(decoded)
	if err != nil || out.EvaluatorVersion != 0 {
		t.Fatalf("zero evaluator lost: %v", err)
	}
}
