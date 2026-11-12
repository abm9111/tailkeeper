package securitypack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/security"
)

func projectionFixture() Replayed {
	t := time.Date(2026, 1, 2, 3, 4, 59, 0, time.UTC)
	r := security.Report{SchemaVersion: security.SchemaVersion, GeneratedAt: t, Status: security.ReportPartial, Snapshot: security.Snapshot{Scope: security.ScopeFleet}, TotalFindings: 3}
	r.Findings = []security.Finding{
		{Asset: "private-a", RuleID: "public-rule", RuleRevision: "1", Applicability: security.ApplicabilityAffected, Confidence: security.ConfidenceReported, EvidenceState: security.EvidenceObserved, SourceSeverity: security.SeverityHigh, Priority: security.PriorityHigh, Evidence: []security.EvidenceRef{{Origin: security.OriginLocal, Freshness: security.FreshnessFresh}, {Origin: security.OriginAPI, Freshness: security.FreshnessUnknown, Error: "private"}}},
		{Asset: "private-b", RuleID: "private-rule", RuleRevision: "private-revision", Applicability: security.ApplicabilityUnknown, Reason: security.ReasonNoVersion, Confidence: security.ConfidenceUnknown, EvidenceState: security.EvidenceUnknown, SourceSeverity: security.SeverityLow, Priority: security.PriorityUnknown},
		{Asset: "private-a", RuleID: "private-rule", RuleRevision: "private-revision", Applicability: security.ApplicabilityPotential, Reason: security.ReasonNoVersion, Confidence: security.ConfidenceUnknown, EvidenceState: security.EvidenceUnknown, SourceSeverity: security.SeverityLow, Priority: security.PriorityUnknown},
	}
	r.Coverage = []security.Coverage{{Target: security.CoverageTarget{Dimension: security.CoverageVersions, Scope: security.ScopeFleet}, Status: security.ReportPartial, Source: "private", Explanation: "private", Counts: &security.CoverageCounts{Assets: 2, Rules: 1}}}
	return Replayed{Report: r, catalog: security.Catalog{Digest: "public-digest", Revision: ^uint64(0), IssuedAt: t.Add(-time.Hour), ExpiresAt: t.Add(time.Hour), Records: []security.AdvisoryRecord{{ReviewState: security.ReviewApproved, ReviewedAt: t.Add(-time.Hour), ReviewExpiresAt: t}, {ReviewState: security.ReviewPending}, {ReviewState: security.ReviewWithdrawn}}}}
}
func projectionBytes(t *testing.T, r Replayed, c PublicCatalog, ref string) []byte {
	t.Helper()
	p, err := projectReplayed(r, c, ref)
	if err != nil {
		t.Fatal(err)
	}
	out, err := EncodeProjection(p)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func TestProjectionAliasesCountsAndPublicCatalog(t *testing.T) {
	r := projectionFixture()
	c := PublicCatalog{Digest: "public-digest", Rules: []PublicRule{{ID: "public-rule", Revision: "1"}}}
	out := projectionBytes(t, r, c, "abcdef123456")
	for _, want := range []string{`"rule":"public-rule","rule_revision":"1"`, `"rule":"rule-1"`, `"id":"finding-1"`, `"device":"device-1"`, `"device":"device-2"`, `"revision":18446744073709551615`, `"stale_review":1`, `"evaluated_at":"2026-01-02T03:04:00Z"`, `"total":3`, `"reason":"no_version"`, `"ref":"abcdef123456"`} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("missing %s in %s", want, out)
		}
	}
	if bytes.Count(out, []byte(`"device":"device-1"`)) != 2 {
		t.Fatal("device aliases did not repeat")
	}
	for _, s := range []string{"private-a", "private-b", "private-rule", "private-revision", "private"} {
		if bytes.Contains(out, []byte(s)) && s != "private" {
			t.Fatalf("leaked %s", s)
		}
	}
	var document json.RawMessage
	if err := json.Unmarshal(out, &document); err != nil {
		t.Fatal(err)
	}
	if out[len(out)-1] != '\n' {
		t.Fatal("missing final LF")
	}
	out = projectionBytes(t, r, PublicCatalog{}, "")
	for _, s := range []string{"public-rule", "public-digest", `"revision":`, `"issued_at":`, `"expires_at":`, `"ref":`} {
		if bytes.Contains(out, []byte(s)) {
			t.Fatalf("unproved catalog value: %s", s)
		}
	}
}
func TestProjectionRefAndOpaqueCopy(t *testing.T) {
	for _, s := range []string{"", "012345abcdef"} {
		if !projectionRef(s) {
			t.Fatalf("rejected %q", s)
		}
	}
	for _, s := range []string{"abc", "012345abcdeF", "012345abcdef0", "012345abcdeg"} {
		if projectionRef(s) {
			t.Fatalf("accepted %q", s)
		}
	}
	if _, err := EncodeProjection(Projection{}); !errors.Is(err, errProjection) {
		t.Fatalf("zero projection: %v", err)
	}
	p, err := projectReplayed(projectionFixture(), PublicCatalog{}, "")
	if err != nil {
		t.Fatal(err)
	}
	one, err := EncodeProjection(p)
	if err != nil {
		t.Fatal(err)
	}
	one[0] = 'x'
	two, err := EncodeProjection(p)
	if err != nil {
		t.Fatal(err)
	}
	if two[0] != '{' {
		t.Fatal("caller mutated projection")
	}
}
func TestProjectionAccessCoordinatesAndNotes(t *testing.T) {
	r := projectionFixture()
	r.inputs.Intent = &security.IntentSet{Network: []security.NetworkExpectation{{ID: "arbitrary-private"}, {ID: "second-private"}}, SSH: []security.SSHExpectation{{ID: "ssh-private"}}}
	r.AccessReport = &security.AccessReport{Counts: security.AccessCounts{Total: 101, Met: 1, Unknown: 100}, Omitted: 99, Notes: []string{security.NoteNoIntent, "sentinel-private"}, Expectations: []security.AccessResult{{ID: "second-private", Kind: security.AccessNetwork, Status: security.AccessMetWithLimits, Limits: []security.AccessLimit{security.LimitApp}}, {ID: "ssh-private", Kind: security.AccessSSH, Status: security.AccessUnknown}}}
	out := projectionBytes(t, r, PublicCatalog{}, "")
	for _, s := range []string{`"id":"network-2"`, `"id":"ssh-1"`, `"total":101`, `"omitted":99`, security.NoteNoIntent} {
		if !bytes.Contains(out, []byte(s)) {
			t.Fatalf("missing %q", s)
		}
	}
	for _, s := range []string{"private", "arbitrary-private", "sentinel-private"} {
		if bytes.Contains(out, []byte(s)) && s != "private" {
			t.Fatalf("leaked %q", s)
		}
	}
	r.AccessReport.Expectations[0].ID = "missing"
	if _, err := projectReplayed(r, PublicCatalog{}, ""); !errors.Is(err, errProjection) {
		t.Fatalf("invalid coordinate: %v", err)
	}
}
func TestProjectionRemovedClasses(t *testing.T) {
	out := projectionBytes(t, projectionFixture(), PublicCatalog{}, "")
	for _, s := range []string{"context", "device_identifiers", "fact_values", "fact_times", "finding_ids", "intent_text", "witnesses", "candidate_rules", "policy_version", "catalog_bytes", "catalog_text", "coverage_text", projectionStatement} {
		if !bytes.Contains(out, []byte(s)) {
			t.Fatalf("missing %q", s)
		}
	}
}
func TestProjectionStringRepresentationIsPrivate(t *testing.T) {
	p := reflect.TypeOf(Projection{})
	if p.NumField() != 1 || p.Field(0).Name != "document" || p.Field(0).Type != reflect.TypeOf([]byte{}) || p.Field(0).IsExported() {
		t.Fatal("projection representation changed: review wire string allowlist")
	}
}
func TestProjectionDropsFreeText(t *testing.T) {
	const sentinel = "synthetic-sentinel-personal"
	r := projectionFixture()
	for i := range r.Report.Findings {
		f := &r.Report.Findings[i]
		f.Context, f.Explanation = sentinel, sentinel
		f.Requirements, f.Remediation, f.Verification = []string{sentinel}, []string{sentinel}, []string{sentinel}
		for j := range f.Evidence {
			f.Evidence[j].Context = sentinel
			f.Evidence[j].Error = sentinel
		}
	}
	for i := range r.Report.Coverage {
		r.Report.Coverage[i].Source, r.Report.Coverage[i].Explanation = sentinel, sentinel
	}
	for i := range r.catalog.Records {
		r.catalog.Records[i].Source, r.catalog.Records[i].Mitigation = sentinel, sentinel
	}
	out := projectionBytes(t, r, PublicCatalog{}, "")
	if strings.Contains(string(out), sentinel) {
		t.Fatal("projected free text")
	}
}

// These wire shapes mirror the explicit streaming schema. The manifest below forces every
// string leaf to declare its source category; DisallowUnknownFields ties it to emitted bytes.
type projectionWire struct {
	Access           *projectionAccessWire    `json:"access"`
	Catalog          projectionCatalogWire    `json:"catalog"`
	Counts           projectionCountsWire     `json:"counts"`
	Coverage         []projectionCoverageWire `json:"coverage"`
	EvaluatedAt      string                   `json:"evaluated_at"`
	EvaluatorVersion int                      `json:"evaluator_version"`
	Findings         []projectionFindingWire  `json:"findings"`
	Format           string                   `json:"format"`
	Potential        []projectionReasonWire   `json:"potential_by_reason"`
	Schema           int                      `json:"projection_schema_version"`
	Ref              string                   `json:"ref"`
	Replay           projectionReplayWire     `json:"replay_coverage"`
	ReportSchema     int                      `json:"report_schema_version"`
	Scope            string                   `json:"scope"`
	Status           string                   `json:"status"`
	Unknown          []projectionReasonWire   `json:"unknown_by_reason"`
}
type projectionCountsWire struct {
	Affected    int `json:"affected"`
	NotAffected int `json:"not_affected"`
	Potential   int `json:"potentially_affected"`
	Total       int `json:"total"`
	Unknown     int `json:"unknown"`
}
type projectionReasonWire struct {
	Count  int    `json:"count"`
	Reason string `json:"reason"`
}
type projectionCatalogWire struct {
	Approved  int    `json:"approved"`
	Digest    string `json:"digest"`
	Expires   string `json:"expires_at"`
	Issued    string `json:"issued_at"`
	Pending   int    `json:"pending"`
	Revision  uint64 `json:"revision"`
	Stale     int    `json:"stale_review"`
	State     string `json:"state_at_evaluation"`
	Withdrawn int    `json:"withdrawn"`
}
type projectionCoverageCountsWire struct {
	Assets    int `json:"assets"`
	Findings  int `json:"findings"`
	Potential int `json:"potential"`
	Rules     int `json:"rules"`
	Unknown   int `json:"unknown"`
	Withdrawn int `json:"withdrawn"`
}
type projectionCoverageWire struct {
	Counts    *projectionCoverageCountsWire `json:"counts"`
	Dimension string                        `json:"dimension"`
	Scope     string                        `json:"scope"`
	Status    string                        `json:"status"`
}
type projectionEvidenceWire struct {
	AnyError  bool     `json:"any_error"`
	Count     int      `json:"count"`
	Freshness []string `json:"freshness"`
	Origins   []string `json:"origins"`
}
type projectionFindingWire struct {
	Applicability string                 `json:"applicability"`
	Confidence    string                 `json:"confidence"`
	Device        string                 `json:"device"`
	Evidence      projectionEvidenceWire `json:"evidence"`
	EvidenceState string                 `json:"evidence_state"`
	ID            string                 `json:"id"`
	Priority      string                 `json:"priority"`
	Reason        string                 `json:"reason"`
	Rule          string                 `json:"rule"`
	Revision      string                 `json:"rule_revision"`
	Severity      string                 `json:"severity"`
}
type projectionAccessCountsWire struct {
	Met           int `json:"met"`
	MetWithLimits int `json:"met_with_limits"`
	NotEvaluated  int `json:"not_evaluated"`
	Total         int `json:"total"`
	Unknown       int `json:"unknown"`
	Unmet         int `json:"unmet"`
}
type projectionExpectationWire struct {
	ID     string   `json:"id"`
	Kind   string   `json:"kind"`
	Limits []string `json:"limits"`
	Status string   `json:"status"`
}
type projectionAccessWire struct {
	Counts       projectionAccessCountsWire  `json:"counts"`
	Expectations []projectionExpectationWire `json:"expectations"`
	Notes        []string                    `json:"notes"`
	Omitted      int                         `json:"omitted"`
}
type projectionConclusionWire struct {
	Class  string   `json:"class"`
	Needs  []string `json:"needs"`
	Status string   `json:"status"`
}
type projectionReplayWire struct {
	Conclusions  []projectionConclusionWire `json:"conclusions"`
	Removed      []string                   `json:"removed"`
	Reproducible bool                       `json:"reproducible"`
	Statement    string                     `json:"statement"`
}

func projectionStringLeaves(t reflect.Type, prefix string, result map[string]bool) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
		t = t.Elem()
	}
	if t.Kind() == reflect.String {
		result[prefix] = true
		return
	}
	if t.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := f.Tag.Get("json")
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		projectionStringLeaves(f.Type, path, result)
	}
}
func TestProjectionWireStringManifest(t *testing.T) {
	kinds := map[string]string{
		"access.expectations.id": "generated", "access.expectations.kind": "closed", "access.expectations.limits": "closed", "access.expectations.status": "closed", "access.notes": "public",
		"catalog.digest": "public", "catalog.expires_at": "time", "catalog.issued_at": "time", "catalog.state_at_evaluation": "closed",
		"coverage.dimension": "closed", "coverage.scope": "closed", "coverage.status": "closed", "evaluated_at": "time", "findings.applicability": "closed", "findings.confidence": "closed", "findings.device": "generated", "findings.evidence.freshness": "closed", "findings.evidence.origins": "closed", "findings.evidence_state": "closed", "findings.id": "generated", "findings.priority": "closed", "findings.reason": "closed", "findings.rule": "public_or_generated", "findings.rule_revision": "public", "findings.severity": "closed", "format": "constant", "potential_by_reason.reason": "closed", "ref": "public", "replay_coverage.conclusions.class": "constant", "replay_coverage.conclusions.needs": "constant", "replay_coverage.conclusions.status": "constant", "replay_coverage.removed": "constant", "replay_coverage.statement": "constant", "scope": "closed", "status": "closed", "unknown_by_reason.reason": "closed",
	}
	leaves := make(map[string]bool)
	projectionStringLeaves(reflect.TypeOf(projectionWire{}), "", leaves)
	if len(leaves) != len(kinds) {
		t.Fatalf("manifest count: got %d, want %d", len(leaves), len(kinds))
	}
	for leaf := range leaves {
		if kinds[leaf] == "" {
			t.Errorf("unclassified string %s", leaf)
		}
	}
	r := projectionFixture()
	r.inputs.Intent = &security.IntentSet{Network: []security.NetworkExpectation{{ID: "network-1"}}}
	r.AccessReport = &security.AccessReport{Expectations: []security.AccessResult{{ID: "network-1", Kind: security.AccessNetwork, Status: security.AccessMet, Limits: []security.AccessLimit{security.LimitApp}}}, Notes: []string{security.NoteNoIntent}}
	out := projectionBytes(t, r, PublicCatalog{Digest: "public-digest", Rules: []PublicRule{{ID: "public-rule", Revision: "1"}}}, "abcdef123456")
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.DisallowUnknownFields()
	var wire projectionWire
	if err := dec.Decode(&wire); err != nil {
		t.Fatal(err)
	}
}

func projectionWireAllowed(data []byte, public PublicCatalog) bool {
	var p projectionWire
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return false
	}
	if p.Format != "tailkeeper-evidence-projection" || !projectionTime(p.EvaluatedAt) || !projectionRef(p.Ref) || !oneOf(p.Scope, "fleet", "local") || !oneOf(p.Status, "complete", "partial") {
		return false
	}
	if !oneOf(p.Catalog.State, "current", "not_yet_valid", "expired") {
		return false
	}
	if p.Catalog.Digest != "" && (p.Catalog.Digest != public.Digest || !projectionTime(p.Catalog.Issued) || !projectionTime(p.Catalog.Expires)) {
		return false
	}
	if p.Catalog.Digest == "" && (p.Catalog.Issued != "" || p.Catalog.Expires != "" || p.Catalog.Revision != 0) {
		return false
	}
	for _, c := range p.Coverage {
		if !oneOf(c.Dimension, "policy", "versions", "features", "intent", "catalog") || !oneOf(c.Scope, "fleet", "local") || !oneOf(c.Status, "complete", "partial", "not_requested") {
			return false
		}
	}
	for _, f := range p.Findings {
		if !projectionFindingAllowed(f, public) {
			return false
		}
	}
	for _, rs := range [][]projectionReasonWire{p.Potential, p.Unknown} {
		for _, r := range rs {
			if !projectionReason(r.Reason) {
				return false
			}
		}
	}
	if p.Access != nil {
		for _, n := range p.Access.Notes {
			if !projectionNote(n) {
				return false
			}
		}
		for _, row := range p.Access.Expectations {
			if !projectionAccessAllowed(row) {
				return false
			}
		}
	}
	return projectionDescriptorAllowed(p.Replay)
}
func oneOf(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}
func projectionTime(s string) bool {
	t, err := time.Parse(time.RFC3339, s)
	return err == nil && t.Second() == 0 && t.Nanosecond() == 0 && strings.HasSuffix(s, "Z")
}
func projectionGenerated(s, prefix string) bool {
	if !strings.HasPrefix(s, prefix+"-") {
		return false
	}
	digits := strings.TrimPrefix(s, prefix+"-")
	if digits == "" || digits[0] == '0' {
		return false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func projectionReason(s string) bool {
	return oneOf(s, "catalog_expired", "review_expired", "review_pending", "no_version", "evidence_error", "stale_evidence", "version_conflict", "unrecognised_build", "channel_unknown", "unstable_track", "os_unrecognised", "os_unknown", "feature_unknown", "runtime_unobserved")
}
func projectionFindingAllowed(f projectionFindingWire, public PublicCatalog) bool {
	if !oneOf(f.Applicability, "affected", "potentially_affected", "not_affected", "unknown") || !oneOf(f.Confidence, "unknown", "reported", "corroborated", "derived") || !oneOf(f.EvidenceState, "observed", "unknown", "stale", "absent") || !oneOf(f.Priority, "unknown", "low", "medium", "high", "urgent") || !oneOf(f.Severity, "unknown", "low", "medium", "high", "critical") || !projectionGenerated(f.ID, "finding") || !projectionGenerated(f.Device, "device") || f.Reason != "" && !projectionReason(f.Reason) {
		return false
	}
	if f.Revision == "" {
		if !projectionGenerated(f.Rule, "rule") {
			return false
		}
	} else if !publicRule(public, f.Rule, f.Revision) {
		return false
	}
	for _, v := range f.Evidence.Freshness {
		if !oneOf(v, "unknown", "fresh", "stale") {
			return false
		}
	}
	for _, v := range f.Evidence.Origins {
		if !oneOf(v, "api", "local", "collector", "operator", "vendor", "derived") {
			return false
		}
	}
	return true
}
func projectionAccessAllowed(r projectionExpectationWire) bool {
	if !oneOf(r.Kind, "network", "ssh") || !projectionGenerated(r.ID, r.Kind) || !oneOf(r.Status, "met", "unmet", "unknown", "met_with_limits", "not_evaluated") {
		return false
	}
	for _, l := range r.Limits {
		if !oneOf(l, "posture", "app", "via", "source", "rules") {
			return false
		}
	}
	return true
}
func projectionDescriptorAllowed(p projectionReplayWire) bool {
	if p.Reproducible || p.Statement != projectionStatement || !reflect.DeepEqual(p.Removed, []string{"context", "device_identifiers", "fact_values", "fact_times", "finding_ids", "intent_text", "witnesses", "candidate_rules", "policy_version", "catalog_bytes", "catalog_text", "coverage_text"}) {
		return false
	}
	return reflect.DeepEqual(p.Conclusions, []projectionConclusionWire{{Class: "advisory_findings", Status: "not_reproducible", Needs: []string{"fact_values", "device_identifiers", "fact_times", "catalog_bytes"}}, {Class: "access_expectations", Status: "not_reproducible", Needs: []string{"intent_text", "witnesses"}}, {Class: "coverage", Status: "recorded_not_reproducible"}})
}
func TestProjectionWireAllowlistPositiveControls(t *testing.T) {
	c := PublicCatalog{Digest: "public-digest", Rules: []PublicRule{{ID: "public-rule", Revision: "1"}}}
	out := projectionBytes(t, projectionFixture(), c, "abcdef123456")
	if !projectionWireAllowed(out, c) {
		t.Fatal("valid output refused")
	}
	for _, changed := range [][]byte{bytes.Replace(out, []byte(`"scope":"fleet"`), []byte(`"scope":"synthetic-sentinel-personal"`), 1), bytes.Replace(out, []byte(`"format":`), []byte(`"forbidden_text":"synthetic-sentinel-personal","format":`), 1)} {
		if bytes.Equal(changed, out) || projectionWireAllowed(changed, c) {
			t.Fatal("positive control was not rejected")
		}
	}
}

func projectionPackFixture(t *testing.T) EvidencePack {
	t.Helper()
	at := time.Date(2026, 2, 1, 12, 0, 47, 0, time.UTC)
	sources := []advisory.Source{{Name: "fixture.json", Data: []byte(`{"schema_version":1,"revision":1,"issued_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","records":[{"id":"RULE-TEST","revision":"1","component":"client","version_role":"running_daemon","source":"synthetic","severity":"low","reviewed_at":"2025-12-01T00:00:00Z","review_expires_at":"2027-01-01T00:00:00Z","review_state":"approved","ranges":[{"fixed":"1.32.3"}],"required_features":["synthetic-feature"],"mitigation":"synthetic mitigation"}]}`)}}
	catalog, err := advisory.Merge(sources)
	if err != nil {
		t.Fatal(err)
	}
	value := "1.30.0"
	snapshot := security.Snapshot{Context: security.ContextLocalOnly, Scope: security.ScopeLocal, ObservedAt: at, Versions: []security.VersionFact{{Name: "client", Value: &value, Role: security.VersionRunningDaemon, Channel: security.ChannelStable, Evidence: security.EvidenceRef{Context: security.ContextLocalOnly, Asset: "synthetic-device", Scope: security.ScopeLocal, Origin: security.OriginLocal, AcquiredAt: at, Freshness: security.FreshnessFresh}}}}
	evidence := snapshot.Versions[0].Evidence
	flag := true
	snapshot.Platforms = []security.PlatformFact{{OS: "linux", Variant: "synthetic-variant", Evidence: evidence}}
	snapshot.Features = []security.FeatureFact{{Name: "synthetic-feature", Value: &flag, Evidence: evidence}}
	snapshot.Policies = []security.PolicyFact{{Name: "synthetic-policy", Value: &value, Evidence: evidence}}
	intent := &security.IntentSet{SchemaVersion: security.SchemaVersion, Revision: strings.Repeat("a", 12), Digest: "sha256:" + strings.Repeat("a", 64),
		Network: []security.NetworkExpectation{{ID: "network-1", Source: "synthetic-source", Protocol: "tcp", Accept: []string{"synthetic-destination:80"}, Deny: []string{"synthetic-denied:80"}, SourcePostureAttributes: security.PostureAttributes{"synthetic-attribute": {Kind: security.ScalarString, String: "synthetic-value"}, "synthetic-number": {Kind: security.ScalarNumber, Number: "1"}}}},
		SSH:     []security.SSHExpectation{{ID: "ssh-1", Source: "synthetic-source", Destinations: []string{"synthetic-destination"}, Accept: []string{"synthetic-user"}, Deny: []string{"synthetic-denied"}, Check: []string{"synthetic-check"}}},
	}
	collected := []security.Coverage{{Context: snapshot.Context, Target: security.CoverageTarget{Dimension: security.CoverageVersions, Scope: snapshot.Scope}, Source: "synthetic source", Status: security.ReportPartial, Explanation: "synthetic explanation"}, {Context: snapshot.Context, Target: security.CoverageTarget{Dimension: security.CoverageFeatures, Scope: snapshot.Scope}, Source: "synthetic source", Status: security.ReportPartial, Explanation: "synthetic explanation"}}
	in := security.Input{Catalog: catalog, Snapshot: snapshot, Intent: intent, Collected: collected, Now: at}
	report, err := security.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	access := &AccessEvidence{Context: "ctx-" + strings.Repeat("0", 16), Selected: []string{"network-1", "ssh-1"}, Input: security.AccessInput{
		Intent: *intent, EvaluatedAt: at, PolicyVersion: "\"" + strings.Repeat("a", 64) + "\"",
		Witnesses:  []security.AccessWitness{{Expectation: "network-1", Cell: security.AccessCell{Expect: "accept", Destination: "synthetic-destination:80"}, Observed: security.ObservedAllowed, Proof: security.AccessProof{Canary: true, LiveUnchanged: true}}},
		Candidates: map[string]security.AccessCandidates{"network-1": {Rules: []security.RuleRef{{Section: "acls", Index: 1, Source: "synthetic-rule-source", Destination: "synthetic-rule-destination", Ports: "80", Traffic: "tcp"}}}},
		Limits:     map[string][]security.AccessLimit{"network-1": {security.LimitApp}}, Owners: []security.AccessOwner{{Source: "synthetic-owner", Tags: []string{"tag:synthetic"}}},
	}}
	data, _, err := Build(context.Background(), BuildInput{Input: in, Report: report, Sources: sources, Access: access}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pack, _, err := Decode(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	return pack
}
func TestProjectionReplaysPrivatePack(t *testing.T) {
	pack := projectionPackFixture(t)
	for _, ref := range []string{"", "abcdef123456"} {
		p, err := Project(context.Background(), pack, security.WorkBudget{}, PublicCatalog{}, ref)
		if err != nil {
			t.Fatal(err)
		}
		data, err := EncodeProjection(p)
		if err != nil {
			t.Fatal(err)
		}
		if !projectionWireAllowed(data, PublicCatalog{}) {
			t.Fatal("invalid wire allowlist")
		}
		if _, _, err := Decode(data, nil); !errors.Is(err, ErrProjectionNotReplayable) {
			t.Fatalf("projection refusal: %v", err)
		}
	}
	if _, err := Project(context.Background(), pack, security.WorkBudget{}, PublicCatalog{}, "BAD"); !errors.Is(err, errProjection) {
		t.Fatalf("bad ref: %v", err)
	}
	pi, err := packInputOf(pack)
	if err != nil {
		t.Fatal(err)
	}
	pi.Expected.Report.SHA256 = strings.Repeat("a", 64)
	changed, err := newPack(pi, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Project(context.Background(), changed, security.WorkBudget{}, PublicCatalog{}, ""); !errors.Is(err, ErrNotReproduced) {
		t.Fatalf("non-reproduced: %v", err)
	}
}

type projectionLeaf struct {
	path    string
	indexes []int
}

func projectionPackLeaves(v reflect.Value, path string, indexes []int, out *[]projectionLeaf) {
	if v.Kind() == reflect.Pointer {
		if !v.IsNil() {
			projectionPackLeaves(v.Elem(), path, append(indexes, -1), out)
		}
		return
	}
	switch v.Kind() {
	case reflect.String:
		*out = append(*out, projectionLeaf{path: path, indexes: append([]int(nil), indexes...)})
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			return
		}
		for i := 0; i < v.NumField(); i++ {
			field := v.Type().Field(i)
			projectionPackLeaves(v.Field(i), path+"."+field.Name, append(indexes, i), out)
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		for i := 0; i < v.Len(); i++ {
			projectionPackLeaves(v.Index(i), path+"[]", append(indexes, i), out)
		}
	}
}
func projectionLeafValue(v reflect.Value, indexes []int) reflect.Value {
	for _, i := range indexes {
		if i == -1 {
			v = v.Elem()
		} else if v.Kind() == reflect.Struct {
			v = v.Field(i)
		} else {
			v = v.Index(i)
		}
	}
	return v
}
func TestProjectionPoisonsPresentPackTextLeaves(t *testing.T) {
	const sentinel = "synthetic-sentinel-personal"
	original := projectionPackFixture(t)
	originalBytes, err := Encode(original)
	if err != nil {
		t.Fatal(err)
	}
	var leaves []projectionLeaf
	projectionPackLeaves(reflect.ValueOf(original.envelope.Body), "body", nil, &leaves)
	accepted, refused := 0, 0
	for _, leaf := range leaves {
		t.Run(leaf.path, func(t *testing.T) {
			pack, _, decodeErr := Decode(originalBytes, nil)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			projectionLeafValue(reflect.ValueOf(&pack.envelope.Body).Elem(), leaf.indexes).SetString(sentinel)
			_, integrity, integrityErr := packSealInput(pack.envelope.Body)
			if integrityErr != nil {
				refused++
				return
			}
			pack.envelope.Integrity = integrity
			candidate, encodeErr := encodePackEnvelope(pack.envelope)
			if encodeErr != nil {
				refused++
				return
			}
			poisoned, _, poisonErr := Decode(candidate, nil)
			if poisonErr != nil {
				refused++
				return
			}
			pi, inputErr := packInputOf(poisoned)
			if inputErr != nil {
				t.Fatal(inputErr)
			}
			catalog, catalogErr := advisory.Merge(pi.Sources)
			if catalogErr != nil {
				t.Fatal(catalogErr)
			}
			pi.CatalogDigest = catalog.Digest
			report, evalErr := security.Evaluate(context.Background(), security.Input{Catalog: catalog, Snapshot: pi.Snapshot, Intent: pi.Intent, Collected: pi.Collected, Now: pi.EvaluationAt, Budget: pi.WorkBudget})
			if evalErr != nil {
				t.Fatalf("accepted pack cannot evaluate: %v", evalErr)
			}
			pi.Expected, evalErr = expectedReport(pi.Snapshot, report)
			if evalErr != nil {
				t.Fatal(evalErr)
			}
			if pi.Access != nil {
				access, _, accessErr := security.JudgeAccess(pi.Access.Input)
				if accessErr != nil {
					t.Fatal(accessErr)
				}
				summary, accessErr := expectedAccess(access)
				if accessErr != nil {
					t.Fatal(accessErr)
				}
				pi.Expected.Access = &summary
			}
			poisoned, evalErr = newPack(pi, nil)
			if evalErr != nil {
				t.Fatal(evalErr)
			}
			projection, projectErr := Project(context.Background(), poisoned, security.WorkBudget{}, PublicCatalog{}, "")
			if projectErr != nil {
				t.Fatal(projectErr)
			}
			output, encodeErr := EncodeProjection(projection)
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			if bytes.Contains(output, []byte(sentinel)) {
				t.Fatal("sentinel appeared in projection")
			}
			accepted++
		})
	}
	if accepted == 0 || refused == 0 {
		t.Fatalf("poisoning did not exercise accepted and refused text: accepted %d refused %d", accepted, refused)
	}
}

func TestProjectionPoisonsCatalogSemanticText(t *testing.T) {
	const sentinel = "synthetic-sentinel-personal"
	original := projectionPackFixture(t)
	for _, field := range []string{`"id":"RULE-TEST"`, `"revision":"1"`, `"component":"client"`, `"source":"synthetic"`, `"mitigation":"synthetic mitigation"`, `"required_features":["synthetic-feature"]`} {
		t.Run(field, func(t *testing.T) {
			pi, err := packInputOf(original)
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.SplitN(field, ":", 2)
			replacement := parts[0] + `:"` + sentinel + `"`
			if strings.HasPrefix(parts[1], "[") {
				replacement = parts[0] + `:["` + sentinel + `"]`
			}
			text := string(pi.Sources[0].Data)
			changed := strings.Replace(text, field, replacement, 1)
			if changed == text {
				t.Fatal("fixture missing catalog field")
			}
			pi.Sources[0].Data = []byte(changed)
			catalog, err := advisory.Merge(pi.Sources)
			if err != nil {
				t.Fatal(err)
			}
			pi.CatalogDigest = catalog.Digest
			report, err := security.Evaluate(context.Background(), security.Input{Catalog: catalog, Snapshot: pi.Snapshot, Intent: pi.Intent, Collected: pi.Collected, Now: pi.EvaluationAt, Budget: pi.WorkBudget})
			if err != nil {
				t.Fatal(err)
			}
			pi.Expected, err = expectedReport(pi.Snapshot, report)
			if err != nil {
				t.Fatal(err)
			}
			access, _, err := security.JudgeAccess(pi.Access.Input)
			if err != nil {
				t.Fatal(err)
			}
			summary, err := expectedAccess(access)
			if err != nil {
				t.Fatal(err)
			}
			pi.Expected.Access = &summary
			pack, err := newPack(pi, nil)
			if err != nil {
				t.Fatal(err)
			}
			p, err := Project(context.Background(), pack, security.WorkBudget{}, PublicCatalog{}, "")
			if err != nil {
				t.Fatal(err)
			}
			out, err := EncodeProjection(p)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(out, []byte(sentinel)) {
				t.Fatal("catalog text leaked")
			}
		})
	}
}
func projectionPackTypeLeaves(typ reflect.Type, path string, out map[string]bool) {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() == reflect.Slice {
		if typ.Elem().Kind() == reflect.Uint8 {
			return
		}
		projectionPackTypeLeaves(typ.Elem(), path+"[]", out)
		return
	}
	if typ.Kind() == reflect.String {
		out[path] = true
		return
	}
	if typ.Kind() != reflect.Struct || typ == reflect.TypeOf(time.Time{}) {
		return
	}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		projectionPackTypeLeaves(f.Type, path+"."+f.Name, out)
	}
}
func TestProjectionPoisonFixtureStringLeafCoverage(t *testing.T) {
	pack := projectionPackFixture(t)
	all := make(map[string]bool)
	projectionPackTypeLeaves(reflect.TypeOf(pack.envelope.Body), "body", all)
	var leaves []projectionLeaf
	projectionPackLeaves(reflect.ValueOf(pack.envelope.Body), "body", nil, &leaves)
	for _, leaf := range leaves {
		delete(all, leaf.path)
	}
	for missing := range all {
		t.Errorf("unpopulated wire string leaf: %s", missing)
	}
}

func TestProjectionPoisonsEveryCatalogStringLeaf(t *testing.T) {
	const sentinel = "synthetic-sentinel-personal"
	pack := projectionPackFixture(t)
	initial, err := packInputOf(pack)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := advisory.Decode(initial.Sources[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	all := make(map[string]bool)
	projectionPackTypeLeaves(reflect.TypeOf(catalog), "catalog", all)
	// Digest is derived by the decoder, has json:"-", and is never source text.
	if !all["catalog.Digest"] {
		t.Fatal("catalog digest exclusion no longer matches the model")
	}
	delete(all, "catalog.Digest")
	var leaves []projectionLeaf
	projectionPackLeaves(reflect.ValueOf(catalog), "catalog", nil, &leaves)
	for _, leaf := range leaves {
		if leaf.path != "catalog.Digest" {
			delete(all, leaf.path)
		}
	}
	for path := range all {
		t.Errorf("catalog string leaf is not populated: %s", path)
	}
	if len(all) != 0 {
		return
	}
	accepted, decodeRefused, codecRefused := 0, 0, 0
	for _, leaf := range leaves {
		if leaf.path == "catalog.Digest" {
			continue
		}
		t.Run(leaf.path, func(t *testing.T) {
			pi, inputErr := packInputOf(pack)
			if inputErr != nil {
				t.Fatal(inputErr)
			}
			c, decodeErr := advisory.Decode(pi.Sources[0].Data)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			projectionLeafValue(reflect.ValueOf(&c).Elem(), leaf.indexes).SetString(sentinel)
			source, marshalErr := json.Marshal(c)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if _, decodeErr = advisory.Decode(source); decodeErr != nil {
				decodeRefused++
				return
			}
			pi.Sources[0].Data = source
			merged, mergeErr := advisory.Merge(pi.Sources)
			if mergeErr != nil {
				t.Fatalf("accepted catalog did not merge: %v", mergeErr)
			}
			pi.CatalogDigest = merged.Digest
			report, evalErr := security.Evaluate(context.Background(), security.Input{Catalog: merged, Snapshot: pi.Snapshot, Intent: pi.Intent, Collected: pi.Collected, Now: pi.EvaluationAt, Budget: pi.WorkBudget})
			if evalErr != nil {
				t.Fatalf("accepted catalog did not evaluate: %v", evalErr)
			}
			pi.Expected, evalErr = expectedReport(pi.Snapshot, report)
			if evalErr != nil {
				t.Fatal(evalErr)
			}
			access, _, accessErr := security.JudgeAccess(pi.Access.Input)
			if accessErr != nil {
				t.Fatal(accessErr)
			}
			summary, accessErr := expectedAccess(access)
			if accessErr != nil {
				t.Fatal(accessErr)
			}
			pi.Expected.Access = &summary
			poisoned, packErr := newPack(pi, nil)
			if packErr != nil {
				if !errors.Is(packErr, ErrInvalidPack) && !errors.Is(packErr, ErrSecretShaped) {
					t.Fatalf("unexpected codec failure: %v", packErr)
				}
				codecRefused++
				return
			}
			encoded, encodeErr := Encode(poisoned)
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			poisoned, _, decodeErr = Decode(encoded, nil)
			if decodeErr != nil {
				t.Fatalf("rebuilt pack did not decode: %v", decodeErr)
			}
			projection, projectErr := Project(context.Background(), poisoned, security.WorkBudget{}, PublicCatalog{}, "")
			if projectErr != nil {
				t.Fatal(projectErr)
			}
			output, encodeErr := EncodeProjection(projection)
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			if bytes.Contains(output, []byte(sentinel)) {
				t.Fatal("catalog text appeared in projection")
			}
			accepted++
		})
	}
	t.Logf("catalog string leaves: %d accepted and replayed, %d advisory-refused, %d codec-refused", accepted, decodeRefused, codecRefused)
	if accepted == 0 || decodeRefused+codecRefused == 0 {
		t.Fatal("catalog poisoning must exercise accepted and refused paths")
	}
}
