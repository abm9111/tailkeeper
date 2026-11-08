package security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

// Every rule of ValidateReport has cases here whose input is valid except for that one
// rule, and whose error text is asserted. A case cannot pass because another check fired:
// the two fixtures pass ValidateReport (TestReportRuleFixturesAreValid), each case changes
// one thing, and the messages of different rules differ (TestReportRuleMessagesDiffer).

const rulesCtx = "context-a"

var rulesNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

var rulesCatalogTarget = CoverageTarget{Dimension: CoverageCatalog, Scope: ScopeLocal}

func rulesEvidence(asset string, origin Origin) EvidenceRef {
	return EvidenceRef{Context: rulesCtx, Asset: asset, Scope: ScopeLocal, Origin: origin, AcquiredAt: rulesNow, Freshness: FreshnessFresh}
}

// rulesFinding builds a finding of the given applicability that satisfies every rule of
// ValidateReport: its ID is the one FindingID gives, an affected or not-affected finding
// cites observed evidence for its own device, and an unknown or potential one has a reason.
func rulesFinding(asset, rule string, applicability Applicability) Finding {
	f := Finding{
		ID: FindingID(rulesCtx, ScopeLocal, asset, rule), Context: rulesCtx, Asset: asset, RuleID: rule, RuleRevision: "1",
		Applicability: applicability, Confidence: ConfidenceReported, SourceSeverity: SeverityLow, Priority: PriorityUnknown,
		Explanation: "Synthetic evaluation.",
	}
	switch applicability {
	case ApplicabilityAffected, ApplicabilityNotAffected:
		f.EvidenceState = EvidenceObserved
		f.Evidence = []EvidenceRef{rulesEvidence(asset, OriginLocal)}
	case ApplicabilityPotential:
		f.EvidenceState = EvidenceObserved
		f.Reason = ReasonOSUnknown
		f.Evidence = []EvidenceRef{rulesEvidence(asset, OriginLocal)}
	default:
		f.EvidenceState = EvidenceStale
		f.Reason = ReasonStaleEvidence
	}
	return f
}

// rulesBase is a report with a snapshot of every kind of fact and no findings or coverage.
func rulesBase() Report {
	e := rulesEvidence("asset-a", OriginLocal)
	policy := rulesEvidence("", OriginAPI)
	version, revision, ssh := "1.30.0", "7", true
	return Report{
		SchemaVersion: SchemaVersion, Context: rulesCtx, GeneratedAt: rulesNow, Status: ReportPartial,
		Snapshot: Snapshot{
			Context: rulesCtx, Scope: ScopeLocal, ObservedAt: rulesNow,
			Versions:  []VersionFact{{Role: VersionRunningDaemon, Channel: ChannelStable, Name: "client", Value: &version, Evidence: e}},
			Platforms: []PlatformFact{{OS: "linux", Evidence: e}},
			Features:  []FeatureFact{{Name: "ssh", Value: &ssh, Evidence: e}},
			Policies:  []PolicyFact{{Name: "acl-revision", Value: &revision, Evidence: policy}},
		},
		RequestedCoverage: []CoverageTarget{rulesCatalogTarget},
	}
}

// rulesPartial holds an affected, a potentially affected and an unknown finding, and a
// partial catalog row that says so.
func rulesPartial() Report {
	r := rulesBase()
	r.Findings = []Finding{
		rulesFinding("asset-a", "rule-a", ApplicabilityAffected),
		rulesFinding("asset-a", "rule-b", ApplicabilityPotential),
		rulesFinding("asset-a", "rule-c", ApplicabilityUnknown),
	}
	r.TotalFindings = 3
	r.Coverage = []Coverage{{Target: rulesCatalogTarget, Context: rulesCtx, Source: "advisory catalog", Status: ReportPartial,
		Explanation: "one unknown and one potentially affected finding", Counts: &CoverageCounts{Rules: 3, Assets: 1, Findings: 3, Unknown: 1, Potential: 1}}}
	return r
}

// rulesComplete holds an affected and a not-affected finding and a complete catalog row.
func rulesComplete() Report {
	r := rulesBase()
	r.Status = ReportComplete
	r.Findings = []Finding{
		rulesFinding("asset-a", "rule-a", ApplicabilityAffected),
		rulesFinding("asset-a", "rule-b", ApplicabilityNotAffected),
	}
	r.TotalFindings = 2
	r.Coverage = []Coverage{{Target: rulesCatalogTarget, Context: rulesCtx, Source: "advisory catalog", Status: ReportComplete,
		Counts: &CoverageCounts{Rules: 2, Assets: 1, Findings: 2}}}
	return r
}

func legacyFindingID(context, asset, rule string) string {
	identity := fmt.Sprintf("%d:%s%d:%s%d:%s", len(context), context, len(asset), asset, len(rule), rule)
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:])
}

func factEvidence(r *Report, kind string) *EvidenceRef {
	switch kind {
	case "version":
		return &r.Snapshot.Versions[0].Evidence
	case "platform":
		return &r.Snapshot.Platforms[0].Evidence
	case "feature":
		return &r.Snapshot.Features[0].Evidence
	case "policy":
		return &r.Snapshot.Policies[0].Evidence
	}
	panic("unknown fact kind " + kind)
}

// backCitations adds to the snapshot a version fact for every piece of evidence a finding
// cites that no fact holds yet, so that a variant that changes what the findings cite stays a
// variant of one thing: R1 refuses evidence the snapshot lacks, and each such case says so
// on its own.
func backCitations(r *Report) {
	held := snapshotEvidence(r.Snapshot)
	for _, f := range r.Findings {
		for _, e := range f.Evidence {
			if !held.holds(e) {
				r.Snapshot.Versions = append(r.Snapshot.Versions, VersionFact{Role: VersionRunningDaemon, Channel: ChannelStable, Name: "client", Evidence: e})
				held = snapshotEvidence(r.Snapshot)
			}
		}
	}
}

type reportRule struct {
	rule     string // the rule under test; cases of one rule share a message
	name     string
	complete bool // start from the complete fixture, not the partial one
	want     string
	mutate   func(r *Report)
}

func reportRules() []reportRule {
	var rules []reportRule
	add := func(rule, name string, complete bool, want string, mutate func(r *Report)) {
		rules = append(rules, reportRule{rule, name, complete, want, mutate})
	}
	finding := func(i int, f func(*Finding)) func(*Report) { return func(r *Report) { f(&r.Findings[i]) } }
	row := func(f func(*Coverage)) func(*Report) { return func(r *Report) { f(&r.Coverage[0]) } }
	counts := func(f func(*CoverageCounts)) func(*Report) { return func(r *Report) { f(r.Coverage[0].Counts) } }

	// Header, limits and status.
	add("schema version", "schema version", false, "unsupported report schema version", func(r *Report) { r.SchemaVersion = 2 })
	add("schema version", "schema version zero", false, "unsupported report schema version", func(r *Report) { r.SchemaVersion = 0 })
	add("report context", "empty context", false, "report context is empty", func(r *Report) { r.Context = "" })
	add("generation time", "no generation time", false, "report generation time is missing", func(r *Report) { r.GeneratedAt = time.Time{} })
	add("snapshot context", "snapshot context", false, "snapshot context does not match the report context", func(r *Report) { r.Snapshot.Context = "other" })
	add("snapshot time", "no snapshot time", false, "snapshot observation time is missing", func(r *Report) { r.Snapshot.ObservedAt = time.Time{} })
	add("snapshot time order", "snapshot after generation", false, "snapshot observed after the report was generated", func(r *Report) { r.Snapshot.ObservedAt = r.GeneratedAt.Add(time.Second) })
	add("report status", "status", false, "invalid report status", func(r *Report) { r.Status = "safe" })
	add("report status", "empty status", false, "invalid report status", func(r *Report) { r.Status = "" })
	add("key epoch", "key epoch", false, "key epoch mismatch", func(r *Report) { r.KeyEpoch = "epoch-a" })
	add("key epoch", "snapshot key epoch", false, "key epoch mismatch", func(r *Report) { r.Snapshot.KeyEpoch = "epoch-a" })
	add("snapshot scope", "snapshot scope", false, "invalid snapshot scope", func(r *Report) { r.Snapshot.Scope = "all" })

	add("untruncated total", "untruncated total above the findings", false, "finding total differs from the findings of an untruncated report", func(r *Report) { r.TotalFindings = 4 })
	add("untruncated total", "untruncated total below the findings", false, "finding total differs from the findings of an untruncated report", func(r *Report) { r.TotalFindings = 2 })
	add("truncated total", "truncated with nothing omitted", false, "truncated report has no omitted finding", func(r *Report) { r.Truncated = true })
	add("truncated total", "truncated with a smaller total", false, "truncated report has no omitted finding", func(r *Report) { r.Truncated, r.TotalFindings = true, 2 })
	add("truncated is partial", "truncated report that is complete", true, "truncated report must be partial", func(r *Report) { r.Truncated, r.TotalFindings = true, 3 })

	// The limits. Each case is consistent in every other respect (the total equals the
	// findings, or exceeds them when truncated), so only its own limit can fire.
	add("findings limit", "too many findings", false, "too many findings", func(r *Report) {
		r.Findings, r.TotalFindings = make([]Finding, MaxFindings+1), MaxFindings+1
	})
	add("total limit", "total above the limit", false, "finding total exceeds the limit", func(r *Report) { r.Truncated, r.TotalFindings = true, MaxFindings+1 })
	add("coverage rows limit", "too many coverage rows", false, "too many coverage rows", func(r *Report) { r.Coverage = make([]Coverage, MaxObservations+1) })
	add("version facts limit", "too many version facts", false, "too many version facts", func(r *Report) { r.Snapshot.Versions = make([]VersionFact, MaxObservations+1) })
	add("platform facts limit", "too many platform facts", false, "too many platform facts", func(r *Report) { r.Snapshot.Platforms = make([]PlatformFact, MaxObservations+1) })
	add("feature facts limit", "too many feature facts", false, "too many feature facts", func(r *Report) { r.Snapshot.Features = make([]FeatureFact, MaxObservations+1) })
	add("policy facts limit", "too many policy facts", false, "too many policy facts", func(r *Report) { r.Snapshot.Policies = make([]PolicyFact, MaxObservations+1) })

	// Text and times. These are the shared checks. The context cases change the snapshot's
	// context too, so the header agrees and the text check is the one that fires (the old
	// test changed only the report's, and the header check fired instead).
	long := strings.Repeat("x", MaxTextBytes+1)
	add("text size and encoding", "oversized context", false, "invalid or oversized text", func(r *Report) { r.Context, r.Snapshot.Context = long, long })
	add("text size and encoding", "invalid UTF-8 context", false, "invalid or oversized text", func(r *Report) {
		r.Context, r.Snapshot.Context = string([]byte{0xff}), string([]byte{0xff})
	})
	add("text size and encoding", "invalid UTF-8 in coverage", false, "invalid or oversized text", row(func(c *Coverage) { c.Explanation = string([]byte{0xff}) }))
	add("text size and encoding", "oversized finding explanation", false, "invalid or oversized text", finding(0, func(f *Finding) { f.Explanation = long }))
	add("control character", "control character", false, "text contains a control character", finding(0, func(f *Finding) { f.Explanation = "a\x1b[31mb" }))
	add("collection size", "oversized collection", false, "oversized collection", finding(0, func(f *Finding) { f.Requirements = make([]string, MaxObservations+1) }))
	add("time year", "generation in year 10000", false, "invalid timestamp", func(r *Report) {
		r.GeneratedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		r.Snapshot.ObservedAt = r.GeneratedAt
	})
	add("time offset", "generation with an offset", false, "UTC offset", func(r *Report) { r.GeneratedAt = r.GeneratedAt.In(time.FixedZone("offset", 3600)) })
	add("time floor", "generation before the floor", false, "before 2019-01-01T00:00:00Z", func(r *Report) {
		r.GeneratedAt = time.Date(2018, 12, 31, 23, 59, 59, 0, time.UTC)
		r.Snapshot.ObservedAt = r.GeneratedAt
	})
	unencodable := time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC)
	add("time year", "snapshot time unencodable", false, "invalid timestamp", func(r *Report) { r.Snapshot.ObservedAt = unencodable })
	add("time year", "fact acquisition unencodable", false, "invalid timestamp", func(r *Report) { r.Snapshot.Versions[0].Evidence.AcquiredAt = unencodable })
	add("time year", "fact observation unencodable", false, "invalid timestamp", func(r *Report) { r.Snapshot.Versions[0].Evidence.ObservedAt = &unencodable })
	add("time year", "finding acquisition unencodable", false, "invalid timestamp", finding(0, func(f *Finding) { f.Evidence[0].AcquiredAt = unencodable }))
	add("time year", "finding observation unencodable", false, "invalid timestamp", finding(0, func(f *Finding) { f.Evidence[0].ObservedAt = &unencodable }))

	// Facts: names, roles, channels, and the evidence rules C5.1 and C5.2 for every kind.
	add("version name", "version without a name", false, "version fact has no name", func(r *Report) { r.Snapshot.Versions[0].Name = "" })
	add("version role", "version role missing", false, "invalid version role", func(r *Report) { r.Snapshot.Versions[0].Role = "" })
	add("version role", "version role unknown", false, "invalid version role", func(r *Report) { r.Snapshot.Versions[0].Role = "invalid" })
	add("version channel", "version channel missing", false, "invalid version channel", func(r *Report) { r.Snapshot.Versions[0].Channel = "" })
	add("version channel", "version channel unknown", false, "invalid version channel", func(r *Report) { r.Snapshot.Versions[0].Channel = "invalid" })
	add("feature name", "feature without a name", false, "feature fact has no name", func(r *Report) { r.Snapshot.Features[0].Name = "" })
	add("policy name", "policy without a name", false, "policy fact has no name", func(r *Report) { r.Snapshot.Policies[0].Name = "" })
	for _, kind := range []string{"version", "platform", "feature", "policy"} {
		ev := func(change func(e *EvidenceRef)) func(*Report) {
			return func(r *Report) { change(factEvidence(r, kind)) }
		}
		add("C5.1 evidence context", kind, false, "evidence context does not match the report", ev(func(e *EvidenceRef) { e.Context = "other" }))
		add("C5.1 evidence scope: "+kind, "other scope", false, kind+" evidence scope differs from the snapshot scope", ev(func(e *EvidenceRef) { e.Scope = ScopeFleet }))
		add("C5.1 evidence scope: "+kind, "no scope", false, kind+" evidence scope differs from the snapshot scope", ev(func(e *EvidenceRef) { e.Scope = "" }))
		add("evidence scope vocabulary", kind+" scope outside the vocabulary", false, "invalid evidence scope", ev(func(e *EvidenceRef) { e.Scope = "global" }))
		add("evidence acquisition time", kind+" acquired after generation", false, "evidence acquisition time is missing or after the report was generated", ev(func(e *EvidenceRef) { e.AcquiredAt = rulesNow.Add(time.Second) }))
		add("evidence observation time", kind+" observed after acquisition", false, "evidence observation time is missing or after its acquisition", ev(func(e *EvidenceRef) {
			t := e.AcquiredAt.Add(time.Second)
			e.ObservedAt = &t
		}))
		add("evidence origin", kind+" origin", false, "invalid evidence origin", ev(func(e *EvidenceRef) { e.Origin = "untrusted" }))
		add("evidence freshness", kind+" freshness", false, "invalid evidence freshness", ev(func(e *EvidenceRef) { e.Freshness = "safe" }))
		if kind != "policy" {
			add("C5.2 evidence device: "+kind, "no device", false, kind+" evidence names no device", ev(func(e *EvidenceRef) { e.Asset = "" }))
		}
	}

	// Findings: shape.
	add("finding context", "context", false, "finding context does not match the report", finding(0, func(f *Finding) { f.Context = "other" }))
	add("finding rule id", "no rule id", false, "finding has no rule id", finding(0, func(f *Finding) { f.RuleID = "" }))
	add("C5.6 rule revision", "empty revision", false, "finding has no rule revision", finding(0, func(f *Finding) { f.RuleRevision = "" }))
	add("finding evidence state", "evidence state", false, "invalid finding evidence state", finding(0, func(f *Finding) { f.EvidenceState = "guaranteed-safe" }))
	add("finding confidence", "confidence", false, "invalid finding confidence", finding(0, func(f *Finding) { f.Confidence = "100%" }))
	add("finding applicability", "applicability", false, "invalid finding applicability", finding(0, func(f *Finding) { f.Applicability = "safe" }))
	add("finding source severity", "source severity", false, "invalid finding source severity", finding(0, func(f *Finding) { f.SourceSeverity = "urgent" }))
	add("finding priority", "priority", false, "invalid finding priority", finding(0, func(f *Finding) { f.Priority = "critical" }))
	add("C5.1 evidence context", "finding evidence context", false, "evidence context does not match the report", finding(0, func(f *Finding) { f.Evidence[0].Context = "other" }))
	add("evidence acquisition time", "finding evidence acquired after generation", false, "evidence acquisition time is missing or after the report was generated",
		finding(0, func(f *Finding) { f.Evidence[0].AcquiredAt = rulesNow.Add(time.Second) }))
	add("evidence origin", "finding evidence origin", false, "invalid evidence origin", finding(0, func(f *Finding) { f.Evidence[0].Origin = "untrusted" }))

	// C5.3: affected and not_affected.
	for _, tc := range []struct {
		name     string
		complete bool
		index    int
	}{{"affected", false, 0}, {"not affected", true, 1}} {
		i := tc.index
		add("C5.3 evidence state", tc.name+" with unknown state", tc.complete, "affected or not affected finding without observed evidence", finding(i, func(f *Finding) { f.EvidenceState = EvidenceUnknown }))
		add("C5.3 evidence state", tc.name+" with stale state", tc.complete, "affected or not affected finding without observed evidence", finding(i, func(f *Finding) { f.EvidenceState = EvidenceStale }))
		add("C5.3 evidence state", tc.name+" with absent state", tc.complete, "affected or not affected finding without observed evidence", finding(i, func(f *Finding) { f.EvidenceState = EvidenceAbsent }))
		add("C5.3 evidence", tc.name+" with no evidence", tc.complete, "affected or not affected finding without evidence", finding(i, func(f *Finding) { f.Evidence = nil }))
		add("C5.3 evidence", tc.name+" with empty evidence", tc.complete, "affected or not affected finding without evidence", finding(i, func(f *Finding) { f.Evidence = []EvidenceRef{} }))
		add("C5.3 evidence device", tc.name+" citing another device", tc.complete, "affected or not affected finding cites evidence for another context or device", finding(i, func(f *Finding) { f.Evidence[0].Asset = "asset-b" }))
		add("C5.3 evidence device", tc.name+" citing no device", tc.complete, "affected or not affected finding cites evidence for another context or device", finding(i, func(f *Finding) { f.Evidence[0].Asset = "" }))
		add("C5.3 evidence device", tc.name+" with a second piece for another device", tc.complete, "affected or not affected finding cites evidence for another context or device", finding(i, func(f *Finding) {
			other := f.Evidence[0]
			other.Asset = "asset-b"
			f.Evidence = append(f.Evidence, other)
		}))
		add("C5.3 reason", tc.name+" with a reason", tc.complete, "affected or not affected finding carries a reason", finding(i, func(f *Finding) { f.Reason = ReasonNoVersion }))
	}

	// C5.4: unknown and potentially_affected.
	add("C5.4 reason", "potential without a reason", false, "unknown or potentially affected finding without a known reason", finding(1, func(f *Finding) { f.Reason = "" }))
	add("C5.4 reason", "potential with an unknown word", false, "unknown or potentially affected finding without a known reason", finding(1, func(f *Finding) { f.Reason = "stale" }))
	add("C5.4 reason", "potential with a wrong case", false, "unknown or potentially affected finding without a known reason", finding(1, func(f *Finding) { f.Reason = "OS_Unknown" }))
	add("C5.4 reason", "unknown without a reason", false, "unknown or potentially affected finding without a known reason", finding(2, func(f *Finding) { f.Reason = "" }))
	add("C5.4 reason", "unknown with an unknown word", false, "unknown or potentially affected finding without a known reason", finding(2, func(f *Finding) { f.Reason = "unknown" }))
	add("C5.4 evidence state", "unknown with observed state", false, "unknown finding must have evidence state unknown, stale or absent", finding(2, func(f *Finding) { f.EvidenceState = EvidenceObserved }))

	// C5.5: identity. The duplicate-tuple check runs before the duplicate-ID check, which
	// runs before the recomputation, so each of the three has a case that only it can fail.
	add("C5.5 id", "empty id", false, "finding id does not match its context, scope, asset and rule", finding(0, func(f *Finding) { f.ID = "" }))
	add("C5.5 id", "arbitrary id", false, "finding id does not match its context, scope, asset and rule", finding(0, func(f *Finding) { f.ID = "finding-a" }))
	add("C5.5 id", "id of another asset", false, "finding id does not match its context, scope, asset and rule", finding(0, func(f *Finding) { f.ID = FindingID(rulesCtx, ScopeLocal, "asset-b", f.RuleID) }))
	add("C5.5 id", "id of another rule", false, "finding id does not match its context, scope, asset and rule", finding(0, func(f *Finding) { f.ID = FindingID(rulesCtx, ScopeLocal, f.Asset, "rule-z") }))
	add("C5.5 id", "id of another context", false, "finding id does not match its context, scope, asset and rule", finding(0, func(f *Finding) { f.ID = FindingID("other", ScopeLocal, f.Asset, f.RuleID) }))
	add("C5.5 id", "id of the other scope", false, "finding id does not match its context, scope, asset and rule", finding(0, func(f *Finding) { f.ID = FindingID(rulesCtx, ScopeFleet, f.Asset, f.RuleID) }))
	add("C5.5 id", "id without a scope", false, "finding id does not match its context, scope, asset and rule", finding(0, func(f *Finding) { f.ID = FindingID(rulesCtx, "", f.Asset, f.RuleID) }))
	add("C5.5 id", "id from the earlier derivation, which had no scope", false, "finding id does not match its context, scope, asset and rule", finding(0, func(f *Finding) { f.ID = legacyFindingID(rulesCtx, f.Asset, f.RuleID) }))
	add("C5.5 id", "changed rule keeps its old id", false, "finding id does not match its context, scope, asset and rule", finding(0, func(f *Finding) { f.RuleID = "rule-z" }))
	add("C5.5 duplicate tuple", "the same finding twice", false, "duplicate finding for the same context, scope, asset and rule", func(r *Report) {
		r.Findings = append(r.Findings, r.Findings[0])
		r.TotalFindings++
	})
	add("C5.5 duplicate tuple", "the same tuple with another id", false, "duplicate finding for the same context, scope, asset and rule", func(r *Report) {
		again := r.Findings[0]
		again.ID = "finding-a"
		r.Findings = append(r.Findings, again)
		r.TotalFindings++
	})
	add("C5.5 duplicate tuple", "the same tuple with another revision", false, "duplicate finding for the same context, scope, asset and rule", func(r *Report) {
		again := r.Findings[0]
		again.RuleRevision = "2"
		r.Findings = append(r.Findings, again)
		r.TotalFindings++
	})
	add("C5.5 duplicate id", "another tuple with the same id", false, "duplicate finding identity", func(r *Report) {
		again := r.Findings[0]
		again.RuleID = "rule-z"
		r.Findings = append(r.Findings, again)
		r.TotalFindings++
	})

	// C5.6: corroboration.
	add("C5.6 corroborated", "one piece of evidence", false, "corroborated finding needs evidence from two origins", finding(0, func(f *Finding) { f.Confidence = ConfidenceCorroborated }))
	add("C5.6 corroborated", "two pieces from one origin", false, "corroborated finding needs evidence from two origins", finding(0, func(f *Finding) {
		f.Confidence = ConfidenceCorroborated
		f.Evidence = append(f.Evidence, f.Evidence[0])
	}))
	add("C5.6 corroborated", "no evidence", false, "corroborated finding needs evidence from two origins", finding(2, func(f *Finding) { f.Confidence = ConfidenceCorroborated }))

	// R1: what a finding cites is, by value, evidence of a fact in the snapshot, and an
	// affected or not-affected finding cites only fresh evidence without an error. Each case
	// below holds the cited evidence equal to the evidence of Versions[0], so that only the
	// rule under test can refuse it.
	const (
		noFact   = "finding cites evidence that no fact of the snapshot holds"
		hasError = "affected or not affected finding cites evidence that carries an error"
		notFresh = "affected or not affected finding cites evidence that is not fresh"
	)
	earlier := rulesNow.Add(-time.Minute)
	for _, tc := range []struct {
		name     string
		complete bool
		index    int
	}{{"affected", false, 0}, {"not affected", true, 1}, {"potentially affected", false, 1}} {
		i := tc.index
		add("R1 snapshot evidence", tc.name+" cites evidence acquired at another time", tc.complete, noFact, finding(i, func(f *Finding) { f.Evidence[0].AcquiredAt = rulesNow.Add(-time.Second) }))
		add("R1 snapshot evidence", tc.name+" cites evidence with an observation time where the fact has none", tc.complete, noFact, finding(i, func(f *Finding) { f.Evidence[0].ObservedAt = &earlier }))
		add("R1 snapshot evidence", tc.name+" cites evidence of another origin", tc.complete, noFact, finding(i, func(f *Finding) { f.Evidence[0].Origin = OriginCollector }))
		add("R1 snapshot evidence", tc.name+" cites evidence with another freshness", tc.complete, noFact, finding(i, func(f *Finding) { f.Evidence[0].Freshness = FreshnessUnknown }))
		add("R1 snapshot evidence", tc.name+" cites evidence with an error no fact has", tc.complete, noFact, finding(i, func(f *Finding) { f.Evidence[0].Error = "read failed" }))
		add("R1 snapshot evidence", tc.name+" cites a second piece no fact holds", tc.complete, noFact, finding(i, func(f *Finding) {
			other := f.Evidence[0]
			other.AcquiredAt = rulesNow.Add(-time.Second)
			f.Evidence = append(f.Evidence, other)
		}))
	}
	add("R1 snapshot evidence", "unknown finding cites evidence no fact holds", false, noFact, finding(2, func(f *Finding) {
		f.Evidence = []EvidenceRef{rulesEvidence("asset-b", OriginLocal)}
	}))
	add("R1 snapshot evidence", "affected finding cites evidence that lacks the observation time of the fact", false, noFact, func(r *Report) {
		r.Snapshot.Versions[0].Evidence.ObservedAt = &earlier
		r.Snapshot.Platforms[0].Evidence.ObservedAt = &earlier
		r.Snapshot.Features[0].Evidence.ObservedAt = &earlier
	})
	for _, tc := range []struct {
		name     string
		complete bool
		index    int
	}{{"affected", false, 0}, {"not affected", true, 1}} {
		i := tc.index
		add("R1 evidence error", tc.name+" cites evidence that carries an error", tc.complete, hasError, func(r *Report) {
			r.Findings[i].Evidence[0].Error = "read failed"
			r.Snapshot.Versions[0].Evidence.Error = "read failed"
		})
		add("R1 evidence freshness", tc.name+" cites stale evidence", tc.complete, notFresh, func(r *Report) {
			r.Findings[i].Evidence[0].Freshness = FreshnessStale
			r.Snapshot.Versions[0].Evidence.Freshness = FreshnessStale
		})
		add("R1 evidence freshness", tc.name+" cites evidence of unknown freshness", tc.complete, notFresh, func(r *Report) {
			r.Findings[i].Evidence[0].Freshness = FreshnessUnknown
			r.Snapshot.Versions[0].Evidence.Freshness = FreshnessUnknown
		})
		add("R1 evidence freshness", tc.name+" cites one fresh and one stale piece", tc.complete, notFresh, func(r *Report) {
			stale := r.Findings[i].Evidence[0]
			stale.Origin, stale.Freshness = OriginCollector, FreshnessStale
			r.Findings[i].Evidence = append(r.Findings[i].Evidence, stale)
			r.Snapshot.Versions = append(r.Snapshot.Versions, VersionFact{Role: VersionRunningDaemon, Channel: ChannelStable, Name: "client", Evidence: stale})
		})
	}

	// Coverage requests and rows.
	add("complete report requires a request", "complete report without a request", true, "complete report requires requested coverage", func(r *Report) { r.RequestedCoverage = nil })
	add("invalid requested coverage", "dimension outside the vocabulary", false, "invalid requested coverage", func(r *Report) {
		r.RequestedCoverage = []CoverageTarget{{Dimension: "bogus", Scope: ScopeLocal}}
	})
	add("invalid requested coverage", "scope outside the vocabulary", false, "invalid requested coverage", func(r *Report) {
		r.RequestedCoverage = []CoverageTarget{{Dimension: CoverageCatalog, Scope: "all"}}
	})
	add("missing requested coverage", "a requested target has no row", true, "missing requested coverage", func(r *Report) {
		r.RequestedCoverage = append(r.RequestedCoverage, CoverageTarget{Dimension: CoveragePolicy, Scope: ScopeFleet})
	})
	add("missing requested coverage", "a local row does not answer a fleet request", true, "missing requested coverage", func(r *Report) {
		r.RequestedCoverage = []CoverageTarget{{Dimension: CoverageCatalog, Scope: ScopeFleet}}
	})
	add("missing requested coverage", "a partial row does not answer a complete request", true, "missing requested coverage", row(func(c *Coverage) {
		c.Status, c.Explanation = ReportPartial, "partial"
	}))
	// The requested target is answered by a complete row, and a second row is partial: the
	// check that a complete report holds no partial row is the only one that can fire.
	add("complete report has a partial row", "complete report with a partial row", true, "complete report has partial coverage", func(r *Report) {
		r.Coverage = append(r.Coverage, Coverage{Target: CoverageTarget{Dimension: CoveragePolicy, Scope: ScopeFleet}, Context: rulesCtx, Source: "api", Status: ReportPartial, Explanation: "policy not read"})
	})
	add("coverage context", "context", false, "coverage context does not match the report", row(func(c *Coverage) { c.Context = "other" }))
	add("coverage target", "dimension", false, "invalid coverage target", row(func(c *Coverage) { c.Target.Dimension = "bogus" }))
	add("coverage target", "scope", false, "invalid coverage target", row(func(c *Coverage) { c.Target.Scope = "all" }))
	add("coverage status", "status", false, "invalid coverage status", row(func(c *Coverage) { c.Status = "safe" }))

	// C5.7: coverage.
	add("C5.7 source", "complete row without a source", true, "complete coverage has no source", row(func(c *Coverage) { c.Source = "" }))
	add("C5.7 complete unknown", "unknown findings counted", true, "complete coverage counts unknown findings", counts(func(c *CoverageCounts) { c.Unknown = 1 }))
	add("C5.7 complete potential", "potential findings counted", true, "complete coverage counts potentially affected findings", counts(func(c *CoverageCounts) { c.Potential = 1 }))
	add("C5.7 complete rules", "no rules", true, "complete coverage counts no rules", counts(func(c *CoverageCounts) { c.Rules = 0 }))
	add("C5.7 complete assets", "no assets", true, "complete coverage counts no assets", counts(func(c *CoverageCounts) { c.Assets = 0 }))
	add("C5.7 complete catalog row", "with an unknown finding", true, "complete catalog coverage with an unknown or potentially affected finding", func(r *Report) {
		r.Findings = append(r.Findings, rulesFinding("asset-a", "rule-c", ApplicabilityUnknown))
		r.TotalFindings, r.Coverage[0].Counts.Findings = 3, 3
	})
	add("C5.7 complete catalog row", "with a potentially affected finding", true, "complete catalog coverage with an unknown or potentially affected finding", func(r *Report) {
		r.Findings = append(r.Findings, rulesFinding("asset-a", "rule-c", ApplicabilityPotential))
		r.TotalFindings, r.Coverage[0].Counts.Findings = 3, 3
	})
	add("C5.7 complete catalog row", "without counts but with an unknown finding", true, "complete catalog coverage with an unknown or potentially affected finding", func(r *Report) {
		r.Findings = append(r.Findings, rulesFinding("asset-a", "rule-c", ApplicabilityUnknown))
		r.TotalFindings, r.Coverage[0].Counts = 3, nil
	})
	add("C5.7 explanation", "partial row without an explanation", false, "partial coverage has no explanation", row(func(c *Coverage) { c.Explanation = "" }))
	add("C5.7 explanation", "partial row with an empty explanation among others", true, "partial coverage has no explanation", func(r *Report) {
		r.Status = ReportPartial
		r.Coverage = append(r.Coverage, Coverage{Target: CoverageTarget{Dimension: CoveragePolicy, Scope: ScopeFleet}, Context: rulesCtx, Source: "api", Status: ReportPartial})
	})
	for name, set := range map[string]func(*CoverageCounts){
		"rules":     func(c *CoverageCounts) { c.Rules = -1 },
		"withdrawn": func(c *CoverageCounts) { c.Withdrawn = -1 },
		"assets":    func(c *CoverageCounts) { c.Assets = -1 },
		"findings":  func(c *CoverageCounts) { c.Findings = -1 },
		"unknown":   func(c *CoverageCounts) { c.Unknown = -1 },
		"potential": func(c *CoverageCounts) { c.Potential = -1 },
	} {
		add("C5.7 counts negative", "negative "+name, false, "coverage counts must not be negative", counts(set))
	}
	add("C5.7 counts sum", "unknown and potential above findings", false, "coverage counts more unknown and potential findings than findings", counts(func(c *CoverageCounts) { c.Unknown, c.Potential = 3, 1 }))
	add("C5.7 counts sum", "unknown alone above findings", false, "coverage counts more unknown and potential findings than findings", counts(func(c *CoverageCounts) { c.Unknown, c.Potential = 4, 0 }))
	// Unknown is not above Findings, and Potential is one more than what is left, but their
	// sum wraps around to a negative number: a check that adds them would let this through.
	add("C5.7 counts sum", "a sum that overflows", false, "coverage counts more unknown and potential findings than findings", counts(func(c *CoverageCounts) {
		c.Findings, c.Unknown, c.Potential = math.MaxInt, math.MaxInt, 1
	}))
	add("C5.7 counts limit", "findings above the limit", false, "coverage counts more findings than the limit allows", counts(func(c *CoverageCounts) { c.Findings = MaxFindings + 1 }))
	add("C5.7 counts limit", "findings above the limit on a non-catalog row", false, "coverage counts more findings than the limit allows", func(r *Report) {
		r.Coverage = append(r.Coverage, Coverage{Target: CoverageTarget{Dimension: CoveragePolicy, Scope: ScopeLocal}, Context: rulesCtx, Source: "api", Status: ReportPartial,
			Explanation: "policy partly read", Counts: &CoverageCounts{Findings: MaxFindings + 1}})
	})
	add("C5.7 findings count", "catalog count above the findings", false, "catalog coverage counts a different number of findings than the report holds", counts(func(c *CoverageCounts) { c.Findings = 5 }))
	add("C5.7 findings count", "catalog count below the findings", false, "catalog coverage counts a different number of findings than the report holds", counts(func(c *CoverageCounts) { c.Findings = 2 }))
	add("C5.7 findings count", "complete catalog count below the findings", true, "catalog coverage counts a different number of findings than the report holds", counts(func(c *CoverageCounts) { c.Findings = 1 }))

	// T3, owner decision on T2's second question: on a report that is not truncated, the
	// unknown and potential counts of the catalog row equal the findings of those kinds. The
	// fixture holds one of each, so a count that is off by one, in either direction, and still
	// a possible count (within the findings) reaches this check and no other.
	add("T3 unknown count", "row counts no unknown finding", false, "catalog coverage counts a different number of unknown findings than the report holds", counts(func(c *CoverageCounts) { c.Unknown = 0 }))
	add("T3 unknown count", "row counts two unknown findings", false, "catalog coverage counts a different number of unknown findings than the report holds", counts(func(c *CoverageCounts) { c.Unknown = 2 }))
	add("T3 potential count", "row counts no potentially affected finding", false, "catalog coverage counts a different number of potentially affected findings than the report holds", counts(func(c *CoverageCounts) { c.Potential = 0 }))
	add("T3 potential count", "row counts two potentially affected findings", false, "catalog coverage counts a different number of potentially affected findings than the report holds", counts(func(c *CoverageCounts) { c.Potential = 2 }))
	add("T3 unknown count", "an unknown finding hidden by a zero count among several rows", false, "catalog coverage counts a different number of unknown findings than the report holds", func(r *Report) {
		r.Coverage[0].Counts.Unknown = 0
		r.Coverage = append(r.Coverage, Coverage{Target: CoverageTarget{Dimension: CoveragePolicy, Scope: ScopeFleet}, Context: rulesCtx, Source: "api", Status: ReportComplete})
	})

	// T3, owner decision on T2's first question: every piece of evidence inside a finding
	// carries the snapshot's scope, as the evidence of the snapshot's facts does. The finding's
	// ID hashes that scope, so evidence of another scope cannot be what it was derived from.
	add("T3 finding evidence scope", "affected finding cites evidence of the other scope", false, "finding evidence scope differs from the snapshot scope", finding(0, func(f *Finding) { f.Evidence[0].Scope = ScopeFleet }))
	add("T3 finding evidence scope", "affected finding cites evidence without a scope", false, "finding evidence scope differs from the snapshot scope", finding(0, func(f *Finding) { f.Evidence[0].Scope = "" }))
	add("T3 finding evidence scope", "potentially affected finding cites evidence of the other scope", false, "finding evidence scope differs from the snapshot scope", finding(1, func(f *Finding) { f.Evidence[0].Scope = ScopeFleet }))
	add("T3 finding evidence scope", "unknown finding cites evidence of the other scope", false, "finding evidence scope differs from the snapshot scope", finding(2, func(f *Finding) {
		e := rulesEvidence("asset-a", OriginLocal)
		e.Scope = ScopeFleet
		f.Evidence = []EvidenceRef{e}
	}))
	add("T3 finding evidence scope", "the second piece is in the other scope", false, "finding evidence scope differs from the snapshot scope", finding(0, func(f *Finding) {
		other := f.Evidence[0]
		other.Scope = ScopeFleet
		f.Evidence = append(f.Evidence, other)
	}))
	return rules
}

func TestReportRuleFixturesAreValid(t *testing.T) {
	for name, r := range map[string]Report{"partial": rulesPartial(), "complete": rulesComplete()} {
		if err := ValidateReport(r); err != nil {
			t.Fatalf("the %s fixture every rule case starts from is not valid: %v", name, err)
		}
		// A report survives JSON, so the reason and the counts do too.
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		var got Report
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if err := ValidateReport(got); err != nil {
			t.Fatalf("the %s fixture is not valid after a JSON round trip: %v", name, err)
		}
	}
}

func TestReportRulesRejectOnlyTheirOwnViolation(t *testing.T) {
	for _, tc := range reportRules() {
		t.Run(tc.rule+"/"+tc.name, func(t *testing.T) {
			r := rulesPartial()
			if tc.complete {
				r = rulesComplete()
			}
			tc.mutate(&r)
			err := ValidateReport(r)
			if err == nil {
				t.Fatalf("accepted a report that breaks %q", tc.rule)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("rule %q: error %q does not say %q", tc.rule, err, tc.want)
			}
		})
	}
}

// Two different rules never share a message, and no message is part of another's, so a
// case cannot pass on the message of another rule.
func TestReportRuleMessagesDiffer(t *testing.T) {
	owner := map[string]string{} // message -> rule
	for _, tc := range reportRules() {
		// A rule label names one check, so a message belongs to one label. The cases of one
		// check (a fact's evidence and a finding's, say) share its label.
		if other, ok := owner[tc.want]; ok && other != tc.rule {
			t.Errorf("rules %q and %q share the message %q", other, tc.rule, tc.want)
		}
		owner[tc.want] = tc.rule
	}
	for a, ruleA := range owner {
		for b, ruleB := range owner {
			if a != b && ruleA != ruleB && strings.Contains(b, a) {
				t.Errorf("the message %q of rule %q is part of the message %q of rule %q", a, ruleA, b, ruleB)
			}
		}
	}
}

// The spec lists these rules (C5 1 to 7); each has a case above.
func TestReportEveryC5RuleHasACase(t *testing.T) {
	have := map[string]bool{}
	for _, tc := range reportRules() {
		have[tc.rule] = true
	}
	for _, rule := range []string{
		"C5.1 evidence context", "C5.1 evidence scope: version", "C5.1 evidence scope: platform", "C5.1 evidence scope: feature", "C5.1 evidence scope: policy",
		"C5.2 evidence device: version", "C5.2 evidence device: platform", "C5.2 evidence device: feature",
		"C5.3 evidence state", "C5.3 evidence", "C5.3 evidence device", "C5.3 reason",
		"C5.4 reason", "C5.4 evidence state",
		"C5.5 id", "C5.5 duplicate tuple", "C5.5 duplicate id", "C5.6 rule revision", "C5.6 corroborated",
		"C5.7 source", "C5.7 complete unknown", "C5.7 complete potential", "C5.7 complete rules", "C5.7 complete assets",
		"C5.7 complete catalog row", "C5.7 explanation", "C5.7 counts negative", "C5.7 counts sum", "C5.7 counts limit", "C5.7 findings count",
		"T3 unknown count", "T3 potential count", "T3 finding evidence scope",
		"R1 snapshot evidence", "R1 evidence error", "R1 evidence freshness",
		"truncated is partial", "complete report has a partial row", "missing requested coverage",
	} {
		if !have[rule] {
			t.Errorf("no isolating case for %q", rule)
		}
	}
}

// Values at the edge of each rule are accepted, so a rule cannot be tightened by one, and
// the shapes the rules must let through are shown to pass.
func TestReportRulesAcceptLegalVariants(t *testing.T) {
	for _, tc := range []struct {
		name     string
		complete bool
		mutate   func(r *Report)
	}{
		{"policy evidence with a device", false, func(r *Report) { r.Snapshot.Policies[0].Evidence.Asset = "asset-a" }},
		{"version fact of unknown channel", false, func(r *Report) { r.Snapshot.Versions[0].Channel = ChannelUnknown }},
		{"version fact of unstable channel", false, func(r *Report) { r.Snapshot.Versions[0].Channel = ChannelUnstable }},
		{"version fact of each role", false, func(r *Report) {
			v := r.Snapshot.Versions[0]
			for _, role := range []VersionRole{VersionAPIReported, VersionLocalCLI} {
				v.Role = role
				r.Snapshot.Versions = append(r.Snapshot.Versions, v)
			}
		}},
		{"version fact without a value", false, func(r *Report) { r.Snapshot.Versions[0].Value = nil }},
		{"platform fact without an os", false, func(r *Report) { r.Snapshot.Platforms[0].OS = "" }},
		{"platform fact with a variant", false, func(r *Report) { r.Snapshot.Platforms[0].Variant = "standalone" }},
		{"feature fact without a value", false, func(r *Report) { r.Snapshot.Features[0].Value = nil }},
		{"unknown with unknown state", false, func(r *Report) { r.Findings[2].EvidenceState = EvidenceUnknown }},
		{"unknown with absent state", false, func(r *Report) { r.Findings[2].EvidenceState = EvidenceAbsent }},
		{"unknown that cites evidence", false, func(r *Report) {
			r.Findings[2].Evidence = []EvidenceRef{rulesEvidence("asset-a", OriginLocal)}
		}},
		{"potential with stale state", false, func(r *Report) { r.Findings[1].EvidenceState = EvidenceStale }},
		{"a revised rule keeps its identity", false, func(r *Report) { r.Findings[0].RuleRevision = "2" }},
		{"corroborated by two origins", false, func(r *Report) {
			f := &r.Findings[0]
			f.Confidence = ConfidenceCorroborated
			f.Evidence = append(f.Evidence, rulesEvidence("asset-a", OriginCollector))
			backCitations(r)
		}},
		{"corroborated by three pieces from two origins", false, func(r *Report) {
			f := &r.Findings[0]
			f.Confidence = ConfidenceCorroborated
			f.Evidence = append(f.Evidence, rulesEvidence("asset-a", OriginLocal), rulesEvidence("asset-a", OriginCollector))
			backCitations(r)
		}},
		{"derived confidence with one piece", false, func(r *Report) { r.Findings[0].Confidence = ConfidenceDerived }},
		{"unknown confidence with no evidence", false, func(r *Report) { r.Findings[2].Confidence = ConfidenceUnknown }},
		{"two assets", false, func(r *Report) {
			r.Findings = append(r.Findings, rulesFinding("asset-b", "rule-a", ApplicabilityNotAffected))
			r.TotalFindings, r.Coverage[0].Counts.Findings = 4, 4
			backCitations(r)
		}},
		// R1: the claims of affected and not-affected findings need fresh evidence without an
		// error, and nothing else does; every finding cites evidence the snapshot holds, by value.
		{"potential finding citing stale evidence that carries an error", false, func(r *Report) {
			r.Findings[1].Evidence[0].Freshness, r.Findings[1].Evidence[0].Error = FreshnessStale, "read failed"
			backCitations(r)
		}},
		{"unknown finding citing evidence of unknown freshness", false, func(r *Report) {
			e := rulesEvidence("asset-a", OriginAPI)
			e.Freshness, e.Error = FreshnessUnknown, "read failed"
			r.Findings[2].Evidence = []EvidenceRef{e}
			backCitations(r)
		}},
		{"evidence behind other pointers and another location", false, func(r *Report) {
			held, cited := rulesNow.Add(-time.Minute), rulesNow.Add(-time.Minute)
			r.Snapshot.Versions[0].Evidence.ObservedAt = &held
			f := &r.Findings[0]
			f.Evidence[0] = r.Snapshot.Versions[0].Evidence
			f.Evidence[0].ObservedAt = &cited
			f.Evidence[0].AcquiredAt = rulesNow.In(time.FixedZone("zero", 0))
		}},
		{"complete catalog row without counts", true, func(r *Report) { r.Coverage[0].Counts = nil }},
		{"complete non-catalog row beside unknown findings", false, func(r *Report) {
			r.RequestedCoverage = append(r.RequestedCoverage, CoverageTarget{Dimension: CoveragePolicy, Scope: ScopeFleet})
			r.Coverage = append(r.Coverage, Coverage{Target: CoverageTarget{Dimension: CoveragePolicy, Scope: ScopeFleet}, Context: rulesCtx, Source: "api", Status: ReportComplete})
		}},
		{"a complete non-catalog row may count other findings", false, func(r *Report) {
			r.Coverage = append(r.Coverage, Coverage{Target: CoverageTarget{Dimension: CoveragePolicy, Scope: ScopeFleet}, Context: rulesCtx, Source: "api", Status: ReportComplete, Counts: &CoverageCounts{Rules: 1, Assets: 1, Findings: 9}})
		}},
		{"a non-catalog row counts other findings", false, func(r *Report) {
			r.Coverage = append(r.Coverage, Coverage{Target: CoverageTarget{Dimension: CoveragePolicy, Scope: ScopeFleet}, Context: rulesCtx, Source: "api", Status: ReportPartial, Explanation: "policy partly read", Counts: &CoverageCounts{Findings: 9, Unknown: 9}})
		}},
		{"zero counts on a partial row of a report with no findings", false, func(r *Report) {
			r.Findings, r.TotalFindings = nil, 0
			r.Coverage[0].Counts = &CoverageCounts{}
		}},
		{"counts at the limit of a truncated report", false, func(r *Report) {
			r.Truncated, r.TotalFindings = true, MaxFindings
			r.Coverage[0].Counts = &CoverageCounts{Rules: 3, Assets: 1, Findings: MaxFindings, Unknown: 1, Potential: 1}
		}},
		{"a truncated report may count more findings than it holds", false, func(r *Report) {
			r.Truncated, r.TotalFindings = true, 9
			r.Coverage[0].Counts.Findings = 9
		}},
		{"a complete catalog row of zero findings", true, func(r *Report) {
			r.Findings, r.TotalFindings = nil, 0
			r.Coverage[0].Counts = &CoverageCounts{Rules: 1, Assets: 1}
		}},
		{"a truncated report may count other unknown and potential findings than it holds", false, func(r *Report) {
			r.Truncated, r.TotalFindings = true, 9
			r.Coverage[0].Counts = &CoverageCounts{Rules: 3, Assets: 1, Findings: 9, Unknown: 4, Potential: 3}
		}},
		{"a row that is not of the catalog dimension may count other unknown and potential findings", false, func(r *Report) {
			r.Coverage = append(r.Coverage, Coverage{Target: CoverageTarget{Dimension: CoveragePolicy, Scope: ScopeFleet}, Context: rulesCtx, Source: "api", Status: ReportPartial, Explanation: "policy partly read", Counts: &CoverageCounts{Findings: 3, Unknown: 2, Potential: 1}})
		}},
		{"a catalog row without counts beside unknown findings", false, func(r *Report) { r.Coverage[0].Counts = nil }},
		{"a finding with no evidence is not asked for a scope", false, func(r *Report) { r.Findings[2].Evidence = nil }},
		{"evidence of the snapshot's scope in a fleet snapshot", false, func(r *Report) {
			r.Snapshot.Scope = ScopeFleet
			for _, e := range []*EvidenceRef{&r.Snapshot.Versions[0].Evidence, &r.Snapshot.Platforms[0].Evidence, &r.Snapshot.Features[0].Evidence, &r.Snapshot.Policies[0].Evidence} {
				e.Scope = ScopeFleet
			}
			r.RequestedCoverage = []CoverageTarget{{Dimension: CoverageCatalog, Scope: ScopeFleet}}
			r.Coverage[0].Target = r.RequestedCoverage[0]
			for i := range r.Findings {
				r.Findings[i].ID = FindingID(rulesCtx, ScopeFleet, r.Findings[i].Asset, r.Findings[i].RuleID)
				for j := range r.Findings[i].Evidence {
					r.Findings[i].Evidence[j].Scope = ScopeFleet
				}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := rulesPartial()
			if tc.complete {
				r = rulesComplete()
			}
			tc.mutate(&r)
			if err := ValidateReport(r); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}

// Every reason is accepted on an unknown and on a potentially affected finding, and no
// reason is accepted on an affected or not-affected one.
func TestReportReasonsAreAcceptedOnlyWhereTheyBelong(t *testing.T) {
	for _, reason := range unknownReasons {
		for _, i := range []int{1, 2} {
			r := rulesPartial()
			r.Findings[i].Reason = reason
			if err := ValidateReport(r); err != nil {
				t.Errorf("reason %q on finding %d: %v", reason, i, err)
			}
		}
		r := rulesComplete()
		r.Findings[1].Reason = reason
		if err := ValidateReport(r); err == nil || !strings.Contains(err.Error(), "carries a reason") {
			t.Errorf("reason %q on a not-affected finding: %v", reason, err)
		}
	}
}

// A report with no scope keeps the evidence of its facts scopeless: the rule is equality
// with the snapshot, whatever the snapshot holds.
func TestReportEvidenceScopeEqualsTheSnapshotsWhenBothAreEmpty(t *testing.T) {
	r := rulesBase()
	r.Snapshot.Scope = ""
	for _, e := range []*EvidenceRef{&r.Snapshot.Versions[0].Evidence, &r.Snapshot.Platforms[0].Evidence, &r.Snapshot.Features[0].Evidence, &r.Snapshot.Policies[0].Evidence} {
		e.Scope = ""
	}
	if err := ValidateReport(r); err != nil {
		t.Fatalf("a scopeless snapshot with scopeless evidence: %v", err)
	}
	r.Snapshot.Versions[0].Evidence.Scope = ScopeLocal
	if err := ValidateReport(r); err == nil || !strings.Contains(err.Error(), "version evidence scope differs from the snapshot scope") {
		t.Fatalf("scoped evidence in a scopeless snapshot: %v", err)
	}
}

// The identity uses the snapshot's scope, so the same device and rule under two scopes are
// two findings with two identities, each valid in its own report and not in the other's.
func TestReportIdentityBindsTheSnapshotScope(t *testing.T) {
	local := rulesPartial()
	fleet := rulesPartial()
	fleet.Snapshot.Scope = ScopeFleet
	fleet.RequestedCoverage = []CoverageTarget{{Dimension: CoverageCatalog, Scope: ScopeFleet}}
	fleet.Coverage[0].Target = fleet.RequestedCoverage[0]
	for _, e := range []*EvidenceRef{&fleet.Snapshot.Versions[0].Evidence, &fleet.Snapshot.Platforms[0].Evidence, &fleet.Snapshot.Features[0].Evidence, &fleet.Snapshot.Policies[0].Evidence} {
		e.Scope = ScopeFleet
	}
	for i := range fleet.Findings {
		for j := range fleet.Findings[i].Evidence {
			fleet.Findings[i].Evidence[j].Scope = ScopeFleet
		}
	}
	if err := ValidateReport(fleet); err == nil || !strings.Contains(err.Error(), "finding id does not match") {
		t.Fatalf("local identities in a fleet report: %v", err)
	}
	for i := range fleet.Findings {
		f := &fleet.Findings[i]
		f.ID = FindingID(f.Context, ScopeFleet, f.Asset, f.RuleID)
		if f.ID == local.Findings[i].ID {
			t.Fatalf("finding %d has the same identity under both scopes", i)
		}
	}
	if err := ValidateReport(fleet); err != nil {
		t.Fatalf("a fleet report with fleet identities: %v", err)
	}
}

// One thousand findings with their identities, in one report, validate.
func TestReportAcceptsManyFindings(t *testing.T) {
	r := rulesBase()
	r.Coverage = []Coverage{{Target: rulesCatalogTarget, Context: rulesCtx, Source: "advisory catalog", Status: ReportPartial, Explanation: "synthetic"}}
	for i := 0; i < 1000; i++ {
		r.Findings = append(r.Findings, rulesFinding(fmt.Sprintf("asset-%d", i%50), fmt.Sprintf("rule-%d", i), ApplicabilityNotAffected))
	}
	r.TotalFindings = len(r.Findings)
	backCitations(&r)
	if err := ValidateReport(r); err != nil {
		t.Fatal(err)
	}
}

// The claims of a finding survive JSON: the reason, the evidence state and the counts of a
// coverage row read back as they were written, and the report still validates.
func TestReportFindingSemanticsSurviveJSON(t *testing.T) {
	r := rulesPartial()
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
	if got.Findings[0].Applicability != ApplicabilityAffected || got.Findings[0].Reason != "" ||
		got.Findings[1].Applicability != ApplicabilityPotential || got.Findings[1].Reason != ReasonOSUnknown ||
		got.Findings[2].Applicability != ApplicabilityUnknown || got.Findings[2].Reason != ReasonStaleEvidence || got.Findings[2].EvidenceState != EvidenceStale {
		t.Fatalf("finding semantics lost: %+v", got.Findings)
	}
	if got.Coverage[0].Counts == nil || *got.Coverage[0].Counts != *r.Coverage[0].Counts {
		t.Fatalf("counts lost: %+v", got.Coverage[0].Counts)
	}
	// An unknown reason spelling is carried through JSON and refused by validation, not by decoding.
	got.Findings[1].Reason = "made_up"
	b, err = json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var again Report
	if err := json.Unmarshal(b, &again); err != nil {
		t.Fatal(err)
	}
	if err := ValidateReport(again); err == nil || !strings.Contains(err.Error(), "without a known reason") {
		t.Fatalf("an unknown reason: %v", err)
	}
}

// The limits are inclusive: a report at each of them is valid, and the cases above show
// that one more is refused.
func TestReportLimitsAreInclusive(t *testing.T) {
	r := rulesBase()
	e := rulesEvidence("asset-a", OriginLocal)
	policy := rulesEvidence("", OriginAPI)
	r.Snapshot.Versions = make([]VersionFact, MaxObservations)
	r.Snapshot.Platforms = make([]PlatformFact, MaxObservations)
	r.Snapshot.Features = make([]FeatureFact, MaxObservations)
	r.Snapshot.Policies = make([]PolicyFact, MaxObservations)
	for i := 0; i < MaxObservations; i++ {
		r.Snapshot.Versions[i] = VersionFact{Role: VersionRunningDaemon, Channel: ChannelStable, Name: "client", Evidence: e}
		r.Snapshot.Platforms[i] = PlatformFact{OS: "linux", Evidence: e}
		r.Snapshot.Features[i] = FeatureFact{Name: "ssh", Evidence: e}
		r.Snapshot.Policies[i] = PolicyFact{Name: "acl-revision", Evidence: policy}
	}
	r.Coverage = make([]Coverage, MaxObservations)
	for i := range r.Coverage {
		r.Coverage[i] = Coverage{Target: rulesCatalogTarget, Context: rulesCtx, Source: "advisory catalog", Status: ReportPartial, Explanation: "synthetic"}
	}
	r.Findings = make([]Finding, MaxFindings)
	for i := range r.Findings {
		r.Findings[i] = rulesFinding("asset-a", fmt.Sprintf("rule-%d", i), ApplicabilityNotAffected)
	}
	r.TotalFindings = MaxFindings
	if err := ValidateReport(r); err != nil {
		t.Fatalf("a report at every limit: %v", err)
	}
	// A truncated report may total as many as MaxFindings while holding fewer.
	r.Findings, r.Truncated, r.TotalFindings = r.Findings[:MaxFindings-1], true, MaxFindings
	if err := ValidateReport(r); err != nil {
		t.Fatalf("a truncated report at the limit: %v", err)
	}
}
