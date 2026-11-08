package securitypack

import (
	"crypto/sha256"
	"fmt"

	"github.com/abm9111/tailkeeper/internal/security"
)

// Report hashes use the private canon/1 schema: snake_case names, sorted keys,
// JSON omitempty semantics, and ordered arrays. Access's public camelCase tags
// are mapped to snake_case here. Snapshot is the sole intentional exclusion: the
// pack integrity already covers it. Empty optional slices and nil are equivalent.
// Times are normalized to UTC without monotonic readings before encoding.
func hashReport(report security.Report) (string, error) {
	h := sha256.New()
	e := newCanonEncoder(h, MaxCanonBytes)
	writeReport(e, report)
	if err := e.finish(true); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func hashAccessReport(report security.AccessReport) (string, error) {
	h := sha256.New()
	e := newCanonEncoder(h, MaxCanonBytes)
	writeAccessReport(e, report)
	if err := e.finish(true); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func writeReport(e *canonEncoder, v security.Report) {
	_ = e.beginObject()
	_ = e.key("context")
	_ = e.text(string(v.Context))
	if len(v.Coverage) != 0 {
		_ = e.key("coverage")
		_ = e.beginArray()
		for _, item := range v.Coverage {
			if e.err != nil {
				break
			}
			writeCoverage(e, item)
		}
		_ = e.endArray()
	}
	if len(v.Findings) != 0 {
		_ = e.key("findings")
		_ = e.beginArray()
		for _, item := range v.Findings {
			if e.err != nil {
				break
			}
			writeFinding(e, item)
		}
		_ = e.endArray()
	}
	_ = e.key("generated_at")
	_ = e.instant(v.GeneratedAt.UTC().Round(0))
	if v.IntentDigest != "" {
		_ = e.key("intent_digest")
		_ = e.text(string(v.IntentDigest))
	}
	if v.IntentRevision != "" {
		_ = e.key("intent_revision")
		_ = e.text(string(v.IntentRevision))
	}
	if v.KeyEpoch != "" {
		_ = e.key("key_epoch")
		_ = e.text(string(v.KeyEpoch))
	}
	_ = e.key("requested_coverage")
	_ = e.beginArray()
	for _, item := range v.RequestedCoverage {
		if e.err != nil {
			break
		}
		writeCoverageTarget(e, item)
	}
	_ = e.endArray()
	_ = e.key("schema_version")
	_ = e.integer(int64(v.SchemaVersion))
	_ = e.key("status")
	_ = e.text(string(v.Status))
	_ = e.key("total_findings")
	_ = e.integer(int64(v.TotalFindings))
	_ = e.key("truncated")
	_ = e.boolean(v.Truncated)
	_ = e.endObject()
}

func writeFinding(e *canonEncoder, v security.Finding) {
	_ = e.beginObject()
	_ = e.key("applicability")
	_ = e.text(string(v.Applicability))
	if v.Asset != "" {
		_ = e.key("asset")
		_ = e.text(string(v.Asset))
	}
	_ = e.key("confidence")
	_ = e.text(string(v.Confidence))
	_ = e.key("context")
	_ = e.text(string(v.Context))
	if len(v.Evidence) != 0 {
		_ = e.key("evidence")
		_ = e.beginArray()
		for _, item := range v.Evidence {
			if e.err != nil {
				break
			}
			writeEvidenceRef(e, item)
		}
		_ = e.endArray()
	}
	_ = e.key("evidence_state")
	_ = e.text(string(v.EvidenceState))
	_ = e.key("explanation")
	_ = e.text(string(v.Explanation))
	_ = e.key("id")
	_ = e.text(string(v.ID))
	_ = e.key("priority")
	_ = e.text(string(v.Priority))
	if v.Reason != "" {
		_ = e.key("reason")
		_ = e.text(string(v.Reason))
	}
	if len(v.Remediation) != 0 {
		_ = e.key("remediation")
		_ = e.beginArray()
		for _, item := range v.Remediation {
			if e.err != nil {
				break
			}
			_ = e.text(string(item))
		}
		_ = e.endArray()
	}
	if len(v.Requirements) != 0 {
		_ = e.key("requirements")
		_ = e.beginArray()
		for _, item := range v.Requirements {
			if e.err != nil {
				break
			}
			_ = e.text(string(item))
		}
		_ = e.endArray()
	}
	_ = e.key("rule_id")
	_ = e.text(string(v.RuleID))
	_ = e.key("rule_revision")
	_ = e.text(string(v.RuleRevision))
	_ = e.key("source_severity")
	_ = e.text(string(v.SourceSeverity))
	if len(v.Verification) != 0 {
		_ = e.key("verification")
		_ = e.beginArray()
		for _, item := range v.Verification {
			if e.err != nil {
				break
			}
			_ = e.text(string(item))
		}
		_ = e.endArray()
	}
	_ = e.endObject()
}

func writeEvidenceRef(e *canonEncoder, v security.EvidenceRef) {
	_ = e.beginObject()
	_ = e.key("acquired_at")
	_ = e.instant(v.AcquiredAt.UTC().Round(0))
	if v.Asset != "" {
		_ = e.key("asset")
		_ = e.text(string(v.Asset))
	}
	_ = e.key("context")
	_ = e.text(string(v.Context))
	if v.Error != "" {
		_ = e.key("error")
		_ = e.text(string(v.Error))
	}
	_ = e.key("freshness")
	_ = e.text(string(v.Freshness))
	if v.ObservedAt != nil {
		_ = e.key("observed_at")
		_ = e.instant(v.ObservedAt.UTC().Round(0))
	}
	_ = e.key("origin")
	_ = e.text(string(v.Origin))
	if v.Scope != "" {
		_ = e.key("scope")
		_ = e.text(string(v.Scope))
	}
	_ = e.endObject()
}

func writeCoverageTarget(e *canonEncoder, v security.CoverageTarget) {
	_ = e.beginObject()
	if v.Asset != "" {
		_ = e.key("asset")
		_ = e.text(string(v.Asset))
	}
	_ = e.key("dimension")
	_ = e.text(string(v.Dimension))
	_ = e.key("scope")
	_ = e.text(string(v.Scope))
	_ = e.endObject()
}

func writeCoverageCounts(e *canonEncoder, v security.CoverageCounts) {
	_ = e.beginObject()
	_ = e.key("assets")
	_ = e.integer(int64(v.Assets))
	_ = e.key("findings")
	_ = e.integer(int64(v.Findings))
	_ = e.key("potential")
	_ = e.integer(int64(v.Potential))
	_ = e.key("rules")
	_ = e.integer(int64(v.Rules))
	_ = e.key("unknown")
	_ = e.integer(int64(v.Unknown))
	_ = e.key("withdrawn")
	_ = e.integer(int64(v.Withdrawn))
	_ = e.endObject()
}

func writeCoverage(e *canonEncoder, v security.Coverage) {
	_ = e.beginObject()
	_ = e.key("context")
	_ = e.text(string(v.Context))
	if v.Counts != nil {
		_ = e.key("counts")
		writeCoverageCounts(e, *v.Counts)
	}
	if v.Explanation != "" {
		_ = e.key("explanation")
		_ = e.text(string(v.Explanation))
	}
	_ = e.key("source")
	_ = e.text(string(v.Source))
	_ = e.key("status")
	_ = e.text(string(v.Status))
	_ = e.key("target")
	writeCoverageTarget(e, v.Target)
	_ = e.endObject()
}

func writeAccessReport(e *canonEncoder, v security.AccessReport) {
	_ = e.beginObject()
	if len(v.Blast) != 0 {
		_ = e.key("blast")
		_ = e.beginArray()
		for _, item := range v.Blast {
			if e.err != nil {
				break
			}
			writeAccessBlast(e, item)
		}
		_ = e.endArray()
	}
	_ = e.key("counts")
	writeAccessCounts(e, v.Counts)
	_ = e.key("evaluated_at")
	_ = e.instant(v.EvaluatedAt.UTC().Round(0))
	if len(v.Expectations) != 0 {
		_ = e.key("expectations")
		_ = e.beginArray()
		for _, item := range v.Expectations {
			if e.err != nil {
				break
			}
			writeAccessResult(e, item)
		}
		_ = e.endArray()
	}
	if v.IntentDigest != "" {
		_ = e.key("intent_digest")
		_ = e.text(string(v.IntentDigest))
	}
	if v.IntentRevision != "" {
		_ = e.key("intent_revision")
		_ = e.text(string(v.IntentRevision))
	}
	if v.NoIntent {
		_ = e.key("no_intent")
		_ = e.boolean(v.NoIntent)
	}
	if len(v.Notes) != 0 {
		_ = e.key("notes")
		_ = e.beginArray()
		for _, item := range v.Notes {
			if e.err != nil {
				break
			}
			_ = e.text(string(item))
		}
		_ = e.endArray()
	}
	if v.Omitted != 0 {
		_ = e.key("omitted")
		_ = e.integer(int64(v.Omitted))
	}
	_ = e.key("pairs_judged")
	_ = e.integer(int64(v.PairsJudged))
	_ = e.key("pairs_past_cap")
	_ = e.integer(int64(v.PairsPastCap))
	if v.PolicyVersion != "" {
		_ = e.key("policy_version")
		_ = e.text(string(v.PolicyVersion))
	}
	_ = e.key("proof")
	writeAccessProof(e, v.Proof)
	_ = e.key("schema_version")
	_ = e.integer(int64(v.SchemaVersion))
	_ = e.key("status")
	_ = e.text(string(v.Status))
	_ = e.endObject()
}

func writeAccessCounts(e *canonEncoder, v security.AccessCounts) {
	_ = e.beginObject()
	_ = e.key("met")
	_ = e.integer(int64(v.Met))
	_ = e.key("met_with_limits")
	_ = e.integer(int64(v.MetWithLimits))
	_ = e.key("not_evaluated")
	_ = e.integer(int64(v.NotEvaluated))
	_ = e.key("total")
	_ = e.integer(int64(v.Total))
	_ = e.key("unknown")
	_ = e.integer(int64(v.Unknown))
	_ = e.key("unmet")
	_ = e.integer(int64(v.Unmet))
	_ = e.endObject()
}

func writeAccessProof(e *canonEncoder, v security.AccessProof) {
	_ = e.beginObject()
	_ = e.key("canary")
	_ = e.boolean(v.Canary)
	_ = e.key("live_unchanged")
	_ = e.boolean(v.LiveUnchanged)
	_ = e.endObject()
}

func writeAccessResult(e *canonEncoder, v security.AccessResult) {
	_ = e.beginObject()
	if len(v.Candidates) != 0 {
		_ = e.key("candidates")
		_ = e.beginArray()
		for _, item := range v.Candidates {
			if e.err != nil {
				break
			}
			writeRuleRef(e, item)
		}
		_ = e.endArray()
	}
	if v.CandidatesOmitted != 0 {
		_ = e.key("candidates_omitted")
		_ = e.integer(int64(v.CandidatesOmitted))
	}
	if len(v.Cells) != 0 {
		_ = e.key("cells")
		_ = e.beginArray()
		for _, item := range v.Cells {
			if e.err != nil {
				break
			}
			writeAccessCellResult(e, item)
		}
		_ = e.endArray()
	}
	_ = e.key("id")
	_ = e.text(string(v.ID))
	_ = e.key("kind")
	_ = e.text(string(v.Kind))
	if len(v.Limits) != 0 {
		_ = e.key("limits")
		_ = e.beginArray()
		for _, item := range v.Limits {
			if e.err != nil {
				break
			}
			_ = e.text(string(item))
		}
		_ = e.endArray()
	}
	if v.PastCap != 0 {
		_ = e.key("past_cap")
		_ = e.integer(int64(v.PastCap))
	}
	_ = e.key("source")
	_ = e.text(string(v.Source))
	_ = e.key("status")
	_ = e.text(string(v.Status))
	_ = e.endObject()
}

func writeAccessCellResult(e *canonEncoder, v security.AccessCellResult) {
	_ = e.beginObject()
	_ = e.key("destination")
	_ = e.text(string(v.AccessCell.Destination))
	_ = e.key("expect")
	_ = e.text(string(v.AccessCell.Expect))
	_ = e.key("observed")
	_ = e.text(string(v.Observed))
	_ = e.key("proof")
	writeAccessProof(e, v.Proof)
	if v.Reason != "" {
		_ = e.key("reason")
		_ = e.text(string(v.Reason))
	}
	if v.AccessCell.User != "" {
		_ = e.key("user")
		_ = e.text(string(v.AccessCell.User))
	}
	_ = e.key("verdict")
	_ = e.text(string(v.Verdict))
	_ = e.endObject()
}

func writeRuleRef(e *canonEncoder, v security.RuleRef) {
	_ = e.beginObject()
	if v.AllTraffic {
		_ = e.key("all_traffic")
		_ = e.boolean(v.AllTraffic)
	}
	if v.Broad {
		_ = e.key("broad")
		_ = e.boolean(v.Broad)
	}
	if v.Column != 0 {
		_ = e.key("column")
		_ = e.integer(int64(v.Column))
	}
	_ = e.key("destination")
	_ = e.text(string(v.Destination))
	_ = e.key("index")
	_ = e.integer(int64(v.Index))
	if v.Line != 0 {
		_ = e.key("line")
		_ = e.integer(int64(v.Line))
	}
	if v.Ports != "" {
		_ = e.key("ports")
		_ = e.text(string(v.Ports))
	}
	if v.Qualified {
		_ = e.key("qualified")
		_ = e.boolean(v.Qualified)
	}
	_ = e.key("section")
	_ = e.text(string(v.Section))
	_ = e.key("source")
	_ = e.text(string(v.Source))
	if v.Traffic != "" {
		_ = e.key("traffic")
		_ = e.text(string(v.Traffic))
	}
	_ = e.endObject()
}

func writeAccessBlast(e *canonEncoder, v security.AccessBlast) {
	_ = e.beginObject()
	if len(v.Broad) != 0 {
		_ = e.key("broad")
		_ = e.beginArray()
		for _, item := range v.Broad {
			if e.err != nil {
				break
			}
			writeRuleRef(e, item)
		}
		_ = e.endArray()
	}
	_ = e.key("heading")
	_ = e.text(string(v.Heading))
	if len(v.Reaches) != 0 {
		_ = e.key("reaches")
		_ = e.beginArray()
		for _, item := range v.Reaches {
			if e.err != nil {
				break
			}
			writeAccessReach(e, item)
		}
		_ = e.endArray()
	}
	_ = e.key("source")
	_ = e.text(string(v.Source))
	if len(v.Tags) != 0 {
		_ = e.key("tags")
		_ = e.beginArray()
		for _, item := range v.Tags {
			if e.err != nil {
				break
			}
			_ = e.text(string(item))
		}
		_ = e.endArray()
	}
	if v.TagsOmitted != 0 {
		_ = e.key("tags_omitted")
		_ = e.integer(int64(v.TagsOmitted))
	}
	_ = e.endObject()
}

func writeAccessReach(e *canonEncoder, v security.AccessReach) {
	_ = e.beginObject()
	_ = e.key("destination")
	_ = e.text(string(v.Destination))
	_ = e.key("expectation")
	_ = e.text(string(v.Expectation))
	_ = e.key("kind")
	_ = e.text(string(v.Kind))
	if v.User != "" {
		_ = e.key("user")
		_ = e.text(string(v.User))
	}
	_ = e.endObject()
}
