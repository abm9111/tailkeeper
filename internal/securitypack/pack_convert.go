package securitypack

import (
	"time"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/security"
)

type EvidencePack struct {
	envelope packEnvelope
	reading  Reading
	valid    bool
}

type packInput struct {
	Snapshot         security.Snapshot
	Sources          []advisory.Source
	CatalogDigest    string
	Collected        []security.Coverage
	EvaluationAt     time.Time
	WorkBudget       security.WorkBudget
	EvaluatorVersion int
	Intent           *security.IntentSet
	IntentDigestForm tokenForm
	Access           *accessInput
	Expected         packExpected
}

type accessInput struct {
	Context           string
	Selected          []string
	Input             security.AccessInput
	PolicyVersionForm tokenForm
}

func ownedString(value *string) *string {
	if value == nil {
		return nil
	}
	v := *value
	return &v
}

func ownedBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	v := *value
	return &v
}

func ownedTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	v := value.UTC().Round(0)
	return &v
}

func evidenceToPack(value security.EvidenceRef) packEvidence {
	return packEvidence{AcquiredAt: value.AcquiredAt.UTC().Round(0), Asset: value.Asset, Context: value.Context,
		Error: value.Error, Freshness: string(value.Freshness), ObservedAt: ownedTime(value.ObservedAt),
		Origin: string(value.Origin), Scope: string(value.Scope)}
}

func evidenceFromPack(value packEvidence) security.EvidenceRef {
	return security.EvidenceRef{AcquiredAt: value.AcquiredAt, Asset: value.Asset, Context: value.Context,
		Error: value.Error, Freshness: security.Freshness(value.Freshness), ObservedAt: ownedTime(value.ObservedAt),
		Origin: security.Origin(value.Origin), Scope: security.Scope(value.Scope)}
}

func snapshotToPack(value security.Snapshot) packSnapshot {
	out := packSnapshot{Context: value.Context, KeyEpoch: value.KeyEpoch, Scope: string(value.Scope), ObservedAt: value.ObservedAt.UTC().Round(0)}
	for _, v := range value.Versions {
		out.Versions = append(out.Versions, packVersion{Channel: string(v.Channel), Evidence: evidenceToPack(v.Evidence), Name: v.Name, Role: string(v.Role), Value: ownedString(v.Value)})
	}
	for _, v := range value.Platforms {
		out.Platforms = append(out.Platforms, packPlatform{Evidence: evidenceToPack(v.Evidence), OS: v.OS, Variant: v.Variant})
	}
	for _, v := range value.Features {
		out.Features = append(out.Features, packFeature{Evidence: evidenceToPack(v.Evidence), Name: v.Name, Value: ownedBool(v.Value)})
	}
	for _, v := range value.Policies {
		out.Policies = append(out.Policies, packPolicy{Evidence: evidenceToPack(v.Evidence), Name: v.Name, Value: ownedString(v.Value)})
	}
	return out
}

func snapshotFromPack(value packSnapshot) security.Snapshot {
	out := security.Snapshot{Context: value.Context, KeyEpoch: value.KeyEpoch, Scope: security.Scope(value.Scope), ObservedAt: value.ObservedAt}
	for _, v := range value.Versions {
		out.Versions = append(out.Versions, security.VersionFact{Channel: security.VersionChannel(v.Channel), Evidence: evidenceFromPack(v.Evidence), Name: v.Name, Role: security.VersionRole(v.Role), Value: ownedString(v.Value)})
	}
	for _, v := range value.Platforms {
		out.Platforms = append(out.Platforms, security.PlatformFact{Evidence: evidenceFromPack(v.Evidence), OS: v.OS, Variant: v.Variant})
	}
	for _, v := range value.Features {
		out.Features = append(out.Features, security.FeatureFact{Evidence: evidenceFromPack(v.Evidence), Name: v.Name, Value: ownedBool(v.Value)})
	}
	for _, v := range value.Policies {
		out.Policies = append(out.Policies, security.PolicyFact{Evidence: evidenceFromPack(v.Evidence), Name: v.Name, Value: ownedString(v.Value)})
	}
	return out
}

func coverageToPack(values []security.Coverage) []packCoverage {
	var out []packCoverage
	for _, v := range values {
		row := packCoverage{Context: v.Context, Explanation: v.Explanation, Source: v.Source, Status: string(v.Status), Target: packCoverageTarget{Asset: v.Target.Asset, Dimension: string(v.Target.Dimension), Scope: string(v.Target.Scope)}}
		if v.Counts != nil {
			row.Counts = &packCoverageCounts{Assets: v.Counts.Assets, Findings: v.Counts.Findings, Potential: v.Counts.Potential, Rules: v.Counts.Rules, Unknown: v.Counts.Unknown, Withdrawn: v.Counts.Withdrawn}
		}
		out = append(out, row)
	}
	return out
}

func coverageFromPack(values []packCoverage) []security.Coverage {
	var out []security.Coverage
	for _, v := range values {
		row := security.Coverage{Context: v.Context, Explanation: v.Explanation, Source: v.Source, Status: security.ReportStatus(v.Status), Target: security.CoverageTarget{Asset: v.Target.Asset, Dimension: security.CoverageDimension(v.Target.Dimension), Scope: security.Scope(v.Target.Scope)}}
		if v.Counts != nil {
			row.Counts = &security.CoverageCounts{Assets: v.Counts.Assets, Findings: v.Counts.Findings, Potential: v.Counts.Potential, Rules: v.Counts.Rules, Unknown: v.Counts.Unknown, Withdrawn: v.Counts.Withdrawn}
		}
		out = append(out, row)
	}
	return out
}
