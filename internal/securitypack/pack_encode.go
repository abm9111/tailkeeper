package securitypack

import (
	"bytes"
	"time"
)

const (
	MaxPackBytes      = 16 << 20
	MaxPackNodes      = 600000
	PackSchemaVersion = 1
)

const (
	maxCatalogSources = 64
	maxCatalogBytes   = 4 << 20
	maxSnapshotFacts  = 10000
	maxCandidateRules = 8
	maxOwnerTags      = 8
)

// preflightPackBody checks bounded collections before allocating a canonical
// encoder or writing any part of a body. Nested writers repeat these checks.
func preflightPackBody(body packBody) error {
	if len(body.Catalog.Sources) > maxCatalogSources {
		return errCanonInvalid
	}
	remaining := maxCatalogBytes
	for i := range body.Catalog.Sources {
		size := len(body.Catalog.Sources[i].Data)
		if size > remaining {
			return errCanonInvalid
		}
		remaining -= size
	}
	return preflightSnapshotFacts(body.Snapshot)
}

func preflightSnapshotFacts(snapshot packSnapshot) error {
	remaining := maxSnapshotFacts
	for _, count := range [4]int{len(snapshot.Features), len(snapshot.Platforms), len(snapshot.Policies), len(snapshot.Versions)} {
		if count > remaining {
			return errCanonInvalid
		}
		remaining -= count
	}
	return nil
}

// encodePackBody writes one canonical body object without a trailing newline.
func encodePackBody(body packBody) ([]byte, error) {
	if err := preflightPackBody(body); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	encoder := newCanonEncoder(&buffer, MaxPackBytes)
	if err := writePackBody(encoder, body); err != nil {
		return nil, err
	}
	if err := encoder.finish(false); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// encodePackEnvelope writes the canonical envelope with exactly one final LF.
// The body is written inline as a nested object, never as encoded text.
func encodePackEnvelope(envelope packEnvelope) ([]byte, error) {
	if err := preflightPackBody(envelope.Body); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	encoder := newCanonEncoder(&buffer, MaxPackBytes)
	if err := encoder.beginObject(); err != nil {
		return nil, err
	}
	if err := encoder.key("body"); err != nil {
		return nil, err
	}
	if err := writePackBody(encoder, envelope.Body); err != nil {
		return nil, err
	}
	if err := encoder.key("integrity"); err != nil {
		return nil, err
	}
	if err := encoder.text(envelope.Integrity); err != nil {
		return nil, err
	}
	if envelope.Seal != nil {
		if err := encoder.key("seal"); err != nil {
			return nil, err
		}
		if err := encoder.text(*envelope.Seal); err != nil {
			return nil, err
		}
	}
	if err := encoder.endObject(); err != nil {
		return nil, err
	}
	if err := encoder.finish(true); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func writePackBody(encoder *canonEncoder, body packBody) error {
	if err := preflightPackBody(body); err != nil {
		return err
	}
	if err := writePackBodyAccessAndCatalog(encoder, body); err != nil {
		return err
	}
	if err := writePackBodyCollectionAndEvaluation(encoder, body); err != nil {
		return err
	}
	if err := writePackBodyExpectedAndFormat(encoder, body); err != nil {
		return err
	}
	if err := writePackBodyIntentAndSnapshot(encoder, body); err != nil {
		return err
	}
	return nil
}

func writePackBodyAccessAndCatalog(encoder *canonEncoder, body packBody) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if body.Access != nil {
		if err := encoder.key("access"); err != nil {
			return err
		}
		if err := writePackAccess(encoder, *body.Access); err != nil {
			return err
		}
	}
	if err := encoder.key("catalog"); err != nil {
		return err
	}
	if err := writePackCatalog(encoder, body.Catalog); err != nil {
		return err
	}
	return nil
}

func writePackBodyCollectionAndEvaluation(encoder *canonEncoder, body packBody) error {
	if err := packIntegerField(encoder, "catalog_schema_version", body.CatalogSchemaVersion); err != nil {
		return err
	}
	if len(body.Collected) > 0 {
		if err := encoder.key("collected"); err != nil {
			return err
		}
		if err := encoder.beginArray(); err != nil {
			return err
		}
		for i := range body.Collected {
			if err := writePackCoverage(encoder, body.Collected[i]); err != nil {
				return err
			}
		}
		if err := encoder.endArray(); err != nil {
			return err
		}
	}
	if err := encoder.key("evaluation"); err != nil {
		return err
	}
	if err := writePackEvaluation(encoder, body.Evaluation); err != nil {
		return err
	}
	return nil
}

func writePackBodyExpectedAndFormat(encoder *canonEncoder, body packBody) error {
	if err := packIntegerField(encoder, "evaluator_version", body.EvaluatorVersion); err != nil {
		return err
	}
	if err := encoder.key("expected"); err != nil {
		return err
	}
	if err := writePackExpected(encoder, body.Expected); err != nil {
		return err
	}
	if err := packTextField(encoder, "format", body.Format); err != nil {
		return err
	}
	return nil
}

func writePackBodyIntentAndSnapshot(encoder *canonEncoder, body packBody) error {
	if body.Intent != nil {
		if err := encoder.key("intent"); err != nil {
			return err
		}
		if err := writePackIntent(encoder, *body.Intent); err != nil {
			return err
		}
	}
	if err := packIntegerField(encoder, "pack_schema_version", body.PackSchemaVersion); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "report_schema_version", body.ReportSchemaVersion); err != nil {
		return err
	}
	if err := encoder.key("snapshot"); err != nil {
		return err
	}
	if err := writePackSnapshot(encoder, body.Snapshot); err != nil {
		return err
	}
	return encoder.endObject()
}

func writePackCatalog(encoder *canonEncoder, catalog packCatalog) error {
	if len(catalog.Sources) > maxCatalogSources {
		return errCanonInvalid
	}
	total := 0
	for i := range catalog.Sources {
		if i > 0 && catalog.Sources[i-1].Name >= catalog.Sources[i].Name {
			return errCanonInvalid
		}
		if len(catalog.Sources[i].Data) > maxCatalogBytes-total {
			return errCanonInvalid
		}
		total += len(catalog.Sources[i].Data)
	}
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if err := packTextField(encoder, "digest", catalog.Digest); err != nil {
		return err
	}
	if err := encoder.key("sources"); err != nil {
		return err
	}
	if err := encoder.beginArray(); err != nil {
		return err
	}
	for i := range catalog.Sources {
		if err := writePackSource(encoder, catalog.Sources[i]); err != nil {
			return err
		}
	}
	if err := encoder.endArray(); err != nil {
		return err
	}
	return encoder.endObject()
}

func writePackSource(encoder *canonEncoder, source packSource) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if err := encoder.key("data"); err != nil {
		return err
	}
	if err := encoder.binary(source.Data); err != nil {
		return err
	}
	if err := packTextField(encoder, "name", source.Name); err != nil {
		return err
	}
	if err := encoder.key("sha256"); err != nil {
		return err
	}
	if err := encoder.text(source.SHA256); err != nil {
		return err
	}
	return encoder.endObject()
}

func writePackEvaluation(encoder *canonEncoder, evaluation packEvaluation) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if err := packInstantField(encoder, "at", evaluation.At); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "work_budget", evaluation.WorkBudget); err != nil {
		return err
	}
	return encoder.endObject()
}

func packInt(encoder *canonEncoder, value int) error {
	return encoder.integer(int64(value))
}

// writePackInstant normalizes trusted producer instants to UTC without a
// monotonic reading so equivalent instants write identical bytes.
func writePackInstant(encoder *canonEncoder, value time.Time) error {
	return encoder.instant(value.UTC().Round(0))
}

func writePackExpected(encoder *canonEncoder, expected packExpected) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if expected.Access != nil {
		if err := encoder.key("access"); err != nil {
			return err
		}
		if err := writePackExpectedAccess(encoder, *expected.Access); err != nil {
			return err
		}
	}
	if err := encoder.key("counts"); err != nil {
		return err
	}
	if err := writePackExpectedCounts(encoder, expected.Counts); err != nil {
		return err
	}
	if err := encoder.key("report"); err != nil {
		return err
	}
	if err := writePackExpectedReport(encoder, expected.Report); err != nil {
		return err
	}
	return encoder.endObject()
}

func writePackExpectedCounts(encoder *canonEncoder, counts packExpectedCounts) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "devices", counts.Devices); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "features", counts.Features); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "platforms", counts.Platforms); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "policies", counts.Policies); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "versions", counts.Versions); err != nil {
		return err
	}
	return encoder.endObject()
}

func writePackExpectedReport(encoder *canonEncoder, report packExpectedReport) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "affected", report.Affected); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "not_affected", report.NotAffected); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "potentially_affected", report.PotentiallyAffected); err != nil {
		return err
	}
	if err := encoder.key("sha256"); err != nil {
		return err
	}
	if err := encoder.text(report.SHA256); err != nil {
		return err
	}
	if err := packTextField(encoder, "status", report.Status); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "total_findings", report.TotalFindings); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "unknown", report.Unknown); err != nil {
		return err
	}
	return encoder.endObject()
}

func writePackExpectedAccess(encoder *canonEncoder, access packExpectedAccess) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "met", access.Met); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "met_with_limits", access.MetWithLimits); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "not_evaluated", access.NotEvaluated); err != nil {
		return err
	}
	if err := encoder.key("sha256"); err != nil {
		return err
	}
	if err := encoder.text(access.SHA256); err != nil {
		return err
	}
	if err := packTextField(encoder, "status", access.Status); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "total", access.Total); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "unknown", access.Unknown); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "unmet", access.Unmet); err != nil {
		return err
	}
	return encoder.endObject()
}

func writePackSnapshot(encoder *canonEncoder, snapshot packSnapshot) error {
	if err := writePackSnapshotStart(encoder, snapshot); err != nil {
		return err
	}
	if err := writePackSnapshotFeatures(encoder, snapshot); err != nil {
		return err
	}
	if err := writePackSnapshotMetaAndPlatforms(encoder, snapshot); err != nil {
		return err
	}
	if err := writePackSnapshotPoliciesAndVersions(encoder, snapshot); err != nil {
		return err
	}
	return nil
}

func writePackSnapshotStart(encoder *canonEncoder, snapshot packSnapshot) error {
	if err := preflightSnapshotFacts(snapshot); err != nil {
		return err
	}
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if err := packTextField(encoder, "context", snapshot.Context); err != nil {
		return err
	}
	return nil
}

func writePackSnapshotFeatures(encoder *canonEncoder, snapshot packSnapshot) error {
	if len(snapshot.Features) > 0 {
		if err := encoder.key("features"); err != nil {
			return err
		}
		if err := encoder.beginArray(); err != nil {
			return err
		}
		for i := range snapshot.Features {
			if err := writePackFeature(encoder, snapshot.Features[i]); err != nil {
				return err
			}
		}
		if err := encoder.endArray(); err != nil {
			return err
		}
	}
	return nil
}

func writePackSnapshotMetaAndPlatforms(encoder *canonEncoder, snapshot packSnapshot) error {
	if snapshot.KeyEpoch != "" {
		if err := packTextField(encoder, "key_epoch", snapshot.KeyEpoch); err != nil {
			return err
		}
	}
	if err := packInstantField(encoder, "observed_at", snapshot.ObservedAt); err != nil {
		return err
	}
	if len(snapshot.Platforms) > 0 {
		if err := encoder.key("platforms"); err != nil {
			return err
		}
		if err := encoder.beginArray(); err != nil {
			return err
		}
		for i := range snapshot.Platforms {
			if err := writePackPlatform(encoder, snapshot.Platforms[i]); err != nil {
				return err
			}
		}
		if err := encoder.endArray(); err != nil {
			return err
		}
	}
	return nil
}

func writePackSnapshotPoliciesAndVersions(encoder *canonEncoder, snapshot packSnapshot) error {
	if len(snapshot.Policies) > 0 {
		if err := encoder.key("policies"); err != nil {
			return err
		}
		if err := encoder.beginArray(); err != nil {
			return err
		}
		for i := range snapshot.Policies {
			if err := writePackPolicy(encoder, snapshot.Policies[i]); err != nil {
				return err
			}
		}
		if err := encoder.endArray(); err != nil {
			return err
		}
	}
	if err := packTextField(encoder, "scope", snapshot.Scope); err != nil {
		return err
	}
	if len(snapshot.Versions) > 0 {
		if err := encoder.key("versions"); err != nil {
			return err
		}
		if err := encoder.beginArray(); err != nil {
			return err
		}
		for i := range snapshot.Versions {
			if err := writePackVersion(encoder, snapshot.Versions[i]); err != nil {
				return err
			}
		}
		if err := encoder.endArray(); err != nil {
			return err
		}
	}
	return encoder.endObject()
}

func writePackVersion(encoder *canonEncoder, version packVersion) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if err := packTextField(encoder, "channel", version.Channel); err != nil {
		return err
	}
	if err := encoder.key("evidence"); err != nil {
		return err
	}
	if err := writePackEvidence(encoder, version.Evidence); err != nil {
		return err
	}
	if err := packTextField(encoder, "name", version.Name); err != nil {
		return err
	}
	if err := packTextField(encoder, "role", version.Role); err != nil {
		return err
	}
	if version.Value != nil {
		if err := packTextField(encoder, "value", *version.Value); err != nil {
			return err
		}
	}
	return encoder.endObject()
}

func writePackPlatform(encoder *canonEncoder, platform packPlatform) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if err := encoder.key("evidence"); err != nil {
		return err
	}
	if err := writePackEvidence(encoder, platform.Evidence); err != nil {
		return err
	}
	if platform.OS != "" {
		if err := packTextField(encoder, "os", platform.OS); err != nil {
			return err
		}
	}
	if platform.Variant != "" {
		if err := packTextField(encoder, "variant", platform.Variant); err != nil {
			return err
		}
	}
	return encoder.endObject()
}

func writePackFeature(encoder *canonEncoder, feature packFeature) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if err := encoder.key("evidence"); err != nil {
		return err
	}
	if err := writePackEvidence(encoder, feature.Evidence); err != nil {
		return err
	}
	if err := packTextField(encoder, "name", feature.Name); err != nil {
		return err
	}
	if feature.Value != nil {
		if err := packBooleanField(encoder, "value", *feature.Value); err != nil {
			return err
		}
	}
	return encoder.endObject()
}

func writePackPolicy(encoder *canonEncoder, policy packPolicy) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if err := encoder.key("evidence"); err != nil {
		return err
	}
	if err := writePackEvidence(encoder, policy.Evidence); err != nil {
		return err
	}
	if err := packTextField(encoder, "name", policy.Name); err != nil {
		return err
	}
	if policy.Value != nil {
		if err := packTextField(encoder, "value", *policy.Value); err != nil {
			return err
		}
	}
	return encoder.endObject()
}

func writePackEvidence(encoder *canonEncoder, evidence packEvidence) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if err := packInstantField(encoder, "acquired_at", evidence.AcquiredAt); err != nil {
		return err
	}
	if evidence.Asset != "" {
		if err := packTextField(encoder, "asset", evidence.Asset); err != nil {
			return err
		}
	}
	if err := packTextField(encoder, "context", evidence.Context); err != nil {
		return err
	}
	if evidence.Error != "" {
		if err := packTextField(encoder, "error", evidence.Error); err != nil {
			return err
		}
	}
	if err := packTextField(encoder, "freshness", evidence.Freshness); err != nil {
		return err
	}
	if evidence.ObservedAt != nil {
		if err := packInstantField(encoder, "observed_at", *evidence.ObservedAt); err != nil {
			return err
		}
	}
	if err := packTextField(encoder, "origin", evidence.Origin); err != nil {
		return err
	}
	if err := packTextField(encoder, "scope", evidence.Scope); err != nil {
		return err
	}
	return encoder.endObject()
}

func writePackCoverage(encoder *canonEncoder, coverage packCoverage) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if err := packTextField(encoder, "context", coverage.Context); err != nil {
		return err
	}
	if coverage.Counts != nil {
		if err := encoder.key("counts"); err != nil {
			return err
		}
		if err := writePackCoverageCounts(encoder, *coverage.Counts); err != nil {
			return err
		}
	}
	if coverage.Explanation != "" {
		if err := packTextField(encoder, "explanation", coverage.Explanation); err != nil {
			return err
		}
	}
	if err := packTextField(encoder, "source", coverage.Source); err != nil {
		return err
	}
	if err := packTextField(encoder, "status", coverage.Status); err != nil {
		return err
	}
	if err := encoder.key("target"); err != nil {
		return err
	}
	if err := writePackCoverageTarget(encoder, coverage.Target); err != nil {
		return err
	}
	return encoder.endObject()
}

func writePackCoverageTarget(encoder *canonEncoder, target packCoverageTarget) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if target.Asset != "" {
		if err := packTextField(encoder, "asset", target.Asset); err != nil {
			return err
		}
	}
	if err := packTextField(encoder, "dimension", target.Dimension); err != nil {
		return err
	}
	if err := packTextField(encoder, "scope", target.Scope); err != nil {
		return err
	}
	return encoder.endObject()
}

func writePackCoverageCounts(encoder *canonEncoder, counts packCoverageCounts) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "assets", counts.Assets); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "findings", counts.Findings); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "potential", counts.Potential); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "rules", counts.Rules); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "unknown", counts.Unknown); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "withdrawn", counts.Withdrawn); err != nil {
		return err
	}
	return encoder.endObject()
}

func writePackToken(encoder *canonEncoder, token packToken) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if err := packTextField(encoder, "form", string(token.Form)); err != nil {
		return err
	}
	if err := packTextField(encoder, "value", token.Value); err != nil {
		return err
	}
	return encoder.endObject()
}

func writePackIntent(encoder *canonEncoder, intent packIntent) error {
	if err := writePackIntentNetworkAndRevision(encoder, intent); err != nil {
		return err
	}
	if err := writePackIntentSchemaAndSSH(encoder, intent); err != nil {
		return err
	}
	return nil
}

func writePackIntentNetworkAndRevision(encoder *canonEncoder, intent packIntent) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if intent.Digest != nil {
		if err := encoder.key("digest"); err != nil {
			return err
		}
		if err := writePackToken(encoder, *intent.Digest); err != nil {
			return err
		}
	}
	if len(intent.Network) > 0 {
		if err := encoder.key("network"); err != nil {
			return err
		}
		if err := encoder.beginArray(); err != nil {
			return err
		}
		for i := range intent.Network {
			if err := writePackNetwork(encoder, intent.Network[i]); err != nil {
				return err
			}
		}
		if err := encoder.endArray(); err != nil {
			return err
		}
	}
	if intent.Revision != "" {
		if err := packTextField(encoder, "revision", intent.Revision); err != nil {
			return err
		}
	}
	return nil
}

func writePackIntentSchemaAndSSH(encoder *canonEncoder, intent packIntent) error {
	if err := packIntegerField(encoder, "schema_version", intent.SchemaVersion); err != nil {
		return err
	}
	if len(intent.SSH) > 0 {
		if err := encoder.key("ssh"); err != nil {
			return err
		}
		if err := encoder.beginArray(); err != nil {
			return err
		}
		for i := range intent.SSH {
			if err := writePackSSH(encoder, intent.SSH[i]); err != nil {
				return err
			}
		}
		if err := encoder.endArray(); err != nil {
			return err
		}
	}
	return encoder.endObject()
}

func writePackNetwork(encoder *canonEncoder, network packNetwork) error {
	if err := writePackNetworkSelectors(encoder, network); err != nil {
		return err
	}
	if err := writePackNetworkSourceAndPosture(encoder, network); err != nil {
		return err
	}
	return encoder.endObject()
}

func writePackNetworkSelectors(encoder *canonEncoder, network packNetwork) error {
	for i := 1; i < len(network.SrcPostureAttrs); i++ {
		if network.SrcPostureAttrs[i-1].Name >= network.SrcPostureAttrs[i].Name {
			return errCanonInvalid
		}
	}
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if len(network.Accept) > 0 {
		if err := encoder.key("accept"); err != nil {
			return err
		}
		if err := writePackTextArray(encoder, network.Accept); err != nil {
			return err
		}
	}
	if len(network.Deny) > 0 {
		if err := encoder.key("deny"); err != nil {
			return err
		}
		if err := writePackTextArray(encoder, network.Deny); err != nil {
			return err
		}
	}
	return nil
}

func writePackNetworkSourceAndPosture(encoder *canonEncoder, network packNetwork) error {
	if err := packTextField(encoder, "id", network.ID); err != nil {
		return err
	}
	if network.Proto != "" {
		if err := packTextField(encoder, "proto", network.Proto); err != nil {
			return err
		}
	}
	if err := packTextField(encoder, "src", network.Src); err != nil {
		return err
	}
	if len(network.SrcPostureAttrs) > 0 {
		if err := encoder.key("src_posture_attrs"); err != nil {
			return err
		}
		if err := encoder.beginArray(); err != nil {
			return err
		}
		for i := range network.SrcPostureAttrs {
			if err := writePackAttribute(encoder, network.SrcPostureAttrs[i]); err != nil {
				return err
			}
		}
		if err := encoder.endArray(); err != nil {
			return err
		}
	}
	return nil
}

func writePackSSH(encoder *canonEncoder, ssh packSSH) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if len(ssh.Accept) > 0 {
		if err := encoder.key("accept"); err != nil {
			return err
		}
		if err := writePackTextArray(encoder, ssh.Accept); err != nil {
			return err
		}
	}
	if len(ssh.Check) > 0 {
		if err := encoder.key("check"); err != nil {
			return err
		}
		if err := writePackTextArray(encoder, ssh.Check); err != nil {
			return err
		}
	}
	if len(ssh.Deny) > 0 {
		if err := encoder.key("deny"); err != nil {
			return err
		}
		if err := writePackTextArray(encoder, ssh.Deny); err != nil {
			return err
		}
	}
	if err := encoder.key("dst"); err != nil {
		return err
	}
	if err := writePackTextArray(encoder, ssh.Dst); err != nil {
		return err
	}
	if err := packTextField(encoder, "id", ssh.ID); err != nil {
		return err
	}
	if err := packTextField(encoder, "src", ssh.Src); err != nil {
		return err
	}
	return encoder.endObject()
}

func writePackAttribute(encoder *canonEncoder, attribute packAttribute) error {
	values := 0
	if attribute.Bool != nil {
		values++
	}
	if attribute.Number != nil {
		values++
	}
	if attribute.String != nil {
		values++
	}
	if values != 1 {
		return errCanonInvalid
	}
	if err := encoder.beginObject(); err != nil {
		return err
	}
	switch {
	case attribute.Bool != nil:
		if err := packBooleanField(encoder, "bool", *attribute.Bool); err != nil {
			return err
		}
		if err := packTextField(encoder, "name", attribute.Name); err != nil {
			return err
		}
	case attribute.Number != nil:
		if err := packTextField(encoder, "name", attribute.Name); err != nil {
			return err
		}
		if err := packTextField(encoder, "number", *attribute.Number); err != nil {
			return err
		}
	default:
		if err := packTextField(encoder, "name", attribute.Name); err != nil {
			return err
		}
		if err := packTextField(encoder, "string", *attribute.String); err != nil {
			return err
		}
	}
	return encoder.endObject()
}

func writePackTextArray(encoder *canonEncoder, values []string) error {
	if err := encoder.beginArray(); err != nil {
		return err
	}
	for i := range values {
		if err := encoder.text(values[i]); err != nil {
			return err
		}
	}
	return encoder.endArray()
}

func writePackAccess(encoder *canonEncoder, access packAccess) error {
	if err := writePackAccessStart(encoder, access); err != nil {
		return err
	}
	if err := writePackAccessCandidates(encoder, access); err != nil {
		return err
	}
	if err := writePackAccessContext(encoder, access); err != nil {
		return err
	}
	if err := writePackAccessLimits(encoder, access); err != nil {
		return err
	}
	if err := writePackAccessOwnersAndPolicy(encoder, access); err != nil {
		return err
	}
	if err := writePackAccessSelected(encoder, access); err != nil {
		return err
	}
	if err := writePackAccessWitnesses(encoder, access); err != nil {
		return err
	}
	return nil
}

func writePackAccessStart(encoder *canonEncoder, access packAccess) error {
	if len(access.Selected) == 0 {
		return errCanonInvalid
	}
	for i := 1; i < len(access.Candidates); i++ {
		if access.Candidates[i-1].Expectation >= access.Candidates[i].Expectation {
			return errCanonInvalid
		}
	}
	for i := range access.Limits {
		if i > 0 && access.Limits[i-1].Expectation >= access.Limits[i].Expectation {
			return errCanonInvalid
		}
		if !strictlySortedUnique(access.Limits[i].Limits) {
			return errCanonInvalid
		}
	}
	if err := encoder.beginObject(); err != nil {
		return err
	}
	return nil
}

func writePackAccessCandidates(encoder *canonEncoder, access packAccess) error {
	if err := encoder.key("candidates"); err != nil {
		return err
	}
	if err := encoder.beginArray(); err != nil {
		return err
	}
	for i := range access.Candidates {
		if err := writePackCandidate(encoder, access.Candidates[i]); err != nil {
			return err
		}
	}
	if err := encoder.endArray(); err != nil {
		return err
	}
	return nil
}

func writePackAccessContext(encoder *canonEncoder, access packAccess) error {
	if err := packTextField(encoder, "context", access.Context); err != nil {
		return err
	}
	if err := packInstantField(encoder, "evaluated_at", access.EvaluatedAt); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "limit", access.Limit); err != nil {
		return err
	}
	return nil
}

func writePackAccessLimits(encoder *canonEncoder, access packAccess) error {
	if err := encoder.key("limits"); err != nil {
		return err
	}
	if err := encoder.beginArray(); err != nil {
		return err
	}
	for i := range access.Limits {
		if err := writePackLimits(encoder, access.Limits[i]); err != nil {
			return err
		}
	}
	if err := encoder.endArray(); err != nil {
		return err
	}
	return nil
}

func writePackAccessOwnersAndPolicy(encoder *canonEncoder, access packAccess) error {
	if err := encoder.key("owners"); err != nil {
		return err
	}
	if err := encoder.beginArray(); err != nil {
		return err
	}
	for i := range access.Owners {
		if err := writePackOwner(encoder, access.Owners[i]); err != nil {
			return err
		}
	}
	if err := encoder.endArray(); err != nil {
		return err
	}
	if access.PolicyVersion != nil {
		if err := encoder.key("policy_version"); err != nil {
			return err
		}
		if err := writePackToken(encoder, *access.PolicyVersion); err != nil {
			return err
		}
	}
	return nil
}

func writePackAccessSelected(encoder *canonEncoder, access packAccess) error {
	if err := packBooleanField(encoder, "rules_partial", access.RulesPartial); err != nil {
		return err
	}
	if err := encoder.key("selected"); err != nil {
		return err
	}
	if err := writePackTextArray(encoder, access.Selected); err != nil {
		return err
	}
	return nil
}

func writePackAccessWitnesses(encoder *canonEncoder, access packAccess) error {
	if err := encoder.key("witnesses"); err != nil {
		return err
	}
	if err := encoder.beginArray(); err != nil {
		return err
	}
	for i := range access.Witnesses {
		if err := writePackWitness(encoder, access.Witnesses[i]); err != nil {
			return err
		}
	}
	if err := encoder.endArray(); err != nil {
		return err
	}
	return encoder.endObject()
}

func writePackCandidate(encoder *canonEncoder, candidate packCandidate) error {
	if len(candidate.Rules) > maxCandidateRules {
		return errCanonInvalid
	}
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if err := packTextField(encoder, "expectation", candidate.Expectation); err != nil {
		return err
	}
	if candidate.Omitted != 0 {
		if err := packIntegerField(encoder, "omitted", candidate.Omitted); err != nil {
			return err
		}
	}
	if err := encoder.key("rules"); err != nil {
		return err
	}
	if err := encoder.beginArray(); err != nil {
		return err
	}
	for i := range candidate.Rules {
		if err := writePackRule(encoder, candidate.Rules[i]); err != nil {
			return err
		}
	}
	if err := encoder.endArray(); err != nil {
		return err
	}
	return encoder.endObject()
}

func writePackLimits(encoder *canonEncoder, limits packLimits) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if err := packTextField(encoder, "expectation", limits.Expectation); err != nil {
		return err
	}
	if err := encoder.key("limits"); err != nil {
		return err
	}
	if err := writePackTextArray(encoder, limits.Limits); err != nil {
		return err
	}
	return encoder.endObject()
}

func writePackOwner(encoder *canonEncoder, owner packOwner) error {
	if len(owner.Tags) > maxOwnerTags {
		return errCanonInvalid
	}
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if owner.Omitted != 0 {
		if err := packIntegerField(encoder, "omitted", owner.Omitted); err != nil {
			return err
		}
	}
	if err := packTextField(encoder, "source", owner.Source); err != nil {
		return err
	}
	if err := encoder.key("tags"); err != nil {
		return err
	}
	if err := writePackTextArray(encoder, owner.Tags); err != nil {
		return err
	}
	return encoder.endObject()
}

func writePackWitness(encoder *canonEncoder, witness packWitness) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if err := encoder.key("cell"); err != nil {
		return err
	}
	if err := writePackCell(encoder, witness.Cell); err != nil {
		return err
	}
	if err := packTextField(encoder, "expectation", witness.Expectation); err != nil {
		return err
	}
	if err := packTextField(encoder, "observed", witness.Observed); err != nil {
		return err
	}
	if err := encoder.key("proof"); err != nil {
		return err
	}
	if err := writePackProof(encoder, witness.Proof); err != nil {
		return err
	}
	if witness.Reason != "" {
		if err := packTextField(encoder, "reason", witness.Reason); err != nil {
			return err
		}
	}
	return encoder.endObject()
}

func writePackCell(encoder *canonEncoder, cell packCell) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if err := packTextField(encoder, "destination", cell.Destination); err != nil {
		return err
	}
	if err := packTextField(encoder, "expect", cell.Expect); err != nil {
		return err
	}
	if cell.User != "" {
		if err := packTextField(encoder, "user", cell.User); err != nil {
			return err
		}
	}
	return encoder.endObject()
}

func writePackProof(encoder *canonEncoder, proof packProof) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if err := packBooleanField(encoder, "canary", proof.Canary); err != nil {
		return err
	}
	if err := packBooleanField(encoder, "live_unchanged", proof.LiveUnchanged); err != nil {
		return err
	}
	return encoder.endObject()
}

func writePackRule(encoder *canonEncoder, rule packRule) error {
	if err := writePackRuleFlags(encoder, rule); err != nil {
		return err
	}
	if err := writePackRulePosition(encoder, rule); err != nil {
		return err
	}
	if err := writePackRuleSourceAndTraffic(encoder, rule); err != nil {
		return err
	}
	return encoder.endObject()
}

func writePackRuleFlags(encoder *canonEncoder, rule packRule) error {
	if err := encoder.beginObject(); err != nil {
		return err
	}
	if rule.AllTraffic {
		if err := packBooleanField(encoder, "all_traffic", true); err != nil {
			return err
		}
	}
	if rule.Broad {
		if err := packBooleanField(encoder, "broad", true); err != nil {
			return err
		}
	}
	if rule.Column != 0 {
		if err := packIntegerField(encoder, "column", rule.Column); err != nil {
			return err
		}
	}
	return nil
}

func writePackRulePosition(encoder *canonEncoder, rule packRule) error {
	if err := packTextField(encoder, "destination", rule.Destination); err != nil {
		return err
	}
	if err := packIntegerField(encoder, "index", rule.Index); err != nil {
		return err
	}
	if rule.Line != 0 {
		if err := packIntegerField(encoder, "line", rule.Line); err != nil {
			return err
		}
	}
	if rule.Ports != "" {
		if err := packTextField(encoder, "ports", rule.Ports); err != nil {
			return err
		}
	}
	return nil
}

func writePackRuleSourceAndTraffic(encoder *canonEncoder, rule packRule) error {
	if rule.Qualified {
		if err := packBooleanField(encoder, "qualified", true); err != nil {
			return err
		}
	}
	if err := packTextField(encoder, "section", rule.Section); err != nil {
		return err
	}
	if err := packTextField(encoder, "source", rule.Source); err != nil {
		return err
	}
	if rule.Traffic != "" {
		if err := packTextField(encoder, "traffic", rule.Traffic); err != nil {
			return err
		}
	}
	return nil
}

func strictlySortedUnique(values []string) bool {
	for i := 1; i < len(values); i++ {
		if values[i-1] >= values[i] {
			return false
		}
	}
	return true
}

// Field helpers keep key ordering and error propagation with the canonical writer.
func packTextField(encoder *canonEncoder, name, value string) error {
	if err := encoder.key(name); err != nil {
		return err
	}
	return encoder.text(value)
}
func packIntegerField(encoder *canonEncoder, name string, value int) error {
	if err := encoder.key(name); err != nil {
		return err
	}
	return packInt(encoder, value)
}
func packInstantField(encoder *canonEncoder, name string, value time.Time) error {
	if err := encoder.key(name); err != nil {
		return err
	}
	return writePackInstant(encoder, value)
}
func packBooleanField(encoder *canonEncoder, name string, value bool) error {
	if err := encoder.key(name); err != nil {
		return err
	}
	return encoder.boolean(value)
}
