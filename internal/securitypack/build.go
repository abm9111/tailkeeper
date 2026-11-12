package securitypack

import (
	"context"
	"strings"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/security"
)

// BuildInput contains the exact scan inputs and the report already produced by Evaluate.
type BuildInput struct {
	Input   security.Input
	Report  security.Report
	Sources []advisory.Source
	Access  *AccessEvidence
}

// AccessEvidence binds selected intent to its separately collected access evidence.
type AccessEvidence struct {
	Context  string
	Selected []string
	Input    security.AccessInput
}

// Build records the decision and returns bytes only after decoding and reproducing it.
func Build(ctx context.Context, in BuildInput, seal Sealer) ([]byte, Replayed, error) {
	if ctx == nil || security.ValidateSnapshot(in.Input.Snapshot, in.Input.Now) != nil || security.ValidateReport(in.Report) != nil || !sameSnapshot(in.Input.Snapshot, in.Report.Snapshot) {
		return nil, Replayed{}, ErrInvalidPack
	}
	if security.StoppedEarly(in.Report) {
		return nil, Replayed{}, ErrStoppedEarly
	}
	expected, err := expectedReport(in.Input.Snapshot, in.Report)
	if err != nil {
		return nil, Replayed{}, err
	}
	intentForm, err := digestForm(in.Input.Intent)
	if err != nil {
		return nil, Replayed{}, err
	}
	pi := packInput{Snapshot: in.Input.Snapshot, Sources: in.Sources, CatalogDigest: in.Input.Catalog.Digest,
		Collected: in.Input.Collected, EvaluationAt: in.Input.Now, WorkBudget: in.Input.Budget,
		EvaluatorVersion: security.EvaluatorVersion, Intent: in.Input.Intent, IntentDigestForm: intentForm, Expected: expected}
	if err := addBuildAccess(&pi, in.Access); err != nil {
		return nil, Replayed{}, err
	}
	pack, err := newPack(pi, seal)
	if err != nil {
		return nil, Replayed{}, err
	}
	data, err := Encode(pack)
	if err != nil {
		return nil, Replayed{}, err
	}
	decoded, _, err := Decode(data, seal)
	if err != nil {
		return nil, Replayed{}, err
	}
	replayed, err := Replay(ctx, decoded, security.WorkBudget{})
	if err != nil {
		return nil, Replayed{}, err
	}
	if replayed.Reproduction.Status != "reproduced" {
		return nil, Replayed{}, ErrNotReproduced
	}
	return data, replayed, nil
}

func addBuildAccess(pi *packInput, evidence *AccessEvidence) error {
	if evidence == nil {
		return nil
	}
	form, err := policyForm(evidence.Input.PolicyVersion)
	if err != nil {
		return err
	}
	pi.Access = &accessInput{Context: evidence.Context, Selected: evidence.Selected, Input: evidence.Input, PolicyVersionForm: form}
	access, _, err := security.JudgeAccess(evidence.Input)
	if err != nil {
		return ErrInvalidPack
	}
	summary, err := expectedAccess(access)
	if err != nil {
		return err
	}
	pi.Expected.Access = &summary
	return nil
}

func digestForm(intent *security.IntentSet) (tokenForm, error) {
	if intent == nil || intent.Digest == "" {
		return "", nil
	}
	if strictDigest(intent.Digest, "sha256:") {
		return tokenForm("plain"), nil
	}
	if strictDigest(intent.Digest, "hmac-sha256:") {
		return tokenForm("keyed"), nil
	}
	return "", ErrInvalidPack
}

func policyForm(token string) (tokenForm, error) {
	if token == "" {
		return "", nil
	}
	if validPlainPolicyToken(token) {
		return tokenForm("plain"), nil
	}
	if strictDigest(token, "hmac-sha256:") {
		return tokenForm("keyed"), nil
	}
	return "", ErrInvalidPack
}

func strictDigest(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	for _, c := range value[len(prefix):] {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// sameSnapshot binds the report field intentionally omitted from the report hash.
func sameSnapshot(a, b security.Snapshot) bool {
	if a.Context != b.Context || a.KeyEpoch != b.KeyEpoch || a.Scope != b.Scope || !a.ObservedAt.Equal(b.ObservedAt) {
		return false
	}
	return sameVersions(a.Versions, b.Versions) && samePlatforms(a.Platforms, b.Platforms) && sameFeatures(a.Features, b.Features) && samePolicies(a.Policies, b.Policies)
}
func sameVersions(a, b []security.VersionFact) bool {
	if len(a) != len(b) {
		return false
	}
	for i, x := range a {
		y := b[i]
		if x.Role != y.Role || x.Channel != y.Channel || x.Name != y.Name || !sameString(x.Value, y.Value) || !sameEvidence(x.Evidence, y.Evidence) {
			return false
		}
	}
	return true
}
func samePlatforms(a, b []security.PlatformFact) bool {
	if len(a) != len(b) {
		return false
	}
	for i, x := range a {
		y := b[i]
		if x.OS != y.OS || x.Variant != y.Variant || !sameEvidence(x.Evidence, y.Evidence) {
			return false
		}
	}
	return true
}
func sameFeatures(a, b []security.FeatureFact) bool {
	if len(a) != len(b) {
		return false
	}
	for i, x := range a {
		y := b[i]
		if x.Name != y.Name || !sameBool(x.Value, y.Value) || !sameEvidence(x.Evidence, y.Evidence) {
			return false
		}
	}
	return true
}
func samePolicies(a, b []security.PolicyFact) bool {
	if len(a) != len(b) {
		return false
	}
	for i, x := range a {
		y := b[i]
		if x.Name != y.Name || !sameString(x.Value, y.Value) || !sameEvidence(x.Evidence, y.Evidence) {
			return false
		}
	}
	return true
}
func sameString(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
func sameBool(a, b *bool) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
func sameEvidence(a, b security.EvidenceRef) bool {
	if a.Context != b.Context || a.Asset != b.Asset || a.Scope != b.Scope || a.Origin != b.Origin || !a.AcquiredAt.Equal(b.AcquiredAt) || a.Freshness != b.Freshness || a.Error != b.Error {
		return false
	}
	if a.ObservedAt == nil || b.ObservedAt == nil {
		return a.ObservedAt == nil && b.ObservedAt == nil
	}
	return a.ObservedAt.Equal(*b.ObservedAt)
}
