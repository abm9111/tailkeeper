package security

import (
	"context"
	"errors"
	"strings"
	"time"
)

// ReleaseOK reports whether s is a canonical bare release usable as a range bound.
func ReleaseOK(s string) bool { _, ok := parseVersion(s); return ok }

// correctionMatcher validates and indexes a snapshot exactly as Match does.
func correctionMatcher(ctx context.Context, s Snapshot, now time.Time, asset, name string, role VersionRole, budget WorkBudget) (*matcher, *deviceFacts, VersionRole, error) {
	if ctx == nil {
		return nil, nil, "", errors.New("nil context")
	}
	limit, err := budget.limit()
	if err != nil {
		return nil, nil, "", err
	}
	if err = validateMatchSnapshot(s, now); err != nil {
		return nil, nil, "", err
	}
	if strings.TrimSpace(asset) == "" || !ValidText(asset) || strings.TrimSpace(name) == "" || !ValidText(name) {
		return nil, nil, "", errors.New("invalid target text")
	}
	if role == "" {
		role = VersionRunningDaemon
	}
	if !validRole(role) {
		return nil, nil, "", errors.New("invalid version role")
	}
	m := &matcher{w: matchWork{ctx: ctx, limit: limit}, s: s, now: now}
	if err = ctx.Err(); err != nil {
		return nil, nil, "", err
	}
	if err = m.indexDevices(); err != nil {
		return nil, nil, "", err
	}
	d := m.byDevice[asset]
	if d == nil {
		d = &deviceFacts{connectedAt: -1}
	}
	return m, d, role, nil
}

// JudgeVersion applies the same selection and release comparison as Match.
func JudgeVersion(ctx context.Context, s Snapshot, now time.Time, asset, component string, role VersionRole, atLeast string, budget WorkBudget) (FactJudgement, error) {
	bound, ok := parseVersion(atLeast)
	if !ok {
		return FactJudgement{}, errors.New("invalid minimum release")
	}
	m, d, role, err := correctionMatcher(ctx, s, now, asset, component, role, budget)
	if err != nil {
		return FactJudgement{}, err
	}
	choice, err := m.selectVersion(AdvisoryRecord{Component: component, VersionRole: role}, asset, d)
	if err != nil {
		return FactJudgement{}, err
	}
	if choice.failure != nil {
		return FactJudgement{Verdict: FactUnobserved, Reason: choice.failure.reason, Evidence: choice.failure.evidence}, nil
	}
	// Match charges a step for the range comparison as well.
	if err = m.w.step(); err != nil {
		return FactJudgement{}, err
	}
	if compareVersions(choice.release, bound) < 0 {
		reason := UnknownReason("")
		if !choice.exact {
			reason = ReasonRuntimeUnobserved
		}
		return FactJudgement{Verdict: FactContradicted, Reason: reason, Evidence: choice.evidence}, nil
	}
	if !choice.exact {
		return FactJudgement{Verdict: FactUnobserved, Reason: ReasonRuntimeUnobserved, Evidence: choice.evidence}, nil
	}
	return FactJudgement{Verdict: FactSatisfied, Evidence: choice.evidence}, nil
}

// JudgeFeature applies the matcher's feature and connection-guard selection.
func JudgeFeature(ctx context.Context, s Snapshot, now time.Time, asset, name string, role VersionRole, want bool, budget WorkBudget) (FactJudgement, error) {
	if name == FeatureConnectedToControl {
		return FactJudgement{}, errors.New("connection guard cannot be an expected feature")
	}
	m, d, role, err := correctionMatcher(ctx, s, now, asset, name, role, budget)
	if err != nil {
		return FactJudgement{}, err
	}
	r := AdvisoryRecord{VersionRole: role, RequiredFeatures: []string{name}}
	states, evidence, err := m.featureStates(r, map[string]int{name: 0}, asset, d, nil)
	if err != nil {
		return FactJudgement{}, err
	}
	st := states[0]
	if st.on == st.off {
		return FactJudgement{Verdict: FactUnobserved, Reason: ReasonFeatureUnknown, Evidence: evidence}, nil
	}
	verdict := FactContradicted
	if st.on == want {
		verdict = FactSatisfied
	}
	return FactJudgement{Verdict: verdict, Evidence: evidence}, nil
}
