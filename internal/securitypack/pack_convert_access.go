package securitypack

import (
	"slices"

	"github.com/abm9111/tailkeeper/internal/security"
)

func selectPackIntent(full *security.IntentSet, selected []string) (*security.IntentSet, error) {
	if full == nil || len(selected) == 0 {
		return nil, ErrInvalidPack
	}
	wanted := make(map[string]bool, len(selected))
	for _, id := range selected {
		if wanted[id] {
			return nil, ErrInvalidPack
		}
		wanted[id] = true
	}
	out := &security.IntentSet{SchemaVersion: full.SchemaVersion, Revision: full.Revision, Digest: full.Digest}
	for _, n := range full.Network {
		if wanted[n.ID] {
			out.Network = append(out.Network, n)
			delete(wanted, n.ID)
		}
	}
	for _, s := range full.SSH {
		if wanted[s.ID] {
			out.SSH = append(out.SSH, s)
			delete(wanted, s.ID)
		}
	}
	if len(wanted) != 0 {
		return nil, ErrInvalidPack
	}
	// The wire round-trip makes every nested map and slice owned.
	// Form has no bearing on selection; this temporary marker is never emitted.
	var form tokenForm
	if out.Digest != "" {
		form = "plain"
	}
	wire, err := intentToPack(out, form)
	if err != nil {
		return nil, err
	}
	copy, _, err := intentFromPack(wire)
	return copy, err
}

func sameIntent(a, b security.IntentSet) bool {
	if a.SchemaVersion != b.SchemaVersion || a.Revision != b.Revision || a.Digest != b.Digest {
		return false
	}
	if !slices.EqualFunc(a.Network, b.Network, sameNetwork) {
		return false
	}
	return slices.EqualFunc(a.SSH, b.SSH, sameSSH)
}

func sameNetwork(a, b security.NetworkExpectation) bool {
	if a.ID != b.ID || a.Source != b.Source || a.Protocol != b.Protocol || !slices.Equal(a.Accept, b.Accept) || !slices.Equal(a.Deny, b.Deny) || len(a.SourcePostureAttributes) != len(b.SourcePostureAttributes) {
		return false
	}
	for k, v := range a.SourcePostureAttributes {
		if other, ok := b.SourcePostureAttributes[k]; !ok || v != other {
			return false
		}
	}
	return true
}

func sameSSH(a, b security.SSHExpectation) bool {
	return a.ID == b.ID && a.Source == b.Source && slices.Equal(a.Destinations, b.Destinations) && slices.Equal(a.Accept, b.Accept) && slices.Equal(a.Check, b.Check) && slices.Equal(a.Deny, b.Deny)
}

func ruleToPack(v security.RuleRef) packRule {
	return packRule{AllTraffic: v.AllTraffic, Broad: v.Broad, Column: v.Column, Destination: v.Destination, Index: v.Index, Line: v.Line, Ports: v.Ports, Qualified: v.Qualified, Section: v.Section, Source: v.Source, Traffic: v.Traffic}
}

func ruleFromPack(v packRule) security.RuleRef {
	return security.RuleRef{AllTraffic: v.AllTraffic, Broad: v.Broad, Column: v.Column, Destination: v.Destination, Index: v.Index, Line: v.Line, Ports: v.Ports, Qualified: v.Qualified, Section: v.Section, Source: v.Source, Traffic: v.Traffic}
}

func normalizedOmitted(omitted, count, keep int) (int, error) {
	const max = 1 << 31
	if omitted < 0 || omitted > max {
		return 0, ErrInvalidPack
	}
	extra := count - keep
	if extra > max-omitted {
		return 0, ErrInvalidPack
	}
	return omitted + extra, nil
}

func candidatesToPack(input map[string]security.AccessCandidates) ([]packCandidate, error) {
	names := make([]string, 0, len(input))
	for name := range input {
		names = append(names, name)
	}
	slices.Sort(names)
	out := make([]packCandidate, 0, len(names))
	for _, name := range names {
		entry := input[name]
		keep := min(len(entry.Rules), maxCandidateRules)
		omitted, err := normalizedOmitted(entry.Omitted, len(entry.Rules), keep)
		if err != nil {
			return nil, err
		}
		c := packCandidate{Expectation: name, Omitted: omitted, Rules: make([]packRule, 0, keep)}
		for _, rule := range entry.Rules[:keep] {
			c.Rules = append(c.Rules, ruleToPack(rule))
		}
		out = append(out, c)
	}
	return out, nil
}

func ownersToPack(input []security.AccessOwner) ([]packOwner, error) {
	out := make([]packOwner, 0, len(input))
	for _, owner := range input {
		keep := min(len(owner.Tags), maxOwnerTags)
		omitted, err := normalizedOmitted(owner.Omitted, len(owner.Tags), keep)
		if err != nil {
			return nil, err
		}
		out = append(out, packOwner{Source: owner.Source, Omitted: omitted, Tags: slices.Clone(owner.Tags[:keep])})
	}
	return out, nil
}

func limitsToPack(input map[string][]security.AccessLimit) []packLimits {
	names := make([]string, 0, len(input))
	for name := range input {
		names = append(names, name)
	}
	slices.Sort(names)
	out := make([]packLimits, 0, len(names))
	for _, name := range names {
		values := make([]string, 0, len(input[name]))
		for _, value := range input[name] {
			values = append(values, string(value))
		}
		slices.Sort(values)
		out = append(out, packLimits{Expectation: name, Limits: slices.Compact(values)})
	}
	return out
}

func accessToPack(value *accessInput, full *security.IntentSet) (*packAccess, error) {
	if value == nil {
		return nil, nil
	}
	selected, err := selectPackIntent(full, value.Selected)
	if err != nil || value.Input.NoIntent || !sameIntent(*selected, value.Input.Intent) {
		return nil, ErrInvalidPack
	}
	candidates, err := candidatesToPack(value.Input.Candidates)
	if err != nil {
		return nil, err
	}
	owners, err := ownersToPack(value.Input.Owners)
	if err != nil {
		return nil, err
	}
	out := &packAccess{Candidates: candidates, Context: value.Context, EvaluatedAt: value.Input.EvaluatedAt.UTC().Round(0), Limit: value.Input.Limit, Limits: limitsToPack(value.Input.Limits), Owners: owners, RulesPartial: value.Input.RulesPartial, Selected: slices.Clone(value.Selected)}
	if value.Input.PolicyVersion != "" {
		out.PolicyVersion = &packToken{Form: value.PolicyVersionForm, Value: value.Input.PolicyVersion}
	} else if value.PolicyVersionForm != "" {
		return nil, ErrInvalidPack
	}
	for _, w := range value.Input.Witnesses {
		out.Witnesses = append(out.Witnesses, packWitness{Cell: packCell{Destination: w.Cell.Destination, Expect: w.Cell.Expect, User: w.Cell.User}, Expectation: w.Expectation, Observed: string(w.Observed), Proof: packProof{Canary: w.Proof.Canary, LiveUnchanged: w.Proof.LiveUnchanged}, Reason: string(w.Reason)})
	}
	return out, nil
}

func accessFromPack(value *packAccess, full *security.IntentSet) (*accessInput, error) {
	if value == nil {
		return nil, nil
	}
	selected, err := selectPackIntent(full, value.Selected)
	if err != nil {
		return nil, err
	}
	out := &accessInput{Context: value.Context, Selected: slices.Clone(value.Selected)}
	out.Input.Intent = *selected
	out.Input.EvaluatedAt = value.EvaluatedAt
	out.Input.Limit, out.Input.RulesPartial = value.Limit, value.RulesPartial
	if value.PolicyVersion != nil {
		out.Input.PolicyVersion, out.PolicyVersionForm = value.PolicyVersion.Value, value.PolicyVersion.Form
	}
	for _, w := range value.Witnesses {
		out.Input.Witnesses = append(out.Input.Witnesses, security.AccessWitness{Cell: security.AccessCell{Destination: w.Cell.Destination, Expect: w.Cell.Expect, User: w.Cell.User}, Expectation: w.Expectation, Observed: security.AccessObserved(w.Observed), Proof: security.AccessProof{Canary: w.Proof.Canary, LiveUnchanged: w.Proof.LiveUnchanged}, Reason: security.AccessReason(w.Reason)})
	}
	if err := accessMapsFromPack(value, &out.Input); err != nil {
		return nil, err
	}
	for _, owner := range value.Owners {
		out.Input.Owners = append(out.Input.Owners, security.AccessOwner{Source: owner.Source, Omitted: owner.Omitted, Tags: slices.Clone(owner.Tags)})
	}
	return out, nil
}

func accessMapsFromPack(value *packAccess, out *security.AccessInput) error {
	out.Candidates = make(map[string]security.AccessCandidates, len(value.Candidates))
	previous := ""
	for i, c := range value.Candidates {
		if i > 0 && c.Expectation <= previous {
			return ErrInvalidPack
		}
		rules := make([]security.RuleRef, 0, len(c.Rules))
		for _, r := range c.Rules {
			rules = append(rules, ruleFromPack(r))
		}
		out.Candidates[c.Expectation] = security.AccessCandidates{Rules: rules, Omitted: c.Omitted}
		previous = c.Expectation
	}
	out.Limits = make(map[string][]security.AccessLimit, len(value.Limits))
	previous = ""
	for i, l := range value.Limits {
		if i > 0 && l.Expectation <= previous {
			return ErrInvalidPack
		}
		limits := make([]security.AccessLimit, 0, len(l.Limits))
		for _, item := range l.Limits {
			limits = append(limits, security.AccessLimit(item))
		}
		out.Limits[l.Expectation] = limits
		previous = l.Expectation
	}
	return nil
}
