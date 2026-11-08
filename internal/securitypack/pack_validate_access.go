package securitypack

import "github.com/abm9111/tailkeeper/internal/security"

type witnessKey struct {
	id   string
	cell security.AccessCell
}

func validPackRule(value packRule) bool {
	if value.Section != "acls" && value.Section != "grants" && value.Section != "ssh" {
		return false
	}
	if value.Index < 1 || value.Line < 0 || value.Column < 0 || value.Broad != (value.Destination == "*") {
		return false
	}
	return !(value.AllTraffic && value.Traffic != "") && !(value.Ports != "" && value.Traffic == "")
}

func checkPackAccess(value *packAccess, snapshot packSnapshot, full *security.IntentSet) error {
	if value == nil {
		return nil
	}
	if !validFleetContext(value.Context) || (snapshot.Scope == "fleet" && value.Context != snapshot.Context) || !validPackTime(value.EvaluatedAt) {
		return ErrInvalidPack
	}
	if value.Limit < 0 || value.Limit > security.MaxAccessPairs || len(value.Witnesses) > security.MaxAccessPairs || !validPolicyToken(value.PolicyVersion) {
		return ErrInvalidPack
	}
	selected, err := selectPackIntent(full, value.Selected)
	if err != nil {
		return err
	}
	if _, err := accessFromPack(value, full); err != nil {
		return err
	}
	plan := security.PlanAccess(*selected, value.Limit)
	cells := make(map[witnessKey]bool)
	selectedIDs := make(map[string]bool)
	judged := make(map[string]bool)
	for _, expectation := range plan {
		selectedIDs[expectation.ID] = true
		for _, cell := range expectation.Cells {
			cells[witnessKey{expectation.ID, cell}] = true
			judged[expectation.ID] = true
		}
	}
	if err := checkPackWitnesses(value.Witnesses, cells); err != nil {
		return err
	}
	return checkPackAccessLists(value, selectedIDs, judged)
}

func checkPackWitnesses(values []packWitness, cells map[witnessKey]bool) error {
	seen := make(map[witnessKey]bool)
	for _, w := range values {
		key := witnessKey{w.Expectation, security.AccessCell{Destination: w.Cell.Destination, Expect: w.Cell.Expect, User: w.Cell.User}}
		if !cells[key] || seen[key] {
			return ErrInvalidPack
		}
		if w.Observed != "allowed" && w.Observed != "denied" && w.Observed != "unknown" && w.Observed != "not_asked" {
			return ErrInvalidPack
		}
		if w.Reason != "" && security.ReasonSentence(security.AccessReason(w.Reason)) == "" {
			return ErrInvalidPack
		}
		seen[key] = true
	}
	return nil
}

func checkPackAccessLists(value *packAccess, selected, judged map[string]bool) error {
	for _, c := range value.Candidates {
		if !judged[c.Expectation] || len(c.Rules) > maxCandidateRules || c.Omitted < 0 || c.Omitted > 1<<31 {
			return ErrInvalidPack
		}
		for _, r := range c.Rules {
			if !validPackRule(r) {
				return ErrInvalidPack
			}
		}
	}
	return checkPackLimitsOwners(value, selected)
}

func checkPackLimitsOwners(value *packAccess, selected map[string]bool) error {
	for _, l := range value.Limits {
		if !selected[l.Expectation] {
			return ErrInvalidPack
		}
		previous := ""
		for i, item := range l.Limits {
			if (i > 0 && item <= previous) || security.LimitSentence(security.AccessLimit(item)) == "" {
				return ErrInvalidPack
			}
			previous = item
		}
	}
	for _, owner := range value.Owners {
		if len(owner.Tags) > maxOwnerTags || owner.Omitted < 0 || owner.Omitted > 1<<31 {
			return ErrInvalidPack
		}
	}
	return nil
}
