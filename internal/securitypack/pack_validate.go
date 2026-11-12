package securitypack

import (
	"time"
	"unicode/utf8"

	"github.com/abm9111/tailkeeper/internal/security"
)

func validPackTime(value time.Time) bool {
	_, offset := value.Zone()
	return !value.IsZero() && value.Year() >= 2019 && value.Year() <= 9999 && offset == 0
}

func validFleetContext(value string) bool {
	if len(value) != 20 || value[:4] != "ctx-" {
		return false
	}
	for _, c := range value[4:] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validSnapshotContext(value packSnapshot) bool {
	switch security.Scope(value.Scope) {
	case security.ScopeLocal:
		return value.Context == security.ContextLocalOnly
	case security.ScopeFleet:
		return validFleetContext(value.Context)
	default:
		return false
	}
}

func validPackEvidence(value packEvidence, snapshot packSnapshot) bool {
	if value.Context != snapshot.Context || value.Scope != snapshot.Scope || !validPackTime(value.AcquiredAt) {
		return false
	}
	if value.ObservedAt != nil && !validPackTime(*value.ObservedAt) {
		return false
	}
	return utf8.RuneCountInString(value.Asset) <= 128 && len(value.Error) <= 256
}

func checkPackEvidence(snapshot packSnapshot) error {
	for _, fact := range snapshot.Versions {
		if !validPackEvidence(fact.Evidence, snapshot) {
			return ErrInvalidPack
		}
	}
	for _, fact := range snapshot.Platforms {
		if !validPackEvidence(fact.Evidence, snapshot) {
			return ErrInvalidPack
		}
	}
	for _, fact := range snapshot.Features {
		if !validPackEvidence(fact.Evidence, snapshot) {
			return ErrInvalidPack
		}
	}
	for _, fact := range snapshot.Policies {
		if !validPackEvidence(fact.Evidence, snapshot) {
			return ErrInvalidPack
		}
	}
	return nil
}

func checkPackSnapshot(snapshot packSnapshot, evaluation time.Time) error {
	if !validPackTime(evaluation) || !validPackTime(snapshot.ObservedAt) || !validSnapshotContext(snapshot) {
		return ErrInvalidPack
	}
	if err := checkPackEvidence(snapshot); err != nil {
		return err
	}
	if err := security.ValidateSnapshot(snapshotFromPack(snapshot), evaluation); err != nil {
		return ErrInvalidPack
	}
	return nil
}

func countsMatch(total int, counts ...int) bool {
	if total < 0 {
		return false
	}
	remaining := total
	for _, value := range counts {
		if value < 0 || value > remaining {
			return false
		}
		remaining -= value
	}
	return remaining == 0
}

func countPackDevices(value packSnapshot) int {
	assets := make(map[string]struct{})
	add := func(e packEvidence) {
		if e.Asset != "" {
			assets[e.Asset] = struct{}{}
		}
	}
	for _, v := range value.Versions {
		add(v.Evidence)
	}
	for _, v := range value.Platforms {
		add(v.Evidence)
	}
	for _, v := range value.Features {
		add(v.Evidence)
	}
	for _, v := range value.Policies {
		add(v.Evidence)
	}
	return len(assets)
}

func checkPackExpected(value packBody) error {
	c, s, r := value.Expected.Counts, value.Snapshot, value.Expected.Report
	if c.Devices != countPackDevices(s) || c.Features != len(s.Features) || c.Platforms != len(s.Platforms) || c.Policies != len(s.Policies) || c.Versions != len(s.Versions) {
		return ErrInvalidPack
	}
	if !lowerHex64(r.SHA256) || (r.Status != "complete" && r.Status != "partial") || !countsMatch(r.TotalFindings, r.Affected, r.NotAffected, r.PotentiallyAffected, r.Unknown) {
		return ErrInvalidPack
	}
	if (value.Access == nil) != (value.Expected.Access == nil) {
		return ErrInvalidPack
	}
	return checkPackExpectedAccess(value.Expected.Access)
}

func checkPackExpectedAccess(value *packExpectedAccess) error {
	if value == nil {
		return nil
	}
	if !lowerHex64(value.SHA256) || (value.Status != "complete" && value.Status != "incomplete") {
		return ErrInvalidPack
	}
	if !countsMatch(value.Total, value.Met, value.MetWithLimits, value.NotEvaluated, value.Unknown, value.Unmet) {
		return ErrInvalidPack
	}
	if value.Status == "complete" && (value.Total == 0 || value.Met != value.Total) {
		return ErrInvalidPack
	}
	return nil
}

func checkPackCoverage(value packBody) error {
	if len(value.Collected) > 2 {
		return ErrInvalidPack
	}
	seen := make(map[string]bool)
	for _, row := range value.Collected {
		if row.Context != value.Snapshot.Context || row.Target.Scope != value.Snapshot.Scope || (row.Target.Dimension != "versions" && row.Target.Dimension != "features") || seen[row.Target.Dimension] {
			return ErrInvalidPack
		}
		if row.Status != "complete" && row.Status != "partial" {
			return ErrInvalidPack
		}
		if row.Counts != nil && !coverageCountsNonnegative(*row.Counts) {
			return ErrInvalidPack
		}
		seen[row.Target.Dimension] = true
	}
	return nil
}

func coverageCountsNonnegative(c packCoverageCounts) bool {
	return c.Assets >= 0 && c.Findings >= 0 && c.Potential >= 0 && c.Rules >= 0 && c.Unknown >= 0 && c.Withdrawn >= 0
}
