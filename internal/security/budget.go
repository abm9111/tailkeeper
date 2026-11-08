package security

import "errors"

const MaxCandidates = 250000

var ErrWorkBudget = errors.New("advisory work budget exhausted")

// ErrInvalidBudget is returned by Match for a negative budget, or one above MaxCandidates. A
// budget is never clamped: the caller asked for something Match will not do.
var ErrInvalidBudget = errors.New("invalid advisory work budget")

// WorkBudget limits record/observation comparisons. Zero uses the hard maximum, MaxCandidates;
// a negative value, or one above it, is invalid (ErrInvalidBudget).
type WorkBudget struct{ Candidates int }

// limit is the number of steps a run may take: MaxCandidates for the zero budget, the budget
// itself within 0 to MaxCandidates, and an error outside it (never a clamped value).
func (b WorkBudget) limit() (int, error) {
	switch {
	case b.Candidates == 0:
		return MaxCandidates, nil
	case b.Candidates < 0 || b.Candidates > MaxCandidates:
		return 0, ErrInvalidBudget
	}
	return b.Candidates, nil
}
