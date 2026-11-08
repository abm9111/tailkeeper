package security

import (
	"errors"
	"slices"
	"time"
)

// This file holds what a producer of snapshots needs from the contracts: the channel a
// release belongs to, the checks a snapshot and its text must pass, and the record a
// collection makes of each source it reads. It reads no clock and calls no source.

// ChannelOf is the channel of a version string as its release says: stable for an even
// minor, unstable for an odd one, and unknown for a string outside the release grammar (see
// parseRelease). A producer sets VersionFact.Channel from it and keeps the raw string.
func ChannelOf(version string) VersionChannel {
	v, ok := parseRelease(version)
	switch {
	case !ok:
		return ChannelUnknown
	case v[1]%2 != 0:
		return ChannelUnstable
	}
	return ChannelStable
}

// ValidText reports whether s may appear in a snapshot, a catalog or a report: at most
// MaxTextBytes of valid UTF-8 with no control, invisible or misleading character. A producer
// checks the strings a source gave it with this, because one string that fails makes the
// whole snapshot invalid.
func ValidText(s string) bool { return validateString(s) == nil }

// ValidateSnapshot applies to a snapshot the checks Match applies before it judges anything,
// as of the evaluation time now. A snapshot that passes can be matched.
func ValidateSnapshot(s Snapshot, now time.Time) error { return validateMatchSnapshot(s, now) }

// RequiredFeatures lists the features that the approved and pending rules of c require, each
// once, in name order. A withdrawn rule is not evaluated and so requires nothing. A producer
// passes it to its collection, which cannot know which features the rules in use need and so
// cannot otherwise say whether its coverage of them is complete.
func RequiredFeatures(c Catalog) []string {
	var names []string
	for _, r := range c.Records {
		if r.ReviewState != ReviewWithdrawn {
			names = append(names, r.RequiredFeatures...)
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// CollectionSource names a source a collection reads. The set is closed: a collection reads
// each source by a fixed operation, and the audit record names it by this value alone.
type CollectionSource string

const (
	// SourceAPIDevices is the API's device list (fleet scope only).
	SourceAPIDevices CollectionSource = "api_devices"
	// SourceLocalStatus is this node's status, which names the node.
	SourceLocalStatus CollectionSource = "local_status"
	// SourceLocalVersion is the versions of this node's CLI and daemon.
	SourceLocalVersion CollectionSource = "local_version"
	// SourceLocalPrefs is this node's preferences.
	SourceLocalPrefs CollectionSource = "local_prefs"
	// SourceValidateNetwork and SourceValidateSSH are the validation requests of an access
	// explanation (`security explain`): the one that carries its network tests and the one that
	// carries its SSH tests. They are not read by a collection, and the audit record of each names
	// nothing of the policy or of the expectations asked about.
	SourceValidateNetwork CollectionSource = "validate_network"
	SourceValidateSSH     CollectionSource = "validate_ssh"
)

// CollectionPhase says which half of a source's record an event is: the attempt, written
// before the source is asked, or the outcome, written after.
type CollectionPhase string

const (
	PhaseAttempt CollectionPhase = "attempt"
	PhaseOutcome CollectionPhase = "outcome"
)

// CollectionOutcome is how a source ended. A source that was not asked has the outcome
// skipped, and no attempt.
type CollectionOutcome string

const (
	// OutcomeOK: the source was read completely.
	OutcomeOK CollectionOutcome = "ok"
	// OutcomeTruncated: the source was read and some of it is not in the snapshot (a bound).
	OutcomeTruncated CollectionOutcome = "truncated"
	// OutcomeError: the source failed; Code says how.
	OutcomeError CollectionOutcome = "error"
	// OutcomeCancelled: the caller cancelled the run while the source was being read.
	OutcomeCancelled CollectionOutcome = "cancelled"
	// OutcomeTimeout: the collection's own time budget ended while the source was being read.
	OutcomeTimeout CollectionOutcome = "timeout"
	// OutcomeSkipped: the source was not asked; Code says why.
	OutcomeSkipped CollectionOutcome = "skipped"
)

// Reasons a source is skipped (the Code of a skipped outcome).
const (
	SkipBudget   = "budget_exhausted"
	SkipCancel   = "cancelled"
	SkipIdentity = "identity_unknown"
)

// maxCollectionCount bounds the counts and the time of a collection event; larger values
// are not a count of anything a collection can hold.
const (
	maxCollectionCount = 1 << 20
	maxCollectionMs    = int64(24 * time.Hour / time.Millisecond)
	maxCollectionCode  = 48
)

// SaturateCount limits a count to what a collection event takes (it is not negative and not
// above the bound the event validator accepts). A list longer than the bound is a count of
// the bound: the number still says that items were left out, and the event stays valid, so a
// big list is a gap in the record and not an error of the program.
func SaturateCount(n int) int { return min(max(n, 0), maxCollectionCount) }

// CollectionEvent is the record of one source in one collection: its attempt, before the
// source is asked, and its outcome. It carries no text from the source, and none from the
// caller either: the caller, the tool and the call it belongs to are known to the framework,
// which adds them where the event is recorded.
type CollectionEvent struct {
	Scope    Scope
	Source   CollectionSource
	Phase    CollectionPhase
	Outcome  CollectionOutcome // set for the outcome phase only
	Code     string            // lower-case words and underscores: the program's error code of a failed source, or the reason a source was skipped
	Observed int               // devices or facts the source gave (outcome only)
	Dropped  int               // items the source gave that the snapshot does not hold (outcome only)
	Millis   int64             // how long the source took (outcome only)
}

// Validate refuses an event that is not one of the closed forms above.
func (e CollectionEvent) Validate() error {
	switch {
	case e.Scope != ScopeLocal && e.Scope != ScopeFleet:
		return errors.New("collection event scope must be local or fleet")
	case !e.Source.valid():
		return errors.New("unknown collection source")
	}
	switch e.Phase {
	case PhaseAttempt:
		if e.Outcome != "" || e.Code != "" || e.Observed != 0 || e.Dropped != 0 || e.Millis != 0 {
			return errors.New("an attempt carries no outcome")
		}
		return nil
	case PhaseOutcome:
		return e.validateOutcome()
	}
	return errors.New("unknown collection phase")
}

func (s CollectionSource) valid() bool {
	switch s {
	case SourceAPIDevices, SourceLocalStatus, SourceLocalVersion, SourceLocalPrefs, SourceValidateNetwork, SourceValidateSSH:
		return true
	}
	return false
}

func (e CollectionEvent) validateOutcome() error {
	switch e.Outcome {
	case OutcomeOK, OutcomeTruncated, OutcomeCancelled, OutcomeTimeout:
		if e.Code != "" {
			return errors.New("only a failed or skipped source has a code")
		}
	case OutcomeError, OutcomeSkipped:
		if !codeShaped(e.Code) {
			return errors.New("a failed or skipped source needs a code of lower-case words")
		}
	default:
		return errors.New("unknown collection outcome")
	}
	switch {
	case e.Observed < 0 || e.Observed > maxCollectionCount || e.Dropped < 0 || e.Dropped > maxCollectionCount:
		return errors.New("collection counts are out of range")
	case e.Millis < 0 || e.Millis > maxCollectionMs:
		return errors.New("collection time is out of range")
	}
	return nil
}

// codeShaped reports whether c is one to maxCollectionCode lower-case letters and
// underscores, starting with a letter: the shape of the program's error codes.
func codeShaped(c string) bool {
	if c == "" || len(c) > maxCollectionCode || c[0] < 'a' || c[0] > 'z' {
		return false
	}
	for i := 0; i < len(c); i++ {
		if (c[i] < 'a' || c[i] > 'z') && c[i] != '_' {
			return false
		}
	}
	return true
}
