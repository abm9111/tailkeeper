package security

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"
)

// ValidateReport checks the bounds, schema, context, evidence, finding identity and
// coverage of a report before it is used. It does not assert that the observations are
// true or current. Every check has its own error text, so a caller (and a test) can tell
// which one refused a report.
//
// The checks run in this order: the header and the limits, the text and time checks
// shared with the catalog, the snapshot's facts, the findings, and the coverage rows.
func ValidateReport(r Report) error {
	if err := validateReportHeader(r); err != nil {
		return err
	}
	if err := validateText(reflect.ValueOf(r)); err != nil {
		return err
	}
	if err := validateSnapshotFacts(r); err != nil {
		return err
	}
	if err := validateFindings(r); err != nil {
		return err
	}
	return validateCoverage(r)
}

// validateReportHeader checks the schema, the context, the times that bind the snapshot
// to the report, the status, the finding total and the size limits. A negative total needs
// no check of its own: an untruncated report must total its findings, and a truncated one
// must total more than them, so neither accepts a total below zero.
func validateReportHeader(r Report) error {
	if err := validateReportIdentity(r); err != nil {
		return err
	}
	if err := validateReportTotals(r); err != nil {
		return err
	}
	return validateReportLimits(r)
}

// validateReportIdentity checks the schema, the context, the times that bind the snapshot
// to the report, and the status.
func validateReportIdentity(r Report) error {
	switch {
	case r.SchemaVersion != SchemaVersion:
		return errors.New("unsupported report schema version")
	case r.Context == "":
		return errors.New("report context is empty")
	case r.GeneratedAt.IsZero():
		return errors.New("report generation time is missing")
	case r.Snapshot.Context != r.Context:
		return errors.New("snapshot context does not match the report context")
	case r.Snapshot.ObservedAt.IsZero():
		return errors.New("snapshot observation time is missing")
	case r.Snapshot.ObservedAt.After(r.GeneratedAt):
		return errors.New("snapshot observed after the report was generated")
	case r.Status != ReportComplete && r.Status != ReportPartial:
		return errors.New("invalid report status")
	}
	return nil
}

// validateReportTotals checks the finding total against the findings, and the key epoch.
func validateReportTotals(r Report) error {
	switch {
	case !r.Truncated && r.TotalFindings != len(r.Findings):
		return errors.New("finding total differs from the findings of an untruncated report")
	case r.Truncated && r.TotalFindings <= len(r.Findings):
		return errors.New("truncated report has no omitted finding")
	case r.Truncated && r.Status != ReportPartial:
		return errors.New("truncated report must be partial")
	case r.KeyEpoch != r.Snapshot.KeyEpoch:
		return errors.New("key epoch mismatch")
	}
	return nil
}

// validateReportLimits checks the size limits and the snapshot's scope.
func validateReportLimits(r Report) error {
	switch {
	case len(r.Findings) > MaxFindings:
		return errors.New("too many findings")
	case r.TotalFindings > MaxFindings:
		return errors.New("finding total exceeds the limit")
	case len(r.Coverage) > MaxObservations:
		return errors.New("too many coverage rows")
	case len(r.Snapshot.Versions) > MaxObservations:
		return errors.New("too many version facts")
	case len(r.Snapshot.Platforms) > MaxObservations:
		return errors.New("too many platform facts")
	case len(r.Snapshot.Features) > MaxObservations:
		return errors.New("too many feature facts")
	case len(r.Snapshot.Policies) > MaxObservations:
		return errors.New("too many policy facts")
	case r.Snapshot.Scope != "" && r.Snapshot.Scope != ScopeFleet && r.Snapshot.Scope != ScopeLocal:
		return errors.New("invalid snapshot scope")
	}
	return nil
}

// validateSnapshotFacts checks every fact of the snapshot. Its evidence must be in the
// report's context and the snapshot's scope; version, platform and feature evidence must
// also name a device, and policy evidence may leave it out.
func validateSnapshotFacts(r Report) error {
	if err := validateVersionFacts(r); err != nil {
		return err
	}
	for _, p := range r.Snapshot.Platforms {
		if err := validateFactEvidence("platform", p.Evidence, r, true); err != nil {
			return err
		}
	}
	for _, f := range r.Snapshot.Features {
		if f.Name == "" {
			return errors.New("feature fact has no name")
		}
		if err := validateFactEvidence("feature", f.Evidence, r, true); err != nil {
			return err
		}
	}
	for _, f := range r.Snapshot.Policies {
		if f.Name == "" {
			return errors.New("policy fact has no name")
		}
		if err := validateFactEvidence("policy", f.Evidence, r, false); err != nil {
			return err
		}
	}
	return nil
}

// validateVersionFacts checks the version facts of the snapshot: each has a name, a role and a channel,
// and its evidence names a device.
func validateVersionFacts(r Report) error {
	for _, f := range r.Snapshot.Versions {
		switch {
		case f.Name == "":
			return errors.New("version fact has no name")
		case !validRole(f.Role):
			return errors.New("invalid version role")
		case f.Channel != ChannelStable && f.Channel != ChannelUnstable && f.Channel != ChannelUnknown:
			return errors.New("invalid version channel")
		}
		if err := validateFactEvidence("version", f.Evidence, r, true); err != nil {
			return err
		}
	}
	return nil
}

// validateFactEvidence checks the evidence of a snapshot fact: the checks every piece of
// evidence passes, the snapshot's scope (equal, so an empty snapshot scope admits only
// empty evidence scopes), and, when the fact is about a device, that the device is named.
func validateFactEvidence(kind string, e EvidenceRef, r Report, needsDevice bool) error {
	if err := validateEvidence(e, r); err != nil {
		return err
	}
	if e.Scope != r.Snapshot.Scope {
		return fmt.Errorf("%s evidence scope differs from the snapshot scope", kind)
	}
	if needsDevice && e.Asset == "" {
		return fmt.Errorf("%s evidence names no device", kind)
	}
	return nil
}

// validateEvidence checks one piece of evidence against the report's context and
// generation time. Both a report's checks and the matcher's input checks use it.
func validateEvidence(e EvidenceRef, r Report) error {
	switch {
	case e.Context != r.Context:
		return errors.New("evidence context does not match the report")
	case e.AcquiredAt.IsZero() || e.AcquiredAt.After(r.GeneratedAt):
		return errors.New("evidence acquisition time is missing or after the report was generated")
	case e.ObservedAt != nil && (e.ObservedAt.IsZero() || e.ObservedAt.After(e.AcquiredAt)):
		return errors.New("evidence observation time is missing or after its acquisition")
	case e.Scope != "" && e.Scope != ScopeFleet && e.Scope != ScopeLocal:
		return errors.New("invalid evidence scope")
	}
	switch e.Origin {
	case OriginAPI, OriginLocal, OriginCollector, OriginOperator, OriginVendor, OriginDerived:
	default:
		return errors.New("invalid evidence origin")
	}
	switch e.Freshness {
	case FreshnessUnknown, FreshnessFresh, FreshnessStale:
	default:
		return errors.New("invalid evidence freshness")
	}
	return nil
}

// findingTuple is what a finding is about: the report's context, the snapshot's scope, the
// device and the rule. The tuple and the finding's ID name each other.
type findingTuple struct {
	context string
	scope   Scope
	asset   string
	rule    string
}

// validateFindings checks each finding's shape, identity, evidence and applicability rules.
// Within a finding the identity checks run in a fixed order, so that each has an input that
// only it refuses: a repeated tuple, then a repeated ID (of another tuple), then an ID that
// is not the one FindingID gives.
func validateFindings(r Report) error {
	tuples := make(map[findingTuple]bool, len(r.Findings))
	ids := make(map[string]bool, len(r.Findings))
	held := snapshotEvidence(r.Snapshot)
	for _, f := range r.Findings {
		if err := validateFindingShape(f, r); err != nil {
			return err
		}
		key := findingTuple{f.Context, r.Snapshot.Scope, f.Asset, f.RuleID}
		if tuples[key] {
			return errors.New("duplicate finding for the same context, scope, asset and rule")
		}
		tuples[key] = true
		if ids[f.ID] {
			return errors.New("duplicate finding identity")
		}
		ids[f.ID] = true
		if f.ID != FindingID(f.Context, r.Snapshot.Scope, f.Asset, f.RuleID) {
			return errors.New("finding id does not match its context, scope, asset and rule")
		}
		for _, e := range f.Evidence {
			if err := validateEvidence(e, r); err != nil {
				return err
			}
			// The ID hashes the snapshot's scope, so what a finding cites must be in it, as the
			// evidence of the snapshot's own facts is (equal, so scopeless meets scopeless).
			if e.Scope != r.Snapshot.Scope {
				return errors.New("finding evidence scope differs from the snapshot scope")
			}
		}
		if err := validateFindingClaim(f, held); err != nil {
			return err
		}
	}
	return nil
}

// evidenceKey is the value of an EvidenceRef, comparable and usable as a map key. The times
// are instants (seconds and nanoseconds since the epoch, not a time.Time, which carries a
// location and a monotonic reading), and the optional observation time is its value and not
// its pointer: two pieces of evidence are equal when everything they say is.
type evidenceKey struct {
	context, asset string
	scope          Scope
	origin         Origin
	acquiredS      int64
	acquiredN      int
	observed       bool
	observedS      int64
	observedN      int
	freshness      Freshness
	errorText      string
}

func keyOfEvidence(e EvidenceRef) evidenceKey {
	k := evidenceKey{
		context: e.Context, asset: e.Asset, scope: e.Scope, origin: e.Origin,
		acquiredS: e.AcquiredAt.Unix(), acquiredN: e.AcquiredAt.Nanosecond(),
		freshness: e.Freshness, errorText: e.Error,
	}
	if e.ObservedAt != nil {
		k.observed, k.observedS, k.observedN = true, e.ObservedAt.Unix(), e.ObservedAt.Nanosecond()
	}
	return k
}

// evidenceSet holds the evidence of the facts of a snapshot, by value.
type evidenceSet map[evidenceKey]struct{}

// snapshotEvidence collects the evidence of every version, platform, feature and policy fact.
func snapshotEvidence(s Snapshot) evidenceSet {
	set := make(evidenceSet, len(s.Versions)+len(s.Platforms)+len(s.Features)+len(s.Policies))
	for _, f := range s.Versions {
		set[keyOfEvidence(f.Evidence)] = struct{}{}
	}
	for _, f := range s.Platforms {
		set[keyOfEvidence(f.Evidence)] = struct{}{}
	}
	for _, f := range s.Features {
		set[keyOfEvidence(f.Evidence)] = struct{}{}
	}
	for _, f := range s.Policies {
		set[keyOfEvidence(f.Evidence)] = struct{}{}
	}
	return set
}

func (s evidenceSet) holds(e EvidenceRef) bool {
	_, ok := s[keyOfEvidence(e)]
	return ok
}

func validateFindingShape(f Finding, r Report) error {
	switch {
	case f.Context != r.Context:
		return errors.New("finding context does not match the report")
	case f.RuleID == "":
		return errors.New("finding has no rule id")
	case f.RuleRevision == "":
		return errors.New("finding has no rule revision")
	case !validEvidenceState(f.EvidenceState):
		return errors.New("invalid finding evidence state")
	case !validConfidence(f.Confidence):
		return errors.New("invalid finding confidence")
	case !validApplicability(f.Applicability):
		return errors.New("invalid finding applicability")
	case !validSeverity(f.SourceSeverity):
		return errors.New("invalid finding source severity")
	case !validPriority(f.Priority):
		return errors.New("invalid finding priority")
	}
	return nil
}

// validateFindingClaim checks that a finding's evidence can support what it claims. A
// finding that says a device is, or is not, affected must rest on observed evidence about
// that device, fresh and free of an error; one that cannot say must say why; one that claims
// corroboration needs two origins. Whatever a finding cites, of any applicability, is the
// evidence of a fact in the snapshot (held): a finding cannot rest on an observation the
// report does not contain.
func validateFindingClaim(f Finding, held evidenceSet) error {
	switch f.Applicability {
	case ApplicabilityAffected, ApplicabilityNotAffected:
		switch {
		case f.EvidenceState != EvidenceObserved:
			return errors.New("affected or not affected finding without observed evidence")
		case len(f.Evidence) == 0:
			return errors.New("affected or not affected finding without evidence")
		case f.Reason != "":
			return errors.New("affected or not affected finding carries a reason")
		}
		for _, e := range f.Evidence {
			if e.Context != f.Context || e.Asset != f.Asset {
				return errors.New("affected or not affected finding cites evidence for another context or device")
			}
		}
	case ApplicabilityUnknown, ApplicabilityPotential:
		if !validReason(f.Reason) {
			return errors.New("unknown or potentially affected finding without a known reason")
		}
		if f.Applicability == ApplicabilityUnknown {
			switch f.EvidenceState {
			case EvidenceUnknown, EvidenceStale, EvidenceAbsent:
			default:
				return errors.New("unknown finding must have evidence state unknown, stale or absent")
			}
		}
	}
	if f.Confidence == ConfidenceCorroborated && distinctOrigins(f.Evidence) < 2 {
		return errors.New("corroborated finding needs evidence from two origins")
	}
	return validateCitedEvidence(f, held)
}

// validateCitedEvidence checks each piece of evidence a finding cites: it is the evidence of
// a fact of the snapshot, by value, and, for an affected or not-affected finding, it carries
// no error and is fresh.
func validateCitedEvidence(f Finding, held evidenceSet) error {
	claims := f.Applicability == ApplicabilityAffected || f.Applicability == ApplicabilityNotAffected
	for _, e := range f.Evidence {
		switch {
		case !held.holds(e):
			return errors.New("finding cites evidence that no fact of the snapshot holds")
		case claims && e.Error != "":
			return errors.New("affected or not affected finding cites evidence that carries an error")
		case claims && e.Freshness != FreshnessFresh:
			return errors.New("affected or not affected finding cites evidence that is not fresh")
		}
	}
	return nil
}

func distinctOrigins(evidence []EvidenceRef) int {
	seen := make(map[Origin]bool, len(evidence))
	for _, e := range evidence {
		seen[e.Origin] = true
	}
	return len(seen)
}

// validateCoverage checks the requested targets and every coverage row. A complete report
// answers each requested target with a complete row and holds no partial row.
func validateCoverage(r Report) error {
	if r.Status == ReportComplete && len(r.RequestedCoverage) == 0 {
		return errors.New("complete report requires requested coverage")
	}
	completeTargets, err := answeredTargets(r)
	if err != nil {
		return err
	}
	for _, target := range r.RequestedCoverage {
		if !validTarget(target) {
			return errors.New("invalid requested coverage")
		}
		if r.Status == ReportComplete && !completeTargets[target] {
			return errors.New("missing requested coverage")
		}
	}
	held := tallyFindings(r.Findings)
	for _, c := range r.Coverage {
		if err := validateCoverageRow(c, r, held); err != nil {
			return err
		}
	}
	return nil
}

// answeredTargets is the targets that have a complete row. A row that says its target was not
// requested is refused here if the report requested the target, before anything else is said
// of the target, so that a requested target is never reported as merely missing.
func answeredTargets(r Report) (map[CoverageTarget]bool, error) {
	requested := make(map[CoverageTarget]bool, len(r.RequestedCoverage))
	for _, target := range r.RequestedCoverage {
		requested[target] = true
	}
	complete := make(map[CoverageTarget]bool, len(r.Coverage))
	for _, row := range r.Coverage {
		if row.Status == CoverageNotRequested && requested[row.Target] {
			return nil, errors.New("not-requested coverage names a requested target")
		}
		if row.Status == ReportComplete {
			complete[row.Target] = true
		}
	}
	return complete, nil
}

// tallyFindings counts the unknown and the potentially affected findings.
func tallyFindings(findings []Finding) findingTally {
	var held findingTally
	for _, f := range findings {
		switch f.Applicability {
		case ApplicabilityUnknown:
			held.unknown++
		case ApplicabilityPotential:
			held.potential++
		}
	}
	return held
}

// findingTally is how many of a report's findings are unknown and how many are only
// potentially affected.
type findingTally struct{ unknown, potential int }

// validateCoverageRow checks one row against the findings the report holds. A complete
// catalog row cannot sit beside an unknown or potentially affected finding, and the counts of
// a catalog row in a report that is not truncated are the findings the report holds.
func validateCoverageRow(c Coverage, r Report, held findingTally) error {
	switch {
	case r.Status == ReportComplete && c.Status == ReportPartial:
		return errors.New("complete report has partial coverage")
	case c.Context != r.Context:
		return errors.New("coverage context does not match the report")
	case !validTarget(c.Target):
		return errors.New("invalid coverage target")
	case c.Status != ReportComplete && c.Status != ReportPartial && c.Status != CoverageNotRequested:
		return errors.New("invalid coverage status")
	}
	if c.Status == CoverageNotRequested {
		return validateNotRequestedRow(c)
	}
	if c.Counts != nil {
		if err := validateCounts(*c.Counts); err != nil {
			return err
		}
	}
	if c.Status == ReportPartial {
		if c.Explanation == "" {
			return errors.New("partial coverage has no explanation")
		}
	} else if err := validateCompleteRow(c, held.unknown+held.potential > 0); err != nil {
		return err
	}
	return validateCatalogCounts(c, r, held)
}

// validateNotRequestedRow checks a row that says its target was not requested. That the target
// is not among the requested ones is checked beforehand, over the whole report.
func validateNotRequestedRow(c Coverage) error {
	switch {
	case c.Source == "":
		return errors.New("not-requested coverage has no source")
	case c.Explanation == "":
		return errors.New("not-requested coverage has no explanation")
	case c.Counts != nil:
		return errors.New("not-requested coverage carries counts")
	}
	return nil
}

// validateCatalogCounts checks that the counts of a catalog row in a report that is not
// truncated are the findings the report holds.
func validateCatalogCounts(c Coverage, r Report, held findingTally) error {
	if c.Counts == nil || c.Target.Dimension != CoverageCatalog || r.Truncated {
		return nil
	}
	switch {
	case c.Counts.Findings != len(r.Findings):
		return errors.New("catalog coverage counts a different number of findings than the report holds")
	case c.Counts.Unknown != held.unknown:
		return errors.New("catalog coverage counts a different number of unknown findings than the report holds")
	case c.Counts.Potential != held.potential:
		return errors.New("catalog coverage counts a different number of potentially affected findings than the report holds")
	}
	return nil
}

// validateCompleteRow checks what a complete row claims: a source, and no unknown or
// potentially affected result (in its counts, when it has them, and, for the catalog
// dimension, among the report's findings), over at least one rule and one asset.
func validateCompleteRow(c Coverage, uncertain bool) error {
	switch {
	case c.Source == "":
		return errors.New("complete coverage has no source")
	case c.Counts != nil && c.Counts.Unknown != 0:
		return errors.New("complete coverage counts unknown findings")
	case c.Counts != nil && c.Counts.Potential != 0:
		return errors.New("complete coverage counts potentially affected findings")
	case c.Counts != nil && c.Counts.Rules == 0:
		return errors.New("complete coverage counts no rules")
	case c.Counts != nil && c.Counts.Assets == 0:
		return errors.New("complete coverage counts no assets")
	case c.Target.Dimension == CoverageCatalog && uncertain:
		return errors.New("complete catalog coverage with an unknown or potentially affected finding")
	}
	return nil
}

// validateCounts checks that a row's counts are possible: none negative, the unknown and
// potential findings among the findings, and the findings within what a report can hold.
// The unknown and potential counts are compared with the findings by subtraction and not by
// their sum, which could overflow; with no count negative, a findings count below the
// unknown count makes the right side negative, which refuses any potential count.
func validateCounts(c CoverageCounts) error {
	switch {
	case c.Rules < 0 || c.Withdrawn < 0 || c.Assets < 0 || c.Findings < 0 || c.Unknown < 0 || c.Potential < 0:
		return errors.New("coverage counts must not be negative")
	case c.Potential > c.Findings-c.Unknown:
		return errors.New("coverage counts more unknown and potential findings than findings")
	case c.Findings > MaxFindings:
		return errors.New("coverage counts more findings than the limit allows")
	}
	return nil
}
func validTarget(t CoverageTarget) bool {
	switch t.Dimension {
	case CoveragePolicy, CoverageVersions, CoverageFeatures, CoverageIntent, CoverageCatalog:
	default:
		return false
	}
	return t.Scope == ScopeFleet || t.Scope == ScopeLocal
}
func validEvidenceState(s EvidenceState) bool {
	switch s {
	case EvidenceObserved, EvidenceUnknown, EvidenceStale, EvidenceAbsent:
		return true
	}
	return false
}
func validConfidence(c Confidence) bool {
	switch c {
	case ConfidenceUnknown, ConfidenceReported, ConfidenceCorroborated, ConfidenceDerived:
		return true
	}
	return false
}
func validApplicability(a Applicability) bool {
	switch a {
	case ApplicabilityAffected, ApplicabilityPotential, ApplicabilityNotAffected, ApplicabilityUnknown:
		return true
	}
	return false
}
func validSeverity(s Severity) bool {
	switch s {
	case SeverityUnknown, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}
func validReason(r UnknownReason) bool {
	for _, known := range unknownReasons {
		if r == known {
			return true
		}
	}
	return false
}
func validPriority(p Priority) bool {
	switch p {
	case PriorityUnknown, PriorityLow, PriorityMedium, PriorityHigh, PriorityUrgent:
		return true
	}
	return false
}

// minTime is the earliest instant a catalog or a report may carry. It lies before
// anything this program can have produced, and rejects zero and implausible dates.
var minTime = time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)

// validateTime is the time check shared by catalogs and reports. A time must use a zero
// UTC offset, be representable in JSON (years 0 to 9999), and not precede minTime.
func validateTime(t time.Time) error {
	if _, offset := t.Zone(); offset != 0 {
		return fmt.Errorf("timestamp must use UTC offset")
	}
	if _, err := t.MarshalJSON(); err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}
	if t.Before(minTime) {
		return fmt.Errorf("timestamp before %s", minTime.Format(time.RFC3339))
	}
	return nil
}

// validateString is the text check shared by catalogs and reports. Text is at most
// MaxTextBytes of valid UTF-8 with no control character (not C0, U+0000 to U+001F, not DEL,
// U+007F, and not C1, U+0080 to U+009F) and no invisible or misleading one: the characters
// sanitize escapes when it renders text, among them bidirectional controls, zero-width
// characters, tag characters, the no-break space and other non-ASCII spaces, the line and
// paragraph separators and the byte order mark. Text is data, but such a character in it
// reaches terminals and logs, or changes what a reader sees, so it is refused where it
// enters.
func validateString(s string) error {
	if len(s) > MaxTextBytes || !utf8.ValidString(s) {
		return fmt.Errorf("invalid or oversized text")
	}
	for _, r := range s {
		switch {
		case r < 0x20 || (r >= 0x7f && r <= 0x9f):
			return fmt.Errorf("text contains a control character")
		case unsafeRune(r):
			return fmt.Errorf("text contains an invisible or misleading character")
		}
	}
	return nil
}

// unsafeRune reports whether r is a character that does not print visibly or that changes
// how text reads: a control character, a format character, a variation selector, a blank
// filler, a private-use or unassigned code point, or a non-ASCII space. It is a copy of
// sanitize's unexported test of the same name, kept here so that this package of data
// contracts imports nothing of the program; TestUnsafeRuneAgreesWithSanitizeOverEveryRune
// holds the two to the same answer for every code point.
func unsafeRune(r rune) bool {
	if r < 0x20 {
		return true // C0
	}
	for _, x := range unsafeRanges {
		if r >= x.lo && r <= x.hi {
			return true
		}
	}
	// Marks that render as nothing, and every other format character (the tag block
	// U+E0000-E007F spells invisible ASCII), private-use, unassigned or non-ASCII space
	// character.
	return unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) || unicode.Is(unicode.Variation_Selector, r) || !strconv.IsPrint(r)
}

// unsafeRanges are the code points, from lo to hi, that unsafeRune names one by one.
var unsafeRanges = [...]struct{ lo, hi rune }{
	{0x7F, 0x9F},       // DEL, C1
	{0x061C, 0x061C},   // Arabic letter mark
	{0x2028, 0x2029},   // line and paragraph separators
	{0xFEFF, 0xFEFF},   // byte order mark
	{0x200B, 0x200F},   // zero-width space and joiners, LRM, RLM
	{0x202A, 0x202E},   // bidirectional embeddings and overrides
	{0x2066, 0x2069},   // bidirectional isolates
	{0xFE00, 0xFE0F},   // variation selectors
	{0xE0100, 0xE01EF}, // variation selectors
	{0x115F, 0x1160},   // fillers that render as blank space
	{0x3164, 0x3164},   // filler
	{0xFFA0, 0xFFA0},   // filler
	{0x2800, 0x2800},   // filler
}

func validateText(v reflect.Value) error {
	if !v.IsValid() {
		return nil
	}
	if v.Type() == reflect.TypeOf(time.Time{}) {
		t, ok := v.Interface().(time.Time)
		if !ok {
			return fmt.Errorf("invalid time")
		}
		return validateTime(t)
	}
	switch v.Kind() {
	case reflect.String:
		return validateString(v.String())
	case reflect.Pointer:
		if !v.IsNil() {
			return validateText(v.Elem())
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if err := validateText(v.Field(i)); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if v.Len() > MaxObservations {
			return fmt.Errorf("oversized collection")
		}
		for i := 0; i < v.Len(); i++ {
			if err := validateText(v.Index(i)); err != nil {
				return err
			}
		}
	}
	return nil
}
