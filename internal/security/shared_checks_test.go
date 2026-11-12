package security

import (
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/sanitize"
)

// The text and time checks are shared by the catalog and the report: the cases here pin
// them through ValidateReport, and catalog_test.go pins the same two checks through
// ValidateCatalog. Each case holds an otherwise valid value, so the only check that can
// fire is the one under test, and each asserts the text of its error.

func reportWithExplanation(s string) Report {
	r := testReport()
	r.Coverage = []Coverage{{Context: r.Context, Target: CoverageTarget{Dimension: CoveragePolicy, Scope: ScopeFleet}, Source: "api", Status: ReportPartial, Explanation: s}}
	return r
}

func TestReportRejectsControlCharactersInEveryRange(t *testing.T) {
	if err := ValidateReport(reportWithExplanation("a plain sentence")); err != nil {
		t.Fatalf("the fixture is not valid: %v", err)
	}
	for _, c := range []rune{0x00, 0x01, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1b, 0x1f, 0x7f, 0x80, 0x85, 0x9b, 0x9f} {
		err := ValidateReport(reportWithExplanation("a" + string(c) + "b"))
		if err == nil || !strings.Contains(err.Error(), "control character") {
			t.Errorf("U+%04X: %v", c, err)
		}
	}
	// The ranges end where the design says: space, tilde and ordinary letters are text.
	for _, c := range []rune{0x20, 0x7e, 0xa9, 0xe9, 0xff, 0x0100, 0x65e5, 0x1f600} {
		if err := ValidateReport(reportWithExplanation("a" + string(c) + "b")); err != nil {
			t.Errorf("U+%04X rejected: %v", c, err)
		}
	}
}

// invisibleRunes are characters that are not C0, DEL or C1 and that sanitize escapes because
// they render as nothing or change what a reader sees: a sample of each class.
var invisibleRunes = []rune{
	0x00a0, 0x00ad, 0x034f, 0x061c, 0x115f, 0x1160, 0x180e, 0x2000, 0x200b, 0x200c, 0x200d, 0x200e, 0x200f,
	0x2028, 0x2029, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x202f, 0x205f, 0x2060, 0x2066, 0x2067, 0x2068, 0x2069,
	0x2800, 0x3000, 0x3164, 0xe000, 0xfe00, 0xfe0f, 0xfeff, 0xffa0, 0xfff9, 0xfffe, 0xe0001, 0xe0041, 0xe007f, 0xe0100, 0x0378,
}

// Text that no terminal shows as typed is refused where it enters, as a control character is:
// bidirectional controls, zero-width characters, tag characters, the no-break space, the line
// and paragraph separators and the byte order mark. The error is its own, so a case cannot
// pass on the control-character check.
func TestReportRejectsInvisibleCharactersWithTheirOwnError(t *testing.T) {
	for _, c := range invisibleRunes {
		err := ValidateReport(reportWithExplanation("a" + string(c) + "b"))
		if err == nil || err.Error() != "text contains an invisible or misleading character" {
			t.Errorf("U+%04X: %v", c, err)
		}
	}
	// Every string of a report is checked, not only the explanation.
	r := testReport()
	r.Context, r.Snapshot.Context = "ctx\u202e", "ctx\u202e"
	if err := ValidateReport(r); err == nil || !strings.Contains(err.Error(), "invisible or misleading") {
		t.Errorf("context: %v", err)
	}
}

// validateString and sanitize agree on which characters are unsafe, over every code point
// that can be text: the copy in this package refuses exactly the characters sanitize
// escapes, so the report and catalog check cannot fall behind the one that guards output.
// Surrogates are not text (utf8 refuses them), and U+FFFD is the replacement character, which
// sanitize shows as it is when the input was really encoded.
func TestUnsafeRuneAgreesWithSanitizeOverEveryRune(t *testing.T) {
	refused, escaped := 0, 0
	for r := rune(0); r <= 0x10ffff; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue
		}
		s := string(r)
		isRefused := validateString(s) != nil
		isEscaped := sanitize.String(s, 0) != s
		if isRefused != isEscaped {
			t.Fatalf("U+%04X: validateString refuses it = %v, sanitize escapes it = %v", r, isRefused, isEscaped)
		}
		if isRefused {
			refused++
		}
		if isEscaped {
			escaped++
		}
	}
	// The comparison is not vacuous: a large set agrees, and the classes named above are in it.
	if refused < 1000 || refused != escaped {
		t.Fatalf("refused %d, escaped %d", refused, escaped)
	}
	for _, c := range invisibleRunes {
		if validateString("a"+string(c)) == nil {
			t.Errorf("U+%04X is accepted", c)
		}
	}
}

func TestReportRejectsControlCharactersInEveryString(t *testing.T) {
	bad := "x\x1b[31m"
	for _, tc := range []struct {
		name   string
		change func(*Report)
	}{
		{"context", func(r *Report) { r.Context = bad; r.Snapshot.Context = bad }},
		{"coverage source", func(r *Report) {
			r.Coverage = []Coverage{{Context: r.Context, Target: CoverageTarget{Dimension: CoveragePolicy, Scope: ScopeFleet}, Source: bad, Status: ReportPartial}}
		}},
		{"fact name", func(r *Report) {
			r.Snapshot.Features = []FeatureFact{{Name: bad, Evidence: EvidenceRef{Context: r.Context, Origin: OriginAPI, Freshness: FreshnessUnknown, AcquiredAt: r.GeneratedAt}}}
		}},
		{"evidence error", func(r *Report) {
			r.Snapshot.Features = []FeatureFact{{Name: "ssh", Evidence: EvidenceRef{Context: r.Context, Origin: OriginAPI, Freshness: FreshnessUnknown, AcquiredAt: r.GeneratedAt, Error: bad}}}
		}},
		{"finding explanation", func(r *Report) {
			r.TotalFindings = 1
			r.Findings = []Finding{{ID: "f", Context: r.Context, RuleID: "r", RuleRevision: "1", EvidenceState: EvidenceUnknown, Confidence: ConfidenceUnknown, Applicability: ApplicabilityUnknown, SourceSeverity: SeverityUnknown, Priority: PriorityUnknown, Explanation: bad}}
		}},
		{"finding remediation", func(r *Report) {
			r.TotalFindings = 1
			r.Findings = []Finding{{ID: "f", Context: r.Context, RuleID: "r", RuleRevision: "1", EvidenceState: EvidenceUnknown, Confidence: ConfidenceUnknown, Applicability: ApplicabilityUnknown, SourceSeverity: SeverityUnknown, Priority: PriorityUnknown, Remediation: []string{"fine", bad}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := testReport()
			tc.change(&r)
			err := ValidateReport(r)
			if err == nil || !strings.Contains(err.Error(), "control character") {
				t.Fatalf("want a control-character error, got %v", err)
			}
		})
	}
}

func TestReportTextLimitsKeepTheirOwnErrors(t *testing.T) {
	if err := ValidateReport(reportWithExplanation(strings.Repeat("x", MaxTextBytes))); err != nil {
		t.Fatalf("text of exactly %d bytes rejected: %v", MaxTextBytes, err)
	}
	for name, s := range map[string]string{
		"oversized":    strings.Repeat("x", MaxTextBytes+1),
		"invalid utf8": "a" + string([]byte{0xff}) + "b",
		"truncated":    "a" + string([]byte{0xc2}),
	} {
		err := ValidateReport(reportWithExplanation(s))
		if err == nil || !strings.Contains(err.Error(), "invalid or oversized text") || strings.Contains(err.Error(), "control") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestReportTimeFloor(t *testing.T) {
	floor := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	before := floor.Add(-time.Nanosecond)
	at := testReport()
	at.GeneratedAt, at.Snapshot.ObservedAt = floor, floor
	if err := ValidateReport(at); err != nil {
		t.Fatalf("the floor itself must be accepted: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Report)
	}{
		{"generated", func(r *Report) { r.GeneratedAt, r.Snapshot.ObservedAt = before, before }},
		{"snapshot observed", func(r *Report) { r.Snapshot.ObservedAt = before }},
		{"fact acquired", func(r *Report) {
			r.Snapshot.Features = []FeatureFact{{Name: "ssh", Evidence: EvidenceRef{Context: r.Context, Origin: OriginAPI, Freshness: FreshnessUnknown, AcquiredAt: before}}}
		}},
		{"fact observed", func(r *Report) {
			r.Snapshot.Features = []FeatureFact{{Name: "ssh", Evidence: EvidenceRef{Context: r.Context, Origin: OriginAPI, Freshness: FreshnessUnknown, AcquiredAt: r.GeneratedAt, ObservedAt: &before}}}
		}},
		{"finding evidence", func(r *Report) {
			r.TotalFindings = 1
			r.Findings = []Finding{{ID: "f", Context: r.Context, RuleID: "r", RuleRevision: "1", EvidenceState: EvidenceObserved, Confidence: ConfidenceReported, Applicability: ApplicabilityUnknown, SourceSeverity: SeverityUnknown, Priority: PriorityUnknown,
				Evidence: []EvidenceRef{{Context: r.Context, Origin: OriginAPI, Freshness: FreshnessUnknown, AcquiredAt: before}}}}
		}},
		{"year 1901", func(r *Report) {
			r.GeneratedAt, r.Snapshot.ObservedAt = time.Date(1901, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(1901, 1, 1, 0, 0, 0, 0, time.UTC)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := testReport()
			tc.change(&r)
			err := ValidateReport(r)
			if err == nil || !strings.Contains(err.Error(), "before 2019-01-01T00:00:00Z") {
				t.Fatalf("want a floor error, got %v", err)
			}
		})
	}
}

// The existing UTC and year rules keep their own errors, and run before the floor.
func TestReportTimeRulesKeepTheirOwnErrors(t *testing.T) {
	r := testReport()
	r.GeneratedAt = r.GeneratedAt.In(time.FixedZone("offset", 3600))
	if err := ValidateReport(r); err == nil || !strings.Contains(err.Error(), "UTC offset") {
		t.Fatalf("want an offset error, got %v", err)
	}
	r = testReport()
	r.GeneratedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	r.Snapshot.ObservedAt = r.GeneratedAt
	if err := ValidateReport(r); err == nil || !strings.Contains(err.Error(), "invalid timestamp") {
		t.Fatalf("want a year error, got %v", err)
	}
}
