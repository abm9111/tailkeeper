package tools

import (
	"fmt"
	"strings"
	"testing"
)

func numberedLines(n int, text string) []rawLine {
	out := make([]rawLine, n)
	for i := range out {
		out[i] = rawLine{text: fmt.Sprintf("%s %d", text, i), place: -1}
	}
	return out
}

func identity(s string) string { return s }

// A result keeps some of what Tailscale said and masks only that: a line that is left out is
// never read by the mask, so the work does not grow with the reply.
func TestLinesAreChosenBeforeTheyAreMasked(t *testing.T) {
	calls := 0
	counting := func(s string) string { calls++; return s }

	// One entry of a thousand lines: 64 shown, and the entry's source masked once.
	m := testMessages{failures: []rawEntry{{src: "tag:ci", lines: numberedLines(1000, "line")}}}
	got := m.showWith(counting)
	if len(got.failures) != 1 || len(got.failures[0].Errors) != maxTestMessages || got.omitted != 1000-maxTestMessages {
		t.Fatalf("%d entries, %d lines, %d omitted", len(got.failures), len(got.failures[0].Errors), got.omitted)
	}
	if calls != maxTestMessages+1 {
		t.Errorf("%d lines were masked to show %d: the lines left out were masked too", calls, maxTestMessages)
	}

	// Seventy entries of one line: 64 entries shown, six left out and never masked.
	calls = 0
	var entries []rawEntry
	for i := 0; i < 70; i++ {
		entries = append(entries, rawEntry{src: fmt.Sprintf("tag:t%d", i), lines: numberedLines(1, "x")})
	}
	got = testMessages{other: entries}.showWith(counting)
	if len(got.other) != maxTestMessages || got.omitted != 6 || calls != 2*maxTestMessages {
		t.Errorf("%d entries, %d omitted, %d masked", len(got.other), got.omitted, calls)
	}

	// A list of unpaired lines and a list of warnings are cut at 64 each, the rest counted.
	calls = 0
	var many []string
	for i := 0; i < 100; i++ {
		many = append(many, fmt.Sprintf("m%d", i))
	}
	got = testMessages{unmatched: many, warnings: many}.showWith(counting)
	if len(got.unmatched) != maxTestMessages || len(got.warnings) != maxTestMessages || got.omitted != 72 || calls != 2*maxTestMessages {
		t.Errorf("%d and %d lines, %d omitted, %d masked", len(got.unmatched), len(got.warnings), got.omitted, calls)
	}
}

// The lines of one result are at most maxResultLines in all its lists, and the first list
// to ask takes them.
func TestAResultShowsAtMostTheCapOfLinesInAllItsLists(t *testing.T) {
	var entries []rawEntry
	for i := 0; i < 10; i++ {
		entries = append(entries, rawEntry{src: fmt.Sprintf("tag:t%d", i), lines: numberedLines(64, "x")})
	}
	got := testMessages{failures: entries, unmatched: []string{"u"}, warnings: []string{"w"}, other: entries[:1]}.showWith(identity)
	shown := len(got.unmatched) + len(got.warnings)
	for _, e := range got.failures {
		shown += len(e.Errors)
	}
	for _, e := range got.other {
		shown += len(e.Errors)
	}
	if shown != maxResultLines || len(got.failures) != 4 || len(got.unmatched)+len(got.warnings)+len(got.other) != 0 {
		t.Errorf("%d lines shown: %d failures, %d unmatched, %d warnings, %d other", shown, len(got.failures), len(got.unmatched), len(got.warnings), len(got.other))
	}
	if want := 10*64 + 1 + 1 + 64 - maxResultLines; got.omitted != want {
		t.Errorf("%d omitted, want %d", got.omitted, want)
	}
}

// The lines of a result take at most the budget, counted as the registry will print them and
// then as JSON text, and the first line that does not fit ends its list, so a later short
// line does not jump the queue.
func TestTheLinesOfAResultTakeAtMostTheBudgetAndTheFirstThatDoesNotFitEndsTheList(t *testing.T) {
	long := strings.Repeat(`"`, 900)
	lines := numberedLines(40, long)
	got := testMessages{failures: []rawEntry{{src: "tag:ci", lines: lines}}}.showWith(identity)
	per := cost(long + " 10")
	want := (testMessageBudget - cost("tag:ci")) / per
	if len(got.failures) != 1 || len(got.failures[0].Errors) != want || got.omitted != 40-want {
		t.Fatalf("%d lines shown, %d omitted; want %d and %d", len(got.failures[0].Errors), got.omitted, want, 40-want)
	}
	total := cost("tag:ci")
	for _, e := range got.failures[0].Errors {
		total += cost(e)
	}
	if total > testMessageBudget {
		t.Errorf("the lines take %d characters, over the budget of %d", total, testMessageBudget)
	}

	// The source of an entry takes its share of the budget: with a long source, fewer lines fit.
	bigSrc := strings.Repeat(`"`, 900)
	withSrc := testMessages{failures: []rawEntry{{src: bigSrc, lines: lines}}}.showWith(identity)
	if want := (testMessageBudget - cost(bigSrc)) / per; len(withSrc.failures[0].Errors) != want || want >= len(got.failures[0].Errors) {
		t.Errorf("%d lines shown behind a long source, want %d (%d behind a short one)", len(withSrc.failures[0].Errors), want, len(got.failures[0].Errors))
	}

	// Fifteen long lines fit; the sixteenth does not, and the short line behind it is not shown.
	big := strings.Repeat(`"`, 2000)
	var seq []rawLine
	for i := 0; i < 20; i++ {
		seq = append(seq, rawLine{text: big, place: -1})
	}
	seq = append(seq, rawLine{text: "short", place: -1})
	got = testMessages{failures: []rawEntry{{src: "tag:ci", lines: seq}}}.showWith(identity)
	n := len(got.failures[0].Errors)
	for _, e := range got.failures[0].Errors {
		if e == "short" {
			t.Errorf("a short line was shown behind lines that did not fit")
		}
	}
	if n == 0 || n >= 20 || got.omitted != 21-n {
		t.Errorf("%d long lines shown, %d omitted", n, got.omitted)
	}
	// The next entry does not jump the queue either.
	got = testMessages{other: []rawEntry{{src: "tag:ci", lines: seq[:20]}, {src: "tag:db", lines: []rawLine{{text: "short", place: -1}}}}}.showWith(identity)
	if len(got.other) != 1 {
		t.Errorf("%d entries shown: an entry behind a line that did not fit was shown", len(got.other))
	}
	// The budget is shared: what the failures took is not there for the warnings.
	got = testMessages{failures: []rawEntry{{src: "tag:ci", lines: lines}}, warnings: []string{long, long, long}}.showWith(identity)
	if len(got.warnings) != 0 {
		t.Errorf("%d warnings shown after the failures took the budget", len(got.warnings))
	}
}

// A line is counted after it is masked: a text that masks to a few characters costs those,
// not its length, so how much of a result shows does not depend on the logins in it.
func TestALineIsCountedByWhatItIsAfterMasking(t *testing.T) {
	raw := strings.Repeat("amy@example.com ", 70) // 1,120 bytes that mask to two characters
	masking := func(string) string { return "a…" }
	var lines []rawLine
	for i := 0; i < maxTestMessages; i++ {
		lines = append(lines, rawLine{text: raw, place: -1})
	}
	m := testMessages{failures: []rawEntry{{src: "tag:ci", lines: lines}}}
	got := m.showWith(masking)
	if n := len(got.failures[0].Errors); n != maxTestMessages || got.omitted != 0 {
		t.Errorf("%d of %d masked lines shown, %d omitted: they were counted by their length before masking", n, maxTestMessages, got.omitted)
	}
	// The same lines, unmasked, do not all fit.
	if n := len(m.showWith(identity).failures[0].Errors); n >= maxTestMessages {
		t.Errorf("%d unmasked lines shown: the control does not fill the budget", n)
	}
}

// An SSH line keeps the test of the call it was placed at.
func TestAnSSHLineShowsTheTestItWasPlacedAt(t *testing.T) {
	got := testMessages{failures: []rawEntry{{src: "tag:ci", lines: []rawLine{{text: "a", place: 2}, {text: "b", place: -1}}}}}.showWith(identity)
	if e := got.failures[0].Errors; len(e) != 2 || e[0] != "ssh[2] a" || e[1] != "b" {
		t.Errorf("%q", e)
	}
}
