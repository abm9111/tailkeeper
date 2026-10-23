package tools

import (
	"fmt"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tripwire"
)

// rawLine is one line of Tailscale's text as it came. place is the SSH test of the call that
// the line was paired with, or -1.
type rawLine struct {
	text  string
	place int
}

// rawEntry is the lines Tailscale gave for one source.
type rawEntry struct {
	src   string
	lines []rawLine
}

func plainLines(in []string) []rawLine {
	out := make([]rawLine, len(in))
	for i, s := range in {
		out[i] = rawLine{text: s, place: -1}
	}
	return out
}

// testMessages is everything Tailscale said that a result may show, as it came: nothing in it
// is masked or cut. A result keeps some of it and masks only what it keeps (show).
type testMessages struct {
	failures  []rawEntry
	unmatched []string
	warnings  []string
	other     []rawEntry
}

func (m *testMessages) add(o testMessages) {
	m.failures = append(m.failures, o.failures...)
	m.unmatched = append(m.unmatched, o.unmatched...)
	m.warnings = append(m.warnings, o.warnings...)
	m.other = append(m.other, o.other...)
}

const (
	// maxResultLines is how many lines of Tailscale's text one result shows, in all its lists.
	maxResultLines = 256

	// testMessageBudget is the most characters, as JSON text, that the lines of one result
	// take together. Every line is counted by what the registry will make of it (masked,
	// credential shapes replaced, escaped, cut at its string cap) and then encoded, where an
	// angle bracket costs six times its length, so that the result stays far under a frame
	// whatever the reply holds.
	testMessageBudget = 32000
)

// shownMessages is what a result shows of testMessages, and how many lines it left out.
type shownMessages struct {
	failures  []ACLTestResult
	unmatched []string
	warnings  []string
	other     []ACLTestResult
	omitted   int
}

// show chooses what a result keeps and masks only that. The lists are taken in the order of
// their weight: the failures of the posted source, the lines nobody could pair, the warnings,
// and last the results for other sources. A list keeps at most maxTestMessages entries of at
// most maxTestMessages lines; the result keeps at most maxResultLines lines and
// testMessageBudget characters; the first line that does not fit ends its list. Each line is
// cut after it is masked, so how much of it shows does not depend on the logins in it, and a
// line that is left out is never masked. The lines left out are counted.
func (m testMessages) show(res *SubjectResolver, env *registry.Env) shownMessages {
	return m.showWith(func(text string) string { return testLine(res, env, text) })
}

// showWith is show with the mask a line goes through.
func (m testMessages) showWith(mask func(string) string) shownMessages {
	s := &shower{mask: mask, room: testMessageBudget, lines: maxResultLines}
	out := shownMessages{}
	out.failures = s.entries(m.failures)
	out.unmatched = s.strings(m.unmatched)
	out.warnings = s.strings(m.warnings)
	out.other = s.entries(m.other)
	out.omitted = s.omitted
	return out
}

type shower struct {
	mask    func(string) string
	room    int // characters left
	lines   int // lines left
	omitted int
}

// cost is what a shown string takes of the budget, with its quotes and its comma.
func cost(shown string) int {
	return encodedLen(sanitize.String(tripwire.Redact(shown), registry.ResultStringMax)) + 3
}

// line masks one line and takes its cost from what is left. It is not masked when no line is
// left to show, and it is not shown when it does not fit.
func (s *shower) line(l rawLine) (string, bool) {
	if s.lines == 0 {
		return "", false
	}
	shown := s.mask(l.text)
	if l.place >= 0 {
		shown = fmt.Sprintf("ssh[%d] %s", l.place, shown)
	}
	c := cost(shown)
	if c > s.room {
		return "", false
	}
	s.room -= c
	s.lines--
	return shown, true
}

func (s *shower) strings(in []string) []string {
	var out []string
	for i, text := range in {
		if i >= maxTestMessages {
			s.omitted += len(in) - i
			break
		}
		shown, ok := s.line(rawLine{text: text, place: -1})
		if !ok {
			s.omitted += len(in) - i
			break
		}
		out = append(out, shown)
	}
	return out
}

func (s *shower) entries(in []rawEntry) []ACLTestResult {
	var out []ACLTestResult
	for i, e := range in {
		src := ""
		fits := i < maxTestMessages && s.lines > 0
		if fits {
			src = s.mask(e.src)
			fits = cost(src) <= s.room
		}
		if !fits {
			s.omitLines(in[i:])
			break
		}
		s.room -= cost(src)
		var shown []string
		full := false
		for j, l := range e.lines {
			if j >= maxTestMessages {
				break
			}
			text, ok := s.line(l)
			if !ok {
				full = true
				break
			}
			shown = append(shown, text)
		}
		s.omitted += len(e.lines) - len(shown)
		if len(shown) > 0 {
			out = append(out, ACLTestResult{Src: src, Errors: shown})
		} else {
			// An entry that shows no line says nothing, and its source takes nothing.
			s.room += cost(src)
		}
		if full {
			// The first line that did not fit ends the list.
			s.omitLines(in[i+1:])
			break
		}
	}
	return out
}

// omitLines counts the lines of entries a result leaves out.
func (s *shower) omitLines(entries []rawEntry) {
	for _, e := range entries {
		s.omitted += len(e.lines)
	}
}
