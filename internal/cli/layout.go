package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/sanitize"
)

// formatOptions are what a formatter needs besides the report.
type formatOptions struct {
	// Names says what to call each source: the path the user typed for the file a
	// flag named, or <stdin>. A source missing here keeps its own name.
	Names map[string]string
	Color bool
}

// formatter writes a report in one --format.
type formatter func(w io.Writer, rep registry.Report, o formatOptions) error

// formatters are the formats --format offers besides json. A new format registers
// here.
var formatters = map[string]formatter{"text": formatText}

// formatNames lists the formats --format accepts, json first among the rest.
func formatNames() []string {
	names := []string{"text", "json"}
	var more []string
	for name := range formatters {
		if name != "text" {
			more = append(more, name)
		}
	}
	sort.Strings(more)
	return append(names, more...)
}

const (
	ansiReset  = "\x1b[0m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
)

func paint(color bool, code, s string) string {
	if !color {
		return s
	}
	return code + s + ansiReset
}

func levelColor(l registry.Level) string {
	switch l {
	case registry.LevelOK:
		return ansiGreen
	case registry.LevelWarn:
		return ansiYellow
	}
	return ansiRed
}

// sourceName is how a finding's source is called in the layout.
func sourceName(src string, names map[string]string) string {
	if n, ok := names[src]; ok {
		return n
	}
	if src == "live" {
		return "live policy"
	}
	return src
}

// formatText prints the human layout: a one-line verdict; what was not
// checked; the counts by class; then the details, each behind a location written
// file:line:column: so a terminal or an editor makes it clickable. Tailscale's own
// text follows a notice that it is untrusted. Every string is escaped here too:
// nothing a policy or a message holds can start a line of its own or move a terminal.
func formatText(w io.Writer, rep registry.Report, o formatOptions) error {
	line := func(format string, args ...any) error {
		_, err := io.WriteString(w, guardLine(fmt.Sprintf(format, args...))+"\n")
		return err
	}
	esc := func(s string) string { return sanitize.String(s, 0) }
	if rep.Verdict != "" {
		if err := line("%s", paint(o.Color, levelColor(rep.Level), esc(rep.Verdict))); err != nil {
			return err
		}
	}
	if len(rep.NotChecked) > 0 {
		parts := make([]string, len(rep.NotChecked))
		for i, n := range rep.NotChecked {
			parts[i] = esc(n)
		}
		if err := line("not checked: %s", strings.Join(parts, ", ")); err != nil {
			return err
		}
	}
	if len(rep.Classes) > 0 {
		if err := line("changes"); err != nil {
			return err
		}
		for _, c := range rep.Classes {
			note := ""
			if c.Expected {
				note = "  (expected)"
			}
			if err := line("  %-18s %d%s", esc(c.Class), c.Count, note); err != nil {
				return err
			}
		}
	}
	var trusted, untrusted []registry.Finding
	for _, f := range rep.Findings {
		if f.Untrusted {
			untrusted = append(untrusted, f)
		} else {
			trusted = append(trusted, f)
		}
	}
	for _, f := range trusted {
		if err := line("%s", findingLine(f, o, esc)); err != nil {
			return err
		}
	}
	if len(untrusted) > 0 {
		if err := line("%s", registry.UntrustedReasonsNotice); err != nil {
			return err
		}
		for _, f := range untrusted {
			if err := line("%s", findingLine(f, o, esc)); err != nil {
				return err
			}
		}
	}
	return nil
}

// guardLine keeps one line of CLI text from acting on a CI log parser. Runner.Run
// puts every line the command line writes to standard output or standard error
// through it, so that text from a policy, a message, the tailnet or the command line
// cannot drive the build that shows it; the JSON the command line prints is escaped
// for the same markers by writeJSON and writeJSONLine instead. Output that is not a
// CI log is not guarded: the mcp command's standard output is the protocol's, and
// ServeMCP owns it. A parser acts on:
//   - GitHub workflow commands, which start a line with "::" (after leading white
//     space);
//   - Azure Pipelines formatting commands, which start a line with "##[";
//   - Azure Pipelines logging commands, which begin "##vso[" and are found anywhere
//     in a line;
//   - TeamCity service messages, which begin "##teamcity[" and are found anywhere
//     in a line.
//
// For the first two, text that reaches the start of a line, such as a path the user
// typed, cannot be told apart from a command by escaping alone, so its first byte
// is written as an escape in the spelling the rest of the layout uses. A runner
// trims leading white space before it looks, so the guard looks past indentation
// too, of any Unicode white space, and leaves that prefix as it is. The layout's
// own colour code in front is skipped as well, so that the guard sees the text
// itself. For the last two, the first # of every occurrence is written the same
// way. Nothing else in the line changes.
func guardLine(s string) string {
	for _, marker := range []string{"##vso[", "##teamcity["} {
		s = strings.ReplaceAll(s, marker, `\u{0023}`+marker[1:])
	}
	rest := s
	for _, code := range []string{ansiRed, ansiGreen, ansiYellow} {
		rest = strings.TrimPrefix(rest, code)
	}
	rest = strings.TrimLeftFunc(rest, unicode.IsSpace)
	head := s[:len(s)-len(rest)]
	switch {
	case strings.HasPrefix(rest, "::"):
		return head + `\u{003A}` + rest[1:]
	case strings.HasPrefix(rest, "##["):
		return head + `\u{0023}` + rest[1:]
	}
	return s
}

// lineGuard is an io.Writer that passes each line written to it through guardLine
// before it reaches w. A line is complete at its newline; Flush writes what is left
// of an unfinished last line. When a write to w fails, the error is kept: nothing
// more is written to w, and every later Write returns that error.
type lineGuard struct {
	w   io.Writer
	buf []byte
	err error
}

func (g *lineGuard) Write(p []byte) (int, error) {
	if g.err != nil {
		return 0, g.err
	}
	g.buf = append(g.buf, p...)
	for {
		i := bytes.IndexByte(g.buf, '\n')
		if i < 0 {
			return len(p), nil
		}
		line := string(g.buf[:i])
		g.buf = g.buf[i+1:]
		if _, err := io.WriteString(g.w, guardLine(line)+"\n"); err != nil {
			g.err, g.buf = err, nil
			return 0, err
		}
	}
}

// Flush writes the unfinished last line, guarded, if there is one. It returns the
// error of that write only: one that failed earlier has been returned already.
func (g *lineGuard) Flush() error {
	if len(g.buf) == 0 || g.err != nil {
		return nil
	}
	line := string(g.buf)
	g.buf = nil
	_, g.err = io.WriteString(g.w, guardLine(line))
	return g.err
}

// findingLine is "name:line:column: severity: message", dropping what is unknown.
func findingLine(f registry.Finding, o formatOptions, esc func(string) string) string {
	var loc strings.Builder
	if f.Source != "" {
		loc.WriteString(esc(sourceName(f.Source, o.Names)))
		if f.Line > 0 {
			fmt.Fprintf(&loc, ":%d", f.Line)
			if f.Column > 0 {
				fmt.Fprintf(&loc, ":%d", f.Column)
			}
		}
		loc.WriteString(": ")
	}
	sev := esc(f.Severity)
	switch f.Severity {
	case "error":
		sev = paint(o.Color, ansiRed, sev)
	case "warning":
		sev = paint(o.Color, ansiYellow, sev)
	}
	msg := esc(f.Message)
	if f.Pointer != "" {
		msg = esc(f.Pointer) + ": " + msg
	}
	return loc.String() + sev + ": " + msg
}

// isTerminal reports whether w is a terminal: a character device.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// color says whether the layout uses colour on w: only on a terminal, and not when
// NO_COLOR is set to anything (no-color.org) or the terminal is dumb.
func (r *Runner) color(w io.Writer) bool {
	// The guard is in front of the real writer; the terminal is the one behind it.
	for {
		g, ok := w.(*lineGuard)
		if !ok {
			break
		}
		w = g.w
	}
	getenv := r.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	term := r.IsTerminal
	if term == nil {
		term = isTerminal
	}
	return getenv("NO_COLOR") == "" && getenv("TERM") != "dumb" && term(w)
}
