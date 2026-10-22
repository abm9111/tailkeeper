package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	// Trusted is the writer behind the CI-log guard. A formatter whose lines must reach a
	// runner as they are (the GitHub annotations) writes those lines here, and only
	// those. Nil means there is none: everything goes to the writer the formatter was
	// given, which is what a test of the layout wants.
	Trusted io.Writer
	// Dir is the directory the command ran in, relative to the root of the repository, with
	// forward slashes: a path typed relative to it names the file Dir/path of the repository.
	// It is empty at the root, and where no root is known (the command line then takes the
	// directory it runs in for the root, as a step of a workflow does that sets no working
	// directory). Outside says that the command ran outside the repository: no typed path
	// names a file of it. Root is the root as the runner names it (GITHUB_WORKSPACE), empty
	// when none is known: an absolute path typed below it names a file of the repository
	// too. Only the GitHub formatter reads them.
	Dir     string
	Root    string
	Outside bool
}

// formatter writes a report in one --format.
type formatter func(w io.Writer, rep registry.Report, o formatOptions) error

// formatters are the formats --format offers besides json. A new format registers
// here.
var formatters = map[string]formatter{"text": formatText, "github": formatGitHub, "markdown": formatMarkdown}

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
	if err := writePreamble(line, rep, esc, func(verdict string) string {
		return paint(o.Color, levelColor(rep.Level), verdict)
	}); err != nil {
		return err
	}
	trusted, untrusted := splitByTrust(rep.Findings)
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

// writePreamble writes what the text and GitHub layouts print before the findings: the
// verdict, what was not checked and the counts by class. line writes one line (the
// layout decides its indentation and its guard), esc escapes a string, and style is
// applied to the escaped verdict.
func writePreamble(line func(format string, args ...any) error, rep registry.Report, esc func(string) string, style func(string) string) error {
	if rep.Verdict != "" {
		if err := line("%s", style(esc(rep.Verdict))); err != nil {
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
	return nil
}

// splitByTrust separates the findings the report makes itself from the ones that hold
// Tailscale's text, each in its order. Every layout prints the first group, then the
// notice that the second is untrusted, then the second.
func splitByTrust(findings []registry.Finding) (ours, theirs []registry.Finding) {
	for _, f := range findings {
		if f.Untrusted {
			theirs = append(theirs, f)
		} else {
			ours = append(ours, f)
		}
	}
	return ours, theirs
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

// Trusted returns the writer behind the guard, for the lines of a formatter that must
// reach a runner as they are. The unfinished line the guard holds is written first,
// guarded and ended, so that what the caller writes next starts a line of its own.
// Whoever writes to it is the guard for those lines.
func (g *lineGuard) Trusted() io.Writer {
	if len(g.buf) > 0 && g.err == nil {
		line := string(g.buf)
		g.buf = nil
		_, g.err = io.WriteString(g.w, guardLine(line)+"\n")
	}
	return g.w
}

// repoDir says where in the repository a command runs, for the file property of a GitHub
// annotation, which is a path from the root of the repository. A runner names the root in
// GITHUB_WORKSPACE; the Runner reads it, and the formatter reads nothing. With it unset there
// is no root to compare with. When the directory is not below the root, or cannot be read,
// no typed path is a file of the repository, and the annotations carry their location in
// the message instead. The root is returned as the runner wrote it, so that an absolute
// path typed below it can be made relative to it.
func (r *Runner) repoDir() (dir, root string, outside bool) {
	getenv := r.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	root = getenv("GITHUB_WORKSPACE")
	if root == "" {
		return "", "", false
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", root, true
	}
	rel, err := filepath.Rel(root, cwd)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", root, true
	}
	if rel == "." {
		return "", root, false
	}
	return filepath.ToSlash(rel), root, false
}

// plainText is s with every character that does not print visibly written as an
// escape, and no cap.
func plainText(s string) string { return sanitize.String(s, 0) }

// findingWhere is "name:line:column", dropping what is unknown, and "" when the finding
// has no source.
func findingWhere(f registry.Finding, o formatOptions, esc func(string) string) string {
	if f.Source == "" {
		return ""
	}
	where := esc(sourceName(f.Source, o.Names))
	if f.Line > 0 {
		where += fmt.Sprintf(":%d", f.Line)
		if f.Column > 0 {
			where += fmt.Sprintf(":%d", f.Column)
		}
	}
	return where
}

// findingLine is "name:line:column: severity: message", dropping what is unknown.
func findingLine(f registry.Finding, o formatOptions, esc func(string) string) string {
	loc := findingWhere(f, o, esc)
	if loc != "" {
		loc += ": "
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
	return loc + sev + ": " + msg
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
