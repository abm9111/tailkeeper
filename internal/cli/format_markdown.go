package cli

import (
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/sanitize"
)

// formatMarkdown writes a report as Markdown, for a job's step summary or a comment
// on a pull request: the verdict in bold, then what was not checked and the counts
// by class as lists, then the findings as a list with the location in a code span.
//
// Nothing a policy, a message or the command line holds may act on the page that
// shows it: text written by tailkeeper's own code is escaped (mdEscape), so that it
// cannot mention a person, link an issue, a URL or an address, open an HTML tag,
// start a block or break a table; Tailscale's text goes in a code span (codeSpan),
// where Markdown reads nothing at all. No item holds a line break: the text is
// escaped for control characters first. Colour does not apply, and every line still
// goes through guardLine, because the page is usually written by a shell redirect
// into a log that a runner reads too.
func formatMarkdown(w io.Writer, rep registry.Report, o formatOptions) error {
	wrote := false
	put := func(s string) error {
		wrote = true
		_, err := io.WriteString(w, guardLine(s)+"\n")
		return err
	}
	// A block starts after a blank line, unless it is the first thing written.
	block := func(heading string) error {
		if wrote {
			if err := put(""); err != nil {
				return err
			}
		}
		if err := put(heading); err != nil {
			return err
		}
		return put("")
	}
	if rep.Verdict != "" {
		if err := put("**" + mdEscape(rep.Verdict) + "**"); err != nil {
			return err
		}
	}
	if len(rep.NotChecked) > 0 {
		if err := block("Not checked:"); err != nil {
			return err
		}
		for _, n := range rep.NotChecked {
			if err := put("- " + mdEscape(n)); err != nil {
				return err
			}
		}
	}
	if len(rep.Classes) > 0 {
		if err := block("Changes:"); err != nil {
			return err
		}
		for _, c := range rep.Classes {
			note := ""
			if c.Expected {
				note = " (expected)"
			}
			if err := put("- " + mdEscape(c.Class) + ": " + strconv.Itoa(c.Count) + note); err != nil {
				return err
			}
		}
	}
	// Our own text first, then Tailscale's behind its notice, as in the text layout.
	ours, theirs := splitByTrust(rep.Findings)
	if len(rep.Findings) > 0 {
		if err := block("Findings:"); err != nil {
			return err
		}
		for _, f := range ours {
			if err := put(markdownFinding(f, o)); err != nil {
				return err
			}
		}
		if len(theirs) > 0 {
			if len(ours) > 0 {
				if err := put(""); err != nil {
					return err
				}
			}
			if err := put(registry.UntrustedReasonsNotice); err != nil {
				return err
			}
			if err := put(""); err != nil {
				return err
			}
			for _, f := range theirs {
				if err := put(markdownFinding(f, o)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// markdownFinding is one list item: the location in a code span, the severity, the
// pointer in a code span, then the message, which is a code span when it is
// Tailscale's.
func markdownFinding(f registry.Finding, o formatOptions) string {
	var b strings.Builder
	b.WriteString("- ")
	if where := findingWhere(f, o, plainText); where != "" {
		b.WriteString(codeSpan(where))
		b.WriteString(" ")
	}
	b.WriteString(mdEscape(f.Severity))
	b.WriteString(": ")
	if f.Pointer != "" {
		b.WriteString(codeSpan(f.Pointer))
		b.WriteString(": ")
	}
	if f.Untrusted {
		b.WriteString(codeSpan(f.Message))
	} else {
		b.WriteString(mdEscape(f.Message))
	}
	return b.String()
}

// codeSpan writes s as a Markdown code span on one line. The fence is one backtick
// longer than the longest run of them in s, so that no text can end the span, and a
// space on each side keeps a backtick at either end of s from joining the fence.
// Control and invisible characters are escaped first, as everywhere in tailkeeper's
// output, so s holds no line break. An empty s is written as nothing.
func codeSpan(s string) string {
	s = sanitize.String(s, 0)
	if s == "" {
		return ""
	}
	longest, run := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") || strings.HasPrefix(s, " ") || strings.HasSuffix(s, " ") {
		return fence + " " + s + " " + fence
	}
	return fence + s + fence
}

// mdEscape writes s as plain text for Markdown on GitHub:
//   - a backslash before each character that can start emphasis, a link, an image, an
//     HTML tag, a table cell or a strike-through (\ ` * _ [ ] < > | ! ~), and before
//     the first character when that would start a list, a heading or a numbered
//     list (- + # and a number with a dot or a parenthesis after it);
//   - @ as &#64;, so that nobody is mentioned or sent an address; # before a digit as
//     &#35;, and GH- before a digit as GH&#45;, so that no issue is linked; :// as
//     :&#47;&#47; and www. as www&#46;, so that no address becomes a link; & as &amp;, so
//     that no entity is read.
//
// Control and invisible characters are escaped first, so s holds no line break. A
// commit hash is still linked by GitHub; it names a commit, and links nowhere new.
func mdEscape(s string) string {
	s = sanitize.String(s, 0)
	var b strings.Builder
	for i := 0; i < len(s); {
		rest := s[i:]
		switch {
		case strings.HasPrefix(rest, "://"):
			b.WriteString(":&#47;&#47;")
			i += 3
			continue
		case len(rest) >= 4 && strings.EqualFold(rest[:4], "www."):
			b.WriteString(rest[:3] + "&#46;")
			i += 4
			continue
		case rest[0] == '#' && len(rest) > 1 && rest[1] >= '0' && rest[1] <= '9':
			b.WriteString("&#35;")
			i++
			continue
		case len(rest) > 3 && strings.EqualFold(rest[:3], "gh-") && rest[3] >= '0' && rest[3] <= '9':
			b.WriteString(rest[:2] + "&#45;")
			i += 3
			continue
		}
		r, size := utf8.DecodeRuneInString(rest)
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '@':
			b.WriteString("&#64;")
		case '\\', '`', '*', '_', '[', ']', '<', '>', '|', '!', '~':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return escapeBlockStart(b.String())
}

// escapeBlockStart stops text that begins with a list or heading marker from being
// one: a backslash before - + or #, and before the dot or parenthesis of a number.
func escapeBlockStart(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '-', '+', '#':
		return `\` + s
	}
	digits := 0
	for digits < len(s) && s[digits] >= '0' && s[digits] <= '9' {
		digits++
	}
	if digits > 0 && digits < len(s) && (s[digits] == '.' || s[digits] == ')') {
		return s[:digits] + `\` + s[digits:]
	}
	return s
}
