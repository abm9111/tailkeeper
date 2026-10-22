package cli

import (
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/sanitize"
)

// maxAnnotations is how many annotations of one severity the formatter writes. GitHub
// keeps ten errors, ten warnings and ten notices of a step and drops the rest without
// a word; the formatter says how many it left out.
const maxAnnotations = 10

// annotationTitle is the title of every annotation.
const annotationTitle = "tailkeeper"

// The two escapes of a workflow command: its data, and a property of it, which also
// cannot hold the two characters that end a property or a name.
var (
	dataEscaper     = strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	propertyEscaper = strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C")
)

// formatGitHub writes the findings of a report as GitHub workflow annotations, one
// for each finding, and the rest of the report as indented lines.
//
// A runner acts on a line that starts with "::", so which lines may do so is the
// whole job. The annotations go to o.Trusted, the writer in front of which the CI-log
// guard is not, and they are the only lines that do: each is built here from a
// severity word of our own, properties that cannot hold a colon, a comma or a line
// end, and data in which no line end survives. Every other line (the verdict, what
// was not checked, the counts, the notice before Tailscale's text, the count of
// annotations left out) goes to w, indented by two spaces and passed through
// guardLine first, because a runner trims leading white space and indentation alone
// would stop nothing. A report text that begins "::add-mask::" is therefore data in
// an annotation or an escaped line, never a command. Without o.Trusted the
// annotations go to w as well.
//
// The formatter reads no environment variable and opens no file: the runner's
// $GITHUB_OUTPUT and $GITHUB_STEP_SUMMARY are not touched, and a test holds the
// source to that. Colour does not apply.
func formatGitHub(w io.Writer, rep registry.Report, o formatOptions) error {
	annotations := o.Trusted
	if annotations == nil {
		annotations = w
	}
	line := func(format string, args ...any) error {
		_, err := io.WriteString(w, guardLine("  "+fmt.Sprintf(format, args...))+"\n")
		return err
	}
	if err := writePreamble(line, rep, plainText, func(verdict string) string { return verdict }); err != nil {
		return err
	}
	// Our own text first, then Tailscale's behind its notice, as in the text layout.
	ours, theirs := splitByTrust(rep.Findings)
	shown := map[string]int{}
	left, noticed := 0, false
	for _, f := range append(ours, theirs...) {
		level := annotationLevel(f.Severity)
		if shown[level] >= maxAnnotations {
			left++
			continue
		}
		shown[level]++
		if f.Untrusted && !noticed {
			noticed = true
			if err := line("%s", registry.UntrustedReasonsNotice); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(annotations, annotation(level, f, o)+"\n"); err != nil {
			return err
		}
	}
	if left > 0 {
		return line("%d more, see the summary", left)
	}
	return nil
}

// annotationLevel is the workflow command for a severity: warning and notice are
// themselves, anything else (error, or a word that is not ours) is an error, because
// a finding is not softened by a spelling nobody expected.
func annotationLevel(severity string) string {
	switch severity {
	case "warning", "notice":
		return severity
	}
	return "error"
}

// annotation is the command line for one finding: ::level properties::data. The file
// property is there only for a path inside the repository; when it is not, the
// location the text layout would print is the start of the message, so that no
// location is lost. The data goes through guardLine too: the markers of the other CI
// systems are acted on in the middle of a line, and this line is not the guard's.
func annotation(level string, f registry.Finding, o formatOptions) string {
	file := ""
	if f.Source != "" && !o.Outside {
		file = repoPath(o.Names[f.Source], o.Dir, o.Root)
	}
	props := make([]string, 0, 4)
	if file != "" {
		props = append(props, "file="+guardLine(propertyEscaper.Replace(file)))
	}
	if f.Line > 0 {
		props = append(props, "line="+strconv.Itoa(f.Line))
	}
	if f.Column > 0 {
		props = append(props, "col="+strconv.Itoa(f.Column))
	}
	props = append(props, "title="+annotationTitle)
	msg := sanitize.Text(f.Message, 0)
	if f.Pointer != "" {
		msg = sanitize.String(f.Pointer, 0) + ": " + msg
	}
	if file == "" {
		if where := findingWhere(f, o, plainText); where != "" {
			msg = where + ": " + msg
		}
	}
	return "::" + level + " " + strings.Join(props, ",") + "::" + guardLine(dataEscaper.Replace(msg))
}

// repoPath is the path from the root of the repository, with forward slashes, when the
// path as typed can be a file of it: a relative path with no .. segment, that is not
// <stdin> and holds no character that is not plain text, below dir, the directory the
// command ran in (relative to the root, empty at the root, and plain text like the path).
// An absolute path is a file of the repository when root, the root as the runner names it,
// is a directory above it; the path from the root is then the path without that prefix
// (a root that is not plain text is a prefix of no path that is).
// Anything else is "": a path outside the repository names nothing the runner can
// annotate, and a name with a line feed in it is nobody's file. Backslashes count as
// separators on every platform, because the path is the one a Windows runner would show.
func repoPath(typed, dir, root string) string {
	if typed == "" || typed == "<stdin>" || sanitize.String(typed, 0) != typed || sanitize.String(dir, 0) != dir {
		return ""
	}
	p := strings.ReplaceAll(typed, `\`, "/")
	if strings.HasPrefix(p, "/") || hasDrive(p) {
		base := strings.TrimRight(strings.ReplaceAll(root, `\`, "/"), "/")
		if (base == "" && root != "/") || !strings.HasPrefix(p, base+"/") {
			return ""
		}
		p, dir = p[len(base)+1:], ""
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == ".." {
			return ""
		}
	}
	if p = path.Clean(p); p == "." {
		return ""
	}
	if dir != "" {
		p = path.Join(dir, p)
	}
	return p
}

// hasDrive says whether p starts with a Windows drive, "C:".
func hasDrive(p string) bool {
	if len(p) < 2 || p[1] != ':' {
		return false
	}
	c := p[0] | 0x20 // lower case, for a letter
	return c >= 'a' && c <= 'z'
}
