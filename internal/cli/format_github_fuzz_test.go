package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/abm9111/tailkeeper/internal/registry"
)

// annotationGrammar is every line the GitHub formatter writes to the writer that the
// guard does not touch: a command from a short list, properties whose values hold no
// comma, colon or line end, and data that holds no line end.
var annotationGrammar = regexp.MustCompile(`^::(error|warning|notice)( [a-z]+=[^,:\r\n]*(,[a-z]+=[^,:\r\n]*)*)?::[^\r\n]*$`)

// annotationsWanted is the number of annotations a list of findings gets, counted on
// its own: a severity that is not warning or notice is an error, and no more than ten
// of a kind are written.
func annotationsWanted(findings []registry.Finding) int {
	seen := map[string]int{}
	want := 0
	for _, f := range findings {
		level := "error"
		if f.Severity == "warning" || f.Severity == "notice" {
			level = f.Severity
		}
		if seen[level] < 10 {
			seen[level]++
			want++
		}
	}
	return want
}

// startsACommand says whether a runner would read a line as a command: after white
// space, it starts with :: (GitHub) or ##[ (Azure Pipelines).
func startsACommand(line string) bool {
	rest := strings.TrimLeftFunc(line, unicode.IsSpace)
	return strings.HasPrefix(rest, "::") || strings.HasPrefix(rest, "##[")
}

// The seeds of the fuzz target are fixtures, and a fixture that stopped holding what it was
// written to hold would still replay green: a seed emptied by an edit, or one that a change
// of the target's parameters left unread. They are the texts a pull request author could
// write: there are at least ten, with no upper bound because every input the fuzzer finds
// and keeps joins them and a bound would fail the commit that records a find; every one has
// the arguments of the target; and three kinds are there: a text with an Azure Pipelines
// error command ("##[error]x") in it, a text with a property of its own (",title=") in it,
// and a line feed inside a file name.
func TestTheFuzzSeedsAreTheTextsAPullRequestAuthorCouldWrite(t *testing.T) {
	dir := filepath.Join("testdata", "fuzz", "FuzzGitHubFormatter")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 10 {
		t.Errorf("%d seeds, want at least 10", len(entries))
	}
	kinds := []string{"string", "string", "string", "string", "string", "string", "string", "int", "int", "bool", "uint8"}
	var azure, title, lineFeedInName bool
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
		if lines[0] != "go test fuzz v1" || len(lines) != 1+len(kinds) {
			t.Errorf("%s: %d lines, want the header and %d values", e.Name(), len(lines), len(kinds))
			continue
		}
		var strs []string
		for i, l := range lines[1:] {
			if !strings.HasPrefix(l, kinds[i]+"(") || !strings.HasSuffix(l, ")") {
				t.Errorf("%s: value %d is %q, want a %s", e.Name(), i+1, l, kinds[i])
				continue
			}
			if kinds[i] == "string" {
				s, err := strconv.Unquote(l[len("string(") : len(l)-1])
				if err != nil {
					t.Errorf("%s: value %d: %v", e.Name(), i+1, err)
				}
				strs = append(strs, s)
			}
		}
		for _, s := range strs {
			azure = azure || strings.Contains(s, "##[error]x")
			title = title || strings.Contains(s, ",title=")
		}
		lineFeedInName = lineFeedInName || len(strs) > 4 && strings.Contains(strs[4], "\n")
	}
	if !azure || !title || !lineFeedInName {
		t.Errorf("seeds with ##[error]x: %v, with ,title=: %v, with a line feed in the file name: %v", azure, title, lineFeedInName)
	}
}

// FuzzGitHubFormatter holds the property the format exists for: whatever the report
// holds, a line that a CI runner would act on is a line the formatter wrote on
// purpose, and it has the shape of an annotation. With the annotation writer recorded
// apart from the guarded one, every line of the stream that starts with :: or ##[
// is an annotation of the recorded writer and matches the grammar, their number is the
// number of findings (ten of a severity at most), the layout lines on the guarded writer
// start none, and no line holds a marker of another CI system or a character that moves
// a terminal. The seeds are the texts a pull request author could write
// (testdata/fuzz) and a message of 1 MiB.
func FuzzGitHubFormatter(f *testing.F) {
	f.Add("v", "c", "error", "from", "policy.hujson", "", strings.Repeat("m", 1<<20), 1, 1, false, uint8(1))
	f.Fuzz(func(t *testing.T, verdict, class, severity, source, name, pointer, message string, line, col int, untrusted bool, copies uint8) {
		rep := registry.Report{
			Verdict:    verdict,
			NotChecked: []string{verdict, class},
			Classes:    []registry.ClassCount{{Class: class, Count: line, Expected: untrusted}},
		}
		for i := 0; i < int(copies)%26; i++ {
			rep.Findings = append(rep.Findings, registry.Finding{Severity: severity, Source: source, Line: line, Column: col,
				Pointer: pointer, Message: message, Untrusted: untrusted != (i%3 == 0)})
		}
		rep.Findings = append(rep.Findings,
			registry.Finding{Severity: "warning", Source: source, Message: message},
			registry.Finding{Severity: "notice", Pointer: pointer, Message: verdict, Untrusted: true})
		names := map[string]string{source: name}
		want := annotationsWanted(rep.Findings)

		// As the command line has it: the layout through the guard, the annotations
		// to the writer behind it, which this test also records on its own.
		var out, ann bytes.Buffer
		g := &lineGuard{w: &out}
		if err := formatGitHub(g, rep, formatOptions{Names: names, Dir: class, Trusted: io.MultiWriter(&out, &ann)}); err != nil {
			t.Fatal(err)
		}
		if err := g.Flush(); err != nil {
			t.Fatal(err)
		}
		emitted := map[string]int{}
		for _, l := range splitLines(ann.String()) {
			if !annotationGrammar.MatchString(l) {
				t.Fatalf("an annotation off the grammar: %q", l)
			}
			emitted[l]++
		}
		if n := len(splitLines(ann.String())); n != want {
			t.Fatalf("%d annotations, want %d", n, want)
		}
		acted := 0
		for _, l := range splitLines(out.String()) {
			if !startsACommand(l) {
				continue
			}
			acted++
			if emitted[l] == 0 {
				t.Fatalf("a line a runner would act on that the formatter did not write as an annotation: %q", l)
			}
			emitted[l]--
		}
		if acted != want {
			t.Fatalf("%d lines a runner would act on, want %d", acted, want)
		}
		if bytes.ContainsAny(out.Bytes(), "\r\x1b") || bytes.Contains(out.Bytes(), []byte("\xe2\x80\xae")) ||
			bytes.Contains(out.Bytes(), []byte("##vso[")) || bytes.Contains(out.Bytes(), []byte("##teamcity[")) {
			t.Fatalf("the output holds a character or a marker that acts on its reader: %q", out.String())
		}

		// The formatter's own escaping, with no guard behind it: the layout lines
		// start no command by themselves, and the annotations are the same.
		var plain, ann2 bytes.Buffer
		if err := formatGitHub(&plain, rep, formatOptions{Names: names, Dir: class, Trusted: &ann2}); err != nil {
			t.Fatal(err)
		}
		if ann2.String() != ann.String() {
			t.Fatalf("the annotations differ with and without the guard:\n%q\n%q", ann2.String(), ann.String())
		}
		for _, l := range splitLines(plain.String()) {
			if startsACommand(l) || strings.Contains(l, "##vso[") || strings.Contains(l, "##teamcity[") {
				t.Fatalf("a layout line the formatter wrote acts on a runner: %q", l)
			}
		}
	})
}
