package cli

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The three policy files a Windows user sends to the command line, kept byte for byte in
// testdata/policies (.gitattributes leaves everything under testdata alone): one saved by
// Windows PowerShell with a byte order mark, one with CRLF line ends, and one whose name has
// a space. The last two repeat a key at line 4, column 2, so that the line the command
// reports shows how the file was counted and the path it prints shows how it was typed.
const (
	bomFile    = "testdata/policies/bom.hujson"
	crlfFile   = "testdata/policies/crlf.hujson"
	spacedFile = "testdata/policies/two words.hujson"
)

func TestFixturesKeepTheirBytes(t *testing.T) {
	bom, crlf, spaced := mustRead(t, bomFile), mustRead(t, crlfFile), mustRead(t, spacedFile)
	if !bytes.HasPrefix(bom, []byte{0xef, 0xbb, 0xbf}) {
		t.Errorf("bom.hujson starts %x, want ef bb bf", bom[:3])
	}
	if !bytes.Contains(crlf, []byte("\r\n")) || bytes.Count(crlf, []byte("\n")) != bytes.Count(crlf, []byte("\r\n")) {
		t.Errorf("crlf.hujson must end every line with CR LF: %d line feeds, %d CR LF", bytes.Count(crlf, []byte("\n")), bytes.Count(crlf, []byte("\r\n")))
	}
	if bytes.Contains(spaced, []byte("\r")) || !strings.Contains(spacedFile, " ") {
		t.Errorf("two words.hujson must have a space in its name and no carriage return in it")
	}
	// Nothing in them names a host other than the documentation domains.
	host := regexp.MustCompile(`[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.(?:com|org|net|io|dev|ai|app)\b`)
	for _, f := range [][]byte{bom, crlf, spaced} {
		for _, h := range host.FindAll(f, -1) {
			if s := string(h); s != "example.com" && s != "example.org" && !strings.HasSuffix(s, ".example.com") && !strings.HasSuffix(s, ".example.org") {
				t.Errorf("a fixture names the host %q, not example.com or example.org", s)
			}
		}
	}
	// Every file of the directory is one of the three, so that a fixture added without a
	// property asserted here is noticed.
	entries, err := os.ReadDir("testdata/policies")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, "|") != "bom.hujson|crlf.hujson|two words.hujson" {
		t.Errorf("testdata/policies holds %v", names)
	}
	// And git keeps them as they are, whatever the checkout's line-end setting is.
	attrs := mustRead(t, "../../.gitattributes")
	if !bytes.Contains(attrs, []byte("**/testdata/** -text")) {
		t.Error(".gitattributes no longer leaves testdata byte for byte")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A file saved with a byte order mark is invalid, found before anything is sent, with the
// reason and the way out: save it as UTF-8 without one.
func TestABOMFileIsInvalidWithTheFix(t *testing.T) {
	h := newHarness(t, nil)
	if code := h.run("acl", "validate", "--offline", "--from", bomFile); code != 2 {
		t.Fatalf("exit %d, want 2: %s", code, h.err)
	}
	want := bomFile + ":1:1: error: the text starts with a UTF-8 byte order mark; save it as UTF-8 without one (Windows PowerShell 5.1 adds one with -Encoding UTF8)\n"
	if !strings.Contains(h.out.String(), want) || !strings.HasPrefix(h.out.String(), "INVALID · 1 problem found before anything was sent to Tailscale\n") {
		t.Errorf("output:\n%s\nwant a line %q", h.out, want)
	}
	h = newHarness(t, nil)
	if code := h.run("--json", "acl", "validate", "--offline", "--from", bomFile); code != 2 {
		t.Fatalf("json: exit %d", code)
	}
	if out := validateJSON(t, h.out.String()); len(out.Errors) != 1 || out.Errors[0].Kind != "encoding" || out.Errors[0].Line != 1 || out.Errors[0].Column != 1 {
		t.Errorf("errors = %+v, want one encoding error at 1:1", out.Errors)
	}
}

// Lines are counted by line feed: a file with CRLF line ends puts the repeated key on the
// same line and column as the same file with LF, and the command says how it counts.
func TestLinesAreCountedByLineFeedOnACRLFFile(t *testing.T) {
	var places [2]string
	for i, file := range []string{crlfFile, spacedFile} {
		h := newHarness(t, nil)
		if code := h.run("acl", "validate", "--offline", "--from", file); code != 2 {
			t.Fatalf("%s: exit %d, want 2: %s", file, code, h.err)
		}
		out := h.out.String()
		want := file + ":4:2: error: /groups: Tailscale refuses a key written twice here (also at line 2)\n"
		if !strings.Contains(out, want) || !strings.Contains(out, "notice: Lines are counted by line feed and columns in bytes") {
			t.Errorf("%s:\n%s\nwant a line %q and the notice", file, out, want)
		}
		m := regexp.MustCompile(regexp.QuoteMeta(file) + `:([0-9]+:[0-9]+): error`).FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("%s: no located error in\n%s", file, out)
		}
		places[i] = m[1]
	}
	if places[0] != places[1] || places[0] != "4:2" {
		t.Errorf("the CRLF file reports %q and the LF file %q, want both 4:2", places[0], places[1])
	}
}

// A path with a space is printed as it was typed, in every layout, and the GitHub formatter
// keeps the space in the file property: only a comma, a colon and a percent are escaped.
func TestAPathWithSpacesAppearsAsTyped(t *testing.T) {
	for format, want := range map[string]string{
		"text":     spacedFile + ":4:2: error: /groups: ",
		"github":   "::error file=" + spacedFile + ",line=4,col=2,title=tailkeeper::/groups: ",
		"markdown": "- `" + spacedFile + ":4:2` error: `/groups`: ",
	} {
		h := newHarness(t, nil)
		args := []string{"acl", "validate", "--offline", "--from", spacedFile}
		if format != "text" {
			args = append([]string{"acl", "validate", "--format", format}, args[2:]...)
		}
		if code := h.run(args...); code != 2 || !strings.Contains(h.out.String(), want+"Tailscale refuses a key written twice here") {
			t.Errorf("%s: exit %d, output:\n%s\nwant a line holding %q", format, code, h.out, want)
		}
	}
}
