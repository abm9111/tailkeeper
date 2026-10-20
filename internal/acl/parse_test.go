package acl

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/tailscale/hujson"
)

func TestParseReadsTheFixturePolicies(t *testing.T) {
	for _, name := range []string{"basic.hujson", "crlf.hujson"} {
		src := fixture(t, name)
		d, err := Parse(context.Background(), src)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d.Len() != len(src) || d.Nodes() < 100 {
			t.Errorf("%s: Len = %d (text %d), Nodes = %d", name, d.Len(), len(src), d.Nodes())
		}
	}
}

// The input rules run before the HuJSON library is called, and each message names the
// cause and the fix. The position is where the cause is.
func TestParseRefusesWhatCannotBeAPolicyFile(t *testing.T) {
	cases := []struct {
		name       string
		in         []byte
		line, col  int
		mentions   []string
		wantNoLine bool
	}{
		{"a UTF-8 byte order mark", fixture(t, "bom.hujson"), 1, 1, []string{"byte order mark", "-Encoding UTF8"}, false},
		{"UTF-16 little endian", fixture(t, "utf16le.hujson"), 1, 1, []string{"UTF-16", "save it as UTF-8"}, false},
		{"UTF-16 big endian", []byte("\xfe\xff\x00{\x00}"), 1, 1, []string{"UTF-16"}, false},
		{"a NUL", []byte("{\n\"a\": \"x\x00y\"}"), 2, 8, []string{"NUL byte", "UTF-16"}, false},
		{"invalid UTF-8 in a string", []byte("{\n\"a\": \"\xff\"}"), 2, 7, []string{"not valid UTF-8", "0xff"}, false},
		{"invalid UTF-8 in a comment", []byte("{} // \xc3(\n"), 1, 7, []string{"not valid UTF-8"}, false},
		{"invalid UTF-8 in a key", []byte("{\"\xe2\x82\": 1}"), 1, 3, []string{"not valid UTF-8"}, false},
	}
	for _, c := range cases {
		_, err := Parse(context.Background(), c.in)
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeInvalid || !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want an invalid *Error", c.name, err)
			continue
		}
		if e.Line != c.line || e.Column != c.col {
			t.Errorf("%s: position %d:%d, want %d:%d (%s)", c.name, e.Line, e.Column, c.line, c.col, e.Message)
		}
		for _, m := range c.mentions {
			if !strings.Contains(e.Message, m) {
				t.Errorf("%s: message %q does not mention %q", c.name, e.Message, m)
			}
		}
	}
}

// A top level that is not an object would run as tests against the live policy.
func TestParseRefusesATopLevelThatIsNotAnObject(t *testing.T) {
	for in, kind := range map[string]string{
		`[{"src":"tag:p","accept":["tag:p:22"]}]`: "an array",
		`"policy"`:    "a string",
		`42`:          "a number",
		`true`:        "a boolean",
		`null`:        "null",
		"// c\n  [1]": "an array",
	} {
		e := parseError(t, in)
		if e.Code != CodeInvalid || !strings.Contains(e.Message, "not "+kind) || !strings.Contains(e.Message, "tests against the live policy") {
			t.Errorf("%q: %+v, want invalid and %q", in, e, kind)
		}
	}
	if e := parseError(t, "// c\n  [1]"); e.Line != 2 || e.Column != 3 {
		t.Errorf("the position is the root's: %d:%d, want 2:3", e.Line, e.Column)
	}
	mustParse(t, "// comment before\n{} // and after\n")
}

// Syntax errors keep the library's message and carry its position, read out of the error
// text; when the text stops matching, the position is unknown and the message is whole.
func TestParseReportsSyntaxErrorsWithTheirPosition(t *testing.T) {
	e := parseError(t, "{\n  \"a\": \"x\n")
	if e.Code != CodeInvalid || e.Line != 3 || e.Column != 1 || e.Message != "parsing string: unexpected EOF" {
		t.Errorf("got %+v", e)
	}
	if got := e.Error(); got != "parsing string: unexpected EOF (line 3, column 1)" {
		t.Errorf("Error() = %q", got)
	}
	e = syntaxError(errors.New("some future wording without a position"))
	if e.Line != 0 || e.Message != "some future wording without a position" || e.Error() != e.Message {
		t.Errorf("an error the regex does not match: %+v", e)
	}
	// A message that quotes the input is cut: one invalid literal must not carry 100 KiB.
	e = parseError(t, `{"a":"`+strings.Repeat("x", 100<<10)+`\q"}`)
	if len(e.Message) > maxMessage+len("\u2026") || !strings.HasSuffix(e.Message, "\u2026") {
		t.Errorf("message of %d bytes was not cut", len(e.Message))
	}
	// The cut falls on a character boundary.
	e = parseError(t, `{"a":"`+strings.Repeat("\u00e9", 400)+`\q"}`)
	if !utf8.ValidString(e.Message) || !strings.HasSuffix(e.Message, "\u00e9\u2026") {
		t.Errorf("a cut message must stay valid UTF-8: %q", e.Message[len(e.Message)-20:])
	}
}

// A kind the table does not name never reads as "null".
func TestKindNameNamesEveryKindAndNeverGuessesNull(t *testing.T) {
	for k, want := range map[hujson.Kind]string{
		'[': "an array", '"': "a string", '0': "a number", 't': "a boolean", 'f': "a boolean",
		'n': "null", '{': "an object", 'x': "a value of another kind",
	} {
		if got := kindName(k); got != want {
			t.Errorf("kindName(%q) = %q, want %q", k, got, want)
		}
	}
}

func TestParseRefusesATextOverTheSizeCap(t *testing.T) {
	big := append([]byte(`{"a":"`), bytes.Repeat([]byte("x"), MaxBytes)...)
	big = append(big, `"}`...)
	_, err := Parse(context.Background(), big)
	if !errors.Is(err, ErrTooComplex) || !strings.Contains(err.Error(), "4194304") {
		t.Errorf("err = %v, want too_complex naming the cap", err)
	}
}

// 1,000 levels are read and 1,001 are refused, with the line of the bracket that passes
// the limit. The top-level object is the first level.
func TestParseRefusesNestingPastTheGuard(t *testing.T) {
	nested := func(levels int) string {
		return strings.Repeat(`{"a":`, levels-1) + `{}` + strings.Repeat("}", levels-1)
	}
	mustParse(t, nested(1000))
	e := parseError(t, "\n"+nested(1001))
	if e.Code != CodeInvalid || e.Line != 2 || !strings.Contains(e.Message, "1000 levels") {
		t.Errorf("1,001 levels: %+v", e)
	}
	e = parseError(t, "{"+strings.Repeat("[", 1001))
	if e.Code != CodeInvalid {
		t.Errorf("a million-bracket style input: %+v", e)
	}
	// The guard reads comments and strings as the parser does.
	mustParse(t, `{"a": "`+strings.Repeat("[", 5000)+`"} // `+strings.Repeat("[", 5000)+"\n")
}

// More values than the cap are refused from the guard's count, before the parser allocates.
func TestParseRefusesMoreValuesThanTheCap(t *testing.T) {
	text := `{"a":[` + strings.Repeat("1,", MaxNodes) + `1]}`
	_, err := Parse(context.Background(), []byte(text))
	if !errors.Is(err, ErrTooComplex) || !strings.Contains(err.Error(), strconv.Itoa(MaxNodes)) {
		t.Errorf("err = %v, want too_complex naming the cap", err)
	}
}

// The work budget and the context are checked as the walk goes.
func TestParseSpendsABudgetAndHonoursTheContext(t *testing.T) {
	src := fixture(t, "basic.hujson")

	old := maxWork
	maxWork = 50
	t.Cleanup(func() { maxWork = old })
	if _, err := Parse(context.Background(), src); !errors.Is(err, ErrTooComplex) || !strings.Contains(err.Error(), "limit of 50 steps") {
		t.Errorf("a budget of 50 steps: err = %v", err)
	}
	maxWork = old

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Parse(ctx, src); !errors.Is(err, context.Canceled) {
		t.Errorf("a context that is done: err = %v", err)
	}

	// A context that is done only after the walk has begun is seen at the next check.
	many := []byte(`{"a":[` + strings.Repeat("1,", 20000) + `1]}`)
	late := &lateContext{Context: context.Background(), okChecks: 1}
	if _, err := Parse(late, many); !errors.Is(err, context.Canceled) {
		t.Errorf("a context that ends during the walk: err = %v", err)
	}
}

// lateContext reports nil from its first okChecks calls to Err and Canceled after that.
type lateContext struct {
	context.Context
	okChecks int
}

func (c *lateContext) Err() error {
	if c.okChecks > 0 {
		c.okChecks--
		return nil
	}
	return context.Canceled
}

// The tree aliases Parse's own copy of the text, so the caller may reuse its buffer.
func TestParseCopiesTheText(t *testing.T) {
	src := []byte(`{"groups": {"group:a": ["a@example.com"]}}`)
	d, err := Parse(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	for i := range src {
		src[i] = 'x'
	}
	if got := string(d.root.Pack()); got != `{"groups": {"group:a": ["a@example.com"]}}` {
		t.Errorf("the tree changed with the caller's buffer: %q", got)
	}
}

// Every value's StartOffset is the offset of its first byte, which is what places a node
// without packing anything. This holds the library to it.
func TestParseOffsetsPointAtTheirValues(t *testing.T) {
	for _, name := range []string{"basic.hujson", "crlf.hujson"} {
		d := mustParse(t, string(fixture(t, name)))
		n := 0
		for v := range d.root.All() {
			n++
			first := d.src[v.StartOffset]
			want := byte(0)
			switch lit := v.Value.(type) {
			case hujson.Literal:
				want = lit[0]
			case *hujson.Object:
				want = '{'
			case *hujson.Array:
				want = '['
			}
			if first != want {
				t.Fatalf("%s: value %d starts at %d with %q, want %q", name, n, v.StartOffset, first, want)
			}
		}
		if n != d.Nodes() {
			t.Errorf("%s: walked %d values, Nodes = %d", name, n, d.Nodes())
		}
	}
}

// Line and column come from one table of line feeds, the way the library counts them.
func TestPositionCountsLinesByLineFeedAndColumnsInBytes(t *testing.T) {
	for _, name := range []string{"basic.hujson", "crlf.hujson", "lone-cr.hujson"} {
		d := mustParse(t, string(fixture(t, name)))
		for off := 0; off <= d.Len(); off += 7 {
			line, col := d.Position(off)
			wantLine, wantCol := position(d.src, off)
			if line != wantLine || col != wantCol {
				t.Fatalf("%s: Position(%d) = %d:%d, the library's formula says %d:%d", name, off, line, col, wantLine, wantCol)
			}
		}
	}
	d := mustParse(t, "{\r\n\"a\": 1,\r\n\"b\": 2}")
	if line, col := d.Position(strings.Index("{\r\n\"a\": 1,\r\n\"b\": 2}", `"b"`)); line != 3 || col != 1 {
		t.Errorf("CRLF: the key on the third line is at %d:%d", line, col)
	}
	d = mustParse(t, "{\r\"a\": 1,\r\"b\": 2}")
	if d.Lines() != 1 {
		t.Errorf("a lone carriage return is whitespace, not a line break: Lines = %d", d.Lines())
	}
	if line, col := d.Position(-5); line != 1 || col != 1 {
		t.Errorf("Position(-5) = %d:%d", line, col)
	}
	if line, col := d.Position(1 << 20); line != 1 || col != d.Len()+1 {
		t.Errorf("Position past the end = %d:%d", line, col)
	}
}
