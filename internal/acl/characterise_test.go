package acl

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tailscale/hujson"
)

// TestCharacteriseHuJSON pins what the pinned github.com/tailscale/hujson accepts and
// rejects, the exact error text it produces (the engine reads the position out of that
// text with positionRE, because the library exposes no structured position), and what the
// engine does with the same input. go.mod pins an untagged pseudo-version that Dependabot
// will move: if a row changes, this test fails and says which, and the engine's input
// rules are reviewed before the bump merges.
func TestCharacteriseHuJSON(t *testing.T) {
	deepArrays := strings.Repeat("[", 5000) + strings.Repeat("]", 5000)
	deepObjects := strings.Repeat(`{"a":`, 1001) + `1` + strings.Repeat("}", 1001)
	rows := []struct {
		name string
		in   string
		// lib is the library's error text, "" when it accepts the input.
		lib string
		// code is the engine's verdict: "" accepted, else the error code; line and col
		// are its position (0 when it has none).
		code      Code
		line, col int
	}{
		{"unterminated string", `{"a": "x`, "hujson: line 1, column 9: parsing string: unexpected EOF", CodeInvalid, 1, 9},
		{"trailing garbage", `{"a":1} x`, "hujson: line 1, column 9: invalid character 'x' after top-level value", CodeInvalid, 1, 9},
		{"bad escape", `{"a":"\q"}`, `hujson: line 1, column 6: invalid literal: "\q"`, CodeInvalid, 1, 6},
		{"lone surrogate", `{"a":"\ud800"}`, "", "", 0, 0},
		{"NUL in a string", "{\"a\":\"x\x00y\"}", "hujson: line 1, column 6: invalid literal: \"x\x00y\"", CodeInvalid, 1, 8},
		{"NUL after the value", "{\"a\":1}\x00", "hujson: line 1, column 8: invalid character '\\u0000' after top-level value", CodeInvalid, 1, 8},
		{"UTF-8 byte order mark", "\xef\xbb\xbf{}", "hujson: line 1, column 1: invalid character '\\ufeff' at start of value", CodeInvalid, 1, 1},
		{"unterminated block comment", `{} /* x`, "hujson: line 1, column 4: parsing comment: unexpected EOF", CodeInvalid, 1, 4},
		{"line comment ended by the end of the text", `{} // x`, "hujson: line 1, column 4: parsing comment: unexpected EOF", CodeInvalid, 1, 4},
		{"line comment ended by a line feed", "{} // x\n", "", "", 0, 0},
		{"duplicate keys", `{"a":1,"a":2}`, "", "", 0, 0},
		{"a huge number", `{"a":1e999999999}`, "", "", 0, 0},
		{"invalid UTF-8 in a string", "{\"a\":\"\xff\"}", "", CodeInvalid, 1, 7},
		{"invalid UTF-8 in a comment", "{} // \xff\n", "hujson: line 1, column 4: invalid UTF-8 in comment", CodeInvalid, 1, 7},
		{"a top-level array", `[1]`, "", CodeInvalid, 1, 1},
		{"empty text", ``, "hujson: line 1, column 1: parsing value: unexpected EOF", CodeInvalid, 1, 1},
		{"a comment and nothing else", "// x\n", "hujson: line 2, column 1: parsing value: unexpected EOF", CodeInvalid, 2, 1},
		{"a trailing comma", `{"a":1,}`, "", "", 0, 0},
		{"U+2028 in a line comment", "{} // a\u2028b\n", "hujson: line 1, column 8: invalid character '\\u2028' in line comment", CodeInvalid, 1, 8},
		{"a leading plus", `{"a":+1}`, "hujson: line 1, column 6: invalid literal: +1", CodeInvalid, 1, 6},
		{"single quotes", `{'a':1}`, `hujson: line 1, column 2: invalid character '\'' at start of value`, CodeInvalid, 1, 2},
		{"an unquoted key", `{a:1}`, "hujson: line 1, column 2: invalid literal: a", CodeInvalid, 1, 2},
		{"a missing colon", `{"a" 1}`, "hujson: line 1, column 6: invalid character '1' after object name", CodeInvalid, 1, 6},
		{"two top-level values", `{} {}`, "hujson: line 1, column 4: invalid character '{' after top-level value", CodeInvalid, 1, 4},
		{"a hexadecimal number", `{"a":0x1}`, "hujson: line 1, column 6: invalid literal: 0x1", CodeInvalid, 1, 6},
		{"a leading zero", `{"a":01}`, "hujson: line 1, column 6: invalid literal: 01", CodeInvalid, 1, 6},
		{"a tab inside a string", "{\"a\":\"x\ty\"}", "hujson: line 1, column 6: invalid literal: \"x\ty\"", CodeInvalid, 1, 6},
		{"5,000 levels of arrays", deepArrays, "", CodeInvalid, 1, 1001},
		{"1,001 levels of objects", deepObjects, "", CodeInvalid, 1, 5001},
	}
	for _, r := range rows {
		_, err := hujson.Parse([]byte(r.in))
		switch {
		case r.lib == "" && err != nil:
			t.Errorf("%s: the library now rejects it: %v", r.name, err)
		case r.lib != "" && err == nil:
			t.Errorf("%s: the library now accepts it", r.name)
		case r.lib != "" && err.Error() != r.lib:
			t.Errorf("%s: the library's error text changed:\n got  %q\n want %q", r.name, err.Error(), r.lib)
		}

		_, err = Parse(context.Background(), []byte(r.in))
		var e *Error
		switch {
		case r.code == "" && err != nil:
			t.Errorf("%s: Parse rejects it: %v", r.name, err)
		case r.code != "" && !errors.As(err, &e):
			t.Errorf("%s: Parse = %v, want a %s error", r.name, err, r.code)
		case r.code != "" && (e.Code != r.code || e.Line != r.line || e.Column != r.col):
			t.Errorf("%s: Parse error is %s at %d:%d, want %s at %d:%d (%s)", r.name, e.Code, e.Line, e.Column, r.code, r.line, r.col, e.Message)
		}
	}
}

// The position regex fails closed: text that does not start with the library's position
// leaves the position unknown and the message whole.
func TestPositionRegexFailsClosed(t *testing.T) {
	for _, text := range []string{
		"hujson: line one, column 2: x",
		"hujson: at line 1, column 2: x",
		"line 1, column 2: x",
		"hujson: line 1, column 2 x",
	} {
		if e := syntaxError(errors.New(text)); e.Line != 0 || e.Column != 0 || e.Message != text {
			t.Errorf("%q: %+v", text, e)
		}
	}
	e := syntaxError(errors.New("hujson: line 12, column 345: invalid literal: x"))
	if e.Line != 12 || e.Column != 345 || e.Message != "invalid literal: x" {
		t.Errorf("a matching text: %+v", e)
	}
}
