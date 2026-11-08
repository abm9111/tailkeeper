package sanitize

import (
	"strings"

	"github.com/abm9111/tailkeeper/internal/tripwire"
)

// maskWindow is the most bytes of one untrusted string that masking and credential
// redaction read when the string is shown under a byte cap (VIGIL-PERF-001). A result
// shows at most DefaultMax bytes of such a string, so reading megabytes of a hostile one
// to mask text nobody sees costs time and memory for nothing: a 3.9 MiB local status
// once peaked at about 158 MB. The window is sixty-four times the cap, so that masking
// shrinking the text (a long local part becomes one character) still leaves the cap's
// worth of it in an ordinary string.
const maskWindow = 64 << 10

// cutBytes are the bytes at which headOf cuts: none of them is part of an email address
// (local part, at sign in any of its spellings, domain), of an IP address run or of a
// credential shape, so text before one is masked and redacted as it is whether or not
// the text after it is read. Space, tab, comma, parentheses, angle brackets and the closing
// square bracket; a quote is handled apart (see headOf), and a line end is a cut of its own
// kind. The opening square bracket is not one: with a privacy key, "[p:" is rewritten to a
// brace escape that is a byte of a local part ("amy[p:x@example.com" is one address), so
// "amy" before it is part of that address and the cut would show it.
const cutBytes = " \t,()<>]"

// headOf returns the part of s that masking reads when s is shown capped, and whether
// it dropped the rest. A string of window bytes or fewer is returned whole: it is read
// exactly as before. A longer one is cut before the last byte, at or before the window's
// end, where masking cannot be reading across the cut:
//
//   - A line end (LF or CR) is such a byte: no address, quoted word, run of address
//     characters or credential shape reaches across one.
//   - Another cut byte (cutBytes) is such a byte unless a double quote has opened on the
//     line before it, because a quoted local part ("amy smith"@example.com) may hold the
//     byte, and a quoted word is read back from its closing quote to an opening one on
//     the same line. Any quote earlier on the line withholds the line's cut bytes; the
//     cut then falls on a line end or before the line.
//
// The cut falls before the byte, so the head ends where the text it holds ends: a token
// that the window's end runs through is dropped whole, never shown half-masked. If no
// byte of the window is a place to cut, the head is empty; the caller shows the notice
// that something was cut and nothing else. Text that has no cut byte in 64 KiB is not
// prose, and that is the price of a bound that holds for every input.
//
// The head is masked and redacted to the same text as the start of the whole string,
// followed by the byte the cut stands before: TestHeadOfIsMaskedAsThePrefixOfTheWhole
// states it as a property over generated text, and the fuzz targets of this package seed
// it. window <= 0 reads everything.
func headOf(s string, window int) (head string, cut bool) {
	if window <= 0 || len(s) <= window {
		return s, false
	}
	best := 0
	quoted := false // a double quote has been seen on the current line
	for i := 0; i <= window; i++ {
		switch c := s[i]; {
		case c == '\n' || c == '\r':
			best, quoted = i, false
		case c == '"':
			quoted = true
		case !quoted && strings.IndexByte(cutBytes, c) >= 0:
			best = i
		}
	}
	return s[:best], true
}

// Shown is an untrusted string as Fields shows it, for a caller that counts what a result
// will show: credential shapes replaced, invisible characters escaped, cut to limit bytes,
// and read through the window (headOf) like every untrusted string.
func Shown(s string, limit int) string { return shownUntrusted(s, limit) }

// shownUntrusted is an untrusted string as Fields shows it: the part of it that
// masking read (headOf), then a notice that the rest was dropped if it was, credential
// shapes replaced, invisible characters escaped, and the whole cut to limit bytes.
func shownUntrusted(s string, limit int) string {
	head, cut := s, false
	if limit > 0 {
		head, cut = headOf(s, maskWindow)
	}
	if cut {
		head += truncatedSuffix
	}
	return String(tripwire.Redact(head), limit)
}
