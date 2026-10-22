package acl

import (
	"bytes"
	"context"
	"regexp"
	"strconv"
	"unicode/utf8"

	"github.com/tailscale/hujson"

	"github.com/abm9111/tailkeeper/internal/guard"
)

const (
	// MaxBytes is the largest text Parse reads: guard.MaxPolicyBytes, the one policy cap of
	// the repository. These are tailkeeper's caps; Tailscale publishes none. The callers
	// apply their own, smaller ones to what they accept (1 MiB over MCP).
	MaxBytes = guard.MaxPolicyBytes

	// MaxNodes is the most values (every member name, member value, element and the root
	// count as one) Parse builds. The cap is sized from the allocation measured at it:
	// parsing costs about 420 bytes of allocation a value (about 0.22 GB at the cap), and a
	// comparison holds two trees and their normal forms. Only the total allocation is
	// pinned (by TestTheNodeCapAndItsMeasuredAllocationArePinnedTogether); peak heap is not
	// measured. A policy of 9-value rules can hold about 58,000 of them. The cap is checked
	// on the guard's count before the parser allocates anything.
	MaxNodes = 1 << 19
)

// Doc is a parsed policy: the text, its HuJSON tree with Go's decoder's reading of repeated
// keys worked out (the server refuses such a text; see the package comment), and what Parse
// found wrong with the structure. A Doc is built by Parse only and is read-only afterwards.
type Doc struct {
	// src is Parse's own copy of the text: the tree aliases it, so the caller's buffer may
	// change after Parse returns.
	src   []byte
	root  hujson.Value
	nodes int
	lines lineIndex

	top      []occurrence     // the top-level members, in document order
	byKey    map[string][]int // sectionKey of a top-level name to its indexes in top
	findings []Finding
	omitted  int
	unknown  []string
	// unknownShown are the unknown names as the caller may see them (see Show), in step with
	// unknown.
	unknownShown []string
	show         Show // how a caller sees text of this policy; nil shows it as it is
}

// Parse reads a policy text. It refuses, in this order and before any call into the HuJSON
// library: a byte order mark, UTF-16, a NUL, invalid UTF-8, a text over MaxBytes, nesting
// over 1,000 levels and more than MaxNodes values. After the parse it refuses a top level
// that is not an object: a JSON array posted to the validate endpoint is run as tests
// against the live policy, and would read as a pass for a proposal nobody validated.
func Parse(ctx context.Context, src []byte) (*Doc, error) { return ParseShown(ctx, src, nil) }

// ParseShown is Parse for a policy whose text a caller may see only through show: every piece
// of the policy that a result quotes (a key, a pointer, a text of a change) is cut after show
// has made it what the caller sees, so that where it is cut tells nothing about the text
// show hides. A nil show leaves the text as it is.
func ParseShown(ctx context.Context, src []byte, show Show) (*Doc, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkEncoding(src); err != nil {
		return nil, err
	}
	if len(src) > MaxBytes {
		// The message does not say how long the text is: a text that stands for logins is longer than
		// the one its caller wrote, and its length would tell how long they are.
		return nil, tooComplex("the policy is more than the %d bytes tailkeeper reads", MaxBytes)
	}
	if err := checkShape(src); err != nil {
		return nil, err
	}
	d := &Doc{src: bytes.Clone(src), show: show}
	root, err := hujson.Parse(d.src)
	if err != nil {
		return nil, syntaxError(err)
	}
	d.root = root
	if _, ok := root.Value.(*hujson.Object); !ok {
		line, col := d.Position(root.StartOffset)
		return nil, invalid(line, col, "the top level must be a JSON object ({...}), not %s: "+
			"a JSON array sent to the validate endpoint is run as tests against the live policy, "+
			"so a proposal in that shape would be reported as passing without being validated", kindName(root.Value.Kind()))
	}
	m := newMeter(ctx)
	if err := d.analyse(m); err != nil {
		return nil, err
	}
	return d, nil
}

// checkShape applies the guard: nesting first, then the number of values.
func checkShape(src []byte) *Error {
	_, e := scanShape(src)
	return e
}

// scanShape is checkShape that also returns the bound the guard found on the number of
// values, for the callers that charge work by it.
func scanShape(src []byte) (int, *Error) {
	r := guard.Scan(src, guard.MaxDepth)
	if r.TooDeep {
		_, col := position(src, r.Offset)
		return 0, invalid(r.Line, col, "the text nests deeper than %d levels of braces and brackets, "+
			"which no policy file does; the parser would run out of stack", guard.MaxDepth)
	}
	if r.NodeBound > MaxNodes {
		return 0, tooComplex("the policy holds more than %d values (a name, a value or an element each); "+
			"tailkeeper does not read documents that large", MaxNodes)
	}
	return r.NodeBound, nil
}

// checkEncoding refuses the encodings a policy file arrives in by accident. Each message
// names the cause and the fix: Windows PowerShell 5.1 writes UTF-16 with a byte order mark
// for ">" and UTF-8 with one for "-Encoding UTF8". HuJSON accepts invalid UTF-8 inside a
// string and Go's decoder then reads U+FFFD, so the text the server compares would not be
// the bytes of the file.
func checkEncoding(src []byte) *Error {
	switch {
	case bytes.HasPrefix(src, []byte("\xef\xbb\xbf")):
		return invalid(1, 1, "the text starts with a UTF-8 byte order mark; save it as UTF-8 without one "+
			"(Windows PowerShell 5.1 adds one with -Encoding UTF8)")
	case bytes.HasPrefix(src, []byte("\xff\xfe")), bytes.HasPrefix(src, []byte("\xfe\xff")):
		return invalid(1, 1, "the text is UTF-16 (it starts with a byte order mark); save it as UTF-8 "+
			"(Windows PowerShell 5.1 writes UTF-16 for >)")
	}
	if i := bytes.IndexByte(src, 0); i >= 0 {
		line, col := position(src, i)
		return invalid(line, col, "the text holds a NUL byte; if the file was saved as UTF-16 "+
			"(Windows PowerShell 5.1 does for >), save it as UTF-8")
	}
	if !utf8.Valid(src) {
		i := 0
		for i < len(src) {
			r, n := utf8.DecodeRune(src[i:])
			if r == utf8.RuneError && n == 1 {
				break
			}
			i += n
		}
		line, col := position(src, i)
		return invalid(line, col, "the text is not valid UTF-8 (byte 0x%02x); save it as UTF-8", src[i])
	}
	return nil
}

// positionRE reads the position out of the HuJSON library's error text, which is the only
// place the library puts it. It fails closed: if the text stops matching, the position is
// unknown and the message is still shown whole. TestCharacteriseHuJSON pins the format.
var positionRE = regexp.MustCompile(`^hujson: line ([0-9]+), column ([0-9]+): `)

func syntaxError(err error) *Error {
	text := err.Error()
	m := positionRE.FindStringSubmatch(text)
	if m == nil {
		return invalid(0, 0, "%s", text)
	}
	line, _ := strconv.Atoi(m[1])
	col, _ := strconv.Atoi(m[2])
	return invalid(line, col, "%s", text[len(m[0]):])
}

// position is the line and column (from 1; a line ends at "\n", a column counts bytes) of
// a byte offset, the way the HuJSON parser and the server count them. A lone carriage
// return is whitespace, not a line break. It is for the error path; Doc.Position serves
// many lookups from an index.
func position(src []byte, off int) (line, col int) {
	off = min(max(off, 0), len(src))
	line = 1 + bytes.Count(src[:off], []byte("\n"))
	col = 1 + off - (bytes.LastIndexByte(src[:off], '\n') + 1)
	return line, col
}

func kindName(k hujson.Kind) string {
	switch k {
	case '[':
		return "an array"
	case '"':
		return "a string"
	case '0':
		return "a number"
	case 't', 'f':
		return "a boolean"
	case 'n':
		return "null"
	case '{':
		return "an object"
	}
	return "a value of another kind"
}
