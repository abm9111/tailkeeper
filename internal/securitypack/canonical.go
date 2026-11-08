// Package securitypack contains low-level building blocks for security reports.
//
// canonical.go is deliberately only a streaming canonical JSON writer. It has
// no schema, decoder, digest or public facade. Callers (a future typed codec)
// decide which fields exist; this writer only enforces JSON grammar, key
// ordering and the output-byte meter. The complete document is never built in
// memory: bytes are streamed to the supplied io.Writer, which may be a hash
// writer.
package securitypack

import (
	"encoding/base64"
	"errors"
	"io"
	"time"

	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tripwire"
)

// MaxCanonBytes is the default document budget a typed codec should pass to
// newCanonEncoder. The encoder itself enforces only the per-writer limit its
// caller supplies; it does not independently clamp arbitrary limits to this
// value.
const MaxCanonBytes = 64 << 20

const (
	// maxCanonDepth bounds the frame stack. Depth 12 is accepted, depth 13 is
	// refused.
	maxCanonDepth = 12

	// maxCanonBinary is a decoded-byte limit for binary values. Its encoded
	// form is larger but is still metered against the output limit.
	maxCanonBinary = 4 << 20

	// canonChunk is a fixed scratch size. It is never derived from the output
	// limit or from the size of any value.
	canonChunk = 1024

	// canonBinaryChunk is a multiple of three so chunked standard base64
	// encoding never needs cross-chunk state.
	canonBinaryChunk = 768
)

// Stable errors. Their text is fixed and must never be built from supplied
// keys, strings, bytes, values or writer error text.
var (
	errCanonInvalid  = errors.New("securitypack: invalid canonical JSON operation")
	errCanonTooLarge = errors.New("securitypack: canonical JSON exceeds output limit")
)

type canonFrameKind uint8

const (
	canonObject canonFrameKind = iota + 1
	canonArray
)

// canonFrame is one open container. Only maxCanonDepth frames exist, in a fixed
// array, so nesting depth cannot grow the writer's memory.
type canonFrame struct {
	kind       canonFrameKind
	needComma  bool
	pendingKey bool
	keyCount   int
	lastKey    [security.MaxTextBytes]byte
	lastKeyLen int
}

// canonEncoder streams one canonical JSON value to w while metering every
// output byte. It holds at most maxCanonDepth frames, one bounded key copy per frame
// and a few fixed scratch buffers. It never buffers the document.
//
// Errors are sticky. After the first semantic or writer error every call
// returns that error and no further bytes are written. A successful finish is
// the only terminal state; every call after it returns errCanonInvalid.
type canonEncoder struct {
	w       io.Writer
	limit   int64
	written int64

	frames [maxCanonDepth]canonFrame
	depth  int
	buf    [canonChunk]byte
	scan   [security.MaxTextBytes]byte

	rootStarted  bool
	rootComplete bool
	finished     bool
	err          error
}

// newCanonEncoder returns a writer with a hard output budget of limit bytes.
// A nil writer or a negative limit fails closed on the first operation. A zero
// limit is legal and permits no output at all.
func newCanonEncoder(w io.Writer, limit int64) *canonEncoder {
	e := &canonEncoder{w: w, limit: limit}
	if w == nil || limit < 0 {
		e.err = errCanonInvalid
	}
	return e
}

func (e *canonEncoder) ready() error {
	if e.err != nil {
		return e.err
	}
	if e.finished {
		return errCanonInvalid
	}
	return nil
}

// fail latches err as the first error and returns the latched error.
func (e *canonEncoder) fail(err error) error {
	if e.err == nil {
		e.err = err
	}
	return e.err
}

// need reports whether n more bytes fit in the output budget without writing
// anything. It separates the byte budget (errCanonTooLarge) from semantic
// invalidity (errCanonInvalid) and latches the first failure.
func (e *canonEncoder) need(n int64) error {
	if n < 0 {
		return e.fail(errCanonInvalid)
	}
	if n > e.limit-e.written {
		return e.fail(errCanonTooLarge)
	}
	return nil
}

// write is the only place bytes reach w. It meters actual bytes, treats a
// short nil-error write as io.ErrShortWrite, and preserves writer errors so
// callers can identify them with errors.Is. Once an error is latched, no
// further write is attempted.
func (e *canonEncoder) write(p []byte) error {
	if e.err != nil {
		return e.err
	}
	if len(p) == 0 {
		return nil
	}
	if int64(len(p)) > e.limit-e.written {
		return e.fail(errCanonTooLarge)
	}
	n, err := e.w.Write(p)
	e.written += int64(n)
	if err != nil {
		return e.fail(err)
	}
	if n != len(p) {
		return e.fail(io.ErrShortWrite)
	}
	return nil
}

func (e *canonEncoder) writeByte(b byte) error {
	e.buf[0] = b
	return e.write(e.buf[:1])
}

// writeString copies through a fixed buffer so a very large key does not need
// a same-sized temporary allocation.
func (e *canonEncoder) writeString(s string) error {
	for len(s) > 0 {
		n := copy(e.buf[:], s)
		if err := e.write(e.buf[:n]); err != nil {
			return err
		}
		s = s[n:]
	}
	return nil
}

// writeEscapedContent writes the bytes of a validated text value. Only double
// quote and backslash are escaped; '<', '>', '&', '/' and all valid non-ASCII
// UTF-8 stay literal. Work is done through one fixed-size chunk.
func (e *canonEncoder) writeEscapedContent(s string) error {
	buf := e.buf[:]
	n := 0
	flush := func() error {
		if n == 0 {
			return nil
		}
		err := e.write(buf[:n])
		n = 0
		return err
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' || c == '\\' {
			if n+2 > len(buf) {
				if err := flush(); err != nil {
					return err
				}
			}
			buf[n] = '\\'
			buf[n+1] = c
			n += 2
			continue
		}
		if n+1 > len(buf) {
			if err := flush(); err != nil {
				return err
			}
		}
		buf[n] = c
		n++
	}
	return flush()
}

// canonEscapedLen returns the byte length of s once inside JSON quotes. The
// caller has already bounded s with security.ValidText (4096 bytes).
func canonEscapedLen(s string) int64 {
	n := int64(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			n++
		}
	}
	return n
}

func validCanonKey(name string) bool {
	if len(name) == 0 || len(name) > security.MaxTextBytes {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			continue
		}
		return false
	}
	return true
}

// valuePrologue checks that a value is legal where it is about to be written.
// It returns whether an array separator comma is needed. Opening a container
// marks the root as started here; a scalar root is completed by deliverValue.
// A root container is completed when its closing byte is written.
func (e *canonEncoder) valuePrologue() (bool, error) {
	if err := e.ready(); err != nil {
		return false, err
	}
	if e.depth == 0 {
		if e.rootStarted {
			return false, e.fail(errCanonInvalid)
		}
		e.rootStarted = true
		return false, nil
	}
	top := &e.frames[e.depth-1]
	if top.kind == canonObject {
		if !top.pendingKey {
			return false, e.fail(errCanonInvalid)
		}
		return false, nil
	}
	return top.needComma, nil
}

// deliverValue records that a value has been delivered to its parent. A
// container calls this when it opens (complete=false), never when it closes,
// so a container is counted exactly once as a parent value.
func (e *canonEncoder) deliverValue(complete bool) {
	if e.depth == 0 {
		if complete {
			e.rootComplete = true
		}
		return
	}
	top := &e.frames[e.depth-1]
	if top.kind == canonObject {
		top.pendingKey = false
	}
	top.needComma = true
}

func (e *canonEncoder) beginObject() error {
	if err := e.ready(); err != nil {
		return err
	}
	if e.depth >= maxCanonDepth {
		return e.fail(errCanonInvalid)
	}
	comma, err := e.valuePrologue()
	if err != nil {
		return err
	}
	prefix := int64(0)
	if comma {
		prefix = 1
	}
	if err := e.need(prefix + 1); err != nil {
		return err
	}
	if comma {
		if err := e.writeByte(','); err != nil {
			return err
		}
	}
	if err := e.writeByte('{'); err != nil {
		return err
	}
	e.deliverValue(false)
	e.frames[e.depth] = canonFrame{kind: canonObject}
	e.depth++
	return nil
}

func (e *canonEncoder) endObject() error {
	if err := e.ready(); err != nil {
		return err
	}
	if e.depth == 0 {
		return e.fail(errCanonInvalid)
	}
	top := &e.frames[e.depth-1]
	if top.kind != canonObject || top.pendingKey {
		return e.fail(errCanonInvalid)
	}
	if err := e.need(1); err != nil {
		return err
	}
	if err := e.writeByte('}'); err != nil {
		return err
	}
	e.depth--
	e.frames[e.depth] = canonFrame{}
	if e.depth == 0 {
		e.rootComplete = true
	}
	return nil
}

func (e *canonEncoder) beginArray() error {
	if err := e.ready(); err != nil {
		return err
	}
	if e.depth >= maxCanonDepth {
		return e.fail(errCanonInvalid)
	}
	comma, err := e.valuePrologue()
	if err != nil {
		return err
	}
	prefix := int64(0)
	if comma {
		prefix = 1
	}
	if err := e.need(prefix + 1); err != nil {
		return err
	}
	if comma {
		if err := e.writeByte(','); err != nil {
			return err
		}
	}
	if err := e.writeByte('['); err != nil {
		return err
	}
	e.deliverValue(false)
	e.frames[e.depth] = canonFrame{kind: canonArray}
	e.depth++
	return nil
}

func (e *canonEncoder) endArray() error {
	if err := e.ready(); err != nil {
		return err
	}
	if e.depth == 0 {
		return e.fail(errCanonInvalid)
	}
	if e.frames[e.depth-1].kind != canonArray {
		return e.fail(errCanonInvalid)
	}
	if err := e.need(1); err != nil {
		return err
	}
	if err := e.writeByte(']'); err != nil {
		return err
	}
	e.depth--
	e.frames[e.depth] = canonFrame{}
	if e.depth == 0 {
		e.rootComplete = true
	}
	return nil
}

func (f *canonFrame) validNextKey(name string) bool {
	return validCanonKey(name) && (f.keyCount == 0 || name > string(f.lastKey[:f.lastKeyLen]))
}

// key writes an object member name. Names are 1 to security.MaxTextBytes ASCII [a-z0-9_] bytes and must arrive
// in strictly increasing byte order, which makes duplicate and reordered keys
// a semantic error rather than something sorted later.
func (e *canonEncoder) key(name string) error {
	if err := e.ready(); err != nil {
		return err
	}
	if e.depth == 0 {
		return e.fail(errCanonInvalid)
	}
	top := &e.frames[e.depth-1]
	if top.kind != canonObject {
		return e.fail(errCanonInvalid)
	}
	if top.pendingKey {
		return e.fail(errCanonInvalid)
	}
	if !top.validNextKey(name) {
		return e.fail(errCanonInvalid)
	}
	comma := top.needComma
	prefix := int64(0)
	if comma {
		prefix = 1
	}
	if err := e.need(prefix + 2 + int64(len(name)) + 1); err != nil {
		return err
	}
	if comma {
		if err := e.writeByte(','); err != nil {
			return err
		}
	}
	if err := e.writeByte('"'); err != nil {
		return err
	}
	if err := e.writeString(name); err != nil {
		return err
	}
	if err := e.writeByte('"'); err != nil {
		return err
	}
	if err := e.writeByte(':'); err != nil {
		return err
	}
	top.pendingKey = true
	top.needComma = true
	top.keyCount++
	top.lastKeyLen = copy(top.lastKey[:], name)
	return nil
}

// text writes a JSON string after validating the semantic value. Validation
// happens before any byte is emitted. Error text never contains the value.
func (e *canonEncoder) text(value string) error {
	if err := e.ready(); err != nil {
		return err
	}
	if !security.ValidText(value) {
		return e.fail(errCanonInvalid)
	}
	n := copy(e.scan[:], value)
	if err := tripwire.Check(e.scan[:n]); err != nil {
		return e.fail(errCanonInvalid)
	}
	token := 2 + canonEscapedLen(value)
	comma, err := e.valuePrologue()
	if err != nil {
		return err
	}
	prefix := int64(0)
	if comma {
		prefix = 1
	}
	if err := e.need(prefix + token); err != nil {
		return err
	}
	if comma {
		if err := e.writeByte(','); err != nil {
			return err
		}
	}
	if err := e.writeByte('"'); err != nil {
		return err
	}
	if err := e.writeEscapedContent(value); err != nil {
		return err
	}
	if err := e.writeByte('"'); err != nil {
		return err
	}
	e.deliverValue(true)
	return nil
}

// integer writes a nonnegative decimal integer. Digits are produced into a
// small fixed buffer; fmt and strconv are deliberately not used.
func (e *canonEncoder) integer(value int64) error {
	if err := e.ready(); err != nil {
		return err
	}
	if value < 0 {
		return e.fail(errCanonInvalid)
	}
	return e.unsigned(uint64(value))
}

// unsigned writes a full-range uint64 as a canonical decimal integer.
func (e *canonEncoder) unsigned(value uint64) error {
	if err := e.ready(); err != nil {
		return err
	}
	// Keep byte zero free for writeByte, which uses e.buf[0] for the
	// separator before a nonfirst array value.
	digits := e.buf[1:21]
	pos := len(digits)
	u := value
	for {
		pos--
		digits[pos] = byte('0' + u%10)
		u /= 10
		if u == 0 {
			break
		}
	}
	token := int64(len(digits) - pos)
	comma, err := e.valuePrologue()
	if err != nil {
		return err
	}
	prefix := int64(0)
	if comma {
		prefix = 1
	}
	if err := e.need(prefix + token); err != nil {
		return err
	}
	if comma {
		if err := e.writeByte(','); err != nil {
			return err
		}
	}
	if err := e.write(digits[pos:]); err != nil {
		return err
	}
	e.deliverValue(true)
	return nil
}

func (e *canonEncoder) boolean(value bool) error {
	if err := e.ready(); err != nil {
		return err
	}
	literal := "false"
	if value {
		literal = "true"
	}
	comma, err := e.valuePrologue()
	if err != nil {
		return err
	}
	prefix := int64(0)
	if comma {
		prefix = 1
	}
	if err := e.need(prefix + int64(len(literal))); err != nil {
		return err
	}
	if comma {
		if err := e.writeByte(','); err != nil {
			return err
		}
	}
	if err := e.writeString(literal); err != nil {
		return err
	}
	e.deliverValue(true)
	return nil
}

var canonInstantFloor = time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)

// validCanonInstant accepts nonzero, monotonic-free UTC instants on or after
// 2019-01-01 that RFC3339 can spell. Zero-offset non-UTC locations are allowed
// because the output normalizes to UTC; other offsets are refused.
func validCanonInstant(t time.Time) bool {
	if t.IsZero() {
		return false
	}
	if t != t.Round(0) {
		// A monotonic reading cannot be represented canonically.
		return false
	}
	_, offset := t.Zone()
	if offset != 0 {
		return false
	}
	u := t.UTC()
	if u.Before(canonInstantFloor) {
		return false
	}
	if y := u.Year(); y < 0 || y > 9999 {
		return false
	}
	return true
}

// instant writes RFC3339Nano in UTC with a literal Z. The fractional part is
// omitted or trimmed exactly as RFC3339Nano does. Formatting uses a fixed
// buffer, never a clock. The timestamp is emitted as a JSON string through the
// same validated text path used for ordinary text values.
func (e *canonEncoder) instant(value time.Time) error {
	if err := e.ready(); err != nil {
		return err
	}
	if !validCanonInstant(value) {
		return e.fail(errCanonInvalid)
	}
	var raw [40]byte
	formatted := value.UTC().AppendFormat(raw[:0], time.RFC3339Nano)
	return e.text(string(formatted))
}

// binary writes standard padded base64 inside a JSON string, streaming in
// fixed-size chunks so no encoded copy of the value is built.
//
// Binary is not text input. This path deliberately bypasses the 4096-byte text
// limit (while enforcing a 4 MiB decoded limit) and deliberately does not scan
// the bytes with tripwire. A future catalog decoder is responsible for scanning
// decoded string fields; arbitrary caller-supplied base64 text must never be
// routed through this method.
func (e *canonEncoder) binary(value []byte) error {
	if err := e.ready(); err != nil {
		return err
	}
	if len(value) > maxCanonBinary {
		return e.fail(errCanonInvalid)
	}
	encoded := int64(base64.StdEncoding.EncodedLen(len(value)))
	comma, err := e.valuePrologue()
	if err != nil {
		return err
	}
	prefix := int64(0)
	if comma {
		prefix = 1
	}
	if err := e.need(prefix + 2 + encoded); err != nil {
		return err
	}
	if comma {
		if err := e.writeByte(','); err != nil {
			return err
		}
	}
	if err := e.writeByte('"'); err != nil {
		return err
	}
	encBuf := e.buf[:]
	for len(value) > 0 {
		n := len(value)
		if n > canonBinaryChunk {
			n = canonBinaryChunk
		}
		base64.StdEncoding.Encode(encBuf[:], value[:n])
		if err := e.write(encBuf[:base64.StdEncoding.EncodedLen(n)]); err != nil {
			return err
		}
		value = value[n:]
	}
	if err := e.writeByte('"'); err != nil {
		return err
	}
	e.deliverValue(true)
	return nil
}

// finish completes the document atomically. All containers must be closed and
// exactly one root value must have been written. newline adds the only
// permitted whitespace outside strings, and it is metered like every other
// byte. finish can succeed once; later calls write nothing and report
// errCanonInvalid.
func (e *canonEncoder) finish(newline bool) error {
	if e.finished {
		return errCanonInvalid
	}
	if e.err != nil {
		return e.err
	}
	if e.depth != 0 || !e.rootStarted || !e.rootComplete {
		return e.fail(errCanonInvalid)
	}
	if newline {
		if err := e.need(1); err != nil {
			return err
		}
		if err := e.writeByte('\n'); err != nil {
			return err
		}
	}
	e.finished = true
	return nil
}
