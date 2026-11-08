package securitypack

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tripwire"
)

type canonOp func(*canonEncoder) error

func opKey(name string) canonOp {
	return func(e *canonEncoder) error { return e.key(name) }
}

func opText(value string) canonOp {
	return func(e *canonEncoder) error { return e.text(value) }
}

func opInteger(value int64) canonOp {
	return func(e *canonEncoder) error { return e.integer(value) }
}

func opBoolean(value bool) canonOp {
	return func(e *canonEncoder) error { return e.boolean(value) }
}

func opInstant(value time.Time) canonOp {
	return func(e *canonEncoder) error { return e.instant(value) }
}

func opBinary(value []byte) canonOp {
	return func(e *canonEncoder) error { return e.binary(value) }
}

func opFinish(newline bool) canonOp {
	return func(e *canonEncoder) error { return e.finish(newline) }
}

func runCanonOps(limit int64, ops []canonOp) (string, error) {
	var buf bytes.Buffer
	e := newCanonEncoder(&buf, limit)
	for _, op := range ops {
		if err := op(e); err != nil {
			return buf.String(), err
		}
	}
	return buf.String(), nil
}

func TestCanonicalGolden(t *testing.T) {
	note := "quote:\" backslash:\\ literal:<>&/ café 😀"
	ops := []canonOp{
		(*canonEncoder).beginObject,
		opKey("bin"), opBinary([]byte{1, 2, 3}),
		opKey("edge"),
		(*canonEncoder).beginArray,
		opText(`"`), opText(`\`), opText("<>&/"), opText("café"), opText("😀"),
		(*canonEncoder).endArray,
		opKey("empty_array"),
		(*canonEncoder).beginArray,
		(*canonEncoder).endArray,
		opKey("empty_object"),
		(*canonEncoder).beginObject,
		(*canonEncoder).endObject,
		opKey("flags"),
		(*canonEncoder).beginArray,
		opBoolean(true), opBoolean(false),
		(*canonEncoder).endArray,
		opKey("instant_frac"), opInstant(time.Date(2024, 1, 2, 3, 4, 5, 123456789, time.UTC)),
		opKey("instant_whole"), opInstant(time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)),
		opKey("max"), opInteger(9223372036854775807),
		opKey("nested"),
		(*canonEncoder).beginObject,
		opKey("a"), opInteger(0),
		opKey("arr"),
		(*canonEncoder).beginArray,
		(*canonEncoder).beginObject,
		opKey("z"), opBoolean(true),
		(*canonEncoder).endObject,
		(*canonEncoder).endArray,
		opKey("q"), opText("x"),
		(*canonEncoder).endObject,
		opKey("note"), opText(note),
		opKey("zero"), opInteger(0),
		(*canonEncoder).endObject,
		opFinish(true),
	}

	want := `{"bin":"AQID","edge":["\"","\\","<>&/","café","😀"],"empty_array":[],"empty_object":{},"flags":[true,false],"instant_frac":"2024-01-02T03:04:05.123456789Z","instant_whole":"2024-01-02T03:04:05Z","max":9223372036854775807,"nested":{"a":0,"arr":[{"z":true}],"q":"x"},"note":"quote:\" backslash:\\ literal:<>&/ café 😀","zero":0}` + "\n"

	got, err := runCanonOps(1<<20, ops)
	if err != nil {
		t.Fatalf("golden encode failed: %v", err)
	}
	if got != want {
		t.Fatalf("golden output mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestCanonicalUnsignedIntegers(t *testing.T) {
	cases := []struct {
		value uint64
		want  string
	}{
		{0, `0`},
		{uint64(1<<63 - 1), `9223372036854775807`},
		{uint64(1 << 63), `9223372036854775808`},
		{^uint64(0), `18446744073709551615`},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		e := newCanonEncoder(&buf, int64(len(tc.want)))
		if err := e.unsigned(tc.value); err != nil {
			t.Fatalf("unsigned(%d) failed: %v", tc.value, err)
		}
		if err := e.finish(false); err != nil {
			t.Fatalf("finish unsigned(%d): %v", tc.value, err)
		}
		if got := buf.String(); got != tc.want {
			t.Errorf("unsigned(%d) = %q, want %q", tc.value, got, tc.want)
		}

		var decoded json.Number
		decoder := json.NewDecoder(strings.NewReader(tc.want))
		decoder.UseNumber()
		if err := decoder.Decode(&decoded); err != nil || decoded.String() != tc.want {
			t.Errorf("independent JSON decode of %q = %q, %v", tc.want, decoded, err)
		}

		var short bytes.Buffer
		e = newCanonEncoder(&short, int64(len(tc.want)-1))
		if err := e.unsigned(tc.value); !errors.Is(err, errCanonTooLarge) {
			t.Errorf("unsigned(%d) short budget error = %v, want %v", tc.value, err, errCanonTooLarge)
		}
		if short.Len() != 0 {
			t.Errorf("unsigned(%d) wrote %q with short budget", tc.value, short.String())
		}
	}

	var embedded bytes.Buffer
	e := newCanonEncoder(&embedded, 100)
	if err := e.beginObject(); err != nil {
		t.Fatal(err)
	}
	if err := e.key("array"); err != nil {
		t.Fatal(err)
	}
	if err := e.beginArray(); err != nil {
		t.Fatal(err)
	}
	if err := e.unsigned(0); err != nil {
		t.Fatal(err)
	}
	if err := e.unsigned(uint64(1 << 63)); err != nil {
		t.Fatal(err)
	}
	if err := e.unsigned(^uint64(0)); err != nil {
		t.Fatal(err)
	}
	if err := e.endArray(); err != nil {
		t.Fatal(err)
	}
	if err := e.key("value"); err != nil {
		t.Fatal(err)
	}
	if err := e.unsigned(uint64(1 << 63)); err != nil {
		t.Fatal(err)
	}
	if err := e.endObject(); err != nil {
		t.Fatal(err)
	}
	if err := e.finish(false); err != nil {
		t.Fatal(err)
	}
	if got, want := embedded.String(), `{"array":[0,9223372036854775808,18446744073709551615],"value":9223372036854775808}`; got != want {
		t.Fatalf("embedded unsigned output = %q, want %q", got, want)
	}

	const nonfirstMax = `[0,18446744073709551615]`
	var exact bytes.Buffer
	e = newCanonEncoder(&exact, int64(len(nonfirstMax)))
	if err := e.beginArray(); err != nil {
		t.Fatal(err)
	}
	if err := e.unsigned(0); err != nil {
		t.Fatal(err)
	}
	if err := e.unsigned(^uint64(0)); err != nil {
		t.Fatal(err)
	}
	if err := e.endArray(); err != nil {
		t.Fatal(err)
	}
	if err := e.finish(false); err != nil {
		t.Fatal(err)
	}
	if got := exact.String(); got != nonfirstMax {
		t.Fatalf("exact-budget nonfirst MaxUint64 = %q, want %q", got, nonfirstMax)
	}

	var short bytes.Buffer
	// One byte less than the separator plus numeric token needed at this
	// position, excluding the final closing bracket from the budget.
	e = newCanonEncoder(&short, int64(len(nonfirstMax)-2))
	if err := e.beginArray(); err != nil {
		t.Fatal(err)
	}
	if err := e.unsigned(0); err != nil {
		t.Fatal(err)
	}
	if err := e.unsigned(^uint64(0)); !errors.Is(err, errCanonTooLarge) {
		t.Fatalf("short-budget nonfirst MaxUint64 error = %v, want %v", err, errCanonTooLarge)
	}
	if got, want := short.String(), `[0`; got != want {
		t.Fatalf("short-budget nonfirst output = %q, want %q", got, want)
	}
}

type canonStateCase struct {
	name         string
	limit        int64
	nilWriter    bool
	ops          []canonOp
	wantErrIndex int
	wantErr      error
	wantOut      string
}

func TestCanonicalStateMachineMisuse(t *testing.T) {
	deepOps := make([]canonOp, 13)
	for i := range deepOps {
		deepOps[i] = (*canonEncoder).beginArray
	}

	cases := []canonStateCase{
		{
			name: "value without key", limit: 100,
			ops:          []canonOp{(*canonEncoder).beginObject, opInteger(1)},
			wantErrIndex: 1, wantErr: errCanonInvalid, wantOut: "{",
		},
		{
			name: "integer negative", limit: 100,
			ops:          []canonOp{opInteger(-1)},
			wantErrIndex: 0, wantErr: errCanonInvalid, wantOut: "",
		},
		{
			name: "key outside object", limit: 100,
			ops:          []canonOp{opKey("a")},
			wantErrIndex: 0, wantErr: errCanonInvalid, wantOut: "",
		},
		{
			name: "key in array", limit: 100,
			ops:          []canonOp{(*canonEncoder).beginArray, opKey("a")},
			wantErrIndex: 1, wantErr: errCanonInvalid, wantOut: "[",
		},
		{
			name: "empty key", limit: 100,
			ops:          []canonOp{(*canonEncoder).beginObject, opKey("")},
			wantErrIndex: 1, wantErr: errCanonInvalid, wantOut: "{",
		},
		{
			name: "uppercase key", limit: 100,
			ops:          []canonOp{(*canonEncoder).beginObject, opKey("A")},
			wantErrIndex: 1, wantErr: errCanonInvalid, wantOut: "{",
		},
		{
			name: "hyphen key", limit: 100,
			ops:          []canonOp{(*canonEncoder).beginObject, opKey("a-b")},
			wantErrIndex: 1, wantErr: errCanonInvalid, wantOut: "{",
		},
		{
			name: "non-ascii key", limit: 100,
			ops:          []canonOp{(*canonEncoder).beginObject, opKey("é")},
			wantErrIndex: 1, wantErr: errCanonInvalid, wantOut: "{",
		},
		{
			name: "duplicate key", limit: 100,
			ops: []canonOp{
				(*canonEncoder).beginObject,
				opKey("a"), opText("x"),
				opKey("a"),
				opText("must not be written"),
			},
			wantErrIndex: 3, wantErr: errCanonInvalid, wantOut: `{"a":"x"`,
		},
		{
			name: "out of order key", limit: 100,
			ops: []canonOp{
				(*canonEncoder).beginObject,
				opKey("b"), opText("x"),
				opKey("a"),
			},
			wantErrIndex: 3, wantErr: errCanonInvalid, wantOut: `{"b":"x"`,
		},
		{
			name: "new key before previous value", limit: 100,
			ops:          []canonOp{(*canonEncoder).beginObject, opKey("a"), opKey("b")},
			wantErrIndex: 2, wantErr: errCanonInvalid, wantOut: `{"a":`,
		},
		{
			name: "unopened object close", limit: 100,
			ops:          []canonOp{(*canonEncoder).endObject},
			wantErrIndex: 0, wantErr: errCanonInvalid, wantOut: "",
		},
		{
			name: "unopened array close", limit: 100,
			ops:          []canonOp{(*canonEncoder).endArray},
			wantErrIndex: 0, wantErr: errCanonInvalid, wantOut: "",
		},
		{
			name: "mismatched object array close", limit: 100,
			ops:          []canonOp{(*canonEncoder).beginObject, (*canonEncoder).endArray},
			wantErrIndex: 1, wantErr: errCanonInvalid, wantOut: "{",
		},
		{
			name: "mismatched array object close", limit: 100,
			ops:          []canonOp{(*canonEncoder).beginArray, (*canonEncoder).endObject},
			wantErrIndex: 1, wantErr: errCanonInvalid, wantOut: "[",
		},
		{
			name: "unclosed object at finish", limit: 100,
			ops:          []canonOp{(*canonEncoder).beginObject, opFinish(false)},
			wantErrIndex: 1, wantErr: errCanonInvalid, wantOut: "{",
		},
		{
			name: "pending key at finish", limit: 100,
			ops:          []canonOp{(*canonEncoder).beginObject, opKey("a"), opFinish(false)},
			wantErrIndex: 2, wantErr: errCanonInvalid, wantOut: `{"a":`,
		},
		{
			name: "empty document finish", limit: 100,
			ops:          []canonOp{opFinish(false)},
			wantErrIndex: 0, wantErr: errCanonInvalid, wantOut: "",
		},
		{
			name: "second root scalar", limit: 100,
			ops:          []canonOp{opBoolean(true), opInteger(1)},
			wantErrIndex: 1, wantErr: errCanonInvalid, wantOut: "true",
		},
		{
			name: "second root container", limit: 100,
			ops:          []canonOp{(*canonEncoder).beginObject, (*canonEncoder).endObject, (*canonEncoder).beginArray},
			wantErrIndex: 2, wantErr: errCanonInvalid, wantOut: "{}",
		},
		{
			name: "call after finish", limit: 100,
			ops:          []canonOp{(*canonEncoder).beginObject, (*canonEncoder).endObject, opFinish(false), opBoolean(true)},
			wantErrIndex: 3, wantErr: errCanonInvalid, wantOut: "{}",
		},
		{
			name: "repeat finish", limit: 100,
			ops:          []canonOp{(*canonEncoder).beginObject, (*canonEncoder).endObject, opFinish(false), opFinish(true)},
			wantErrIndex: 3, wantErr: errCanonInvalid, wantOut: "{}",
		},
		{
			name: "negative limit", limit: -1,
			ops:          []canonOp{(*canonEncoder).beginObject},
			wantErrIndex: 0, wantErr: errCanonInvalid, wantOut: "",
		},
		{
			name: "zero limit", limit: 0,
			ops:          []canonOp{(*canonEncoder).beginObject},
			wantErrIndex: 0, wantErr: errCanonTooLarge, wantOut: "",
		},
		{
			name: "nil writer", limit: 100, nilWriter: true,
			ops:          []canonOp{(*canonEncoder).beginObject},
			wantErrIndex: 0, wantErr: errCanonInvalid, wantOut: "",
		},
		{
			name: "depth thirteen refused", limit: 100,
			ops:          deepOps,
			wantErrIndex: 12, wantErr: errCanonInvalid, wantOut: strings.Repeat("[", 12),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			var w io.Writer = &buf
			if tc.nilWriter {
				w = nil
			}
			e := newCanonEncoder(w, tc.limit)
			for i, op := range tc.ops {
				err := op(e)
				switch {
				case i < tc.wantErrIndex:
					if err != nil {
						t.Fatalf("operation %d returned unexpected error: %v", i, err)
					}
				case i == tc.wantErrIndex:
					if err == nil || !errors.Is(err, tc.wantErr) {
						t.Fatalf("operation %d error = %v, want %v", i, err, tc.wantErr)
					}
				default:
					if err == nil || !errors.Is(err, tc.wantErr) {
						t.Fatalf("operation %d did not retain sticky error: %v", i, err)
					}
				}
			}
			if got := buf.String(); got != tc.wantOut {
				t.Fatalf("output = %q, want %q", got, tc.wantOut)
			}
		})
	}
}

func TestCanonicalKeyOrderAndGrammar(t *testing.T) {
	ops := []canonOp{
		(*canonEncoder).beginObject,
		opKey("0a"), opInteger(0),
		opKey("_"), opInteger(1),
		opKey("a0"), opInteger(2),
		opKey("a_"), opInteger(3),
		opKey("aa"), opInteger(4),
		opKey("z9_"), opInteger(5),
		(*canonEncoder).endObject,
		opFinish(false),
	}
	want := `{"0a":0,"_":1,"a0":2,"a_":3,"aa":4,"z9_":5}`
	got, err := runCanonOps(256, ops)
	if err != nil {
		t.Fatalf("key encoding failed: %v", err)
	}
	if got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestCanonicalKeyLengthAndRetention(t *testing.T) {
	name := strings.Repeat("a", security.MaxTextBytes)
	e := newCanonEncoder(io.Discard, MaxCanonBytes)
	if err := e.beginObject(); err != nil {
		t.Fatal(err)
	}
	if err := e.key(name); err != nil {
		t.Fatalf("maximum key rejected: %v", err)
	}
	if e.frames[0].lastKeyLen != len(name) || string(e.frames[0].lastKey[:e.frames[0].lastKeyLen]) != name {
		t.Fatal("key was not retained correctly")
	}
	// Mutating the retained copy must not affect the caller's string.
	e.frames[0].lastKey[0] = 'b'
	if name[0] != 'a' {
		t.Fatal("key storage aliases caller data")
	}
	if err := e.boolean(true); err != nil {
		t.Fatal(err)
	}
	if err := e.endObject(); err != nil {
		t.Fatal(err)
	}
	if e.frames[0] != (canonFrame{}) {
		t.Fatal("closing an object retained frame data")
	}

	e = newCanonEncoder(io.Discard, MaxCanonBytes)
	if err := e.beginObject(); err != nil {
		t.Fatal(err)
	}
	if err := e.key(name + "a"); !errors.Is(err, errCanonInvalid) {
		t.Fatalf("oversized key error = %v", err)
	}
}

func TestCanonicalContainerParentAccounting(t *testing.T) {
	objectOps := []canonOp{
		(*canonEncoder).beginObject,
		opKey("a"), (*canonEncoder).beginObject, (*canonEncoder).endObject,
		opKey("b"), (*canonEncoder).beginArray, (*canonEncoder).endArray,
		opKey("c"), opText("x"),
		opKey("d"), (*canonEncoder).beginObject, opKey("x"), opInteger(1), (*canonEncoder).endObject,
		opKey("e"), opBoolean(true),
		(*canonEncoder).endObject,
		opFinish(false),
	}
	objectWant := `{"a":{},"b":[],"c":"x","d":{"x":1},"e":true}`
	got, err := runCanonOps(256, objectOps)
	if err != nil {
		t.Fatalf("object sibling encoding failed: %v", err)
	}
	if got != objectWant {
		t.Fatalf("object output = %q, want %q", got, objectWant)
	}

	arrayOps := []canonOp{
		(*canonEncoder).beginArray,
		(*canonEncoder).beginObject, opKey("a"), opInteger(1), (*canonEncoder).endObject,
		opInteger(2),
		(*canonEncoder).beginArray, opInteger(3), (*canonEncoder).endArray,
		opInteger(4),
		(*canonEncoder).endArray,
		opFinish(false),
	}
	arrayWant := `[{"a":1},2,[3],4]`
	got, err = runCanonOps(256, arrayOps)
	if err != nil {
		t.Fatalf("array sibling encoding failed: %v", err)
	}
	if got != arrayWant {
		t.Fatalf("array output = %q, want %q", got, arrayWant)
	}
}

func TestCanonicalDepthBoundary(t *testing.T) {
	if maxCanonDepth != 12 {
		t.Fatalf("maxCanonDepth = %d, want 12", maxCanonDepth)
	}
	ops := make([]canonOp, 0, 12+1+12+1)
	for i := 0; i < 12; i++ {
		ops = append(ops, (*canonEncoder).beginArray)
	}
	ops = append(ops, opInteger(7))
	for i := 0; i < 12; i++ {
		ops = append(ops, (*canonEncoder).endArray)
	}
	ops = append(ops, opFinish(false))
	want := strings.Repeat("[", 12) + "7" + strings.Repeat("]", 12)
	got, err := runCanonOps(256, ops)
	if err != nil {
		t.Fatalf("depth 12 encoding failed: %v", err)
	}
	if got != want {
		t.Fatalf("depth output = %q, want %q", got, want)
	}
}

func TestCanonicalTextValidation(t *testing.T) {
	bad := []struct {
		name  string
		value string
	}{
		{name: "invalid utf8", value: string([]byte{0x61, 0xff, 0x62})},
		{name: "too long", value: strings.Repeat("a", 4097)},
		{name: "control", value: "a\x00b"},
		{name: "invisible", value: "a\u200bb"},
	}
	for _, tc := range bad {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			e := newCanonEncoder(&buf, 1<<20)
			err := e.text(tc.value)
			if err == nil || !errors.Is(err, errCanonInvalid) {
				t.Fatalf("text error = %v, want %v", err, errCanonInvalid)
			}
			if buf.Len() != 0 {
				t.Fatalf("invalid text wrote %d bytes", buf.Len())
			}
		})
	}

	value := strings.Repeat("a", 4096)
	want := `"` + value + `"`
	got, err := runCanonOps(int64(len(want)), []canonOp{opText(value), opFinish(false)})
	if err != nil {
		t.Fatalf("4096-byte text rejected: %v", err)
	}
	if got != want {
		t.Fatalf("4096-byte text output length = %d, want %d", len(got), len(want))
	}
}

func TestCanonicalTextRejectsCredentialShape(t *testing.T) {
	credential := strings.Join([]string{"ts", "key", "-", "api", "-"}, "")
	if tripwire.Check([]byte(credential)) == nil {
		t.Fatal("synthetic shape fixture was not recognised by tripwire")
	}
	if !security.ValidText(credential) {
		t.Fatal("synthetic credential fixture must be valid text to isolate the tripwire rejection path")
	}

	var buf bytes.Buffer
	e := newCanonEncoder(&buf, 1<<20)
	err := e.text(credential)
	if err == nil || !errors.Is(err, errCanonInvalid) {
		t.Fatalf("credential-shaped text error = %v, want %v", err, errCanonInvalid)
	}
	if buf.Len() != 0 {
		t.Fatalf("credential-shaped text wrote %d bytes", buf.Len())
	}
	if strings.Contains(err.Error(), credential) {
		t.Fatal("canonical error text leaked the supplied value")
	}
}

type canonBudgetCase struct {
	name string
	ops  []canonOp
	want string
}

func TestCanonicalByteBudget(t *testing.T) {
	cases := []canonBudgetCase{
		{
			name: "object punctuation",
			ops:  []canonOp{(*canonEncoder).beginObject, (*canonEncoder).endObject, opFinish(false)},
			want: `{}`,
		},
		{
			name: "array comma punctuation",
			ops:  []canonOp{(*canonEncoder).beginArray, opInteger(0), opInteger(1), (*canonEncoder).endArray, opFinish(false)},
			want: `[0,1]`,
		},
		{
			name: "escaped string",
			ops:  []canonOp{opText(`a\b"c`), opFinish(false)},
			want: `"a\\b\"c"`,
		},
		{
			name: "base64",
			ops:  []canonOp{opBinary([]byte{0, 1, 2, 3, 4}), opFinish(false)},
			want: `"AAECAwQ="`,
		},
		{
			name: "final newline",
			ops:  []canonOp{opBoolean(true), opFinish(true)},
			want: "true\n",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			exact := int64(len(tc.want))
			got, err := runCanonOps(exact, tc.ops)
			if err != nil {
				t.Fatalf("exact budget failed: %v", err)
			}
			if got != tc.want {
				t.Fatalf("exact output = %q, want %q", got, tc.want)
			}

			shortLimit := exact - 1
			short, err := runCanonOps(shortLimit, tc.ops)
			if err == nil || !errors.Is(err, errCanonTooLarge) {
				t.Fatalf("one-byte-short error = %v, want %v", err, errCanonTooLarge)
			}
			if int64(len(short)) > shortLimit {
				t.Fatalf("one-byte-short wrote %d bytes with limit %d", len(short), shortLimit)
			}
			if !strings.HasPrefix(tc.want, short) {
				t.Fatalf("one-byte-short output %q is not a prefix of %q", short, tc.want)
			}
		})
	}
}

type canonShortWriter struct {
	n     int
	calls int
	got   []byte
}

func (w *canonShortWriter) Write(p []byte) (int, error) {
	w.calls++
	n := w.n
	if n > len(p) {
		n = len(p)
	}
	w.got = append(w.got, p[:n]...)
	return n, nil
}

type canonFailWriter struct {
	err   error
	calls int
}

func (w *canonFailWriter) Write(p []byte) (int, error) {
	w.calls++
	return 0, w.err
}

type canonPartialErrorWriter struct {
	err   error
	n     int
	calls int
	got   []byte
}

func (w *canonPartialErrorWriter) Write(p []byte) (int, error) {
	w.calls++
	n := w.n
	if n > len(p) {
		n = len(p)
	}
	w.got = append(w.got, p[:n]...)
	return n, w.err
}

func TestCanonicalWriterErrors(t *testing.T) {
	t.Run("unsigned retains writer error", func(t *testing.T) {
		sentinel := errors.New("synthetic unsigned writer failure")
		w := &canonFailWriter{err: sentinel}
		e := newCanonEncoder(w, 100)
		if err := e.unsigned(^uint64(0)); !errors.Is(err, sentinel) {
			t.Fatalf("unsigned error = %v, want supplied error", err)
		}
		if err := e.finish(false); !errors.Is(err, sentinel) {
			t.Fatalf("finish error = %v, want sticky supplied error", err)
		}
		if err := e.unsigned(0); !errors.Is(err, sentinel) {
			t.Fatalf("later unsigned error = %v, want sticky supplied error", err)
		}
		if w.calls != 1 {
			t.Fatalf("writer called %d times after error, want 1", w.calls)
		}
	})

	t.Run("short nil write", func(t *testing.T) {
		w := &canonShortWriter{n: 0}
		e := newCanonEncoder(w, 100)
		err := e.beginObject()
		if !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("beginObject error = %v, want %v", err, io.ErrShortWrite)
		}
		if err := e.endObject(); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("later error = %v, want sticky %v", err, io.ErrShortWrite)
		}
		if w.calls != 1 {
			t.Fatalf("writer called %d times, want 1", w.calls)
		}
		if len(w.got) != 0 {
			t.Fatalf("short writer received %q", w.got)
		}
	})

	t.Run("ordinary error", func(t *testing.T) {
		sentinel := errors.New("synthetic writer failure")
		w := &canonFailWriter{err: sentinel}
		e := newCanonEncoder(w, 100)
		err := e.beginObject()
		if !errors.Is(err, sentinel) {
			t.Fatalf("beginObject error = %v, want supplied error", err)
		}
		if err := e.integer(1); !errors.Is(err, sentinel) {
			t.Fatalf("later error = %v, want sticky supplied error", err)
		}
		if w.calls != 1 {
			t.Fatalf("writer called %d times, want 1", w.calls)
		}
	})

	t.Run("error after partial write", func(t *testing.T) {
		sentinel := errors.New("synthetic partial writer failure")
		w := &canonPartialErrorWriter{err: sentinel, n: 1}
		e := newCanonEncoder(w, 100)
		err := e.boolean(true)
		if !errors.Is(err, sentinel) {
			t.Fatalf("boolean error = %v, want supplied error", err)
		}
		if string(w.got) != "t" {
			t.Fatalf("partial output = %q, want %q", w.got, "t")
		}
		if err := e.finish(false); !errors.Is(err, sentinel) {
			t.Fatalf("finish error = %v, want sticky supplied error", err)
		}
		if w.calls != 1 {
			t.Fatalf("writer called %d times, want 1", w.calls)
		}
	})
}

func TestCanonicalBinaryStreaming(t *testing.T) {
	value := make([]byte, 5000)
	for i := range value {
		value[i] = byte((i*37 + 11) % 256)
	}
	limit := int64(base64.StdEncoding.EncodedLen(len(value))) + 2
	var buf bytes.Buffer
	e := newCanonEncoder(&buf, limit)
	if err := e.binary(value); err != nil {
		t.Fatalf("binary encode failed: %v", err)
	}
	if err := e.finish(false); err != nil {
		t.Fatalf("binary finish failed: %v", err)
	}
	want := `"` + base64.StdEncoding.EncodeToString(value) + `"`
	if got := buf.String(); got != want {
		t.Fatalf("binary output mismatch: got %d bytes, want %d", len(got), len(want))
	}
	if len(value) <= 4096 {
		t.Fatal("test fixture must exceed the text-size limit")
	}

	tooLarge := make([]byte, maxCanonBinary+1)
	var rejected bytes.Buffer
	e = newCanonEncoder(&rejected, MaxCanonBytes)
	err := e.binary(tooLarge)
	if !errors.Is(err, errCanonInvalid) {
		t.Fatalf("oversized binary error = %v, want %v", err, errCanonInvalid)
	}
	if rejected.Len() != 0 {
		t.Fatalf("oversized binary wrote %d bytes", rejected.Len())
	}
}

type canonCountWriter struct {
	n int64
}

func (w *canonCountWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return len(p), nil
}

func measureBinaryAllocs(value []byte) (float64, error) {
	var firstErr error
	allocs := testing.AllocsPerRun(5, func() {
		if firstErr != nil {
			return
		}
		e := newCanonEncoder(io.Discard, int64(base64.StdEncoding.EncodedLen(len(value))+2))
		if err := e.binary(value); err != nil {
			firstErr = err
			return
		}
		if err := e.finish(false); err != nil {
			firstErr = err
		}
	})
	return allocs, firstErr
}

func TestCanonicalBinaryAllocationBounded(t *testing.T) {
	small := make([]byte, 3*canonBinaryChunk)
	large := make([]byte, 1<<20)
	for i := range small {
		small[i] = byte(i % 251)
	}
	for i := range large {
		large[i] = byte(i % 251)
	}

	var count canonCountWriter
	limit := int64(base64.StdEncoding.EncodedLen(len(large))) + 2
	e := newCanonEncoder(&count, limit)
	if err := e.binary(large); err != nil {
		t.Fatalf("large binary encode failed: %v", err)
	}
	if err := e.finish(false); err != nil {
		t.Fatalf("large binary finish failed: %v", err)
	}
	if count.n != limit {
		t.Fatalf("counting writer saw %d bytes, want %d", count.n, limit)
	}

	smallAllocs, err := measureBinaryAllocs(small)
	if err != nil {
		t.Fatalf("small binary allocation run failed: %v", err)
	}
	largeAllocs, err := measureBinaryAllocs(large)
	if err != nil {
		t.Fatalf("large binary allocation run failed: %v", err)
	}
	if largeAllocs > smallAllocs+1 {
		t.Fatalf("binary allocation count grew with input: small=%v large=%v", smallAllocs, largeAllocs)
	}
	if largeAllocs > 4 {
		t.Fatalf("binary writer allocated %v times for a fixed-size chunked path", largeAllocs)
	}
}

func benchmarkBinaryBytes(value []byte) (int64, error) {
	var firstErr error
	result := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			e := newCanonEncoder(io.Discard, int64(base64.StdEncoding.EncodedLen(len(value))+2))
			if err := e.binary(value); err != nil {
				firstErr = err
				return
			}
			if err := e.finish(false); err != nil {
				firstErr = err
				return
			}
		}
	})
	return result.AllocedBytesPerOp(), firstErr
}

func TestCanonicalBinaryAllocatedBytesBounded(t *testing.T) {
	small, err := benchmarkBinaryBytes(make([]byte, 3*canonBinaryChunk))
	if err != nil {
		t.Fatal(err)
	}
	large, err := benchmarkBinaryBytes(make([]byte, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if large > small+(32<<10) {
		t.Fatalf("binary allocated bytes grew with output: small=%d large=%d", small, large)
	}
}

// The writer scratch is reused across leaves and punctuation. This measures the
// streaming path directly because regexp pools can be dropped under the race detector.
func measureTextSequenceAllocs(count int) (float64, error) {
	var firstErr error
	allocs := testing.AllocsPerRun(10, func() {
		if firstErr != nil {
			return
		}
		e := newCanonEncoder(io.Discard, 1<<20)
		if err := e.beginArray(); err != nil {
			firstErr = err
			return
		}
		for i := 0; i < count; i++ {
			if err := e.writeByte('"'); err != nil {
				firstErr = err
				return
			}
			if err := e.writeEscapedContent(`short "leaf"`); err != nil {
				firstErr = err
				return
			}
			if err := e.writeByte('"'); err != nil {
				firstErr = err
				return
			}
		}
		if err := e.endArray(); err != nil {
			firstErr = err
			return
		}
		firstErr = e.finish(false)
	})
	return allocs, firstErr
}

func TestCanonicalTextSequenceAllocationBounded(t *testing.T) {
	small, err := measureTextSequenceAllocs(8)
	if err != nil {
		t.Fatal(err)
	}
	large, err := measureTextSequenceAllocs(512)
	if err != nil {
		t.Fatal(err)
	}
	if large > small+1 {
		t.Fatalf("text allocations grew with leaves: small=%v large=%v", small, large)
	}
}

func BenchmarkCanonicalTextSequence(b *testing.B) {
	for _, count := range []int{8, 512} {
		name := "8"
		if count == 512 {
			name = "512"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				e := newCanonEncoder(io.Discard, 1<<20)
				if err := e.beginArray(); err != nil {
					b.Fatal(err)
				}
				for j := 0; j < count; j++ {
					if err := e.text(`short "leaf"`); err != nil {
						b.Fatal(err)
					}
				}
				if err := e.endArray(); err != nil {
					b.Fatal(err)
				}
				if err := e.finish(false); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

type failAtCanonWrite struct {
	calls  int
	failAt int
	err    error
}

func (w *failAtCanonWrite) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == w.failAt {
		return 0, w.err
	}
	return len(p), nil
}

func TestCanonicalWriteFailuresAtEveryBoundary(t *testing.T) {
	// Exercise every write in a document with each scalar, nested containers,
	// long keys, escapes across chunks, and multiple base64 chunks.
	ops := []canonOp{
		(*canonEncoder).beginObject,
		opKey("a"), (*canonEncoder).beginArray,
		opBoolean(true), opInteger(23), opText(strings.Repeat(`a"`, 1024)),
		opBinary(make([]byte, 900)), (*canonEncoder).beginObject,
		opKey(strings.Repeat("z", 1100)), opInstant(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
		(*canonEncoder).endObject, (*canonEncoder).beginArray, (*canonEncoder).endArray,
		(*canonEncoder).endArray, opKey("b"), opBoolean(false),
		(*canonEncoder).endObject, opFinish(true),
	}
	sentinel := errors.New("write failure")
	count := &failAtCanonWrite{err: sentinel}
	e := newCanonEncoder(count, MaxCanonBytes)
	for _, op := range ops {
		if err := op(e); err != nil {
			t.Fatalf("count run: %v", err)
		}
	}
	for failAt := 1; failAt <= count.calls; failAt++ {
		w := &failAtCanonWrite{failAt: failAt, err: sentinel}
		e = newCanonEncoder(w, MaxCanonBytes)
		var got error
		for _, op := range ops {
			got = op(e)
			if got != nil {
				break
			}
		}
		if !errors.Is(got, sentinel) {
			t.Fatalf("write %d: got %v", failAt, got)
		}
		calls := w.calls
		if err := e.finish(false); !errors.Is(err, sentinel) || w.calls != calls {
			t.Fatalf("write %d: failure was not sticky", failAt)
		}
	}
}

func TestCanonicalInternalMeterDefensivePaths(t *testing.T) {
	e := newCanonEncoder(io.Discard, 1)
	if err := e.write(nil); err != nil {
		t.Fatal(err)
	}
	if err := e.write([]byte("ab")); !errors.Is(err, errCanonTooLarge) {
		t.Fatalf("oversized direct write: %v", err)
	}
	if err := e.write([]byte("a")); !errors.Is(err, errCanonTooLarge) {
		t.Fatalf("direct write failed to retain error: %v", err)
	}
	e = newCanonEncoder(io.Discard, 1)
	if err := e.need(-1); !errors.Is(err, errCanonInvalid) {
		t.Fatalf("negative reservation: %v", err)
	}
}

func TestCanonicalInstantValidation(t *testing.T) {
	good := []struct {
		name  string
		value time.Time
		want  string
	}{
		{
			name:  "fractional UTC",
			value: time.Date(2024, 1, 2, 3, 4, 5, 123456789, time.UTC),
			want:  `"2024-01-02T03:04:05.123456789Z"`,
		},
		{
			name:  "integral UTC",
			value: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
			want:  `"2024-01-02T03:04:05Z"`,
		},
		{
			name:  "trimmed fraction",
			value: time.Date(2024, 1, 2, 3, 4, 5, 120000000, time.UTC),
			want:  `"2024-01-02T03:04:05.12Z"`,
		},
		{
			name:  "zero offset location",
			value: time.Date(2024, 1, 2, 3, 4, 5, 0, time.FixedZone("zero", 0)),
			want:  `"2024-01-02T03:04:05Z"`,
		},
		{
			name:  "floor",
			value: time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
			want:  `"2019-01-01T00:00:00Z"`,
		},
	}
	for _, tc := range good {
		got, err := runCanonOps(int64(len(tc.want)), []canonOp{opInstant(tc.value), opFinish(false)})
		if err != nil {
			t.Fatalf("%s rejected: %v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("%s output = %q, want %q", tc.name, got, tc.want)
		}
	}

	bad := []struct {
		name  string
		value time.Time
	}{
		{name: "before floor", value: time.Date(2018, 12, 31, 23, 59, 59, 999999999, time.UTC)},
		{name: "nonzero offset", value: time.Date(2024, 1, 2, 3, 4, 5, 0, time.FixedZone("plus", 3600))},
		{name: "zero time", value: time.Time{}},
		{name: "year too large", value: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	for _, tc := range bad {
		got, err := runCanonOps(100, []canonOp{opInstant(tc.value), opFinish(false)})
		if err == nil || !errors.Is(err, errCanonInvalid) {
			t.Fatalf("%s error = %v, want %v", tc.name, err, errCanonInvalid)
		}
		if got != "" {
			t.Fatalf("%s wrote %q", tc.name, got)
		}
	}

	t.Run("monotonic", func(t *testing.T) {
		now := time.Now()
		if now == now.Round(0) {
			t.Skip("runtime supplied a time without a monotonic reading")
		}
		got, err := runCanonOps(100, []canonOp{opInstant(now), opFinish(false)})
		if err == nil || !errors.Is(err, errCanonInvalid) {
			t.Fatalf("monotonic instant error = %v, want %v", err, errCanonInvalid)
		}
		if got != "" {
			t.Fatalf("monotonic instant wrote %q", got)
		}
	})
}

func FuzzCanonicalText(f *testing.F) {
	f.Add("", int64(2))
	f.Add("hello", int64(64))
	f.Add("a\"b\\c<>&/ café 😀", int64(128))
	f.Add("a\x00b", int64(64))
	f.Add(strings.Repeat("a", 4097), int64(5000))
	f.Add(string([]byte{0xff}), int64(64))
	f.Add("x", int64(-1))

	f.Fuzz(func(t *testing.T, value string, limit int64) {
		valid := security.ValidText(value)
		flagged := tripwire.Check([]byte(value)) != nil

		var buf bytes.Buffer
		e := newCanonEncoder(&buf, limit)
		err := e.text(value)

		if limit < 0 && buf.Len() != 0 {
			t.Fatalf("negative limit wrote %d bytes", buf.Len())
		}
		if limit >= 0 && int64(buf.Len()) > limit {
			t.Fatalf("wrote %d bytes with limit %d", buf.Len(), limit)
		}

		escapedLen := int64(2 + len(value))
		for i := 0; i < len(value); i++ {
			if value[i] == '"' || value[i] == '\\' {
				escapedLen++
			}
		}

		if err == nil && (!valid || flagged) {
			t.Fatal("invalid or credential-shaped text was accepted")
		}
		if err != nil && valid && !flagged && limit >= escapedLen {
			t.Fatalf("valid unflagged text rejected with sufficient budget: %v", err)
		}
		if err != nil {
			if valid && !flagged && limit >= 0 && limit < escapedLen && !errors.Is(err, errCanonTooLarge) {
				t.Fatalf("under-budget text error = %v, want %v", err, errCanonTooLarge)
			}
			return
		}

		if err := e.finish(false); err != nil {
			t.Fatalf("text succeeded but finish failed: %v", err)
		}
		if int64(buf.Len()) > limit {
			t.Fatalf("finished output wrote %d bytes with limit %d", buf.Len(), limit)
		}

		var decoded string
		if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
			t.Fatalf("accepted output is not valid JSON: %v", err)
		}
		if decoded != value {
			t.Fatal("accepted text did not roundtrip")
		}

		probe := newCanonEncoder(io.Discard, limit)
		if err := probe.beginObject(); err == nil {
			if err := probe.text(value); err == nil {
				t.Fatal("text was accepted in an object without a key")
			}
		}
	})
}
