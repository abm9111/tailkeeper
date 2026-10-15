package sanitize

import (
	"encoding/json"
	"math/bits"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/abm9111/tailkeeper/internal/tripwire"
)

// r returns the one-rune string for code point cp. Tests build special characters
// this way so that no tool in the chain rewrites escape sequences in the source.
func r(cp rune) string { return string(cp) }

func TestStringEscapesDangerousRunes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain-host", "plain-host"},
		{"line1" + r(0x0A) + "line2", `line1\u{000A}line2`},
		{"tab" + r(0x09) + "here", `tab\u{0009}here`},
		{r(0x1B) + "[31mred", `\u{001B}[31mred`},
		{"abc" + r(0x202E) + "evil", `abc\u{202E}evil`},
		{"zero" + r(0x200B) + "width", `zero\u{200B}width`},
		{"iso" + r(0x2066) + "late" + r(0x2069), `iso\u{2066}late\u{2069}`},
		{"bom" + r(0xFEFF), `bom\u{FEFF}`},
		{"c1" + r(0x85) + "next", `c1\u{0085}next`},
		{"bad" + string([]byte{0xFF}) + "byte", `bad\u{FFFD}byte`},
		{"caf" + r(0xE9) + " " + r(0x1F680) + " ok", "caf" + r(0xE9) + " " + r(0x1F680) + " ok"},
	}
	for _, c := range cases {
		if got := String(c.in, 0); got != c.want {
			t.Errorf("String(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMaskID(t *testing.T) {
	for in, want := range map[string]string{
		"T1a2b3c4d5CNTRL": "T1a2…", // a tailnet ID
		"kAbCdEf12CNTRL":  "kAbC…", // an OAuth client ID
		"123456789":       "1234…",
		"12345678":        "12345678", // too short to identify anything: kept
		"":                "",
		"ÄÖÜßäöüéè":       "ÄÖÜß…", // cut on runes, not bytes
	} {
		if got := MaskID(in); got != want {
			t.Errorf("MaskID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStringCapsOnRuneBoundary(t *testing.T) {
	in := strings.Repeat(r(0xE9), 100) // 200 bytes
	got := String(in, 21)
	if len(got) > 21 {
		t.Fatalf("len = %d, want <= 21", len(got))
	}
	if !utf8.ValidString(got) {
		t.Fatalf("result is not valid UTF-8: %q", got)
	}
	if !strings.HasSuffix(got, "...[truncated]") {
		t.Fatalf("missing truncation suffix: %q", got)
	}
}

type inner struct {
	Label string `json:"label" tk:"untrusted"`
	Safe  string `json:"safe"`
}

type outer struct {
	Name   string            `json:"name" tk:"untrusted"`
	Kept   string            `json:"kept"`
	Tags   []string          `json:"tags" tk:"untrusted"`
	Inner  inner             `json:"inner"`
	Many   []inner           `json:"many" tk:"rows"`
	ByName map[string]string `json:"byName" tk:"untrusted"`
	Ptr    *inner            `json:"ptr,omitempty"`
}

func TestFieldsEscapesEveryStringAndCapsTaggedOnes(t *testing.T) {
	o := outer{
		Name:   "a" + r(0x0A) + "b",
		Kept:   "c" + r(0x0A) + "d",
		Tags:   []string{"tag:x" + r(0x202E)},
		Inner:  inner{Label: "l" + r(0x1B), Safe: "s" + r(0x0A)},
		Many:   []inner{{Label: "m" + r(0x0A), Safe: "n" + r(0x0A)}},
		ByName: map[string]string{"k" + r(0x0A): "v" + r(0x0A)},
		Ptr:    &inner{Label: "p" + r(0x0A)},
	}
	Fields(&o, 0)
	if o.Name != `a\u{000A}b` || o.Kept != `c\u{000A}d` {
		t.Errorf("Name/Kept = %q/%q", o.Name, o.Kept)
	}
	if o.Tags[0] != `tag:x\u{202E}` {
		t.Errorf("Tags = %q", o.Tags)
	}
	if o.Inner.Label != `l\u{001B}` || o.Inner.Safe != `s\u{000A}` {
		t.Errorf("Inner = %+v", o.Inner)
	}
	if o.Many[0].Label != `m\u{000A}` || o.Many[0].Safe != `n\u{000A}` {
		t.Errorf("Many = %+v", o.Many)
	}
	if o.ByName[`k\u{000A}`] != `v\u{000A}` {
		t.Errorf("ByName = %q", o.ByName)
	}
	if o.Ptr.Label != `p\u{000A}` {
		t.Errorf("Ptr.Label = %q", o.Ptr.Label)
	}
}

func TestUntrustedPaths(t *testing.T) {
	got := UntrustedPaths(reflect.TypeOf(outer{}))
	want := []string{"byName", "inner.label", "many[].label", "name", "ptr.label", "tags"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UntrustedPaths = %v, want %v", got, want)
	}
}

func TestHasTag(t *testing.T) {
	type s struct {
		A string `tk:"untrusted,col"`
		B string `tk:"col"`
	}
	ft := reflect.TypeOf(s{})
	if !HasTag(ft.Field(0).Tag, "untrusted") || !HasTag(ft.Field(0).Tag, "col") {
		t.Error("field A should have untrusted and col")
	}
	if HasTag(ft.Field(1).Tag, "untrusted") {
		t.Error("field B should not be untrusted")
	}
}

func TestUntrustedPathsRefusesShapesFieldsCannotSanitize(t *testing.T) {
	type inner struct {
		Name string `json:"name" tk:"untrusted"`
	}
	type withAny struct {
		V any `json:"v" tk:"untrusted"`
	}
	type withStructMap struct {
		M map[string]inner `json:"m"`
	}
	type withEmbedded struct {
		inner
		ID string `json:"id"`
	}
	type withBytes struct {
		B []byte `json:"b" tk:"untrusted"`
	}
	type withRawJSON struct {
		Rows []struct {
			Old json.RawMessage `json:"old"`
		} `json:"rows"`
	}
	for name, typ := range map[string]reflect.Type{
		"interface":       reflect.TypeFor[withAny](),
		"map of structs":  reflect.TypeFor[withStructMap](),
		"embedded struct": reflect.TypeFor[withEmbedded](),
		"raw bytes":       reflect.TypeFor[withBytes](),
		"raw JSON":        reflect.TypeFor[withRawJSON](),
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: UntrustedPaths accepted a shape Fields cannot sanitize", name)
				}
			}()
			UntrustedPaths(typ)
		}()
	}
}

func TestUntrustedPathsAcceptsScalarMaps(t *testing.T) {
	type ok struct {
		Labels  map[string]string  `json:"labels" tk:"untrusted"`
		Latency map[string]float64 `json:"latency"`
	}
	if got := UntrustedPaths(reflect.TypeFor[ok]()); len(got) != 1 || got[0] != "labels" {
		t.Errorf("paths = %v", got)
	}
}

func TestStringEscapesInvisibleUnicode(t *testing.T) {
	// Tag characters spell ASCII that no one sees; the rest render as nothing or
	// as blank space.
	for _, cp := range []rune{0xE0041, 0xE007F, 0xFE0F, 0xE0100, 0x3164, 0x2800, 0x00A0, 0x00AD, 0x2060, 0x7F, 0x9F} {
		got := String("a"+r(cp)+"b", 0)
		if strings.ContainsRune(got, cp) || !strings.HasPrefix(got, `a\u{`) {
			t.Errorf("U+%04X: %q", cp, got)
		}
	}
	for _, ok := range []string{"web-1", "café", "日本語", "Ünïcödé"} {
		if got := String(ok, 0); got != ok {
			t.Errorf("%q changed to %q", ok, got)
		}
	}
}

func TestStringBoundsWorkByMax(t *testing.T) {
	huge := strings.Repeat(r(0x1B), 1<<20)
	got := String(huge, 64)
	if len(got) > 64 || !strings.HasSuffix(got, truncatedSuffix) {
		t.Errorf("len %d: %q", len(got), got)
	}
	if want := String(huge[:64], 64); got != want {
		t.Errorf("prefix result %q, want %q", got, want)
	}
}

func TestFieldsRedactsCredentialShapesOnlyInTaggedFields(t *testing.T) {
	// Assembled at run time so that no credential shape sits in the source.
	key := "tskey" + "-auth-" + "kTEST1CNTRL-" + "notarealsecretvalue"
	o := struct {
		Name string `json:"name" tk:"untrusted"`
		ID   string `json:"id"`
	}{Name: "box " + key, ID: key}
	Fields(&o, 0)
	if strings.Contains(o.Name, "tskey") || !strings.Contains(o.Name, tripwire.Redacted) {
		t.Errorf("Name = %q", o.Name)
	}
	// An untagged field keeps it, so the tripwire still withholds the result.
	if o.ID != key {
		t.Errorf("ID = %q", o.ID)
	}
}

// Escaping and the cap can make two map keys the same text, and a map holds one entry for
// them: the others were dropped, and which one stayed depended on the order Go ranged over
// the map. Every entry is kept, under a counter after the second key and the ones that
// follow, in the order of the keys as they were, so the result is the same every time.
func TestFieldsKeepsEveryMapEntryWhoseKeysCollide(t *testing.T) {
	type out struct {
		Tagged map[string]string `json:"tagged" tk:"untrusted"`
		Plain  map[string]string `json:"plain"`
		Ints   map[int]string    `json:"ints"`
	}
	esc := string(rune(92)) + "u{001B}"
	long := strings.Repeat("k", 40)
	build := func() out {
		return out{
			// A control character and the text that spells it, and a key that is the counter
			// the second one gets.
			Tagged: map[string]string{"a\x1b": "one", "a" + esc: "two", "a" + esc + "#2": "three"},
			// Bytes that are not UTF-8, and the text that stands for them.
			Plain: map[string]string{"b\xff": "x", "b\xfe": "y", "b" + string(rune(92)) + "u{FFFD}": "z"},
			Ints:  map[int]string{1: "i", 2: "j"},
		}
	}
	var first out
	for i := range 60 {
		o := build()
		Fields(&o, 0)
		if i == 0 {
			first = o
			continue
		}
		if !reflect.DeepEqual(o, first) {
			t.Fatalf("run %d: %v, but the first run gave %v", i, o, first)
		}
	}
	wantTagged := map[string]string{"a" + esc: "one", "a" + esc + "#2": "two", "a" + esc + "#2#2": "three"}
	if !reflect.DeepEqual(first.Tagged, wantTagged) {
		t.Errorf("tagged keys = %v, want %v", first.Tagged, wantTagged)
	}
	// Three keys of one text take the plain text, #2 and #3, in the order of the keys as they were
	// (the spelled escape sorts before the bytes 0xFE and 0xFF).
	wantPlain := map[string]string{"b" + string(rune(92)) + "u{FFFD}": "z", "b" + string(rune(92)) + "u{FFFD}#2": "y", "b" + string(rune(92)) + "u{FFFD}#3": "x"}
	if !reflect.DeepEqual(first.Plain, wantPlain) {
		t.Errorf("plain keys = %v, want %v", first.Plain, wantPlain)
	}
	if !reflect.DeepEqual(first.Ints, map[int]string{1: "i", 2: "j"}) {
		t.Errorf("int keys = %v", first.Ints)
	}
	// Keys cut at the cap collide too, and the counter stays within the cap.
	capped := struct {
		M map[string]string `json:"m" tk:"untrusted"`
	}{M: map[string]string{long + "1": "one", long + "2": "two", long + "3": "three"}}
	Fields(&capped, 24)
	base := strings.Repeat("k", 10) + truncatedSuffix // 24 bytes: the counter cuts two bytes off it
	wantCapped := map[string]string{base: "one", base[:22] + "#2": "two", base[:22] + "#3": "three"}
	if !reflect.DeepEqual(capped.M, wantCapped) {
		t.Errorf("capped keys = %v, want %v", capped.M, wantCapped)
	}
	// Many keys of one text: the n-th, in the order of the keys as they were, is the plain text for
	// the first and #n for the others, however many came before it.
	keys := collidingKeys(200)
	raw := make([]string, 0, len(keys))
	for k := range keys {
		raw = append(raw, k)
	}
	sort.Strings(raw)
	for i, k := range raw {
		keys[k] = strconv.Itoa(i) // a value that escaping leaves as it is: the key's rank
	}
	many := struct {
		M map[string]string `json:"m" tk:"untrusted"`
	}{M: keys}
	Fields(&many, DefaultMax)
	shown := "k" + strings.Repeat(string(rune(92))+"u{0001}", bits.Len(200))
	for i := range raw {
		want := shown
		if i > 0 {
			want = shown + "#" + strconv.Itoa(i+1)
		}
		if got := many.M[want]; got != strconv.Itoa(i) {
			t.Fatalf("the %dth of 200 colliding keys: %q holds the value of key %q, want that of key %d", i+1, want, got, i)
		}
	}
	if len(many.M) != 200 {
		t.Errorf("%d keys, want 200", len(many.M))
	}
}

// Masked text is cut after it is masked, and a cut can land inside the pseudonym that masking
// appended. What is left of a marker is dropped with it: the text ends before the marker, so
// no cut shows a pseudonym that is not whole.
func TestStringNeverCutsInsideAPseudonymMarker(t *testing.T) {
	const marker = " [p:abcdefghij]"
	whole, dropped := 0, 0
	for pad := 0; pad <= 60; pad++ {
		text := strings.Repeat("x", pad) + marker + " " + strings.Repeat("q", 60)
		for _, max := range []int{40, 48, 64} {
			cut := max - len(truncatedSuffix) // where the cap cuts the text
			var want string
			switch {
			case cut <= pad:
				want = text[:cut]
			case cut == pad+1:
				want = text[:cut] // a lone space is no part of a marker
			case cut < pad+len(marker):
				want, dropped = text[:pad], dropped+1 // inside the marker: all of it goes
			default:
				want, whole = text[:cut], whole+1 // after the marker: it stays
			}
			if got := String(text, max); got != want+truncatedSuffix {
				t.Errorf("String(%d x, a marker and more, %d) = %q, want %q", pad, max, got, want+truncatedSuffix)
			}
		}
	}
	if whole < 20 || dropped < 20 {
		t.Errorf("the cases do not reach both outcomes: %d with a whole marker, %d with it dropped", whole, dropped)
	}
	// Text that is not cut, and text whose cut is not in a marker, is as it was.
	if got := String("a"+marker, 0); got != "a"+marker {
		t.Errorf("no cap: %q", got)
	}
	if got := String("a"+marker, 100); got != "a"+marker {
		t.Errorf("under the cap: %q", got)
	}
	if got := String(strings.Repeat("y", 50)+" [ not a marker", 30); got != strings.Repeat("y", 16)+truncatedSuffix {
		t.Errorf("a cut before any marker: %q", got)
	}
	// The start of a marker (" [" and " [p") goes with it.
	for _, tail := range []string{" [", " [p", " [p:", " [p:abc"} {
		text := strings.Repeat("z", 16) + tail + strings.Repeat("q", 40)
		if got, want := String(text, 30), strings.Repeat("z", 16)+truncatedSuffix; got != want {
			t.Errorf("String(…%q…, 30) = %q, want %q", tail, got, want)
		}
	}
}
