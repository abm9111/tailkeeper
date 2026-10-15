// Package sanitize makes attacker-influenced tailnet text safe to show (spec §3, §17).
//
// Struct fields carrying such text are tagged `tk:"untrusted"` (a comma-separated
// tag; other values such as "rows" and "col" are used by the CLI renderer).
package sanitize

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/abm9111/tailkeeper/internal/tripwire"
)

// DefaultMax is the byte cap for one untrusted string in tool results.
const DefaultMax = 1024

const truncatedSuffix = "...[truncated]"

// MaxText caps one multi-line field (`tk:"untrusted,multiline"`, such as a page
// of the policy file). It is a backstop: acl_get pages the policy below 4 MiB of
// JSON text and refuses a longer line, so no page of it reaches this cap.
const MaxText = 16 << 20

// String renders every rune that does not print visibly (control characters, ANSI
// escape introducers, bidirectional, zero-width and other format characters, tag
// characters, variation selectors, blank fillers) and invalid UTF-8 as visible
// \u{XXXX} escapes, then cuts the result to max bytes on a rune boundary. max <= 0
// means no cap.
func String(s string, max int) string { return escape(s, max, false) }

// Text is String for multi-line documents such as the policy file: line feeds and
// tabs are kept, a CRLF line end is shown as LF, and a lone carriage return, like
// every other invisible character, is escaped. A terminal only moves the cursor
// for LF and TAB; nothing else can redraw or hide text.
func Text(s string, max int) string { return escape(strings.ReplaceAll(s, "\r\n", "\n"), max, true) }

func escape(s string, max int, lines bool) string {
	truncated := false
	if max > 0 && len(s) > max {
		// Escaping never shortens text, so input past max bytes cannot reach the
		// output: dropping it first bounds the work.
		cut := max
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s, truncated = s[:cut], true
	}
	var b strings.Builder
	for i, r := range s {
		if r == utf8.RuneError {
			if _, size := utf8.DecodeRuneInString(s[i:]); size <= 1 {
				b.WriteString(`\u{FFFD}`)
				continue
			}
		}
		if unsafeRune(r) && !(lines && (r == '\n' || r == '\t')) {
			fmt.Fprintf(&b, `\u{%04X}`, r)
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if max <= 0 || (!truncated && len(out) <= max) {
		return out
	}
	cut := max - len(truncatedSuffix)
	if cut < 0 {
		cut = 0
	}
	if cut < len(out) {
		for cut > 0 && !utf8.RuneStart(out[cut]) {
			cut--
		}
		out = dropPartialMarker(out[:cut])
	}
	return out + truncatedSuffix
}

// markerOpen is how the pseudonym marker that masking appends to a masked value starts:
// privacy.Suffix writes it as " [p:" and ten characters and "]".
const markerOpen = " [p:"

// dropPartialMarker removes a pseudonym marker that the end of s cuts through (or the start
// of one: " [" and " [p"), so a cut never leaves a pseudonym that a filter or a reader could
// take for another. Masked text is cut after it is masked, so a cut can land in a marker.
func dropPartialMarker(s string) string {
	for k := len(markerOpen) - 1; k >= 2; k-- {
		if strings.HasSuffix(s, markerOpen[:k]) {
			return s[:len(s)-k]
		}
	}
	if i := strings.LastIndex(s, markerOpen); i >= 0 && !strings.Contains(s[i:], "]") {
		return s[:i]
	}
	return s
}

func unsafeRune(r rune) bool {
	switch {
	case r < 0x20, r == 0x7F, r >= 0x80 && r <= 0x9F:
		return true // C0 (including \n, \t, ESC), DEL, C1
	case r == 0x061C, r == 0x2028, r == 0x2029, r == 0xFEFF:
		return true // Arabic letter mark, line/paragraph separators, BOM
	case r >= 0x200B && r <= 0x200F:
		return true // zero-width space/joiners, LRM, RLM
	case r >= 0x202A && r <= 0x202E:
		return true // bidi embeddings and overrides
	case r >= 0x2066 && r <= 0x2069:
		return true // bidi isolates
	case r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0100 && r <= 0xE01EF:
		return true // variation selectors
	case r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0, r == 0x2800:
		return true // fillers that render as blank space
	case unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r), unicode.Is(unicode.Variation_Selector, r):
		return true // marks that render as nothing, such as U+034F and the Mongolian selectors
	case !strconv.IsPrint(r):
		// Every other format character (the tag block U+E0000-E007F spells
		// invisible ASCII), private-use, unassigned or non-ASCII space character.
		return true
	}
	return false
}

// HasTag reports whether a `tk` struct tag value contains the given option.
func HasTag(tag reflect.StructTag, option string) bool {
	for _, part := range strings.Split(tag.Get("tk"), ",") {
		if strings.TrimSpace(part) == option {
			return true
		}
	}
	return false
}

// Fields escapes, in place, every string reachable from ptr (a pointer). Strings
// inside a field tagged `tk:"untrusted"` (text tailnet members choose) are also
// capped at max and have credential shapes replaced (tripwire.Redact); a tagged
// struct, slice or map field has everything inside it treated as untrusted. A
// string field tagged `tk:"untrusted,multiline"` keeps its line feeds and tabs
// (Text) and is capped at MaxText. Map keys and values are rebuilt; keys that are
// the same text once escaped and capped are all kept (see distinctKey). It panics
// unless ptr is a non-nil pointer: skipping the escaping of a result is a
// programming error that must not pass silently.
func Fields(ptr any, max int) {
	v := reflect.ValueOf(ptr)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		panic(fmt.Sprintf("sanitize.Fields: want a non-nil pointer, got %T", ptr))
	}
	walk(v.Elem(), false, false, max)
}

func walk(v reflect.Value, untrusted, multiline bool, max int) {
	switch v.Kind() {
	case reflect.String:
		if !v.CanSet() {
			return
		}
		switch {
		case multiline:
			v.SetString(Text(tripwire.Redact(v.String()), MaxText))
		case untrusted:
			v.SetString(String(tripwire.Redact(v.String()), max))
		default:
			v.SetString(String(v.String(), 0))
		}
	case reflect.Pointer:
		if !v.IsNil() {
			walk(v.Elem(), untrusted, multiline, max)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			walk(v.Field(i), untrusted || HasTag(f.Tag, "untrusted"), multiline || HasTag(f.Tag, "multiline"), max)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			walk(v.Index(i), untrusted, multiline, max)
		}
	case reflect.Map:
		if v.IsNil() || !v.CanSet() {
			return
		}
		fresh := reflect.MakeMapWithSize(v.Type(), v.Len())
		keys := v.MapKeys()
		if v.Type().Key().Kind() == reflect.String {
			// Go ranges over a map in a random order, and keys can collide once they are
			// escaped: a fixed order makes the result the same every time.
			sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		}
		next := map[string]int{} // for each escaped key that collided, the counter to try next
		for _, key := range keys {
			k := reflect.New(v.Type().Key()).Elem()
			k.Set(key)
			walk(k, untrusted, multiline, max)
			if k.Kind() == reflect.String {
				k.SetString(distinctKey(fresh, k, keyCap(untrusted, multiline, max), next))
			}
			val := reflect.New(v.Type().Elem()).Elem()
			val.Set(v.MapIndex(key))
			walk(val, untrusted, multiline, max)
			fresh.SetMapIndex(k, val)
		}
		v.Set(fresh)
	}
}

// keyCap is the byte cap walk puts on a string in the field it is reading.
func keyCap(untrusted, multiline bool, max int) int {
	switch {
	case multiline:
		return MaxText
	case untrusted:
		return max
	}
	return 0
}

// distinctKey is the escaped key k, or k with a counter after it ("#2", "#3") when fresh
// already holds it. Escaping and the cap can make two keys the same text (a control
// character and the \u{001B} that spells it, bytes that are not UTF-8, keys cut at the cap),
// and a map holds one entry for them: the rest would be dropped, and a crafted key could
// hide another's entry. The counter stays within max bytes. The counters tried for a text
// are all taken once a key has passed them, and an entry is never removed, so next holds
// where the next key of that text resumes: the answer is the same as counting from #2 each
// time, without the cost of K keys that collide being K squared.
func distinctKey(fresh, k reflect.Value, max int, next map[string]int) string {
	base := k.String()
	cand := base
	n := 2
	if resume := next[base]; resume > n {
		n = resume
	}
	for ; fresh.MapIndex(reflect.ValueOf(cand).Convert(k.Type())).IsValid(); n++ {
		tail := "#" + strconv.Itoa(n)
		keep := base
		if max > 0 && len(base)+len(tail) > max {
			cut := max - len(tail)
			if cut < 0 {
				cut = 0
			}
			for cut > 0 && !utf8.RuneStart(base[cut]) {
				cut--
			}
			keep = base[:cut]
		}
		cand = keep + tail
		next[base] = n + 1
	}
	return cand
}

// UntrustedPaths lists, in sorted order, the JSON paths of fields tagged
// `tk:"untrusted"` in type t. Slice elements are written as "[]".
func UntrustedPaths(t reflect.Type) []string {
	var out []string
	collect(t, "", map[reflect.Type]bool{}, &out)
	sort.Strings(out)
	return out
}

func collect(t reflect.Type, prefix string, seen map[reflect.Type]bool, out *[]string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Interface:
		panic(unsupported(prefix, "is an interface"))
	case reflect.Map:
		if !scalar(t.Key()) || !scalar(t.Elem()) {
			panic(unsupported(prefix, "is a map whose keys or values are not scalars"))
		}
		return
	case reflect.Slice, reflect.Array:
		if t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8 {
			panic(unsupported(prefix, "is raw bytes ([]byte, json.RawMessage), which would carry unchecked text"))
		}
		collect(t.Elem(), prefix+"[]", seen, out)
		return
	case reflect.Struct:
	default:
		return
	}
	if seen[t] {
		return
	}
	seen[t] = true
	defer delete(seen, t)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous {
			panic(unsupported(join(prefix, f.Name), "is an embedded struct"))
		}
		if !f.IsExported() {
			continue
		}
		name := jsonName(f)
		if name == "-" {
			continue
		}
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		if HasTag(f.Tag, "multiline") && (!HasTag(f.Tag, "untrusted") || f.Type.Kind() != reflect.String) {
			panic(unsupported(path, "is tagged multiline but is not an untrusted string; multiline only relaxes escaping for untrusted text"))
		}
		if HasTag(f.Tag, "untrusted") {
			*out = append(*out, path)
			// The whole field is untrusted, but its shape must still be one
			// Fields can walk.
			var inner []string
			collect(f.Type, path, seen, &inner)
			continue
		}
		collect(f.Type, path, seen, out)
	}
}

// unsupported describes an output shape Fields cannot sanitize. UntrustedPaths
// panics with it, so a tool using that shape fails at registration instead of
// returning unescaped text.
func unsupported(path, what string) string {
	if path == "" {
		path = "(top level)"
	}
	return fmt.Sprintf("sanitize: output field %q %s; tool outputs may hold only structs, pointers, slices and maps of scalars", path, what)
}

// jsonName is the name encoding/json gives field f: its json tag's name, or the
// Go name when the tag has none. "-" means the field is never encoded.
func jsonName(f reflect.StructField) string {
	if name := strings.Split(f.Tag.Get("json"), ",")[0]; name != "" {
		return name
	}
	return f.Name
}

func join(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

func scalar(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Bool, reflect.String, reflect.Float32, reflect.Float64,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	}
	return false
}

// MaskID keeps the first four characters of an identifier such as a tailnet or
// OAuth client ID and drops the rest, so a report shows which one is meant
// without spreading the whole ID into terminals and agent transcripts. IDs of
// eight characters or fewer are kept whole: too short to identify anything.
func MaskID(id string) string {
	r := []rune(id)
	if len(r) <= 8 {
		return id
	}
	return string(r[:4]) + "…"
}
