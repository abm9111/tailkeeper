package acl

import (
	"encoding/json"
	"strings"
	"unicode"

	"github.com/tailscale/hujson"
)

// foldKey is the form under which Go's encoding/json matches the name of a struct field to
// a key: letters equal under simple Unicode case folding (the Kelvin sign is a K, the long
// s is an s) have the same form. Keys of a map are not folded.
func foldKey(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return strings.ToUpper(s)
	}
	var b strings.Builder
	for _, r := range s {
		low := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < low {
				low = f
			}
		}
		b.WriteRune(low)
	}
	return b.String()
}

// nameOf decodes the text of an object member's name.
func nameOf(v *hujson.Value) string {
	lit, ok := v.Value.(hujson.Literal)
	if !ok || len(lit) < 2 {
		return ""
	}
	if !strings.Contains(string(lit), `\`) {
		return string(lit[1 : len(lit)-1])
	}
	var s string
	if json.Unmarshal(lit, &s) != nil {
		return string(lit)
	}
	return s
}

// escapePointer escapes one reference token of a JSON Pointer (RFC 6901).
func escapePointer(s string) string {
	if !strings.ContainsAny(s, "~/") {
		return s
	}
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}
