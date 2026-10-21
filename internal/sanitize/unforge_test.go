package sanitize

import (
	"strings"
	"testing"
)

// Unforge is the rewrite Text and PolicyText start with, offered alone for text that is not
// masked by the masker but must not carry a marker the masker did not append (a message
// Tailscale echoed from a proposal).
func TestUnforgeLeavesNoMarkerTheMaskerDidNotAppend(t *testing.T) {
	m, _ := keyedMasker(t)
	spelled := string(rune(92)) + "u{005B}p:" // how a bracket is written where a marker was
	inputs := []string{
		"", "no marker here", "[p:abcdefghij]", "x [p:abcdefghij]", "[[p:abcdefghij]]",
		"[p:[p:abcdefghij", "a…@example.com [p:abcdefghij]", "[p:", "p:abcdefghij", "[p", "p:]",
		"two [p:aaaaaaaaaa] and [p:bbbbbbbbbb]",
	}
	checked := 0
	for _, in := range inputs {
		checked++
		got := m.Unforge(in)
		if strings.Contains(got, "[p:") {
			t.Errorf("Unforge(%q) = %q still holds a marker", in, got)
		}
		if want := strings.ReplaceAll(in, "[p:", spelled); got != want {
			t.Errorf("Unforge(%q) = %q, want %q: only the marker may change", in, got, want)
		}
		if again := m.Unforge(got); again != got {
			t.Errorf("Unforge is not idempotent on %q: %q", got, again)
		}
		if !strings.Contains(in, "@") {
			if pt := m.PolicyText(in); pt != got {
				t.Errorf("PolicyText(%q) = %q, want the same rewrite as Unforge: %q", in, pt, got)
			}
		}
		// Without a key nothing is named, so nothing is rewritten.
		if plain := NewMasker(nil).Unforge(in); plain != in {
			t.Errorf("a keyless Unforge(%q) = %q, want the text as it came", in, plain)
		}
	}
	if checked != len(inputs) || checked != 12 {
		t.Fatalf("checked %d inputs, want all 12", checked)
	}
}
