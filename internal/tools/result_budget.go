package tools

import (
	"encoding/json"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tripwire"
)

// A result goes to the host in one frame of at most 16 MiB, and the frame holds the result
// twice (as structured content and as text) with every quote and backslash doubled in the second
// copy. The tools below that read text the tailnet or its policy supplies count what they put
// in a result against a budget of characters, counted as the registry will show them and as JSON
// text, where an angle bracket costs six bytes, and leave the rest out with a word that says so.

// shownCost is what the string s takes in a result once the registry has made it safe and cut
// it: its length as JSON text, with its quotes and the comma after it.
func shownCost(s string) int {
	return encodedLen(sanitize.String(tripwire.Redact(s), registry.ResultStringMax)) + 3
}

// shownJSONLen is the length, as JSON text, of v as a result will show it: masked, escaped and
// cut by the same pass the registry runs. v is not changed.
func shownJSONLen[T any](env *registry.Env, v T) int {
	b, err := json.Marshal(v)
	if err != nil {
		return 1 << 30
	}
	var shown T
	if json.Unmarshal(b, &shown) != nil {
		return 1 << 30
	}
	env.Display(&shown)
	b, err = json.Marshal(shown)
	if err != nil {
		return 1 << 30
	}
	return len(b)
}

// shownText is the string s as the registry shows an untrusted field: its addresses and
// logins masked. Where the owner chose to see personal data it is s. A budget counts a value
// by this, not by s, so that where a list is cut tells nothing of how long a masked value is.
func shownText(env *registry.Env, s string) string {
	if env.ShowPersonalData() {
		return s
	}
	return env.Masker().Text(s)
}

// shownWhole is the string s as the registry shows a field masked whole (a profile id, a login):
// see shownText.
func shownWhole(env *registry.Env, s string) string {
	if env.ShowPersonalData() {
		return s
	}
	return env.Masker().Identifier(s)
}
