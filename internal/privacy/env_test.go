package privacy_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
)

// testMaster is the key every test here parses.
var testMaster = strings.Repeat("5a", 32)

// holder keeps a Key the ways a program does: by value in exported and unexported
// fields, and by pointer. fmt cannot call a method on an unexported field, so it
// prints what is inside the Key itself.
type holder struct {
	Pub  privacy.Key
	priv privacy.Key
	P    *privacy.Key
}

// verbs is every fmt verb a program might use, with %p and %w, which fmt handles
// before it looks for a Format method, and some that are not verbs at all.
var verbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%o", "%b", "%c", "%U", "%e", "%t", "%p", "%w", "%T", "%!", "%z", "%10v", "%-8s", "%08d"}

// secretsIn returns, for each derived key, the forms in which its bytes could
// appear in output printed with verb.
func secretsIn(verb string) []string {
	var out []string
	for _, b := range privacy.Derived(testMaster) {
		out = append(out, hex.EncodeToString(b), fmt.Sprint(b), string(b), fmt.Sprintf(verb, b), fmt.Sprintf("%#v", b))
	}
	return out
}

// An Env holds the key where logs and error paths can reach it, so printing the
// Env, or a copy of it, must show none of the derived keys. Neither may printing
// the key itself, by value, by pointer, in a struct field (exported or not), a
// slice, an array or a map, whatever the verb.
func TestAnEnvHoldingTheKeyNeverPrintsIt(t *testing.T) {
	k, err := privacy.Parse(testMaster)
	if err != nil {
		t.Fatal(err)
	}
	env := registry.Env{Privacy: k}
	h := holder{Pub: *k, priv: *k, P: k}
	for name, v := range map[string]any{
		"env": env, "pointer to env": &env, "key": k, "key copy": *k, "slice of envs": []registry.Env{env},
		"holder": h, "pointer to holder": &h, "slice of keys": []privacy.Key{*k}, "array of keys": [1]privacy.Key{*k},
		"map of keys": map[string]privacy.Key{"a": *k}, "map of pointers": map[string]*privacy.Key{"a": k}, "slice of pointers": []*privacy.Key{k},
		"interface holding a key": []any{*k}, "struct of a holder": struct{ H holder }{h},
	} {
		for _, verb := range verbs {
			s := fmt.Sprintf(verb, v)
			for _, secret := range secretsIn(verb) {
				if strings.Contains(s, secret) {
					t.Errorf("%s printed with %s shows key material %q", name, verb, secret)
				}
			}
		}
		if s := fmt.Sprint(v) + fmt.Sprintln(v) + fmt.Sprintf("%v", fmt.Errorf("wrapped: %w", fmt.Errorf("%v", v))); strings.Contains(s, hex.EncodeToString(privacy.Derived(testMaster)[0])) {
			t.Errorf("%s printed by Sprint, Sprintln or Errorf shows key material", name)
		}
	}
}

// Nor does JSON or a structured logger, which reach a value without fmt's verbs.
func TestAnEnvHoldingTheKeyNeverEncodesIt(t *testing.T) {
	k, err := privacy.Parse(testMaster)
	if err != nil {
		t.Fatal(err)
	}
	env := registry.Env{Privacy: k}
	h := holder{Pub: *k, priv: *k, P: k}
	values := map[string]any{"key": k, "key copy": *k, "env": env, "holder": h, "map": map[string]privacy.Key{"a": *k}}
	for name, v := range values {
		if b, err := json.Marshal(v); err == nil {
			assertNoKeyBytes(t, "json "+name, string(b))
		}
		var text, js bytes.Buffer
		slog.New(slog.NewTextHandler(&text, nil)).Info("m", "v", v, slog.Any("w", v))
		slog.New(slog.NewJSONHandler(&js, nil)).Info("m", "v", v, slog.Any("w", v))
		assertNoKeyBytes(t, "slog text "+name, text.String())
		assertNoKeyBytes(t, "slog json "+name, js.String())
	}
}

func assertNoKeyBytes(t *testing.T, what string, s string) {
	t.Helper()
	for _, b := range privacy.Derived(testMaster) {
		for _, secret := range []string{hex.EncodeToString(b), fmt.Sprint(b), string(b)} {
			if strings.Contains(s, secret) {
				t.Errorf("%s shows key material: %.120s", what, s)
			}
		}
	}
}
