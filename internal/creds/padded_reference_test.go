package creds

import (
	"context"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// A value is a file reference when it starts with "file:" once its spaces are trimmed. A
// reference with a space, a tab or a line end around it (a stray newline pasted from a
// terminal is the usual one) used to be read as a token that was literally "file:/path":
// the leading case skipped the prefix check and the absolute-path rule with it. It is
// refused now, with a message that says to remove the spaces and never shows the value.
// Plain values are trimmed as before.
func TestAFileReferenceWithSurroundingSpacesIsRefused(t *testing.T) {
	path := absPath("/run/secrets/value")
	key := strings.Repeat("5a", 32)
	for name, v := range map[string]string{
		"leading space":                  " file:" + path,
		"trailing space":                 "file:" + path + " ",
		"both":                           "  file:" + path + "\t",
		"leading tab":                    "\tfile:" + path,
		"trailing newline":               "file:" + path + "\n",
		"a relative path, leading space": " file:secrets/key",
		"only the prefix, padded":        " file: ",
	} {
		t.Run(name, func(t *testing.T) {
			reads := 0
			read := func(string) ([]byte, error) { reads++; return []byte(key), nil }
			tok, err := value(EnvAPIKey, v, read)
			e, ok := tkerr.As(err)
			if !ok || e.Code != tkerr.ConfigInvalid || tok != "" {
				t.Fatalf("value(%q) = %q, %v: want no token and config_invalid", v, tok, err)
			}
			if !strings.Contains(e.Message, EnvAPIKey) || !strings.Contains(e.Message+" "+e.Hint, "remove the spaces") ||
				strings.Contains(e.Message+e.Hint, path) || strings.Contains(e.Message+e.Hint, "secrets/key") {
				t.Errorf("message %q, hint %q: want the variable, the instruction to remove the spaces, and no path", e.Message, e.Hint)
			}
			if reads != 0 {
				t.Errorf("a refused reference still read a file %d times", reads)
			}
			// Through the provider: the variable never becomes a credential.
			s := System{Getenv: func(k string) string {
				if k == EnvAPIKey {
					return v
				}
				return ""
			}, ReadSecretFile: read}
			r, err := Resolve(context.Background(), config.Provider{Provider: "env"}, s)
			if code(err) != tkerr.ConfigInvalid || r.Kind != "" || r.APIKey.Reveal() != "" {
				t.Errorf("Resolve returned %+v, %v: want no credential and config_invalid", r, err)
			}
			if reads != 0 {
				t.Errorf("Resolve read a file %d times", reads)
			}
		})
	}
}

// For the privacy key the same refusal is the key's own code, with the reason and the fix
// shown, as for a relative path, and no value.
func TestAPaddedPrivacyKeyReferenceIsRefusedWithItsReason(t *testing.T) {
	v := " file:" + absPath("/run/secrets/key")
	s := sys(map[string]string{privacy.EnvKey: v}, nil)
	k, _, err := LoadPrivacyKey(config.Provider{Provider: "env"}, s)
	e, ok := tkerr.As(err)
	if !ok || k != nil || e.Code != tkerr.PrivacyKeyUnavailable || !strings.Contains(e.Message, privacy.EnvKey) ||
		!strings.Contains(e.Message+e.Hint, "remove the spaces") || strings.Contains(e.Message+e.Hint, "/run/secrets") {
		t.Fatalf("key %v, err %v: want privacy_key_unavailable that names the variable and says to remove the spaces", k, err)
	}
}

// What stays as it was: a plain value is trimmed, a reference without spaces is read, and a
// value that merely contains "file:" later in its text is a plain value.
func TestPlainValuesAndTightReferencesAreUnchanged(t *testing.T) {
	path := absPath("/run/secrets/value")
	read := func(p string) ([]byte, error) {
		if p != path {
			t.Errorf("read %q", p)
		}
		return []byte("  from-file \n"), nil
	}
	for name, c := range map[string]struct{ in, want string }{
		"plain":                   {"token", "token"},
		"plain with spaces":       {"  token\t\n", "token"},
		"empty":                   {"", ""},
		"blank":                   {" \t", ""},
		"file: later in the text": {" a file:/x ", "a file:/x"},
		"a reference":             {"file:" + path, "from-file"},
		"an upper-case prefix":    {" FILE:/x ", "FILE:/x"},
	} {
		got, err := value(EnvAPIKey, c.in, read)
		if err != nil || got != c.want {
			t.Errorf("%s: value(%q) = %q, %v; want %q", name, c.in, got, err, c.want)
		}
	}
}
