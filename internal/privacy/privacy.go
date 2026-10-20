// Package privacy holds the per-install privacy key (spec §7.6) and what it
// derives: pseudonyms that follow masked values, and keyed digests of audit-log
// values (spec Appendix C). The key itself is never used directly, printed or
// returned.
package privacy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// EnvKey is the variable that carries the key, beside the read credential.
const EnvKey = "TAILKEEPER_PRIVACY_KEY"

// Derivation labels: changing one changes every pseudonym or digest.
const (
	pseudonymLabel = "tailkeeper pseudonym v1"
	digestLabel    = "tailkeeper digest v1"
)

// Key names values under the two keys derived from the privacy key: a pseudonym
// key and a digest key. The derived bytes are captured by two functions and held
// in no field, because fmt prints a struct's fields itself, without calling
// Format, in two cases: a bad verb (%p or %w on a value, %s on a field that is a
// pointer) prints what a pointer points to, and an unexported field of another
// struct is printed field by field. A function prints as an address under every
// verb, so no verb, on a Key, a pointer to one, a struct field, a slice element or
// a map value, can reach the bytes, and a Key copied or compared holds nothing
// to read.
type Key struct {
	pseudonym func(normalized string) []byte
	digest    func(b []byte) []byte
}

// ready returns k, or stops if it is not what Parse returned: a pseudonym or digest
// derived from nothing would look like any other.
func (k *Key) ready() *Key {
	if k == nil || k.pseudonym == nil || k.digest == nil {
		panic("privacy: use of a Key that Parse did not return")
	}
	return k
}

// Parse reads a key written as 64 hexadecimal characters. Its error never
// quotes the input.
func Parse(s string) (*Key, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		return nil, tkerr.New(tkerr.PrivacyKeyUnavailable,
			EnvKey+" must be 64 hexadecimal characters (32 random bytes)",
			"generate one with `openssl rand -hex 32` and keep it where the read credential is kept")
	}
	pk, dk := derive(b, pseudonymLabel), derive(b, digestLabel)
	return &Key{
		pseudonym: func(v string) []byte { return mac(pk, []byte(v)) },
		digest:    func(b []byte) []byte { return mac(dk, b) },
	}, nil
}

func derive(master []byte, label string) []byte { return mac(master, []byte(label)) }

func mac(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Pseudonym names text without revealing it: "p:" and the first ten base32
// characters of its HMAC under the pseudonym key, after Normalize. It is for text read
// from a policy or from a result's free text, where a login may be spelled with JSON
// escapes; a value the API returned is named by APIPseudonym.
func (k *Key) Pseudonym(value string) string { return k.name(Normalize(value)) }

// APIPseudonym names a value the Tailscale API returned (a login name, a display name)
// as Pseudonym names text, except that it decodes nothing: such a value is not text, and
// a login that holds a backslash sequence is not the address the sequence spells. An
// address is lower-cased, so the pseudonym of a login is the one of the same address in a
// policy.
func (k *Key) APIPseudonym(value string) string { return k.name(foldAddress(value)) }

// name is the pseudonym of an already normalized value.
func (k *Key) name(normalized string) string {
	return "p:" + strings.ToLower(b32.EncodeToString(k.ready().pseudonym(normalized)[:7]))[:10]
}

// foldAddress lower-cases a value that holds an at sign.
func foldAddress(v string) string {
	if strings.Contains(v, "@") {
		return strings.ToLower(v)
	}
	return v
}

// Digest is a keyed digest of b, which confirms nothing to whoever lacks the key.
func (k *Key) Digest(b []byte) string {
	return "hmac-sha256:" + hex.EncodeToString(k.ready().digest(b))
}

// Format keeps key material out of every format verb. fmt calls it before any
// other way of printing, so the numeric verbs (%d %o %b %c %U %e %t), which
// expand a struct's fields and a byte slice's elements and would print the
// derived keys, print the same "privacy key" as %v. It has a value receiver:
// with a pointer receiver, printing a Key by value (a copy, a struct field, a
// slice element) would not call it.
func (Key) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "privacy key") }

// String is what a Key is called as text outside fmt.
func (Key) String() string { return "privacy key" }

// Normalize is what the pseudonym of text is computed over: JSON escapes decoded, since a
// policy file may spell a login with them, and email addresses lower-cased. It is applied
// once, to text read from a policy; Pseudonym applies it itself, so a caller does not, and a
// login the API returned never goes through it (see APIPseudonym).
func Normalize(v string) string {
	if strings.Contains(v, `\u`) {
		var d string
		if json.Unmarshal([]byte(`"`+v+`"`), &d) == nil {
			v = d
		}
	}
	return foldAddress(v)
}

var (
	refRE    = regexp.MustCompile(`^p:[a-z2-7]{10}$`)
	suffixRE = regexp.MustCompile(`(?:^| )\[(p:[a-z2-7]{10})\]$`)
)

// Ref returns the pseudonym s names: s itself, the bracketed form alone, or the
// masked value ending in it.
func Ref(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if refRE.MatchString(s) {
		return s, true
	}
	if m := suffixRE.FindStringSubmatch(s); m != nil {
		return m[1], true
	}
	return "", false
}

// Suffix is a pseudonym as masking appends it to a masked value.
func Suffix(p string) string { return " [" + p + "]" }
