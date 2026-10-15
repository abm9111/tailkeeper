package privacy

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

func testKey(t *testing.T) *Key {
	t.Helper()
	k, err := Parse(strings.Repeat("5a", 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var pseudonymRE = regexp.MustCompile(`^p:[a-z2-7]{10}$`)

func TestPseudonymsAreStableKeyedAndNormalized(t *testing.T) {
	k := testKey(t)
	a := k.Pseudonym("amy@example.com")
	if !pseudonymRE.MatchString(a) {
		t.Fatalf("Pseudonym = %q, want p: and ten base32 characters", a)
	}
	if k.Pseudonym("amy@example.com") != a || k.Pseudonym("AMY@Example.COM") != a {
		t.Error("the same address must give the same pseudonym, whatever its case")
	}
	bs := "\\"
	if k.Pseudonym("am"+bs+"u0079@example.com") != a {
		t.Error("a JSON escape inside an address must not change its pseudonym")
	}
	if k.Pseudonym("bob@example.com") == a {
		t.Error("two addresses share a pseudonym")
	}
	other, _ := Parse(strings.Repeat("a5", 32))
	if other.Pseudonym("amy@example.com") == a {
		t.Error("two keys give the same pseudonym")
	}
	if k.Pseudonym("Amy Lee") == k.Pseudonym("amy lee") {
		t.Error("a display name is not an address: its case must count")
	}
}

func TestDigestsAreKeyedAndSeparateFromPseudonyms(t *testing.T) {
	k := testKey(t)
	d := k.Digest([]byte(`"amy@example.com"`))
	if !regexp.MustCompile(`^hmac-sha256:[0-9a-f]{64}$`).MatchString(d) {
		t.Fatalf("Digest = %q", d)
	}
	other, _ := Parse(strings.Repeat("a5", 32))
	if other.Digest([]byte("x")) == k.Digest([]byte("x")) {
		t.Error("two keys give the same digest")
	}
}

func TestParseRefusesBadKeysWithoutQuotingThem(t *testing.T) {
	for _, bad := range []string{"", "zz", strings.Repeat("5a", 31), strings.Repeat("5a", 33), strings.Repeat("5g", 32)} {
		_, err := Parse(bad)
		e, ok := tkerr.As(err)
		if !ok || e.Code != tkerr.PrivacyKeyUnavailable {
			t.Errorf("Parse(%d chars) = %v, want privacy_key_unavailable", len(bad), err)
			continue
		}
		if bad != "" && strings.Contains(e.Error(), bad) {
			t.Errorf("the error quotes the key: %v", e)
		}
	}
	if _, err := Parse("  " + strings.Repeat("5A", 32) + "\n"); err != nil {
		t.Errorf("surrounding space and upper case must be accepted: %v", err)
	}
}

// allVerbs is every verb that expands a struct's fields or a byte slice's
// elements, as well as those that print text: a verb missing from a Key's
// formatting prints the derived bytes under it.
var allVerbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%o", "%b", "%c", "%U", "%e", "%t", "%p", "%w"}

// keyBytes renders the derived keys every way fmt could print them under verb:
// as text, as hex, as a list in that verb, and as the first eight bytes of one.
func keyBytes(verb string) []string {
	var out []string
	for _, b := range Derived(strings.Repeat("5a", 32)) {
		out = append(out, hex.EncodeToString(b), string(b), fmt.Sprint(b), fmt.Sprintf("%x", b),
			fmt.Sprintf(verb, b), strings.Trim(fmt.Sprintf(verb, b[:8]), "[]"))
	}
	return out
}

func TestKeyNeverPrints(t *testing.T) {
	k := testKey(t)
	type holder struct{ K Key }
	for name, v := range map[string]any{"pointer": k, "value copy": *k, "struct holding a value": holder{*k},
		"pointer to struct": &holder{*k}, "slice of values": []Key{*k}, "map of values": map[string]Key{"k": *k}} {
		for _, verb := range allVerbs {
			s := fmt.Sprintf(verb, v)
			for _, secret := range keyBytes(verb) {
				if strings.Contains(s, secret) {
					t.Errorf("%s printed with %s shows key material %q: %q", name, verb, secret, s)
				}
			}
			if strings.Contains(s, "5a5a") || strings.Contains(strings.ToLower(s), "pseudonym:") {
				t.Errorf("%s printed with %s shows key material: %q", name, verb, s)
			}
		}
	}
	// Nothing of a Key is printed but its name: a list of fields, even of ones
	// that hold no byte of it, shows how it is built.
	for _, verb := range allVerbs {
		got := fmt.Sprintf(verb, *k)
		if verb == "%p" || verb == "%w" {
			// Not verbs fmt hands a Format method on a value: it reports a bad verb and
			// prints the fields, which are functions and show as addresses.
			if !regexp.MustCompile(`^%!` + verb[1:] + `\(privacy\.Key=\{0x[0-9a-f]+ 0x[0-9a-f]+\}\)$`).MatchString(got) {
				t.Errorf("a key printed with %s is %q, want a bad-verb report of two addresses", verb, got)
			}
		} else if got != "privacy key" {
			t.Errorf("a key printed with %s is %q, want %q", verb, got, "privacy key")
		}
	}
	if got := k.String(); got != "privacy key" {
		t.Errorf("String() = %q", got)
	}
}

// The expected strings were computed outside this program, from the definition
// in the spec (HMAC-SHA-256 of the labelled derivation, base32 of the first seven
// bytes, ten characters), so that changing a label, or the order of the steps,
// fails here instead of silently renaming every pseudonym and digest.
func TestDerivationsKeepTheirLabelsAndShape(t *testing.T) {
	k := testKey(t)
	if got, want := k.Pseudonym("amy@example.com"), "p:ys3mrm23sj"; got != want {
		t.Errorf("Pseudonym = %q, want %q", got, want)
	}
	wantDigest := "hmac-sha256:" + "ed35b855e85075def0dffd276110e0a5" + "298aa48213bbc9cdbe8d4dc8d81a40e4"
	if got := k.Digest([]byte(`"amy@example.com"`)); got != wantDigest {
		t.Errorf("Digest = %q, want %q", got, wantDigest)
	}
	if d := Derived(strings.Repeat("5a", 32)); string(d[0]) == string(d[1]) {
		t.Error("the pseudonym key and the digest key must differ")
	}
	// A digest of the same bytes must not equal a pseudonym's HMAC: the labels
	// keep the two uses apart.
	if strings.Contains(k.Digest([]byte("amy@example.com")), strings.TrimPrefix(k.Pseudonym("amy@example.com"), "p:")) {
		t.Error("a digest and a pseudonym of one value share material")
	}
}

func TestRefFindsAPseudonymAloneOrAtTheEndOfAMaskedValue(t *testing.T) {
	for in, want := range map[string]string{
		"p:abcdefgh23":                   "p:abcdefgh23",
		" p:abcdefgh23 ":                 "p:abcdefgh23",
		"a…@example.com [p:abcdefgh23]":  "p:abcdefgh23",
		"A… [p:abcdefgh23]":              "p:abcdefgh23",
		"[p:abcdefgh23]":                 "p:abcdefgh23",
		"  [p:abcdefgh23]  ":             "p:abcdefgh23",
		"[p:abcdefgh2]":                  "",
		"[p:ABCDEFGH23]":                 "",
		"x[p:abcdefgh23]":                "",
		"[p:abcdefgh23]]":                "",
		"[[p:abcdefgh23]":                "",
		"p:ABCDEFGH23":                   "",
		"p:abcdefgh2":                    "",
		"p:abcdefgh231":                  "",
		"p:abcdefgh01":                   "",
		"amy@example.com":                "",
		"[p:abcdefgh23] amy@example.com": "",
		"a…@example.com [p:abcdefgh23]x": "",
	} {
		got, ok := Ref(in)
		if got != want || ok != (want != "") {
			t.Errorf("Ref(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	if Suffix("p:abcdefgh23") != " [p:abcdefgh23]" {
		t.Error("Suffix format")
	}
}

// A Key that Parse did not return holds no material, and a pseudonym or digest
// derived from nothing would look like any other: using one stops.
func TestAZeroKeyStopsInsteadOfDerivingFromNothing(t *testing.T) {
	for name, use := range map[string]func(){
		"pseudonym of a zero key": func() { (&Key{}).Pseudonym("a") },
		"digest of a zero key":    func() { (&Key{}).Digest([]byte("a")) },
		"pseudonym of a nil key":  func() { (*Key)(nil).Pseudonym("a") },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s did not stop", name)
				}
			}()
			use()
		}()
	}
}
