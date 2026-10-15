package tripwire

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// Credential-shaped test values are assembled at run time so that no literal in
// the repository matches a secret scanner's rules.
func shapes() map[string]string {
	seg := strings.Repeat("A", 12)
	return map[string]string{
		"auth key":   "tskey" + "-auth-" + seg,
		"client":     "tskey" + "-client-" + seg,
		"api token":  "tskey" + "-api-" + seg,
		"scim":       "tskey" + "-scim-" + seg,
		"app":        "tskey" + "-app-" + seg,
		"jwt":        "ey" + "J" + seg + "." + "ey" + "J" + seg + "." + seg,
		"in a field": `{"name":"x tskey` + `-webhook-` + seg + `"}`,
	}
}

func TestCheckCatchesCredentialShapes(t *testing.T) {
	for name, v := range shapes() {
		err := Check([]byte(v))
		e, ok := tkerr.As(err)
		if !ok || e.Code != tkerr.OutputWithheld {
			t.Errorf("%s: err = %v, want output_withheld", name, err)
			continue
		}
		if strings.Contains(e.Message, "AAAA") {
			t.Errorf("%s: error message repeats the matched text: %q", name, e.Message)
		}
	}
}

func TestCheckPassesOrdinaryOutput(t *testing.T) {
	// Matching is case-sensitive (spec Appendix C): Tailscale keys are lower case,
	// so a case-mangled prefix is ordinary text, not key material.
	mangled := "TSKEY" + "-AUTH-" + strings.Repeat("A", 12)
	for _, v := range []string{`{"name":"tskey"}`, `{"keyType":"auth"}`, "eyJhbGciOi", `{"a":"b.c.d"}`, mangled} {
		if err := Check([]byte(v)); err != nil {
			t.Errorf("%q: %v", v, err)
		}
	}
}

func TestRedactRemovesWholeShapes(t *testing.T) {
	for name, v := range shapes() {
		got := Redact("before " + v + " after")
		if strings.Contains(got, "AAAA") || !strings.Contains(got, Redacted) || Check([]byte(got)) != nil {
			t.Errorf("%s: Redact = %q", name, got)
		}
	}
	if got := Redact("web-1"); got != "web-1" {
		t.Errorf("ordinary text changed: %q", got)
	}
}

// SECURITY.md lists, under Known limits, the shapes the tripwire recognises and says every
// other credential format is not caught. This pins that list to the patterns: each prefix it
// names is caught, a prefix it does not name is not, the three lengths of a JWT are the
// boundary it states, and the formats it says are not caught pass.
func TestSecurityMDListsExactlyTheShapesTheTripwireRecognises(t *testing.T) {
	page, err := os.ReadFile("../../SECURITY.md")
	if err != nil {
		t.Fatal(err)
	}
	var line string
	for _, l := range strings.Split(string(page), "\n") {
		if strings.Contains(l, "The secret tripwire is a backstop that recognises two shapes only") {
			line = l
		}
	}
	if line == "" {
		t.Fatal("SECURITY.md has no Known limits entry for the tripwire")
	}
	seg := strings.Repeat("A", 12)
	// The kinds of key the page names are the kinds the pattern has, no more and no fewer.
	named := map[string]bool{}
	for _, m := range regexp.MustCompile("`tskey-([a-z]+)-`").FindAllStringSubmatch(line, -1) {
		named[m[1]] = true
	}
	coded := map[string]bool{}
	for _, m := range regexp.MustCompile(`tskey-\(([^)]*)\)-`).FindAllStringSubmatch(patterns[0].re.String(), -1) {
		for _, kind := range strings.Split(m[1], "|") {
			coded[kind] = true
		}
	}
	if len(coded) != 6 || !reflect.DeepEqual(named, coded) {
		t.Errorf("SECURITY.md names the key kinds %v, and the pattern has %v", named, coded)
	}
	for kind := range coded {
		if prefix := "tskey" + "-" + kind + "-"; Check([]byte(prefix+seg)) == nil {
			t.Errorf("%s%s is not caught", prefix, seg)
		}
	}
	// A kind that is not named is not recognised, nor is a capital.
	for _, v := range []string{"tskey" + "-other-" + seg, "tskey" + "-" + seg, "TSKEY" + "-auth-" + seg} {
		if Check([]byte(v)) != nil {
			t.Errorf("%q is caught, and SECURITY.md does not name it", v)
		}
	}
	jwt := func(a, b, c int) string {
		return "ey" + "J" + strings.Repeat("a", a) + ".ey" + "J" + strings.Repeat("b", b) + "." + strings.Repeat("c", c)
	}
	for _, c := range []struct {
		jwt  string
		want bool
	}{
		{jwt(10, 10, 10), true}, {jwt(9, 10, 10), false}, {jwt(10, 9, 10), false}, {jwt(10, 10, 9), false},
		{jwt(10, 10, 0), false}, {"ey" + "J" + strings.Repeat("a", 10) + "." + strings.Repeat("b", 14) + "." + strings.Repeat("c", 10), false},
		{"ey" + "J" + strings.Repeat("a-_", 5) + ".ey" + "J" + strings.Repeat("0Z", 5) + "." + strings.Repeat("-", 10), true},
	} {
		if got := Check([]byte(c.jwt)) != nil; got != c.want {
			t.Errorf("Check(%q) caught = %v, want %v", c.jwt, got, c.want)
		}
	}
	// What SECURITY.md says is not caught.
	for name, v := range map[string]string{
		"a password":           `{"password":"hunter2hunter2hunter2"}`,
		"another vendor's key": "sk" + "_live_" + strings.Repeat("A", 24),
		"a signing secret":     "whsec" + "_" + strings.Repeat("a1", 16),
		"an unsigned token":    jwt(12, 12, 0),
		"a bare client secret": strings.Repeat("kJ3", 14),
	} {
		if err := Check([]byte(v)); err != nil {
			t.Errorf("%s is caught: %v", name, err)
		}
	}
}
