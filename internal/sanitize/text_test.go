package sanitize

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestTextKeepsLinesAndEscapesTheRest(t *testing.T) {
	for in, want := range map[string]string{
		"{\n\t\"acls\": [],\n}\n":        "{\n\t\"acls\": [],\n}\n",
		"a\r\nb\r\n":                     "a\nb\n",
		"a\rb":                           `a\u{000D}b`,
		"x\x1b[2Jy":                      `x\u{001B}[2Jy`,
		"// \u202egnirts\u202c":          `// \u{202E}gnirts\u{202C}`,
		"next\u0085line \u2028 sep":      `next\u{0085}line \u{2028} sep`,
		"bell\a and \v vertical \f page": `bell\u{0007} and \u{000B} vertical \u{000C} page`,
	} {
		if got := Text(in, 0); got != want {
			t.Errorf("Text(%q) = %q, want %q", in, got, want)
		}
	}
}

// Whatever goes in, Text's output holds no invisible character but LF and TAB.
func TestTextOutputHasNoInvisibleCharactersButLFAndTab(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	interesting := []rune{'\n', '\t', '\r', 0x1b, 0x7f, 0x85, 0x9b, 0x200b, 0x202e, 0x2066, 0x2028, 0xfeff, 0xe0041, 0xfe0f, 'a', '{', '"', ' ', 0x00}
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for j := rnd.Intn(40); j > 0; j-- {
			if rnd.Intn(4) == 0 {
				b.WriteByte(byte(rnd.Intn(256))) // invalid UTF-8 too
			} else {
				b.WriteRune(interesting[rnd.Intn(len(interesting))])
			}
		}
		checkText(t, b.String())
	}
}

func FuzzText(f *testing.F) {
	for _, seed := range []string{"a\r\nb", "\x1b[0m", "\u202e", "\n\t\r", "\xff\xfe", "\u0085"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) { checkText(t, s) })
}

func checkText(t *testing.T, in string) {
	t.Helper()
	out := Text(in, 0)
	if !utf8.ValidString(out) {
		t.Fatalf("Text(%q) = %q: invalid UTF-8", in, out)
	}
	for _, r := range out {
		if unsafeRune(r) && r != '\n' && r != '\t' {
			t.Fatalf("Text(%q) = %q keeps %U", in, out, r)
		}
	}
}

type document struct {
	Policy string `json:"policy" tk:"untrusted,multiline"`
	Note   string `json:"note" tk:"untrusted"`
}

func TestFieldsKeepsLinesOnlyInMultilineFields(t *testing.T) {
	v := document{Policy: "{\n\t\"acls\": [],\n}\n" + strings.Repeat("x", 2*DefaultMax), Note: "two\nlines"}
	Fields(&v, DefaultMax)
	if !strings.HasPrefix(v.Policy, "{\n\t\"acls\": [],\n}\n") || len(v.Policy) < 2*DefaultMax {
		t.Errorf("policy = %.40q (%d bytes): lines lost or capped at DefaultMax", v.Policy, len(v.Policy))
	}
	if v.Note != `two\u{000A}lines` {
		t.Errorf("note = %q", v.Note)
	}
	if got := UntrustedPaths(reflect.TypeFor[document]()); strings.Join(got, ",") != "note,policy" {
		t.Errorf("UntrustedPaths = %v", got)
	}
}

func TestMultilineIsOnlyForUntrustedStrings(t *testing.T) {
	type trusted struct {
		P string `json:"p" tk:"multiline"`
	}
	type list struct {
		P []string `json:"p" tk:"untrusted,multiline"`
	}
	for _, typ := range []reflect.Type{reflect.TypeFor[trusted](), reflect.TypeFor[list]()} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("UntrustedPaths(%s) did not panic", typ)
				}
			}()
			UntrustedPaths(typ)
		}()
	}
}

// An oracle independent of unsafeRune: Unicode's own classes of characters that
// do not print visibly. Every one of them must come out escaped.
func TestEscapingCoversUnicodesInvisibleClasses(t *testing.T) {
	invisible := []*unicode.RangeTable{unicode.Cc, unicode.Cf, unicode.Co, unicode.Zl, unicode.Zp,
		unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue // surrogates cannot be encoded
		}
		hidden := unicode.IsOneOf(invisible, r) || unicode.Is(unicode.Zs, r) && r != ' '
		if !hidden || r == '\n' || r == '\t' {
			continue
		}
		if out := Text(string(r), 0); !strings.HasPrefix(out, `\u{`) {
			t.Errorf("Text(%U) = %q, want it escaped", r, out)
		}
	}
}
