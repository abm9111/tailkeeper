package sanitize

import (
	"math/rand"
	"slices"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tripwire"
)

// reference is what a result showed for an untrusted string before the window: the whole
// string masked, credential shapes replaced, escaped and capped. It is the oracle of the
// tests below; it shares no code with headOf.
func reference(m Masker, s string, limit int) string {
	return String(tripwire.Redact(m.Text(s)), limit)
}

// pieces are the bytes a window's cut has to get right: the shapes of an address in
// every spelling the masker reads, the glue around them, quotes, line ends and the
// bytes at which headOf cuts.
var windowPieces = []string{
	"a", "amy", "bob", "x", "@", "@", "\\u0040", "%40", "&#64;", "&#x40;", "＠", "﹫", ".", ".", "-", "_", ":", "::", "/", "=", "?", "\"", "\\\"",
	"example.com", "8.8.8.8", "203.0.113.7", "2001:db8:abcd:1234:5678:9abc:def0:1111", "0x08080808", "010.010.010.010", "3232235777", "//",
	"1", "2", "9", "0", "12", "255", "tskey-api-", "tskey-auth-abc", "eyJabcdefghijk.eyJabcdefghijk.abcdefghijk",
	" ", " ", " ", "\t", ",", "(", ")", "<", ">", "[", "]", "\n", "\r", "group:", "…", "é", "\x00", "\x01", "[p:", "p:", "%2", "\\x", "\\u",
	"\\u{0001}", "%00", "user=", "\\u0061", "A", "f", "dead", "::ffff:", "/24", "0/24", "/32", "/7", "\u200b", "'", "`", ";", "!", "~", "9e8f", "100.64.0.1", "192.168.1.1",
}

func randomText(rnd *rand.Rand, n int) string {
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(windowPieces[rnd.Intn(len(windowPieces))])
	}
	return b.String()
}

// The head headOf returns is masked and redacted to the start of what the whole string
// is masked and redacted to, and the whole string goes on with the byte the head stands
// before. That is what lets the window read less than the string without a token being
// cut through: an address, an email or a credential shape never reaches across the cut.
func TestHeadOfIsMaskedAsThePrefixOfTheWhole(t *testing.T) {
	keyed, _ := keyedMasker(t)
	plain := Masker{}
	rnd := rand.New(rand.NewSource(11))
	cuts := 0
	for i := 0; i < 15000; i++ {
		s := randomText(rnd, 20+rnd.Intn(120))
		window := 8 + rnd.Intn(60)
		head, cut := headOf(s, window)
		if len(s) <= window {
			if head != s || cut {
				t.Fatalf("headOf(%q, %d) = %q, %v: a string within the window is returned whole", s, window, head, cut)
			}
			continue
		}
		cuts++
		if !cut || len(head) > window || !strings.HasPrefix(s, head) {
			t.Fatalf("headOf(%q, %d) = %q, %v", s, window, head, cut)
		}
		for name, m := range map[string]Masker{"plain": plain, "keyed": keyed} {
			whole, part := m.Text(s), m.Text(head)
			if !strings.HasPrefix(whole, part) {
				t.Fatalf("%s: Text(%q) = %q does not start with Text(%q) = %q (window %d)", name, s, whole, head, part, window)
			}
			// An empty head is no cut at a byte: nothing in the window was a place to cut.
			if rest := whole[len(part):]; len(head) > 0 && (rest == "" || rest[0] != s[len(head)]) {
				t.Fatalf("%s: Text(%q) = %q continues with %q after the head %q, want the cut byte %q", name, s, whole, rest, head, s[len(head)])
			}
			// The email pass alone (the fields tagged emails) reads the same head.
			wholeE, partE := m.Emails(s), m.Emails(head)
			if !strings.HasPrefix(wholeE, partE) {
				t.Fatalf("%s: Emails(%q) = %q does not start with Emails(%q) = %q (window %d)", name, s, wholeE, head, partE, window)
			}
			wholeR, partR := tripwire.Redact(whole), tripwire.Redact(part)
			if !strings.HasPrefix(wholeR, partR) {
				t.Fatalf("%s: Redact(Text(%q)) = %q does not start with %q (window %d)", name, s, wholeR, partR, window)
			}
		}
	}
	if cuts < 5000 {
		t.Fatalf("only %d of the generated strings were cut: the property was barely exercised", cuts)
	}
}

// The property above must be able to fail. A cut taken at every byte, quotes and all,
// breaks it: the text below is one quoted local part with a space inside it.
func TestACutInsideAQuotedLocalPartBreaksThePrefixProperty(t *testing.T) {
	s := `"amy smith"@example.com`
	head := s[:strings.IndexByte(s, ' ')]
	whole, part := MaskText(s), MaskText(head)
	if strings.HasPrefix(whole, part) {
		t.Fatalf("Text(%q) = %q starts with Text(%q) = %q: the property cannot fail", s, whole, head, part)
	}
	// headOf does not cut there: the quote withholds the line's cut bytes.
	if got, _ := headOf(s+" tail", 14); strings.Contains(got, "amy") {
		t.Errorf("headOf cut inside a quoted local part: %q", got)
	}
}

// A token that the window's end runs through is dropped whole, not shown half-masked.
func TestAnAddressThatTheWindowRunsThroughIsDroppedWhole(t *testing.T) {
	m, _ := keyedMasker(t)
	for name, c := range map[string]struct {
		s      string
		window int
		want   string
	}{
		"IPv6":                  {"ping 2001:db8:abcd:1234:5678:9abc:def0:1111 now", 28, "ping"},
		"IPv4":                  {"ping 203.0.113.77 now", 12, "ping"},
		"email":                 {"mail amy.longlocalpart@example.com now", 28, "mail"},
		"email, entity at sign": {"mail amy.longlocalpart&#64;example.com now", 28, "mail"},
		"email, quoted":         {`mail "amy longlocalpart"@example.com now`, 20, "mail"},
		"credential":            {"key tskey-api-kABCDEFGHIJKLMNOP now", 20, "key"},
		"one long token":        {strings.Repeat("a", 100) + "@example.com", 28, ""},
		"after a line end":      {"first line\nping 2001:db8:abcd:1234:5678:9abc:def0:1111 now", 28, "first line\nping"},
		"a forged marker":       {"amy[p:x@example.com and more", 12, ""},
	} {
		head, cut := headOf(c.s, c.window)
		if !cut || head != c.want {
			t.Errorf("%s: headOf(%q, %d) = %q, %v, want %q", name, c.s, c.window, head, cut, c.want)
		}
		shown := display2(m, c.s, c.window, DefaultMax)
		for _, leak := range []string{"2001:db8:abcd:1234", "203.0.113.77", "longlocalpart", "tskey-api-k", "aaaa", "amy"} {
			if strings.Contains(shown, leak) {
				t.Errorf("%s: the display %q shows %q", name, shown, leak)
			}
		}
	}
}

// display2 is display with a window of its own, for tests that cannot afford 64 KiB strings.
func display2(m Masker, s string, window, limit int) string {
	head, cut := headOf(s, window)
	masked := m.Text(head)
	if cut {
		masked += truncatedSuffix
	}
	return String(tripwire.Redact(masked), limit)
}

// A string of up to the window reads exactly as before, and a longer one reads as before
// whenever the head masks to the cap's worth of text or more.
func TestDisplayIsUnchangedWhereTheHeadFillsTheCap(t *testing.T) {
	keyed, _ := keyedMasker(t)
	rnd := rand.New(rand.NewSource(5))
	for i := 0; i < 3000; i++ {
		m := Masker{}
		if i%2 == 1 {
			m = keyed
		}
		s := randomText(rnd, 1+rnd.Intn(5000))
		if got, want := shown(m, s, DefaultMax), reference(m, s, DefaultMax); got != want {
			t.Fatalf("display(%.60q) = %q, want %q", s, got, want)
		}
	}
	// Over the window: ordinary text of 200 KiB.
	for _, m := range []Masker{{}, keyed} {
		var b strings.Builder
		for b.Len() < 200<<10 {
			b.WriteString("host-" + "7 owner amy@example.com seen from 203.0.113.9 and 2001:db8:abcd::1, ")
		}
		s := b.String()
		if got, want := shown(m, s, DefaultMax), reference(m, s, DefaultMax); got != want {
			t.Errorf("a 200 KiB string: display = %q, want %q", got, want)
		}
	}
	// Under the cap, byte for byte, whatever the content.
	for _, s := range []string{"", "plain", "amy@example.com", "8.8.8.8", "a\x00b\u202e", strings.Repeat("x", DefaultMax-1), strings.Repeat("é", 400)} {
		if got, want := shown(keyed, s, DefaultMax), reference(keyed, s, DefaultMax); got != want {
			t.Errorf("display(%.30q) = %q, want %q", s, got, want)
		}
	}
}

// A field tagged multiline is capped at MaxText, not at the window: a policy page of
// 200 KiB keeps all of it, masked, as it did.
func TestMaskCappedDoesNotWindowMultilineFields(t *testing.T) {
	keyed, _ := keyedMasker(t)
	line := "// owner amy@example.com from 203.0.113.9\n"
	page := strings.Repeat(line, (200<<10)/len(line))
	r := struct {
		Policy string `json:"policy" tk:"untrusted,multiline"`
		Note   string `json:"note" tk:"untrusted"`
	}{Policy: page, Note: page}
	keyed.MaskCapped(&r, DefaultMax)
	Fields(&r, DefaultMax)
	if len(r.Policy) < maskWindow || strings.HasSuffix(r.Policy, truncatedSuffix) || strings.Contains(r.Policy, "amy@example.com") ||
		strings.Count(r.Policy, "a…@example.com") != strings.Count(page, "amy@example.com") {
		t.Errorf("the multiline field was windowed or left unmasked: %d bytes of %d, ends %q", len(r.Policy), len(page), r.Policy[len(r.Policy)-40:])
	}
	if len(r.Note) > DefaultMax || !strings.HasSuffix(r.Note, truncatedSuffix) {
		t.Errorf("the plain untrusted field is %d bytes, ends %q", len(r.Note), r.Note[len(r.Note)-20:])
	}
}

// Where the owner shows personal data nothing is masked, but credential shapes are still
// replaced, and the same bound holds: a credential the window ends in is dropped whole.
func TestFieldsWindowsAnUntrustedStringWhenNothingIsMasked(t *testing.T) {
	s := "key " + strings.Repeat("filler ", 12000) + "tskey-api-k" + strings.Repeat("A", 8000) + " tail"
	r := struct {
		Name string `tk:"untrusted"`
	}{s}
	Fields(&r, 1<<20)
	if strings.Contains(r.Name, "tskey-api-k") || !strings.HasSuffix(r.Name, truncatedSuffix) || len(r.Name) > maskWindow+len(truncatedSuffix) {
		t.Errorf("Fields shows %d bytes ending %q", len(r.Name), r.Name[len(r.Name)-40:])
	}
	// A credential inside the window is replaced as before.
	short := "key tskey-api-kABCDEFGH now"
	r.Name = short
	Fields(&r, DefaultMax)
	if r.Name != "key [credential-shaped text removed] now" {
		t.Errorf("Fields = %q", r.Name)
	}
}

// The pseudonyms a filter may match are those the display shows, over the window too.
func TestTextRefsAgreeWithTheDisplayOfAStringLongerThanTheWindow(t *testing.T) {
	m, _ := keyedMasker(t)
	for name, s := range map[string]string{
		"two addresses, one past the cap": "ask amy@example.com " + strings.Repeat("filler ", 20000) + "bob@example.com",
		"one address on the cap":          strings.Repeat("y ", DefaultMax/2-10) + "amy@example.com " + strings.Repeat("filler ", 20000),
		"no cut byte":                     strings.Repeat("a", maskWindow+10) + "@example.com",
		"quoted line":                     `"` + strings.Repeat("amy smith ", 20000) + `"@example.com`,
	} {
		for _, limit := range []int{DefaultMax, 64} {
			got, want := m.TextRefs(s, limit), distinct(shownIn(shown(m, s, limit)))
			if !slices.Equal(got, want) {
				t.Errorf("%s, limit %d: TextRefs = %v, but the display shows %v", name, limit, got, want)
			}
		}
	}
}
