package sanitize

import (
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// formCases are the spellings of an address that masking reads or leaves, as MaskText
// shows them (VIGIL-EGRESS-002). Each case is also run keyed, where the text is the same
// but for the pseudonym after an email address, and masked text must mask to itself.
// doc is the example SECURITY.md quotes for the case, or "" when the page describes it in
// words: TestSecurityMDQuotesTheUnusualSpellingsItMasks reads the page against this table.
var formCases = []struct{ doc, in, want string }{
	// A bare hexadecimal number is a number, as a bare decimal one is: an error code in a
	// diagnostic stays readable. It is an address as the host of a URL.
	{"0xcb007107", "0xcb007107", "0xcb007107"},
	{"", "ping 0xCB007107. then", "ping 0xCB007107. then"},
	{"", "src=0x08080808,dst=0x0a000001", "src=0x08080808,dst=0x0a000001"},
	{"", "error 0x80070005 (0xC0000005) at 0x08048000", "error 0x80070005 (0xC0000005) at 0x08048000"},
	{"http://0xcb007107/", "http://0xcb007107/", "http://203.0.113.0/24/"},
	{"", "get http://0X08080808:8080/x then", "get http://8.8.8.0/24:8080/x then"},
	{"", "http://0xC0A80101/ http://0x7f000001/", "http://0xC0A80101/ http://0x7f000001/"},
	{"", "http://0x08080808.example.com/ http://0x08080808z/", "http://0x08080808.example.com/ http://0x08080808z/"},
	// A number of two or three parts with a hexadecimal part is an address wherever it stands.
	{"0xCB.0x00.0x71.0x07", "0xCB.0x00.0x71.0x07", "203.0.113.0/24"},
	{"", "203.0x0.113.0x7", "203.0.113.0/24"},
	{"0xCB.0x007107", "0xCB.0x007107", "203.0.113.0/24"},
	{"", "203.0x7107", "203.0.113.0/24"},
	{"", "203.0.0x7107", "203.0.113.0/24"},
	{"", "0x8.0x8.0x8.0x8 and 0X08.0X08.0X08.0X08", "8.8.8.0/24 and 8.8.8.0/24"},
	// ... that denotes no public address is left as written.
	{"", "0xC0A80101 0x7f000001 0x7f.1 0xA.0.0.1 0x64400001 0xE0000001 0xFFFFFFFF 0x1F 0x80", "0xC0A80101 0x7f000001 0x7f.1 0xA.0.0.1 0x64400001 0xE0000001 0xFFFFFFFF 0x1F 0x80"},
	// An error code stays as written.
	{"0x80070005", "0x80070005", "0x80070005"},
	// Not an address of four bytes, or glued to a word.
	{"ip0xcb007107", "ip0xcb007107", "ip0xcb007107"},
	{"host.0xcb007107", "host.0xcb007107", "host.0xcb007107"},
	{"", "0x1234567890 0xCB0071070 0xcb007107z _0xcb007107 0xcb007107_", "0x1234567890 0xCB0071070 0xcb007107z _0xcb007107 0xcb007107_"},

	// A leading zero after the first part: octal, or decimal (either reading may be public).
	{"203.000.113.007", "203.000.113.007", "203.0.113.0/24"},
	{"0313.0.0161.07", "0313.0.0161.07", "203.0.113.0/24"},
	{"010.010.010.010", "010.010.010.010", "8.8.8.0/24"},
	{"", "203.008.113.007 is not octal", "203.8.113.0/24 is not octal"},
	{"", "012.001.001.001", "12.1.1.0/24"},
	{"", "ping 203.000.113.007:443", "ping 203.0.113.0/24:443"},
	// A prefix length after the number is read as it is after a plain address: a narrower one
	// is cut to the network, a wider one loses its host bits, and nothing of the written
	// address is left (the route is not shown whole because its last part is a 0).
	{"", "route 8.8.8.0/32 seen", "route 8.8.8.0/24 seen"},
	{"0x8.0x8.0x8.0/32", "0x8.0x8.0x8.0/32", "8.8.8.0/24"},
	{"010.010.010.0/7", "010.010.010.0/7", "8.0.0.0/7"},
	{"", "route 0x8.0x8.0x8.0/32 seen", "route 8.8.8.0/24 seen"},
	{"", "route 010.010.010.0/7 seen", "route 8.0.0.0/7 seen"},
	{"", "route 203.000.113.0/32 seen", "route 203.0.113.0/24 seen"},
	{"", "route 0x8.0x8.0x8.8/32 seen", "route 8.8.8.0/24 seen"},
	{"", "route 0x8.0x8.0x8.8/24 seen", "route 8.8.8.0/24 seen"},
	{"", "route 0x8.0x8.0x8.8/16 seen", "route 8.8.0.0/16 seen"},
	{"", "route 0xCB.0x007107/24 and ８.８.８.８/32", "route 203.0.113.0/24 and 8.8.8.0/24"},
	{"", "route 010.010.010.0/24 seen", "route 8.8.8.0/24 seen"},
	// ... that denotes no public address is left as written.
	{"", "route 0xC0.0xA8.0x01.0x00/24 seen", "route 0xC0.0xA8.0x01.0x00/24 seen"},
	{"0300.0250.01.01", "0300.0250.01.01", "0300.0250.01.01"},
	{"", "192.168.001.001 10.001.001.001 100.100.000.001 127.000.000.001", "192.168.001.001 10.001.001.001 100.100.000.001 127.000.000.001"},
	// A zero in front of the first part is glue, read by the scan for the usual form.
	{"", "007.8.8.8 052.94.236.248:443", "007.8.8.0/24 052.94.236.0/24:443"},
	// Five parts, or a part that is no number, are not an address of four.
	{"", "8.8.008.8.1 203.000.113.007.1 203.000.113.0x", "8.8.008.8.1 203.000.113.007.1 203.000.113.0x"},

	// Full-width digits and full stops.
	{"８.８.８.８", "８.８.８.８", "8.8.8.0/24"},
	{"8。8。8。8", "8。8。8。8", "8.8.8.0/24"},
	{"", "8．8．8．8 and 8。8。8。8 and 8｡8｡8｡8", "8.8.8.0/24 and 8.8.8.0/24 and 8.8.8.0/24"},
	{"", "８.８.８.８:53", "8.8.8.0/24:53"},
	{"", "１０.０.０.１", "１０.０.０.１"},

	// The host of a URL: a number alone, or in two or three parts, is an address as a URL parser reads it.
	{"http://134744072/", "http://134744072/", "http://8.8.8.0/24/"},
	{"", "get http://3405803783:8080/x?y=1 now", "get http://203.0.113.0/24:8080/x?y=1 now"},
	{"", "//3405803783", "//203.0.113.0/24"},
	{"http://203.0.28935/", "http://203.0.28935/", "http://203.0.113.0/24/"},
	{"", "http://203.28935/", "http://203.0.113.0/24/"},
	{"", "http://0313.0.0161.07/", "http://203.0.113.0/24/"},
	{"", "http://031300070407/", "http://203.0.113.0/24/"},
	{"", "http://１３４７４４０７２/", "http://8.8.8.0/24/"},
	{"", "http://3232235777/ http://0300.0250.1/ http://127.1/", "http://3232235777/ http://0300.0250.1/ http://127.1/"},
	{"", "see (http://134744072) or <http://134744072>, ok", "see (http://8.8.8.0/24) or <http://8.8.8.0/24>, ok"},
	{"", "http://134744072.example.com/ http://134744072a/", "http://134744072.example.com/ http://134744072a/"},
	// The same numbers outside a URL host are numbers.
	{"3405803783", "3405803783", "3405803783"},
	{"", "epoch 1730000000, 134744072 bytes, id 3405803783.", "epoch 1730000000, 134744072 bytes, id 3405803783."},
	{"8.8.2056", "8.8.2056 8.526344 203.28935", "8.8.2056 8.526344 203.28935"},
	{"1.27.3", "1.27.3", "1.27.3"},
	{"31.10.2026", "31.10.2026", "31.10.2026"},
	{"", "10.1 192.168.257 3.14 v6.5", "10.1 192.168.257 3.14 v6.5"},
	{"", "path//134744072 and a//b", "path//8.8.8.0/24 and a//b"},

	// The usual forms are as they were.
	{"", "8.8.8.8 and 203.0.113.7:443 and 2001:db8::1", "8.8.8.0/24 and 203.0.113.0/24:443 and 2001:db8::/48"},

	// An at sign written as a character reference, full-width, or small.
	{"alice&#64;example.com", "alice&#64;example.com", "a…@example.com"},
	{"alice&#x40;example.com", "alice&#x40;example.com alice&#X40;example.com", "a…@example.com a…@example.com"},
	{"", "alice&#064;example.com alice&#x0040;example.com alice&#0000064;example.com", "a…@example.com a…@example.com a…@example.com"},
	{"alice&commat;example.com", "alice&commat;example.com", "a…@example.com"},
	{"alice＠example.com", "alice＠example.com and alice﹫example.com", "a…@example.com and a…@example.com"},
	{"", `"alice smith"&#64;example.com`, "a…@example.com"},
	{"", "mail: bob.o'brien&#64;example.com, and more", "mail: b…@example.com, and more"},
	{"", "mixed alice&#64;example.com and alice@example.com and alice%40example.com", "mixed a…@example.com and a…@example.com and a…@example.com"},
	// ... only between a local part and a domain.
	{"", "price &#64; 5 and &#64;example.com and x&#64; y and x &#64;y", "price &#64; 5 and &#64;example.com and x&#64; y and x &#64;y"},
	{"&#64", "&#64", "&#64"},
	{"&#64;", "&#64;", "&#64;"},
	{"&#x40;", "&#x40;", "&#x40;"},
	{"&commat;", "&commat;", "&commat;"},
	{"0/24", "0/24", "0/24"},
	{"", "&#65;lice&#6;4;example &#x;40; &#640; &#64 example", "&#65;lice&#6;4;example &#x;40; &#640; &#64 example"},
	{"", "ＡＢ＠ and ＠x", "ＡＢ＠ and ＠x"},
	// A synced group keeps its name, with the at sign as @.
	{"", "group:eng&#64;example.com", "group:eng@example.com"},
}

func TestUnusualSpellingsAreMasked(t *testing.T) {
	keyed, _ := keyedMasker(t)
	for _, c := range formCases {
		if got := MaskText(c.in); got != c.want {
			t.Errorf("MaskText(%q) = %q, want %q", c.in, got, c.want)
		}
		if again := MaskText(c.want); again != c.want {
			t.Errorf("MaskText(%q) = %q: masked text does not mask to itself", c.want, again)
		}
		if got := keyed.Text(c.in); pseudonymRE.ReplaceAllString(got, "") != c.want {
			t.Errorf("keyed Text(%q) = %q: without its pseudonyms it is not %q", c.in, got, c.want)
		}
	}
}

var pseudonymRE = regexp.MustCompile(` \[p:[a-z2-7]{10}\]`)

// An address in one of these spellings is the same address, for the pseudonym too.
func TestAnAddressInAnotherSpellingHasTheSamePseudonym(t *testing.T) {
	keyed, _ := keyedMasker(t)
	want := keyed.Text("alice@example.com")
	if !pseudonymRE.MatchString(want) {
		t.Fatalf("Text(alice@example.com) = %q names nothing", want)
	}
	for _, in := range []string{"alice&#64;example.com", "alice&#x40;example.com", "alice&commat;example.com", "alice＠example.com", "alice﹫example.com"} {
		if got := keyed.Text(in); got != want {
			t.Errorf("Text(%q) = %q, want %q", in, got, want)
		}
	}
}

// Nothing the normaliser leaves alone changes: text with no such spelling in it is returned
// as it came, the same string.
func TestNormalizeFormsLeavesOrdinaryTextAlone(t *testing.T) {
	for _, s := range []string{"", "plain", "amy@example.com", "8.8.8.8", "2001:db8::1", "version 1.2.3 of 12 items", "a & b &amp; c &#38; d", "0x", "0xg", "0.5 0.0.0.0", "x.0x8.0x8.0x8.0x8", "日本語のテキスト"} {
		if got := normalizeForms(s); got != s {
			t.Errorf("normalizeForms(%q) = %q", s, got)
		}
	}
}

// Every byte at which headOf cuts also ends a URL host, so a number at the end of the part
// that masking reads is read as it is in the whole text.
func TestEveryCutByteEndsAURLHost(t *testing.T) {
	for _, c := range []byte(cutBytes + "\n\r") {
		if !strings.ContainsRune(hostEnds, rune(c)) {
			t.Errorf("headOf cuts before %q, but a URL host does not end there", c)
		}
	}
}

// What SECURITY.md quotes of the unusual spellings is what the code does, both ways: each
// example the page quotes in its bullet on them is run above, and each example above that
// the page says it quotes is quoted there.
func TestSecurityMDQuotesTheUnusualSpellingsItMasks(t *testing.T) {
	pageBytes, err := os.ReadFile("../../SECURITY.md")
	if err != nil {
		t.Fatal(err)
	}
	page := string(pageBytes)
	pinned := map[string]bool{}
	for _, c := range formCases {
		if c.doc != "" && !strings.Contains(page, "`"+c.doc+"`") {
			t.Errorf("SECURITY.md does not quote `%s`", c.doc)
		}
		pinned[c.doc], pinned[c.in], pinned[c.want] = true, true, true
	}
	quoted, bullets := regexp.MustCompile("`([^`]+)`"), 0
	for _, line := range strings.Split(page, "\n") {
		if !strings.HasPrefix(line, "- Masking also reads unusual spellings") {
			continue
		}
		bullets++
		for _, m := range quoted.FindAllStringSubmatch(line, -1) {
			if e := m[1]; strings.ContainsAny(e, "0123456789&＠﹫") && !pinned[e] {
				t.Errorf("SECURITY.md quotes `%s`, and no test here runs it", e)
			}
		}
	}
	if bullets != 1 {
		t.Errorf("SECURITY.md has %d bullets that open \"- Masking also reads unusual spellings\", want 1", bullets)
	}
}

// spelled is the four bytes of an address written part by part with the given spelling of a
// byte.
func spelled(b [4]byte, part func(v byte) string) string {
	var parts [4]string
	for k, v := range b {
		parts[k] = part(v)
	}
	return strings.Join(parts[:], ".")
}

// fullWidth writes the ASCII digits of s as full-width digits.
func fullWidth(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			c += '\uFF10' - '0'
		}
		b.WriteRune(c)
	}
	return b.String()
}

// Over random public addresses, each in every spelling the masker reads, the text shows the
// network and not the address, and an address that is no one's is left as written. The
// oracle is net/netip and the arithmetic of inet_aton, not the code under test.
func TestEveryPublicAddressIsMaskedInEverySpellingItIsRead(t *testing.T) {
	rnd := rand.New(rand.NewSource(3))
	checked := 0
	for i := 0; i < 1500; i++ {
		var b [4]byte
		for k := range b {
			b[k] = byte(rnd.Intn(256))
		}
		a := netip.AddrFrom4(b)
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		isPublic := public(a) && b[0] != 0
		net := fmt.Sprintf("%d.%d.%d.0/24", b[0], b[1], b[2])
		upper := rnd.Intn(2) == 0
		hex := func(v uint64, width int) string {
			s := fmt.Sprintf("%0*x", width, v)
			if upper {
				s = strings.ToUpper(s)
			}
			return s
		}
		// Spellings of four parts.
		fourParts := map[string]func(byte) string{
			"hex":        func(v byte) string { return "0x" + hex(uint64(v), 1+rnd.Intn(2)) },
			"hex padded": func(v byte) string { return "0X" + hex(uint64(v), 2+rnd.Intn(4)) },
			"octal":      func(v byte) string { return "0" + strconv.FormatUint(uint64(v), 8) },
			"octal wide": func(v byte) string { return "00" + strconv.FormatUint(uint64(v), 8) },
			"mixed": func(v byte) string {
				if rnd.Intn(2) == 0 {
					return "0x" + hex(uint64(v), 1)
				}
				return strconv.Itoa(int(v))
			},
			"full-width": func(v byte) string { return fullWidth(strconv.Itoa(int(v))) },
		}
		for name, part := range fourParts {
			whole := spelled(b, part)
			if name == "mixed" && !strings.Contains(whole, "0x") {
				continue // plain decimal parts only: the usual form, read by the dotted scan
			}
			if !isPublic {
				if name == "octal" || name == "octal wide" {
					continue // the decimal reading of a zero-padded part may be public
				}
				// The usual scan may still read part of such text (the glue before an address);
				// what is asserted is that the rewriting leaves it alone.
				if got := normalizeForms(whole); got != whole {
					t.Fatalf("%s: normalizeForms(%q) = %q, want it as written (%s is no one's)", name, whole, got, a)
				}
				continue
			}
			checked++
			// The network of the plain address, with the port after it as for a plain address, and
			// with a prefix length: a narrower one is cut to the network.
			if got := MaskText("host " + whole + ":443"); got != "host "+net+":443" {
				t.Fatalf("%s: MaskText(%q) = %q, want %q", name, "host "+whole+":443", got, "host "+net+":443")
			}
			if got := MaskText("route " + whole + "/32 seen"); got != "route "+net+" seen" {
				t.Fatalf("%s: MaskText(%q) = %q, want %q", name, "route "+whole+"/32 seen", got, "route "+net+" seen")
			}
		}
		// Hexadecimal numbers of one to three parts, and the host of a URL in any spelling.
		hexInts := []string{
			"0x" + hex(uint64(b[0]), 1) + ".0x" + hex(uint64(v&0xFFFFFF), 1),
			fmt.Sprintf("%d.0x%s", b[0], hex(uint64(v&0xFFFFFF), 6)),
			fmt.Sprintf("%d.%d.0x%s", b[0], b[1], hex(uint64(v&0xFFFF), 4)),
		}
		hosts := []string{
			"0x" + hex(uint64(v), 8), "0x" + hex(uint64(v), 1),
			strconv.FormatUint(uint64(v), 10), fullWidth(strconv.FormatUint(uint64(v), 10)),
			"0" + strconv.FormatUint(uint64(v), 8),
			fmt.Sprintf("%d.%d", b[0], v&0xFFFFFF), fmt.Sprintf("%d.%d.%d", b[0], b[1], v&0xFFFF),
		}
		for _, s := range hexInts {
			if strings.Count(s, ".") < 3 && b[0] == 0 {
				continue
			}
			want := net
			if !isPublic {
				want = s
			}
			if got := MaskText("x=" + s + " y"); got != "x="+want+" y" {
				t.Fatalf("MaskText(%q) = %q, want %q (%s)", "x="+s+" y", got, "x="+want+" y", a)
			}
			checked++
		}
		for _, s := range hosts {
			want := net
			if !isPublic {
				if strings.HasPrefix(s, "0") && !strings.HasPrefix(s, "0x") {
					continue // a leading zero: the decimal reading of the digits may be public
				}
				want = s
			}
			in := "see http://" + s + "/path and"
			if got := MaskText(in); got != "see http://"+want+"/path and" {
				t.Fatalf("MaskText(%q) = %q, want %q (%s)", in, got, "see http://"+want+"/path and", a)
			}
			// Outside a URL host a bare number, hexadecimal or decimal, or a short one of decimal
			// parts, is a number: shown as written.
			if got := MaskText("n=" + s + " y"); got != "n="+s+" y" {
				t.Fatalf("MaskText(%q) = %q, want it as written", "n="+s+" y", got)
			}
			checked++
		}
	}
	if checked < 7000 {
		t.Fatalf("only %d spellings were checked", checked)
	}
}

// Rewriting is idempotent: over text built from the pieces of an attack, normalising the
// result again changes nothing.
func TestNormalizeFormsIsIdempotentOverGeneratedText(t *testing.T) {
	rnd := rand.New(rand.NewSource(17))
	extra := []string{"&#64;", "&#x40;", "&commat;", "＠", "﹫", "0x08080808", "010.010.010.010", "203.000.113.007", "３.４.５.６", "http://134744072/", "//3405803783", "8。8。8。8", "0/24", "0x", "0xg"}
	pieces := append(append([]string{}, windowPieces...), extra...)
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		target := 10 + rnd.Intn(80)
		for b.Len() < target {
			b.WriteString(pieces[rnd.Intn(len(pieces))])
		}
		s := b.String()
		once := normalizeForms(s)
		if twice := normalizeForms(once); twice != once {
			t.Fatalf("normalizeForms(%q) = %q, and again %q", s, once, twice)
		}
	}
}
