package sanitize

import (
	"fmt"
	"math/rand"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unicode/utf8"
)

// This file holds the reading of unusual spellings of an address (forms.go) as it was before
// addressForm, formNumber.address and readFormPart were split into smaller functions (the
// copies below are verbatim from commit 67b9d3c, with the name suffix Before, and each calls
// only the copies, apart from the helpers that were not changed), and the tests that require
// the split code to give byte-identical results. It is an oracle, not code that runs; see
// maskat_oracle_test.go for the other one.

// formPieces are the parts of the generated strings: the digits and signs of the spellings
// forms.go reads, and the text around them that decides whether it does.
var formPieces = []string{
	"0", "0", "1", "7", "8", "9", "08", "010", "007", "000", "113", "203", "255", "256", "99", "12345678901", "1234567890123", "4294967295", "4294967296",
	"0x", "0X", "0x0", "0xcb", "0xCB", "0x007107", "0x7107", "0xcb007107", "0x08080808", "0x100000000", "0xg", "cb", "7107", "ff", "FF",
	"８", "０", "１", "９", "．", "。", "｡", ".", ".", ".", ".", ".", "/", "//", "/24", "/32", "/7", ":", ":80", "?", "#", "\\", "\"", "'", ",", ";", "(", ")", "[", "]", "<", ">",
	" ", " ", "\t", "\n", "_", "a", "x", "z", "-", "é", "http://", "//", "ip", "host.", "&#64;", "&commat;", "@", "＠", "﹫", "amy", "example.com",
	"8.8.8.8", "203.0.113.7", "10.0.0.1", "100.64.0.1", "127.0.0.1", "0.0.0.0", "0.1.2.3", "224.0.0.1",
}

func randomFormText(rnd *rand.Rand) string {
	var b strings.Builder
	for n := 1 + rnd.Intn(14); n > 0; n-- {
		b.WriteString(formPieces[rnd.Intn(len(formPieces))])
	}
	return b.String()
}

// formDifference returns what differs between the original and the split reading of s, or "".
func formDifference(s string) string {
	if o, n := normalizeFormsBefore(s), normalizeForms(s); o != n {
		return fmt.Sprintf("normalizeForms(%q): before %q, after %q", s, o, n)
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) && s[i] < utf8.RuneSelf {
			continue
		}
		of, oe, or, ook := addressFormBefore(s, i)
		nf, ne, nr, nok := addressForm(s, i)
		if of != nf || oe != ne || or != nr || ook != nok {
			return fmt.Sprintf("addressForm(%q, %d): before %d, %d, %q, %v; after %d, %d, %q, %v", s, i, of, oe, or, ook, nf, ne, nr, nok)
		}
		if i < len(s) && isDigit(s[i]) {
			if d := numberDifference(s, i); d != "" {
				return d
			}
		}
	}
	return ""
}

// numberDifference compares the readings of the number at s[i] part by part: the parts,
// and the address it denotes in each reading of a leading zero.
func numberDifference(s string, i int) string {
	of, nf := readFormNumberBefore(s, i), readFormNumber(s, i)
	if of != nf {
		return fmt.Sprintf("readFormNumber(%q, %d): before %+v, after %+v", s, i, of, nf)
	}
	if of.bad {
		return ""
	}
	for _, octal := range [2]bool{true, false} {
		oa, ook := formAddressBefore(of, octal)
		na, nok := nf.address(octal)
		if oa != na || ook != nok {
			return fmt.Sprintf("address(%q, %d, octal %v): before %v, %v; after %v, %v", s, i, octal, oa, ook, na, nok)
		}
	}
	oa, ook := formPublicAddressBefore(of)
	na, nok := nf.publicAddress()
	if oa != na || ook != nok {
		return fmt.Sprintf("publicAddress(%q, %d): before %v, %v; after %v, %v", s, i, oa, ook, na, nok)
	}
	return ""
}

func TestFormsMatchTheOriginalOnTheFuzzCorpora(t *testing.T) {
	files, literals := corpusStrings(t)
	n := 0
	for _, group := range [][]string{files, literals} {
		for _, c := range group {
			if len(c) > 4096 {
				continue
			}
			for _, f := range framed {
				n++
				if d := formDifference(f[0] + c + f[1]); d != "" {
					t.Fatal(d)
				}
			}
		}
	}
	t.Logf("%d strings from %d corpus files and %d test literals, each in %d frames", n, len(files), len(literals), len(framed))
}

func TestFormsMatchTheOriginalOnGeneratedText(t *testing.T) {
	total := *maskAtCount
	workers := min(runtime.GOMAXPROCS(0), 16)
	var wg sync.WaitGroup
	var failed atomic.Bool
	var changed, compared atomic.Int64
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rnd := rand.New(rand.NewSource(*maskAtSeed*7000003 + int64(w)))
			for x := w; x < total; x += workers {
				if failed.Load() {
					return
				}
				s := randomFormText(rnd)
				compared.Add(1)
				if d := formDifference(s); d != "" {
					failed.Store(true)
					t.Error(d)
					return
				}
				if normalizeForms(s) != s {
					changed.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	// A comparison in which nothing is ever rewritten proves nothing.
	if !failed.Load() && changed.Load() < compared.Load()/20 {
		t.Errorf("only %d of %d generated strings were rewritten: the generator does not reach the code", changed.Load(), compared.Load())
	}
	t.Logf("%d generated strings (seed %d), each compared as normalizeForms, addressForm and the readings of each number in it; %d of them were rewritten", compared.Load(), *maskAtSeed, changed.Load())
}

// Original code, copied from forms.go at 67b9d3c.

// normalizeFormsBefore is normalizeForms as it was.
func normalizeFormsBefore(s string) string {
	var b strings.Builder
	copied := 0
	for i := 0; i < len(s); {
		c := s[i]
		from, end, repl := i, 0, ""
		switch {
		case c == '&':
			if end = i + atEntityLen(s[i:]); end > i && atBetween(s, i, end) {
				repl = "@"
			} else {
				i++
				continue
			}
		case c >= 0x80 && atRuneLen(s[i:]) > 0:
			if end = i + atRuneLen(s[i:]); atBetween(s, i, end) {
				repl = "@"
			} else {
				i = end
				continue
			}
		case isDigit(c) || c >= 0x80:
			var ok bool
			if from, end, repl, ok = addressFormBefore(s, i); !ok {
				i = max(end, i+1)
				continue
			}
		default:
			i++
			continue
		}
		b.WriteString(s[copied:from])
		b.WriteString(repl)
		copied, i = end, end
	}
	if copied == 0 {
		return s
	}
	b.WriteString(s[copied:])
	return b.String()
}

// readFormNumberBefore reads the number that starts at s[i], a digit, as far as it goes.
func readFormNumberBefore(s string, i int) formNumber {
	var f formNumber
	p := i
	for {
		part, q, ok := readFormPartBefore(s, p)
		if !ok || f.n >= len(f.parts) {
			f.bad = true
		} else {
			f.parts[f.n] = part
		}
		f.n++
		if part.start != part.end && !isASCIIDigits(s[part.start:part.end]) && !part.hex {
			f.nonASCII = true
		}
		p = q
		dot := dotAt(s, p)
		if dot == 0 {
			break
		}
		if _, size := digitAt(s, p+dot); size == 0 {
			break
		}
		f.nonASCII = f.nonASCII || dot > 1
		p += dot
	}
	f.end = p
	return f
}

// readFormPartBefore reads one part at s[p], a digit: 0x and hexadecimal digits, or decimal
// digits (ASCII or full-width). ok is false for a part that cannot be an IPv4 number: one
// of more than twelve digits, or a hexadecimal one of more than eight. The part is read to
// its end either way, so that the caller skips it whole.
func readFormPartBefore(s string, p int) (part formPart, q int, ok bool) {
	part.start = p
	if s[p] == '0' && p+2 < len(s) && (s[p+1] == 'x' || s[p+1] == 'X') && hexVal(s[p+2]) >= 0 {
		part.hex = true
		q = p + 2
		for q < len(s) {
			d, isHex := hexDigit(s[q])
			if !isHex {
				break
			}
			if q-p-2 < 8 {
				part.dec = part.dec<<4 | d
			}
			q++
		}
		part.end = q
		return part, q, q-p-2 <= 8
	}
	part.octOK = true
	q, digits, zeroFirst := p, 0, false
	for {
		d, size := digitAt(s, q)
		if size == 0 {
			break
		}
		if digits == 0 {
			zeroFirst = d == 0
		}
		if digits < maxFormDigits {
			part.dec = part.dec*10 + d
			part.oct = part.oct*8 + d
		}
		part.octOK = part.octOK && d < 8
		digits++
		q += size
	}
	part.end = q
	part.lead0 = digits > 1 && zeroFirst
	part.octOK = part.octOK && part.lead0
	return part, q, digits <= maxFormDigits
}

// formAddressBefore reads the number as inet_aton reads it: four parts are the four bytes, three
// parts end in a 16-bit number, two in a 24-bit one and one is the whole address. A part
// with a leading zero is octal when octal is set and every digit of it is below 8, and
// decimal otherwise: parsers differ on "010", so both readings are tried.
func formAddressBefore(f formNumber, octal bool) (netip.Addr, bool) {
	var v [4]uint64
	for k := 0; k < f.n; k++ {
		p := f.parts[k]
		v[k] = p.dec
		if p.lead0 && octal {
			if !p.octOK {
				return netip.Addr{}, false
			}
			v[k] = p.oct
		}
	}
	var w uint64
	switch f.n {
	case 1:
		w = v[0]
	case 2:
		if v[0] > 0xFF || v[1] > 0xFFFFFF {
			return netip.Addr{}, false
		}
		w = v[0]<<24 | v[1]
	case 3:
		if v[0] > 0xFF || v[1] > 0xFF || v[2] > 0xFFFF {
			return netip.Addr{}, false
		}
		w = v[0]<<24 | v[1]<<16 | v[2]
	case 4:
		if v[0] > 0xFF || v[1] > 0xFF || v[2] > 0xFF || v[3] > 0xFF {
			return netip.Addr{}, false
		}
		w = v[0]<<24 | v[1]<<16 | v[2]<<8 | v[3]
	default:
		return netip.Addr{}, false
	}
	if w > 0xFFFFFFFF {
		return netip.Addr{}, false
	}
	a := netip.AddrFrom4([4]byte{byte(w >> 24 & 0xFF), byte(w >> 16 & 0xFF), byte(w >> 8 & 0xFF), byte(w & 0xFF)}) // w is at most 0xFFFFFFFF: the masks drop nothing
	return a, true
}

// formPublicAddressBefore is the public address the number denotes in one of its readings (octal
// first), if there is one. 0.0.0.0/8 locates no one, as it does in the dotted scan.
func formPublicAddressBefore(f formNumber) (netip.Addr, bool) {
	for _, octal := range [2]bool{true, false} {
		if a, ok := formAddressBefore(f, octal); ok && public(a) && a.As4()[0] != 0 {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// addressFormBefore reads the number at s[i], which starts with a digit, as an IPv4 address in an
// unusual spelling, and returns where its replacement starts and ends in s and the text of
// it. ok is false when the number is not rewritten; end is then where it ends, for the caller
// to skip it whole, so that the time stays linear in the text.
//
// A number is read only where nothing makes it part of a longer word: no letter, digit,
// underscore or full stop before it, and no letter, digit or underscore after it. Then
//
//   - four parts are read when one is hexadecimal, one after the first has a leading zero, or
//     a digit or full stop is full-width. (A first part with a leading zero, "007.8.8.8", is
//     read as glue by the scan for the usual form, which already masks it. Four parts of
//     plain decimal numbers are that scan's too.)
//   - two or three parts are read when one is hexadecimal. Every other number of fewer than
//     four parts, one number alone (hexadecimal or not) included, is read only as the host
//     of a URL, right after "//" and followed by the end of the text or a character that
//     ends a host (a slash, a colon, a question mark, a number sign, a backslash, white
//     space, a quote, a bracket, a comma or a semicolon). A URL parser reads such a host as
//     an IPv4 address whatever its spelling, as a number that ends it; the same text
//     elsewhere is a time, a size, a version, a date or an error code.
//
// The address is the number as inet_aton reads it (formNumber.address), in either reading of
// a leading zero, the octal one first. It is rewritten when it is public, as that address in
// dotted decimal, and so masked by the scan for the usual form, with whatever prefix length
// follows it. There is no number to leave alone for being masked already: what masking writes
// is a plain dotted network, which this function does not read.
func addressFormBefore(s string, i int) (from, end int, repl string, ok bool) {
	_, first := digitAt(s, i)
	if first == 0 {
		return i, i, "", false
	}
	if i > 0 {
		before, _ := utf8.DecodeLastRuneInString(s[:i])
		if before == '.' || wordRune(before) {
			return i, i + first, "", false
		}
	}
	f := readFormNumberBefore(s, i)
	skip := func() (int, int, string, bool) { return i, f.end, "", false }
	if f.bad {
		return skip()
	}
	hasHex, tail0 := false, false
	for k := 0; k < f.n; k++ {
		hasHex = hasHex || f.parts[k].hex
		tail0 = tail0 || k > 0 && f.parts[k].lead0
	}
	host := i >= 2 && s[i-2] == '/' && s[i-1] == '/'
	hostOnly := f.n < 4 && (f.n == 1 || !hasHex) // a number that is an address only as the host of a URL
	switch {
	case f.n == 4 && !hasHex && !tail0 && !f.nonASCII:
		return skip()
	case hostOnly && !host:
		return skip()
	}
	if f.end < len(s) {
		after, _ := utf8.DecodeRuneInString(s[f.end:])
		if wordRune(after) || hostOnly && !strings.ContainsRune(hostEnds, after) {
			return skip()
		}
	}
	a, ok := formPublicAddressBefore(f)
	if !ok {
		return skip()
	}
	return i, f.end, a.String(), true
}
