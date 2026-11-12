package sanitize

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// This file holds the address masking of personal.go as it was before maskAt was split into
// smaller functions (the copies below are verbatim from commit 67b9d3c, with the name
// suffix Before, and each calls only the copies), and the tests that require the split
// code to give byte-identical results. The copies are an oracle, not code that runs: they
// share the helpers that were not changed (starts, readAddr, readPrefix, maskGlue's
// callees, ...), so they check what the split changed and nothing else. A helper that is
// changed later changes the oracle with it; the tests above the oracle in personal_test.go
// and the fuzz targets are what hold those.

var (
	maskAtCount = flag.Int("maskat.n", 3000, "generated strings the maskAt differential tests compare, for each of the plain and keyed masker")
	maskAtSeed  = flag.Int64("maskat.seed", 1, "seed of the generated strings of the maskAt differential tests")
	maskAtLen   = flag.Int("maskat.len", 6, "longest string, in symbols, of the exhaustive maskAt differential test")
)

// textBefore is Masker.Text with the address masking of the oracle.
func textBefore(m Masker, s string) string {
	return m.Emails(maskAddrsAllBefore(m.readable(s)))
}

// maskAddrsAllBefore is MaskAddrs with the oracle's maskAddrsBefore.
func maskAddrsAllBefore(s string) string {
	for range maxRounds {
		next := maskAddrsBefore(maskWindows(s), true)
		if next == s {
			break
		}
		s = next
	}
	return s
}

// atCall is one call of maskAt, in a shape maskRun and maskGlue make.
type atCall struct {
	i, j, k int
	bits    string
	settle  bool
	depth   int
}

// atCalls lists the calls the masking makes for the run s[i:j], and a few at other starts of
// the run: the run read as an address (k = j), with the bits that follow it, as a prefix
// (k > j), and as glue (depth 0), each with and without settle.
func atCalls(s string, i, j int) []atCall {
	var out []atCall
	k := bitsEnd(s, i, j)
	for _, from := range []int{i, i + 1, i + 2} {
		if from >= j {
			break
		}
		for _, settle := range []bool{true, false} {
			out = append(out,
				atCall{from, j, j, "", settle, 1},
				atCall{from, j, j, s[j:k], settle, 1},
				atCall{from, j, j, "", settle, 0})
			if k > j {
				out = append(out, atCall{from, j, k, "", settle, 1})
			}
		}
	}
	return out
}

// atRuns calls fn for each run of address bytes in s, as maskAddrs finds them.
func atRuns(s string, fn func(i, j int)) {
	for i := 0; i < len(s); {
		if !addrByte(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && addrByte(s[j]) {
			j++
		}
		fn(i, j)
		i = j
	}
}

// atDifference returns what differs between the original and the split maskAt for s, or "".
func atDifference(s string, keyed Masker) string {
	var diff string
	atRuns(s, func(i, j int) {
		if diff != "" {
			return
		}
		for _, c := range atCalls(s, i, j) {
			oo, oe, of := maskAtBefore(s, c.i, c.j, c.k, c.bits, c.settle, c.depth)
			no, ne, nf := maskAt(s, c.i, c.j, c.k, c.bits, c.settle, c.depth)
			if oo != no || oe != ne || of != nf {
				diff = fmt.Sprintf("maskAt(%q, %d, %d, %d, %q, %v, %d): before %q, %d, %+v; after %q, %d, %+v", s, c.i, c.j, c.k, c.bits, c.settle, c.depth, oo, oe, of, no, ne, nf)
				return
			}
		}
	})
	if diff != "" {
		return diff
	}
	if o, n := maskAddrsAllBefore(s), MaskAddrs(s); o != n {
		return fmt.Sprintf("MaskAddrs(%q): before %q, after %q", s, o, n)
	}
	for name, m := range map[string]Masker{"plain": {}, "keyed": keyed} {
		if o, n := textBefore(m, s), m.Text(s); o != n {
			return fmt.Sprintf("%s Text(%q): before %q, after %q", name, s, o, n)
		}
	}
	return ""
}

// corpusStrings are the strings of the existing fuzz corpora: the files under testdata/fuzz,
// and every string literal in the package's other test files (the seeds of the fuzz targets
// among them, and the tables of the address tests).
func corpusStrings(t *testing.T) (files, literals []string) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "fuzz", "*", "*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			if q, ok := strings.CutPrefix(line, "string("); ok {
				if u, err := strconv.Unquote(strings.TrimSuffix(q, ")")); err == nil {
					files = append(files, u)
				}
			}
		}
	}
	tests, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, p := range tests {
		if strings.HasSuffix(p, "_oracle_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if l, ok := n.(*ast.BasicLit); ok && l.Kind == token.STRING {
				if u, err := strconv.Unquote(l.Value); err == nil && !seen[u] {
					seen[u] = true
					literals = append(literals, u)
				}
			}
			return true
		})
	}
	sort.Strings(literals)
	return files, literals
}

// framed are the neighbours a corpus string is also tried with: a label that runs into an
// address, an escape, and the text that ends one.
var framed = [][2]string{{"", ""}, {"x", ""}, {"eth0:", ""}, {"%22", ""}, {`\x`, ""}, {"", "."}, {"", ":"}, {"", "/24"}, {"", ".443"}, {"", "::1"}, {"ipv6.", " 8.8.8.8"}}

// hardRuns are runs the tests of this package build by concatenation, so that no literal of
// them holds the whole: the ones that reach the readings made last (a run that holds two "::"
// and a reading after the first that locates nobody, and eight groups after a "::").
var hardRuns = []string{
	"A010.010.010.010::2001:db8:abcd:1234:5678:9abc:def0:1111.a", "A8.8.8.8::2001:db8:abcd:1234:5678:9abc:def0:1111.a",
	"::ffff::::", "::ffff::::.", "9e8f128.8.8.8::ffff::::", "x::ffff::::1", "fd7a:115c:a1e0::1::ffff::", "a::b::c::d", "2001:db8::1::5", "2001:db8:abcd::9e8f::8.8.8.8",
}

func TestMaskAtMatchesTheOriginalOnTheFuzzCorpora(t *testing.T) {
	keyed, _ := keyedMasker(t)
	files, literals := corpusStrings(t)
	if len(files) < 5 || len(literals) < 1000 {
		t.Fatalf("the corpora hold %d corpus files' strings and %d test literals: the walk found too little", len(files), len(literals))
	}
	n := 0
	for _, group := range [][]string{files, literals, hardRuns} {
		for _, c := range group {
			if len(c) > 4096 {
				continue
			}
			for _, f := range framed {
				s := f[0] + c + f[1]
				n++
				if d := atDifference(s, keyed); d != "" {
					t.Fatal(d)
				}
			}
		}
	}
	t.Logf("%d strings from %d corpus files and %d test literals, each in %d frames, compared plain and keyed", n, len(files), len(literals), len(framed))
}

// atPieces are the parts of the generated strings: groups and numbers of addresses, what
// joins them, what runs into them and what ends them.
var (
	atGroups = []string{"0", "1", "5", "8", "20", "64", "db8", "dead", "beef", "2001", "fd7a", "115c", "a1e0", "ffff", "ff9b", "9e8f", "abcd", "1234", "41641", "443",
		"198", "51", "100", "203", "113", "255", "256", "10", "192", "168", "127", "169", "254", "224", "007", "00", "6", "7", "9", "2606", "4700", "1111",
		"2001:db8:abcd:1234:5678:9abc:def0:1111", "8.8.8.8", "010.010.010.010", "198.51.100.247a", "::ffff::::", "::ffff:", "a::b::c", "dead::", "1.5.6", "fd7a:115c:a1e0::1"}
	atJoins  = []string{":", ":", ":", "::", ".", ".", ".", ":::", ".", ":", "::", "/24", "/64", "/48", "/40", "/128", "/129", "/7", "/32", "/8", "/0", "/", "/3", "/24198", ".0/24"}
	atLabels = []string{"A", "9e8f", "eth0", "ens5", "ipv6", "x", "a1", "dead", "tcp", "%22", "%2", `\x`, `\u`, `\x52`, "%", "Error", "example.com", "db8", "e", "0x", "f", "a", "::ffff:", "ipv6:", "ipv6."}
	atGlue   = []string{" ", " ", ",", "[", "]", "(", ")", "=", "@", "\"", "\n", "-", ";"}
)

// randomAddressText joins pieces of addresses, with glue between the runs.
func randomAddressText(rnd *rand.Rand) string {
	var b strings.Builder
	for runs := 1 + rnd.Intn(4); runs > 0; runs-- {
		if rnd.Intn(3) == 0 {
			b.WriteString(atLabels[rnd.Intn(len(atLabels))])
		}
		for parts := 1 + rnd.Intn(11); parts > 0; parts-- {
			b.WriteString(atGroups[rnd.Intn(len(atGroups))])
			if parts > 1 || rnd.Intn(2) == 0 {
				b.WriteString(atJoins[rnd.Intn(len(atJoins))])
			}
		}
		if rnd.Intn(4) == 0 {
			b.WriteString(atLabels[rnd.Intn(len(atLabels))])
		}
		b.WriteString(atGlue[rnd.Intn(len(atGlue))])
	}
	return b.String()
}

// groupsRun is a label and an IPv4 address in front of "::" and eight groups, as the run that
// the readings made last are made of ("A8.8.8.8::2001:db8:abcd:1234:5678:9abc:def0:1111.a"),
// with the number of groups, the separators and the text after the groups drawn at random.
func groupsRun(rnd *rand.Rand) string {
	var b strings.Builder
	b.WriteString([]string{"", "A", "x", "9e8f", "eth0:", "ipv6.", "%22", "0"}[rnd.Intn(8)])
	b.WriteString([]string{"8.8.8.8", "010.010.010.010", "198.51.100.247", "203.0.113.7", "10.0.0.1", "8.8.8", "1.2.3.4.5", "", "dead", "fd7a:115c:a1e0::1"}[rnd.Intn(10)])
	b.WriteString([]string{"::", "::", ":::", ":", "::ffff:", ".", "::1::"}[rnd.Intn(7)])
	groups := []string{"2001", "db8", "abcd", "1234", "5678", "9abc", "def0", "1111", "0", "ffff", "8.8.8.8", "1.5.6"}
	for n := 5 + rnd.Intn(6); n > 0; n-- {
		b.WriteString(groups[rnd.Intn(len(groups))])
		if n > 1 {
			b.WriteString([]string{":", ":", ":", ":", "::", "."}[rnd.Intn(6)])
		}
	}
	b.WriteString([]string{"", ".a", ".5.6", ".Error", ":443", ".dead:443", ":", ".", "/64", "a", ".example.com", "::"}[rnd.Intn(12)])
	return b.String()
}

// generatedText is a string for the comparison: mostly runs of address pieces, some mixed with the
// pieces of window_test.go (emails, credentials, unusual spellings).
func generatedText(rnd *rand.Rand) string {
	switch rnd.Intn(8) {
	case 0:
		return randomText(rnd, 10+rnd.Intn(80))
	case 1:
		return randomAddressText(rnd) + randomText(rnd, 5+rnd.Intn(25)) + randomAddressText(rnd)
	case 2, 3:
		return groupsRun(rnd)
	}
	return randomAddressText(rnd)
}

func TestMaskAtMatchesTheOriginalOnGeneratedText(t *testing.T) {
	keyed, _ := keyedMasker(t)
	total := *maskAtCount
	workers := min(runtime.GOMAXPROCS(0), 16)
	var wg sync.WaitGroup
	var failed atomic.Bool
	var maskedAny, strings64 atomic.Int64
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rnd := rand.New(rand.NewSource(*maskAtSeed*1000003 + int64(w)))
			for x := w; x < total; x += workers {
				if failed.Load() {
					return
				}
				s := generatedText(rnd)
				strings64.Add(1)
				if d := atDifference(s, keyed); d != "" {
					failed.Store(true)
					t.Error(d)
					return
				}
				if MaskAddrs(s) != s {
					maskedAny.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	// A comparison that never masks anything proves nothing.
	if !failed.Load() && maskedAny.Load() < strings64.Load()/10 {
		t.Errorf("only %d of %d generated strings were changed by masking: the generator does not reach the code", maskedAny.Load(), strings64.Load())
	}
	t.Logf("%d generated strings (seed %d), each compared as maskAt calls, MaskAddrs and Text with a plain and a keyed masker; %d of them were changed by masking", strings64.Load(), *maskAtSeed, maskedAny.Load())
}

// exhaustiveSymbols are the parts of the strings the exhaustive test enumerates: digits that
// make an octet or a group, a hex letter, the separators, and the "/" of a prefix.
var exhaustiveSymbols = []string{"8", "0", "f", ":", ".", "/"}

// The comparison over every string of up to -maskat.len symbols: nothing is left to the
// luck of a generator for the short runs, which hold every shape of group, separator and
// "::" that the readings tell apart.
func TestMaskAtMatchesTheOriginalOnEveryShortRun(t *testing.T) {
	keyed, _ := keyedMasker(t)
	maxLen := *maskAtLen
	workers := min(runtime.GOMAXPROCS(0), 16)
	var wg sync.WaitGroup
	var failed atomic.Bool
	var count atomic.Int64
	base := len(exhaustiveSymbols)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var b strings.Builder
			for n := 1; n <= maxLen; n++ {
				total := 1
				for range n {
					total *= base
				}
				for x := w; x < total; x += workers {
					if failed.Load() {
						return
					}
					b.Reset()
					for v, k := x, 0; k < n; k++ {
						b.WriteString(exhaustiveSymbols[v%base])
						v /= base
					}
					s := b.String()
					count.Add(1)
					if d := atDifference(s, keyed); d != "" {
						failed.Store(true)
						t.Error(d)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	t.Logf("%d strings: every one of up to %d symbols of %q, each compared as maskAt calls, MaskAddrs and Text with a plain and a keyed masker", count.Load(), maxLen, exhaustiveSymbols)
}

// Original code, copied from personal.go at 67b9d3c.

// maskAddrsBefore masks the runs of s. With settle, an address read from behind a label is
// masked once more together with the label (see maskAt).
func maskAddrsBefore(s string, settle bool) string {
	if !strings.ContainsAny(s, ".:") {
		return s // every address literal has a dot or a colon
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if !addrByte(s[i]) {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := i
		for j < len(s) && addrByte(s[j]) {
			j++
		}
		out, end := maskEscapedRunBefore(s, i, j, settle)
		b.WriteString(out)
		i = end
	}
	return b.String()
}

// maskEscapedRunBefore masks the run s[i:j] and returns the text that replaces s up to the
// returned end. When the run follows what could be an escape, "%22" or a backslash
// and x or u with their digits, the digits may be the escape's or the address's, and
// the text is read both ways: the escape's digits are not the start of what follows
// them ("%22" before 10.0.0.53 is not "2210.0.0.53"), but a reader who takes the
// backslash and x for two ordinary characters sees 52.94.236.248 in "\x52.94.236.248",
// and sees 8.8.8.8 in "%228.8.8.8" whatever 228.8.8.8 is. A public address in either
// reading is masked. The reading with the escape's digits left out is used when it
// masks an address from the start of what follows them; otherwise the run is read
// from its start, and if that masks something, or is one address that is not public,
// it is used.
func maskEscapedRunBefore(s string, i, j int, settle bool) (string, int) {
	skip := escapeLen(s, i, j)
	if skip == 0 {
		out, end, _ := maskRunBefore(s, i, j, settle)
		return out, end
	}
	outA, endA, fA := maskRunBefore(s, i+skip, j, settle)
	if fA.reading == masked && fA.start == i+skip {
		return s[i:i+skip] + outA, endA
	}
	outB, endB, fB := maskRunBefore(s, i, j, settle)
	if fB.reading == kept && fB.start == i && s[i-1] != '%' && outA != s[i+skip:endA] {
		// A backslash and x or u is an escape, whatever follows: "\xfd7a:115c:a1e0::1" is
		// the byte 0xfd and "7a:115c:a1e0::1", not a tailnet address behind a stray "\x".
		// (After a percent sign that may be a sign and no escape, the tailnet address wins.)
		return s[i:i+skip] + outA, endA
	}
	if outB != s[i:endB] || fB.reading == kept && fB.start == i {
		// Read from its start the run is a public address, or is all one address that
		// locates nobody ("ipv6%fd7a:115c:a1e0::1", a tailnet address after a percent
		// sign), which the escape's reading with a later start does not outweigh.
		return outB, endB
	}
	return s[i:i+skip] + outA, endA
}

// maskRunBefore masks the run s[i:j] and returns the text that replaces s up to the
// returned end: j, or the end of a "/bits" that follows the run, when the run ends
// in a prefix. It also returns what the run was read as.
func maskRunBefore(s string, i, j int, settle bool) (string, int, found) {
	k := bitsEnd(s, i, j)
	var res struct {
		out string
		end int
		f   found
	}
	if k > j {
		out, _, f := maskAtBefore(s, i, j, k, "", settle, 1)
		if f.reading == masked || f.reading == kept {
			return out, k, f
		}
		if f.reading == reserved {
			// Read as a prefix the run is text that is no address, such as the IPv4-in-IPv6
			// form "20::ffff:8.8.8.8/64"; read without the bits, "::ffff:8.8.8.8" is one.
			res.out, res.end, res.f = out, k, f
		}
	}
	out, end, f := maskAtBefore(s, i, j, j, s[j:k], settle, 1)
	if f.reading == masked || f.reading == kept || f.reading == reserved && res.f.reading == unread {
		return out, end, f
	}
	if res.f.reading == reserved {
		return res.out, res.end, res.f
	}
	mout, usedBits := maskIPv4WithinBits(s[i:j], s[j:k])
	if usedBits {
		return mout, k, found{start: -1}
	}
	return mout, j, found{start: -1}
}

// maskAtBefore reads the run s[i:j] as glue and an address that ends it, or, when k > j,
// as glue and a prefix that ends at k, and returns s[i:k] masked, with the end of what it
// masked and what the address was. The address starts at the first candidate (see starts)
// that reads as a public address, so the whole of what the label might hide is masked: a
// text in the reserved block is read again from a later start, and one that is another
// kind of address stays as it is and ends the search (in a run that holds two "::", a
// reading after the first is kept only when no later one is public). The address may end
// where the run does, before the colons and full stops that end it, or before the last
// "::" of a run that holds two. What comes before it is masked as glue (maskGlue) and
// what comes after it as text: an IPv4 address in it, with bits, the "/bits" that
// follow a run that is not read as a prefix, if it ends the run. Nothing is returned when
// no start reads as an address. depth is 1 for a run, and 0 for glue read as a run: glue
// is never the whole of its run, and is not read for a glue of its own.
func maskAtBefore(s string, i, j, k int, bits string, settle bool, depth int) (string, int, found) {
	ends := []int{j}
	// Glue that ends in a colon (depth 0) is the front of a longer run: its eight groups after
	// a "::" are not an address of their own, as they are where the run ends.
	open := depth == 0 && j > i && s[j-1] == ':'
	portFrom := -1     // the ends from here on are those before a colon and a port
	var stopEnds []int // the ends before a full stop and more, tried when nothing else reads
	if k == j {
		// A full stop or a colon after an address ends the sentence, not the address; but
		// an address may end in "::" ("2001:db8::.").
		if e := trimEnd(s, i, j); e > i && e < j {
			if j-e > 2 && s[e] == ':' && s[e+1] == ':' {
				ends = append(ends, e+2)
			}
			ends = append(ends, e)
		}
		// So may an IPv6 address that a port follows after a full stop, as tcpdump writes
		// it ("2001:db8::1.443").
		for _, e := range slices.Clone(ends) {
			if d := strings.LastIndexByte(s[i:e], '.') + i; d > i && e-d <= 6 && e-d > 1 && digitsEnd(s, d+1) >= e && strings.IndexByte(s[i:d], ':') >= 0 {
				ends = append(ends, d)
			}
		}
		// A second "::" begins text that is no part of an address: "2001:db8::1::5".
		if e := strings.LastIndex(s[i:j], "::") + i; e > i && strings.Contains(s[i:e], "::") {
			ends = append(ends, e)
		}
		// Or one that a port follows after a colon ("2001:db8::1:41641", "2001:db8:::443"), or
		// after a full stop whatever its length ("2001:db8::1.100022"). These ends come last,
		// since the run is read whole first: a colon and digits are one more group of the
		// address where the two make an address ("2001:db8::1:4164"), and the port after it
		// where they do not.
		portFrom = len(ends)
		for _, e := range slices.Clone(ends) {
			if c := strings.LastIndexByte(s[i:e], ':') + i; c > i && e-c > 1 && digitsEnd(s, c+1) >= e {
				ends = append(ends, c)
				if c-1 > i && s[c-1] == ':' {
					ends = append(ends, c-1) // a port after "::": the address ends before both colons
				}
			}
			if d := strings.LastIndexByte(s[i:e], '.') + i; d > i && e-d > 6 && digitsEnd(s, d+1) >= e && strings.IndexByte(s[i:d], ':') >= 0 {
				ends = append(ends, d)
			}
		}
		// Or one that a full stop and more follow: a word that starts with a letter a to f is
		// part of the run ("2001:db8::1.Error"), and so are numbers ("2001:db8::1.5.6"), and a
		// colon may follow them ("2001:db8::1.dead:443"). A full stop belongs to the literal
		// only in an IPv4 address at its end, which the whole run is read for first, so the
		// address ends before the first full stop after its last colon, or after its first.
		// A colon and a port may stand before the full stop, as they may at the end of the
		// run ("2001:db8::1:41641.example.com", "2001:db8::1:41641:.Error"): the address
		// ends before the colons that end it, after the end before the full stop, and then
		// before the port.
		// These ends are tried only when no reading above is made, not even a reserved one,
		// and the run holds no IPv4 address to mask: that one is masked first, and the run
		// read again ("dead::198.51.100.247a" is not "dead::198" and a tail).
		addStop := func(e int) {
			if !slices.Contains(stopEnds, e) {
				stopEnds = append(stopEnds, e)
			}
		}
		for _, e := range ends[:portFrom] {
			for _, c := range []int{strings.LastIndexByte(s[i:e], ':'), strings.IndexByte(s[i:e], ':')} {
				if c >= 0 {
					if d := strings.IndexByte(s[i+c:e], '.'); d > 0 && !slices.Contains(stopEnds, i+c+d) {
						stop := i + c + d
						addStop(stop)
						if t := trimEnd(s, i, stop); t > i && t < stop {
							addStop(t)
							stop = t
						}
						if q := strings.LastIndexByte(s[i:stop], ':') + i; q > i && stop-q > 1 && digitsEnd(s, q+1) >= stop {
							addStop(q)
							if q-1 > i && s[q-1] == ':' {
								addStop(q - 1)
							}
						}
					}
				}
			}
		}
	}
	// The text after the address is masked as text: an IPv4 address in it, with the bits
	// that follow the run if it ends the run, is cut to its network (see
	// maskIPv4WithinBits). Then the bits are used, and the end is theirs.
	tail := func(e int) (string, int) {
		out, usedBits := maskIPv4WithinBits(s[e:j], bits)
		if usedBits {
			return out, j + len(bits)
		}
		return out, j
	}
	// atMasked is the text for the public reading f of s[t:e].
	atMasked := func(t, e int, f found) (string, int, found) {
		rest, end := tail(e)
		out := maskGlueBefore(s, i, t, depth, f.dotted) + f.text + rest
		if settle && !f.dotted && t > i && (s[t-1] == ':' || hexVal(s[t-1]) >= 0) {
			// "dead:" and eight groups is no address, so the eight were masked on
			// their own; but "dead:2001:db8:abcd::/48" is one, and the next scan
			// would cut it to "dead:2001:db8::/48". The same holds where the label
			// runs into the first group ("0" and "226:fe80::/48" make the group 0226,
			// which a scan writes as 226). Settle on that now. It is for IPv6 only:
			// a second scan of a masked IPv4 prefix has nothing to add, and reads it
			// without the name that it was read behind.
			out = maskAddrsBefore(out, false)
		}
		return out, max(end, k), f
	}
	sawReserved, reservedAt, reservedEnd := false, k, k
	lateKept, lateKeptEnd, lateKeptFound := -1, 0, found{}
	// stopRead reads the run as ending before a full stop, one of stopEnds:
	// the reading that is made when nothing else reads, not even a reserved one, and the run
	// holds no IPv4 address to mask first, which is masked, and the run read again
	// ("dead::198.51.100.247a" is not "dead::198" and a tail). It reads as the run was read
	// before eight groups after a "::" were an address, or, with afterColons, only at such a
	// start.
	stopRead := func(afterColons bool) (int, int, found, bool) {
		if len(stopEnds) > 0 && maskIPv4Within(s[i:j]) != s[i:j] {
			return 0, 0, found{}, false
		}
		for _, e := range stopEnds {
			for _, t := range starts(s, i, e, j, open || !afterColons) {
				if afterColons && (t <= i+1 || s[t-1] != ':' || s[t-2] != ':' || strings.Count(s[i:e], "::") >= 2) {
					continue
				}
				f := readAddr(s[t:e])
				f.start = t
				if f.reading == masked {
					return t, e, f, true
				}
				if f.reading == kept {
					break // an address that is kept is not read from behind its first groups
				}
			}
		}
		return 0, 0, found{}, false
	}
	// lateRead is a public reading that starts after a "::" only because the eight groups
	// there end the run (see starts).
	type lateRead struct {
		t, e int
		f    found
	}
	var late lateRead
	for x, e := range ends {
		multi := strings.Count(s[i:e], "::") >= 2
		for _, t := range starts(s, i, e, j, open) {
			var f found
			if k > j {
				f = readPrefix(s[t:k])
			} else {
				f = readAddr(s[t:e])
			}
			f.start = t
			if portFrom >= 0 && x >= portFrom && f.reading != masked {
				// A port is the last reading to try: it changes nothing but what it masks, and
				// an address that is kept ("fd7a:115c:a1e0::1:41641") is not read from behind
				// its first groups.
				if f.reading == kept {
					break
				}
				continue
			}
			if f.embeds && f.reading != masked && (t > i || e < j || afterEscape(s, i) || depth == 0) {
				// An IPv4 address inside an IPv6 literal is kept only when the literal
				// is all there is to the run ("64:ff9b::203.0.113.7"). Behind a label, after
				// an escape's digits, or before a full stop, the literal is not the whole
				// run, and the IPv4 address in it is masked as it is anywhere else in the run.
				continue
			}
			switch f.reading {
			case masked:
				if !multi && t > i+1 && s[t-1] == ':' && s[t-2] == ':' {
					// A start after a "::" is listed only for eight groups that end the run, and
					// the run is read as it was before that first: its front may be an address
					// that this reading would leave whole ("<eight groups>.5.6::<eight groups>").
					// The late reading is made when nothing else reads; the next round of
					// MaskAddrs masks what the front left.
					if late.e == 0 {
						late = lateRead{t, e, f}
					}
					continue
				}
				return atMasked(t, e, f)
			case kept:
				if multi && t > i+1 && s[t-1] == ':' && s[t-2] == ':' {
					// In a run that holds two "::" a reading after the first is one guess among
					// several: look on for a public one before settling for it.
					if lateKept < 0 {
						lateKept, lateKeptEnd, lateKeptFound = t, e, f
					}
					continue
				}
				rest, end := tail(e)
				return maskGlueBefore(s, i, t, depth, false) + s[t:e] + rest + s[j:k], max(end, k), f
			case reserved:
				if t < reservedAt {
					reservedAt, reservedEnd = t, e
				}
				sawReserved = true
			}
		}
	}
	if lateKept >= 0 {
		rest, end := tail(lateKeptEnd)
		return maskGlueBefore(s, i, lateKept, depth, false) + s[lateKept:lateKeptEnd] + rest + s[j:k], max(end, k), lateKeptFound
	}
	if sawReserved {
		// What the label's digits and the address read as is left as it is, but not what
		// comes before the first such reading: "8.8.8.8::1" holds the IPv4 address 8.8.8.8
		// and the text ::1.
		rest, end := tail(reservedEnd)
		return maskGlueBefore(s, i, reservedAt, depth, false) + s[reservedAt:reservedEnd] + rest + s[j:k], max(end, k), found{reading: reserved, start: i}
	}
	if t, e, f, ok := stopRead(false); ok {
		return atMasked(t, e, f)
	}
	if late.e > 0 {
		return atMasked(late.t, late.e, late.f)
	}
	if t, e, f, ok := stopRead(true); ok {
		return atMasked(t, e, f)
	}
	return "", j, found{start: -1}
}

// maskGlueBefore masks what comes before the address that starts at t in the run s[i:j]: the
// IPv4 addresses in it, and, once, the IPv6 address it may hold if it is written with
// "::", since two addresses can be written with nothing between them. So may glue of
// eight groups or more: before an IPv4 address (v4: "2001:db8:abcd:b3a7:c9d1:e2f4:a5b6:9e8f"
// and 5.6.7.8, with a full stop between them or not), and, ending in a full stop, before
// any address ("...:9e8f." and dead::1): the full stop ends an address; or when the start
// is inside a group, because an address was glued on in front of another with nothing
// between them (the glue ends in a hex digit: "...:9e8f" and 2606:4700:...), and a port's
// digits make such a group too. (Other glue of groups alone may be a fingerprint or a MAC
// address: a run of 16 groups has no address in its first eight.)
func maskGlueBefore(s string, i, t, depth int, v4 bool) string {
	if g := s[i:t]; depth > 0 && (strings.Contains(g, "::") || strings.Count(g, ":") >= 7 && (v4 || fullStopAfterEightGroups(g) || hexByte(g[len(g)-1]))) {
		if out, _, f := maskAtBefore(s, i, t, t, "", false, depth-1); f.reading != unread {
			return out
		}
	}
	return maskIPv4Within(s[i:t])
}
