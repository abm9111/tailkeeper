package guard

import (
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/tailscale/hujson"
)

func deepArray(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }

func deepObject(n int) string {
	return strings.Repeat(`{"a":`, n) + "1" + strings.Repeat("}", n)
}

// The limit is exact: 1,000 levels pass and 1,001 do not. A pass that moved the
// comparison by one (>= for >) fails the first row.
func TestNestsDeeperThanBoundary(t *testing.T) {
	cases := map[string]struct {
		in   string
		deep bool
	}{
		"1,000 array levels":                {deepArray(1000), false},
		"1,001 array levels":                {deepArray(1001), true},
		"1,000 object levels":               {deepObject(1000), false},
		"1,001 object levels":               {deepObject(1001), true},
		"opens only, 1,001":                 {strings.Repeat("[", 1001), true},
		"a million opens":                   {strings.Repeat("[", 1_000_000), true},
		"closers first count for nothing":   {strings.Repeat("]", 50) + deepArray(1000), false},
		"closers first, then 1,001":         {strings.Repeat("]", 50) + deepArray(1001), true},
		"brackets in a string":              {`"` + strings.Repeat("[", 5000) + `"`, false},
		"an escaped quote keeps it open":    {`"\"` + strings.Repeat("[", 5000) + `"`, false},
		"an escaped backslash ends it":      {`"\\"` + deepArray(1001), true},
		"brackets in a line comment":        {"// " + strings.Repeat("[", 5000) + "\n1", false},
		"brackets in a block comment":       {"/* " + strings.Repeat("[", 5000) + " */ 1", false},
		"deep after a line comment":         {"// c\n" + deepArray(1001), true},
		"deep after a block comment":        {"/* [[[ */" + deepArray(1001), true},
		"an unterminated line comment":      {"// " + strings.Repeat("[", 5000), false},
		"an unterminated block comment":     {"/* " + strings.Repeat("[", 5000), false},
		"a block comment that is only /*/":  {"/*/" + strings.Repeat("[", 5000), false},
		"an empty block comment":            {"/**/" + deepArray(1001), true},
		"a slash at the end":                {"/", false},
		"a slash that starts nothing":       {"/x" + deepArray(1001), true},
		"an unterminated string ends it":    {`"` + strings.Repeat("[", 5000), false},
		"nothing":                           {"", false},
		"1,000 levels around a long string": {strings.Repeat("[", 1000) + `"` + strings.Repeat("[", 5000) + `"` + strings.Repeat("]", 1000), false},
	}
	for name, c := range cases {
		if got := NestsDeeperThan(c.in, MaxDepth); got != c.deep {
			t.Errorf("%s: NestsDeeperThan = %v, want %v", name, got, c.deep)
		}
		if got := NestsDeeperThan([]byte(c.in), MaxDepth); got != c.deep {
			t.Errorf("%s (bytes): NestsDeeperThan = %v, want %v", name, got, c.deep)
		}
	}
	if !NestsDeeperThan("[[", 1) || NestsDeeperThan("[[", 2) {
		t.Error("the limit argument is not the limit the pass applies")
	}
}

// The line is counted by line feeds, as the HuJSON parser counts, and a carriage return
// is not a line break.
func TestScanReportsTheOffsetAndLineOfTheBracketPastTheLimit(t *testing.T) {
	r := Scan("\n\n"+strings.Repeat("[", 1001), MaxDepth)
	if !r.TooDeep || r.Offset != 2+1000 || r.Line != 3 {
		t.Errorf("got %+v, want TooDeep at offset 1002, line 3", r)
	}
	r = Scan("\r\r"+strings.Repeat("[", 1001), MaxDepth)
	if !r.TooDeep || r.Line != 1 {
		t.Errorf("carriage returns: got %+v, want line 1", r)
	}
	r = Scan(deepArray(1000), MaxDepth)
	if r.TooDeep || r.Offset != 0 || r.Line != 0 {
		t.Errorf("1,000 levels: got %+v, want no position", r)
	}
}

// NodeBound never undercounts the values the parser builds, and for documents without
// empty containers it is exact.
func TestScanNodeBoundCoversEveryValueTheParserBuilds(t *testing.T) {
	cases := []struct {
		in    string
		bound int
	}{
		{`5`, 1},
		{`[]`, 2},
		{`[1,2,3]`, 4},
		{`{"a":1,"b":[1,2]}`, 7},
		{`"a,b:c{[" `, 1},
		{"// , : { [\n[1]", 2},
		{"/* , : { [ */ [1]", 2},
		{`[[],[]]`, 5},
	}
	for _, c := range cases {
		r := Scan(c.in, MaxDepth)
		if r.NodeBound != c.bound {
			t.Errorf("Scan(%q).NodeBound = %d, want %d", c.in, r.NodeBound, c.bound)
		}
		v, err := hujson.Parse([]byte(c.in))
		if err != nil {
			t.Fatalf("%q: %v", c.in, err)
		}
		n := 0
		for range v.All() {
			n++
		}
		if r.NodeBound < n {
			t.Errorf("Scan(%q).NodeBound = %d, below the %d values the parser built", c.in, r.NodeBound, n)
		}
	}
}

// A document of millions of one-token values is counted without parsing it.
func TestScanCountsAFourMiBArrayOfOnes(t *testing.T) {
	r := Scan("["+strings.Repeat("1,", 2<<20)+"1]", MaxDepth)
	if want := 2 + 2<<20; r.TooDeep || r.NodeBound != want {
		t.Errorf("NodeBound = %d (too deep: %v), want %d", r.NodeBound, r.TooDeep, want)
	}
}

// refNestsDeeperThan is the pre-scan as it stood in internal/tools/cut.go before it moved
// here, kept as the reference the moved code is compared with.
func refNestsDeeperThan(t string, limit int) bool {
	depth := 0
	for i := 0; i < len(t); i++ {
		switch t[i] {
		case '"':
			for i++; i < len(t) && t[i] != '"'; i++ {
				if t[i] == '\\' {
					i++
				}
			}
		case '/':
			if i+1 == len(t) {
				break
			}
			switch t[i+1] {
			case '/':
				j := strings.IndexByte(t[i:], '\n')
				if j < 0 {
					return false
				}
				i += j
			case '*':
				j := strings.Index(t[i+2:], "*/")
				if j < 0 {
					return false
				}
				i += 2 + j + 1
			}
		case '{', '[':
			if depth++; depth > limit {
				return true
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return false
}

// The moved pass answers as the old one did on text built from the characters that steer
// it: brackets, quotes, backslashes, slashes, stars and line feeds. The seed is fixed, so
// a failure repeats.
func TestScanAgreesWithThePassItReplaced(t *testing.T) {
	const alphabet = "[]{}\"\\/*\n,:a1 "
	rng := rand.New(rand.NewPCG(1, 2))
	for i := range 20000 {
		b := make([]byte, rng.IntN(60))
		for j := range b {
			b[j] = alphabet[rng.IntN(len(alphabet))]
		}
		for _, limit := range []int{0, 1, 2, 5} {
			if got, want := NestsDeeperThan(string(b), limit), refNestsDeeperThan(string(b), limit); got != want {
				t.Fatalf("case %d, limit %d, %q: NestsDeeperThan = %v, the old pass says %v", i, limit, b, got, want)
			}
		}
	}
}
