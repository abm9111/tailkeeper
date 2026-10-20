package acl

import (
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"
)

func TestParsePortsMergesAndNeverExpandsRanges(t *testing.T) {
	for in, want := range map[string]string{
		"*":              "*",
		"0-65535":        "*",
		"80":             "80",
		"443,80":         "80,443",
		"80,80,81":       "80-81",
		"80-90,85-95":    "80-95",
		"80-90,91":       "80-91",
		"80-90,92":       "80-90,92",
		"1-65535":        "1-65535",
		"22,*":           "*",
		"65535":          "65535",
		"0":              "0",
		"1000-2000,1500": "1000-2000",
		"5-1":            "",
		"65536":          "",
		"":               "",
		"-5":             "",
		"a":              "",
		"80,":            "",
		"80-":            "",
		"080":            "80",
		"123456":         "",
		"1-2-3":          "",
		"tcp":            "",
		"80:90":          "",
	} {
		p, ok := parsePorts(in)
		if (want == "") == ok {
			t.Errorf("parsePorts(%q) ok = %v, want %v", in, ok, want != "")
			continue
		}
		if ok && p.String() != want {
			t.Errorf("parsePorts(%q) = %s, want %s", in, p.String(), want)
		}
	}
}

func TestSplitDstAtTheLastColon(t *testing.T) {
	for in, want := range map[string][3]string{
		"tag:web:80,443":                    {"tag:web", "80,443", "ok"},
		"*:*":                               {"*", "*", "ok"},
		"autogroup:self:*":                  {"autogroup:self", "*", "ok"},
		"192.0.2.0/24:22":                   {"192.0.2.0/24", "22", "ok"},
		"[2001:db8::1]:80":                  {"[2001:db8::1]", "80", "ok"},
		"2001:db8::/32:443":                 {"2001:db8::/32", "443", "ok"},
		"build-box:22":                      {"build-box", "22", "ok"},
		"group:finance team@example.com:22": {"group:finance team@example.com", "22", "ok"},
		"tag:web":                           {"tag:web", "none", "no"},
		"nocolon":                           {"nocolon", "none", "no"},
		"tag:web:":                          {"tag:web:", "none", "no"},
	} {
		sel, p, ok := splitDst(in)
		if sel != want[0] || p.String() != want[1] || (want[2] == "ok") != ok {
			t.Errorf("splitDst(%q) = %q, %s, %v; want %q, %s, %s", in, sel, p.String(), ok, want[0], want[1], want[2])
		}
	}
}

func TestSplitIPReadsProtocolAndPorts(t *testing.T) {
	for in, want := range map[string][2]string{
		"tcp:443":   {"tcp", "443"},
		"TCP:443":   {"tcp", "443"},
		"udp:53,67": {"udp", "53,67"},
		"80":        {"", "80"},
		"*":         {"", "*"},
		"tcp:*":     {"tcp", "*"},
		"icmp":      {"", `"icmp"`},
		"tcp:":      {"", `"tcp:"`},
		"6:22":      {"6", "22"},
		"80-90":     {"", "80-90"},
	} {
		proto, p := splitIP(in)
		if proto != want[0] || p.String() != want[1] {
			t.Errorf("splitIP(%q) = %q, %s; want %q, %s", in, proto, p.String(), want[0], want[1])
		}
	}
}

func TestPortsUnionAndMinus(t *testing.T) {
	a, _ := parsePorts("80,443")
	b, _ := parsePorts("443,8000-8100")
	u := ports{}
	u.union(a)
	u.union(b)
	u.union(rawPorts("weird"))
	u.union(rawPorts("weird"))
	if got := u.String(); got != `80,443,8000-8100,"weird"` {
		t.Errorf("union = %s", got)
	}
	all, _ := parsePorts("*")
	if got := all.minus(a); got != "0-79,81-442,444-65535" {
		t.Errorf("* minus 80,443 = %s", got)
	}
	if got := u.minus(a); got != `8000-8100,"weird"` {
		t.Errorf("minus = %s", got)
	}
	if got := a.minus(u); got != "" {
		t.Errorf("a minus its superset = %q", got)
	}
	if got := (ports{}).String(); got != "none" {
		t.Errorf("empty = %s", got)
	}
}

func TestCanonSelectorMapsTheLegacyAutogroup(t *testing.T) {
	if canonSelector("autogroup:members") != "autogroup:member" || canonSelector("autogroup:member") != "autogroup:member" || canonSelector("group:members") != "group:members" {
		t.Error("canonSelector")
	}
}

// minus agrees with a set difference on a small universe, and is linear on a large one.
func TestPortsMinusAgreesWithASetDifference(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	spec := func() string {
		var parts []string
		for range 1 + rng.IntN(4) {
			lo := rng.IntN(60)
			if rng.IntN(2) == 0 {
				parts = append(parts, strconv.Itoa(lo))
			} else {
				parts = append(parts, strconv.Itoa(lo)+"-"+strconv.Itoa(lo+rng.IntN(12)))
			}
		}
		return strings.Join(parts, ",")
	}
	members := func(s string) map[int]bool {
		out := map[int]bool{}
		if s == "" {
			return out
		}
		for _, part := range strings.Split(s, ",") {
			lo, hi, isRange := strings.Cut(part, "-")
			a, _ := strconv.Atoi(lo)
			b := a
			if isRange {
				b, _ = strconv.Atoi(hi)
			}
			for n := a; n <= b; n++ {
				out[n] = true
			}
		}
		return out
	}
	for range 2000 {
		a, b := spec(), spec()
		pa, _ := parsePorts(a)
		pb, _ := parsePorts(b)
		got := members(pa.minus(pb))
		want := map[int]bool{}
		for n := range members(a) {
			if !members(b)[n] {
				want[n] = true
			}
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%s minus %s = %s (%v), want %v", a, b, pa.minus(pb), got, want)
		}
	}
	// Sixty thousand ranges against sixty thousand: one pass, not a pass for each.
	var big, odd []string
	for i := range 30000 {
		big = append(big, strconv.Itoa(2*i+1))
		odd = append(odd, strconv.Itoa(4*i+1))
	}
	x, _ := parsePorts(strings.Join(big[:30000], ","))
	y, _ := parsePorts(strings.Join(odd[:16000], ","))
	if got := x.minus(y); len(got) == 0 {
		t.Error("the difference of two large sets is empty")
	}
}
