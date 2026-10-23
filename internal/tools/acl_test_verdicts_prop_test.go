package tools

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api"
)

// propHosts is the hosts section the generated tests are read against. web:443 may be
// quoted back as 192.0.2.10:443; a wider prefix is not an address of an alias.
var propHosts = map[string]string{"web": "192.0.2.10", "net": "192.0.2.0/24"}

var propDestinations = []string{
	"tag:db:5432", "web:443", "192.0.2.10:22", "192.0.2.10:443", "[2001:db8::10]:443",
	"[2001:DB8:0:0:0:0:0:10]:443", "192.0.2.1:1", "svc:web:443", "198.51.100.0/24:22",
}

var propForeign = []string{"192.0.2.99:1", "tag:other:22", "[2001:db8::99]:22"}

// genCase builds one test and one reply. The reply mixes lines of the grammar, lines for
// addresses no destination has, lines outside the grammar, an SSH line, a protocol that
// is not a name, a second spelling of an address and entries for other sources.
func genCase(rng *rand.Rand) (dests []testDest, results []api.TestResult) {
	for _, i := range rng.Perm(len(propDestinations))[:1+rng.IntN(4)] {
		d := testDest{Sent: propDestinations[i], Shown: propDestinations[i]}
		switch rng.IntN(8) {
		case 0, 1, 2:
			d.Accept = true
		case 3, 4, 5, 6:
			d.Deny = true
		default:
			d.Accept, d.Deny = true, true
		}
		dests = append(dests, d)
	}
	protos := []string{"", "tcp", "udp", "icmp"}
	words := [][2]string{{"Accept", "Drop"}, {"Drop", "Accept"}}
	var lines []string
	for _, d := range dests {
		n := rng.IntN(5) / 2
		if d.Accept && d.Deny {
			n = 1 + rng.IntN(8)/7
		}
		for ; n > 0; n-- {
			w := words[rng.IntN(2)]
			if rng.IntN(6) > 0 {
				switch {
				case d.Accept && !d.Deny:
					w = words[0]
				case d.Deny && !d.Accept:
					w = words[1]
				}
			}
			quoted := d.Sent
			if d.Sent == "web:443" && rng.IntN(2) == 0 {
				quoted = "192.0.2.10:443"
			}
			lines = append(lines, gridLine(quoted, protos[rng.IntN(len(protos))], w[0], w[1]))
		}
	}
	for n := rng.IntN(6) / 5; n > 0; n-- {
		w := words[rng.IntN(2)]
		lines = append(lines, gridLine(propForeign[rng.IntN(len(propForeign))], "tcp", w[0], w[1]))
	}
	extras := []string{
		testHeading + `user or host is invalid: bad user spec given: "198.51.100.0/24"`,
		testHeading + `address autogroup:internet:22: is not a valid address`,
		"test(s) failed",
		gridLine("tag:db:5432", "TCP", "Accept", "Drop"),
		sshHeading + `src "tag:p" at "100.64.0.1", dst "tag:db" at "100.64.0.2", ssh user "root": want: "accept" got: "deny"`,
		"address `tag:db:5432`: want: Accept, got: Drop",
	}
	for n := rng.IntN(6) / 4; n > 0; n-- {
		lines = append(lines, extras[rng.IntN(len(extras))])
	}
	rng.Shuffle(len(lines), func(i, j int) { lines[i], lines[j] = lines[j], lines[i] })
	cut := rng.IntN(len(lines) + 1)
	results = append(results, api.TestResult{User: verdictSrc, Errors: lines[:cut]})
	if cut < len(lines) {
		results = append(results, api.TestResult{User: verdictSrc, Errors: lines[cut:]})
	}
	if rng.IntN(3) == 0 {
		other := gridLine(propDestinations[rng.IntN(len(propDestinations))], "tcp", "Accept", "Drop")
		results = append(results, api.TestResult{User: "group:ops", Errors: []string{other}})
	}
	if rng.IntN(3) == 0 {
		results = append(results, api.TestResult{User: verdictSrc, Warnings: []string{"a warning"}})
	}
	rng.Shuffle(len(results), func(i, j int) { results[i], results[j] = results[j], results[i] })
	return dests, results
}

// TestVerdictsNeverClaimWhatNoLineSupports is the property the reading is held to. A
// destination is allowed or denied only when no unmatched line and no line outside the
// grammar belongs to its test, and every such verdict has either a pairing line whose got
// word it is, or no line and the expectation it was listed with. The seed is printed when
// a case fails.
func TestVerdictsNeverClaimWhatNoLineSupports(t *testing.T) {
	seen := map[string]int{}
	for _, seed := range []uint64{1, 2, 3, 4} {
		rng := rand.New(rand.NewPCG(seed, 0x7a11))
		for i := 0; i < 400; i++ {
			dests, results := genCase(rng)
			got := deriveVerdicts(dests, verdictSrc, propHosts, results)
			if msg := checkProperty(dests, results, got); msg != "" {
				t.Fatalf("seed %d, case %d: %s\ndests %+v\nresults %+v\nreading %+v", seed, i, msg, dests, results, got)
			}
			seen["status "+got.Status]++
			for _, v := range got.Verdicts {
				seen["verdict "+v.Verdict]++
			}
		}
	}
	for _, k := range []string{
		"status pass", "status fail", "status unresolved", "status unknown",
		"verdict allowed", "verdict denied", "verdict unresolved", "verdict unknown",
	} {
		if seen[k] < 20 {
			t.Errorf("only %d of the generated cases reached %q (all: %v)", seen[k], k, seen)
		}
	}
}

func checkProperty(dests []testDest, results []api.TestResult, got testReading) string {
	if len(got.Verdicts) != len(dests) {
		return fmt.Sprintf("%d verdicts for %d destinations", len(got.Verdicts), len(dests))
	}
	for _, v := range got.Verdicts {
		if v.Why != "" && !slices.Contains(verdictReasons, v.Why) {
			return fmt.Sprintf("reason %q is outside the closed list", v.Why)
		}
		for _, p := range v.Protocols {
			if !protoRE.MatchString(p) {
				return fmt.Sprintf("protocol %q is not a protocol name", p)
			}
		}
	}
	seen := map[string]bool{}
	var order []string
	for _, d := range dests {
		k := canonicalDst(d.Sent)
		if !seen[k] {
			seen[k] = true
			order = append(order, k)
		}
	}
	keysOf := func(d testDest) []string {
		k := canonicalDst(d.Sent)
		keys := []string{k}
		if via := hostAddress(d.Sent, propHosts); via != "" && via != k {
			keys = append(keys, via)
		}
		return keys
	}
	ownersOf := func(dst string) []string {
		key := canonicalDst(dst)
		var hit []string
		for _, k := range order {
			for _, d := range dests {
				if canonicalDst(d.Sent) != k {
					continue
				}
				if slices.Contains(keysOf(d), key) {
					hit = append(hit, k)
					break
				}
			}
		}
		return hit
	}
	outside, stray := 0, 0
	foreignHit := map[string]bool{}
	paired := map[string][]FailureLine{}
	for _, res := range results {
		if res.User != verdictSrc {
			for _, text := range res.Errors {
				f, kind := readAssertion(text)
				if kind != AssertionFailed || f.SSH {
					continue
				}
				for _, k := range ownersOf(f.Dst) {
					foreignHit[k] = true
				}
			}
			continue
		}
		for _, text := range res.Errors {
			f, kind := readAssertion(text)
			if kind != AssertionFailed || f.SSH {
				if kind != AssertionFailed {
					outside++
				} else {
					stray++
				}
				continue
			}
			hit := ownersOf(f.Dst)
			if len(hit) != 1 {
				stray++
				continue
			}
			g := groupFlags(dests, hit[0])
			takes := g.accept && g.deny || g.accept && f.Want == "Accept" || g.deny && !g.accept && f.Want == "Drop"
			if !takes {
				stray++
				continue
			}
			paired[hit[0]] = append(paired[hit[0]], f)
		}
	}
	if (stray > 0 || len(foreignHit) > 0) != (len(got.Unmatched) > 0) {
		return fmt.Sprintf("stray lines %d, foreign %d, unmatched %d", stray, len(foreignHit), len(got.Unmatched))
	}
	for i, v := range got.Verdicts {
		k := canonicalDst(dests[i].Sent)
		lines := paired[k]
		switch v.Verdict {
		case verdictAllowed, verdictDenied:
			if stray > 0 || outside > 0 || foreignHit[k] {
				return fmt.Sprintf("verdict %d is %s beside a line that is unmatched or outside the grammar", i, v.Verdict)
			}
			if len(lines) == 0 {
				asked := verdictDenied
				if dests[i].Accept && !dests[i].Deny {
					asked = verdictAllowed
				}
				if groupFlags(dests, k).accept && groupFlags(dests, k).deny || v.Verdict != asked {
					return fmt.Sprintf("verdict %d is %s with no line (asked %s)", i, v.Verdict, asked)
				}
			} else {
				word := verdictDenied
				if lines[0].Got == "Accept" {
					word = verdictAllowed
				}
				same := true
				for _, f := range lines {
					w := verdictDenied
					if f.Got == "Accept" {
						w = verdictAllowed
					}
					if w != word {
						same = false
					}
				}
				if !same || v.Verdict != word || (groupFlags(dests, k).accept && groupFlags(dests, k).deny && len(lines) != 1) {
					return fmt.Sprintf("verdict %d is %s; the line says %s (%d lines)", i, v.Verdict, word, len(lines))
				}
			}
		case verdictUnresolved, verdictUnknown:
		default:
			return fmt.Sprintf("verdict %d is %q", i, v.Verdict)
		}
	}
	if got.Status == statusPass && (stray > 0 || outside > 0) {
		return "status pass beside a line that is unmatched or outside the grammar"
	}
	if stray > 0 && got.Status != statusUnknown {
		return "an unmatched line left the status " + got.Status
	}
	return ""
}

func groupFlags(dests []testDest, key string) (g struct{ accept, deny bool }) {
	for _, d := range dests {
		if canonicalDst(d.Sent) == key {
			g.accept = g.accept || d.Accept
			g.deny = g.deny || d.Deny
		}
	}
	return g
}
