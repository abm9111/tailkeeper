package acl

import (
	"fmt"
	"strings"
	"testing"
)

// The growth guard counts the engine's own operations, not time: a wall-clock guard is
// blind above the sizes it can afford, and the Windows clock steps too coarsely for it. An
// operation is a value visited, an atom built, a comparison made (the unit of MaxWork), so
// the same input reads the same on every machine.
//
// For each adversarial family the guard builds the input at two sizes, 16 times apart,
// and compares the work. Linear work grows 16 times, n log n about 22, quadratic 256; the
// limit is 40, so only work worse than n log n fails.
const (
	opsFactor    = 16
	maxOpsGrowth = 40
)

// Sizes: the families of rules are measured from 1,000 to 16,000 rules; the others, which
// parse more slowly, from 250 to 4,000. The families in which every unit is a change are
// measured from 1,000 to 16,000 too: a loop that costs a sixteenth of a unit more for each
// change found is only over the limit once there are some thousands of them.
const (
	rulesSmall = 1000
	otherSmall = 250
)

type family2 struct {
	name string
	// small is the size the guard starts from, in rules or entries.
	small int
	// build returns the old and the new text for n units.
	build func(n int) (old, new string)
	// exercises, when set, says what the result must show for the pair to be the kind it
	// claims to be: that every unit is a change, say. It returns "" when it does.
	exercises func(r *DiffResult, n int) string
}

// growthTooHigh reports whether work grew past the limit when the input grew by opsFactor.
func growthTooHigh(small, large int64) bool {
	return float64(large)/float64(small) > maxOpsGrowth
}

func rep(n int, f func(i int) string) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = f(i)
	}
	return strings.Join(parts, ",")
}

var adversarial = []family2{
	{"identical rules", rulesSmall, func(n int) (string, string) {
		r := `{"action":"accept","src":["*"],"dst":["*:*"]}`
		return `{"acls":[` + rep(n, func(int) string { return r }) + `]}`, `{"acls":[` + rep(n+1, func(int) string { return r }) + `]}`
	}, nil},
	{"a full reversal", rulesSmall, func(n int) (string, string) {
		rule := func(i int) string { return fmt.Sprintf(`{"action":"accept","src":["g%d"],"dst":["t%d:80"]}`, i, i) }
		rev := func(i int) string { return rule(n - 1 - i) }
		return `{"acls":[` + rep(n, rule) + `]}`, `{"acls":[` + rep(n, rev) + `]}`
	}, nil},
	{"one rule with n destinations", rulesSmall, func(n int) (string, string) {
		dst := func(i int) string { return fmt.Sprintf(`"t%d:80"`, i) }
		return `{"acls":[{"action":"accept","src":["a"],"dst":[` + rep(n, dst) + `]}]}`, `{"acls":[{"action":"accept","src":["a"],"dst":[` + rep(n, dst) + `,"extra:1"]}]}`
	}, nil},
	{"one rule with n sources", rulesSmall, func(n int) (string, string) {
		src := func(i int) string { return fmt.Sprintf(`"g%d"`, i) }
		return `{"acls":[{"action":"accept","src":[` + rep(n, src) + `],"dst":["x:80"]}]}`, `{"acls":[{"action":"accept","src":[` + rep(n, src) + `,"*"],"dst":["x:80"]}]}`
	}, nil},
	{"n rules that differ only in source", rulesSmall, func(n int) (string, string) {
		rule := func(i int) string { return fmt.Sprintf(`{"action":"accept","src":["g%d"],"dst":["x:80"]}`, i) }
		return `{"acls":[` + rep(n, rule) + `]}`, `{"acls":[` + rep(n+1, rule) + `]}`
	}, nil},
	{"n rules that differ only in port", rulesSmall, func(n int) (string, string) {
		rule := func(i int) string { return fmt.Sprintf(`{"action":"accept","src":["a"],"dst":["x:%d"]}`, 2*i+1) }
		return `{"acls":[` + rep(n, rule) + `]}`, `{"acls":[` + rep(n+1, rule) + `]}`
	}, nil},
	{"a grant with n ip entries", rulesSmall, func(n int) (string, string) {
		ip := func(i int) string { return fmt.Sprintf(`"tcp:%d"`, 2*i+1) }
		return `{"grants":[{"src":["a"],"dst":["x"],"ip":[` + rep(n, ip) + `]}]}`, `{"grants":[{"src":["a"],"dst":["x"],"ip":[` + rep(n+1, ip) + `]}]}`
	}, nil},
	{"n tests, reversed", otherSmall, func(n int) (string, string) {
		test := func(i int) string { return fmt.Sprintf(`{"src":"g%d","accept":["t%d:80"]}`, i, i) }
		rev := func(i int) string { return test(n - 1 - i) }
		return `{"tests":[` + rep(n, test) + `]}`, `{"tests":[` + rep(n, rev) + `]}`
	}, nil},
	{"n groups", otherSmall, func(n int) (string, string) {
		g := func(i int) string { return fmt.Sprintf(`"group:g%d":["u%d@example.com"]`, i, i) }
		return `{"groups":{` + rep(n, g) + `}}`, `{"groups":{` + rep(n+1, g) + `}}`
	}, nil},
	{"one group of n one-character names", otherSmall, func(n int) (string, string) {
		name := func(i int) string { return fmt.Sprintf(`"%c"`, 'a'+i%26) }
		return `{"groups":{"g":[` + rep(n, name) + `]}}`, `{"groups":{"g":[` + rep(n+1, name) + `]}}`
	}, nil},
	{"n node attributes", otherSmall, func(n int) (string, string) {
		e := func(i int) string { return fmt.Sprintf(`{"target":["tag:t%d"],"attr":["a%d"]}`, i, i%7) }
		return `{"nodeAttrs":[` + rep(n, e) + `]}`, `{"nodeAttrs":[` + rep(n+1, e) + `]}`
	}, nil},
	{"n ssh rules", otherSmall, func(n int) (string, string) {
		e := func(i int) string {
			return fmt.Sprintf(`{"action":"accept","src":["g%d"],"dst":["t"],"users":["root"]}`, i)
		}
		return `{"ssh":[` + rep(n, e) + `]}`, `{"ssh":[` + rep(n+1, e) + `]}`
	}, nil},
	{"an unknown section of n elements", otherSmall, func(n int) (string, string) {
		e := func(i int) string { return fmt.Sprintf(`{"k%d":[%d]}`, i, i) }
		return `{"future":[` + rep(n, e) + `]}`, `{"future":[` + rep(n+1, e) + `]}`
	}, nil},
	// The families above diff a pair that is equal or one entry apart, so the loops that run
	// once for each change are barely entered. These change every unit, so n units are n
	// changes, and a loop that costs more for each change already found grows with the square.
	{"n rules widened", rulesSmall, func(n int) (string, string) {
		rule := func(posture string) func(int) string {
			return func(i int) string {
				return fmt.Sprintf(`{"action":"accept","src":["g%d"],"dst":["t%d:80"]%s}`, i, i, posture)
			}
		}
		return `{"acls":[` + rep(n, rule(`,"srcPosture":["posture:p"]`)) + `]}`, `{"acls":[` + rep(n, rule("")) + `]}`
	}, func(r *DiffResult, n int) string {
		if r.Counts.Widening < n {
			return fmt.Sprintf("%d widening findings for %d rules", r.Counts.Widening, n)
		}
		return ""
	}},
	{"n atoms of one destination, all edited", rulesSmall, func(n int) (string, string) {
		rule := func(port int) func(int) string {
			return func(i int) string {
				return fmt.Sprintf(`{"action":"accept","src":["g%d"],"dst":["x:%d"]}`, i, 2*i+port)
			}
		}
		return `{"acls":[` + rep(n, rule(1)) + `]}`, `{"acls":[` + rep(n, rule(2)) + `]}`
	}, func(r *DiffResult, n int) string {
		if r.Matched != 1 || len(r.Changes) != 1 || r.Counts.Semantic != 1 {
			return fmt.Sprintf("%d changes, want the one change that holds all %d atoms", r.Matched, n)
		}
		return ""
	}},
	{"n tag owners changed", rulesSmall, func(n int) (string, string) {
		e := func(owner string) func(int) string {
			return func(i int) string { return fmt.Sprintf(`"tag:t%d":["%s%d@example.com"]`, i, owner, i) }
		}
		return `{"tagOwners":{` + rep(n, e("u")) + `}}`, `{"tagOwners":{` + rep(n, e("v")) + `}}`
	}, func(r *DiffResult, n int) string {
		if r.Matched < n {
			return fmt.Sprintf("%d changes for %d units", r.Matched, n)
		}
		return ""
	}},
	{"n hosts changed", rulesSmall, func(n int) (string, string) {
		e := func(octet int) func(int) string {
			return func(i int) string { return fmt.Sprintf(`"h%d":"192.0.2.%d"`, i, octet+i%100) }
		}
		return `{"hosts":{` + rep(n, e(1)) + `}}`, `{"hosts":{` + rep(n, e(101)) + `}}`
	}, func(r *DiffResult, n int) string {
		if r.Matched < n {
			return fmt.Sprintf("%d changes for %d units", r.Matched, n)
		}
		return ""
	}},
	{"n distinct node attributes changed", rulesSmall, func(n int) (string, string) {
		e := func(target string) func(int) string {
			return func(i int) string { return fmt.Sprintf(`{"target":["tag:%s%d"],"attr":["a%d"]}`, target, i, i) }
		}
		return `{"nodeAttrs":[` + rep(n, e("t")) + `]}`, `{"nodeAttrs":[` + rep(n, e("u")) + `]}`
	}, func(r *DiffResult, n int) string {
		if r.Matched < n {
			return fmt.Sprintf("%d changes for %d units", r.Matched, n)
		}
		return ""
	}},
	{"n unknown sections changed", rulesSmall, func(n int) (string, string) {
		e := func(v int) func(int) string {
			return func(i int) string { return fmt.Sprintf(`"future%d":[%d]`, i, v) }
		}
		return `{` + rep(n, e(1)) + `}`, `{` + rep(n, e(2)) + `}`
	}, func(r *DiffResult, n int) string {
		if r.Matched < n {
			return fmt.Sprintf("%d changes for %d units", r.Matched, n)
		}
		return ""
	}},
}

func opsOf(t *testing.T, f family2, n int) int64 {
	t.Helper()
	old, new := f.build(n)
	r := propertyDiff(t, old, new)
	if f.exercises != nil {
		if why := f.exercises(r, n); why != "" {
			t.Fatalf("n=%d: the pair does not exercise what the family is for: %s", n, why)
		}
	}
	return r.Ops
}

func TestOperationCountGrowsLinearly(t *testing.T) {
	for _, f := range adversarial {
		// The families do not share state, so they run side by side.
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			small, large := opsOf(t, f, f.small), opsOf(t, f, f.small*opsFactor)
			if small < 100 {
				t.Fatalf("only %d operations at n=%d: the input does not exercise anything", small, f.small)
			}
			if growthTooHigh(small, large) {
				t.Errorf("%d operations at n=%d and %d at n=%d: x%.1f, over the limit of x%d", small, f.small, large, f.small*opsFactor, float64(large)/float64(small), maxOpsGrowth)
			} else {
				t.Logf("x%.1f", float64(large)/float64(small))
			}
		})
	}
}

// The guard must be able to fail: work that grows with the square of the input is over the
// limit, work that grows linearly or as n log n is not. (The real code was seen failing it
// with a planted quadratic: a sort of a rule's ports after every port added to it.)
func TestOperationCountGuardCanFail(t *testing.T) {
	for _, c := range []struct {
		name         string
		small, large int64
		tooHigh      bool
	}{
		{"linear", 1000, 16000, false},
		{"n log n", 1000, 22400, false},
		{"quadratic", 1000, 256000, true},
		{"n to the 1.5", 1000, 64000, true},
	} {
		if got := growthTooHigh(c.small, c.large); got != c.tooHigh {
			t.Errorf("%s: growthTooHigh(%d, %d) = %v", c.name, c.small, c.large, got)
		}
	}
}
