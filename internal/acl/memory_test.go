package acl

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// allocDuring is the bytes the runtime allocated while f ran, garbage included (TotalAlloc):
// the bound is on what a call costs the allocator, whatever the collector does later.
func allocDuring(f func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// parseAllocAtCap is the allocation Parse was measured to need for a document of exactly
// MaxNodes values (an object holding one array of ones), rounded up. The node cap is
// derived from it the way the MCP server's body cap is derived from its probe of four
// concurrent 8 MiB reads (internal/mcpserver/server.go): about 420 bytes of allocation a
// value (510 under the race detector), 0.45 GB at 1<<20 values and 0.22 GB at the cap of
// 1<<19, which four calls in flight, each holding two policies, keep within what the
// server budgets. The figure is rounded up so that a run with the race detector fits; the
// test below pins the cap and the number together: doubling the cap, or halving it, fails
// it.
const parseAllocAtCap = 300 << 20

func onesDocument(values int) []byte {
	// {"a":[1,1,...,1]} holds the object, the name, the array and the ones: 3 + n values.
	return []byte(`{"a":[` + strings.Repeat("1,", values-4) + `1]}`)
}

func TestTheNodeCapAndItsMeasuredAllocationArePinnedTogether(t *testing.T) {
	if MaxNodes != 1<<19 {
		t.Fatalf("MaxNodes is %d: measure Parse at the new cap, set parseAllocAtCap, and say why in the comment", MaxNodes)
	}
	text := onesDocument(MaxNodes)
	var d *Doc
	var err error
	got := allocDuring(func() { d, err = Parse(context.Background(), text) })
	if err != nil {
		t.Fatalf("a document of exactly MaxNodes values: %v", err)
	}
	if d.Nodes() != MaxNodes {
		t.Fatalf("a document of exactly MaxNodes values has %d nodes", d.Nodes())
	}
	t.Logf("Parse at the cap allocated %d bytes (%d a value)", got, got/MaxNodes)
	if got > parseAllocAtCap || got < parseAllocAtCap*2/3 {
		t.Errorf("Parse at the cap allocated %d bytes; the pinned figure is %d (between two thirds of it and all of it is accepted): re-measure and update both", got, uint64(parseAllocAtCap))
	}
	// One value more is refused before the parser allocates.
	over := onesDocument(MaxNodes + 1)
	var oerr error
	refusal := allocDuring(func() { _, oerr = Parse(context.Background(), over) })
	if !errors.Is(oerr, ErrTooComplex) || refusal > 64<<10 {
		t.Errorf("one value over the cap: err = %v, allocated %d bytes", oerr, refusal)
	}
}

// The bomb inputs are refused at the cap or cost a stated multiple of their size.
func TestBombInputsCostWhatIsStated(t *testing.T) {
	ctx := context.Background()
	const perNode = 640 // bytes of allocation a value, measured at 420 to 480, with room

	// Millions of one-token values: refused from the guard's count, before any allocation.
	ones := []byte("[" + strings.Repeat("1,", 2<<20) + "1]")
	var err error
	if a := allocDuring(func() { _, err = Parse(ctx, ones) }); !errors.Is(err, ErrTooComplex) || a > 64<<10 {
		t.Errorf("a 4 MiB array of ones: err = %v, allocated %d bytes", err, a)
	}
	// Many tiny objects: a stated cost a value.
	tiny := []byte(`{"a":[` + strings.Repeat("{},", 100000) + `{}]}`)
	var d *Doc
	a := allocDuring(func() { d, err = Parse(ctx, tiny) })
	if err != nil {
		t.Fatalf("100,000 tiny objects: %v", err)
	}
	if a > uint64(perNode*d.Nodes()+(64<<10)) {
		t.Errorf("100,000 tiny objects: %d values, allocated %d bytes (limit %d a value)", d.Nodes(), a, perNode)
	}
	if a := allocDuring(func() { _, err = Normalise(ctx, d) }); err != nil || a > uint64(perNode*d.Nodes()) {
		t.Errorf("normalising them: allocated %d bytes, err %v", a, err)
	}
	// One string of 4 MiB: parsing copies it once; normalising writes it out a few times.
	big := []byte(`{"a":"` + strings.Repeat("x", MaxBytes-20) + `"}`)
	a = allocDuring(func() { d, err = Parse(ctx, big) })
	if err != nil {
		t.Fatalf("a 4 MiB string: %v", err)
	}
	if a > 2*uint64(len(big)) {
		t.Errorf("a 4 MiB string: Parse allocated %d bytes for %d", a, len(big))
	}
	if a := allocDuring(func() { _, err = Normalise(ctx, d) }); err != nil || a > 12*uint64(len(big)) {
		t.Errorf("a 4 MiB string: Normalise allocated %d bytes for %d, err %v", a, len(big), err)
	}
	// Deep and wide: 500 levels of 20 values each.
	var b strings.Builder
	b.WriteString(`{"groups":{"g":`)
	for range 500 {
		b.WriteString(`[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,`)
	}
	b.WriteString(`0` + strings.Repeat("]", 500) + `}}`)
	wide := []byte(b.String())
	a = allocDuring(func() { d, err = Parse(ctx, wide) })
	if err != nil {
		t.Fatalf("deep and wide: %v", err)
	}
	if a > uint64(perNode*d.Nodes()) {
		t.Errorf("deep and wide: %d values, allocated %d bytes", d.Nodes(), a)
	}
	if a := allocDuring(func() { _, err = Normalise(ctx, d) }); err != nil || a > uint64(perNode*d.Nodes()) {
		t.Errorf("deep and wide, normalised: allocated %d bytes, err %v", a, err)
	}
	// A megabyte of one-character strings.
	chars := []byte(`{"groups":{"g":[` + strings.Repeat(`"a",`, 262000) + `"a"]}}`)
	a = allocDuring(func() { d, err = Parse(ctx, chars) })
	if err != nil {
		t.Fatalf("1 MiB of one-character strings: %v", err)
	}
	if a > uint64(perNode*d.Nodes()) {
		t.Errorf("1 MiB of one-character strings: %d values, allocated %d bytes", d.Nodes(), a)
	}
}

// A document of the largest size the cap allows fits in the work budget with room to spare,
// so the budget is a net for work nobody planned for and not a limit real policies meet. A
// sixteenth of the cap is measured and the work scaled up: the work is linear in the input
// (TestOperationCountGrowsLinearly), and a policy at the cap is slow to build under the
// race detector.
func TestTheWorkBudgetCoversTheLargestAcceptedPolicy(t *testing.T) {
	const scale = 16
	rule := `{"action":"accept","src":["*"],"dst":["*:*"]}`
	// 9 values a rule.
	text := `{"acls":[` + strings.Repeat(rule+",", (MaxNodes/scale-3)/9-1) + rule + `]}`
	d, err := Parse(context.Background(), []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	r, err := Diff(context.Background(), d, d, DiffOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Ops*scale > MaxWork/8 {
		t.Errorf("%d values need %d operations to compare with themselves; at the cap that is %d, more than an eighth of the budget of %d", d.Nodes(), r.Ops, r.Ops*scale, int64(MaxWork))
	}
	t.Logf("%d values, %d operations, %d at the cap, a budget of %d", d.Nodes(), r.Ops, r.Ops*scale, int64(MaxWork))
}

// diffAllocPerOp is the most bytes of allocation (TotalAlloc, garbage included) a unit of
// work may cost in Diff. A host costs Diff about 3 KB however many hosts there are, and
// the units it is charged fall as the pair gets smaller (the sorts are shorter), so the
// ratio does: measured at 30,000 hosts, 26 for a pair that all differ and 56 for an equal
// pair (two normal forms and no change; 51 at 200,000 hosts), and 17 to 25 for the other
// shapes tried (rules, groups, tests, ssh rules). Everything Diff builds is paid for from
// the work budget, so the budget bounds the allocation per unit; what a call can reach is
// bounded first by the 4 MiB of text and the node cap. The worst measured within them is
// 233,000 hosts with short names: a changed pair costs 30.3M units of work (45% of
// the budget) and 787 MiB; 200,000 hosts cost 731 MiB changed and 561 MiB equal. The limit
// leaves room for the race detector (a few percent more).
const diffAllocPerOp = 80

// hostsDocument is a policy of n hosts, h0 to h(n-1), each at an address that ends in its
// number plus tail; two documents with different tails differ in every host.
func hostsDocument(n int, tail string) []byte {
	var b strings.Builder
	b.WriteString(`{"hosts":{`)
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"h%d":"192.0.2.%d%s"`, i, i%250, tail)
	}
	b.WriteString(`}}`)
	return []byte(b.String())
}

// Diff of a large pair costs the allocator a stated multiple of the work it counts. The
// pair is 30,000 hosts that all differ: 60,000 values on each side and 30,000 changes,
// each held as a raw change (about 120 bytes) until a page is cut.
func TestDiffAllocationIsBoundedByTheWork(t *testing.T) {
	const hosts = 30000
	ctx := context.Background()
	for _, c := range []struct {
		name         string
		oldTail, new string
		changes      int
	}{
		{"every host changed", "", "1", hosts},
		{"the same hosts twice", "", "", 0},
	} {
		oldDoc, err := Parse(ctx, hostsDocument(hosts, c.oldTail))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		newDoc, err := Parse(ctx, hostsDocument(hosts, c.new))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var r *DiffResult
		a := allocDuring(func() { r, err = Diff(ctx, oldDoc, newDoc, DiffOptions{PageSize: MaxPage}) })
		if err != nil {
			t.Fatalf("%s: Diff: %v", c.name, err)
		}
		if r.Matched != c.changes {
			t.Fatalf("%s: %d changes, want %d: the pair does not exercise what the pin measures", c.name, r.Matched, c.changes)
		}
		t.Logf("%s: %d values a side, %d changes, %d operations, allocated %d bytes (%.1f a unit of work)", c.name, oldDoc.Nodes(), r.Matched, r.Ops, a, float64(a)/float64(r.Ops))
		if r.Ops < MaxWork/64 || r.Ops > MaxWork/2 {
			t.Errorf("%s: %d operations, outside a sixty-fourth to a half of the budget %d: resize the pair", c.name, r.Ops, int64(MaxWork))
		}
		if limit := uint64(diffAllocPerOp) * uint64(r.Ops); a > limit {
			t.Errorf("%s: Diff allocated %d bytes for %d operations, past %d (%d a unit): something is built without being counted", c.name, a, r.Ops, limit, diffAllocPerOp)
		}
	}
}

// What Normalise may allocate, in bytes a unit of work, when the policy is made to multiply
// what it holds (a rule's ranges copied for each of its destinations). A refusal can leave
// everything add copied allocated, and add charges four units for the 16 bytes of a range
// (rangeCopyWeight): measured 5.0 for a refusal. An input that is accepted also writes the
// text of the ranges twice for each atom (the ports of the atom and the key that groups
// atoms), and pays for every byte of it: measured 4.4. The test of what a policy makes the
// engine build (shapes_test.go) states 16 for the shapes it covers, which copy no ranges.
const allocPerWorkUnit = 8

// allocAtDefaultBudget is the most a refusal may allocate at the default budget, whatever
// the number of destinations: add stops at 67 million units, at 4 units and 16 bytes a
// range copied, and measured 260 MiB for a policy of 32,768 ranges and 1,000 or 2,000
// destinations (it was 759 MiB and 1,019 MiB when a range cost one unit).
const allocAtDefaultBudget = 320 << 20

// portsByDestinations is a grant with one ip entry of ranges odd ports, which are ranges
// of their own (1,3,5,...), and dsts destinations: 6 bytes of text a range, in the one
// entry, and a copy of the ranges, and of their text, for each destination.
func portsByDestinations(ranges, dsts int) []byte {
	var ip, dst strings.Builder
	for i := range ranges {
		if i > 0 {
			ip.WriteByte(',')
		}
		fmt.Fprintf(&ip, "%d", 2*i+1)
	}
	for i := range dsts {
		if i > 0 {
			dst.WriteByte(',')
		}
		fmt.Fprintf(&dst, `"t%d"`, i)
	}
	return []byte(`{"grants":[{"src":["a"],"dst":[` + dst.String() + `],"ip":["tcp:` + ip.String() + `"]}]}`)
}

// A grant with one long list of port ranges and many destinations makes an atom for each
// destination, and each atom holds the ranges and the text of them: the work is the number
// of ranges times the number of destinations, and so is the memory. At the default budget a
// 198 KB policy (32,768 ranges, 1,000 destinations) was accepted at 65.6 million units of
// work and allocated 3.5 GiB, with a heap of 1.4 GiB at its peak, because the text of the
// ranges was written for each atom and counted once a range. Now what is written is
// counted by its bytes, so the allocation of whatever is accepted, or refused, is within
// a stated number of bytes a unit of the work budget. The budget is lowered so that the test is
// quick; the shapes are the real ones.
func TestPortRangesTimesDestinationsCostWhatIsStated(t *testing.T) {
	old := maxWork
	maxWork = 1 << 22
	t.Cleanup(func() { maxWork = old })
	ctx := context.Background()
	limit := uint64(allocPerWorkUnit)*uint64(maxWork) + 2<<20
	normalise := func(text []byte) (ops int64, alloc uint64, err error) {
		d, perr := Parse(ctx, text)
		if perr != nil {
			t.Fatal(perr)
		}
		var n *NormalForm
		alloc = allocDuring(func() { n, err = Normalise(ctx, d) })
		if n != nil {
			ops = n.Ops()
		}
		return ops, alloc, err
	}

	// The bomb: refused, and cheap to refuse.
	ops, alloc, err := normalise(portsByDestinations(32768, 1000))
	t.Logf("32,768 ranges, 1,000 destinations: ops %d, allocated %d bytes, err %v", ops, alloc, err)
	if !errors.Is(err, ErrTooComplex) {
		t.Errorf("32,768 ranges by 1,000 destinations: err = %v, want too_complex at a budget of %d", err, maxWork)
	}
	if alloc > limit {
		t.Errorf("32,768 ranges by 1,000 destinations: allocated %d bytes before it was refused, past %d (%d a unit of work)", alloc, limit, allocPerWorkUnit)
	}

	// The most destinations the budget accepts, found by growing the number a quarter at a
	// time: its work is more than four fifths of the budget (the next size up was refused),
	// and its allocation is within the limit.
	var best int
	var bestOps int64
	var bestAlloc uint64
	for dsts := 1; dsts <= 1024; dsts += (dsts + 3) / 4 {
		ops, alloc, err := normalise(portsByDestinations(32768, dsts))
		if err != nil {
			if !errors.Is(err, ErrTooComplex) {
				t.Fatalf("%d destinations: %v", dsts, err)
			}
			break
		}
		best, bestOps, bestAlloc = dsts, ops, alloc
	}
	t.Logf("accepted up to %d destinations: ops %d of %d, allocated %d bytes", best, bestOps, maxWork, bestAlloc)
	if best == 0 || best == 1024 || bestOps <= maxWork*3/5 {
		t.Fatalf("the largest accepted input has %d destinations and %d operations of a budget of %d: the family does not reach the budget", best, bestOps, maxWork)
	}
	if bestAlloc > limit {
		t.Errorf("%d destinations of 32,768 ranges: accepted at %d operations and allocated %d bytes, past %d (%d a unit of work): the text of the ranges is built without being counted", best, bestOps, bestAlloc, limit, allocPerWorkUnit)
	}
}

// At the default budget the same policies, which the budget refuses, cost a bounded amount
// however many destinations they name: 400 KB of text (32,768 ranges, 2,000 destinations)
// was refused with 1 GiB held, and the server runs several calls at once.
func TestPortRangesTimesDestinationsAreRefusedCheaplyAtTheDefaultBudget(t *testing.T) {
	ctx := context.Background()
	for _, dsts := range []int{1000, 2000} {
		d, err := Parse(ctx, portsByDestinations(32768, dsts))
		if err != nil {
			t.Fatal(err)
		}
		var nerr error
		alloc := allocDuring(func() { _, nerr = Normalise(ctx, d) })
		t.Logf("32,768 ranges, %d destinations: allocated %d bytes, err %v", dsts, alloc, nerr)
		if !errors.Is(nerr, ErrTooComplex) {
			t.Errorf("%d destinations: err = %v, want too_complex", dsts, nerr)
		}
		if alloc > allocAtDefaultBudget {
			t.Errorf("%d destinations of 32,768 ranges: allocated %d bytes before it was refused, past %d", dsts, alloc, int64(allocAtDefaultBudget))
		}
	}
}
