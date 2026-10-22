package sanitize

import (
	"fmt"
	"math"
	"math/bits"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A clock reads the time elapsed since it was made. Production code never sees one:
// growth takes it as an argument so that a test can hand it a coarse one.
type clock func() time.Duration

// wallClock is the monotonic clock of the test binary.
func wallClock() clock {
	base := time.Now()
	return func() time.Duration { return time.Since(base) }
}

// fakeClock is a monotonic source of its own, so that a test of a coarse clock does not
// depend on the clock of the machine it runs on: a runner whose real clock is coarse too
// (Windows reads the system's interrupt time) would add its own jumps to a simulated
// one. Time passes only when the work says so (spend); the reading is that time rounded
// down to whole steps, as the monotonic clock of Windows does: Go reads the interrupt
// time, which moves with the timer tick (15.6 ms by default, 0.5 to 1 ms while a program
// has asked for a finer one), so a run shorter than a tick is timed as 0 and one of a
// few ticks as a whole number of them.
type fakeClock struct{ t, step time.Duration }

// reading is the clock the guard times with. Every reading lets a microsecond pass, so
// that clockStep, which waits for the clock to move, ends on a clock whose work has not.
func (f *fakeClock) reading() clock {
	return func() time.Duration { f.t += time.Microsecond; return f.t - f.t%f.step }
}

// exact is the same time, unrounded: what a deadline measures.
func (f *fakeClock) exact() clock { return func() time.Duration { return f.t } }

// spend lets d of time pass.
func (f *fakeClock) spend(d time.Duration) { f.t += d }

// work returns a function of the input size, as the guard takes it, whose run spends
// cost(n) of this clock's time and does nothing else.
func (f *fakeClock) work(cost func(n int) time.Duration) func(n int) func() {
	return func(n int) func() {
		c := cost(n)
		return func() { f.spend(c) }
	}
}

// linearCost and quadraticCost: 1 ns a byte, and the n²/256 ns of a loop that copies the
// string built so far. At 16 KiB the first is 16 µs; at 4 KiB the second is 65 µs. Both
// are far below a 15.6 ms step, and 8 times the input costs 8 and 64 times as much.
func linearCost(n int) time.Duration    { return time.Duration(n) }
func quadraticCost(n int) time.Duration { return time.Duration(n) * time.Duration(n) / 256 }

// nLogNCost is n·log₂n/16 ns, as a sort costs: it grows about 9.7 times from 16 to 128 KiB.
func nLogNCost(n int) time.Duration { return time.Duration(float64(n) * math.Log2(float64(n)) / 16) }

// powerCost is n^e/1024 ns: 8 times the input costs 8^e times as much.
func powerCost(e float64) func(n int) time.Duration {
	return func(n int) time.Duration { return time.Duration(math.Pow(float64(n), e) / 1024) }
}

// clockStep is the largest jump the clock made over a few tries: the distance between
// two readings that differ. A clock that moves in ticks reads as one tick, however
// long the wait for the next one was. It is the error of any one timing.
func clockStep(now clock) time.Duration {
	var step time.Duration
	for range 5 {
		first := now()
		next := now()
		for next == first {
			next = now()
		}
		step = max(step, next-first)
	}
	return step
}

const (
	// A timed batch of runs lasts at least minFloor, and at least floorSteps steps of the
	// clock, so that the clock's step is at most a tenth of what it measures. A single
	// run of the smaller input takes tens of microseconds, below the step of a coarse
	// clock, and was timed as 0 there.
	minFloor   = 20 * time.Millisecond
	floorSteps = 10
	// A size is timed in batches, and the fastest batch counts, so that a scheduler pause
	// or a collection inflates neither.
	batches = 3
	// maxRuns stops a batch that grows without end because the work takes no time at all.
	maxRuns = 1 << 20
)

// A batcher times batches of fresh runs of the work f(n). f builds its input untimed and
// returns the work to time, and every run gets an input of its own, built before the batch
// is timed. A batch of runs is timed as a whole: one timing is off by a step of the clock
// at most, and a batch is many steps long.
type batcher struct {
	now   clock
	floor time.Duration
	by    deadline
	f     func(n int) func()
	n     int
	runs  int // runs per batch, once settled
}

// time runs one batch of b.runs runs and returns how long it took.
func (b *batcher) time() time.Duration {
	work := make([]func(), b.runs)
	for i := range work {
		work[i] = b.f(b.n)
	}
	start := b.now()
	for _, run := range work {
		run()
	}
	return b.now() - start
}

// settle finds how many runs make a batch that lasts at least the floor, and returns that
// batch's time per run in nanoseconds. A batch shorter than the floor is thrown away and
// repeated with more runs.
func (b *batcher) settle() (float64, error) {
	for b.runs = 1; ; {
		if err := b.by.check(); err != nil {
			return 0, err
		}
		if b.runs > maxRuns {
			panic("growth: the work takes no time, so no batch of it reaches the floor")
		}
		d := b.time()
		if d >= b.floor {
			return float64(d) / float64(b.runs), nil
		}
		// A batch that read 0 gives no rate to extrapolate from; otherwise aim a quarter
		// past the floor, and never more than 16 times the runs at once.
		grow := 16
		if d > 0 {
			grow = int(min(16, max(2, 5*b.floor/(4*d)+1)))
		}
		b.runs *= grow
	}
}

// next times one more batch at the settled count, in nanoseconds per run.
func (b *batcher) next() (float64, error) {
	if err := b.by.check(); err != nil {
		return 0, err
	}
	return float64(b.time()) / float64(b.runs), nil
}

// A deadline bounds the guard as a whole. On a clock that moves in big steps every batch
// lasts many steps, and the 900 s package timeout of the Windows job would end the run
// with no word about which test was slow or why; the guard fails first, and says so.
type deadline struct {
	now   clock // the real clock, but in a test of the deadline itself
	end   time.Duration
	limit time.Duration
	step  *time.Duration // the largest clock step seen, for the message
}

// within returns a deadline limit from now, by the real clock.
func within(limit time.Duration) deadline { return withinOn(wallClock(), limit) }

// withinOn is within on the given clock, which a test can make its own.
func withinOn(now clock, limit time.Duration) deadline {
	return deadline{now: now, end: now() + limit, limit: limit, step: new(time.Duration)}
}

// check fails once the deadline has passed. The message names the guard and the clock.
func (d deadline) check() error {
	if d.now() < d.end {
		return nil
	}
	return fmt.Errorf("the growth guard (TestMaskingScalesLinearly) ran past its %v deadline, and stopped before the package timeout "+
		"could end the run without naming it: the clock it times with steps by %v, and every timed batch lasts at least "+
		"max(%v, %d steps) to read through that step; a clock this coarse needs a longer deadline or fewer rows",
		d.limit, *d.step, minFloor, floorSteps)
}

// growthOn returns how many times longer the work f(n) prepares takes on an input
// factor times larger, with the time read from now, or the deadline's error. Linear
// work grows about factor times, quadratic about factor squared.
//
// Each size is timed in batches and the fastest counts, so that a scheduler pause or a
// collection inflates neither. The batches of the two sizes alternate: a burst of load
// that lasts as long as several batches would otherwise land on all the batches of one
// size and none of the other, and move the ratio by the whole size of the burst.
func growthOn(now clock, by deadline, f func(n int) func(), n, factor int) (float64, error) {
	step := clockStep(now)
	*by.step = max(*by.step, step)
	floor := max(minFloor, floorSteps*step)
	small := &batcher{now: now, floor: floor, by: by, f: f, n: n}
	large := &batcher{now: now, floor: floor, by: by, f: f, n: n * factor}
	bestSmall, err := small.settle()
	if err != nil {
		return 0, err
	}
	bestLarge, err := large.settle()
	if err != nil {
		return 0, err
	}
	for range batches - 1 {
		each, err := small.next()
		if err != nil {
			return 0, err
		}
		bestSmall = min(bestSmall, each)
		if each, err = large.next(); err != nil {
			return 0, err
		}
		bestLarge = min(bestLarge, each)
	}
	// A reading of no time at all makes a ratio of 0/0, which is not above any limit: the
	// guard would pass on it. It is a failure of the measurement, not a pass.
	if bestSmall <= 0 || bestLarge <= 0 {
		return 0, fmt.Errorf("the growth guard (TestMaskingScalesLinearly) read %v per run at the smaller size and %v at the larger, "+
			"through a clock that steps by %v: it measured nothing", time.Duration(bestSmall), time.Duration(bestLarge), step)
	}
	return bestLarge / bestSmall, nil
}

// growth is growthOn the test binary's clock.
func growth(by deadline, f func(n int) func(), n, factor int) (float64, error) {
	return growthOn(wallClock(), by, f, n, factor)
}

// maxFailedRows is how many rows may fail before the guard stops: a regression shows in
// the first few, and timing the rest three times each only delays the report.
const maxFailedRows = 3

const (
	scaleN      = 16 << 10  // the smaller input: 16 KiB
	scaleFactor = 8         // the larger: 128 KiB
	scaleN2     = 128 << 10 // the smaller input of the second pair, for the rows of pastFirstPair: the larger is 1 MiB
	// maxGrowth sits halfway, in log scale, between linear (8) and quadratic
	// (64), so neither noise nor an n·log n path reaches it.
	maxGrowth = 24
)

// pastFirstPair are the rows also timed from 128 KiB to 1 MiB, since a quadratic term that
// dominates only past 128 KiB reads as linear on the first pair. The second pair costs eight
// times as much per run, so it is for some rows of the email scan, where the quadratic scan of
// 0.3.0 was and where the work of this change is, and the cheap colon scan. Each name must be
// a row of scalingCases.
var pastFirstPair = []string{
	"MaskEmails at signs", "MaskEmails escaped at signs", "MaskEmails chain", "MaskEmails long local part",
	"MaskEmails control characters", "MaskEmails percent chain", "MaskEmails quoted local parts",
	"MaskEmails words, dots, at signs", "MaskEmails brace escapes before at signs", "MaskEmails group names",
	"MaskEmails group names, then local bytes", "MaskAddrs colons",
}

// rowSizes are the smaller sizes a row is timed from, each against one eight times larger:
// the first pair for every row, the second also for the rows of pastFirstPair.
func rowSizes(name string) []int {
	if slices.Contains(pastFirstPair, name) {
		return []int{scaleN, scaleN2}
	}
	return []int{scaleN}
}

// The guard must be able to fail: work that is quadratic in its input must read as
// quadratic. This is proven on the fake clock, where the work costs what the model says
// and nothing else moves time, so the result is the same on every run. It was once
// proven on a real loop that concatenates a string (quadratic, as each step copies the
// string built so far), and 6 of 600 runs read below the limit (the lowest 17.65) with the
// machine idle: no real-clock threshold is both sure to be met by quadratic work and sure
// to be missed by linear work, which is why the real rows below are retried and this
// check is not made on the real clock at all. That the real rows fail on real quadratic
// code was shown by planting a quadratic loop in MaskAddrs: TestMaskingScalesLinearly
// fails, and stops once maxFailedRows rows have failed.
func TestGrowthDetectsQuadraticWork(t *testing.T) {
	fc := &fakeClock{step: time.Nanosecond}
	g, err := growthOn(fc.reading(), withinOn(fc.exact(), time.Minute), fc.work(quadraticCost), 4<<10, scaleFactor)
	if err != nil {
		t.Fatal(err)
	}
	// 8 times the input costs 64 times as much; the model has no noise, so the ratio is
	// the model's up to the microsecond each reading adds to a batch.
	if g < 60 || g > 68 {
		t.Fatalf("growth = %.1f for quadratic work, want about %d: the guard cannot fail", g, scaleFactor*scaleFactor)
	}
	if g, err = growthOn(fc.reading(), withinOn(fc.exact(), time.Minute), fc.work(linearCost), scaleN, scaleFactor); err != nil || g < 7.5 || g > 8.5 {
		t.Fatalf("growth = %.1f, %v for linear work, want about %d", g, err, scaleFactor)
	}
}

// The test above holds the guard able to fail, but not the limit where the comment on
// maxGrowth puts it: quadratic work reads as 64, over any limit below that, so the test
// would still pass with the limit raised to 56, where work clearly worse than linear but
// short of quadratic passes too. Halfway in log scale is 8^1.5, about 22.6. Work that
// grows as n^1.6 (about 28 times) must read as over the limit, and work that grows as
// n^1.4 (about 18) or as n·log n (about 9.7) as under it: the limit cannot move more than
// a tenth of an exponent from halfway without failing here.
func TestGrowthLimitSitsHalfwayBetweenLinearAndQuadratic(t *testing.T) {
	for _, c := range []struct {
		name string
		cost func(n int) time.Duration
		over bool
	}{
		{"n·log n", nLogNCost, false},
		{"n^1.4", powerCost(1.4), false},
		{"n^1.6", powerCost(1.6), true},
	} {
		fc := &fakeClock{step: time.Nanosecond}
		g, err := growthOn(fc.reading(), withinOn(fc.exact(), time.Minute), fc.work(c.cost), scaleN, scaleFactor)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if c.over && g <= maxGrowth {
			t.Errorf("growth = %.1f for %s work, not over the limit %d: the limit has moved toward quadratic", g, c.name, maxGrowth)
		}
		if !c.over && g >= maxGrowth {
			t.Errorf("growth = %.1f for %s work, at or over the limit %d: the limit has moved toward linear", g, c.name, maxGrowth)
		}
	}
}

// sink keeps the work of the two tests below from being optimised away.
var sink uint64

// The guard must also read through a coarse clock, where a run shorter than a step is
// timed as 0: on Windows the whole of TestMaskingScalesLinearly failed that way (every
// row that failed ran 10^5 to 10^6 times slower, because the smaller input read as one
// nanosecond), and a row whose two sizes both read 0 passed whatever grew. The clock is
// simulated here, at the 15.6 ms tick Windows has by default, so that every platform
// runs the case that broke one. Linear work must read as linear, and quadratic work as
// quadratic: a guard that read both as 1 would pass anything.
func TestGrowthReadsLinearAndQuadraticWorkThroughACoarseClock(t *testing.T) {
	fc := &fakeClock{step: 15625 * time.Microsecond}
	if step := clockStep(fc.reading()); step != fc.step {
		t.Fatalf("clockStep = %v for a clock that moves every %v", step, fc.step)
	}
	by := withinOn(fc.exact(), 5*time.Minute)
	g, err := growthOn(fc.reading(), by, fc.work(linearCost), scaleN, scaleFactor)
	if err != nil {
		t.Fatal(err)
	}
	if g < 3 || g > maxGrowth {
		t.Errorf("growth = %.1f for linear work on a coarse clock, want between 3 and %d (linear is about %d)", g, maxGrowth, scaleFactor)
	}
	g, err = growthOn(fc.reading(), by, fc.work(quadraticCost), 4<<10, scaleFactor)
	if err != nil {
		t.Fatal(err)
	}
	if g < maxGrowth {
		t.Errorf("growth = %.1f for quadratic work on a coarse clock, want at least %d: the guard cannot fail there", g, maxGrowth)
	}
}

// clockStep reports the largest jump: on a clock whose ticks are sometimes late, so that
// one reading jumps by two ticks, it says two. That is the safe way to be wrong: the
// guard's floor is a number of steps, so a larger step only makes its batches longer.
// (It was once tested against the real clock under a simulated one, and a real clock
// that is itself coarse added a jump of its own and made the test fail on Windows.)
func TestClockStepIsTheLargestJump(t *testing.T) {
	const tick = 15625 * time.Microsecond
	fc := &fakeClock{step: time.Millisecond}
	late := func() time.Duration { // every third tick is late: a jump of two ticks
		fc.spend(time.Millisecond)
		k := fc.t / tick
		return (k + k/3) * tick
	}
	if step := clockStep(late); step != 2*tick {
		t.Errorf("clockStep = %v on a clock whose ticks are %v and sometimes late by one, want %v", step, tick, 2*tick)
	}
}

// emailPatterns are the inputs that once made the email scan quadratic, and the
// shapes around them, n bytes each (about).
func emailPatterns(n int) map[string]string {
	return map[string]string{
		"at signs":                 strings.Repeat("@", n),
		"escaped at signs":         strings.Repeat(`\u0040`, n/6),
		"escaped at signs between": "a" + strings.Repeat(`\u0040!`, n/7),
		"at signs between":         "a" + strings.Repeat("@!", n/2),
		"local parts":              strings.Repeat("a!@", n/3),
		"dots":                     strings.Repeat("x@.", n/3),
		"chain":                    strings.Repeat("a@", n/2),
		"markers":                  strings.Repeat("@…", n/4),
		"long local part":          strings.Repeat("a", n) + "@!",
		"percent at signs":         strings.Repeat("%40", n/3),
		"percent at signs between": "a" + strings.Repeat("%40!", n/4),
		"percent local parts":      strings.Repeat("a!%40", n/5),
		"percent chain":            strings.Repeat("a%40", n/4),
		"control characters":       strings.Repeat("\x01", n) + "@!",
		"controls after at signs":  strings.Repeat("a@\x01", n/3),
		"controls after an at":     "a@" + strings.Repeat("\x01", n) + "!",
		"controls, then a break":   strings.Repeat("a@\x01 ", n/4),
		"percent controls":         "a@" + strings.Repeat("%00", n/3) + "!",
		"percent controls between": strings.Repeat("a@%00 ", n/6),
		"percent control chain":    strings.Repeat("a@%00", n/5),
		"addresses":                strings.Repeat("amy@example.com ", n/16),
		// A quoted local part is read back to its opening quote.
		"quotes before at signs":    strings.Repeat(`"@`, n/2),
		"quoted local parts":        strings.Repeat(`"a"@!`, n/5),
		"quoted words chained":      strings.Repeat(`"a".`, n/4) + "@!",
		"quoted words, many at":     strings.Repeat(`"a".@!`, n/6),
		"long quoted word":          `"` + strings.Repeat("a", n) + `"@!`,
		"long quoted word, escaped": `\"` + strings.Repeat("a", n) + `\"@!`,
		"escaped quotes":            strings.Repeat(`\"a\"@!`, n/7),
		"quotes, then an at sign":   strings.Repeat(`"`, n) + "@!",
		"escaped quotes, then at":   strings.Repeat(`\"`, n/2) + "@!",
		"both kinds of quote":       strings.Repeat(`"@!\"@!`, n/7),
		"quotes round at signs":     `"` + strings.Repeat("a@", n/2) + `"@!`,
		"quoted addresses":          strings.Repeat(`"amy"@example.com `, n/18),
		// A quoted word and an at sign with nothing after it, over and over: the at sign
		// before a quoted word is part of the local part of the one after it, and each
		// of them was once read back through all the earlier ones.
		"words, dots, at signs":             strings.Repeat(`"a".@`, n/5),
		"at signs, quotes, dots":            strings.Repeat(`@".`, n/3),
		"dots, at signs, quotes":            strings.Repeat(`.@"`, n/3),
		"two words, a dot, an at sign":      strings.Repeat(`"a"."a".@`, n/9),
		"escaped words, dots, at signs":     strings.Repeat(`\"a\".@`, n/6),
		"at signs, quotes, dots, words":     strings.Repeat(`@".dead`, n/7),
		"percent at signs, quotes, dots":    strings.Repeat(`%40".dead`, n/9),
		"dots, percent at signs, quotes":    strings.Repeat(`.%40"`, n/5),
		"words and at signs, then a domain": strings.Repeat(`"a".@`, n/5) + `"a"@example.com`,
		// A control character spelled as String shows it, in the places of an address.
		"brace escapes before at signs":   strings.Repeat("a\\u{0001}@", n/10),
		"brace escapes round at signs":    strings.Repeat("\\u{0001}@\\u{0001}", n/17),
		"brace escapes starting a domain": strings.Repeat("a@\\u{0001}b", n/11),
		// Words read back from one at sign, and a domain as long as they are: the domain is
		// scanned once for the at sign, not once for each word the walk crosses.
		"words, then a long domain": strings.Repeat(`"a".`, n/8) + `"a"@` + strings.Repeat("d", n/2),
		// A synced group's name is passed over whole: the text after it is scanned once.
		"group names":                        strings.Repeat("group:a@d.example ", n/18),
		"group names, then local bytes":      strings.Repeat("group:a@d!", n/10),
		"group prefixes after a used domain": strings.Repeat("group:a@", n/8),
		"group names, escaped tails":         strings.Repeat("group:a@d"+string(rune(92))+"u0020", n/16),
		"group name, a long domain, tails":   "group:a@" + strings.Repeat("d", n/2) + strings.Repeat("!@", n/4),
	}
}

// scalingRow is a result row with every kind of field Mask walks.
type scalingRow struct {
	Login string   `json:"login" tk:"untrusted,personal"`
	Note  string   `json:"note" tk:"untrusted"`
	Tags  []string `json:"tags" tk:"untrusted"`
}

type scalingOut struct {
	Rows []scalingRow `json:"rows" tk:"rows"`
}

// scalingKeys is a result with a map of text the tailnet chooses, as a key's custom claim
// rules are.
type scalingKeys struct {
	Claims map[string]string `json:"claims" tk:"untrusted"`
}

// collidingKeys is count distinct keys that all escape to one text: each of the positions
// after the first byte is a control character or the brace escape that spells it.
func collidingKeys(count int) map[string]string {
	keys := make(map[string]string, count)
	for i := range count {
		var b strings.Builder
		b.WriteByte('k')
		for bit := range bits.Len(uint(count)) {
			if i>>bit&1 == 1 {
				b.WriteString("\x01")
			} else {
				b.WriteString(`\u{0001}`)
			}
		}
		keys[b.String()] = "v"
	}
	return keys
}

// scalingCases are the rows of the growth guard: each builds the work for an input of about
// n bytes.
func scalingCases(t testing.TB) map[string]func(n int) func() {
	keyed, _ := keyedMasker(t)
	cases := map[string]func(n int) func(){}
	// The patterns of one size, built once: a string is only read, so every run of a case
	// may share it, and a batch of thousands of runs does not build thousands of them.
	patterns := map[int]map[string]string{}
	pattern := func(n int, name string) string {
		if patterns[n] == nil {
			patterns[n] = emailPatterns(n)
		}
		return patterns[n][name]
	}
	for name := range emailPatterns(1) {
		cases["MaskEmails "+name] = func(n int) func() {
			s := pattern(n, name)
			return func() { MaskEmails(s) }
		}
		cases["keyed Emails "+name] = func(n int) func() {
			s := pattern(n, name)
			return func() { keyed.Emails(s) }
		}
	}
	cases["MaskAddrs IPv4"] = func(n int) func() {
		s := strings.Repeat("203.0.113.7 ", n/12)
		return func() { MaskAddrs(s) }
	}
	cases["MaskAddrs IPv6"] = func(n int) func() {
		s := strings.Repeat("2001:db8::1 ", n/12)
		return func() { MaskAddrs(s) }
	}
	cases["MaskAddrs IPv6 and full stops"] = func(n int) func() {
		s := strings.Repeat("2001:db8:abcd::9e8f.Error ", n/26)
		return func() { MaskAddrs(s) }
	}
	cases["MaskAddrs IPv6, one long dotted tail"] = func(n int) func() {
		s := "2001:db8:abcd::9e8f" + strings.Repeat(".dead", n/5)
		return func() { MaskAddrs(s) }
	}
	cases["MaskAddrs groups, then dotted words"] = func(n int) func() {
		s := strings.Repeat("a:", n/4) + strings.Repeat(".dead", n/10)
		return func() { MaskAddrs(s) }
	}
	cases["MaskAddrs IPv6, words and ports"] = func(n int) func() {
		s := strings.Repeat("2001:db8::1.dead:443 ", n/21)
		return func() { MaskAddrs(s) }
	}
	cases["MaskAddrs eight groups and words"] = func(n int) func() {
		s := strings.Repeat("2001:db8:abcd:b3a7:c9d1:e2f4:a5b6:9e8f.dead::1 ", n/46)
		return func() { MaskAddrs(s) }
	}
	const eight = "2001:db8:abcd:b3a7:c9d1:e2f4:a5b6:9e8f"
	cases["MaskAddrs prefixes and eight groups"] = func(n int) func() {
		s := strings.Repeat("peer::"+eight+" ", n/(len(eight)+7))
		return func() { MaskAddrs(s) }
	}
	cases["MaskAddrs eight groups glued in one run"] = func(n int) func() {
		s := strings.Repeat(eight, n/len(eight))
		return func() { MaskAddrs(s) }
	}
	cases["MaskAddrs eight groups, a port and double colons"] = func(n int) func() {
		s := strings.Repeat(eight+":41641::", n/(len(eight)+8))
		return func() { MaskAddrs(s) }
	}
	const front = "2606:4700:4700:1111:aaaa:bbbb:cccc:dddd"
	cases["MaskAddrs a front, a word and double colons"] = func(n int) func() {
		s := strings.Repeat(eight+".5.6::"+front+" ", n/(len(eight)+len(front)+8))
		return func() { MaskAddrs(s) }
	}
	cases["MaskAddrs fronts, words and double colons in one run"] = func(n int) func() {
		s := strings.Repeat(eight+".A0::"+front+".A0", n/(len(eight)+len(front)+7))
		return func() { MaskAddrs(s) }
	}
	cases["MaskAddrs colons"] = func(n int) func() {
		s := strings.Repeat(":", n)
		return func() { MaskAddrs(s) }
	}
	// MaskText is MaskAddrs and then Emails over what it returned, and with a key it
	// first rewrites "[p:". A path that is linear in each is not necessarily linear in
	// the three together: the rows below put addresses and at signs side by side, so
	// that the address pass makes text the email pass then has to read.
	textRows := map[string]func(n int) string{
		"addresses and emails":         func(n int) string { return strings.Repeat("amy@example.com 203.0.113.7 ", n/28) },
		"addresses before at signs":    func(n int) string { return strings.Repeat("203.0.113.7@", n/12) },
		"at signs before addresses":    func(n int) string { return strings.Repeat("@203.0.113.7", n/12) },
		"addresses as domains":         func(n int) string { return strings.Repeat("a@203.0.113.7 ", n/14) },
		"percent at signs, addresses":  func(n int) string { return strings.Repeat("%40203.0.113.7 ", n/15) },
		"quoted words, addresses":      func(n int) string { return strings.Repeat(`"a".@8.8.8.8`, n/12) },
		"forged markers":               func(n int) string { return strings.Repeat(" [p:", n/4) },
		"forged markers and addresses": func(n int) string { return strings.Repeat("[p:203.0.113.7@", n/15) },
	}
	for name, row := range textRows {
		cases["MaskText "+name] = func(n int) func() {
			s := row(n)
			return func() { MaskText(s) }
		}
		cases["keyed Text "+name] = func(n int) func() {
			s := row(n)
			return func() { keyed.Text(s) }
		}
	}
	cases["keyed Text forged markers"] = func(n int) func() {
		s := strings.Repeat(" [p:", n/4)
		return func() { keyed.Text(s) }
	}
	cases["String controls"] = func(n int) func() {
		s := strings.Repeat("a\x1b[2J\u200b", n/8)
		return func() { String(s, 0) }
	}
	cases["Text line ends"] = func(n int) func() {
		s := strings.Repeat("x\r\n\t\r", n/5)
		return func() { Text(s, 0) }
	}
	cases["Fields keys that escape to one text"] = func(n int) func() {
		out := scalingKeys{Claims: collidingKeys(n / 48)}
		return func() { Fields(&out, DefaultMax) }
	}
	cases["Fields keys that differ after the cap"] = func(n int) func() {
		out := scalingKeys{Claims: map[string]string{}}
		for i := range n / 80 {
			out.Claims[strings.Repeat("k", 70)+strconv.Itoa(i)] = "v"
		}
		return func() { Fields(&out, 64) }
	}
	cases["Mask rows"] = func(n int) func() {
		rows := n / 64
		return func() {
			out := scalingOut{Rows: make([]scalingRow, rows)}
			for i := range out.Rows {
				out.Rows[i] = scalingRow{Login: "amy@example.com", Note: "owner bob@example.com", Tags: []string{"tag:web"}}
			}
			keyed.Mask(&out)
		}
	}
	return cases
}

// Every path that walks untrusted text or result rows grows linearly with its
// input. The 0.3.0 email scan grew with the square of it.
func TestMaskingScalesLinearly(t *testing.T) {
	cases := scalingCases(t)
	by := within(guardDeadline)
	failed := 0
	for name, f := range cases {
		reads, err := readRow(wallClock(), by, name, f)
		for _, r := range reads {
			if r.best > maxGrowth {
				failed++
				t.Errorf("%s from %d KiB: %.1f times slower on %d times the input, want at most %d (linear is about %d); %d measurements, each above it: %.1f",
					name, r.n>>10, r.best, scaleFactor, maxGrowth, scaleFactor, len(r.tries), r.tries)
				if failed == maxFailedRows {
					t.Fatalf("%d rows failed: the code they time grew faster than linearly; stopping here rather than timing the rest", failed)
				}
			} else if len(r.tries) > 1 {
				t.Logf("%s from %d KiB: first read %.1f, over %d; measured again: %.1f", name, r.n>>10, r.tries[0], maxGrowth, r.tries[1:])
			}
		}
		if err != nil {
			// Rows that really are quadratic are measured three times each and take long, so
			// a regression can reach the deadline: then the rows already reported are the
			// cause, and the clock is not.
			if failed > 0 {
				t.Fatalf("%d rows failed above: the code they time grew faster than linearly; the guard then ran past its %v deadline", failed, guardDeadline)
			}
			t.Fatal(err)
		}
	}
}

// rowAttempts is how many times a row over the limit is measured before it fails.
const rowAttempts = 3

// rowGrowthOn measures a row from the size n to one scaleFactor times larger on the given
// clock, and measures it again when it reads over the limit, up to rowAttempts times; it
// returns the lowest reading and all of them. A row fails only if every measurement is
// over: noise that moves a linear row (a reading of 26 to 28 against a limit of 24 turned
// up once in 10 runs with the race detector and once in 16 on Linux) comes and goes
// between measurements, and a quadratic row reads over the limit every time it is measured.
func rowGrowthOn(now clock, by deadline, f func(n int) func(), n int) (best float64, tries []float64, err error) {
	for range rowAttempts {
		g, err := growthOn(now, by, f, n, scaleFactor)
		if err != nil {
			return 0, nil, err
		}
		tries = append(tries, g)
		if len(tries) == 1 || g < best {
			best = g
		}
		if g <= maxGrowth {
			break
		}
	}
	return best, tries, nil
}

// rowRead is what timing a row from one size read: the size it started from, the lowest
// reading and every reading.
type rowRead struct {
	n     int
	best  float64
	tries []float64
}

// readRow times the row name from each size of rowSizes(name), one rowRead per size, on the
// given clock. It is the one reader of a row, for the guard and for the proof that the second
// pair can fail. It stops after the first size whose best reading is over maxGrowth: a row
// that fails is not timed on a pair eight times larger, which the deadline (checked only
// between batches) could not cut short, so a real regression cannot run past the go test
// timeout and lose the guard's own message. On an error it returns the reads so far.
func readRow(now clock, by deadline, name string, f func(n int) func()) ([]rowRead, error) {
	var reads []rowRead
	for _, n := range rowSizes(name) {
		best, tries, err := rowGrowthOn(now, by, f, n)
		if err != nil {
			return reads, err
		}
		reads = append(reads, rowRead{n: n, best: best, tries: tries})
		if best > maxGrowth {
			break
		}
	}
	return reads, nil
}

// The guard stops itself at its deadline, under the go test timeout of the platform's
// job, and fails with a message that names it: a clock that steps by 15.6 ms (Windows)
// makes it take much longer, which must pass there, and a run that overran would be ended
// by the timeout with no word about the guard. Elsewhere, with the race detector, it took
// 35 s at a load average of 5.6 to 10 (the second pair included).
const (
	guardDeadlineWindows = 600 * time.Second // under the Windows job's -timeout 900s
	guardDeadlineOther   = 100 * time.Second // under make test's -timeout 300s
	// restOfPackage is what the other tests of the package may take, on top of the guard.
	restOfPackage = 60 * time.Second
)

// guardDeadline is the deadline for this platform.
var guardDeadline = func() time.Duration {
	if runtime.GOOS == "windows" {
		return guardDeadlineWindows
	}
	return guardDeadlineOther
}()

// Each deadline must sit under the go test timeout of the run that has it, with room for
// the rest of the package: the Windows deadline under the Windows job's timeout in
// verify.yml, the other under the timeout of make test (which CI runs on Linux) and the
// other jobs'. A deadline at or over its timeout never fires before the timeout does.
func TestTheGuardDeadlinesAreUnderTheirTimeouts(t *testing.T) {
	yml, err := os.ReadFile("../../.github/workflows/verify.yml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`timeout=(\d+)s; if \[ "\$RUNNER_OS" = Windows \]; then timeout=(\d+)s`).FindSubmatch(yml)
	if m == nil {
		t.Fatal("verify.yml: no `timeout=Ns; if [ \"$RUNNER_OS\" = Windows ]; then timeout=Ns` in the test step")
	}
	mk, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	mt := regexp.MustCompile(`(?m)^\tenv -u TAILKEEPER_LIVE \$\(GO\) test -race -count=1 -timeout (\d+)s `).FindSubmatch(mk)
	if mt == nil {
		t.Fatal("Makefile: no `go test -race -count=1 -timeout Ns` line in the test target")
	}
	// make cover runs every package with -cover, which is slower, under its own timeout.
	mc := regexp.MustCompile(`(?m)^\tenv -u TAILKEEPER_LIVE \$\(GO\) test -count=1 -timeout (\d+)s -cover `).FindSubmatch(mk)
	if mc == nil {
		t.Fatal("Makefile: no `go test -count=1 -timeout Ns -cover` line in the cover target")
	}
	secs := func(b []byte) time.Duration {
		n, err := strconv.Atoi(string(b))
		if err != nil {
			t.Fatal(err)
		}
		return time.Duration(n) * time.Second
	}
	windowsJob, otherJobs, makeTest, makeCover := secs(m[2]), secs(m[1]), secs(mt[1]), secs(mc[1])
	for _, c := range []struct {
		what     string
		deadline time.Duration
		timeout  time.Duration
	}{
		{"the Windows deadline and the Windows job's timeout", guardDeadlineWindows, windowsJob},
		{"the default deadline and make test's timeout", guardDeadlineOther, makeTest},
		{"the default deadline and the other jobs' timeout", guardDeadlineOther, otherJobs},
		{"the default deadline and make cover's timeout", guardDeadlineOther, makeCover},
	} {
		if c.deadline+restOfPackage > c.timeout {
			t.Errorf("%s: %v plus %v for the rest of the package is over %v", c.what, c.deadline, restOfPackage, c.timeout)
		}
	}
}

// The deadline fires, with a message that names the guard and the clock step, on a
// coarse clock and a deadline too short for it; and it does not fire on the real clock
// with the deadline the guard has. A deadline that never fired would be no deadline, and
// one that fired on a healthy run would fail the gate.
func TestGrowthGuardFailsAtItsDeadlineAndNamesTheClock(t *testing.T) {
	fc := &fakeClock{step: 15625 * time.Microsecond}
	if g, err := growthOn(fc.reading(), withinOn(fc.exact(), 50*time.Millisecond), fc.work(linearCost), scaleN, scaleFactor); err == nil {
		t.Errorf("growth = %.1f on a 15.6 ms clock past a 50 ms deadline, want the deadline's error", g)
	} else if msg := err.Error(); !strings.Contains(msg, "growth guard (TestMaskingScalesLinearly)") || !strings.Contains(msg, "deadline") || !strings.Contains(msg, "15.625ms") {
		t.Errorf("the deadline's message does not name the guard and the clock step: %q", msg)
	}
	work := func(n int) func() {
		src := strings.Repeat("abcd", n/4)
		return func() {
			var h uint64
			for i := range len(src) {
				h = h*31 + uint64(src[i])
			}
			sink = h
		}
	}
	start := time.Now()
	// Only that the deadline does not fire is asserted here: the reading itself is noise on a
	// real clock, and a bound on it would be a test that fails at random.
	if g, err := growth(within(guardDeadline), work, scaleN, scaleFactor); err != nil {
		t.Errorf("growth = %.1f, %v on the real clock with the guard's own deadline, want a reading and no error", g, err)
	}
	if took := time.Since(start); took > guardDeadline/10 {
		t.Errorf("one row took %v on the real clock, a tenth of the deadline", took)
	}
}

// The first pair, 16 KiB and 128 KiB, cannot see a quadratic term that costs less than the
// linear work up to 128 KiB. Cost n + n*n/131072 ns is 14.2 times as much at 128 KiB as at
// 16 KiB, under the limit, and 36 times as much at 1 MiB as at 128 KiB, over it. The rows of
// pastFirstPair are timed from both sizes, and this holds the second pair to the limit.
func TestGrowthSeesAQuadraticTermThatOnlyDominatesPastTheFirstPair(t *testing.T) {
	cost := func(n int) time.Duration { return time.Duration(n) + time.Duration(n)*time.Duration(n)/131072 }
	const row = "MaskEmails at signs"
	if sizes, want := rowSizes(row), []int{scaleN, scaleN2}; !slices.Equal(sizes, want) {
		t.Fatalf("rowSizes(%q) = %v, want %v", row, sizes, want)
	}
	fc := &fakeClock{step: time.Nanosecond}
	reads, err := readRow(fc.reading(), withinOn(fc.exact(), time.Minute), row, fc.work(cost))
	if err != nil {
		t.Fatal(err)
	}
	if len(reads) != 2 || reads[0].n != scaleN || reads[1].n != scaleN2 {
		t.Fatalf("readRow(%q) = %+v, want one read from %d and one from %d", row, reads, scaleN, scaleN2)
	}
	if reads[0].best >= maxGrowth || reads[1].best <= maxGrowth {
		t.Errorf("growth from %d KiB reads %.1f and from %d KiB reads %.1f, want one under %d and one over it", scaleN>>10, reads[0].best, scaleN2>>10, reads[1].best, maxGrowth)
	}
	fc = &fakeClock{step: time.Nanosecond}
	if got, err := readRow(fc.reading(), withinOn(fc.exact(), time.Minute), "MaskEmails dots", fc.work(cost)); err != nil || len(got) != 1 || got[0].n != scaleN {
		t.Errorf("a row outside pastFirstPair read %+v (error %v), want exactly one read, from %d", got, err, scaleN)
	}
}

// A row that reads over the limit on the first pair is not timed on the second: that pair
// costs eight times as much per run, and the deadline is checked only between batches.
func TestARowThatFailsItsFirstPairIsNotTimedOnTheSecond(t *testing.T) {
	cost := func(n int) time.Duration { return time.Duration(n) * time.Duration(n) / 1024 }
	const row = "MaskEmails at signs"
	fc := &fakeClock{step: time.Nanosecond}
	reads, err := readRow(fc.reading(), withinOn(fc.exact(), time.Minute), row, fc.work(cost))
	if err != nil {
		t.Fatal(err)
	}
	if len(reads) != 1 || reads[0].n != scaleN || reads[0].best <= maxGrowth {
		t.Fatalf("readRow(%q) = %+v, want exactly one read, from %d KiB, over %d", row, reads, scaleN>>10, maxGrowth)
	}
}

// A name in pastFirstPair that is no row of the guard (a row renamed, a typo) would lose its
// second size without a word.
func TestEveryRowPastTheFirstPairIsARowOfTheGuard(t *testing.T) {
	cases := scalingCases(t)
	for _, name := range pastFirstPair {
		if cases[name] == nil {
			t.Errorf("pastFirstPair names %q, which is no row of the guard", name)
		}
	}
	if len(pastFirstPair) < 12 {
		t.Errorf("pastFirstPair has %d rows, want at least 12", len(pastFirstPair))
	}
}
