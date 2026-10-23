package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// clock is the bucket's time in these tests: it moves when a test moves it.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// spend begins a call of n posts, sends k policies, ends it, and reports the error of the
// beginning, if any: it is how a test uses tokens up.
func spend(c *api.Client, n, k int) error {
	call, err := c.BeginValidate(context.Background(), n)
	if err != nil {
		return err
	}
	defer call.End()
	for i := 0; i < k; i++ {
		if _, err := call.Send([]byte(emptyPolicy)); err != nil {
			return err
		}
	}
	return nil
}

// limited says whether err is tailkeeper's own validation limit.
func limited(err error) bool {
	e, ok := tkerr.As(err)
	return ok && e.Code == tkerr.ValidateRateLimited
}

// passingFake answers every validate POST with the pass of policy mode.
func passingFake(t *testing.T) *apitest.Fake {
	t.Helper()
	f := apitest.New(t)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	return f
}

func TestTheBucketGrantsTheRateAndRefillsOnAFakeClock(t *testing.T) {
	f := passingFake(t)
	clk := newClock()
	c := newClient(t, f, api.Options{Now: clk.now})
	for i := 0; i < 30; i++ {
		if err := spend(c, 1, 1); err != nil {
			t.Fatalf("call %d of the 30 a minute: %v", i+1, err)
		}
	}
	if err := spend(c, 1, 1); !limited(err) {
		t.Fatalf("the 31st: err = %v, want validate_rate_limited", err)
	}
	// 30 a minute is one every 2 s.
	clk.advance(2 * time.Second)
	if err := spend(c, 1, 1); err != nil {
		t.Fatalf("after 2 s: %v", err)
	}
	if err := spend(c, 1, 1); !limited(err) {
		t.Fatalf("a second one after 2 s: err = %v, want validate_rate_limited", err)
	}
	if n := len(f.Requests()); n != 31 {
		t.Errorf("%d requests, want 31: the refused calls sent nothing", n)
	}
}

// After any idle, however long, the bucket holds its size and no more: a refill is bounded
// by the time an empty bucket takes to fill, so that the product of the time and the rate
// stays inside an int64 (about 2.4 years at 120 a minute; a Duration reaches 292 years),
// and by the size of the bucket. Without the bound on time the product wraps and the bucket
// is refused for ever, or grants some other number; without the bound on size it grants more
// than it holds.
func TestAfterALongIdleTheBucketHoldsItsSizeAndNoMore(t *testing.T) {
	const longIdle = 290 * 365 * 24 * time.Hour
	for _, rate := range []int{1, 2, 7, 30, 120} {
		size := max(rate, 2)
		for name, spent := range map[string]int{"a bucket that was drained": size, "a bucket that was used once": 1} {
			f := passingFake(t)
			clk := newClock()
			c := newClient(t, f, api.Options{Now: clk.now, ValidatePerMinute: rate})
			for i := 0; i < spent; i++ {
				if err := spend(c, 1, 1); err != nil {
					t.Fatalf("rate %d, %s, call %d: %v", rate, name, i+1, err)
				}
			}
			clk.advance(longIdle)
			granted := 0
			for granted < 3*size && spend(c, 1, 1) == nil {
				granted++
			}
			if granted != size {
				t.Errorf("rate %d, %s, after %v idle: granted %d calls, want exactly %d", rate, name, longIdle, granted, size)
			}
		}
	}
}

func TestAnExhaustedBucketIsValidateRateLimitedWithRetryAfterSeconds(t *testing.T) {
	f := passingFake(t)
	clk := newClock()
	c := newClient(t, f, api.Options{Now: clk.now, ValidatePerMinute: 1})
	// A bucket holds at least two tokens, whatever the rate: two sends empty it.
	for i := 0; i < 2; i++ {
		if err := spend(c, 1, 1); err != nil {
			t.Fatal(err)
		}
	}
	for _, step := range []struct {
		advance time.Duration
		want    int
	}{
		{0, 60},
		{500 * time.Millisecond, 60}, // 59.5 s left, rounded up
		{59 * time.Second, 1},        // 0.5 s left: never 0, which would read as "now"
	} {
		clk.advance(step.advance)
		err := spend(c, 1, 1)
		e, ok := tkerr.As(err)
		if !ok || e.Code != tkerr.ValidateRateLimited || e.RetryAfterSeconds != step.want || tkerr.ExitCode(err) != 1 {
			t.Fatalf("after %v: err = %#v, want validate_rate_limited, exit 1, retryAfterSeconds %d", step.advance, err, step.want)
		}
		b, _ := json.Marshal(e)
		if !strings.Contains(string(b), `"retryAfterSeconds":`+strconv.Itoa(step.want)) {
			t.Errorf("JSON = %s", b)
		}
		if !strings.Contains(e.Hint, "acl.validatePerMinute") || !strings.Contains(e.Message, "limit of 1 validation request a minute (") {
			t.Errorf("message %q, hint %q", e.Message, e.Hint)
		}
		// The limit counts the requests tailkeeper decides to send, and says so, with the
		// retries that take no token.
		if !strings.Contains(e.Message, "counts the requests tailkeeper decides to send") || !strings.Contains(e.Message, "retries of a request take no token") {
			t.Errorf("message %q does not say what the limit counts", e.Message)
		}
		// The text surfaces print the message and not the field, so the message names the wait.
		if want := "is used up; try again in " + strconv.Itoa(step.want) + " s"; !strings.HasSuffix(e.Message, want) {
			t.Errorf("message %q, want it to end with %q", e.Message, want)
		}
	}
	// Waiting as long as the error said is enough.
	clk.advance(time.Second)
	if err := spend(c, 1, 1); err != nil {
		t.Errorf("after the wait the error named: %v", err)
	}
}

// A call with invariants takes two tokens at once, and acl.validatePerMinute may be 1: a
// bucket of one token could never grant it, and the error would send the caller to wait
// for ever. The bucket holds two tokens at a rate of 1, refills one a minute, and a call of
// two that finds one is told the true wait for the second.
func TestAtOneAMinuteATwoTokenCallWaitsForItsSecondToken(t *testing.T) {
	f := passingFake(t)
	clk := newClock()
	c := newClient(t, f, api.Options{Now: clk.now, ValidatePerMinute: 1})
	whole, err := c.BeginValidate(context.Background(), 2)
	if err != nil {
		t.Fatalf("a call of two on a fresh bucket at 1 a minute: %v", err)
	}
	whole.End() // nothing was sent: both tokens come back
	if err := spend(c, 1, 1); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		advance time.Duration
		want    int
	}{
		{0, 60},                // one token left, and the second is a minute away
		{30 * time.Second, 30}, // half of it gone
		{29 * time.Second, 1},  // one second to go
	} {
		clk.advance(step.advance)
		_, err := c.BeginValidate(context.Background(), 2)
		if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ValidateRateLimited || e.RetryAfterSeconds != step.want {
			t.Fatalf("after %v: err = %#v, want validate_rate_limited with retryAfterSeconds %d", step.advance, err, step.want)
		} else if want := "; try again in " + strconv.Itoa(step.want) + " s"; !strings.HasSuffix(e.Message, want) {
			t.Errorf("after %v: message %q, want it to end with %q", step.advance, e.Message, want)
		}
	}
	clk.advance(time.Second) // the wait the last error named
	call, err := c.BeginValidate(context.Background(), 2)
	if err != nil {
		t.Fatalf("after waiting as long as the error said: %v", err)
	}
	call.End()
	// However long it rests, the bucket holds two and no more.
	clk.advance(time.Hour)
	for i := 0; i < 2; i++ {
		if err := spend(c, 1, 1); err != nil {
			t.Fatalf("token %d after an hour: %v", i+1, err)
		}
	}
	if err := spend(c, 1, 1); !limited(err) {
		t.Errorf("a third token after an hour: %v, want the limit: the bucket holds two", err)
	}
}

// A retry is the same send again: it takes no token.
func TestRetriesDrawNoToken(t *testing.T) {
	f := apitest.New(t)
	answers(f, apitest.PolicyServerError500(), apitest.TestsPassEmptyObject())
	clk := newClock()
	c := newClient(t, f, api.Options{Now: clk.now, ValidatePerMinute: 2})
	if err := spend(c, 1, 1); err != nil {
		t.Fatal(err)
	}
	if n := len(f.Requests()); n != 2 {
		t.Fatalf("%d requests, want the send and its retry", n)
	}
	if err := spend(c, 1, 1); err != nil {
		t.Fatalf("the second call: %v: the retry drew a token", err)
	}
	if err := spend(c, 1, 1); !limited(err) {
		t.Errorf("the third call: %v, want the limit of 2", err)
	}
}

func TestAnInvariantsCallTakesTwoTokensAtOnce(t *testing.T) {
	f := passingFake(t)
	clk := newClock()
	c := newClient(t, f, api.Options{Now: clk.now, ValidatePerMinute: 3})
	first, err := c.BeginValidate(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	defer first.End()
	// One token is left: a second call of two fails and takes nothing.
	if _, err := c.BeginValidate(context.Background(), 2); !limited(err) {
		t.Fatalf("a call of 2 with one token left: %v", err)
	}
	if err := spend(c, 1, 1); err != nil {
		t.Errorf("the one token that was left: %v", err)
	}
}

func TestUnspentTokensAreRefunded(t *testing.T) {
	f := passingFake(t)
	clk := newClock()
	c := newClient(t, f, api.Options{Now: clk.now, ValidatePerMinute: 3})
	call, err := c.BeginValidate(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := call.Send([]byte(emptyPolicy)); err != nil {
		t.Fatal(err)
	}
	call.End()
	call.End() // ending twice refunds once
	// 3 - 2 + 1 refunded = 2 tokens.
	for i := 0; i < 2; i++ {
		if err := spend(c, 1, 1); err != nil {
			t.Fatalf("token %d after the refund: %v", i+1, err)
		}
	}
	if err := spend(c, 1, 1); !limited(err) {
		t.Errorf("a third token: %v, want the limit: the refund came twice", err)
	}
}

func TestARefundNeverMakesTheBucketBiggerThanItsSize(t *testing.T) {
	f := passingFake(t)
	clk := newClock()
	c := newClient(t, f, api.Options{Now: clk.now, ValidatePerMinute: 2})
	a, err := c.BeginValidate(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	clk.advance(time.Minute) // the bucket is full again, and the next look at the clock sees it
	b, err := c.BeginValidate(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	b.End() // gives its token back to a full bucket
	a.End() // gives back a token that the refill has already replaced
	for i := 0; i < 2; i++ {
		if err := spend(c, 1, 1); err != nil {
			t.Fatalf("token %d: %v", i+1, err)
		}
	}
	if err := spend(c, 1, 1); !limited(err) {
		t.Errorf("a third token: %v, want the limit of 2", err)
	}
}

func TestAClockThatGoesBackDoesNotMintTokens(t *testing.T) {
	f := passingFake(t)
	clk := newClock()
	c := newClient(t, f, api.Options{Now: clk.now, ValidatePerMinute: 1})
	for i := 0; i < 2; i++ { // the bucket holds two
		if err := spend(c, 1, 1); err != nil {
			t.Fatal(err)
		}
	}
	clk.advance(-time.Hour)
	if err := spend(c, 1, 1); !limited(err) {
		t.Fatalf("after the clock went back: %v", err)
	}
	clk.advance(time.Minute)
	if err := spend(c, 1, 1); err != nil {
		t.Errorf("a minute after the new time: %v", err)
	}
}

// A copy of the struct that held the bucket by value would pass every other test here.
func TestTheBucketIsSharedByCopiesOfTheClient(t *testing.T) {
	f := passingFake(t)
	clk := newClock()
	c := newClient(t, f, api.Options{Now: clk.now, ValidatePerMinute: 1})
	for i := 0; i < 2; i++ { // the bucket holds two
		if err := spend(c.WithMaxBody(1<<20), 1, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := spend(c, 1, 1); !limited(err) {
		t.Errorf("the original after the copy used the tokens: %v", err)
	}
}

func TestAtMostTwoValidateCallsRunAtOnce(t *testing.T) {
	f := passingFake(t)
	c := f.Client(t)
	a, err := c.BeginValidate(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.BeginValidate(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer b.End()

	// A third waits, and gives up when its context ends.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.BeginValidate(ctx, 1); tkerr.From(err).Code != tkerr.APIError || !strings.Contains(err.Error(), "request cancelled") {
		t.Errorf("a third call with a context that ends: %v", err)
	}

	// A third waits, and goes on when a slot is freed.
	started := make(chan error, 1)
	go func() {
		third, err := c.BeginValidate(context.Background(), 1)
		if err == nil {
			third.End()
		}
		started <- err
	}()
	select {
	case err := <-started:
		t.Fatalf("a third call began while two were running: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	a.End()
	select {
	case err := <-started:
		if err != nil {
			t.Errorf("the waiting call: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting call did not begin after a slot was freed")
	}
}

func TestARefusedBeginHoldsNoSlot(t *testing.T) {
	f := passingFake(t)
	clk := newClock()
	c := newClient(t, f, api.Options{Now: clk.now, ValidatePerMinute: 1, ValidateInFlight: 1})
	for i := 0; i < 2; i++ { // the bucket holds two
		if err := spend(c, 1, 1); err != nil {
			t.Fatal(err)
		}
	}
	// Limited calls must not hold the only slot.
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := c.BeginValidate(ctx, 1)
		cancel()
		if !limited(err) {
			t.Fatalf("attempt %d: %v, want the limit and not a wait for the slot", i+1, err)
		}
	}
	for _, n := range []int{0, 3} {
		if _, err := c.BeginValidate(context.Background(), n); tkerr.From(err).Code != tkerr.Internal {
			t.Errorf("a call of %d posts: %v, want internal_error", n, err)
		}
	}
	clk.advance(time.Minute)
	if err := spend(c, 1, 1); err != nil {
		t.Errorf("after a minute: %v", err)
	}
}

func TestASendPastTheReservedTokensIsRefused(t *testing.T) {
	f := passingFake(t)
	c := f.Client(t)
	call, err := c.BeginValidate(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer call.End()
	if _, err := call.Send([]byte(emptyPolicy)); err != nil {
		t.Fatal(err)
	}
	if _, err := call.Send([]byte(emptyPolicy)); tkerr.From(err).Code != tkerr.Internal {
		t.Errorf("a second send on one token: %v", err)
	}
	if n := len(f.Requests()); n != 1 {
		t.Errorf("%d requests, want 1", n)
	}
}

func TestAValidateCallEndsAtItsDeadline(t *testing.T) {
	f := apitest.New(t)
	f.Handle("POST", apitest.ValidatePath, func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	// Without the deadline the send would end at the one second of the request, as a transport error.
	c := newClient(t, f, api.Options{ValidateDeadline: 50 * time.Millisecond, Timeout: time.Second, Retries: -1})
	call, err := c.BeginValidate(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer call.End()
	start := time.Now()
	_, err = call.Send([]byte(emptyPolicy))
	e, ok := tkerr.As(err)
	if !ok || e.Code != tkerr.UpstreamUnavailable || !strings.Contains(e.Message, "ran past its 50ms deadline") {
		t.Fatalf("err = %#v, want upstream_unavailable naming the deadline", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("the send took %v: the deadline did not end it", d)
	}
}

// The caller giving up is not the deadline.
func TestACallerThatGivesUpIsNotTheDeadline(t *testing.T) {
	f := apitest.New(t)
	f.Handle("POST", apitest.ValidatePath, func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	c := newClient(t, f, api.Options{Timeout: 30 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	call, err := c.BeginValidate(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer call.End()
	time.AfterFunc(50*time.Millisecond, cancel)
	_, err = call.Send([]byte(emptyPolicy))
	if e := tkerr.From(err); e.Code != tkerr.APIError || e.Message != "request cancelled" {
		t.Errorf("err = %#v, want api_error \"request cancelled\"", err)
	}
}

func TestTheDefaultDeadlineOfACallIsSixtySeconds(t *testing.T) {
	c := passingFake(t).Client(t)
	call, err := c.BeginValidate(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer call.End()
	if dl, ok := call.Context().Deadline(); !ok || time.Until(dl) > time.Minute || time.Until(dl) < 55*time.Second {
		t.Errorf("deadline = %v, %v, want a minute from now", dl, ok)
	}
}

// tests mode is metered too: the one other path that sends the validate POST has no way round.
func TestValidateTestsDrawsOneToken(t *testing.T) {
	f := apitest.New(t)
	f.ServeValidate(apitest.TestsPass())
	clk := newClock()
	c := newClient(t, f, api.Options{Now: clk.now, ValidatePerMinute: 2})
	tests := []api.PolicyTest{{Src: "tag:p", Accept: []string{"tag:p:22"}}}
	for i := 0; i < 2; i++ {
		if res, err := c.ValidateTests(context.Background(), tests); err != nil || !res.Passed {
			t.Fatalf("call %d: %+v, %v", i+1, res, err)
		}
	}
	_, err := c.ValidateTests(context.Background(), tests)
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ValidateRateLimited || e.RetryAfterSeconds != 30 {
		t.Errorf("the third call: %#v, want validate_rate_limited after 30 s", err)
	}
	if n := len(f.Requests()); n != 2 {
		t.Errorf("%d requests, want 2", n)
	}
}

// Tailscale's own 429 keeps its code and gains the wait it asked for, in whole seconds.
func TestA429CarriesItsRetryAfterAsSeconds(t *testing.T) {
	for _, c := range []struct {
		name, header string
		status, want int
	}{
		{"seconds", "7", 429, 7},
		{"a huge count", "9300000000", 429, maxSeconds},
		{"more digits than an int holds", "99999999999999999999", 429, maxSeconds},
		{"zero", "0", 429, 0},
		{"no header", "", 429, 0},
		{"a 503 is not a rate limit", "7", 503, 0},
	} {
		f := apitest.New(t)
		f.Handle("GET", devicesPath, func(w http.ResponseWriter, _ *http.Request) {
			if c.header != "" {
				w.Header().Set("Retry-After", c.header)
			}
			w.WriteHeader(c.status)
		})
		cl := newClient(t, f, api.Options{Retries: -1})
		err := cl.Get(context.Background(), cl.TailnetPath("/devices"), nil, &devicesResp{})
		if e := tkerr.From(err); e.RetryAfterSeconds != c.want {
			t.Errorf("%s: retryAfterSeconds = %d, want %d (%v)", c.name, e.RetryAfterSeconds, c.want, err)
		}
	}
}

// maxSeconds is the longest wait an error reports: a day, the 24 hours that RetryAfter is
// cut to.
const maxSeconds = 86400

func TestTheBucketIsRaceFree(t *testing.T) {
	f := passingFake(t)
	c := newClient(t, f, api.Options{ValidatePerMinute: 120})
	var wg sync.WaitGroup
	var granted, refused atomic.Int32
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch err := spend(c.WithMaxBody(1<<20), 1, 1); {
			case err == nil:
				granted.Add(1)
			case limited(err):
				refused.Add(1)
			default:
				t.Errorf("err = %v", err)
			}
		}()
	}
	wg.Wait()
	if granted.Load()+refused.Load() != 64 || granted.Load() < 64 {
		t.Errorf("granted %d, refused %d of 64 calls on a bucket of 120", granted.Load(), refused.Load())
	}
}

// A charged call takes all its tokens at once and gives back none of the extra ones.
func TestAChargedCallTakesItsTokensAtOnceAndRefundsOnlyWhatItDidNotSend(t *testing.T) {
	f := passingFake(t)
	clk := newClock()
	c := newClient(t, f, api.Options{Now: clk.now, ValidatePerMinute: 5})
	call, err := c.BeginValidateCharged(context.Background(), 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := call.Send([]byte(emptyPolicy)); err != nil {
		t.Fatal(err)
	}
	call.End()
	// 5 - 3 = 2 tokens, however the call ended.
	if _, err := c.BeginValidateCharged(context.Background(), 1, 3); !limited(err) {
		t.Fatalf("a call charged 3 with 2 left: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := spend(c, 1, 1); err != nil {
			t.Fatalf("token %d left after a call charged 3: %v", i+1, err)
		}
	}
	if err := spend(c, 1, 1); !limited(err) {
		t.Errorf("a third token: %v, want the limit", err)
	}

	// A charged call that sent nothing gets back the policy it did not send, not the charge.
	c = newClient(t, f, api.Options{Now: clk.now, ValidatePerMinute: 5})
	call, err = c.BeginValidateCharged(context.Background(), 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	call.End()
	for i := 0; i < 3; i++ {
		if err := spend(c, 1, 1); err != nil {
			t.Fatalf("token %d after a charged call that sent nothing: %v", i+1, err)
		}
	}
	if err := spend(c, 1, 1); !limited(err) {
		t.Errorf("a fourth token: %v: the charge came back", err)
	}
}

// A call charged more than the bucket holds can never be granted: the error says so, tells
// no one to wait, and holds no slot and no token.
func TestAChargedCallBiggerThanTheBucketIsRefusedAtOnceAndNamesTheCause(t *testing.T) {
	f := passingFake(t)
	clk := newClock()
	c := newClient(t, f, api.Options{Now: clk.now, ValidatePerMinute: 4})
	_, err := c.BeginValidateCharged(context.Background(), 1, 5)
	e, ok := tkerr.As(err)
	if !ok || e.Code != tkerr.ValidateRateLimited || e.RetryAfterSeconds != 0 || !strings.Contains(e.Message, "waiting will not help") {
		t.Fatalf("err = %v, want validate_rate_limited that says waiting will not help, with no retryAfterSeconds", err)
	}
	// A call is never charged fewer tokens than the policies it sends, and the bucket is full.
	if _, err := c.BeginValidateCharged(context.Background(), 2, 1); err == nil {
		t.Error("a call charged fewer tokens than it sends was accepted")
	}
	for i := 0; i < 4; i++ {
		if err := spend(c, 1, 1); err != nil {
			t.Fatalf("token %d: the refused calls took tokens or a slot: %v", i+1, err)
		}
	}
}
