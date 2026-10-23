package api

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// tailkeeper limits the validation requests it sends to Tailscale: a bucket of tokens
// (acl.validatePerMinute a minute), a deadline for each call of a tool and at most two
// calls in flight. The tokens count the requests tailkeeper decides to send, one for each
// policy of a call; a retry of a request that failed takes none, so a failing upstream
// sees up to four POSTs for each token, within the call's deadline. Tailscale's own limit
// is unpublished and per credential; this one protects an MCP session from a prompt that
// asks for a hundred validations, and four calls of 1 MiB cannot hold the server for
// minutes. It lives in the client, so every path that sends the validate POST goes
// through it, and a call that retries draws nothing more.

const (
	defaultValidateDeadline = 60 * time.Second
	defaultValidateInFlight = 2
	maxRetryAfterSeconds    = int(maxRetryAfter / time.Second) // the longest retryAfterSeconds an error reports: the 24 hours that RetryAfter is cut to
	minBucketSize           = 2                                // the fewest tokens a bucket holds: see newBucket
)

// tokenUnits is how many units of the bucket make a token: a minute of nanoseconds. A
// bucket of rate tokens a minute then gains rate units for each nanosecond that passes,
// and the arithmetic stays in integers, so a wait is exact and a rounding cannot
// leave the bucket one unit short when the error said to come back.
const tokenUnits = int64(time.Minute)

// bucket is a token bucket that refills continuously.
type bucket struct {
	mu    sync.Mutex
	rate  int64         // tokens a minute
	size  int64         // tokens it holds at most: rate, and never fewer than minBucketSize
	fill  time.Duration // how long an empty bucket takes to fill
	units int64         // what the bucket holds, in units of 1/tokenUnits of a token
	last  time.Time
	now   func() time.Time
}

// newBucket makes a full bucket that refills at rate tokens a minute (rate is at least 1)
// and holds at least two tokens. A call with invariants takes two tokens at once, and
// acl.validatePerMinute may be 1: a bucket of one token could never grant that call, and
// the error would tell its caller to wait for ever. At a rate of 1 the bucket therefore
// starts with two tokens and refills one a minute.
func newBucket(rate int, now func() time.Time) *bucket {
	size := max(int64(rate), minBucketSize)
	return &bucket{rate: int64(rate), size: size, fill: time.Duration(size * tokenUnits / int64(rate)), units: size * tokenUnits, last: now(), now: now}
}

// refill adds what has accrued since the last look. Time that goes backwards accrues
// nothing, and the bucket restarts from the earlier time. The caller holds mu.
func (b *bucket) refill() {
	t := b.now()
	if d := t.Sub(b.last); d > 0 {
		// Longer than it takes to fill an empty bucket is not counted: nothing overflows.
		b.units = min(b.units+int64(min(d, b.fill))*b.rate, b.size*tokenUnits)
	}
	b.last = t
}

// take removes n tokens at once, or none. When fewer are held it says how long until n
// are.
func (b *bucket) take(n int) (taken bool, wait time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill()
	need := int64(n) * tokenUnits
	if b.units >= need {
		b.units -= need
		return true, 0
	}
	return false, time.Duration((need - b.units + b.rate - 1) / b.rate)
}

// give returns n tokens, never above the size of the bucket.
func (b *bucket) give(n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.units = min(b.units+int64(n)*tokenUnits, b.size*tokenUnits)
}

// validateGate is what the copies of one Client share: the bucket, the slots for calls in
// flight and the deadline of a call. Client holds a pointer to it, so WithMaxBody's copy
// of the struct draws from the same bucket.
type validateGate struct {
	bucket   *bucket
	slots    chan struct{}
	deadline time.Duration
	rate     int
}

func newValidateGate(opt Options) *validateGate {
	rate := opt.ValidatePerMinute
	if rate <= 0 {
		rate = config.DefaultValidatePerMinute
	}
	now := opt.Now
	if now == nil {
		now = time.Now
	}
	deadline := opt.ValidateDeadline
	if deadline <= 0 {
		deadline = defaultValidateDeadline
	}
	inFlight := opt.ValidateInFlight
	if inFlight <= 0 {
		inFlight = defaultValidateInFlight
	}
	return &validateGate{bucket: newBucket(rate, now), slots: make(chan struct{}, inFlight), deadline: deadline, rate: rate}
}

// ValidateCall is one tool call's use of the validate endpoint: the tokens it reserved,
// its deadline and its slot among the calls in flight. One goroutine uses it. It must be
// ended.
type ValidateCall struct {
	c      *Client
	parent context.Context
	ctx    context.Context
	cancel context.CancelFunc
	posts  int
	used   int
	ended  sync.Once
}

// BeginValidate starts a call that will send posts policies (1, or 2 for a call with
// invariants). It waits for a free slot (or for ctx), then takes posts tokens at once or
// none: when fewer are left it frees the slot and returns validate_rate_limited, whose
// retryAfterSeconds is the whole seconds, rounded up, until posts tokens exist. A call
// that ends having sent fewer gets the rest back.
func (c *Client) BeginValidate(ctx context.Context, posts int) (*ValidateCall, error) {
	return c.beginValidate(ctx, posts, posts)
}

// BeginValidateCharged is BeginValidate for a call that sends posts policies and is charged
// tokens in all, tokens being at least posts. The tokens beyond the posts pay for what the
// call asks of Tailscale besides sending: they are taken with the rest, at once or not at
// all, and End does not give them back. A call that asks for more tokens than the bucket
// holds can never be granted: it is refused at once, with an error that says so and not one
// that tells its caller to wait.
func (c *Client) BeginValidateCharged(ctx context.Context, posts, tokens int) (*ValidateCall, error) {
	if tokens < posts {
		return nil, tkerr.New(tkerr.Internal, fmt.Sprintf("a validate call is charged %d tokens for %d policies", tokens, posts), "this is a tailkeeper bug; report it")
	}
	return c.beginValidate(ctx, posts, tokens)
}

func (c *Client) beginValidate(ctx context.Context, posts, tokens int) (*ValidateCall, error) {
	if posts < 1 || posts > 2 {
		return nil, tkerr.New(tkerr.Internal, fmt.Sprintf("a validate call sends one or two policies, not %d", posts), "this is a tailkeeper bug; report it")
	}
	g := c.gate
	if int64(tokens) > g.bucket.size {
		return nil, validateTooWide(g.rate, tokens, int(g.bucket.size))
	}
	if err := ctx.Err(); err != nil {
		return nil, tkerr.Wrap(tkerr.APIError, err, "request cancelled", "")
	}
	select {
	case g.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, tkerr.Wrap(tkerr.APIError, ctx.Err(), "request cancelled", "")
	}
	if taken, wait := g.bucket.take(tokens); !taken {
		<-g.slots
		return nil, validateRateLimited(g.rate, wait)
	}
	dctx, cancel := context.WithTimeout(ctx, g.deadline)
	return &ValidateCall{c: c, parent: ctx, ctx: dctx, cancel: cancel, posts: posts}, nil
}

// validateTooWide is the error for a call that is charged more tokens than the bucket holds.
// No wait helps, so there is no retryAfterSeconds.
func validateTooWide(rate, tokens, size int) error {
	return tkerr.New(tkerr.ValidateRateLimited,
		fmt.Sprintf("this call is charged %d validation requests, and tailkeeper's own limit (acl.validatePerMinute: %d a minute) lets a call take at most %d at once, so waiting will not help", tokens, rate, size),
		"give fewer SSH users in the call, or raise acl.validatePerMinute (1 to 120) in the configuration")
}

// validateRateLimited is the error for an empty bucket. The message names the wait as
// well as the field does: the text a command prints and the text an MCP host shows carry
// the message and the hint, not the field, and the hint says to wait.
func validateRateLimited(rate int, wait time.Duration) error {
	secs := wholeSeconds(wait)
	unit := "validation requests"
	if rate == 1 {
		unit = "validation request"
	}
	e := tkerr.New(tkerr.ValidateRateLimited,
		fmt.Sprintf("tailkeeper's own limit of %d %s a minute (acl.validatePerMinute: it counts the requests tailkeeper decides to send, and retries of a request take no token) is used up; try again in %d s", rate, unit, secs),
		"wait the retryAfterSeconds this error carries and run the call again; raise acl.validatePerMinute (1 to 120) in the configuration if the limit is too low for your use")
	e.RetryAfterSeconds = secs
	return e
}

// wholeSeconds rounds a wait up to whole seconds, at most maxRetryAfterSeconds. A wait of
// nothing is 0: a 429 with "Retry-After: 0" reports no seconds. The wait of an empty bucket
// is never 0, because there is a token to wait for.
func wholeSeconds(d time.Duration) int {
	secs := int((d + time.Second - 1) / time.Second)
	return min(secs, maxRetryAfterSeconds)
}

// Context is the context of the call: the caller's, with the call's deadline.
func (v *ValidateCall) Context() context.Context { return v.ctx }

// Send validates a policy in policy mode. Each Send uses one of the tokens the call
// reserved; the retries inside it use none. A send past the call's deadline fails with
// upstream_unavailable.
func (v *ValidateCall) Send(body []byte) (PolicyValidation, error) {
	if err := v.spend(); err != nil {
		return PolicyValidation{}, err
	}
	pv, err := v.c.validatePolicy(v.ctx, body)
	return pv, v.deadlineError(err)
}

// spend marks one of the reserved tokens as used: End gives back only the others.
func (v *ValidateCall) spend() error {
	if v.used >= v.posts {
		return tkerr.New(tkerr.Internal, "a validate call sent more policies than it reserved tokens for", "this is a tailkeeper bug; report it")
	}
	v.used++
	return nil
}

// deadlineError names the deadline when it, and not the caller, ended the call.
func (v *ValidateCall) deadlineError(err error) error {
	if err == nil || !errors.Is(v.ctx.Err(), context.DeadlineExceeded) || v.parent.Err() != nil {
		return err
	}
	d := v.c.gate.deadline
	text := d.String()
	if d%time.Second == 0 {
		text = fmt.Sprintf("%d s", d/time.Second)
	}
	return tkerr.Wrap(tkerr.UpstreamUnavailable, err, "the validate call ran past its "+text+" deadline",
		"Tailscale answered too slowly; wait a few seconds and retry once, and report it to the owner if it persists")
}

// End frees the call's slot, stops its deadline and gives back the tokens it did not use.
// It may be called more than once.
func (v *ValidateCall) End() {
	v.ended.Do(func() {
		v.cancel()
		if unused := v.posts - v.used; unused > 0 {
			v.c.gate.bucket.give(unused)
		}
		<-v.c.gate.slots
	})
}
