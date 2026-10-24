// Package probe is the harness behind `make probe-acl`: the read-only live
// probes of the probe table (docs/design.md §22), each with its request and its expectation written down before
// any run, and a printer that shows what the real API said without showing a value
// from the tailnet.
//
// Everything a probe sends is a synthetic document (tag:p, example.com, documentation
// addresses) or a document built in memory from the live policy; everything it records
// goes through internal/skeleton, which keeps a status, key paths with types, error texts
// reduced to templates, and booleans and counts the probe computed. Nothing here sends
// anything but GET and POST .../acl/validate: the client's guard sees to that.
package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/skeleton"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// API is what the probes call; *api.Client satisfies it.
type API interface {
	TailnetPath(suffix string) string
	ValidatePolicy(ctx context.Context, body []byte, contentType string) (api.RawResponse, error)
	GetPolicy(ctx context.Context, g api.PolicyGet) (api.RawResponse, error)
	GetOnce(ctx context.Context, path string, q url.Values) (api.RawResponse, error)
}

// Probe is one row of the probe table. Expected and Branch are copied from the table before
// any run and printed beside what was observed.
type Probe struct {
	ID       string
	Title    string
	Sends    string
	Expected string
	Branch   string
	Run      func(ctx context.Context, x *Exec) error
}

// Step names one request of a probe: what it is, and what the probe table expects of it.
type Step struct {
	Label  string
	Expect string
}

// Check is an expectation the harness can test: the answer to a yes-or-no question the
// table's "Expected" column implies, as the table expects it (Want) and as the API behaved (Got).
type Check struct {
	Name string `json:"name"`
	Want bool   `json:"want"`
	Got  bool   `json:"got"`
}

// Matches reports whether the API behaved as the probe table expected.
func (c Check) Matches() bool { return c.Want == c.Got }

// Observation is one request and the skeleton of its answer.
type Observation struct {
	Label   string             `json:"label"`
	Expect  string             `json:"expect,omitempty"`
	Request string             `json:"request"`
	Result  *skeleton.Skeleton `json:"result,omitempty"`
	ETag    string             `json:"etag,omitempty"` // the form of the ETag header, never the value
	Error   string             `json:"error,omitempty"`
}

// Result is what one probe recorded.
type Result struct {
	ID           string          `json:"probe"`
	Title        string          `json:"title"`
	Sends        string          `json:"sends"`
	Expected     string          `json:"expected"`
	Branch       string          `json:"branch"`
	Observations []Observation   `json:"observations"`
	Checks       []Check         `json:"checks,omitempty"`
	Facts        map[string]bool `json:"facts,omitempty"`
	Counts       map[string]int  `json:"counts,omitempty"`
	Skipped      []string        `json:"skipped,omitempty"`
	Error        string          `json:"error,omitempty"`
	NotRun       bool            `json:"notRun,omitempty"`
}

// Errors that stop the whole run.
var (
	// ErrRateLimited means the API answered 429: no more requests are sent.
	ErrRateLimited = errors.New("the API answered 429, so the run stopped")
	// ErrBudget means the run reached its request ceiling.
	ErrBudget = errors.New("the request budget is spent, so the run stopped")
)

// DefaultBudget is the most requests one run sends when Options.Budget is not set. A full
// run sends 61 at most (A-10's fallback and three windows of the audit log); the ceiling
// is there to stop a probe that loops, not to be reached.
const DefaultBudget = 80

// Options tune a run. The zero value is a production run except for Gap.
type Options struct {
	Gap    time.Duration                              // pause before every request after the first; the CLI uses 2s
	Sleep  func(context.Context, time.Duration) error // default: a timer that honours ctx
	Budget int                                        // most requests in one run; default DefaultBudget
	Only   []string                                   // probe IDs to run; empty runs all
	Hex    func(n int) string                         // n random lower-case hex digits; default crypto/rand
	// OnStart, when set, is called with a probe's ID as the probe starts, before its first
	// request. A probe that is not run because the run stopped is not announced.
	OnStart func(id string)
	// Against is the directory of committed captures a self-check compares with.
	// Empty means the run is not a self-check.
	Against string
}

// Exec is what a probe runs against. It paces and counts requests, records every one,
// and holds the live policy in memory for the probes that need data from it.
type Exec struct {
	api     API
	o       Options
	sent    int
	stopped error
	res     *Result
	live    *Live
	liveErr error
	skOpts  skeleton.Options
	shapes  []Result // the shape probes of the last self-check, for --out
}

// Run runs the probes in order and returns one Result per probe selected, in order. A
// probe that fails (a transport error) is recorded and the next one runs; a 429, the
// request ceiling or a cancelled ctx stops the run, and the probes after that are marked
// NotRun.
// newExec applies the defaults a run and a self-check share.
func newExec(a API, o Options) *Exec {
	if o.Sleep == nil {
		o.Sleep = sleep
	}
	if o.Budget == 0 {
		o.Budget = DefaultBudget
	}
	if o.Hex == nil {
		o.Hex = randomHex
	}
	opts := skeleton.DefaultOptions()
	opts.TemplateText = true
	return &Exec{api: a, o: o, skOpts: opts}
}

func Run(ctx context.Context, a API, probes []Probe, o Options) []Result {
	x := newExec(a, o)
	var out []Result
	for _, p := range probes {
		if len(o.Only) > 0 && !contains(o.Only, p.ID) {
			continue
		}
		r := Result{ID: p.ID, Title: p.Title, Sends: p.Sends, Expected: p.Expected, Branch: p.Branch}
		if x.stopped != nil || ctx.Err() != nil {
			r.NotRun = true
			out = append(out, r)
			continue
		}
		x.res = &r
		if o.OnStart != nil {
			o.OnStart(p.ID)
		}
		if err := x.runOne(ctx, p); err != nil {
			r.Error = errorCode(err)
		}
		if x.stopped != nil {
			r.Error = errorCode(x.stopped) // the sentinel wins over a later generic code
		}
		out = append(out, r)
	}
	return out
}

// errPanic is the error runOne returns for a probe that panicked; the panic value is
// dropped, because it could quote anything.
var errPanic = errors.New("the probe panicked")

// runOne runs one probe and turns a panic inside it into an error, so the next probe still runs.
func (x *Exec) runOne(ctx context.Context, p Probe) (err error) {
	defer func() {
		if recover() != nil {
			err = errPanic
		}
	}()
	return p.Run(ctx, x)
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// errorCode names a failure without quoting it: the run's own sentinels, a tkerr code, or "error".
func errorCode(err error) string {
	switch {
	case errors.Is(err, errPanic):
		return "panic"
	case errors.Is(err, ErrRateLimited):
		return "rate_limited"
	case errors.Is(err, ErrBudget):
		return "request_budget"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "cancelled"
	}
	if e, ok := tkerr.As(err); ok {
		return string(e.Code)
	}
	return "error"
}

// Seen is one answer, in memory: the status, the ETag and the body as sent. It is for the
// probe to compute booleans and counts from; none of it is printed.
type Seen struct {
	Status int
	ETag   string
	Body   []byte
	sk     skeleton.Skeleton
}

// pace waits before every request after the first, and refuses once the run has stopped.
func (x *Exec) pace(ctx context.Context) error {
	if x.stopped != nil {
		return x.stopped
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if x.sent >= x.o.Budget {
		x.stopped = ErrBudget
		return x.stopped
	}
	if x.sent > 0 {
		if err := x.o.Sleep(ctx, x.o.Gap); err != nil {
			return err
		}
	}
	x.sent++
	return nil
}

// record stores the observation of a request and returns what the probe may look at. The
// form of the ETag header is recorded for a read of the policy, where it matters, and not
// for a POST.
func (x *Exec) record(s Step, request string, raw api.RawResponse, err error, withETag bool) (Seen, error) {
	ob := Observation{Label: s.Label, Expect: s.Expect, Request: request}
	if err != nil {
		ob.Error = errorCode(err)
		x.res.Observations = append(x.res.Observations, ob)
		return Seen{}, err
	}
	sk := skeleton.Of(raw.Status, raw.Body, x.skOpts)
	ob.Result = &sk
	if withETag {
		ob.ETag = skeleton.ETagForm(raw.ETag)
	}
	x.res.Observations = append(x.res.Observations, ob)
	if raw.Status == 429 {
		x.stopped = ErrRateLimited
	}
	return Seen{Status: raw.Status, ETag: raw.ETag, Body: raw.Body, sk: sk}, nil
}

// Post sends body to POST .../acl/validate as contentType and records the answer. The
// request line shows the body's size: use it for a synthetic body only.
func (x *Exec) Post(ctx context.Context, s Step, contentType string, body []byte) (Seen, error) {
	return x.post(ctx, s, contentType, body, fmt.Sprintf("POST validate, %s, %d bytes", contentType, len(body)))
}

// PostLive is Post for a body built from the live policy: the request line shows no size,
// because the size of a body that holds the policy's names says something about the policy.
func (x *Exec) PostLive(ctx context.Context, s Step, contentType string, body []byte) (Seen, error) {
	return x.post(ctx, s, contentType, body, fmt.Sprintf("POST validate, %s, a body built from the live policy", contentType))
}

func (x *Exec) post(ctx context.Context, s Step, contentType string, body []byte, request string) (Seen, error) {
	if err := x.pace(ctx); err != nil {
		return Seen{}, err
	}
	raw, err := x.api.ValidatePolicy(ctx, body, contentType)
	return x.record(s, request, raw, err, false)
}

// PostPolicy is Post in policy mode: application/hujson.
func (x *Exec) PostPolicy(ctx context.Context, s Step, doc string) (Seen, error) {
	return x.Post(ctx, s, "application/hujson", []byte(doc))
}

// GetPolicy performs GET .../acl as g says and records the answer.
func (x *Exec) GetPolicy(ctx context.Context, s Step, g api.PolicyGet) (Seen, error) {
	if err := x.pace(ctx); err != nil {
		return Seen{}, err
	}
	raw, err := x.api.GetPolicy(ctx, g)
	req := "GET policy"
	if g.Details {
		req += ", details=true"
	}
	if g.Accept != "" {
		req += ", Accept " + g.Accept
	}
	if g.IfNoneMatch != "" {
		req += ", If-None-Match set"
	}
	return x.record(s, req, raw, err, true)
}

// GetJSON performs a GET of a path below the tailnet and records the answer, whatever its
// status. It makes one attempt: the client's retrying reader is not used, so a 429 is seen
// and stops the run, and every request is paced and counted.
func (x *Exec) GetJSON(ctx context.Context, s Step, suffix string, q url.Values) (Seen, error) {
	if err := x.pace(ctx); err != nil {
		return Seen{}, err
	}
	raw, err := x.api.GetOnce(ctx, x.api.TailnetPath(suffix), q)
	return x.record(s, "GET "+suffix, raw, err, false)
}

// Check records an expectation and how the API behaved against it.
func (x *Exec) Check(name string, want, got bool) {
	x.res.Checks = append(x.res.Checks, Check{Name: name, Want: want, Got: got})
}

// Fact records a yes-or-no the probe table makes no promise about.
func (x *Exec) Fact(name string, v bool) {
	if x.res.Facts == nil {
		x.res.Facts = map[string]bool{}
	}
	x.res.Facts[name] = v
}

// Count records a number the probe computed.
func (x *Exec) Count(name string, n int) {
	if x.res.Counts == nil {
		x.res.Counts = map[string]int{}
	}
	x.res.Counts[name] = n
}

// Skip records why part of a probe did not run. The reason is a fixed sentence.
func (x *Exec) Skip(reason string) { x.res.Skipped = append(x.res.Skipped, reason) }

// Hex returns n random lower-case hex digits.
func (x *Exec) Hex(n int) string { return x.o.Hex(n) }

// TextHas reports whether a template of the answer contains sub.
func (s Seen) TextHas(sub string) bool {
	for _, t := range s.sk.Texts {
		if strings.Contains(t, sub) {
			return true
		}
	}
	return false
}

// BodyHas reports whether the answer's body, as received, contains sub. Unlike TextHas it
// reads the words the printer would template away (only a pinned list of phrases survives
// it), and like every Seen method it yields a boolean for the probe to record.
func (s Seen) BodyHas(sub string) bool { return strings.Contains(string(s.Body), sub) }

// HasPath reports whether the answer, as JSON, holds a value at path (see skeleton.Path).
func (s Seen) HasPath(path string) bool {
	for _, p := range s.sk.Paths {
		if p.Path == path {
			return true
		}
	}
	return false
}

// Bare reports a bare message: a JSON object with a message and no data array, which is
// how the API words a rejection of the policy itself.
func (s Seen) Bare() bool { return s.HasPath("message") && !s.HasPath("data") }

// Entries decodes the answer's data array into its entries; nil when it has none.
func (s Seen) Entries() []Entry {
	var v struct {
		Data []Entry `json:"data"`
	}
	if json.Unmarshal(s.Body, &v) != nil {
		return nil
	}
	return v.Data
}

// Entry is one element of the data array of an answer.
type Entry struct {
	User     string   `json:"user"`
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

// grammarRE is the end of a verdict line in the validate grammar as a template:
// the network form and the SSH form.
var grammarRE = regexp.MustCompile(`want: (Accept|Drop), got: (Accept|Drop)$|want: "accept" got: "deny"$`)

// Grammar counts the error lines of the answer that are in the verdict grammar (one per
// failed assertion), whatever their repetition.
func (s Seen) Grammar() int {
	n := 0
	for _, e := range s.Entries() {
		for _, text := range e.Errors {
			if grammarRE.MatchString(skeleton.Template(text)) {
				n++
			}
		}
	}
	return n
}

// ErrorLines counts the error lines of the answer, in the grammar or not.
func (s Seen) ErrorLines() int {
	n := 0
	for _, e := range s.Entries() {
		n += len(e.Errors)
	}
	return n
}

// WarningLines returns the warning strings of the answer's data entries.
func (s Seen) WarningLines() []string {
	var out []string
	for _, e := range s.Entries() {
		out = append(out, e.Warnings...)
	}
	return out
}

// Passes reports an answer that found no fault: an HTTP 200 with a JSON or empty body
// (an HTML page from a proxy is not a pass), not a bare message, no error line.
func (s Seen) Passes() bool { return s.Accepted() && s.ErrorLines() == 0 }

// Accepted reports a policy the server took: an HTTP 200 with a JSON or empty body, and
// not a bare message.
func (s Seen) Accepted() bool {
	return s.Status == 200 && (s.sk.Body == "json" || s.sk.Body == "empty") && !s.Bare()
}

// String and GoString keep a stray %v or %+v from printing a body: it can hold names
// from the tailnet.
func (Seen) String() string   { return "<seen>" }
func (Seen) GoString() string { return "<seen>" }

// signature is the printed skeleton of the answer, for comparing two answers.
func (s Seen) signature() string {
	b, _ := json.Marshal(s.sk)
	return string(b)
}

// sameSet reports whether a and b hold the same strings as sets: order and repetition do not matter.
func sameSet(a, b []string) bool {
	in := func(list []string, s string) bool { return contains(list, s) }
	for _, s := range a {
		if !in(b, s) {
			return false
		}
	}
	for _, s := range b {
		if !in(a, s) {
			return false
		}
	}
	return true
}

func isJSONObject(b []byte) bool {
	t := bytes.TrimSpace(b)
	return len(t) > 0 && t[0] == '{' && json.Valid(t)
}

// Compare reports how two observations differ in status and in the set of (path, type)
// pairs. Texts are templates and are not compared, and nothing returned is a text from
// an answer: a status difference is the word "status", and a path difference is the path.
func Compare(committed, now Observation) []string {
	var out []string
	if statusOf(committed.Result) != statusOf(now.Result) {
		out = append(out, "status")
	}
	cp, np := pathTypes(committed.Result), pathTypes(now.Result)
	names := make([]string, 0, len(cp)+len(np))
	seen := map[string]bool{}
	for _, m := range []map[string]string{cp, np} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				names = append(names, k)
			}
		}
	}
	sort.Strings(names)
	for _, k := range names {
		ct, cok := cp[k]
		nt, nok := np[k]
		if !cok || !nok || ct != nt {
			out = append(out, k)
		}
	}
	return out
}

func statusOf(sk *skeleton.Skeleton) int {
	if sk == nil {
		return -1
	}
	return sk.Status
}

func pathTypes(sk *skeleton.Skeleton) map[string]string {
	out := map[string]string{}
	if sk == nil {
		return out
	}
	for _, p := range sk.Paths {
		out[p.Path] = p.Type
	}
	return out
}
