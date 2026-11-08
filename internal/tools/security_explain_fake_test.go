package tools_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/tailscale/hujson"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// A model of the validate endpoint for the explanation. It does not evaluate a policy: the test
// says which pairs the live policy lets through (allow, sshAllow), and the model answers a
// posted text as the endpoint does, with one line for each test that is not as asked and the
// canary's own line beside them. The synthetic names are the reserved ones.

type policyModel struct {
	mu sync.Mutex
	// allow: "src|dst" lets src reach dst; sshAllow: "src|dst|user" lets the user in.
	allow, sshAllow map[string]bool
	// what the model leaves out or adds to the answer, to show that a reading needs the canary.
	omitCanary, omitSSHCanary bool
	canaryTwice               bool
	canaryUnevaluable         bool
	extraLine                 func(src string) []string // lines added to the entry of a source
	foreign                   []apitest.Entry           // entries of sources nobody asked about, added to the answer
	refuse                    string                    // when set, the answer is a bare message with it
	after                     func(n int)               // called after each answer, with its number
	onPost                    func(n int)               // called as each text arrives, before it is answered, with its number
	fiveHundred               func(n int) bool          // when it says so for a post, the endpoint answers HTTP 500 and reads nothing
	sshExtra                  func(src string) []string // lines added to the entry of a source of the ssh tests
	sshCanaryLines            func(tag string) []string // when set, the lines of the SSH canary's entry, in place of its own
	canaryExtra               func() []string           // lines added to the entry of the tests canary, beside its own
	canaryText                string                    // when set, the line of the tests canary, in place of its own
	bodies                    []string                  // the posted texts
}

// serveExplain registers the live policy and the validate endpoint on f.
func serveExplain(f *apitest.Fake, live string, m *policyModel) *liveRoute {
	route := serveLive(f, live, nil, nil)
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.bodies = append(m.bodies, string(body))
		n := len(m.bodies)
		m.mu.Unlock()
		if m.onPost != nil {
			m.onPost(n)
		}
		if m.fiveHundred != nil && m.fiveHundred(n) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"message":"synthetic"}`)
			return
		}
		m.mu.Lock()
		shape := m.answer(body)
		m.mu.Unlock()
		shape.Write(w)
		if m.after != nil {
			m.after(n)
		}
	})
	return route
}

// sent is what a posted text holds of tests.
type postedTests struct {
	Tests []struct {
		Src    string   `json:"src"`
		Proto  string   `json:"proto"`
		Accept []string `json:"accept"`
		Deny   []string `json:"deny"`
		Attrs  any      `json:"srcPostureAttrs"`
	} `json:"tests"`
	SSHTests []struct {
		Src    string   `json:"src"`
		Dst    []string `json:"dst"`
		Accept []string `json:"accept"`
		Check  []string `json:"check"`
		Deny   []string `json:"deny"`
	} `json:"sshTests"`
}

func decodeSent(body string) (postedTests, error) {
	std, err := hujson.Standardize([]byte(body))
	if err != nil {
		return postedTests{}, fmt.Errorf("the posted text is not HuJSON: %w", err)
	}
	var s postedTests
	if err := json.Unmarshal(std, &s); err != nil {
		return postedTests{}, fmt.Errorf("the posted text does not decode: %w", err)
	}
	return s, nil
}

func parseSent(t testing.TB, body string) postedTests {
	t.Helper()
	s, err := decodeSent(body)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (m *policyModel) answer(body []byte) apitest.Shape {
	if m.refuse != "" {
		return apitest.BareMessage200(m.refuse)
	}
	s, err := decodeSent(string(body))
	if err != nil {
		return apitest.BareMessage200(err.Error())
	}
	var order []string
	lines := map[string][]string{}
	add := func(src string, errs ...string) {
		if _, ok := lines[src]; !ok {
			order = append(order, src)
		}
		lines[src] = append(lines[src], errs...)
	}
	for _, t := range s.Tests {
		if canaryTagRE.MatchString(t.Src) {
			m.canary(t.Src, add)
			continue
		}
		add(t.Src)
		for _, d := range t.Accept {
			if !m.allow[t.Src+"|"+d] {
				add(t.Src, fmt.Sprintf(`[acl test error]: address %q: want: Accept, got: Drop`, d))
			}
		}
		for _, d := range t.Deny {
			if m.allow[t.Src+"|"+d] {
				add(t.Src, fmt.Sprintf(`[acl test error]: address %q: want: Drop, got: Accept`, d))
			}
		}
		if m.extraLine != nil {
			add(t.Src, m.extraLine(t.Src)...)
		}
	}
	for _, t := range s.SSHTests {
		if sshCanaryTagRE.MatchString(t.Src) {
			if !m.omitSSHCanary {
				e := sshCanaryEntryOf(t.Src)
				if m.sshCanaryLines != nil {
					e.Errors = m.sshCanaryLines(t.Src)
				}
				add(e.User, e.Errors...)
			}
			continue
		}
		add(t.Src)
		if m.sshExtra != nil {
			add(t.Src, m.sshExtra(t.Src)...)
		}
		for _, d := range t.Dst {
			for _, u := range t.Accept {
				if !m.sshAllow[t.Src+"|"+d+"|"+u] {
					add(t.Src, sshLine(t.Src, d, u, "accept", "deny"))
				}
			}
			for _, u := range t.Deny {
				if m.sshAllow[t.Src+"|"+d+"|"+u] {
					add(t.Src, sshLine(t.Src, d, u, "deny", "accept"))
				}
			}
		}
	}
	var entries []apitest.Entry
	for _, src := range order {
		if len(lines[src]) > 0 {
			entries = append(entries, apitest.Entry{User: src, Errors: lines[src]})
		}
	}
	entries = append(entries, m.foreign...)
	if len(entries) == 0 {
		return apitest.TestsPassEmptyObject()
	}
	return apitest.TestsFailed(entries...)
}

func (m *policyModel) canary(tag string, add func(string, ...string)) {
	switch {
	case m.omitCanary:
	case m.canaryUnevaluable:
		add(tag, "[acl test error]: user or host is invalid: tag not found")
	case m.canaryTwice:
		add(tag, canaryLine)
		add(tag, canaryLine)
	default:
		line := canaryLine
		if m.canaryText != "" {
			line = m.canaryText
		}
		add(tag, line)
		if m.canaryExtra != nil {
			add(tag, m.canaryExtra()...)
		}
	}
}

func sshLine(src, dst, user, want, got string) string {
	return fmt.Sprintf(`[ssh test error]: src %q at "100.64.0.1", dst %q at "100.64.0.2", ssh user %q: want: %q got: %q`, src, dst, user, want, got)
}

// obsLog is the audit record of the validation requests of an explanation, as a surface keeps it:
// every event is kept, and a test may make a record fail. A test that sets env.RecordObservation
// itself keeps its own.
type obsLog struct {
	mu     sync.Mutex
	events []security.CollectionEvent
	// fail, when set, is asked about each event before it is kept; a non-nil answer is the
	// error of the record, and the event is not kept.
	fail func(security.CollectionEvent) error
}

func (l *obsLog) record(_ context.Context, ev security.CollectionEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := ev.Validate(); err != nil {
		return tkerr.Wrap(tkerr.Internal, err, "an event the audit log does not take", "")
	}
	if l.fail != nil {
		if err := l.fail(ev); err != nil {
			return err
		}
	}
	l.events = append(l.events, ev)
	return nil
}

func (l *obsLog) all() []security.CollectionEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.events)
}

var (
	observations    sync.Map // *registry.Env -> *obsLog
	withoutRecorder sync.Map // *registry.Env a test keeps without any audit record
)

// recorderOf gives env the audit recorder of a surface, unless it has one, and returns the log.
func recorderOf(env *registry.Env) *obsLog {
	if l, ok := observations.Load(env); ok {
		return l.(*obsLog)
	}
	l := &obsLog{}
	env.RecordObservation = l.record
	observations.Store(env, l)
	return l
}

// explainOnce runs the explanation as the command line would: with the file's text as the
// operator's own.
func explainOnce(t testing.TB, env *registry.Env, intent string, mod ...func(*tools.SecurityExplainInput)) (tools.SecurityExplainOutput, error) {
	t.Helper()
	return explainCtx(context.Background(), t, env, intent, mod...)
}

func explainCtx(ctx context.Context, t testing.TB, env *registry.Env, intent string, mod ...func(*tools.SecurityExplainInput)) (tools.SecurityExplainOutput, error) {
	t.Helper()
	if _, bare := withoutRecorder.Load(env); env.RecordObservation == nil && !bare {
		recorderOf(env)
	}
	p, err := tools.SecurityExplainTool().Validate(json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	in := p.Input().(*tools.SecurityExplainInput)
	in.Invariants, in.Operator = intent, intent != ""
	for _, m := range mod {
		m(in)
	}
	out, err := p.Run(registry.WithCaller(ctx, registry.Caller{Kind: "cli"}), env)
	if err != nil {
		return tools.SecurityExplainOutput{}, err
	}
	return out.(tools.SecurityExplainOutput), nil
}

func rowOf(out tools.SecurityExplainOutput, id string) tools.SecurityExplainRow {
	for _, r := range out.Expectations {
		if r.ID == id {
			return r
		}
	}
	return tools.SecurityExplainRow{}
}

func cellReasons(r tools.SecurityExplainRow) []string {
	var out []string
	for _, c := range r.Cells {
		out = append(out, c.Reason)
	}
	return out
}

func blastOf(out tools.SecurityExplainOutput, source string) *tools.SecurityExplainBlast {
	for i := range out.Blast {
		if out.Blast[i].Source == source {
			return &out.Blast[i]
		}
	}
	return nil
}

// reportText is the findings and facts of the human layout as lines, for a test that looks for
// a sentence.
func reportText(out tools.SecurityExplainOutput) string {
	rep := out.Report()
	var b strings.Builder
	b.WriteString(rep.Verdict + "\n")
	for _, f := range rep.Facts {
		b.WriteString(f.Label + ": " + f.Text + "\n")
	}
	for _, f := range rep.Findings {
		fmt.Fprintf(&b, "%s %d:%d %s\n", f.Source, f.Line, f.Column, f.Message)
	}
	return b.String()
}

// the posts of the model that held tests, as parsed texts.
func (m *policyModel) sentTexts(t testing.TB) []postedTests {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]postedTests, len(m.bodies))
	for i, b := range m.bodies {
		out[i] = parseSent(t, b)
	}
	return out
}
