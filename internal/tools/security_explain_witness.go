package tools

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// The witness of an explanation is Tailscale's own validation of the live policy: a copy of the
// live text with its own tests removed, the selected expectations as tests, and the canary
// beside them (buildInvariantsText, the text acl validate sends for its invariants and acl_test
// for its SSH tests). A test that passes shows nothing in the reply, so the reply is read only
// when the canary came back once, in the grammar (takeCanary, takeSSHCanary); a line is read by
// the one grammar (ParseFailureLine, through deriveVerdicts and deriveSSHVerdicts, the readers
// of acl_test). No pair is asked about that an expectation did not list, and at most two
// requests are made: one for the network tests and one for the SSH tests.

// cellAsk is one pair put to Tailscale, and the expectation it belongs to.
type cellAsk struct {
	id   string
	cell security.AccessCell
}

// netEntry is the one test a source has in the request of the network tests: its terms, and the
// pairs of every selected expectation of the source that has the same terms.
type netEntry struct {
	src   string
	proto string
	attrs security.PostureAttributes
	asks  []cellAsk // accept pairs and deny pairs, in the order they were asked
}

// sshEntry is the one sshTests entry a source has in the request of the SSH tests: the
// destinations it names, the users it accepts, checks and denies on each of them, and the pairs
// it asks about, with the expectation each belongs to. Tailscale is known to fail two tests that
// share a src (docs/design.md, 12.2, for tests; no probe shows that sshTests are spared), so a
// source has one entry, and the pairs of it that no one entry can hold are not asked.
type sshEntry struct {
	src                 string
	dsts                []string
	accept, check, deny []string
	asks                []cellAsk
}

// asks is what an explanation puts to Tailscale, and what it does not.
type asks struct {
	net      []*netEntry
	ssh      []*sshEntry
	notAsked []security.AccessWitness
}

// planAsks turns the pairs a plan judges into the entries of the two requests. Two selected
// expectations with one source and the same terms share an entry; a second set of terms for a
// source is not asked, because one request holds one test for a source, and its pairs are
// recorded as not asked, with the reason. A pair that names the coordinates of tailkeeper's own
// canary is not asked either: it is unknown (ReasonCanaryCoordinates), because a reply that
// proves the canary and holds nothing for the source reads, at those coordinates, as the canary's
// own line does, and silence there would be a verdict. hosts resolves the aliases a destination
// may be written with.
func planAsks(plan []security.PlannedExpectation, set security.IntentSet, hosts map[string]string) asks {
	var out asks
	netExp := map[string]security.NetworkExpectation{}
	for _, e := range set.Network {
		netExp[e.ID] = e
	}
	bySrc := map[string]*netEntry{}
	for _, pe := range plan {
		if pe.Kind == security.AccessNetwork {
			out.addNetwork(pe, netExp[pe.ID], bySrc, hosts)
		}
	}
	out.planSSH(plan, hosts)
	// A source none of whose pairs is judged (past the cap) has no test: an entry with nothing in
	// it would assert nothing and name a source for no reason.
	out.net = slices.DeleteFunc(out.net, func(e *netEntry) bool { return len(e.asks) == 0 })
	return out
}

// setAside is the witness of a pair that names the canary's coordinates: unknown, not asked.
func setAside(id string, c security.AccessCell) security.AccessWitness {
	return security.AccessWitness{Expectation: id, Cell: c, Observed: security.ObservedUnknown, Reason: security.ReasonCanaryCoordinates}
}

func (a *asks) addNetwork(pe security.PlannedExpectation, e security.NetworkExpectation, bySrc map[string]*netEntry, hosts map[string]string) {
	var cells []security.AccessCell
	for _, c := range pe.Cells {
		if namesTheTestsCanary(c.Destination, hosts) {
			a.notAsked = append(a.notAsked, setAside(pe.ID, c))
			continue
		}
		cells = append(cells, c)
	}
	if len(cells) == 0 {
		return // an entry with nothing to ask would only fix the terms of a source for nothing
	}
	entry := bySrc[pe.Source]
	if entry == nil {
		entry = &netEntry{src: pe.Source, proto: e.Protocol, attrs: e.SourcePostureAttributes}
		bySrc[pe.Source] = entry
		a.net = append(a.net, entry)
	}
	sameTerms := entry.proto == e.Protocol && reflect.DeepEqual(entry.attrs, e.SourcePostureAttributes)
	for _, c := range cells {
		if sameTerms {
			entry.asks = append(entry.asks, cellAsk{pe.ID, c})
		} else {
			a.notAsked = append(a.notAsked, security.AccessWitness{Expectation: pe.ID, Cell: c, Observed: security.ObservedNotAsked, Reason: security.ReasonSameSource})
		}
	}
}

// planSSH makes the SSH entries of a plan: one for each source. The pairs of a source are a set
// of (expect, user) keys with the destinations each is asked on, and one sshTests entry holds
// exactly the product of its destinations and its users: so the keys whose destinations are the
// same set go into one entry (an accept user and a deny user on the same destinations are one
// test, as the owner would have written them), and the pairs of the keys with another set are
// not asked, with the reason same_source, as the network side treats another set of terms for a
// source. Nothing is widened to make them fit.
func (a *asks) planSSH(plan []security.PlannedExpectation, hosts map[string]string) {
	var order []string
	bySrc := map[string][]cellAsk{}
	for _, pe := range plan {
		if pe.Kind != security.AccessSSH {
			continue
		}
		for _, c := range pe.Cells {
			if namesTheSSHCanary(c.Destination, c.User, hosts) {
				a.notAsked = append(a.notAsked, setAside(pe.ID, c))
				continue
			}
			if _, seen := bySrc[pe.Source]; !seen {
				order = append(order, pe.Source)
			}
			bySrc[pe.Source] = append(bySrc[pe.Source], cellAsk{pe.ID, c})
		}
	}
	for _, src := range order {
		a.addSSHSource(src, bySrc[src])
	}
}

// sshUserKey is a user of one list: what one test of an entry is asked about, across destinations.
type sshUserKey struct{ expect, user string }

func (a *asks) addSSHSource(src string, list []cellAsk) {
	dstsOf := map[sshUserKey][]string{}
	var keys []sshUserKey
	for _, ca := range list {
		k := sshUserKey{ca.cell.Expect, ca.cell.User}
		if _, seen := dstsOf[k]; !seen {
			keys = append(keys, k)
		}
		if !slices.Contains(dstsOf[k], ca.cell.Destination) {
			dstsOf[k] = append(dstsOf[k], ca.cell.Destination)
		}
	}
	setOf := func(k sshUserKey) string {
		d := slices.Clone(dstsOf[k])
		slices.Sort(d)
		return strings.Join(d, "\x00")
	}
	chosen := setOf(keys[0])
	e := &sshEntry{src: src, dsts: dstsOf[keys[0]]}
	for _, k := range keys {
		if setOf(k) != chosen {
			continue
		}
		switch k.expect {
		case "accept":
			e.accept = append(e.accept, k.user)
		case "check":
			e.check = append(e.check, k.user)
		default:
			e.deny = append(e.deny, k.user)
		}
	}
	for _, ca := range list {
		if setOf(sshUserKey{ca.cell.Expect, ca.cell.User}) == chosen {
			e.asks = append(e.asks, ca)
		} else {
			a.notAsked = append(a.notAsked, security.AccessWitness{Expectation: ca.id, Cell: ca.cell, Observed: security.ObservedNotAsked, Reason: security.ReasonSameSource})
		}
	}
	a.ssh = append(a.ssh, e)
}

// uniq lists the destinations of the asks of one kind once each, in order.
func (e *netEntry) list(expect string) []string {
	var out []string
	for _, a := range e.asks {
		if a.cell.Expect == expect && !slices.Contains(out, a.cell.Destination) {
			out = append(out, a.cell.Destination)
		}
	}
	return out
}

// testJSON is the entry of the tests section: the source, the terms it was given and the
// destinations it must or must not reach. A list with nothing in it is left out.
func (e *netEntry) testJSON() ([]byte, error) {
	m := map[string]any{"src": e.src}
	if e.proto != "" {
		m["proto"] = e.proto
	}
	if len(e.attrs) > 0 {
		m["srcPostureAttrs"] = e.attrs
	}
	if l := e.list("accept"); len(l) > 0 {
		m["accept"] = l
	}
	if l := e.list("deny"); len(l) > 0 {
		m["deny"] = l
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, tkerr.Wrap(tkerr.Internal, err, "a test of the explanation could not be encoded", "this is a tailkeeper bug; report it")
	}
	return b, nil
}

// dests is the destinations of the entry for deriveVerdicts, one for each pair asked, in order.
func (e *netEntry) dests() []testDest {
	out := make([]testDest, len(e.asks))
	for i, a := range e.asks {
		out[i] = testDest{Sent: a.cell.Destination, Shown: a.cell.Destination, Accept: a.cell.Expect == "accept", Deny: a.cell.Expect == "deny"}
	}
	return out
}

// test is the entry as an SSH test of acl_test, the form deriveSSHVerdicts reads.
func (e *sshEntry) test() ACLSSHTestInput {
	return ACLSSHTestInput{Dst: e.dsts, Accept: e.accept, Check: e.check, Deny: e.deny}
}

// requestReason is the reason an error of a validation request leaves pairs unknown, and false
// for an error that stops the command: a credential that does not work, a scope it lacks, a
// text that is too complex or a bug. A limit, an upstream that does not answer, an answer that is
// not one the client reads and a cancelled call leave the pairs unknown instead.
func requestReason(err error) (security.AccessReason, bool) {
	switch tkerr.From(err).Code {
	case tkerr.ValidateRateLimited, tkerr.APIRateLimited:
		return security.ReasonRateLimited, true
	case tkerr.UpstreamUnavailable, tkerr.APIError, tkerr.PolicyRejectedOrServerError, tkerr.ResponseTooLarge:
		return security.ReasonRequestFailed, true
	}
	return "", false
}

// unknownAll is a witness of unknown for each pair, with one reason.
func unknownAll(list []cellAsk, reason security.AccessReason) []security.AccessWitness {
	out := make([]security.AccessWitness, len(list))
	for i, a := range list {
		out[i] = security.AccessWitness{Expectation: a.id, Cell: a.cell, Observed: security.ObservedUnknown, Reason: reason}
	}
	return out
}

func (a asks) netAsks() []cellAsk {
	var out []cellAsk
	for _, e := range a.net {
		out = append(out, e.asks...)
	}
	return out
}

func (a asks) sshAsks() []cellAsk {
	var out []cellAsk
	for _, e := range a.ssh {
		out = append(out, e.asks...)
	}
	return out
}

// foreignErrors says that a reply holds errors for a source that is none of the sources of the
// request, or a spelling of one. The live policy's own tests are not in the text, so such a line
// is about nothing that was asked, and no pair of the request is read.
func foreignErrors(results []api.TestResult, srcs []string) bool {
	for _, r := range results {
		if len(r.Errors) == 0 {
			continue
		}
		if !slices.ContainsFunc(srcs, func(s string) bool { return r.User == s || spellsSource(r.User, s) }) {
			return true
		}
	}
	return false
}

// resultsOf are the entries of a reply that belong to a source, as it was sent or as a spelling
// of it: deriveVerdicts and deriveSSHVerdicts treat a spelling as a reason to read nothing.
func resultsOf(results []api.TestResult, src string) []api.TestResult {
	var out []api.TestResult
	for _, r := range results {
		if r.User == src || spellsSource(r.User, src) {
			out = append(out, r)
		}
	}
	return out
}

// networkReason is the reason a verdict of deriveVerdicts that is neither allowed nor denied
// gives.
func networkReason(v destVerdict) security.AccessReason {
	switch {
	case v.Verdict == verdictUnresolved:
		return security.ReasonUnresolved
	case v.Why == whyProtocolsDiffer, v.Why == whyBothNeedOneLine:
		return security.ReasonDisagree
	case v.Why == whyUnpairedLine, v.Why == whyOtherSpelling, v.Why == whySourceSpelling:
		return security.ReasonUnpaired
	}
	return security.ReasonUnparseable
}

// observed is the observation a verdict word stands for.
func observed(verdict string) security.AccessObserved {
	switch verdict {
	case verdictAllowed:
		return security.ObservedAllowed
	case verdictDenied:
		return security.ObservedDenied
	}
	return security.ObservedUnknown
}

// readNetwork reads the reply of the network request, canary taken off, into a witness for each
// pair asked.
func readNetwork(entries []*netEntry, results []api.TestResult, hosts map[string]string) []security.AccessWitness {
	srcs := make([]string, len(entries))
	var all []cellAsk
	for i, e := range entries {
		srcs[i] = e.src
		all = append(all, e.asks...)
	}
	if foreignErrors(results, srcs) {
		return unknownAll(all, security.ReasonUnpaired)
	}
	var out []security.AccessWitness
	for _, e := range entries {
		reading := deriveVerdicts(e.dests(), e.src, hosts, resultsOf(results, e.src))
		for i, v := range reading.Verdicts {
			w := security.AccessWitness{Expectation: e.asks[i].id, Cell: e.asks[i].cell, Observed: observed(v.Verdict)}
			if w.Observed == security.ObservedUnknown {
				w.Reason = networkReason(v)
			}
			out = append(out, w)
		}
	}
	return out
}

// sshPair is a pair of an SSH verdict as deriveSSHVerdicts names it.
type sshPair struct{ expect, dst, user string }

// misattributed lists the sources a reply attributes inconsistently: a line in the SSH form that
// names a source other than the one whose entry it was found in. The shared parser reads the
// pair a line is about and leaves its source out, so the attribution is checked here: the entry
// the line is in and the source it quotes must be the same, and when they are not, neither can be
// read, for the line is evidence about one of them and sits under the other. The quoted source
// need not be one of the request's. The SSH canary's entry is not here: it is taken off before
// this runs, and takeSSHCanary takes it only when its line quotes the canary's own tag, which is
// this same check made on the one entry that would otherwise go unchecked.
func misattributed(results []api.TestResult) []string {
	var out []string
	for _, r := range results {
		for _, e := range r.Errors {
			if quoted, ok := SSHLineSource(e); ok && quoted != r.User {
				out = append(out, r.User, quoted)
			}
		}
	}
	return out
}

// readSSH reads the reply of the SSH request, both canaries taken off, into a witness for each
// pair asked.
func readSSH(entries []*sshEntry, results []api.TestResult) []security.AccessWitness {
	var srcs []string
	var all []cellAsk
	for _, e := range entries {
		srcs = append(srcs, e.src)
		all = append(all, e.asks...)
	}
	if foreignErrors(results, srcs) {
		return unknownAll(all, security.ReasonUnpaired)
	}
	bad := misattributed(results)
	out := make([]security.AccessWitness, 0, len(all))
	for _, e := range entries {
		if slices.ContainsFunc(bad, func(b string) bool { return b == e.src || spellsSource(b, e.src) }) {
			out = append(out, unknownAll(e.asks, security.ReasonUnpaired)...)
			continue
		}
		verdicts, _, _, _ := deriveSSHVerdicts(e.src, []ACLSSHTestInput{e.test()}, resultsOf(results, e.src))
		got := map[sshPair]ACLSSHVerdict{}
		for _, v := range verdicts {
			got[sshPair{v.Expect, v.Dst, v.User}] = v
		}
		for _, ca := range e.asks {
			v := got[sshPair{ca.cell.Expect, ca.cell.Destination, ca.cell.User}]
			w := security.AccessWitness{Expectation: ca.id, Cell: ca.cell, Observed: observed(v.Verdict)}
			if w.Observed == security.ObservedUnknown {
				w.Reason = sshReason(v)
			}
			out = append(out, w)
		}
	}
	return out
}

// sshReason is the reason an SSH verdict that is neither allowed nor denied gives.
func sshReason(v ACLSSHVerdict) security.AccessReason {
	switch {
	case v.Why == whyCheckSilent:
		return security.ReasonCheckUser
	case v.Verdict == verdictUnresolved, v.Why == whySSHUnevaluable:
		return security.ReasonUnresolved
	case v.Why == whySSHDisagree:
		return security.ReasonDisagree
	case v.Why == whySSHUnpaired, v.Why == whySourceSpelling:
		return security.ReasonUnpaired
	}
	return security.ReasonUnparseable
}

// answerKind is how a reply to a request ended, before any line of it is read.
type answerKind int

const (
	answerProven  answerKind = iota // the canary came back once, in the grammar: the lines are read
	answerNoProof                   // the reply shows no canary: nothing in it is a verdict
	answerRefused                   // Tailscale refused the text built from the live policy
	answerOdd                       // an answer this version does not recognise
)

// proveCanary takes the canary or canaries off a reply that failed, and says what the reply is.
// The SSH canary is taken only for a request that held SSH tests.
func proveCanary(ctx context.Context, pv api.PolicyValidation, built invariantsCall) (api.PolicyValidation, answerKind) {
	switch pv.Status {
	case api.PolicyRejected:
		return pv, answerRefused
	case api.PolicyFail:
		rest, ok := takeCanary(pv, built.Canary, accessStateOf(ctx, built.Text))
		if ok && built.SSHCanary != "" {
			rest, ok = takeSSHCanary(rest, built.SSHCanary)
		}
		if !ok {
			return pv, answerNoProof
		}
		return rest, answerProven
	case api.PolicyPass:
		return pv, answerNoProof // a pass carries no canary, which is a failure by design
	}
	return pv, answerOdd
}

// failedAnswer is the witnesses of a request whose answer cannot be read.
func failedAnswer(list []cellAsk, kind answerKind) []security.AccessWitness {
	reason := security.ReasonCanary
	switch kind {
	case answerRefused:
		reason = security.ReasonRefused
	case answerOdd:
		reason = security.ReasonUnparseable
	}
	return unknownAll(list, reason)
}

// proven marks the witnesses of a request whose canary came back as having it. The live policy
// is shown unchanged separately, once both requests are made.
func proven(ws []security.AccessWitness) []security.AccessWitness {
	for i := range ws {
		ws[i].Proof.Canary = true
	}
	return ws
}

// hostAliases is the hosts section as deriveVerdicts takes it, or nil.
func hostAliases(facts *explainFacts) map[string]string {
	if facts == nil || facts.access == nil {
		return nil
	}
	return facts.access.Hosts
}

// witness makes the requests the asks need against the live policy and reads the replies. The
// live policy is read once, by the caller; a text that cannot be built from it, a policy with
// errors stored or one this version cannot read is not sent, and every pair is unknown for the
// reason. The tokens of both requests are reserved at once, so that a limit leaves every pair
// unknown and not one mode answered and the other not. After the requests the live policy is
// read once more, and the witnesses are marked unchanged only if it is the same.
func (r *explainRun) witness(ctx context.Context, a asks) ([]security.AccessWitness, error) {
	out := slices.Clone(a.notAsked)
	netAll, sshAll := a.netAsks(), a.sshAsks()
	if len(netAll)+len(sshAll) == 0 {
		return out, nil
	}
	if reason := r.unaskable(); reason != "" {
		return slices.Concat(out, unknownAll(netAll, reason), unknownAll(sshAll, reason)), nil
	}
	posts := 0
	for _, n := range []int{len(netAll), len(sshAll)} {
		if n > 0 {
			posts++
		}
	}
	call, err := r.c.BeginValidate(ctx, posts)
	if err != nil {
		reason, soft := requestReason(err)
		if !soft {
			return nil, err
		}
		return slices.Concat(out, unknownAll(netAll, reason), unknownAll(sshAll, reason)), nil
	}
	defer call.End()
	var asked []security.AccessWitness
	if len(netAll) > 0 {
		ws, err := r.askNetwork(ctx, call, a.net, netAll)
		if err != nil {
			return nil, err
		}
		asked = append(asked, ws...)
	}
	if len(sshAll) > 0 {
		ws, err := r.askSSH(ctx, call, a.ssh, sshAll)
		if err != nil {
			return nil, err
		}
		asked = append(asked, ws...)
	}
	stamp, err := r.c.LiveStamp(call.Context())
	unchanged := err == nil && !liveMoved(r.live, stamp)
	for i := range asked {
		asked[i].Proof.LiveUnchanged = unchanged
	}
	return slices.Concat(out, asked), nil
}

// unaskable says why nothing is sent: the live policy has errors stored with it, or this version
// cannot read it.
func (r *explainRun) unaskable() security.AccessReason {
	switch {
	case len(r.live.Errors) > 0:
		return security.ReasonLiveErrors
	case r.facts == nil || r.facts.doc == nil:
		return security.ReasonLiveUnreadable
	}
	return ""
}

// askNetwork sends the network tests and reads the reply.
func (r *explainRun) askNetwork(ctx context.Context, call *api.ValidateCall, entries []*netEntry, list []cellAsk) ([]security.AccessWitness, error) {
	tests := make([][]byte, len(entries))
	for i, e := range entries {
		b, err := e.testJSON()
		if err != nil {
			return nil, err
		}
		tests[i] = b
	}
	built, err := buildInvariantsText(ctx, r.live.Text, &invariantSet{Tests: tests}, randomHex8)
	if err != nil {
		return stoppedOr(ctx, list, err)
	}
	pv, reason, err := r.send(ctx, call, security.SourceValidateNetwork, len(list), built.Text)
	if err != nil {
		return nil, err
	}
	if reason != "" {
		return unknownAll(list, reason), nil
	}
	rest, kind := proveCanary(ctx, pv, built)
	if kind != answerProven {
		return failedAnswer(list, kind), nil
	}
	return proven(readNetwork(entries, rest.Results, hostAliases(r.facts))), nil
}

// askSSH sends the SSH tests, with an SSH canary beside the tests canary, and reads the reply.
func (r *explainRun) askSSH(ctx context.Context, call *api.ValidateCall, entries []*sshEntry, list []cellAsk) ([]security.AccessWitness, error) {
	tests := make([][]byte, len(entries))
	for i, e := range entries {
		b, err := sshTestEntry(e.src, e.test())
		if err != nil {
			return nil, err
		}
		tests[i] = b
	}
	built, err := buildInvariantsText(ctx, r.live.Text, &invariantSet{SSHTests: tests, WithSSHCanary: true}, randomHex8)
	if err != nil {
		return stoppedOr(ctx, list, err)
	}
	pv, reason, err := r.send(ctx, call, security.SourceValidateSSH, len(list), built.Text)
	if err != nil {
		return nil, err
	}
	if reason != "" {
		return unknownAll(list, reason), nil
	}
	rest, kind := proveCanary(ctx, pv, built)
	if kind != answerProven {
		return failedAnswer(list, kind), nil
	}
	return proven(readSSH(entries, rest.Results)), nil
}

// send makes one validation request, with its own audit records: an attempt, written before the
// request is sent, and an outcome, written after, through the surface's required security audit
// method (registry.Env.RecordObservation, the one the collector uses, which refuses
// audit.reads "none", a log that is not open and a line the log refuses). The records name the
// request by a closed source, the pairs it carries as a count, how it ended as a closed outcome
// and its error code: no text of the intent and none of the policy. If the attempt cannot be
// recorded the request is not sent, and if the outcome cannot be recorded its answer is not
// relied on: the reason comes back as ReasonNotRecorded, and the pairs are unknown. A failure of
// the request that leaves its pairs unknown is a reason too; one that stops the command is the
// error. The request is sent once (SendOnce): a retry would be a second POST that the promise of
// at most two requests does not count.
func (r *explainRun) send(ctx context.Context, call *api.ValidateCall, source security.CollectionSource, pairs int, text []byte) (api.PolicyValidation, security.AccessReason, error) {
	record := func(ev security.CollectionEvent) error {
		if r.env == nil || r.env.RecordObservation == nil {
			return tkerr.New(tkerr.AuditUnavailable, "this surface keeps no per-request audit record", "run it through the tailkeeper command line")
		}
		ev.Scope, ev.Source = security.ScopeFleet, source
		return r.env.RecordObservation(context.WithoutCancel(ctx), ev)
	}
	if record(security.CollectionEvent{Phase: security.PhaseAttempt}) != nil {
		return api.PolicyValidation{}, security.ReasonNotRecorded, nil
	}
	begin := time.Now() // a monotonic clock: a step of the wall clock cannot make a duration negative
	pv, err := call.SendOnce(text)
	end := security.CollectionEvent{Phase: security.PhaseOutcome, Outcome: security.OutcomeOK, Observed: security.SaturateCount(pairs), Millis: time.Since(begin).Milliseconds()}
	switch {
	case err == nil:
	case ctx.Err() != nil:
		end.Outcome = security.OutcomeCancelled
	default:
		end.Outcome, end.Code = security.OutcomeError, string(tkerr.From(err).Code)
	}
	recordErr := record(end)
	reason := security.AccessReason("")
	if err != nil {
		var soft bool
		if reason, soft = requestReason(err); !soft {
			return api.PolicyValidation{}, "", err // an error that stops the command stops it, recorded or not
		}
	}
	if recordErr != nil {
		return api.PolicyValidation{}, security.ReasonNotRecorded, nil
	}
	return pv, reason, nil
}

// stoppedOr is the result of a text that could not be built: when the call was cancelled that is
// why, and the pairs are unknown; anything else is the error of the build.
func stoppedOr(ctx context.Context, list []cellAsk, err error) ([]security.AccessWitness, error) {
	if ctx.Err() != nil {
		return unknownAll(list, security.ReasonRequestFailed), nil
	}
	return nil, err
}

// hasPrefixAny says that s starts with one of the prefixes.
func hasPrefixAny(s string, prefixes ...string) bool {
	return slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(s, p) })
}
