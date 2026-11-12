package security

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
)

// This file explains selected access: for each expectation of an intent set, whether the live
// policy was witnessed to do what the expectation says, and what a compromised source could
// reach by the witnessed pairs. It is pure: it reads no clock, calls no source and judges
// nothing it was not given a witness for. A witness is Tailscale's own validation of the live
// policy with the expectation as a test and a canary beside it; the rules it cites are
// candidates (a text match of the rule's selectors on the pair), never the cause of a verdict.
//
// Nothing here says that a service listens, that a credential works or that an exploit
// succeeds: a verdict is about what the policy does with a connection, and the blast radius is
// an assumption about a compromised source, worded as one.

const (
	// MaxAccessPairs is the most (source, destination) pairs one run judges. It is the number
	// of tests one validation call may carry (the cap on the tests a text adds), and it is
	// applied to pairs, so that it is never above what a call carries even if each pair were
	// a test of its own. A pair past it is not evaluated, and the report counts it.
	MaxAccessPairs = 64
	// MaxAccessRows is the most expectations a report lists. The counts cover all of them.
	MaxAccessRows = 100
	// MaxAccessCandidates is the most candidate rules listed for one expectation.
	MaxAccessCandidates = 8
	// MaxAccessTags is the most tags listed for one source.
	MaxAccessTags = 8
)

// AccessKind says whether an expectation is a network test or an SSH test. The two are
// separate questions: an SSH verdict says nothing of network reachability and the reverse.
type AccessKind string

const (
	AccessNetwork AccessKind = "network"
	AccessSSH     AccessKind = "ssh"
)

// AccessStatus is the status of an expectation, and of one of its pairs (which is never
// met_with_limits).
type AccessStatus string

const (
	// AccessMet: every pair was witnessed to be as the expectation says, with a canary.
	AccessMet AccessStatus = "met"
	// AccessUnmet: a pair was witnessed to be the other way: an accepted pair dropped, or a
	// denied pair accepted.
	AccessUnmet AccessStatus = "unmet"
	// AccessUnknown: a pair could not be witnessed. It is never met.
	AccessUnknown AccessStatus = "unknown"
	// AccessMetWithLimits: every pair was witnessed as met, and a case the test language
	// cannot express (posture, app capabilities, via, a source it cannot name) is stated.
	AccessMetWithLimits AccessStatus = "met_with_limits"
	// AccessNotEvaluated: a pair was left out, past the cap or by a rule of the request.
	AccessNotEvaluated AccessStatus = "not_evaluated"
)

// AccessOverall is the status of a report. It is complete only when every selected
// expectation is met with a canary: an unmet, unknown, limited or unevaluated row, or no
// expectation at all, makes it incomplete.
type AccessOverall string

const (
	AccessComplete   AccessOverall = "complete"
	AccessIncomplete AccessOverall = "incomplete"
)

// AccessObserved is what the live policy was witnessed to do with a pair's traffic.
type AccessObserved string

const (
	ObservedAllowed AccessObserved = "allowed"
	ObservedDenied  AccessObserved = "denied"
	ObservedUnknown AccessObserved = "unknown"
	// ObservedNotAsked: the pair was not put to Tailscale, for the reason that comes with it.
	ObservedNotAsked AccessObserved = "not_asked"
)

// AccessReason is why a pair is unknown or not evaluated. The set is closed, and each has a
// fixed sentence (ReasonSentence): no word of Tailscale's, and none of the intent, is in one.
type AccessReason string

const (
	ReasonNoWitness      AccessReason = "no_witness"
	ReasonCanary         AccessReason = "canary"
	ReasonLiveChanged    AccessReason = "live_changed"
	ReasonUnparseable    AccessReason = "unparseable_line"
	ReasonUnresolved     AccessReason = "unresolved"
	ReasonUnpaired       AccessReason = "unpaired_line"
	ReasonDisagree       AccessReason = "lines_disagree"
	ReasonRateLimited    AccessReason = "rate_limited"
	ReasonRequestFailed  AccessReason = "request_failed"
	ReasonRefused        AccessReason = "refused"
	ReasonLiveErrors     AccessReason = "live_policy_errors"
	ReasonLiveUnreadable AccessReason = "live_policy_unreadable"
	ReasonSameSource     AccessReason = "same_source"
	ReasonCheckUser      AccessReason = "check_user"
	ReasonPastCap        AccessReason = "past_cap"
	ReasonNotRecorded    AccessReason = "audit_unrecorded"
	// ReasonCanaryCoordinates: the pair names the coordinates of tailkeeper's own canary (the
	// address 192.0.2.1 on port 1; the user canary on 192.0.2.1), where a reply that proves the
	// canary and holds nothing for the source reads as the canary's own line does.
	ReasonCanaryCoordinates AccessReason = "canary_coordinates"
)

var reasonSentences = map[AccessReason]string{
	ReasonNoWitness:      "no validation was made for this pair",
	ReasonCanary:         "Tailscale's answer did not show the canary once, in its grammar, so nothing in it is a verdict",
	ReasonLiveChanged:    "the live policy changed, or could not be shown unchanged, while it was checked",
	ReasonUnparseable:    "a line of Tailscale's answer is not in the grammar this version reads",
	ReasonUnresolved:     "Tailscale could not evaluate a name or a destination of this test",
	ReasonUnpaired:       "a line of Tailscale's answer matches no single pair of this call",
	ReasonDisagree:       "the lines of Tailscale's answer for this pair do not agree",
	ReasonRateLimited:    "tailkeeper's own limit on validation requests was used up",
	ReasonRequestFailed:  "the validation request did not complete",
	ReasonRefused:        "Tailscale refused the text built from the live policy",
	ReasonLiveErrors:     "Tailscale stored errors with the live policy, so it would not be accepted as it is",
	ReasonLiveUnreadable: "this version of tailkeeper cannot read the live policy",
	ReasonSameSource:     "another selected expectation with this source has other terms, and one request holds one test for a source",
	ReasonCheckUser:      "a check user with no line is not a pass: the form a check failure takes was not observed",
	ReasonPastCap:        "past the number of pairs one run judges",
	ReasonNotRecorded:    "the audit log could not record the validation request that would answer this pair, so no verdict is made from it",

	ReasonCanaryCoordinates: "it names the destination, or the SSH user and destination, of tailkeeper's own canary test, so no reply can show it apart from the canary",
}

// ReasonSentence is the fixed sentence of a reason, or "" for a word that is none.
func ReasonSentence(r AccessReason) string { return reasonSentences[r] }

// AccessLimit is a case the test language cannot express, so that an answer holds only for
// what it can. An expectation with one is at best met_with_limits.
type AccessLimit string

const (
	LimitPosture AccessLimit = "posture"
	LimitApp     AccessLimit = "app"
	LimitVia     AccessLimit = "via"
	LimitSource  AccessLimit = "source"
	// LimitRules: some rules of the live policy could not be listed or read, or the search of them
	// was cut short (the work limit, a cancelled call), so whether a rule that depends on posture,
	// carries app capabilities or routes through via applies to the expectation cannot be ruled out.
	LimitRules AccessLimit = "rules"
)

var limitSentences = map[AccessLimit]string{
	LimitPosture: "A rule of the live policy that is not shown to name only other destinations (for an SSH expectation, nor to be about only other users), or the policy's defaultSrcPosture, depends on device posture, and this expectation gives no posture attributes: the answer holds for a device that reports none, and tailkeeper does not guess a device's posture.",
	LimitApp:     "A grant of the live policy that is not shown to name only other destinations carries app capabilities, which Tailscale's test language cannot express: the answer says nothing about them.",
	LimitVia:     "A grant of the live policy that is not shown to name only other destinations routes through via, which Tailscale's test language cannot express: the answer says nothing about it.",
	LimitSource:  "The source is one Tailscale's test language cannot express (an autogroup), so a verdict for it is not established.",
	LimitRules:   "Some rules of the live policy could not be listed or read here, or the search of them was cut short, so a rule that depends on device posture, carries app capabilities or routes through via cannot be ruled out: the answer holds for what the test language can express.",
}

// LimitSentence is the fixed sentence of a limit, or "" for a word that is none.
func LimitSentence(l AccessLimit) string { return limitSentences[l] }

// The fixed sentences a report states in its own words.
const (
	// NoteNoIntent is the whole report of a run with no intent set.
	NoteNoIntent = "no intent set: nothing explained"
	// NoteEmptySet is the whole report of an intent set that holds no expectation.
	NoteEmptySet = "the intent set holds no expectations: nothing explained"
	// NoteSSHNotNetwork is said once: an SSH verdict and a network verdict are separate answers.
	NoteSSHNotNetwork = "SSH and network access are separate questions: a verdict about SSH says nothing about network reachability of port 22, and a verdict about the network says nothing about SSH."
	// NoteCandidates is said once, beside the first candidate rule list.
	NoteCandidates = "A candidate rule is a rule whose selectors match the pair as text. It is not the rule that grants or denies: every verdict comes from Tailscale's validation of the live policy."
	// NoteCandidatesShort is said with NoteCandidates: a list of candidates may be short, and a
	// verdict is unaffected.
	NoteCandidatesShort = "A list of candidate rules may be incomplete: the protocol of a rule is ignored, and autogroup:member and localpart: selectors are not resolved."
	// NoteRulesPartial is said once when the lists of candidate rules may be short: the live policy
	// has more rules than are listed, rules that are not readable, or could not be read here.
	NoteRulesPartial = "The candidate lists may be short: the live policy has rules that tailkeeper could not list or read, or the search for candidates reached its work limit. Every verdict is unaffected."
	// NoteAssumption is said once, beside the first blast radius.
	NoteAssumption = "A blast radius is an assumption about a compromised source, not a finding: policy reachability is not that a service listens, a credential works or an exploit succeeds."
)

// BlastHeading is the heading of the blast radius of a source.
func BlastHeading(source string) string {
	return "if " + source + " were compromised, the live policy would let it reach:"
}

// AccessCell is one pair an expectation asks about. Expect is accept, deny or check. A network
// pair is a destination (host:port) and no user; an SSH pair is a destination and an SSH user.
type AccessCell struct {
	Expect      string `json:"expect"`
	Destination string `json:"destination"`
	User        string `json:"user,omitempty"`
}

// AccessProof is the evidence of a witness. A witness with no canary is not a verdict, and a
// verdict that the policy is as asked needs the live policy to be shown unchanged. The zero
// value proves nothing.
type AccessProof struct {
	Canary        bool `json:"canary"`
	LiveUnchanged bool `json:"liveUnchanged"`
}

// AccessWitness is what Tailscale's validation of the live policy showed for one pair.
type AccessWitness struct {
	Expectation string         `json:"expectation"`
	Cell        AccessCell     `json:"cell"`
	Observed    AccessObserved `json:"observed"`
	Reason      AccessReason   `json:"reason,omitempty"`
	Proof       AccessProof    `json:"proof"`
}

// RuleRef is a candidate rule: the place of a rule of acls, grants or ssh whose selectors match
// a pair as text. It is a pointer into the policy and not a verdict.
type RuleRef struct {
	Section     string `json:"section"`
	Index       int    `json:"index"`
	Line        int    `json:"line,omitempty"`
	Column      int    `json:"column,omitempty"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	// Ports is the rule's port text when it limits them; "" for all.
	Ports string `json:"ports,omitempty"`
	// Broad: the rule's destination selector is "*".
	Broad bool `json:"broad,omitempty"`
	// Qualified: the rule is gated on srcPosture, or the policy has a defaultSrcPosture (which
	// gates every rule), or the rule carries app capabilities or routes through via. A qualified
	// rule is a place to look and never a statement that the source reaches every destination.
	Qualified bool `json:"qualified,omitempty"`
	// AllTraffic: the rule allows every port and every protocol (an acls destination with the
	// ports * and no proto; a grant whose ip entries include *). Traffic is then empty.
	AllTraffic bool `json:"allTraffic,omitempty"`
	// Traffic is what a rule that does not allow all of it writes about the ports and protocols
	// it allows: an acls rule's proto and ports, a grant's ip entries, as written. It is empty
	// when AllTraffic is set, and when the rule writes nothing to quote (a grant with no ip).
	Traffic string `json:"traffic,omitempty"`
}

// AccessCandidates are the candidate rules of one expectation. Omitted counts the matches the
// list does not hold.
type AccessCandidates struct {
	Rules   []RuleRef `json:"rules,omitempty"`
	Omitted int       `json:"omitted,omitempty"`
}

// AccessOwner is a tagOwners fact: the tags a source may apply to a device. Applying one makes
// that tag's rules apply to the device, which is how ownership differs from access.
type AccessOwner struct {
	Source  string   `json:"source"`
	Tags    []string `json:"tags"`
	Omitted int      `json:"omitted,omitempty"`
}

// AccessInput is everything ExplainAccess judges by. The intent set is the selected
// expectations only (Digest and Revision are the whole file's); everything else is already
// bounded and typed by whoever made it.
type AccessInput struct {
	// NoIntent: no intent set was supplied. Intent must then be empty.
	NoIntent bool
	Intent   IntentSet
	// Limit is the most pairs judged; 0 and anything above MaxAccessPairs mean MaxAccessPairs.
	Limit      int
	Witnesses  []AccessWitness
	Candidates map[string]AccessCandidates
	Limits     map[string][]AccessLimit
	Owners     []AccessOwner
	// RulesPartial: the candidate lists may be short (see NoteRulesPartial).
	RulesPartial  bool
	PolicyVersion string
	EvaluatedAt   time.Time
}

// PlannedExpectation is the pairs an expectation asks about that this run judges, in the order
// they are judged, and how many it asks about past the limit. Only the pairs that are judged
// are made: the rest are counted, never listed, so that a list of thousands of destinations and
// thousands of users costs the limit and not their product.
type PlannedExpectation struct {
	ID     string
	Kind   AccessKind
	Source string
	Cells  []AccessCell
	// PastCap counts the pairs left out past the limit. It saturates rather than overflows.
	PastCap int
}

// pairList is the pairs of one list of an expectation, as a product that is not expanded: every
// destination with every user (a network pair has the one user ""), accept, deny or check.
type pairList struct {
	expect string
	dsts   []string
	users  []string
}

// size is the number of pairs the list holds, saturating at the largest int.
func (l pairList) size() int { return satMul(len(l.dsts), len(l.users)) }

func satMul(a, b int) int {
	if a == 0 || b == 0 {
		return 0
	}
	if a > math.MaxInt/b {
		return math.MaxInt
	}
	return a * b
}

func satAdd(a, b int) int {
	if a > math.MaxInt-b {
		return math.MaxInt
	}
	return a + b
}

// uniqueOf is a list once, in its order: a pair listed twice is one pair.
func uniqueOf(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, dup := seen[s]; !dup {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// PlanAccess lists, for each expectation of the set, the pairs it asks about: the destinations
// of a network test's accept and deny lists, and the users of an SSH test's accept, check and
// deny lists on each of its destinations. Only the expectation's own source and its own
// destinations are ever named: nothing is widened, and no other pair is derived. The first
// limit pairs, in order, are judged and listed; the rest are counted by arithmetic and never
// made. A pair an expectation lists twice is one pair.
func PlanAccess(set IntentSet, limit int) []PlannedExpectation {
	if limit <= 0 || limit > MaxAccessPairs {
		limit = MaxAccessPairs
	}
	var out []PlannedExpectation
	judged := 0
	plan := func(id string, kind AccessKind, source string, lists []pairList) {
		pe := PlannedExpectation{ID: id, Kind: kind, Source: source}
		total := 0
		for _, l := range lists {
			total = satAdd(total, l.size())
		}
	fill:
		for _, l := range lists {
			for _, d := range l.dsts {
				for _, u := range l.users {
					if judged >= limit {
						break fill
					}
					pe.Cells = append(pe.Cells, AccessCell{Expect: l.expect, Destination: d, User: u})
					judged++
				}
			}
		}
		pe.PastCap = total - len(pe.Cells)
		out = append(out, pe)
	}
	for _, e := range set.Network {
		none := []string{""}
		plan(e.ID, AccessNetwork, e.Source, []pairList{
			{"accept", uniqueOf(e.Accept), none}, {"deny", uniqueOf(e.Deny), none},
		})
	}
	for _, e := range set.SSH {
		dsts := uniqueOf(e.Destinations)
		plan(e.ID, AccessSSH, e.Source, []pairList{
			{"accept", dsts, uniqueOf(e.Accept)}, {"check", dsts, uniqueOf(e.Check)}, {"deny", dsts, uniqueOf(e.Deny)},
		})
	}
	return out
}

// AccessCellResult is one judged pair: what was asked, what the live policy was witnessed to
// do, and the verdict that makes of it.
type AccessCellResult struct {
	AccessCell
	Verdict  AccessStatus   `json:"verdict"`
	Observed AccessObserved `json:"observed"`
	Reason   AccessReason   `json:"reason,omitempty"`
	Proof    AccessProof    `json:"proof"`
}

// AccessResult is one expectation's explanation.
type AccessResult struct {
	ID     string       `json:"id"`
	Kind   AccessKind   `json:"kind"`
	Source string       `json:"source"`
	Status AccessStatus `json:"status"`
	// Cells are the pairs judged. PastCap counts the pairs of the expectation that were left
	// out past the cap; they are not listed.
	Cells             []AccessCellResult `json:"cells,omitempty"`
	PastCap           int                `json:"pastCap,omitempty"`
	Candidates        []RuleRef          `json:"candidates,omitempty"`
	CandidatesOmitted int                `json:"candidatesOmitted,omitempty"`
	Limits            []AccessLimit      `json:"limits,omitempty"`
}

// AccessReach is a destination the witnessed pairs show a source could reach.
type AccessReach struct {
	Kind        AccessKind `json:"kind"`
	Destination string     `json:"destination"`
	User        string     `json:"user,omitempty"`
	Expectation string     `json:"expectation"`
}

// AccessBlast is the blast radius of one source: only what the witnessed pairs show as
// reachable, the broad candidate rules that name every destination (with the ports and protocols
// they allow, all of them or what the rule writes), and the tags the source can apply. Heading
// states the assumption.
type AccessBlast struct {
	Source      string        `json:"source"`
	Heading     string        `json:"heading"`
	Reaches     []AccessReach `json:"reaches,omitempty"`
	Broad       []RuleRef     `json:"broad,omitempty"`
	Tags        []string      `json:"tags,omitempty"`
	TagsOmitted int           `json:"tagsOmitted,omitempty"`
}

// AccessCounts counts the selected expectations by status, all of them, listed or not.
type AccessCounts struct {
	Total         int `json:"total"`
	Met           int `json:"met"`
	MetWithLimits int `json:"metWithLimits"`
	Unmet         int `json:"unmet"`
	Unknown       int `json:"unknown"`
	NotEvaluated  int `json:"notEvaluated"`
}

// AccessReport is the explanation. Status is complete only when every selected expectation is
// met with a canary; ExitCode follows the counts and nothing else.
type AccessReport struct {
	SchemaVersion  int           `json:"schemaVersion"`
	Status         AccessOverall `json:"status"`
	NoIntent       bool          `json:"noIntent,omitempty"`
	IntentDigest   string        `json:"intentDigest,omitempty"`
	IntentRevision string        `json:"intentRevision,omitempty"`
	PolicyVersion  string        `json:"policyVersion,omitempty"`
	EvaluatedAt    time.Time     `json:"evaluatedAt"`
	Counts         AccessCounts  `json:"counts"`
	// Proof is the evidence behind every pair that is met, listed or not: the canary came back
	// for each, and the live policy was shown unchanged for each. It is false while no pair is
	// met. A report that counts a met expectation, or is complete, without it does not validate.
	Proof AccessProof `json:"proof"`
	// PairsJudged counts the pairs of all the selected expectations that count against the limit
	// of MaxAccessPairs: the pairs put to Tailscale, and the pairs that were not put to it
	// because another selected expectation with the same source has other terms (they use up
	// the limit all the same). PairsPastCap counts the pairs left out past the limit.
	PairsJudged  int            `json:"pairsJudged"`
	PairsPastCap int            `json:"pairsPastCap"`
	Expectations []AccessResult `json:"expectations,omitempty"`
	// Omitted is the expectations not listed (past MaxAccessRows); the counts include them.
	Omitted int           `json:"omitted,omitempty"`
	Blast   []AccessBlast `json:"blast,omitempty"`
	Notes   []string      `json:"notes,omitempty"`
}

// ExitCode is 8 when any expectation is unmet, else 1 when the report is not complete
// (anything unknown, limited or not evaluated, or no intent), else 0. 8 outranks 1: an unmet
// expectation is the answer even when others are unknown.
func (r AccessReport) ExitCode() int {
	switch {
	case r.Counts.Unmet > 0:
		return 8
	case r.Status != AccessComplete:
		return 1
	}
	return 0
}

// ExplainAccess judges the selected expectations by their witnesses. A pair with no witness is
// unknown, and no pair is met without a witness whose canary was seen and whose live policy was
// shown unchanged. It refuses an input that names a pair nobody asked about, a witness twice, or
// a word outside the closed sets, and it returns no report that does not validate.
func ExplainAccess(in AccessInput) (AccessReport, error) {
	report, _, err := JudgeAccess(in)
	return report, err
}

// AccessJudgement records an expectation's status and limits before the display cap.
type AccessJudgement struct {
	ID     string
	Status AccessStatus
	Limits []AccessLimit
}

// JudgeAccess produces the same report as ExplainAccess and every judgement in plan order.
func JudgeAccess(in AccessInput) (AccessReport, []AccessJudgement, error) {
	plan := PlanAccess(in.Intent, in.Limit)
	if in.NoIntent && len(plan) > 0 {
		return AccessReport{}, nil, errors.New("an access input with no intent set holds expectations")
	}
	byCell, err := indexWitnesses(plan, in.Witnesses)
	if err != nil {
		return AccessReport{}, nil, err
	}
	if err := checkAccessInput(plan, in); err != nil {
		return AccessReport{}, nil, err
	}
	r := AccessReport{
		SchemaVersion: SchemaVersion, NoIntent: in.NoIntent, IntentDigest: in.Intent.Digest, IntentRevision: in.Intent.Revision,
		PolicyVersion: in.PolicyVersion, EvaluatedAt: in.EvaluatedAt,
	}
	var results []AccessResult
	for _, pe := range plan {
		res := explainOne(pe, byCell, in)
		r.PairsJudged += len(res.Cells)
		r.PairsPastCap = satAdd(r.PairsPastCap, res.PastCap) // each is saturated; their sum is too
		r.Counts.add(res.Status)
		results = append(results, res)
	}
	r.Proof = metProof(results)
	r.Blast = blastRadii(results, in)
	r.Notes = reportNotes(r, results, in)
	r.Status = AccessIncomplete
	if r.Counts.Total > 0 && r.Counts.Met == r.Counts.Total {
		r.Status = AccessComplete
	}
	r.Expectations, r.Omitted = listRows(results)
	if err := ValidateAccessReport(r); err != nil {
		return AccessReport{}, nil, fmt.Errorf("explanation made a report that does not validate: %w", err)
	}
	judgements := make([]AccessJudgement, 0, len(results))
	for _, result := range results {
		judgements = append(judgements, AccessJudgement{ID: result.ID, Status: result.Status, Limits: slices.Clone(result.Limits)})
	}
	return r, judgements, nil
}

// metProof is the evidence behind the pairs that are met, listed or not. judgeCell makes a pair
// met only with the canary and the unchanged live policy, so the proof is the same for every one
// of them; the report carries it itself so that its validator can ask for it when rows are
// omitted, and no pair met is no proof.
func metProof(results []AccessResult) AccessProof {
	for _, res := range results {
		for _, c := range res.Cells {
			if c.Verdict == AccessMet {
				return AccessProof{Canary: true, LiveUnchanged: true}
			}
		}
	}
	return AccessProof{}
}

func (c *AccessCounts) add(s AccessStatus) {
	c.Total++
	switch s {
	case AccessMet:
		c.Met++
	case AccessMetWithLimits:
		c.MetWithLimits++
	case AccessUnmet:
		c.Unmet++
	case AccessUnknown:
		c.Unknown++
	case AccessNotEvaluated:
		c.NotEvaluated++
	}
}

type witnessKey struct {
	id   string
	cell AccessCell
}

// indexWitnesses maps each witness to its pair. A witness for an expectation or a pair that
// is not in the plan, for a pair this run does not judge, or a second one for a pair, is an
// error: the witnesses are the only evidence, and a stray one would be evidence of nothing.
func indexWitnesses(plan []PlannedExpectation, ws []AccessWitness) (map[witnessKey]AccessWitness, error) {
	judged := map[witnessKey]bool{}
	for _, pe := range plan {
		for _, c := range pe.Cells {
			judged[witnessKey{pe.ID, c}] = true
		}
	}
	out := make(map[witnessKey]AccessWitness, len(ws))
	for _, w := range ws {
		k := witnessKey{w.Expectation, w.Cell}
		switch {
		case !judged[k]:
			return nil, errors.New("a witness names a pair that no selected expectation asks about, or that this run does not judge")
		case !validObserved(w.Observed):
			return nil, errors.New("a witness has an observation outside the closed set")
		case w.Reason != "" && reasonSentences[w.Reason] == "":
			return nil, errors.New("a witness has a reason outside the closed set")
		}
		if _, dup := out[k]; dup {
			return nil, errors.New("a pair has two witnesses")
		}
		out[k] = w
	}
	return out, nil
}

func validObserved(o AccessObserved) bool {
	switch o {
	case ObservedAllowed, ObservedDenied, ObservedUnknown, ObservedNotAsked:
		return true
	}
	return false
}

// checkAccessInput refuses candidates, limits and owners the input does not tie to a selected
// expectation, and limits and candidates outside their closed forms.
func checkAccessInput(plan []PlannedExpectation, in AccessInput) error {
	ids := map[string]bool{}
	for _, pe := range plan {
		ids[pe.ID] = true
	}
	for id, c := range in.Candidates {
		if !ids[id] {
			return errors.New("candidate rules name an expectation that is not selected")
		}
		for _, ref := range c.Rules {
			if err := validRuleRef(ref); err != nil {
				return err
			}
		}
	}
	for id, ls := range in.Limits {
		if !ids[id] {
			return errors.New("limits name an expectation that is not selected")
		}
		for _, l := range ls {
			if limitSentences[l] == "" {
				return errors.New("a limit is outside the closed set")
			}
		}
	}
	return nil
}

func validRuleRef(r RuleRef) error {
	switch {
	case r.Section != "acls" && r.Section != "grants" && r.Section != "ssh":
		return errors.New("a candidate rule is in no section of acls, grants or ssh")
	case r.Index < 1 || r.Line < 0 || r.Column < 0:
		return errors.New("a candidate rule has a position that is not one")
	case len(r.Source) > MaxTextBytes || len(r.Destination) > MaxTextBytes || len(r.Ports) > MaxTextBytes || len(r.Traffic) > MaxTextBytes:
		return errors.New("a candidate rule holds text past the limit")
	case r.Broad != (r.Destination == "*"):
		return errors.New("a candidate rule's broad flag does not match its destination")
	}
	return validTraffic(r)
}

// validTraffic checks that the ports, the traffic and the flag of a candidate agree: a rule that
// allows every port and protocol limits no ports and writes no limit, and a rule that limits ports
// says what it allows.
func validTraffic(r RuleRef) error {
	switch {
	case r.AllTraffic && r.Traffic != "":
		return errors.New("a candidate rule that allows every port and protocol also lists a limit")
	case r.Ports != "" && r.Traffic == "":
		return errors.New("a candidate rule limited to some ports does not say what it allows, or allows every port and protocol")
	}
	return nil
}

// explainOne judges one expectation.
func explainOne(pe PlannedExpectation, byCell map[witnessKey]AccessWitness, in AccessInput) AccessResult {
	res := AccessResult{ID: pe.ID, Kind: pe.Kind, Source: pe.Source, PastCap: pe.PastCap}
	for _, c := range pe.Cells {
		var w *AccessWitness
		if x, ok := byCell[witnessKey{pe.ID, c}]; ok {
			w = &x
		}
		res.Cells = append(res.Cells, judgeCell(c, w))
	}
	res.Limits = slices.Clone(in.Limits[pe.ID])
	slices.Sort(res.Limits)
	res.Limits = slices.Compact(res.Limits)
	cands := in.Candidates[pe.ID]
	res.Candidates = slices.Clone(cands.Rules)
	res.CandidatesOmitted = cands.Omitted
	if len(res.Candidates) > MaxAccessCandidates {
		res.CandidatesOmitted += len(res.Candidates) - MaxAccessCandidates
		res.Candidates = res.Candidates[:MaxAccessCandidates]
	}
	res.Status = accessStatusOf(res)
	return res
}

// judgeCell makes the verdict of one pair from its witness. The rules that matter: with no
// canary there is no verdict at all, met or unmet, and with a live policy that is not shown
// unchanged there is none either.
func judgeCell(c AccessCell, w *AccessWitness) AccessCellResult {
	r := AccessCellResult{AccessCell: c, Verdict: AccessUnknown, Observed: ObservedUnknown, Reason: ReasonNoWitness}
	if w == nil {
		return r
	}
	r.Observed, r.Reason, r.Proof = w.Observed, w.Reason, w.Proof
	switch {
	case w.Observed == ObservedNotAsked:
		r.Verdict = AccessNotEvaluated
		if r.Reason == "" {
			r.Reason = ReasonNoWitness
		}
	case w.Observed == ObservedUnknown:
		// Nothing was observed, and the reason the witness gives is the reason.
		r.Verdict = AccessUnknown
		if r.Reason == "" {
			r.Reason = ReasonNoWitness
		}
	case !w.Proof.Canary:
		// Something was observed with no canary beside it: it is no verdict, met or unmet.
		r.Verdict, r.Observed, r.Reason = AccessUnknown, ObservedUnknown, ReasonCanary
	case c.Expect == "check":
		r.Verdict, r.Observed, r.Reason = AccessUnknown, ObservedUnknown, ReasonCheckUser
	case !w.Proof.LiveUnchanged:
		// What was witnessed is about a policy that is no longer shown to be the live one, or
		// that could not be read again: it is no verdict, a failure included. An unmet verdict
		// would be a claim about the live policy that nothing now supports.
		r.Verdict, r.Observed, r.Reason = AccessUnknown, ObservedUnknown, ReasonLiveChanged
	case (c.Expect == "accept") == (w.Observed == ObservedAllowed):
		r.Verdict, r.Reason = AccessMet, ""
	default:
		// The policy did the other thing, and was shown unchanged.
		r.Verdict, r.Reason = AccessUnmet, ""
	}
	return r
}

// accessStatusOf is an expectation's status from its pairs: unmet outranks unknown, which outranks
// not evaluated, and only an expectation whose every pair is met is met, with limits if any
// are stated. An expectation that asks about nothing is not evaluated.
func accessStatusOf(res AccessResult) AccessStatus {
	var unmet, unknown, left bool
	met := 0
	for _, c := range res.Cells {
		switch c.Verdict {
		case AccessUnmet:
			unmet = true
		case AccessUnknown:
			unknown = true
		case AccessNotEvaluated:
			left = true
		case AccessMet:
			met++
		}
	}
	switch {
	case unmet:
		return AccessUnmet
	case unknown:
		return AccessUnknown
	case left || res.PastCap > 0 || len(res.Cells) == 0:
		return AccessNotEvaluated
	case len(res.Limits) > 0:
		return AccessMetWithLimits
	}
	return AccessMet
}

// blastRadii collects, for each source in the order it first appears, the pairs the live policy
// was witnessed to allow (an accepted pair that is met, or a denied pair that is unmet), under a
// canary and an unchanged live policy; the broad candidate rules of the source's expectations;
// and the tags the source can apply.
func blastRadii(results []AccessResult, in AccessInput) []AccessBlast {
	var order []string
	by := map[string]*AccessBlast{}
	for _, res := range results {
		b, ok := by[res.Source]
		if !ok {
			b = &AccessBlast{Source: res.Source, Heading: BlastHeading(res.Source)}
			by[res.Source] = b
			order = append(order, res.Source)
		}
		b.addReaches(res)
		b.addBroad(res)
	}
	for _, o := range in.Owners {
		if b, ok := by[o.Source]; ok {
			b.setTags(o)
		}
	}
	var out []AccessBlast
	for _, src := range order {
		b := by[src]
		if len(b.Reaches) > 0 || len(b.Broad) > 0 || len(b.Tags) > 0 {
			out = append(out, *b)
		}
	}
	return out
}

// reaches reports whether a judged pair shows the live policy allowing the traffic, under proof.
func (c AccessCellResult) reaches() bool {
	return c.Observed == ObservedAllowed && c.Proof.Canary && c.Proof.LiveUnchanged
}

func (b *AccessBlast) addReaches(res AccessResult) {
	for _, c := range res.Cells {
		if !c.reaches() {
			continue
		}
		reach := AccessReach{Kind: res.Kind, Destination: c.Destination, User: c.User, Expectation: res.ID}
		if !slices.Contains(b.Reaches, reach) {
			b.Reaches = append(b.Reaches, reach)
		}
	}
}

// addBroad keeps the candidate rules the blast radius states a line for: a plain network rule
// whose destination is "*", with no posture, app capability or via, and with traffic to state
// (the line says "all destinations" only for a rule that allows every port and protocol, and
// otherwise what the rule writes). An ssh rule is about ssh, not about every destination, and a
// qualified rule says less than that; the limit of the expectation already says what the
// qualifier means.
func (b *AccessBlast) addBroad(res AccessResult) {
	for _, ref := range res.Candidates {
		if ref.statesEveryDestination() && !slices.Contains(b.Broad, ref) {
			b.Broad = append(b.Broad, ref)
		}
	}
}

// plain says that a candidate is a network rule with no posture, app capability or via.
func (r RuleRef) plain() bool { return r.Section != "ssh" && !r.Qualified }

// statesEveryDestination says that a candidate is a plain network rule whose destination is *
// (the destination itself, not the flag that says so) and whose traffic is known and consistent:
// every port and protocol, with no ports limited and no limit written, or what the rule limits it
// to, and not both.
func (r RuleRef) statesEveryDestination() bool {
	if r.Destination != "*" || !r.plain() {
		return false
	}
	if r.AllTraffic {
		return r.Ports == "" && r.Traffic == ""
	}
	return r.Traffic != ""
}

// setTags records the tags an owner fact says the source can apply, cut at MaxAccessTags.
func (b *AccessBlast) setTags(o AccessOwner) {
	b.Tags = slices.Clone(o.Tags)
	b.TagsOmitted = o.Omitted
	if len(b.Tags) > MaxAccessTags {
		b.TagsOmitted += len(b.Tags) - MaxAccessTags
		b.Tags = b.Tags[:MaxAccessTags]
	}
}

// reportNotes are the sentences a report states once: why there is nothing, that SSH and
// network are separate, how to read a candidate rule, and what a blast radius is.
func reportNotes(r AccessReport, results []AccessResult, in AccessInput) []string {
	if r.Counts.Total == 0 {
		if r.NoIntent {
			return []string{NoteNoIntent}
		}
		return []string{NoteEmptySet}
	}
	notes := []string{NoteSSHNotNetwork}
	for _, res := range results {
		if len(res.Candidates) > 0 {
			notes = append(notes, NoteCandidates, NoteCandidatesShort)
			break
		}
	}
	if in.RulesPartial {
		notes = append(notes, NoteRulesPartial)
	}
	if len(r.Blast) > 0 {
		notes = append(notes, NoteAssumption)
	}
	return notes
}

// statusRank orders the rows a report lists: what needs attention first.
var statusRank = map[AccessStatus]int{AccessUnmet: 0, AccessUnknown: 1, AccessNotEvaluated: 2, AccessMetWithLimits: 3, AccessMet: 4}

// listRows keeps at most MaxAccessRows rows, the ones that need attention first and the others
// in the order they were given, and counts the rest.
func listRows(results []AccessResult) ([]AccessResult, int) {
	if len(results) <= MaxAccessRows {
		return stableByRank(results), 0
	}
	sorted := stableByRank(results)
	return sorted[:MaxAccessRows], len(sorted) - MaxAccessRows
}

func stableByRank(results []AccessResult) []AccessResult {
	out := slices.Clone(results)
	slices.SortStableFunc(out, func(a, b AccessResult) int { return statusRank[a.Status] - statusRank[b.Status] })
	return out
}

// ValidateAccessReport checks a report before it is used, whoever made it: the closed sets, the
// counts against the rows, and the one rule the whole report rests on, that nothing is met
// without a canary and an unchanged live policy. Every check has its own error text.
func ValidateAccessReport(r AccessReport) error {
	if err := validateAccessHeader(r); err != nil {
		return err
	}
	listed := AccessCounts{}
	for _, res := range r.Expectations {
		if err := validateAccessResult(res); err != nil {
			return err
		}
		listed.add(res.Status)
	}
	if err := validateAccessCounts(r, listed); err != nil {
		return err
	}
	return validateAccessBlast(r)
}

func validateAccessHeader(r AccessReport) error {
	switch {
	case r.SchemaVersion != SchemaVersion:
		return errors.New("unsupported access report schema version")
	case r.Status != AccessComplete && r.Status != AccessIncomplete:
		return errors.New("invalid access report status")
	case r.EvaluatedAt.IsZero() && r.Counts.Total > 0:
		return errors.New("access report evaluation time is missing")
	}
	if err := validateAccessNothing(r); err != nil {
		return err
	}
	return validateAccessBounds(r)
}

// validateAccessNothing checks a report that explains nothing: it says why in one of two fixed
// sentences, and is incomplete.
func validateAccessNothing(r AccessReport) error {
	if r.Counts.Total > 0 {
		if r.NoIntent {
			return errors.New("the no-intent mark disagrees with the report")
		}
		return nil
	}
	switch {
	case r.Status != AccessIncomplete:
		return errors.New("an access report that explains nothing must be incomplete")
	case len(r.Notes) != 1:
		return errors.New("an access report that explains nothing must say why, once")
	case r.Notes[0] != NoteNoIntent && r.Notes[0] != NoteEmptySet:
		return errors.New("an access report that explains nothing says a sentence that is not one of the two")
	case r.NoIntent != (r.Notes[0] == NoteNoIntent):
		return errors.New("the no-intent mark disagrees with the report")
	}
	return nil
}

func validateAccessBounds(r AccessReport) error {
	switch {
	case r.Omitted < 0 || r.PairsJudged < 0 || r.PairsPastCap < 0:
		return errors.New("a negative count in an access report")
	case r.PairsJudged > MaxAccessPairs:
		return errors.New("an access report judged more pairs than one run may")
	case len(r.Expectations) > MaxAccessRows:
		return errors.New("an access report lists more rows than it may")
	}
	return nil
}

func validateAccessResult(res AccessResult) error {
	if res.Kind != AccessNetwork && res.Kind != AccessSSH {
		return errors.New("an expectation is neither network nor ssh")
	}
	if len(res.Source) > MaxTextBytes {
		return errors.New("an expectation's source is past the text limit")
	}
	if len(res.Candidates) > MaxAccessCandidates || res.CandidatesOmitted < 0 || res.PastCap < 0 {
		return errors.New("candidate rules or counts of an expectation are out of bounds")
	}
	for _, ref := range res.Candidates {
		if err := validRuleRef(ref); err != nil {
			return err
		}
	}
	for _, l := range res.Limits {
		if limitSentences[l] == "" {
			return errors.New("a limit is outside the closed set")
		}
	}
	tally := map[AccessStatus]int{}
	for _, c := range res.Cells {
		if err := validateAccessCell(c); err != nil {
			return err
		}
		tally[c.Verdict]++
	}
	return validateAccessStatus(res, tally)
}

func validateAccessCell(c AccessCellResult) error {
	switch c.Expect {
	case "accept", "deny", "check":
	default:
		return errors.New("a pair expects neither accept, deny nor check")
	}
	if len(c.Destination) > MaxTextBytes || len(c.User) > MaxTextBytes {
		return errors.New("a pair holds text past the limit")
	}
	if c.Reason != "" && reasonSentences[c.Reason] == "" {
		return errors.New("a pair has a reason outside the closed set")
	}
	switch c.Verdict {
	case AccessMet, AccessUnmet:
		return validateJudgedCell(c)
	case AccessUnknown, AccessNotEvaluated:
		if c.Reason == "" {
			return errors.New("a pair that is unknown or not evaluated has no reason")
		}
		return nil
	}
	return errors.New("a pair's verdict is outside the closed set")
}

// validateJudgedCell checks a pair that claims a verdict about the policy: it needs the canary
// and the live policy shown unchanged, and the verdict must be what the witnessed observation
// makes of the expectation.
func validateJudgedCell(c AccessCellResult) error {
	switch {
	case !c.Proof.Canary:
		return errors.New("a pair is judged without a canary")
	case !c.Proof.LiveUnchanged:
		return errors.New("a pair is judged without the live policy shown unchanged")
	case c.Observed != ObservedAllowed && c.Observed != ObservedDenied:
		return errors.New("a met or unmet pair was not witnessed to be allowed or denied")
	case c.Expect == "check":
		return errors.New("a check pair cannot be judged")
	case ((c.Expect == "accept") == (c.Observed == ObservedAllowed)) != (c.Verdict == AccessMet):
		return errors.New("a pair's verdict disagrees with what was witnessed")
	}
	return nil
}

// validateAccessStatus checks an expectation's status against the verdicts of its pairs.
func validateAccessStatus(res AccessResult, tally map[AccessStatus]int) error {
	n := len(res.Cells)
	allMet := n > 0 && tally[AccessMet] == n && res.PastCap == 0
	switch res.Status {
	case AccessMet:
		if !allMet || len(res.Limits) > 0 {
			return errors.New("an expectation is met without every pair met, or beside a limit")
		}
	case AccessMetWithLimits:
		if !allMet || len(res.Limits) == 0 {
			return errors.New("an expectation is met with limits without every pair met, or with no limit")
		}
	case AccessUnmet:
		if tally[AccessUnmet] == 0 {
			return errors.New("an expectation is unmet with no pair unmet")
		}
	case AccessUnknown:
		if tally[AccessUnknown] == 0 || tally[AccessUnmet] > 0 {
			return errors.New("an expectation is unknown with no pair unknown, or beside one unmet")
		}
	case AccessNotEvaluated:
		return validateNotEvaluated(res, tally)
	default:
		return errors.New("an expectation's status is outside the closed set")
	}
	return nil
}

func validateNotEvaluated(res AccessResult, tally map[AccessStatus]int) error {
	switch {
	case tally[AccessUnmet] > 0 || tally[AccessUnknown] > 0:
		return errors.New("an expectation is not evaluated beside a pair that is unmet or unknown")
	case tally[AccessNotEvaluated] == 0 && res.PastCap == 0 && len(res.Cells) > 0:
		return errors.New("an expectation is not evaluated with every pair judged")
	}
	return nil
}

// validateAccessCounts checks the counts against the listed rows, and then the overall status
// and the proof against the counts.
func validateAccessCounts(r AccessReport, listed AccessCounts) error {
	c := r.Counts
	sum := c.Met + c.MetWithLimits + c.Unmet + c.Unknown + c.NotEvaluated
	switch {
	case c.Total != sum || c.Total != len(r.Expectations)+r.Omitted:
		return errors.New("the counts of an access report do not add up to its rows")
	case c.below(listed):
		return errors.New("a count of an access report is below the rows it lists")
	case r.Omitted == 0 && c != listed:
		return errors.New("the counts of an access report differ from its rows")
	}
	if err := validateAccessOverall(r); err != nil {
		return err
	}
	return validateAccessPairs(r)
}

// validateAccessOverall checks the overall status and the proof against the counts. The overall
// status is complete only for rows that are all met. A report that counts a met expectation, or is
// complete, carries the proof of the canary and the unchanged live policy itself, whether or not
// rows are omitted: the omitted rows are in the counts, and nothing else in the report speaks for
// them.
func validateAccessOverall(r AccessReport) error {
	c := r.Counts
	switch {
	case r.Status == AccessComplete && (c.Total == 0 || c.Met != c.Total):
		return errors.New("an access report is complete beside a row that is not met")
	case r.Status == AccessIncomplete && c.Total > 0 && c.Met == c.Total:
		return errors.New("an access report is incomplete with every row met")
	case (c.Met > 0 || c.MetWithLimits > 0 || r.Status == AccessComplete) && !(r.Proof.Canary && r.Proof.LiveUnchanged):
		return errors.New("an access report counts a met expectation, or is complete, without the proof of the canary and the unchanged live policy")
	case r.Status == AccessComplete && r.PairsPastCap > 0:
		// Omitted rows cannot be reconciled with the pair counts, but every row a complete report
		// counts is met, and a met row has no pair past the cap.
		return errors.New("an access report is complete with pairs past the cap")
	}
	return nil
}

// below reports whether a count is lower than the same count of the rows that are listed.
func (c AccessCounts) below(listed AccessCounts) bool {
	return c.Met < listed.Met || c.MetWithLimits < listed.MetWithLimits || c.Unmet < listed.Unmet ||
		c.Unknown < listed.Unknown || c.NotEvaluated < listed.NotEvaluated
}

// validateAccessPairs checks the counts of pairs against the rows: they are those of the rows when
// all of them are listed, and when some are left out they include the rows that are not listed, so
// they are at least those of the rows that are.
func validateAccessPairs(r AccessReport) error {
	judged, past := 0, 0
	for _, res := range r.Expectations {
		judged += len(res.Cells)
		past = satAdd(past, res.PastCap)
	}
	if r.Omitted == 0 && (judged != r.PairsJudged || past != r.PairsPastCap) {
		return errors.New("the pair counts of an access report differ from its rows")
	}
	if judged > r.PairsJudged || past > r.PairsPastCap {
		return errors.New("the pair counts of an access report are below its rows")
	}
	return nil
}

// validateAccessBlast checks the blast radii: the heading is the one fixed wording, every
// destination a source is said to reach is one a pair of an expectation of that source, in the
// listed rows, was witnessed to allow, and every broad rule is a candidate of an expectation of
// that source in the listed rows. With rows left out, what a row that is listed proves is still
// checked; only what could come from a row that is not listed cannot be.
func validateAccessBlast(r AccessReport) error {
	rows := blastRows{reaches: map[blastReach]bool{}, listed: map[string]bool{}, candidates: map[blastRule]bool{}}
	for _, res := range r.Expectations {
		rows.listed[res.ID] = true
		for _, c := range res.Cells {
			if c.reaches() {
				rows.reaches[blastReach{res.Source, AccessReach{Kind: res.Kind, Destination: c.Destination, User: c.User, Expectation: res.ID}}] = true
			}
		}
		for _, ref := range res.Candidates {
			rows.candidates[blastRule{res.Source, ref}] = true
		}
	}
	for _, b := range r.Blast {
		if err := validateOneBlast(b, rows, r.Omitted == 0); err != nil {
			return err
		}
	}
	return nil
}

// blastReach is a reach as the blast radius of one source may name it: a reach proves the blast
// radius of the source of the expectation that was witnessed to allow it, and of no other.
type blastReach struct {
	source string
	reach  AccessReach
}

// blastRule is a candidate rule as the blast radius of one source may name it: one of the
// candidates of an expectation of that source.
type blastRule struct {
	source string
	rule   RuleRef
}

// blastRows is what the listed rows of a report prove about its blast radii: the reaches they
// witnessed, the ids of the rows, and the candidate rules of each source.
type blastRows struct {
	reaches    map[blastReach]bool
	listed     map[string]bool
	candidates map[blastRule]bool
}

func validateOneBlast(b AccessBlast, rows blastRows, allListed bool) error {
	if b.Heading != BlastHeading(b.Source) || strings.Contains(b.Heading, "\n") {
		return errors.New("a blast radius does not state its assumption in the fixed words")
	}
	for _, reach := range b.Reaches {
		// A reach that names a row that is listed is proved by that row or by none; one that names a
		// row that is not listed can only be checked when every row is.
		if !rows.reaches[blastReach{b.Source, reach}] && (allListed || rows.listed[reach.Expectation]) {
			return errors.New("a blast radius names a destination no witnessed pair shows as reachable")
		}
	}
	if len(b.Tags) > MaxAccessTags || b.TagsOmitted < 0 {
		return errors.New("the tags of a blast radius are out of bounds")
	}
	for _, ref := range b.Broad {
		if err := validRuleRef(ref); err != nil {
			return err
		}
		if !ref.statesEveryDestination() {
			return errors.New("a broad rule of a blast radius is not a plain network rule with the destination * and its traffic")
		}
		if allListed && !rows.candidates[blastRule{b.Source, ref}] {
			return errors.New("a broad rule of a blast radius is not a candidate of an expectation of its source")
		}
	}
	return nil
}
