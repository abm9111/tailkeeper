package tools

import (
	"fmt"
	"strings"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/security"
)

// shapeExplain turns the pure report into the tool's result. Every word of the owner's (a
// source, a destination, a user, a selector) lands in a field the framework masks and
// sanitizes; the intent set itself, and the text of the policy, are in no field.
func shapeExplain(r security.AccessReport, intent SecurityExplainIntent) SecurityExplainOutput {
	out := SecurityExplainOutput{
		Status: string(r.Status), Intent: intent, PolicyVersion: r.PolicyVersion,
		Counts: SecurityExplainCounts(r.Counts), PairsJudged: r.PairsJudged, PairsPastCap: r.PairsPastCap,
		Omitted: r.Omitted, Notes: r.Notes, Expectations: make([]SecurityExplainRow, 0, len(r.Expectations)),
	}
	if !r.EvaluatedAt.IsZero() {
		out.EvaluatedAt = timeText(r.EvaluatedAt)
	}
	for _, e := range r.Expectations {
		row := SecurityExplainRow{ID: e.ID, Kind: string(e.Kind), Source: e.Source, Status: string(e.Status), PastCap: e.PastCap,
			CandidatesOmitted: e.CandidatesOmitted, Candidates: ruleViews(e.Candidates)}
		for _, c := range e.Cells {
			row.Cells = append(row.Cells, SecurityExplainCell{Expect: c.Expect, Destination: c.Destination, User: c.User, Verdict: string(c.Verdict),
				Observed: string(c.Observed), Reason: string(c.Reason), Canary: c.Proof.Canary, LiveUnchanged: c.Proof.LiveUnchanged})
		}
		for _, l := range e.Limits {
			row.Limits = append(row.Limits, string(l))
		}
		out.Expectations = append(out.Expectations, row)
	}
	for _, b := range r.Blast {
		view := SecurityExplainBlast{Source: b.Source, Heading: b.Heading, Broad: ruleViews(b.Broad), Tags: b.Tags, TagsOmitted: b.TagsOmitted}
		for _, x := range b.Reaches {
			view.Reaches = append(view.Reaches, SecurityExplainReach{Kind: string(x.Kind), Destination: x.Destination, User: x.User, Expectation: x.Expectation})
		}
		out.Blast = append(out.Blast, view)
	}
	return out
}

func ruleViews(refs []security.RuleRef) []SecurityExplainRule {
	var out []SecurityExplainRule
	for _, r := range refs {
		out = append(out, SecurityExplainRule{Section: r.Section, Index: r.Index, Line: r.Line, Column: r.Column,
			Source: r.Source, Destination: r.Destination, Ports: r.Ports, Broad: r.Broad, Qualified: r.Qualified, AllTraffic: r.AllTraffic, Traffic: r.Traffic})
	}
	return out
}

// Report is the human layout every --format renders: the verdict, the facts the explanation
// states about itself, and a finding for each expectation, each pair that is not as asked, each
// limit, each candidate rule and each blast radius. Every finding that holds a word of the
// owner's is marked untrusted, so the layouts print it behind the notice; the level follows the
// exit code.
func (o SecurityExplainOutput) Report() registry.Report {
	rep := registry.Report{Verdict: o.verdict(), Level: o.level(), Facts: o.facts()}
	for _, row := range o.Expectations {
		rep.Findings = append(rep.Findings, row.findings()...)
	}
	for _, b := range o.Blast {
		rep.Findings = append(rep.Findings, b.findings()...)
	}
	return rep
}

func (o SecurityExplainOutput) level() registry.Level {
	switch o.ExitCode() {
	case 0:
		return registry.LevelOK
	case 1:
		return registry.LevelWarn
	}
	return registry.LevelFail
}

func (o SecurityExplainOutput) verdict() string {
	c := o.Counts
	if c.Total == 0 {
		return "explain: " + o.Status + "; " + firstOr(o.Notes, security.NoteEmptySet)
	}
	return fmt.Sprintf("explain: %s; %d met, %d unmet, %d unknown, %d met with limits, %d not evaluated (%s, %s judged, %s past the limit)",
		o.Status, c.Met, c.Unmet, c.Unknown, c.MetWithLimits, c.NotEvaluated, plural(c.Total, "expectation"), plural(o.PairsJudged, "pair"), plural(o.PairsPastCap, "pair"))
}

func firstOr(list []string, or string) string {
	if len(list) > 0 {
		return list[0]
	}
	return or
}

// facts are the statements the explanation makes about itself, each under its label.
func (o SecurityExplainOutput) facts() []registry.Fact {
	var facts []registry.Fact
	if o.Intent.Source != string(intentNone) && o.Intent.Source != "" {
		named := "revision " + o.Intent.Revision
		if o.Intent.Revision == "" {
			named = "no digest (personal data is masked and no privacy key is loaded)"
		}
		facts = append(facts, registry.Fact{Label: "intent", Text: fmt.Sprintf("%s file, %s, %s explained of %d",
			o.Intent.Source, named, plural(o.Intent.Selected, "expectation"), o.Intent.Expectations)})
	}
	if o.EvaluatedAt != "" {
		text := "asked at " + o.EvaluatedAt
		if o.PolicyVersion != "" {
			text += ", live policy version " + o.PolicyVersion
		}
		facts = append(facts, registry.Fact{Label: "witness", Text: text + "; every verdict is Tailscale's validation of the live policy with a canary"})
	}
	if o.PairsPastCap > 0 {
		facts = append(facts, registry.Fact{Label: "not evaluated", Text: fmt.Sprintf("%s past the limit of %d pairs a run judges", plural(o.PairsPastCap, "pair"), security.MaxAccessPairs)})
	}
	if o.Omitted > 0 {
		facts = append(facts, registry.Fact{Label: "omitted", Text: fmt.Sprintf("%s not listed; the counts and the exit code include them", plural(o.Omitted, "expectation"))})
	}
	for _, n := range o.Notes {
		facts = append(facts, registry.Fact{Label: "note", Text: n})
	}
	return facts
}

// statusSeverity is the severity of an expectation's finding: an unmet expectation is an error,
// anything short of met a warning, and met a notice.
func statusSeverity(status string) string {
	switch security.AccessStatus(status) {
	case security.AccessUnmet:
		return "error"
	case security.AccessMet:
		return "notice"
	}
	return "warning"
}

// findings are the lines of one expectation. Each holds the owner's words, so each is untrusted.
func (r SecurityExplainRow) findings() []registry.Finding {
	out := []registry.Finding{{Severity: statusSeverity(r.Status), Untrusted: true,
		Message: fmt.Sprintf("%s · %s · %s · %s", r.ID, r.Kind, r.Source, strings.ReplaceAll(r.Status, "_", " "))}}
	for _, c := range r.Cells {
		if r.Status == string(security.AccessMet) || r.Status == string(security.AccessMetWithLimits) {
			break // every pair of a met expectation was as asked
		}
		sev := "warning"
		if c.Verdict == string(security.AccessUnmet) {
			sev = "error"
		}
		out = append(out, registry.Finding{Severity: sev, Untrusted: true, Message: r.ID + " · " + c.line()})
	}
	if r.PastCap > 0 {
		out = append(out, registry.Finding{Severity: "warning", Message: fmt.Sprintf("%s · %s not evaluated: %s", r.ID, plural(r.PastCap, "pair"), security.ReasonSentence(security.ReasonPastCap))})
	}
	for _, l := range r.Limits {
		out = append(out, registry.Finding{Severity: "warning", Message: r.ID + " · limit · " + security.LimitSentence(security.AccessLimit(l))})
	}
	for _, c := range r.Candidates {
		out = append(out, c.finding(r.ID+" · candidate rule (a text match, not a verdict)"))
	}
	if r.CandidatesOmitted > 0 {
		out = append(out, registry.Finding{Severity: "notice", Message: fmt.Sprintf("%s · %s candidate rule not listed", r.ID, plural(r.CandidatesOmitted, "more"))})
	}
	return out
}

// line is one pair and its witness: the pair, what the live policy was witnessed to do, and the
// verdict, with the reason in the tool's own sentence.
func (c SecurityExplainCell) line() string {
	pair := c.Expect + " " + c.Destination
	if c.User != "" {
		pair += " as " + c.User
	}
	text := fmt.Sprintf("%s · %s", pair, strings.ReplaceAll(c.Verdict, "_", " "))
	switch c.Verdict {
	case string(security.AccessUnmet):
		text += " · the live policy " + c.Observed + " it, which is the other thing"
	case string(security.AccessUnknown), string(security.AccessNotEvaluated):
		text += " · " + security.ReasonSentence(security.AccessReason(c.Reason))
	}
	return text
}

// finding is a candidate rule laid out at its place in the live policy.
func (r SecurityExplainRule) finding(prefix string) registry.Finding {
	text := fmt.Sprintf("%s · %s[%d] · source %s · destination %s", prefix, r.Section, r.Index, r.Source, r.Destination)
	if r.Ports != "" {
		text += " · ports " + r.Ports
	}
	if r.Qualified {
		text += " · qualified by srcPosture or defaultSrcPosture, app capabilities or via"
	}
	return registry.Finding{Severity: "notice", Source: "live", Line: r.Line, Column: r.Column, Message: text, Untrusted: true}
}

// findings are the lines of one blast radius: the assumption, the pairs, the broad rules and the
// tags, in the fixed wording.
func (b SecurityExplainBlast) findings() []registry.Finding {
	out := []registry.Finding{{Severity: "notice", Untrusted: true, Message: b.Heading}}
	for _, x := range b.Reaches {
		dest := x.Destination
		if x.User != "" {
			dest += " as " + x.User
		}
		out = append(out, registry.Finding{Severity: "notice", Untrusted: true, Message: fmt.Sprintf("  %s %s (%s)", x.Kind, dest, x.Expectation)})
	}
	for _, r := range b.Broad {
		text := "  policy grants this source all destinations"
		if !r.AllTraffic {
			text = "  policy grants this source every destination on " + r.Traffic
		}
		text += fmt.Sprintf(" (candidate rule at %d:%d)", r.Line, r.Column)
		out = append(out, registry.Finding{Severity: "notice", Untrusted: true, Message: text})
	}
	for _, t := range b.Tags {
		out = append(out, registry.Finding{Severity: "notice", Untrusted: true, Message: "  assumption: can apply " + t + " (tagOwners), whose rules would then apply"})
	}
	if b.TagsOmitted > 0 {
		out = append(out, registry.Finding{Severity: "notice", Message: fmt.Sprintf("  %s not listed", plural(b.TagsOmitted, "more tag"))})
	}
	return out
}
