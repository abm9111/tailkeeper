package tools

import (
	"context"
	"fmt"

	"regexp"
	"strconv"
	"strings"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// ACLTestInput is one test: a source and the destinations it must or must not reach.
type ACLTestInput struct {
	Src             string            `json:"src" jsonschema:"the source: a tag, a group (a synced group may contain spaces), a host alias, a tailnet address, or a user named by the pseudonym users_list shows"`
	Accept          []string          `json:"accept,omitempty" jsonschema:"destinations src must reach, as host:port (tag:prod:22, 100.64.0.5:443, [fd7a:115c:a1e0::5]:22)"`
	Deny            []string          `json:"deny,omitempty" jsonschema:"destinations src must not reach, as host:port"`
	Proto           string            `json:"proto,omitempty" jsonschema:"IP protocol, a name such as tcp, udp or icmp, or a number from 1 to 255; icmp needs port 0. Needs accept or deny destinations: an SSH-only call refuses it"`
	SrcPostureAttrs map[string]any    `json:"srcPostureAttrs,omitempty" cli:"json:src-posture-attrs" jsonschema:"posture attributes passed through to the test, at most 16: a name such as node:tsVersion or custom:my_attr (a lower-case letter, then letters, digits and : . - _) with a string, number or bool value. Refused together with ssh"`
	SSH             []ACLSSHTestInput `json:"ssh,omitempty" cli:"json:ssh" jsonschema:"SSH tests of this source, at most 8: each names up to 32 destinations with no port and up to 16 users in accept, check or deny"`
}

// ACLTestOutput is the live policy's answer for the posted source.
type ACLTestOutput struct {
	Status         string           `json:"status" jsonschema:"pass: every destination matched as asked; fail: an assertion failed; unresolved: a name could not be evaluated; unknown: a line could not be paired, which is not a pass"`
	Verdicts       []ACLTestVerdict `json:"verdicts,omitempty"`
	SSHVerdicts    []ACLSSHVerdict  `json:"sshVerdicts,omitempty"`
	Omitted        int              `json:"omitted,omitempty" jsonschema:"SSH verdicts left out past the cap; the status counts them, and the ones not as asked are listed first"`
	SSHNotAsked    int              `json:"sshNotAsked,omitempty" jsonschema:"SSH verdicts that are not what their test asked for, counting those left out of the list"`
	SSHError       string           `json:"sshError,omitempty" tk:"untrusted,emails" jsonschema:"set when the SSH half of a call that also had destinations did not run: the error. The tests half is kept and the SSH verdicts are unknown"`
	OmittedLines   int              `json:"omittedLines,omitempty" jsonschema:"lines of Tailscale's text left out of failures, unmatched, warnings and otherTests past their caps; none of them changes the status"`
	Failures       []ACLTestResult  `json:"failures,omitempty" tk:"details"`
	Unmatched      []string         `json:"unmatched,omitempty" tk:"untrusted,emails,details"`
	OtherTests     []ACLTestResult  `json:"otherTests,omitempty" tk:"details"`
	Warnings       []string         `json:"warnings,omitempty" tk:"untrusted,emails,details"`
	Posture        string           `json:"posture" jsonschema:"none when the live policy does not gate on posture, gated when it does, unknown when the policy could not be read"`
	PosturesNeeded []string         `json:"posturesNeeded,omitempty" tk:"untrusted,emails" jsonschema:"the posture attributes the live policy names"`
	PostureNote    string           `json:"postureNote,omitempty" jsonschema:"set when the live policy could not be read, or when it names more attributes than this result lists"`
	Caveats        []string         `json:"caveats,omitempty" jsonschema:"fixed sentences about how a verdict was read"`
	EvaluatedAt    string           `json:"evaluatedAt"`
	Note           string           `json:"note"`
}

// ACLTestVerdict is what the reply says about one destination, as the caller wrote it.
type ACLTestVerdict struct {
	Dst       string   `json:"dst" tk:"untrusted,emails" jsonschema:"the destination as the caller wrote it"`
	Expect    string   `json:"expect" jsonschema:"accept, deny or accept+deny"`
	Verdict   string   `json:"verdict" jsonschema:"allowed, denied, unresolved or unknown"`
	Why       string   `json:"why,omitempty" jsonschema:"a fixed sentence, when the line alone is not the whole reason"`
	Protocols []string `json:"protocols,omitempty" tk:"untrusted" jsonschema:"the protocol names of the lines that speak for this destination"`
}

// ACLTestResult is Tailscale's reasons for one source.
type ACLTestResult struct {
	Src    string   `json:"src" tk:"untrusted,emails"`
	Errors []string `json:"errors" tk:"untrusted,emails"`
}

// The sentences a result states in its own words. Each list is closed: a field that
// carries one is a constant only while its values stay inside the list.
const (
	aclTestNote = "Evaluated against the live policy. SSH rules are tested only when the call gives ssh. Posture-gated rules match only when srcPostureAttrs names their attributes."

	aclTestSSHNote = "Evaluated against the live policy. SSH tests are a copy of the live policy with its own tests removed, plus an SSH canary, sent to Tailscale, which changes nothing. srcPostureAttrs are refused together with ssh."

	caveatProtoOmitted = "with proto omitted, a destination that must be denied can yield one line for tcp and one for udp"
	caveatBothLists    = "a destination in accept and in deny is told apart by the line's got word"
	caveatHostAddress  = "the server may quote a host alias as its address"
)

// ExitCode is 0 for a pass, 1 for unknown or a status this version does not know,
// 2 for unresolved and 9 for a failed assertion.
func (o ACLTestOutput) ExitCode() int {
	switch o.Status {
	case statusPass:
		return 0
	case statusUnresolved:
		return 2
	case statusFail:
		return 9
	default:
		return 1
	}
}

// Report is the human layout: one verdict line, the facts the result states under their
// labels, what it did not check, then Tailscale's lines behind the notice the layout prints
// for untrusted findings.
func (o ACLTestOutput) Report() registry.Report {
	var facts []registry.Fact
	var notChecked []string
	if o.Note != "" {
		facts = append(facts, registry.Fact{Label: "note", Text: o.Note})
	}
	if o.Posture != "" && o.Posture != postureNone {
		facts = append(facts, registry.Fact{Label: "posture", Text: o.Posture})
	}
	if o.Posture == postureUnknown {
		notChecked = append(notChecked, postureUnproved)
	}
	if o.PostureNote != "" {
		if o.Posture == postureUnknown {
			notChecked = append(notChecked, o.PostureNote)
		} else {
			facts = append(facts, registry.Fact{Label: "posture", Text: o.PostureNote})
		}
	}
	for _, c := range o.Caveats {
		facts = append(facts, registry.Fact{Label: "caveat", Text: c})
	}
	if o.Omitted > 0 {
		facts = append(facts, registry.Fact{Label: "omitted", Text: fmt.Sprintf("%s not listed; the status counts them", plural(o.Omitted, "SSH verdict"))})
	}
	if o.OmittedLines > 0 {
		facts = append(facts, registry.Fact{Label: "omitted", Text: fmt.Sprintf("%s of Tailscale's text not listed; the status does not depend on them", plural(o.OmittedLines, "line"))})
	}
	rep := registry.Report{Facts: facts, NotChecked: notChecked}
	rep.Verdict, rep.Level = o.verdictLine()
	// The names come from the policy: they are findings, behind the notice the layouts print
	// for untrusted text, and not a sentence of tailkeeper's own.
	for _, name := range o.PosturesNeeded {
		rep.Findings = append(rep.Findings, registry.Finding{Severity: "notice", Message: "posture attribute needed: " + name, Untrusted: true})
	}
	if o.SSHError != "" {
		rep.Findings = append(rep.Findings, registry.Finding{Severity: "error", Message: "the SSH tests did not run: " + o.SSHError, Untrusted: true})
	}
	for _, v := range o.Verdicts {
		if v.Why != "" {
			rep.Findings = append(rep.Findings, registry.Finding{Severity: "warning", Message: v.Dst + ": " + v.Why, Untrusted: true})
		}
	}
	for _, v := range o.SSHVerdicts {
		if v.Why != "" {
			rep.Findings = append(rep.Findings, registry.Finding{Severity: "warning", Message: v.Dst + " " + v.User + ": " + v.Why, Untrusted: true})
		}
	}
	seen := map[string]bool{}
	for _, e := range o.Unmatched {
		if seen[e] {
			continue
		}
		seen[e] = true
		rep.Findings = append(rep.Findings, registry.Finding{Severity: "warning", Message: "unpaired line: " + e, Untrusted: true})
	}
	for _, f := range o.Failures {
		for _, e := range f.Errors {
			if seen[e] {
				continue
			}
			rep.Findings = append(rep.Findings, registry.Finding{Severity: "error", Message: "failed  " + f.Src + ": " + e, Untrusted: true})
		}
	}
	for _, w := range o.Warnings {
		rep.Findings = append(rep.Findings, registry.Finding{Severity: "warning", Message: w, Untrusted: true})
	}
	for _, f := range o.OtherTests {
		for _, e := range f.Errors {
			rep.Findings = append(rep.Findings, registry.Finding{Severity: "notice", Message: "other test " + f.Src + ": " + e, Untrusted: true})
		}
	}
	return rep
}

// maxSSHVerdicts is how many SSH verdicts a result lists. The input bounds are 8 tests of
// 32 destinations and 16 users, which is 4,096 verdicts; the status is read from all of them.
const maxSSHVerdicts = 256

// sshNotAsked reports whether an SSH verdict is anything but what its test asked for.
func sshNotAsked(v ACLSSHVerdict) bool {
	return v.Verdict == verdictUnknown || v.Verdict == verdictUnresolved ||
		(v.Expect == expectAccept && v.Verdict == verdictDenied) || (v.Expect == expectDeny && v.Verdict == verdictAllowed)
}

// capSSHVerdicts keeps at most maxSSHVerdicts verdicts, the ones not as asked first, in the
// order they were given, and counts the rest. A verdict left out is one as asked unless more
// than maxSSHVerdicts are not.
func capSSHVerdicts(in []ACLSSHVerdict) ([]ACLSSHVerdict, int) {
	if len(in) <= maxSSHVerdicts {
		return in, 0
	}
	keep := make([]bool, len(in))
	n := 0
	for _, wantBad := range []bool{true, false} {
		for i, v := range in {
			if n < maxSSHVerdicts && !keep[i] && sshNotAsked(v) == wantBad {
				keep[i] = true
				n++
			}
		}
	}
	out := make([]ACLSSHVerdict, 0, n)
	for i, v := range in {
		if keep[i] {
			out = append(out, v)
		}
	}
	return out, len(in) - n
}

// sshBad is how many SSH verdicts are not what their test asked for, at least one: the list
// holds at most maxSSHVerdicts of them, and SSHNotAsked counts them all.
func (o ACLTestOutput) sshBad() int {
	return max(1, o.SSHNotAsked)
}

func (o ACLTestOutput) verdictLine() (string, registry.Level) {
	n := len(o.Verdicts)
	nSSH := len(o.SSHVerdicts) + o.Omitted
	ssh := nSSH > 0
	switch o.Status {
	case statusPass:
		if ssh && n == 0 {
			return fmt.Sprintf("PASS · %s as asked", plural(nSSH, "SSH user")), registry.LevelOK
		}
		if ssh {
			return fmt.Sprintf("PASS · %s and %s as asked", plural(n, "destination"), plural(nSSH, "SSH user")), registry.LevelOK
		}
		return fmt.Sprintf("PASS · %s as asked", plural(n, "destination")), registry.LevelOK
	case statusFail:
		bad := 0
		for _, v := range o.Verdicts {
			if v.Expect == expectBoth || (v.Expect == expectAccept && v.Verdict == verdictDenied) || (v.Expect == expectDeny && v.Verdict == verdictAllowed) {
				bad++
			}
		}
		if ssh && n == 0 {
			return fmt.Sprintf("FAILED · %s not as asked", plural(o.sshBad(), "SSH user")), registry.LevelFail
		}
		if bad == 0 {
			bad = 1
		}
		if ssh {
			return fmt.Sprintf("FAILED · %s and %s not as asked", plural(bad, "destination"), plural(o.sshBad(), "SSH user")), registry.LevelFail
		}
		return fmt.Sprintf("FAILED · %s not as asked", plural(bad, "destination")), registry.LevelFail
	case statusUnresolved:
		return "UNRESOLVED · a name or destination does not resolve", registry.LevelFail
	default:
		return "UNKNOWN · the answer could not be established; this is not a pass", registry.LevelFail
	}
}

// Check refuses a test that is malformed or has nothing to test, before anything is sent.
func (in ACLTestInput) Check() error { return checkACLTest(in) }

func aclTest(ctx context.Context, env *registry.Env, in ACLTestInput) (ACLTestOutput, error) {
	res := NewSubjectResolver(env)
	res.Typed(typedInputs(in)...)
	written := make([]string, 0, len(in.Accept)+len(in.Deny))
	written = append(written, in.Accept...)
	written = append(written, in.Deny...)
	if err := screenTestSubjects(env, in.Src, written); err != nil {
		return ACLTestOutput{}, res.HideError(err)
	}
	if err := screenTestSubjects(env, in.Src, sshDestinations(in.SSH)); err != nil {
		return ACLTestOutput{}, res.HideError(err)
	}
	c, err := env.RequireAPI()
	if err != nil {
		return ACLTestOutput{}, res.HideError(err)
	}
	var out ACLTestOutput
	var said testMessages
	if len(written) > 0 {
		out, said, err = runTestsMode(ctx, env, res, c, in, written)
		if err != nil {
			return ACLTestOutput{}, res.HideError(err)
		}
	}
	if len(in.SSH) > 0 {
		ssh, sshErr := runSSHTests(ctx, res, c, in)
		if sshErr != nil {
			if len(written) == 0 {
				return ACLTestOutput{}, res.HideError(sshErr)
			}
			// The tests half was answered and its token spent: it is kept, and the SSH half
			// reads as not run, which is not a pass.
			ssh = sshSent{src: in.Src, tests: in.SSH}.unknown()
			out.SSHError = sshNotRunNote(res.HideError(sshErr))
		}
		if len(written) == 0 {
			_, posture, postures, postureNote := postureNeeds(ctx, c)
			out = ACLTestOutput{
				Status:         ssh.Status,
				EvaluatedAt:    env.Clock().UTC().Format("2006-01-02T15:04:05Z"),
				Note:           aclTestSSHNote,
				Posture:        posture,
				PosturesNeeded: testLines(res, env, postures),
				PostureNote:    postureNote,
			}
		} else {
			out.Status = worse(out.Status, ssh.Status)
			out.Note = aclTestSSHNote
		}
		out.SSHVerdicts, out.Omitted = capSSHVerdicts(ssh.Verdicts)
		out.SSHNotAsked = ssh.NotAsked
		for i := range out.SSHVerdicts {
			out.SSHVerdicts[i].Dst = echoed(env, out.SSHVerdicts[i].Dst)
			out.SSHVerdicts[i].User = echoed(env, out.SSHVerdicts[i].User)
		}
		said.add(ssh.Messages)
		if ssh.Caveat != "" {
			out.Caveats = append(out.Caveats, ssh.Caveat)
		}
		if note := sshSrcNote(in.Src); note != "" {
			out.Caveats = append(out.Caveats, note)
		}
	}
	shown := said.show(res, env)
	out.Failures, out.Unmatched, out.Warnings, out.OtherTests = shown.failures, shown.unmatched, shown.warnings, shown.other
	out.OmittedLines = shown.omitted
	return out, nil
}

// sshNotRunNote is how a result says the SSH half of the call did not run: the code and the
// message of the error, which is masked already.
func sshNotRunNote(err error) string {
	e := tkerr.From(err)
	return string(e.Code) + ": " + e.Message
}

// sshDestinations is every destination of the SSH tests, in order, with no port.
func sshDestinations(tests []ACLSSHTestInput) []string {
	var out []string
	for _, t := range tests {
		out = append(out, t.Dst...)
	}
	return out
}

// runTestsMode is the tests-mode half of acl_test: one source, its destinations, no SSH. The
// lines Tailscale gave come back as they came; the caller masks and cuts what it shows.
func runTestsMode(ctx context.Context, env *registry.Env, res *SubjectResolver, c *api.Client, in ACLTestInput, written []string) (ACLTestOutput, testMessages, error) {
	hosts, ports, err := destinationHosts(written)
	if err != nil {
		return ACLTestOutput{}, testMessages{}, err
	}
	subjects, err := resolveTestSubjects(ctx, res, in.Src, hosts)
	if err != nil {
		return ACLTestOutput{}, testMessages{}, err
	}
	sent := make([]string, len(subjects.Dsts))
	for i, host := range subjects.Dsts {
		sent[i] = host + ":" + ports[i]
	}
	nAccept := len(in.Accept)
	v, err := c.ValidateTests(ctx, []api.PolicyTest{{
		Src:             subjects.Src,
		Proto:           in.Proto,
		Accept:          sent[:nAccept],
		Deny:            sent[nAccept:],
		SrcPostureAttrs: in.SrcPostureAttrs,
	}})
	if err != nil {
		return ACLTestOutput{}, testMessages{}, err
	}
	policyHosts, posture, postures, postureNote := postureNeeds(ctx, c)
	dests := make([]testDest, len(written))
	for i, shown := range written {
		dests[i] = testDest{Sent: sent[i], Shown: shown, Accept: i < nAccept, Deny: i >= nAccept}
	}
	reading := deriveVerdicts(dests, subjects.Src, policyHosts, v.Results)
	out := ACLTestOutput{
		Status:         reading.Status,
		EvaluatedAt:    env.Clock().UTC().Format("2006-01-02T15:04:05Z"),
		Note:           aclTestNote,
		Posture:        posture,
		PosturesNeeded: testLines(res, env, postures),
		PostureNote:    postureNote,
		Caveats:        testCaveats(in, reading),
	}
	for _, d := range reading.Verdicts {
		vrd := ACLTestVerdict(d)
		vrd.Dst = echoed(env, vrd.Dst)
		for i, p := range vrd.Protocols {
			vrd.Protocols[i] = testLine(res, env, p)
		}
		out.Verdicts = append(out.Verdicts, vrd)
	}
	said := testMessages{unmatched: reading.Unmatched, warnings: postedWarnings(v.Results)}
	for _, r := range v.Results {
		if r.User == subjects.Src && len(r.Errors) > 0 {
			said.failures = append(said.failures, rawEntry{src: r.User, lines: plainLines(r.Errors)})
		}
	}
	for _, r := range reading.Other {
		if len(r.Errors) == 0 && len(r.Warnings) == 0 {
			continue
		}
		said.other = append(said.other, rawEntry{src: r.User, lines: plainLines(append(append([]string{}, r.Errors...), r.Warnings...))})
	}
	return out, said, nil
}

// destinationHosts splits each destination the caller wrote into the host that a
// pseudonym may name and the port that is joined back on after it is resolved.
func destinationHosts(dests []string) (hosts, ports []string, err error) {
	hosts = make([]string, len(dests))
	ports = make([]string, len(dests))
	for i, d := range dests {
		host, port, splitErr := splitDestination(d)
		if splitErr != nil {
			return nil, nil, invalidf("a destination is host:port")
		}
		hosts[i], ports[i] = host, port
	}
	return hosts, ports, nil
}

// testLine shows one line of a reply. Hide masks every login the call resolved and
// then every other address, and cuts on that masked text, so the cut does not move
// when a login is longer.
func testLine(res *SubjectResolver, env *registry.Env, s string) string {
	return messageDisplay(res, env, s)
}

func testLines(res *SubjectResolver, env *registry.Env, in []string) []string {
	if len(in) == 0 {
		return nil
	}
	n := min(len(in), maxTestMessages)
	out := make([]string, 0, n)
	for _, s := range in[:n] {
		out = append(out, testLine(res, env, s))
	}
	return out
}

func postedWarnings(results []api.TestResult) []string {
	var out []string
	for _, r := range results {
		out = append(out, r.Warnings...)
	}
	return out
}

func testCaveats(in ACLTestInput, reading testReading) []string {
	var out []string
	if in.Proto == "" && len(in.Deny) > 0 {
		out = append(out, caveatProtoOmitted)
	}
	for _, v := range reading.Verdicts {
		if v.Expect == expectBoth {
			out = append(out, caveatBothLists)
			break
		}
	}
	for _, v := range reading.Verdicts {
		if v.Why == whyHostAddress {
			out = append(out, caveatHostAddress)
			break
		}
	}
	return out
}

// checkACLTest checks a test's structure, not its meaning: Tailscale decides what
// a source or destination names, and stricter local rules would refuse valid ones.
func checkACLTest(in ACLTestInput) error {
	if strings.TrimSpace(in.Src) == "" {
		return invalidf("src is required")
	}
	if err := checkTestSrc(in.Src); err != nil {
		return err
	}
	n := len(in.Accept) + len(in.Deny)
	if n == 0 && len(in.SSH) == 0 {
		return invalidf("give at least one destination in accept or deny, or one SSH test: a test with none passes without testing anything")
	}
	if n > maxDestinations {
		return invalidf("at most %d destinations per test, not %d", maxDestinations, n)
	}
	if len(in.SSH) > 0 {
		if len(in.SrcPostureAttrs) > 0 {
			return invalidf("srcPostureAttrs cannot be given together with ssh")
		}
		if err := checkSSHTests(in.Src, in.SSH); err != nil {
			return err
		}
	}
	if in.Proto != "" {
		// A protocol qualifies the destinations of accept and deny; an SSH test has none, and a
		// value that nothing reads is refused, not dropped.
		if n == 0 {
			return invalidf("proto applies to the destinations of accept and deny, and this call gives none")
		}
		if !protoRE.MatchString(in.Proto) {
			return invalidf("proto %q must be a protocol name such as tcp, udp or icmp, or a number", in.Proto)
		}
		if n, err := strconv.Atoi(in.Proto); err == nil && (n < 1 || n > 255) {
			return invalidf("proto %d must be between 1 and 255", n)
		}
	}
	if n == 0 {
		return checkPostureAttrs(in.SrcPostureAttrs)
	}
	icmp := map[string]bool{"icmp": true, "1": true, "ipv6-icmp": true, "58": true}[in.Proto]
	for _, list := range []struct {
		name  string
		dests []string
	}{{"accept", in.Accept}, {"deny", in.Deny}} {
		for i, d := range list.dests {
			// Errors name the entry, not its value: an error message is masked like
			// free text, and a public address echoed back would read as a range.
			at := fmt.Sprintf("%s[%d]", list.name, i)
			if err := checkTestDestination(at, d); err != nil {
				return err
			}
			_, port, err := splitDestination(d)
			if err != nil {
				return invalidf("%s: %s", at, err.Error())
			}
			n, conv := strconv.Atoi(port)
			if icmp && (conv != nil || n != 0) {
				return invalidf("%s: ICMP tests use port 0", at)
			}
		}
	}
	return checkPostureAttrs(in.SrcPostureAttrs)
}

var protoRE = regexp.MustCompile(`^[a-z0-9-]{1,16}$`)
