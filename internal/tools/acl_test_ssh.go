package tools

import (
	"context"
	"encoding/json"
	"net/netip"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// ACLSSHVerdict is what the reply says about one SSH user on one destination, as the
// caller wrote them. Expect is accept, check or deny. Verdict is allowed, denied,
// unresolved or unknown. Why, when set, is one of sshVerdictReasons.
type ACLSSHVerdict struct {
	Dst     string `json:"dst" tk:"untrusted,emails" jsonschema:"the destination as the caller wrote it"`
	User    string `json:"user" tk:"untrusted,emails" jsonschema:"the SSH user as the caller wrote it"`
	Expect  string `json:"expect" jsonschema:"accept, check or deny"`
	Verdict string `json:"verdict" jsonschema:"allowed, denied, unresolved or unknown"`
	Why     string `json:"why,omitempty" jsonschema:"a fixed sentence, when the line alone is not the whole reason"`
}

// The sentences an SSH verdict's Why is chosen from, and the two sentences a rejected
// SSH request puts in Caveats. Each is a constant only while its values stay in the list.
const (
	whyCheckSilent    = "a check user with no line is not a pass"
	whySSHUnevaluable = "a line of this SSH test is not in the grammar"
	whySSHNotRun      = "the SSH tests were not shown to have run"
	whySSHUnpaired    = "an SSH line matches no single user"
	whySSHDisagree    = "the lines for this SSH user do not agree"
	caveatLiveInvalid = "the live policy does not validate"
	caveatSSHRefused  = "your SSH tests were refused"
	expectCheck       = "check"
)

// sshReading is what one SSH request made of the reply, after the canary was taken off.
// Messages holds Tailscale's lines as they came: the result masks and cuts what it keeps.
// NotAsked counts every verdict that is not what its test asked for, listed or not.
type sshReading struct {
	Verdicts []ACLSSHVerdict
	NotAsked int
	Messages testMessages
	Caveat   string
	Status   string
}

// sshTestEntry is one sshTests element: the source, the destinations and the user lists
// the caller gave, with empty lists left out.
func sshTestEntry(src string, t ACLSSHTestInput) ([]byte, error) {
	b, err := json.Marshal(struct {
		Src    string   `json:"src"`
		Dst    []string `json:"dst"`
		Accept []string `json:"accept,omitempty"`
		Check  []string `json:"check,omitempty"`
		Deny   []string `json:"deny,omitempty"`
	}{src, t.Dst, t.Accept, t.Check, t.Deny})
	if err != nil {
		return nil, tkerr.Wrap(tkerr.Internal, err, "the SSH test could not be encoded", "this is a tailkeeper bug; report it")
	}
	return b, nil
}

// takeSSHCanary removes the SSH canary. A missing, doubled or unevaluable SSH
// canary is not proof that sshTests ran, so the caller reads the result as unknown.
func takeSSHCanary(pv api.PolicyValidation, src string) (api.PolicyValidation, bool) {
	if src == "" {
		return pv, false
	}
	return api.RemoveCanary(pv, src, func(line string) bool {
		f := ParseFailureLine(line)
		return f.Kind == AssertionFailed && f.SSH && f.User == sshCanaryUser && f.Dst == sshCanaryDst
	})
}

// sshTokens is how many tokens of the validation bucket the SSH request takes. It takes one,
// unless the source is a pseudonym: a login that the call resolved can be tested for the
// accounts it maps to (a rule written localpart:*@domain accepts the SSH user that is the
// local part of the login), and a test of 128 users would then be 128 guesses at a name that
// masking hides, for the price of one request. For a pseudonym source each distinct SSH user
// of the call takes a token of its own, so the guesses stay at the rate of the bucket.
func sshTokens(in ACLTestInput) int {
	if !pseudonymCarrier(in.Src) {
		return 1
	}
	users := map[string]bool{}
	for _, t := range in.SSH {
		for _, list := range [][]string{t.Accept, t.Check, t.Deny} {
			for _, u := range list {
				users[u] = true
			}
		}
	}
	return max(1, len(users))
}

// silentCheckVerdict is the verdict of a check user that no line names. Silence is not
// a pass: the form a check failure takes was not observed.
func silentCheckVerdict() string { return verdictUnknown }

// runSSHTests reads the live policy and sends one policy-mode validation of a copy: the
// live tests and sshTests removed, the caller's SSH tests appended, and the canary. The
// copy is only that. Subjects are the ones the rules allow, resolved from pseudonyms, and
// the request takes the tokens sshTokens gives. A rejection sends the unmodified live
// text once more, and the caveat says which of the two was refused.
func runSSHTests(ctx context.Context, res *SubjectResolver, c *api.Client, in ACLTestInput) (sshReading, error) {
	live, err := c.GetPolicyDetails(ctx)
	if err != nil {
		return sshReading{}, err
	}
	sent, err := sentSSHTests(ctx, res, in)
	if err != nil {
		return sshReading{}, err
	}
	entries := make([][]byte, len(sent.tests))
	for i, t := range sent.tests {
		entries[i], err = sshTestEntry(sent.src, t)
		if err != nil {
			return sshReading{}, err
		}
	}
	built, err := buildInvariantsText(ctx, live.Text, &invariantSet{SSHTests: entries, WithSSHCanary: true}, randomHex8)
	if err != nil {
		return sshReading{}, err
	}
	call, err := c.BeginValidateCharged(ctx, 1, sshTokens(in))
	if err != nil {
		return sshReading{}, err
	}
	pv, err := call.Send(built.Text)
	call.End()
	if err != nil {
		return sshReading{}, err
	}
	switch pv.Status {
	case api.PolicyRejected:
		return sshRejection(ctx, c, live.Text, sent)
	case api.PolicyFail:
		rest, ok := takeCanary(pv, built.Canary, accessStateOf(ctx, built.Text))
		if !ok {
			return sent.unknown(), nil
		}
		rest, ok = takeSSHCanary(rest, built.SSHCanary)
		if !ok {
			return sent.unknown(), nil
		}
		return sent.reading(rest.Results), nil
	default:
		// A pass has no canary, and anything else was not read. Neither is a pass.
		return sent.unknown(), nil
	}
}

// sshRejection tells a refusal of the built copy from a live policy that does not validate.
// The second send is the unmodified live text, and it takes a second token. The server's
// position is not shown: it names a line of the copy, not of the caller's tests.
func sshRejection(ctx context.Context, c *api.Client, live []byte, sent sshSent) (sshReading, error) {
	call, err := c.BeginValidate(ctx, 1)
	if err != nil {
		return sshReading{}, err
	}
	pv, err := call.Send(live)
	call.End()
	if err != nil {
		return sshReading{}, err
	}
	caveat := caveatSSHRefused
	if pv.Status == api.PolicyRejected {
		caveat = caveatLiveInvalid
	}
	out := sent.unknown()
	out.Caveat = caveat
	out.Status = statusUnknown
	return out, nil
}

// sshSent is the caller's SSH tests after pseudonyms were resolved, and the text each
// sent destination was written as.
type sshSent struct {
	src   string
	tests []ACLSSHTestInput
	shown map[string]string
}

func sentSSHTests(ctx context.Context, res *SubjectResolver, in ACLTestInput) (sshSent, error) {
	hosts := make([]string, 0, len(in.SSH))
	for _, t := range in.SSH {
		hosts = append(hosts, t.Dst...)
	}
	subjects, err := resolveTestSubjects(ctx, res, in.Src, hosts)
	if err != nil {
		return sshSent{}, err
	}
	out := sshSent{src: subjects.Src, shown: subjects.Shown, tests: make([]ACLSSHTestInput, len(in.SSH))}
	n := 0
	for i, t := range in.SSH {
		out.tests[i] = ACLSSHTestInput{Accept: t.Accept, Check: t.Check, Deny: t.Deny}
		out.tests[i].Dst = append([]string(nil), subjects.Dsts[n:n+len(t.Dst)]...)
		n += len(t.Dst)
	}
	return out, nil
}

func (s sshSent) unknown() sshReading {
	v, _, _, _ := deriveSSHVerdicts(s.src, s.tests, nil)
	for i := range v {
		v[i].Verdict = verdictUnknown
		v[i].Why = whySSHNotRun
		if w, ok := s.shown[v[i].Dst]; ok {
			v[i].Dst = w
		}
	}
	return sshReading{Verdicts: v, NotAsked: len(v), Status: statusUnknown}
}

// reading reads the reply of the SSH request. The lines of the posted source keep the order
// they came in, each with the caller's test it was paired with.
func (s sshSent) reading(results []api.TestResult) sshReading {
	v, unmatched, status, placed := deriveSSHVerdicts(s.src, s.tests, results)
	notAsked := 0
	for i := range v {
		if sshNotAsked(v[i]) {
			notAsked++
		}
		if w, ok := s.shown[v[i].Dst]; ok {
			v[i].Dst = w
		}
	}
	out := sshReading{Verdicts: v, NotAsked: notAsked, Status: status}
	out.Messages.unmatched = unmatched
	var lines []rawLine
	for _, r := range results {
		if r.User != s.src {
			continue
		}
		for _, e := range r.Errors {
			place := -1
			if n, ok := placed[e]; ok {
				place = n
			}
			lines = append(lines, rawLine{text: e, place: place})
		}
	}
	if len(lines) > 0 {
		out.Messages.failures = []rawEntry{{src: s.src, lines: lines}}
	}
	return out
}

type sshUser struct {
	index  int
	dst    string
	user   string
	expect string
}

func sshUsersOf(tests []ACLSSHTestInput) []sshUser {
	var out []sshUser
	for i, t := range tests {
		for _, list := range []struct {
			expect string
			users  []string
		}{{expectAccept, t.Accept}, {expectCheck, t.Check}, {expectDeny, t.Deny}} {
			for _, dst := range t.Dst {
				for _, user := range list.users {
					out = append(out, sshUser{i, dst, user, list.expect})
				}
			}
		}
	}
	return out
}

// canonicalSSHDst is the form in which two spellings of one SSH destination are equal:
// an IP address through netip, and anything else as written. An SSH destination has no port.
func canonicalSSHDst(d string) string {
	if a, err := netip.ParseAddr(d); err == nil {
		return a.String()
	}
	return d
}

type sshGotLine struct {
	text string
	f    FailureLine
	used bool
}

// sshKey is what pairs a line with a user: the destination the line quotes, in canonical
// form, and the SSH user.
type sshKey struct{ dst, user string }

// deriveSSHVerdicts reads the SSH-form lines of src. A line pairs with one destination and
// one user, by the destination and the ssh user the line quotes. Silence for an accept user
// is allowed, and for a deny user is denied. Silence for a check user is unknown. A line
// outside the grammar, or one that pairs with nobody, makes every user unknown. The lines are
// indexed by the pair once, so the work is that of the users and the lines together, not
// their product. placed maps the text of each line that pairs with a user to the first of the
// caller's tests that holds the pair.
func deriveSSHVerdicts(src string, tests []ACLSSHTestInput, results []api.TestResult) (v []ACLSSHVerdict, unmatched []string, status string, placed map[string]int) {
	users := sshUsersOf(tests)
	keys := make([]sshKey, len(users))
	firstTest := make(map[sshKey]int, len(users))
	for i, u := range users {
		keys[i] = sshKey{canonicalSSHDst(u.dst), u.user}
		if _, seen := firstTest[keys[i]]; !seen {
			firstTest[keys[i]] = u.index
		}
	}
	var lines []sshGotLine
	byKey := map[sshKey][]int{}
	placed = map[string]int{}
	unevaluable := false
	spelled := false
	for _, r := range results {
		if r.User != src {
			// An entry for another source holds no verdict of this call, and a line it
			// holds is never dropped: it is shown, and every user is unknown. The posted
			// source written another way is this call's own, whatever its lines are.
			spelled = spelled || spellsSource(r.User, src)
			unmatched = append(unmatched, r.Errors...)
			continue
		}
		for _, e := range r.Errors {
			f := ParseFailureLine(e)
			if f.Kind != AssertionFailed || !f.SSH {
				unevaluable = true
				unmatched = append(unmatched, e)
				continue
			}
			k := sshKey{canonicalSSHDst(f.Dst), f.User}
			byKey[k] = append(byKey[k], len(lines))
			lines = append(lines, sshGotLine{text: e, f: f})
			if n, ok := firstTest[k]; ok {
				placed[e] = n
			}
		}
	}
	v = make([]ACLSSHVerdict, len(users))
	for i, u := range users {
		v[i] = ACLSSHVerdict{Dst: u.dst, User: u.user, Expect: u.expect}
		var got []sshGotLine
		for _, j := range byKey[keys[i]] {
			got = append(got, lines[j])
			lines[j].used = true
		}
		v[i].Verdict, v[i].Why = sshOne(u.expect, got)
	}
	for _, ln := range lines {
		if !ln.used {
			unmatched = append(unmatched, ln.text)
		}
	}
	if len(unmatched) > 0 || spelled {
		why := whySSHUnpaired
		if spelled {
			why = whySourceSpelling
		}
		if unevaluable {
			why = whySSHUnevaluable
		}
		for i := range v {
			v[i].Verdict = verdictUnknown
			if v[i].Why == "" {
				v[i].Why = why
			}
		}
		return v, unmatched, statusUnknown, placed
	}
	return v, unmatched, sshStatus(v), placed
}

func sshOne(expect string, lines []sshGotLine) (verdict, why string) {
	if expect == expectCheck {
		if len(lines) == 0 {
			return silentCheckVerdict(), whyCheckSilent
		}
		return verdictUnknown, whySSHUnevaluable
	}
	if len(lines) == 0 {
		if expect == expectDeny {
			return verdictDenied, ""
		}
		return verdictAllowed, ""
	}
	if len(lines) > 1 {
		for _, ln := range lines[1:] {
			if ln.f.Got != lines[0].f.Got || ln.f.Want != lines[0].f.Want {
				return verdictUnknown, whySSHDisagree
			}
		}
	}
	f := lines[0].f
	if (expect == expectAccept && f.Want != "accept") || (expect == expectDeny && f.Want != "deny") {
		return verdictUnknown, whySSHDisagree
	}
	if f.Got == "accept" {
		return verdictAllowed, ""
	}
	return verdictDenied, ""
}

func sshStatus(v []ACLSSHVerdict) string {
	st := statusPass
	for _, one := range v {
		switch {
		case one.Verdict == verdictUnknown:
			st = worse(st, statusUnknown)
		case one.Expect == expectAccept && one.Verdict == verdictDenied:
			st = worse(st, statusFail)
		case one.Expect == expectDeny && one.Verdict == verdictAllowed:
			st = worse(st, statusFail)
		case one.Expect == expectCheck:
			st = worse(st, statusUnknown)
		}
	}
	return st
}
