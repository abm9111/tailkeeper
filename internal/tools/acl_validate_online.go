package tools

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// The caps on what a reply is allowed to put in a result. The registry masks before it caps,
// so the tool bounds what it hands over: at most this many entries of a reply are read, this
// many messages of an entry, this many places for one message, and, over all of it, this many
// problems in the result. The three first caps multiply (64 entries of 64 messages of 8 places
// is 32,768 problems), so the last one is what bounds the result: a problem carries a message
// and a pointer of at most 4 KiB each, which JSON writes in at most 6 times their size, and a
// result is sent twice (its structured content and its text), so 64 problems are at most about
// 6 MiB of a frame of 16 MiB, and a few tens of KiB in any ordinary case. What is left out is
// counted in Omitted.
const (
	maxReplyEntries  = 64
	maxEntryMessages = 64
	maxCandidates    = 8
	maxProblems      = 64
)

// capProblems keeps the first maxProblems problems of a result and counts the rest in
// Omitted. The errors come first, since they are what made the status; then the new warnings,
// which --fail-on counts, so one survives whenever there are no errors; then the notices and
// the existing warnings. The status is never read from these lists, so cutting them changes
// no status.
func (o *ACLValidateOutput) capProblems() {
	room := maxProblems
	keep := func(list []ACLProblem) []ACLProblem {
		if len(list) <= room {
			room -= len(list)
			return list
		}
		o.Omitted += len(list) - room
		list, room = list[:room:room], 0
		return list
	}
	o.Errors = keep(o.Errors)
	listed := len(o.NewWarnings)
	o.NewWarnings = keep(o.NewWarnings)
	o.NewWarningsOmitted += listed - len(o.NewWarnings) // --fail-on warnings counts them still
	o.Notices = keep(o.Notices)
	o.ExistingWarnings = keep(o.ExistingWarnings)
}

// online is the part of a validation that talks to Tailscale: it reads the live policy
// (one details request: the text, its ETag and the warnings it already has), compares the
// text to validate with it, sends that text to the validate endpoint in policy mode, reads the
// live policy once more to see that it did not change meanwhile, and reads whether the policy
// is managed elsewhere. When invariants apply, the same text is validated a second time with
// them in place of its own tests. An error leaves through the resolver, which masks any login
// it handed out, and a result is cut to maxProblems problems.
func (v *validation) online(ctx context.Context, c *api.Client) (out ACLValidateOutput, err error) {
	defer func() {
		if err != nil {
			err = v.res.HideError(err)
			return
		}
		out.capProblems()
	}()
	// A call that gives neither a policy nor a patch validates the live policy. An empty policy
	// is no policy, so a caller who meant to send a text and sent an empty one is told, in the
	// result, that what passed was the live policy and not its text.
	v.out.ValidatedLive = v.in.Policy == "" && v.in.Patch == ""
	// The invariants are read before anything is requested: a file that is set and cannot be
	// read is an error for every call that uses it, and one that is not an invariants file is
	// an invalid result, with nothing sent.
	inv, invProblems, err := loadInvariants(ctx, v.env, v.in)
	if err != nil {
		return ACLValidateOutput{}, err
	}
	for _, p := range invProblems {
		v.add(v.hidden(p))
	}
	if len(invProblems) > 0 {
		v.out.Status = statusInvalid
		v.out.NotChecked = append(v.out.NotChecked, "invariants")
		return v.out, nil
	}
	if inv != nil && len(inv.Tests)+len(inv.SSHTests) == 0 {
		// A file with no tests runs nothing, and a second request that carries only the canary
		// would cost a token to find that out: say so and send the one.
		v.add(v.problem(kindNote, severityNotice, sourceInvariants, "the invariants file holds no tests, so none were run"))
		inv = nil
	}
	live, err := c.GetPolicyDetails(ctx)
	if err != nil {
		return ACLValidateOutput{}, err
	}
	v.out.DependsOnLiveState = true
	v.out.PolicyVersion = policyVersion(v.env, live.ETag)
	_, _, _, v.out.PolicySHA256 = maskedPolicy(v.env, string(live.Text))

	liveDoc, err := v.readLive(ctx, live)
	if err != nil {
		return ACLValidateOutput{}, err
	}
	if liveDoc == nil {
		// The live policy is not one this version can read, so there is nothing to compare
		// the text with and nothing is sent.
		v.externalFacts(ctx)
		return v.out, nil
	}
	prop, problems, err := v.prepare(ctx, live, liveDoc)
	if err != nil {
		return ACLValidateOutput{}, err
	}
	for _, p := range problems {
		v.add(p)
	}
	if prop == nil {
		// The text is not one that can be sent: it is invalid, and nothing is sent.
		v.out.Status = statusInvalid
		v.notRun(inv)
		v.externalFacts(ctx)
		return v.out, nil
	}
	sent, sentDoc, source := prop.Sent, prop.Doc, prop.Source
	if err := v.patched(ctx, prop); err != nil {
		return ACLValidateOutput{}, err
	}
	// A text that is the live policy byte for byte has its warnings in the baseline by
	// definition: the ETag is the SHA-256 of the body (probe A-13), so the bytes decide.
	identical := bytes.Equal(sent, live.Text) || (live.ETag != "" && api.ETagOf(sent) == live.ETag)
	if err := v.compare(ctx, liveDoc, sentDoc, identical); err != nil {
		return ACLValidateOutput{}, err
	}
	v.out.IdenticalToLive = identical
	v.storedErrors(live.Errors)
	if prop.Source == sourceLive && len(live.Errors) > 0 {
		// The live policy has errors Tailscale stored with it: validating it would be
		// rejected, and the stored errors say why. Only the live policy itself: a patch or a
		// proposal is another text, which may be what fixes them, and Tailscale judges it.
		v.out.Status = statusRejected
		v.out.rejections += len(live.Errors)
		v.add(v.problem(kindNote, severityError, sourceLive, "Tailscale stored errors with the live policy, so it would not be accepted as it is; they are in serverErrors"))
		v.notRun(inv)
		v.externalFacts(ctx)
		return v.out, nil
	}

	// A call with invariants reserves both its tokens before the first request; the second is
	// given back if the first answer makes the second pointless.
	posts := 1
	if inv != nil {
		posts = 2
	}
	call, err := c.BeginValidate(ctx, posts)
	if err != nil {
		return ACLValidateOutput{}, err
	}
	defer call.End()
	pv, err := call.Send(sent)
	if err != nil {
		return ACLValidateOutput{}, v.sendError(err, sent)
	}
	v.out.ServerChecked = true
	if err := v.read(ctx, pv, live.Warnings, sentDoc, source, identical); err != nil {
		return ACLValidateOutput{}, err
	}
	if inv != nil {
		if err := v.runInvariants(ctx, call, sent, inv); err != nil {
			return ACLValidateOutput{}, err
		}
	}

	// The live policy may have changed while the check ran, and then the verdict is about
	// a policy that no longer exists. A pass is no longer a pass; a failure stays one.
	stamp, err := c.LiveStamp(call.Context())
	if err != nil {
		return ACLValidateOutput{}, err
	}
	if liveMoved(live, stamp) {
		v.out.LiveChanged = true
		if v.out.Status == statusPass {
			v.out.Status = statusUnknown
			v.add(v.problem(kindNote, severityError, "", "the live policy changed while it was being checked, so the answer is about a policy that is no longer the live one"))
		}
	}
	v.externalFacts(ctx)
	return v.out, nil
}

// notRun says that the invariants did not run because no text was sent.
func (v *validation) notRun(inv *invariantSet) {
	if inv != nil {
		v.out.NotChecked = append(v.out.NotChecked, "invariants")
	}
}

// patched records what a patch made: the size of the patched policy, and, with a privacy key,
// a keyed digest of its normal form. The size is the one acl_get shows for a policy (while
// personal data is masked, that of the masked text), never that of the file: the file's own
// size would tell the caller how long the logins are that masking hides, those the live policy
// holds and those a pseudonym of the patch stands for. After the owner applies the change,
// acl_get's summary should show the same digest if the live policy now means exactly what was
// validated.
func (v *validation) patched(ctx context.Context, prop *proposal) error {
	if prop.Source != sourcePatch {
		return nil
	}
	_, _, v.out.PatchedBytes, _ = maskedPolicy(v.env, string(prop.Sent))
	d, err := semanticDigest(ctx, v.env, prop.Doc)
	if err != nil {
		return v.engineError(err)
	}
	v.out.PatchedDigest = d
	return nil
}

// readLive parses the live policy and records what it shows by itself: a key written twice
// or a section this version does not know are notices, since Tailscale stored the policy.
// A live policy this version cannot read at all makes the status unknown, and the result is
// nil.
func (v *validation) readLive(ctx context.Context, live api.PolicyDetails) (*acl.Doc, error) {
	d, err := v.parse(ctx, live.Text)
	if err != nil {
		p, perr := v.parseProblem(live.Text, err, sourceLive)
		if perr != nil {
			return nil, perr
		}
		p.Message = "this version of tailkeeper cannot read the live policy, so nothing was sent: " + p.Message
		v.out.Status = statusUnknown
		v.add(p)
		return nil, nil
	}
	v.structure(d, sourceLive, true)
	return d, nil
}

// compare counts the differences between the text to validate and the live policy by class,
// and the tests on each side. Validating the live policy, or a text that is it byte for
// byte, differs in nothing.
func (v *validation) compare(ctx context.Context, liveDoc, sentDoc *acl.Doc, identical bool) error {
	v.out.Changes = &ACLChangeCounts{}
	if identical || sentDoc == liveDoc {
		s, err := acl.Summarise(ctx, liveDoc)
		if err != nil {
			return v.engineError(err)
		}
		v.out.TestsBefore, v.out.TestsAfter, v.out.SSHTestsBefore, v.out.SSHTestsAfter = s.Tests, s.Tests, s.SSHTests, s.SSHTests
		return nil
	}
	d, err := acl.Diff(ctx, liveDoc, sentDoc, acl.DiffOptions{PageSize: 1})
	if err != nil {
		return v.engineError(err)
	}
	*v.out.Changes = ACLChangeCounts{Defaults: d.Counts.Defaults, TestsReduced: d.Counts.TestsReduced, Widening: d.Counts.Widening,
		TailscaleWritten: d.Counts.TailscaleWritten, Semantic: d.Counts.Semantic, CommentOnly: d.Counts.CommentOnly, FormatOnly: d.Counts.FormatOnly}
	v.out.TestsBefore, v.out.TestsAfter, v.out.SSHTestsBefore, v.out.SSHTestsAfter = d.TestsBefore, d.TestsAfter, d.SSHTestsBefore, d.SSHTestsAfter
	return nil
}

// storedErrors files the errors Tailscale stored with the live policy.
func (v *validation) storedErrors(errs []string) {
	for i, e := range errs {
		if i >= maxEntryMessages {
			v.out.Omitted += len(errs) - i
			return
		}
		v.out.ServerErrors = append(v.out.ServerErrors, v.hide(e))
	}
}

// sendError adds to a 500 that came twice the digest of the masked form of what was sent
// (the same digest acl_get shows for the live policy), so that the owner can tell which text
// failed without the error repeating any of it.
func (v *validation) sendError(err error, sent []byte) error {
	e, ok := tkerr.As(err)
	if !ok || e.Code != tkerr.PolicyRejectedOrServerError {
		return err
	}
	c := *e
	_, _, _, sha := maskedPolicy(v.env, string(sent))
	c.Message += " (policy sha256 " + sha + ")"
	return &c
}

// read turns the strict reader's understanding of Tailscale's answer into a status and its
// problems. A pass is read only from a shape the reader recognised as one; everything else
// is a failure, a rejection, or unknown. doc is the text that was sent, to place a problem
// in it.
func (v *validation) read(ctx context.Context, pv api.PolicyValidation, baseline []string, doc *acl.Doc, source string, identical bool) error {
	switch pv.Status {
	case api.PolicyPass:
		v.out.Status = statusPass
		v.warnings(pv.Results, baseline, source, identical)
	case api.PolicyFail:
		v.warnings(pv.Results, baseline, source, identical)
		return v.failures(ctx, pv.Results, doc, source)
	case api.PolicyRejected:
		v.out.Status = statusRejected
		v.out.rejections++
		pl, err := placeMessage(ctx, doc, "", pv.Message)
		if err != nil {
			return v.engineError(err)
		}
		p := v.problem(kindServerMessage, severityError, "", pv.Message)
		p.FromTailscale = true
		v.addPlaced(p, pl, source)
		if pv.Hint != "" {
			v.add(v.problem(kindNote, severityNotice, "", pv.Hint))
		}
	default:
		v.out.Status = statusUnknown
		v.add(v.problem(kindServerMessage, severityError, "", "Tailscale's answer was not one tailkeeper recognises, so nothing is known about the text: "+pv.Why))
	}
	return nil
}

// failures files the error lines of a failed validation of the text. See fileFailures.
func (v *validation) failures(ctx context.Context, results []api.TestResult, doc *acl.Doc, source string) error {
	status, err := v.fileFailures(ctx, results, replyFiling{doc: doc, source: source, assertion: kindAssertionFailed})
	if err != nil {
		return err
	}
	v.out.Status = status
	return nil
}

// replyFiling says where the lines of a reply are placed and what they are called: the
// document they are about, the source of the problems placed in it, the kind of a failed
// assertion, and the source of the note that says a failure was not read.
type replyFiling struct {
	doc        *acl.Doc
	source     string
	assertion  string
	noteSource string
}

// fileFailures files the error lines of a failed reply, for the validation of the text and
// the validation of the invariants alike, and returns the status the reply makes. A line in the
// want/got grammar is an assertion that failed, whatever the policy allows: the status is fail.
// Any other line says nothing about access (a name that does not resolve, a malformed test):
// it makes the status unresolved when no assertion failed. A line is never read as a verdict
// by a search for words in it. Each line is placed in the document by the test it is about.
// At most maxReplyEntries entries of maxEntryMessages lines are read; Omitted counts the rest.
// What it reads is counted for the verdict: the assertions that failed and the tests that
// could not be evaluated, whatever the number of places a line was filed at.
func (v *validation) fileFailures(ctx context.Context, results []api.TestResult, f replyFiling) (string, error) {
	failed, unevaluable := 0, 0
	for i, r := range results {
		if i >= maxReplyEntries {
			for _, rest := range results[i:] {
				v.out.Omitted += len(rest.Errors)
			}
			break
		}
		for j, line := range r.Errors {
			if j >= maxEntryMessages {
				v.out.Omitted += len(r.Errors) - j
				break
			}
			kind := f.assertion
			if ParseFailureLine(line).Kind == AssertionFailed {
				failed++
			} else {
				kind = kindUnevaluable
				unevaluable++
			}
			pl, err := placeMessage(ctx, f.doc, r.User, line)
			if err != nil {
				return "", v.engineError(err)
			}
			p := v.problem(kind, severityError, "", line)
			p.FromTailscale = true
			v.addPlaced(p, pl, f.source)
		}
	}
	v.out.failedAssertions += failed
	v.out.unevaluableTests += unevaluable
	switch {
	case failed > 0:
		return statusFail, nil
	case unevaluable > 0:
		return statusUnresolved, nil
	}
	// Not a pass either: the reader called the answer a failure, so some entry holds an
	// error, and none was read when it lies past the entries this version reads.
	v.add(v.problem(kindNote, severityError, f.noteSource, "Tailscale reported a failure that tailkeeper did not read, because it lies past the entries of the reply that are read, so this is not a pass"))
	return statusUnknown, nil
}

// warnings files the warnings of a validation. The baseline is the warnings the live policy
// already has (the details request): a warning of the validated text is existing only if the
// baseline holds it word for word, as its text or as the policy element it names followed by
// a colon and its text. A warning that matches none of the two is new, however alike it
// looks: if Tailscale words a stored warning differently in the two places, every warning of
// the live policy reads as new, which fails a gate that should have passed and never passes
// one that should have failed. The spelling of the baseline has not been observed against a
// live policy that has warnings; a check of it has to validate a copy of the live policy that
// is not byte for byte the live policy (a trailing comment is enough), since the rule below
// reads every warning of an identical text as existing without looking at the baseline. A
// warning is filed with its element in the message and no place in the text. Every warning
// of a text that is the live policy byte for byte is existing.
//
// Every warning of the reply is classified, the ones past the 64 entries of 64 messages that
// are listed too: those are not filed, they are counted in Omitted, and a new one among them
// in NewWarningsOmitted, so that a gate on new warnings sees what a listing does not show.
func (v *validation) warnings(results []api.TestResult, baseline []string, source string, identical bool) {
	stored := make(map[string]bool, len(baseline))
	for _, b := range baseline {
		stored[b] = true
	}
	for i, r := range results {
		for j, w := range r.Warnings {
			text := w
			if r.User != "" {
				text = r.User + ": " + w
			}
			existing := identical || stored[w] || stored[text]
			if i >= maxReplyEntries || j >= maxEntryMessages {
				v.out.Omitted++
				if !existing {
					v.out.NewWarningsOmitted++
				}
				continue
			}
			p := v.problem(kindWarning, severityWarning, source, text)
			p.FromTailscale = true
			if existing {
				v.out.ExistingWarnings = append(v.out.ExistingWarnings, p)
			} else {
				v.out.NewWarnings = append(v.out.NewWarnings, p)
			}
		}
	}
}

// liveMoved reports that the live policy read after a validation is not the one read
// before: its body differs, or both reads carried an ETag and the two differ.
func liveMoved(before api.PolicyDetails, after api.PolicyStamp) bool {
	sum := sha256.Sum256(before.Text)
	if after.SHA256 != hex.EncodeToString(sum[:]) {
		return true
	}
	return before.ETag != "" && after.ETag != "" && before.ETag != after.ETag
}

// externalFacts records on the result whether the policy is managed outside the admin
// console: the advisory read that acl_get makes too, so both tools say the same thing.
func (v *validation) externalFacts(ctx context.Context) {
	v.out.ExternallyManaged, v.out.ExternalLink, v.out.ExternallyManagedNote = externalFacts(ctx, v.env)
}
