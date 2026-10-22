package tools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/guard"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/safefile"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// Invariants are tests every validation must also pass, kept by the owner in a file: a
// HuJSON object with a tests array and an sshTests array in the policy's own syntax and
// nothing else. They are checked by a second validation of the same text with its own tests
// taken out and the invariants put in, so that a failure is attributed to the invariants
// (failures are keyed by their source only, and merging the two lists would lose which one
// failed and could trigger Tailscale's false failure for two tests with one source).

// stripTests and appendTests are acl.StripTests and acl.AppendTests. A test replaces them to
// plant a text that still holds a test, or one that gains a test the invariants do not hold,
// which buildInvariantsText must refuse.
var (
	stripTests  = acl.StripTests
	appendTests = acl.AppendTests
)

// loadInvariants finds the invariants a call applies. NoInvariants means none. A file the
// operator named on the command line replaces the configured one. Otherwise the file of the
// configuration is read, which is the only source an MCP call has: it is opened by the rules
// of every file that holds policy content, and by the owner's check, the file and its
// directory belonging to the user who runs tailkeeper and writable by no one else. A path
// that is set and cannot be read is config_invalid (exit 6) on every call that uses it, never
// a silent none. The problems returned are the file's own: a key other than tests and
// sshTests, a pseudonym marker, a syntax error.
func loadInvariants(ctx context.Context, env *registry.Env, in ACLValidateInput) (*invariantSet, []ACLProblem, error) {
	switch {
	case in.NoInvariants:
		return nil, nil, nil
	case in.Invariants != "":
		return parseInvariants(ctx, in.Invariants)
	}
	if env.Config == nil || env.Config.Config.ACL.InvariantsFile == "" {
		return nil, nil, nil
	}
	path := env.Config.Config.ACL.InvariantsFile
	data, err := safefile.Read(path, safefile.Options{Cap: guard.MaxPolicyBytes, Code: tkerr.ConfigInvalid, Verify: config.OwnedBy(os.Getuid())})
	if err != nil {
		return nil, nil, err
	}
	return parseInvariants(ctx, string(data))
}

// invariantsCall is the text of the second validation.
type invariantsCall struct {
	Text   []byte // the sent text with its own tests removed, the invariants and one canary appended
	Canary string // "tag:tailkeeper-canary-" and eight random hexadecimal digits
}

// buildInvariantsText makes the text of the second validation from the text that was sent:
// its own tests removed, the canary's tag added to tagOwners, and the invariants and the
// canary test appended, so that the result is the original plus a tail. It then counts the
// tests of what it built and refuses, without sending anything, unless they are exactly the
// invariants' tests plus the canary and exactly the invariants' SSH tests.
func buildInvariantsText(ctx context.Context, sent []byte, inv *invariantSet, hex8 func() string) (invariantsCall, error) {
	canary := canaryTagPrefix + hex8()
	stripped, err := stripTests(ctx, sent)
	if err != nil {
		return invariantsCall{}, rebuildError(err)
	}
	patch, err := canaryPatch(stripped, canary)
	if err != nil {
		return invariantsCall{}, err
	}
	tagged, err := acl.ApplyPatch(ctx, stripped, patch)
	if err != nil {
		return invariantsCall{}, rebuildError(err)
	}
	tests := append(slices.Clone(inv.Tests), canaryTest(canary))
	text, err := appendTests(ctx, tagged, tests, inv.SSHTests)
	if err != nil {
		return invariantsCall{}, rebuildError(err)
	}
	doc, err := acl.Parse(ctx, text)
	if err != nil {
		return invariantsCall{}, rebuildError(err)
	}
	s, err := acl.Summarise(ctx, doc)
	if err != nil {
		return invariantsCall{}, rebuildError(err)
	}
	if s.Tests != len(inv.Tests)+1 || s.SSHTests != len(inv.SSHTests) || len(doc.Findings()) > 0 {
		return invariantsCall{}, tkerr.New(tkerr.Internal,
			fmt.Sprintf("the text built to check the invariants holds %d tests and %d SSH tests, and should hold %d and %d; nothing was sent", s.Tests, s.SSHTests, len(inv.Tests)+1, len(inv.SSHTests)),
			"this is a tailkeeper bug; report it")
	}
	return invariantsCall{Text: text, Canary: canary}, nil
}

// rebuildError is the error for a text that was just accepted and could not be changed: too
// complex stays so, anything else is a bug.
func rebuildError(err error) error {
	var e *acl.Error
	if errors.As(err, &e) && e.Code == acl.CodeTooComplex {
		return tkerr.New(tkerr.TooComplex, e.Message, "")
	}
	return tkerr.Wrap(tkerr.Internal, err, "the text could not be rebuilt to check the invariants; nothing was sent", "this is a tailkeeper bug; report it")
}

// worse is the more severe of two statuses, in this order: unknown, then fail, then invalid,
// then rejected, then unresolved, then pass.
func worse(a, b string) string {
	rank := map[string]int{statusPass: 0, statusUnresolved: 1, statusRejected: 2, statusInvalid: 3, statusFail: 4, statusUnknown: 5}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// runInvariants is the second validation of a call. It does not run when the first one was
// not a validation of a text Tailscale read (the text was rejected, invalid or unknown): the
// same text would be refused again and cost a token, and the result says what it skipped. It
// takes the second token the call reserved, sends the built text, and reads the answer: the
// canary must be in it once, in the grammar, or the status is unknown; what remains are the
// failures of the invariants, placed in the invariants file itself.
func (v *validation) runInvariants(ctx context.Context, call *api.ValidateCall, sent []byte, inv *invariantSet) error {
	if slices.Contains([]string{statusRejected, statusInvalid, statusUnknown}, v.out.Status) {
		v.out.NotChecked = append(v.out.NotChecked, "invariants")
		v.add(v.problem(kindNote, severityNotice, sourceInvariants, "the invariants were not run: the text itself was not accepted, and the same text would be refused again"))
		return nil
	}
	built, err := buildInvariantsText(ctx, sent, inv, randomHex8)
	if err != nil {
		return err
	}
	pv, err := call.Send(built.Text)
	if err != nil {
		return v.sendError(err, built.Text)
	}
	n := len(inv.Tests) + len(inv.SSHTests)
	switch pv.Status {
	case api.PolicyPass:
		v.out.Status = worse(v.out.Status, statusUnknown)
		v.add(v.problem(kindNote, severityError, sourceInvariants, "Tailscale did not fail the canary test, so there is no sign that the invariants ran: this is not a pass"))
	case api.PolicyRejected:
		v.out.Status = worse(v.out.Status, statusRejected)
		v.out.rejections++
		p := v.problem(kindServerMessage, severityError, "", "while checking the invariants: "+pv.Message)
		p.FromTailscale = true
		v.add(p)
	case api.PolicyFail:
		rest, ok := takeCanary(pv, built.Canary)
		if !ok {
			v.out.Status = worse(v.out.Status, statusUnknown)
			v.add(v.problem(kindNote, severityError, sourceInvariants, "the canary test did not come back once, as one failed assertion: there is no sign that the invariants ran, so this is not a pass"))
			return nil
		}
		v.out.InvariantsApplied = n
		if rest.Status == api.PolicyFail {
			return v.invariantFailures(ctx, rest.Results, inv)
		}
	default:
		v.out.Status = worse(v.out.Status, statusUnknown)
		v.add(v.problem(kindServerMessage, severityError, "", "Tailscale's answer to the invariants was not one tailkeeper recognises: "+pv.Why))
	}
	return nil
}

// invariantFailures files what failed among the invariants. Each line is placed in the
// invariants file by the test it is about, so its line is the file's, however many lines the
// strip removed from the policy. Only the errors of the reply are read: its warnings are those
// of the text, which the first request carried too.
func (v *validation) invariantFailures(ctx context.Context, results []api.TestResult, inv *invariantSet) error {
	status, err := v.fileFailures(ctx, results, replyFiling{doc: inv.Doc, source: sourceInvariants, assertion: kindInvariantFailed, noteSource: sourceInvariants})
	if err != nil {
		return err
	}
	v.out.Status = worse(v.out.Status, status)
	return nil
}
