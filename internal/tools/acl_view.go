package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tripwire"
)

// The helpers the policy tools share: the masked view of a policy text, the version token of
// a policy, the advisory read of who manages the policy, and the two rules for showing a
// string that came from a policy or from Tailscale.

// maskedPolicy prepares each line of a policy as the registry shows it, so that its passes
// change nothing: masked, credential shapes replaced, escaped (a CRLF shown as LF, a lone CR
// escaped), and masked again, since escaping can turn an invisible character into text that
// reads as part of an address. The first pass also rewrites any [p: the policy holds, so a
// marker on the page is one the tool appended; the second must not, since it would rewrite
// those. masked says, per line, that masking changed it. size and sha describe the policy
// as shown, every line joined, while masking is on: the size and hash of the file itself
// would confirm a guessed address, which in a small tailnet is a short list. With
// personalData show they describe the text as it came.
func maskedPolicy(env *registry.Env, text string) (shown []string, masked []bool, size int, sha string) {
	mask := !env.ShowPersonalData()
	mk := env.Masker()
	lines := splitLines(text)
	shown, masked = make([]string, len(lines)), make([]bool, len(lines))
	h := sha256.New()
	for i, l := range lines {
		shown[i] = sanitize.Text(tripwire.Redact(l), 0)
		if mask {
			m := mk.Emails(sanitize.Text(tripwire.Redact(mk.PolicyText(l)), 0))
			shown[i], masked[i] = m, m != shown[i]
			_, _ = io.WriteString(h, m)
			size += len(m)
		}
	}
	if !mask {
		sum := sha256.Sum256([]byte(text))
		return shown, masked, len(text), hex.EncodeToString(sum[:])
	}
	return shown, masked, size, hex.EncodeToString(h.Sum(nil))
}

// policyVersion is the token that names the version of a policy a result describes. The ETag
// is the unkeyed SHA-256 of the file (probe A-13), so it would confirm a guessed address and
// is shown only with personalData show; with a privacy key the token is a keyed digest of
// it, equal across calls while the policy is; with masking on and no key there is none.
func policyVersion(env *registry.Env, etag string) string {
	switch {
	case etag == "" || env == nil:
		return ""
	case env.ShowPersonalData():
		return etag
	case env.Privacy != nil:
		return env.Privacy.Digest([]byte(etag))
	}
	return ""
}

// externalFacts reads whether the policy is managed outside the admin console (GitOps, say)
// from the tailnet settings. It is advisory: when the settings cannot be read the answer is
// "unknown" and note says so, never false, and a slow settings call must not hold back a
// policy already fetched.
func externalFacts(ctx context.Context, env *registry.Env) (managed, link, note string) {
	sctx, cancel := context.WithTimeout(ctx, settingsWait)
	defer cancel()
	s, err := settingsGet(sctx, env, NoInput{})
	if err != nil {
		return "unknown", "", "the tailnet settings could not be read: " + string(tkerr.From(err).Code)
	}
	managed = s.ExternallyManaged
	if s.Settings.ACLsExternalLink != nil {
		link = *s.Settings.ACLsExternalLink
	}
	if managed == "unknown" {
		note = "the settings did not say"
	}
	return managed, link, note
}

// semanticDigest is the keyed digest of what a policy means: the digest of its normal form, so
// it is equal after a reformat or a rewrite of acls into grants. acl_get's summary shows it for
// the live policy and acl_validate shows it for a patched one, which makes the two comparable:
// once the owner applies the patch, the live policy's digest is the patched one. Without a
// privacy key there is none.
func semanticDigest(ctx context.Context, env *registry.Env, d *acl.Doc) (string, error) {
	if env == nil || env.Privacy == nil {
		return "", nil
	}
	nf, err := acl.NormalFormBytes(ctx, d)
	if err != nil {
		return "", err
	}
	return env.Privacy.Digest(nf), nil
}

// policyNameMax is the most bytes of a name, a key or a scalar of a policy that a summary
// shows, once escaped.
const policyNameMax = 256

// policyDisplay shows a name, a key or a scalar read from a policy: masked while personal
// data is masked, credential shapes replaced, escaped and cut at policyNameMax bytes. A
// pseudonym marker the policy spells itself is rewritten first, as the page text does:
// the registry's masking pass appends markers but does not rewrite one, so a marker in a
// result is one the tool appended and nothing else.
func policyDisplay(env *registry.Env, s string) string {
	if env.ShowPersonalData() {
		return sanitize.String(tripwire.Redact(s), policyNameMax)
	}
	mk := env.Masker()
	return mk.Emails(sanitize.String(tripwire.Redact(mk.PolicyText(s)), policyNameMax))
}

// messageDisplay shows a message that Tailscale wrote or echoed about a policy: every login
// res has handed out, then every other address, masked without a pseudonym, since the message
// repeats what was sent and a pseudonym beside it would confirm a guess; a marker in it is
// rewritten. A nil res is a resolver that has handed out nothing.
func messageDisplay(res *SubjectResolver, env *registry.Env, s string) string {
	if res == nil {
		res = NewSubjectResolver(env)
	}
	return res.Hide(s)
}

// messageBudget is the most characters, as JSON text, that one list of messages takes. Two
// lists come to 32,000: with the largest default page (153,600) or with the summary (132,000)
// they stay under the 200,000 characters the tool declares, whatever the messages are.
const messageBudget = 16000

// messageList shows the messages of a list: at most maxTestMessages of them, and within
// messageBudget, each counted by what the registry will make of it (masked, credential
// shapes replaced, escaped, cut at its string cap) and then encoded as JSON text, where an
// angle bracket costs six times its length. One last entry counts the messages left out, so
// that nothing is dropped without a trace.
func messageList(res *SubjectResolver, env *registry.Env, in []string) []string {
	if len(in) == 0 {
		return nil
	}
	n := min(len(in), maxTestMessages)
	out := make([]string, 0, n+1)
	left := messageBudget
	for _, m := range in[:n] {
		shown := messageDisplay(res, env, m)
		cost := encodedLen(sanitize.String(tripwire.Redact(shown), registry.ResultStringMax)) + 3 // the quotes and a comma
		if cost > left {
			break
		}
		left -= cost
		out = append(out, shown)
	}
	if rest := len(in) - len(out); rest > 0 {
		out = append(out, fmt.Sprintf("(%d more not shown)", rest))
	}
	return out
}
