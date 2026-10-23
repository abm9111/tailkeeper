package tools

import (
	"fmt"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/sanitize"
)

// typedInputs lists every string of a call that Tailscale or the result may quote back: the
// source, the destinations, the protocol, the SSH destinations and users, and the posture
// attributes with their values. The resolver is told them (SubjectResolver.Typed) before it
// masks a reply.
func typedInputs(in ACLTestInput) []string {
	out := []string{in.Src, in.Proto}
	out = append(out, in.Accept...)
	out = append(out, in.Deny...)
	for _, t := range in.SSH {
		out = append(out, t.Dst...)
		out = append(out, t.Accept...)
		out = append(out, t.Check...)
		out = append(out, t.Deny...)
	}
	for k, v := range in.SrcPostureAttrs {
		out = append(out, k)
		if s, ok := v.(string); ok {
			out = append(out, s)
		} else {
			out = append(out, fmt.Sprint(v))
		}
	}
	return out
}

// echoed shows a string the caller typed, back to the caller. It is masked by the text alone,
// without a pseudonym and without what the call resolved: a pseudonym beside a typed address
// would match it to the user the pseudonym stands for, and a mask that read the call's logins
// would show whether the text was one. A destination or a source that is a pseudonym carrier is
// shown as it was typed, which is the pseudonym the caller already held. A marker in any other
// string is not the masker's and is rewritten, so that no result carries one the call did not
// type as a carrier.
func echoed(env *registry.Env, s string) string {
	if env.ShowPersonalData() {
		return s
	}
	if _, carrier, _ := carrierRef(subjectHost(s)); carrier {
		return s
	}
	if _, carrier, _ := carrierRef(s); carrier {
		return s
	}
	return sanitize.MaskEmails(env.Masker().Unforge(s))
}
