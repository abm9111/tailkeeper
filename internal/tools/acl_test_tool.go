package tools

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/sanitize"
)

// ACLTestInput is one test: a source and the destinations it must or must not reach.
type ACLTestInput struct {
	Src    string   `json:"src" jsonschema:"the source: a user's login, group:name, tag:name, a host alias or a tailnet address; never a masked value"`
	Accept []string `json:"accept,omitempty" jsonschema:"destinations src must reach, as host:port (tag:prod:22, 100.64.0.5:443, [fd7a:115c:a1e0::5]:22)"`
	Deny   []string `json:"deny,omitempty" jsonschema:"destinations src must not reach, as host:port"`
	Proto  string   `json:"proto,omitempty" jsonschema:"IP protocol, a name such as tcp, udp or icmp, or a number from 1 to 255; icmp needs port 0"`
}

// ACLTestOutput is the live policy's answer.
type ACLTestOutput struct {
	Status      string          `json:"status" jsonschema:"pass: every destination matched as asked; fail: at least one did not"`
	Failures    []ACLTestResult `json:"failures,omitempty" tk:"details"`
	Warnings    []string        `json:"warnings,omitempty" tk:"untrusted,emails,details"`
	EvaluatedAt string          `json:"evaluatedAt"`
	Note        string          `json:"note"`
}

// ACLTestResult is Tailscale's reasons for a failed source.
type ACLTestResult struct {
	Src    string   `json:"src" tk:"untrusted,emails"`
	Errors []string `json:"errors" tk:"untrusted,emails"`
}

// ExitCode makes the CLI exit 9 (the spec's tests_failed) for a failed test.
func (o ACLTestOutput) ExitCode() int {
	if o.Status == "fail" {
		return 9
	}
	return 0
}

const aclTestNote = "Evaluated against the live policy with no posture attributes; SSH rules are not tested."

// Check refuses a test that is malformed or has nothing to test, before anything is sent.
func (in ACLTestInput) Check() error { return checkACLTest(in) }

func aclTest(ctx context.Context, env *registry.Env, in ACLTestInput) (ACLTestOutput, error) {
	c, err := env.RequireAPI()
	if err != nil {
		return ACLTestOutput{}, err
	}
	v, err := c.ValidateTests(ctx, []api.PolicyTest{{Src: in.Src, Proto: in.Proto, Accept: in.Accept, Deny: in.Deny}})
	if err != nil {
		return ACLTestOutput{}, err
	}
	out := ACLTestOutput{Status: "pass", EvaluatedAt: env.Clock().UTC().Format("2006-01-02T15:04:05Z"), Note: aclTestNote}
	if !v.Passed {
		out.Status = "fail"
	}
	// The fields are tagged emails: only email addresses are masked, since the
	// destinations are the caller's own input and must still name what failed.
	//
	// They are masked here, without pseudonyms: the reasons echo the caller's own
	// guess, and a pseudonym beside it would confirm the guess. The registry's
	// pass over an address already masked changes nothing (Emails is idempotent).
	hide := func(s string) string {
		if env.ShowPersonalData() {
			return s
		}
		return sanitize.MaskEmails(s)
	}
	for _, r := range v.Results {
		if len(r.Errors) > 0 && len(out.Failures) < maxTestMessages {
			errs := make([]string, 0, len(r.Errors))
			for _, e := range r.Errors[:min(len(r.Errors), maxTestMessages)] {
				errs = append(errs, hide(e))
			}
			out.Failures = append(out.Failures, ACLTestResult{Src: hide(r.User), Errors: errs})
		}
		for _, w := range r.Warnings {
			if len(out.Warnings) < maxTestMessages {
				out.Warnings = append(out.Warnings, hide(w))
			}
		}
	}
	return out, nil
}

// Details lets the CLI print each reason on its own line instead of one capped
// cell, after a notice that the reasons are Tailscale's text, not tailkeeper's.
func (o ACLTestOutput) Details() []string {
	var lines []string
	for _, f := range o.Failures {
		for _, e := range f.Errors {
			lines = append(lines, "failed  "+f.Src+": "+e)
		}
	}
	for _, w := range o.Warnings {
		lines = append(lines, "warning "+w)
	}
	if len(lines) == 0 {
		return nil
	}
	return append([]string{registry.UntrustedReasonsNotice}, lines...)
}

var protoRE = regexp.MustCompile(`^[a-z0-9-]{1,16}$`)

// checkACLTest checks a test's structure, not its meaning: Tailscale decides what
// a source or destination names, and stricter local rules would refuse valid ones.
func checkACLTest(in ACLTestInput) error {
	if strings.TrimSpace(in.Src) == "" {
		return invalidf("src is required")
	}
	if err := checkTestValue("src", in.Src); err != nil {
		return err
	}
	if strings.ContainsAny(in.Src, "/ ") {
		return invalidf("src is one identity, with no CIDR range and no spaces")
	}
	if n := len(in.Accept) + len(in.Deny); n == 0 {
		return invalidf("give at least one destination in accept or deny: a test with none passes without testing anything")
	} else if n > maxDestinations {
		return invalidf("at most %d destinations per test, not %d", maxDestinations, n)
	}
	if in.Proto != "" {
		if !protoRE.MatchString(in.Proto) {
			return invalidf("proto %q must be a protocol name such as tcp, udp or icmp, or a number", in.Proto)
		}
		if n, err := strconv.Atoi(in.Proto); err == nil && (n < 1 || n > 255) {
			return invalidf("proto %d must be between 1 and 255", n)
		}
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
			if err := checkTestValue(at, d); err != nil {
				return err
			}
			port, err := destinationPort(d)
			if err != nil {
				return invalidf("%s: %s", at, err)
			}
			if icmp && port != 0 {
				return invalidf("%s: ICMP tests use port 0", at)
			}
		}
	}
	return nil
}

func checkTestValue(field, v string) error {
	switch {
	case len(v) > maxTestValue:
		return invalidf("%s is longer than %d bytes", field, maxTestValue)
	case strings.Contains(v, "…"):
		return invalidf("%s is a masked value; ask the user for the real one, or have the owner set personalData to show", field)
	case sanitize.String(v, 0) != v:
		return invalidf("%s holds control or invisible characters", field)
	case strings.Contains(v, "*"):
		return invalidf("%s: tests take no wildcards", field)
	}
	return nil
}

// destinationPort checks host:port, with an IPv6 address in brackets, and returns
// the port. Tests take one numeric port and no CIDR (spec §12.2).
func destinationPort(d string) (int, error) {
	host, port := "", ""
	if strings.HasPrefix(d, "[") {
		end := strings.Index(d, "]:")
		if end < 0 {
			return 0, fmt.Errorf("an IPv6 destination is [address]:port")
		}
		host, port = d[1:end], d[end+2:]
	} else {
		i := strings.LastIndexByte(d, ':')
		if i < 0 {
			return 0, fmt.Errorf("a destination is host:port")
		}
		host, port = d[:i], d[i+1:]
		// tag:prod:22 has colons too; only an IPv6 address must be bracketed.
		if a, err := netip.ParseAddr(host); err == nil && a.Is6() {
			return 0, fmt.Errorf("an IPv6 destination needs brackets: [address]:port")
		}
		if _, err := netip.ParseAddr(d); err == nil {
			return 0, fmt.Errorf("an IPv6 destination needs brackets and a port: [address]:port")
		}
	}
	switch {
	case host == "":
		return 0, fmt.Errorf("the host is empty")
	case strings.Contains(host, "/"):
		return 0, fmt.Errorf("tests take no CIDR ranges")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 || strconv.Itoa(n) != port {
		return 0, fmt.Errorf("the port must be one number from 0 to 65535")
	}
	return n, nil
}
