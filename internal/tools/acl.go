package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tripwire"
)

// The ACL reads (spec §12), pulled forward from M3. Both only read: acl_test sends
// POST .../acl/validate, which Tailscale documents as never changing the policy,
// and the API client refuses every other request but GET.

// aclScopes is policy_file:read with the companions Tailscale requires of it.
var aclScopes = []string{"policy_file:read", "devices:core:read", "devices:posture_attributes:read"}

const (
	defaultPolicyPage = 150 << 10 // keeps a page's JSON text under the 200,000 characters MCP results declare
	maxPolicyPage     = 4 << 20
	maxDestinations   = 32
	maxTestValue      = 300
	maxTestMessages   = 64
)

func aclTools() []registry.Tool {
	get := withOps(readMeta("acl_get", "acl", "get", "Show the tailnet policy file, a page at a time, as the API returned it.", aclScopes...),
		"GET /tailnet/{tailnet}/acl", "GET /tailnet/{tailnet}/settings")
	get.MaxResultChars = 200000
	get.Notes = "A display copy, not the file to edit: email addresses are masked unless personalData is show (addresses and CIDRs stay whole), and line ends are shown as LF. " +
		"With personalData show, bytes, sha256 and etag describe the policy as the API returned it; otherwise bytes and sha256 describe the policy as shown, every page joined, and etag is left out, so none of them can confirm a guessed address. " +
		"The whole policy, comments included, goes to whoever reads the result."
	test := withOps(readMeta("acl_test", "acl", "test", "Test whether a source can or cannot reach destinations under the live policy, without changing it.", aclScopes...),
		"POST /tailnet/{tailnet}/acl/validate")
	test.Title, test.OpenWorld = "Test access under the live policy", true
	test.Notes = "One source per call, against the live policy only, with no posture attributes; SSH rules are not tested. A masked value (one with …) cannot be tested: ask the user for it. " +
		"A source or destination Tailscale cannot resolve fails the test, with its reason. The CLI exits 9 when the test fails."
	return []registry.Tool{registry.Define(get, aclGet), registry.Define(test, aclTest)}
}

// ACLGetInput selects a page of the policy.
type ACLGetInput struct {
	FromLine int `json:"fromLine,omitempty" jsonschema:"first line of the page, from 1 (default 1); use nextLine from the previous page"`
	MaxBytes int `json:"maxBytes,omitempty" jsonschema:"page size: bytes of the page once masked, escaped and encoded as JSON text, 1024 to 4194304 (default 153600); a line longer than the page is refused with the size to ask for"`
}

// ACLGetOutput is a page of the policy and facts about the whole file.
type ACLGetOutput struct {
	Policy                string `json:"policy" tk:"untrusted,emails,multiline" jsonschema:"lines fromLine to toLine of the policy file (HuJSON, comments included) as the API returned it, line ends shown as LF; email addresses masked unless personalData is show"`
	FromLine              int    `json:"fromLine"`
	ToLine                int    `json:"toLine"`
	Lines                 int    `json:"lines" jsonschema:"lines in the whole policy"`
	NextLine              int    `json:"nextLine" jsonschema:"fromLine of the next page; 0 on the last page"`
	Truncated             bool   `json:"truncated" jsonschema:"more lines follow this page"`
	Masked                bool   `json:"masked" jsonschema:"email addresses on this page were masked"`
	Bytes                 int    `json:"bytes" jsonschema:"size of the whole policy: as the API returned it with personalData show; otherwise as shown, every page joined, so it cannot confirm a guessed address"`
	SHA256                string `json:"sha256" jsonschema:"SHA-256 of the whole policy, of the same bytes as bytes"`
	ETag                  string `json:"etag,omitempty" jsonschema:"the policy version's ETag, verbatim; only with personalData show, since it may be derived from the unmasked file"`
	ExternallyManaged     string `json:"externallyManaged" jsonschema:"true, false or unknown: whether the policy is managed outside the admin console, for example by GitOps"`
	ExternalLink          string `json:"externalLink,omitempty" tk:"untrusted,plain"`
	ExternallyManagedNote string `json:"externallyManagedNote,omitempty" jsonschema:"why externallyManaged is unknown"`
}

// Block lets the CLI print the page as a document: these fields first, then the
// policy lines with their numbers.
func (o ACLGetOutput) Block() (int, string) { return o.FromLine, o.Policy }

// Check refuses a page that cannot exist, before anything is sent. Zero means the default.
func (in ACLGetInput) Check() error {
	if in.FromLine < 0 {
		return invalidf("fromLine must be 1 or more")
	}
	if m := in.MaxBytes; m != 0 && (m < 1024 || m > maxPolicyPage) {
		return invalidf("maxBytes must be between 1024 and %d", maxPolicyPage)
	}
	return nil
}

func aclGet(ctx context.Context, env *registry.Env, in ACLGetInput) (ACLGetOutput, error) {
	from, max := in.FromLine, in.MaxBytes
	if from == 0 {
		from = 1
	}
	if max == 0 {
		max = defaultPolicyPage
	}
	c, err := env.RequireAPI()
	if err != nil {
		return ACLGetOutput{}, err
	}
	path, err := tailnetPath(env, "/acl")
	if err != nil {
		return ACLGetOutput{}, err
	}
	raw, err := c.GetRaw(ctx, path, "application/hujson")
	if err != nil {
		return ACLGetOutput{}, err
	}
	// Each line is prepared as the registry shows it, so that its passes change
	// nothing: masked, credential shapes replaced, escaped (a CRLF shown as LF, a
	// lone CR escaped), and masked again, since escaping can turn an invisible
	// character into text that reads as part of an address. The first pass also
	// rewrites any [p: the policy holds, so a marker on the page is one acl_get
	// appended; the second must not, since it would rewrite those.
	mask := !env.ShowPersonalData()
	mk := env.Masker()
	lines := splitLines(string(raw.Body))
	shown, masked := make([]string, len(lines)), make([]bool, len(lines))
	h, size := sha256.New(), 0
	for i, l := range lines {
		shown[i] = sanitize.Text(tripwire.Redact(l), 0)
		if mask {
			m := mk.Emails(sanitize.Text(tripwire.Redact(mk.PolicyText(l)), 0))
			shown[i], masked[i] = m, m != shown[i]
			_, _ = io.WriteString(h, m)
			size += len(m)
		}
	}
	out := ACLGetOutput{ExternallyManaged: "unknown", Lines: len(lines)}
	if mask {
		// The size and hash are those of the policy as shown, every page joined,
		// and the ETag is left out: the file's own would confirm a guessed address,
		// which in a small tailnet is a short list.
		out.Bytes, out.SHA256 = size, hex.EncodeToString(h.Sum(nil))
	} else {
		sum := sha256.Sum256(raw.Body)
		out.Bytes, out.SHA256, out.ETag = len(raw.Body), hex.EncodeToString(sum[:]), raw.ETag
	}
	if from > max1(out.Lines) {
		return ACLGetOutput{}, invalidf("fromLine %d is past the policy's last line, %d", from, out.Lines)
	}
	var page strings.Builder
	used, to := 0, from-1
	for to < out.Lines {
		// A line costs what it takes in the result: encoded as JSON text, which can
		// be a third longer than the line itself.
		cost := encodedLen(shown[to])
		if used+cost > max {
			if page.Len() > 0 {
				break
			}
			if cost > maxPolicyPage {
				return ACLGetOutput{}, invalidf("line %d is %d bytes as JSON text, more than the largest page, %d: it cannot be shown", to+1, cost, maxPolicyPage)
			}
			return ACLGetOutput{}, invalidf("line %d is %d bytes as JSON text, more than maxBytes %d; ask for maxBytes %d or more", to+1, cost, max, cost)
		}
		page.WriteString(shown[to])
		used += cost
		out.Masked = out.Masked || masked[to]
		to++
	}
	out.Policy, out.FromLine, out.ToLine = page.String(), from, to
	if to < out.Lines {
		out.Truncated, out.NextLine = true, to+1
	}
	// Whether the policy is managed elsewhere comes from the settings; when they
	// cannot be read it is unknown, never false. It is advisory, so a slow settings
	// call must not hold back a policy already fetched.
	sctx, cancel := context.WithTimeout(ctx, settingsWait)
	defer cancel()
	if s, err := settingsGet(sctx, env, NoInput{}); err != nil {
		out.ExternallyManagedNote = "the tailnet settings could not be read: " + string(tkerr.From(err).Code)
	} else {
		out.ExternallyManaged = s.ExternallyManaged
		if s.Settings.ACLsExternalLink != nil {
			out.ExternalLink = *s.Settings.ACLsExternalLink
		}
		if out.ExternallyManaged == "unknown" {
			out.ExternallyManagedNote = "the settings did not say"
		}
	}
	return out, nil
}

// invalidf is validationf with formatting.
func invalidf(format string, args ...any) error { return validationf(fmt.Sprintf(format, args...)) }

// splitLines splits text after each line feed, dropping the empty tail a final
// line feed leaves.
func splitLines(text string) []string {
	lines := strings.SplitAfter(text, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// settingsWait bounds acl_get's advisory settings call, retries included. It is a
// variable only so a test can shorten it.
var settingsWait = 10 * time.Second

// encodedLen is what an escaped line costs in a result: its length encoded as a
// JSON string, without the quotes.
func encodedLen(line string) int {
	b, _ := json.Marshal(line) // a string always encodes
	return len(b) - 2
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

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
