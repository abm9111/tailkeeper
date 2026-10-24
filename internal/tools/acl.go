package tools

import (
	"fmt"

	"github.com/abm9111/tailkeeper/internal/guard"
	"github.com/abm9111/tailkeeper/internal/registry"
)

// The ACL tools, pulled forward from M3: acl_get reads the policy, acl_test sends
// POST .../acl/validate, which Tailscale documents as never changing the policy, and the API
// client refuses every other request but GET. One file for each tool: acl_get.go and
// acl_test_tool.go, with the helpers they share in acl_view.go.

// aclScopes is policy_file:read with the companions Tailscale requires of it.
var aclScopes = []string{"policy_file:read", "devices:core:read", "devices:posture_attributes:read"}

const (
	defaultPolicyPage = 150 << 10 // keeps a page's JSON text under the 200,000 characters MCP results declare
	maxPolicyPage     = guard.MaxPolicyBytes
	maxDestinations   = 32
	maxTestValue      = 300
	maxTestMessages   = 64
)

func aclTools() []registry.Tool {
	get := withOps(readMeta("acl_get", "acl", "get", "Show the tailnet policy file, a page at a time or at a glance, with Tailscale's warnings about it and its version.", aclScopes...),
		"GET /tailnet/{tailnet}/acl", "GET /tailnet/{tailnet}/settings")
	get.MaxResultChars = 200000
	get.Notes = "A display copy, not the file to edit: email addresses are masked unless personalData is show (addresses and CIDRs stay whole), and line ends are shown as LF. " +
		"One request reads the policy with its warnings and stored errors (Tailscale's own, about the policy as stored); a second reads whether the policy is managed elsewhere. " +
		"With personalData show, bytes, sha256 and etag describe the policy as the API returned it; otherwise bytes and sha256 describe the policy as shown, every page joined, and etag is left out, so none of them can confirm a guessed address. " +
		"policyVersion names the version read: a keyed digest of its ETag when a privacy key is configured, the ETag itself with personalData show, and nothing otherwise. " +
		"With view summary the result lists the sections, the names the policy defines and a keyed digest of what it means, and no text. " +
		"The whole policy, comments included, goes to whoever reads the result."
	test := withOps(readMeta("acl_test", "acl", "test", "Test whether a source can or cannot reach destinations under the live policy, without changing it.", aclScopes...),
		"POST /tailnet/{tailnet}/acl/validate", "GET /tailnet/{tailnet}/acl", "GET /tailnet/{tailnet}/users")
	test.Title, test.OpenWorld = "Test access under the live policy", true
	test.OptionalScopes = []registry.OptionalScope{{Scope: "users:read", Reason: "resolve a pseudonym in src or a destination"}}
	test.Notes = "A user is named by the pseudonym from users_list; a masked value with no pseudonym cannot be tested. The text of the test goes to Tailscale and changes nothing. " +
		"One source per call, against the live policy. Status is pass (exit 0), unknown (1, never a pass), unresolved (2: a name Tailscale cannot resolve) or fail (9: an assertion failed). " +
		"srcPostureAttrs pass through when ssh is not given, and posture is none, gated or unknown: unknown means the live policy could not be read, which is not a pass of that question. A test without the attributes does not match a posture-gated rule. " +
		"A destination with no line has what it was listed to get, and the line's got word is the verdict. A result for another source is otherTests only when it names none of this call's destinations; one that names one of them makes that destination unknown. " +
		"SSH rules are tested only when the call gives ssh. SSH tests are a separate request: a copy of the live policy with its own tests removed, the caller's SSH tests and an SSH canary appended, sent to Tailscale, which changes nothing. A missing SSH canary is unknown. A check user with no line is unknown, never a pass. srcPostureAttrs together with ssh are refused, and so is proto when the call gives no accept or deny destination. With only SSH tests, no tests-mode request is sent. When src is a pseudonym, each distinct SSH user of the call takes one validation token (acl.validatePerMinute) instead of one for the request: a rule written localpart:*@domain accepts the SSH user that is a login's local part, so users guessed in one call would read a masked local part off the verdicts at the price of one token. A call that cannot take them all is validate_rate_limited before the SSH request is sent. What you typed comes back as typed, masked without a pseudonym. When the SSH half cannot run in a call that also has destinations, the tests half is kept, the SSH verdicts are unknown and sshError says why. Lines of Tailscale's text are cut to a bound and omittedLines counts the rest."
	validate := withOps(readMeta("acl_validate", "acl", "validate",
		"Validate a policy proposal, or the live policy, and the invariants the owner configured, with Tailscale's own validator: the policy text is sent to Tailscale and changes nothing.",
		aclScopes...),
		"GET /tailnet/{tailnet}/acl", "POST /tailnet/{tailnet}/acl/validate", "GET /tailnet/{tailnet}/users", "GET /tailnet/{tailnet}/settings")
	validate.Credential = registry.CredOptional
	validate.OptionalScopes = []registry.OptionalScope{{Scope: "users:read", Reason: "resolve a pseudonym in a proposal or patch"}}
	validate.Title, validate.OpenWorld = "Validate a policy proposal", true
	validate.Notes = "Give a policy to validate a whole proposal, a patch (RFC 6902 operations) to change the live policy and validate the result, or neither to validate the live policy. The status is pass (exit 0), unknown (1), invalid, rejected or unresolved (2), or fail (9); unknown is not a pass. " +
		"A pass means Tailscale accepts the text and its tests and the invariants pass, not that the change is safe: notChecked lists what is not established. " +
		"A user is named by pseudonym, never by login. A patch may not hold a test operation, a text with a credential shape is refused, and one call adds or replaces at most 64 tests. Problem kinds: syntax, encoding, structure, duplicate_key, case_collision, unknown_section, assertion_failed, test_unevaluable, server_message, invariant, warning, note."
	diff := withOps(readMeta("acl_diff", "acl", "diff",
		"Compare two policies by what they mean, the live policy against a text, a text against a text, the live policy against a patch, or a stored version from acl_history, and list the changes by class.",
		aclScopes...),
		"GET /tailnet/{tailnet}/acl", "GET /tailnet/{tailnet}/users", "GET /tailnet/{tailnet}/settings", "GET /tailnet/{tailnet}/logging/configuration")
	diff.Credential = registry.CredOptional
	diff.OptionalScopes = []registry.OptionalScope{
		{Scope: "users:read", Reason: "resolve a pseudonym in a text or patch"},
		{Scope: "logs:configuration:read", Reason: "read a policy version from the audit log"},
	}
	diff.Title = "Compare two policies"
	diff.MaxResultChars = 200000
	diff.Notes = "Nothing is sent to Tailscale for validation: a diff reads the live policy, when a side is live, and changes nothing. The old side is against, or fromVersion, or the live policy; the new side is policy, or patch applied to the live policy, or toVersion, or the live policy; the two are never both live. " +
		"A rewrite that means the same (comments, layout, key order, acls written as grants, a rule split or merged) is no change. Changes are listed by class, defaults, testsReduced and widening first, a page at a time: section narrows the list and fromChange continues it; counts and the CLI's --fail-on cover every change. " +
		"notChecked lists what a diff does not establish: a small change to an alias, a group or a host can widen access. A user is named by pseudonym, never by login. Over MCP a text is screened as for acl_validate, though nothing is sent: a patch may not hold a test operation and a text with a credential shape is refused, and the cap on the tests a text adds does not apply. " +
		"fromVersion and toVersion name a policy acl_history listed. A version is read from the audit log with the optional logs:configuration:read scope, and without that scope a diff that names no version works as before. A version is tailnet data, not a caller's text: the subject rule does not read it, and it is shown as the live policy is."
	history := withOps(readMeta("acl_history", "acl", "history", "List the versions of the tailnet policy from the configuration audit log, to compare with acl_diff.", "logs:configuration:read"),
		"GET /tailnet/{tailnet}/logging/configuration")
	history.MaxResultChars = 200000
	history.Notes = "One request per slice of at most 31 days, across a window of at most 90 days (the default is 30 days and 50 versions). Each version names the policy an ACL update wrote and the one it replaced. " +
		"policyVersion is a keyed digest of the text as acl_get would show it when a privacy key is configured, the SHA-256 of the text itself with personalData show, and nothing otherwise. policySha256 and bytes describe that shown text, so two logins that mask to one form share them. " +
		"An entry whose old or new value is not a string, or is over 4 MiB, is counted in skipped and not listed. A large policy over more than a few days can answer api_error: narrow start and end."
	return []registry.Tool{registry.Define(get, aclGet), registry.Define(test, aclTest), registry.Define(validate, aclValidate), registry.Define(diff, aclDiff), registry.Define(history, aclHistory)}
}

// invalidf is validationf with formatting.
func invalidf(format string, args ...any) error { return validationf(fmt.Sprintf(format, args...)) }
