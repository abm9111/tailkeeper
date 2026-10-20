package probe

// row is one row of the probe table (docs/design.md §22) as it stood when the probes were written, before
// any of them ran: what is sent, what is expected, and which branch of the design each
// outcome selects. The text is that table's, with its review IDs and section numbers
// dropped, and not otherwise edited; the "observed" column of the table
// is filled from the run (internal/api/apitest/testdata/observed).
type row struct {
	Sends, Expected, Branch string
}

// registered is the probe table, keyed by probe ID.
var registered = map[string]row{
	"A-1": {
		Sends:    "Policy mode, `{\"tagOwners\":{\"tag:p\":[]},\"hosts\":{\"probe-a\":\"100.64.0.1\"},\"tests\":[{\"src\":\"tag:p\",\"deny\":[\"probe-a:22\"]}]}`; the same with `\"acls\":[]`, with `\"acls\":null`, with `\"grants\":[]`; control: with `\"acls\":[{\"action\":\"accept\",\"src\":[\"*\"],\"dst\":[\"*:*\"]}]`",
		Expected: "Control fails (want Drop, got Accept, in the grammar); absent fails like the control (allow-all); `acls: []` passes (deny-all); `acls: null` fails like absent; `grants: []` fails like absent (low confidence). If the control passes, the probe does not discriminate and is redesigned before any reading",
		Branch:   "The `defaults` wording for `grants` and `null`; the canary's `src` shape (a tag with empty owners)",
	},
	"A-2": {
		Sends:    "Policy mode with `[]`, `[{\"src\":\"tag:p\",\"accept\":[\"tag:p:22\"]}]`, an empty body, `null`",
		Expected: "Arrays run in tests mode against live; empty and `null` rejected with a bare `{message}`",
		Branch:   "Confirms the object rule, which stays either way",
	},
	"A-3": {
		Sends:    "Policy mode: a syntax error, an unknown field, an unknown tag, `app: {}` without `ip`",
		Expected: "400 with a bare `{message}`, no `data`; the syntax error carries `line N, column M`",
		Branch:   "A 200 bare `{message}` maps to `rejected` only if seen; otherwise `unknown`",
	},
	"A-4": {
		Sends:    "Policy mode: two `groups` blocks, two `acls` blocks, two `acls` blocks whose second rule has no `dst`, `tagOwners` plus `TagOwners`, a group name defined twice inside `groups`",
		Expected: "All accepted: struct-valued sections merge, arrays replace, keys fold case, the later map entry wins; a repeated array of rules replaces whole, with no element-wise merge (the one rule left has no `dst`, so it is rejected or its test fails)",
		Branch:   "The folding rules; if rejected, proposals with duplicates are `invalid` anyway and only the live-side wording changes; if the second rule keeps the first's `dst`, the server merges repeated arrays element-wise and how repeated array sections are read changes",
	},
	"A-5": {
		Sends:    "Policy mode: `{\"nodeAttr\":[]}`, `{\"attrConfig\":{}}`, `{\"extraDNSRecords\":[]}`, `{\"sshTests\":[]}`",
		Expected: "`nodeAttr` rejected as unknown field; the other three accepted",
		Branch:   "The known-sections table",
	},
	"A-6": {
		Sends:    "Policy mode: a `nodeAttrs` entry whose target is `autogroup:self` (a third-party capture of the SaaS, 7 May 2026, returned 500), sent twice",
		Expected: "500 both times",
		Branch:   "The retry-once rule and its hint",
	},
	"A-7": {
		Sends:    "`details=true` GET, then POST the same text in policy mode",
		Expected: "The same warning set both ways",
		Branch:   "The warnings baseline; if they differ, the baseline comes from a POST of live",
	},
	"A-8": {
		Sends:    "`details=true` with and without `Accept: application/hujson`; compare decoded `acl` and ETag with the plain GET; then `If-None-Match`",
		Expected: "Decoded text equals the plain body; ETags equal; `If-None-Match` answers 304 (low confidence)",
		Branch:   "One-call `acl_get`; the re-check after POST",
	},
	"A-9": {
		Sends:    "Tests mode against live, one test per destination kind, each accepting and denying the same destination so exactly one assertion fails whatever live allows; `src` a tag or user from live held in memory. Kinds: tag, host alias, IPv4, bracketed IPv6, user, `svc:`, ICMP port 0, with and without `proto`; and CIDR and `autogroup:internet` as kinds tests refuse; plus the canary in policy mode",
		Expected: "Every accepted kind yields one line in the validate grammar; CIDR and `autogroup:internet` come back unevaluable; the canary yields one `assertion_failed` line with its `src`",
		Branch:   "The verdict grammar's golden set; the kinds `doctor --probe` uses; the canary's shape",
	},
	"A-10": {
		Sends:    "Policy mode: a synthetic document with an `ssh` rule and a failing and a passing `sshTests` entry; if refused, the live text plus a test built from its first `ssh` rule (printed as booleans only)",
		Expected: "`sshTests` run; the failure has the SSH form",
		Branch:   "SSH tests in 0.6.0, or out",
	},
	"A-11": {
		Sends:    "Policy mode: raw HuJSON with a leading comment and trailing commas; the same `Standardize`d; the same with a BOM",
		Expected: "Raw and standardized accepted with `application/hujson`; BOM rejected",
		Branch:   "Send exact bytes or `Standardize`d",
	},
	"A-12": {
		Sends:    "Tests mode with one passing test",
		Expected: "No other results on a healthy tailnet (not decidable unless a stored test fails)",
		Branch:   "Nothing; the `otherTests` filter ships regardless, tested on the fake",
	},
	"A-13": {
		Sends:    "`sha256(hujson.Format(GET body))` in hex against the ETag",
		Expected: "Equal",
		Branch:   "\"Identical to live\" without a request",
	},
	"A-14": {
		Sends:    "Policy mode: a login that cannot exist (`nobody-<random>@example.com`) placed in turn in `groups`, `tagOwners`, an `acls` `src`, an `ssh` `src`, a test `src`, and as an object key",
		Expected: "Every position yields either the same rejection or a pass that does not depend on the user existing",
		Branch:   "If a position distinguishes existing from absent users, the subject rule already covers it (keys and values); the guide names the positions",
	},
	"H-1": {
		Sends:    "`GET` configuration audit log, 90 days, ACL update entries: are `old` and `new` strings that parse as a HuJSON object with a known section",
		Expected: "Yes (the documentation promises a full diff)",
		Branch:   "`acl_history` in 0.6.0 or metadata in 0.7.0",
	},
}
