package workflows

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// designSection returns one section of docs/design.md: the line equal to heading and
// every line after it up to the next "## " heading. The heading must occur exactly once.
// A "###" heading's section therefore runs to the next "## ", not to the next "###".
func designSection(t *testing.T, doc, heading string) string {
	t.Helper()
	lines := strings.Split(doc, "\n")
	start := -1
	for i, l := range lines {
		if l != heading {
			continue
		}
		if start >= 0 {
			t.Fatalf("docs/design.md has the heading %q twice", heading)
		}
		start = i
	}
	if start < 0 {
		t.Fatalf("docs/design.md has no heading %q", heading)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "## ") {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

// designRule is what one section of the design must say, and must no longer say.
type designRule struct {
	section string   // the section's heading line
	want    []string // snippets the section must contain
	absent  []string // snippets it must not contain
}

// designRules are the statements of the 0.6.0 contract that are checked in docs/design.md,
// and the claims it dropped because nothing sources them. The design is the contract the
// code is reviewed against, and it is public, so a later edit that brings an unsourced
// claim back, or drops a row of the contract, fails here.
var designRules = []designRule{
	{
		section: "# tailkeeper — design",
		want: []string{
			"v0.7 records the contract of 0.6.0",
			"§4, §6, §10.5, §12, §13.3, §13.5, §15, §16, §17, §19, §22 to §24 and §26 changed",
		},
		absent: []string{"§6, §12, §13.5, §16, §19,"},
	},
	{
		section: "## 4. Architecture",
		want: []string{
			"validate/test/preview;\n                          pure: no I/O, no masking (§12.9)",
			"internal/guard            the nesting-depth pre-scan, shared by internal/acl and internal/tools (§12.9)",
		},
	},
	{
		section: "## 6. Tool catalogue",
		want: []string{
			"`acl_validate` (0.6.0:", "`acl_diff` (0.6.0:", "`acl_history` (alpha: policy versions from the configuration audit log",
			"`view: summary`", "`policyOverridesAnalysed: false`", "`extraDNSRecords`",
			"on 20 Oct 2026 the decoded text and the ETag equalled the plain GET's", "the failure had the SSH form, and the passing entry alone passed)",
			"one `details=true` call, sent with no `Accept` header, returns",
			"a file (a side for the CLI only: MCP takes text or a patch, never a path), the live policy and",
			"every ACL update entry in the window held policy texts with a known section",
			"validated in policy mode with the configured invariants, if any",
			"a stored version from `acl_history`",
			"a keyed `semanticDigest` of the normal form (§12.10) when a privacy key is loaded",
			"in effect only with `overrideLocalDNS` on and alpha enabled",
			"outputs client ID and audience (neither is a credential; the recipe keeps the client ID in an environment secret so that no log shows it)",
		},
		absent: []string{"`Accept: application/hujson`; one `details=true` call",
			"split-DNS `nodeAttrs`", "arrive in M3; until then", "pass only on an empty body",
			"stored errors; `view", "validated in policy mode with the invariants;", "a file and a stored version",
			"in effect only with `overrideLocalDNS` on, which", "if a probe shows policy mode runs", "if a probe shows the log holds",
		},
	},
	{
		// The CI runner row: what the live identity reads, where its job runs, and who can reach it
		// with and without a required reviewer. It is the row of the published threat model too.
		section: "## 3. Threat model",
		want:    ciRunnerClauses,
		absent:  []string{"| CI runner | OIDC identity, network access to the API |"},
	},
	{
		section: "## 17. MCP server",
		want:    []string{"the others arrive with the gate (M2) and the ACL engine (M3); `tailnet://acl` arrives with 0.6.0"},
		absent:  []string{"`tailnet://acl` waits for M3"},
	},
	{
		section: "## 10. Policy",
		want:    []string{"`tailkeeper acl validate` applies them to the live policy"},
		absent:  []string{"`tailkeeper acl test --invariants`"},
	},
	{
		section: "## 12. ACL engine",
		want: []string{
			"*pending probe*", "### 12.9 Parsing and input limits", "### 12.10 Normal form and diff", "### 12.11 Proposals, subjects and invariants",
			"`policy_rejected_or_server_error`", "`semanticallyEqual: true` is exact", "`liveChanged`", "`unresolved`", "canary",
			"`validate_rate_limited`", "`too_complex`", "`internal/guard`", "`acl.invariantsFile`",
			"`acl_get` reads the policy with one `details=true` call, sent with no `Accept` header",
		},
		absent: []string{"`tag://`", "`group://`", "Server warnings come from a separate `details=true` call", "`acl_get` sends `Accept: application/hujson`"},
	},
	{
		section: "## 15. Configuration",
		want:    []string{`"invariantsFile"`, `"validatePerMinute"`},
	},
	{
		section: "## 13. Events and automation",
		want: []string{
			"`tailkeeper acl validate` (read credential)", "`tailkeeper acl diff OLD NEW`", "`--against FILE|live`",
			"`pull_request_target`", "`--tests-only` is no longer a flag", "`acl validate` (with the invariants of `acl.invariantsFile`)",
			// The identity of the recipe: its job, its subject, who can reach it, and where its identifiers live.
			"and runs the job that reads the live policy in a named environment, with `id-token: write` on that job only.",
			"Every step of that job, including the pinned `actions/checkout` and `sigstore/cosign-installer` and the downloaded binary, can request the OIDC token; the SHA pins and the environment's reviewer are the controls.",
			"The federated identity's subject is that environment (`repo:OWNER/REPO:environment:NAME`). With a required reviewer on the environment and the credential's subject bound to that environment, a person approves each run and only an approved run gets the identity; without the binding, a job that names no environment gets a token with no approval, and without a reviewer, anyone who can push a branch can still edit the workflow and read the policy, the devices and their posture attributes (whatever scopes the client holds) with that identity.",
			workflowGuardClause + " The environment is created before the first run, because GitHub creates a missing one with no protection rules; \"Prevent self-review\" is on, and with one maintainer the gate is that person's reading of the change to the workflow file; no deployment-branch rule is set, because a pull request job runs on `refs/pull/N/merge`.",
			"The tailnet ID and the OAuth client ID are environment secrets of that environment, not repository secrets, so only an approved job receives them and no log shows them.",
			"Only the status check `tailkeeper-acl-result`, the workflow's `result` job, is required, because branch protection counts a job that its `if` skipped as a pass; the workflow has no `paths` filter on `on.pull_request`, because a workflow that does not run never reports that check.",
			"A read identity whose subject is the environment of the job that reads (`repo:OWNER/REPO:environment:NAME`), not a pull-request subject: a credential bound to pull-request subjects refuses that job.",
			"A pull request from a fork gets no OIDC token and runs only the offline step, after which the job fails.",
			"and prints the client ID, which belongs in an environment secret, and the audience.",
		},
		absent: []string{
			"`acl test --invariants`", "(read credential): exit 9 on failure (0.3.0's",
			"for repository variables", "may restrict the federated identity's subject to a protected environment that needs approval",
		},
	},
	{
		section: "## 16. CLI",
		want: []string{
			"`--format text|json|github|markdown`", "**8 is shared: a check you asked for found something.**",
			"| 8 | A check you asked for found something", "the first of 1, 9, 2, 8 and 0 wins",
		},
		absent: []string{"(there is no `--fail-on` yet)", "| 8 | Findings at or above `--fail-on` |"},
	},
	{
		section: "## 19. Error model",
		want: []string{
			"| `usage` |", "| `policy_rejected_or_server_error` |", "| `validate_rate_limited` |", "| `too_complex` |",
			"statuses of the typed ACL results",
			// The three planned codes, each with its exit cell, so a changed exit fails here
			// (TestDesignCatalogueAgreesWithTheCodes checks the declared codes only).
			"never a truncated answer | 2 |",
			"A refusal with a message is a `rejected` result, not this | 1 |",
			"Tailscale's 429 is `api_rate_limited` | 1 |",
			"| `validation_failed` | HTTP 400 (not in policy mode, where the strict reader of §12.2 reads a 400 as a `rejected` or `unknown` result),",
		},
		absent: []string{"`acl_test` returns a typed `fail` instead, with Tailscale's reasons, which the CLI maps to exit 9)"},
	},
	{
		// The statements of §12 that rest on behaviour nobody has observed keep their mark, in
		// the one form *pending probe* A-n: one snippet per sentence, so dropping a single mark,
		// or its probe ID, fails here.
		section: "## 12. ACL engine",
		want: []string{
			"The probes of §22 ran on 20 Oct 2026", "The one mark left, in §12.10, waits for a console save",
			"which no probe of §22 settles",
			"with and without `Accept`, and `If-None-Match` did not answer 304",
			"If a later call's decoded text or ETag differs from the plain GET's",
			"the server refused every repeated key it was sent, a case collision at the top level among them",
			"`rejected`, under a 400 and under a 200 that carries a bare message",
			"SSH tests are in 0.6.0 and `acl_test` runs them through a copy of the live policy",
			"a byte order mark was HTTP 400, so the client sends the exact bytes",
			"an empty array, an empty body and `null` were HTTP 400 with a message",
			"the canary yielded one line and named its tag",
			"not HTTP 400, and the syntax error named a line and a column",
			"both sends were HTTP 500 and the retry did not clear it",
			"had the same warning set, so the baseline is that set. Both sets were empty on that tailnet (the counts were 0 and 0)",
			"one line for a tag, a host alias, IPv4 with and without `proto`",
			"A live policy is not described as having been accepted with a repeated key",
			"the one case collision was sent at the top level only; what the server does with a case collision below the top level was not observed",
			"That reading is Go's decoder's, not the server's: it keeps the later value for a map entry and for an array, and merges a repeated struct-valued section.",
			"(the probe expected HTTP 400; the body is still a rejection)",
			"the ETag is the unkeyed SHA-256 of the formatted file (probe A-13)",
			"`nodeAttr` was HTTP 200 with a message that has the words \"unknown field\"",
			"(*pending probe*, which no probe of §22 settles: a console save captured before and after on a scratch tailnet",
			"`grants: []` is deny-all like `acls: []`",
			"`sha256` of the formatted body equalled the ETag",
		},
	},
	{
		// Corrections to the first draft of §12 (what ships in 0.6.0, how a proposal is made, the validation ranges).
		section: "## 12. ACL engine",
		want: []string{
			"Two parts of that range ship in 0.6.0",
			"an agent proposes a change by validating a JSON Patch",
			"In tests mode (`acl_test`)", "any other 400 stays `validation_failed`, and a 200 that carries a message and no results stays an unrecognised-response error, as in 0.5.0 (`readValidation` in `internal/api/client.go`)",
			"`acl_test` runs them through a copy of the live policy with the tests appended",
			"requiring exactly one match; zero or several is `validation_failed`.", "refused before anything is sent, with `validation_failed`;",
			"In policy mode (`acl_validate`) the strict reader below applies: a 400 with a bare `{message}` is `rejected`",
			"a message with no results is `rejected`, under a 400 and under a 200 that carries a bare message (which is what 20 Oct 2026 showed), unless the message is empty or says `test(s) failed` or `warning(s) found`: it then promises entries that are not there, and the answer is `unknown`.",
			"for a patch, `patchedBytes` and `patchedDigest`",
			"`case_collision` (struct objects only, which is the decoder's reading; only the top level was observed)", "the top level, the rule arrays, `autoApprovers` and `derpMap`",
			"`MaxNodes` 2^19", "`MaxWork` 2^26", "`MaxAtoms` 2^18", "`MaxPatchOps` 256", "`ApplyPatch` refuses the `copy` operation",
			"`StartOffset` and `EndOffset`",
			"one call with `type=all&role=all`", "a risk, not documented behaviour",
			"Apart from the credential's token request",
			"the `postureSensitive` reading of `acl_test`",
		},
		absent: []string{
			"(§12.4 to §12.7) wait for M2",
			"an agent changes a policy by validating",
			"any other 400 is `validation_failed`",
			"a 400 in none of the recognised shapes is an unrecognised response.",
			"is an unrecognised-response error, never a pass",
			"keys match case-insensitively, unknown fields",
			"Duplicates are found in every object at any depth",
			"HuJSON reports no structured position, so line",
			"members and suspended users, paged",
			"`policy_file:read` only for",
			"The only request other than a GET that tailkeeper makes remains",
			"with the tests appended, or wait for M2", "invalid_input", "until the probe below settles it", "a probe confirms how the endpoint treats",
			"the case rule is not limited to struct objects", "is probably the unkeyed SHA-256", "the check asked for HTTP 400",
			"pusher sends it, On 20 Oct", "is made On 20 Oct", "including a case collision, so a live policy",
		},
	},
	{
		section: "## 19. Error model",
		want: []string{
			"both sends were HTTP 500 and the retry did not clear it",
			"a literal login typed as an ACL test subject, inside an MCP proposal or patch, or in a text given to `acl_diff` over MCP",
			"the operator's own files (`--from`, `--against`, `--patch`, `--invariants`), standard input and `acl.invariantsFile` are exempt",
			"`acl_diff` has `equal` and `changed` (exit 0) and `invalid` (2)",
		},
		absent: []string{
			"deterministic 500 for some invalid policies; the hint", "(also as an ACL test subject or inside a proposal)",
			"| `validation_failed` | HTTP 400, unparsable input,", "typed as an ACL test subject or inside an MCP proposal or patch (the operator's own files",
		},
	},
	{
		section: "## 16. CLI",
		want:    []string{"a policy too complex to parse or compare", "a policy-mode validate that got HTTP 500 twice (`policy_rejected_or_server_error`) and an ACL answer that is `unknown`"},
		absent:  []string{"a policy too complex to compare"},
	},
	{
		section: "## 22. Testing",
		want: []string{
			"### Probes first (read-only)", "| A-1 |", "| A-10 |", "| H-1 |", "`make probe-acl`", "TAILKEEPER_LIVE_POLICY_SOURCE",
			"7. Whether validate (policy mode) runs `sshTests`. Settled by probe A-10 (0.6.0): it does, so SSH tests ship.",
			"13. Whether preview evaluates grants, `via` and posture. With `acl_preview` (0.7.0).",
			"(with apply, after M2)", "**ACL engine, read side (0.6.0).**",
			"about 48 validate POSTs and up to 10 GETs, one request every 2 seconds", "a 429 stops the run and marks the rest not run",
			"built with `-tags probe`",
			"`column`, `test(s) failed`, `warning(s) found`, `json: unknown field`, `tag not found`, `user or host is invalid`",
			"fuzzes within its job timeout", "a 4 MiB array of `1`, 1 MiB of one-character strings)",
			"Coverage: 95% for `internal/acl` and `internal/guard`",
			"one `assertion_failed` line with its `src`", "`internal/tools/testdata/schemas/<tool>.json`", "GitOps oracle: not requested",
		},
		absent: []string{"about 40 validate calls", "fuzzes for minutes", "a 4 MiB array of `1`);", "before the SSH-test code is written"},
	},
	{
		section: "## 23. Repository layout",
		want:    []string{"internal/{acl,guard}/", "internal/safefile", "internal/probe", "internal/skeleton", "scripts/mutate.go", "github-actions,gitops,n8n-webhooks,cron", "release-notes-check", "`make probe-acl`", "acl.md"},
		absent:  []string{"internal/{plan,approve,policy,acl,events}/"},
	},
	{
		section: "## 24. Roadmap",
		want:    []string{"**0.6.0, the policy core (read side):**", "**0.7.0:**", "**After M2:**", "a docs-page drift check", "a composite setup action", "the full Terraform recipe", "`acl_history` (the log holds the policy texts, observed 20 Oct 2026);", "SSH tests (they ran on 20 Oct 2026);"},
		absent:  []string{"| M3 ACL engine | ACL validate, preview, diff, audit catalogue (and"},
	},
	{
		section: "## 26. What would make this wrong in ways tests would not catch",
		want:    []string{"A live response shape that the strict reader rejects", "A rewrite that the diff swallows", "A proposal leaves the machine"},
	},
	// rows are appended above this line
}

func TestDesignStatesTheZeroSixContract(t *testing.T) {
	data, err := os.ReadFile("../../docs/design.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	for _, r := range designRules {
		section := designSection(t, doc, r.section)
		for _, w := range r.want {
			if !strings.Contains(section, w) {
				t.Errorf("%s: missing %q", r.section, w)
			}
		}
		for _, a := range r.absent {
			if strings.Contains(section, a) {
				t.Errorf("%s: still says %q", r.section, a)
			}
		}
	}
}

// pendingProbe finds every mention of a pending probe, in any case or form.
var pendingProbe = regexp.MustCompile(`(?i)pending probe`)

// probeIDs is what follows a mark of the one form: "*pending probe* A-4" or, for a sentence
// that rests on several probes, "*pending probe* A-1, A-9" (also H-1, the history probe).
var probeIDs = regexp.MustCompile(`^\*pending probe\* ((?:[AH]-(?:\d+|n))(?:, [AH]-(?:\d+|n))*)`)

// pendingProbeProblems says where the document marks a statement in a form other than
// "*pending probe* A-n", or names a probe that §22 does not list. A-n itself is the
// placeholder the prose uses to describe the mark. The one mark that no probe settles (a
// console save) is written out here, so that a new exception is a change to this test.
func pendingProbeProblems(doc string) []string {
	var out []string
	listed := regexp.MustCompile(`(?m)^\| ([AH]-\d+) \|`)
	probes := map[string]bool{}
	for _, m := range listed.FindAllStringSubmatch(doc, -1) {
		probes[m[1]] = true
	}
	if len(probes) < 15 {
		return []string{fmt.Sprintf("found %d probes in the table of §22, want A-1 to A-14 and H-1", len(probes))}
	}
	exceptions := []string{"*pending probe*, which no probe of §22 settles:"}
	for _, at := range pendingProbe.FindAllStringIndex(doc, -1) {
		// The mark starts at the star before the words.
		start := at[0]
		if start > 0 && doc[start-1] == '*' {
			start--
		}
		rest := doc[start:min(len(doc), start+80)]
		line := 1 + strings.Count(doc[:start], "\n")
		excepted := false
		for _, e := range exceptions {
			if strings.HasPrefix(doc[start:], e) {
				excepted = true
			}
		}
		if excepted {
			continue
		}
		m := probeIDs.FindStringSubmatch(rest)
		if m == nil {
			out = append(out, fmt.Sprintf("line %d: %q is not in the form *pending probe* A-n", line, strings.SplitN(rest, "\n", 2)[0]))
			continue
		}
		for _, id := range strings.Split(m[1], ", ") {
			if id != "A-n" && !probes[id] {
				out = append(out, fmt.Sprintf("line %d: %s is not a probe in the table of §22", line, id))
			}
		}
	}
	return out
}

// Every statement that waits on a live probe says so in one form, with the probe's ID, so
// the probe that settles it can be found and the mark replaced by what was observed. A mark
// in another form (a bare "(pending probe)", an unitalicised one, an ID the table does not
// have) cannot be told from prose by the snippets above, which pin sentences, not the form.
func TestDesignMarksEveryPendingProbeOneWay(t *testing.T) {
	data, err := os.ReadFile("../../docs/design.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pendingProbeProblems(string(data)) {
		t.Error(p)
	}

	table := strings.Repeat("| A-1 | x |\n| A-2 | x |\n", 1) + "| A-3 | x |\n| A-4 | x |\n| A-5 | x |\n| A-6 | x |\n| A-7 | x |\n| A-8 | x |\n| A-9 | x |\n| A-10 | x |\n| A-11 | x |\n| A-12 | x |\n| A-13 | x |\n| A-14 | x |\n| H-1 | x |\n"
	for _, c := range []struct{ name, text, want string }{
		{"the one form", "It is so (*pending probe* A-4).\n", ""},
		{"several probes", "So (*pending probe* A-1, A-9).\n", ""},
		{"the history probe", "So (*pending probe* H-1).\n", ""},
		{"a bare mark", "It is so (pending probe).\n", "is not in the form"},
		{"not italic", "It is pending probe A-4.\n", "is not in the form"},
		{"no ID", "It is *pending probe* here.\n", "is not in the form"},
		{"an ID the table lacks", "It is *pending probe* A-99.\n", "A-99 is not a probe"},
		{"capitals", "It is Pending Probe A-4.\n", "is not in the form"},
		{"the console exception", "x (*pending probe*, which no probe of §22 settles: a save)\n", ""},
	} {
		got := pendingProbeProblems(table + c.text)
		switch {
		case c.want == "" && len(got) != 0:
			t.Errorf("%s: problems %v, want none", c.name, got)
		case c.want != "" && (len(got) != 1 || !strings.Contains(got[0], c.want)):
			t.Errorf("%s: problems %v, want one containing %q", c.name, got, c.want)
		}
	}
	if got := pendingProbeProblems("It is *pending probe* A-4.\n"); len(got) != 1 || !strings.Contains(got[0], "found") {
		t.Errorf("a document without the probe table is not refused: %v", got)
	}
}

// guardPaths finds every path under internal/ that names a guard package, as the design
// writes them: internal/guard, or internal/{acl,guard}.
var guardPaths = regexp.MustCompile(`internal/(?:\{[a-z,]*guard[a-z,]*\}|[a-z]*guard[a-z]*)`)

// The shared depth guard is one package with one name, internal/guard; the policy engine must use it or
// change the design in the same change. A misspelling (internal/guards, internal/depthguard)
// would send an implementer to a package that does not exist, and a different word for it
// (depthguard) would name a second package.
func TestDesignNamesTheGuardPackageOneWay(t *testing.T) {
	data, err := os.ReadFile("../../docs/design.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	if strings.Contains(doc, "depthguard") {
		t.Error("docs/design.md says depthguard: the package is internal/guard")
	}
	found := 0
	for _, g := range guardPaths.FindAllString(doc, -1) {
		found++
		if g != "internal/guard" && g != "internal/{acl,guard}" {
			t.Errorf("docs/design.md names the guard package %q, want internal/guard", g)
		}
	}
	if found < 4 {
		t.Errorf("found %d mentions of the guard package, want at least 4 (§4, §12.9, §22, §23): the scan found too little to judge", found)
	}
}

// TestDesignHasNoPendingProbeMarkExceptTheConsoleSave checks that the probes of
// 20 Oct 2026 replaced every mark, and that the console-save sentence is the one left.
func TestDesignHasNoPendingProbeMarkExceptTheConsoleSave(t *testing.T) {
	data, err := os.ReadFile("../../docs/design.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	hits := pendingProbe.FindAllStringIndex(doc, -1)
	if len(hits) != 1 {
		t.Fatalf("pending probe occurs %d times, want the console-save sentence only", len(hits))
	}
	start := hits[0][0]
	if start > 0 && doc[start-1] == '*' {
		start--
	}
	const exception = "*pending probe*, which no probe of §22 settles:"
	if !strings.HasPrefix(doc[start:], exception) {
		t.Fatalf("the remaining mark is %q", doc[start:min(len(doc), start+80)])
	}
}

// TestDesignStatesTheProbeOutcomes pins one observed sentence per probe the release rests on.
func TestDesignStatesTheProbeOutcomes(t *testing.T) {
	data, err := os.ReadFile("../../docs/design.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	for _, s := range []string{
		"`grants: []` is deny-all like `acls: []`",
		"the server refused every repeated key it was sent, a case collision at the top level among them",
		"both sends were HTTP 500 and the retry did not clear it",
		"`sshTests` ran and the failure had the SSH form",
		"`old` and `new` were JSON strings and held a known section",
		"five positions had no message",
	} {
		if !strings.Contains(doc, s) {
			t.Errorf("docs/design.md does not state %q", s)
		}
	}
	if strings.Contains(doc, "the server accepted it") {
		t.Error("the folding section still says the server accepted a repeated key")
	}
}

func TestDesignSaysTheServerRefusesARepeatedKey(t *testing.T) {
	data, err := os.ReadFile("../../docs/design.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	fold := designSection(t, doc, "## 12. ACL engine")
	const refused = "A live policy is not described as having been accepted with a repeated key"
	if n := strings.Count(fold, refused); n != 1 {
		t.Errorf("the folding section says %q %d times, want once", refused, n)
	}
	if strings.Contains(fold, "the server accepted it") {
		t.Error("the folding section still says the server accepted it")
	}
	// The case rule is as far as probe A-4 went: the one collision it sent was at the top
	// level, and the design says so rather than that the rule covers every object.
	for _, s := range []string{
		"the one case collision was sent at the top level only",
		"what the server does with a case collision below the top level was not observed",
	} {
		if !strings.Contains(fold, s) {
			t.Errorf("the folding section does not say %q", s)
		}
	}
}

// fencedBlock returns the first ``` block of a section. The layout is that block: prose
// beside it names the same files, which would hide a line deleted from the layout.
func fencedBlock(t *testing.T, section string) string {
	t.Helper()
	lines := strings.Split(section, "\n")
	start := -1
	for i, l := range lines {
		if !strings.HasPrefix(l, "```") {
			continue
		}
		if start < 0 {
			start = i + 1
			continue
		}
		return strings.Join(lines[start:i], "\n")
	}
	t.Fatal("the section has no closed fenced block")
	return ""
}

func TestDesignNamesThePackagesTheLayoutShips(t *testing.T) {
	data, err := os.ReadFile("../../docs/design.md")
	if err != nil {
		t.Fatal(err)
	}
	layout := fencedBlock(t, designSection(t, string(data), "## 23. Repository layout"))
	for _, name := range []string{"internal/safefile", "internal/probe", "internal/skeleton", "scripts/mutate.go", "acl.md", "github-actions,gitops,n8n-webhooks,cron", "release-notes-check"} {
		if !strings.Contains(layout, name) {
			t.Errorf("the layout block of §23 does not name %s", name)
		}
	}
}

// The subject rule is the same text in the design and in the published threat model:
// the sentences below are pinned whole, in both files, so a sentence that says the opposite,
// or a count that disagrees ("Two things"), fails in whichever file carries it.
func TestDesignAndTheThreatModelStateTheSubjectRule(t *testing.T) {
	design, err := os.ReadFile("../../docs/design.md")
	if err != nil {
		t.Fatal(err)
	}
	model, err := os.ReadFile("../../docs/threat-model.md")
	if err != nil {
		t.Fatal(err)
	}
	sec := designSection(t, string(design), "## 3. Threat model")
	rule := aclSection(t, string(model), "## Subjects an agent types")
	for _, s := range []string{
		"While masking is on, a user's login enters a call only as a pseudonym or as a masked value that carries one.",
		"A login a pseudonym stood for is masked on the way out, whole and without a pseudonym beside the echo, and so is each word of its local part where the word stands alone.",
		"Two logins of different lengths that mask to one form produce the same result.",
		"Three things are not masked.",
		"A word shorter than two bytes is not.",
		"A word the caller typed is not masked as a local part: it is shown as typed, because a text that masked it only when it was a word of a login would answer each guess.",
		"A local part of a login this call did not resolve is not found, because masking reads whole logins.",
		"Every echo of text the caller typed (an SSH user, a destination, a protocol) is masked without a pseudonym, because a pseudonym beside a guess would confirm it.",
	} {
		if !strings.Contains(sec, s) {
			t.Errorf("design §3 does not say %q", s)
		}
		if !strings.Contains(rule, s) {
			t.Errorf("threat-model.md does not say %q", s)
		}
	}
	// The sentences are one paragraph, in this order, in each file.
	for name, text := range map[string]string{"design §3": sec, "threat-model.md": rule} {
		at := -1
		for _, s := range []string{"Three things are not masked.", "A word shorter than two bytes is not.", "A word the caller typed is not masked", "A local part of a login this call did not resolve", "Every echo of text the caller typed"} {
			i := strings.Index(text, s)
			if i < at {
				t.Errorf("%s: %q is out of order", name, s)
			}
			at = max(at, i)
		}
	}
}

// probeSkeleton is the part of a committed probe record the Observed column of §22 is held to.
type probeSkeleton struct {
	Checks []struct {
		Name string `json:"name"`
		Got  bool   `json:"got"`
	} `json:"checks"`
	Observations []struct {
		Label  string `json:"label"`
		Result struct {
			Status int `json:"status"`
			Paths  []struct {
				Path string `json:"path"`
			} `json:"paths"`
		} `json:"result"`
	} `json:"observations"`
	Counts map[string]int `json:"counts"`
}

func loadSkeleton(t *testing.T, id string) probeSkeleton {
	t.Helper()
	b, err := os.ReadFile("../../internal/api/apitest/testdata/observed/" + id + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var sk probeSkeleton
	if err := json.Unmarshal(b, &sk); err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	return sk
}

func (sk probeSkeleton) check(t *testing.T, id, name string) bool {
	t.Helper()
	for _, c := range sk.Checks {
		if c.Name == name {
			return c.Got
		}
	}
	t.Fatalf("%s has no check %q", id, name)
	return false
}

func (sk probeSkeleton) observation(t *testing.T, id, label string) (status int, paths []string) {
	t.Helper()
	for _, o := range sk.Observations {
		if o.Label == label {
			for _, p := range o.Result.Paths {
				paths = append(paths, p.Path)
			}
			return o.Result.Status, paths
		}
	}
	t.Fatalf("%s has no observation %q", id, label)
	return 0, nil
}

// observedCells are the Observed cells of the §22 table that carry a decision, whole. Each is
// a restatement of a committed skeleton (internal/api/apitest/testdata/observed): a cell
// edited to say something else fails here, and so does a cell the skeleton no longer bears out.
var observedCells = map[string]string{
	"A-1":  "`grants: []` passed like `acls: []` (deny-all); `null` failed like absent",
	"A-2":  "an empty array, an empty body and `null` were HTTP 400; one test was HTTP 200 with `data`",
	"A-3":  "HTTP 200 with a bare message and no `data`, not HTTP 400",
	"A-4":  "the server refused every repeated key it was sent; the one case collision was sent at the top level",
	"A-6":  "HTTP 500 both times; the retry did not clear it",
	"A-7":  "the details GET and the policy-mode POST had the same warning set, and both sets were empty (0 and 0)",
	"A-11": "raw HuJSON and standardized HuJSON were accepted; a byte order mark was HTTP 400",
	"A-14": "five positions had no message; the object key in `hosts` had a message",
}

// TestDesignObservedColumnMatchesTheSkeletons pins the §22 Observed cell of each probe that
// decides something, and checks the facts it states against the probe's committed record,
// never against the expected texts.
func TestDesignObservedColumnMatchesTheSkeletons(t *testing.T) {
	data, err := os.ReadFile("../../docs/design.md")
	if err != nil {
		t.Fatal(err)
	}
	table := designSection(t, string(data), "## 22. Testing")
	cells := map[string]string{}
	for _, line := range strings.Split(table, "\n") {
		f := strings.Split(line, " | ")
		if len(f) == 5 && regexp.MustCompile(`^\| [AH]-\d+$`).MatchString(f[0]) {
			cells[strings.TrimPrefix(f[0], "| ")] = f[3]
		}
	}
	for id, want := range observedCells {
		if got := cells[id]; got != want {
			t.Errorf("%s: the Observed cell is %q, want %q", id, got, want)
		}
	}

	// A-1: the empty grants list passed, as the empty acls list did, and null failed like absent.
	a1 := loadSkeleton(t, "A-1")
	if a1.check(t, "A-1", "grants [] fails like absent") || !a1.check(t, "A-1", "acls [] passes") || !a1.check(t, "A-1", "acls null fails like absent") {
		t.Error("A-1: the skeleton does not bear out the cell")
	}
	for _, label := range []string{"acls []", "grants []"} {
		if st, paths := a1.observation(t, "A-1", label); st != 200 || strings.Join(paths, ",") != "$" {
			t.Errorf("A-1 %s: status %d paths %v, want a bare 200 object", label, st, paths)
		}
	}

	// A-3: every rejection came back HTTP 200 with a bare message, and none as HTTP 400.
	a3 := loadSkeleton(t, "A-3")
	if len(a3.Observations) != 4 {
		t.Errorf("A-3 holds %d observations, want 4", len(a3.Observations))
	}
	for _, o := range a3.Observations {
		var paths []string
		for _, p := range o.Result.Paths {
			paths = append(paths, p.Path)
		}
		if o.Result.Status != 200 || strings.Join(paths, ",") != "$,message" {
			t.Errorf("A-3 %s: status %d paths %v, want a 200 with a bare message", o.Label, o.Result.Status, paths)
		}
	}

	// A-4: five sends, each with a repeated key, each answered with a message; the case
	// collision was one send, at the top level.
	a4 := loadSkeleton(t, "A-4")
	if len(a4.Observations) != 5 {
		t.Errorf("A-4 holds %d observations, want 5", len(a4.Observations))
	}
	collisions := 0
	for _, o := range a4.Observations {
		var paths []string
		for _, p := range o.Result.Paths {
			paths = append(paths, p.Path)
		}
		if o.Result.Status != 200 || strings.Join(paths, ",") != "$,message" {
			t.Errorf("A-4 %s: status %d paths %v, want a refusal with a message", o.Label, o.Result.Status, paths)
		}
		if strings.Contains(o.Label, "TagOwners") {
			collisions++
		}
	}
	if collisions != 1 {
		t.Errorf("A-4 sent %d case collisions, want the one at the top level", collisions)
	}
	for _, c := range a4.Checks {
		if c.Got {
			t.Errorf("A-4 check %q holds: the server accepted what the cell says it refused", c.Name)
		}
	}

	// A-6: both sends answered 500.
	a6 := loadSkeleton(t, "A-6")
	for _, label := range []string{"the first send", "the second send"} {
		if st, _ := a6.observation(t, "A-6", label); st != 500 {
			t.Errorf("A-6 %s: status %d, want 500", label, st)
		}
	}

	// A-7: the two calls had the same warning set, and the set was empty on both: the cell says
	// so, because a baseline the two calls share cannot be told from no warnings at all.
	a7 := loadSkeleton(t, "A-7")
	if !a7.check(t, "A-7", "the same warning set both ways") {
		t.Error("A-7: the skeleton does not bear out that the two calls had the same warning set")
	}
	for _, c := range []string{"details errors", "details warnings", "policy-mode error lines", "policy-mode warnings"} {
		if n, ok := a7.Counts[c]; !ok || n != 0 {
			t.Errorf("A-7: %s is %d (present %v); the cell says both sets were empty (0 and 0)", c, n, ok)
		}
	}
	for _, label := range []string{"live policy (details=true), held in memory for the probes that need it", "the live text, validated in policy mode"} {
		if st, _ := a7.observation(t, "A-7", label); st != 200 {
			t.Errorf("A-7 %s: status %d, want 200", label, st)
		}
	}

	// A-11: the byte order mark was HTTP 400, the other two sends HTTP 200.
	a11 := loadSkeleton(t, "A-11")
	for label, want := range map[string]int{
		"raw HuJSON, a leading comment and trailing commas": 200,
		"the same, standardized":                            200,
		"the same, with a byte order mark":                  400,
	} {
		if st, _ := a11.observation(t, "A-11", label); st != want {
			t.Errorf("A-11 %s: status %d, want %d", label, st, want)
		}
	}
}
