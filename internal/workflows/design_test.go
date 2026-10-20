package workflows

import (
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
			"stored errors (*pending probe* A-8:", "if policy mode runs `sshTests` (*pending probe* A-10, §22))",
			"a file (a side for the CLI only: MCP takes text or a patch, never a path), the live policy and",
			"0.6.0 if the log holds the policy texts (*pending probe* H-1), otherwise metadata only in 0.7.0",
			"validated in policy mode with the configured invariants, if any",
			"the live policy and, if `acl_history` ships, a stored version (*pending probe* H-1); at least one side is not the live policy",
			"a keyed `semanticDigest` of the normal form (§12.10) when a privacy key is loaded",
			"in effect only with `overrideLocalDNS` on and alpha enabled",
		},
		absent: []string{
			"split-DNS `nodeAttrs`", "arrive in M3; until then", "pass only on an empty body",
			"stored errors; `view", "validated in policy mode with the invariants;", "a file and a stored version",
			"in effect only with `overrideLocalDNS` on, which", "if a probe shows policy mode runs", "if a probe shows the log holds",
		},
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
		},
		absent: []string{"`tag://`", "`group://`", "Server warnings come from a separate `details=true` call"},
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
		},
		absent: []string{"`acl test --invariants`", "(read credential): exit 9 on failure (0.3.0's"},
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
			"A statement marked *pending probe* A-n describes behaviour", "names each (*pending probe* A-1, A-9)",
			"The one mark with no probe ID, in §12.10, waits for a console save",
			"the shape of that body is *pending probe* A-8, since",
			"differs from the plain GET's (*pending probe* A-8),",
			"and whether map keys fold too, is §12.9's folding rule (*pending probe* A-4).",
			"`unknown` under a 200 in policy mode (*pending probe* A-3).",
			"Whether it also runs `sshTests` is *pending probe* A-10 (live acceptance item 7)",
			"whichever the probe shows is accepted (*pending probe* A-11).",
			"(*pending probe* A-2 confirms how the endpoint treats an array, an empty body and `null`)",
			"The canary's shape is *pending probe* A-1, A-9;",
			"Whether a 200 can carry a bare message is *pending probe* A-3;",
			"for some invalid policies (*pending probe* A-6).",
			"return the same warnings is *pending probe* A-7;",
			"The grammar is *pending probe* A-9:",
			"(inferred from its error texts; *pending probe* A-4).",
			"Whether map keys fold too (a group name in `groups`, a host in `hosts`) is *pending probe* A-4,",
			"(the server's own view is *pending probe* A-5)",
			"(*pending probe*, which no probe of §22 settles: a console save captured before and after on a scratch tailnet",
			"and whether `grants` alone cancels the default allow-all, are *pending probe* A-1.",
			"Whether the ETag is the SHA-256 of the formatted policy is *pending probe* A-13;",
		},
	},
	{
		// Corrections to the first draft of §12 (what ships in 0.6.0, how a proposal is made, the validation ranges).
		section: "## 12. ACL engine",
		want: []string{
			"Two parts of that range ship in 0.6.0",
			"an agent proposes a change by validating a JSON Patch",
			"In tests mode (`acl_test`)", "any other 400 stays `validation_failed`, and a 200 that carries a message and no results stays an unrecognised-response error, as in 0.5.0 (`readValidation` in `internal/api/client.go`)",
			"if it does, SSH assertions run in the same call and `acl_test` runs SSH tests through a proposed copy of the live policy with the tests appended; if it does not, SSH tests leave 0.6.0 and wait for M2.",
			"requiring exactly one match; zero or several is `validation_failed`.", "refused before anything is sent, with `validation_failed`;",
			"In policy mode (`acl_validate`) the strict reader below applies: a 400 with a bare `{message}` is `rejected`",
			"a message with no results is `rejected` under a 400",
			"for a patch, `patchedBytes` and `patchedDigest`",
			"`case_collision` (struct objects only)", "the top level, the rule arrays, `autoApprovers` and `derpMap`",
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
		},
	},
	{
		section: "## 19. Error model",
		want: []string{
			"deterministic 500 for some invalid policies (*pending probe* A-6)",
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
			"7. Whether validate (policy mode) runs `sshTests`. Settled by probe A-10",
			"13. Whether preview evaluates grants, `via` and posture. With `acl_preview` (0.7.0).",
			"(with apply, after M2)", "**ACL engine, read side (0.6.0).**",
			"about 48 validate POSTs and up to 10 GETs, one request every 2 seconds", "a 429 stops the run and marks the rest not run",
			"built with `-tags probe`",
			"`column`, `test(s) failed`, `warning(s) found`, `json: unknown field`, `tag not found`, `user or host is invalid`",
			"fuzzes within its job timeout", "a 4 MiB array of `1`, 1 MiB of one-character strings)",
			"Coverage: 95% for `internal/acl` and `internal/guard`",
			"one `assertion_failed` line with its `src`", "`internal/tools/testdata/schemas/<tool>.json`", "GitOps oracle: not requested",
		},
		absent: []string{"about 40 validate calls", "fuzzes for minutes", "a 4 MiB array of `1`);"},
	},
	{
		section: "## 23. Repository layout",
		want:    []string{"internal/{acl,guard}/", "github-actions,gitops,n8n-webhooks,cron", "release-notes-check", "`make probe-acl`", "acl.md"},
		absent:  []string{"internal/{plan,approve,policy,acl,events}/"},
	},
	{
		section: "## 24. Roadmap",
		want:    []string{"**0.6.0, the policy core (read side):**", "**0.7.0:**", "**After M2:**", "a docs-page drift check", "a composite setup action", "the full Terraform recipe", "and, if a probe allows, `acl_history` (*pending probe* H-1);", "and, if a probe allows, SSH tests (*pending probe* A-10);"},
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
