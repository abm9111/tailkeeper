package workflows

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// The subject rule is stated in SECURITY.md, in the README and in the threat model. Each
// pin below is a whole clause the documents make about what the tools do, so a document
// that says the opposite, or drops the clause, fails on that clause. A word that every
// version of the text contains ("canary", "local part", "GET") pins nothing.

const (
	securityBulletStart = "- Masking personal data is a best effort"
	readmeBulletStart   = "  - With a privacy key configured, every masked name"
	threatHeading       = "## Subjects an agent types"
)

// securityPins are clauses of SECURITY.md's best-effort bullet.
var securityPins = []string{
	"a typed login in its source or in a destination, an SSH destination included, is refused (`filter_refused`) while masking is on",
	"when the source is a pseudonym, each distinct SSH user of a call takes one validation token",
	"is masked where it stands alone, except for a word the call itself typed, which is shown as typed",
	"what `acl_test` shows of the text it was given (an SSH user, a destination, a protocol) are masked without one",
	"The refusal of a typed login also covers the strings of a policy proposal or patch that `acl_validate` is given over MCP, comments excepted, and a text that `acl_diff` is given over MCP",
	"`srcPostureAttrs` names are not logins and are not held to it",
	"A file the operator names, standard input and the invariants file are the operator's own documents: their logins are accepted and shown masked without pseudonyms",
	"`acl_test` and `acl_validate` send a test or a policy to `POST .../acl/validate`, which changes nothing, as does `doctor --probe` with the live policy, a canary and two synthetic documents",
	"An SSH user is an account name and is not held to that rule",
	"an SSH test goes out with a canary, a test that must fail: a missing canary is `unknown`, never a pass",
	"A known limit: a bare local part shorter than two bytes is not masked, and a local part of a login this call did not resolve is left whole, because masking reads whole logins",
}

// readmePins are clauses of the README bullet that states the privacy key and the refusals.
var readmePins = []string{
	"a typed login in `acl_test`'s `src` or in a destination, an SSH destination included (name the user by the pseudonym `users_list` shows)",
	"What `acl_test` is given comes back as typed (an SSH user, a destination, a protocol), masked without a pseudonym",
	"each distinct SSH user of the call takes one validation token",
	"An SSH user is an account name, so it is not held to that rule",
	"A file the operator names is the operator's own document: its logins are accepted, sent to Tailscale and shown masked without pseudonyms",
}

// threatPins are clauses of the threat model's section on subjects an agent types.
var threatPins = []string{
	"A literal login is `filter_refused`; the hint names the pseudonym route, or, without a privacy key, says that pseudonyms need one",
	"zero matches or several is `validation_failed`",
	"An SSH user is an operating-system account, not a Tailscale login, and is not refused as one",
	"every string of a policy proposal or a patch given over MCP, keys and values, comments excepted, a text given to `acl_diff` over MCP",
	"are the operator's own documents. Their logins are accepted, sent to Tailscale, and shown masked without pseudonyms",
	"An agent with a shell that writes one of those files is outside this boundary",
	"the only request other than GET is `POST .../acl/validate`",
	"A proposal, a test, an SSH test and, under `doctor --probe`, the live policy with a canary appended and two synthetic documents are sent to Tailscale for validation and change nothing there",
	"`srcPostureAttrs` pass through on the tests-mode request and are refused together with SSH tests",
	"`unknown` means the live policy could not be read, which is not a claim that no rule is posture-gated",
	"with an absent access section (allow-all) the canary is a denial that fails",
	"with an empty one (deny-all) an acceptance that fails",
	"with a non-empty one either line is the canary",
	"A missing canary, a second copy, or one in another shape is `unknown`, never a pass",
	"A `check` user with no line is `unknown`, never a pass",
	"and so is each word of its local part where the word stands alone",
	"A word shorter than two bytes is not",
	"A word the caller typed is not masked as a local part: it is shown as typed",
	"A local part of a login this call did not resolve is not found, because masking reads whole logins",
	"Every echo of text the caller typed (an SSH user, a destination, a protocol) is masked without a pseudonym",
}

// threatAbsent are statements the threat model must not make: the first is the error a
// reader of the code would not make, a resolved local part left whole.
var threatAbsent = []string{
	"is left whole",
	"is refused as one",
	"masked as a local part, ",
}

// subjectDocProblems checks the three documents and returns what is wrong with them.
func subjectDocProblems(security, readme, threat string) []string {
	var out []string
	check := func(doc, text string, pins []string) {
		for _, pin := range pins {
			if !strings.Contains(text, pin) {
				out = append(out, fmt.Sprintf("%s lacks: %s", doc, pin))
			}
		}
	}
	bullet := lineStarting(security, securityBulletStart)
	if bullet == "" {
		out = append(out, "SECURITY.md has no best-effort bullet")
	}
	check("SECURITY.md's best-effort bullet", bullet, securityPins)
	if n := countPrefixes(security, maskingBulletPrefixes); n != 5 {
		out = append(out, fmt.Sprintf("SECURITY.md has %d masking bullets, want 5", n))
	}

	line := lineStarting(readme, readmeBulletStart)
	if line == "" {
		out = append(out, "README has no privacy-key bullet")
	}
	check("README's privacy-key bullet", line, readmePins)

	section := sectionUnder(threat, threatHeading)
	if section == "" {
		out = append(out, "docs/threat-model.md has no Subjects an agent types section")
	}
	check("the threat model's subject section", section, threatPins)
	for _, bad := range threatAbsent {
		if strings.Contains(section, bad) {
			out = append(out, fmt.Sprintf("the threat model's subject section says %q", bad))
		}
	}
	return out
}

func TestTheSubjectRuleIsDocumentedWhereItIsEnforced(t *testing.T) {
	problems := subjectDocProblems(
		readRepoFile(t, "../../SECURITY.md"),
		readRepoFile(t, "../../README.md"),
		readRepoFile(t, "../../docs/threat-model.md"))
	for _, p := range problems {
		t.Error(p)
	}
}

// Each plant is a document that states the rule wrongly, or drops a clause of it. The
// check must name the clause.
func TestTheSubjectDocsCheckRefusesEachWrongStatement(t *testing.T) {
	docs := [3]string{
		readRepoFile(t, "../../SECURITY.md"),
		readRepoFile(t, "../../README.md"),
		readRepoFile(t, "../../docs/threat-model.md"),
	}
	const sec, readme, threat = 0, 1, 2
	for _, tc := range []struct {
		name      string
		doc       int
		old, new  string
		wantLacks string
		wantSays  string
	}{
		{
			name: "SECURITY.md drops the skip of a word shorter than two bytes", doc: sec,
			old: "a bare local part shorter than two bytes is not masked, and ", new: "",
			wantLacks: "A known limit: a bare local part shorter than two bytes",
		},
		{
			name: "SECURITY.md drops the validation token of each SSH user", doc: sec,
			old: "when the source is a pseudonym, each distinct SSH user of a call takes one validation token (`acl.validatePerMinute` a minute), so the guesses stay at the rate of that limit. ", new: "",
			wantLacks: "each distinct SSH user of a call takes one validation token",
		},
		{
			name: "SECURITY.md masks a word the caller typed", doc: sec,
			old: "except for a word the call itself typed, which is shown as typed", new: "including a word the call itself typed",
			wantLacks: "except for a word the call itself typed, which is shown as typed",
		},
		{
			name: "SECURITY.md drops the operator's own documents", doc: sec,
			old: "are the operator's own documents: their logins are accepted and shown masked without pseudonyms", new: "are refused",
			wantLacks: "the operator's own documents",
		},
		{
			name: "README drops the operator's own document", doc: readme,
			old: "A file the operator names is the operator's own document: its logins are accepted, sent to Tailscale and shown masked without pseudonyms.", new: "",
			wantLacks: "A file the operator names is the operator's own document",
		},
		{
			name: "README says the echo of typed text carries a pseudonym", doc: readme,
			old: "(an SSH user, a destination, a protocol), masked without a pseudonym", new: "(an SSH user, a destination, a protocol), masked with a pseudonym",
			wantLacks: "What `acl_test` is given comes back as typed",
		},
		{
			name: "SECURITY.md says an SSH user is refused like a login", doc: sec,
			old: "An SSH user is an account name and is not held to that rule", new: "An SSH user is refused like a login and is held to that rule",
			wantLacks: "An SSH user is an account name and is not held to that rule",
		},
		{
			name: "README says an SSH user is refused like a login", doc: readme,
			old: "An SSH user is an account name, so it is not held to that rule", new: "An SSH user is refused like a login, so it is held to that rule",
			wantLacks: "An SSH user is an account name, so it is not held to that rule",
		},
		{
			name: "the threat model says an SSH user is refused as a login", doc: threat,
			old: "and is not refused as one", new: "and is refused as one",
			wantLacks: "is not refused as one", wantSays: "is refused as one",
		},
		{
			name: "the threat model has the allow-all canary in the wrong direction", doc: threat,
			old:       "with an absent access section (allow-all) the canary is a denial that fails, with an empty one (deny-all) an acceptance that fails",
			new:       "with an absent access section (allow-all) the canary is an acceptance that fails, with an empty one (deny-all) a denial that fails",
			wantLacks: "with an absent access section (allow-all) the canary is a denial that fails",
		},
		{
			name: "the threat model has the canary fixed for a non-empty policy", doc: threat,
			old: "and with a non-empty one either line is the canary", new: "and with a non-empty one a denial is the canary",
			wantLacks: "with a non-empty one either line is the canary",
		},
		{
			name: "the threat model leaves a resolved local part whole", doc: threat,
			old: "and so is each word of its local part where the word stands alone", new: "while its local part is left whole",
			wantLacks: "and so is each word of its local part where the word stands alone", wantSays: "is left whole",
		},
		{
			name: "the threat model masks a word the caller typed", doc: threat,
			old: "A word the caller typed is not masked as a local part: it is shown as typed", new: "A word the caller typed is masked as a local part",
			wantLacks: "A word the caller typed is not masked as a local part: it is shown as typed",
		},
		{
			name: "the threat model drops the skip of a short word", doc: threat,
			old: "A word shorter than two bytes is not. ", new: "",
			wantLacks: "A word shorter than two bytes is not",
		},
		{
			name: "the threat model drops the echo of typed text", doc: threat,
			old: "Every echo of text the caller typed (an SSH user, a destination, a protocol) is masked without a pseudonym", new: "Every echo of text the caller typed is masked with a pseudonym",
			wantLacks: "Every echo of text the caller typed (an SSH user, a destination, a protocol) is masked without a pseudonym",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if n := strings.Count(docs[tc.doc], tc.old); n != 1 {
				t.Fatalf("the plant's old text occurs %d times, want 1: %q", n, tc.old)
			}
			planted := docs
			planted[tc.doc] = strings.Replace(docs[tc.doc], tc.old, tc.new, 1)
			problems := strings.Join(subjectDocProblems(planted[sec], planted[readme], planted[threat]), "\n")
			if tc.wantLacks != "" && !namesMissingClause(problems, tc.wantLacks) {
				t.Errorf("the check does not name the missing clause %q:\n%s", tc.wantLacks, problems)
			}
			if tc.wantSays != "" && !strings.Contains(problems, "says \""+tc.wantSays+"\"") {
				t.Errorf("the check does not refuse the statement %q:\n%s", tc.wantSays, problems)
			}
		})
	}
}

// namesMissingClause reports whether a problem line says that a clause containing want is lacking.
func namesMissingClause(problems, want string) bool {
	for _, line := range strings.Split(problems, "\n") {
		if strings.Contains(line, " lacks: ") && strings.Contains(line, want) {
			return true
		}
	}
	return false
}

// The bullets the address tests count are those that begin with one of four prefixes
// (five bullets, two of which begin "Masking reads"); this change adds none.
var maskingBulletPrefixes = []string{
	"- Masking reads",
	"- Masked text is read again",
	"- Masking does not recognise",
	"- Masking also errs",
}

func readRepoFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func lineStarting(page, prefix string) string {
	for _, line := range strings.Split(page, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

func countPrefixes(page string, prefixes []string) int {
	n := 0
	for _, line := range strings.Split(page, "\n") {
		for _, prefix := range prefixes {
			if strings.HasPrefix(line, prefix) {
				n++
				break
			}
		}
	}
	return n
}

func sectionUnder(page, heading string) string {
	i := strings.Index(page, heading)
	if i < 0 {
		return ""
	}
	rest := page[i+len(heading):]
	if j := strings.Index(rest, "\n## "); j >= 0 {
		return rest[:j]
	}
	return rest
}

// postingSentenceProblems returns, for each line of a document that names the validate
// endpoint beside acl_test (the lines that list what sends to it), the lines that do not
// also name doctor --probe, which posts the live policy, a canary and two synthetic
// documents there. The count of lines checked is returned so a document that no longer
// has such a line cannot pass by having nothing to check.
func postingSentenceProblems(doc, text string) (problems []string, checked int) {
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, "POST .../acl/validate") || !strings.Contains(line, "`acl_test`") {
			continue
		}
		checked++
		if !strings.Contains(line, "doctor --probe") {
			problems = append(problems, doc+" names the commands that post to validate and leaves out doctor --probe: "+line[:min(len(line), 80)])
		}
	}
	return problems, checked
}

func TestEveryDocumentThatListsWhatPostsToValidateNamesDoctorProbe(t *testing.T) {
	for _, doc := range []string{"README.md", "CLAUDE.md", "SECURITY.md", "docs/threat-model.md"} {
		problems, checked := postingSentenceProblems(doc, readRepoFile(t, "../../"+doc))
		if checked == 0 {
			t.Errorf("%s has no line that lists what posts to the validate endpoint", doc)
		}
		for _, p := range problems {
			t.Error(p)
		}
	}
}

func TestThePostingCheckRefusesALineWithoutDoctorProbe(t *testing.T) {
	line := "- `acl_test` and `acl_validate` send a test to `POST .../acl/validate`.\n"
	if problems, checked := postingSentenceProblems("x", line); len(problems) != 1 || checked != 1 {
		t.Errorf("a line that omits doctor --probe: %d problems over %d lines, want 1 over 1", len(problems), checked)
	}
	if problems, _ := postingSentenceProblems("x", strings.Replace(line, "send", "and doctor --probe send", 1)); len(problems) != 0 {
		t.Errorf("a line that names doctor --probe is refused: %v", problems)
	}
}
