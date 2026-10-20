package tkerr

import (
	"sort"
	"strings"
	"testing"
)

// hintProblems says what is wrong with a table of program hints: a code without
// one, a hint for a code that does not exist, and a hint that is not one
// sentence that says what to do about retrying.
func hintProblems(hints map[Code]string, codes []Code) []string {
	var problems []string
	known := map[Code]bool{}
	for _, c := range codes {
		known[c] = true
		h, ok := hints[c]
		switch {
		case !ok || h == "":
			problems = append(problems, string(c)+": no program hint")
		case strings.ContainsAny(h, "\r\n"):
			problems = append(problems, string(c)+": the hint has a line break")
		case len(h) > 200:
			problems = append(problems, string(c)+": the hint is longer than 200 bytes")
		case !strings.HasSuffix(h, "."):
			problems = append(problems, string(c)+": the hint is not a sentence ending in a full stop")
		case !strings.Contains(strings.ToLower(h), "retry"):
			problems = append(problems, string(c)+": the hint does not say whether to retry")
		}
	}
	for c := range hints {
		if !known[c] {
			problems = append(problems, string(c)+": a hint for a code that is not declared")
		}
	}
	sort.Strings(problems)
	return problems
}

// Every error code has a hint addressed to a program: an agent or a script reads
// what to do about it, in particular whether to retry. A code added later fails
// this test until its hint is written.
func TestEveryErrorCodeHasAProgramHint(t *testing.T) {
	var codes []Code
	for c := range declaredCodes(t) {
		codes = append(codes, c)
	}
	if len(codes) < 30 {
		t.Fatalf("found %d codes in tkerr.go: the parser lost the const block", len(codes))
	}
	for _, p := range hintProblems(programHints, codes) {
		t.Error(p)
	}
	for _, c := range codes {
		if got := ProgramHint(c); got != programHints[c] {
			t.Errorf("ProgramHint(%s) = %q", c, got)
		}
	}
	if ProgramHint("no_such_code") != "" {
		t.Error("an unknown code has a hint")
	}
}

// The check above must be able to fail: plant one problem of each kind.
func TestHintProblemsFindsEachKindOfProblem(t *testing.T) {
	hints := map[Code]string{
		"fine":      "Do not retry.",
		"empty":     "",
		"two_lines": "Do not retry.\nReport it.",
		"long":      strings.Repeat("retry ", 40) + ".",
		"no_stop":   "Do not retry",
		"no_retry":  "Report it to the owner.",
		"stale":     "Do not retry.",
	}
	codes := []Code{"fine", "empty", "two_lines", "long", "no_stop", "no_retry", "missing"}
	got := strings.Join(hintProblems(hints, codes), "\n")
	for _, want := range []string{"empty: no program hint", "missing: no program hint", "two_lines: the hint has a line break",
		"long: the hint is longer than 200 bytes", "no_stop: the hint is not a sentence", "no_retry: the hint does not say whether to retry",
		"stale: a hint for a code that is not declared"} {
		if !strings.Contains(got, want) {
			t.Errorf("problems lack %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "fine:") {
		t.Errorf("a good hint was reported:\n%s", got)
	}
}
