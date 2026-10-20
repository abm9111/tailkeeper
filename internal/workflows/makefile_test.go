package workflows

import (
	"os"
	"strings"
	"testing"
)

// makeRecipe returns the command lines of one target of a Makefile, each without its
// leading tab and any leading @: the tab-indented lines after "target:", up to the first
// line that is neither a command nor blank.
func makeRecipe(makefile, target string) []string {
	var out []string
	in := false
	for _, line := range strings.Split(makefile, "\n") {
		switch {
		case !in:
			in = strings.HasPrefix(line, target+":")
		case strings.HasPrefix(line, "\t"):
			out = append(out, strings.TrimPrefix(strings.TrimPrefix(line, "\t"), "@"))
		case strings.TrimSpace(line) == "":
		default:
			return out
		}
	}
	return out
}

// actionlintProblems says what is wrong with the actionlint target of a Makefile: it
// must print the version of shellcheck before it runs the checks that call it.
func actionlintProblems(makefile string) []string {
	recipe := makeRecipe(makefile, "actionlint")
	if len(recipe) == 0 {
		return []string{"the Makefile has no actionlint target"}
	}
	version, run := -1, -1
	for i, line := range recipe {
		if strings.TrimSpace(line) == "shellcheck --version" && version < 0 {
			version = i
		}
		if strings.Contains(line, "$(ACTIONLINT)") && run < 0 {
			run = i
		}
	}
	switch {
	case version < 0:
		return []string{"the actionlint target does not print the version of shellcheck (`shellcheck --version`): CI uses the shellcheck on its runner image, and a check that is green locally and red in CI cannot be traced to a version"}
	case run < 0:
		return []string{"the actionlint target does not run $(ACTIONLINT)"}
	case version > run:
		return []string{"the actionlint target prints the version of shellcheck after the checks that use it"}
	}
	// Without shellcheck, actionlint skips the shell in the workflow steps and scripts/ goes
	// unchecked, and the target must say so and fail, not go on green. The guard is a line
	// of its own that stops the recipe, and the scripts are checked by a line of their own
	// that is neither ignored (a leading -) nor allowed to fail (|| true).
	guard, scripts := false, false
	for _, line := range recipe {
		if strings.HasPrefix(line, "command -v shellcheck") && strings.Contains(line, "exit 1") && !strings.Contains(line, "|| true") {
			guard = true
		}
		if strings.TrimSpace(line) == "shellcheck scripts/*.sh" {
			scripts = true
		}
	}
	var problems []string
	if !guard {
		problems = append(problems, "the actionlint target has no `command -v shellcheck` line that exits 1 when shellcheck is missing (a leading - or `|| true` makes it a no-op): without shellcheck the shell in the workflow steps goes unchecked and the target is green")
	}
	if !scripts {
		problems = append(problems, "the actionlint target has no plain `shellcheck scripts/*.sh` line (a leading - or `|| true` would let a finding pass): the scripts under scripts/ go unchecked")
	}
	return problems
}

// releaseCheckProblems says what is wrong with the release-check target: it runs the notes
// check before its snapshot, which is the one use of the notes fixture that exercises the
// release path (a snapshot leaves the changelog stage out).
func releaseCheckProblems(makefile string) []string {
	recipe := makeRecipe(makefile, "release-check")
	if len(recipe) == 0 {
		return []string{"the Makefile has no release-check target"}
	}
	notes, snapshot := -1, -1
	for i, line := range recipe {
		if strings.TrimSpace(line) == "$(MAKE) release-notes-check" && notes < 0 {
			notes = i
		}
		if strings.Contains(line, "$(GORELEASER)") && strings.Contains(line, "--snapshot") && snapshot < 0 {
			snapshot = i
		}
	}
	switch {
	case notes < 0:
		return []string{"the release-check target does not run `$(MAKE) release-notes-check` as a line of its own: the notes would not be exercised before the snapshot"}
	case snapshot < 0:
		return []string{"the release-check target has no GoReleaser snapshot line"}
	case notes > snapshot:
		return []string{"the release-check target runs the notes check after its snapshot"}
	}
	return nil
}

func TestReleaseCheckRunsTheNotesCheckFirst(t *testing.T) {
	data, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	for _, problem := range releaseCheckProblems(string(data)) {
		t.Error(problem)
	}
	const good = "release-check:\n\t$(GO) run $(GORELEASER) check\n\t$(MAKE) release-notes-check\n\t$(GO) run $(GORELEASER) release --snapshot --clean\n\nverify:\n\techo x\n"
	for _, c := range []struct {
		name, makefile, want string
	}{
		{"a correct target", good, ""},
		{"no notes line", strings.Replace(good, "\t$(MAKE) release-notes-check\n", "", 1), "does not run `$(MAKE) release-notes-check`"},
		{"the notes line is ignored", strings.Replace(good, "\t$(MAKE) release-notes-check", "\t-$(MAKE) release-notes-check", 1), "does not run `$(MAKE) release-notes-check`"},
		{"the notes line after the snapshot", "release-check:\n\t$(GO) run $(GORELEASER) release --snapshot --clean\n\t$(MAKE) release-notes-check\n", "after its snapshot"},
		{"no snapshot line", "release-check:\n\t$(MAKE) release-notes-check\n", "no GoReleaser snapshot line"},
		{"the notes line belongs to the next target", "release-check:\n\t$(GO) run $(GORELEASER) release --snapshot\n\nverify:\n\t$(MAKE) release-notes-check\n", "does not run `$(MAKE) release-notes-check`"},
		{"no target", "verify:\n\techo x\n", "no release-check target"},
	} {
		problems := releaseCheckProblems(c.makefile)
		switch {
		case c.want == "" && len(problems) != 0:
			t.Errorf("%s: unexpected problems %v", c.name, problems)
		case c.want != "" && (len(problems) != 1 || !strings.Contains(problems[0], c.want)):
			t.Errorf("%s: problems %v, want one containing %q", c.name, problems, c.want)
		}
	}
}

// An older shellcheck once reported SC2015 on two lines that a newer one did not, and CI
// went red on a check that passed locally. Nothing installs or pins shellcheck in CI, so
// the target prints the version it judged with, and the log of either run says which.
func TestActionlintTargetPrintsTheShellcheckVersion(t *testing.T) {
	data, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	for _, problem := range actionlintProblems(string(data)) {
		t.Error(problem)
	}
}

// The check above is run on Makefiles that have each fault, so it cannot pass by reading
// nothing.
func TestActionlintCheckFindsEachFault(t *testing.T) {
	const good = "actionlint:\n\t@command -v shellcheck >/dev/null || exit 1\n\tshellcheck --version\n\t$(GO) run $(ACTIONLINT)\n\tshellcheck scripts/*.sh\n\nvuln:\n\techo x\n"
	for _, c := range []struct {
		name, makefile, want string
	}{
		{"a correct target", good, ""},
		{"no version line", strings.Replace(good, "\tshellcheck --version\n", "", 1), "does not print the version"},
		{"the version line after the run", "actionlint:\n\t$(GO) run $(ACTIONLINT)\n\tshellcheck --version\n", "after the checks"},
		{"no run line", "actionlint:\n\tshellcheck --version\n", "does not run"},
		{"no target", "vuln:\n\tshellcheck --version\n", "no actionlint target"},
		{"no guard line", strings.Replace(good, "\t@command -v shellcheck >/dev/null || exit 1\n", "", 1), "no `command -v shellcheck` line"},
		{"a guard that ends in || true", strings.Replace(good, "|| exit 1", "|| true", 1), "no `command -v shellcheck` line"},
		{"a guard whose failure is ignored", strings.Replace(good, "\t@command -v", "\t-command -v", 1), "no `command -v shellcheck` line"},
		{"a guard that never exits", strings.Replace(good, "|| exit 1", "|| echo missing", 1), "no `command -v shellcheck` line"},
		{"no scripts line", strings.Replace(good, "\tshellcheck scripts/*.sh\n", "", 1), "no plain `shellcheck scripts/*.sh` line"},
		{"a scripts line whose failure is ignored", strings.Replace(good, "\tshellcheck scripts/*.sh", "\t-shellcheck scripts/*.sh", 1), "no plain `shellcheck scripts/*.sh` line"},
		{"a scripts line that cannot fail", strings.Replace(good, "\tshellcheck scripts/*.sh", "\tshellcheck scripts/*.sh || true", 1), "no plain `shellcheck scripts/*.sh` line"},
		{"the version line belongs to the next target", "actionlint:\n\t$(GO) run $(ACTIONLINT)\n\nvuln:\n\tshellcheck --version\n", "does not print the version"},
	} {
		problems := actionlintProblems(c.makefile)
		switch {
		case c.want == "" && len(problems) != 0:
			t.Errorf("%s: unexpected problems %v", c.name, problems)
		case c.want != "" && (len(problems) != 1 || !strings.Contains(problems[0], c.want)):
			t.Errorf("%s: problems %v, want one containing %q", c.name, problems, c.want)
		}
	}
}
