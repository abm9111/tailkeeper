package workflows

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/cli"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/doctor"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// aclGuide is docs/acl.md. The file is the operator and agent guide, so these tests
// hold its sentences to the behaviour the tools actually have.
func aclGuide(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../docs/acl.md")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// aclSection is the guide from a heading line through the line before the next heading
// of the same or higher rank. The heading must occur once.
func aclSection(t *testing.T, doc, heading string) string {
	t.Helper()
	lines := strings.Split(doc, "\n")
	start := -1
	for i, l := range lines {
		if l != heading {
			continue
		}
		if start >= 0 {
			t.Fatalf("docs/acl.md has the heading %q twice", heading)
		}
		start = i
	}
	if start < 0 {
		t.Fatalf("docs/acl.md has no heading %q", heading)
	}
	end := len(lines)
	rank := strings.Count(heading, "#")
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "#") && strings.Count(strings.Fields(lines[i])[0], "#") <= rank {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

func requireIn(t *testing.T, where, text string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(text, w) {
			t.Errorf("%s does not contain %q", where, w)
		}
	}
}

// The agent workflow is the order the server already gives, and a pass is not a claim
// that the change is safe. notChecked is named, and an empty grants list is deny-all
// in the same way an empty acls list is.
func TestTheACLGuideNamesTheWorkflowAndWhatAPassMeans(t *testing.T) {
	doc := aclGuide(t)
	agent := aclSection(t, doc, "## What an agent does")
	order := []string{"acl_get", "users_list", "acl_test", "acl_validate", "acl_diff"}
	at := -1
	for _, name := range order {
		i := strings.Index(agent, name)
		if i < 0 || i < at {
			t.Fatalf("in %q, %q is missing or out of order", agent, name)
		}
		at = i
	}
	requireIn(t, "the agent section", agent, "grants: []", "deny-all", "acls: []")
	pass := aclSection(t, doc, "## What a pass means")
	requireIn(t, "the pass section", pass, "not that the change is safe", "notChecked", "`unresolved`", "`unknown`", "acl_test",
		"or the live policy changed while the check ran (`liveChanged` is true).",
		"An online pass is about the live policy at the moment it was checked: `dependsOnLiveState` is true.",
		"An invariants file that holds no tests runs nothing, and the result says so in a notice.",
	)
	if strings.Contains(pass, "no `unresolved` status") || strings.Contains(pass, "no `unknown` status") {
		t.Error("the guide denies acl_test's unresolved and unknown statuses")
	}
	if strings.Contains(pass, "the change is safe") && !strings.Contains(pass, "not that the change is safe") {
		t.Error("a pass is described as the change being safe")
	}
	headings := []string{
		"## What an agent does",
		"## What the owner does after a pass",
		"## What a pass means",
		"## Invariants",
		"## Pseudonyms and the subject rule",
		"## Offline use",
		"## SSH tests",
		"## Terraform",
		"## Relative paths",
		"## Recipes",
	}
	at = -1
	for _, h := range headings {
		i := strings.Index(doc, h)
		if i < 0 || i < at {
			t.Errorf("heading %q is missing or out of order", h)
		}
		at = i
	}
	requireIn(t, "docs/acl.md", doc, "docs/recipes/github-actions.md", "docs/recipes/cron.md")
}

// The controls the starter prints are the ones the guide lists, in the starter's order and
// no others. The starter is written by the code itself, so a change to its list shows here.
// A pseudonym marker in an invariants file is invalid.
func TestTheACLGuideNamesWhatInvariantsCannotTest(t *testing.T) {
	out := filepath.Join(t.TempDir(), "invariants.hujson")
	res, err := doctor.WriteStarter(context.Background(), &app.App{}, doctor.StarterInput{
		Out: out, Tags: []string{"tag:web"}, AdminGroups: []string{"group:admins"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Untestable) == 0 {
		t.Fatal("the starter lists no control it cannot test")
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(out)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("the starter file: mode %v, err %v; the guide says 0600", fi, err)
		}
	}
	if _, err := doctor.WriteStarter(context.Background(), &app.App{}, doctor.StarterInput{
		Out: out, Tags: []string{"tag:web"}, AdminGroups: []string{"group:admins"},
	}); err == nil {
		t.Error("the starter overwrote its file; the guide says it never does")
	}

	inv := aclSection(t, aclGuide(t), "## Invariants")
	var listed []string
	for _, line := range strings.Split(inv, "\n") {
		if c, ok := strings.CutPrefix(line, "- "); ok {
			// The guide writes code in backticks; the starter prints plain text.
			listed = append(listed, strings.ReplaceAll(c, "`", ""))
		}
	}
	if strings.Join(listed, "\n") != strings.Join(res.Untestable, "\n") {
		t.Errorf("the guide lists %q; the starter prints %q", listed, res.Untestable)
	}
	counts := map[int]string{2: "two", 3: "three", 4: "four", 5: "five", 6: "six"}
	word, ok := counts[len(res.Untestable)]
	if !ok {
		t.Fatalf("the starter lists %d controls; extend this test's number words", len(res.Untestable))
	}
	requireIn(t, "the invariants section", inv,
		"The test language cannot express these "+word+", and the guide lists the same "+word+" the starter prints:",
		"[p:",
		"invalid",
		"doctor --policy --out FILE",
		"0600",
		"is created mode 0600 and is never overwritten",
		"a CIDR and `autogroup:internet`, as destinations of a test, came back unevaluable.",
	)
	if strings.Contains(inv, "no `--policy` flag") {
		t.Error("the guide says doctor has no --policy flag")
	}
}

// A literal login over MCP is filter_refused. The operator's own files are the
// exception. An offline check sets serverChecked false.
func TestTheACLGuideStatesTheSubjectRuleAndOfflineUse(t *testing.T) {
	doc := aclGuide(t)
	requireIn(t, "docs/acl.md", doc, "filter_refused", "operator's own", "--offline", "serverChecked")
	sub := aclSection(t, doc, "## Pseudonyms and the subject rule")
	requireIn(t, "the subject section", sub, "filter_refused", "operator's own", "keys", "acl_test",
		"The check reads keys and values, and it skips comments. It skips no short word: a login with a one-character local part is refused like any other.",
		"When a result echoes text, masking leaves three things as they are. A word shorter than two bytes is not masked. A word the caller typed is not masked as a local part. A local part of a login this call did not resolve is not found. An echo of text the caller typed is masked without a pseudonym.",
		"The command line marks its call as the operator's, with one exception: a login typed as an argument of `acl test` is refused there too.",
	)
	// The refusal check skips no short word: the masker's definition of a login holds for a
	// one-character local part. The short-word skip is in echo masking only.
	for _, login := range []string{"a@example.com", "ab@example.com"} {
		if !tools.IsLiteralLogin(login) {
			t.Errorf("%q is not a literal login, so the guide's \"skips no short word\" is false", login)
		}
	}
	if strings.Contains(sub, "does not apply this rule") {
		t.Error("the guide says acl_test does not apply the subject rule")
	}
	off := aclSection(t, doc, "## Offline use")
	requireIn(t, "the offline section", off, "--offline", "serverChecked", "--from-version", "--to-version", "acl history",
		"`--against FILE` names the old side and `--from FILE` the new side, and `--against live` is the live policy.",
		"A stored policy is named with `--from-version` for the old side and `--to-version` for the new side;",
	)
}

// The paragraph says who owns the file and what a drift check compares. It does not
// say this release ships a provider or a recipe.
func TestTheACLGuideHasTheTerraformParagraph(t *testing.T) {
	tf := aclSection(t, aclGuide(t), "## Terraform")
	requireIn(t, "the Terraform section", tf,
		"owns the policy file",
		"rendered output",
		"does not ship a Terraform provider",
		"does not ship a Terraform recipe",
		"operator file",
		"masked",
	)
}

// SSH tests go through a copy of the live policy. Policy mode ran sshTests on 20 Oct 2026.
func TestTheACLGuideSaysSSHTestsGoThroughACopyOfTheLivePolicy(t *testing.T) {
	ssh := aclSection(t, aclGuide(t), "## SSH tests")
	requireIn(t, "the SSH section", ssh,
		"SSH tests go through a copy of the live policy",
		"sshTests",
		"passing entry alone",
		"The canary of the second validation is a `tests` canary only: the SSH canary belongs to `acl_test`, so a second validation that lost the `sshTests` array would not be noticed.",
	)
	if strings.Contains(ssh, "does not send SSH tests") || strings.Contains(ssh, "SSH rules are not tested") {
		t.Error("the guide says SSH tests are not sent")
	}
}

// The owner compares the two digests. The guide documents no flag that would export
// the policy with personal data shown.
func TestTheACLGuideSaysTheOwnerConfirmsWithTheSemanticDigest(t *testing.T) {
	owner := aclSection(t, aclGuide(t), "## What the owner does after a pass")
	requireIn(t, "the owner section", owner, "semanticDigest", "patchedDigest", "privacy key",
		"Unless `personalData` is `show`, no command exports the policy unmasked. With `personalData` set to `show`, `acl_get` returns the text as the API returned it; the scheduled check writes its saved baseline that way.")
	if strings.Contains(owner, "--unmasked") || strings.Contains(owner, "--export") {
		t.Error("the owner section documents a flag for an unmasked export")
	}
}

// A relative policy path is the process's working directory. The configured
// invariants path is absolute.
func TestTheACLGuideSaysARelativeFileIsReadInTheWorkingDirectory(t *testing.T) {
	rel := aclSection(t, aclGuide(t), "## Relative paths")
	requireIn(t, "the paths section", rel,
		"working directory",
		"--from",
		"--against",
		"--patch",
		"--invariants",
		"absolute",
	)
}

func windowsPolicy(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../docs/windows.md")
	if err != nil {
		t.Fatal(err)
	}
	return aclSection(t, string(b), "## Policy files")
}

func TestWindowsPolicyFilesNamesEncodingsBOMAndCRLF(t *testing.T) {
	sec := windowsPolicy(t)
	requireIn(t, "Policy files", sec,
		"[Console]::InputEncoding",
		"$OutputEncoding",
		"-Encoding utf8NoBOM",
		"BOM",
		"UTF-16",
		"CRLF",
		"line feed",
	)
}

// The section sits before the marker lists and holds none of their lines.
// No test skips because the Windows leg runs without the race detector, so the
// section does not say that it does.
func TestWindowsPolicyFilesDoesNotClaimARaceTestIsSkipped(t *testing.T) {
	b, err := os.ReadFile("../../docs/windows.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	sec := windowsPolicy(t)
	head := strings.Index(doc, "## Policy files")
	mark := strings.Index(doc, "<!-- windows-skipped:begin -->")
	if head < 0 || mark < 0 || head > mark {
		t.Fatalf("Policy files at %d, first marker at %d", head, mark)
	}
	for _, marker := range []string{"windows-skipped", "windows-excluded"} {
		if strings.Contains(sec, marker) {
			t.Errorf("Policy files holds a %s line", marker)
		}
	}
	if strings.Contains(sec, "t.Skip") || strings.Contains(sec, "-race") || strings.Contains(sec, "race-tested") {
		t.Error("Policy files states a race fact, and no test skips for that reason")
	}
}

// The Reference list names the guide. The exit table is left for a later edit.
func TestTheACLGuideIsLinkedFromTheReadme(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	ref := aclSection(t, string(b), "## Reference")
	if !strings.Contains(ref, "`docs/acl.md`") {
		t.Error("the Reference section does not name docs/acl.md")
	}
}

// toolNames is the set of tool names the registry holds.
func toolNames(t *testing.T) map[string]bool {
	t.Helper()
	reg := registry.New()
	tools.Register(reg)
	names := map[string]bool{}
	for _, tool := range reg.All() {
		names[tool.Meta.Name] = true
	}
	if len(names) == 0 {
		t.Fatal("the registry holds no tools")
	}
	return names
}

func readme(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestTheReadmeNamesTheWiderExitEightAndTheACLTestStatuses(t *testing.T) {
	doc := readme(t)
	table := aclSection(t, doc, "### Exit codes")
	requireIn(t, "the exit table", table,
		"`unknown`",
		"`unresolved`",
		"`findings_present`",
		"failed assertion",
	)
	row := func(code string) string {
		for _, line := range strings.Split(table, "\n") {
			if strings.HasPrefix(line, "| "+code+" |") {
				return line
			}
		}
		t.Fatalf("no exit %s row", code)
		return ""
	}
	if !strings.Contains(row("1"), "`acl test`") || !strings.Contains(row("1"), "`unknown`") {
		t.Fatalf("exit 1: %s", row("1"))
	}
	if !strings.Contains(row("2"), "`acl test`") || !strings.Contains(row("2"), "`unresolved`") {
		t.Fatalf("exit 2: %s", row("2"))
	}
	if !strings.Contains(row("8"), "`findings_present`") || !strings.Contains(row("8"), "`--fail-on`") {
		t.Fatalf("exit 8: %s", row("8"))
	}
	if !strings.Contains(row("9"), "That is a failed assertion.") || !strings.Contains(row("9"), "`acl validate` ran") {
		t.Fatalf("exit 9: %s", row("9"))
	}
}

func TestTheReadmeNamesOptionalScopes(t *testing.T) {
	ref := aclSection(t, readme(t), "## Reference")
	requireIn(t, "Reference", ref, "optionalTools", "docs/scopes.md")
}

func TestTheReadmeMarksThePathsThatCannotBeExercisedLive(t *testing.T) {
	sec := aclSection(t, readme(t), "### Not shown by a live run")
	requireIn(t, "Not shown by a live run", sec,
		"a pass with new warnings when the tailnet has none",
		"Tailscale's 429, not provoked",
		"a console save on a scratch tailnet",
	)
	if strings.Contains(sec, "passed") || strings.Contains(sec, "verified") {
		t.Fatalf("the section claims a run: %s", sec)
	}
	if strings.Contains(sec, "GitOps") || strings.Contains(sec, "doctor --probe") {
		t.Error("the section lists a path a live run can record")
	}
}

func TestTheReadmeToolCountMatchesTheRegistry(t *testing.T) {
	doc := readme(t)
	para := doc[:strings.Index(doc, "## What it does differently")]
	re := regexp.MustCompile(`\((\d+) tools, (\w+) of them for alpha features, which MCP lists only with ` + "`--enable-alpha`" + `\) and this node's Tailscale state \((\d+) tools\)`)
	m := re.FindStringSubmatch(para)
	if m == nil {
		t.Fatal("the status paragraph does not use the registry's tool-count phrase")
	}
	apiN, _ := strconv.Atoi(m[1])
	numberWords := map[string]int{"one": 1, "two": 2, "three": 3, "four": 4, "five": 5}
	alphaN, ok := numberWords[m[2]]
	if !ok {
		t.Fatalf("the status paragraph gives the alpha count as %q, a number word this test does not know", m[2])
	}
	localN, _ := strconv.Atoi(m[3])
	reg := registry.New()
	tools.Register(reg)
	var api, local, alpha int
	for _, tool := range reg.All() {
		if tool.Meta.Area == "local" {
			local++
		} else {
			api++
		}
		if tool.Meta.Stage == registry.StageAlpha {
			alpha++
		}
	}
	if apiN != api || localN != local || alphaN != alpha {
		t.Fatalf("README says %d API tools, %d of them alpha, and %d local tools; registry has %d, %d alpha, and %d", apiN, alphaN, localN, api, alpha, local)
	}
}

func TestTheThreatModelSaysTheReadIdentityIsReadAllPolicy(t *testing.T) {
	b, err := os.ReadFile("../../docs/threat-model.md")
	if err != nil {
		t.Fatal(err)
	}
	sec := aclSection(t, string(b), "## Actors")
	requireIn(t, "the CI runner row", sec, ciRunnerClauses...)
}

// ciRunnerClauses are the sentences of the CI runner row, whole: what the live identity can
// read, where the job that holds it runs, and who can reach it with and without a required
// reviewer. The same row stands in the threat model and in design section 3.
var ciRunnerClauses = []string{
	"The read identity is a read-all-policy credential, because masking is client-side: it reads the policy, the devices and their posture attributes.",
	"The GitHub Actions recipe runs the job that holds it in a named environment, with `id-token: write` on that job only.",
	"Every step of that job, including the pinned `actions/checkout` and `sigstore/cosign-installer` and the downloaded binary, can request the OIDC token; the SHA pins and the environment's reviewer are the controls.",
	"With a required reviewer on the environment and the federated credential's subject bound to that environment, only an approved run gets the identity; without the binding, a job that names no environment gets a token with no approval, and without a reviewer, anyone who can push a branch can edit a `pull_request` workflow and use that identity.",
	workflowGuardClause,
	"A pull request from a fork gets no OIDC token.",
	"On a public repository the log of a run on a branch of the repository is public, and it carries text taken from the live policy (annotations and a step summary), masked for personal data but not for tag names, host names or the shape of a rule",
}

// The row is the same text in the published threat model and in the design it is section 3 of,
// and the identity it describes is the one the recipe and the code give: the three read scopes
// are the scopes of the policy tools the recipe runs, and the oidc provider reads the Actions token
// itself.
func TestTheCIRunnerRowIsTheSameInTheDesignAndTheThreatModel(t *testing.T) {
	model, err := os.ReadFile("../../docs/threat-model.md")
	if err != nil {
		t.Fatal(err)
	}
	design, err := os.ReadFile("../../docs/design.md")
	if err != nil {
		t.Fatal(err)
	}
	row := func(doc string) string {
		for _, line := range strings.Split(doc, "\n") {
			if strings.HasPrefix(line, "| CI runner |") {
				return line
			}
		}
		t.Fatal("no CI runner row")
		return ""
	}
	if a, b := row(string(model)), row(string(design)); a != b {
		t.Errorf("the CI runner row differs:\nthreat-model.md: %s\ndesign.md:       %s", a, b)
	}
	reg := registry.New()
	tools.Register(reg)
	scopes := map[string]bool{}
	for _, name := range []string{"acl_get", "acl_validate", "acl_diff"} {
		tool, ok := reg.Get(name)
		if !ok {
			t.Fatalf("no tool %s", name)
		}
		for _, sc := range tool.Meta.Scopes {
			scopes[sc] = true
		}
	}
	for _, sc := range []string{"policy_file:read", "devices:core:read", "devices:posture_attributes:read"} {
		if !scopes[sc] {
			t.Errorf("the scope %s is named for the CI identity, and none of acl_get, acl_validate and acl_diff needs it", sc)
		}
	}
}

func TestTheThreatModelSaysAProposalIsSentToTailscale(t *testing.T) {
	b, err := os.ReadFile("../../docs/threat-model.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "sent to Tailscale for validation and change nothing") {
		t.Fatal("the threat model does not say a proposal is sent and changes nothing")
	}
}

func TestTheThreatModelKeepsTheSubjectSection(t *testing.T) {
	b, err := os.ReadFile("../../docs/threat-model.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "## Subjects an agent types") {
		t.Fatal("the subject section heading is gone")
	}
}

// zeroSixHeading is the line that heads the 0.6.0 section of a changelog: "unreleased" until
// the release commit, and the day of that commit after it. Both are the same section, so
// these tests hold on the commit the release workflow runs `make verify` on, which is dated.
func zeroSixHeading(t *testing.T, changelog string) string {
	t.Helper()
	re := regexp.MustCompile(`^## 0\.6\.0 — (?:unreleased|\d{4}-\d{2}-\d{2})$`)
	var found []string
	for _, line := range strings.Split(changelog, "\n") {
		if re.MatchString(line) {
			found = append(found, line)
		}
	}
	if len(found) != 1 {
		t.Fatalf("CHANGELOG.md has %d headings of the 0.6.0 section (%q), want 1", len(found), found)
	}
	return found[0]
}

// upgradingParagraph is the paragraph that starts "Upgrading:" under the 0.6.0 heading.
// The tests below search it and nothing else: the Added bullets repeat its tokens.
func upgradingParagraph(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	top := aclSection(t, string(b), zeroSixHeading(t, string(b)))
	var found []string
	for _, para := range strings.Split(top, "\n\n") {
		if strings.HasPrefix(para, "Upgrading:") {
			found = append(found, para)
		}
	}
	if len(found) != 1 {
		t.Fatalf("the 0.6.0 section has %d paragraphs that start Upgrading:, want 1", len(found))
	}
	return found[0]
}

// Each clause is a sentence of the paragraph a 0.5.0 binary's owner reads, pinned whole, so
// a sentence changed to say what the code does not do fails here, and not only a deleted one.
func TestTheUpgradingParagraphNamesWhatAZeroFiveBinaryMeets(t *testing.T) {
	// The answers are written in pieces: this file quotes the changelog, it sends nothing,
	// and the lint on hand-written validate JSON looks for whole literals.
	q := func(s string) string { return "\"" + s + "\"" }
	requireIn(t, "Upgrading", upgradingParagraph(t),
		"While masking is on, a typed login in `acl test`'s source or a destination is refused (`filter_refused`), on the command line and over MCP, where 0.5.0 accepted it; the pseudonym from `users_list` replaces it.",
		"`acl test`'s status gains `unresolved` (exit 2) and `unknown` (exit 1).",
		"A source or destination Tailscale cannot resolve was a `fail` (exit 9) and is `unresolved` now.",
		"A tests-mode answer of `{"+q("data")+":[]}`, `{"+q("data")+":null}` or `{"+q("message")+":"+q("")+"}` was a pass and is an unrecognised response (`api_error`).",
		"`dns_get` reads the policy when `policy_file:read` is granted, and `policyOverridesAnalysed` is true when the policy could be read and analysed; `policyNote` says why when it could not.",
		"`acl_history`, `acl validate`, `acl diff` (with its `fromVersion` and `toVersion`), `doctor --policy` and `doctor --probe`'s new checks are new, and `doctor --policy` writes a file.",
		"Exit 8 is `findings_present` for `doctor` and for `--fail-on`.",
		"A running MCP server needs a restart to load this release.",
		"The two new configuration keys are refused by a 0.5.0 binary (`config_invalid`, exit 6), so a configuration that a 0.5.0 binary also reads cannot use them.",
	)
}

func TestTheUpgradingParagraphDoesNotDropTheEarlierSentences(t *testing.T) {
	requireIn(t, "Upgrading", upgradingParagraph(t),
		"`acl test`, and `doctor --probe` which runs it, exit 1 with `validate_rate_limited` once they pass 30 validation requests a minute (`acl.validatePerMinute`), where nothing limited them; the error carries `retryAfterSeconds`.",
		"A command whose argument is refused before the configuration loads exits 2 where a missing or invalid configuration made it exit 6: a text flag over 8 KiB that 0.5.0 did not itself check (`devices list --hostname`, `--name-contains` and `--os`, `logs audit --actor`, `--event` and `--origin`, `logs network --node`). A login typed as the source of `acl test` while masking is on is refused (`filter_refused`) before the credential is asked for, so with no configuration it exits 2 where it exited 6. A missing `--src` and an unknown flag exited 2 in 0.5.0 too.",
		"A privacy key file that cannot be read, is unsafe or does not parse is `privacy_key_unavailable` (exit 5), where it was `config_unsafe` or `config_invalid` (exit 6).",
	)
}

func TestSchemasOfThisReleaseHaveBaselines(t *testing.T) {
	b, err := os.ReadFile("../../internal/tools/testdata/schemas/unreleased.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			t.Errorf("unreleased.txt still names %s", line)
		}
	}
	for _, name := range []string{"acl_diff", "acl_history", "acl_validate"} {
		if _, err := os.Stat("../../internal/tools/testdata/schemas/" + name + ".json"); err != nil {
			t.Errorf("%s baseline: %v", name, err)
		}
	}
}

// At the release every baseline is the 0.6.0 contract. The three tools that 0.5.0 shipped
// carry a field this release added, so a baseline still at the 0.5.0 contract fails here.
func TestTheReleasedBaselinesAreTheZeroSixContract(t *testing.T) {
	for tool, field := range map[string]string{
		"acl_get":  `"semanticDigest"`,
		"acl_test": `"srcPostureAttrs"`,
		"dns_get":  `"dnsNodeAttrs"`,
	} {
		b, err := os.ReadFile("../../internal/tools/testdata/schemas/" + tool + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), field) {
			t.Errorf("the %s baseline lacks %s: it is still the 0.5.0 contract", tool, field)
		}
	}
}

func TestTheReadmePinsTheZeroSixRelease(t *testing.T) {
	doc := readme(t)
	sec := aclSection(t, doc, "## Verify a release")
	if !strings.Contains(sec, "VERSION=v0.6.0") {
		t.Fatal("the verify block does not pin VERSION=v0.6.0")
	}
	if strings.Contains(sec, "VERSION=v0.5.0") {
		t.Fatal("the verify block still pins v0.5.0")
	}
}

// liveRecord is the owner's record of the 0.6.0 live acceptance: the closing lines of their
// make live run, copied as printed. The README shows exactly these lines. It changes only
// when the owner hands over a new run.
const liveRecord = `self-check: 9 checks, all held
tools allowed to be unavailable (make live LIVE_UNAVAILABLE=…): 3: log_streaming_get, oauth_apps_list, user_invites_list
acl_validate: invariants not run: no test is known to hold on the live policy, and an empty file proves nothing
GitOps oracle: not requested
doctor: 0 failing checks
user_invites_list            unavailable not_found                   192 bytes  0 personal paths     0 personal values examined
oauth_apps_list              unavailable not_found                   192 bytes  0 personal paths     0 personal values examined
log_streaming_get            unavailable scope_missing               275 bytes  0 personal paths     0 personal values examined
summary: 46 tools: 37 ok, 3 unavailable, 6 none, 0 fail
none, so nothing was called for: device_invite_get, oauth_app_get, posture_integration_get, service_get, user_invite_get, webhook_get
mcp: 44 tools advertised
`

// liveRecordLine is the shape of every line the record may hold: the fixed closing lines of
// make live, with counts and tool names only, so no value from the tailnet can be copied in.
var liveRecordLine = regexp.MustCompile(`^(self-check: \d+ checks, all held|` +
	`tools allowed to be unavailable \(make live LIVE_UNAVAILABLE=…\): \d+: [a-z_]+(, [a-z_]+)*|` +
	`acl_validate: invariants not run: no test is known to hold on the live policy, and an empty file proves nothing|` +
	`GitOps oracle: not requested|doctor: \d+ failing checks|` +
	`summary: \d+ tools: \d+ ok, \d+ unavailable, \d+ none, \d+ fail|mcp: \d+ tools advertised|` +
	`[a-z_]+ +unavailable +[a-z_]+ +\d+ bytes +\d+ personal paths +\d+ personal values examined|` +
	`none, so nothing was called for: [a-z_]+(, [a-z_]+)*)$`)

// liveRecordProse is what the prose of the record section must not hold: a login, an
// address, a tailnet name. Only the fenced lines carry the run, and they have fixed shapes.
var liveRecordProse = regexp.MustCompile(`@|\b\d{1,3}(\.\d{1,3}){3}\b|[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{0,4}){3,}|\.ts\.net\b|tail[0-9a-f]{4,}`)

// The live acceptance the README records is the owner's run, line for line, and only lines of
// the fixed shapes; outside that block no README sentence about a live run claims a pass.
func TestTheLiveAcceptanceRecordIsTheOwnersRun(t *testing.T) {
	doc := readme(t)
	sec := aclSection(t, doc, "### Live acceptance of 0.6.0")
	parts := strings.Split(sec, "```")
	if len(parts) != 3 {
		t.Fatalf("the live acceptance section holds %d fences, want one fenced record", len(parts)/2)
	}
	block := strings.TrimPrefix(parts[1], "\n")
	if block != liveRecord {
		t.Errorf("the README's record is not the owner's run:\n%s\nwant:\n%s", block, liveRecord)
	}
	for _, line := range strings.Split(strings.TrimSuffix(liveRecord, "\n"), "\n") {
		if !liveRecordLine.MatchString(line) {
			t.Errorf("a record line has no fixed shape, so it could hold a tailnet value: %q", line)
		}
	}
	tools := toolNames(t)
	listed := regexp.MustCompile(`(?m)^tools allowed to be unavailable \(make live LIVE_UNAVAILABLE=…\): (\d+): (.+)$`).FindStringSubmatch(liveRecord)
	if listed == nil {
		t.Fatal("the record has no line listing the tools allowed to be unavailable")
	}
	names := strings.Split(listed[2], ", ")
	if strconv.Itoa(len(names)) != listed[1] {
		t.Errorf("the record lists %d tools as allowed to be unavailable and says %s", len(names), listed[1])
	}
	rowNames := regexp.MustCompile(`(?m)^([a-z_]+) +unavailable `).FindAllStringSubmatch(liveRecord, -1)
	for _, n := range names {
		if !tools[n] {
			t.Errorf("the record names %q, which is not a tool", n)
		}
	}
	if len(rowNames) != len(names) {
		t.Errorf("the record holds %d unavailable rows for %d listed tools", len(rowNames), len(names))
	}
	for _, m := range rowNames {
		if !tools[m[1]] || !slices.Contains(names, m[1]) {
			t.Errorf("the unavailable row %q is not a listed tool", m[1])
		}
	}
	none := regexp.MustCompile(`(?m)^none, so nothing was called for: (.+)$`).FindStringSubmatch(liveRecord)
	summary := regexp.MustCompile(`(?m)^summary: \d+ tools: \d+ ok, (\d+) unavailable, (\d+) none, \d+ fail$`).FindStringSubmatch(liveRecord)
	if none == nil || summary == nil {
		t.Fatal("the record lacks its none line or its summary line")
	}
	noneNames := strings.Split(none[1], ", ")
	for _, n := range noneNames {
		if !tools[n] {
			t.Errorf("the none line names %q, which is not a tool", n)
		}
	}
	if strconv.Itoa(len(noneNames)) != summary[2] || summary[1] != listed[1] {
		t.Errorf("the summary says %s unavailable and %s none; the record lists %s and names %d", summary[1], summary[2], listed[1], len(noneNames))
	}
	if !strings.Contains(sec, "The six tools of the `none` line were not called either") {
		t.Error("the record does not say the tools of the none line were not called")
	}
	if hit := liveRecordProse.FindString(parts[0] + parts[2]); hit != "" {
		t.Errorf("the prose of the record holds what looks like a tailnet value: %q", hit)
	}
	if !strings.Contains(sec, "The three tools listed as unavailable were not exercised") {
		t.Error("the record does not say the listed tools were not exercised")
	}
	if strings.Contains(doc, "live acceptance is not recorded") {
		t.Error("the README still says the live acceptance is not recorded")
	}
	about := regexp.MustCompile(`(?i)\blive (run|acceptance|check|policy test)|\bmake live\b|\bTestLive`)
	claim := regexp.MustCompile(`(?i)\b(held|holds|passed|passes|verified|succeeded|succeeds|confirmed|green|clean|ok)\b`)
	// Words that claim coverage count only in a sentence that negates nothing: "cannot be
	// exercised" and "does not cover" are the README saying what a live run leaves out.
	covers := regexp.MustCompile(`(?i)\b(covered|covers|exercised|end to end|works|worked)\b`)
	negates := regexp.MustCompile(`(?i)\b(not|cannot|never|no)\b`)
	sentences := regexp.MustCompile(`[.!?](?:\s+|$)|\n`)
	outside := strings.Replace(doc, parts[1], "", 1)
	n := 0
	for _, sentence := range sentences.Split(outside, -1) {
		if !about.MatchString(sentence) {
			continue
		}
		n++
		if claim.MatchString(sentence) || (covers.MatchString(sentence) && !negates.MatchString(sentence)) {
			t.Errorf("a README sentence outside the record claims a live check held or passed: %q", sentence)
		}
	}
	if n < 3 {
		t.Errorf("found %d sentences about a live run, want at least 3: the scan found too little to judge", n)
	}
}

// Each argument the Upgrading paragraph says exits 2 before the configuration loads does so in
// the code: the command line refuses it with the configuration missing, and the configuration
// is never asked for. The list is the probe of a 0.5.0 binary against this one (the text flags
// over 8 KiB that 0.5.0 sent on to the configuration), so a flag added to or dropped from the
// sentence without the code agreeing fails here.
func TestTheUpgradingExitsAreTheOnesTheCommandLineGives(t *testing.T) {
	big := strings.Repeat("a", 9000)
	run := func(args ...string) (int, string, int) {
		var out, errb bytes.Buffer
		built := 0
		empty := t.TempDir()
		dirs := config.Dirs{System: filepath.Join(empty, "system"), User: filepath.Join(empty, "user"), State: filepath.Join(empty, "state"), Logs: filepath.Join(empty, "logs")}
		r := &cli.Runner{
			Stdout: &out, Stderr: &errb,
			// The real Build, with no configuration anywhere: a missing configuration is kept
			// for the tools that need the API, as it is in the binary.
			Build: func(ctx context.Context, name string) (*app.App, error) {
				built++
				return app.Build(ctx, app.Options{Context: name, Dirs: &dirs, Getenv: func(string) string { return "" }})
			},
			Reexec: func(config.Provider) error {
				return tkerr.New(tkerr.CredentialUnavailable, "re-exec is not possible in tests", "")
			},
			Getenv: func(string) string { return "" },
		}
		return r.Run(context.Background(), args), errb.String(), built
	}
	para := upgradingParagraph(t)
	for _, c := range []struct {
		flag string
		args []string
	}{
		{"`devices list --hostname`", []string{"devices", "list", "--hostname", big}},
		{"`--name-contains`", []string{"devices", "list", "--name-contains", big}},
		{"`--os`", []string{"devices", "list", "--os", big}},
		{"`logs audit --actor`", []string{"logs", "audit", "--actor", big}},
		{"`--event`", []string{"logs", "audit", "--event", big}},
		{"`--origin`", []string{"logs", "audit", "--origin", big}},
		{"`logs network --node`", []string{"logs", "network", "--node", big}},
	} {
		if !strings.Contains(para, c.flag) {
			t.Errorf("the Upgrading paragraph does not name %s", c.flag)
		}
		code, stderr, built := run(c.args...)
		if code != 2 || built != 0 || !strings.Contains(stderr, "takes a short value, not a document") || strings.Contains(stderr, "aaaaaaaa") {
			t.Errorf("%v: exit %d, configuration loaded %d times, stderr %.200q; want 2, never loaded, the size and no echo", c.args[:3], code, built, stderr)
		}
	}
	// A login typed as the source is refused by the tool before it asks for the credential, so
	// with no configuration the exit is 2; the configuration itself is read.
	code, stderr, _ := run("acl", "test", "bob@example.com", "--accept", "tag:prod:22")
	if code != 2 || !strings.Contains(stderr, "filter_refused") {
		t.Errorf("a login typed as the source of acl test, no configuration: exit %d, stderr %.200q; want 2, filter_refused", code, stderr)
	}
	// What 0.5.0 already refused first stays a usage error, so the paragraph's last sentence is true.
	if code, _, built := run("acl", "test", "--accept", "tag:prod:22"); code != 2 || built != 0 {
		t.Errorf("a missing --src: exit %d, configuration loaded %d times; want 2, never loaded", code, built)
	}
	if code, _, built := run("devices", "list", "--nope"); code != 2 || built != 0 {
		t.Errorf("an unknown flag: exit %d, configuration loaded %d times; want 2, never loaded", code, built)
	}
	// An argument that is not refused first still meets the configuration.
	if code, _, built := run("devices", "list"); code != 6 || built != 1 {
		t.Errorf("a plain command with no configuration: exit %d, configuration loaded %d times; want 6 after one load", code, built)
	}
}

// The numbers the changelog gives for the validation limit and the annotations are the code's.
func TestTheChangelogNumbersAreTheCodes(t *testing.T) {
	b, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	top := aclSection(t, string(b), zeroSixHeading(t, string(b)))
	def, lo, hi := config.DefaultValidatePerMinute, config.MinValidatePerMinute, config.MaxValidatePerMinute
	requireIn(t, "the 0.6.0 section", top,
		fmt.Sprintf("once they pass %d validation requests a minute (`acl.validatePerMinute`)", def),
		fmt.Sprintf("`acl.validatePerMinute` (the validation requests one process decides to send per minute, %d to %d, default %d;", lo, hi, def),
		fmt.Sprintf("`acl.validatePerMinute` a minute (default %d) for the process", def),
		fmt.Sprintf("so the default `acl.validatePerMinute` of %d allows about three runs a minute", def),
	)
	// One run of doctor --probe draws nine validation tokens, ten with a service in the policy.
	if runs := def / 9; runs != 3 {
		t.Errorf("the default limit allows %d runs of nine tokens a minute; the changelog says about three", runs)
	}
	src, err := os.ReadFile("../../internal/cli/format_github.go")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`const maxAnnotations = (\d+)`).FindSubmatch(src)
	if m == nil {
		t.Fatal("internal/cli/format_github.go has no const maxAnnotations")
	}
	words := map[string]string{"10": "ten", "20": "twenty", "50": "fifty"}
	word, ok := words[string(m[1])]
	if !ok {
		t.Fatalf("maxAnnotations is %s, a number this test has no word for", m[1])
	}
	requireIn(t, "the 0.6.0 section", top, "one workflow annotation for each finding, at most "+word+" of each severity and then a line saying how many were left out")
	if strings.Contains(top, "at most ten annotations") {
		t.Error("the changelog gives the annotation limit in a form this test does not read")
	}
}

// The 0.6.0 section lists the recipes, the guide, the Windows section and the lint of the
// recipes, and says what the design now records of the probes.
func TestTheChangelogListsTheRecipesTheGuideAndTheLint(t *testing.T) {
	b, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	top := aclSection(t, string(b), zeroSixHeading(t, string(b)))
	requireIn(t, "the 0.6.0 section", top,
		"- `docs/recipes/github-actions.md` checks a policy change on a pull request:",
		"The job that reads the live policy runs in a named GitHub environment, with `id-token: write` on that job only, and the tailnet ID and the OAuth client ID are environment secrets of that environment, not repository secrets, so only an approved job receives them and no log shows them.",
		"a third job, `result`, fails unless the live job succeeded, and its name, `tailkeeper-acl-result`, is the one status check to require, because branch protection counts a job that its condition skipped as a pass.",
		"A pull request from a fork runs the offline checks and then fails the job, so a fork cannot pass a policy change green;",
		"and what stays open without one: anyone who can push a branch can then edit the workflow and read the policy, the devices and their posture attributes with that identity. Without the binding, a job that names no environment gets a token with no approval. "+workflowGuardClause,
		"- `docs/recipes/cron.md` runs a daily check from a LaunchAgent or a systemd user timer:",
		"The default baseline reads the configuration audit log and needs the optional scope `logs:configuration:read`.",
		"- `docs/acl.md`, the guide to checking a policy:",
		"- `docs/windows.md` has a Policy files section:",
		"- `make actionlint` also lints the workflow and shell code fenced in `docs/recipes/`, which `scripts/recipes.go` extracts, as it lints the repository's own workflow files and scripts. It still fails without shellcheck on `PATH`.",
		"and what the live probes of 20 Oct 2026 observed. One statement still waits for a console save on a scratch tailnet.",
	)
	if strings.Contains(top, "the live probes whose results decide what is still open") {
		t.Error("the changelog still says the probes decide what is open; the design records what they observed")
	}
	// The scope the cron baseline needs is one acl_diff takes for a stored version.
	reg := registry.New()
	tools.Register(reg)
	diff, ok := reg.Get("acl_diff")
	if !ok {
		t.Fatal("no acl_diff tool")
	}
	found := false
	for _, o := range diff.Meta.OptionalScopes {
		found = found || o.Scope == "logs:configuration:read"
	}
	if !found {
		t.Error("acl_diff does not take logs:configuration:read as an optional scope, and the cron baseline needs it")
	}
}

// What a pass means: the statuses and their exits are the code's, the not-checked list is the
// engine's, and the sentences about them are pinned whole.
func TestTheACLGuideStatusesExitsAndNotCheckedAreTheCodes(t *testing.T) {
	exitOf := func(status string) int { return tools.ACLValidateOutput{Status: status}.ExitCode() }
	testExit := func(status string) int { return tools.ACLTestOutput{Status: status}.ExitCode() }
	for status, want := range map[string]int{"pass": 0, "fail": 9, "invalid": 2, "rejected": 2, "unresolved": 2, "unknown": 1} {
		if got := exitOf(status); got != want {
			t.Errorf("acl_validate %s exits %d, the guide's table was written for %d", status, got, want)
		}
	}
	for status, want := range map[string]int{"pass": 0, "fail": 9, "unresolved": 2, "unknown": 1} {
		if got := testExit(status); got != want {
			t.Errorf("acl_test %s exits %d, the guide's table was written for %d", status, got, want)
		}
	}
	pass := aclSection(t, aclGuide(t), "## What a pass means")
	list := "`" + strings.Join(acl.NotChecked[:len(acl.NotChecked)-1], "`, `") + "` and `" + acl.NotChecked[len(acl.NotChecked)-1] + "`"
	requireIn(t, "the pass section", pass,
		fmt.Sprintf("status `pass` (exit %d) means Tailscale accepts the text", exitOf("pass")),
		"`notChecked` names what was not established, on `acl_validate` and on `acl_diff`: "+list+".",
		fmt.Sprintf("`unknown` (exit %d) is not a pass.", exitOf("unknown")),
		fmt.Sprintf("`invalid` and `rejected` are exit %d for `acl_validate`.", exitOf("invalid")),
		fmt.Sprintf("`unresolved` (exit %d) is a source or a destination Tailscale cannot resolve, for `acl_test` and for `acl_validate`.", exitOf("unresolved")),
		fmt.Sprintf("A failed assertion is `fail` (exit %d).", exitOf("fail")),
		"`acl_test`'s status is `pass`, `fail`, `unresolved` or `unknown`.",
		"An offline pass of `acl_validate` was not sent to Tailscale. `serverChecked` is false, and `notChecked` also names `server_validation` and `tests`.",
	)
	// No tool applies a policy; the guide says so and the registry agrees.
	reg := registry.New()
	tools.Register(reg)
	for _, tool := range reg.All() {
		if strings.Contains(tool.Meta.Name, "apply") {
			t.Errorf("tool %s applies something, and the guide says no command applies a policy", tool.Meta.Name)
		}
	}
	requireIn(t, "the guide", aclGuide(t),
		"The call changes nothing. There is no command that applies a policy.",
		"`acl_test`, `acl_validate` and `doctor --probe` send a test, the live policy, a proposed policy or a synthetic document to that call.",
	)
	off := aclSection(t, aclGuide(t), "## Offline use")
	requireIn(t, "the offline section", off, "`acl validate --offline --invariants FILE` checks that file's syntax and does not run its tests. `notChecked` then also names `invariants`.")
	inv := aclSection(t, aclGuide(t), "## Invariants")
	requireIn(t, "the invariants section", inv,
		"An invariants file is a HuJSON object. It may hold `tests` and `sshTests`, each an array of tests in the policy's own syntax, and no other key. Any other key is invalid.",
		"The file is unsigned. `invariantsSignature` is `none`.",
	)
}

// The Recipes section says what each recipe compares with and what that needs.
func TestTheACLGuideRecipesNameTheBaselineAndTheScope(t *testing.T) {
	rec := aclSection(t, aclGuide(t), "## Recipes")
	requireIn(t, "the recipes section", rec,
		"The job that reads the live policy runs in a named GitHub environment, and a pull request from a fork gets the offline checks only.",
		"By default the baseline is the version id of the newest ACL update you accepted, which `acl history` lists: `acl diff --from-version` reads that stored policy from the configuration audit log, and that needs the optional scope `logs:configuration:read`.",
		"The id ages out after 90 days without a policy update, and then the check fails until you refresh it or use the alternative, a saved policy file named with `--against`, written with `personalData` set to `show`.",
		"With a required reviewer on the environment and the federated credential's subject bound to that environment, only an approved run gets the identity; without the binding, a job that names no environment gets a token with no approval. "+workflowGuardClause+" Require only the status check `tailkeeper-acl-result`, the workflow's `result` job, because branch protection counts a job that its condition skipped as a pass.",
	)
	if strings.Contains(rec, "compares it with a saved file.") {
		t.Error("the guide says the scheduled run compares with a saved file; the default baseline is a version id")
	}
}

// The README points at all four kinds of recipe, and says who can reach the CI identity.
func TestTheReadmeNamesTheRecipesAndTheCIIdentity(t *testing.T) {
	doc := readme(t)
	requireIn(t, "README.md", doc,
		"`docs/recipes/` shows wrappers for two secret managers, a GitHub Actions check of a policy change, and a scheduled policy check.",
		"- `docs/recipes/`: credential wrappers for two secret managers, a GitHub Actions check of a policy change, and a scheduled policy check.",
		"is the convention of the two wrapper recipes in `docs/recipes/` (`1password.md` and `proton-pass.md`)",
		"The `oidc` identity of a GitHub Actions job is a read-all-policy credential, because masking happens in tailkeeper: a job that holds it reads the policy, the devices and their posture attributes whole.",
		"runs the job that holds it in a named GitHub environment, with `id-token: write` on that job only. Every step of that job, including the pinned `actions/checkout` and `sigstore/cosign-installer` and the downloaded binary, can request the OIDC token; the SHA pins and the environment's reviewer are the controls. With a required reviewer on the environment and the federated credential's subject bound to that environment, only an approved run gets the identity; without the binding, a job that names no environment gets a token with no approval, and without a reviewer, anyone who can push a branch to the repository can edit the workflow and use it.",
		workflowGuardClause+" A pull request from a fork gets no OIDC token. The tailnet ID and the client ID are environment secrets of `tailkeeper-policy`, not repository secrets, so only an approved job receives them and no log shows them.",
		// The client ID row of the provider table, and the recipes index: where the ids live.
		"(not a credential; the GitHub Actions recipe keeps it in an environment secret anyway, so that no log shows it)",
		"masked for personal data but not for tag names, host names or the shape of a rule.",
	)
}

// The statements of the Policy files section about what the parser does with a file saved on
// Windows are the parser's: each is run, and the sentence that states it is pinned whole, so
// a sentence edited to say another position, another cause or another fix fails here.
func TestWindowsPolicyFilesStatementsAreWhatTheParserDoes(t *testing.T) {
	sec := windowsPolicy(t)
	requireIn(t, "Policy files", sec,
		"A policy file is UTF-8 with no byte order mark (BOM). A UTF-8 BOM and UTF-16 (a BOM of either byte order) are `invalid`, kind `encoding`, at line 1, column 1.",
		"The UTF-8 BOM message says to save the file as UTF-8 without one; the UTF-16 message says to save it as UTF-8.",
		"PowerShell 5.1 adds a UTF-8 BOM with `-Encoding UTF8`, and it writes UTF-16 for `>`.",
		"A NUL byte and a byte that is not valid UTF-8 are the same status and the same kind, at the line and column of that byte.",
		"Lines are counted by line feed and columns in bytes, as Tailscale counts them. A lone carriage return is whitespace, not a line break, so a file whose lines end in CRLF is reported on the same line and column as the same file with line feeds only.",
	)
	src, err := os.ReadFile("../../internal/tools/acl_problems.go")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`kindEncoding\s+= "encoding"`).Match(src) {
		t.Error("the kind of an encoding refusal is not `encoding`, as the section says")
	}
	parse := func(text string) *acl.Error {
		t.Helper()
		_, err := acl.Parse(context.Background(), []byte(text))
		var e *acl.Error
		if !errors.As(err, &e) {
			t.Fatalf("%q: error %v, want an *acl.Error", text, err)
		}
		return e
	}
	check := func(name, text string, line, col int, says ...string) {
		t.Helper()
		e := parse(text)
		if e.Code != acl.CodeInvalid || e.Line != line || e.Column != col {
			t.Errorf("%s: code %v at line %d column %d, want invalid at %d:%d", name, e.Code, e.Line, e.Column, line, col)
		}
		for _, w := range says {
			if !strings.Contains(e.Message, w) {
				t.Errorf("%s: the message %q does not say %q", name, e.Message, w)
			}
		}
	}
	const body = "{\"acls\": []}"
	check("a UTF-8 BOM", "\xef\xbb\xbf"+body, 1, 1, "UTF-8 byte order mark", "without one")
	check("UTF-16 little endian", "\xff\xfe"+body, 1, 1, "UTF-16", "save it as UTF-8")
	check("UTF-16 big endian", "\xfe\xff"+body, 1, 1, "UTF-16", "save it as UTF-8")
	// The column is the byte's own, counted in bytes from 1 on its line.
	nul := "{\n\"acls\": [],\x00}"
	check("a NUL byte", nul, 2, strings.Index(strings.SplitN(nul, "\n", 2)[1], "\x00")+1, "NUL")
	bad := "{\n  \"acls\": [], \"hosts\": {\"a\": \"\xc3\"}}"
	check("invalid UTF-8", bad, 2, strings.Index(strings.SplitN(bad, "\n", 2)[1], "\xc3")+1, "not valid UTF-8")
	// A lone carriage return is white space: CRLF and LF files report one position.
	lf := "{\n  \"acls\": [],\n  \"bogus\" ?\n}"
	crlf := strings.ReplaceAll(lf, "\n", "\r\n")
	a, b := parse(lf), parse(crlf)
	if a.Line != b.Line || a.Column != b.Column || a.Line == 0 {
		t.Errorf("CRLF reports %d:%d and LF %d:%d; the section says the same", b.Line, b.Column, a.Line, a.Column)
	}
}

// The device names the section lists are the ones the name check refuses: the plain names and
// the digit range are read from the source of the check, which is tested on every platform.
func TestWindowsPolicyFilesListsTheRefusedDeviceNames(t *testing.T) {
	src, err := os.ReadFile("../../internal/safefile/safefile.go")
	if err != nil {
		t.Fatal(err)
	}
	plain := regexp.MustCompile(`"(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$)": true`).FindAllStringSubmatch(string(src), -1)
	var names []string
	for _, m := range plain {
		names = append(names, "`"+m[1]+"`")
	}
	if len(names) != 6 {
		t.Fatalf("found %d plain device names in safefile.go, want 6: %v", len(names), names)
	}
	if !regexp.MustCompile(`for i := '0'; i <= '9'; i\+\+ \{\s*reserved\["COM"\+string\(i\)\] = true\s*reserved\["LPT"\+string\(i\)\] = true`).Match(src) {
		t.Error("safefile.go no longer refuses COM and LPT with each digit 0 to 9, as the section says")
	}
	for _, sup := range []string{`"COM\u00b9"`, `"COM\u00b2"`, `"COM\u00b3"`, `"LPT\u00b9"`, `"LPT\u00b2"`, `"LPT\u00b3"`} {
		if !strings.Contains(string(src), sup) {
			t.Errorf("safefile.go does not refuse %s, and the section lists the superscripts 1, 2 and 3", sup)
		}
	}
	requireIn(t, "Policy files", windowsPolicy(t),
		"a device name ("+strings.Join(names, ", ")+", `COM` or `LPT` with a digit 0 to 9, and `COM` or `LPT` with a superscript 1, 2 or 3), in any directory, with any extension, in any case;",
		"Refused: a UNC path; a path whose prefix is `\\\\?\\`, `\\\\.\\` or `\\??\\` (a `/` counts as a `\\`, including a mix of the two);",
		"an alternate data stream (a colon after the drive letter). Other platforms do not apply that name check.",
	)
}

// The recipes index holds the wrapper rules to the two wrapper recipes, and says where the other
// two recipes state theirs. A heading that says "every recipe" would make a false claim about
// the Actions and cron recipes, which hold no wrapper. The claim about the test is checked:
// TestRecipesAreValid reads only those two files for the wrapper rules.
func TestTheRecipesIndexHoldsTheWrapperRulesToTheTwoWrapperRecipes(t *testing.T) {
	b, err := os.ReadFile("../../docs/recipes/README.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	requireIn(t, "docs/recipes/README.md", doc,
		"\n## What every wrapper recipe follows\n",
		"This section is about `1password.md` and `proton-pass.md`. `github-actions.md` and `cron.md` run tailkeeper's policy commands and set no wrapper: they hold no `command`, and a test (`TestRecipesAreValid` in `cmd/tailkeeper`) checks the wrapper rules for the first two only.",
		"What the other two follow is in their own files: the Actions recipe reads the tailnet id and the OAuth client id from the environment secrets of its environment and never prints them, its live job alone holds `id-token: write`, and the scheduled check reads its ping URL from the environment.",
	)
	if strings.Contains(doc, "## What every recipe follows") {
		t.Error("the recipes index says every recipe follows the wrapper rules")
	}
	test, err := os.ReadFile("../../cmd/tailkeeper/main_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(test), `if base != "1password.md" && base != "proton-pass.md" {`) {
		t.Error("TestRecipesAreValid no longer limits the wrapper rules to the two wrapper recipes, which the index says")
	}
}
