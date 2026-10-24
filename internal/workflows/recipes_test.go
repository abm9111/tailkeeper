package workflows

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// runRecipes runs the recipe extractor with its working directory at cwd, writing into dest.
// The source is always docs/recipes under cwd; dest is the only place it may write.
func runRecipes(t *testing.T, cwd, dest string) (string, int) {
	t.Helper()
	script := filepath.Join(repoRoot(t), "scripts", "recipes.go")
	if _, err := os.Stat(script); err != nil {
		t.Fatal("scripts/recipes.go: no such file or directory")
	}
	cmd := exec.Command("go", "run", script, "-dir", dest)
	cmd.Dir = cwd
	out, err := cmd.CombinedOutput()
	return string(out), exitCode(err)
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func writeRecipe(t *testing.T, dir, name, body string) {
	t.Helper()
	docs := filepath.Join(dir, "docs", "recipes")
	if err := os.MkdirAll(docs, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(docs, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func filesUnder(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func readMakefile(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestRecipeFencesAreExtractedAndOtherFencesAreNot checks the extractor's contract:
// yaml, sh and bash are written; hujson, json, toml and an untagged fence are not;
// an unclosed fence exits 1 and writes nothing; a second extract into the same
// directory exits 1 rather than overwriting.
func TestRecipeFencesAreExtractedAndOtherFencesAreNot(t *testing.T) {
	dir := t.TempDir()
	writeRecipe(t, dir, "sample.md", ""+
		"   ```yaml\n"+
		"   name: one\n"+
		"   ```\n"+
		"\n"+
		"```bash\n"+
		"echo ok\n"+
		"```\n"+
		"\n"+
		"   ```hujson\n"+
		"   {\"ok\": true}\n"+
		"   ```\n"+
		"\n"+
		"```json\n"+
		"{}\n"+
		"```\n"+
		"\n"+
		"```toml\n"+
		"a = 1\n"+
		"```\n"+
		"\n"+
		"   ```\n"+
		"   echo skipped\n"+
		"   ```\n"+
		"\n"+
		"```xml\n"+
		"<a/>\n"+
		"```\n"+
		"\n"+
		"```ini\n"+
		"[a]\n"+
		"```\n")
	dest := filepath.Join(dir, "out")
	first, code := runRecipes(t, dir, dest)
	if code != 0 {
		t.Fatalf("extract exit %d\n%s", code, first)
	}
	// The extractor says what it wrote and where from, and names each fence it left out.
	for _, want := range []string{
		"recipes: github/workflows/sample-1.yml is the fence that opens at docs/recipes/sample.md:1",
		"recipes: scripts/sample-1.sh is the fence that opens at docs/recipes/sample.md:5",
		"not linted: docs/recipes/sample.md:9 (hujson), docs/recipes/sample.md:13 (json), docs/recipes/sample.md:17 (toml), docs/recipes/sample.md:21 (no tag), docs/recipes/sample.md:25 (xml), docs/recipes/sample.md:29 (ini)",
	} {
		if !strings.Contains(first, want) {
			t.Errorf("extractor output lacks %q:\n%s", want, first)
		}
	}
	got := filesUnder(t, dest)
	want := []string{
		"github/workflows/sample-1.yml",
		"scripts/sample-1.sh",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("files %v, want %v", got, want)
	}
	yml, err := os.ReadFile(filepath.Join(dest, "github", "workflows", "sample-1.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(yml) != "name: one\n" {
		t.Fatalf("yaml fence = %q", yml)
	}
	sh, err := os.ReadFile(filepath.Join(dest, "scripts", "sample-1.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if string(sh) != "echo ok\n" {
		t.Fatalf("bash fence = %q", sh)
	}

	two := t.TempDir()
	writeRecipe(t, two, "paired.md", ""+
		"```sh\n"+
		"echo a\n"+
		"```\n"+
		"```yaml\n"+
		"name: a\n"+
		"```\n"+
		"```yaml\n"+
		"name: b\n"+
		"```\n")
	twoOut := filepath.Join(two, "out")
	if out, code := runRecipes(t, two, twoOut); code != 0 {
		t.Fatalf("second tree exit %d\n%s", code, out)
	}
	if got := filesUnder(t, twoOut); strings.Join(got, ",") != "github/workflows/paired-1.yml,github/workflows/paired-2.yml,scripts/paired-1.sh" {
		t.Fatalf("numbered files %v", got)
	}

	open := t.TempDir()
	writeRecipe(t, open, "open.md", "```yaml\nname: x\n")
	openOut := filepath.Join(open, "out")
	out, code := runRecipes(t, open, openOut)
	if code != 1 {
		t.Fatalf("unclosed fence exit %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "fence is not closed") {
		t.Fatalf("unclosed fence output %q", out)
	}
	if _, err := os.Stat(openOut); !os.IsNotExist(err) {
		t.Fatalf("unclosed fence wrote %v", filesUnder(t, openOut))
	}

	again, code := runRecipes(t, dir, dest)
	if code != 1 || !strings.Contains(again, "already exists") {
		t.Fatalf("second extract exit %d\n%s", code, again)
	}
}

// A tilde fence is a fence: it is extracted like a backtick one. A fence the extractor cannot
// read as one (inside a blockquote, or indented four spaces or a tab) is an error that names
// the file and the line, and writes nothing, since a linter would otherwise never see it.
func TestTheExtractorLintsTildeFencesAndRefusesFencesItCannotRead(t *testing.T) {
	dir := t.TempDir()
	writeRecipe(t, dir, "tilde.md", ""+
		"text\n"+
		"~~~sh\n"+
		"echo tilde\n"+
		"```\n"+
		"echo still the body\n"+
		"~~~\n"+
		"\n"+
		"   ~~~~yaml\n"+
		"   name: indented\n"+
		"   ~~~~\n"+
		"\n"+
		"~~~hujson\n"+
		"{}\n"+
		"~~~\n"+
		"\n"+
		"~~~ `weird`\n"+
		"~~~\n")
	dest := filepath.Join(dir, "out")
	out, code := runRecipes(t, dir, dest)
	if code != 1 || !strings.Contains(out, `docs/recipes/tilde.md:16: fence tag "`+"`weird`"+`" is not one the extractor knows`) {
		t.Fatalf("a tilde fence with an unknown tag: exit %d\n%s", code, out)
	}
	writeRecipe(t, dir, "tilde.md", strings.Replace(readFile(t, filepath.Join(dir, "docs", "recipes", "tilde.md")), "~~~ `weird`\n~~~\n", "", 1))
	out, code = runRecipes(t, dir, dest)
	if code != 0 {
		t.Fatalf("tilde fences: exit %d\n%s", code, out)
	}
	if got := strings.Join(filesUnder(t, dest), ","); got != "github/workflows/tilde-1.yml,scripts/tilde-1.sh" {
		t.Fatalf("files %s", got)
	}
	if body := readFile(t, filepath.Join(dest, "scripts", "tilde-1.sh")); body != "echo tilde\n```\necho still the body\n" {
		t.Errorf("the tilde fence body = %q; a backtick line inside it is body", body)
	}
	if body := readFile(t, filepath.Join(dest, "github", "workflows", "tilde-1.yml")); body != "name: indented\n" {
		t.Errorf("the indented tilde fence body = %q", body)
	}
	for _, want := range []string{"tilde-1.sh is the fence that opens at docs/recipes/tilde.md:2", "docs/recipes/tilde.md:12 (hujson)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, c := range []struct {
		name, body, line, say string
	}{
		{"a fence in a blockquote", "text\n\n> ```sh\n> echo $UNQUOTED\n> ```\n", "3", "a fence inside a blockquote is not extracted or linted"},
		{"a tilde fence in a nested blockquote", "text\n> > ~~~sh\n", "2", "a fence inside a blockquote"},
		{"a fence indented by four spaces", "- item\n\n    ```sh\n    echo $UNQUOTED\n    ```\n", "3", "a fence indented by four or more spaces or a tab is not extracted or linted"},
		{"a fence indented by a tab", "text\n\t~~~yaml\n", "2", "a fence indented by four or more spaces or a tab"},
	} {
		d := t.TempDir()
		writeRecipe(t, d, "hidden.md", c.body)
		out, code := runRecipes(t, d, filepath.Join(d, "out"))
		if code != 1 || !strings.Contains(out, "docs/recipes/hidden.md:"+c.line+": "+c.say) {
			t.Errorf("%s: exit %d, want 1 and the file and line %s\n%s", c.name, code, c.line, out)
		}
		if _, err := os.Stat(filepath.Join(d, "out")); !os.IsNotExist(err) {
			t.Errorf("%s: the extractor wrote %v", c.name, filesUnder(t, filepath.Join(d, "out")))
		}
	}
	// Prose that mentions a fence, or quotes text that is not one, is not an error.
	d := t.TempDir()
	writeRecipe(t, d, "prose.md", "> a quoted sentence\n\n    an indented code block\n\nUse ``` or ~~~ to fence.\n\n> ``\n")
	if out, code := runRecipes(t, d, filepath.Join(d, "out")); code != 0 {
		t.Errorf("prose with fence-like text: exit %d\n%s", code, out)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: a file in the test directory
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestTheActionlintTargetExtractsRecipesBeforeItLints reads the real Makefile.
// The extractor runs before actionlint, and the four lines the shellcheck check
// requires stay in an order that check accepts.
func TestTheActionlintTargetExtractsRecipesBeforeItLints(t *testing.T) {
	text := readMakefile(t)
	for _, problem := range actionlintProblems(text) {
		t.Error(problem)
	}
	extractAt := strings.Index(text, "$(GO) run scripts/recipes.go")
	lintAt := strings.Index(text, "$(GO) run $(ACTIONLINT)")
	if extractAt < 0 || lintAt < 0 || extractAt > lintAt {
		t.Fatal("actionlint does not run $(GO) run scripts/recipes.go before $(GO) run $(ACTIONLINT)")
	}
	if !strings.Contains(text, `"$$tmp"/github/workflows/*.yml`) {
		t.Fatal("actionlint is not pointed at the extracted workflows")
	}
	if !strings.Contains(text, `shellcheck "$$tmp"/scripts/*.sh`) {
		t.Fatal("shellcheck is not pointed at the extracted scripts")
	}
}

// TestAWorkflowFenceIsExtractedUnchangedForTheLinter extracts a workflow actionlint
// would reject. The test does not run actionlint; it checks that the fence is written
// unchanged and that the Makefile lints the extracted workflows after the extractor.
// That a failure of either stops the target is TestTheActionlintTargetFailsWhenAnyCheckOfTheRecipesFails.
func TestAWorkflowFenceIsExtractedUnchangedForTheLinter(t *testing.T) {
	dir := t.TempDir()
	const body = "name: bad\non: [not-an-event]\n"
	writeRecipe(t, dir, "bad.md", "```yaml\n"+body+"```\n")
	dest := filepath.Join(dir, "out")
	out, code := runRecipes(t, dir, dest)
	if code != 0 {
		t.Fatalf("extract exit %d\n%s", code, out)
	}
	got, err := os.ReadFile(filepath.Join(dest, "github", "workflows", "bad-1.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("extracted workflow = %q, want the fence unchanged", got)
	}
	text := readMakefile(t)
	extractAt := strings.Index(text, "$(GO) run scripts/recipes.go")
	lintAt := strings.Index(text, `"$$tmp"/github/workflows/*.yml`)
	if extractAt < 0 || lintAt < 0 || extractAt > lintAt {
		t.Fatal("make actionlint does not lint the extracted workflows after the extractor")
	}
	if strings.Contains(text, "-config-file") {
		t.Fatal("actionlint is given a config file; the extracted workflows use its defaults")
	}
}

func githubActionsRecipe(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "recipes", "github-actions.md"))
	if err != nil {
		t.Fatal("docs/recipes/github-actions.md: no such file or directory")
	}
	return string(b)
}

// fence returns the body of the first fenced block tagged tag, including its trailing newline.
func fence(t *testing.T, text, tag string) string {
	t.Helper()
	open := "```" + tag + "\n"
	i := strings.Index(text, open)
	if i < 0 {
		t.Fatalf("no %s fence", tag)
	}
	rest := text[i+len(open):]
	j := strings.Index(rest, "\n```")
	if j < 0 {
		t.Fatalf("%s fence is not closed", tag)
	}
	return rest[:j+1]
}

func workflowOf(t *testing.T) (file, wf string) {
	t.Helper()
	file = githubActionsRecipe(t)
	return file, fence(t, file, "yaml")
}

// The recipe's workflow, parsed. The tests read the structure (a job's environment, a
// step's with: and env:) from it and not from the text, so a guard moved into a comment
// or a string does not count.
type recipeStep struct {
	Name string            `yaml:"name"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	With map[string]any    `yaml:"with"`
	Env  map[string]string `yaml:"env"`
	Run  string            `yaml:"run"`
}

type recipeJob struct {
	Name           string            `yaml:"name"`
	If             string            `yaml:"if"`
	Needs          []string          `yaml:"needs"`
	Environment    any               `yaml:"environment"`
	Permissions    any               `yaml:"permissions"`
	Env            map[string]string `yaml:"env"`
	TimeoutMinutes int               `yaml:"timeout-minutes"`
	Steps          []recipeStep      `yaml:"steps"`
}

type recipeWorkflow struct {
	On          map[string]any       `yaml:"on"`
	Permissions any                  `yaml:"permissions"`
	Env         map[string]string    `yaml:"env"`
	Jobs        map[string]recipeJob `yaml:"jobs"`
}

// recipeJobNames are the two jobs that check a pull request: offline for one from a fork,
// live for one from this repository. The workflow has a third, result, which is the check to
// require.
var recipeJobNames = []string{"offline", "live"}

const resultJob = "result"

// checkName is the name of the status check to require: the name: of the result job. Branch
// protection matches a job's name, or its id when it has none, so a name: on the job changes
// the check that reports, and every document that tells the owner what to require carries
// this string.
const checkName = "tailkeeper-acl-result"

// checkNameDocuments are the documents that tell the owner which status check to require.
var checkNameDocuments = []string{"docs/recipes/github-actions.md", "docs/acl.md", "CHANGELOG.md", "docs/design.md"}

// workflowGuardClause is the sentence every document carries about the workflow file: under
// pull_request the pull request's own copy runs, so it is guarded like the policy files.
const workflowGuardClause = "Under `pull_request` the workflow that runs is the pull request's own, so add the workflow file to CODEOWNERS beside the policy and invariants files and require code-owner review on the default branch."

func recipeWorkflowOf(t *testing.T) recipeWorkflow {
	t.Helper()
	_, wf := workflowOf(t)
	var w recipeWorkflow
	if err := yaml.Unmarshal([]byte(wf), &w); err != nil {
		t.Fatal(err)
	}
	if len(w.Jobs) != len(recipeJobNames)+1 {
		t.Fatalf("the workflow has %d jobs, want %v and %s", len(w.Jobs), recipeJobNames, resultJob)
	}
	for _, name := range append([]string{resultJob}, recipeJobNames...) {
		if _, ok := w.Jobs[name]; !ok {
			t.Fatalf("the workflow has no job %s", name)
		}
	}
	return w
}

// stepOf returns the one step of the job with the name.
func stepOf(t *testing.T, job, name string) recipeStep {
	t.Helper()
	var found []recipeStep
	for _, s := range recipeWorkflowOf(t).Jobs[job].Steps {
		if s.Name == name {
			found = append(found, s)
		}
	}
	if len(found) != 1 {
		t.Fatalf("job %s has %d steps named %q, want 1", job, len(found), name)
	}
	return found[0]
}

// jobScript is the shell of every run: step of the job, in order.
func jobScript(t *testing.T, job string) string {
	t.Helper()
	var b strings.Builder
	for _, s := range recipeWorkflowOf(t).Jobs[job].Steps {
		b.WriteString(s.Run)
		b.WriteByte('\n')
	}
	return b.String()
}

// jobText is the text of one job, from its key to the next job or the end of the fence.
func jobText(t *testing.T, job string) string {
	t.Helper()
	_, wf := workflowOf(t)
	start := strings.Index(wf, "\n  "+job+":\n")
	if start < 0 {
		t.Fatalf("no job %s", job)
	}
	rest := wf[start+1:]
	if end := regexp.MustCompile(`(?m)^  [a-z]+:\n`).FindAllStringIndex(rest, -1); len(end) > 1 {
		return rest[:end[1][0]]
	}
	return rest
}

// commandsOnly drops whole-line comments so a comment cannot satisfy a command check.
func commandsOnly(wf string) string {
	var b strings.Builder
	for _, line := range strings.Split(wf, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func TestTheGitHubActionsRecipePinsActionsBySHA(t *testing.T) {
	_, wf := workflowOf(t)
	uses := regexp.MustCompile(`(?m)^[ \t]*uses:[ \t]*([^ \t#]+)[ \t]*(#.*)?$`)
	found := uses.FindAllStringSubmatch(wf, -1)
	if len(found) == 0 {
		t.Fatal("workflow has no uses:")
	}
	pin := regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)+@[0-9a-f]{40}$`)
	ver := regexp.MustCompile(`^# v[0-9]`)
	for _, m := range found {
		if !pin.MatchString(m[1]) {
			t.Fatalf("uses %q is not a full commit SHA", m[1])
		}
		if !ver.MatchString(strings.TrimSpace(m[2])) {
			t.Fatalf("uses %s: the comment %q does not name a version", m[1], m[2])
		}
		if strings.Contains(m[1], "@v") || strings.HasSuffix(m[1], "@main") || strings.HasSuffix(m[1], "@master") {
			t.Fatalf("uses %s is a branch or a tag", m[1])
		}
	}
}

func TestTheGitHubActionsRecipeUsesPullRequestAndNeverPullRequestTarget(t *testing.T) {
	file, wf := workflowOf(t)
	if strings.Contains(wf, "pull_request_target") {
		t.Fatal("workflow contains pull_request_target")
	}
	if !strings.Contains(wf, "on:\n  pull_request:\n") {
		t.Fatal("workflow does not trigger on pull_request")
	}
	for _, event := range []string{"push:", "schedule:", "workflow_dispatch:", "pull_request_target:"} {
		if strings.Contains(wf, "\n  "+event) {
			t.Fatalf("workflow also triggers on %s", event)
		}
	}
	if !strings.Contains(file, "pull_request_target") {
		t.Fatal("the recipe does not name pull_request_target")
	}
}

// Only the live job can mint an OIDC token, and it runs in a named environment. The workflow
// grants contents read; the offline job, which runs a fork's pull request, inherits only that
// and holds no environment and no secret.
func TestTheGitHubActionsRecipeGrantsTheTokenToTheLiveJobInANamedEnvironmentOnly(t *testing.T) {
	w := recipeWorkflowOf(t)
	_, wf := workflowOf(t)
	code := commandsOnly(wf)
	if got, want := permissionsOf(t, "the workflow", w.Permissions), map[string]string{"contents": "read"}; !reflect.DeepEqual(got, want) {
		t.Errorf("the workflow's permissions are %v, want %v", got, want)
	}
	if got := permissionsOf(t, "job offline", w.Jobs["offline"].Permissions); got != nil {
		t.Errorf("job offline sets permissions %v; it inherits the workflow's", got)
	}
	if got, want := permissionsOf(t, "job live", w.Jobs["live"].Permissions), map[string]string{"contents": "read", "id-token": "write"}; !reflect.DeepEqual(got, want) {
		t.Errorf("job live has permissions %v, want %v", got, want)
	}
	if strings.Count(code, "id-token") != 1 {
		t.Errorf("id-token appears %d times in the workflow, want once (the live job)", strings.Count(code, "id-token"))
	}
	for _, extra := range []string{"contents: write", "pull-requests:", "packages:", "actions:", "checks:", "statuses:", "id-token: read", "attestations:"} {
		if strings.Contains(code, extra) {
			t.Errorf("permissions include %s", extra)
		}
	}
	// A hung run holds the runner until GitHub's own limit, six hours: every job has its own.
	for name, job := range w.Jobs {
		if job.TimeoutMinutes < 1 || job.TimeoutMinutes > 60 {
			t.Errorf("job %s has timeout-minutes %d, want 1 to 60", name, job.TimeoutMinutes)
		}
	}
	if w.Jobs["live"].Environment != "tailkeeper-policy" {
		t.Errorf("the live job's environment is %v, want tailkeeper-policy", w.Jobs["live"].Environment)
	}
	if w.Jobs["offline"].Environment != nil || strings.Contains(jobText(t, "offline"), "environment:") {
		t.Error("the offline job names an environment")
	}
	if got, want := w.Jobs["offline"].If, "github.event.pull_request.head.repo.full_name != github.repository"; got != want {
		t.Errorf("the offline job runs when %q, want %q", got, want)
	}
	if got, want := w.Jobs["live"].If, "github.event.pull_request.head.repo.full_name == github.repository"; got != want {
		t.Errorf("the live job runs when %q, want %q", got, want)
	}
	offline := commandsOnly(jobText(t, "offline"))
	for _, bad := range []string{"secrets.", "id-token", "OIDC", "ACTIONS_ID_TOKEN", "TAILNET_ID"} {
		if strings.Contains(offline, bad) {
			t.Errorf("the offline job, which runs a fork's pull request, mentions %q", bad)
		}
	}
	for _, name := range recipeJobNames {
		if len(w.Jobs[name].Env) != 0 {
			t.Errorf("job %s sets env at the job level: %v; the ids are set on the one step that needs them", name, w.Jobs[name].Env)
		}
	}
	if len(w.Env) != 0 {
		t.Errorf("the workflow sets env: %v", w.Env)
	}
}

// The tailnet id and the OAuth client id are identifiers that must not reach a log: GitHub
// prints a step's merged env: in its header and masks only secrets. So they come from
// secrets, on the one step that writes the configuration, and never from vars.
func TestTheGitHubActionsRecipeTakesBothIdsFromSecretsOnTheCheckStepOnly(t *testing.T) {
	file, wf := workflowOf(t)
	code := commandsOnly(wf)
	if strings.Contains(code, "vars.") {
		t.Error("the workflow reads vars.*: GitHub prints a variable in the step header and masks only secrets")
	}
	if strings.Contains(wf, "T1234CNTRL") {
		t.Error("the workflow embeds a tailnet id")
	}
	for _, s := range []string{"${{ secrets.TAILKEEPER_TAILNET_ID }}", "${{ secrets.TAILKEEPER_OIDC_CLIENT_ID }}"} {
		if strings.Count(code, s) != 1 {
			t.Errorf("the workflow reads %s %d times, want once", s, strings.Count(code, s))
		}
	}
	env := stepOf(t, "live", "Check the policy").Env
	if env["TAILNET_ID"] != "${{ secrets.TAILKEEPER_TAILNET_ID }}" || env["OIDC_CLIENT_ID"] != "${{ secrets.TAILKEEPER_OIDC_CLIENT_ID }}" {
		t.Errorf("the live Check step's env is %v, want both ids from secrets", env)
	}
	for _, s := range []string{
		"The workflow reads the tailnet id from the secret `TAILKEEPER_TAILNET_ID` and the OAuth client id from the secret `TAILKEEPER_OIDC_CLIENT_ID`. Both are environment secrets of the environment `tailkeeper-policy`, not repository secrets, so only a job that has passed the environment's protection receives them.",
		"with `tailnetId` and `clientId` taken from the two environment secrets",
		"In the workflow those two values are the secrets TAILKEEPER_TAILNET_ID\n  // and TAILKEEPER_OIDC_CLIENT_ID of the environment tailkeeper-policy.",
		"Both are secrets and not variables: GitHub prints a step's `env:` in the log header of the step and masks only secrets",
		"prints neither id",
	} {
		if !strings.Contains(file, s) {
			t.Errorf("the recipe does not say %q", s)
		}
	}
	for _, old := range []string{"repository variable", "from the repository secret", "the two repository secrets", "the repository secrets TAILKEEPER"} {
		if strings.Contains(file, old) {
			t.Errorf("the recipe still says %q: the ids are environment secrets, which only an approved job receives", old)
		}
	}
	// An environment secret reaches only a job that names the environment: the one step that
	// reads them is in that job.
	live := commandsOnly(jobText(t, "live"))
	if strings.Count(live, "secrets.TAILKEEPER_") != 2 || recipeWorkflowOf(t).Jobs["live"].Environment != "tailkeeper-policy" {
		t.Error("the ids are not read in the job that names the environment")
	}
}

// The token is tailkeeper's own business: the oidc provider asks the job's token endpoint
// (internal/creds/read.go), so the workflow has no step that fetches, writes or prints it.
func TestTheGitHubActionsRecipeNeverHandlesTheOIDCToken(t *testing.T) {
	file, wf := workflowOf(t)
	for _, bad := range []string{"python", "ACTIONS_ID_TOKEN", "tokenFile", "oidc-token", "TOKEN_PATH", "add-mask", "urllib"} {
		if strings.Contains(wf, bad) {
			t.Errorf("the workflow mentions %q: the token is the oidc provider's to fetch", bad)
		}
	}
	for _, s := range []string{
		"tailkeeper's `oidc` provider fetches the GitHub Actions token itself",
		"The workflow never reads, writes or prints the token.",
		"The configuration it writes has a `clientId` and no `tokenFile`, so no token file exists on the runner.",
		"The audience is the provider's default; the workflow does not set one.",
	} {
		if !strings.Contains(file, s) {
			t.Errorf("the recipe does not say %q", s)
		}
	}
	// The provider really does what the recipe says: with no tokenFile it uses the two variables.
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "creds", "read.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`"ACTIONS_ID_TOKEN_REQUEST_URL"`, `"ACTIONS_ID_TOKEN_REQUEST_TOKEN"`, `aud = "api.tailscale.com/" + p.ClientID`} {
		if !strings.Contains(string(src), s) {
			t.Errorf("internal/creds/read.go no longer has %s, which the recipe relies on", s)
		}
	}
}

// The base commit's files are the trust anchor: the second checkout is of the base SHA and
// never of the head, in both jobs, and the first checkout names no ref.
func TestTheGitHubActionsRecipeChecksOutTheBaseFromTheBaseSHAInBothJobs(t *testing.T) {
	for _, job := range recipeJobNames {
		first := stepOf(t, job, "Checkout")
		second := stepOf(t, job, "Checkout the base commit")
		if _, ok := first.With["ref"]; ok || first.With["persist-credentials"] != false {
			t.Errorf("job %s: the first checkout is %v; it names no ref and keeps no credential", job, first.With)
		}
		if second.With["ref"] != "${{ github.event.pull_request.base.sha }}" || second.With["path"] != "base" || second.With["persist-credentials"] != false {
			t.Errorf("job %s: the base checkout is %v; want ref github.event.pull_request.base.sha, path base, no credential", job, second.With)
		}
		files := stepScript(t, job, "Files from the base commit")
		for _, s := range []string{
			`cp base/invariants.hujson "$RUNNER_TEMP/tailkeeper/invariants.hujson"`,
			`cp base/policy.hujson "$RUNNER_TEMP/tailkeeper/policy.hujson"`,
			"umask 077",
			`install -d -m 700 "$RUNNER_TEMP/tailkeeper"`,
		} {
			if !strings.Contains(files, s) {
				t.Errorf("job %s: the files step lacks %q", job, s)
			}
		}
	}
	_, wf := workflowOf(t)
	if strings.Contains(wf, "head.sha") {
		t.Error("the workflow names head.sha")
	}
	if strings.Contains(wf, "git fetch") {
		t.Error("workflow fetches after the credential is removed")
	}
}

// The release is verified as the README does, in both jobs, with the signer identity written
// whole and compared exactly. A pattern in its place (cosign's -regexp flags, gh's -regex)
// would accept any signer.
func TestTheGitHubActionsRecipeVerifiesTheReleaseAsTheREADMEDoesInBothJobs(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join(repoRoot(t), "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"cosign verify-blob", "gh attestation verify", "shasum -a 256 -c -", "sha256sum -c -", `IDENTITY="https://github.com/abm9111/tailkeeper/.github/workflows/release.yml@refs/tags/$VERSION"`} {
		if !strings.Contains(string(readme), cmd) {
			t.Fatalf("README verify block no longer contains %q", cmd)
		}
	}
	_, wf := workflowOf(t)
	for _, bad := range []string{"regexp", "-regex", "identity-regex", "--insecure", "skip-verify", "--force"} {
		if strings.Contains(wf, bad) {
			t.Errorf("the workflow has %q: the signer identity is compared exactly", bad)
		}
	}
	for _, job := range recipeJobNames {
		verify := stepOf(t, job, "Verify the release")
		if verify.Env["GH_TOKEN"] != "${{ github.token }}" {
			t.Errorf("job %s: the verify step's GH_TOKEN is %q", job, verify.Env["GH_TOKEN"])
		}
		script := verify.Run
		var at []int
		for _, s := range []string{
			`IDENTITY="https://github.com/abm9111/tailkeeper/.github/workflows/release.yml@refs/tags/${VERSION}"`,
			"cosign verify-blob checksums.txt \\\n  --bundle checksums.txt.sigstore.json \\\n  --certificate-identity \"$IDENTITY\" \\\n  --certificate-oidc-issuer https://token.actions.githubusercontent.com\n",
			"sha256sum -c -",
			"shasum -a 256 -c -",
			`gh attestation verify "$ARCHIVE" --repo abm9111/tailkeeper --cert-identity "$IDENTITY"` + "\n",
			`gh attestation verify checksums.txt --repo abm9111/tailkeeper --cert-identity "$IDENTITY"` + "\n",
			"tar -xzf",
		} {
			i := strings.Index(script, s)
			if i < 0 {
				t.Errorf("job %s: the verify step lacks %q", job, s)
			}
			at = append(at, i)
		}
		if !sort.IntsAreSorted(at) {
			t.Errorf("job %s: the verify commands are not in the order cosign, checksum, attestation of the archive, attestation of checksums.txt, tar: %v", job, at)
		}
		if !strings.Contains(script, "set -eu\nset -o pipefail\n") {
			t.Errorf("job %s: the verify step does not stop at the first failure", job)
		}
		// A download that fails with an HTTP error must stop the step at the download: -f
		// makes curl exit on a 4xx or 5xx instead of saving the error page as the file.
		downloads := 0
		for _, line := range strings.Split(script, "\n") {
			if strings.Contains(line, "curl ") {
				downloads++
				if !strings.HasPrefix(line, "curl -fsSL -o ") {
					t.Errorf("job %s: the download %q is not curl -fsSL -o", job, line)
				}
			}
		}
		if downloads != 3 {
			t.Errorf("job %s: the verify step has %d downloads, want the archive, checksums.txt and the bundle", job, downloads)
		}
		if first := strings.Index(jobScript(t, job), "acl "); first < strings.Index(jobScript(t, job), "cosign verify-blob") {
			t.Errorf("job %s: tailkeeper runs before the release is verified", job)
		}
	}
}

func recipeExits(t *testing.T) []int {
	t.Helper()
	usage := tkerr.ExitCode(tkerr.New(tkerr.Usage, "m", ""))
	rejected := (tools.ACLValidateOutput{Status: "rejected"}).ExitCode()
	if rejected != usage || tkerr.ExitCode(tkerr.New(tkerr.ValidationFailed, "m", "")) != usage {
		t.Fatalf("usage is %d and a rejected policy is %d", usage, rejected)
	}
	api := tkerr.ExitCode(tkerr.New(tkerr.APIError, "m", ""))
	if (tools.ACLValidateOutput{Status: "unknown"}).ExitCode() != api {
		t.Fatal("an unknown ACL answer and an API error do not share an exit")
	}
	return []int{
		tkerr.ExitCode(nil),
		api,
		usage,
		tkerr.ExitCode(tkerr.New(tkerr.CredentialUnavailable, "m", "")),
		tkerr.ExitCode(tkerr.New(tkerr.FindingsPresent, "m", "")),
		(tools.ACLValidateOutput{Status: "fail"}).ExitCode(),
	}
}

func TestTheGitHubActionsRecipeCoversTheExitCodes(t *testing.T) {
	cred := tkerr.ExitCode(tkerr.New(tkerr.CredentialUnavailable, "m", ""))
	for _, job := range recipeJobNames {
		step := stepScript(t, job, "Exit")
		arms := regexp.MustCompile(`(?m)^[ \t]*([0-9]+|\*)\)`).FindAllStringSubmatch(step, -1)
		var got []string
		star := ""
		for _, m := range arms {
			if m[1] == "*" {
				star = m[1]
				continue
			}
			got = append(got, m[1])
		}
		var want []string
		for _, n := range recipeExits(t) {
			// The offline job reads no credential, so it has no arm for a missing one.
			if job == "offline" && n == cred {
				continue
			}
			want = append(want, strconv.Itoa(n))
		}
		if strings.Join(got, ",") != strings.Join(want, ",") || star != "*" {
			t.Errorf("job %s: Exit step case arms %v *, want %v and *", job, got, want)
		}
		i := strings.Index(step, "*)")
		end := strings.Index(step[i:], ";;")
		arm := step[i : i+end]
		if !strings.Contains(arm, "exit 1") || strings.Contains(arm, "exit 0") {
			t.Errorf("job %s: Exit step * arm = %q, want exit 1", job, arm)
		}
	}
	for _, line := range strings.Split(commandsOnly(jobText(t, "live")), "\n") {
		if strings.Contains(line, "acl validate") && strings.Contains(line, "--offline") {
			t.Errorf("the live job validates offline: %s", line)
		}
	}
	for _, line := range strings.Split(commandsOnly(jobText(t, "offline")), "\n") {
		if strings.Contains(line, "acl validate") && (!strings.Contains(line, "--offline") || strings.Contains(line, "--fail-on")) {
			t.Errorf("the offline job runs %q: it must be offline and without --fail-on, which the command refuses", line)
		}
		if strings.Contains(line, "acl diff") && !strings.Contains(line, "--offline") {
			t.Errorf("the offline job runs %q: the diff of two files is offline", line)
		}
	}
}

func TestTheGitHubActionsRecipeKeepsTheForkAndProbingCostSentences(t *testing.T) {
	file, wf := workflowOf(t)
	for _, s := range []string{
		"A pull request from a fork runs only the offline job.",
		"personalData stays mask",
		"Tailscale's own limit is per credential and unpublished.",
		"A forked pull request cannot: it gets no OIDC token.",
		"A fork pull request is never green on the offline checks alone.",
		"the job still fails, with a message that a maintainer must run the live check from a branch of this repository",
		"Masking covers personal data only. On a public repository the annotations and the step summary carry text derived from the live policy",
		"masked for personal data and not for tag names, host names or rule shapes",
		"The `live` job's `case` has an arm for 0, 1, 2, 5, 8 and 9, and a `*` arm that fails the job.",
		"Those six are a success, an API error or an ACL answer of `unknown`, usage or a rejected policy, a missing credential, findings (`--fail-on`), and a failed assertion.",
		"Exit 6 (configuration) and exit 7 (the audit log) fall through to `*` and fail the job.",
		"The OAuth client has the policy scopes only: `policy_file:read`, `devices:core:read` and `devices:posture_attributes:read`. It does not request `users:read`.",
		"`--format github` writes at most ten annotations of each severity and then a line that says to see the summary.",
		"tailkeeper's bucket (`acl.validatePerMinute`, 30 in the configuration, which is also the default)",
	} {
		if !strings.Contains(file, s) {
			t.Errorf("recipe does not say %q", s)
		}
	}
	// The offline job's description, in the section that describes the jobs: it holds no
	// token, because GitHub issues none to a fork. The sentence pair is pinned there, so the
	// same fact elsewhere in the file cannot stand in for it.
	runs := aclSection(t, file, "## What it runs")
	for _, s := range []string{
		"It has no environment, no `id-token` and no secret. GitHub issues no OIDC token to a fork.",
		"A fork pull request is never green on the offline checks alone.",
		"- **`result`, the one check to require.** It needs both jobs, runs always (`if: always()`), and has no environment, no `id-token` and no secret. It fails unless `live` succeeded and `offline` was skipped, which is what a pull request from this repository gives. A pull request from a fork runs `offline`, which fails by design, so `result` fails too. Branch protection counts a job that its `if` skipped as a pass, so requiring `live` alone would let every fork pull request through and requiring `offline` alone would let every pull request from this repository through. Require only the status check `tailkeeper-acl-result`, the `name:` of this job.",
		"The `result` job passes only for `skipped` and `success`, in that order for `offline` and `live`, and fails for every other pair, a cancelled or failed job included.",
	} {
		if !strings.Contains(runs, s) {
			t.Errorf("the section \"What it runs\" does not say %q", s)
		}
	}
	if config.DefaultValidatePerMinute != 30 {
		t.Errorf("the recipe says the default validatePerMinute is 30; the code says %d", config.DefaultValidatePerMinute)
	}
	if strings.Contains(wf, ".fork") {
		t.Error("workflow reads head.repo.fork; a deleted fork is an empty name and must stay off the live path")
	}
	if strings.Count(wf, "persist-credentials: false") != 4 || strings.Count(wf, "path: base") != 2 {
		t.Error("the base policy is not a second checkout at its own path in each job")
	}
}

// The third job, result, is named tailkeeper-acl-result, and that name is the status check to
// require: branch protection matches a job's name, or its id when it has none. The job needs
// both of the others, runs whatever they did, and holds nothing: no environment, no permission
// of its own, no secret, no action, no checkout.
func TestTheResultJobIsTheOneCheckToRequireAndHoldsNothing(t *testing.T) {
	_, wf := workflowOf(t)
	if !strings.HasPrefix(wf, "name: tailkeeper-acl\n") {
		t.Error("the workflow is not named tailkeeper-acl")
	}
	w := recipeWorkflowOf(t)
	job := w.Jobs[resultJob]
	if job.Name != checkName {
		t.Errorf("the result job is named %q, want %q: the documents tell the owner to require that status check", job.Name, checkName)
	}
	for _, other := range recipeJobNames {
		if w.Jobs[other].Name != "" {
			t.Errorf("the %s job has a name %q: only the result job is a check to require, and a name elsewhere could collide with it", other, w.Jobs[other].Name)
		}
	}
	if !reflect.DeepEqual(job.Needs, []string{"offline", "live"}) {
		t.Errorf("the result job needs %v, want offline and live", job.Needs)
	}
	if job.If != "always()" {
		t.Errorf("the result job runs when %q, want always(): a skipped job would count as a pass", job.If)
	}
	if job.Environment != nil || job.Permissions != nil || len(job.Env) != 0 || job.TimeoutMinutes <= 0 || len(job.Steps) != 1 {
		t.Errorf("the result job holds an environment %v, permissions %v, env %v, timeout %d and %d steps; want none of the first three, a timeout and one step", job.Environment, job.Permissions, job.Env, job.TimeoutMinutes, len(job.Steps))
	}
	text := commandsOnly(jobText(t, resultJob))
	for _, bad := range []string{"secrets.", "id-token", "uses:", "checkout", "environment:", "GITHUB_TOKEN", "github.token"} {
		if strings.Contains(text, bad) {
			t.Errorf("the result job mentions %q", bad)
		}
	}
	step := stepOf(t, resultJob, "Result")
	if step.Env["OFFLINE_RESULT"] != "${{ needs.offline.result }}" || step.Env["LIVE_RESULT"] != "${{ needs.live.result }}" || len(step.Env) != 2 {
		t.Errorf("the result step's env is %v, want the results of offline and live", step.Env)
	}
	// Each document that tells the owner what to require names the same check, and none
	// names the long form that branch protection does not list.
	for _, doc := range checkNameDocuments {
		text := readFile(t, filepath.Join(repoRoot(t), doc))
		if !strings.Contains(text, "`"+checkName+"`") {
			t.Errorf("%s does not tell the owner to require the status check `%s`", doc, checkName)
		}
		if strings.Contains(text, "tailkeeper-acl / result") {
			t.Errorf("%s names the check \"tailkeeper-acl / result\"; the status check is `%s`", doc, checkName)
		}
	}
}

// The workflow runs on every pull request. A workflow that a paths filter keeps from running
// never reports the required check, so the check would block every pull request that does not
// touch the policy; the recipe says so beside the check to require.
func TestTheWorkflowHasNoPathFilterBecauseARequiredCheckMustAlwaysReport(t *testing.T) {
	on := recipeWorkflowOf(t).On
	pr, ok := on["pull_request"]
	if !ok || len(on) != 1 {
		t.Fatalf("on is %v, want pull_request alone", on)
	}
	if filter, isMap := pr.(map[string]any); pr != nil && (!isMap || len(filter) != 0) {
		t.Errorf("on.pull_request is %v, want no filter at all: no paths, paths-ignore, branches or types", pr)
	}
	_, wf := workflowOf(t)
	for _, key := range []string{"paths:", "paths-ignore:"} {
		if strings.Contains(commandsOnly(wf), key) {
			t.Errorf("the workflow has %s", key)
		}
	}
}

// The result step decides on every pair of results GitHub gives a job. Only a skipped offline
// job with a successful live job passes: the pull request from this repository whose live
// check succeeded. A pull request from a fork has a failed offline job and a skipped live one,
// and fails; a pair with a failed, cancelled or skipped live job fails, and so does a pair
// where both ran or neither did.
func TestTheResultStepPassesOnlyWhenTheLiveJobSucceededAndTheOfflineJobWasSkipped(t *testing.T) {
	skipOnWindows(t)
	results := []string{"success", "failure", "cancelled", "skipped"}
	passes := 0
	for _, offline := range results {
		for _, live := range results {
			r := stepRun(t, t.TempDir(), resultJob, "Result", "OFFLINE_RESULT="+offline, "LIVE_RESULT="+live)
			want := 1
			if offline == "skipped" && live == "success" {
				want = 0
				passes++
			}
			if r.code != want {
				t.Errorf("offline %s, live %s: exit %d, want %d\n%s", offline, live, r.code, want, r.stderr)
			}
			if want == 1 && !strings.Contains(r.stdout, "::error title=tailkeeper::The policy check did not pass (offline "+offline+", live "+live+")") {
				t.Errorf("offline %s, live %s: the failure says %q", offline, live, r.stdout)
			}
		}
	}
	if passes != 1 {
		t.Errorf("%d pairs pass, want one", passes)
	}
	// An empty or odd result, which GitHub does not give, is not a pass either.
	for _, c := range [][2]string{{"", ""}, {"skipped", ""}, {"", "success"}, {"skipped", "Success"}, {"skipped", "success "}} {
		if r := stepRun(t, t.TempDir(), resultJob, "Result", "OFFLINE_RESULT="+c[0], "LIVE_RESULT="+c[1]); r.code == 0 {
			t.Errorf("offline %q, live %q: the step passed", c[0], c[1])
		}
	}
}

func TestTheGitHubActionsRecipeWritesTheStepSummaryTheFormatterPointsAt(t *testing.T) {
	file, wf := workflowOf(t)
	if strings.Contains(wf, "GITHUB_OUTPUT") {
		t.Fatal("workflow names GITHUB_OUTPUT")
	}
	if strings.Count(wf, "--format github") < 4 || !strings.Contains(wf, "acl diff") {
		t.Fatal("workflow does not run acl validate and acl diff with --format github in each job")
	}
	if !strings.Contains(file, "see the summary") {
		t.Fatal("recipe does not say see the summary")
	}
	for _, job := range recipeJobNames {
		step := stepOf(t, job, "Write the step summary")
		if !strings.Contains(step.Run, "--format markdown") || !strings.Contains(step.Run, "GITHUB_STEP_SUMMARY") {
			t.Errorf("job %s: the summary step does not append --format markdown to GITHUB_STEP_SUMMARY", job)
		}
		if step.Env["XDG_CONFIG_HOME"] != "${{ runner.temp }}/config" || step.Env["XDG_STATE_HOME"] != "${{ runner.temp }}/state" {
			t.Errorf("job %s: the summary step does not set XDG_CONFIG_HOME and XDG_STATE_HOME: %v", job, step.Env)
		}
		if step.If != "always()" || stepOf(t, job, "Exit").If != "always()" {
			t.Errorf("job %s: the summary and Exit steps must run after a failure", job)
		}
	}
}

func TestTheGitHubActionsConfigParses(t *testing.T) {
	file := githubActionsRecipe(t)
	body := fence(t, file, "hujson")
	cfg, err := config.Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PersonalData != config.PersonalDataMask {
		t.Fatalf("personalData = %q", cfg.PersonalData)
	}
	if len(cfg.Contexts) != 1 {
		t.Fatalf("contexts = %d", len(cfg.Contexts))
	}
	ctx, ok := cfg.Contexts["ci"]
	if !ok {
		t.Fatal("no context ci")
	}
	if !filepath.IsAbs(cfg.ACL.InvariantsFile) {
		t.Fatalf("invariantsFile %q is not absolute", cfg.ACL.InvariantsFile)
	}
	p := ctx.Credentials.Read
	if p.Provider != "oidc" || len(p.Command) != 0 || p.Path != "" || p.TokenFile != "" || p.Audience != "" {
		t.Fatalf("provider = %#v; the oidc provider takes its token from the job and its default audience", p)
	}
	for _, bad := range []string{`"command"`, `"path"`, `"clientSecret"`, `"client_secret"`, `"secret"`, `"password"`, `"tokenFile"`, `"audience"`} {
		if strings.Contains(body, bad) {
			t.Fatalf("config contains %s", bad)
		}
	}
}

func cronRecipe(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "recipes", "cron.md"))
	if err != nil {
		t.Fatal("docs/recipes/cron.md: no such file or directory")
	}
	return string(b)
}

// fenced returns the bodies of fences whose info word is tag. The recipes indent
// no fence, and the extractor's rules are not reimplemented here.
func fenced(text, tag string) []string {
	var out []string
	var b strings.Builder
	open := false
	for _, line := range strings.Split(text, "\n") {
		if !open {
			if line == "```"+tag {
				open = true
				b.Reset()
			}
			continue
		}
		if line == "```" {
			open = false
			out = append(out, b.String())
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return out
}

// hasLine reports whether body has a line that is exactly want.
func hasLine(body, want string) bool {
	for _, line := range strings.Split(body, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

func exitArms(script string) map[string]string {
	arms := map[string]string{}
	var arm, body string
	in := false
	for _, line := range strings.Split(script, "\n") {
		trim := strings.TrimSpace(line)
		if !in {
			if strings.HasPrefix(trim, "case ") {
				in = true
			}
			continue
		}
		if trim == "esac" {
			if arm != "" {
				arms[arm] = body
			}
			in, arm, body = false, "", ""
			continue
		}
		if len(trim) >= 2 && trim[len(trim)-1] == ')' && armLine(trim[:len(trim)-1]) {
			if arm != "" {
				arms[arm] = body
			}
			arm, body = trim[:len(trim)-1], ""
			continue
		}
		body += line + "\n"
	}
	return arms
}

func armLine(s string) bool {
	if s == "*" {
		return true
	}
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func shellJoined(t *testing.T, text string) string {
	t.Helper()
	shells := fenced(text, "sh")
	if len(shells) == 0 {
		t.Fatal("no sh fence")
	}
	return strings.Join(shells, "\n")
}

func TestTheCronRecipeIsALaunchAgentAndASystemdTimer(t *testing.T) {
	text := cronRecipe(t)
	plist := fenced(text, "xml")
	if len(plist) != 1 || !strings.Contains(plist[0], "<plist") {
		t.Fatal("the LaunchAgent plist is not one xml fence")
	}
	if !strings.Contains(plist[0], "StandardOutPath") || !strings.Contains(plist[0], "StandardErrorPath") || !strings.Contains(plist[0], "$HOME/Library/Logs/") {
		t.Fatal("the plist does not keep stdout and stderr under ~/Library/Logs/")
	}
	if !strings.Contains(text, "LaunchAgent") {
		t.Fatal("LaunchAgent is not named")
	}
	timers := 0
	for _, body := range fenced(text, "ini") {
		if strings.Contains(body, "[Timer]") {
			timers++
		}
		if strings.Contains(body, "$HOME") {
			t.Fatal("a Linux unit uses the macOS home placeholder")
		}
	}
	if timers != 1 || !strings.Contains(text, "systemd timer") {
		t.Fatal("the systemd timer is not one ini fence")
	}
	if !strings.Contains(text, "cron on macOS is not the schedule") || !strings.Contains(text, "macOS cron has no keychain access") {
		t.Fatal("cron on macOS is not refused")
	}
	if strings.Contains(text, "policy-exec.sh") {
		t.Fatal("the recipe wraps the check in policy-exec.sh")
	}
	if !strings.Contains(text, "/home/you/") {
		t.Fatal("Linux paths are not under /home/you")
	}
	for _, s := range []string{
		"`BASELINE_FILE` is a file of one line: a version id from `acl history`",
		"`acl diff --from-version` reads that stored policy from the configuration audit log as the old side and classifies the live policy (the new side) against it",
		"Reading the log needs the optional scope `logs:configuration:read`",
		"Tailscale keeps the configuration audit log for 90 days",
		"`acl diff` prints `not_found`",
		"the numbered layout that `acl get` prints on a terminal or into a redirect is a document, and `acl diff --against` refuses it (exit 2)",
		"It needs `personalData: show` in the configuration of that command",
		"**This default needs a policy update at least every 90 days.**",
		"for a policy that changes rarely, use the saved file below from the start",
		"The script then writes its own alert, `alert: exit 1: the version id in PATH is no longer in the configuration audit log`, in which `PATH` is the path of the baseline file, and a second line that says how to re-baseline",
		"The invariants file and its directory must be owned by the user who runs the check and writable by no one else. A missing file or a symlink is `config_invalid`, and a file writable by the group or by others is `config_unsafe`; both exit 6, and nothing is sent. Another key, a syntax error or a pseudonym marker is an invalid result (exit 2), and nothing is sent.",
		"Any other exit 1 (the API, or an `unknown` answer) is `fail: tailkeeper exited 1`.",
		"A failed invariant test exits 9.",
		"A name the test uses that does not resolve exits 2 (`unresolved`), which is also the exit for an invalid policy and for a refused command.",
		"Exit 9 is a failed test of the policy or of the invariants; it is not exit 2.",
		"`Persistent=true` runs a check that was missed because the machine was off, once it is back.",
		"The unit file has no URL.",
	} {
		if !strings.Contains(text, s) {
			t.Fatalf("the baseline does not say %q", s)
		}
	}
	if strings.Contains(text, "YESTERDAY") || strings.Contains(text, "Redirect that stdout") {
		t.Fatal("the recipe still names the file of the previous policy or a redirect of acl get")
	}
	if !strings.Contains(plist[0], "<!-- launchd does not expand $HOME or ~") || !strings.Contains(text, "**launchd does not expand `$HOME` or `~` in a plist string.**") {
		t.Fatal("the recipe does not say, at the plist, that launchd does not expand $HOME or ~")
	}
	// The timer keeps Persistent=true; no unit or plist holds a URL or the ping variable's value;
	// the service reads the ping from the environment file; and the plist's Label is the one
	// the launchctl lines load and remove.
	for _, body := range fenced(text, "ini") {
		if strings.Contains(body, "[Timer]") && !hasLine(body, "Persistent=true") {
			t.Error("the timer does not keep Persistent=true")
		}
		if strings.Contains(body, "://") || strings.Contains(body, "http") {
			t.Errorf("a unit file holds a URL:\n%s", body)
		}
		if strings.Contains(body, "[Service]") {
			if !hasLine(body, "EnvironmentFile=%h/.config/tailkeeper/deadman.env") {
				t.Error("the service does not read the ping from EnvironmentFile=%h/.config/tailkeeper/deadman.env")
			}
			if strings.Contains(body, "DEADMAN_URL") {
				t.Errorf("the service unit names DEADMAN_URL; the environment file holds it:\n%s", body)
			}
		}
	}
	if strings.Contains(plist[0], "://") || strings.Contains(plist[0], "DEADMAN_URL") {
		t.Error("the plist holds a URL or the ping variable")
	}
	label := regexp.MustCompile(`<key>Label</key>\s*<string>([^<]+)</string>`).FindStringSubmatch(plist[0])
	if label == nil {
		t.Fatal("the plist has no Label")
	}
	for _, want := range []string{
		"The plist is `~/Library/LaunchAgents/" + label[1] + ".plist`.",
		"`launchctl bootstrap gui/$UID $HOME/Library/LaunchAgents/" + label[1] + ".plist` loads it.",
		"`launchctl bootout gui/$UID/" + label[1] + "` removes it.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the plist's Label is %s, and the recipe does not say %q", label[1], want)
		}
	}
	if home := "/" + "Users/"; strings.Contains(text, home) {
		t.Fatalf("the recipe names %s", home)
	}
	if strings.Contains(text, "prints nothing on exit 0, stdout or stderr") {
		t.Fatal("the recipe says --quiet prints nothing on stderr")
	}
	if !strings.Contains(text, "this read was not audited") || !strings.Contains(text, "including on exit 0") {
		t.Fatal("the recipe does not say the audit warning is still written on exit 0")
	}
}

// armExits reports whether an arm has a line of its own that exits with the code: a message
// that says "exit 5" is not an exit.
func armExits(body, code string) bool {
	want := "exit " + code
	if code == "*" {
		want = `exit "$code"`
	}
	for _, line := range strings.Split(body, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

func armSays(body, prefix string) bool {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), `echo "`+prefix+`: `) {
			return true
		}
	}
	return false
}

func cronCheckScript(t *testing.T) string {
	t.Helper()
	var script string
	for _, sh := range fenced(cronRecipe(t), "sh") {
		if strings.Contains(sh, "audit verify") {
			script = sh
		}
	}
	if script == "" {
		t.Fatal("no shell fence runs audit verify")
	}
	return script
}

func TestTheCronRecipeTreatsExitsFiveAndSevenAsAlerts(t *testing.T) {
	arms := exitArms(cronCheckScript(t))
	for _, code := range []string{"0", "2", "5", "7", "8", "9", "*"} {
		if _, ok := arms[code]; !ok {
			t.Fatalf("case has no %s arm: %v", code, arms)
		}
	}
	for _, line := range strings.Split(arms["0"], "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "exit") {
			t.Fatalf("exit 0 is not success: %q", arms["0"])
		}
	}
	for code, body := range arms {
		if code != "0" && !armExits(body, code) {
			t.Fatalf("arm %s has no line of its own that exits %s: %q", code, code, body)
		}
	}
	for _, code := range []string{"5", "7"} {
		if !armSays(arms[code], "alert") {
			t.Fatalf("exit %s is not its own alert: %q", code, arms[code])
		}
	}
	// Exit 1 is two things: an expired baseline is an alert, any other exit 1 a failure.
	if !armSays(arms["1"], "alert") || !armSays(arms["1"], "fail") || !strings.Contains(arms["1"], "grep -qF 'the log no longer holds this version' \"$errs\"") {
		t.Fatalf("exit 1 does not tell an expired baseline (an alert) from any other exit 1 (a failure): %q", arms["1"])
	}
	for _, code := range []string{"2", "8", "9", "*"} {
		if !armSays(arms[code], "fail") {
			t.Fatalf("exit %s does not say it fails the run: %q", code, arms[code])
		}
	}
}

// writeStub writes an executable shell stand-in.
func writeStub(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o700); err != nil { //nolint:gosec // G306: an executable stand-in in a test directory
		t.Fatal(err)
	}
	return p
}

// The check script is run, with a stand-in tailkeeper that exits with the code the case sets
// for each of its three commands, and a stand-in curl. The dead-man ping happens only when all
// three exit 0; every other code ends the run with that code, and nothing reaches the ping.
func TestTheCronScriptExitsWithTheCodeOfTheFailingCommandAndPingsOnlyOnSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the recipe is a POSIX shell script")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "check.sh")
	if err := os.WriteFile(script, []byte(cronCheckScript(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	tk := writeStub(t, dir, "tk", `echo "$*" >> "$STUB_ARGV"
case "$1 $2" in
  "acl validate") exit "${STUB_VALIDATE:-0}" ;;
  "acl diff") [ -z "$STUB_DIFF_ERR" ] || echo "$STUB_DIFF_ERR" >&2; exit "${STUB_DIFF:-0}" ;;
  "audit verify") exit "${STUB_AUDIT:-0}" ;;
esac
exit 99
`)
	writeStub(t, dir, "curl", `echo "$*" >> "$STUB_ARGV"
cat > "$STUB_PING"
exit 0
`)
	baseline := filepath.Join(dir, "baseline-version")
	if err := os.WriteFile(baseline, []byte("v1.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const url = "https://ping.example.com/not-a-secret-but-never-an-argument"
	run := func(stubs ...string) (code int, stderr string, argv, ping string) {
		t.Helper()
		argvFile, pingFile := filepath.Join(dir, "argv"), filepath.Join(dir, "ping")
		_ = os.Remove(argvFile)
		_ = os.Remove(pingFile)
		cmd := exec.Command("/bin/sh", script)
		cmd.Env = append([]string{"PATH=" + dir + ":/usr/bin:/bin", "TAILKEEPER=" + tk, "BASELINE_FILE=" + baseline, "DEADMAN_URL=" + url,
			"STUB_ARGV=" + argvFile, "STUB_PING=" + pingFile}, stubs...)
		var errb strings.Builder
		cmd.Stderr = &errb
		err := cmd.Run()
		a, _ := os.ReadFile(argvFile) //nolint:gosec // G304: a file in the test directory
		p, _ := os.ReadFile(pingFile) //nolint:gosec // G304: as above
		return exitCode(err), errb.String(), string(a), string(p)
	}
	code, stderr, argv, ping := run()
	if code != 0 || stderr != "" || !strings.Contains(ping, url) {
		t.Fatalf("all commands exit 0: exit %d, stderr %q, ping config %q", code, stderr, ping)
	}
	if strings.Contains(argv, url) || strings.Contains(argv, "ping.example.com") {
		t.Fatalf("the URL reached an argument:\n%s", argv)
	}
	if !strings.Contains(argv, "acl diff --from-version v1.example --fail-on change --quiet") {
		t.Fatalf("the diff does not read the version id from the baseline file:\n%s", argv)
	}
	for _, c := range []struct {
		name  string
		stubs []string
		want  int
		said  string
	}{
		{"credential unavailable in validate", []string{"STUB_VALIDATE=5"}, 5, "alert: exit 5"},
		{"audit log unavailable", []string{"STUB_AUDIT=7"}, 7, "alert: exit 7"},
		{"audit log unavailable in diff", []string{"STUB_DIFF=7"}, 7, "alert: exit 7"},
		{"a change", []string{"STUB_DIFF=8"}, 8, "fail: exit 8"},
		{"a failed invariant", []string{"STUB_VALIDATE=9"}, 9, "fail: exit 9"},
		{"a refused command", []string{"STUB_VALIDATE=2"}, 2, "fail: exit 2"},
		{"the API or an unknown", []string{"STUB_DIFF=1"}, 1, "tailkeeper exited 1"},
		{"a configuration error", []string{"STUB_AUDIT=6"}, 6, "tailkeeper exited 6"},
		{"any other code", []string{"STUB_VALIDATE=3"}, 3, "tailkeeper exited 3"},
	} {
		code, stderr, _, ping := run(c.stubs...)
		if code != c.want || !strings.Contains(stderr, c.said) {
			t.Errorf("%s: exit %d, stderr %q; want exit %d and %q", c.name, code, stderr, c.want, c.said)
		}
		if ping != "" {
			t.Errorf("%s: the dead-man ping ran", c.name)
		}
	}
	// An expired baseline is its own alert, which says how to re-baseline; the command's own
	// message is still shown. Any other exit 1 is not that alert.
	const gone = "tailkeeper: not_found: the log no longer holds this version"
	code, stderr, _, ping = run("STUB_DIFF=1", "STUB_DIFF_ERR="+gone)
	for _, want := range []string{gone, "alert: exit 1: the version id in " + baseline + " is no longer in the configuration audit log", "alert: re-baseline: write the newest VERSION of acl history to " + baseline} {
		if !strings.Contains(stderr, want) {
			t.Errorf("an expired baseline: stderr %q lacks %q", stderr, want)
		}
	}
	// The alert the recipe quotes is the one the script prints, with the file's path where the
	// recipe writes PATH.
	const quoted = "alert: exit 1: the version id in PATH is no longer in the configuration audit log"
	if !strings.Contains(cronRecipe(t), "`"+quoted+"`") || !strings.Contains(strings.ReplaceAll(stderr, baseline, "PATH"), quoted) {
		t.Errorf("the alert the recipe quotes (%q) is not the one the script prints:\n%s", quoted, stderr)
	}
	if code != 1 || ping != "" {
		t.Errorf("an expired baseline: exit %d, ping %q; want exit 1 and no ping", code, ping)
	}
	code, stderr, _, ping = run("STUB_DIFF=1", "STUB_DIFF_ERR=tailkeeper: api_error: the API answered 500")
	if code != 1 || ping != "" || strings.Contains(stderr, "alert:") || !strings.Contains(stderr, "fail: tailkeeper exited 1") || !strings.Contains(stderr, "the API answered 500") {
		t.Errorf("another exit 1: exit %d, ping %q, stderr %q; want a fail line, the command's message and no alert", code, ping, stderr)
	}
	// A failing command ends the run before the commands after it.
	if _, _, argv, _ := run("STUB_VALIDATE=5"); strings.Contains(argv, "acl diff") || strings.Contains(argv, "audit verify") {
		t.Errorf("a failed validate went on:\n%s", argv)
	}
	// A baseline file with no version id fails before any command, and does not ping.
	if err := os.WriteFile(baseline, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code, stderr, argv, ping = run()
	if code != 1 || !strings.Contains(stderr, "holds no version id") || argv != "" || ping != "" {
		t.Errorf("an empty baseline: exit %d, stderr %q, argv %q, ping %q", code, stderr, argv, ping)
	}
	if err := os.Remove(baseline); err != nil {
		t.Fatal(err)
	}
	code, stderr, argv, ping = run()
	if code != 1 || !strings.Contains(stderr, "holds no version id") || argv != "" || ping != "" {
		t.Errorf("a missing baseline: exit %d, stderr %q, argv %q, ping %q", code, stderr, argv, ping)
	}
}

func TestTheCronRecipePingsADeadManWithNoSecretInArgv(t *testing.T) {
	text := cronRecipe(t)
	shells := fenced(text, "sh")
	all := shellJoined(t, text)
	if !strings.Contains(all, `"$DEADMAN_URL"`) {
		t.Fatal("the ping does not use \"$DEADMAN_URL\"")
	}
	if strings.Contains(all, "http://") || strings.Contains(all, "https://") {
		t.Fatal("a shell fence has a URL literal")
	}
	if !strings.Contains(text, "DEADMAN_URL is not printed") {
		t.Fatal("the file does not say DEADMAN_URL is not printed")
	}
	for _, sh := range shells {
		for _, line := range strings.Split(sh, "\n") {
			if strings.Contains(line, "curl") && strings.Contains(line, "DEADMAN_URL") {
				t.Fatalf("curl's command line names DEADMAN_URL: %s", line)
			}
		}
	}
	for _, banned := range []string{"tskey-", "CLIENT_SECRET", "client_secret"} {
		if strings.Contains(text, banned) {
			t.Fatalf("the recipe holds %s", banned)
		}
	}
}

func TestTheCronRecipeUsesQuietAndFailOnChange(t *testing.T) {
	var validate, diff string
	for _, line := range strings.Split(cronCheckScript(t), "\n") {
		switch {
		case strings.Contains(line, "acl validate"):
			validate = line
		case strings.Contains(line, "acl diff"):
			diff = line
		}
	}
	if validate == "" || !strings.Contains(validate, "--quiet") || strings.Contains(validate, "--from") {
		t.Fatalf("validate = %q", validate)
	}
	want := `run "$TAILKEEPER" acl diff --from-version "$version" --fail-on change --quiet`
	if diff != want {
		t.Fatalf("diff = %q, want %q", diff, want)
	}
}

func TestTheCronRecipeSaysTheHashChangesOnKeyRotation(t *testing.T) {
	text := cronRecipe(t)
	if !strings.Contains(text, "policySha256") || !strings.Contains(text, "changes when the privacy key is replaced") {
		t.Fatal("the file does not say policySha256 changes when the privacy key is replaced")
	}
	if !strings.Contains(text, "checkedAt") {
		t.Fatal("checkedAt is not named")
	}
}

// A fence tag the extractor does not know is an error that names the markdown file and the
// line the fence opens at, and writes nothing: yml, shell, zsh and a misspelling would
// otherwise be skipped, and a broken workflow in them would be linted by nobody.
func TestAFenceTagTheExtractorDoesNotKnowFailsAndNamesItsLine(t *testing.T) {
	for _, tag := range []string{"yml", "shell", "zsh", "YAML", "bash-session"} {
		dir := t.TempDir()
		writeRecipe(t, dir, "tags.md", "text\n\n```sh\necho ok\n```\n\n```"+tag+"\nname: x\n```\n")
		dest := filepath.Join(dir, "out")
		out, code := runRecipes(t, dir, dest)
		if code != 1 {
			t.Errorf("tag %s: exit %d, want 1\n%s", tag, code, out)
		}
		if !strings.Contains(out, "docs/recipes/tags.md:7: fence tag \""+tag+"\" is not one the extractor knows") {
			t.Errorf("tag %s: output does not name the file and line:\n%s", tag, out)
		}
		if _, err := os.Stat(dest); !os.IsNotExist(err) {
			t.Errorf("tag %s: the extractor wrote %v", tag, filesUnder(t, dest))
		}
	}
}

// stubToolbox is a directory of stand-ins for the tools make actionlint calls. The go stand-in
// runs the real extractor and answers for actionlint; shellcheck is a stand-in too. What each
// does is set by environment variables of the run.
func stubToolbox(t *testing.T, withShellcheck bool) (dir, goStub string) {
	t.Helper()
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go on PATH")
	}
	dir = t.TempDir()
	goStub = filepath.Join(dir, "gostub")
	script := "#!/bin/sh\n" +
		"case \"$*\" in\n" +
		"  *scripts/recipes.go*)\n" +
		"    if [ -n \"$STUB_EXTRACT_FAILS\" ]; then echo 'stub: the extractor fails' >&2; exit 3; fi\n" +
		"    exec " + realGo + " \"$@\" ;;\n" +
		"  *rhysd/actionlint*)\n" +
		"    # The call with files is the extracted workflows; the call without is the repository's own.\n" +
		"    if [ \"$#\" -gt 2 ] && [ -n \"$STUB_LINT_EXTRACTED_FAILS\" ]; then echo 'stub: actionlint rejects the extracted workflow' >&2; exit 4; fi\n" +
		"    exit 0 ;;\n" +
		"esac\n" +
		"echo \"gostub: unexpected $*\" >&2\n" +
		"exit 99\n"
	if err := os.WriteFile(goStub, []byte(script), 0o700); err != nil { //nolint:gosec // G306: an executable stand-in in a test directory
		t.Fatal(err)
	}
	if withShellcheck {
		sc := "#!/bin/sh\n" +
			"case \"$1\" in\n" +
			"  --version) echo 'stub shellcheck'; exit 0 ;;\n" +
			"  /*) if [ -n \"$STUB_SHELLCHECK_EXTRACTED_FAILS\" ]; then echo 'stub: shellcheck rejects the extracted script' >&2; exit 5; fi ;;\n" +
			"esac\n" +
			"exit 0\n"
		if err := os.WriteFile(filepath.Join(dir, "shellcheck"), []byte(sc), 0o700); err != nil { //nolint:gosec // G306: as above
			t.Fatal(err)
		}
	}
	return dir, goStub
}

// runActionlintTarget runs the real Makefile's actionlint target with the stand-ins, in the
// repository root, and returns its exit code and output.
func runActionlintTarget(t *testing.T, withShellcheck bool, env ...string) (string, int) {
	t.Helper()
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("no make on PATH")
	}
	dir, goStub := stubToolbox(t, withShellcheck)
	cmd := exec.Command("make", "-f", "Makefile", "actionlint", "GO="+goStub)
	cmd.Dir = repoRoot(t)
	var kept []string
	for _, kv := range os.Environ() {
		// A parent make's flags would reach this one; the run is its own.
		if strings.HasPrefix(kv, "MAKEFLAGS=") || strings.HasPrefix(kv, "MFLAGS=") || strings.HasPrefix(kv, "PATH=") || strings.HasPrefix(kv, "STUB_") {
			continue
		}
		kept = append(kept, kv)
	}
	cmd.Env = append(append(kept, "PATH="+dir+":/usr/bin:/bin"), env...)
	out, err := cmd.CombinedOutput()
	return string(out), exitCode(err)
}

// The target fails when the extractor fails, when actionlint rejects an extracted workflow,
// when shellcheck rejects an extracted script, and when shellcheck is missing; and it passes
// when all of them pass. Each line of the target that must stop the run is run, not read.
func TestTheActionlintTargetFailsWhenAnyCheckOfTheRecipesFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Makefile needs a POSIX shell")
	}
	if out, code := runActionlintTarget(t, true); code != 0 || !strings.Contains(out, "stub shellcheck") {
		t.Fatalf("with every check passing: exit %d, want 0\n%s", code, out)
	}
	for _, c := range []struct {
		name  string
		shell bool
		env   string
		want  string
	}{
		{"the extractor fails", true, "STUB_EXTRACT_FAILS=1", "stub: the extractor fails"},
		{"actionlint rejects an extracted workflow", true, "STUB_LINT_EXTRACTED_FAILS=1", "stub: actionlint rejects the extracted workflow"},
		{"shellcheck rejects an extracted script", true, "STUB_SHELLCHECK_EXTRACTED_FAILS=1", "stub: shellcheck rejects the extracted script"},
		{"shellcheck is missing", false, "STUB_NOTHING=1", "actionlint needs shellcheck on PATH"},
	} {
		out, code := runActionlintTarget(t, c.shell, c.env)
		if code == 0 {
			t.Errorf("%s: the target exited 0\n%s", c.name, out)
		}
		if !strings.Contains(out, c.want) {
			t.Errorf("%s: output lacks %q:\n%s", c.name, c.want, out)
		}
	}
}

// stepScript returns the shell of the named step's run: block of the job, as the runner
// hands it to bash (the YAML parser has removed the block's indent).
func stepScript(t *testing.T, job, name string) string {
	t.Helper()
	s := stepOf(t, job, name)
	if s.Run == "" {
		t.Fatalf("step %s of job %s has no run: block", name, job)
	}
	return s.Run
}

// ran is the outcome of a step's shell.
type ran struct {
	code           int
	stdout, stderr string
}

// stepRunScript runs a script under bash -e in dir, with PATH set to dir/bin and the system
// directories, and the given environment (a later PATH wins). The script is written to a
// file outside dir/bin.
func stepRunScript(t *testing.T, dir, script string, env ...string) ran {
	t.Helper()
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("no /bin/bash")
	}
	file := filepath.Join(t.TempDir(), "step.sh")
	if err := os.WriteFile(file, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", "-e", file)
	cmd.Dir = dir
	cmd.Env = append([]string{"PATH=" + filepath.Join(dir, "bin") + ":/usr/bin:/bin", "HOME=" + dir}, env...)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	return ran{exitCode(cmd.Run()), out.String(), errb.String()}
}

func stepRun(t *testing.T, dir, job, name string, env ...string) ran {
	t.Helper()
	return stepRunScript(t, dir, stepScript(t, job, name), env...)
}

func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the step is a bash script")
	}
}

func readOrEmpty(path string) string {
	b, _ := os.ReadFile(path) //nolint:gosec // G304: a file in the test directory
	return string(b)
}

// verifyResult is a run of the Verify step in a workspace that holds a link named like a
// download.
type verifyResult struct {
	ran
	calls     string
	installed bool
	workspace string
	victim    string
}

// runVerify runs the Verify step of the job with stand-ins for curl, cosign, the checksum
// tool, gh and tar. With shasumOnly, PATH holds links to the few real tools the step needs and
// no sha256sum, so that the step takes its shasum fallback.
func runVerify(t *testing.T, job string, shasumOnly bool, env ...string) verifyResult {
	t.Helper()
	const archive = "tailkeeper_0.6.0_linux_amd64.tar.gz"
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	tmp := filepath.Join(dir, "tmp")
	for _, d := range []string{bin, filepath.Join(tmp, "tailkeeper")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// The workspace holds the pull request's files. A link there named like a download must
	// not carry a download to another file.
	victim := filepath.Join(t.TempDir(), "checksums.txt")
	if err := os.WriteFile(victim, []byte("TRUSTED\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, "checksums.txt")); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "calls")
	writeStub(t, bin, "curl", `echo "curl" >> "$STUB_LOG"
out=""; while [ $# -gt 0 ]; do if [ "$1" = "-o" ]; then out="$2"; fi; shift; done
case "$out" in
  */checksums.txt|checksums.txt) if [ -z "$STUB_NO_CHECKSUM_LINE" ]; then echo "abc  `+archive+`" > "$out"; else echo "abc  other.tar.gz" > "$out"; fi ;;
  *) echo x > "$out" ;;
esac
`)
	writeStub(t, bin, "cosign", `echo "cosign" >> "$STUB_LOG"
[ -z "$STUB_FAIL_COSIGN" ] || exit 1
`)
	checksum := "sha256sum"
	if shasumOnly {
		checksum = "shasum"
		for _, tool := range []string{"awk", "install", "rm", "cat"} {
			p, err := exec.LookPath(tool)
			if err != nil {
				t.Skip("no " + tool + " on PATH")
			}
			if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
				t.Fatal(err)
			}
		}
		env = append(env, "PATH="+bin)
	}
	writeStub(t, bin, checksum, `echo "`+checksum+`" >> "$STUB_LOG"
cat > /dev/null
[ -z "$STUB_FAIL_SHA" ] || exit 1
`)
	writeStub(t, bin, "gh", `echo "gh $3" >> "$STUB_LOG"
case "$3" in
  checksums.txt) [ -z "$STUB_FAIL_GH_CHECKSUMS" ] || exit 1 ;;
  *) [ -z "$STUB_FAIL_GH_ARCHIVE" ] || exit 1 ;;
esac
`)
	writeStub(t, bin, "tar", `echo "tar" >> "$STUB_LOG"
echo bin > tailkeeper
`)
	r := stepRun(t, dir, job, "Verify the release", append([]string{"RUNNER_TEMP=" + tmp, "GH_TOKEN=x", "STUB_LOG=" + log}, env...)...)
	_, err := os.Stat(filepath.Join(tmp, "tailkeeper", "tailkeeper"))
	return verifyResult{ran: r, calls: readOrEmpty(log), installed: err == nil, workspace: dir, victim: victim}
}

// The Verify step is run with stand-ins. Each check that must stop the job is made to fail in
// turn, and the binary is not installed. Everything it downloads goes to the runner's
// temporary directory: the workspace holds the pull request's files, and a link in it named
// like a download would carry the download elsewhere.
func TestTheVerifyStepStopsBeforeInstallingWhenAnyCheckFails(t *testing.T) {
	skipOnWindows(t)
	const archive = "tailkeeper_0.6.0_linux_amd64.tar.gz"
	for _, job := range recipeJobNames {
		r := runVerify(t, job, false)
		if r.code != 0 || !r.installed {
			t.Fatalf("job %s, every check passes: exit %d, installed %v\n%s\n%s", job, r.code, r.installed, r.stderr, r.calls)
		}
		if want := "curl\ncurl\ncurl\ncosign\nsha256sum\ngh " + archive + "\ngh checksums.txt\ntar\n"; r.calls != want {
			t.Fatalf("job %s: the checks ran as\n%s\nwant\n%s", job, r.calls, want)
		}
		if _, err := os.Stat(filepath.Join(r.workspace, "tmp", "tailkeeper", "download")); !os.IsNotExist(err) {
			t.Errorf("job %s: the download directory is left behind", job)
		}
		for _, c := range []struct {
			name, env string
			stop      string
		}{
			{"cosign fails", "STUB_FAIL_COSIGN=1", "cosign"},
			{"the checksum does not match", "STUB_FAIL_SHA=1", "sha256sum"},
			{"checksums.txt has no line for the archive", "STUB_NO_CHECKSUM_LINE=1", "cosign"},
			{"the attestation of the archive fails", "STUB_FAIL_GH_ARCHIVE=1", "gh " + archive},
			{"the attestation of checksums.txt fails", "STUB_FAIL_GH_CHECKSUMS=1", "gh checksums.txt"},
		} {
			r := runVerify(t, job, false, c.env)
			if r.code == 0 || r.installed || strings.Contains("\n"+r.calls, "\ntar\n") {
				t.Errorf("job %s, %s: exit %d, installed %v\n%s", job, c.name, r.code, r.installed, r.calls)
			}
			if !strings.HasSuffix(strings.TrimSpace(r.calls), c.stop) {
				t.Errorf("job %s, %s: the run did not stop at %q:\n%s", job, c.name, c.stop, r.calls)
			}
		}
	}
}

// With no sha256sum on PATH the step uses shasum, and a mismatch there stops the job too.
func TestTheVerifyStepFallsBackToShasumAndStopsOnItsFailure(t *testing.T) {
	skipOnWindows(t)
	for _, job := range recipeJobNames {
		r := runVerify(t, job, true)
		if r.code != 0 || !r.installed || !strings.Contains(r.calls, "\nshasum\n") || strings.Contains(r.calls, "sha256sum") {
			t.Fatalf("job %s, shasum passes: exit %d, installed %v\n%s\n%s", job, r.code, r.installed, r.stderr, r.calls)
		}
		r = runVerify(t, job, true, "STUB_FAIL_SHA=1")
		if r.code == 0 || r.installed || strings.Contains("\n"+r.calls, "\ntar\n") {
			t.Errorf("job %s, shasum fails: exit %d, installed %v\n%s", job, r.code, r.installed, r.calls)
		}
	}
}

func TestTheVerifyStepWritesNothingIntoTheWorkspace(t *testing.T) {
	skipOnWindows(t)
	for _, job := range recipeJobNames {
		r := runVerify(t, job, false)
		if got := readOrEmpty(r.victim); got != "TRUSTED\n" {
			t.Errorf("job %s: a download was written through a link in the workspace: %q", job, got)
		}
		entries, err := os.ReadDir(r.workspace)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			switch e.Name() {
			case "bin", "tmp", "calls", "checksums.txt":
			default:
				t.Errorf("job %s: the step left %s in the workspace", job, e.Name())
			}
		}
		if fi, err := os.Lstat(filepath.Join(r.workspace, "checksums.txt")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("job %s: the link in the workspace was replaced", job)
		}
		// A failed run leaves nothing there either.
		r = runVerify(t, job, false, "STUB_FAIL_COSIGN=1")
		if got := readOrEmpty(r.victim); got != "TRUSTED\n" {
			t.Errorf("job %s, a failed run: a download was written through a link: %q", job, got)
		}
	}
}

// checkRun is a run of a job's Check step.
type checkRun struct {
	ran
	argv       []string
	exitFile   string
	conf       []byte
	hasConf    bool
	confMode   os.FileMode
	tmp, inv   string
	basePolicy string
}

// runCheck runs the Check step of the job with a stand-in tailkeeper, in a workspace that
// holds policy.hujson. The path the live step tests for a system configuration is replaced
// by one in the test directory, which exists only when etc is true: no test depends on, or
// touches, /etc.
func runCheck(t *testing.T, job string, etc bool, env ...string) checkRun {
	t.Helper()
	dir := t.TempDir()
	tmp := filepath.Join(dir, "tmp")
	for _, d := range []string{filepath.Join(dir, "bin"), filepath.Join(tmp, "tailkeeper"), filepath.Join(tmp, "config", "tailkeeper")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	inv := filepath.Join(tmp, "tailkeeper", "invariants.hujson")
	basePolicy := filepath.Join(tmp, "tailkeeper", "policy.hujson")
	for _, f := range []string{filepath.Join(dir, "policy.hujson"), inv, basePolicy} {
		if err := os.WriteFile(f, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := stepScript(t, job, "Check the policy")
	if job == "live" {
		const probe = "[ -e /etc/tailkeeper/config.hujson ]"
		if strings.Count(script, probe) != 1 {
			t.Fatalf("the live Check step does not test %q exactly once", probe)
		}
		system := filepath.Join(dir, "etc-config.hujson")
		if etc {
			if err := os.WriteFile(system, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		script = strings.Replace(script, probe, "[ -e "+system+" ]", 1)
	}
	log := filepath.Join(dir, "argv")
	writeStub(t, filepath.Join(tmp, "tailkeeper"), "tailkeeper", `echo "$*" >> "$STUB_LOG"
case "$1 $2" in
  "acl validate") exit "${STUB_VALIDATE:-0}" ;;
  "acl diff") exit "${STUB_DIFF:-0}" ;;
esac
exit 99
`)
	r := stepRunScript(t, dir, script, append([]string{
		"RUNNER_TEMP=" + tmp, "XDG_CONFIG_HOME=" + filepath.Join(tmp, "config"), "XDG_STATE_HOME=" + filepath.Join(tmp, "state"),
		"STUB_LOG=" + log}, env...)...)
	out := checkRun{ran: r, exitFile: strings.TrimSpace(readOrEmpty(filepath.Join(tmp, "tailkeeper", "exit"))), tmp: tmp, inv: inv, basePolicy: basePolicy}
	for _, line := range strings.Split(strings.TrimSpace(readOrEmpty(log)), "\n") {
		if line != "" {
			out.argv = append(out.argv, line)
		}
	}
	conf := filepath.Join(tmp, "config", "tailkeeper", "config.hujson")
	if fi, err := os.Stat(conf); err == nil {
		out.hasConf, out.confMode = true, fi.Mode().Perm()
		out.conf = []byte(readOrEmpty(conf))
	}
	return out
}

const (
	fixtureTailnet = "T1234CNTRL"
	fixtureClient  = "kFED1CNTRL"
)

func liveIDs() []string {
	return []string{"TAILNET_ID=" + fixtureTailnet, "OIDC_CLIENT_ID=" + fixtureClient}
}

// The live Check step writes the configuration the binary loads and runs the two commands
// with the flags that make them gates. The configuration is parsed by the real loader.
func TestTheLiveCheckStepWritesTheConfigurationAndRunsTheGatesWithTheirFlags(t *testing.T) {
	skipOnWindows(t)
	r := runCheck(t, "live", false, liveIDs()...)
	if r.code != 0 || r.exitFile != "0" {
		t.Fatalf("exit %d, exit file %q\n%s", r.code, r.exitFile, r.stderr)
	}
	want := []string{
		"acl validate --from policy.hujson --invariants " + r.inv + " --fail-on warnings,change --format github",
		"acl diff --offline --against " + r.basePolicy + " --from policy.hujson --fail-on change --format github",
	}
	if strings.Join(r.argv, "\n") != strings.Join(want, "\n") {
		t.Errorf("the commands are\n%s\nwant\n%s", strings.Join(r.argv, "\n"), strings.Join(want, "\n"))
	}
	if !r.hasConf || r.confMode != 0o600 {
		t.Fatalf("configuration written %v with mode %o, want mode 600", r.hasConf, r.confMode)
	}
	cfg, err := config.Parse(r.conf)
	if err != nil {
		t.Fatalf("the written configuration does not load: %v\n%s", err, r.conf)
	}
	ctx := cfg.Contexts["ci"]
	p := ctx.Credentials.Read
	if cfg.PersonalData != config.PersonalDataMask || cfg.DefaultContext != "ci" || len(cfg.Contexts) != 1 {
		t.Errorf("personalData %q, defaultContext %q, %d contexts", cfg.PersonalData, cfg.DefaultContext, len(cfg.Contexts))
	}
	if ctx.TailnetID != fixtureTailnet || p.Provider != "oidc" || p.ClientID != fixtureClient || p.TokenFile != "" || p.Audience != "" || p.Path != "" || len(p.Command) != 0 {
		t.Errorf("the context is %#v", ctx)
	}
	if cfg.ACL.InvariantsFile != r.inv || cfg.ACL.ValidatePerMinute == nil || *cfg.ACL.ValidatePerMinute != 30 {
		t.Errorf("acl is %#v", cfg.ACL)
	}
	if _, err := os.Stat(filepath.Join(r.tmp, "tailkeeper", "oidc-token")); err == nil {
		t.Error("a token file was written")
	}
	for _, id := range []string{fixtureTailnet, fixtureClient} {
		if strings.Contains(r.stdout+r.stderr, id) {
			t.Errorf("the step printed an identifier: %q", id)
		}
	}
}

// The exit file holds the validate command's exit when that is not 0, and otherwise the diff's.
func TestTheCheckStepsRecordTheValidateExitThenTheDiffExit(t *testing.T) {
	skipOnWindows(t)
	for _, job := range recipeJobNames {
		for _, c := range []struct {
			validate, diff string
			want           string
		}{
			{"0", "0", "0"}, {"0", "8", "8"}, {"9", "0", "9"}, {"9", "8", "9"}, {"1", "0", "1"}, {"2", "8", "2"}, {"3", "0", "3"}, {"0", "1", "1"},
		} {
			env := []string{"STUB_VALIDATE=" + c.validate, "STUB_DIFF=" + c.diff}
			if job == "live" {
				env = append(env, liveIDs()...)
			}
			r := runCheck(t, job, false, env...)
			if r.code != 0 || r.exitFile != c.want {
				t.Errorf("job %s, validate %s, diff %s: step exit %d, exit file %q, want %s\n%s", job, c.validate, c.diff, r.code, r.exitFile, c.want, r.stderr)
			}
			if len(r.argv) != 2 {
				t.Errorf("job %s: %d commands ran, want validate and diff:\n%v", job, len(r.argv), r.argv)
			}
		}
	}
}

// A missing or odd id stops before any call, exits 5 or 6 in the file, writes no
// configuration and never echoes the id; the diff of two files, which needs no credential, still runs.
func TestTheLiveCheckStepStopsWithoutAnIdAndRefusesAnOddOne(t *testing.T) {
	skipOnWindows(t)
	for _, c := range []struct {
		name string
		env  []string
		exit string
		say  string
	}{
		{"no client id", []string{"OIDC_CLIENT_ID=", "TAILNET_ID=" + fixtureTailnet}, "5", "OIDC_CLIENT_ID is not set"},
		{"no tailnet id", []string{"OIDC_CLIENT_ID=" + fixtureClient, "TAILNET_ID="}, "5", "TAILKEEPER_TAILNET_ID is not set"},
		{"a quote in the client id", []string{`OIDC_CLIENT_ID=a"b`, "TAILNET_ID=" + fixtureTailnet}, "6", "not a plain identifier"},
		{"a space in the tailnet id", []string{"OIDC_CLIENT_ID=" + fixtureClient, "TAILNET_ID=x y"}, "6", "not a plain identifier"},
		{"a command substitution in the tailnet id", []string{"OIDC_CLIENT_ID=" + fixtureClient, "TAILNET_ID=$(touch pwned)"}, "6", "not a plain identifier"},
		{"a newline in the client id", []string{"OIDC_CLIENT_ID=a\nb", "TAILNET_ID=" + fixtureTailnet}, "6", "not a plain identifier"},
	} {
		r := runCheck(t, "live", false, c.env...)
		if r.code != 0 || r.exitFile != c.exit || !strings.Contains(r.stderr, c.say) {
			t.Errorf("%s: exit %d, exit file %q, stderr %q; want the file %s and %q", c.name, r.code, r.exitFile, r.stderr, c.exit, c.say)
		}
		if r.hasConf {
			t.Errorf("%s: a configuration was written:\n%s", c.name, r.conf)
		}
		for _, line := range r.argv {
			if strings.HasPrefix(line, "acl validate") {
				t.Errorf("%s: validate ran", c.name)
			}
		}
		if len(r.argv) != 1 || !strings.HasPrefix(r.argv[0], "acl diff --offline") {
			t.Errorf("%s: the commands are %v, want the offline diff only", c.name, r.argv)
		}
		for _, bad := range []string{`a"b`, "x y", "touch pwned"} {
			if strings.Contains(r.stdout+r.stderr, bad) {
				t.Errorf("%s: the step echoed the id: %q", c.name, bad)
			}
		}
	}
}

// A configuration in /etc/tailkeeper wins over the one the job writes. The step stops with
// exit 6 in the file, runs nothing, writes nothing; the last step turns that into a failure.
func TestTheLiveCheckStepRefusesASystemConfigurationWithExitSix(t *testing.T) {
	skipOnWindows(t)
	r := runCheck(t, "live", true, liveIDs()...)
	if r.code != 0 || r.exitFile != "6" || len(r.argv) != 0 || r.hasConf {
		t.Fatalf("exit %d, exit file %q, commands %v, configuration written %v", r.code, r.exitFile, r.argv, r.hasConf)
	}
	if !strings.Contains(r.stderr, "tailkeeper would load /etc/tailkeeper/config.hujson and ignore the configuration this job writes") {
		t.Errorf("stderr %q", r.stderr)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "tmp", "tailkeeper"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tmp", "tailkeeper", "exit"), []byte(r.exitFile+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if e := stepRun(t, dir, "live", "Exit", "RUNNER_TEMP="+filepath.Join(dir, "tmp")); e.code != 1 || !strings.Contains(e.stderr, "exit 6 is not one this recipe handles") {
		t.Errorf("the Exit step after exit 6: exit %d, stderr %q; want 1", e.code, e.stderr)
	}
}

// The offline job reads no secret and no credential: with an empty environment it checks the
// proposal offline, without --fail-on, and writes no configuration.
func TestTheOfflineCheckStepRunsOnlyOfflineCommands(t *testing.T) {
	skipOnWindows(t)
	r := runCheck(t, "offline", false)
	if r.code != 0 || r.exitFile != "0" || r.hasConf {
		t.Fatalf("exit %d, exit file %q, configuration written %v\n%s", r.code, r.exitFile, r.hasConf, r.stderr)
	}
	want := []string{
		"acl validate --from policy.hujson --offline --invariants " + r.inv + " --format github",
		"acl diff --offline --against " + r.basePolicy + " --from policy.hujson --fail-on change --format github",
	}
	if strings.Join(r.argv, "\n") != strings.Join(want, "\n") {
		t.Errorf("the commands are\n%s\nwant\n%s", strings.Join(r.argv, "\n"), strings.Join(want, "\n"))
	}
}

// The Exit step of each job. The live job passes its recorded code through; the offline job
// never ends green: a fork's pull request has had no live check.
func TestTheExitStepMapsEachRecordedCodeAndNeverPassesAForkOnTheOfflineChecksAlone(t *testing.T) {
	skipOnWindows(t)
	run := func(job string, record *string) ran {
		dir := t.TempDir()
		tmp := filepath.Join(dir, "tmp")
		if err := os.MkdirAll(filepath.Join(tmp, "tailkeeper"), 0o700); err != nil {
			t.Fatal(err)
		}
		if record != nil {
			if err := os.WriteFile(filepath.Join(tmp, "tailkeeper", "exit"), []byte(*record+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return stepRun(t, dir, job, "Exit", "RUNNER_TEMP="+tmp)
	}
	str := func(s string) *string { return &s }
	for _, c := range []struct {
		job, record string
		want        int
	}{
		{"live", "0", 0}, {"live", "1", 1}, {"live", "2", 2}, {"live", "5", 5}, {"live", "8", 8}, {"live", "9", 9},
		{"live", "6", 1}, {"live", "7", 1}, {"live", "3", 1}, {"live", "137", 1},
		{"offline", "0", 1}, {"offline", "1", 1}, {"offline", "2", 2}, {"offline", "8", 8}, {"offline", "9", 9},
		{"offline", "5", 1}, {"offline", "6", 1}, {"offline", "137", 1},
	} {
		if r := run(c.job, str(c.record)); r.code != c.want {
			t.Errorf("job %s, recorded %s: exit %d, want %d\n%s", c.job, c.record, r.code, c.want, r.stderr)
		}
	}
	for _, job := range recipeJobNames {
		if r := run(job, nil); r.code != 1 || !strings.Contains(r.stderr, "the policy check did not finish") {
			t.Errorf("job %s, nothing recorded: exit %d, stderr %q", job, r.code, r.stderr)
		}
	}
	r := run("offline", str("0"))
	for _, s := range []string{"::error", "This pull request is from a fork", "Only the offline checks ran", "A maintainer must run the live check from a branch of this repository."} {
		if !strings.Contains(r.stderr, s) {
			t.Errorf("a fork that passed offline: stderr %q lacks %q", r.stderr, s)
		}
	}
}

// The summary step runs the commands again with --format markdown after exit 1, 2, 8 or 9.
// A validate that exits 1 must not stop the group before the diff section is written, and the
// offline job repeats the offline validate: it must not send a fork's policy to Tailscale.
func TestTheSummaryStepAppendsTheDiffAndKeepsTheOfflineJobOffline(t *testing.T) {
	skipOnWindows(t)
	for _, job := range recipeJobNames {
		for _, c := range []struct {
			record string
			runs   bool
		}{{"1", true}, {"2", true}, {"8", true}, {"9", true}, {"0", false}, {"5", false}, {"6", false}, {"7", false}} {
			dir := t.TempDir()
			tmp := filepath.Join(dir, "tmp")
			if err := os.MkdirAll(filepath.Join(tmp, "tailkeeper"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(tmp, "tailkeeper", "exit"), []byte(c.record+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(dir, "argv")
			writeStub(t, filepath.Join(tmp, "tailkeeper"), "tailkeeper", `echo "$*" >> "$STUB_LOG"
case "$1 $2" in
  "acl validate") echo VALIDATE; exit 1 ;;
  "acl diff") echo DIFF; exit 8 ;;
esac
`)
			summary := filepath.Join(dir, "summary.md")
			r := stepRun(t, dir, job, "Write the step summary", "RUNNER_TEMP="+tmp, "STUB_LOG="+log, "GITHUB_STEP_SUMMARY="+summary,
				"XDG_CONFIG_HOME="+tmp, "XDG_STATE_HOME="+tmp)
			if r.code != 0 {
				t.Fatalf("job %s, recorded %s: exit %d\n%s", job, c.record, r.code, r.stderr)
			}
			argv := strings.TrimSpace(readOrEmpty(log))
			got := readOrEmpty(summary)
			if !c.runs {
				if argv != "" || got != "" {
					t.Errorf("job %s, recorded %s: the step ran commands %q or wrote %q", job, c.record, argv, got)
				}
				continue
			}
			if !strings.Contains(got, "VALIDATE") || !strings.Contains(got, "## diff") || !strings.Contains(got, "DIFF") {
				t.Errorf("job %s, recorded %s: summary %q does not keep the diff after a failing validate", job, c.record, got)
			}
			validates := 0
			for _, line := range strings.Split(argv, "\n") {
				if strings.HasPrefix(line, "acl validate") {
					validates++
					if strings.Contains(line, "--offline") != (job == "offline") {
						t.Errorf("job %s: the summary runs %q", job, line)
					}
					if (job == "live") != strings.Contains(line, "--fail-on warnings,change") {
						t.Errorf("job %s: the summary runs %q", job, line)
					}
				}
				if strings.HasPrefix(line, "acl diff") && !strings.Contains(line, "--offline") {
					t.Errorf("job %s: the summary's diff is not offline: %q", job, line)
				}
			}
			if validates != 1 {
				t.Errorf("job %s: %d validate commands:\n%s", job, validates, argv)
			}
		}
	}
}

// The files step makes the directory 0700 and the copies 0600 (umask 077), and the first
// policy, a base commit with no policy.hujson, stops the job at the copy.
func TestTheBaseFilesStepKeepsItsModesAndFailsWhenTheBaseHasNoPolicy(t *testing.T) {
	skipOnWindows(t)
	for _, job := range recipeJobNames {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "base"), 0o700); err != nil {
			t.Fatal(err)
		}
		tmp := filepath.Join(dir, "tmp")
		env := []string{"RUNNER_TEMP=" + tmp, "XDG_CONFIG_HOME=" + filepath.Join(tmp, "config"), "XDG_STATE_HOME=" + filepath.Join(tmp, "state")}
		if err := os.WriteFile(filepath.Join(dir, "base", "invariants.hujson"), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if r := stepRun(t, dir, job, "Files from the base commit", env...); r.code == 0 {
			t.Fatalf("job %s, no base policy.hujson: the step exited 0\n%s", job, r.stderr)
		}
		if err := os.WriteFile(filepath.Join(dir, "base", "policy.hujson"), []byte("{}\n"), 0o644); err != nil { //nolint:gosec // G306: the base files may be world-readable; the step must not copy that mode
			t.Fatal(err)
		}
		if r := stepRun(t, dir, job, "Files from the base commit", env...); r.code != 0 {
			t.Fatalf("job %s, both files present: exit %d\n%s", job, r.code, r.stderr)
		}
		for path, want := range map[string]os.FileMode{
			filepath.Join(tmp, "tailkeeper"):                      0o700,
			filepath.Join(tmp, "config", "tailkeeper"):            0o700,
			filepath.Join(tmp, "state", "tailkeeper"):             0o700,
			filepath.Join(tmp, "tailkeeper", "invariants.hujson"): 0o600,
			filepath.Join(tmp, "tailkeeper", "policy.hujson"):     0o600,
		} {
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != want {
				t.Errorf("job %s: %s has mode %o, want %o", job, strings.TrimPrefix(path, dir), fi.Mode().Perm(), want)
			}
		}
	}
}

func TestTheGitHubActionsRecipeSaysWhatTheMissingEnvironmentLeavesOpen(t *testing.T) {
	file := githubActionsRecipe(t)
	for _, s := range []string{
		"The `live` job names the GitHub environment `tailkeeper-policy`",
		"only that job adds `id-token: write`",
		"Every step of the `live` job, including the pinned `actions/checkout` and `sigstore/cosign-installer` and the downloaded binary, can request the OIDC token; the SHA pins and the environment's reviewer are the controls.",
		"Do both in the settings, before the first run:",
		"1. Create the environment `tailkeeper-policy` in the repository before the first run, and add required reviewers to it. Required reviewers on an environment are available for public repositories, and for private repositories only on a paid GitHub plan; on a plan without them this step cannot be done and the environment is a name, not a gate. A workflow that names an environment that does not exist makes GitHub create it with no protection rules, so a first run without this step is ungated. Turn on \"Prevent self-review\". With one maintainer, who is also the author of every pull request, either nobody can approve a run (\"Prevent self-review\" on) or that person approves their own run (off); the gate is then that person's reading of the change to the workflow file.",
		"Set no deployment-branch rule on the environment: a pull request job runs on `refs/pull/N/merge`, which a rule for protected or named branches cannot match, so the job would not start.",
		"3. Require only the status check `tailkeeper-acl-result` in the branch protection of the base branch, and no other check of this workflow. It is the `name:` of the `result` job: branch protection matches a job's name, or its id when it has none, and this name was not checked on a runner. A job skipped by its `if` counts as a pass there.",
		"The workflow has no `paths` or `paths-ignore` on `on.pull_request`, and must not get one: a workflow that does not run never reports `tailkeeper-acl-result`, so a required check would block every pull request that does not touch the policy. Skipping work on a pull request that leaves the policy files alone is a step inside the jobs that compares each policy file with its copy in the base checkout at `base/` (`cmp`; both checkouts hold one commit, so `git diff` against the base SHA has nothing to compare with), and `result` still reports.",
		"With `tailkeeper-acl-result` required, that blocks every Dependabot pull request from merging, a dependency update included, until a maintainer lands the change another way",
		"Dependabot secrets do not help, because the `id-token` permission is still withheld.",
		"A `paths` filter on `on.pull_request` is not the fix either, because step 3 of \"Who can use the identity\" says why a required check cannot have one.",
		"Cover the whole `.github/workflows/` directory, not only this file: a pull request can add a workflow as well as edit one.",
		"Required reviewers on an environment are available for public repositories, and for private repositories only on a paid GitHub plan; on a plan without them this step cannot be done and the environment is a name, not a gate.",
		"**Guard the workflow file.** " + workflowGuardClause + " Without that, a pull request can edit `result`, or remove the `live` job, and pass: the environment's reviewer is asked only when the `live` job still runs.",
		"GitHub's subject for a job that names an environment is `repo:OWNER/REPO:environment:tailkeeper-policy` (replace `OWNER/REPO`); it replaces the `repo:OWNER/REPO:pull_request` form",
		"With 1 and 2, a person approves each run of the `live` job before it can mint a token, and only an approved job receives the two environment secrets.",
		"(the three scopes above, or whatever scopes the client holds)",
		"read the pull request's change to that file before you approve",
		"**Without a required reviewer the environment is a name, not a gate.**",
		"Anyone who can push a branch to this repository can therefore edit the workflow, open a pull request, and have the job read the policy, the devices and their posture attributes",
		"Without the subject condition a job that names no environment can mint a token as well.",
		"Treat the read identity as available to everyone with write access to the repository unless steps 1 and 2 are both done.",
		"**A pull request from Dependabot**",
		"GitHub withholds two things from a Dependabot-triggered run: the `id-token` permission, and the Actions secrets (it gives the run Dependabot secrets in their place). Either way the job fails closed: the Check step stops with `OIDC_CLIENT_ID is not set` and the job exits 5, or GitHub refuses the token request before the step, and the job fails. This was not run on a real runner.",
		"**The first policy.** The job copies `policy.hujson` and `invariants.hujson` from the base commit. When the pull request adds either file, the base has no copy, `cp` fails in the step \"Files from the base commit\", and the job fails (exit 1, \"the policy check did not finish\") before any check. Both files have to exist on the base branch first.",
		"`cp` fails in the step \"Files from the base commit\"",
		"downloaded into `$RUNNER_TEMP/tailkeeper/download`, not into the workspace",
		"The Check step stops when that file exists (exit 6, which the last step turns into a failure)",
	} {
		if !strings.Contains(file, s) {
			t.Errorf("the recipe does not say %q", s)
		}
	}
	for _, old := range []string{"This recipe sets neither, and does not invent an environment name", "This recipe does not invent one.", "No protected environment is set", "give Dependabot the secrets", "git diff --name-only` against the base"} {
		if strings.Contains(file, old) {
			t.Errorf("the recipe still says %q", old)
		}
	}
}
