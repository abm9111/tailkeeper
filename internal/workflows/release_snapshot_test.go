package workflows

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// A manual run builds a snapshot and publishes nothing, so it must not hold the
// permissions of the job that publishes. Before 0.6.0 the snapshot was a step of the
// release job, which holds contents: write, id-token: write and attestations: write for
// a tag release, and a manual run held all three although none of its steps used them.
// The snapshot has a job of its own that holds contents: read and nothing else, and the
// release job does not run for a manual run at all. Before the snapshot is built, that
// job runs the release path with the notes fixture (make release-notes-check), so the
// fix to the release notes is exercised before any tag exists.
func TestSnapshotRunsInItsOwnReadOnlyJob(t *testing.T) {
	wf, _ := loadWorkflow(t)
	snap, ok := wf.Jobs["snapshot"]
	if !ok {
		t.Fatal("release.yml has no snapshot job: a manual run builds its snapshot in a job of its own, with no write permission")
	}
	if snap.If != manualRun {
		t.Errorf("the snapshot job's if = %q, want %q", snap.If, manualRun)
	}
	if got := fmt.Sprint(snap.Needs); got != "verify" {
		t.Errorf("the snapshot job needs %q, want verify alone", got)
	}
	want := map[string]string{"contents": "read"}
	if got := permissionsOf(t, "the snapshot job", snap.Permissions); !reflect.DeepEqual(got, want) {
		t.Errorf("the snapshot job has permissions %v, want %v: a manual run holds no write token", got, want)
	}
	if got := wf.Jobs["release"].If; got != tagPush {
		t.Errorf("the release job's if = %q, want %q: it holds the write permissions and must not run for a manual run", got, tagPush)
	}

	// --snapshot is in the GoReleaser step of the snapshot job and nowhere else, and that
	// step skips signing and publishing.
	snapshots := 0
	for name, j := range wf.Jobs {
		for _, s := range j.Steps {
			args, _ := s.With["args"].(string)
			if !strings.Contains(args, "--snapshot") {
				continue
			}
			if name != "snapshot" {
				t.Errorf("%s job, step %q passes --snapshot: only the snapshot job builds one", name, s.Name)
				continue
			}
			snapshots++
			if !strings.Contains(args, "--skip=sign,publish") {
				t.Errorf("the snapshot step's args are %q, want them to skip sign and publish", args)
			}
		}
	}
	if snapshots != 1 {
		t.Errorf("the snapshot job has %d steps that pass --snapshot, want 1", snapshots)
	}

	// Nothing in the job may fail without failing the job: a step with continue-on-error
	// (the notes check above all, or the snapshot) would let a dropped release note or a
	// failed build go on green. Any value counts, an expression included.
	if snap.ContinueOnError != nil {
		t.Errorf("the snapshot job sets continue-on-error %v: a failed step would not fail the job", snap.ContinueOnError)
	}
	for i, s := range snap.Steps {
		if s.ContinueOnError != nil {
			t.Errorf("the snapshot job's step %d (%s) sets continue-on-error %v: a failure of it would not fail the job", i, s.Name+s.Uses, s.ContinueOnError)
		}
	}

	// The notes check runs, as the make target, before the snapshot cleans dist/.
	notes, snapshot := -1, -1
	for i, s := range snap.Steps {
		if strings.TrimSpace(s.Run) == "make release-notes-check" {
			notes = i
		}
		if strings.HasPrefix(s.Uses, "goreleaser/goreleaser-action@") {
			snapshot = i
		}
	}
	if notes < 0 || snapshot < 0 || notes > snapshot {
		t.Errorf("the snapshot job must run `make release-notes-check` (step %d) before its GoReleaser step (step %d)", notes, snapshot)
	}
}

// tokenPatterns match the ways the text of a job can name a token: the secrets context
// (secrets.NAME, secrets['NAME'], toJSON(secrets)), the token of the run itself
// (github.token, github['token'], the variable GITHUB_TOKEN that GoReleaser and gh read)
// and the whole github context, which holds it. GitHub reads context names without regard
// to case, so these do not either.
var tokenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)secrets\s*\.`),
	regexp.MustCompile(`(?i)\$\{\{[^}]*\bsecrets\b`),
	regexp.MustCompile(`(?i)github_token`),
	regexp.MustCompile(`(?i)gh_token`),
	regexp.MustCompile(`(?i)github\s*\.\s*token`),
	regexp.MustCompile(`(?i)github\s*\[\s*['"]token['"]\s*\]`),
	regexp.MustCompile(`(?i)tojson\(\s*github\s*\)`),
}

func namesAToken(text string) bool {
	for _, p := range tokenPatterns {
		if p.MatchString(text) {
			return true
		}
	}
	return false
}

// tokenReferencesIn lists where a job names a token: in its own env, or in a step's env,
// with values or run text. Where a step puts one is the only way it reaches a process,
// so these are all the places a token or a secret can enter the job.
func tokenReferencesIn(j job) []string {
	var found []string
	check := func(where, text string) {
		if namesAToken(text) {
			found = append(found, where+": "+text)
		}
	}
	for k, v := range j.Env {
		check("the job's env", k+"="+v)
	}
	for i, s := range j.Steps {
		name := s.Name
		if name == "" {
			name = s.Uses
		}
		where := fmt.Sprintf("step %d (%s)", i, name)
		check(where+" run", s.Run)
		for k, v := range s.Env {
			check(where+" env", k+"="+fmt.Sprint(v))
		}
		for k, v := range s.With {
			check(where+" with", k+"="+fmt.Sprint(v))
		}
	}
	sort.Strings(found)
	return found
}

// workflowTokenReferences lists where the workflow's own env, which every job inherits
// (the snapshot job included), names a token: a step's env is only one of the places a
// process gets its environment from, and a top-level GITHUB_TOKEN or GH_TOKEN reaches
// every step of every job, whatever the job's permissions say.
func workflowTokenReferences(wf workflow) []string {
	var found []string
	for k, v := range wf.Env {
		if namesAToken(k + "=" + v) {
			found = append(found, "the workflow's env: "+k+"="+v)
		}
	}
	sort.Strings(found)
	return found
}

// The snapshot job holds no token. Its permissions block (contents: read) caps the run's
// own token and nothing else: a personal access token from secrets.* is not capped by it,
// and GoReleaser publishes with whatever GITHUB_TOKEN it finds, so a snapshot step given
// one could publish after all. The manual run is safe only while the job holds no token
// of any kind.
func TestSnapshotJobHoldsNoToken(t *testing.T) {
	wf, _ := loadWorkflow(t)
	snap, ok := wf.Jobs["snapshot"]
	if !ok {
		t.Fatal("release.yml has no snapshot job")
	}
	if len(snap.Steps) == 0 {
		t.Fatal("the snapshot job has no steps: nothing was scanned")
	}
	for _, found := range tokenReferencesIn(snap) {
		t.Errorf("the snapshot job names a token or a secret in %s: a manual run holds none, whatever contents: read allows", found)
	}
	for _, found := range workflowTokenReferences(wf) {
		t.Errorf("the snapshot job inherits a token or a secret from %s: a manual run holds none, whatever contents: read allows", found)
	}
}

// The detector is checked on known positives and negatives first: a scan that cannot find
// a planted token proves nothing when it finds none in the real job.
func TestTokenReferenceDetector(t *testing.T) {
	for _, text := range []string{
		"${{ secrets.GITHUB_TOKEN }}",
		"${{ secrets.SOME_PAT }}",
		"${{ SECRETS.some_pat }}",
		"${{ secrets['SOME_PAT'] }}",
		"${{ toJSON(secrets) }}",
		"${{ github.token }}",
		"${{ Github.Token }}",
		"${{ github . token }}",
		"${{ github['token'] }}",
		"${{ toJSON(github) }}",
		"GITHUB_TOKEN",
		"GITHUB_TOKEN=${{ secrets.X }}",
		"GH_TOKEN",
		"GH_TOKEN=${{ github.token }}",
		"echo $GITHUB_TOKEN | gh auth login",
	} {
		if !namesAToken(text) {
			t.Errorf("the detector does not find a token in %q", text)
		}
	}
	for _, text := range []string{
		"make release-notes-check",
		"release --snapshot --clean --skip=sign,publish",
		"goreleaser",
		"v2.18.2",
		"go.mod",
		"false",
		"0",
		"${{ github.event_name }}",
		"${{ github.ref_name }}",
		"persist-credentials=false",
		"echo no secrets here",
	} {
		if namesAToken(text) {
			t.Errorf("the detector finds a token in %q", text)
		}
	}

	// Each place a job can hold one is read: the job's env, and a step's env, with and run.
	clean := step{Name: "clean", Run: "make release-notes-check", Env: map[string]string{"A": "b"}, With: map[string]any{"c": true, "d": 1}}
	if got := tokenReferencesIn(job{Steps: []step{clean}, Env: map[string]string{"E": "f"}}); len(got) != 0 {
		t.Errorf("a job with no token has references %v", got)
	}
	planted := map[string]job{
		"the job's env": {Env: map[string]string{"X": "${{ secrets.P }}"}, Steps: []step{clean}},
		"env":           {Steps: []step{clean, {Name: "s", Env: map[string]string{"GITHUB_TOKEN": "${{ github.token }}"}}}},
		"with":          {Steps: []step{clean, {Name: "s", With: map[string]any{"token": "${{ secrets.P }}"}}}},
		"run":           {Steps: []step{clean, {Name: "s", Run: "echo ${{ secrets.P }}"}}},
	}
	for where, j := range planted {
		got := tokenReferencesIn(j)
		if len(got) == 0 || !strings.Contains(got[0], where) {
			t.Errorf("a token in %s is reported as %v", where, got)
		}
	}

	// The workflow's own env reaches every job: a top-level secret, GITHUB_TOKEN or GH_TOKEN
	// is found, and the env of the real file (OWNER) is not.
	if got := workflowTokenReferences(workflow{Env: map[string]string{"OWNER": "someone"}}); len(got) != 0 {
		t.Errorf("a workflow env with no token has references %v", got)
	}
	for name, env := range map[string]map[string]string{
		"a secret under GITHUB_TOKEN": {"GITHUB_TOKEN": "${{ secrets.X }}"},
		"github.token under GH_TOKEN": {"GH_TOKEN": "${{ github.token }}"},
		"a literal under GH_TOKEN":    {"GH_TOKEN": "x"},
		"a secret under another name": {"PAT": "${{ secrets.X }}"},
		"alongside an innocent entry": {"OWNER": "someone", "GITHUB_TOKEN": "${{ github.token }}"},
	} {
		if got := workflowTokenReferences(workflow{Env: env}); len(got) != 1 || !strings.Contains(got[0], "the workflow's env") {
			t.Errorf("%s in the workflow's env is reported as %v", name, got)
		}
	}
}

// releaseNotesCheckRecipe returns the logical lines of the release-notes-check recipe in
// the Makefile text: the tab-indented lines after its target line, backslash
// continuations joined, comments left out. It returns nothing when there is no such target.
func releaseNotesCheckRecipe(makefile string) []string {
	var lines []string
	var cur string
	in := false
	for _, line := range strings.Split(strings.ReplaceAll(makefile, "\r\n", "\n"), "\n") {
		if !in {
			in = strings.HasPrefix(line, "release-notes-check:")
			continue
		}
		if cur == "" && !strings.HasPrefix(line, "\t") {
			break
		}
		text := strings.TrimPrefix(line, "\t")
		if strings.HasSuffix(text, `\`) {
			cur += strings.TrimSuffix(text, `\`) + " "
			continue
		}
		text = cur + text
		cur = ""
		if !strings.HasPrefix(strings.TrimSpace(text), "#") {
			lines = append(lines, text)
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// goreleaserCommands returns, for each use of $(GORELEASER) in the lines, its arguments:
// the text from the variable to the first shell operator or redirection after it.
func goreleaserCommands(lines []string) []string {
	const v = "$(GORELEASER)"
	var cmds []string
	for _, l := range lines {
		for {
			i := strings.Index(l, v)
			if i < 0 {
				break
			}
			l = l[i+len(v):]
			end := len(l)
			if j := strings.IndexAny(l, ">|;&"); j >= 0 {
				end = j
			}
			cmds = append(cmds, l[:end])
		}
	}
	return cmds
}

// skippedBy returns every step named by a --skip flag in the arguments: --skip is a list
// flag, so a value can be a comma list, can follow after a space, and can be given again.
func skippedBy(args string) []string {
	var skipped []string
	words := strings.Fields(args)
	for i, w := range words {
		var list string
		switch {
		case strings.HasPrefix(w, "--skip="):
			list = strings.TrimPrefix(w, "--skip=")
		case w == "--skip" && i+1 < len(words):
			list = words[i+1]
		default:
			continue
		}
		skipped = append(skipped, strings.Split(strings.Trim(list, `"'`), ",")...)
	}
	return skipped
}

// notesCheckProblems reads the recipe of make release-notes-check and says what is wrong
// with it. The run is the release path without --snapshot, so the changelog stage runs;
// it publishes nothing only because its command line skips publish.
func notesCheckProblems(makefile string) []string {
	recipe := releaseNotesCheckRecipe(makefile)
	cmds := goreleaserCommands(recipe)
	if len(cmds) == 0 {
		return []string{"the Makefile has no release-notes-check recipe that runs $(GORELEASER)"}
	}
	var problems []string
	for _, c := range cmds {
		if !contains(skippedBy(c), "publish") {
			problems = append(problems, fmt.Sprintf("the GoReleaser command %q does not skip publish: the run is not a snapshot, so it would publish", strings.TrimSpace(c)))
		}
	}
	for _, l := range recipe {
		if strings.Contains(l, "--snapshot") {
			problems = append(problems, fmt.Sprintf("the recipe line %q passes --snapshot: a snapshot skips the changelog stage this target exists to run", strings.TrimSpace(l)))
		}
	}
	return problems
}

func TestNotesCheckRunSkipsPublishAndIsNoSnapshot(t *testing.T) {
	data, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range notesCheckProblems(string(data)) {
		t.Error(p)
	}
}

func TestNotesCheckRecipeReading(t *testing.T) {
	recipe := func(args string) string {
		return "# a comment\nrelease-notes-check:\n\t@log=\"$$(mktemp)\"; \\\n\t$(GO) run $(GORELEASER) " + args + " > \"$$log\" 2>&1 \\\n\t\t|| { exit 1; }; \\\n\t./scripts/release-notes-check.sh\n\nrelease-check:\n\t$(GO) run $(GORELEASER) release --snapshot --clean --skip=sign,sbom,publish\n"
	}
	good := "--verbose release --clean --skip=publish,sign,sbom,validate,announce --release-notes f.md"
	for name, c := range map[string]struct {
		makefile string
		want     string // a substring of the one problem, or "" for none
	}{
		"as it is":                    {recipe(good), ""},
		"CRLF line ends":              {strings.ReplaceAll(recipe(good), "\n", "\r\n"), ""},
		"skip given with a space":     {recipe("release --skip publish,sign"), ""},
		"skip given twice":            {recipe("release --skip=sign --skip=publish"), ""},
		"quoted list":                 {recipe(`release --skip="sign,publish"`), ""},
		"publish dropped":             {recipe("--verbose release --clean --skip=sign,sbom,validate,announce"), "does not skip publish"},
		"no skip at all":              {recipe("--verbose release --clean"), "does not skip publish"},
		"publish only in a name":      {recipe("release --skip=sign,publishing"), "does not skip publish"},
		"publish in another flag":     {recipe("release --skip=sign --release-notes publish.md"), "does not skip publish"},
		"snapshot added":              {recipe(good + " --snapshot"), "passes --snapshot"},
		"no recipe":                   {"release-check:\n\t$(GO) run $(GORELEASER) release --skip=publish\n", "no release-notes-check recipe"},
		"recipe that runs no command": {"release-notes-check:\n\t@echo hi\n", "no release-notes-check recipe"},
	} {
		got := notesCheckProblems(c.makefile)
		switch {
		case c.want == "" && len(got) != 0:
			t.Errorf("%s: problems %v, want none", name, got)
		case c.want != "" && (len(got) != 1 || !strings.Contains(got[0], c.want)):
			t.Errorf("%s: problems %v, want one containing %q", name, got, c.want)
		}
	}
	// release-check's own snapshot line, after the recipe, is not part of it.
	if got := notesCheckProblems(recipe(good)); len(got) != 0 {
		t.Errorf("the next target's --snapshot leaked into the recipe: %v", got)
	}
}
