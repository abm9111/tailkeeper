package workflows

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The publish job flips the draft release to published, after which a release is
// immutable. It checks the draft's file names and hashes against checksums.txt, and it
// must also check the signature the draft carries over checksums.txt, as the README tells
// a reader to: cosign verify-blob with the workflow's identity and GitHub's issuer. A
// bundle that does not verify must stop the publication, not be found by the first
// reader. The identity and the issuer are read from the README, so the two cannot drift.
func TestPublishVerifiesTheCosignBundleAsTheReadmeDoes(t *testing.T) {
	wf, text := loadWorkflow(t)
	data, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(data)
	id := regexp.MustCompile(`IDENTITY="https://github\.com/([^/"]+/[^/"]+)/(\.github/workflows/[^"@]+)@refs/tags/\$VERSION"`).FindStringSubmatch(readme)
	issuer := regexp.MustCompile(`--certificate-oidc-issuer (\S+)`).FindStringSubmatch(readme)
	if id == nil || issuer == nil {
		t.Fatalf("the README has no IDENTITY line or no --certificate-oidc-issuer (identity %v, issuer %v): this test reads both, so the README's verify block was reworded; update the test with it", id, issuer)
	}

	pub, ok := wf.Jobs["publish"]
	if !ok {
		t.Fatal("release.yml has no publish job")
	}
	install, verify := -1, -1
	var vs step
	for i, s := range pub.Steps {
		if strings.HasPrefix(s.Uses, "sigstore/cosign-installer@") && install < 0 {
			install = i
			if got, _ := s.With["cosign-release"].(string); !regexp.MustCompile(`^v\d+\.\d+\.\d+$`).MatchString(got) {
				t.Errorf("the publish job installs cosign-release %q, want a full version such as v3.1.3", got)
			}
			if s.If != "" || s.ContinueOnError != nil {
				t.Errorf("the cosign installer step of the publish job has if %q or continue-on-error %v: it must always run and must fail the job", s.If, s.ContinueOnError)
			}
		}
		if strings.Contains(s.Run, "cosign verify-blob") && verify < 0 {
			verify, vs = i, s
		}
	}
	if install < 0 || verify < 0 || install > verify {
		t.Fatalf("the publish job must install cosign (step %d) before a step that runs cosign verify-blob (step %d)", install, verify)
	}

	// Nothing may let the job go on after a failed verification: not a condition on the
	// step, a shell that does not stop on error, or continue-on-error on the step or job.
	if vs.If != "" {
		t.Errorf("the publish step has if %q: the verification would be skipped when it is false", vs.If)
	}
	if vs.Shell != "" {
		t.Errorf("the publish step sets shell %q: the default `bash -e` shell is what stops it on a failed command (a custom shell such as `bash {0}` does not)", vs.Shell)
	}
	if vs.ContinueOnError != nil {
		t.Errorf("the publish step sets continue-on-error %v: a failed verification would not fail the job", vs.ContinueOnError)
	}
	if pub.ContinueOnError != nil {
		t.Errorf("the publish job sets continue-on-error %v: a failed verification would not fail the job", pub.ContinueOnError)
	}

	// The script as the shell reads it: comment lines dropped, continuation lines joined,
	// whitespace collapsed, one logical command per line.
	var kept []string
	for _, l := range strings.Split(vs.Run, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			kept = append(kept, l)
		}
	}
	var lines []string
	for _, l := range strings.Split(strings.ReplaceAll(strings.Join(kept, "\n"), "\\\n", " "), "\n") {
		if f := strings.Join(strings.Fields(l), " "); f != "" {
			lines = append(lines, f)
		}
	}
	script := strings.Join(lines, "\n")

	// It runs under `set -euo pipefail` from its first command, and nothing turns that off.
	if len(lines) == 0 || lines[0] != "set -euo pipefail" {
		t.Errorf("the publish step's first command is not `set -euo pipefail`: a failed verification would not stop it")
	}
	if m := regexp.MustCompile(`\bset\s+\+`).FindString(script); m != "" {
		t.Errorf("the publish step runs %q: that turns off what stops it on a failed verification", m)
	}
	for _, bad := range []string{"--insecure-ignore-tlog", "--insecure-ignore-sct", "--private-infrastructure", "--certificate-identity-regexp", "--certificate-oidc-issuer-regexp"} {
		if strings.Contains(script, bad) {
			t.Errorf("the publish step uses %s: that loosens what the verification accepts", bad)
		}
	}

	// The verification is one command, exactly the README's: the draft's own files, this
	// workflow's identity for this tag, GitHub's issuer, and nothing before or after it
	// on its line (no `|| true`, pipe, `&` or `;`).
	var verifyLines []string
	for _, l := range lines {
		if strings.Contains(l, "cosign verify-blob") {
			verifyLines = append(verifyLines, l)
		}
	}
	wantLine := `cosign verify-blob "$draft/checksums.txt"` +
		` --bundle "$draft/checksums.txt.sigstore.json"` +
		` --certificate-identity "https://github.com/$GITHUB_REPOSITORY/` + id[2] + `@refs/tags/$TAG"` +
		` --certificate-oidc-issuer ` + issuer[1]
	if len(verifyLines) != 1 || verifyLines[0] != wantLine {
		t.Errorf("the publish step's cosign verify-blob command is %q, want exactly one command, %q (the README's repository is %s)", verifyLines, wantLine, id[1])
	}
	// It runs before the draft is published (comments do not count).
	if at, edit := strings.Index(script, "cosign verify-blob"), strings.Index(script, "gh release edit"); edit < 0 || at < 0 || at > edit {
		t.Errorf("cosign verify-blob must come before `gh release edit` in the same step")
	}

	// Every installer is pinned to a full commit SHA with a version comment.
	pins := regexp.MustCompile(`uses: sigstore/cosign-installer@[0-9a-f]{40} # v\d+\.\d+\.\d+`).FindAllString(text, -1)
	if n := strings.Count(text, "uses: sigstore/cosign-installer@"); len(pins) != n || n != 2 {
		t.Errorf("found %d cosign-installer steps, %d of them pinned to a SHA with a version comment, want 2 of 2 (release signs, publish verifies)", n, len(pins))
	}
}

// needsOf reads a job's needs: a name or a list of names.
func needsOf(needs any) []string {
	switch n := needs.(type) {
	case string:
		return []string{n}
	case []any:
		var out []string
		for _, x := range n {
			out = append(out, fmt.Sprint(x))
		}
		sort.Strings(out)
		return out
	}
	return nil
}

// publishGateProblems says what is wrong with the gates of the publish job, which flips a
// draft release to published and so cannot be undone. The header of release.yml says it
// needs verify, release and reproduce, so an unsigned or unreproducible tag never reaches
// it; it runs for a tag push only; and before it verifies the signature it checks that the
// draft carries the checksums.txt the release job produced and that every file in the draft
// has the hash it lists.
func publishGateProblems(wf workflow) []string {
	pub, ok := wf.Jobs["publish"]
	if !ok {
		return []string{"release.yml has no publish job"}
	}
	var problems []string
	if got, want := fmt.Sprint(needsOf(pub.Needs)), fmt.Sprint([]string{"release", "reproduce", "verify"}); got != want {
		problems = append(problems, fmt.Sprintf("the publish job needs %s, want exactly [release reproduce verify]: a release that is not built, reproduced and verified must not be published", got))
	}
	if pub.If != tagPush {
		problems = append(problems, fmt.Sprintf("the publish job's if = %q, want %q", pub.If, tagPush))
	}
	const (
		cmpLine = `cmp "$sums" "$draft/checksums.txt"`
		sumLine = `(cd "$draft" && sha256sum -c "$sums")`
	)
	cmpAt, sumAt, verifyAt, found := -1, -1, -1, false
	for _, s := range pub.Steps {
		if !strings.Contains(s.Run, "cosign verify-blob") {
			continue
		}
		found = true
		n := 0
		for _, l := range strings.Split(s.Run, "\n") {
			l = strings.Join(strings.Fields(l), " ")
			switch {
			case strings.HasPrefix(l, "#"):
			case l == cmpLine || (strings.HasPrefix(l, cmpLine+" || {") && strings.Contains(l, "exit 1")):
				cmpAt = n
			case l == sumLine:
				sumAt = n
			case strings.HasPrefix(l, "cosign verify-blob"):
				verifyAt = n
			}
			n++
		}
	}
	switch {
	case !found:
		problems = append(problems, "the publish job has no step that runs cosign verify-blob")
	case cmpAt < 0:
		problems = append(problems, "the publish step has no line "+cmpLine+" that stops on a difference: the draft's checksums.txt would not be compared with the one the release job produced")
	case sumAt < 0:
		problems = append(problems, "the publish step has no line "+sumLine+": the draft's files would not be checked against the hashes in checksums.txt")
	case cmpAt > verifyAt || sumAt > verifyAt:
		problems = append(problems, "the publish step checks the draft's checksums after it verifies the signature: the signature is over checksums.txt, so the files and the list must be checked first")
	}
	return problems
}

func TestPublishJobKeepsItsGates(t *testing.T) {
	wf, _ := loadWorkflow(t)
	for _, p := range publishGateProblems(wf) {
		t.Error(p)
	}

	// The check is run on jobs that have each fault, so it cannot pass by reading nothing.
	good := func() workflow {
		return workflow{Jobs: map[string]job{"publish": {
			Needs: []any{"verify", "release", "reproduce"},
			If:    tagPush,
			Steps: []step{{Run: "set -euo pipefail\n# a comment\ncmp \"$sums\" \"$draft/checksums.txt\" || { echo x; exit 1; }\n(cd \"$draft\" && sha256sum -c \"$sums\")\ncosign verify-blob \"$draft/checksums.txt\" \\\n  --bundle b\ngh release edit \"$TAG\" --draft=false\n"}},
		}}}
	}
	if got := publishGateProblems(good()); len(got) != 0 {
		t.Fatalf("the model job has problems %v", got)
	}
	for _, c := range []struct {
		name string
		edit func(*job)
		want string
	}{
		{"needs without reproduce", func(j *job) { j.Needs = []any{"verify", "release"} }, "needs [release verify]"},
		{"needs in another order", func(j *job) { j.Needs = []any{"reproduce", "verify", "release"} }, ""},
		{"needs as a bare name", func(j *job) { j.Needs = "release" }, "needs [release]"},
		{"no needs", func(j *job) { j.Needs = nil }, "needs []"},
		{"an extra need", func(j *job) { j.Needs = []any{"verify", "release", "reproduce", "snapshot"} }, "needs [release reproduce snapshot verify]"},
		{"if always()", func(j *job) { j.If = "always()" }, "the publish job's if"},
		{"no if", func(j *job) { j.If = "" }, "the publish job's if"},
		{"if with an alternative", func(j *job) { j.If = tagPush + " || always()" }, "the publish job's if"},
		{"cmp dropped", func(j *job) {
			j.Steps[0].Run = strings.Replace(j.Steps[0].Run, "cmp \"$sums\" \"$draft/checksums.txt\" || { echo x; exit 1; }\n", "", 1)
		}, "no line cmp"},
		{"cmp that cannot fail", func(j *job) {
			j.Steps[0].Run = strings.Replace(j.Steps[0].Run, "|| { echo x; exit 1; }", "|| true", 1)
		}, "no line cmp"},
		{"sha256sum -c dropped", func(j *job) {
			j.Steps[0].Run = strings.Replace(j.Steps[0].Run, "(cd \"$draft\" && sha256sum -c \"$sums\")\n", "", 1)
		}, "no line (cd"},
		{"the checks after the verification", func(j *job) {
			j.Steps[0].Run = "set -e\ncosign verify-blob \"$draft/checksums.txt\"\ncmp \"$sums\" \"$draft/checksums.txt\"\n(cd \"$draft\" && sha256sum -c \"$sums\")\n"
		}, "after it verifies"},
		{"no verification step", func(j *job) { j.Steps[0].Run = "gh release edit" }, "no step that runs cosign"},
	} {
		wf := good()
		j := wf.Jobs["publish"]
		j.Steps = append([]step{}, j.Steps...)
		c.edit(&j)
		wf.Jobs["publish"] = j
		got := publishGateProblems(wf)
		switch {
		case c.want == "" && len(got) != 0:
			t.Errorf("%s: problems %v, want none", c.name, got)
		case c.want != "" && (len(got) != 1 || !strings.Contains(got[0], c.want)):
			t.Errorf("%s: problems %v, want one containing %q", c.name, got, c.want)
		}
	}
	if got := publishGateProblems(workflow{Jobs: map[string]job{}}); len(got) != 1 || !strings.Contains(got[0], "no publish job") {
		t.Errorf("a workflow with no publish job: %v", got)
	}
}
