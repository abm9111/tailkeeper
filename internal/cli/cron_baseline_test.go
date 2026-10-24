package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// The scheduled check of docs/recipes/cron.md compares the live policy with a baseline. These
// tests run the command lines the recipe prints, read from the recipe itself, against the fake
// API: a changed policy exits 8, an unchanged one exits 0, and a baseline the log no longer
// holds is a failure. The file baseline's shell lines are run too, where jq is available.

// cronRecipeLines returns the lines of the recipe.
func cronRecipeLines(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "recipes", "cron.md"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(string(b), "\n")
}

// cronCommand returns the arguments, after the binary, of the one line of the recipe that
// matches re in its first group. The line may not hold a shell expansion other
// than the one named in subst.
func cronCommand(t *testing.T, re *regexp.Regexp, subst map[string]string) []string {
	t.Helper()
	var found []string
	for _, line := range cronRecipeLines(t) {
		if m := re.FindStringSubmatch(line); m != nil {
			found = append(found, m[1])
		}
	}
	if len(found) != 1 {
		t.Fatalf("cron.md: %d lines match %s, want 1: %q", len(found), re, found)
	}
	args := strings.Fields(found[0])
	for i, a := range args {
		a = strings.Trim(a, `"`)
		if v, ok := subst[a]; ok {
			a = v
		}
		if strings.Contains(a, "$") {
			t.Fatalf("cron.md: %q holds an expansion the test does not model", a)
		}
		args[i] = a
	}
	return args
}

// cronVersionDiff is the recipe's `acl diff` line with the version id in place.
func cronVersionDiff(t *testing.T, id string) []string {
	t.Helper()
	return cronCommand(t, regexp.MustCompile(`^\s*run "\$TAILKEEPER" (acl diff .*)$`), map[string]string{"$version": id})
}

const cronPolicy = "{\n\t\"tagOwners\": {\"tag:ci\": [\"amy@example.com\"]},\n}\n"

// cronFake serves a configuration audit log whose newest ACL update wrote cronPolicy, and live
// as the live policy.
func cronFake(t *testing.T, live string) *apitest.Fake {
	t.Helper()
	f := apitest.New(t)
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/logging/configuration", 200, cronAuditBody(t))
	f.Handle("GET", "/api/v2/tailnet/T1234CNTRL/acl", func(w http.ResponseWriter, r *http.Request) {
		apitest.DetailsOK(live, api.ETagOf([]byte(live)), nil, nil).Write(w)
	})
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/settings", 200, `{"aclsExternallyManagedOn":false}`)
	return f
}

// cronAuditBody is the log: an older update, and the one that wrote cronPolicy.
func cronAuditBody(t *testing.T) string {
	t.Helper()
	type entry struct {
		EventTime    string `json:"eventTime"`
		EventGroupID string `json:"eventGroupID"`
		Origin       string `json:"origin"`
		Type         string `json:"type"`
		Old          string `json:"old"`
		New          string `json:"new"`
	}
	b, err := json.Marshal(struct {
		Logs []entry `json:"logs"`
	}{[]entry{
		{"2026-10-01T00:00:00Z", "g1", "ADMIN_CONSOLE", "TAILNET.UPDATE.ACL", "{}", `{"tagOwners":{}}`},
		{"2026-10-08T00:00:00Z", "g2", "ADMIN_CONSOLE", "TAILNET.UPDATE.ACL", `{"tagOwners":{}}`, cronPolicy},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// newestVersion is the VERSION of the last row of `acl history`, the one the recipe tells the
// owner to write to the baseline file.
func newestVersion(t *testing.T, f *apitest.Fake) string {
	t.Helper()
	h := newHarness(t, f)
	if code := h.run("--json", "acl", "history"); code != 0 {
		t.Fatalf("acl history exit %d: %s", code, h.err)
	}
	var out tools.ACLHistoryOutput
	if err := json.Unmarshal(h.out.Bytes(), &out); err != nil || len(out.Versions) != 2 {
		t.Fatalf("acl history: %d versions, %v", len(out.Versions), err)
	}
	return out.Versions[len(out.Versions)-1].Version
}

// A baseline that is a version id: no policy text on disk, masking on (the harness default),
// and the live policy classified against the stored one.
func TestTheCronBaselineByVersionIDExitsEightOnAChangeAndZeroWhenUnchanged(t *testing.T) {
	changed := strings.Replace(cronPolicy, `["amy@example.com"]`, `["amy@example.com", "autogroup:admin"]`, 1)
	if changed == cronPolicy {
		t.Fatal("the changed policy equals the stored one")
	}
	for _, c := range []struct {
		name, live string
		want       int
	}{
		{"unchanged", cronPolicy, 0},
		{"a comment and a layout only", "// reviewed\n{\"tagOwners\": {\"tag:ci\": [\"amy@example.com\"]}}\n", 0},
		{"changed", changed, 8},
	} {
		f := cronFake(t, c.live)
		id := newestVersion(t, f)
		h := newHarness(t, f)
		if code := h.run(cronVersionDiff(t, id)...); code != c.want {
			t.Errorf("%s: exit %d, want %d\nstdout %s\nstderr %s", c.name, code, c.want, h.out, h.err)
		}
		if c.want == 8 && !strings.Contains(h.err.String(), "findings_present") {
			t.Errorf("%s: stderr %q does not say findings_present", c.name, h.err)
		}
		if strings.Contains(h.out.String()+h.err.String(), "amy@example.com") {
			t.Errorf("%s: a login reached the output while masking is on", c.name)
		}
	}
}

// An id the log does not hold fails the run, not green: the recipe's script has no arm for it
// and so exits with the command's own code.
func TestTheCronBaselineByVersionIDFailsWhenTheLogNoLongerHoldsIt(t *testing.T) {
	f := cronFake(t, cronPolicy)
	id := newestVersion(t, f)
	gone := apitest.New(t)
	gone.JSON("GET", "/api/v2/tailnet/T1234CNTRL/logging/configuration", 200, `{"logs":[]}`)
	h := newHarness(t, gone)
	code := h.run(cronVersionDiff(t, id)...)
	if code != 1 || !strings.Contains(h.err.String(), "not_found") || !strings.Contains(h.err.String(), "the log no longer holds this version") {
		t.Errorf("exit %d, stderr %q; want 1, not_found, and the log no longer holds this version", code, h.err)
	}
	if h.out.Len() != 0 {
		t.Errorf("stdout %q", h.out)
	}
	// The check script tells this exit 1 from any other by this text of the command's message.
	m := regexp.MustCompile(`grep -qF '([^']+)'`).FindStringSubmatch(strings.Join(cronRecipeLines(t), "\n"))
	if m == nil || !strings.Contains(h.err.String(), m[1]) {
		t.Errorf("the script's grep text %v is not in the command's message %q", m, h.err)
	}
}

// cronFileFence is the recipe's shell fence that writes the saved-file baseline.
func cronFileFence(t *testing.T) string {
	t.Helper()
	var found []string
	var b strings.Builder
	open := false
	for _, line := range cronRecipeLines(t) {
		switch {
		case !open && line == "```sh":
			open = true
			b.Reset()
		case open && line == "```":
			open = false
			if strings.Contains(b.String(), "acl get") {
				found = append(found, b.String())
			}
		case open:
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	if len(found) != 1 {
		t.Fatalf("cron.md: %d shell fences run acl get, want 1", len(found))
	}
	return found[0]
}

// The file baseline: the recipe's own lines (acl get, jq, mv) are run with a stand-in
// tailkeeper that prints a page of `acl get --json`, and the file they write is the policy
// text that `acl diff --against` reads. A page that is masked or cut writes nothing, and the
// file already there stays.
func TestTheCronFileBaselineIsThePolicyTextAndDiffReadsIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the recipe's lines are a POSIX shell script")
	}
	jq, err := exec.LookPath("jq")
	if err != nil {
		t.Skip("no jq on PATH: the recipe's jq line is not run here")
	}
	fence := cronFileFence(t)
	against := cronCommand(t, regexp.MustCompile("`run \"\\$TAILKEEPER\" (acl diff --against [^`]*)`"), map[string]string{"$BASELINE_FILE": "BASELINE"})
	f := cronFake(t, cronPolicy)

	page := func(personalData string) tools.ACLGetOutput {
		t.Helper()
		h := newHarness(t, f)
		h.app.Env.Config = &config.Loaded{Config: config.Config{PersonalData: personalData}}
		if code := h.run("acl", "get", "--json"); code != 0 {
			t.Fatalf("acl get exit %d: %s", code, h.err)
		}
		var out tools.ACLGetOutput
		if err := json.Unmarshal(h.out.Bytes(), &out); err != nil {
			t.Fatalf("acl get did not print JSON: %v\n%s", err, h.out)
		}
		return out
	}
	usable := page(config.PersonalDataShow)
	if usable.Truncated || usable.Masked || usable.Policy == "" {
		t.Fatalf("the page is truncated (%v), masked (%v) or empty", usable.Truncated, usable.Masked)
	}
	masked := page(config.PersonalDataMask)
	if !masked.Masked {
		t.Fatal("the page under personalData mask is not marked masked")
	}
	cut := usable
	cut.Truncated = true

	run := func(p tools.ACLGetOutput, existing string) (code int, file, argv string) {
		t.Helper()
		dir := t.TempDir()
		pageFile := filepath.Join(dir, "page.json")
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pageFile, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		argvFile := filepath.Join(dir, "argv")
		stub := filepath.Join(dir, "tk")
		if err := os.WriteFile(stub, []byte("#!/bin/sh\necho \"$*\" >> \"$STUB_ARGV\"\ncat \"$PAGE\"\n"), 0o700); err != nil { //nolint:gosec // G306: an executable stand-in in a test directory
			t.Fatal(err)
		}
		baseline := filepath.Join(dir, "baseline.hujson")
		if existing != "" {
			if err := os.WriteFile(baseline, []byte(existing), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command("/bin/sh", "-c", fence)
		cmd.Env = []string{"PATH=" + filepath.Dir(jq) + ":/usr/bin:/bin", "TAILKEEPER=" + stub, "BASELINE_FILE=" + baseline, "PAGE=" + pageFile, "STUB_ARGV=" + argvFile}
		err = cmd.Run()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(baseline) //nolint:gosec // G304: a file in the test directory
		a, _ := os.ReadFile(argvFile) //nolint:gosec // G304: as above
		if code == 0 {
			if fi, err := os.Stat(baseline); err != nil || fi.Mode().Perm() != 0o600 {
				t.Errorf("the baseline file's mode is not 600: %v %v", fi, err)
			}
		}
		return code, string(b), string(a)
	}

	code, file, argv := run(usable, "")
	if code != 0 || strings.TrimRight(file, "\n") != strings.TrimRight(usable.Policy, "\n") {
		t.Fatalf("a usable page: exit %d, the file is %q, want the policy text", code, file)
	}
	if strings.TrimSpace(argv) != "acl get --json --max-bytes 4194304" {
		t.Errorf("the recipe runs %q", argv)
	}
	if strings.Contains(file, "  1  ") || !strings.Contains(file, "amy@example.com") {
		t.Errorf("the baseline is not the policy text:\n%s", file)
	}
	for name, p := range map[string]tools.ACLGetOutput{"masked": masked, "cut": cut} {
		code, file, _ := run(p, "OLD BASELINE\n")
		if code == 0 || file != "OLD BASELINE\n" {
			t.Errorf("a %s page: exit %d, the file is %q; want a failure and the old file kept", name, code, file)
		}
		code, file, _ = run(p, "")
		if code == 0 || strings.TrimSpace(file) != "" {
			t.Errorf("a %s page and no file: exit %d, the file is %q; want a failure and no policy written", name, code, file)
		}
	}

	baseline := writeFile(t, "baseline.hujson", file)
	for i, a := range against {
		if a == "BASELINE" {
			against[i] = baseline
		}
	}
	h := newHarness(t, f)
	if code := h.run(against...); code != 0 {
		t.Errorf("the unchanged live policy against its saved copy: exit %d\n%s\n%s", code, h.out, h.err)
	}
	changed := strings.Replace(cronPolicy, `"tag:ci"`, `"tag:other"`, 1)
	h = newHarness(t, cronFake(t, changed))
	if code := h.run(against...); code != 8 {
		t.Errorf("a changed live policy against its saved copy: exit %d, want 8\n%s\n%s", code, h.out, h.err)
	}
}

// The text layout of `acl get`, which a redirect would write, is a document and not a policy:
// `acl diff --against` refuses it. This is why the recipe asks for --json and a filter.
func TestTheNumberedLayoutOfACLGetIsNotAPolicyFile(t *testing.T) {
	f := cronFake(t, cronPolicy)
	h := newHarness(t, f)
	h.app.Env.Config = &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}
	if code := h.run("acl", "get"); code != 0 {
		t.Fatalf("acl get exit %d: %s", code, h.err)
	}
	file := writeFile(t, "layout.hujson", h.out.String())
	h = newHarness(t, f)
	if code := h.run("acl", "diff", "--against", file, "--fail-on", "change", "--quiet"); code != 2 {
		t.Errorf("a redirected acl get as the baseline: exit %d, want 2\n%s\n%s", code, h.out, h.err)
	}
}
