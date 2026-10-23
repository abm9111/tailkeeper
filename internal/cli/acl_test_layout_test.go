package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
)

// acl test through the real command line, against the fake API. Each case is rendered
// in every format the command offers and compared with a golden. The goldens hold no
// login and no tailnet value. An SSH pass and an SSH unknown are among them.

func TestEveryLayoutOfACLTestMatchesItsGolden(t *testing.T) {
	for _, c := range aclTestLayoutCases {
		got := map[string]string{}
		for _, rendering := range c.renderings() {
			t.Run(c.name+"/"+rendering, func(t *testing.T) {
				code, stdout, stderr := c.run(t, rendering)
				got[rendering] = stdout
				if code != c.exit || stderr != c.stderr {
					t.Errorf("exit %d, stderr %q; want exit %d, stderr %q", code, stderr, c.exit, c.stderr)
				}
				if stdout == "" {
					t.Error("nothing on standard output")
				}
				if rendering == "json" && !json.Valid([]byte(stdout)) {
					t.Errorf("not JSON: %q", stdout)
				}
				if rendering != "color" && strings.Contains(stdout, "\x1b") {
					t.Errorf("colour written where none was asked for: %q", stdout)
				}
				if rendering == "text" && c.wantPrefix != "" && !strings.HasPrefix(stdout, c.wantPrefix) {
					t.Errorf("the verdict line is %q, want prefix %q", firstLine(stdout), c.wantPrefix)
				}
				checkGolden(t, goldenPath(c.name, rendering), stdout)
			})
		}
		if colour, plain := got["color"], got["text"]; colour != "" {
			if stripped := ansiCode.ReplaceAllString(colour, ""); stripped != plain {
				t.Errorf("%s: the coloured layout is not the plain one with codes:\n%q\n%q", c.name, stripped, plain)
			}
			if colour == plain {
				t.Errorf("%s: the coloured layout holds no colour", c.name)
			}
		}
	}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// aclTestCase is one acl test run. wantPrefix is the verdict line the text rendering
// must start with, so a golden written from a wrong reading is still rejected.
type aclTestCase struct {
	aclCase
	wantPrefix string
}

var aclTestLayoutCases = []aclTestCase{
	{aclCase: aclCase{name: "test-pass", args: []string{"acl", "test", "tag:ci", "--accept", "tag:web:22", "--accept", "tag:db:443", "--deny", "tag:ci:22"},
		fake: layoutFake("{}\n", nil, answerWith(apitest.TestsPass()))},
		wantPrefix: "PASS · 3 destinations as asked"},
	{aclCase: aclCase{name: "test-fail", args: []string{"acl", "test", "tag:ci", "--accept", "tag:web:22"}, exit: 9,
		fake: layoutFake("{}\n", nil, answerWith(apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{
			`[acl test error]: address "tag:web:22" (protocol "tcp"): want: Accept, got: Drop`}})))},
		wantPrefix: "FAILED · 1 destination not as asked"},
	{aclCase: aclCase{name: "test-unresolved", args: []string{"acl", "test", "tag:missing", "--accept", "tag:web:22"}, exit: 2,
		fake: layoutFake("{}\n", nil, answerWith(apitest.TestUnevaluable("tag:missing")))},
		wantPrefix: "UNRESOLVED · a name or destination does not resolve"},
	{aclCase: aclCase{name: "test-unknown", args: []string{"acl", "test", "tag:ci", "--accept", "tag:web:22"}, exit: 1,
		fake: layoutFake("{}\n", nil, answerWith(apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{
			`[acl test error]: address "tag:other:22" (protocol "tcp"): want: Accept, got: Drop`}})))},
		wantPrefix: "UNKNOWN · the answer could not be established; this is not a pass"},
	{aclCase: aclCase{name: "test-posture", args: []string{"acl", "test", "tag:ci", "--accept", "tag:web:22"},
		fake: layoutFake(posturePolicy, nil, answerWith(apitest.TestsPass()))},
		wantPrefix: "PASS · 1 destination as asked"},
	{aclCase: aclCase{name: "test-ssh-pass", args: []string{"acl", "test", "tag:ci", "--ssh", `[{"dst":["tag:web"],"accept":["root"]}]`},
		fake: sshLayoutFake(true)},
		wantPrefix: "PASS · 1 SSH user as asked"},
	{aclCase: aclCase{name: "test-ssh-unknown", args: []string{"acl", "test", "tag:ci", "--ssh", `[{"dst":["tag:web"],"accept":["root"]}]`}, exit: 1,
		fake: sshLayoutFake(false)},
		wantPrefix: "UNKNOWN · the answer could not be established; this is not a pass"},
	{aclCase: aclCase{name: "test-hostile", args: []string{"acl", "test", "tag:ci", "--accept", "tag:web:22"},
		fake: layoutFake("{}\n", nil, answerWith(apitest.TestsWarned(apitest.Entry{User: "tag:ci", Warnings: []string{
			"::add-mask::secret\n##[error]forged ##vso[task.complete result=Failed;] %0A"}})))},
		wantPrefix: "PASS · 1 destination as asked"},
}

// sshLayoutFake answers a policy-mode validation with the tests canary taken from
// the request, and, when pass is set, the SSH canary too. A missing SSH canary is
// unknown. The caller's own SSH user has no line, so silence is allowed.
func sshLayoutFake(pass bool) func(t *testing.T) *apitest.Fake {
	testsTag := regexp.MustCompile(`tag:tailkeeper-canary-[0-9a-f]{8}`)
	sshTag := regexp.MustCompile(`tag:tailkeeper-sshcanary-[0-9a-f]{8}`)
	return func(t *testing.T) *apitest.Fake {
		t.Helper()
		f := apitest.New(t)
		serveLayoutLive(f, func() string { return "{}\n" }, nil)
		f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			text := string(b)
			var es []apitest.Entry
			if tag := testsTag.FindString(text); tag != "" {
				es = append(es, apitest.Entry{User: tag, Errors: []string{`[acl test error]: address "192.0.2.1:1" (protocol "tcp"): want: Drop, got: Accept`}})
			}
			if pass {
				if tag := sshTag.FindString(text); tag != "" {
					es = append(es, sshCanaryEntry(t, tag))
				}
			}
			apitest.TestsFailed(es...).Write(w)
		})
		return f
	}
}

func sshCanaryEntry(t *testing.T, tag string) apitest.Entry {
	t.Helper()
	s := apitest.SSHTestFailed(tag, "192.0.2.1", "192.0.2.1", "192.0.2.1", "canary")
	var body struct {
		Data []struct {
			User   string   `json:"user"`
			Errors []string `json:"errors"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(s.Body), &body); err != nil || len(body.Data) != 1 {
		t.Fatalf("SSH canary shape: %v", err)
	}
	return apitest.Entry{User: body.Data[0].User, Errors: body.Data[0].Errors}
}

// posturePolicy gates one rule on a posture attribute. It names no user.
const posturePolicy = "{\n\t\"tagOwners\": {\"tag:ci\": [\"autogroup:admin\"], \"tag:web\": [\"autogroup:admin\"]},\n\t\"acls\": [{\"action\": \"accept\", \"src\": [\"tag:ci\"], \"dst\": [\"tag:web:22\"], \"srcPosture\": [\"posture:diskEncrypted\"]}],\n}\n"

// Every golden of these cases belongs to a case, and every case has its goldens.
func TestEveryACLTestGoldenBelongsToACase(t *testing.T) {
	if *update {
		t.Skip("the goldens are being written")
	}
	want := map[string]bool{}
	for _, c := range aclTestLayoutCases {
		for _, rendering := range c.renderings() {
			want[goldenPath(c.name, rendering)] = true
		}
	}
	var have []string
	for _, pattern := range []string{
		filepath.Join(packageDir, "testdata", "layout", "acl-test-*.golden"),
		filepath.Join(packageDir, "testdata", "format", "acl-test-*.golden"),
	} {
		files, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		have = append(have, files...)
	}
	for _, f := range have {
		if !want[f] {
			t.Errorf("%s belongs to no case of aclTestLayoutCases", shown(f))
		}
		delete(want, f)
	}
	for f := range want {
		t.Errorf("%s is named by a case and does not exist", shown(f))
	}
}

// The goldens carry no login, no tailnet id and no path of this machine.
func TestTheGoldensCarryNoLoginAndNoTailnetValue(t *testing.T) {
	if *update {
		t.Skip("the goldens are being written")
	}
	banned := []string{"@", "example.com", "example.org", apitest.Tailnet, "ops/", "amy", os.TempDir(), "/private/", "/var/folders", "/Users/"}
	for _, c := range aclTestLayoutCases {
		for _, rendering := range c.renderings() {
			b, err := os.ReadFile(goldenPath(c.name, rendering))
			if err != nil {
				t.Fatalf("%s cannot be read (run TestEveryLayoutOfACLTestMatchesItsGolden with -update to write it)", shown(goldenPath(c.name, rendering)))
			}
			for _, s := range banned {
				if bytes.Contains(b, []byte(s)) {
					t.Errorf("%s (%s) contains %q", c.name, rendering, s)
				}
			}
		}
	}
}

// GitHub and markdown render the same report the text layout does: the verdict, the
// caveat, and Tailscale's line behind the notice. One failing case is enough to see
// all three; the goldens cover the rest.
func TestTheLayoutIsTheSameInTheGitHubAndMarkdownFormats(t *testing.T) {
	var fail aclTestCase
	for _, c := range aclTestLayoutCases {
		if c.name == "test-fail" {
			fail = c
		}
	}
	_, textOut, _ := fail.run(t, "text")
	_, github, _ := fail.run(t, "github")
	_, markdown, _ := fail.run(t, "markdown")
	for _, out := range []string{textOut, github, markdown} {
		if !strings.Contains(out, "FAILED · 1 destination not as asked") ||
			!strings.Contains(out, "untrusted text from the tailnet follows") ||
			!strings.Contains(out, `address "tag:web:22"`) {
			t.Errorf("a rendering dropped the verdict, the notice or the reason:\n%s", out)
		}
	}
	if strings.Contains(github, "##vso[") || strings.HasPrefix(strings.TrimSpace(github), "::") && !strings.Contains(github, "::error ") {
		t.Errorf("github output:\n%s", github)
	}
}

// The four statuses are the four exit codes, through the command, with no binary.
func TestACLTestExitCodesAreTheStatusOnTheCommandLine(t *testing.T) {
	for _, c := range aclTestLayoutCases {
		if c.name == "test-hostile" || c.name == "test-posture" {
			continue
		}
		code, _, stderr := c.run(t, "text")
		if code != c.exit {
			t.Errorf("%s: exit %d, want %d (%s)", c.name, code, c.exit, stderr)
		}
	}
	seen := map[int]bool{}
	for _, c := range aclTestLayoutCases {
		seen[c.exit] = true
	}
	for _, want := range []int{0, 1, 2, 9} {
		if !seen[want] {
			t.Errorf("no case exits %d", want)
		}
	}
}
