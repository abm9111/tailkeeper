package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/tailscale/hujson"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// `security explain` through the command line: exit codes, formats, privacy and the audit line.
// The validate endpoint is a model that answers the posted text as the real one does for the
// pairs the test says the live policy lets through. Everything is synthetic.

const cliExplainPolicy = `// zq-policy-comment: policy text that no output may repeat
{
	"groups": {"group:example-admins": ["zq-policy-member@example.com"]},
	"tagOwners": {"tag:example-db": ["group:example-admins"], "tag:example-web": ["group:example-admins"]},
	"acls": [
		{"action": "accept", "src": ["group:example-admins"], "dst": ["tag:example-db:22"]},
	],
}`

const cliExplainIntent = `{
	"tests": [
		{"src": "group:example-admins", "accept": ["tag:example-db:22"]},
		{"src": "tag:example-web", "deny": ["tag:example-db:22"]},
	],
}`

type cliModel struct {
	mu         sync.Mutex
	allow      map[string]bool
	omitCanary bool
}

var (
	cliCanaryRE    = regexp.MustCompile(`tag:tailkeeper-canary-[0-9a-f]{8}`)
	cliCanaryLine  = `[acl test error]: address "192.0.2.1:1" (protocol "tcp"): want: Drop, got: Accept`
	cliExplainAt   = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	cliDetailsPath = "/api/v2/tailnet/" + apitest.Tailnet + "/acl"
)

// explainHarness is a harness whose API serves the live policy and the validate endpoint.
func explainHarness(t *testing.T, policy string, m *cliModel) *harness {
	t.Helper()
	return explainHarnessOn(t, apitest.New(t), policy, m)
}

// explainHarnessOn is explainHarness on a fake the test holds.
func explainHarnessOn(t *testing.T, f *apitest.Fake, policy string, m *cliModel) *harness {
	t.Helper()
	f.Handle("GET", cliDetailsPath, func(w http.ResponseWriter, r *http.Request) {
		etag := api.ETagOf([]byte(policy))
		if r.URL.Query().Get("details") == "true" {
			apitest.DetailsOK(policy, etag, nil, nil).Write(w)
			return
		}
		apitest.PolicyText(policy, etag).Write(w)
	})
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		defer m.mu.Unlock()
		m.answer(body).Write(w)
	})
	h := newHarness(t, f)
	h.app.Env.Now = func() time.Time { return cliExplainAt }
	return h
}

func (m *cliModel) answer(body []byte) apitest.Shape {
	std, err := hujson.Standardize(body)
	if err != nil {
		return apitest.BareMessage200("not HuJSON")
	}
	var s struct {
		Tests []struct {
			Src    string   `json:"src"`
			Accept []string `json:"accept"`
			Deny   []string `json:"deny"`
		} `json:"tests"`
	}
	if json.Unmarshal(std, &s) != nil {
		return apitest.BareMessage200("not a policy")
	}
	var entries []apitest.Entry
	for _, test := range s.Tests {
		var errs []string
		if cliCanaryRE.MatchString(test.Src) {
			if !m.omitCanary {
				entries = append(entries, apitest.Entry{User: test.Src, Errors: []string{cliCanaryLine}})
			}
			continue
		}
		for _, d := range test.Accept {
			if !m.allow[test.Src+"|"+d] {
				errs = append(errs, fmt.Sprintf(`[acl test error]: address %q: want: Accept, got: Drop`, d))
			}
		}
		for _, d := range test.Deny {
			if m.allow[test.Src+"|"+d] {
				errs = append(errs, fmt.Sprintf(`[acl test error]: address %q: want: Drop, got: Accept`, d))
			}
		}
		if len(errs) > 0 {
			entries = append(entries, apitest.Entry{User: test.Src, Errors: errs})
		}
	}
	if len(entries) == 0 {
		return apitest.TestsPassEmptyObject()
	}
	return apitest.TestsFailed(entries...)
}

func adminCLIModel() *cliModel {
	return &cliModel{allow: map[string]bool{"group:example-admins|tag:example-db:22": true}}
}

func (h *harness) explain(t *testing.T, path string, extra ...string) int {
	t.Helper()
	h.out.Reset()
	h.err.Reset()
	// The surface keeps the audit record of each validation request, as the command line does.
	if h.app.Env.RecordObservation == nil {
		h.app.Env.RecordObservation = h.app.RecordObservation
	}
	args := []string{"security", "explain"}
	if path != "" {
		args = append(args, "--invariants", path)
	}
	return h.run(append(args, extra...)...)
}

func TestExplainExitCodesThroughTheCommandLine(t *testing.T) {
	path := writeIntent(t, cliExplainIntent)
	t.Run("met is 0", func(t *testing.T) {
		h := explainHarness(t, cliExplainPolicy, adminCLIModel())
		if code := h.explain(t, path); code != 0 {
			t.Fatalf("exit %d: %s %s", code, h.out, h.err)
		}
		if !strings.Contains(h.out.String(), "explain: complete; 2 met, 0 unmet") {
			t.Errorf("output:\n%s", h.out)
		}
	})
	t.Run("unmet is 8, and the line says what it is", func(t *testing.T) {
		m := adminCLIModel()
		m.allow["tag:example-web|tag:example-db:22"] = true
		h := explainHarness(t, cliExplainPolicy, m)
		if code := h.explain(t, path, "--json"); code != 8 {
			t.Fatalf("exit %d: %s %s", code, h.out, h.err)
		}
		if !strings.Contains(h.err.String(), "findings_present: an expectation of the intent set is unmet") || strings.Contains(h.err.String(), "threshold") {
			t.Errorf("stderr: %q", h.err)
		}
		out := decode(t, h.out.Bytes())
		if out["status"] != "incomplete" || out["counts"].(map[string]any)["unmet"] != float64(1) {
			t.Errorf("status %v counts %v", out["status"], out["counts"])
		}
	})
	t.Run("unknown is 1", func(t *testing.T) {
		m := adminCLIModel()
		m.omitCanary = true
		h := explainHarness(t, cliExplainPolicy, m)
		if code := h.explain(t, path); code != 1 {
			t.Fatalf("exit %d: %s %s", code, h.out, h.err)
		}
	})
	t.Run("no intent set is 1, with one sentence, and asks nothing", func(t *testing.T) {
		f := apitest.New(t)
		h := newHarness(t, f)
		h.app.Env.Now = func() time.Time { return cliExplainAt }
		if code := h.explain(t, ""); code != 1 {
			t.Fatalf("exit %d: %s %s", code, h.out, h.err)
		}
		if !strings.Contains(h.out.String(), "no intent set: nothing explained") || len(f.Requests()) != 0 {
			t.Errorf("output %q, %d requests", h.out, len(f.Requests()))
		}
	})
	t.Run("an unknown ID is a usage error, 2", func(t *testing.T) {
		h := explainHarness(t, cliExplainPolicy, adminCLIModel())
		if code := h.explain(t, path, "--only", "network-7"); code != 2 {
			t.Fatalf("exit %d: %s %s", code, h.out, h.err)
		}
		if strings.Contains(h.err.String(), "network-7") {
			t.Errorf("the refusal repeats what was typed: %q", h.err)
		}
	})
	t.Run("a configured file that cannot be read is config_invalid, 6", func(t *testing.T) {
		h := explainHarness(t, cliExplainPolicy, adminCLIModel())
		h.app.Env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: "/no/such/file.hujson"}}}
		if code := h.explain(t, ""); code != 6 {
			t.Fatalf("exit %d: %s %s", code, h.out, h.err)
		}
	})
	t.Run("no credential is 5", func(t *testing.T) {
		h := newHarness(t, nil)
		if code := h.explain(t, path); code != 5 {
			t.Fatalf("exit %d: %s %s", code, h.out, h.err)
		}
	})
	t.Run("--json with another format is 2", func(t *testing.T) {
		h := explainHarness(t, cliExplainPolicy, adminCLIModel())
		if code := h.explain(t, path, "--json", "--format", "markdown"); code != 2 {
			t.Fatalf("exit %d: %s %s", code, h.out, h.err)
		}
	})
}

// The command is the owner's: its help says it is not an MCP tool, and the command list names it.
func TestExplainHelpSaysItIsNotAnMCPTool(t *testing.T) {
	h := explainHarness(t, cliExplainPolicy, adminCLIModel())
	if code := h.run("security", "explain", "--help"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	help := h.err.String()
	if !strings.Contains(help, "Owner command line only: not an MCP tool") || strings.Contains(help, "MCP tool: security_explain") {
		t.Errorf("help:\n%s", help)
	}
	for _, flag := range []string{"-invariants", "-only", "-format", "-json", "-quiet"} {
		if !strings.Contains(help, flag) {
			t.Errorf("help has no %s", flag)
		}
	}
	for _, flag := range []string{"no-invariants", "scope", "threshold", "fail-on"} {
		if strings.Contains(help, flag) {
			t.Errorf("help offers %s, which this command does not take", flag)
		}
	}
	h.out.Reset()
	h.err.Reset()
	if code := h.run("help"); code != 0 || !strings.Contains(h.out.String(), "security") || !strings.Contains(h.out.String(), "explain | export | redact | replay | scan") {
		t.Errorf("help lists: %s", h.out)
	}
	h.out.Reset()
	h.err.Reset()
	if code := h.run("docs"); code != 0 || strings.Contains(h.out.String(), "security_explain") || strings.Contains(h.out.String(), "security explain") {
		t.Errorf("the generated reference lists the owner command (exit %d)", code)
	}
}

func TestExplainFormats(t *testing.T) {
	path := writeIntent(t, cliExplainIntent)
	m := adminCLIModel()
	m.allow["tag:example-web|tag:example-db:22"] = true
	for _, format := range []string{"text", "markdown", "github", "json"} {
		h := explainHarness(t, cliExplainPolicy, m)
		if code := h.explain(t, path, "--format", format); code != 8 {
			t.Fatalf("%s: exit %d: %s %s", format, code, h.out, h.err)
		}
		out := h.out.String()
		switch format {
		case "markdown":
			assertInertExplainMarkdown(t, "Markdown of the explanation", out)
			if !strings.Contains(out, "network-2") || !strings.Contains(out, "unmet") {
				t.Errorf("markdown:\n%s", out)
			}
		case "github":
			n := 0
			for _, line := range strings.Split(out, "\n") {
				switch {
				case strings.HasPrefix(line, "::error ") || strings.HasPrefix(line, "::warning ") || strings.HasPrefix(line, "::notice "):
					n++
				case regexp.MustCompile(`^\s*(::|##)`).MatchString(line):
					t.Errorf("a line starts a command that is not an annotation: %q", line)
				}
			}
			if n == 0 || n > 30 {
				t.Errorf("%d annotations", n)
			}
		case "json":
			if v := decode(t, h.out.Bytes()); v["status"] != "incomplete" {
				t.Errorf("json: %v", v)
			}
		default:
			if !strings.Contains(out, "network-2 · network · ") || !strings.Contains(out, "the live policy allowed it") {
				t.Errorf("text:\n%s", out)
			}
		}
	}
}

// The distinctive words of the synthetic login and policy: none of them is in any output, in the
// audit line, or in the error of a command.
const (
	cliLogin     = "zq-login-owner@example.com"
	cliLoginWord = "zq-login-owner"
)

// TestExplainOutputMasksLoginsAndHidesPolicyText is the privacy of the command: a login in the
// intent appears masked, or as a pseudonym with a key, in every format and never in the audit
// line; the policy's text, comments and members, and the intent file's path, are nowhere.
func TestExplainOutputMasksLoginsAndHidesPolicyText(t *testing.T) {
	policy := strings.Replace(cliExplainPolicy, `"tag:example-web": ["group:example-admins"]`, `"tag:example-web": ["group:example-admins", "`+cliLogin+`"]`, 1)
	intent := `{"tests": [
		{"src": "` + cliLogin + `", "accept": ["tag:example-db:22"]},
		{"src": "tag:example-web", "deny": ["tag:example-db:22"]},
	]}`
	for _, keyed := range []bool{false, true} {
		t.Run(fmt.Sprintf("a key: %v", keyed), func(t *testing.T) {
			dir := t.TempDir()
			path := dir + "/zq-path-marker-intent.hujson"
			if err := os.WriteFile(path, []byte(intent), 0o600); err != nil {
				t.Fatal(err)
			}
			m := adminCLIModel()
			m.allow[cliLogin+"|tag:example-db:22"] = false // the owner's login is unmet: the page lists it
			m.allow["tag:example-web|tag:example-db:22"] = true
			outputs := map[string]string{}
			for _, format := range []string{"text", "json", "markdown", "github"} {
				h := explainHarness(t, policy, m)
				if keyed {
					withKey(h)
				}
				if code := h.explain(t, path, "--format", format); code != 8 {
					t.Fatalf("%s: exit %d: %s %s", format, code, h.out, h.err)
				}
				outputs[format] = h.out.String() + h.err.String()
				if format == "json" {
					audit, err := os.ReadFile(h.app.AuditPath)
					if err != nil {
						t.Fatal(err)
					}
					outputs["audit"] = string(audit)
				}
			}
			for name, text := range outputs {
				for _, needle := range []string{cliLoginWord, "zq-policy-comment", "zq-policy-member", "zq-path-marker", dir, "tailkeeper-canary"} {
					if strings.Contains(text, needle) {
						t.Errorf("%s holds %q", name, needle)
					}
				}
				if !strings.Contains(text, "network-1") && name != "audit" {
					t.Errorf("%s does not hold the expectation: the check looked at nothing", name)
				}
			}
			masked := regexp.MustCompile(`z…@example\.com`)
			for _, format := range []string{"text", "json", "markdown", "github"} {
				if !masked.MatchString(strings.ReplaceAll(outputs[format], `\`, "")) {
					t.Errorf("%s: the login is not shown masked (z…@example.com): the premise failed", format)
				}
				if keyed && !strings.Contains(outputs[format], "[p:") {
					t.Errorf("%s: with a privacy key the masked login carries a pseudonym", format)
				}
				if !keyed && strings.Contains(outputs[format], "[p:") {
					t.Errorf("%s: a pseudonym without a key", format)
				}
			}
		})
	}
}

// spanItem matches the end of a list item that carries text of the tailnet: the severity, and
// the text in a code span that runs to the end of the line.
var spanItem = regexp.MustCompile("^- (`[^`]+` )?(error|warning|notice): (`+)(.*)$")

// assertInertExplainMarkdown is assertInertMarkdown for a layout whose findings hold text of the
// tailnet: such an item ends in a code span, which Markdown reads nothing in. The span must be
// well formed: its fence is longer than any run of backticks inside it, it closes at the end of
// the line, and it holds no control character. What is left of the item once the span is taken out
// is checked as any item is, and every other line as assertInertMarkdown checks it.
func assertInertExplainMarkdown(t *testing.T, name, md string) {
	t.Helper()
	var rest []string
	for i, line := range strings.Split(md, "\n") {
		m := spanItem.FindStringSubmatch(line)
		if m == nil {
			rest = append(rest, line)
			continue
		}
		fence, body := m[3], m[4]
		if !strings.HasSuffix(body, fence) {
			t.Errorf("%s: line %d: a code span does not close at the end of the line: %q", name, i+1, line)
			continue
		}
		inside := strings.TrimSuffix(body, fence)
		if strings.Contains(strings.TrimPrefix(strings.TrimSuffix(inside, " "), " "), fence) {
			t.Errorf("%s: line %d: a run of backticks as long as the fence is inside the span: %q", name, i+1, line)
		}
		for _, r := range line {
			if unicode.IsControl(r) || r == '\u202e' {
				t.Errorf("%s: line %d holds a control or bidirectional character %U", name, i+1, r)
			}
		}
		// The rest of the item is a severity and an empty message: a shape the layout writes.
		loc := ""
		if m[1] != "" {
			loc = m[1]
		}
		rest = append(rest, "- "+strings.ReplaceAll(loc, "`", "")+m[2]+": x")
	}
	assertInertMarkdown(t, name, strings.Join(rest, "\n"))
}

// jsonQuote writes s as a JSON string: the escapes of Go's quoting are not all JSON's.
func jsonQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// hostileExplain is an explanation whose every string is s, as it would be if the framework's own
// escaping had not run: the layout must stand on its own.
func hostileExplain(s string) tools.SecurityExplainOutput {
	rule := tools.SecurityExplainRule{Section: s, Index: 1, Line: 3, Column: 4, Source: s, Destination: s, Ports: s, Broad: true, Traffic: s}
	cell := func(verdict string) tools.SecurityExplainCell {
		return tools.SecurityExplainCell{Expect: s, Destination: s, User: s, Verdict: verdict, Observed: s, Reason: s}
	}
	row := func(status string) tools.SecurityExplainRow {
		return tools.SecurityExplainRow{ID: s, Kind: s, Source: s, Status: status, Cells: []tools.SecurityExplainCell{cell("unmet"), cell("unknown"), cell(s)},
			PastCap: 2, Candidates: []tools.SecurityExplainRule{rule}, CandidatesOmitted: 3, Limits: []string{s, "posture"}}
	}
	return tools.SecurityExplainOutput{
		Status: s, Intent: tools.SecurityExplainIntent{Source: s, Digest: s, Revision: s, Expectations: 3, Selected: 2}, PolicyVersion: s, EvaluatedAt: s,
		Counts: tools.SecurityExplainCounts{Total: 5, Unmet: 1, Unknown: 1, Met: 1, MetWithLimits: 1, NotEvaluated: 1}, PairsJudged: 4, PairsPastCap: 2,
		Expectations: []tools.SecurityExplainRow{row("unmet"), row("unknown"), row(s)}, Omitted: 2,
		Blast: []tools.SecurityExplainBlast{{Source: s, Heading: s, Reaches: []tools.SecurityExplainReach{{Kind: s, Destination: s, User: s, Expectation: s}}, Broad: []tools.SecurityExplainRule{rule}, Tags: []string{s}, TagsOmitted: 1}},
		Notes: []string{s},
	}
}

// Every string of an explanation, laid out as Markdown, is text on the page and nothing else.
func TestExplainMarkdownEscapesTailnetText(t *testing.T) {
	t.Run("a layout that trusts nothing it is given", func(t *testing.T) {
		for _, s := range hostileText {
			var b strings.Builder
			if err := formatMarkdown(&b, hostileExplain(s).Report(), formatOptions{}); err != nil {
				t.Fatal(err)
			}
			assertInertExplainMarkdown(t, "Markdown of "+strconv.Quote(s), b.String())
		}
	})
	t.Run("an intent whose sources and destinations are such strings, through the command line", func(t *testing.T) {
		var tests []string
		for _, s := range hostileText[:19] {
			tests = append(tests, fmt.Sprintf(`{"src": %s, "accept": [%s]}`, jsonQuote(s), jsonQuote(s+":22")))
		}
		path := writeIntent(t, `{"tests": [`+strings.Join(tests, ",")+`]}`)
		h := explainHarness(t, cliExplainPolicy, &cliModel{allow: map[string]bool{}})
		if code := h.explain(t, path, "--format", "markdown"); code != 8 {
			t.Fatalf("exit %d: %s", code, h.err)
		}
		md := h.out.String()
		assertInertExplainMarkdown(t, "Markdown of the explanation", md)
		// The premise: the strings are in the page, each inside a code span, where a page reads
		// nothing, so the check above looked at them.
		for _, shown := range []string{"`network-1 · network · a|b|c|d · unmet`", "`network-3 · network · [x](https://example.com) · unmet`",
			"`network-5 · network · <b>bold</b> · unmet`", "`network-14 · network · @someone · unmet`"} {
			if !strings.Contains(md, shown) {
				t.Errorf("the premise: %q is not in the page, so the check did not look at it", shown)
			}
		}
		for _, line := range strings.Split(md, "\n") {
			if (strings.Contains(line, "](http") || strings.Contains(line, "<b>")) && !spanItem.MatchString(line) {
				t.Errorf("a link or a tag outside a code span: %q", line)
			}
		}
	})
	t.Run("a rule for * whose traffic is such a string, through the command line", func(t *testing.T) {
		// A grant's ip entry is a word of the policy's: the blast radius quotes it, behind the
		// notice, as a code span, and the page holds no link or tag of it outside one.
		policy := `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["tcp:22<b>bold</b> [x](https://example.com) |a|b"]}]}`
		path := writeIntent(t, `{"tests": [{"src": "tag:example-web", "deny": ["tag:example-db:22"]}]}`)
		h := explainHarness(t, policy, &cliModel{allow: map[string]bool{"tag:example-web|tag:example-db:22": true}})
		if code := h.explain(t, path, "--format", "markdown"); code != 8 {
			t.Fatalf("exit %d: %s", code, h.err)
		}
		md := h.out.String()
		assertInertExplainMarkdown(t, "Markdown of the explanation", md)
		quoted := 0
		for _, line := range strings.Split(md, "\n") {
			if strings.Contains(line, "every destination on") {
				quoted++
				if !spanItem.MatchString(line) {
					t.Errorf("the line that quotes the traffic is not a code span item: %q", line)
				}
			}
			if (strings.Contains(line, "](http") || strings.Contains(line, "<b>")) && !spanItem.MatchString(line) {
				t.Errorf("a link or a tag outside a code span: %q", line)
			}
		}
		if quoted != 1 {
			t.Errorf("the premise: %d lines quote the traffic, want 1, so the check looked at it", quoted)
		}
	})
	t.Run("the GitHub layout starts no command", func(t *testing.T) {
		var tests []string
		for _, s := range hostileText {
			tests = append(tests, fmt.Sprintf(`{"src": %s, "accept": [%s]}`, jsonQuote(s), jsonQuote(s+":22")))
		}
		path := writeIntent(t, `{"tests": [`+strings.Join(tests, ",")+`]}`)
		h := explainHarness(t, cliExplainPolicy, &cliModel{allow: map[string]bool{}})
		if code := h.explain(t, path, "--format", "github"); code != 8 {
			t.Fatalf("exit %d: %s", code, h.err)
		}
		for _, line := range strings.Split(h.out.String(), "\n") {
			if regexp.MustCompile(`^\s*(::|##)`).MatchString(line) && !regexp.MustCompile(`^::(error|warning|notice) `).MatchString(line) {
				t.Errorf("a line starts a command: %q", line)
			}
			if strings.Contains(line, "::error file=x") {
				t.Errorf("an annotation holds a command of the strings: %q", line)
			}
		}
	})
}

// The audit line of the command: the tool, the intent's source, the start of its digest by the
// rule of the digests and the counts; no text of the intent, the policy or a path.
func TestExplainAuditLine(t *testing.T) {
	read := func(t *testing.T, h *harness) map[string]any {
		t.Helper()
		data, err := os.ReadFile(h.app.AuditPath)
		if err != nil {
			t.Fatal(err)
		}
		var last map[string]any
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var v map[string]any
			if json.Unmarshal([]byte(line), &v) == nil && v["tool"] == "security_explain" {
				last = v
			}
		}
		if last == nil {
			t.Fatalf("no line for the command in the log:\n%s", data)
		}
		return last
	}
	path := writeIntent(t, cliExplainIntent)
	t.Run("a keyed digest while masked", func(t *testing.T) {
		m := adminCLIModel()
		m.allow["tag:example-web|tag:example-db:22"] = true
		h := withKey(explainHarness(t, cliExplainPolicy, m))
		if code := h.explain(t, path); code != 8 {
			t.Fatalf("exit %d: %s", code, h.err)
		}
		line := read(t, h)
		d := keyedDigest(cliExplainIntent)
		want := map[string]any{"intent": "cli", "digest": revisionOfDigest(d), "expectations": float64(2), "met": float64(1), "unmet": float64(1),
			"unknown": float64(0), "limited": float64(0), "not_evaluated": float64(0), "tool": "security_explain", "status": "ok"}
		for k, v := range want {
			if line[k] != v {
				t.Errorf("%s = %v, want %v", k, line[k], v)
			}
		}
		raw, _ := json.Marshal(line)
		for _, needle := range append(cliIntentNeedles, "example-db", "example-web", "example-admins", path, "zq-policy") {
			if strings.Contains(string(raw), needle) {
				t.Errorf("the audit line holds %q: %s", needle, raw)
			}
		}
		if strings.Contains(string(raw), sha256Hex(cliExplainIntent)) {
			t.Error("the audit line holds the plain digest while personal data is masked")
		}
	})
	t.Run("no digest while masked with no key", func(t *testing.T) {
		h := explainHarness(t, cliExplainPolicy, adminCLIModel())
		if code := h.explain(t, path); code != 0 {
			t.Fatalf("exit %d: %s", code, h.err)
		}
		line := read(t, h)
		if _, ok := line["digest"]; ok || line["intent"] != "cli" {
			t.Errorf("line = %v, want no digest", line)
		}
	})
	t.Run("the plain digest with personalData show", func(t *testing.T) {
		h := explainHarness(t, cliExplainPolicy, adminCLIModel())
		h.app.Env.Config = &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}
		if code := h.explain(t, path); code != 0 {
			t.Fatalf("exit %d: %s", code, h.err)
		}
		if line := read(t, h); line["digest"] != sha256Hex(cliExplainIntent)[:12] {
			t.Errorf("digest = %v", line["digest"])
		}
	})
	t.Run("no intent is recorded as none", func(t *testing.T) {
		h := newHarness(t, apitest.New(t))
		if code := h.explain(t, ""); code != 1 {
			t.Fatalf("exit %d: %s", code, h.err)
		}
		if line := read(t, h); line["intent"] != "none" || line["expectations"] != float64(0) {
			t.Errorf("line = %v", line)
		}
	})
	t.Run("the log still verifies", func(t *testing.T) {
		h := explainHarness(t, cliExplainPolicy, adminCLIModel())
		h.explain(t, path)
		h.out.Reset()
		if code := h.run("audit", "verify"); code != 0 {
			t.Errorf("audit verify: exit %d: %s %s", code, h.out, h.err)
		}
	})
	t.Run("audit reads none: no request is sent, and nothing is known", func(t *testing.T) {
		f := apitest.New(t)
		m := adminCLIModel()
		h := explainHarnessOn(t, f, cliExplainPolicy, m)
		h.app.AuditReads = "none"
		if code := h.explain(t, path); code != 1 {
			t.Fatalf("exit %d: %s %s", code, h.out, h.err)
		}
		for _, r := range f.Requests() {
			if r.Method == "POST" {
				t.Errorf("a validation request was sent with audit.reads none: the attempt cannot be recorded")
			}
		}
		if !strings.Contains(h.out.String(), "2 unknown") || !strings.Contains(h.out.String(), "the audit log could not record the validation request") {
			t.Errorf("output:\n%s", h.out)
		}
	})
	t.Run("each request has an attempt and an outcome in the log, and no text", func(t *testing.T) {
		h := explainHarness(t, cliExplainPolicy, adminCLIModel())
		if code := h.explain(t, path); code != 0 {
			t.Fatalf("exit %d: %s", code, h.err)
		}
		data, err := os.ReadFile(h.app.AuditPath)
		if err != nil {
			t.Fatal(err)
		}
		var collect []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var v map[string]any
			if json.Unmarshal([]byte(line), &v) == nil && v["event"] == "collect" {
				collect = append(collect, v)
			}
		}
		if len(collect) != 2 || collect[0]["phase"] != "attempt" || collect[1]["phase"] != "outcome" || collect[0]["source"] != "validate_network" || collect[1]["source"] != "validate_network" {
			t.Fatalf("collect lines = %v, want an attempt and an outcome of validate_network", collect)
		}
		if collect[1]["outcome"] != "ok" || collect[1]["observed"] != float64(2) || collect[0]["tool"] != "security_explain" || collect[0]["scope"] != "fleet" {
			t.Errorf("outcome line = %v", collect[1])
		}
		for _, needle := range append(cliIntentNeedles, "example-db", "example-web", "example-admins", path, "zq-policy") {
			if strings.Contains(fmt.Sprint(collect), needle) {
				t.Errorf("a collect line holds %q: %v", needle, collect)
			}
		}
		h.out.Reset()
		if code := h.run("audit", "verify"); code != 0 {
			t.Errorf("audit verify: exit %d: %s %s", code, h.out, h.err)
		}
	})
}
