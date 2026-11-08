package cli

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// The scan in the formats --format offers: text, markdown and github are layouts of one
// Report, and json is the result itself. Everything is synthetic.

// hostileText is what a name, a tag or a version might hold in a tailnet that means harm to
// the page that shows it: a table cell, a link, an image, an HTML tag or an autolink, a code
// span or a fence, a heading, a list item, a mention, an issue, a bare address, an entity, an
// emphasis, a line break, and the characters that move a terminal.
var hostileText = []string{
	"a|b|c|d", "x\ny\nz", "[x](https://example.com)", "![i](https://example.com/i.png)", "<b>bold</b>", "`code`", "``` fence",
	"# heading", "<https://example.com>", "- item", "+ item", "1. item", "2) item", "@someone", "#123", "GH-12", "www.example.com",
	"&amp; &lt;b&gt;", "**bold**", "__bold__", "~~gone~~", `\`, "javascript:alert(1)", "<script>alert(1)</script>",
	"line1\r\nline2", "\u202eevil", "tab\there", "\x1b[31mred", "::error file=x::injected", "##vso[task.logissue]x", "***", "---", "> quote",
}

var (
	mdEscapePair = regexp.MustCompile(`\\.`)
	mdEntity     = regexp.MustCompile(`&(#[0-9]+|amp);`)
	mdBlockStart = regexp.MustCompile(`^([-+#>]|[0-9]+[.)])`)
)

// assertInertMarkdown fails unless every line of md is one of the shapes the layout writes (a
// bold verdict, a heading of its own, a list item) and the text in it holds, once the layout's
// own escapes are taken out, nothing Markdown reads as structure: no bracket, angle, pipe,
// backtick, emphasis mark, bang, tilde, at sign or backslash, no address and no line break, and
// nothing at the start of an item that would make it a list, a heading or a quote.
func assertInertMarkdown(t *testing.T, name, md string) {
	t.Helper()
	if strings.TrimSpace(md) == "" {
		t.Errorf("%s: no Markdown", name)
		return
	}
	for i, line := range strings.Split(md, "\n") {
		if line == "" {
			continue
		}
		for _, r := range line {
			if unicode.IsControl(r) || r == '\u202e' {
				t.Errorf("%s: line %d holds a control or bidirectional character %U: %q", name, i+1, r, line)
			}
		}
		var body string
		switch {
		case strings.HasPrefix(line, "**") && strings.HasSuffix(line, "**") && len(line) > 4:
			body = line[2 : len(line)-2]
		case strings.HasPrefix(line, "- "):
			body = line[2:]
			if mdBlockStart.MatchString(body) {
				t.Errorf("%s: line %d: an item starts a block of its own: %q", name, i+1, line)
			}
		case line == "Facts:" || line == "Findings:" || line == "Not checked:" || line == "Changes:" || line == registry.UntrustedReasonsNotice:
			continue
		default:
			t.Errorf("%s: line %d is not a shape the layout writes: %q", name, i+1, line)
			continue
		}
		plain := mdEntity.ReplaceAllString(mdEscapePair.ReplaceAllString(body, ""), "")
		if strings.ContainsAny(plain, "[]<>|`*_!~@\\") {
			t.Errorf("%s: line %d holds Markdown structure that was not escaped: %q", name, i+1, line)
		}
		if strings.Contains(plain, "://") || strings.Contains(strings.ToLower(plain), "www.") {
			t.Errorf("%s: line %d holds an address a page would link: %q", name, i+1, line)
		}
	}
}

// hostileOutput is a scan result whose every string is s, as a result would be if the
// framework's own escaping had not run: the layout must stand on its own.
func hostileOutput(s string) tools.SecurityScanOutput {
	row := tools.SecurityScanCoverage{Dimension: s, Source: s, Status: s, Explanation: s, Counts: &tools.SecurityScanRowCount{Rules: 1}}
	finding := func(applicability string) tools.SecurityScanFinding {
		return tools.SecurityScanFinding{Rule: s, RuleRevision: s, Device: s, DeviceRef: s, Applicability: applicability, Severity: s, Reason: s,
			EvidenceState: s, Confidence: s, Explanation: s, Verification: []string{s, s}, Evidence: []tools.SecurityScanEvidence{{Origin: s, AcquiredAt: s, Freshness: s, Error: s}}}
	}
	return tools.SecurityScanOutput{
		Status: s, Scope: s, Threshold: s, ObservedAt: s, GeneratedAt: s, TotalFindings: 5, Truncated: true,
		Counts:      tools.SecurityScanCounts{Affected: 1, PotentiallyAffected: 1, Unknown: 1, NotAffected: 1},
		AtThreshold: tools.SecurityScanThreshold{Affected: 1},
		Catalog:     tools.SecurityScanCatalog{Revision: 1, IssuedAt: s, ExpiresAt: s, Digest: s, Rules: 4, Approved: 1, Pending: 3},
		Intent:      tools.SecurityScanIntent{Source: s, Digest: s, Revision: s, Expectations: 2},
		Coverage:    []tools.SecurityScanCoverage{row, row},
		Findings:    []tools.SecurityScanFinding{finding("affected"), finding("potentially_affected"), finding("unknown"), finding("not_affected"), finding(s)},
	}
}

// Every string a result holds, laid out as Markdown, is text on the page and nothing else.
func TestSecurityScanMarkdownEscapesTailnetText(t *testing.T) {
	t.Run("a layout that trusts nothing it is given", func(t *testing.T) {
		for _, s := range hostileText {
			out := hostileOutput(s)
			var b strings.Builder
			if err := formatMarkdown(&b, out.Report(), formatOptions{}); err != nil {
				t.Fatal(err)
			}
			assertInertMarkdown(t, "Markdown of "+strconv.Quote(s), b.String())
		}
	})
	t.Run("a scan of devices with such IDs, through the command line", func(t *testing.T) {
		at := scanAt(t)
		// The ordinary device is first, and with the hostile ones it stays within the 20 devices
		// whose five findings each a scan lists (100): what is cut is not looked at.
		devs := []map[string]any{scanDevice(at, "nOLD01CNTRL", "1.28.2-t0123456ab", nil)}
		for _, id := range hostileText[:19] {
			devs = append(devs, scanDevice(at, id, "1.28.2-t0123456ab", nil))
		}
		h := scanHarness(t, at, devs...)
		if code := h.run("security", "scan", "fleet", "--format", "markdown"); code != 8 {
			t.Fatalf("exit %d: %s", code, h.err)
		}
		md := h.out.String()
		assertInertMarkdown(t, "Markdown of the scan", md)
		// The premise: the hostile devices are in the page (cut to four characters), so the
		// check above looked at them, and so is the ordinary one.
		for _, shown := range []string{"nOLD…", `a\|b…`, `\[x\](…`, `\!\[i\]…`, `\<b\>b…`, `\<htt…`, "&#64;som…", "www&#46;…"} {
			if !strings.Contains(md, shown) {
				t.Errorf("the premise: %q is not in the page, so the check did not look at it", shown)
			}
		}
		if strings.Contains(md, "example.com") || strings.Contains(md, "<b>") {
			t.Errorf("the page holds a link or a tag that was cut from an ID:\n%.2000s", md)
		}
	})
}

// The three views of one scan agree: JSON, text and Markdown give one status, one set of
// counts, one total, one number of listed findings, the same cut, and the command one exit.
func TestSecurityScanFormatsAgree(t *testing.T) {
	at := scanAt(t)
	var many []map[string]any
	for i := 0; i < 120; i++ {
		many = append(many, scanDevice(at, "nOLD"+strconv.Itoa(i)+"CNTRL", "1.28.2-t0123456ab", nil))
	}
	cases := map[string]struct {
		devs      []map[string]any
		args      []string
		code      int
		truncated bool
	}{
		"findings, cut at 100":       {many, nil, 8, true},
		"a finding, not cut":         {fleet(at), nil, 8, false},
		"nothing found, incomplete":  {[]map[string]any{scanDevice(at, "nNEW01CNTRL", "1.102.5-t0123456ab", nil)}, nil, 1, false},
		"a threshold above the find": {fleet(at), []string{"--threshold", "high"}, 1, false},
	}
	for name, c := range cases {
		run := func(extra ...string) (int, string, string) {
			h := scanHarness(t, at, c.devs...)
			code := h.run(append(append([]string{"security", "scan", "fleet"}, c.args...), extra...)...)
			return code, h.out.String(), h.err.String()
		}
		jcode, jtext, _ := run("--json")
		tcode, text, _ := run()
		mcode, md, _ := run("--format", "markdown")
		if jcode != c.code || tcode != c.code || mcode != c.code {
			t.Errorf("%s: exit codes json %d, text %d, markdown %d, want %d", name, jcode, tcode, mcode, c.code)
		}
		j := decode(t, []byte(jtext))
		counts := j["counts"].(map[string]any)
		want := []string{
			j["scope"].(string), j["status"].(string), num(counts["affected"]), num(counts["potentiallyAffected"]), num(counts["unknown"]),
			num(counts["notAffected"]), num(j["totalFindings"]), strconv.Itoa(len(j["findings"].([]any))),
		}
		if j["truncated"] != c.truncated {
			t.Errorf("%s: JSON truncated %v, want %v", name, j["truncated"], c.truncated)
		}
		verdict := regexp.MustCompile(`(\w+) scan: (\w+); (\d+) affected, (\d+) potentially affected, (\d+) unknown, (\d+) not affected \((\d+) findings, (\d+) listed\)`)
		for layout, body := range map[string]string{"text": text, "markdown": md} {
			m := verdict.FindStringSubmatch(body)
			if m == nil || strings.Join(m[1:], ",") != strings.Join(want, ",") {
				t.Errorf("%s: the %s verdict says %v, the JSON says %v\n%.600s", name, layout, m, want, body)
			}
			cut := strings.Contains(body, "output truncated: showing "+strconv.Itoa(len(j["findings"].([]any)))+" of "+num(j["totalFindings"])+" findings")
			if cut != c.truncated {
				t.Errorf("%s: the %s says the output is cut: %v, want %v", name, layout, cut, c.truncated)
			}
		}
		// One finding line each: in the text layout a line that starts with a severity word,
		// in Markdown the items of the Findings block.
		listed := len(j["findings"].([]any))
		if n := len(devicesOfLines(text, "")); n == 0 {
			t.Errorf("%s: the text layout lists no finding", name)
		}
		if got := countFindingLines(text, ""); got != listed {
			t.Errorf("%s: the text layout lists %d findings, JSON %d", name, got, listed)
		}
		if got := countFindingLines(md, "- "); got != listed {
			t.Errorf("%s: the Markdown lists %d findings, JSON %d", name, got, listed)
		}
		assertInertMarkdown(t, name, md)
	}
}

// num is a JSON number as a decimal text.
func num(v any) string { return strconv.Itoa(int(v.(float64))) }

// countFindingLines counts the lines that start with prefix and a severity word.
func countFindingLines(layout, prefix string) int {
	n := 0
	for _, line := range strings.Split(layout, "\n") {
		for _, sev := range []string{"error: ", "warning: ", "notice: "} {
			if strings.HasPrefix(line, prefix+sev) {
				n++
			}
		}
	}
	return n
}

// Markdown is one more layout of the same scan, through the global formatter path: the
// verdict in bold, the facts and the findings as lists, and the rest of the command as in text.
func TestSecurityScanMarkdownLayout(t *testing.T) {
	at := scanAt(t)
	h := scanHarness(t, at, fleet(at)...)
	if code := h.run("security", "scan", "fleet", "--format", "markdown"); code != 8 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	md := h.out.String()
	for _, want := range []string{
		"**fleet scan: partial; 1 affected, 0 potentially affected, 8 unknown, 1 not affected (10 findings, 10 listed)**\n\nFacts:\n\n- threshold low: 1 affected and 0 potentially affected at or above it\n",
		"- catalog: revision ", "- coverage intent: not\\_requested - intent not requested: no intent set is configured\n", "\nFindings:\n\n- error: CVE-2022-41925 · nOLD… · affected · severity low · ",
		"- notice: CVE-2022-41925 · nNEW… · not\\_affected · severity low · ",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("the Markdown lacks %q:\n%.1500s", want, md)
		}
	}
	// stderr says why the exit is 8, as in every layout, and the page itself is on stdout only.
	if !strings.Contains(h.err.String(), "findings_present") {
		t.Errorf("stderr: %q", h.err)
	}
	// --quiet keeps the page back only when the command succeeds.
	h = scanHarness(t, at, fleet(at)...)
	if code := h.run("security", "scan", "fleet", "--format", "markdown", "--quiet"); code != 8 || h.out.Len() == 0 {
		t.Errorf("--quiet with a finding: exit %d, %d bytes", code, h.out.Len())
	}
}

// The github layout is offered with the same report. Every annotation is one a runner can
// take as ours, and no line of ours starts a command, whatever the IDs hold.
func TestSecurityScanGitHubFormatIsInert(t *testing.T) {
	at := scanAt(t)
	var devs []map[string]any
	for _, id := range hostileText {
		devs = append(devs, scanDevice(at, id, "1.28.2-t0123456ab", nil))
	}
	h := scanHarness(t, at, devs...)
	if code := h.run("security", "scan", "fleet", "--format", "github"); code != 8 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	annotations := 0
	for _, line := range strings.Split(h.out.String(), "\n") {
		switch {
		case strings.HasPrefix(line, "::error ") || strings.HasPrefix(line, "::warning ") || strings.HasPrefix(line, "::notice "):
			annotations++
			if strings.Count(line, "\n") != 0 || strings.Contains(line, "injected") && strings.Contains(line, "::error file=x") {
				t.Errorf("an annotation holds a command of the IDs: %q", line)
			}
		case regexp.MustCompile(`^\s*(::|##)`).MatchString(line):
			t.Errorf("a line starts a command: %q", line)
		}
	}
	if annotations == 0 || annotations > 30 {
		t.Errorf("%d annotations, want 1 to 30 (ten of each severity at most)", annotations)
	}
}
