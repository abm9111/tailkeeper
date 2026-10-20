package tools_test

import (
	"strings"
	"testing"
)

const waiverChangelog = "# Changelog\n\nPreamble about `pre_tool` and `$.pre`.\n\n## 0.6.0 \u2014 unreleased\n\n- `acl_test` `$.status` changed.\n## 0.5.0 \u2014 2026-10-16\n\n`dns_get` `$.x` is only here.\n"

// A waiver line needs six fields, the reason may be one word or many and is kept
// whole, a bad line does not stop the next one from being read, and a problem names
// the line it is on (counting comments and blanks).
func TestCheckWaiversParsesLinesOneByOne(t *testing.T) {
	lines := []string{
		"# comment",
		"",
		"2026-10-20 acl_test output $.status enum-value-removed moved",
		"2026-10-20 acl_test output $.status",
		"2026-10-20 acl_test output $.status removed-property one two three",
		"nonsense",
	}
	problems, ws := checkWaivers(lines, waiverChangelog)
	if len(ws) != 2 || ws[0].Reason != "moved" || ws[1].Reason != "one two three" || ws[1].Rule != "removed-property" || ws[0].Date != "2026-10-20" {
		t.Errorf("waivers = %+v", ws)
	}
	if len(problems) != 2 || !strings.HasPrefix(problems[0], "waivers.txt line 4: want <date>") || !strings.HasPrefix(problems[1], "waivers.txt line 6: want <date>") {
		t.Errorf("problems = %q", problems)
	}
}

// Only the top section of the CHANGELOG counts: not the text above the first
// release, not an older release, and a mention that ends the section counts.
func TestCheckWaiversReadsOnlyTheTopSectionOfTheChangelog(t *testing.T) {
	for name, c := range map[string]struct {
		line string
		ok   bool
	}{
		"in the top section":         {"2026-10-20 acl_test output $.status type-changed why", true},
		"in the preamble":            {"2026-10-20 pre_tool output $.pre type-changed why", false},
		"in an older section":        {"2026-10-20 dns_get output $.x type-changed why", false},
		"property only in preamble":  {"2026-10-20 acl_test output $.pre type-changed why", false},
		"tool right, property wrong": {"2026-10-20 acl_test output $.other type-changed why", false},
	} {
		problems, ws := checkWaivers([]string{c.line}, waiverChangelog)
		if c.ok != (len(problems) == 0 && len(ws) == 1) {
			t.Errorf("%s: problems %q, waivers %+v", name, problems, ws)
		}
	}
	// With no release heading at all, the whole text is the top section.
	if problems, ws := checkWaivers([]string{"2026-10-20 acl_test output $.status type-changed why"}, "`acl_test` `$.status`"); len(problems) != 0 || len(ws) != 1 {
		t.Errorf("a changelog without sections: problems %q, waivers %+v", problems, ws)
	}
	// The last character of a section is part of it, even when the next heading follows at once.
	tight := "# C\n\n## 0.6.0\n\n`acl_test` `$.status`\n## 0.5.0\n"
	if problems, ws := checkWaivers([]string{"2026-10-20 acl_test output $.status type-changed why"}, tight); len(problems) != 0 || len(ws) != 1 {
		t.Errorf("a mention that ends the section: problems %q, waivers %+v", problems, ws)
	}
}
