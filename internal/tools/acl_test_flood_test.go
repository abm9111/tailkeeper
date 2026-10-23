package tools_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// floodEntries is n entries of lines lines each, every line of width quote characters, which
// cost the most as JSON text. users names the source of entry i.
func floodEntries(n, lines, width int, user func(i int) string) []apitest.Entry {
	var out []apitest.Entry
	for i := 0; i < n; i++ {
		e := apitest.Entry{User: user(i)}
		for j := 0; j < lines; j++ {
			e.Errors = append(e.Errors, "[acl test error]: "+strings.Repeat(`"`, width))
		}
		out = append(out, e)
	}
	return out
}

func shownLines(out tools.ACLTestOutput) int {
	n := len(out.Unmatched) + len(out.Warnings)
	for _, r := range append(append([]tools.ACLTestResult{}, out.Failures...), out.OtherTests...) {
		n += len(r.Errors)
	}
	return n
}

// What Tailscale says in a tests-mode reply is bounded in the result whatever its size: 64
// entries of 64 lines of 900 characters, for other sources or for the posted one, show a
// few dozen lines, count the rest, and leave the status as the lines alone would.
func TestAHostileTestsModeReplyIsBoundedAndItsStatusIsUntouched(t *testing.T) {
	const entries, lines, width = 64, 64, 900
	other := func(i int) string { return fmt.Sprintf("tag:t%02d", i) }
	posted := func(int) string { return "tag:ci" }
	for name, c := range map[string]struct {
		user   func(i int) string
		status string
	}{
		"entries of other sources":  {other, "pass"},
		"entries of the posted one": {posted, "unresolved"},
	} {
		t.Run(name, func(t *testing.T) {
			f, reg, env := apiEnv(t)
			servePolicy(f, "{}\n", `"e1"`)
			f.ServeValidate(apitest.TestsFailed(floodEntries(entries, lines, width, c.user)...))
			var out tools.ACLTestOutput
			s := mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:web:22"]}`, &out)
			if out.Status != c.status {
				t.Errorf("status %q, want %q", out.Status, c.status)
			}
			shown := shownLines(out)
			if shown == 0 || shown > 64 {
				t.Errorf("%d lines shown of %d", shown, entries*lines)
			}
			if out.OmittedLines != entries*lines-shown {
				t.Errorf("omittedLines = %d, want %d (%d shown)", out.OmittedLines, entries*lines-shown, shown)
			}
			if len(s) > 80<<10 {
				t.Errorf("the result is %d bytes", len(s))
			}
			if rep := out.Report(); !strings.Contains(fmt.Sprint(rep.Facts), "not listed") {
				t.Errorf("the report does not say lines were left out: %+v", rep.Facts)
			}
			b, err := json.Marshal(out)
			if err != nil || !strings.Contains(string(b), `"omittedLines":`) {
				t.Errorf("omittedLines is not in the JSON: %v", err)
			}
		})
	}
}

// A small reply loses nothing and counts nothing.
func TestASmallTestsModeReplyLeavesNothingOutAndCountsNothing(t *testing.T) {
	f, reg, env := apiEnv(t)
	servePolicy(f, "{}\n", `"e1"`)
	f.ServeValidate(apitest.TestsFailed(floodEntries(2, 3, 60, func(i int) string { return fmt.Sprintf("tag:t%d", i) })...))
	var out tools.ACLTestOutput
	s := mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:web:22"]}`, &out)
	if shownLines(out) != 6 || out.OmittedLines != 0 || strings.Contains(s, "omittedLines") {
		t.Errorf("%d lines shown, %d omitted: %s", shownLines(out), out.OmittedLines, s)
	}
}
