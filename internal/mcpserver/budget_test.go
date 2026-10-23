package mcpserver

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// toolListBudget is the size in bytes of the tool definitions an MCP host loads
// from a default server (the reads profile, no alpha tools): each as tools/list
// sends it. Two thirds of it is output schemas, and a host that does not defer
// tool definitions pays for it on every turn, so growth is a decision: a change
// that raises the total raises this number in the same commit, and says why in
// the CHANGELOG. It is tight on purpose: the test also fails when the total falls
// more than 1,024 bytes below it, so the number follows the code down as well.
const toolListBudget = 96540

const budgetSlack = 1024

func definitionSizes(t *testing.T) (total int, sizes map[string]int) {
	t.Helper()
	reg := registry.New()
	tools.Register(reg)
	list, err := reg.Profile("reads", false)
	if err != nil {
		t.Fatal(err)
	}
	sizes = map[string]int{}
	for _, tl := range list {
		d, err := Describe(tl)
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		sizes[tl.Meta.Name] = len(b)
		total += len(b)
	}
	return total, sizes
}

func largest(sizes map[string]int, n int) string {
	names := make([]string, 0, len(sizes))
	for k := range sizes {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool {
		return sizes[names[i]] > sizes[names[j]] || sizes[names[i]] == sizes[names[j]] && names[i] < names[j]
	})
	var parts []string
	for _, k := range names[:min(n, len(names))] {
		parts = append(parts, fmt.Sprintf("%s %d", k, sizes[k]))
	}
	return strings.Join(parts, ", ")
}

// budgetProblem says what is wrong when total is not within slack below budget.
func budgetProblem(total, budget int, sizes map[string]int) string {
	switch {
	case total > budget:
		return fmt.Sprintf("the tool definitions are %d bytes, %d over the budget of %d: raise toolListBudget in the same commit and say why in the CHANGELOG, or shorten them. Largest: %s",
			total, total-budget, budget, largest(sizes, 5))
	case total < budget-budgetSlack:
		return fmt.Sprintf("the tool definitions are %d bytes, %d under the budget of %d: lower toolListBudget to %d so growth cannot hide in the slack",
			total, budget-total, budget, total+budgetSlack/2)
	}
	return ""
}

func TestToolListStaysWithinItsByteBudget(t *testing.T) {
	total, sizes := definitionSizes(t)
	t.Logf("the tool definitions are %d bytes; the budget is %d", total, toolListBudget)
	if p := budgetProblem(total, toolListBudget, sizes); p != "" {
		t.Error(p)
	}
}

// thousands writes n as the CHANGELOG writes a number of this size: 88,772.
func thousands(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// topSection is the first section of the CHANGELOG, the one a change in progress writes to:
// the lines after the first heading of the second level and before the next. A text with no
// such heading is taken whole.
func topSection(changelog string) []string {
	var section []string
	started := false
	for _, line := range strings.Split(changelog, "\n") {
		if strings.HasPrefix(line, "## ") {
			if started {
				break
			}
			started = true
			continue
		}
		section = append(section, line)
	}
	if !started {
		return strings.Split(changelog, "\n")
	}
	return section
}

// budgetReasonProblem says whether some line of the top section of the CHANGELOG names
// toolListBudget and its value: a change that raises the budget says why there, and the number
// follows the code in the same bullet, so a budget the CHANGELOG does not give has no reason on
// record. A line of an older release does not count: a later raise to a number an old line
// holds would otherwise need no new reason.
func budgetReasonProblem(changelog string, budget int) string {
	for _, line := range topSection(changelog) {
		if strings.Contains(line, "`toolListBudget`") && strings.Contains(line, thousands(budget)) {
			return ""
		}
	}
	return fmt.Sprintf("no line of CHANGELOG.md names `toolListBudget` and its value, %s: a change that raises the budget says why there, in the same commit", thousands(budget))
}

func TestTheChangelogGivesTheReasonForTheBudget(t *testing.T) {
	b, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	if p := budgetReasonProblem(string(b), toolListBudget); p != "" {
		t.Error(p)
	}
	// The check can fail: the budget moved without the bullet, the name missing, and the
	// number written without its comma.
	for name, c := range map[string]struct {
		text   string
		budget int
	}{
		"a budget the bullet does not give": {"- The byte budget (`toolListBudget`) rises from 65,536 to 88,772 bytes.\n", 88773},
		"a line of an older release":        {"## 0.6.0 — unreleased\n\n- Something else.\n\n## 0.5.0 — 2026-10-16\n\n- `toolListBudget` is 88,772.\n", 88772},
		"a bullet that names no budget":     {"- The tool list is now 88,772 bytes.\n", 88772},
		"a number without its comma":        {"- `toolListBudget` is 88772.\n", 88772},
	} {
		if p := budgetReasonProblem(c.text, c.budget); !strings.Contains(p, "names `toolListBudget` and its value, "+thousands(c.budget)) {
			t.Errorf("%s: %q", name, p)
		}
	}
	if p := budgetReasonProblem("- The byte budget (`toolListBudget`) rises from 65,536 to 88,772 bytes.\n", 88772); p != "" {
		t.Errorf("a bullet that gives the value: %q", p)
	}
	if p := budgetReasonProblem("# Changelog\n\n## 0.6.0 — unreleased\n\n- `toolListBudget` is 88,772.\n\n## 0.5.0 — 2026-10-16\n", 88772); p != "" {
		t.Errorf("a bullet of the top section that gives the value: %q", p)
	}
	if got := thousands(88772) + " " + thousands(65536) + " " + thousands(999) + " " + thousands(1000) + " " + thousands(1234567); got != "88,772 65,536 999 1,000 1,234,567" {
		t.Errorf("thousands: %q", got)
	}
}

// The check above must be able to fail: plant a total over the budget, one far
// under it, and the limits themselves.
func TestBudgetProblemFindsGrowthAndSlack(t *testing.T) {
	sizes := map[string]int{"a_get": 10, "b_get": 30, "c_get": 30}
	if p := budgetProblem(5001, 5000, sizes); !strings.Contains(p, "1 over the budget of 5000") || !strings.Contains(p, "Largest: b_get 30, c_get 30, a_get 10") {
		t.Errorf("over: %q", p)
	}
	if p := budgetProblem(5000-budgetSlack-1, 5000, sizes); !strings.Contains(p, "1025 under the budget of 5000: lower toolListBudget to 4487") {
		t.Errorf("under: %q", p)
	}
	for _, total := range []int{5000, 5000 - budgetSlack} {
		if p := budgetProblem(total, 5000, sizes); p != "" {
			t.Errorf("total %d: %q", total, p)
		}
	}
}
