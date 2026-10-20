package mcpserver

import (
	"encoding/json"
	"fmt"
	"sort"
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
const toolListBudget = 65536

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
	if p := budgetProblem(total, toolListBudget, sizes); p != "" {
		t.Error(p)
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
