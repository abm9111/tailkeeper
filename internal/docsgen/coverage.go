package docsgen

import (
	"fmt"
	"sort"
	"strings"

	"github.com/abm9111/tailkeeper/internal/api/openapi"
	"github.com/abm9111/tailkeeper/internal/registry"
)

// CoverageRow is one operation of the pinned OpenAPI document that tailkeeper
// must answer for: the tools that call it, or why none does.
type CoverageRow struct {
	Operation string
	Tools     []string
	Skip      string
}

// Coverage maps the pinned document's required operations to the tools that call
// them (spec §20). problems lists every way the map is incomplete or wrong; the
// docs show them and a test fails on them.
func Coverage(reg *registry.Registry) (rows []CoverageRow, problems []string) {
	known := map[string]bool{}
	for _, op := range openapi.Operations() {
		known[op] = true
	}
	callers := map[string][]string{}
	for _, t := range reg.All() {
		m := t.Meta
		if m.Tier == registry.TierRead && len(m.Operations) == 0 {
			problems = append(problems, m.Name+" declares no operation")
		}
		for _, op := range m.Operations {
			if !known[op] {
				problems = append(problems, fmt.Sprintf("%s declares %s, which the pinned document does not have", m.Name, op))
				continue
			}
			callers[op] = append(callers[op], m.Name)
		}
	}
	for _, op := range openapi.Operations() {
		if !openapi.Required(op) {
			continue
		}
		tools, skip := callers[op], openapi.Skipped[op]
		sort.Strings(tools)
		switch {
		case len(tools) == 0 && skip == "":
			problems = append(problems, op+" is neither called by a tool nor skipped")
		case len(tools) > 0 && skip != "":
			problems = append(problems, op+" is called by "+strings.Join(tools, ", ")+" and also skipped")
		}
		rows = append(rows, CoverageRow{Operation: op, Tools: tools, Skip: skip})
	}
	for op := range openapi.Skipped {
		if !known[op] {
			problems = append(problems, "skip entry "+op+" is not in the pinned document")
		}
	}
	sort.Strings(problems)
	return rows, problems
}

func coverageSection(b *strings.Builder, reg *registry.Registry) {
	rows, problems := Coverage(reg)
	b.WriteString("\n## API coverage\n\n")
	b.WriteString("This map is checked against a pinned list of the operations in Tailscale's OpenAPI document (`internal/api/openapi/operations.txt`). It shows every read operation in that list, and the policy validation `acl_test` sends, with the tools that call it or the reason none does. A weekly check compares the pin with the live document.\n\n")
	for _, p := range problems {
		fmt.Fprintf(b, "**Problem:** %s\n\n", cell(p))
	}
	b.WriteString("| Operation | Tools | Not called because |\n|---|---|---|\n")
	for _, r := range rows {
		fmt.Fprintf(b, "| `%s` | %s | %s |\n", r.Operation, code(r.Tools), cell(r.Skip))
	}
}
