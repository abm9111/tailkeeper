package tools_test

import (
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/mcpserver"
	"github.com/abm9111/tailkeeper/internal/registry"
)

var update = flag.Bool("update", false, "write testdata/schemas from the registry: the baseline of a release")

const schemaDir = "testdata/schemas"

// snapshot is a tool's contract as the MCP server advertises it: the input schema
// and the output schema with its untrusted and masked markers.
func snapshot(t *testing.T, tool registry.Tool) map[string]any {
	t.Helper()
	in, err := json.Marshal(tool.InputSchema)
	if err != nil {
		t.Fatal(err)
	}
	var input any
	if err := json.Unmarshal(in, &input); err != nil {
		t.Fatal(err)
	}
	out, err := mcpserver.OutputSchema(tool)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"tool": tool.Meta.Name, "input": input, "output": out}
}

// readLines returns the lines of a text file, or none if it does not exist.
func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(string(b), "\n")
}

// TestSchemasKeepTheReleasedContract compares every tool's schemas with the
// baseline of the last release in testdata/schemas, by the rules in
// schemacompat_test.go. A tool not yet released is listed in unreleased.txt and has
// no baseline; the release PR empties that list and runs the test with -update,
// which writes the baselines (and refuses to while a break is not waived).
func TestSchemasKeepTheReleasedContract(t *testing.T) {
	reg := newRegistry(t)
	changelog, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	problems, waivers := checkWaivers(readLines(t, filepath.Join(schemaDir, "waivers.txt")), string(changelog))
	waived := map[string]bool{}
	for _, w := range waivers {
		waived[w.key()] = true
	}
	unreleased := map[string]bool{}
	for _, l := range readLines(t, filepath.Join(schemaDir, "unreleased.txt")) {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			unreleased[l] = true
		}
	}

	files, err := filepath.Glob(filepath.Join(schemaDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	baseline := map[string]string{} // tool name -> file
	for _, f := range files {
		baseline[strings.TrimSuffix(filepath.Base(f), ".json")] = f
	}
	var writable []registry.Tool // tools whose baseline -update may write
	var noBaseline []string
	var breaks []violation
	for _, tool := range reg.All() {
		name := tool.Meta.Name
		file, have := baseline[name]
		switch {
		case unreleased[name] && have:
			problems = append(problems, name+" is listed in unreleased.txt and has a baseline: remove it from the list")
		case unreleased[name]:
		case !have:
			noBaseline = append(noBaseline, name)
			writable = append(writable, tool)
		default:
			b, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var old map[string]any
			if err := json.Unmarshal(b, &old); err != nil {
				t.Fatalf("%s: %v", file, err)
			}
			cur := snapshot(t, tool)
			for _, io := range []string{"input", "output"} {
				breaks = append(breaks, compareSchemas(name, io, old[io], cur[io])...)
			}
			writable = append(writable, tool)
		}
		delete(baseline, name)
	}
	for name := range unreleased {
		if _, ok := reg.Get(name); !ok {
			problems = append(problems, name+" is listed in unreleased.txt and is not a registered tool")
		}
	}
	for name := range baseline { // baselines of tools that no longer exist
		breaks = append(breaks, violation{Tool: name, IO: "input", Path: "$", Rule: "removed-tool", Detail: "the tool was removed"})
	}
	problems = append(problems, staleWaivers(waivers, breaks)...)
	var unwaived []string
	for _, v := range breaks {
		if !waived[v.key()] {
			unwaived = append(unwaived, v.key()+": "+v.Detail)
		}
	}
	if *update && len(unwaived) == 0 && len(problems) == 0 {
		for _, tool := range writable {
			b, err := json.MarshalIndent(snapshot(t, tool), "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(schemaDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(schemaDir, tool.Meta.Name+".json"), append(b, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		for name := range baseline {
			if err := os.Remove(filepath.Join(schemaDir, name+".json")); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
	if len(noBaseline) > 0 {
		shown := strings.Join(noBaseline[:min(3, len(noBaseline))], ", ")
		if len(noBaseline) > 3 {
			shown += ", ..."
		}
		t.Errorf("%d tools have no baseline in %s (%s): run `go test ./internal/tools -run TestSchemasKeepTheReleasedContract -update`, or list a tool in unreleased.txt if it is not released yet",
			len(noBaseline), schemaDir, shown)
	}
	for _, u := range unwaived {
		t.Errorf("breaks the released contract (a dated line in %s/waivers.txt, mentioned in the CHANGELOG, excuses it): %s", schemaDir, u)
	}
}
