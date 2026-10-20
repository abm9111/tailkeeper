package workflows

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// dependabotGroup is one group of a Dependabot update: the dependency names it takes in
// and, with exclude-patterns, the names it leaves out again.
type dependabotGroup struct {
	Patterns        []string `yaml:"patterns"`
	ExcludePatterns []string `yaml:"exclude-patterns"`
}

// namedGroup is a group with its name, kept in the order the file lists the groups:
// Dependabot puts a dependency in the first group that matches it, so the order decides
// where a dependency goes.
type namedGroup struct {
	Name string
	dependabotGroup
}

// dependabotGroups returns the groups of the github-actions update in
// .github/dependabot.yml, in the order of the file. Each group stays apart: pull requests
// are raised per group, so a list of every group's patterns would hide whether one group
// holds them all.
func dependabotGroups(t *testing.T) []namedGroup {
	t.Helper()
	data, err := os.ReadFile("../../.github/dependabot.yml")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Updates []struct {
			Ecosystem string    `yaml:"package-ecosystem"`
			Groups    yaml.Node `yaml:"groups"`
		} `yaml:"updates"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	var out []namedGroup
	for _, u := range cfg.Updates {
		if u.Ecosystem != "github-actions" || u.Groups.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(u.Groups.Content); i += 2 {
			var g dependabotGroup
			if err := u.Groups.Content[i+1].Decode(&g); err != nil {
				t.Fatal(err)
			}
			out = append(out, namedGroup{Name: u.Groups.Content[i].Value, dependabotGroup: g})
		}
	}
	return out
}

// patternCovers reports whether a Dependabot group pattern names a dependency: the whole
// name must match, and * stands for any run of characters.
func patternCovers(pattern, name string) bool {
	re := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$"
	return regexp.MustCompile(re).MatchString(name)
}

// groupCovers reports whether the group takes in the dependency: one of its patterns
// names it and none of its exclude-patterns does.
func groupCovers(g dependabotGroup, name string) bool {
	covered := false
	for _, p := range g.Patterns {
		covered = covered || patternCovers(p, name)
	}
	for _, p := range g.ExcludePatterns {
		if patternCovers(p, name) {
			return false
		}
	}
	return covered
}

// groupsCoveringAll returns, sorted, the names of the groups that take in every one of
// the dependencies.
func groupsCoveringAll(groups []namedGroup, names []string) []string {
	var out []string
	for _, g := range groups {
		all := true
		for _, n := range names {
			all = all && groupCovers(g.dependabotGroup, n)
		}
		if all {
			out = append(out, g.Name)
		}
	}
	sort.Strings(out)
	return out
}

// firstGroupFor returns the name of the first group, in file order, that takes in the
// dependency, which is the group Dependabot puts it in; "" when no group does.
func firstGroupFor(groups []namedGroup, name string) string {
	for _, g := range groups {
		if groupCovers(g.dependabotGroup, name) {
			return g.Name
		}
	}
	return ""
}

// codeqlGroupProblems says why the dependencies would not move as one pull request:
// a group that covers all of them is not enough when an earlier group takes one of them
// first, so the first group to match each must be the same group for all.
func codeqlGroupProblems(groups []namedGroup, names []string) []string {
	first := map[string]string{}
	for _, n := range names {
		g := firstGroupFor(groups, n)
		if g == "" {
			return []string{fmt.Sprintf("no group of the github-actions update takes in %s", n)}
		}
		first[n] = g
	}
	var distinct []string
	for _, n := range names {
		if !contains(distinct, first[n]) {
			distinct = append(distinct, first[n])
		}
	}
	if len(distinct) != 1 {
		return []string{fmt.Sprintf("Dependabot puts the actions in different groups, by the first group that matches each (%v): they would not move as one pull request", first)}
	}
	return nil
}

// usedActions returns the distinct names (without @ref) of the actions the workflow
// files use, that start with prefix.
func usedActions(t *testing.T, prefix string) []string {
	t.Helper()
	files, err := filepath.Glob("../../.github/workflows/*.yml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflow files found: %v", err)
	}
	seen := map[string]bool{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var wf workflow
		if err := yaml.Unmarshal(data, &wf); err != nil {
			t.Fatal(err)
		}
		for _, j := range wf.Jobs {
			for _, s := range j.Steps {
				if name, _, _ := strings.Cut(s.Uses, "@"); strings.HasPrefix(name, prefix) {
					seen[name] = true
				}
			}
		}
	}
	var names []string
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// The three github/codeql-action/* actions (init, analyze, upload-sarif) are versions of
// one release and have to move together: a bump of init on its own failed the analyze
// job. Dependabot opens one pull request per group, and one per action for what no group
// takes in, and each merge forces the next to be rebased. So one group has to take in all
// three: three groups of one action each would be three pull requests again.
func TestDependabotGroupsTheCodeQLActions(t *testing.T) {
	groups := dependabotGroups(t)
	names := usedActions(t, "github/codeql-action/")
	if len(names) < 3 {
		t.Fatalf("the workflows use %d github/codeql-action/* actions (%v), want init, analyze and upload-sarif: this test guards their group, so it was moved or renamed", len(names), names)
	}
	if len(groupsCoveringAll(groups, names)) == 0 {
		t.Errorf("no single group of the github-actions update in .github/dependabot.yml takes in all of %v: they would not move as one pull request (groups: %+v)", names, groups)
	}
	for _, p := range codeqlGroupProblems(groups, names) {
		t.Errorf("%s (groups in file order: %+v)", p, groups)
	}
}

// The matching is checked on names it must and must not cover, so a group that matches
// everything or nothing cannot satisfy the test above.
func TestDependabotPatternMatching(t *testing.T) {
	for _, c := range []struct {
		pattern, name string
		want          bool
	}{
		{"github/codeql-action/*", "github/codeql-action/init", true},
		{"github/codeql-action/*", "github/codeql-action/upload-sarif", true},
		{"github/codeql-action/*", "github/codeql-action", false},
		{"github/codeql-action/*", "actions/checkout", false},
		{"github/codeql-action/*", "xgithub/codeql-action/init", false},
		{"github/codeql-action/init", "github/codeql-action/analyze", false},
		{"actions/*", "github/codeql-action/init", false},
	} {
		if got := patternCovers(c.pattern, c.name); got != c.want {
			t.Errorf("patternCovers(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

// A group counts for a name only when a pattern takes it in and no exclude-pattern takes it
// out, and "one group covers all" means one group, not the union of several.
func TestDependabotGroupCoverage(t *testing.T) {
	names := []string{"github/codeql-action/analyze", "github/codeql-action/init", "github/codeql-action/upload-sarif"}
	all := dependabotGroup{Patterns: []string{"github/codeql-action/*"}}
	for _, c := range []struct {
		desc   string
		groups []namedGroup
		want   []string
	}{
		{"no groups", nil, nil},
		{"one group takes all", []namedGroup{{"codeql", all}}, []string{"codeql"}},
		{"one group per action", []namedGroup{
			{"a", dependabotGroup{Patterns: []string{"github/codeql-action/analyze"}}},
			{"i", dependabotGroup{Patterns: []string{"github/codeql-action/init"}}},
			{"u", dependabotGroup{Patterns: []string{"github/codeql-action/upload-sarif"}}},
		}, nil},
		{"an exclude-pattern takes a name out", []namedGroup{{"codeql", dependabotGroup{
			Patterns:        []string{"github/codeql-action/*"},
			ExcludePatterns: []string{"github/codeql-action/init"},
		}}}, nil},
		{"an exclude-pattern for another name changes nothing", []namedGroup{{"codeql", dependabotGroup{
			Patterns:        []string{"github/codeql-action/*"},
			ExcludePatterns: []string{"actions/*"},
		}}}, []string{"codeql"}},
		{"a group of everything, minus the exclusions, still takes all", []namedGroup{{"every", dependabotGroup{
			Patterns:        []string{"*"},
			ExcludePatterns: []string{"actions/*"},
		}}}, []string{"every"}},
		{"only the group that holds all is named", []namedGroup{
			{"codeql", all},
			{"init", dependabotGroup{Patterns: []string{"github/codeql-action/init"}}},
		}, []string{"codeql"}},
	} {
		got := groupsCoveringAll(c.groups, names)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: groupsCoveringAll = %v, want %v", c.desc, got, c.want)
		}
	}
}

// Dependabot puts a dependency in the first group, in file order, that matches it. A group
// that holds all three actions does not help when an earlier group takes one of them: that
// one would move alone. The order of the file is read, and the first match decides.
func TestDependabotFirstMatchingGroupDecides(t *testing.T) {
	names := []string{"github/codeql-action/analyze", "github/codeql-action/init", "github/codeql-action/upload-sarif"}
	all := dependabotGroup{Patterns: []string{"github/codeql-action/*"}}
	initOnly := dependabotGroup{Patterns: []string{"github/codeql-action/init"}}
	for _, c := range []struct {
		desc   string
		groups []namedGroup
		want   string // a substring of the one problem, or "" for none
	}{
		{"one group takes all", []namedGroup{{"codeql", all}}, ""},
		{"a later group of one action changes nothing", []namedGroup{{"codeql", all}, {"init", initOnly}}, ""},
		{"an earlier group takes init first", []namedGroup{{"init", initOnly}, {"codeql", all}}, "different groups"},
		{"an earlier group of everything takes all of them, the same group", []namedGroup{{"every", dependabotGroup{Patterns: []string{"*"}}}, {"codeql", all}}, ""},
		{"no group takes one", []namedGroup{{"analyze", dependabotGroup{Patterns: []string{"github/codeql-action/analyze"}}}}, "no group"},
		{"no groups", nil, "no group"},
	} {
		got := codeqlGroupProblems(c.groups, names)
		switch {
		case c.want == "" && len(got) != 0:
			t.Errorf("%s: problems %v, want none", c.desc, got)
		case c.want != "" && (len(got) != 1 || !strings.Contains(got[0], c.want)):
			t.Errorf("%s: problems %v, want one containing %q", c.desc, got, c.want)
		}
	}
}
