package workflows

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
)

// `make probe-acl` sends synthetic documents to the owner's tailnet and reads its policy. It
// is the owner's: no workflow runs it, the gate does not depend on it, and a release does
// not contain it (the command exists only in a binary built with -tags probe, and nothing
// else imports the probe package). A file that broke one of these would keep every other
// test green.

var probeImport = regexp.MustCompile(`"github\.com/abm9111/tailkeeper/internal/probe"`)

// probeTag finds the build tag probe, as a whole word, anywhere in the value of a -tags
// flag: bare, quoted with " or ', alone or in a comma or space separated list. The words
// probes, probeX, probe_x and probe.x are other tags, and do not match. Whatever is not
// part of a tag name ends the word: a space, a quote, a comma, or shell punctuation
// such as ; & | ) > or a trailing backslash.
var probeTag = regexp.MustCompile(`(?m)(?:^|[\s'"=])--?tags(?:=|\s+)(?:` +
	`"(?:[^"]*[\s,])?probe(?:[\s,][^"]*)?"|` +
	`'(?:[^']*[\s,])?probe(?:[\s,][^']*)?'|` +
	`(?:[^\s"',]*,)*probe(?:[^A-Za-z0-9_.]|$))`)

// runsProbes reports whether text runs make probe-acl or builds with the probe tag.
func runsProbes(text string) bool {
	return strings.Contains(text, "probe-acl") || probeTag.MatchString(text)
}

// makeRule is one rule of a Makefile: its targets, its prerequisites with their
// continuation lines joined, and its recipe lines (continuations joined).
type makeRule struct {
	targets []string
	prereqs string
	recipe  []string
}

var (
	ruleHeader = regexp.MustCompile(`^([^\t#:=\s][^:=#]*?):(?:[^=]|$)(.*)$`)
	subMake    = regexp.MustCompile(`(?:\$\(MAKE\)|\bmake)\s+(?:-\S+\s+)*([A-Za-z0-9_.-]+)`)
)

// parseMake reads the rules of a Makefile. It is not make: it reads enough of the syntax to
// join a prerequisite list that continues on the next line, and to take each recipe line.
func parseMake(text string) []makeRule {
	lines := strings.Split(text, "\n")
	var rules []makeRule
	for i := 0; i < len(lines); i++ {
		m := ruleHeader.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		header := m[2]
		for strings.HasSuffix(strings.TrimRight(lines[i], " \t"), "\\") && i+1 < len(lines) {
			header = strings.TrimSuffix(strings.TrimRight(header, " \t"), "\\") + " " + lines[i+1]
			i++
		}
		r := makeRule{targets: strings.Fields(m[1]), prereqs: header}
		for i+1 < len(lines) && (strings.HasPrefix(lines[i+1], "\t") || strings.TrimSpace(lines[i+1]) == "") {
			i++
			line := lines[i]
			for strings.HasSuffix(strings.TrimRight(line, " \t"), "\\") && i+1 < len(lines) {
				line = strings.TrimSuffix(strings.TrimRight(line, " \t"), "\\") + " " + lines[i+1]
				i++
			}
			if strings.TrimSpace(line) != "" {
				r.recipe = append(r.recipe, line)
			}
		}
		rules = append(rules, r)
	}
	return rules
}

// gateProblems says what in the rules that verify and install reach, directly or through
// a prerequisite or a $(MAKE) line, runs the probes. The whole rule is read: the
// prerequisite line with its continuations, and every recipe line.
func gateProblems(text string) []string {
	rules := parseMake(text)
	reached := map[string]bool{}
	queue := []string{"verify", "install"}
	var problems []string
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if reached[name] {
			continue
		}
		reached[name] = true
		for _, r := range rules {
			if !contains(r.targets, name) {
				continue
			}
			body := r.prereqs + "\n" + strings.Join(r.recipe, "\n")
			if strings.Contains(r.prereqs, "probe") || runsProbes(body) {
				problems = append(problems, "Makefile: "+name+" runs or depends on the probes")
			}
			queue = append(queue, strings.Fields(r.prereqs)...)
			for _, line := range r.recipe {
				for _, sub := range subMake.FindAllStringSubmatch(line, -1) {
					queue = append(queue, sub[1])
				}
			}
		}
	}
	return problems
}

var (
	exportLive   = regexp.MustCompile(`(?m)^[^#\n]*\bexport\b[^\n#]*\bTAILKEEPER_LIVE\b`)
	exportAll    = regexp.MustCompile(`(?m)^(?:export\s*|\.EXPORT_ALL_VARIABLES.*)$`)
	probeRunLine = regexp.MustCompile(`^\s*TAILKEEPER_LIVE=1 "\$\$dir/tailkeeper-probe" probe-acl\b`)
)

// switchProblems says where TAILKEEPER_LIVE=1 reaches further than the one command that
// needs it: an export of it (for the whole recipe, for the target, or Makefile-wide), or a
// line that sets it without being the line that runs the probe binary or the live tests.
func switchProblems(text, target string) []string {
	var problems []string
	if exportLive.MatchString(text) || exportAll.MatchString(text) {
		problems = append(problems, "Makefile: TAILKEEPER_LIVE is exported beyond the one command that needs it")
	}
	for _, line := range strings.Split(target, "\n") {
		if strings.Contains(line, "TAILKEEPER_LIVE") && !strings.HasPrefix(strings.TrimSpace(line), "#") && !probeRunLine.MatchString(line) {
			problems = append(problems, "Makefile: the probe-acl target sets TAILKEEPER_LIVE on a line that does not run the probe binary")
		}
	}
	runs := 0
	for _, line := range strings.Split(target, "\n") {
		if probeRunLine.MatchString(line) {
			runs++
			if !strings.Contains(line, ` --out "$(PROBE_OUT)"`) {
				problems = append(problems, "Makefile: the line that runs the probe binary does not pass --out \"$(PROBE_OUT)\"")
			}
		}
	}
	if runs != 1 {
		problems = append(problems, fmt.Sprintf("Makefile: %d lines of the probe-acl target run the probe binary, want 1", runs))
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "TAILKEEPER_LIVE=1") && !strings.HasPrefix(strings.TrimSpace(line), "#") && !probeRunLine.MatchString(line) && !strings.Contains(line, "-run '^TestLive'") {
			problems = append(problems, "Makefile: TAILKEEPER_LIVE=1 is set on a line that runs neither the probe binary nor the live tests")
		}
	}
	return problems
}

// probeProblems says what in files (path to content, slash-separated paths from the
// repository root) lets the probes into CI, the gate or a release.
func probeProblems(files map[string]string) []string {
	var problems []string
	for path, text := range files {
		switch {
		case strings.HasPrefix(path, ".github/") && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")):
			if runsProbes(text) {
				problems = append(problems, path+" runs or builds the probes")
			}
		case strings.HasPrefix(path, "scripts/"):
			if runsProbes(text) {
				problems = append(problems, path+" runs or builds the probes")
			}
		case path == ".goreleaser.yaml":
			if strings.Contains(text, "probe") || regexp.MustCompile(`(?m)^\s*tags:`).MatchString(text) || strings.Contains(text, "-tags") {
				problems = append(problems, path+" builds with tags, or names the probes")
			}
		case path == "Makefile":
			problems = append(problems, gateProblems(text)...)
			start := strings.Index(text, "\nprobe-acl:\n")
			if start < 0 {
				problems = append(problems, "Makefile has no probe-acl target")
				break
			}
			target := text[start+1:]
			if end := strings.Index(target, "\n\n"); end > 0 {
				target = target[:end]
			}
			for _, need := range []string{"-tags probe", "TAILKEEPER_LIVE=1", "mktemp -d"} {
				if !strings.Contains(target, need) {
					problems = append(problems, "Makefile: the probe-acl target lacks "+need)
				}
			}
			problems = append(problems, switchProblems(text, target)...)
		case strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go"):
			tagged := false
			for _, line := range strings.Split(text, "\n") {
				if strings.HasPrefix(line, "//go:build") && regexp.MustCompile(`\bprobe\b`).MatchString(line) {
					tagged = true
				}
			}
			if tagged && path != "cmd/tailkeeper/probe_on.go" {
				problems = append(problems, path+" carries the probe build tag; only cmd/tailkeeper/probe_on.go may")
			}
			if probeImport.MatchString(text) && path != "cmd/tailkeeper/probe_on.go" {
				problems = append(problems, path+" imports internal/probe; only cmd/tailkeeper/probe_on.go may")
			}
			if path == "cmd/tailkeeper/probe_on.go" && !tagged {
				problems = append(problems, path+" lacks its build tag, so the probes are in every build")
			}
		}
	}
	sort.Strings(problems)
	return problems
}

// readRepo returns the files probeProblems looks at.
func readRepo(t *testing.T) map[string]string {
	t.Helper()
	root := "../.."
	files := map[string]string{}
	add := func(rel string) {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		files[rel] = string(b)
	}
	add("Makefile")
	add(".goreleaser.yaml")
	for _, top := range []string{".github", "scripts", "cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(top)), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			switch {
			case strings.HasPrefix(filepath.ToSlash(rel), "scripts/"), strings.HasSuffix(rel, ".yml"), strings.HasSuffix(rel, ".yaml"), strings.HasSuffix(rel, ".go"):
				add(filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return files
}

// probeOut finds every assignment of PROBE_OUT, whatever the operator: =, ?=, :=, ::= or +=.
var probeOut = regexp.MustCompile(`(?m)^PROBE_OUT[ \t]*(?:[:?+]|::)?=[ \t]*(.*?)[ \t]*$`)

// probeOutProblem says what is wrong with the Makefile's PROBE_OUT: it is assigned exactly
// once, and to the directory the ledger reads its captures from.
func probeOutProblem(makefile string) string {
	m := probeOut.FindAllStringSubmatch(makefile, -1)
	if len(m) != 1 {
		return fmt.Sprintf("the Makefile assigns PROBE_OUT %d times, want once", len(m))
	}
	if want := "internal/api/apitest/" + apitest.CaptureDir; m[0][1] != want {
		return fmt.Sprintf("PROBE_OUT is %q, but the ledger reads its captures from %q", m[0][1], want)
	}
	return ""
}

// The skeleton files make probe-acl writes are the captures the ledger looks for: the
// only assignment of PROBE_OUT is the ledger's own directory, not a copy of its name.
func TestProbeOutIsTheLedgersCaptureDirectory(t *testing.T) {
	if p := probeOutProblem(readRepo(t)["Makefile"]); p != "" {
		t.Error(p)
	}
}

// The check can fail: a default that is another directory, a typo, nothing, no assignment,
// or a second assignment with any operator that overrides the first.
func TestProbeOutCheckFindsADifferentDefault(t *testing.T) {
	const good = "PROBE_OUT ?= internal/api/apitest/testdata/observed\n"
	if p := probeOutProblem(good); p != "" {
		t.Errorf("the good Makefile has a problem: %s", p)
	}
	for name, text := range map[string]string{
		"another directory": "PROBE_OUT ?= internal/probe/testdata/observed\n",
		"a typo":            "PROBE_OUT ?= internal/api/apitest/testdata/observe\n",
		"nothing":           "PROBE_OUT ?=\n",
		"no assignment":     "PROBE_ARGS ?=\n",
		"a later =":         good + "PROBE_OUT = elsewhere\n",
		"a later :=":        good + "PROBE_OUT := elsewhere\n",
		"a later ::=":       good + "PROBE_OUT ::= elsewhere\n",
		"a later +=":        good + "PROBE_OUT += elsewhere\n",
		"an earlier =":      "PROBE_OUT=elsewhere\n" + good,
		"a plain = alone":   "PROBE_OUT = internal/probe/testdata/observed\n",
	} {
		if probeOutProblem(text) == "" {
			t.Errorf("%s: no problem found", name)
		}
	}
	if p := probeOutProblem("PROBE_OUT = internal/api/apitest/testdata/observed\n"); p != "" {
		t.Errorf("a single assignment of the right directory has a problem: %s", p)
	}
}

var planNumber = regexp.MustCompile(`\bPR[0-9]+\b`)

// Public text cites public documents. A pull request number belongs to a plan the
// repository does not hold, so no source, script or changelog line may name one.
func TestPublicTextNamesNoPullRequestNumber(t *testing.T) {
	files := readRepo(t)
	for _, name := range []string{"CHANGELOG.md", "CONTRIBUTING.md"} {
		b, err := os.ReadFile(filepath.Join("../..", name))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = string(b)
	}
	for path, text := range files {
		if m := planNumber.FindString(text); m != "" {
			t.Errorf("%s names %s, a plan the repository does not hold; say what comes instead", path, m)
		}
	}
	if !planNumber.MatchString("a later change, PR"+"6, reads it") || planNumber.MatchString("a PRX or an SP"+"R6 row") {
		t.Error("the pull request number detector does not find a number, or finds a word")
	}
}

// probe-acl is never run in CI, but the test suite does build the tagged binary and run it,
// offline, until it stops without a configuration. The changelog and the Makefile say that,
// not "never in CI".
func TestTheCIClaimsAboutProbeACLAreTrue(t *testing.T) {
	for _, name := range []string{"CHANGELOG.md", "Makefile"} {
		b, err := os.ReadFile(filepath.Join("../..", name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(b)
		if strings.Contains(text, "never in CI") {
			t.Errorf("%s says probe-acl is never in CI, but a test in cmd/tailkeeper builds the tagged binary and runs it", name)
		}
		if i := strings.Index(text, "probe-acl"); i < 0 || !strings.Contains(text, "stops without a configuration") {
			t.Errorf("%s does not say that the test only proves the tagged binary stops without a configuration", name)
		}
	}
}

func TestTheProbesStayOutOfCIAndOutOfReleases(t *testing.T) {
	files := readRepo(t)
	if _, ok := files["cmd/tailkeeper/probe_on.go"]; !ok {
		t.Fatal("cmd/tailkeeper/probe_on.go is missing: the probes are not wired")
	}
	if problems := probeProblems(files); len(problems) > 0 {
		t.Errorf("%s", strings.Join(problems, "\n"))
	}
}

// The check can fail: each file below is a known positive, and the good tree is clean.
func TestProbeProblemsFindsEveryWayIn(t *testing.T) {
	const makefile = "verify: fmt-check test\n\ninstall:\n\tgo build\n\nlive:\n\tTAILKEEPER_LIVE=1 go test -run '^TestLive' ./x\n\n" +
		"probe-acl:\n\t@dir=\"$$(mktemp -d)\" || exit 1; trap 'rm -rf \"$$dir\"' EXIT INT TERM; \\\n" +
		"\tgo build -tags probe -o \"$$dir/tailkeeper-probe\" ./cmd/tailkeeper || exit 1; \\\n" +
		"\tTAILKEEPER_LIVE=1 \"$$dir/tailkeeper-probe\" probe-acl --out \"$(PROBE_OUT)\" $(PROBE_ARGS)\n\nother:\n\ttrue\n"
	const runLine = "TAILKEEPER_LIVE=1 \"$$dir/tailkeeper-probe\""
	good := map[string]string{
		"Makefile":                      makefile,
		".goreleaser.yaml":              "builds:\n  - id: tailkeeper\n    flags:\n      - -trimpath\n",
		".github/workflows/verify.yml":  "run: make verify\n",
		".github/workflows/vet.yaml":    "run: go vet -tags probes ./... && go test ./internal/probe/...\n",
		"scripts/deps.sh":               "go list -tags=live,probes ./...\n",
		"cmd/tailkeeper/probe_on.go":    "//go:build probe\n\npackage main\n\nimport \"github.com/abm9111/tailkeeper/internal/probe\"\n",
		"cmd/tailkeeper/main.go":        "package main\n",
		"internal/probe/probe.go":       "package probe\n",
		"internal/probe/probes_test.go": "package probe\n",
	}
	if p := probeProblems(good); len(p) != 0 {
		t.Fatalf("the good tree has problems: %v", p)
	}
	clone := func(m map[string]string) map[string]string {
		c := map[string]string{}
		for k, v := range m {
			c[k] = v
		}
		return c
	}
	// A word that merely starts with probe, or a path that has it, is not the tag.
	for _, text := range []string{
		"run: go build -tags probes ./...\n", "run: go build -tags probeX ./...\n", "run: go build -tags=live,probes ./...\n",
		"run: go build -tags 'x probes' ./...\n", "run: go build -tags \"probe_x,y\" ./...\n", "run: go test ./internal/probe/...\n",
		"run: go build -tags live ./cmd/probe\n", "run: go build -tags probe_x ./...\n", "run: go build -tags=live,probeX ./...\n",
		"run: go build -tags probe.x ./...\n",
	} {
		if p := probeProblems(map[string]string{".github/workflows/x.yml": text, "scripts/x.sh": text}); len(p) != 0 {
			t.Errorf("%q is not the probe tag, but: %v", text, p)
		}
	}
	// Shell punctuation after the tag does not hide it.
	for _, text := range []string{
		"run: go build -tags probe;echo\n", "run: go build -tags probe&&x\n", "run: $(go build -tags probe)\n", "run: go build -tags=probe;\n",
		"run: go build -tags probe|cat\n", "run: go build -tags=probe)\n", "run: go build -tags probe>x\n", "run: go build -tags probe\\\n",
	} {
		for _, path := range []string{".github/workflows/x.yml", "scripts/x.sh"} {
			if p := probeProblems(map[string]string{path: text}); len(p) == 0 {
				t.Errorf("%s: %q is the probe tag, but no problem was found", path, text)
			}
		}
	}
	for name, mutate := range map[string]func(map[string]string){
		"a workflow runs the target":     func(m map[string]string) { m[".github/workflows/verify.yml"] = "run: make probe-acl\n" },
		"a workflow builds with the tag": func(m map[string]string) { m[".github/workflows/fuzz.yml"] = "run: go build -tags probe ./...\n" },
		"the release builds with tags":   func(m map[string]string) { m[".goreleaser.yaml"] += "    tags:\n      - probe\n" },
		"the release names the probes":   func(m map[string]string) { m[".goreleaser.yaml"] += "# probe\n" },
		"verify depends on the probes": func(m map[string]string) {
			m["Makefile"] = strings.Replace(makefile, "verify: fmt-check", "verify: probe-acl fmt-check", 1)
		},
		"install depends on the probes": func(m map[string]string) {
			m["Makefile"] = strings.Replace(makefile, "install:", "install: probe-acl", 1)
		},
		"the target is gone":       func(m map[string]string) { m["Makefile"] = "verify: x\n" },
		"the target loses the tag": func(m map[string]string) { m["Makefile"] = strings.Replace(makefile, "-tags probe", "", 1) },
		"the target loses the switch": func(m map[string]string) {
			m["Makefile"] = strings.Replace(makefile, runLine, "\"$$dir/tailkeeper-probe\"", 1)
		},
		"the target hard-codes its output": func(m map[string]string) {
			m["Makefile"] = strings.Replace(makefile, `--out "$(PROBE_OUT)"`, "--out internal/probe/testdata/observed", 1)
		},
		"the target drops --out":        func(m map[string]string) { m["Makefile"] = strings.Replace(makefile, ` --out "$(PROBE_OUT)"`, "", 1) },
		"the target builds in the tree": func(m map[string]string) { m["Makefile"] = strings.Replace(makefile, "mktemp -d", "pwd", 1) },
		// The ways past the first checks.
		"verify runs the target in a recipe line": func(m map[string]string) {
			m["Makefile"] = strings.Replace(makefile, "verify: fmt-check test\n", "verify: fmt-check test\n\t$(MAKE) probe-acl\n", 1)
		},
		"verify has the target on a continuation line": func(m map[string]string) {
			m["Makefile"] = strings.Replace(makefile, "verify: fmt-check test\n", "verify: fmt-check \\\n\tprobe-acl test\n", 1)
		},
		"verify builds with the tag in a recipe line": func(m map[string]string) {
			m["Makefile"] = strings.Replace(makefile, "verify: fmt-check test\n", "verify: fmt-check test\n\tgo vet -tags probe ./cmd/...\n", 1)
		},
		"a prerequisite of verify runs the target": func(m map[string]string) {
			m["Makefile"] = strings.Replace(makefile, "other:\n\ttrue\n", "other:\n\t$(MAKE) probe-acl\n", 1)
			m["Makefile"] = strings.Replace(m["Makefile"], "verify: fmt-check test\n", "verify: fmt-check test other\n", 1)
		},
		"a workflow quotes the tag":                   func(m map[string]string) { m[".github/workflows/a.yml"] = "run: go build -tags \"probe\" ./...\n" },
		"a workflow lists the tag":                    func(m map[string]string) { m[".github/workflows/a.yml"] = "run: go build -tags=live,probe ./...\n" },
		"a workflow quotes a list that holds the tag": func(m map[string]string) { m[".github/workflows/a.yml"] = "run: go build -tags 'x probe' ./...\n" },
		"a workflow with the extension yaml":          func(m map[string]string) { m[".github/workflows/a.yaml"] = "run: make probe-acl\n" },
		"a script runs the target":                    func(m map[string]string) { m["scripts/x.sh"] = "#!/bin/sh\nmake probe-acl\n" },
		"a script builds with the tag":                func(m map[string]string) { m["scripts/x.sh"] = "#!/bin/sh\ngo build -tags probe ./cmd/tailkeeper\n" },
		"the switch is exported for the whole recipe": func(m map[string]string) {
			m["Makefile"] = strings.Replace(makefile, "@dir=", "@export TAILKEEPER_LIVE=1; dir=", 1)
		},
		"the switch is exported for the target": func(m map[string]string) {
			m["Makefile"] = strings.Replace(makefile, "probe-acl:\n", "probe-acl: export TAILKEEPER_LIVE := 1\nprobe-acl:\n", 1)
		},
		"the switch is exported for the Makefile": func(m map[string]string) { m["Makefile"] = "export TAILKEEPER_LIVE = 1\n" + makefile },
		"everything is exported":                  func(m map[string]string) { m["Makefile"] = "export\n" + makefile },
		"the switch is set on the build line": func(m map[string]string) {
			m["Makefile"] = strings.Replace(strings.Replace(makefile, runLine, "\"$$dir/tailkeeper-probe\"", 1), "\tgo build", "\tTAILKEEPER_LIVE=1 go build", 1)
		},
		"another target sets the switch": func(m map[string]string) {
			m["Makefile"] = strings.Replace(makefile, "other:\n\ttrue", "other:\n\tTAILKEEPER_LIVE=1 true", 1)
		},
		"another file takes the tag": func(m map[string]string) {
			m["cmd/tailkeeper/other.go"] = "//go:build linux && probe\n\npackage main\n"
		},
		"main imports the probes": func(m map[string]string) {
			m["cmd/tailkeeper/main.go"] = "package main\n\nimport \"github.com/abm9111/tailkeeper/internal/probe\"\n"
		},
		"probe_on.go loses its tag": func(m map[string]string) {
			m["cmd/tailkeeper/probe_on.go"] = "package main\n\nimport \"github.com/abm9111/tailkeeper/internal/probe\"\n"
		},
	} {
		m := clone(good)
		mutate(m)
		if p := probeProblems(m); len(p) == 0 {
			t.Errorf("%s: no problem found", name)
		}
	}
}
