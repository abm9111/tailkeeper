package cli

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// diffJSON decodes the JSON of a diff command.
func diffJSON(t *testing.T, stdout string) tools.ACLDiffOutput {
	t.Helper()
	var out tools.ACLDiffOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("stdout is not acl_diff's JSON: %q (%v)", stdout, err)
	}
	return out
}

const (
	diffOld = "{\n\t\"tagOwners\": {\"tag:ci\": [\"autogroup:admin\"]},\n\t\"acls\": [{\"action\": \"accept\", \"src\": [\"tag:ci\"], \"dst\": [\"tag:ci:22\"]}],\n}\n"
	diffNew = "// widened\n{\n\t\"tagOwners\": {\"tag:ci\": [\"autogroup:admin\"]},\n\t\"acls\": [{\"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"tag:ci:22\"]}],\n}\n"
)

// `acl diff OLD NEW` compares two files: no credential, no wrapper, no request, Build once.
func TestDiffOfTwoFilesNeedsNoCredentialOrFetch(t *testing.T) {
	h, builds := execHarness(t)
	older, newer := writeFile(t, "old.hujson", diffOld), writeFile(t, "new.hujson", diffNew)
	if code := h.run("--json", "acl", "diff", older, newer); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	if h.reexecProvider != nil || *builds != 1 {
		t.Errorf("the wrapper started (%v) or Build ran %d times; want no wrapper and one Build", h.reexecProvider != nil, *builds)
	}
	out := diffJSON(t, h.out.String())
	if out.Status != "changed" || out.Counts.Widening != 1 || out.Counts.Semantic != 1 || out.Old.Source != "file" || out.New.Source != "file" {
		t.Errorf("result = %+v", out)
	}
	// The text layout opens with a verdict, then the counts and the located change, with the
	// path the user typed in place of the side's name.
	h, _ = execHarness(t)
	if code := h.run("acl", "diff", older, newer); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	lines := strings.Split(h.out.String(), "\n")
	if lines[0] != "CHANGED · 1 widening, 1 semantic" || !strings.Contains(h.out.String(), "new.hujson:4: warning: widening: added acls+grants") || strings.Contains(h.out.String(), "untrusted text") {
		t.Errorf("output:\n%s", h.out)
	}
	// --quiet prints nothing when the command succeeds; the same files in the other order
	// are a change too, and a file against itself is equal.
	h, _ = execHarness(t)
	if code := h.run("acl", "diff", "--quiet", older, newer); code != 0 || h.out.Len() != 0 {
		t.Errorf("--quiet: exit %d, output %q", code, h.out)
	}
	h, _ = execHarness(t)
	if code := h.run("acl", "diff", older, older); code != 0 || !strings.HasPrefix(h.out.String(), "EQUAL · ") {
		t.Errorf("a file against itself: exit %d, output %q", code, h.out)
	}
	// The flags say the same as the arguments.
	h, _ = execHarness(t)
	if code := h.run("--json", "acl", "diff", "--against", older, "--from", newer); code != 0 || diffJSON(t, h.out.String()).Counts.Widening != 1 {
		t.Errorf("flags: exit %d, output %s", code, h.out)
	}
}

// A side that is not a policy is exit 2 with its place in the file that was typed.
func TestADiffOfAnInvalidFileIsExit2(t *testing.T) {
	h, _ := execHarness(t)
	bad, good := writeFile(t, "bad.hujson", "{\n\"acls\": [\n{,}\n]\n}"), writeFile(t, "good.hujson", "{}")
	if code := h.run("acl", "diff", bad, good); code != 2 {
		t.Fatalf("exit %d, want 2: %s", code, h.err)
	}
	out := h.out.String()
	if !strings.HasPrefix(out, "INVALID · 1 problem found before anything was compared") || !strings.Contains(out, "bad.hujson:3:2: error: invalid character") {
		t.Errorf("output:\n%s", out)
	}
}

// An empty file or empty standard input is refused on every side, before anything is read or
// compared: an empty text is not a policy, and a side that read as nothing must not make the
// other side look like an addition. The binder says so for every file flag; this is the same
// refusal for the flags and arguments of the diff.
func TestADiffRefusesAnEmptyFileOrStandardInputOnEverySide(t *testing.T) {
	empty, good := writeFile(t, "empty.hujson", ""), writeFile(t, "good.hujson", diffOld)
	for name, args := range map[string][]string{
		"OLD":                         {empty, good},
		"NEW":                         {good, empty},
		"--against":                   {"--against", empty, "--from", good},
		"--from":                      {"--against", good, "--from", empty},
		"--from on standard input":    {"--against", good, "--from", "-"},
		"--against on standard input": {"--against", "-", "--from", good},
		"--offline":                   {"--offline", "--against", empty, "--from", good},
	} {
		f := apitest.New(t)
		h := newHarness(t, f)
		h.r.Stdin = strings.NewReader("")
		if code := h.run(append([]string{"acl", "diff"}, args...)...); code != 2 || !strings.Contains(h.err.String(), " is empty; ") {
			t.Errorf("%s: exit %d, stderr %q; want 2 and a refusal that says the text is empty", name, code, h.err)
		}
		if h.out.Len() != 0 || len(f.Requests()) != 0 {
			t.Errorf("%s: stdout %q, %d requests; want none", name, h.out, len(f.Requests()))
		}
	}
}

// With one side given, the other is the live policy: --against FILE makes the live policy
// the new side, --from FILE makes it the old one.
func TestDiffAgainstLiveDirections(t *testing.T) {
	f := apitest.New(t)
	f.Handle("GET", "/api/v2/tailnet/T1234CNTRL/acl", func(w http.ResponseWriter, r *http.Request) {
		apitest.DetailsOK(diffNew, api.ETagOf([]byte(diffNew)), nil, nil).Write(w)
	})
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/settings", 200, `{"aclsExternallyManagedOn":false}`)
	older := writeFile(t, "old.hujson", diffOld)
	h := newHarness(t, f)
	if code := h.run("--json", "acl", "diff", "--against", older); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	out := diffJSON(t, h.out.String())
	if out.Old.Source != "file" || out.New.Source != "live" || out.Counts.Widening != 1 || out.ExternallyManaged != "false" {
		t.Errorf("against alone: %+v", out)
	}
	for _, c := range out.Changes {
		if c.Class == "widening" && (c.Op != "added" || c.NewLine == 0 || c.OldLine != 0) || c.Class == "semantic" && (c.Op != "changed" || c.NewLine == 0 || c.OldLine == 0) {
			t.Errorf("change = %+v", c)
		}
	}
	h = newHarness(t, f)
	if code := h.run("--json", "acl", "diff", "--from", older); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	if out := diffJSON(t, h.out.String()); out.Old.Source != "live" || out.New.Source != "file" || out.Counts.Widening != 0 || out.Counts.Semantic != 1 {
		t.Errorf("from alone (a narrowing): %+v", out)
	}
	for _, r := range f.Requests() {
		if r.Method != "GET" {
			t.Errorf("a diff sent %s %s", r.Method, r.Path)
		}
	}
	// --against live is the same as no --against; both sides live is refused.
	h = newHarness(t, f)
	if code := h.run("acl", "diff", "--against", "live"); code != 2 || !strings.Contains(h.err.String(), "both sides would be the live policy") {
		t.Errorf("both sides live: exit %d, stderr %q", code, h.err)
	}
}

// --from-version and --to-version name a stored policy. Either one together with the file
// flag of the same side (--against live included) is refused before the credential is asked
// for, and nothing is read from the API.
func TestAVersionFlagClashesWithTheTextOfTheSameSide(t *testing.T) {
	h, _ := execHarness(t)
	if code := h.run("acl", "diff", "--help"); code != 0 || !strings.Contains(h.err.String()+h.out.String(), "-from-version") || !strings.Contains(h.err.String()+h.out.String(), "-to-version") {
		t.Fatalf("help exit %d:\n%s\n%s", code, h.out, h.err)
	}
	older := writeFile(t, "old.hujson", diffOld)
	newer := writeFile(t, "new.hujson", diffNew)
	for _, args := range [][]string{
		{"acl", "diff", "--from-version", "v1.x", "--against", older},
		{"acl", "diff", "--to-version", "v1.x", "--from", newer},
		{"acl", "diff", "--to-version", "v1.x", "--patch", newer},
		{"acl", "diff", "--from-version", "v1.x", "--against", "live"},
	} {
		h, builds := execHarness(t)
		if code := h.run(args...); code != 2 || !strings.HasPrefix(h.err.String(), "tailkeeper: usage: ") {
			t.Errorf("%v: exit %d, stderr %q", args, code, h.err)
		}
		if h.reexecProvider != nil || *builds != 0 {
			t.Errorf("%v: the wrapper started or the configuration loaded", args)
		}
	}
}

// --offline needs no credential and refuses a live side before it reads anything.
func TestOfflineRefusesALiveSideOnTheCommandLine(t *testing.T) {
	h, builds := execHarness(t)
	older := writeFile(t, "old.hujson", diffOld)
	if code := h.run("acl", "diff", "--offline", "--from", older); code != 2 || !strings.HasPrefix(h.err.String(), "tailkeeper: validation_failed: ") || !strings.Contains(h.err.String(), "--offline compares two files") {
		t.Errorf("exit %d, stderr %q", code, h.err)
	}
	if h.reexecProvider != nil || *builds != 1 {
		t.Errorf("wrapper started %v, Build ran %d times; want a command that needs no credential", h.reexecProvider != nil, *builds)
	}
	h, _ = execHarness(t)
	if code := h.run("acl", "diff", "--offline", "--patch", older); code != 2 || !strings.Contains(h.err.String(), "applied to the live policy") {
		t.Errorf("an offline patch: exit %d, stderr %q", code, h.err)
	}
}

// The classes, the gate: each class of change exits 8 under --fail-on change, and its own
// token exits 8 only for its own class; a comment or a layout is exit 0 whatever is asked.
func TestFailOnChangeFiresForEveryChangeClass(t *testing.T) {
	const base = `{"tests": [{"src": "a", "accept": ["x:1"]}], "acls": [{"action": "accept", "src": ["g"], "dst": ["x:1"]}], "groups": {"group:g": []}}`
	cases := []struct {
		name, old, new, token string
		ignorable             bool
	}{
		{"defaults", `{"groups": {"group:g": []}}`, `{"groups": {"group:g": []}, "acls": []}`, "defaults", false},
		{"testsReduced", base, strings.Replace(base, `"tests": [{"src": "a", "accept": ["x:1"]}], `, "", 1), "tests-reduced", false},
		{"widening", base, strings.Replace(base, `"src": ["g"]`, `"src": ["*"]`, 1), "widening", false},
		{"tailscaleWritten", base, strings.TrimSuffix(base, "}") + `, "nodeAttrs": [{"target": ["autogroup:member"], "attr": ["funnel"]}]}`, "", true},
		{"semantic", base, strings.Replace(base, `"group:g": []`, `"group:g": ["m@example.com"]`, 1), "", false},
	}
	for _, c := range cases {
		older, newer := writeFile(t, "old.hujson", c.old), writeFile(t, "new.hujson", c.new)
		run := func(extra ...string) (int, string) {
			h, _ := execHarness(t)
			code := h.run(append(append([]string{"acl", "diff"}, extra...), older, newer)...)
			return code, h.err.String()
		}
		if code, stderr := run("--fail-on", "change"); code != 8 || !strings.Contains(stderr, "findings_present") {
			t.Errorf("%s: --fail-on change exit %d (%s), want 8", c.name, code, stderr)
		}
		if c.ignorable {
			if code, _ := run("--fail-on", "change", "--ignore-tailscale-written"); code != 0 {
				t.Errorf("%s: ignored, --fail-on change exit %d, want 0", c.name, code)
			}
		}
		for _, token := range []string{"defaults", "tests-reduced", "widening"} {
			want := 0
			if token == c.token {
				want = 8
			}
			if code, _ := run("--fail-on", token); code != want {
				t.Errorf("%s: --fail-on %s exit %d, want %d", c.name, token, code, want)
			}
		}
	}
	// A comment and a layout change only: nothing is found, whatever is asked for.
	older, newer := writeFile(t, "old.hujson", base), writeFile(t, "new.hujson", "// the same\n{\n  \"tests\": [{\"src\": \"a\", \"accept\": [\"x:1\"]}],\n  \"acls\": [{\"action\": \"accept\", \"src\": [\"g\"], \"dst\": [\"x:1\"]}],\n  \"groups\": {\"group:g\": []},\n}\n")
	h, _ := execHarness(t)
	if code := h.run("acl", "diff", "--fail-on", "change,defaults,tests-reduced,widening", older, newer); code != 0 {
		t.Errorf("a comment and a layout: exit %d: %s", code, h.err)
	}
	// A kind acl_diff does not compute is refused, not counted as zero.
	h, _ = execHarness(t)
	if code := h.run("acl", "diff", "--fail-on", "warnings", older, newer); code != 2 || !strings.Contains(h.err.String(), "warnings") {
		t.Errorf("--fail-on warnings: exit %d, stderr %q", code, h.err)
	}
	// The help line lists the four kinds the diff computes, and the usage names both arguments.
	h, _ = execHarness(t)
	h.run("acl", "diff", "--help")
	if !strings.Contains(h.err.String(), "[OLD [NEW]]") {
		t.Errorf("usage:\n%s", h.err)
	}
}

// A page continues from its nextChange on the command line, and --section narrows it.
func TestADiffPagesOnTheCommandLine(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"groups": {`)
	for i := range 60 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"group:g` + string(rune('a'+i/26)) + string(rune('a'+i%26)) + `": ["m@example.com"]`)
	}
	b.WriteString(`}}`)
	older, newer := writeFile(t, "old.hujson", "{}"), writeFile(t, "new.hujson", b.String())
	h, _ := execHarness(t)
	if code := h.run("--json", "acl", "diff", older, newer); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	first := diffJSON(t, h.out.String())
	if !first.Truncated || first.NextChange == "" || len(first.Changes) != 50 || first.Matched != 60 {
		t.Fatalf("first page: %+v", first)
	}
	h, _ = execHarness(t)
	if code := h.run("--json", "acl", "diff", "--from-change", first.NextChange, older, newer); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	if rest := diffJSON(t, h.out.String()); len(rest.Changes) != 10 || rest.Truncated {
		t.Errorf("second page: %d changes, truncated %v", len(rest.Changes), rest.Truncated)
	}
	h, _ = execHarness(t)
	if code := h.run("acl", "diff", "--from-change", first.NextChange, older, newer); code != 0 || !strings.Contains(h.out.String(), "CHANGED · 60 semantic") {
		t.Errorf("text of the second page: exit %d\n%s", code, h.out)
	}
	h, _ = execHarness(t)
	if code := h.run("acl", "diff", "--section", "hosts", older, newer); code != 0 || strings.Contains(h.out.String(), "group:") {
		t.Errorf("--section hosts: exit %d\n%s", code, h.out)
	}
}

// The text layout of `acl history` prints the id of each version and the id before it, so that
// a person can give them to `acl diff --from-version` and `--to-version` without --json.
func TestTheVersionIdsOfTheTextHistoryFeedTheDiffFlags(t *testing.T) {
	f := apitest.New(t)
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/logging/configuration", 200, apitest.AuditACLUpdates().Body)
	h := newHarness(t, f)
	if code := h.run("acl", "history"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	lines := strings.Split(strings.TrimSpace(h.out.String()), "\n")
	for _, word := range []string{"VERSION", "PREVIOUS", "EVENT-TIME"} {
		if !strings.Contains(lines[0], word) {
			t.Errorf("the header has no %s:\n%s", word, h.out)
		}
	}
	idRE := regexp.MustCompile(`v1\.[A-Za-z0-9_-]+`)
	var ids [][]string
	for _, line := range lines[1:] {
		if found := idRE.FindAllString(line, -1); len(found) == 2 {
			ids = append(ids, found)
		}
	}
	if len(ids) != 2 {
		t.Fatalf("%d rows hold a version and a previous id, want 2:\n%s", len(ids), h.out)
	}
	// The ids of a row are those of the entry on its line: the version, then the previous.
	h = newHarness(t, f)
	if code := h.run("--json", "acl", "diff", "--from-version", ids[0][1], "--to-version", ids[0][0]); code != 0 {
		t.Fatalf("diff exit %d: %s", code, h.err)
	}
	out := diffJSON(t, h.out.String())
	if out.Status != "changed" || out.Old.Version != ids[0][1] || out.New.Version != ids[0][0] || out.Old.Source != "version" {
		t.Errorf("the diff of the ids the text printed: %+v", out)
	}
	if ids[0][0] == ids[1][0] || ids[0][1] == ids[0][0] {
		t.Errorf("the ids repeat: %v", ids)
	}
}
