package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/hujson"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
)

// serveFormatted makes the model's live policy the formatted text, so the ETag
// the model derives is the ETag of the body it serves.
func serveFormatted(t *testing.T, w *world) { t.Helper(); serveFormattedText(t, w, liveText) }

// serveFormattedText makes text, formatted, the live policy.
func serveFormattedText(t *testing.T, w *world, text string) {
	t.Helper()
	f, err := hujson.Format([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	w.serveText(string(f))
}

func checksByName(list []SelfCheck) map[string]SelfCheck {
	out := map[string]SelfCheck{}
	for _, c := range list {
		out[c.Name] = c
	}
	return out
}

func fixedNow() func() time.Time {
	return func() time.Time { return time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC) }
}

func runCommand(t *testing.T, w *world, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errb bytes.Buffer
	code = command(context.Background(), w.f.Client(t), args, &out, &errb, fixedNow())
	return out.String(), errb.String(), code
}

func TestEachSelfCheckHoldsOnAWellFormedPolicyAndFailsOnARewriteThatMeansSomethingElse(t *testing.T) {
	w := newWorld(t)
	serveFormatted(t, w)
	held := checksByName(RunSelfCheck(context.Background(), newExec(w.f.Client(t), Options{Gap: 0})))
	for _, name := range []string{"reformat", "round-trip", "summary", "etag"} {
		c, ok := held[name]
		if !ok || !c.Held {
			t.Errorf("%s: %+v", name, c)
		}
	}
	if held["summary"].Count == 0 {
		t.Errorf("summary compared nothing: %+v", held["summary"])
	}
	if held["etag"].Count != 1 {
		t.Errorf("etag: %+v", held["etag"])
	}

	prev := formatPolicy
	formatPolicy = func(context.Context, []byte) ([]byte, error) {
		return []byte(`{"acls":[]}`), nil
	}
	t.Cleanup(func() { formatPolicy = prev })
	w2 := newWorld(t)
	serveFormatted(t, w2)
	broken := checksByName(RunSelfCheck(context.Background(), newExec(w2.f.Client(t), Options{Gap: 0})))
	if broken["reformat"].Held || broken["reformat"].Count == 0 {
		t.Errorf("a dropped rule read as the same policy: %+v", broken["reformat"])
	}
	if broken["round-trip"].Held {
		t.Errorf("a dropped rule kept the normal form: %+v", broken["round-trip"])
	}
	if !broken["summary"].Held || !broken["etag"].Held {
		t.Errorf("the rewrite disturbed a check that does not format: summary %+v etag %+v", broken["summary"], broken["etag"])
	}

	w3 := newWorld(t)
	serveFormatted(t, w3)
	w3.etag = `"` + strings.Repeat("ab", 32) + `"`
	wrong := checksByName(RunSelfCheck(context.Background(), newExec(w3.f.Client(t), Options{Gap: 0})))
	if wrong["etag"].Held {
		t.Errorf("a different ETag held: %+v", wrong["etag"])
	}

	ok, n := countsMatch(nil, sectionCounts{counts: map[string]int{"acls": 1}})
	if ok || n != 0 {
		t.Errorf("a member the summary does not name matched: %v %d", ok, n)
	}
	bad, _ := countsMatch([]acl.SectionSummary{{Name: "acls", Known: true, State: acl.StateNonEmpty, Count: 2}}, sectionCounts{counts: map[string]int{"acls": 1}})
	if bad {
		t.Error("a section count that is not the array length matched")
	}
}

// changeOnePathType flips the first path type in path and plants texts the
// report must not print.
func changeOnePathType(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	obs, _ := doc["observations"].([]any)
	changed := false
	for _, raw := range obs {
		o, _ := raw.(map[string]any)
		res, _ := o["result"].(map[string]any)
		if res == nil {
			continue
		}
		paths, _ := res["paths"].([]any)
		if len(paths) == 0 {
			continue
		}
		p, _ := paths[0].(map[string]any)
		p["type"] = "number"
		res["texts"] = []any{"198.51.100.50 node.example.ts.net T1234CNTRL"}
		changed = true
		break
	}
	if !changed {
		t.Fatal("the capture has no path to change")
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAShapeDriftIsReportedByPathAndCountOnly(t *testing.T) {
	w := newWorld(t)
	serveFormatted(t, w)
	dir := t.TempDir()
	if _, stderr, code := runCommand(t, w, "--out", dir, "--gap", "0s"); code != 0 {
		t.Fatalf("writing the captures: exit %d\n%s", code, stderr)
	}
	changeOnePathType(t, filepath.Join(dir, "A-8.json"))
	stdout, stderr, code := runCommand(t, w, "--self-check", "--against", dir, "--gap", "0s")
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s\n%s", code, stdout, stderr)
	}
	for _, want := range []string{"shape: A-8 differs: 1 paths", "shape: A-1 same", "shape: A-9 same", "shape: A-10 same", "shape: H-1 same"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "all held") {
		t.Errorf("a drift was reported as held\n%s", stdout)
	}
	for _, secret := range []string{"198.51.100.50", "node.example.ts.net", "T1234CNTRL", "lee@example.com", "tag:live"} {
		if strings.Contains(stdout, secret) || strings.Contains(stderr, secret) {
			t.Errorf("the report printed %q\nstdout:\n%s\nstderr:\n%s", secret, stdout, stderr)
		}
	}
}

func TestTheSelfCheckPrintsNothingThatIsNotABooleanACountOrAProbeName(t *testing.T) {
	w := newWorld(t)
	// A name and an address in the policy, plus a tailnet-ID shape and a ts.net name.
	text := strings.Replace(liveText, `"hosts": {"live-host": "198.51.100.77"}`,
		`"hosts": {"live-host": "198.51.100.77", "node.example.ts.net": "192.0.2.8"}`, 1)
	f, err := hujson.Format([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	w.serveText(string(f))
	dir := t.TempDir()
	if _, stderr, code := runCommand(t, w, "--out", dir, "--gap", "0s"); code != 0 {
		t.Fatalf("writing the captures: exit %d\n%s", code, stderr)
	}
	stdout, stderr, code := runCommand(t, w, "--self-check", "--against", dir, "--out", dir, "--gap", "0s")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "self-check: ") || !strings.Contains(stdout, "checks, all held") {
		t.Fatalf("stdout:\n%s", stdout)
	}
	banned := []string{"198.51.100.77", "lee@example.com", "tag:live", "node.example.ts.net", "192.0.2.8", "T1234CNTRL", "svc:db", "group:eng"}
	blob := stdout + stderr
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		blob += string(b)
	}
	for _, secret := range banned {
		if strings.Contains(blob, secret) {
			t.Errorf("a self-check result contains %q", secret)
		}
	}
}

func TestTheSelfCheckRefusesToRunWithoutTailkeeperLive(t *testing.T) {
	t.Setenv("TAILKEEPER_LIVE", "")
	w := newWorld(t)
	var out, errb bytes.Buffer
	code := Command(context.Background(), w.f.Client(t), []string{"--self-check", "--against", t.TempDir(), "--gap", "0s"}, &out, &errb)
	if code != 2 || out.Len() != 0 || !strings.Contains(errb.String(), "TAILKEEPER_LIVE=1") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out.String(), errb.String())
	}
	if n := len(w.f.Requests()); n != 0 {
		t.Errorf("a refused self-check sent %d requests", n)
	}
}

func TestTheShapeCheckHoldsOnAnUnchangedWorldAgainstCapturesOfAFullRun(t *testing.T) {
	w := newWorld(t)
	serveFormatted(t, w)
	dir := t.TempDir()
	if _, stderr, code := runCommand(t, w, "--out", dir, "--gap", "0s"); code != 0 {
		t.Fatalf("writing the captures of a full run: exit %d\n%s", code, stderr)
	}
	stdout, stderr, code := runCommand(t, w, "--self-check", "--against", dir, "--gap", "0s")
	if code != 0 {
		t.Fatalf("an unchanged world differs from its own full-run captures: exit %d\n%s\n%s", code, stdout, stderr)
	}
	for _, id := range shapeProbeIDs {
		if !strings.Contains(stdout, "shape: "+id+" same") {
			t.Errorf("%s is not the same\n%s", id, stdout)
		}
	}
}

// everySectionKind holds each section kind the summary table counts: the elements of
// arrays, the entries of keyed sections, the routes and the exit node of autoApprovers,
// the regions of derpMap, and the scalars.
const everySectionKind = `{
	"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}, {"action": "accept", "src": ["tag:a"], "dst": ["tag:a:22"]}],
	"grants": [{"src": ["tag:a"], "dst": ["tag:a"], "ip": ["tcp:22"]}],
	"autoApprovers": {
		"routes": {"192.0.2.0/24": ["tag:a", "tag:b"], "198.51.100.0/24": ["tag:a"]},
		"exitNode": ["tag:a"]
	},
	"groups": {"group:eng": ["lee@example.com"], "group:ops": ["pat@example.com"]},
	"hosts": {"web": "192.0.2.5"},
	"ipsets": {"ipset:one": ["192.0.2.0/24"]},
	"nodeAttrs": [{"target": ["tag:a"], "attr": ["funnel"]}, {"target": ["*"], "attr": ["nextdns:abc123"]}],
	"postures": {"posture:p": ["node:os == 'linux'"]},
	"ssh": [{"action": "accept", "src": ["tag:a"], "dst": ["tag:a"], "users": ["root"]}],
	"sshTests": [{"src": "tag:a", "dst": ["tag:a"], "accept": ["root"]}],
	"tagOwners": {"tag:a": ["group:eng"], "tag:b": []},
	"tests": [{"src": "tag:a", "accept": ["tag:a:22"]}],
	"derpMap": {"omitDefaultRegions": true, "regions": {"900": {"regionID": 900, "regionCode": "ex", "regionName": "Example"}}},
	"disableIPv4": true,
	"OneCGNATRoute": "mapped",
	"randomizeClientPort": false,
	"defaultSrcPosture": ["posture:p"],
	"extraDNSRecords": [{"Name": "a.example.com", "Type": "A", "Value": "192.0.2.9"}],
	"externalTailnets": {"example.org": {"allowExternalReferencesTo": ["tag:a"]}},
	"attrConfig": {"a": {"broadcastToPeers": ["tag:a"]}}
}`

func TestTheSummaryCheckCountsEachSectionByTheRuleOfTheSummary(t *testing.T) {
	cases := []struct {
		name string
		text string
		want []string // words the line names as not compared
	}{
		{name: "every section kind the summary table counts", text: everySectionKind},
		{name: "an unknown section that is an object", text: `{"acls": [], "unknownThing": {"a": 1, "b": 2}}`, want: []string{"1 unknown"}},
		{name: "an unknown section that is an array and a scalar", text: `{"tagOwners": {"tag:a": []}, "x": [1, 2, 3], "y": "z"}`, want: []string{"2 unknown"}},
		{name: "a known section of the wrong type is one entry", text: `{"acls": {"a": 1, "b": 2}, "groups": ["x", "y"], "autoApprovers": [1, 2], "disableIPv4": [1, 2]}`},
		{name: "an empty autoApprovers field counts as one", text: `{"autoApprovers": {"routes": {}, "exitNode": []}}`},
		{name: "null sections are absent", text: `{"acls": null, "groups": null, "autoApprovers": null, "nope": null}`},
		{name: "a known section spelled twice in different case is not compared", text: `{"ACLs": [], "acls": [1, 2], "hosts": {"a": "192.0.2.1"}}`, want: []string{"acls"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := summaryCheck(context.Background(), []byte(c.text))
			if !got.Held || got.Note != "" {
				t.Fatalf("the summary check does not hold: %+v", got)
			}
			if strings.Join(got.Skipped, ",") != strings.Join(c.want, ",") {
				t.Errorf("not compared: %v, want %v", got.Skipped, c.want)
			}
		})
	}
}

func TestTheSummaryCheckHoldsOnManyLongUnknownSectionNames(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]`)
	for i := 0; i < 1500; i++ {
		b.WriteString(`, "` + strings.Repeat("u", 1100) + string(rune('a'+i%26)) + strings.Repeat("v", i%7) + `-` + strconv.Itoa(i) + `": {"k": ` + strconv.Itoa(i) + `}`)
	}
	b.WriteString(`}`)
	got := summaryCheck(context.Background(), []byte(b.String()))
	if !got.Held || got.Note != "" {
		t.Fatalf("the summary check does not hold on 1500 long unknown names: %+v", got)
	}
	if len(got.Skipped) != 1 || got.Skipped[0] != "1500 unknown" {
		t.Errorf("not compared: %v", got.Skipped)
	}
	for _, w := range got.Skipped {
		if strings.Contains(w, "uuuu") {
			t.Errorf("a name from the policy is in the line: %q", w)
		}
	}
}

func TestTheSummaryCheckHoldsOnEveryFixturePolicyInTheRepository(t *testing.T) {
	var paths []string
	err := filepath.WalkDir(filepath.Join("..", ".."), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == ".worktrees") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(p, ".hujson") {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The denominator: the policies the repository holds as of this test; fewer means the walk missed some.
	if len(paths) < 12 {
		t.Fatalf("found %d fixture policies, want at least 12: %v", len(paths), paths)
	}
	held := 0
	for _, p := range paths {
		text, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		got := summaryCheck(context.Background(), text)
		if got.Note == noteNotRead {
			// Only a policy the parser itself refuses (a byte order mark, UTF-16) has no summary to check.
			if _, perr := acl.Parse(context.Background(), text); perr == nil {
				t.Errorf("%s: the parser reads it but the summary check did not", p)
			}
			continue
		}
		held++
		if !got.Held {
			t.Errorf("%s: the summary check does not hold: %+v", p, got)
		}
	}
	if held < 8 {
		t.Errorf("the check was made on %d of %d fixture policies, want at least 8", held, len(paths))
	}
}

func TestTheIndependentCountsKnowEverySectionTheSummaryTableCounts(t *testing.T) {
	for _, sec := range acl.Sections() {
		kind, ok := knownSectionKinds[strings.ToLower(sec.Name)]
		if !ok {
			t.Errorf("%s: no kind in the independent counts", sec.Name)
			continue
		}
		want := map[acl.Shape]sectionKind{
			acl.ShapeRules: kindArray, acl.ShapeNodeAttrs: kindArray, acl.ShapeSet: kindArray, acl.ShapeTests: kindArray, acl.ShapeList: kindArray,
			acl.ShapeMap: kindMap, acl.ShapeStruct: kindStruct, acl.ShapeScalar: kindScalar,
		}[sec.Shape]
		if kind != want {
			t.Errorf("%s: kind %d, the table's shape wants %d", sec.Name, kind, want)
		}
	}
	if len(knownSectionKinds) != len(acl.Sections()) {
		t.Errorf("%d kinds for %d sections", len(knownSectionKinds), len(acl.Sections()))
	}
}

func TestTheShapeCheckDoesNotDependOnWhatTheTailnetHolds(t *testing.T) {
	w := newWorld(t)
	serveFormatted(t, w)
	w.warnings = []string{liveWarning} // this tailnet's policy has a warning, the other's has none
	dir := t.TempDir()
	if _, stderr, code := runCommand(t, w, "--out", dir, "--gap", "0s"); code != 0 {
		t.Fatalf("writing the captures: exit %d\n%s", code, stderr)
	}
	// The same API, a tailnet that holds no tag, no host alias, no login and no service.
	other := newWorld(t)
	serveFormattedText(t, other, `{"groups":{"group:zzmark":["zzmark"]},"acls":[]}`)
	stdout, stderr, code := runCommand(t, other, "--self-check", "--against", dir, "--gap", "0s")
	if code != 0 {
		t.Fatalf("a different tailnet differs in shape: exit %d\n%s\n%s", code, stdout, stderr)
	}
	for _, want := range []string{
		"shape: A-9 same (not compared: a tag, a host alias, a user, a service)",
		"shape: A-8 same (not compared: the form of the policy text, warnings and errors)",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the line does not name what was not compared; want %q\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "zzmark") || strings.Contains(stderr, "zzmark") {
		t.Errorf("a name from the tailnet is printed\n%s\n%s", stdout, stderr)
	}
}

func TestAShapeThatCannotBeComparedSaysSoInsteadOfDiffers(t *testing.T) {
	w := newWorld(t)
	serveFormatted(t, w)
	stdout, _, code := runCommand(t, w, "--self-check", "--against", t.TempDir(), "--gap", "0s")
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, stdout)
	}
	for _, id := range shapeProbeIDs {
		if !strings.Contains(stdout, "shape: "+id+" capture missing\n") {
			t.Errorf("%s: no capture is not said\n%s", id, stdout)
		}
	}
	if strings.Contains(stdout, "differs") {
		t.Errorf("a missing capture reads as a drift\n%s", stdout)
	}

	var b bytes.Buffer
	renderSelfCheck(&b, []SelfCheck{
		{Name: "A-1", Note: noteNotRun},
		{Name: "A-8", Note: noteProbeFailed},
		{Name: "summary", Note: noteNotRead},
		{Name: "etag"},
	})
	for _, want := range []string{"shape: A-1 not run\n", "shape: A-8 probe failed\n", "self-check: summary not read\n", "self-check: etag not held 0\n", "self-check: 4 checks, 4 not held\n"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("lacks %q\n%s", want, b.String())
		}
	}
}

func TestAShapeProbeThatDidNotRunSaysNotRun(t *testing.T) {
	w := newWorld(t)
	serveFormatted(t, w)
	dir := t.TempDir()
	if _, stderr, code := runCommand(t, w, "--out", dir, "--gap", "0s"); code != 0 {
		t.Fatalf("writing the captures: exit %d\n%s", code, stderr)
	}
	// The API answers 429 to the first validate: that probe fails and the run stops, so the rest are not run.
	limited := newWorld(t)
	serveFormatted(t, limited)
	limited.override = func(string) (apitest.Shape, bool) {
		return apitest.Shape{Status: 429, Body: `{"message":"slow down"}`}, true
	}
	stdout, _, code := runCommand(t, limited, "--self-check", "--against", dir, "--gap", "0s")
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "shape: A-1 probe failed\n") || !strings.Contains(stdout, "shape: A-8 not run\n") {
		t.Errorf("a stopped run is not told apart from a drift\n%s", stdout)
	}
}

func TestAgainstWithoutSelfCheckIsAUsageError(t *testing.T) {
	w := newWorld(t)
	stdout, stderr, code := runCommand(t, w, "--against", t.TempDir(), "--gap", "0s")
	if code != 2 || stdout != "" || !strings.Contains(stderr, "--against") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if n := len(w.f.Requests()); n != 0 {
		t.Errorf("a usage error sent %d requests", n)
	}
}

// changeStatus sets the status of the observation labelled label in the capture at path.
func changeStatus(t *testing.T, path, label string, status int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	changed := false
	obs, _ := doc["observations"].([]any)
	for _, raw := range obs {
		o, _ := raw.(map[string]any)
		res, _ := o["result"].(map[string]any)
		if o["label"] == label && res != nil {
			res["status"] = status
			changed = true
		}
	}
	if !changed {
		t.Fatalf("the capture has no observation %q", label)
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAStatusThatChangedIsADriftEvenWhereThePolicyTextIsNotCompared(t *testing.T) {
	w := newWorld(t)
	serveFormatted(t, w)
	dir := t.TempDir()
	if _, stderr, code := runCommand(t, w, "--out", dir, "--gap", "0s"); code != 0 {
		t.Fatalf("writing the captures: exit %d\n%s", code, stderr)
	}
	changeStatus(t, filepath.Join(dir, "A-8.json"), "plain, Accept: application/hujson", 404)
	stdout, _, code := runCommand(t, w, "--self-check", "--against", dir, "--gap", "0s")
	if code != 1 || !strings.Contains(stdout, "shape: A-8 differs: 1 paths") {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
}

func TestAPolicyThatCouldNotBeReadSaysNotReadForEachPolicyCheck(t *testing.T) {
	w := newWorld(t)
	serveFormatted(t, w)
	w.detailsFail = &struct {
		code int
		body string
	}{403, `{"message":"forbidden"}`}
	stdout, _, code := runCommand(t, w, "--self-check", "--against", t.TempDir(), "--gap", "0s")
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, stdout)
	}
	for _, name := range []string{"reformat", "round-trip", "summary", "etag"} {
		if !strings.Contains(stdout, "self-check: "+name+" not read\n") {
			t.Errorf("%s: a check that could not read says something else\n%s", name, stdout)
		}
	}
	if strings.Contains(stdout, "not held 0") {
		t.Errorf("a check that could not read reads as one that ran and failed\n%s", stdout)
	}
}

func TestAChecksThatCannotBeMadeCarryTheNotReadNote(t *testing.T) {
	text := []byte(`{"acls": []}`)
	if c := etagCheck(text, ""); c.Held || c.Note != noteNotRead {
		t.Errorf("no ETag: %+v", c)
	}
	if c := etagCheck(text, `"`+strings.Repeat("ab", 32)+`"`); c.Held || c.Note != "" {
		t.Errorf("a different ETag is a check that failed, not one that was not made: %+v", c)
	}
	prev := formatPolicy
	formatPolicy = func(context.Context, []byte) ([]byte, error) { return nil, os.ErrInvalid }
	t.Cleanup(func() { formatPolicy = prev })
	if c := reformatCheck(context.Background(), text); c.Held || c.Note != noteNotRead {
		t.Errorf("reformat: %+v", c)
	}
	if c := roundTripCheck(context.Background(), text); c.Held || c.Note != noteNotRead {
		t.Errorf("round-trip: %+v", c)
	}
}

func TestAFullSelfCheckMakesAsManyChecksAsItCountsWhetherOrNotThePolicyWasRead(t *testing.T) {
	dir := t.TempDir()
	w := newWorld(t)
	serveFormatted(t, w)
	if _, stderr, code := runCommand(t, w, "--out", dir, "--gap", "0s"); code != 0 {
		t.Fatalf("writing the captures: exit %d\n%s", code, stderr)
	}
	if got := SelfCheckCount(); got != 4+len(shapeProbeIDs) || got != 9 {
		t.Fatalf("SelfCheckCount is %d, want 9 (four policy checks and five shapes)", got)
	}
	read := RunSelfCheck(context.Background(), newExec(w.f.Client(t), Options{Against: dir}))
	if len(read) != SelfCheckCount() {
		t.Errorf("%d checks with the policy read, want %d", len(read), SelfCheckCount())
	}
	unread := newWorld(t)
	serveFormatted(t, unread)
	unread.detailsFail = &struct {
		code int
		body string
	}{403, `{"message":"forbidden"}`}
	got := RunSelfCheck(context.Background(), newExec(unread.f.Client(t), Options{Against: dir}))
	if len(got) != SelfCheckCount() {
		t.Errorf("%d checks with the policy unread, want %d", len(got), SelfCheckCount())
	}
}

func TestEveryLineTheSelfCheckPrintsIsOfAKindClassifyLineKnows(t *testing.T) {
	checks := []SelfCheck{
		{Name: "reformat", Held: true, Count: 2},
		{Name: "round-trip", Count: 1},
		{Name: "summary", Held: true, Count: 6, Skipped: []string{"autoApprovers", "1500 unknown"}},
		{Name: "summary", Count: 3, Skipped: []string{"1 unknown"}},
		{Name: "etag", Note: noteNotRead},
		{Name: "A-1", Held: true},
		{Name: "A-9", Held: true, Skipped: []string{"a tag", "a host alias"}},
		{Name: "A-8", Count: 4, Skipped: []string{"the form of the policy text", "warnings and errors"}},
		{Name: "A-10", Note: noteNoCapture},
		{Name: "A-14", Note: noteNotRun},
		{Name: "H-1", Note: noteProbeFailed},
	}
	var b bytes.Buffer
	renderSelfCheck(&b, checks)
	lines := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
	if len(lines) != len(checks)+1 {
		t.Fatalf("%d lines for %d checks:\n%s", len(lines), len(checks), b.String())
	}
	for _, line := range lines[:len(checks)] {
		if kind, _, _ := ClassifyLine(line); kind != LineCheck {
			t.Errorf("a check line is not classified as one: %q", line)
		}
	}
	kind, n, notHeld := ClassifyLine(lines[len(lines)-1])
	if kind != LineClosing || n != len(checks) || notHeld != 7 {
		t.Errorf("closing line %q: kind %d, %d checks, %d not held", lines[len(lines)-1], kind, n, notHeld)
	}
	var all bytes.Buffer
	renderSelfCheck(&all, []SelfCheck{{Name: "etag", Held: true, Count: 1}})
	if kind, n, notHeld := ClassifyLine(strings.Split(all.String(), "\n")[1]); kind != LineClosing || n != 1 || notHeld != 0 {
		t.Errorf("all held: %d %d %d", kind, n, notHeld)
	}
	for _, line := range []string{"", "self-check: summary held", "shape: A-1 same 198.51.100.7", "self-check: reformat held 1 (not compared: a.b@example.com)", "wrote 5 skeleton files to /tmp/x", "lee@example.com"} {
		if kind, _, _ := ClassifyLine(line); kind != LineUnknown {
			t.Errorf("%q is classified as a line the self-check prints", line)
		}
	}
}

// A shape comparison does not depend on who edited the policy, or on whether anyone did:
// captures taken with an audit log of user edits hold against a tailnet whose log holds an
// edit made with an API key, or no edit at all, and the line says what it left out.
func TestTheShapeCheckDoesNotDependOnTheAuditLogsEntries(t *testing.T) {
	user := map[string]any{
		"eventTime": "2026-10-01T00:00:00Z", "action": "UPDATE", "type": "CONFIG", "origin": "ADMIN_CONSOLE",
		"actor":  map[string]any{"id": "u1", "type": "USER", "loginName": "lee@example.com", "displayName": "Lee"},
		"target": map[string]any{"id": "t1", "name": "acl", "type": "TAILNET", "property": "ACL"},
		"old":    liveText, "new": strings.Replace(liveText, "tag:live", "tag:live2", 1),
	}
	apiKey := map[string]any{
		"eventTime": "2026-10-02T00:00:00Z", "action": "UPDATE", "old": liveText, "new": liveText,
		"actor": map[string]any{"id": "k1", "type": "API_KEY"},
	}
	w := newWorld(t)
	serveFormatted(t, w)
	w.auditLogs = []map[string]any{user, user}
	dir := t.TempDir()
	if _, stderr, code := runCommand(t, w, "--out", dir, "--gap", "0s"); code != 0 {
		t.Fatalf("writing the captures: exit %d\n%s", code, stderr)
	}
	const (
		entriesLeftOut = "shape: H-1 same (not compared: the actor and target of an entry, and the fields an entry may omit)"
		logLeftOut     = "shape: H-1 same (not compared: the audit log entries)"
	)
	for name, c := range map[string]struct {
		logs []map[string]any
		want string
	}{
		"an edit made with an API key": {[]map[string]any{apiKey}, entriesLeftOut},
		"an edit with no actor":        {[]map[string]any{{"eventTime": "2026-10-03T00:00:00Z", "old": liveText, "new": liveText}}, entriesLeftOut},
		// With no entry on one side there is no shape of an entry to compare, and the line says so.
		"no edit": {nil, logLeftOut},
	} {
		logs := c.logs
		other := newWorld(t)
		serveFormatted(t, other)
		other.auditLogs = logs
		stdout, stderr, code := runCommand(t, other, "--self-check", "--against", dir, "--gap", "0s")
		if code != 0 {
			t.Errorf("%s: the audit log differs in shape: exit %d\n%s\n%s", name, code, stdout, stderr)
			continue
		}
		if !strings.Contains(stdout, c.want) {
			t.Errorf("%s: the line does not name what was not compared; want %q\n%s", name, c.want, stdout)
		}
	}
}

// The entries of the audit log that acl_history and acl_diff read are compared by shape when
// both sides hold one: an entry whose old or new is not a string, or whose time is not, is a
// drift, whatever the values, the number of entries and the kind of actor.
func TestTheShapeCheckComparesTheEntriesThatVersionsDependOn(t *testing.T) {
	entry := func(mod func(e map[string]any)) map[string]any {
		e := map[string]any{
			"eventTime": "2026-10-01T00:00:00Z", "action": "UPDATE", "origin": "ADMIN_CONSOLE", "eventGroupID": "g1",
			"actor": map[string]any{"id": "u1", "type": "USER", "loginName": "lee@example.com"},
			"old":   liveText, "new": strings.Replace(liveText, "tag:live", "tag:live2", 1),
		}
		if mod != nil {
			mod(e)
		}
		return e
	}
	capture := func(t *testing.T, logs ...map[string]any) string {
		t.Helper()
		w := newWorld(t)
		serveFormatted(t, w)
		w.auditLogs = logs
		dir := t.TempDir()
		if _, stderr, code := runCommand(t, w, "--out", dir, "--gap", "0s"); code != 0 {
			t.Fatalf("writing the captures: exit %d\n%s", code, stderr)
		}
		return dir
	}
	against := func(t *testing.T, dir string, logs ...map[string]any) (string, int) {
		t.Helper()
		w := newWorld(t)
		serveFormatted(t, w)
		w.auditLogs = logs
		stdout, _, code := runCommand(t, w, "--self-check", "--against", dir, "--gap", "0s")
		return stdout, code
	}
	dir := capture(t, entry(nil), entry(nil))
	for name, c := range map[string]struct {
		logs []map[string]any
		held bool
		line string
	}{
		"one actor kind in the capture, another in the tailnet": {
			[]map[string]any{entry(func(e map[string]any) {
				e["actor"] = map[string]any{"id": "k1", "type": "API_KEY", "tags": []string{"tag:ci"}}
				e["target"] = map[string]any{"id": "t1", "type": "TAILNET"}
			})}, true, "shape: H-1 same",
		},
		"a different number of entries": {[]map[string]any{entry(nil), entry(nil), entry(nil)}, true, "shape: H-1 same"},
		"an old that is an object":      {[]map[string]any{entry(func(e map[string]any) { e["old"] = map[string]any{"acls": []any{}} })}, false, "shape: H-1 differs: 1 paths"},
		"a new that is a number":        {[]map[string]any{entry(func(e map[string]any) { e["new"] = 7 })}, false, "shape: H-1 differs: 1 paths"},
		"a time that is a number":       {[]map[string]any{entry(func(e map[string]any) { e["eventTime"] = 7 })}, false, "shape: H-1 differs: 1 paths"},
		"an old that is missing":        {[]map[string]any{entry(func(e map[string]any) { delete(e, "old") })}, false, "shape: H-1 differs: 1 paths"},
	} {
		stdout, code := against(t, dir, c.logs...)
		if (code == 0) != c.held || !strings.Contains(stdout, c.line) {
			t.Errorf("%s: exit %d, want held %v and the line %q\n%s", name, code, c.held, c.line, stdout)
		}
	}
	// A capture whose entry has an old that is an object does not hold against a tailnet whose
	// entries are the usual ones.
	bad := capture(t, entry(func(e map[string]any) { e["old"] = map[string]any{"acls": []any{}} }))
	if stdout, code := against(t, bad, entry(nil)); code == 0 || !strings.Contains(stdout, "shape: H-1 differs") {
		t.Errorf("a capture whose old is an object held: exit %d\n%s", code, stdout)
	}
	// With no entry on either side, the line says the entries were not compared.
	empty := capture(t)
	for name, c := range map[string]struct {
		dir  string
		logs []map[string]any
	}{
		"an empty capture and a tailnet with entries": {empty, []map[string]any{entry(nil)}},
		"a capture with entries and an empty tailnet": {dir, nil},
		"an empty capture and an empty tailnet":       {empty, nil},
	} {
		stdout, code := against(t, c.dir, c.logs...)
		if want := "shape: H-1 same (not compared: the audit log entries)"; code != 0 || !strings.Contains(stdout, want) {
			t.Errorf("%s: exit %d, want 0 and %q\n%s", name, code, want, stdout)
		}
	}
}

// What a shape comparison leaves out is named in the line, and every such word is one the
// line's pattern accepts: a word the pattern refuses makes the live run take the line for
// something the self-check does not print.
func TestEveryWordAShapeComparisonLeavesOutIsAcceptedByTheLinePattern(t *testing.T) {
	steps := map[string][]dependentStep{"H-1 with entries": h1EntrySteps}
	for _, id := range shapeProbeIDs {
		steps[id] = tailnetDependentSteps[id]
	}
	for id, st := range steps {
		for _, held := range []bool{true, false} {
			var b bytes.Buffer
			renderSelfCheck(&b, []SelfCheck{{Name: strings.TrimSuffix(id, " with entries"), Held: held, Count: 1, Skipped: dependentWords(st)}})
			line := strings.Split(b.String(), "\n")[0]
			if kind, _, _ := ClassifyLine(line); kind != LineCheck {
				t.Errorf("%s (held %v): %q is not a line the self-check prints", id, held, line)
			}
		}
	}
	if len(dependentWords(tailnetDependentSteps["H-1"])) == 0 || len(dependentWords(h1EntrySteps)) == 0 {
		t.Error("H-1 names nothing it leaves out")
	}
}

// Leaving the audit log's entries out does not leave out the rest of its answer: a change
// in the shape of the envelope is still a drift.
func TestADriftInTheAuditLogEnvelopeIsStillReportedWhenItsEntriesAreNotCompared(t *testing.T) {
	w := newWorld(t)
	serveFormatted(t, w)
	w.auditLogs = []map[string]any{{"eventTime": "2026-10-01T00:00:00Z", "old": liveText, "new": liveText}}
	dir := t.TempDir()
	if _, stderr, code := runCommand(t, w, "--out", dir, "--gap", "0s"); code != 0 {
		t.Fatalf("writing the captures: exit %d\n%s", code, stderr)
	}
	changeOnePathType(t, filepath.Join(dir, "H-1.json"))
	stdout, _, code := runCommand(t, w, "--self-check", "--against", dir, "--gap", "0s")
	if want := "shape: H-1 differs: 1 paths (not compared: the actor and target of an entry, and the fields an entry may omit)"; code != 1 || !strings.Contains(stdout, want) {
		t.Errorf("exit %d, want 1 and %q\n%s", code, want, stdout)
	}
}

// The same holds when the log holds no entry, and the line says the entries were not compared.
func TestADriftInTheAuditLogEnvelopeIsStillReportedWhenThereAreNoEntries(t *testing.T) {
	w := newWorld(t)
	serveFormatted(t, w)
	dir := t.TempDir()
	if _, stderr, code := runCommand(t, w, "--out", dir, "--gap", "0s"); code != 0 {
		t.Fatalf("writing the captures: exit %d\n%s", code, stderr)
	}
	// An empty log is read more than once under one label, and the last reading is the one compared.
	b, err := os.ReadFile(filepath.Join(dir, "H-1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, raw := range doc["observations"].([]any) {
		paths := raw.(map[string]any)["result"].(map[string]any)["paths"].([]any)
		paths[0].(map[string]any)["type"] = "number"
	}
	if b, err = json.Marshal(doc); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "H-1.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, _, code := runCommand(t, w, "--self-check", "--against", dir, "--gap", "0s")
	if code != 1 || !strings.Contains(stdout, "shape: H-1 differs: ") || !strings.Contains(stdout, " paths (not compared: the audit log entries)") {
		t.Errorf("exit %d, want 1 and a drift that names the entries as not compared\n%s", code, stdout)
	}
}

// The summary check reports the disagreement of the summary with the policy's own sections,
// through the self-check's own wiring and not only in the function that compares the counts.
func TestTheSummaryCheckDoesNotHoldWhenTheSummaryCountsWrong(t *testing.T) {
	prev := summarisePolicy
	summarisePolicy = func(ctx context.Context, d *acl.Doc) (*acl.Summary, error) {
		s, err := prev(ctx, d)
		if err != nil {
			return nil, err
		}
		for i := range s.Sections {
			if s.Sections[i].State == acl.StateNonEmpty {
				s.Sections[i].Count++
			}
		}
		return s, nil
	}
	t.Cleanup(func() { summarisePolicy = prev })
	w := newWorld(t)
	serveFormatted(t, w)
	got := checksByName(RunSelfCheck(context.Background(), newExec(w.f.Client(t), Options{Gap: 0})))
	if got["summary"].Held {
		t.Errorf("a summary that counts every section one too many held: %+v", got["summary"])
	}
	if !got["reformat"].Held || !got["etag"].Held {
		t.Errorf("the skewed summary disturbed a check that does not use it: %+v %+v", got["reformat"], got["etag"])
	}
}
