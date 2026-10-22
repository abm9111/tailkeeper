package acl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A rule's action is part of what it means: accept and deny are different atoms.
func TestActionIsPartOfAnAtom(t *testing.T) {
	a := `{"acls":[{"action":"accept","src":["a@example.com"],"dst":["x:1"]}]}`
	b := `{"acls":[{"action":"deny","src":["a@example.com"],"dst":["x:1"]}]}`
	if r := diff(t, a, b); r.SemanticallyEqual {
		t.Fatalf("accept -> deny read as unchanged: %+v", r.Counts)
	}
}

// An SSH test that expects check is not the same test as one that expects accept.
func TestSSHTestsCheckVersusAccept(t *testing.T) {
	a := `{"sshTests":[{"src":"a@example.com","dst":["tag:x"],"check":["root"]}]}`
	b := `{"sshTests":[{"src":"a@example.com","dst":["tag:x"],"accept":["root"]}]}`
	if r := diff(t, a, b); r.SemanticallyEqual {
		t.Fatalf("check -> accept read as unchanged: %+v", r.Counts)
	}
}

// A null grants section is absent and an empty one is not: the change is a defaults change.
func TestGrantsNullIsNotEmpty(t *testing.T) {
	a := `{"grants":null}`
	b := `{"grants":[]}`
	r := diff(t, a, b)
	if r.SemanticallyEqual || r.Counts.Defaults != 1 {
		t.Fatalf("null -> [] for grants: %+v", r.Counts)
	}
}

// Going from autogroup:member to * as a source is reported as a widening.
func TestMemberToStarIsAWidening(t *testing.T) {
	a := `{"acls":[{"action":"accept","src":["autogroup:member"],"dst":["x:1"]}]}`
	b := `{"acls":[{"action":"accept","src":["*"],"dst":["x:1"]}]}`
	r := diff(t, a, b)
	if r.Counts.Widening == 0 {
		t.Fatalf("autogroup:member -> * not a widening: %+v", r.Counts)
	}
}

// The legacy autogroup:members spelling widens an SSH rule exactly as autogroup:member does.
func TestSSHLegacyMembersAliasIsWide(t *testing.T) {
	mk := func(sel string) string {
		return `{"ssh":[{"action":"accept","src":["` + sel + `"],"dst":["tag:x"],"users":["alice"]}]}`
	}
	cur := diff(t, `{"ssh":[]}`, mk("autogroup:member"))
	old := diff(t, `{"ssh":[]}`, mk("autogroup:members"))
	if cur.Counts.Widening == 0 || old.Counts.Widening != cur.Counts.Widening {
		t.Fatalf("widening for autogroup:member %d, for the legacy alias %d", cur.Counts.Widening, old.Counts.Widening)
	}
}

func hasKey(r *DiffResult, class Class, key string) bool {
	for _, c := range r.Changes {
		if c.Class == class && strings.Contains(c.Key, key) {
			return true
		}
	}
	return false
}

// An SSH rule that goes from check to accept is reported when the source becomes an autogroup.
func TestCheckToAcceptWithAnAutogroupSource(t *testing.T) {
	a := `{"ssh":[{"action":"check","src":["alice@example.com"],"dst":["tag:x"],"users":["root"]}]}`
	b := `{"ssh":[{"action":"accept","src":["autogroup:member"],"dst":["tag:x"],"users":["root"]}]}`
	r := diff(t, a, b)
	if !hasKey(r, ClassWidening, "ssh check to accept") {
		t.Fatalf("no check-to-accept widening: %+v", r.Changes)
	}
}

// An SSH rule that goes from check to accept is reported when it lists no users.
func TestCheckToAcceptWithNoUsers(t *testing.T) {
	a := `{"ssh":[{"action":"check","src":["alice@example.com"],"dst":["tag:x"]}]}`
	b := `{"ssh":[{"action":"accept","src":["alice@example.com"],"dst":["tag:x"]}]}`
	r := diff(t, a, b)
	if !hasKey(r, ClassWidening, "ssh check to accept") {
		t.Fatalf("no check-to-accept widening: %+v", r.Changes)
	}
}

// A removed srcPosture is reported as a widening when the ports cannot be read.
func TestPostureRemovedWithUnreadablePorts(t *testing.T) {
	a := `{"grants":[{"src":["a@example.com"],"dst":["tag:x"],"ip":["weird"],"srcPosture":["posture:p"]}]}`
	b := `{"grants":[{"src":["b@example.com"],"dst":["tag:x"],"ip":["weird"]}]}`
	r := diff(t, a, b)
	if !hasKey(r, ClassWidening, "srcPosture removed") {
		t.Fatalf("posture removal not found: %+v", r.Changes)
	}
}

// A removed srcPosture is reported when the old and new port ranges meet at a single port.
func TestPostureRemovedWherePortRangesTouchAtOnePort(t *testing.T) {
	a := `{"acls":[{"action":"accept","src":["a@example.com"],"dst":["tag:x:80"],"srcPosture":["posture:p"]}]}`
	b := `{"acls":[{"action":"accept","src":["b@example.com"],"dst":["tag:x:70-80"]}]}`
	r := diff(t, a, b)
	if !hasKey(r, ClassWidening, "srcPosture removed") {
		t.Fatalf("posture removal not found: %+v", r.Changes)
	}
}

// IgnoreTailscaleWritten hides only the Tailscale-written class: a widening and a defaults
// change are still counted and listed.
func TestIgnoreTailscaleWrittenKeepsEveryOtherClassListed(t *testing.T) {
	a := `{"acls":[{"action":"accept","src":["a@example.com"],"dst":["x:1"]}]}`
	b := `{"acls":[{"action":"accept","src":["*"],"dst":["x:1"]}]}`
	r := diff(t, a, b, DiffOptions{IgnoreTailscaleWritten: true})
	if r.Counts.Widening == 0 {
		t.Fatalf("counts %+v", r.Counts)
	}
	got := false
	for _, c := range r.Changes {
		if c.Class == ClassWidening {
			got = true
		}
	}
	if !got {
		t.Fatalf("a widening is counted but not listed with IgnoreTailscaleWritten: %v", classes(r))
	}
	r = diff(t, `{}`, `{"acls":[]}`, DiffOptions{IgnoreTailscaleWritten: true})
	if r.Counts.Defaults == 0 || len(r.Changes) == 0 {
		t.Fatalf("defaults change hidden: %+v", r)
	}
}

func writtenCount(t *testing.T, a, b string) (written, semantic int) {
	r := diff(t, a, b)
	return r.Counts.TailscaleWritten, r.Counts.Semantic
}

// A log-stream rule to a wildcard destination is not the rule Tailscale writes.
func TestLogStreamToAWildcardDestinationIsNotTailscalesRule(t *testing.T) {
	base := `{"acls":[{"action":"accept","src":["z@example.com"],"dst":["x:1"]}`
	w, _ := writtenCount(t, base+`]}`, base+`,{"action":"accept","src":["logstream@tailscale"],"dst":["*:514"]}]}`)
	if w != 0 {
		t.Fatalf("a log-stream rule to a wildcard destination counted as Tailscale-written: %d", w)
	}
}

// A log-stream source beside another source is not the rule Tailscale writes; the exact shape is.
func TestLogStreamBesideOtherSourcesIsNotTailscalesRule(t *testing.T) {
	base := `{"acls":[{"action":"accept","src":["z@example.com"],"dst":["x:1"]}`
	w, _ := writtenCount(t, base+`]}`, base+`,{"action":"accept","src":["logstream@tailscale","zz@example.com"],"dst":["x:514"]}]}`)
	if w != 0 {
		t.Fatalf("a rule with another source beside logstream@tailscale counted as written: %d", w)
	}
	w, _ = writtenCount(t, base+`]}`, base+`,{"action":"accept","src":["logstream@tailscale"],"dst":["x:514"]}]}`)
	if w != 1 {
		t.Fatalf("the real shape is not Tailscale-written: %d", w)
	}
}

func preset(entry string) string {
	return `{"nodeAttrs":[{"target":["*"],"app":{"tailscale.com/app-connectors":[` + entry + `]}`
}

// An app connector entry counts as Tailscale-written only when it has exactly the fields a
// preset entry has: no unknown field, and a preset name.
func TestPresetShapeIsStructural(t *testing.T) {
	good := `{"name":"x","presetAppID":"p","connectors":["tag:c"]}`
	w, _ := writtenCount(t, `{}`, preset(good)+`}]}`)
	if w != 1 {
		t.Fatalf("a real preset entry is not written: %d", w)
	}
	w, _ = writtenCount(t, `{}`, preset(good)+`,"bogus":1}]}`)
	if w != 0 {
		t.Fatalf("a preset entry with an unknown field is written: %d", w)
	}
	w, _ = writtenCount(t, `{}`, preset(`{"name":"x","connectors":["tag:c"]}`)+`}]}`)
	if w != 0 {
		t.Fatalf("an app connector entry with no preset is written: %d", w)
	}
}

func nfBytes(t *testing.T, text string) []byte {
	b, err := NormalFormBytes(context.Background(), mustParse(t, text))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The normal form records which sources go with which destination, so swapping the sources of
// two rules changes the digest as well as the diff.
func TestDigestKnowsWhichSourcesGoWithWhichDestination(t *testing.T) {
	a := `{"acls":[{"action":"accept","src":["a@example.com"],"dst":["x:1"]},{"action":"accept","src":["b@example.com"],"dst":["y:1"]}]}`
	b := `{"acls":[{"action":"accept","src":["b@example.com"],"dst":["x:1"]},{"action":"accept","src":["a@example.com"],"dst":["y:1"]}]}`
	if r := diff(t, a, b); r.SemanticallyEqual {
		t.Fatal("diff says equal")
	}
	if bytes.Equal(nfBytes(t, a), nfBytes(t, b)) {
		t.Fatal("swapped sources give one digest")
	}
}

// The normal form records which section an entry belongs to, so the same entry moved between
// sections changes the digest.
func TestDigestKnowsWhichSectionAnEntryBelongsTo(t *testing.T) {
	a := `{"ipsets":{"ipset:x":["add 192.0.2.1"]}}`
	b := `{"groups":{"ipset:x":["add 192.0.2.1"]}}`
	if bytes.Equal(nfBytes(t, a), nfBytes(t, b)) {
		t.Fatal("an entry moved between sections gives one digest")
	}
}

// StripTests finds the tests sections when their names are written as unicode escapes.
func TestStripTestsRemovesEscapedNames(t *testing.T) {
	bs := "\x5c"
	esc := func(s string) string {
		var b strings.Builder
		for _, r := range s {
			b.WriteString(bs + "u00")
			b.WriteString(string("0123456789abcdef"[r>>4]))
			b.WriteString(string("0123456789abcdef"[r&15]))
		}
		return b.String()
	}
	for _, name := range []string{"tests", "sshTests"} {
		text := `{"` + esc(name) + `": [{"src":"a","accept":["b:1"]}], "groups": {}}`
		out, err := StripTests(context.Background(), []byte(text))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "accept") {
			t.Fatalf("%s written as escapes was not removed: %s", name, out)
		}
	}
}

func listOf(prefix string, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"%s%d"`, prefix, i)
	}
	return b.String()
}

func mustRefuse(t *testing.T, a, b string, what string) {
	t.Helper()
	da, db := mustParse(t, a), mustParse(t, b)
	start := time.Now()
	_, err := Diff(context.Background(), da, db, DiffOptions{})
	el := time.Since(start)
	t.Logf("%s: err=%v elapsed=%v (a=%d b=%d bytes)", what, err, el, len(a), len(b))
	if !errors.Is(err, ErrTooComplex) {
		t.Fatalf("%s: want a too_complex refusal, got %v after %v", what, err, el)
	}
}

// Comparing the big source sets of many (new atom, old atom) pairs is charged by size, so
// the work budget refuses it.
func TestOverlapOfLargeSourceSetsIsCharged(t *testing.T) {
	const n, k = 1500, 100
	oldSrcs, newSrcs := listOf("s", k), listOf("n", k)
	var oldRules, newRules []string
	for i := 0; i < n; i++ {
		oldRules = append(oldRules, fmt.Sprintf(`{"action":"accept","src":[%s],"dst":["tag:x:%d"],"srcPosture":["posture:p%d"],"id":%d}`, oldSrcs, i+1, i, i))
		newRules = append(newRules, fmt.Sprintf(`{"action":"accept","src":[%s],"dst":["tag:x:%d"],"id":%d}`, newSrcs, n+10, i))
	}
	mustRefuse(t, `{"acls":[`+strings.Join(oldRules, ",")+`]}`, `{"acls":[`+strings.Join(newRules, ",")+`]}`, "overlap")
}

// Testing whether big posture sets are subsets, for many pairs none of which is one, is
// charged by size.
func TestSubsetOfLargePostureSetsIsCharged(t *testing.T) {
	const n, k = 1500, 100
	post := func(last string) string {
		var b strings.Builder
		for i := 0; i < k-1; i++ {
			fmt.Fprintf(&b, `"posture:p%d",`, i)
		}
		b.WriteString(`"` + last + `"`)
		return b.String()
	}
	var oldRules, newRules []string
	for i := 0; i < n; i++ {
		oldRules = append(oldRules, fmt.Sprintf(`{"action":"accept","src":["a@example.com"],"dst":["tag:x:%d"],"srcPosture":[%s],"id":%d}`, i+1, post("posture:q"), i))
		newRules = append(newRules, fmt.Sprintf(`{"action":"accept","src":["a@example.com"],"dst":["tag:x:%d"],"srcPosture":[%s],"id":%d}`, i+1, post("posture:zz"), i))
	}
	mustRefuse(t, `{"acls":[`+strings.Join(oldRules, ",")+`]}`, `{"acls":[`+strings.Join(newRules, ",")+`]}`, "subset")
}

// One very long test source with many accept items is charged by the size of every key built
// from it, so the work budget refuses it before the memory does.
func TestALongTestSourceTimesManyItemsIsCharged(t *testing.T) {
	src := strings.Repeat("a", 1<<20)
	var items []string
	for i := 0; i < 3000; i++ {
		items = append(items, fmt.Sprintf(`"h%d:1"`, i))
	}
	text := `{"tests":[{"src":"` + src + `","accept":[` + strings.Join(items, ",") + `]}]}`
	_, err := Normalise(context.Background(), mustParse(t, text))
	if !errors.Is(err, ErrTooComplex) {
		t.Fatalf("want too_complex, got %v", err)
	}
}

// StripTests charges each removal by the size of the document, so 256 removals from a top level
// of 250,000 members are refused.
func TestStripTestsChargesEveryRemovalByTheSizeOfTheDocument(t *testing.T) {
	// 256 repeated "tests" members at the front, then many small members
	s := strings.Repeat(`"tests":[],`, 256)
	var m strings.Builder
	for i := 0; i < 250000; i++ {
		fmt.Fprintf(&m, `"k%d":1,`, i)
	}
	text := "{" + s + strings.TrimSuffix(m.String(), ",") + "}"
	start := time.Now()
	_, err := StripTests(context.Background(), []byte(text))
	el := time.Since(start)
	t.Logf("elapsed=%v err=%v bytes=%d", el, err, len(text))
	if !errors.Is(err, ErrTooComplex) {
		t.Fatalf("256 removals from a top level of 250,000 members were not refused (%v after %v)", err, el)
	}
}

// The order of a node attribute's ipPool is not a change.
func TestIPPoolOrderIsNotAChange(t *testing.T) {
	mk := func(pool string) string {
		return `{"nodeAttrs":[{"target":["*"],"attr":["x"],"ipPool":[` + pool + `]}]}`
	}
	r := diff(t, mk(`"100.64.0.0/24","100.64.1.0/24"`), mk(`"100.64.1.0/24","100.64.0.0/24"`))
	if !r.SemanticallyEqual {
		t.Fatalf("a reordered ipPool is a change: %+v", r.Counts)
	}
}

// A wildcard source already present for a destination makes a new port there no widening,
// whatever the order of the old rules.
func TestAWildcardAlreadyThereForADestinationIsNotNewWhateverTheOldRuleOrder(t *testing.T) {
	old := `{"acls":[{"action":"accept","src":["*"],"dst":["x:1"]},{"action":"accept","src":["autogroup:member"],"dst":["x:2"]}]}`
	nw := `{"acls":[{"action":"accept","src":["*"],"dst":["x:1"]},{"action":"accept","src":["autogroup:member"],"dst":["x:2"]},{"action":"accept","src":["*"],"dst":["x:3"]}]}`
	r := diff(t, old, nw)
	if r.Counts.Widening != 0 {
		t.Fatalf("a port added where * was already a source for the destination is %d widenings: %+v", r.Counts.Widening, r.Changes)
	}
}

// A check rule for everyone covers the accept that replaces a check, so no check-to-accept
// widening is reported.
func TestACheckRuleForEveryoneCoversTheAcceptThatReplacesACheck(t *testing.T) {
	old := `{"ssh":[{"action":"check","src":["alice@example.com"],"dst":["tag:x"],"users":["root"]}]}`
	nw := `{"ssh":[{"action":"accept","src":["alice@example.com"],"dst":["tag:x"],"users":["root"]},{"action":"check","src":["*"],"dst":["*"],"users":["*"]}]}`
	r := diff(t, old, nw)
	if hasKey(r, ClassWidening, "ssh check to accept") {
		t.Fatalf("a check rule for * covers the connection, yet check-to-accept is reported: %+v", r.Changes)
	}
}

// A case collision inside autoApprovers is found.
func TestCaseCollisionInAutoApproversIsFound(t *testing.T) {
	d := mustParse(t, `{"autoApprovers":{"routes":{"192.0.2.0/24":["a@example.com"]},"Routes":{"198.51.100.0/24":["b@example.com"]}}}`)
	found := false
	for _, f := range d.Findings() {
		if f.Code == FindingCaseCollision {
			found = true
		}
	}
	if !found {
		t.Fatalf("no case_collision finding for routes/Routes in autoApprovers: %+v", d.Findings())
	}
}

// Unknown sections are ordered by their folded names, so spelling one in another case is no change.
func TestUnknownSectionsAreOrderedByTheirFoldedName(t *testing.T) {
	a := `{"Zeta": 1, "alpha": 2}`
	b := `{"zeta": 1, "alpha": 2}`
	r := diff(t, a, b)
	if !r.SemanticallyEqual {
		t.Fatalf("a section spelled in another case is a change: %+v %+v", r.Counts, r.Changes)
	}
}

// A summarised scalar is cut at 1 KiB.
func TestASummarisedScalarIsCutAtOneKiB(t *testing.T) {
	long := strings.Repeat("x", 5000)
	s, err := Summarise(context.Background(), mustParse(t, `{"randomizeClientPort": "`+long+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range s.Sections {
		if row.Name == "randomizeClientPort" && len(row.Scalar) > 1024+4 {
			t.Fatalf("Scalar is %d bytes", len(row.Scalar))
		}
	}
}

// A host named like a group does not define that group.
func TestAHostNamedLikeAGroupDoesNotDefineTheGroup(t *testing.T) {
	d := mustParse(t, `{"hosts":{"group:eng@example.com":"192.0.2.1"},"acls":[{"action":"accept","src":["group:eng@example.com"],"dst":["*:*"]}]}`)
	s, err := Summarise(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.SyncedGroups) != 1 || s.SyncedGroups[0] != "group:eng@example.com" {
		t.Fatalf("synced groups: %v", s.SyncedGroups)
	}
}

// AppendTests with nothing to add returns its own copy, not the caller's buffer.
func TestAppendTestsReturnsItsOwnCopyWhenThereIsNothingToAdd(t *testing.T) {
	text := []byte(`{"a": 1}`)
	out, err := AppendTests(context.Background(), text, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if &out[0] == &text[0] {
		t.Fatal("the result shares the caller's buffer")
	}
}

// The caps are the values the documentation states.
func TestTheCapsAreTheDocumentedValues(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"MaxFindings", MaxFindings, 100},
		{"MaxLocations", MaxLocations, 100},
		{"MaxNames", MaxNames, 1000},
		{"MaxAtoms", MaxAtoms, 1 << 18},
		{"MaxBytes", MaxBytes, 4 << 20},
		{"MaxNodes", MaxNodes, 1 << 19},
		{"MaxFormatted", MaxFormatted, 16 << 20},
		{"1 KiB text cap", maxPointer, 1024},
		{"maxMessage", maxMessage, 512},
		{"MaxPatchOps", MaxPatchOps, 256},
		{"MaxAppended", MaxAppended, 4096},
		{"DefaultPage", DefaultPage, 50},
		{"MaxPage", MaxPage, 200},
		{"pageCost", pageCost, 56000},
		{"listCost", listCost, 6000},
		{"maxDeltaItems", maxDeltaItems, 50},
		{"maxSyncedRef", maxSyncedRef, 4096},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, the documented value is %d", c.name, c.got, c.want)
		}
	}
	if int64(MaxWork) != 1<<26 {
		t.Errorf("MaxWork = %d", MaxWork)
	}
}

// The 1 KiB text cut falls between 1,024 and 1,025 bytes, and the message cut between 512 and 513.
func TestTheTextCapIsExactlyOneKiB(t *testing.T) {
	for _, n := range []int{1023, 1024, 1025, 3000} {
		s := strings.Repeat("a", n)
		c := capped(s)
		if c.Truncated != (n > 1024) || c.Len != n || (n <= 1024 && c.Text != s) || len(c.Text) > 1024+len(ellipsis) {
			t.Errorf("capped(%d bytes) = len %d, truncated %v, text %d bytes", n, c.Len, c.Truncated, len(c.Text))
		}
		var tb textBuf
		tb.add(s)
		if got := tb.text(); got.Truncated != (n > 1024) || got.Len != n || len(got.Text) > 1024+len(ellipsis) {
			t.Errorf("textBuf(%d bytes) = len %d, truncated %v, text %d bytes", n, got.Len, got.Truncated, len(got.Text))
		}
		if got := capText(s); (n <= 1024) != (got == s) {
			t.Errorf("capText(%d bytes) = %d bytes", n, len(got))
		}
	}
	for _, n := range []int{511, 512, 513} {
		s := strings.Repeat("a", n)
		if got := capMessage(s); (n <= 512) != (got == s) {
			t.Errorf("capMessage(%d bytes) = %d bytes", n, len(got))
		}
	}
}

// A text of exactly MaxBytes is read and one byte more is refused, by Parse and by every guarded transform.
func TestTheSizeCapIsExactlyMaxBytes(t *testing.T) {
	ctx := context.Background()
	at := []byte("{" + strings.Repeat(" ", MaxBytes-2) + "}")
	over := []byte("{" + strings.Repeat(" ", MaxBytes-1) + "}")
	if len(at) != MaxBytes || len(over) != MaxBytes+1 {
		t.Fatal("construction")
	}
	if _, err := Parse(ctx, at); err != nil {
		t.Errorf("Parse of exactly MaxBytes: %v", err)
	}
	if _, err := Parse(ctx, over); !errors.Is(err, ErrTooComplex) {
		t.Errorf("Parse of MaxBytes+1: %v", err)
	}
	for name, fn := range map[string]func([]byte) error{
		"Standardize": func(b []byte) error { _, err := Standardize(ctx, b); return err },
		"Format":      func(b []byte) error { _, err := Format(ctx, b); return err },
		"StripTests":  func(b []byte) error { _, err := StripTests(ctx, b); return err },
	} {
		if err := fn(at); err != nil {
			t.Errorf("%s of exactly MaxBytes: %v", name, err)
		}
		if err := fn(over); !errors.Is(err, ErrTooComplex) {
			t.Errorf("%s of MaxBytes+1: %v", name, err)
		}
	}
}

// MaxPatchOps operations apply and one more is refused.
func TestThePatchCapIsExactlyMaxPatchOps(t *testing.T) {
	ops := func(n int) []byte {
		var b strings.Builder
		b.WriteString("[")
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"op":"add","path":"/k%d","value":1}`, i)
		}
		b.WriteString("]")
		return []byte(b.String())
	}
	if _, err := ApplyPatch(context.Background(), []byte(`{}`), ops(MaxPatchOps)); err != nil {
		t.Errorf("%d operations: %v", MaxPatchOps, err)
	}
	if _, err := ApplyPatch(context.Background(), []byte(`{}`), ops(MaxPatchOps+1)); !errors.Is(err, ErrTooComplex) {
		t.Errorf("%d operations: %v", MaxPatchOps+1, err)
	}
}

// MaxAppended+1 SSH tests are refused as MaxAppended+1 tests are.
func TestTheAppendCapAppliesToSSHTestsToo(t *testing.T) {
	entry := []byte(`{"src":"a","accept":["b:1"]}`)
	list := func(n int) [][]byte {
		out := make([][]byte, n)
		for i := range out {
			out[i] = entry
		}
		return out
	}
	ctx := context.Background()
	if _, err := AppendTests(ctx, []byte(`{}`), list(MaxAppended), list(MaxAppended)); err != nil {
		t.Errorf("%d of each: %v", MaxAppended, err)
	}
	if _, err := AppendTests(ctx, []byte(`{}`), nil, list(MaxAppended+1)); !errors.Is(err, ErrTooComplex) {
		t.Errorf("%d SSH tests: %v", MaxAppended+1, err)
	}
	if _, err := AppendTests(ctx, []byte(`{}`), list(MaxAppended+1), nil); !errors.Is(err, ErrTooComplex) {
		t.Errorf("%d tests: %v", MaxAppended+1, err)
	}
}

// Locate lists at most MaxLocations of each kind of match: by source and destination, and by source.
func TestLocateListsAtMostMaxLocationsOfEachKind(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"tests":[`)
	for i := 0; i < MaxLocations*2+5; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"src":"s","accept":["d:1"]}`)
	}
	b.WriteString(`]}`)
	d := mustParse(t, b.String())
	if got, cut := Locate(d, Failure{Src: "s", Dst: "d:1"}); len(got) != MaxLocations || cut != MaxLocations+5 || got[0].Match != MatchSrcAndDestination {
		t.Errorf("destination matches: %d listed, %d cut, first %v", len(got), cut, got[0].Match)
	}
	if got, cut := Locate(d, Failure{Src: "s"}); len(got) != MaxLocations || cut != MaxLocations+5 {
		t.Errorf("source matches: %d listed, %d cut", len(got), cut)
	}
}

// Exactly MaxAtoms atoms are read and one more, in another rule, is refused.
func TestTheAtomCapIsExactlyMaxAtoms(t *testing.T) {
	rule := func(n int, extra bool) string {
		var b strings.Builder
		b.WriteString(`{"acls":[{"action":"accept","src":["a"],"dst":[`)
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `"h%d:1"`, i)
		}
		b.WriteString(`]}`)
		if extra {
			b.WriteString(`,{"action":"accept","src":["b"],"dst":["z:1"]}`)
		}
		b.WriteString(`]}`)
		return b.String()
	}
	ctx := context.Background()
	if _, err := Normalise(ctx, mustParse(t, rule(MaxAtoms, false))); err != nil {
		t.Errorf("%d atoms: %v", MaxAtoms, err)
	}
	if _, err := Normalise(ctx, mustParse(t, rule(MaxAtoms, true))); !errors.Is(err, ErrTooComplex) {
		t.Errorf("%d atoms: %v", MaxAtoms+1, err)
	}
}

// 512 destinations by 512 protocols is exactly MaxAtoms for one rule; 513 by 512 is refused.
func TestTheExpansionOfOneRuleIsCappedAtMaxAtoms(t *testing.T) {
	rule := func(dsts, protos int) string {
		var d, p strings.Builder
		for i := 0; i < dsts; i++ {
			if i > 0 {
				d.WriteString(",")
			}
			fmt.Fprintf(&d, `"h%d:1"`, i)
		}
		for i := 0; i < protos; i++ {
			if i > 0 {
				p.WriteString(",")
			}
			fmt.Fprintf(&p, `"p%d"`, i)
		}
		return `{"acls":[{"action":"accept","src":["a"],"proto":[` + p.String() + `],"dst":[` + d.String() + `]}]}`
	}
	ctx := context.Background()
	if _, err := Normalise(ctx, mustParse(t, rule(512, 512))); err != nil {
		t.Errorf("512 x 512: %v", err)
	}
	_, e := Normalise(ctx, mustParse(t, rule(513, 512)))
	if !errors.Is(e, ErrTooComplex) || !strings.Contains(e.Error(), "destinations") {
		t.Errorf("513 x 512: %v", e)
	}
}

// A test that expands past MaxAtoms assertions is refused.
func TestATestExpandsToAtMostMaxAtomsAssertions(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"tests":[{"src":"a","accept":[`)
	for i := 0; i < MaxAtoms+1; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"h%d:1"`, i)
	}
	b.WriteString(`]}]}`)
	if _, err := Normalise(context.Background(), mustParse(t, b.String())); !errors.Is(err, ErrTooComplex) {
		t.Errorf("a test with %d assertions: %v", MaxAtoms+1, err)
	}
}

// A page holds DefaultPage changes, and at most MaxPage whatever size is asked for.
func TestAPageIsDefaultPageAndAtMostMaxPage(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"groups":{`)
	for i := 0; i < 400; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"group:g%d@example.com":[]`, i)
	}
	b.WriteString(`}}`)
	r := diff(t, `{}`, b.String())
	if len(r.Changes) != DefaultPage || !r.Truncated {
		t.Errorf("default page: %d changes", len(r.Changes))
	}
	r = diff(t, `{}`, b.String(), DiffOptions{PageSize: 100000})
	if len(r.Changes) != MaxPage || !r.Truncated {
		t.Errorf("an enormous page size: %d changes", len(r.Changes))
	}
}

// A case collision inside a rule is found in every section whose elements are read as structs.
func TestCaseCollisionInsideARuleIsFoundInEverySection(t *testing.T) {
	for _, sec := range []string{"acls", "grants", "ssh", "sshTests", "tests", "extraDNSRecords", "nodeAttrs"} {
		d := mustParse(t, `{"`+sec+`":[{"src":"a","SRC":"b"}]}`)
		found := false
		for _, f := range d.Findings() {
			if f.Code == FindingCaseCollision && f.Pointer == "/"+sec+"/0" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no case_collision finding for src/SRC in its first element: %+v", sec, d.Findings())
		}
	}
}

// The product of the destinations and the protocols of one grant is capped whatever merges
// afterwards, as it is for a rule of acls.
func TestTheExpansionOfOneGrantIsCappedAtMaxAtoms(t *testing.T) {
	grant := func(dsts, protos int) string {
		var d, p strings.Builder
		for i := 0; i < dsts; i++ {
			if i > 0 {
				d.WriteString(",")
			}
			d.WriteString(`"x"`)
		}
		for i := 0; i < protos; i++ {
			if i > 0 {
				p.WriteString(",")
			}
			fmt.Fprintf(&p, `"p%d:1"`, i)
		}
		return `{"grants":[{"src":["a"],"dst":[` + d.String() + `],"ip":[` + p.String() + `]}]}`
	}
	ctx := context.Background()
	if _, err := Normalise(ctx, mustParse(t, grant(512, 512))); err != nil {
		t.Errorf("512 x 512: %v", err)
	}
	_, err := Normalise(ctx, mustParse(t, grant(513, 512)))
	if !errors.Is(err, ErrTooComplex) || !strings.Contains(err.Error(), "destinations") {
		t.Errorf("513 x 512: %v", err)
	}
}

// The pointer of a change in a section written twice names the occurrence that was read.
func TestAPointerNamesTheOccurrenceOfARepeatedSectionThatWasRead(t *testing.T) {
	r := diff(t, `{"acls":[],"ACLS":[{"action":"accept","src":["a"],"dst":["x:1"]}]}`, `{"acls":[]}`)
	c := find(t, r, ClassSemantic, "x")
	if c.OldPointer != "/ACLS/0" {
		t.Fatalf("pointer %q, want /ACLS/0", c.OldPointer)
	}
}

// A node attribute given to other targets, in equal number, is a change.
func TestANodeAttributeGivenToOtherTargetsIsAChange(t *testing.T) {
	r := diff(t, `{"nodeAttrs":[{"target":["tag:a"],"attr":["x"]}]}`, `{"nodeAttrs":[{"target":["tag:b"],"attr":["x"]}]}`)
	if r.SemanticallyEqual {
		t.Fatalf("tag:a -> tag:b read as unchanged: %+v", r.Counts)
	}
}

// Synced groups are listed sorted whatever their order in the text.
func TestSyncedGroupsAreListedSorted(t *testing.T) {
	d := mustParse(t, `{"acls":[{"action":"accept","src":["group:b@example.com","group:c@example.com","group:a@example.com"],"dst":["x:1"]}]}`)
	s, err := Summarise(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"group:a@example.com", "group:b@example.com", "group:c@example.com"}
	if fmt.Sprint(s.SyncedGroups) != fmt.Sprint(want) {
		t.Fatalf("%v", s.SyncedGroups)
	}
}
