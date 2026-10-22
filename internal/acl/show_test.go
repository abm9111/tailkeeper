package acl

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// addressRE finds the logins of a text; testShow masks each to its first character and its
// domain, as the registry does, so that two logins of different lengths read alike.
var addressRE = regexp.MustCompile(`[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+)`)

func testShow(s string, _ int) string {
	return addressRE.ReplaceAllStringFunc(s, func(m string) string {
		at := strings.IndexByte(m, '@')
		return m[:1] + "…" + m[at:]
	})
}

func parseShown(t testing.TB, text string, show Show) *Doc {
	t.Helper()
	d, err := ParseShown(context.Background(), []byte(text), show)
	if err != nil {
		t.Fatalf("ParseShown: %v", err)
	}
	return d
}

// group is a policy with one group of n members whose logins have local parts of the given
// length.
func group(n, localLen int) string {
	var b strings.Builder
	b.WriteString(`{"groups": {"group:big": [`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, `"a%0*d@example.com"`, localLen-1, i)
	}
	b.WriteString(`]}, "hosts": {`)
	b.WriteString(fmt.Sprintf(`"h%0*d@example.com": "192.0.2.1"`, localLen-1, 7))
	b.WriteString(`}, "acls": [{"action": "accept", "src": ["group:big"], "dst": [`)
	b.WriteString(fmt.Sprintf(`"w%0*d@example.com:22"`, localLen-1, 3))
	b.WriteString(`]}]}`)
	return b.String()
}

// shownBoth shows both sides of a comparison through testShow.
var shownBoth = DiffOptions{OldShow: testShow, NewShow: testShow}

// everything flattens a result to the bytes a reader of it could compare.
func everything(r *DiffResult) string {
	return fmt.Sprintf("%+v|%d|%t|%s|%d|%d", r.Changes, r.Matched, r.Truncated, r.NextChange, r.Counts, len(r.Changes))
}

// What a result quotes of a policy is cut after the policy is shown: two policies whose logins
// differ in length and read alike once masked give the same result, down to the bytes, however
// the texts are cut. Without a Show the cut falls where the real text says, and the lengths
// show.
func TestWhatADiffQuotesIsCutAfterTheTextIsShown(t *testing.T) {
	newer := `{"groups": {}, "hosts": {}, "acls": []}`
	results := map[int]string{}
	for _, local := range []int{9, 40} {
		r, err := Diff(context.Background(), mustParse(t, group(200, local)), mustParse(t, newer), shownBoth)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Changes) == 0 || !slices.ContainsFunc(r.Changes, func(c Change) bool { return c.Old.Truncated }) {
			t.Fatalf("no change was cut, so the test checked nothing: %+v", r.Changes)
		}
		results[local] = everything(r)
	}
	if results[9] != results[40] {
		t.Errorf("the result tells the length of a login:\n%.500s\n%.500s", results[9], results[40])
	}
	// The control: without a Show the two differ.
	plain := map[int]string{}
	for _, local := range []int{9, 40} {
		r, err := Diff(context.Background(), mustParse(t, group(200, local)), mustParse(t, newer), DiffOptions{})
		if err != nil {
			t.Fatal(err)
		}
		plain[local] = everything(r)
	}
	if plain[9] == plain[40] {
		t.Error("without a Show the cut text was the same for both lengths: the test cannot see a leak")
	}
}

// Truncated says the text was cut as a reader sees it, not that the real text is long: a group
// whose real text is past 1 KiB and whose shown text is not is not cut.
func TestATextIsCutOnlyWhenItsShownTextIsPast1KiB(t *testing.T) {
	older := group(60, 40) // about 3.6 KiB of text, about 1.7 KiB shown
	older60 := mustParse(t, older)
	empty := mustParse(t, `{"groups": {"group:big": []}, "hosts": {}, "acls": []}`)
	r, err := Diff(context.Background(), older60, empty, shownBoth)
	if err != nil {
		t.Fatal(err)
	}
	cut := 0
	for _, c := range r.Changes {
		if c.Old.Truncated {
			cut++
		}
		// Whatever the shown text is, no byte of a real login is in the result.
		if strings.Contains(everything(r), "a00000000000000000000000000000000000000") {
			t.Fatalf("a real login is in the result: %+v", c)
		}
	}
	// 60 members shown as a…@example.com are 60 * 20 bytes: past 1 KiB, so the group is cut.
	if cut == 0 {
		t.Errorf("no change is cut: %+v", r.Changes)
	}
	small := mustParse(t, group(20, 40)) // 20 shown members: about 400 bytes
	r, err = Diff(context.Background(), small, empty, shownBoth)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Changes {
		if c.Old.Truncated {
			t.Errorf("a text of %d shown bytes is cut, though the real text is %d: %+v", len(c.Old.Text), len(group(20, 40)), c)
		}
	}
}

// A pointer, a key and a finding are cut after the policy is shown as well.
func TestAPointerAndAKeyAreCutAfterTheTextIsShown(t *testing.T) {
	results := map[int]string{}
	for _, local := range []int{9, 90} {
		long := fmt.Sprintf("a%0*d@example.com", local-1, 1) + strings.Repeat("x", 1200)
		// A name made of three hundred logins: past 1 KiB as it is, and past it again when
		// masked, and so long that only a head of it is read.
		var many strings.Builder
		for i := 0; i < 300; i++ {
			fmt.Fprintf(&many, "u%0*d@example.com,", local-1, i)
		}
		text := fmt.Sprintf(`{"hosts": {%q: "192.0.2.1", %q: "192.0.2.2"}, "%s@example.com": {"b": 1, "b": 2}, %q: {"c": 1, "c": 2}}`,
			long, long, strings.Repeat("u", local), many.String())
		d := parseShown(t, text, testShow)
		f := d.Findings()
		if len(f) != 3 {
			t.Fatalf("findings = %+v", f)
		}
		r, err := Diff(context.Background(), d, mustParse(t, `{}`), shownBoth)
		if err != nil {
			t.Fatal(err)
		}
		// A column is a position in the real text, and the caller of the engine maps it or leaves
		// it out; the strings and the cuts are the engine's.
		var seen []string
		for _, x := range f {
			seen = append(seen, fmt.Sprintf("%s|%s|%s|%s", x.Code, x.Pointer, x.Key, x.FirstKey))
		}
		results[local] = fmt.Sprintf("%s|%v|%s", strings.Join(seen, ";"), d.UnknownSectionsShown(), everything(r))
	}
	if results[9] != results[90] {
		t.Errorf("a pointer, a key or a name tells the length of a login:\n%.400s\n%.400s", results[9], results[90])
	}
}

// The closed list of notes holds every sentence a change can carry, and none of them quotes a
// policy: each is produced by a comparison whose names are all logins.
func TestEveryNoteOfAChangeIsInTheClosedList(t *testing.T) {
	const amy = "amy@example.com"
	rule := func(src, dst string) string {
		return `{"action": "accept", "src": [` + src + `], "dst": [` + dst + `]}`
	}
	ssh := func(src, dst, users, action string) string {
		return `{"action": "` + action + `", "src": [` + src + `], "dst": [` + dst + `], "users": [` + users + `]}`
	}
	pairs := [][2]string{
		{`{"acls": [` + rule(`"tag:ci"`, `"`+amy+`:22"`) + `]}`, `{"acls": [` + rule(`"*"`, `"`+amy+`:22"`) + `]}`},
		{`{"acls": [` + rule(`"tag:ci"`, `"`+amy+`:22"`) + `]}`, `{"acls": [` + rule(`"autogroup:member"`, `"`+amy+`:22"`) + `]}`},
		{`{"acls": [` + rule(`"`+amy+`"`, `"tag:x:22"`) + `]}`, `{"acls": [` + rule(`"`+amy+`"`, `"tag:x:22", "autogroup:internet:*"`) + `]}`},
		{`{"groups": {"group:a": ["` + amy + `"]}}`, `{"groups": "` + amy + `"}`},
		{`{"groups": "` + amy + `"}`, `{"groups": {"group:a": ["` + amy + `"]}}`},
		{`{}`, `{"acls": []}`},
		{`{"acls": []}`, `{"acls": [` + rule(`"`+amy+`"`, `"`+amy+`:1"`) + `]}`},
		{`{"acls": [` + rule(`"`+amy+`"`, `"`+amy+`:1"`) + `]}`, `{}`},
		{`{"grants": []}`, `{}`},
		{`{}`, `{"ssh": []}`},
		{`{"ssh": []}`, `{"ssh": [` + ssh(`"`+amy+`"`, `"tag:t"`, `"u"`, "accept") + `]}`},
		{`{"ssh": [` + ssh(`"`+amy+`"`, `"tag:t"`, `"u"`, "accept") + `]}`, `{"ssh": []}`},
		{`{"ssh": [` + ssh(`"`+amy+`"`, `"tag:t"`, `"u"`, "accept") + `]}`, `{}`},
		{`{}`, `{"ssh": [` + ssh(`"`+amy+`"`, `"tag:t"`, `"u"`, "accept") + `]}`},
		{`{"ssh": [` + ssh(`"`+amy+`"`, `"tag:t"`, `"u"`, "check") + `]}`, `{"ssh": [` + ssh(`"`+amy+`"`, `"tag:t"`, `"u"`, "accept") + `]}`},
		{`{"ssh": [` + ssh(`"g"`, `"t"`, `"u"`, "accept") + `]}`, `{"ssh": [` + ssh(`"*"`, `"t"`, `"u"`, "accept") + `]}`},
		{`{"ssh": [` + ssh(`"g"`, `"t"`, `"u"`, "accept") + `]}`, `{"ssh": [` + ssh(`"g"`, `"autogroup:member"`, `"u"`, "accept") + `]}`},
		{`{"ssh": [` + ssh(`"g"`, `"t"`, `"u"`, "accept") + `]}`, `{"ssh": [` + ssh(`"g"`, `"t"`, `"root"`, "accept") + `]}`},
		{`{"tagOwners": {"tag:` + amy + `": []}}`, `{"tagOwners": {"tag:` + amy + `": ["autogroup:admin"]}}`},
		{`{"postures": {"posture:p": ["x"]}, "acls": [{"action": "accept", "src": ["` + amy + `"], "dst": ["tag:x:80"], "srcPosture": ["posture:p"]}]}`,
			`{"postures": {"posture:p": ["x"]}, "acls": [{"action": "accept", "src": ["` + amy + `"], "dst": ["tag:x:80"]}]}`},
		{`{"defaultSrcPosture": ["posture:` + amy + `"]}`, `{}`},
	}
	closed := ChangeNotes()
	if !slices.IsSorted(closed) || len(slices.Compact(slices.Clone(closed))) != len(closed) {
		t.Fatalf("the list is not sorted and free of repeats: %q", closed)
	}
	seen := 0
	for i, p := range pairs {
		for _, args := range [][2]string{{p[0], p[1]}, {p[1], p[0]}} {
			r := diff(t, args[0], args[1])
			for _, c := range r.Changes {
				if c.Note == "" {
					continue
				}
				seen++
				if !slices.Contains(closed, c.Note) {
					t.Errorf("pair %d: the note %q is not in the closed list", i, c.Note)
				}
				if strings.Contains(c.Note, amy) {
					t.Errorf("pair %d: the note quotes the policy: %q", i, c.Note)
				}
			}
		}
	}
	if seen < 20 {
		t.Errorf("the corpus produced %d notes, so it covers little of the list of %d", seen, len(closed))
	}
}

// manyChanges is a pair of policies whose comparison runs past one page.
func manyChanges(n int) (older, newer string) {
	var b strings.Builder
	b.WriteString(`{"groups": {`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, `"group:g%03d": ["a%03d@example.com"]`, i, i)
	}
	b.WriteString("}}")
	return `{}`, b.String()
}

// The cursor is a digest of the normal forms as their Docs show them, sealed when the options
// say how: a sealed cursor is not the unsealed one, is not taken for it, and tells two
// policies that are shown alike apart only if the seal does.
func TestACursorIsOfTheShownFormsAndSealedWhenAsked(t *testing.T) {
	older, newer := manyChanges(80)
	seal := func(b []byte) string { return "sealed:" + string(b) }
	cursorOf := func(newer string, show Show, o DiffOptions) string {
		o.OldShow, o.NewShow = show, show
		r, err := Diff(context.Background(), mustParse(t, older), mustParse(t, newer), o)
		if err != nil {
			t.Fatal(err)
		}
		if !r.Truncated {
			t.Fatal("the comparison fits one page")
		}
		return r.NextChange
	}
	plain := cursorOf(newer, nil, DiffOptions{})
	sealed := cursorOf(newer, nil, DiffOptions{Seal: seal})
	if plain == sealed {
		t.Errorf("a sealed cursor is the unsealed one: %s", plain)
	}
	// Shown alike: the logins of the new policy differ by one letter and read the same.
	other := strings.ReplaceAll(newer, "@example.com", "x@example.com")
	if a, b := cursorOf(newer, testShow, DiffOptions{}), cursorOf(other, testShow, DiffOptions{}); a != b {
		t.Errorf("two policies shown alike give two cursors: %s %s", a, b)
	}
	if a, b := cursorOf(newer, nil, DiffOptions{}), cursorOf(other, nil, DiffOptions{}); a == b {
		t.Errorf("two policies shown as they are give one cursor: %s", a)
	}
	// The unsealed cursor is refused where a seal is asked, and the sealed one where it is not.
	for name, c := range map[string]struct {
		cursor string
		o      DiffOptions
	}{
		"unsealed under a seal": {plain, DiffOptions{Seal: seal}},
		"sealed under none":     {sealed, DiffOptions{}},
		"sealed under another":  {sealed, DiffOptions{Seal: func(b []byte) string { return "other:" + string(b) }}},
	} {
		c.o.Cursor = c.cursor
		if _, err := Diff(context.Background(), mustParse(t, older), mustParse(t, newer), c.o); err == nil || !strings.Contains(err.Error(), "does not belong") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := Diff(context.Background(), mustParse(t, older), mustParse(t, newer), DiffOptions{Seal: seal, Cursor: sealed}); err != nil {
		t.Errorf("a sealed cursor under its seal: %v", err)
	}
}

// The message of a text that is past the size the engine reads does not say how long the text
// is: the text may stand for logins its caller never saw, and its length would tell how long
// they are.
func TestTheMessagesOfAnOversizedTextNameNoLength(t *testing.T) {
	big := func(extra int) []byte {
		return append([]byte(`{"a": "`), append([]byte(strings.Repeat("x", MaxBytes+extra)), []byte(`"}`)...)...)
	}
	messages := map[string][]string{}
	for _, extra := range []int{1, 5000} {
		text := big(extra)
		_, parseErr := Parse(context.Background(), text)
		_, patchErr := ApplyPatch(context.Background(), text, []byte(`[]`))
		_, appendErr := AppendTests(context.Background(), []byte(`{}`), [][]byte{text}, nil)
		for name, err := range map[string]error{"Parse": parseErr, "ApplyPatch": patchErr, "AppendTests": appendErr} {
			if err == nil {
				t.Fatalf("%s accepted a text of %d bytes", name, len(text))
			}
			messages[name] = append(messages[name], err.Error())
		}
	}
	for name, m := range messages {
		if m[0] != m[1] {
			t.Errorf("%s: the message tells the size of the text:\n%s\n%s", name, m[0], m[1])
		}
	}
}

func TestDisplayCost(t *testing.T) {
	for _, c := range []struct {
		s    string
		want int
	}{
		{"", 0}, {"abc", 3}, {"<>&", 18}, {`"\`, 4}, {"\x01", 9}, {"\x7f", 9}, {"é", 4}, {" ", 6}, {"a<b", 8},
	} {
		if got := DisplayCost(c.s); got != c.want {
			t.Errorf("DisplayCost(%q) = %d, want %d", c.s, got, c.want)
		}
	}
}

// A list of what a change gained and lost stops where its cost runs out, and counts the rest:
// elements of 400 angle brackets cost 2,400 characters each, so two of them fit.
func TestAListOfElementsStopsWhereItsCostRunsOut(t *testing.T) {
	var srcOld, srcNew []string
	for i := range 10 {
		srcOld = append(srcOld, fmt.Sprintf("%q", strings.Repeat("<", 400)+fmt.Sprintf("o%d", i)))
		srcNew = append(srcNew, fmt.Sprintf("%q", strings.Repeat("<", 400)+fmt.Sprintf("n%d", i)))
	}
	r := diff(t, `{"acls": [{"action": "accept", "src": [`+strings.Join(srcOld, ",")+`], "dst": ["tag:x:80"]}]}`,
		`{"acls": [{"action": "accept", "src": [`+strings.Join(srcNew, ",")+`], "dst": ["tag:x:80"]}]}`)
	ch := find(t, r, ClassSemantic, "tag:x")
	var src *FieldDelta
	for i := range ch.Fields {
		if ch.Fields[i].Field == "src" {
			src = &ch.Fields[i]
		}
	}
	if src == nil {
		t.Fatalf("no src field: %+v", ch.Fields)
	}
	if len(src.Added) != 2 || src.AddedMore != 8 || len(src.Removed) != 2 || src.RemovedMore != 8 {
		t.Errorf("added %d (+%d more), removed %d (+%d more), want 2 and 8 of each", len(src.Added), src.AddedMore, len(src.Removed), src.RemovedMore)
	}
}

// The raw pieces of an atom (the capabilities of a grant, say) are shown too: a login in them
// is masked before the text is cut.
func TestTheRawPiecesOfAnAtomAreShown(t *testing.T) {
	grant := func(who string) string {
		return `{"grants": [{"src": ["tag:a"], "dst": ["tag:b"], "app": {"tailscale.com/cap/test": [{"users": ["` + who + `"]}]}}]}`
	}
	r, err := Diff(context.Background(), mustParse(t, grant("amyamyamy@example.com")), mustParse(t, grant("bobbobbob@example.com")), shownBoth)
	if err != nil {
		t.Fatal(err)
	}
	all := everything(r)
	if strings.Contains(all, "amyamy") || strings.Contains(all, "bobbob") {
		t.Errorf("a login of a capability is in the result: %s", all)
	}
	if !strings.Contains(all, "a…@example.com") || !strings.Contains(all, "b…@example.com") {
		t.Errorf("the masked logins are not in the result: %s", all)
	}
}

// The two sides of a comparison are each shown through their own Show: what the old side holds is
// shown as the old side shows it and what the new side holds as the new side does, in the key,
// the texts, the items gained and lost, and the pointers.
func TestEachSideIsShownThroughItsOwnShow(t *testing.T) {
	side := func(tag string) Show {
		return func(s string, need int) string { return tag + "(" + testShow(s, need) + ")" }
	}
	o := DiffOptions{OldShow: side("O"), NewShow: side("N")}
	run := func(a, b string) *DiffResult {
		t.Helper()
		r, err := Diff(context.Background(), mustParse(t, a), mustParse(t, b), o)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	has := func(what, s, tag string) {
		t.Helper()
		if !strings.Contains(s, tag+"(") || strings.Contains(s, map[string]string{"O": "N", "N": "O"}[tag]+"(") {
			t.Errorf("%s = %q, want it shown by the %s side only", what, s, tag)
		}
	}
	rule := func(src string) string {
		return `{"acls": [{"action": "accept", "src": [` + src + `], "dst": ["tag:x:80"], "srcPosture": ["posture:p"]}], "postures": {"posture:p": ["node:os == 'linux'"]}}`
	}
	// An entry that came and an entry that went.
	r := run(`{}`, `{"groups": {"group:x": []}}`)
	has("the key of an entry that came", r.Changes[0].Key, "N")
	has("the text of an entry that came", r.Changes[0].New.Text, "N")
	r = run(`{"groups": {"group:x": []}}`, `{}`)
	has("the key of an entry that went", r.Changes[0].Key, "O")
	has("the text of an entry that went", r.Changes[0].Old.Text, "O")
	// A rule that was edited.
	r = run(rule(`"tag:a"`), rule(`"tag:b"`))
	ch := find(t, r, ClassSemantic, "tag:x")
	has("the key of a rule", ch.Key, "N")
	has("the old text", ch.Old.Text, "O")
	has("the new text", ch.New.Text, "N")
	has("the old pointer", ch.OldPointer, "O")
	has("the new pointer", ch.NewPointer, "N")
	for _, f := range ch.Fields {
		for _, s := range f.Added {
			has("an item gained", s, "N")
		}
		for _, s := range f.Removed {
			has("an item lost", s, "O")
		}
	}
	// A wide source: the rule that came and its destination are the new side's.
	r = run(rule(`"tag:a"`), rule(`"*"`))
	ch = find(t, r, ClassWidening, "src *")
	has("the new text of a widening", ch.New.Text, "N")
	for _, f := range ch.Fields {
		for _, s := range f.Added {
			has("an item of a widening", s, "N")
		}
	}
	// The posture a new rule no longer asks for: the rule is the new side's and the posture
	// the old side's.
	r = run(rule(`"tag:a"`), `{"acls": [{"action": "accept", "src": ["tag:a"], "dst": ["tag:x:80"]}], "postures": {"posture:p": ["node:os == 'linux'"]}}`)
	ch = find(t, r, ClassWidening, "srcPosture removed")
	has("the key of a posture that went", ch.Key, "N")
	has("the old text of a posture that went", ch.Old.Text, "O")
	has("the new text of a posture that went", ch.New.Text, "N")
	has("the posture that was lost", ch.Fields[0].Removed[0], "O")
	// A section only one side has.
	r = run(`{}`, `{"futureSection": 1}`)
	has("the section that came", r.Changes[0].Section, "N")
	r = run(`{"futureSection": 1}`, `{}`)
	has("the section that went", r.Changes[0].Section, "O")
	// A node attribute whose targets changed.
	r = run(`{"nodeAttrs": [{"target": ["tag:a"], "attr": ["custom:x"]}]}`, `{"nodeAttrs": [{"target": ["tag:b"], "attr": ["custom:x"]}]}`)
	ch = r.Changes[0]
	has("the old text of an attribute", ch.Old.Text, "O")
	has("the new text of an attribute", ch.New.Text, "N")
	has("the key of an attribute", ch.Key, "N")
	// A test that went.
	r = run(`{"tests": [{"src": "tag:a", "accept": ["tag:x:80"]}]}`, `{}`)
	has("the key of a test that went", r.Changes[0].Key, "O")
}

// A page counts the fields of a change in its cost: changes that gained a few thousand
// characters of members each fill a page of cost before they fill a page of changes.
func TestPageCostCountsTheFieldsOfAChange(t *testing.T) {
	var older, newer []string
	for i := 0; i < 40; i++ {
		older = append(older, fmt.Sprintf("%q", fmt.Sprintf("%s%02d", strings.Repeat("a", 500), i)))
		newer = append(newer, fmt.Sprintf("%q", fmt.Sprintf("%s%02d", strings.Repeat("b", 500), i)))
	}
	var a, b strings.Builder
	a.WriteString(`{"acls": [`)
	b.WriteString(`{"acls": [`)
	for i := 0; i < 60; i++ {
		if i > 0 {
			a.WriteString(",")
			b.WriteString(",")
		}
		fmt.Fprintf(&a, `{"action": "accept", "src": [%s], "dst": ["tag:t%02d:80"]}`, strings.Join(older, ","), i)
		fmt.Fprintf(&b, `{"action": "accept", "src": [%s], "dst": ["tag:t%02d:80"]}`, strings.Join(newer, ","), i)
	}
	a.WriteString(`]}`)
	b.WriteString(`]}`)
	r := diff(t, a.String(), b.String(), DiffOptions{PageSize: MaxPage})
	cost := 0
	for i := range r.Changes {
		cost += changeCost(&r.Changes[i])
	}
	if !r.Truncated || len(r.Changes) >= 12 {
		t.Fatalf("%d changes of cost %d, truncated %v: want a page that the fields of the changes fill", len(r.Changes), cost, r.Truncated)
	}
	if cost > pageCost+30000 {
		t.Errorf("the page costs %d, past %d and one change", cost, pageCost)
	}
}

// The digest of a cursor is of each side's own view: two sides that show their text differently
// give a cursor that follows the old side's view on the old side's forms.
func TestACursorOfTheTwoSidesFollowsEachSidesShow(t *testing.T) {
	older, newer := manyChanges(80)
	cursor := func(oldShow, newShow Show) string {
		r, err := Diff(context.Background(), mustParse(t, older), mustParse(t, newer), DiffOptions{OldShow: oldShow, NewShow: newShow})
		if err != nil {
			t.Fatal(err)
		}
		return r.NextChange
	}
	// An old side that is empty shows the same through any Show; the new side's view decides.
	mask := func(s string, _ int) string { return strings.ReplaceAll(s, "a0", "z0") }
	if a, b := cursor(nil, nil), cursor(nil, mask); a == b {
		t.Error("the new side's view does not reach the cursor")
	}
	// A view of the old side that changes what the old side holds changes the cursor too.
	oldText := `{"groups": {"group:a0": ["a000@example.com"]}}`
	cursorOld := func(oldShow Show) string {
		r, err := Diff(context.Background(), mustParse(t, oldText), mustParse(t, newer), DiffOptions{OldShow: oldShow})
		if err != nil {
			t.Fatal(err)
		}
		return r.NextChange
	}
	if a, b := cursorOld(nil), cursorOld(mask); a == b {
		t.Error("the old side's view does not reach the cursor")
	}
}

// A page counts the names and the pointers of a change in its cost: sections with names of 800
// characters fill a page long before a hundred of them do.
func TestPageCostCountsTheNamesAndPointersOfAChange(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{`)
	for i := 0; i < 100; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"%s%03d": 1`, strings.Repeat("s", 800), i)
	}
	b.WriteString(`}`)
	r := diff(t, `{}`, b.String(), DiffOptions{PageSize: MaxPage})
	if !r.Truncated || len(r.Changes) < 10 || len(r.Changes) >= 50 {
		t.Errorf("%d changes of 100 on the page, truncated %v: want a page that the names and pointers fill", len(r.Changes), r.Truncated)
	}
}
