package acl

import (
	"bytes"
	"context"
	"errors"
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"

	"github.com/tailscale/hujson"

	"github.com/abm9111/tailkeeper/internal/guard"
)

const policyWithComments = "// header\n{\n\t// who\n\t\"groups\": {\"group:a\": [\"a@example.com\"]}, // trailing\n\t\"acls\": [\n\t\t{\"action\": \"accept\", \"src\": [\"group:a\"], \"dst\": [\"tag:x:80\"]},\n\t],\n}\n"

func TestApplyPatchKeepsTheCommentsAndLayoutItDoesNotTouch(t *testing.T) {
	ctx := context.Background()
	out, err := ApplyPatch(ctx, []byte(policyWithComments), []byte(`[
		// one more rule
		{"op": "add", "path": "/acls/-", "value": {"action": "accept", "src": ["group:a"], "dst": ["tag:y:22"]}}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	for _, kept := range []string{"// header\n", "\t// who\n", "// trailing\n", `"dst": ["tag:x:80"]}`} {
		if !strings.Contains(string(out), kept) {
			t.Errorf("%q was lost:\n%s", kept, out)
		}
	}
	r, err := Diff(ctx, mustParse(t, policyWithComments), mustParse(t, string(out)), DiffOptions{})
	if err != nil || r.Counts.Semantic != 1 || r.Changes[0].Op != OpAdded || r.Changes[0].Key != "tag:y" {
		t.Errorf("the patched text differs from the original by one atom: %+v, %v", r, err)
	}
	// replace, remove, move and test.
	for name, patch := range map[string]string{
		"replace": `[{"op": "replace", "path": "/groups/group:a/0", "value": "b@example.com"}]`,
		"remove":  `[{"op": "remove", "path": "/groups/group:a"}]`,
		"move":    `[{"op": "move", "from": "/groups", "path": "/hosts"}]`,
		"test":    `[{"op": "test", "path": "/groups/group:a/0", "value": "a@example.com"}, {"op": "add", "path": "/hosts", "value": {}}]`,
	} {
		if _, err := ApplyPatch(ctx, []byte(policyWithComments), []byte(patch)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestApplyPatchRefusesAPatchItCannotApplySafely(t *testing.T) {
	ctx := context.Background()
	manyOps := "[" + strings.Repeat(`{"op":"add","path":"/hosts","value":{}},`, MaxPatchOps+1) + "]"
	deep := strings.Repeat("[", 990) + strings.Repeat("]", 990)
	cases := []struct {
		name, text, patch string
		code              Code
		mentions          string
	}{
		{"a test that fails", policyWithComments, `[{"op": "test", "path": "/groups/group:a/0", "value": "other@example.com"}]`, CodeInvalid, "values differ"},
		{"a path that is not there", policyWithComments, `[{"op": "remove", "path": "/nothing"}]`, CodeInvalid, "value not found"},
		{"an operation that does not exist", policyWithComments, `[{"op": "frob", "path": "/a"}]`, CodeInvalid, "unknown operation"},
		{"a patch that is not an array", policyWithComments, `{"op": "add"}`, CodeInvalid, "JSON array"},
		{"a patch that does not parse", policyWithComments, `[{"op": "add"`, CodeInvalid, "the patch:"},
		{"a missing value", policyWithComments, `[{"op": "add", "path": "/x"}]`, CodeInvalid, `"value"`},
		{"a copy", policyWithComments, "[\n{\"op\": \"copy\", \"from\": \"/groups\", \"path\": \"/hosts\"}]", CodeInvalid, "copy"},
		{"too many operations", policyWithComments, manyOps, CodeTooComplex, "257 operations"},
		{"a patch that replaces the policy with an array", policyWithComments, `[{"op": "add", "path": "", "value": [1]}]`, CodeInvalid, "not an object"},
		{"a text that is not an object", `[1]`, `[]`, CodeInvalid, "must be a JSON object"},
		{"a text with a byte order mark", "\xef\xbb\xbf{}", `[]`, CodeInvalid, "the policy text: the text starts with a UTF-8 byte order mark"},
		{"a patch that is UTF-16", `{}`, "\xff\xfe[\x00]\x00", CodeInvalid, "the patch: the text is UTF-16"},
		{"a text that does not parse", `{"a": `, `[]`, CodeInvalid, "the policy text:"},
		{"a result too deep", `{"a": ` + deep + `}`, `[{"op": "add", "path": "/a` + strings.Repeat("/0", 989) + `/-", "value": ` + strings.Repeat("[", 30) + strings.Repeat("]", 30) + `}]`, CodeInvalid, "after the change"},
	}
	for _, c := range cases {
		_, err := ApplyPatch(ctx, []byte(c.text), []byte(c.patch))
		var e *Error
		if !errors.As(err, &e) || e.Code != c.code || !strings.Contains(e.Message, c.mentions) {
			t.Errorf("%s: err = %v, want %s mentioning %q", c.name, err, c.code, c.mentions)
		}
	}
	// The position of a copy is the position of its op in the patch.
	_, err := ApplyPatch(ctx, []byte(policyWithComments), []byte("[\n{\"op\": \"copy\", \"from\": \"/groups\", \"path\": \"/hosts\"}]"))
	var e *Error
	if !errors.As(err, &e) || e.Line != 2 || e.Column != 8 {
		t.Errorf("copy at %+v", e)
	}
	// A text over the size cap.
	big := append([]byte(`{"a":"`), bytes.Repeat([]byte("x"), MaxBytes)...)
	if _, err := ApplyPatch(ctx, append(big, `"}`...), []byte(`[]`)); !errors.Is(err, ErrTooComplex) {
		t.Errorf("a text past the size cap: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := ApplyPatch(cancelled, []byte(`{}`), []byte(`[]`)); !errors.Is(err, context.Canceled) {
		t.Errorf("a context that is done: %v", err)
	}
}

func TestStripTestsRemovesEveryTestsMemberAndNothingElse(t *testing.T) {
	ctx := context.Background()
	text := "{\n\t\"tests\": [{\"src\": \"a\", \"accept\": [\"x:1\"]}],\n\t// keep\n\t\"acls\": [],\n\t\"Tests\": [],\n\t\"sshTests\": [{}], // gone\n\t\"tests\": [],\n\t\"SSHTESTS\": null,\n\t\"groups\": {}\n}\n"
	out, err := StripTests(ctx, []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	d := mustParse(t, string(out))
	if len(d.byKey[sectionKey("tests")])+len(d.byKey[sectionKey("sshTests")]) != 0 {
		t.Errorf("tests remain:\n%s", out)
	}
	if !strings.Contains(string(out), "// keep") || !strings.Contains(string(out), `"acls": []`) || !strings.Contains(string(out), `"groups": {}`) {
		t.Errorf("the rest was not kept:\n%s", out)
	}
	if again, err := StripTests(ctx, out); err != nil || !bytes.Equal(again, out) {
		t.Errorf("stripping twice: %v\n%s", err, again)
	}
	// A text with none comes back as it was, as a copy.
	in := []byte(policyWithComments)
	same, err := StripTests(ctx, in)
	if err != nil || !bytes.Equal(same, in) || &same[0] == &in[0] {
		t.Errorf("no tests: %v", err)
	}
	// A name written with an escape and a name with a slash are found.
	out, err = StripTests(ctx, []byte(`{"t\u0065sts": [], "a/b": 1}`))
	if err != nil || strings.Contains(string(out), "sts") || !strings.Contains(string(out), `"a/b"`) {
		t.Errorf("escaped name: %v %s", err, out)
	}
	// The server folds case as Unicode does: a long s is an s.
	out, err = StripTests(ctx, []byte(`{"te\u017fts": [], "SSHTE\u017fTS": [], "a": 1}`))
	if err != nil || string(out) != `{ "a": 1}` {
		t.Errorf("folded names: %v %q", err, out)
	}
	if _, err := AppendTests(ctx, []byte(`{"te\u017fts": []}`), [][]byte{[]byte(`{}`)}, nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("a folded tests section: %v", err)
	}
	if _, err := StripTests(ctx, []byte(`[1]`)); !errors.Is(err, ErrInvalid) {
		t.Errorf("not an object: %v", err)
	}
	if _, err := StripTests(ctx, []byte(`{"tests": `)); !errors.Is(err, ErrInvalid) {
		t.Errorf("not a policy: %v", err)
	}
}

func TestAppendTestsAddsATail(t *testing.T) {
	ctx := context.Background()
	text := []byte(policyWithComments)
	out, err := AppendTests(ctx, text, [][]byte{[]byte(`{"src": "group:a", "accept": ["tag:x:80"]}`), []byte("{ // c\n\"src\": \"group:a\", \"deny\": [\"tag:z:1\"]}")},
		[][]byte{[]byte(`{"src": "group:a", "dst": ["tag:x"], "accept": ["alice"]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(out), "// header\n{\n\t// who\n") || !strings.Contains(string(out), "// trailing") {
		t.Errorf("the original text was not kept:\n%s", out)
	}
	d := mustParse(t, string(out))
	s, err := Summarise(ctx, d)
	if err != nil || s.Tests != 2 || s.SSHTests != 1 {
		t.Fatalf("summary: %+v, %v", s, err)
	}
	r, err := Diff(ctx, mustParse(t, policyWithComments), d, DiffOptions{PageSize: MaxPage})
	if err != nil || r.Counts.Semantic != 3 || r.Counts.TestsReduced != 0 {
		t.Errorf("only tests were added: %+v, %v", r.Counts, err)
	}
	// Nothing to add: the text, copied.
	same, err := AppendTests(ctx, text, nil, nil)
	if err != nil || !bytes.Equal(same, text) {
		t.Errorf("nothing to add: %v", err)
	}
	// tests only, sshTests only.
	if out, err := AppendTests(ctx, []byte(`{}`), [][]byte{[]byte(`{"src":"a"}`)}, nil); err != nil || !strings.Contains(string(out), `"tests"`) || strings.Contains(string(out), "sshTests") {
		t.Errorf("tests only: %v %s", err, out)
	}
	if out, err := AppendTests(ctx, []byte(`{}`), nil, [][]byte{[]byte(`{"src":"a"}`)}); err != nil || !strings.Contains(string(out), `"sshTests"`) {
		t.Errorf("sshTests only: %v %s", err, out)
	}
}

func TestAppendTestsRefusesWhatWouldPutTestsWhereTheyAreIgnored(t *testing.T) {
	ctx := context.Background()
	entry := [][]byte{[]byte(`{"src":"a"}`)}
	for name, text := range map[string]string{
		"a tests section":     `{"tests": []}`,
		"a Tests section":     `{"Tests": [1]}`,
		"an sshTests section": `{"sshtests": []}`,
	} {
		if _, err := AppendTests(ctx, []byte(text), entry, nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "already has") {
			t.Errorf("%s: %v", name, err)
		}
	}
	deep := []byte(strings.Repeat("[", 5000))
	for name, c := range map[string]struct {
		text    string
		entries [][]byte
		code    Code
		says    string
	}{
		"an entry that is not an object": {`{}`, [][]byte{[]byte(`[1]`)}, CodeInvalid, "must be a JSON object"},
		"an entry that does not parse":   {`{}`, [][]byte{[]byte(`{"src":`)}, CodeInvalid, "test tests[0]"},
		"an entry that is too deep":      {`{}`, [][]byte{[]byte(`{}`), deep}, CodeInvalid, "test tests[1]: the text nests deeper"},
		"too many entries":               {`{}`, make([][]byte, MaxAppended+1), CodeTooComplex, "at most"},
		"a text that is not an object":   {`[]`, entry, CodeInvalid, "must be a JSON object"},
	} {
		_, err := AppendTests(ctx, []byte(c.text), c.entries, nil)
		var e *Error
		if !errors.As(err, &e) || e.Code != c.code || !strings.Contains(e.Message, c.says) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := AppendTests(ctx, []byte(`{}`), nil, [][]byte{[]byte(`{"src":"a"}`), deep}); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "sshTests[1]") {
		t.Errorf("ssh entry too deep: %v", err)
	}
}

func TestStandardizeAndFormatAreGuardedWrappers(t *testing.T) {
	ctx := context.Background()
	text := []byte("{\n// c\n\"a\": [1, 2,], /* d */\n}\n")
	std, err := Standardize(ctx, text)
	if err != nil || len(std) != len(text) || bytes.Count(std, []byte("\n")) != bytes.Count(text, []byte("\n")) || strings.Contains(string(std), "//") || strings.Contains(string(std), ",]") {
		t.Errorf("Standardize: %v %q", err, std)
	}
	f, err := Format(ctx, []byte(`{"a":[1,2],"b":{"c":1}}`))
	if err != nil || !strings.Contains(string(f), "\n") {
		t.Errorf("Format: %v %q", err, f)
	}
	if again, _ := Format(ctx, f); !bytes.Equal(again, f) {
		t.Errorf("Format is not idempotent: %q", again)
	}
	for name, fn := range map[string]func(context.Context, []byte) ([]byte, error){"Standardize": Standardize, "Format": Format} {
		if _, err := fn(ctx, []byte(`{"a": `)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s of a broken text: %v", name, err)
		}
		if _, err := fn(ctx, []byte("\xef\xbb\xbf{}")); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s of a text with a byte order mark: %v", name, err)
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := fn(cancelled, []byte(`{}`)); !errors.Is(err, context.Canceled) {
			t.Errorf("%s: a context that is done: %v", name, err)
		}
	}
	// Both accept any JSON value, as the library does: the top-level rule is Parse's.
	if _, err := Standardize(ctx, []byte(`[1,]`)); err != nil {
		t.Errorf("Standardize of an array: %v", err)
	}
}

func init() {
	deep := func(levels int) []byte { return []byte(strings.Repeat("[", levels)) }
	ctx := context.Background()
	depthEntries["ApplyPatch, the text"] = func(levels int) error {
		_, err := ApplyPatch(ctx, deep(levels), []byte(`[]`))
		return err
	}
	depthEntries["ApplyPatch, the patch"] = func(levels int) error {
		_, err := ApplyPatch(ctx, []byte(`{}`), deep(levels))
		return err
	}
	depthEntries["StripTests"] = func(levels int) error {
		_, err := StripTests(ctx, deep(levels))
		return err
	}
	depthEntries["AppendTests, the text"] = func(levels int) error {
		_, err := AppendTests(ctx, deep(levels), [][]byte{[]byte(`{}`)}, nil)
		return err
	}
	depthEntries["AppendTests, a test"] = func(levels int) error {
		_, err := AppendTests(ctx, []byte(`{}`), [][]byte{deep(levels)}, nil)
		return err
	}
	depthEntries["AppendTests, an SSH test"] = func(levels int) error {
		_, err := AppendTests(ctx, []byte(`{}`), nil, [][]byte{deep(levels)})
		return err
	}
	depthEntries["Standardize"] = func(levels int) error {
		_, err := Standardize(ctx, deep(levels))
		return err
	}
	depthEntries["Format"] = func(levels int) error {
		_, err := Format(ctx, deep(levels))
		return err
	}
	// A text nested just past the cap whose levels are objects: the pre-scan, not the
	// shape of the text, is what refuses it.
	depthEntries["StripTests, objects"] = func(levels int) error {
		_, err := StripTests(ctx, []byte(strings.Repeat(`{"a":`, levels/5)))
		return err
	}
}

// deepestPolicies are policies nested exactly as deep as Parse accepts (guard.MaxDepth
// levels of braces and brackets), in the places a policy has structure.
func deepestPolicies() map[string]string {
	n := guard.MaxDepth
	return map[string]string{
		"objects under an unknown name": strings.Repeat(`{"a":`, n) + `1` + strings.Repeat(`}`, n),
		"arrays inside a group":         `{"groups": {"group:a": ` + strings.Repeat("[", n-2) + strings.Repeat("]", n-2) + `}}`,
		"arrays inside a rule":          `{"acls": [{"action": "accept", "src": ` + strings.Repeat("[", n-3) + strings.Repeat("]", n-3) + `, "dst": ["tag:x:80"]}]}`,
		"arrays inside a test":          `{"tests": [{"src": "tag:x", "accept": ` + strings.Repeat("[", n-3) + strings.Repeat("]", n-3) + `}]}`,
	}
}

// Normalise, Diff, Summarise and LocateToken take a *Doc, so Parse is their only text entry
// point and the guard that Parse runs is the only one they need: they get no subprocess
// depth entry of their own. What this test adds is that a Doc as deep as the guard lets
// through (the deepest the engine will ever hold) goes through each of them, so that none
// recurses past what the guard assumed. An overflow of the stack is fatal and cannot be
// recovered, but a panic of any other kind is caught here and named.
func TestTheDeepestDocumentParseAcceptsIsReadByEveryFunctionThatTakesADoc(t *testing.T) {
	ctx := context.Background()
	empty := mustParse(t, `{}`)
	for name, text := range deepestPolicies() {
		if _, err := Parse(ctx, []byte(`{"z":`+text+`}`)); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "nests deeper") {
			t.Fatalf("%s: one level deeper than the deepest is not refused: %v", name, err)
		}
		d, err := Parse(ctx, []byte(text))
		if err != nil {
			t.Fatalf("%s: Parse refuses a document at the limit: %v", name, err)
		}
		calls := map[string]func() error{
			"Normalise":           func() error { _, err := Normalise(ctx, d); return err },
			"Diff against itself": func() error { _, err := Diff(ctx, d, d, DiffOptions{}); return err },
			"Diff against empty":  func() error { _, err := Diff(ctx, d, empty, DiffOptions{}); return err },
			"Diff from empty":     func() error { _, err := Diff(ctx, empty, d, DiffOptions{}); return err },
			"Summarise":           func() error { _, err := Summarise(ctx, d); return err },
			"LocateToken":         func() error { _, _, err := LocateToken(ctx, d, "tag:x"); return err },
		}
		for call, fn := range calls {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s, %s: panic: %v", name, call, r)
					}
				}()
				if err := fn(); err != nil {
					t.Errorf("%s, %s: %v", name, call, err)
				}
			}()
		}
	}
}

func setMaxWork(t *testing.T, n int64) {
	t.Helper()
	old := maxWork
	t.Cleanup(func() { maxWork = old })
	maxWork = n
}

func nodeBound(b []byte) int { return guard.Scan(b, guard.MaxDepth).NodeBound }

// Each operation of a patch can walk the whole document (a test clones and decodes the
// value at its path, an array operation moves every later element, a name is found by a
// scan of its object), so a patch is charged its operations times the values the document
// can hold while it runs.
func TestApplyPatchIsChargedForEveryOperationOnTheWholeDocument(t *testing.T) {
	ctx := context.Background()
	text := []byte(`{"a": 0, "b": [1, 2, 3]}`)
	var ops []string
	for i := 0; i < 20; i++ {
		ops = append(ops, `{"op":"test","path":"/b","value":[1,2,3]}`, `{"op":"replace","path":"/a","value":`+strconv.Itoa(i)+`}`)
	}
	patch := []byte("[" + strings.Join(ops, ",") + "]")
	reading := int64(4 * len(ops)) // checking the patch ticks once for each operation and each of its three members
	cost := reading + int64(len(ops))*int64(nodeBound(text)+nodeBound(patch))
	setMaxWork(t, cost)
	if _, err := ApplyPatch(ctx, text, patch); err != nil {
		t.Errorf("a patch that costs exactly the budget: %v", err)
	}
	setMaxWork(t, cost-1)
	if _, err := ApplyPatch(ctx, text, patch); !errors.Is(err, ErrTooComplex) {
		t.Errorf("a patch one step over the budget: %v", err)
	}
}

// 256 tests on the root of a document of 300,000 values are 77 million steps: past the
// budget, refused before the first operation runs, not after minutes of cloning.
func TestApplyPatchRefusesAHugeDocumentWithManyOperationsBeforeItRunsThem(t *testing.T) {
	ctx := context.Background()
	text := []byte(`{"a": [` + strings.Repeat("1,", 300000) + `1]}`)
	var ops []string
	for i := 0; i < MaxPatchOps; i++ {
		ops = append(ops, `{"op":"test","path":"","value":{}}`)
	}
	_, err := ApplyPatch(ctx, text, []byte("["+strings.Join(ops, ",")+"]"))
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeTooComplex {
		t.Errorf("err = %v, want too_complex", err)
	}
}

func TestStripTestsRefusesMoreThanTheMostItWillRemove(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		n    int
		fail bool
	}{{MaxPatchOps, false}, {MaxPatchOps + 1, true}} {
		text := []byte("{" + strings.Repeat(`"Tests": [],`, c.n) + `"hosts": {}}`)
		out, err := StripTests(ctx, text)
		var e *Error
		switch {
		case c.fail && (!errors.As(err, &e) || e.Code != CodeTooComplex || !strings.Contains(e.Message, "at most")):
			t.Errorf("%d members: err = %v, want too_complex", c.n, err)
		case !c.fail && (err != nil || string(out) != `{"hosts": {}}`):
			t.Errorf("%d members: %v %q", c.n, err, out)
		}
	}
	setMaxWork(t, 5)
	if _, err := StripTests(ctx, []byte(`{"tests": [], "hosts": {}}`)); !errors.Is(err, ErrTooComplex) {
		t.Errorf("a removal is charged to the budget: %v", err)
	}
}

// The tests to add are read, copied into a patch and applied: the total of what is added
// is bounded, not just each entry.
func TestAppendTestsBoundsWhatItAddsInAll(t *testing.T) {
	ctx := context.Background()
	half := []byte(`{"a":"` + strings.Repeat("x", MaxBytes/2+1000) + `"}`)
	_, err := AppendTests(ctx, []byte(`{}`), [][]byte{half, half}, nil)
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeTooComplex || !strings.Contains(e.Message, "together") {
		t.Errorf("bytes: err = %v", err)
	}
	_, err = AppendTests(ctx, []byte(`{}`), [][]byte{half}, [][]byte{half})
	if !errors.As(err, &e) || e.Code != CodeTooComplex || !strings.Contains(e.Message, "together") {
		t.Errorf("bytes across the two lists: err = %v", err)
	}
	wide := []byte(`{"a":[` + strings.Repeat("1,", MaxNodes*3/5) + `1]}`)
	_, err = AppendTests(ctx, []byte(`{}`), [][]byte{wide, wide}, nil)
	if !errors.As(err, &e) || e.Code != CodeTooComplex || !strings.Contains(e.Message, "values together") {
		t.Errorf("values: err = %v", err)
	}
	// Each of the two alone is fine.
	if _, err := AppendTests(ctx, []byte(`{}`), [][]byte{wide}, nil); err != nil {
		t.Errorf("one wide test: %v", err)
	}
	// The members of the top level are read once and charged for it.
	setMaxWork(t, 3)
	if _, err := AppendTests(ctx, []byte(`{"a":1,"b":2,"c":3,"d":4,"e":5}`), [][]byte{[]byte(`{}`)}, nil); !errors.Is(err, ErrTooComplex) {
		t.Errorf("the scan of the top level is charged: %v", err)
	}
}

func TestAppendTestsAddsOneSectionPerListWhateverTheNumberOfTests(t *testing.T) {
	ctx := context.Background()
	text := `{"hosts": {}}`
	entries := make([][]byte, 3000)
	for i := range entries {
		entries[i] = []byte(`{"src": "tag:x", "accept": ["tag:y:` + strconv.Itoa(i%60000+1) + `"]} // n` + strconv.Itoa(i) + "\n")
	}
	out, err := AppendTests(ctx, []byte(text), entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := mustParse(t, string(out))
	if s, err := Summarise(ctx, d); err != nil || s.Tests != len(entries) {
		t.Errorf("tests = %+v, %v", s, err)
	}
	if !strings.HasPrefix(string(out), `{"hosts": {}`) || strings.Count(string(out), `"tests"`) != 1 {
		t.Errorf("not the original plus a tail: %.80s", out)
	}
}

// Format lays every element on a line of its own and indents it by its depth, pads the names
// of a block of members to one width and indents each line of a block comment, so a small
// text can become a huge one. The size is bounded before the library runs.
func TestFormatRefusesATextThatWouldBecomeHuge(t *testing.T) {
	ctx := context.Background()
	// Each is a few hundred kilobytes at most; the library turns it into tens of megabytes.
	indentation := strings.Repeat("[\n", 990) + strings.Repeat("1,\n", 40000) + strings.Repeat("]", 990)
	padding := "{\n\"" + strings.Repeat("n", 100_000) + "\": 1,\n" + strings.Repeat("\"a\": 1,\n", 300) + "}"
	comment := strings.Repeat("{\n\"a\":", 900) + "/*\n" + strings.Repeat("x\n", 30000) + "*/ 1" + strings.Repeat("}", 900)
	for name, text := range map[string]string{"indentation": indentation, "padding": padding, "comment lines": comment} {
		if out, err := hujson.Format([]byte(text)); err != nil || len(out) <= MaxFormatted {
			t.Fatalf("%s is not the bomb it was written to be: %d bytes become %d (%v)", name, len(text), len(out), err)
		}
		_, err := Format(ctx, []byte(text))
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeTooComplex || !strings.Contains(e.Message, "format") {
			t.Errorf("%s (%d bytes): err = %v, want too_complex", name, len(text), err)
		}
	}
	// A text that is large but formats to a reasonable size is formatted.
	if _, err := Format(ctx, []byte("["+strings.Repeat("1,\n", 50000)+"1]")); err != nil {
		t.Errorf("a long flat array: %v", err)
	}
	if _, err := Format(ctx, []byte(strings.Repeat("[", 1000)+strings.Repeat("]", 1000))); err != nil {
		t.Errorf("the deepest empty nest: %v", err)
	}
	setMaxWork(t, 3)
	if _, err := Format(ctx, []byte(`{"a": [1, 2, 3]}`)); !errors.Is(err, ErrTooComplex) {
		t.Errorf("the walk of the tree is charged: %v", err)
	}
}

func genHuJSON(r *rand.Rand, b *strings.Builder, depth int) {
	space := func() {
		switch r.IntN(10) {
		case 0:
			b.WriteString(" ")
		case 1:
			b.WriteString("\n")
		case 2:
			b.WriteString("\n\t\n\n\n")
		case 3:
			b.WriteString(" /* c */ ")
		case 4:
			b.WriteString("\n// line\n")
		case 5:
			b.WriteString("/*\n * a\n * b\n */\n")
		case 6:
			b.WriteString("\r\n")
		}
	}
	if depth >= 7 || r.IntN(3) == 0 {
		switch r.IntN(5) {
		case 0:
			b.WriteString(strconv.Itoa(r.IntN(1000)))
		case 1:
			b.WriteString(`"` + strings.Repeat("s", r.IntN(40)) + `"`)
		case 2:
			b.WriteString(`"a\/b\u0041"`)
		case 3:
			b.WriteString("null")
		default:
			b.WriteString("true")
		}
		return
	}
	obj := r.IntN(2) == 0
	open, closer := "[", "]"
	if obj {
		open, closer = "{", "}"
	}
	b.WriteString(open)
	n := r.IntN(6)
	for i := 0; i < n; i++ {
		space()
		if obj {
			b.WriteString(`"` + strings.Repeat("k", r.IntN(30)) + strconv.Itoa(i) + `"`)
			if r.IntN(5) == 0 {
				space()
			}
			b.WriteString(":")
			if r.IntN(5) == 0 {
				space()
			}
		}
		genHuJSON(r, b, depth+1)
		space()
		if i < n-1 || r.IntN(3) == 0 {
			b.WriteString(",")
		}
	}
	space()
	b.WriteString(closer)
}

// The bound is what makes Format safe to run, so it is held to the property that decides
// it: it is never below the size of what the library produces.
func TestFormatBoundIsNeverBelowTheOutput(t *testing.T) {
	ctx := context.Background()
	r := rand.New(rand.NewPCG(3, 5))
	texts := []string{
		policyWithComments,
		strings.Repeat("[\n", 200) + strings.Repeat("1,\n", 2000) + strings.Repeat("]", 200),
		strings.Repeat("[", 200) + strings.Repeat("1,\n", 2000) + strings.Repeat("]", 200),
		strings.Repeat("{\n\"a\":\n", 150) + "1" + strings.Repeat("}", 150),
		strings.Repeat("{\n\"a\":\n", 200) + "[\n" + strings.Repeat("1,\n", 3000) + "]" + strings.Repeat("}", 200),
		// Where a line break between each name and its value doubles the depth, and each element
		// is mostly lines of comment: the lines are what the bound has least slack in.
		strings.Repeat("{\n\"a\":\n", 200) + "[\n" + strings.Repeat("/*\nx\nx\nx\nx\nx\nx\nx\nx\n*/ 1,\n", 300) + "]" + strings.Repeat("}", 200),
		"{\n\"" + strings.Repeat("n", 3000) + "\": 1,\n" + strings.Repeat("\"a\": 1,\n", 100) + "}",
		strings.Repeat("{\n\"a\":", 150) + "/*\n" + strings.Repeat("x\n", 500) + "*/ 1" + strings.Repeat("}", 150),
		strings.Repeat(`{"a":`, 150) + "/*\n" + strings.Repeat("x\n", 500) + "*/ 1" + strings.Repeat("}", 150),
		string(fixture(t, "basic.hujson")), string(fixture(t, "crlf.hujson")), string(fixture(t, "duplicates.hujson")),
	}
	for range 600 {
		var b strings.Builder
		genHuJSON(r, &b, 0)
		texts = append(texts, b.String())
	}
	for i, text := range texts {
		v, err := hujson.Parse([]byte(text))
		if err != nil {
			t.Fatalf("text %d does not parse: %v\n%s", i, err, text)
		}
		out, err := hujson.Format([]byte(text))
		if err != nil {
			t.Fatalf("text %d: %v", i, err)
		}
		bound, err := formatBound(newMeter(ctx), &v, len(text))
		if err != nil {
			t.Fatalf("text %d: %v", i, err)
		}
		if bound < len(out) {
			t.Fatalf("text %d: the bound is %d and the output %d bytes:\n%s", i, bound, len(out), text)
		}
	}
}

func TestTransformsStopForADoneContextAndAnExhaustedBudget(t *testing.T) {
	ctx := context.Background()
	done, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := StripTests(done, []byte(`{}`)); !errors.Is(err, context.Canceled) {
		t.Errorf("StripTests: %v", err)
	}
	if _, err := AppendTests(done, []byte(`{}`), nil, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("AppendTests: %v", err)
	}
	// The budget is spent by the reading of the patch, of the top level and of each test.
	ops := []byte(`[{"op":"add","path":"/a","value":1},{"op":"add","path":"/b","value":1}]`)
	setMaxWork(t, 3)
	if _, err := ApplyPatch(ctx, []byte(`{}`), ops); !errors.Is(err, ErrTooComplex) {
		t.Errorf("ApplyPatch: the reading of the patch is charged: %v", err)
	}
	if _, err := StripTests(ctx, []byte(`{"a":1,"b":2,"c":3,"d":4}`)); !errors.Is(err, ErrTooComplex) {
		t.Errorf("StripTests: the scan of the top level is charged: %v", err)
	}
	setMaxWork(t, 20)
	entry := []byte(`{"src": "a", "accept": ["b:1"], "deny": ["c:2"], "x": [1, 2, 3, 4, 5, 6, 7, 8, 9]}`)
	if _, err := AppendTests(ctx, []byte(`{}`), [][]byte{entry}, nil); !errors.Is(err, ErrTooComplex) {
		t.Errorf("AppendTests: the reading of a test is charged: %v", err)
	}
	// Text that is wrong comes back wrong from each, with the guard's message.
	for name, fn := range map[string]func() error{
		"StripTests":  func() error { _, err := StripTests(ctx, []byte("\xef\xbb\xbf{}")); return err },
		"AppendTests": func() error { _, err := AppendTests(ctx, []byte("\xef\xbb\xbf{}"), nil, nil); return err },
	} {
		if err := fn(); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "byte order mark") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A member name too long to be tests or sshTests is not decoded, and is not one.
func TestStripTestsLeavesALongNameAlone(t *testing.T) {
	long := strings.Repeat("t", 100)
	out, err := StripTests(context.Background(), []byte(`{"`+long+`": 1, "tests": []}`))
	if err != nil || string(out) != `{"`+long+`": 1}` {
		t.Errorf("%v %q", err, out)
	}
}
