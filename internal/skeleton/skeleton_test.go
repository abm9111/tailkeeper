package skeleton

import (
	"encoding/json"
	"math/rand/v2"
	"sort"
	"strings"
	"testing"
	"unicode"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
)

// plant is a value a probe must never print, and the fragments of it that would show it.
type plant struct {
	name, value string
	fragments   []string
}

// planted returns an email address, a public and a tailnet address, a tailnet-ID shape,
// a name under ts.net, a key prefix, an IPv6 address and a group name. The key prefix is
// assembled here so that no scanner sees it in the source.
func planted() []plant {
	return []plant{
		{"email address", "amy@example.com", []string{"amy"}},
		{"public address", "203.0.113.9", []string{"203", "113"}},
		{"100.x address", "100.101.102.103", []string{"100", "101", "102", "103"}},
		{"tailnet ID", "T9876ABCDE", []string{"T9876", "ABCDE"}},
		{"ts.net name", "host1.tail1234.ts.net", []string{"host1", "tail1234", "ts.net"}},
		{"key prefix", "tskey" + "-api-" + "kABC123CNTRL", []string{"tskey", "kABC123", "CNTRL"}},
		{"IPv6 address", "fd7a:115c:a1e0::1", []string{"fd7a", "115c", "a1e0"}},
		{"group name", "group:secret-team@example.com", []string{"group", "secret", "team"}},
	}
}

func TestTemplateKeepsTheGrammarAndNothingElse(t *testing.T) {
	for in, want := range map[string]string{
		`address "tag:prod:22": want: Accept, got: Drop`:                    `address "<s>:<s>:<n>": want: Accept, got: Drop`,
		`address "tag:qux:22" (protocol "tcp"): want: Drop, got: Accept`:    `address "<s>:<s>:<n>" (protocol "<s>"): want: Drop, got: Accept`,
		`[acl test error]: address "192.0.2.1:22": want: Accept, got: Drop`: `[acl test error]: address "<n>.<n>.<n>.<n>:<n>": want: Accept, got: Drop`,
		`address "[2001:db8::1]:22": want: Accept, got: Drop`:               `address "[<n>:<s>::<n>]:<n>": want: Accept, got: Drop`,
		`line 719, column 5: invalid literal: invalidtext`:                  `line <n>, column <n>: <s> <s>: <s>`,
		`json: unknown field "nodeAttr"`:                                    `json: unknown field "<s>"`,
		`test(s) failed`:                                                    `test(s) failed`,
		`warning(s) found`:                                                  `warning(s) found`,
		`tag not found: "tag:nonexistent"`:                                  `tag not found: "<s>:<s>"`,
		`user or host is invalid: tag not found`:                            `user or host is invalid: tag not found`,
		`[ssh test error]: src "tag:p" at "100.64.0.1", dst "tag:p" at "100.64.0.2", ssh user "root": want: "accept" got: "deny"`: `[ssh test error]: src "<s>:<s>" at "<n>.<n>.<n>.<n>", dst "<s>:<s>" at "<n>.<n>.<n>.<n>", ssh user "<s>": want: "accept" got: "deny"`,
		"a\n\tb\x1b[2J":      "<s> <s>[<s>",
		"tag not foundation": "<s> <s> <s>",
		"want:Accept":        "want:Accept",
		"Wanted got":         "<s> got",
		"":                   "",
		"\xff\xfe bad":       "<s> <s>",
		"0123 4x 5":          "<n> <s> <n>",
		"<s> <n>":            "<s> <s>",
	} {
		if got := Template(in); got != want {
			t.Errorf("Template(%q) = %q, want %q", in, got, want)
		}
	}
}

// The known positives: every value a tailnet could put in an error text is gone from
// its template, and the grammar around it stays.
func TestTemplateDropsEveryPlantedValue(t *testing.T) {
	for _, p := range planted() {
		in := `address "` + p.value + `" (protocol "tcp"): want: Accept, got: Drop`
		got := Template(in)
		for _, frag := range p.fragments {
			if strings.Contains(got, frag) {
				t.Errorf("%s: %q survives in %q", p.name, frag, got)
			}
		}
		if !strings.HasPrefix(got, `address "`) || !strings.HasSuffix(got, `" (protocol "<s>"): want: Accept, got: Drop`) {
			t.Errorf("%s: the grammar did not survive: %q", p.name, got)
		}
	}
}

// The same values in every place a skeleton reads: a message, a data entry's user, errors
// and warnings, an unknown key, a value in a field no path lists, and the policy text.
func TestOfShowsNoPlantedValue(t *testing.T) {
	var errs, values []string
	obj := map[string]any{}
	for _, p := range planted() {
		errs = append(errs, "address "+`"`+p.value+`"`+": want: Accept, got: Drop")
		values = append(values, p.value)
		obj[p.value] = []string{p.value} // a key and a value that are the planted text
	}
	body, err := json.Marshal(map[string]any{
		"message": "test(s) failed " + strings.Join(values, " "),
		"data":    []map[string]any{{"user": values[0], "errors": errs, "warnings": values, "extra": obj}},
		"acl":     strings.Join(values, "\n"),
		"tailnet": values[1],
		"obj":     obj,
	})
	if err != nil {
		t.Fatal(err)
	}
	opts := DefaultOptions()
	opts.TemplateText = true
	sk := Of(400, body, opts)
	var shown []string
	for _, p := range sk.Paths {
		shown = append(shown, p.Path, p.Type)
	}
	shown = append(shown, sk.Texts...)
	all := strings.Join(shown, "\n")
	for _, p := range planted() {
		for _, frag := range p.fragments {
			if strings.Contains(all, frag) {
				t.Errorf("%s: %q survives in the skeleton:\n%s", p.name, frag, all)
			}
		}
	}
	if !strings.Contains(all, "want: Accept, got: Drop") {
		t.Errorf("the grammar did not survive:\n%s", all)
	}
	// Unknown keys print as <key>; the documented ones keep their names.
	var paths []string
	for _, p := range sk.Paths {
		paths = append(paths, p.Path+":"+p.Type)
	}
	joined := strings.Join(paths, " ")
	for _, want := range []string{"message:string", "data:array", "data[].errors[]:string", "data[].<key>:object", "<key>.<key>[]:string", "$:object"} {
		if !strings.Contains(joined, want) {
			t.Errorf("paths %q lack %s", joined, want)
		}
	}
}

// The output of Template is built from a fixed vocabulary, whatever the input: after the
// placeholders, the phrases and the words are removed, only separators and spaces remain.
func TestTemplateOutputIsClosedOverTheVocabulary(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 11))
	pieces := []string{"want", "got", "Accept", "Drop", "tag", ":", " ", "\n", "\t", "22", "x", "\xc3\xa9", "\x00", "\x1b", "\\", "{", "}", "<", ">", "%", "&", "\xc3\xa9", "\xe4\xb8\x96", "\xff",
		"100.64.0.1", "tskey-api-k", "ts.net", "@", "example.com", "test(s) failed", "[acl test error]", "ssh user", "\xc2\xa0", "\xe2\x80\x8b", "a1", "_"}
	for i := 0; i < 4000; i++ {
		var b strings.Builder
		for n := r.IntN(40); n >= 0; n-- {
			b.WriteString(pieces[r.IntN(len(pieces))])
		}
		out := Template(b.String())
		rest := out
		rest = strings.ReplaceAll(rest, "<cut>", "")
		rest = strings.ReplaceAll(rest, "<s>", "")
		rest = strings.ReplaceAll(rest, "<n>", "")
		for _, p := range phrases {
			rest = strings.ReplaceAll(rest, p, "")
		}
		for w := range words {
			rest = strings.ReplaceAll(rest, w, "")
		}
		for _, c := range rest {
			if c != ' ' && !isSeparator(c) {
				t.Fatalf("Template(%q) = %q holds %q, which is not in the vocabulary", b.String(), out, c)
			}
		}
		for _, c := range out {
			if unicode.IsControl(c) || c >= 0x80 {
				t.Fatalf("Template(%q) = %q holds the character %U", b.String(), out, c)
			}
		}
	}
}

func TestTemplateIsCut(t *testing.T) {
	long := strings.Repeat("word ", 400)
	out := Template(long)
	if !strings.HasSuffix(out, "<cut>") || len(out) > maxTemplate+len("<s> ")+len("<cut>") {
		t.Errorf("a long text gives %d bytes ending %q", len(out), out[max(0, len(out)-12):])
	}
	if got := Template(strings.Repeat("x", 3*maxInput)); got != "<s>" {
		t.Errorf("one huge token gives %q", got)
	}
}

func TestETagForm(t *testing.T) {
	hex64 := strings.Repeat("ab12", 16)
	for in, want := range map[string]string{
		"":                                 "none",
		`"` + hex64 + `"`:                  "quoted-hex64",
		`W/"` + hex64 + `"`:                "weak-quoted-hex64",
		`"` + hex64[:40] + `"`:             "quoted-hex",
		`"` + strings.ToUpper(hex64) + `"`: "quoted-other",
		`"ts-default"`:                     "quoted-ts-default",
		`"e0b2816b418zz"`:                  "quoted-other",
		hex64:                              "unquoted",
		`"`:                                "unquoted",
		`""`:                               "quoted-other",
	} {
		got := ETagForm(in)
		if got != want {
			t.Errorf("ETagForm(%q) = %q, want %q", in, got, want)
		}
		if strings.Contains(got, hex64[:8]) {
			t.Errorf("ETagForm(%q) shows part of the value", in)
		}
	}
}

func TestOfBodyKinds(t *testing.T) {
	o := DefaultOptions()
	for _, c := range []struct {
		name, body, kind string
		paths            []string
		texts            []string
	}{
		{"empty", "", "empty", nil, nil},
		{"white space", " \n\t ", "empty", nil, nil},
		{"an object", apitest.TestsWarned(apitest.Entry{User: "tag:p", Warnings: []string{`host alias "p" unused`}}).Body, "json",
			[]string{"$:object", "data:array", "data[]:object", "data[].user:string", "data[].warnings:array", "data[].warnings[]:string", "message:string"},
			[]string{`<s> <s> "<s>" <s>`, `<s>:<s>`, `warning(s) found`}},
		{"null lists", apitest.DetailsOK("{}", `"e1"`, nil, nil).Body, "json",
			[]string{"$:object", "acl:string", "errors:null", "warnings:null"}, nil},
		{"a root array", `[{"user":"tag:p","errors":["e1"]}]`, "json",
			[]string{"$:array", "[]:object", "[].errors:array", "[].errors[]:string", "[].user:string"}, nil},
		{"mixed types at one path", `{"data":[{"errors":["x"]},{"errors":null}]}`, "json",
			[]string{"$:object", "data:array", "data[]:object", "data[].errors:array", "data[].errors:null", "data[].errors[]:string"}, []string{"<s>"}},
		{"a number, a boolean", `{"id":1,"type":true}`, "json", []string{"$:object", "id:number", "type:boolean"}, nil},
		{"HuJSON text", "// c\n{\"acls\": []}\n", "text", nil, nil},
		{"two documents", `{} {}`, "text", nil, nil},
		{"a bare string", `"ok"`, "json", []string{"$:string"}, nil},
	} {
		sk := Of(200, []byte(c.body), o)
		if sk.Body != c.kind || sk.Status != 200 {
			t.Errorf("%s: kind %q status %d", c.name, sk.Body, sk.Status)
		}
		var paths []string
		for _, p := range sk.Paths {
			paths = append(paths, p.Path+":"+p.Type)
		}
		if strings.Join(paths, "|") != strings.Join(c.paths, "|") {
			t.Errorf("%s: paths %v, want %v", c.name, paths, c.paths)
		}
		if strings.Join(sk.Texts, "|") != strings.Join(c.texts, "|") {
			t.Errorf("%s: texts %q, want %q", c.name, sk.Texts, c.texts)
		}
	}
	o.TemplateText = true
	if sk := Of(500, []byte("upstream connect error for 203.0.113.9"), o); sk.Body != "text" || len(sk.Texts) != 1 || strings.Contains(sk.Texts[0], "203") {
		t.Errorf("a text body: %+v", sk)
	}
}

// A body that is not JSON is templated only when the API refused the request. A policy
// read that succeeded is HuJSON, and its comments, strings and grammar words are the tailnet's.
func TestOfTemplatesATextBodyOnlyForAnErrorStatus(t *testing.T) {
	o := DefaultOptions()
	o.TemplateText = true
	policy := "// Tailnet policy for the accounting team: do not touch\n{\n\t\"acls\": [{\"action\": \"accept\", \"src\": [\"tag:zzmark\"], \"dst\": [\"*:*\"]}],\n\t// want: Drop, got: Accept\n}\n"
	for _, status := range []int{200, 201, 204, 301, 304, 399} {
		sk := Of(status, []byte(policy), o)
		if sk.Body != "text" || len(sk.Texts) != 0 {
			t.Errorf("status %d: body %q, texts %q; want a text body with no texts", status, sk.Body, sk.Texts)
		}
	}
	for _, status := range []int{400, 404, 429, 500, 502} {
		sk := Of(status, []byte("upstream connect error for 203.0.113.9: want: Drop, got: Accept"), o)
		if sk.Body != "text" || len(sk.Texts) != 1 || sk.Texts[0] != "<s> <s> <s> <s> <n>.<n>.<n>.<n>: want: Drop, got: Accept" {
			t.Errorf("status %d: body %q, texts %q; want the template of the text", status, sk.Body, sk.Texts)
		}
	}
}

func TestOfCapsWhatOneAnswerContributes(t *testing.T) {
	o := DefaultOptions()
	var deep strings.Builder
	for i := 0; i < maxDepth+10; i++ {
		deep.WriteString(`{"data":`)
	}
	deep.WriteString("1")
	deep.WriteString(strings.Repeat("}", maxDepth+10))
	if sk := Of(200, []byte(deep.String()), o); !sk.Truncated {
		t.Error("a nesting past the cap was not marked truncated")
	}
	arr := make([]string, 0, 100)
	for i := 0; i < 100; i++ {
		arr = append(arr, `"`+strings.Repeat("x", i+1)+`"`)
	}
	// 100 distinct strings of different lengths all template to <s>: one text.
	if sk := Of(200, []byte(`{"errors":[`+strings.Join(arr, ",")+`]}`), o); len(sk.Texts) != 1 || sk.Truncated {
		t.Errorf("texts = %v, truncated %v", sk.Texts, sk.Truncated)
	}
	// 100 distinct templates: the cap.
	var distinct []string
	for i := 0; i < 100; i++ {
		distinct = append(distinct, `"`+strings.Repeat("x:", i+1)+`"`)
	}
	if sk := Of(200, []byte(`{"errors":[`+strings.Join(distinct, ",")+`]}`), o); len(sk.Texts) != maxTexts || !sk.Truncated {
		t.Errorf("%d texts, truncated %v", len(sk.Texts), sk.Truncated)
	}
	// 400 keys that are all unknown still make one path.
	obj := map[string]int{}
	for i := 0; i < 400; i++ {
		obj[strings.Repeat("k", i+1)] = i
	}
	b, _ := json.Marshal(obj)
	if sk := Of(200, b, o); len(sk.Paths) != 2 || sk.Truncated {
		t.Errorf("paths = %v", sk.Paths)
	}
	// More distinct paths than the cap: arrays of arrays of ... give one path per depth, so
	// use many documented keys at many depths.
	var many strings.Builder
	many.WriteString("{")
	keys := strings.Fields("message data user errors warnings acl error logs version tailnet eventTime deferredAt eventGroupID origin action actionDetails actor target old new id type name property isEphemeral loginName displayName tags")
	for i, k := range keys {
		if i > 0 {
			many.WriteString(",")
		}
		many.WriteString(`"` + k + `":{"` + strings.Join(keys, `":{"x":1},"`) + `":{"x":1}}`)
	}
	many.WriteString("}")
	if sk := Of(200, []byte(many.String()), o); len(sk.Paths) != maxPaths || !sk.Truncated {
		t.Errorf("%d paths, cap %d, truncated %v", len(sk.Paths), maxPaths, sk.Truncated)
	}
}

// Past a cap, which entries are kept must not depend on the order Go happens to visit the
// members of an object in: a committed skeleton would change on every run of the probes.
func TestOfKeepsTheSameEntriesPastItsCapsOnEveryRun(t *testing.T) {
	o := DefaultOptions()
	keys := strings.Fields("message data user errors warnings acl error logs version tailnet eventTime deferredAt eventGroupID origin action actionDetails actor target old new id type name property isEphemeral loginName displayName tags")
	var paths strings.Builder
	paths.WriteString("{")
	for i, k := range keys {
		if i > 0 {
			paths.WriteString(",")
		}
		paths.WriteString(`"` + k + `":{"` + strings.Join(keys, `":1,"`) + `":1}`)
	}
	paths.WriteString("}")
	// Two arrays of 60 templates each, no template in both: 120 against a cap of 64.
	var errs, warns []string
	for i := 1; i <= 60; i++ {
		errs = append(errs, `"`+strings.Repeat("x:", i)+`"`)
		warns = append(warns, `"`+strings.Repeat("x,", i)+`"`)
	}
	texts := `{"errors":[` + strings.Join(errs, ",") + `],"warnings":[` + strings.Join(warns, ",") + `],"message":"m:m","error":"e:e:e"}`
	for _, c := range []struct{ name, body string }{{"paths", paths.String()}, {"texts", texts}} {
		first, err := json.Marshal(Of(200, []byte(c.body), o))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(first), `"truncated":true`) {
			t.Fatalf("%s: the document does not pass the cap: %s", c.name, first)
		}
		for i := 0; i < 20; i++ {
			again, err := json.Marshal(Of(200, []byte(c.body), o))
			if err != nil {
				t.Fatal(err)
			}
			if string(again) != string(first) {
				t.Errorf("%s: run %d differs from the first:\n%s\n%s", c.name, i+2, first, again)
				break
			}
		}
	}
}

// The vocabulary is pinned: a word or a phrase added to it shows in this test, so widening
// what a template may print is a deliberate edit that a reviewer reads.
func TestTheVocabularyIsPinned(t *testing.T) {
	var gotWords []string
	for w := range words {
		gotWords = append(gotWords, w)
	}
	sort.Strings(gotWords)
	wantWords := []string{"Accept", "Drop", "accept", "address", "at", "column", "deny", "dst", "got", "line", "protocol", "src", "ssh", "user", "want"}
	if strings.Join(gotWords, "|") != strings.Join(wantWords, "|") {
		t.Errorf("words = %q, pinned %q", gotWords, wantWords)
	}
	gotPhrases := append([]string(nil), phrases...)
	sort.Strings(gotPhrases)
	wantPhrases := []string{"[acl test error]", "[ssh test error]", "json: unknown field", "ssh user", "tag not found", "test(s) failed", "user or host is invalid", "warning(s) found"}
	if strings.Join(gotPhrases, "|") != strings.Join(wantPhrases, "|") {
		t.Errorf("phrases = %q, pinned %q", gotPhrases, wantPhrases)
	}
}
