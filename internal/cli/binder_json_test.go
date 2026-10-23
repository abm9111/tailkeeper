package cli

import (
	"encoding/json"
	"flag"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// jsonCanary is text no error may repeat. Every refused value below carries it.
const jsonCanary = "canary-7f3a9c-must-not-be-echoed"

func decodeAttr(t *testing.T, stdout string) attrOut {
	t.Helper()
	var out attrOut
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("stdout is not the tool's JSON: %q (%v)", stdout, err)
	}
	return out
}

func TestParseCLITagKnowsTheJSONKind(t *testing.T) {
	for tag, want := range map[string]cliTag{
		"json:src-posture-attrs": {kind: "json", flag: "src-posture-attrs"},
		"json:ssh":               {kind: "json", flag: "ssh"},
	} {
		got, err := parseCLITag(tag)
		if err != nil || got != want {
			t.Errorf("parseCLITag(%q) = %+v, %v, want %+v", tag, got, err, want)
		}
	}
	for _, tag := range []string{"json", "json:", "json:Bad_Name", "json:-a", "json:a-", "json:x,", "json:x,stdin", "json:x,live",
		"json:x,group=g", "json:x,arg=1,as=A", "json:x,file"} {
		if got, err := parseCLITag(tag); err == nil {
			t.Errorf("parseCLITag(%q) = %+v, want an error", tag, got)
		}
	}
}

// The flag's name and the MCP property's name are separate, and the text reaches the
// arguments with a number's digits kept as written.
func TestAJSONFlagFillsAMapAndAListOfStructs(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	b, err := bind(fs, reflect.TypeFor[attrIn](), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if fs.Lookup("attrs") != nil || fs.Lookup("device-attrs") == nil || fs.Lookup("rules") == nil {
		t.Fatal("flags: want --device-attrs and --rules, and no --attrs")
	}
	args := []string{
		"--device-attrs", `{"os":"macos","n":3,"ok":true,"id":9007199254740993,"nested":{"a":[1,"b"]}}`,
		"--rules", `[{"dst":["tag:a:22"],"accept":["root"]},{"dst":["tag:b:443"]}]`,
	}
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	if g := b.given(); !g["device-attrs"] || !g["rules"] {
		t.Errorf("given = %v, want the JSON flags that were set", g)
	}
	raw, err := b.arguments(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"attrs":{"id":9007199254740993,"n":3,"nested":{"a":[1,"b"]},"ok":true,"os":"macos"},` +
		`"rules":[{"dst":["tag:a:22"],"accept":["root"]},{"dst":["tag:b:443"]}]}`
	if string(raw) != want {
		t.Errorf("arguments = %s\nwant       %s", raw, want)
	}
	// A flag that was not given adds nothing, and the MCP name is the key.
	fs = flag.NewFlagSet("t", flag.ContinueOnError)
	b, err = bind(fs, reflect.TypeFor[attrIn](), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Parse([]string{"--rules", `[{"dst":["tag:a:22"]}]`}); err != nil {
		t.Fatal(err)
	}
	if g := b.given(); g["device-attrs"] || !g["rules"] {
		t.Errorf("given = %v, want only --rules", g)
	}
	if raw, err = b.arguments(nil); err != nil || string(raw) != `{"rules":[{"dst":["tag:a:22"]}]}` {
		t.Errorf("only --rules: %s, %v", raw, err)
	}
}

// The same through the command: the tool receives a map whose values are a string, a
// number and a bool, and a list of structs. The number is a float64, which is what a
// JSON number is when it arrives through MCP as well.
func TestAJSONFlagReachesTheToolAsTypedValues(t *testing.T) {
	h, builds, ran := fixtureHarness(t)
	h.app.Env.APIErr = nil
	code := h.run("--json", "attr", "check", "--device-attrs", `{"os":"macos","n":3,"ok":true}`, "--rules", `[{"dst":["tag:a:22"],"accept":["root"]}]`)
	if code != 0 || *ran != 1 || *builds != 1 {
		t.Fatalf("exit %d, ran %d, Build %d, stderr %q", code, *ran, *builds, h.err)
	}
	out := decodeAttr(t, h.out.String())
	if out.Kinds != "n=float64,ok=bool,os=string" ||
		out.Echo != `{"attrs":{"n":3,"ok":true,"os":"macos"},"rules":[{"dst":["tag:a:22"],"accept":["root"]}]}` {
		t.Errorf("kinds %q, echo %q", out.Kinds, out.Echo)
	}
	h, _, ran = fixtureHarness(t)
	h.app.Env.APIErr = nil
	if code := h.run("--json", "attr", "check", `--device-attrs={"os":"macos"}`); code != 0 || *ran != 1 || decodeAttr(t, h.out.String()).Kinds != "os=string" {
		t.Errorf("--device-attrs=: exit %d, ran %d, stdout %q, stderr %q", code, *ran, h.out, h.err)
	}
}

// A value the binder cannot read as exactly what the field takes is a usage error that
// names the flag and, where there is one, the byte. It never repeats the value.
func TestAJSONFlagRefusesAnUnknownFieldATrailingValueAndAnOversizedText(t *testing.T) {
	over := `{"k":"` + strings.Repeat("x", maxFlagText) + `"}`
	for name, c := range map[string]struct{ flag, value, want string }{
		"an unknown field":                {"rules", `[{"dst":["tag:a:22"],"` + jsonCanary + `":1}]`, "--rules names a field the flag does not take"},
		"a second value":                  {"device-attrs", `{"os":"macos"} {"` + jsonCanary + `":1}`, "--device-attrs holds more than one JSON value (text after byte 14)"},
		"text after the value":            {"device-attrs", `{"os":"macos"} ` + jsonCanary, "--device-attrs holds more than one JSON value (text after byte 14)"},
		"a syntax error":                  {"device-attrs", `{"os":"` + jsonCanary + `",}`, "--device-attrs is not JSON (syntax error at byte "},
		"a word that is not JSON":         {"device-attrs", jsonCanary, "--device-attrs is not JSON (syntax error at byte "},
		"a value that ends early":         {"device-attrs", `{"os":"` + jsonCanary, "--device-attrs is not JSON (the text ends before the value does)"},
		"a list where a map is taken":     {"device-attrs", `["` + jsonCanary + `"]`, "--device-attrs does not have the shape it takes: the value ending at byte "},
		"a map where a list is taken":     {"rules", `{"dst":["` + jsonCanary + `"]}`, "is not an array"},
		"a string where a list is nested": {"rules", `[{"dst":"` + jsonCanary + `"}]`, "is not an array"},
		"over 8 KiB":                      {"device-attrs", over, "--device-attrs takes a short value, not a document"},
	} {
		for _, asJSON := range []bool{false, true} {
			h, builds, ran := fixtureHarness(t)
			args := []string{"attr", "check", "--" + c.flag, c.value}
			if asJSON {
				args = append([]string{"--json"}, args...)
			}
			code := h.run(args...)
			got := h.err.String() + h.out.String()
			if code != 2 || !strings.Contains(got, c.want) || strings.Contains(got, jsonCanary) || strings.Contains(got, "xxxxxxxx") {
				t.Errorf("%s (json %v): exit %d, output %q; want 2, %q and no echo of the value", name, asJSON, code, got, c.want)
			}
			if asJSON && (!strings.Contains(h.out.String(), `"code": "usage"`) || h.err.Len() != 0) {
				t.Errorf("%s: with --json, stdout %q, stderr %q; want the usage error document", name, h.out, h.err)
			}
			if h.reexecProvider != nil || *builds != 0 || *ran != 0 {
				t.Errorf("%s (json %v): wrapper started %v, Build %d, ran %d; want none", name, asJSON, h.reexecProvider != nil, *builds, *ran)
			}
		}
	}
}

// An empty text must not read as the flag not being given. A JSON flag has no file and
// no standard input, so the empty forms are the empty value and the values that decode
// to nothing. A dash is not a request to read standard input.
func TestAnEmptyJSONFlagIsRefusedLikeAnEmptyFile(t *testing.T) {
	for name, c := range map[string]struct{ flag, value string }{
		"an empty string":        {"device-attrs", ""},
		"blanks":                 {"device-attrs", "  \n\t "},
		"null for a map":         {"device-attrs", "null"},
		"null with blanks":       {"rules", " null\n"},
		"an empty object":        {"device-attrs", "{}"},
		"an empty list":          {"rules", "[]"},
		"an empty list in blank": {"rules", " [ ] "},
	} {
		h, builds, ran := fixtureHarness(t)
		code := h.run("attr", "check", "--"+c.flag, c.value)
		got := h.err.String()
		if code != 2 || !strings.Contains(got, "--"+c.flag+" ") || !strings.Contains(got, "so nothing would be checked") {
			t.Errorf("%s: exit %d, stderr %q; want 2 and a refusal that says nothing would be checked", name, code, got)
		}
		if h.reexecProvider != nil || *builds != 0 || *ran != 0 {
			t.Errorf("%s: wrapper started %v, Build %d, ran %d; want none", name, h.reexecProvider != nil, *builds, *ran)
		}
	}
	h, _, ran := fixtureHarness(t)
	h.app.Env.APIErr = nil
	if code := h.run("--json", "attr", "check", "--device-attrs", `{"os":""}`); code != 0 || *ran != 1 {
		t.Errorf("a map with one empty value: exit %d, ran %d, stderr %q", code, *ran, h.err)
	}
	h, builds, ran := fixtureHarness(t)
	stdin := newCounting(`{"os":"macos"}`)
	h.r.Stdin = stdin
	if code := h.run("attr", "check", "--device-attrs", "-"); code != 2 || !strings.Contains(h.err.String(), "--device-attrs is not JSON") ||
		stdin.reads != 0 || *builds != 0 || *ran != 0 {
		t.Errorf("--device-attrs -: exit %d, stderr %q, stdin reads %d, Build %d, ran %d", code, h.err, stdin.reads, *builds, *ran)
	}
}

// A flag given twice would keep the last text and drop the first.
func TestAJSONFlagGivenTwiceIsRefused(t *testing.T) {
	h, builds, ran := fixtureHarness(t)
	code := h.run("attr", "check", "--device-attrs", `{"a":1}`, "--device-attrs", `{"b":2}`)
	if code != 2 || !strings.Contains(h.err.String(), "--device-attrs is given twice; give the JSON once") || *builds != 0 || *ran != 0 {
		t.Errorf("exit %d, stderr %q, Build %d, ran %d", code, h.err, *builds, *ran)
	}
}

type jsonOnFile struct {
	From  string            `json:"-" cli:"file:from"`
	Notes map[string]string `json:"notes,omitempty" cli:"json:notes"`
}
type jsonListOnFile struct {
	From  string     `json:"-" cli:"file:from"`
	Rules []attrRule `json:"rules,omitempty" cli:"json:rules"`
}
type jsonNoFile struct {
	Notes map[string]string `json:"notes,omitempty" cli:"json:notes"`
}
type jsonPolicyNamed struct {
	Policy map[string]any `json:"policy,omitempty" cli:"json:policy"`
}
type jsonPatchNamed struct {
	Patch []attrRule `json:"patch,omitempty" cli:"json:patch"`
}
type jsonTextNamed struct {
	Text map[string]any `json:"text,omitempty" cli:"json:text"`
}
type jsonAgainstNamed struct {
	Against map[string]any `json:"against,omitempty" cli:"json:against"`
}
type jsonInvariantsNamed struct {
	Invariants []attrRule `json:"invariants,omitempty" cli:"json:invariants"`
}
type jsonProposalNamed struct {
	Proposal map[string]any `json:"proposal,omitempty" cli:"json:proposal"`
}

// A JSON field of a tool that reads files needs no tk:"short": it is not a text field.
// A field named for a policy, a patch or invariants is never a flag, whatever its type.
func TestAJSONFlagOnAFileToolNeedsNoShortTag(t *testing.T) {
	describe := func(string) string { return "" }
	for name, typ := range map[string]reflect.Type{
		"a map in a file tool":         reflect.TypeFor[jsonOnFile](),
		"a list in a file tool":        reflect.TypeFor[jsonListOnFile](),
		"a map in a tool with no file": reflect.TypeFor[jsonNoFile](),
	} {
		if _, err := bind(flag.NewFlagSet("t", flag.ContinueOnError), typ, describe); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAJSONFlagKeepsPolicyTextOutOfFlags(t *testing.T) {
	describe := func(string) string { return "" }
	for name, c := range map[string]struct {
		typ  reflect.Type
		want string
	}{
		"a field named policy":     {reflect.TypeFor[jsonPolicyNamed](), "policy"},
		"a field named patch":      {reflect.TypeFor[jsonPatchNamed](), "patch"},
		"a field named text":       {reflect.TypeFor[jsonTextNamed](), "text"},
		"a field named against":    {reflect.TypeFor[jsonAgainstNamed](), "against"},
		"a field named invariants": {reflect.TypeFor[jsonInvariantsNamed](), "invariants"},
		"a field named proposal":   {reflect.TypeFor[jsonProposalNamed](), "proposal"},
	} {
		_, err := bind(flag.NewFlagSet("t", flag.ContinueOnError), c.typ, describe)
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), `cli:"file:NAME"`) {
			t.Errorf("%s: err = %v, want a refusal that names %s and a file tag", name, err, c.want)
		}
	}
}

type jsonKeyed struct {
	By map[string][]string `json:"by,omitempty" cli:"json:by"`
}

// The decoder's own error for a wrong type spells the path, and for a map the path holds
// the key. The binder's error leaves the key out.
func TestAJSONErrorNeverSpellsAMapKey(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	b, err := bind(fs, reflect.TypeFor[jsonKeyed](), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Parse([]string{"--by", `{"` + jsonCanary + `":"x"}`}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.arguments(nil); err == nil || !strings.Contains(err.Error(), "--by does not have the shape it takes: the value ending at byte ") ||
		!strings.Contains(err.Error(), "is not an array") || strings.Contains(err.Error(), jsonCanary) {
		t.Errorf("arguments: %v; want the shape named and the key not repeated", err)
	}
}

type jsonRequired struct {
	A map[string]any `json:"a" cli:"json:a"`
}
type jsonNameless struct {
	A map[string]any `json:"-" cli:"json:a"`
}
type jsonScalar struct {
	A string `json:"a,omitempty" cli:"json:a"`
}
type jsonBytes struct {
	A []byte `json:"a,omitempty" cli:"json:a"`
}
type jsonStrings struct {
	A []string `json:"a,omitempty" cli:"json:a"`
}
type jsonPointer struct {
	A *attrRule `json:"a,omitempty" cli:"json:a"`
}
type jsonIntKey struct {
	A map[int]string `json:"a,omitempty" cli:"json:a"`
}
type jsonTaken struct {
	A map[string]any `json:"a,omitempty" cli:"json:json"`
}

func TestARequiredJSONFieldIsRefusedAtBindTime(t *testing.T) {
	_, err := bind(flag.NewFlagSet("t", flag.ContinueOnError), reflect.TypeFor[jsonRequired](), func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "a json field must be optional") {
		t.Errorf("err = %v", err)
	}
}

func TestBindRefusesAMisplacedJSONTag(t *testing.T) {
	for name, c := range map[string]struct {
		typ  reflect.Type
		want string
	}{
		"a field MCP lacks":     {reflect.TypeFor[jsonNameless](), "a json field needs a JSON name"},
		"a string":              {reflect.TypeFor[jsonScalar](), "a json field must be a map or a list of structs, not string"},
		"bytes":                 {reflect.TypeFor[jsonBytes](), "a json field must be a map or a list of structs, not []uint8"},
		"a list of strings":     {reflect.TypeFor[jsonStrings](), "a json field must be a map or a list of structs, not []string"},
		"a pointer to a struct": {reflect.TypeFor[jsonPointer](), "a json field must be a map or a list of structs, not *cli.attrRule"},
		"a map with int keys":   {reflect.TypeFor[jsonIntKey](), "must have string keys"},
		"a flag that exists":    {reflect.TypeFor[jsonTaken](), "flag --json is already taken"},
	} {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.Bool("json", false, "")
		_, err := bind(fs, c.typ, func(string) string { return "" })
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}

// MCP is unaffected: the property is the field's own schema, the tag leaves no trace,
// and a call the command line refuses as empty is a call like another.
func TestAnMCPCallIsUnaffected(t *testing.T) {
	tool, ok := fixtureRegistry(new(int)).Get("attr_check")
	if !ok {
		t.Fatal("no attr_check tool")
	}
	names := make([]string, 0, 2)
	for name := range tool.InputSchema.Properties {
		names = append(names, name)
	}
	slices.Sort(names)
	attrs, rules := tool.InputSchema.Properties["attrs"], tool.InputSchema.Properties["rules"]
	if !slices.Equal(names, []string{"attrs", "rules"}) || attrs == nil || rules == nil || attrs.Type != "object" ||
		!slices.Contains(rules.Types, "array") || rules.Items == nil || rules.Items.Type != "object" {
		t.Fatalf("schema properties %v: attrs %+v, rules %+v", names, attrs, rules)
	}
	if attrs.Description != "device attributes, key to value" || rules.Description != "rules echoed back" {
		t.Errorf("descriptions: attrs %q, rules %q", attrs.Description, rules.Description)
	}
	if schema, err := json.Marshal(tool.InputSchema); err != nil || strings.Contains(string(schema), "cli") || strings.Contains(string(schema), "json:") || strings.Contains(string(schema), "device-attrs") {
		t.Errorf("schema %s, %v: a trace of the flag", schema, err)
	}
	for _, body := range []string{`{"attrs":{"a":1}}`, `{"attrs":{},"rules":[]}`, `{"rules":[{"dst":["tag:a:22"]}]}`, `{}`} {
		if _, err := tool.Validate([]byte(body)); err != nil {
			t.Errorf("MCP call %s refused: %v", body, err)
		}
	}
	for _, body := range []string{`{"rules":[{"dst":["tag:a:22"],"extra":1}]}`, `{"attrs":["a"]}`} {
		if _, err := tool.Validate([]byte(body)); err == nil {
			t.Errorf("MCP call %s accepted", body)
		}
	}
}

// The help says what the flag takes: JSON text, and its limit. The flag package prints
// one dash; the placeholder is JSON.
func TestTheHelpNamesTheJSONFlags(t *testing.T) {
	h, _, _ := fixtureHarness(t)
	if code := h.run("attr", "check", "--help"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	flat := strings.Join(strings.Fields(h.err.String()), " ")
	for _, want := range []string{
		"-device-attrs JSON device attributes, key to value (given as JSON text, at most 8 KiB)",
		"-rules JSON rules echoed back (given as JSON text, at most 8 KiB)",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("help lacks %q:\n%s", want, h.err)
		}
	}
}
