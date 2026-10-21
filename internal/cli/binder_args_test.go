package cli

import (
	"flag"
	"reflect"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
)

// The first argument is the old side and the second the new: `fixture check OLD NEW` is
// `--against OLD --from NEW`, a file name read as the flag's value would be.
func TestAFileArgumentFillsItsFlag(t *testing.T) {
	oldFile := writeFile(t, "old.hujson", `{"old": 1}`)
	newFile := writeFile(t, "new.hujson", `{"new": 1}`)
	h, _, ran := fixtureHarness(t)
	h.app.Env.APIErr = nil
	if code := h.run("--json", "fixture", "check", oldFile, newFile); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	if out := decodeFixture(t, h.out.String()); out.Against != `{"old": 1}` || out.Policy != `{"new": 1}` || *ran != 1 {
		t.Errorf("out = %+v after %d runs", out, *ran)
	}
	// One argument is the old side; the new one stays a flag's.
	h.out.Reset()
	if code := h.run("--json", "fixture", "check", "--from", newFile, oldFile); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	if out := decodeFixture(t, h.out.String()); out.Against != `{"old": 1}` || out.Policy != `{"new": 1}` {
		t.Errorf("out = %+v", out)
	}
	// The flags may follow the arguments.
	h.out.Reset()
	if code := h.run("--json", "fixture", "check", oldFile, newFile, "--name", "x"); code != 0 || decodeFixture(t, h.out.String()).Name != "x" {
		t.Errorf("flags after the arguments: exit %d, %s", code, h.out)
	}
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"the new side twice":    {[]string{"--from", newFile, oldFile, newFile}, "NEW given both as --from and as an argument"},
		"the old side twice":    {[]string{"--against", oldFile, oldFile}, "OLD given both as --against and as an argument"},
		"a third argument":      {[]string{oldFile, newFile, newFile}, "unexpected argument"},
		"a patch is not a side": {[]string{"--patch", newFile, oldFile, newFile}, "--from and --patch both give the proposal"},
	} {
		h, builds, ran := fixtureHarness(t)
		code := h.run(append([]string{"fixture", "check"}, c.args...)...)
		if code != 2 || !strings.Contains(h.err.String(), c.want) {
			t.Errorf("%s: exit %d, stderr %q; want 2 and %q", name, code, h.err, c.want)
		}
		if h.reexecProvider != nil || *builds != 0 || *ran != 0 {
			t.Errorf("%s: wrapper started %v, Build %d, ran %d; want none", name, h.reexecProvider != nil, *builds, *ran)
		}
	}
}

// Two files, given as arguments, are an offline call like the two flags: the wrapper
// does not start, the credential is not needed, and the tool runs once.
func TestPositionalFilesRunOffline(t *testing.T) {
	a, b := writeFile(t, "a.hujson", "{}"), writeFile(t, "b.hujson", "{}")
	h, builds, ran := fixtureHarness(t)
	if code := h.run("--json", "fixture", "check", a, b); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	if h.reexecProvider != nil || *builds != 1 || *ran != 1 {
		t.Errorf("two arguments: wrapper started %v, Build %d, ran %d; want no wrapper, one Build, one run", h.reexecProvider != nil, *builds, *ran)
	}
	// One argument is one side and the live policy: that needs the credential.
	h, builds, ran = fixtureHarness(t)
	h.run("--json", "fixture", "check", a)
	if h.reexecProvider == nil || *builds != 1 || *ran != 0 {
		t.Errorf("one argument: wrapper started %v, Build %d, ran %d; want the wrapper started", h.reexecProvider != nil, *builds, *ran)
	}
}

func TestUsageNamesThePositionalFiles(t *testing.T) {
	h, _, _ := fixtureHarness(t)
	if code := h.run("fixture", "check", "--help"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.err.String(), "Usage: tailkeeper fixture check [flags] [OLD [NEW]]\n") {
		t.Errorf("the usage line does not name the arguments:\n%s", h.err)
	}
	h.err.Reset()
	// A command with a single positional value and no file arguments keeps its line.
	if code := h.run("gate", "check", "--help"); code != 0 || !strings.Contains(h.err.String(), "Usage: tailkeeper gate check [flags] [status]\n") {
		t.Errorf("a command with one positional value: exit %d:\n%s", code, h.err)
	}
}

// The operator mark is set by the command line on every call and can never be sent by
// an MCP caller: the field is not in the schema, and the decoder refuses the key in
// either case.
func TestOperatorIsSetByTheCommandLineAndNeverByMCP(t *testing.T) {
	h, _, _ := fixtureHarness(t)
	if code := h.run("--json", "fixture", "check", "--offline"); code != 0 || !decodeFixture(t, h.out.String()).Operator {
		t.Errorf("the command line did not mark its call as the operator's: exit %d, %s", code, h.out)
	}
	tool, _ := fixtureRegistry(new(int)).Get("fixture_check")
	if _, ok := tool.InputSchema.Properties["operator"]; ok {
		t.Error("the MCP schema has an operator property")
	}
	for _, body := range []string{`{"operator":true}`, `{"Operator":true}`, `{"OPERATOR":true}`} {
		if _, err := tool.Validate([]byte(body)); err == nil {
			t.Errorf("an MCP call %s was accepted", body)
		}
	}
	p, err := tool.Validate([]byte(`{"name":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if reflect.ValueOf(p.Input()).Elem().FieldByName("Operator").Bool() {
		t.Error("an MCP call arrived marked as the operator's")
	}
}

type docField struct {
	From  string `json:"-" cli:"file:from"`
	Notes string `json:"notes,omitempty"`
}
type shortField struct {
	From  string `json:"-" cli:"file:from"`
	Notes string `json:"notes,omitempty" tk:"short"`
}
type listField struct {
	From  string   `json:"-" cli:"file:from"`
	Names []string `json:"names,omitempty"`
}
type shortList struct {
	From  string   `json:"-" cli:"file:from"`
	Names []string `json:"names,omitempty" tk:"short"`
}
type noFileTool struct {
	Notes string `json:"notes,omitempty"`
}

func hasFileField(t reflect.Type) bool {
	for i := 0; i < t.NumField(); i++ {
		if strings.HasPrefix(t.Field(i).Tag.Get("cli"), "file:") {
			return true
		}
	}
	return false
}

// In a tool that reads files, a text field that no file fills is a name, a token or an
// identifier, and says so (tk:"short"): otherwise a policy could be given as a flag's
// value. The rule is on the field types, so the next tool's author meets it, not a list
// of names.
func TestEveryTextFieldOfAFileToolIsADocumentOrShort(t *testing.T) {
	describe := func(string) string { return "" }
	seen, fileTools := 0, 0
	for which, reg := range map[string]*registry.Registry{"product": newRegistry(), "fixture": fixtureRegistry(new(int))} {
		for _, tool := range reg.All() {
			if _, err := bind(flag.NewFlagSet("t", flag.ContinueOnError), tool.InputType, describe); err != nil {
				t.Errorf("%s tool %s: %v", which, tool.Meta.Name, err)
			}
			seen++
			if hasFileField(tool.InputType) {
				fileTools++
			}
		}
	}
	if seen < 40 || fileTools == 0 {
		t.Errorf("the walk saw %d tools, %d of them reading files: it must see the product tools and the fixture's", seen, fileTools)
	}
	// The rule must be able to fail, on a string and on a list, and must name the field.
	for name, c := range map[string]struct {
		typ     reflect.Type
		wantErr string
	}{
		"an untagged string":  {reflect.TypeFor[docField](), "Notes"},
		"an untagged list":    {reflect.TypeFor[listField](), "Names"},
		"a short string":      {reflect.TypeFor[shortField](), ""},
		"a short list":        {reflect.TypeFor[shortList](), ""},
		"a tool with no file": {reflect.TypeFor[noFileTool](), ""},
	} {
		_, err := bind(flag.NewFlagSet("t", flag.ContinueOnError), c.typ, describe)
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr) || !strings.Contains(err.Error(), `tk:"short"`)):
			t.Errorf("%s: err = %v, want a refusal that names %s and tk:\"short\"", name, err, c.wantErr)
		}
	}
}

type listIn struct {
	Names []string `json:"names,omitempty"`
}
type posIn struct {
	Name string `json:"name"`
}

// A flag takes a name or a number, not a document: a value over 8 KiB is refused with
// a usage error that points at the file flags and does not repeat the value.
func TestAFlagValueThatLooksLikeADocumentIsRefused(t *testing.T) {
	const limit = 8 << 10
	big := strings.Repeat("x", limit+1)
	h, builds, ran := fixtureHarness(t)
	code := h.run("fixture", "check", "--name", big)
	got := h.err.String()
	if code != 2 || !strings.Contains(got, "--name takes a short value, not a document") || !strings.Contains(got, "8193 bytes") ||
		!strings.Contains(got, "--from, --patch, --against or --invariants") || strings.Contains(got, "xxxxxxxx") {
		t.Errorf("exit %d, stderr %q", code, got)
	}
	if h.reexecProvider != nil || *builds != 0 || *ran != 0 {
		t.Errorf("wrapper started %v, Build %d, ran %d; want none", h.reexecProvider != nil, *builds, *ran)
	}
	// Exactly the limit passes.
	h, _, ran = fixtureHarness(t)
	h.app.Env.APIErr = nil
	if code := h.run("--json", "fixture", "check", "--name", strings.Repeat("x", limit)); code != 0 || *ran != 1 {
		t.Errorf("a value of exactly 8 KiB: exit %d, ran %d, stderr %q", code, *ran, h.err)
	}
	// A repeatable flag and a positional value follow the same rule, and a command with
	// no file flag says only what the limit is.
	describe := func(string) string { return "" }
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	b, err := bind(fs, reflect.TypeFor[listIn](), describe)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Parse([]string{"--names", "a", "--names", big}); err != nil {
		t.Fatalf("Parse: %v: the flag package would echo the value", err)
	}
	if _, err := b.arguments(nil); err == nil || !strings.Contains(err.Error(), "--names takes a short value, not a document") || strings.Contains(err.Error(), "xxxxxxxx") ||
		strings.Contains(err.Error(), "--from") {
		t.Errorf("a long list element: %v", err)
	}
	b, err = bind(flag.NewFlagSet("t", flag.ContinueOnError), reflect.TypeFor[posIn](), describe)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.arguments([]string{big}); err == nil || !strings.Contains(err.Error(), "name takes a short value, not a document") {
		t.Errorf("a long positional value: %v", err)
	}
}

// The cap is on every flag and argument of every command, the ones that exist today
// included, not only on the commands that read files: acl test takes its source as an
// argument and its destinations as a repeatable flag, and refuses a long value in either.
func TestAnExistingCommandRefusesAFlagValueOverEightKiB(t *testing.T) {
	big := strings.Repeat("x", 8<<10+1)
	for _, args := range [][]string{
		{"acl", "test", "tag:ci", "--accept", big},
		{"acl", "test", big, "--accept", "tag:prod:22"},
	} {
		h := newHarness(t, nil)
		code := h.run(args...)
		if got := h.err.String(); code != 2 || !strings.Contains(got, "takes a short value, not a document") || !strings.Contains(got, "8193 bytes") || strings.Contains(got, "xxxxxxxx") {
			t.Errorf("%d-byte value: exit %d, stderr %q", len(big), code, got)
		}
	}
	// Exactly the limit is not refused for its size.
	h := newHarness(t, nil)
	h.run("acl", "test", "tag:ci", "--accept", strings.Repeat("x", 8<<10))
	if strings.Contains(h.err.String(), "takes a short value") {
		t.Errorf("a value of exactly 8 KiB was refused for its size: %q", h.err)
	}
}

type dupArg struct {
	A string `json:"-" cli:"file:a,arg=1,as=OLD"`
	B string `json:"-" cli:"file:b,arg=1,as=NEW"`
}
type gapArg struct {
	A string `json:"-" cli:"file:a,arg=2,as=NEW"`
}
type jsonOperator struct {
	Op bool `json:"op" cli:"operator"`
}
type stringOperator struct {
	Op string `json:"-" cli:"operator"`
}
type twoOperators struct {
	A bool `json:"-" cli:"operator"`
	B bool `json:"-" cli:"operator"`
}

func TestBindRefusesABadArgumentOrOperatorTag(t *testing.T) {
	for name, c := range map[string]struct {
		typ  reflect.Type
		want string
	}{
		"two fields for one argument":  {reflect.TypeFor[dupArg](), "argument 1 is taken"},
		"a second without a first":     {reflect.TypeFor[gapArg](), "argument 2 needs argument 1"},
		"an operator MCP can send":     {reflect.TypeFor[jsonOperator](), `an operator field must be json:"-"`},
		"an operator that is a string": {reflect.TypeFor[stringOperator](), "an operator field must be a bool"},
		"two operator fields":          {reflect.TypeFor[twoOperators](), "more than one operator field"},
	} {
		_, err := bind(flag.NewFlagSet("t", flag.ContinueOnError), c.typ, func(string) string { return "" })
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}
