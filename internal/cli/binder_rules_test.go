package cli

import (
	"flag"
	"reflect"
	"strings"
	"testing"
)

// A flag that does not read standard input refuses "-" as its file name, before
// the configuration loads, the wrapper starts or anything is read.
func TestAFlagWithoutStdinRefusesTheDash(t *testing.T) {
	h, builds, ran := fixtureHarness(t)
	stdin := newCounting("{}")
	h.r.Stdin = stdin
	code := h.run("fixture", "check", "--invariants", "-")
	if code != 2 || !strings.Contains(h.err.String(), "--invariants takes a file name, not standard input") {
		t.Errorf("exit %d, stderr %q", code, h.err)
	}
	if h.reexecProvider != nil || *builds != 0 || *ran != 0 || stdin.reads != 0 {
		t.Errorf("wrapper started %v, Build %d, ran %d, stdin reads %d; want none", h.reexecProvider != nil, *builds, *ran, stdin.reads)
	}
}

// The help text of a command says where each file flag reads from, and carries
// the description of the field it fills.
func TestFileFlagsAreDescribedInTheirHelp(t *testing.T) {
	h, _, _ := fixtureHarness(t)
	if code := h.run("fixture", "check", "--help"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	help := h.err.String()
	flat := strings.Join(strings.Fields(help), " ")
	for _, want := range []string{
		"-from value the proposed policy text (read from FILE, or from standard input with -)",
		"-invariants value invariants to check the proposal against (read from FILE)",
		"-no-invariants skip the configured invariants",
		"-offline do not call the API",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("help lacks %q:\n%s", want, help)
		}
	}
}

type badBoolField struct {
	Flag string `json:"-" cli:"bool:flag"`
}
type badFileField struct {
	Flag int `json:"-" cli:"file:flag"`
}
type skippedFields struct {
	hidden bool   `cli:"bool:hid"`
	Gone   string `json:"-"`
	Name   string `json:"name,omitempty"`
	Skip   string `cli:"-" json:"skip,omitempty"`
}

// The unexported field is there to be skipped by the binder; this reads it once so
// that the linter sees it used.
var _ = skippedFields{}.hidden

// A cli tag on a field of the wrong kind is refused when the flags are built, and a
// field with no name, an unexported field or a "-" tag gets no flag; none of them
// ends the walk over the fields that follow.
func TestBindRefusesAMisplacedTagAndSkipsFieldsWithoutAFlag(t *testing.T) {
	describe := func(string) string { return "" }
	if _, err := bind(flag.NewFlagSet("x", flag.ContinueOnError), reflect.TypeFor[badBoolField](), describe); err == nil || !strings.Contains(err.Error(), "a bool field must be a bool") {
		t.Errorf("a bool tag on a string: %v", err)
	}
	if _, err := bind(flag.NewFlagSet("x", flag.ContinueOnError), reflect.TypeFor[badFileField](), describe); err == nil || !strings.Contains(err.Error(), "a file field must be a string") {
		t.Errorf("a file tag on an int: %v", err)
	}
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	b, err := bind(fs, reflect.TypeFor[skippedFields](), describe)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	fs.VisitAll(func(f *flag.Flag) { names = append(names, f.Name) })
	if strings.Join(names, ",") != "name" || len(b.params) != 1 || b.params[0].json != "name" {
		t.Errorf("flags = %v, params = %+v, want the one for name", names, b.params)
	}
}

func TestParseCLITag(t *testing.T) {
	for tag, want := range map[string]cliTag{
		"":                               {},
		"-":                              {kind: "-"},
		"bool:offline":                   {kind: "bool", flag: "offline"},
		"file:from":                      {kind: "file", flag: "from"},
		"file:from,stdin":                {kind: "file", flag: "from", stdin: true},
		"file:against,stdin,live":        {kind: "file", flag: "against", stdin: true, live: true},
		"file:from,group=proposal":       {kind: "file", flag: "from", group: "proposal"},
		"file:from,stdin,group=a-b,live": {kind: "file", flag: "from", stdin: true, live: true, group: "a-b"},
	} {
		got, err := parseCLITag(tag)
		if err != nil || got != want {
			t.Errorf("parseCLITag(%q) = %+v, %v, want %+v", tag, got, err, want)
		}
	}
	for _, tag := range []string{"file:", "file:Bad", "file:a_b", "file:-a", "file:a-", "bool:x,stdin", "bool:x,live", "bool:x,group=g",
		"file:x,group=", "file:x,group", "file:x,stdin,stdin2", "file:x,", "other:x", "stdin", "file:x,live=1"} {
		if got, err := parseCLITag(tag); err == nil {
			t.Errorf("parseCLITag(%q) = %+v, want an error", tag, got)
		}
	}
}

// The terminator is the first "--" that stands alone: not a flag's value, whether
// the flag is a string flag (the next argument is its value) or a bool flag (it
// takes none), and not the text after an equals sign.
func TestSplitAtTerminator(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	fs.Bool("json", false, "")
	fs.String("name", "", "")
	fs.String("n", "", "")
	for _, c := range []struct {
		args        string
		flags, tail string
	}{
		{"--json -- x", "--json", "x"},
		{"-json -- x", "-json", "x"},
		{"--name -- x", "--name -- x", ""},
		{"-n -- x", "-n -- x", ""},
		{"--name=-- -- x", "--name=--", "x"},
		{"--name a -- x y", "--name a", "x y"},
		{"- -- x", "-", "x"},
		{"-- --json", "", "--json"},
		{"x --json -- y", "x --json", "y"},
		{"--unknown -- x", "--unknown", "x"},
		{"--json=true -- x", "--json=true", "x"},
		{"x y", "x y", ""},
		{"--name", "--name", ""},
		{"-x -- y", "-x", "y"},
		{"name -- x", "name", "x"},
		{"n -- x", "n", "x"},
		{"json -- x", "json", "x"},
	} {
		flags, tail := splitAtTerminator(fs, strings.Fields(c.args))
		if strings.Join(flags, " ") != c.flags || strings.Join(tail, " ") != c.tail {
			t.Errorf("splitAtTerminator(%q) = %q, %q, want %q, %q", c.args, flags, tail, c.flags, c.tail)
		}
	}
}

// An empty argument is an argument like another: it is not a flag and it does not
// end the flags.
func TestSplitAtTerminatorToleratesAnEmptyArgument(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	fs.String("name", "", "")
	flags, tail := splitAtTerminator(fs, []string{"", "--", "x"})
	if strings.Join(flags, "|") != "" || len(flags) != 1 || strings.Join(tail, "|") != "x" {
		t.Errorf("splitAtTerminator = %q, %q", flags, tail)
	}
}
