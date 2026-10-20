package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/safefile"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// Flags are derived from a tool's input type, so the CLI accepts exactly the
// parameters MCP does. Only flags the user set reach the tool: defaults are the
// tool's own.

type strValue struct {
	set bool
	v   string
}

func (s *strValue) String() string     { return s.v }
func (s *strValue) Set(v string) error { s.v, s.set = v, true; return nil }

type intValue struct {
	set bool
	v   int
}

func (i *intValue) String() string { return strconv.Itoa(i.v) }
func (i *intValue) Set(v string) error {
	n, err := strconv.Atoi(v)
	if err != nil {
		return fmt.Errorf("%q is not an integer", v)
	}
	i.v, i.set = n, true
	return nil
}

type boolValue struct {
	set bool
	v   bool
}

func (b *boolValue) String() string   { return strconv.FormatBool(b.v) }
func (b *boolValue) IsBoolFlag() bool { return true }
func (b *boolValue) Set(v string) error {
	x, err := strconv.ParseBool(v)
	if err != nil {
		return fmt.Errorf("%q is not true or false", v)
	}
	b.v, b.set = x, true
	return nil
}

// listValue is a repeatable flag: --tags tag:a --tags tag:b.
type listValue struct{ v []string }

func (l *listValue) String() string     { return strings.Join(l.v, ",") }
func (l *listValue) Set(v string) error { l.v = append(l.v, v); return nil }

type param struct {
	json     string
	flag     string
	required bool
	value    flag.Value
}

// binding holds the parameters of one tool command.
type binding struct {
	params     []param
	positional string // JSON name filled by the single positional argument, if any
	files      []fileParam
	switches   []switchParam
}

// fileParam is a string field filled from a file, or from standard input, named
// by a flag. The tool sees the text; the command line never carries it.
type fileParam struct {
	field       int // index of the field in the input struct
	flag        string
	val         *strValue
	stdin, live bool
	group       string
}

// switchParam is a bool field set by a flag that exists on the command line only.
type switchParam struct {
	field int
	flag  string
	val   *boolValue
}

// cliTag is a parsed `cli` struct tag. A tool's input type uses it on fields the
// command line fills differently from MCP:
//
//	cli:"file:NAME[,stdin][,live][,group=G]"  a string field read from the file NAME names;
//	                                          stdin allows -, live makes the word live mean
//	                                          "no file", and at most one flag of a group may be set
//	cli:"bool:NAME"                           a bool field set by --NAME (use json:"-" for a
//	                                          field MCP must not have)
//	cli:"-"                                   no flag for this field
//
// A field with a cli tag gets no flag from its JSON name, so a policy's text is
// never an argument.
type cliTag struct {
	kind        string // "file", "bool" or "-"
	flag        string
	stdin, live bool
	group       string
}

var flagNameRE = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

func parseCLITag(tag string) (cliTag, error) {
	if tag == "" || tag == "-" {
		return cliTag{kind: tag}, nil
	}
	kind, rest, _ := strings.Cut(tag, ":")
	parts := strings.Split(rest, ",")
	t := cliTag{kind: kind, flag: parts[0]}
	if (kind != "file" && kind != "bool") || !flagNameRE.MatchString(t.flag) {
		return cliTag{}, fmt.Errorf("cli tag %q must be file:NAME, bool:NAME or -", tag)
	}
	for _, o := range parts[1:] {
		switch {
		case kind == "file" && o == "stdin":
			t.stdin = true
		case kind == "file" && o == "live":
			t.live = true
		case kind == "file" && strings.HasPrefix(o, "group=") && len(o) > len("group="):
			t.group = strings.TrimPrefix(o, "group=")
		default:
			return cliTag{}, fmt.Errorf("cli tag %q: unknown option %q", tag, o)
		}
	}
	return t, nil
}

// kebab turns a JSON name into a flag name: nameContains -> name-contains.
func kebab(s string) string {
	var b strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) && i > 0 {
			b.WriteByte('-')
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// bind registers one flag per field of the input struct t.
func bind(fs *flag.FlagSet, t reflect.Type, describe func(jsonName string) string) (*binding, error) {
	b := &binding{}
	var requiredStrings []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := strings.Split(f.Tag.Get("json"), ",")
		name := tag[0]
		ct, err := parseCLITag(f.Tag.Get("cli"))
		if err != nil {
			return nil, fmt.Errorf("input field %s: %w", f.Name, err)
		}
		if ct.kind != "" {
			if err := b.addCLI(fs, i, f, ct, name, describe); err != nil {
				return nil, fmt.Errorf("input field %s: %w", f.Name, err)
			}
			continue
		}
		if name == "" || name == "-" {
			continue
		}
		p := param{json: name, flag: kebab(name), required: !strings.Contains(f.Tag.Get("json"), "omitempty")}
		ft := f.Type
		switch {
		case ft.Kind() == reflect.String:
			p.value = &strValue{}
			if p.required {
				requiredStrings = append(requiredStrings, name)
			}
		case ft.Kind() == reflect.Int:
			p.value = &intValue{}
		case ft.Kind() == reflect.Bool, ft.Kind() == reflect.Pointer && ft.Elem().Kind() == reflect.Bool:
			p.value = &boolValue{}
		case ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.String:
			p.value = &listValue{}
		default:
			return nil, fmt.Errorf("input field %s has unsupported type %s", name, ft)
		}
		if fs.Lookup(p.flag) != nil {
			return nil, fmt.Errorf("input field %s: flag --%s is already taken", f.Name, p.flag)
		}
		fs.Var(p.value, p.flag, describe(name))
		b.params = append(b.params, p)
	}
	if len(requiredStrings) == 1 {
		b.positional = requiredStrings[0]
	}
	return b, nil
}

// addCLI registers the flag a cli tag asks for. The field's JSON name, if it has
// one, gets no flag of its own.
func (b *binding) addCLI(fs *flag.FlagSet, i int, f reflect.StructField, ct cliTag, jsonName string, describe func(string) string) error {
	if ct.kind == "-" {
		return nil
	}
	if fs.Lookup(ct.flag) != nil {
		return fmt.Errorf("flag --%s is already taken", ct.flag)
	}
	desc := f.Tag.Get("jsonschema")
	if jsonName != "" && jsonName != "-" {
		if d := describe(jsonName); d != "" {
			desc = d
		}
	}
	switch ct.kind {
	case "file":
		if f.Type.Kind() != reflect.String {
			return fmt.Errorf("a file field must be a string, not %s", f.Type)
		}
		if ct.stdin {
			desc += " (read from FILE, or from standard input with -)"
		} else {
			desc += " (read from FILE)"
		}
		fp := fileParam{field: i, flag: ct.flag, val: &strValue{}, stdin: ct.stdin, live: ct.live, group: ct.group}
		fs.Var(fp.val, ct.flag, desc)
		b.files = append(b.files, fp)
	case "bool":
		if f.Type.Kind() != reflect.Bool {
			return fmt.Errorf("a bool field must be a bool, not %s", f.Type)
		}
		sp := switchParam{field: i, flag: ct.flag, val: &boolValue{}}
		fs.Var(sp.val, ct.flag, desc)
		b.switches = append(b.switches, sp)
	}
	return nil
}

// given reports which of the binder's flags the command line set, for the
// registry's decision whether the call needs the credential. A file flag whose
// value is the word live (where the tag allows it) counts as not set.
func (b *binding) given() registry.Given {
	g := registry.Given{}
	for _, f := range b.files {
		if f.val.set && !(f.live && f.val.v == "live") {
			g[f.flag] = true
		}
	}
	for _, s := range b.switches {
		if s.val.set && s.val.v {
			g[s.flag] = true
		}
	}
	return g
}

func usageErr(format string, args ...any) error {
	return tkerr.New(tkerr.Usage, fmt.Sprintf(format, args...), "")
}

// check refuses, before the configuration loads and before the credential wrapper
// starts, what can be refused without reading: two flags of a group, standard
// input named twice, and a file that is not a regular file of an acceptable size.
// It reads nothing: standard input is for the process that holds the credential.
func (b *binding) check() error {
	groups := map[string]string{} // group -> the flag that took it
	stdinBy := ""
	for _, f := range b.files {
		if !f.val.set || f.live && f.val.v == "live" {
			continue
		}
		if f.val.v == "" {
			return usageErr("--%s needs a file name", f.flag)
		}
		if f.group != "" {
			if prev, taken := groups[f.group]; taken {
				return usageErr("--%s and --%s both give the %s: give one", prev, f.flag, f.group)
			}
			groups[f.group] = f.flag
		}
		if f.val.v == "-" {
			if !f.stdin {
				return usageErr("--%s takes a file name, not standard input", f.flag)
			}
			if stdinBy != "" {
				return usageErr("standard input can be read once: --%s and --%s both name it", stdinBy, f.flag)
			}
			stdinBy = f.flag
		}
	}
	for _, f := range b.files {
		if f.val.set && f.val.v != "" && f.val.v != "-" && !(f.live && f.val.v == "live") {
			if err := safefile.Check(f.val.v, safefile.Options{Code: tkerr.Usage}); err != nil {
				return err
			}
		}
	}
	return nil
}

// setSwitches sets the bool fields their flags name. in is the input struct.
func (b *binding) setSwitches(in reflect.Value) {
	for _, s := range b.switches {
		if s.val.set {
			in.Field(s.field).SetBool(s.val.v)
		}
	}
}

// load reads each file, and standard input if a flag names it, into its field of
// the input struct in, and returns how each flag's source is called in output
// (the path as typed, or <stdin>). It runs in the process that holds the credential.
func (b *binding) load(in reflect.Value, stdin io.Reader) (map[string]string, error) {
	names := map[string]string{}
	o := safefile.Options{Code: tkerr.Usage}
	for _, f := range b.files {
		if !f.val.set || f.live && f.val.v == "live" {
			continue
		}
		var data []byte
		var err error
		if f.val.v == "-" {
			data, err = safefile.ReadAll(stdin, "standard input", o)
			names[f.flag] = "<stdin>"
		} else {
			data, err = safefile.Read(f.val.v, o)
			names[f.flag] = f.val.v
		}
		if err != nil {
			return nil, err
		}
		in.Field(f.field).SetString(string(data))
	}
	return names, nil
}

// arguments builds the JSON arguments from the flags that were set and the
// positional argument.
func (b *binding) arguments(rest []string) (json.RawMessage, error) {
	args := map[string]any{}
	for _, p := range b.params {
		switch v := p.value.(type) {
		case *strValue:
			if v.set {
				args[p.json] = v.v
			}
		case *intValue:
			if v.set {
				args[p.json] = v.v
			}
		case *boolValue:
			if v.set {
				args[p.json] = v.v
			}
		case *listValue:
			if len(v.v) > 0 {
				args[p.json] = v.v
			}
		}
	}
	switch {
	case len(rest) > 1:
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(rest[1:], " "))
	case len(rest) == 1 && b.positional == "":
		return nil, fmt.Errorf("unexpected argument %q", rest[0])
	case len(rest) == 1:
		if _, dup := args[b.positional]; dup {
			return nil, fmt.Errorf("%s given both as a flag and as an argument", b.positional)
		}
		args[b.positional] = rest[0]
	}
	for _, p := range b.params {
		if _, ok := args[p.json]; p.required && !ok {
			return nil, fmt.Errorf("--%s is required", p.flag)
		}
	}
	return json.Marshal(args)
}

// parseInterspersed parses flags that may follow the positional argument, as in
// `tailkeeper devices get web-1 --json`. A "--" that ends the flags makes everything
// after it positional; a "--" that a flag takes as its value does not.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	args, tail := splitAtTerminator(fs, args)
	var positional []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
	return append(positional, tail...), nil
}

// splitAtTerminator cuts args at the first "--" that stands on its own: not the
// value of a flag (the argument after a flag that takes one, or the text after an
// equals sign). The terminator is dropped.
func splitAtTerminator(fs *flag.FlagSet, args []string) (flags, tail []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return args[:i], args[i+1:]
		}
		if len(a) < 2 || a[0] != '-' || strings.Contains(a, "=") {
			continue
		}
		name := strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-")
		if f := fs.Lookup(name); f != nil {
			if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); !ok || !bf.IsBoolFlag() {
				i++ // the next argument is this flag's value, whatever it is
			}
		}
	}
	return args, nil
}
