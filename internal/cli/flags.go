package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unicode"
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
		tag := strings.Split(f.Tag.Get("json"), ",")
		name := tag[0]
		if name == "" || name == "-" || !f.IsExported() {
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
		fs.Var(p.value, p.flag, describe(name))
		b.params = append(b.params, p)
	}
	if len(requiredStrings) == 1 {
		b.positional = requiredStrings[0]
	}
	return b, nil
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
// `tailkeeper devices get web-1 --json`. After "--" everything is positional.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if consumed := len(args) - len(rest); consumed > 0 && args[consumed-1] == "--" {
			return append(positional, rest...), nil
		}
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
	return positional, nil
}
