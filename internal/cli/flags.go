package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/safefile"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// Flags are derived from a tool's input type, so the CLI accepts exactly the
// parameters MCP does. Only flags the user set reach the tool: defaults are the
// tool's own.

// maxFlagText is the most a flag's value may hold: 8 KiB. A flag takes a name, a
// number or a file name; a document in one would travel in argv, where `ps` shows it.
// A longer value is kept as its size alone and refused by the binder (checkSizes): the
// flag package would put the value into its own error message, and the document would
// be echoed.
const maxFlagText = 8 << 10

type strValue struct {
	set bool
	v   string
	big int // the size of a value over maxFlagText, which is not kept
}

func (s *strValue) String() string { return s.v }
func (s *strValue) Set(v string) error {
	s.set = true
	if len(v) > maxFlagText {
		s.v, s.big = "", len(v)
		return nil
	}
	s.v, s.big = v, 0
	return nil
}

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

// listValue is a repeatable flag: --tags tag:a --tags tag:b. An element over
// maxFlagText is not kept; big is the size of the largest.
type listValue struct {
	v   []string
	big int
}

func (l *listValue) String() string { return strings.Join(l.v, ",") }
func (l *listValue) Set(v string) error {
	if len(v) > maxFlagText {
		l.big = max(l.big, len(v))
		return nil
	}
	l.v = append(l.v, v)
	return nil
}

// jsonFlag is a flag that takes one JSON text: --attrs '{"os":"macos"}'. Like strValue it
// keeps a text over maxFlagText as its size alone, so that neither the flag package nor an
// error repeats it. dup records a flag given more than once: the flag package would otherwise
// keep the last text and drop the first without a word. The name is not jsonValue: that
// function already reads the --json switch.
type jsonFlag struct {
	raw string
	set bool
	dup bool
	big int
}

func (j *jsonFlag) String() string { return j.raw }
func (j *jsonFlag) Set(v string) error {
	j.dup = j.dup || j.set
	j.set = true
	if len(v) > maxFlagText {
		j.raw, j.big = "", len(v)
		return nil
	}
	j.raw, j.big = v, 0
	return nil
}

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
	argFiles   []fileParam // the files that arguments fill, in argument order
	operators  []int       // fields of the input struct that the command line marks true
	jsons      []jsonParam // fields filled from one JSON text each
}

// jsonParam is a map or a list filled from the JSON text of a flag. json is the field's
// JSON name, which stays the MCP property; flag is the command-line name.
type jsonParam struct {
	flag string
	json string
	val  *jsonFlag
	typ  reflect.Type
}

// fileParam is a string field filled from a file, or from standard input, named
// by a flag. The tool sees the text; the command line never carries it.
type fileParam struct {
	field       int // index of the field in the input struct
	flag        string
	val         *strValue
	stdin, live bool
	group       string
	arg         int    // 1 or 2 when the Nth argument fills this field, as if --flag VALUE were typed
	as          string // how that argument is called in the usage line and in errors
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
//	cli:"file:NAME,arg=N,as=LABEL"            the Nth argument (1 or 2) is that flag's value, as if
//	                                          --NAME VALUE were typed; LABEL (OLD, NEW) is how the
//	                                          usage line and the errors call it. arg and as go together
//	cli:"bool:NAME"                           a bool field set by --NAME (use json:"-" for a
//	                                          field MCP must not have)
//	cli:"json:NAME"                           a map or a list of structs, optional (omitempty),
//	                                          given as the JSON text of --NAME (at most 8 KiB,
//	                                          read strictly). The field keeps its JSON name for
//	                                          MCP. It is not a file and it does not read standard
//	                                          input.
//	cli:"operator"                            a bool field (json:"-" only) that every command line
//	                                          sets true and MCP can never set: the text it
//	                                          accompanies is the operator's own
//	cli:"-"                                   no flag for this field
//
// A field with a cli tag gets no flag from its JSON name, so a policy's text is
// never an argument. In a tool with a file field, every other string or list field
// says tk:"short" (a name, a token, an identifier) or bind refuses the tool. A json
// field is not such a text field: what it holds is structured. A field whose JSON
// name is a document (a policy, a patch, invariants) is still filled from a file,
// never from a json flag.
type cliTag struct {
	kind        string // "file", "bool", "json", "operator" or "-"
	flag        string
	stdin, live bool
	group       string
	arg         int
	as          string
}

var flagNameRE = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

// policyTextNames are the JSON names of a document: a policy, a patch or invariants.
// Such a field is filled from a file. A flag, of any kind, must not carry it.
var policyTextNames = []string{"policy", "patch", "against", "invariants", "proposal", "text"}

func isPolicyTextName(name string) bool {
	for _, n := range policyTextNames {
		if name == n {
			return true
		}
	}
	return false
}

// maxArgFiles is how many file arguments a command takes: `acl diff OLD NEW`.
const maxArgFiles = 2

var argLabelRE = regexp.MustCompile(`^[A-Z][A-Z0-9]*$`)

func parseCLITag(tag string) (cliTag, error) {
	if tag == "" || tag == "-" || tag == "operator" {
		return cliTag{kind: tag}, nil
	}
	kind, rest, _ := strings.Cut(tag, ":")
	parts := strings.Split(rest, ",")
	t := cliTag{kind: kind, flag: parts[0]}
	if (kind != "file" && kind != "bool" && kind != "json") || !flagNameRE.MatchString(t.flag) {
		return cliTag{}, fmt.Errorf("cli tag %q must be file:NAME, bool:NAME, json:NAME or -", tag)
	}
	for _, o := range parts[1:] {
		switch {
		case kind == "file" && o == "stdin":
			t.stdin = true
		case kind == "file" && o == "live":
			t.live = true
		case kind == "file" && strings.HasPrefix(o, "group=") && len(o) > len("group="):
			t.group = strings.TrimPrefix(o, "group=")
		case kind == "file" && strings.HasPrefix(o, "arg="):
			n, err := strconv.Atoi(strings.TrimPrefix(o, "arg="))
			if err != nil || n < 1 || n > maxArgFiles {
				return cliTag{}, fmt.Errorf("cli tag %q: arg must be 1 to %d", tag, maxArgFiles)
			}
			t.arg = n
		case kind == "file" && strings.HasPrefix(o, "as="):
			if t.as = strings.TrimPrefix(o, "as="); !argLabelRE.MatchString(t.as) {
				return cliTag{}, fmt.Errorf("cli tag %q: as must be a label in capitals, such as OLD", tag)
			}
		default:
			return cliTag{}, fmt.Errorf("cli tag %q: unknown option %q", tag, o)
		}
	}
	if (t.arg == 0) != (t.as == "") {
		return cliTag{}, fmt.Errorf("cli tag %q: arg=N and as=LABEL go together", tag)
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

// readsFiles reports whether a field of t is filled from a file.
func readsFiles(t reflect.Type) bool {
	for i := 0; i < t.NumField(); i++ {
		if ct, err := parseCLITag(t.Field(i).Tag.Get("cli")); err == nil && ct.kind == "file" {
			return true
		}
	}
	return false
}

// bind registers one flag per field of the input struct t.
func bind(fs *flag.FlagSet, t reflect.Type, describe func(jsonName string) string) (*binding, error) {
	b := &binding{}
	var requiredStrings []string
	filesTool := readsFiles(t)
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
			if err := b.needsShort(filesTool, f); err != nil {
				return nil, err
			}
			p.value = &strValue{}
			if p.required {
				requiredStrings = append(requiredStrings, name)
			}
		case ft.Kind() == reflect.Int:
			p.value = &intValue{}
		case ft.Kind() == reflect.Bool, ft.Kind() == reflect.Pointer && ft.Elem().Kind() == reflect.Bool:
			p.value = &boolValue{}
		case ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.String:
			if err := b.needsShort(filesTool, f); err != nil {
				return nil, err
			}
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
	sort.Slice(b.argFiles, func(x, y int) bool { return b.argFiles[x].arg < b.argFiles[y].arg })
	for n, fp := range b.argFiles {
		if fp.arg != n+1 {
			return nil, fmt.Errorf("argument %d needs argument %d", fp.arg, fp.arg-1)
		}
	}
	return b, nil
}

// needsShort refuses a text field of a tool that reads files unless it says it holds a
// short value: a name, a token or an identifier. A text field with no such word could
// hold a document, and the binder would make it a flag, so the policy would travel in
// argv. The rule is on the field, so the author of the next tool meets it.
func (b *binding) needsShort(filesTool bool, f reflect.StructField) error {
	if filesTool && !sanitize.HasTag(f.Tag, "short") {
		return fmt.Errorf(`input field %s: a text field of a tool that reads files is filled from a file (a cli:"file:NAME" tag) or tagged tk:"short" (a name, a token or an identifier), so that a document cannot become a flag`, f.Name)
	}
	return nil
}

// addCLI registers the flag a cli tag asks for. The field's JSON name, if it has
// one, gets no flag of its own.
func (b *binding) addCLI(fs *flag.FlagSet, i int, f reflect.StructField, ct cliTag, jsonName string, describe func(string) string) error {
	if ct.kind == "-" {
		return nil
	}
	if ct.kind == "operator" {
		switch {
		case f.Type.Kind() != reflect.Bool:
			return fmt.Errorf("an operator field must be a bool, not %s", f.Type)
		case jsonName != "-":
			return fmt.Errorf(`an operator field must be json:"-", so that an MCP caller cannot send it`)
		case len(b.operators) > 0:
			return fmt.Errorf("more than one operator field")
		}
		b.operators = append(b.operators, i)
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
		fp := fileParam{field: i, flag: ct.flag, val: &strValue{}, stdin: ct.stdin, live: ct.live, group: ct.group, arg: ct.arg, as: ct.as}
		if fp.arg > 0 {
			for _, o := range b.argFiles {
				if o.arg == fp.arg {
					return fmt.Errorf("argument %d is taken by --%s", fp.arg, o.flag)
				}
			}
			b.argFiles = append(b.argFiles, fp)
		}
		fs.Var(fp.val, ct.flag, desc)
		b.files = append(b.files, fp)
	case "bool":
		if f.Type.Kind() != reflect.Bool {
			return fmt.Errorf("a bool field must be a bool, not %s", f.Type)
		}
		sp := switchParam{field: i, flag: ct.flag, val: &boolValue{}}
		fs.Var(sp.val, ct.flag, desc)
		b.switches = append(b.switches, sp)
	case "json":
		if err := checkJSONField(f, jsonName); err != nil {
			return err
		}
		jp := jsonParam{flag: ct.flag, json: jsonName, val: &jsonFlag{}, typ: f.Type}
		fs.Var(jp.val, ct.flag, jsonFlagUsage(desc))
		b.jsons = append(b.jsons, jp)
	}
	return nil
}

// checkJSONField refuses a json tag that would put a document in argv, a tag on a
// field the command line cannot leave unset, or a tag on a type that is itself text.
func checkJSONField(f reflect.StructField, jsonName string) error {
	switch {
	case jsonName == "" || jsonName == "-":
		return fmt.Errorf("a json field needs a JSON name: it is an MCP property too")
	case !strings.Contains(f.Tag.Get("json"), "omitempty"):
		return fmt.Errorf("a json field must be optional (omitempty): a flag that was not given must read as not given")
	case isPolicyTextName(jsonName):
		return fmt.Errorf("a json field named %s would carry a document in a flag: a policy, a patch or invariants is filled from a file (a cli:\"file:NAME\" tag)", jsonName)
	}
	t := f.Type
	switch t.Kind() {
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return fmt.Errorf("a json field that is a map must have string keys, not %s", t)
		}
		return nil
	case reflect.Slice:
		if t.Elem().Kind() != reflect.Struct {
			return fmt.Errorf("a json field must be a map or a list of structs, not %s", t)
		}
		return nil
	default:
		return fmt.Errorf("a json field must be a map or a list of structs, not %s", t)
	}
}

// jsonFlagUsage is the help line of a JSON flag. The backquoted JSON is the placeholder
// the flag package prints after the name, so the line shows the flag taking JSON.
func jsonFlagUsage(desc string) string {
	tail := fmt.Sprintf("(given as `JSON` text, at most %d KiB)", maxFlagText>>10)
	if desc == "" {
		return tail
	}
	return desc + " " + tail
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
	for _, jp := range b.jsons {
		if jp.val.set {
			g[jp.flag] = true
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

// setOperator marks the call as the operator's own: the text it carries comes from a
// file or a pipe the person at the command line named, not from an MCP caller.
func (b *binding) setOperator(in reflect.Value) {
	for _, i := range b.operators {
		in.Field(i).SetBool(true)
	}
}

// usageArgs is what follows [flags] in a usage line: the single positional value, then
// the file arguments, nested because the second needs the first: [OLD [NEW]].
func (b *binding) usageArgs() string {
	s := ""
	if b.positional != "" {
		s = " [" + b.positional + "]"
	}
	nested := ""
	for i := len(b.argFiles) - 1; i >= 0; i-- {
		if nested == "" {
			nested = "[" + b.argFiles[i].as + "]"
		} else {
			nested = "[" + b.argFiles[i].as + " " + nested + "]"
		}
	}
	if nested != "" {
		s += " " + nested
	}
	return s
}

// longFlagValue is the refusal of a flag value over the cap: where the value is from
// and how long it was, never the value.
func longFlagValue(flag string, size int) string {
	return fmt.Sprintf("%s takes a short value, not a document (%d bytes; the limit is %d)", flag, size, maxFlagText)
}

// nameArgument says what an argument that nothing takes is, for an error: the argument
// itself when it is short, its length when it is over the flag cap, so that a document
// is not repeated in the message.
func nameArgument(s string) string {
	if len(s) > maxFlagText {
		return fmt.Sprintf("(an argument of %d bytes)", len(s))
	}
	return s
}

// checkSizes refuses a value that is too long to be a flag's: the message says where a
// document goes and never repeats the value.
func (b *binding) checkSizes() error {
	where := ""
	if n := len(b.files); n > 0 {
		names := make([]string, n)
		for i, f := range b.files {
			names[i] = "--" + f.flag
		}
		where = ": give a document in a file with " + strings.Join(names[:max(n-1, 0)], ", ")
		if n > 1 {
			where += " or "
		}
		where += names[n-1]
	}
	long := func(flag string, size int) error {
		return errors.New(longFlagValue(flag, size) + where)
	}
	for _, p := range b.params {
		switch v := p.value.(type) {
		case *strValue:
			if v.big > 0 {
				return long("--"+p.flag, v.big)
			}
		case *listValue:
			if v.big > 0 {
				return long("--"+p.flag, v.big)
			}
		}
	}
	for _, jp := range b.jsons {
		if jp.val.big > 0 {
			return long("--"+jp.flag, jp.val.big)
		}
	}
	for _, f := range b.files {
		if f.val.big > 0 {
			return fmt.Errorf("--%s takes a file name, and %d bytes is too long for one", f.flag, f.val.big)
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
		if len(data) == 0 {
			// The field would stay as it is when the flag is not given, and a tool reads that
			// as "the live policy" or "no invariants": a text that was never checked would read
			// as a pass. Refuse it here, whichever tool the flag belongs to.
			return nil, usageErr("--%s: %s is empty; an empty text is read as no text at all, so nothing was checked: give a file that holds the text", f.flag, names[f.flag])
		}
		in.Field(f.field).SetString(string(data))
	}
	return names, nil
}

// arguments builds the JSON arguments from the flags that were set and the
// positional argument.
func (b *binding) arguments(rest []string) (json.RawMessage, error) {
	if err := b.checkSizes(); err != nil {
		return nil, err
	}
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
	for _, jp := range b.jsons {
		if !jp.val.set {
			continue
		}
		dst := reflect.New(jp.typ).Elem()
		if err := b.decodeJSON(dst, jp); err != nil {
			return nil, err
		}
		args[jp.json] = dst.Interface()
	}
	// The arguments fill, in order: the single positional value, if the tool has one,
	// then the file arguments, each as if its flag had been typed.
	room := len(b.argFiles)
	if b.positional != "" {
		room++
	}
	switch {
	case len(rest) > room && room == 0 && len(rest) == 1:
		if len(rest[0]) > maxFlagText {
			return nil, fmt.Errorf("an unexpected argument of %d bytes", len(rest[0]))
		}
		return nil, fmt.Errorf("unexpected argument %q", rest[0])
	case len(rest) > room:
		extra := make([]string, 0, len(rest)-room)
		for _, a := range rest[room:] {
			extra = append(extra, nameArgument(a))
		}
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(extra, " "))
	}
	if b.positional != "" && len(rest) > 0 {
		if _, dup := args[b.positional]; dup {
			return nil, fmt.Errorf("%s given both as a flag and as an argument", b.positional)
		}
		if len(rest[0]) > maxFlagText {
			return nil, fmt.Errorf("the argument %s takes a short value, not a document (%d bytes; the limit is %d)", b.positional, len(rest[0]), maxFlagText)
		}
		args[b.positional] = rest[0]
		rest = rest[1:]
	}
	for i, v := range rest {
		fp := b.argFiles[i]
		if fp.val.set {
			return nil, fmt.Errorf("%s given both as --%s and as an argument", fp.as, fp.flag)
		}
		_ = fp.val.Set(v) // never fails; a name over the limit is refused below
	}
	if len(rest) > 0 {
		if err := b.checkSizes(); err != nil {
			return nil, err
		}
	}
	for _, p := range b.params {
		if _, ok := args[p.json]; p.required && !ok {
			return nil, fmt.Errorf("--%s is required", p.flag)
		}
	}
	return json.Marshal(args)
}

// decodeJSON reads the flag's text into target, which must be settable and of the
// field's type. It is strict: a field the type does not have, or anything after the
// value, is an error, and so is a text that reads as no value (blank, null, an empty
// object or an empty list). An empty value would leave the field as it is when the
// flag is not given, and a tool takes that for "nothing to check", the same as an
// empty file. An error names the flag and, where there is one, the byte; it never
// repeats the text. Numbers in a map keep the digits as written, so the text handed
// to the tool is the caller's.
func (b *binding) decodeJSON(target reflect.Value, jp jsonParam) error {
	if jp.val.dup {
		return fmt.Errorf("--%s is given twice; give the JSON once", jp.flag)
	}
	if strings.TrimSpace(jp.val.raw) == "" {
		return fmt.Errorf("--%s is empty; an empty value is read as no value at all, so nothing would be checked: give the JSON, or leave the flag out", jp.flag)
	}
	dec := json.NewDecoder(strings.NewReader(jp.val.raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(target.Addr().Interface()); err != nil {
		return fmt.Errorf("--%s %s", jp.flag, jsonProblem(err))
	}
	end := dec.InputOffset()
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("--%s holds more than one JSON value (text after byte %d)", jp.flag, end)
	}
	if jsonValueEmpty(target) {
		return fmt.Errorf("--%s holds no value (null, {} or []); that is read as the flag not being given, so nothing would be checked: give the JSON, or leave the flag out", jp.flag)
	}
	return nil
}

// jsonValueEmpty reports whether a decoded map or list holds nothing. null decodes
// to a nil map or slice, whose length is zero, as do {} and [].
func jsonValueEmpty(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Map, reflect.Slice, reflect.Array:
		return v.Len() == 0
	default:
		return false
	}
}

// jsonProblem says what is wrong with JSON text, in words of its own. The decoder's
// messages quote the text: an unknown field's name, a map key, a number.
func jsonProblem(err error) string {
	var syntax *json.SyntaxError
	var shape *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntax):
		return fmt.Sprintf("is not JSON (syntax error at byte %d)", syntax.Offset)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "is not JSON (the text ends before the value does)"
	case errors.As(err, &shape):
		return fmt.Sprintf("does not have the shape it takes: the value ending at byte %d is not %s", shape.Offset, jsonShape(shape.Type))
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		return "names a field the flag does not take"
	default:
		return "does not fit what the flag takes"
	}
}

// jsonShape is how JSON spells the kind of value a Go type takes.
func jsonShape(t reflect.Type) string {
	if t == nil {
		return "the kind of value it takes"
	}
	switch t.Kind() {
	case reflect.Map, reflect.Struct:
		return "an object"
	case reflect.Slice, reflect.Array:
		return "an array"
	case reflect.String:
		return "a string"
	case reflect.Bool:
		return "a boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return "a number"
	default:
		return "the kind of value it takes"
	}
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
