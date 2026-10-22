package acl

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/tailscale/hujson"
)

// This file is the pure text transforms on a policy: apply a JSON Patch, take the tests
// out, add tests, standardize and format. Each takes text and returns text, keeps the
// comments and layout of what it does not touch, and runs the guard (the encoding rules,
// the size cap, the depth pre-scan and the value count) on every text before the first call
// into the HuJSON library. The library recurses once per level of nesting without a bound,
// so an unguarded call on a million levels ends the process.
//
// The guard bounds the input, not the work or the output, and the library has several ways
// to turn a small text into a large cost: an operation of a patch can walk the whole
// document, Format pads and indents what it lays out, a copy duplicates a subtree. So
// every byte these functions copy is bounded by the caps on what they accept, every loop
// over the text ticks the meter of the call, and what the library is asked to do is
// charged or bounded before it runs (see chargePatch and formatBound).
//
// The tests-mode path of validation and the SSH test path are built from these. The callers
// that wire them (acl_validate, acl_test) are later changes; their depth tests are here
// because the functions are.

// MaxPatchOps is the most operations a patch may hold, and the most tests members
// StripTests removes. Each operation on an array can move every element after it, so the
// cap bounds the time a patch can spend (the meter charges the rest: see chargePatch).
const MaxPatchOps = 256

// MaxAppended is the most tests AppendTests adds in one call, of each kind.
const MaxAppended = 4096

// MaxFormatted is the most bytes Format will produce. It lays every element on a line of its
// own, indents it by its depth, pads the names of a block of members to one width and
// indents each line of a block comment, so the output can be many times the size of the
// input: a million levels of nesting is refused by the guard, but a thousand levels with
// ten thousand elements is a few megabytes of tabs. The size is bounded before the library
// runs, from the tree (see formatBound); a text over it is a too_complex error.
const MaxFormatted = 4 * MaxBytes

// maxTestsNameLit is the longest member name (as written, quotes and escapes included) that
// can be tests or sshTests in any case: eight characters of at most six bytes each, and
// two quotes. A longer name is not decoded.
const maxTestsNameLit = 8*6 + 2

// guardText applies the input rules to a text about to go to a recursive HuJSON function and
// returns the bound on the number of values the guard found in it. what names the text in
// the message ("the patch").
func guardText(what string, text []byte) (int, error) {
	nodes := 0
	e := checkEncoding(text)
	switch {
	case e != nil:
	case len(text) > MaxBytes:
		e = tooComplex("the text is more than the %d bytes tailkeeper reads", MaxBytes)
	default:
		nodes, e = scanShape(text)
	}
	if e == nil {
		return nodes, nil
	}
	e.Message = capMessage(what + ": " + e.Message)
	return 0, e
}

// parseGuarded parses a text that has passed guardText. The text is copied (at most
// MaxBytes, which guardText checked) because the tree aliases it.
func parseGuarded(what string, text []byte) (hujson.Value, *Error) {
	v, err := hujson.Parse(bytes.Clone(text))
	if err != nil {
		e := syntaxError(err)
		e.Message = capMessage(what + ": " + e.Message)
		return v, e
	}
	return v, nil
}

// parseObject is parseGuarded for a text whose top level must be an object.
func parseObject(what string, text []byte) (hujson.Value, *Error) {
	v, e := parseGuarded(what, text)
	if e != nil {
		return v, e
	}
	if _, ok := v.Value.(*hujson.Object); !ok {
		line, col := position(text, v.StartOffset)
		return v, invalid(line, col, "%s: the top level must be a JSON object, not %s", what, kindName(v.Value.Kind()))
	}
	return v, nil
}

// chargePatch charges the meter for a patch before it runs: its operations times the values
// the document can hold while they do. An operation can walk the whole document (a test
// clones and decodes the value at its path, an insert into or removal from an array or an
// object moves every later member, a name is found by a scan of its object), and the library
// does not count any of it, so 256 tests on the root of a large document would be minutes
// of work for a patch of a few kilobytes.
func chargePatch(m *meter, ops, nodes int) error {
	err := m.tick(ops * nodes)
	var e *Error
	if errors.As(err, &e) && e.Code == CodeTooComplex {
		return tooComplex("%d operations on a policy of up to %d values need more work than the limit of %d steps allows; "+
			"send fewer operations or a smaller policy", ops, nodes, maxWork)
	}
	return err
}

// applyPatch applies a patch to a parsed value; why heads the message when it fails.
func applyPatch(v *hujson.Value, patch []byte, why string) error {
	if err := v.Patch(patch); err != nil {
		return invalid(0, 0, "%s: %s", why, strings.TrimPrefix(err.Error(), "hujson: "))
	}
	return nil
}

// packChecked packs a value that was changed in memory and applies the guard to the result,
// which may be deeper or larger than either input. The result is at most the text and the
// patch together, since no operation but copy (which is refused) makes a value twice.
func packChecked(what string, v *hujson.Value) ([]byte, error) {
	if _, ok := v.Value.(*hujson.Object); !ok {
		return nil, invalid(0, 0, "%s: the change replaced the policy with %s, not an object", what, kindName(v.Value.Kind()))
	}
	out := v.Pack()
	if _, err := guardText(what+" after the change", out); err != nil {
		return nil, err
	}
	return out, nil
}

// checkPatch reads a patch before it is applied and returns its number of operations: it
// must be an array of at most MaxPatchOps objects, and none may be a copy. A copy duplicates
// a subtree, so a few dozen of them double a document past any memory; move, add, remove,
// replace and test cannot.
func checkPatch(m *meter, patch []byte) (int, error) {
	v, e := parseGuarded("the patch", patch)
	if e != nil {
		return 0, e
	}
	arr, ok := v.Value.(*hujson.Array)
	if !ok {
		return 0, invalid(0, 0, "the patch must be a JSON array of operations")
	}
	if len(arr.Elements) > MaxPatchOps {
		return 0, tooComplex("the patch holds %d operations; tailkeeper applies at most %d", len(arr.Elements), MaxPatchOps)
	}
	for i := range arr.Elements {
		obj, ok := arr.Elements[i].Value.(*hujson.Object)
		if !ok {
			continue // the library reports it
		}
		if err := m.tick(1 + len(obj.Members)); err != nil {
			return 0, err
		}
		for j := range obj.Members {
			name, ok := obj.Members[j].Name.Value.(hujson.Literal)
			if !ok || !litEquals(name, "op") {
				continue
			}
			if lit, ok := obj.Members[j].Value.Value.(hujson.Literal); ok && litEquals(lit, "copy") {
				line, col := position(patch, obj.Members[j].Value.StartOffset)
				return 0, invalid(line, col, "the patch has a copy operation; copy duplicates a subtree and is not applied: use add, replace, remove or move")
			}
		}
	}
	return len(arr.Elements), nil
}

// ApplyPatch applies an RFC 6902 patch to a policy text and returns the patched text with
// the comments and layout of what the patch did not touch. The patch may be HuJSON. A patch
// that fails to apply, or leaves something that is not a policy, is an invalid error and no
// text. A patch past MaxPatchOps operations, or whose operations would need more work than
// the budget on this policy, is a too_complex error.
func ApplyPatch(ctx context.Context, text, patch []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m := newMeter(ctx)
	textNodes, err := guardText("the policy text", text)
	if err != nil {
		return nil, err
	}
	patchNodes, err := guardText("the patch", patch)
	if err != nil {
		return nil, err
	}
	ops, err := checkPatch(m, patch)
	if err != nil {
		return nil, err
	}
	v, e := parseObject("the policy text", text)
	if e != nil {
		return nil, e
	}
	if err := chargePatch(m, ops, textNodes+patchNodes); err != nil {
		return nil, err
	}
	if err := applyPatch(&v, patch, "the patch does not apply"); err != nil {
		return nil, err
	}
	return packChecked("the patched policy", &v)
}

// testsName decodes the name of a top-level member if it can be tests or sshTests in any
// case, and reports whether it is. A name too long to be either is not decoded.
func testsName(name *hujson.Value) (string, bool) {
	lit, ok := name.Value.(hujson.Literal)
	if !ok || len(lit) > maxTestsNameLit {
		return "", false
	}
	n := nameOf(name)
	k := sectionKey(n)
	return n, k == sectionKey("tests") || k == sectionKey("sshTests")
}

// StripTests removes every tests and sshTests member from the top level of a policy text,
// whatever the case of its name and however many times it is written (up to MaxPatchOps
// members). The rest keeps its text, but the HuJSON library also drops the comments attached
// to a removed member and the whitespace around it. A text with none comes back as it was.
func StripTests(ctx context.Context, text []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m := newMeter(ctx)
	nodes, err := guardText("the policy text", text)
	if err != nil {
		return nil, err
	}
	v, e := parseObject("the policy text", text)
	if e != nil {
		return nil, e
	}
	members := v.Value.(*hujson.Object).Members
	var ops []string
	for i := range members {
		if err := m.tick(1); err != nil {
			return nil, err
		}
		if name, ok := testsName(&members[i].Name); ok {
			if len(ops) == MaxPatchOps {
				return nil, tooComplex("the policy text has more than %d tests and sshTests members; tailkeeper removes at most %d", MaxPatchOps, MaxPatchOps)
			}
			ops = append(ops, `{"op":"remove","path":`+string(appendJSONString(nil, "/"+escapePointer(name)))+`}`)
		}
	}
	if len(ops) == 0 {
		return bytes.Clone(text), nil
	}
	if err := chargePatch(m, len(ops), nodes); err != nil {
		return nil, err
	}
	if err := applyPatch(&v, []byte("["+strings.Join(ops, ",")+"]"), "the tests could not be removed"); err != nil {
		return nil, err
	}
	return packChecked("the policy without its tests", &v)
}

// AppendTests adds tests to the top level of a policy text as new tests and sshTests
// members at its end, so the result is the original text plus a tail. Each entry is one
// test object, as text; a list that is empty adds no member. The text must hold neither
// section already (StripTests first): a second one is a repeated key, which the server
// refuses and Go's decoder would resolve by keeping the later of the two. The entries are
// bounded in all, not only each:
// the policy and the entries together may not pass MaxBytes bytes or MaxNodes values, and
// each list holds at most MaxAppended.
func AppendTests(ctx context.Context, text []byte, tests, sshTests [][]byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(tests) > MaxAppended || len(sshTests) > MaxAppended {
		return nil, tooComplex("%d tests and %d SSH tests to add; tailkeeper adds at most %d of each", len(tests), len(sshTests), MaxAppended)
	}
	added := 0
	for _, list := range [][][]byte{tests, sshTests} {
		for _, entry := range list {
			added += len(entry)
		}
	}
	if added+len(text) > MaxBytes {
		return nil, tooComplex("the policy and the tests to add together come to more than the %d bytes tailkeeper reads", MaxBytes)
	}
	m := newMeter(ctx)
	nodes, err := guardText("the policy text", text)
	if err != nil {
		return nil, err
	}
	v, e := parseObject("the policy text", text)
	if e != nil {
		return nil, e
	}
	members := v.Value.(*hujson.Object).Members
	for i := range members {
		if err := m.tick(1); err != nil {
			return nil, err
		}
		if name, ok := testsName(&members[i].Name); ok {
			return nil, invalid(0, 0, "the policy text already has a %q section; remove its tests first", capText(name))
		}
	}
	// One add per list, with the whole list as its value: an add of each entry would find
	// the section again for each, a scan of the top level a thousand times over.
	var patch bytes.Buffer
	patch.Grow(added + 64*2)
	adds := 0
	patch.WriteByte('[')
	for _, list := range []struct {
		section string
		entries [][]byte
	}{{"tests", tests}, {"sshTests", sshTests}} {
		if len(list.entries) == 0 {
			continue
		}
		if adds++; adds > 1 {
			patch.WriteString(",\n")
		}
		patch.WriteString(`{"op":"add","path":"/` + list.section + `","value":[`)
		for i, entry := range list.entries {
			what := "test " + list.section + "[" + strconv.Itoa(i) + "]"
			n, err := guardText(what, entry)
			if err != nil {
				return nil, err
			}
			if nodes += n; nodes > MaxNodes {
				return nil, tooComplex("the policy and the tests to add hold %d values together; tailkeeper reads at most %d", nodes, MaxNodes)
			}
			if err := m.tick(n); err != nil {
				return nil, err
			}
			if _, e := parseObject(what, entry); e != nil {
				return nil, e
			}
			if i > 0 {
				patch.WriteString(",\n") // a line comment that parsed ends in a line feed, so it cannot hide the comma
			}
			patch.Write(entry)
		}
		patch.WriteString("\n]}")
	}
	patch.WriteByte(']')
	if adds == 0 {
		return bytes.Clone(text), nil
	}
	if err := chargePatch(m, adds, nodes); err != nil {
		return nil, err
	}
	if err := applyPatch(&v, patch.Bytes(), "the tests could not be added"); err != nil {
		return nil, err
	}
	return packChecked("the policy with its tests", &v)
}

// Standardize replaces the comments and trailing commas of a text with spaces, keeping
// every line and byte offset, as Tailscale's own pusher does before it validates.
func Standardize(ctx context.Context, text []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := guardText("the policy text", text); err != nil {
		return nil, err
	}
	v, e := parseGuarded("the policy text", text)
	if e != nil {
		return nil, e
	}
	v.Standardize()
	return v.Pack(), nil
}

// Format formats a text the way Tailscale's pusher does before it compares. The output is
// at most MaxFormatted bytes: a text that would format to more is a too_complex error.
func Format(ctx context.Context, text []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := guardText("the policy text", text); err != nil {
		return nil, err
	}
	v, e := parseGuarded("the policy text", text)
	if e != nil {
		return nil, e
	}
	if _, err := formatBound(newMeter(ctx), &v, len(text)); err != nil {
		return nil, err
	}
	v.Format()
	return v.Pack(), nil
}

// formatBound is an upper bound on the size of the text Format would produce for v, which
// was parsed from a text of size bytes, or a too_complex error when the bound passes
// MaxFormatted. It reads the tree once (a tick a value) before the library lays anything
// out, because what the library appends cannot be seen from the size of the input:
//
//   - each member or element starts a line, and each line of a comment is a line of its own,
//     indented by the depth it sits at. The depth grows by one for each object or array
//     (Format expands any of them that holds a line break or runs past 80 columns, and the
//     bound takes every one as expanded) and by one more where an object member has a line
//     break between its name and its value;
//   - the values of a block of members are aligned by spaces added after each name, as
//     many as the block's longest name is longer than the name, so one long name among a
//     thousand short ones adds a thousand times its length.
//
// The bound takes each object's longest and shortest row for the padding of every member
// of it, and two lines a value plus the lines of its comments for the indentation, so it
// is never below the output (TestFormatBoundIsNeverBelowTheOutput holds it to that).
func formatBound(m *meter, v *hujson.Value, size int) (int, error) {
	f := &formatSizer{m: m, total: size}
	if err := f.value(v, 0, 0); err != nil {
		return 0, err
	}
	return f.total, nil
}

type formatSizer struct {
	m     *meter
	total int
}

func (f *formatSizer) add(n int) error {
	if f.total += n; f.total > MaxFormatted {
		return tooComplex("formatting the text would produce more than %d bytes of indentation and padding; "+
			"tailkeeper formats at most that", MaxFormatted)
	}
	return nil
}

// extra adds the indentation of the lines of the comments and whitespace around a value,
// which Format indents by indent tabs.
func (f *formatSizer) extra(indent int, around ...hujson.Extra) error {
	lines := 2
	for _, x := range around {
		lines += bytes.Count(x, []byte{'\n'})
	}
	return f.add(lines*(indent+1) + 4)
}

// value adds what v and everything under it can add. depth is what Format passes to
// formatWhitespace for v (the number of expanded levels above its members), indent the
// tabs Format puts before v's own comments.
func (f *formatSizer) value(v *hujson.Value, depth, indent int) error {
	if err := f.m.tick(1); err != nil {
		return err
	}
	if err := f.extra(indent, v.BeforeExtra, v.AfterExtra); err != nil {
		return err
	}
	switch c := v.Value.(type) {
	case *hujson.Object:
		shortest, longest := -1, 0
		for i := range c.Members {
			name, val := &c.Members[i].Name, &c.Members[i].Value
			if err := f.value(name, depth+1, depth+2); err != nil {
				return err
			}
			child := depth + 1
			if bytes.IndexByte(name.AfterExtra, '\n') >= 0 || bytes.IndexByte(val.BeforeExtra, '\n') >= 0 {
				child++ // a line break between the name and the value indents the value again
			}
			if err := f.value(val, child, depth+2); err != nil {
				return err
			}
			row := len(name.Value.(hujson.Literal)) + len(name.AfterExtra) + len(val.BeforeExtra) + 5
			if shortest < 0 || row < shortest {
				shortest = row
			}
			longest = max(longest, row)
		}
		if err := f.add(len(c.Members) * (longest - max(shortest, 0))); err != nil {
			return err
		}
		return f.extra(depth+1, c.AfterExtra)
	case *hujson.Array:
		for i := range c.Elements {
			if err := f.value(&c.Elements[i], depth+1, depth+2); err != nil {
				return err
			}
		}
		return f.extra(depth+1, c.AfterExtra)
	}
	return nil
}
