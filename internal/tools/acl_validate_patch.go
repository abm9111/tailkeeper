package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/tailscale/hujson"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/guard"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tripwire"
)

// This file prepares the text a validation sends: the caller's policy, the live policy with
// the caller's patch applied, or the live policy itself. An agent edits by patch, because
// acl_get is a masked display copy that cannot be sent back, and names a user only by the
// pseudonym a result showed; the pseudonym is replaced by the login here, after the subject
// rule has read the same bytes and before the text is parsed again.

// maxCallerTests is how many tests an MCP caller may add or replace in one call: one
// validation could otherwise carry thousands of probing tests. The live policy's stored
// tests, an operator's files and the invariants are not counted, and acl_diff, which sends
// no request, applies no cap.
const maxCallerTests = 64

// proposal is the text a call validates and what is known about it.
type proposal struct {
	Sent     []byte   // the exact bytes that go to Tailscale
	Doc      *acl.Doc // Parse of Sent
	Source   string   // "from", "patch" or "live"
	Replaced int      // pseudonyms replaced by logins
}

// prepare builds the proposal of a call from what the caller gave and the live policy that was
// read for it. The problems it returns are the text's own: the call is invalid, nothing is
// sent, and the proposal is nil. An error is a refusal (a literal login, a credential shape,
// too many tests, a pseudonym that names no one, a text past the engine's budgets), and
// nothing is sent then either. Nothing is requested here but the users, and only when the
// text carries a pseudonym.
//
// The text of an MCP caller goes through, in this order: the subject rule and the credential
// tripwire on the bytes the caller wrote, the replacement of each pseudonym by the login it
// names, the patch if there is one, a new parse of the result (replacing a pseudonym can
// write a key twice), and the cap on the tests the caller adds. An operator's own file is
// sent as it is, except that a marker of a pseudonym in it is invalid: an operator file holds
// logins.
func (v *validation) prepare(ctx context.Context, live api.PolicyDetails, liveDoc *acl.Doc) (*proposal, []ACLProblem, error) {
	switch {
	case v.in.Patch != "":
		return v.prepatch(ctx, live, liveDoc)
	case v.in.Policy != "":
		return v.prepolicy(ctx, live)
	}
	return &proposal{Sent: live.Text, Doc: liveDoc, Source: sourceLive}, nil, nil
}

// prepolicy prepares the caller's policy text.
func (v *validation) prepolicy(ctx context.Context, live api.PolicyDetails) (*proposal, []ACLProblem, error) {
	text := []byte(v.in.Policy)
	doc := v.doc
	if doc == nil {
		d, err := v.parse(ctx, text)
		if err != nil {
			p, perr := v.parseProblem(text, err, sourceFrom)
			if perr != nil {
				return nil, nil, perr
			}
			return nil, []ACLProblem{p}, nil
		}
		doc = d
	}
	if v.in.Operator {
		if p, found := v.operatorMarker(text, sourceFrom); found {
			return nil, []ACLProblem{p}, nil
		}
		return &proposal{Sent: text, Doc: doc, Source: sourceFrom}, nil, nil
	}
	if err := screenMCPText(v.env, text, "a proposal"); err != nil {
		return nil, nil, err
	}
	sent, replaced, err := SubstituteSubjects(ctx, v.res, text)
	if err != nil {
		return nil, nil, err
	}
	var fresh []ACLProblem
	if replaced > 0 {
		// From here on a position in the sent text is mapped back to the caller's own: the
		// logins are longer or shorter than the pseudonyms they replaced.
		v.pos = newColumnMap(text, sent)
		d, err := v.parse(ctx, sent)
		if err != nil {
			p, perr := v.parseProblem(sent, err, sourceFrom)
			if perr != nil {
				return nil, nil, perr
			}
			return nil, []ACLProblem{p}, nil
		}
		doc = d
		fresh = v.newFindings(doc)
	}
	if n := countCallerTests(live.Text, sent); n > maxCallerTests && !v.uncapped {
		return nil, nil, tooManyTests(n)
	}
	if hasError(fresh) {
		return nil, fresh, nil
	}
	return &proposal{Sent: sent, Doc: doc, Source: sourceFrom, Replaced: replaced}, fresh, nil
}

// newFindings are the structural problems of the text once pseudonyms are replaced that the
// caller's own text did not show: two spellings of one user as keys of one object are a key
// written twice only after the replacement.
func (v *validation) newFindings(doc *acl.Doc) []ACLProblem {
	ps, omitted := v.structureProblems(doc, sourceFrom, false)
	v.out.Omitted += omitted
	var fresh []ACLProblem
	for _, p := range ps {
		known := false
		for _, old := range v.out.Errors {
			known = known || (old.Kind == p.Kind && old.Line == p.Line && old.Source == p.Source)
		}
		for _, old := range v.out.Notices {
			known = known || (old.Kind == p.Kind && old.Line == p.Line && old.Source == p.Source)
		}
		if !known {
			fresh = append(fresh, p)
		}
	}
	return fresh
}

// hasError reports a problem of severity error.
func hasError(ps []ACLProblem) bool {
	for _, p := range ps {
		if p.Severity == severityError {
			return true
		}
	}
	return false
}

// prepatch applies the caller's patch to the live policy.
func (v *validation) prepatch(ctx context.Context, live api.PolicyDetails, liveDoc *acl.Doc) (*proposal, []ACLProblem, error) {
	patch := []byte(v.in.Patch)
	replaced := 0
	if v.in.Operator {
		if p, found := v.operatorMarker(patch, sourcePatch); found {
			return nil, []ACLProblem{p}, nil
		}
	} else {
		if err := screenPatch(v.env, patch, v.uncapped); err != nil {
			return nil, nil, err
		}
		var err error
		if patch, replaced, err = SubstituteSubjects(ctx, v.res, patch); err != nil {
			return nil, nil, err
		}
		if replaced > 0 {
			v.patchPos = newColumnMap([]byte(v.in.Patch), patch)
		}
	}
	patched, err := acl.ApplyPatch(ctx, live.Text, patch)
	if err != nil {
		p, perr := v.parseProblem(patch, err, sourcePatch)
		if perr != nil {
			return nil, nil, perr
		}
		if p.Kind == kindSyntax && p.Line == 0 {
			p.Kind = kindStructure // a patch that is well formed but does not apply has no position to be a syntax error at
		}
		return nil, []ACLProblem{p}, nil
	}
	// The operations were counted before anything was requested, and that count is only a bound:
	// a move carries entries into tests from anywhere in the policy, and an add that
	// comes first can put them where a move then takes them. The cap is on what the patched text
	// holds that the live policy does not, and not on an operator's own patch file.
	if n := countCallerTests(live.Text, patched); n > maxCallerTests && !v.in.Operator && !v.uncapped {
		return nil, nil, tooManyTests(n)
	}
	doc, err := v.parse(ctx, patched)
	if err != nil {
		p, perr := v.parseProblem(patched, err, sourcePatch)
		if perr != nil {
			return nil, nil, perr
		}
		p.Line, p.Column = 0, 0 // the caller never wrote this text
		return nil, []ACLProblem{p}, nil
	}
	problems, omitted := v.structureProblems(doc, sourcePatch, false)
	v.out.Omitted += omitted
	problems = append(problems, v.addedSections(liveDoc, doc)...)
	if hasError(problems) {
		return nil, problems, nil
	}
	return &proposal{Sent: patched, Doc: doc, Source: sourcePatch, Replaced: replaced}, problems, nil
}

// addedSections are the sections the patch added that this version of tailkeeper does not
// know, as notices. The live policy's own unknown sections are already a notice.
func (v *validation) addedSections(liveDoc, doc *acl.Doc) []ACLProblem {
	had := map[string]bool{}
	for _, name := range liveDoc.UnknownSections() {
		had[name] = true
	}
	var out []ACLProblem
	shown := doc.UnknownSectionsShown()
	for i, name := range doc.UnknownSections() {
		if had[name] {
			continue
		}
		p := v.problem(kindUnknownSection, severityNotice, sourcePatch,
			"Tailscale will probably reject the section "+quoteName(shown[i])+": it is not one it knows (json: unknown field)")
		p.Pointer = v.hide("/" + pointerEscape.Replace(cutRunes(shown[i], 128)))
		out = append(out, p)
	}
	return out
}

// operatorMarker finds a pseudonym marker in an operator's file. The file holds logins, which
// are the operator's own; a pseudonym is not one, and Tailscale would not know it.
func (v *validation) operatorMarker(text []byte, source string) (ACLProblem, bool) {
	loc := markerRE.FindIndex(text)
	if loc == nil {
		return ACLProblem{}, false
	}
	line := lineOf(text, loc[0])
	col := loc[0] - bytes.LastIndexByte(text[:loc[0]], '\n')
	p := v.problem(kindStructure, severityError, source, "an operator file holds logins; a pseudonym is not one: write the user's login")
	p.Line, p.Column = line, col
	return p, true
}

// screenPatch is screenMCPText for a patch, after the guard's own limits: the depth of the
// nesting and the number of values, which hujson would otherwise meet unbounded, and the cap
// on the tests the patch adds, unless uncapped.
func screenPatch(env *registry.Env, patch []byte, uncapped bool) error {
	r := guard.Scan(patch, guard.MaxDepth)
	switch {
	case r.TooDeep:
		return tkerr.New(tkerr.ValidationFailed, "a patch nests deeper than 1,000 levels, which no patch does", "")
	case r.NodeBound > acl.MaxNodes:
		return tkerr.New(tkerr.TooComplex, fmt.Sprintf("a patch holds more than %d values (a name, a value or an element each)", acl.MaxNodes), "")
	}
	if err := screenMCPText(env, patch, "a patch"); err != nil {
		return err
	}
	if n := countPatchTests(patch); n > maxCallerTests && !uncapped {
		return tooManyTests(n)
	}
	return nil
}

// tooManyTests is the refusal of a call that adds or replaces more tests than the cap.
func tooManyTests(n int) error {
	return tkerr.New(tkerr.ValidationFailed,
		fmt.Sprintf("the call adds or replaces %d tests, and one call may carry at most %d: a validation could otherwise be used to probe the tailnet with thousands of them", n, maxCallerTests),
		"split the change; the tests the live policy already has, and the invariants, are not counted")
}

// screenMCPText applies to a text an MCP caller gave the two rules that keep it from
// confirming or carrying what it must not: while masking is on, no user's login may be written
// in it (a verdict would confirm the guess), and no credential shape may be (the text goes to
// Tailscale). what names the text in the refusal. Both run on the exact bytes that will be
// used, before any request.
func screenMCPText(env *registry.Env, text []byte, what string) error {
	if err := checkSubjects(env, string(text), what); err != nil {
		return err
	}
	where, found := tripwireWhere(text)
	if !found {
		return nil
	}
	return tkerr.New(tkerr.ValidationFailed,
		what+" holds text shaped like a credential, "+where+", so it is not sent to Tailscale",
		"validate a patch that leaves that text alone, or ask the owner to validate the text on the command line")
}

// tripwireWhere says where the first credential shape of a text is, and whether there is one:
// a JSON pointer to the value or member that holds it, or "in a comment". The shape is looked
// for in the bytes as written and in every string and key once its JSON escapes are decoded,
// since Tailscale decodes them: a prefix spelled with an escape for one of its letters is the
// prefix when it arrives. A key that is itself credential-shaped shows as (credential-shaped)
// on the path, so the pointer never repeats a credential.
func tripwireWhere(text []byte) (string, bool) {
	raw := tripwire.Check(text) != nil
	if guard.NestsDeeperThan(text, guard.MaxDepth) {
		return "in a text nested too deeply to place it", raw
	}
	v, err := hujson.Parse(bytes.Clone(text))
	if err != nil {
		return "in the text", raw
	}
	var walk func(v *hujson.Value, path string) (string, bool)
	walk = func(v *hujson.Value, path string) (string, bool) {
		switch x := v.Value.(type) {
		case hujson.Literal:
			if x.Kind() == '"' && tripwire.Check([]byte(x.String())) != nil {
				return path, true
			}
		case *hujson.Object:
			for i := range x.Members {
				m := &x.Members[i]
				name := ""
				if lit, ok := m.Name.Value.(hujson.Literal); ok {
					name = lit.String()
				}
				seg := sanitize.String(cutRunes(name, maxPointerSegment), maxPointerSegment)
				if tripwire.Check([]byte(name)) != nil {
					return path + "/(credential-shaped)" + " (a key)", true
				}
				if p, ok := walk(&m.Value, path+"/"+pointerEscape.Replace(seg)); ok {
					return p, true
				}
			}
		case *hujson.Array:
			for i := range x.Elements {
				if p, ok := walk(&x.Elements[i], path+"/"+strconv.Itoa(i)); ok {
					return p, true
				}
			}
		}
		return "", false
	}
	if p, ok := walk(&v, ""); ok {
		if p == "" {
			return "at the top level", true
		}
		return "at " + p, true
	}
	return "in a comment", raw
}

// testEntries returns, for each entry of the top-level tests and sshTests of a policy text, its
// section and its text with comments and white space removed, so that two spellings of one
// test compare equal. The text has been through the guard.
func testEntries(text []byte) []string {
	v, err := hujson.Parse(bytes.Clone(text))
	if err != nil {
		return nil
	}
	if obj, ok := v.Value.(*hujson.Object); ok {
		return entriesOf(obj)
	}
	return nil
}

// entriesOf is testEntries for an object that has been parsed.
func entriesOf(obj *hujson.Object) []string {
	var out []string
	for i := range obj.Members {
		name := ""
		if lit, ok := obj.Members[i].Name.Value.(hujson.Literal); ok {
			name = lit.String()
		}
		sec, known := acl.SectionByName(name)
		list, isList := obj.Members[i].Value.Value.(*hujson.Array)
		if !known || !isList || (sec.Name != "tests" && sec.Name != "sshTests") {
			continue
		}
		for j := range list.Elements {
			c := list.Elements[j].Clone()
			c.Minimize()
			out = append(out, sec.Name+" "+string(c.Pack()))
		}
	}
	return out
}

// countCallerTests is how many tests of the text a caller sent are new: the entries of tests
// and sshTests that the live policy does not already hold, compared with comments and white
// space removed. The live policy's stored tests do not count.
func countCallerTests(liveText, sent []byte) int {
	have := map[string]bool{}
	for _, e := range testEntries(liveText) {
		have[e] = true
	}
	n := 0
	for _, e := range testEntries(sent) {
		if !have[e] {
			n++
		}
	}
	return n
}

// countPatchTests is how many tests the operations of a patch add or replace: the entries of
// an array written to /tests or /sshTests, or one for each operation on an entry or below it,
// and the entries of those sections in a value written to the root. It is a bound read from the
// operations alone, so that a patch is refused before any request; the exact count is that of
// the patched text (countCallerTests), which no spelling of an operation can get past. A patch
// that is not readable counts none: the engine refuses it.
func countPatchTests(patch []byte) int {
	v, err := hujson.Parse(bytes.Clone(patch))
	if err != nil {
		return 0
	}
	ops, ok := v.Value.(*hujson.Array)
	if !ok {
		return 0
	}
	member := func(obj *hujson.Object, name string) *hujson.Value {
		for i := range obj.Members {
			if lit, ok := obj.Members[i].Name.Value.(hujson.Literal); ok && strings.EqualFold(lit.String(), name) {
				return &obj.Members[i].Value
			}
		}
		return nil
	}
	n := 0
	for i := range ops.Elements {
		obj, ok := ops.Elements[i].Value.(*hujson.Object)
		if !ok {
			continue
		}
		op, path, value := member(obj, "op"), member(obj, "path"), member(obj, "value")
		if op == nil || path == nil {
			continue
		}
		kind, _ := op.Value.(hujson.Literal)
		if k := kind.String(); k != "add" && k != "replace" && k != "move" {
			continue
		}
		ptr, _ := path.Value.(hujson.Literal)
		var p string
		if json.Unmarshal(ptr, &p) != nil {
			continue
		}
		segs := []string{}
		if p != "" {
			for _, s := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
				segs = append(segs, pointerUnescape.Replace(s))
			}
		}
		switch {
		case len(segs) == 0 && value != nil:
			if root, ok := value.Value.(*hujson.Object); ok {
				n += len(entriesOf(root))
			}
		case len(segs) >= 1:
			sec, known := acl.SectionByName(segs[0])
			if !known || (sec.Name != "tests" && sec.Name != "sshTests") {
				continue
			}
			if len(segs) == 1 && value != nil {
				if arr, ok := value.Value.(*hujson.Array); ok {
					n += len(arr.Elements)
					continue
				}
			}
			n++
		}
	}
	return n
}

// columnMap maps a position in the text that was sent back to the text the caller wrote. The
// two differ only inside the strings where a login replaced a pseudonym, so a line is the same
// in both and a column moves by the lengths of the replacements before it on its line. Without
// it a column would be off by the difference between a login and the pseudonym the caller held,
// and that difference is the length of a login the caller never saw.
type columnMap struct {
	text, sent []byte
	spans      []replacedSpan // in order, one for each replaced string
	broken     bool           // the two texts do not agree: no column can be told
}

// replacedSpan is one replaced string: where it was in the caller's text and where it is in
// the sent one.
type replacedSpan struct{ oldStart, oldEnd, newStart, newEnd int }

// newColumnMap finds the strings of text that were replaced in sent, which is text with every
// pseudonym carrier replaced by a JSON string. It is nil when nothing was replaced.
func newColumnMap(text, sent []byte) *columnMap {
	found, _, _, err := stringsOf(text)
	if err != nil || len(found) == 0 {
		return nil
	}
	m := &columnMap{text: text, sent: sent}
	delta := 0
	for _, f := range found {
		start := f.start + delta
		end := stringEnd(sent, start)
		if end < 0 {
			m.broken = true
			return m
		}
		m.spans = append(m.spans, replacedSpan{f.start, f.end, start, end})
		delta += (end - start) - (f.end - f.start)
	}
	m.broken = len(text)+delta != len(sent)
	return m
}

// stringEnd is the offset just past the JSON string that starts at start, or -1 when none does.
func stringEnd(b []byte, start int) int {
	if start < 0 || start >= len(b) || b[start] != '"' {
		return -1
	}
	for j := start + 1; j < len(b); j++ {
		switch b[j] {
		case '\\':
			j++
		case '"':
			return j + 1
		}
	}
	return -1
}

// back maps a line and a column (from 1, in bytes) of the sent text to the caller's text. A
// column that cannot be told comes back as 0, which a result leaves out. A nil map is the
// identity.
func (m *columnMap) back(line, col int) (int, int) {
	if m == nil || col < 1 {
		return line, col
	}
	if m.broken || line < 1 {
		return line, 0
	}
	start := 0
	for l := 1; l < line; l++ {
		i := bytes.IndexByte(m.sent[start:], '\n')
		if i < 0 {
			return line, 0
		}
		start += i + 1
	}
	off := start + col - 1
	if off > len(m.sent) {
		return line, 0
	}
	shift := 0
	for _, s := range m.spans {
		if off < s.newStart {
			break
		}
		if off < s.newEnd {
			off, shift = s.oldStart, 0 // inside a replaced string: where the string began
			break
		}
		shift += (s.newEnd - s.newStart) - (s.oldEnd - s.oldStart)
	}
	off -= shift
	if off < 0 || off > len(m.text) || lineOf(m.text, off) != line {
		return line, 0
	}
	return line, off - bytes.LastIndexByte(m.text[:off], '\n')
}

// callerPos maps a position of source to what a result may say of it. A proposal the caller
// wrote went through the replacement of pseudonyms, so its position is mapped back to the
// caller's own text. The live policy holds logins the caller never saw: a column in it counts
// their bytes, so only its line is kept (the caller reads the line in acl_get; a line is a
// count of line feeds, which no login changes). A patched policy is placed by pointer and the
// callers of this function leave its positions out.
func (v *validation) callerPos(source string, line, col int) (int, int) {
	switch source {
	case sourceFrom:
		return v.pos.back(line, col)
	case sourceLive:
		return line, 0
	}
	return line, col
}

// withoutPosition removes the position a server message begins with ("line N, column M: ..."):
// it is called for a message that was placed by that position.
func withoutPosition(msg string) string {
	_, rest, _ := strings.Cut(msg, ": ")
	return rest
}

// restatePosition rewrites the position a server message begins with ("line N, column M: ...")
// to the caller's own: the server counted the text it was sent, and the column it names is
// off by the lengths of the logins that replaced pseudonyms. A column that cannot be told is
// left out.
func restatePosition(msg string, line, col int) string {
	_, rest, ok := strings.Cut(msg, ": ")
	if !ok {
		return msg
	}
	if col == 0 {
		return fmt.Sprintf("line %d: %s", line, rest)
	}
	return fmt.Sprintf("line %d, column %d: %s", line, col, rest)
}
