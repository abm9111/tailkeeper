package acl

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// textRoom is how much of a text a textBuf keeps: enough to cut it at maxPointer on a rune
// boundary.
const textRoom = maxPointer + 4

// textBuf collects the head of a text that may be far longer than a result shows. It keeps
// the first bytes and counts the rest, so a value of megabytes costs a result a kilobyte and
// the length it reports is the whole's. Nothing is built past the room: a piece is cut
// before it is copied, and a piece that is only counted is scanned, never copied.
type textBuf struct {
	b    []byte
	full int
	// show is how a caller sees the policy text written with addText and quoted; nil writes
	// it as it is. The room is spent on what the caller sees, so that where the text is cut,
	// and whether it is, tells nothing about the text show hides. full then counts the shown
	// text.
	show Show
}

func (t *textBuf) room() int { return textRoom - len(t.b) }

// add writes s as it is: a literal of the text's own, never policy text.
func (t *textBuf) add(s string) {
	t.full += len(s)
	if r := t.room(); r > 0 {
		t.b = append(t.b, s[:min(len(s), r)]...)
	}
}

// addText writes s, which is policy text, as a caller sees it.
func (t *textBuf) addText(s string) {
	if r := t.room(); t.show != nil && r > 0 {
		s = t.show(s, r)
	}
	t.add(s)
}

func (t *textBuf) addBytes(p []byte) {
	t.full += len(p)
	if r := t.room(); r > 0 {
		t.b = append(t.b, p[:min(len(p), r)]...)
	}
}

// skip counts n bytes that are not kept.
func (t *textBuf) skip(n int) { t.full += n }

func (t *textBuf) done() bool { return t.room() <= 0 }

// quoted writes s as a JSON string. The part that fits is encoded; the length of the rest
// is counted by scanning it, which is paid for by its bytes.
func (t *textBuf) quoted(m *meter, s string) error {
	room := t.room()
	if room <= 0 {
		return t.count(m, s, 2)
	}
	if t.show != nil {
		s = t.show(s, room)
	}
	if len(s) <= room {
		t.addBytes(appendJSONString(nil, s))
		return nil
	}
	cut := room
	for cut > 0 && !runeStart(s[cut]) {
		cut--
	}
	t.addBytes(appendJSONString(nil, s[:cut]))
	return t.count(m, s[cut:], 0)
}

// count adds the length s would have once escaped, and quotes more bytes for the quotes
// around it, without building it. The scan is paid for by its bytes.
func (t *textBuf) count(m *meter, s string, quotes int) error {
	if err := m.tick(len(s)/8 + 1); err != nil {
		return err
	}
	t.full += quotes + escapedLen(s)
	return nil
}

// set writes the items of a set as a JSON list. The items are written until the room is
// spent; the length of the rest is the set's, known when the set was made.
func (t *textBuf) set(m *meter, s *idSet) error {
	t.add("[")
	written := 0
	for i, it := range s.items {
		if t.done() {
			if t.show == nil {
				t.skip(s.quoted - written)
			}
			break
		}
		if i > 0 {
			t.add(",")
			written++
		}
		before := t.full
		if err := t.quoted(m, it); err != nil {
			return err
		}
		written += t.full - before
	}
	t.add("]")
	return nil
}

// text is what the buffer holds as a Text: cut at 1 KiB, with the length of the whole.
func (t *textBuf) text() Text {
	s := string(t.b)
	if t.full > maxPointer {
		return Text{Text: capText(s), Len: t.full, Truncated: true}
	}
	return Text{Text: s, Len: t.full}
}

// quotedLen is len(appendJSONString(nil, s)), counted without building it.
func quotedLen(s string) int { return 2 + escapedLen(s) }

// escapedLen is the length of s once escaped, without the quotes around it.
func escapedLen(s string) int {
	n := 0
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '"' || c == '\\' || c == '\n' || c == '\r' || c == '\t':
			n += 2
		case c < 0x20 || c == 0x7f:
			n += 6
		case c < utf8.RuneSelf:
			n++
		default:
			r, size := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && size == 1 {
				n += len("\xef\xbf\xbd")
			} else {
				n += size
			}
			i += size
			continue
		}
		i++
	}
	return n
}

// capped is a Text for a string that is already built, cut at 1 KiB.
func capped(s string) Text {
	if len(s) <= maxPointer {
		return Text{Text: s, Len: len(s)}
	}
	return Text{Text: capText(s), Len: len(s), Truncated: true}
}

// FieldDelta is what a changed element gained and lost in one field, so a reader sees the
// widening entry even when the element is too long to show whole. Each item is cut at
// 1 KiB, and at most maxDeltaItems of each side are listed (the rest are counted), with the
// wide selectors first.
type FieldDelta struct {
	Field                  string
	Added, Removed         []string
	AddedMore, RemovedMore int
}

const maxDeltaItems = 50

// fieldDelta makes the delta of one field: the items gained are the new policy's, shown as
// its Doc shows them, and the items lost the old one's.
func fieldDelta(m *meter, field string, added, removed []string, newView, oldView view) (FieldDelta, error) {
	f := FieldDelta{Field: field}
	var err error
	if f.Added, f.AddedMore, err = capList(m, added, newView); err != nil {
		return f, err
	}
	f.Removed, f.RemovedMore, err = capList(m, removed, oldView)
	return f, err
}

// capList lists at most maxDeltaItems of the items, the selectors that widen access first
// and the rest in their order, each cut at 1 KiB, as far as their cost goes (listCost), and
// counts the items left out. It stops at the first item that does not fit.
func capList(m *meter, items []string, v view) ([]string, int, error) {
	if err := m.tick(len(items)); err != nil {
		return nil, 0, err
	}
	out := make([]string, 0, min(len(items), maxDeltaItems))
	cost := 0
list:
	for _, wide := range []bool{true, false} {
		for _, it := range items {
			if len(out) == maxDeltaItems {
				break list
			}
			if (wideBit(it) != 0) == wide {
				shown := v.cut(it)
				if cost += DisplayCost(shown) + 3; cost > listCost {
					break list
				}
				out = append(out, shown)
			}
		}
	}
	return out, len(items) - len(out), nil
}

// setMinus is the items of a that b lacks; both are sorted without repeats.
func setMinus(m *meter, a, b []string) ([]string, error) {
	if err := m.tick(len(a) + len(b) + 1); err != nil {
		return nil, err
	}
	var out []string
	i, j := 0, 0
	for i < len(a) {
		switch {
		case j >= len(b) || a[i] < b[j]:
			out = append(out, a[i])
			i++
		case a[i] == b[j]:
			i++
			j++
		default:
			j++
		}
	}
	return out, nil
}

// unionItems is the sorted items of the sources of a group of atoms, without repeats.
func unionItems(m *meter, as []*atom) ([]string, error) {
	if len(as) == 1 {
		return as[0].src.items, nil
	}
	var all []string
	for _, a := range as {
		all = append(all, a.src.items...)
	}
	if err := m.tick(len(all)); err != nil {
		return nil, err
	}
	return sortedUnique(m, all)
}

// atomsDelta says what a changed group of atoms gained and lost in sources and in ports.
func (d *comparer) atomsDelta(oa, na []*atom) ([]FieldDelta, error) {
	m := d.m
	srcOld, err := unionItems(m, oa)
	if err != nil {
		return nil, err
	}
	srcNew, err := unionItems(m, na)
	if err != nil {
		return nil, err
	}
	var out []FieldDelta
	added, err := setMinus(m, srcNew, srcOld)
	if err != nil {
		return nil, err
	}
	removed, err := setMinus(m, srcOld, srcNew)
	if err != nil {
		return nil, err
	}
	if len(added)+len(removed) > 0 {
		f, err := fieldDelta(m, "src", added, removed, d.nv, d.ov)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	portsOld, err := portsOf(m, oa)
	if err != nil {
		return nil, err
	}
	portsNew, err := portsOf(m, na)
	if err != nil {
		return nil, err
	}
	if err := m.tick(len(portsOld.ranges) + len(portsOld.raw) + len(portsNew.ranges) + len(portsNew.raw) + 1); err != nil {
		return nil, err
	}
	var padded, premoved []string
	if s := portsNew.minus(portsOld); s != "" {
		padded = append(padded, s)
	}
	if s := portsOld.minus(portsNew); s != "" {
		premoved = append(premoved, s)
	}
	if len(padded)+len(premoved) > 0 {
		f, err := fieldDelta(m, "ports", padded, premoved, d.nv, d.ov)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// portsOf is the ports of a group of atoms together.
func portsOf(m *meter, as []*atom) (ports, error) {
	if len(as) == 1 {
		return as[0].ports, nil
	}
	var p ports
	for _, a := range as {
		if err := m.tick(len(a.ports.ranges) + len(a.ports.raw) + 1); err != nil {
			return ports{}, err
		}
		p.add(a.ports)
	}
	return p, p.normalise(m)
}

// writeAtom writes an atom as a JSON object.
func (d *comparer) writeAtom(tb *textBuf, a *atom) error {
	m := d.m
	tb.add(`{"dst":`)
	if err := tb.quoted(m, a.dst); err != nil {
		return err
	}
	if a.proto != "" {
		tb.add(`,"proto":`)
		if err := tb.quoted(m, a.proto); err != nil {
			return err
		}
	}
	if a.act != "" {
		tb.add(`,"action":`)
		if err := tb.quoted(m, a.act); err != nil {
			return err
		}
	}
	tb.add(`,"ports":`)
	if err := tb.quoted(m, a.pkey); err != nil {
		return err
	}
	tb.add(`,"src":`)
	if err := tb.set(m, a.src); err != nil {
		return err
	}
	if a.posture != "" {
		tb.add(`,"srcPosture":[`)
		tb.addText(a.posture)
		tb.add("]")
	}
	if a.via != "" {
		tb.add(`,"via":[`)
		tb.addText(a.via)
		tb.add("]")
	}
	if a.app != "" {
		tb.add(`,"app":`)
		tb.addText(a.app)
	}
	if a.extra != "" {
		tb.add(`,"extra":`)
		tb.addText(a.extra)
	}
	tb.add("}")
	return nil
}

// atomsText writes a group of atoms, separated by "; ".
func (d *comparer) atomsText(tb *textBuf, as []*atom) error {
	for i, a := range as {
		if i > 0 {
			tb.add("; ")
		}
		if err := d.m.tick(1); err != nil {
			return err
		}
		if err := d.writeAtom(tb, a); err != nil {
			return err
		}
	}
	return nil
}

// wholePrefix heads the identity of an element that is not an object (a node attribute
// entry, a test): the entry is its canonical text, kept whole.
const wholePrefix = "whole" + sep

// attrText writes a node attribute entry with its targets.
func (d *comparer) attrText(tb *textBuf, e *nfEntry) error {
	if rest, ok := strings.CutPrefix(e.key, wholePrefix); ok {
		tb.addText(rest)
		return nil
	}
	tb.addText(strings.TrimSuffix(e.val, "}"))
	tb.add(`,"target":`)
	if err := tb.set(d.m, e.targets); err != nil {
		return err
	}
	tb.add("}")
	return nil
}

// attrKey names a node attribute entry for a reader, as the Doc it is in shows it.
func attrKey(v view, e *nfEntry) string {
	if rest, ok := strings.CutPrefix(e.key, wholePrefix); ok {
		return v.cut(rest)
	}
	return v.cut(e.key)
}

// atomKey names an atom for a reader: its destination and protocol, as the Doc it is in shows
// them.
func atomKey(v view, a *atom) string {
	k := v.cut(a.dst)
	if a.proto != "" {
		k += " " + v.cut(a.proto)
	}
	return capText(k)
}

// assertionKey shows the identity of an assertion of a test or an SSH test as words. The
// identity holds the source, protocol, destination and item JSON-quoted, so none can
// run into the next; they are decoded here, each only as far as a reader can see.
func assertionKey(key string) string { return view{}.assertionKey(key) }

// assertionKey is assertionKey for an assertion of the policy in v, whose words are cut after
// v shows them.
func (v view) assertionKey(key string) string {
	if rest, ok := strings.CutPrefix(key, wholePrefix); ok {
		return capText("whole " + v.cut(rest))
	}
	parts := strings.Split(key, sep)
	if len(parts) != 8 {
		return v.cut(strings.ReplaceAll(key, sep, " "))
	}
	// A word is read from its quoted form as far as a cut of what a caller sees can reach: a
	// login masked is shorter than the bytes that make it.
	read := textRoom
	if v.show != nil {
		read *= shownRead
	}
	word := func(q string) string { return v.shown(unquoteHead(q, read), textRoom) }
	kind, src, proto, attrs, extra, polarity, dst, item := parts[0], word(parts[1]), word(parts[2]),
		parts[3], parts[4], parts[5], word(parts[6]), word(parts[7])
	var words []string
	if kind == "ssh" {
		words = []string{src, "->", dst, polarity, item}
	} else {
		words = []string{src, proto, polarity, dst}
	}
	if attrs != "" {
		words = append(words, "srcPostureAttrs="+v.cut(attrs))
	}
	if extra != "" {
		words = append(words, "extra="+v.cut(extra))
	}
	var b strings.Builder
	for _, w := range words {
		if w == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(w)
	}
	return capText(b.String())
}

// unquoteHead decodes the JSON string q (as appendJSONString writes it), stopping once it
// has limit bytes.
func unquoteHead(q string, limit int) string {
	if len(q) < 2 {
		return q
	}
	q = q[1 : len(q)-1]
	var b []byte
	for i := 0; i < len(q) && len(b) < limit; i++ {
		c := q[i]
		if c != '\\' || i+1 >= len(q) {
			b = append(b, c)
			continue
		}
		i++
		switch q[i] {
		case 'n':
			b = append(b, '\n')
		case 'r':
			b = append(b, '\r')
		case 't':
			b = append(b, '\t')
		case 'u':
			// The encoder writes only \u00XX, for the control characters.
			if i+5 <= len(q) && q[i+1:i+3] == "00" {
				hi, lo := hexValue(q[i+3]), hexValue(q[i+4])
				if hi < 16 && lo < 16 {
					b = append(b, hi<<4|lo)
					i += 4
					continue
				}
			}
			b = append(b, 'u')
		default:
			b = append(b, q[i])
		}
	}
	return string(b)
}

// hexValue is the value of a hexadecimal digit, or 255.
func hexValue(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 255
}

// materialise cuts one change for a page: its texts, its deltas and where it is in each
// text. Everything it builds is bounded by the cut, and what it reads is paid for.
func (d *comparer) materialise(c *rawChange) (Change, error) {
	m := d.m
	ch := Change{Class: classNames[c.class], Op: opNames[c.op], Section: c.secName(), Key: d.displayKey(c)}
	if !c.known() {
		ch.Section = d.viewOf(c).cut(ch.Section)
	}
	if err := m.tick(1); err != nil {
		return ch, err
	}
	var oldAt, newAt *ref
	switch c.kind {
	case kDefault:
		ch.Old, ch.New, ch.Note = capped(c.x.oldText), capped(c.x.newText), c.x.note
	case kWide:
		ch.Fields, ch.Note = d.shownFields(c.x.fields), c.x.note
		if c.x.atomTexts {
			o, n := textBuf{show: d.ov.show}, textBuf{show: d.nv.show}
			if err := d.atomsText(&o, c.oa); err != nil {
				return ch, err
			}
			if err := d.atomsText(&n, c.na); err != nil {
				return ch, err
			}
			ch.Old, ch.New = o.text(), n.text()
		} else {
			ch.Old, ch.New = d.ov.capped(c.x.oldText), d.nv.capped(c.x.newText)
		}
		if len(c.oa) > 0 {
			oldAt = &c.oa[0].ref
		}
		if len(c.na) > 0 {
			newAt = &c.na[0].ref
		}
		if c.oe != nil {
			oldAt = &c.oe.ref
		}
		if c.ne != nil {
			newAt = &c.ne.ref
		}
	case kAtoms:
		o, n := textBuf{show: d.ov.show}, textBuf{show: d.nv.show}
		if err := d.atomsText(&o, c.oa); err != nil {
			return ch, err
		}
		if err := d.atomsText(&n, c.na); err != nil {
			return ch, err
		}
		if len(c.oa) > 0 {
			ch.Old = o.text()
			oldAt = firstRef(c.oa)
		}
		if len(c.na) > 0 {
			ch.New = n.text()
			newAt = firstRef(c.na)
		}
		if len(c.oa) > 0 && len(c.na) > 0 {
			var err error
			if ch.Fields, err = d.atomsDelta(c.oa, c.na); err != nil {
				return ch, err
			}
		}
	case kEntry, kAssertion:
		if c.oe != nil {
			ch.Old = entryText(d.ov, c.oe, c.kind)
			oldAt = &c.oe.ref
			ch.OldN = noteCount(c, c.oe)
		}
		if c.ne != nil {
			ch.New = entryText(d.nv, c.ne, c.kind)
			newAt = &c.ne.ref
			ch.NewN = noteCount(c, c.ne)
		}
		if c.kind == kEntry && c.sec.name == "tagOwners" && c.oe != nil && c.ne != nil &&
			(c.oe.val == "[]" && c.ne.val == `["autogroup:admin"]` || c.oe.val == `["autogroup:admin"]` && c.ne.val == "[]") {
			ch.Note = tagOwnersNote
		}
	case kAttr:
		for i, e := range []*nfEntry{c.oe, c.ne} {
			if e == nil {
				continue
			}
			tb := textBuf{show: []Show{d.ov.show, d.nv.show}[i]}
			if err := d.attrText(&tb, e); err != nil {
				return ch, err
			}
			if i == 0 {
				ch.Old, oldAt = tb.text(), &e.ref
			} else {
				ch.New, newAt = tb.text(), &e.ref
			}
		}
		if c.oe != nil && c.ne != nil {
			added, err := setMinus(m, c.ne.targets.items, c.oe.targets.items)
			if err != nil {
				return ch, err
			}
			removed, err := setMinus(m, c.oe.targets.items, c.ne.targets.items)
			if err != nil {
				return ch, err
			}
			f, err := fieldDelta(m, "target", added, removed, d.nv, d.ov)
			if err != nil {
				return ch, err
			}
			ch.Fields = []FieldDelta{f}
		}
	case kSection:
		ch.Note = c.x.note
		ch.Old, oldAt = d.sectionText(c.x.osec, d.ov)
		ch.New, newAt = d.sectionText(c.x.nsec, d.nv)
	}
	if oldAt != nil {
		ch.OldPointer, ch.OldLine = d.pointerLine(d.ov, *oldAt)
	}
	if newAt != nil {
		ch.NewPointer, ch.NewLine = d.pointerLine(d.nv, *newAt)
	}
	return ch, m.tick(len(ch.Old.Text) + len(ch.New.Text) + len(ch.Key))
}

// noteCount is the number of times an entry appears, for the sections that keep a count.
func noteCount(c *rawChange, e *nfEntry) int {
	if c.kind == kAssertion || c.sec.sec.Shape == ShapeSet {
		return e.n
	}
	return 0
}

// entryText shows a keyed entry's canonical value, or an element's canonical text, as the Doc
// the entry is in shows it.
func entryText(v view, e *nfEntry, k kind) Text {
	if k == kAssertion {
		return capped(v.assertionKey(e.key))
	}
	if e.val != "" {
		return v.capped(e.val)
	}
	return v.capped(e.key)
}

// sectionText shows what a section holds when it is compared as a whole.
func (d *comparer) sectionText(s *nfSec, v view) (Text, *ref) {
	if s == nil || s.state == StateAbsent {
		return Text{}, nil
	}
	var r *ref
	if s.top >= 0 {
		r = &ref{val: v.doc.top[s.top].val, top: s.top, idx: -1}
	}
	if s.whole {
		return v.capped(s.entries[0].val), r
	}
	if s.state == StateEmpty {
		return Text{Text: "empty", Len: len("empty")}, r
	}
	t := strconv.Itoa(s.count) + " entries"
	return Text{Text: t, Len: len(t)}, r
}

func (d *comparer) pointerLine(v view, r ref) (string, int) {
	line, _ := v.doc.lineOf(r)
	return v.pointerOf(r), line
}

// firstRef is the ref of the atom that comes first in its text.
func firstRef(as []*atom) *ref {
	best := &as[0].ref
	for _, a := range as[1:] {
		if a.ref.val != nil && (best.val == nil || a.ref.val.StartOffset < best.val.StartOffset) {
			best = &a.ref
		}
	}
	return best
}

// viewOf is the policy a change is read from, as its side shows it: the new one when the
// change has a new side, the old one otherwise.
func (d *comparer) viewOf(c *rawChange) view {
	if c.ne != nil || len(c.na) > 0 {
		return d.nv
	}
	return d.ov
}

// shownFields returns the deltas a detector built with the text of the policies in them, as
// the callers of the two policies see that text: the items gained are the new policy's, the
// items lost the old one's. Each item is cut after it is shown.
func (d *comparer) shownFields(in []FieldDelta) []FieldDelta {
	out := make([]FieldDelta, len(in))
	for i, f := range in {
		out[i] = FieldDelta{Field: f.Field, AddedMore: f.AddedMore, RemovedMore: f.RemovedMore}
		for _, s := range f.Added {
			out[i].Added = append(out[i].Added, d.nv.cut(s))
		}
		for _, s := range f.Removed {
			out[i].Removed = append(out[i].Removed, d.ov.cut(s))
		}
	}
	return out
}
