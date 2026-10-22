package acl

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Class is the kind of a change, and the order they are listed in: a reader looks at the
// first classes first. The first five are changes; the last two are only counted.
type Class string

const (
	// ClassDefaults: acls, grants or ssh moved between absent, [] and non-empty. An absent
	// acls is allow-all, "acls": [] is deny-all, and removing ssh turns Tailscale SSH off.
	ClassDefaults Class = "defaults"
	// ClassTestsReduced: a test or SSH test assertion was removed or weakened.
	ClassTestsReduced Class = "testsReduced"
	// ClassWidening: a structural change that can only widen access (see widening.go).
	ClassWidening Class = "widening"
	// ClassTailscaleWritten: a change to a construct Tailscale writes itself; expected.
	ClassTailscaleWritten Class = "tailscaleWritten"
	// ClassSemantic: everything else that changes what the server enforces.
	ClassSemantic Class = "semantic"
	// ClassCommentOnly and ClassFormatOnly are counts, never entries.
	ClassCommentOnly Class = "commentOnly"
	ClassFormatOnly  Class = "formatOnly"
)

// The classes of a change as the comparison holds them, in the order they are listed.
const (
	cDefaults uint8 = iota
	cTestsReduced
	cWidening
	cWritten
	cSemantic
)

var classNames = [...]Class{ClassDefaults, ClassTestsReduced, ClassWidening, ClassTailscaleWritten, ClassSemantic}

// Op is what happened to the thing a change names.
type Op string

const (
	OpRemoved Op = "removed"
	OpAdded   Op = "added"
	OpChanged Op = "changed"
)

// The operations as the comparison holds them, in the order they are listed.
const (
	oRemoved uint8 = iota
	oAdded
	oChanged
)

var opNames = [...]Op{OpRemoved, OpAdded, OpChanged}

// Text is a piece of a policy shown to a reader, cut at 1 KiB; Len is its full length.
type Text struct {
	Text      string
	Len       int
	Truncated bool
}

// Change is one difference between two policies.
type Change struct {
	Class   Class
	Op      Op
	Section string // acls, grants, "acls+grants" for access rules that are in both, a section name, or an unknown section's name
	Key     string // the entry's key, or a summary of the atom or assertion
	Old     Text   // the canonical value on the old side (empty when added)
	New     Text   // and on the new side (empty when removed)
	Fields  []FieldDelta
	// OldN and NewN count a repeated entry on each side (tests, SSH rules); 0 when the
	// section has no repeats to count.
	OldN, NewN int
	// Note is a constant sentence that qualifies the change.
	Note string
	// OldPointer and NewPointer are JSON Pointers into each text, and OldLine and NewLine
	// the lines, for what the change names; empty or 0 when there is none.
	OldPointer, NewPointer string
	OldLine, NewLine       int
}

// Counts are the number of changes of each class, over every change: the page of a result
// shows some, and a gate evaluates all.
type Counts struct {
	Defaults, TestsReduced, Widening, TailscaleWritten, Semantic int
	CommentOnly, FormatOnly                                      int
}

// DiffOptions narrow what a diff lists. None of them changes what it counts.
type DiffOptions struct {
	// Section lists only the changes in one section: a known section name in any case, or
	// "unknown" for the sections the table does not know.
	Section string
	// Cursor continues a listing from the NextChange of an earlier result of the same pair.
	Cursor string
	// PageSize is the most changes listed; 0 means DefaultPage.
	PageSize int
	// IgnoreTailscaleWritten leaves the Tailscale-written changes out of the list and out of
	// Equal; they are still counted.
	IgnoreTailscaleWritten bool
	// OldShow and NewShow are how a caller sees the text of the old and of the new policy:
	// whatever a result quotes of a side is cut after its Show has run, and the digest of a
	// cursor is of the normal forms as they show. A nil Show shows the text as it is.
	OldShow, NewShow Show
	// Seal keys the digest that ties a cursor to its comparison: it is given that digest and
	// returns a keyed one. A nil Seal leaves the digest unkeyed.
	Seal func(digest []byte) string
}

// Page sizes: a page holds at most this many changes, and stops once the changes it holds cost
// pageCost (see DisplayCost); the change that crosses it is the last. A list of what a change
// gained or lost stops at listCost, and counts the rest. With these a page, in the characters a
// host receives, stays under what the tool declares: 56,000 and the last change (at most about
// 80,000, with its scalar strings and the two lists of each of two fields), and the findings of
// the two sides, which their caller bounds in the same way.
const (
	DefaultPage = 50
	MaxPage     = 200
	pageCost    = 56000
	listCost    = 6000
)

// NotChecked names what a diff does not establish. It is structural: it cannot say whether
// a change in a group, a host, a tag owner or an alias widens who can reach what, and it
// does not simulate lockout. Those are the audit catalogue and the downgrade checks of later
// releases.
var NotChecked = []string{"access_change", "app_capabilities", "downgrades", "lockout", "ssh_lockout", "via"}

// normalFormLimit is said whenever the access rules or the node attributes differ: the
// reduction to atoms is exact when it says two policies are equal, and can be short when it
// says they differ.
const normalFormLimit = "A rule re-split along both its sources and its ports at once is not reduced to the same atoms, " +
	"so it can read as changed when the access is the same. That is the safe direction."

// DiffResult is the comparison of two policies.
type DiffResult struct {
	// SemanticallyEqual is true only if the two normal forms are equal: no change of the
	// five classes, whatever the options. False can be a false "changed" (see
	// NormalFormLimits); true is exact.
	SemanticallyEqual bool
	// Equal is SemanticallyEqual once the changes IgnoreTailscaleWritten leaves out are left
	// out.
	Equal   bool
	Counts  Counts
	Changes []Change // the page
	// Matched is how many changes the section filter and the options select.
	Matched   int
	Truncated bool
	// NextChange continues the listing. It identifies the comparison it was issued for: the two
	// normal forms as the two sides show them (so it tells nothing about a policy that the result
	// does not), the section filter and the Tailscale-written option, and, with a Seal, a key
	// that only the holder of it can compute. It is not a secret and is not signed: it keeps a
	// listing from continuing on the wrong comparison, and nothing more.
	NextChange string
	// NormalFormLimits, NotChecked and the as-of date qualify the answer.
	NormalFormLimits     []string
	NotChecked           []string
	TailscaleWrittenAsOf string
	// Test counts on each side, in elements.
	TestsBefore, TestsAfter       int
	SSHTestsBefore, SSHTestsAfter int
	// Ops is the work the whole comparison spent, in the units of MaxWork.
	Ops int64
}

// kind says how the texts of a change are made when a page is cut.
type kind uint8

const (
	kDefault   kind = iota // access or ssh moved between absent, empty and non-empty
	kAtoms                 // a group of access atoms
	kEntry                 // a keyed entry, a set element, an unknown section
	kAttr                  // a node attribute entry
	kAssertion             // an assertion of a test
	kWide                  // a widening finding
	kSection               // a section whose value changed type
)

// rawChange is a change before it is cut for a page: pointers into the two normal forms and
// no text, small enough that hundreds of thousands of them fit.
type rawChange struct {
	class, op uint8
	kind      kind
	bits      uint8 // kAtoms: the origins of the atoms (originACLs, originGrants)
	rank      int   // the position of the section in the listing
	seq       int
	sort      string // orders the changes of one section: the identity of what changed
	sec       *nfSec
	oe, ne    *nfEntry
	oa, na    []*atom
	x         *rawExtra // what only a few kinds of change carry
}

type rawExtra struct {
	sec, key string
	keyAtom  *atom // kWide: the atom whose destination ends the key, shown with the new policy

	oldText, newText string
	note             string
	fields           []FieldDelta
	atomTexts        bool // kWide: the texts are the atoms'
	osec, nsec       *nfSec
}

func (c *rawChange) known() bool {
	switch c.kind {
	case kDefault, kAtoms, kWide:
		return true
	}
	return c.sec.known
}

// secName is the section a change is listed under.
func (c *rawChange) secName() string {
	switch c.kind {
	case kAtoms:
		switch c.bits {
		case originACLs:
			return "acls"
		case originGrants:
			return "grants"
		}
		return "acls+grants"
	case kDefault, kWide:
		return c.x.sec
	}
	return c.sec.name
}

// displayKey names what a change is about, cut at 1 KiB after the policy it is read from shows
// it.
func (d *comparer) displayKey(c *rawChange) string {
	e := c.ne
	if e == nil {
		e = c.oe
	}
	v := d.viewOf(c)
	switch c.kind {
	case kAtoms:
		if len(c.na) > 0 {
			return atomKey(d.nv, c.na[0])
		}
		return atomKey(d.ov, c.oa[0])
	case kDefault:
		return c.x.key
	case kWide:
		if c.x.keyAtom != nil {
			return capText(c.x.key + atomKey(d.nv, c.x.keyAtom))
		}
		return c.x.key
	case kAssertion:
		return v.assertionKey(e.key)
	case kAttr:
		return attrKey(v, e)
	case kEntry:
		if c.sec.known {
			return v.cut(e.key)
		}
	}
	return ""
}

type comparer struct {
	m      *meter
	oa, ob *Doc
	// ov and nv are the two policies as the caller sees them: what a result quotes of a side is
	// cut after its Show has run.
	ov, nv view
	na, nb *NormalForm
	raw    []rawChange
	format int // format-only differences found on the way
	base   [sha256.Size]byte
	based  bool
}

// Diff compares two parsed policies. It normalises both, so a rewrite that means the same
// (whitespace, comments, key order and case, acls or grants, a rule split or merged) is no
// change, and everything the normaliser cannot prove equal is. It spends the work budget,
// honours ctx and returns too_complex rather than an answer that is cut short.
func Diff(ctx context.Context, oldDoc, newDoc *Doc, o DiffOptions) (*DiffResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkDoc(oldDoc); err != nil {
		return nil, err
	}
	if err := checkDoc(newDoc); err != nil {
		return nil, err
	}
	section, err := sectionFilter(o.Section)
	if err != nil {
		return nil, err
	}
	cur, err := parseCursor(o.Cursor)
	if err != nil {
		return nil, err
	}
	m := newMeter(ctx)
	na, err := normaliseWith(m, oldDoc)
	if err != nil {
		return nil, err
	}
	nb, err := normaliseWith(m, newDoc)
	if err != nil {
		return nil, err
	}
	d := &comparer{m: m, oa: oldDoc, ob: newDoc, na: na, nb: nb, ov: view{oldDoc, o.OldShow}, nv: view{newDoc, o.NewShow}}
	if err := d.compare(); err != nil {
		return nil, err
	}
	if err := d.sortChanges(); err != nil {
		return nil, err
	}
	res := &DiffResult{NotChecked: slices.Clone(NotChecked), TailscaleWrittenAsOf: TailscaleWrittenAsOf}
	tests, sshTests := sectionPos("tests"), sectionPos("sshTests")
	res.TestsBefore, res.TestsAfter = assertionCount(na.secs[tests]), assertionCount(nb.secs[tests])
	res.SSHTestsBefore, res.SSHTestsAfter = assertionCount(na.secs[sshTests]), assertionCount(nb.secs[sshTests])
	limited := false
	for i := range d.raw {
		c := &d.raw[i]
		switch c.class {
		case cDefaults:
			res.Counts.Defaults++
		case cTestsReduced:
			res.Counts.TestsReduced++
		case cWidening:
			res.Counts.Widening++
		case cWritten:
			res.Counts.TailscaleWritten++
		case cSemantic:
			res.Counts.Semantic++
		}
		if (c.kind == kAtoms || c.kind == kAttr) && (c.class == cSemantic || c.class == cWritten) {
			limited = true
		}
	}
	if err := m.tick(len(d.raw)); err != nil {
		return nil, err
	}
	res.SemanticallyEqual = len(d.raw) == 0
	res.Equal = len(d.raw) == res.Counts.TailscaleWritten && (o.IgnoreTailscaleWritten || res.Counts.TailscaleWritten == 0)
	if limited {
		res.NormalFormLimits = []string{normalFormLimit}
	}
	if err := d.formatCounts(res); err != nil {
		return nil, err
	}
	if err := d.page(res, o, section, cur); err != nil {
		return nil, err
	}
	if err := m.tick(0); err != nil {
		return nil, err
	}
	res.Ops = m.used
	return res, nil
}

// assertionCount is the number of tests a section holds, in elements; a value of the wrong
// type holds none.
func assertionCount(s *nfSec) int {
	if s.whole {
		return 0
	}
	return s.count
}

// sectionFilter validates a section filter: a known name in any case, "unknown", or "".
func sectionFilter(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	if strings.EqualFold(name, "unknown") {
		return "unknown", nil
	}
	if s, ok := SectionByName(name); ok {
		return s.Name, nil
	}
	return "", invalid(0, 0, "%q is not a section of the policy file; use a section name, or \"unknown\" for the sections tailkeeper does not know", capText(name))
}

func (d *comparer) emit(c rawChange) {
	c.seq = len(d.raw)
	d.raw = append(d.raw, c)
}

// compare finds every difference, in no particular order.
func (d *comparer) compare() error {
	d.defaults()
	if err := d.atoms(); err != nil {
		return err
	}
	d.writtenSwap()
	for i := range sections {
		if err := d.section(d.na.secs[i], d.nb.secs[i], i); err != nil {
			return err
		}
	}
	if err := d.unknown(); err != nil {
		return err
	}
	return d.widening()
}

// section compares one known section on the two sides.
//
// A section that holds a value of the wrong type is one opaque entry, under the key "", and a
// real entry of a map can be named "" too. The two are never paired: when only one side is
// opaque the section is a change of its own, and when both are the values are compared.
func (d *comparer) section(sa, sb *nfSec, rank int) error {
	if sa.whole != sb.whole {
		d.wholeMismatch(sa, sb, rank)
		return nil
	}
	if !sa.whole {
		switch sa.sec.Shape {
		case ShapeTests:
			return d.assertions(sa, sb, rank)
		case ShapeNodeAttrs:
			return d.attrs(sa, sb, rank)
		}
	}
	return d.entries(sa, sb, rank)
}

func (d *comparer) wholeMismatch(sa, sb *nfSec, rank int) {
	c := rawChange{class: cSemantic, kind: kSection, rank: rank, sort: "", sec: sb,
		x: &rawExtra{osec: sa, nsec: sb, note: wholeMismatchNote}}
	switch {
	case sa.state == StateAbsent:
		c.op = oAdded
	case sb.state == StateAbsent:
		c.op = oRemoved
	default:
		c.op = oChanged
	}
	// Tests that were assertions and are now a value no test can be read from are a reduction.
	if sa.known && sa.sec.Shape == ShapeTests && !sa.whole && len(sa.entries) > 0 {
		c.class = cTestsReduced
	}
	d.emit(c)
}

// wholeMismatchNote qualifies a section that holds a value of another type on one side.
const wholeMismatchNote = "one side holds a value of another type than the server reads for this section; it is kept whole and compared as one value"

// tagOwnersNote qualifies the move of tagOwners between [] and the admin group.
const tagOwnersNote = "tagOwners [] is documented as equivalent to [\"autogroup:admin\"]; it is reported, not equated"

func stateText(s State, n int) string {
	switch s {
	case StateAbsent:
		return "absent"
	case StateEmpty:
		return "empty"
	}
	return strconv.Itoa(n)
}

// defaultsNote is what a move of the access rules between absent and empty means. Probe A-1
// (20 Oct 2026) measured acls absent (allow-all), acls [] (deny-all) and grants [] with no
// acls (deny-all); a non-empty grants section with no acls was not measured.
const defaultsNote = "an absent acls section is the default allow-all, and an empty acls or grants section is deny-all (measured against the live API, 20 Oct 2026); whether a non-empty grants section alone cancels the default allow-all was not measured, so the move is reported"

// defaults reports the access rules and ssh moving between absent, empty and non-empty. The
// access rules are read together (acls and grants are one pool), and then each section on its
// own where the pool did not move: one section written as [] where it was absent, or the
// other way round, is a change whatever the other holds.
func (d *comparer) defaults() {
	if a, b := d.na.AccessState(), d.nb.AccessState(); a != b {
		d.emit(rawChange{class: cDefaults, op: oChanged, kind: kDefault, sort: "access",
			x: &rawExtra{sec: "acls+grants", key: "acls+grants",
				oldText: stateText(a, len(d.na.atoms)), newText: stateText(b, len(d.nb.atoms)),
				note: defaultsNote}})
	} else {
		oldAcls, oldGrants := d.na.writtenEmpty()
		newAcls, newGrants := d.nb.writtenEmpty()
		for _, s := range []struct {
			name     string
			was, now bool
		}{{"acls", oldAcls, newAcls}, {"grants", oldGrants, newGrants}} {
			if s.was == s.now {
				continue
			}
			pos := sectionPos(s.name)
			sa, sb := d.na.secs[pos], d.nb.secs[pos]
			d.emit(rawChange{class: cDefaults, op: oChanged, kind: kDefault, rank: pos, sort: s.name,
				x: &rawExtra{sec: s.name, key: s.name, oldText: stateText(sa.state, sa.count), newText: stateText(sb.state, sb.count),
					note: accessSectionNote(s.name, s.now)}})
		}
	}
	pos := sectionPos("ssh")
	sa, sb := d.na.secs[pos], d.nb.secs[pos]
	if sa.state != sb.state {
		d.emit(rawChange{class: cDefaults, op: oChanged, kind: kDefault, rank: pos, sort: "ssh",
			x: &rawExtra{sec: "ssh", key: "ssh", oldText: stateText(sa.state, sa.count), newText: stateText(sb.state, sb.count),
				note: sshNote(sa.state, sb.state)}})
	}
}

// accessSectionNote says which way an access section, acls or grants, moved: to [] or away
// from it.
func accessSectionNote(section string, empty bool) string {
	if empty {
		return section + " is now written as []: " + defaultsNote
	}
	return section + " is no longer written as []: " + defaultsNote
}

// sshNote says what a move of the ssh section between absent, empty and non-empty is. Only
// the moves that leave no SSH rule are said to turn Tailscale SSH off.
func sshNote(from, to State) string {
	switch {
	case from == StateAbsent && to == StateEmpty:
		return "the ssh section now exists and is empty: it defines no SSH rule"
	case from == StateEmpty && to == StateAbsent:
		return "the empty ssh section was removed: it defined no SSH rule"
	case from == StateEmpty:
		return "SSH rules were added to the empty ssh section"
	case from == StateAbsent:
		return "the ssh section was added: it defines SSH rules"
	case to == StateEmpty:
		return "every SSH rule was removed: an empty ssh section turns Tailscale SSH off"
	}
	return "removing the ssh section turns Tailscale SSH off"
}

// comparePos orders two atoms of one group.
func comparePos(a, b *atom) int {
	if c := strings.Compare(a.pkey, b.pkey); c != 0 {
		return c
	}
	return strings.Compare(a.src.id, b.src.id)
}

// atoms compares the pools of atoms: both are sorted by their qualifiers, so groups of
// atoms with the same qualifiers are found by walking the two lists together. Each atom is
// looked at a constant number of times; the strings compared were paid for when they were
// built.
func (d *comparer) atoms() error {
	oa, ob := d.na.atoms, d.nb.atoms
	i, j := 0, 0
	for i < len(oa) || j < len(ob) {
		if err := d.m.tick(1); err != nil {
			return err
		}
		var rest string
		switch {
		case i >= len(oa):
			rest = ob[j].rest
		case j >= len(ob):
			rest = oa[i].rest
		default:
			rest = min(oa[i].rest, ob[j].rest)
		}
		i2, j2 := i, j
		for i2 < len(oa) && oa[i2].rest == rest {
			i2++
		}
		for j2 < len(ob) && ob[j2].rest == rest {
			j2++
		}
		d.group(oa[i:i2], ob[j:j2])
		i, j = i2, j2
	}
	return nil
}

// group compares the atoms of one qualifier set on the two sides.
func (d *comparer) group(og, ng []*atom) {
	var onlyOld, onlyNew []*atom
	i, j := 0, 0
	for i < len(og) && j < len(ng) {
		d.m.used++
		switch c := comparePos(og[i], ng[j]); {
		case c == 0:
			i++
			j++
		case c < 0:
			onlyOld = append(onlyOld, og[i])
			i++
		default:
			onlyNew = append(onlyNew, ng[j])
			j++
		}
	}
	onlyOld = append(onlyOld, og[i:]...)
	onlyNew = append(onlyNew, ng[j:]...)
	switch {
	case len(onlyOld) == 0 && len(onlyNew) == 0:
	case len(onlyOld) > 0 && len(onlyNew) > 0:
		// A rule edited in place is somebody's change, even if it is the shape Tailscale
		// writes: only the whole rule coming or going can be Tailscale's.
		d.emit(rawChange{class: cSemantic, op: oChanged, kind: kAtoms, bits: atomOrigins(onlyOld, onlyNew),
			sort: onlyNew[0].rest, oa: onlyOld, na: onlyNew})
	case len(onlyOld) > 0:
		for _, a := range onlyOld {
			d.emit(rawChange{class: atomClass([]*atom{a}, nil), op: oRemoved, kind: kAtoms, bits: a.origin, sort: a.rest, oa: []*atom{a}})
		}
	default:
		for _, a := range onlyNew {
			d.emit(rawChange{class: atomClass(nil, []*atom{a}), op: oAdded, kind: kAtoms, bits: a.origin, sort: a.rest, na: []*atom{a}})
		}
	}
}

// writtenSwap takes the log-stream shape off a rule that was removed while another of that
// shape was added: Tailscale writes the rule or removes it, it does not replace one by
// another, so that is an edit (a new destination, say) and an ordinary change.
func (d *comparer) writtenSwap() {
	removed, added := false, false
	for i := range d.raw {
		if c := &d.raw[i]; c.kind == kAtoms && c.class == cWritten {
			removed = removed || c.op == oRemoved
			added = added || c.op == oAdded
		}
	}
	if !removed || !added {
		return
	}
	for i := range d.raw {
		if c := &d.raw[i]; c.kind == kAtoms && c.class == cWritten {
			c.class = cSemantic
		}
	}
}

// atomClass is the class of a change to atoms: Tailscale-written only if every atom on both
// sides is.
func atomClass(a, b []*atom) uint8 {
	for _, as := range [][]*atom{a, b} {
		for _, x := range as {
			if !atomWritten(x) {
				return cSemantic
			}
		}
	}
	return cWritten
}

func atomOrigins(a, b []*atom) uint8 {
	var bits uint8
	for _, as := range [][]*atom{a, b} {
		for _, x := range as {
			bits |= x.origin
		}
	}
	return bits
}

// entries compares the entries of two sections of the same name, which are sorted by key.
// Both sections hold what their shape says, or both hold one opaque value.
func (d *comparer) entries(sa, sb *nfSec, rank int) error {
	oe, ne := sa.entries, sb.entries
	i, j := 0, 0
	for i < len(oe) || j < len(ne) {
		if err := d.m.tick(1); err != nil {
			return err
		}
		switch {
		case j >= len(ne) || i < len(oe) && oe[i].key < ne[j].key:
			d.entryChange(sa, rank, oRemoved, &oe[i], nil)
			i++
		case i >= len(oe) || ne[j].key < oe[i].key:
			d.entryChange(sb, rank, oAdded, nil, &ne[j])
			j++
		default:
			o, n := &oe[i], &ne[j]
			switch {
			case o.val != n.val:
				d.entryChange(sb, rank, oChanged, o, n)
			case n.n > o.n:
				d.entryChange(sb, rank, oAdded, o, n)
			case n.n < o.n:
				d.entryChange(sb, rank, oRemoved, o, n)
			}
			i++
			j++
		}
	}
	return nil
}

func (d *comparer) entryChange(s *nfSec, rank int, op uint8, o, n *nfEntry) {
	e := n
	if e == nil {
		e = o
	}
	d.emit(rawChange{class: cSemantic, op: op, kind: kEntry, rank: rank, sort: e.key, sec: s, oe: o, ne: n})
}

// assertions compares tests and sshTests: a removed assertion is a reduction, an added one
// is an ordinary change.
func (d *comparer) assertions(sa, sb *nfSec, rank int) error {
	oe, ne := sa.entries, sb.entries
	i, j := 0, 0
	emit := func(op uint8, o, n *nfEntry) {
		class := cSemantic
		if op == oRemoved {
			class = cTestsReduced
		}
		e := n
		if e == nil {
			e = o
		}
		d.emit(rawChange{class: class, op: op, kind: kAssertion, rank: rank, sort: e.key, sec: sa, oe: o, ne: n})
	}
	for i < len(oe) || j < len(ne) {
		if err := d.m.tick(1); err != nil {
			return err
		}
		switch {
		case j >= len(ne) || i < len(oe) && oe[i].key < ne[j].key:
			emit(oRemoved, &oe[i], nil)
			i++
		case i >= len(oe) || ne[j].key < oe[i].key:
			emit(oAdded, nil, &ne[j])
			j++
		default:
			switch o, n := &oe[i], &ne[j]; {
			case n.n > o.n:
				emit(oAdded, o, n)
			case n.n < o.n:
				emit(oRemoved, o, n)
			}
			i++
			j++
		}
	}
	return nil
}

// attrs compares nodeAttrs: entries with the same attribute and qualifiers are compared by
// their targets.
func (d *comparer) attrs(sa, sb *nfSec, rank int) error {
	oe, ne := sa.entries, sb.entries
	i, j := 0, 0
	for i < len(oe) || j < len(ne) {
		if err := d.m.tick(1); err != nil {
			return err
		}
		switch {
		case j >= len(ne) || i < len(oe) && oe[i].key < ne[j].key:
			d.attrChange(sa, rank, oRemoved, &oe[i], nil)
			i++
		case i >= len(oe) || ne[j].key < oe[i].key:
			d.attrChange(sb, rank, oAdded, nil, &ne[j])
			j++
		default:
			if oe[i].targets.id != ne[j].targets.id {
				d.attrChange(sb, rank, oChanged, &oe[i], &ne[j])
			}
			i++
			j++
		}
	}
	return nil
}

func (d *comparer) attrChange(s *nfSec, rank int, op uint8, o, n *nfEntry) {
	e := n
	if e == nil {
		e = o
	}
	class := cSemantic
	if (o == nil || o.written) && (n == nil || n.written) {
		class = cWritten
	}
	d.emit(rawChange{class: class, op: op, kind: kAttr, rank: rank, sort: e.key, sec: s, oe: o, ne: n})
}

// unknown compares the sections the table does not know, which are sorted by name. Each is
// one opaque value.
func (d *comparer) unknown() error {
	oa, ob := d.na.secs[len(sections):], d.nb.secs[len(sections):]
	i, j := 0, 0
	rank := len(sections)
	for i < len(oa) || j < len(ob) {
		if err := d.m.tick(1); err != nil {
			return err
		}
		rank++
		switch {
		case j >= len(ob) || i < len(oa) && oa[i].fold < ob[j].fold:
			d.entryChange(oa[i], rank, oRemoved, &oa[i].entries[0], nil)
			i++
		case i >= len(oa) || ob[j].fold < oa[i].fold:
			d.entryChange(ob[j], rank, oAdded, nil, &ob[j].entries[0])
			j++
		default:
			if oa[i].spelled != ob[j].spelled {
				d.format++ // the name is spelled in another case
			}
			if err := d.entries(oa[i], ob[j], rank); err != nil {
				return err
			}
			i++
			j++
		}
	}
	return nil
}

// sortChanges orders the changes: by class, section, operation and key, and where those are
// equal in the order they were found.
func (d *comparer) sortChanges() error {
	sort.Slice(d.raw, func(i, j int) bool {
		d.m.used++
		a, b := &d.raw[i], &d.raw[j]
		if a.class != b.class {
			return a.class < b.class
		}
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		if a.op != b.op {
			return a.op < b.op
		}
		if a.sort != b.sort {
			return a.sort < b.sort
		}
		return a.seq < b.seq
	})
	return d.m.tick(0)
}

// formatCounts fills the comment and format counts, which are never entries.
func (d *comparer) formatCounts(res *DiffResult) error {
	oldScan, err := scanText(d.m, d.oa.src)
	if err != nil {
		return err
	}
	newScan, err := scanText(d.m, d.ob.src)
	if err != nil {
		return err
	}
	if err := d.m.tick(len(oldScan.comments) + len(newScan.comments)); err != nil {
		return err
	}
	res.Counts.CommentOnly = commentDifference(oldScan.comments, newScan.comments)
	f := d.format
	for i := range sections {
		sa, sb := d.na.secs[i], d.nb.secs[i]
		if sa.state != StateAbsent && sb.state != StateAbsent && sa.spelled != sb.spelled {
			f++ // the name is spelled in another case
		}
		if sa.null != sb.null && sa.state == StateAbsent && sb.state == StateAbsent {
			f++ // absent against null
		}
		switch sa.sec.Shape {
		case ShapeRules, ShapeSet, ShapeTests, ShapeNodeAttrs:
		default:
			continue
		}
		if !sa.whole && !sb.whole && sa.count == sb.count {
			same, err := pureReorder(d.m, sa.seq, sb.seq)
			if err != nil {
				return err
			}
			if same {
				f++
			}
		}
	}
	if oldScan.layout != newScan.layout {
		f++
	}
	res.Counts.FormatOnly = f
	return d.m.tick(0)
}

// pureReorder reports whether two sequences hold the same hashes in a different order.
func pureReorder(m *meter, a, b []uint64) (bool, error) {
	if len(a) != len(b) || len(a) < 2 {
		return false, nil
	}
	if err := m.tick(len(a) + len(b)); err != nil {
		return false, err
	}
	same := true
	for i := range a {
		if a[i] != b[i] {
			same = false
			break
		}
	}
	if same {
		return false, nil
	}
	x, y := slices.Clone(a), slices.Clone(b)
	for _, s := range [][]uint64{x, y} {
		sort.Slice(s, func(i, j int) bool { m.used++; return s[i] < s[j] })
	}
	if err := m.tick(0); err != nil {
		return false, err
	}
	return slices.Equal(x, y), nil
}

// cursor is "c1.<index>.<digest>": the digest ties it to the pair and the options, so a
// cursor from another comparison is refused instead of listing the wrong changes. The digest is
// of the normal forms as each side shows them (DiffOptions), and keyed when it has a Seal: a
// cursor identifies the comparison as a reader of the result sees it, and tells nothing that
// the result does not (two policies whose logins differ and are shown alike share a cursor
// unless a key names them apart).
type cursor struct {
	idx int
	sum string
}

func badCursor() *Error {
	return invalid(0, 0, "the cursor does not belong to this comparison: use the nextChange of a result for the same two policies and options")
}

// parseCursor reads the shape of a cursor; whether it belongs to the comparison is for the
// digest to say.
func parseCursor(s string) (*cursor, error) {
	if s == "" {
		return nil, nil
	}
	rest, ok := strings.CutPrefix(s, "c1.")
	idxText, sum, found := strings.Cut(rest, ".")
	idx, err := strconv.Atoi(idxText)
	if !ok || !found || err != nil || idx < 0 || strconv.Itoa(idx) != idxText || len(sum) != 16 {
		return nil, badCursor()
	}
	return &cursor{idx: idx, sum: sum}, nil
}

// meterWriter hashes what is written to it and pays for its bytes.
type meterWriter struct {
	h   io.Writer
	m   *meter
	err error
}

func (w *meterWriter) Write(p []byte) (int, error) {
	if w.err == nil {
		w.err = w.m.tick(len(p))
	}
	if w.err != nil {
		return 0, w.err
	}
	return w.h.Write(p)
}

// digest is the part of a cursor that ties it to this comparison: a hash of the canonical
// bytes of both normal forms as the two sides show them, the section filter and whether the
// Tailscale-written changes are left out, sealed when the options say how. The page size is not
// in it, so a cursor works for any size. Reading the normal forms is paid for by their bytes,
// once per call.
func (d *comparer) digest(o DiffOptions, section string) (string, error) {
	if !d.based {
		h := sha256.New()
		w := &meterWriter{h: h, m: d.m}
		if _, err := d.na.writeShown(w, d.ov.show); err != nil {
			return "", err
		}
		_, _ = w.Write([]byte{0})
		if _, err := d.nb.writeShown(w, d.nv.show); err != nil {
			return "", err
		}
		if w.err != nil {
			return "", w.err
		}
		h.Sum(d.base[:0])
		d.based = true
	}
	h := sha256.New()
	_, _ = h.Write(d.base[:])
	_, _ = h.Write([]byte(section))
	if o.IgnoreTailscaleWritten {
		_, _ = h.Write([]byte{1})
	}
	sum := h.Sum(nil)
	if o.Seal != nil {
		keyed := sha256.Sum256([]byte(o.Seal(sum)))
		sum = keyed[:]
	}
	return hex.EncodeToString(sum)[:16], nil
}

// match reports whether the options select a change.
func (c *rawChange) match(section string, ignore bool) bool {
	if ignore && c.class == cWritten {
		return false
	}
	if section == "" {
		return true
	}
	if c.rank >= len(sections) {
		return section == "unknown"
	}
	if section == "unknown" {
		return false
	}
	// "acls" and "grants" match the access rules that are in both.
	name := c.secName()
	return name == section || name == "acls+grants" && (section == "acls" || section == "grants")
}

// page cuts the list the options select: it counts what is selected, checks the cursor,
// and writes the changes from the cursor on until the page is full.
func (d *comparer) page(res *DiffResult, o DiffOptions, section string, cur *cursor) error {
	if err := d.m.tick(len(d.raw)); err != nil {
		return err
	}
	for i := range d.raw {
		if d.raw[i].match(section, o.IgnoreTailscaleWritten) {
			res.Matched++
		}
	}
	if res.Matched > 0 {
		// Placing a change reads the table of line ends of each text, which is built on first
		// use and costs about what the text does.
		if err := d.m.tick(len(d.oa.src)/8 + len(d.ob.src)/8 + 2); err != nil {
			return err
		}
	}
	start := 0
	if cur != nil {
		if cur.idx > res.Matched {
			return badCursor()
		}
		sum, err := d.digest(o, section)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(sum), []byte(cur.sum)) != 1 {
			return badCursor()
		}
		start = cur.idx
	}
	size := o.PageSize
	if size <= 0 {
		size = DefaultPage
	}
	size = min(size, MaxPage)
	used, idx, next := 0, 0, -1
	for i := range d.raw {
		c := &d.raw[i]
		if !c.match(section, o.IgnoreTailscaleWritten) {
			continue
		}
		if idx >= start {
			if len(res.Changes) >= size || used >= pageCost {
				next = idx
				break
			}
			ch, err := d.materialise(c)
			if err != nil {
				return err
			}
			used += changeCost(&ch)
			res.Changes = append(res.Changes, ch)
		}
		idx++
	}
	if next >= 0 {
		sum, err := d.digest(o, section)
		if err != nil {
			return err
		}
		res.Truncated = true
		res.NextChange = "c1." + strconv.Itoa(next) + "." + sum
	}
	return nil
}

// DisplayCost is the most characters a string takes in a result once a host has it as JSON text,
// counted per byte: an angle bracket or an ampersand is written as a six-character escape, a
// control character is shown as an eight-character escape of its own whose backslash JSON
// doubles, a quote or a backslash takes two, and a byte of a multi-byte character is counted as
// two (a character that JSON escapes takes six for its three bytes). It is an upper bound, and
// the measure by which a page and a list are cut.
func DisplayCost(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '<' || c == '>' || c == '&':
			n += 6
		case c == '"' || c == '\\':
			n += 2
		case c < 0x20 || c == 0x7f:
			n += 9
		case c >= 0x80:
			n += 2
		default:
			n++
		}
	}
	return n
}

// changeCost is what a change adds to a page, by DisplayCost.
func changeCost(c *Change) int {
	n := 200 + DisplayCost(c.Old.Text) + DisplayCost(c.New.Text) + DisplayCost(c.Key) + DisplayCost(c.Note) +
		DisplayCost(c.Section) + DisplayCost(c.OldPointer) + DisplayCost(c.NewPointer)
	for _, f := range c.Fields {
		n += 60 + DisplayCost(f.Field)
		for _, l := range [][]string{f.Added, f.Removed} {
			for _, s := range l {
				n += DisplayCost(s) + 3
			}
		}
	}
	return n
}
