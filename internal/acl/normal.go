package acl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"hash/fnv"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/tailscale/hujson"
)

// MaxAtoms is the most atoms one normal form may hold: the access rules expand over their
// destinations and protocols, and a rule can be built to expand far past its size. Past it
// Normalise returns too_complex, never a truncated normal form that would read as "no change".
const MaxAtoms = 1 << 18

// State is whether a section is in the text and whether it holds anything. A section spelled
// null is absent: Go decodes null and a missing key to the same nil.
type State uint8

const (
	StateAbsent   State = iota // not in the text, or null
	StateEmpty                 // [] or {}
	StateNonEmpty              // holds elements, entries or a value
)

func (s State) String() string {
	switch s {
	case StateAbsent:
		return "absent"
	case StateEmpty:
		return "empty"
	}
	return "non-empty"
}

// ref is where something came from in the text: the value to take a line from, the
// top-level member it lies under, and the rest of its JSON Pointer.
type ref struct {
	val  *hujson.Value
	top  int    // index into Doc.top; -1 when unknown
	idx  int    // array index, or -1
	tail string // an escaped pointer suffix such as "/routes/192.0.2.0~124", or ""
	// named: val is the name of an object member, and the pointer ends with that name.
	named bool
}

// nfSec is one section of a normal form.
type nfSec struct {
	name    string
	known   bool
	sec     Section
	state   State
	null    bool // the section is spelled null
	whole   bool // the section holds a value of the wrong type, kept as one value
	count   int  // elements of an array, entries of an object, 1 for a scalar
	spelled string
	fold    string    // sectionKey(name), made once: an unknown section is sorted and paired by it
	entries []nfEntry // sorted by key
	seq     []uint64  // hash of each element, in document order (arrays only)
	top     int       // index into Doc.top of the occurrence that was read, or -1
}

// nfEntry is one keyed entry, set element or assertion of a section.
type nfEntry struct {
	key string // identity: a map key, a canonical element, an assertion
	val string // the canonical value, for keyed entries
	n   int    // how many times it appears
	ref ref
	// ssh rules only
	rest   string // the canonical rule without its action
	action string
	root   bool // the rule lets someone in as root
	// nodeAttrs only
	targets *idSet
	written bool // a construct Tailscale writes itself
	// ssh rules only: the sources, destinations and users as sets, nil when not a list of
	// strings (the rule is then kept whole and nothing is known of them)
	sshSrc, sshDst, sshUsers *idSet
}

// NormalForm is a policy reduced to what the server enforces: access rules as atoms,
// tests as assertions, entries keyed, and every field kept. Two policies with equal normal
// forms mean the same to the server; a pair the reduction cannot prove equal is "changed".
type NormalForm struct {
	secs  []*nfSec
	atoms []*atom
	sets  *setTable
	ops   int64 // work spent building it, for the operation-count guard
}

// Normalise reduces d to its normal form. It spends the work budget and honours ctx.
func Normalise(ctx context.Context, d *Doc) (*NormalForm, error) {
	if err := checkDoc(d); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return normaliseWith(newMeter(ctx), d)
}

func checkDoc(d *Doc) error {
	if d == nil || d.root.Value == nil {
		return invalid(0, 0, "there is no parsed policy to normalise: build one with Parse")
	}
	return nil
}

// normaliseWith is Normalise on a meter the caller shares with other work, so that one
// call's budget covers all of it.
func normaliseWith(m *meter, d *Doc) (*NormalForm, error) {
	if err := checkDoc(d); err != nil {
		return nil, err
	}
	start := m.used
	b := &nfBuilder{d: d, m: m, nf: &NormalForm{sets: newSetTable()}}
	if err := b.build(); err != nil {
		return nil, err
	}
	b.nf.ops = m.used - start
	return b.nf, nil
}

type nfBuilder struct {
	d  *Doc
	m  *meter
	nf *NormalForm
	ab *atomBuilder
}

func (b *nfBuilder) build() error {
	b.ab = newAtomBuilder(b.m, b.nf.sets)
	for i := range sections {
		sec := sections[i]
		occ := b.d.byKey[sectionKey(sec.Name)]
		s, err := b.section(sec, occ)
		if err != nil {
			return err
		}
		b.nf.secs = append(b.nf.secs, s)
	}
	// Sections nothing knows are compared as whole canonical values, in first-seen order.
	seen := map[string]bool{}
	for i := range b.d.top {
		k := sectionKey(b.d.top[i].name)
		if _, known := sectionIndex[k]; known || seen[k] {
			continue
		}
		seen[k] = true
		s, err := b.unknown(b.d.top[i].name, b.d.byKey[k])
		if err != nil {
			return err
		}
		// The key is made once and paid for by its bytes: a sort or a merge that made it on
		// every comparison would copy a name of a megabyte for each section it is held against.
		s.fold = k
		if err := b.m.tick(len(k)); err != nil {
			return err
		}
		if s.null {
			continue // null is the same as absent
		}
		b.nf.secs = append(b.nf.secs, s)
	}
	// Unknown sections come after the known ones, ordered by name, so two texts that write
	// them in a different order have one normal form.
	unknown := b.nf.secs[len(sections):]
	sort.Slice(unknown, func(i, j int) bool {
		b.m.used++
		return unknown[i].fold < unknown[j].fold
	})
	if err := b.m.tick(0); err != nil {
		return err
	}
	atoms, err := b.ab.finish()
	if err != nil {
		return err
	}
	b.nf.atoms = atoms
	return nil
}

// layersOf returns the values written for a section, in document order.
func (b *nfBuilder) layersOf(occ []int) []*hujson.Value {
	layers := make([]*hujson.Value, len(occ))
	for i, o := range occ {
		layers[i] = b.d.top[o].val
	}
	return layers
}

// section reads one known section.
func (b *nfBuilder) section(sec Section, occ []int) (*nfSec, error) {
	s := &nfSec{name: sec.Name, known: true, sec: sec, top: -1}
	if len(occ) == 0 {
		return s, nil
	}
	last := occ[len(occ)-1]
	s.top = last
	s.spelled = b.d.top[last].name
	layers := b.layersOf(occ)
	lv := layers[len(layers)-1]
	if lit, ok := lv.Value.(hujson.Literal); ok && lit.Kind() == 'n' {
		s.null = true
		return s, nil
	}
	switch sec.Shape {
	case ShapeRules:
		return s, b.rules(s, sec, lv, last)
	case ShapeSet:
		return s, b.setArray(s, sec, lv, last)
	case ShapeTests:
		return s, b.tests(s, sec, lv, last)
	case ShapeNodeAttrs:
		return s, b.nodeAttrs(s, lv, last)
	case ShapeMap:
		return s, b.keyedMap(s, sec, layers, occ)
	case ShapeStruct:
		return s, b.structFields(s, sec, layers, occ)
	case ShapeList:
		return s, b.list(s, lv, last)
	}
	return s, b.scalar(s, lv, last)
}

// opaque reads a section whose value is not the type the server expects (an object where
// an array belongs): it is one canonical value, so a change to it is a change.
func (b *nfBuilder) opaque(s *nfSec, layers []*hujson.Value, top int) error {
	text, err := appendCanon(b.m, nil, layers, canonOpts{})
	if err != nil {
		return err
	}
	s.state, s.count, s.whole = StateNonEmpty, 1, true
	s.entries = []nfEntry{{key: "", val: string(text), n: 1, ref: ref{val: layers[len(layers)-1], top: top, idx: -1}}}
	return nil
}

// unknown reads a top-level section the table does not know.
func (b *nfBuilder) unknown(name string, occ []int) (*nfSec, error) {
	s := &nfSec{name: name, top: occ[len(occ)-1], spelled: b.d.top[occ[len(occ)-1]].name}
	layers := b.layersOf(occ)
	if lit, ok := layers[len(layers)-1].Value.(hujson.Literal); ok && lit.Kind() == 'n' {
		s.null = true
		return s, nil
	}
	return s, b.opaque(s, layers, s.top)
}

// fnv64 hashes a canonical text, to compare the order of two arrays.
func fnv64(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

// idSet is a set of strings that is written once however many atoms share it. Its id is a
// digest of its items with their lengths, so two sets have one id only if they are equal.
type idSet struct {
	id    string
	items []string // sorted, without repeats
	// wide has a bit for each selector that widens access when it is added to a source or
	// a destination (wideStar, wideInternet, wideMember).
	wide uint8
	// written: the set is exactly the source of the rule Tailscale writes for private log
	// streaming. A set that holds it beside other sources is somebody's own rule.
	written bool
	// quoted is the length of the items written as a JSON list body: each quoted, with a
	// comma between. A result that shows a cut of the set reports it.
	quoted int
}

const (
	wideStar uint8 = 1 << iota
	wideInternet
	wideMember
)

// wideBit is the bit of a selector that widens access, or 0.
func wideBit(sel string) uint8 {
	switch canonSelector(sel) {
	case "*":
		return wideStar
	case "autogroup:internet":
		return wideInternet
	case "autogroup:member":
		return wideMember
	}
	return 0
}

type setTable struct {
	byID   map[string]*idSet
	unions map[string]*idSet
}

func newSetTable() *setTable {
	return &setTable{byID: map[string]*idSet{}, unions: map[string]*idSet{}}
}

// intern returns the shared set for items, which must be sorted and without repeats.
func (t *setTable) intern(m *meter, items []string) (*idSet, error) {
	// A set is paid for by its bytes, before they are hashed: the text of a set is hashed and
	// stored once for each distinct set, and written once by WriteTo, so what WriteTo writes
	// of the sets is bounded by what was spent here. A large item in many distinct unions is
	// paid for in each.
	cost := len(items) + 1
	for _, it := range items {
		cost += len(it)
	}
	if err := m.tick(cost); err != nil {
		return nil, err
	}
	h := sha256.New()
	var n [20]byte
	for _, it := range items {
		_, _ = h.Write(strconv.AppendInt(n[:0], int64(len(it)), 10))
		_, _ = h.Write([]byte{':'})
		_, _ = io.WriteString(h, it)
	}
	id := hex.EncodeToString(h.Sum(nil))
	if s, ok := t.byID[id]; ok {
		return s, nil
	}
	s := &idSet{id: id, items: items, written: len(items) == 1 && items[0] == logStreamSource}
	for i, it := range items {
		s.wide |= wideBit(it)
		s.quoted += quotedLen(it) // counted, not built: the bytes were paid for above
		if i > 0 {
			s.quoted++
		}
	}
	t.byID[id] = s
	return s, nil
}

// union returns the set holding every item of sets. The same combination is built once.
func (t *setTable) union(m *meter, sets []*idSet) (*idSet, error) {
	ids := make([]string, 0, len(sets))
	for _, s := range sets {
		ids = append(ids, s.id)
	}
	ids, err := sortedUnique(m, ids)
	if err != nil {
		return nil, err
	}
	if len(ids) == 1 {
		return t.byID[ids[0]], nil
	}
	key := strings.Join(ids, "|")
	if s, ok := t.unions[key]; ok {
		return s, nil
	}
	var items []string
	for _, id := range ids {
		items = append(items, t.byID[id].items...)
	}
	if items, err = sortedUnique(m, items); err != nil {
		return nil, err
	}
	s, err := t.intern(m, items)
	if err != nil {
		return nil, err
	}
	t.unions[key] = s
	return s, nil
}

// sortEntries orders entries by key, counting the comparisons.
func sortEntries(m *meter, es []nfEntry) error {
	sort.Slice(es, func(i, j int) bool {
		m.used++
		return es[i].key < es[j].key
	})
	return m.tick(0)
}

// normalFormVersion heads the canonical bytes. A change to how they are written changes
// it, so a digest of the bytes from another version never compares equal by accident.
const normalFormVersion = "tailkeeper-normal-form 1"

// WriteTo writes the canonical bytes of the normal form: one line for each section, entry,
// atom and shared source set, in a fixed order, every text JSON-quoted so none holds a
// line feed or a tab. Two policies with the same meaning write the same bytes whatever
// their comments, whitespace, key order, key case, acls or grants spelling or rule
// splitting, so a keyed digest of them says whether the policy now means what was
// validated. The state of a section is written; whether it was spelled null, and what case
// its name had, is not.
func (n *NormalForm) WriteTo(w io.Writer) (int64, error) {
	cw := &countWriter{w: w}
	line := func(fields ...string) {
		if cw.err != nil {
			return // nothing more is encoded once the writer has failed
		}
		for i, f := range fields {
			if i > 0 {
				_, _ = cw.Write([]byte{'\t'})
			}
			_, _ = cw.Write(appendJSONString(nil, f))
		}
		_, _ = cw.Write([]byte{'\n'})
	}
	_, _ = cw.Write([]byte(normalFormVersion + "\n"))
	used := map[string]*idSet{}
	aclsEmpty, grantsEmpty := n.writtenEmpty()
	line("access", n.AccessState().String(), strconv.Itoa(len(n.atoms)), emptyText(aclsEmpty), emptyText(grantsEmpty))
	for _, s := range n.secs {
		if cw.err != nil {
			break
		}
		switch {
		case s.name == "ssh" && s.whole:
			line("section", s.name, s.state.String(), "whole")
		case s.name == "ssh":
			line("section", s.name, s.state.String())
		case len(s.entries) == 0:
			// The access rules are written as atoms, and an empty or absent section holds
			// nothing to write.
			continue
		case !s.known:
			line("section", fieldSpelling(s.fold))
		case s.whole:
			// A wrong-typed value is not an entry named "": the section says so, because no
			// key could.
			line("section", s.name, "whole")
		default:
			line("section", s.name)
		}
		for _, e := range s.entries {
			if cw.err != nil {
				break
			}
			line("entry", e.key, e.val, strconv.Itoa(e.n))
			if e.targets != nil {
				line("targets", e.targets.id)
				used[e.targets.id] = e.targets
			}
		}
	}
	for _, a := range n.atoms {
		if cw.err != nil {
			break
		}
		line("atom", a.dst, a.proto, a.act, a.posture, a.via, a.app, a.extra, a.ports.String(), a.src.id)
		used[a.src.id] = a.src
	}
	ids := make([]string, 0, len(used))
	for id := range used {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if cw.err != nil {
			break
		}
		line(append([]string{"set", id}, used[id].items...)...)
	}
	return cw.n, cw.err
}

// Bytes is the canonical bytes of the normal form (see WriteTo).
func (n *NormalForm) Bytes() []byte {
	var b bytes.Buffer
	_, _ = n.WriteTo(&b)
	return b.Bytes()
}

type countWriter struct {
	w   io.Writer
	n   int64
	err error
}

func (c *countWriter) Write(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	k, err := c.w.Write(p)
	c.n += int64(k)
	c.err = err
	return k, err
}

// AccessState is the state of the access rules as the server reads them together: acls and
// grants, which the admin console rewrites into each other, are non-empty if either is,
// empty if neither is non-empty and one is [], and absent if neither is in the text. An
// absent acls section is the default allow-all, and "acls": [] and "grants": [] are both
// deny-all (probe A-1, 20 Oct 2026). Whether a non-empty grants section alone cancels the
// default was not measured, so a move between these states is always reported (the defaults
// class of a diff). The pooled state hides which of the two sections is written as [], and
// that is not a rewrite: see writtenEmpty.
func (n *NormalForm) AccessState() State {
	st := StateAbsent
	for _, s := range n.secs[:len(sections)] {
		if s.sec.Shape == ShapeRules {
			st = max(st, s.state)
		}
	}
	return st
}

// writtenEmpty says which of acls and grants is written as []. Moving a rule from one to the
// other is the console's rewrite and changes nothing, but a section that is [] where it was
// absent, or the other way round, can turn the default allow-all on or off whatever the other
// section holds, so the pooled state alone is not enough to call two policies equal.
func (n *NormalForm) writtenEmpty() (acls, grants bool) {
	return n.secs[sectionPos("acls")].state == StateEmpty, n.secs[sectionPos("grants")].state == StateEmpty
}

// emptyText is how the normal form writes whether a section is [].
func emptyText(empty bool) string {
	if empty {
		return "empty"
	}
	return "-"
}

// Ops is the work spent building the normal form, in the units of MaxWork.
func (n *NormalForm) Ops() int64 { return n.ops }
