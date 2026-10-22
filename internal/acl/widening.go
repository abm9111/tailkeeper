package acl

import (
	"slices"
	"strings"
)

// widening finds the structural changes that can only widen access. They are cheap checks
// on the changes already found, not the audit catalogue, and they err toward reporting: a
// selector that widens access in a source or destination of an atom that is new, a source
// posture removed or weakened, an SSH check that became an accept, an SSH rule that lets
// someone in as root where the old rules did not, and the default source posture removed.
// "New" means in the new policy and not in the old one, atom by atom (or rule by rule), so a
// wildcard that is swapped for another is found where a count of them would not. Each is
// reported in addition to the atoms that changed with it.
func (d *comparer) widening() error {
	n := len(d.raw) // what the comparison found; the findings below are not read back
	if err := d.wideSelectors(n); err != nil {
		return err
	}
	if err := d.postureRemoved(n); err != nil {
		return err
	}
	d.defaultPostureRemoved()
	return d.sshWidening(n)
}

var wideNames = [...]struct {
	bit  uint8
	name string
}{{wideStar, "*"}, {wideInternet, "autogroup:internet"}, {wideMember, "autogroup:member"}}

// wideSelectors raises a widening for every new atom that has a selector that widens access
// as a source or as its destination, where the old policy did not have it in that position
// for the same counterpart: for a source, the same destination; for a destination, the same
// sources. Ports are not part of that, so editing the ports of a rule that has a wildcard
// already is not adding one.
func (d *comparer) wideSelectors(n int) error {
	var srcOf map[string]uint8 // destination to the wide bits of the old sources that reach it
	var dstOf map[string]uint8 // set of sources to the wide bits of the destinations they reach
	for i := 0; i < n; i++ {
		c := &d.raw[i]
		if c.kind != kAtoms {
			continue
		}
		added := c.na
		if err := d.m.tick(len(added)); err != nil {
			return err
		}
		for _, a := range added {
			if a.src.wide == 0 && wideBit(a.dst) == 0 {
				continue
			}
			if srcOf == nil {
				var err error
				if srcOf, dstOf, err = d.oldWide(); err != nil {
					return err
				}
			}
			for _, w := range wideNames {
				if a.src.wide&w.bit != 0 && srcOf[a.dst]&w.bit == 0 {
					d.wideAtom("src", w.name, a, wideSrcNote(w.name))
				}
				if wideBit(a.dst) == w.bit && dstOf[a.src.id]&w.bit == 0 {
					d.wideAtom("dst", w.name, a, wideDstNote(w.name))
				}
			}
		}
	}
	return nil
}

// oldWide indexes the old atoms by what a widening selector in them was paired with.
func (d *comparer) oldWide() (srcOf, dstOf map[string]uint8, err error) {
	srcOf, dstOf = map[string]uint8{}, map[string]uint8{}
	for _, o := range d.na.atoms {
		if err := d.m.tick(len(o.dst)/8 + 1); err != nil {
			return nil, nil, err
		}
		if o.src.wide != 0 {
			srcOf[o.dst] |= o.src.wide
		}
		if b := wideBit(o.dst); b != 0 {
			dstOf[o.src.id] |= b
		}
	}
	return srcOf, dstOf, nil
}

// wideSrcNote and wideDstNote are the sentences that qualify a wide selector that is new. They
// name the selector, which is one of wideNames, and never the destination or the sources it is
// new for: those are in the change's fields.
func wideSrcNote(name string) string {
	return "a rule with " + name + " in src is new for the destination in dst"
}
func wideDstNote(name string) string {
	return "a rule with " + name + " in dst is new for these sources"
}

// wideAtom raises the widening of one new atom. For a wide source the destination it is new for
// is the second field, so a reader has it without the note quoting the policy.
func (d *comparer) wideAtom(field, name string, a *atom, note string) {
	key := field + " " + name
	fields := []FieldDelta{{Field: field, Added: []string{name}}}
	if field == "src" {
		fields = append(fields, FieldDelta{Field: "dst", Added: []string{a.dst}})
	}
	d.emit(rawChange{class: cWidening, op: oAdded, kind: kWide, sort: key, na: []*atom{a},
		x: &rawExtra{sec: "acls+grants", key: key, atomTexts: true, note: note, fields: fields}})
}

// isWildSelector reports a selector that stands for many others: everyone, an autogroup, a
// group or a tag. The engine does not resolve membership, so such a selector overlaps every
// other selector.
func isWildSelector(s string) bool {
	return s == "*" || strings.HasPrefix(s, "autogroup:") || strings.HasPrefix(s, "group:") || strings.HasPrefix(s, "tag:")
}

// selectorsOverlap reports whether two sorted sets of selectors can name the same thing: they
// share an item, or one holds a selector that stands for many, or one is empty (unknown).
func selectorsOverlap(m *meter, a, b []string) (bool, error) {
	if err := m.tick(len(a) + len(b) + 1); err != nil {
		return false, err
	}
	if len(a) == 0 || len(b) == 0 {
		return true, nil
	}
	for _, s := range [][]string{a, b} {
		for _, it := range s {
			if isWildSelector(it) {
				return true, nil
			}
		}
	}
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			return true, nil
		case a[i] < b[j]:
			i++
		default:
			j++
		}
	}
	return false, nil
}

// portsOverlap reports whether two sets of ports share one; specs that could not be read
// overlap everything.
func portsOverlap(p, q ports) bool {
	if len(p.raw) > 0 || len(q.raw) > 0 {
		return true
	}
	i, j := 0, 0
	for i < len(p.ranges) && j < len(q.ranges) {
		switch {
		case p.ranges[i].hi < q.ranges[j].lo:
			i++
		case q.ranges[j].hi < p.ranges[i].lo:
			j++
		default:
			return true
		}
	}
	return false
}

// itemsOf is the items of a set that may be missing.
func itemsOf(s *idSet) []string {
	if s == nil {
		return nil
	}
	return s.items
}

// subset reports whether every item of a is in b (both sorted); strict also needs b to have
// one more.
func subset(m *meter, a, b []string, strict bool) (bool, error) {
	if err := m.tick(len(a) + len(b) + 1); err != nil {
		return false, err
	}
	if len(a) > len(b) || strict && len(a) == len(b) {
		return false, nil
	}
	j := 0
	for _, it := range a {
		for j < len(b) && b[j] < it {
			j++
		}
		if j >= len(b) || b[j] != it {
			return false, nil
		}
		j++
	}
	return true, nil
}

// postureRemoved finds access that an old atom allowed only from devices with a posture and
// a new atom allows with none, or with fewer: a new atom whose destination is the old one's
// and whose sources or ports overlap it. The old atoms are all of them, not only those that
// went away, so a twin without the posture, or a rule that stopped sharing an atom with its
// postured neighbour, is found.
func (d *comparer) postureRemoved(n int) error {
	var came []*atom
	for i := 0; i < n; i++ {
		if c := &d.raw[i]; c.kind == kAtoms {
			came = append(came, c.na...)
		}
	}
	if len(came) == 0 {
		return nil
	}
	byDst := map[string][]*atom{}
	for _, o := range d.na.atoms {
		if err := d.m.tick(len(o.dst)/8 + 1); err != nil {
			return err
		}
		if o.pset != nil {
			byDst[o.dst] = append(byDst[o.dst], o)
		}
	}
	if len(byDst) == 0 {
		return nil
	}
	for _, a := range came {
		for _, o := range byDst[a.dst] {
			if err := d.m.tick(1); err != nil {
				return err
			}
			fewer := a.pset == nil
			if !fewer {
				var err error
				if fewer, err = subset(d.m, a.pset.items, o.pset.items, true); err != nil {
					return err
				}
			}
			if !fewer {
				continue
			}
			overlap, err := selectorsOverlap(d.m, a.src.items, o.src.items)
			if err != nil {
				return err
			}
			if overlap || portsOverlap(a.ports, o.ports) {
				d.emit(rawChange{class: cWidening, op: oChanged, kind: kWide, sort: a.rest, oa: []*atom{o}, na: []*atom{a},
					x: &rawExtra{sec: "acls+grants", key: "srcPosture removed: ", keyAtom: a, atomTexts: true,
						note:   postureRemovedNote,
						fields: []FieldDelta{{Field: "srcPosture", Removed: []string{o.posture}}}}})
				break
			}
		}
	}
	return nil
}

// defaultPostureRemoved reports the default source posture taken away: every rule without
// a srcPosture of its own lost the requirement.
func (d *comparer) defaultPostureRemoved() {
	pos := sectionPos("defaultSrcPosture")
	o, n := d.na.secs[pos], d.nb.secs[pos]
	if o.state == StateNonEmpty && !o.whole && (n.state != StateNonEmpty || n.whole) {
		d.emit(rawChange{class: cWidening, op: oRemoved, kind: kWide, rank: pos, sort: "defaultSrcPosture", oe: &o.entries[0],
			x: &rawExtra{sec: "defaultSrcPosture", key: "defaultSrcPosture", oldText: o.entries[0].val, newText: "[]",
				note:   defaultPostureNote,
				fields: []FieldDelta{{Field: "defaultSrcPosture", Removed: []string{o.entries[0].val}}}}})
	}
}

// sshOverlap reports whether two SSH rules can apply to the same connection: their sources,
// destinations and users each can name the same thing.
func (d *comparer) sshOverlap(a, b *nfEntry) (bool, error) {
	for _, p := range [][2]*idSet{{a.sshSrc, b.sshSrc}, {a.sshDst, b.sshDst}, {a.sshUsers, b.sshUsers}} {
		ok, err := selectorsOverlap(d.m, itemsOf(p[0]), itemsOf(p[1]))
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

// sshCovers reports whether rule x certainly applies wherever rule c does: each of its sets
// holds every item of c's (or is everyone).
func (d *comparer) sshCovers(x, c *nfEntry) (bool, error) {
	for _, p := range [][2]*idSet{{c.sshSrc, x.sshSrc}, {c.sshDst, x.sshDst}, {c.sshUsers, x.sshUsers}} {
		if p[0] == nil || p[1] == nil {
			return false, nil
		}
		if slices.Contains(p[1].items, "*") {
			continue
		}
		ok, err := subset(d.m, p[0].items, p[1].items, false)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

// sshWidening finds, among the SSH rules that changed: a rule that is new and has a
// selector that widens access as its source or destination; a check rule that went away
// where a rule that accepts the same connection is in the new policy and no check rule
// covers it; and a rule that is new and lets someone in as root where the old rules let
// that source in on that destination with none.
func (d *comparer) sshWidening(n int) error {
	pos := sectionPos("ssh")
	o, nw := d.na.secs[pos], d.nb.secs[pos]
	if o.whole || nw.whole {
		return nil
	}
	var gone, came, repeated []*nfEntry
	for i := 0; i < n; i++ {
		c := &d.raw[i]
		if c.kind != kEntry || c.rank != pos {
			continue
		}
		switch {
		case c.oe == nil && c.ne != nil:
			came = append(came, c.ne)
		case c.ne == nil && c.oe != nil && c.oe.action == "check":
			gone = append(gone, c.oe)
		case c.oe != nil && c.ne != nil && c.ne.n > c.oe.n && c.ne.root:
			repeated = append(repeated, c.ne)
		}
	}
	// A wide selector is added where no old rule had it for the same counterpart: for a
	// source, the same destinations and users; for a destination, the same sources.
	var srcOf, dstOf map[string]uint8
	if len(came) > 0 {
		srcOf, dstOf = map[string]uint8{}, map[string]uint8{}
		for i := range o.entries {
			e := &o.entries[i]
			if err := d.m.tick(1); err != nil {
				return err
			}
			if e.sshSrc != nil && e.sshDst != nil && e.sshUsers != nil && e.sshSrc.wide != 0 {
				srcOf[e.sshDst.id+e.sshUsers.id] |= e.sshSrc.wide
			}
			if e.sshSrc != nil && e.sshDst != nil && e.sshDst.wide != 0 {
				dstOf[e.sshSrc.id] |= e.sshDst.wide
			}
		}
	}
	for _, e := range came {
		for _, w := range wideNames {
			if e.sshSrc != nil && e.sshSrc.wide&w.bit != 0 &&
				(e.sshDst == nil || e.sshUsers == nil || srcOf[e.sshDst.id+e.sshUsers.id]&w.bit == 0) {
				d.sshWide("src", w.name, "destinations and users", e, pos)
			}
			if e.sshDst != nil && e.sshDst.wide&w.bit != 0 &&
				(e.sshSrc == nil || dstOf[e.sshSrc.id]&w.bit == 0) {
				d.sshWide("dst", w.name, "sources", e, pos)
			}
		}
	}
	for _, c := range gone {
		if err := d.m.tick(len(nw.entries) + 1); err != nil {
			return err
		}
		var accepting *nfEntry
		covered := false
		for i := range nw.entries {
			x := &nw.entries[i]
			switch x.action {
			case "accept":
				if accepting != nil {
					continue
				}
				ok, err := d.sshOverlap(c, x)
				if err != nil {
					return err
				}
				if ok {
					accepting = x
				}
			case "check":
				if covered {
					continue
				}
				ok, err := d.sshCovers(x, c)
				if err != nil {
					return err
				}
				covered = ok
			}
		}
		if accepting != nil && !covered {
			d.emit(rawChange{class: cWidening, op: oChanged, kind: kWide, rank: pos, sort: "ssh check to accept", ne: accepting,
				x: &rawExtra{sec: "ssh", key: "ssh check to accept", oldText: "check", newText: "accept",
					note:   sshCheckToAcceptNote,
					fields: []FieldDelta{{Field: "action", Added: []string{"accept"}, Removed: []string{"check"}}}}})
		}
	}
	// Root: a new rule that has it, where no old rule has it for the same sources and
	// destinations; and a root rule that appears more often than it did.
	granted := map[string]bool{}
	for i := range o.entries {
		e := &o.entries[i]
		if err := d.m.tick(1); err != nil {
			return err
		}
		if e.root && e.sshSrc != nil && e.sshDst != nil {
			granted[e.sshSrc.id+e.sshDst.id] = true
		}
	}
	root := func(e *nfEntry, note string) {
		d.emit(rawChange{class: cWidening, op: oAdded, kind: kWide, rank: pos, sort: "ssh users root", ne: e,
			x: &rawExtra{sec: "ssh", key: "ssh users root", note: note, fields: []FieldDelta{{Field: "users", Added: []string{"root"}}}}})
	}
	for _, e := range came {
		if e.root && (e.sshSrc == nil || e.sshDst == nil || !granted[e.sshSrc.id+e.sshDst.id]) {
			root(e, rootNewNote)
		}
	}
	for _, e := range repeated {
		root(e, rootRepeatedNote)
	}
	return nil
}

// The sentences that qualify a widening besides the wide selectors'.
const (
	postureRemovedNote   = "an atom with fewer or no posture requirements is new where an old atom with the same destination required a posture"
	defaultPostureNote   = "the default source posture is gone: rules without a srcPosture of their own no longer require it"
	sshCheckToAcceptNote = "a check rule went away, an accepting rule that can match the same connections is in the new policy, and no check rule certainly covers them"
	rootNewNote          = "a rule that lets someone in as root is new, and no old rule did so for these sources and destinations"
	rootRepeatedNote     = "a rule that lets someone in as root appears more often than before"
)

// sshWideNote qualifies a wide selector that is new in an SSH rule. other names what the
// selector is new for.
func sshWideNote(field, name, other string) string {
	return "an SSH rule with " + name + " in " + field + " is new for these " + other
}

// ChangeNotes is every sentence a Change's Note can be: a closed list of tailkeeper's own
// words. A note qualifies a change and is never built from a policy, so a caller that treats
// the field as fixed text can hold each result to this list.
func ChangeNotes() []string {
	notes := []string{wholeMismatchNote, defaultsNote, tagOwnersNote, postureRemovedNote, defaultPostureNote,
		sshCheckToAcceptNote, rootNewNote, rootRepeatedNote}
	for _, name := range []string{"acls", "grants"} {
		notes = append(notes, accessSectionNote(name, true), accessSectionNote(name, false))
	}
	states := []State{StateAbsent, StateEmpty, StateNonEmpty}
	for _, from := range states {
		for _, to := range states {
			notes = append(notes, sshNote(from, to))
		}
	}
	for _, w := range wideNames {
		notes = append(notes, wideSrcNote(w.name), wideDstNote(w.name),
			sshWideNote("src", w.name, "destinations and users"), sshWideNote("dst", w.name, "sources"))
	}
	slices.Sort(notes)
	return slices.Compact(notes)
}

func (d *comparer) sshWide(field, name, other string, e *nfEntry, pos int) {
	key := "ssh " + field + " " + name
	d.emit(rawChange{class: cWidening, op: oAdded, kind: kWide, rank: pos, sort: key, ne: e,
		x: &rawExtra{sec: "ssh", key: key, note: sshWideNote(field, name, other),
			fields: []FieldDelta{{Field: field, Added: []string{name}}}}})
}
