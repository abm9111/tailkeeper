package acl

import (
	"sort"
	"strings"

	"github.com/tailscale/hujson"
)

// atom is one thing a rule lets through, with the sources that share it: a destination
// selector, a protocol, a set of ports and everything else that qualifies the rule. The
// rules of acls and grants are reduced to atoms in two stages (see atomBuilder), so a rule
// split or merged by source, by destination or by ports is the same atoms. Every field of a
// rule that the engine does not model is in extra, so nothing can vanish from a comparison.
type atom struct {
	dst, proto string
	act        string // "" for accept; anything else is part of the identity
	posture    string // canonical sorted set
	via        string // canonical sorted set
	pset       *idSet // the postures as a set, nil for none (what posture is the text of)
	app        string // canonical JSON of the capability map, or ""
	extra      string // canonical JSON of every field not modelled, or ""
	rest       string // the fields above joined: the identity without sources and ports
	ports      ports
	pkey       string // ports.String(), once the atoms are final
	src        *idSet
	origin     uint8 // originACLs, originGrants
	ref        ref   // the first rule it came from
}

const (
	originACLs   uint8 = 1
	originGrants uint8 = 2
)

// sep joins the parts of a key. No part can hold it: the sets, app and extra are canonical
// JSON, which escapes control characters, and dst, proto and act (which are raw text from the
// policy) are JSON-quoted by identity before they join, so no field's text can run into the
// next one's.
const sep = "\x1f"

// rangeCopyWeight is the units of work charged for each port range an atom copies in add.
const rangeCopyWeight = 4

// atomBuilder builds the pool of atoms for acls and grants together, because the admin
// console rewrites one into the other.
//
// Stage 1 expands each rule over its destinations (and, for grants, over the protocols of
// its ip list) and merges atoms with the same sources and qualifiers by the union of their
// ports. Stage 2 merges atoms equal in everything but their sources by the union of their
// source sets. Sources are never multiplied by destinations, and port ranges are never
// expanded, so the atom count is bounded by the sum of the destination lists times the
// protocols. A rewrite the two stages do not reduce (the same access re-split along both
// sources and ports at once) reads as changed, which is the safe direction; the diff says
// so in its normalFormLimits.
type atomBuilder struct {
	m     *meter
	sets  *setTable
	byKey map[string]*atom
	order []*atom
}

func newAtomBuilder(m *meter, sets *setTable) *atomBuilder {
	return &atomBuilder{m: m, sets: sets, byKey: map[string]*atom{}}
}

// contribution is what one destination of a rule adds.
type contribution struct {
	dst, proto string
	ports      ports
}

// stringList reads a field as a list of strings. A null is the empty list. A value that is
// not an array of strings cannot be read, and the caller keeps the field whole.
func stringList(f *field) ([]string, bool) {
	last := f.layers[len(f.layers)-1]
	switch x := last.Value.(type) {
	case hujson.Literal:
		return nil, x.Kind() == 'n'
	case *hujson.Array:
		out := make([]string, 0, len(x.Elements))
		for i := range x.Elements {
			lit, ok := x.Elements[i].Value.(hujson.Literal)
			if !ok || lit.Kind() != '"' {
				return nil, false
			}
			out = append(out, litString(lit))
		}
		return out, true
	}
	return nil, false
}

// stringOrList reads a field holding one string or a list of them (proto).
func stringOrList(f *field) ([]string, bool) {
	last := f.layers[len(f.layers)-1]
	if lit, ok := last.Value.(hujson.Literal); ok && lit.Kind() == '"' {
		return []string{litString(lit)}, true
	}
	return stringList(f)
}

func sortedSet(m *meter, items []string) ([]string, error) {
	if len(items) == 0 {
		return nil, nil
	}
	return sortedUnique(m, append([]string(nil), items...))
}

func joinSet(items []string) string {
	var b strings.Builder
	for i, it := range items {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(appendJSONString(nil, it))
	}
	return b.String()
}

// extraFields writes, as one canonical JSON object, every field in fields whose name is not
// in used: the fields a reader of a rule or an entry does not model, kept whole so that
// nothing can vanish from a comparison. The members are sorted by name, so two texts that
// write the same unknown fields in a different order give the same bytes. It returns nil
// when there is no such field.
func extraFields(m *meter, fields []field, used map[string]bool) ([]byte, error) {
	rest := make([]*field, 0, len(fields))
	for i := range fields {
		if !used[fields[i].name] {
			rest = append(rest, &fields[i])
		}
	}
	if len(rest) == 0 {
		return nil, nil
	}
	sort.Slice(rest, func(i, j int) bool {
		m.used++
		return rest[i].name < rest[j].name
	})
	if err := m.tick(len(rest)); err != nil {
		return nil, err
	}
	out := []byte{'{'}
	for i, f := range rest {
		if i > 0 {
			out = append(out, ',')
		}
		out = appendJSONString(out, f.name)
		out = append(out, ':')
		var err error
		if out, err = appendCanon(m, out, f.layers, canonOpts{}); err != nil {
			return nil, err
		}
	}
	return append(out, '}'), nil
}

// addRule reads one rule of acls (grant false) or grants (grant true).
func (ab *atomBuilder) addRule(el *hujson.Value, grant bool, origin uint8, at ref) error {
	m := ab.m
	if err := m.tick(1); err != nil {
		return err
	}
	if _, isObject := el.Value.(*hujson.Object); !isObject {
		// A rule that is not an object cannot be read: it stays whole.
		text, err := appendCanon(m, nil, []*hujson.Value{el}, canonOpts{})
		if err != nil {
			return err
		}
		none, err := ab.sets.intern(m, nil)
		if err != nil {
			return err
		}
		return ab.add(&atom{act: "not-an-object", extra: string(text), src: none, origin: origin, ref: at}, ports{})
	}
	fields, err := objectFields(m, []*hujson.Value{el}, true)
	if err != nil {
		return err
	}
	by := map[string]*field{}
	for i := range fields {
		by[fields[i].name] = &fields[i]
	}
	used := map[string]bool{}

	list := func(names ...string) ([]string, bool) {
		for _, n := range names {
			if f := by[n]; f != nil && !used[n] {
				if l, ok := stringList(f); ok {
					used[n] = true
					return l, true
				}
				return nil, false
			}
		}
		return nil, true
	}
	// Sources: src, or the legacy users. When both are given, users stays in extra.
	srcNames, dstNames := []string{"src", "users"}, []string{"dst", "ports"}
	if grant {
		srcNames, dstNames = []string{"src"}, []string{"dst"}
	}
	src, _ := list(srcNames...)
	dst, _ := list(dstNames...)
	posture, _ := list("srcPosture")
	via, _ := list("via")

	var protos []string
	var ipEntries []string
	act := ""
	if grant {
		ipEntries, _ = list("ip")
	} else {
		if f := by["proto"]; f != nil {
			if l, ok := stringOrList(f); ok {
				protos = l
				used["proto"] = true
			}
		}
		switch f := by["action"]; {
		case f == nil:
			act = "none"
		default:
			if l, ok := stringOrList(f); ok && len(l) == 1 {
				used["action"] = true
				if l[0] != "accept" && l[0] != "allow" {
					act = l[0]
				}
			}
		}
	}
	// The lists were read without the meter; their length is the work spent on them.
	if err := m.tick(len(src) + len(dst) + len(posture) + len(via) + len(ipEntries) + len(protos)); err != nil {
		return err
	}

	app := ""
	if f := by["app"]; f != nil {
		used["app"] = true
		if lit, ok := f.layers[len(f.layers)-1].Value.(hujson.Literal); !ok || lit.Kind() != 'n' {
			text, err := appendCanon(m, nil, f.layers, canonOpts{})
			if err != nil {
				return err
			}
			app = string(text)
		}
	}

	// Everything else is kept whole.
	extra, err := extraFields(m, fields, used)
	if err != nil {
		return err
	}

	srcCanon := make([]string, len(src))
	for i, s := range src {
		srcCanon[i] = canonSelector(s)
	}
	if srcCanon, err = sortedSet(m, srcCanon); err != nil {
		return err
	}
	if posture, err = sortedSet(m, posture); err != nil {
		return err
	}
	var pset *idSet
	if len(posture) > 0 {
		if pset, err = ab.sets.intern(m, posture); err != nil {
			return err
		}
	}
	if via, err = sortedSet(m, via); err != nil {
		return err
	}
	srcSet, err := ab.sets.intern(m, srcCanon)
	if err != nil {
		return err
	}

	base := atom{act: act, posture: joinSet(posture), pset: pset, via: joinSet(via), app: app, extra: string(extra), src: srcSet, origin: origin, ref: at}

	var contributions []contribution
	if grant {
		groups := map[string]*ports{}
		var protoOrder []string
		for _, e := range ipEntries {
			proto, p := splitIP(e)
			g, ok := groups[proto]
			if !ok {
				g = &ports{}
				groups[proto] = g
				protoOrder = append(protoOrder, proto)
			}
			g.add(p)
		}
		sort.Strings(protoOrder)
		for _, proto := range protoOrder {
			if err := groups[proto].normalise(m); err != nil {
				return err
			}
		}
		if len(protoOrder) == 0 {
			protoOrder = []string{""}
			groups[""] = &ports{}
		}
		dsts := dst
		if len(dsts) == 0 {
			dsts = []string{""}
		}
		if len(dsts)*len(protoOrder) > MaxAtoms {
			return tooComplex("a rule expands to %d destinations by %d protocols, past the limit of %d atoms", len(dsts), len(protoOrder), MaxAtoms)
		}
		// A grant's dst is a selector with no ports; its ports are in ip.
		for _, d := range dsts {
			for _, proto := range protoOrder {
				contributions = append(contributions, contribution{canonSelector(d), proto, *groups[proto]})
			}
		}
	} else {
		if len(protos) == 0 {
			protos = []string{""}
		}
		protos, err = sortedUnique(m, lowerAll(protos))
		if err != nil {
			return err
		}
		dsts := dst
		if len(dsts) == 0 {
			dsts = []string{""}
		}
		if len(dsts)*len(protos) > MaxAtoms {
			return tooComplex("a rule expands to %d destinations by %d protocols, past the limit of %d atoms", len(dsts), len(protos), MaxAtoms)
		}
		for _, d := range dsts {
			sel, p, ok := splitDst(d)
			if !ok {
				sel, p = d, ports{}
			}
			for _, proto := range protos {
				contributions = append(contributions, contribution{canonSelector(sel), proto, p})
			}
		}
	}
	for _, c := range contributions {
		a := base
		a.dst, a.proto = c.dst, c.proto
		if err := ab.add(&a, c.ports); err != nil {
			return err
		}
	}
	return nil
}

// lowerAll returns in in lower case, as a new slice.
func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

// identity is the text of everything that qualifies an atom but its sources and its ports.
// dst, proto and act are quoted, because they are raw text and one of them could hold the
// separator: "a" + sep + "b" in one destination would otherwise read as "a" in one and "b"
// in the next field of another rule.
func identity(a *atom) string {
	var b []byte
	for _, f := range []string{a.dst, a.proto, a.act} {
		b = appendJSONString(b, f)
		b = append(b, sep...)
	}
	return string(b) + strings.Join([]string{a.posture, a.via, a.app, a.extra}, sep)
}

// add is stage 1: atoms with the same sources and qualifiers merge by the union of their
// ports. The ports are added without sorting them, and sorted once, with a meter, in
// finish. What an atom costs is the text of its identity and the ports it copies, so that
// is what is counted: a rule with many destinations and a large app or extra field, or a
// long list of port ranges, would otherwise hold a copy of it for each destination.
//
// The copy of the ports is charged rangeCopyWeight units an item. A range is 16 bytes (a
// raw spec the same), the copies of one rule are all held until the rules are done, and a
// refusal leaves them allocated: at one unit a range, 32,768 ranges by 2,000 destinations
// (a 400 KB policy) held 1 GiB when the budget ran out. At four units a refusal in add holds
// about 4 bytes a unit of the budget, 270 MiB at the default.
func (ab *atomBuilder) add(a *atom, p ports) error {
	a.rest = identity(a)
	if err := ab.m.tick(1 + len(a.rest) + rangeCopyWeight*(len(p.ranges)+len(p.raw))); err != nil {
		return err
	}
	key := a.src.id + sep + a.rest
	if have, ok := ab.byKey[key]; ok {
		have.ports.add(p)
		have.origin |= a.origin
		if a.ref.val != nil && (have.ref.val == nil || a.ref.val.StartOffset < have.ref.val.StartOffset) {
			have.ref = a.ref
		}
		return nil
	}
	if len(ab.order) >= MaxAtoms {
		return tooComplex("the rules expand to more than %d atoms", MaxAtoms)
	}
	a.ports = ports{}
	a.ports.add(p)
	ab.byKey[key] = a
	ab.order = append(ab.order, a)
	return nil
}

// finish is stage 2: atoms equal in everything but their sources merge by the union of
// their source sets. The result is sorted by qualifiers, ports and sources.
func (ab *atomBuilder) finish() ([]*atom, error) {
	m := ab.m
	groups := map[string][]*atom{}
	var keys []string
	for _, a := range ab.order {
		if err := m.tick(1); err != nil {
			return nil, err
		}
		if err := a.ports.normalise(m); err != nil {
			return nil, err
		}
		// The text of the ports and the key that groups the atoms are written for every
		// atom, and an atom of a rule with many destinations repeats them for each one, so
		// they are charged by their bytes: charged by the number of ranges alone, a rule
		// of 32,768 ranges and 1,000 destinations wrote 200 MB of text and 3.5 GiB of
		// garbage inside the budget.
		a.pkey = a.ports.String()
		if err := m.tick(len(a.pkey) + len(a.rest) + len(sep) + len(a.pkey)); err != nil {
			return nil, err
		}
		k := a.rest + sep + a.pkey
		if _, ok := groups[k]; !ok {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], a)
	}
	out := make([]*atom, 0, len(keys))
	for _, k := range keys {
		g := groups[k]
		first := g[0]
		if len(g) > 1 {
			sets := make([]*idSet, len(g))
			for i, a := range g {
				sets[i] = a.src
				first.origin |= a.origin
				if a.ref.val != nil && (first.ref.val == nil || a.ref.val.StartOffset < first.ref.val.StartOffset) {
					first.ref = a.ref
				}
			}
			u, err := ab.sets.union(m, sets)
			if err != nil {
				return nil, err
			}
			first.src = u
		}
		out = append(out, first)
	}
	sort.Slice(out, func(i, j int) bool {
		m.used++
		a, b := out[i], out[j]
		if a.rest != b.rest {
			return a.rest < b.rest
		}
		if a.pkey != b.pkey {
			return a.pkey < b.pkey
		}
		return a.src.id < b.src.id
	})
	return out, m.tick(0)
}
