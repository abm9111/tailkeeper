package acl

import (
	"strings"

	"github.com/tailscale/hujson"
)

// Field sets: the arrays of these fields are sets, written sorted.
var (
	ruleSetFields     = map[string]bool{"src": true, "dst": true, "users": true, "ports": true, "srcPosture": true, "via": true, "proto": true}
	sshSetFields      = map[string]bool{"src": true, "dst": true, "users": true, "recorder": true}
	testSetFields     = map[string]bool{"accept": true, "allow": true, "deny": true, "check": true, "src": true, "dst": true}
	nodeAttrSetFields = map[string]bool{"target": true, "attr": true, "ipPool": true}
)

// elements reads a section's value as an array, or keeps it whole.
func (b *nfBuilder) elements(s *nfSec, lv *hujson.Value, top int) (*hujson.Array, error) {
	arr, ok := lv.Value.(*hujson.Array)
	if !ok {
		return nil, b.opaque(s, []*hujson.Value{lv}, top)
	}
	s.count = len(arr.Elements)
	s.state = StateEmpty
	if s.count > 0 {
		s.state = StateNonEmpty
	}
	return arr, nil
}

// rules feeds the rules of acls or grants to the atom builder.
func (b *nfBuilder) rules(s *nfSec, sec Section, lv *hujson.Value, top int) error {
	arr, err := b.elements(s, lv, top)
	if arr == nil {
		return err
	}
	grant, origin := sec.Name == "grants", originACLs
	if grant {
		origin = originGrants
	}
	s.seq = make([]uint64, 0, len(arr.Elements))
	for i := range arr.Elements {
		el := &arr.Elements[i]
		if err := b.ab.addRule(el, grant, origin, ref{val: el, top: top, idx: i}); err != nil {
			return err
		}
		text, err := appendCanon(b.m, nil, []*hujson.Value{el}, canonOpts{fold: true, setFields: ruleSetFields})
		if err != nil {
			return err
		}
		s.seq = append(s.seq, fnv64(string(text)))
	}
	return nil
}

// multiset collects entries by key, counting repeats.
type multiset struct {
	at      map[string]int
	entries []nfEntry
}

func newMultiset() *multiset { return &multiset{at: map[string]int{}} }

func (ms *multiset) add(e nfEntry) {
	if i, ok := ms.at[e.key]; ok {
		ms.entries[i].n++
		return
	}
	e.n = 1
	ms.at[e.key] = len(ms.entries)
	ms.entries = append(ms.entries, e)
}

// setArray reads ssh and extraDNSRecords: a multiset of canonical elements.
func (b *nfBuilder) setArray(s *nfSec, sec Section, lv *hujson.Value, top int) error {
	arr, err := b.elements(s, lv, top)
	if arr == nil {
		return err
	}
	opts := canonOpts{fold: true}
	if sec.Name == "ssh" {
		opts.setFields = sshSetFields
	}
	ms := newMultiset()
	for i := range arr.Elements {
		el := &arr.Elements[i]
		e := nfEntry{ref: ref{val: el, top: top, idx: i}}
		if _, isObject := el.Value.(*hujson.Object); isObject && sec.Name == "ssh" {
			fields, err := objectFields(b.m, []*hujson.Value{el}, true)
			if err != nil {
				return err
			}
			for j := range fields {
				f := &fields[j]
				switch f.name {
				case "action":
					if l, ok := stringOrList(f); ok && len(l) == 1 {
						e.action = l[0]
					}
				case "users", "src", "dst":
					l, ok := stringList(f)
					if !ok {
						break
					}
					if err := b.m.tick(len(l)); err != nil {
						return err
					}
					set, err := sortedSet(b.m, l)
					if err != nil {
						return err
					}
					is, err := b.nf.sets.intern(b.m, set)
					if err != nil {
						return err
					}
					switch f.name {
					case "users":
						e.sshUsers = is
						for _, u := range set {
							e.root = e.root || u == "root"
						}
					case "src":
						e.sshSrc = is
					default:
						e.sshDst = is
					}
				}
			}
			rest, err := appendFields(b.m, nil, fields, "action", opts)
			if err != nil {
				return err
			}
			e.rest = string(rest)
			whole, err := appendFields(b.m, nil, fields, "", opts)
			if err != nil {
				return err
			}
			e.key = string(whole)
		} else {
			text, err := appendCanon(b.m, nil, []*hujson.Value{el}, opts)
			if err != nil {
				return err
			}
			e.key = string(text)
		}
		s.seq = append(s.seq, fnv64(e.key))
		ms.add(e)
	}
	s.entries = ms.entries
	return sortEntries(b.m, s.entries)
}

// tests reads tests and sshTests as a multiset of assertions: a test that asserts two
// things is two assertions, so a test split in two, or two merged into one, compare equal.
func (b *nfBuilder) tests(s *nfSec, sec Section, lv *hujson.Value, top int) error {
	arr, err := b.elements(s, lv, top)
	if arr == nil {
		return err
	}
	ssh := sec.Name == "sshTests"
	ms := newMultiset()
	for i := range arr.Elements {
		el := &arr.Elements[i]
		at := ref{val: el, top: top, idx: i}
		keys, err := b.assertions(el, ssh)
		if err != nil {
			return err
		}
		for _, k := range keys {
			ms.add(nfEntry{key: k, ref: at})
		}
		text, err := appendCanon(b.m, nil, []*hujson.Value{el}, canonOpts{fold: true, setFields: testSetFields})
		if err != nil {
			return err
		}
		s.seq = append(s.seq, fnv64(string(text)))
	}
	s.entries = ms.entries
	return sortEntries(b.m, s.entries)
}

// assertions lists the assertions of one test element, each as its identity text.
func (b *nfBuilder) assertions(el *hujson.Value, ssh bool) ([]string, error) {
	m := b.m
	whole := func() ([]string, error) {
		text, err := appendCanon(m, nil, []*hujson.Value{el}, canonOpts{})
		return []string{"whole" + sep + string(text)}, err
	}
	if _, isObject := el.Value.(*hujson.Object); !isObject {
		return whole()
	}
	fields, err := objectFields(m, []*hujson.Value{el}, true)
	if err != nil {
		return nil, err
	}
	by := map[string]*field{}
	for i := range fields {
		by[fields[i].name] = &fields[i]
	}
	used := map[string]bool{}
	take := func(names ...string) ([]string, bool) {
		for _, n := range names {
			if f := by[n]; f != nil && !used[n] {
				l, ok := stringOrList(f)
				if ok {
					used[n] = true
				}
				return l, ok
			}
		}
		return nil, false
	}
	srcNames := []string{"src", "user"}
	if ssh {
		srcNames = []string{"src"}
	}
	srcs, ok := take(srcNames...)
	if !ok {
		return whole()
	}
	proto := ""
	if !ssh {
		// The protocol is read only as exactly one string (or null, which is no protocol); any
		// other value stays among the fields kept whole, so it is part of what is compared.
		if f := by["proto"]; f != nil {
			if lit, ok := f.layers[len(f.layers)-1].Value.(hujson.Literal); ok && lit.Kind() == 'n' {
				used["proto"] = true
			} else if p, ok := stringOrList(f); ok && len(p) == 1 {
				used["proto"] = true
				proto = strings.ToLower(p[0])
			}
		}
	}
	type group struct {
		polarity string
		items    []string
	}
	var groups []group
	var dsts []string
	if ssh {
		dsts, _ = take("dst")
	}
	for _, g := range [][2]string{{"accept", "accept"}, {"allow", "accept"}, {"deny", "deny"}, {"check", "check"}} {
		if g[0] == "check" && !ssh {
			continue
		}
		if f := by[g[0]]; f != nil && !used[g[0]] {
			if l, ok := stringList(f); ok {
				used[g[0]] = true
				groups = append(groups, group{g[1], l})
			}
		}
	}
	attrs := ""
	if f := by["srcPostureAttrs"]; f != nil && !ssh {
		used["srcPostureAttrs"] = true
		text, err := appendCanon(m, nil, f.layers, canonOpts{})
		if err != nil {
			return nil, err
		}
		attrs = string(text)
	}
	// Everything else is kept whole.
	extra, err := extraFields(m, fields, used)
	if err != nil {
		return nil, err
	}
	if srcs, err = sortedSet(m, srcs); err != nil {
		return nil, err
	}
	if len(srcs) == 0 {
		srcs = []string{""}
	}
	if len(dsts) == 0 {
		dsts = []string{""}
	}
	n := len(srcs) * len(dsts)
	for _, g := range groups {
		n += len(g.items) * len(srcs) * len(dsts)
	}
	if n > MaxAtoms {
		return nil, tooComplex("a test expands to %d assertions, past the limit of %d atoms", n, MaxAtoms)
	}
	// Every key holds the text of attrs and extra, and each of src, dst and item: the bytes
	// are counted before any key is built, so a long list beside a large field is refused
	// after the first few keys, not after gigabytes.
	if err := m.tick(n * (1 + len(attrs) + len(extra) + 16)); err != nil {
		return nil, err
	}
	var out []string
	var emitErr error
	emit := func(src, dst, polarity, item string) {
		if emitErr != nil {
			return
		}
		if emitErr = m.tick(len(src) + len(proto) + len(dst) + len(item)); emitErr != nil {
			return
		}
		kind := "test"
		if ssh {
			kind = "ssh"
		}
		// src, proto, dst and item are raw text from the policy, and one of them could hold the
		// separator: they are quoted, so no field's text can run into the next one's.
		q := func(v string) string { return string(appendJSONString(nil, v)) }
		out = append(out, strings.Join([]string{kind, q(src), q(proto), attrs, string(extra), polarity, q(dst), q(item)}, sep))
	}
	for _, src := range srcs {
		for _, dst := range dsts {
			if ssh {
				if len(groups) == 0 {
					emit(src, dst, "", "")
				}
				for _, g := range groups {
					for _, u := range g.items {
						emit(src, dst, g.polarity, u)
					}
					if len(g.items) == 0 {
						emit(src, dst, g.polarity, "")
					}
				}
				continue
			}
			if len(groups) == 0 {
				emit(src, "", "", "")
			}
			for _, g := range groups {
				for _, d := range g.items {
					emit(src, d, g.polarity, "")
				}
				if len(g.items) == 0 {
					emit(src, "", g.polarity, "")
				}
			}
		}
	}
	return out, emitErr
}

// nodeAttrs reads nodeAttrs, whose entries are additive: the same target twice, or an
// attribute listed twice, is one entry. An atom is an attribute with its qualifiers; the
// targets of atoms with the same attribute and qualifiers are united.
func (b *nfBuilder) nodeAttrs(s *nfSec, lv *hujson.Value, top int) error {
	arr, err := b.elements(s, lv, top)
	if arr == nil {
		return err
	}
	m := b.m
	type acc struct {
		sets    []*idSet // the targets of each part, shared: never copied for each attribute
		entry   nfEntry
		written bool
	}
	none, err := b.nf.sets.intern(m, nil)
	if err != nil {
		return err
	}
	by := map[string]*acc{}
	var order []string
	for i := range arr.Elements {
		el := &arr.Elements[i]
		at := ref{val: el, top: top, idx: i}
		text, err := appendCanon(m, nil, []*hujson.Value{el}, canonOpts{fold: true, setFields: nodeAttrSetFields})
		if err != nil {
			return err
		}
		s.seq = append(s.seq, fnv64(string(text)))
		parts := []*nodeAttrPart{{rest: "whole" + sep + string(text), targets: none, at: at}}
		if _, isObject := el.Value.(*hujson.Object); isObject {
			if parts, err = b.nodeAttrParts(el, at); err != nil {
				return err
			}
		}
		for _, p := range parts {
			a, ok := by[p.rest]
			if !ok {
				a = &acc{entry: nfEntry{key: p.rest, val: p.val, n: 1, ref: p.at}, written: p.written}
				by[p.rest] = a
				order = append(order, p.rest)
			}
			if err := m.tick(1); err != nil {
				return err
			}
			// One atom can come from several entries (a funnel entry, and the funnel
			// attribute of another that lists more); it is Tailscale's only if all are.
			a.written = a.written && p.written
			if len(a.sets) == 0 || a.sets[len(a.sets)-1] != p.targets {
				a.sets = append(a.sets, p.targets)
			}
			if p.at.val.StartOffset < a.entry.ref.val.StartOffset {
				a.entry.ref = p.at
			}
		}
	}
	for _, k := range order {
		a := by[k]
		set, err := b.nf.sets.union(m, a.sets)
		if err != nil {
			return err
		}
		a.entry.targets, a.entry.written = set, a.written
		s.entries = append(s.entries, a.entry)
	}
	return sortEntries(m, s.entries)
}

type nodeAttrPart struct {
	rest, val string
	targets   *idSet
	written   bool
	at        ref
}

// nodeAttrParts splits one nodeAttrs entry into one part for each attribute it lists (or
// one with no attribute), each with the qualifiers that make it the same attribute.
func (b *nfBuilder) nodeAttrParts(el *hujson.Value, at ref) ([]*nodeAttrPart, error) {
	m := b.m
	fields, err := objectFields(m, []*hujson.Value{el}, true)
	if err != nil {
		return nil, err
	}
	by := map[string]*field{}
	for i := range fields {
		by[fields[i].name] = &fields[i]
	}
	used := map[string]bool{}
	list := func(name string) []string {
		if f := by[name]; f != nil {
			if l, ok := stringList(f); ok {
				used[name] = true
				return l
			}
		}
		return nil
	}
	targets, attrs, pool := list("target"), list("attr"), list("ipPool")
	// The lists were read without the meter; their length is the work spent on them.
	if err := m.tick(len(targets) + len(attrs) + len(pool)); err != nil {
		return nil, err
	}
	if targets, err = sortedSet(m, targets); err != nil {
		return nil, err
	}
	targetSet, err := b.nf.sets.intern(m, targets)
	if err != nil {
		return nil, err
	}
	if pool, err = sortedSet(m, pool); err != nil {
		return nil, err
	}
	app := ""
	if f := by["app"]; f != nil {
		used["app"] = true
		if lit, ok := f.layers[len(f.layers)-1].Value.(hujson.Literal); !ok || lit.Kind() != 'n' {
			text, err := appendCanon(m, nil, f.layers, canonOpts{})
			if err != nil {
				return nil, err
			}
			app = string(text)
		}
	}
	// Everything else is kept whole.
	extra, err := extraFields(m, fields, used)
	if err != nil {
		return nil, err
	}
	if attrs, err = sortedSet(m, attrs); err != nil {
		return nil, err
	}
	if len(attrs) == 0 {
		attrs = []string{""}
	}
	if len(attrs) > MaxAtoms {
		return nil, tooComplex("a node attribute entry lists %d attributes, past the limit of %d atoms", len(attrs), MaxAtoms)
	}
	// What every attribute of the entry shares is built once; each attribute's value is that
	// text behind its own name, and its length is counted before it is built.
	var tail strings.Builder
	if app != "" {
		tail.WriteString(`,"app":` + app)
	}
	if len(pool) > 0 {
		tail.WriteString(`,"ipPool":[` + joinSet(pool) + `]`)
	}
	if extra != nil {
		tail.WriteString(`,"extra":` + string(extra))
	}
	tail.WriteString("}")
	preset := false
	if f := by["app"]; f != nil && extra == nil {
		var err error
		if preset, err = appIsPreset(m, f.layers); err != nil {
			return nil, err
		}
	}
	// The console writes Funnel as one attribute for a target and nothing else.
	bare := len(attrs) == 1 && len(targets) > 0 && app == "" && len(pool) == 0 && extra == nil
	var out []*nodeAttrPart
	for _, attr := range attrs {
		head := `{"attr":` + string(appendJSONString(nil, attr))
		if err := m.tick(1 + len(head) + tail.Len()); err != nil {
			return nil, err
		}
		val := head + tail.String()
		out = append(out, &nodeAttrPart{
			rest: val, val: val, targets: targetSet, at: at,
			written: attrWritten(attr, preset, bare),
		})
	}
	return out, nil
}

// keyedOpts says how the value of an entry of each keyed section is read: the entries of
// groups and tagOwners are sets, and the entries of postures, attrConfig and externalTailnets
// are structs. hosts and ipsets are read as written: an ipset's operations are in order.
var keyedOpts = map[string]canonOpts{
	"groups":           {sets: true},
	"tagOwners":        {sets: true},
	"postures":         {fold: true, setFields: map[string]bool{"assertions": true}},
	"attrConfig":       {fold: true, setFields: map[string]bool{"broadcastToPeers": true}},
	"externalTailnets": {fold: true, setFields: map[string]bool{"allowExternalReferencesTo": true}},
}

// readOpts is how the server's decoder reads the value of a section, as the options the normal
// form reads it with: the rules of an array section are structs, autoApprovers and derpMap are
// structs of fields (derpMapOpts describes what lies inside derpMap), and the entries of a keyed
// section are read with keyedOpts. Parse walks the text with the same description, so a
// collision of two spellings is reported wherever the normal form folds one.
func readOpts(sec Section) canonOpts {
	switch {
	case sec.StructElements:
		return canonOpts{elem: &canonOpts{fold: true}}
	case sec.Shape == ShapeStruct:
		o := structOpts[sec.Name]
		o.fold = true
		return o
	case sec.Shape == ShapeMap:
		o := keyedOpts[sec.Name]
		return canonOpts{elem: &o}
	}
	return canonOpts{}
}

// keyedMap reads groups, hosts, tagOwners, postures, ipsets, attrConfig and
// externalTailnets: entries compared by key. A key's value is canonical, with its arrays
// written as sets except in ipsets, whose operation lists are processed in order.
func (b *nfBuilder) keyedMap(s *nfSec, sec Section, layers []*hujson.Value, occ []int) error {
	top := occ[len(occ)-1]
	lv := layers[len(layers)-1]
	if _, ok := lv.Value.(*hujson.Object); !ok {
		return b.opaque(s, layers, top)
	}
	fields, err := objectFields(b.m, objectLayers(layers), false)
	if err != nil {
		return err
	}
	s.count = len(fields)
	s.state = StateEmpty
	if s.count > 0 {
		s.state = StateNonEmpty
	}
	opts := keyedOpts[sec.Name]
	for i := range fields {
		f := &fields[i]
		var text []byte
		if arr, ok := f.layers[len(f.layers)-1].Value.(*hujson.Array); ok && sec.Name == "postures" && allScalars(arr) {
			// The legacy form, a bare list of assertions, is the same posture as
			// {"assertions": [...]}.
			inner, err := appendCanon(b.m, nil, f.layers, canonOpts{sets: true})
			if err != nil {
				return err
			}
			text = append(append([]byte(`{"assertions":`), inner...), '}')
		} else if text, err = appendCanon(b.m, nil, f.layers, opts); err != nil {
			return err
		}
		last := len(f.names) - 1
		s.entries = append(s.entries, nfEntry{
			key: f.name, val: string(text), n: 1,
			ref: ref{val: f.names[last], top: top, idx: -1, named: true},
		})
	}
	return sortEntries(b.m, s.entries)
}

// derpMapOpts describes the nested structs of derpMap, which the server decodes into
// structs and so reads with case folding and merging: a region (ACLDERPRegion) and a node of
// its list (ACLDERPNode). Read as maps, {"regionID": 1, "RegionID": 2} and its reorder would
// canonicalise alike while the server reads 2 in one and 1 in the other.
var derpMapOpts = canonOpts{fold: true, fields: map[string]canonOpts{
	"regions": {elem: &canonOpts{fold: true, fields: map[string]canonOpts{
		"nodes": {elem: &canonOpts{fold: true}},
	}}},
}}

// structOpts says how the fields of autoApprovers and derpMap are read. The values of
// autoApprovers are lists of strings and maps of them, all sets.
var structOpts = map[string]canonOpts{
	"autoApprovers": {sets: true},
	"derpMap":       derpMapOpts,
}

// structFields reads autoApprovers and derpMap: each field is an entry, and a field that
// is a map (routes, services, regions) has an entry for each of its keys.
func (b *nfBuilder) structFields(s *nfSec, sec Section, layers []*hujson.Value, occ []int) error {
	top := occ[len(occ)-1]
	if _, ok := layers[len(layers)-1].Value.(*hujson.Object); !ok {
		return b.opaque(s, layers, top)
	}
	fields, err := objectFields(b.m, objectLayers(layers), true)
	if err != nil {
		return err
	}
	opts := structOpts[sec.Name]
	for i := range fields {
		f := &fields[i]
		last := len(f.names) - 1
		if _, isObject := f.layers[len(f.layers)-1].Value.(*hujson.Object); isObject {
			sub, err := objectFields(b.m, objectLayers(f.layers), false)
			if err != nil {
				return err
			}
			for j := range sub {
				g := &sub[j]
				text, err := appendCanon(b.m, nil, g.layers, opts.child(f.name).child(g.name))
				if err != nil {
					return err
				}
				key := escapePointer(f.name) + "/" + escapePointer(g.name)
				s.entries = append(s.entries, nfEntry{
					key: key, val: string(text), n: 1,
					ref: ref{val: g.names[len(g.names)-1], top: top, idx: -1, tail: "/" + key},
				})
			}
			if len(sub) > 0 {
				continue
			}
		}
		text, err := appendCanon(b.m, nil, f.layers, opts.child(f.name))
		if err != nil {
			return err
		}
		s.entries = append(s.entries, nfEntry{
			key: escapePointer(f.name), val: string(text), n: 1,
			ref: ref{val: f.names[last], top: top, idx: -1, tail: "/" + escapePointer(f.name)},
		})
	}
	s.count = len(s.entries)
	s.state = StateEmpty
	if s.count > 0 {
		s.state = StateNonEmpty
	}
	return sortEntries(b.m, s.entries)
}

// list reads defaultSrcPosture: one set of strings.
func (b *nfBuilder) list(s *nfSec, lv *hujson.Value, top int) error {
	arr, err := b.elements(s, lv, top)
	if arr == nil {
		return err
	}
	text, err := appendCanon(b.m, nil, []*hujson.Value{lv}, canonOpts{sets: true})
	if err != nil {
		return err
	}
	s.entries = []nfEntry{{key: "", val: string(text), n: 1, ref: ref{val: lv, top: top, idx: -1}}}
	return nil
}

// scalar reads disableIPv4, OneCGNATRoute and randomizeClientPort.
func (b *nfBuilder) scalar(s *nfSec, lv *hujson.Value, top int) error {
	text, err := appendCanon(b.m, nil, []*hujson.Value{lv}, canonOpts{})
	if err != nil {
		return err
	}
	s.state, s.count = StateNonEmpty, 1
	s.entries = []nfEntry{{key: "", val: string(text), n: 1, ref: ref{val: lv, top: top, idx: -1}}}
	return nil
}
