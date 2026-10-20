package acl

import (
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
)

// This file is the independent rewriter the property tests use. It never calls the
// engine's normal form: it holds a policy as a model, in which a family of rules is the
// cross product of sources, destinations and ports, and writes that model as text in many
// equivalent ways, from the conversion table of Tailscale's migration page
// (https://tailscale.com/docs/reference/migrate-acls-grants): an ACL rule has src, dst
// entries "selector:ports" and a proto; its grant has src, dst selectors and ip entries
// "proto:ports". Splitting a family along one dimension, or writing it as one rule, is
// the same access. A rewriter that shared the engine's reduction would pass whatever the
// reduction did.

// jv is a JSON value the writer renders: a string, an int, a bool, nil, a []jv or a *jobj.
type jv any

// jobj is an object whose members keep the order they were added in. An object made with
// newPairs holds a list of members instead, and a key may appear in it more than once: that
// is how the writer repeats a key, with a decoy first and the value that counts later.
type jobj struct {
	keys  []string
	vals  map[string]jv
	pairs []jmember
}

// jmember is one member of a pairs object. Members of one group keep their order when the
// writer shuffles: the server reads a repeated key in the order it is written, so the shuffle
// must not turn a decoy into the value that counts.
type jmember struct {
	grp, key string
	val      jv
}

func newObj() *jobj { return &jobj{vals: map[string]jv{}} }

func newPairs(ms []jmember) *jobj {
	return &jobj{vals: map[string]jv{}, pairs: append([]jmember{}, ms...)}
}

// members lists the members of the object in the order they were added.
func (o *jobj) members() []jmember {
	if o.pairs != nil {
		return o.pairs
	}
	out := make([]jmember, len(o.keys))
	for i, k := range o.keys {
		out[i] = jmember{grp: k, key: k, val: o.vals[k]}
	}
	return out
}

func (o *jobj) set(k string, v jv) *jobj {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
	return o
}

// style is how the writer lays text out: everything here changes the text and nothing
// about what it means.
type style struct {
	indent          string
	newline         string
	trailing        bool // trailing commas
	comments        bool // line and block comments before members and elements
	shuffleKeys     bool // object members in a random order
	shuffleSets     bool // the arrays that are sets in a random order
	upperSections   bool // section names in another case
	upperFields     bool // the field names of rules in another case
	grants          bool // access rules written as grants
	legacy          bool // users and ports for src and dst, allow for accept
	protoArray      bool // proto as an array
	oneEntryPerPort bool
	decoys          bool // a repeated key: a decoy value first, the value that counts later
	fragments       bool // a section written as two members of the policy, merged by the reader
}

func randomStyle(rng *rand.Rand) style {
	return style{
		indent:          []string{"", "  ", "\t"}[rng.IntN(3)],
		newline:         []string{"\n", "\r\n"}[rng.IntN(2)],
		trailing:        rng.IntN(2) == 0,
		comments:        rng.IntN(2) == 0,
		shuffleKeys:     rng.IntN(2) == 0,
		shuffleSets:     rng.IntN(2) == 0,
		upperSections:   rng.IntN(3) == 0,
		upperFields:     rng.IntN(3) == 0,
		grants:          rng.IntN(2) == 0,
		legacy:          rng.IntN(3) == 0,
		protoArray:      rng.IntN(3) == 0,
		oneEntryPerPort: rng.IntN(2) == 0,
		decoys:          rng.IntN(2) == 0,
		fragments:       rng.IntN(2) == 0,
	}
}

// writer renders values in a style.
type writer struct {
	st  style
	rng *rand.Rand
	b   strings.Builder
	n   int // comments written
}

func (w *writer) nl(depth int) {
	if w.st.indent == "" && w.st.newline == "\n" {
		return
	}
	w.b.WriteString(w.st.newline)
	w.b.WriteString(strings.Repeat(w.st.indent, depth))
}

func (w *writer) comment(depth int) {
	if !w.st.comments {
		return
	}
	w.n++
	if w.rng.IntN(2) == 0 {
		fmt.Fprintf(&w.b, "/* c%d */ ", w.n)
		return
	}
	fmt.Fprintf(&w.b, "// c%d%s", w.n, "\n")
	w.b.WriteString(strings.Repeat(w.st.indent, depth))
}

func (w *writer) write(v jv, depth int) {
	switch x := v.(type) {
	case nil:
		w.b.WriteString("null")
	case string:
		fmt.Fprintf(&w.b, "%q", x)
	case int:
		fmt.Fprintf(&w.b, "%d", x)
	case bool:
		fmt.Fprintf(&w.b, "%v", x)
	case []jv:
		if len(x) == 0 {
			w.b.WriteString("[]")
			return
		}
		w.b.WriteByte('[')
		for i, e := range x {
			w.nl(depth + 1)
			w.comment(depth + 1)
			w.write(e, depth+1)
			if i < len(x)-1 || w.st.trailing {
				w.b.WriteByte(',')
			}
			if w.st.indent == "" && w.st.newline == "\n" && i < len(x)-1 {
				w.b.WriteByte(' ')
			}
		}
		w.nl(depth)
		w.b.WriteByte(']')
	case *jobj:
		ms := x.members()
		if len(ms) == 0 {
			w.b.WriteString("{}")
			return
		}
		ms = w.shuffleMembers(ms)
		w.b.WriteByte('{')
		for i, mem := range ms {
			w.nl(depth + 1)
			w.comment(depth + 1)
			fmt.Fprintf(&w.b, "%q: ", mem.key)
			w.write(mem.val, depth+1)
			if i < len(ms)-1 || w.st.trailing {
				w.b.WriteByte(',')
			}
			if w.st.indent == "" && w.st.newline == "\n" && i < len(ms)-1 {
				w.b.WriteByte(' ')
			}
		}
		w.nl(depth)
		w.b.WriteByte('}')
	default:
		panic(fmt.Sprintf("writer: %T", v))
	}
}

// shuffleMembers puts the members in a random order when the style shuffles keys, and keeps
// the members of one group in the order they were given.
func (w *writer) shuffleMembers(ms []jmember) []jmember {
	if !w.st.shuffleKeys {
		return ms
	}
	sh := append([]jmember(nil), ms...)
	w.rng.Shuffle(len(sh), func(i, j int) { sh[i], sh[j] = sh[j], sh[i] })
	at := map[string][]int{}
	for i, mem := range sh {
		at[mem.grp] = append(at[mem.grp], i)
	}
	inOrder := map[string][]jmember{}
	for _, mem := range ms {
		inOrder[mem.grp] = append(inOrder[mem.grp], mem)
	}
	for g, positions := range at {
		for n, pos := range positions {
			sh[pos] = inOrder[g][n]
		}
	}
	return sh
}

// Name pools: names the generator draws from. A destination or a source is used by one
// family only, so no two families share what the engine reduces by.
var (
	srcPool  = []string{"group:eng", "group:ops", "group:qa", "tag:ci", "tag:web", "autogroup:member", "alice@example.com", "bo@example.com", "group:finance team@example.com", "*"}
	selPool  = []string{"tag:db", "tag:cache", "tag:queue", "tag:mail", "tag:dns", "tag:vpn", "host-a", "host-b", "192.0.2.0/24", "198.51.100.0/24", "autogroup:self", "autogroup:internet"}
	portPool = []string{"22", "80", "443", "5432", "8080", "9000-9100", "6379", "25"}
	viaPool  = []string{"tag:exit-a", "tag:exit-b", "tag:exit-c"}
)

// family is a cross product of sources, destination selectors and ports, with a protocol
// and the qualifiers that must be equal across the rules of a family. A family with a via or
// an app is written as grants, the only form that has them.
type family struct {
	src, sels, ports []string
	proto            string // "", "tcp", "udp"
	posture          []string
	via              []string
	app              *jobj  // nil: none
	extraKey         string // an unknown field the rules carry, or ""
	extraVal         string
}

func (f family) needsGrant() bool { return len(f.via) > 0 || f.app != nil }

// splitKind is how a family is written as rules.
type splitKind int

const (
	whole splitKind = iota
	bySrc
	bySel
	byPort
)

func (f family) pieces(k splitKind) []family {
	one := func(src, sels, ports []string) family {
		g := f
		g.src, g.sels, g.ports = src, sels, ports
		return g
	}
	var out []family
	switch k {
	case bySrc:
		for _, s := range f.src {
			out = append(out, one([]string{s}, f.sels, f.ports))
		}
	case bySel:
		for _, s := range f.sels {
			out = append(out, one(f.src, []string{s}, f.ports))
		}
	case byPort:
		for _, p := range f.ports {
			out = append(out, one(f.src, f.sels, []string{p}))
		}
	default:
		out = []family{f}
	}
	return out
}

func strs(in []string) []jv {
	out := make([]jv, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

func (w *writer) set(in []string) []jv {
	cp := append([]string(nil), in...)
	if w.st.shuffleSets {
		w.rng.Shuffle(len(cp), func(i, j int) { cp[i], cp[j] = cp[j], cp[i] })
	}
	return strs(cp)
}

// field is a struct field's name in the style's case.
func (w *writer) field(name string) string {
	if w.st.upperFields {
		return strings.ToUpper(name[:1]) + name[1:]
	}
	return name
}

// aclRule writes one piece of a family as a rule of acls.
func (w *writer) aclRule(f family) *jobj {
	o := newObj()
	if w.st.legacy {
		o.set(w.field("action"), "allow")
	} else {
		o.set(w.field("action"), "accept")
	}
	srcName, dstName := "src", "dst"
	if w.st.legacy {
		srcName, dstName = "users", "ports"
	}
	o.set(w.field(srcName), w.set(f.src))
	var dst []string
	for _, sel := range f.sels {
		if w.st.oneEntryPerPort {
			for _, p := range f.ports {
				dst = append(dst, sel+":"+p)
			}
		} else {
			dst = append(dst, sel+":"+strings.Join(f.ports, ","))
		}
	}
	o.set(w.field(dstName), w.set(dst))
	if f.proto != "" {
		if w.st.protoArray {
			o.set(w.field("proto"), []jv{f.proto})
		} else {
			o.set(w.field("proto"), f.proto)
		}
	}
	if len(f.posture) > 0 {
		o.set(w.field("srcPosture"), w.set(f.posture))
	}
	if f.extraKey != "" {
		o.set(f.extraKey, f.extraVal)
	}
	return o
}

// grantRule writes one piece of a family as a grant: the destination selectors, and the
// ports with the protocol joined to each.
func (w *writer) grantRule(f family) *jobj {
	o := newObj()
	o.set(w.field("src"), w.set(f.src))
	o.set(w.field("dst"), w.set(f.sels))
	var ip []string
	for _, p := range f.ports {
		if f.proto != "" {
			ip = append(ip, f.proto+":"+p)
		} else {
			ip = append(ip, p)
		}
	}
	o.set(w.field("ip"), w.set(ip))
	if len(f.posture) > 0 {
		o.set(w.field("srcPosture"), w.set(f.posture))
	}
	if len(f.via) > 0 {
		o.set(w.field("via"), w.set(f.via))
	}
	if f.app != nil {
		o.set(w.field("app"), f.app)
	}
	if f.extraKey != "" {
		o.set(f.extraKey, f.extraVal)
	}
	return o
}

// model is a policy as the generator holds it.
type model struct {
	groups    map[string][]string
	tagOwners map[string][]string
	hosts     map[string]string
	postures  map[string][]string
	families  []family
	tests     []modelTest
	ssh       []modelSSH
	attrs     []modelAttr
	ipsets    map[string][]string
	// autoRoutes and autoExit are the autoApprovers, a struct section.
	autoRoutes map[string][]string
	autoExit   []string
	unknown    map[string]jv
}

type modelTest struct {
	src          string
	accept, deny []string
}

type modelSSH struct {
	action, src, dst string
	users            []string
}

type modelAttr struct {
	targets, attrs []string
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// render writes the model as text. splits chooses, for each family, how it is cut into
// rules (nil: whole); style decides everything about the layout, including whether a key is
// repeated (a decoy value first, the value that counts later) and whether a section is
// written as two members of the policy.
func (m *model) render(st style, rng *rand.Rand, splits []splitKind) string {
	w := &writer{st: st, rng: rng}
	root := newPairs(nil)
	// spell writes a section name in the style's case, or in the other one when flipped.
	spell := func(name string, flip bool) string {
		if st.upperSections != flip {
			return strings.ToUpper(name[:1]) + name[1:]
		}
		return name
	}
	// The members of one section keep their order whatever the shuffle: the group is the
	// name in lower case, so a second member in another case still comes second.
	put := func(name string, v jv) {
		root.pairs = append(root.pairs, jmember{grp: strings.ToLower(name), key: spell(name, false), val: v})
	}
	// putMembers writes a section from its members, in order: one object, or in a fragments
	// style the first members in one object and the rest in a second one, which the reader
	// merges into the first.
	putMembers := func(name string, ms []jmember) {
		if !st.fragments {
			put(name, newPairs(ms))
			return
		}
		cut := rng.IntN(len(ms) + 1)
		put(name, newPairs(ms[:cut]))
		root.pairs = append(root.pairs, jmember{grp: strings.ToLower(name), key: spell(name, rng.IntN(3) == 0), val: newPairs(ms[cut:])})
	}
	// putMap writes a map section; in a decoys style an entry is written twice, with a value
	// that does not count before the one that does.
	putMap := func(name string, keys []string, real, decoy func(k string) jv) {
		if len(keys) == 0 {
			return
		}
		var ms []jmember
		for _, k := range keys {
			if st.decoys && rng.IntN(2) == 0 {
				ms = append(ms, jmember{grp: k, key: k, val: decoy(k)})
			}
			ms = append(ms, jmember{grp: k, key: k, val: real(k)})
		}
		putMembers(name, ms)
	}
	putMap("groups", sortedKeys(m.groups),
		func(k string) jv { return w.set(m.groups[k]) },
		func(string) jv { return []jv{"decoy@example.com"} })
	putMap("tagOwners", sortedKeys(m.tagOwners),
		func(k string) jv { return w.set(m.tagOwners[k]) },
		func(string) jv { return []jv{"group:decoy"} })
	putMap("hosts", sortedKeys(m.hosts),
		func(k string) jv { return m.hosts[k] },
		func(string) jv { return "203.0.113.200" })
	putMap("postures", sortedKeys(m.postures),
		func(k string) jv {
			if st.legacy {
				return w.set(m.postures[k]) // the bare list is the same posture
			}
			return newObj().set(w.field("assertions"), w.set(m.postures[k]))
		},
		// A decoy that merges with the real value would leave its extra field behind.
		func(string) jv {
			return newObj().set(w.field("assertions"), []jv{"node:os == 'windows'"}).set("x-decoy", 1)
		})
	putMap("ipsets", sortedKeys(m.ipsets),
		func(k string) jv { return strs(m.ipsets[k]) }, // the operations are ordered: never shuffled
		func(string) jv { return []jv{"add 203.0.113.9"} })

	if len(m.autoRoutes) > 0 || len(m.autoExit) > 0 {
		routes, exit := w.field("routes"), w.field("exitNode")
		var ms []jmember
		if rkeys := sortedKeys(m.autoRoutes); len(rkeys) > 0 {
			if (st.decoys || st.fragments) && rng.IntN(2) == 0 {
				// One routes member for each route: a repeated struct field, merged.
				for _, k := range rkeys {
					if st.decoys && rng.IntN(2) == 0 {
						ms = append(ms, jmember{grp: "routes", key: routes, val: newPairs([]jmember{{grp: k, key: k, val: []jv{"tag:decoy"}}})})
					}
					ms = append(ms, jmember{grp: "routes", key: routes, val: newPairs([]jmember{{grp: k, key: k, val: w.set(m.autoRoutes[k])}})})
				}
			} else {
				var es []jmember
				for _, k := range rkeys {
					if st.decoys && rng.IntN(2) == 0 {
						es = append(es, jmember{grp: k, key: k, val: []jv{"tag:decoy"}})
					}
					es = append(es, jmember{grp: k, key: k, val: w.set(m.autoRoutes[k])})
				}
				ms = append(ms, jmember{grp: "routes", key: routes, val: newPairs(es)})
			}
		}
		if len(m.autoExit) > 0 {
			if st.decoys && rng.IntN(2) == 0 {
				ms = append(ms, jmember{grp: "exitnode", key: exit, val: []jv{"tag:decoy"}})
			}
			ms = append(ms, jmember{grp: "exitnode", key: exit, val: w.set(m.autoExit)})
		}
		putMembers("autoApprovers", ms)
	}

	var aclRules, grantRules []jv
	for i, f := range m.families {
		kind := whole
		if i < len(splits) {
			kind = splits[i]
		}
		for _, p := range f.pieces(kind) {
			if st.grants || p.needsGrant() {
				grantRules = append(grantRules, w.grantRule(p))
			} else {
				aclRules = append(aclRules, w.aclRule(p))
			}
		}
	}
	if st.shuffleSets {
		rng.Shuffle(len(aclRules), func(i, j int) { aclRules[i], aclRules[j] = aclRules[j], aclRules[i] })
		rng.Shuffle(len(grantRules), func(i, j int) { grantRules[i], grantRules[j] = grantRules[j], grantRules[i] })
	}
	if len(aclRules) > 0 {
		put("acls", aclRules)
	}
	if len(grantRules) > 0 {
		put("grants", grantRules)
	}
	if len(m.tests) > 0 {
		var tests []jv
		for _, t := range m.tests {
			o := newObj()
			if st.legacy {
				o.set(w.field("user"), t.src)
			} else {
				o.set(w.field("src"), t.src)
			}
			if len(t.accept) > 0 {
				if st.legacy {
					o.set(w.field("allow"), w.set(t.accept))
				} else {
					o.set(w.field("accept"), w.set(t.accept))
				}
			}
			if len(t.deny) > 0 {
				o.set(w.field("deny"), w.set(t.deny))
			}
			tests = append(tests, o)
		}
		put("tests", tests)
	}
	if len(m.ssh) > 0 {
		var rules []jv
		for _, s := range m.ssh {
			o := newObj().set(w.field("action"), s.action).set(w.field("src"), []jv{s.src}).set(w.field("dst"), []jv{s.dst}).set(w.field("users"), w.set(s.users))
			rules = append(rules, o)
		}
		if st.shuffleSets {
			rng.Shuffle(len(rules), func(i, j int) { rules[i], rules[j] = rules[j], rules[i] })
		}
		put("ssh", rules)
	}
	if len(m.attrs) > 0 {
		var entries []jv
		for _, a := range m.attrs {
			entries = append(entries, newObj().set(w.field("target"), w.set(a.targets)).set(w.field("attr"), w.set(a.attrs)))
		}
		put("nodeAttrs", entries)
	}
	// The names of sections the engine does not know change case with the rest: the server
	// reads them without regard to case.
	for _, k := range sortedKeys(m.unknown) {
		put(k, m.unknown[k])
	}
	w.write(root, 0)
	w.b.WriteString(st.newline)
	return w.b.String()
}

// plain is the layout the base text of a test is written in.
var plain = style{indent: "  ", newline: "\n"}

// randomModel draws a policy. Each family takes names from the pools that no other family
// takes, so the rewrites that cut or join one family do not change how the engine's two
// stages group the rest.
func randomModel(rng *rand.Rand) *model {
	pick := func(pool []string, n int) []string {
		idx := rng.Perm(len(pool))[:n]
		sort.Ints(idx)
		out := make([]string, n)
		for i, j := range idx {
			out[i] = pool[j]
		}
		return out
	}
	m := &model{
		groups: map[string][]string{"group:eng": {"alice@example.com", "bo@example.com"}, "group:ops": {"cy@example.com"}},
		// Several owners in an entry, so that the order of a set is something to get wrong.
		tagOwners:  map[string][]string{"tag:web": {"group:eng", "group:ops", "alice@example.com"}, "tag:db": {"group:eng", "bo@example.com"}, "tag:ci": {}},
		hosts:      map[string]string{"host-a": "192.0.2.10", "host-b": "192.0.2.11"},
		postures:   map[string][]string{"posture:a": {"node:os == 'linux'", "node:tsVersion >= '1.50'"}, "posture:b": {"node:os == 'macos'"}},
		ipsets:     map[string][]string{"ipset:s": {"add 192.0.2.1", "remove 192.0.2.1"}},
		autoRoutes: map[string][]string{"192.0.2.0/24": {"group:eng", "tag:web"}, "198.51.100.0/24": {"tag:ci"}},
		autoExit:   []string{"tag:web", "tag:ci"},
		unknown:    map[string]jv{},
	}
	sels := rng.Perm(len(selPool))
	next := 0
	for i, n := 0, 1+rng.IntN(3); i < n && next < len(sels); i++ {
		k := 1 + rng.IntN(2)
		if next+k > len(sels) {
			k = len(sels) - next
		}
		f := family{
			src:   pick(srcPool, 1+rng.IntN(3)),
			ports: pick(portPool, 1+rng.IntN(3)),
			proto: []string{"", "tcp", "udp"}[rng.IntN(3)],
		}
		for _, j := range sels[next : next+k] {
			f.sels = append(f.sels, selPool[j])
		}
		next += k
		if rng.IntN(3) == 0 {
			f.posture = pick([]string{"posture:a", "posture:b", "posture:c"}, 1+rng.IntN(2))
		}
		if rng.IntN(3) == 0 {
			f.via = pick(viaPool, 1+rng.IntN(2))
		}
		if rng.IntN(3) == 0 {
			f.app = appValue(rng.IntN(100))
		}
		if rng.IntN(4) == 0 {
			f.extraKey, f.extraVal = "x-note", fmt.Sprintf("n%d", rng.IntN(100))
		}
		m.families = append(m.families, f)
	}
	for i, n := 0, rng.IntN(3); i < n; i++ {
		m.tests = append(m.tests, modelTest{src: pick(srcPool, 1)[0], accept: pick(selPool, 1+rng.IntN(2)), deny: pick(portPool, rng.IntN(2))})
	}
	for i, n := 0, rng.IntN(3); i < n; i++ {
		m.ssh = append(m.ssh, modelSSH{action: []string{"accept", "check"}[rng.IntN(2)], src: srcPool[rng.IntN(len(srcPool))], dst: fmt.Sprintf("tag:ssh%d", i), users: pick([]string{"alice", "bob", "carol"}, 1+rng.IntN(2))})
	}
	for i, n := 0, rng.IntN(3); i < n; i++ {
		m.attrs = append(m.attrs, modelAttr{targets: pick([]string{"tag:a", "tag:b", "tag:c"}, 1+rng.IntN(2)), attrs: pick([]string{"attr-one", "attr-two"}, 1+rng.IntN(2))})
	}
	if rng.IntN(2) == 0 {
		m.unknown["futureThing"] = newObj().set("k", rng.IntN(1000)).set("list", []jv{1, 2, 3})
	}
	return m
}

// appValue is the app field of a grant: capability names, each with a list of objects. The
// lists have one element, so no rewrite reorders them.
func appValue(n int) *jobj {
	return newObj().
		set("example.com/cap/a", []jv{newObj().set("role", fmt.Sprintf("r%d", n))}).
		set("example.com/cap/b", []jv{})
}

// clone copies a model deeply enough to mutate one copy. The unknown sections and the app
// of a family are shared: a mutation replaces them and never changes them in place.
func (m *model) clone() *model {
	c := &model{
		groups: map[string][]string{}, tagOwners: map[string][]string{}, hosts: map[string]string{}, ipsets: map[string][]string{},
		postures: map[string][]string{}, autoRoutes: map[string][]string{}, unknown: map[string]jv{},
		autoExit: append([]string(nil), m.autoExit...),
	}
	for k, v := range m.groups {
		c.groups[k] = append([]string(nil), v...)
	}
	for k, v := range m.tagOwners {
		c.tagOwners[k] = append([]string(nil), v...)
	}
	for k, v := range m.hosts {
		c.hosts[k] = v
	}
	for k, v := range m.postures {
		c.postures[k] = append([]string(nil), v...)
	}
	for k, v := range m.ipsets {
		c.ipsets[k] = append([]string(nil), v...)
	}
	for k, v := range m.autoRoutes {
		c.autoRoutes[k] = append([]string(nil), v...)
	}
	for k, v := range m.unknown {
		c.unknown[k] = v
	}
	for _, f := range m.families {
		f.src, f.sels, f.ports, f.posture, f.via = append([]string(nil), f.src...), append([]string(nil), f.sels...), append([]string(nil), f.ports...), append([]string(nil), f.posture...), append([]string(nil), f.via...)
		c.families = append(c.families, f)
	}
	for _, t := range m.tests {
		t.accept, t.deny = append([]string(nil), t.accept...), append([]string(nil), t.deny...)
		c.tests = append(c.tests, t)
	}
	for _, s := range m.ssh {
		s.users = append([]string(nil), s.users...)
		c.ssh = append(c.ssh, s)
	}
	for _, a := range m.attrs {
		a.targets, a.attrs = append([]string(nil), a.targets...), append([]string(nil), a.attrs...)
		c.attrs = append(c.attrs, a)
	}
	return c
}
