package acl

import (
	"context"
	"net/netip"
	"sort"
	"strings"

	"github.com/tailscale/hujson"
)

// This file reads, from a parsed policy, what an explanation of access needs to cite: the
// rules of acls, grants and ssh with their selectors and where they are, the facts that
// resolve a name textually (groups, hosts, tagOwners) and whether a default posture is set. It
// reads the policy as the normal form does (the section names without regard to case, the
// fields of a rule likewise, the legacy users and ports of an acl rule) and decides nothing:
// whether a rule covers a pair is the caller's text match, and whether a pair is allowed is
// Tailscale's answer, never this reading's.

// The sections a rule is read from.
const (
	RulesACLs   = "acls"
	RulesGrants = "grants"
	RulesSSH    = "ssh"
)

// MaxAccessRules is the most rules ReadAccess lists, over the three sections together. Past it
// the rules are counted in OmittedRules, and a caller states that its list of candidates may
// be short.
const MaxAccessRules = 4096

// AccessDst is one destination of a rule: the selector, and the ports as the rule wrote them
// ("" when the rule states none, which is every grant and ssh destination).
type AccessDst struct {
	Selector string
	Ports    string
}

// AccessRule is one rule of acls, grants or ssh as written. A rule that is not an object, or
// whose sources or destinations are not lists of strings, or whose proto is neither a string
// nor a list of them, or whose ssh users or grant ip entries are not a list of strings, is
// Unreadable: its other fields are empty, and it matches nothing. A section that is neither a
// list nor null is one Unreadable rule.
type AccessRule struct {
	Section string
	// Index is the 1-based position in the section; Line and Column the rule's place in the
	// text, counted as Doc.Position counts.
	Index        int
	Line, Column int
	Src          []string
	Dst          []AccessDst
	// Users are the ssh users of an ssh rule.
	Users []string
	// IP are the ip entries of a grant ("tcp:22", "*"), as written; none for an ACL or ssh rule.
	IP []string
	// Proto are the protocols an acls rule lists in proto (a string or a list of them), as
	// written; none when it lists none, and for a grant or an ssh rule.
	Proto []string
	// Posture: the rule lists a srcPosture. Via and App: a grant has a via list, or an app
	// capability map.
	Posture, Via, App bool
	Unreadable        bool
}

// Access is what a policy says that an explanation cites.
type Access struct {
	Rules []AccessRule
	// OmittedRules counts the rules past MaxAccessRules.
	OmittedRules int
	// DefaultPosture: defaultSrcPosture lists something.
	DefaultPosture bool
	// Groups and TagOwners map a group or a tag to the names it lists, as written; Hosts maps
	// an alias to its address or prefix. Only the last occurrence of a section is read.
	Groups, TagOwners map[string][]string
	Hosts             map[string]string
}

// ReadAccess reads the access facts of d. It spends the work budget and honours ctx, and
// returns too_complex when the budget is spent.
func ReadAccess(ctx context.Context, d *Doc) (*Access, error) {
	if err := checkDoc(d); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r := &accessReader{d: d, m: newMeter(ctx), out: &Access{}}
	for _, sec := range []string{RulesACLs, RulesGrants, RulesSSH} {
		if err := r.rules(sec); err != nil {
			return nil, err
		}
	}
	var err error
	if r.out.Groups, err = r.lists("groups"); err != nil {
		return nil, err
	}
	if r.out.TagOwners, err = r.lists("tagOwners"); err != nil {
		return nil, err
	}
	if r.out.Hosts, err = r.hosts(); err != nil {
		return nil, err
	}
	if v := r.last("defaultSrcPosture"); v != nil {
		r.out.DefaultPosture = setPosture(v)
	}
	return r.out, nil
}

type accessReader struct {
	d   *Doc
	m   *meter
	out *Access
}

// last is the value of the last occurrence of a top-level section, or nil.
func (r *accessReader) last(name string) *hujson.Value {
	occ := r.d.byKey[sectionKey(name)]
	if len(occ) == 0 {
		return nil
	}
	return r.d.top[occ[len(occ)-1]].val
}

// rules lists the rules of one section.
func (r *accessReader) rules(section string) error {
	v := r.last(section)
	if v == nil {
		return nil
	}
	arr, ok := v.Value.(*hujson.Array)
	if !ok {
		if lit, isLit := v.Value.(hujson.Literal); isLit && lit.Kind() == 'n' {
			return nil // a section written null holds no rules
		}
		// A section that is neither a list nor null is rules the reader cannot take: one
		// unreadable rule stands for it, so that the limits cannot rule them out.
		line, col := r.d.Position(v.StartOffset)
		r.out.Rules = append(r.out.Rules, AccessRule{Section: section, Index: 1, Line: line, Column: col, Unreadable: true})
		return nil
	}
	for i := range arr.Elements {
		if len(r.out.Rules) >= MaxAccessRules {
			r.out.OmittedRules += len(arr.Elements) - i
			return nil
		}
		el := &arr.Elements[i]
		if err := r.m.tick(1); err != nil {
			return err
		}
		rule := AccessRule{Section: section, Index: i + 1}
		rule.Line, rule.Column = r.d.Position(el.StartOffset)
		if err := r.readRule(el, &rule); err != nil {
			return err
		}
		r.out.Rules = append(r.out.Rules, rule)
	}
	return nil
}

// readRule fills a rule from its element. A rule it cannot read is marked so and left bare.
func (r *accessReader) readRule(el *hujson.Value, rule *AccessRule) error {
	if _, isObject := el.Value.(*hujson.Object); !isObject {
		rule.Unreadable = true
		return nil
	}
	fields, err := objectFields(r.m, []*hujson.Value{el}, true)
	if err != nil {
		return err
	}
	by := map[string]*field{}
	for i := range fields {
		by[fields[i].name] = &fields[i]
	}
	srcNames, dstNames := []string{"src", "users"}, []string{"dst", "ports"}
	if rule.Section != RulesACLs {
		srcNames, dstNames = []string{"src"}, []string{"dst"}
	}
	src, srcOK, err := r.list(by, srcNames)
	if err != nil {
		return err
	}
	dst, dstOK, err := r.list(by, dstNames)
	if err != nil {
		return err
	}
	if !srcOK || !dstOK {
		rule.Unreadable = true
		return nil
	}
	own, err := r.readSectionFields(by, rule)
	if err != nil {
		return err
	}
	if !own {
		rule.Unreadable = true
		return nil
	}
	rule.Src = src
	for _, d := range dst {
		if rule.Section == RulesACLs {
			sel, ports := splitDstPorts(d)
			rule.Dst = append(rule.Dst, AccessDst{Selector: canonSelector(sel), Ports: ports})
			continue
		}
		rule.Dst = append(rule.Dst, AccessDst{Selector: canonSelector(d)})
	}
	for i := range rule.Src {
		rule.Src[i] = canonSelector(rule.Src[i])
	}
	return r.readQualifiers(by, rule)
}

// readSectionFields reads the field a section has of its own, the users of an ssh rule and the proto
// of an acls rule; it says false for one that is not what it should be, which makes the rule one the
// reader cannot take (its other fields are then left empty by the caller). The members of the list
// are a step each.
func (r *accessReader) readSectionFields(by map[string]*field, rule *AccessRule) (bool, error) {
	switch rule.Section {
	case RulesSSH:
		users, ok, err := r.list(by, []string{"users"})
		rule.Users = users
		return ok, err
	case RulesACLs:
		f := by["proto"]
		if f == nil {
			return true, nil
		}
		if err := r.m.tick(members(f)); err != nil {
			return false, err
		}
		proto, ok := stringOrList(f)
		if len(proto) > 0 {
			rule.Proto = proto
		}
		return ok, nil
	}
	return true, nil
}

// readQualifiers reads what qualifies a rule: its posture (an ssh rule has srcPosture too), and a
// grant's ip entries, via and app capabilities.
func (r *accessReader) readQualifiers(by map[string]*field, rule *AccessRule) error {
	posture, ok, err := r.list(by, []string{"srcPosture"})
	if err != nil {
		return err
	}
	if ok {
		rule.Posture = len(posture) > 0
	} else if by["srcPosture"] != nil {
		rule.Posture = true // a srcPosture the reader cannot take is not an absent one
	}
	if rule.Section != RulesGrants {
		return nil
	}
	ip, ipOK, err := r.list(by, []string{"ip"})
	if err != nil {
		return err
	}
	if !ipOK {
		*rule = AccessRule{Section: rule.Section, Index: rule.Index, Line: rule.Line, Column: rule.Column, Unreadable: true}
		return nil
	}
	rule.IP = ip
	via, ok, err := r.list(by, []string{"via"})
	if err != nil {
		return err
	}
	if ok {
		rule.Via = len(via) > 0
	} else if by["via"] != nil {
		rule.Via = true
	}
	if f := by["app"]; f != nil {
		last := f.layers[len(f.layers)-1]
		lit, isLit := last.Value.(hujson.Literal)
		rule.App = !isLit || lit.Kind() != 'n'
		if obj, isObj := last.Value.(*hujson.Object); isObj {
			rule.App = len(obj.Members) > 0
		}
	}
	return r.m.tick(1)
}

// members is how many entries a field holds as a list: what reading it costs.
func members(f *field) int {
	if arr, ok := f.layers[len(f.layers)-1].Value.(*hujson.Array); ok {
		return len(arr.Elements)
	}
	return 0
}

// list reads the first of the named fields that is present as a list of strings. A field that is
// present and is not such a list is not ok; a field that is absent is ok and empty. Each member
// is a step of the work budget, spent before any is read: a list of ten thousand selectors costs
// ten thousand steps, whether or not it is one the reader can take.
func (r *accessReader) list(by map[string]*field, names []string) (out []string, ok bool, err error) {
	for _, n := range names {
		if f := by[n]; f != nil {
			if err = r.m.tick(members(f)); err != nil {
				return nil, false, err
			}
			out, ok = stringList(f)
			return out, ok, nil
		}
	}
	return nil, true, nil
}

// splitDstPorts splits an acl destination "selector:ports". Ports are what follows the last
// colon when they read as a port spec; an entry whose tail does not is all selector.
func splitDstPorts(entry string) (selector, ports string) {
	if _, err := netip.ParseAddr(entry); err == nil {
		return entry, "" // an IPv6 address with no brackets carries no ports
	}
	i := strings.LastIndexByte(entry, ':')
	if i <= 0 || i == len(entry)-1 {
		return entry, ""
	}
	if _, ok := parsePorts(entry[i+1:]); !ok {
		return entry, ""
	}
	selector = entry[:i]
	if len(selector) > 2 && selector[0] == '[' && selector[len(selector)-1] == ']' {
		selector = selector[1 : len(selector)-1]
	}
	return selector, entry[i+1:]
}

// lists reads a top-level object whose values are lists of strings (groups, tagOwners): the
// entries whose value is not such a list are left out.
func (r *accessReader) lists(section string) (map[string][]string, error) {
	out := map[string][]string{}
	obj := r.object(section)
	if obj == nil {
		return out, nil
	}
	for i := range obj.Members {
		if err := r.m.tick(1); err != nil {
			return nil, err
		}
		arr, ok := obj.Members[i].Value.Value.(*hujson.Array)
		if !ok {
			continue
		}
		if err := r.m.tick(len(arr.Elements)); err != nil { // the members are paid for before they are read
			return nil, err
		}
		var items []string
		okAll := true
		for j := range arr.Elements {
			lit, isLit := arr.Elements[j].Value.(hujson.Literal)
			if !isLit || lit.Kind() != '"' {
				okAll = false
				break
			}
			items = append(items, litString(lit))
		}
		if okAll {
			out[nameOf(&obj.Members[i].Name)] = items
		}
	}
	return out, nil
}

// hosts reads the hosts section: an alias and the address or prefix it names.
func (r *accessReader) hosts() (map[string]string, error) {
	out := map[string]string{}
	obj := r.object("hosts")
	if obj == nil {
		return out, nil
	}
	for i := range obj.Members {
		if err := r.m.tick(1); err != nil {
			return nil, err
		}
		if lit, ok := obj.Members[i].Value.Value.(hujson.Literal); ok && lit.Kind() == '"' {
			out[nameOf(&obj.Members[i].Name)] = litString(lit)
		}
	}
	return out, nil
}

func (r *accessReader) object(section string) *hujson.Object {
	v := r.last(section)
	if v == nil {
		return nil
	}
	obj, _ := v.Value.(*hujson.Object)
	return obj
}

// setPosture says that a defaultSrcPosture value sets a posture: a list that names something does,
// an empty list or null does not, and a value the reader cannot take as a list (a string, a number,
// an object) is read as set, as an srcPosture of a rule is: it is not an absent one.
func setPosture(v *hujson.Value) bool {
	switch x := v.Value.(type) {
	case *hujson.Array:
		return len(x.Elements) > 0
	case hujson.Literal:
		return x.Kind() != 'n'
	}
	return true
}

// PortSet is a port spec read once: the ranges it names, sorted and merged. A caller that asks
// about many ports reads the spec once and asks the set, which searches its ranges, instead of
// reading the spec again for each port.
type PortSet struct{ p ports }

// ParsePortSet reads a port spec ("*", "22", "22,80-90"). ok is false for a spec the engine cannot
// read as ports.
func ParsePortSet(spec string) (PortSet, bool) {
	p, ok := parsePorts(spec)
	return PortSet{p}, ok
}

// Contains says that the set names the port, by a binary search of its sorted, merged ranges.
func (s PortSet) Contains(port int) bool {
	rs := s.p.ranges
	i := sort.Search(len(rs), func(i int) bool { return rs[i].hi >= port })
	return i < len(rs) && rs[i].lo <= port
}

// PortsContain reports whether a port spec ("*", "22", "22,80-90") names the port. readable is
// false for a spec the engine cannot read as ports, which a caller that lists candidates
// treats as possibly naming it.
func PortsContain(spec string, port int) (contains, readable bool) {
	set, ok := ParsePortSet(spec)
	if !ok {
		return false, false
	}
	return set.Contains(port), true
}
