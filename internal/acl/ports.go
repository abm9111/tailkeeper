package acl

import (
	"sort"
	"strconv"
	"strings"
)

// portRange is an inclusive range of ports.
type portRange struct{ lo, hi int }

const maxPort = 65535

// ports is the set of ports a rule names: ranges sorted, merged and without overlap, and
// the specs that could not be read as ports, kept whole so that two rules naming something
// the engine does not understand are equal only if they name it alike. "*" is 0-65535 and
// is never expanded to individual ports.
type ports struct {
	ranges []portRange
	raw    []string // sorted, without repeats
}

// parsePorts reads a port spec: "*", "80", "80-90" or a comma list of those.
func parsePorts(spec string) (ports, bool) {
	var p ports
	if spec == "" {
		return p, false
	}
	for _, part := range strings.Split(spec, ",") {
		if part == "*" {
			p.ranges = append(p.ranges, portRange{0, maxPort})
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, ok := atoPort(lo)
		if !ok {
			return ports{}, false
		}
		b := a
		if isRange {
			if b, ok = atoPort(hi); !ok || b < a {
				return ports{}, false
			}
		}
		p.ranges = append(p.ranges, portRange{a, b})
	}
	_ = p.normalise(nil)
	return p, true
}

func atoPort(s string) (int, bool) {
	if s == "" || len(s) > 5 {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	return n, err == nil && n <= maxPort
}

// rawPorts holds a spec the engine cannot read.
func rawPorts(spec string) ports { return ports{raw: []string{spec}} }

// normalise sorts the ranges and merges those that overlap or touch. With a meter it counts
// the work, so a caller that normalises after every addition shows as quadratic in the
// operation-count guard.
func (p *ports) normalise(m *meter) error {
	if m != nil {
		if err := m.tick(len(p.ranges) + len(p.raw) + 1); err != nil {
			return err
		}
	}
	sort.Slice(p.ranges, func(i, j int) bool { return p.ranges[i].lo < p.ranges[j].lo })
	out := p.ranges[:0]
	for _, r := range p.ranges {
		if n := len(out); n > 0 && r.lo <= out[n-1].hi+1 {
			out[n-1].hi = max(out[n-1].hi, r.hi)
			continue
		}
		out = append(out, r)
	}
	p.ranges = out
	sort.Strings(p.raw)
	raw := p.raw[:0]
	for i, s := range p.raw {
		if i == 0 || s != p.raw[i-1] {
			raw = append(raw, s)
		}
	}
	p.raw = raw
	return nil
}

// add puts the ports of q into p without sorting them: a caller that adds many sets calls
// normalise once at the end, because sorting after each one is quadratic.
func (p *ports) add(q ports) {
	p.ranges = append(p.ranges, q.ranges...)
	p.raw = append(p.raw, q.raw...)
}

// union adds the ports of q to p and normalises.
func (p *ports) union(q ports) {
	p.add(q)
	_ = p.normalise(nil)
}

// String is the canonical text: "none" for no ports, "*" for all, ranges as "80,90-95", then
// each unreadable spec quoted. It is written into one buffer, sized for the common case of
// a few digits a range: a rule with many destinations writes this text for each atom, and
// building a string a range (as an earlier version did) allocated about 50 bytes a range.
func (p ports) String() string {
	if len(p.ranges) == 0 && len(p.raw) == 0 {
		return "none"
	}
	var b strings.Builder
	b.Grow(6*len(p.ranges) + 8*len(p.raw))
	var num [24]byte
	first := true
	comma := func() {
		if !first {
			b.WriteByte(',')
		}
		first = false
	}
	if len(p.ranges) == 1 && p.ranges[0] == (portRange{0, maxPort}) {
		comma()
		b.WriteByte('*')
	} else {
		for _, r := range p.ranges {
			comma()
			b.Write(strconv.AppendInt(num[:0], int64(r.lo), 10))
			if r.lo != r.hi {
				b.WriteByte('-')
				b.Write(strconv.AppendInt(num[:0], int64(r.hi), 10))
			}
		}
	}
	for _, s := range p.raw {
		comma()
		b.WriteString(strconv.Quote(s))
	}
	return b.String()
}

// minus is the ports of p that q does not name, as text, for a diff to show what a change
// added or removed. Both range lists are sorted and disjoint, so it walks them together.
func (p ports) minus(q ports) string {
	var parts []string
	emit := func(lo, hi int) {
		if lo == hi {
			parts = append(parts, strconv.Itoa(lo))
		} else {
			parts = append(parts, strconv.Itoa(lo)+"-"+strconv.Itoa(hi))
		}
	}
	j := 0
	for _, r := range p.ranges {
		lo := r.lo
		for j < len(q.ranges) && q.ranges[j].hi < lo {
			j++
		}
		for k := j; ; k++ {
			if k >= len(q.ranges) || q.ranges[k].lo > r.hi {
				emit(lo, r.hi)
				break
			}
			if q.ranges[k].lo > lo {
				emit(lo, q.ranges[k].lo-1)
			}
			if q.ranges[k].hi >= r.hi {
				break
			}
			lo = q.ranges[k].hi + 1
		}
	}
	for _, s := range p.raw {
		if !containsString(q.raw, s) {
			parts = append(parts, strconv.Quote(s))
		}
	}
	return strings.Join(parts, ",")
}

func containsString(sorted []string, s string) bool {
	i := sort.SearchStrings(sorted, s)
	return i < len(sorted) && sorted[i] == s
}

// splitDst splits an ACL destination "selector:ports" at its last colon. A destination
// whose tail is not a port spec ("tag:web", no ports) comes back whole with ok false.
//
// It is for the destinations of acls rules and tests, which carry ports; an ssh destination
// carries none, and a caller that may be handed any string (the summary) takes a false ok to
// mean it has none. A bare IPv6 address with no port ("2001:db8::1") would be cut at its last
// colon, and its last group read as a port.
func splitDst(dst string) (selector string, p ports, ok bool) {
	i := strings.LastIndexByte(dst, ':')
	if i < 0 {
		return dst, ports{}, false
	}
	p, ok = parsePorts(dst[i+1:])
	if !ok {
		return dst, ports{}, false
	}
	return dst[:i], p, true
}

// splitIP splits a grant's ip entry "proto:ports" or "ports" into its protocol (lower
// case, empty for none) and ports. An entry that is neither comes back as unreadable ports
// with no protocol.
func splitIP(entry string) (proto string, p ports) {
	if p, ok := parsePorts(entry); ok {
		return "", p
	}
	if i := strings.IndexByte(entry, ':'); i > 0 {
		if p, ok := parsePorts(entry[i+1:]); ok {
			return strings.ToLower(entry[:i]), p
		}
	}
	return "", rawPorts(entry)
}

// canonSelector maps the legacy spelling of a selector to the current one:
// autogroup:members is the old name of autogroup:member.
func canonSelector(s string) string {
	if s == "autogroup:members" {
		return "autogroup:member"
	}
	return s
}
