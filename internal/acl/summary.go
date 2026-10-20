package acl

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/tailscale/hujson"
)

// MaxNames is the most names a summary lists in each group.
const MaxNames = 1000

// maxSyncedRef is the longest string (decoded) the summary reads as a reference to a synced
// group. A longer one that starts like a group is not read, and is reported as a cut list
// (NamesTruncated), so the summary never copies a string the size of the text.
const maxSyncedRef = 4 * maxPointer

// SectionSummary is one section of a policy at a glance.
type SectionSummary struct {
	// Name is the section's name as the table spells it, or as an unknown section was first
	// written (cut at 1 KiB).
	Name  string
	Known bool
	State State
	// Count is the elements of an array section, the entries of a map, or 1 for a value.
	Count int
	// Scalar is the canonical value of a section that holds one (disableIPv4,
	// OneCGNATRoute, randomizeClientPort), cut at 1 KiB.
	Scalar string
}

// Summary is what a caller needs to know about a policy without reading it: the state and
// size of every section, the names it defines, the synced groups it refers to, the number
// of tests and what the table does not know.
type Summary struct {
	// Sections are the known sections in table order, then the unknown ones by name (at most
	// MaxNames of them, the first by name; a section whose value is null is absent and has no
	// row).
	Sections []SectionSummary
	// Defined names, sorted and exact (each cut at 1 KiB, at most MaxNames of each; when a
	// list is cut it holds the first MaxNames in sorted order).
	Groups, TagOwners, Hosts, Postures, IPSets []string
	// SyncedGroups are the group names the policy refers to that it does not define in
	// groups: groups synced from an identity provider are written group:name@domain, and
	// can hold spaces and capitals. When the list is cut it holds the first MaxNames found
	// in the text, sorted. Names are compared as cut at 1 KiB.
	SyncedGroups []string
	// NamesTruncated: a list above was cut at MaxNames (the unknown sections too), or a
	// reference too long to read (over 4 KiB) was passed over.
	NamesTruncated bool
	// Tests and SSHTests are the numbers of elements of those sections.
	Tests, SSHTests int
	// Unknown are the sections the table does not know, in the order they were first written:
	// the unknown sections that have a row above, so at most MaxNames and none whose value is
	// null (Doc.UnknownSections lists every name, null or not).
	Unknown []string
}

// Summarise reads the shape of a policy. Its work is metered with the normal form's: one
// budget covers the reduction, the rows, the names and the walk for synced groups.
func Summarise(ctx context.Context, d *Doc) (*Summary, error) {
	m := newMeter(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	nf, err := normaliseWith(m, d)
	if err != nil {
		return nil, err
	}
	s := &Summary{}
	defined := map[string]bool{}
	type unknownRow struct {
		first int // the index in Doc.top of the first occurrence
		name  string
	}
	var unknown []unknownRow
	for _, sec := range nf.secs {
		if err := m.tick(1); err != nil {
			return nil, err
		}
		if !sec.known {
			// Unknown sections come after the known ones, by name. Past the cap a section is
			// only counted, as a name is: no row is built for it.
			if len(unknown) >= MaxNames {
				s.NamesTruncated = true
				continue
			}
			unknown = append(unknown, unknownRow{first: d.byKey[sec.fold][0], name: capText(sec.name)})
		}
		row := SectionSummary{Name: capText(sec.name), Known: sec.known, State: sec.state, Count: sec.count}
		if sec.known && sec.sec.Shape == ShapeScalar && len(sec.entries) > 0 {
			row.Scalar = capText(sec.entries[0].val)
		}
		s.Sections = append(s.Sections, row)
		var dst *[]string
		switch {
		case !sec.known:
		case sec.name == "groups":
			dst = &s.Groups
		case sec.name == "tagOwners":
			dst = &s.TagOwners
		case sec.name == "hosts":
			dst = &s.Hosts
		case sec.name == "postures":
			dst = &s.Postures
		case sec.name == "ipsets":
			dst = &s.IPSets
		case sec.name == "tests":
			s.Tests = sec.count
		case sec.name == "sshTests":
			s.SSHTests = sec.count
		}
		if dst == nil {
			continue
		}
		for _, e := range sec.entries {
			if !e.ref.named {
				continue // a section of the wrong type is kept whole, and defines nothing
			}
			// The name is cut before it is kept, and paid for by what is kept. Every group is
			// remembered as defined, though only MaxNames are listed: a group past the cut is
			// still not a synced one.
			name := capText(e.key)
			if err := m.tick(1 + len(name)); err != nil {
				return nil, err
			}
			if sec.name == "groups" {
				defined[name] = true
			}
			if len(*dst) >= MaxNames {
				s.NamesTruncated = true
				continue
			}
			*dst = append(*dst, name)
		}
	}
	// The names come in the order the text first wrote them, which is not the order of the rows.
	if err := m.tick(len(unknown)); err != nil {
		return nil, err
	}
	sort.Slice(unknown, func(i, j int) bool { return unknown[i].first < unknown[j].first })
	for _, u := range unknown {
		s.Unknown = append(s.Unknown, u.name)
	}
	synced, truncated, err := syncedGroups(m, d, defined)
	if err != nil {
		return nil, err
	}
	s.SyncedGroups, s.NamesTruncated = synced, s.NamesTruncated || truncated
	return s, nil
}

// errEnough ends the walk for synced groups once the list is full and a name does not fit.
var errEnough = errors.New("the list of synced groups is full")

// syncedGroups finds the strings in the policy's values (not its names) that look like a
// synced group, group:name@domain, and are not defined in groups. A string is read only
// once the work for it is paid for by its length, a name is cut before it is kept, and a
// string over maxSyncedRef is not decoded at all.
func syncedGroups(m *meter, d *Doc, defined map[string]bool) ([]string, bool, error) {
	seen := map[string]bool{}
	var names []string
	truncated := false
	var visit func(v *hujson.Value) error
	visit = func(v *hujson.Value) error {
		if err := m.tick(1); err != nil {
			return err
		}
		switch x := v.Value.(type) {
		case hujson.Literal:
			if x.Kind() != '"' {
				return nil
			}
			if err := m.tick(len(x)); err != nil {
				return err
			}
			str, over := syncedCandidate(v, x)
			truncated = truncated || over
			if str == "" {
				return nil
			}
			if sel, _, ok := splitDst(str); ok {
				str = sel // a destination: the ports are not part of the name
			}
			// "group:80" splits at its colon into "group" and a port: that is no name.
			if !strings.HasPrefix(str, "group:") || !strings.Contains(str[len("group:"):], "@") {
				return nil
			}
			name := capText(str)
			if defined[name] || seen[name] {
				return nil
			}
			if len(names) >= MaxNames {
				truncated = true
				return errEnough
			}
			seen[name] = true
			names = append(names, name)
		case *hujson.Array:
			for i := range x.Elements {
				if err := visit(&x.Elements[i]); err != nil {
					return err
				}
			}
		case *hujson.Object:
			for i := range x.Members {
				if err := visit(&x.Members[i].Value); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(&d.root); err != nil && !errors.Is(err, errEnough) {
		return nil, false, err
	}
	if err := m.tick(len(names)); err != nil {
		return nil, false, err
	}
	sort.Strings(names)
	return names, truncated, nil
}

// syncedCandidate decodes a string literal that starts with "group:" and is no longer than
// maxSyncedRef, or returns "". over says the string starts like a group but is too long to
// read. It decodes at most 6*maxSyncedRef bytes of a literal and only the head of a longer
// one; a literal that cannot start with "group:" is not copied.
func syncedCandidate(v *hujson.Value, lit hujson.Literal) (str string, over bool) {
	const prefix = "group:"
	body := len(lit) - 2
	escaped := bytes.IndexByte(lit, '\\') >= 0
	switch {
	case !escaped:
		if !bytes.HasPrefix(lit[1:], []byte(prefix)) {
			return "", false
		}
		if body > maxSyncedRef {
			return "", true
		}
		return string(lit[1 : len(lit)-1]), false
	case body > 6*maxSyncedRef:
		// Only the head is decoded: enough to see whether it is a group.
		return "", strings.HasPrefix(nameHead(v, len(prefix)), prefix)
	}
	str = litString(lit)
	if !strings.HasPrefix(str, prefix) {
		return "", false
	}
	if len(str) > maxSyncedRef {
		return "", true
	}
	return str, false
}

// NormalFormBytes is the canonical bytes of d's normal form, for a keyed digest that says
// whether two policies mean the same (see NormalForm.WriteTo). What WriteTo writes was paid
// for, by its bytes, while the normal form was built.
func NormalFormBytes(ctx context.Context, d *Doc) ([]byte, error) {
	nf, err := Normalise(ctx, d)
	if err != nil {
		return nil, err
	}
	return nf.Bytes(), nil
}
