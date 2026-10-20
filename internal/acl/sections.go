package acl

import "slices"

// Shape says how a section is read and compared.
type Shape uint8

const (
	// ShapeRules is an array of access rules, reduced to atoms: acls and grants, which
	// the admin console rewrites into each other, share one pool of atoms.
	ShapeRules Shape = iota + 1
	// ShapeSet is an array of objects compared as a multiset of canonical elements:
	// ssh and extraDNSRecords.
	ShapeSet
	// ShapeTests is an array of test objects reduced to assertions: tests and sshTests.
	ShapeTests
	// ShapeNodeAttrs is nodeAttrs, whose entries are additive.
	ShapeNodeAttrs
	// ShapeMap is an object of named entries compared key by key.
	ShapeMap
	// ShapeStruct is an object of fields compared field by field, and key by key inside
	// a field that is a map: autoApprovers and derpMap.
	ShapeStruct
	// ShapeScalar is a single value.
	ShapeScalar
	// ShapeList is an array read as one set of strings: defaultSrcPosture.
	ShapeList
)

// Order says what a section's order means.
type Order uint8

const (
	// OrderNone: there is no order to speak of (a scalar).
	OrderNone Order = iota + 1
	// OrderInsensitive: the arrays are sets. Reordering them never changes what the server
	// enforces (SSH evaluates "check" before "accept" whatever the order), so a reorder is
	// counted as a format change.
	OrderInsensitive
	// OrderSensitive: the arrays are lists processed in order, so a reorder is a change.
	// Today that is the operation lists inside ipsets values ("add" and "remove" are
	// processed in order) and the node lists of derpMap, which are compared in order
	// (conservative: only the ipsets operation lists need an order). The readers apply this
	// rule through keyedOpts, structOpts and the shapes, not through this field, and
	// TestSectionOrderIsWhatTheReadersDo compares the two for every section.
	OrderSensitive
)

// Section is one entry of the table of sections the engine knows.
type Section struct {
	// Name is the spelling Tailscale documents; the server reads names without regard to
	// case.
	Name  string
	Shape Shape
	Order Order
	// StructElements says what a nested object in the section looks like to the server's
	// decoder: the rules of an array are structs, whose field names fold case; the entries
	// of a map are exact.
	StructElements bool
}

// sections are the top-level sections of a policy file, in the order a normal form lists
// them. The list is the documented sections plus the ones the docs mention elsewhere
// (defaultSrcPosture, extraDNSRecords) and the ones in Tailscale's own Go client
// (externalTailnets, attrConfig). TestSectionsCoverTheClientStruct fails when a bump of
// tailscale.com/client/tailscale/v2 adds one this table lacks. The check is one-directional:
// the client struct has no sshTests or extraDNSRecords.
//
// nodeAttr (singular) is not an alias of nodeAttrs: case folding does not make them equal.
var sections = []Section{
	{"acls", ShapeRules, OrderInsensitive, true},
	{"autoApprovers", ShapeStruct, OrderInsensitive, false},
	{"grants", ShapeRules, OrderInsensitive, true},
	{"groups", ShapeMap, OrderInsensitive, false},
	{"hosts", ShapeMap, OrderNone, false},
	{"ipsets", ShapeMap, OrderSensitive, false},
	{"nodeAttrs", ShapeNodeAttrs, OrderInsensitive, true},
	{"postures", ShapeMap, OrderInsensitive, false},
	{"ssh", ShapeSet, OrderInsensitive, true},
	{"sshTests", ShapeTests, OrderInsensitive, true},
	{"tagOwners", ShapeMap, OrderInsensitive, false},
	{"tests", ShapeTests, OrderInsensitive, true},
	{"derpMap", ShapeStruct, OrderSensitive, false},
	{"disableIPv4", ShapeScalar, OrderNone, false},
	{"OneCGNATRoute", ShapeScalar, OrderNone, false},
	{"randomizeClientPort", ShapeScalar, OrderNone, false},
	{"defaultSrcPosture", ShapeList, OrderInsensitive, false},
	{"extraDNSRecords", ShapeSet, OrderInsensitive, true},
	{"externalTailnets", ShapeMap, OrderInsensitive, false},
	{"attrConfig", ShapeMap, OrderInsensitive, false},
}

// sectionKey is the key under which a top-level name is looked up: the server matches
// the name of a section without regard to case.
func sectionKey(name string) string { return foldKey(name) }

// Sections returns the known sections in the order a normal form lists them. It is a copy: the
// table itself is private, so a caller cannot make it disagree with the index built from it.
func Sections() []Section { return slices.Clone(sections) }

var sectionIndex = func() map[string]int {
	m := make(map[string]int, len(sections))
	for i, s := range sections {
		m[sectionKey(s.Name)] = i
	}
	return m
}()

// SectionByName finds a known section by a name spelled in any case.
func SectionByName(name string) (Section, bool) {
	i, ok := sectionIndex[sectionKey(name)]
	if !ok {
		return Section{}, false
	}
	return sections[i], true
}

// sectionPos is the position of a known section in Sections, or -1.
func sectionPos(name string) int {
	if i, ok := sectionIndex[sectionKey(name)]; ok {
		return i
	}
	return -1
}
