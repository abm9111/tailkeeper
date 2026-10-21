package acl

import (
	"encoding/json"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/tailscale/hujson"
)

// This file reads a value the way the server's decoder does and writes it in one canonical
// JSON form: keys sorted, no whitespace, no comments, strings in one spelling of their
// escapes, and every field kept, known or not, so a field Tailscale adds later can never
// vanish from a comparison.
//
// A value that was written more than once (a section twice, a field twice in a rule) is a
// list of layers, in document order. In a struct, Go's decoder lets a later object merge into
// an earlier one and a later array, string or number replace it; in a map, a later entry for
// a key replaces the earlier one whole. objectFields reads that rule. The server refuses such
// a text (probe A-4), so this is the engine's reading of a proposal, not the server's.

// objectLayers is the trailing run of object layers: what the decoder merges. It is nil
// when the last layer is not an object.
//
// A null before an object layer resets what came before it. That is right for the pointer,
// map and slice fields the policy's structs use; a non-pointer struct field would ignore a
// null and keep its earlier fields, and no field of the policy is one. A scalar or an array
// before an object layer is no reset: the server's decoder refuses to read one into an object
// field, so it rejects the text. The layers before the last object are left out here all the
// same, so that the rest of the comparison still has a reading to work with.
func objectLayers(layers []*hujson.Value) []*hujson.Value {
	i := len(layers)
	for i > 0 {
		if _, ok := layers[i-1].Value.(*hujson.Object); !ok {
			break
		}
		i--
	}
	if i == len(layers) {
		return nil
	}
	return layers[i:]
}

// field is one key of an object, with every value written for it.
type field struct {
	name   string          // the key; for a struct, its documented spelling
	layers []*hujson.Value // the values, in document order
	names  []*hujson.Value // the member names, parallel to layers
}

// objectFields lists the keys of the merged object layers in order of first appearance.
// With fold, keys that differ only in case are one field and take the documented spelling
// (a rule is decoded into a struct) and every value written for the field is kept, to be
// merged; without it, keys are exact (a map) and a repeated key keeps its later value only.
func objectFields(m *meter, layers []*hujson.Value, fold bool) ([]field, error) {
	var out []field
	at := map[string]int{}
	for _, l := range layers {
		obj, ok := l.Value.(*hujson.Object)
		if !ok {
			continue
		}
		for i := range obj.Members {
			if err := m.tick(1); err != nil {
				return nil, err
			}
			mem := &obj.Members[i]
			key := nameOf(&mem.Name)
			id := key
			if fold {
				id = foldKey(key)
			}
			j, seen := at[id]
			if seen && !fold {
				// A map entry is replaced whole: nothing of the earlier value survives.
				out[j].layers = out[j].layers[:0]
				out[j].names = out[j].names[:0]
			}
			if !seen {
				name := key
				if fold {
					name = fieldSpelling(id)
				}
				j = len(out)
				at[id] = j
				out = append(out, field{name: name})
			}
			out[j].layers = append(out[j].layers, &mem.Value)
			out[j].names = append(out[j].names, &mem.Name)
		}
	}
	return out, nil
}

// documentedFields are the field names of the policy file's structs, as documented. The
// canonical form spells a struct's field this way whatever case the text used; a field not
// in the list is spelled in lower case.
var documentedFields = func() map[string]string {
	m := map[string]string{}
	for _, n := range []string{
		// access rules, tests, SSH rules, node attributes, DNS records
		"action", "src", "dst", "users", "ports", "proto", "srcPosture", "via", "app", "ip",
		"accept", "allow", "deny", "check", "user", "srcPostureAttrs", "target", "attr", "ipPool",
		"checkPeriod", "recorder", "enforceRecorder", "Name", "Type", "Value",
		// postures, autoApprovers, derpMap, attrConfig, externalTailnets and app connectors
		"assertions", "onFailure", "routes", "exitNode", "services", "regions", "omitDefaultRegions",
		"regionID", "regionCode", "regionName", "avoid", "nodes", "hostName", "certName", "ipv4",
		"ipv6", "stunPort", "stunOnly", "derpPort", "allowSetByNode", "broadcastToPeers",
		"externalID", "allowIncomingConnections", "allowExternalReferencesTo", "connectors", "domains",
		"presetAppID",
	} {
		m[foldKey(n)] = n
	}
	return m
}()

func fieldSpelling(foldedKey string) string {
	if n, ok := documentedFields[foldedKey]; ok {
		return n
	}
	// Lower case reads best, but lowering can join two fold classes (U+0130 lowers to "i"),
	// and two fields the server keeps apart must not get one spelling.
	if lower := strings.ToLower(foldedKey); foldKey(lower) == foldedKey {
		return lower
	}
	return foldedKey
}

// canonOpts says how the arrays and objects of a value are written.
type canonOpts struct {
	// fold: the object is a struct, so keys that differ only in case are one field.
	fold bool
	// sets: arrays of scalars are sets, written sorted and without repeats.
	sets bool
	// setFields: in a struct, the fields whose arrays are sets (by documented spelling).
	setFields map[string]bool
	// fields: in a struct, how the value of a named field (by documented spelling) is read.
	// A field not named here is read with the zero canonOpts: as a map. Ignored when fold is
	// false.
	fields map[string]canonOpts
	// elem: how the elements of an array, and the values of a map, are read. When nil they
	// are read with the zero canonOpts. Ignored for the fields of a struct (see fields).
	elem *canonOpts
}

// appendCanon writes the canonical JSON of the value whose layers are given.
func appendCanon(m *meter, buf []byte, layers []*hujson.Value, o canonOpts) ([]byte, error) {
	if err := m.tick(1); err != nil {
		return nil, err
	}
	last := layers[len(layers)-1]
	switch x := last.Value.(type) {
	case hujson.Literal:
		return appendScalar(buf, x), nil
	case *hujson.Array:
		return appendArray(m, buf, x, o)
	}
	// The only other kind is an object: the merged layers of it.
	fields, err := objectFields(m, objectLayers(layers), o.fold)
	if err != nil {
		return nil, err
	}
	return appendFields(m, buf, fields, "", o)
}

// appendFields writes fields as an object, in key order, leaving out the one named skip.
//
// A value inside the object is read with the options o describes for it (see canonOpts.child).
// One the caller does not describe is read as a map. That reading loses case folding and the
// merging of a repeated object-valued field, so a nested struct read as a map can canonicalise
// two policies alike that the server reads differently. Callers describe the schema's nested
// structs.
func appendFields(m *meter, buf []byte, fields []field, skip string, o canonOpts) ([]byte, error) {
	sort.Slice(fields, func(i, j int) bool { return fields[i].name < fields[j].name })
	buf = append(buf, '{')
	first := true
	for _, f := range fields {
		if f.name == skip {
			continue
		}
		if !first {
			buf = append(buf, ',')
		}
		first = false
		buf = appendJSONString(buf, f.name)
		buf = append(buf, ':')
		var err error
		child := o.child(f.name)
		if buf, err = appendCanon(m, buf, f.layers, child); err != nil {
			return nil, err
		}
	}
	return append(buf, '}'), nil
}

// child is the options for the value of the field named name (its documented spelling in a
// struct, the exact key in a map). A struct's field takes o.fields[name]; the value of a map
// takes o.elem; neither described is the zero canonOpts, a map. Sets carry down: the child is
// a set where o is, or where o.setFields names the field.
func (o canonOpts) child(name string) canonOpts {
	var c canonOpts
	if o.fold {
		c = o.fields[name]
	} else if o.elem != nil {
		c = *o.elem
	}
	c.sets = c.sets || o.sets || o.setFields[name]
	return c
}

// element is the options for an element of an array: o.elem, set where o is.
func (o canonOpts) element() canonOpts {
	var c canonOpts
	if o.elem != nil {
		c = *o.elem
	}
	c.sets = c.sets || o.sets
	return c
}

// appendArray writes an array. An element that is an object is read with o.elem, and with the
// zero canonOpts (a map) when the caller does not describe it; see appendFields.
func appendArray(m *meter, buf []byte, a *hujson.Array, o canonOpts) ([]byte, error) {
	if o.sets && allScalars(a) {
		texts := make([]string, 0, len(a.Elements))
		for i := range a.Elements {
			if err := m.tick(1); err != nil {
				return nil, err
			}
			texts = append(texts, string(appendScalar(nil, a.Elements[i].Value.(hujson.Literal))))
		}
		var err error
		if texts, err = sortedUnique(m, texts); err != nil {
			return nil, err
		}
		buf = append(buf, '[')
		for i, t := range texts {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = append(buf, t...)
		}
		return append(buf, ']'), nil
	}
	buf = append(buf, '[')
	for i := range a.Elements {
		if i > 0 {
			buf = append(buf, ',')
		}
		var err error
		if buf, err = appendCanon(m, buf, []*hujson.Value{&a.Elements[i]}, o.element()); err != nil {
			return nil, err
		}
	}
	return append(buf, ']'), nil
}

func allScalars(a *hujson.Array) bool {
	for i := range a.Elements {
		if _, ok := a.Elements[i].Value.(hujson.Literal); !ok {
			return false
		}
	}
	return true
}

// sortedUnique sorts texts and drops repeats, counting the comparisons as work.
func sortedUnique(m *meter, texts []string) ([]string, error) {
	sort.Slice(texts, func(i, j int) bool {
		m.used++
		return texts[i] < texts[j]
	})
	if err := m.tick(0); err != nil {
		return nil, err
	}
	out := texts[:0]
	for i, t := range texts {
		if i == 0 || t != texts[i-1] {
			out = append(out, t)
		}
	}
	return out, nil
}

// appendScalar writes a string in one spelling of its escapes, and a number, true, false
// or null as written.
func appendScalar(buf []byte, lit hujson.Literal) []byte {
	if lit.Kind() == '"' {
		return appendJSONString(buf, litString(lit))
	}
	return append(buf, lit...)
}

// litString decodes a string literal. U+FFFD stands for what Go's decoder reads for an
// unpaired surrogate escape.
func litString(lit hujson.Literal) string {
	if !strings.Contains(string(lit), `\`) {
		return string(lit[1 : len(lit)-1])
	}
	var s string
	if json.Unmarshal(lit, &s) != nil {
		return string(lit)
	}
	return s
}

const hexDigits = "0123456789abcdef"

// appendJSONString writes s as a JSON string with the minimal escapes.
func appendJSONString(buf []byte, s string) []byte {
	buf = append(buf, '"')
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			buf = append(buf, '\\', c)
		case c == '\n':
			buf = append(buf, '\\', 'n')
		case c == '\r':
			buf = append(buf, '\\', 'r')
		case c == '\t':
			buf = append(buf, '\\', 't')
		case c < 0x20 || c == 0x7f:
			buf = append(buf, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&15])
		case c < utf8.RuneSelf:
			buf = append(buf, c)
		default:
			r, n := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && n == 1 {
				buf = append(buf, "\ufffd"...)
			} else {
				buf = append(buf, s[i:i+n]...)
			}
			i += n
			continue
		}
		i++
	}
	return append(buf, '"')
}
