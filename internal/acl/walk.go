package acl

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"

	"github.com/tailscale/hujson"
)

// FindingCode names a structural problem Parse found.
type FindingCode string

const (
	// FindingDuplicateKey is an object that holds the same key twice, at any depth: a
	// group defined twice inside "groups" is one.
	FindingDuplicateKey FindingCode = "duplicate_key"
	// FindingCaseCollision is an object whose field names the server's decoder folds to
	// the same name though they are spelled differently ("tests" and "Tests"). It is
	// reported only where the server decodes into a struct, which is where the normal form
	// folds too: the top level, the elements of the array sections, the fields of
	// autoApprovers and derpMap and the structs inside derpMap (a region and its nodes), and
	// the values of postures, attrConfig and externalTailnets. The keys of a map ("group:a"
	// and "group:A") are distinct.
	FindingCaseCollision FindingCode = "case_collision"
)

// Keeps says which value the server's decoder keeps when a key is repeated.
type Keeps string

const (
	// KeepsLater: the later value replaces the earlier one (an array, a scalar, or a map
	// entry).
	KeepsLater Keeps = "later"
	// KeepsMerged: both are objects and the decoder merges them, the later value winning
	// per key.
	KeepsMerged Keeps = "merged"
)

// Finding is one repeated key. The generic HuJSON tree keeps both; the server keeps one
// reading, which Keeps names, and everything after Parse reads the policy that way.
type Finding struct {
	Code FindingCode
	// Pointer is the JSON Pointer of the object that holds the key, cut at 1 KiB.
	Pointer string
	// Key and FirstKey are the two spellings, the later and the first (each cut at 1 KiB).
	Key, FirstKey string
	// Line and Column place the later key; FirstLine and FirstColumn the first.
	Line, Column           int
	FirstLine, FirstColumn int
	Keeps                  Keeps
}

// MaxFindings is how many findings Parse keeps; the rest are counted.
const MaxFindings = 100

// maxPointer cuts a pointer or a key quoted in a finding.
const maxPointer = 1 << 10

// occurrence is one top-level member of the policy.
type occurrence struct {
	name string // the spelling in the text
	key  *hujson.Value
	val  *hujson.Value
}

type pathElem struct {
	key *hujson.Value // a member name, or nil
	idx int           // an element index when key is nil
}

type walker struct {
	d    *Doc
	m    *meter
	path []pathElem
}

// analyse walks the tree once: it counts the values, spends the work budget, finds the
// repeated keys at any depth, and records the top-level members and the sections the table
// does not know.
func (d *Doc) analyse(m *meter) error {
	w := &walker{d: d, m: m}
	if err := w.walk(&d.root, canonOpts{fold: true}, true); err != nil {
		return err
	}
	sort.SliceStable(d.findings, func(i, j int) bool {
		a, b := d.findings[i], d.findings[j]
		return a.Line < b.Line || a.Line == b.Line && a.Column < b.Column
	})
	obj := d.root.Value.(*hujson.Object)
	d.byKey = make(map[string][]int, len(obj.Members))
	seenUnknown := map[string]bool{}
	for i := range obj.Members {
		mem := &obj.Members[i]
		name := nameOf(&mem.Name)
		d.top = append(d.top, occurrence{name: name, key: &mem.Name, val: &mem.Value})
		k := sectionKey(name)
		d.byKey[k] = append(d.byKey[k], i)
		if _, known := sectionIndex[k]; !known && !seenUnknown[k] {
			seenUnknown[k] = true
			d.unknown = append(d.unknown, capText(name))
		}
	}
	return nil
}

// walk reads a value with the options the normal form reads it with (canonOpts, and readOpts
// for a section), so Parse finds a repeated key exactly where Normalise folds or merges one:
// the keys of a struct match without regard to case and the keys of a map are exact.
func (w *walker) walk(v *hujson.Value, o canonOpts, top bool) error {
	w.d.nodes++
	if err := w.m.tick(1); err != nil {
		return err
	}
	switch x := v.Value.(type) {
	case *hujson.Object:
		return w.object(x, o, top)
	case *hujson.Array:
		for i := range x.Elements {
			w.path = append(w.path, pathElem{idx: i})
			err := w.walk(&x.Elements[i], o.element(), false)
			w.path = w.path[:len(w.path)-1]
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// smallObject is the member count up to which repeated keys are found by comparing every
// pair, which allocates nothing; larger objects use a map.
const smallObject = 8

func (w *walker) object(obj *hujson.Object, o canonOpts, top bool) error {
	n := len(obj.Members)
	names := make([]string, n)
	for i := range obj.Members {
		names[i] = nameOf(&obj.Members[i].Name)
	}
	if n >= 2 {
		if err := w.repeats(obj, names, o.fold); err != nil {
			return err
		}
	}
	for i := range obj.Members {
		mem := &obj.Members[i]
		w.d.nodes++ // the name
		if err := w.m.tick(1); err != nil {
			return err
		}
		var child canonOpts
		if top {
			if pos := sectionPos(names[i]); pos >= 0 {
				child = readOpts(sections[pos])
			}
		} else if !o.fold || len(o.fields) > 0 {
			name := names[i]
			if o.fold {
				name = fieldSpelling(foldKey(name)) // a struct's fields are described by their documented spelling
			}
			child = o.child(name)
		}
		w.path = append(w.path, pathElem{key: &mem.Name})
		err := w.walk(&mem.Value, child, false)
		w.path = w.path[:len(w.path)-1]
		if err != nil {
			return err
		}
	}
	return nil
}

// repeats reports each key of o that repeats an earlier one. In a struct (fold) the names
// match without regard to case.
func (w *walker) repeats(o *hujson.Object, names []string, fold bool) error {
	key := func(i int) string {
		if fold {
			return foldKey(names[i])
		}
		return names[i]
	}
	report := func(first, later int) {
		// Past the cap a repeat is only counted: nothing is built for it, so the cost of
		// the repeats of a deep or long-keyed object stays with the meter's ticks.
		if len(w.d.findings) >= MaxFindings {
			w.d.omitted++
			return
		}
		code := FindingDuplicateKey
		if names[first] != names[later] {
			code = FindingCaseCollision
		}
		// Only a struct-valued field merges; a map entry written twice keeps the later value
		// even when both are objects.
		keeps := KeepsLater
		_, a := o.Members[first].Value.Value.(*hujson.Object)
		_, b := o.Members[later].Value.Value.(*hujson.Object)
		if a && b && fold {
			keeps = KeepsMerged
		}
		w.record(Finding{
			Code: code, Pointer: w.pointer(), Key: capText(names[later]), FirstKey: capText(names[first]),
			Keeps: keeps,
		}, &o.Members[first].Name, &o.Members[later].Name)
	}
	if len(names) <= smallObject {
		if err := w.m.tick(len(names) * len(names) / 2); err != nil {
			return err
		}
		for later := 1; later < len(names); later++ {
			for first := 0; first < later; first++ {
				if key(first) == key(later) {
					report(first, later)
					break
				}
			}
		}
		return nil
	}
	firstAt := make(map[string]int, len(names))
	for later := range names {
		if err := w.m.tick(1); err != nil {
			return err
		}
		k := key(later)
		if first, seen := firstAt[k]; seen {
			report(first, later)
			continue
		}
		firstAt[k] = later
	}
	return nil
}

func (w *walker) record(f Finding, first, later *hujson.Value) {
	f.Line, f.Column = w.d.Position(later.StartOffset)
	f.FirstLine, f.FirstColumn = w.d.Position(first.StartOffset)
	w.d.findings = append(w.d.findings, f)
}

// pointer is the JSON Pointer of the current path.
func (w *walker) pointer() string { return pointerOf(w.path) }

// pointerOf is the JSON Pointer of a path, cut at maxPointer bytes. It is built for a
// finding only, never for a node, and stops early: a pointer for every node would be as
// long as the sum of the keys above it, which is quadratic in the text.
func pointerOf(path []pathElem) string {
	var b []byte
	for _, e := range path {
		b = append(b, '/')
		if e.key != nil && len(b) <= maxPointer {
			// Only the head of a name that could still fit is decoded: a key of 500 KB
			// costs about as much as one of 1 KiB.
			b = append(b, escapePointer(nameHead(e.key, maxPointer+1-len(b)))...)
		} else if e.key == nil {
			b = strconv.AppendInt(b, int64(e.idx), 10)
		}
		if len(b) > maxPointer {
			return capText(string(b))
		}
	}
	return string(b)
}

// nameHead is nameOf, except that a name much longer than need bytes comes back cut: the
// result is a prefix of the decoded name holding at least need bytes (an escape decodes to
// no fewer than a sixth of its length, and the cut leaves whole escapes and characters).
func nameHead(v *hujson.Value, need int) string {
	lit, ok := v.Value.(hujson.Literal)
	limit := 6*(need+4) + 16
	if !ok || len(lit) <= limit {
		return nameOf(v)
	}
	i := 1
	for i < limit {
		step := 1
		if lit[i] == '\\' {
			step = 2
			if lit[i+1] == 'u' {
				step = 6
			}
		}
		if i+step > limit {
			break
		}
		i += step
	}
	for i > 1 && !runeStart(lit[i]) {
		i--
	}
	head := append(bytes.Clone(lit[:i]), '"')
	var s string
	if json.Unmarshal(head, &s) != nil {
		return string(lit[1:i])
	}
	return s
}

// capText cuts s at maxPointer bytes on a rune boundary.
func capText(s string) string {
	if len(s) <= maxPointer {
		return s
	}
	cut := maxPointer
	for cut > 0 && !runeStart(s[cut]) {
		cut--
	}
	return s[:cut] + "\u2026"
}

// Findings are the repeated keys Parse found, at most MaxFindings, in document order.
func (d *Doc) Findings() []Finding { return d.findings }

// FindingsOmitted is how many repeated keys Parse found beyond MaxFindings.
func (d *Doc) FindingsOmitted() int { return d.omitted }

// UnknownSections are the top-level names (each once, as first spelled) that the table of
// sections does not know. In the live policy that means tailkeeper is stale: Tailscale
// accepted a section this version does not know. In a proposal it means the server will
// probably reject it ("json: unknown field"). The wording differs; neither is an error
// here.
func (d *Doc) UnknownSections() []string { return d.unknown }
