package acl

import (
	"bytes"
	"context"

	"github.com/tailscale/hujson"
)

// Match says how a location matched what was asked for.
type Match string

const (
	// MatchSrcAndDestination: a test whose source and one of whose destinations are the ones
	// the failure names.
	MatchSrcAndDestination Match = "src_and_destination"
	// MatchSrcOnly: a test with the failure's source. It is every candidate when the failure
	// names no destination, or none of the tests with that source lists the destination (the
	// server may quote an address where the test wrote a name).
	MatchSrcOnly Match = "src_only"
	// MatchKey and MatchValue: a name or a string in the text that is the token asked for.
	MatchKey   Match = "key"
	MatchValue Match = "value"
)

// Location is a place in the text.
type Location struct {
	Match   Match
	Pointer string // JSON Pointer, cut at 1 KiB
	Line    int
	Column  int
}

// Failure is what the server's message says about a failed test: the source of the test
// (the legacy field is named user) and, if the message names one, the destination.
type Failure struct {
	Src string
	Dst string
	// SSH: the failure is of an entry of sshTests, not tests.
	SSH bool
}

// MaxLocations is the most places a location search lists.
const MaxLocations = 100

// The fields of a test that Locate reads.
const (
	fSrc = iota
	fUser
	fAccept
	fAllow
	fDeny
	fDst
	nTestFields
)

// testFieldKeys are the fold keys of those fields: the server decodes a test into a struct,
// so a key matches without regard to case.
var testFieldKeys = [nTestFields]string{
	fSrc: foldKey("src"), fUser: foldKey("user"), fAccept: foldKey("accept"),
	fAllow: foldKey("allow"), fDeny: foldKey("deny"), fDst: foldKey("dst"),
}

// maxFieldLiteral is the longest raw name (quoted, escapes undecoded) that can be one of the
// fields above: the longest is six characters of at most three bytes, and an escape is six
// raw bytes for at least one decoded one. A longer name is passed over unread.
const maxFieldLiteral = 2 + 6*3*6

// Locate finds the tests a failure can be about. It matches the source, written src or
// user, and, when the failure names a destination, the destination among the accept, allow
// and deny entries (an SSH test's dst), by their text. A failure that names no destination,
// or whose destination no test with that source lists, gets every test with that source,
// labelled as such: the answer is never "cannot tell". Lines refer to d, the caller's own
// document; a caller that built the text it sent maps them back.
//
// It lists at most MaxLocations, and cut is how many more places match in the kind of match
// returned (as LocateToken counts the rest), so a caller can tell a list of 100 from one of
// 1,000. No match is no locations and 0 cut: not a verdict on the policy.
//
// Locate takes no context and is bounded by construction. It makes one pass over the
// elements of one section and over the members of each element, so its work is at most
// the size of the text Parse accepted (MaxBytes, MaxNodes values). Nothing is decoded that
// the length of the text cannot rule out (see litEquals), a member name is read only if it
// is short enough to be one of the six fields, and a location (its pointer and line) is
// built only while the list has room: at most MaxLocations of each kind.
func Locate(d *Doc, f Failure) (locations []Location, cut int) {
	if d == nil || d.root.Value == nil {
		return nil, 0
	}
	name := "tests"
	if f.SSH {
		name = "sshTests"
	}
	occ := d.byKey[sectionKey(name)]
	if len(occ) == 0 {
		return nil, 0
	}
	top := occ[len(occ)-1] // the later array replaces the earlier
	arr, ok := d.top[top].val.Value.(*hujson.Array)
	if !ok {
		return nil, 0
	}
	dstFields := []int{fAccept, fAllow, fDeny}
	if f.SSH {
		dstFields = []int{fDst}
	}
	var bySrc, byDst []Location
	var nSrc, nDst int // every match, listed or not
	for i := range arr.Elements {
		el := &arr.Elements[i]
		obj, ok := el.Value.(*hujson.Object)
		if !ok {
			continue
		}
		vals := testFields(obj)
		if !hasString(vals[fSrc], f.Src) && !hasString(vals[fUser], f.Src) {
			continue
		}
		toDst := f.Dst != ""
		if toDst {
			toDst = false
			for _, k := range dstFields {
				if hasString(vals[k], f.Dst) {
					toDst = true
					break
				}
			}
		}
		nSrc++
		if toDst {
			nDst++
		}
		listSrc, listDst := len(bySrc) < MaxLocations, toDst && len(byDst) < MaxLocations
		if !listSrc && !listDst {
			continue // counted, and nothing is built for it
		}
		line, col := d.Position(el.StartOffset)
		loc := Location{Match: MatchSrcOnly, Pointer: d.pointerOf(ref{val: el, top: top, idx: i}), Line: line, Column: col}
		if listSrc {
			bySrc = append(bySrc, loc)
		}
		if listDst {
			loc.Match = MatchSrcAndDestination
			byDst = append(byDst, loc)
		}
	}
	if len(byDst) > 0 {
		return byDst, nDst - len(byDst)
	}
	return bySrc, nSrc - len(bySrc)
}

// testFields finds the value written for each field Locate reads: the last one when a field
// is repeated, because a string or an array written later replaces an earlier one. One case
// differs from the server's decoder: a null written after a string for src or user is
// ignored by Go, which keeps the earlier string, and here it is the value, so the test does
// not match by that string. It is rare, and Parse reports the repetition as duplicate_key.
// The server refuses a repeated key (probe A-4), but a proposal can carry one, and Locate
// still reads it the way Go's decoder does.
func testFields(obj *hujson.Object) [nTestFields]*hujson.Value {
	var vals [nTestFields]*hujson.Value
	for i := range obj.Members {
		mem := &obj.Members[i]
		lit, ok := mem.Name.Value.(hujson.Literal)
		if !ok || len(lit) > maxFieldLiteral {
			continue
		}
		key := foldKey(nameOf(&mem.Name))
		for k := range testFieldKeys {
			if key == testFieldKeys[k] {
				vals[k] = &mem.Value
			}
		}
	}
	return vals
}

// hasString reports whether the text want is, or is among, the strings of v.
func hasString(v *hujson.Value, want string) bool {
	if v == nil {
		return false
	}
	switch x := v.Value.(type) {
	case hujson.Literal:
		return litEquals(x, want)
	case *hujson.Array:
		for i := range x.Elements {
			if lit, ok := x.Elements[i].Value.(hujson.Literal); ok && litEquals(lit, want) {
				return true
			}
		}
	}
	return false
}

// litEquals reports whether the string literal lit (quoted, as written) decodes to want.
func litEquals(lit hujson.Literal, want string) bool {
	return litFits(lit, want) && litIs(lit, want)
}

// litFits reports whether the string literal lit can decode to something as long as want.
// The length of the literal rules most of them out before a byte is read: every byte of the
// text decodes to one byte or fewer, and an escape of six bytes decodes to at least one.
func litFits(lit hujson.Literal, want string) bool {
	if lit.Kind() != '"' {
		return false
	}
	body := len(lit) - 2
	return len(want) <= body && 6*len(want)+5 >= body
}

// litIs reports whether a literal that fits decodes to want. It reads the literal once, so
// what it spends is bounded by 6*len(want) a literal and by the size of the text in all.
func litIs(lit hujson.Literal, want string) bool {
	if bytes.IndexByte(lit, '\\') < 0 {
		return string(lit[1:len(lit)-1]) == want
	}
	return litString(lit) == want
}

// LocateToken finds every place the text holds the token as a name or as a string: where a
// server message quotes a tag or a group ("tag:x"), the failing element is one of these.
// It lists at most MaxLocations in document order and counts the rest.
func LocateToken(ctx context.Context, d *Doc, token string) ([]Location, int, error) {
	if err := checkDoc(d); err != nil {
		return nil, 0, err
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	w := &tokenWalker{d: d, m: newMeter(ctx), token: token}
	if err := w.walk(&d.root); err != nil {
		return nil, 0, err
	}
	return w.found, w.more, nil
}

type tokenWalker struct {
	d     *Doc
	m     *meter
	token string
	path  []pathElem
	found []Location
	more  int
}

// hit records a place. Past MaxLocations it only counts: no pointer is built for it.
func (w *tokenWalker) hit(v *hujson.Value, match Match) {
	if len(w.found) >= MaxLocations {
		w.more++
		return
	}
	line, col := w.d.Position(v.StartOffset)
	w.found = append(w.found, Location{Match: match, Pointer: w.d.pathPointer(w.path), Line: line, Column: col})
}

// isToken reports whether v is a string that decodes to the token. A literal the length
// test lets through is read once, and paid for by its bytes before it is.
func (w *tokenWalker) isToken(v *hujson.Value) (bool, error) {
	lit, ok := v.Value.(hujson.Literal)
	if !ok || !litFits(lit, w.token) {
		return false, nil
	}
	if err := w.m.tick(len(lit)); err != nil {
		return false, err
	}
	return litIs(lit, w.token), nil
}

func (w *tokenWalker) walk(v *hujson.Value) error {
	if err := w.m.tick(1); err != nil {
		return err
	}
	switch x := v.Value.(type) {
	case hujson.Literal:
		if is, err := w.isToken(v); err != nil {
			return err
		} else if is {
			w.hit(v, MatchValue)
		}
	case *hujson.Array:
		for i := range x.Elements {
			w.path = append(w.path, pathElem{idx: i})
			err := w.walk(&x.Elements[i])
			w.path = w.path[:len(w.path)-1]
			if err != nil {
				return err
			}
		}
	case *hujson.Object:
		for i := range x.Members {
			mem := &x.Members[i]
			if err := w.m.tick(1); err != nil { // the name
				return err
			}
			w.path = append(w.path, pathElem{key: &mem.Name})
			is, err := w.isToken(&mem.Name)
			if err == nil {
				if is {
					w.hit(&mem.Name, MatchKey)
				}
				err = w.walk(&mem.Value)
			}
			w.path = w.path[:len(w.path)-1]
			if err != nil {
				return err
			}
		}
	}
	return nil
}
