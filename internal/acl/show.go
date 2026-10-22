package acl

import (
	"math"

	"github.com/tailscale/hujson"
)

// Show is how a caller sees a piece of a policy's text: masked, with the markers it must not
// forge rewritten. It returns the first need bytes of what the caller sees of s, or all of it
// when that is shorter; it may return more. A result cuts what it quotes only after Show has
// run, because masking changes the length of a text and a cut made before it would fall where
// the real text says (a login a caller never saw, and how long it is) and not where the shown
// text does.
type Show func(s string, need int) string

// wholeText asks a Show for all of a text.
const wholeText = math.MaxInt32

// shownRead is how many times as many bytes of a name that is read from the tree as are
// needed are read before Show runs on them: masking a login shortens it, so the bytes that
// make a prefix of the shown name are more than the bytes that long.
const shownRead = 16

// view is a policy as one side of a comparison shows it: the Doc, and the Show that says what
// a caller sees of its text. A zero view shows text as it is.
type view struct {
	doc  *Doc
	show Show
}

// view is the Doc as the view its own Show gives: the one that every echo of the text the Doc
// was parsed from (a finding, a location, a name) goes through. A nil Doc is a zero view.
func (d *Doc) view() view {
	if d == nil {
		return view{}
	}
	return view{doc: d, show: d.show}
}

// shown is what a caller sees of s, at least its first need bytes.
func (v view) shown(s string, need int) string {
	if v.show == nil {
		return s
	}
	return v.show(s, need)
}

// cut is capText of what a caller sees of s.
func (v view) cut(s string) string { return capText(v.shown(s, maxPointer+1)) }

// capped is the Text of a string that is already built, as a caller sees it: cut at 1 KiB.
func (v view) capped(s string) Text { return capped(v.shown(s, maxPointer+1)) }

// shownName is the head of what a caller sees of the name n: at least need bytes of it, or all
// of it. Only a head of the name is read, as nameHead does, so a name of 500 KB costs about
// what one of 1 KiB does.
func (v view) shownName(n *hujson.Value, need int) string {
	if v.show == nil {
		return nameHead(n, need)
	}
	return v.show(nameHead(n, need*shownRead), need)
}

// pointerOf is the JSON Pointer of what a ref names, cut at 1 KiB of what a caller sees.
func (v view) pointerOf(r ref) string { return v.doc.pointerIn(v, r) }

func (d *Doc) cut(s string) string                        { return d.view().cut(s) }
func (d *Doc) shownName(n *hujson.Value, need int) string { return d.view().shownName(n, need) }

// UnknownSectionsShown are the names UnknownSections lists, in step with it, as the caller
// may see them: each cut after Show ran on it. The names themselves are for comparing, these
// for printing.
func (d *Doc) UnknownSectionsShown() []string { return d.unknownShown }
