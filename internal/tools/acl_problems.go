package tools

import (
	"context"

	"github.com/abm9111/tailkeeper/internal/acl"
)

// The kinds of an ACLProblem. They are tailkeeper's own words, never text from a policy or
// from Tailscale, so the class test lists them as constants.
const (
	kindSyntax          = "syntax"           // the text is not valid HuJSON
	kindEncoding        = "encoding"         // a byte order mark, UTF-16, a NUL or invalid UTF-8
	kindStructure       = "structure"        // the top level is not an object, the nesting is past the guard, an invariants file holds more than tests
	kindDuplicateKey    = "duplicate_key"    // an object writes a key twice
	kindCaseCollision   = "case_collision"   // an object writes two keys that differ only in case
	kindUnknownSection  = "unknown_section"  // a top-level section tailkeeper does not know
	kindAssertionFailed = "assertion_failed" // a test of the policy failed
	kindUnevaluable     = "test_unevaluable" // a test names something Tailscale cannot resolve, or is malformed
	kindInvariantFailed = "invariant"        // a test of the invariants file failed
	kindServerMessage   = "server_message"   // Tailscale refused the text, or answered in a way tailkeeper does not read
	kindWarning         = "warning"          // a warning of the policy
	kindNote            = "note"             // tailkeeper's own remark about the result
)

// The severities of an ACLProblem.
const (
	severityError   = "error"
	severityWarning = "warning"
	severityNotice  = "notice"
)

// The sources of an ACLProblem: the text its location is in.
const (
	sourceFrom       = "from"       // the proposal the caller gave
	sourceAgainst    = "against"    // the old policy a diff was asked to start from
	sourceInvariants = "invariants" // the invariants file
	sourceLive       = "live"       // the live policy
	sourcePatch      = "patch"      // the patch, or the live policy with the patch applied: a pointer into that policy, no line
)

// ACLProblem is one thing a validation found, placed in the text it is about. Line and
// Column are counted as Tailscale counts them: lines by line feed, columns in bytes.
type ACLProblem struct {
	Kind           string `json:"kind" jsonschema:"the kind of finding, as the tool's description lists"`
	Severity       string `json:"severity" jsonschema:"error, warning or notice"`
	Source         string `json:"source" jsonschema:"where the position is: from, against, patch (the patch, or the policy it makes: a pointer), invariants or live; empty for a message about the text as a whole"`
	Line           int    `json:"line,omitempty" jsonschema:"from 1, counting line feeds as Tailscale does; absent when unknown"`
	Column         int    `json:"column,omitempty" jsonschema:"in bytes, from 1"`
	Pointer        string `json:"pointer,omitempty" tk:"untrusted,emails" jsonschema:"JSON pointer, when the line is not known"`
	Message        string `json:"message" tk:"untrusted,emails"`
	FromTailscale  bool   `json:"fromTailscale" jsonschema:"Tailscale's own text"`
	MoreCandidates int    `json:"moreCandidates,omitempty" jsonschema:"more places match, past the cap"`
}

// placeBasis says how a server message was placed in the caller's own text.
type placeBasis string

const (
	// notPlaced: the message names nothing the text can be searched for.
	notPlaced placeBasis = ""
	// placedByPosition: the message begins with the server's own "line N, column M:".
	placedByPosition placeBasis = "position"
	// placedByTest: a failed assertion; the tests whose src, and destination when the line
	// names one, are the ones the line is about.
	placedByTest placeBasis = "test"
	// placedByToken: the first quoted name of the message, wherever the text holds it.
	placedByToken placeBasis = "token"
)

// placement is where one server message sits in the caller's own document.
type placement struct {
	basis placeBasis
	// line and column are the server's own, for placedByPosition (lines count line feeds,
	// columns count bytes).
	line, column int
	// locations are the candidates, at most acl.MaxLocations; cut is how many more match.
	// Candidates are never "cannot tell": a message that matches nothing has none and a cut
	// of 0, which is not a verdict on the policy.
	locations []acl.Location
	cut       int
}

// placeMessage finds where one message of a validate reply sits in d, the caller's own
// document, for a test whose source is src. An assertion in the want/got grammar is placed
// by its test; a message that starts with a position is placed by it; any other message by
// the first name it quotes. The order matters: a name that embeds a position or a verdict
// must not choose the way a message is read, so the grammar is tried first and is anchored.
func placeMessage(ctx context.Context, d *acl.Doc, src, msg string) (placement, error) {
	if f := ParseFailureLine(msg); f.Kind == AssertionFailed {
		locs, cut := acl.Locate(d, f.Failure(src))
		return placement{basis: placedByTest, locations: locs, cut: cut}, nil
	}
	if line, col, ok := positionIn(msg); ok {
		return placement{basis: placedByPosition, line: line, column: col}, nil
	}
	tok, ok := quotedToken(msg)
	if !ok {
		return placement{basis: notPlaced}, nil
	}
	locs, cut, err := acl.LocateToken(ctx, d, tok)
	if err != nil {
		return placement{}, err
	}
	return placement{basis: placedByToken, locations: locs, cut: cut}, nil
}

// addPlaced files a problem about a message of the reply once for each place the message
// can be about, so that a name Tailscale quotes is never shown at one line when it is on
// several. The first problem carries the server's message and the count of places left out
// (MoreCandidates); each is labelled with how it matched. A message that matches nothing is
// filed as it is, with no position: that is not a verdict on the text. A problem found in a
// patched text carries a pointer and no line, since the caller never wrote that text.
func (v *validation) addPlaced(base ACLProblem, pl placement, source string) {
	switch pl.basis {
	case placedByPosition:
		base.Source = source
		if source == sourcePatch {
			// The server counted the lines and the bytes of the policy the patch makes, a text
			// the caller never wrote and that holds logins: its position is left out, in the
			// fields and in the words.
			base.Line, base.Column = 0, 0
			base.Message = withoutPosition(base.Message)
			v.add(base)
			return
		}
		base.Line, base.Column = v.callerPos(source, pl.line, pl.column)
		if base.Line != pl.line || base.Column != pl.column {
			base.Message = restatePosition(base.Message, base.Line, base.Column)
		}
		v.add(base)
	case placedByTest, placedByToken:
		if len(pl.locations) == 0 {
			v.add(base)
			return
		}
		shown := min(len(pl.locations), maxCandidates)
		for i, loc := range pl.locations[:shown] {
			p := base
			p.Source, p.Pointer = source, v.hide(loc.Pointer)
			p.Line, p.Column = v.callerPos(source, loc.Line, loc.Column)
			if source == sourcePatch {
				p.Line, p.Column = 0, 0
			}
			p.Message = v.hide(base.Message + matchLabel(loc.Match))
			if i == 0 {
				p.MoreCandidates = pl.cut + len(pl.locations) - shown
			}
			v.add(p)
		}
	default:
		v.add(base)
	}
}

// matchLabel says how a place matched the message, in tailkeeper's words.
func matchLabel(m acl.Match) string {
	switch m {
	case acl.MatchSrcOnly:
		return " (a test with the same source)"
	case acl.MatchKey:
		return " (the name the message quotes is a key here)"
	case acl.MatchValue:
		return " (the name the message quotes is a string here)"
	}
	return ""
}
