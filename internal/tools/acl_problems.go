package tools

import (
	"context"

	"github.com/abm9111/tailkeeper/internal/acl"
)

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
