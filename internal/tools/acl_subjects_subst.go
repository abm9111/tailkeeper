package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// maxSubjects is how many distinct pseudonyms one text may carry. Each is one lookup in the
// users already read, but a text with hundreds is not a policy a person wrote by pasting
// from a result.
const maxSubjects = 64

// maxLoginSize is the most bytes a login is taken to take in a text: an address is at most 254
// bytes, and the rest leaves room for the escapes JSON may write in it.
const maxLoginSize = 320

var (
	// bareCarrierRE, bracketCarrierRE and maskedCarrierRE are the three forms in which a
	// result shows a user and a text may carry one back: the pseudonym alone, in brackets,
	// and after the masked address, which is one character, the mark masking leaves ("…")
	// and "@" with the domain. Resolve takes any text that ends in a space and the bracketed
	// pseudonym, so substitution holds the line itself: "tag:x [p:…]" is not a user.
	bareCarrierRE    = regexp.MustCompile(`^p:[a-z2-7]{10}$`)
	bracketCarrierRE = regexp.MustCompile(`^\[(p:[a-z2-7]{10})\]$`)
	maskedCarrierRE  = regexp.MustCompile(`^.…@\S+ \[(p:[a-z2-7]{10})\]$`)
	// markerRE is a pseudonym marker anywhere in a string.
	markerRE = regexp.MustCompile(`\[p:[a-z2-7]{10}\]`)
)

// carrierRef returns the pseudonym s carries when s is exactly one of the three carrier
// forms. holds reports a string that holds a pseudonym marker, or a bare pseudonym as a
// segment of a JSON pointer (a patch path or from), without being a carrier: such a string
// is refused, not left alone.
func carrierRef(s string) (ref string, carrier, holds bool) {
	if bareCarrierRE.MatchString(s) {
		return s, true, false
	}
	if m := bracketCarrierRE.FindStringSubmatch(s); m != nil {
		return m[1], true, false
	}
	if m := maskedCarrierRE.FindStringSubmatch(s); m != nil {
		return m[1], true, false
	}
	if markerRE.MatchString(s) {
		return "", false, true
	}
	if strings.HasPrefix(s, "/") {
		for _, seg := range strings.Split(s[1:], "/") {
			if bareCarrierRE.MatchString(pointerUnescape.Replace(seg)) {
				return "", false, true
			}
		}
	}
	return "", false, false
}

// subjectString is a string of the text: the bytes of its literal, quotes included, and the
// pseudonym it carries when it is a carrier.
type subjectString struct {
	start, end int
	ref        string
}

// lineOf is the line (from 1, counted by line feeds) of the byte at offset.
func lineOf(text []byte, offset int) int { return 1 + bytes.Count(text[:offset], []byte{'\n'}) }

// stringsOf finds the strings of a HuJSON text that carry a pseudonym, by one pass that reads
// strings and comments as HuJSON does and builds no tree: the bytes between them are never
// touched. It returns the carriers in order, and the line of the first string that holds a
// marker without being a carrier (0 when there is none) with how many there are.
func stringsOf(text []byte) (found []subjectString, badLine, bad int, err error) {
	unreadable := func(what string, at int) error {
		return tkerr.New(tkerr.ValidationFailed, what+" on line "+strconv.Itoa(lineOf(text, at)),
			"fix the syntax first: a pseudonym can only be replaced in text that is whole HuJSON")
	}
	n := len(text)
	for i := 0; i < n; i++ {
		switch text[i] {
		case '"':
			j := i + 1
			for j < n && text[j] != '"' {
				if text[j] == '\\' {
					j++
				}
				j++
			}
			if j >= n {
				return nil, 0, 0, unreadable("a string never ends", i)
			}
			raw := text[i : j+1]
			start := i
			i = j
			// A string with no "p:" and no escape can be neither a carrier nor hold a marker.
			if !bytes.Contains(raw, []byte("p:")) && bytes.IndexByte(raw, '\\') < 0 {
				continue
			}
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return nil, 0, 0, unreadable("a string is not valid JSON", start)
			}
			ref, carrier, holds := carrierRef(s)
			switch {
			case carrier:
				found = append(found, subjectString{start: start, end: j + 1, ref: ref})
			case holds:
				if bad == 0 {
					badLine = lineOf(text, start)
				}
				bad++
			}
		case '/':
			if i+1 >= n {
				continue
			}
			switch text[i+1] {
			case '/':
				j := bytes.IndexByte(text[i:], '\n')
				if j < 0 {
					return found, badLine, bad, nil
				}
				i += j
			case '*':
				j := bytes.Index(text[i+2:], []byte("*/"))
				if j < 0 {
					return nil, 0, 0, unreadable("a comment never ends", i)
				}
				i += 2 + j + 1
			}
		}
	}
	return found, badLine, bad, nil
}

// SubstituteSubjects replaces each pseudonym carrier in text (a policy, or the operations of
// a patch, as HuJSON; keys and values, never comments) by the login it names, keeping every
// other byte, and returns how many strings it replaced. A carrier is a string that is
// exactly "p:xxxxxxxxxx", "[p:xxxxxxxxxx]", or "<masked address> [p:xxxxxxxxxx]" where the
// masked address contains "…@". A string that holds a pseudonym marker and is none of these,
// a pseudonym in a patch's path or from, more than maxSubjects distinct pseudonyms, a text
// whose strings or comments do not end, and a pseudonym that resolves to zero or several
// users are validation_failed, and none of them sends a request for the users unless the
// text was fine up to the lookup. When nothing is replaced the result is a copy of text.
//
// Run CheckProposalSubjects or CheckPatchSubjects on the same bytes first: the output holds
// literal logins by design, and the subject rule would refuse it.
func SubstituteSubjects(ctx context.Context, r *SubjectResolver, text []byte) (out []byte, replaced int, err error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, tkerr.Wrap(tkerr.APIError, err, "request cancelled", "")
	}
	found, badLine, bad, err := stringsOf(text)
	if err != nil {
		return nil, 0, err
	}
	if bad > 0 {
		return nil, 0, tkerr.New(tkerr.ValidationFailed,
			strconv.Itoa(bad)+" string(s) hold a pseudonym marker without being a pseudonym, the first on line "+strconv.Itoa(badLine),
			"write a user as a result shows them, alone in its string: p:…, [p:…], or the masked address followed by [p:…]; a marker inside any other string, or in a patch path or from, is refused")
	}
	distinct := map[string]bool{}
	for _, f := range found {
		distinct[f.ref] = true
	}
	if len(distinct) > maxSubjects {
		return nil, 0, tkerr.New(tkerr.ValidationFailed,
			"the text names "+strconv.Itoa(len(distinct))+" distinct users by pseudonym, more than the "+strconv.Itoa(maxSubjects)+" one call resolves",
			"split the change into smaller ones")
	}
	// The text with the logins in it must fit what the engine reads, and whether it does must
	// not depend on the logins: the check is made on the longest a login can be, so that where
	// a text crosses the limit tells nothing of how long the logins it names are.
	if len(text)+len(found)*maxLoginSize > acl.MaxBytes {
		return nil, 0, tkerr.New(tkerr.TooComplex,
			"the text, with the logins its "+strconv.Itoa(len(found))+" pseudonyms stand for at their longest, could come to more than the "+strconv.Itoa(acl.MaxBytes)+" bytes tailkeeper reads",
			"split the change into smaller ones")
	}
	logins := make(map[string][]byte, len(distinct))
	for _, f := range found {
		if _, done := logins[f.ref]; done {
			continue
		}
		login, err := r.Resolve(ctx, f.ref)
		if err != nil {
			return nil, 0, err
		}
		var lit bytes.Buffer
		enc := json.NewEncoder(&lit)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(login.Reveal()); err != nil {
			return nil, 0, tkerr.Wrap(tkerr.Internal, err, "a login could not be written as JSON", "report this with `tailkeeper version` output")
		}
		logins[f.ref] = bytes.TrimSuffix(lit.Bytes(), []byte{'\n'})
	}
	var b bytes.Buffer
	b.Grow(len(text))
	last := 0
	for _, f := range found {
		b.Write(text[last:f.start])
		b.Write(logins[f.ref])
		last = f.end
	}
	b.Write(text[last:])
	return b.Bytes(), len(found), nil
}
