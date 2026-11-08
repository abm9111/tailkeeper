package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// The intent of a scan is the owner's expectation of the policy: the tests of the invariants
// file, in the policy's own syntax. A scan reads it from the same places `acl validate` reads
// its invariants (the file the operator named, or else acl.invariantsFile of the configuration,
// which is the only source an MCP call has), decodes it with the same checked loader
// (parseInvariants) and adapts it into the typed expectations of the security package. Nothing
// judges an expectation in this version, so a scan that was given an intent set is partial; the
// set is named in the report by its digest and revision and by how many expectations it holds,
// and none of its text (a source, a destination, a login, a posture value) is repeated in any
// result, error or audit line.

// intentOrigin says where the intent set of a scan came from.
type intentOrigin string

const (
	intentNone       intentOrigin = "none"       // no intent set: the intent is not requested
	intentConfigured intentOrigin = "configured" // the file acl.invariantsFile names
	intentCLI        intentOrigin = "cli"        // the file --invariants named
)

// The kinds of refusal the adapter makes of an entry it does not take. They are the whole
// vocabulary of such a refusal: an error names a kind and a place, never a word of the file.
const (
	refusedField   = "unsupported_field" // a field this version does not map, or one spelled twice
	refusedValue   = "unsupported_value" // a field of a shape this version does not map
	refusedMissing = "missing_field"     // a field every expectation needs
)

// intentListMax is how many places a refusal names before it counts the rest.
const intentListMax = 5

// intentRefusal is one entry the adapter refuses, by kind and place.
type intentRefusal struct {
	Kind    string
	Section string // "tests" or "sshTests"
	Entry   int    // 1-based, in its section
	At      filePos
}

type fieldType int

const (
	fieldString fieldType = iota
	fieldList
	fieldAttrs
)

// fieldTypes is how the typed expectations hold each field of a test that the adapter maps. The
// keys of a test, and the spellings of each, are internal/acl's (acl.PolicyTestKeys): the
// adapter reads a file as the normal form reads it, so that a file `acl validate` takes is not
// refused by a scan. A field the normal form reads and this table lacks is refused, not dropped.
var fieldTypes = map[string]fieldType{
	"src": fieldString, "proto": fieldString, "srcPostureAttrs": fieldAttrs,
	"dst": fieldList, "accept": fieldList, "deny": fieldList, "check": fieldList,
}

// requiredFields are the fields every test of a kind needs.
func requiredFields(ssh bool) []string {
	if ssh {
		return []string{"src", "dst"}
	}
	return []string{"src"}
}

// intentDigest is the digest of the exact bytes of the file and the revision that names it. The
// digest follows the rule the other digests of a policy follow (rawDigest): the plain SHA-256
// only with personalData show, a keyed digest while personal data is masked and a privacy key is
// loaded, and none while it is masked with no key, because an unkeyed hash of a file that holds
// logins would confirm a guessed file. The revision is the first twelve hexadecimal digits of
// whatever digest is shown, and none when there is none. The report schema takes any short text
// as a revision, and a file has no number of its own.
func intentDigest(env *registry.Env, text []byte) (digest, revision string) {
	digest = rawDigest(env, text)
	return digest, ShortDigest(digest, 12)
}

// intentSetOf adapts a decoded invariants file to the typed intent set. Every entry that holds
// a field the adapter does not map, a field of another shape or no source is refused with its
// kind and its place; the set is returned only when no entry was.
func intentSetOf(ctx context.Context, set *invariantSet, digest, revision string) (security.IntentSet, []intentRefusal, error) {
	out := security.IntentSet{SchemaVersion: security.SchemaVersion, Revision: revision, Digest: digest}
	var refused []intentRefusal
	refuse := func(kinds []string, section string, i int, at filePos) {
		for _, k := range kinds {
			refused = append(refused, intentRefusal{Kind: k, Section: section, Entry: i + 1, At: at})
		}
	}
	for i, raw := range set.Tests {
		vals, kinds, err := readEntry(ctx, raw, false)
		if err != nil {
			return security.IntentSet{}, nil, err
		}
		e := security.NetworkExpectation{ID: fmt.Sprintf("network-%d", i+1)}
		kinds = append(kinds, takeNetwork(vals, &e)...)
		refuse(kinds, "tests", i, set.TestAt[i])
		out.Network = append(out.Network, e)
	}
	for i, raw := range set.SSHTests {
		vals, kinds, err := readEntry(ctx, raw, true)
		if err != nil {
			return security.IntentSet{}, nil, err
		}
		e := security.SSHExpectation{ID: fmt.Sprintf("ssh-%d", i+1)}
		kinds = append(kinds, takeSSH(vals, &e)...)
		refuse(kinds, "sshTests", i, set.SSHTestAt[i])
		out.SSH = append(out.SSH, e)
	}
	if len(refused) > 0 {
		return security.IntentSet{}, refused, nil
	}
	return out, nil, nil
}

// readEntry splits one test into the raw values of its fields, by field and not by spelling,
// as the normal form of internal/acl reads it (acl.PolicyTestKeys). The keys are matched
// whatever their case. A field written in two spellings follows the normal form's rule: of a
// list (accept, allow) both are read, in the order of the spellings, and of anything else the
// first one present is the field and the other is an unread field, which is refused. A key the
// normal form does not read as a field, a key it reads that the adapter does not map, a field
// spelled twice and a required field that is absent are returned as kinds of refusal, each once.
// The only error is a cancelled call or an entry past the engine's budgets.
func readEntry(ctx context.Context, raw []byte, ssh bool) (map[string][]json.RawMessage, []string, error) {
	std, err := acl.Standardize(ctx, raw)
	if err != nil {
		return nil, nil, err // the engine's own refusal, or a cancelled call: loadScanIntent words it by the file's origin
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(std, &members); err != nil {
		// The loader has read this entry as an object; this cannot happen, and it is refused
		// like any other shape the adapter does not take.
		return nil, []string{refusedValue}, nil
	}
	keys := acl.PolicyTestKeys(ssh)
	present, kinds := spelledKeys(members, keys)
	vals, more := readFields(present, keys)
	for _, k := range more {
		kinds = addKind(kinds, k)
	}
	for _, field := range requiredFields(ssh) {
		if len(vals[field]) == 0 {
			kinds = addKind(kinds, refusedMissing)
		}
	}
	return vals, kinds, nil
}

// spelledKeys names each member of a test by the spelling the normal form documents, whatever
// its case. A key that is no spelling of any field, and a spelling written twice, are refused.
func spelledKeys(members map[string]json.RawMessage, keys map[string][]string) (map[string]json.RawMessage, []string) {
	present := map[string]json.RawMessage{}
	var kinds []string
	for key, v := range members {
		spelling := spellingOf(keys, key)
		if _, twice := present[spelling]; spelling == "" || twice {
			kinds = addKind(kinds, refusedField)
			continue
		}
		present[spelling] = v
	}
	return present, kinds
}

// spellingOf is the spelling of a field that key is, whatever its case, or "".
func spellingOf(keys map[string][]string, key string) string {
	for _, spellings := range keys {
		for _, sp := range spellings {
			if strings.EqualFold(sp, key) {
				return sp
			}
		}
	}
	return ""
}

// readFields gathers the values of each field in the order of its spellings. Of a list both
// spellings are kept; of any other field only the first, and a second spelling of it is an unread
// field, refused. A field the normal form reads and the adapter does not map is refused.
func readFields(present map[string]json.RawMessage, keys map[string][]string) (map[string][]json.RawMessage, []string) {
	vals := map[string][]json.RawMessage{}
	var kinds []string
	for field, spellings := range keys {
		typ, mapped := fieldTypes[field]
		for _, sp := range spellings {
			v, ok := present[sp]
			switch {
			case !ok:
			case !mapped, typ != fieldList && len(vals[field]) > 0:
				kinds = addKind(kinds, refusedField)
			default:
				vals[field] = append(vals[field], v)
			}
		}
	}
	return vals, kinds
}

func addKind(kinds []string, k string) []string {
	if slices.Contains(kinds, k) {
		return kinds
	}
	return append(kinds, k)
}

// takeNetwork fills a network expectation from the fields of its test and returns the kinds of
// refusal for a field whose value has a shape the expectation does not hold.
func takeNetwork(vals map[string][]json.RawMessage, e *security.NetworkExpectation) []string {
	var kinds []string
	bad := func(ok bool) {
		if !ok {
			kinds = addKind(kinds, refusedValue)
		}
	}
	var ok bool
	if raws := vals["src"]; len(raws) > 0 {
		e.Source, ok = asText(raws[0])
		bad(ok)
	}
	if raws := vals["proto"]; len(raws) > 0 {
		e.Protocol, ok = asText(raws[0])
		bad(ok)
	}
	if raws := vals["srcPostureAttrs"]; len(raws) > 0 {
		// The checked decoder of the typed model: an object of strings, numbers and booleans,
		// each attribute once.
		var attrs security.PostureAttributes
		bad(json.Unmarshal(raws[0], &attrs) == nil)
		e.SourcePostureAttributes = attrs
	}
	e.Accept, ok = asLists(vals["accept"])
	bad(ok)
	e.Deny, ok = asLists(vals["deny"])
	bad(ok)
	return kinds
}

// takeSSH is takeNetwork for an SSH test. Its destinations are a list that names at least one.
func takeSSH(vals map[string][]json.RawMessage, e *security.SSHExpectation) []string {
	var kinds []string
	bad := func(ok bool) {
		if !ok {
			kinds = addKind(kinds, refusedValue)
		}
	}
	var ok bool
	if raws := vals["src"]; len(raws) > 0 {
		e.Source, ok = asText(raws[0])
		bad(ok)
	}
	if raws := vals["dst"]; len(raws) > 0 {
		e.Destinations, ok = asLists(raws)
		bad(ok && len(e.Destinations) > 0)
	}
	e.Accept, ok = asLists(vals["accept"])
	bad(ok)
	e.Deny, ok = asLists(vals["deny"])
	bad(ok)
	e.Check, ok = asLists(vals["check"])
	bad(ok)
	return kinds
}

// asText reads a JSON string that says something. null, a number and the empty string are not
// one.
func asText(raw json.RawMessage) (string, bool) {
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil || s == "" {
		return "", false
	}
	return s, true
}

// asList reads a JSON array of strings that each say something; an empty array is an empty
// list (nil), and null is not an array.
func asList(raw json.RawMessage) ([]string, bool) {
	var l []string
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &l) != nil {
		return nil, false
	}
	if slices.Contains(l, "") {
		return nil, false
	}
	if len(l) == 0 {
		return nil, true
	}
	return l, true
}

// asLists reads the values a list field was written with, one for each spelling present, and
// joins them in that order, as the normal form asserts them together. No value is no list, and
// one that is not a list of strings that say something makes the whole field one the adapter
// does not take.
func asLists(raws []json.RawMessage) ([]string, bool) {
	var all []string
	for _, raw := range raws {
		l, ok := asList(raw)
		if !ok {
			return nil, false
		}
		all = append(all, l...)
	}
	return all, true
}

// loadScanIntent finds the intent set of a scan, with the rules of loadInvariants: NoInvariants
// means none; a file the operator named replaces the configured one; otherwise the file of the
// configuration is read, by the one reader that opens it (readConfiguredInvariants). A path
// that is set and cannot be read is config_invalid on every scan that uses it, never a silent
// none: an intent that is quietly not requested would turn a partial scan into a complete one.
// A file with problems, or with an entry the adapter does not take, is refused by the kind and
// the place of each, never by its words.
func loadScanIntent(ctx context.Context, env *registry.Env, in SecurityScanInput) (*security.IntentSet, intentOrigin, error) {
	loaded, origin, err := loadIntentFile(ctx, env, in.NoInvariants, in.Invariants)
	if loaded == nil {
		return nil, origin, err
	}
	return &loaded.Set, origin, nil
}

// loadedIntent is an intent file as the typed set the scan and the explanation both work from.
// The explanation rebuilds each test it sends to Tailscale from the typed set (the pairs it
// judges), not from the file's entries, so nothing of the checked file is kept.
type loadedIntent struct {
	Set security.IntentSet
}

// loadIntentFile is the loading the scan and the explanation share: the same places, the same
// loader, the same refusals. noFile means no intent even if the configuration names a file;
// named is the text of a file the operator named, which replaces the configured one. The result
// is nil, with a nil error, for no intent set.
func loadIntentFile(ctx context.Context, env *registry.Env, noFile bool, named string) (*loadedIntent, intentOrigin, error) {
	var text []byte
	origin := intentCLI
	switch {
	case noFile:
		return nil, intentNone, nil
	case named != "":
		text = []byte(named)
	default:
		data, configured, err := readConfiguredInvariants(env)
		if err != nil {
			return nil, intentConfigured, err
		}
		if !configured {
			return nil, intentNone, nil
		}
		text, origin = data, intentConfigured
	}
	set, problems, err := parseInvariants(ctx, string(text))
	if err != nil {
		return nil, origin, intentEngineError(origin, err)
	}
	if len(problems) > 0 {
		places := make([]string, len(problems))
		for i, p := range problems {
			places[i] = placeOf(p.Kind, p.Line, p.Column)
		}
		return nil, origin, refuseIntent(origin, fmt.Sprintf("the intent file has %s", plural(len(problems), "problem")), places)
	}
	digest, revision := intentDigest(env, text)
	intent, refused, err := intentSetOf(ctx, set, digest, revision)
	if err != nil {
		return nil, origin, intentEngineError(origin, err)
	}
	if len(refused) > 0 {
		places := make([]string, len(refused))
		for i, r := range refused {
			places[i] = fmt.Sprintf("%s in entry %d of %s (%s)", r.Kind, r.Entry, r.Section, placeOf("", r.At.Line, r.At.Column))
		}
		return nil, origin, refuseIntent(origin, "the intent file holds what this version cannot take", places)
	}
	return &loadedIntent{Set: intent}, origin, nil
}

// placeOf is "kind at line L, column C", or what of it is known.
func placeOf(kind string, line, col int) string {
	where := ""
	switch {
	case line > 0 && col > 0:
		where = fmt.Sprintf("line %d, column %d", line, col)
	case line > 0:
		where = fmt.Sprintf("line %d", line)
	}
	switch {
	case kind == "":
		return where
	case where == "":
		return kind
	}
	return kind + " at " + where
}

// refuseIntent is the error for an intent file that cannot be used. It lists the first places
// and counts the rest. Its code is the file's owner's: config_invalid for the configured file
// (exit 6, on every call that uses it), validation_failed for a file the command line named
// (exit 2).
func refuseIntent(origin intentOrigin, what string, places []string) error {
	listed := places[:min(len(places), intentListMax)]
	msg := what + ": " + strings.Join(listed, "; ")
	if more := len(places) - len(listed); more > 0 {
		msg += fmt.Sprintf("; and %d more", more)
	}
	msg += "; no source was read"
	if origin == intentConfigured {
		return tkerr.New(tkerr.ConfigInvalid, msg,
			"fix the file acl.invariantsFile names, or take the setting out; `tailkeeper acl validate --offline --invariants FILE` shows each problem")
	}
	return tkerr.New(tkerr.ValidationFailed, msg,
		"fix the file, or leave out --invariants; `tailkeeper acl validate --offline --invariants FILE` shows each problem")
}

// intentEngineError is the error for an intent file the engine refuses (past its budgets, or
// otherwise), or for a call that was cancelled while it was read. The words are fixed: nothing of
// the file is in them. The code follows the file's origin, as for every other way a file cannot
// be used: the configured file is config_invalid (exit 6) on every call that uses it; a file the
// command line named is too_complex, or validation_failed (exit 2). A cancellation is the call's,
// whichever file it was reading.
func intentEngineError(origin intentOrigin, err error) error {
	var e *acl.Error
	if !errors.As(err, &e) {
		return tkerr.Wrap(tkerr.APIError, err, "the call was cancelled while it read the intent file", "")
	}
	message, hint := "the intent file could not be read", ""
	if e.Code == acl.CodeTooComplex {
		message, hint = "the intent file is too large or too complex to read", "split it, or take out the tests the scan does not need"
	}
	switch {
	case origin == intentConfigured:
		return tkerr.New(tkerr.ConfigInvalid, message, "fix the file acl.invariantsFile names, or take the setting out"+orHint(hint))
	case e.Code == acl.CodeTooComplex:
		return tkerr.New(tkerr.TooComplex, message, hint)
	}
	return tkerr.New(tkerr.ValidationFailed, message, hint)
}

// orHint is "; " and a hint, or nothing.
func orHint(h string) string {
	if h == "" {
		return ""
	}
	return "; " + h
}

// scanIntentOf is what the output says of the intent set: where it came from, its digest and
// revision as the report names them, and how many expectations it holds. It repeats none of
// the set.
func scanIntentOf(origin intentOrigin, set *security.IntentSet, r security.Report) SecurityScanIntent {
	if set == nil {
		return SecurityScanIntent{Source: string(intentNone)}
	}
	return SecurityScanIntent{Source: string(origin), Digest: r.IntentDigest, Revision: r.IntentRevision, Expectations: len(set.Network) + len(set.SSH)}
}
