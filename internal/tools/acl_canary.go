package tools

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"

	"github.com/tailscale/hujson"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// The canary is how an invariants validation proves that the invariants ran. A validation
// that reports no failure says nothing by itself: the invariants could have been dropped, or
// never evaluated. So the text of the second validation also holds one test that fails
// whatever the policy allows, and the answer must contain that failure, once, in the
// want/got grammar. A clean pass, a missing canary or a canary that is unevaluable is
// unknown, never a pass.
//
// The canary adds a tag with no owners to tagOwners and one test whose source is that tag. It
// accepts and denies the same destination, so exactly one of the two fails: with no acls
// (allow-all) the denial fails (want Drop, got Accept), with acls [] (deny-all) the
// acceptance does (want Accept, got Drop), probe A-9. The destination is a documentation
// address.

const (
	canaryTagPrefix   = "tag:tailkeeper-canary-"
	canaryDestination = "192.0.2.1:1"
)

// randomHex8 is eight random hexadecimal digits: the part of the canary's tag that nobody can
// guess, so that a policy cannot contain it by accident or on purpose. It is a variable so
// that a test can fix it.
var randomHex8 = func() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand failed: " + err.Error()) // there is nothing to fall back to
	}
	return hex.EncodeToString(b[:])
}

// canaryTest is the entry of the canary test for the tag src.
func canaryTest(src string) []byte {
	b, err := json.Marshal(map[string]any{"src": src, "accept": []string{canaryDestination}, "deny": []string{canaryDestination}})
	if err != nil {
		panic(err) // strings always encode
	}
	return b
}

// canaryPatch is the patch that adds the canary's tag to tagOwners with no owners, in the
// spelling the text already uses for the section. The section is found whatever its case; an
// absent one, or one written null, is made. A tagOwners that is neither an object nor null
// is a text the server would not have accepted.
func canaryPatch(text []byte, tag string) ([]byte, error) {
	v, err := hujson.Parse(bytes.Clone(text))
	if err != nil {
		return nil, tkerr.Wrap(tkerr.Internal, err, "the text could not be read to add the canary", "this is a tailkeeper bug; report it")
	}
	obj, _ := v.Value.(*hujson.Object)
	op := map[string]any{"op": "add", "path": "/tagOwners", "value": map[string][]string{tag: {}}}
	if obj != nil {
		for i := range obj.Members {
			lit, ok := obj.Members[i].Name.Value.(hujson.Literal)
			if !ok {
				continue
			}
			name := lit.String()
			if sec, known := acl.SectionByName(name); !known || sec.Name != "tagOwners" {
				continue
			}
			switch x := obj.Members[i].Value.Value.(type) {
			case *hujson.Object:
				op = map[string]any{"op": "add", "path": "/" + pointerEscape.Replace(name) + "/" + pointerEscape.Replace(tag), "value": []string{}}
			case hujson.Literal:
				if x.Kind() != 'n' {
					return nil, tkerr.New(tkerr.Internal, "tagOwners is not an object, so the canary cannot be added to it", "this is a tailkeeper bug; report it")
				}
				op = map[string]any{"op": "replace", "path": "/" + pointerEscape.Replace(name), "value": map[string][]string{tag: {}}}
			default:
				return nil, tkerr.New(tkerr.Internal, "tagOwners is not an object, so the canary cannot be added to it", "this is a tailkeeper bug; report it")
			}
			break
		}
	}
	return json.Marshal([]any{op})
}

// takeCanary removes the canary from an answer that failed. It says false, and the answer
// stays as it was, unless exactly one entry has the canary's tag as its user, that entry has
// exactly one error and no warning, and the error is in the want/got grammar: a canary that
// comes back in any other shape is not proof that the invariants ran.
func takeCanary(pv api.PolicyValidation, src string) (api.PolicyValidation, bool) {
	var line string
	n := 0
	for _, r := range pv.Results {
		if r.User == src {
			n++
			if len(r.Errors) == 1 {
				line = r.Errors[0]
			}
		}
	}
	if n != 1 || ParseFailureLine(line).Kind != AssertionFailed {
		return pv, false
	}
	return api.RemoveCanary(pv, src)
}
