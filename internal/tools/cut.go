package tools

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"unicode"

	"github.com/tailscale/hujson"

	"github.com/abm9111/tailkeeper/internal/guard"
)

// urlRE finds an http or https URL in free text, in the spellings JSON gives it:
// slashes as \/ or \u002f, the colon as \u003a. A URL ends at a space, a double
// quote or an angle bracket; a backslash that only escapes the next character
// (\", \n) is not part of it. An apostrophe is legal in a path, so it does not end
// one: the cut may take a closing quote with it, never leave a tail. There is no
// word boundary in front: "endpointhttps://…" is a URL too.
var urlRE = regexp.MustCompile(`(?i)https?(?::|\\u003a)(?:\\?/|\\u002f){2}(?:[^\s"<>\\]|\\[^\s"<>])+`)

// unescapeURL undoes the JSON spellings urlRE accepts, so the URL parses.
var unescapeURL = strings.NewReplacer(`\/`, "/", `\u002f`, "/", `\u003a`, ":", `\u0026`, "&")

// unreadableURL is shown in place of a URL that cannot be reduced to a host.
const unreadableURL = "(a URL that could not be read)"

// cutURLs shows every URL in s as its scheme and host, with a hash of its path
// and query in their place, as the webhook tools show endpoints: webhook and
// log-stream URLs carry their token in the path (spec Appendix C), and the
// configuration audit log and a log stream's delivery errors name them. It is the
// identity on text with no URL.
//
// It is not idempotent, on purpose: text that imitates a cut URL is cut again, so
// nobody can smuggle a path past it by writing the marker.
func cutURLs(s string) string {
	return urlRE.ReplaceAllStringFunc(s, func(u string) string {
		host, sum := endpoint(unescapeURL.Replace(u))
		switch {
		case host == "":
			return unreadableURL
		case sum == "":
			return host
		default:
			return host + "/…[path sha256 " + sum[:12] + "]"
		}
	})
}

// secretKeyRE matches the JSON keys whose values are credentials: a token, a
// secret, a password, an API, auth, access or private key, an authorization
// header, a credential, a cookie or a bearer.
var secretKeyRE = regexp.MustCompile(`(?i)(token|secret|password|passwd|api[_-]?key|auth[_-]?key|access[_-]?key|authorization|credential|private[_-]?key|cookie|bearer)`)

// removedValue stands where a credential-named key held its value, and for a value
// that could not be read at all.
const removedValue = "[removed]"

var removedJSON = json.RawMessage(`"` + removedValue + `"`)

// maxNesting is how many strings deep a document is read: a string that holds
// JSON, which holds a string that holds JSON, and so on. A string that holds JSON
// below that is removed whole, since it is not searched.
const maxNesting = 3

// redactSecrets returns raw with the value under every credential-named key
// replaced by "[removed]", at any depth and whatever its shape: a nested object
// under "token" would keep its secret if only strings went. Only true, false and
// null stay, since they say nothing a reader could use. A string that holds a JSON
// object, array or string, or the same in HuJSON (a policy file), is searched too, to
// maxNesting strings deep. Other values come back unchanged.
//
// When nothing was removed the API's own text comes back as it was. When
// something was, the rest is encoded again without HTML escaping, every number
// with its exact text. A key repeated in one object counts as something removed:
// Go keeps the last value, so the API's text would still hold the earlier ones,
// and an earlier one can be the credential. A value that cannot be read
// (truncated, or followed by more) comes back as "[removed]": what the parser
// never reached could hold a credential.
func redactSecrets(raw json.RawMessage) json.RawMessage {
	v, repeats, ok := decodeJSON(raw)
	if !ok {
		return removedJSON
	}
	switch v.(type) {
	case map[string]any, []any:
		out, changed := scrub(v, 0)
		if !changed && !repeats {
			return raw
		}
		if text, ok := encodeJSON(out); ok {
			return json.RawMessage(text)
		}
		return removedJSON
	}
	return raw
}

// redactJSONText is redactSecrets for a string whose content may be a JSON object,
// array or string (itself holding more), or the same in HuJSON, the policy file's
// format: comments (also before the first brace and after the last), a byte order
// mark and trailing commas. It returns the content with its
// credential-named values removed, and whether it removed any; what is removed
// from HuJSON comes back as plain JSON. Any other text, JSON or not, comes back as
// it was, and so does a document with nothing to remove.
func redactJSONText(s string) (string, bool) { return redactNested(s, 0) }

// redactNested is redactJSONText for a string that lies depth strings down.
func redactNested(s string, depth int) (string, bool) {
	if !strings.ContainsAny(s, `{["`) {
		return s, false // no document has none of these
	}
	// A policy file may open with a byte order mark, and with comments before its first
	// brace: HuJSON reads the comments, and the mark is dropped here. The text keeps its
	// end: a line comment is ended by the line feed after it, and one that ends the text
	// has none ("// end"), so HuJSON is given one.
	t := strings.TrimLeftFunc(s, func(r rune) bool { return r == '\ufeff' || unicode.IsSpace(r) })
	if strings.TrimSpace(t) == "" {
		return s, false
	}
	v, repeats, ok := decodeJSON(json.RawMessage(t))
	if !ok {
		// Not strict JSON: a policy file's old and new values are HuJSON. Its parser
		// recurses once for each level of nesting and has no bound: some 700,000 levels of
		// text from the tailnet end the process. So text nested deeper than any policy file
		// is, is removed unread, as text that nests deeper than a string can is.
		if guard.NestsDeeperThan(t, guard.MaxDepth) {
			return removedValue, true
		}
		std, err := hujson.Standardize([]byte(t + "\n"))
		if err != nil {
			return s, false
		}
		if v, repeats, ok = decodeJSON(json.RawMessage(std)); !ok {
			return s, false
		}
	}
	switch v.(type) {
	case map[string]any, []any, string:
	default:
		return s, false // a number, true, false or null holds no credential
	}
	if depth >= maxNesting {
		return removedValue, true
	}
	var out any
	changed := false
	if str, isString := v.(string); isString {
		// The text of a JSON string: what it says may be a document.
		out, changed = redactNested(str, depth+1)
	} else {
		out, changed = scrub(v, depth+1)
		changed = changed || repeats
	}
	if !changed {
		return s, false
	}
	if text, ok := encodeJSON(out); ok {
		return text, true
	}
	return removedValue, true
}

// scrub removes credential-named values from a decoded document in place and
// reports whether it removed anything; depth is how many strings deep the document
// lies.
func scrub(x any, depth int) (any, bool) {
	changed := false
	switch t := x.(type) {
	case map[string]any:
		for k, e := range t {
			if secretKeyRE.MatchString(k) {
				if _, isBool := e.(bool); isBool || e == nil {
					continue
				}
				t[k], changed = removedValue, true
			} else if n, c := scrub(e, depth); c {
				t[k], changed = n, true
			}
		}
	case []any:
		for i, e := range t {
			if n, c := scrub(e, depth); c {
				t[i], changed = n, true
			}
		}
	case string:
		return redactNested(t, depth)
	}
	return x, changed
}

// decodeJSON reads exactly one JSON value, numbers kept as their text, and says
// whether any object in it repeats a key.
func decodeJSON(raw json.RawMessage) (v any, repeats, ok bool) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&v) != nil {
		return nil, false, false
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, false, false
	}
	return v, repeatsAKey(raw), true
}

// repeatsAKey reports whether any one object in the JSON document raw has the same
// key twice (as decoded, so "tok\u0065n" and "token" are the same). raw is valid.
func repeatsAKey(raw json.RawMessage) bool {
	type frame struct {
		keys      map[string]bool // nil for an array
		expectKey bool
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var stack []*frame
	// valueDone notes that the value of the key an object was waiting on is read.
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].keys != nil {
			stack[n-1].expectKey = true
		}
	}
	for {
		tok, err := d.Token()
		if err != nil {
			return false
		}
		if delim, isDelim := tok.(json.Delim); isDelim {
			switch delim {
			case '{':
				stack = append(stack, &frame{keys: map[string]bool{}, expectKey: true})
			case '[':
				stack = append(stack, &frame{})
			default:
				stack = stack[:len(stack)-1]
				valueDone()
			}
			continue
		}
		if n := len(stack); n > 0 && stack[n-1].keys != nil && stack[n-1].expectKey {
			key, _ := tok.(string)
			if stack[n-1].keys[key] {
				return true
			}
			stack[n-1].keys[key], stack[n-1].expectKey = true, false
			continue
		}
		valueDone()
	}
}

// encodeJSON writes v without HTML escaping, as the compact text json.Marshal
// would, but with < > & as they are.
func encodeJSON(v any) (string, bool) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(v) != nil {
		return "", false
	}
	return strings.TrimSuffix(b.String(), "\n"), true
}
