// Package skeleton reduces an API answer to its structure: the HTTP status, the key
// paths with their JSON types, and each error text with only the grammar's own words
// kept. It is how `make probe-acl` (and later `make live`) records what the real API
// sends without recording a single value from the tailnet.
//
// Redaction here is an allowlist, never a detector. Nothing is looked for and removed:
// a token survives only if it is on the short list of words below, a key survives only
// if it is on the list of keys the API documents, and everything else is replaced by a
// fixed placeholder (<s> for a word, <n> for a number, <key> for a key). A value the
// author never thought of therefore cannot leak, which a pattern for IP addresses or
// key prefixes cannot promise.
package skeleton

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// phrases are the grammar's own words that survive as a unit, at a token boundary:
// the verdict lines of the validate endpoint and the server's rejections.
var phrases = []string{
	"test(s) failed", "warning(s) found", "json: unknown field", "tag not found", "user or host is invalid",
	"[acl test error]", "[ssh test error]", "ssh user",
}

// words are the single tokens that survive. address, protocol, want, got, Accept, Drop,
// line and column are the words of the validate grammar; src, dst, at, ssh, user, accept
// and deny complete its SSH form, whose template would otherwise be nothing but <s>.
var words = map[string]bool{
	"address": true, "protocol": true, "want": true, "got": true, "Accept": true, "Drop": true, "line": true, "column": true,
	"src": true, "dst": true, "at": true, "ssh": true, "user": true, "accept": true, "deny": true,
}

// separators are the only punctuation a template keeps. Any run of white space is one space.
const separators = ` :,.;()[]"'/-=@`

// maxTemplate is the longest template: a longer text is cut at a token and ends in <cut>.
const maxTemplate = 400

// maxInput is how much of a text is read: the rest of a longer text is not looked at.
const maxInput = 8192

// Template reduces s to its template. Every token (a run of characters that are neither
// white space nor in separators) becomes <n> when it is only ASCII digits, stays when it
// is one of words, and becomes <s> otherwise; the phrases above stay as they are; the
// separators stay; a run of white space becomes one space; nothing else is written. The
// output therefore holds nothing but those pieces.
func Template(s string) string {
	if len(s) > maxInput {
		s = s[:maxInput]
	}
	var b strings.Builder
	lastSpace := false
	for i := 0; i < len(s); {
		switch p := phraseAt(s[i:]); {
		case p != "":
			b.WriteString(p)
			i += len(p)
			lastSpace = false
		default:
			r, size := utf8.DecodeRuneInString(s[i:])
			switch {
			case unicode.IsSpace(r):
				i += size
				for i < len(s) {
					r2, n := utf8.DecodeRuneInString(s[i:])
					if !unicode.IsSpace(r2) {
						break
					}
					i += n
				}
				if !lastSpace {
					b.WriteByte(' ')
				}
				lastSpace = true
			case isSeparator(r):
				b.WriteRune(r)
				i += size
				lastSpace = false
			default:
				j := i + size
				for j < len(s) {
					r2, n := utf8.DecodeRuneInString(s[j:])
					if unicode.IsSpace(r2) || isSeparator(r2) {
						break
					}
					j += n
				}
				b.WriteString(classify(s[i:j]))
				i = j
				lastSpace = false
			}
		}
		if b.Len() > maxTemplate {
			b.WriteString("<cut>")
			break
		}
	}
	return b.String()
}

func isSeparator(r rune) bool {
	return r < utf8.RuneSelf && strings.ContainsRune(separators, r)
}

// phraseAt returns the phrase s starts with, if it ends at a token boundary.
func phraseAt(s string) string {
	for _, p := range phrases {
		if !strings.HasPrefix(s, p) {
			continue
		}
		if rest := s[len(p):]; rest == "" {
			return p
		} else if r, _ := utf8.DecodeRuneInString(rest); unicode.IsSpace(r) || isSeparator(r) {
			return p
		}
	}
	return ""
}

// classify names one token.
func classify(tok string) string {
	if words[tok] {
		return tok
	}
	digits := tok != ""
	for i := 0; i < len(tok); i++ {
		if tok[i] < '0' || tok[i] > '9' {
			digits = false
			break
		}
	}
	if digits {
		return "<n>"
	}
	return "<s>"
}

// ETagForm describes an ETag header without showing it: none, weak or strong, quoted or
// not, and whether the inside is 64 lower-case hex digits (a SHA-256), hex of another
// length, the documented placeholder ts-default, or anything else.
func ETagForm(h string) string {
	if h == "" {
		return "none"
	}
	prefix := ""
	if strings.HasPrefix(h, "W/") {
		prefix, h = "weak-", h[2:]
	}
	if len(h) < 2 || h[0] != '"' || h[len(h)-1] != '"' {
		return prefix + "unquoted"
	}
	in := h[1 : len(h)-1]
	hex := in != ""
	for i := 0; i < len(in); i++ {
		if c := in[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			hex = false
			break
		}
	}
	switch {
	case hex && len(in) == 64:
		return prefix + "quoted-hex64"
	case hex:
		return prefix + "quoted-hex"
	case in == "ts-default":
		return prefix + "quoted-ts-default"
	}
	return prefix + "quoted-other"
}

// Path is a key path and the JSON type found there. The root is "$"; below it an object
// member is its key (a.b), and an array element is "[]" (a[].b).
type Path struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

// Skeleton is what is recorded of one answer.
type Skeleton struct {
	Status    int      `json:"status"`
	Body      string   `json:"body"`                // empty, json or text
	Paths     []Path   `json:"paths,omitempty"`     // json bodies only
	Texts     []string `json:"texts,omitempty"`     // templates of the strings at Options.TextPaths, sorted, each once
	Truncated bool     `json:"truncated,omitempty"` // more paths or texts than the caps below, or nesting deeper than maxDepth
}

// Caps on what one answer contributes.
const (
	maxPaths = 256
	maxTexts = 64
	maxDepth = 32
)

// Options say which keys and strings an answer's skeleton may show.
type Options struct {
	// Keys are the object keys that appear in a path; any other key appears as <key>.
	Keys map[string]bool
	// TextPaths are the paths whose strings are listed as templates. A string at any other
	// path is recorded as a type only.
	TextPaths map[string]bool
	// TemplateText also lists a template of a body that is not JSON, when its status is 400
	// or above: a refusal's text is the server's wording. A text body that came with a lower
	// status is the tailnet's own document (the policy as HuJSON), so it is recorded as a
	// type only, whatever this says.
	TemplateText bool
}

// DefaultOptions are the keys the Tailscale API documents for the answers of the validate
// endpoint, the policy endpoint (details=true) and the configuration audit log, and the
// paths of the message-bearing strings among them.
func DefaultOptions() Options {
	keys := map[string]bool{}
	for _, k := range strings.Fields(`message data user errors warnings acl error logs version tailnet
		eventTime deferredAt eventGroupID origin action actionDetails actor target old new
		id type name property isEphemeral loginName displayName tags`) {
		keys[k] = true
	}
	texts := map[string]bool{}
	for _, p := range []string{"message", "error", "data[].user", "data[].errors[]", "data[].warnings[]", "errors[]", "warnings[]", "logs[].error"} {
		texts[p] = true
	}
	return Options{Keys: keys, TextPaths: texts}
}

// Of reduces an answer to its skeleton.
func Of(status int, body []byte, o Options) Skeleton {
	sk := Skeleton{Status: status}
	if len(bytes.TrimSpace(body)) == 0 {
		sk.Body = "empty"
		return sk
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return textSkeleton(sk, body, o)
	}
	if _, err := dec.Token(); err != io.EOF {
		return textSkeleton(sk, body, o)
	}
	sk.Body = "json"
	w := walker{o: o, paths: map[Path]bool{}, texts: map[string]bool{}}
	w.walk("", v, 0)
	for p := range w.paths {
		sk.Paths = append(sk.Paths, p)
	}
	sort.Slice(sk.Paths, func(i, j int) bool {
		if sk.Paths[i].Path != sk.Paths[j].Path {
			return sk.Paths[i].Path < sk.Paths[j].Path
		}
		return sk.Paths[i].Type < sk.Paths[j].Type
	})
	for t := range w.texts {
		sk.Texts = append(sk.Texts, t)
	}
	sort.Strings(sk.Texts)
	sk.Truncated = w.truncated
	return sk
}

func textSkeleton(sk Skeleton, body []byte, o Options) Skeleton {
	sk.Body = "text"
	if o.TemplateText && sk.Status >= 400 {
		sk.Texts = []string{Template(string(body))}
	}
	return sk
}

type walker struct {
	o         Options
	paths     map[Path]bool
	texts     map[string]bool
	truncated bool
}

func (w *walker) add(path, typ string) {
	if path == "" {
		path = "$"
	}
	p := Path{path, typ}
	if w.paths[p] {
		return
	}
	if len(w.paths) >= maxPaths {
		w.truncated = true
		return
	}
	w.paths[p] = true
}

// walk records v at path, where the root's path is "".
func (w *walker) walk(path string, v any, depth int) {
	switch x := v.(type) {
	case map[string]any:
		w.add(path, "object")
		if depth >= maxDepth {
			w.truncated = true
			return
		}
		// Sorted, so that what survives the caps is the same on every run for one answer.
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := x[k]
			seg := "<key>"
			if w.o.Keys[k] {
				seg = k
			}
			w.walk(join(path, seg), child, depth+1)
		}
	case []any:
		w.add(path, "array")
		if depth >= maxDepth {
			w.truncated = true
			return
		}
		for _, child := range x {
			w.walk(path+"[]", child, depth+1)
		}
	case string:
		w.add(path, "string")
		if w.o.TextPaths[path] {
			t := Template(x)
			switch {
			case w.texts[t]:
			case len(w.texts) < maxTexts:
				w.texts[t] = true
			default:
				w.truncated = true
			}
		}
	case json.Number:
		w.add(path, "number")
	case bool:
		w.add(path, "boolean")
	case nil:
		w.add(path, "null")
	}
}

func join(parent, seg string) string {
	if parent == "" {
		return seg
	}
	return parent + "." + seg
}
