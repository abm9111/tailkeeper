package probe

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/skeleton"
)

// The files under internal/api/apitest/testdata/observed are what the owner's live run wrote
// and a person read before they were committed. Nothing else keeps them to placeholders: a
// later run, or a hand edit, could commit a capture that holds a real tailnet value, and every
// other test would stay green. This file reads every capture and fails, naming the file and
// the JSON path (never the value), for anything the printer and the probe code could not have
// written there. It lives in this package because the probe-authored fields are tied to the
// probe code itself (All, registered), which no other package may import.

// capturesDir is where the captures are committed, found through the ledger's own constant.
func capturesDir() string {
	return filepath.Join("..", "api", "apitest", filepath.FromSlash(apitest.CaptureDir))
}

// vocab is what the probe code can write into one probe's capture, apart from the skeletons.
type vocab struct {
	observations map[string]bool // label, expect and request of a request, joined by NUL
	checks       map[string]bool
	facts        map[string]bool
	counts       map[string]bool
	skipped      map[string]bool
}

func newVocab() *vocab {
	return &vocab{map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}}
}

func obsKey(label, expect, request string) string { return label + "\x00" + expect + "\x00" + request }

// addResults records everything the probe code wrote into rs.
func addResults(vs map[string]*vocab, rs []Result) {
	for _, r := range rs {
		v := vs[r.ID]
		if v == nil {
			v = newVocab()
			vs[r.ID] = v
		}
		for _, o := range r.Observations {
			v.observations[obsKey(o.Label, o.Expect, o.Request)] = true
		}
		for _, c := range r.Checks {
			v.checks[c.Name] = true
		}
		for name := range r.Facts {
			v.facts[name] = true
		}
		for name := range r.Counts {
			v.counts[name] = true
		}
		for _, s := range r.Skipped {
			v.skipped[s] = true
		}
	}
}

// probeVocabularies runs every probe against the model world, and against the variants of it
// in which a probe takes another branch (a policy with no source, no host, no stored test or
// no ssh rule; an audit log that is empty, refused or not JSON; a live policy that cannot be
// read). The names, labels and sentences a probe can write are those it wrote in one of them.
// Nothing here is typed from a capture: a capture that holds a sentence none of the runs
// produced fails, and the way to accept it is to add the world that produces it.
func probeVocabularies(t *testing.T) map[string]*vocab {
	t.Helper()
	const head = `{"tagOwners":{"tag:live":[]},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]`
	unknownSSHTests := func(body string) (apitest.Shape, bool) {
		if strings.Contains(body, "sshTests") && !strings.Contains(body, "probe-nobody") {
			return apitest.PolicyUnknownField("sshTests"), true
		}
		return apitest.Shape{}, false
	}
	vs := map[string]*vocab{}
	for _, c := range []struct {
		name  string
		setup func(w *world)
	}{
		{"the model world, one audit entry", func(w *world) {
			w.auditLogs = []map[string]any{
				{"eventTime": "2026-10-01T00:00:00Z", "action": "UPDATE", "old": liveText, "new": strings.Replace(liveText, "tag:live", "tag:live2", 1)}}
		}},
		{"an empty audit log and an A-10 fallback", func(w *world) {
			w.override = func(body string) (apitest.Shape, bool) {
				if strings.Contains(body, "probe-nobody") {
					return apitest.SSHTestFailed("tag:live", "100.64.0.1", "tag:live", "100.64.0.2", "probe-nobody-aaaaaaaa"), true
				}
				return unknownSSHTests(body)
			}
		}},
		{"a policy with no tag, login or group", func(w *world) { w.serveText(`{"acls":[]}`) }},
		{"a policy with a tag and nothing else, and no ssh rule to fall back on", func(w *world) {
			w.serveText(`{"tagOwners":{"tag:live":[]},"acls":[]}`)
			w.override = unknownSSHTests
		}},
		{"a policy with one stored test", func(w *world) { w.serveText(head + `,"tests":[{"src":"tag:live","accept":["192.0.2.1:22"]}]}`) }},
		{"a live policy that cannot be read", func(w *world) {
			w.detailsFail = &struct {
				code int
				body string
			}{500, `{}`}
		}},
		{"an audit log that is refused", func(w *world) { w.auditCode = http.StatusForbidden }},
		{"an audit log that is not JSON", func(w *world) {
			w.f.Handle("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/logging/configuration", func(rw http.ResponseWriter, _ *http.Request) {
				_, _ = rw.Write([]byte("not json"))
			})
		}},
	} {
		w := newWorld(t)
		c.setup(w)
		rs := runAll(t, w, opts())
		if len(rs) != len(All()) {
			t.Fatalf("%s: %d results, want %d", c.name, len(rs), len(All()))
		}
		addResults(vs, rs)
	}
	return vs
}

// etagForms are the forms the printer can name an ETag by, found by asking the printer about
// one header of each kind, bare and weak.
func etagForms() map[string]bool {
	forms := map[string]bool{}
	for _, h := range []string{"", `"` + strings.Repeat("a", 64) + `"`, `"abc"`, `"ts-default"`, `"zz"`, `abc`} {
		forms[skeleton.ETagForm(h)] = true
		if h != "" {
			forms[skeleton.ETagForm("W/"+h)] = true
		}
	}
	return forms
}

// printerOutput reports whether s is something skeleton.Template can write. Template is the
// printer's own definition of what a text may hold, so the test asks it instead of keeping a
// second list: s must come back unchanged when fed through it. It is a fixed point except
// for the placeholders it writes for what it drops: <n> (a number) would come back as <s>,
// so each <n> is first put back as a digit, and the <cut> that ends a long text is taken off
// and left for Template to write again. A text with any other word, any digit, a byte outside
// the vocabulary, or a different length is changed by Template, so it is not accepted.
func printerOutput(s string) bool {
	body := strings.TrimSuffix(s, "<cut>")
	return skeleton.Template(strings.ReplaceAll(body, "<n>", "0")) == s
}

// printedPath reports whether p is a path the printer writes: $, or segments joined by dots,
// each a key from the printer's own list or <key>, with any number of [] after it; a root
// array starts with a bare [].
func printedPath(p string, keys map[string]bool) bool {
	if p == "$" {
		return true
	}
	for i, seg := range strings.Split(p, ".") {
		base := seg
		for strings.HasSuffix(base, "[]") {
			base = strings.TrimSuffix(base, "[]")
		}
		switch {
		case base == "<key>" || keys[base]:
		case base == "" && i == 0 && seg != "":
		default:
			return false
		}
	}
	return true
}

var (
	jsonTypes = map[string]bool{"object": true, "array": true, "string": true, "number": true, "boolean": true, "null": true}
	bodyKinds = map[string]bool{"empty": true, "json": true, "text": true}
	dayRE     = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
)

// captureKeys are the members a capture may have at each level. A member the probe never
// writes (a note, an error, a body) is a place for a value to hide.
var captureKeys = map[string][]string{
	"file":        {"observedOn", "probe", "title", "sends", "expected", "branch", "observations", "checks", "facts", "counts", "skipped"},
	"observation": {"label", "expect", "request", "result", "etag"},
	"result":      {"status", "body", "paths", "texts", "truncated"},
	"path":        {"path", "type"},
	"check":       {"name", "want", "got"},
}

// unexpectedMembers names, by position, the members of v that kind does not allow. The
// member's own name is not printed: it is the one thing in a stray member a person wrote.
func unexpectedMembers(path, kind string, v any) []string {
	m, ok := v.(map[string]any)
	if !ok {
		return []string{path + ": not a JSON object"}
	}
	allowed := map[string]bool{}
	for _, k := range captureKeys[kind] {
		allowed[k] = true
	}
	var names []string
	for k := range m {
		if !allowed[k] {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	var out []string
	for i := range names {
		out = append(out, fmt.Sprintf("%s: has a member the probe never writes (no. %d in sorted order)", path, i+1))
	}
	return out
}

// shapeProblems checks the members of the document, level by level.
func shapeProblems(doc any) []string {
	out := unexpectedMembers("$", "file", doc)
	root, ok := doc.(map[string]any)
	if !ok {
		return out
	}
	each := func(key, kind string, v any) []string {
		list, ok := v.([]any)
		if !ok {
			return nil // the typed decode reports a wrong type
		}
		var ps []string
		for i, el := range list {
			ps = append(ps, unexpectedMembers(fmt.Sprintf("%s[%d]", key, i), kind, el)...)
		}
		return ps
	}
	out = append(out, each("checks", "check", root["checks"])...)
	obs, _ := root["observations"].([]any)
	for i, o := range obs {
		p := fmt.Sprintf("observations[%d]", i)
		out = append(out, unexpectedMembers(p, "observation", o)...)
		om, ok := o.(map[string]any)
		if !ok || om["result"] == nil {
			continue
		}
		out = append(out, unexpectedMembers(p+".result", "result", om["result"])...)
		if rm, ok := om["result"].(map[string]any); ok {
			out = append(out, each(p+".result.paths", "path", rm["paths"])...)
		}
	}
	return out
}

// safeMembers are the member names the printer's file format has, which a path may show; any
// other name is a key somebody chose and is shown by its position.
var safeMembers = func() map[string]bool {
	m := map[string]bool{"result": true, "observations": true, "checks": true, "facts": true, "counts": true, "skipped": true}
	for _, ks := range captureKeys {
		for _, k := range ks {
			m[k] = true
		}
	}
	return m
}()

// repeatedMembers finds an object that has the same member twice. A decoder keeps the last
// of them, so the first would sit in the file where no other check looks.
func repeatedMembers(raw []byte) []string {
	var out []string
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	var walk func(path string)
	walk = func(path string) {
		tok, err := dec.Token()
		if err != nil {
			return
		}
		switch tok {
		case json.Delim('{'):
			seen := map[string]bool{}
			for n := 1; dec.More(); n++ {
				kt, err := dec.Token()
				if err != nil {
					return
				}
				key, _ := kt.(string)
				if seen[key] {
					out = append(out, fmt.Sprintf("%s: member %d repeats an earlier member", orRoot(path), n))
				}
				seen[key] = true
				name := fmt.Sprintf("#%d", n)
				if safeMembers[key] {
					name = key
				}
				if path == "" {
					walk(name)
				} else {
					walk(path + "." + name)
				}
			}
			_, _ = dec.Token()
		case json.Delim('['):
			for i := 0; dec.More(); i++ {
				walk(fmt.Sprintf("%s[%d]", path, i))
			}
			_, _ = dec.Token()
		}
	}
	walk("")
	return out
}

func orRoot(path string) string {
	if path == "" {
		return "$"
	}
	return path
}

// captureProblems reads one capture, whose file is <stem>.json, and returns what it holds
// that the printer and the probe code could not have written. Each problem names the file and
// the JSON path; none shows the offending value.
func captureProblems(stem string, raw []byte, vs map[string]*vocab) []string {
	name := stem + ".json"
	var probes = map[string]Probe{}
	for _, p := range All() {
		probes[p.ID] = p
	}
	var problems []string
	add := func(path, format string, args ...any) {
		problems = append(problems, name+": "+path+": "+fmt.Sprintf(format, args...))
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		add("$", "not valid JSON")
		return problems
	}
	for _, s := range shapeProblems(doc) {
		problems = append(problems, name+": "+s)
	}
	for _, s := range repeatedMembers(raw) {
		problems = append(problems, name+": "+s)
	}
	var f file
	if err := json.Unmarshal(raw, &f); err != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			// A member of facts or counts is named by its key, which is not ours to print.
			field := typeErr.Field
			if strings.HasPrefix(field, "facts.") || strings.HasPrefix(field, "counts.") {
				field = field[:strings.Index(field, ".")]
			}
			add(field, "cannot be read as %s", typeErr.Type)
		} else {
			add("$", "cannot be read as a capture")
		}
		return problems
	}

	p, known := probes[stem]
	if !known {
		add("$", "no probe has this ID")
		return problems
	}
	if f.ID != stem {
		add("probe", "is not the ID of the file")
	}
	// The probe-authored texts are the probe code's: the table row, and the title the probe is registered with.
	row := registered[stem]
	for _, c := range []struct{ path, got, want string }{
		{"title", f.Title, p.Title}, {"sends", f.Sends, row.Sends}, {"expected", f.Expected, row.Expected}, {"branch", f.Branch, row.Branch},
	} {
		if c.got != c.want {
			add(c.path, "differs from what the probe code defines")
		}
	}
	if !dayRE.MatchString(f.ObservedOn) {
		add("observedOn", "is not YYYY-MM-DD")
	} else if _, err := time.Parse("2006-01-02", f.ObservedOn); err != nil {
		add("observedOn", "is not a date")
	}

	v := vs[stem]
	if v == nil {
		v = newVocab()
	}
	keys := skeleton.DefaultOptions().Keys
	forms := etagForms()
	if len(f.Observations) == 0 {
		add("observations", "is empty")
	}
	if f.Error != "" || f.NotRun {
		add("$", "records a probe that did not complete")
	}
	for i, o := range f.Observations {
		at := fmt.Sprintf("observations[%d]", i)
		if !v.observations[obsKey(o.Label, o.Expect, o.Request)] {
			// Name the field that is not the probe's, or say that the three are each the probe's but not together.
			bad := false
			for n, c := range []struct{ field, got string }{{"label", o.Label}, {"expect", o.Expect}, {"request", o.Request}} {
				listed := false
				for k := range v.observations {
					if strings.Split(k, "\x00")[n] == c.got {
						listed = true
						break
					}
				}
				if !listed {
					add(at+"."+c.field, "is not one the probe code writes for %s", stem)
					bad = true
				}
			}
			if !bad {
				add(at, "label, expect and request are each the probe's, but not together for one request")
			}
		}
		if o.Error != "" {
			add(at+".error", "a request with no answer is not a committed capture")
		}
		if o.ETag != "" && !forms[o.ETag] {
			add(at+".etag", "is not one of the forms the printer writes")
		}
		sk := o.Result
		if sk == nil {
			add(at+".result", "is missing")
			continue
		}
		if sk.Status < 100 || sk.Status > 599 {
			add(at+".result.status", "is not an HTTP status")
		}
		if !bodyKinds[sk.Body] {
			add(at+".result.body", "is not empty, json or text")
		}
		if sk.Body != "json" && len(sk.Paths) > 0 {
			add(at+".result.paths", "are recorded for a body that is not JSON")
		}
		for j, pt := range sk.Paths {
			if !printedPath(pt.Path, keys) {
				add(fmt.Sprintf("%s.result.paths[%d].path", at, j), "is not <key>, a key the printer lists, or $")
			}
			if !jsonTypes[pt.Type] {
				add(fmt.Sprintf("%s.result.paths[%d].type", at, j), "is not a JSON type")
			}
		}
		for j, tx := range sk.Texts {
			if !printerOutput(tx) {
				add(fmt.Sprintf("%s.result.texts[%d]", at, j), "is not a text skeleton.Template can write")
			}
		}
	}
	for i, c := range f.Checks {
		if !v.checks[c.Name] {
			add(fmt.Sprintf("checks[%d].name", i), "is not a check the probe code names for %s", stem)
		}
	}
	for _, c := range []struct {
		field string
		names []string
		known map[string]bool
	}{
		{"facts", sortedKeys(f.Facts), v.facts},
		{"counts", sortedKeys(f.Counts), v.counts},
	} {
		for i, n := range c.names {
			if !c.known[n] {
				add(fmt.Sprintf("%s (name %d in order)", c.field, i+1), "is not a name the probe code records for %s", stem)
			}
		}
	}
	for i, s := range f.Skipped {
		if !v.skipped[s] {
			add(fmt.Sprintf("skipped[%d]", i), "is not a sentence the probe code writes for %s", stem)
		}
	}
	return problems
}

// captureDirProblems checks every file of dir and returns the problems with the number of
// captures it read. The files must be exactly one <ID>.json per probe.
func captureDirProblems(dir string, vs map[string]*vocab) ([]string, int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{"the captures directory cannot be read"}, 0
	}
	byID := map[string]bool{}
	for _, p := range All() {
		byID[p.ID] = true
	}
	var problems []string
	seen := map[string]bool{}
	read := 0
	for _, e := range entries {
		stem := strings.TrimSuffix(e.Name(), ".json")
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || !byID[stem] {
			problems = append(problems, e.Name()+": not a capture of a registered probe")
			continue
		}
		seen[stem] = true
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			problems = append(problems, e.Name()+": cannot be read")
			continue
		}
		read++
		problems = append(problems, captureProblems(stem, raw, vs)...)
	}
	for _, p := range All() {
		if !seen[p.ID] {
			problems = append(problems, p.ID+".json: missing")
		}
	}
	return problems, read
}

// Every committed capture holds only what the printer and the probe code can write.
func TestCommittedCapturesHoldOnlyPlaceholders(t *testing.T) {
	problems, n := captureDirProblems(capturesDir(), probeVocabularies(t))
	if n != len(All()) {
		t.Fatalf("read %d captures, want one for each of the %d probes", n, len(All()))
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// The forms an ETag can be named by are the printer's eleven: none, then unquoted and the four
// quoted forms, each bare and weak (none has no weak form). The set is found by asking the
// printer, so this pin shows a form added to it.
func TestTheETagFormsArePinned(t *testing.T) {
	got := etagForms()
	want := []string{"none", "quoted-hex", "quoted-hex64", "quoted-other", "quoted-ts-default", "unquoted",
		"weak-quoted-hex", "weak-quoted-hex64", "weak-quoted-other", "weak-quoted-ts-default", "weak-unquoted"}
	if len(got) != len(want) {
		t.Errorf("%d forms, want %d: %v", len(got), len(want), got)
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("no input gave the form %q", w)
		}
	}
}

// ---- the check can fail ----

// edit changes a capture through its generic JSON form.
type edit func(doc map[string]any)

func member(v any, key string) map[string]any { return v.(map[string]any)[key].(map[string]any) }
func items(v any, key string) []any           { return v.(map[string]any)[key].([]any) }
func obsAt(doc map[string]any, i int) map[string]any {
	return items(doc, "observations")[i].(map[string]any)
}
func resultAt(doc map[string]any, i int) map[string]any { return member(obsAt(doc, i), "result") }

// The check fails, naming the file and the path and not the value, for each way a capture
// could hold something real, and passes the capture it started from. A clean result means
// nothing until the same function has been shown to fail on a known positive.
func TestCaptureCheckFindsWhatItShould(t *testing.T) {
	vs := probeVocabularies(t)
	hex64 := strings.Repeat("0123456789abcdef", 4)
	cases := []struct {
		name, stem string
		change     edit
		path       string // the JSON path the problem names
		planted    string // the value the problem must not show
	}{
		{"an email address in a text", "A-2", func(d map[string]any) { resultAt(d, 0)["texts"].([]any)[0] = "amy@example.com" }, "observations[0].result.texts[0]", "amy@example.com"},
		{"an address in a text", "A-2", func(d map[string]any) { resultAt(d, 0)["texts"].([]any)[0] = "100.64.0.7" }, "observations[0].result.texts[0]", "100.64.0.7"},
		{"a 64-digit hex string in a text", "A-2", func(d map[string]any) { resultAt(d, 0)["texts"].([]any)[0] = hex64 }, "observations[0].result.texts[0]", hex64},
		{"an address among the grammar's words", "A-2", func(d map[string]any) { resultAt(d, 0)["texts"].([]any)[0] = "address 100.64.0.7:22" }, "observations[0].result.texts[0]", "100.64.0.7"},
		{"a word the printer would have replaced", "A-2", func(d map[string]any) { resultAt(d, 0)["texts"].([]any)[0] = "<s> amy <s>" }, "observations[0].result.texts[0]", "amy"},
		{"a digit where the printer writes <n>", "A-2", func(d map[string]any) { resultAt(d, 0)["texts"].([]any)[0] = "line 7" }, "observations[0].result.texts[0]", "line 7"},
		{"a newline in a text", "A-2", func(d map[string]any) { resultAt(d, 0)["texts"].([]any)[0] = "<s>\n<s>" }, "observations[0].result.texts[0]", "<s>\n<s>"},
		{"a byte outside the vocabulary (a non-ASCII letter)", "A-2", func(d map[string]any) { resultAt(d, 0)["texts"].([]any)[0] = "<s> caf\xc3\xa9" }, "observations[0].result.texts[0]", "caf\xc3\xa9"},
		{"a control byte in a text", "A-2", func(d map[string]any) { resultAt(d, 0)["texts"].([]any)[0] = "<s>\x00<s>" }, "observations[0].result.texts[0]", "\x00"},
		{"a cut marker on a text that was not cut", "A-2", func(d map[string]any) { resultAt(d, 0)["texts"].([]any)[0] = "<s><cut>" }, "observations[0].result.texts[0]", "<s><cut>"},
		{"a placeholder inside a word", "A-2", func(d map[string]any) { resultAt(d, 0)["texts"].([]any)[0] = "<s><n>" }, "observations[0].result.texts[0]", "<s><n>"},
		{"a key that is not on the printer's list", "A-2", func(d map[string]any) {
			resultAt(d, 0)["paths"].([]any)[1].(map[string]any)["path"] = "amy@example.com"
		}, "observations[0].result.paths[1].path", "amy@example.com"},
		{"a listed key under an unlisted one", "A-2", func(d map[string]any) { resultAt(d, 1)["paths"].([]any)[2].(map[string]any)["path"] = "data[].lee" }, "observations[1].result.paths[2].path", "lee"},
		{"a path with an empty segment", "A-2", func(d map[string]any) { resultAt(d, 1)["paths"].([]any)[2].(map[string]any)["path"] = "data..user" }, "observations[1].result.paths[2].path", "data..user"},
		{"a type that is not a JSON type", "A-2", func(d map[string]any) { resultAt(d, 0)["paths"].([]any)[0].(map[string]any)["type"] = "amy" }, "observations[0].result.paths[0].type", "amy"},
		{"an ETag held raw", "A-13", func(d map[string]any) { obsAt(d, 0)["etag"] = `"` + hex64 + `"` }, "observations[0].etag", hex64},
		{"an ETag held raw, weak", "A-13", func(d map[string]any) { obsAt(d, 0)["etag"] = `W/"` + hex64 + `"` }, "observations[0].etag", hex64},
		{"an ETag form the printer does not write", "A-13", func(d map[string]any) { obsAt(d, 0)["etag"] = "quoted-hex65" }, "observations[0].etag", "quoted-hex65"},
		{"a date that is not a date", "A-2", func(d map[string]any) { d["observedOn"] = "2026-02-30" }, "observedOn", "2026-02-30"},
		{"a date in words", "A-2", func(d map[string]any) { d["observedOn"] = "amy@example.com" }, "observedOn", "amy@example.com"},
		{"a short date", "A-2", func(d map[string]any) { d["observedOn"] = "2026-10-2" }, "observedOn", "2026-10-2"},
		{"a time after the date", "A-2", func(d map[string]any) { d["observedOn"] = "2026-10-20T10:00:00Z" }, "observedOn", "2026-10-20T10:00:00Z"},
		{"a probe ID that is not the file's", "A-2", func(d map[string]any) { d["probe"] = "A-3" }, "probe", "A-3"},
		{"a changed title", "A-2", func(d map[string]any) { d["title"] = "lee@example.com" }, "title", "lee@example.com"},
		{"a changed sends", "A-2", func(d map[string]any) { d["sends"] = "100.64.0.7" }, "sends", "100.64.0.7"},
		{"a changed expected", "A-2", func(d map[string]any) { d["expected"] = d["expected"].(string) + " tailnet-name.ts.net" }, "expected", "tailnet-name.ts.net"},
		{"a changed branch", "A-2", func(d map[string]any) { d["branch"] = "" }, "branch", "zzz"},
		{"a changed label", "A-2", func(d map[string]any) { obsAt(d, 2)["label"] = "lee@example.com" }, "observations[2].label", "lee@example.com"},
		{"a changed expect", "A-2", func(d map[string]any) { obsAt(d, 2)["expect"] = "100.64.0.7" }, "observations[2].expect", "100.64.0.7"},
		{"a changed request", "A-2", func(d map[string]any) { obsAt(d, 2)["request"] = "POST validate, application/hujson, lee@example.com" }, "observations[2].request", "lee@example.com"},
		{"a request that is the probe's but for another request", "A-2", func(d map[string]any) { obsAt(d, 2)["request"] = obsAt(d, 3)["request"] }, "observations[2]", "zzz"},
		{"a changed check name", "A-2", func(d map[string]any) { items(d, "checks")[1].(map[string]any)["name"] = "lee@example.com" }, "checks[1].name", "lee@example.com"},
		{"a fact the probe does not record", "A-13", func(d map[string]any) { member(d, "facts")["amy@example.com"] = true }, "facts", "amy@example.com"},
		{"a count the probe does not record", "A-7", func(d map[string]any) { member(d, "counts")["lee@example.com"] = float64(3) }, "counts", "lee@example.com"},
		{"a skip sentence that is not the probe's", "A-9", func(d map[string]any) { items(d, "skipped")[0] = "the live policy has no host named lee-laptop" }, "skipped[0]", "lee-laptop"},
		{"a member the probe does not write, at the top", "A-2", func(d map[string]any) { d["note"] = "amy@example.com" }, "$", "amy@example.com"},
		{"a member the probe does not write, in a request", "A-2", func(d map[string]any) { obsAt(d, 0)["body"] = "amy@example.com" }, "observations[0]", "amy@example.com"},
		{"a member the probe does not write, in a result", "A-2", func(d map[string]any) { resultAt(d, 0)["raw"] = "amy@example.com" }, "observations[0].result", "amy@example.com"},
		{"a member the probe does not write, in a check", "A-2", func(d map[string]any) { items(d, "checks")[0].(map[string]any)["why"] = "amy@example.com" }, "checks[0]", "amy@example.com"},
		{"an error recorded in a request", "A-2", func(d map[string]any) { obsAt(d, 0)["error"] = "api_error" }, "observations[0]", "api_error"},
		{"a status that is not HTTP", "A-2", func(d map[string]any) { resultAt(d, 0)["status"] = float64(0) }, "observations[0].result.status", "zzz"},
		{"a body that is not a kind", "A-2", func(d map[string]any) { resultAt(d, 0)["body"] = "amy@example.com" }, "observations[0].result.body", "amy@example.com"},
		{"paths on a body that is not JSON", "A-2", func(d map[string]any) { resultAt(d, 0)["body"] = "text" }, "observations[0].result.paths", "zzz"},
		{"a count that is not a number", "A-7", func(d map[string]any) { member(d, "counts")["details errors"] = "amy@example.com" }, "counts", "amy@example.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(capturesDir(), c.stem+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if clean := captureProblems(c.stem, raw, vs); len(clean) != 0 {
				t.Fatalf("the capture the case starts from has problems: %v", clean)
			}
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			c.change(doc)
			edited, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			problems := captureProblems(c.stem, edited, vs)
			all := strings.Join(problems, "\n")
			if len(problems) == 0 {
				t.Fatalf("the changed capture passed")
			}
			if !strings.Contains(all, c.stem+".json: "+c.path) {
				t.Errorf("no problem names %s.json and the path %q:\n%s", c.stem, c.path, all)
			}
			if strings.Contains(all, c.planted) {
				t.Errorf("a problem shows the planted value %q:\n%s", c.planted, all)
			}
		})
	}
}

// A member written twice is found although a decoder keeps only the last, and the path names the object, never the key.
func TestCaptureCheckFindsARepeatedMember(t *testing.T) {
	vs := probeVocabularies(t)
	raw, err := os.ReadFile(filepath.Join(capturesDir(), "A-2.json"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for name, c := range map[string]struct{ old, new, path string }{
		"at the top":      {`"probe": "A-2",`, `"probe": "A-2", "probe": "A-2",`, "A-2.json: $: member"},
		"in a request":    {`"label": "an empty array",`, `"label": "amy@example.com", "label": "an empty array",`, "A-2.json: observations[0]: member"},
		"in a result":     {`"status": 400,`, `"status": 400, "status": 400,`, "A-2.json: observations[0].result: member"},
		"an unlisted key": {`"paths": [`, `"amy@example.com": 1, "amy@example.com": 2, "paths": [`, "A-2.json: observations[0].result: member"},
	} {
		if !strings.Contains(text, c.old) {
			t.Fatalf("%s: A-2.json lacks %q", name, c.old)
		}
		problems := captureProblems("A-2", []byte(strings.Replace(text, c.old, c.new, 1)), vs)
		all := strings.Join(problems, "\n")
		if !strings.Contains(all, c.path) || !strings.Contains(all, "repeats an earlier member") {
			t.Errorf("%s: no problem says %q and a repeated member:\n%s", name, c.path, all)
		}
		if strings.Contains(all, "amy@example.com") {
			t.Errorf("%s: a problem shows the planted key", name)
		}
	}
}

// A capture of a long text ends in <cut>, which Template writes again from the text before it.
func TestPrinterOutputAcceptsWhatTheProbeWrites(t *testing.T) {
	for _, in := range []string{
		`address "192.0.2.1:22": want: Accept, got: Drop`, "line 719, column 5: invalid literal: invalidtext", "tag not found: x",
		"", "   ", strings.Repeat("word ", 400), strings.Repeat("100.64.0.1:22 ", 100),
	} {
		out := skeleton.Template(in)
		if !printerOutput(out) {
			t.Errorf("Template(%.40q) = %.60q is not accepted", in, out)
		}
	}
	long := skeleton.Template(strings.Repeat("word ", 400))
	if !strings.HasSuffix(long, "<cut>") {
		t.Fatalf("the long text was not cut: %.60q", long)
	}
	// Cut earlier or later than the printer cuts, or not cut at all although long.
	for name, s := range map[string]string{
		"cut too early": "<s> <s><cut>", "too long, not cut": strings.TrimSuffix(long, "<cut>"), "cut twice": long + "<cut>",
		"cut in the middle": strings.Replace(long, "<s> <s>", "<s><cut> <s>", 1),
	} {
		if printerOutput(s) {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The directory check reads every file: it fails a planted value in a file on disk, a missing
// capture, a stray file and a file for no probe, and passes the committed captures copied whole.
func TestCaptureDirCheckFindsWhatItShould(t *testing.T) {
	vs := probeVocabularies(t)
	dir := t.TempDir()
	entries, err := os.ReadDir(capturesDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(capturesDir(), e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if problems, n := captureDirProblems(dir, vs); len(problems) != 0 || n != len(All()) {
		t.Fatalf("the copy of the committed captures: %d read, problems %v", n, problems)
	}

	// A raw value in a text, in the file on disk.
	path := filepath.Join(dir, "A-2.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	planted := strings.Replace(string(raw), `"<s> <s> <s>"`, `"amy@example.com"`, 1)
	if planted == string(raw) {
		t.Fatal("A-2.json holds no text to plant in")
	}
	if err := os.WriteFile(path, []byte(planted), 0o600); err != nil {
		t.Fatal(err)
	}
	// A missing capture, a stray file, a file for no probe, a directory.
	for name, content := range map[string]string{"notes.json": "{}", "README.md": "x", "A-99.json": "{}"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(dir, "H-1.json")); err != nil {
		t.Fatal(err)
	}
	problems, n := captureDirProblems(dir, vs)
	all := strings.Join(problems, "\n")
	t.Logf("planted run:\n%s", all)
	if n != len(All())-1 {
		t.Errorf("read %d captures, want %d", n, len(All())-1)
	}
	for _, want := range []string{"A-2.json: observations[0].result.texts[0]", "notes.json: not a capture", "README.md: not a capture", "A-99.json: not a capture", "H-1.json: missing"} {
		if !strings.Contains(all, want) {
			t.Errorf("no problem says %q", want)
		}
	}
	if strings.Contains(all, "amy@example.com") {
		t.Error("a problem shows the planted value")
	}
}

// The vocabularies are not empty or tiny: a probe that wrote nothing in every world would
// make every capture fail loudly, but one that wrote less than the capture needs must be seen.
func TestEveryProbeHasAVocabulary(t *testing.T) {
	vs := probeVocabularies(t)
	for _, p := range All() {
		v := vs[p.ID]
		if v == nil || len(v.observations) == 0 {
			t.Errorf("%s: no observations in any world", p.ID)
		}
	}
}
