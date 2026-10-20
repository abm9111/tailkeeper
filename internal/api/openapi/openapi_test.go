package openapi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

var update = flag.Bool("update", false, "rewrite operations.txt and fingerprint.txt from the document named by "+liveEnv)

var methods = []string{"get", "post", "put", "patch", "delete"}

// document is the part of an OpenAPI 3.1 document these tests read.
type document struct {
	Paths      map[string]map[string]yaml.Node `yaml:"paths"`
	Components struct {
		Schemas       map[string]*schema      `yaml:"schemas"`
		Responses     map[string]*response    `yaml:"responses"`
		Parameters    map[string]*parameter   `yaml:"parameters"`
		RequestBodies map[string]*requestBody `yaml:"requestBodies"`
	} `yaml:"components"`
}

// schema is the part of a schema object the fingerprint reads: its type and the
// fields below it. Examples, descriptions and constraints are left out on
// purpose, so a pinned fingerprint holds names and types only.
type schema struct {
	Ref        string             `yaml:"$ref"`
	Type       any                `yaml:"type"`
	Properties map[string]*schema `yaml:"properties"`
	Items      *schema            `yaml:"items"`
	// Values describes the values of a map (additionalProperties); the keyword
	// may also be a boolean, which describes no schema.
	Values values    `yaml:"additionalProperties"`
	AllOf  []*schema `yaml:"allOf"`
	OneOf  []*schema `yaml:"oneOf"`
	AnyOf  []*schema `yaml:"anyOf"`
}

type values struct{ *schema }

func (v *values) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	v.schema = new(schema)
	return n.Decode(v.schema)
}

type response struct {
	Ref     string `yaml:"$ref"`
	Content map[string]struct {
		Schema *schema `yaml:"schema"`
	} `yaml:"content"`
}

// parameter is a path, query or header parameter, inline or a $ref to
// components/parameters. Only its name and place are read: its schema, its
// description and whether it is required are left out, like the examples.
type parameter struct {
	Ref  string `yaml:"$ref"`
	Name string `yaml:"name"`
	In   string `yaml:"in"`
}

// requestBody is what an operation accepts: the content types of its body. The
// schema below each is left out: the pin records what a tool sends, and the
// document's schema of the validate body (an array or a string) is not a source
// for the fake API, whose shapes come from captured responses.
type requestBody struct {
	Ref     string              `yaml:"$ref"`
	Content map[string]struct{} `yaml:"content"`
}

type operation struct {
	Parameters  []*parameter         `yaml:"parameters"`
	RequestBody *requestBody         `yaml:"requestBody"`
	Responses   map[string]*response `yaml:"responses"`
}

func load(t *testing.T, path string) *document {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var d document
	if err := yaml.Unmarshal(b, &d); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if len(d.Paths) == 0 {
		t.Fatalf("%s has no paths", path)
	}
	return &d
}

func (d *document) operations() []string {
	var out []string
	for p, item := range d.Paths {
		for _, m := range methods {
			if _, ok := item[m]; ok {
				out = append(out, strings.ToUpper(m)+" "+p)
			}
		}
	}
	sort.Strings(out)
	return out
}

const liveEnv = "TAILKEEPER_OPENAPI_LIVE"

// header is the comment block at the top of operations.txt and fingerprint.txt;
// test names the test whose -update run writes the file.
func header(test, sum string) string {
	return "# Generated from Tailscale's OpenAPI document by " + test + " (go test ./internal/api/openapi -update); do not edit by hand.\n" +
		"# Document sha256 " + sum + ", fetched " + time.Now().Format("2006-01-02") + ".\n"
}

func TestOperationsMatchTheDocument(t *testing.T) {
	path := os.Getenv(liveEnv)
	if path == "" {
		t.Skipf("set %s to a copy of Tailscale's OpenAPI document (https://api.tailscale.com/api/v2?outputOpenapiSchema=true) to compare operations.txt with it", liveEnv)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ops := load(t, path).operations()
	if *update {
		sum := sha256.Sum256(raw)
		text := header("TestOperationsMatchTheDocument", hex.EncodeToString(sum[:])) + strings.Join(ops, "\n") + "\n"
		if err := os.WriteFile("operations.txt", []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		// operations.txt is embedded at compile time, so this run cannot compare
		// the file it just wrote: say so and let the next run check it.
		t.Log("operations.txt rewritten from the document; run the test again without -update to check it")
		return
	}
	have := map[string]bool{}
	for _, op := range Operations() {
		have[op] = true
	}
	want := map[string]bool{}
	for _, op := range ops {
		want[op] = true
		if !have[op] {
			t.Errorf("operation added to the document: %s", op)
		}
	}
	for op := range have {
		if !want[op] {
			t.Errorf("operation gone from the document: %s", op)
		}
	}
	if t.Failed() {
		t.Logf("run go test ./internal/api/openapi -run 'TestOperationsMatchTheDocument|TestLiveDocumentMatchesThePin' -update with %s set, and commit operations.txt and fingerprint.txt together", liveEnv)
	}
}

func TestOperationsFileLoads(t *testing.T) {
	if n := len(Operations()); n < 90 {
		t.Fatalf("only %d operations: operations.txt did not load as expected", n)
	}
	for _, op := range Operations() {
		if strings.HasPrefix(op, "#") || !strings.Contains(op, " /") {
			t.Errorf("not an operation: %q", op)
		}
	}
}

func TestParseOperationsSkipsHeaderAndBlankLines(t *testing.T) {
	got := parseOperations("# header\n\n  # indented comment\nGET /a\n\nPOST /b/{id}\n")
	if want := []string{"GET /a", "POST /b/{id}"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSkippedOperationsAreRequiredOnes(t *testing.T) {
	known := map[string]bool{}
	for _, op := range Operations() {
		known[op] = true
	}
	for op, why := range Skipped {
		if !known[op] || !Required(op) || why == "" {
			t.Errorf("skip entry %q: known %v, required %v, reason %q", op, known[op], Required(op), why)
		}
	}
}

// resolve follows $refs to a component schema. seen holds the schemas already
// followed on this path: meeting one again is a cycle, and ok is false with no
// error. A reference to a schema the document does not hold is an error, never a
// cycle: reading it as one would pin "(cycle)" for a field the walk could not see.
func (d *document) resolve(s *schema, seen map[string]bool) (*schema, bool, error) {
	for s != nil && s.Ref != "" {
		name := strings.TrimPrefix(s.Ref, "#/components/schemas/")
		if seen[name] {
			return nil, false, nil
		}
		seen[name] = true
		ref := s.Ref
		if s = d.Components.Schemas[name]; s == nil {
			return nil, false, fmt.Errorf("schema %s is not in components/schemas", ref)
		}
	}
	return s, s != nil, nil
}

func copySeen(m map[string]bool) map[string]bool {
	c := make(map[string]bool, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

// maxDepth bounds the walk below a response's root schema. Each level of
// properties, items or map values counts one, and so does each allOf, oneOf or
// anyOf member. A schema past the bound with nothing left to walk is a leaf and
// harmless; one with fields below it is an error (see walk).
const maxDepth = 8

// hasFields reports whether the walk would list a line below s if it went on: s
// declares properties, items or additionalProperties, or an allOf, oneOf or anyOf
// member (followed through $refs) does. A reference it cannot resolve is an
// error, as in the walk.
func (d *document) hasFields(s *schema, seen map[string]bool) (bool, error) {
	s, ok, err := d.resolve(s, seen)
	if err != nil || !ok {
		return false, err
	}
	if len(s.Properties) > 0 || s.Items != nil || s.Values.schema != nil {
		return true, nil
	}
	for _, sub := range slices.Concat(s.AllOf, s.OneOf, s.AnyOf) {
		if more, err := d.hasFields(sub, copySeen(seen)); err != nil || more {
			return more, err
		}
	}
	return false, nil
}

// walk appends "path type" for every property below s, and for the elements of
// an array ("[]") or a map ("{}"): through allOf, oneOf and anyOf, which keep the
// path, and into nested objects (".name"). A reference it cannot resolve is an
// error (see resolve); a cycle is cut and shows as "(cycle)". Past maxDepth it
// stops: a leaf there is fine, but a schema that still has fields below it is an
// error, because those fields would be left out of the pin without a word.
func (d *document) walk(prefix string, s *schema, depth int, seen map[string]bool, out *[]string) error {
	s, ok, err := d.resolve(s, seen)
	if err != nil || !ok {
		return err
	}
	if depth > maxDepth {
		more, err := d.hasFields(s, seen)
		if err != nil {
			return err
		}
		if more {
			return fmt.Errorf("fields below %q lie more than %d levels deep, past what the walk reads", prefix, maxDepth)
		}
		return nil
	}
	for _, sub := range slices.Concat(s.AllOf, s.OneOf, s.AnyOf) {
		if err := d.walk(prefix, sub, depth+1, copySeen(seen), out); err != nil {
			return err
		}
	}
	below := map[string]*schema{"[]": s.Items, "{}": s.Values.schema}
	for name, p := range s.Properties {
		below["."+name] = p
	}
	for suffix, p := range below {
		if p == nil {
			continue
		}
		path := strings.TrimPrefix(prefix+suffix, ".")
		typ := "(cycle)"
		r, ok, err := d.resolve(p, copySeen(seen))
		if err != nil {
			return err
		}
		if ok {
			typ = typeName(r.Type)
		}
		*out = append(*out, strings.TrimSpace(path+" "+typ))
		if err := d.walk(path, p, depth+1, copySeen(seen), out); err != nil {
			return err
		}
	}
	return nil
}

// typeName renders a schema's type: a name, or the list OpenAPI 3.1 allows
// joined with "|" ("boolean|null").
func typeName(t any) string {
	switch v := t.(type) {
	case nil:
		return ""
	case []any:
		names := make([]string, len(v))
		for i, n := range v {
			names[i] = fmt.Sprint(n)
		}
		return strings.Join(names, "|")
	}
	return fmt.Sprint(t)
}

// parameterLines returns "param <name> <in>" for each parameter in the lists
// (a path item's, then an operation's). A $ref is read from components/parameters;
// one that is not there, or a parameter without a name or a place, is an error:
// a line dropped because a reference did not resolve would pin less than the
// document says and look like a clean run.
func (d *document) parameterLines(lists ...[]*parameter) ([]string, error) {
	var out []string
	for _, list := range lists {
		for _, p := range list {
			if p == nil {
				return nil, errors.New("a parameter in a list is null")
			}
			label := p.Name
			if p.Ref != "" {
				label = p.Ref
				p = d.Components.Parameters[strings.TrimPrefix(label, "#/components/parameters/")]
				if p == nil {
					return nil, fmt.Errorf("parameter %s is not in components/parameters", label)
				}
			}
			if p.Name == "" || p.In == "" {
				what := "a parameter"
				if label != "" {
					what = "parameter " + label
				}
				return nil, fmt.Errorf("%s has no name or no place (in)", what)
			}
			out = append(out, "param "+p.Name+" "+p.In)
		}
	}
	return out, nil
}

// requestLines returns "req <content-type>" for each content type of the request
// body. A $ref is read from components/requestBodies; one that is not there, or
// that points at another reference, is an error, as for a response. So is a body
// with no content: every body the pin records names a content type, and a body
// that names none would leave the operation's "req" lines out unnoticed. A nil
// body is an operation that takes none, and no error.
func (d *document) requestLines(b *requestBody) ([]string, error) {
	if b == nil {
		return nil, nil
	}
	what := "request body"
	if b.Ref != "" {
		ref := b.Ref
		what += " " + ref
		b = d.Components.RequestBodies[strings.TrimPrefix(ref, "#/components/requestBodies/")]
		if b == nil {
			return nil, fmt.Errorf("request body %s is not in components/requestBodies", ref)
		}
		if b.Ref != "" {
			return nil, fmt.Errorf("request body %s is itself a reference (%s), which the walk does not follow", ref, b.Ref)
		}
	}
	if len(b.Content) == 0 {
		return nil, fmt.Errorf("%s has no content", what)
	}
	var out []string
	for ct := range b.Content {
		out = append(out, "req "+ct)
	}
	return out, nil
}

// responseLines returns the fields of the JSON content types of a response, each
// as "path type" (see walk). A $ref is read from components/responses; one that is
// not there, or that points at another reference, is an error, as is a schema
// below it that cannot be resolved. The caller asks only for the statuses it pins,
// so a response it does not pin is never resolved and never an error.
func (d *document) responseLines(r *response) ([]string, error) {
	if r != nil && r.Ref != "" {
		ref := r.Ref
		r = d.Components.Responses[strings.TrimPrefix(ref, "#/components/responses/")]
		if r == nil {
			return nil, fmt.Errorf("response %s is not in components/responses", ref)
		}
		if r.Ref != "" {
			return nil, fmt.Errorf("response %s is itself a reference (%s), which the walk does not follow", ref, r.Ref)
		}
	}
	if r == nil {
		return nil, nil
	}
	var out []string
	for ct, c := range r.Content {
		if !strings.Contains(ct, "json") {
			continue
		}
		if err := d.walk("", c.Schema, 0, map[string]bool{}, &out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// pinsStatus reports whether the fields of op's response with this status are
// pinned: every 2xx, and the 4xx of the operation ReadsErrorBody names.
func pinsStatus(op, status string) bool {
	return strings.HasPrefix(status, "2") || (strings.HasPrefix(status, "4") && ReadsErrorBody(op))
}

// fingerprint is fingerprintOf for a test that has nothing to do with a document
// it cannot read: any error ends the test.
func (d *document) fingerprint(t *testing.T) []string {
	t.Helper()
	out, err := d.fingerprintOf()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// fingerprintOf lists every required operation and what a tool depends on: the
// fields of its 2xx JSON responses (and of its 4xx JSON responses, for the
// operation ReadsErrorBody names), its parameters ("param <name> <in>") and the
// content types it accepts ("req <type>"). A reference it cannot resolve in
// anything it pins, and a field below the depth bound, is an error naming the
// operation, not a line left out: the returned list is only ever complete.
func (d *document) fingerprintOf() ([]string, error) {
	var out []string
	for p, item := range d.Paths {
		var shared []*parameter
		if node, ok := item["parameters"]; ok {
			if err := node.Decode(&shared); err != nil {
				return nil, fmt.Errorf("%s: parameters: %w", p, err)
			}
		}
		for _, m := range methods {
			node, ok := item[m]
			op := strings.ToUpper(m) + " " + p
			if !ok || !Required(op) {
				continue
			}
			out = append(out, op)
			var o operation
			if err := node.Decode(&o); err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			params, err := d.parameterLines(shared, o.Parameters)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			req, err := d.requestLines(o.RequestBody)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			for _, l := range slices.Concat(params, req) {
				out = append(out, op+" "+l)
			}
			for status, r := range o.Responses {
				if !pinsStatus(op, status) {
					continue
				}
				fields, err := d.responseLines(r)
				if err != nil {
					return nil, fmt.Errorf("%s %s: %w", op, status, err)
				}
				for _, f := range fields {
					out = append(out, op+" "+status+" "+f)
				}
			}
		}
	}
	sort.Strings(out)
	return slices.Compact(out), nil
}

// diff returns the lines of a that b lacks and the lines of b that a lacks.
func diff(a, b []string) (gone, added []string) {
	for _, v := range a {
		if !slices.Contains(b, v) {
			gone = append(gone, v)
		}
	}
	for _, v := range b {
		if !slices.Contains(a, v) {
			added = append(added, v)
		}
	}
	return gone, added
}

// wantMini is the fingerprint of testdata/mini.yaml, written out line by line:
// the $ref'd response and schema are resolved, allOf contributes the fields of
// both parts (Widget itself declares no type, so widgets[] has none), maps show
// as {}, a type list joins with "|", only required operations count (each GET
// and the validate POST), and the recursive parent field is cut. Their 2xx JSON
// responses count; so do every parameter (a path item's, an inline one and a
// $ref'd one, as "param <name> <in>") and every request content type
// ("req <type>"); the validate POST's 4xx JSON responses count too, and its 500
// and every other operation's 404 do not.
var wantMini = []string{
	"GET /widgets",
	"GET /widgets 200 widgets array",
	"GET /widgets 200 widgets[]",
	"GET /widgets 200 widgets[].createdAt string",
	"GET /widgets 200 widgets[].flags object",
	"GET /widgets 200 widgets[].id string",
	"GET /widgets 200 widgets[].labels object",
	"GET /widgets 200 widgets[].labels{} object",
	"GET /widgets 200 widgets[].labels{}.note string",
	"GET /widgets 200 widgets[].nickname string|null",
	"GET /widgets 200 widgets[].owner object",
	"GET /widgets 200 widgets[].owner.contact object",
	"GET /widgets 200 widgets[].owner.contact.kind string",
	"GET /widgets 200 widgets[].owner.name string",
	"GET /widgets 200 widgets[].parent (cycle)",
	"GET /widgets 200 widgets[].parts array",
	"GET /widgets 200 widgets[].parts[] object",
	"GET /widgets 200 widgets[].parts[].partId integer",
	"GET /widgets 200 widgets[].parts[].weight number",
	"GET /widgets param <field>=<value> filters query",
	"GET /widgets param Accept header",
	"GET /widgets param limit query",
	"GET /widgets/{id}",
	"GET /widgets/{id} 200 createdAt string",
	"GET /widgets/{id} 200 flags object",
	"GET /widgets/{id} 200 id string",
	"GET /widgets/{id} 200 labels object",
	"GET /widgets/{id} 200 labels{} object",
	"GET /widgets/{id} 200 labels{}.note string",
	"GET /widgets/{id} 200 nickname string|null",
	"GET /widgets/{id} 200 owner object",
	"GET /widgets/{id} 200 owner.contact object",
	"GET /widgets/{id} 200 owner.contact.kind string",
	"GET /widgets/{id} 200 owner.name string",
	"GET /widgets/{id} 200 parent (cycle)",
	"GET /widgets/{id} 200 parts array",
	"GET /widgets/{id} 200 parts[] object",
	"GET /widgets/{id} 200 parts[].partId integer",
	"GET /widgets/{id} 200 parts[].weight number",
	"GET /widgets/{id} param id path",
	"POST /tailnet/{tailnet}/acl/validate",
	"POST /tailnet/{tailnet}/acl/validate 200 data array",
	"POST /tailnet/{tailnet}/acl/validate 200 message string",
	"POST /tailnet/{tailnet}/acl/validate 400 hint string|null",
	"POST /tailnet/{tailnet}/acl/validate 400 message string",
	"POST /tailnet/{tailnet}/acl/validate 403 hint string|null",
	"POST /tailnet/{tailnet}/acl/validate 403 message string",
	"POST /tailnet/{tailnet}/acl/validate param tailnet path",
	"POST /tailnet/{tailnet}/acl/validate req application/hujson",
	"POST /tailnet/{tailnet}/acl/validate req application/json",
}

func TestFingerprintOfTheMiniDocument(t *testing.T) {
	got := load(t, "testdata/mini.yaml").fingerprint(t)
	if !slices.Equal(got, wantMini) {
		gone, added := diff(wantMini, got)
		t.Fatalf("fingerprint differs from the expected lines\nmissing: %q\nunexpected: %q", gone, added)
	}
}

// The detector must see a change before a clean drift run means anything.
func TestFingerprintSeesAChangedField(t *testing.T) {
	pinned, err := os.ReadFile("testdata/mini.yaml")
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.ReplaceAll(string(pinned), "kind:", "category:")
	if changed == string(pinned) {
		t.Fatal("the plant did not apply: pick another field the document holds")
	}
	path := filepath.Join(t.TempDir(), "changed.yaml")
	if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	gone, added := diff(load(t, "testdata/mini.yaml").fingerprint(t), load(t, path).fingerprint(t))
	for _, want := range []string{
		"GET /widgets 200 widgets[].owner.contact.kind string",
		"GET /widgets/{id} 200 owner.contact.kind string",
	} {
		if !slices.Contains(gone, want) {
			t.Errorf("%q is not reported as gone: %q", want, gone)
		}
	}
	for _, want := range []string{
		"GET /widgets 200 widgets[].owner.contact.category string",
		"GET /widgets/{id} 200 owner.contact.category string",
	} {
		if !slices.Contains(added, want) {
			t.Errorf("%q is not reported as new: %q", want, added)
		}
	}
	if len(gone) != 2 || len(added) != 2 {
		t.Errorf("only the renamed field should differ: gone %q, added %q", gone, added)
	}
}

// The request side and the error bodies are pinned, and nothing around them is:
// a changed content type, parameter name, parameter place or 4xx field of the
// validate call shows, while a write operation's parameter, a body's fields, a
// 500's fields and a GET's 404 do not move the fingerprint.
func TestFingerprintSeesAChangedRequestSide(t *testing.T) {
	pinned, err := os.ReadFile("testdata/mini.yaml")
	if err != nil {
		t.Fatal(err)
	}
	changed := string(pinned)
	for _, r := range [][2]string{
		// pinned
		{"application/hujson:", "application/x-hujson:"},
		{"name: limit", "name: pagesize"},
		{"name: tailnet", "name: tenant"},
		{"hint:", "tip:"},
		// not pinned
		{"name: dryRun", "name: dry"},
		{"name: force", "name: hard"},
		{"formOnly:", "formElse:"},
		{"bodyOnly:", "bodyElse:"},
		{"serverOnly:", "serverElse:"},
		{"errorOnly:", "errorElse:"},
	} {
		if !strings.Contains(changed, r[0]) {
			t.Fatalf("the plant %q did not apply: the document does not hold it", r[0])
		}
		changed = strings.ReplaceAll(changed, r[0], r[1])
	}
	path := filepath.Join(t.TempDir(), "changed.yaml")
	if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	gone, added := diff(load(t, "testdata/mini.yaml").fingerprint(t), load(t, path).fingerprint(t))
	wantGone := []string{
		"GET /widgets param limit query",
		"POST /tailnet/{tailnet}/acl/validate 400 hint string|null",
		"POST /tailnet/{tailnet}/acl/validate 403 hint string|null",
		"POST /tailnet/{tailnet}/acl/validate param tailnet path",
		"POST /tailnet/{tailnet}/acl/validate req application/hujson",
	}
	wantAdded := []string{
		"GET /widgets param pagesize query",
		"POST /tailnet/{tailnet}/acl/validate 400 tip string|null",
		"POST /tailnet/{tailnet}/acl/validate 403 tip string|null",
		"POST /tailnet/{tailnet}/acl/validate param tenant path",
		"POST /tailnet/{tailnet}/acl/validate req application/x-hujson",
	}
	slices.Sort(gone)
	slices.Sort(added)
	if !slices.Equal(gone, wantGone) || !slices.Equal(added, wantAdded) {
		t.Errorf("gone %q, want %q\nadded %q, want %q", gone, wantGone, added, wantAdded)
	}
}

// A parameter or a request body the document points at and does not hold is an
// error, not a line left out: a fingerprint that dropped it would pin less than the
// document says and read as a clean run.
func TestParameterAndRequestLinesRefuseWhatTheyCannotResolve(t *testing.T) {
	d := &document{}
	d.Components.Parameters = map[string]*parameter{"Known": {Name: "n", In: "query"}}
	d.Components.RequestBodies = map[string]*requestBody{
		"Known": {Content: map[string]struct{}{"application/json": {}}},
		"Alias": {Ref: "#/components/requestBodies/Known"},
		"Empty": {},
	}

	got, err := d.parameterLines([]*parameter{{Ref: "#/components/parameters/Known"}}, []*parameter{{Name: "x", In: "header"}})
	if want := []string{"param n query", "param x header"}; err != nil || !slices.Equal(got, want) {
		t.Errorf("parameterLines = %q, %v; want %q", got, err, want)
	}
	for name, bad := range map[string][]*parameter{
		"a $ref the document lacks":      {{Ref: "#/components/parameters/Gone"}},
		"a $ref to another kind":         {{Ref: "#/components/schemas/Known"}},
		"a parameter without a place":    {{Name: "x"}},
		"a parameter without a name":     {{In: "query"}},
		"a null entry in the list":       {nil},
		"a good parameter and a bad one": {{Name: "x", In: "query"}, {Ref: "#/components/parameters/Gone"}},
	} {
		if got, err := d.parameterLines(bad); err == nil {
			t.Errorf("%s: parameterLines = %q, want an error", name, got)
		}
	}

	if got, err := d.requestLines(nil); err != nil || len(got) != 0 {
		t.Errorf("requestLines(nil) = %q, %v; want no lines", got, err)
	}
	got, err = d.requestLines(&requestBody{Ref: "#/components/requestBodies/Known"})
	if want := []string{"req application/json"}; err != nil || !slices.Equal(got, want) {
		t.Errorf("requestLines($ref) = %q, %v; want %q", got, err, want)
	}
	for name, bad := range map[string]*requestBody{
		"a $ref the document lacks":        {Ref: "#/components/requestBodies/Gone"},
		"a $ref to another kind":           {Ref: "#/components/schemas/Known"},
		"a $ref to a $ref":                 {Ref: "#/components/requestBodies/Alias"},
		"a $ref to a body without content": {Ref: "#/components/requestBodies/Empty"},
		"an inline body without content":   {},
	} {
		if got, err := d.requestLines(bad); err == nil {
			t.Errorf("%s: requestLines = %q, want an error", name, got)
		}
	}
}

// plant replaces the one occurrence of old in text with new, and fails the test if
// the document does not hold old exactly once: a plant that did not apply would
// make the test below it prove nothing.
func plant(t *testing.T, text, old, new string) string {
	t.Helper()
	if n := strings.Count(text, old); n != 1 {
		t.Fatalf("the plant %q applies %d times, want once", old, n)
	}
	return strings.Replace(text, old, new, 1)
}

func loadText(t *testing.T, text string) *document {
	t.Helper()
	var d document
	if err := yaml.Unmarshal([]byte(text), &d); err != nil {
		t.Fatal(err)
	}
	return &d
}

// The walk passes a reference it cannot resolve on as an error that names the
// operation, in anything the pin records. The unit test above proves the helpers
// refuse; this one proves fingerprintOf does not drop the line, read the reference
// as a cycle or skip the response. A response or schema the pin does not record is
// not resolved at all: widening what is pinned is the pin's decision, not the
// walk's.
func TestFingerprintRefusesADanglingReference(t *testing.T) {
	raw, err := os.ReadFile("testdata/mini.yaml")
	if err != nil {
		t.Fatal(err)
	}
	mini := string(raw)
	const validate = "POST /tailnet/{tailnet}/acl/validate"
	for _, tc := range []struct {
		name, old, new string
		also           [2]string // a second plant, applied after the first (zero: none)
		op, status     string
		ref, ref2      string // what the error must name (ref2: zero for none)
	}{
		{
			name: "an operation parameter",
			old:  "#/components/parameters/AcceptHeader", new: "#/components/parameters/Gone",
			op: "GET /widgets", ref: "#/components/parameters/Gone",
		},
		{
			name: "a path item parameter",
			old:  "#/components/parameters/Tenant", new: "#/components/parameters/Gone",
			op: validate, ref: "#/components/parameters/Gone",
		},
		{
			name: "the validate request body",
			old:  "      requestBody:\n        content:\n          application/json:\n            schema:\n              oneOf:",
			new:  "      requestBody:\n        $ref: '#/components/requestBodies/Gone'\n        content:\n          application/json:\n            schema:\n              oneOf:",
			op:   validate, ref: "#/components/requestBodies/Gone",
		},
		{
			name: "a request body that is itself a reference",
			old:  "      requestBody:\n        content:\n          application/json:\n            schema:\n              oneOf:",
			new:  "      requestBody:\n        $ref: '#/components/requestBodies/Outer'\n        content:\n          application/json:\n            schema:\n              oneOf:",
			also: [2]string{
				"components:\n  parameters:\n",
				"components:\n  requestBodies:\n    Outer:\n      $ref: '#/components/requestBodies/Inner'\n    Inner:\n      content:\n        application/json:\n          schema:\n            type: string\n  parameters:\n",
			},
			op: validate, ref: "#/components/requestBodies/Outer", ref2: "#/components/requestBodies/Inner",
		},
		{
			name: "a request body component without content",
			old:  "      requestBody:\n        content:\n          application/json:\n            schema:\n              oneOf:",
			new:  "      requestBody:\n        $ref: '#/components/requestBodies/Empty'\n        content:\n          application/json:\n            schema:\n              oneOf:",
			also: [2]string{
				"components:\n  parameters:\n",
				"components:\n  requestBodies:\n    Empty:\n      description: A body that names no content type.\n  parameters:\n",
			},
			op: validate, ref: "#/components/requestBodies/Empty", ref2: "has no content",
		},
		{
			name: "an inline request body without content",
			old:  "      requestBody:\n        content:\n          application/json:\n            schema:\n              oneOf:",
			new:  "      requestBody:\n        description: A body that names no content type.\n        notContent:\n          application/json:\n            schema:\n              oneOf:",
			op:   validate, ref: "request body has no content",
		},
		{
			name: "the validate 400 response",
			old:  "#/components/responses/BadRequest", new: "#/components/responses/Gone",
			op: validate, status: "400", ref: "#/components/responses/Gone",
		},
		{
			name: "a 2xx response",
			old:  "#/components/responses/Widgets", new: "#/components/responses/Gone",
			op: "GET /widgets", status: "200", ref: "#/components/responses/Gone",
		},
		{
			name: "a response that is itself a reference",
			old:  "    BadRequest:\n      description: Bad request.\n",
			new:  "    BadRequest:\n      $ref: '#/components/responses/Widgets'\n      description: Bad request.\n",
			op:   validate, status: "400", ref: "#/components/responses/Widgets",
		},
		{
			name: "the schema of a response",
			old:  "    Problem:\n", new: "    Renamed:\n",
			op: validate, ref: "#/components/schemas/Problem",
		},
		{
			name: "an allOf member",
			old:  "#/components/schemas/Base", new: "#/components/schemas/Gone",
			op: "GET /widgets", ref: "#/components/schemas/Gone",
		},
		{
			name: "the items of an array",
			old:  "                  $ref: '#/components/schemas/Widget'\n", new: "                  $ref: '#/components/schemas/Gone'\n",
			op: "GET /widgets", status: "200", ref: "#/components/schemas/Gone",
		},
		{
			// Read as a cycle, this would pin "parent (cycle)" for a field the walk never saw.
			name: "a property that is not a cycle",
			old:  "            parent:\n              $ref: '#/components/schemas/Widget'", new: "            parent:\n              $ref: '#/components/schemas/Gone'",
			op: "GET /widgets", ref: "#/components/schemas/Gone",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := plant(t, mini, tc.old, tc.new)
			if tc.also != ([2]string{}) {
				text = plant(t, text, tc.also[0], tc.also[1])
			}
			got, err := loadText(t, text).fingerprintOf()
			if err == nil {
				t.Fatalf("fingerprintOf = %d lines and no error, want an error", len(got))
			}
			if got != nil {
				t.Errorf("fingerprintOf returned %d lines beside its error: a caller that ignored the error would read a partial list", len(got))
			}
			want := []string{tc.op, tc.ref}
			if tc.ref2 != "" {
				want = append(want, tc.ref2)
			}
			if tc.status != "" {
				want = append(want, " "+tc.status+": ")
			}
			for _, w := range want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("the error %q does not hold %q", err, w)
				}
			}
		})
	}

	// The same references where nothing is pinned: a 500 and a GET's 404, a write
	// operation, and a schema below a response whose status is not pinned. None is
	// resolved, so none is an error, and the list is the mini document's.
	for _, tc := range []struct{ name, old, new string }{
		{
			name: "the validate 500 response",
			old:  "        '500':\n          description: Server error.\n",
			new:  "        '500':\n          $ref: '#/components/responses/Gone'\n          description: Server error.\n",
		},
		{
			name: "the schema of the validate 500 response",
			old:  "                type: object\n                properties:\n                  serverOnly:\n                    type: string\n",
			new:  "                $ref: '#/components/schemas/Gone'\n",
		},
		{
			name: "a GET 404 response",
			old:  "        '404':\n          description: Not found.\n",
			new:  "        '404':\n          $ref: '#/components/responses/Gone'\n          description: Not found.\n",
		},
		{
			name: "a write operation's parameter",
			old:  "        - name: dryRun\n",
			new:  "        - $ref: '#/components/parameters/Gone'\n          name: dryRun\n",
		},
		{
			name: "a write operation's request body",
			old:  "      requestBody:\n        content:\n          application/x-www-form-urlencoded:\n",
			new:  "      requestBody:\n        $ref: '#/components/requestBodies/Gone'\n        content:\n          application/x-www-form-urlencoded:\n",
		},
	} {
		t.Run("unpinned: "+tc.name, func(t *testing.T) {
			got, err := loadText(t, plant(t, mini, tc.old, tc.new)).fingerprintOf()
			if err != nil {
				t.Fatalf("fingerprintOf: %v", err)
			}
			if !slices.Equal(got, wantMini) {
				gone, added := diff(wantMini, got)
				t.Errorf("an unpinned reference moved the fingerprint\nmissing: %q\nunexpected: %q", gone, added)
			}
		})
	}
}

// nestedDoc is a document with one GET whose 200 response is an object nested
// depth levels deep: the schema below each level holds one property (p1, p2, ...)
// and the schema of the last, at walk depth `depth`, is last (a YAML mapping, as
// text).
func nestedDoc(depth int, last string) string {
	var b strings.Builder
	b.WriteString("paths:\n  /nest:\n    get:\n      responses:\n        '200':\n          description: Nested.\n          content:\n            application/json:\n              schema:\n")
	indent := "                "
	for i := 1; i <= depth; i++ {
		fmt.Fprintf(&b, "%stype: object\n%sproperties:\n%s  p%d:\n", indent, indent, indent, i)
		indent += "    "
	}
	b.WriteString(indent + strings.ReplaceAll(last, "\n", "\n"+indent) + "\n")
	return b.String()
}

// The walk stops below maxDepth, and a field it stops at must not vanish without a
// word: a schema past the bound that still has properties, items or
// additionalProperties to walk is an error, while a leaf there is not. Depth counts
// each level of properties, items and map values, and each allOf/oneOf/anyOf member.
func TestFingerprintRefusesFieldsPastTheDepthBound(t *testing.T) {
	const leaf = "type: string"
	const fields = "type: object\nproperties:\n  x:\n    type: string"
	path := func(n int) string { // p1.p2...pn
		parts := make([]string, n)
		for i := range parts {
			parts[i] = fmt.Sprintf("p%d", i+1)
		}
		return strings.Join(parts, ".")
	}

	// Within the bound, the walk is complete: the deepest field is listed.
	for name, tc := range map[string]struct {
		depth int
		last  string
		line  string
	}{
		"a leaf at the bound":                      {maxDepth, leaf, "GET /nest 200 " + path(maxDepth) + " string"},
		"fields below the last level at the bound": {maxDepth, fields, "GET /nest 200 " + path(maxDepth) + ".x string"},
		"a leaf one level past the bound":          {maxDepth + 1, leaf, "GET /nest 200 " + path(maxDepth+1) + " string"},
	} {
		t.Run("ok: "+name, func(t *testing.T) {
			got, err := loadText(t, nestedDoc(tc.depth, tc.last)).fingerprintOf()
			if err != nil {
				t.Fatalf("fingerprintOf: %v", err)
			}
			if !slices.Contains(got, tc.line) {
				t.Errorf("the list lacks %q: %q", tc.line, got)
			}
		})
	}

	// One level past the bound with something still to walk below it.
	for name, last := range map[string]string{
		"properties":           fields,
		"items":                "type: array\nitems:\n  type: string",
		"additionalProperties": "type: object\nadditionalProperties:\n  type: string",
		"an allOf member":      "allOf:\n  - type: object\n    properties:\n      x:\n        type: string",
		"a oneOf member":       "oneOf:\n  - type: object\n    properties:\n      x:\n        type: string",
		"an anyOf member":      "anyOf:\n  - type: array\n    items:\n      type: string",
	} {
		t.Run("error: "+name, func(t *testing.T) {
			got, err := loadText(t, nestedDoc(maxDepth+1, last)).fingerprintOf()
			if err == nil {
				t.Fatalf("fingerprintOf = %d lines and no error, want an error", len(got))
			}
			if got != nil {
				t.Errorf("fingerprintOf returned %d lines beside its error", len(got))
			}
			for _, w := range []string{"GET /nest 200", path(maxDepth + 1), fmt.Sprint(maxDepth)} {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("the error %q does not hold %q", err, w)
				}
			}
		})
	}

	// A member of a composite that has nothing to walk is a leaf, past the bound too.
	t.Run("ok: a leaf allOf member past the bound", func(t *testing.T) {
		if _, err := loadText(t, nestedDoc(maxDepth+1, "allOf:\n  - type: string")).fingerprintOf(); err != nil {
			t.Errorf("fingerprintOf: %v", err)
		}
	})
}

// ReadsErrorBody names the operation whose 4xx fields the pin records, and it must
// stay an operation the pin knows and requires: a renamed path would leave the
// error fields unpinned without failing anything else.
func TestReadsErrorBodyNamesARequiredOperation(t *testing.T) {
	if !ReadsErrorBody("POST /tailnet/{tailnet}/acl/validate") || ReadsErrorBody("GET /tailnet/{tailnet}/acl") {
		t.Error("ReadsErrorBody is not true for the validate call alone")
	}
	n := 0
	for _, op := range Operations() {
		if ReadsErrorBody(op) {
			n++
			if !Required(op) {
				t.Errorf("ReadsErrorBody names %s, which is not a required operation", op)
			}
		}
	}
	if n != 1 {
		t.Errorf("ReadsErrorBody names %d operations, want 1 (the validate call)", n)
	}
}

func TestDiffReportsBothDirections(t *testing.T) {
	gone, added := diff([]string{"a", "b"}, []string{"b", "c"})
	if !slices.Equal(gone, []string{"a"}) || !slices.Equal(added, []string{"c"}) {
		t.Errorf("gone %q, added %q", gone, added)
	}
}

// errorLine matches the pinned fields of a 4xx response.
var errorLine = regexp.MustCompile(`^[A-Z]+ \S+ 4\d\d `)

// The pinned fingerprint must hold the walk's results, not just operations: a
// walk that reached no schema, no parameter or no request body would still match
// itself. The floors sit below the counts of 18 Oct 2026 (621 lines: 519 fields of
// 2xx responses, 61 parameters, 2 request content types, 3 fields of error
// responses), so an ordinary change of the document does not trip them.
func TestFingerprintFileLoads(t *testing.T) {
	raw, err := os.ReadFile("fingerprint.txt")
	if err != nil {
		t.Fatal(err)
	}
	lines := parseOperations(string(raw))
	fields, params, requests, errs := 0, 0, 0, 0
	for _, l := range lines {
		switch {
		case strings.Contains(l, " 200 "):
			fields++
		case strings.Contains(l, " param "):
			params++
		case strings.Contains(l, " req "):
			requests++
		case errorLine.MatchString(l):
			errs++
		}
	}
	if len(lines) < 500 || fields < 400 || params < 45 || requests < 2 || errs < 3 {
		t.Fatalf("%d lines, %d of them 2xx response fields, %d parameters, %d request content types and %d error fields: fingerprint.txt did not load as expected", len(lines), fields, params, requests, errs)
	}
	if !slices.IsSorted(lines) {
		t.Error("fingerprint.txt is not sorted")
	}
	for _, op := range Operations() {
		if Required(op) && !slices.Contains(lines, op) {
			t.Errorf("required operation %q is missing from fingerprint.txt", op)
		}
		if ReadsErrorBody(op) && !slices.ContainsFunc(lines, func(l string) bool { return strings.HasPrefix(l, op+" 4") }) {
			t.Errorf("ReadsErrorBody names %q, and fingerprint.txt pins no 4xx field of it", op)
		}
	}
	// A parameter line is "<op> param <name> <in>", and a name may hold spaces:
	// <in> is the last word, and nothing may have split the line on spaces. A line
	// with two spaces in a row would hide an empty word.
	for _, l := range lines {
		if strings.Contains(l, "  ") {
			t.Errorf("line %q holds two spaces in a row", l)
		}
		if strings.Contains(l, " param ") && !slices.Contains([]string{"path", "query", "header"}, l[strings.LastIndex(l, " ")+1:]) {
			t.Errorf("parameter line %q does not end in path, query or header", l)
		}
	}
	// What the policy work of 0.6.0 sends and reads. A change to any of these in
	// Tailscale's document fails the weekly drift job; once the owner has reviewed
	// it and moved the pin, this list is where tailkeeper's design is asked to
	// agree.
	for _, want := range []string{
		"POST /tailnet/{tailnet}/acl/validate req application/hujson",
		"POST /tailnet/{tailnet}/acl/validate req application/json",
		"POST /tailnet/{tailnet}/acl/validate 400 message string",
		"GET /tailnet/{tailnet}/acl param details query",
		"GET /tailnet/{tailnet}/acl param Accept header",
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("fingerprint.txt lacks %q", want)
		}
	}
}

// operations.txt and fingerprint.txt are written by different tests from the same
// document, and each names that document's hash and fetch date on its second
// line: nothing else ties the two, so a refresh that moved one file and not the
// other would leave pins of different documents side by side.
func TestPinHeadersNameTheSameDocument(t *testing.T) {
	var second [2]string
	for i, name := range []string{"operations.txt", "fingerprint.txt"} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.SplitN(string(raw), "\n", 3)
		if len(lines) < 3 || !strings.HasPrefix(lines[1], "# Document sha256 ") {
			t.Fatalf("%s: the second line is not the document header: %q", name, lines)
		}
		second[i] = lines[1]
	}
	if second[0] != second[1] {
		t.Errorf("the pins name different documents\noperations.txt:  %s\nfingerprint.txt: %s", second[0], second[1])
	}
}

// TestLiveDocumentMatchesThePin runs in the weekly drift job, which downloads
// the live document and names it in TAILKEEPER_OPENAPI_LIVE. With -update it
// rewrites fingerprint.txt from that document instead.
func TestLiveDocumentMatchesThePin(t *testing.T) {
	path := os.Getenv(liveEnv)
	if path == "" {
		t.Skipf("set %s to a copy of Tailscale's OpenAPI document to compare fingerprint.txt with it; the weekly drift job sets it", liveEnv)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	live := load(t, path).fingerprint(t)
	if *update {
		sum := sha256.Sum256(raw)
		text := header("TestLiveDocumentMatchesThePin", hex.EncodeToString(sum[:])) + strings.Join(live, "\n") + "\n"
		if err := os.WriteFile("fingerprint.txt", []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("fingerprint.txt rewritten from the document: %d lines", len(live))
		return
	}
	pinned, err := os.ReadFile("fingerprint.txt")
	if err != nil {
		t.Fatal(err)
	}
	gone, added := diff(parseOperations(string(pinned)), live)
	for _, v := range gone {
		t.Errorf("gone from the live document: %s", v)
	}
	for _, v := range added {
		t.Errorf("new in the live document: %s", v)
	}
	if len(gone)+len(added) > 0 {
		t.Logf("review the change and update tailkeeper if a tool depends on it; then run go test ./internal/api/openapi -run 'TestOperationsMatchTheDocument|TestLiveDocumentMatchesThePin' -update with %s set to the reviewed document, and commit operations.txt and fingerprint.txt together", liveEnv)
	}
}
