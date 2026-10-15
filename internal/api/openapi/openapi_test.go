package openapi

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
		Schemas   map[string]*schema   `yaml:"schemas"`
		Responses map[string]*response `yaml:"responses"`
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

type operation struct {
	Responses map[string]*response `yaml:"responses"`
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
// followed on this path: meeting one again is a cycle, and ok is false.
func (d *document) resolve(s *schema, seen map[string]bool) (*schema, bool) {
	for s != nil && s.Ref != "" {
		name := strings.TrimPrefix(s.Ref, "#/components/schemas/")
		if seen[name] {
			return nil, false
		}
		seen[name] = true
		s = d.Components.Schemas[name]
	}
	return s, s != nil
}

func copySeen(m map[string]bool) map[string]bool {
	c := make(map[string]bool, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

// maxDepth bounds the walk below a response's root schema.
const maxDepth = 8

// walk appends "path type" for every property below s, and for the elements of
// an array ("[]") or a map ("{}"): through allOf, oneOf and anyOf, which keep the
// path, and into nested objects (".name").
func (d *document) walk(prefix string, s *schema, depth int, seen map[string]bool, out *[]string) {
	s, ok := d.resolve(s, seen)
	if !ok || depth > maxDepth {
		return
	}
	for _, sub := range slices.Concat(s.AllOf, s.OneOf, s.AnyOf) {
		d.walk(prefix, sub, depth+1, copySeen(seen), out)
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
		if r, ok := d.resolve(p, copySeen(seen)); ok {
			typ = typeName(r.Type)
		}
		*out = append(*out, strings.TrimSpace(path+" "+typ))
		d.walk(path, p, depth+1, copySeen(seen), out)
	}
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

// fingerprint lists every required operation and the fields of its 2xx JSON
// responses: what a tool's decoding depends on.
func (d *document) fingerprint(t *testing.T) []string {
	t.Helper()
	var out []string
	for p, item := range d.Paths {
		for _, m := range methods {
			node, ok := item[m]
			op := strings.ToUpper(m) + " " + p
			if !ok || !Required(op) {
				continue
			}
			out = append(out, op)
			var o operation
			if err := node.Decode(&o); err != nil {
				t.Fatalf("%s: %v", op, err)
			}
			for status, r := range o.Responses {
				if !strings.HasPrefix(status, "2") || r == nil {
					continue
				}
				if r.Ref != "" {
					r = d.Components.Responses[strings.TrimPrefix(r.Ref, "#/components/responses/")]
				}
				if r == nil {
					continue
				}
				for ct, c := range r.Content {
					if !strings.Contains(ct, "json") {
						continue
					}
					var fields []string
					d.walk("", c.Schema, 0, map[string]bool{}, &fields)
					for _, f := range fields {
						out = append(out, op+" "+status+" "+f)
					}
				}
			}
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
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
// as {}, a type list joins with "|", only required GETs and their 2xx JSON
// responses count, and the recursive parent field is cut.
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

func TestDiffReportsBothDirections(t *testing.T) {
	gone, added := diff([]string{"a", "b"}, []string{"b", "c"})
	if !slices.Equal(gone, []string{"a"}) || !slices.Equal(added, []string{"c"}) {
		t.Errorf("gone %q, added %q", gone, added)
	}
}

// The pinned fingerprint must hold the walk's results, not just operations: a
// walk that reached no schema would still match itself.
func TestFingerprintFileLoads(t *testing.T) {
	raw, err := os.ReadFile("fingerprint.txt")
	if err != nil {
		t.Fatal(err)
	}
	lines := parseOperations(string(raw))
	fields := 0
	for _, l := range lines {
		if strings.Contains(l, " 200 ") {
			fields++
		}
	}
	if len(lines) < 400 || fields < 350 {
		t.Fatalf("%d lines, %d of them response fields: fingerprint.txt did not load as expected", len(lines), fields)
	}
	if !slices.IsSorted(lines) {
		t.Error("fingerprint.txt is not sorted")
	}
	for _, op := range Operations() {
		if Required(op) && !slices.Contains(lines, op) {
			t.Errorf("required operation %q is missing from fingerprint.txt", op)
		}
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
