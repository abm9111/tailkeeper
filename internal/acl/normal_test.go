package acl

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/tailscale/hujson"
)

func normalise(t testing.TB, text string) *NormalForm {
	t.Helper()
	n, err := Normalise(context.Background(), mustParse(t, text))
	if err != nil {
		t.Fatalf("Normalise(%.80q): %v", text, err)
	}
	return n
}

// same fails unless the two texts have one normal form; differ, unless they have two.
func same(t *testing.T, name, a, b string) {
	t.Helper()
	if x, y := normalise(t, a).Bytes(), normalise(t, b).Bytes(); string(x) != string(y) {
		t.Errorf("%s: the normal forms differ\n--- a: %s\n--- b: %s\n%s\n%s", name, a, b, x, y)
	}
}

func differ(t *testing.T, name, a, b string) {
	t.Helper()
	if x, y := normalise(t, a).Bytes(), normalise(t, b).Bytes(); string(x) == string(y) {
		t.Errorf("%s: the normal forms are equal, and the policies differ\n--- a: %s\n--- b: %s", name, a, b)
	}
}

func section(t testing.TB, n *NormalForm, name string) *nfSec {
	t.Helper()
	for _, s := range n.secs {
		if s.name == name {
			return s
		}
	}
	t.Fatalf("no section %s", name)
	return nil
}

func TestAbsentNullAndEmptyAreStates(t *testing.T) {
	for in, want := range map[string]State{
		`{}`:                           StateAbsent,
		`{"acls": null}`:               StateAbsent,
		`{"acls": []}`:                 StateEmpty,
		`{"grants": []}`:               StateEmpty,
		`{"grants": [], "acls": null}`: StateEmpty,
		`{"acls": [], "grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}`: StateNonEmpty,
	} {
		if got := normalise(t, in).AccessState(); got != want {
			t.Errorf("%s: access state %v, want %v", in, got, want)
		}
	}
	if s := section(t, normalise(t, `{"acls": null}`), "acls"); !s.null || s.state != StateAbsent {
		t.Errorf("null: %+v", s)
	}
	if s := section(t, normalise(t, `{"acls": []}`), "acls"); s.null || s.state != StateEmpty {
		t.Errorf("empty: %+v", s)
	}
	// null is the same state as absent; [] is a different one.
	same(t, "null is absent", `{"acls": null}`, `{}`)
	differ(t, "empty is not absent", `{"acls": []}`, `{}`)
	// acls and grants are read together: the console moves a policy from one to the other.
	differ(t, "acls [] beside grants []", `{"acls": [], "grants": []}`, `{"grants": []}`)
	differ(t, "an empty pool is not an absent one", `{"grants": []}`, `{}`)
}

func TestARuleBecomesAtoms(t *testing.T) {
	n := normalise(t, `{"acls": [{"action": "accept", "src": ["group:eng", "group:eng", "autogroup:members"], "dst": ["tag:web:443,80", "tag:db:5432", "tag:web:8080"], "proto": "tcp"}]}`)
	var got []string
	for _, a := range n.atoms {
		got = append(got, fmt.Sprintf("%s %s %s %v", a.dst, a.proto, a.ports, a.src.items))
	}
	want := []string{
		"tag:db tcp 5432 [autogroup:member group:eng]",
		"tag:web tcp 80,443,8080 [autogroup:member group:eng]",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("atoms:\n got  %q\n want %q", got, want)
	}
}

// A rule split or merged by source, by destination or by ports is the same atoms.
func TestSplitAndMergedRulesAreOneSetOfAtoms(t *testing.T) {
	one := `{"acls": [{"action": "accept", "src": ["group:a", "group:b"], "dst": ["tag:x:80", "tag:x:443", "tag:y:80", "tag:y:443"], "proto": "tcp"}]}`
	same(t, "split by source", one, `{"acls": [
		{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80", "tag:x:443", "tag:y:80", "tag:y:443"], "proto": "tcp"},
		{"action": "accept", "src": ["group:b"], "dst": ["tag:y:443", "tag:x:443", "tag:y:80", "tag:x:80"], "proto": "tcp"}]}`)
	same(t, "split by destination", one, `{"acls": [
		{"action": "accept", "src": ["group:b", "group:a"], "dst": ["tag:x:80", "tag:x:443"], "proto": "tcp"},
		{"action": "accept", "src": ["group:a", "group:b"], "dst": ["tag:y:80", "tag:y:443"], "proto": "tcp"}]}`)
	same(t, "split by ports", one, `{"acls": [
		{"action": "accept", "src": ["group:a", "group:b"], "dst": ["tag:x:80", "tag:y:80"], "proto": "tcp"},
		{"action": "accept", "src": ["group:a", "group:b"], "dst": ["tag:x:443", "tag:y:443"], "proto": "tcp"}]}`)
	same(t, "ports as a list", one, `{"acls": [{"action": "accept", "src": ["group:a", "group:b"], "dst": ["tag:x:443,80", "tag:y:80-80,443"], "proto": "tcp"}]}`)
	same(t, "split by source and destination", one, `{"acls": [
		{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80", "tag:x:443"], "proto": "tcp"},
		{"action": "accept", "src": ["group:a"], "dst": ["tag:y:80", "tag:y:443"], "proto": "tcp"},
		{"action": "accept", "src": ["group:b"], "dst": ["tag:x:80", "tag:x:443"], "proto": "tcp"},
		{"action": "accept", "src": ["group:b"], "dst": ["tag:y:80", "tag:y:443"], "proto": "tcp"}]}`)
	same(t, "a repeated rule", one, `{"acls": [`+strings.TrimSuffix(strings.TrimPrefix(one, `{"acls": [`), "]}")+`, `+strings.TrimSuffix(strings.TrimPrefix(one, `{"acls": [`), "]}")+`]}`)
	same(t, "order of rules", `{"acls": [{"action":"accept","src":["a"],"dst":["x:1"]},{"action":"accept","src":["b"],"dst":["y:2"]}]}`,
		`{"acls": [{"action":"accept","src":["b"],"dst":["y:2"]},{"action":"accept","src":["a"],"dst":["x:1"]}]}`)

	// Re-splitting along source and ports at once is the limit: the two stages do not reduce it.
	differ(t, "the documented limit",
		`{"acls": [{"action": "accept", "src": ["a", "b"], "dst": ["x:80", "x:443"]}]}`,
		`{"acls": [{"action": "accept", "src": ["a", "b"], "dst": ["x:80"]}, {"action": "accept", "src": ["a"], "dst": ["x:443"]}, {"action": "accept", "src": ["b"], "dst": ["x:443"]}]}`)
}

func TestARuleChangedInAnyFieldIsAChange(t *testing.T) {
	base := `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"], "proto": "tcp"}]}`
	for name, other := range map[string]string{
		"another source":               `{"acls": [{"action": "accept", "src": ["group:a", "group:z"], "dst": ["tag:x:80"], "proto": "tcp"}]}`,
		"another destination":          `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:z:80"], "proto": "tcp"}]}`,
		"another port":                 `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:81"], "proto": "tcp"}]}`,
		"a wider port":                 `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80-90"], "proto": "tcp"}]}`,
		"another protocol":             `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"], "proto": "udp"}]}`,
		"no protocol":                  `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"]}]}`,
		"a posture":                    `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"], "proto": "tcp", "srcPosture": ["posture:p"]}]}`,
		"an unknown field":             `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"], "proto": "tcp", "future": true}]}`,
		"another action":               `{"acls": [{"action": "deny", "src": ["group:a"], "dst": ["tag:x:80"], "proto": "tcp"}]}`,
		"no action":                    `{"acls": [{"src": ["group:a"], "dst": ["tag:x:80"], "proto": "tcp"}]}`,
		"a case in a name":             `{"acls": [{"action": "accept", "src": ["group:A"], "dst": ["tag:x:80"], "proto": "tcp"}]}`,
		"an extra rule":                `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"], "proto": "tcp"}, {"action": "accept", "src": [], "dst": []}]}`,
		"a dst with no port":           `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x"], "proto": "tcp"}]}`,
		"a rule that is not an object": `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"], "proto": "tcp"}, "x"]}`,
	} {
		differ(t, name, base, other)
	}
}

func TestSpellingsOfTheSamePolicyAreOneNormalForm(t *testing.T) {
	base := `{"acls": [{"action": "accept", "src": ["group:a", "group:b"], "dst": ["tag:x:80"], "proto": "tcp", "srcPosture": ["p1", "p2"]}]}`
	for name, other := range map[string]string{
		"whitespace and comments": "// c\n{ \"acls\" : [ { \"action\": \"accept\", /* x */ \"src\": [\"group:a\", \"group:b\",], \"dst\": [\"tag:x:80\"], \"proto\": \"tcp\", \"srcPosture\": [\"p1\", \"p2\"] }, ], }",
		"key order":               `{"acls": [{"proto": "tcp", "dst": ["tag:x:80"], "srcPosture": ["p1", "p2"], "src": ["group:a", "group:b"], "action": "accept"}]}`,
		"section name case":       `{"ACLs": [{"action": "accept", "src": ["group:a", "group:b"], "dst": ["tag:x:80"], "proto": "tcp", "srcPosture": ["p1", "p2"]}]}`,
		"field name case":         `{"acls": [{"Action": "accept", "SRC": ["group:a", "group:b"], "Dst": ["tag:x:80"], "PROTO": "tcp", "SrcPosture": ["p1", "p2"]}]}`,
		"allow for accept":        `{"acls": [{"action": "allow", "src": ["group:a", "group:b"], "dst": ["tag:x:80"], "proto": "tcp", "srcPosture": ["p1", "p2"]}]}`,
		"legacy users and ports":  `{"acls": [{"action": "accept", "users": ["group:a", "group:b"], "ports": ["tag:x:80"], "proto": "tcp", "srcPosture": ["p1", "p2"]}]}`,
		"proto as an array":       `{"acls": [{"action": "accept", "src": ["group:a", "group:b"], "dst": ["tag:x:80"], "proto": ["tcp"], "srcPosture": ["p1", "p2"]}]}`,
		"proto in upper case":     `{"acls": [{"action": "accept", "src": ["group:a", "group:b"], "dst": ["tag:x:80"], "proto": "TCP", "srcPosture": ["p1", "p2"]}]}`,
		"posture order":           `{"acls": [{"action": "accept", "src": ["group:a", "group:b"], "dst": ["tag:x:80"], "proto": "tcp", "srcPosture": ["p2", "p1", "p2"]}]}`,
		"null via":                `{"acls": [{"action": "accept", "src": ["group:a", "group:b"], "dst": ["tag:x:80"], "proto": "tcp", "srcPosture": ["p1", "p2"], "via": null}]}`,
		"empty via":               `{"acls": [{"action": "accept", "src": ["group:a", "group:b"], "dst": ["tag:x:80"], "proto": "tcp", "srcPosture": ["p1", "p2"], "via": []}]}`,
		"an escape in a name":     `{"acls": [{"action": "acc\u0065pt", "src": ["group:a", "group:b"], "dst": ["tag:x:80"], "proto": "tcp", "srcPosture": ["p1", "p2"]}]}`,
		"a section written twice": `{"acls": [{"action": "accept", "src": ["nobody"], "dst": ["x:1"]}], "acls": [{"action": "accept", "src": ["group:a", "group:b"], "dst": ["tag:x:80"], "proto": "tcp", "srcPosture": ["p1", "p2"]}]}`,
		"a field written twice":   `{"acls": [{"action": "accept", "src": ["nobody"], "src": ["group:a", "group:b"], "dst": ["tag:x:80"], "proto": "tcp", "srcPosture": ["p1", "p2"]}]}`,
	} {
		same(t, name, base, other)
	}
}

func TestGrantsAndACLsAreOnePool(t *testing.T) {
	same(t, "the console's rewrite",
		`{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80", "tag:x:443"], "proto": "tcp"}]}`,
		`{"grants": [{"src": ["group:a"], "dst": ["tag:x"], "ip": ["tcp:80", "tcp:443"]}]}`)
	same(t, "both at once", `{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:80"]}], "grants": [{"src": ["b"], "dst": ["y"], "ip": ["22"]}]}`,
		`{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["80"]}, {"src": ["b"], "dst": ["y"], "ip": ["22"]}]}`)
	// A grant for several protocols is one atom for each.
	same(t, "protocols", `{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["tcp:80", "udp:53", "tcp:443"]}]}`,
		`{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:80,443"], "proto": "tcp"}, {"action": "accept", "src": ["a"], "dst": ["x:53"], "proto": "udp"}]}`)
	differ(t, "app capabilities", `{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["80"]}]}`, `{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["80"], "app": {"example.com/cap": [{"k": 1}]}}]}`)
	differ(t, "via", `{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["80"]}]}`, `{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["80"], "via": ["tag:r"]}]}`)
	differ(t, "an unknown grant field", `{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["80"]}]}`, `{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["80"], "future": 1}]}`)
	differ(t, "posture removed", `{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["80"], "srcPosture": ["p"]}]}`, `{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["80"]}]}`)
	// A grant has no action; a field the engine does not know in a grant is kept.
	differ(t, "action in a grant", `{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["80"]}]}`, `{"grants": [{"action": "accept", "src": ["a"], "dst": ["x"], "ip": ["80"]}]}`)
}

func TestWriteToWritesTheCanonicalBytes(t *testing.T) {
	var buf strings.Builder
	n, err := normalise(t, `{"acls": []}`).WriteTo(&buf)
	if err != nil || int(n) != buf.Len() {
		t.Errorf("WriteTo = %d, %v (wrote %d)", n, err, buf.Len())
	}
	if want := normalFormVersion + "\n\"access\"\t\"empty\"\t\"0\"\t\"empty\"\t\"-\"\n\"section\"\t\"ssh\"\t\"absent\"\n"; buf.String() != want {
		t.Errorf("bytes:\n got  %q\n want %q", buf.String(), want)
	}
	if _, err := normalise(t, `{"acls": []}`).WriteTo(failingWriter{}); err == nil {
		t.Error("a failing writer's error is lost")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestNormaliseRefusesWhatItCannotBound(t *testing.T) {
	// 2,000 destinations by 600 protocols is 1.2 million atoms from a 40 KiB text.
	var b strings.Builder
	b.WriteString(`{"grants": [{"src": ["a"], "dst": [`)
	for i := range 2000 {
		fmt.Fprintf(&b, `"t%d",`, i)
	}
	b.WriteString(`], "ip": [`)
	for i := range 600 {
		fmt.Fprintf(&b, `"p%d:80",`, i)
	}
	b.WriteString(`]}]}`)
	_, err := Normalise(context.Background(), mustParse(t, b.String()))
	if !errors.Is(err, ErrTooComplex) || !strings.Contains(err.Error(), "atoms") {
		t.Errorf("err = %v, want too_complex naming the atoms", err)
	}
	// The same for acls.
	b.Reset()
	b.WriteString(`{"acls": [{"action": "accept", "src": ["a"], "dst": [`)
	for i := range 2000 {
		fmt.Fprintf(&b, `"t%d:80",`, i)
	}
	b.WriteString(`], "proto": [`)
	for i := range 600 {
		fmt.Fprintf(&b, `"p%d",`, i)
	}
	b.WriteString(`]}]}`)
	if _, err := Normalise(context.Background(), mustParse(t, b.String())); !errors.Is(err, ErrTooComplex) {
		t.Errorf("acls: err = %v", err)
	}
}

func TestNormaliseSpendsABudgetAndHonoursTheContext(t *testing.T) {
	d := mustParse(t, string(fixture(t, "basic.hujson")))
	old := maxWork
	t.Cleanup(func() { maxWork = old })
	maxWork = 20
	if _, err := Normalise(context.Background(), d); !errors.Is(err, ErrTooComplex) {
		t.Errorf("a budget of 20 steps: err = %v", err)
	}
	maxWork = old
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Normalise(ctx, d); !errors.Is(err, context.Canceled) {
		t.Errorf("a context that is done: err = %v", err)
	}
	if _, err := Normalise(context.Background(), nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("no document: err = %v", err)
	}
	if _, err := Normalise(context.Background(), &Doc{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("an empty document: err = %v", err)
	}
}

// The fields a rule has that the engine does not model are kept whole, and written in one
// order whatever order the text gave them.
func TestUnknownFieldsAreKeptInOneOrder(t *testing.T) {
	same(t, "unknown fields of a rule in another order",
		`{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"], "zeta": [1, 2], "alpha": {"k": "v", "j": 1}}]}`,
		`{"acls": [{"alpha": {"j": 1, "k": "v"}, "action": "accept", "src": ["a"], "dst": ["x:1"], "zeta": [1, 2]}]}`)
	same(t, "unknown fields of a grant in another order",
		`{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["1"], "zeta": 1, "alpha": 2}]}`,
		`{"grants": [{"alpha": 2, "src": ["a"], "dst": ["x"], "ip": ["1"], "zeta": 1}]}`)
	differ(t, "an unknown field's value",
		`{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["1"], "alpha": 2}]}`,
		`{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["1"], "alpha": 3}]}`)
	differ(t, "an unknown field's name",
		`{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["1"], "alpha": 2}]}`,
		`{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["1"], "beta": 2}]}`)
}

func TestExtraFieldsSkipsWhatIsUsed(t *testing.T) {
	d := mustParse(t, `{"r": {"b": 2, "used": 1, "c": {"y": 1, "x": [3, 2]}, "a": 3}}`)
	m := newMeter(context.Background())
	fields, err := objectFields(m, []*hujson.Value{d.top[0].val}, true)
	if err != nil {
		t.Fatal(err)
	}
	got, err := extraFields(m, fields, map[string]bool{"used": true})
	if err != nil || string(got) != `{"a":3,"b":2,"c":{"x":[3,2],"y":1}}` {
		t.Errorf("extraFields = %s, %v", got, err)
	}
	// Nothing left over is nil, not an empty object: a rule with no extra field and one with
	// an empty extra would otherwise differ.
	got, err = extraFields(m, fields, map[string]bool{"b": true, "used": true, "c": true, "a": true})
	if err != nil || got != nil {
		t.Errorf("extraFields with everything used = %s, %v; want nil", got, err)
	}
	old := maxWork
	t.Cleanup(func() { maxWork = old })
	maxWork = 1
	if _, err := extraFields(newMeter(context.Background()), fields, nil); !errors.Is(err, ErrTooComplex) {
		t.Errorf("extraFields past the budget: err = %v", err)
	}
}

// A rule can be built to repeat what it holds for each of its destinations: a long list of
// port ranges, or a large field. What an atom copies is spent from the budget, so such a
// rule is refused instead of held in memory many times over.
func TestAnAtomsCopiesAreMetered(t *testing.T) {
	old := maxWork
	t.Cleanup(func() { maxWork = old })
	maxWork = 1 << 20

	var dsts strings.Builder
	for i := range 2000 {
		fmt.Fprintf(&dsts, `"t%d",`, i)
	}
	var ranges strings.Builder
	for i := range 1000 {
		fmt.Fprintf(&ranges, `"%d",`, 2*i+10)
	}
	_, err := Normalise(context.Background(), mustParse(t, `{"grants": [{"src": ["a"], "dst": [`+dsts.String()+`], "ip": [`+ranges.String()+`]}]}`))
	if !errors.Is(err, ErrTooComplex) {
		t.Errorf("2,000 destinations by 1,000 port ranges: err = %v", err)
	}
	_, err = Normalise(context.Background(), mustParse(t, `{"grants": [{"src": ["a"], "dst": [`+dsts.String()+`], "ip": ["80"], "app": {"example.com/cap": [{"k": "`+strings.Repeat("v", 2000)+`"}]}}]}`))
	if !errors.Is(err, ErrTooComplex) {
		t.Errorf("2,000 destinations by a 2 KB field: err = %v", err)
	}
	// The same rule with few destinations is read.
	if _, err := Normalise(context.Background(), mustParse(t, `{"grants": [{"src": ["a"], "dst": ["t1", "t2"], "ip": [`+ranges.String()+`]}]}`)); err != nil {
		t.Errorf("2 destinations by 1,000 port ranges: %v", err)
	}
}

// Ports are collected and sorted once for a rule, never after each entry: the work for twice
// the entries is about twice the work.
func TestPortWorkIsLinear(t *testing.T) {
	ops := func(n int) int64 {
		var b strings.Builder
		for i := range n {
			fmt.Fprintf(&b, `"%d",`, 2*i+10)
		}
		return normalise(t, `{"grants": [{"src": ["a"], "dst": ["x"], "ip": [`+b.String()+`]}]}`).Ops()
	}
	small, large := ops(5000), ops(20000)
	if large > 6*small {
		t.Errorf("work for 20,000 port entries is %d, for 5,000 it is %d: more than linear", large, small)
	}
}

// The separator that joins the parts of an atom's key is a control character, and the
// destination, protocol and action are raw text from the policy: none of them may run into
// the next one's, however the text is split. Each pair is two rules that must stay two atoms.
func TestNoTextCanJoinTwoRules(t *testing.T) {
	for name, rules := range map[string][2]string{
		"a grant's dst against the protocol of its ip": {
			`{"src":["s"],"dst":["a\u001fb"],"ip":["c:80"]}`,
			`{"src":["s"],"dst":["a"],"ip":["b\u001fc:80"]}`,
		},
		"an acl's dst against its protocol": {
			`{"action":"accept","src":["s"],"dst":["x:80"],"proto":"a\u001fb"}`,
			`{"action":"accept","src":["s"],"dst":["x\u001fa:80"],"proto":"b"}`,
		},
		"an acl's protocol against its action": {
			`{"action":"c","src":["s"],"dst":["x:80"],"proto":"a\u001fb"}`,
			`{"action":"b\u001fc","src":["s"],"dst":["x:80"],"proto":"a"}`,
		},
		"an acl's dst against its action": {
			`{"action":"a\u001fb","src":["s"],"dst":["x:80"]}`,
			`{"action":"b","src":["s"],"dst":["x\u001f:80"],"proto":"a"}`,
		},
	} {
		section := "acls"
		if strings.Contains(rules[0], `"ip"`) {
			section = "grants"
		}
		both := `{"` + section + `": [` + rules[0] + `,` + rules[1] + `]}`
		if n := len(normalise(t, both).atoms); n != 2 {
			t.Errorf("%s: %d atoms, want 2", name, n)
		}
		differ(t, name+" (the first rule alone)", both, `{"`+section+`": [`+rules[0]+`]}`)
		differ(t, name+" (the second rule alone)", both, `{"`+section+`": [`+rules[1]+`]}`)
	}
}

// Two rules that differ only in one qualifier are two atoms, in either order: each of the
// parts of the key has a test that would notice it missing.
func TestRulesThatDifferInOneQualifierDoNotMerge(t *testing.T) {
	pair := func(name, a, b string) {
		t.Helper()
		ab := `{"grants": [` + a + `,` + b + `]}`
		ba := `{"grants": [` + b + `,` + a + `]}`
		same(t, name+": order", ab, ba)
		for which, one := range map[string]string{"first": a, "second": b} {
			differ(t, name+" (the "+which+" alone, in order)", ab, `{"grants": [`+one+`]}`)
			differ(t, name+" (the "+which+" alone, reversed)", ba, `{"grants": [`+one+`]}`)
		}
	}
	pair("via", `{"src":["s"],"dst":["x"],"ip":["80"],"via":["tag:r"]}`, `{"src":["s"],"dst":["x"],"ip":["80"]}`)
	pair("srcPosture", `{"src":["s"],"dst":["x"],"ip":["80"],"srcPosture":["p"]}`, `{"src":["s"],"dst":["x"],"ip":["80"]}`)

	// Rules with other sources and other ports are merged by neither stage: they are not one
	// rule for the union of their sources, whose ports would be the union of both.
	ab := `{"grants": [{"src":["a"],"dst":["x"],"ip":["80"]},{"src":["b"],"dst":["x"],"ip":["443"]}]}`
	differ(t, "ports (stage 2)", ab, `{"grants": [{"src":["a","b"],"dst":["x"],"ip":["80"]}]}`)
	differ(t, "ports (stage 2), the other", ab, `{"grants": [{"src":["a","b"],"dst":["x"],"ip":["443"]}]}`)
	// And rules with the same ports and other sources are one atom for both sources.
	same(t, "sources (stage 2)", `{"grants": [{"src":["a"],"dst":["x"],"ip":["80"]},{"src":["b"],"dst":["x"],"ip":["80"]}]}`,
		`{"grants": [{"src":["a","b"],"dst":["x"],"ip":["80"]}]}`)
}
