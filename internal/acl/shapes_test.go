package acl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
)

func TestNormaliseStatesOfTheFixture(t *testing.T) {
	n := normalise(t, string(fixture(t, "basic.hujson")))
	for name, want := range map[string]struct {
		state State
		count int
	}{
		"acls": {StateNonEmpty, 4}, "grants": {StateNonEmpty, 3}, "ssh": {StateNonEmpty, 2},
		"tests": {StateNonEmpty, 2}, "sshTests": {StateNonEmpty, 1}, "nodeAttrs": {StateNonEmpty, 3},
		"groups": {StateNonEmpty, 3}, "tagOwners": {StateNonEmpty, 4}, "hosts": {StateNonEmpty, 2},
		"ipsets": {StateNonEmpty, 1}, "postures": {StateNonEmpty, 2}, "defaultSrcPosture": {StateNonEmpty, 1},
		"autoApprovers": {StateNonEmpty, 2}, "extraDNSRecords": {StateNonEmpty, 1},
		"disableIPv4": {StateNonEmpty, 1}, "randomizeClientPort": {StateNonEmpty, 1},
		"derpMap": {StateAbsent, 0}, "attrConfig": {StateAbsent, 0}, "OneCGNATRoute": {StateAbsent, 0},
	} {
		if s := section(t, n, name); s.state != want.state || s.count != want.count {
			t.Errorf("%s: state %v, count %d; want %v, %d", name, s.state, s.count, want.state, want.count)
		}
	}
	if n.AccessState() != StateNonEmpty || len(n.atoms) != 9 {
		t.Errorf("access: %v with %d atoms, want non-empty and 9", n.AccessState(), len(n.atoms))
	}
	if n.Ops() <= 0 {
		t.Error("Ops is not counted")
	}
}

// Outside the access rules and ssh an empty section holds nothing, which is what an absent
// one holds.
func TestEmptySectionsOutsideTheDefaultsHoldNothing(t *testing.T) {
	if s := section(t, normalise(t, `{"ssh": []}`), "ssh"); s.null || s.state != StateEmpty {
		t.Errorf("ssh: %+v", s)
	}
	differ(t, "empty ssh is not absent", `{"ssh": []}`, `{}`)
	same(t, "empty groups", `{"groups": {}, "tests": [], "nodeAttrs": [], "hosts": {}}`, `{}`)
	same(t, "null ssh is absent", `{"ssh": null}`, `{}`)
}

func TestTestsAreAssertions(t *testing.T) {
	one := `{"tests": [{"src": "group:a", "accept": ["tag:x:80", "tag:x:443"], "deny": ["tag:y:22"], "proto": "tcp"}]}`
	same(t, "split", one, `{"tests": [{"src": "group:a", "proto": "tcp", "accept": ["tag:x:80"]}, {"src": "group:a", "proto": "tcp", "accept": ["tag:x:443"], "deny": ["tag:y:22"]}]}`)
	same(t, "legacy names", one, `{"tests": [{"user": "group:a", "allow": ["tag:x:443", "tag:x:80"], "deny": ["tag:y:22"], "proto": "tcp"}]}`)
	differ(t, "a dropped assertion", one, `{"tests": [{"src": "group:a", "accept": ["tag:x:80"], "deny": ["tag:y:22"], "proto": "tcp"}]}`)
	differ(t, "another protocol", one, `{"tests": [{"src": "group:a", "accept": ["tag:x:80", "tag:x:443"], "deny": ["tag:y:22"], "proto": "udp"}]}`)
	differ(t, "posture attributes", one, `{"tests": [{"src": "group:a", "accept": ["tag:x:80", "tag:x:443"], "deny": ["tag:y:22"], "proto": "tcp", "srcPostureAttrs": {"node:os": "macos"}}]}`)
	differ(t, "an unknown field", one, `{"tests": [{"src": "group:a", "accept": ["tag:x:80", "tag:x:443"], "deny": ["tag:y:22"], "proto": "tcp", "future": 1}]}`)
	// The same test twice is two assertions: removing one is a reduction.
	two := `{"tests": [{"src": "a", "accept": ["x:1"]}, {"src": "a", "accept": ["x:1"]}]}`
	differ(t, "a repeated test counts", two, `{"tests": [{"src": "a", "accept": ["x:1"]}]}`)
	n := normalise(t, two)
	if s := section(t, n, "tests"); s.count != 2 || len(s.entries) != 1 || s.entries[0].n != 2 {
		t.Errorf("tests: %+v", s)
	}
	// A test the engine cannot read is kept whole.
	differ(t, "an unreadable test", `{"tests": ["x"]}`, `{"tests": ["y"]}`)
	differ(t, "a test with no source", `{"tests": [{"accept": ["x:1"]}]}`, `{"tests": [{"accept": ["x:2"]}]}`)
	differ(t, "a test that asserts nothing", `{"tests": [{"src": "a"}]}`, `{"tests": [{"src": "b"}]}`)
	// SSH tests.
	ssh := `{"sshTests": [{"src": "group:a", "dst": ["tag:x"], "accept": ["alice", "bob"], "check": ["carol"], "deny": ["root"]}]}`
	same(t, "ssh split", ssh, `{"sshTests": [{"src": "group:a", "dst": ["tag:x"], "accept": ["bob"]}, {"src": "group:a", "dst": ["tag:x"], "accept": ["alice"], "check": ["carol"], "deny": ["root"]}]}`)
	differ(t, "ssh user", ssh, `{"sshTests": [{"src": "group:a", "dst": ["tag:x"], "accept": ["alice", "bob"], "check": ["carol"], "deny": ["admin"]}]}`)
	differ(t, "ssh destination", ssh, `{"sshTests": [{"src": "group:a", "dst": ["tag:y"], "accept": ["alice", "bob"], "check": ["carol"], "deny": ["root"]}]}`)
}

func TestNodeAttrsAreAdditive(t *testing.T) {
	same(t, "the same target twice", `{"nodeAttrs": [{"target": ["tag:a"], "attr": ["funnel"]}, {"target": ["tag:a"], "attr": ["funnel"]}]}`,
		`{"nodeAttrs": [{"target": ["tag:a"], "attr": ["funnel"]}]}`)
	same(t, "targets united", `{"nodeAttrs": [{"target": ["tag:a"], "attr": ["funnel"]}, {"target": ["tag:b"], "attr": ["funnel"]}]}`,
		`{"nodeAttrs": [{"target": ["tag:b", "tag:a"], "attr": ["funnel"]}]}`)
	same(t, "attributes split", `{"nodeAttrs": [{"target": ["tag:a"], "attr": ["funnel", "x"]}]}`,
		`{"nodeAttrs": [{"target": ["tag:a"], "attr": ["x"]}, {"target": ["tag:a"], "attr": ["funnel"]}]}`)
	differ(t, "another target", `{"nodeAttrs": [{"target": ["tag:a"], "attr": ["funnel"]}]}`, `{"nodeAttrs": [{"target": ["tag:b"], "attr": ["funnel"]}]}`)
	differ(t, "another attribute", `{"nodeAttrs": [{"target": ["tag:a"], "attr": ["funnel"]}]}`, `{"nodeAttrs": [{"target": ["tag:a"], "attr": ["other"]}]}`)
	differ(t, "an app", `{"nodeAttrs": [{"target": ["tag:a"], "attr": ["x"]}]}`, `{"nodeAttrs": [{"target": ["tag:a"], "attr": ["x"], "app": {"c": [{"name": "n"}]}}]}`)
	differ(t, "an unknown field", `{"nodeAttrs": [{"target": ["tag:a"], "attr": ["x"]}]}`, `{"nodeAttrs": [{"target": ["tag:a"], "attr": ["x"], "future": 1}]}`)
	differ(t, "an ip pool", `{"nodeAttrs": [{"target": ["tag:a"], "attr": ["x"]}]}`, `{"nodeAttrs": [{"target": ["tag:a"], "attr": ["x"], "ipPool": ["192.0.2.0/24"]}]}`)
	differ(t, "an entry that is not an object", `{"nodeAttrs": ["a"]}`, `{"nodeAttrs": ["b"]}`)
	// Tailscale-written entries are marked.
	n := normalise(t, `{"nodeAttrs": [{"target": ["autogroup:member"], "attr": ["funnel"]}, {"target": ["tag:a"], "attr": ["x"], "app": {"tailscale.com/app-connectors": [{"name": "n", "presetAppID": "github"}]}}, {"target": ["tag:a"], "attr": ["plain"]}]}`)
	var written int
	for _, e := range section(t, n, "nodeAttrs").entries {
		if e.written {
			written++
		}
	}
	if written != 2 {
		t.Errorf("written entries = %d, want 2 (funnel and the preset)", written)
	}
}

func TestKeyedSectionsCompareKeyByKey(t *testing.T) {
	same(t, "group members in any order", `{"groups": {"group:a": ["x@example.com", "y@example.com"]}}`, `{"groups": {"group:a": ["y@example.com", "x@example.com", "y@example.com"]}}`)
	differ(t, "a member", `{"groups": {"group:a": ["x@example.com"]}}`, `{"groups": {"group:a": ["y@example.com"]}}`)
	differ(t, "a group", `{"groups": {"group:a": []}}`, `{"groups": {"group:b": []}}`)
	differ(t, "tagOwners [] is not autogroup:admin", `{"tagOwners": {"tag:a": []}}`, `{"tagOwners": {"tag:a": ["autogroup:admin"]}}`)
	differ(t, "ipset operations are ordered", `{"ipsets": {"ipset:s": ["add 192.0.2.1", "remove 192.0.2.1"]}}`, `{"ipsets": {"ipset:s": ["remove 192.0.2.1", "add 192.0.2.1"]}}`)
	same(t, "a posture as a list or as an object", `{"postures": {"posture:p": ["node:os == 'linux'", "node:a == 1"]}}`, `{"postures": {"posture:p": {"assertions": ["node:a == 1", "node:os == 'linux'"]}}}`)
	differ(t, "a posture's onFailure", `{"postures": {"posture:p": {"assertions": ["a"], "onFailure": "deny"}}}`, `{"postures": {"posture:p": {"assertions": ["a"]}}}`)
	differ(t, "a host", `{"hosts": {"h": "192.0.2.1"}}`, `{"hosts": {"h": "192.0.2.2"}}`)
	same(t, "two groups blocks merge", `{"groups": {"group:a": ["x"]}, "Groups": {"group:b": ["y"]}}`, `{"groups": {"group:a": ["x"], "group:b": ["y"]}}`)
	same(t, "a later group replaces", `{"groups": {"group:a": ["x"], "group:a": ["z"]}}`, `{"groups": {"group:a": ["z"]}}`)
	differ(t, "map keys are exact", `{"hosts": {"Build": "192.0.2.1"}}`, `{"hosts": {"build": "192.0.2.1"}}`)
	differ(t, "autoApprovers route", `{"autoApprovers": {"routes": {"192.0.2.0/24": ["tag:r"]}}}`, `{"autoApprovers": {"routes": {"192.0.2.0/24": ["tag:s"]}}}`)
	same(t, "autoApprovers sets", `{"autoApprovers": {"exitNode": ["tag:a", "tag:b"]}}`, `{"autoApprovers": {"ExitNode": ["tag:b", "tag:a"]}}`)
	differ(t, "an exit node", `{"autoApprovers": {"exitNode": ["tag:a"]}}`, `{"autoApprovers": {"exitNode": []}}`)
	differ(t, "derpMap", `{"derpMap": {"regions": {"900": {"regionID": 900}}}}`, `{"derpMap": {"regions": {"900": {"regionID": 901}}}}`)
	differ(t, "attrConfig", `{"attrConfig": {"a": {"type": "string"}}}`, `{"attrConfig": {"a": {"type": "number"}}}`)
	same(t, "attrConfig field case", `{"attrConfig": {"a": {"type": "string", "broadcastToPeers": ["x", "y"]}}}`, `{"attrConfig": {"a": {"Type": "string", "BroadcastToPeers": ["y", "x"]}}}`)
	differ(t, "externalTailnets", `{"externalTailnets": {"a": {"externalID": "1"}}}`, `{"externalTailnets": {"a": {"externalID": "2"}}}`)
	differ(t, "a scalar", `{"disableIPv4": true}`, `{"disableIPv4": false}`)
	differ(t, "defaultSrcPosture", `{"defaultSrcPosture": ["posture:a"]}`, `{"defaultSrcPosture": ["posture:b"]}`)
	same(t, "defaultSrcPosture order", `{"defaultSrcPosture": ["posture:a", "posture:b"]}`, `{"defaultSrcPosture": ["posture:b", "posture:a"]}`)
	differ(t, "extraDNSRecords", `{"extraDNSRecords": [{"Name": "a", "Value": "192.0.2.1"}]}`, `{"extraDNSRecords": [{"Name": "a", "Value": "192.0.2.2"}]}`)
}

func TestSSHRulesAreASetAndTheirActionIsKept(t *testing.T) {
	a := `{"action": "accept", "src": ["g"], "dst": ["t"], "users": ["root", "alice"]}`
	b := `{"action": "check", "src": ["g"], "dst": ["t"], "users": ["alice"]}`
	same(t, "order does not change what SSH enforces", `{"ssh": [`+a+`, `+b+`]}`, `{"ssh": [`+b+`, `+a+`]}`)
	same(t, "users in any order", `{"ssh": [`+a+`]}`, `{"ssh": [{"action": "accept", "src": ["g"], "dst": ["t"], "users": ["alice", "root"]}]}`)
	differ(t, "check to accept", `{"ssh": [`+b+`]}`, `{"ssh": [{"action": "accept", "src": ["g"], "dst": ["t"], "users": ["alice"]}]}`)
	differ(t, "an unknown field", `{"ssh": [`+b+`]}`, `{"ssh": [{"action": "check", "src": ["g"], "dst": ["t"], "users": ["alice"], "future": 1}]}`)
	e := section(t, normalise(t, `{"ssh": [`+a+`]}`), "ssh").entries[0]
	if !e.root || e.action != "accept" || e.rest == "" || strings.Contains(e.rest, `"action"`) {
		t.Errorf("ssh entry: %+v", e)
	}
	if section(t, normalise(t, `{"ssh": [`+b+`]}`), "ssh").entries[0].root {
		t.Error("a rule for alice only is not a root rule")
	}
}

func TestUnknownSectionsAreKeptWhole(t *testing.T) {
	same(t, "key order inside", `{"futureSection": {"a": 1, "b": [2, 3]}}`, `{"futureSection": {"b": [2, 3], "a": 1}}`)
	differ(t, "a change inside", `{"futureSection": {"a": 1}}`, `{"futureSection": {"a": 2}}`)
	differ(t, "an array's order inside", `{"futureSection": [1, 2]}`, `{"futureSection": [2, 1]}`)
	differ(t, "present or not", `{"futureSection": {}}`, `{}`)
	differ(t, "nodeAttr is not nodeAttrs", `{"nodeAttr": [{"target": ["a"], "attr": ["b"]}]}`, `{"nodeAttrs": [{"target": ["a"], "attr": ["b"]}]}`)
	same(t, "unknown sections in any order", `{"b": 1, "a": 2}`, `{"a": 2, "b": 1}`)
	same(t, "unknown section case", `{"FutureSection": 1}`, `{"futuresection": 1}`)
	same(t, "null unknown is absent", `{"futureSection": null}`, `{}`)
	// A known section holding the wrong type is kept whole too.
	differ(t, "an object where an array belongs", `{"acls": {"a": 1}}`, `{"acls": {"a": 2}}`)
	differ(t, "a string where an object belongs", `{"groups": "x"}`, `{"groups": "y"}`)
	differ(t, "a number where an object belongs", `{"autoApprovers": 1}`, `{"autoApprovers": 2}`)
	differ(t, "an object where a list belongs", `{"defaultSrcPosture": {"a": 1}}`, `{"defaultSrcPosture": {"a": 2}}`)
}

func TestNormalFormBytesAreIndependentOfSpelling(t *testing.T) {
	base := normalise(t, string(fixture(t, "basic.hujson"))).Bytes()
	if got := normalise(t, string(fixture(t, "crlf.hujson"))).Bytes(); string(got) != string(base) {
		t.Error("crlf.hujson: the normal form differs from basic.hujson")
	}
	if !strings.HasPrefix(string(base), normalFormVersion+"\n") || strings.Contains(string(base), "\r") {
		t.Errorf("bytes: %.60q", base)
	}
}

func TestATestCannotExpandWithoutBound(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"sshTests": [{"src": [`)
	for i := range 1100 {
		fmt.Fprintf(&b, `"s%d",`, i)
	}
	b.WriteString(`], "dst": [`)
	for i := range 1100 {
		fmt.Fprintf(&b, `"d%d",`, i)
	}
	b.WriteString(`], "accept": ["u"]}]}`)
	if _, err := Normalise(context.Background(), mustParse(t, b.String())); !errors.Is(err, ErrTooComplex) {
		t.Errorf("sshTests: err = %v", err)
	}
}

// A map entry written twice reads as the later one, not as the two merged.
func TestAMapEntryWrittenTwiceReadsAsTheLaterOne(t *testing.T) {
	first := `{"assertions": ["a"], "onFailure": "deny"}`
	second := `{"assertions": ["a"]}`
	twice := `{"postures": {"posture:p": ` + first + `, "posture:p": ` + second + `}}`
	same(t, "postures: the later copy", twice, `{"postures": {"posture:p": `+second+`}}`)
	differ(t, "postures: not the merged object", twice, `{"postures": {"posture:p": `+first+`}}`)

	r1 := `{"regionID": 900, "regionCode": "a", "nodes": [{"name": "1"}]}`
	r2 := `{"regionID": 900}`
	region := `{"derpMap": {"regions": {"900": ` + r1 + `, "900": ` + r2 + `}}}`
	same(t, "derpMap: the later copy", region, `{"derpMap": {"regions": {"900": `+r2+`}}}`)
	differ(t, "derpMap: not the merged object", region, `{"derpMap": {"regions": {"900": `+r1+`}}}`)

	// A struct field written twice is the other rule: objects merge.
	same(t, "a struct field's objects merge", `{"derpMap": {"regions": {"900": {"regionID": 900}}, "regions": {"901": {"regionID": 901}}}}`,
		`{"derpMap": {"regions": {"900": {"regionID": 900}, "901": {"regionID": 901}}}}`)
}

// The nested structs of derpMap are read as structs: a field name folds case, and a field
// written twice keeps the later value.
func TestDerpMapNestedStructsFoldCase(t *testing.T) {
	a := `{"derpMap": {"regions": {"900": {"regionID": 1, "RegionID": 2}}}}`
	b := `{"derpMap": {"regions": {"900": {"RegionID": 2, "regionID": 1}}}}`
	differ(t, "region fields in opposite order", a, b)
	same(t, "the same region written identically", a, a)
	same(t, "region field case", `{"derpMap": {"regions": {"900": {"regionID": 900, "regionCode": "a"}}}}`,
		`{"derpMap": {"regions": {"900": {"RegionID": 900, "REGIONCODE": "a"}}}}`)
	n1 := `{"derpMap": {"regions": {"900": {"nodes": [{"hostName": "x", "HostName": "y"}]}}}}`
	n2 := `{"derpMap": {"regions": {"900": {"nodes": [{"HostName": "y", "hostName": "x"}]}}}}`
	differ(t, "node fields in opposite order", n1, n2)
	same(t, "node field case", `{"derpMap": {"regions": {"900": {"nodes": [{"hostName": "x", "stunPort": 3478}]}}}}`,
		`{"derpMap": {"regions": {"900": {"Nodes": [{"HOSTNAME": "x", "STUNPORT": 3478}]}}}}`)
	// Region keys are map keys: exact.
	differ(t, "region keys are exact", `{"derpMap": {"regions": {"a": {}}}}`, `{"derpMap": {"regions": {"A": {}}}}`)
	// The node list is compared in order.
	differ(t, "node order", `{"derpMap": {"regions": {"900": {"nodes": [{"name": "1"}, {"name": "2"}]}}}}`,
		`{"derpMap": {"regions": {"900": {"nodes": [{"name": "2"}, {"name": "1"}]}}}}`)
}

// describedKeys calls visit for every field name an options value describes: the keys of
// fields and of setFields, at any depth.
func describedKeys(o canonOpts, path string, visit func(path, key string)) {
	for k, c := range o.fields {
		visit(path, k)
		describedKeys(c, path+"/"+k, visit)
	}
	for k := range o.setFields {
		visit(path, k)
	}
	if o.elem != nil {
		describedKeys(*o.elem, path+"/*", visit)
	}
}

// documented reports whether key is the documented spelling of a field. A key spelled any
// other way is silently ignored by canonOpts, and the description would do nothing.
func documented(key string) bool { return documentedFields[foldKey(key)] == key }

func TestEveryDescribedKeyIsADocumentedSpelling(t *testing.T) {
	roots := map[string]canonOpts{
		"derpMap":   derpMapOpts,
		"rule":      {setFields: ruleSetFields},
		"ssh":       {setFields: sshSetFields},
		"tests":     {setFields: testSetFields},
		"nodeAttrs": {setFields: nodeAttrSetFields},
	}
	for name, o := range keyedOpts {
		roots["keyed/"+name] = o
	}
	var seen int
	for name, o := range roots {
		describedKeys(o, name, func(path, key string) {
			seen++
			if !documented(key) {
				t.Errorf("%s: %q is not a documented spelling (want %q)", path, key, documentedFields[foldKey(key)])
			}
		})
	}
	if seen < 20 {
		t.Errorf("only %d described keys were checked", seen)
	}
	// The detector: a misspelt key and a key in the wrong case are both found.
	for _, bad := range []string{"Regions", "regoins", "regionid", "nodes "} {
		var found bool
		describedKeys(canonOpts{fold: true, fields: map[string]canonOpts{bad: {}}}, "x", func(_, key string) {
			found = found || !documented(key)
		})
		if !found {
			t.Errorf("the check does not reject %q", bad)
		}
	}
}

// The raw text of a test (a source, a protocol, a destination) can hold the separator of the
// assertion's key. Joined unquoted, a source "a<sep>" and a source "a" with the protocol
// "<sep>" would be one assertion.
func TestATestCannotHideItsTextInTheSeparator(t *testing.T) {
	ctl := "\\" + "u001f"
	a := `{"tests": [{"src": "a", "proto": "` + ctl + `", "accept": [""]}]}`
	b := `{"tests": [{"src": "a` + ctl + `", "accept": [""]}]}`
	if got, want := string(normalise(t, a).Bytes()), string(normalise(t, b).Bytes()); got == want {
		t.Errorf("two different tests have one normal form:\n%s", got)
	}
	differ(t, "ssh", `{"sshTests": [{"src": "a", "dst": ["b`+ctl+`"], "accept": ["u"]}]}`,
		`{"sshTests": [{"src": "a", "dst": ["b"], "accept": ["`+ctl+`u"]}]}`)
}

// allocOf is the bytes Normalise and then WriteTo allocate for text, the work Normalise
// counts and the bytes WriteTo writes (zero when it refuses), with the work budget lowered
// so that a refusal comes fast.
func allocOf(t *testing.T, text string) (alloc uint64, ops, written int64, err error) {
	t.Helper()
	old := maxWork
	maxWork = 1 << 22
	t.Cleanup(func() { maxWork = old })
	d := mustParse(t, text)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	n, err := Normalise(context.Background(), d)
	runtime.ReadMemStats(&after)
	if n != nil {
		ops = n.Ops()
		cw := &countWriter{w: io.Discard}
		if _, werr := n.WriteTo(cw); werr != nil {
			t.Fatal(werr)
		}
		written = cw.n
		runtime.ReadMemStats(&after)
	}
	return after.TotalAlloc - before.TotalAlloc, ops, written, err
}

// What a policy makes the engine allocate is bounded by the work budget: every string it
// builds is ticked by its length before it is built, so text made to multiply (a long
// attribute list beside a large app, a long list of items beside a large posture
// attribute) is refused as too_complex after a few budgets of allocation, not after
// gigabytes.
func TestWhatIsBuiltIsBoundedByTheWorkBudget(t *testing.T) {
	big := strings.Repeat("x", 200_000)
	list := func(prefix string, n int) string {
		var b strings.Builder
		for i := range n {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `"%s%d"`, prefix, i)
		}
		return b.String()
	}
	// Entry j lists the attributes j.., each with its own 3000 targets: the attribute i unites
	// the targets of the entries 0..i, and each of those unions is a different set.
	var tri strings.Builder
	tri.WriteString(`{"nodeAttrs": [`)
	for j := range 60 {
		if j > 0 {
			tri.WriteByte(',')
		}
		var attrs []string
		for i := j; i < 60; i++ {
			attrs = append(attrs, fmt.Sprintf(`"a%d"`, i))
		}
		fmt.Fprintf(&tri, `{"target": [%s], "attr": [%s]}`, list(fmt.Sprintf("tag:e%d-", j), 3000), strings.Join(attrs, ","))
	}
	tri.WriteString(`]}`)
	// Entry 0 holds one large target and the attributes a0..a99; entry j holds the target tj
	// and the attribute a(j-1). Each attribute is a different union holding the large item,
	// and the large item is hashed for every union and written for every set.
	var shared strings.Builder
	fmt.Fprintf(&shared, `{"nodeAttrs": [{"target": ["%s"], "attr": [%s]}`, strings.Repeat("t", 1_000_000), list("a", 100))
	for j := 1; j <= 100; j++ {
		fmt.Fprintf(&shared, `,{"target": ["t%d"], "attr": ["a%d"]}`, j, j-1)
	}
	shared.WriteString(`]}`)
	for name, text := range map[string]string{
		"unions that share a large target":        shared.String(),
		"attributes whose unions differ":          tri.String(),
		"attributes beside a large app":           `{"nodeAttrs": [{"target": ["tag:a"], "attr": [` + list("a", 600) + `], "app": {"c": [{"name": "` + big + `"}]}}]}`,
		"attributes beside a large ipPool":        `{"nodeAttrs": [{"target": ["tag:a"], "attr": [` + list("a", 600) + `], "ipPool": [` + list("192.0.2.", 20000) + `]}]}`,
		"attributes beside a large unknown field": `{"nodeAttrs": [{"target": ["tag:a"], "attr": [` + list("a", 600) + `], "future": "` + big + `"}]}`,
		"attributes by targets":                   `{"nodeAttrs": [{"target": [` + list("tag:t", 3000) + `], "attr": [` + list("a", 3000) + `]}]}`,
		"items beside large posture attributes":   `{"tests": [{"src": "a", "accept": [` + list("tag:x:", 1000) + `], "srcPostureAttrs": {"node:os": "` + big + `"}}]}`,
		"items beside a large unknown field":      `{"tests": [{"src": "a", "accept": [` + list("tag:x:", 1000) + `], "future": "` + big + `"}]}`,
		"ssh items beside a large unknown field":  `{"sshTests": [{"src": "a", "dst": ["d"], "accept": [` + list("u", 1000) + `], "future": "` + big + `"}]}`,
	} {
		alloc, ops, written, err := allocOf(t, text)
		t.Logf("%s: allocated %d MB, ops %d, written %d MB, err %v", name, alloc>>20, ops, written>>20, err)
		if err != nil && !errors.Is(err, ErrTooComplex) {
			t.Errorf("%s: %v", name, err)
		}
		// Every set WriteTo writes was paid for when it was interned.
		if limit := 8*uint64(maxWork) + 2<<20; uint64(written) > limit {
			t.Errorf("%s: WriteTo wrote %d bytes, past %d", name, written, limit)
		}
		if limit := 16*uint64(maxWork) + 2<<20; alloc > limit {
			t.Errorf("%s: allocated %d bytes (ops %d), past %d: a string was built without being counted", name, alloc, ops, limit)
		}
	}
}

// A protocol that is not exactly one string is not read as the protocol: it stays in the
// assertion's other fields, so two different lists are two different assertions.
func TestATestProtocolThatIsNotOneStringIsKept(t *testing.T) {
	test := func(proto string) string {
		return `{"tests": [{"src": "a", "accept": ["x:1"]` + proto + `}]}`
	}
	differ(t, "two protocols", test(`, "proto": ["tcp", "udp"]`), test(`, "proto": ["tcp", "icmp"]`))
	differ(t, "an empty list", test(`, "proto": []`), test(``))
	differ(t, "a list and a protocol", test(`, "proto": ["tcp", "udp"]`), test(`, "proto": "tcp"`))
	same(t, "one protocol as a list or a string", test(`, "proto": ["TCP"]`), test(`, "proto": "tcp"`))
	same(t, "null is absent", test(`, "proto": null`), test(``))
}

// A section holding the wrong type is one whole value, and no entry of the right type can
// stand for it, even an entry with the empty name.
func TestAWrongTypedSectionIsNotAnEntryNamedNothing(t *testing.T) {
	for _, p := range [][2]string{
		{`{"groups": {"": ["a"]}}`, `{"groups": ["a"]}`},
		{`{"hosts": {"": "a"}}`, `{"hosts": "a"}`},
		{`{"autoApprovers": {"": ["a"]}}`, `{"autoApprovers": ["a"]}`},
		{`{"derpMap": {"": ["a"]}}`, `{"derpMap": ["a"]}`},
		{`{"tagOwners": {"": ["a"]}}`, `{"tagOwners": ["a"]}`},
		{`{"postures": {"": ["a"]}}`, `{"postures": ["a"]}`},
	} {
		differ(t, p[0], p[0], p[1])
	}
}
