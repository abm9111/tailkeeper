package acl

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

// The properties of Diff, checked on policies a seeded generator draws and a rewriter
// (rewriter_test.go) writes in many equivalent ways. The seed is fixed so a failure repeats,
// and every failure message carries the seed, the iteration and both texts. The count is
// sized to about two seconds under the race detector.
const (
	propertySeed = 20261017
	// Iterations of the relations that draw one policy each; (d) applies each mutation
	// propertyApplied times.
	propertyIterations = 60
	propertyApplied    = 8
)

func propertyRNG(iteration int) *rand.Rand {
	return rand.New(rand.NewPCG(propertySeed, uint64(iteration)))
}

// clip shortens a text for a failure message: the adversarial inputs of the complexity
// guard are megabytes long.
func clip(s string) string {
	if len(s) <= 600 {
		return s
	}
	return fmt.Sprintf("%s\n... (%d bytes in all)", s[:600], len(s))
}

func propertyDiff(t *testing.T, a, b string) *DiffResult {
	t.Helper()
	da, err := Parse(context.Background(), []byte(a))
	if err != nil {
		t.Fatalf("the generator wrote a text that does not parse: %v\n%s", err, clip(a))
	}
	db, err := Parse(context.Background(), []byte(b))
	if err != nil {
		t.Fatalf("the generator wrote a text that does not parse: %v\n%s", err, clip(b))
	}
	r, err := Diff(context.Background(), da, db, DiffOptions{PageSize: MaxPage})
	if err != nil {
		t.Fatalf("Diff: %v\n--- a\n%s\n--- b\n%s", err, clip(a), clip(b))
	}
	return r
}

func randomSplits(rng *rand.Rand, n int) []splitKind {
	out := make([]splitKind, n)
	for i := range out {
		out[i] = splitKind(rng.IntN(4))
	}
	return out
}

func describe(r *DiffResult) string {
	var parts []string
	for _, c := range r.Changes {
		parts = append(parts, fmt.Sprintf("%s %s %s %q old=%s new=%s", c.Class, c.Op, c.Section, c.Key, c.Old.Text, c.New.Text))
	}
	return strings.Join(parts, "\n")
}

// (a) Whatever the rewriter does that does not change the meaning leaves Diff empty:
// whitespace, comments, trailing commas, the order of members and of sets, the case of
// section and field names, a string or an array for proto, accept or allow, users and
// ports for src and dst, acls or grants, a family of rules cut by sources, by destinations
// or by ports or written whole, and a rule written twice.
func TestPropertyRewritesAreEmpty(t *testing.T) {
	t.Logf("property seed %d (PCG, one stream per iteration)", propertySeed)
	for i := range propertyIterations {
		rng := propertyRNG(i)
		base := randomModel(rng)
		a := base.render(plain, rng, randomSplits(rng, len(base.families)))
		other := base
		if rng.IntN(4) == 0 && len(base.families) > 0 {
			other = base.clone()
			other.families = append(other.families, other.families[rng.IntN(len(other.families))])
		}
		b := other.render(randomStyle(rng), rng, randomSplits(rng, len(other.families)))
		r := propertyDiff(t, a, b)
		if !r.SemanticallyEqual || len(r.Changes) != 0 {
			t.Fatalf("relation (a) rewrites are empty: seed %d, iteration %d: a rewrite is a change\n--- a\n%s\n--- b\n%s\n--- changes\n%s", propertySeed, i, a, b, describe(r))
		}
	}
}

// (a) again, for repeated keys: the writer repeats a key of a map section with a decoy value
// first and the value that counts later, and writes a struct section (autoApprovers) as
// several members and as two fragments of the policy, in every case and shuffle style. A
// repeated map entry keeps the later value whole, and a repeated struct field merges, so the
// text has the normal form of the one written without the repeats.
func TestPropertyRepeatedKeysReadAsTheLastOrMerged(t *testing.T) {
	t.Logf("property seed %d (PCG, one stream per iteration)", propertySeed)
	decoyed, fragmented := 0, 0
	for i := range propertyIterations {
		rng := propertyRNG(i)
		base := randomModel(rng)
		a := base.render(plain, rng, nil)
		st := randomStyle(rng)
		st.decoys, st.fragments = true, true
		b := base.render(st, rng, randomSplits(rng, len(base.families)))
		if strings.Contains(b, "decoy") {
			decoyed++
		}
		if strings.Count(b, `"groups"`)+strings.Count(b, `"Groups"`) > 1 {
			fragmented++
		}
		if r := propertyDiff(t, a, b); !r.SemanticallyEqual || len(r.Changes) != 0 {
			t.Fatalf("relation (a) repeated keys: seed %d, iteration %d: a repeated key or a section in two fragments is a change\n--- a\n%s\n--- b\n%s\n--- changes\n%s", propertySeed, i, a, b, describe(r))
		}
	}
	if decoyed < propertyIterations/2 || fragmented < propertyIterations/4 {
		t.Fatalf("the writer repeated keys in %d and fragmented groups in %d of %d texts: the property would pass without them", decoyed, fragmented, propertyIterations)
	}
}

// mutation changes one thing in a model. It returns false when the model has nothing to
// change that way.
type mutation struct {
	name  string
	apply func(rng *rand.Rand, m *model) bool
}

var mutations = []mutation{
	{"a source added to a family", func(rng *rand.Rand, m *model) bool {
		if len(m.families) == 0 {
			return false
		}
		f := &m.families[rng.IntN(len(m.families))]
		f.src = append(f.src, "group:fresh")
		return true
	}},
	{"a source removed or replaced", func(rng *rand.Rand, m *model) bool {
		if len(m.families) == 0 {
			return false
		}
		f := &m.families[rng.IntN(len(m.families))]
		if len(f.src) > 1 {
			f.src = f.src[1:]
		} else {
			f.src = []string{"group:fresh"}
		}
		return true
	}},
	{"a destination added", func(rng *rand.Rand, m *model) bool {
		if len(m.families) == 0 {
			return false
		}
		f := &m.families[rng.IntN(len(m.families))]
		f.sels = append(f.sels, "tag:fresh")
		return true
	}},
	{"a port replaced", func(rng *rand.Rand, m *model) bool {
		if len(m.families) == 0 {
			return false
		}
		f := &m.families[rng.IntN(len(m.families))]
		f.ports[0] = "7777"
		return true
	}},
	{"a port added", func(rng *rand.Rand, m *model) bool {
		if len(m.families) == 0 {
			return false
		}
		f := &m.families[rng.IntN(len(m.families))]
		f.ports = append(f.ports, "7777")
		return true
	}},
	{"the protocol changed", func(rng *rand.Rand, m *model) bool {
		if len(m.families) == 0 {
			return false
		}
		f := &m.families[rng.IntN(len(m.families))]
		f.proto = map[string]string{"": "tcp", "tcp": "udp", "udp": ""}[f.proto]
		return true
	}},
	{"a source posture added or removed", func(rng *rand.Rand, m *model) bool {
		if len(m.families) == 0 {
			return false
		}
		f := &m.families[rng.IntN(len(m.families))]
		if len(f.posture) > 0 {
			f.posture = nil
		} else {
			f.posture = []string{"posture:z"}
		}
		return true
	}},
	{"an unknown field added to a rule or changed", func(rng *rand.Rand, m *model) bool {
		if len(m.families) == 0 {
			return false
		}
		f := &m.families[rng.IntN(len(m.families))]
		if f.extraKey == "" {
			f.extraKey, f.extraVal = "x-new", "1"
		} else {
			f.extraVal += "!"
		}
		return true
	}},
	{"a family removed", func(rng *rand.Rand, m *model) bool {
		if len(m.families) == 0 {
			return false
		}
		i := rng.IntN(len(m.families))
		m.families = append(m.families[:i], m.families[i+1:]...)
		return true
	}},
	{"a family added", func(rng *rand.Rand, m *model) bool {
		m.families = append(m.families, family{src: []string{"group:fresh"}, sels: []string{"tag:fresh"}, ports: []string{"7777"}})
		return true
	}},
	{"a test added", func(rng *rand.Rand, m *model) bool {
		m.tests = append(m.tests, modelTest{src: "group:fresh", accept: []string{"tag:fresh:1"}})
		return true
	}},
	{"a test assertion removed", func(rng *rand.Rand, m *model) bool {
		for i := range m.tests {
			if len(m.tests[i].accept) > 0 {
				m.tests[i].accept = m.tests[i].accept[1:]
				return true
			}
		}
		return false
	}},
	{"a group member added", func(rng *rand.Rand, m *model) bool {
		m.groups["group:eng"] = append(m.groups["group:eng"], "new@example.com")
		return true
	}},
	{"a tag owner changed", func(rng *rand.Rand, m *model) bool {
		m.tagOwners["tag:web"] = []string{"group:ops"}
		return true
	}},
	{"a host changed", func(rng *rand.Rand, m *model) bool {
		m.hosts["host-a"] = "192.0.2.99"
		return true
	}},
	{"an SSH rule's action flipped", func(rng *rand.Rand, m *model) bool {
		if len(m.ssh) == 0 {
			return false
		}
		s := &m.ssh[rng.IntN(len(m.ssh))]
		s.action = map[string]string{"accept": "check", "check": "accept"}[s.action]
		return true
	}},
	{"a node attribute target added", func(rng *rand.Rand, m *model) bool {
		if len(m.attrs) == 0 {
			return false
		}
		m.attrs[0].targets = append(m.attrs[0].targets, "tag:fresh")
		return true
	}},
	{"the operations of an ipset reordered", func(rng *rand.Rand, m *model) bool {
		ops := m.ipsets["ipset:s"]
		ops[0], ops[1] = ops[1], ops[0]
		return true
	}},
	{"a tag owner added to an entry that has several", func(rng *rand.Rand, m *model) bool {
		m.tagOwners["tag:db"] = append(m.tagOwners["tag:db"], "group:fresh")
		return true
	}},
	{"a via changed or added", func(rng *rand.Rand, m *model) bool {
		if len(m.families) == 0 {
			return false
		}
		f := &m.families[rng.IntN(len(m.families))]
		f.via = append(f.via, "tag:exit-fresh")
		return true
	}},
	{"an app changed or added", func(rng *rand.Rand, m *model) bool {
		if len(m.families) == 0 {
			return false
		}
		f := &m.families[rng.IntN(len(m.families))]
		f.app = appValue(1000 + rng.IntN(100))
		return true
	}},
	{"a posture assertion changed", func(rng *rand.Rand, m *model) bool {
		m.postures["posture:b"] = append(m.postures["posture:b"], "node:os == 'ios'")
		return true
	}},
	{"an auto-approved route's approver added", func(rng *rand.Rand, m *model) bool {
		m.autoRoutes["198.51.100.0/24"] = append(m.autoRoutes["198.51.100.0/24"], "group:fresh")
		return true
	}},
	{"an auto-approved route removed", func(rng *rand.Rand, m *model) bool {
		delete(m.autoRoutes, "192.0.2.0/24")
		return true
	}},
	{"an exit node approver removed", func(rng *rand.Rand, m *model) bool {
		m.autoExit = m.autoExit[1:]
		return true
	}},
	{"two elements of an array inside an unknown section swapped", func(rng *rand.Rand, m *model) bool {
		obj, ok := m.unknown["futureThing"].(*jobj)
		if !ok {
			return false
		}
		list := append([]jv(nil), obj.vals["list"].([]jv)...)
		list[0], list[1] = list[1], list[0]
		m.unknown["futureThing"] = newObj().set("k", obj.vals["k"]).set("list", list)
		return true
	}},
	{"a field of an unknown section changed", func(rng *rand.Rand, m *model) bool {
		if _, ok := m.unknown["futureThing"]; !ok {
			return false
		}
		m.unknown["futureThing"] = newObj().set("k", -1).set("list", []jv{1, 2, 3})
		return true
	}},
	{"an unknown section added", func(rng *rand.Rand, m *model) bool {
		m.unknown["anotherThing"] = true
		return true
	}},
}

// (d) Changing any one thing is always reported: no rewrite class swallows a real change.
// That includes a field the engine does not know in a rule, and a field of a section it
// does not know. This is the direction in which a normal form can do harm.
func TestPropertyAnyOneChangeIsReported(t *testing.T) {
	t.Logf("property seed %d (PCG, one stream per iteration)", propertySeed)
	for _, mu := range mutations {
		applied := 0
		for i := 0; applied < propertyApplied; i++ {
			if i >= 400 {
				t.Fatalf("%s: applied %d times in 400 policies: the property would pass without it", mu.name, applied)
			}
			rng := propertyRNG(i)
			base := randomModel(rng)
			changed := base.clone()
			if !mu.apply(rng, changed) {
				continue
			}
			applied++
			a := base.render(randomStyle(rng), rng, randomSplits(rng, len(base.families)))
			b := changed.render(randomStyle(rng), rng, randomSplits(rng, len(changed.families)))
			r := propertyDiff(t, a, b)
			if r.SemanticallyEqual || len(r.Changes) == 0 {
				t.Fatalf("relation (d) any one change is reported: seed %d, iteration %d, %s: not reported\n--- a\n%s\n--- b\n%s", propertySeed, i, mu.name, a, b)
			}
		}
	}
}

// (b) Diff(a, b) mirrors Diff(b, a): what one adds the other removes, what one changes the
// other changes, and the two agree on whether the policies are equal. Defaults and
// widening are one-sided by nature and a removed test is a reduction where an added one is
// an ordinary change, so the comparison is over the total of the other classes.
func TestPropertyDiffMirrors(t *testing.T) {
	t.Logf("property seed %d (PCG, one stream per iteration)", propertySeed)
	flip := map[Op]Op{OpAdded: OpRemoved, OpRemoved: OpAdded, OpChanged: OpChanged}
	ops := func(r *DiffResult) map[string]int {
		m := map[string]int{}
		for _, c := range r.Changes {
			if c.Class == ClassSemantic || c.Class == ClassTestsReduced || c.Class == ClassTailscaleWritten {
				m[fmt.Sprintf("%s %s %s", c.Section, c.Op, c.Key)]++
			}
		}
		return m
	}
	for i := range propertyIterations {
		rng := propertyRNG(i)
		base := randomModel(rng)
		changed := base.clone()
		for k := 0; k < 1+rng.IntN(3); k++ {
			mutations[rng.IntN(len(mutations))].apply(rng, changed)
		}
		a := base.render(plain, rng, nil)
		b := changed.render(plain, rng, nil)
		ab, ba := propertyDiff(t, a, b), propertyDiff(t, b, a)
		if ab.SemanticallyEqual != ba.SemanticallyEqual {
			t.Fatalf("relation (b) Diff mirrors: seed %d, iteration %d: equal one way and not the other\n--- a\n%s\n--- b\n%s", propertySeed, i, a, b)
		}
		x, y := ops(ab), ops(ba)
		for key, n := range x {
			parts := strings.SplitN(key, " ", 3)
			mirrored := fmt.Sprintf("%s %s %s", parts[0], flip[Op(parts[1])], parts[2])
			if y[mirrored] != n {
				t.Fatalf("relation (b) Diff mirrors: seed %d, iteration %d: %q is %d one way and %d (%q) the other\n--- a\n%s\n--- b\n%s\n--- ab\n%s\n--- ba\n%s",
					propertySeed, i, key, n, y[mirrored], mirrored, a, b, describe(ab), describe(ba))
			}
		}
		if len(x) != len(y) {
			t.Fatalf("relation (b) Diff mirrors: seed %d, iteration %d: %d changes one way and %d the other", propertySeed, i, len(x), len(y))
		}
	}
}

// mutationNamed finds a mutation by its name, so that a test does not depend on where the
// list puts it.
func mutationNamed(t *testing.T, name string) mutation {
	t.Helper()
	for _, mu := range mutations {
		if mu.name == name {
			return mu
		}
	}
	t.Fatalf("no mutation is named %q", name)
	return mutation{}
}

// (c) On the keyed sections, composition is consistent: a key that differs between a and c
// differs between a and b or between b and c, and a key that changed from a to b and not
// from b to c still differs between a and c.
func TestPropertyCompositionOnKeyedSections(t *testing.T) {
	t.Logf("property seed %d (PCG, one stream per iteration)", propertySeed)
	keys := func(r *DiffResult) map[string]bool {
		m := map[string]bool{}
		for _, c := range r.Changes {
			if c.Section == "groups" || c.Section == "tagOwners" || c.Section == "hosts" {
				m[c.Section+"/"+c.Key] = true
			}
		}
		return m
	}
	keyed := []mutation{mutationNamed(t, "a group member added"), mutationNamed(t, "a tag owner changed"), mutationNamed(t, "a host changed"), mutationNamed(t, "a tag owner added to an entry that has several")}
	extra := []func(m *model){
		func(m *model) { m.groups["group:ops"] = nil },
		func(m *model) { m.groups["group:new"] = []string{"n@example.com"} },
		func(m *model) { delete(m.hosts, "host-b") },
		func(m *model) { m.tagOwners["tag:fresh"] = []string{} },
		func(m *model) { m.hosts["host-a"] = "192.0.2.10" }, // back to what it was
	}
	for i := range propertyIterations {
		rng := propertyRNG(i)
		m0 := randomModel(rng)
		m1 := m0.clone()
		for k := 0; k < rng.IntN(3); k++ {
			if rng.IntN(2) == 0 {
				keyed[rng.IntN(len(keyed))].apply(rng, m1)
			} else {
				extra[rng.IntN(len(extra))](m1)
			}
		}
		// m2 builds on m1, not on m0.
		m2 := m1.clone()
		for k := 0; k < rng.IntN(3); k++ {
			if rng.IntN(2) == 0 {
				keyed[rng.IntN(len(keyed))].apply(rng, m2)
			} else {
				extra[rng.IntN(len(extra))](m2)
			}
		}
		a, b, c := m0.render(plain, rng, nil), m1.render(plain, rng, nil), m2.render(plain, rng, nil)
		ab, bc, ac := keys(propertyDiff(t, a, b)), keys(propertyDiff(t, b, c)), keys(propertyDiff(t, a, c))
		for k := range ac {
			if !ab[k] && !bc[k] {
				t.Fatalf("relation (c) composition on keyed sections: seed %d, iteration %d: %s differs from a to c and from neither step", propertySeed, i, k)
			}
		}
		for k := range ab {
			if !bc[k] && !ac[k] {
				t.Fatalf("relation (c) composition on keyed sections: seed %d, iteration %d: %s changed from a to b, was kept from b to c, and is not in a to c", propertySeed, i, k)
			}
		}
	}
}

// (e) A difference inside a section the engine does not know is always reported, and a
// change in key order inside it, or in the case of its name, is not one. An array inside such
// a section is a list: two elements swapped, at any depth, are a change.
func TestPropertyUnknownSectionsAreCompared(t *testing.T) {
	t.Logf("property seed %d (PCG, one stream per iteration)", propertySeed)
	future := func(a int, b []jv, d int, e []jv) *jobj {
		return newObj().set("a", a).set("b", b).set("c", newObj().set("d", d).set("e", e))
	}
	for i := range propertyIterations {
		rng := propertyRNG(i)
		base := randomModel(rng)
		a0, b0, d0 := rng.IntN(5), rng.IntN(5), rng.IntN(5)
		listB, listE := []jv{b0, "x"}, []jv{1, 2, 3}
		base.unknown["futureThing"] = future(a0, listB, d0, listE)
		a := base.render(plain, rng, nil)

		reordered := base.clone()
		reordered.unknown["futureThing"] = newObj().set("c", newObj().set("e", listE).set("d", d0)).set("b", listB).set("a", a0)
		st := randomStyle(rng)
		st.upperSections = i%2 == 0 // the name of the section in another case
		if r := propertyDiff(t, a, reordered.render(st, rng, nil)); !r.SemanticallyEqual {
			t.Fatalf("relation (e) unknown sections are compared: seed %d, iteration %d: key order inside an unknown section, or the case of its name, is a change\n%s", propertySeed, i, describe(r))
		}

		for _, c := range []struct {
			what string
			to   *jobj
		}{
			{"a value changed", future(a0, listB, d0+100, listE)},
			{"two elements of an array swapped", future(a0, []jv{"x", b0}, d0, listE)},
			{"two elements of an array in an object swapped", future(a0, listB, d0, []jv{1, 3, 2})},
		} {
			changed := base.clone()
			changed.unknown["futureThing"] = c.to
			r := propertyDiff(t, a, changed.render(plain, rng, nil))
			if r.SemanticallyEqual || r.Counts.Semantic != 1 || !strings.EqualFold(r.Changes[0].Section, "futureThing") {
				t.Fatalf("relation (e) unknown sections are compared: seed %d, iteration %d, %s: not reported as one change in the section\n%s", propertySeed, i, c.what, describe(r))
			}
		}
	}
}

// The documented limit: a family cut along its sources and its ports at once is the same
// access and reads as changed, with the limit named. It is the safe direction.
func TestPropertyTheReductionLimitIsSaidAndSafe(t *testing.T) {
	a := `{"acls": [{"action": "accept", "src": ["a", "b"], "dst": ["x:80", "x:443"]}]}`
	b := `{"acls": [{"action": "accept", "src": ["a", "b"], "dst": ["x:80"]}, {"action": "accept", "src": ["a"], "dst": ["x:443"]}, {"action": "accept", "src": ["b"], "dst": ["x:443"]}]}`
	r := propertyDiff(t, a, b)
	if r.SemanticallyEqual || len(r.NormalFormLimits) != 1 {
		t.Errorf("the limit: %+v", r)
	}
}
