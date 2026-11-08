package acl

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// accessPolicy is a synthetic policy that has every kind of rule the reading lists, written the
// ways the server reads: a section name in another case, the legacy users and ports of an acl
// rule, comments and trailing commas.
const accessPolicy = `// synthetic
{
	"Groups": {"group:example-admins": ["alice@example.com", "bob@example.com"], "group:bad": [1]},
	"hosts": {"example-host": "192.0.2.10", "range": "198.51.100.0/24", "bad": 7},
	"tagOwners": {"tag:example-web": ["group:example-admins"], "tag:example-db": ["alice@example.com"]},
	"ACLs": [
		{"action": "accept", "src": ["group:example-admins"], "dst": ["tag:example-db:22", "[fd7a:115c:a1e0::1]:443", "*:80,443"]},
		{"action": "accept", "users": ["tag:example-web"], "ports": ["tag:example-db:5432"], "srcPosture": ["posture:ok"]},
		{"action": "accept", "src": ["*"], "dst": ["*:*"]},
		"not an object",
		{"action": "accept", "src": "tag:x", "dst": ["tag:y:1"]},
	],
	"grants": [
		{"src": ["tag:example-web"], "dst": ["tag:example-db"], "ip": ["tcp:22", "443"], "via": ["tag:exit"]},
		{"src": ["*"], "dst": ["tag:example-db"], "app": {"example.com/cap": [{"x": 1}]}},
		{"src": ["*"], "dst": ["tag:example-db"], "app": {}},
		{"src": ["*"], "dst": ["tag:example-db"], "app": null, "via": []},
	],
	"ssh": [
		{"action": "accept", "src": ["group:example-admins"], "dst": ["tag:example-db"], "users": ["root", "autogroup:nonroot"]},
	],
	"defaultSrcPosture": ["posture:default"],
}`

func readAccess(t *testing.T, text string) *Access {
	t.Helper()
	a, err := ReadAccess(context.Background(), mustParse(t, text))
	if err != nil {
		t.Fatalf("ReadAccess: %v", err)
	}
	return a
}

func TestReadAccessListsTheRulesOfEverySection(t *testing.T) {
	a := readAccess(t, accessPolicy)
	if len(a.Rules) != 5+4+1 || a.OmittedRules != 0 {
		t.Fatalf("%d rules, %d omitted; want 10 and 0", len(a.Rules), a.OmittedRules)
	}
	r0 := a.Rules[0]
	want := AccessRule{Section: "acls", Index: 1, Line: 7, Column: 3, Src: []string{"group:example-admins"}, Dst: []AccessDst{
		{"tag:example-db", "22"}, {"fd7a:115c:a1e0::1", "443"}, {"*", "80,443"}}}
	if !reflect.DeepEqual(r0, want) {
		t.Errorf("acls[1] = %+v\nwant     %+v", r0, want)
	}
	r1 := a.Rules[1]
	if r1.Src[0] != "tag:example-web" || r1.Dst[0] != (AccessDst{"tag:example-db", "5432"}) || !r1.Posture || r1.Index != 2 {
		t.Errorf("a legacy users/ports rule with a posture: %+v", r1)
	}
	if !a.Rules[3].Unreadable || a.Rules[3].Index != 4 || !a.Rules[4].Unreadable {
		t.Errorf("a rule that is not an object, or whose src is a string, is unreadable: %+v %+v", a.Rules[3], a.Rules[4])
	}
	g := a.Rules[5]
	if g.Section != "grants" || !g.Via || g.App || !reflect.DeepEqual(g.IP, []string{"tcp:22", "443"}) || g.Dst[0] != (AccessDst{"tag:example-db", ""}) {
		t.Errorf("grants[1] = %+v", g)
	}
	if !a.Rules[6].App || a.Rules[7].App || a.Rules[8].App || a.Rules[8].Via {
		t.Errorf("app capabilities: a map with an entry is one; {} and null are not: %+v %+v %+v", a.Rules[6], a.Rules[7], a.Rules[8])
	}
	s := a.Rules[9]
	if s.Section != "ssh" || !reflect.DeepEqual(s.Users, []string{"root", "autogroup:nonroot"}) || s.Dst[0].Selector != "tag:example-db" {
		t.Errorf("ssh[1] = %+v", s)
	}
	if !a.DefaultPosture {
		t.Error("defaultSrcPosture was not seen")
	}
}

// An acls rule's proto is read as written, one string or a list: it is what limits an acls rule
// to some protocols. A grant has no proto (its ip entries carry the protocols), a proto that is
// neither a string nor a list of them makes the rule unreadable, and an empty one is none.
func TestReadAccessReadsTheProtoOfAnACLRule(t *testing.T) {
	a := readAccess(t, `{
	"acls": [
		{"action": "accept", "src": ["*"], "dst": ["*:*"]},
		{"action": "accept", "src": ["*"], "proto": "tcp", "dst": ["*:22"]},
		{"action": "accept", "src": ["*"], "proto": ["tcp", "udp"], "dst": ["*:22"]},
		{"action": "accept", "src": ["*"], "proto": null, "dst": ["*:*"]},
		{"action": "accept", "src": ["*"], "proto": [], "dst": ["*:*"]},
		{"action": "accept", "src": ["*"], "proto": 6, "dst": ["*:*"]},
		{"action": "accept", "src": ["*"], "proto": ["tcp", 6], "dst": ["*:*"]},
	],
	"grants": [
		{"src": ["*"], "dst": ["*"], "ip": ["tcp:22"], "proto": "udp"},
	],
}`)
	if len(a.Rules) != 8 {
		t.Fatalf("%d rules, want 8", len(a.Rules))
	}
	for i, want := range [][]string{nil, {"tcp"}, {"tcp", "udp"}, nil, nil} {
		if got := a.Rules[i].Proto; !reflect.DeepEqual(got, want) || a.Rules[i].Unreadable {
			t.Errorf("acls[%d]: proto %#v unreadable %v, want %#v", i+1, got, a.Rules[i].Unreadable, want)
		}
	}
	for _, i := range []int{5, 6} {
		r := a.Rules[i]
		if !r.Unreadable || r.Proto != nil || r.Src != nil || r.Dst != nil || r.Section != "acls" || r.Index != i+1 {
			t.Errorf("acls[%d] = %+v, want an unreadable rule with its other fields empty", i+1, r)
		}
	}
	if g := a.Rules[7]; g.Proto != nil || g.Unreadable || !reflect.DeepEqual(g.IP, []string{"tcp:22"}) {
		t.Errorf("a grant = %+v: it has no proto", g)
	}
}

// An ssh rule can carry srcPosture as an acls rule or a grant does, and it is read the same way: a
// list that names something is a posture, an empty one or null is none, and a value that is not a
// list is read as a posture, for a srcPosture the reader cannot take is not an absent one.
func TestReadAccessReadsThePostureOfAnSSHRule(t *testing.T) {
	a := readAccess(t, `{
	"ssh": [
		{"action": "accept", "src": ["*"], "dst": ["tag:example-db"], "users": ["root"]},
		{"action": "accept", "src": ["*"], "dst": ["tag:example-db"], "users": ["root"], "srcPosture": ["posture:example"]},
		{"action": "accept", "src": ["*"], "dst": ["tag:example-db"], "users": ["root"], "srcPosture": []},
		{"action": "accept", "src": ["*"], "dst": ["tag:example-db"], "users": ["root"], "srcPosture": null},
		{"action": "accept", "src": ["*"], "dst": ["tag:example-db"], "users": ["root"], "srcPosture": "posture:example"},
	],
}`)
	if len(a.Rules) != 5 {
		t.Fatalf("%d rules, want 5", len(a.Rules))
	}
	for i, want := range []bool{false, true, false, false, true} {
		r := a.Rules[i]
		if r.Posture != want || r.Unreadable || !reflect.DeepEqual(r.Users, []string{"root"}) || r.Section != "ssh" {
			t.Errorf("ssh[%d] = %+v, want posture %v and its users", i+1, r, want)
		}
	}
}

// What the reader cannot take it does not drop: a field of a rule that is not the list it should
// be makes the rule unreadable, with its other fields empty (so the rules limit stands), and so does a
// section that is neither a list of rules nor null.
func TestReadAccessDoesNotDropWhatItCannotRead(t *testing.T) {
	a := readAccess(t, `{
	"ssh": [
		{"action": "accept", "src": ["*"], "dst": ["tag:example-db"], "users": "root", "srcPosture": ["posture:example"]},
		{"action": "accept", "src": ["*"], "dst": ["tag:example-db"], "users": ["root", 7]},
		{"action": "accept", "src": ["*"], "dst": ["tag:example-db"], "users": null},
		{"action": "accept", "src": ["*"], "dst": ["tag:example-db"]},
	],
	"grants": [
		{"src": ["*"], "dst": ["tag:example-db"], "ip": "tcp:22"},
		{"src": ["*"], "dst": ["tag:example-db"], "ip": ["tcp:22", 80]},
		{"src": ["*"], "dst": ["tag:example-db"], "ip": null},
		{"src": ["*"], "dst": ["tag:example-db"], "ip": ["tcp:22"]},
	],
	"acls": {"action": "accept"},
}`)
	var bySection = map[string][]AccessRule{}
	for _, r := range a.Rules {
		bySection[r.Section] = append(bySection[r.Section], r)
	}
	for i, wantUnreadable := range []bool{true, true, false, false} {
		r := bySection["ssh"][i]
		if r.Unreadable != wantUnreadable || (wantUnreadable && (r.Src != nil || r.Dst != nil || r.Users != nil || r.Posture)) {
			t.Errorf("ssh[%d] = %+v, want unreadable %v, with its other fields empty when it is", i+1, r, wantUnreadable)
		}
	}
	for i, wantUnreadable := range []bool{true, true, false, false} {
		r := bySection["grants"][i]
		if r.Unreadable != wantUnreadable || (wantUnreadable && (r.Src != nil || r.Dst != nil || r.IP != nil)) {
			t.Errorf("grants[%d] = %+v, want unreadable %v, with its other fields empty when it is", i+1, r, wantUnreadable)
		}
	}
	if acls := bySection["acls"]; len(acls) != 1 || !acls[0].Unreadable || acls[0].Index != 1 {
		t.Errorf("a section that is an object: %+v, want one unreadable rule standing for it", acls)
	}
	if n := len(readAccess(t, `{"acls": null, "grants": null, "ssh": null}`).Rules); n != 0 {
		t.Errorf("sections written null hold %d rules, want none", n)
	}
}

// A grant's via and app that the reader cannot take as what they should be are not absent ones: a via
// that is not a list of strings, and an app that is not an object or null, are read as set, as a
// srcPosture that is not a list is, so that the limits cannot rule them out. An empty list, null and
// an empty object are none.
func TestReadAccessReadsAViaOrAppItCannotTakeAsSet(t *testing.T) {
	grant := func(extra string) AccessRule {
		a := readAccess(t, `{"grants": [{"src": ["*"], "dst": ["tag:example-db"], "ip": ["*"]`+extra+`}]}`)
		if len(a.Rules) != 1 || a.Rules[0].Unreadable {
			t.Fatalf("grant with %q: rules %+v, want one readable rule", extra, a.Rules)
		}
		return a.Rules[0]
	}
	for extra, want := range map[string]bool{
		``: false, `, "via": ["tag:example-exit"]`: true, `, "via": []`: false, `, "via": null`: false,
		`, "via": "tag:example-exit"`: true, `, "via": 7`: true, `, "via": true`: true, `, "via": {"tag:example-exit": 1}`: true,
		`, "via": ["tag:example-exit", 7]`: true, `, "via": [7]`: true,
	} {
		if got := grant(extra).Via; got != want {
			t.Errorf("grant%s: Via = %v, want %v", extra, got, want)
		}
	}
	for extra, want := range map[string]bool{
		`, "app": {"tailscale.com/cap/example": [{}]}`: true, `, "app": {}`: false, `, "app": null`: false,
		`, "app": "tailscale.com/cap/example"`: true, `, "app": 7`: true, `, "app": true`: true, `, "app": []`: true, `, "app": ["tailscale.com/cap/example"]`: true,
	} {
		if got := grant(extra).App; got != want {
			t.Errorf("grant%s: App = %v, want %v", extra, got, want)
		}
	}
}

// defaultSrcPosture that is not a list is not an absent one: a list that names something, a string, a
// number and an object set a posture, an empty list and null set none.
func TestReadAccessReadsAMalformedDefaultPostureAsSet(t *testing.T) {
	for value, want := range map[string]bool{
		`["posture:example"]`: true, `[]`: false, `null`: false, `"posture:example"`: true, `7`: true, `true`: true,
		`{"posture:example": 1}`: true, `[1]`: true, `[null]`: true, `""`: true,
	} {
		if got := readAccess(t, `{"defaultSrcPosture": `+value+`}`).DefaultPosture; got != want {
			t.Errorf("defaultSrcPosture %s: DefaultPosture = %v, want %v", value, got, want)
		}
	}
	if readAccess(t, `{}`).DefaultPosture {
		t.Error("a policy that writes no defaultSrcPosture has one")
	}
}

func TestReadAccessResolvesNamesAsText(t *testing.T) {
	a := readAccess(t, accessPolicy)
	if !reflect.DeepEqual(a.Groups["group:example-admins"], []string{"alice@example.com", "bob@example.com"}) {
		t.Errorf("groups = %v", a.Groups)
	}
	if _, ok := a.Groups["group:bad"]; ok {
		t.Error("a group whose members are not strings was listed")
	}
	if a.Hosts["example-host"] != "192.0.2.10" || a.Hosts["range"] != "198.51.100.0/24" || len(a.Hosts) != 2 {
		t.Errorf("hosts = %v", a.Hosts)
	}
	if !reflect.DeepEqual(a.TagOwners["tag:example-db"], []string{"alice@example.com"}) {
		t.Errorf("tagOwners = %v", a.TagOwners)
	}
}

func TestReadAccessOfAnEmptyOrOddPolicy(t *testing.T) {
	a := readAccess(t, `{}`)
	if len(a.Rules) != 0 || a.DefaultPosture || len(a.Groups) != 0 || len(a.Hosts) != 0 || len(a.TagOwners) != 0 {
		t.Errorf("an empty policy: %+v", a)
	}
	a = readAccess(t, `{"acls": {"x": 1}, "grants": null, "ssh": "no", "groups": [], "hosts": 3, "tagOwners": null, "defaultSrcPosture": []}`)
	// A section that is neither a list nor null is one unreadable rule (the limits cannot rule out
	// what was not read); one written null holds nothing.
	if len(a.Rules) != 2 || !a.Rules[0].Unreadable || a.Rules[0].Section != "acls" || !a.Rules[1].Unreadable || a.Rules[1].Section != "ssh" || a.DefaultPosture {
		t.Errorf("sections of the wrong type: %+v", a)
	}
	if _, err := ReadAccess(context.Background(), nil); err == nil {
		t.Error("a nil document was read")
	}
}

// The reading is bounded: the rules past the cap are counted, not listed.
func TestReadAccessCapsTheRules(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"acls": [`)
	for i := 0; i < MaxAccessRules+10; i++ {
		fmt.Fprintf(&b, `{"src": ["tag:a"], "dst": ["tag:b:%d"]},`, i%60000+1)
	}
	b.WriteString(`], "grants": [{"src": ["*"], "dst": ["*"]}]}`)
	a := readAccess(t, b.String())
	if len(a.Rules) != MaxAccessRules || a.OmittedRules != 10+1 {
		t.Errorf("%d rules listed, %d omitted; want %d and 11", len(a.Rules), a.OmittedRules, MaxAccessRules)
	}
}

func TestReadAccessSpendsTheWorkBudget(t *testing.T) {
	d := mustParse(t, accessPolicy)
	old := maxWork
	maxWork = 20
	defer func() { maxWork = old }()
	if _, err := ReadAccess(context.Background(), d); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("err = %v, want too_complex", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	maxWork = old
	if _, err := ReadAccess(ctx, d); err == nil {
		t.Error("a cancelled context was read")
	}
}

// The work is counted where it is done: a rule costs five units (its own tick, one for each of two
// fields, and one for each member of the two lists it reads), and a list costs its members.
func TestReadAccessSpendsTheWorkBudgetOnRules(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"acls": [`)
	for i := 0; i < 50; i++ {
		b.WriteString(`{"src": ["tag:a"], "dst": ["tag:b:1"]},`)
	}
	b.WriteString(`]}`)
	d := mustParse(t, b.String())
	old := maxWork
	defer func() { maxWork = old }()
	maxWork = 260
	if _, err := ReadAccess(context.Background(), d); err != nil {
		t.Fatalf("50 rules within a budget of 260: %v", err)
	}
	maxWork = 240
	if _, err := ReadAccess(context.Background(), d); err == nil {
		t.Error("50 rules, 250 units of work, were read within a budget of 240")
	}
}

// A grant costs eight units: its own tick, one for each of its three fields, one for each member of
// the three lists it reads, and one more for the grant.
func TestReadAccessSpendsTheWorkBudgetOnGrants(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"grants": [`)
	for i := 0; i < 50; i++ {
		b.WriteString(`{"src": ["tag:a"], "dst": ["tag:b"], "ip": ["22"]},`)
	}
	b.WriteString(`]}`)
	d := mustParse(t, b.String())
	old := maxWork
	defer func() { maxWork = old }()
	maxWork = 410
	if _, err := ReadAccess(context.Background(), d); err != nil {
		t.Fatalf("50 grants within a budget of 410: %v", err)
	}
	maxWork = 390
	if _, err := ReadAccess(context.Background(), d); err == nil {
		t.Error("50 grants, 400 units of work, were read within a budget of 390")
	}
}

// The members of a group and of the owners of a tag are charged before they are read, as those of a
// rule are: a list of a hundred thousand members, read with a budget of a hundred, is refused
// without its members being decoded and appended (the allocation, about 10 MB when they are, is what shows it).
func TestReadAccessChargesTheListOfAGroupOrOfTagOwnersBeforeReadingIt(t *testing.T) {
	members := strings.TrimSuffix(strings.Repeat(`"user@example.com",`, 100000), ",")
	old := maxWork
	defer func() { maxWork = old }()
	for _, c := range []struct{ section, key string }{{"groups", "group:example-a"}, {"tagOwners", "tag:example-a"}} {
		maxWork = old // parsing the text is metered too
		d := mustParse(t, `{"`+c.section+`": {"`+c.key+`": [`+members+`]}}`)
		maxWork = 100
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, err := ReadAccess(context.Background(), d)
		runtime.ReadMemStats(&after)
		if err == nil || !strings.Contains(err.Error(), "limit") {
			t.Errorf("%s: 100,000 members within a budget of 100: err = %v, want too_complex", c.section, err)
		}
		if got := after.TotalAlloc - before.TotalAlloc; got > 256<<10 {
			t.Errorf("%s: a list refused by the budget allocated %d bytes: its members were read before they were charged", c.section, got)
		}
	}
}

// Every list a rule is read with costs its members, before they are read: a rule that lists ten
// thousand selectors, destinations, users, protocols, postures, ip entries or via entries is a rule
// of ten thousand steps and not of three. The same rule with ten members is read within the same
// budget, so that the refusal is for the length.
func TestReadAccessChargesTheListsOfARule(t *testing.T) {
	list := func(n int, item string) string {
		return `[` + strings.TrimSuffix(strings.Repeat(`"`+item+`",`, n), ",") + `]`
	}
	cases := []struct{ name, rule, field, item string }{
		{"the sources of an acls rule", `{"src": %s, "dst": ["tag:b:1"]}`, "acls", "tag:a"},
		{"the sources of an acls rule that has no destinations", `{"src": %s}`, "acls", "tag:a"},
		{"the destinations of an acls rule", `{"src": ["tag:a"], "dst": %s}`, "acls", "tag:b:1"},
		{"the legacy users of an acls rule", `{"users": %s, "ports": ["tag:b:1"]}`, "acls", "tag:a"},
		{"the legacy ports of an acls rule", `{"users": ["tag:a"], "ports": %s}`, "acls", "tag:b:1"},
		{"the protocols of an acls rule", `{"src": ["tag:a"], "dst": ["tag:b:1"], "proto": %s}`, "acls", "tcp"},
		{"the postures of an acls rule", `{"src": ["tag:a"], "dst": ["tag:b:1"], "srcPosture": %s}`, "acls", "posture:x"},
		{"the sources of an ssh rule", `{"action": "accept", "src": %s, "dst": ["tag:b"], "users": ["root"]}`, "ssh", "tag:a"},
		{"the destinations of an ssh rule", `{"action": "accept", "src": ["tag:a"], "dst": %s, "users": ["root"]}`, "ssh", "tag:b"},
		{"the users of an ssh rule", `{"action": "accept", "src": ["tag:a"], "dst": ["tag:b"], "users": %s}`, "ssh", "root"},
		{"the sources of a grant", `{"src": %s, "dst": ["tag:b"], "ip": ["22"]}`, "grants", "tag:a"},
		{"the destinations of a grant", `{"src": ["tag:a"], "dst": %s, "ip": ["22"]}`, "grants", "tag:b"},
		{"the ip entries of a grant", `{"src": ["tag:a"], "dst": ["tag:b"], "ip": %s}`, "grants", "tcp:22"},
		{"the via entries of a grant", `{"src": ["tag:a"], "dst": ["tag:b"], "ip": ["22"], "via": %s}`, "grants", "tag:r"},
	}
	old := maxWork
	defer func() { maxWork = old }()
	for _, c := range cases {
		read := func(n int) error {
			maxWork = old // parsing the text is metered too: only the reading has the small budget
			d := mustParse(t, `{"`+c.field+`": [`+strings.Replace(c.rule, "%s", list(n, c.item), 1)+`]}`)
			maxWork = 5000
			_, err := ReadAccess(context.Background(), d)
			return err
		}
		if err := read(10); err != nil {
			t.Errorf("%s: ten members within a budget of 5,000: %v", c.name, err)
		}
		if err := read(10000); err == nil || !strings.Contains(err.Error(), "limit") {
			t.Errorf("%s: ten thousand members within a budget of 5,000: err = %v, want too_complex", c.name, err)
		}
	}
}

func TestReadAccessSpendsTheWorkBudgetOnMembers(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"groups": {"group:a": [`)
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&b, `"u%d@example.com",`, i)
	}
	b.WriteString(`]}}`)
	d := mustParse(t, b.String())
	old := maxWork
	defer func() { maxWork = old }()
	maxWork = 100
	if _, err := ReadAccess(context.Background(), d); err == nil {
		t.Error("300 members were read within a budget of 100")
	}
}

func TestPortsContain(t *testing.T) {
	cases := []struct {
		spec     string
		port     int
		in, read bool
	}{
		{"*", 0, true, true}, {"*", 65535, true, true}, {"22", 22, true, true}, {"22", 23, false, true},
		{"22,80-90", 85, true, true}, {"22,80-90", 91, false, true}, {"80-90", 80, true, true}, {"80-90", 90, true, true},
		{"", 22, false, false}, {"abc", 22, false, false}, {"90-80", 85, false, false},
	}
	for _, c := range cases {
		in, read := PortsContain(c.spec, c.port)
		if in != c.in || read != c.read {
			t.Errorf("PortsContain(%q, %d) = %v, %v; want %v, %v", c.spec, c.port, in, read, c.in, c.read)
		}
	}
}

func TestSplitDstPorts(t *testing.T) {
	cases := map[string][2]string{
		"tag:example-db:22":      {"tag:example-db", "22"},
		"*:*":                    {"*", "*"},
		"192.0.2.0/24:22,80-90":  {"192.0.2.0/24", "22,80-90"},
		"[fd7a::1]:443":          {"fd7a::1", "443"},
		"example-host":           {"example-host", ""},
		"tag:example-db":         {"tag:example-db", ""},
		"fd7a:115c:a1e0::1":      {"fd7a:115c:a1e0::1", ""},
		"tag:example-db:":        {"tag:example-db:", ""},
		":22":                    {":22", ""},
		"autogroup:internet:443": {"autogroup:internet", "443"},
	}
	for in, want := range cases {
		sel, ports := splitDstPorts(in)
		if sel != want[0] || ports != want[1] {
			t.Errorf("splitDstPorts(%q) = %q, %q; want %q, %q", in, sel, ports, want[0], want[1])
		}
	}
}

// A port spec read once is a set that says, by a search of its ranges, whether it names a port.
func TestPortSetReadsASpecOnce(t *testing.T) {
	set, ok := ParsePortSet("80,22,1000-2000,90,1500,*-")
	if ok {
		t.Fatalf("a spec with a part that is no port was read: %+v", set)
	}
	set, ok = ParsePortSet("443,22,1000-2000,80-90,1500")
	if !ok {
		t.Fatal("a spec was not read")
	}
	for port, want := range map[int]bool{21: false, 22: true, 23: false, 79: false, 80: true, 85: true, 90: true, 91: false, 442: false, 443: true, 444: false, 999: false, 1000: true, 1500: true, 2000: true, 2001: false, 0: false, 65535: false} {
		if got := set.Contains(port); got != want {
			t.Errorf("Contains(%d) = %v, want %v", port, got, want)
		}
	}
	all, _ := ParsePortSet("*")
	if !all.Contains(0) || !all.Contains(65535) {
		t.Error("* does not name every port")
	}
	if _, ok := ParsePortSet(""); ok {
		t.Error("an empty spec was read")
	}
}
