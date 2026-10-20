package acl

import "testing"

// vectorSource is where the pairs below come from. Each pair is an ACL rule and the grant
// the page says it converts to, in the page's own words: the same access, written two ways.
// The page was last validated on 13 March 2026; the copy these were taken from was read on
// 17 October 2026.
const vectorSource = "https://tailscale.com/docs/reference/migrate-acls-grants (Migrate from ACLs to grants)"

var equivalenceVectors = []struct {
	name string
	// section of the page the pair is taken from
	where string
	acls  string // the "acls" array
	grant string // the "grants" array
}{
	{
		"one destination, one port, a protocol", "Basic migration patterns",
		`[{"action": "accept", "src": ["group:eng"], "dst": ["tag:web-server:443"], "proto": "tcp"}]`,
		`[{"src": ["group:eng"], "dst": ["tag:web-server"], "ip": ["tcp:443"]}]`,
	},
	{
		"no protocol, no prefix", "Basic migration patterns (the tip)",
		`[{"action": "accept", "src": ["group:eng"], "dst": ["tag:web-server:443"]}]`,
		`[{"src": ["group:eng"], "dst": ["tag:web-server"], "ip": ["443"]}]`,
	},
	{
		"several ports of one destination", "Basic migration patterns",
		`[{"action": "accept", "src": ["group:eng"], "dst": ["tag:web-server:80", "tag:web-server:22"]}]`,
		`[{"src": ["group:eng"], "dst": ["tag:web-server"], "ip": ["80", "22"]}]`,
	},
	{
		"two tags with different ports become two grants", "Basic migration patterns",
		`[{"action": "accept", "src": ["group:eng"], "dst": ["tag:web-server:80", "tag:dev-server:22"]}]`,
		`[{"src": ["group:eng"], "dst": ["tag:web-server"], "ip": ["80"]}, {"src": ["group:eng"], "dst": ["tag:dev-server"], "ip": ["22"]}]`,
	},
	{
		"every port", "Wildcards",
		`[{"action": "accept", "src": ["group:prod"], "dst": ["tag:database:*"]}]`,
		`[{"src": ["group:prod"], "dst": ["tag:database"], "ip": ["*"]}]`,
	},
	{
		"a CIDR range with a protocol written as an array", "IP address ranges and CIDR notations",
		`[{"action": "accept", "src": ["group:devops"], "dst": ["192.0.2.0/24:22"], "proto": ["tcp"]}]`,
		`[{"src": ["group:devops"], "dst": ["192.0.2.0/24"], "ip": ["tcp:22"]}]`,
	},
	{
		"autogroups", "Autogroups",
		`[{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}]`,
		`[{"src": ["autogroup:member"], "dst": ["autogroup:self"], "ip": ["*"]}]`,
	},
	{
		"a posture is copied", "Manually convert ACLs to grants (step 5)",
		`[{"action": "accept", "src": ["group:eng"], "dst": ["tag:web-server:443"], "srcPosture": ["posture:managed"]}]`,
		`[{"src": ["group:eng"], "dst": ["tag:web-server"], "ip": ["443"], "srcPosture": ["posture:managed"]}]`,
	},
	{
		"a protocol joins each port", "Manually convert ACLs to grants (step 4.3)",
		`[{"action": "accept", "src": ["group:eng"], "dst": ["tag:web-server:80", "tag:web-server:443"], "proto": "tcp"}]`,
		`[{"src": ["group:eng"], "dst": ["tag:web-server"], "ip": ["tcp:80", "tcp:443"]}]`,
	},
}

// Each pair is equal under the normal form, whichever way round and however it is mixed
// with other rules.
func TestAclToGrantVectorsAreEqual(t *testing.T) {
	for _, v := range equivalenceVectors {
		same(t, v.name+" ("+v.where+")", `{"acls": `+v.acls+`}`, `{"grants": `+v.grant+`}`)
		same(t, v.name+", beside another rule", `{"acls": `+v.acls+`, "grants": [{"src": ["x"], "dst": ["y"], "ip": ["1"]}]}`,
			`{"grants": [{"src": ["x"], "dst": ["y"], "ip": ["1"]}, `+v.grant[1:]+`}`)
	}
	if vectorSource == "" || len(equivalenceVectors) < 9 {
		t.Error("the vectors lost their source or their count")
	}
}

// The page warns that one grant for two tags with different ports is a different outcome:
// it would allow both ports on both tags.
func TestTheMergedGrantTheManualWarnsAboutIsNotEqual(t *testing.T) {
	differ(t, "the merged grant (Basic migration patterns)",
		`{"acls": [{"action": "accept", "src": ["group:eng"], "dst": ["tag:web-server:80", "tag:dev-server:22"]}]}`,
		`{"grants": [{"src": ["group:eng"], "dst": ["tag:web-server", "tag:dev-server"], "ip": ["80", "22"]}]}`)
}

// Each vector with one thing changed is not equal: the vectors are not satisfied by a
// normal form that ignores the field.
func TestEachVectorWithOneFieldChangedIsNotEqual(t *testing.T) {
	for _, v := range equivalenceVectors {
		base := `{"acls": ` + v.acls + `}`
		for name, other := range map[string]string{
			"another source": `{"grants": ` + replaceOnce(v.grant, `"src": [`, `"src": ["group:other", `) + `}`,
			"a protocol":     `{"grants": ` + replaceOnce(v.grant, `"ip": [`, `"ip": ["udp:31337", `) + `}`,
			"a destination":  `{"grants": ` + replaceOnce(v.grant, `"dst": [`, `"dst": ["tag:other", `) + `}`,
		} {
			differ(t, v.name+": "+name, base, other)
		}
	}
}
