package tools_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/guard"
	"github.com/abm9111/tailkeeper/internal/mcpserver"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

const dnsBody = `{"nameservers":[{"address":"192.0.2.53"}],"searchPaths":["example.com"],"preferences":{"magicDNS":true,"overrideLocalDNS":true}}`

func dnsCall(t *testing.T, env *registry.Env, reg *registry.Registry) (tools.DNSOutput, string) {
	t.Helper()
	var out tools.DNSOutput
	s := mustCall(t, reg, env, "dns_get", `{}`, &out)
	return out, s
}

func serveDNS(f *apitest.Fake, policy string) {
	f.JSON("GET", tailnetPath+"/dns/configuration", 200, dnsBody)
	if policy != "" {
		servePolicy(f, policy, `"e1"`)
	}
}

func TestTheDNSPolicyFixtureKeepsItsBytes(t *testing.T) {
	b, err := os.ReadFile("testdata/policies/dns.hujson")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "\r") || len(b) != 726 {
		t.Fatalf("the fixture is %d bytes and holds %q", len(b), string(b))
	}
	sum := sha256.Sum256(b)
	const want = "d46b30306cd28be5987d0d3b0330a068415448430aabd19a9faa257fecd8f89a"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Errorf("sha256 = %s, want %s", got, want)
	}
}

func TestDNSGetReadsExtraDNSRecordsAndSaysWhenTheyTakeEffect(t *testing.T) {
	b, err := os.ReadFile("testdata/policies/dns.hujson")
	if err != nil {
		t.Fatal(err)
	}
	f, reg, env := apiEnv(t)
	serveDNS(f, string(b))
	out, s := dnsCall(t, env, reg)
	if !out.PolicyOverridesAnalysed || out.PolicyNote != "" {
		t.Fatalf("analysed %v note %q", out.PolicyOverridesAnalysed, out.PolicyNote)
	}
	if len(out.ExtraRecords) != 2 || out.ExtraRecords[0].Type != "A" || out.ExtraRecords[0].Value != "192.0.2.10" || out.ExtraRecords[1].Type != "" || out.ExtraRecords[1].Value != "2001:db8::10" {
		t.Fatalf("records = %+v", out.ExtraRecords)
	}
	if strings.Join(out.ExtraRecordsEffectiveIf, ",") != "overrideLocalDNS,alphaEnabled" {
		t.Fatalf("effectiveIf = %v", out.ExtraRecordsEffectiveIf)
	}
	if out.OverrideLocalDNS == nil || !*out.OverrideLocalDNS || !strings.Contains(s, `"overrideLocalDns":true`) {
		t.Fatalf("the API's overrideLocalDns is not beside the conditions: %s", s)
	}
	if len(out.Nameservers) != 1 || out.Nameservers[0].Address != "192.0.2.53" {
		t.Fatalf("nameservers = %+v", out.Nameservers)
	}
}

func TestDNSGetListsNextDNSAndControlDAttributesAndMasksTheIdentifiersWhole(t *testing.T) {
	const shortID, longID = "abc123", "abc123xyzXYZ"
	policy := func(id, login string) string {
		return `{"nodeAttrs":[{"target":["` + login + `"],"attr":["nextdns:` + id + `","nextdns:no-device-info","controld:def456?priority=7"]}]}`
	}
	f, reg, env := apiEnv(t)
	serveDNS(f, policy(shortID, "amy@example.com"))
	out, s := dnsCall(t, env, reg)
	if len(out.NextDNS) != 1 || out.NextDNS[0].ID == shortID || !out.NextDNS[0].NoDeviceInfo || strings.Join(out.NextDNS[0].Targets, ",") != "a…@example.com" {
		t.Fatalf("nextdns = %+v in %s", out.NextDNS, s)
	}
	if !strings.Contains(out.NextDNS[0].ID, "…") || strings.Contains(s, shortID) {
		t.Fatalf("the profile id is not masked whole: %s", s)
	}
	if len(out.ControlD) != 1 || out.ControlD[0].Priority == nil || *out.ControlD[0].Priority != 7 || strings.Contains(s, "def456") {
		t.Fatalf("controlD = %+v in %s", out.ControlD, s)
	}
	key, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		t.Fatal(err)
	}
	env.Privacy = key
	_, keyed := dnsCall(t, env, reg)
	if strings.Contains(keyed, shortID) || strings.Contains(keyed, "def456") || !strings.Contains(keyed, "[p:") || !strings.Contains(keyed, "…") {
		t.Fatalf("with a key: %s", keyed)
	}
	_, shown := dnsCall(t, show(env), reg)
	if !strings.Contains(shown, shortID) || !strings.Contains(shown, "def456") || !strings.Contains(shown, "amy@example.com") {
		t.Fatalf("with personalData show: %s", shown)
	}
	// Two identifiers of different lengths, and two logins of different lengths, behind one masked form.
	results := map[string]string{}
	for _, c := range []struct{ id, login string }{{shortID, "amy@example.com"}, {longID, "alongnamepaddedout@example.com"}} {
		f, reg, env := apiEnv(t)
		serveDNS(f, policy(c.id, c.login))
		_, got := dnsCall(t, env, reg)
		results[c.id] = got
		if strings.Contains(got, c.id) || strings.Contains(got, strings.Split(c.login, "@")[0]) {
			t.Errorf("a raw identifier or login is in the result: %s", got)
		}
	}
	if results[shortID] != results[longID] {
		t.Errorf("the result tells the length of an identifier or a login:\n%s\n%s", results[shortID], results[longID])
	}
}

func TestSeveralNextDNSProfilesInOneListAreReportedWithPrecedenceUnknown(t *testing.T) {
	f, reg, env := apiEnv(t)
	serveDNS(f, `{"nodeAttrs":[{"target":["tag:a"],"attr":["nextdns:abc","nextdns:xyz"]}]}`)
	out, _ := dnsCall(t, env, reg)
	if len(out.NextDNS) != 2 || !strings.Contains(out.ResolverNote, "precedence unknown") {
		t.Fatalf("nextdns = %+v note %q", out.NextDNS, out.ResolverNote)
	}
}

func TestTargetsAreSelectorsAndTheOutputSaysItCannotNameDevices(t *testing.T) {
	f, reg, env := apiEnv(t)
	serveDNS(f, `{"nodeAttrs":[{"target":["tag:dns","*","group:eng"],"attr":["nextdns:abc"]}]}`)
	out, _ := dnsCall(t, env, reg)
	if len(out.NextDNS) != 1 || strings.Join(out.NextDNS[0].Targets, ",") != "tag:dns,*,group:eng" {
		t.Fatalf("targets = %+v", out.NextDNS)
	}
	if !strings.Contains(out.ResolverNote, "targets are selectors, not devices") {
		t.Fatalf("note = %q", out.ResolverNote)
	}
}

func TestTheSevenDNSNodeAttributesAreListedWithTheirTargets(t *testing.T) {
	b, err := os.ReadFile("testdata/policies/dns.hujson")
	if err != nil {
		t.Fatal(err)
	}
	f, reg, env := apiEnv(t)
	serveDNS(f, string(b))
	out, _ := dnsCall(t, env, reg)
	if len(out.DNSNodeAttrs) != 7 || out.AttrTableAsOf != "2026-10-17" {
		t.Fatalf("attrs %d as of %q", len(out.DNSNodeAttrs), out.AttrTableAsOf)
	}
	for i, want := range []string{"magicdns-aaaa", "dns-subdomain-resolve", "dns-forwarder-disable-tcp-retries", "disable-split-dns-when-no-custom-resolvers", "disable-local-dns-override-via-nrpt", "disable-hosts-file-updates", "force-register-magicdns-ipv4-only"} {
		if out.DNSNodeAttrs[i].Attr != want || strings.Join(out.DNSNodeAttrs[i].Targets, ",") != "tag:dns,*" {
			t.Errorf("[%d] = %+v, want %s", i, out.DNSNodeAttrs[i], want)
		}
	}
}

func TestOtherAttributesAreListedByNameWithNoDNSClaim(t *testing.T) {
	f, reg, env := apiEnv(t)
	serveDNS(f, `{"nodeAttrs":[{"target":["*"],"attr":["dns-lookalike","funnel","nextdns"]}]}`)
	out, _ := dnsCall(t, env, reg)
	if len(out.DNSNodeAttrs) != 0 || strings.Join(out.OtherAttrs, ",") != "dns-lookalike,funnel,nextdns" {
		t.Fatalf("dns = %+v other = %v", out.DNSNodeAttrs, out.OtherAttrs)
	}
	if strings.Contains(out.ResolverNote, "dns-lookalike") {
		t.Fatalf("the note claims a DNS meaning: %q", out.ResolverNote)
	}
}

func TestAnUnparsedProfileAttributeIsAFixedLabel(t *testing.T) {
	// The ids differ in length behind each label: the result must not tell.
	got := map[string]string{}
	for _, c := range []struct{ attr, key string }{
		{"controld:def456secret?priority=x", "short-c"},
		{"controld:def456secretwithalongerid?priority=x", "long-c"},
		{"nextdns:abc 123secret", "short-n"},
		{"nextdns:abc 123secretwithalongerid", "long-n"},
	} {
		f, reg, env := apiEnv(t)
		serveDNS(f, `{"nodeAttrs":[{"target":["*"],"attr":["`+c.attr+`"]}]}`)
		_, body := dnsCall(t, env, reg)
		if strings.Contains(body, "secret") || strings.Contains(body, "priority=x") {
			t.Errorf("%s shows the raw value: %s", c.attr, body)
		}
		got[c.key] = body
	}
	if got["short-c"] != got["long-c"] || got["short-n"] != got["long-n"] {
		t.Errorf("the result tells the length of an unparsed profile id")
	}
	f, reg, env := apiEnv(t)
	serveDNS(f, `{"nodeAttrs":[{"target":["*"],"attr":["nextdns:abc123","controld:def456?priority=7","controld:def456secret?priority=x","nextdns:abc 123secret"]}]}`)
	out, s := dnsCall(t, env, reg)
	if len(out.NextDNS) != 1 || len(out.ControlD) != 1 || out.ControlD[0].Priority == nil || *out.ControlD[0].Priority != 7 {
		t.Fatalf("parsed nextdns %+v controlD %+v", out.NextDNS, out.ControlD)
	}
	if strings.Join(out.OtherAttrs, ",") != "controld:(unparsed),nextdns:(unparsed)" {
		t.Fatalf("other = %v", out.OtherAttrs)
	}
	if strings.Contains(s, "def456secret") || strings.Contains(s, "123secret") || strings.Contains(s, "priority=x") {
		t.Fatalf("a raw profile value is in the result: %s", s)
	}
}

func TestAControlDPriorityIsAnUnsignedNumberOrTheAttributeIsUnparsed(t *testing.T) {
	f, reg, env := apiEnv(t)
	serveDNS(f, `{"nodeAttrs":[{"target":["*"],"attr":["controld:ok1?priority=0","controld:ok2?priority=12","controld:plus?priority=+3","controld:minus?priority=-5","controld:blank?priority=","controld:big?priority=99999999999999999999"]}]}`)
	out, s := dnsCall(t, env, reg)
	if len(out.ControlD) != 2 || *out.ControlD[0].Priority != 0 || *out.ControlD[1].Priority != 12 {
		t.Fatalf("controlD = %+v in %s", out.ControlD, s)
	}
	if strings.Join(out.OtherAttrs, ",") != "controld:(unparsed)" {
		t.Fatalf("other = %v in %s", out.OtherAttrs, s)
	}
	for _, raw := range []string{"plus", "minus", "blank", "big"} {
		if strings.Contains(s, raw) {
			t.Errorf("the id %q of an unparsed attribute is in the result: %s", raw, s)
		}
	}
}

func TestWithoutPolicyFileReadDNSGetAnswersAndSaysWhy(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/dns/configuration", 200, dnsBody)
	f.JSON("GET", tailnetPath+"/acl", 403, `{"message":"forbidden"}`)
	out, s := dnsCall(t, env, reg)
	if out.PolicyOverridesAnalysed || !strings.Contains(out.PolicyNote, "policy_file:read") || len(out.Nameservers) != 1 || out.Nameservers[0].Address != "192.0.2.53" {
		t.Fatalf("out = %+v\n%s", out, s)
	}
	if len(out.ExtraRecords) != 0 || len(out.NextDNS) != 0 {
		t.Fatalf("a refused policy still contributed fields: %+v", out)
	}
	n := 0
	for _, r := range f.Requests() {
		if strings.HasSuffix(r.Path, "/acl") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d policy reads, want one", n)
	}
}

func TestAPolicyTheGuardsRefuseLeavesTheAPIHalfAndANote(t *testing.T) {
	// A million levels, in a child: the guard must refuse it before the parser recurses.
	cmd := exec.Command(os.Args[0], "-test.run=^TestDNSGetDepthChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), "TAILKEEPER_DNS_DEPTH_CHILD=1")
	child, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(child), "DEPTH-OK dns_get") {
		t.Fatalf("a million levels: %v\n%s", err, tailOf(string(child), 1500))
	}
	over := strings.Repeat("a", guard.MaxPolicyBytes+1)
	notJSON := `{`
	for _, c := range []struct{ name, policy, note string }{
		{"over the cap", over, "over the size cap"},
		{"not HuJSON", notJSON, "not a policy"},
	} {
		f, reg, env := apiEnv(t)
		serveDNS(f, c.policy)
		out, s := dnsCall(t, env, reg)
		if out.PolicyOverridesAnalysed || !strings.Contains(out.PolicyNote, c.note) || len(out.Nameservers) != 1 {
			t.Errorf("%s: %+v\n%s", c.name, out, s)
		}
		if strings.Contains(s, strconv.Itoa(guard.MaxPolicyBytes+1)) {
			t.Errorf("%s: the result holds the size of the text", c.name)
		}
	}
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/dns/configuration", 200, dnsBody)
	f.JSON("GET", tailnetPath+"/acl", 500, `{"message":"boom"}`)
	out, _ := dnsCall(t, env, reg)
	if out.PolicyOverridesAnalysed || out.PolicyNote != "the policy was not read" || len(out.Nameservers) != 1 {
		t.Fatalf("a read error: %+v", out)
	}
}

func TestExtraRecordsAreCappedAtOneHundredAndSaySo(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"extraDNSRecords":[`)
	for i := 0; i < 101; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"Name":"n%d.example.com","Type":"A","Value":"192.0.2.10"}`, i)
	}
	b.WriteString(`]}`)
	f, reg, env := apiEnv(t)
	serveDNS(f, b.String())
	out, s := dnsCall(t, env, reg)
	if len(out.ExtraRecords) != 100 || !out.Truncated || !out.PolicyOverridesAnalysed {
		t.Fatalf("records %d truncated %v analysed %v", len(out.ExtraRecords), out.Truncated, out.PolicyOverridesAnalysed)
	}
	if strings.Contains(s, "n100.example.com") || out.ExtraRecords[0].Name != "n0.example.com" || out.ExtraRecords[99].Name != "n99.example.com" {
		t.Fatalf("the cap did not keep the first 100: %s", s)
	}
	if strings.Join(out.ExtraRecordsEffectiveIf, ",") != "overrideLocalDNS,alphaEnabled" {
		t.Fatalf("effectiveIf = %v", out.ExtraRecordsEffectiveIf)
	}
}

func TestDNSGetFixedSentencesComeFromTheirClosedLists(t *testing.T) {
	for _, c := range []struct{ policy, note string }{
		{`{}`, ""},
		{`{"extraDNSRecords":[{"Name":"a.example.com","Type":"A","Value":"192.0.2.1"}]}`, ""},
		{`{"nodeAttrs":[{"target":["tag:a","amy@example.com"],"attr":["nextdns:abc","nextdns:xyz","dns-lookalike"]}]}`, ""},
		{`not a policy`, "not a policy"},
		{`{"extraDNSRecords":{}}`, "not a list"},
		{`{"nodeAttrs":{"target":["*"]}}`, "not a list"},
	} {
		f, reg, env := apiEnv(t)
		serveDNS(f, c.policy)
		out, _ := dnsCall(t, env, reg)
		if bad := closedViolations(reflect.ValueOf(out), aclClosedLists); len(bad) > 0 {
			t.Errorf("%s: %v", c.policy, bad)
		}
		if c.note != "" && !strings.Contains(out.PolicyNote, c.note) {
			t.Errorf("note %q, want %q", out.PolicyNote, c.note)
		}
	}
}

func TestAnExtraRecordsValueAndTypeShowNoLoginAndNoLengthOfOne(t *testing.T) {
	bodies := map[string]string{}
	for _, login := range []string{"amy@example.com", "alongnamepaddedout@example.com"} {
		f, reg, env := apiEnv(t)
		serveDNS(f, `{"extraDNSRecords":[{"Name":"x.example.com","Type":"TXT","Value":"v=spf1 `+login+`"},{"Name":"y.example.com","Type":"`+login+`","Value":"192.0.2.1"}]}`)
		out, s := dnsCall(t, env, reg)
		if len(out.ExtraRecords) != 2 {
			t.Fatalf("records = %+v", out.ExtraRecords)
		}
		if strings.Contains(s, strings.Split(login, "@")[0]) {
			t.Errorf("a login is in the result: %s", s)
		}
		if !strings.Contains(out.ExtraRecords[0].Value, "…@example.com") || !strings.Contains(out.ExtraRecords[1].Type, "…@example.com") {
			t.Errorf("the value and the type are not masked: %+v", out.ExtraRecords)
		}
		bodies[login] = s
	}
	if bodies["amy@example.com"] != bodies["alongnamepaddedout@example.com"] {
		t.Errorf("the result tells the length of a login:\n%s\n%s", bodies["amy@example.com"], bodies["alongnamepaddedout@example.com"])
	}
}

func TestAnExtraRecordsTypeIsCutLikeEveryOtherNameOfThePolicy(t *testing.T) {
	f, reg, env := apiEnv(t)
	serveDNS(f, `{"extraDNSRecords":[{"Name":"x.example.com","Type":"`+strings.Repeat("T", 600)+`","Value":"192.0.2.1"}]}`)
	out, _ := dnsCall(t, env, reg)
	if len(out.ExtraRecords) != 1 {
		t.Fatalf("records = %+v", out.ExtraRecords)
	}
	if got := len(out.ExtraRecords[0].Type); got > 256+len("…") {
		t.Errorf("the type is %d bytes: it is not cut where a policy name is", got)
	}
}

func TestAnExtraRecordsValueIsCutLikeEveryOtherNameOfThePolicy(t *testing.T) {
	f, reg, env := apiEnv(t)
	serveDNS(f, `{"extraDNSRecords":[{"Name":"x.example.com","Type":"TXT","Value":"`+strings.Repeat("V", 600)+`"}]}`)
	out, _ := dnsCall(t, env, reg)
	if len(out.ExtraRecords) != 1 {
		t.Fatalf("records = %+v", out.ExtraRecords)
	}
	if got := len(out.ExtraRecords[0].Value); got > 256+len("…") {
		t.Errorf("the value is %d bytes: it is not cut where a policy name is", got)
	}
}

// dnsAttrPolicy is a policy with one nodeAttrs entry for the targets and attributes given.
func dnsAttrPolicy(targets, attrs []string) string {
	q := func(in []string) string {
		out := make([]string, len(in))
		for i, s := range in {
			out[i] = strconv.Quote(s)
		}
		return strings.Join(out, ",")
	}
	return `{"nodeAttrs":[{"target":[` + q(targets) + `],"attr":[` + q(attrs) + `]}]}`
}

func manyDNS(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%03d", prefix, i)
	}
	return out
}

func TestEachListThatDNSGetDrawsFromThePolicyIsCappedAtOneHundredAndSaysSo(t *testing.T) {
	for _, c := range []struct {
		name   string
		policy func(n int) string
		count  func(tools.DNSOutput) int
	}{
		{"nextdns profiles", func(n int) string { return dnsAttrPolicy([]string{"*"}, manyDNS("nextdns:p", n)) },
			func(o tools.DNSOutput) int { return len(o.NextDNS) }},
		{"controld profiles", func(n int) string { return dnsAttrPolicy([]string{"*"}, manyDNS("controld:p", n)) },
			func(o tools.DNSOutput) int { return len(o.ControlD) }},
		{"targets of one entry", func(n int) string {
			return dnsAttrPolicy(manyDNS("tag:t", n), []string{"nextdns:abc"})
		}, func(o tools.DNSOutput) int {
			if len(o.NextDNS) != 1 {
				return -1
			}
			return len(o.NextDNS[0].Targets)
		}},
		{"targets of one DNS node attribute", func(n int) string {
			return dnsAttrPolicy(manyDNS("tag:t", n), []string{"magicdns-aaaa"})
		}, func(o tools.DNSOutput) int {
			if len(o.DNSNodeAttrs) != 1 {
				return -1
			}
			return len(o.DNSNodeAttrs[0].Targets)
		}},
		{"other attributes", func(n int) string { return dnsAttrPolicy([]string{"*"}, manyDNS("other-", n)) },
			func(o tools.DNSOutput) int { return len(o.OtherAttrs) }},
	} {
		f, reg, env := apiEnv(t)
		serveDNS(f, c.policy(100))
		out, _ := dnsCall(t, env, reg)
		if got := c.count(out); got != 100 || out.Truncated || !out.PolicyOverridesAnalysed {
			t.Errorf("%s: 100 entries gave %d, truncated %v, analysed %v", c.name, got, out.Truncated, out.PolicyOverridesAnalysed)
		}
		f, reg, env = apiEnv(t)
		serveDNS(f, c.policy(101))
		out, s := dnsCall(t, env, reg)
		if got := c.count(out); got != 100 || !out.Truncated || !out.PolicyOverridesAnalysed {
			t.Errorf("%s: 101 entries gave %d, truncated %v, analysed %v", c.name, got, out.Truncated, out.PolicyOverridesAnalysed)
		}
		if strings.Contains(s, "tag:t100") || strings.Contains(s, "other-100") {
			t.Errorf("%s: the cut did not keep the first 100: %s", c.name, s)
		}
	}
}

func TestADuplicateOtherAttributeDoesNotUseUpTheCap(t *testing.T) {
	attrs := append(manyDNS("other-", 100), manyDNS("other-", 100)...)
	f, reg, env := apiEnv(t)
	serveDNS(f, dnsAttrPolicy([]string{"*"}, attrs))
	out, _ := dnsCall(t, env, reg)
	if len(out.OtherAttrs) != 100 || out.Truncated {
		t.Fatalf("%d other attributes, truncated %v: a repeated name was counted twice", len(out.OtherAttrs), out.Truncated)
	}
}

func TestAPolicyPastTheValueBudgetLeavesTheAPIHalfAndTheComplexityNote(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"x":[`)
	b.WriteString(strings.Repeat("0,", 1<<19))
	b.WriteString(`0]}`)
	f, reg, env := apiEnv(t)
	serveDNS(f, b.String())
	out, s := dnsCall(t, env, reg)
	if out.PolicyOverridesAnalysed || out.PolicyNote != "the policy was not analysed: the text is past a work budget" || len(out.Nameservers) != 1 {
		t.Fatalf("%+v\n%s", out, s)
	}
}

func TestThePolicyEnginesRefusalsEachGetTheirOwnFixedSentence(t *testing.T) {
	over, err := acl.Standardize(context.Background(), []byte(strings.Repeat("a", guard.MaxPolicyBytes+1)))
	if err == nil || over != nil {
		t.Fatalf("a text over the cap was standardized: %v", err)
	}
	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"over the byte cap", err, "the policy was not analysed: the text is over the size cap"},
		{"past a budget", &acl.Error{Code: acl.CodeTooComplex, Message: "the policy holds more than 524288 values"}, "the policy was not analysed: the text is past a work budget"},
		{"nesting", &acl.Error{Code: acl.CodeInvalid, Message: "the text nests deeper than 1000 levels"}, "the policy was not analysed: the text nests too deeply"},
		{"another invalid text", &acl.Error{Code: acl.CodeInvalid, Message: "bad"}, "the policy was not analysed: the text is not a policy"},
		{"not an engine error", errors.New("amy@example.com"), "the policy was not analysed: the text is not a policy"},
	} {
		if got := tools.PolicyEngineNote(c.err); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestTheFieldsThatDNSGetAddsFromThePolicyAreDescribedInItsOutputSchema(t *testing.T) {
	tool, ok := newRegistry(t).Get("dns_get")
	if !ok {
		t.Fatal("dns_get is not registered")
	}
	schema, err := mcpserver.OutputSchema(tool)
	if err != nil {
		t.Fatal(err)
	}
	props, _ := schema["properties"].(map[string]any)
	for _, name := range []string{"policyOverridesAnalysed", "policyNote", "extraDnsRecordsEffectiveIf", "resolverNote", "attrTableAsOf", "truncated"} {
		field, _ := props[name].(map[string]any)
		if d, _ := field["description"].(string); d == "" {
			t.Errorf("the output field %s has no description", name)
		}
	}
}

// A record's value has its email addresses masked, and the tool says so where it says what is
// masked: the generated reference lists the field with those whose email addresses alone are
// masked, and the output schema of the field says it too.
func TestAnExtraRecordsValueIsListedAsHavingItsEmailAddressesMasked(t *testing.T) {
	tool, ok := newRegistry(t).Get("dns_get")
	if !ok {
		t.Fatal("dns_get is not registered")
	}
	const field = "extraDnsRecords[].value"
	if !stringsContain(tool.EmailFields, field) || stringsContain(tool.PlainFields, field) {
		t.Errorf("email fields %v, plain fields %v: want the value among the first and not the second", tool.EmailFields, tool.PlainFields)
	}
	schema, err := mcpserver.OutputSchema(tool)
	if err != nil {
		t.Fatal(err)
	}
	props, _ := schema["properties"].(map[string]any)
	items, _ := props["extraDnsRecords"].(map[string]any)["items"].(map[string]any)
	value, _ := items["properties"].(map[string]any)["value"].(map[string]any)
	if d, _ := value["description"].(string); !strings.Contains(d, "email addresses") || !strings.Contains(d, "masked") {
		t.Errorf("the value's description is %q, want it to say that its email addresses are masked", d)
	}
}
