package tools

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestSplitDestinationReadsEveryFormACarrierCanTake(t *testing.T) {
	ok := []struct{ in, host, port string }{
		{"tag:prod:22", "tag:prod", "22"},
		{"svc:db:443", "svc:db", "443"},
		{"100.64.0.5:443", "100.64.0.5", "443"},
		{"[fd7a:115c:a1e0::5]:22", "[fd7a:115c:a1e0::5]", "22"},
		{"p:abcdefghij:22", "p:abcdefghij", "22"},
		{"[p:abcdefghij]:22", "[p:abcdefghij]", "22"},
		{"a…@example.com [p:abcdefghij]:22", "a…@example.com [p:abcdefghij]", "22"},
		{"group:finance team@example.com:443", "group:finance team@example.com", "443"},
	}
	for _, c := range ok {
		host, port, err := splitDestination(c.in)
		if err != nil || host != c.host || port != c.port {
			t.Errorf("splitDestination(%q) = %q, %q, %v; want %q, %q", c.in, host, port, err, c.host, c.port)
		}
		if err := checkTestDestination("accept[0]", c.in); err != nil {
			t.Errorf("checkTestDestination(%q) = %v", c.in, err)
		}
	}
	bad := []string{
		"tag:prod",
		"tag:prod:70000",
		":22",
		"fd7a:115c:a1e0::5:22",
		"[p:abcdefghij extra]:22",
	}
	for _, in := range bad {
		if _, _, err := splitDestination(in); err == nil {
			t.Errorf("splitDestination(%q) succeeded, want an error", in)
		}
	}
}

func TestASourceMayHoldSpacesForASyncedGroup(t *testing.T) {
	if err := checkTestSrc("group:finance team@example.com"); err != nil {
		t.Errorf("a synced group with a space: %v", err)
	}
	for _, src := range []string{" tag:ci", "tag:ci ", " ", ""} {
		if err := checkTestSrc(src); err == nil {
			t.Errorf("checkTestSrc(%q) was accepted", src)
		}
	}
	if _, _, err := splitDestination("tag:prod:070"); err == nil {
		t.Error("a leading-zero port was accepted")
	}
	if _, _, err := splitDestination("tag:prod:+22"); err == nil {
		t.Error("a signed port was accepted")
	}
	if _, _, err := splitDestination("tag:prod:65536"); err == nil {
		t.Error("port 65536 was accepted")
	}
	if _, _, err := splitDestination("100.64.0.0/10:22"); err == nil {
		t.Error("a CIDR destination was accepted")
	}
	if err := checkTestSrc(strings.Repeat("a", maxTestValue+1)); err == nil {
		t.Error("an overlong src was accepted")
	}
	if err := checkPostureAttrs(map[string]any{"node:os": math.Inf(1)}); err == nil {
		t.Error("+Inf was accepted")
	}
	if err := checkPostureAttrs(map[string]any{"node:os": "a\nb"}); err == nil {
		t.Error("a posture value with a control character was accepted")
	}
}

func TestSlashControlCharactersAndWildcardsAreStillRefused(t *testing.T) {
	for _, src := range []string{"100.64.0.0/10", "group:eng\t@example.com", "*", "tag:prod*"} {
		if err := checkTestSrc(src); err == nil {
			t.Errorf("checkTestSrc(%q) succeeded, want a refusal", src)
		}
	}
}

func TestACredentialShapeInASubjectIsRefusedIncludingADecodedEscape(t *testing.T) {
	// The backslash is a rune so no tool turns the escape into the character.
	bs := string(rune(92))
	raw := "tskey-api-x"
	escaped := "tskey" + bs + "u002dapi-x"
	for _, src := range []string{raw, escaped} {
		err := checkTestSrc(src)
		if err == nil || !strings.Contains(err.Error(), "shaped like a credential") {
			t.Errorf("checkTestSrc(%q) = %v", src, err)
		}
		if err != nil && (strings.Contains(err.Error(), "tskey") || strings.Contains(err.Error(), "u002d")) {
			t.Errorf("the refusal repeats the text: %v", err)
		}
	}
	one := []ACLSSHTestInput{{Dst: []string{"tag:" + raw}, Accept: []string{"root"}}}
	if err := checkSSHTests("tag:web", one); err == nil || strings.Contains(err.Error(), "tskey") {
		t.Errorf("SSH destination: %v", err)
	}
	if err := checkPostureAttrs(map[string]any{"node:os": escaped}); err == nil || strings.Contains(err.Error(), "u002d") {
		t.Errorf("posture value: %v", err)
	}
}

func TestAMaskedValueEndingInAPseudonymIsAcceptedAsASource(t *testing.T) {
	for _, src := range []string{
		"p:abcdefghij",
		"[p:abcdefghij]",
		"a…@example.com [p:abcdefghij]",
	} {
		if err := checkTestSrc(src); err != nil {
			t.Errorf("checkTestSrc(%q): %v", src, err)
		}
	}
	if err := checkTestSrc("a…@example.com"); err == nil {
		t.Error("a masked value with no pseudonym was accepted")
	}
}

func TestPostureAttributesAcceptStringNumberAndBoolAndNothingElse(t *testing.T) {
	ok := map[string]any{
		"node:os": "macos", "node:tsVersion": "1.80", "node:tsReleaseTrack": "stable",
		"node:osVersion": "15", "node:tsAutoUpdate": true, "node:n": json.Number("1"),
	}
	if err := checkPostureAttrs(ok); err != nil {
		t.Fatalf("accepted values: %v", err)
	}
	if err := checkPostureAttrs(nil); err != nil {
		t.Fatalf("no attributes: %v", err)
	}
	long := map[string]any{"node:os": strings.Repeat("a", maxPostureValue+1)}
	nested := map[string]any{"node:os": map[string]any{"a": "b"}}
	list := map[string]any{"node:os": []any{"macos"}}
	null := map[string]any{"node:os": nil}
	nan := map[string]any{"node:os": math.NaN()}
	many := map[string]any{}
	for i := 0; i < maxPostureAttrs+1; i++ {
		many[fmt.Sprintf("node:k%d", i)] = true
	}
	badKey := map[string]any{"Node:tsVersion": "1"}
	for name, attrs := range map[string]map[string]any{
		"a nested object":   nested,
		"a list":            list,
		"null":              null,
		"a NaN":             nan,
		"a 17th key":        many,
		"a long string":     long,
		"an upper-case key": badKey,
	} {
		if err := checkPostureAttrs(attrs); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestSSHTestsRefuseAnAutogroupSourceAndNoteAGroupSource(t *testing.T) {
	one := []ACLSSHTestInput{{Dst: []string{"tag:db"}, Accept: []string{"root"}}}
	if err := checkSSHTests("autogroup:member", one); err == nil || !strings.Contains(err.Error(), "14102") {
		t.Errorf("autogroup source: %v", err)
	}
	if err := checkSSHTests("group:eng@example.com", one); err != nil {
		t.Errorf("group source: %v", err)
	}
	note := sshSrcNote("group:eng@example.com")
	if note == "" || !strings.Contains(note, "11790") {
		t.Errorf("sshSrcNote(group) = %q", note)
	}
	if sshSrcNote("tag:web") != "" {
		t.Errorf("sshSrcNote(tag) = %q, want empty", sshSrcNote("tag:web"))
	}
}

func TestSSHTestsNeedADestinationAndAUserList(t *testing.T) {
	if err := checkSSHTests("tag:web", []ACLSSHTestInput{{Accept: []string{"root"}}}); err == nil {
		t.Error("a test with no destination was accepted")
	}
	if err := checkSSHTests("tag:web", []ACLSSHTestInput{{Dst: []string{"tag:db"}}}); err == nil {
		t.Error("a test with no user list was accepted")
	}
	if err := checkSSHTests("tag:web", []ACLSSHTestInput{{Dst: []string{"tag:*"}, Accept: []string{"root"}}}); err == nil {
		t.Error("a wildcard destination was accepted")
	}
	many := make([]ACLSSHTestInput, maxSSHTests+1)
	for i := range many {
		many[i] = ACLSSHTestInput{Dst: []string{"tag:db"}, Deny: []string{"root"}}
	}
	if err := checkSSHTests("tag:web", many); err == nil {
		t.Error("9 SSH tests were accepted")
	}
	wide := ACLSSHTestInput{Accept: []string{"root"}}
	for i := 0; i < maxDestinations+1; i++ {
		wide.Dst = append(wide.Dst, "tag:db")
	}
	if err := checkSSHTests("tag:web", []ACLSSHTestInput{wide}); err == nil {
		t.Error("33 destinations were accepted")
	}
	if err := checkSSHTests("tag:web", []ACLSSHTestInput{{Dst: []string{"100.64.0.5"}, Check: []string{"admin"}}}); err != nil {
		t.Errorf("a check user: %v", err)
	}
	// The users of one test are bounded across the three lists, so that destinations times
	// users stays a result a host can read.
	users := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("user%d", i)
		}
		return out
	}
	if err := checkSSHTests("tag:web", []ACLSSHTestInput{{Dst: []string{"tag:db"}, Accept: users(maxSSHUsers)}}); err != nil {
		t.Errorf("%d users: %v", maxSSHUsers, err)
	}
	for _, c := range []ACLSSHTestInput{
		{Dst: []string{"tag:db"}, Accept: users(maxSSHUsers + 1)},
		{Dst: []string{"tag:db"}, Accept: users(maxSSHUsers), Deny: users(1)},
		{Dst: []string{"tag:db"}, Accept: users(6), Check: users(6), Deny: users(5)},
		{Dst: []string{"tag:db"}, Deny: users(3000)},
	} {
		if err := checkSSHTests("tag:web", []ACLSSHTestInput{c}); err == nil || !strings.Contains(err.Error(), "SSH users per SSH test") {
			t.Errorf("%d users were accepted: %v", len(c.Accept)+len(c.Check)+len(c.Deny), err)
		}
	}
	for _, c := range []ACLSSHTestInput{
		{Dst: []string{""}, Accept: []string{"root"}},
		{Dst: []string{"tag:db"}, Accept: []string{""}},
		{Dst: []string{"tag:db"}, Accept: []string{"…"}},
		{Dst: []string{"tag:db"}, Accept: []string{strings.Repeat("a", maxTestValue+1)}},
		{Dst: []string{"tag:db"}, Accept: []string{"ro\not"}},
		{Dst: []string{"192.0.2.0/24"}, Accept: []string{"root"}},
		{Dst: []string{"tag:db:22"}, Accept: []string{"root"}},
	} {
		if err := checkSSHTests("tag:web", []ACLSSHTestInput{c}); err == nil {
			t.Errorf("SSH value %+v was accepted", c)
		}
	}
	for _, src := range []string{" autogroup:member", "AUTOGROUP:member", " autogroup:member "} {
		if err := checkSSHTests(src, []ACLSSHTestInput{{Dst: []string{"tag:db"}, Accept: []string{"root"}}}); err == nil || !strings.Contains(err.Error(), "14102") {
			t.Errorf("checkSSHTests(%q) = %v", src, err)
		}
	}
}

// A posture attribute name starts with a lower-case letter and holds letters, digits and the
// separators : . - _. Tailscale's own names mix cases (node:tsVersion), a custom one has an
// underscore or a hyphen, and nothing that could start a sentence, a path or an address is a
// name.
func TestPostureAttributeNamesTakeTheShapesTailscaleUsesAndNothingElse(t *testing.T) {
	for _, k := range []string{"node:tsVersion", "node:os", "node:tsReleaseTrack", "custom:my_attr", "node:ts-version", "a", "a.b_c-d:e", "custom:a:b", strings.Repeat("a", 256)} {
		if err := checkPostureAttrs(map[string]any{k: "x"}); err != nil {
			t.Errorf("%q: %v", k, err)
		}
	}
	for _, k := range []string{"", "Node:os", ":os", "1abc", "-a", "a b", "a/b", "a@b", "a\nb", "a…", "a,b", strings.Repeat("a", 257)} {
		if err := checkPostureAttrs(map[string]any{k: "x"}); err == nil {
			t.Errorf("%q was accepted", k)
		}
	}
}
