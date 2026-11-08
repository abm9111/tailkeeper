package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// configuredIntent is an environment whose configuration names a file holding text.
func configuredIntent(t *testing.T, text string) *registry.Env {
	t.Helper()
	path := filepath.Join(t.TempDir(), "intent.hujson")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return &registry.Env{Config: &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: path}}}}
}

// adapt reads text with the checked loader and adapts it, as a scan does. The text must be a
// file the loader takes: the adapter's refusals are the subject here, not the loader's.
func adapt(t *testing.T, text string) (security.IntentSet, []intentRefusal) {
	t.Helper()
	set, problems, err := parseInvariants(context.Background(), text)
	if err != nil || len(problems) > 0 {
		t.Fatalf("the loader refused the fixture: %v %+v", err, problems)
	}
	digest, revision := intentDigest(shownEnv, []byte(text))
	out, refused, err := intentSetOf(context.Background(), set, digest, revision)
	if err != nil {
		t.Fatal(err)
	}
	return out, refused
}

// Every field of the policy's test syntax that the typed expectations hold is kept, whatever
// its case and whatever comments and trailing commas surround it, and the expectations are
// numbered by position.
func TestIntentAdapterKeepsEveryMappedField(t *testing.T) {
	const text = `// the owner's intent, synthetic
{
	"tests": [
		// a network test with every field
		{
			"src": "owner-one@example.com",
			"proto": "tcp",
			"srcPostureAttrs": {"node:os": "macos", "custom:level": 3, "custom:managed": true,},
			"accept": ["tag:db-one:5432", "198.51.100.7:443"],
			"deny": ["tag:vault-one:22"],
		},
		{"SRC": "group:ops-one", "Accept": ["tag:db-one:5432"], "DENY": []},
	],
	"sshTests": [
		{"src": "owner-two@example.com", "dst": ["tag:ssh-one", "tag:ssh-two"], "accept": ["root"], "deny": ["admin"], "check": ["ops"]},
		{"src": "tag:ci-one", "dst": ["tag:ssh-one"]},
	],
}
`
	got, refused := adapt(t, text)
	if len(refused) > 0 {
		t.Fatalf("refused: %+v", refused)
	}
	sum := sha256.Sum256([]byte(text))
	want := security.IntentSet{
		SchemaVersion: security.SchemaVersion, Digest: "sha256:" + hex.EncodeToString(sum[:]), Revision: hex.EncodeToString(sum[:])[:12],
		Network: []security.NetworkExpectation{
			{
				ID: "network-1", Source: "owner-one@example.com", Protocol: "tcp",
				SourcePostureAttributes: security.PostureAttributes{
					"node:os":        {Kind: security.ScalarString, String: "macos"},
					"custom:level":   {Kind: security.ScalarNumber, Number: "3"},
					"custom:managed": {Kind: security.ScalarBool, Bool: true},
				},
				Accept: []string{"tag:db-one:5432", "198.51.100.7:443"}, Deny: []string{"tag:vault-one:22"},
			},
			{ID: "network-2", Source: "group:ops-one", Accept: []string{"tag:db-one:5432"}},
		},
		SSH: []security.SSHExpectation{
			{ID: "ssh-1", Source: "owner-two@example.com", Destinations: []string{"tag:ssh-one", "tag:ssh-two"}, Accept: []string{"root"}, Deny: []string{"admin"}, Check: []string{"ops"}},
			{ID: "ssh-2", Source: "tag:ci-one", Destinations: []string{"tag:ssh-one"}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the adapted set differs\n got %+v\nwant %+v", got, want)
	}
	// The premise of the comparison above: between the two expectations of each kind, every
	// field the typed model has is exercised, so a field added to the model and not mapped
	// leaves the test red here instead of being dropped unseen.
	for _, c := range []struct {
		typ  reflect.Type
		vals []reflect.Value
	}{
		{reflect.TypeFor[security.NetworkExpectation](), []reflect.Value{reflect.ValueOf(got.Network[0]), reflect.ValueOf(got.Network[1])}},
		{reflect.TypeFor[security.SSHExpectation](), []reflect.Value{reflect.ValueOf(got.SSH[0]), reflect.ValueOf(got.SSH[1])}},
	} {
		for i := 0; i < c.typ.NumField(); i++ {
			used := false
			for _, v := range c.vals {
				used = used || !v.Field(i).IsZero()
			}
			if !used {
				t.Errorf("%s.%s is not exercised by the fixture: map it and add it to the file above", c.typ.Name(), c.typ.Field(i).Name)
			}
		}
	}
}

// Anything the adapter does not map is refused with its kind and its place, for each kind of
// expectation, and is never dropped: a file that would be read with a field silently missing
// would pass for an intent it does not state.
func TestIntentAdapterRefusesUnmappedField(t *testing.T) {
	for name, c := range map[string]struct {
		text    string
		section string
		kind    string
	}{
		// A field of the policy's syntax that no expectation holds, and one nobody knows.
		"network: another unmapped field": {`{"tests": [{"src": "a", "zz-unmapped": ["tag:x:1"]}]}`, "tests", refusedField},
		"network: an unknown field":       {`{"tests": [{"src": "a", "accept": ["tag:x:1"], "zz-extra": "v"}]}`, "tests", refusedField},
		"network: a field of ssh tests":   {`{"tests": [{"src": "a", "dst": ["tag:x"], "accept": ["tag:x:1"]}]}`, "tests", refusedField},
		"network: a field spelled twice":  {`{"tests": [{"src": "a", "SRC": "b"}]}`, "", ""}, // the loader refuses this one: case_collision
		"ssh: proto":                      {`{"sshTests": [{"src": "a", "dst": ["tag:x"], "proto": "tcp"}]}`, "sshTests", refusedField},
		"ssh: posture attributes":         {`{"sshTests": [{"src": "a", "dst": ["tag:x"], "srcPostureAttrs": {"a": "b"}}]}`, "sshTests", refusedField},
		"ssh: an unknown field":           {`{"sshTests": [{"src": "a", "dst": ["tag:x"], "user": "root"}]}`, "sshTests", refusedField},
		// A field that is mapped, of a shape the typed model does not hold.
		"network: src is a list":          {`{"tests": [{"src": ["a"], "accept": ["tag:x:1"]}]}`, "tests", refusedValue},
		"network: src is empty":           {`{"tests": [{"src": "", "accept": ["tag:x:1"]}]}`, "tests", refusedValue},
		"network: src is null":            {`{"tests": [{"src": null}]}`, "tests", refusedValue},
		"network: proto is a number":      {`{"tests": [{"src": "a", "proto": 6}]}`, "tests", refusedValue},
		"network: accept is a string":     {`{"tests": [{"src": "a", "accept": "tag:x:1"}]}`, "tests", refusedValue},
		"network: accept holds a number":  {`{"tests": [{"src": "a", "accept": [1]}]}`, "tests", refusedValue},
		"network: accept holds an empty":  {`{"tests": [{"src": "a", "accept": [""]}]}`, "tests", refusedValue},
		"network: deny is null":           {`{"tests": [{"src": "a", "deny": null}]}`, "tests", refusedValue},
		"network: posture is a list":      {`{"tests": [{"src": "a", "srcPostureAttrs": ["x"]}]}`, "tests", refusedValue},
		"network: posture is null":        {`{"tests": [{"src": "a", "srcPostureAttrs": null}]}`, "tests", refusedValue},
		"network: posture holds an array": {`{"tests": [{"src": "a", "srcPostureAttrs": {"k": [1]}}]}`, "tests", refusedValue},
		"network: posture holds null":     {`{"tests": [{"src": "a", "srcPostureAttrs": {"k": null}}]}`, "tests", refusedValue},
		"ssh: dst is a string":            {`{"sshTests": [{"src": "a", "dst": "tag:x"}]}`, "sshTests", refusedValue},
		"ssh: dst is empty":               {`{"sshTests": [{"src": "a", "dst": []}]}`, "sshTests", refusedValue},
		"ssh: check is a string":          {`{"sshTests": [{"src": "a", "dst": ["tag:x"], "check": "root"}]}`, "sshTests", refusedValue},
		"ssh: accept holds an object":     {`{"sshTests": [{"src": "a", "dst": ["tag:x"], "accept": [{}]}]}`, "sshTests", refusedValue},
		// A field every expectation needs.
		"network: no src": {`{"tests": [{"accept": ["tag:x:1"]}]}`, "tests", refusedMissing},
		"ssh: no src":     {`{"sshTests": [{"dst": ["tag:x"]}]}`, "sshTests", refusedMissing},
		"ssh: no dst":     {`{"sshTests": [{"src": "a", "accept": ["root"]}]}`, "sshTests", refusedMissing},
	} {
		if c.kind == "" {
			// Not the adapter's to refuse: the loader does, before the adapter is reached.
			if _, problems, err := parseInvariants(context.Background(), c.text); err != nil || len(problems) == 0 {
				t.Errorf("%s: the loader took %q (%v)", name, c.text, err)
			}
			continue
		}
		_, refused := adapt(t, c.text)
		if len(refused) == 0 {
			t.Errorf("%s: %s was adapted: a field was dropped or taken in a shape the model does not hold", name, c.text)
			continue
		}
		if r := refused[0]; r.Kind != c.kind || r.Section != c.section || r.Entry != 1 || r.At.Line != 1 || r.At.Column == 0 {
			t.Errorf("%s: refusal %+v, want %s in entry 1 of %s at line 1", name, r, c.kind, c.section)
		}
	}
}

// One refusal names its entry (the second of two) and where the entry starts in the file; the
// next entry, which is fine, is not in the way.
func TestIntentAdapterNamesTheEntryItRefuses(t *testing.T) {
	text := "{\n\t\"tests\": [\n\t\t{\"src\": \"a\", \"accept\": [\"tag:x:1\"]},\n\t\t{\"src\": \"b\", \"zz-unmapped\": [\"tag:x:1\"]},\n\t],\n}\n"
	_, refused := adapt(t, text)
	want := []intentRefusal{{Kind: refusedField, Section: "tests", Entry: 2, At: filePos{4, 3}}}
	if !reflect.DeepEqual(refused, want) {
		t.Errorf("refusals %+v, want %+v", refused, want)
	}
}

// A scan refuses an intent file by kind and place and quotes none of it: not the field it
// refused, not a value, not a login. The same holds for the file's own problems.
func TestIntentRefusalsQuoteNoWordOfTheFile(t *testing.T) {
	const field, value, login = "zq-secret-field", "zq-secret-value", "zq-secret-owner@example.com"
	for name, c := range map[string]struct {
		text   string
		kind   string
		origin intentOrigin
		code   tkerr.Code
	}{
		"an unmapped field": {`{"tests": [{"src": "` + login + `", "` + field + `": "` + value + `"}]}`, refusedField, intentCLI, tkerr.ValidationFailed},
		"a shape":           {`{"tests": [{"src": ["` + login + `"], "accept": ["` + value + `"]}]}`, refusedValue, intentCLI, tkerr.ValidationFailed},
		"another section":   {`{"` + field + `": [{"src": "` + login + `"}]}`, "structure", intentCLI, tkerr.ValidationFailed},
		"a syntax error":    {`{"tests": [{"src": "` + login + `" "` + value + `"}]}`, "syntax", intentCLI, tkerr.ValidationFailed},
		"a duplicate key":   {`{"tests": [{"src": "` + login + `", "src": "` + value + `"}]}`, "duplicate_key", intentCLI, tkerr.ValidationFailed},
		"a pseudonym":       {`{"tests": [{"src": "` + login + ` [p:abcdefghij]"}]}`, "structure", intentCLI, tkerr.ValidationFailed},
		"the configured":    {`{"tests": [{"src": "` + login + `", "` + field + `": "` + value + `"}]}`, refusedField, intentConfigured, tkerr.ConfigInvalid},
	} {
		in := SecurityScanInput{Scope: "local", Invariants: c.text, Operator: true}
		env := &registry.Env{}
		if c.origin == intentConfigured {
			in.Invariants = ""
			env = configuredIntent(t, c.text)
		}
		_, _, err := loadScanIntent(context.Background(), env, in)
		e, ok := tkerr.As(err)
		if !ok || e.Code != c.code {
			t.Errorf("%s: err = %v, want %s", name, err, c.code)
			continue
		}
		text := e.Message + " | " + e.Hint
		if !strings.HasSuffix(e.Message, "; no source was read") {
			t.Errorf("%s: the message does not end by saying no source was read: %q", name, e.Message)
		}
		if !strings.Contains(text, c.kind) {
			t.Errorf("%s: %q does not name the kind %s", name, text, c.kind)
		}
		for _, secret := range []string{field, value, login, "example.com"} {
			if strings.Contains(text, secret) {
				t.Errorf("%s: the error quotes %q: %q", name, secret, text)
			}
		}
	}
}

// Several refusals are listed up to five places and the rest counted. The bound is written out
// here and not read from the constant, so that changing the constant is noticed.
func TestIntentRefusalListsAreBounded(t *testing.T) {
	for _, c := range []struct {
		entries int
		more    string // what the message says of the rest; "" for nothing
	}{{1, ""}, {4, ""}, {5, ""}, {6, "; and 1 more"}, {8, "; and 3 more"}} {
		var b strings.Builder
		b.WriteString(`{"tests": [`)
		for i := 0; i < c.entries; i++ {
			b.WriteString(`{"src": "a", "zz-unmapped": ["tag:x:1"]},`)
		}
		b.WriteString(`]}`)
		_, _, err := loadScanIntent(context.Background(), &registry.Env{}, SecurityScanInput{Scope: "local", Invariants: b.String(), Operator: true})
		e, ok := tkerr.As(err)
		if !ok {
			t.Fatalf("%d entries: err = %v", c.entries, err)
		}
		if got, want := strings.Count(e.Message, refusedField), min(c.entries, 5); got != want {
			t.Errorf("%d entries: %d places named, want %d: %q", c.entries, got, want, e.Message)
		}
		wantEnd := c.more + "; no source was read"
		if !strings.HasSuffix(e.Message, wantEnd) || (c.more == "" && strings.Contains(e.Message, "more")) {
			t.Errorf("%d entries: the message ends %q, want it to end %q", c.entries, e.Message[max(0, len(e.Message)-40):], wantEnd)
		}
	}
}

// shownEnv shows personal data, so a digest in it is the plain one.
var shownEnv = &registry.Env{Config: &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}}

// The digest is of the exact bytes (a trailing newline, a comment and a byte order of the keys
// all change it) and follows the rule of the other digests of a policy: the plain SHA-256 only
// with personalData show, a keyed digest while masked with a privacy key, and none while masked
// with no key. The revision is the first twelve digits of whatever digest is shown.
func TestIntentDigestIsOfTheExactBytesAndFollowsTheRule(t *testing.T) {
	key, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		t.Fatal(err)
	}
	text, longer := []byte(`{"tests": []}`), []byte(`{"tests": []}`+"\n")
	sum := sha256.Sum256(text)
	plain := hex.EncodeToString(sum[:])
	a, ra := intentDigest(shownEnv, text)
	b, rb := intentDigest(shownEnv, longer)
	if a != "sha256:"+plain || a == b || ra != plain[:12] || rb != ShortDigest(b, 12) || len(ra) != 12 {
		t.Errorf("shown: digests %s %s, revisions %s %s", a, b, ra, rb)
	}
	keyedEnv := &registry.Env{Privacy: key}
	k, rk := intentDigest(keyedEnv, text)
	if k != key.Digest(text) || !strings.HasPrefix(k, "hmac-sha256:") || rk != strings.TrimPrefix(k, "hmac-sha256:")[:12] || rk == ra || strings.Contains(k, plain) {
		t.Errorf("keyed: digest %s, revision %s", k, rk)
	}
	// Personal data shown wins over a key, as it does for the policy version.
	if both := (&registry.Env{Privacy: key, Config: shownEnv.Config}); func() bool { d, _ := intentDigest(both, text); return d != a }() {
		t.Errorf("a key beside personalData show changed the digest")
	}
	for name, env := range map[string]*registry.Env{"masked, no key": {}, "no environment": nil} {
		if d, r := intentDigest(env, text); d != "" || r != "" {
			t.Errorf("%s: digest %q revision %q, want none", name, d, r)
		}
	}
}

// The spellings of a test that internal/acl reads as one thing are one thing to the adapter too:
// the deprecated allow is accept, and in a test (not an SSH test) the deprecated user is src. A
// file that `acl validate` takes must not be refused by a scan.
func TestIntentAdapterTakesTheSpellingsTheNormalFormReads(t *testing.T) {
	wantNet := func(e security.NetworkExpectation) security.IntentSet {
		e.ID = "network-1"
		return security.IntentSet{Network: []security.NetworkExpectation{e}}
	}
	wantSSH := func(e security.SSHExpectation) security.IntentSet {
		e.ID = "ssh-1"
		return security.IntentSet{SSH: []security.SSHExpectation{e}}
	}
	for name, c := range map[string]struct {
		text string
		want security.IntentSet
	}{
		"allow is accept":                         {`{"tests": [{"src": "a", "allow": ["tag:x:1"]}]}`, wantNet(security.NetworkExpectation{Source: "a", Accept: []string{"tag:x:1"}})},
		"allow in any case":                       {`{"tests": [{"src": "a", "ALLOW": ["tag:x:1"]}]}`, wantNet(security.NetworkExpectation{Source: "a", Accept: []string{"tag:x:1"}})},
		"user is src":                             {`{"tests": [{"user": "a", "accept": ["tag:x:1"]}]}`, wantNet(security.NetworkExpectation{Source: "a", Accept: []string{"tag:x:1"}})},
		"the legacy test, whole":                  {`{"tests": [{"User": "a", "allow": ["tag:x:1"], "deny": ["tag:y:2"], "proto": "tcp"}]}`, wantNet(security.NetworkExpectation{Source: "a", Protocol: "tcp", Accept: []string{"tag:x:1"}, Deny: []string{"tag:y:2"}})},
		"accept and allow together are both read": {`{"tests": [{"src": "a", "accept": ["tag:x:1"], "allow": ["tag:x:2"]}]}`, wantNet(security.NetworkExpectation{Source: "a", Accept: []string{"tag:x:1", "tag:x:2"}})},
		"allow beside accept, written first":      {`{"tests": [{"allow": ["tag:x:2"], "src": "a", "accept": ["tag:x:1"]}]}`, wantNet(security.NetworkExpectation{Source: "a", Accept: []string{"tag:x:1", "tag:x:2"}})},
		"allow in an ssh test":                    {`{"sshTests": [{"src": "a", "dst": ["tag:s"], "allow": ["root"], "check": ["ops"]}]}`, wantSSH(security.SSHExpectation{Source: "a", Destinations: []string{"tag:s"}, Accept: []string{"root"}, Check: []string{"ops"}})},
		"accept and allow in an ssh test":         {`{"sshTests": [{"src": "a", "dst": ["tag:s"], "accept": ["root"], "allow": ["admin"]}]}`, wantSSH(security.SSHExpectation{Source: "a", Destinations: []string{"tag:s"}, Accept: []string{"root", "admin"}})},
	} {
		got, refused := adapt(t, c.text)
		if len(refused) > 0 {
			t.Errorf("%s: refused %+v", name, refused)
			continue
		}
		got.SchemaVersion, got.Digest, got.Revision = 0, "", ""
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", name, got, c.want)
		}
	}
	// What the normal form does not read as an alias stays refused: user beside src is an
	// unread field there (the source is src), and user means nothing to an SSH test.
	for name, c := range map[string]struct{ text, section, kind string }{
		"user beside src":             {`{"tests": [{"src": "a", "user": "b", "accept": ["tag:x:1"]}]}`, "tests", refusedField},
		"user in an ssh test":         {`{"sshTests": [{"user": "a", "dst": ["tag:s"]}]}`, "sshTests", refusedField},
		"user beside src in ssh":      {`{"sshTests": [{"src": "a", "user": "b", "dst": ["tag:s"]}]}`, "sshTests", refusedField},
		"allow of the wrong shape":    {`{"tests": [{"src": "a", "allow": "tag:x:1"}]}`, "tests", refusedValue},
		"allow holding an empty":      {`{"tests": [{"src": "a", "allow": [""]}]}`, "tests", refusedValue},
		"user of the wrong shape":     {`{"tests": [{"user": ["a"], "accept": ["tag:x:1"]}]}`, "tests", refusedValue},
		"allow spelled twice by case": {`{"tests": [{"src": "a", "allow": ["x"], "ALLOW": ["y"]}]}`, "", ""}, // the loader refuses this one
	} {
		if c.kind == "" {
			if _, problems, err := parseInvariants(context.Background(), c.text); err != nil || len(problems) == 0 {
				t.Errorf("%s: the loader took %q (%v)", name, c.text, err)
			}
			continue
		}
		_, refused := adapt(t, c.text)
		if len(refused) == 0 || refused[0].Kind != c.kind || refused[0].Section != c.section {
			t.Errorf("%s: refusals %+v, want %s in %s", name, refused, c.kind, c.section)
		}
	}
}

// legacyIntentFile and currentIntentFile say the same thing in the deprecated and in the
// current spellings: user for src, allow for accept, and a test that gives accept and allow
// together, which the normal form reads as one list.
const legacyIntentFile = `{
	"tests": [
		{"user": "owner-one@example.com", "allow": ["tag:db-one:5432"], "deny": ["tag:vault-one:22"]},
		{"src": "tag:ci-one", "accept": ["tag:db-one:5432"], "allow": ["tag:db-one:6432"]},
	],
	"sshTests": [
		{"src": "tag:ci-one", "dst": ["tag:ssh-one"], "allow": ["root"], "check": ["ops"]},
	],
}
`

const currentIntentFile = `{
	"tests": [
		{"src": "owner-one@example.com", "accept": ["tag:db-one:5432"], "deny": ["tag:vault-one:22"]},
		{"src": "tag:ci-one", "accept": ["tag:db-one:5432", "tag:db-one:6432"]},
	],
	"sshTests": [
		{"src": "tag:ci-one", "dst": ["tag:ssh-one"], "accept": ["root"], "check": ["ops"]},
	],
}
`

// The same file in the legacy spellings gives the same expectations as in the current ones.
func TestLegacySpellingsGiveTheSameExpectationsAsTheCurrentOnes(t *testing.T) {
	legacy, refused := adapt(t, legacyIntentFile)
	if len(refused) > 0 {
		t.Fatalf("the legacy file was refused: %+v", refused)
	}
	current, refused := adapt(t, currentIntentFile)
	if len(refused) > 0 {
		t.Fatalf("the current file was refused: %+v", refused)
	}
	if !reflect.DeepEqual(legacy.Network, current.Network) || !reflect.DeepEqual(legacy.SSH, current.SSH) || len(current.Network) != 2 || len(current.SSH) != 1 {
		t.Errorf("legacy %+v\ncurrent %+v", legacy, current)
	}
}

// The adapter takes every key the normal form of internal/acl reads as a field of a test or of
// an SSH test, in every spelling the normal form gives it. A key that internal/acl learns to read
// and the adapter does not map leaves this test red, so that the owner decides whether it is
// mapped or refused, and a file that `acl validate` takes is not refused by the scan unseen.
func TestEveryKeyTheNormalFormReadsOfATestIsTakenByTheAdapter(t *testing.T) {
	value := map[string]string{
		"src": `"a"`, "dst": `["tag:s"]`, "proto": `"tcp"`, "srcPostureAttrs": `{"node:os": "macos"}`,
		"accept": `["x:1"]`, "deny": `["x:2"]`, "check": `["ops"]`,
	}
	for _, ssh := range []bool{false, true} {
		section := "tests"
		if ssh {
			section = "sshTests"
		}
		for field, spellings := range acl.PolicyTestKeys(ssh) {
			v, known := value[field]
			if !known {
				t.Errorf("%s: internal/acl reads %q as a field of a test and this test has no value for it: map it in the adapter, or refuse it, and say so here", section, field)
				continue
			}
			for _, spelling := range spellings {
				// A test needs a source (and an SSH test a destination), unless the field is it.
				members := []string{`"` + spelling + `": ` + v}
				if field != "src" {
					members = append(members, `"src": "a"`)
				}
				if ssh && field != "dst" {
					members = append(members, `"dst": ["tag:s"]`)
				}
				text := `{"` + section + `": [{` + strings.Join(members, ", ") + `}]}`
				if _, refused := adapt(t, text); len(refused) > 0 {
					t.Errorf("%s: %s is refused: %+v", section, text, refused)
				}
			}
		}
	}
}

// A field the normal form reads and the adapter does not map is refused, not dropped: the file
// would otherwise be taken for an intent it does not state. (No such field exists today, so the
// test takes one away from the adapter for its length.)
func TestAFieldTheNormalFormReadsAndTheAdapterDoesNotMapIsRefused(t *testing.T) {
	typ, had := fieldTypes["check"]
	if !had {
		t.Fatal("the premise: check is a mapped field")
	}
	delete(fieldTypes, "check")
	defer func() { fieldTypes["check"] = typ }()
	_, refused := adapt(t, `{"sshTests": [{"src": "a", "dst": ["tag:s"], "check": ["ops"]}]}`)
	if len(refused) != 1 || refused[0].Kind != refusedField || refused[0].Section != "sshTests" {
		t.Errorf("refusals %+v, want one unsupported_field in sshTests", refused)
	}
	// And with the field mapped again, the same entry is taken.
	fieldTypes["check"] = typ
	if _, refused := adapt(t, `{"sshTests": [{"src": "a", "dst": ["tag:s"], "check": ["ops"]}]}`); len(refused) != 0 {
		t.Errorf("refusals %+v with the field mapped", refused)
	}
}

// tooComplexIntentFile is a file the engine refuses for its size in values (acl.MaxNodes), well
// under the byte cap of a file: it is the one way the engine refuses a file that reads.
func tooComplexIntentFile() string {
	return `{"tests": [` + strings.Repeat("{},", acl.MaxNodes) + `]}`
}

// An engine refusal of the intent file follows the file's origin: a file the command line named
// is a usage error (too_complex, exit 2), the configured one is config_invalid (exit 6) like
// every other way the configured file cannot be used. The words are fixed either way, and a
// cancelled call is the call's, not the file's.
func TestAnEngineRefusalOfAnIntentFileFollowsItsOrigin(t *testing.T) {
	big := tooComplexIntentFile()
	const fixed = "the intent file is too large or too complex to read"
	_, _, err := loadScanIntent(context.Background(), &registry.Env{}, SecurityScanInput{Scope: "local", Invariants: big, Operator: true})
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.TooComplex || tkerr.ExitCode(err) != 2 || e.Message != fixed {
		t.Errorf("a named file: %v, want too_complex (exit 2) with fixed words", err)
	}
	_, _, err = loadScanIntent(context.Background(), configuredIntent(t, big), SecurityScanInput{Scope: "local"})
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ConfigInvalid || tkerr.ExitCode(err) != 6 || e.Message != fixed {
		t.Errorf("the configured file: %v, want config_invalid (exit 6) with the same words", err)
	}
	// The other class of engine refusal, for both origins, and a cancellation.
	other := &acl.Error{Code: acl.CodeInvalid, Message: "zq-secret-word"}
	for origin, want := range map[intentOrigin]tkerr.Code{intentCLI: tkerr.ValidationFailed, intentConfigured: tkerr.ConfigInvalid} {
		err := intentEngineError(origin, other)
		if e, ok := tkerr.As(err); !ok || e.Code != want || strings.Contains(e.Message+e.Hint, "zq-secret") {
			t.Errorf("%s, another refusal: %v, want %s and none of its words", origin, err, want)
		}
		if e, ok := tkerr.As(intentEngineError(origin, context.Canceled)); !ok || e.Code != tkerr.APIError {
			t.Errorf("%s, cancelled: %v, want api_error", origin, e)
		}
	}
}
