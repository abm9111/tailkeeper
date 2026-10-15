package tools_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// keyed returns a copy of env with a privacy key loaded, and the key.
func keyed(t *testing.T, env *registry.Env) (*registry.Env, *privacy.Key) {
	t.Helper()
	k, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		t.Fatal(err)
	}
	e := *env
	e.Privacy = k
	return &e, k
}

func TestMaskedValuesCarryOneStablePseudonymAcrossTools(t *testing.T) {
	f, reg, env := apiEnv(t)
	env, k := keyed(t, env)
	const amy = `"amy@example.com"`
	f.JSON("GET", tailnetPath+"/devices", 200, `{"devices":[{"id":"1","nodeId":"nAAA1CNTRL","name":"a.example.ts.net","hostname":"a","user":`+amy+`}]}`)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[{"eventTime":"2026-10-10T10:00:00Z","origin":"ADMIN_CONSOLE",
		"action":"UPDATE","actor":{"id":"u1","loginName":"AMY@example.com","displayName":"Amy Lee"},"target":{"id":"t1","name":"amy@example.com"}}]}`)
	f.Raw("GET", tailnetPath+"/acl", 200, "{\n  \"groups\": {\"group:a\": [\"amy@example.com\"]},\n}\n", map[string]string{"Content-Type": "application/hujson"})
	f.JSON("GET", tailnetPath+"/settings", 200, `{"aclsExternallyManagedOn":false}`)
	want := privacy.Suffix(k.Pseudonym("amy@example.com"))
	for tool, n := range map[string]int{"devices_list": 1, "audit_log": 2, "acl_get": 1} {
		out := mustCall(t, reg, env, tool, `{}`, nil)
		absent(t, out, "amy@")
		if got := strings.Count(out, want); got != n {
			t.Errorf("%s: %d values named %q, want %d: %s", tool, got, want, n, out)
		}
	}
	plain := mustCall(t, reg, show(env), "devices_list", `{}`, nil)
	if strings.Contains(plain, "[p:") {
		t.Errorf("with masking off nothing is named: %s", plain)
	}
}

const twoOwners = `{"devices":[
	{"id":"1","nodeId":"nAAA1CNTRL","name":"a.example.ts.net","hostname":"a","user":"amy@example.com"},
	{"id":"2","nodeId":"nBBB2CNTRL","name":"b.example.ts.net","hostname":"b","user":"bob@example.com"}]}`

// sent reports whether any recorded request carried value anywhere in its query.
func sent(f *apitest.Fake, value string) bool {
	for _, r := range f.Requests() {
		for _, vs := range r.Query {
			for _, v := range vs {
				if strings.Contains(v, value) {
					return true
				}
			}
		}
	}
	return false
}

func TestDevicesListUserFilterTakesOnlyPseudonymsWhileMasked(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/devices", 200, twoOwners)
	_, err := call(t, reg, env, "devices_list", `{"user":"amy@example.com"}`)
	if code(err) != tkerr.FilterRefused || sent(f, "amy") {
		t.Fatalf("literal user while masked: err = %v, sent = %v", err, sent(f, "amy"))
	}
	kenv, k := keyed(t, env)
	p := k.Pseudonym("amy@example.com")
	var out struct {
		Devices []struct {
			NodeID string `json:"nodeId"`
		} `json:"devices"`
		ClientFilters []string `json:"clientFilters"`
	}
	for _, arg := range []string{p, "a…@example.com [" + p + "]"} {
		mustCall(t, reg, kenv, "devices_list", `{"user":"`+arg+`"}`, &out)
		if len(out.Devices) != 1 || out.Devices[0].NodeID != "nAAA1CNTRL" {
			t.Errorf("user %q: %+v", arg, out)
		}
	}
	if sent(f, "p:") || sent(f, "@") {
		t.Error("a pseudonym or an address reached the server")
	}
	if _, err := call(t, reg, env, "devices_list", `{"user":"`+p+`"}`); code(err) != tkerr.PrivacyKeyUnavailable {
		t.Errorf("pseudonym without a key: %v", err)
	}
	mustCall(t, reg, show(env), "devices_list", `{"user":"amy@example.com"}`, nil)
	if !sent(f, "amy@example.com") {
		t.Error("with masking off the literal filter goes to the server as before")
	}
}

const auditTwo = `{"logs":[
	{"eventTime":"2026-10-10T10:00:00Z","origin":"ADMIN_CONSOLE","action":"UPDATE",
	 "actor":{"id":"u1","loginName":"amy@example.com","displayName":"Amy Lee"},"target":{"id":"t1","name":"bob@example.com"}},
	{"eventTime":"2026-10-10T10:01:00Z","origin":"ADMIN_CONSOLE","action":"UPDATE",
	 "actor":{"id":"u2","loginName":"bob@example.com","displayName":"Bob"},"target":{"id":"t10","name":"amy@example.com"}}]}`

func TestAuditLogFiltersNeverConfirmAGuessWhileMasked(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, auditTwo)
	for _, args := range []string{`{"actor":["~amy"]}`, `{"actor":["amy@example.com"]}`, `{"target":["amy@example.com"]}`,
		`{"target":["amy lee"]}`} {
		if _, err := call(t, reg, env, "audit_log", args); code(err) != tkerr.FilterRefused {
			t.Errorf("%s: %v, want filter_refused", args, err)
		}
	}
	if sent(f, "amy") {
		t.Fatal("a refused filter reached the server")
	}
	kenv, k := keyed(t, env)
	var out struct {
		Entries []struct {
			Actor  struct{ ID string } `json:"actor"`
			Target struct{ ID string } `json:"target"`
		} `json:"entries"`
	}
	ids := func() string {
		var s []string
		for _, e := range out.Entries {
			s = append(s, e.Actor.ID+">"+e.Target.ID)
		}
		return strings.Join(s, ",")
	}
	for args, want := range map[string]string{
		`{"actor":["` + k.Pseudonym("amy@example.com") + `"]}`:      "u1>t1",
		`{"actor":["` + k.Pseudonym("Bob") + `"]}`:                  "u2>t10",
		`{"actor":["u2","` + k.Pseudonym("amy@example.com") + `"]}`: "u1>t1,u2>t10",
		`{"target":["` + k.Pseudonym("amy@example.com") + `"]}`:     "u2>t10",
		`{"target":["t1"]}`: "u1>t1",
	} {
		mustCall(t, reg, kenv, "audit_log", args, &out)
		if got := ids(); got != want {
			t.Errorf("%s: entries %s, want %s", args, got, want)
		}
	}
	if sent(f, "p:") || sent(f, "@") {
		t.Error("a pseudonym or an address reached the server")
	}
	mustCall(t, reg, show(env), "audit_log", `{"actor":["~amy"],"target":["amy"]}`, nil)
	if !sent(f, "~amy") {
		t.Error("with masking off the filters go to the server as before")
	}
}

func TestAuditDigestsAreKeyedOrLeftOutWhileMasked(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[{"eventTime":"2026-10-10T10:00:00Z","origin":"ADMIN_CONSOLE",
		"action":"UPDATE","actor":{"id":"u1"},"target":{"id":"t1"},"old":"amy@example.com","new":"bob@example.com"}]}`)
	raw := []byte(`"amy@example.com"`)
	sum := sha256.Sum256(raw)
	plain := "sha256:" + hex.EncodeToString(sum[:])
	type entry struct {
		OldDigest  string `json:"oldDigest"`
		NewDigest  string `json:"newDigest"`
		OldPreview string `json:"oldPreview"`
	}
	var out struct {
		Entries []entry `json:"entries"`
		Note    string  `json:"note"`
	}
	s := mustCall(t, reg, env, "audit_log", `{}`, &out)
	if out.Entries[0].OldDigest != "" || out.Entries[0].NewDigest != "" || strings.Contains(s, hex.EncodeToString(sum[:])) {
		t.Errorf("masked without a key, the digests must be left out: %s", s)
	}
	if !strings.Contains(out.Note, "privacy key") {
		t.Errorf("the note must say why the digests are missing: %q", out.Note)
	}
	kenv, k := keyed(t, env)
	s = mustCall(t, reg, kenv, "audit_log", `{}`, &out)
	if out.Entries[0].OldDigest != k.Digest(raw) || out.Entries[0].OldDigest == plain || strings.Contains(s, hex.EncodeToString(sum[:])) {
		t.Errorf("masked with a key: %q, want %q: %s", out.Entries[0].OldDigest, k.Digest(raw), s)
	}
	if !strings.HasPrefix(out.Entries[0].OldDigest, "hmac-sha256:") || strings.Contains(out.Note, "privacy key") {
		t.Errorf("keyed digest or note wrong: %q, %q", out.Entries[0].OldDigest, out.Note)
	}
	// The keyed preview names the masked address and carries the keyed digest.
	mustCall(t, reg, kenv, "audit_log", `{"includeValues":true}`, &out)
	if !strings.Contains(out.Entries[0].OldPreview, privacy.Suffix(k.Pseudonym("amy@example.com"))) ||
		out.Entries[0].NewDigest != k.Digest([]byte(`"bob@example.com"`)) {
		t.Errorf("keyed preview = %q, new digest = %q", out.Entries[0].OldPreview, out.Entries[0].NewDigest)
	}
	mustCall(t, reg, show(env), "audit_log", `{}`, &out)
	if out.Entries[0].OldDigest != plain {
		t.Errorf("masking off: %q, want %q", out.Entries[0].OldDigest, plain)
	}
	if strings.Contains(out.Note, "privacy key") {
		t.Errorf("masking off needs no key: %q", out.Note)
	}
}

// A value the display shows with no pseudonym (one masking leaves unchanged, or
// whose pseudonym the length cap cuts off) must not match a filter on the
// pseudonym it would have had: asking for it would confirm a guess at it.
func TestPersonalFiltersMatchOnlyPseudonymsTheDisplayShows(t *testing.T) {
	f, reg, env := apiEnv(t)
	kenv, k := keyed(t, env)
	tooLong := "z@" + strings.Repeat("x", 1100) + ".com" // its pseudonym is past the length cap
	logins := []string{"amy@example.com", "tagged-devices", "Tagged Devices", "a", tooLong, ""}
	var logs, devices []string
	for i, l := range logins {
		b, _ := json.Marshal(l)
		logs = append(logs, fmt.Sprintf(`{"eventTime":"2026-10-10T10:%02d:00Z","origin":"ADMIN_CONSOLE","action":"UPDATE",
			"actor":{"id":"u%d","loginName":%s,"displayName":%s},"target":{"id":"t%d"}}`, i, i, b, b, i))
		devices = append(devices, fmt.Sprintf(`{"id":"%d","nodeId":"n%d","name":"d%d.example.ts.net","hostname":"d%d","user":%s}`, i, i, i, i, b))
	}
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[`+strings.Join(logs, ",")+`]}`)
	f.JSON("GET", tailnetPath+"/devices", 200, `{"devices":[`+strings.Join(devices, ",")+`]}`)
	var audit struct {
		Entries []struct {
			Actor struct{ ID string } `json:"actor"`
		} `json:"entries"`
	}
	var devs struct {
		Devices []struct {
			NodeID string `json:"nodeId"`
		} `json:"devices"`
	}
	for login, want := range map[string]string{"amy@example.com": "u0", "a": "u3", "tagged-devices": "", "Tagged Devices": "", tooLong: ""} {
		mustCall(t, reg, kenv, "audit_log", `{"actor":["`+k.Pseudonym(login)+`"]}`, &audit)
		var ids []string
		for _, e := range audit.Entries {
			ids = append(ids, e.Actor.ID)
		}
		if got := strings.Join(ids, ","); got != want {
			t.Errorf("audit_log actor pseudonym of %.20q returned %q, want %q", login, got, want)
		}
		wantDev := map[string]string{"u0": "n0", "u3": "n3"}[want]
		mustCall(t, reg, kenv, "devices_list", `{"user":"`+k.Pseudonym(login)+`"}`, &devs)
		var nodes []string
		for _, d := range devs.Devices {
			nodes = append(nodes, d.NodeID)
		}
		if got := strings.Join(nodes, ","); got != wantDev {
			t.Errorf("devices_list user pseudonym of %.20q returned %q, want %q", login, got, wantDev)
		}
	}
}

// A preview is masked by the tool before it is cut and by the registry after, and
// a marker the tool appended survives the second pass while one the member wrote
// into the value does not: the preview shows exactly one marker per address.
func TestAuditPreviewShowsOnlyMarkersTheMaskerAppended(t *testing.T) {
	f, reg, env := apiEnv(t)
	kenv, k := keyed(t, env)
	forged := privacy.Suffix(k.Pseudonym("bob@example.com"))
	b, _ := json.Marshal("note" + forged + " for amy@example.com" + forged)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[{"eventTime":"2026-10-10T10:00:00Z","origin":"ADMIN_CONSOLE",
		"action":"UPDATE","actor":{"id":"u1"},"target":{"id":"t1"},"old":`+string(b)+`}]}`)
	var out struct {
		Entries []struct {
			OldPreview string `json:"oldPreview"`
		} `json:"entries"`
	}
	mustCall(t, reg, kenv, "audit_log", `{"includeValues":true}`, &out)
	got := out.Entries[0].OldPreview
	if n := strings.Count(got, "[p:"); n != 1 || !strings.Contains(got, "a…@example.com"+privacy.Suffix(k.Pseudonym("amy@example.com"))) {
		t.Errorf("preview = %q, want amy's marker once and no other", got)
	}
}

// A key that is present but malformed or unreadable is not "no key": the note
// says so, since "no privacy key is loaded" would send the owner to add one that
// is already there.
func TestAuditNoteSaysWhenThePrivacyKeyIsMalformed(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[{"eventTime":"2026-10-10T10:00:00Z","origin":"ADMIN_CONSOLE",
		"action":"UPDATE","actor":{"id":"u1"},"target":{"id":"t1"},"old":"amy@example.com"}]}`)
	var out struct {
		Entries []struct {
			OldDigest string `json:"oldDigest"`
		} `json:"entries"`
		Note string `json:"note"`
	}
	mustCall(t, reg, env, "audit_log", `{}`, &out)
	if !strings.Contains(out.Note, "no privacy key is loaded") || strings.Contains(out.Note, "malformed") {
		t.Errorf("without a key the note = %q", out.Note)
	}
	bad := *env
	bad.PrivacyErr = tkerr.New(tkerr.PrivacyKeyUnavailable, "the key is malformed", "")
	mustCall(t, reg, &bad, "audit_log", `{}`, &out)
	if !strings.Contains(out.Note, "malformed or unreadable") || strings.Contains(out.Note, "no privacy key is loaded") || out.Entries[0].OldDigest != "" {
		t.Errorf("with a malformed key the note = %q, digest %q", out.Note, out.Entries[0].OldDigest)
	}
	mustCall(t, reg, show(&bad), "audit_log", `{}`, &out)
	if strings.Contains(out.Note, "privacy key") || !strings.HasPrefix(out.Entries[0].OldDigest, "sha256:") {
		t.Errorf("with masking off the key does not matter: %q", out.Note)
	}
}

// Errors echo what the caller typed, so a pseudonym beside the echo would
// confirm a guessed address to a model that can match it against a listing.
// Errors are masked without pseudonyms, under a key too.
func TestErrorsEchoingAnAddressNeverCarryAPseudonym(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/devices", 200, twoOwners)
	kenv, k := keyed(t, env)
	pseudonym := k.Pseudonym("amy@example.com")
	for name, c := range map[string]struct{ tool, args string }{
		"not found":         {"device_get", `{"device":"amy@example.com"}`},
		"schema value":      {"devices_list", `{"staleDays":"amy@example.com"}`},
		"unknown property":  {"devices_list", `{"amy@example.com":1}`},
		"audit limit":       {"audit_log", `{"limit":"amy@example.com"}`},
		"unparsable window": {"audit_log", `{"start":"amy@example.com"}`},
	} {
		_, err := call(t, reg, kenv, c.tool, c.args)
		fe := tkerr.From(err)
		if fe == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		msg := fe.Message + "\n" + fe.Hint
		if strings.Contains(msg, "[p:") || strings.Contains(msg, pseudonym) {
			t.Errorf("%s: the error names the value: %s", name, msg)
		}
		if strings.Contains(msg, "amy@") {
			t.Errorf("%s: the error does not mask the address: %s", name, msg)
		}
	}
	// The not-found case must still echo, masked, so the test above cannot pass
	// by an error that says nothing.
	_, err := call(t, reg, kenv, "device_get", `{"device":"amy@example.com"}`)
	if e := tkerr.From(err); e == nil || e.Code != tkerr.NotFound || !strings.Contains(e.Message, "a…@example.com") {
		t.Errorf("device_get = %v, want a masked echo", err)
	}
}

// acl_test echoes the caller's own source and destinations in Tailscale's
// reasons. Like an error, that echo must not carry a pseudonym: a guessed
// address would come back confirmed.
func TestACLTestEchoOfACallersGuessCarriesNoPseudonym(t *testing.T) {
	f, reg, env := apiEnv(t)
	kenv, _ := keyed(t, env)
	f.Raw("POST", "/api/v2/tailnet/T1234CNTRL/acl/validate", 200,
		`{"message":"test(s) failed","data":[{"user":"amy@example.com","errors":["address \"203.0.113.9:22\": want: Accept, got: Drop for amy@example.com"],"warnings":["amy@example.com has no rule"]}]}`,
		map[string]string{"Content-Type": "application/json"})
	s := mustCall(t, reg, kenv, "acl_test", `{"src":"amy@example.com","accept":["203.0.113.9:22"]}`, nil)
	absent(t, s, "amy@", "[p:")
	if !strings.Contains(s, "a…@example.com") {
		t.Errorf("the echo must still be there, masked: %s", s)
	}
}

// The server may match an actor filter more widely than an exact ID (it also
// takes ~search), so while masked a literal actor is narrowed here to the entries
// whose actor.id is exactly it.
func TestAuditLogLiteralActorKeepsOnlyExactIDsWhileMasked(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[
	 {"eventTime":"2026-10-10T10:00:00Z","origin":"ADMIN_CONSOLE","action":"UPDATE","actor":{"id":"u1"},"target":{"id":"t1"}},
	 {"eventTime":"2026-10-10T10:01:00Z","origin":"ADMIN_CONSOLE","action":"UPDATE","actor":{"id":"u12"},"target":{"id":"t2"}},
	 {"eventTime":"2026-10-10T10:02:00Z","origin":"ADMIN_CONSOLE","action":"UPDATE","actor":{"id":"u2"},"target":{"id":"t3"}}]}`)
	var out struct {
		Entries []struct {
			Actor struct{ ID string } `json:"actor"`
		} `json:"entries"`
	}
	ids := func() string {
		var s []string
		for _, e := range out.Entries {
			s = append(s, e.Actor.ID)
		}
		return strings.Join(s, ",")
	}
	kenv, _ := keyed(t, env)
	for name, e := range map[string]*registry.Env{"masked": env, "masked with a key": kenv} {
		mustCall(t, reg, e, "audit_log", `{"actor":["u1"]}`, &out)
		if got := ids(); got != "u1" {
			t.Errorf("%s: actor u1 kept %q, want only u1", name, got)
		}
	}
	if !sent(f, "u1") {
		t.Error("a literal actor ID still goes to the server")
	}
	mustCall(t, reg, show(env), "audit_log", `{"actor":["u1"]}`, &out)
	if got := ids(); got != "u1,u12,u2" {
		t.Errorf("masking off: the server's match stands, kept %q", got)
	}
}

// With masking off the server reads a literal actor as an ID or a ~search and a
// literal target as a substring. A pseudonym moves the whole filter client-side,
// where only exact IDs and pseudonyms match, so a list that mixes a pseudonym
// with a search or a substring would silently return less: it is refused.
func TestAuditLogRefusesAPseudonymMixedWithASearchWhileUnmasked(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, auditTwo)
	kenv, k := keyed(t, env)
	shown := show(kenv)
	p := k.Pseudonym("amy@example.com")
	for _, args := range []string{
		`{"actor":["~amy","` + p + `"]}`,
		`{"actor":["amy@example.com","` + p + `"]}`,
		`{"target":["t1","` + p + `"]}`,
		`{"target":["bob","` + p + `"]}`,
	} {
		_, err := call(t, reg, shown, "audit_log", args)
		if code(err) != tkerr.ValidationFailed || !strings.Contains(err.Error(), "pseudonyms or by literals, not both") {
			t.Errorf("%s: %v, want validation_failed saying not both", args, err)
		}
	}
	// Each kind alone, and exact actor IDs beside a pseudonym, still work.
	for _, args := range []string{`{"actor":["~amy"]}`, `{"actor":["` + p + `"]}`, `{"actor":["u2","` + p + `"]}`, `{"target":["` + p + `"]}`, `{"target":["bob"]}`} {
		if _, err := call(t, reg, shown, "audit_log", args); err != nil {
			t.Errorf("%s: %v", args, err)
		}
	}
}

// An untrusted target name is masked as text, so each address in it is named
// separately, and the filter must agree with what is displayed: a pseudonym
// returns every entry that shows it and no other. Matching the pseudonym of the
// whole name dropped "auth key for amy@example.com", and would
// have confirmed a guess at "Amy Lee", which shows no pseudonym at all.
func TestAuditLogTargetPseudonymMatchesEveryAddressTheNameShows(t *testing.T) {
	f, reg, env := apiEnv(t)
	bs := "\\"
	names := []string{
		"auth key for amy@example.com",                    // t1: one address inside text
		"amy@example.com",                                 // t2: the whole name
		"invite for bob@example.com and Amy@Example.com.", // t3: two addresses, one upper case, a full stop
		"Amy Lee",           // t4: no address, so no pseudonym is shown
		"carol@example.com", // t5
		strings.Repeat("x", 1100) + " amy@example.com",           // t6: its pseudonym is cut off by the length cap
		"key for amy" + bs + "u0040example.com, owner dan@x.org", // t7: an escaped at sign
		"chain a@b@c.d", // t8: a chain is one address
	}
	var logs []string
	for i, n := range names {
		b, _ := json.Marshal(n)
		logs = append(logs, fmt.Sprintf(`{"eventTime":"2026-10-10T10:%02d:00Z","origin":"ADMIN_CONSOLE","action":"UPDATE",
			"actor":{"id":"u%d"},"target":{"id":"t%d","name":%s}}`, i, i, i+1, b))
	}
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[`+strings.Join(logs, ",")+`]}`)
	kenv, k := keyed(t, env)
	type entries struct {
		Entries []struct {
			Target struct{ ID, Name string } `json:"target"`
		} `json:"entries"`
	}
	ids := func(o entries) string {
		var s []string
		for _, e := range o.Entries {
			s = append(s, e.Target.ID)
		}
		return strings.Join(s, ",")
	}
	var all entries
	mustCall(t, reg, kenv, "audit_log", `{}`, &all)
	if len(all.Entries) != len(names) {
		t.Fatalf("unfiltered audit_log returned %d entries, want %d", len(all.Entries), len(names))
	}
	// What the display shows is the source of truth: every pseudonym that appears
	// in a target name returns exactly the entries whose name shows it.
	shownRE := regexp.MustCompile(`\[(p:[a-z2-7]{10})\]`)
	shown := map[string][]string{}
	for _, e := range all.Entries {
		for _, m := range shownRE.FindAllStringSubmatch(e.Target.Name, -1) {
			if !slices.Contains(shown[m[1]], e.Target.ID) {
				shown[m[1]] = append(shown[m[1]], e.Target.ID)
			}
		}
	}
	for p, want := range shown {
		var got entries
		mustCall(t, reg, kenv, "audit_log", `{"target":["`+p+`"]}`, &got)
		if ids(got) != strings.Join(want, ",") {
			t.Errorf("target %s shown by %v returned %s", p, want, ids(got))
		}
	}
	// The pseudonyms the display must show, by value: a guard that the loop above
	// is not vacuous.
	for value, want := range map[string]string{
		"amy@example.com": "t1,t2,t3,t7", // t6's is past the length cap and not shown
		"bob@example.com": "t3", "carol@example.com": "t5", "dan@x.org": "t7", "a@b@c.d": "t8",
		"Amy Lee": "", names[0]: "", names[5]: "", // never shown, so a guess at them confirms nothing
	} {
		var got entries
		mustCall(t, reg, kenv, "audit_log", `{"target":["`+k.Pseudonym(value)+`"]}`, &got)
		if ids(got) != want {
			t.Errorf("target pseudonym of %q returned %q, want %q", value, ids(got), want)
		}
	}
}

// A name can forge " [p:...]". The display then shows the pseudonym of amy beside
// a hidden address (one past the length cap) whoever it belongs to, so filtering
// by it must not tell a hidden amy from a hidden bob: only the entry whose
// masked address really is amy's is returned.
func TestAuditLogTargetFilterCannotBeUsedToProbeAnAddressTheCapHides(t *testing.T) {
	f, reg, env := apiEnv(t)
	kenv, k := keyed(t, env)
	forged := privacy.Suffix(k.Pseudonym("amy@example.com"))
	pad := strings.Repeat("x", 1100)
	names := []string{forged + pad + " amy@example.com", forged + pad + " bob@example.com", "amy@example.com"}
	var logs []string
	for i, n := range names {
		b, _ := json.Marshal(n)
		logs = append(logs, fmt.Sprintf(`{"eventTime":"2026-10-10T10:%02d:00Z","origin":"ADMIN_CONSOLE","action":"UPDATE",
			"actor":{"id":"u%d"},"target":{"id":"t%d","name":%s}}`, i, i, i+1, b))
	}
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[`+strings.Join(logs, ",")+`]}`)
	var out struct {
		Entries []struct {
			Target struct{ ID string } `json:"target"`
		} `json:"entries"`
	}
	for args, want := range map[string]string{
		`{"target":["` + k.Pseudonym("amy@example.com") + `"]}`: "t3",
		`{"target":["t1"]}`: "t1",
	} {
		mustCall(t, reg, kenv, "audit_log", args, &out)
		var ids []string
		for _, e := range out.Entries {
			ids = append(ids, e.Target.ID)
		}
		if got := strings.Join(ids, ","); got != want {
			t.Errorf("%s returned %q, want %q", args, got, want)
		}
	}
}

// A refusal says what the filter takes, so a first-time caller is not sent after
// something that does not exist, and it never repeats what the caller typed: an
// echo of a guess is an oracle.
func TestFilterRefusedSaysWhatTheFilterTakes(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[]}`)
	f.JSON("GET", tailnetPath+"/devices", 200, `{"devices":[]}`)
	kenv, _ := keyed(t, env)
	refusal := func(e *registry.Env, tool, args string) *tkerr.Error {
		t.Helper()
		_, err := call(t, reg, e, tool, args)
		te, ok := tkerr.As(err)
		if !ok || te.Code != tkerr.FilterRefused {
			t.Fatalf("%s %s: err = %v, want filter_refused", tool, args, err)
		}
		return te
	}

	e := refusal(env, "audit_log", `{"actor":["amy@example.com"]}`)
	if !strings.Contains(e.Message, "actor takes an exact ID") || !strings.Contains(e.Hint, "privacy key") {
		t.Errorf("audit_log actor without a privacy key: message %q, hint %q", e.Message, e.Hint)
	}
	e = refusal(env, "audit_log", `{"target":["amy lee"]}`)
	if !strings.Contains(e.Message, "target takes an exact ID") {
		t.Errorf("audit_log target: message %q", e.Message)
	}
	e = refusal(env, "devices_list", `{"user":"amy@example.com"}`)
	if !strings.Contains(e.Message, "user takes a pseudonym (p:…)") || strings.Contains(e.Message, "exact ID") || strings.Contains(e.Hint, "exact ID") {
		t.Errorf("devices_list user takes no ID: message %q, hint %q", e.Message, e.Hint)
	}
	if !strings.Contains(e.Hint, "privacy key") {
		t.Errorf("devices_list user without a privacy key must say why no pseudonym is shown: %q", e.Hint)
	}

	e = refusal(kenv, "audit_log", `{"actor":["amy@example.com"]}`)
	if strings.Contains(e.Hint, "privacy key") || !strings.Contains(e.Hint, "pseudonym shown after a masked value") {
		t.Errorf("with a privacy key the hint points at the pseudonym shown: %q", e.Hint)
	}
	e = refusal(kenv, "devices_list", `{"user":"amy@example.com"}`)
	if strings.Contains(e.Hint, "privacy key") {
		t.Errorf("with a privacy key the hint need not explain the key: %q", e.Hint)
	}

	for _, probe := range []struct{ tool, args string }{
		{"audit_log", `{"actor":["amy@example.com"]}`}, {"audit_log", `{"target":["amy lee"]}`}, {"devices_list", `{"user":"amy@example.com"}`}} {
		for _, ev := range []*registry.Env{env, kenv} {
			e := refusal(ev, probe.tool, probe.args)
			if s := strings.ToLower(e.Message + " " + e.Hint); strings.Contains(s, "amy") || strings.Contains(s, "example.com") {
				t.Errorf("%s %s: the refusal repeats what the caller typed: %q", probe.tool, probe.args, s)
			}
		}
	}
}

// The owner Tailscale reports for tagged devices names no person and is shown
// unmasked, so filtering on it confirms nothing.
func TestTaggedDevicesIsAFilterWhileMasked(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/devices", 200, `{"devices":[]}`)
	if _, err := call(t, reg, env, "devices_list", `{"user":"tagged-devices"}`); err != nil {
		t.Fatalf("user=tagged-devices while masked: %v", err)
	}
	if q := f.Requests()[0].Query; q.Get("user") != "tagged-devices" {
		t.Errorf("query = %v, want user=tagged-devices sent to the server", q)
	}
	if _, err := call(t, reg, env, "devices_list", `{"user":"tagged-devices@example.com"}`); code(err) != tkerr.FilterRefused {
		t.Errorf("a login that merely starts with tagged-devices: err = %v, want filter_refused", err)
	}
}

// includeValues previews are capped at 256 bytes, counting the ...[truncated]
// that ends a cut one, and cut on a rune boundary.
func TestAuditPreviewIsCappedAt256BytesAndSaysSo(t *testing.T) {
	f, reg, env := apiEnv(t)
	short, ascii, multibyte := strings.Repeat("a", 200), strings.Repeat("b", 1000), strings.Repeat("é", 400)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[{"eventTime":"2026-10-10T10:00:00Z","origin":"ADMIN_CONSOLE",
		"action":"UPDATE","actor":{"id":"u1"},"target":{"id":"t1"},"old":"`+short+`","new":"`+ascii+`"},
		{"eventTime":"2026-10-10T10:01:00Z","origin":"ADMIN_CONSOLE","action":"UPDATE","actor":{"id":"u1"},"target":{"id":"t2"},"old":"`+multibyte+`"}]}`)
	var out struct {
		Entries []struct {
			OldPreview string `json:"oldPreview"`
			NewPreview string `json:"newPreview"`
		} `json:"entries"`
	}
	mustCall(t, reg, env, "audit_log", `{"includeValues":true}`, &out)
	const suffix = "...[truncated]"
	if got := out.Entries[0].OldPreview; got != short {
		t.Errorf("a value under the cap is returned whole, got %d bytes", len(got))
	}
	if got := out.Entries[0].NewPreview; len(got) != 256 || !strings.HasSuffix(got, suffix) {
		t.Errorf("1000 ASCII bytes: preview is %d bytes ending %q, want 256 ending %q", len(got), got[len(got)-len(suffix):], suffix)
	}
	if got := out.Entries[1].OldPreview; len(got) > 256 || !strings.HasSuffix(got, suffix) || !utf8.ValidString(got) {
		t.Errorf("800 multibyte bytes: preview is %d bytes, valid UTF-8 %v, ends %q", len(got), utf8.ValidString(got), got[len(got)-len(suffix):])
	}
}
