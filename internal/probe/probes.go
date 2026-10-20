package probe

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/tailscale/hujson"

	"github.com/abm9111/tailkeeper/internal/api"
)

// entry builds a Probe from its row of the probe table (docs/design.md §22).
func entry(id, title string, run func(ctx context.Context, x *Exec) error) Probe {
	r := registered[id]
	return Probe{ID: id, Title: title, Sends: r.Sends, Expected: r.Expected, Branch: r.Branch, Run: run}
}

// All returns the probes of the probe table in order: A-1 to A-14, then H-1. Every synthetic
// document uses tag:p, example.com and documentation addresses (192.0.2.0/24,
// 2001:db8::/32), plus the one 100.64.0.1 that A-1 names; documents built from the live
// policy exist only in memory.
func All() []Probe {
	return []Probe{
		entry("A-1", "Defaults: absent, empty and null acls, empty grants", a1),
		entry("A-2", "Policy mode with a non-object body", a2),
		entry("A-3", "What a rejection looks like", a3),
		entry("A-4", "Duplicate sections and keys", a4),
		entry("A-5", "Which section names the server knows", a5),
		entry("A-6", "The 500 for an autogroup:self target", a6),
		entry("A-7", "Warnings: details=true against policy mode", a7),
		entry("A-8", "details=true, Accept and If-None-Match", a8),
		entry("A-9", "The verdict grammar, one destination kind at a time", a9),
		entry("A-10", "sshTests in policy mode", a10),
		entry("A-11", "Raw, standardized and BOM-prefixed HuJSON", a11),
		entry("A-12", "Stored tests in tests mode", a12),
		entry("A-13", "The ETag formula", a13),
		entry("A-14", "Does validate leak whether a login exists", a14),
		entry("H-1", "Do the audit log's old and new hold policy texts", h1),
	}
}

// step is a Step with an expectation.
func step(label, expect string) Step { return Step{Label: label, Expect: expect} }

func a1(ctx context.Context, x *Exec) error {
	const head = `{"tagOwners":{"tag:p":[]},"hosts":{"probe-a":"100.64.0.1"},`
	const tests = `"tests":[{"src":"tag:p","deny":["probe-a:22"]}]}`
	docs := []struct{ label, expect, doc string }{
		{"acls absent", "fails like the control (allow-all)", head + tests},
		{"acls []", "passes (deny-all)", head + `"acls":[],` + tests},
		{"acls null", "fails like absent", head + `"acls":null,` + tests},
		{"grants []", "fails like absent (low confidence)", head + `"grants":[],` + tests},
		{"control: acls accept everything", "fails: want Drop, got Accept, in the grammar", head + `"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],` + tests},
	}
	seen := make([]Seen, len(docs))
	for i, d := range docs {
		s, err := x.PostPolicy(ctx, step(d.label, d.expect), d.doc)
		if err != nil {
			return err
		}
		seen[i] = s
	}
	fails := func(s Seen) bool { return s.TextHas("want: Drop, got: Accept") }
	x.Check("the control fails with want Drop, got Accept", true, fails(seen[4]))
	x.Check("absent acls fails like the control", true, fails(seen[0]))
	x.Check("acls [] passes", true, seen[1].Passes())
	x.Check("acls null fails like absent", true, fails(seen[2]))
	x.Check("grants [] fails like absent", true, fails(seen[3]))
	return nil
}

func a2(ctx context.Context, x *Exec) error {
	docs := []struct{ label, expect, doc string }{
		{"an empty array", "runs in tests mode against live", `[]`},
		{"an array with one test", "runs in tests mode against live", `[{"src":"tag:p","accept":["tag:p:22"]}]`},
		{"an empty body", "rejected with a bare message", ``},
		{"null", "rejected with a bare message", `null`},
	}
	seen := make([]Seen, len(docs))
	for i, d := range docs {
		s, err := x.PostPolicy(ctx, step(d.label, d.expect), d.doc)
		if err != nil {
			return err
		}
		seen[i] = s
	}
	x.Check("an empty array is not rejected as a policy", true, seen[0].Accepted())
	x.Check("an array with a test is not rejected as a policy", true, seen[1].Accepted())
	x.Check("an empty body is rejected with a bare message", true, seen[2].Status == 400 && seen[2].Bare())
	x.Check("null is rejected with a bare message", true, seen[3].Status == 400 && seen[3].Bare())
	return nil
}

func a3(ctx context.Context, x *Exec) error {
	docs := []struct{ label, doc string }{
		{"a syntax error", "{\n  \"tagOwners\": {\"tag:p\": []},\n  \"acls\": [ invalidtext ]\n}\n"},
		{"an unknown field", `{"tagOwners":{"tag:p":[]},"unknownsection":[]}`},
		{"an unknown tag", `{"acls":[{"action":"accept","src":["tag:p"],"dst":["tag:p:22"]}]}`},
		{"app: {} without ip", `{"tagOwners":{"tag:p":[]},"grants":[{"src":["tag:p"],"dst":["tag:p"],"app":{}}]}`},
	}
	for i, d := range docs {
		s, err := x.PostPolicy(ctx, step(d.label, "HTTP 400 with a bare message and no data"), d.doc)
		if err != nil {
			return err
		}
		x.Check(d.label+" answers 400 with a bare message and no data", true, s.Status == 400 && s.Bare())
		if i == 0 {
			x.Check("the syntax error names a line and a column", true, s.TextHas("line <n>, column <n>"))
		}
	}
	return nil
}

// rejectedOrFailed is an answer that is not the pass of an element-wise merge and is still
// the server's own: a 400, or an accepted policy whose test failed. A 403, a 500 or a
// non-JSON page is neither, so a request that failed does not read as the table's answer.
func rejectedOrFailed(s Seen) bool {
	return s.Status == 400 || (s.Accepted() && s.ErrorLines() > 0)
}

func a4(ctx context.Context, x *Exec) error {
	const rulesCase = "two acls blocks, the second rule without dst"
	docs := []struct {
		label, expect, doc string
		check              func(Seen) bool
		what               string
	}{
		{"two groups blocks", "accepted: the blocks merge, so group:one still exists",
			`{"groups":{"group:one":["amy@example.com"]},"groups":{"group:two":["bob@example.com"]},"tagOwners":{"tag:p":["group:one"]},"acls":[]}`,
			Seen.Accepted, "two groups blocks are accepted and merge"},
		{"two acls blocks", "accepted: the later array replaces the earlier, so deny-all and the test passes",
			`{"tagOwners":{"tag:p":[]},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],"acls":[],"tests":[{"src":"tag:p","deny":["tag:p:22"]}]}`,
			Seen.Passes, "two acls blocks are accepted and the later array replaces the earlier"},
		{rulesCase, "rejected, or accepted with the test failing: the later array replaces the earlier, so the one rule has no dst",
			`{"tagOwners":{"tag:p":[],"tag:q":[]},"acls":[{"action":"accept","src":["tag:p"],"dst":["tag:q:22"]}],"acls":[{"action":"accept","src":["tag:p"]}],"tests":[{"src":"tag:p","accept":["tag:q:22"],"deny":["tag:q:80"]}]}`,
			rejectedOrFailed, "a repeated acls array replaces its rules whole (no element-wise merge)"},
		{"tagOwners and TagOwners", "accepted: the keys fold case and the blocks merge, so both tags exist",
			`{"tagOwners":{"tag:p":[]},"TagOwners":{"tag:q":[]},"acls":[],"tests":[{"src":"tag:p","deny":["tag:q:22"]}]}`,
			func(s Seen) bool { return s.Passes() && !s.TextHas("tag not found") }, "tagOwners and TagOwners are accepted and merge"},
		{"a group defined twice inside groups", "accepted: the later entry wins",
			`{"groups":{"group:one":["amy@example.com"],"group:one":["bob@example.com"]},"acls":[]}`,
			Seen.Accepted, "a group defined twice inside groups is accepted"},
	}
	for _, d := range docs {
		s, err := x.PostPolicy(ctx, step(d.label, d.expect), d.doc)
		if err != nil {
			return err
		}
		x.Check(d.what, true, d.check(s))
		// Only an element-wise merge lets the one rule keep the first block's dst and pass. An
		// answer that is neither a 400 nor an accepted policy (a 403, a 500, a page) says nothing
		// either way, so no fact is recorded for it.
		if d.label == rulesCase && (s.Accepted() || s.Status == 400) {
			x.Fact("the second acls block kept the first block's dst (element-wise merge)", s.Passes())
		}
	}
	return nil
}

func a5(ctx context.Context, x *Exec) error {
	docs := []struct{ label, expect, doc string }{
		{"nodeAttr (singular)", "rejected: json: unknown field", `{"nodeAttr":[]}`},
		{"attrConfig", "accepted", `{"attrConfig":{}}`},
		{"extraDNSRecords", "accepted", `{"extraDNSRecords":[]}`},
		{"sshTests", "accepted", `{"sshTests":[]}`},
	}
	for i, d := range docs {
		s, err := x.PostPolicy(ctx, step(d.label, d.expect), d.doc)
		if err != nil {
			return err
		}
		if i == 0 {
			x.Check("nodeAttr is rejected as an unknown field", true, s.Status == 400 && s.BodyHas("unknown field"))
		} else {
			x.Check(d.label+" is accepted", true, s.Accepted())
		}
	}
	return nil
}

func a6(ctx context.Context, x *Exec) error {
	const doc = `{"tagOwners":{"tag:p":[]},"nodeAttrs":[{"target":["autogroup:self"],"attr":["randomize-client-port"]}]}`
	var seen [2]Seen
	for i, label := range []string{"the first send", "the second send"} {
		s, err := x.PostPolicy(ctx, step(label, "HTTP 500"), doc)
		if err != nil {
			return err
		}
		seen[i] = s
		x.Check(label+" answers 500", true, s.Status == 500)
	}
	x.Fact("both sends have the same skeleton", seen[0].signature() == seen[1].signature())
	return nil
}

func a7(ctx context.Context, x *Exec) error {
	live, err := x.Live(ctx)
	if err != nil {
		return err
	}
	s, err := x.PostLive(ctx, step("the live text, validated in policy mode", "the same warning set as details=true"), "application/hujson", live.Text)
	if err != nil {
		return err
	}
	x.Count("details warnings", len(live.Warnings))
	x.Count("details errors", len(live.Errors))
	x.Count("policy-mode warnings", len(s.WarningLines()))
	x.Count("policy-mode error lines", s.ErrorLines())
	x.Check("the same warning set both ways", true, s.Accepted() && sameSet(live.Warnings, s.WarningLines()))
	return nil
}

func a8(ctx context.Context, x *Exec) error {
	plain, err := x.GetPolicy(ctx, step("plain, Accept: application/hujson", "the policy text and an ETag"), api.PolicyGet{Accept: "application/hujson"})
	if err != nil {
		return err
	}
	withAccept, err := x.GetPolicy(ctx, step("details=true, Accept: application/hujson", "the details object, or the plain text"), api.PolicyGet{Details: true, Accept: "application/hujson"})
	if err != nil {
		return err
	}
	noAccept, err := x.GetPolicy(ctx, step("details=true, no Accept", "the details object"), api.PolicyGet{Details: true})
	if err != nil {
		return err
	}
	inm, err := x.GetPolicy(ctx, step("plain, If-None-Match: the plain ETag", "304 (low confidence)"), api.PolicyGet{Accept: "application/hujson", IfNoneMatch: plain.ETag})
	if err != nil {
		return err
	}
	inmDetails, err := x.GetPolicy(ctx, step("details=true, If-None-Match: the plain ETag", "304 (low confidence)"), api.PolicyGet{Details: true, IfNoneMatch: plain.ETag})
	if err != nil {
		return err
	}
	decoded := func(s Seen) []byte {
		var d struct {
			ACL string `json:"acl"`
		}
		if json.Unmarshal(s.Body, &d) != nil {
			return nil
		}
		b, _ := base64.StdEncoding.DecodeString(d.ACL)
		return b
	}
	x.Check("details with Accept decodes to the plain body", true, len(plain.Body) > 0 && string(decoded(withAccept)) == string(plain.Body))
	x.Check("details without Accept decodes to the plain body", true, len(plain.Body) > 0 && string(decoded(noAccept)) == string(plain.Body))
	x.Check("the ETags are equal", true, plain.ETag != "" && withAccept.ETag == plain.ETag && noAccept.ETag == plain.ETag)
	x.Check("If-None-Match answers 304", true, inm.Status == 304)
	x.Fact("details with Accept is a JSON object", isJSONObject(withAccept.Body))
	x.Fact("If-None-Match with details answers 304", inmDetails.Status == 304)
	return nil
}

// destination is one kind of destination a test may name.
type destination struct {
	label  string
	dst    string // "" when the live policy has none of this kind
	proto  string
	refuse bool   // a kind Tailscale's tests refuse
	absent string // the sentence for Skip when dst is ""
}

// source returns a name from the live policy a test can use as its src: a tag, else a
// login written as an address, else a group; "" when the policy has none of them.
func (l *Live) source() string {
	for _, list := range [][]string{l.Tags, l.Logins, l.Groups} {
		if len(list) > 0 {
			return list[0]
		}
	}
	return ""
}

// a9Tests sends one tests-mode request per destination kind, from the source src.
func a9Tests(ctx context.Context, x *Exec, live *Live, src string) error {
	first := func(list []string) string {
		if len(list) == 0 {
			return ""
		}
		return list[0]
	}
	withPort := func(name string) string {
		if name == "" {
			return ""
		}
		return name + ":22"
	}
	kinds := []destination{
		{label: "a tag", dst: withPort(first(live.Tags)), absent: "the live policy defines no tag"},
		{label: "a host alias", dst: withPort(first(live.Hosts)), absent: "the live policy defines no host alias"},
		{label: "an IPv4 address, no proto", dst: "192.0.2.1:22"},
		{label: "an IPv4 address, proto tcp", dst: "192.0.2.1:22", proto: "tcp"},
		{label: "a bracketed IPv6 address", dst: "[2001:db8::1]:22"},
		{label: "a user", dst: withPort(first(live.Logins)), absent: "the live policy has no group member written as an address"},
		{label: "a service", dst: withPort(first(live.Services)), absent: "the live policy names no svc: service"},
		{label: "ICMP, port 0, proto icmp", dst: "192.0.2.1:0", proto: "icmp"},
		{label: "ICMP, port 0, no proto", dst: "192.0.2.1:0"},
		{label: "a CIDR (a kind tests refuse)", dst: "192.0.2.0/24:22", refuse: true},
		{label: "autogroup:internet (a kind tests refuse)", dst: "autogroup:internet:22", refuse: true},
	}
	for _, k := range kinds {
		if k.dst == "" {
			x.Skip(k.absent)
			continue
		}
		test := map[string]any{"src": src, "accept": []string{k.dst}, "deny": []string{k.dst}}
		if k.proto != "" {
			test["proto"] = k.proto
		}
		body, err := json.Marshal([]any{test})
		if err != nil {
			return err
		}
		want := "one line in the verdict grammar"
		if k.refuse {
			want = "unevaluable: an error that is not in the verdict grammar"
		}
		s, err := x.PostLive(ctx, step(k.label+", accepted and denied together", want), "application/json", body)
		if err != nil {
			return err
		}
		if k.refuse {
			x.Check(k.label+" comes back unevaluable", true, s.ErrorLines() > 0 && s.Grammar() == 0)
		} else {
			x.Check(k.label+" yields one line in the verdict grammar", true, s.Grammar() == 1)
		}
	}
	return nil
}

func a9(ctx context.Context, x *Exec) error {
	live, err := x.Live(ctx)
	switch {
	case err != nil && (x.stopped != nil || ctx.Err() != nil):
		return err
	case err != nil:
		// The canary does not need the live policy: run it, and say what was not run.
		x.Skip("the live policy could not be read, so no tests-mode request has a source")
	case live.source() == "":
		x.Skip("the live policy defines no tag, no login and no group, so no tests-mode request has a source")
	default:
		if err := a9Tests(ctx, x, live, live.source()); err != nil {
			return err
		}
	}
	for _, c := range []struct{ label, acls string }{{"the canary, acls absent (allow-all)", ``}, {"the canary, acls [] (deny-all)", `"acls":[],`}} {
		tag := "tag:tailkeeper-canary-" + x.Hex(8)
		doc := `{"tagOwners":{"` + tag + `":[]},` + c.acls + `"tests":[{"src":"` + tag + `","accept":["192.0.2.1:1"],"deny":["192.0.2.1:1"]}]}`
		s, err := x.PostPolicy(ctx, step(c.label, "exactly one failed assertion, whose src is the canary tag"), doc)
		if err != nil {
			return err
		}
		es := s.Entries()
		x.Check(c.label+" yields one line in the verdict grammar", true, s.Grammar() == 1)
		x.Check(c.label+" names the canary tag as its src", true, len(es) == 1 && es[0].User == tag)
	}
	return nil
}

func a10(ctx context.Context, x *Exec) error {
	const head = `{"tagOwners":{"tag:p":[]},"acls":[{"action":"accept","src":["tag:p"],"dst":["tag:p:*"]}],` +
		`"ssh":[{"action":"accept","src":["tag:p"],"dst":["tag:p"],"users":["root"]}],`
	both, err := x.PostPolicy(ctx, step("a failing and a passing sshTests entry", "the failure has the SSH form"),
		head+`"sshTests":[{"src":"tag:p","dst":["tag:p"],"accept":["root"]},{"src":"tag:p","dst":["tag:p"],"accept":["nobody"]}]}`)
	if err != nil {
		return err
	}
	passing, err := x.PostPolicy(ctx, step("the passing sshTests entry alone", "passes"),
		head+`"sshTests":[{"src":"tag:p","dst":["tag:p"],"accept":["root"]}]}`)
	if err != nil {
		return err
	}
	x.Check("sshTests run: the failure has the SSH form", true, both.TextHas("ssh user"))
	x.Check("the passing entry alone passes", true, passing.Passes())
	if !both.BodyHas("unknown field") {
		return nil
	}
	// The server does not know sshTests: try the live text plus a test built from its first ssh rule.
	live, err := x.Live(ctx)
	if err != nil {
		return err
	}
	doc, ok := sshFallback(live, x.Hex(8))
	if !ok {
		x.Skip("the live policy has no ssh rule a test can be built from")
		return nil
	}
	fb, err := x.PostLive(ctx, step("the live text plus a failing sshTests entry built from its first ssh rule", "the failure has the SSH form"), "application/hujson", doc)
	if err != nil {
		return err
	}
	x.Fact("the fallback shows the SSH form", fb.TextHas("ssh user"))
	return nil
}

// sshFallback returns the live text with one failing sshTests entry added, built from the
// first ssh rule whose source and destination are a tag or a group. It exists only in memory.
func sshFallback(l *Live, suffix string) ([]byte, bool) {
	named := func(s string) bool { return strings.HasPrefix(s, "tag:") || strings.HasPrefix(s, "group:") }
	for _, r := range l.SSH {
		if len(r.Src) == 0 || len(r.Dst) == 0 || !named(r.Src[0]) || !named(r.Dst[0]) {
			continue
		}
		std, err := hujson.Standardize(append([]byte(nil), l.Text...))
		if err != nil {
			return nil, false
		}
		var doc map[string]json.RawMessage
		if json.Unmarshal(std, &doc) != nil {
			return nil, false
		}
		var tests []json.RawMessage
		_ = json.Unmarshal(doc["sshTests"], &tests)
		entry, _ := json.Marshal(map[string]any{"src": r.Src[0], "dst": []string{r.Dst[0]}, "accept": []string{"probe-nobody-" + suffix}})
		doc["sshTests"], _ = json.Marshal(append(tests, entry))
		out, err := json.Marshal(doc)
		return out, err == nil
	}
	return nil, false
}

func a11(ctx context.Context, x *Exec) error {
	raw := []byte("// probe\n{\n  \"tagOwners\": {\"tag:p\": [],},\n  \"acls\": [],\n}\n")
	std, err := hujson.Standardize(append([]byte(nil), raw...))
	if err != nil {
		return err
	}
	bom := append([]byte("\xef\xbb\xbf"), raw...)
	steps := []struct {
		label, expect string
		body          []byte
	}{
		{"raw HuJSON, a leading comment and trailing commas", "accepted", raw},
		{"the same, standardized", "accepted", std},
		{"the same, with a byte order mark", "rejected", bom},
	}
	var seen []Seen
	for _, st := range steps {
		s, err := x.Post(ctx, step(st.label, st.expect), "application/hujson", st.body)
		if err != nil {
			return err
		}
		seen = append(seen, s)
	}
	x.Check("raw HuJSON is accepted", true, seen[0].Accepted())
	x.Check("standardized HuJSON is accepted", true, seen[1].Accepted())
	x.Check("a byte order mark is rejected", true, seen[2].Status == 400)
	return nil
}

func a12(ctx context.Context, x *Exec) error {
	live, err := x.Live(ctx)
	if err != nil {
		return err
	}
	src := live.source()
	if src == "" {
		x.Skip("the live policy defines no tag, no login and no group, so there is no source for a test")
		return nil
	}
	body, err := json.Marshal([]any{map[string]any{"src": src, "deny": []string{"192.0.2.1:1"}}})
	if err != nil {
		return err
	}
	s, err := x.PostLive(ctx, step("one test that should pass", "no results for any other source"), "application/json", body)
	if err != nil {
		return err
	}
	other := 0
	for _, e := range s.Entries() {
		if e.User != src {
			other++
		}
	}
	x.Count("data entries for another source", other)
	// Without a stored test nothing can fail, so "no other result" would match whatever the
	// API does: say so, and leave the question open instead of recording a confirmation.
	x.Fact("the live policy has stored tests", live.StoredTests > 0)
	if live.StoredTests > 0 {
		x.Check("no entry names another source", true, s.Accepted() && other == 0)
	}
	return nil
}

func a13(ctx context.Context, x *Exec) error {
	s, err := x.GetPolicy(ctx, step("the policy as HuJSON", "an ETag equal to sha256(hujson.Format(body))"), api.PolicyGet{Accept: "application/hujson"})
	if err != nil {
		return err
	}
	etag := strings.Trim(strings.TrimPrefix(s.ETag, "W/"), `"`)
	formatted, ferr := hujson.Format(append([]byte(nil), s.Body...))
	sum := sha256.Sum256(formatted)
	raw := sha256.Sum256(s.Body)
	x.Fact("hujson.Format accepted the body", ferr == nil)
	x.Fact("sha256 of the raw body equals the ETag", etag != "" && hex.EncodeToString(raw[:]) == etag)
	x.Check("sha256(hujson.Format(body)) equals the ETag", true, ferr == nil && etag != "" && hex.EncodeToString(sum[:]) == etag)
	return nil
}

func a14(ctx context.Context, x *Exec) error {
	login := "nobody-" + x.Hex(8) + "@example.com"
	docs := []struct{ label, doc string }{
		{"in groups", `{"groups":{"group:p":["` + login + `"]},"acls":[]}`},
		{"in tagOwners", `{"tagOwners":{"tag:p":["` + login + `"]},"acls":[]}`},
		{"as an acls src", `{"tagOwners":{"tag:p":[]},"acls":[{"action":"accept","src":["` + login + `"],"dst":["tag:p:22"]}]}`},
		{"as an ssh src", `{"tagOwners":{"tag:p":[]},"acls":[],"ssh":[{"action":"accept","src":["` + login + `"],"dst":["tag:p"],"users":["root"]}]}`},
		{"as a test src", `{"tagOwners":{"tag:p":[]},"acls":[],"tests":[{"src":"` + login + `","deny":["tag:p:22"]}]}`},
		{"as an object key (in hosts)", `{"hosts":{"` + login + `":"192.0.2.1"},"acls":[]}`},
	}
	accepted, rejected := 0, 0
	clean := true
	sigs, rejections := map[string]bool{}, map[string]bool{}
	for _, d := range docs {
		s, err := x.PostPolicy(ctx, step("a login that cannot exist, "+d.label, "the same rejection, or a pass that does not depend on the user existing"), d.doc)
		if err != nil {
			return err
		}
		sigs[s.signature()] = true
		switch {
		case s.Passes(): // a 200 that carries an error line is neither a pass nor the same rejection
			accepted++
			if len(s.WarningLines()) > 0 {
				clean = false
			}
		case s.Status == 400 && s.Bare():
			rejected++
			rejections[s.signature()] = true
		}
	}
	x.Count("distinct answers across the six positions", len(sigs))
	x.Check("an accepted position exists and none carries a warning about the login", true, accepted > 0 && clean)
	x.Check("acceptance does not vary across the six positions", true, accepted+rejected == len(docs) && (accepted == 0 || rejected == 0))
	x.Check("every rejection is the same rejection", true, accepted+rejected == len(docs) && len(rejections) <= 1)
	return nil
}

// h1 asks the configuration audit log for ACL updates and looks, in memory, at whether
// old and new hold a policy text. It reports counts and booleans only.
func h1(ctx context.Context, x *Exec) error {
	const day = 24 * time.Hour
	end := time.Now().UTC()
	entries, usable, known, strs := 0, 0, 0, 0
	for window := 0; window < 3 && entries == 0; window++ {
		start := end.Add(-31 * day)
		q := url.Values{"start": {start.Format(time.RFC3339)}, "end": {end.Format(time.RFC3339)}, "event": {"TAILNET.UPDATE.ACL"}}
		s, err := x.GetJSON(ctx, step("ACL update entries in a 31-day window", "entries whose old and new are policy texts"), "/logging/configuration", q)
		if err != nil {
			return err
		}
		if s.Status != 200 {
			x.Fact("the audit log answered 200", false)
			return nil
		}
		var body struct {
			Logs []struct {
				Old json.RawMessage `json:"old"`
				New json.RawMessage `json:"new"`
			} `json:"logs"`
		}
		if json.Unmarshal(s.Body, &body) != nil {
			x.Fact("the audit log answer is a JSON object with logs", false)
			return nil
		}
		for _, l := range body.Logs {
			entries++
			oldText, newText := policyText(l.Old), policyText(l.New)
			if oldText.isString && newText.isString {
				strs++
			}
			if oldText.isString && newText.isString && oldText.isObject && newText.isObject {
				usable++
			}
			if oldText.isString && newText.isString && oldText.hasKnown && newText.hasKnown {
				known++
			}
		}
		end = start
	}
	x.Count("ACL update entries seen", entries)
	x.Fact("old and new are JSON strings", entries > 0 && strs == entries)
	x.Count("entries whose old and new parse as a policy object", usable)
	x.Count("entries whose old and new also hold a known section", known)
	x.Check("every ACL update entry holds old and new policy texts with a known section", true, entries > 0 && known == entries)
	return nil
}

// knownSections are the top-level keys of a policy, lower case.
var knownSections = map[string]bool{
	"acls": true, "autoapprovers": true, "grants": true, "groups": true, "hosts": true, "ipsets": true, "nodeattrs": true,
	"postures": true, "ssh": true, "sshtests": true, "tagowners": true, "tests": true, "derpmap": true, "disableipv4": true,
	"onecgnatroute": true, "randomizeclientport": true, "defaultsrcposture": true, "extradnsrecords": true,
	"externaltailnets": true, "attrconfig": true,
}

// textKind is what an audit entry's old or new is: whether it is a JSON string, whether
// the text (or the value itself) parses as a HuJSON object, and whether that object holds a known section.
type textKind struct{ isString, isObject, hasKnown bool }

// policyText classifies v, an audit entry's old or new. An object given as a JSON object
// (not as a string) is classified too, so the caller can tell the two apart; the row asks for strings.
func policyText(v json.RawMessage) textKind {
	b := []byte(v)
	var k textKind
	var str string
	if strings.TrimSpace(string(v)) != "null" && json.Unmarshal(v, &str) == nil { // null unmarshals into a string without error; it is not one
		k.isString = true
		b = []byte(str)
	}
	std, err := hujson.Standardize(append([]byte(nil), b...))
	if err != nil {
		return k
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(std, &obj) != nil || obj == nil {
		return k
	}
	k.isObject = true
	for key := range obj {
		if knownSections[strings.ToLower(key)] {
			k.hasKnown = true
			break
		}
	}
	return k
}
