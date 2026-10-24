package tools_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// boundLine is one entry of the configuration log: an ACL update by an actor with tags.
type boundLine struct {
	EventTime    string `json:"eventTime"`
	DeferredAt   string `json:"deferredAt,omitempty"`
	EventGroupID string `json:"eventGroupID"`
	Origin       string `json:"origin"`
	Action       string `json:"action"`
	Target       struct {
		ID   string `json:"id,omitempty"`
		Type string `json:"type,omitempty"`
	} `json:"target"`
	Actor struct {
		ID          string   `json:"id"`
		Type        string   `json:"type"`
		LoginName   string   `json:"loginName"`
		DisplayName string   `json:"displayName"`
		Tags        []string `json:"tags,omitempty"`
	} `json:"actor"`
	Old string `json:"old"`
	New string `json:"new"`
}

// boundLog is a log of n updates a minute apart, the newest a minute before the tests' clock.
func boundLog(n int, fill func(i int, l *boundLine)) string {
	logs := make([]boundLine, n)
	for i := range logs {
		l := &logs[i]
		l.EventTime = now.Add(-time.Duration(n-i) * time.Minute).Format(time.RFC3339)
		l.EventGroupID, l.Origin, l.Action = fmt.Sprintf("g%03d", i), "ADMIN_CONSOLE", "UPDATE"
		l.Actor.ID, l.Actor.Type, l.Actor.LoginName, l.Actor.DisplayName = "u1", "user", "amy@example.com", "Amy"
		l.Old, l.New = `{"tagOwners":{}}`, fmt.Sprintf(`{"tagOwners":{"tag:t%d":[]}}`, i)
		fill(i, l)
	}
	b, err := json.Marshal(struct {
		Logs []boundLine `json:"logs"`
	}{logs})
	if err != nil {
		panic(err)
	}
	return string(b)
}

// shownActor is the part of a result's actor the tests read, decoded apart from the tools' own
// types.
type shownActor struct {
	Tags []string `json:"tags"`
}

func manyTags(n int, tag string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = tag
	}
	return out
}

// An actor with thousands of tags takes a bounded part of a result in audit_log and in
// acl_history, which show an actor the same way, and the result counts what it left out.
func TestAnActorsTagsAreCutToTheFirstThatFitAndTheRestIsCounted(t *testing.T) {
	type shown struct {
		Note    string `json:"note"`
		Entries []struct {
			Actor shownActor `json:"actor"`
		} `json:"entries"`
		Versions []struct {
			Actor shownActor `json:"actor"`
		} `json:"versions"`
	}
	for _, tool := range []string{"audit_log", "acl_history"} {
		t.Run(tool, func(t *testing.T) {
			f, reg, env := apiEnv(t)
			serveHistory(f, boundLog(2, func(i int, l *boundLine) {
				if i == 0 {
					l.Actor.Tags = manyTags(3500, strings.Repeat(`"`, 1000))
				} else {
					l.Actor.Tags = []string{"tag:ci", "tag:web"}
				}
			}))
			var out shown
			raw := mustCall(t, reg, env, tool, `{}`, &out)
			actors := []shownActor{}
			for _, e := range out.Entries {
				actors = append(actors, e.Actor)
			}
			for _, v := range out.Versions {
				actors = append(actors, v.Actor)
			}
			if len(actors) != 2 {
				t.Fatalf("%d actors in %s", len(actors), raw)
			}
			// The first tags that fit are shown, and a last entry counts the others.
			got := actors[0].Tags
			if len(got) == 0 || len(got) > 17 || got[len(got)-1] != fmt.Sprintf("(%d more not shown)", 3500-(len(got)-1)) {
				t.Errorf("the 3,500 tags show %d entries ending in %q", len(got), got[len(got)-1])
			}
			if len(actors[1].Tags) != 2 || actors[1].Tags[1] != "tag:web" {
				t.Errorf("two short tags show %v", actors[1].Tags)
			}
			if !strings.Contains(out.Note, "counts the rest") {
				t.Errorf("the note does not say that tags were left out: %q", out.Note)
			}
			if len(raw) > 64<<10 {
				t.Errorf("the result is %d bytes: the tags were not bounded", len(raw))
			}
		})
	}
	// Without a long list nothing is said.
	f, reg, env := apiEnv(t)
	serveHistory(f, boundLog(1, func(_ int, l *boundLine) { l.Actor.Tags = []string{"tag:ci"} }))
	for _, tool := range []string{"audit_log", "acl_history"} {
		var out shown
		raw := mustCall(t, reg, env, tool, `{}`, &out)
		if strings.Contains(raw, "not shown") || strings.Contains(out.Note, "counts the rest") {
			t.Errorf("%s says tags were left out of an actor with one: %s", tool, raw)
		}
	}
}

// Tags that fit are the first ones, in order, and a tag over the room is not skipped for a
// shorter one after it.
func TestTheTagsAnActorShowsAreTheFirstOnesInOrder(t *testing.T) {
	f, reg, env := apiEnv(t)
	var tags []string
	for i := range 40 {
		tags = append(tags, fmt.Sprintf("tag:t%02d", i))
	}
	serveHistory(f, boundLog(1, func(_ int, l *boundLine) { l.Actor.Tags = tags }))
	var out struct {
		Versions []struct {
			Actor shownActor `json:"actor"`
		} `json:"versions"`
	}
	mustCall(t, reg, env, "acl_history", `{}`, &out)
	got := out.Versions[0].Actor
	if len(got.Tags) != 17 || got.Tags[0] != "tag:t00" || got.Tags[15] != "tag:t15" || got.Tags[16] != "(24 more not shown)" {
		t.Fatalf("%d tags %v: want the first 16 and the count of the other 24", len(got.Tags), got.Tags)
	}
	// The room is spent as tags are shown: tags of 100 angle brackets cost 603 characters each,
	// and six of them fit in 4,096.
	f, reg, env = apiEnv(t)
	serveHistory(f, boundLog(1, func(_ int, l *boundLine) { l.Actor.Tags = manyTags(40, strings.Repeat("<", 100)) }))
	out.Versions = nil
	mustCall(t, reg, env, "acl_history", `{}`, &out)
	if got := out.Versions[0].Actor.Tags; len(got) != 7 || got[6] != "(34 more not shown)" {
		t.Fatalf("%d entries %.60v: want six tags and the count of 34", len(got), got)
	}
	// A first tag that is over the room ends the list: the short tag after it is not shown.
	f, reg, env = apiEnv(t)
	serveHistory(f, boundLog(1, func(_ int, l *boundLine) {
		l.Actor.Tags = []string{strings.Repeat("<", 1000), "tag:ci"}
	}))
	out.Versions = nil
	mustCall(t, reg, env, "acl_history", `{}`, &out)
	if got := out.Versions[0].Actor; len(got.Tags) != 1 || got.Tags[0] != "(2 more not shown)" {
		t.Fatalf("tags %v: want none shown and 2 counted", got.Tags)
	}
}

// A page of acl_history ends where its versions fill the budget, says so, and the next page
// starts at the next version: every version is listed once.
func TestAHistoryPageEndsWhereItsVersionsFillTheBudgetAndTheNextPageContinues(t *testing.T) {
	const entries = 60
	f, reg, env := apiEnv(t)
	// An origin of 1,000 angle brackets and six tags of 100: about 10,000 bytes a version.
	serveHistory(f, boundLog(entries, func(_ int, l *boundLine) {
		l.Origin, l.Actor.Tags = strings.Repeat("<", 1000), manyTags(6, strings.Repeat("<", 100))
	}))
	type page struct {
		Count      int    `json:"count"`
		NextCursor string `json:"nextCursor"`
		Note       string `json:"note"`
		Versions   []struct {
			Version   string `json:"version"`
			EventTime string `json:"eventTime"`
		} `json:"versions"`
	}
	seen := map[string]int{}
	args, pages := `{"limit":50}`, 0
	for {
		var p page
		raw := mustCall(t, reg, env, "acl_history", args, &p)
		pages++
		if len(raw) > 200000 {
			t.Fatalf("page %d is %d bytes, over the 200,000 the tool declares", pages, len(raw))
		}
		if p.Count == 0 || pages > entries {
			t.Fatalf("page %d holds %d versions", pages, p.Count)
		}
		if p.NextCursor != "" && p.Count < 50 && !strings.Contains(p.Note, "nextCursor") {
			t.Errorf("page %d ended early and its note does not say so: %q", pages, p.Note)
		}
		for _, v := range p.Versions {
			seen[v.Version]++
		}
		if p.NextCursor == "" {
			break
		}
		args = fmt.Sprintf(`{"limit":50,"cursor":%q}`, p.NextCursor)
	}
	if pages < 2 {
		t.Fatalf("%d versions of 10,000 bytes each came in %d page: the budget did not end a page", entries, pages)
	}
	if len(seen) != entries {
		t.Fatalf("%d distinct versions over %d pages, want %d", len(seen), pages, entries)
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("version %s listed %d times", id, n)
		}
	}
}

// A version whose strings are as long as the log lets them be is listed, and one page of them
// is under the budget.
func TestAVersionOfLongStringsIsBoundedByItsCaps(t *testing.T) {
	f, reg, env := apiEnv(t)
	long := strings.Repeat("<", 4000)
	serveHistory(f, boundLog(1, func(_ int, l *boundLine) {
		l.EventGroupID, l.Origin, l.Actor.ID, l.Actor.Type = long, long, long, long
		l.Actor.LoginName, l.Actor.DisplayName, l.Actor.Tags = long, long, []string{long}
	}))
	raw := mustCall(t, reg, env, "acl_history", `{}`, nil)
	if len(raw) > 40<<10 {
		t.Fatalf("one version of long strings is %d bytes", len(raw))
	}
}

// Every id acl_history writes is one acl_diff accepts: a group or a time longer than any the
// log writes does not make an id over the length acl_diff reads.
func TestEveryVersionIdTheHistoryWritesIsOneTheDiffAccepts(t *testing.T) {
	for name, c := range map[string]struct{ group, when string }{
		"a group of 400 angle brackets": {strings.Repeat("<", 400), "2026-10-08T00:00:00Z"},
		"a group of 9,000 letters":      {strings.Repeat("x", 9000), "2026-10-08T00:00:00Z"},
		// 160 bytes as JSON text, quotes included: the longest group an id carries as it is.
		"a group of 158 letters":             {strings.Repeat("x", 158), "2026-10-08T00:00:00Z"},
		"a group of the digest's own length": {"sha256:" + strings.Repeat("a", 64), "2026-10-08T00:00:00Z"},
		"a time of 400 fractional zeros":     {"g", "2026-10-08T00:00:00." + strings.Repeat("0", 400) + "Z"},
		"a group of 398 letters":             {strings.Repeat("x", 398), "2026-10-08T00:00:00Z"},
		"a time of 60 fractional digits":     {strings.Repeat("g", 150), "2026-10-08T00:00:00." + strings.Repeat("1", 9) + strings.Repeat("0", 51) + "+00:00"},
	} {
		t.Run(name, func(t *testing.T) {
			f, reg, env := apiEnv(t)
			serveHistory(f, historyLogs(historyLine(c.when, c.group, "ADMIN_CONSOLE", "amy@example.com",
				`{"tagOwners":{"tag:a":[]}}`, `{"tagOwners":{"tag:a":[],"tag:b":[]}}`)))
			var hist tools.ACLHistoryOutput
			mustCall(t, reg, env, "acl_history", `{}`, &hist)
			if len(hist.Versions) != 1 {
				t.Fatalf("%d versions", len(hist.Versions))
			}
			v := hist.Versions[0]
			if len(v.Version) > 512 || len(v.Previous) > 512 {
				t.Fatalf("ids of %d and %d bytes: acl_diff reads at most 512", len(v.Version), len(v.Previous))
			}
			var out tools.ACLDiffOutput
			mustCall(t, reg, env, "acl_diff", fmt.Sprintf(`{"fromVersion":%q,"toVersion":%q}`, v.Previous, v.Version), &out)
			if out.Status != "changed" {
				t.Fatalf("the diff of the version and its previous is %s, want changed", out.Status)
			}
		})
	}
}

// The ids of two long groups that differ stay different, and the same group gives the same id.
func TestTwoLongGroupsKeepTheirOwnVersionIds(t *testing.T) {
	f, reg, env := apiEnv(t)
	a, b := strings.Repeat("a", 500), strings.Repeat("a", 499)+"b"
	when := "2026-10-08T00:00:00Z"
	serveHistory(f, historyLogs(
		historyLine(when, a, "ADMIN_CONSOLE", "amy@example.com", `{"tagOwners":{}}`, `{"tagOwners":{"tag:a":[]}}`),
		historyLine(when, b, "ADMIN_CONSOLE", "amy@example.com", `{"tagOwners":{}}`, `{"tagOwners":{"tag:b":[]}}`),
	))
	var hist tools.ACLHistoryOutput
	mustCall(t, reg, env, "acl_history", `{}`, &hist)
	if len(hist.Versions) != 2 || hist.Versions[0].Version == hist.Versions[1].Version {
		t.Fatalf("%+v", hist.Versions)
	}
	// The version of each group names its own text.
	for i, want := range []string{"tag:a", "tag:b"} {
		var out tools.ACLDiffOutput
		raw := mustCall(t, reg, env, "acl_diff", fmt.Sprintf(`{"fromVersion":%q,"toVersion":%q}`, hist.Versions[i].Previous, hist.Versions[i].Version), &out)
		if !strings.Contains(raw, want) {
			t.Errorf("the diff of version %d does not name %s:\n%s", i, want, raw)
		}
	}
}

// dnsConfigBody is a DNS configuration whose nameservers, split-DNS domains and search paths
// number n each, with 900-byte names.
func dnsConfigBody(kind string, n int) string {
	name := func(i int) string { return fmt.Sprintf("%d.%s", i, strings.Repeat("a", 900)) }
	var parts []string
	switch kind {
	case "nameservers":
		for i := range n {
			parts = append(parts, fmt.Sprintf(`{"address":%q}`, name(i)))
		}
		return `{"nameservers":[` + strings.Join(parts, ",") + `],"preferences":{}}`
	case "splitDns":
		for i := range n {
			parts = append(parts, fmt.Sprintf(`%q:[{"address":"192.0.2.53"}]`, name(i)))
		}
		return `{"nameservers":[],"splitDNS":{` + strings.Join(parts, ",") + `},"preferences":{}}`
	}
	for i := range n {
		parts = append(parts, fmt.Sprintf("%q", name(i)))
	}
	return `{"nameservers":[],"searchPaths":[` + strings.Join(parts, ",") + `],"preferences":{}}`
}

// dns_get lists what its policy holds up to a budget of characters for all its lists
// together, says so, and keeps the start.
func TestDNSGetCutsItsListsToOneBudgetAndSaysSo(t *testing.T) {
	targets := manyTags(100, strings.Repeat("<", 600))
	var entries []map[string]any
	for range 65 {
		entries = append(entries, map[string]any{"target": targets, "attr": []string{"nextdns:abc", "controld:def", "magicdns-aaaa"}})
	}
	var policy strings.Builder
	enc := json.NewEncoder(&policy)
	enc.SetEscapeHTML(false) // an angle bracket is one byte in the policy, as Tailscale holds it
	if err := enc.Encode(map[string]any{"nodeAttrs": entries}); err != nil {
		t.Fatal(err)
	}
	if policy.Len() > 4<<20 {
		t.Fatalf("the policy is %d bytes, over the 4 MiB the tool reads", policy.Len())
	}
	f, reg, env := apiEnv(t)
	serveDNS(f, policy.String())
	out, raw := dnsCall(t, env, reg)
	if len(raw) > 130000 {
		t.Fatalf("the result is %d bytes: its lists were not bounded", len(raw))
	}
	if note := out.PolicyNote; !out.Truncated || note == "" || !out.PolicyOverridesAnalysed ||
		len(out.ControlD) != 1 || len(out.ControlD[0].Targets) == 0 || len(out.ControlD[0].Targets) >= 100 {
		t.Fatalf("truncated %v, note %q, analysed %v, controlD %+v: want a cut result that still lists the start of its first entry\n%.300s", out.Truncated, note, out.PolicyOverridesAnalysed, len(out.ControlD), raw)
	}
	// The same lists of ordinary size are not cut and have no note.
	f, reg, env = apiEnv(t)
	serveDNS(f, dnsAttrPolicy(manyDNS("tag:t", 100), []string{"nextdns:abc", "controld:def", "magicdns-aaaa"}))
	out, _ = dnsCall(t, env, reg)
	if note := out.PolicyNote; out.Truncated || note != "" || len(out.NextDNS) != 1 || len(out.NextDNS[0].Targets) != 100 {
		t.Fatalf("an ordinary policy: truncated %v, note %q, %+v", out.Truncated, note, out.NextDNS)
	}
}

// The configuration the API reports is bounded by the same budget, in each of its lists.
func TestDNSGetCutsTheConfigurationItReadsToTheSameBudget(t *testing.T) {
	for _, c := range []struct {
		kind  string
		count func(tools.DNSOutput) int
	}{
		{"nameservers", func(o tools.DNSOutput) int { return len(o.Nameservers) }},
		{"splitDns", func(o tools.DNSOutput) int { return len(o.SplitDNS) }},
		{"searchPaths", func(o tools.DNSOutput) int { return len(o.SearchPaths) }},
	} {
		t.Run(c.kind, func(t *testing.T) {
			f, reg, env := apiEnv(t)
			f.JSON("GET", tailnetPath+"/dns/configuration", 200, dnsConfigBody(c.kind, 4000))
			servePolicy(f, "{}\n", `"e1"`)
			out, raw := dnsCall(t, env, reg)
			if len(raw) > 130000 {
				t.Fatalf("the result is %d bytes: the %s were not bounded", len(raw), c.kind)
			}
			if got := c.count(out); got == 0 || got >= 4000 || !out.Truncated || out.PolicyNote != cutSentence {
				t.Fatalf("%d %s, truncated %v, note %q", got, c.kind, out.Truncated, out.PolicyNote)
			}
		})
	}
}

// The sentence dns_get gives when the budget cut its lists.
const cutSentence = "the result was cut to its size limit: what is listed is the start of what the tailnet holds"

// Each list drawn from the policy is cut at the budget, and a result lists a start of what the
// policy holds: once something did not fit, nothing after it does, though it is short.
func TestDNSGetCutsEachListOfThePolicyAndKeepsAStart(t *testing.T) {
	long := strings.Repeat("<", 600)
	enc := func(v any) string {
		var b strings.Builder
		e := json.NewEncoder(&b)
		e.SetEscapeHTML(false)
		if err := e.Encode(v); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	var records []map[string]string
	var others []string
	for i := range 100 {
		records = append(records, map[string]string{"Name": fmt.Sprintf("%03d%s", i, long), "Type": "A", "Value": long})
		others = append(others, fmt.Sprintf("other-%03d%s", i, long))
	}
	for name, c := range map[string]struct {
		policy string
		count  func(tools.DNSOutput) int
	}{
		"extra records": {enc(map[string]any{"extraDNSRecords": records}), func(o tools.DNSOutput) int { return len(o.ExtraRecords) }},
		"other attributes": {enc(map[string]any{"nodeAttrs": []map[string]any{{"target": []string{"*"}, "attr": others}}}),
			func(o tools.DNSOutput) int { return len(o.OtherAttrs) }},
		"targets of a node attribute": {enc(map[string]any{"nodeAttrs": []map[string]any{{"target": manyTags(100, long), "attr": []string{"magicdns-aaaa"}}}}),
			func(o tools.DNSOutput) int {
				if len(o.DNSNodeAttrs) != 1 {
					return -1
				}
				return len(o.DNSNodeAttrs[0].Targets)
			}},
		"targets of a profile": {enc(map[string]any{"nodeAttrs": []map[string]any{{"target": manyTags(100, long), "attr": []string{"nextdns:abc"}}}}),
			func(o tools.DNSOutput) int {
				if len(o.NextDNS) != 1 {
					return -1
				}
				return len(o.NextDNS[0].Targets)
			}},
	} {
		t.Run(name, func(t *testing.T) {
			f, reg, env := apiEnv(t)
			serveDNS(f, c.policy)
			out, raw := dnsCall(t, env, reg)
			if len(raw) > 130000 {
				t.Fatalf("the result is %d bytes", len(raw))
			}
			if got := c.count(out); got < 1 || got >= 100 || !out.Truncated || out.PolicyNote != cutSentence {
				t.Fatalf("lists %d, truncated %v, note %q: want a start of 100 and the sentence", got, out.Truncated, out.PolicyNote)
			}
		})
	}
	// Once an entry did not fit, a short entry after it is not listed either.
	short := manyDNS("tag:t", 3)
	policy := enc(map[string]any{"nodeAttrs": []map[string]any{
		{"target": manyTags(100, long), "attr": []string{"controld:first"}},
		{"target": short, "attr": []string{"controld:second"}},
	}})
	f, reg, env := apiEnv(t)
	serveDNS(f, policy)
	out, raw := dnsCall(t, env, reg)
	if len(out.ControlD) != 1 || strings.Contains(raw, "tag:t00") {
		t.Fatalf("controlD %+v: want the first entry alone, cut", out.ControlD)
	}
}

// A page of audit_log ends where its entries fill the budget, says so, and the next page
// starts at the next entry: every entry is listed once. The fields the registry does not cap
// are cut by the tool.
func TestAnAuditLogPageEndsWhereItsEntriesFillTheBudgetAndTheNextPageContinues(t *testing.T) {
	const entries = 300
	f, reg, env := apiEnv(t)
	lots := strings.Repeat("<", 1000)
	body := boundLog(entries, func(i int, l *boundLine) {
		if i == 0 { // a time written with more digits than any time is
			l.EventTime = strings.TrimSuffix(l.EventTime, "Z") + "." + strings.Repeat("0", 400) + "Z"
		}
		l.Origin = lots
		l.EventGroupID = strings.Repeat("g", 5000)
		l.Actor.ID = strings.Repeat("u", 5000)
		l.Target.ID, l.Target.Type = lots, lots
	})
	serveHistory(f, body)
	type page struct {
		Count      int    `json:"count"`
		NextCursor string `json:"nextCursor"`
		Note       string `json:"note"`
		Entries    []struct {
			EventTime    string `json:"eventTime"`
			EventGroupID string `json:"eventGroupId"`
			Actor        struct {
				ID string `json:"id"`
			} `json:"actor"`
		} `json:"entries"`
	}
	seen := map[string]int{}
	args, pages := `{"limit":300}`, 0
	for {
		var p page
		raw := mustCall(t, reg, env, "audit_log", args, &p)
		pages++
		if len(raw) > 1100000 {
			t.Fatalf("page %d is %d bytes, over the budget", pages, len(raw))
		}
		if p.Count == 0 || pages > entries {
			t.Fatalf("page %d holds %d entries", pages, p.Count)
		}
		if p.NextCursor != "" && !strings.Contains(p.Note, "continue with nextCursor") {
			t.Errorf("page %d ended early and its note does not say so: %q", pages, p.Note)
		}
		for _, e := range p.Entries {
			seen[e.EventTime]++
			if len(e.EventTime) > 64 {
				t.Fatalf("a time of %d bytes in an entry", len(e.EventTime))
			}
			if len(e.EventGroupID) > 300 || len(e.Actor.ID) > 300 {
				t.Fatalf("a group of %d bytes and an actor id of %d bytes in an entry", len(e.EventGroupID), len(e.Actor.ID))
			}
		}
		if p.NextCursor == "" {
			break
		}
		args = fmt.Sprintf(`{"limit":300,"cursor":%q}`, p.NextCursor)
	}
	if pages < 2 {
		t.Fatalf("%d entries came in %d page: the budget did not end a page", entries, pages)
	}
	if len(seen) != entries {
		t.Fatalf("%d distinct entries over %d pages, want %d", len(seen), pages, entries)
	}
	for when, n := range seen {
		if n != 1 {
			t.Errorf("entry %s listed %d times", when, n)
		}
	}
}

// longStrings reports every string in v longer than max, with the path it sits at.
func longStrings(v any, path string, max int) []string {
	var out []string
	switch x := v.(type) {
	case string:
		if len(x) > max {
			out = append(out, fmt.Sprintf("%s is %d bytes", path, len(x)))
		}
	case []any:
		for i, e := range x {
			out = append(out, longStrings(e, fmt.Sprintf("%s[%d]", path, i), max)...)
		}
	case map[string]any:
		for k, e := range x {
			out = append(out, longStrings(e, path+"."+k, max)...)
		}
	}
	return out
}

// No string of an entry of audit_log, or of a version of acl_history, is longer than the
// registry lets one string be, whichever field of the log carries it: a field the registry does
// not cap is cut by the tool, and one reply that holds a megabyte of one field ends the session
// of a host that reads at most 16 MiB a frame.
func TestNoStringOfAnAuditEntryOrAVersionIsLongerThanTheRegistryAllows(t *testing.T) {
	long := strings.Repeat("<", 100000)
	for name, set := range map[string]func(l *boundLine){
		"origin":        func(l *boundLine) { l.Origin = long },
		"action":        func(l *boundLine) { l.Action = long },
		"deferredAt":    func(l *boundLine) { l.DeferredAt = long },
		"eventGroupID":  func(l *boundLine) { l.EventGroupID = long },
		"target.type":   func(l *boundLine) { l.Target.Type = long },
		"actor.id":      func(l *boundLine) { l.Actor.ID = long },
		"actor.type":    func(l *boundLine) { l.Actor.Type = long },
		"actor.login":   func(l *boundLine) { l.Actor.LoginName = long },
		"actor.display": func(l *boundLine) { l.Actor.DisplayName = long },
		"actor.tags":    func(l *boundLine) { l.Actor.Tags = []string{long, long} },
		"old and new":   func(l *boundLine) { l.Old, l.New = `"`+long+`"`, `"`+long+`x"` },
		"every field at": func(l *boundLine) {
			l.Origin, l.Action, l.DeferredAt, l.EventGroupID, l.Target.ID, l.Target.Type = long, long, long, long, long, long
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, tool := range []string{"audit_log", "acl_history"} {
				f, reg, env := apiEnv(t)
				serveHistory(f, boundLog(1, func(_ int, l *boundLine) { set(l) }))
				args := `{}`
				if tool == "audit_log" {
					args = `{"includeValues":true}`
				}
				var out map[string]any
				raw := mustCall(t, reg, env, tool, args, &out)
				if long := longStrings(out, tool, registry.ResultStringMax); len(long) > 0 {
					t.Errorf("%s: %s (a result of %d bytes)", name, strings.Join(long, "; "), len(raw))
				}
				if len(raw) > 32<<10 {
					t.Errorf("%s: %s is %d bytes for one entry", name, tool, len(raw))
				}
			}
		})
	}
}

// Where the tags of an actor are cut does not depend on the length of a login that the result
// masks: two logins of different lengths that show the same masked form give the same result,
// byte for byte, in audit_log and in acl_history.
func TestTheTagsAnActorShowsDoNotDependOnTheLengthOfAMaskedLogin(t *testing.T) {
	for name, c := range map[string]struct {
		tag       func(login string) string
		shorter   int
		longer    int
		wantShown func(n int) bool
	}{
		// Sixteen tags is the most shown: the character budget is not reached.
		"tags that are a login": {func(l string) string { return "tag:" + l }, 8, 300, func(n int) bool { return n == 17 }},
		// A tag of 260 characters beside its login: fifteen fit the character budget when the
		// login is counted as it is shown, and fewer when it is counted by its length.
		"tags that hold a login beside a long word": {
			func(l string) string { return strings.Repeat("w", 250) + " " + l },
			8, 900, func(n int) bool { return n > 2 && n < 17 },
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, tool := range []string{"audit_log", "acl_history"} {
				var raws []string
				for _, n := range []int{c.shorter, c.longer} {
					f, reg, env := apiEnv(t)
					login := strings.Repeat("a", n) + "@example.com"
					serveHistory(f, boundLog(1, func(_ int, l *boundLine) {
						for range 40 {
							l.Actor.Tags = append(l.Actor.Tags, c.tag(login))
						}
					}))
					var out struct {
						Entries []struct {
							Actor shownActor `json:"actor"`
						} `json:"entries"`
						Versions []struct {
							Actor shownActor `json:"actor"`
						} `json:"versions"`
					}
					raws = append(raws, mustCall(t, reg, env, tool, `{}`, &out))
					var tags []string
					for _, e := range out.Entries {
						tags = e.Actor.Tags
					}
					for _, v := range out.Versions {
						tags = v.Actor.Tags
					}
					if strings.Contains(raws[len(raws)-1], login) || !c.wantShown(len(tags)) {
						t.Fatalf("%s, login of %d: %d entries %.80v: want a masked login and the count this case expects", tool, n, len(tags), tags)
					}
				}
				if raws[0] != raws[1] {
					t.Errorf("%s: a login of %d bytes and one of %d bytes behind one masked form give different results:\n%.400s\n%.400s", tool, c.shorter, c.longer, raws[0], raws[1])
				}
			}
		})
	}
}

// The room for the tags of an actor, 4,096 characters, is spent to the character: a tag costs
// its text with its quotes and the comma after it.
func TestTheTagsOfAnActorFillTheirRoomToTheCharacter(t *testing.T) {
	for name, c := range map[string]struct {
		letters int // the length of every tag
		want    int // the tags shown before the count
	}{
		// 512 characters a tag: eight fill the room exactly, and the eighth is shown.
		"eight tags that fill the room exactly": {509, 8},
		// 258 characters a tag: fifteen fit, and a sixteenth would not.
		"fifteen tags and a sixteenth over the room": {255, 15},
	} {
		t.Run(name, func(t *testing.T) {
			for _, tool := range []string{"audit_log", "acl_history"} {
				f, reg, env := apiEnv(t)
				serveHistory(f, boundLog(1, func(_ int, l *boundLine) { l.Actor.Tags = manyTags(40, strings.Repeat("w", c.letters)) }))
				var out struct {
					Entries []struct {
						Actor shownActor `json:"actor"`
					} `json:"entries"`
					Versions []struct {
						Actor shownActor `json:"actor"`
					} `json:"versions"`
				}
				mustCall(t, reg, env, tool, `{}`, &out)
				var tags []string
				for _, e := range out.Entries {
					tags = e.Actor.Tags
				}
				for _, v := range out.Versions {
					tags = v.Actor.Tags
				}
				if len(tags) != c.want+1 || tags[c.want] != fmt.Sprintf("(%d more not shown)", 40-c.want) {
					t.Errorf("%s: %d entries ending in %q: want %d tags and the count of %d", tool, len(tags), tags[len(tags)-1], c.want, 40-c.want)
				}
			}
		})
	}
}

// Where dns_get cuts its lists does not depend on the length of a value that the result masks:
// two values of different lengths that show the same masked form give the same result, byte
// for byte. A profile id is masked whole, and a login or an address inside a split-DNS domain,
// a search path or a record's type is masked in place.
func TestWhereDNSGetCutsItsListsDoesNotDependOnTheLengthOfAMaskedValue(t *testing.T) {
	word := strings.Repeat("w", 500)
	for name, c := range map[string]struct {
		// serve answers a call whose masked value is n bytes long.
		serve func(f *apitest.Fake, n int)
		count func(tools.DNSOutput) int
		small int
		large int
	}{
		"profile ids": {
			serve: func(f *apitest.Fake, n int) {
				var entries []map[string]any
				for e := range 5 {
					var targets []string
					for i := range 100 {
						targets = append(targets, fmt.Sprintf("t%02d%s", i, strings.Repeat("x", 200)))
					}
					entries = append(entries, map[string]any{"target": targets, "attr": []string{fmt.Sprintf("nextdns:%d%s", e, strings.Repeat("a", n-1))}})
				}
				b, err := json.Marshal(map[string]any{"nodeAttrs": entries})
				if err != nil {
					t.Fatal(err)
				}
				serveDNS(f, string(b))
			},
			count: func(o tools.DNSOutput) int {
				n := 0
				for _, a := range o.NextDNS {
					n = n*1000 + len(a.Targets)
				}
				return n
			},
			small: 6, large: 3000,
		},
		"control d profile ids": {
			serve: func(f *apitest.Fake, n int) {
				var entries []map[string]any
				for e := range 5 {
					var targets []string
					for i := range 100 {
						targets = append(targets, fmt.Sprintf("t%02d%s", i, strings.Repeat("x", 200)))
					}
					entries = append(entries, map[string]any{"target": targets, "attr": []string{fmt.Sprintf("controld:%d%s", e, strings.Repeat("a", n-1))}})
				}
				b, err := json.Marshal(map[string]any{"nodeAttrs": entries})
				if err != nil {
					t.Fatal(err)
				}
				serveDNS(f, string(b))
			},
			count: func(o tools.DNSOutput) int {
				n := 0
				for _, a := range o.ControlD {
					n = n*1000 + len(a.Targets)
				}
				return n
			},
			small: 6, large: 3000,
		},
		"search paths that hold a login": {
			serve: func(f *apitest.Fake, n int) {
				var paths []string
				for i := range 400 {
					paths = append(paths, fmt.Sprintf("%s%03d %s@example.com", word, i, strings.Repeat("a", n)))
				}
				b, err := json.Marshal(map[string]any{"nameservers": []any{}, "searchPaths": paths, "preferences": map[string]any{}})
				if err != nil {
					t.Fatal(err)
				}
				f.JSON("GET", tailnetPath+"/dns/configuration", 200, string(b))
				servePolicy(f, "{}\n", `"e1"`)
			},
			count: func(o tools.DNSOutput) int { return len(o.SearchPaths) },
			small: 8, large: 700,
		},
		"split-DNS domains that hold a login": {
			serve: func(f *apitest.Fake, n int) {
				split := map[string]any{}
				for i := range 400 {
					split[fmt.Sprintf("%s%03d %s@example.com", word, i, strings.Repeat("a", n))] = []map[string]string{{"address": "192.0.2.53"}}
				}
				b, err := json.Marshal(map[string]any{"nameservers": []any{}, "splitDNS": split, "preferences": map[string]any{}})
				if err != nil {
					t.Fatal(err)
				}
				f.JSON("GET", tailnetPath+"/dns/configuration", 200, string(b))
				servePolicy(f, "{}\n", `"e1"`)
			},
			count: func(o tools.DNSOutput) int { return len(o.SplitDNS) },
			small: 8, large: 700,
		},
		"record types that hold an address": {
			serve: func(f *apitest.Fake, n int) {
				// An IPv6 address written short or in full shows the same /48 network. The
				// search paths take most of the room, so that the records meet the end of it.
				ip := "2001:4860:4860::8888"
				if n > 1 {
					ip = "2001:4860:4860:0000:0000:0000:0000:8888"
				}
				var recs []map[string]string
				for i := range 100 {
					recs = append(recs, map[string]string{
						"Name":  fmt.Sprintf("%03d%s", i, strings.Repeat("n", 240)),
						"Type":  strings.Repeat("t", 200) + " " + ip,
						"Value": "192.0.2.1",
					})
				}
				var paths []string
				for i := range 300 {
					paths = append(paths, fmt.Sprintf("%03d%s", i, strings.Repeat("p", 250)))
				}
				b, err := json.Marshal(map[string]any{"extraDNSRecords": recs})
				if err != nil {
					t.Fatal(err)
				}
				pb, err := json.Marshal(map[string]any{"nameservers": []any{}, "searchPaths": paths, "preferences": map[string]any{}})
				if err != nil {
					t.Fatal(err)
				}
				f.JSON("GET", tailnetPath+"/dns/configuration", 200, string(pb))
				servePolicy(f, string(b), `"e1"`)
			},
			count: func(o tools.DNSOutput) int { return len(o.ExtraRecords) },
			small: 1, large: 2,
		},
	} {
		t.Run(name, func(t *testing.T) {
			var raws []string
			var counts []int
			for _, n := range []int{c.small, c.large} {
				f, reg, env := apiEnv(t)
				c.serve(f, n)
				out, raw := dnsCall(t, env, reg)
				if !out.Truncated {
					t.Fatalf("a value of %d bytes: the lists were not cut, so the case does not reach the budget", n)
				}
				raws = append(raws, raw)
				counts = append(counts, c.count(out))
			}
			if raws[0] != raws[1] {
				t.Errorf("a value of %d bytes and one of %d bytes behind one masked form give different results (%d and %d entries)", c.small, c.large, counts[0], counts[1])
			}
		})
	}
}

// While the owner has chosen to see personal data, dns_get counts a value as it shows it: as it
// is, so a longer login leaves room for fewer entries.
func TestWhileTheOwnerSeesPersonalDataDNSGetCountsAValueAsItIs(t *testing.T) {
	counts := map[string]int{}
	for _, n := range []int{8, 700} {
		f, reg, env := apiEnv(t)
		env.Config = &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}
		var paths []string
		for i := range 400 {
			paths = append(paths, fmt.Sprintf("%s%03d %s@example.com", strings.Repeat("w", 500), i, strings.Repeat("a", n)))
		}
		b, err := json.Marshal(map[string]any{"nameservers": []any{}, "searchPaths": paths, "preferences": map[string]any{}})
		if err != nil {
			t.Fatal(err)
		}
		f.JSON("GET", tailnetPath+"/dns/configuration", 200, string(b))
		servePolicy(f, "{}\n", `"e1"`)
		out, raw := dnsCall(t, env, reg)
		if !strings.Contains(raw, strings.Repeat("a", 8)) || strings.Contains(raw, "a…@") || !out.Truncated {
			t.Fatalf("a login of %d bytes: truncated %v; the login is not shown as it is", n, out.Truncated)
		}
		counts[fmt.Sprint(n)] = len(out.SearchPaths)
	}
	if counts["700"] >= counts["8"] {
		t.Errorf("paths with a login of 8 bytes: %d listed; of 700 bytes: %d: a longer login shown as it is should leave room for fewer", counts["8"], counts["700"])
	}
}

// The same holds for a profile id, which is masked whole when personal data is hidden.
func TestWhileTheOwnerSeesPersonalDataDNSGetCountsAProfileIDAsItIs(t *testing.T) {
	counts := map[int]int{}
	for _, n := range []int{6, 3000} {
		f, reg, env := apiEnv(t)
		env.Config = &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}
		var entries []map[string]any
		for e := range 5 {
			var targets []string
			for i := range 100 {
				targets = append(targets, fmt.Sprintf("t%02d%s", i, strings.Repeat("x", 200)))
			}
			entries = append(entries, map[string]any{"target": targets, "attr": []string{fmt.Sprintf("nextdns:%d%s", e, strings.Repeat("a", n-1))}})
		}
		b, err := json.Marshal(map[string]any{"nodeAttrs": entries})
		if err != nil {
			t.Fatal(err)
		}
		serveDNS(f, string(b))
		out, _ := dnsCall(t, env, reg)
		if !out.Truncated || len(out.NextDNS) == 0 {
			t.Fatalf("an id of %d bytes: truncated %v, %d profiles", n, out.Truncated, len(out.NextDNS))
		}
		total := 0
		for _, p := range out.NextDNS {
			total += len(p.Targets)
		}
		counts[n] = total
	}
	if counts[3000] >= counts[6] {
		t.Errorf("ids of 6 bytes leave room for %d targets and ids of 3,000 bytes (shown as 1,024) for %d: a longer id shown as it is should leave fewer", counts[6], counts[3000])
	}
}

// Entries that share one instant are all listed once across pages that end early on their
// budget, even when the end falls inside the entries of that instant: the cursor skips as many
// entries at the instant as the page held, not as many as its limit allowed.
func TestPagesThatEndEarlyOnTheirBudgetListEveryEntryOfOneInstantOnce(t *testing.T) {
	for _, c := range []struct {
		tool    string
		entries int
	}{{"acl_history", 60}, {"audit_log", 300}} {
		t.Run(c.tool, func(t *testing.T) {
			f, reg, env := apiEnv(t)
			when := now.Add(-time.Hour).UTC().Format(time.RFC3339)
			lots := strings.Repeat("<", 1000)
			serveHistory(f, boundLog(c.entries, func(i int, l *boundLine) {
				l.EventTime = when
				l.Origin = lots
				l.EventGroupID = fmt.Sprintf("g%03d%s", i, strings.Repeat("g", 50))
				l.Actor.Tags = manyTags(6, strings.Repeat("<", 100))
				l.Target.ID, l.Target.Type = lots, lots
			}))
			type page struct {
				Count      int    `json:"count"`
				NextCursor string `json:"nextCursor"`
				Versions   []struct {
					Version  string `json:"version"`
					Previous string `json:"previous"`
				} `json:"versions"`
				Entries []struct {
					EventGroupID string `json:"eventGroupId"`
				} `json:"entries"`
			}
			limit := 50
			if c.tool == "audit_log" {
				limit = c.entries
			}
			seen := map[string]int{}
			var ids [][2]string
			args, pages := fmt.Sprintf(`{"limit":%d}`, limit), 0
			for {
				var p page
				mustCall(t, reg, env, c.tool, args, &p)
				pages++
				if p.Count == 0 || pages > c.entries {
					t.Fatalf("page %d holds %d", pages, p.Count)
				}
				for _, v := range p.Versions {
					seen[v.Version]++
					ids = append(ids, [2]string{v.Previous, v.Version})
				}
				for _, e := range p.Entries {
					seen[e.EventGroupID[:4]]++
				}
				if p.NextCursor == "" {
					break
				}
				args = fmt.Sprintf(`{"limit":%d,"cursor":%q}`, limit, p.NextCursor)
			}
			if pages < 2 {
				t.Fatalf("one page: the budget did not end a page early")
			}
			if len(seen) != c.entries {
				t.Fatalf("%d distinct over %d pages, want %d", len(seen), pages, c.entries)
			}
			for k, n := range seen {
				if n != 1 {
					t.Errorf("%s listed %d times", k, n)
				}
			}
			if c.tool == "acl_history" {
				// Each version listed names its own text: none was listed for another.
				tags := map[string]bool{}
				for _, pr := range ids {
					var out tools.ACLDiffOutput
					raw := mustCall(t, reg, env, "acl_diff", fmt.Sprintf(`{"fromVersion":%q,"toVersion":%q}`, pr[0], pr[1]), &out)
					i := strings.Index(raw, "tag:t")
					if i < 0 {
						t.Fatalf("no tag in %.300s", raw)
					}
					tags[raw[i:i+9]] = true
				}
				if len(tags) != c.entries {
					t.Errorf("the version ids name %d distinct texts, want %d", len(tags), c.entries)
				}
			}
		})
	}
}

// A dns_get result cut to its size limit says so in policyNote in every case: alone when the
// note was empty, and after the sentence that was there when the policy part has a note of its
// own (the policy could not be read).
func TestADNSGetResultCutToItsSizeLimitAlwaysSaysSoInThePolicyNote(t *testing.T) {
	const noScope = "the policy was not read: the read credential lacks policy_file:read"
	for name, c := range map[string]struct {
		policy func(f *apitest.Fake)
		want   string
	}{
		"an empty note": {func(f *apitest.Fake) { servePolicy(f, "{}\n", `"e1"`) }, cutSentence},
		"a policy that cannot be read": {func(f *apitest.Fake) {
			f.JSON("GET", tailnetPath+"/acl", 403, `{"message":"forbidden"}`)
		}, noScope + "; " + cutSentence},
	} {
		t.Run(name, func(t *testing.T) {
			f, reg, env := apiEnv(t)
			f.JSON("GET", tailnetPath+"/dns/configuration", 200, dnsConfigBody("nameservers", 4000))
			c.policy(f)
			out, _ := dnsCall(t, env, reg)
			if !out.Truncated || len(out.Nameservers) == 0 || len(out.Nameservers) >= 4000 {
				t.Fatalf("%d nameservers, truncated %v: the case does not cut", len(out.Nameservers), out.Truncated)
			}
			if out.PolicyNote != c.want {
				t.Errorf("policyNote = %q, want %q", out.PolicyNote, c.want)
			}
		})
	}
}
