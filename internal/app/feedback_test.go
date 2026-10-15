package app

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/privacy"
)

var printedPseudonymRE = regexp.MustCompile(` \[(p:[a-z2-7]{10})\]$`)

// feedbackApp builds one App the way the binary does, with the key from the
// environment, over a fake API that holds a mixed-case login, a display name and
// an address that appears as a target in two spellings.
func feedbackApp(t *testing.T) (*App, *apitest.Fake) {
	t.Helper()
	f := apitest.New(t)
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/devices", 200, `{"devices":[
	 {"nodeId":"nAAA1CNTRL","name":"a","hostname":"a","user":"Amy.Lee@Example.com"},
	 {"nodeId":"nBBB2CNTRL","name":"b","hostname":"b","user":"bob@example.com"},
	 {"nodeId":"nCCC3CNTRL","name":"c","hostname":"c","user":"Dev Person"},
	 {"nodeId":"nDDD4CNTRL","name":"d","hostname":"d","user":"amy.lee@example.com"}]}`)
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/logging/configuration", 200, `{"logs":[
	 {"eventTime":"2026-10-10T10:00:00Z","origin":"ADMIN_CONSOLE","action":"UPDATE","actor":{"id":"u1","loginName":"Amy.Lee@Example.com","displayName":"Amy Lee"},"target":{"id":"t1","name":"bob@example.com"}},
	 {"eventTime":"2026-10-10T10:01:00Z","origin":"ADMIN_CONSOLE","action":"UPDATE","actor":{"id":"u2","loginName":"bob@example.com","displayName":"Bob"},"target":{"id":"t2","name":"Amy.Lee@Example.com"}},
	 {"eventTime":"2026-10-10T10:02:00Z","origin":"ADMIN_CONSOLE","action":"UPDATE","actor":{"id":"u3","loginName":"Dev Person","displayName":"Dev Person"},"target":{"id":"t3","name":"tag:x"}},
	 {"eventTime":"2026-10-10T10:03:00Z","origin":"ADMIN_CONSOLE","action":"UPDATE","actor":{"id":"u1","loginName":"Amy.Lee@Example.com","displayName":"Amy Lee"},"target":{"id":"t4","name":"amy.lee@example.com"}}]}`)
	env := map[string]string{creds.EnvClientID: apitest.ClientID, creds.EnvClientSecret: apitest.ClientSecret,
		privacy.EnvKey: strings.Repeat("c3", 32)}
	a, err := Build(context.Background(), Options{Dirs: dirs(t, envConfig), Stat: noCLI,
		Getenv: func(k string) string { return env[k] },
		Now:    func() time.Time { return time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC) },
		API:    api.Options{BaseURL: f.URL(), Sleep: func(context.Context, time.Duration) error { return nil }}})
	if err != nil {
		t.Fatal(err)
	}
	return a, f
}

func runTool(t *testing.T, a *App, tool string, args any, out any) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	tl, ok := a.Registry.Get(tool)
	if !ok {
		t.Fatalf("no tool %s", tool)
	}
	res, err := tl.Call(context.Background(), a.Env, raw)
	if err != nil {
		t.Fatalf("%s %s: %v", tool, raw, err)
	}
	b, _ := json.Marshal(res)
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
}

// Each pseudonym is taken exactly as a tool printed it, bare and inside the
// masked value, and fed back as a filter: the rows it names come back, and no
// request to the server carries the pseudonym.
func TestPrintedPseudonymsAreAcceptedAsFiltersEndToEnd(t *testing.T) {
	a, f := feedbackApp(t)
	type device struct {
		NodeID string `json:"nodeId"`
		User   string `json:"user"`
	}
	var devs struct {
		Devices []device `json:"devices"`
	}
	runTool(t, a, "devices_list", map[string]any{}, &devs)
	byPseudonym := map[string]string{} // bare pseudonym -> node IDs, in listing order
	printedAs := map[string][]string{} // bare pseudonym -> every way the listing printed it
	for _, d := range devs.Devices {
		if strings.Contains(d.User, "@example") && !strings.Contains(d.User, "…") || strings.Contains(strings.ToLower(d.User), "amy.") {
			t.Errorf("devices_list printed an unmasked owner: %q", d.User)
		}
		m := printedPseudonymRE.FindStringSubmatch(d.User)
		if m == nil {
			t.Fatalf("owner %q carries no pseudonym", d.User)
		}
		byPseudonym[m[1]] += d.NodeID + ","
		printedAs[m[1]] = append(printedAs[m[1]], d.User)
	}
	// A login spelled in mixed case and in lower case is one owner with two devices.
	if len(byPseudonym) != 3 {
		t.Fatalf("expected three owners (Amy twice, Bob, Dev Person), got %q", byPseudonym)
	}
	for bare, ids := range byPseudonym {
		for _, arg := range append([]string{bare}, printedAs[bare]...) {
			var got struct {
				Devices []device `json:"devices"`
			}
			runTool(t, a, "devices_list", map[string]any{"user": arg}, &got)
			var gotIDs string
			for _, d := range got.Devices {
				gotIDs += d.NodeID + ","
			}
			if gotIDs != ids {
				t.Errorf("devices_list user=%q gave %q, want %q", arg, gotIDs, ids)
			}
		}
	}

	type entry struct {
		Actor struct {
			ID          string `json:"id"`
			LoginName   string `json:"loginName"`
			DisplayName string `json:"displayName"`
		} `json:"actor"`
		Target struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"target"`
	}
	type auditOut struct {
		Entries []entry `json:"entries"`
	}
	var all auditOut
	runTool(t, a, "audit_log", map[string]any{}, &all)
	if len(all.Entries) != 4 {
		t.Fatalf("audit_log printed %d entries, want 4", len(all.Entries))
	}
	pairs := func(o auditOut) string {
		var s []string
		for _, e := range o.Entries {
			s = append(s, e.Actor.ID+">"+e.Target.ID)
		}
		return strings.Join(s, ",")
	}
	e1, e2, e3, e4 := all.Entries[0], all.Entries[1], all.Entries[2], all.Entries[3]
	if printedPseudonymRE.FindString(e2.Target.Name) != printedPseudonymRE.FindString(e4.Target.Name) {
		t.Errorf("one address in two spellings must print one pseudonym: %q, %q", e2.Target.Name, e4.Target.Name)
	}
	for _, c := range []struct {
		field, printed, want string
	}{
		{"actor", e1.Actor.LoginName, "u1>t1,u1>t4"},   // mixed-case login
		{"actor", e1.Actor.DisplayName, "u1>t1,u1>t4"}, // display name
		{"actor", e2.Actor.LoginName, "u2>t2"},         // lower-case login
		{"actor", e2.Actor.DisplayName, "u2>t2"},       // short display name
		{"actor", e3.Actor.LoginName, "u3>t3"},         // a name that is not an address
		{"target", e1.Target.Name, "u1>t1"},            // target name that is an address
		{"target", e2.Target.Name, "u2>t2,u1>t4"},      // mixed case and lower case together
		{"target", e4.Target.Name, "u2>t2,u1>t4"},      // the same address, other spelling
	} {
		m := printedPseudonymRE.FindStringSubmatch(c.printed)
		if m == nil {
			t.Errorf("%s %q carries no pseudonym", c.field, c.printed)
			continue
		}
		for _, arg := range []string{c.printed, m[1]} {
			var got auditOut
			runTool(t, a, "audit_log", map[string][]string{c.field: {arg}}, &got)
			if p := pairs(got); p != c.want {
				t.Errorf("audit_log %s=%q gave %s, want %s", c.field, arg, p, c.want)
			}
		}
	}
	for _, r := range f.Requests() {
		for k, vs := range r.Query {
			for _, v := range vs {
				if strings.Contains(v, "p:") || strings.Contains(v, "@") || strings.Contains(v, "…") {
					t.Errorf("a masked value reached the server: %s=%q in %s", k, v, r.Path)
				}
			}
		}
	}
}
