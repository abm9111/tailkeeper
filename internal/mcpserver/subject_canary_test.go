package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// canaryLogin has a slash, which the address scan does not read as part of a local part: the
// registry's masking alone would leave "ops/" showing, so only the reverse map hides it.
const canaryLogin = "ops/amy@example.com"

type canaryIn struct {
	Subject string `json:"subject" jsonschema:"a pseudonym"`
	Mode    string `json:"mode" jsonschema:"result, error or raw"`
}

type canaryOut struct {
	Status  string   `json:"status"`
	Src     string   `json:"src,omitempty" tk:"untrusted,emails"`
	Reasons []string `json:"reasons,omitempty" tk:"untrusted,emails"`
}

// canaryTool is the shape of the tools that resolve a pseudonym: resolve the
// pseudonym, put the login in the request and nowhere else, and pass what comes back through
// the reverse map. Mode raw forgets the reverse map, which the test must catch.
func canaryTool() registry.Tool {
	return registry.Define(registry.Meta{
		Name: "acl_canary", Area: "acl", Verb: "canary", Summary: "A test tool for the login canary.",
		Tier: registry.TierRead, Stage: registry.StageGA, Credential: registry.CredRead,
		Scopes: []string{"policy_file:read"}, Operations: []string{"POST /tailnet/{tailnet}/acl/validate"},
	}, func(ctx context.Context, env *registry.Env, in canaryIn) (canaryOut, error) {
		res := tools.NewSubjectResolver(env)
		login, err := res.Resolve(ctx, in.Subject)
		if err != nil {
			return canaryOut{}, res.HideError(err)
		}
		c, err := env.RequireAPI()
		if err != nil {
			return canaryOut{}, err
		}
		v, err := c.ValidateTests(ctx, []api.PolicyTest{{Src: login.Reveal(), Accept: []string{"tag:p:22"}}})
		if err != nil {
			if in.Mode == "raw" {
				return canaryOut{}, err
			}
			return canaryOut{}, res.HideError(err)
		}
		hide := res.Hide
		if in.Mode == "raw" {
			hide = func(s string) string { return s }
		}
		out := canaryOut{Status: "pass"}
		for _, r := range v.Results {
			out.Src = hide(r.User)
			for _, e := range r.Errors {
				out.Reasons = append(out.Reasons, hide(e))
			}
			out.Status = "fail"
		}
		return out, nil
	})
}

// echoes are how Tailscale's reply may write a login it was sent.
func echoes(login string) []string {
	local, domain, _ := strings.Cut(login, "@")
	return []string{
		"user or host is invalid: " + login,
		"user or host is invalid: " + strings.ToUpper(login),
		"user or host is invalid: " + local + "%40" + domain,
		"user=" + login + " has no devices",
	}
}

// canaryServer returns a session on a server with the canary tool, the audit log on and a
// privacy key loaded, a fake API that knows two users and answers a validation by echoing the
// login in the given way, and the pseudonym of the user with the slash in the login.
func canaryServer(t *testing.T, shown bool, reply func(w http.ResponseWriter, login string)) (*mcp.ClientSession, *app.App, *apitest.Fake, string) {
	t.Helper()
	return canaryServerWith(t, shown, reply, nil)
}

// canaryServerWith is canaryServer with a change to the application before the server is built,
// for a test that needs a setting the server reads once (the invariants file, say).
func canaryServerWith(t *testing.T, shown bool, reply func(w http.ResponseWriter, login string), tweak func(*app.App)) (*mcp.ClientSession, *app.App, *apitest.Fake, string) {
	t.Helper()
	f := apitest.New(t)
	users, err := json.Marshal(map[string]any{"users": []map[string]string{
		{"id": "u1", "loginName": canaryLogin, "type": "member", "status": "active"},
		{"id": "u2", "loginName": "bob@example.org", "type": "member", "status": "active"}}})
	if err != nil {
		t.Fatal(err)
	}
	f.JSON("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/users", 200, string(users))
	f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) { reply(w, canaryLogin) })
	a := newApp(t, f)
	key, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		t.Fatal(err)
	}
	a.Env.Privacy = key
	if shown {
		a.Env.Config = &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}
	}
	if tweak != nil {
		tweak(a)
	}
	a.Registry.MustAdd(canaryTool())
	// A warning is a failure here: a canary that ran on a server that complained proved less.
	cs := connect(t, a, Options{Warn: func(s string) { t.Errorf("the server warned: %s", s) }})
	// The pseudonym is read off a real result, as a model reads it.
	list := callTool(t, cs, "users_list", map[string]any{})
	b, _ := json.Marshal(list.StructuredContent)
	var out struct {
		Users []struct{ ID, LoginName string } `json:"users"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	for _, u := range out.Users {
		if u.ID == "u1" {
			if ref, ok := privacy.Ref(u.LoginName); ok {
				return cs, a, f, ref
			}
			if shown {
				return cs, a, f, key.APIPseudonym(canaryLogin)
			}
		}
	}
	t.Fatalf("users_list did not show a pseudonym for the first user: %s", b)
	return nil, nil, nil, ""
}

// failureReply answers a validation with a failed test whose user and reasons echo the login,
// in the ledger's shape of a failed test.
func failureReply(w http.ResponseWriter, login string) {
	apitest.TestsFailed(apitest.Entry{User: login, Errors: echoes(login)}).Write(w)
}

// rejectionReply answers with a 400 whose message echoes the login, in the ledger's shape of a
// body the API does not read as a policy.
func rejectionReply(w http.ResponseWriter, login string) {
	apitest.Rejected400(strings.Join(echoes(login), "; ")).Write(w)
}

// rejectionAt200Reply answers with a bare message at HTTP 200 that echoes the login: how the
// live API rejects a well-formed document it cannot accept (the ledger's BareMessage200).
func rejectionAt200Reply(w http.ResponseWriter, login string) {
	apitest.BareMessage200(strings.Join(echoes(login), "; ")).Write(w)
}

// everything is all that the server produced for a call: the whole result, its structured
// content and its _meta as JSON, and the audit log.
func everything(t *testing.T, a *app.App, res *mcp.CallToolResult) string {
	t.Helper()
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := os.ReadFile(a.AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n" + string(audit)
}

// bareName matches the two names of the login as whole words, so that a tool which shows the
// local part with the at sign and the domain taken off (ops, amy) is seen as well.
var bareName = regexp.MustCompile(`\b(?:ops|amy)\b`)

// leaks lists the pieces of the login that appear in s, in any case: the pieces of its text,
// the at sign as a reply may write it (json.Marshal doubles the backslash of a JSON escape),
// and each of its names on its own.
func leaks(s string) []string {
	var found []string
	lower := strings.ToLower(s)
	bs := string(rune(92))
	for _, piece := range []string{"ops/", "amy@", "amy%40", "amy" + bs + bs + "u0040", "example.com"} {
		if strings.Contains(lower, piece) {
			found = append(found, piece)
		}
	}
	for _, name := range bareName.FindAllString(lower, -1) {
		if !slices.Contains(found, name) {
			found = append(found, name)
		}
	}
	return found
}

func TestAResolvedLoginReachesOnlyTheRequest(t *testing.T) {
	for name, reply := range map[string]func(http.ResponseWriter, string){"a failed test": failureReply, "a rejection": rejectionReply, "a rejection at 200": rejectionAt200Reply} {
		t.Run(name, func(t *testing.T) {
			cs, a, f, ref := canaryServer(t, false, reply)
			res := callTool(t, cs, "acl_canary", map[string]any{"subject": ref, "mode": "result"})
			all := everything(t, a, res)
			if got := leaks(all); len(got) > 0 {
				t.Errorf("the result, _meta or audit log shows %v:\n%s", got, all)
			}
			if !strings.Contains(all, `"tool":"acl_canary"`) {
				t.Errorf("the audit log has no line for the call, so the audit check saw nothing:\n%s", all)
			}
			// The flow happened: the request carried the login.
			sent := false
			for _, r := range f.Requests() {
				if r.Path == apitest.ValidatePath && strings.Contains(string(r.Body), canaryLogin) {
					sent = true
				}
			}
			if !sent {
				t.Error("the validation request did not carry the login, so the test checked nothing")
			}
		})
	}
}

func TestACanaryThatForgetsTheReverseMapIsCaught(t *testing.T) {
	cs, a, _, ref := canaryServer(t, false, failureReply)
	res := callTool(t, cs, "acl_canary", map[string]any{"subject": ref, "mode": "raw"})
	all := everything(t, a, res)
	if got := leaks(all); !strings.Contains(strings.Join(got, ","), "ops/") {
		t.Errorf("a tool that skips the reverse map shows %v, want ops/: the registry's masking alone leaves the front of the login, and the canary must see it:\n%s", got, all)
	}
}

func TestWithPersonalDataShownTheCanaryCanSeeTheLogin(t *testing.T) {
	cs, a, _, ref := canaryServer(t, true, failureReply)
	res := callTool(t, cs, "acl_canary", map[string]any{"subject": ref, "mode": "result"})
	all := everything(t, a, res)
	if !strings.Contains(all, canaryLogin) {
		t.Errorf("with personalData show the result should carry the login, as the owner asked:\n%s", all)
	}
}

func TestAnUnresolvedPseudonymLeavesNoLoginEither(t *testing.T) {
	cs, a, _, _ := canaryServer(t, false, failureReply)
	res := callTool(t, cs, "acl_canary", map[string]any{"subject": "p:abcdefghij", "mode": "result"})
	all := everything(t, a, res)
	if !res.IsError || !strings.Contains(text(res, 0), "no user has that pseudonym") {
		t.Errorf("an unknown pseudonym: isError %v, %s", res.IsError, text(res, 0))
	}
	if got := leaks(all); len(got) > 0 {
		t.Errorf("an error shows %v:\n%s", got, all)
	}
	if !strings.Contains(all, `"tool":"acl_canary"`) {
		t.Errorf("the audit log has no line for the call, so the audit check saw nothing:\n%s", all)
	}
}
