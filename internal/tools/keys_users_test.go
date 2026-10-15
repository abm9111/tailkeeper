package tools_test

import (
	"slices"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

const keysFixture = `{"keys":[
{"id":"k1","key":"KEY-MATERIAL-CANARY","keyType":"auth","description":"ci","capabilities":{"devices":{"create":{"reusable":true,"ephemeral":true,"preauthorized":false,"tags":["tag:ci"]}}}},
{"id":"k2","keyType":"client","scopes":["devices:core:read"],"tags":["tag:ci"]}
]}`

func TestKeysListNeverReturnsKeyMaterial(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/keys", 200, keysFixture)
	var out tools.KeysListOutput
	s := mustCall(t, reg, env, "keys_list", `{}`, &out)
	absent(t, s, "KEY-MATERIAL-CANARY")
	if f.Requests()[0].Query.Get("all") != "true" {
		t.Errorf("query = %v, want all=true", f.Requests()[0].Query)
	}
	if out.Count != 2 || out.Keys[0].AuthKeyCapabilities == nil || !out.Keys[0].AuthKeyCapabilities.Reusable {
		t.Errorf("keys = %+v", out.Keys)
	}
}

func TestKeysListCoverageFollowsGrantedScopes(t *testing.T) {
	cases := []struct {
		scope    string
		visible  []string
		complete bool
	}{
		{"auth_keys:read devices:core:read", []string{"auth"}, false},
		{"all:read", []string{"api", "auth", "client", "federated"}, true},
	}
	for _, c := range cases {
		f, reg, env := apiEnv(t)
		f.Scope = c.scope
		f.JSON("GET", tailnetPath+"/keys", 200, `{"keys":[]}`)
		var out tools.KeysListOutput
		mustCall(t, reg, env, "keys_list", `{}`, &out)
		var visible []string
		for typ, v := range out.Coverage {
			if v == "visible" {
				visible = append(visible, typ)
			}
		}
		slices.Sort(visible)
		if !slices.Equal(visible, c.visible) || out.Complete == nil || *out.Complete != c.complete {
			t.Errorf("scope %q: coverage %v complete %v", c.scope, out.Coverage, out.Complete)
		}
	}
}

func TestKeysListCoverageUnknownWhenNoScopesNamed(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.Scope = ""
	f.JSON("GET", tailnetPath+"/keys", 200, `{"keys":[]}`)
	var out tools.KeysListOutput
	mustCall(t, reg, env, "keys_list", `{}`, &out)
	if out.Complete != nil || len(out.Coverage) != 4 {
		t.Fatalf("coverage %v complete %v", out.Coverage, out.Complete)
	}
	for typ, v := range out.Coverage {
		if v != "unknown" {
			t.Errorf("%s = %s, want unknown", typ, v)
		}
	}
}

func TestUsersListDefaultsToAllTypes(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, `{"users":[{"id":"u1","loginName":"amy@example.com","type":"shared","role":"member"}]}`)
	var out tools.UsersListOutput
	mustCall(t, reg, env, "users_list", `{}`, &out)
	q := f.Requests()[0].Query
	if q.Get("type") != "all" || q.Get("role") != "all" || out.Count != 1 {
		t.Errorf("query %v, out %+v", q, out)
	}
	if _, err := call(t, reg, env, "users_list", `{"role":"root"}`); code(err) != tkerr.ValidationFailed {
		t.Errorf("bad role: err = %v", err)
	}
}

func TestInvitesNeverReturnInviteURL(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", "/api/v2/device/nAAA1CNTRL/device-invites", 200,
		`[{"id":"i1","inviteUrl":"https://login.example.test/share/INVITE-CANARY","multiUse":true,"accepted":false}]`)
	f.JSON("GET", tailnetPath+"/user-invites", 200,
		`[{"id":"u1","role":"admin","email":"new@example.com","inviteUrl":"https://login.example.test/invite/USER-CANARY"}]`)
	s1 := mustCall(t, reg, env, "device_invites_list", `{"device":"nAAA1CNTRL"}`, nil)
	s2 := mustCall(t, reg, env, "user_invites_list", `{}`, nil)
	absent(t, s1+s2, "CANARY")
}

func TestAPIErrorsKeepTheirCodes(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/keys", 403, `{"message":"missing scope"}`)
	if _, err := call(t, reg, env, "keys_list", `{}`); code(err) != tkerr.ScopeMissing {
		t.Errorf("err = %v, want scope_missing", err)
	}
}

func TestKeyUserInvitePathIDsAreValidated(t *testing.T) {
	_, reg, env := apiEnv(t)
	for name, args := range map[string]string{
		"key_get": `{"id":"../../acl"}`, "user_get": `{"id":"a/b"}`, "device_invite_get": `{"id":"x?y"}`, "user_invite_get": `{"id":""}`,
	} {
		if _, err := call(t, reg, env, name, args); code(err) != tkerr.ValidationFailed {
			t.Errorf("%s %s: err = %v, want validation_failed", name, args, err)
		}
	}
}
