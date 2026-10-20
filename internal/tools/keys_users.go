package tools

import (
	"context"
	"net/url"
	"slices"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/registry"
)

// apiKey mirrors the API's Key schema minus "key", which carries the secret.
type apiKey struct {
	ID           string `json:"id"`
	KeyType      string `json:"keyType"`
	Created      string `json:"created"`
	Updated      string `json:"updated"`
	Expires      string `json:"expires"`
	Revoked      string `json:"revoked"`
	Capabilities struct {
		Devices struct {
			Create *AuthKeyCaps `json:"create"`
		} `json:"devices"`
	} `json:"capabilities"`
	Scopes           []string          `json:"scopes"`
	Tags             []string          `json:"tags"`
	Description      string            `json:"description"`
	Invalid          bool              `json:"invalid"`
	UserID           string            `json:"userId"`
	Audience         string            `json:"audience"`
	Issuer           string            `json:"issuer"`
	Subject          string            `json:"subject"`
	CustomClaimRules map[string]string `json:"customClaimRules"`
}

// AuthKeyCaps are the capabilities of an auth key.
type AuthKeyCaps struct {
	Reusable      bool     `json:"reusable"`
	Ephemeral     bool     `json:"ephemeral"`
	Preauthorized bool     `json:"preauthorized"`
	Tags          []string `json:"tags,omitempty" tk:"untrusted"`
}

// Key is a key's metadata. The key material itself is never returned.
type Key struct {
	ID                  string            `json:"id" tk:"col"`
	KeyType             string            `json:"keyType" tk:"col"`
	Description         string            `json:"description,omitempty" tk:"untrusted,col"`
	Created             string            `json:"created,omitempty"`
	Updated             string            `json:"updated,omitempty"`
	Expires             string            `json:"expires,omitempty" tk:"col"`
	Revoked             string            `json:"revoked,omitempty"`
	Invalid             bool              `json:"invalid" tk:"col"`
	Scopes              []string          `json:"scopes,omitempty"`
	Tags                []string          `json:"tags,omitempty" tk:"untrusted"`
	AuthKeyCapabilities *AuthKeyCaps      `json:"authKeyCapabilities,omitempty"`
	UserID              string            `json:"userId,omitempty"`
	Issuer              string            `json:"issuer,omitempty" tk:"untrusted"`
	Subject             string            `json:"subject,omitempty" tk:"untrusted"`
	Audience            string            `json:"audience,omitempty" tk:"untrusted"`
	CustomClaimRules    map[string]string `json:"customClaimRules,omitempty" tk:"untrusted"`
}

func toKey(a apiKey) Key {
	return Key{
		ID: a.ID, KeyType: a.KeyType, Description: a.Description, Created: a.Created, Updated: a.Updated,
		Expires: a.Expires, Revoked: a.Revoked, Invalid: a.Invalid, Scopes: a.Scopes, Tags: a.Tags,
		AuthKeyCapabilities: a.Capabilities.Devices.Create, UserID: a.UserID, Issuer: a.Issuer, Subject: a.Subject,
		Audience: a.Audience, CustomClaimRules: a.CustomClaimRules,
	}
}

// KeysListOutput lists keys with an honest statement of what could be seen.
type KeysListOutput struct {
	Keys     []Key             `json:"keys" tk:"rows"`
	Count    int               `json:"count"`
	Coverage map[string]string `json:"coverage" jsonschema:"per key type: visible, not_visible or unknown"`
	Complete *bool             `json:"complete,omitempty" jsonschema:"true only when every key type was visible; absent when unknown"`
}

// KeyRef names one key.
type KeyRef struct {
	ID string `json:"id" jsonschema:"key ID"`
}

// Check refuses an ID that cannot be one, before anything is sent.
func (in KeyRef) Check() error { return requireID("id", in.ID) }

// User is a tailnet user.
type User struct {
	ID                 string `json:"id" tk:"col"`
	LoginName          string `json:"loginName" tk:"untrusted,col,personal"`
	DisplayName        string `json:"displayName,omitempty" tk:"untrusted,personal"`
	TailnetID          string `json:"tailnetId,omitempty" tk:"personal"`
	Created            string `json:"created,omitempty"`
	Type               string `json:"type" tk:"col"`
	Role               string `json:"role" tk:"col"`
	Status             string `json:"status" tk:"col"`
	DeviceCount        int    `json:"deviceCount" tk:"col"`
	LastSeen           string `json:"lastSeen,omitempty"`
	CurrentlyConnected bool   `json:"currentlyConnected"`
}

// UsersListInput filters users. Unlike the API, type defaults to all.
type UsersListInput struct {
	Type string `json:"type,omitempty" jsonschema:"member, shared or all (default all; the API's own default hides shared users)"`
	Role string `json:"role,omitempty" jsonschema:"owner, member, admin, it-admin, network-admin, billing-admin, auditor or all (default all)"`
}

// UsersListOutput lists users.
type UsersListOutput struct {
	Users []User `json:"users" tk:"rows"`
	Count int    `json:"count"`
	Type  string `json:"type"`
}

// UserRef names one user.
type UserRef struct {
	ID string `json:"id" jsonschema:"user ID"`
}

// Check refuses an ID that cannot be one, before anything is sent.
func (in UserRef) Check() error { return requireID("id", in.ID) }

// keyTypeScopes maps each key type to the scopes that let a credential list it.
var keyTypeScopes = map[string][]string{
	"auth":      {"auth_keys:read", "auth_keys"},
	"client":    {"oauth_keys:read", "oauth_keys"},
	"federated": {"federated_keys:read", "federated_keys"},
	"api":       {"api_access_tokens:read", "api_access_tokens"},
}

func keyTools() []registry.Tool {
	m := withOps(readMeta("keys_list", "keys", "list", "List auth keys, OAuth clients, federated identities and API tokens (metadata only).",
		"auth_keys:read", "oauth_keys:read", "federated_keys:read", "api_access_tokens:read"), "GET /tailnet/{tailnet}/keys")
	m.Notes = "Each key type needs its own read scope (or all:read); the output says which types were visible."
	m.PartialScopes = true
	g := withOps(readMeta("key_get", "keys", "get", "Get one key's metadata.",
		"auth_keys:read", "oauth_keys:read", "federated_keys:read", "api_access_tokens:read"), "GET /tailnet/{tailnet}/keys/{keyId}")
	g.Notes = "Each key type needs its own read scope (or all:read): without it, keys of that type cannot be read."
	g.PartialScopes = true
	return []registry.Tool{
		registry.Define(m, keysList),
		registry.Define(g, keyGet),
	}
}

func keysList(ctx context.Context, env *registry.Env, _ NoInput) (KeysListOutput, error) {
	path, err := tailnetPath(env, "/keys")
	if err != nil {
		return KeysListOutput{}, err
	}
	var r struct {
		Keys []apiKey `json:"keys"`
	}
	if err := get(ctx, env, path, url.Values{"all": {"true"}}, &r); err != nil {
		return KeysListOutput{}, err
	}
	out := KeysListOutput{Keys: []Key{}, Coverage: map[string]string{}}
	for _, k := range r.Keys {
		out.Keys = append(out.Keys, toKey(k))
	}
	out.Count = len(out.Keys)
	c, err := env.RequireAPI()
	if err != nil {
		return KeysListOutput{}, err
	}
	scopes, known := c.GrantedScopes()
	// A token response that names no scopes says nothing about coverage.
	known = known && len(scopes) > 0
	complete := true
	for typ, need := range keyTypeScopes {
		switch {
		case !known:
			out.Coverage[typ] = "unknown"
		case slices.Contains(scopes, "all") || slices.Contains(scopes, "all:read") ||
			slices.Contains(scopes, need[0]) || slices.Contains(scopes, need[1]):
			out.Coverage[typ] = "visible"
		default:
			out.Coverage[typ] = "not_visible"
			complete = false
		}
	}
	if known {
		out.Complete = &complete
	}
	return out, nil
}

func keyGet(ctx context.Context, env *registry.Env, in KeyRef) (Key, error) {
	path, err := tailnetPath(env, "/keys/"+url.PathEscape(in.ID))
	if err != nil {
		return Key{}, err
	}
	var k apiKey
	if err := get(ctx, env, path, nil, &k); err != nil {
		return Key{}, err
	}
	return toKey(k), nil
}

func userTools() []registry.Tool {
	return []registry.Tool{
		registry.Define(withOps(readMeta("users_list", "users", "list", "List users (members and shared users by default).", "users:read"),
			"GET /tailnet/{tailnet}/users"), usersList),
		registry.Define(withOps(readMeta("user_get", "users", "get", "Get one user.", "users:read"),
			"GET /users/{userId}"), userGet),
	}
}

// Check refuses a type or a role Tailscale does not have, before anything is sent.
func (in UsersListInput) Check() error {
	if in.Type != "" && !slices.Contains([]string{"member", "shared", "all"}, in.Type) {
		return validationf("type must be member, shared or all")
	}
	if in.Role != "" && !slices.Contains([]string{"owner", "member", "admin", "it-admin", "network-admin", "billing-admin", "auditor", "all"}, in.Role) {
		return validationf("role is not a Tailscale role")
	}
	return nil
}

func usersList(ctx context.Context, env *registry.Env, in UsersListInput) (UsersListOutput, error) {
	typ := in.Type
	if typ == "" {
		typ = "all"
	}
	role := in.Role
	if role == "" {
		role = "all"
	}
	path, err := tailnetPath(env, "/users")
	if err != nil {
		return UsersListOutput{}, err
	}
	var r struct {
		Users []User `json:"users"`
	}
	if err := get(ctx, env, path, url.Values{"type": {typ}, "role": {role}}, &r); err != nil {
		return UsersListOutput{}, err
	}
	return UsersListOutput{Users: nonNil(r.Users), Count: len(r.Users), Type: typ}, nil
}

func userGet(ctx context.Context, env *registry.Env, in UserRef) (User, error) {
	var u User
	if err := get(ctx, env, api.Path("users/%s", in.ID), nil, &u); err != nil {
		return User{}, err
	}
	return u, nil
}
