package tools_test

import (
	"slices"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
)

// wantTools is the complete M1 surface. A tool added or removed without updating
// this list (and docs/tools.md) fails the build.
var wantTools = []string{
	"acl_get", "acl_test", "audit_log", "contacts_get", "device_get", "device_invite_get", "device_invites_list",
	"device_posture_attributes", "device_routes", "devices_list", "dns_get", "key_get", "keys_list",
	"log_streaming_get", "network_flow_logs", "oauth_app_get", "oauth_apps_list",
	"posture_integration_get", "posture_integrations_list", "service_get", "services_list",
	"settings_get", "user_get", "user_invite_get", "user_invites_list", "users_list",
	"webhook_get", "webhooks_list",
	"local_dns_query", "local_dns_status", "local_funnel_status", "local_ip", "local_lock_status",
	"local_metrics", "local_netcheck", "local_ping", "local_prefs", "local_serve_status",
	"local_status", "local_syspolicy", "local_version", "local_whoami", "local_whois",
}

func TestRegisterAll(t *testing.T) {
	reg := newRegistry(t)
	var got []string
	tiers := map[registry.Tier]int{}
	for _, tool := range reg.All() {
		got = append(got, tool.Meta.Name)
		tiers[tool.Meta.Tier]++
		if tool.InputSchema.Type != "object" {
			t.Errorf("%s: input schema type %q, want object", tool.Meta.Name, tool.InputSchema.Type)
		}
	}
	want := slices.Clone(wantTools)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("registered tools differ:\n got %v\nwant %v", got, want)
	}
	if tiers[registry.TierRead] != 28 || tiers[registry.TierLocal] != 15 || len(tiers) != 2 {
		t.Fatalf("tiers = %v, want 28 read and 15 local", tiers)
	}
}

func TestReadsProfileHidesAlphaUnlessEnabled(t *testing.T) {
	reg := newRegistry(t)
	without, err := reg.Profile("reads", false)
	if err != nil {
		t.Fatal(err)
	}
	with, err := reg.Profile("reads", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(without) != 41 || len(with) != 43 {
		t.Fatalf("reads profile: %d tools without alpha, %d with; want 41 and 43", len(without), len(with))
	}
	for _, tool := range without {
		if tool.Meta.Stage == registry.StageAlpha {
			t.Errorf("alpha tool %s advertised without enableAlpha", tool.Meta.Name)
		}
	}
}

func TestEveryUntrustedStringIsDeclared(t *testing.T) {
	// Tools whose output carries names chosen by tailnet members must declare at
	// least one untrusted field, or the MCP layer will not warn the model.
	reg := newRegistry(t)
	for _, name := range []string{"devices_list", "device_get", "users_list", "audit_log", "keys_list",
		"webhooks_list", "local_status", "local_whois", "local_syspolicy", "local_serve_status"} {
		tool, _ := reg.Get(name)
		if len(tool.UntrustedFields) == 0 {
			t.Errorf("%s declares no untrusted output fields", name)
		}
	}
}
