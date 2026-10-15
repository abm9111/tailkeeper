package tools

import (
	"context"
	"reflect"
	"sort"
	"strings"

	"github.com/abm9111/tailkeeper/internal/registry"
)

// Settings mirrors the API's TailnetSettings. Every field is a pointer: a field
// the read credential cannot see is absent, and absent must never read as false.
type Settings struct {
	DevicesApprovalOn                      *bool   `json:"devicesApprovalOn,omitempty"`
	DevicesAutoUpdatesOn                   *bool   `json:"devicesAutoUpdatesOn,omitempty"`
	DevicesKeyDurationDays                 *int    `json:"devicesKeyDurationDays,omitempty"`
	UsersApprovalOn                        *bool   `json:"usersApprovalOn,omitempty"`
	UsersRoleAllowedToJoinExternalTailnets *string `json:"usersRoleAllowedToJoinExternalTailnets,omitempty"`
	NetworkFlowLoggingOn                   *bool   `json:"networkFlowLoggingOn,omitempty"`
	RegionalRoutingOn                      *bool   `json:"regionalRoutingOn,omitempty"`
	RouteSelection                         *string `json:"routeSelection,omitempty"`
	PostureIdentityCollectionOn            *bool   `json:"postureIdentityCollectionOn,omitempty"`
	HTTPSEnabled                           *bool   `json:"httpsEnabled,omitempty"`
	ACLsExternallyManagedOn                *bool   `json:"aclsExternallyManagedOn,omitempty"`
	ACLsExternalLink                       *string `json:"aclsExternalLink,omitempty" tk:"untrusted,plain"`
}

// SettingsOutput reports the settings, which fields could not be read, and the
// GitOps lock state (spec §11.1).
type SettingsOutput struct {
	Settings          Settings `json:"settings"`
	Unreadable        []string `json:"unreadable" jsonschema:"fields absent or null in the response: hidden from these read scopes (scope-partitioned) or not set; unknown, not false"`
	ExternallyManaged string   `json:"externallyManaged" jsonschema:"true, false or unknown"`
}

// Contact is one tailnet contact.
type Contact struct {
	Email             string `json:"email,omitempty" tk:"untrusted,personal"`
	FallbackEmail     string `json:"fallbackEmail,omitempty" tk:"untrusted,personal"`
	NeedsVerification *bool  `json:"needsVerification" jsonschema:"null when the API did not say; only an explicit false counts as verified"`
}

// ContactsOutput lists the tailnet's contacts.
type ContactsOutput struct {
	Account           *Contact `json:"account,omitempty"`
	Support           *Contact `json:"support,omitempty"`
	Security          *Contact `json:"security,omitempty"`
	SecurityContactOK bool     `json:"securityContactOk" jsonschema:"security contact set and verified: Tailscale emails it when secret scanning revokes a leaked key"`
}

// NoInput is the input of tools without parameters.
type NoInput struct{}

func settingsTools() []registry.Tool {
	m := withOps(readMeta("settings_get", "settings", "get", "Show tailnet settings, unreadable fields and the GitOps lock state.",
		"feature_settings:read", "policy_file:read", "devices:core:read", "devices:posture_attributes:read",
		"logs:network:read", "networking_settings:read"), "GET /tailnet/{tailnet}/settings")
	m.Notes = "Settings are scope-partitioned: without a scope its fields are reported as unreadable."
	m.PartialScopes = true
	return []registry.Tool{
		registry.Define(m, settingsGet),
		registry.Define(withOps(readMeta("contacts_get", "contacts", "get", "Show the account, support and security contacts.", "account_settings:read"),
			"GET /tailnet/{tailnet}/contacts"), contactsGet),
	}
}

func settingsGet(ctx context.Context, env *registry.Env, _ NoInput) (SettingsOutput, error) {
	path, err := tailnetPath(env, "/settings")
	if err != nil {
		return SettingsOutput{}, err
	}
	var s Settings
	if err := get(ctx, env, path, nil, &s); err != nil {
		return SettingsOutput{}, err
	}
	out := SettingsOutput{Settings: s, Unreadable: nilFields(s), ExternallyManaged: "unknown"}
	if s.ACLsExternallyManagedOn != nil {
		out.ExternallyManaged = "false"
		if *s.ACLsExternallyManagedOn {
			out.ExternallyManaged = "true"
		}
	}
	return out, nil
}

// nilFields lists the JSON names of nil pointer fields.
func nilFields(v any) []string {
	rv := reflect.ValueOf(v)
	rt := rv.Type()
	out := []string{}
	for i := 0; i < rt.NumField(); i++ {
		if rv.Field(i).Kind() == reflect.Pointer && rv.Field(i).IsNil() {
			out = append(out, strings.Split(rt.Field(i).Tag.Get("json"), ",")[0])
		}
	}
	sort.Strings(out)
	return out
}

func contactsGet(ctx context.Context, env *registry.Env, _ NoInput) (ContactsOutput, error) {
	path, err := tailnetPath(env, "/contacts")
	if err != nil {
		return ContactsOutput{}, err
	}
	var out ContactsOutput
	if err := get(ctx, env, path, nil, &out); err != nil {
		return ContactsOutput{}, err
	}
	sec := out.Security
	out.SecurityContactOK = sec != nil && sec.Email != "" && sec.NeedsVerification != nil && !*sec.NeedsVerification
	return out, nil
}
