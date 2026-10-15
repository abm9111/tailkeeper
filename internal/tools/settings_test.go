package tools_test

import (
	"slices"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tools"
)

func TestSettingsReportUnreadableFields(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/settings", 200, `{"devicesApprovalOn":true,"networkFlowLoggingOn":false}`)
	var out tools.SettingsOutput
	mustCall(t, reg, env, "settings_get", `{}`, &out)
	if out.Settings.DevicesApprovalOn == nil || !*out.Settings.DevicesApprovalOn {
		t.Errorf("devicesApprovalOn = %v", out.Settings.DevicesApprovalOn)
	}
	if out.ExternallyManaged != "unknown" {
		t.Errorf("externallyManaged = %q, want unknown when the field is unreadable", out.ExternallyManaged)
	}
	if !slices.Contains(out.Unreadable, "aclsExternallyManagedOn") || slices.Contains(out.Unreadable, "devicesApprovalOn") {
		t.Errorf("unreadable = %v", out.Unreadable)
	}
}

func TestSettingsExternallyManaged(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/settings", 200, `{"aclsExternallyManagedOn":true,"aclsExternalLink":"https://git.example.test/acl"}`)
	var out tools.SettingsOutput
	mustCall(t, reg, env, "settings_get", `{}`, &out)
	if out.ExternallyManaged != "true" {
		t.Errorf("externallyManaged = %q", out.ExternallyManaged)
	}
}

func TestContactsSecurityContactOK(t *testing.T) {
	for body, want := range map[string]bool{
		`{"security":{"email":"sec@example.com","needsVerification":false}}`: true,
		`{"security":{"email":"sec@example.com","needsVerification":true}}`:  false,
		`{"account":{"email":"a@example.com"}}`:                              false,
		`{"security":{"email":"sec@example.com"}}`:                           false,
		`{"security":{"email":"sec@example.com","needsVerification":null}}`:  false,
	} {
		f, reg, env := apiEnv(t)
		f.JSON("GET", tailnetPath+"/contacts", 200, body)
		var out tools.ContactsOutput
		mustCall(t, reg, env, "contacts_get", `{}`, &out)
		if out.SecurityContactOK != want {
			t.Errorf("%s: securityContactOk = %v, want %v", body, out.SecurityContactOK, want)
		}
	}
}

func TestDNSGetSortsSplitDNS(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/dns/configuration", 200, `{"nameservers":[{"address":"1.1.1.1"}],
		"splitDNS":{"zeta.example":[{"address":"10.0.0.53"}],"alpha.example":[{"address":"10.0.0.54","useWithExitNode":true}]},
		"searchPaths":["corp.example"],"preferences":{"magicDNS":true,"overrideLocalDNS":false}}`)
	var out tools.DNSOutput
	mustCall(t, reg, env, "dns_get", `{}`, &out)
	if len(out.SplitDNS) != 2 || out.SplitDNS[0].Domain != "alpha.example" || !out.SplitDNS[0].Resolvers[0].UseWithExitNode {
		t.Errorf("splitDns = %+v", out.SplitDNS)
	}
	if out.MagicDNS == nil || !*out.MagicDNS || out.OverrideLocalDNS == nil || *out.OverrideLocalDNS || out.PolicyOverridesAnalysed {
		t.Errorf("dns = %+v", out)
	}
}

func TestDNSPreferencesAbsentAreUnknown(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/dns/configuration", 200, `{"nameservers":[{"address":"1.1.1.1"}]}`)
	var out tools.DNSOutput
	mustCall(t, reg, env, "dns_get", `{}`, &out)
	if out.MagicDNS != nil || out.OverrideLocalDNS != nil {
		t.Errorf("magicDns = %v, overrideLocalDns = %v, want null", out.MagicDNS, out.OverrideLocalDNS)
	}
}
