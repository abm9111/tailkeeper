package tools_test

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// Confusing the Tailscale version with this binary, or claiming an unimplemented
// assessment schema, must fail even with no Tailscale installation/configuration.
func TestSelfInfoNamesThisBinary(t *testing.T) {
	reg := newRegistry(t)
	out, err := call(t, reg, &registry.Env{}, "tailkeeper_info", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Name                   string   `json:"name"`
		Version                string   `json:"version"`
		OS                     string   `json:"os"`
		Arch                   string   `json:"arch"`
		ReportSchemas          []string `json:"reportSchemas"`
		CatalogSchemas         []string `json:"catalogSchemas"`
		AssessmentCapabilities []string `json:"assessmentCapabilities"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "tailkeeper" || got.Version != "dev" || got.OS != runtime.GOOS || got.Arch != runtime.GOARCH {
		t.Fatalf("wrong binary metadata: %s", out)
	}
	if got.ReportSchemas == nil || len(got.ReportSchemas) != 0 || got.CatalogSchemas == nil || len(got.CatalogSchemas) != 0 || got.AssessmentCapabilities == nil || len(got.AssessmentCapabilities) != 0 {
		t.Fatalf("unimplemented assessment advertised: %s", out)
	}
	tool, _ := reg.Get("tailkeeper_info")
	if tool.Meta.Credential != registry.CredNone || tool.Meta.Tier != registry.TierOffline || len(tool.Meta.Scopes) != 0 || len(tool.Meta.Operations) != 0 || tool.Meta.OpenWorld {
		t.Fatal("self info declares external authority")
	}
}

func TestSelfInfoLeaksNoConfiguration(t *testing.T) {
	reg := newRegistry(t)
	canary := strings.Repeat("private-fixture-", 8)
	env := &registry.Env{APIErr: tkerr.New(tkerr.CredentialUnavailable, canary, ""), LocalErr: tkerr.New(tkerr.LocalBinaryMissing, canary, ""), PrivacyErr: tkerr.New(tkerr.PrivacyKeyUnavailable, canary, "")}
	out, err := call(t, reg, env, "tailkeeper_info", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, canary) {
		t.Fatal("provider configuration leaked")
	}
	if _, err := call(t, reg, env, "tailkeeper_info", `{"path":"ignored"}`); err == nil {
		t.Fatal("accepted caller-selected file input")
	}
}

// The description says what the CLI form and the MCP call do that the other does not, and
// the lists say what they list. A build that exposes no assessor publicly says so in the
// words the owner chose, whatever schema versions exist inside it.
func TestSelfInfoDescribesItselfAndItsLists(t *testing.T) {
	tool, ok := newRegistry(t).Get("tailkeeper_info")
	if !ok {
		t.Fatal("tailkeeper_info is not registered")
	}
	for _, want := range []string{"The CLI form reads no configuration and is not audited", "MCP calls are audited"} {
		if !strings.Contains(tool.Meta.Summary, want) {
			t.Errorf("the description lacks %q: %s", want, tool.Meta.Summary)
		}
	}
	const schemas = "Schema versions this build exposes publicly; empty until an assessor ships."
	for name, want := range map[string]string{
		"reportSchemas":          schemas,
		"catalogSchemas":         schemas,
		"assessmentCapabilities": "Assessment capabilities this build exposes publicly; empty until an assessor ships.",
	} {
		p, ok := tool.OutputSchema.Properties[name]
		if !ok || p.Description != want {
			t.Errorf("%s: description %q, want %q", name, p.Description, want)
		}
	}
}
