package tools

import (
	"context"
	"runtime"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/version"
)

// SelfInput deliberately accepts no paths, configuration or credential options.
type SelfInput struct{}

// SelfOutput identifies Tailkeeper, separately from Tailscale's local versions.
// The lists name what this build exposes publicly: empty until an assessor ships, whatever
// schema versions exist inside it. The text form prints each list, none when it is empty.
type SelfOutput struct {
	Name                   string   `json:"name" jsonschema:"The product this build identifies."`
	Version                string   `json:"version" jsonschema:"Tailkeeper build version; dev is an unreleased build."`
	OS                     string   `json:"os" jsonschema:"Operating system this binary targets."`
	Arch                   string   `json:"arch" jsonschema:"Processor architecture this binary targets."`
	ReportSchemas          []string `json:"reportSchemas" jsonschema:"Schema versions this build exposes publicly; empty until an assessor ships." tk:"none"`
	CatalogSchemas         []string `json:"catalogSchemas" jsonschema:"Schema versions this build exposes publicly; empty until an assessor ships." tk:"none"`
	AssessmentCapabilities []string `json:"assessmentCapabilities" jsonschema:"Assessment capabilities this build exposes publicly; empty until an assessor ships." tk:"none"`
}

func selfTools() []registry.Tool {
	meta := registry.Meta{Name: "tailkeeper_info", Area: "self", Verb: "info", Summary: "This Tailkeeper build and the assessment schemas it exposes publicly; no credential or Tailscale access. The CLI form reads no configuration and is not audited; MCP calls are audited.", Tier: registry.TierOffline, Stage: registry.StageGA, Credential: registry.CredNone}
	return []registry.Tool{registry.Define(meta, selfInfo)}
}

func selfInfo(_ context.Context, _ *registry.Env, _ SelfInput) (SelfOutput, error) {
	return SelfOutput{Name: "tailkeeper", Version: version.Version, OS: runtime.GOOS, Arch: runtime.GOARCH, ReportSchemas: []string{}, CatalogSchemas: []string{}, AssessmentCapabilities: []string{}}, nil
}
