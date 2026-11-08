package workflows

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBundleReleaseConfiguration(t *testing.T) {
	data, err := os.ReadFile("../../.goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Universal []struct {
			ID      string   `yaml:"id"`
			IDs     []string `yaml:"ids"`
			Replace bool     `yaml:"replace"`
		} `yaml:"universal_binaries"`
		Archives []struct {
			IDs []string `yaml:"ids"`
		} `yaml:"archives"`
		Checksum struct {
			Extra []struct {
				Glob string `yaml:"glob"`
			} `yaml:"extra_files"`
		} `yaml:"checksum"`
		Release struct {
			Extra []struct {
				Glob string `yaml:"glob"`
			} `yaml:"extra_files"`
		} `yaml:"release"`
		SBOMs []struct {
			ID        string `yaml:"id"`
			Artifacts string `yaml:"artifacts"`
		} `yaml:"sboms"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Universal) != 1 || cfg.Universal[0].ID != "tailkeeper_mcpb" || cfg.Universal[0].Replace || len(cfg.Universal[0].IDs) != 1 || cfg.Universal[0].IDs[0] != "tailkeeper" {
		t.Error("universal bundle must retain thin binaries")
	}
	if len(cfg.Archives) != 1 || len(cfg.Archives[0].IDs) != 1 || cfg.Archives[0].IDs[0] != "tailkeeper" {
		t.Error("archives must contain only original builds")
	}
	if len(cfg.Checksum.Extra) != 1 || len(cfg.Release.Extra) != 1 || cfg.Checksum.Extra[0].Glob != cfg.Release.Extra[0].Glob || !strings.HasSuffix(cfg.Checksum.Extra[0].Glob, ".mcpb") {
		t.Error("bundle must enter checksums and release")
	}
	found := false
	for _, s := range cfg.SBOMs {
		if s.ID == "mcpb" && s.Artifacts == "any" {
			found = true
		}
	}
	if !found {
		t.Error("bundle SBOM stage missing")
	}
}

func reproductionProblems(j job) []string {
	var scripts []string
	for _, s := range j.Steps {
		if strings.Contains(s.Run, "go run ./scripts/mcpb.go verify") {
			scripts = append(scripts, s.Run)
		}
	}
	if len(scripts) != 1 {
		return []string{"missing or duplicated bundle verification"}
	}
	script := scripts[0]
	var problems []string
	for _, required := range []string{
		"set -euo pipefail", "darwin_amd64 darwin_arm64 linux_amd64 linux_arm64 windows_amd64",
		`test "${#all_archives[@]}" = 5`, `test "${#bundles[@]}" = 1`,
		`test "${#builds[@]}" = 1`, `test "${#archives[@]}" = 1`,
		`(cd released && sha256sum -c checksums.txt)`,
		`cmp "${builds[0]}" "$work/$target/$binary"`,
		`go run ./scripts/mcpb.go verify -bundle "${bundles[0]}" -dist dist -version "$version"`,
		`cmp "${bundles[0]}" "$rebuilt"`,
	} {
		if !strings.Contains(script, required) {
			problems = append(problems, required)
		}
	}
	return problems
}
func TestBundleReproductionHasNegativeControls(t *testing.T) {
	wf, _ := loadWorkflow(t)
	job := wf.Jobs["reproduce"]
	if problems := reproductionProblems(job); len(problems) != 0 {
		t.Fatalf("missing reproduction checks: %v", problems)
	}
	for _, needle := range []string{`test "${#all_archives[@]}" = 5`, `test "${#bundles[@]}" = 1`, `test "${#builds[@]}" = 1`, `test "${#archives[@]}" = 1`, `cmp "${builds[0]}" "$work/$target/$binary"`, `go run ./scripts/mcpb.go verify -bundle`, `cmp "${bundles[0]}" "$rebuilt"`} {
		changed := job
		changed.Steps = append([]step{}, job.Steps...)
		found := false
		for i := range changed.Steps {
			if strings.Contains(changed.Steps[i].Run, needle) {
				changed.Steps[i].Run = strings.Replace(changed.Steps[i].Run, needle, "omitted", 1)
				found = true
				break
			}
		}
		if !found || len(reproductionProblems(changed)) == 0 {
			t.Errorf("failed to catch mutation %q", needle)
		}
	}
}
