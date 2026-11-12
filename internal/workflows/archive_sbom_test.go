package workflows

import (
	"os"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestArchiveSBOMReleaseConfiguration(t *testing.T) {
	data, err := os.ReadFile("../../.goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		SBOMs []struct {
			ID        string   `yaml:"id"`
			Artifacts string   `yaml:"artifacts"`
			Cmd       string   `yaml:"cmd"`
			Documents []string `yaml:"documents"`
			Args      []string `yaml:"args"`
			Skip      bool     `yaml:"skip"`
		} `yaml:"sboms"`
	}
	if err = yaml.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.SBOMs) != 2 {
		t.Fatalf("expected two SBOM stages, got %d", len(config.SBOMs))
	}
	want := map[string]struct {
		artifacts, cmd  string
		documents, args []string
	}{
		"archives": {"archive", "go", []string{"{{ .ArtifactName }}.sbom.cdx.json"}, []string{"run", "../scripts/mcpb.go", "archive-sbom", "-archive", "$artifact", "-dist", ".", "-out", "$document", "-syft", "syft"}},
		"mcpb":     {"any", "go", []string{"tailkeeper_{{ .Version }}_darwin_universal.mcpb.sbom.cdx.json"}, []string{"run", "../scripts/mcpb.go", "sbom", "-bundle", "tailkeeper_{{ .Version }}_darwin_universal.mcpb", "-out", "$document", "-syft", "syft"}},
	}
	for _, stage := range config.SBOMs {
		expected, ok := want[stage.ID]
		if !ok {
			t.Errorf("unexpected or duplicate stage %q", stage.ID)
			continue
		}
		delete(want, stage.ID)
		if stage.Artifacts != expected.artifacts || stage.Cmd != expected.cmd || stage.Skip || !reflect.DeepEqual(stage.Documents, expected.documents) || !reflect.DeepEqual(stage.Args, expected.args) {
			t.Errorf("incorrect SBOM stage %q", stage.ID)
		}
	}
	if len(want) != 0 {
		t.Error("missing SBOM stage")
	}
}
