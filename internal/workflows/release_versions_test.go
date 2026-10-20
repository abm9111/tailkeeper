package workflows

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The tool versions are written in several files and nothing else ties them: GoReleaser
// in the Makefile, the README's rebuild line and three release.yml steps; cosign in
// release.yml and the README's "signed with". A bump that missed one would build with one
// version and tell the reader another.
func TestToolVersionsAgreeAcrossFiles(t *testing.T) {
	wf, _ := loadWorkflow(t)
	read := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	makefile, readme := read("../../Makefile"), read("../../README.md")

	versions := map[string]string{} // where: version
	for _, m := range regexp.MustCompile(`github\.com/goreleaser/goreleaser/v2@(v[0-9][0-9.]*)`).FindAllStringSubmatch(makefile, -1) {
		versions["Makefile"] = m[1]
	}
	for i, m := range regexp.MustCompile(`goreleaser/v2@(v[0-9][0-9.]*)`).FindAllStringSubmatch(readme, -1) {
		versions["README #"+strconv.Itoa(i+1)] = m[1]
	}
	for jobName, j := range wf.Jobs {
		for i, s := range j.Steps {
			if strings.HasPrefix(s.Uses, "goreleaser/goreleaser-action@") {
				v, _ := s.With["version"].(string)
				versions["release.yml "+jobName+" step "+strconv.Itoa(i)] = v
			}
		}
	}
	// Makefile 1, README 1, release.yml: the release job's Release (draft) step, the
	// snapshot job's Snapshot step and the reproduce job's rebuild.
	if len(versions) != 5 {
		t.Errorf("found GoReleaser versions in %d places (%v), want 5: the Makefile, the README, and three release.yml steps (Release (draft), Snapshot and the rebuild)", len(versions), versions)
	}
	var first string
	for where, v := range versions {
		if first == "" {
			first = v
		}
		if v != first || !regexp.MustCompile(`^v\d+\.\d+\.\d+$`).MatchString(v) {
			t.Errorf("GoReleaser is %q in %s but %q elsewhere: %v", v, where, first, versions)
		}
	}

	var cosign []string
	for _, j := range wf.Jobs {
		for _, s := range j.Steps {
			if strings.HasPrefix(s.Uses, "sigstore/cosign-installer@") {
				v, _ := s.With["cosign-release"].(string)
				cosign = append(cosign, v)
			}
		}
	}
	m := regexp.MustCompile(`signed with (\d+\.\d+\.\d+)`).FindStringSubmatch(readme)
	// Two installs: the release job signs with cosign and the publish job verifies with it.
	if len(cosign) != 2 || m == nil {
		t.Fatalf("found %d cosign-release values in release.yml (want 2: release and publish) and the README's \"signed with\": %v %v", len(cosign), cosign, m)
	}
	for _, v := range cosign {
		if v != "v"+m[1] {
			t.Errorf("release.yml installs cosign %s but the README says the release is signed with %s", v, m[1])
		}
	}
}
