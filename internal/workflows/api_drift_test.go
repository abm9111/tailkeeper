package workflows

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// flagValue returns the word after flag in a command's words, or "" when the
// flag is missing or last.
func flagValue(words []string, flag string) string {
	if i := slices.Index(words, flag); i >= 0 && i+1 < len(words) {
		return words[i+1]
	}
	return ""
}

// curlRetries reports whether the words of a curl command retry a failed download
// the way #19 asks: three retries, five seconds apart, on every kind of error (a
// connection reset and a 5xx included, which curl does not retry by default).
func curlRetries(words []string) bool {
	return flagValue(words, "--retry") == "3" && flagValue(words, "--retry-delay") == "5" && slices.Contains(words, "--retry-all-errors")
}

// curlCommand returns the words of the one command in a run block that starts with
// curl. Backslash-newline continuations are joined first, and a trailing shell
// comment is dropped. The block may hold other lines (set -euo pipefail, an echo
// that names the flags); their words are not curl's, so a flag on one of them
// proves nothing. The test does not parse a shell: the command must start its
// line, and it is an error unless exactly one line does.
func curlCommand(run string) ([]string, error) {
	var found [][]string
	for _, line := range strings.Split(strings.ReplaceAll(run, "\\\n", " "), "\n") {
		words := strings.Fields(line)
		if len(words) == 0 || words[0] != "curl" {
			continue
		}
		if i := slices.IndexFunc(words, func(w string) bool { return strings.HasPrefix(w, "#") }); i >= 0 {
			words = words[:i]
		}
		found = append(found, words)
	}
	switch len(found) {
	case 0:
		return nil, errors.New("no line starts with curl")
	case 1:
		return found[0], nil
	}
	return nil, fmt.Errorf("%d lines start with curl, want 1", len(found))
}

// curlProblems lists what the curl command of a run block lacks: the retries, the
// --fail that keeps an HTTP error page from being compared as the document, and a
// --max-time that bounds a stalled download.
func curlProblems(run string) []string {
	words, err := curlCommand(run)
	if err != nil {
		return []string{err.Error()}
	}
	var out []string
	if !curlRetries(words) {
		out = append(out, "no --retry 3 --retry-delay 5 --retry-all-errors")
	}
	if !slices.Contains(words, "--fail") {
		out = append(out, "no --fail: an HTTP error page would be compared as the document")
	}
	if flagValue(words, "--max-time") != "60" {
		out = append(out, "no --max-time 60: a stalled download would hold the job until its timeout")
	}
	return out
}

func TestCurlRetriesNeedsAllThreeFlags(t *testing.T) {
	for run, want := range map[string]bool{
		"curl -sS --fail --retry 3 --retry-delay 5 --retry-all-errors -o out url": true,
		"curl --retry-all-errors --retry-delay 5 --retry 3 url":                   true,
		"curl -sS --fail --max-time 60 -o out url":                                false,
		"curl --retry 3 --retry-delay 5 url":                                      false,
		"curl --retry 3 --retry-all-errors url":                                   false,
		"curl --retry-delay 5 --retry-all-errors url":                             false,
		"curl --retry 30 --retry-delay 5 --retry-all-errors url":                  false,
		"curl --retry 3 --retry-delay 50 --retry-all-errors url":                  false,
		"curl --retry-all-errors --retry-delay 5 --retry":                         false,
	} {
		if got := curlRetries(strings.Fields(run)); got != want {
			t.Errorf("curlRetries(%q) = %v, want %v", run, got, want)
		}
	}
}

// Flags are judged on the curl command alone: an echo that names them, or a
// comment, must not stand in for them.
func TestCurlProblemsJudgeTheCurlCommandAlone(t *testing.T) {
	const flags = "--fail --retry 3 --retry-delay 5 --retry-all-errors --max-time 60"
	const retries, fail, maxTime = "--retry 3", "--fail", "--max-time 60"
	for _, tc := range []struct {
		name string
		run  string
		want []string // a substring of each problem, in the order curlProblems reports them
	}{
		{"every flag on one line", "curl -sS " + flags + " -o out url", nil},
		{"a line before the command", "set -euo pipefail\ncurl -sS " + flags + " -o out url", nil},
		{"a command continued over lines", "curl -sS --fail \\\n  --retry 3 --retry-delay 5 \\\n  --retry-all-errors --max-time 60 \\\n  -o out url", nil},
		{"every flag on an echo line only", "echo \"curl " + flags + "\"\ncurl -sS -o out url", []string{retries, fail, maxTime}},
		{"--fail on an echo line only", "echo --fail\ncurl -sS --retry 3 --retry-delay 5 --retry-all-errors --max-time 60 -o out url", []string{fail}},
		{"every flag in a comment line only", "# curl " + flags + "\ncurl -o out url", []string{retries, fail, maxTime}},
		{"every flag in a trailing comment only", "curl -o out url # " + flags, []string{retries, fail, maxTime}},
		{"no --max-time", "curl -sS --fail --retry 3 --retry-delay 5 --retry-all-errors -o out url", []string{maxTime}},
		{"a --max-time of 600", "curl -sS --fail --retry 3 --retry-delay 5 --retry-all-errors --max-time 600 -o out url", []string{maxTime}},
		{"no --retry-all-errors", "curl -sS --fail --retry 3 --retry-delay 5 --max-time 60 -o out url", []string{retries}},
		{"no curl command", "echo curl " + flags, []string{"no line starts with curl"}},
		{"two curl commands", "curl -sS " + flags + " url\ncurl -sS " + flags + " url", []string{"lines start with curl"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := curlProblems(tc.run)
			if len(got) != len(tc.want) {
				t.Fatalf("problems %q, want %d, each holding %q", got, len(tc.want), tc.want)
			}
			for i, w := range tc.want {
				if !strings.Contains(got[i], w) {
					t.Errorf("problem %d is %q, want it to hold %q", i, got[i], w)
				}
			}
		})
	}
}

// api-drift.yml downloads Tailscale's OpenAPI document every Monday; a network
// blip there is a red run that says nothing about the API (#19).
func TestAPIDriftRetriesTheDownload(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/api-drift.yml")
	if err != nil {
		t.Fatal(err)
	}
	var wf workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatal(err)
	}
	job, ok := wf.Jobs["drift"]
	if !ok {
		t.Fatal("api-drift.yml has no drift job")
	}
	downloads := 0
	for _, s := range job.Steps {
		if !strings.Contains(s.Run, "curl") {
			continue
		}
		downloads++
		for _, p := range curlProblems(s.Run) {
			t.Errorf("step %q: its curl command has a problem: %s\n%s", s.Name, p, s.Run)
		}
	}
	if downloads != 1 {
		t.Errorf("api-drift.yml runs curl in %d steps, want 1 (the download of the live document)", downloads)
	}
}
