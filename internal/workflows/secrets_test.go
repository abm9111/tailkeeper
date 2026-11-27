package workflows

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The secret scanners of the push gate did not know this project's own credential: gitleaks
// 8.30 has no Tailscale rule, and trufflehog 3.100 missed tskey-client- and tskey-auth- keys,
// the two kinds tailkeeper uses (VIGIL-SEC-001, 27 Nov 2026). .gitleaks.toml adds the rule;
// these tests read it from there, check that it finds every key kind and no mere mention of a
// prefix, and apply it to the files a commit could take.

// gitleaksConfig is .gitleaks.toml.
func gitleaksConfig(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", ".gitleaks.toml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// tailscaleKeyRule is the regex of the tailscale-key rule in .gitleaks.toml.
func tailscaleKeyRule(t *testing.T) *regexp.Regexp {
	t.Helper()
	m := regexp.MustCompile(`(?s)\nid = "tailscale-key"\n.*?\nregex = '''([^']+)'''`).FindStringSubmatch(gitleaksConfig(t))
	if m == nil {
		t.Fatal(`.gitleaks.toml has no tailscale-key rule with a regex = '''...''' line`)
	}
	re, err := regexp.Compile(m[1])
	if err != nil {
		t.Fatalf("the tailscale-key regex does not compile: %v", err)
	}
	return re
}

func TestTheGitleaksConfigKeepsTheDefaultRules(t *testing.T) {
	if !regexp.MustCompile(`(?m)^\[extend\]\nuseDefault = true$`).MatchString(gitleaksConfig(t)) {
		t.Error(".gitleaks.toml must extend the default rules ([extend] useDefault = true): without it the file replaces them")
	}
}

func TestTheGitleaksRuleFindsEveryTailscaleKeyKind(t *testing.T) {
	re := tailscaleKeyRule(t)
	// Built, never written whole, so this file holds no key shape itself.
	id, secret := "k"+strings.Repeat("Q", 9)+"CNTRL", strings.Repeat("s", 33)
	for _, kind := range []string{"api-", "auth-", "client-", "scim-", "webhook-", "app-", ""} {
		if line := "TAILKEEPER_READ_CLIENT_SECRET=tskey-" + kind + id + "-" + secret; !re.MatchString(line) {
			t.Errorf("the rule misses a tskey-%s key", kind)
		}
	}
	for _, mention := range []string{
		"tskey-api-", "tskey-client-<id>-<secret>", "tskey-api-<id>-<secret>;", "tskey-auth-abc123.com",
		"tskey-api-x:22", "tskey-api-" + strings.Repeat("k", 16), "tskey-key-" + strings.Repeat("s", 20),
	} {
		if re.MatchString(mention) {
			t.Errorf("the rule matches %q, which is not a key", mention)
		}
	}
}

// skipDirs are the root directories a commit never takes: build output and one machine's tool
// state. Every other directory is read, dot-directories included.
var skipDirs = map[string]bool{
	".git": true, "bin": true, "dist": true,
	".claude": true, ".superpowers": true, ".vigil": true, ".worktrees": true,
}

// TestTheTreeHoldsNoTailscaleKey reads every regular file under the repository root but those
// in skipDirs, a nested .git, a *.local.md file (one machine's notes, never committed) and a
// *.test binary (go test -c and -cpuprofile leave one; the compiler folds a test's built key
// into one literal there). A hit names the file and line, never the text. A file that cannot be
// read fails the test, since it was not scanned; one that went away during the walk is skipped.
func TestTheTreeHoldsNoTailscaleKey(t *testing.T) {
	re := tailscaleKeyRule(t)
	root := filepath.Join("..", "..")
	var hits, unread []string
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if (!strings.Contains(rel, "/") && skipDirs[rel]) || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || strings.HasSuffix(rel, ".local.md") || strings.HasSuffix(rel, ".test") {
			return nil
		}
		b, err := os.ReadFile(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil
		case err != nil:
			unread = append(unread, fmt.Sprintf("%s (%v)", rel, err))
			return nil
		}
		seen[rel] = true
		if !re.Match(b) {
			return nil
		}
		for i, line := range bytes.Split(b, []byte("\n")) {
			if re.Match(line) {
				hits = append(hits, fmt.Sprintf("%s:%d", rel, i+1))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The walk must have reached the tree: a wrong root, or a skip that grew too wide, would
	// pass on nothing.
	for _, f := range []string{"go.mod", ".gitleaks.toml", ".github/workflows/verify.yml", "internal/workflows/secrets_test.go", "docs/design.md"} {
		if !seen[f] {
			t.Errorf("the walk did not read %s", f)
		}
	}
	if len(unread) > 0 {
		t.Errorf("not scanned, so not known to be clean: %s", strings.Join(unread, ", "))
	}
	if len(hits) > 0 {
		t.Errorf("a Tailscale key shape (the tailscale-key rule of .gitleaks.toml) is at %s: remove it, and revoke it in the admin console if Tailscale ever issued it", strings.Join(hits, ", "))
	}
}
