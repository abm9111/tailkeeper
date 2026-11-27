package workflows

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The secret scanners of the push gate did not know this project's own credential: gitleaks
// 8.30 has no Tailscale rule and trufflehog 3.100 matches tskey-api- keys only, so an OAuth
// client secret or an auth key passed both (VIGIL-SEC-001, 27 Nov 2026). .gitleaks.toml adds
// the rule; these tests read it from there, check that it finds every key kind and no mere
// mention of a prefix, and apply it to the files a commit could take.

// tailscaleKeyRule is the regex of the tailscale-key rule in .gitleaks.toml.
func tailscaleKeyRule(t *testing.T) *regexp.Regexp {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", ".gitleaks.toml"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)\nid = "tailscale-key"\n.*?\nregex = '''([^']+)'''`).FindSubmatch(b)
	if m == nil {
		t.Fatal(`.gitleaks.toml has no tailscale-key rule with a regex = '''...''' line`)
	}
	re, err := regexp.Compile(string(m[1]))
	if err != nil {
		t.Fatalf("the tailscale-key regex does not compile: %v", err)
	}
	return re
}

func TestTheGitleaksRuleFindsEveryTailscaleKeyKind(t *testing.T) {
	re := tailscaleKeyRule(t)
	// Built, never written whole, so this file holds no key shape itself.
	id, secret := "k"+strings.Repeat("Q", 9)+"CNTRL", strings.Repeat("s", 33)
	for _, kind := range []string{"api", "auth", "client", "scim", "webhook", "app"} {
		if line := "TAILKEEPER_READ_CLIENT_SECRET=tskey-" + kind + "-" + id + "-" + secret; !re.MatchString(line) {
			t.Errorf("the rule misses a tskey-%s- key", kind)
		}
	}
	for _, mention := range []string{
		"tskey-api-", "tskey-client-<id>-<secret>", "tskey-api-<id>-<secret>;", "tskey-auth-abc123.com",
		"tskey-api-x:22", "tskey-api-" + strings.Repeat("k", 16), "tskey-key-" + id + "-" + secret,
	} {
		if re.MatchString(mention) {
			t.Errorf("the rule matches %q, which is not a key", mention)
		}
	}
}

// TestTheTreeHoldsNoTailscaleKey reads every regular file at the root and under every
// directory but build output (bin, dist) and machine-local dot-directories (.git, .claude and
// the like; .github is read). A *.local.md file is one machine's notes and is never committed,
// so it is not read. A hit names the file and line, never the text.
func TestTheTreeHoldsNoTailscaleKey(t *testing.T) {
	re := tailscaleKeyRule(t)
	root := filepath.Join("..", "..")
	var hits []string
	scan := func(path string) error {
		b, err := os.ReadFile(path)
		if err != nil || !re.Match(b) {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		for i, line := range bytes.Split(b, []byte("\n")) {
			if re.Match(line) {
				hits = append(hits, fmt.Sprintf("%s:%d", filepath.ToSlash(rel), i+1))
			}
		}
		return nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	files := 0
	for _, e := range entries {
		name, path := e.Name(), filepath.Join(root, e.Name())
		switch {
		case e.Type().IsRegular():
			if strings.HasSuffix(name, ".local.md") {
				continue
			}
			files++
			if err := scan(path); err != nil {
				t.Fatal(err)
			}
		case e.IsDir():
			if name == "bin" || name == "dist" || (strings.HasPrefix(name, ".") && name != ".github") {
				continue
			}
			err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() && d.Name() == ".git" {
					return filepath.SkipDir
				}
				if !d.Type().IsRegular() {
					return nil
				}
				files++
				return scan(p)
			})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	// The walk must have reached the tree: a wrong root would pass on nothing.
	if files < 500 {
		t.Fatalf("read %d files, expected the repository's (over 500)", files)
	}
	if len(hits) > 0 {
		t.Errorf("a Tailscale key shape (the tailscale-key rule of .gitleaks.toml) is at %s: remove it, and revoke it in the admin console if Tailscale ever issued it", strings.Join(hits, ", "))
	}
}
