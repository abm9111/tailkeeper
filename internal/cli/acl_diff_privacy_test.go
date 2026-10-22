package cli

import (
	"strings"
	"testing"
)

// A login in the destination of a rule is masked wherever acl diff writes about the rule: the
// line of the text layout, the annotation of the GitHub layout and the item of the Markdown
// one. A widening is about the destination, and says which one in a field and not in a
// sentence of its own.
func TestALoginInADestinationIsMaskedInEveryLayoutOfADiff(t *testing.T) {
	older := "{\n\t\"tagOwners\": {\"tag:ci\": []},\n\t\"acls\": [{\"action\": \"accept\", \"src\": [\"tag:ci\"], \"dst\": [\"amy@example.com:22\"]}],\n}\n"
	newer := "{\n\t\"tagOwners\": {\"tag:ci\": []},\n\t\"acls\": [{\"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"amy@example.com:22\"]}],\n}\n"
	for _, format := range []string{"text", "github", "markdown"} {
		t.Run(format, func(t *testing.T) {
			h := newHarness(t, nil)
			code := h.run("acl", "diff", "--format", format, writeFile(t, "old.hujson", older), writeFile(t, "new.hujson", newer))
			if code != 0 {
				t.Fatalf("exit %d: %s%s", code, h.out.String(), h.err.String())
			}
			// The Markdown layout writes an at sign as a character reference.
			out := strings.ReplaceAll(h.out.String(), "&#64;", "@")
			if strings.Contains(out, "amy@") || strings.Contains(out, "amy%40") {
				t.Errorf("the login shows in the %s layout:\n%s", format, out)
			}
			if !strings.Contains(out, "widening") || !strings.Contains(out, "a…@example.com") {
				t.Errorf("the %s layout does not say which destination the widening is about:\n%s", format, out)
			}
		})
	}
}

// A destination shaped like a credential is redacted in every layout, and the diff is written.
func TestACredentialShapedDestinationIsRedactedInEveryLayoutOfADiff(t *testing.T) {
	older := "{\n\t\"tagOwners\": {\"tag:ci\": []},\n\t\"acls\": [{\"action\": \"accept\", \"src\": [\"tag:ci\"], \"dst\": [\"tag:tskey-api-x:80\"]}],\n}\n"
	newer := strings.Replace(older, `"src": ["tag:ci"]`, `"src": ["*"]`, 1)
	for _, format := range []string{"text", "github", "markdown"} {
		t.Run(format, func(t *testing.T) {
			h := newHarness(t, nil)
			code := h.run("acl", "diff", "--format", format, writeFile(t, "old.hujson", older), writeFile(t, "new.hujson", newer))
			if code != 0 {
				t.Fatalf("exit %d: %s%s", code, h.out.String(), h.err.String())
			}
			out := h.out.String()
			if strings.Contains(out, "tskey-api-x") {
				t.Errorf("the credential shape shows in the %s layout:\n%s", format, out)
			}
			if !strings.Contains(out, "widening") {
				t.Errorf("the %s layout lacks the widening, so the diff was not written:\n%s", format, out)
			}
		})
	}
}
