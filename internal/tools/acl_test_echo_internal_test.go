package tools

import (
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
)

// What the caller typed is shown by the text alone: an address is masked with no pseudonym, a
// pseudonym carrier is the caller's own and stays, any other marker is rewritten, and a masked
// value that is not a carrier is left as it is.
func TestEchoedShowsATypedTextByTheTextAlone(t *testing.T) {
	k, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		t.Fatal(err)
	}
	env := &registry.Env{Privacy: k}
	p := k.APIPseudonym("bob@example.org")
	masked := "b…@example.org" + privacy.Suffix(p)
	for in, want := range map[string]string{
		"bob@example.org":                    "b…@example.org",
		"logstream@tailscale:22":             "l…@tailscale:22",
		"x bob@example.org y":                "x b…@example.org y",
		"root":                               "root",
		"tag:db:22":                          "tag:db:22",
		"group:eng@example.com:22":           "group:eng@example.com:22",
		masked:                               masked,
		masked + ":22":                       masked + ":22",
		p:                                    p,
		p + ":22":                            p + ":22",
		"[" + p + "]":                        "[" + p + "]",
		"[" + p + "]:22":                     "[" + p + "]:22",
		"eve [p:abcdefghij]":                 "eve \\u{005B}p:abcdefghij]",
		"eve [p:abcdefghij] bob@example.org": "eve \\u{005B}p:abcdefghij] b…@example.org",
	} {
		if got := echoed(env, in); got != want {
			t.Errorf("echoed(%q) = %q, want %q", in, got, want)
		}
	}
	shown := &registry.Env{Privacy: k, Config: &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}}
	if got := echoed(shown, "bob@example.org"); got != "bob@example.org" {
		t.Errorf("with personalData show: %q", got)
	}
}
