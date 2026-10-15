// Package tripwire is the backstop of spec §7.6. Serialized results and audit
// lines are scanned for credential shapes, and a hit fails closed. The typed
// output allowlist is the control; the tripwire catches what slips past it.
package tripwire

import (
	"regexp"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

var patterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"tailscale key", regexp.MustCompile(`tskey-(api|auth|client|scim|webhook|app)-`)},
	{"JWT", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
}

// Check returns an output_withheld error naming the kind of match, never the
// matched text, when b contains a credential shape.
func Check(b []byte) error {
	for _, p := range patterns {
		if p.re.Match(b) {
			return tkerr.New(tkerr.OutputWithheld, "output withheld: it contains a "+p.kind+" shape",
				"this is a tailkeeper bug or hostile tailnet text; report it without the output")
		}
	}
	return nil
}

// Redacted replaces a credential shape inside text that tailnet members choose.
const Redacted = "[credential-shaped text removed]"

// redactions match whole credential-shaped tokens, not only their prefixes.
var redactions = []*regexp.Regexp{
	regexp.MustCompile(`tskey-(api|auth|client|scim|webhook|app)-[A-Za-z0-9_-]*`),
	patterns[1].re,
}

// Redact replaces every credential shape in s with Redacted. It is for fields that
// tailnet members write (device names, descriptions): such a field can neither
// leak a key nor, by holding a key shape, withhold the whole result it is in.
func Redact(s string) string {
	for _, re := range redactions {
		s = re.ReplaceAllString(s, Redacted)
	}
	return s
}
