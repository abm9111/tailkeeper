package tools

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tripwire"
)

// ACLSSHTestInput is one SSH test: destinations and the users that must be accepted,
// checked or denied. The source is the call's src, not a field of this struct.
type ACLSSHTestInput struct {
	Dst    []string `json:"dst" jsonschema:"destinations of this SSH test, with no port (tag:prod, 100.64.0.5)"`
	Accept []string `json:"accept,omitempty" jsonschema:"SSH users that must be accepted"`
	Check  []string `json:"check,omitempty" jsonschema:"SSH users that must be checked"`
	Deny   []string `json:"deny,omitempty" jsonschema:"SSH users that must be denied"`
}

const (
	maxPostureAttrs = 16
	maxPostureValue = 256
	maxSSHTests     = 8
	// maxSSHUsers bounds the users of one SSH test, accept, check and deny together. Each
	// destination is read against each user, so a test of 32 destinations and 16 users is
	// 512 verdicts; a list of thousands of users would be a result of megabytes.
	maxSSHUsers = 16
)

// postureAttrRE is a posture attribute name: a lower-case letter, then letters, digits and the
// separators colon, dot, hyphen and underscore. Tailscale's own names are a namespace and a
// camelCase key (node:tsVersion, node:tsReleaseTrack, node:osVersion), and a custom
// attribute is custom:name; neither a space, a slash nor an at sign is part of one.
var postureAttrRE = regexp.MustCompile(`^[a-z][A-Za-z0-9:._-]*$`)

// maskedWithoutPseudonym is why a masked value that carries no pseudonym names no one. One text
// serves a source, a destination and an SSH destination.
const maskedWithoutPseudonym = "a masked value with no pseudonym; ask the user for the real one, or have the owner set personalData to show"

// splitDestination splits a tests-mode destination into a host and one port.
// The port is the text after the last colon. An IPv6 host keeps its brackets.
// A host may itself contain colons: a tag, a bracketed address or a pseudonym carrier.
func splitDestination(d string) (host, port string, err error) {
	if strings.HasPrefix(d, "[") {
		end := strings.Index(d, "]:")
		if end < 0 {
			return "", "", fmt.Errorf("an IPv6 destination is [address]:port")
		}
		inner, bracket := d[1:end], d[:end+1]
		port = d[end+2:]
		if a, perr := netip.ParseAddr(inner); perr == nil && a.Is6() {
			host = bracket
		} else if bracketCarrierRE.MatchString(bracket) {
			host = bracket
		} else {
			return "", "", fmt.Errorf("an IPv6 destination is [address]:port")
		}
	} else {
		i := strings.LastIndexByte(d, ':')
		if i < 0 {
			return "", "", fmt.Errorf("a destination is host:port")
		}
		host, port = d[:i], d[i+1:]
		if a, perr := netip.ParseAddr(host); perr == nil && a.Is6() {
			return "", "", fmt.Errorf("an IPv6 destination needs brackets: [address]:port")
		}
		if _, perr := netip.ParseAddr(d); perr == nil {
			return "", "", fmt.Errorf("an IPv6 destination needs brackets and a port: [address]:port")
		}
	}
	switch {
	case host == "":
		return "", "", fmt.Errorf("the host is empty")
	case strings.Contains(host, "/"):
		return "", "", fmt.Errorf("tests take no CIDR ranges")
	}
	n, nerr := strconv.Atoi(port)
	if nerr != nil || n < 0 || n > 65535 || strconv.Itoa(n) != port {
		return "", "", fmt.Errorf("the port must be one number from 0 to 65535")
	}
	if strings.Contains(host, "…") {
		if _, carrier, _ := carrierRef(host); !carrier {
			return "", "", errors.New(maskedWithoutPseudonym)
		}
	}
	return host, port, nil
}

// checkTestDestination is the one rule for a tests-mode destination. A masked
// address is accepted only when it carries a pseudonym, which is the form a
// result shows a user in. The message is the same wherever the form is refused.
func checkTestDestination(field, d string) error {
	switch {
	case len(d) > maxTestValue:
		return invalidf("%s is longer than %d bytes", field, maxTestValue)
	case sanitize.String(d, 0) != d:
		return invalidf("%s holds control or invisible characters", field)
	case strings.Contains(d, "*"):
		return invalidf("%s: tests take no wildcards", field)
	}
	if _, _, err := splitDestination(d); err != nil {
		return invalidf("%s: %s", field, err.Error())
	}
	return nil
}

// checkTestSrc checks a test source. A plain space is allowed, because a synced
// group is written with spaces in its name. A slash, a control character, a wildcard
// and a masked value that carries no pseudonym are refused.
func checkTestSrc(src string) error {
	switch {
	case strings.TrimSpace(src) == "":
		return invalidf("src is required")
	case src != strings.TrimSpace(src):
		return invalidf("src has leading or trailing spaces")
	case len(src) > maxTestValue:
		return invalidf("src is longer than %d bytes", maxTestValue)
	case strings.Contains(src, "/"):
		return invalidf("src is one identity, with no CIDR range")
	case sanitize.String(src, 0) != src:
		return invalidf("src holds control or invisible characters")
	case strings.Contains(src, "*"):
		return invalidf("src: tests take no wildcards")
	case strings.Contains(src, "…"):
		if _, carrier, _ := carrierRef(src); !carrier {
			return invalidf("src is " + maskedWithoutPseudonym)
		}
	}
	return refuseCredentialShape("src", src)
}

// refuseCredentialShape refuses a subject that holds a credential shape, in the
// bytes as written or once JSON escapes are decoded. Both looks are the policy
// tripwire (tripwire.Check and tripwireWhere); this function does not keep a copy.
func refuseCredentialShape(field, value string) error {
	if value == "" {
		return nil
	}
	if tripwire.Check([]byte(value)) != nil {
		return invalidf("%s holds text shaped like a credential, so it is not sent to Tailscale", field)
	}
	if !strings.Contains(value, `\`) {
		return nil
	}
	// One JSON string, with the caller's bytes inside the quotes, so an escape is
	// decoded by the same walk a policy text uses.
	if _, found := tripwireWhere([]byte(`{"v":"` + value + `"}`)); found {
		return invalidf("%s holds text shaped like a credential, so it is not sent to Tailscale", field)
	}
	return nil
}

// checkPostureAttrs checks the attributes a test passes through. At most 16 keys.
// A key is a name of at most 256 bytes (postureAttrRE). A value is a string of at most 256 bytes, a
// finite number or a bool.
func checkPostureAttrs(attrs map[string]any) error {
	if len(attrs) == 0 {
		return nil
	}
	if len(attrs) > maxPostureAttrs {
		return invalidf("at most %d posture attributes, not %d", maxPostureAttrs, len(attrs))
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		v := attrs[k]
		if !postureAttrRE.MatchString(k) || len(k) > maxPostureValue {
			return invalidf("a posture attribute name starts with a lower-case letter and holds letters, digits and the separators : . - _ up to %d bytes, such as node:tsVersion or custom:my_attr", maxPostureValue)
		}
		switch x := v.(type) {
		case string:
			if len(x) > maxPostureValue {
				return invalidf("a posture attribute value is longer than %d bytes", maxPostureValue)
			}
			if sanitize.String(x, 0) != x {
				return invalidf("a posture attribute value holds control or invisible characters")
			}
			if err := refuseCredentialShape("a posture attribute", x); err != nil {
				return err
			}
		case bool:
		case json.Number:
			if err := finitePosture(x.String()); err != nil {
				return err
			}
		case float64:
			if err := finitePosture(strconv.FormatFloat(x, 'g', -1, 64)); err != nil {
				return err
			}
		case float32:
			if err := finitePosture(strconv.FormatFloat(float64(x), 'g', -1, 32)); err != nil {
				return err
			}
		case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		default:
			return invalidf("a posture attribute value must be a string, a number or a bool")
		}
	}
	return nil
}

func finitePosture(s string) error {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return invalidf("a posture attribute number must be finite")
	}
	return nil
}

// checkSSHTests checks SSH tests before anything is sent. An autogroup source is
// refused (tailscale/tailscale#14102). At most 8 tests, 32 destinations and 16 users
// each, no wildcard, and each test names at least one user.
func checkSSHTests(src string, tests []ACLSSHTestInput) error {
	if err := refuseCredentialShape("src", src); err != nil {
		return err
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(src)), "autogroup:") {
		return invalidf("an SSH test cannot use an autogroup source (tailscale/tailscale#14102)")
	}
	if len(tests) > maxSSHTests {
		return invalidf("at most %d SSH tests, not %d", maxSSHTests, len(tests))
	}
	for i, test := range tests {
		if len(test.Dst) == 0 {
			return invalidf("SSH test %d needs a destination", i)
		}
		if len(test.Dst) > maxDestinations {
			return invalidf("at most %d destinations per SSH test, not %d", maxDestinations, len(test.Dst))
		}
		users := len(test.Accept) + len(test.Check) + len(test.Deny)
		if users == 0 {
			return invalidf("SSH test %d needs a user in accept, check or deny", i)
		}
		if users > maxSSHUsers {
			return invalidf("at most %d SSH users per SSH test, not %d", maxSSHUsers, users)
		}
		for _, list := range []struct {
			name string
			vals []string
			dst  bool
		}{
			{"an SSH destination", test.Dst, true},
			{"an SSH user", test.Accept, false},
			{"an SSH user", test.Check, false},
			{"an SSH user", test.Deny, false},
		} {
			for _, v := range list.vals {
				if err := checkSSHString(list.name, v, list.dst); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// pseudonymCarrier reports whether s is a user as a result shows one: the pseudonym alone, in
// brackets, or after the masked address.
func pseudonymCarrier(s string) bool {
	_, carrier, _ := carrierRef(s)
	return carrier
}

// checkSSHString bounds one SSH destination or user: empty, size, control
// characters, a masked value, and a credential shape. A masked value passes as a
// destination when it carries a pseudonym, as it does for a source and a tests-mode
// destination; an SSH user is an account name, and no masked value is one. A destination
// also takes no CIDR and no port. A tag (tag:prod) has a colon and is not a port.
func checkSSHString(field, v string, dst bool) error {
	switch {
	case strings.TrimSpace(v) == "":
		return invalidf("%s is empty", field)
	case len(v) > maxTestValue:
		return invalidf("%s is longer than %d bytes", field, maxTestValue)
	case sanitize.String(v, 0) != v:
		return invalidf("%s holds control or invisible characters", field)
	case strings.Contains(v, "…") && !(dst && pseudonymCarrier(v)):
		return invalidf("%s is "+maskedWithoutPseudonym, field)
	case strings.Contains(v, "*"):
		return invalidf("SSH tests take no wildcards")
	}
	if dst {
		if strings.Contains(v, "/") {
			return invalidf("an SSH destination takes no CIDR range")
		}
		if _, _, err := splitDestination(v); err == nil {
			return invalidf("an SSH destination takes no port")
		}
	}
	return refuseCredentialShape(field, v)
}

// sshSrcNote is the fixed sentence for a group: source, or "" for any other source.
// A group source is accepted; Tailscale can report it denied when the user is in the
// group (tailscale/tailscale#11790).
func sshSrcNote(src string) string {
	if strings.HasPrefix(src, "group:") {
		return "a group: source in an SSH test can be reported denied when the user is in the group (tailscale/tailscale#11790)"
	}
	return ""
}
