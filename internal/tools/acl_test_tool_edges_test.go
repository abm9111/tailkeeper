package tools_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// The structure checks of acl_test, at their edges and by the reason they give:
// destinations, the protocol, ICMP and the length of a value.
func TestACLTestInputChecksAtTheirEdges(t *testing.T) {
	reg := newRegistry(t)
	tool, _ := reg.Get("acl_test")
	many := func(n int) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = fmt.Sprintf(`"tag:prod:%d"`, i+1)
		}
		return strings.Join(parts, ",")
	}
	for _, c := range []struct {
		args string
		want string // "" means valid; otherwise a part of the reason
	}{
		{`{"src":"tag:ci","accept":["tag:prod:22"]}`, ""},
		{`{"src":"tag:ci","accept":[` + many(32) + `]}`, ""},
		{`{"src":"tag:ci","accept":[` + many(33) + `]}`, "at most 32 destinations"},
		{`{"src":"tag:ci","accept":[` + many(16) + `],"deny":[` + many(16) + `]}`, ""},
		{`{"src":"tag:ci","accept":[` + many(17) + `],"deny":[` + many(16) + `]}`, "at most 32 destinations"},
		{`{"src":"tag:ci","accept":["tag:prod:22"],"proto":"0"}`, "must be between 1 and 255"},
		{`{"src":"tag:ci","accept":["tag:prod:22"],"proto":"1"}`, "ICMP tests use port 0"},
		{`{"src":"tag:ci","accept":["tag:prod:22"],"proto":"255"}`, ""},
		{`{"src":"tag:ci","accept":["tag:prod:22"],"proto":"256"}`, "must be between 1 and 255"},
		{`{"src":"tag:ci","accept":["tag:prod:22"],"proto":"tcp"}`, ""},
		{`{"src":"tag:ci","accept":["tag:prod:22"],"proto":"TCP"}`, "must be a protocol name"},
		{`{"src":"tag:ci","accept":["tag:prod:22"],"proto":"icmp"}`, "ICMP tests use port 0"},
		{`{"src":"tag:ci","accept":["tag:prod:22"],"proto":"ipv6-icmp"}`, "ICMP tests use port 0"},
		{`{"src":"tag:ci","accept":["tag:prod:22"],"proto":"58"}`, "ICMP tests use port 0"},
		{`{"src":"tag:ci","deny":["tag:prod:22"],"proto":"icmp"}`, "deny[0]: ICMP tests use port 0"},
		{`{"src":"tag:ci","accept":["tag:prod:0"],"proto":"icmp"}`, ""},
		{`{"src":"tag:ci","accept":["tag:prod:22"],"proto":"udp"}`, ""},
		{`{"src":"` + strings.Repeat("a", 300) + `","accept":["h:1"]}`, ""},
		{`{"src":"` + strings.Repeat("a", 301) + `","accept":["h:1"]}`, "src is longer than 300 bytes"},
		{`{"src":"tag:ci","accept":["` + strings.Repeat("a", 297) + `:22"]}`, ""},
		{`{"src":"tag:ci","accept":["` + strings.Repeat("a", 298) + `:22"]}`, "accept[0] is longer than 300 bytes"},
		{`{"src":"tag:ci","accept":["[fd7a:115c:a1e0::5]:22"]}`, ""},
		{`{"src":"tag:ci","accept":["[::1]:22"]}`, ""},
		{`{"src":"tag:ci","accept":["[]:22"]}`, "the host is empty"},
		{`{"src":"tag:ci","accept":["[::1]22"]}`, "an IPv6 destination is [address]:port"},
		{`{"src":"tag:ci","accept":["[::1]"]}`, "an IPv6 destination is [address]:port"},
		{`{"src":"tag:ci","accept":["[::1]:10"],"proto":"icmp"}`, "ICMP tests use port 0"},
		{`{"src":"tag:ci","accept":["[::1]:0"],"proto":"icmp"}`, ""},
		{`{"src":"tag:ci","accept":["[::1]:65535"]}`, ""},
		{`{"src":"tag:ci","accept":["[::1]:65536"]}`, "the port must be one number from 0 to 65535"},
		{`{"src":"tag:ci","accept":["h:022"]}`, "the port must be one number"},
		{`{"src":"tag:ci","accept":["h:-1"]}`, "the port must be one number"},
		{`{"src":"tag:ci","accept":["justahost"]}`, "a destination is host:port"},
		{`{"src":"tag:ci","accept":[":22"]}`, "the host is empty"},
		{`{"src":"tag:ci","accept":["10.0.0.0/24:22"]}`, "tests take no CIDR ranges"},
		{`{"src":"tag:ci","accept":["fd7a:115c:a1e0::5:22"]}`, "an IPv6 destination needs brackets"},
		{`{"src":"tag:ci","accept":["fd7a:115c:a1e0::5"]}`, "an IPv6 destination needs brackets"},
		{`{"src":"tag:ci","accept":["100.64.0.5:443"]}`, ""},
		{`{"src":"tag:*","accept":["h:22"]}`, "tests take no wildcards"},
		{`{"src":"tag:ci","accept":["h:*"]}`, "tests take no wildcards"},
		{`{"src":"a\u2026@example.com","accept":["h:22"]}`, "is a masked value"},
		{`{"src":"tag ci","accept":["h:22"]}`, "one identity, with no CIDR range and no spaces"},
		{`{"src":"10.0.0.0/8","accept":["h:22"]}`, "one identity, with no CIDR range and no spaces"},
		{`{"src":" ","accept":["h:22"]}`, "src is required"},
	} {
		_, err := tool.Validate(json.RawMessage(c.args))
		switch e, isErr := tkerr.As(err); {
		case c.want == "" && err != nil:
			t.Errorf("%s: Validate = %v, want it valid", c.args[:min(len(c.args), 90)], err)
		case c.want != "" && (!isErr || e.Code != tkerr.ValidationFailed || !strings.Contains(e.Message, c.want)):
			t.Errorf("%s: Validate = %v, want validation_failed mentioning %q", c.args[:min(len(c.args), 90)], err, c.want)
		}
	}
}
