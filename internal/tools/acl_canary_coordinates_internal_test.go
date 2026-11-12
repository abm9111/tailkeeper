package tools

import "testing"

// The coordinates of the canaries are the address 192.0.2.1 on a port that holds port 1 (the
// tests canary) and the user canary on that address (the SSH canary). Anything that reads as
// those, or cannot be read, is set aside; anything else is not.
func TestNamesTheCanaryCoordinates(t *testing.T) {
	hosts := map[string]string{"example-canary": "192.0.2.1", "example-canary32": "192.0.2.1/32", "example-net": "192.0.2.0/24", "example-other": "192.0.2.2", "example-bad": "not an address"}
	for dst, want := range map[string]bool{
		"192.0.2.1:1":             true,
		"192.0.2.1:*":             true,
		"192.0.2.1:1-100":         true,
		"192.0.2.1:0-65535":       true,
		"192.0.2.1:22,1":          true,
		"192.0.2.1:abc":           true, // a port spec that cannot be read may hold port 1
		"[::ffff:192.0.2.1]:1":    true,
		"example-canary:1":        true,
		"example-canary32:1":      true,
		"192.0.2.1:2":             false,
		"192.0.2.1:22,443":        false,
		"192.0.2.2:1":             false,
		"192.0.2.10:1":            false,
		"example-other:1":         false,
		"example-net:1":           false, // a range that holds the address is not the address
		"example-bad:1":           false,
		"tag:example-db:1":        false,
		"[2001:db8::1]:1":         false,
		"192.0.2.1":               false, // no port: not a destination of a test
		":1":                      false,
		"[192.0.2.1]:1":           true,
		"192.0.2.1/32:1":          true,
		"192.0.2.0/24:1":          false,
		"192.0.2.1/24:1":          false, // the address with a prefix length is a range, not the address
		"192.0.2.1:2-100":         false,
		"192.0.2.1:65535":         false,
		"192.0.2.1:2,3,4,5,6,7,8": false,
	} {
		if got := namesTheTestsCanary(dst, hosts); got != want {
			t.Errorf("namesTheTestsCanary(%q) = %v, want %v", dst, got, want)
		}
	}
	for _, c := range []struct {
		dst, user string
		want      bool
	}{
		{"192.0.2.1", "canary", true},
		{"example-canary", "canary", true},
		{"::ffff:192.0.2.1", "canary", true},
		{"192.0.2.1", "root", false},
		{"192.0.2.1", "Canary", false},
		{"192.0.2.2", "canary", false},
		{"tag:example-db", "canary", false},
		{"example-net", "canary", false},
	} {
		if got := namesTheSSHCanary(c.dst, c.user, hosts); got != c.want {
			t.Errorf("namesTheSSHCanary(%q, %q) = %v, want %v", c.dst, c.user, got, c.want)
		}
	}
	if namesTheSSHCanary("example-canary", "canary", nil) {
		t.Error("an alias was resolved with no hosts")
	}
}
