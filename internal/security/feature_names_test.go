package security

import "testing"

// A shipped rule names a feature by its spelling, so the spelling is part of the catalog
// format: changing a constant's value would silently change what a rule requires.
func TestFeatureNamesKeepTheirCatalogSpelling(t *testing.T) {
	names := []struct{ got, want string }{
		{FeatureConnectedToControl, "connected_to_control"},
		{FeatureTailscaleSSH, "tailscale_ssh"},
		{FeatureSSHForwardingAllowed, "ssh_forwarding_allowed"},
		{FeatureServeUnixBackend, "serve_unix_backend"},
		{FeatureServeTLSMultiMount, "serve_tls_multi_mount"},
	}
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if n.got != n.want {
			t.Errorf("feature name %q, want %q", n.got, n.want)
		}
		if seen[n.got] {
			t.Errorf("feature name %q is defined twice", n.got)
		}
		seen[n.got] = true
	}
}
