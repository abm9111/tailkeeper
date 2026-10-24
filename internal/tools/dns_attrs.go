package tools

// dnsNodeAttrs are the DNS node attributes Tailscale's client defines, in the
// order the result lists them. A name that is not here is not reported as DNS.
// provenance: tailcfg/nodecap, 2026-10-17, names sha256 8a6b61be448d3fb2df60f3bc70abb87a724f77a21fa6e337ae2e54cdd3857d76
var dnsNodeAttrs = [...]string{
	"magicdns-aaaa",
	"dns-subdomain-resolve",
	"dns-forwarder-disable-tcp-retries",
	"disable-split-dns-when-no-custom-resolvers",
	"disable-local-dns-override-via-nrpt",
	"disable-hosts-file-updates",
	"force-register-magicdns-ipv4-only",
}

// dnsAttrTableAsOf is the date of dnsNodeAttrs, printed when the policy was read.
const dnsAttrTableAsOf = "2026-10-17"

// dnsNodeAttrIndex reports the table position of name, or -1 when name is not one of the seven.
func dnsNodeAttrIndex(name string) int {
	for i, n := range dnsNodeAttrs {
		if n == name {
			return i
		}
	}
	return -1
}
