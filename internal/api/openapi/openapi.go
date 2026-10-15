// Package openapi pins the operations of Tailscale's OpenAPI document (spec §20).
// operations.txt lists every operation in it, with a header naming the document's
// sha256. The document itself is not committed: TestOperationsMatchTheDocument
// compares the list with a copy named by TAILKEEPER_OPENAPI_LIVE, and the weekly
// drift check does the same against the live document. fingerprint.txt pins what
// the tools decode: the required operations and the fields of their 2xx JSON
// responses, compared by TestLiveDocumentMatchesThePin. The binary never parses
// YAML.
package openapi

import (
	_ "embed"
	"strings"
)

//go:embed operations.txt
var operationsTxt string

// Operations returns every operation of the pinned document as "METHOD /path",
// sorted.
func Operations() []string { return parseOperations(operationsTxt) }

// parseOperations reads one operation per line, skipping blank lines and the
// header lines that start with "#".
func parseOperations(text string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// Required reports whether tailkeeper must answer for op: each GET, and the
// policy validation acl_test sends. Writes arrive with the gate (M2).
func Required(op string) bool {
	return strings.HasPrefix(op, "GET ") || op == "POST /tailnet/{tailnet}/acl/validate"
}

// Skipped lists the required operations no tool calls, and why.
var Skipped = map[string]string{
	"GET /tailnet/{tailnet}/dns/nameservers":                                   "dns_get reads /dns/configuration, which carries the nameservers",
	"GET /tailnet/{tailnet}/dns/preferences":                                   "dns_get reads /dns/configuration, which carries MagicDNS and the override setting",
	"GET /tailnet/{tailnet}/dns/searchpaths":                                   "dns_get reads /dns/configuration, which carries the search paths",
	"GET /tailnet/{tailnet}/dns/split-dns":                                     "dns_get reads /dns/configuration, which carries split DNS",
	"GET /tailnet/{tailnet}/services/{serviceName}/devices":                    "a privileged read: the API demands the write-level services scope with devices:core, so service_hosts waits for the approval gate (M2)",
	"GET /tailnet/{tailnet}/services/{serviceName}/device/{deviceId}/approved": "a privileged read: the API demands the write-level services scope with devices:core, so service_hosts waits for the approval gate (M2)",
	"GET /organizations/{organization}/tailnets":                               "organization endpoints are a non-goal in v1 (spec §2)",
}
