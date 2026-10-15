package tools

import (
	"context"

	"github.com/abm9111/tailkeeper/internal/registry"
)

// Resolver is one DNS resolver.
type Resolver struct {
	Address         string `json:"address" tk:"untrusted,plain"`
	UseWithExitNode bool   `json:"useWithExitNode"`
}

// SplitDomain is a split-DNS route.
type SplitDomain struct {
	Domain    string     `json:"domain" tk:"untrusted"`
	Resolvers []Resolver `json:"resolvers"`
}

// DNSOutput is the tailnet's DNS configuration from /dns/configuration.
type DNSOutput struct {
	Nameservers             []Resolver    `json:"nameservers"`
	SplitDNS                []SplitDomain `json:"splitDns"`
	SearchPaths             []string      `json:"searchPaths" tk:"untrusted"`
	MagicDNS                *bool         `json:"magicDns" jsonschema:"null when the API did not say"`
	OverrideLocalDNS        *bool         `json:"overrideLocalDns" jsonschema:"null when the API did not say"`
	PolicyOverridesAnalysed bool          `json:"policyOverridesAnalysed" jsonschema:"false until milestone M3: split-DNS policies and extraDNSRecords in the policy file are not yet included"`
}

func dnsTools() []registry.Tool {
	m := withOps(readMeta("dns_get", "dns", "get", "Show the tailnet DNS configuration (nameservers, split DNS, search paths, MagicDNS, override).", "dns:read"),
		"GET /tailnet/{tailnet}/dns/configuration")
	m.Notes = "The OpenAPI document names no scope for /dns/configuration; dns:read is assumed and checked by `doctor --probe`."
	return []registry.Tool{registry.Define(m, dnsGet)}
}

func dnsGet(ctx context.Context, env *registry.Env, _ NoInput) (DNSOutput, error) {
	path, err := tailnetPath(env, "/dns/configuration")
	if err != nil {
		return DNSOutput{}, err
	}
	var r struct {
		Nameservers []Resolver            `json:"nameservers"`
		SplitDNS    map[string][]Resolver `json:"splitDNS"`
		SearchPaths []string              `json:"searchPaths"`
		Preferences struct {
			OverrideLocalDNS *bool `json:"overrideLocalDNS"`
			MagicDNS         *bool `json:"magicDNS"`
		} `json:"preferences"`
	}
	if err := get(ctx, env, path, nil, &r); err != nil {
		return DNSOutput{}, err
	}
	out := DNSOutput{
		Nameservers: nonNil(r.Nameservers), SearchPaths: nonNil(r.SearchPaths), SplitDNS: []SplitDomain{},
		MagicDNS: r.Preferences.MagicDNS, OverrideLocalDNS: r.Preferences.OverrideLocalDNS,
	}
	for _, domain := range sortedKeys(r.SplitDNS) {
		out.SplitDNS = append(out.SplitDNS, SplitDomain{Domain: domain, Resolvers: nonNil(r.SplitDNS[domain])})
	}
	return out, nil
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
