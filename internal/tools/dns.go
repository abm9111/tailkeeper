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

// DNSOutput is the tailnet's DNS configuration from /dns/configuration, plus what the
// policy sets for DNS when the read credential may read the policy.
type DNSOutput struct {
	Nameservers             []Resolver        `json:"nameservers"`
	SplitDNS                []SplitDomain     `json:"splitDns"`
	SearchPaths             []string          `json:"searchPaths" tk:"untrusted"`
	MagicDNS                *bool             `json:"magicDns" jsonschema:"null when the API did not say"`
	OverrideLocalDNS        *bool             `json:"overrideLocalDns" jsonschema:"null when the API did not say"`
	PolicyOverridesAnalysed bool              `json:"policyOverridesAnalysed" jsonschema:"true when extraDNSRecords and DNS node attributes were read from the policy"`
	PolicyNote              string            `json:"policyNote,omitempty" jsonschema:"why the policy part is missing or cut: a fixed sentence"`
	ExtraRecords            []ExtraDNSRecord  `json:"extraDnsRecords,omitempty"`
	ExtraRecordsEffectiveIf []string          `json:"extraDnsRecordsEffectiveIf,omitempty" jsonschema:"settings the extra records need before they take effect"`
	NextDNS                 []DNSResolverAttr `json:"nextdns,omitempty"`
	ControlD                []DNSResolverAttr `json:"controlD,omitempty"`
	ResolverNote            string            `json:"resolverNote,omitempty" jsonschema:"what the resolver attributes cannot tell: precedence between profiles, and that targets are selectors"`
	DNSNodeAttrs            []DNSNodeAttr     `json:"dnsNodeAttrs,omitempty"`
	OtherAttrs              []string          `json:"otherAttrs,omitempty" tk:"untrusted,emails"`
	AttrTableAsOf           string            `json:"attrTableAsOf,omitempty" jsonschema:"the date of the table of DNS node attributes this tool knows"`
	Truncated               bool              `json:"truncated,omitempty" jsonschema:"true when a list was cut at 100 entries or at the size limit"`
}

// ExtraDNSRecord is one extraDNSRecords entry. An empty Type means A or AAAA by the value.
type ExtraDNSRecord struct {
	Name  string `json:"name" tk:"untrusted,emails"`
	Type  string `json:"type,omitempty" tk:"untrusted"`
	Value string `json:"value" tk:"untrusted,emails" jsonschema:"email addresses in it are masked"`
}

// DNSResolverAttr is one NextDNS or Control D attribute. Targets are selectors.
// ID is the profile identifier, masked whole.
type DNSResolverAttr struct {
	Targets      []string `json:"targets" tk:"untrusted,emails"`
	ID           string   `json:"id" tk:"untrusted,personal"`
	Priority     *int     `json:"priority,omitempty"`
	NoDeviceInfo bool     `json:"noDeviceInfo,omitempty"`
}

// DNSNodeAttr is one of the seven DNS node attributes, with the selectors it applies to.
type DNSNodeAttr struct {
	Attr    string   `json:"attr"`
	Targets []string `json:"targets" tk:"untrusted,emails"`
}

func dnsTools() []registry.Tool {
	m := withOps(readMeta("dns_get", "dns", "get", "Show the tailnet DNS configuration (nameservers, split DNS, search paths, MagicDNS, override) and, with policy_file:read, the policy's extraDNSRecords and DNS node attributes.", "dns:read"),
		"GET /tailnet/{tailnet}/dns/configuration",
		"GET /tailnet/{tailnet}/acl")
	m.Notes = "The OpenAPI document names no scope for /dns/configuration; dns:read is assumed and checked by `doctor --probe`. policy_file:read is optional and is used only to read extraDNSRecords and DNS node attributes."
	m.OptionalScopes = []registry.OptionalScope{{
		Scope:  "policy_file:read",
		Reason: "analyse extraDNSRecords and DNS node attributes in the policy",
	}}
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
	budget := newDNSBudget()
	out := DNSOutput{
		Nameservers: nonNil(takeResolvers(budget, r.Nameservers)), SplitDNS: []SplitDomain{},
		MagicDNS: r.Preferences.MagicDNS, OverrideLocalDNS: r.Preferences.OverrideLocalDNS,
	}
	for _, domain := range sortedKeys(r.SplitDNS) {
		if !budget.take(shownText(env, domain)) {
			break
		}
		resolvers := takeResolvers(budget, r.SplitDNS[domain])
		out.SplitDNS = append(out.SplitDNS, SplitDomain{Domain: domain, Resolvers: nonNil(resolvers)})
	}
	out.SearchPaths, _ = budget.prefixShown(r.SearchPaths, func(s string) string { return shownText(env, s) })
	out.SearchPaths = nonNil(out.SearchPaths)
	reading, err := dnsPolicy(ctx, env, budget)
	if err != nil {
		return DNSOutput{}, err
	}
	out.PolicyOverridesAnalysed = reading.analysed
	out.PolicyNote = reading.note
	out.ExtraRecords = reading.records
	out.ExtraRecordsEffectiveIf = reading.effectiveIf
	out.NextDNS = reading.nextDNS
	out.ControlD = reading.controlD
	out.ResolverNote = reading.resolverNote
	out.DNSNodeAttrs = reading.nodeAttrs
	out.OtherAttrs = reading.other
	out.AttrTableAsOf = reading.asOf
	out.Truncated = reading.truncated || budget.cut
	if budget.cut {
		// The note the policy part has stays, and the cut is said after it.
		if out.PolicyNote != "" {
			out.PolicyNote += "; "
		}
		out.PolicyNote += dnsNoteCut
	}
	return out, nil
}

// takeResolvers returns the start of in that fits the budget, a resolver at a time.
func takeResolvers(b *dnsBudget, in []Resolver) []Resolver {
	for i, r := range in {
		if !b.take(r.Address) {
			return in[:i:i]
		}
	}
	return in
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
