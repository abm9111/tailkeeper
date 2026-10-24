package tools

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// dnsListCap is the most entries one policy-derived list shows. The rest is
// reported by Truncated, never by a count taken from the text.
const dnsListCap = 100

// dnsResultBudget is the most characters, as JSON text and as the registry will show them,
// that the lists of a dns_get result take together. The policy names its targets again in every
// list, a result lists up to 100 entries of up to 100 targets, and the DNS configuration can be
// as long as an 8 MiB reply. An ordinary tailnet takes a few thousand.
const dnsResultBudget = 100000

// dnsBudget is the room left in a dns_get result. It is spent in the order the result is
// built, and once something did not fit, nothing after it does: the result is a prefix of
// what the DNS configuration and the policy hold.
type dnsBudget struct {
	left int
	cut  bool
}

func newDNSBudget() *dnsBudget { return &dnsBudget{left: dnsResultBudget} }

// take spends the cost of the strings and reports whether they all fit. A group that does not
// fit spends nothing and closes the budget.
func (b *dnsBudget) take(strs ...string) bool {
	cost := 0
	for _, s := range strs {
		cost += shownCost(s)
	}
	if b.cut || cost > b.left {
		b.cut = true
		return false
	}
	b.left -= cost
	return true
}

// prefix returns the longest start of in that fits, after the room that fixed takes, and
// closes the budget when it is not all of in.
func (b *dnsBudget) prefix(in []string, fixed ...string) ([]string, bool) {
	return b.prefixShown(in, func(s string) string { return s }, fixed...)
}

// prefixShown is prefix for strings the registry still rewrites: each is counted as show makes
// it, and the strings returned are those of in.
func (b *dnsBudget) prefixShown(in []string, show func(string) string, fixed ...string) ([]string, bool) {
	if !b.take(fixed...) {
		return nil, false
	}
	for i, s := range in {
		if !b.take(show(s)) {
			return in[:i:i], true
		}
	}
	return in, true
}

// Fixed sentences. A policy string never reaches one of them.
const (
	dnsNoteUnread    = "the policy was not read"
	dnsNoteNoScope   = "the policy was not read: the read credential lacks policy_file:read"
	dnsNoteNotPolicy = "the policy was not analysed: the text is not a policy"
	dnsNoteShape     = "the policy was not analysed: extraDNSRecords or nodeAttrs is not a list"
	dnsNoteDepth     = "the policy was not analysed: the text nests too deeply"
	dnsNoteCap       = "the policy was not analysed: the text is over the size cap"
	dnsNoteComplex   = "the policy was not analysed: the text is past a work budget"
	dnsNoteCut       = "the result was cut to its size limit: what is listed is the start of what the tailnet holds"

	dnsEffectiveOverride = "overrideLocalDNS"
	dnsEffectiveAlpha    = "alphaEnabled"

	dnsPrecedenceUnknown      = "precedence unknown"
	dnsTargetsAreSelectors    = "targets are selectors, not devices"
	dnsPrecedenceAndSelectors = "precedence unknown; targets are selectors, not devices"
	dnsNextNoDeviceInfo       = "nextdns:no-device-info"
)

// policyReading is what dns_get adds from the policy. analysed is false, and note
// is set, when the policy could not be read or could not be used; the call still
// succeeds. A note is one of the fixed sentences.
type policyReading struct {
	analysed     bool
	note         string
	records      []ExtraDNSRecord
	effectiveIf  []string
	nextDNS      []DNSResolverAttr
	controlD     []DNSResolverAttr
	resolverNote string
	nodeAttrs    []DNSNodeAttr
	other        []string
	asOf         string
	truncated    bool
}

func unread(note string) policyReading { return policyReading{note: note} }

// dnsPolicy reads the live policy and takes extraDNSRecords and the DNS node
// attributes from it. It returns no error for a policy that cannot be read or
// cannot be used: the reading carries the reason, and dns_get still succeeds.
func dnsPolicy(ctx context.Context, env *registry.Env, budget *dnsBudget) (policyReading, error) {
	c, err := env.RequireAPI()
	if err != nil {
		return unread(dnsNoteUnread), nil
	}
	details, err := c.GetPolicyDetails(ctx)
	if err != nil {
		return unread(policyReadNote(err)), nil
	}
	std, err := acl.Standardize(ctx, details.Text)
	if err != nil {
		return unread(policyEngineNote(err)), nil
	}
	var doc struct {
		Extra json.RawMessage `json:"extraDNSRecords"`
		Attrs json.RawMessage `json:"nodeAttrs"`
	}
	if err := json.Unmarshal(std, &doc); err != nil {
		return unread(dnsNoteNotPolicy), nil
	}
	records, err := decodeExtraRecords(doc.Extra)
	if err != nil {
		return unread(dnsNoteShape), nil
	}
	entries, err := decodeNodeAttrs(doc.Attrs)
	if err != nil {
		return unread(dnsNoteShape), nil
	}
	return readPolicyDNS(env, budget, records, entries), nil
}

// policyReadNote maps a failed policy read to a fixed sentence. The error's own
// text stays out of the result: it can quote a size.
func policyReadNote(err error) string {
	e, ok := tkerr.As(err)
	if !ok {
		return dnsNoteUnread
	}
	if e.Code == tkerr.ScopeMissing {
		return dnsNoteNoScope
	}
	if e.Code == tkerr.APIError && strings.Contains(e.Message, "more than the 4 MiB") {
		return dnsNoteCap
	}
	return dnsNoteUnread
}

// policyEngineNote maps a refusal from the policy engine to a fixed sentence.
func policyEngineNote(err error) string {
	var e *acl.Error
	if !errors.As(err, &e) {
		return dnsNoteNotPolicy
	}
	switch e.Code {
	case acl.CodeTooComplex:
		if strings.Contains(e.Message, "more than the") {
			return dnsNoteCap
		}
		return dnsNoteComplex
	case acl.CodeInvalid:
		if strings.Contains(e.Message, "nests deeper") {
			return dnsNoteDepth
		}
		return dnsNoteNotPolicy
	default:
		return dnsNoteNotPolicy
	}
}

type rawExtraRecord struct {
	Name  string `json:"Name"`
	Type  string `json:"Type"`
	Value string `json:"Value"`
}

func decodeExtraRecords(raw json.RawMessage) ([]rawExtraRecord, error) {
	if len(bytesTrim(raw)) == 0 || string(bytesTrim(raw)) == "null" {
		return nil, nil
	}
	var recs []rawExtraRecord
	if err := json.Unmarshal(raw, &recs); err != nil {
		return nil, err
	}
	return recs, nil
}

type rawNodeAttr struct {
	Target []string `json:"target"`
	Attr   []string `json:"attr"`
}

func decodeNodeAttrs(raw json.RawMessage) ([]rawNodeAttr, error) {
	if len(bytesTrim(raw)) == 0 || string(bytesTrim(raw)) == "null" {
		return nil, nil
	}
	var entries []rawNodeAttr
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func bytesTrim(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

func readPolicyDNS(env *registry.Env, budget *dnsBudget, records []rawExtraRecord, entries []rawNodeAttr) policyReading {
	out := policyReading{analysed: true, asOf: dnsAttrTableAsOf}
	for _, rec := range records {
		if rec.Name == "" && rec.Value == "" {
			continue
		}
		if len(out.records) >= dnsListCap {
			out.truncated = true
			break
		}
		shown := ExtraDNSRecord{
			Name:  policyDisplay(env, rec.Name),
			Type:  policyDisplay(env, rec.Type),
			Value: policyDisplay(env, rec.Value),
		}
		if !budget.take(shown.Name, shownText(env, shown.Type), shown.Value) {
			out.truncated = true
			break
		}
		out.records = append(out.records, shown)
	}
	if len(out.records) > 0 {
		out.effectiveIf = []string{dnsEffectiveOverride, dnsEffectiveAlpha}
	}
	var other []string
	nodeTargets := map[string][]string{}
	for _, entry := range entries {
		targets := showTargets(env, entry.Target, &out.truncated)
		var profiles []string
		noDevice := false
		for _, attr := range entry.Attr {
			if attr == dnsNextNoDeviceInfo {
				noDevice = true
				continue
			}
			if isNextDNSProfile(attr) {
				profiles = append(profiles, strings.TrimPrefix(attr, "nextdns:"))
				continue
			}
			if id, priority, ok := takeControlD(attr); ok {
				out.controlD = appendCapped(env, out.controlD, DNSResolverAttr{Targets: targets, ID: id, Priority: priority}, budget, &out.truncated)
				continue
			}
			if label, ok := unparsedProfile(attr); ok {
				other = append(other, label)
				continue
			}
			if dnsNodeAttrIndex(attr) >= 0 {
				nodeTargets[attr] = append(nodeTargets[attr], targets...)
				continue
			}
			other = append(other, attr)
		}
		if noDevice && len(profiles) == 0 {
			profiles = []string{""}
		}
		for _, id := range profiles {
			out.nextDNS = appendCapped(env, out.nextDNS, DNSResolverAttr{Targets: targets, ID: id, NoDeviceInfo: noDevice}, budget, &out.truncated)
		}
	}
	for _, name := range dnsNodeAttrs {
		targets, ok := nodeTargets[name]
		if !ok {
			continue
		}
		capped := capTargets(targets, &out.truncated)
		kept, ok := budget.prefix(capped, name)
		if !ok {
			out.truncated = true
			break
		}
		if len(kept) < len(capped) {
			out.truncated = true
		}
		out.nodeAttrs = append(out.nodeAttrs, DNSNodeAttr{Attr: name, Targets: kept})
	}
	out.other = showOther(env, budget, other, &out.truncated)
	out.resolverNote = resolverNote(out.nextDNS, out.controlD, out.nodeAttrs)
	return out
}

func isNextDNSProfile(attr string) bool {
	id, ok := strings.CutPrefix(attr, "nextdns:")
	return ok && id != "" && id != "no-device-info" && !strings.ContainsAny(id, "? \t")
}

func takeControlD(attr string) (string, *int, bool) {
	rest, ok := strings.CutPrefix(attr, "controld:")
	if !ok || rest == "" {
		return "", nil, false
	}
	id, query, hasQ := strings.Cut(rest, "?")
	if id == "" || strings.ContainsAny(id, " \t") {
		return "", nil, false
	}
	if !hasQ {
		return id, nil, true
	}
	n, ok := strings.CutPrefix(query, "priority=")
	if !ok || n == "" || strings.Trim(n, "0123456789") != "" {
		return "", nil, false
	}
	v, err := strconv.Atoi(n)
	if err != nil {
		return "", nil, false
	}
	return id, &v, true
}

// unparsedProfile is the fixed label for a nextdns: or controld: attribute that
// did not parse. The raw value is a profile id and is never listed.
func unparsedProfile(attr string) (string, bool) {
	switch {
	case strings.HasPrefix(attr, "nextdns:"):
		return "nextdns:(unparsed)", true
	case strings.HasPrefix(attr, "controld:"):
		return "controld:(unparsed)", true
	}
	return "", false
}

func showTargets(env *registry.Env, in []string, truncated *bool) []string {
	return capTargets(showEach(env, in), truncated)
}

func showEach(env *registry.Env, in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = policyDisplay(env, s)
	}
	return out
}

func capTargets(in []string, truncated *bool) []string {
	if len(in) <= dnsListCap {
		return in
	}
	*truncated = true
	return in[:dnsListCap]
}

// appendCapped adds item to dst unless dst holds dnsListCap entries, with as many of its
// targets as the budget has room for.
func appendCapped(env *registry.Env, dst []DNSResolverAttr, item DNSResolverAttr, budget *dnsBudget, truncated *bool) []DNSResolverAttr {
	if len(dst) >= dnsListCap {
		*truncated = true
		return dst
	}
	targets, ok := budget.prefix(item.Targets, shownWhole(env, item.ID))
	if !ok || len(targets) < len(item.Targets) {
		*truncated = true
	}
	if !ok {
		return dst
	}
	item.Targets = targets
	return append(dst, item)
}

func showOther(env *registry.Env, budget *dnsBudget, names []string, truncated *bool) []string {
	if len(names) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		if len(out) >= dnsListCap {
			*truncated = true
			break
		}
		shown := policyDisplay(env, name)
		if !budget.take(shown) {
			*truncated = true
			break
		}
		out = append(out, shown)
	}
	sort.Strings(out)
	return out
}

func resolverNote(next, control []DNSResolverAttr, nodes []DNSNodeAttr) string {
	ids := map[string]bool{}
	for _, a := range next {
		if a.ID != "" {
			ids[a.ID] = true
		}
	}
	several := len(ids) > 1
	hasTargets := false
	for _, list := range [][]DNSResolverAttr{next, control} {
		for _, a := range list {
			if len(a.Targets) > 0 {
				hasTargets = true
			}
		}
	}
	for _, n := range nodes {
		if len(n.Targets) > 0 {
			hasTargets = true
		}
	}
	switch {
	case several && hasTargets:
		return dnsPrecedenceAndSelectors
	case several:
		return dnsPrecedenceUnknown
	case hasTargets && (len(next) > 0 || len(control) > 0 || len(nodes) > 0):
		return dnsTargetsAreSelectors
	default:
		return ""
	}
}
