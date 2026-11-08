package tools

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// security explain is the owner's question about their own intent: for each expectation they
// wrote in an invariants file, was the live policy witnessed to do what it says, which rules are
// candidates for the answer, and what could a compromised source reach. It exists on the
// command line only: SecurityExplainTool is not part of Register, and nothing that builds the
// MCP server adds it. Every verdict is Tailscale's own validation of the live policy with a
// canary (security_explain_witness.go); the rules are text matches (security_explain_rules.go).

// SecurityExplainTool is the security_explain tool. It is registered by RegisterOwnerOnly, for
// the command line, and never by Register, which is what the MCP server and the generated
// documents are built from.
func SecurityExplainTool() registry.Tool {
	m := readMeta("security_explain", "security", "explain",
		"Explain, for the expectations of the intent set, whether the live policy was witnessed to do what each says, the rules that are candidates for it, and what a compromised source could reach; owner command line only.",
		aclScopes...)
	// With no intent set nothing is asked of Tailscale, so the credential is optional: see RunsOfflineIn.
	m.Title, m.OpenWorld, m.Credential = "Explain selected access", true, registry.CredOptional
	m.Operations = []string{"GET /tailnet/{tailnet}/acl", "POST /tailnet/{tailnet}/acl/validate"}
	m.Notes = "Owner command line only: it is not an MCP tool. Reads the live policy once and sends it to Tailscale's validator, which changes nothing, with the expectations as tests and a canary; at most one request for the network tests and one for the SSH tests, each sent once with no retry and each recorded in the audit log before and after it is sent. With no intent set nothing is asked and no credential is needed."
	return registry.Define(m, securityExplain)
}

// RegisterOwnerOnly adds the tools that exist on the owner's command line and nowhere else.
func RegisterOwnerOnly(r *registry.Registry) {
	r.MustAdd(SecurityExplainTool(), SecurityExportTool(), SecurityReplayTool(), SecurityRedactTool(), SecurityVerifyTool())
}

// maxExplainOnly is the most expectation IDs a call may select.
const maxExplainOnly = 1024

var explainIDRE = regexp.MustCompile(`^(network|ssh)-[1-9][0-9]{0,5}$`)

// SecurityExplainInput is what the owner may choose: which expectations, and which file. There
// is no destination, source, device or user: what is judged is what the expectations list.
type SecurityExplainInput struct {
	Only       []string `json:"only,omitempty" tk:"short" jsonschema:"expectation IDs to explain, network-N and ssh-N by their position in the file, repeatable or comma-separated; all of them when not given"`
	Invariants string   `json:"-" cli:"file:invariants" jsonschema:"a file of tests (a HuJSON object with tests and sshTests) taken as the owner's intent, instead of the configured acl.invariantsFile"`
	Operator   bool     `json:"-" cli:"operator"`
}

// RunsOfflineIn says that the command asks nothing of Tailscale, so that the command line does not
// start the credential's wrapper for it: no file was named with --invariants and the
// configuration names none. With no intent set there is nothing to explain, and the command says
// so. A configured file, or one named on the command line, may be empty, and is then also asked
// about nothing; it is not known before it is read, and the command line may need the credential
// for it.
func (SecurityExplainInput) RunsOfflineIn(env *registry.Env, g registry.Given) bool {
	return !g["invariants"] && (env.Config == nil || env.Config.Config.ACL.InvariantsFile == "")
}

// onlyIDs reads the IDs the owner selected. An empty one, one that is no ID, a repeat and more
// than maxExplainOnly are refused without repeating a word of what was typed.
func (in SecurityExplainInput) onlyIDs() ([]string, error) {
	var ids []string
	for _, arg := range in.Only {
		for _, part := range strings.Split(arg, ",") {
			id := strings.TrimSpace(part)
			if !explainIDRE.MatchString(id) {
				return nil, validationf("--only takes expectation IDs, network-N or ssh-N, separated by commas")
			}
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
			if len(ids) > maxExplainOnly {
				return nil, validationf(fmt.Sprintf("--only names more than %d expectations", maxExplainOnly))
			}
		}
	}
	return ids, nil
}

// Check refuses a selection that is not IDs, before the configuration is read.
func (in SecurityExplainInput) Check() error {
	_, err := in.onlyIDs()
	return err
}

// SecurityExplainOutput is the explanation. It holds the owner's own words (a source, a
// destination, a user, a selector of the policy) only in fields the framework masks and
// sanitizes as untrusted; every other word is the tool's.
type SecurityExplainOutput struct {
	Status        string                 `json:"status" jsonschema:"complete: every selected expectation is met, with a canary and the live policy shown unchanged; incomplete otherwise, an unmet expectation included (exit 8)"`
	Intent        SecurityExplainIntent  `json:"intent" tk:"details" jsonschema:"the intent set, by digest; none of its text is in a result"`
	PolicyVersion string                 `json:"policyVersion,omitempty" jsonschema:"the live policy version the witnesses are about: a keyed digest of its ETag, or the ETag with personalData show; absent otherwise"`
	EvaluatedAt   string                 `json:"evaluatedAt,omitempty" jsonschema:"when the live policy was asked: RFC 3339, in UTC"`
	Counts        SecurityExplainCounts  `json:"counts" tk:"details" jsonschema:"the selected expectations by status, all of them"`
	PairsJudged   int                    `json:"pairsJudged" jsonschema:"pairs counted against the limit of 64 a run: the pairs put to Tailscale, and pairs not put to it because another selected expectation with the same source has other terms"`
	PairsPastCap  int                    `json:"pairsPastCap" jsonschema:"pairs the expectations list that were left out past the limit; they are not evaluated"`
	Expectations  []SecurityExplainRow   `json:"expectations" tk:"rows" jsonschema:"at most 100, unmet first"`
	Omitted       int                    `json:"omitted,omitempty" jsonschema:"expectations not listed past the 100; the counts include them"`
	Blast         []SecurityExplainBlast `json:"blast,omitempty" jsonschema:"what a compromised source could reach by the witnessed pairs: an assumption, not a finding"`
	Notes         []string               `json:"notes,omitempty" jsonschema:"fixed sentences the explanation states once"`
}

// SecurityExplainIntent names the intent set an explanation used.
type SecurityExplainIntent struct {
	Source       string `json:"source" jsonschema:"none, configured or cli"`
	Digest       string `json:"digest,omitempty" jsonschema:"keyed digest of the intent file (sha256: with personalData show); none while masked with no privacy key"`
	Revision     string `json:"revision,omitempty" jsonschema:"the first twelve digits of the digest; none without it"`
	Expectations int    `json:"expectations,omitempty" jsonschema:"expectations the file holds"`
	Selected     int    `json:"selected,omitempty" jsonschema:"expectations explained: all of them, or the ones --only named"`
}

// SecurityExplainCounts counts the selected expectations by status.
type SecurityExplainCounts struct {
	Total         int `json:"total"`
	Met           int `json:"met"`
	MetWithLimits int `json:"metWithLimits"`
	Unmet         int `json:"unmet"`
	Unknown       int `json:"unknown"`
	NotEvaluated  int `json:"notEvaluated"`
}

// SecurityExplainRow is one expectation.
type SecurityExplainRow struct {
	ID                string                `json:"id" jsonschema:"network-N or ssh-N, by position in the file"`
	Kind              string                `json:"kind" jsonschema:"network or ssh"`
	Source            string                `json:"source" tk:"untrusted,emails" jsonschema:"the expectation's source, as the file wrote it"`
	Status            string                `json:"status" jsonschema:"met, unmet, unknown, met_with_limits or not_evaluated"`
	Cells             []SecurityExplainCell `json:"cells,omitempty" jsonschema:"the pairs judged, one witness each"`
	PastCap           int                   `json:"pastCap,omitempty" jsonschema:"pairs of this expectation left out past the limit"`
	Candidates        []SecurityExplainRule `json:"candidates,omitempty" jsonschema:"candidate rules: text matches of the live policy, never the cause of a verdict"`
	CandidatesOmitted int                   `json:"candidatesOmitted,omitempty"`
	Limits            []string              `json:"limits,omitempty" jsonschema:"cases the test language cannot express: posture, app, via or source"`
}

// SecurityExplainCell is one pair and the witness for it.
type SecurityExplainCell struct {
	Expect        string `json:"expect" jsonschema:"accept, deny or check"`
	Destination   string `json:"destination" tk:"untrusted,emails"`
	User          string `json:"user,omitempty" tk:"untrusted,emails" jsonschema:"the ssh user, for an ssh pair"`
	Verdict       string `json:"verdict" jsonschema:"met, unmet, unknown or not_evaluated"`
	Observed      string `json:"observed" jsonschema:"what the live policy was witnessed to do: allowed, denied, unknown or not_asked"`
	Reason        string `json:"reason,omitempty" jsonschema:"why a pair is unknown or not evaluated: a word of a closed set, docs/security/access-explanations.md lists them"`
	Canary        bool   `json:"canary" jsonschema:"the canary came back once, in the grammar"`
	LiveUnchanged bool   `json:"liveUnchanged" jsonschema:"the live policy was shown unchanged after the request"`
}

// SecurityExplainRule is a candidate rule: where it is in the live policy, and the selectors
// that matched.
type SecurityExplainRule struct {
	Section     string `json:"section" jsonschema:"acls, grants or ssh"`
	Index       int    `json:"index" jsonschema:"1-based position in its section"`
	Line        int    `json:"line,omitempty"`
	Column      int    `json:"column,omitempty"`
	Source      string `json:"source" tk:"untrusted,emails" jsonschema:"the rule's source selector that matched"`
	Destination string `json:"destination" tk:"untrusted,emails" jsonschema:"the rule's destination selector that matched"`
	Ports       string `json:"ports,omitempty" tk:"untrusted,plain" jsonschema:"the rule's ports, when they limit the pair"`
	Broad       bool   `json:"broad,omitempty" jsonschema:"the destination selector is *"`
	Qualified   bool   `json:"qualified,omitempty" jsonschema:"the rule is gated on srcPosture or the policy's defaultSrcPosture, carries app capabilities or routes through via"`
	AllTraffic  bool   `json:"allTraffic,omitempty" jsonschema:"the rule allows every port and every protocol (acls ports * and no proto, a grant with ip *)"`
	Traffic     string `json:"traffic,omitempty" tk:"untrusted,plain" jsonschema:"what a rule that does not allow all of it writes about its ports and protocols: the proto and ports of an acls rule, the ip entries of a grant"`
}

// SecurityExplainBlast is the blast radius of one source.
type SecurityExplainBlast struct {
	Source      string                 `json:"source" tk:"untrusted,emails"`
	Heading     string                 `json:"heading" tk:"untrusted,emails" jsonschema:"the assumption, in fixed words"`
	Reaches     []SecurityExplainReach `json:"reaches,omitempty"`
	Broad       []SecurityExplainRule  `json:"broad,omitempty" jsonschema:"candidate rules whose destination is *"`
	Tags        []string               `json:"tags,omitempty" tk:"untrusted,emails" jsonschema:"tags the source can apply (tagOwners): their rules would then apply"`
	TagsOmitted int                    `json:"tagsOmitted,omitempty"`
}

// SecurityExplainReach is a destination a witnessed pair shows a source could reach.
type SecurityExplainReach struct {
	Kind        string `json:"kind" jsonschema:"network or ssh"`
	Destination string `json:"destination" tk:"untrusted,emails"`
	User        string `json:"user,omitempty" tk:"untrusted,emails"`
	Expectation string `json:"expectation"`
}

// ExitCode follows the counts and the status and nothing else: 8 when any expectation is unmet,
// else 1 when the explanation is not complete, else 0. 8 outranks 1.
func (o SecurityExplainOutput) ExitCode() int {
	switch {
	case o.Counts.Unmet > 0:
		return 8
	case o.Status != string(security.AccessComplete):
		return 1
	}
	return 0
}

// ExitNote is what the command line says to explain exit 8.
func (SecurityExplainOutput) ExitNote() string {
	return "an expectation of the intent set is unmet: the live policy was witnessed to do the other thing"
}

// AuditFields are the fields the read line of the audit log carries for this tool: where the
// intent came from, the start of its digest by the rule of the digests, and how many
// expectations were explained and ended each way. Counts and closed words only: no text of the
// intent, no text of the policy and no path.
func (o SecurityExplainOutput) AuditFields() map[string]any {
	f := map[string]any{
		"intent": o.Intent.Source, "expectations": o.Counts.Total,
		"met": o.Counts.Met, "unmet": o.Counts.Unmet, "unknown": o.Counts.Unknown,
		"limited": o.Counts.MetWithLimits, "not_evaluated": o.Counts.NotEvaluated,
	}
	if o.Intent.Revision != "" {
		f["digest"] = o.Intent.Revision
	}
	return f
}

// explainFacts is the live policy as the explanation reads it: parsed, and its rules and names.
// doc is nil when this version cannot read the policy.
type explainFacts struct {
	doc    *acl.Doc
	access *acl.Access
}

// explainRun is one explanation in progress: the client, the live policy it reads once, and what
// that holds.
type explainRun struct {
	env   *registry.Env
	c     *api.Client
	live  api.PolicyDetails
	facts *explainFacts
}

// readFacts parses the live policy and reads its rules. A policy this version cannot read is
// not an error: it leaves doc nil, and the explanation says so. A call that was cancelled is.
func readFacts(ctx context.Context, text []byte) (*explainFacts, error) {
	doc, err := acl.Parse(ctx, text)
	if err != nil {
		return unreadableFacts(err)
	}
	access, err := acl.ReadAccess(ctx, doc)
	if err != nil {
		return unreadableFacts(err)
	}
	return &explainFacts{doc: doc, access: access}, nil
}

func unreadableFacts(err error) (*explainFacts, error) {
	var e *acl.Error
	if errors.As(err, &e) {
		return &explainFacts{}, nil
	}
	return nil, tkerr.Wrap(tkerr.APIError, err, "request cancelled", "")
}

// judgedIDs are the expectations of a plan that have a pair this run judges.
func judgedIDs(plan []security.PlannedExpectation) map[string]bool {
	out := map[string]bool{}
	for _, pe := range plan {
		out[pe.ID] = len(pe.Cells) > 0
	}
	return out
}

// selectIntent keeps the expectations the owner named, in the order of the file. An ID the set
// does not hold is a usage error that names the IDs it does hold and repeats nothing.
func selectIntent(set security.IntentSet, only []string) (security.IntentSet, error) {
	if len(only) == 0 {
		return set, nil
	}
	held := map[string]bool{}
	out := set
	out.Network, out.SSH = nil, nil
	for _, e := range set.Network {
		held[e.ID] = true
		if slices.Contains(only, e.ID) {
			out.Network = append(out.Network, e)
		}
	}
	for _, e := range set.SSH {
		held[e.ID] = true
		if slices.Contains(only, e.ID) {
			out.SSH = append(out.SSH, e)
		}
	}
	for _, id := range only {
		if !held[id] {
			return security.IntentSet{}, validationf(fmt.Sprintf("--only names an expectation the intent set does not hold; it holds %s", heldIDs(set)))
		}
	}
	return out, nil
}

// heldIDs says which IDs a set holds, as ranges.
func heldIDs(set security.IntentSet) string {
	var parts []string
	if n := len(set.Network); n > 0 {
		parts = append(parts, fmt.Sprintf("network-1 to network-%d", n))
	}
	if n := len(set.SSH); n > 0 {
		parts = append(parts, fmt.Sprintf("ssh-1 to ssh-%d", n))
	}
	if len(parts) == 0 {
		return "no expectation"
	}
	return strings.Join(parts, " and ")
}

func securityExplain(ctx context.Context, env *registry.Env, in SecurityExplainInput) (SecurityExplainOutput, error) {
	only, err := in.onlyIDs()
	if err != nil {
		return SecurityExplainOutput{}, err
	}
	if in.Invariants != "" && !in.Operator {
		// Only the command line sets the file, and it marks the call as the operator's own.
		return SecurityExplainOutput{}, tkerr.New(tkerr.ValidationFailed, "the intent file is chosen by the operator at the command line, not by a caller of the tool", "")
	}
	// The intent is read before anything is asked: a file that cannot be used stops the command
	// with no request made, and is never taken for no intent.
	loaded, origin, err := loadIntentFile(ctx, env, false, in.Invariants)
	if err != nil {
		return SecurityExplainOutput{}, err
	}
	if loaded == nil {
		if len(only) > 0 {
			return SecurityExplainOutput{}, validationf("--only names expectations, and there is no intent set")
		}
		return explainNothing(security.AccessInput{NoIntent: true}, SecurityExplainIntent{Source: string(intentNone)})
	}
	selected, err := selectIntent(loaded.Set, only)
	if err != nil {
		return SecurityExplainOutput{}, err
	}
	intent := SecurityExplainIntent{Source: string(origin), Digest: loaded.Set.Digest, Revision: loaded.Set.Revision,
		Expectations: len(loaded.Set.Network) + len(loaded.Set.SSH), Selected: len(selected.Network) + len(selected.SSH)}
	if intent.Selected == 0 {
		return explainNothing(security.AccessInput{Intent: selected}, intent)
	}
	report, err := explainSelected(ctx, env, selected)
	if err != nil {
		return SecurityExplainOutput{}, err
	}
	return shapeExplain(report, intent), nil
}

// explainNothing is the explanation of an intent set that has nothing to explain: no request is
// made, and the report says why in one fixed sentence.
func explainNothing(in security.AccessInput, intent SecurityExplainIntent) (SecurityExplainOutput, error) {
	report, err := security.ExplainAccess(in)
	if err != nil {
		return SecurityExplainOutput{}, tkerr.Wrap(tkerr.Internal, err, "the explanation failed", "this is a tailkeeper bug; report it")
	}
	return shapeExplain(report, intent), nil
}

// explainSelected reads the live policy once, asks Tailscale about the pairs the selected
// expectations list, and makes the report.
func explainSelected(ctx context.Context, env *registry.Env, selected security.IntentSet) (security.AccessReport, error) {
	in, _, err := collectAccessInput(ctx, env, selected)
	if err != nil {
		return security.AccessReport{}, err
	}
	report, err := security.ExplainAccess(in)
	if err != nil {
		return security.AccessReport{}, tkerr.Wrap(tkerr.Internal, err, "the explanation failed", "this is a tailkeeper bug; report it")
	}
	return report, nil
}

// collectAccessInput reads the policy and witnesses once, recording the start before the first request.
func collectAccessInput(ctx context.Context, env *registry.Env, selected security.IntentSet) (security.AccessInput, time.Time, error) {
	c, err := env.RequireAPI()
	if err != nil {
		return security.AccessInput{}, time.Time{}, err
	}
	startedAt := env.Clock().UTC().Round(0)
	live, err := c.GetPolicyDetails(ctx)
	if err != nil {
		return security.AccessInput{}, time.Time{}, err
	}
	facts, err := readFacts(ctx, live.Text)
	if err != nil {
		return security.AccessInput{}, time.Time{}, err
	}
	run := &explainRun{env: env, c: c, live: live, facts: facts}
	plan := security.PlanAccess(selected, 0)
	witnesses, err := run.witness(ctx, planAsks(plan, selected, hostAliases(facts)))
	if err != nil {
		return security.AccessInput{}, time.Time{}, err
	}
	cands, limits, owners, partial, err := explainRules(ctx, facts, selected, judgedIDs(plan))
	if err != nil {
		return security.AccessInput{}, time.Time{}, tkerr.Wrap(tkerr.APIError, err, "request cancelled", "")
	}
	return security.AccessInput{
		Intent: selected, Witnesses: witnesses, Candidates: cands, Limits: limits, Owners: owners, RulesPartial: partial,
		PolicyVersion: policyVersion(env, live.ETag), EvaluatedAt: env.Clock().UTC().Round(0),
	}, startedAt, nil
}
