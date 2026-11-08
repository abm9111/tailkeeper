package tools

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// scanFindingLimit is the most findings a scan lists. The report keeps every finding it made
// (up to the matcher's own limit) and counts all of them; the listing is cut here and says
// so. There is no cursor: paging waits for immutable stored reports, which a stateless scan
// does not have.
const scanFindingLimit = 100

const (
	scanFleet = "fleet"
	scanLocal = "local"
)

// scanThresholds are the severities a threshold may be, in the order of the help text.
var scanThresholds = []string{"low", "medium", "high", "critical"}

// defaultScanThreshold is the threshold when the caller gives none: every affected finding
// counts, because a gate that starts lenient is a gate that is not noticed to be.
const defaultScanThreshold = "low"

// scanCatalog is where the scan gets the catalog it judges by: the one built into the binary.
// It is a variable for a test; nothing a caller supplies reaches it.
var scanCatalog = advisory.Shipped

func securityTools() []registry.Tool {
	return []registry.Tool{SecurityScanTool(func() (security.Catalog, error) { return scanCatalog() })}
}

// SecurityScanTool is the security_scan tool judging by the catalog that catalog returns. The
// registered tool is built with the catalog shipped in the binary; this constructor exists so
// that a test of the command line can run the scan against rules of its own. Nothing a caller
// of the tool supplies reaches it.
func SecurityScanTool(catalog func() (security.Catalog, error)) registry.Tool {
	m := readMeta("security_scan", "security", "scan",
		"Scan this tailnet's devices (fleet) or this node (local) against the advisories shipped with tailkeeper; reports each device as affected, potentially affected, unknown or not affected, and what the scan could not cover.",
		"devices:core:read")
	m.Credential = registry.CredOptional
	m.Notes = "Reads only: the device list (fields=all, fleet scope) and this node's status, version and preferences, judged by the few reviewed rules built into this binary (counted in catalog.rules). Complete and exit 0 hold only relative to those rules: they say nothing of other advisories and are not a statement that the fleet is safe. Pending rules, a failed source or a stale review keep a scan partial. The configured acl.invariantsFile, if any, is the intent: named by digest, not judged yet (the scan is partial), never repeated. Every source read is recorded in the audit log, so audit.reads must not be none. Sends nothing to Tailscale."
	return registry.Define(withOps(m, "GET /tailnet/{tailnet}/devices"), func(ctx context.Context, env *registry.Env, in SecurityScanInput) (SecurityScanOutput, error) {
		return securityScan(ctx, env, in, catalog)
	})
}

// SecurityScanInput is all a caller may choose. There is no catalog, path, URL, destination
// or expectation: what is judged, and by what, is the tool's. Over MCP the intent is the
// configured invariants file and nothing a caller says; the command line alone can name another
// file or switch the intent off, and those fields are not in the MCP schema (json:"-").
type SecurityScanInput struct {
	Scope     string `json:"scope" tk:"short" jsonschema:"fleet: the devices the API lists plus this node's own facts; local: this node only, with no API request. One of fleet, local"`
	Threshold string `json:"threshold,omitempty" tk:"short" jsonschema:"lowest rule severity that counts toward exit 8 and atThreshold: low (default), medium, high or critical; a rule with no severity counts at every threshold"`

	Invariants   string `json:"-" cli:"file:invariants" jsonschema:"a file of tests (a HuJSON object with tests and sshTests) taken as the owner's intent for this scan, instead of the configured acl.invariantsFile"`
	NoInvariants bool   `json:"-" cli:"bool:no-invariants" jsonschema:"scan with no intent, even if acl.invariantsFile is configured"`
	Operator     bool   `json:"-" cli:"operator"`
}

// Check refuses a scope or a threshold outside the closed sets, from the input alone.
func (in SecurityScanInput) Check() error {
	if in.Scope != scanFleet && in.Scope != scanLocal {
		return validationf("scope must be fleet or local")
	}
	if in.Threshold != "" && !containsString(scanThresholds, in.Threshold) {
		return validationf("threshold must be low, medium, high or critical")
	}
	return nil
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// RunsOffline: a local scan makes no API request, so it needs no credential.
func (in SecurityScanInput) RunsOffline(registry.Given) bool { return in.Scope == scanLocal }

func (in SecurityScanInput) threshold() string {
	if in.Threshold == "" {
		return defaultScanThreshold
	}
	return in.Threshold
}

// SecurityScanOutput is the scan: its status, what it found, what it could not cover, and at
// most 100 findings. It holds no safe or unsafe verdict of its own; status says whether the
// scan covered what it set out to.
type SecurityScanOutput struct {
	Status        string                 `json:"status" jsonschema:"complete or partial. complete: every requested coverage is complete, relative to the shipped catalog (the rules built into this binary, counted in catalog.rules), which is not a statement that the fleet is safe. Pending rules, a failed source or a stale review keep it partial: read coverage"`
	Scope         string                 `json:"scope" jsonschema:"fleet or local"`
	Threshold     string                 `json:"threshold" jsonschema:"the severity threshold that applied"`
	ObservedAt    string                 `json:"observedAt" jsonschema:"when the sources were read: RFC 3339, in UTC"`
	GeneratedAt   string                 `json:"generatedAt" jsonschema:"when the findings were made: RFC 3339, in UTC"`
	TotalFindings int                    `json:"totalFindings" jsonschema:"every finding the scan made, one for each device and rule; findings lists at most 100"`
	Truncated     bool                   `json:"truncated" jsonschema:"findings lists fewer than totalFindings; affected come first, so the cut is the last; no way to page to the rest"`
	Counts        SecurityScanCounts     `json:"counts" tk:"details" jsonschema:"findings by applicability, over all of them"`
	AtThreshold   SecurityScanThreshold  `json:"atThreshold" tk:"details" jsonschema:"affected and potentially affected findings at or above the threshold, over all findings, not the listed: any gives exit 8"`
	Catalog       SecurityScanCatalog    `json:"catalog" tk:"details" jsonschema:"the advisory catalog the scan judged by"`
	Intent        SecurityScanIntent     `json:"intent" tk:"details" jsonschema:"the intent set, by digest; none of its text is in a result"`
	Coverage      []SecurityScanCoverage `json:"coverage" tk:"details" jsonschema:"what each requested dimension covered, and what it did not"`
	Findings      []SecurityScanFinding  `json:"findings" tk:"rows" jsonschema:"at most 100, affected first"`
}

// SecurityScanCounts counts findings by applicability.
type SecurityScanCounts struct {
	Affected            int `json:"affected"`
	PotentiallyAffected int `json:"potentiallyAffected"`
	Unknown             int `json:"unknown"`
	NotAffected         int `json:"notAffected"`
}

// SecurityScanThreshold counts the findings at or above the threshold.
type SecurityScanThreshold struct {
	Affected            int `json:"affected"`
	PotentiallyAffected int `json:"potentiallyAffected"`
}

// SecurityScanCatalog describes the catalog: the merge of the files shipped in the binary.
type SecurityScanCatalog struct {
	Revision  uint64 `json:"revision" jsonschema:"the highest revision of any file"`
	IssuedAt  string `json:"issuedAt" jsonschema:"the latest issue time of any file"`
	ExpiresAt string `json:"expiresAt" jsonschema:"the earliest expiry of any file: the catalog is stale from then"`
	Digest    string `json:"digest" jsonschema:"SHA-256 over the files' name:digest lines; changes with any byte of any file"`
	Rules     int    `json:"rules" jsonschema:"rules built into this binary: complete and exit 0 are relative to these, and say nothing of advisories the catalog does not hold"`
	Approved  int    `json:"approved" jsonschema:"rules the owner approved"`
	Pending   int    `json:"pending" jsonschema:"rules not yet approved: they give unknown findings only"`
	Withdrawn int    `json:"withdrawn" jsonschema:"rules withdrawn: they give no finding"`
}

// SecurityScanIntent names the intent set a scan was given. It holds the set's digest and
// revision and how many expectations it has, and none of its text.
type SecurityScanIntent struct {
	Source       string `json:"source" jsonschema:"none, configured or cli"`
	Digest       string `json:"digest,omitempty" jsonschema:"keyed digest of the intent file (sha256: with personalData show); none while masked with no privacy key"`
	Revision     string `json:"revision,omitempty" jsonschema:"the first twelve digits of the digest; none without it"`
	Expectations int    `json:"expectations,omitempty" jsonschema:"tests the file holds; none is judged yet"`
}

// SecurityScanCoverage is one row of coverage.
type SecurityScanCoverage struct {
	Dimension   string                `json:"dimension" jsonschema:"versions, features, catalog or intent"`
	Source      string                `json:"source" jsonschema:"what produced the row"`
	Status      string                `json:"status" jsonschema:"complete or partial; not_requested for a dimension not asked for (intent, with no intent set configured), which blocks nothing"`
	Explanation string                `json:"explanation,omitempty" jsonschema:"why a row is partial or not requested: fixed words, error codes and counts"`
	Counts      *SecurityScanRowCount `json:"counts,omitempty" jsonschema:"what a row evaluated; the catalog row has them"`
}

// SecurityScanRowCount is what a coverage row evaluated.
type SecurityScanRowCount struct {
	Rules               int `json:"rules"`
	Withdrawn           int `json:"withdrawn"`
	Devices             int `json:"devices"`
	Findings            int `json:"findings"`
	Unknown             int `json:"unknown"`
	PotentiallyAffected int `json:"potentiallyAffected"`
}

// SecurityScanFinding is one rule judged for one device. The device is shown by the start of
// its node ID (maskDeviceID) and, with a privacy key, a pseudonym; the finding's
// identity hash, the context and the whole node ID are not in the result.
type SecurityScanFinding struct {
	Rule          string                 `json:"rule" tk:"col" jsonschema:"the advisory rule, for example CVE-2022-41925"`
	RuleRevision  string                 `json:"ruleRevision"`
	Device        string                 `json:"device" tk:"untrusted,col" jsonschema:"the node ID cut to four characters at most, then an ellipsis"`
	DeviceRef     string                 `json:"deviceRef,omitempty" jsonschema:"a pseudonym of the node ID, the same in every call; needs a privacy key"`
	Applicability string                 `json:"applicability" tk:"col" jsonschema:"affected, potentially_affected, unknown or not_affected"`
	Severity      string                 `json:"severity" tk:"col" jsonschema:"the rule's own severity: unknown, low, medium, high or critical"`
	Reason        string                 `json:"reason,omitempty" tk:"col" jsonschema:"why a finding is unknown or only potentially affected, from a fixed set"`
	EvidenceState string                 `json:"evidenceState" jsonschema:"observed, unknown, stale or absent"`
	Confidence    string                 `json:"confidence" jsonschema:"unknown or reported"`
	Explanation   string                 `json:"explanation" jsonschema:"fixed words that say what the finding rests on"`
	Verification  []string               `json:"verification,omitempty" jsonschema:"what the vendor advises, for an affected or potentially affected finding"`
	Evidence      []SecurityScanEvidence `json:"evidence,omitempty" jsonschema:"the observations the finding cites"`
}

// SecurityScanEvidence is one observation a finding cites, without its context or device.
type SecurityScanEvidence struct {
	Origin     string `json:"origin" jsonschema:"api or local"`
	AcquiredAt string `json:"acquiredAt" jsonschema:"when tailkeeper read it"`
	ObservedAt string `json:"observedAt,omitempty" jsonschema:"when its source says it was true"`
	Freshness  string `json:"freshness" jsonschema:"fresh, stale or unknown"`
	Error      string `json:"error,omitempty" jsonschema:"why the observation is not usable"`
}

// ExitCode comes from the findings and the status alone, never from text: 8 when an affected
// or potentially affected finding is at or above the threshold, even if the scan is partial
// (most real scans are partial, so letting 1 outrank 8 would hide findings: this command, not
// the policy commands, puts 8 first); 1 when the scan is not complete and found nothing at
// the threshold (it is not a pass either); 0 only for a complete scan with nothing at the
// threshold. An output with no status is not complete.
func (o SecurityScanOutput) ExitCode() int {
	switch {
	case o.AtThreshold.Affected+o.AtThreshold.PotentiallyAffected > 0:
		return 8
	case o.Status != string(security.ReportComplete):
		return 1
	}
	return 0
}

// layout is the scan laid out for people: its verdict line, and a fact for each thing it
// states about itself: the threshold, the catalog, the intent set if there is one, each
// coverage row, the cut, and how a device is named. The findings are the table below them.
// Every word is the tool's own or a field of the result, which the framework has already
// escaped; a layout escapes again for its own syntax.
func (o SecurityScanOutput) layout() (verdict string, facts []registry.Fact) {
	c := o.Counts
	verdict = fmt.Sprintf("%s scan: %s; %d affected, %d potentially affected, %d unknown, %d not affected (%d findings, %d listed)",
		o.Scope, o.Status, c.Affected, c.PotentiallyAffected, c.Unknown, c.NotAffected, o.TotalFindings, len(o.Findings))
	facts = []registry.Fact{
		{Label: "threshold " + o.Threshold, Text: fmt.Sprintf("%d affected and %d potentially affected at or above it", o.AtThreshold.Affected, o.AtThreshold.PotentiallyAffected)},
		{Label: "catalog", Text: fmt.Sprintf("revision %d, issued %s, expires %s: %d rules built into this binary (%d approved, %d pending, %d withdrawn); complete and exit 0 are relative to these rules and do not mean the fleet is safe",
			o.Catalog.Revision, o.Catalog.IssuedAt, o.Catalog.ExpiresAt, o.Catalog.Rules, o.Catalog.Approved, o.Catalog.Pending, o.Catalog.Withdrawn)},
	}
	if o.Intent.Source != string(intentNone) && o.Intent.Source != "" {
		named := "revision " + o.Intent.Revision
		if o.Intent.Revision == "" {
			named = "no digest (personal data is masked and no privacy key is loaded)"
		}
		facts = append(facts, registry.Fact{Label: "intent", Text: fmt.Sprintf("%s file, %s, %s; none is judged in this version, so the scan is partial",
			o.Intent.Source, named, plural(o.Intent.Expectations, "expectation"))})
	}
	for _, row := range o.Coverage {
		text := row.Status
		if row.Explanation != "" {
			text += " - " + row.Explanation
		}
		facts = append(facts, registry.Fact{Label: "coverage " + row.Dimension, Text: text})
	}
	if o.Truncated {
		facts = append(facts, registry.Fact{Label: "output truncated", Text: fmt.Sprintf("showing %d of %d findings, affected first; there is no way to page to the rest yet", len(o.Findings), o.TotalFindings)})
	}
	if len(o.Findings) > 0 {
		facts = append(facts, registry.Fact{Label: "devices", Text: "a device is shown by the start of its node ID, at most four characters, and part of it is always withheld; a privacy key adds a pseudonym (deviceRef in JSON)"})
	}
	return verdict, facts
}

// Details is the layout as plain lines: the verdict, then each fact as label: text.
func (o SecurityScanOutput) Details() []string {
	verdict, facts := o.layout()
	lines := []string{verdict}
	for _, f := range facts {
		lines = append(lines, f.Label+": "+f.Text)
	}
	return lines
}

// Report is the human layout every --format renders: the verdict, the facts, and a line for
// each listed finding. The level follows the exit code (0 ok, 1 warn, 8 fail).
func (o SecurityScanOutput) Report() registry.Report {
	verdict, facts := o.layout()
	rep := registry.Report{Verdict: verdict, Level: o.level(), Facts: facts}
	for _, f := range o.Findings {
		rep.Findings = append(rep.Findings, registry.Finding{Severity: findingSeverity(f.Applicability), Message: findingLine(f)})
	}
	return rep
}

func (o SecurityScanOutput) level() registry.Level {
	switch o.ExitCode() {
	case 0:
		return registry.LevelOK
	case 1:
		return registry.LevelWarn
	}
	return registry.LevelFail
}

// findingSeverity is the severity a layout gives a finding: an affected device is an error, a
// potentially affected one a warning, and what is unknown or cleared a notice.
func findingSeverity(applicability string) string {
	switch applicability {
	case string(security.ApplicabilityAffected):
		return "error"
	case string(security.ApplicabilityPotential):
		return "warning"
	}
	return "notice"
}

// findingLine is one finding as a layout lists it: the rule, the device, what the scan found,
// the rule's severity, why when it is only potential or unknown, the words that say what the
// finding rests on and what the vendor advises. The parts are joined by a middle dot, which
// the text of a field does not make a structure of.
func findingLine(f SecurityScanFinding) string {
	device := f.Device
	if f.DeviceRef != "" {
		device += " " + f.DeviceRef
	}
	parts := []string{f.Rule, device, f.Applicability, "severity " + f.Severity}
	if f.Reason != "" {
		parts = append(parts, "reason "+f.Reason)
	}
	parts = append(parts, f.Explanation)
	if len(f.Verification) > 0 {
		parts = append(parts, "verify: "+strings.Join(f.Verification, "; "))
	}
	return strings.Join(parts, " · ")
}

// securityScan collects the sources of the scope, judges them by the shipped catalog, and
// shapes the report for output.
func securityScan(ctx context.Context, env *registry.Env, in SecurityScanInput, source func() (security.Catalog, error)) (SecurityScanOutput, error) {
	run, err := runScanInputs(ctx, env, in, source)
	if err != nil {
		return SecurityScanOutput{}, err
	}
	catalog, intent, origin, report := run.Input.Catalog, run.Input.Intent, run.Origin, run.Report
	threshold := in.threshold()
	hits, err := security.CountAtThreshold(report.Findings, security.Severity(threshold))
	if err != nil {
		return SecurityScanOutput{}, tkerr.Wrap(tkerr.Internal, err, "the scan counted its findings against a threshold it does not know", "this is a tailkeeper bug; report it")
	}
	counts := countFindings(report.Findings)
	listed, err := security.Truncate(report, scanFindingLimit)
	if err != nil {
		return SecurityScanOutput{}, tkerr.Wrap(tkerr.Internal, err, "the scan could not cut its report to the findings it lists", "this is a tailkeeper bug; report it")
	}
	out := shapeScan(env, in, catalog, listed, counts, hits)
	out.Intent = scanIntentOf(origin, intent, listed)
	return out, nil
}

// scanInputs retains the exact evaluator input and result from one collection.
type scanInputs struct {
	Input  security.Input
	Report security.Report
	Origin intentOrigin
}

// runScanInputs runs the same collection and evaluation used by securityScan.
func runScanInputs(ctx context.Context, env *registry.Env, in SecurityScanInput, source func() (security.Catalog, error)) (scanInputs, error) {
	if in.Invariants != "" && in.NoInvariants {
		return scanInputs{}, tkerr.New(tkerr.ValidationFailed, "give --invariants FILE or --no-invariants, not both: the first replaces the configured invariants and the second removes them", "")
	}
	if (in.Invariants != "" || in.NoInvariants) && !in.Operator {
		// Only the command line sets these, and it marks the call as the operator's own; a call
		// that carries one without the mark did not come from a person at the command line.
		return scanInputs{}, tkerr.New(tkerr.ValidationFailed, "the intent file is chosen by the operator at the command line, not by a caller of the tool", "")
	}
	catalog, err := source()
	if err != nil {
		return scanInputs{}, tkerr.Wrap(tkerr.Internal, err, "the advisory catalog built into this binary does not load", "this is a tailkeeper bug; report it with `tailkeeper version` output")
	}
	// The intent is read before any source is asked: a file that cannot be used stops the scan
	// with nothing read and nothing recorded, and is never taken for no intent.
	intent, origin, err := loadScanIntent(ctx, env, in)
	if err != nil {
		return scanInputs{}, err
	}
	collection, err := collectSecurity(ctx, env, security.Scope(in.Scope), security.RequiredFeatures(catalog))
	if err != nil {
		return scanInputs{}, scanError(err, "the scan was cancelled while it read its sources")
	}
	now := env.Clock().UTC().Round(0)
	if now.Before(collection.Snapshot.ObservedAt) {
		now = collection.Snapshot.ObservedAt
	}
	input := security.Input{Catalog: catalog, Snapshot: collection.Snapshot, Intent: intent, Collected: collection.Coverage, Now: now}
	report, err := security.Evaluate(ctx, input)
	if err != nil {
		return scanInputs{}, scanError(err, "the scan was cancelled while it judged what it read")
	}
	return scanInputs{Input: input, Report: report, Origin: origin}, nil
}

// scanError is the error of a scan that stopped: the caller's cancellation is told as such,
// a program's own error is kept, and anything else is an internal error without its cause.
func scanError(err error, cancelled string) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return tkerr.Wrap(tkerr.APIError, err, cancelled, "")
	}
	if _, ok := tkerr.As(err); ok {
		return err
	}
	return tkerr.Wrap(tkerr.Internal, err, "the scan failed", "this is a tailkeeper bug; report it with `tailkeeper version` output")
}

func countFindings(fs []security.Finding) SecurityScanCounts {
	var c SecurityScanCounts
	for _, f := range fs {
		switch f.Applicability {
		case security.ApplicabilityAffected:
			c.Affected++
		case security.ApplicabilityPotential:
			c.PotentiallyAffected++
		case security.ApplicabilityUnknown:
			c.Unknown++
		case security.ApplicabilityNotAffected:
			c.NotAffected++
		}
	}
	return c
}

// shapeScan builds the output from the report: no context, no finding identity hash, no
// whole node ID and no raw fact of the snapshot is in it.
func shapeScan(env *registry.Env, in SecurityScanInput, catalog security.Catalog, r security.Report, counts SecurityScanCounts, hits security.ThresholdCounts) SecurityScanOutput {
	out := SecurityScanOutput{
		Status: string(r.Status), Scope: in.Scope, Threshold: in.threshold(),
		ObservedAt: timeText(r.Snapshot.ObservedAt), GeneratedAt: timeText(r.GeneratedAt),
		TotalFindings: r.TotalFindings, Truncated: r.Truncated, Counts: counts,
		AtThreshold: SecurityScanThreshold{Affected: hits.Affected, PotentiallyAffected: hits.Potential},
		Catalog:     catalogInfo(catalog),
		Coverage:    make([]SecurityScanCoverage, 0, len(r.Coverage)),
		Findings:    make([]SecurityScanFinding, 0, len(r.Findings)),
	}
	for _, c := range r.Coverage {
		row := SecurityScanCoverage{Dimension: string(c.Target.Dimension), Source: c.Source, Status: string(c.Status), Explanation: c.Explanation}
		if c.Counts != nil {
			row.Counts = &SecurityScanRowCount{Rules: c.Counts.Rules, Withdrawn: c.Counts.Withdrawn, Devices: c.Counts.Assets,
				Findings: c.Counts.Findings, Unknown: c.Counts.Unknown, PotentiallyAffected: c.Counts.Potential}
		}
		out.Coverage = append(out.Coverage, row)
	}
	for _, f := range r.Findings {
		sf := SecurityScanFinding{
			Rule: f.RuleID, RuleRevision: f.RuleRevision, Device: maskDeviceID(f.Asset), Applicability: string(f.Applicability),
			Severity: string(f.SourceSeverity), Reason: string(f.Reason), EvidenceState: string(f.EvidenceState),
			Confidence: string(f.Confidence), Explanation: f.Explanation, Verification: append([]string(nil), f.Verification...),
		}
		if env.Privacy != nil {
			sf.DeviceRef = env.Privacy.APIPseudonym(f.Asset)
		}
		for _, e := range f.Evidence {
			se := SecurityScanEvidence{Origin: string(e.Origin), AcquiredAt: timeText(e.AcquiredAt), Freshness: string(e.Freshness), Error: e.Error}
			if e.ObservedAt != nil {
				se.ObservedAt = timeText(*e.ObservedAt)
			}
			sf.Evidence = append(sf.Evidence, se)
		}
		out.Findings = append(out.Findings, sf)
	}
	return out
}

func catalogInfo(c security.Catalog) SecurityScanCatalog {
	info := SecurityScanCatalog{Revision: c.Revision, IssuedAt: timeText(c.IssuedAt), ExpiresAt: timeText(c.ExpiresAt), Digest: c.Digest, Rules: len(c.Records)}
	for _, r := range c.Records {
		switch r.ReviewState {
		case security.ReviewApproved:
			info.Approved++
		case security.ReviewPending:
			info.Pending++
		case security.ReviewWithdrawn:
			info.Withdrawn++
		}
	}
	return info
}

func timeText(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// maskDeviceID is how a scan shows a device's node ID: the first four characters and an
// ellipsis, and for an ID shorter than eight characters only its first half (none, for one
// character), so that part of an ID is withheld whatever its length. sanitize.MaskID keeps an
// ID of eight characters or fewer whole, which suits a tailnet or a client ID (it is used for
// those, and not changed) and would show a short device ID in full. Characters are counted as
// runes, and the cut is on a rune boundary.
func maskDeviceID(id string) string {
	r := []rune(id)
	return string(r[:min(4, len(r)/2)]) + "…"
}
