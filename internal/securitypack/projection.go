package securitypack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/abm9111/tailkeeper/internal/security"
)

// PublicRule is a rule identity established by the caller's shipped catalog.
type PublicRule struct{ ID, Revision string }

// PublicCatalog is the caller's trusted description of its shipped catalog.
type PublicCatalog struct {
	Digest string
	Rules  []PublicRule
}

// Projection is an immutable, conclusions-only document. Its representation is private.
type Projection struct{ document []byte }

var errProjection = errors.New("securitypack: projection refused")

// EncodeProjection returns a copy of the canonical projection document.
func EncodeProjection(p Projection) ([]byte, error) {
	if len(p.document) == 0 {
		return nil, errProjection
	}
	return bytes.Clone(p.document), nil
}

// Project replays pack before constructing a shareable projection. public and ref come
// from trusted adapters: public describes the shipped catalog; ref is empty or 12 hex.
func Project(ctx context.Context, pack EvidencePack, budget security.WorkBudget, public PublicCatalog, ref string) (Projection, error) {
	if !projectionRef(ref) {
		return Projection{}, errProjection
	}
	r, err := Replay(ctx, pack, budget)
	if err != nil {
		return Projection{}, err
	}
	if r.Reproduction.Status != "reproduced" {
		return Projection{}, ErrNotReproduced
	}
	return projectReplayed(r, public, ref)
}

func projectionRef(s string) bool {
	if s == "" {
		return true
	}
	if len(s) != 12 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

type projectionWriter struct {
	e   *canonEncoder
	err error
}

func (w *projectionWriter) step(err error) {
	if w.err == nil && err != nil {
		w.err = err
	}
}
func (w *projectionWriter) obj()                   { w.step(w.e.beginObject()) }
func (w *projectionWriter) endObj()                { w.step(w.e.endObject()) }
func (w *projectionWriter) arr()                   { w.step(w.e.beginArray()) }
func (w *projectionWriter) endArr()                { w.step(w.e.endArray()) }
func (w *projectionWriter) key(s string)           { w.step(w.e.key(s)) }
func (w *projectionWriter) text(s string)          { w.step(w.e.text(s)) }
func (w *projectionWriter) num(n int)              { w.step(w.e.integer(int64(n))) }
func (w *projectionWriter) uint(n uint64)          { w.step(w.e.unsigned(n)) }
func (w *projectionWriter) boolean(v bool)         { w.step(w.e.boolean(v)) }
func (w *projectionWriter) instant(t time.Time)    { w.step(w.e.instant(t.UTC().Truncate(time.Minute))) }
func (w *projectionWriter) str(k, v string)        { w.key(k); w.text(v) }
func (w *projectionWriter) number(k string, v int) { w.key(k); w.num(v) }

func projectReplayed(r Replayed, public PublicCatalog, ref string) (Projection, error) {
	var b bytes.Buffer
	w := &projectionWriter{e: newCanonEncoder(&b, MaxCanonBytes)}
	w.obj()
	if r.AccessReport != nil {
		w.key("access")
		writeProjectionAccess(w, *r.AccessReport, r.inputs.Intent)
	}
	w.key("catalog")
	writeProjectionCatalog(w, r.catalog, r.Report.GeneratedAt, public)
	w.key("counts")
	writeProjectionCounts(w, r.Report)
	w.key("coverage")
	writeProjectionCoverage(w, r.Report.Coverage)
	w.str("evaluated_at", r.Report.GeneratedAt.UTC().Truncate(time.Minute).Format(time.RFC3339))
	w.number("evaluator_version", security.EvaluatorVersion)
	w.key("findings")
	writeProjectionFindings(w, r.Report.Findings, public)
	w.str("format", "tailkeeper-evidence-projection")
	w.key("potential_by_reason")
	writeProjectionReasons(w, r.Report.Findings, security.ApplicabilityPotential)
	w.number("projection_schema_version", 1)
	if ref != "" {
		w.str("ref", ref)
	}
	w.key("replay_coverage")
	writeProjectionReplayCoverage(w)
	w.number("report_schema_version", security.SchemaVersion)
	w.str("scope", string(r.Report.Snapshot.Scope))
	w.str("status", string(r.Report.Status))
	w.key("unknown_by_reason")
	writeProjectionReasons(w, r.Report.Findings, security.ApplicabilityUnknown)
	w.endObj()
	w.step(w.e.finish(true))
	if w.err != nil {
		return Projection{}, w.err
	}
	return Projection{document: bytes.Clone(b.Bytes())}, nil
}

func writeProjectionCounts(w *projectionWriter, r security.Report) {
	var affected, potential, unknown, notAffected int
	for _, f := range r.Findings {
		switch f.Applicability {
		case security.ApplicabilityAffected:
			affected++
		case security.ApplicabilityPotential:
			potential++
		case security.ApplicabilityUnknown:
			unknown++
		case security.ApplicabilityNotAffected:
			notAffected++
		}
	}
	w.obj()
	w.number("affected", affected)
	w.number("not_affected", notAffected)
	w.number("potentially_affected", potential)
	w.number("total", r.TotalFindings)
	w.number("unknown", unknown)
	w.endObj()
}
func writeProjectionReasons(w *projectionWriter, fs []security.Finding, applicability security.Applicability) {
	counts := make(map[security.UnknownReason]int)
	for _, f := range fs {
		if f.Applicability == applicability {
			counts[f.Reason]++
		}
	}
	keys := make([]security.UnknownReason, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	w.arr()
	for _, k := range keys {
		w.obj()
		w.number("count", counts[k])
		w.str("reason", string(k))
		w.endObj()
	}
	w.endArr()
}
func writeProjectionCatalog(w *projectionWriter, c security.Catalog, at time.Time, public PublicCatalog) {
	var approved, pending, withdrawn, stale int
	for _, r := range c.Records {
		switch r.ReviewState {
		case security.ReviewApproved:
			approved++
		case security.ReviewPending:
			pending++
		case security.ReviewWithdrawn:
			withdrawn++
		}
		if security.ReviewStale(r, at) {
			stale++
		}
	}
	w.obj()
	w.number("approved", approved)
	if c.Digest != "" && c.Digest == public.Digest {
		w.str("digest", public.Digest)
		w.key("expires_at")
		w.instant(c.ExpiresAt)
		w.key("issued_at")
		w.instant(c.IssuedAt)
	}
	w.number("pending", pending)
	if c.Digest != "" && c.Digest == public.Digest {
		w.key("revision")
		w.uint(c.Revision)
	}
	w.number("stale_review", stale)
	w.str("state_at_evaluation", string(security.CatalogStateAt(c, at)))
	w.number("withdrawn", withdrawn)
	w.endObj()
}
func writeProjectionCoverage(w *projectionWriter, rows []security.Coverage) {
	w.arr()
	for _, row := range rows {
		w.obj()
		if row.Counts != nil {
			c := row.Counts
			w.key("counts")
			w.obj()
			w.number("assets", c.Assets)
			w.number("findings", c.Findings)
			w.number("potential", c.Potential)
			w.number("rules", c.Rules)
			w.number("unknown", c.Unknown)
			w.number("withdrawn", c.Withdrawn)
			w.endObj()
		}
		w.str("dimension", string(row.Target.Dimension))
		w.str("scope", string(row.Target.Scope))
		w.str("status", string(row.Status))
		w.endObj()
	}
	w.endArr()
}
func publicRule(public PublicCatalog, id, revision string) bool {
	for _, r := range public.Rules {
		if r.ID == id && r.Revision == revision {
			return true
		}
	}
	return false
}
func ordinal(prefix string, n int) string { return fmt.Sprintf("%s-%d", prefix, n) }
func writeProjectionFindings(w *projectionWriter, findings []security.Finding, public PublicCatalog) {
	devices := make(map[string]string)
	rules := make(map[string]string)
	w.arr()
	for i, f := range findings {
		device, ok := devices[f.Asset]
		if !ok {
			device = ordinal("device", len(devices)+1)
			devices[f.Asset] = device
		}
		rule, known := f.RuleID, publicRule(public, f.RuleID, f.RuleRevision)
		if !known {
			rule, ok = rules[f.RuleID]
			if !ok {
				rule = ordinal("rule", len(rules)+1)
				rules[f.RuleID] = rule
			}
		}
		w.obj()
		w.str("applicability", string(f.Applicability))
		w.str("confidence", string(f.Confidence))
		w.str("device", device)
		w.key("evidence")
		writeProjectionEvidence(w, f.Evidence)
		w.str("evidence_state", string(f.EvidenceState))
		w.str("id", ordinal("finding", i+1))
		w.str("priority", string(f.Priority))
		if f.Reason != "" {
			w.str("reason", string(f.Reason))
		}
		w.str("rule", rule)
		if known {
			w.str("rule_revision", f.RuleRevision)
		}
		w.str("severity", string(f.SourceSeverity))
		w.endObj()
	}
	w.endArr()
}
func writeProjectionEvidence(w *projectionWriter, refs []security.EvidenceRef) {
	origins := make(map[security.Origin]bool)
	freshness := make(map[security.Freshness]bool)
	var hasError bool
	for _, r := range refs {
		origins[r.Origin] = true
		freshness[r.Freshness] = true
		hasError = hasError || r.Error != ""
	}
	os := make([]security.Origin, 0, len(origins))
	for o := range origins {
		os = append(os, o)
	}
	slices.Sort(os)
	fs := make([]security.Freshness, 0, len(freshness))
	for f := range freshness {
		fs = append(fs, f)
	}
	slices.Sort(fs)
	w.obj()
	w.key("any_error")
	w.boolean(hasError)
	w.number("count", len(refs))
	w.key("freshness")
	w.arr()
	for _, f := range fs {
		w.text(string(f))
	}
	w.endArr()
	w.key("origins")
	w.arr()
	for _, o := range os {
		w.text(string(o))
	}
	w.endArr()
	w.endObj()
}

func projectionExpectationID(id string, kind security.AccessKind, intent *security.IntentSet) (string, bool) {
	if intent == nil {
		return "", false
	}
	switch kind {
	case security.AccessNetwork:
		for i, expectation := range intent.Network {
			if expectation.ID == id {
				return ordinal("network", i+1), true
			}
		}
	case security.AccessSSH:
		for i, expectation := range intent.SSH {
			if expectation.ID == id {
				return ordinal("ssh", i+1), true
			}
		}
	}
	return "", false
}
func projectionNote(s string) bool {
	switch s {
	case security.NoteNoIntent, security.NoteEmptySet, security.NoteSSHNotNetwork, security.NoteCandidates, security.NoteCandidatesShort, security.NoteRulesPartial, security.NoteAssumption:
		return true
	}
	return false
}
func writeProjectionAccess(w *projectionWriter, r security.AccessReport, intent *security.IntentSet) {
	w.obj()
	w.key("counts")
	w.obj()
	w.number("met", r.Counts.Met)
	w.number("met_with_limits", r.Counts.MetWithLimits)
	w.number("not_evaluated", r.Counts.NotEvaluated)
	w.number("total", r.Counts.Total)
	w.number("unknown", r.Counts.Unknown)
	w.number("unmet", r.Counts.Unmet)
	w.endObj()
	w.key("expectations")
	w.arr()
	for _, row := range r.Expectations {
		id, ok := projectionExpectationID(row.ID, row.Kind, intent)
		if !ok {
			w.step(errProjection)
			return
		}
		w.obj()
		w.str("id", id)
		w.str("kind", string(row.Kind))
		w.key("limits")
		w.arr()
		for _, l := range row.Limits {
			w.text(string(l))
		}
		w.endArr()
		w.str("status", string(row.Status))
		w.endObj()
	}
	w.endArr()
	w.key("notes")
	w.arr()
	for _, n := range r.Notes {
		if projectionNote(n) {
			w.text(n)
		}
	}
	w.endArr()
	w.number("omitted", r.Omitted)
	w.endObj()
}

const projectionStatement = "This is a redacted projection. It records conclusions made from a private evidence pack and does not carry the facts they rest on, so none of them can be reproduced from this file. Only the owner of the private pack can replay it. A projection is not evidence that its conclusions are true."

func writeProjectionReplayCoverage(w *projectionWriter) {
	w.obj()
	w.key("conclusions")
	w.arr()
	writeProjectionConclusion(w, "advisory_findings", "not_reproducible", []string{"fact_values", "device_identifiers", "fact_times", "catalog_bytes"})
	writeProjectionConclusion(w, "access_expectations", "not_reproducible", []string{"intent_text", "witnesses"})
	writeProjectionConclusion(w, "coverage", "recorded_not_reproducible", nil)
	w.endArr()
	w.key("removed")
	w.arr()
	for _, s := range []string{"context", "device_identifiers", "fact_values", "fact_times", "finding_ids", "intent_text", "witnesses", "candidate_rules", "policy_version", "catalog_bytes", "catalog_text", "coverage_text"} {
		w.text(s)
	}
	w.endArr()
	w.key("reproducible")
	w.boolean(false)
	w.str("statement", projectionStatement)
	w.endObj()
}
func writeProjectionConclusion(w *projectionWriter, class, status string, needs []string) {
	w.obj()
	w.str("class", class)
	if needs != nil {
		w.key("needs")
		w.arr()
		for _, s := range needs {
			w.text(s)
		}
		w.endArr()
	}
	w.str("status", status)
	w.endObj()
}
