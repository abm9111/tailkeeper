package security

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// coverageSource names the coverage row that Match returns.
const coverageSource = "advisory catalog"

// errFindingsLimit is returned, wrapping ErrWorkBudget, when a run would produce more than
// MaxFindings findings: a caller that tests for ErrWorkBudget sees it, and the coverage row
// says which limit was reached.
var errFindingsLimit = fmt.Errorf("%w (findings limit)", ErrWorkBudget)

type matchWork struct {
	ctx         context.Context
	used, limit int
}

func (w *matchWork) step() error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if w.used >= w.limit {
		return ErrWorkBudget
	}
	w.used++
	return nil
}

// Match evaluates every rule of the catalog against every device the snapshot names, and
// returns a finding for each pair, in the order of the rules and then of the devices as
// their facts were first seen (versions, then platforms, then features). It evaluates present
// observations only and does not reconcile previous findings. It does not read the clock: now is
// the time of evaluation.
//
// A device is judged by every approved or pending rule; a device a rule cannot judge gets an
// unknown finding with a reason, and is never left out. A withdrawn rule is skipped and
// counted. The coverage row it returns (catalog dimension, the snapshot's scope and context)
// always carries counts, and is complete only when the catalog and every rule evaluated are
// approved and fresh, at least one rule and one device were evaluated, and no finding is
// unknown or potentially affected; otherwise it is partial and explains why.
//
// Input that is not valid (a nil context, a budget outside 0 to MaxCandidates, an invalid
// snapshot or catalog) returns (nil, nil, err) with no coverage row: nothing was judged. Once
// evaluation has started, an error (cancellation, the work budget, the findings limit) returns
// the findings so far, a valid partial row that says where it stopped, and the error.
//
// The facts are indexed by device once, so the work is about the number of rules times the
// number of facts and not that times the number of devices.
func Match(ctx context.Context, c Catalog, s Snapshot, now time.Time, budget WorkBudget) ([]Finding, []Coverage, error) {
	if ctx == nil {
		return nil, nil, errors.New("nil context")
	}
	limit, err := budget.limit()
	if err != nil {
		return nil, nil, err
	}
	if err := validateMatchSnapshot(s, now); err != nil {
		return nil, nil, err
	}
	// From here the snapshot is valid, so a coverage row can name its scope and context.
	m := &matcher{w: matchWork{ctx: ctx, limit: limit}, c: c, s: s, now: now, findings: make([]Finding, 0),
		unknown: map[UnknownReason]int{}, potential: map[UnknownReason]int{}}
	if err := ctx.Err(); err != nil {
		return m.findings, m.rows(err), err
	}
	if err := validateCatalog(ctx, c); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return m.findings, m.rows(err), err
		}
		return nil, nil, err
	}
	m.catalogChecked = true
	m.catalogFresh = CatalogStateAt(c, now) == CatalogCurrent
	if err := m.indexDevices(); err != nil {
		return m.findings, m.rows(err), err
	}
	if err := m.evaluateRules(); err != nil {
		return m.findings, m.rows(err), err
	}
	return m.findings, m.rows(nil), nil
}

// validateMatchSnapshot refuses a snapshot that could not be the snapshot of a report. It
// applies the checks ValidateReport applies to a report's snapshot, so that what Match
// returns for a valid snapshot can be put in a report: every fact names a device and carries
// the snapshot's context and scope, and the text and times are those a report may hold.
func validateMatchSnapshot(s Snapshot, now time.Time) error {
	switch {
	case s.Context == "":
		return errors.New("snapshot context is empty")
	case s.Scope != ScopeLocal && s.Scope != ScopeFleet:
		return errors.New("snapshot scope must be local or fleet")
	case now.IsZero():
		return errors.New("evaluation time is missing")
	case s.ObservedAt.IsZero():
		return errors.New("snapshot observation time is missing")
	case s.ObservedAt.After(now):
		return errors.New("snapshot observed after the evaluation time")
	case len(s.Versions)+len(s.Platforms)+len(s.Features)+len(s.Policies) > MaxObservations:
		return errors.New("too many snapshot observations")
	}
	if err := validateText(reflect.ValueOf(s)); err != nil {
		return err
	}
	return validateSnapshotFacts(Report{Context: s.Context, GeneratedAt: now, Snapshot: s})
}

// matcher is one run of Match: the inputs, the facts indexed by device, the findings so far
// and the tallies that the coverage row reports.
type matcher struct {
	w   matchWork
	c   Catalog
	s   Snapshot
	now time.Time

	catalogChecked bool // the catalog has been validated, so its freshness is known
	catalogFresh   bool
	byDevice       map[string]*deviceFacts
	order          []string // the devices, in the order their facts were first seen
	findings       []Finding

	position             int // the rule being evaluated, counting withdrawn ones; 0 before the first
	rules, withdrawn     int // evaluated and skipped rules
	pending, reviewStale int // evaluated rules that are pending, and approved with an expired review
	nUnknown, nPotential int
	unknown, potential   map[UnknownReason]int
}

// deviceFacts are the positions in the snapshot of the facts that name one device.
type deviceFacts struct {
	versions, platforms, features []int
	// connectedAt is the position of the first usable connected_to_control=true fact of origin
	// api, or -1; disconnected says a usable false one exists. Together they decide R9.
	connectedAt  int
	disconnected bool
}

// connected says that the device is connected to control as the API reports it: a usable
// true fact of origin api and no usable false one. Contradictory facts of the API are not
// believed. This is the one test of the guard that lets the API speak for the daemon: the
// version the API reports (D1) and the features it reports (D5) both pass through it.
func (d *deviceFacts) connected() bool { return d.connectedAt >= 0 && !d.disconnected }

// indexDevices indexes every fact by the device it names, in one pass over each list, and
// records the devices in first-seen order: versions, then platforms, then features. A fact
// of a device that has no usable evidence still names it.
func (m *matcher) indexDevices() error {
	m.byDevice = make(map[string]*deviceFacts)
	device := func(asset string) *deviceFacts {
		d, ok := m.byDevice[asset]
		if !ok {
			d = &deviceFacts{connectedAt: -1}
			m.byDevice[asset] = d
			m.order = append(m.order, asset)
		}
		return d
	}
	for i := range m.s.Versions {
		if err := m.w.step(); err != nil {
			return err
		}
		d := device(m.s.Versions[i].Evidence.Asset)
		d.versions = append(d.versions, i)
	}
	for i := range m.s.Platforms {
		if err := m.w.step(); err != nil {
			return err
		}
		d := device(m.s.Platforms[i].Evidence.Asset)
		d.platforms = append(d.platforms, i)
	}
	for i := range m.s.Features {
		if err := m.w.step(); err != nil {
			return err
		}
		f := &m.s.Features[i]
		asset := f.Evidence.Asset
		d := device(asset)
		d.features = append(d.features, i)
		if f.Name == FeatureConnectedToControl && f.Value != nil && f.Evidence.Origin == OriginAPI && usable(f.Evidence, m.s, asset, m.now) {
			if *f.Value {
				if d.connectedAt < 0 {
					d.connectedAt = i
				}
			} else {
				d.disconnected = true
			}
		}
	}
	return nil
}

// evaluateRules judges every device by every rule that is not withdrawn.
func (m *matcher) evaluateRules() error {
	for i, r := range m.c.Records {
		m.position = i + 1
		if r.ReviewState == ReviewWithdrawn {
			m.withdrawn++
			continue
		}
		m.rules++
		switch {
		case r.ReviewState == ReviewPending:
			m.pending++
		case ReviewStale(r, m.now):
			m.reviewStale++
		}
		var required map[string]int
		if len(r.RequiredFeatures) > 0 {
			required = make(map[string]int, len(r.RequiredFeatures))
			for k, name := range r.RequiredFeatures {
				required[name] = k
			}
		}
		for _, asset := range m.order {
			if err := m.w.step(); err != nil {
				return err
			}
			out, err := m.judge(r, required, asset, m.byDevice[asset])
			if err != nil {
				return err
			}
			if len(m.findings) >= MaxFindings {
				return errFindingsLimit
			}
			m.add(m.finding(r, asset, m.applyState(r, out)))
		}
	}
	return nil
}

func (m *matcher) reviewFresh(r AdvisoryRecord) bool { return ReviewFresh(r, m.now) }

func (m *matcher) add(f Finding) {
	m.findings = append(m.findings, f)
	switch f.Applicability {
	case ApplicabilityUnknown:
		m.nUnknown++
		m.unknown[f.Reason]++
	case ApplicabilityPotential:
		m.nPotential++
		m.potential[f.Reason]++
	}
}

// outcome is what the matcher concludes about one rule and one device from the evidence,
// before the state of the rule and of the catalog is applied.
type outcome struct {
	applicability Applicability
	reason        UnknownReason // set for unknown and potentially affected, empty otherwise
	evidence      []EvidenceRef
}

func unknownOutcome(reason UnknownReason, evidence []EvidenceRef) outcome {
	return outcome{applicability: ApplicabilityUnknown, reason: reason, evidence: evidence}
}

// versionChoice is the release a rule is compared with. exact says that it comes from
// evidence of the running daemon (a local or collector fact of that role, or, while the
// device is connected to control, the API's report: R9); when it does not, only reports of
// the version exist (the runtime is unobserved). failure is set instead when no release can
// be chosen.
type versionChoice struct {
	release  numericVersion
	exact    bool
	evidence []EvidenceRef
	failure  *outcome
}

// refuse is the choice of no release: the device is unknown for the reason.
func refuse(reason UnknownReason, evidence []EvidenceRef) versionChoice {
	o := unknownOutcome(reason, evidence)
	return versionChoice{failure: &o}
}

func evidenceOf(facts []*VersionFact) []EvidenceRef {
	evidence := make([]EvidenceRef, len(facts))
	for i, v := range facts {
		evidence[i] = v.Evidence
	}
	return evidence
}

// selectVersion chooses the release of one device for one rule (C6 step 1).
//
// The candidates are the device's usable facts for the rule's component that carry a value.
// Exact facts are those whose role is the rule's role, from an origin allowed for that role.
// For a running-daemon rule the API's report counts as exact too while the device is
// connected to control (R9), and a local CLI report is ignored whenever an exact fact exists.
// Without an exact fact, a running-daemon rule falls back on the API and CLI reports, which
// cannot establish what the daemon runs. The releases of the facts compared must be equal;
// each fact that decides must be on the stable track.
func (m *matcher) selectVersion(r AdvisoryRecord, asset string, d *deviceFacts) (versionChoice, error) {
	facts, err := m.collectVersions(r, asset, d)
	if err != nil {
		return versionChoice{}, err
	}
	if refusal, ok := facts.refusal(); ok {
		return refusal, nil
	}
	connected := r.VersionRole == VersionRunningDaemon && d.connected()
	basis, ok := facts.basis(connected)
	if !ok {
		// Usable facts exist, but none of a role and origin this rule can use.
		return refuse(ReasonNoVersion, nil), nil
	}
	evidence := evidenceOf(basis.compared)
	if connected && len(facts.api) > 0 {
		evidence = append(evidence, m.s.Features[d.connectedAt].Evidence)
	}
	return chooseRelease(basis, evidence), nil
}

// versionFacts are the facts of one device for the component of a rule: all that name it,
// and the usable ones that carry a value by the role they can play.
type versionFacts struct {
	named, exact, api, cli []*VersionFact
	usableAny, errored     bool
}

// collectVersions sorts the device's facts for the rule's component. Each fact costs a step
// of the work budget.
func (m *matcher) collectVersions(r AdvisoryRecord, asset string, d *deviceFacts) (versionFacts, error) {
	var c versionFacts
	for _, i := range d.versions {
		if err := m.w.step(); err != nil {
			return versionFacts{}, err
		}
		v := &m.s.Versions[i]
		if v.Name != r.Component {
			continue
		}
		c.named = append(c.named, v)
		if v.Evidence.Error != "" {
			c.errored = true
		}
		if !usable(v.Evidence, m.s, asset, m.now) {
			continue
		}
		c.usableAny = true
		if v.Value != nil {
			c.classify(v, r)
		}
	}
	return c, nil
}

// classify puts the usable fact v, which carries a value, among the exact facts or, for a
// running-daemon rule, among the reports that can only stand in for them.
func (c *versionFacts) classify(v *VersionFact, r AdvisoryRecord) {
	daemon := r.VersionRole == VersionRunningDaemon
	switch {
	case v.Role == r.VersionRole && roleOriginOK(v.Role, v.Evidence.Origin):
		c.exact = append(c.exact, v)
	case daemon && v.Role == VersionAPIReported && roleOriginOK(v.Role, v.Evidence.Origin):
		c.api = append(c.api, v)
	case daemon && v.Role == VersionLocalCLI && roleOriginOK(v.Role, v.Evidence.Origin):
		c.cli = append(c.cli, v)
	}
}

// refusal is the choice of no release when the device has no usable fact for the component.
func (c versionFacts) refusal() (versionChoice, bool) {
	switch {
	case len(c.named) == 0:
		return refuse(ReasonNoVersion, nil), true
	case !c.usableAny && c.errored:
		return refuse(ReasonEvidenceError, evidenceOf(c.named)), true
	case !c.usableAny:
		return refuse(ReasonStaleEvidence, evidenceOf(c.named)), true
	}
	return versionChoice{}, false
}

// A versionBasis is the facts that decide the release and the facts whose releases must
// agree with it.
type versionBasis struct {
	deciding, compared []*VersionFact
	fallback           bool // only reports of the version, which cannot establish what the daemon runs
}

// basis chooses the deciding facts. ok is false when no fact of a role and origin the rule
// can use exists.
func (c versionFacts) basis(connected bool) (versionBasis, bool) {
	deciding := c.exact
	if connected {
		deciding = append(append([]*VersionFact(nil), c.exact...), c.api...)
	}
	fallback := false
	if len(deciding) == 0 {
		if len(c.api)+len(c.cli) == 0 {
			return versionBasis{}, false
		}
		deciding = append(append([]*VersionFact(nil), c.api...), c.cli...)
		fallback = true
	}
	compared := deciding
	if !fallback && !connected {
		// An API report that is not believed as the daemon must still agree with it.
		compared = append(append([]*VersionFact(nil), c.exact...), c.api...)
	}
	return versionBasis{deciding: deciding, compared: compared, fallback: fallback}, true
}

// chooseRelease reads the releases of the facts compared. They must be recognised and equal,
// and each fact that decides must be on the stable track.
func chooseRelease(b versionBasis, evidence []EvidenceRef) versionChoice {
	releases := make([]numericVersion, len(b.compared))
	for i, v := range b.compared {
		n, ok := parseRelease(*v.Value)
		if !ok {
			return refuse(ReasonUnrecognisedBuild, evidence)
		}
		releases[i] = n
	}
	for _, n := range releases[1:] {
		if n != releases[0] {
			return refuse(ReasonVersionConflict, evidence)
		}
	}
	if reason := trackRefusal(b.deciding, releases[0]); reason != "" {
		return refuse(reason, evidence)
	}
	return versionChoice{release: releases[0], exact: !b.fallback, evidence: evidence}
}

// trackRefusal is the reason the release cannot be used, or "": a fact on the unstable track
// refuses at once, and a channel that is not known refuses after the others are read.
func trackRefusal(deciding []*VersionFact, release numericVersion) UnknownReason {
	unknownTrack := false
	for _, v := range deciding {
		switch trackReason(v.Channel, release) {
		case ReasonUnstableTrack:
			return ReasonUnstableTrack
		case ReasonChannelUnknown:
			unknownTrack = true
		}
	}
	if unknownTrack {
		return ReasonChannelUnknown
	}
	return ""
}

// judge evaluates one rule for one device (C6 steps 1 to 3), before the state of the rule
// and of the catalog is applied.
func (m *matcher) judge(r AdvisoryRecord, required map[string]int, asset string, d *deviceFacts) (outcome, error) {
	choice, err := m.selectVersion(r, asset, d)
	if err != nil {
		return outcome{}, err
	}
	if choice.failure != nil {
		return *choice.failure, nil
	}
	inRange := false
	for _, rg := range r.Ranges {
		if err := m.w.step(); err != nil {
			return outcome{}, err
		}
		if insideRange(choice.release, rg) {
			inRange = true
			break
		}
	}
	switch {
	case !choice.exact && inRange:
		return outcome{applicability: ApplicabilityPotential, reason: ReasonRuntimeUnobserved, evidence: choice.evidence}, nil
	case !choice.exact:
		return unknownOutcome(ReasonRuntimeUnobserved, choice.evidence), nil
	case !inRange:
		// Out of range, the operating system and the features do not matter.
		return outcome{applicability: ApplicabilityNotAffected, evidence: choice.evidence}, nil
	}
	return m.applyConditions(r, required, asset, d, choice.evidence)
}

// truth is what the evidence says about one condition of a rule.
type truth int

const (
	truthUnknown truth = iota
	truthTrue
	truthFalse
)

// applyConditions decides an exact, in-range result. A condition known to be false clears
// the device, whatever else is unknown; all conditions known to hold make it affected;
// otherwise it is potentially affected, for the reason of the first unknown condition (the
// operating system, then the features).
func (m *matcher) applyConditions(r AdvisoryRecord, required map[string]int, asset string, d *deviceFacts, base []EvidenceRef) (outcome, error) {
	osTruth, osReason, osEvidence, err := m.osCondition(r, asset, d)
	if err != nil {
		return outcome{}, err
	}
	featureTruth, featureReason, featureEvidence, err := m.featureCondition(r, required, asset, d, base)
	if err != nil {
		return outcome{}, err
	}
	evidence := append(append(append([]EvidenceRef(nil), base...), osEvidence...), featureEvidence...)
	switch {
	case osTruth == truthFalse || featureTruth == truthFalse:
		return outcome{applicability: ApplicabilityNotAffected, evidence: evidence}, nil
	case osTruth == truthTrue && featureTruth == truthTrue:
		return outcome{applicability: ApplicabilityAffected, evidence: evidence}, nil
	case osTruth == truthUnknown:
		return outcome{applicability: ApplicabilityPotential, reason: osReason, evidence: evidence}, nil
	}
	return outcome{applicability: ApplicabilityPotential, reason: featureReason, evidence: evidence}, nil
}

// osCondition says whether the device runs the operating system the rule names. Only usable
// platform facts whose origin matches the rule's role speak (the others are conditional, and
// say nothing); a fact without an OS says nothing; a spelling outside the vocabulary, or
// facts that disagree, leave the condition unknown.
func (m *matcher) osCondition(r AdvisoryRecord, asset string, d *deviceFacts) (truth, UnknownReason, []EvidenceRef, error) {
	if r.OS == "" {
		return truthTrue, "", nil, nil
	}
	var evidence []EvidenceRef
	seen := ""
	mixed, unrecognised := false, false
	for _, i := range d.platforms {
		if err := m.w.step(); err != nil {
			return truthUnknown, "", nil, err
		}
		p := &m.s.Platforms[i]
		if p.OS == "" || !usable(p.Evidence, m.s, asset, m.now) || !roleOriginOK(r.VersionRole, p.Evidence.Origin) {
			continue
		}
		evidence = append(evidence, p.Evidence)
		canonical, ok := NormaliseOS(p.OS)
		switch {
		case !ok:
			unrecognised = true
		case seen == "":
			seen = canonical
		case seen != canonical:
			mixed = true
		}
	}
	switch {
	case unrecognised:
		return truthUnknown, ReasonOSUnrecognised, evidence, nil
	case seen == "" || mixed:
		return truthUnknown, ReasonOSUnknown, evidence, nil
	case seen == r.OS:
		return truthTrue, "", evidence, nil
	}
	return truthFalse, "", evidence, nil
}

// featureCondition says whether the features the rule requires are all on. Only usable
// facts with a value, whose origin matches the rule's role, speak (featureSpeaks says which
// do). One feature reported both on and off, by a local fact and a guarded API fact for
// instance, is unknown; any feature known to be off makes the condition false. base is the
// evidence the result already cites.
func (m *matcher) featureCondition(r AdvisoryRecord, required map[string]int, asset string, d *deviceFacts, base []EvidenceRef) (truth, UnknownReason, []EvidenceRef, error) {
	if len(required) == 0 {
		return truthTrue, "", nil, nil
	}
	states, evidence, err := m.featureStates(r, required, asset, d, base)
	if err != nil {
		return truthUnknown, "", nil, err
	}
	anyOff, allOn := false, true
	for _, st := range states {
		switch {
		case st.on && st.off:
			allOn = false
		case st.off:
			anyOff, allOn = true, false
		case !st.on:
			allOn = false
		}
	}
	switch {
	case anyOff:
		return truthFalse, "", evidence, nil
	case allOn:
		return truthTrue, "", evidence, nil
	}
	return truthUnknown, ReasonFeatureUnknown, evidence, nil
}

// reportedState is what the facts of one feature say: that it is on, that it is off, or both.
type reportedState struct{ on, off bool }

// featureStates reads the device's feature facts that speak for the rule, by the index the
// rule gives each required feature, and returns the evidence of those facts. When a fact
// spoke through the guard of D5, the connected_to_control fact that opened the guard is cited
// as well, unless base or the evidence of the facts read already holds the same observation.
// Each fact costs a step of the work budget.
func (m *matcher) featureStates(r AdvisoryRecord, required map[string]int, asset string, d *deviceFacts, base []EvidenceRef) ([]reportedState, []EvidenceRef, error) {
	states := make([]reportedState, len(r.RequiredFeatures))
	var evidence []EvidenceRef
	guarded := false
	for _, i := range d.features {
		if err := m.w.step(); err != nil {
			return nil, nil, err
		}
		f := &m.s.Features[i]
		k, ok := required[f.Name]
		if !ok || f.Value == nil || !usable(f.Evidence, m.s, asset, m.now) {
			continue
		}
		speaks, viaGuard := featureSpeaks(r.VersionRole, f, d)
		if !speaks {
			continue
		}
		guarded = guarded || viaGuard
		evidence = append(evidence, f.Evidence)
		if *f.Value {
			states[k].on = true
		} else {
			states[k].off = true
		}
	}
	if guarded {
		c := m.s.Features[d.connectedAt].Evidence
		held, err := m.cites(append(append([]EvidenceRef(nil), base...), evidence...), c)
		if err != nil {
			return nil, nil, err
		}
		if !held {
			evidence = append(evidence, c)
		}
	}
	return states, evidence, nil
}

// featureSpeaks says whether the usable feature fact f may speak for a rule of the role about
// its device, and whether it does so through the guard. A fact of an origin the role accepts
// (roleOriginOK) speaks. D5 adds one case: for a running-daemon or local-CLI rule a fact of
// origin api speaks too, while the device passes the guard of D1 (connected). The guard's
// own fact, connected_to_control, is never read this way: it stays what it is, the guard.
func featureSpeaks(role VersionRole, f *FeatureFact, d *deviceFacts) (speaks, viaGuard bool) {
	if roleOriginOK(role, f.Evidence.Origin) {
		return true, false
	}
	viaGuard = (role == VersionRunningDaemon || role == VersionLocalCLI) &&
		f.Evidence.Origin == OriginAPI && f.Name != FeatureConnectedToControl && d.connected()
	return viaGuard, viaGuard
}

// cites reports whether the evidence list already holds e, by value. Each element costs a
// step of the work budget.
func (m *matcher) cites(list []EvidenceRef, e EvidenceRef) (bool, error) {
	k := keyOfEvidence(e)
	for _, c := range list {
		if err := m.w.step(); err != nil {
			return false, err
		}
		if keyOfEvidence(c) == k {
			return true, nil
		}
	}
	return false, nil
}

// applyState applies the state of the catalog and of the rule to a result that is not
// already unknown (C6 step 4); an unknown keeps the reason it was given. A catalog or a
// review that is not fresh cannot clear a device, but a positive warning is kept. A pending
// rule neither clears nor confirms anything.
func (m *matcher) applyState(r AdvisoryRecord, o outcome) outcome {
	if o.applicability == ApplicabilityUnknown {
		return o
	}
	switch {
	case o.applicability == ApplicabilityNotAffected && !m.catalogFresh:
		return unknownOutcome(ReasonCatalogExpired, o.evidence)
	case o.applicability == ApplicabilityNotAffected && !m.reviewFresh(r):
		return unknownOutcome(ReasonReviewExpired, o.evidence)
	case r.ReviewState == ReviewPending:
		return unknownOutcome(ReasonReviewPending, o.evidence)
	}
	return o
}

// finding builds the finding of one outcome (C6 steps 5 and 6): the mitigation text goes to
// an affected or potentially affected finding only, and a pending rule has no such result
// (applyState made it unknown), so it never reaches a pending or withdrawn rule's finding; the
// evidence state follows the result.
func (m *matcher) finding(r AdvisoryRecord, asset string, o outcome) Finding {
	f := Finding{
		ID: FindingID(m.s.Context, m.s.Scope, asset, r.ID), Context: m.s.Context, Asset: asset, RuleID: r.ID, RuleRevision: r.Revision,
		EvidenceState: evidenceStateOf(o), Applicability: o.applicability, Reason: o.reason, Confidence: ConfidenceReported,
		SourceSeverity: r.Severity, Priority: PriorityUnknown, Evidence: o.evidence,
	}
	if len(o.evidence) == 0 {
		f.Confidence = ConfidenceUnknown
	}
	f.Explanation = explain(o, !m.catalogFresh || !m.reviewFresh(r))
	if r.Mitigation != "" && (o.applicability == ApplicabilityAffected || o.applicability == ApplicabilityPotential) {
		f.Verification = []string{r.Mitigation}
	}
	return f
}

// evidenceStateOf is observed for a result that rests on a version that was read (affected,
// not affected, potentially affected); for an unknown it is stale when the evidence was
// stale, absent when there was none, and unknown otherwise.
func evidenceStateOf(o outcome) EvidenceState {
	if o.applicability != ApplicabilityUnknown {
		return EvidenceObserved
	}
	switch o.reason {
	case ReasonStaleEvidence:
		return EvidenceStale
	case ReasonNoVersion:
		return EvidenceAbsent
	}
	return EvidenceUnknown
}

// reasonText says, in words fixed in the program, why a device is unknown or only
// potentially affected. No text of the input reaches it.
var reasonText = map[UnknownReason]string{
	ReasonCatalogExpired:    "The advisory catalog is not current, so it cannot clear this device.",
	ReasonReviewExpired:     "The review of this advisory rule has expired, so it cannot clear this device.",
	ReasonReviewPending:     "This advisory rule is pending review; it neither confirms nor clears this device.",
	ReasonNoVersion:         "No usable version of this component was reported for this device.",
	ReasonEvidenceError:     "The version evidence for this device carries an error.",
	ReasonStaleEvidence:     "The version evidence for this device is stale.",
	ReasonVersionConflict:   "The usable version reports for this device disagree.",
	ReasonUnrecognisedBuild: "A reported version is outside the release format this assessment reads.",
	ReasonChannelUnknown:    "The reported release does not say whether it is a stable release.",
	ReasonUnstableTrack:     "The reported release is on the unstable track, which the advisory ranges do not cover.",
	ReasonOSUnrecognised:    "The reported operating system is outside the vocabulary this assessment reads.",
	ReasonOSUnknown:         "The operating system the rule names is not established for this device.",
	ReasonFeatureUnknown:    "A feature the rule requires is not established for this device.",
	ReasonRuntimeUnobserved: "The running daemon was not observed; only reports of its version exist.",
}

const (
	plainExplanation = "Advisory evaluation of reported evidence."
	staleExplanation = "The advisory catalog or its review is stale; verify current guidance."
)

// explain is the explanation of a finding. A positive warning that is kept although the
// catalog or the rule's review is stale says so.
func explain(o outcome, stale bool) string {
	text := plainExplanation
	if o.reason != "" {
		text = reasonText[o.reason]
	}
	if !stale || (o.applicability != ApplicabilityAffected && o.applicability != ApplicabilityPotential) {
		return text
	}
	if o.reason == "" {
		return staleExplanation
	}
	return text + " " + staleExplanation
}

// rows is the coverage row of the run so far, with its counts. It is complete only if the
// catalog is fresh, every rule evaluated is approved and fresh, at least one rule and one
// device were evaluated, no finding is unknown or potentially affected and the run was not
// stopped; otherwise it is partial and its explanation names each cause with its count.
func (m *matcher) rows(stopped error) []Coverage {
	counts := CoverageCounts{Rules: m.rules, Withdrawn: m.withdrawn, Assets: len(m.order), Findings: len(m.findings), Unknown: m.nUnknown, Potential: m.nPotential}
	var causes []string
	if stopped != nil {
		causes = append(causes, m.stopCause(stopped))
	}
	if m.catalogChecked && !m.catalogFresh {
		causes = append(causes, "catalog expired or not yet valid")
	}
	if stopped == nil && m.rules == 0 {
		cause := "no rules evaluated"
		if m.withdrawn > 0 {
			cause += fmt.Sprintf(" (withdrawn rules skipped: %d)", m.withdrawn)
		}
		causes = append(causes, cause)
	}
	if m.pending > 0 {
		causes = append(causes, fmt.Sprintf("pending rules: %d", m.pending))
	}
	if m.reviewStale > 0 {
		causes = append(causes, fmt.Sprintf("rules with a stale review: %d", m.reviewStale))
	}
	if stopped == nil && len(m.order) == 0 {
		causes = append(causes, "no devices observed")
	}
	if m.nUnknown > 0 {
		causes = append(causes, fmt.Sprintf("unknown findings: %d (%s)", m.nUnknown, byReason(m.unknown)))
	}
	if m.nPotential > 0 {
		causes = append(causes, fmt.Sprintf("potentially affected findings: %d (%s)", m.nPotential, byReason(m.potential)))
	}
	row := Coverage{Target: CoverageTarget{Dimension: CoverageCatalog, Scope: m.s.Scope}, Context: m.s.Context, Source: coverageSource, Status: ReportComplete, Counts: &counts}
	if len(causes) > 0 {
		row.Status = ReportPartial
		row.Explanation = strings.Join(causes, "; ")
	}
	return []Coverage{row}
}

const stoppedEarlyPrefix = "evaluation stopped early:"

// StoppedEarly reports whether catalog evaluation stopped before completing its work.
func StoppedEarly(r Report) bool {
	for _, row := range r.Coverage {
		if row.Target.Dimension == CoverageCatalog && row.Source == coverageSource && strings.HasPrefix(row.Explanation, stoppedEarlyPrefix) {
			return true
		}
	}
	return false
}

// EvidenceMaxAge is the maximum age of evidence used for evaluation.
const EvidenceMaxAge = 30 * time.Minute

// stopCause says why and where a run stopped.
func (m *matcher) stopCause(err error) string {
	why := "error"
	switch {
	case errors.Is(err, errFindingsLimit):
		why = "findings limit reached"
	case errors.Is(err, ErrWorkBudget):
		why = "work budget exhausted"
	case errors.Is(err, context.Canceled):
		why = "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		why = "deadline exceeded"
	}
	where := "before the first rule"
	if m.position > 0 {
		where = fmt.Sprintf("at rule %d of %d", m.position, len(m.c.Records))
	}
	return stoppedEarlyPrefix + " " + why + ", " + where
}

// byReason lists the reasons of a tally in the order of the closed set, each with its count.
func byReason(tally map[UnknownReason]int) string {
	var parts []string
	for _, reason := range unknownReasons {
		if n := tally[reason]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", reason, n))
		}
	}
	return strings.Join(parts, ", ")
}

func usable(e EvidenceRef, s Snapshot, asset string, now time.Time) bool {
	observed := e.AcquiredAt
	if e.ObservedAt != nil {
		observed = *e.ObservedAt
	}
	if now.Sub(observed) > EvidenceMaxAge {
		return false
	}
	return e.Context == s.Context && e.Asset == asset && e.Scope == s.Scope && e.Freshness == FreshnessFresh && e.Error == "" && timesHold(e, now) && knownOrigin(e.Origin)
}

// timesHold reports whether the times of the evidence are possible at now: it was acquired,
// not in the future, and observed, if at all, at a time that is set and not after that.
func timesHold(e EvidenceRef, now time.Time) bool {
	if e.AcquiredAt.IsZero() || e.AcquiredAt.After(now) {
		return false
	}
	return e.ObservedAt == nil || (!e.ObservedAt.IsZero() && !e.ObservedAt.After(e.AcquiredAt))
}

// knownOrigin reports whether o is one of the origins evidence can have.
func knownOrigin(o Origin) bool {
	return o == OriginAPI || o == OriginLocal || o == OriginCollector || o == OriginOperator || o == OriginVendor || o == OriginDerived
}

func insideRange(n numericVersion, r VersionRange) bool {
	if r.Introduced != "" {
		x, _ := parseVersion(r.Introduced)
		if compareVersions(n, x) < 0 {
			return false
		}
	}
	if r.Fixed != "" {
		x, _ := parseVersion(r.Fixed)
		if compareVersions(n, x) >= 0 {
			return false
		}
	}
	return true
}

func roleOriginOK(role VersionRole, origin Origin) bool {
	switch role {
	case VersionRunningDaemon, VersionLocalCLI:
		return origin == OriginLocal || origin == OriginCollector
	case VersionAPIReported:
		return origin == OriginAPI
	default:
		return false
	}
}
