package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// This file collects the observations the advisory matcher judges: a snapshot of version,
// platform and feature facts, read from a fixed list of sources and bounded in time, in size
// and in the requests it makes. It reads canonical API bytes and the local CLI's JSON before
// any display masking, keeps the raw strings and the presence of every field, and records
// every source twice in the audit log (before it is asked, and how it ended). It registers
// no tool: a later change puts a tool on top of collectSecurity.

const (
	// securityBudget is the time a collection may spend asking its sources. The matching and
	// the output that follow have the rest of the call's time.
	securityBudget = 45 * time.Second
	// securityBodyMax bounds the device list a collection reads, as far as the surface lets
	// it: the client takes the lower of this and its own limit, so it is the limit over the
	// command line (32 MiB; the client's own is 64 MiB) and not over MCP, where the server
	// gives every call 8 MiB and a device list over that fails the API source. That failure
	// is a gap with a code of its own (response_too_large), recorded and shown in the
	// coverage, and nothing of the list is kept.
	securityBodyMax = 32 << 20
	// localFactReserve is the room the snapshot keeps for this node's own facts, so that a
	// full device list cannot crowd them out.
	localFactReserve = 8
	// securityCoverageSource names the producer in the coverage rows.
	securityCoverageSource = "security collection"
)

// securitySource is one source a collection may ask, with the operation it performs: an API
// operation spelled as the pinned OpenAPI document spells it, or the CLI's arguments. The
// list is fixed, at most four long, and nothing a caller supplies adds to it.
type securitySource struct {
	name security.CollectionSource
	op   string
}

var securitySources = [...]securitySource{
	{security.SourceAPIDevices, "GET /tailnet/{tailnet}/devices"},
	{security.SourceLocalStatus, "tailscale status --json --peers=false"},
	{security.SourceLocalVersion, "tailscale version --json --daemon"},
	{security.SourceLocalPrefs, "tailscale get --json"},
}

// args are the arguments of a local source's operation.
func (s securitySource) args() []string { return strings.Fields(s.op)[1:] }

// securityCollection is what a collection produced. Coverage has a row for each dimension the
// collection fed (versions and features) in the collection's scope; a row is complete only if
// every source that feeds it was read completely, and otherwise names each that was not. A
// snapshot that is missing a source is therefore never mistaken for a whole one.
type securityCollection struct {
	Snapshot security.Snapshot
	Coverage []security.Coverage
}

// collectSecurity reads the sources of the scope within securityBudget: the API device list
// (fleet scope only) and this node's status, versions and preferences. A source that fails is
// a gap in the coverage, not an error. It returns an error, and no collection, when a record
// of a source cannot be written to the audit log (before the first source is asked: nothing
// was asked), or when the snapshot fails its own validation. When the caller cancels, it
// returns the collection so far, its sources recorded as cancelled or skipped, and the
// context's error. The record of each source is made through env.RecordObservation, whose
// caller, tool and call come from the framework; the scope is the only input a caller of the
// tool supplies. required is the features the approved and pending rules of the catalog in
// use require (security.RequiredFeatures): the collection cannot know them, and the features
// coverage row is complete only if each is something the collection could and did observe.
func collectSecurity(ctx context.Context, env *registry.Env, scope security.Scope, required []string) (securityCollection, error) {
	return collectWithin(ctx, env, scope, required, securityBudget)
}

func collectWithin(ctx context.Context, env *registry.Env, scope security.Scope, required []string, budget time.Duration) (securityCollection, error) {
	if scope != security.ScopeLocal && scope != security.ScopeFleet {
		return securityCollection{}, validationf("the scope of a security collection is local or fleet")
	}
	if env == nil || env.RecordObservation == nil {
		return securityCollection{}, tkerr.New(tkerr.AuditUnavailable,
			"this surface keeps no per-source audit record, so the security assessment cannot run", "run it through the tailkeeper command line or MCP server")
	}
	r := &securityRun{env: env, scope: scope, ref: securityContextRef(env, scope), required: requiredSet(required)}
	bctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	for _, src := range securitySources {
		if src.name == security.SourceAPIDevices && scope != security.ScopeFleet {
			continue
		}
		if err := r.read(ctx, bctx, src); err != nil {
			return securityCollection{}, err
		}
	}
	now := r.now()
	r.snap.Context, r.snap.Scope, r.snap.ObservedAt = r.ref, scope, now
	if err := security.ValidateSnapshot(r.snap, now); err != nil {
		return securityCollection{}, tkerr.Wrap(tkerr.Internal, err, "the collected snapshot failed its own validation", "this is a tailkeeper bug; report it")
	}
	return securityCollection{Snapshot: r.snap, Coverage: r.coverage()}, ctx.Err()
}

// securityContextRef binds fleet observations to the API context when available. Local
// observations cannot establish membership, even when a client is configured.
func securityContextRef(env *registry.Env, scope security.Scope) string {
	if scope == security.ScopeFleet {
		if ref, err := apiContextRef(env); err == nil {
			return ref
		}
	}
	return security.ContextLocalOnly
}

// apiContextRef names the configured API context without exposing its tailnet.
func apiContextRef(env *registry.Env) (string, error) {
	client, err := env.RequireAPI()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte("tailkeeper security context\x00" + client.Tailnet()))
	return "ctx-" + hex.EncodeToString(sum[:8]), nil
}

// securityRun is one collection in progress.
type securityRun struct {
	env   *registry.Env
	scope security.Scope
	ref   string
	snap  security.Snapshot
	self  string // this node's ID, once local_status has named it and the tailnet has been shown to hold it
	// list is the device list this run read; it is nil until the API source has read one, and
	// stays nil if that source failed.
	list    *deviceList
	results []sourceResult
	// required is the features a rule requires, each once, in name order.
	required []string
	last     time.Time // the latest reading of the clock, so that the times of a run never go back
}

// sourceResult is how one source ended.
type sourceResult struct {
	source            security.CollectionSource
	outcome           security.CollectionOutcome
	code              string
	observed, dropped int
}

// now is the time to write into the snapshot and its evidence: the surface's clock, which a
// test can fix. It never runs backward within a run. A wall clock that steps back (a time
// correction) would put a fact's acquisition after the snapshot's observation, and the
// snapshot would fail its own validation; the reading is held at the latest one instead.
// Durations are not taken from it: see read.
func (r *securityRun) now() time.Time {
	t := r.env.Clock().UTC().Round(0)
	if t.Before(r.last) {
		t = r.last
	}
	r.last = t
	return t
}

func (r *securityRun) factCount() int {
	return len(r.snap.Versions) + len(r.snap.Platforms) + len(r.snap.Features)
}

// read asks one source: its attempt is recorded first, and a source that cannot be asked is
// recorded as skipped. It returns an error only when a record cannot be written.
func (r *securityRun) read(ctx, bctx context.Context, src securitySource) error {
	if reason := r.skipReason(ctx, bctx, src.name); reason != "" {
		return r.finish(ctx, sourceResult{source: src.name, outcome: security.OutcomeSkipped, code: reason}, 0)
	}
	if err := r.record(ctx, security.CollectionEvent{Scope: r.scope, Source: src.name, Phase: security.PhaseAttempt}); err != nil {
		return err
	}
	// The duration comes from a monotonic clock, which a step of the wall clock cannot make
	// negative, and not from the clock that timestamps the facts.
	begin := time.Now()
	observed, dropped, err := r.fetch(bctx, src)
	res := sourceResult{source: src.name, observed: observed, dropped: dropped}
	res.outcome, res.code = r.classify(ctx, bctx, err, dropped)
	return r.finish(ctx, res, time.Since(begin))
}

// skipReason says why a source is not asked, or "" when it is.
func (r *securityRun) skipReason(ctx, bctx context.Context, src security.CollectionSource) string {
	switch {
	case ctx.Err() != nil:
		return security.SkipCancel
	case bctx.Err() != nil:
		return security.SkipBudget
	case src != security.SourceAPIDevices && src != security.SourceLocalStatus && r.self == "":
		return security.SkipIdentity
	}
	return ""
}

// classify turns the end of a source into its outcome: the caller's cancellation and the
// budget's end are told apart from a failure, and a failure is named by the program's own
// error code, never by the text the source gave.
func (r *securityRun) classify(ctx, bctx context.Context, err error, dropped int) (security.CollectionOutcome, string) {
	switch {
	case err == nil && dropped > 0:
		return security.OutcomeTruncated, ""
	case err == nil:
		return security.OutcomeOK, ""
	case ctx.Err() != nil:
		return security.OutcomeCancelled, ""
	case bctx.Err() != nil:
		return security.OutcomeTimeout, ""
	}
	return security.OutcomeError, string(tkerr.From(err).Code)
}

// finish records the outcome of a source and keeps it for the coverage.
func (r *securityRun) finish(ctx context.Context, res sourceResult, took time.Duration) error {
	ev := security.CollectionEvent{Scope: r.scope, Source: res.source, Phase: security.PhaseOutcome, Outcome: res.outcome,
		Code: res.code, Observed: security.SaturateCount(res.observed), Dropped: security.SaturateCount(res.dropped), Millis: took.Milliseconds()}
	if err := r.record(ctx, ev); err != nil {
		return err
	}
	r.results = append(r.results, res)
	return nil
}

// record writes one event through the surface's required audit path. It does not give up
// when the caller has cancelled: the record of a cancelled source is the one that matters.
func (r *securityRun) record(ctx context.Context, ev security.CollectionEvent) error {
	return r.env.RecordObservation(context.WithoutCancel(ctx), ev)
}

// fetch asks one source and puts what it gave into the snapshot. A source that fails adds
// nothing.
func (r *securityRun) fetch(ctx context.Context, src securitySource) (observed, dropped int, err error) {
	switch src.name {
	case security.SourceAPIDevices:
		return r.fetchDevices(ctx)
	case security.SourceLocalStatus:
		observed, err = r.fetchStatus(ctx, src)
	case security.SourceLocalVersion:
		observed, err = r.fetchVersion(ctx, src)
	default:
		observed, err = r.fetchPrefs(ctx, src)
	}
	return observed, 0, err
}

// ---- the API device list --------------------------------------------------------------

// observedDevice is the part of the API's Device that a collection reads, with the presence
// of each decision field kept: a boolean the API left out is a nil pointer, not false. The
// public Device keeps its plain booleans; this is read from the same bytes for the snapshot
// only. Authorized and BlocksIncomingConnections are kept for the rules that will read them;
// no fact is made of them until a rule names one.
type observedDevice struct {
	NodeID                    string `json:"nodeId"`
	ClientVersion             string `json:"clientVersion"`
	OS                        string `json:"os"`
	LastSeen                  string `json:"lastSeen"`
	ConnectedToControl        *bool  `json:"connectedToControl"`
	Authorized                *bool  `json:"authorized"`
	BlocksIncomingConnections *bool  `json:"blocksIncomingConnections"`
	SSHEnabled                *bool  `json:"sshEnabled"`
}

// facts is how many facts the device adds to a snapshot: one for each decision field the API
// gave, and one (a version fact with no value) for a device that gave none, so that the
// device is still named and the matcher says why it cannot judge it.
func (d observedDevice) facts() int {
	n := 0
	for _, present := range []bool{d.ClientVersion != "", d.OS != "", d.ConnectedToControl != nil, d.SSHEnabled != nil} {
		if present {
			n++
		}
	}
	return max(n, 1)
}

// assetOK says whether id can name a device in a snapshot.
func assetOK(id string) bool { return id != "" && len(id) <= 128 && security.ValidText(id) }

// fetchDevices reads the device list with fields=all (sshEnabled is returned only then; a
// device without it has no fact, it is not off), as a stream (security_devices.go): rows are
// decoded only while the snapshot has room for their facts, and every row is counted. Devices
// beyond the snapshot's bound, which are the later ones in the API's order, and devices
// without a usable node ID are dropped and counted. A node ID the list gives more than once
// is not believed on any of its rows: two rows for one device may disagree, and which of them
// comes first is not evidence, so every row of that ID is dropped and counted, and the device
// is named only by a fact that says why it cannot be judged (addRepeated).
func (r *securityRun) fetchDevices(ctx context.Context) (observed, dropped int, err error) {
	c, err := r.env.RequireAPI()
	if err != nil {
		return 0, 0, err
	}
	feed := &deviceFeed{room: security.MaxObservations - localFactReserve - r.factCount()}
	capped := c.WithMaxBody(securityBodyMax)
	if err := capped.Get(ctx, c.TailnetPath("/devices"), url.Values{"fields": {"all"}}, feed); err != nil {
		if errors.Is(err, api.ErrBodyTooLarge) {
			return 0, 0, tooLargeError(capped.MaxBody())
		}
		return 0, 0, err
	}
	acquired := r.now()
	r.list = feed.list
	for _, d := range r.list.kept {
		r.addDevice(d, acquired)
	}
	r.addRepeated(acquired)
	observed = len(r.list.kept)
	r.list.kept = nil
	return observed, r.list.dropped, nil
}

// tooLargeError is the error of a device list over the body limit that applied, which is the
// lower of securityBodyMax and the surface's own. Its text is fixed and holds nothing of the
// body.
func tooLargeError(limit int64) *tkerr.Error {
	return tkerr.New(tkerr.ResponseTooLarge, fmt.Sprintf("the device list is longer than the %d bytes a collection reads here", limit),
		"the command line reads up to 32 MiB of device list and an MCP call 8 MiB, so run the scan from the command line; a tailnet this large is a gap in the report, not a clean result")
}

// addRepeated names each node ID the list gave more than once, and each whose row gave a
// decision field twice, with a version fact that has no value and says why, while the
// snapshot has room. None of its rows is believed, but the device is still judged: the
// matcher gives it evidence_error, an explicit unknown, rather than leaving it out of the
// findings (ruling Q1). Its rows stay counted as not observed.
func (r *securityRun) addRepeated(acquired time.Time) {
	why := make(map[string]string, len(r.list.repeated)+len(r.list.doubled))
	for id := range r.list.doubled {
		why[id] = "the API gave a field of this device more than once"
	}
	for id := range r.list.repeated {
		why[id] = "the API listed this node ID more than once"
	}
	for _, id := range slices.Sorted(maps.Keys(why)) {
		if r.factCount() >= security.MaxObservations-localFactReserve {
			return
		}
		e := r.evidence(security.OriginAPI, id, acquired)
		e.Freshness, e.Error = security.FreshnessUnknown, why[id]
		r.snap.Versions = append(r.snap.Versions, security.VersionFact{Role: security.VersionAPIReported,
			Channel: security.ChannelUnknown, Name: "client", Evidence: e})
	}
}

// addDevice adds the facts of one API device. Every fact names the device, keeps the raw
// strings the API gave, and takes the device's own lastSeen as its observation time.
func (r *securityRun) addDevice(d observedDevice, acquired time.Time) {
	base := r.evidence(security.OriginAPI, d.NodeID, acquired)
	base.ObservedAt, base.Freshness, base.Error = observationOf(d.LastSeen, acquired)
	if d.ClientVersion != "" {
		e, v := textFact(base, d.ClientVersion)
		r.snap.Versions = append(r.snap.Versions, security.VersionFact{Role: security.VersionAPIReported,
			Channel: security.ChannelOf(d.ClientVersion), Name: "client", Value: v, Evidence: e})
	}
	if d.OS != "" {
		e, v := textFact(base, d.OS)
		r.snap.Platforms = append(r.snap.Platforms, security.PlatformFact{OS: deref(v), Evidence: e})
	}
	r.addFeature(security.FeatureConnectedToControl, d.ConnectedToControl, base)
	r.addFeature(security.FeatureTailscaleSSH, d.SSHEnabled, base)
	if d.ClientVersion == "" && d.OS == "" && d.ConnectedToControl == nil && d.SSHEnabled == nil {
		// The API named the device and said nothing the matcher reads. A device with no fact
		// is not in the snapshot, and so would not be judged: it would be counted as observed
		// and never appear in a finding. A version fact with no value names it, and the
		// matcher gives it no_version (or evidence_error, if the device's lastSeen is no good).
		r.snap.Versions = append(r.snap.Versions, security.VersionFact{Role: security.VersionAPIReported,
			Channel: security.ChannelUnknown, Name: "client", Evidence: cloneEvidence(base)})
	}
}

// addFeature adds a feature fact when the source gave a value, true or false; a field the
// source left out gives no fact.
func (r *securityRun) addFeature(name string, value *bool, e security.EvidenceRef) {
	if value != nil {
		v := *value
		r.snap.Features = append(r.snap.Features, security.FeatureFact{Name: name, Value: &v, Evidence: cloneEvidence(e)})
	}
}

// cloneEvidence copies the evidence with its own observation time, so that no two facts share
// a pointer.
func cloneEvidence(e security.EvidenceRef) security.EvidenceRef {
	if e.ObservedAt != nil {
		t := *e.ObservedAt
		e.ObservedAt = &t
	}
	return e
}

func (r *securityRun) evidence(origin security.Origin, asset string, acquired time.Time) security.EvidenceRef {
	return security.EvidenceRef{Context: r.ref, Asset: asset, Scope: r.scope, Origin: origin, AcquiredAt: acquired, Freshness: security.FreshnessFresh}
}

// minObserved is the earliest time a report may hold (the schema's floor); a lastSeen before
// it is the API's way of saying never.
var minObserved = time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)

// observationOf is the source's own time of a device's facts: its lastSeen. A lastSeen that
// is missing, not a time or before the schema's floor leaves the time unknown, and the
// evidence says so, so no fact rests on it. One later than the acquisition (the device's
// clock is ahead of ours, or ours behind) is clamped to the acquisition and says so: the fact
// is then unusable, and the one skewed device cannot make the snapshot invalid for the rest.
func observationOf(lastSeen string, acquired time.Time) (*time.Time, security.Freshness, string) {
	t, err := time.Parse(time.RFC3339Nano, lastSeen)
	switch {
	case lastSeen == "":
		return nil, security.FreshnessUnknown, "the API gave no lastSeen for this device"
	case err != nil || t.Before(minObserved):
		return nil, security.FreshnessUnknown, "the API gave a lastSeen that is not a usable time"
	}
	t = t.UTC()
	if t.After(acquired) {
		return &acquired, security.FreshnessFresh, "lastSeen is later than the time of collection (clock skew); clamped to it"
	}
	return &t, security.FreshnessFresh, ""
}

// textFact returns the evidence and the value for a raw string a source gave. A string the
// report cannot hold (a control or invisible character, too long) is not kept: the fact stays,
// with no value and an error in its evidence, so that the device is still named and the fact
// is unusable. An error already on the evidence is kept.
func textFact(e security.EvidenceRef, raw string) (security.EvidenceRef, *string) {
	e = cloneEvidence(e)
	if security.ValidText(raw) {
		return e, &raw
	}
	if e.Error == "" {
		e.Error = "the source gave text that a report cannot hold"
	}
	return e, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ---- this node ------------------------------------------------------------------------

// fetchStatus reads this node's status: it names the node, and gives its operating system.
// Peers are not asked for, and a local collection claims nothing about them. In a fleet
// collection the node joins the evidence only if its ID is one the API listed for the
// tailnet (docs/design.md, the local tools): otherwise it is a node of another tailnet, or
// the list is missing, and the source ends with local_tailnet_mismatch with no fact kept.
func (r *securityRun) fetchStatus(ctx context.Context, src securitySource) (int, error) {
	var s cliStatus
	args := src.args()
	if err := runJSON(ctx, r.env, &s, []string{"BackendState"}, args...); err != nil {
		return 0, err
	}
	if s.Self == nil || !assetOK(s.Self.ID) {
		return 0, unrecognized(args, "no usable Self.ID")
	}
	if r.scope == security.ScopeFleet && (r.list == nil || !r.list.has(s.Self.ID)) {
		// The daemon may have been pointed at another tailnet (fast user switching), or the
		// list that would show it is in this one was not read. Nothing it says is used, and
		// the sources that ask about this node are not asked.
		return 0, tkerr.New(tkerr.LocalTailnetMismatch, "this node's ID is not among the devices of the tailnet the API read", "")
	}
	r.self = s.Self.ID
	if s.Self.OS == "" {
		return 0, nil
	}
	e, v := textFact(r.evidence(security.OriginLocal, r.self, r.now()), s.Self.OS)
	r.snap.Platforms = append(r.snap.Platforms, security.PlatformFact{OS: deref(v), Evidence: e})
	return 1, nil
}

// fetchVersion reads the versions of this node's CLI and daemon. The daemon's is the one that
// establishes what runs; the CLI's is only the CLI's. Neither carries a source time.
func (r *securityRun) fetchVersion(ctx context.Context, src securitySource) (int, error) {
	args := src.args()
	stdout, _, err := run(ctx, r.env, localTimeout, args...)
	if err != nil {
		return 0, err
	}
	var v struct {
		Long       string `json:"long"`
		DaemonLong string `json:"daemonLong"`
	}
	if err := decodeCLI(stdout, &v, []string{"long"}, args); err != nil {
		return 0, err
	}
	acquired := r.now()
	n := 0
	for _, f := range []struct {
		raw  string
		role security.VersionRole
	}{{v.Long, security.VersionLocalCLI}, {v.DaemonLong, security.VersionRunningDaemon}} {
		if f.raw == "" {
			continue
		}
		e, val := textFact(r.evidence(security.OriginLocal, r.self, acquired), f.raw)
		r.snap.Versions = append(r.snap.Versions, security.VersionFact{Role: f.role, Channel: security.ChannelOf(f.raw), Name: "client", Value: val, Evidence: e})
		n++
	}
	return n, nil
}

// fetchPrefs reads this node's preferences for Tailscale SSH. A preference that is missing
// gives no fact; one that is not a boolean is an unrecognised output.
func (r *securityRun) fetchPrefs(ctx context.Context, src securitySource) (int, error) {
	args := src.args()
	var prefs map[string]any
	if err := runJSON(ctx, r.env, &prefs, nil, args...); err != nil {
		return 0, err
	}
	known := false
	for _, k := range prefKeys {
		if _, ok := prefs[k]; ok {
			known = true
			break
		}
	}
	if !known {
		return 0, unrecognized(args, "no known preference")
	}
	raw, present := prefs["ssh"]
	if !present {
		return 0, nil
	}
	on, ok := raw.(bool)
	if !ok {
		return 0, unrecognized(args, "an ssh preference that is not a boolean")
	}
	r.addFeature(security.FeatureTailscaleSSH, &on, r.evidence(security.OriginLocal, r.self, r.now()))
	return 1, nil
}

// ---- coverage -------------------------------------------------------------------------

// collectedFeatures are the features some source of a collection gives a fact for. The API's
// connectedToControl and sshEnabled and this node's ssh preference are all there is: a rule
// that requires any other feature asks for something no source observes today.
var collectedFeatures = map[string]bool{security.FeatureConnectedToControl: true, security.FeatureTailscaleSSH: true}

// namedFeatures are the feature names the explanation of a coverage row may spell out: the
// constants of the program. A name outside them, from a catalog, is counted and not shown.
var namedFeatures = map[string]bool{security.FeatureConnectedToControl: true, security.FeatureTailscaleSSH: true,
	security.FeatureSSHForwardingAllowed: true, security.FeatureServeUnixBackend: true, security.FeatureServeTLSMultiMount: true}

// requiredSet is the features a rule requires, each once, in name order.
func requiredSet(names []string) []string {
	out := slices.Clone(names)
	slices.Sort(out)
	return slices.Compact(out)
}

// coverage has one row for each dimension the collection fed. A row is complete only if every
// source that feeds it was read completely and the facts it should hold are there: a version
// of the running daemon or the API for each device, and each feature a rule requires, from a
// source that gives it, for each device. Its explanation is made of fixed words, the
// program's error codes, names of the program's own features and counts, never of text a
// source gave.
func (r *securityRun) coverage() []security.Coverage {
	devices := r.devices()
	feeds := []struct {
		dimension security.CoverageDimension
		sources   []security.CollectionSource
		gaps      []string
	}{
		{security.CoverageVersions, []security.CollectionSource{security.SourceAPIDevices, security.SourceLocalStatus, security.SourceLocalVersion}, r.versionGaps(devices)},
		{security.CoverageFeatures, []security.CollectionSource{security.SourceAPIDevices, security.SourceLocalStatus, security.SourceLocalPrefs}, r.featureGaps(devices)},
	}
	rows := make([]security.Coverage, 0, len(feeds))
	for _, f := range feeds {
		row := security.Coverage{Target: security.CoverageTarget{Dimension: f.dimension, Scope: r.scope}, Context: r.ref,
			Source: securityCoverageSource, Status: security.ReportComplete}
		var causes []string
		for _, res := range r.results {
			if res.outcome != security.OutcomeOK && slices.Contains(f.sources, res.source) {
				causes = append(causes, res.describe())
			}
		}
		causes = append(causes, f.gaps...)
		if len(causes) > 0 {
			row.Status, row.Explanation = security.ReportPartial, strings.Join(causes, "; ")
		}
		rows = append(rows, row)
	}
	return rows
}

// devices lists the devices of the snapshot, and this node, in ID order: those the coverage
// speaks of. A node whose sources gave no fact is a device all the same.
func (r *securityRun) devices() []string {
	set := map[string]bool{}
	if r.self != "" {
		set[r.self] = true
	}
	for _, v := range r.snap.Versions {
		set[v.Evidence.Asset] = true
	}
	for _, p := range r.snap.Platforms {
		set[p.Evidence.Asset] = true
	}
	for _, f := range r.snap.Features {
		set[f.Evidence.Asset] = true
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	slices.Sort(out)
	return out
}

// versionGaps says what keeps the versions row from being complete although every source
// ended well: a device with no running-daemon or API version that carries a value and no
// error. A CLI version alone does not do (it is not what runs), and neither does a placeholder.
func (r *securityRun) versionGaps(devices []string) []string {
	if len(devices) == 0 {
		return []string{"no device was observed"}
	}
	have := map[string]bool{}
	for _, v := range r.snap.Versions {
		if (v.Role == security.VersionAPIReported || v.Role == security.VersionRunningDaemon) && v.Value != nil && v.Evidence.Error == "" {
			have[v.Evidence.Asset] = true
		}
	}
	if missing := countMissing(devices, have); missing > 0 {
		return []string{fmt.Sprintf("%d of %d devices have no running-daemon or API version", missing, len(devices))}
	}
	return nil
}

// featureGaps says what keeps the features row from being complete although every source
// ended well: a feature a rule requires that no source gives, and a feature a source gives
// but gave no value for some device. A feature the API leaves out is not off, it is unknown.
func (r *securityRun) featureGaps(devices []string) []string {
	if len(devices) == 0 {
		return []string{"no device was observed"}
	}
	var gaps, nowhere []string
	unknown := 0
	for _, name := range r.required {
		switch {
		case !collectedFeatures[name] && namedFeatures[name]:
			nowhere = append(nowhere, name)
		case !collectedFeatures[name]:
			unknown++
		default:
			have := map[string]bool{}
			for _, f := range r.snap.Features {
				if f.Name == name && f.Value != nil && f.Evidence.Error == "" {
					have[f.Evidence.Asset] = true
				}
			}
			if missing := countMissing(devices, have); missing > 0 {
				gaps = append(gaps, fmt.Sprintf("%s: no value for %d of %d devices", name, missing, len(devices)))
			}
		}
	}
	if len(nowhere) > 0 {
		gaps = append(gaps, "no source gives the features "+strings.Join(nowhere, ", "))
	}
	if unknown > 0 {
		gaps = append(gaps, fmt.Sprintf("%d required features that this program does not know", unknown))
	}
	return gaps
}

// countMissing counts the devices not in have.
func countMissing(devices []string, have map[string]bool) int {
	n := 0
	for _, d := range devices {
		if !have[d] {
			n++
		}
	}
	return n
}

var sourceLabels = map[security.CollectionSource]string{
	security.SourceAPIDevices: "API device list", security.SourceLocalStatus: "local status",
	security.SourceLocalVersion: "local version", security.SourceLocalPrefs: "local preferences",
}

// describe says how a source that was not read completely ended.
func (s sourceResult) describe() string {
	text := sourceLabels[s.source] + ": " + string(s.outcome)
	if s.code != "" {
		text += " (" + s.code + ")"
	}
	if s.dropped > 0 {
		text += fmt.Sprintf(" (%d of %d items not observed)", s.dropped, s.observed+s.dropped)
		if s.source == security.SourceAPIDevices {
			// The cut is where a bounded stream ends, not a choice: nothing sorted the list.
			text += "; the devices kept are the first the API listed, not sorted, so which are left out follows its order"
		}
	}
	return text
}
