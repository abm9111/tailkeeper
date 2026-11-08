// Package security defines the pure, versioned assessment data contracts.
package security

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"time"
	"unicode/utf8"
)

const (
	SchemaVersion     = 1
	MaxFindings       = 10000
	MaxTextBytes      = 4096
	MaxObservations   = 10000
	MaxCatalogRecords = 1000
	MaxRanges         = 32
)

// ContextLocalOnly identifies a snapshot not bound to a known tailnet.
const ContextLocalOnly = "ctx-local-only"

type Scope string

const (
	ScopeFleet Scope = "fleet"
	ScopeLocal Scope = "local"
)

type Origin string

const (
	OriginAPI       Origin = "api"
	OriginLocal     Origin = "local"
	OriginCollector Origin = "collector"
	OriginOperator  Origin = "operator"
	OriginVendor    Origin = "vendor"
	OriginDerived   Origin = "derived"
)

type Freshness string

const (
	FreshnessUnknown Freshness = "unknown"
	FreshnessFresh   Freshness = "fresh"
	FreshnessStale   Freshness = "stale"
)

type ReportStatus string

const (
	ReportComplete ReportStatus = "complete"
	ReportPartial  ReportStatus = "partial"
)

// CoverageNotRequested is a status of a coverage row, never of a report. It says that the
// report did not ask for the row's target (for instance intent, when no intent set is
// configured), so that the absence is stated and not silent. It is valid only for a target
// that is not in the report's RequestedCoverage, and needs a source, an explanation and no
// counts; it never keeps a report from being complete, and it is no answer to a requested
// target (ValidateReport enforces each).
const CoverageNotRequested ReportStatus = "not_requested"

type Priority string

const (
	PriorityUnknown Priority = "unknown"
	PriorityLow     Priority = "low"
	PriorityMedium  Priority = "medium"
	PriorityHigh    Priority = "high"
	PriorityUrgent  Priority = "urgent"
)

type Severity string

const (
	SeverityUnknown  Severity = "unknown"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type EvidenceState string

const (
	EvidenceObserved EvidenceState = "observed"
	EvidenceUnknown  EvidenceState = "unknown"
	EvidenceStale    EvidenceState = "stale"
	EvidenceAbsent   EvidenceState = "absent"
)

type Confidence string

const (
	ConfidenceUnknown      Confidence = "unknown"
	ConfidenceReported     Confidence = "reported"
	ConfidenceCorroborated Confidence = "corroborated"
	ConfidenceDerived      Confidence = "derived"
)

type Applicability string

const (
	ApplicabilityAffected    Applicability = "affected"
	ApplicabilityPotential   Applicability = "potentially_affected"
	ApplicabilityNotAffected Applicability = "not_affected"
	ApplicabilityUnknown     Applicability = "unknown"
)

// UnknownReason is the closed set of reasons a finding is unknown or only potentially
// affected. A finding that is affected or not affected carries none.
type UnknownReason string

const (
	// ReasonCatalogExpired: the catalog is not fresh, so it cannot clear a device.
	ReasonCatalogExpired UnknownReason = "catalog_expired"
	// ReasonReviewExpired: the rule's review is not fresh, so it cannot clear a device.
	ReasonReviewExpired UnknownReason = "review_expired"
	// ReasonReviewPending: the rule has not been approved.
	ReasonReviewPending UnknownReason = "review_pending"
	// ReasonNoVersion: no version fact of the rule's component carries a value of a role and
	// origin the rule can use for the device (or none names the component at all).
	ReasonNoVersion UnknownReason = "no_version"
	// ReasonEvidenceError: version facts exist but none is usable, and at least one carries an error.
	ReasonEvidenceError UnknownReason = "evidence_error"
	// ReasonStaleEvidence: version facts exist but none is usable (not fresh, or older than the
	// 30 minutes evidence may be), and none carries an error.
	ReasonStaleEvidence UnknownReason = "stale_evidence"
	// ReasonVersionConflict: usable version facts disagree.
	ReasonVersionConflict UnknownReason = "version_conflict"
	// ReasonUnrecognisedBuild: a version string is outside the release grammar.
	ReasonUnrecognisedBuild UnknownReason = "unrecognised_build"
	// ReasonChannelUnknown: the version fact does not say whether it is a stable release.
	ReasonChannelUnknown UnknownReason = "channel_unknown"
	// ReasonUnstableTrack: the release is on the unstable track (an odd minor), where ranges do not apply.
	ReasonUnstableTrack UnknownReason = "unstable_track"
	// ReasonOSUnrecognised: the reported operating system is outside the vocabulary.
	ReasonOSUnrecognised UnknownReason = "os_unrecognised"
	// ReasonOSUnknown: no usable operating-system fact exists for a rule that names one.
	ReasonOSUnknown UnknownReason = "os_unknown"
	// ReasonFeatureUnknown: a required feature has no usable fact.
	ReasonFeatureUnknown UnknownReason = "feature_unknown"
	// ReasonRuntimeUnobserved: only reports of the version, not the running daemon, exist.
	ReasonRuntimeUnobserved UnknownReason = "runtime_unobserved"
)

// unknownReasons lists every UnknownReason, in the order above. It is the closed set.
var unknownReasons = [...]UnknownReason{
	ReasonCatalogExpired, ReasonReviewExpired, ReasonReviewPending, ReasonNoVersion, ReasonEvidenceError,
	ReasonStaleEvidence, ReasonVersionConflict, ReasonUnrecognisedBuild, ReasonChannelUnknown,
	ReasonUnstableTrack, ReasonOSUnrecognised, ReasonOSUnknown, ReasonFeatureUnknown, ReasonRuntimeUnobserved,
}

type ReviewState string

const (
	ReviewPending   ReviewState = "pending"
	ReviewApproved  ReviewState = "approved"
	ReviewWithdrawn ReviewState = "withdrawn"
)

type EventKind string

const (
	EventOpened   EventKind = "opened"
	EventResolved EventKind = "resolved"
	EventChanged  EventKind = "changed"
	EventReopened EventKind = "reopened"
)

type LifecycleState string

const (
	LifecycleOpen       LifecycleState = "open"
	LifecycleResolved   LifecycleState = "resolved"
	LifecycleSuppressed LifecycleState = "suppressed"
)

type EvidenceRef struct {
	Context    string     `json:"context"`
	Asset      string     `json:"asset,omitempty"`
	Scope      Scope      `json:"scope,omitempty"`
	Origin     Origin     `json:"origin"`
	AcquiredAt time.Time  `json:"acquired_at"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
	Freshness  Freshness  `json:"freshness"`
	Error      string     `json:"error,omitempty"`
}
type VersionRole string

const (
	VersionAPIReported   VersionRole = "api_reported"
	VersionLocalCLI      VersionRole = "local_cli"
	VersionRunningDaemon VersionRole = "running_daemon"
)

type VersionChannel string

const (
	ChannelStable   VersionChannel = "stable"
	ChannelUnstable VersionChannel = "unstable"
	ChannelUnknown  VersionChannel = "unknown"
)

type VersionFact struct {
	Role     VersionRole    `json:"role"`
	Channel  VersionChannel `json:"channel"`
	Name     string         `json:"name"`
	Value    *string        `json:"value,omitempty"`
	Evidence EvidenceRef    `json:"evidence"`
}

// PlatformFact reports an operating system in the spelling its source used (see
// NormaliseOS). Variant is information for the reader: matching ignores it.
type PlatformFact struct {
	OS       string      `json:"os,omitempty"`
	Variant  string      `json:"variant,omitempty"`
	Evidence EvidenceRef `json:"evidence"`
}
type FeatureFact struct {
	Name     string      `json:"name"`
	Value    *bool       `json:"value,omitempty"`
	Evidence EvidenceRef `json:"evidence"`
}

// FeatureConnectedToControl names the feature fact that says whether a device is connected
// to Tailscale's control plane. The matcher reads it from a fact of origin api only: while
// the same device has a usable one that is true, the version the API reports for that device
// stands in for the running daemon's (decisions R9 and D1), and so do the features it
// reports (D5). It is the guard and is never itself a feature a rule requires.
const FeatureConnectedToControl = "connected_to_control"

// The feature names that the rules TS-2026-014 to TS-2026-017 require. A rule names a
// feature by this spelling, so it is part of the catalog format. A rule's feature can clear
// a device or confirm it only through a fact of that name, from an origin the rule accepts;
// with no such fact the feature is unknown (feature_unknown). The collector emits FeatureTailscaleSSH
// and no other of these: the rest are not observable today.
const (
	// FeatureTailscaleSSH: the device runs Tailscale SSH.
	FeatureTailscaleSSH = "tailscale_ssh"
	// FeatureSSHForwardingAllowed: the policy allows forwarding over Tailscale SSH to the device.
	FeatureSSHForwardingAllowed = "ssh_forwarding_allowed"
	// FeatureServeUnixBackend: the device serves a backend that is a Unix socket.
	FeatureServeUnixBackend = "serve_unix_backend"
	// FeatureServeTLSMultiMount: the device serves with TLS and has two or more mounts.
	FeatureServeTLSMultiMount = "serve_tls_multi_mount"
)

type PolicyFact struct {
	Name     string      `json:"name"`
	Value    *string     `json:"value,omitempty"`
	Evidence EvidenceRef `json:"evidence"`
}
type VersionRange struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// AdvisoryRecord is one reviewed rule. OS, when set, is a canonical operating-system name
// (linux, windows, macos, ios, tvos, android, freebsd, openbsd, illumos, solaris, plan9, js,
// aix, dragonfly, netbsd, tamago or wasip1); a rule cannot name an OS variant or a reported
// spelling such as macOS or darwin. Each range bound is a bare release with an even minor.
type AdvisoryRecord struct {
	ID               string         `json:"id"`
	Revision         string         `json:"revision"`
	Component        string         `json:"component"`
	VersionRole      VersionRole    `json:"version_role"`
	OS               string         `json:"os,omitempty"`
	Ranges           []VersionRange `json:"ranges,omitempty"`
	RequiredFeatures []string       `json:"required_features,omitempty"`
	Source           string         `json:"source"`
	Severity         Severity       `json:"severity"`
	PublishedAt      *time.Time     `json:"published_at,omitempty"`
	UpdatedAt        *time.Time     `json:"updated_at,omitempty"`
	ReviewedAt       time.Time      `json:"reviewed_at"`
	ReviewExpiresAt  time.Time      `json:"review_expires_at"`
	SourceCheckedAt  *time.Time     `json:"source_checked_at,omitempty"`
	ReviewState      ReviewState    `json:"review_state"`
	Mitigation       string         `json:"mitigation,omitempty"`
}

// Catalog is a set of reviewed rules. Digest is set by the decoder, never read from the
// input: it is the SHA-256 of the exact input bytes in lowercase hex. It is not a content
// identity (the same catalog spelled with other whitespace or key order has another
// digest) and it does not authenticate the input.
type Catalog struct {
	SchemaVersion int              `json:"schema_version"`
	Revision      uint64           `json:"revision"`
	IssuedAt      time.Time        `json:"issued_at"`
	ExpiresAt     time.Time        `json:"expires_at"`
	Digest        string           `json:"-"`
	Records       []AdvisoryRecord `json:"records"`
}
type Snapshot struct {
	Context    string         `json:"context"`
	KeyEpoch   string         `json:"key_epoch,omitempty"`
	Scope      Scope          `json:"scope,omitempty"`
	ObservedAt time.Time      `json:"observed_at"`
	Versions   []VersionFact  `json:"versions,omitempty"`
	Platforms  []PlatformFact `json:"platforms,omitempty"`
	Features   []FeatureFact  `json:"features,omitempty"`
	Policies   []PolicyFact   `json:"policies,omitempty"`
}
type Finding struct {
	ID             string        `json:"id"`
	Context        string        `json:"context"`
	Asset          string        `json:"asset,omitempty"`
	RuleID         string        `json:"rule_id"`
	RuleRevision   string        `json:"rule_revision"`
	EvidenceState  EvidenceState `json:"evidence_state"`
	Applicability  Applicability `json:"applicability"`
	Reason         UnknownReason `json:"reason,omitempty"`
	Confidence     Confidence    `json:"confidence"`
	Requirements   []string      `json:"requirements,omitempty"`
	Verification   []string      `json:"verification,omitempty"`
	Remediation    []string      `json:"remediation,omitempty"`
	SourceSeverity Severity      `json:"source_severity"`
	Priority       Priority      `json:"priority"`
	Explanation    string        `json:"explanation"`
	Evidence       []EvidenceRef `json:"evidence,omitempty"`
}

// FindingID is the per-report identity of one rule evaluated for one asset: the lowercase
// hex SHA-256 of "len:value" for the context, the scope, the asset and the rule ID, in that
// order, with len the byte length of the value. The length prefixes make the encoding
// unambiguous, so no two different tuples share an input. The rule revision is not part of
// it: a revised rule changes the finding, not its identity. This is the one definition:
// the matcher that emits a finding and the validator that checks it must both call it.
//
// The identity is unkeyed. It is not a privacy-preserving pseudonym, and a later output
// boundary must not show it or the asset it hashes.
func FindingID(context string, scope Scope, asset, ruleID string) string {
	var in []byte
	for _, field := range [...]string{context, string(scope), asset, ruleID} {
		in = strconv.AppendInt(in, int64(len(field)), 10)
		in = append(in, ':')
		in = append(in, field...)
	}
	sum := sha256.Sum256(in)
	return hex.EncodeToString(sum[:])
}

type CoverageDimension string

const (
	CoveragePolicy   CoverageDimension = "policy"
	CoverageVersions CoverageDimension = "versions"
	CoverageFeatures CoverageDimension = "features"
	CoverageIntent   CoverageDimension = "intent"
	CoverageCatalog  CoverageDimension = "catalog"
)

type CoverageTarget struct {
	Dimension CoverageDimension `json:"dimension"`
	Scope     Scope             `json:"scope"`
	Asset     string            `json:"asset,omitempty"`
}

// CoverageCounts says what a coverage row evaluated. The matcher always fills it on its
// catalog row: Rules counts the rules evaluated (approved and pending), Withdrawn the rules
// it skipped, Assets the devices, and Findings, Unknown and Potential its results. A count of
// zero is a stated zero, not an absent one.
type CoverageCounts struct {
	Rules     int `json:"rules"`
	Withdrawn int `json:"withdrawn"`
	Assets    int `json:"assets"`
	Findings  int `json:"findings"`
	Unknown   int `json:"unknown"`
	Potential int `json:"potential"`
}
type Coverage struct {
	Target      CoverageTarget  `json:"target"`
	Context     string          `json:"context"`
	Source      string          `json:"source"`
	Status      ReportStatus    `json:"status"`
	Explanation string          `json:"explanation,omitempty"`
	Counts      *CoverageCounts `json:"counts,omitempty"`
}
type Report struct {
	SchemaVersion     int              `json:"schema_version"`
	Context           string           `json:"context"`
	KeyEpoch          string           `json:"key_epoch,omitempty"`
	GeneratedAt       time.Time        `json:"generated_at"`
	Status            ReportStatus     `json:"status"`
	TotalFindings     int              `json:"total_findings"`
	Truncated         bool             `json:"truncated"`
	Snapshot          Snapshot         `json:"snapshot"`
	Findings          []Finding        `json:"findings,omitempty"`
	RequestedCoverage []CoverageTarget `json:"requested_coverage"`
	Coverage          []Coverage       `json:"coverage,omitempty"`
	IntentDigest      string           `json:"intent_digest,omitempty"`
	IntentRevision    string           `json:"intent_revision,omitempty"`
}

// ScalarKind identifies the active member of a Scalar.
type ScalarKind string

const (
	ScalarString ScalarKind = "string"
	ScalarNumber ScalarKind = "number"
	ScalarBool   ScalarKind = "bool"
)

// Scalar retains the JSON scalar type and the original finite number spelling.
// Inactive members must have their zero values.
type Scalar struct {
	Kind   ScalarKind
	String string
	Number string
	Bool   bool
}

func (s *Scalar) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || !utf8.Valid(data) {
		return fmt.Errorf("empty or invalid scalar")
	}
	switch data[0] {
	case '"':
		return s.unmarshalString(data)
	case 't', 'f':
		return s.unmarshalBool(data)
	default:
		return s.unmarshalNumber(data)
	}
}

func (s *Scalar) unmarshalString(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	if len(v) > MaxTextBytes {
		return fmt.Errorf("oversized scalar string")
	}
	*s = Scalar{Kind: ScalarString, String: v}
	return nil
}

func (s *Scalar) unmarshalBool(data []byte) error {
	var v bool
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*s = Scalar{Kind: ScalarBool, Bool: v}
	return nil
}

func (s *Scalar) unmarshalNumber(data []byte) error {
	if len(data) > MaxTextBytes || (data[0] != '-' && (data[0] < '0' || data[0] > '9')) {
		return fmt.Errorf("invalid scalar number")
	}
	var n json.Number
	if err := json.Unmarshal(data, &n); err != nil {
		return fmt.Errorf("invalid scalar: %w", err)
	}
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return fmt.Errorf("invalid finite number")
	}
	*s = Scalar{Kind: ScalarNumber, Number: string(n)}
	return nil
}
func (s Scalar) MarshalJSON() ([]byte, error) {
	switch s.Kind {
	case ScalarString:
		if s.Number != "" || s.Bool || len(s.String) > MaxTextBytes || !utf8.ValidString(s.String) {
			return nil, fmt.Errorf("invalid scalar string")
		}
		return json.Marshal(s.String)
	case ScalarBool:
		if s.String != "" || s.Number != "" {
			return nil, fmt.Errorf("invalid scalar bool")
		}
		return json.Marshal(s.Bool)
	case ScalarNumber:
		if s.String != "" || s.Bool {
			return nil, fmt.Errorf("invalid scalar number")
		}
		var checked Scalar
		if err := checked.UnmarshalJSON([]byte(s.Number)); err != nil || checked.Kind != ScalarNumber {
			return nil, fmt.Errorf("invalid number")
		}
		return []byte(s.Number), nil
	default:
		return nil, fmt.Errorf("invalid scalar kind")
	}
}

type PostureAttributes map[string]Scalar

func (p PostureAttributes) MarshalJSON() ([]byte, error) {
	if len(p) > MaxObservations {
		return nil, fmt.Errorf("oversized posture attributes")
	}
	for key := range p {
		if len(key) > MaxTextBytes || !utf8.ValidString(key) {
			return nil, fmt.Errorf("invalid posture attribute name")
		}
	}
	type attributes PostureAttributes
	return json.Marshal(attributes(p))
}

func (p *PostureAttributes) UnmarshalJSON(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("invalid posture attributes")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return fmt.Errorf("posture attributes must be object")
	}
	result := make(PostureAttributes)
	for d.More() {
		keyToken, err := d.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("invalid attribute key")
		}
		if len(key) > MaxTextBytes || len(result) >= MaxObservations {
			return fmt.Errorf("oversized posture attributes")
		}
		if _, exists := result[key]; exists {
			return fmt.Errorf("duplicate attribute")
		}
		var value Scalar
		if err := d.Decode(&value); err != nil {
			return err
		}
		result[key] = value
	}
	if _, err := d.Token(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing attribute data")
	}
	*p = result
	return nil
}

// NetworkExpectation and SSHExpectation retain the known policy-test fields.
// Adapters must reject unsupported fields rather than silently discard them.
type NetworkExpectation struct {
	ID                      string            `json:"id"`
	Source                  string            `json:"src"`
	Protocol                string            `json:"proto,omitempty"`
	SourcePostureAttributes PostureAttributes `json:"src_posture_attrs,omitempty"`
	Accept                  []string          `json:"accept,omitempty"`
	Deny                    []string          `json:"deny,omitempty"`
}
type SSHExpectation struct {
	ID           string   `json:"id"`
	Source       string   `json:"src"`
	Destinations []string `json:"dst"`
	Accept       []string `json:"accept,omitempty"`
	Deny         []string `json:"deny,omitempty"`
	Check        []string `json:"check,omitempty"`
}
type IntentSet struct {
	SchemaVersion int                  `json:"schema_version"`
	Revision      string               `json:"revision"`
	Digest        string               `json:"digest"`
	Network       []NetworkExpectation `json:"network,omitempty"`
	SSH           []SSHExpectation     `json:"ssh,omitempty"`
}

// CorrectionIntent describes owner-declared targets, without observation metadata.
type CorrectionIntent struct {
	SchemaVersion  int                 `json:"schema_version"`
	ActionAt       time.Time           `json:"action_at"`
	Findings       []CorrectionFinding `json:"findings,omitempty"`
	ExpectationIDs []string            `json:"expectation_ids,omitempty"`
	Versions       []ExpectedVersion   `json:"versions,omitempty"`
	Features       []ExpectedFeature   `json:"features,omitempty"`
}

type CorrectionFinding struct {
	RuleID string `json:"rule_id"`
	Asset  string `json:"asset"`
}

type ExpectedVersion struct {
	Asset   string      `json:"asset"`
	Name    string      `json:"name"`
	Role    VersionRole `json:"role,omitempty"`
	AtLeast string      `json:"at_least"`
}

type ExpectedFeature struct {
	Asset string      `json:"asset"`
	Name  string      `json:"name"`
	Role  VersionRole `json:"role,omitempty"`
	Value bool        `json:"value"`
}

// FactVerdict states what a snapshot establishes about one expected fact.
type FactVerdict string

const (
	FactSatisfied    FactVerdict = "satisfied"
	FactContradicted FactVerdict = "contradicted"
	FactUnobserved   FactVerdict = "unobserved"
)

type FactJudgement struct {
	Verdict  FactVerdict
	Reason   UnknownReason
	Evidence []EvidenceRef
}

// Input is everything Evaluate judges by: the catalog, the snapshot, the coverage rows the
// collection that made the snapshot reports (the versions and features it fed), the intent
// set if one was supplied, the time of evaluation and the work budget. Evaluate reads
// nothing else.
type Input struct {
	Catalog   Catalog    `json:"catalog"`
	Snapshot  Snapshot   `json:"snapshot"`
	Intent    *IntentSet `json:"intent,omitempty"`
	Collected []Coverage `json:"collected,omitempty"`
	Now       time.Time  `json:"now"`
	Budget    WorkBudget `json:"budget"`
}
type LifecycleEntry struct {
	Finding         Finding        `json:"finding"`
	State           LifecycleState `json:"state"`
	ChangedAt       time.Time      `json:"changed_at"`
	SuppressedUntil *time.Time     `json:"suppressed_until,omitempty"`
}
type Lifecycle struct {
	SchemaVersion int              `json:"schema_version"`
	Context       string           `json:"context"`
	KeyEpoch      string           `json:"key_epoch"`
	Entries       []LifecycleEntry `json:"entries"`
}
type CatalogChange struct {
	PreviousRevision uint64   `json:"previous_revision"`
	CurrentRevision  uint64   `json:"current_revision"`
	ChangedRuleIDs   []string `json:"changed_rule_ids,omitempty"`
}
type Event struct {
	ID         string    `json:"id"`
	Context    string    `json:"context"`
	KeyEpoch   string    `json:"key_epoch"`
	FindingID  string    `json:"finding_id"`
	Kind       EventKind `json:"kind"`
	OccurredAt time.Time `json:"occurred_at"`
}
