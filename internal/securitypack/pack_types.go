package securitypack

import "time"

// Stage A typed wire values. All types are package-private and contain only
// schema-listed fields. Optional fields carry ",omitempty" where the writer
// omits empty/zero/false values or nil pointers; required fields are emitted
// even when empty or zero.

type packEnvelope struct {
	Body      packBody `json:"body"`
	Integrity string   `json:"integrity"`
	Seal      *string  `json:"seal,omitempty"`
}

type packBody struct {
	Access               *packAccess    `json:"access,omitempty"`
	Catalog              packCatalog    `json:"catalog"`
	CatalogSchemaVersion int            `json:"catalog_schema_version"`
	Collected            []packCoverage `json:"collected,omitempty"`
	Evaluation           packEvaluation `json:"evaluation"`
	EvaluatorVersion     int            `json:"evaluator_version"`
	Expected             packExpected   `json:"expected"`
	Format               string         `json:"format"`
	Intent               *packIntent    `json:"intent,omitempty"`
	PackSchemaVersion    int            `json:"pack_schema_version"`
	ReportSchemaVersion  int            `json:"report_schema_version"`
	Snapshot             packSnapshot   `json:"snapshot"`
}

type packCatalog struct {
	Digest  string       `json:"digest"`
	Sources []packSource `json:"sources"`
}

type packSource struct {
	Data   []byte `json:"data"`
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type packEvaluation struct {
	At         time.Time `json:"at"`
	WorkBudget int       `json:"work_budget"`
}

type packExpected struct {
	Access *packExpectedAccess `json:"access,omitempty"`
	Counts packExpectedCounts  `json:"counts"`
	Report packExpectedReport  `json:"report"`
}

type packExpectedCounts struct {
	Devices   int `json:"devices"`
	Features  int `json:"features"`
	Platforms int `json:"platforms"`
	Policies  int `json:"policies"`
	Versions  int `json:"versions"`
}

type packExpectedReport struct {
	Affected            int    `json:"affected"`
	NotAffected         int    `json:"not_affected"`
	PotentiallyAffected int    `json:"potentially_affected"`
	SHA256              string `json:"sha256"`
	Status              string `json:"status"`
	TotalFindings       int    `json:"total_findings"`
	Unknown             int    `json:"unknown"`
}

type packExpectedAccess struct {
	Met           int    `json:"met"`
	MetWithLimits int    `json:"met_with_limits"`
	NotEvaluated  int    `json:"not_evaluated"`
	SHA256        string `json:"sha256"`
	Status        string `json:"status"`
	Total         int    `json:"total"`
	Unknown       int    `json:"unknown"`
	Unmet         int    `json:"unmet"`
}

type packSnapshot struct {
	Context    string         `json:"context"`
	Features   []packFeature  `json:"features,omitempty"`
	KeyEpoch   string         `json:"key_epoch,omitempty"`
	ObservedAt time.Time      `json:"observed_at"`
	Platforms  []packPlatform `json:"platforms,omitempty"`
	Policies   []packPolicy   `json:"policies,omitempty"`
	Scope      string         `json:"scope"`
	Versions   []packVersion  `json:"versions,omitempty"`
}

type packVersion struct {
	Channel  string       `json:"channel"`
	Evidence packEvidence `json:"evidence"`
	Name     string       `json:"name"`
	Role     string       `json:"role"`
	Value    *string      `json:"value,omitempty"`
}

type packPlatform struct {
	Evidence packEvidence `json:"evidence"`
	OS       string       `json:"os,omitempty"`
	Variant  string       `json:"variant,omitempty"`
}

type packFeature struct {
	Evidence packEvidence `json:"evidence"`
	Name     string       `json:"name"`
	Value    *bool        `json:"value,omitempty"`
}

type packPolicy struct {
	Evidence packEvidence `json:"evidence"`
	Name     string       `json:"name"`
	Value    *string      `json:"value,omitempty"`
}

type packEvidence struct {
	AcquiredAt time.Time  `json:"acquired_at"`
	Asset      string     `json:"asset,omitempty"`
	Context    string     `json:"context"`
	Error      string     `json:"error,omitempty"`
	Freshness  string     `json:"freshness"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
	Origin     string     `json:"origin"`
	Scope      string     `json:"scope"`
}

type packCoverage struct {
	Context     string              `json:"context"`
	Counts      *packCoverageCounts `json:"counts,omitempty"`
	Explanation string              `json:"explanation,omitempty"`
	Source      string              `json:"source"`
	Status      string              `json:"status"`
	Target      packCoverageTarget  `json:"target"`
}

type packCoverageTarget struct {
	Asset     string `json:"asset,omitempty"`
	Dimension string `json:"dimension"`
	Scope     string `json:"scope"`
}

type packCoverageCounts struct {
	Assets    int `json:"assets"`
	Findings  int `json:"findings"`
	Potential int `json:"potential"`
	Rules     int `json:"rules"`
	Unknown   int `json:"unknown"`
	Withdrawn int `json:"withdrawn"`
}

type tokenForm string

type packToken struct {
	Form  tokenForm `json:"form"`
	Value string    `json:"value"`
}

type packIntent struct {
	Digest        *packToken    `json:"digest,omitempty"`
	Network       []packNetwork `json:"network,omitempty"`
	Revision      string        `json:"revision,omitempty"`
	SchemaVersion int           `json:"schema_version"`
	SSH           []packSSH     `json:"ssh,omitempty"`
}

type packNetwork struct {
	Accept          []string        `json:"accept,omitempty"`
	Deny            []string        `json:"deny,omitempty"`
	ID              string          `json:"id"`
	Proto           string          `json:"proto,omitempty"`
	Src             string          `json:"src"`
	SrcPostureAttrs []packAttribute `json:"src_posture_attrs,omitempty"`
}

type packSSH struct {
	Accept []string `json:"accept,omitempty"`
	Check  []string `json:"check,omitempty"`
	Deny   []string `json:"deny,omitempty"`
	Dst    []string `json:"dst"`
	ID     string   `json:"id"`
	Src    string   `json:"src"`
}

type packAttribute struct {
	Bool   *bool   `json:"bool,omitempty"`
	Name   string  `json:"name"`
	Number *string `json:"number,omitempty"`
	String *string `json:"string,omitempty"`
}

type packAccess struct {
	Candidates    []packCandidate `json:"candidates"`
	Context       string          `json:"context"`
	EvaluatedAt   time.Time       `json:"evaluated_at"`
	Limit         int             `json:"limit"`
	Limits        []packLimits    `json:"limits"`
	Owners        []packOwner     `json:"owners"`
	PolicyVersion *packToken      `json:"policy_version,omitempty"`
	RulesPartial  bool            `json:"rules_partial"`
	Selected      []string        `json:"selected"`
	Witnesses     []packWitness   `json:"witnesses"`
}

type packWitness struct {
	Cell        packCell  `json:"cell"`
	Expectation string    `json:"expectation"`
	Observed    string    `json:"observed"`
	Proof       packProof `json:"proof"`
	Reason      string    `json:"reason,omitempty"`
}

type packCell struct {
	Destination string `json:"destination"`
	Expect      string `json:"expect"`
	User        string `json:"user,omitempty"`
}

type packProof struct {
	Canary        bool `json:"canary"`
	LiveUnchanged bool `json:"live_unchanged"`
}

type packCandidate struct {
	Expectation string     `json:"expectation"`
	Omitted     int        `json:"omitted,omitempty"`
	Rules       []packRule `json:"rules"`
}

type packLimits struct {
	Expectation string   `json:"expectation"`
	Limits      []string `json:"limits"`
}

type packOwner struct {
	Omitted int      `json:"omitted,omitempty"`
	Source  string   `json:"source"`
	Tags    []string `json:"tags"`
}

type packRule struct {
	AllTraffic  bool   `json:"all_traffic,omitempty"`
	Broad       bool   `json:"broad,omitempty"`
	Column      int    `json:"column,omitempty"`
	Destination string `json:"destination"`
	Index       int    `json:"index"`
	Line        int    `json:"line,omitempty"`
	Ports       string `json:"ports,omitempty"`
	Qualified   bool   `json:"qualified,omitempty"`
	Section     string `json:"section"`
	Source      string `json:"source"`
	Traffic     string `json:"traffic,omitempty"`
}
