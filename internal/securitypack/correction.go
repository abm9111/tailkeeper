package securitypack

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/abm9111/tailkeeper/internal/guard"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tripwire"
)

const (
	MaxCorrectionBytes   = 64 * 1024
	MaxCorrectionTargets = 256
)

// ErrCorrectionInvalid is the only error returned for an invalid correction.
var ErrCorrectionInvalid = errors.New("correction_invalid")

type correctionDocument struct {
	SchemaVersion *int                `json:"schema_version"`
	ActionAt      *time.Time          `json:"action_at"`
	Findings      []correctionFinding `json:"findings"`
	Expectations  []string            `json:"expectations"`
	Expect        *correctionExpect   `json:"expect"`
}
type correctionFinding struct {
	Rule   *string `json:"rule"`
	Device *string `json:"device"`
}
type correctionExpect struct {
	Versions []correctionVersion `json:"versions"`
	Features []correctionFeature `json:"features"`
}
type correctionVersion struct {
	Device  *string `json:"device"`
	Name    *string `json:"name"`
	Role    *string `json:"role"`
	AtLeast *string `json:"at_least"`
}
type correctionFeature struct {
	Device *string `json:"device"`
	Name   *string `json:"name"`
	Role   *string `json:"role"`
	Value  *bool   `json:"value"`
}

// correctionShape is a schema node used only for checking JSON structure and keys.
type correctionShape uint8

const (
	shapeRoot correctionShape = iota
	shapeExpect
	shapeFinding
	shapeVersion
	shapeFeature
	shapeFindings
	shapeExpectations
	shapeVersions
	shapeFeatures
	shapeScalar
)

func correctionField(shape correctionShape, key string) (correctionShape, bool) {
	switch shape {
	case shapeRoot:
		switch key {
		case "schema_version", "action_at":
			return shapeScalar, true
		case "findings":
			return shapeFindings, true
		case "expectations":
			return shapeExpectations, true
		case "expect":
			return shapeExpect, true
		}
	case shapeExpect:
		switch key {
		case "versions":
			return shapeVersions, true
		case "features":
			return shapeFeatures, true
		}
	case shapeFinding:
		switch key {
		case "rule", "device":
			return shapeScalar, true
		}
	case shapeVersion:
		switch key {
		case "device", "name", "role", "at_least":
			return shapeScalar, true
		}
	case shapeFeature:
		switch key {
		case "device", "name", "role", "value":
			return shapeScalar, true
		}
	}
	return 0, false
}

// checkCorrectionJSON refuses null, duplicate keys (including escaped spellings),
// unknown keys and unexpected containers before decoding into typed wire values.
func checkCorrectionJSON(dec *json.Decoder, shape correctionShape) error {
	token, err := dec.Token()
	if err != nil || token == nil {
		return ErrCorrectionInvalid
	}
	switch shape {
	case shapeRoot, shapeExpect, shapeFinding, shapeVersion, shapeFeature:
		if token != json.Delim('{') {
			return ErrCorrectionInvalid
		}
		return checkCorrectionObject(dec, shape)
	case shapeFindings, shapeExpectations, shapeVersions, shapeFeatures:
		if token != json.Delim('[') {
			return ErrCorrectionInvalid
		}
		return checkCorrectionArray(dec, shape)
	case shapeScalar:
		if _, ok := token.(json.Delim); ok {
			return ErrCorrectionInvalid
		}
		return nil
	default:
		return ErrCorrectionInvalid
	}
}

func checkCorrectionObject(dec *json.Decoder, shape correctionShape) error {
	seen := make(map[string]struct{})
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return ErrCorrectionInvalid
		}
		key, ok := token.(string)
		if !ok {
			return ErrCorrectionInvalid
		}
		child, ok := correctionField(shape, key)
		if !ok {
			return ErrCorrectionInvalid
		}
		if _, ok := seen[key]; ok {
			return ErrCorrectionInvalid
		}
		seen[key] = struct{}{}
		if err := checkCorrectionJSON(dec, child); err != nil {
			return ErrCorrectionInvalid
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') {
		return ErrCorrectionInvalid
	}
	return nil
}

func checkCorrectionArray(dec *json.Decoder, shape correctionShape) error {
	child := shapeScalar
	switch shape {
	case shapeFindings:
		child = shapeFinding
	case shapeVersions:
		child = shapeVersion
	case shapeFeatures:
		child = shapeFeature
	}
	for dec.More() {
		if err := checkCorrectionJSON(dec, child); err != nil {
			return ErrCorrectionInvalid
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim(']') {
		return ErrCorrectionInvalid
	}
	return nil
}

// DecodeCorrection decodes the strict correction format without requiring canonical JSON.
func DecodeCorrection(data []byte) (security.CorrectionIntent, error) {
	invalid := func() (security.CorrectionIntent, error) { return security.CorrectionIntent{}, ErrCorrectionInvalid }
	if len(data) > MaxCorrectionBytes || !utf8.Valid(data) || guard.NestsDeeperThan(data, 8) {
		return invalid()
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := checkCorrectionJSON(dec, shapeRoot); err != nil {
		return invalid()
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return invalid()
	}
	var doc correctionDocument
	if err := json.Unmarshal(data, &doc); err != nil || doc.SchemaVersion == nil || doc.ActionAt == nil {
		return invalid()
	}
	out, err := correctionFromDocument(doc)
	if err != nil {
		return invalid()
	}
	if err := ValidateCorrection(out); err != nil {
		return invalid()
	}
	return out, nil
}

func correctionFromDocument(doc correctionDocument) (security.CorrectionIntent, error) {
	out := security.CorrectionIntent{SchemaVersion: *doc.SchemaVersion, ActionAt: *doc.ActionAt, ExpectationIDs: doc.Expectations}
	for _, f := range doc.Findings {
		if f.Rule == nil || f.Device == nil {
			return security.CorrectionIntent{}, ErrCorrectionInvalid
		}
		out.Findings = append(out.Findings, security.CorrectionFinding{RuleID: *f.Rule, Asset: *f.Device})
	}
	if doc.Expect != nil {
		versions, err := correctionVersions(doc.Expect.Versions)
		if err != nil {
			return security.CorrectionIntent{}, ErrCorrectionInvalid
		}
		features, err := correctionFeatures(doc.Expect.Features)
		if err != nil {
			return security.CorrectionIntent{}, ErrCorrectionInvalid
		}
		out.Versions, out.Features = versions, features
	}
	return out, nil
}

func correctionVersions(items []correctionVersion) ([]security.ExpectedVersion, error) {
	var out []security.ExpectedVersion
	for _, v := range items {
		if v.Device == nil || v.Name == nil || v.AtLeast == nil {
			return nil, ErrCorrectionInvalid
		}
		role, ok := correctionRole(v.Role)
		if !ok {
			return nil, ErrCorrectionInvalid
		}
		out = append(out, security.ExpectedVersion{Asset: *v.Device, Name: *v.Name, Role: role, AtLeast: *v.AtLeast})
	}
	return out, nil
}

func correctionFeatures(items []correctionFeature) ([]security.ExpectedFeature, error) {
	var out []security.ExpectedFeature
	for _, f := range items {
		if f.Device == nil || f.Name == nil || f.Value == nil {
			return nil, ErrCorrectionInvalid
		}
		role, ok := correctionRole(f.Role)
		if !ok {
			return nil, ErrCorrectionInvalid
		}
		out = append(out, security.ExpectedFeature{Asset: *f.Device, Name: *f.Name, Role: role, Value: *f.Value})
	}
	return out, nil
}

func correctionRole(value *string) (security.VersionRole, bool) {
	if value == nil {
		return security.VersionRunningDaemon, true
	}
	role := security.VersionRole(*value)
	return role, role != "" && validCorrectionRole(role)
}
func validCorrectionRole(role security.VersionRole) bool {
	return role == "" || role == security.VersionRunningDaemon || role == security.VersionLocalCLI || role == security.VersionAPIReported
}
func validCorrectionText(s string) bool {
	return strings.TrimSpace(s) != "" && security.ValidText(s) && tripwire.Check([]byte(s)) == nil
}

// ValidateCorrection checks constructed intents using the same semantic rules as the decoder.
func ValidateCorrection(c security.CorrectionIntent) error {
	if c.SchemaVersion != 1 || c.ActionAt.IsZero() {
		return ErrCorrectionInvalid
	}
	count := len(c.Findings) + len(c.ExpectationIDs) + len(c.Versions) + len(c.Features)
	if count < 1 || count > MaxCorrectionTargets {
		return ErrCorrectionInvalid
	}
	if !validCorrectionFindings(c.Findings) || !validCorrectionExpectations(c.ExpectationIDs) || !validCorrectionVersions(c.Versions) || !validCorrectionFeatures(c.Features) {
		return ErrCorrectionInvalid
	}
	return nil
}

func validCorrectionFindings(items []security.CorrectionFinding) bool {
	seen := make(map[[2]string]struct{}, len(items))
	for _, f := range items {
		if !validCorrectionText(f.RuleID) || !validCorrectionText(f.Asset) {
			return false
		}
		key := [2]string{f.RuleID, f.Asset}
		if _, ok := seen[key]; ok {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

func validCorrectionExpectations(items []string) bool {
	seen := make(map[string]struct{}, len(items))
	for _, id := range items {
		if !validCorrectionText(id) {
			return false
		}
		if _, ok := seen[id]; ok {
			return false
		}
		seen[id] = struct{}{}
	}
	return true
}

func correctionTargetKey(asset, name string, role security.VersionRole) [3]string {
	if role == "" {
		role = security.VersionRunningDaemon
	}
	return [3]string{asset, name, string(role)}
}

func validCorrectionVersions(items []security.ExpectedVersion) bool {
	seen := make(map[[3]string]struct{}, len(items))
	for _, v := range items {
		if !validCorrectionText(v.Asset) || !validCorrectionText(v.Name) || !validCorrectionText(v.AtLeast) || !security.ReleaseOK(v.AtLeast) || !validCorrectionRole(v.Role) {
			return false
		}
		key := correctionTargetKey(v.Asset, v.Name, v.Role)
		if _, ok := seen[key]; ok {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

func validCorrectionFeatures(items []security.ExpectedFeature) bool {
	seen := make(map[[3]string]struct{}, len(items))
	values := make(map[[2]string]bool, len(items))
	for _, f := range items {
		if !validCorrectionText(f.Asset) || !validCorrectionText(f.Name) || f.Name == "connected_to_control" || !validCorrectionRole(f.Role) {
			return false
		}
		fact := [2]string{f.Asset, f.Name}
		if value, ok := values[fact]; ok && value != f.Value {
			return false
		}
		values[fact] = f.Value
		key := correctionTargetKey(f.Asset, f.Name, f.Role)
		if _, ok := seen[key]; ok {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}
