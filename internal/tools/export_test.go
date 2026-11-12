package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// SetSettingsWait shortens acl_get's settings deadline for one test and returns
// the function that restores it.
func SetSettingsWait(d time.Duration) (restore func()) {
	old := settingsWait
	settingsWait = d
	return func() { settingsWait = old }
}

// SetStripTests replaces how the invariants text has the policy's own tests taken out, so that
// a test can plant a text that still holds one, and returns the function that restores it.
func SetStripTests(f func(context.Context, []byte) ([]byte, error)) (restore func()) {
	old := stripTests
	stripTests = f
	return func() { stripTests = old }
}

// SetAppendTests replaces how the invariants and the canary are put into the text, so that a
// test can plant a text with a test too many, and returns the function that restores it.
func SetAppendTests(f func(context.Context, []byte, [][]byte, [][]byte) ([]byte, error)) (restore func()) {
	old := appendTests
	appendTests = f
	return func() { appendTests = old }
}

// SetCompareTexts replaces the comparison acl_diff makes of its two sides, so that a test can
// fail a call after a pseudonym was resolved, and returns the function that restores it.
func SetCompareTexts(f func(context.Context, *acl.Doc, *acl.Doc, acl.DiffOptions) (*acl.DiffResult, error)) (restore func()) {
	old := compareTexts
	compareTexts = f
	return func() { compareTexts = old }
}

// SetPseudonymFunc replaces how the resolver names a user's login, so that a test can force
// two users to one pseudonym.
func (r *SubjectResolver) SetPseudonymFunc(f func(login string) string) { r.name = f }

// ZeroSubjectResolver returns a resolver built as a composite literal, not by
// NewSubjectResolver, so that a test can check what a resolver with no state does.
func ZeroSubjectResolver(env *registry.Env) *SubjectResolver { return &SubjectResolver{env: env} }

// PolicyEngineNote is the fixed sentence dns_get gives for a refusal of the policy engine.
func PolicyEngineNote(err error) string { return policyEngineNote(err) }

// SecurityCollection is what a security collection returns.
type SecurityCollection = securityCollection

// CollectSecurity runs a security collection for the rules that require the features named.
func CollectSecurity(ctx context.Context, env *registry.Env, scope security.Scope, required ...string) (SecurityCollection, error) {
	return collectSecurity(ctx, env, scope, required)
}

// CollectSecurityWithin runs a security collection with a time budget of the test's choosing.
func CollectSecurityWithin(ctx context.Context, env *registry.Env, scope security.Scope, budget time.Duration) (SecurityCollection, error) {
	return collectWithin(ctx, env, scope, nil, budget)
}

// SecurityOperations are the operations of the sources a collection may ask, in order.
func SecurityOperations() []string {
	ops := make([]string, len(securitySources))
	for i, s := range securitySources {
		ops[i] = s.op
	}
	return ops
}

// SecurityDevice is what a collection keeps of one device of the API: the presence of each
// decision field is a pointer.
type SecurityDevice struct {
	NodeID                                                       string
	Connected, Authorized, BlocksIncomingConnections, SSHEnabled *bool
}

// DecodeSecurityDevices reads a device list as a collection does.
func DecodeSecurityDevices(body []byte) ([]SecurityDevice, error) {
	var resp struct {
		Devices []observedDevice `json:"devices"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	out := make([]SecurityDevice, len(resp.Devices))
	for i, d := range resp.Devices {
		out[i] = SecurityDevice{d.NodeID, d.ConnectedToControl, d.Authorized, d.BlocksIncomingConnections, d.SSHEnabled}
	}
	return out, nil
}

// SecurityDeviceList is what a read of a device list kept.
type SecurityDeviceList struct{ l *deviceList }

// ReadSecurityDeviceList reads a device list as a collection does, with room for the given
// number of facts.
func ReadSecurityDeviceList(data []byte, room int) (SecurityDeviceList, error) {
	l, err := readDeviceList(bytes.NewReader(data), room)
	return SecurityDeviceList{l}, err
}

// Kept is the node IDs of the rows that were kept, in the order they are kept in.
func (s SecurityDeviceList) Kept() []string {
	var out []string
	for _, d := range s.l.kept {
		out = append(out, d.NodeID)
	}
	return out
}

// Dropped is the number of rows that give no fact.
func (s SecurityDeviceList) Dropped() int { return s.l.dropped }

// Rows is the number of rows in the list.
func (s SecurityDeviceList) Rows() int { return s.l.rows }

// Has says whether the list gave the node ID, as far as the read could remember it.
func (s SecurityDeviceList) Has(id string) bool { return s.l.has(id) }

// IDsFull says that the read had no room to remember a node ID.
func (s SecurityDeviceList) IDsFull() bool { return s.l.idsFull }

// SecurityMaxListedIDs is the number of node IDs a read remembers.
func SecurityMaxListedIDs() int { return maxListedIDs }

// TooLargeError is the error a device list over the body cap becomes.
func TooLargeError(limit int64) *tkerr.Error { return tooLargeError(limit) }

// SetScanCatalog replaces where security_scan gets its catalog, so that a test can judge by
// rules of its own, and returns the function that restores it.
func SetScanCatalog(f func() (security.Catalog, error)) (restore func()) {
	old := scanCatalog
	scanCatalog = f
	return func() { scanCatalog = old }
}

// MaskDeviceID is how a scan shows a device's node ID.
func MaskDeviceID(id string) string { return maskDeviceID(id) }
