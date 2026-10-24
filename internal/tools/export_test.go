package tools

import (
	"context"
	"time"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/registry"
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
