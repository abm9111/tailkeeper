package tools

import (
	"time"

	"github.com/abm9111/tailkeeper/internal/registry"
)

// SetSettingsWait shortens acl_get's settings deadline for one test and returns
// the function that restores it.
func SetSettingsWait(d time.Duration) (restore func()) {
	old := settingsWait
	settingsWait = d
	return func() { settingsWait = old }
}

// SetPseudonymFunc replaces how the resolver names a user's login, so that a test can force
// two users to one pseudonym.
func (r *SubjectResolver) SetPseudonymFunc(f func(login string) string) { r.name = f }

// ZeroSubjectResolver returns a resolver built as a composite literal, not by
// NewSubjectResolver, so that a test can check what a resolver with no state does.
func ZeroSubjectResolver(env *registry.Env) *SubjectResolver { return &SubjectResolver{env: env} }
