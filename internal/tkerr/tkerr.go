// Package tkerr defines tailkeeper's structured errors and their exit codes (spec §16, §19).
package tkerr

import (
	"errors"
	"fmt"
	"time"
)

// Code is a stable, documented error code.
type Code string

const (
	Usage                 Code = "usage"
	ScopeMissing          Code = "scope_missing"
	CredentialUnavailable Code = "credential_unavailable"
	TokenRejected         Code = "token_rejected"
	ValidationFailed      Code = "validation_failed"
	PaymentRequired       Code = "payment_required"
	FeatureUnavailable    Code = "feature_unavailable"
	NotFound              Code = "not_found"
	Conflict              Code = "conflict"
	UnsupportedTarget     Code = "unsupported_target"
	APIRateLimited        Code = "api_rate_limited"
	UpstreamUnavailable   Code = "upstream_unavailable"
	APIError              Code = "api_error"
	ConfigMissing         Code = "config_missing"
	ConfigInvalid         Code = "config_invalid"
	ConfigUnsafe          Code = "config_unsafe"
	AuditUnavailable      Code = "audit_unavailable"
	FindingsPresent       Code = "findings_present"
	FilterRefused         Code = "filter_refused"
	PrivacyKeyUnavailable Code = "privacy_key_unavailable"
	ToolHidden            Code = "tool_hidden"

	// PolicyRejectedOrServerError is a policy-mode validation that got HTTP 500 twice. The
	// hosted service answers 500 for some policies it cannot evaluate.
	PolicyRejectedOrServerError Code = "policy_rejected_or_server_error"

	// ValidateRateLimited is tailkeeper's own bucket of validation requests being empty. It
	// is a wait, not a failure: RetryAfterSeconds says when. Tailscale's 429 is
	// APIRateLimited.
	ValidateRateLimited Code = "validate_rate_limited"

	// TooComplex is a policy, or a comparison of two, past one of the engine's budgets: its
	// size, its number of values or the work it would take. It is never a partial answer.
	TooComplex Code = "too_complex"

	LocalBinaryMissing      Code = "local_binary_missing"
	LocalDaemonUnreachable  Code = "local_daemon_unreachable"
	LocalPermissionDenied   Code = "local_permission_denied"
	LocalStopped            Code = "local_stopped"
	LocalNeedsLogin         Code = "local_needs_login"
	LocalNeedsMachineAuth   Code = "local_needs_machine_auth"
	LocalTimeout            Code = "local_timeout"
	LocalOutputUnrecognized Code = "local_output_unrecognized"
	LocalRateLimited        Code = "local_rate_limited"
	LocalCommandFailed      Code = "local_command_failed"

	Internal       Code = "internal_error"
	OutputWithheld Code = "output_withheld"
)

// Error is the only error type tailkeeper shows to users and agents.
type Error struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
	Status  int    `json:"httpStatus,omitempty"`
	// RetryAfter is the delay the server asked for (HTTP Retry-After), if any.
	RetryAfter time.Duration `json:"-"`
	// RetryAfterSeconds is how long a program should wait before it tries again, in whole
	// seconds rounded up, when the error knows: tailkeeper's own validation limit, and a 429
	// that came with a Retry-After. Zero is left out.
	RetryAfterSeconds int   `json:"retryAfterSeconds,omitempty"`
	Err               error `json:"-"`
}

func (e *Error) Error() string {
	if e.Hint == "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("%s: %s (hint: %s)", e.Code, e.Message, e.Hint)
}

func (e *Error) Unwrap() error { return e.Err }

// New returns an *Error with no cause.
func New(code Code, message, hint string) *Error {
	return &Error{Code: code, Message: message, Hint: hint}
}

// Wrap returns an *Error that keeps err as its cause. The cause is never shown to agents.
func Wrap(code Code, err error, message, hint string) *Error {
	return &Error{Code: code, Message: message, Hint: hint, Err: err}
}

// As returns the *Error in err's chain, if any.
func As(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// From converts any error to an *Error, classifying unknown errors as internal.
func From(err error) *Error {
	if err == nil {
		return nil
	}
	if e, ok := As(err); ok {
		return e
	}
	return Wrap(Internal, err, "unexpected internal error", "report this with `tailkeeper version` output")
}

// ExitCode maps an error to the CLI exit codes of spec §16. A nil error is 0.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	switch From(err).Code {
	case Usage, ValidationFailed, FilterRefused, ToolHidden, TooComplex:
		return 2
	case ScopeMissing, CredentialUnavailable, TokenRejected, PrivacyKeyUnavailable:
		return 5
	case ConfigMissing, ConfigInvalid, ConfigUnsafe:
		return 6
	case AuditUnavailable:
		return 7
	case FindingsPresent:
		return 8
	default:
		return 1
	}
}
