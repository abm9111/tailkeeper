package tkerr

import (
	"errors"
	"fmt"
	"testing"
)

func TestExitCode(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{nil, 0},
		{New(Usage, "bad flag", ""), 2},
		{New(ValidationFailed, "bad input", ""), 2},
		{New(ScopeMissing, "no scope", ""), 5},
		{New(CredentialUnavailable, "no cred", ""), 5},
		{New(TokenRejected, "401", ""), 5},
		{New(ConfigMissing, "no config", ""), 6},
		{New(ConfigUnsafe, "group writable", ""), 6},
		{New(ConfigInvalid, "bad file", ""), 6},
		{fmt.Errorf("reading the configuration: %w", New(ConfigInvalid, "bad file", "")), 6},
		{New(OutputWithheld, "tripwire matched", ""), 1},
		{New(AuditUnavailable, "disk full", ""), 7},
		{New(FindingsPresent, "doctor failed", ""), 8},
		{New(NotFound, "404", ""), 1},
		{errors.New("plain"), 1},
	}
	for _, c := range cases {
		if got := ExitCode(c.err); got != c.want {
			t.Errorf("ExitCode(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}

func TestAsFindsWrappedError(t *testing.T) {
	inner := New(ScopeMissing, "missing devices:core:read", "run tailkeeper doctor")
	wrapped := fmt.Errorf("listing devices: %w", inner)
	got, ok := As(wrapped)
	if !ok || got.Code != ScopeMissing {
		t.Fatalf("As(wrapped) = %v, %v; want scope_missing", got, ok)
	}
}

func TestFromClassifiesUnknownAsInternal(t *testing.T) {
	got := From(errors.New("boom"))
	if got.Code != Internal {
		t.Fatalf("From(plain).Code = %s, want internal_error", got.Code)
	}
	if got.Message == "boom" {
		t.Fatalf("internal cause leaked into Message: %q", got.Message)
	}
}

func TestPrivacyCodesExit(t *testing.T) {
	for c, want := range map[Code]int{FilterRefused: 2, ToolHidden: 2, PrivacyKeyUnavailable: 5} {
		if got := ExitCode(New(c, "m", "")); got != want {
			t.Errorf("ExitCode(%s) = %d, want %d", c, got, want)
		}
	}
	if FilterRefused != "filter_refused" || ToolHidden != "tool_hidden" || PrivacyKeyUnavailable != "privacy_key_unavailable" {
		t.Error("code spellings must match spec §19")
	}
}
