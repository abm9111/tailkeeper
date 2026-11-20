package tkerr

import (
	"errors"
	"fmt"
	"strings"
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

// The cause of an unclassified error is kept for the program and hidden from every text that
// reaches a user or an agent: Error(), the message and the hint never carry it, and errors.Is
// and errors.As still find it.
func TestFromKeepsTheCauseOutOfEveryTextButStillUnwrapsToIt(t *testing.T) {
	const secret = "CAUSE-CANARY open /home/someone/secret: permission denied"
	cause := errors.New(secret)
	for name, err := range map[string]error{
		"plain":   cause,
		"wrapped": fmt.Errorf("reading the thing: %w", cause),
	} {
		got := From(err)
		if got.Code != Internal {
			t.Fatalf("%s: code = %s, want internal_error", name, got.Code)
		}
		for field, text := range map[string]string{"Error()": got.Error(), "Message": got.Message, "Hint": got.Hint} {
			if strings.Contains(text, "CAUSE-CANARY") || strings.Contains(text, "permission denied") {
				t.Errorf("%s: %s = %q carries the cause", name, field, text)
			}
		}
		if got.Message == "" || got.Hint == "" {
			t.Errorf("%s: the error says nothing a user can act on: message %q, hint %q", name, got.Message, got.Hint)
		}
		if !errors.Is(got, cause) {
			t.Errorf("%s: errors.Is no longer finds the cause", name)
		}
	}
	// A cause that is itself a classified error is not hidden: its code, message and hint stand.
	inner := New(ScopeMissing, "missing devices:core:read", "run tailkeeper doctor")
	got := From(fmt.Errorf("listing devices: %w", inner))
	if got.Code != ScopeMissing || got.Message != inner.Message || got.Hint != inner.Hint {
		t.Errorf("From(wrapped *Error) = %+v, want the classified error's own code, message and hint", got)
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
