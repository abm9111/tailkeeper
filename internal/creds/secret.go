package creds

import (
	"fmt"
	"io"
)

// Secret holds a credential's bytes in a closure, not in a field: fmt prints a
// struct's fields itself, without calling Format, for a bad verb (%p, %w) and for an
// unexported field of another struct, and a function prints as an address under
// every verb. So no verb, on a Secret or on anything holding one, and no JSON
// encoder or logger, can reach the bytes. privacy.Key is built the same way.
type Secret struct{ reveal func() string }

// NewSecret wraps s.
func NewSecret(s string) Secret { return Secret{reveal: func() string { return s }} }

// Reveal returns the bytes: the one way to read them, used only to send them.
func (s Secret) Reveal() string {
	if s.reveal == nil {
		return ""
	}
	return s.reveal()
}

// Format keeps the bytes out of every verb fmt hands a Format method; it has a
// value receiver so that a Secret printed by value, as a field or an element, calls it.
func (Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "(secret)") }

// String is what a Secret is called as text outside fmt.
func (Secret) String() string { return "(secret)" }

// MarshalText keeps the bytes out of JSON and of text-based loggers.
func (Secret) MarshalText() ([]byte, error) { return []byte("(secret)"), nil }
