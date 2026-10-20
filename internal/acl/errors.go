package acl

import "fmt"

// Code names why the engine refused an input.
type Code string

const (
	// CodeInvalid is a text the engine cannot read as a policy: bad encoding, bad syntax,
	// nesting past the guard, a top level that is not an object, a bad cursor.
	CodeInvalid Code = "invalid"
	// CodeTooComplex is a text or a comparison past one of the engine's budgets: its size,
	// the number of values, the number of atoms or the work spent on it. It is never a
	// partial answer.
	CodeTooComplex Code = "too_complex"
)

// Error is the engine's typed error. Cancellation of the caller's context is not one: it
// comes back as the context's own error.
type Error struct {
	Code Code
	// Message says what is wrong and, where there is one, the fix. It may quote the input,
	// so a caller treats it as untrusted text.
	Message string
	// Line and Column place the error in the text (from 1, bytes); Line is 0 when the
	// error has no position.
	Line, Column int
}

func (e *Error) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%s (line %d, column %d)", e.Message, e.Line, e.Column)
	}
	return e.Message
}

// Is makes errors.Is(err, ErrInvalid) and errors.Is(err, ErrTooComplex) match by code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Message == "" && t.Code == e.Code
}

// ErrInvalid and ErrTooComplex are the targets for errors.Is.
var (
	ErrInvalid    = &Error{Code: CodeInvalid}
	ErrTooComplex = &Error{Code: CodeTooComplex}
)

func invalid(line, col int, format string, args ...any) *Error {
	return &Error{Code: CodeInvalid, Message: capMessage(fmt.Sprintf(format, args...)), Line: line, Column: col}
}

func tooComplex(format string, args ...any) *Error {
	return &Error{Code: CodeTooComplex, Message: capMessage(fmt.Sprintf(format, args...))}
}

// maxMessage caps a message that quotes the input.
const maxMessage = 512

func capMessage(s string) string {
	if len(s) <= maxMessage {
		return s
	}
	cut := maxMessage
	for cut > 0 && !runeStart(s[cut]) {
		cut--
	}
	return s[:cut] + "\u2026"
}

func runeStart(b byte) bool { return b&0xC0 != 0x80 }
