package api

import (
	"slices"
	"strconv"
	"strings"
)

// PolicyStatus is what an answer of the validate endpoint to a policy (policy mode) means.
// The reader trusts nothing it does not recognise: a pass is read only from a shape the
// documentation or a probe of the live API showed, and everything else is PolicyUnknown,
// which a caller must treat as "not validated".
type PolicyStatus string

// The four things a policy-mode answer can mean.
const (
	PolicyPass     PolicyStatus = "pass"     // HTTP 200 and a recognised pass; warnings may ride along
	PolicyFail     PolicyStatus = "fail"     // HTTP 200, at least one entry with errors
	PolicyRejected PolicyStatus = "rejected" // a bare {message}: the server refused the document
	PolicyUnknown  PolicyStatus = "unknown"  // anything else, including every Assumed shape
)

// PolicyValidation is a policy-mode answer as the strict reader understood it.
type PolicyValidation struct {
	Status  PolicyStatus
	HTTP    int
	Message string       // the server's message: untrusted text
	Results []TestResult // entries with their errors and warnings, in order; set for pass and fail only
	Why     string       // for PolicyUnknown: tailkeeper's words, quoting nothing but capped untrusted tokens
	Hint    string       // set by the client's send, never by the reader: the size hint of a rejection that speaks of size
}

// ReadPolicyValidation reads the answer of the validate endpoint to a policy:
//
//   - 200 with an empty body or {} is a pass;
//   - 200 {message, data[]}: any entry with errors is a fail; entries with warnings only are
//     a pass whose Results carry them, if the message reports warnings or is absent; an
//     entry with neither is unknown;
//   - 200 or 400 with exactly the key message is a rejection (the live API rejects a
//     well-formed document with a 200 and a bare message, and a body that is no policy at
//     all with a 400), unless the message says "test(s) failed" or "warning(s) found":
//     it then promises entries that are not there, which is unknown;
//   - anything else is unknown: a 400 that carries data, any other status, a field the
//     documentation does not name, a field given twice, a non-object, trailing bytes, a
//     comment, a byte order mark.
//
// body is at most what the client read (the policy call reads 1 MiB); the message is not
// cut here.
func ReadPolicyValidation(status int, body []byte) PolicyValidation {
	v := PolicyValidation{Status: PolicyUnknown, HTTP: status}
	if status != 200 && status != 400 {
		v.Why = "it came with HTTP " + strconv.Itoa(status) + ", not 200 or 400"
		return v
	}
	message, results, shape, err := parseValidationBody(body)
	if err != nil {
		v.Why = err.Error()
		return v
	}
	v.Message = message
	switch shape {
	case shapeBlank, shapeObject:
		if status != 200 {
			v.Why = "it is an empty answer with HTTP " + strconv.Itoa(status) + ", not 200"
			return v
		}
		v.Status = PolicyPass
	case shapeMessage:
		readBareMessage(&v)
	case shapeData:
		readEntries(&v, results)
	}
	return v
}

// readBareMessage classifies an answer whose only key is message.
func readBareMessage(v *PolicyValidation) {
	l := strings.ToLower(v.Message)
	switch {
	case v.Message == "":
		v.Why = "it is an object with an empty message and nothing else"
	case strings.Contains(l, "test(s) failed") || strings.Contains(l, "warning(s) found"):
		v.Why = "its message reports test results or warnings, but the answer carries none"
	default:
		v.Status = PolicyRejected
	}
}

// readEntries classifies an answer with a data field.
func readEntries(v *PolicyValidation, results []TestResult) {
	switch {
	case v.HTTP != 200:
		v.Why = "it carries test results with HTTP " + strconv.Itoa(v.HTTP) + ", not 200"
	case len(results) == 0:
		v.Why = "it carries a data field with no entries"
	case slices.ContainsFunc(results, func(r TestResult) bool { return len(r.Errors) > 0 }):
		v.Status, v.Results = PolicyFail, results
	case !reportsWarningsOrNothing(v.Message):
		v.Why = "it names no errors, but its message does not report warnings"
	default:
		v.Status, v.Results = PolicyPass, results
	}
}

// RemoveCanary drops the one result whose User is src, which must carry exactly one error
// and no warning, and sets the status from what is left: a fail while an entry has errors,
// else a pass, which carries no message. It reports false, and returns v unchanged, when v is not a fail, when no
// result or more than one has that User (compared exactly), or when the one has anything
// but a single error. grammar, when not nil, is the caller's check of that one error: a canary
// that comes back in another shape is not a pass. The check lives in grammar, not in a second copy here.
func RemoveCanary(v PolicyValidation, src string, grammar func(line string) bool) (PolicyValidation, bool) {
	if v.Status != PolicyFail {
		return v, false
	}
	at := -1
	for i, r := range v.Results {
		if r.User != src {
			continue
		}
		if at >= 0 {
			return v, false
		}
		at = i
	}
	if at < 0 || len(v.Results[at].Errors) != 1 || len(v.Results[at].Warnings) != 0 {
		return v, false
	}
	if grammar != nil && !grammar(v.Results[at].Errors[0]) {
		return v, false
	}
	out := v
	out.Results = slices.Concat(v.Results[:at], v.Results[at+1:])
	out.Status = PolicyPass
	if slices.ContainsFunc(out.Results, func(r TestResult) bool { return len(r.Errors) > 0 }) {
		out.Status = PolicyFail
	} else {
		// The message said the tests failed. A pass that carried it would be one the reader
		// refuses, and a tool that prints the message beside "pass" would contradict itself.
		out.Message = ""
	}
	return out, true
}
