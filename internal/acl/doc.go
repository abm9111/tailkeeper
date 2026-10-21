// Package acl is the read side of tailkeeper's policy engine: it parses a tailnet policy
// file, brings it to a normal form, compares two of them, and places a failure on a line.
// It is pure. It opens no file, makes no request, and knows nothing of masking or
// pseudonyms: texts go in as bytes and results come out as values, and the tools that use
// it (internal/tools) own every string that reaches a caller.
//
// A policy file is HuJSON. The server that stores it reads it with Go's strict
// encoding/json after the comments and trailing commas are gone: keys of a struct match
// without regard to case and an unknown field is an error. The server also refuses a text
// that writes a key twice, at any depth, a top-level pair that differs only in case
// included (probe A-4, 20 Oct 2026), so such a text can be neither stored nor validated.
// A generic HuJSON tree keeps both keys, and Go's decoder would keep one: a repeated map
// entry is replaced whole, a repeated struct field that holds an object merges into the
// earlier one, and an array or a scalar replaces it. Parse reports every repeated key as a
// Finding, and everything after Parse reads the text with the decoder's rule, so that two
// texts can still be compared and a failure placed on a line. That is the reading Diff
// uses; it is not what the server does with such a text.
//
// Every entry point that takes text runs the depth pre-scan of internal/guard
// before the first call into the HuJSON library: that library recurses once for each level
// of nesting and has no bound, and a stack overflow cannot be recovered from.
package acl
