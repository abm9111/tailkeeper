// Package acl is the read side of tailkeeper's policy engine: it parses a tailnet policy
// file, brings it to a normal form, compares two of them, and places a failure on a line.
// It is pure. It opens no file, makes no request, and knows nothing of masking or
// pseudonyms: texts go in as bytes and results come out as values, and the tools that use
// it (internal/tools) own every string that reaches a caller.
//
// A policy file is HuJSON. The server that stores it reads it with Go's strict
// encoding/json after the comments and trailing commas are gone: keys of a struct match
// without regard to case, an unknown field is an error, and a key written twice keeps the
// later value: a repeated map entry is replaced whole, a repeated struct field that holds an
// object merges into the earlier one, and an array or a scalar replaces it. A generic HuJSON
// tree does not see
// that, so Parse reports every place where the two readings differ, and everything after
// Parse reads the file as the server does.
//
// Every entry point that takes text runs the depth pre-scan of internal/guard
// before the first call into the HuJSON library: that library recurses once for each level
// of nesting and has no bound, and a stack overflow cannot be recovered from.
package acl
