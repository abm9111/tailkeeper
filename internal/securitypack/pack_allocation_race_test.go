//go:build race

package securitypack

// Race instrumentation increases allocation counts; the production predicate
// is defined separately in the non-race test build.
const packAllocationMultiplier = 64
