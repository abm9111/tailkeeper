package api

// ValidatePolicyForTest is the policy-mode send for the tests of this directory. The send
// is unexported because it is unmetered; nothing outside the package may call it.
var ValidatePolicyForTest = (*Client).validatePolicy
