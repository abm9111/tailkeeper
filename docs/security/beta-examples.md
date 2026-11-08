# Reproducible synthetic examples

These developer-assisted examples use the current Unix-only tests, Go and
permission to bind a local fake HTTP server. From a checkout run:

```sh
env -u TAILKEEPER_LIVE go test -count=1 -run '^TestPublicDemo' -v ./internal/cli
```

The tests invoke an injected CLI runner and fake API, not the installed binary
or MCP; they never contact a live tailnet. Temporary private fixtures and packs
stay in temporary directories, and transcript paths are placeholders. A passing
assertion is evidence for the tested fixture only, not participant beta outcomes
or support of a production artifact. Read the assertions in
[public_demo_unix_test.go](../../internal/cli/public_demo_unix_test.go) and the
[demo description](demos.md):

1. **Advisory:** an old reported stable client matches the reviewed rule;
   four pending rules are unknown. Scan exit 8 for a threshold finding outranks
   partial coverage. The reported version is evidence, not proof of exploitation.
2. **Access:** the fake validator witnesses a deny expectation allowed, exit 8.
   A broad matching rule is a candidate, not proven cause; conditional blast
   radius establishes neither a listening service nor exploitation.
3. **Correction:** a private before-pack and changed fake-device report model a
   correction. Fresh new running evidence produces `fixed` and exit 0; a
   contradictory old running version produces `not_fixed` and exit 8. This is
   neither a fleet security claim nor an instruction to downgrade a real host.

Scan and verify have distinct exit contracts. For scan, a threshold finding can
produce 8 despite partial assessment. For verification, `not_fixed` or an
unmet selected expectation produces 8 ahead of incomplete rows; otherwise an
incomplete result is 1 and success is 0. Errors have their own codes; consult
[evidence packs](evidence-packs.md) and [coverage](coverage.md).

For a private owner exercise, consult the actual `security export`, `security
replay`, `security redact`, and `security verify` syntax and requirements in
[evidence packs](evidence-packs.md). Keep packs private, use fresh baseline and
post-action observations, and review any projection before sharing. Sample dates
in documentation are illustrations, not participant action times. Windows pack
commands are unsupported. Do not point these fixture tests at a real API.

## Orientation and full exercise

A participant can run and explain these demos for synthetic-only orientation,
then do so again in a separate later session. Record orientation attempts,
completions, understanding and assistance separately. The test's hardcoded
version change and a rerun are not a participant-configured product change.
The full installed-product pack/replay/correction and configuration-change
repeat are blocked in synthetic-only mode with current tooling. A separately
approved safe fixture interface or a participant's separately chosen authorized
lab workflow is needed. No real data or production change is required for
orientation; it does not count toward independent full completion.
