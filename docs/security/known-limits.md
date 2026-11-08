# Known limits for beta participants

This is a concise guide, not a security assurance or a complete support matrix.
See [coverage](coverage.md), [threat model](../threat-model.md) and
[security policy](../../SECURITY.md) for details.

- The assessor is partial. The embedded catalog has one reviewed rule,
  CVE-2022-41925, and four pending rules, TS-2026-014 through TS-2026-017.
  Pending rules yield unknown; there is no live catalog sync or promise to cover
  every CVE. A positive finding is not proof of exploitation.
- API versions are reported evidence. Only current connection and freshness
  conditions allow them to speak for a running daemon. Upgrading the local CLI
  alone does not prove the daemon was fixed. Missing, stale, offline, unsupported
  or unauthorized facts remain unknown; unknown is not automatically a false
  positive or a clean result.
- `security explain` is CLI-only and addresses selected owner expectations.
  It does not enumerate access, prove reachability or compromise, or establish
  rule causation. Candidate rules are text matches; blast radius is conditional.
- Replay reproduces a calculation from declared inputs, not their truth or
  current security. A redacted projection is not replayable or automatically
  safe to publish; review metadata and free text. Export requires audit before
  publication; replay/redact audit is best effort; verify requires audit.
  Verification is stateless and changes no network or devices. Changed rules,
  context or key epoch, stale/pre-action data and missing seals can cap or
  refuse success. See [evidence packs](evidence-packs.md) for exact conditions.
- Personal mode cannot resist same-user code or root. The audit chain does not
  prove completeness after deletion or rollback; it checks retained entries.
  A hardened service, remote runtime collector, scheduler, webhooks and
  notification guarantees are not implemented.
- Windows credential checks do not enforce owner/ACL confidentiality; packs are
  unsupported on Windows. A Windows build check is not runtime acceptance.
- The only isolated MCPB acceptance recorded is an unsigned `de4f25e` snapshot
  on macOS ARM64 with Claude Desktop 4.23118.0 and macOS 27.2 build 26B123.
  It does not establish Intel runtime, a signed/published release, generic
  Linux/Windows runtime or arbitrary host support. See [MCPB](../install/mcpb.md)
  and its existing signed-release verification requirements.
- Synthetic-only Go demos use Unix-only tests and cannot run on Windows. A
  Windows orientation attempt is attempted/blocked, not completed, skipped or
  omitted. The demos support orientation, not the full installed-product
  pack/replay/correction and configuration-change repeat. That full route is
  blocked without a separately approved safe fixture interface or a separately
  chosen authorized lab workflow. Orientation does not satisfy the independent
  full-completion target; no real data or production change is required for it.
