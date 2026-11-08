# Security coverage and assurance boundaries

Tailkeeper currently provides typed, read-only Tailscale observations, policy
validation and policy comparisons. A complete advisory assessor, persistent
security monitor and hardened service are planned features. This document is a
coverage record, not a certification or a claim that a network is secure.

## Current evidence

| Question | Available source | Limit |
|---|---|---|
| Which version is installed? | `local version` reads CLI and daemon versions separately | A newer CLI does not prove a running daemon was restarted. |
| Which versions does the fleet report? | Device API client version, OS and last seen | API-reported state is not a direct runtime measurement; absent/stale data stays unknown. |
| Is SSH enabled? | Optional API SSH field and local preferences | A missing field is unknown. Local evidence covers only the inspected node. The internal collector reads the API field with `fields=all`, keeps absent, false and true apart, and an API fact speaks for a daemon rule only while the device is connected to control. |
| What access does policy permit? | Existing policy validation, tests, invariants and diff; for the owner's own expectations, `tailkeeper security explain` (command line only, [access explanations](access-explanations.md)): a canary-backed verdict for each listed pair, candidate rules as text matches and an assumed blast radius | Canary/unsupported-feature limitations still apply; device posture (on a rule of `acls`, `grants` or `ssh`, and `defaultSrcPosture`), app capabilities, `via` and autogroup sources are stated limits; at most 64 pairs and two validation requests a run, and nothing is enumerated; policy permission is not service reachability or compromise. |
| Is native device posture passing? | Pinned OpenAPI includes `postureStatus` on device/list responses | Current device DTO does not expose it. Integration and live response/scope validation are not evaluated. |
| Is SSH forwarding effectively disabled? | No established source in the current tool | Not evaluated for any OS/installation variant; no process-environment dump or inference from version/policy. |
| Does a published advisory apply? | `tailkeeper security scan` (MCP `security_scan`) judges each device by the advisories shipped in the binary: one reviewed rule (CVE-2022-41925) and four pending ones (TS-2026-014 to TS-2026-017, which give `unknown` only) | Partial while the four pending rules give `unknown` findings (and for any other gap the coverage names); the owner's intent is not requested unless an intent set is given (the configured invariants file, or `--invariants FILE`), which the report says in a row of its own; a supplied set is requested and not judged, so it keeps the scan partial. A device that is offline, whose version the API did not give, or whose daemon was not observed is not cleared. No CVE completeness or fixed-version claim, and the catalog is a handful of rules, not the vendor's list. |
| Was an observed change a human login or intrusion? | Management logs and device state answer narrower questions | A connectivity change establishes neither authentication nor compromise. |

The posture fields were compared with the committed API fingerprint fetched on
18 October 2026: `postureStatus.passing`, `impacting` and `failingAssertions`.
This establishes a pinned schema capability, not successful current API use.
Native Tailscale posture monitoring and network/SSH policy tests should be reused
where their evidence contracts are verified.

## Platform evidence

The foundations change is exercised on macOS with synthetic files and fake APIs.
The normal verification gate also vets a Windows build. A compile check does not
establish Windows runtime behavior, Linux runtime behavior, or support for every
Tailscale app/standalone/container variant. Existing tests with platform-specific
skips retain those limits. No real fleet or remote device was inspected to fill
these gaps.

Credential files and all their indirections use one checked descriptor boundary,
with a 1 MiB limit. Unix checks allow the current user or root as owner and require
private file permissions and a non-writable-by-others immediate directory.
Windows rejects non-regular files and reparse points and checks file identity,
but does not enforce owner/ACL confidentiality or Unix change-time checks.
See [the security policy](../../SECURITY.md) for migration and threat limits.

## Gates that remain open

| Capability | Evidence so far | Required before activation |
|---|---|---|
| Signed advisory sync | Local cosign v3.1.4 is available; interoperability not evaluated | Pinned verifier/dependency review; trusted artifact and hostile identity/bytes/expiry/replay/revocation cases; clean-environment test. No catalog sync is enabled. |
| Remote runtime collection | Not evaluated | Per-OS/variant narrow collection and permission tests; authenticated import/replay review. A sender signature cannot prove a compromised host told the truth. |
| Scheduled monitoring/notifications | Not implemented | Durable lifecycle/state/outbox, privacy, scheduler and delivery failure tests; explicit operator activation. |
| Private replay/correction verification | Owner-only export, replay, redact and stateless verification implemented; synthetic correction, context, post-action evidence, rule-change and access-guard tests | Repeat the documented workflow with independent users. Replay establishes a calculation from declared inputs; it cannot establish that a host is uncompromised or secure now. See [evidence packs](evidence-packs.md). |
| Hardened deployment | Not implemented | Separate service-account/IPC design, OS isolation/recovery tests and independent review. |
| Independent audit custody | Not implemented | Reviewed checkpoint/receiver contract and deletion/rollback/outage tests. The current chain verifies retained entries, not completeness of a deleted log. |

Completing foundations does not close these gates. No trusted catalog bundle was
available in this milestone, so the signed-catalog spike did not run and has no
pass verdict. No advisory fixtures were created from a current investigation;
that work must recheck the official notice before curating rules. No new runtime
dependency or license was added for a hypothetical verifier.

## Proposed focused workflow

The owner workflow evaluates a small owner-defined access expectation and
reviewed advisory, explains evidence and missing coverage, exports a private replay
pack, and verifies a correction using newer observations. Existing configured
invariants are the intent authority; imported data cannot silently change it.
Independent users should repeat that workflow before optional operational modules
expand the product.

The useful self-hosted workflow and supported security fixes remain free. Managed
operation, deployment assistance and support are future options; no hosted service,
pricing or response-time commitment is made here.

Stronger claims require evidence tied to a specific artifact: implemented,
tested in stated scenarios, independently reviewed, then demonstrated in field
use. Same-user code can alter user-owned files and access credentials available to
that user. Read-only API access still carries confidentiality risk. No score or
“military grade” label establishes protection from those actors or unknown flaws.
