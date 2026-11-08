# Reviewed advisory inputs

`cve-2022-41925.json` is one deliberately narrow historical rule, not a complete Tailscale advisory catalog. `ts-2026-014.json` to `ts-2026-017.json` are four rules that are still pending (see below). It is data for the matcher that `tailkeeper security scan` and the MCP tool `security_scan` run, embedded in the binary (see below); no automatic acquisition or activation of other catalogs is installed.

## Shipped in the binary

Every `*.json` file directly in this directory is embedded (`data/advisories/embed.go`; `testdata/` and this README are not) and merged by `advisory.Shipped` into the one catalog a scan judges by. Each file is decoded by the checked decoder first, and a file that fails refuses the whole catalog: there is no partial one. The merge keeps the earliest `expires_at` of any file (so the catalog is stale as soon as any file is), the latest `issued_at` and the highest `revision`; a rule ID that two files hold, a file name given twice, or files whose windows have no instant in common (one issued after another expires) is refused. The digest is the SHA-256 of the sorted lines `name:digest`, one per file with the decoder's digest of its exact bytes, so a change to any byte of any file, or to a name, changes it. Pending rules stay pending. A new file in this directory is part of the next build without any other edit, and the freshness test below reads the same glob, so it is covered too.

## Provenance

The re-check of the [official bulletin](https://tailscale.com/security-bulletins#ts-2022-005) was done on 2026-10-30 at about 16:12Z. The owner delegated it, and Claude (Opus 5.5) performed it by reading the bulletin in the owner's browser. The bulletin says:

- it is TS-2022-005, dated 2022-11-21, for CVE-2022-41925, with severity Low;
- the affected platforms are all platforms, and all Tailscale clients before v1.32.3 are affected;
- the patched client versions are v1.32.3 or later, and v1.33.257 or later on the unstable track.

The rule models the stable track only: the client, as the running daemon, is affected before the exclusive fixed endpoint 1.32.3, and the absent introduced endpoint is open. The unstable fix at 1.33.257 is outside the version grammar the matcher accepts, so unstable, prerelease, development and downstream versions remain unknown. The rule carries no `published_at` or `updated_at`.

## Dates and revisions

`reviewed_at`, `source_checked_at` and the catalog `issued_at` are the time of that check, 2026-10-30T16:12:00Z. `review_expires_at` and the catalog `expires_at` are that time plus 90 days, 2027-01-28T16:12:00Z. The catalog `revision` is 2 and the record `revision` is "2".

Revision 1 (reviewed 2026-10-28) rested on a cached copy of the bulletin and carried no source-check time; the retrieval date its README stated came after its review date. Revision 2 replaces it, and this README states no retrieval date other than the check above.

## Pending rules: TS-2026-014 to TS-2026-017

`ts-2026-014.json` to `ts-2026-017.json` hold one rule each. They come from four Tailscale security bulletins of 2026-10-26 (TS-2026-014 to TS-2026-017), as read on the [bulletins page](https://tailscale.com/security-bulletins) on 2026-10-30. Every rule is `pending`: the owner has not yet confirmed the bulletin text, so the matcher never gives a device `affected`, `potentially_affected` or `not_affected` for them: every finding is `unknown`, whatever the device's version and features, and no mitigation text is attached. The reason is `review_pending` when the evidence would have decided the device, and an earlier one when it did not: a device the evidence could not judge keeps the reason it earned (for example `no_version`, `evidence_error`, `stale_evidence` or `runtime_unobserved`), and one the rules would have cleared reads `catalog_expired` or `review_expired` when the catalog or the rule's review is no longer fresh. A rule becomes `approved` only when the owner confirms the text, by changing `review_state` and refreshing the dates and revisions with the steps below.

What the bulletins say, and so what the rules say:

| Rule | Issue | Required features |
|---|---|---|
| TS-2026-014 | Tailscale SSH forwarding to Unix sockets as root, where policy allows forwarding | `tailscale_ssh`, `ssh_forwarding_allowed` |
| TS-2026-015 | Tailscale SSH session memory exhaustion, ending in an out-of-memory kill of `tailscaled` | `tailscale_ssh` |
| TS-2026-016 | Serve with Unix-socket backends can reach privileged sockets, the local API among them | `serve_unix_backend` |
| TS-2026-017 | Serve over HTTP/2 mixes app-capability headers across mounts, with TLS and two or more mounts | `serve_tls_multi_mount` |

- All four are fixed in 1.104.4 and newer, and none has a CVE. The client, as the running daemon, is affected below the exclusive fixed endpoint 1.104.4.
- The bulletins publish no lower bound and no backport. Each range is `{"fixed": "1.104.4"}` alone: `introduced` is open, and a 1.102.x release is in range. No lower bound or 1.102.x fix is to be added without the bulletin saying so.
- The bulletins give no severity, so `severity` is `unknown`.
- `published_at` is 2026-10-26, a day: the hour is not known, so midnight UTC stands for it.
- The feature names are the constants in `internal/security/model.go`. The collector in `internal/tools` (the scan uses it) emits `tailscale_ssh` only, from the API's `sshEnabled` (read with `fields=all`; a device without the field has no fact) and from this node's `ssh` preference; the other three features are not observable and have no fact, so once a rule that requires one is approved a device in range is `potentially_affected` (`feature_unknown`). An API fact counts for these running-daemon rules only while the device is connected to control (decision D5).

`reviewed_at`, `source_checked_at` and each catalog's `issued_at` are 2026-10-30T00:00:00Z: the day of the check is known and the hour is not, so midnight UTC stands for it. `review_expires_at` and each catalog's `expires_at` are that time plus 90 days, 2027-01-28T00:00:00Z. Each catalog's `revision` is 1 and each record's `revision` is "1". The freshness test below covers these files too and starts to fail on 2027-01-14.

## Re-review

`TestShippedAdvisoriesAreNotNearExpiry` in `internal/advisory` reads every shipped `data/advisories/*.json` against the real clock and fails when the catalog `expires_at` or a record `review_expires_at` is past or within 14 days. With the dates above it starts to fail on 2027-01-14. To fix it, re-check the official bulletin, then update the dates and revisions in the JSON and in this file together.

## Semantics

Runtime daemon evidence and API-reported client versions remain distinct. API observations cannot prove the running daemon patched. Exact-byte digest is computed by the decoder; it does not authenticate the source. No source fetch renews the rule review.

Positive/negative and uncertain controls are in `internal/advisory/curated_test.go`; synthetic matching controls are in the security package. Each additional real rule needs source, rule and fixture review.
