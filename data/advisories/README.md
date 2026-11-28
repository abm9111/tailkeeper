# Reviewed advisory inputs

`cve-2022-41925.json` is one deliberately narrow historical rule, not a complete Tailscale advisory catalog. `ts-2026-014.json` to `ts-2026-017.json` are four rules approved by the owner on 2026-11-28 (see below). It is data for the matcher that `tailkeeper security scan` and the MCP tool `security_scan` run, embedded in the binary (see below); no automatic acquisition or activation of other catalogs is installed.

## Shipped in the binary

Every `*.json` file directly in this directory is embedded (`data/advisories/embed.go`; `testdata/` and this README are not) and merged by `advisory.Shipped` into the one catalog a scan judges by. Each file is decoded by the checked decoder first, and a file that fails refuses the whole catalog: there is no partial one. The merge keeps the earliest `expires_at` of any file (so the catalog is stale as soon as any file is), the latest `issued_at` and the highest `revision`; a rule ID that two files hold, a file name given twice, or files whose windows have no instant in common (one issued after another expires) is refused. The digest is the SHA-256 of the sorted lines `name:digest`, one per file with the decoder's digest of its exact bytes, so a change to any byte of any file, or to a name, changes it. The merge keeps each rule's review state as its file gives it: a rule a file leaves `pending` stays pending, and a new rule starts there until the owner confirms the bulletin text. A new file in this directory is part of the next build without any other edit, and the freshness test below reads the same glob, so it is covered too.

## Provenance

The re-check of the [official bulletins](https://tailscale.com/security-bulletins#ts-2022-005) was done on 2026-11-28 at 08:35Z. The owner delegated it, and Claude (Opus 5.5) performed it by fetching the bulletins' RSS feed (`https://tailscale.com/security-bulletins/index.xml`) live (no cached copy) and reading it. The text of TS-2022-005 (CVE-2022-41925) and of TS-2026-014 to TS-2026-018 in the feed was identical to what the check of 2026-11-27 (about 18:22Z, which read the bulletins page and its feed) had read; only the feed's build date had changed. The bulletin of CVE-2022-41925 says, as it did at the previous checks on 2026-10-30 and 2026-11-27:

- it is TS-2022-005, dated 2022-11-21, for CVE-2022-41925, with severity Low;
- the affected platforms are all platforms, and all Tailscale clients before v1.32.3 are affected;
- the patched client versions are v1.32.3 or later, and v1.33.257 or later on the unstable track.

The rule models the stable track only: the client, as the running daemon, is affected before the exclusive fixed endpoint 1.32.3, and the absent introduced endpoint is open. The unstable fix at 1.33.257 is outside the version grammar the matcher accepts, so unstable, prerelease, development and downstream versions remain unknown. The rule carries no `published_at` or `updated_at`.

## Dates and revisions

`reviewed_at`, `source_checked_at` and the catalog `issued_at` are the time of that check, 2026-11-28T08:35:00Z. `review_expires_at` and the catalog `expires_at` are that time plus 90 days, 2027-02-26T08:35:00Z. The catalog `revision` is 4 and the record `revision` is "4".

Revision 1 (reviewed 2026-10-28) rested on a cached copy of the bulletin and carried no source-check time; the retrieval date its README stated came after its review date. Revision 2 (checked 2026-10-30 at about 16:12Z in the owner's browser) replaced it. Revision 3 renewed revision 2 after the check of 2026-11-27 found the bulletin unchanged. Revision 4 renews revision 3 after the check above found the bulletin unchanged; the rule itself is unchanged. The four TS-2026 files have a revision of their own, counted in the section below, so the merged catalog's `revision`, the highest of the five, is 4.

## Rules TS-2026-014 to TS-2026-017, approved

`ts-2026-014.json` to `ts-2026-017.json` hold one rule each. They come from four Tailscale security bulletins of 2026-10-26 (TS-2026-014 to TS-2026-017), as read on the [bulletins page](https://tailscale.com/security-bulletins) on 2026-10-30, again, unchanged, on 2026-11-27, and once more, unchanged, in the feed at the check of 2026-11-28 above. Until 2026-11-28 every one of them was `pending`: the matcher gave `unknown` for every device and attached no mitigation text. The four rules were approved by the owner on 2026-11-28 (`review_state` is `approved`), after a comparison of each rule with its bulletin as read at that check.

What the bulletins say, and so what the rules say:

| Rule | Issue | Required features |
|---|---|---|
| TS-2026-014 | Tailscale SSH forwarding to Unix sockets as root, where policy allows forwarding | `tailscale_ssh`, `ssh_forwarding_allowed` |
| TS-2026-015 | Tailscale SSH session memory exhaustion, ending in an out-of-memory kill of `tailscaled` | `tailscale_ssh` |
| TS-2026-016 | Serve with Unix-socket backends can reach privileged sockets, the local API among them | `serve_unix_backend` |
| TS-2026-017 | Serve over HTTP/2 mixes app-capability headers across mounts, with TLS and two or more mounts | `serve_tls_multi_mount` |

- All four are fixed in 1.104.4 and newer, and none has a CVE. The client, as the running daemon, is affected below the exclusive fixed endpoint 1.104.4.
- The bulletins publish no lower bound and no backport. Each range is `{"fixed": "1.104.4"}` alone: `introduced` is open, and a 1.102.x release is in range. No lower bound or 1.102.x fix is to be added without the bulletin saying so.
- The bulletins give no severity, so `severity` is `unknown`. An unknown severity is above every threshold, so a finding of these rules that is `affected` or `potentially_affected` counts at every `--threshold` and makes `security scan` exit 8.
- `published_at` is 2026-10-26, a day: the hour is not known, so midnight UTC stands for it.
- The bulletin of TS-2026-014 also gives a mitigation: setting `TS_SSH_DISABLE_FORWARDING=1` in the `tailscaled` service environment and restarting the service disables SSH forwarding without disabling Tailscale SSH. The rule's `mitigation` text says so after the sentence to update; the mitigation text of the other three is that sentence alone. The matcher attaches it to `affected` and `potentially_affected` findings only.
- The feature names are the constants in `internal/security/model.go`. The collector in `internal/tools` (the scan uses it) emits `tailscale_ssh` only, from the API's `sshEnabled` (read with `fields=all`; a device without the field has no fact) and from this node's `ssh` preference. The other three features (`ssh_forwarding_allowed`, `serve_unix_backend`, `serve_tls_multi_mount`) are not observable and have no fact. An API fact counts for these running-daemon rules only while the device is connected to control (decision D5).

Two rules are broader than their bulletins, and the owner accepted both over-approximations:

- TS-2026-016: the bulletin also conditions the issue on a local operator who can write the Serve configuration or the backend paths, which tailkeeper cannot observe. The rule requires `serve_unix_backend` alone.
- TS-2026-017: the bulletin concerns Serve with TLS and two or more mounts whose capability requirements differ. The rule requires `serve_tls_multi_mount` and does not check that the requirements differ.

What approval changes for a scan, given what the collector observes:

- A running daemon at 1.104.4 or later is `not_affected` by all four rules, whatever the features say.
- A running daemon below 1.104.4 is `affected` when every feature the rule requires is known on, `not_affected` when one is known off, and otherwise `potentially_affected` (`feature_unknown`). Only `tailscale_ssh` is ever known, so TS-2026-015 gets a verdict from it; TS-2026-014 is cleared by `tailscale_ssh` known off and is otherwise `potentially_affected`; TS-2026-016 and TS-2026-017 are `potentially_affected` for every such device, whatever it runs.
- A version the API reports, for a device that is not shown connected to control, does not establish what the daemon runs: below 1.104.4 it is `potentially_affected` (`runtime_unobserved`) and at 1.104.4 or later it is `unknown` (`runtime_unobserved`), never cleared.
- These rules do not make a scan by the shipped catalog complete. The features coverage row stays `partial` and names the three features no source gives, as it did while the rules were pending, and every `potentially_affected` or `unknown` finding keeps the catalog row partial. A scan by the shipped catalog therefore exits 8 when an `affected` or `potentially_affected` finding is at its threshold and 1 otherwise, never 0, until some source observes those three features.

`reviewed_at`, `source_checked_at` and each catalog's `issued_at` are 2026-11-28T08:35:00Z, the time of the check above, which found the text of each bulletin identical to the check of 2026-11-27. `review_expires_at` and each catalog's `expires_at` are that time plus 90 days, 2027-02-26T08:35:00Z. Each catalog's `revision` is 3 and each record's `revision` is "3" (revision 1 was checked on 2026-10-30, at midnight UTC for an unknown hour; revision 2 renewed it on 2026-11-27 and left the rules pending; revision 3 is the approval). The freshness test below covers these files too and starts to fail on 2027-02-12 at 08:35 UTC.

Not modelled: TS-2026-018 (2026-11-12) concerns the Tailscale Kubernetes operator's dedicated API server proxy, fixed in 1.104.7. It is not a client rule, and the collector has no fact for that deployment, so no file holds it; adding one needs the source, rule and fixture review below.

## Re-review

`TestShippedAdvisoriesAreNotNearExpiry` in `internal/advisory` reads every shipped `data/advisories/*.json` against the real clock and fails when the catalog `expires_at` or a record `review_expires_at` is past or within 14 days. With the dates above it starts to fail on 2027-02-12 at 08:35 UTC. To fix it, re-check the official bulletin, then update the dates and revisions in the JSON and in this file together, and the pins of `TestShippedTS2026RulesAreAsReviewed` in `internal/advisory/ts2026_test.go` (`ts2026Now`, the issue time and the revisions); state the new expiry and warning dates in `CHANGELOG.md` and `docs/security/known-limits.md`, which no test ties to the JSON.

## Semantics

Runtime daemon evidence and API-reported client versions remain distinct. API observations cannot prove the running daemon patched. Exact-byte digest is computed by the decoder; it does not authenticate the source. No source fetch renews the rule review.

Positive/negative and uncertain controls are in `internal/advisory/curated_test.go`; synthetic matching controls are in the security package. Each additional real rule needs source, rule and fixture review.
