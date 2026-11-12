# Security evidence packs

`tailkeeper security export --scope local|fleet` captures the inputs to a security scan in a private, reproducible evidence pack. Add `--access` to capture access evidence for the configured intent, or choose an intent with `--invariants FILE`; `--only` selects expectation IDs when access is requested. `--no-invariants` omits configured intent. Fleet collection and access evidence require a credential. Local export without access can collect without contacting the API.

A pack is private: it contains the facts and intent needed to reproduce the recorded decision. Keep it out of repositories and share a projection instead. The default location is the state directory's `packs` folder. `--out FILE` chooses a different path; its parent must already exist and be private. Output never goes to standard output, existing files are not overwritten, and symbolic links and repository destinations are refused. The pack directory is private, and pack and projection files are mode 0600. These commands are unsupported on Windows.

`tailkeeper security replay PACK` checks the pack's integrity and, when a privacy key is available, its seal. It re-evaluates the recorded inputs against the recorded catalog at the recorded evaluation time. Freshness at replay time is reported separately. A reproduced decision means the calculation was reproduced from the declared inputs. Every replay states:

> Replay reproduces a decision from the inputs the pack declares. It does not show that those inputs were true, that a host is uncompromised, or that anything is secure now.

Without the key, a sealed pack's seal is not checked. A pack with no seal is identified separately, including when a key is loaded.

`tailkeeper security redact PACK --out FILE` writes a shareable projection after successful replay. The projection excludes the private facts and is not itself replayable. Replay and redact do not resolve credentials; they load the privacy key only from the environment. Output is text or JSON, with paths subject to the current privacy setting.

Export records source collection and a required pack audit event before publishing the file. If recording fails, publication stops. If publication fails after the event was recorded, the audit can describe a pack that was never published. Replay and redact use the ordinary best-effort read audit; failure to append that record does not prevent a successful projection. A successful export means the pack was written and reproduced; it is not a security assessment gate.

Replay reports the embedded catalog's revision, dates, and counts. Its full catalog digest is shown only when it equals this binary's public shipped catalog digest. For another catalog, show mode displays only its first twelve hexadecimal digits; masked mode withholds it. Recorded intent and policy tokens are shown only when their form matches the current privacy setting, and then only in shortened form. Complete integrity, report, intent, and policy hashes remain in the private pack. This makes private catalog digests unavailable in masked output; comparisons that require the full recorded tokens use the private pack.

## Verify a correction

`tailkeeper security verify --before PACK --correction FILE [--invariants FILE]` compares a private baseline with fresh observations. It makes no changes to devices or policy. The command uses the configured credential and current shipped catalog; it never runs intent imported from the pack. The configured invariants file, or `--invariants FILE`, remains the intent authority.

The correction file is strict JSON, at most 64 KiB and eight levels deep. It requires schema version 1, an action time and between 1 and 256 targets. Unknown or duplicate keys, duplicate or conflicting targets, and policy-fact targets are refused. A finding target names its rule and device; an access target names a selected expectation ID. Expected versions and features name a device, component or feature, and an optional role (`running_daemon`, `local_cli` or `api_reported`). The default role is `running_daemon`. `at_least` requires a bare release such as `1.32.3`; `connected_to_control` cannot be an expected feature.

For example, this synthetic correction expects a daemon version at least `1.32.3` after the declared action:

```json
{
  "schema_version": 1,
  "action_at": "2026-11-05T10:15:00Z",
  "expect": {
    "versions": [
      {"device": "nEXAMPLE1CNTRL", "name": "client", "at_least": "1.32.3"}
    ]
  }
}
```

Use the actual device reference from `devices list` and an action time strictly after every observation and evaluation in the baseline. Targets that were already satisfied, targets absent from the baseline and wrong-context packs are refused before collection. A future action beyond the five-minute clock allowance is also refused.

An unreadable explicit `--invariants` file is rejected during flag parsing, before the evidence files are opened. When several inputs are invalid, that flag error can be reported first. No collection occurs.

Verification reports `fixed`, `not_fixed` or `incomplete` for each target. `fixed` requires a fleet-scope baseline, matching context and key epoch, and fresh decision evidence strictly after the action, including the connection evidence that lets API observations speak for a daemon. An old API version still contradicts an expected upgrade when a device is disconnected; a new API version without current connection evidence cannot establish that the daemon was upgraded. A changed or removed targeted rule cannot establish a fix. Changes to other rules are reported separately.

Every access expectation selected in the baseline is accounted for. Current expectations whose content still matches are rerun together. Edited or missing intent, stale or pre-action access collection, substituted access input and missing judgements make the affected rows incomplete. A selected expectation that is unmet after collection blocks success, even when it was not a correction target. Unchanged limits and unchanged unconfirmed expectations do not themselves block success. An unconfirmed or unmet baseline becoming met with limits is an improvement; a loss or new limits on previously confirmed access block success.

A missing baseline seal while a privacy key is loaded caps a prospective success at `incomplete`. With no key, the seal state is reported without claiming authentication. Verification appends a required metadata-only pack audit record before returning any result; a failed append produces an audit error instead of an unaudited success.

Exit 0 means all correction targets were fixed and no selected access guard blocks success. Exit 8 means a target is not fixed or a selected expectation is unmet; it takes precedence over incomplete rows. Exit 1 means incomplete verification without an exit-8 result. Invalid input is exit 2; credential, configuration and audit errors retain their existing codes. Text and JSON output apply the current privacy setting. Verification is stateless and creates no lifecycle or notification transition. The replay scope statement above applies: these observations cannot establish that a host is uncompromised or secure now.

The synthetic CLI correction exercise uses the fake API and runs with `go test ./internal/cli -run '^TestSecurityVerifyCorrectionDemo$' -count=1`. It does not contact a live tailnet. Production-binary command and MCP exclusion checks are separate from the injected fake-API CLI exercise.
