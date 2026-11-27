# macOS MCP bundle: verification and acceptance

The macOS MCPB, shipped from 0.7.0, is a universal bundle containing amd64 and arm64 executable slices. Its manifest uses MCPB schema version `0.3`, declares `darwin`, and starts `server/tailkeeper` with `mcp`. The manifest's package `version` is the release version without the leading `v`; the release binary reports that version with the `v`. The OS declaration is not a CPU selection field. Two slices in a file do not establish runtime acceptance on both CPUs.

**Narrow ARM64 host acceptance has been observed for an unsigned local snapshot.** It establishes that Claude Desktop 4.23118.0 on macOS 27.2 build 26B123 ARM64 recognized, installed, ran, and removed this package in a disposable VM. **A signed release bundle, v0.7.0, has since been verified, installed and run once** on the owner's own ARM64 Mac, which was not an isolated host ([below](#observed-signed-release-acceptance-v070)). Neither record establishes Intel runtime behavior or Windows behavior. Use the [direct-binary route](../../README.md#install) when host acceptance is not established for your platform and package.

## Verify before opening

When a published release actually supplies an MCPB, obtain the bundle, `checksums.txt`, and `checksums.txt.sigstore.json` for the same release. Follow [Verify a release](../../README.md#verify-a-release) in order, setting `VERSION` to its actual tag and `ARCHIVE` to the exact MCPB filename. Require the checksum signature, the exact named checksum, the bundle provenance attestation and the checksum-file provenance attestation all to pass before opening the bundle. Stop on a missing asset or failed check. The existing release workflow signs checksums and attests the subjects it lists; a local snapshot is not signed or attested. This document does not assert that a bundle has been published, signed, or attested.

## External configuration

The bundle does not configure a tailnet or embed credentials. Useful API reads require native configuration and a suitable credential provider. On macOS the user configuration is `~/Library/Application Support/tailkeeper/config.hujson`; `/etc/tailkeeper/config.hujson`, when present, wins outright rather than merging with it. `tailkeeper doctor` reports the selected file. The audit log is in `~/Library/Logs/tailkeeper/`. See the [configuration and provider reference](../../README.md#credential-providers) for permissions and alternatives.

A `file` provider uses an absolute credential-file path. An `exec` provider uses an argument list with an absolute wrapper path. These remain external to the bundle. With `exec`, a complete inherited API credential or OAuth client pair is accepted before tailkeeper requests its wrapper; do not assume a locked wrapper is always invoked. A locked-wrapper refusal trial is meaningful only with inherited Tailkeeper credential, reexec and privacy inputs absent. For the locked-provider phase below, Claude was launched with a minimal environment and those inputs absent; the wrapper subsequently observed tailkeeper’s reexec marker. General host environment inheritance remains unestablished.

## Observed ARM64 snapshot acceptance

The following is a bounded host acceptance record for one unsigned local snapshot, not a release verification or general provider behavior guarantee.

| Item | Observed result |
| --- | --- |
| Package | `v0.6.0-SNAPSHOT-de4f25e`; SHA-256 `5eae8677f8bb7d7d7f4b2ba91715c7e34f570f83ccb8abbad0e640119c1584c1` |
| Host | Claude Desktop 4.23118.0; macOS 27.2 build 26B123; ARM64; disposable Apple Silicon VM |
| Manifest and install | Opening the `.mcpb` in Finder opened the install dialog; it showed “All requirements met.” The owner installed it. Claude showed the extension Installed, Enabled, and Running. The dialog warned about access to the guest computer and an unverified developer. |
| Managed server and tool call | Claude showed the extension-managed server path and `mcp` argument, discovered `tailkeeper_info`, and returned the inspected raw structured response: name `tailkeeper`, version `v0.6.0-SNAPSHOT-de4f25e`, OS `darwin`, architecture `arm64`, and empty `reportSchemas`, `catalogSchemas`, and `assessmentCapabilities` arrays. Tool discovery was observed; no independently enumerated full tool count is claimed. |
| Audit | `audit tail -n 5` showed `tailkeeper_info`; `audit verify` printed one line reporting an intact chain. The audit log itself was not read directly. |
| Locked synthetic exec-provider refusal | With a fixed minimal environment and synthetic external config/wrapper, the wrapper confirmed credential and privacy inputs absent and its reexec marker present, then exited 53 without starting a child. Claude showed the extension failed to start; the scoped host log had the fixture's locked-provider message and no tailkeeper process remained. |
| Uninstall and preservation | In the extension `…` menu, Uninstall followed by confirmation removed the managed bundle directory; no tailkeeper process remained. Hashes of the synthetic external config, preserved direct binary, and external state file were unchanged; the direct binary remained executable and reported the expected version. |
| Reinstall | Reopening the same package reinstalled it. The restored executable was byte-identical to the preserved binary. The preserved locked config again produced the expected refusal, and external hashes remained unchanged. |

The tested UI route was **Settings > Desktop app > Extensions > Manage**. For installation, opening the `.mcpb` in Finder displayed the confirmation dialog described above. For removal, use the extension's `…` menu and confirm Uninstall. The same package and refusal were checked after reinstall. Do not treat this local snapshot trial as satisfying the signed checksum and provenance requirements above.

This trial supplied no credentials and made no live Tailscale reads. The locked-provider phase launched Claude with a minimal environment in which credential, reexec, and privacy inputs were absent; the wrapper later observed the expected reexec marker. This does not establish general host environment inheritance. The refusal wrapper never executes its appended server arguments. This trial established no Intel runtime and no signed-release acceptance (the signed v0.7.0 bundle is recorded below). Successful credential-dependent calls remain supported by the injected fake-API harness, not inferred from this host trial.

## Observed signed release acceptance (v0.7.0)

A bounded record of one install of the published v0.7.0 bundle on 27 Nov 2026. It is not a general host guarantee.

| Item | Observed result |
| --- | --- |
| Package | `tailkeeper_0.7.0_darwin_universal.mcpb` from the v0.7.0 release; SHA-256 `3ce349a7c4aafe1f5bf1405799cf7f6a8cea9fe7240c58eb90923431eb2930e6` |
| Release verification | As [Verify a release](../../README.md#verify-a-release) says: `cosign verify-blob` over `checksums.txt` printed `Verified OK`; the bundle's line of `checksums.txt` checked `OK`; `gh attestation verify` exited 0 for the bundle and for `checksums.txt`. That command printed nothing on success in this shell, so it was confirmed with `--format json` (an attestation whose subjects include the bundle) and with a tampered copy, which failed with exit 1. |
| Host | Claude Desktop 6.28899.6; macOS 27.2.1 build 26B131; ARM64; the owner's own Mac with their existing configuration, not a disposable VM |
| Install | Opening the bundle with Claude Desktop showed the install dialog, which warned that installing grants the extension access to everything on the computer and that the developer information is not verified by Anthropic. The owner installed it, and the extension showed Enabled. |
| Tool call | `tailkeeper_info` returned version `v0.7.0`, OS `darwin`, architecture `arm64`, and empty `reportSchemas`, `catalogSchemas` and `assessmentCapabilities`. |
| Audit | `audit tail -n 5` showed the `tailkeeper_info` call, requester kind `mcp`, status `ok`; `audit verify` reported the chain intact. |
| Not covered | Uninstall and reinstall, a call that needs the credential, Intel, an isolated host. |

The host's model read the three empty lists as meaning that `security_scan` had nothing to run, although `security_scan` ships in this release: the lists name only published schemas, and the report schema is not yet published (the field text in 0.7.0 still says they stay empty until an assessor ships; from 0.7.1 it says `security_scan` runs regardless).

## Future host trials

Record outcomes and exact errors without credential values, real identifiers, addresses, hostnames or private configuration contents. Do not read existing private user configs. For each package and platform, record the exact version and digest, macOS/CPU, host version and isolation, provider and executable mode, signed release verification results, install and tool-call behavior, uninstall/reinstall behavior, and preservation of external config/state sentinels. Verify the inherited credential, reexec, and privacy input conditions before interpreting a locked fake-provider refusal. Record actual CPU; Intel runtime acceptance requires a trial on Intel hardware. If the host cannot load the manifest or an expected environment is absent, record the exact error and retain the direct-binary route.

Any unlocked fake-wrapper trial remains limited to initialize, tools list, `tailkeeper_info`, and a private wrapper marker. Successful credential-dependent calls are exercised only by the injected fake-API harness, not inferred from that host trial. Remove only host-managed bundle files during uninstall trials; preserve external configuration and state unless the owner separately requests their removal. Installing a bundle does not establish or schedule recurring checks.
