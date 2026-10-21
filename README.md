# tailkeeper

A Tailscale command line and MCP server for agents and the people who supervise them.

**Status: 0.x pre-release, read-only.** tailkeeper reads the Tailscale API (28 tools, two of them for alpha features, which MCP lists only with `--enable-alpha`) and this node's Tailscale state (15 tools). It cannot change a tailnet: apart from the credential's own token request, the only API request it sends other than GET is `POST .../acl/validate`, which tests the live policy and which Tailscale documents as never changing it, and the API client refuses any other. Write tools arrive in milestone M2, behind an approval gate. Until 1.0, a minor release may change the CLI or the MCP tool list (see `CHANGELOG.md`).

**Personal mode protects against misuse through tool calls, not against code that runs as you.** tailkeeper runs as your user, so an agent with an unsandboxed shell can rewrite its configuration and audit log. Run your agent in a sandbox that cannot write tailkeeper's configuration directory. Hardened mode, which moves tailkeeper to its own service account, is on the roadmap.

## What it does differently

- **One registry, two surfaces.** Every tool is an MCP tool and a CLI command with the same parameters, validation and output. MCP lists the alpha tools only with `--enable-alpha`.
- **Allowlisted output.** Responses are decoded into tailkeeper's own types. Key material, invite links, webhook secrets and login URLs are never returned, and the fields that hold devices' public endpoints are dropped. Webhook and log-stream URLs are cut to scheme and host plus a hash of the path, wherever they appear, the audit log's target names and properties, details, errors and value previews and a log stream's last delivery error included; in those previews, a string, number, object or array under a key that names a credential (token, secret, password, API key and the like) is removed, and `true`, `false` and `null` stay, whether the key sits in a JSON document, in a string that holds one, or in a policy file's HuJSON (comments, also before the first brace and after the last, a byte order mark and trailing commas; text that is neither JSON nor HuJSON, such as a truncated or doubled document, a document with other text before or after it (`{"token":"X"} x`) or `key=value` pairs, stays as written). That cut is best effort: `SECURITY.md` lists the shapes it leaves whole. `audit_log`'s `target` filter reads the target as shown, so it cannot confirm a guess at a path. A tripwire withholds any result that still contains a Tailscale key or a JWT.
- **Untrusted text is marked.** Every string is escaped before it is shown; only the policy text of `acl_get` keeps its line feeds and tabs, and the CLI prints it behind line numbers, after a notice that it is untrusted, as it does Tailscale's reasons in `acl test`. Names, tags and messages come from the tailnet: they are also capped, have Tailscale key and JWT shapes replaced, are flagged in output schemas (`x-tailkeeper-untrusted`) and are called out to the model.
- **Least privilege.** One read credential with read scopes only. `tailkeeper doctor` fails when the credential shows a write scope and warns for an API access token. tailkeeper never reads `TS_*` or `TAILSCALE_*` variables.
- **Personal data masked by default.** Login names, display names, email addresses and users' tailnet IDs come back cut to their first character (`a…@example.com`); the owner name Tailscale gives tagged devices, `tagged-devices`, names no person and stays whole. In all other text from the tailnet, and in the error messages of tool calls, email addresses are masked the same way and public IP addresses are cut to their /24 or /48 network. Set `"personalData": "show"` in the configuration to see them whole. Masking reduces what a model sees by default; it does not hide everything:
  - Device names and hostnames are not masked as personal names are (every other tool needs them, and they often contain a first name); an email address or a public IP address written inside one is masked like any other text, so look a device up by its node ID.
  - Configuration a diagnosis needs stays whole: DNS resolvers and answers, routes, a webhook's or log stream's host, OAuth redirect URIs, the policy file's external link, and local preferences other than the operator and nickname. `docs/tools.md` lists these fields per tool.
  - Free text is masked by pattern, as a best effort: a name written in it, or an address in an unusual form, is not found.
  - Masking reads email addresses written with `@`, its JSON escape and `%40`, and IP addresses in their usual written forms; the forms it does not recognise are listed under Known limits in `SECURITY.md`. The name of a synced group (`group:engineering@example.com`) is left whole wherever masking runs, in the policy, in free text and in error messages.
  - The policy file (`acl_get`) masks email addresses only: host names, tags, groups, SSH users, addresses and comments stay whole (with a privacy key, a `[p:` the policy holds is shown with its bracket spelled out, so a marker on the page is one tailkeeper appended), and the whole policy, your access topology, goes to the model provider whenever an agent reads it. While masking is on, `acl_get` leaves out the policy's ETag and gives the size and SHA-256 of the policy as shown, every page joined: those of the file itself would confirm a guessed address.
  - With a privacy key configured, every masked name and address in a result ends in a pseudonym such as `[p:k7x2m9qd4a]`, the same in every call. Filters take that pseudonym. The error messages of tool calls, and the reasons `acl_test` returns, are masked without pseudonyms: they echo what the caller typed, and a pseudonym beside a guess would confirm it. While masking is on, filters that would confirm a guess are refused (`filter_refused`): a typed login in `devices_list`'s `user` (`tagged-devices` is accepted), a `hostname` in `devices_list` that masking would change (an email address, a public IP address, or text that looks like one; use the node ID for such a device), a `~search` or an address in `audit_log`'s `actor`, and anything but an exact ID in its `target`. `audit_log`'s old and new values come back as keyed digests, or not at all without the key. `acl_test` still confirms what a guessed user may reach.
- **Audited reads.** A hash-chained JSONL log records which tool ran, for whom, and how much it returned, never the values. Nothing is deleted from it: `tailkeeper audit rotate` verifies the log, keeps it beside the new one as an archive until you delete it, and starts the new log with an entry that records where the archive ends. `tailkeeper audit verify` checks the log and every archive it continues. `tailkeeper doctor` suggests a rotation once the log passes 64 MiB. Rotation is not available on Windows yet.
  `tailkeeper audit verify` checks that the lines present chain correctly. It cannot tell that lines were removed from the end of the log, that the log was deleted and started again, or that an archive was deleted (it says so, warns, and exits 0). A read whose line cannot be written (the lock held for more than 2 seconds, an unreadable log, a full disk) is not recorded, and tailkeeper warns on standard error. tailkeeper does not log its own start-ups or configuration changes, so setting `audit.reads` to `none` leaves no trace in the log.

## Install

Download the archive for your platform (macOS and Linux on amd64 and arm64, Windows on amd64) from the [latest release](https://github.com/abm9111/tailkeeper/releases/latest), verify it (next section), then put `tailkeeper` on your `PATH`, for example in `~/.local/bin`.

On Windows the archive is a `.zip`, and the Windows build differs: it has no `exec` provider (start tailkeeper under your secret manager's run command and use the `env` provider), it does not check the owner or permissions of the configuration and credential files (`tailkeeper doctor` warns), and it cannot rotate the audit log. The audit log has no lock between processes there, so two tailkeeper processes writing at the same moment can break its chain. [docs/windows.md](docs/windows.md) lists every difference and the tests that do not run on Windows.

With Go 1.27.3 or later, `go install github.com/abm9111/tailkeeper/cmd/tailkeeper@latest` also works; that binary reports `tailkeeper dev` instead of its version, and it is built on your machine rather than by the release workflow, so the checks below do not apply to it.

From a clone, `make install` runs the gate (`make verify`), then installs the binary as `~/.local/bin/tailkeeper` (set `BINDIR` to change the directory). It refuses uncommitted changes, so `tailkeeper version` always names a commit. Point MCP hosts at the installed binary, not at `bin/tailkeeper`: `make build` rewrites `bin/` on whatever branch is checked out.

## Verify a release

Every release is built by `.github/workflows/release.yml` from a signed tag. `checksums.txt` lists the SHA-256 of every archive and SBOM. A [cosign](https://docs.sigstore.dev/) keyless signature over it (`checksums.txt.sigstore.json`) proves that file came from that workflow, and a GitHub build-provenance attestation covers each file it lists; a second attestation step covers `checksums.txt` itself, which cannot list its own hash. Download the archive, `checksums.txt` and `checksums.txt.sigstore.json`, then run these lines in order and stop at the first one that fails (a shell does not stop for you when you paste them, so a later line can succeed after an earlier one failed):

```
VERSION=v0.5.0
ARCHIVE=tailkeeper_${VERSION#v}_darwin_arm64.tar.gz   # the archive you downloaded
IDENTITY="https://github.com/abm9111/tailkeeper/.github/workflows/release.yml@refs/tags/$VERSION"

cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
line="$(awk -v f="$ARCHIVE" '$2 == f' checksums.txt)"   # the line of checksums.txt that names your archive
if [ -n "$line" ]; then printf '%s\n' "$line" | shasum -a 256 -c -; else echo "no line for $ARCHIVE in checksums.txt" >&2; false; fi   # Linux: sha256sum -c -
gh attestation verify "$ARCHIVE" --repo abm9111/tailkeeper --cert-identity "$IDENTITY"
gh attestation verify checksums.txt --repo abm9111/tailkeeper --cert-identity "$IDENTITY"
```

All of these must succeed. `cosign` (version 3; the release is signed with 3.1.3) must print `Verified OK`. The checksum step must say `<archive>: OK`. `FAILED` means the archive is not the one the release built. `no line for <archive> in checksums.txt` means `checksums.txt` has no line named exactly like your archive, because you renamed it or downloaded another file, and the step exits 1. Do not use the archive in either case. The step looks for the line itself because the `sha256sum` that macOS ships prints nothing and exits 0 when it is given no checksum line; use `shasum -a 256 -c -` on macOS and `sha256sum -c -` on Linux. `gh attestation verify` must exit 0; on a terminal it also prints `Verification succeeded!` and names `abm9111/tailkeeper` as the build repository, and when its output is piped it prints nothing, so read the exit status. The signature ties `checksums.txt` to the workflow, the checksum ties your archive to `checksums.txt`, and the attestation ties your archive to the workflow on its own. On Windows, `Get-FileHash -Algorithm SHA256 <archive>` prints the hash to compare with the archive's line in `checksums.txt`.

Each archive has a CycloneDX SBOM beside it (`<archive>.sbom.cdx.json`), listed in `checksums.txt` like the archive. Do not run a binary whose checks fail; report it as described in `SECURITY.md`.

You can also rebuild a release rather than trust the workflow's build. Releases are built with GoReleaser, at the version the repository pins (the command below), and the Go toolchain named in `go.mod`; a binary rebuilt from a git clone at the tag, in the same shell as above, is byte-identical to the one inside the archive. The release workflow rebuilds every binary on a second architecture and compares them before it publishes.

```
git clone --branch "$VERSION" https://github.com/abm9111/tailkeeper.git
cd tailkeeper
GOTOOLCHAIN="$(awk '$1 == "toolchain" { print $2 }' go.mod)" \
  go run github.com/goreleaser/goreleaser/v2@v2.18.2 build --clean
tar -xzOf /path/to/"$ARCHIVE" tailkeeper | cmp - dist/tailkeeper_darwin_arm64*/tailkeeper && echo identical
```

## Configure

1. In the Tailscale admin console, create an OAuth client with read scopes only. `tailkeeper scopes` prints the scopes, and which tools need each (also in `docs/scopes.md`).
2. Write the configuration, mode 0600, to `~/Library/Application Support/tailkeeper/config.hujson` on macOS or `~/.config/tailkeeper/config.hujson` on Linux (other locations are listed under Configuration reference):

```hujson
{
  "contexts": {
    "home": {
      "tailnetId": "T1234CNTRL", // the tailnet ID from the admin console's General settings
      "credentials": {
        "read": {
          // An absolute path to a wrapper that sets TAILKEEPER_READ_CLIENT_ID and
          // TAILKEEPER_READ_CLIENT_SECRET, then runs the rest of its arguments.
          // tailkeeper re-runs itself under it, so the secret never reaches your shell.
          "provider": "exec",
          "command": ["/usr/local/bin/read-secrets", "--"]
        }
      }
    }
  }
}
```

`docs/recipes/` shows wrappers for two secret managers. A wrapper is any program that puts the two variables (and `TAILKEEPER_PRIVACY_KEY`, below) in the environment of the command it runs, without printing them.

tailkeeper refuses a key it does not know, a key written twice and a key whose letter case differs, so a typo is an error, not a setting that does nothing.

3. Run `tailkeeper doctor`. It checks the configuration's permissions, the credential's scopes and expiry, the privacy key, the local `tailscale` CLI, and the audit log.

### Credential providers

`credentials.read.provider` says where the read credential comes from. Every provider reads the same variables: `TAILKEEPER_READ_CLIENT_ID` and `TAILKEEPER_READ_CLIENT_SECRET` for an OAuth client (recommended), or `TAILKEEPER_READ_API_KEY` for an API access token (`doctor` warns: such a token carries its owner's full permissions); never both. A value may be `file:/absolute/path`, which is read and trimmed; that file is read by name, with no check of its owner or permissions (`SECURITY.md`), so keep it mode 0600 in a directory only you can write. `TAILKEEPER_PRIVACY_KEY` sits beside them. tailkeeper never reads `TS_*` or `TAILSCALE_*` variables.

| Provider | Fields | Where the secret comes from |
|---|---|---|
| `env` | none | tailkeeper's own environment. The simplest, but the variables then reach every process that environment starts; on a workstation prefer `exec` or `file`. |
| `file` | `path`, absolute | a file of `NAME=value` lines (`#` comments and blank lines ignored, surrounding quotes trimmed). On macOS and Linux it must be a regular file with no group or other access (mode 0600), owned by you or root, in a directory owned by you or root that no group or other user can write; otherwise `config_unsafe`. |
| `exec` | `command`: an argument list whose first element is an absolute path | a wrapper that sets the variables, then runs the rest of its arguments (the example above, and `docs/recipes/`). tailkeeper re-runs itself under it, so the secret never reaches your shell. Not available on Windows: start tailkeeper under the wrapper yourself and use `env`. |
| `oidc` | `clientId` (required), `audience` (default `api.tailscale.com/<clientId>`), `tokenFile` (absolute path) | no stored secret: a workload identity token, read from `tokenFile`, else from GitHub Actions (`ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`; the job needs `permissions: id-token: write`), else from `TAILKEEPER_OIDC_TOKEN`, and exchanged for a Tailscale token. With no stored secret there is no privacy key, so masked values carry no pseudonyms. |

```hujson
// env: the variables are in the environment of whatever starts tailkeeper
{"contexts": {"home": {"tailnetId": "T1234CNTRL", "credentials": {"read": {"provider": "env"}}}}}
```

```hujson
// file
{"contexts": {"home": {"tailnetId": "T1234CNTRL", "credentials": {"read": {"provider": "file", "path": "/path/to/read.env"}}}}}
```

```hujson
// oidc, for example in a GitHub Actions job
{"contexts": {"ci": {"tailnetId": "T1234CNTRL", "credentials": {"read": {"provider": "oidc", "clientId": "kFED1CNTRL"}}}}}
```

### Privacy key

Put `TAILKEEPER_PRIVACY_KEY`, 64 hexadecimal characters (`openssl rand -hex 32`), where the read credential is kept: the environment for the `env` provider, the wrapper's secret store for `exec`, the credential file for `file`. The `oidc` provider stores no secret, so it has no privacy key, and masked values there carry no pseudonym. tailkeeper derives two keys from it and never shows it. Pseudonyms appear in results only: the error messages of tool calls are masked without them, because an error echoes what the caller typed. Without it, masking still works, but masked values carry no pseudonym, a pseudonym filter fails with `privacy_key_unavailable` (exit 5), and `audit_log` leaves out its digests. Replacing the key changes every pseudonym. `tailkeeper doctor` reports whether it is loaded.

### Configuration reference

| Key | Values |
|---|---|
| `contexts.<name>` | one per tailnet; the name starts with a lower-case letter or digit, continues with lower-case letters, digits, `_` and `-`, and has at most 32 characters |
| `contexts.<name>.tailnetId` | the tailnet ID from the admin console's General settings (never `-`) |
| `contexts.<name>.credentials.read` | a provider block, above |
| `contexts.<name>.credentials.read.provider` | `env`, `file`, `exec` or `oidc` |
| `contexts.<name>.credentials.read.command` | `exec`: the wrapper and its arguments. tailkeeper checks that the list is not empty and that its first element is an absolute path, and nothing else; it runs the list followed by its own binary and arguments. A last element `--`, which ends the wrapper's own options so that it takes the rest as the command to run, is the convention of the recipes in `docs/recipes/`: their test checks it, tailkeeper does not check it in your configuration |
| `contexts.<name>.credentials.read.path` | `file`: the absolute path of the credential file |
| `contexts.<name>.credentials.read.clientId` | `oidc`: the federated identity's client ID (not a secret) |
| `contexts.<name>.credentials.read.audience` | `oidc`: the token's audience; `api.tailscale.com/<clientId>` when left out |
| `contexts.<name>.credentials.read.tokenFile` | `oidc`: the absolute path of a file that holds the identity token |
| `defaultContext` | the context to use when none is named |
| `local.tailscaleBinary` | absolute path of the `tailscale` CLI; otherwise the first of its usual install locations that exists |
| `local.socket` | absolute path of tailscaled's socket, passed to the CLI as `--socket` |
| `local.dnsQueryAllowlist` | names, or suffixes written with a leading dot, that `tailkeeper local dns-query` may resolve besides the tailnet's MagicDNS suffix |
| `mcp.profile` | `reads` (the default), `core` or `full` (the same tools in 0.x) |
| `mcp.enableAlpha` | `true` also advertises the tools for alpha Tailscale features |
| `audit.reads` | `metadata` (the default: which tool ran, for whom, how much it returned) or `none` |
| `acl.invariantsFile` | absolute path of the invariants file the policy checks add to every validation; unset by default. No command reads it yet. A path that is set and cannot be read fails every call that uses it. A 0.5.0 binary refuses this key, so set it in a context only 0.6.0 uses |
| `acl.validatePerMinute` | a whole number from 1 to 120 (default 30): how many policy validation requests one tailkeeper process decides to send per minute (a retry of a request takes no token). A 0.5.0 binary refuses this key |
| `personalData` | `mask` (the default) or `show` |

The context is chosen by `--context NAME` (before the command, or after `mcp`), then `TAILKEEPER_CONTEXT`, then `defaultContext`, then the only context there is. A system configuration, `/etc/tailkeeper/config.hujson` (Windows: `%ProgramData%\tailkeeper\config.hujson`), wins outright over yours; `doctor` says which file it read. Your configuration lives at `~/Library/Application Support/tailkeeper/config.hujson` (macOS), `$XDG_CONFIG_HOME/tailkeeper/config.hujson`, by default `~/.config/tailkeeper/config.hujson` (Linux), or `%AppData%\tailkeeper\config.hujson` (Windows). The audit log is `~/Library/Logs/tailkeeper/audit.jsonl` (macOS), `$XDG_STATE_HOME/tailkeeper/audit.jsonl`, by default `~/.local/state/tailkeeper/audit.jsonl` (Linux), or `%LocalAppData%\tailkeeper\audit.jsonl` (Windows).

tailkeeper sends its API requests only to `api.tailscale.com`, over HTTPS. It honours `HTTPS_PROXY` and `NO_PROXY` as Go programs do; a proxy sees the host name and the encrypted connection, not the requests. The `local` tools run the `tailscale` command line instead, and the `oidc` provider, inside GitHub Actions, also asks the job's token endpoint for an identity token.

## Use

```
tailkeeper devices list --stale-days 30
tailkeeper devices routes web-1
tailkeeper local status --peers
tailkeeper acl get                               # the policy file, a page at a time
tailkeeper acl test tag:ci --accept tag:prod:22   # exits 9 if tag:ci cannot reach tag:prod on port 22
tailkeeper --json keys list
```

Register the MCP server with Claude Code (use absolute paths: MCP hosts start servers with a minimal `PATH`):

```
claude mcp add -s user tailkeeper -- "$HOME/.local/bin/tailkeeper" mcp
```

Other MCP hosts start the same stdio server. Give them the absolute path of the installed binary (`/path/to/tailkeeper` below stands for it, for example `~/.local/bin/tailkeeper` written out in full), because hosts start servers with a minimal `PATH`. File locations change between host versions; check the host's own documentation if one of these is not where it says.

- Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

  ```json
  {"mcpServers": {"tailkeeper": {"command": "/path/to/tailkeeper", "args": ["mcp"]}}}
  ```

- Cursor: `~/.cursor/mcp.json`, with the same `mcpServers` object.
- VS Code: `.vscode/mcp.json` in a workspace, or the user-level `mcp.json`:

  ```json
  {"servers": {"tailkeeper": {"type": "stdio", "command": "/path/to/tailkeeper", "args": ["mcp"]}}}
  ```

- Codex CLI: `~/.codex/config.toml`:

  ```toml
  [mcp_servers.tailkeeper]
  command = "/path/to/tailkeeper"
  args = ["mcp"]
  ```

`tailkeeper mcp` takes `--profile reads|core|full` (default: `mcp.profile` from the configuration, else `reads`) and `--enable-alpha` (also advertise the tools for alpha Tailscale features; the configuration's `mcp.enableAlpha` does the same). In 0.x every tool reads, so the three profiles list the same tools; `core` and `full` gain the write tools in M2.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | An error with no code of its own below: Tailscale's API returned an error (not found, rate limited, a feature your plan lacks, and so on) or could not be reached, the local `tailscale` command failed, a result was withheld, or an internal error. |
| 2 | Usage or validation error: an unknown command or flag, a bad parameter, or a filter refused while masking is on (`filter_refused`). |
| 5 | The read credential is unavailable or was rejected, a scope is missing, or the privacy key is unavailable. |
| 6 | The configuration is missing, invalid or unsafe. |
| 7 | The audit log is unavailable or damaged (`audit verify` found a break). |
| 8 | `doctor` found a failing check. |
| 9 | `acl test` ran, and at least one destination did not behave as asked (an `--accept` it cannot reach, or a `--deny` it can). |

The design reserves 3, 4, 10 and 11 (denied, precondition failed, approval required, outcome unknown) for the write tools; nothing returns them yet.

## Reference

- `docs/tools.md`: every tool, its CLI command, scopes, parameters and untrusted fields, and a map from each read operation in Tailscale's OpenAPI document to the tools that call it, or the reason none does (generated; `make docs-check` keeps it current). The map is checked against two pinned files, not against a copy of the document: `internal/api/openapi/operations.txt` lists the document's operations, and `fingerprint.txt` lists, for every read operation and the validate call, their parameters, the content types of their request bodies and the fields of their responses (for the validate call, its error responses too). A weekly job compares the pins with the live document. To move the pin, download the document, run `go test ./internal/api/openapi -run 'TestOperationsMatchTheDocument|TestLiveDocumentMatchesThePin' -update` with `TAILKEEPER_OPENAPI_LIVE` set to its path, review the diff, and commit both files.
- `docs/design.md`: the design and roadmap. `docs/threat-model.md`: what tailkeeper protects, against whom, and what it does not stop.
- `docs/scopes.md`: every OAuth scope and the tools that need it (generated; `tailkeeper scopes` prints it).
- `docs/dependencies.md`: every package the binary links (generated; `make deps-check` fails on any change until it is reviewed).
- `docs/recipes/`: credential wrappers for secret managers.
- `CHANGELOG.md`: what each release changed. `SECURITY.md`: how to report a vulnerability. `CONTRIBUTING.md`: how to work on the code.
- `CLAUDE.md`: the rules for agents working in this repository.

## License

Apache-2.0. tailkeeper is an independent project, not affiliated with, endorsed by or sponsored by Tailscale Inc. "Tailscale" is a trademark of Tailscale Inc.
