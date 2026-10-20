# Changelog

What each release of tailkeeper changed. Versions follow semantic versioning; until 1.0, a minor release may change the CLI or the MCP tool list.

## 0.6.0 — unreleased

### Added

- Library code for pseudonym subjects, used by no tool yet: a resolver that turns a pseudonym into the one user it names (`GET /users`, held for one call), a reverse map that masks a resolved login, and any word glued to it, out of Tailscale's reply, and the subject rule over a policy text and over patch operations.
- `TestMaskingScalesLinearly` also times some rows of the guard (the email scan and the colon scan) from 128 KiB to 1 MiB, and the bound on the work of `sanitize.String` is tested by bytes allocated, not by its output (#13).
- Fuzzing runs nightly one package to a job, with the inputs a night finds carried to the next, so a long package cannot time out the others. `make fuzz FUZZ_PKG=./internal/acl` fuzzes one package, and `FUZZ_MIN` is the number of targets that must run. The pull-request job named `fuzz` is unchanged.
- `make mutate` changes a package's code one listed mutant at a time (the `mutants.txt` beside the package; `MUTATE_PKG` picks one package) and fails if a test does not notice. It is not part of `make verify`.
- `make cover` also requires 95% statement coverage for `internal/acl` and `internal/guard`, measured from each package's own tests.
- `make probe-acl`: the owner's live probes of the policy validate endpoint. It sends about 50 documents to `POST .../acl/validate`: synthetic ones, or ones built in memory from the tailnet's own policy and sent back to its own validate endpoint, which changes nothing. It makes up to ten reads, the policy and the configuration audit log (that read needs the `logs:configuration:read` scope), through the read client, and prints what the API answered without printing a value from the tailnet: statuses, key paths with their JSON types, and error texts reduced to templates in which only the grammar's own words survive. It writes one skeleton file per probe for the owner to commit. It is opt-in (`TAILKEEPER_LIVE=1`, which the target sets), not part of `make verify`, the target is never run in CI (a test builds the tagged binary only to prove that it stops without a configuration and sends nothing), and the command is not in any release: it exists only in a binary built with `-tags probe`.
- `internal/api`: `ValidatePolicy` and `GetPolicy`, the low-level calls the probes use (one attempt, any status returned as data). The fake API in `internal/api/apitest` gains a shape ledger (`Documented`, `Observed`, `Assumed`) that every test must use for validate and details answers, and a spy that fails a test whose validate request names one mode and carries the other's body.

### Fixed

- The release notes now come from this file. `.goreleaser.yaml` disabled GoReleaser's changelog stage, which is the stage that reads the notes the release job cuts from this file, so 0.5.0 was published with only its footer. The stage stays on. A test fails if it is disabled while the release workflow passes the notes, and `make release-check` and the manual snapshot run now run the release path with a notes fixture and fail unless GoReleaser read it.
- The release workflow verifies the cosign signature of `checksums.txt`, as the README tells a reader to, before it publishes a draft release.
- Masking leaves the name of a synced group, `group:engineering@example.com`, as written and names nothing for it, where `group:` begins a word (at the start, or after a space, a quote, an opening bracket or a separator). A group is masked as an address when its name is quoted, escaped or holds `=` or `?`, when it is glued to the word before it, when it is written after //, or when it is followed by another address; an at sign written as `%40` or a JSON escape keeps the name whole. It had been shown as `group:e…@example.com`, which made two groups with one initial look alike.
- Masking hides a quoted local part (`"amy"@example.com`) when a control character stands between the closing quote and the at sign, whether the character is a raw byte, `%01` or a brace escape such as the one `acl_get` writes for a control character. The quoted name had been shown.
- The pseudonym of an address that text glues to a word with `=` or `?` (`user=amy@example.com`, `?u=amy@example.com`) is the address's own, as `users_list` shows it. It had been the pseudonym of the whole run, so a filter given it matched nothing. A login whose local part holds `=` or `?` (`a=b@example.com`) is named in text by the part after it.
- A login or display name that the API returns and that holds a backslash sequence is no longer given the pseudonym of the address the sequence spells. Pseudonyms of values from the API decode no JSON escapes; text from a policy or free text still does.
- With a privacy key, `acl_get` shows a `[p:` that the policy itself holds with its bracket spelled out, as free text does, so a marker on the page is one tailkeeper appended. `masked` is true for a page whose only change is such a marker.
- `sanitize.String` and `Text` return at most the limit they are given: below 14 bytes they returned the 14-byte truncation notice. `HasTag` finds no empty option in an untagged field. Nothing called either with such arguments.

### Changed

- The pin of Tailscale's OpenAPI document (`internal/api/openapi`) is refreshed to the document of 18 Oct 2026. It differs from the pin of 12 Oct by one response field, `adminConsoleSessionTimeoutMinutes` on the tailnet settings, which `settings_get` does not return. The pin now also records the parameters and request content types of every read operation and of the validate call, and the error fields of the validate call, so a change to the `details` parameter of the policy file or to the content types of the validate call fails the weekly drift check.
- The weekly drift check retries its download of the document three times.
- The manual snapshot run of the release workflow builds in a job of its own that holds read access only.
- `docs/design.md` states the contract of 0.6.0, the read side of the ACL engine: the tools, the rules of the engine, the error and exit codes, the tests, and the live probes whose results decide what is still open.

## 0.5.0 — 2026-10-16

The first public release: tailkeeper's repository is public, and releases are signed, attested binaries. The tools are the same; the fixes, and what masking now covers, are listed below.

### Added

- `tailkeeper scopes` and `docs/scopes.md`: the OAuth scopes the tools need, and which tools need each.
- `make live`: an opt-in run of every tool against the configured tailnet that checks the results without printing them. The test suite also runs on macOS and Windows in CI; `docs/windows.md` says what the Windows build does differently.
- Release archives for macOS and Linux (amd64, arm64) and Windows (amd64), built by GitHub Actions from a tag signed by the maintainer, with `checksums.txt`, a cosign keyless signature over it, a CycloneDX SBOM per archive, and GitHub build-provenance attestations. The workflow rebuilds every binary on a second architecture and publishes only if the bytes match. `README.md` says how to verify a download.
- `TestMaskingScalesLinearly` fails `make verify` when a masking or sanitizing path grows faster than linearly with its input (the 0.3.0 email-scan regression would have failed it), and `make bench` benchmarks those paths and two end-to-end tools.
- golangci-lint, with gosec, runs in `make verify`. `docs/dependencies.md` lists every package outside the standard library that the binary links, per release target; `make deps-check` fails on any change until it is reviewed.
- Fuzzing in CI (every target, on pull requests and nightly), CodeQL and OpenSSF Scorecard.
- `docs/design.md` (the design, moved), `docs/threat-model.md`, `docs/recipes/` (credential wrappers for two secret managers), `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `NOTICE`, issue and pull request templates, and a response and disclosure policy in `SECURITY.md`. The README documents every credential provider, every configuration key and the common MCP hosts.

### Fixed

- Masking finds email addresses written with `%40`, with a quoted local part (`"amy"@example.com`), and with quotes that split a percent-encoded at sign (`%4"0amy"@example.com`). It also finds one with a control character, or a brace escape such as `\u{0001}`, in its local part or right after the at sign. Reading a quoted local part takes time linear in the text.
- Masking finds an IPv6 address behind a label that ends in a digit (`ipv6:2001:db8::1`), before a full stop and a word (`2001:db8::1.Error`), and before a port after a colon or a full stop (`2001:db8::1:41641`, `2001:db8::1.443`), also when a full stop and more follow the port (`2001:db8::1:41641.example.com`). An address of eight groups is found before `::` and a port, before a port and `::`, and before a full stop and a word.
- Masking finds a public IPv4 address behind a name and a full stop (`eth0.203.0.113.7`), behind an escape (`%20203.0.113.7`), at the start of a longer dotted number (`203.0.113.7.443`), and after a slash that follows an address (`1.1.1.1/8.8.8.8`). Masking is a best effort: SECURITY.md lists the forms it does not read.
- The invite tools no longer return the tailnet ID.
- `audit_log` cuts each `http` or `https` URL it can read to its host and a hash of its path, in a target's name and property, in action details, in an error and in `includeValues` previews, also when `personalData` is `show`; `log_streaming_get` does the same to a URL in a delivery error. A token in the path of a webhook or log-stream URL no longer shows. SECURITY.md lists the spellings of a URL that stay whole.
- `audit_log` previews remove the values under credential-named keys (`true`, `false` and `null` stay), also in a policy file held in a string: HuJSON (comments, a byte order mark, trailing commas) is read before redacting. Text that is not strict JSON and nests more than 1,000 levels deep is removed rather than parsed, so a deeply nested value cannot exhaust the stack. SECURITY.md lists what this cut does not reach.
- `audit_log` shows a target's `property` as untrusted text, as it does the target's name: escaped, capped, masked, and with credential shapes replaced.
- A webhook or log-stream URL that is set and cannot be read shows as a URL that could not be read, not as an empty host.
- `devices_list`'s `nameContains` filter and the lookup of a device by hostname (`device_get`, `device_routes`, `device_posture_attributes`, `device_invites_list`) read the name as the result shows it, so they cannot confirm a guess at an address the result masks.
- The configuration file and a `file` provider's credential file are read through the file that passed the ownership check, not looked up by name a second time: on macOS and Linux, a file put in its place in between is refused (also one that takes the inode number of the file removed, as ext4 gives it), a symlink there is refused too, and a FIFO cannot block the read. That narrows a race and does not close it; SECURITY.md says what is left.
- A credential's secret (an OAuth client secret or an API key) no longer prints under any format verb.
- A `resources/read` of an unknown URI holding a control character no longer ends the MCP session, and the reply no longer repeats the URI. An API error's message is marked untrusted in the structured error.
- Messages that quote text from the caller, the configuration or the audit log are escaped: `doctor --json`, the flag package's errors, the MCP server's warnings, the warning for a read that was not audited, and the paths that `audit verify`, `audit rotate` and `docs --check` print.
- A result printed as text that cannot be written in full makes the command exit 1. `tailkeeper docs` refuses an argument it would have ignored, and `docs --help` exits 0.
- On Windows, the audit-log appends of one process are serialised, so the parallel calls of one MCP server no longer break the chain; two processes writing at once still can.
- `audit verify` warns on standard error when an archive it continues is missing, and a failure to close the audit log after an append is reported.
- With a privacy key, the length cap no longer leaves half a pseudonym marker at the end of a cut value. Entries of a result's map whose keys are the same text once escaped or cut are all kept, with a counter (`#2`) after the first, instead of all but one being dropped.
- `filter_refused` says what a filter takes, and whether a privacy key is needed for pseudonyms; `devices_list user=tagged-devices` works while masked; the `includeValues` previews and the digests are described exactly.

### Changed

- The repository starts a fresh public history at 0.5.0. Earlier releases (0.1.0 to 0.4.0) are described below but were not published.
- While personal data is masked, `devices_list` refuses a `hostname` filter that masking would change (an email address, a public IP address, or text that looks like one) (`filter_refused`), `nameContains` matches the name as shown, and a device is looked up by its hostname as the result shows it: use the node ID for a device whose hostname masking changes.
- With masking off, `audit_log`'s `target` filter matches a substring of the target's ID, name, type or property as the result shows it, on the client, so the path of a URL, which the result cuts, matches nothing. The server used to match the raw target.
- Masking reads more shapes of address, and so also masks some text that only looks like one: any four parts of a dotted number of five parts or more that make a public IPv4 address (`v1.80.2.1.5` becomes `v1.80.2.0/24.5`). SECURITY.md lists the shapes.
- The invite tools' results have no `tailnetId` field.

## 0.4.0 — 2026-10-12

Masking stops confirming guesses, and masked values get names. tailkeeper's API coverage is now checked against Tailscale's own OpenAPI document.

Upgrading: while personal data is masked (the default), `devices_list --user` with a login, and `audit_log` with a `~search` or an address as `actor` or a non-ID `target`, are refused with `filter_refused`. Use the pseudonym a masked value carries, or set `personalData` to `show`. `audit_log`'s `oldSha256` and `newSha256` are now `oldDigest` and `newDigest`.

### Added

- A privacy key (`TAILKEEPER_PRIVACY_KEY`, 64 hexadecimal characters), kept where the read credential is. It names every masked identifier and email address in a result with a pseudonym (`a…@example.com [p:k7x2m9qd4a]`), stable across calls and tools, and keys `audit_log` digests. Error messages, and the reasons `acl_test` returns, are masked without pseudonyms: they echo what the caller typed, and a pseudonym beside a guess would confirm it. `doctor` reports it.
- Filters take pseudonyms: `devices_list`'s `user`, `audit_log`'s `actor` and `target`, matched client-side. With masking off, `audit_log` refuses a list that mixes a pseudonym with a `~search` or a substring (`validation_failed`), which a client-side match would silently drop.
- `audit_log`'s `target` pseudonym matches an entry only through an address its target name shows, one pseudonym per address, and only while that pseudonym is still displayed: not the pseudonym of the name as a whole, and not one the length cap cuts off. Text cannot forge one (see Changed). With masking off, a pseudonym filter no longer matches a whole name that is not an address.
- A privacy key that is set but malformed or unreadable is reported once when the MCP server starts, and `audit_log`'s note says so instead of that no key is loaded. Masking still runs, without pseudonyms or digests.
- `audit_log`'s `actor` and `devices_list`'s `user` pseudonyms match only a pseudonym the display shows: not that of a value masking leaves as it is (the owner of tagged devices) and not one the length cap cuts off.
- An MCP call to a tool the server hides (today the two alpha OAuth-app tools, without `--enable-alpha`) returns `tool_hidden` with the setting that shows it, and the server's instructions list the hidden tools.
- `docs/tools.md` maps every read operation in a pinned list of the operations in Tailscale's OpenAPI document to the tools that call it, or the reason none does; a test fails on any gap. A weekly job compares the pin with the live document.

### Changed

- While masking is on, filters that would confirm a guessed personal value are refused (`filter_refused`, exit 2).
- With a privacy key loaded, a `[p:` written in untrusted free text (a target name, a tag, an `includeValues` preview) is shown with its bracket spelled as an escape, `\u{005B}p:`, so that a pseudonym marker in a result is one tailkeeper appended and a member cannot plant one beside a hidden address. This is the only change to a result's text; with no key, and in the policy file and `acl_test` reasons, which no filter reads, text is shown as before.
- `audit_log` returns `oldDigest` and `newDigest`: an HMAC under the privacy key while masking is on, a SHA-256 when it is off, and nothing while masking is on without a key.
- `audit_log` orders entries that share a timestamp by a hash of the entry as displayed, so no raw login or old or new value feeds it. A `nextCursor` is good only with the same filters, limit and `includeValues`, the same masking setting and the same privacy key; otherwise `validation_failed`.
- New error codes: `filter_refused` (2), `privacy_key_unavailable` (5), `tool_hidden` (2).

## 0.3.0 — 2026-10-11

Two policy tools, pulled forward read-only from the spec's M3 (the ACL engine).

### Added

- `acl_get` (`tailkeeper acl get`): the tailnet policy file as the API returned it (HuJSON, comments included), a page at a time (`fromLine`, `nextLine`; `maxBytes`, default 150 KiB, measured as escaped JSON text, and a line longer than the page is refused with the size to ask for), with the size and SHA-256 of the whole policy and whether it is managed outside the admin console (`unknown` when the settings cannot be read, never `false`). Email addresses are masked unless `personalData` is `show`; addresses, CIDRs, hosts, tags and comments stay whole. While masking is on, the size and SHA-256 are those of the policy as shown, every page joined, and the ETag is left out, so none of them can confirm a guessed address; with `show`, they describe the file as the API returned it, ETag included. It is a display copy, not the file to edit. The CLI prints the facts, a notice that the policy is untrusted text, then the policy behind line numbers. In MCP it is in the default `reads` profile: the whole policy goes to the model provider when an agent reads it.
- `acl_test` (`tailkeeper acl test SRC --accept DST --deny DST [--proto P]`): whether one source can or cannot reach destinations under the live policy, without changing it. Pass or fail with Tailscale's reasons, one per line in the CLI after a notice that they are untrusted text; the CLI exits 9 on a failure. A source or destination Tailscale cannot resolve fails the test, with its reason. A pass is read only from a response shape Tailscale documents, with no field unknown or given twice; any other answer is an error, never a pass. Evaluated with no posture attributes; SSH rules are not tested. It refuses masked values, wildcards, CIDRs, unbracketed IPv6 and more than 32 destinations.
- `doctor --probe` checks `acl_get` and sends `acl_test` a test no policy can pass. A failure carrying Tailscale's reasons shows that failures are read as such and that the read credential may run tests; a pass is reported as a failure, and a refusal by the endpoint, or warnings alone, as a warning.

### Changed

- Apart from the credential's token request, the API client sends one request other than GET, `POST .../acl/validate` on its own tailnet, which Tailscale documents as never changing the policy. Its outermost transport refuses every other request but GET, for every credential kind, and the fake API fails any test in which one gets past it.
- A result field tagged `multiline` keeps line feeds and tabs (CRLF shown as LF); every other invisible character is still escaped. Escaping now also covers the default-ignorable code points and variation selectors it missed, such as U+034F and U+180B.
- Email masking reads JSON escapes inside an address (`\u0040` as an at sign, `\u0061` as a letter), which a policy file may use and Tailscale decodes, and masks a chain such as `a@b@c.d` whole instead of leaving `b@c.d` readable.
- `docs/tools.md` lists, per tool, the fields whose email addresses alone are masked.
- MCP tools can declare a larger result size for the host; `acl_get` declares 200,000 characters.

## 0.2.0 — 2026-10-11

Fixes for the findings an audit of 0.1.1 left open. Tool results now mask personal data by default, so a consumer that read whole login names or public addresses sees them masked until the owner sets `"personalData": "show"`.

Upgrading: restart MCP hosts that still run 0.1.x before the first `tailkeeper audit rotate`. An older process does not know about rotation and can append to the archive while a rotation runs, which `audit verify` then reports as a break; to recover, keep that archive for the record but move it out of the logs directory, and verification then notes it as not present.

### Changed

- Personal data is masked by default (spec Appendix C), in CLI and MCP results and in error messages. Identifiers are masked whole to their first character, plus the domain of an email address (`a…@example.com`): device owners, users' login and display names and tailnet ID, invite and contact emails, invite acceptors, configuration audit-log actors, webhook creators, `local_whoami` and `local_whois` users, the log-stream user, and the `operator` and `nickname` preferences. In every other untrusted field (health messages, audit-log targets, details, errors and `includeValues` previews, key descriptions and claims, posture and log-stream errors, flow-log endpoints, and so on), email addresses are masked the same way and public IP addresses are cut to their /24 or /48 network (/40 for 6to4), port kept. The owner opts in to whole values with `"personalData": "show"` in the configuration; no tool parameter unmasks them.
- What masking leaves whole: device names and hostnames, configuration a diagnosis needs (DNS resolvers and answers, routes, a webhook's or log stream's host, OAuth redirect URIs, the policy file's external link, other local preferences), an organisation's tailnet name, and text the patterns do not recognise. Search filters can recover a masked value: `audit_log`'s `actor` and `target` match substrings. README and SECURITY.md state these limits; `docs/tools.md` lists the masked-whole and never-masked fields per tool.
- An MCP call reads at most 8 MiB of an API response; a larger read fails with a hint to narrow it. The CLI keeps 64 MiB. With the four-call cap this bounds the server's memory, at a level that depends on the response's shape: in probes, four concurrent calls reading 8 MiB of device JSON each used 460 to 770 MiB of heap for typical rows and up to 1.4 GiB for a pathological body of one-character strings; 64 MiB responses would need eight times that.
- `go install` in the README names `@latest` instead of a release.
- `tailkeeper audit tail` shows the first four characters of the tailnet ID, as `doctor` does, unless `personalData` is `show`.
- `tailkeeper audit verify` reports a log whose last line has lost its newline, which appends and rotation already refused, and every chain break now says how to go on: move the log aside while no tailkeeper process runs.
- Dependabot proposes a release only once it is a week old.

### Added

- `tailkeeper audit rotate` verifies the audit log, keeps it beside the new one as `audit-<UTC time>.jsonl`, and starts a new chain whose first entry records where the archive ends. It refuses a log that fails verification, so a rotation never hides damage, and refuses a log that is a symbolic link. Nothing is pruned. An append that waited for the log's lock through a rotation writes to the new log. Not available on Windows yet, where the log has no file lock.
- `tailkeeper audit verify` follows the rotations back through every archive still present and checks each chain, and says when an archive is gone. The `audit` commands now refuse arguments: `audit verify <archive>` used to check the live log instead.
- `tailkeeper doctor` suggests a rotation once the audit log passes 64 MiB.
- The MCP server's instructions say that personal data is masked and that a masked value must not be passed to a filter; output schemas mark masked-whole fields with `x-tailkeeper-masked`.
- `make cover`: statement coverage of every package by every test, the end-to-end binary runs included, failing below 90% (91.03% now); CI runs it, and CI now also runs weekly, so a newly published vulnerability is found without a push. New tests cover the integration get tools, log-tool errors and filters, OIDC token sources, config rules, CLI flag types and audit-log failure paths.

### Fixed

- `local_status` capped health messages at 512 bytes before they were masked, so an address on the cut could show more of itself than its network.

## 0.1.1 — 2026-10-11

Fixes from the review and audit of 0.1.0.

### Fixed

- The MCP server runs at most four tool calls and resource reads at once; before, a burst of calls all ran together. Further calls wait for a slot; one still waiting when its request or the server ends returns an error that says so. This limits concurrency, not memory: each API read may still buffer up to 64 MiB.
- An audit-log append gives up after 2 seconds when another process holds the log's lock, instead of waiting forever. Reads then continue unaudited, with a warning; an unavailable log is no longer retried with a stripped `line_withheld` line. The MCP server warns again after each recovery instead of only once per session.
- MCP resource reads end with the treat-as-data sentence, as tool results do: a `text/plain` entry after the unchanged JSON. The resource descriptions carry it too.
- `tailkeeper doctor` shows only the first four characters of the tailnet ID and the OAuth client ID, and its audit-log check warns when doctor's own reads could not be recorded instead of reporting ok.
- `make install` checks for a commit itself instead of relying on the clean-tree check.

### Changed

- `github.com/tailscale/hujson` updated from a 2022 version to the 2026-07-27 one. Its one behaviour change: a `//` comment that contains U+2028 or U+2029 no longer parses. `golang.org/x/oauth2` 0.35.0 to 0.37.0.
- CI runs on `ubuntu-24.04` instead of `ubuntu-latest`.

### Added

- `SECURITY.md`: how to report a vulnerability, what counts, and the known limits.
- Tests: an expired OAuth token is replaced before the next request, each request carrying the new one; resource reads share the call cap; the shutdown test waits for the call to reach the API instead of sleeping 200 ms; a lock or slot regression fails within seconds instead of hanging, and `make test` has a 180-second timeout.

## 0.1.0 — 2026-10-11

The first release: milestone M1, the read-only foundation, and the tooling to install and release it.

### Tools and safeguards

- 41 read tools from one registry, each both an MCP tool and a CLI command with the same parameters, validation and output: 26 for the Tailscale API (two alpha tools, listed by MCP only with `--enable-alpha`) and 15 for this node's local Tailscale state.
- A stdio MCP server with the reads profile.
- Configuration with named contexts, checked for ownership and permissions in strict mode, and a read credential from an `exec` provider, so the secret never reaches the caller's shell.
- Allowlisted output: responses are decoded into tailkeeper's own types; key material, invite links, webhook secrets and login URLs are never returned; a tripwire withholds any result that still contains a Tailscale key or a JWT. Text from the tailnet is escaped, capped and marked untrusted.
- `tailkeeper doctor`: checks the configuration, the credential's scopes (fails on a write scope), the local Tailscale install and the audit log.
- An audit log: hash-chained JSONL that records which tool ran, for whom and how much it returned, never the values; `tailkeeper audit tail` and `tailkeeper audit verify`.

### Build and release

- `make verify`, run before every commit by convention and by CI on pull requests and on pushes to `main`: gofmt, vet (including a Windows build), staticcheck, race tests, docs freshness, govulncheck and `go mod verify`.
- `make install`: passes the gate, refuses uncommitted changes, checks that the binary runs and names the commit, then installs it as `~/.local/bin/tailkeeper` (`BINDIR` changes the directory). MCP hosts run this copy, so `make build` on a work-in-progress branch never changes what a live MCP server runs.
- `CLAUDE.md`: the rules for agents working in this repository.
- Dependabot: weekly update pull requests for Go modules and the SHA-pinned GitHub Actions.
- `.gitignore` covers local audit records and agent workspaces.
