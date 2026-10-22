# tailkeeper: rules for agents

tailkeeper is a read-only Tailscale CLI and stdio MCP server in Go. The design and roadmap are in `docs/design.md`, the threat model in `docs/threat-model.md`. If a `CLAUDE.local.md` exists beside this file, it adds rules for the machine you are on; read it too.

## The gate

- `make verify` passes before and after every change, and before every commit. It runs gofmt, vet (including a Windows build), staticcheck, golangci-lint (gosec, errcheck, errorlint, bodyclose, misspell, ineffassign, unused), race tests (with the growth guard on the masking paths), the generated-docs and dependency checks, govulncheck and `go mod verify`. CI runs the same target, then `make actionlint` (the workflow files and, with shellcheck, `scripts/`) and `make cover` (statement coverage including the end-to-end runs; it fails below 90%, and below 95% for `internal/acl` and `internal/guard` measured from their own tests).
- `docs/tools.md`, `docs/scopes.md`, `docs/dependencies.md` and `THIRD_PARTY_LICENSES` are generated. After changing a tool, run `make docs`; after changing dependencies, review the diff of `make deps`; commit the results.
- Commit messages are `type: description`. Stage files by name, never `git add <directory>`.
- Never `--no-verify`. If a hook blocks, report what it says and stop.

## Credentials and identifiers

- Never put a credential in an argument, a file in this repository, a test or a log.
- Never copy a tailnet ID, OAuth client IDs, device addresses or internal hostnames into chat, commits, docs or tests. `tailkeeper doctor` shows only the first four characters of the tailnet and OAuth client IDs, and `tailkeeper audit tail` those of the tailnet ID unless the configuration sets `"personalData": "show"`; the log file itself holds the whole ID, so read it through `audit tail`.
- Never read, print or copy the privacy key (TAILKEEPER_PRIVACY_KEY); tests build keys with strings.Repeat.
- Tests use the fake API in `internal/api/apitest`; never point a test at the real API.
- tailkeeper only reads. Apart from the credential's token request, its only API request other than GET is `POST .../acl/validate`: `acl_test` and `acl_validate` send a test, the live policy or a proposed policy to Tailscale for validation, which changes nothing, and send nothing else; the API client refuses any other, and the fake API fails any test in which one gets past that guard. Policy and settings changes are the owner's, made in the admin console. Write tools arrive in M2, behind an approval gate.

## The installed binary

- MCP hosts should run the binary `make install` writes (`~/.local/bin/tailkeeper` by default). Only `make install` writes it, and only from a clean tree that passes the gate. `make build` writes `bin/`, which nothing live uses.
- After `make install`, test the MCP server end to end in a headless session. Write a config file with `{"mcpServers": {"tailkeeper": {"type": "stdio", "command": "<absolute path to the installed binary>", "args": ["mcp"]}}}`, then run `claude -p --strict-mcp-config --mcp-config <file> --allowedTools mcp__tailkeeper --disallowedTools Bash --output-format json "<a read-only question>"`. Confirm the call in `tailkeeper audit tail -n 5` and run `tailkeeper audit verify`.
