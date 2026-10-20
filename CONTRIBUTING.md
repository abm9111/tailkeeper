# Contributing

Thank you for helping. tailkeeper reads Tailscale tailnets on behalf of people and agents, so a change is judged first by what it could expose.

## Before you start

- Security problems: do not open an issue or a pull request. Follow `SECURITY.md`.
- Larger changes: open an issue first and describe the problem. The design in `docs/design.md` and the threat model in `docs/threat-model.md` say what tailkeeper will and will not do; a change outside them starts with a design discussion.
- 0.x releases are read-only. Write tools arrive behind an approval gate (milestone M2); pull requests that add a write path before then will be closed.

## Working on the code

- Go 1.27.2 (the toolchain line in `go.mod`), GNU make, and git.
- `make verify` runs gofmt, vet (including a Windows build), staticcheck, golangci-lint (including gosec), race tests, the generated-docs and dependency checks, govulncheck and `go mod verify`. It must pass on every commit. CI runs it, then `make actionlint` (the workflow files and, with shellcheck, `scripts/`) and `make cover`, which must stay at or above 90%. `make actionlint` needs `shellcheck` on your path and prints its version; CI uses the one on its Ubuntu runner image, so when your result and CI's differ, compare the versions in the two logs.
- `docs/tools.md`, `docs/scopes.md`, `docs/dependencies.md` and `THIRD_PARTY_LICENSES` are generated: run `make docs` (the first two) or `make deps` (the last two) and commit the result. `THIRD_PARTY_LICENSES` names the Go toolchain version, so a toolchain bump needs `make deps` too.
- Tests run against the fake API in `internal/api/apitest`. Never point a test at the real API (`make live`, which a maintainer runs against their own tailnet and CI never runs, is the one exception), and never put a credential, a real tailnet ID, a real device name or address in a test. Build credential-shaped values from parts at run time, so secret scanners never fire on the repository.
- Masking or sanitizing changes: run `make bench` before and after, and keep `TestMaskingScalesLinearly` passing.

## Commits and pull requests

- Commit messages are `type: description` (`feat`, `fix`, `docs`, `test`, `ci`, `build`, `chore`, `refactor`, `perf`), with a body that says why.
- Commits on `main` must be signed.
- One logical change per pull request. Say what it changes for a user, what you tested, and whether it touches output that agents see.

By contributing, you agree that your contribution is licensed under the Apache License 2.0, as the rest of the project is.
