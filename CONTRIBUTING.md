# Contributing

Thank you for helping. tailkeeper reads Tailscale tailnets on behalf of people and agents, so a change is judged first by what it could expose.

## Before you start

- Security problems: do not open an issue or a pull request. Follow `SECURITY.md`.
- Larger changes: open an issue first and describe the problem. The design in `docs/design.md` and the threat model in `docs/threat-model.md` say what tailkeeper will and will not do; a change outside them starts with a design discussion.
- 0.x releases are read-only. Write tools arrive behind an approval gate (milestone M2); pull requests that add a write path before then will be closed.

## Working on the code

- Go 1.27.3 (the toolchain line in `go.mod`), GNU make, and git.
- `make verify` runs gofmt, vet (including a Windows build), staticcheck, golangci-lint (including gosec), race tests, the generated-docs and dependency checks, govulncheck and `go mod verify`. It must pass on every commit. CI runs it, then `make actionlint` (the workflow files and, with shellcheck, `scripts/`) and `make cover`, which must stay at or above 90% and at or above 95% for `internal/acl` and `internal/guard`, each measured from its own tests. `make actionlint` needs `shellcheck` on your path and prints its version; CI uses the one on its Ubuntu runner image, so when your result and CI's differ, compare the versions in the two logs.
- `docs/tools.md`, `docs/scopes.md`, `docs/dependencies.md` and `THIRD_PARTY_LICENSES` are generated: run `make docs` (the first two) or `make deps` (the last two) and commit the result. `THIRD_PARTY_LICENSES` names the Go toolchain version, so a toolchain bump needs `make deps` too.
- Tests run against the fake API in `internal/api/apitest`. Never point a test at the real API (`make live` and `make probe-acl`, which a maintainer runs against their own tailnet and CI never runs, are the only exceptions), and never put a credential, a real tailnet ID, a real device name or address in a test. Build credential-shaped values from parts at run time, so secret scanners never fire on the repository.
- Masking or sanitizing changes: run `make bench` before and after, and keep `TestMaskingScalesLinearly` passing.
- A bump of `github.com/tailscale/hujson` (an untagged pseudo-version that Dependabot moves) must keep the characterisation tests green: `TestCharacteriseHuJSON` pins what that version accepts and rejects and the exact text of its errors, `TestCharacteriseHuJSONPatch` pins how `Patch` places a new member and what its errors say, and `TestParseOffsetsPointAtTheirValues` holds it to the byte offsets the engine places lines with. If a row changes, change the engine's input rules in the same pull request.
- Changes to the policy engine (`internal/acl`) or its guard (`internal/guard`): run `make mutate`, which changes the code in a copy, one listed mutant at a time, and fails if a test does not notice. Add a mutant to the package's `mutants.txt` for each class of defect a new test is written to catch.
- `make fuzz FUZZ_PKG=./internal/acl` fuzzes one package; the policy engine (`internal/acl`) and its guard (`internal/guard`) keep their fuzz seeds under `testdata/fuzz`, built from the fixtures (`go test ./internal/acl -run TestFuzzSeedsAreCurrent -update-seeds` rewrites them).
- A crasher a fuzz run finds is kept by committing the file Go wrote under its hash name (`testdata/fuzz/<Target>/0123456789abcdef`, 16 hex digits): `TestFuzzSeedsAreCurrent` lets such a file stand, and `-update-seeds` leaves it alone. Do not rename it; every other file there must be a seed the test builds.

## Commits and pull requests

- Commit messages are `type: description` (`feat`, `fix`, `docs`, `test`, `ci`, `build`, `chore`, `refactor`, `perf`), with a body that says why.
- Commits on `main` must be signed.
- One logical change per pull request. Say what it changes for a user, what you tested, and whether it touches output that agents see.

By contributing, you agree that your contribution is licensed under the Apache License 2.0, as the rest of the project is.
