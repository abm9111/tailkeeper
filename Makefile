# `make verify` is the gate every change passes before it is committed.
GO          ?= go
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X github.com/abm9111/tailkeeper/internal/version.Version=$(VERSION)
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.1
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.8.0
GOLANGCI    := github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
ACTIONLINT  := github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
GORELEASER  := github.com/goreleaser/goreleaser/v2@v2.18.2
BINDIR      ?= $(HOME)/.local/bin

.PHONY: build install test cover bench fuzz live vet fmt-check lint lint-extra actionlint vuln docs docs-check deps deps-check release-notes-check release-check verify

# Every go command a recipe runs refuses to change go.mod or go.sum, whatever GOFLAGS the
# environment or the command line carries (a stray -mod=mod) and even if a vendor/
# directory appears and switches the default to -mod=vendor (spec §20). The flag is
# appended, not assigned: a developer's own GOFLAGS (such as -count=1) is kept, and Go
# honours the last -mod, so `make GOFLAGS=-mod=mod build` still ends in readonly. Copies
# of -mod=readonly are removed first: the exported value comes back through the
# environment into every nested $(MAKE) (install runs `$(MAKE) verify`), and each level
# would otherwise add one more.
# `override` is what lets the makefile edit a value given on the command line. Flags a
# command does not know are ignored, so `go mod verify` and the tools run as
# `go run module@version` are unaffected. scripts/deps.sh does the same when it is run
# directly.
override GOFLAGS := $(strip $(filter-out -mod=readonly,$(GOFLAGS)) -mod=readonly)
export GOFLAGS

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/tailkeeper ./cmd/tailkeeper

# The binary MCP hosts and your PATH run. `make build` only rewrites bin/ on whatever
# branch is checked out. install passes the gate, refuses uncommitted changes before and
# after the build (fails closed outside a repository) and a commit made while the gate
# ran, checks that the binary runs and names HEAD (a VERSION override or a cross-compile
# fails here), then swaps the file in one rename so a running server is untouched.
CLEAN := out="$$(git status --porcelain)" || exit 1; test -z "$$out" || { echo "install: commit, stash or remove these first:"; echo "$$out"; exit 1; }
HEAD0 := $(shell git rev-parse --verify -q HEAD 2>/dev/null)

install:
	@$(CLEAN)
	$(MAKE) verify
	$(MAKE) build
	@$(CLEAN)
	@test -n "$(HEAD0)" && test "$$(git rev-parse --verify -q HEAD)" = "$(HEAD0)" || { echo "install: no commit, or HEAD moved while the gate ran"; exit 1; }
	@test "$$(bin/tailkeeper version)" = "tailkeeper $$(git describe --tags --always)" || { echo "install: bin/tailkeeper does not name HEAD"; exit 1; }
	mkdir -p $(BINDIR)
	install -m 0755 bin/tailkeeper $(BINDIR)/.tailkeeper.new
	$(BINDIR)/.tailkeeper.new version
	mv -f $(BINDIR)/.tailkeeper.new $(BINDIR)/tailkeeper
	$(BINDIR)/tailkeeper version

# The go test lines below drop TAILKEEPER_LIVE: an ambient TAILKEEPER_LIVE=1 in the
# shell must never send the gate to the tailnet your configuration names. Only the
# live target sets it, and only for its own test run.
test:
	env -u TAILKEEPER_LIVE $(GO) test -race -count=1 -timeout 180s ./...

# Statement coverage of every package by every test, the end-to-end runs of the
# built binary included (cmd/tailkeeper builds it with -cover when go test collects
# coverage). Each code block counts once, however many binaries ran it; the floor
# compares exact counts, not a rounded percentage. Fails below COVER_MIN percent.
COVER_MIN ?= 90

cover:
	@root="$$(mktemp -d)" && trap 'rm -rf "$$root"' EXIT && mkdir "$$root/data" && \
	env -u TAILKEEPER_LIVE $(GO) test -count=1 -timeout 180s -cover -coverpkg=github.com/abm9111/tailkeeper/... ./... -args -test.gocoverdir="$$root/data" && \
	$(GO) tool covdata textfmt -i="$$root/data" -o="$$root/cover.out" && \
	awk -v m="$(COVER_MIN)" 'BEGIN { if (m !~ /^[0-9]+([.][0-9]+)?$$/) { print "COVER_MIN must be a number, not \"" m "\""; bad = 1; exit 2 } } \
		NR > 1 { stmts[$$1] = $$2; if ($$3 > 0) hit[$$1] = 1 } \
		END { if (bad) exit 2; for (b in stmts) { n += stmts[b]; if (b in hit) c += stmts[b] } if (n == 0) exit 1; \
			printf "coverage: %.2f%% of %d statements (minimum %s%%)\n", 100 * c / n, n, m; exit !(100 * c >= m * n) }' "$$root/cover.out"

# Benchmarks of the masking paths and two end-to-end tools, six runs each so
# benchstat (golang.org/x/perf/cmd/benchstat) can compare two saved outputs. Not
# part of verify: timings vary by machine. TestMaskingScalesLinearly, which
# verify runs, is the regression gate.
bench:
	$(GO) test -run '^$$' -bench . -benchmem -count 6 ./internal/sanitize ./internal/privacy ./internal/tools

# Runs every fuzz target for FUZZTIME each (go test -fuzz takes one at a time). A failing
# input is written to testdata/fuzz/<target>/ and fails the run. Fails closed: each
# package's listing is captured on its own, so a listing that fails (a compile error)
# fails the run instead of reading as "no targets", and the run fails unless it ran at
# least FUZZ_MIN targets (five exist today). A package with no fuzz target is fine. Not
# part of verify: it takes minutes and its inputs are random.
FUZZTIME ?= 20s
FUZZ_MIN ?= 5

fuzz:
	@set -eu; \
	case "$(FUZZ_MIN)" in ''|*[!0-9]*) echo "fuzz: FUZZ_MIN must be a whole number, not \"$(FUZZ_MIN)\""; exit 2;; esac; \
	pkgs="$$($(GO) list ./...)" || { echo "fuzz: go list ./... failed"; exit 1; }; \
	n=0; \
	for pkg in $$pkgs; do \
		listing="$$($(GO) test -list '^Fuzz' $$pkg)" || { echo "fuzz: go test -list failed for $$pkg"; exit 1; }; \
		names="$$(printf '%s\n' "$$listing" | awk '/^Fuzz/')" || { echo "fuzz: could not read the listing for $$pkg"; exit 1; }; \
		for f in $$names; do \
			echo "fuzz $$pkg $$f"; \
			$(GO) test -run '^$$' -fuzz "^$$f$$" -fuzztime "$(FUZZTIME)" $$pkg; \
			n=$$((n + 1)); \
		done; \
	done; \
	echo "fuzz: ran $$n target(s) (minimum $(FUZZ_MIN))"; \
	if [ "$$n" -lt "$(FUZZ_MIN)" ]; then echo "fuzz: fewer than $(FUZZ_MIN) targets ran, so the listing or the package list is wrong"; exit 1; fi

# Runs every tool once against the tailnet your configuration names, and one MCP
# session, through the built binary, and checks the results without printing them:
# only tool names, outcomes, error codes, sizes and counts reach the terminal. Uses
# your real configuration and credential: never run in CI, and not part of verify.
# The tests stay inert without TAILKEEPER_LIVE=1, which only this target sets.
#
# LIVE_UNAVAILABLE: list the tools your credential or plan does not cover, as a comma
# list of tool names (make live LIVE_UNAVAILABLE=network_flow_logs,oauth_apps_list,oauth_app_get).
# A tool that answers with a scope, plan or payment error counts as unavailable only
# if it is listed here; any other tool that does is a failure, so a credential with no
# usable scope cannot pass. The test logs the list when it starts.
#
# scripts/live-check.sh fails the run if a live test skipped (it checked nothing) or
# did not reach its closing line, and prints only the lines that hold no tailnet value.
#
# The go test timeout is 1500s. Each of the 43 calls may take up to 90s (live_test.go),
# so a run in which most calls time out needs longer; a run that runs out of time ends
# without a pass line, which fails, and the log is withheld.
LIVE_UNAVAILABLE ?=

live: export TAILKEEPER_LIVE_UNAVAILABLE := $(LIVE_UNAVAILABLE)
live:
	@log="$$(mktemp)" || exit 1; trap 'rm -f "$$log"' EXIT; \
	TAILKEEPER_LIVE=1 $(GO) test -count=1 -timeout 1500s -run '^TestLive' -v ./cmd/tailkeeper > "$$log" 2>&1; status=$$?; \
	./scripts/live-check.sh "$$log" "$$status"

# Strict mode, re-exec and log locking have Windows-only files: vet them too.
vet:
	$(GO) vet ./...
	GOOS=windows $(GO) vet ./...

fmt-check:
	@out="$$(gofmt -l .)" || exit 1; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

# staticcheck v0.8.1 cannot read go1.27.2 export data. Lint results do not depend
# on the patch release, so it runs under go1.27.1; builds and govulncheck use the
# toolchain pinned in go.mod.
lint:
	GOTOOLCHAIN=go1.27.1 $(GO) run $(STATICCHECK) ./...

# gosec, errcheck, errorlint, bodyclose, misspell, ineffassign and unused
# (.golangci.yml). staticcheck stays in `lint`.
lint-extra:
	$(GO) run $(GOLANGCI) run ./...

# Checks the workflow files: syntax, expressions, permissions and the shell in run:
# steps; and, with shellcheck itself, the scripts in scripts/. Not in verify (it needs no
# Go code); CI runs it in verify.yml. Run from the repository root, it reads
# .github/workflows.
#
# actionlint checks the shell in run: steps by calling shellcheck, and without shellcheck
# on PATH it checks none and still exits 0 (a planted SC2086 gave 1 with it, 0 without).
# So the target fails closed without it. CI uses the shellcheck on its runner image
# (ubuntu-24.04); no workflow step installs or pins one. Versions differ (an older one
# reports SC2015 where a newer does not), so a clean local run is not always a clean CI
# run. The target prints the version it judged with, so the log of either run says which.
actionlint:
	@command -v shellcheck >/dev/null || { echo "actionlint needs shellcheck on PATH: without it the shell in the workflow steps and scripts/ is not checked"; exit 1; }
	shellcheck --version
	$(GO) run $(ACTIONLINT)
	shellcheck scripts/*.sh

vuln:
	$(GO) run $(GOVULNCHECK) ./...

docs:
	$(GO) run ./cmd/tailkeeper docs > docs/tools.md
	$(GO) run ./cmd/tailkeeper docs --scopes > docs/scopes.md

docs-check:
	$(GO) run ./cmd/tailkeeper docs --check docs/tools.md
	$(GO) run ./cmd/tailkeeper docs --scopes --check docs/scopes.md

# docs/dependencies.md lists what the binary links, per release target; THIRD_PARTY_LICENSES
# holds the licence text of every module it links, and ships in each release archive
# (scripts/licenses.sh, from the go toolchain and the module cache). Each is written to a
# side file first, so a failing script cannot leave a truncated one.
deps:
	@./scripts/deps.sh > docs/dependencies.md.new && mv docs/dependencies.md.new docs/dependencies.md || { rm -f docs/dependencies.md.new; echo "deps: scripts/deps.sh failed; docs/dependencies.md is unchanged"; exit 1; }
	@./scripts/licenses.sh > THIRD_PARTY_LICENSES.new && mv THIRD_PARTY_LICENSES.new THIRD_PARTY_LICENSES || { rm -f THIRD_PARTY_LICENSES.new; echo "deps: scripts/licenses.sh failed; THIRD_PARTY_LICENSES is unchanged"; exit 1; }

# The binary's dependencies are reviewed: a difference fails, and so does gopkg.in/yaml,
# which only the OpenAPI pin tests may use (spec §20). The generator runs once, into a
# file, so its own failure fails the check; the checks all run, so one failure does
# not hide another. The YAML test reads dependency rows only (the header names yaml.v3
# as test-only), and grep's exit 2 (an error) fails it like a match. THIRD_PARTY_LICENSES
# is checked the same way: a module added, removed or re-versioned, or a licence file
# changed, fails until `make deps` is run and the diff reviewed.
deps-check:
	@out="$$(mktemp)" || exit 1; lic="$$(mktemp)" || exit 1; trap 'rm -f "$$out" "$$lic"' EXIT; \
	./scripts/deps.sh > "$$out" || { echo "deps-check: scripts/deps.sh failed"; exit 1; }; \
	rc=0; \
	diff -u docs/dependencies.md "$$out" || { echo "deps-check: dependencies changed; review them, then run make deps"; rc=1; }; \
	grep -qE '^- `gopkg\.in/yaml[./]' "$$out"; \
	if [ $$? -ne 1 ]; then echo "deps-check: the binary links a YAML parser"; rc=1; fi; \
	./scripts/licenses.sh > "$$lic" || { echo "deps-check: scripts/licenses.sh failed"; exit 1; }; \
	diff -u THIRD_PARTY_LICENSES "$$lic" || { echo "deps-check: THIRD_PARTY_LICENSES is stale; review the change, then run make deps"; rc=1; }; \
	exit $$rc

# What a release does with the notes it is given, before any tag exists. The release job
# passes the notes it cut from CHANGELOG.md with --release-notes, and GoReleaser reads
# that file in its changelog stage; v0.5.0 was published with only the footer because the
# stage was disabled. A snapshot leaves the stage out, so this is a run of the release
# path with nothing published: no --snapshot, no signing, no SBOM, validation off (the
# tree is not at a tag) and publishing skipped. Its debug log goes to
# scripts/release-notes-check.sh, which fails unless the stage ran and read the fixture.
# GoReleaser takes the nearest tag as the version, so what this builds is not for use;
# the snapshot that follows in release-check starts by cleaning dist/.
RELEASE_NOTES_FIXTURE := scripts/testdata/release-notes.md

release-notes-check:
	@log="$$(mktemp)" || exit 1; trap 'rm -f "$$log"' EXIT; \
	$(GO) run $(GORELEASER) --verbose release --clean --skip=publish,sign,sbom,validate,announce --release-notes $(RELEASE_NOTES_FIXTURE) > "$$log" 2>&1 \
		|| { tail -n 40 "$$log"; echo "release-notes-check: GoReleaser failed"; exit 1; }; \
	./scripts/release-notes-check.sh $(RELEASE_NOTES_FIXTURE) "$$log"

# Validates .goreleaser.yaml, runs the release-notes check above, and builds every
# archive into dist/ as a snapshot without publishing, signing or writing SBOMs (cosign
# and syft run only in the release workflow). Not in verify: it builds five targets
# twice and downloads GoReleaser.
release-check:
	$(GO) run $(GORELEASER) check
	$(MAKE) release-notes-check
	$(GO) run $(GORELEASER) release --snapshot --clean --skip=sign,sbom,publish

verify: fmt-check vet lint lint-extra test docs-check deps-check vuln
	$(GO) mod verify
