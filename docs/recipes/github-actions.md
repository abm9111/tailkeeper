# GitHub Actions

A pull request workflow for `tailkeeper acl validate` and `tailkeeper acl diff`. Its `on` is `pull_request` only. It does not use `pull_request_target`, and it does not check out a fork's head under that event. It runs on `ubuntu-24.04`, the runner where tailkeeper reads `XDG_CONFIG_HOME` and `XDG_STATE_HOME` (`internal/config/load.go`). On macOS those two variables are not the configuration or the audit log.

Copy the workflow and the configuration block into the repository that holds the policy. The workflow reads the tailnet id from the secret `TAILKEEPER_TAILNET_ID` and the OAuth client id from the secret `TAILKEEPER_OIDC_CLIENT_ID`. Both are environment secrets of the environment `tailkeeper-policy`, not repository secrets, so only a job that has passed the environment's protection receives them. Both are secrets and not variables: GitHub prints a step's `env:` in the log header of the step and masks only secrets, and a tailnet id in a public pull request log is public. The configuration block below uses the documentation id `T1234CNTRL` so the block itself loads; the workflow does not install that literal. The workflow holds no client secret and no token, and prints neither id.

## What it runs

The workflow has three jobs. Which of the first two runs depends on where the pull request comes from; the third is the check to require.

- **`live`, a pull request from this repository.** It runs in the GitHub environment `tailkeeper-policy` and is the only job with `id-token: write`. `tailkeeper acl validate --format github` checks the proposal, `policy.hujson` in the pull request, against the live policy with the read identity. `--invariants` is the invariants file taken from the base commit, and `--fail-on warnings,change` is on. Exit 0 means the proposal's tests and the base branch's invariants passed. It does not mean the change is safe. `notChecked` is what that result still does not establish.
- **`offline`, a pull request from a fork.** It has no environment, no `id-token` and no secret. GitHub issues no OIDC token to a fork. `acl validate --offline` checks the proposal and the syntax of the invariants file here, sends nothing, and does not run the tests or the invariants (`serverChecked` is false). A pass of that command is not the pass in the previous paragraph. `--fail-on` is not set on that command: an offline validate computes none of the five kinds and refuses the flag. When both offline commands pass, the job still fails, with a message that a maintainer must run the live check from a branch of this repository. A fork pull request is never green on the offline checks alone.
- **`result`, the one check to require.** It needs both jobs, runs always (`if: always()`), and has no environment, no `id-token` and no secret. It fails unless `live` succeeded and `offline` was skipped, which is what a pull request from this repository gives. A pull request from a fork runs `offline`, which fails by design, so `result` fails too. Branch protection counts a job that its `if` skipped as a pass, so requiring `live` alone would let every fork pull request through and requiring `offline` alone would let every pull request from this repository through. Require only the status check `tailkeeper-acl-result`, the `name:` of this job.

Both check jobs also run `tailkeeper acl diff --offline --against` the base commit's `policy.hujson` `--from` the proposal `--fail-on change --format github`, which compares the two files. It needs no credential. `--fail-on change` on a diff of two files can exit 8. The constructs Tailscale writes itself count toward that exit unless `--ignore-tailscale-written` is set; this recipe does not set it, so a pull request that only changes one of those constructs still fails the job.

In each of those two jobs the exit is the validate command's exit when that is not 0, and otherwise the diff's exit. The `live` job's `case` has an arm for 0, 1, 2, 5, 8 and 9, and a `*` arm that fails the job. Those six are a success, an API error or an ACL answer of `unknown`, usage or a rejected policy, a missing credential, findings (`--fail-on`), and a failed assertion. Exit 6 (configuration) and exit 7 (the audit log) fall through to `*` and fail the job. An unlisted exit must not look green. The `offline` job's `case` has the same arms except 5, and its arm for 0 is the failure above. The `result` job passes only for `skipped` and `success`, in that order for `offline` and `live`, and fails for every other pair, a cancelled or failed job included.

## Identity, forks and cost

The OAuth client has the policy scopes only: `policy_file:read`, `devices:core:read` and `devices:posture_attributes:read`. It does not request `users:read`. A person in a proposal is named by a pseudonym only when that scope is granted, and this job does not grant it.

The four situations are a public or a private repository, and a pull request from a fork or from this repository. A pull request from a fork runs only the offline job. personalData stays mask, including on a public repository: the log of a public pull request is public, and masking is done in this process. Masking covers personal data only. On a public repository the annotations and the step summary carry text derived from the live policy (warnings marked `existing:`, the rules a proposal changes), and that text is masked for personal data and not for tag names, host names or rule shapes. Use a private repository for a policy whose structure is not public.

Tailscale's own limit is per credential and unpublished. tailkeeper's bucket (`acl.validatePerMinute`, 30 in the configuration, which is also the default) protects a process, not a CI loop. Each job is a new process. When the check exits non-zero, the summary step runs the same commands again with `--format markdown`, and that is another process and, in the `live` job, another validation request.

## The token

tailkeeper's `oidc` provider fetches the GitHub Actions token itself: with no `tokenFile` set, it asks `ACTIONS_ID_TOKEN_REQUEST_URL` with `ACTIONS_ID_TOKEN_REQUEST_TOKEN` for the audience `api.tailscale.com/<clientId>` (`internal/creds/read.go`). GitHub sets those two variables for a job with `id-token: write`, and only the `live` job has it. The workflow never reads, writes or prints the token. The configuration it writes has a `clientId` and no `tokenFile`, so no token file exists on the runner. The audience is the provider's default; the workflow does not set one.

## Invariants

The invariants file and the base policy come from a second checkout of `github.event.pull_request.base.sha` at `base/`, with credentials not persisted, so a private repository does not need `git fetch` after the credential is removed and the pull request cannot replace the copy it is checked against. CODEOWNERS on `invariants.hujson` and `policy.hujson` covers those files: a change to either needs the owners' review before it becomes the base commit. A local invariants file is as trusted as the shell that wrote it; this job does not use one from the pull request.

## Who can use the identity

The `live` job names the GitHub environment `tailkeeper-policy`, and the workflow's own permissions are `contents: read`; only that job adds `id-token: write`, so a third-party action in the `offline` job cannot mint a token. Every step of the `live` job, including the pinned `actions/checkout` and `sigstore/cosign-installer` and the downloaded binary, can request the OIDC token; the SHA pins and the environment's reviewer are the controls. The workflow cannot create the environment or the credential's condition. Do both in the settings, before the first run:

1. Create the environment `tailkeeper-policy` in the repository before the first run, and add required reviewers to it. Required reviewers on an environment are available for public repositories, and for private repositories only on a paid GitHub plan; on a plan without them this step cannot be done and the environment is a name, not a gate. A workflow that names an environment that does not exist makes GitHub create it with no protection rules, so a first run without this step is ungated. Turn on "Prevent self-review". With one maintainer, who is also the author of every pull request, either nobody can approve a run ("Prevent self-review" on) or that person approves their own run (off); the gate is then that person's reading of the change to the workflow file. Set no deployment-branch rule on the environment: a pull request job runs on `refs/pull/N/merge`, which a rule for protected or named branches cannot match, so the job would not start.
2. Bind the Tailscale federated credential's subject claim to that environment. GitHub's subject for a job that names an environment is `repo:OWNER/REPO:environment:tailkeeper-policy` (replace `OWNER/REPO`); it replaces the `repo:OWNER/REPO:pull_request` form, so a credential that accepts only this subject refuses a job that names no environment.
3. Require only the status check `tailkeeper-acl-result` in the branch protection of the base branch, and no other check of this workflow. It is the `name:` of the `result` job: branch protection matches a job's name, or its id when it has none, and this name was not checked on a runner. A job skipped by its `if` counts as a pass there. The workflow has no `paths` or `paths-ignore` on `on.pull_request`, and must not get one: a workflow that does not run never reports `tailkeeper-acl-result`, so a required check would block every pull request that does not touch the policy. Skipping work on a pull request that leaves the policy files alone is a step inside the jobs that compares each policy file with its copy in the base checkout at `base/` (`cmp`; both checkouts hold one commit, so `git diff` against the base SHA has nothing to compare with), and `result` still reports.

With 1 and 2, a person approves each run of the `live` job before it can mint a token, and only an approved job receives the two environment secrets. The run executes the workflow file in the pull request's branch, so read the pull request's change to that file before you approve.

**Guard the workflow file.** Under `pull_request` the workflow that runs is the pull request's own, so add the workflow file to CODEOWNERS beside the policy and invariants files and require code-owner review on the default branch. Without that, a pull request can edit `result`, or remove the `live` job, and pass: the environment's reviewer is asked only when the `live` job still runs. Cover the whole `.github/workflows/` directory, not only this file: a pull request can add a workflow as well as edit one.

**Without a required reviewer the environment is a name, not a gate.** The job mints an OIDC token on any pull request from this repository, and the workflow file that asks for it is the one in the pull request's branch. Anyone who can push a branch to this repository can therefore edit the workflow, open a pull request, and have the job read the policy, the devices and their posture attributes (the three scopes above, or whatever scopes the client holds) with the read identity, with no one to approve the run. Without the subject condition a job that names no environment can mint a token as well. Treat the read identity as available to everyone with write access to the repository unless steps 1 and 2 are both done. A forked pull request cannot: it gets no OIDC token.

## Pull requests the job cannot check

- **A pull request from Dependabot** is from this repository, so the `live` job runs. GitHub withholds two things from a Dependabot-triggered run: the `id-token` permission, and the Actions secrets (it gives the run Dependabot secrets in their place). Either way the job fails closed: the Check step stops with `OIDC_CLIENT_ID is not set` and the job exits 5, or GitHub refuses the token request before the step, and the job fails. This was not run on a real runner. With `tailkeeper-acl-result` required, that blocks every Dependabot pull request from merging, a dependency update included, until a maintainer lands the change another way, for example from a branch of this repository. Dependabot secrets do not help, because the `id-token` permission is still withheld. A `paths` filter on `on.pull_request` is not the fix either, because step 3 of "Who can use the identity" says why a required check cannot have one.
- **The first policy.** The job copies `policy.hujson` and `invariants.hujson` from the base commit. When the pull request adds either file, the base has no copy, `cp` fails in the step "Files from the base commit", and the job fails (exit 1, "the policy check did not finish") before any check. Both files have to exist on the base branch first. The pull request that adds them fails the check; the workflow triggers on `pull_request` only, so a push that adds them directly to the base branch runs nothing.

## Where files go

The job sets `XDG_CONFIG_HOME` and `XDG_STATE_HOME` under `runner.temp`. The audit log is `$XDG_STATE_HOME/tailkeeper/audit.jsonl`. tailkeeper writes that log and does not write the policy, the workspace, or the cache of `tailscale/gitops-acl-action` (this recipe does not run that action). The release archive, its checksums and its signature are downloaded into `$RUNNER_TEMP/tailkeeper/download`, not into the workspace, which holds the pull request's files: a file of the pull request cannot be a link that a download writes through.

A system directory `/etc/tailkeeper` wins when it contains `config.hujson`: tailkeeper loads that file and ignores the one this job writes. The Check step stops when that file exists (exit 6, which the last step turns into a failure), so it does not validate with a configuration it did not write.

The installed configuration's `invariantsFile` is an absolute path under `$RUNNER_TEMP/tailkeeper`. The configuration block below uses `/tmp/tailkeeper` so the block itself loads: a configuration file cannot contain a shell variable, and a relative path is refused. The workflow does not install that `/tmp` path. It writes the same fields with the runner temporary directory, with `tailnetId` and `clientId` taken from the two environment secrets, and with mode 0600 in a directory of mode 0700. The two ids are checked to be plain identifiers (letters, digits, dot, underscore and hyphen) before they are written into the file.

## Verify the release first

The binary is the release archive, and only after the three checks in the README's "Verify a release" section. `cosign verify-blob` must print `Verified OK`, the checksum step must say the archive is `OK`, and both `gh attestation verify` commands must exit 0. One failure stops the job, and the binary is not run. The README's checksum line is `shasum -a 256 -c -`; on Linux, which this runner is, that step says to use `sha256sum -c -`, and the workflow does, with the `shasum` line as the fallback when `sha256sum` is missing. The signer identity is written out whole and compared exactly (`--certificate-identity`, never a pattern). `VERSION` is `v0.6.0`, the release these commands belong to. Until that tag is published, or if a check fails, the verify step stops the job.

## Annotations and the summary

`--format github` writes at most ten annotations of each severity and then a line that says to see the summary. The tool writes nothing to `$GITHUB_OUTPUT` or `$GITHUB_STEP_SUMMARY`. The summary step is the recipe's. It runs only after exit 1, 2, 8 or 9, the exits of a result, which is when the formatter may have written annotations, and it appends `--format markdown` to `$GITHUB_STEP_SUMMARY`. A missing credential (5), a configuration error (6) or an audit-log error (7) has no annotations, and the summary step does not run the commands again. Nothing in the workflow assigns `GITHUB_OUTPUT`.

```yaml
name: tailkeeper-acl

on:
  pull_request:

permissions:
  contents: read

jobs:
  offline:
    # A pull request from a fork: no environment, no id-token, no secret.
    if: github.event.pull_request.head.repo.full_name != github.repository
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    steps:
      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Checkout the base commit
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          ref: ${{ github.event.pull_request.base.sha }}
          path: base
          persist-credentials: false

      # invariants.hujson and policy.hujson come from the base checkout.
      # CODEOWNERS on those paths covers the files this job checks.
      - name: Files from the base commit
        env:
          XDG_CONFIG_HOME: ${{ runner.temp }}/config
          XDG_STATE_HOME: ${{ runner.temp }}/state
        run: |
          set -eu
          umask 077
          install -d -m 700 "$RUNNER_TEMP/tailkeeper" "$XDG_CONFIG_HOME/tailkeeper" "$XDG_STATE_HOME/tailkeeper"
          cp base/invariants.hujson "$RUNNER_TEMP/tailkeeper/invariants.hujson"
          cp base/policy.hujson "$RUNNER_TEMP/tailkeeper/policy.hujson"

      - name: Install cosign
        uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2

      - name: Verify the release
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          set -eu
          set -o pipefail
          VERSION=v0.6.0
          ARCHIVE="tailkeeper_${VERSION#v}_linux_amd64.tar.gz"
          IDENTITY="https://github.com/abm9111/tailkeeper/.github/workflows/release.yml@refs/tags/${VERSION}"
          rel="https://github.com/abm9111/tailkeeper/releases/download/${VERSION}"
          d="$RUNNER_TEMP/tailkeeper/download"
          install -d -m 700 "$d"
          cd "$d"
          curl -fsSL -o "$ARCHIVE" "${rel}/${ARCHIVE}"
          curl -fsSL -o checksums.txt "${rel}/checksums.txt"
          curl -fsSL -o checksums.txt.sigstore.json "${rel}/checksums.txt.sigstore.json"
          cosign verify-blob checksums.txt \
            --bundle checksums.txt.sigstore.json \
            --certificate-identity "$IDENTITY" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com
          line="$(awk -v f="$ARCHIVE" '$2 == f' checksums.txt)"
          if [ -z "$line" ]; then echo "no line for $ARCHIVE in checksums.txt" >&2; false; fi
          if command -v sha256sum >/dev/null 2>&1; then printf '%s\n' "$line" | sha256sum -c -; else printf '%s\n' "$line" | shasum -a 256 -c -; fi
          gh attestation verify "$ARCHIVE" --repo abm9111/tailkeeper --cert-identity "$IDENTITY"
          gh attestation verify checksums.txt --repo abm9111/tailkeeper --cert-identity "$IDENTITY"
          tar -xzf "$ARCHIVE" tailkeeper
          install -m 755 tailkeeper "$RUNNER_TEMP/tailkeeper/tailkeeper"
          cd "$RUNNER_TEMP"
          rm -rf "$d"

      - name: Check the policy
        env:
          XDG_CONFIG_HOME: ${{ runner.temp }}/config
          XDG_STATE_HOME: ${{ runner.temp }}/state
        run: |
          set -eu
          set -o pipefail
          tk="$RUNNER_TEMP/tailkeeper/tailkeeper"
          inv="$RUNNER_TEMP/tailkeeper/invariants.hujson"
          base="$RUNNER_TEMP/tailkeeper/policy.hujson"
          set +e
          "$tk" acl validate --from policy.hujson --offline --invariants "$inv" --format github
          v=$?
          "$tk" acl diff --offline --against "$base" --from policy.hujson --fail-on change --format github
          d=$?
          set -e
          if [ "$v" -eq 0 ]; then
            printf '%s\n' "$d" > "$RUNNER_TEMP/tailkeeper/exit"
          else
            printf '%s\n' "$v" > "$RUNNER_TEMP/tailkeeper/exit"
          fi

      - name: Write the step summary
        if: always()
        env:
          XDG_CONFIG_HOME: ${{ runner.temp }}/config
          XDG_STATE_HOME: ${{ runner.temp }}/state
        run: |
          set -eu
          f="$RUNNER_TEMP/tailkeeper/exit"
          if [ ! -s "$f" ]; then
            exit 0
          fi
          IFS= read -r code < "$f"
          case "$code" in
            1|2|8|9) ;;
            *) exit 0 ;;
          esac
          tk="$RUNNER_TEMP/tailkeeper/tailkeeper"
          inv="$RUNNER_TEMP/tailkeeper/invariants.hujson"
          base="$RUNNER_TEMP/tailkeeper/policy.hujson"
          set +e
          {
            echo "## tailkeeper"
            echo "Findings past ten annotations say to see the summary."
            "$tk" acl validate --from policy.hujson --offline --invariants "$inv" --format markdown
            echo "## diff"
            "$tk" acl diff --offline --against "$base" --from policy.hujson --fail-on change --format markdown
          } >> "$GITHUB_STEP_SUMMARY"
          set -e

      - name: Exit
        if: always()
        run: |
          set -eu
          f="$RUNNER_TEMP/tailkeeper/exit"
          if [ ! -s "$f" ]; then
            echo "the policy check did not finish" >&2
            exit 1
          fi
          IFS= read -r code < "$f"
          case "$code" in
            0)
              echo "::error title=tailkeeper::This pull request is from a fork. Only the offline checks ran: the proposal, the syntax of the invariants file and the diff against the base policy. The policy tests and the invariants did not run. A maintainer must run the live check from a branch of this repository." >&2
              exit 1
              ;;
            1) exit 1 ;;
            2) exit 2 ;;
            8) exit 8 ;;
            9) exit 9 ;;
            *) echo "exit ${code} is not one this recipe handles" >&2; exit 1 ;;
          esac

  live:
    # A pull request from this repository: the only job with id-token.
    if: github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    environment: tailkeeper-policy
    permissions:
      contents: read
      id-token: write
    steps:
      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Checkout the base commit
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          ref: ${{ github.event.pull_request.base.sha }}
          path: base
          persist-credentials: false

      # invariants.hujson and policy.hujson come from the base checkout.
      # CODEOWNERS on those paths covers the files this job checks.
      - name: Files from the base commit
        env:
          XDG_CONFIG_HOME: ${{ runner.temp }}/config
          XDG_STATE_HOME: ${{ runner.temp }}/state
        run: |
          set -eu
          umask 077
          install -d -m 700 "$RUNNER_TEMP/tailkeeper" "$XDG_CONFIG_HOME/tailkeeper" "$XDG_STATE_HOME/tailkeeper"
          cp base/invariants.hujson "$RUNNER_TEMP/tailkeeper/invariants.hujson"
          cp base/policy.hujson "$RUNNER_TEMP/tailkeeper/policy.hujson"

      - name: Install cosign
        uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2

      - name: Verify the release
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          set -eu
          set -o pipefail
          VERSION=v0.6.0
          ARCHIVE="tailkeeper_${VERSION#v}_linux_amd64.tar.gz"
          IDENTITY="https://github.com/abm9111/tailkeeper/.github/workflows/release.yml@refs/tags/${VERSION}"
          rel="https://github.com/abm9111/tailkeeper/releases/download/${VERSION}"
          d="$RUNNER_TEMP/tailkeeper/download"
          install -d -m 700 "$d"
          cd "$d"
          curl -fsSL -o "$ARCHIVE" "${rel}/${ARCHIVE}"
          curl -fsSL -o checksums.txt "${rel}/checksums.txt"
          curl -fsSL -o checksums.txt.sigstore.json "${rel}/checksums.txt.sigstore.json"
          cosign verify-blob checksums.txt \
            --bundle checksums.txt.sigstore.json \
            --certificate-identity "$IDENTITY" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com
          line="$(awk -v f="$ARCHIVE" '$2 == f' checksums.txt)"
          if [ -z "$line" ]; then echo "no line for $ARCHIVE in checksums.txt" >&2; false; fi
          if command -v sha256sum >/dev/null 2>&1; then printf '%s\n' "$line" | sha256sum -c -; else printf '%s\n' "$line" | shasum -a 256 -c -; fi
          gh attestation verify "$ARCHIVE" --repo abm9111/tailkeeper --cert-identity "$IDENTITY"
          gh attestation verify checksums.txt --repo abm9111/tailkeeper --cert-identity "$IDENTITY"
          tar -xzf "$ARCHIVE" tailkeeper
          install -m 755 tailkeeper "$RUNNER_TEMP/tailkeeper/tailkeeper"
          cd "$RUNNER_TEMP"
          rm -rf "$d"

      - name: Check the policy
        env:
          XDG_CONFIG_HOME: ${{ runner.temp }}/config
          XDG_STATE_HOME: ${{ runner.temp }}/state
          OIDC_CLIENT_ID: ${{ secrets.TAILKEEPER_OIDC_CLIENT_ID }}
          TAILNET_ID: ${{ secrets.TAILKEEPER_TAILNET_ID }}
        run: |
          set -eu
          set -o pipefail
          umask 077
          if [ -e /etc/tailkeeper/config.hujson ]; then
            echo "tailkeeper would load /etc/tailkeeper/config.hujson and ignore the configuration this job writes" >&2
            printf '%s\n' 6 > "$RUNNER_TEMP/tailkeeper/exit"
            exit 0
          fi
          tk="$RUNNER_TEMP/tailkeeper/tailkeeper"
          inv="$RUNNER_TEMP/tailkeeper/invariants.hujson"
          base="$RUNNER_TEMP/tailkeeper/policy.hujson"
          conf="$XDG_CONFIG_HOME/tailkeeper/config.hujson"
          plain() {
            case "$1" in
              "" | *[!A-Za-z0-9._-]*) return 1 ;;
            esac
          }
          v=0
          if [ -z "${OIDC_CLIENT_ID:-}" ]; then
            echo "OIDC_CLIENT_ID is not set" >&2
            v=5
          elif [ -z "${TAILNET_ID:-}" ]; then
            echo "TAILKEEPER_TAILNET_ID is not set" >&2
            v=5
          elif ! plain "$OIDC_CLIENT_ID" || ! plain "$TAILNET_ID"; then
            echo "the OAuth client id or the tailnet id is not a plain identifier" >&2
            v=6
          else
            cat > "$conf" <<EOF
          {
            "personalData": "mask",
            "defaultContext": "ci",
            "contexts": {
              "ci": {
                "tailnetId": "$TAILNET_ID",
                "credentials": {"read": {"provider": "oidc", "clientId": "$OIDC_CLIENT_ID"}}
              }
            },
            "acl": {"invariantsFile": "$inv", "validatePerMinute": 30}
          }
          EOF
            set +e
            "$tk" acl validate --from policy.hujson --invariants "$inv" --fail-on warnings,change --format github
            v=$?
            set -e
          fi
          set +e
          "$tk" acl diff --offline --against "$base" --from policy.hujson --fail-on change --format github
          d=$?
          set -e
          if [ "$v" -eq 0 ]; then
            printf '%s\n' "$d" > "$RUNNER_TEMP/tailkeeper/exit"
          else
            printf '%s\n' "$v" > "$RUNNER_TEMP/tailkeeper/exit"
          fi

      - name: Write the step summary
        if: always()
        env:
          XDG_CONFIG_HOME: ${{ runner.temp }}/config
          XDG_STATE_HOME: ${{ runner.temp }}/state
        run: |
          set -eu
          f="$RUNNER_TEMP/tailkeeper/exit"
          if [ ! -s "$f" ]; then
            exit 0
          fi
          IFS= read -r code < "$f"
          case "$code" in
            1|2|8|9) ;;
            *) exit 0 ;;
          esac
          tk="$RUNNER_TEMP/tailkeeper/tailkeeper"
          inv="$RUNNER_TEMP/tailkeeper/invariants.hujson"
          base="$RUNNER_TEMP/tailkeeper/policy.hujson"
          set +e
          {
            echo "## tailkeeper"
            echo "Findings past ten annotations say to see the summary."
            "$tk" acl validate --from policy.hujson --invariants "$inv" --fail-on warnings,change --format markdown
            echo "## diff"
            "$tk" acl diff --offline --against "$base" --from policy.hujson --fail-on change --format markdown
          } >> "$GITHUB_STEP_SUMMARY"
          set -e

      - name: Exit
        if: always()
        run: |
          set -eu
          f="$RUNNER_TEMP/tailkeeper/exit"
          if [ ! -s "$f" ]; then
            echo "the policy check did not finish" >&2
            exit 1
          fi
          IFS= read -r code < "$f"
          case "$code" in
            0) exit 0 ;;
            1) exit 1 ;;
            2) exit 2 ;;
            5) exit 5 ;;
            8) exit 8 ;;
            9) exit 9 ;;
            *) echo "exit ${code} is not one this recipe handles" >&2; exit 1 ;;
          esac

  result:
    # The one check to require. Branch protection counts a job that its `if` skipped
    # as a pass, so neither of the two jobs above is safe to require alone. No
    # environment, no id-token, no secret, no checkout.
    name: tailkeeper-acl-result
    needs: [offline, live]
    if: always()
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - name: Result
        env:
          OFFLINE_RESULT: ${{ needs.offline.result }}
          LIVE_RESULT: ${{ needs.live.result }}
        run: |
          set -eu
          case "${OFFLINE_RESULT}/${LIVE_RESULT}" in
            skipped/success) ;;
            *)
              echo "::error title=tailkeeper::The policy check did not pass (offline ${OFFLINE_RESULT}, live ${LIVE_RESULT}). A pull request from this repository passes when the live job succeeds; a pull request from a fork does not pass."
              exit 1
              ;;
          esac
```

```hujson
{
  // Replace tailnetId. T1234CNTRL is the documentation id.
  // Replace clientId with the OAuth client id of the federated identity.
  // In the workflow those two values are the secrets TAILKEEPER_TAILNET_ID
  // and TAILKEEPER_OIDC_CLIENT_ID of the environment tailkeeper-policy.
  // They are identifiers. This block holds no client secret and no token.
  // There is no tokenFile: the oidc provider asks the job's token endpoint itself.
  // invariantsFile is absolute so this block loads. The workflow writes the
  // installed file with that path under the runner temporary directory
  // ($RUNNER_TEMP/tailkeeper), not this /tmp path.
  "personalData": "mask",
  "defaultContext": "ci",
  "contexts": {
    "ci": {
      "tailnetId": "T1234CNTRL",
      "credentials": {
        "read": {
          "provider": "oidc",
          "clientId": "replace-with-your-client-id"
        }
      }
    }
  },
  "acl": {
    "invariantsFile": "/tmp/tailkeeper/invariants.hujson",
    "validatePerMinute": 30
  }
}
```
