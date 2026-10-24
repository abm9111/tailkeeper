# Scheduled policy check

A LaunchAgent on macOS and a systemd timer on Linux run one check a day. macOS cron has no keychain access, so cron on macOS is not the schedule. The Linux schedule is a systemd user timer: it runs as the user the credential belongs to. A system service would not see that user's session.

The check is read-only. It validates the live policy, compares it with a stored version of it, and verifies the audit log. When every command exits 0, it pings a dead-man URL taken from the environment. Exit 0 is the only success. The scripts name no ping service, hold no credential and print no value from the tailnet.

macOS paths that start with `$HOME` and Linux paths that start with `/home/you` are placeholders. Replace that prefix with the home directory. `make install` writes the binary at `$HOME/.local/bin/tailkeeper` unless the install prefix was changed; set `TAILKEEPER` to that absolute path. A LaunchAgent and a systemd user service do not load a login shell's `PATH`. Set `TAILKEEPER` to the absolute path so the check does not depend on either `PATH`, and keep every other path absolute too.

## The check

`TAILKEEPER`, `BASELINE_FILE` and `DEADMAN_URL` are set by the schedule, not written into the script.

### The baseline

**This default needs a policy update at least every 90 days.** Tailscale keeps the configuration audit log for 90 days, so a policy that nobody has updated for 90 days has no version in the log to point at; for a policy that changes rarely, use the saved file below from the start.

`BASELINE_FILE` is a file of one line: a version id from `acl history`, the one of the newest ACL update whose policy you accepted. The file holds no policy text, no login and no credential, only a time and the log's own event id, so it needs neither `personalData: show` nor mode 0600 (keep 0600 anyway). `acl diff --from-version` reads that stored policy from the configuration audit log as the old side and classifies the live policy (the new side) against it.

- **Reading the log needs the optional scope `logs:configuration:read`.** Without it the check exits 5 (`scope_missing`), which the script treats as an alert.
- **To start, and to accept the live policy as the new baseline:** run `tailkeeper acl history` with the same configuration the schedule uses and write the VERSION of the last row (the list is oldest first) to the file. Check that the time of that row is the update you accepted. Ids are for the `personalData` setting they were listed under: list them under the one the check runs with.
- **The id ages out.** `acl history` reads a window of at most 90 days. When the log no longer holds the id, `acl diff` prints `not_found` ("the log no longer holds this version") and exits 1. The script then writes its own alert, `alert: exit 1: the version id in PATH is no longer in the configuration audit log`, in which `PATH` is the path of the baseline file, and a second line that says how to re-baseline (write the newest VERSION of `acl history` to the file, or switch to the saved file below), and exits 1, so there is no ping. Any other exit 1 (the API, or an `unknown` answer) is `fail: tailkeeper exited 1`. Refresh the id before then.

If you use a saved file of the policy instead, the check script's diff line becomes `run "$TAILKEEPER" acl diff --against "$BASELINE_FILE" --fail-on change --quiet`, and the block that reads the version id is dropped. The file must be the policy text: the numbered layout that `acl get` prints on a terminal or into a redirect is a document, and `acl diff --against` refuses it (exit 2). Write the file as below. It needs `personalData: show` in the configuration of that command, so that the policy is not masked (a credential shape is still redacted, and a CRLF line end is written as LF), and `jq`; the filter writes nothing when the page is masked or cut. The policy is never in an argument. The check script itself never prints the policy. Run the commands again when you accept the live policy.

```sh
# shellcheck shell=sh
umask 077
page=$("$TAILKEEPER" acl get --json --max-bytes 4194304) &&
  printf '%s\n' "$page" | jq -er 'select(.truncated == false and .masked == false) | .policy' > "$BASELINE_FILE.new" &&
  mv "$BASELINE_FILE.new" "$BASELINE_FILE"
```

`policySha256` is the SHA-256 of the policy as `acl_get` shows it, so while `personalData` is `mask` two logins that mask to one form share it and a change that does not change the mask is invisible. `semanticDigest` says that the policy changed and does not say how. That is why the check classifies with `acl diff` and does not compare a hash.

### The invariants

The configuration key `acl.invariantsFile` is the absolute path of the invariants file. On macOS the user configuration directory is `$HOME/Library/Application Support/tailkeeper`. On Linux it is `$XDG_CONFIG_HOME/tailkeeper`, or `$HOME/.config/tailkeeper` when `XDG_CONFIG_HOME` is unset. A `config.hujson` in `/etc/tailkeeper` wins outright, and the user file is then ignored, so the key has to be in the file that loads. The value is an absolute path. A 0.5.0 binary refuses the key (`config_invalid`, exit 6). The configuration file is HuJSON, and the member below is JSON, which HuJSON accepts. The invariants file is a HuJSON object whose only keys are optional `tests` and optional `sshTests`. The invariants file and its directory must be owned by the user who runs the check and writable by no one else. A missing file or a symlink is `config_invalid`, and a file writable by the group or by others is `config_unsafe`; both exit 6, and nothing is sent. Another key, a syntax error or a pseudonym marker is an invalid result (exit 2), and nothing is sent.

```json
"acl": {
  "invariantsFile": "/home/you/.config/tailkeeper/invariants.hujson"
}
```

On macOS that path is `$HOME/Library/Application Support/tailkeeper/invariants.hujson` instead.

With the key set, `acl validate` of the live policy (no `--from` and no `--patch`) runs those tests. A failed invariant test exits 9. A name the test uses that does not resolve exits 2 (`unresolved`), which is also the exit for an invalid policy and for a refused command. Both fail this run. Exit 9 is a failed test of the policy or of the invariants; it is not exit 2.

`acl diff --from-version "$version" --fail-on change` compares the stored policy of the baseline (the old side) with the live policy (the new side). A change that `--fail-on change` counts exits 8. Those are the text report's `defaults`, `tests reduced`, `widening`, `tailscale-written` and `semantic`. Stderr then includes `findings_present` and `--fail-on matched`. A comment-only or format-only difference does not exit 8. The text report marks `tailscale-written` with `(expected)`. Those changes still count for `--fail-on change`, so they still exit 8. Adding `--ignore-tailscale-written` leaves them out of the list and out of `changed`; the count is still reported. The scheduled command does not pass that flag.

`--quiet` prints nothing of the result on exit 0. On any other exit the command prints the result, when there is one, or the error, when it failed before a result. When the audit line cannot be written, the warning `this read was not audited` is still written to stderr, including on exit 0, and the command keeps its own exit: `acl validate` and `acl diff` do not exit 7 for that warning. `audit verify` exits 7 (`audit_unavailable`) when the log cannot be opened or the chain does not verify. A missing older archive is a warning and exit 0. The script runs `audit verify` so exit 7 is an outcome of this schedule, and it sends that command's stdout to `/dev/null`. The script's own alerts stay on stderr.

Exit 5 is the credential unavailable or rejected, a missing scope, or the privacy key unavailable. Exit 7 is the audit log. The script names those two as alerts and exits with the same code. Exit 2, exit 8, exit 9 and every other non-zero code, including exit 1 (`unknown`, or the API) and exit 6 (the configuration), fail the run. The ping runs only after all three commands have exited 0.

`acl validate` and `acl diff` put `checkedAt` on the result, RFC 3339 in UTC. `acl validate` puts `policySha256` on the result once it has read the live policy: the SHA-256 of that policy as `acl_get` shows it. `acl diff` puts `policySha256` on each side it compared, computed the same way. An error, including exit 5, is not that result and carries neither field.

While masking is on, an email address in the policy as shown is followed by a pseudonym derived from the privacy key. Replacing the privacy key changes that pseudonym, so `policySha256` changes when the privacy key is replaced and the shown policy contains an email address. `policySha256` does not change when `personalData` is `show`, and it does not change when the shown policy has no email address. A `[p:` the policy itself holds is rewritten the same way for every key, so replacing one key with another does not change the hash on that account. `policyVersion`, when masking is on and a privacy key is loaded, is a keyed digest of the ETag and is omitted when there is no key; it is not `policySha256`.

The scheduled script does not pass `--json` and does not print `policySha256` or `checkedAt`. To read them, run the same `acl validate` or `acl diff` without `--quiet`. That prints the result, including text Tailscale wrote.

## The check script

Install this file at the path the schedule names. On macOS that path is `$HOME/Library/Application Support/tailkeeper/check-policy.sh`. On Linux it is `/home/you/.local/state/tailkeeper/check-policy.sh` (the state directory is `$XDG_STATE_HOME/tailkeeper`, or `$HOME/.local/state/tailkeeper` when `XDG_STATE_HOME` is unset). Mode 0700 is enough. The file holds no secret.

`DEADMAN_URL` is not printed. The value is one URL with no space, double quote, dollar sign or backtick. It is not an argument of `curl` or of `tailkeeper`: `curl` reads it from a configuration line on its standard input.

```sh
#!/bin/sh
# Scheduled policy check.
# TAILKEEPER is the absolute path of the binary. BASELINE_FILE is the absolute
# path of a file that holds one version id from acl history. DEADMAN_URL is the
# ping, set by the scheduler.
# DEADMAN_URL is not printed. It is not an argument of any command.
set -u
TAILKEEPER=${TAILKEEPER:?}
BASELINE_FILE=${BASELINE_FILE:?}
DEADMAN_URL=${DEADMAN_URL:?}

# A failing command is judged by the case below. set -e would exit first.
# Each command's stderr goes to a temporary file first, so that the case can
# tell an expired baseline from any other exit 1; the file is then shown.
errs=$(mktemp) || exit 1
trap 'rm -f "$errs"' EXIT
run() {
  code=0
  "$@" 2>"$errs" || code=$?
  cat "$errs" >&2
  case "$code" in
    0)
      ;;
    1)
      if grep -qF 'the log no longer holds this version' "$errs"; then
        echo "alert: exit 1: the version id in ${BASELINE_FILE} is no longer in the configuration audit log" >&2
        echo "alert: re-baseline: write the newest VERSION of acl history to ${BASELINE_FILE}, or use a saved policy file as the baseline" >&2
        exit 1
      fi
      echo "fail: tailkeeper exited 1" >&2
      exit 1
      ;;
    5)
      echo "alert: exit 5: the credential is unavailable or was rejected, a scope is missing, or the privacy key is unavailable" >&2
      exit 5
      ;;
    7)
      echo "alert: exit 7: the audit log is unavailable" >&2
      exit 7
      ;;
    2)
      echo "fail: exit 2: a name does not resolve, or the command was refused" >&2
      exit 2
      ;;
    8)
      echo "fail: exit 8: the check found a change" >&2
      exit 8
      ;;
    9)
      echo "fail: exit 9: a test of the policy or of the invariants failed" >&2
      exit 9
      ;;
    *)
      echo "fail: tailkeeper exited ${code}" >&2
      exit "$code"
      ;;
  esac
}

version=""
if [ -r "$BASELINE_FILE" ]; then
  IFS= read -r version < "$BASELINE_FILE" || :
fi
if [ -z "$version" ]; then
  echo "fail: ${BASELINE_FILE} holds no version id" >&2
  exit 1
fi

run "$TAILKEEPER" acl validate --quiet
run "$TAILKEEPER" acl diff --from-version "$version" --fail-on change --quiet
run "$TAILKEEPER" audit verify >/dev/null

# curl reads the URL from the configuration on its standard input, so the
# URL is not an argument. DEADMAN_URL is not printed.
curl --silent --show-error --fail --max-time 30 --output /dev/null --config - <<EOF
url = "$DEADMAN_URL"
EOF
```

## LaunchAgent

The plist is `~/Library/LaunchAgents/com.example.tailkeeper.policy.plist`. **launchd does not expand `$HOME` or `~` in a plist string.** Each `$HOME` in the plist below is a placeholder: write the absolute path of your home directory in its place in the copy on the machine, before you load it, or the agent cannot find its script. Do not commit that copy. It runs in the `gui` domain, which exists while the user is logged in to a graphical session. That is the session in which a credential wrapper can unlock. The published plist sets `TAILKEEPER` and `BASELINE_FILE` and does not set `DEADMAN_URL`. `StandardOutPath` and `StandardErrorPath` are under `$HOME/Library/Logs/` (a full path there too), so an alert written to stderr is kept. Add `DEADMAN_URL` to `EnvironmentVariables` on the machine, and do not commit that copy. The value is not a program argument.

`launchctl bootstrap gui/$UID $HOME/Library/LaunchAgents/com.example.tailkeeper.policy.plist` loads it. `launchctl bootout gui/$UID/com.example.tailkeeper.policy` removes it.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!-- launchd does not expand $HOME or ~: replace each $HOME below with the
     absolute path of your home directory before you load this file. -->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.tailkeeper.policy</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>$HOME/Library/Application Support/tailkeeper/check-policy.sh</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>TAILKEEPER</key>
    <string>$HOME/.local/bin/tailkeeper</string>
    <key>BASELINE_FILE</key>
    <string>$HOME/Library/Application Support/tailkeeper/baseline-version</string>
  </dict>
  <key>StandardOutPath</key>
  <string>$HOME/Library/Logs/tailkeeper-policy.log</string>
  <key>StandardErrorPath</key>
  <string>$HOME/Library/Logs/tailkeeper-policy.err</string>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key>
    <integer>7</integer>
    <key>Minute</key>
    <integer>15</integer>
  </dict>
</dict>
</plist>
```

## systemd timer

The user units are `/home/you/.config/systemd/user/tailkeeper-policy.service` and `tailkeeper-policy.timer` beside it. When `XDG_CONFIG_HOME` is set, systemd reads user units from `$XDG_CONFIG_HOME/systemd/user` instead of `~/.config/systemd/user`.

`EnvironmentFile=%h/.config/tailkeeper/deadman.env` is one line, mode 0600, not committed: the name `DEADMAN_URL`, an equals sign, and the URL. `%h` is the user's home directory. The unit file has no URL. `DEADMAN_URL` is not printed.

```ini
[Unit]
Description=Scheduled tailkeeper policy check

[Service]
Type=oneshot
Environment=TAILKEEPER=/home/you/.local/bin/tailkeeper
Environment=BASELINE_FILE=/home/you/.local/state/tailkeeper/baseline-version
EnvironmentFile=%h/.config/tailkeeper/deadman.env
ExecStart=/bin/sh /home/you/.local/state/tailkeeper/check-policy.sh
```

`ExecStart` runs the check script directly. The unit does not put `DEADMAN_URL` in an argument. `DEADMAN_URL` is not printed.

```ini
[Unit]
Description=Scheduled tailkeeper policy check

[Timer]
OnCalendar=daily
Persistent=true
Unit=tailkeeper-policy.service

[Install]
WantedBy=timers.target
```

`Persistent=true` runs a check that was missed because the machine was off, once it is back. A day the machine is off, the ping does not happen until that run. `systemctl --user daemon-reload` and `systemctl --user enable --now tailkeeper-policy.timer` start the timer. `loginctl enable-linger` keeps the user manager running when the user is logged out, which a user timer needs in order to fire then.
