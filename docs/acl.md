# Checking a policy

tailkeeper only reads. Apart from the credential's token request, the only API request it sends other than GET is `POST .../acl/validate`. `acl_test`, `acl_validate` and `doctor --probe` send a test, the live policy, a proposed policy or a synthetic document to that call. The call changes nothing. There is no command that applies a policy.

## What an agent does

Read the policy at a glance first: `acl_get` with `view` set to `summary`, or the resource `tailnet://acl`. Fetch a page of the text only for the part you need. The summary is a display copy. It is not the file to edit.

When a person is involved, call `users_list` and use the pseudonym that call gives for them.

Check one source with `acl_test`. It evaluates that source against the live policy. `srcPostureAttrs` name the posture attributes of that source. When the live policy has `defaultSrcPosture` or a rule with `srcPosture`, the result's posture is `gated` and it names the attributes a test without them does not match; `none` means no such rule was read, and `unknown` means the live policy could not be read, which is not a pass of that question. `srcPostureAttrs` are refused together with SSH tests. Validate a proposed change as a patch with `acl_validate`. A whole policy is also accepted; the path for an agent is the patch, because a page from `acl_get` is a masked display copy and not a text to send back. Compare two policies with `acl_diff`. A stored policy is named with `--from-version` and `--to-version`, and the ids come from `acl_history`.

On 20 Oct 2026 an absent `acls` section failed the same way as a policy that accepts everything, and `acls` set to null failed the same way. `acls: []` passed. `grants: []` did not fail that way. Its answer had the same shape as the `acls: []` pass: a root object, and no `message` and no `data`. That pass is deny-all, so `grants: []` is deny-all in the same way.

## What the owner does after a pass

The agent validates a patch. The owner applies the change, in the admin console or in the policy file they keep. tailkeeper does not apply it. Unless `personalData` is `show`, no command exports the policy unmasked. With `personalData` set to `show`, `acl_get` returns the text as the API returned it; the scheduled check writes its saved baseline that way.

After the change is live, `acl_get` with `view` set to `summary` returns `semanticDigest` when a privacy key is loaded. The validation of the patch returned `patchedDigest`, and only when a privacy key is loaded. The two are equal when the live policy means exactly what was validated. Without a privacy key neither digest is present, so there is nothing to compare.

## What a pass means

For `acl_validate`, status `pass` (exit 0) means Tailscale accepts the text, the tests that ran passed, and the invariants passed when they ran. That is not that the change is safe. `notChecked` names what was not established, on `acl_validate` and on `acl_diff`: `access_change`, `app_capabilities`, `downgrades`, `lockout`, `ssh_lockout` and `via`. A small change to an alias, a group or a host can widen access. A diff does not say whether it did.

`unknown` (exit 1) is not a pass. For `acl_validate` it is an answer tailkeeper does not recognise, the invariants gave no clear answer, or the live policy changed while the check ran (`liveChanged` is true). For `acl_test` it is a line that could not be paired, a half of the call that did not run, or an SSH `check` user with no line. `invalid` and `rejected` are exit 2 for `acl_validate`. `unresolved` (exit 2) is a source or a destination Tailscale cannot resolve, for `acl_test` and for `acl_validate`. A failed assertion is `fail` (exit 9). `acl_test`'s status is `pass`, `fail`, `unresolved` or `unknown`.

An online pass is about the live policy at the moment it was checked: `dependsOnLiveState` is true. An invariants file that holds no tests runs nothing, and the result says so in a notice.

An offline pass of `acl_validate` was not sent to Tailscale. `serverChecked` is false, and `notChecked` also names `server_validation` and `tests`.

## Invariants

An invariants file is a HuJSON object. It may hold `tests` and `sshTests`, each an array of tests in the policy's own syntax, and no other key. Any other key is invalid. A `[p:` anywhere in the file is invalid: the file holds logins, and a pseudonym stops naming anyone when the privacy key is replaced.

The file is unsigned. `invariantsSignature` is `none`. It is as trusted as the shell that wrote it: tailkeeper checks no signature.

`acl.invariantsFile` is an absolute path. The file must be a regular file that you own, in a directory you own, and writable by no one else. On Windows only the regular file is checked. A path that is set and cannot be read fails every call that uses it: `config_invalid` when the file is missing or unreadable, `config_unsafe` for the wrong owner or mode, both exit 6. It is never read as none.

An MCP call of `acl_validate` always uses that file. On the command line, `--invariants FILE` replaces it for one command and `--no-invariants` leaves it out. Giving both is refused. The file `--invariants` names is opened like any other policy file on the command line. The ownership check above is for the configured path.

When the file applies, tailkeeper validates the text, then validates it again with that text's own `tests` and `sshTests` removed and the file's tests appended, plus one canary. A reply that does not show the canary failed as one assertion is `unknown`, not a pass.

`doctor --policy --out FILE` writes a starter the owner reviews. The file is created mode 0600 and is never overwritten, and the command prints the path and the list of controls, never a login. The test language cannot express these four, and the guide lists the same four the starter prints:

- `autogroup:admin` as a source
- an application capability
- `via`
- SSH autogroups and groups

On 20 Oct 2026 a CIDR and `autogroup:internet`, as destinations of a test, came back unevaluable.

## Pseudonyms and the subject rule

While masking is on, a user's login enters a call only as a pseudonym or as a masked value that carries one. A typed login in `acl_test`'s `src` or a destination, an SSH destination included, is `filter_refused`, and so is a literal login in a proposal, a patch, or a text given to `acl_diff` over MCP. The check reads keys and values, and it skips comments. It skips no short word: a login with a one-character local part is refused like any other. Setting `personalData` to `show` is the escape.

When a result echoes text, masking leaves three things as they are. A word shorter than two bytes is not masked. A word the caller typed is not masked as a local part. A local part of a login this call did not resolve is not found. An echo of text the caller typed is masked without a pseudonym.

On 20 Oct 2026 the six positions of a login were not accepted alike. Five answers had no `message`. The object key, in `hosts`, had a `message`. The check covers keys.

The command line marks its call as the operator's, with one exception: a login typed as an argument of `acl test` is refused there too. A file named with `--from`, `--against`, `--patch` or `--invariants`, standard input given with `-`, and the file `acl.invariantsFile` names are the operator's own documents. A login in them is accepted and sent to Tailscale, and shown masked, with no pseudonym beside it. A `[p:` in one of those files is invalid.

## Offline use

`acl validate --offline` parses a policy file, or an invariants file, and sends nothing. `acl diff OLD NEW` compares two files and sends nothing. `--against FILE` names the old side and `--from FILE` the new side, and `--against live` is the live policy. A stored policy is named with `--from-version` for the old side and `--to-version` for the new side; `acl history` lists the ids. Neither an offline diff nor `acl validate --offline` needs a credential. `serverChecked` is false on `acl validate --offline` (`acl diff` has no such field; a diff of two files sends nothing either way). Exit 0 is a local pass. Exit 2 is a text the local check rejects. A patch cannot be checked offline: a patch is applied to the live policy, so the command asks for the whole policy instead.

`acl validate --offline --invariants FILE` checks that file's syntax and does not run its tests. `notChecked` then also names `invariants`.

## SSH tests

SSH tests go through a copy of the live policy: its own tests and SSH tests removed, the caller's SSH tests appended, and two canaries appended. Each must come back once. A missing canary is `unknown`, never a pass.

An invariants file may hold `sshTests`. Those entries are part of the second validation. The canary of the second validation is a `tests` canary only: the SSH canary belongs to `acl_test`, so a second validation that lost the `sshTests` array would not be noticed.

On 20 Oct 2026 a policy-mode call ran `sshTests`. The failure had the SSH form, and the passing entry alone passed.

## Terraform

The Terraform provider owns the policy file. A drift check compares the live policy with that provider's rendered output, not with a hand-edited copy. The rendered file is an operator file. tailkeeper shows a login in it masked. This release does not ship a Terraform provider, and it does not ship a Terraform recipe.

## Relative paths

A relative `--from`, `--against`, `--patch` or `--invariants` is read in the process's working directory. `acl.invariantsFile` must be an absolute path. `--against live` means the live policy. A file of that name is `./live`.

## Recipes

The GitHub Actions recipe is [docs/recipes/github-actions.md](recipes/github-actions.md). It checks a proposal with `acl validate` and compares it with the base policy with `acl diff --against` and `--from`. The job that reads the live policy runs in a named GitHub environment, and a pull request from a fork gets the offline checks only. With a required reviewer on the environment and the federated credential's subject bound to that environment, only an approved run gets the identity; without the binding, a job that names no environment gets a token with no approval. Under `pull_request` the workflow that runs is the pull request's own, so add the workflow file to CODEOWNERS beside the policy and invariants files and require code-owner review on the default branch. Require only the status check `tailkeeper-acl-result`, the workflow's `result` job, because branch protection counts a job that its condition skipped as a pass. A stored policy, when the check has one, is `acl diff --from-version` and `--to-version`, and `acl history` lists those ids.

The scheduled run, a LaunchAgent and a systemd timer, is [docs/recipes/cron.md](recipes/cron.md). It validates the live policy and compares it with a baseline. By default the baseline is the version id of the newest ACL update you accepted, which `acl history` lists: `acl diff --from-version` reads that stored policy from the configuration audit log, and that needs the optional scope `logs:configuration:read`. The id ages out after 90 days without a policy update, and then the check fails until you refresh it or use the alternative, a saved policy file named with `--against`, written with `personalData` set to `show`.
