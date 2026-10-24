# tailkeeper threat model

This is section 3 of the design (`docs/design.md`), published on its own as the design requires. Section numbers in it refer to that document. It describes the whole design, including the approval gate and hardened mode, which later milestones build: 0.x releases are read-only, so the write path below does not exist yet.

## Assets

1. The tailnet policy file: the root of every authorization decision, including who may apply tags and which routes are auto-approved.
2. Devices, routes, DNS, users, keys, webhooks, log streams, posture integrations, services, tailnet settings.
3. The write credentials (§7) and every credential the API can mint.
4. Personal data: user emails and names inside the policy file, plans, audit-log `old`/`new` values and `policyUpdate` webhook payloads; hardware serial numbers; client public endpoints.
5. tailkeeper's own audit trail.

## Actors

| Actor | Capability | Intent |
|---|---|---|
| Owner | Everything | Benign |
| Agent (Claude Code, Codex, a cron job, an Aperture gateway) | Calls tools; may have a shell as the owner's user | Benign, but steerable by injected text |
| Tailnet data | Text fields the API returns: user display names, ACL comments, key descriptions, OAuth-app names, service comments, posture attribute values, audit-log `actionDetails`, error messages, client `Health[]` strings, webhook URLs | Attacker-influenced content that reaches the agent |
| Other managers | GitOps pipelines, Terraform, Pulumi, the Kubernetes operator, SCIM, JIT tools (ConductorOne, Opal) | Benign, but write the same objects |
| CI runner | OIDC identity and network access to the API. The read identity is a read-all-policy credential, because masking is client-side: it reads the policy, the devices and their posture attributes. The GitHub Actions recipe runs the job that holds it in a named environment, with `id-token: write` on that job only. Every step of that job, including the pinned `actions/checkout` and `sigstore/cosign-installer` and the downloaded binary, can request the OIDC token; the SHA pins and the environment's reviewer are the controls. With a required reviewer on the environment and the federated credential's subject bound to that environment, only an approved run gets the identity; without the binding, a job that names no environment gets a token with no approval, and without a reviewer, anyone who can push a branch can edit a `pull_request` workflow and use that identity. Under `pull_request` the workflow that runs is the pull request's own, so add the workflow file to CODEOWNERS beside the policy and invariants files and require code-owner review on the default branch. A pull request from a fork gets no OIDC token. On a public repository the log of a run on a branch of the repository is public, and it carries text taken from the live policy (annotations and a step summary), masked for personal data but not for tag names, host names or the shape of a rule | Benign; runs code from the repository |
| Thief of a plan file, audit log or CI artifact | Reads files | Malicious; plans contain policy text with personal data |
| Thief of the supply chain | Replaces the binary or a dependency | Malicious |

## Trust boundaries

1. **Resident read, per-plan write.** The long-running process holds only the read credential. Write credentials enter a child process that executes one approved plan with a token scoped to that plan's operations (where the provider supports scoping, §7.4), then exits.
2. **Approval.** Every write passes the approver chain (§8). Policy deny rules run first and stop everything, including signed plans. The first approver that applies decides; the default when nothing approves is deny. The executor re-checks the gate immediately before writing.
3. **Precondition.** The ACL write is conditional server-side (`If-Match`). Every other write re-reads the fields it changes and aborts on drift.
4. **Gate configuration.** Configuration, policy, signer lists and the kill switch are read only from directories that the requesting process cannot modify:
   - In hardened mode, from root-owned files that only `tailkeeperd` reads.
   - In personal mode, from the user's own directory. That protects against misuse through tool calls, not against code running as the user (see "What the gate does not stop", below).

   No flag or environment variable changes a gate setting.
5. **Secret boundary.** Secret inputs travel as references resolved inside the child; secret outputs go to the sink. Neither appears in plans, dialogs, MCP results or the audit log.
6. **Write-ahead audit.** The intent to write is recorded before the child starts. If it cannot be recorded, nothing is written.
7. **Privilege separation (hardened mode).** `tailkeeperd` runs as the `_tailkeeper` system user and owns the write, mint and user credentials, the gate configuration, the audit log and its HMAC key. User processes reach it only through a Unix socket whose peer credentials identify the requesting OS user. It builds and evaluates every plan itself; nothing a client sends is trusted beyond the request.

## What the gate stops

- An agent steered by tailnet text into calling a write tool: the approver sees the exact change and declines.
- A retried or replayed call: plans are idempotent per caller and single-use.
- A stale decision: the precondition check aborts a write whose target changed after approval.
- A runaway automation: per-tier rate buckets, a kill switch, plan expiry and step caps bound it.
- A gateway or client in a permissive mode (Aperture's YOLO launch, an allow-all agent configuration): the gate is server-side; client prompts and MCP annotations are advisory.
- A leaked plan or audit file yielding a credential: neither contains one.
- A replaced release artifact: checksums, cosign signatures and provenance attestations expose it.

## What the gate does not stop

**In personal mode:**
- **Same-user code with a shell.** It can edit the gate configuration and the signer list, delete the kill switch, and reach a write credential through the provider that releases it. Then it can run the whole ceremony itself or call the API directly.
  - Mitigations: run the agent's shell in a sandbox that cannot write tailkeeper's directories or read the secret store (§21 ships the Claude Code sandbox settings); keep credential classes separate (§7); use agent-host deny rules and a hook (§21).
  - Detection: `audit_reconcile` compares Tailscale's audit log against tailkeeper's plans (§14). How Tailscale attributes OAuth-client actions is a live acceptance item.
  - Hardened mode removes this exposure.
- **Same-user code that drives an interactive approver.** A desktop-automation agent can click a dialog; any process can allocate a pseudo-terminal or answer an MCP elicitation through a permissive host. Plans that grant access, weaken a control or cannot be undone should require a hardware-key signature with a touch (§8.3).

**In hardened mode:**
- Root on the machine, or anyone who can act as `_tailkeeper`.
- An approver whose authenticator is compromised (a stolen hardware key, a compromised pager account).
- Sessions approved through `session`-level approvers. In hardened mode these count only as `host` assurance, because the user's own processes can drive them; by default they approve only reversible, narrowing changes (§8.3).

**In both modes:**
- **Authority that never passes through the API.** Tag owners applying tags at `tailscale up`, `autoApprovers` approving routes, nodes minting their own auth keys with an OAuth secret, admins editing in the console ("Edit anyway" bypasses the GitOps lock). tailkeeper audits the policy that grants these powers and detects console edits after the fact.
- **Races outside the ACL.** Only the policy file has a server-side precondition. Every other setter replaces state, so a concurrent change between the child's re-read and its write can be overwritten. Detection, not prevention.
- A compromised Tailscale account, identity provider or OAuth client created outside tailkeeper.

## Subjects an agent types

While masking is on, a user's login enters a call only as a pseudonym or as a masked value that carries one. A literal login is `filter_refused`; the hint names the pseudonym route, or, without a privacy key, says that pseudonyms need one. A pseudonym resolves to exactly one user; zero matches or several is `validation_failed`. This covers `acl_test`'s source and destinations, including an SSH test's source and destinations. An SSH user is an operating-system account, not a Tailscale login, and is not refused as one. It also covers every string of a policy proposal or a patch given over MCP, keys and values, comments excepted, a text given to `acl_diff` over MCP, and a login typed as an argument of `acl test`.

A file the operator names on the command line (`--from`, `--against`, `--patch`, `--invariants`), standard input given with `-`, and the configured invariants file are the operator's own documents. Their logins are accepted, sent to Tailscale, and shown masked without pseudonyms. `"personalData": "show"` for that context is the escape. An agent with a shell that writes one of those files is outside this boundary: personal mode stops a tool call, not code that runs as the user. The channel this closes is guess-confirmation of a tailnet user. The channel it leaves is that shell.

A proposal, a test, an SSH test and, under `doctor --probe`, the live policy with a canary appended and two synthetic documents are sent to Tailscale for validation and change nothing there. `acl_diff` sends nothing. Apart from the credential's token request, the only request other than GET is `POST .../acl/validate`. `acl_test` also reads the live policy (`GET .../acl`) and, when a pseudonym is given, the users (`GET .../users`, the optional scope `users:read`, held for that one call). `srcPostureAttrs` pass through on the tests-mode request and are refused together with SSH tests. The result's posture is `none`, `gated` or `unknown`. `unknown` means the live policy could not be read, which is not a claim that no rule is posture-gated, and it is not a pass of that question.

SSH tests go out as a copy of the live policy: its own tests and SSH tests removed, the caller's SSH tests appended, and two canaries appended, one for tests mode and one in the SSH form. Each must come back once. The tests-mode canary is one failed assertion for its destination, in the direction the access state fixes: with an absent access section (allow-all) the canary is a denial that fails, with an empty one (deny-all) an acceptance that fails, and with a non-empty one either line is the canary. The SSH canary is one SSH-form failure for its user and destination. A missing canary, a second copy, or one in another shape is `unknown`, never a pass. A `check` user with no line is `unknown`, never a pass.

A login a pseudonym stood for is masked on the way out, whole and without a pseudonym beside the echo, and so is each word of its local part where the word stands alone. Two logins of different lengths that mask to one form produce the same result. Three things are not masked. A word shorter than two bytes is not. A word the caller typed is not masked as a local part: it is shown as typed, because a text that masked it only when it was a word of a login would answer each guess. A local part of a login this call did not resolve is not found, because masking reads whole logins. Every echo of text the caller typed (an SSH user, a destination, a protocol) is masked without a pseudonym, because a pseudonym beside a guess would confirm it.
