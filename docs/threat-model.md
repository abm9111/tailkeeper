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
| CI runner | OIDC identity, network access to the API | Benign; runs code from the repository |
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
