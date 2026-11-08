# Independent beta facilitator protocol

Status: **preparation only**. Recruitment, sessions and results have not been
collected. This guide does not complete Task 14 or establish release readiness.
The owner must approve actual outreach separately. Use the [known limits](known-limits.md)
and [synthetic examples](beta-examples.md) alongside this guide.

## Before inviting anyone

1. The owner approves an invitation and confirms an actual private feedback
   channel, who may access private notes, a concrete retention/deletion date,
   and an operational route for withdrawal. Record these privately and tell
   each participant before consent. This document creates no private service;
   public GitHub issues are never a private feedback channel.
2. Aim for five independent consenting participants, including homelab and
   small-team contexts, and more than one OS/installation variant. Record the
   actual mix and gaps. Staff, author and agent runs and the prior single VM
   acceptance are not independent participants.
3. Select an artifact and review its version, hash and verification using the
   existing [installation instructions](../../README.md#install). Record the
   exact artifact, version, hash, host, OS, architecture and install variant
   in the private study record, without host identifiers. Distinguish CLI from
   MCP. Fixture success does not establish a supported production artifact.
4. Prepare the synthetic exercise and private workspace. The existing examples
   require a developer-assisted Go test, not an interactive production fixture
   CLI. Review [pack commands](evidence-packs.md) and their requirements. Windows
   pack commands are unsupported: record an attempted/blocked exercise rather
   than seeking a bypass. Do not demand a live API to fill unsupported or
   runtime-unknown evidence.

## Owner-review copy — UNSENT

Fill in the private feedback channel, who can access notes, the concrete
retention/deletion date and the withdrawal route before sending. The owner must
approve the invitation and outreach separately; this is a draft, not a sent
invitation or a consent record.

> Would you consider taking part in an independent tailkeeper beta exercise?
> Participation is voluntary. You may skip any task, stop or withdraw. The
> default is synthetic orientation, with no recording or raw operational data
> collected. The full product exercise is blocked in synthetic-only mode today;
> an authorized lab is optional, never required.
> Private feedback channel: [fill in]. Note access: [fill in]. Retention/deletion
> date: [fill in]. Withdrawal route: [fill in]. We will ask separately before
> sharing any information, publishing an aggregate, or using a quote or case study.

Before observation, the facilitator can ask:

> Having received the channel, note-access, retention/deletion and withdrawal
> details, do you voluntarily agree to participate under these privacy defaults?
> You may skip, stop or withdraw. Participation does not grant permission to
> share or publish; we will ask separately for each optional permission. Synthetic
> orientation is separate from a full product exercise, and a lab is optional.

Record the answer privately only, as described below; do not infer consent from
an invitation or silence.

## Consent and privacy

Before observation, explain the tasks, privacy defaults, private channel,
access, retention date and withdrawal route. Obtain explicit, voluntary
participation consent; a participant may skip, stop or withdraw. Separately ask
for permission for any optional sharing, aggregate publication, and individual
public quotation or case study. A public quotation or case study requires its
own explicit permission and redaction review. Aggregate publication also
requires explicit consent and redaction review. A refusal does not prevent
participation. Record consent choices privately; do not put consent records or
participant codes in a public issue.

Default to no recordings, screenshots, remote control, or collection of raw
output, tailnet data, configuration, policy, packs, logs or credentials. The
participant retains real inputs and outputs in their authorized environment.
For observation notes record only a participant-selected random study code,
coarse setup, requested task outcome, assistance category, elapsed time if
observed, their explanation of unknown coverage, and failure classification.
Keep study records, consent choices, observation notes and identity/contact
mappings outside this repository and its Git history. Do not require names,
organization details or contact information in the repository or public
feedback form.

Default to synthetic inputs. If someone elects to use their own authorized
environment, they separately approve each API read or validation; configuration,
credentials and raw data remain with them. Never use a maintainer's tailnet for
participants, request access widening, disable guards, run exploits, or collect
full process environments. Tailkeeper does not remediate: any correction or
configuration change is a separate participant/owner action.

## Synthetic-only orientation

A participant must personally run all three existing Go demos and explain each
result and its relevant limit to complete synthetic orientation. Record any
assistance. Record partial completion, skipped demos and facilitator-only runs
separately; none of those counts as a full orientation completion. Record
initial orientation attempts, completions, understanding and assistance separately,
with denominators. In a separate later session they may run and explain them
again; record orientation returns, repeat attempts and completions separately.
The hardcoded internal version change and rerunning the command are not a
participant-configured product change or independent product repeat use. See
[examples](beta-examples.md).

These three demos use Unix-only tests and cannot run on Windows. Record a
Windows orientation attempt as attempted/blocked, not completed, skipped or
omitted.

The full installed-product pack, replay, correction and configuration-change
repeat remain **blocked** for a synthetic-only participant with current tooling.
They need a separately approved safe fixture interface or their separately chosen
authorized lab workflow. Do not pressure anyone to use real data or make
production changes. Record the blocked full exercise; do not count orientation
toward the five-person initial and repeat full-completion target. The Task 14
field requirements remain open.

## Initial exercise — select a route before starting

Choose either the full product route below or synthetic-only orientation before
beginning. Synthetic-only participants use the separate orientation above; it
does not substitute for any phase of the full product route. The full product
route remains blocked for synthetic-only participants with current tooling.

### Full product route

Reconfirm consent and context. Observe the participant, recording assistance and
elapsed time where observed. Ask them to:

1. Install the verified artifact on the chosen host and state one access
   expectation *before* seeing the result. Record artifact and setup as above.
2. Assess one reviewed advisory, explain the evidence for its applicability and
   what remains unknown. Explain that pending rules and unavailable facts are
   not clean findings.
3. Evaluate the stated expectation with CLI `security explain` where available;
   explain its verdict and why a candidate rule is not established causation.
4. Export and replay a private before-pack and verify an independently performed
   correction with fresh evidence, following [evidence packs](evidence-packs.md).
   The participant retains the files.
5. In their own words explain why the finding applies, what is unknown and what
   verification actually established. Record outcome and assistance without
   collecting their raw explanation if it contains operational data.

A source, credential, audit or coverage failure is visible, not a healthy empty
report. Treat a suspected false finding as unconfirmed/disputed until privately
reproduced and reviewed; unknown alone is not a false positive. Stop the affected
exercise on credential or personal-data exposure, an unexpected write, an
unexplained audit/integrity failure, or an unsafe request. Preserve only safe
metadata, use the agreed private route, and follow [SECURITY.md](../../SECURITY.md)
for vulnerability reports; never post unreported vulnerability details publicly.
Fix material usability failures and repeat affected exercises before counting
them complete. Record unsupported variants as attempted/blocked, not omitted.

## Separate repeat exercise — full product route

After the first exercise, the participant/owner independently makes a reversible,
owner-approved configuration change. Do not make it for them. In a separate
session reconfirm consent, authorization, setup and context; record return and
repeat attempt. Capture, export and replay a fresh baseline with an eligible unmet
target. The participant/owner then independently performs the approved reversible
correction and records its actual time strictly after every baseline observation
and evaluation. Collect fresh post-action evidence, then repeat the explanation
and verify the correction. Record assistance and observed elapsed time.

If the change between sessions was only a context change, name it separately and
require a distinct subsequent correction action after the baseline. Never reuse a
pre-baseline action as the correction or invent its time. No real-host downgrade
or access widening is needed. A repeated command in one maintainer demo is not
participant repeat use after a separate change. Apply the same stop and failure
rules.

## Outcome rubric and counts

For each phase mark completed, blocked, skipped, withdrawn or failed; distinguish
synthetic-only from an authorized environment and CLI from MCP. Independent
full completion requires the participant to actually execute every
required product phase and demonstrate understanding, including correction
verification, with material failures fixed and affected exercises repeated. A
required blocked or skipped phase cannot become not applicable to count as full
completion. Hints and guided coaching may be recorded, but the participant must
perform the critical steps. If the facilitator performs any required phase,
classify it as an assisted demonstration and exclude it from the independent
full-completion numerator. Preserve the attempt and its assistance. Correctly
interpreted partial or unknown outcomes are distinct from failures.
Record assistance as none, hint, guided steps or facilitator performed; retain
which phase needed it. Record explanation as accurate, partial, incorrect or not
observed, including whether the participant identified the evidence and unknowns.
Record suspected false findings as disputed until reviewed, then the disposition;
record other failures by phase and category. Do not infer a security verdict.

Count distinct people once per cohort and stage, and specify denominators:
invited (distinct invitees), consented / invited, attempted initial / consented,
independent full completed initial / attempted, returned / independent full
completed initial, repeat-attempted / returned, independent full repeat-completed
/ repeat-attempted. Also report declined / invited,
withdrawn / consented, and blocked / attempted for each exercise; these can
intersect other stages, so do not add them as mutually exclusive totals. Record
assistance by phase and denominator, incomplete cases, platform mix and missing
data. Count someone once per stage even if they retry; document retries and
fixes separately. Never infer users from downloads or stars.

Results template (blank means **not collected**, not zero):

| Measure | Count | Denominator / notes |
|---|---|---|
| Invited; declined | — | Distinct invitees; declined / invited |
| Consented; withdrawn | — | Consented / invited; withdrawn / consented |
| Initial attempted; independent full completed; blocked | — | Attempted / consented; full completed and blocked / attempted |
| Returned; repeat attempted; independent full repeat completed; blocked | — | Returned / initial full completed; attempted / returned; full completed and blocked / repeat attempted |
| Synthetic orientation initial and repeat attempts; completions; returns | — | Initial attempts / consented; initial completions / initial attempts; returns / initial completions; repeat attempts / returns; repeat completions / repeat attempts |
| Assisted demonstrations by phase | — | Distinct participants / phase attempts; excluded from independent full completion |
| Understanding and assistance by phase | — | Categories and number observed / phase attempts |
| Disputed and reviewed findings; failures and fixes | — | Status, phase, retries and denominator |
| Cohort, variants, omissions and dates | — | Coarse context and collection period |

Scheduled notifications and duplicate/irrelevant alert metrics are **not
evaluated**, not zero. Include them only if Tasks 8–10 actually ship, with a
separately consented optional exercise.

## Publication gate

After fixing material failures and repeating affected exercises, report measured
counts with denominators, missing data, assistance, understanding, repeat use,
unsupported cases and limitations. Obtain the specified aggregate consent and
redaction review before publication; individual quotes and case studies need
separate explicit consent and redaction review. Update coverage documentation
with observed evidence, not invented results. M2 evidence is counts,
understanding and repeat use; usability success does not close security
assurance gaps or by itself establish release readiness.
