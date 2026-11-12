# Access explanations

`tailkeeper security explain` is the owner's question about their own intent: for each expectation they wrote in an invariants file, was the live policy witnessed to do what it says, which rules are candidates for the answer, and what could a compromised source reach. It exists on the command line only. No MCP tool, argument, resource or prompt reaches it, the generated tool reference does not list it, and `toolListBudget` is the number it was.

```
tailkeeper security explain [--invariants FILE] [--only ID[,ID…]] [--format text|json|markdown|github] [--json] [--quiet] [--context NAME]
```

## What it answers

Three things, and each is kept apart from the others.

1. **Selected access: a verdict for each pair.** An expectation is a test of the invariants file (a `tests` entry: a source, destinations it must or must not reach; an `sshTests` entry: a source, destinations, SSH users in `accept`, `check` or `deny`). Each destination, or each destination and user, is a pair. A pair is `met` when the live policy was witnessed to do what the expectation says, `unmet` when it was witnessed to do the other thing, and `unknown` or `not_evaluated` when it was not witnessed. An expectation is `met`, `unmet`, `unknown`, `met_with_limits` or `not_evaluated`, by the rules below.
2. **Candidate rules: where to look.** For each expectation, the rules of `acls`, `grants` and `ssh` of the live policy whose selectors match its source and a destination as text, each as a place in the policy (`line:column`) with the selectors that matched. A candidate is labelled as one. It is not the rule that grants or denies, and it never changes a verdict.
3. **A blast radius: an assumption.** For each source, under the heading `if <source> were compromised, the live policy would let it reach:`, the pairs the witnesses show the policy allows, the candidate rules whose destination is `*`, and the tags the source can apply. It is an assumption about a compromised source, not a finding. The line `policy grants this source all destinations` is said only for a plain network rule that allows every destination on every port and every protocol: an `acls` rule with the destination `*:*` and no `proto`, or a grant with the destination `*` and the `ip` entry `*` (both written as the wildcard: `1-65535` is a limit), with no `srcPosture`, `app` capabilities or `via`, in a policy with no `defaultSrcPosture` (which gates every rule that has no `srcPosture` of its own). A plain rule for `*` that limits the ports or the protocol (`*:22`, a `proto`, `ip: ["tcp:22"]`) is still a candidate, and the blast radius says what it writes instead: `policy grants this source every destination on ports 22`, `... on proto tcp, ports *`, `... on tcp:22, udp:53` (an `acls` rule's `proto` and ports, or a grant's `ip` entries, as the rule writes them, shown as tailnet text like any other). A rule that writes nothing to quote (a grant with no `ip` entries) is a candidate and gets no line. A rule with `srcPosture`, `app` capabilities or `via`, or a rule in a policy that has `defaultSrcPosture`, is still a candidate (marked as qualified) and its limit says what the qualifier means, but it is not said to grant every destination. An `ssh` rule is never said to grant every destination, and is marked as qualified when `srcPosture` or `defaultSrcPosture` gates it (an `ssh` rule has neither `app` capabilities nor `via`).

## What it never claims

- That a service listens on a destination, that a credential works, or that an exploit would succeed. Policy reachability is what the policy allows a connection to do, nothing more.
- A verdict from a rule. Every `met` and `unmet` is Tailscale's own validation of the live policy (below). Reading rules cannot make a pair `met`.
- That SSH access is network reachability of port 22, or the reverse. The two are separate questions and the report keeps them apart, and says so once.
- That a user who owns a tag holds the rules of that tag. Ownership is not access: a rule whose source is a tag the user owns is not a candidate for the user. The blast radius says instead, as an assumption, `can apply tag:X (tagOwners), whose rules would then apply`.
- Anything about device posture, app capabilities, `via`, or a source Tailscale's test language cannot name. Those are stated as limits, below, and an expectation that meets one is never `met`. The limits do not depend on the candidate lists: a rule of `acls` or `grants` with `srcPosture`, `app` capabilities or `via`, and the policy's `defaultSrcPosture`, count for a network expectation unless the rule is shown to be about other destinations, whether or not tailkeeper could match its selectors to the expectation. For an SSH expectation the same holds of an `ssh` rule with `srcPosture` and of `defaultSrcPosture` (an `ssh` rule can be gated on posture as a rule of `acls` is, and the witness is a device that reports none), unless the rule is shown to be about other users or other destinations; an `ssh` rule says nothing of a network expectation, nor a rule of `acls` or `grants` of an SSH one. A policy with rules that were not listed (past 4,096) or could not be read (for an SSH expectation, an `ssh` rule that could not be read) counts too, and so does a search of the rules that reached its budget or was cut short: what it did not search it did not rule out.
- Anything about the tailnet's devices or users. Nothing is enumerated: the only names asked about are the ones the expectations list. So a `deny` expectation for a login that is mistyped is `met`: Tailscale matches no device for it, and the policy allows nothing from a source that is no one. Checking that a name exists would need a list of users, which this command does not make.

## How a verdict is made

The witness is one validation of the live policy at Tailscale (`POST .../acl/validate`, which changes nothing), the one `acl validate` makes for its invariants and `acl test` makes for its SSH tests.

1. The live policy is read once. Tailkeeper makes a copy of its text with the policy's own `tests` and `sshTests` taken out, and puts the selected expectations in as tests, and beside them a canary: a test that fails whatever the policy allows. SSH tests also get an SSH canary.
2. A test that passes shows nothing in the reply. So the reply is read only if the canary came back once, in the grammar the reply has (`want`/`got`), the SSH canary's line names the canary's own tag as its source (a failure of an expectation's source filed under the canary's tag is that source's and not the canary: it proves nothing, and the SSH pairs are `unknown` with the reason `canary`), and the live policy was read again afterwards and was the same. Without the canary there is no verdict at all, `met` or `unmet`. If the policy moved, or could not be read again, every pair is `unknown`, a failure included: what was witnessed is no longer a claim about the live policy, so it is neither `met` nor `unmet`, and it is not offered as something a source could reach.
3. A pair that names the coordinates of tailkeeper's own canary is not asked at all: the address `192.0.2.1` on a port that holds port 1 (written as the address or as a host alias that is exactly it) for a network pair, the user `canary` on `192.0.2.1` for an SSH pair. A reply that proves the canary and holds nothing for the expectation's source reads, there, as the canary's own line does, so silence would be a verdict; the pair is `unknown` with the reason `canary_coordinates`, whatever the reply says, and `acl test` does the same for an SSH test of that user on that address, on an alias for it in the live policy's `hosts` section, and, if that policy could not be read, on any destination that is not a literal address (it may be an alias). Any other port, user or address is judged as usual.
4. A line is read by the grammar `acl test` reads. A line that cannot be paired with one pair, a name Tailscale cannot evaluate, or a reply with a line for a source nobody asked about leaves the pairs it touches `unknown`. A line in the SSH form also names the source it is about: when that is not the source of the entry of the reply it was found in, the line is evidence about one source set under another, and the pairs of both sources are `unknown` (`unpaired_line`).

**It is bounded.** At most two validation requests: one for the network tests and one for the SSH tests (a run with only one kind makes one). That is two POSTs on the wire: the requests are sent once, with no retry (a retry is a POST, and takes no token), so a request that fails, a 500 included, leaves its pairs `unknown` (`request_failed`) and is not sent again. They take their tokens from the same bucket as every validation (`acl.validatePerMinute`), reserved together; a limit, a cancelled call or a failed request leaves the pairs `unknown`, with the reason, and is not an error. Each request has its own audit records (below), and one whose attempt cannot be recorded is not sent. At most 64 pairs are judged in a run, the number of tests one validation call may carry; the pairs past it are `not_evaluated`, counted, and the report is incomplete. A list of thousands of destinations and thousands of users is counted and not expanded: only the first 64 pairs are made, the rest are counted by arithmetic, and the memory the plan takes is that of the lists, not of their product. The search for candidate rules and for the tags a source can apply spends a budget of steps (a rule's sources looked at, a selector compared, a member of a group visited, a destination or a user walked, each part of the ports a rule's destinations and `ip` entries list, read once for the rule and paid for by its parts, each port entry of a grant checked, the text a candidate quotes of the ports and protocols it allows built only for the destination that is quoted and not for every destination that matches, each tag of the policy looked at, one with no owners too, and each owner of it, each selector of a source list or a user list looked through), so that a group that lists a large group many times, or rules with thousands of destinations against an expectation with thousands, cannot make it quadratic in the policy; when the budget is reached, or the call is cancelled, the search stops at once, in the walks of the limits and of the tags a source owns too, the candidate lists are short, the report says so, a network expectation it cut short has the `rules` limit, and no verdict is made or taken away (a rule not searched counts as not shown to be about other destinations, so a limit is raised, never lowered). Only an expectation's own source and its own destinations and users are ever put to Tailscale: a group or a tag is never widened to its members, and no device or user is listed to find one. Two expectations of one source with the same terms (`proto`, `srcPostureAttrs`) share a test; an expectation of that source with other terms is `not_evaluated` with the reason `same_source`, because one request holds one test for a source. The SSH tests follow the same rule, because Tailscale is known to fail two tests that share a `src` (design 12.2) and no probe shows that `sshTests` are spared: a source has one `sshTests` entry in the request. The users it accepts, checks and denies on the same destinations are one entry (as the owner would have written them); pairs that one entry could hold only by also asking about pairs nobody listed (`root` on one destination and `deploy` on another) are not asked, and are `not_evaluated` with the reason `same_source`.

## Statuses and exit codes

| Status | Meaning |
|---|---|
| `met` | Every pair was witnessed to be as the expectation says, with a canary, and the live policy was shown unchanged. |
| `unmet` | A pair was witnessed the other way: an accepted pair dropped, or a denied pair accepted. |
| `unknown` | A pair could not be witnessed. Never met. A `check` user is always `unknown`: the form a check failure takes has not been observed. |
| `met_with_limits` | Every pair was `met`, and a case the test language cannot express is stated (below). It counts as incomplete. |
| `not_evaluated` | A pair was left out: past the cap, or for the reason `same_source`. |

The report is `complete` only when every selected expectation is `met`; otherwise `incomplete`, an `unmet` one included. The exit code follows the counts and nothing else:

| Exit | When |
|---|---|
| 0 | Every selected expectation is `met`, with a canary. |
| 8 | Any expectation is `unmet` (`findings_present`). 8 outranks 1, as it does for `security scan`. |
| 1 | Otherwise, when anything is `unknown`, `met_with_limits` or `not_evaluated`, or there is no intent set (`no intent set: nothing explained`). |
| 2 | A usage error: `--only` names an ID the set does not hold, `--json` with another `--format`. |
| 5, 6, 7 | A credential that does not work, a configuration or intent file that cannot be used, an audit log that cannot be written, as for every command. With no intent set no credential is needed: nothing is asked of Tailscale, and the command does not start the exec provider's wrapper for it. |

An intent set with no expectation is also exit 1, with its own sentence (`the intent set holds no expectations: nothing explained`). With no intent set nothing is asked of Tailscale.

## The intent

`security explain` takes the intent as `security scan` does: the file `--invariants FILE` names, else the file `acl.invariantsFile` names (read by the same reader, with the same refusals: a path that is set and cannot be read, decoded or adapted is `config_invalid`, exit 6, never no intent). There is no `--no-invariants`: with nothing to explain there is nothing to switch off. The IDs are `network-N` for the Nth entry of `tests` and `ssh-N` for the Nth of `sshTests`, as the scan counts them; `--only network-1,ssh-2` explains those (repeatable, in the file's order). An ID the set does not hold is a usage error, and the message lists the IDs it holds without repeating what was typed.

## Candidate rules

A rule is a candidate for an expectation when its source covers the expectation's source and one of its destinations covers one of the expectation's destinations on its port (an SSH rule: its users include one of the expectation's). "Covers" is a text match, and stops short of guessing:

- the same name (logins without regard to case), `*`, a group that lists the name (directly, or through one group it lists), a host alias or an address range that contains it, and `autogroup:tagged` for a tag;
- a port is compared with the rule's port list (a grant's `ip` entries; a grant with none, an app grant, may name any port); the protocol is not compared;
- `autogroup:member` for a login, `localpart:*@domain` for an SSH user and similar are not resolved, so a candidate list may be short. The report says so beside the first candidate list, in one fixed sentence: `A list of candidate rules may be incomplete: the protocol of a rule is ignored, and autogroup:member and localpart: selectors are not resolved.` When the policy has more rules than are read (4,096), a rule it cannot read, or could not be read at all, or the search reached its budget, it also says the candidate lists may be short because of that. A verdict, and a limit, never depends on a candidate list.

At most 8 candidates are listed for an expectation, with a count of the rest; a broad rule (destination `*`) is kept ahead of the others so that the cut never drops the rule the blast radius names.

## Limits: what the test language cannot express

Each limit is a fixed sentence, stated for the expectation, and the expectation is at best `met_with_limits` (exit 1):

| Limit | When | Sentence |
|---|---|---|
| `posture` | A rule of `acls` or `grants` (for an SSH expectation, of `ssh`) has `srcPosture`, or the policy has `defaultSrcPosture`, and the expectation gives no `srcPostureAttrs` (an SSH expectation never does) | A rule of the live policy that is not shown to name only other destinations (for an SSH expectation, nor to be about only other users), or the policy's defaultSrcPosture, depends on device posture, and this expectation gives no posture attributes: the answer holds for a device that reports none, and tailkeeper does not guess a device's posture. |
| `app` | A grant carries `app` capabilities | A grant of the live policy that is not shown to name only other destinations carries app capabilities, which Tailscale's test language cannot express: the answer says nothing about them. |
| `via` | A grant routes through `via` | A grant of the live policy that is not shown to name only other destinations routes through via, which Tailscale's test language cannot express: the answer says nothing about it. |
| `source` | The source is an autogroup (for SSH, the source or a destination) | The source is one Tailscale's test language cannot express (an autogroup), so a verdict for it is not established. |
| `rules` | A rule of `acls` or `grants` (for an SSH expectation, of `ssh`) could not be read (a rule that is no object, or has a `src`, `dst`, `users`, `ip` or `proto` that is not what it should be, or a section that is neither a list nor null), the policy has more rules than are listed (4,096), the policy could not be read here, or the search of the rules was cut short (its budget, a cancelled call) | Some rules of the live policy could not be listed or read here, or the search of them was cut short, so a rule that depends on device posture, carries app capabilities or routes through via cannot be ruled out: the answer holds for what the test language can express. |

A rule is shown to be about other destinations only when every destination of the rule differs from every destination of the expectation, or the rule's ports leave out the expectation's port. A destination differs only when both are fully resolved addresses of one family (an address, a range, or a host alias for one) that do not overlap: a tag, a group or an autogroup may include anything, a device may carry several tags, and a device has an address of each family, so none of those is shown to differ. A rule with `app` capabilities is not made other by its ports, which are the `ip` entries' and not the app's. The `rules` limit applies to both kinds, to a network expectation through the rules of `acls` and `grants` and to an SSH expectation through the rules of `ssh`: an `ssh` rule carries no `app` capability or `via`, but it can carry `srcPosture`, so the `app` and `via` limits are for network expectations only. An `ssh` rule is shown to be about other users when the rule lists only plain names and `autogroup:nonroot` and none covers a user of the expectation (a `localpart:` or another autogroup is never shown to differ), and about other destinations by the same fully resolved addresses as above; a tag or a group is never shown to differ.

A `defaultSrcPosture` that is not a list (a string, a number, an object) is read as a posture that is set, as an `srcPosture` that is not a list is: it is not an absent one.

An expectation that gives `srcPostureAttrs` has them sent in its test, and Tailscale evaluates it as a device that reports them: the posture limit does not apply to it (`app`, `via` and `rules` still do).

## Reasons a pair is unknown or not evaluated

The `reason` of a pair is a word of a closed set, each with a fixed sentence in the text layout:

| Reason | Sentence |
|---|---|
| `canary` | Tailscale's answer did not show the canary once, in its grammar, so nothing in it is a verdict |
| `live_changed` | the live policy changed, or could not be shown unchanged, while it was checked |
| `unparseable_line` | a line of Tailscale's answer is not in the grammar this version reads |
| `unresolved` | Tailscale could not evaluate a name or a destination of this test |
| `unpaired_line` | a line of Tailscale's answer matches no single pair of this call |
| `lines_disagree` | the lines of Tailscale's answer for this pair do not agree |
| `rate_limited` | tailkeeper's own limit on validation requests was used up |
| `request_failed` | the validation request did not complete |
| `refused` | Tailscale refused the text built from the live policy |
| `live_policy_errors` | Tailscale stored errors with the live policy, so it would not be accepted as it is |
| `live_policy_unreadable` | this version of tailkeeper cannot read the live policy |
| `same_source` | another selected expectation with this source has other terms, and one request holds one test for a source |
| `check_user` | a check user with no line is not a pass: the form a check failure takes was not observed |
| `past_cap` | past the number of pairs one run judges |
| `audit_unrecorded` | the audit log could not record the validation request that would answer this pair, so no verdict is made from it |
| `canary_coordinates` | it names the destination, or the SSH user and destination, of tailkeeper's own canary test, so no reply can show it apart from the canary |
| `no_witness` | no validation was made for this pair |

## Privacy

It is an owner command, so it shows what was asked about: an expectation's source, destinations and users. Every one of those is a tailnet string, so it goes through the same masking as `acl_test`: a login is masked (`a…@example.com`) and, with a privacy key, carries its pseudonym; the strings are escaped, capped and checked for a credential shape; and the text, Markdown and GitHub layouts print them behind the notice that they are untrusted, Markdown in a code span. The policy's own text is never shown: a rule appears as a place and the selectors that matched, never as a dump, and comments, group members and other rules are nowhere. The intent file is named by the digest rule of the other digests (a keyed digest while personal data is masked and a key is loaded, the plain SHA-256 with `personalData: show`, none otherwise) and its path is in no output.

The `read` line of the audit log for the command carries the tool, the requester, the identifier of the call and, for this command, `intent` (`none`, `configured` or `cli`), `digest` (the first twelve digits of the digest by that rule, absent when there is none), `expectations` and the counts `met`, `unmet`, `unknown`, `limited` and `not_evaluated`. No text of the intent, no text of the policy, no path. Each validation request also has two `collect` lines of its own, through the audit method the security scan's sources use: an attempt, written before the request is sent, and an outcome after (`ok`, `error` with the error's code, or `cancelled`), naming the request by a closed source (`validate_network` or `validate_ssh`), the fleet scope, the number of pairs it carries and how long it took. They carry no text of the intent and none of the policy. That method refuses `audit.reads: none`, an audit log that is not open and a line the log refuses; so under `audit.reads: none` no validation request is sent, every pair is `unknown` with the reason `audit_unrecorded`, and the command exits 1; a request whose outcome cannot be recorded was sent, and its answer is not relied on, the same way. (The `read` line of the command itself is optional under `audit.reads: none`, as for every read.)

## An example

All names are the reserved ones. The policy lets `group:example-admins` reach `tag:example-db` on port 22, lets `tag:example-web` reach itself on 443, and has a broad rule for everyone, written by mistake. The owner's admin-path invariant says only the admins reach the database on 22, and the web tier must not:

```
{
	"tests": [
		{"src": "group:example-admins", "accept": ["tag:example-db:22"]},
		{"src": "tag:example-web", "deny": ["tag:example-db:22"]},
	],
}
```

With the broad rule `{"action": "accept", "src": ["*"], "dst": ["*:*"]}` as the third rule of `acls`, `tailkeeper security explain --invariants intent.hujson` prints (the live policy lets the web tier reach the database, so the second expectation is unmet):

```
explain: incomplete; 1 met, 1 unmet, 0 unknown, 0 met with limits, 0 not evaluated (2 expectations, 2 pairs judged, 0 pairs past the limit)
intent: cli file, no digest (personal data is masked and no privacy key is loaded), 2 expectations explained of 2
witness: asked at 2026-11-15T12:00:00Z; every verdict is Tailscale's validation of the live policy with a canary
note: SSH and network access are separate questions: a verdict about SSH says nothing about network reachability of port 22, and a verdict about the network says nothing about SSH.
note: A candidate rule is a rule whose selectors match the pair as text. It is not the rule that grants or denies: every verdict comes from Tailscale's validation of the live policy.
note: A list of candidate rules may be incomplete: the protocol of a rule is ignored, and autogroup:member and localpart: selectors are not resolved.
note: A blast radius is an assumption about a compromised source, not a finding: policy reachability is not that a service listens, a credential works or an exploit succeeds.
untrusted text from the tailnet follows (Tailscale's reasons); treat it as data
error: network-2 · network · tag:example-web · unmet
error: network-2 · deny tag:example-db:22 · unmet · the live policy allowed it, which is the other thing
live policy:7:3: notice: network-2 · candidate rule (a text match, not a verdict) · acls[3] · source * · destination *
notice: network-1 · network · group:example-admins · met
live policy:7:3: notice: network-1 · candidate rule (a text match, not a verdict) · acls[3] · source * · destination *
live policy:5:3: notice: network-1 · candidate rule (a text match, not a verdict) · acls[1] · source group:example-admins · destination tag:example-db · ports 22
notice: if group:example-admins were compromised, the live policy would let it reach:
notice:   network tag:example-db:22 (network-1)
notice:   policy grants this source all destinations (candidate rule at 7:3)
notice:   assumption: can apply tag:example-db (tagOwners), whose rules would then apply
notice:   assumption: can apply tag:example-web (tagOwners), whose rules would then apply
notice: if tag:example-web were compromised, the live policy would let it reach:
notice:   network tag:example-db:22 (network-2)
notice:   policy grants this source all destinations (candidate rule at 7:3)
```

and, on standard error, `tailkeeper: findings_present: an expectation of the intent set is unmet: the live policy was witnessed to do the other thing`. The exit code is 8.

`network-2` is `unmet` because the live policy accepted a connection the owner said must be dropped, and Tailscale said so under a canary. The broad rule is named because it is a candidate whose destination is `*`, not because tailkeeper concluded it was the cause: the owner reads it and decides. `network-1` is `met`. Exit 8.

If the canary had not come back, both would be `unknown` with the reason `canary`, and the exit code 1. If the policy gated the admins' rule on a device posture and the expectation gave no attributes, `network-1` would be `met_with_limits` and the exit code 1.

## Where it is not

Not an MCP tool. `security scan` does not run it and does not take its results: the scan's intent row stays partial, as it is, until a later change judges expectations there. It sends nothing but the read of the live policy and the validation requests above, with the credential `acl_test` uses (`policy_file:read` and the scopes that go with it).
