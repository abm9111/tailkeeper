# Community drafts — unsent

These drafts are for review. No outreach or publication has been performed.

## Advisory applicability

I made a reproducible synthetic example of an old reported client matching a reviewed advisory rule. The scan returns a finding while keeping the assessment partial because four rules are pending. A version match does not establish exploitation. Run the advisory test or all three examples using the command in [synthetic security demos](../security/demos.md).

## Excessive access

Here's a synthetic access explanation: a deny expectation is witnessed allowed, and a broad matching rule is shown as a candidate. The conditional blast radius does not prove which rule caused the result, that a service is listening, or that an exploit works. Reproduce it with the command in [synthetic security demos](../security/demos.md).

## Correction verification

A synthetic correction example exports a private before-pack, changes the fake device's reported version, and compares fresh post-action evidence. A new running version meets the target; an old one remains `not_fixed`. This demonstrates the workflow with a fake API, not a real fleet's state. Reproduce it with the command in [synthetic security demos](../security/demos.md).
