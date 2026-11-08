# Synthetic security demos

Run all three from a checkout with Go installed:

```sh
env -u TAILKEEPER_LIVE go test -count=1 -run '^TestPublicDemo' -v ./internal/cli
```

The tests invoke the CLI runner with the in-process fake API. They do not connect to a real tailnet. Their private fixture files and the before-pack live in temporary directories; the transcript prints placeholders for those paths, not pack contents. The command requires permission to bind a local fake HTTP server.

- **Advisory applicability:** an old reported stable client matches a reviewed shipped rule. The finding takes exit 8 even though the assessment is partial. Four pending rules yield unknown results; an affected version is not proof of exploitation.
- **Excessive access:** a deny expectation is witnessed allowed by the fake validator. A broad matching rule is a candidate, not an established cause. The conditional blast radius does not establish that a service listens, credentials work, or an exploit succeeds.
- **Correction verification:** the test exports a private before-pack, changes the fake device's reported version to model an owner correction, and collects new evidence. A fresh new running version yields `fixed` and exit 0; a contradictory old running version yields `not_fixed` and exit 8. This is a synthetic observation, not a claim about any real device.
