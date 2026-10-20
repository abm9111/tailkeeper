### Release notes fixture

`make release-notes-check` and the manual snapshot run in `.github/workflows/release.yml`
give this file to GoReleaser with `--release-notes`, in place of the notes the release job
cuts from CHANGELOG.md, so that GoReleaser's changelog stage reads a notes file before any
tag exists.
