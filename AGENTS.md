## Testing

Most tests are run as integration tests. See the Makefile for various targets. PJDFS tests are much faster than
the XFS test suite. Only run the full XFS test suite to verify your work at the end.

## CI
Pull request checks run on Linux x86_64 hosted runners (`ubuntu-*`) only. Other platforms (the `mac-ci` job on
macOS) run on push to master, not on pull requests.

## Style guide
- Comments should be brief and focus on important invariants, architectural details, or other
  long-term relevant information. They should not contain minor implementation details of the current
  commit.

## Git commits
Make one commit per feature / bug fix when opening a PR. Multiple commits or "fixup" commits are
should not be merged to master.

## Release notes

Changes that are significant to users should be documented in `CHANGELOG.md`. Entries should be
brief and focus on the user-facing impact of the change, not on implementation details.

## Other notes

- The repo enforces ASCII-only source: CI fails on non-ASCII characters in
  `*.rs` and `*.toml` files. Keep new code ASCII-only.
- `RUSTFLAGS=--deny warnings` is set in CI, so any new warning will break the
  build. Fix warnings rather than silencing them.
