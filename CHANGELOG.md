# Changelog

## Unreleased

- Imported `contracts/` from the `sage` repository with history (git subtree
  split, 80 commits).
- Added `abi/` with the exported ABI of the ten deployable contracts and
  `scripts/export-abi.sh`; CI fails when the sources and `abi/` drift.
- Added workflows: Hardhat lint/compile/test, Slither (blocking on High),
  npm licence check, Solana formatting check, and an ABI archive release on
  `v*` tags. Dependabot covers npm, cargo and GitHub Actions.
