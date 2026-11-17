# Changelog

## Unreleased

- Reorganised the repository by spec version. `v1/` (0.9.0-draft.1) holds the
  AgentCard, ERC-8004 and governance Hardhat project, the Solana programs,
  `abi/` and `examples/`; `v2/` (0.9.0-draft.2) and `v3/` (0.10.0) have no
  contracts; `v4/` (0.11.0 draft) holds the chain Registry, its component
  tests, scripts, Sepolia record and research. Each folder has a `README.md`
  and `docs/DEPLOYMENTS.md`. The Go bindings now read `v1/abi/`.
- Split CI into `v1-*` and `v4-*` workflows. The Slither triage of the chain
  Registry runs on its own Hardhat project in `v4/ethereum`; v1 has a plain
  Slither job.
- Re-pinned the v4 runtime tool hashes after the runtime checkers learnt to
  read `.github/workflows/v4-*.yml` from the git top level. Contract sources,
  the compiler and source unit names are unchanged, so the compiled bytecode
  still matches the 2026-10-23 Sepolia deployment.

- Imported `contracts/` from the `sage` repository with history (git subtree
  split, 80 commits).
- Added `abi/` with the exported ABI of the ten deployable contracts and
  `scripts/export-abi.sh`; CI fails when the sources and `abi/` drift.
- Added workflows: Hardhat lint/compile/test, Slither (blocking on High),
  npm licence check, Solana formatting check, and an ABI archive release on
  `v*` tags. Dependabot covers npm, cargo and GitHub Actions.
