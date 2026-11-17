# sage-contracts

Smart contracts for SAGE (Secure Agent Guarantee Engine), kept per
[`sage-spec`](https://github.com/SAGE-X-project/sage-spec) version. Extracted
from [`sage`](https://github.com/SAGE-X-project/sage) (`contracts/`) on
2026-09-12 with full history.

## Versions

| Folder | Spec version | Spec reference | Contracts | Status |
|---|---|---|---|---|
| [`v1/`](v1/README.md) | 0.9.0-draft.1 | sage-spec `a34dd49` | AgentCard registry and hook, ERC-8004 registries, governance, Solana programs, exported ABI | Deployed on Sepolia 2025-11-03; known defects, redeployment planned |
| [`v2/`](v2/README.md) | 0.9.0-draft.2 | sage-spec `f4a4e7f` | none | Never released |
| [`v3/`](v3/README.md) | 0.10.0 | sage-spec `spec/09-registry.md` | none (abstract contract only) | No contract of its own |
| [`v4/`](v4/README.md) | 0.11.0 (draft) | sage-spec `profiles/sage-0.11.0` at `a22a275` | chain Registry (13 instances), component tests, research | Test deployment on Sepolia 2026-10-23 |

Each folder has a `README.md` (spec version and commit, contents, status,
build and test commands) and `docs/DEPLOYMENTS.md` (deployment history).
`scripts/export-abi.sh` regenerates `v1/abi/` from the v1 Hardhat artifacts.

## Layout rule

- A spec version that changes a contract gets its own `vN/` folder; the next
  one is `v5/`. Older folders stay as the record of what they deployed.
- A deployed source changes only together with a new entry in that folder's
  `docs/DEPLOYMENTS.md` that records the new deployment. Never edit a deployed
  source in place without one.
- Every pinned path in `v4/` is relative to `v4/` (source unit names
  `ethereum/contracts/chain-registry/...`), so the compiled bytecode matches the
  Sepolia deployment. Workflows are named `vN-*.yml`; the v4 manifests pin
  `.github/workflows/v4-registry-runtime.yml` by SHA-256.

## Consumers

The Go core generates its bindings from `v1/abi/` at a pinned git ref of this
repository (`.contracts-version` in `sage`, `make bindings`). A release tag
`vX.Y.Z` attaches `sage-contracts-abi-vX.Y.Z.tar.gz` (built from `v1/abi/`)
with a SHA-256 checksum to the GitHub release. The 0.11.0 chain Registry
record and ABI are in `v4/ethereum/deployments/`.

## Licence

MIT (see `LICENSE`). The Solidity sources and the Solana programs carry their
own MIT licence files from the original tree.
