# v1: SAGE 0.9.0-draft.1 contracts

| | |
|---|---|
| Spec version | `0.9.0-draft.1` (the legacy draft that documents sage v1.5.2) |
| Spec reference | [`sage-spec`](https://github.com/SAGE-X-project/sage-spec) commit `a34dd49` |
| Status | Deployed on Sepolia (2025-11-03); known defects, a fixed contract and redeployment are planned (see [docs/DEPLOYMENTS.md](docs/DEPLOYMENTS.md)) |

## Contents

| Path | What |
|---|---|
| `ethereum/` | Hardhat project: `AgentCardRegistry`, `AgentCardStorage`, `AgentCardVerifyHook`, the ERC-8004 standalone registries, governance (`SimpleMultiSig`, `TEEKeyRegistry`, `TimelockController`), interfaces, 219 tests, deployment and verification scripts, docs |
| `ethereum/deployments/` | Machine records of local deployments (`hardhat-latest.json`) and the deployment guide |
| `solana/` | Anchor programs `sage-registry` and `sage-verification-hook`; draft.1 chapter 06 names the Solana chain. No `Anchor.toml`, lockfile or CI build yet (sage BACKLOG C-04); CI only checks Rust formatting |
| `abi/` | Exported ABI of the ten deployable contracts, kept in sync with the sources by CI (`v1-test.yml`) and published as a release archive (`v1-release.yml`) |
| `examples/` | Client examples |

The chain Registry of SAGE 0.11.0 is not part of this version; it lives in
[`../v4`](../v4/README.md).

## Build and test

```bash
cd v1/ethereum
npm ci --ignore-scripts
npm run lint        # solhint
npm run compile
npm test            # 219 tests
cd ../.. && scripts/export-abi.sh   # refresh v1/abi/ after a contract change
```

`ethereum/README.md` documents the contracts, deployment scripts and the
multi-network configuration in detail.

## Changing this version

The sources deployed on 2025-11-03 are the record of that deployment. A fix
(for example of the known defects) changes a deployed source only together
with a new entry in [docs/DEPLOYMENTS.md](docs/DEPLOYMENTS.md) that records the new
deployment; a contract change that belongs to a new spec version goes into
that version's folder instead.
