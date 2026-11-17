# v4: SAGE 0.11.0 chain Registry (draft)

| | |
|---|---|
| Spec version | `0.11.0` (draft) |
| Spec reference | [`sage-spec`](https://github.com/SAGE-X-project/sage-spec) `profiles/sage-0.11.0`, commit `a22a275` (the `spec_commit` of the Sepolia record) |
| Status | Test deployment on Sepolia (2026-10-23), no registered Agent; not production-qualified |

## Contents

| Path | What |
|---|---|
| `ethereum/contracts/chain-registry/` | The 29 chain Registry sources (`ChainRegistry`, role, factory and processor contracts, vendored `Sha2Ext`) |
| `ethereum/component-tests/chain-registry/` | Component tests: library controls, runtime constructor and lifecycle controls, framing, supplemental source controls, with SHA-256 manifests (`source-identities.json`) |
| `ethereum/scripts/` | `deploy-chain-registry.mjs`, `registry-lifecycle-scenarios.mjs`, and the Slither triage tools `registry_slither.py` / `registry_triage.py` with their tests |
| `ethereum/deployments/` | The Sepolia record (`chain-registry-sepolia.json`, `.md`, ABI) and the deployment guide |
| `ethereum/slither.db.json`, `ethereum/.slither.config.json` | The one reviewed Slither finding and the pinned analyzer configuration (same configuration as v1; its rationale is in `../v1/ethereum/.slither.config.md`) |
| `ethereum/hardhat.config.js`, `package.json`, `package-lock.json` | A Hardhat project used for lint, compile and Slither, and for `ethers` in the scripts; same dependency set as v1 |
| `research/` | Chain Registry research: strict Ed25519 evaluation, bounded bulk workload, normal-state resource paths |

`v4/` is the root of every pinned path. The compiled source unit names are
`ethereum/contracts/chain-registry/...` relative to this folder, which keeps the
runtime bytecode identical to the Sepolia deployment. Workflow files are the
one exception: manifests name them as `.github/workflows/v4-*.yml` and the
tools read them from the git top level.

## Build and test

```bash
# Component tests (what .github/workflows/v4-registry-*.yml run)
cd v4/ethereum/component-tests/chain-registry
npm ci --ignore-scripts
python3 prepare.py                 # pinned solc 0.8.20 (SHA-256 checked)
python3 -B libraries/run.py        # all library groups
python3 -B runtime/run.py          # constructor and ordinary owned calls
python3 -B source-controls/run.py  # supplemental source controls

# Hardhat lint/compile (v4-test.yml) and Slither (v4-security.yml)
cd ../..
npm ci --ignore-scripts
npm run lint
npm run compile
```

Each tool refuses to overwrite earlier `evidence/` output; remove it before a
rerun. Changing a pinned tool or a `v4-registry-runtime.yml` workflow requires
updating `runtime/source-identities.json`; changing a pinned contract source
breaks bytecode identity with the Sepolia deployment.

Deploying locally and replaying the lifecycle scenarios is described in
`ethereum/deployments/README.md`.

## Deployments

See [docs/DEPLOYMENTS.md](docs/DEPLOYMENTS.md). A deployed source changes
only together with a new entry there.
