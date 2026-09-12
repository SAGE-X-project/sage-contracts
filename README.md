# sage-contracts

Smart contracts for SAGE (Secure Agent Guarantee Engine): the on-chain
agent registry, ERC-8004 registries and governance contracts on EVM chains,
and the Solana programs. Extracted from
[`sage`](https://github.com/SAGE-X-project/sage) (`contracts/`) on
2026-09-12 with full history.

| Path | What |
|---|---|
| `ethereum/` | Hardhat project: Solidity 0.8.20 sources, 219 tests, deployment and verification scripts, docs |
| `solana/` | Anchor programs `sage-registry` and `sage-verification-hook` (not yet built in CI, see below) |
| `abi/` | Exported ABI of every deployable contract, kept in sync with the sources by CI |
| `examples/` | Client examples |
| `scripts/export-abi.sh` | Regenerates `abi/` from the Hardhat artifacts |

## Consumers

The Go core generates its bindings from `abi/` at a pinned git ref of this
repository (`.contracts-version` in `sage`, `make bindings`); the protocol
specification lives in [`sage-spec`](https://github.com/SAGE-X-project/sage-spec).
A release tag `vX.Y.Z` attaches `sage-contracts-abi-vX.Y.Z.tar.gz` with a
SHA-256 checksum to the GitHub release.

## Deployed contracts (Sepolia, chain id 11155111)

| Contract | Address |
|---|---|
| AgentCardRegistry | `0xC7eCF7Ad6ee71CB0d94f0eb00F46f1DDf432a808` |
| AgentCardVerifyHook | `0xf3be150cd4EC0819bef95890DeeE0B71d9C94F6b` |
| ERC8004IdentityRegistry | `0x5B0763c3649eee889966dF478a73e53Df0420C84` |
| ERC8004ReputationRegistry | `0xE953B278fd2378BA4987FE07f71575dd3353C9a8` |
| ERC8004ValidationRegistry | `0x97291e2D3023d166878ed45BBD176F92E5Fda098` |

Deployed 2025-11-03 and verified on Etherscan. The Sepolia
`ERC8004ValidationRegistry` runs the code from before the access-control fix
(sage BACKLOG C-01) and will be redeployed before any mainnet or public
demo use. The Go core's `chain.Presets` table is the runtime source of these
addresses.

## Development

```bash
cd ethereum
npm ci --ignore-scripts
npm run lint        # solhint
npm run compile
npm test            # 219 tests
cd .. && scripts/export-abi.sh   # refresh abi/ after a contract change
```

`ethereum/README.md` documents the contracts, deployment scripts and the
multi-network configuration in detail.

## Solana

The programs under `solana/` target Anchor 0.29 but have no `Anchor.toml`,
lockfile or CI build yet (sage BACKLOG C-04). CI only checks their Rust
formatting until that is fixed.

## Licence

MIT (see `LICENSE`). The Solidity sources under `ethereum/` and the programs
under `solana/` carry their own MIT licence files from the original tree.
