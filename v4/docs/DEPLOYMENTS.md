# v4 deployment history (0.11.0 draft)

Facts come only from this repository: `ethereum/deployments/chain-registry-sepolia.json`,
`ethereum/deployments/chain-registry-sepolia.md`, the root README and the git
history (`12d32de` "docs: record Sepolia Registry deployment"). Cells that the
repository does not record say "unknown".

## Deployments

All rows: 2026-10-23, Ethereum Sepolia, chain ID 11155111, source commit
`9677235` (`967723542e371dbe943ac9bf18040798e251b917`), spec commit `a22a275`,
solc 0.8.20 (shanghai, via-IR, 200 runs), deployer
`0x5ade38c2d961628ef5753411352fc3d9ca765348`.

| Contract | Address | Creation tx | Block | Verified where | Status |
|---|---|---|---|---|---|
| RegistryRenderer | `0x74d73d44a0f6a54d40ac6e5fb8b271758747075f` | `0x486f05353d8c739c51001e86a6e33b43319089d353f11464c1455d08ccd0f0ae` | 11974661 | runtime code matched on two public RPCs; explorer source verification unknown | active (test deployment) |
| RegistryEd25519 | `0x00399c943927a9f16fcfc2fb4b9287c56392e018` | `0xabcc1de6af2acd18298b65fb13e7dde5a68d6833ea73a5638d28013083109395` | 11974663 | same | active (test deployment) |
| RegistryRules | `0x3ae62e61d81c7223abd19581e7b5caa8bcdc119e` | `0xc7ef099d429ab10f9737bdecca9394fbf0336da21fce8f03ac452fbce109dc30` | 11974664 | same | active (test deployment) |
| RegistryCallValidator | `0xd1494feceeb21f6448e40f128446c66a08c16a10` | `0x8fefaaecf434cdafc614592c6bc60b80f2b5fe17458ac9089581d4a8b1995555` | 11974665 | same | active (test deployment) |
| RegistryStoreFactory | `0xb15945511e8e5fce5566765244dc54c422080da7` | `0xb6442646b1771bfccb20dae77a1bf03b4b509ae61d26fcebe2eae3b2daaaead4` | 11974666 | same | active (test deployment) |
| RegistryClaimProcessorFactory | `0xb8b0051e61cfaab6782fc9e60b5829295876b4ee` | `0x59a16d8e37af89b1fdaa9f07a96237be66ce51dace1a53cde43522981b41d277` | 11974667 | same | active (test deployment) |
| RegistryKeyServiceProcessorFactory | `0x2348833deabb13a80c93b096b27be7cf72ee4a1c` | `0x24664fe0a8f3781221b4e0fe250fdf93321bafe3cac40f391aae258b52c9fd4c` | 11974668 | same | active (test deployment) |
| RegistryLifecycleProcessorFactory | `0x3c25f62be1416a0223fe840a8cbdb3a3b51b5f50` | `0xdf417eba26cf9e8a2f714696bea49c9c5181ee2b9b608b807c972a9ecc000fcf` | 11974669 | same | active (test deployment) |
| ChainRegistry | `0x9361223865e641f9941f4640d8fe34faad54bf23` | `0x0bbe893c6c0765c1f97372d65515b539713fd83f670b8729959a436d2783abb6` | 11974670 | same; `registryId()` matched on both RPCs | active (test deployment) |
| RegistryStore | `0x9a5ea2f922d87041efd62090672f24f7b48440e1` | created by the ChainRegistry constructor (tx above) | 11974670 | same | active (test deployment) |
| RegistryClaimProcessor | `0x0f2afc847a3cf2b6ebe22b09edab83348a50559f` | created by the ChainRegistry constructor | 11974670 | same | active (test deployment) |
| RegistryKeyServiceProcessor | `0x14feab43919e753257384702dc3cce21f65a718c` | created by the ChainRegistry constructor | 11974670 | same | active (test deployment) |
| RegistryLifecycleProcessor | `0xeb7ed0efe6a153045c5aa7ca1797d6d0d888b197` | created by the ChainRegistry constructor | 11974670 | same | active (test deployment) |

Registry identity: `eip155:11155111:0x9361223865e641f9941f4640d8fe34faad54bf23`.
All nine creation receipts succeeded; total gas 238,344,377; fees
0.000000241442853901 ETH. Runtime SHA-256 hashes of all thirteen instances and
the full receipts are in `ethereum/deployments/chain-registry-sepolia.json`.

## Qualification boundary

This is a test deployment with no registered Agent. Agreement of two RPC
providers on code and identity is diagnostic evidence, not authenticated
consensus, finality or production readiness (see
`ethereum/deployments/chain-registry-sepolia.md`). The record does not state
whether the sources were verified on a block explorer.
