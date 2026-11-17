# v1 deployment history (0.9.0-draft.1)

Facts come only from this repository: the root README, `ethereum/README.md`,
`ethereum/deployments/` and the git history. Cells that the repository does
not record say "unknown". No transaction hash below is guessed.

## Deployments

| Date | Network | Chain ID | Contract | Address | Source commit | Tx / receipt | Verified where | Status |
|---|---|---|---|---|---|---|---|---|
| 2025-11-03 | Ethereum Sepolia | 11155111 | AgentCardRegistry | `0xC7eCF7Ad6ee71CB0d94f0eb00F46f1DDf432a808` | `749c077` (commit that records the deployment) | unknown | Etherscan and Blockscout (commit `749c077` message) | active, known defects (see below); to become superseded |
| 2025-11-03 | Ethereum Sepolia | 11155111 | AgentCardVerifyHook | `0xf3be150cd4EC0819bef95890DeeE0B71d9C94F6b` | `749c077` | unknown | Etherscan and Blockscout | active |
| 2025-11-03 | Ethereum Sepolia | 11155111 | ERC8004IdentityRegistry | `0x5B0763c3649eee889966dF478a73e53Df0420C84` | `749c077` | unknown | Etherscan and Blockscout | active |
| 2025-11-03 | Ethereum Sepolia | 11155111 | ERC8004ReputationRegistry | `0xE953B278fd2378BA4987FE07f71575dd3353C9a8` | `749c077` | unknown | Etherscan and Blockscout | active |
| 2025-11-03 | Ethereum Sepolia | 11155111 | ERC8004ValidationRegistry | `0x97291e2D3023d166878ed45BBD176F92E5Fda098` | `749c077` | unknown | Etherscan and Blockscout | known defect: runs the code from before the access-control fix (sage BACKLOG C-01, fixed later in `c9a6181`); to be redeployed before any mainnet or public demo use |
| 2025-10-26 | Hardhat (local) | 31337 | AgentCardVerifyHook, AgentCardRegistry | see `ethereum/deployments/hardhat-latest.json` | unknown | recorded in `hardhat-latest.json` (local chain only) | none | local test record, not a public deployment |

The deployment commit `749c077` states the ERC8004ValidationRegistry
configuration at deployment: minimum stake 0.01 ETH, minimum validators 3,
consensus threshold 66%. The Go core's `chain.Presets` table in `sage` is the
runtime source of these addresses.

## Known defects

These defects are in the deployed `ethereum/contracts/AgentCardRegistry.sol`.
A fixed contract and a redeployment are planned. That deployment gets its own
row above, and the 2025-11-03 AgentCardRegistry row then becomes
"superseded".

1. `revokeKey` (lines 307-330) does not check that `keyHash` belongs to the
   caller's agent. The loop removes the hash only if it finds it, but
   `agentKeys[keyHash].verified = false` runs for any hash, so the owner of
   any agent can mark another agent's key unverified.
2. `_verifyKeyOwnership` does not check the SAGE proof of possession that
   spec section 4 requires. For Ed25519 it only checks that the signature is
   64 bytes long.
3. The ECDSA proof (lines 424-438) signs a message built from the chain ID,
   the registry address and the owner address only. It proves control of the
   owner account, not possession of the key being registered.
