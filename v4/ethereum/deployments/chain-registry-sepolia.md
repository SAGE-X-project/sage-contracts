# SAGE 0.11.0 Sepolia Registry deployment

Deployed on 2026-10-23 to Ethereum Sepolia (chain ID 11155111).
Core address: `0x9361223865e641f9941f4640d8fe34faad54bf23`.
Immutable identity: `eip155:11155111:0x9361223865e641f9941f4640d8fe34faad54bf23`.

The [machine-readable record](chain-registry-sepolia.json) retains the exact
source/spec revisions, compiler settings, runtime SHA-256 hashes and all nine
creation receipts. The [ABI](chain-registry-sepolia-abi.json) is the unchanged
compiler output for `ChainRegistry`, including thirteen functions, twenty-two
errors and two events. Its SHA-256 is pinned in the record.

## Instances

| Contract | Address |
|---|---|
| RegistryRenderer | `0x74d73d44a0f6a54d40ac6e5fb8b271758747075f` |
| RegistryEd25519 | `0x00399c943927a9f16fcfc2fb4b9287c56392e018` |
| RegistryRules | `0x3ae62e61d81c7223abd19581e7b5caa8bcdc119e` |
| RegistryCallValidator | `0xd1494feceeb21f6448e40f128446c66a08c16a10` |
| RegistryStoreFactory | `0xb15945511e8e5fce5566765244dc54c422080da7` |
| RegistryClaimProcessorFactory | `0xb8b0051e61cfaab6782fc9e60b5829295876b4ee` |
| RegistryKeyServiceProcessorFactory | `0x2348833deabb13a80c93b096b27be7cf72ee4a1c` |
| RegistryLifecycleProcessorFactory | `0x3c25f62be1416a0223fe840a8cbdb3a3b51b5f50` |
| ChainRegistry | `0x9361223865e641f9941f4640d8fe34faad54bf23` |
| RegistryStore | `0x9a5ea2f922d87041efd62090672f24f7b48440e1` |
| RegistryClaimProcessor | `0x0f2afc847a3cf2b6ebe22b09edab83348a50559f` |
| RegistryKeyServiceProcessor | `0x14feab43919e753257384702dc3cce21f65a718c` |
| RegistryLifecycleProcessor | `0xeb7ed0efe6a153045c5aa7ca1797d6d0d888b197` |

Eight role/factory contracts were created first. The ninth transaction
created `ChainRegistry`; its constructor used the factories to create the four
state/processor instances. All nine receipts succeeded. The final creation
was included in block 11974670. No Agent registration was sent.

## Verification and cost

Two public RPC endpoints independently returned the expected runtime bytes
for all thirteen instances at the final creation block and the expected
`registryId()` ABI return. The successful sender enforced receipt, receipt-block
hash and new-code assertions before each subsequent transaction. Its intermediate
block/code RPC responses were not archived; directly preserved two-provider
code responses cover all thirteen instances at the final creation block.
Runtime hashes identify the exact instances, including constructor-bound
immutable values.

Total actual gas was 238,344,377; actual fees were **0.000000241442853901 ETH**.
The approved total ceiling was 0.001 ETH. Fixed gas limits and a 1,000,000 wei
maximum fee per gas reserved at most 0.000289490008 ETH. The compiler target
was Shanghai; the observed live Sepolia execution fork was Glamsterdam.
Historical Paris/Shanghai VM gas figures are not the live deployment costs.

## Initial read observations

At the same deployment block, both RPCs returned `record("sage-deployment-check")`
as absent with empty record bytes. `activeGrants` and `historyItem` version 1
for that absent identifier both refused with `WrongRecordState`, as required.
These are read-only observations; no record, history entry or grant was created.
The initial provider-reported finalized height was 11,974,611, below deployment
block 11,974,670. This observation therefore does not attest deployment finality.
The backup returned Sepolia genesis hash
`0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9`;
the primary could not return genesis because its old history was pruned.
This is an explicit evidence gap, not two-provider genesis agreement.

## Qualification boundary

This deployment does not change the normative protocol or existing deployments.
Code/identity agreement from RPC providers is diagnostic evidence, not
authenticated consensus verification, a selected finality policy or authoritative
Source enrollment. No full live lifecycle, operational custody, host or
protected-message qualification is claimed. The deployment alone does not
complete core, ADK or Inspector integration. Existing historical findings remain
unchanged. Additional paid lifecycle transactions require a separately scoped
plan and approval.
