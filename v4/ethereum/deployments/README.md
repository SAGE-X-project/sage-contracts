# Deployment Records

## SAGE 0.11.0 chain Registry

`scripts/deploy-chain-registry.mjs` deploys the thirteen chain Registry
instances with the compiler settings of the [Sepolia deployment](chain-registry-sepolia.md)
(solc 0.8.20, shanghai, via-IR, 200 runs) and writes a record in the same
shape. It compiles the sources pinned by
`component-tests/chain-registry/runtime/source-identities.json`, so fetch the
pinned compiler first.

```bash
python3 component-tests/chain-registry/prepare.py
anvil --port 8545 &
node scripts/deploy-chain-registry.mjs --rpc http://127.0.0.1:8545 --network anvil
```

- On chain ID 31337 the script uses the public Anvil/Hardhat test key unless
  `SAGE_DEPLOYER_PRIVATE_KEY` is set. Any other chain needs `--allow-remote`
  and that variable; deploy to a public network only after approval.
- The record lands in `deployments/chain-registry-<network>.json`, which git
  ignores, and the script never overwrites an existing record.
- `runtime_matches_sepolia` compares runtime hashes with the Sepolia record.
  The eight role contracts must match byte for byte. `ChainRegistry`, the store
  and the three processors embed addresses as immutables, so they differ.
- Gas use depends on the node's fork rules. On Anvil 1.9.0 with default
  settings `ChainRegistry` creation used about 12M gas; on Sepolia it used
  88.8M. Do not treat local gas as a testnet cost estimate.

### Lifecycle scenarios

`scripts/registry-lifecycle-scenarios.mjs` drives one agent through
registration, metadata changes, a leaked signing key, a scoped operator grant
and removal on chain ID 31337, and checks every refusal by its error name.

```bash
node scripts/registry-lifecycle-scenarios.mjs --rpc http://127.0.0.1:8545 \
  --deployment deployments/chain-registry-anvil.json --out /tmp/registry-trace.json
```

For each step the trace keeps the acting account, the call, the transaction,
the canonical record and grants before and after, and the `RecordChanged`
event, so every change of Registry data or of the acting subject can be
inspected. It also keeps all history items and commands. `--keep-active` stops
before removal and leaves the agent active with `sig-3` (and `kem-2`) usable,
so other components can verify messages it signs. `--key-index-base` (default
100) shifts the disclosed key recipes so a second agent gets its own keys; the
agent's key `sig-3` uses recipe base+3.
