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

This directory stores deployment information for AgentCard contracts across multiple blockchain networks.

## Supported Networks

### Ethereum
- **Mainnet**: Production deployments
- **Sepolia**: Testnet deployments

### Kaia (formerly Klaytn)
- **Cypress (Mainnet)**: Production deployments
- **Kairos (Testnet)**: Testnet deployments

### Binance Smart Chain (BSC)
- **Mainnet**: Production deployments
- **Testnet**: Testnet deployments

### Base
- **Mainnet**: Production deployments
- **Sepolia (Testnet)**: Testnet deployments

### Arbitrum
- **One (Mainnet)**: Production deployments
- **Sepolia (Testnet)**: Testnet deployments

### Optimism
- **Mainnet**: Production deployments
- **Sepolia (Testnet)**: Testnet deployments

## File Naming Convention

```
{network}-{contract}-{timestamp}.json
```

**Examples:**
- `ethereum-mainnet-AgentCardRegistry-1729123456789.json`
- `kaia-kairos-AgentCardRegistry-1729123456789.json`
- `bsc-mainnet-AgentCardRegistry-1729123456789.json`

## Latest Deployment Files

Each network maintains a symlink or copy to the latest deployment:

```
{network}-latest.json
```

**Examples:**
- `ethereum-mainnet-latest.json`
- `kaia-kairos-latest.json`

## Deployment File Structure

```json
{
  "network": "ethereum-mainnet",
  "chainId": 1,
  "timestamp": 1729123456789,
  "contracts": {
    "AgentCardRegistry": {
      "address": "0x...",
      "deployer": "0x...",
      "blockNumber": 12345678,
      "transactionHash": "0x...",
      "constructorArgs": [],
      "verified": true
    },
    "AgentCardVerifyHook": {
      "address": "0x...",
      "deployer": "0x...",
      "blockNumber": 12345679,
      "transactionHash": "0x...",
      "constructorArgs": [],
      "verified": true
    }
  }
}
```

## Network Configuration

### Ethereum Networks
```javascript
// Mainnet
chainId: 1
rpcUrl: "https://eth-mainnet.g.alchemy.com/v2/YOUR-API-KEY"

// Sepolia
chainId: 11155111
rpcUrl: "https://eth-sepolia.g.alchemy.com/v2/YOUR-API-KEY"
```

### Kaia Networks
```javascript
// Cypress (Mainnet)
chainId: 8217
rpcUrl: "https://public-en.node.kaia.io"

// Kairos (Testnet)
chainId: 1001
rpcUrl: "https://public-en-kairos.node.kaia.io"
```

### BSC Networks
```javascript
// Mainnet
chainId: 56
rpcUrl: "https://bsc-dataseed.binance.org"

// Testnet
chainId: 97
rpcUrl: "https://data-seed-prebsc-1-s1.binance.org:8545"
```

### Base Networks
```javascript
// Mainnet
chainId: 8453
rpcUrl: "https://mainnet.base.org"

// Sepolia
chainId: 84532
rpcUrl: "https://sepolia.base.org"
```

### Arbitrum Networks
```javascript
// One (Mainnet)
chainId: 42161
rpcUrl: "https://arb1.arbitrum.io/rpc"

// Sepolia
chainId: 421614
rpcUrl: "https://sepolia-rollup.arbitrum.io/rpc"
```

### Optimism Networks
```javascript
// Mainnet
chainId: 10
rpcUrl: "https://mainnet.optimism.io"

// Sepolia
chainId: 11155420
rpcUrl: "https://sepolia.optimism.io"
```

## Deployment Scripts

Deploy to specific networks using:

```bash
# Ethereum
npm run deploy:ethereum:mainnet
npm run deploy:ethereum:sepolia

# Kaia
npm run deploy:kaia:mainnet
npm run deploy:kaia:testnet

# BSC
npm run deploy:bsc:mainnet
npm run deploy:bsc:testnet

# Base
npm run deploy:base:mainnet
npm run deploy:base:testnet

# Arbitrum
npm run deploy:arbitrum:mainnet
npm run deploy:arbitrum:testnet

# Optimism
npm run deploy:optimism:mainnet
npm run deploy:optimism:testnet
```

## Environment Variables

Set the following in `.env` file:

```bash
# Private Keys
PRIVATE_KEY=your_private_key_for_testnets
MAINNET_PRIVATE_KEY=your_private_key_for_mainnets

# Ethereum
ETHEREUM_MAINNET_RPC_URL=
ETHEREUM_SEPOLIA_RPC_URL=
ETHERSCAN_API_KEY=

# Kaia
KAIA_MAINNET_RPC_URL=
KAIA_TESTNET_RPC_URL=

# BSC
BSC_MAINNET_RPC_URL=
BSC_TESTNET_RPC_URL=
BSCSCAN_API_KEY=

# Base
BASE_MAINNET_RPC_URL=
BASE_TESTNET_RPC_URL=
BASESCAN_API_KEY=

# Arbitrum
ARBITRUM_MAINNET_RPC_URL=
ARBITRUM_TESTNET_RPC_URL=
ARBISCAN_API_KEY=

# Optimism
OPTIMISM_MAINNET_RPC_URL=
OPTIMISM_TESTNET_RPC_URL=
OPTIMISTIC_ETHERSCAN_API_KEY=
```

## Verification

After deployment, verify contracts on block explorers:

```bash
npm run verify:ethereum:mainnet
npm run verify:kaia:mainnet
npm run verify:bsc:mainnet
npm run verify:base:mainnet
npm run verify:arbitrum:mainnet
npm run verify:optimism:mainnet
```

## Security Notes

1. **Never commit private keys** to version control
2. **Use separate keys** for testnet and mainnet
3. **Verify deployed contracts** on block explorers
4. **Test thoroughly** on testnets before mainnet deployment
5. **Keep deployment records** for audit trail
