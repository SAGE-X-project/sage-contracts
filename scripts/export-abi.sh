#!/usr/bin/env bash
# Export the ABI of every deployable contract from the Hardhat artifacts into
# abi/<Contract>.json (ABI array only, sorted keys, stable formatting) so
# consumers such as the Go core can generate bindings from a git ref or a
# release tarball without compiling Solidity.
#
# Usage: scripts/export-abi.sh [OUT_DIR]   (default: abi)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARTIFACTS="$ROOT/ethereum/artifacts/contracts"
OUT="${1:-$ROOT/abi}"

# Contract name -> artifact path (relative to artifacts/contracts).
CONTRACTS=(
  "AgentCardRegistry=AgentCardRegistry.sol/AgentCardRegistry.json"
  "AgentCardStorage=AgentCardStorage.sol/AgentCardStorage.json"
  "AgentCardVerifyHook=AgentCardVerifyHook.sol/AgentCardVerifyHook.json"
  "IRegistryHook=interfaces/IRegistryHook.sol/IRegistryHook.json"
  "ISageRegistry=interfaces/ISageRegistry.sol/ISageRegistry.json"
  "ERC8004IdentityRegistry=erc-8004/standalone/ERC8004IdentityRegistry.sol/ERC8004IdentityRegistry.json"
  "ERC8004ReputationRegistry=erc-8004/standalone/ERC8004ReputationRegistry.sol/ERC8004ReputationRegistry.json"
  "ERC8004ValidationRegistry=erc-8004/standalone/ERC8004ValidationRegistry.sol/ERC8004ValidationRegistry.json"
  "TEEKeyRegistry=governance/TEEKeyRegistry.sol/TEEKeyRegistry.json"
  "SimpleMultiSig=governance/SimpleMultiSig.sol/SimpleMultiSig.json"
)

if [ ! -d "$ARTIFACTS" ]; then
  echo "artifacts not found at $ARTIFACTS; run 'npm run compile' in ethereum/ first" >&2
  exit 1
fi
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

mkdir -p "$OUT"
for entry in "${CONTRACTS[@]}"; do
  name="${entry%%=*}"
  path="${entry#*=}"
  src="$ARTIFACTS/$path"
  [ -f "$src" ] || { echo "missing artifact $src" >&2; exit 1; }
  jq -S '.abi' "$src" > "$OUT/$name.json"
done
echo "exported ${#CONTRACTS[@]} ABIs to $OUT"
