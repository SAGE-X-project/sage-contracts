// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {RegistryDomain} from "ethereum/contracts/chain-registry/RegistryDomain.sol";

/// @dev Pure fixed construction/hash controls only; never a Registry entrypoint.
contract DomainHarness {
    function pop(string memory registry, string memory agentId, string memory name,
        string memory algorithm, bytes memory rawKey) external pure returns (bytes memory) {
        return RegistryDomain.pop(registry, agentId, name, algorithm, rawKey);
    }
    function claimDigest(bytes memory canonicalClaim) external pure returns (bytes32) {
        return RegistryDomain.claimDigest(canonicalClaim);
    }
}
