// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {IChainRegistry} from "./IChainRegistry.sol";

/// @notice Construction of the exact adopted Registry commitment/PoP domains.
/// @dev Callers supply bounded, validated fields and complete claim JCS. This
/// helper does not validate an identity, a JSON schema, a key role or a proof.
library RegistryDomain {
    function pop(
        string memory registry,
        string memory agentId,
        string memory name,
        string memory algorithm,
        bytes memory rawKey
    ) internal pure returns (bytes memory) {
        bytes memory registryBytes = bytes(registry);
        bytes memory agentBytes = bytes(agentId);
        bytes memory nameBytes = bytes(name);
        bytes memory algorithmBytes = bytes(algorithm);
        if (registryBytes.length > 82 || agentBytes.length > 64 || nameBytes.length > 32 ||
            algorithmBytes.length > 24 || rawKey.length > 65) revert IChainRegistry.BoundsExceeded();
        return abi.encodePacked(
            "sage-pop-0.11.0",
            uint16(registryBytes.length), registryBytes,
            uint16(agentBytes.length), agentBytes,
            uint16(nameBytes.length), nameBytes,
            uint16(algorithmBytes.length), algorithmBytes,
            uint16(rawKey.length), rawKey
        );
    }

    function claimDigest(bytes memory canonicalClaim) internal pure returns (bytes32) {
        return sha256(abi.encodePacked("sage-claim-0.11.0", bytes1(0), canonicalClaim));
    }
}
