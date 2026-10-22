// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {RegistryTransition} from "ethereum/contracts/chain-registry/RegistryTransition.sol";
import {RegistryJson} from "ethereum/contracts/chain-registry/RegistryJson.sol";
import {RegistryRoleHashes} from "ethereum/contracts/chain-registry/RegistryRoleHashes.sol";

/// @dev Test-only read/pure helpers. This contract cannot admit a Registry caller.
contract SemanticHelperControls {
    function operationName(uint8 operation) external pure returns (string memory) {
        return RegistryTransition.operationName(RegistryJson.Operation(operation));
    }
    function sameBytes(bytes memory first, bytes memory second) external pure returns (bool) {
        return RegistryTransition.equal(first, second);
    }
    function acceptsRoles(address r0,address r1,address r2,address r3,address r4,address r5,address r6,address r7)
        external view returns (bool) {
        return RegistryRoleHashes.accepts([r0,r1,r2,r3,r4,r5,r6,r7]);
    }
}
