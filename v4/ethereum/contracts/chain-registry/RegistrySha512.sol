// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {IChainRegistry} from "./IChainRegistry.sol";
import {Sha2Ext} from "./vendor/Sha2Ext.sol";

/// @notice SHA512 construction component for at most R32||A32||PoP292 bytes.
/// @dev This bound follows the adopted Registry fields, not a generic message
/// limit or an alternate Ed25519 mode. This helper neither verifies nor signs.
library RegistrySha512 {
    function digest(bytes memory input) internal pure returns (bytes memory) {
        if (input.length > 356) revert IChainRegistry.BoundsExceeded();
        (bytes32 first, bytes32 second) = Sha2Ext.sha512(input);
        return abi.encodePacked(first, second);
    }
}
