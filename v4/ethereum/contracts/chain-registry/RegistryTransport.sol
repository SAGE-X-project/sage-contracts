// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {IChainRegistry} from "./IChainRegistry.sol";

/// @dev Fixed internal targets only. Bound return data BEFORE copying it.
library RegistryTransport {
    uint256 internal constant MAXIMUM = 1048576;

    function read(address target, bytes memory input) internal view returns (bytes memory output) {
        if (input.length > MAXIMUM) revert IChainRegistry.WrongRegistryContext();
        bool success;
        uint256 size;
        assembly ("memory-safe") {
            success := staticcall(gas(), target, add(input, 32), mload(input), 0, 0)
            size := returndatasize()
        }
        if (size > MAXIMUM) revert IChainRegistry.WrongRegistryContext();
        output = new bytes(size);
        assembly ("memory-safe") {
            returndatacopy(add(output, 32), 0, size)
        }
        if (!success)
            assembly ("memory-safe") {
                revert(add(output, 32), mload(output))
            }
    }

    function write(address target, bytes memory input) internal returns (bytes memory output) {
        if (input.length > MAXIMUM) revert IChainRegistry.WrongRegistryContext();
        bool success;
        uint256 size;
        assembly ("memory-safe") {
            success := call(gas(), target, 0, add(input, 32), mload(input), 0, 0)
            size := returndatasize()
        }
        if (size > MAXIMUM) revert IChainRegistry.WrongRegistryContext();
        output = new bytes(size);
        assembly ("memory-safe") {
            returndatacopy(add(output, 32), 0, size)
        }
        if (!success)
            assembly ("memory-safe") {
                revert(add(output, 32), mload(output))
            }
    }

    function proof(address target, bytes memory input) internal view returns (bool) {
        bool success;
        uint256 size;
        assembly ("memory-safe") {
            success := staticcall(15000000, target, add(input, 32), mload(input), 0, 0)
            size := returndatasize()
        }
        if (size > MAXIMUM) revert IChainRegistry.WrongRegistryContext();
        bytes memory output = new bytes(size);
        assembly ("memory-safe") {
            returndatacopy(add(output, 32), 0, size)
        }
        if (!success)
            assembly ("memory-safe") {
                revert(add(output, 32), mload(output))
            }
        if (size != 32) revert IChainRegistry.WrongRegistryContext();
        return abi.decode(output, (bool));
    }
}
