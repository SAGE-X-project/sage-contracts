// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {RegistryProcessor} from "ethereum/contracts/chain-registry/RegistryProcessor.sol";
import {IChainRegistry} from "ethereum/contracts/chain-registry/IChainRegistry.sol";
import {RegistryJson} from "ethereum/contracts/chain-registry/RegistryJson.sol";

/// @dev Test-only pure helper interface. Constructor preserves real binding checks.
contract ProcessorPureControls is RegistryProcessor {
    constructor(address owner, address stored, address rendered, address verified, address ruled)
        RegistryProcessor(owner, stored, rendered, verified, ruled) {}

    function initialKeys(IChainRegistry.KeyInput[] memory keys) external pure returns (RegistryJson.Key[] memory) {
        return initial(keys);
    }

    function insertKey(RegistryJson.Key[] memory keys, IChainRegistry.KeyInput memory entry)
        external pure returns (RegistryJson.Key[] memory) {
        return inserted(keys, entry);
    }

    function sameBytes(bytes memory first, bytes memory second) external pure returns (bool) {
        return equalBytes(first, second);
    }

    function sameText(string memory first, string memory second) external pure returns (bool) {
        return equal(first, second);
    }

    function beforeText(string memory first, string memory second) external pure returns (bool) {
        return less(first, second);
    }
}
