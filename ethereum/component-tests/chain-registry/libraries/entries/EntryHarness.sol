// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {IChainRegistry} from "ethereum/contracts/chain-registry/IChainRegistry.sol";
import {RegistryJson} from "ethereum/contracts/chain-registry/RegistryJson.sol";
import {RegistryEntries} from "ethereum/contracts/chain-registry/RegistryEntries.sol";

/// @dev Pure structural unit fragments only. No cryptographic or management API.
contract EntryHarness {
    function keyScalars(IChainRegistry.KeyInput memory entry) external pure returns (bytes memory) {
        RegistryEntries.keyScalars(entry);
        return hex"01";
    }
    function serviceScalars(IChainRegistry.ServiceInput[] memory services) external pure returns (bytes memory) {
        RegistryEntries.serviceScalars(services);
        return hex"01";
    }
    function createTargets(RegistryJson.Record memory value, uint64 admitted) external pure returns (bytes memory) {
        RegistryEntries.createTargets(value, admitted);
        return hex"01";
    }
    function addTargets(RegistryJson.Record memory value, IChainRegistry.KeyInput memory entry, uint64 admitted)
        external pure returns (bytes memory)
    {
        RegistryEntries.addTargets(value, entry, admitted);
        return hex"01";
    }
    function serviceTargets(IChainRegistry.ServiceInput[] memory services, RegistryJson.Key[] memory keys)
        external pure returns (bytes memory)
    {
        RegistryEntries.serviceTargets(services, keys);
        return hex"01";
    }
    function eligible(RegistryJson.Key memory key, uint64 admitted) external pure returns (bytes memory) {
        return abi.encode(RegistryEntries.eligible(key, admitted));
    }
    function usable(RegistryJson.Key[] memory keys, uint64 admitted) external pure returns (bytes memory) {
        return abi.encode(RegistryEntries.usable(keys, admitted));
    }
}
