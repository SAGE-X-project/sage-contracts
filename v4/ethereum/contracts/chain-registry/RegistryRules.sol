// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {IChainRegistry} from "./IChainRegistry.sol";
import {RegistryJson} from "./RegistryJson.sol";
import {RegistryState} from "./RegistryState.sol";
import {RegistryGrammar} from "./RegistryGrammar.sol";
import {RegistryEntries} from "./RegistryEntries.sol";

/// @notice Candidate stateless rule adapter. Never an admission authority.
/// @dev The Registry supplies its actual caller and coherent snapshot in the
/// specified order. This module has no storage, setter, callback or event.
contract RegistryRules {
    function name(string memory value, bool agent) external pure {
        RegistryGrammar.name(value, agent);
    }

    function keyScalars(IChainRegistry.KeyInput memory entry) external pure {
        RegistryEntries.keyScalars(entry);
    }

    function serviceScalars(IChainRegistry.ServiceInput[] memory entries) external pure {
        RegistryEntries.serviceScalars(entries);
    }

    function createTargets(RegistryJson.Record memory record, uint64 admitted) external pure {
        RegistryEntries.createTargets(record, admitted);
    }

    function addTargets(
        RegistryJson.Record memory record,
        IChainRegistry.KeyInput memory entry,
        uint64 admitted
    ) external pure {
        RegistryEntries.addTargets(record, entry, admitted);
    }

    function serviceTargets(
        IChainRegistry.ServiceInput[] memory entries,
        RegistryJson.Key[] memory keys
    ) external pure {
        RegistryEntries.serviceTargets(entries, keys);
    }

    function usable(RegistryJson.Key[] memory keys, uint64 admitted) external pure returns (bool) {
        return RegistryEntries.usable(keys, admitted);
    }

    function authorized(
        RegistryState.Snapshot memory current,
        address actor,
        RegistryJson.Operation operation
    ) external pure returns (bool) {
        return RegistryState.authorized(current, actor, operation);
    }

    function advance(
        RegistryState.Snapshot memory current,
        RegistryJson.Operation operation,
        uint64 expectedVersion,
        uint256 admitted
    ) external pure returns (RegistryState.Snapshot memory) {
        RegistryState.advance(current, operation, expectedVersion, admitted);
        return current;
    }

    function authorizeGrant(
        RegistryState.Snapshot memory current,
        address operator,
        string memory scope
    ) external pure returns (RegistryJson.Grant[] memory) {
        return RegistryState.authorizeGrant(current, operator, scope);
    }

    function revokeGrant(
        RegistryState.Snapshot memory current,
        address operator,
        string memory scope
    ) external pure returns (RegistryJson.Grant[] memory) {
        return RegistryState.revokeGrant(current, operator, scope);
    }

    function cleanup(
        RegistryJson.Grant[] memory grants,
        bool activation,
        bool terminal
    ) external pure returns (RegistryJson.Grant[] memory retained, RegistryJson.Grant[] memory removed) {
        return RegistryState.cleanup(grants, activation, terminal);
    }
}
