// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {IChainRegistry} from "./IChainRegistry.sol";
import {RegistryJson} from "./RegistryJson.sol";

/// @notice Prospective in-memory lifecycle/grant helpers for the Registry.
/// @dev Not an external authority boundary. The Registry must first authenticate
/// its own msg.sender and coherent stored identity/history, and commit only after
/// all target/proof/successor checks. These helpers never write storage or emit.
library RegistryState {
    struct Snapshot {
        RegistryJson.Record value;
        RegistryJson.Grant[] grants;
        uint64 admitted;
    }

    function authorized(Snapshot memory current, address actor, RegistryJson.Operation operation)
        internal pure returns (bool)
    {
        if (operation == RegistryJson.Operation.Create) return false;
        if (actor == current.value.controller) return true;
        if (operation == RegistryJson.Operation.AuthorizeOperator ||
            operation == RegistryJson.Operation.RevokeOperator) return false;
        if (operation == RegistryJson.Operation.RevokeKey && current.value.state != RegistryJson.RecordState.Active) {
            return false;
        }
        string memory required = scope(operation);
        for (uint256 i; i < current.grants.length; ++i) {
            if (current.grants[i].operator == actor && equal(current.grants[i].scope, required)) return true;
        }
        return false;
    }

    /// @dev Call after rank5 authorization. Produces memory only; target/proof,
    /// usable-key cleanup, exact serialization and atomic persistence follow.
    function advance(
        Snapshot memory current, RegistryJson.Operation operation, uint64 expectedVersion, uint256 nowValue
    ) internal pure
    {
        RegistryJson.RecordState state = current.value.state;
        if (current.value.version == 0 || operation == RegistryJson.Operation.Create ||
            state == RegistryJson.RecordState.Deactivated ||
            (operation == RegistryJson.Operation.Activate && state != RegistryJson.RecordState.Created) ||
            ((operation == RegistryJson.Operation.AddKey || operation == RegistryJson.Operation.UpdateServices) &&
                state != RegistryJson.RecordState.Active)) revert IChainRegistry.WrongRecordState();
        if (expectedVersion != current.value.version) revert IChainRegistry.PreviousVersionMismatch();
        if (current.value.version == type(uint64).max) revert IChainRegistry.VersionExhausted();
        if (nowValue > 9007199254740991 || nowValue < current.admitted) revert IChainRegistry.TimeInvalid();
        ++current.value.version;
        current.admitted = uint64(nowValue);
        if (operation == RegistryJson.Operation.Activate) current.value.state = RegistryJson.RecordState.Active;
        else if (operation == RegistryJson.Operation.Deactivate)
            current.value.state = RegistryJson.RecordState.Deactivated;
    }

    function authorizeGrant(Snapshot memory current, address operator, string memory requested)
        internal pure returns (RegistryJson.Grant[] memory next)
    {
        if (operator == current.value.controller || !allowedScope(current.value.state, requested)) {
            revert IChainRegistry.InvalidEntry();
        }
        for (uint256 i; i < current.grants.length; ++i) {
            if (current.grants[i].operator == operator && equal(current.grants[i].scope, requested)) {
                revert IChainRegistry.GrantAlreadyPresent();
            }
        }
        if (current.grants.length >= 128) revert IChainRegistry.BoundsExceeded();
        RegistryJson.Grant memory entry = RegistryJson.Grant(operator, requested);
        next = new RegistryJson.Grant[](current.grants.length + 1);
        uint256 position;
        while (position < current.grants.length && grantCompare(current.grants[position], entry) < 0) {
            next[position] = current.grants[position];
            ++position;
        }
        next[position] = entry;
        for (uint256 i = position; i < current.grants.length; ++i) next[i + 1] = current.grants[i];
    }

    function revokeGrant(Snapshot memory current, address operator, string memory requested)
        internal pure returns (RegistryJson.Grant[] memory next)
    {
        if (operator == current.value.controller) revert IChainRegistry.InvalidEntry();
        uint256 found = current.grants.length;
        for (uint256 i; i < current.grants.length; ++i) {
            if (current.grants[i].operator == operator && equal(current.grants[i].scope, requested)) {
                found = i;
                break;
            }
        }
        if (found == current.grants.length) revert IChainRegistry.GrantUnavailable();
        next = new RegistryJson.Grant[](current.grants.length - 1);
        uint256 cursor;
        for (uint256 i; i < current.grants.length; ++i) if (i != found) next[cursor++] = current.grants[i];
    }

    /// @dev Stable partition of an already canonical grant list. Explicit revoke
    /// does not use this helper and must not duplicate itself as automatic removal.
    function cleanup(RegistryJson.Grant[] memory grants, bool activation, bool terminal)
        internal pure returns (RegistryJson.Grant[] memory retained, RegistryJson.Grant[] memory removed)
    {
        uint256 removals;
        for (uint256 i; i < grants.length; ++i) {
            if (terminal || (activation && equal(grants[i].scope, "activate"))) ++removals;
        }
        retained = new RegistryJson.Grant[](grants.length - removals);
        removed = new RegistryJson.Grant[](removals);
        uint256 keep;
        uint256 drop;
        for (uint256 i; i < grants.length; ++i) {
            if (terminal || (activation && equal(grants[i].scope, "activate"))) removed[drop++] = grants[i];
            else retained[keep++] = grants[i];
        }
    }

    function allowedScope(RegistryJson.RecordState state, string memory requested) internal pure returns (bool) {
        if (state == RegistryJson.RecordState.Created)
            return equal(requested, "activate") || equal(requested, "deactivate");
        if (state == RegistryJson.RecordState.Active) {
            return equal(requested, "add-key") || equal(requested, "revoke-key") ||
                equal(requested, "update-services") || equal(requested, "deactivate");
        }
        return false;
    }

    function scope(RegistryJson.Operation operation) private pure returns (string memory) {
        if (operation == RegistryJson.Operation.Activate) return "activate";
        if (operation == RegistryJson.Operation.AddKey) return "add-key";
        if (operation == RegistryJson.Operation.RevokeKey) return "revoke-key";
        if (operation == RegistryJson.Operation.UpdateServices) return "update-services";
        if (operation == RegistryJson.Operation.Deactivate) return "deactivate";
        return "";
    }

    function grantCompare(RegistryJson.Grant memory first, RegistryJson.Grant memory second)
        private pure returns (int256)
    {
        if (uint160(first.operator) < uint160(second.operator)) return -1;
        if (uint160(first.operator) > uint160(second.operator)) return 1;
        bytes memory a = bytes(first.scope);
        bytes memory b = bytes(second.scope);
        uint256 length = a.length < b.length ? a.length : b.length;
        for (uint256 i; i < length; ++i) {
            if (uint8(a[i]) < uint8(b[i])) return -1;
            if (uint8(a[i]) > uint8(b[i])) return 1;
        }
        if (a.length < b.length) return -1;
        if (a.length > b.length) return 1;
        return 0;
    }

    function equal(string memory first, string memory second) private pure returns (bool) {
        bytes memory a = bytes(first);
        bytes memory b = bytes(second);
        if (a.length != b.length) return false;
        for (uint256 i; i < a.length; ++i) if (a[i] != b[i]) return false;
        return true;
    }
}
