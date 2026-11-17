// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {RegistryState} from "./RegistryState.sol";
import {RegistryJson} from "./RegistryJson.sol";

/// @dev Internal transport only. Not a new Registry input or history format.
library RegistryTransition {
    struct Plan {
        RegistryState.Snapshot next;
        bytes record;
        bytes grants;
        bytes command;
        bytes history;
        bytes eventData;
        bytes32 claimDigest;
        bool consumeClaim;
        uint64 previousVersion;
        RegistryJson.Operation operation;
        bytes32 didHash;
        address actor;
    }

    function operationName(RegistryJson.Operation value) internal pure returns (string memory) {
        if (value == RegistryJson.Operation.Create) return "create";
        if (value == RegistryJson.Operation.Activate) return "activate";
        if (value == RegistryJson.Operation.AddKey) return "add-key";
        if (value == RegistryJson.Operation.RevokeKey) return "revoke-key";
        if (value == RegistryJson.Operation.UpdateServices) return "update-services";
        if (value == RegistryJson.Operation.AuthorizeOperator) return "authorize-operator";
        if (value == RegistryJson.Operation.RevokeOperator) return "revoke-operator";
        return "deactivate";
    }

    function equal(bytes memory a, bytes memory b) internal pure returns (bool) {
        if (a.length != b.length) return false;
        for (uint256 i; i < a.length; ++i) if (a[i] != b[i]) return false;
        return true;
    }
}
