// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {IChainRegistry} from "./IChainRegistry.sol";
import {RegistryFraming} from "./RegistryFraming.sol";

/// @notice Candidate stateless canonical-call checker, not a Registry service.
/// @dev Matching input selectors only. No operation executes or returns a
/// Registry reply. The Registry uses an immutable hash-bound STATICCALL target.
contract RegistryCallValidator {
    fallback() external payable {
        if (msg.data.length > 148804) revert IChainRegistry.BoundsExceeded();
        revert IChainRegistry.MalformedCall();
    }

    function commitClaim(bytes32 commitment) external pure {
        RegistryFraming.check(msg.data);
        canonical(abi.encodeWithSelector(msg.sig, commitment));
    }

    function revealClaim(
        string calldata agentId,
        address controller,
        IChainRegistry.KeyInput[] calldata keys,
        IChainRegistry.ServiceInput[] calldata services,
        bytes32 salt
    ) external pure {
        RegistryFraming.check(msg.data);
        canonical(abi.encodeWithSelector(msg.sig, agentId, controller, keys, services, salt));
    }

    function activate(string calldata agentId, uint64 expectedVersion) external pure {
        RegistryFraming.check(msg.data);
        canonical(abi.encodeWithSelector(msg.sig, agentId, expectedVersion));
    }

    function deactivate(string calldata agentId, uint64 expectedVersion) external pure {
        RegistryFraming.check(msg.data);
        canonical(abi.encodeWithSelector(msg.sig, agentId, expectedVersion));
    }

    function addKey(
        string calldata agentId,
        uint64 expectedVersion,
        IChainRegistry.KeyInput calldata entry
    ) external pure {
        RegistryFraming.check(msg.data);
        canonical(abi.encodeWithSelector(msg.sig, agentId, expectedVersion, entry));
    }

    function revokeKey(string calldata agentId, uint64 expectedVersion, string calldata name) external pure {
        RegistryFraming.check(msg.data);
        canonical(abi.encodeWithSelector(msg.sig, agentId, expectedVersion, name));
    }

    function updateServices(
        string calldata agentId,
        uint64 expectedVersion,
        IChainRegistry.ServiceInput[] calldata services
    ) external pure {
        RegistryFraming.check(msg.data);
        canonical(abi.encodeWithSelector(msg.sig, agentId, expectedVersion, services));
    }

    function authorizeOperator(
        string calldata agentId,
        uint64 expectedVersion,
        address operator,
        string calldata scope
    ) external pure {
        RegistryFraming.check(msg.data);
        canonical(abi.encodeWithSelector(msg.sig, agentId, expectedVersion, operator, scope));
    }

    function revokeOperator(
        string calldata agentId,
        uint64 expectedVersion,
        address operator,
        string calldata scope
    ) external pure {
        RegistryFraming.check(msg.data);
        canonical(abi.encodeWithSelector(msg.sig, agentId, expectedVersion, operator, scope));
    }

    function registryId() external pure {
        RegistryFraming.check(msg.data);
        canonical(abi.encodeWithSelector(msg.sig));
    }

    function record(string calldata agentId) external pure {
        RegistryFraming.check(msg.data);
        canonical(abi.encodeWithSelector(msg.sig, agentId));
    }

    function activeGrants(string calldata agentId) external pure {
        RegistryFraming.check(msg.data);
        canonical(abi.encodeWithSelector(msg.sig, agentId));
    }

    function historyItem(string calldata agentId, uint64 version) external pure {
        RegistryFraming.check(msg.data);
        canonical(abi.encodeWithSelector(msg.sig, agentId, version));
    }

    function canonical(bytes memory encoded) private pure {
        if (msg.data.length != encoded.length) revert IChainRegistry.MalformedCall();
        uint256 position;
        bool same;
        for (; position + 32 <= encoded.length; position += 32) {
            assembly ("memory-safe") {
                same := eq(calldataload(position), mload(add(add(encoded, 32), position)))
            }
            if (!same) revert IChainRegistry.MalformedCall();
        }
        if (position < encoded.length) {
            uint256 mask = type(uint256).max << ((32 - (encoded.length - position)) * 8);
            assembly ("memory-safe") {
                same := eq(and(calldataload(position), mask), and(mload(add(add(encoded, 32), position)), mask))
            }
            if (!same) revert IChainRegistry.MalformedCall();
        }
    }
}
