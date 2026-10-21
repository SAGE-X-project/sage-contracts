// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {IChainRegistry} from "./IChainRegistry.sol";
import {RegistryProcessor} from "./RegistryProcessor.sol";
import {RegistryJson} from "./RegistryJson.sol";
import {RegistryState} from "./RegistryState.sol";

contract RegistryLifecycleProcessor is RegistryProcessor {
    constructor(
        address owner,
        address stored,
        address rendered,
        address verified,
        address ruled
    ) RegistryProcessor(owner, stored, rendered, verified, ruled) {}

    function prepare(address actor, bytes calldata command) external view returns (bytes memory) {
        owner();
        if (command.length > 148804 || command.length < 4) revert IChainRegistry.WrongRegistryContext();
        bytes4 selector = bytes4(command[:4]);
        if (selector == IChainRegistry.activate.selector) {
            (string memory agentId, uint64 version) = abi.decode(command[4:], (string, uint64));
            return activate(agentId, version, actor);
        }
        if (selector == IChainRegistry.deactivate.selector) {
            (string memory agentId, uint64 version) = abi.decode(command[4:], (string, uint64));
            return deactivate(agentId, version, actor);
        }
        if (selector == IChainRegistry.authorizeOperator.selector) {
            (string memory agentId, uint64 version, address operator, string memory scope) = abi.decode(
                command[4:],
                (string, uint64, address, string)
            );
            return authorizeOperator(agentId, version, operator, scope, actor);
        }
        if (selector == IChainRegistry.revokeOperator.selector) {
            (string memory agentId, uint64 version, address operator, string memory scope) = abi.decode(
                command[4:],
                (string, uint64, address, string)
            );
            return revokeOperator(agentId, version, operator, scope, actor);
        }
        revert IChainRegistry.WrongRegistryContext();
    }

    function activate(
        string memory agentId,
        uint64 expectedVersion,
        address actor
    ) private view returns (bytes memory) {
        _name(agentId, true);
        RegistryState.Snapshot memory next = authorizedMutation(
            agentId,
            expectedVersion,
            RegistryJson.Operation.Activate,
            actor
        );
        bytes memory prospective = prospectiveRecord(next.value);
        if (!_usable(next.value.keys, next.admitted)) revert IChainRegistry.InvalidEntry();
        RegistryJson.Grant[] memory removed;
        (next.grants, removed) = _cleanup(next.grants, true, false);
        return
            finish(
                next,
                baseCommand(next, RegistryJson.Operation.Activate, expectedVersion, actor),
                prospective,
                removed,
                bytes32(0),
                false
            );
    }

    function deactivate(
        string memory agentId,
        uint64 expectedVersion,
        address actor
    ) private view returns (bytes memory) {
        _name(agentId, true);
        RegistryState.Snapshot memory next = authorizedMutation(
            agentId,
            expectedVersion,
            RegistryJson.Operation.Deactivate,
            actor
        );
        bytes memory prospective = prospectiveRecord(next.value);
        RegistryJson.Grant[] memory removed;
        (next.grants, removed) = _cleanup(next.grants, false, true);
        return
            finish(
                next,
                baseCommand(next, RegistryJson.Operation.Deactivate, expectedVersion, actor),
                prospective,
                removed,
                bytes32(0),
                false
            );
    }

    function authorizeOperator(
        string memory agentId,
        uint64 expectedVersion,
        address operator,
        string memory scope,
        address actor
    ) private view returns (bytes memory) {
        RegistryState.Snapshot memory next = grantMutation(
            agentId,
            expectedVersion,
            scope,
            RegistryJson.Operation.AuthorizeOperator,
            actor
        );
        next.grants = _authorizeGrant(next, operator, scope);
        bytes memory prospective = prospectiveRecord(next.value);
        RegistryJson.Command memory command = baseCommand(
            next,
            RegistryJson.Operation.AuthorizeOperator,
            expectedVersion,
            actor
        );
        command.operator = operator;
        command.scope = scope;
        return finish(next, command, prospective, new RegistryJson.Grant[](0), bytes32(0), false);
    }

    function revokeOperator(
        string memory agentId,
        uint64 expectedVersion,
        address operator,
        string memory scope,
        address actor
    ) private view returns (bytes memory) {
        RegistryState.Snapshot memory next = grantMutation(
            agentId,
            expectedVersion,
            scope,
            RegistryJson.Operation.RevokeOperator,
            actor
        );
        next.grants = _revokeGrant(next, operator, scope);
        bytes memory prospective = prospectiveRecord(next.value);
        RegistryJson.Command memory command = baseCommand(
            next,
            RegistryJson.Operation.RevokeOperator,
            expectedVersion,
            actor
        );
        command.operator = operator;
        command.scope = scope;
        return finish(next, command, prospective, new RegistryJson.Grant[](0), bytes32(0), false);
    }
}
