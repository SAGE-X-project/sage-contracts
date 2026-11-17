// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {IChainRegistry} from "./IChainRegistry.sol";
import {RegistryProcessor} from "./RegistryProcessor.sol";
import {RegistryJson} from "./RegistryJson.sol";
import {RegistryState} from "./RegistryState.sol";

contract RegistryKeyServiceProcessor is RegistryProcessor {
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
        if (selector == IChainRegistry.addKey.selector) {
            (string memory agentId, uint64 version, IChainRegistry.KeyInput memory entry) = abi.decode(
                command[4:],
                (string, uint64, IChainRegistry.KeyInput)
            );
            return addKey(agentId, version, entry, actor);
        }
        if (selector == IChainRegistry.revokeKey.selector) {
            (string memory agentId, uint64 version, string memory name) = abi.decode(
                command[4:],
                (string, uint64, string)
            );
            return revokeKey(agentId, version, name, actor);
        }
        if (selector == IChainRegistry.updateServices.selector) {
            (string memory agentId, uint64 version, IChainRegistry.ServiceInput[] memory services) = abi.decode(
                command[4:],
                (string, uint64, IChainRegistry.ServiceInput[])
            );
            return updateServices(agentId, version, services, actor);
        }
        revert IChainRegistry.WrongRegistryContext();
    }

    function addKey(
        string memory agentId,
        uint64 expectedVersion,
        IChainRegistry.KeyInput memory entry,
        address actor
    ) private view returns (bytes memory) {
        _name(agentId, true);
        _keyScalars(entry);
        RegistryState.Snapshot memory next = authorizedMutation(
            agentId,
            expectedVersion,
            RegistryJson.Operation.AddKey,
            actor
        );
        _addTargets(next.value, entry, next.admitted);
        next.value.keys = inserted(next.value.keys, entry);
        bytes memory prospective = prospectiveRecord(next.value);
        proof(agentId, entry, next.value.keys);
        RegistryJson.Command memory command = baseCommand(next, RegistryJson.Operation.AddKey, expectedVersion, actor);
        command.key = entry;
        return finish(next, command, prospective, new RegistryJson.Grant[](0), bytes32(0), false);
    }

    function revokeKey(
        string memory agentId,
        uint64 expectedVersion,
        string memory name,
        address actor
    ) private view returns (bytes memory) {
        _name(agentId, true);
        _name(name, false);
        RegistryState.Snapshot memory next = authorizedMutation(
            agentId,
            expectedVersion,
            RegistryJson.Operation.RevokeKey,
            actor
        );
        bool found;
        for (uint256 i; i < next.value.keys.length; ++i) {
            if (equal(next.value.keys[i].input.name, name)) {
                if (next.value.keys[i].state != RegistryJson.KeyState.Accepted) revert IChainRegistry.KeyUnavailable();
                next.value.keys[i].state = RegistryJson.KeyState.Revoked;
                found = true;
                break;
            }
        }
        if (!found) revert IChainRegistry.KeyUnavailable();
        bool terminal = !_usable(next.value.keys, next.admitted);
        if (terminal) next.value.state = RegistryJson.RecordState.Deactivated;
        bytes memory prospective = prospectiveRecord(next.value);
        RegistryJson.Grant[] memory removed;
        (next.grants, removed) = _cleanup(next.grants, false, terminal);
        RegistryJson.Command memory command = baseCommand(
            next,
            RegistryJson.Operation.RevokeKey,
            expectedVersion,
            actor
        );
        command.name = name;
        return finish(next, command, prospective, removed, bytes32(0), false);
    }

    function updateServices(
        string memory agentId,
        uint64 expectedVersion,
        IChainRegistry.ServiceInput[] memory services,
        address actor
    ) private view returns (bytes memory) {
        _name(agentId, true);
        _serviceScalars(services);
        RegistryState.Snapshot memory next = authorizedMutation(
            agentId,
            expectedVersion,
            RegistryJson.Operation.UpdateServices,
            actor
        );
        _serviceTargets(services, next.value.keys);
        next.value.services = services;
        bytes memory prospective = prospectiveRecord(next.value);
        RegistryJson.Command memory command = baseCommand(
            next,
            RegistryJson.Operation.UpdateServices,
            expectedVersion,
            actor
        );
        command.services = services;
        return finish(next, command, prospective, new RegistryJson.Grant[](0), bytes32(0), false);
    }
}
