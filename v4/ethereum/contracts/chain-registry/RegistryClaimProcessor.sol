// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {IChainRegistry} from "./IChainRegistry.sol";
import {RegistryProcessor} from "./RegistryProcessor.sol";
import {RegistryJson} from "./RegistryJson.sol";
import {RegistryState} from "./RegistryState.sol";
import {RegistryDomain} from "./RegistryDomain.sol";
import {RegistryRenderer} from "./RegistryRenderer.sol";
import {RegistryStore} from "./RegistryStore.sol";
import {RegistryTransport} from "./RegistryTransport.sol";

contract RegistryClaimProcessor is RegistryProcessor {
    constructor(
        address owner,
        address stored,
        address rendered,
        address verified,
        address ruled
    ) RegistryProcessor(owner, stored, rendered, verified, ruled) {}

    function prepare(address actor, bytes calldata command) external view returns (bytes memory) {
        owner();
        if (
            command.length > 148804 || command.length < 4 || bytes4(command[:4]) != IChainRegistry.revealClaim.selector
        ) {
            revert IChainRegistry.WrongRegistryContext();
        }
        (
            string memory agentId,
            address controller,
            IChainRegistry.KeyInput[] memory keys,
            IChainRegistry.ServiceInput[] memory services,
            bytes32 salt
        ) = abi.decode(
                command[4:],
                (string, address, IChainRegistry.KeyInput[], IChainRegistry.ServiceInput[], bytes32)
            );
        return reveal(agentId, controller, keys, services, salt, actor);
    }

    function reveal(
        string memory agentId,
        address controller,
        IChainRegistry.KeyInput[] memory keys,
        IChainRegistry.ServiceInput[] memory services,
        bytes32 salt,
        address actor
    ) private view returns (bytes memory) {
        _name(agentId, true);
        for (uint256 i; i < keys.length; ++i) _keyScalars(keys[i]);
        _serviceScalars(services);
        (bool present, , RegistryState.Snapshot memory current) = snapshot(agentId);
        if (present || current.value.version != 0) revert IChainRegistry.IdentifierUnavailable();
        bytes memory claimBytes = abi.decode(
            RegistryTransport.read(
                renderer,
                abi.encodeCall(RegistryRenderer.claim, (registryIdentity, agentId, controller, keys, services, salt))
            ),
            (bytes)
        );
        bytes32 digest = RegistryDomain.claimDigest(claimBytes);
        (bool committed, bool consumed, uint256 committedBlock) = abi.decode(
            RegistryTransport.read(store, abi.encodeCall(RegistryStore.claim, (actor, digest))),
            (bool, bool, uint256)
        );
        if (!committed || consumed) revert IChainRegistry.ClaimUnavailable();
        if (controller != actor) revert IChainRegistry.UnauthorizedCaller();
        if (block.number <= committedBlock || block.number - committedBlock > 256)
            revert IChainRegistry.ClaimWindowInvalid();
        RegistryState.Snapshot memory next;
        next.admitted = time(0);
        next.value = RegistryJson.Record({
            did: did(agentId),
            controller: controller,
            keys: initial(keys),
            services: services,
            state: RegistryJson.RecordState.Created,
            version: 1
        });
        next.grants = new RegistryJson.Grant[](0);
        _createTargets(next.value, next.admitted);
        bytes memory prospective = prospectiveRecord(next.value);
        for (uint256 i; i < keys.length; ++i) if (signing(keys[i].alg)) proof(agentId, keys[i], next.value.keys);
        for (uint256 i; i < keys.length; ++i) if (!signing(keys[i].alg)) proof(agentId, keys[i], next.value.keys);
        if (!_usable(next.value.keys, next.admitted)) revert IChainRegistry.InvalidEntry();
        RegistryJson.Command memory command = baseCommand(next, RegistryJson.Operation.Create, 0, actor);
        command.controller = controller;
        command.keys = keys;
        command.services = services;
        command.salt = salt;
        return finish(next, command, prospective, new RegistryJson.Grant[](0), digest, true);
    }
}
