// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {IChainRegistry} from "./IChainRegistry.sol";
import {RegistryJson} from "./RegistryJson.sol";
import {RegistryState} from "./RegistryState.sol";
import {RegistryDomain} from "./RegistryDomain.sol";
import {RegistryText} from "./RegistryText.sol";
import {RegistryRenderer} from "./RegistryRenderer.sol";
import {RegistryEd25519} from "./RegistryEd25519.sol";
import {RegistryRules} from "./RegistryRules.sol";
import {RegistryStore} from "./RegistryStore.sol";
import {RegistryTransition} from "./RegistryTransition.sol";
import {RegistryTransport} from "./RegistryTransport.sol";

/// @dev Source-bound Core-only read-only preparation; no storage mutation or logs.
abstract contract RegistryProcessor {
    address internal immutable core;
    address internal immutable store;
    address internal immutable renderer;
    address internal immutable verifier;
    address internal immutable rules;
    uint256 private immutable executionChain;
    address private immutable instance;
    string internal registryIdentity;

    constructor(
        address owner,
        address storeAddress,
        address renderAddress,
        address verifyAddress,
        address ruleAddress
    ) {
        if (
            owner == address(0) ||
            storeAddress.code.length == 0 ||
            renderAddress.code.length == 0 ||
            verifyAddress.code.length == 0 ||
            ruleAddress.code.length == 0
        ) revert IChainRegistry.WrongRegistryContext();
        core = owner;
        store = storeAddress;
        renderer = renderAddress;
        verifier = verifyAddress;
        rules = ruleAddress;
        executionChain = block.chainid;
        instance = address(this);
        (address boundCore, uint256 chain, address boundStore) = abi.decode(
            RegistryTransport.read(storeAddress, abi.encodeCall(RegistryStore.binding, ())),
            (address, uint256, address)
        );
        if (boundCore != owner || chain != block.chainid || boundStore != storeAddress)
            revert IChainRegistry.WrongRegistryContext();
        registryIdentity = string(
            abi.encodePacked("eip155:", RegistryText.decimal(block.chainid), ":", RegistryText.addressText(owner))
        );
    }

    function binding() external view returns (address, address, address, address, address, uint256, address) {
        return (core, store, renderer, verifier, rules, executionChain, instance);
    }

    function owner() internal view {
        if (msg.sender != core) revert IChainRegistry.UnauthorizedCaller();
        if (block.chainid != executionChain || address(this) != instance || msg.data.length > 1048576) {
            revert IChainRegistry.WrongRegistryContext();
        }
    }

    function snapshot(
        string memory agentId
    ) internal view returns (bool present, bool coherent, RegistryState.Snapshot memory next) {
        return
            abi.decode(
                RegistryTransport.read(store, abi.encodeCall(RegistryStore.snapshot, (agentId))),
                (bool, bool, RegistryState.Snapshot)
            );
    }

    function authorizedMutation(
        string memory agentId,
        uint64 version,
        RegistryJson.Operation operation,
        address actor
    ) internal view returns (RegistryState.Snapshot memory next) {
        (bool present, bool coherent, RegistryState.Snapshot memory current) = snapshot(agentId);
        if (!present) revert IChainRegistry.WrongRecordState();
        if (!coherent) revert IChainRegistry.HistoryUnavailable();
        if (!_authorized(current, actor, operation)) revert IChainRegistry.UnauthorizedCaller();
        next = _advance(current, operation, version, block.timestamp);
    }

    function grantMutation(
        string memory agentId,
        uint64 version,
        string memory scope,
        RegistryJson.Operation operation,
        address actor
    ) internal view returns (RegistryState.Snapshot memory) {
        _name(agentId, true);
        bytes memory raw = bytes(scope);
        for (uint256 i; i < raw.length; ++i) if (uint8(raw[i]) > 127) revert IChainRegistry.InvalidEntry();
        return authorizedMutation(agentId, version, operation, actor);
    }

    function prospectiveRecord(RegistryJson.Record memory value) internal view returns (bytes memory encoded) {
        encoded = renderRecord(value);
        empty(RegistryTransport.read(renderer, abi.encodeCall(RegistryRenderer.checkHeadroom, (value))));
    }

    function renderRecord(RegistryJson.Record memory value) private view returns (bytes memory) {
        return abi.decode(RegistryTransport.read(renderer, abi.encodeCall(RegistryRenderer.record, (value))), (bytes));
    }

    function empty(bytes memory output) private pure {
        if (output.length != 0) revert IChainRegistry.WrongRegistryContext();
    }

    function time(uint64 previous) internal view returns (uint64) {
        if (block.timestamp > 9007199254740991 || block.timestamp < previous) revert IChainRegistry.TimeInvalid();
        return uint64(block.timestamp);
    }

    function did(string memory agentId) internal view returns (string memory) {
        return string(abi.encodePacked("did:sage:", registryIdentity, ":", agentId));
    }

    function initial(IChainRegistry.KeyInput[] memory keys) internal pure returns (RegistryJson.Key[] memory entries) {
        entries = new RegistryJson.Key[](keys.length);
        for (uint256 i; i < keys.length; ++i) entries[i] = RegistryJson.Key(keys[i], RegistryJson.KeyState.Accepted);
    }

    function inserted(
        RegistryJson.Key[] memory keys,
        IChainRegistry.KeyInput memory entry
    ) internal pure returns (RegistryJson.Key[] memory result) {
        result = new RegistryJson.Key[](keys.length + 1);
        uint256 position;
        while (position < keys.length && less(keys[position].input.name, entry.name)) {
            result[position] = keys[position];
            ++position;
        }
        result[position] = RegistryJson.Key(entry, RegistryJson.KeyState.Accepted);
        for (uint256 i = position; i < keys.length; ++i) result[i + 1] = keys[i];
    }

    function signing(string memory algorithm) internal pure returns (bool) {
        return equal(algorithm, "ed25519");
    }

    function equalBytes(bytes memory first, bytes memory second) internal pure returns (bool) {
        if (first.length != second.length) return false;
        uint256 position;
        bool same;
        for (; position + 32 <= first.length; position += 32) {
            assembly ("memory-safe") {
                same := eq(mload(add(add(first, 32), position)), mload(add(add(second, 32), position)))
            }
            if (!same) return false;
        }
        for (; position < first.length; ++position) if (first[position] != second[position]) return false;
        return true;
    }

    function equal(string memory first, string memory second) internal pure returns (bool) {
        bytes memory a = bytes(first);
        bytes memory b = bytes(second);
        if (a.length != b.length) return false;
        for (uint256 i; i < a.length; ++i) if (a[i] != b[i]) return false;
        return true;
    }

    function less(string memory first, string memory second) internal pure returns (bool) {
        bytes memory a = bytes(first);
        bytes memory b = bytes(second);
        uint256 length = a.length < b.length ? a.length : b.length;
        for (uint256 i; i < length; ++i) {
            if (uint8(a[i]) < uint8(b[i])) return true;
            if (uint8(a[i]) > uint8(b[i])) return false;
        }
        return a.length < b.length;
    }

    function proof(
        string memory agentId,
        IChainRegistry.KeyInput memory entry,
        RegistryJson.Key[] memory keys
    ) internal view {
        bytes memory signer;
        if (signing(entry.alg)) signer = entry.key;
        else
            for (uint256 i; i < keys.length; ++i) {
                if (equal(entry.signer, string(abi.encodePacked(did(agentId), "#", keys[i].input.name)))) {
                    signer = keys[i].input.key;
                    break;
                }
            }
        bytes memory challenge = RegistryDomain.pop(registryIdentity, agentId, entry.name, entry.alg, entry.key);
        if (
            !RegistryTransport.proof(verifier, abi.encodeCall(RegistryEd25519.verify, (signer, challenge, entry.proof)))
        ) {
            revert IChainRegistry.InvalidKeyProof();
        }
    }

    function baseCommand(
        RegistryState.Snapshot memory next,
        RegistryJson.Operation operation,
        uint64 previous,
        address actor
    ) internal view returns (RegistryJson.Command memory command) {
        command = RegistryJson.Command({
            actor: actor,
            operation: operation,
            registry: registryIdentity,
            did: next.value.did,
            expectedVersion: previous,
            controller: address(0),
            keys: new IChainRegistry.KeyInput[](0),
            services: new IChainRegistry.ServiceInput[](0),
            salt: bytes32(0),
            key: IChainRegistry.KeyInput("", "", bytes(""), "", bytes(""), false, 0),
            name: "",
            operator: address(0),
            scope: ""
        });
    }

    function finish(
        RegistryState.Snapshot memory next,
        RegistryJson.Command memory command,
        bytes memory prospective,
        RegistryJson.Grant[] memory removed,
        bytes32 digest,
        bool consume
    ) internal view returns (bytes memory) {
        RegistryTransition.Plan memory plan;
        plan.next = next;
        plan.record = renderRecord(next.value);
        if (!equalBytes(plan.record, prospective)) revert IChainRegistry.InvalidEntry();
        plan.grants = abi.decode(
            RegistryTransport.read(renderer, abi.encodeCall(RegistryRenderer.grants, (next.grants))),
            (bytes)
        );
        plan.command = abi.decode(
            RegistryTransport.read(renderer, abi.encodeCall(RegistryRenderer.command, (command))),
            (bytes)
        );
        RegistryJson.History memory item;
        item.actor = command.actor;
        item.admitted = next.admitted;
        item.operation = command.operation;
        item.previousVersion = command.expectedVersion;
        item.version = next.value.version;
        item.commandDigest = sha256(plan.command);
        item.recordDigest = sha256(plan.record);
        item.grantsDigest = sha256(plan.grants);
        item.target = RegistryJson.Grant(command.operator, command.scope);
        item.automaticRemovals = removed;
        plan.history = abi.decode(
            RegistryTransport.read(renderer, abi.encodeCall(RegistryRenderer.history, (item))),
            (bytes)
        );
        plan.eventData = abi.encode(
            next.value.did,
            item.previousVersion,
            item.version,
            RegistryTransition.operationName(command.operation),
            item.commandDigest,
            item.recordDigest,
            item.grantsDigest,
            item.admitted
        );
        plan.claimDigest = digest;
        plan.consumeClaim = consume;
        plan.previousVersion = item.previousVersion;
        plan.operation = command.operation;
        plan.didHash = sha256(bytes(next.value.did));
        plan.actor = command.actor;
        bytes memory encoded = abi.encode(plan);
        if (encoded.length > 779424 || plan.eventData.length > 512) revert IChainRegistry.WrongRegistryContext();
        return encoded;
    }

    function _name(string memory value, bool agent) internal view {
        empty(RegistryTransport.read(rules, abi.encodeCall(RegistryRules.name, (value, agent))));
    }

    function _keyScalars(IChainRegistry.KeyInput memory entry) internal view {
        empty(RegistryTransport.read(rules, abi.encodeCall(RegistryRules.keyScalars, (entry))));
    }

    function _serviceScalars(IChainRegistry.ServiceInput[] memory entries) internal view {
        empty(RegistryTransport.read(rules, abi.encodeCall(RegistryRules.serviceScalars, (entries))));
    }

    function _createTargets(RegistryJson.Record memory record, uint64 admitted) internal view {
        empty(RegistryTransport.read(rules, abi.encodeCall(RegistryRules.createTargets, (record, admitted))));
    }

    function _addTargets(
        RegistryJson.Record memory record,
        IChainRegistry.KeyInput memory entry,
        uint64 admitted
    ) internal view {
        empty(RegistryTransport.read(rules, abi.encodeCall(RegistryRules.addTargets, (record, entry, admitted))));
    }

    function _serviceTargets(
        IChainRegistry.ServiceInput[] memory entries,
        RegistryJson.Key[] memory keys
    ) internal view {
        empty(RegistryTransport.read(rules, abi.encodeCall(RegistryRules.serviceTargets, (entries, keys))));
    }

    function _usable(RegistryJson.Key[] memory keys, uint64 admitted) internal view returns (bool) {
        return
            abi.decode(RegistryTransport.read(rules, abi.encodeCall(RegistryRules.usable, (keys, admitted))), (bool));
    }

    function _authorized(
        RegistryState.Snapshot memory current,
        address actor,
        RegistryJson.Operation operation
    ) internal view returns (bool) {
        return
            abi.decode(
                RegistryTransport.read(rules, abi.encodeCall(RegistryRules.authorized, (current, actor, operation))),
                (bool)
            );
    }

    function _advance(
        RegistryState.Snapshot memory current,
        RegistryJson.Operation operation,
        uint64 version,
        uint256 admitted
    ) internal view returns (RegistryState.Snapshot memory) {
        return
            abi.decode(
                RegistryTransport.read(
                    rules,
                    abi.encodeCall(RegistryRules.advance, (current, operation, version, admitted))
                ),
                (RegistryState.Snapshot)
            );
    }

    function _authorizeGrant(
        RegistryState.Snapshot memory current,
        address operator,
        string memory scope
    ) internal view returns (RegistryJson.Grant[] memory) {
        return
            abi.decode(
                RegistryTransport.read(rules, abi.encodeCall(RegistryRules.authorizeGrant, (current, operator, scope))),
                (RegistryJson.Grant[])
            );
    }

    function _revokeGrant(
        RegistryState.Snapshot memory current,
        address operator,
        string memory scope
    ) internal view returns (RegistryJson.Grant[] memory) {
        return
            abi.decode(
                RegistryTransport.read(rules, abi.encodeCall(RegistryRules.revokeGrant, (current, operator, scope))),
                (RegistryJson.Grant[])
            );
    }

    function _cleanup(
        RegistryJson.Grant[] memory grants,
        bool activation,
        bool terminal
    ) internal view returns (RegistryJson.Grant[] memory, RegistryJson.Grant[] memory) {
        return
            abi.decode(
                RegistryTransport.read(rules, abi.encodeCall(RegistryRules.cleanup, (grants, activation, terminal))),
                (RegistryJson.Grant[], RegistryJson.Grant[])
            );
    }
}
