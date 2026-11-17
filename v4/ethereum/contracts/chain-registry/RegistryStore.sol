// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {IChainRegistry} from "./IChainRegistry.sol";
import {RegistryJson} from "./RegistryJson.sol";
import {RegistryState} from "./RegistryState.sol";
import {RegistryGrammar} from "./RegistryGrammar.sol";
import {RegistryText} from "./RegistryText.sol";
import {RegistryTransition} from "./RegistryTransition.sol";

/// @notice Candidate auxiliary storage; only its constructor-bound Core writes.
/// @dev Read views expose already-public chain state, not an alternate Registry.
contract RegistryStore {
    struct Claim {
        bool present;
        bool consumed;
        uint256 committed;
    }
    struct Retained {
        bool present;
        bytes history;
        bytes command;
    }
    struct Stored {
        bool present;
        RegistryJson.Record value;
        RegistryJson.Grant[] grants;
        uint64 admitted;
        bytes canonicalRecord;
        bytes canonicalGrants;
        mapping(uint64 => Retained) items;
    }

    address private immutable core;
    uint256 private immutable executionChain;
    address private immutable instance;
    string private identity;
    mapping(address => mapping(bytes32 => Claim)) private claims;
    mapping(string => Stored) private records;

    constructor(address owner) {
        if (owner == address(0) || block.chainid == 0 || block.chainid >= 10 ** 32) {
            revert IChainRegistry.WrongRegistryContext();
        }
        core = owner;
        executionChain = block.chainid;
        instance = address(this);
        identity = string(
            abi.encodePacked("eip155:", RegistryText.decimal(block.chainid), ":", RegistryText.addressText(owner))
        );
    }

    function binding() external view returns (address, uint256, address) {
        context();
        return (core, executionChain, instance);
    }

    function claim(address actor, bytes32 digest) external view returns (bool, bool, uint256) {
        context();
        Claim storage value = claims[actor][digest];
        return (value.present, value.consumed, value.committed);
    }

    function snapshot(string calldata agentId) external view returns (bool, bool, RegistryState.Snapshot memory value) {
        context();
        RegistryGrammar.name(agentId, true);
        Stored storage stored = records[agentId];
        value.value = stored.value;
        value.grants = stored.grants;
        value.admitted = stored.admitted;
        return (stored.present, coherent(stored), value);
    }

    function record(string calldata agentId) external view returns (bool, bytes memory) {
        context();
        RegistryGrammar.name(agentId, true);
        Stored storage stored = records[agentId];
        if (!stored.present) return (false, bytes(""));
        if (!coherent(stored)) revert IChainRegistry.HistoryUnavailable();
        return (true, stored.canonicalRecord);
    }

    function activeGrants(string calldata agentId) external view returns (bytes memory) {
        context();
        RegistryGrammar.name(agentId, true);
        Stored storage stored = existing(agentId);
        return stored.canonicalGrants;
    }

    function historyItem(string calldata agentId, uint64 version) external view returns (bytes memory, bytes memory) {
        context();
        RegistryGrammar.name(agentId, true);
        if (version == 0) revert IChainRegistry.InvalidEntry();
        Stored storage stored = existing(agentId);
        Retained storage retained = stored.items[version];
        if (
            version > stored.value.version ||
            !retained.present ||
            retained.history.length == 0 ||
            retained.command.length == 0
        ) {
            revert IChainRegistry.HistoryUnavailable();
        }
        return (retained.history, retained.command);
    }

    function commitClaim(address actor, bytes32 digest) external returns (uint256) {
        owner();
        Claim storage entry = claims[actor][digest];
        if (entry.present) revert IChainRegistry.ClaimUnavailable();
        entry.present = true;
        entry.committed = block.number;
        return block.number;
    }

    function commit(
        address actor,
        string calldata agentId,
        RegistryJson.Operation operation,
        bytes calldata encoded
    ) external returns (uint64, bytes32, bytes memory) {
        owner();
        if (encoded.length > 779424 || msg.data.length > 1048576) revert IChainRegistry.WrongRegistryContext();
        RegistryGrammar.name(agentId, true);
        RegistryTransition.Plan memory plan = abi.decode(encoded, (RegistryTransition.Plan));
        string memory expectedDid = string(abi.encodePacked("did:sage:", identity, ":", agentId));
        if (
            plan.actor != actor ||
            plan.operation != operation ||
            !RegistryTransition.equal(bytes(plan.next.value.did), bytes(expectedDid)) ||
            plan.didHash != sha256(bytes(expectedDid))
        ) revert IChainRegistry.WrongRegistryContext();
        if (
            plan.record.length == 0 ||
            plan.record.length > 65536 ||
            plan.grants.length == 0 ||
            plan.grants.length > 10753 ||
            plan.command.length == 0 ||
            plan.command.length > 262144 ||
            plan.history.length == 0 ||
            plan.history.length > 262144 ||
            plan.eventData.length > 512 ||
            plan.next.value.keys.length > 128 ||
            plan.next.value.services.length > 16 ||
            plan.next.grants.length > 128 ||
            plan.next.admitted > 9007199254740991
        ) revert IChainRegistry.WrongRegistryContext();
        Stored storage stored = records[agentId];
        if (operation == RegistryJson.Operation.Create) {
            if (
                stored.present ||
                stored.value.version != 0 ||
                plan.previousVersion != 0 ||
                plan.next.value.version != 1 ||
                !plan.consumeClaim ||
                plan.next.value.controller != actor
            ) revert IChainRegistry.WrongRegistryContext();
            Claim storage entry = claims[actor][plan.claimDigest];
            if (
                !entry.present ||
                entry.consumed ||
                block.number <= entry.committed ||
                block.number - entry.committed > 256
            ) {
                revert IChainRegistry.WrongRegistryContext();
            }
            entry.consumed = true;
        } else {
            if (
                !stored.present ||
                !coherent(stored) ||
                plan.consumeClaim ||
                plan.claimDigest != bytes32(0) ||
                plan.previousVersion != stored.value.version ||
                stored.value.version == type(uint64).max ||
                plan.next.value.version != stored.value.version + 1 ||
                plan.next.value.controller != stored.value.controller ||
                plan.next.admitted < stored.admitted
            ) revert IChainRegistry.WrongRegistryContext();
        }
        if (plan.next.admitted != block.timestamp || stored.items[plan.next.value.version].present) {
            revert IChainRegistry.WrongRegistryContext();
        }
        bytes memory expectedEvent = abi.encode(
            expectedDid,
            plan.previousVersion,
            plan.next.value.version,
            RegistryTransition.operationName(operation),
            sha256(plan.command),
            sha256(plan.record),
            sha256(plan.grants),
            plan.next.admitted
        );
        if (!RegistryTransition.equal(plan.eventData, expectedEvent)) revert IChainRegistry.WrongRegistryContext();
        persist(stored, plan.next, plan.record, plan.grants);
        stored.items[plan.next.value.version] = Retained(true, plan.history, plan.command);
        return (plan.next.value.version, plan.didHash, plan.eventData);
    }

    function context() private view {
        if (block.chainid != executionChain || address(this) != instance || msg.data.length > 1048576) {
            revert IChainRegistry.WrongRegistryContext();
        }
    }

    function owner() private view {
        context();
        if (msg.sender != core) revert IChainRegistry.UnauthorizedCaller();
    }

    function coherent(Stored storage stored) private view returns (bool) {
        uint64 version = stored.value.version;
        return
            stored.present &&
            version != 0 &&
            stored.items[version].present &&
            stored.canonicalRecord.length != 0 &&
            stored.canonicalGrants.length != 0 &&
            stored.items[version].history.length != 0 &&
            stored.items[version].command.length != 0;
    }

    function existing(string memory agentId) private view returns (Stored storage stored) {
        stored = records[agentId];
        if (!stored.present) revert IChainRegistry.WrongRecordState();
        if (!coherent(stored)) revert IChainRegistry.HistoryUnavailable();
    }

    function persist(
        Stored storage stored,
        RegistryState.Snapshot memory next,
        bytes memory encoded,
        bytes memory grants
    ) private {
        stored.present = true;
        stored.value.did = next.value.did;
        stored.value.controller = next.value.controller;
        stored.value.state = next.value.state;
        stored.value.version = next.value.version;
        delete stored.value.keys;
        for (uint256 i; i < next.value.keys.length; ++i) stored.value.keys.push(next.value.keys[i]);
        delete stored.value.services;
        for (uint256 i; i < next.value.services.length; ++i) stored.value.services.push(next.value.services[i]);
        delete stored.grants;
        for (uint256 i; i < next.grants.length; ++i) stored.grants.push(next.grants[i]);
        stored.admitted = next.admitted;
        stored.canonicalRecord = encoded;
        stored.canonicalGrants = grants;
    }
}
