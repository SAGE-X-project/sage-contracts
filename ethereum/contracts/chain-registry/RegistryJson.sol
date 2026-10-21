// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {IChainRegistry} from "./IChainRegistry.sol";
import {RegistryText} from "./RegistryText.sol";
import {RegistryBuffer} from "./RegistryBuffer.sol";

/// @notice Exact bounded ASCII Registry schema construction from trusted typed state.
/// @dev Does not parse external JSON or authorize, prove or admit any state.
library RegistryJson {
    using RegistryBuffer for RegistryBuffer.Sink;

    enum KeyState { Accepted, Revoked }
    enum RecordState { Created, Active, Deactivated }
    enum Operation {
        Create, Activate, AddKey, RevokeKey, UpdateServices, AuthorizeOperator, RevokeOperator, Deactivate
    }

    struct Key {
        IChainRegistry.KeyInput input;
        KeyState state;
    }

    struct Record {
        string did;
        address controller;
        Key[] keys;
        IChainRegistry.ServiceInput[] services;
        RecordState state;
        uint64 version;
    }

    struct Grant {
        address operator;
        string scope;
    }

    /// @dev Only members belonging to operation are serialized. The Registry derives
    /// this trusted structure from the accepted function and its exact arguments.
    struct Command {
        address actor;
        Operation operation;
        string registry;
        string did;
        uint64 expectedVersion;
        address controller;
        IChainRegistry.KeyInput[] keys;
        IChainRegistry.ServiceInput[] services;
        bytes32 salt;
        IChainRegistry.KeyInput key;
        string name;
        address operator;
        string scope;
    }

    struct History {
        address actor;
        uint64 admitted;
        Operation operation;
        uint64 previousVersion;
        uint64 version;
        bytes32 commandDigest;
        bytes32 recordDigest;
        bytes32 grantsDigest;
        Grant target;
        Grant[] automaticRemovals;
    }

    function record(Record memory value) internal pure returns (bytes memory) {
        return encodeRecord(value, value.state, value.version);
    }

    /// @dev Temporary size-only bytes are neither returned nor hashed or stored.
    function checkHeadroom(Record memory value) internal pure {
        if (value.state != RecordState.Deactivated) {
            encodeRecord(value, RecordState.Deactivated, type(uint64).max);
        }
    }

    function encodeRecord(Record memory value, RecordState state, uint64 version) private pure returns (bytes memory) {
        if (version == 0) revert IChainRegistry.InvalidEntry();
        RegistryBuffer.Sink memory out = RegistryBuffer.create(65536);
        out.append(bytes('{"controller":'));
        addressValue(out, value.controller);
        out.append(bytes(',"id":'));
        quoted(out, value.did);
        out.append(bytes(',"keys":'));
        keys(out, value.keys);
        out.append(bytes(',"services":'));
        services(out, value.services);
        out.append(bytes(',"state":'));
        quoted(out, recordState(state));
        out.append(bytes(',"version":'));
        versionValue(out, version);
        out.append(bytes('}'));
        return out.finish();
    }

    function claim(
        string memory registry,
        string memory agentId,
        address controller,
        IChainRegistry.KeyInput[] memory entries,
        IChainRegistry.ServiceInput[] memory endpoints,
        bytes32 salt
    ) internal pure returns (bytes memory) {
        RegistryBuffer.Sink memory out = RegistryBuffer.create(262144);
        out.append(bytes('{"agentId":'));
        quoted(out, agentId);
        out.append(bytes(',"controller":'));
        addressValue(out, controller);
        out.append(bytes(',"keys":'));
        initialKeys(out, entries);
        out.append(bytes(',"registryId":'));
        quoted(out, registry);
        out.append(bytes(',"salt":'));
        binaryValue(out, abi.encodePacked(salt));
        out.append(bytes(',"services":'));
        services(out, endpoints);
        out.append(bytes('}'));
        return out.finish();
    }

    function grants(Grant[] memory entries) internal pure returns (bytes memory) {
        RegistryBuffer.Sink memory out = RegistryBuffer.create(262144);
        grantArray(out, entries);
        return out.finish();
    }

    function command(Command memory value) internal pure returns (bytes memory) {
        if ((value.operation == Operation.Create) != (value.expectedVersion == 0)) {
            revert IChainRegistry.InvalidEntry();
        }
        RegistryBuffer.Sink memory out = RegistryBuffer.create(262144);
        out.append(bytes('{"actor":'));
        addressValue(out, value.actor);
        out.append(bytes(',"arguments":'));
        arguments(out, value);
        out.append(bytes(',"binding":"sage-registry-chain-0.11.0","did":'));
        quoted(out, value.did);
        out.append(bytes(',"expectedVersion":'));
        if (value.expectedVersion == 0) out.append(bytes('""'));
        else versionValue(out, value.expectedVersion);
        out.append(bytes(',"operation":'));
        quoted(out, operation(value.operation));
        out.append(bytes(',"registry":'));
        quoted(out, value.registry);
        out.append(bytes('}'));
        return out.finish();
    }

    function history(History memory value) internal pure returns (bytes memory) {
        if (value.admitted > 9007199254740991) revert IChainRegistry.TimeInvalid();
        if (value.previousVersion == type(uint64).max || value.version != value.previousVersion + 1) {
            revert IChainRegistry.InvalidEntry();
        }
        if ((value.operation == Operation.Create) != (value.previousVersion == 0)) {
            revert IChainRegistry.InvalidEntry();
        }
        RegistryBuffer.Sink memory out = RegistryBuffer.create(262144);
        out.append(bytes('{"actor":'));
        addressValue(out, value.actor);
        out.append(bytes(',"admitted":'));
        out.append(RegistryText.decimal(value.admitted));
        out.append(bytes(',"automaticRemovals":'));
        grantArray(out, value.automaticRemovals);
        out.append(bytes(',"commandDigest":'));
        binaryValue(out, abi.encodePacked(value.commandDigest));
        out.append(bytes(',"grantsDigest":'));
        binaryValue(out, abi.encodePacked(value.grantsDigest));
        out.append(bytes(',"operation":'));
        quoted(out, operation(value.operation));
        out.append(bytes(',"previousVersion":'));
        if (value.previousVersion == 0) out.append(bytes('""'));
        else versionValue(out, value.previousVersion);
        out.append(bytes(',"recordDigest":'));
        binaryValue(out, abi.encodePacked(value.recordDigest));
        out.append(bytes(',"target":'));
        if (value.operation == Operation.AuthorizeOperator || value.operation == Operation.RevokeOperator) {
            grant(out, value.target);
        } else out.append(bytes('null'));
        out.append(bytes(',"version":'));
        versionValue(out, value.version);
        out.append(bytes('}'));
        return out.finish();
    }

    function arguments(RegistryBuffer.Sink memory out, Command memory value) private pure {
        out.append(bytes('{'));
        if (value.operation == Operation.Create) {
            out.append(bytes('"controller":'));
            addressValue(out, value.controller);
            out.append(bytes(',"keys":'));
            initialKeys(out, value.keys);
            out.append(bytes(',"salt":'));
            binaryValue(out, abi.encodePacked(value.salt));
            out.append(bytes(',"services":'));
            services(out, value.services);
        } else if (value.operation == Operation.AddKey) {
            out.append(bytes('"key":'));
            key(out, value.key, KeyState.Accepted);
        } else if (value.operation == Operation.RevokeKey) {
            out.append(bytes('"name":'));
            quoted(out, value.name);
        } else if (value.operation == Operation.UpdateServices) {
            out.append(bytes('"services":'));
            services(out, value.services);
        } else if (value.operation == Operation.AuthorizeOperator || value.operation == Operation.RevokeOperator) {
            out.append(bytes('"operator":'));
            addressValue(out, value.operator);
            out.append(bytes(',"scope":'));
            quoted(out, value.scope);
        }
        out.append(bytes('}'));
    }

    function keys(RegistryBuffer.Sink memory out, Key[] memory entries) private pure {
        if (entries.length > 128) revert IChainRegistry.BoundsExceeded();
        out.append(bytes('['));
        for (uint256 i; i < entries.length; ++i) {
            if (i != 0) out.append(bytes(','));
            key(out, entries[i].input, entries[i].state);
        }
        out.append(bytes(']'));
    }

    function initialKeys(RegistryBuffer.Sink memory out, IChainRegistry.KeyInput[] memory entries) private pure {
        if (entries.length > 128) revert IChainRegistry.BoundsExceeded();
        out.append(bytes('['));
        for (uint256 i; i < entries.length; ++i) {
            if (i != 0) out.append(bytes(','));
            key(out, entries[i], KeyState.Accepted);
        }
        out.append(bytes(']'));
    }

    function key(RegistryBuffer.Sink memory out, IChainRegistry.KeyInput memory entry, KeyState state) private pure {
        out.append(bytes('{"alg":'));
        quoted(out, entry.alg);
        if (entry.hasExpiry) {
            if (entry.expires > 9007199254740991) revert IChainRegistry.TimeInvalid();
            out.append(bytes(',"expires":'));
            out.append(RegistryText.decimal(entry.expires));
        } else if (entry.expires != 0) revert IChainRegistry.InvalidEntry();
        out.append(bytes(',"key":'));
        binaryValue(out, entry.key);
        out.append(bytes(',"name":'));
        quoted(out, entry.name);
        out.append(bytes(',"proof":{"signer":'));
        quoted(out, entry.signer);
        out.append(bytes(',"value":'));
        binaryValue(out, entry.proof);
        out.append(bytes('},"state":'));
        quoted(out, state == KeyState.Accepted ? "accepted" : "revoked");
        out.append(bytes('}'));
    }

    function services(RegistryBuffer.Sink memory out, IChainRegistry.ServiceInput[] memory entries) private pure {
        if (entries.length > 16) revert IChainRegistry.BoundsExceeded();
        out.append(bytes('['));
        for (uint256 i; i < entries.length; ++i) {
            if (i != 0) out.append(bytes(','));
            out.append(bytes('{"name":'));
            quoted(out, entries[i].name);
            out.append(bytes(',"type":'));
            quoted(out, entries[i].serviceType);
            out.append(bytes(',"uri":'));
            quoted(out, entries[i].uri);
            out.append(bytes('}'));
        }
        out.append(bytes(']'));
    }

    function grantArray(RegistryBuffer.Sink memory out, Grant[] memory entries) private pure {
        if (entries.length > 128) revert IChainRegistry.BoundsExceeded();
        out.append(bytes('['));
        for (uint256 i; i < entries.length; ++i) {
            if (i != 0) out.append(bytes(','));
            grant(out, entries[i]);
        }
        out.append(bytes(']'));
    }

    function grant(RegistryBuffer.Sink memory out, Grant memory entry) private pure {
        out.append(bytes('{"operator":'));
        addressValue(out, entry.operator);
        out.append(bytes(',"scope":'));
        quoted(out, entry.scope);
        out.append(bytes('}'));
    }

    function quoted(RegistryBuffer.Sink memory out, string memory value) private pure {
        out.append(RegistryText.quote(bytes(value)));
    }

    function binaryValue(RegistryBuffer.Sink memory out, bytes memory value) private pure {
        out.append(bytes('"'));
        out.append(RegistryText.base64url(value));
        out.append(bytes('"'));
    }

    function addressValue(RegistryBuffer.Sink memory out, address value) private pure {
        out.append(bytes('"'));
        out.append(RegistryText.addressText(value));
        out.append(bytes('"'));
    }

    function versionValue(RegistryBuffer.Sink memory out, uint64 value) private pure {
        out.append(bytes('"'));
        out.append(RegistryText.decimal(value));
        out.append(bytes('"'));
    }

    function recordState(RecordState value) private pure returns (string memory) {
        if (value == RecordState.Created) return "created";
        if (value == RecordState.Active) return "active";
        return "deactivated";
    }

    function operation(Operation value) private pure returns (string memory) {
        if (value == Operation.Create) return "create";
        if (value == Operation.Activate) return "activate";
        if (value == Operation.AddKey) return "add-key";
        if (value == Operation.RevokeKey) return "revoke-key";
        if (value == Operation.UpdateServices) return "update-services";
        if (value == Operation.AuthorizeOperator) return "authorize-operator";
        if (value == Operation.RevokeOperator) return "revoke-operator";
        return "deactivate";
    }
}
