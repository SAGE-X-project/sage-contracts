// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {IChainRegistry} from "./IChainRegistry.sol";
import {RegistryJson} from "./RegistryJson.sol";
import {RegistryStore} from "./RegistryStore.sol";
import {RegistryProcessor} from "./RegistryProcessor.sol";
import {RegistryTransport} from "./RegistryTransport.sol";
import {RegistryRoleHashes} from "./RegistryRoleHashes.sol";
import {RegistryText} from "./RegistryText.sol";

interface IRegistryStoreFactory {
    function create() external returns (address);
}
interface IRegistryProcessorFactory {
    function create(address stored, address rendered, address verified, address ruled) external returns (address);
}
interface IRegistryPrepared {
    function prepare(address actor, bytes calldata raw) external view returns (bytes memory);
}

/// @notice Unqualified implementation candidate. Exactly thirteen Registry methods.
/// @dev No generic execute, initializer, upgrade, delegation or substituted actor.
contract ChainRegistry is IChainRegistry {
    uint256 private immutable executionChain;
    address private immutable instance;
    address private immutable renderer;
    address private immutable verifier;
    address private immutable rules;
    address private immutable validator;
    address private immutable store;
    address private immutable claimProcessor;
    address private immutable keyProcessor;
    address private immutable lifecycleProcessor;
    bytes32 private immutable rendererHash;
    bytes32 private immutable verifierHash;
    bytes32 private immutable rulesHash;
    bytes32 private immutable validatorHash;
    bytes32 private immutable storeHash;
    bytes32 private immutable claimHash;
    bytes32 private immutable keyHash;
    bytes32 private immutable lifecycleHash;
    string private identity;

    constructor(
        address rendered,
        address verified,
        address ruled,
        address validated,
        address storeFactory,
        address claimFactory,
        address keyFactory,
        address lifecycleFactory
    ) {
        address[8] memory roles = [
            rendered,
            verified,
            ruled,
            validated,
            storeFactory,
            claimFactory,
            keyFactory,
            lifecycleFactory
        ];
        if (!RegistryRoleHashes.accepts(roles) || block.chainid == 0 || block.chainid >= 10 ** 32)
            revert WrongRegistryContext();
        renderer = rendered;
        verifier = verified;
        rules = ruled;
        validator = validated;
        executionChain = block.chainid;
        instance = address(this);
        identity = string(
            abi.encodePacked(
                "eip155:",
                RegistryText.decimal(block.chainid),
                ":",
                RegistryText.addressText(address(this))
            )
        );
        address stored = abi.decode(
            RegistryTransport.write(storeFactory, abi.encodeCall(IRegistryStoreFactory.create, ())),
            (address)
        );
        if (stored.code.length == 0) revert WrongRegistryContext();
        (address boundCore, uint256 chain, address boundStore) = abi.decode(
            RegistryTransport.read(stored, abi.encodeCall(RegistryStore.binding, ())),
            (address, uint256, address)
        );
        if (boundCore != address(this) || chain != block.chainid || boundStore != stored) revert WrongRegistryContext();
        address claimed = createProcessor(claimFactory, stored, rendered, verified, ruled);
        address keyed = createProcessor(keyFactory, stored, rendered, verified, ruled);
        address lived = createProcessor(lifecycleFactory, stored, rendered, verified, ruled);
        store = stored;
        claimProcessor = claimed;
        keyProcessor = keyed;
        lifecycleProcessor = lived;
        rendererHash = rendered.codehash;
        verifierHash = verified.codehash;
        rulesHash = ruled.codehash;
        validatorHash = validated.codehash;
        storeHash = stored.codehash;
        claimHash = claimed.codehash;
        keyHash = keyed.codehash;
        lifecycleHash = lived.codehash;
    }

    function createProcessor(
        address factory,
        address stored,
        address rendered,
        address verified,
        address ruled
    ) private returns (address child) {
        child = abi.decode(
            RegistryTransport.write(
                factory,
                abi.encodeCall(IRegistryProcessorFactory.create, (stored, rendered, verified, ruled))
            ),
            (address)
        );
        if (child.code.length == 0 || child == stored) revert WrongRegistryContext();
        (
            address owner,
            address actualStore,
            address actualRenderer,
            address actualVerifier,
            address actualRules,
            uint256 chain,
            address self
        ) = abi.decode(
                RegistryTransport.read(child, abi.encodeCall(RegistryProcessor.binding, ())),
                (address, address, address, address, address, uint256, address)
            );
        if (
            owner != address(this) ||
            actualStore != stored ||
            actualRenderer != rendered ||
            actualVerifier != verified ||
            actualRules != ruled ||
            chain != block.chainid ||
            self != child
        ) revert WrongRegistryContext();
    }

    fallback() external payable {
        if (msg.data.length > 148804) revert BoundsExceeded();
        revert MalformedCall();
    }

    function commitClaim(bytes32 commitment) external override {
        validate();
        context();
        uint256 committed = abi.decode(
            RegistryTransport.write(store, abi.encodeCall(RegistryStore.commitClaim, (msg.sender, commitment))),
            (uint256)
        );
        if (committed != block.number) revert WrongRegistryContext();
        emit ClaimCommitted(msg.sender, commitment, committed);
    }

    function revealClaim(
        string calldata agentId,
        address,
        KeyInput[] calldata,
        ServiceInput[] calldata,
        bytes32
    ) external override returns (uint64) {
        return change(agentId, RegistryJson.Operation.Create);
    }
    function activate(string calldata agentId, uint64) external override returns (uint64) {
        return change(agentId, RegistryJson.Operation.Activate);
    }
    function deactivate(string calldata agentId, uint64) external override returns (uint64) {
        return change(agentId, RegistryJson.Operation.Deactivate);
    }
    function addKey(string calldata agentId, uint64, KeyInput calldata) external override returns (uint64) {
        return change(agentId, RegistryJson.Operation.AddKey);
    }
    function revokeKey(string calldata agentId, uint64, string calldata) external override returns (uint64) {
        return change(agentId, RegistryJson.Operation.RevokeKey);
    }
    function updateServices(
        string calldata agentId,
        uint64,
        ServiceInput[] calldata
    ) external override returns (uint64) {
        return change(agentId, RegistryJson.Operation.UpdateServices);
    }
    function authorizeOperator(
        string calldata agentId,
        uint64,
        address,
        string calldata
    ) external override returns (uint64) {
        return change(agentId, RegistryJson.Operation.AuthorizeOperator);
    }
    function revokeOperator(
        string calldata agentId,
        uint64,
        address,
        string calldata
    ) external override returns (uint64) {
        return change(agentId, RegistryJson.Operation.RevokeOperator);
    }
    function registryId() external view override returns (string memory) {
        validate();
        context();
        return identity;
    }
    function record(string calldata) external view override returns (bool, bytes memory) {
        validate();
        context();
        reply(RegistryTransport.read(store, msg.data));
    }
    function activeGrants(string calldata) external view override returns (bytes memory) {
        validate();
        context();
        reply(RegistryTransport.read(store, msg.data));
    }
    function historyItem(string calldata, uint64) external view override returns (bytes memory, bytes memory) {
        validate();
        context();
        reply(RegistryTransport.read(store, msg.data));
    }

    function change(string calldata agentId, RegistryJson.Operation operation) private returns (uint64 version) {
        validate();
        context();
        address processor =
            operation == RegistryJson.Operation.Create
                ? claimProcessor
                : (operation == RegistryJson.Operation.AddKey ||
                    operation == RegistryJson.Operation.RevokeKey ||
                    operation == RegistryJson.Operation.UpdateServices)
                    ? keyProcessor
                    : lifecycleProcessor;
        address actor = msg.sender;
        bytes memory plan = abi.decode(
            RegistryTransport.read(processor, abi.encodeCall(IRegistryPrepared.prepare, (actor, msg.data))),
            (bytes)
        );
        if (plan.length > 779424) revert WrongRegistryContext();
        bytes32 didHash;
        bytes memory eventData;
        (version, didHash, eventData) = abi.decode(
            RegistryTransport.write(store, abi.encodeCall(RegistryStore.commit, (actor, agentId, operation, plan))),
            (uint64, bytes32, bytes)
        );
        if (eventData.length > 512) revert WrongRegistryContext();
        bytes32 topic = keccak256(
            "RecordChanged(bytes32,address,string,uint64,uint64,string,bytes32,bytes32,bytes32,uint64)"
        );
        assembly ("memory-safe") {
            log3(add(eventData, 32), mload(eventData), topic, didHash, actor)
        }
    }

    function validate() private view {
        if (msg.data.length > 148804) revert BoundsExceeded();
        bytes memory result = RegistryTransport.read(validator, msg.data);
        if (result.length != 0) revert WrongRegistryContext();
    }

    function context() private view {
        if (msg.value != 0) revert ValueNotAllowed();
        if (
            block.chainid != executionChain ||
            address(this) != instance ||
            renderer.codehash != rendererHash ||
            verifier.codehash != verifierHash ||
            rules.codehash != rulesHash ||
            validator.codehash != validatorHash ||
            store.codehash != storeHash ||
            claimProcessor.codehash != claimHash ||
            keyProcessor.codehash != keyHash ||
            lifecycleProcessor.codehash != lifecycleHash
        ) revert WrongRegistryContext();
    }

    function reply(bytes memory output) private pure {
        assembly ("memory-safe") {
            return(add(output, 32), mload(output))
        }
    }
}
