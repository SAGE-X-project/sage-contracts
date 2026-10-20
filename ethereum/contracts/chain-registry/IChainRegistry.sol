// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @notice Exact SAGE 0.11.0 chain management surface. No implementation or deployment.
interface IChainRegistry {
    struct KeyInput {
        string name;
        string alg;
        bytes key;
        string signer;
        bytes proof;
        bool hasExpiry;
        uint64 expires;
    }

    struct ServiceInput {
        string name;
        string serviceType;
        string uri;
    }

    error MalformedCall();
    error ValueNotAllowed();
    error WrongRegistryContext();
    error UnauthorizedCaller();
    error WrongRecordState();
    error PreviousVersionMismatch();
    error VersionExhausted();
    error ClaimUnavailable();
    error ClaimWindowInvalid();
    error ClaimMismatch();
    error IdentifierUnavailable();
    error KeyUnavailable();
    error KeyNameReused();
    error KeyMaterialReused();
    error InvalidKeyProof();
    error UnsupportedKeyAlgorithm();
    error InvalidEntry();
    error BoundsExceeded();
    error GrantUnavailable();
    error GrantAlreadyPresent();
    error HistoryUnavailable();
    error TimeInvalid();
    event ClaimCommitted(address indexed caller, bytes32 indexed commitment, uint256 blockNumber);
    event RecordChanged(
        bytes32 indexed didHash,
        address indexed actor,
        string did,
        uint64 previousVersion,
        uint64 version,
        string operation,
        bytes32 commandDigest,
        bytes32 recordDigest,
        bytes32 grantsDigest,
        uint64 admitted
    );

    function commitClaim(bytes32 commitment) external;
    function revealClaim(
        string calldata agentId,
        address controller,
        KeyInput[] calldata keys,
        ServiceInput[] calldata services,
        bytes32 salt
    ) external returns (uint64 version);
    function activate(string calldata agentId, uint64 expectedVersion) external returns (uint64 version);
    function deactivate(string calldata agentId, uint64 expectedVersion) external returns (uint64 version);
    function addKey(
        string calldata agentId,
        uint64 expectedVersion,
        KeyInput calldata entry
    ) external returns (uint64 version);
    function revokeKey(
        string calldata agentId,
        uint64 expectedVersion,
        string calldata name
    ) external returns (uint64 version);
    function updateServices(
        string calldata agentId,
        uint64 expectedVersion,
        ServiceInput[] calldata services
    ) external returns (uint64 version);
    function authorizeOperator(
        string calldata agentId,
        uint64 expectedVersion,
        address operator,
        string calldata scope
    ) external returns (uint64 version);
    function revokeOperator(
        string calldata agentId,
        uint64 expectedVersion,
        address operator,
        string calldata scope
    ) external returns (uint64 version);
    function registryId() external view returns (string memory registry);
    function record(string calldata agentId) external view returns (bool present, bytes memory canonicalRecord);
    function activeGrants(string calldata agentId) external view returns (bytes memory canonicalGrants);
    function historyItem(
        string calldata agentId,
        uint64 version
    ) external view returns (bytes memory canonicalHistory, bytes memory canonicalCommand);
}
