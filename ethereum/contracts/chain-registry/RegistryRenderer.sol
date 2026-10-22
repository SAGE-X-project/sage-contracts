// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {IChainRegistry} from "./IChainRegistry.sol";
import {RegistryJson} from "./RegistryJson.sol";

/// @notice Candidate stateless serializer module, not a management endpoint.
/// @dev Only the separately qualified Registry decides authority and admission.
contract RegistryRenderer {
    function record(RegistryJson.Record memory value) external pure returns (bytes memory) {
        return RegistryJson.record(value);
    }
    function checkHeadroom(RegistryJson.Record memory value) external pure {
        RegistryJson.checkHeadroom(value);
    }
    function claim(
        string memory registry,
        string memory agentId,
        address controller,
        IChainRegistry.KeyInput[] memory keys,
        IChainRegistry.ServiceInput[] memory services,
        bytes32 salt
    ) external pure returns (bytes memory) {
        return RegistryJson.claim(registry, agentId, controller, keys, services, salt);
    }
    function grants(RegistryJson.Grant[] memory value) external pure returns (bytes memory) {
        return RegistryJson.grants(value);
    }
    function command(RegistryJson.Command memory value) external pure returns (bytes memory) {
        return RegistryJson.command(value);
    }
    function history(RegistryJson.History memory value) external pure returns (bytes memory) {
        return RegistryJson.history(value);
    }
}
