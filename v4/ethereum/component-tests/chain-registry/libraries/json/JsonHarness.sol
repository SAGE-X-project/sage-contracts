// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {IChainRegistry} from "ethereum/contracts/chain-registry/IChainRegistry.sol";
import {RegistryJson} from "ethereum/contracts/chain-registry/RegistryJson.sol";

/// @dev Isolated pure construction controls only; never a Registry runtime API.
contract JsonHarness {
    function record(RegistryJson.Record memory value, bool headroom) external pure returns (bytes memory output) {
        output = RegistryJson.record(value);
        if (headroom) RegistryJson.checkHeadroom(value);
    }
    function claim(string memory registry, string memory agentId, address controller,
        IChainRegistry.KeyInput[] memory keys, IChainRegistry.ServiceInput[] memory services, bytes32 salt
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
