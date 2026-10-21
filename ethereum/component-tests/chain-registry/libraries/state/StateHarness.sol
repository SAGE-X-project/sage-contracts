// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {RegistryState} from "ethereum/contracts/chain-registry/RegistryState.sol";
import {RegistryJson} from "ethereum/contracts/chain-registry/RegistryJson.sol";

/// @dev Pure finite lifecycle/grant controls only; not a stored Registry.
contract StateHarness {
    function authorized(RegistryState.Snapshot memory value, address actor, RegistryJson.Operation operation)
        external pure returns (bool)
    {
        return RegistryState.authorized(value, actor, operation);
    }
    function advance(RegistryState.Snapshot memory value, RegistryJson.Operation operation,
        uint64 expectedVersion, uint256 nowValue) external pure returns (uint64, uint8, uint64)
    {
        RegistryState.advance(value, operation, expectedVersion, nowValue);
        return (value.value.version, uint8(value.value.state), value.admitted);
    }
    function authorizeGrant(RegistryState.Snapshot memory value, address operator, string memory scope)
        external pure returns (RegistryJson.Grant[] memory)
    {
        return RegistryState.authorizeGrant(value, operator, scope);
    }
    function revokeGrant(RegistryState.Snapshot memory value, address operator, string memory scope)
        external pure returns (RegistryJson.Grant[] memory)
    {
        return RegistryState.revokeGrant(value, operator, scope);
    }
    function cleanup(RegistryJson.Grant[] memory grants, bool activation, bool terminal)
        external pure returns (RegistryJson.Grant[] memory, RegistryJson.Grant[] memory)
    {
        return RegistryState.cleanup(grants, activation, terminal);
    }
    function allowedScope(RegistryJson.RecordState state, string memory scope) external pure returns (bool) {
        return RegistryState.allowedScope(state, scope);
    }
}
