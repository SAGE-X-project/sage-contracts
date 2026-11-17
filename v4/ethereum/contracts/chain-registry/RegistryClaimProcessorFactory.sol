// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {RegistryClaimProcessor} from "./RegistryClaimProcessor.sol";

/// @dev Stateless single-child factory. The actual creator becomes child owner.
contract RegistryClaimProcessorFactory {
    function create(address stored, address rendered, address verified, address ruled) external returns (address) {
        return address(new RegistryClaimProcessor(msg.sender, stored, rendered, verified, ruled));
    }
}
