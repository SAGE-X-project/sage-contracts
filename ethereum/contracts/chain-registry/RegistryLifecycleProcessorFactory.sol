// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {RegistryLifecycleProcessor} from "./RegistryLifecycleProcessor.sol";

/// @dev Stateless single-child factory. The actual creator becomes child owner.
contract RegistryLifecycleProcessorFactory {
    function create(address stored, address rendered, address verified, address ruled) external returns (address) {
        return address(new RegistryLifecycleProcessor(msg.sender, stored, rendered, verified, ruled));
    }
}
