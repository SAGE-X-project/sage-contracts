// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {RegistryKeyServiceProcessor} from "./RegistryKeyServiceProcessor.sol";

/// @dev Stateless single-child factory. The actual creator becomes child owner.
contract RegistryKeyServiceProcessorFactory {
    function create(address stored, address rendered, address verified, address ruled) external returns (address) {
        return address(new RegistryKeyServiceProcessor(msg.sender, stored, rendered, verified, ruled));
    }
}
