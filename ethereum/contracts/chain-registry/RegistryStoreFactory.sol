// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {RegistryStore} from "./RegistryStore.sol";

/// @dev Stateless single-child factory. The actual creator becomes child owner.
contract RegistryStoreFactory {
    function create() external returns (address) {
        return address(new RegistryStore(msg.sender));
    }
}
