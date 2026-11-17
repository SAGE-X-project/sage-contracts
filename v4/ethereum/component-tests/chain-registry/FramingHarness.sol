// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {RegistryFraming} from "../../contracts/chain-registry/RegistryFraming.sol";

/// @dev Unit control only. Never part of a deployed Registry or its accepted ABI.
contract FramingHarness {
    function check(bytes calldata data) external pure returns (bytes4) {
        return RegistryFraming.check(data);
    }
}
