// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {RegistryText} from "ethereum/contracts/chain-registry/RegistryText.sol";

/// @notice Pure finite unit controls; no Registry, authority or transaction API.
contract TextHarness {
    function quote(bytes calldata value) external pure returns (bytes memory) {
        return RegistryText.quote(value);
    }

    function base64url(bytes calldata value) external pure returns (bytes memory) {
        return RegistryText.base64url(value);
    }

    function decimal(uint256 value) external pure returns (bytes memory) {
        return RegistryText.decimal(value);
    }

    function addressText(address value) external pure returns (bytes memory) {
        return RegistryText.addressText(value);
    }
}
