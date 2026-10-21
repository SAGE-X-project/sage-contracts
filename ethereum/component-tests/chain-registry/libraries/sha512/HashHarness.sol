// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {RegistrySha512} from "ethereum/contracts/chain-registry/RegistrySha512.sol";
import {RegistryHashBytes} from "ethereum/contracts/chain-registry/RegistryHashBytes.sol";

/// @dev Pure fixed hashing/bounds controls only. No Registry, signature or key API.
contract HashHarness {
    function digest(bytes memory input) external pure returns (bytes memory) { return RegistrySha512.digest(input); }
    function slice(bytes memory input, uint256 start, uint256 end) external pure returns (bytes memory) {
        return RegistryHashBytes.slice(input, start, end);
    }
    function readBytes8(bytes memory input, uint256 offset) external pure returns (bytes memory) {
        return abi.encodePacked(RegistryHashBytes.readBytes8(input, offset));
    }
}
