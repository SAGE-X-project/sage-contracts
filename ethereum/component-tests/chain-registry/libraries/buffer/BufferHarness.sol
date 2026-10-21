// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {RegistryBuffer} from "ethereum/contracts/chain-registry/RegistryBuffer.sol";

/// @notice Pure append/length unit controls only; never an accepted Registry API.
contract BufferHarness {
    function render(uint256 capacity, bytes[] calldata parts) external pure returns (bytes memory) {
        RegistryBuffer.Sink memory sink = RegistryBuffer.create(capacity);
        // Adjacent sentinel makes an out-of-capacity final word store observable.
        bytes memory sentinel = hex"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        bytes32 original = keccak256(sentinel);
        for (uint256 i; i < parts.length; ++i) RegistryBuffer.append(sink, parts[i]);
        require(keccak256(sentinel) == original, "adjacent unit bytes changed");
        return RegistryBuffer.finish(sink);
    }

    function invalidCursor(bool onFinish) external pure returns (bytes memory) {
        RegistryBuffer.Sink memory sink = RegistryBuffer.create(0);
        sink.cursor = 1;
        if (onFinish) return RegistryBuffer.finish(sink);
        RegistryBuffer.append(sink, bytes(""));
        return bytes("");
    }
}
