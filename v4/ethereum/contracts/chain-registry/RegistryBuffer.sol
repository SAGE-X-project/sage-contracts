// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {IChainRegistry} from "./IChainRegistry.sol";

/// @notice A bounded append buffer for the exact Registry JSON schemas.
/// @dev Internal construction helper only. No input parser or admission policy.
library RegistryBuffer {
    struct Sink {
        bytes data;
        uint256 cursor;
    }

    function create(uint256 capacity) internal pure returns (Sink memory sink) {
        if (capacity > 262144) revert IChainRegistry.BoundsExceeded();
        sink.data = new bytes(capacity);
    }

    function append(Sink memory sink, bytes memory value) internal pure {
        bytes memory data = sink.data;
        uint256 cursor = sink.cursor;
        if (cursor > data.length || value.length > data.length - cursor) revert IChainRegistry.BoundsExceeded();
        uint256 i;
        // Every complete store lies inside the checked destination allocation.
        // The short tail is copied bytewise, never past the capacity boundary.
        for (; i + 32 <= value.length; i += 32) {
            assembly ("memory-safe") {
                mstore(add(add(data, 32), add(cursor, i)), mload(add(add(value, 32), i)))
            }
        }
        for (; i < value.length; ++i) data[cursor + i] = value[i];
        sink.cursor = cursor + value.length;
    }

    function finish(Sink memory sink) internal pure returns (bytes memory output) {
        output = sink.data;
        uint256 cursor = sink.cursor;
        if (cursor > output.length) revert IChainRegistry.BoundsExceeded();
        assembly ("memory-safe") { mstore(output, cursor) }
    }
}
