// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @notice Small independently written byte accessors for the fixed SHA helper.
/// @dev Not copied from the historical mixed-notice LibBytes dependency.
library RegistryHashBytes {
    function slice(bytes memory data, uint256 start, uint256 end) internal pure returns (bytes memory output) {
        if (start > end || end > data.length) revert();
        output = new bytes(end - start);
        for (uint256 i; i < output.length; ++i) output[i] = data[start + i];
    }

    function readBytes8(bytes memory data, uint256 offset) internal pure returns (bytes8) {
        if (offset > data.length || data.length - offset < 8) revert();
        uint64 word;
        for (uint256 i; i < 8; ++i) word = (word << 8) | uint64(uint8(data[offset + i]));
        return bytes8(word);
    }
}
