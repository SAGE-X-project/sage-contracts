// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {IChainRegistry} from "./IChainRegistry.sol";

/// @notice ASCII string and binary primitives for the bounded Registry schemas.
/// @dev Internal field helpers only; not a Unicode JSON parser or admission check.
library RegistryText {
    function quote(bytes memory value) internal pure returns (bytes memory output) {
        if (value.length > 2048) revert IChainRegistry.BoundsExceeded();
        bytes16 digits = "0123456789abcdef";
        output = new bytes(6 * value.length + 2);
        uint256 cursor = 1;
        output[0] = 0x22;
        for (uint256 i; i < value.length; ++i) {
            uint8 character = uint8(value[i]);
            if (character > 127) revert IChainRegistry.InvalidEntry();
            if (character == 34 || character == 92) {
                output[cursor++] = 0x5c;
                output[cursor++] = bytes1(character);
            } else if (character == 8 || character == 9 || character == 10 || character == 12 || character == 13) {
                output[cursor++] = 0x5c;
                if (character == 8) output[cursor++] = 0x62;
                else if (character == 9) output[cursor++] = 0x74;
                else if (character == 10) output[cursor++] = 0x6e;
                else if (character == 12) output[cursor++] = 0x66;
                else output[cursor++] = 0x72;
            } else if (character < 32) {
                output[cursor++] = 0x5c;
                output[cursor++] = 0x75;
                output[cursor++] = 0x30;
                output[cursor++] = 0x30;
                output[cursor++] = digits[character >> 4];
                output[cursor++] = digits[character & 15];
            } else {
                output[cursor++] = bytes1(character);
            }
        }
        output[cursor++] = 0x22;
        // Shrink only the initialized prefix of this function's own allocation.
        assembly ("memory-safe") { mstore(output, cursor) }
    }

    function base64url(bytes memory raw) internal pure returns (bytes memory output) {
        // Every admitted Registry binary field is at most65 bytes.
        if (raw.length > 65) revert IChainRegistry.BoundsExceeded();
        bytes memory alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        output = new bytes((raw.length * 4 + 2) / 3);
        uint256 cursor;
        for (uint256 i; i < raw.length; i += 3) {
            uint256 chunk = uint256(uint8(raw[i])) << 16;
            if (i + 1 < raw.length) chunk |= uint256(uint8(raw[i + 1])) << 8;
            if (i + 2 < raw.length) chunk |= uint8(raw[i + 2]);
            output[cursor++] = alphabet[(chunk >> 18) & 63];
            output[cursor++] = alphabet[(chunk >> 12) & 63];
            if (i + 1 < raw.length) output[cursor++] = alphabet[(chunk >> 6) & 63];
            if (i + 2 < raw.length) output[cursor++] = alphabet[chunk & 63];
        }
    }

    function decimal(uint256 value) internal pure returns (bytes memory output) {
        if (value == 0) return bytes("0");
        uint256 temporary = value;
        uint256 digits;
        while (temporary != 0) {
            ++digits;
            temporary /= 10;
        }
        output = new bytes(digits);
        while (value != 0) {
            output[--digits] = bytes1(uint8(48 + value % 10));
            value /= 10;
        }
    }

    function addressText(address value) internal pure returns (bytes memory output) {
        bytes16 digits = "0123456789abcdef";
        output = new bytes(42);
        output[0] = 0x30;
        output[1] = 0x78;
        for (uint256 i; i < 40; ++i) {
            output[41 - i] = digits[(uint160(value) >> (4 * i)) & 15];
        }
    }
}
