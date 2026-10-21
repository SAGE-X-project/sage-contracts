// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {IChainRegistry} from "./IChainRegistry.sol";

/// @notice Bounded scalar syntax for the adopted Registry management schema.
/// @dev URI syntax follows RFC3986 sections2/3 and AppendixA with the explicit
/// HTTPS/nonempty-host/no-userinfo/no-fragment profile. No fetching, decoding,
/// normalization, DNS resolution or authority/transport trust is established.
library RegistryGrammar {
    function name(string memory value, bool agent) internal pure {
        bytes memory data = bytes(value);
        uint256 maximum = agent ? 64 : 32;
        if (data.length > maximum) revert IChainRegistry.BoundsExceeded();
        if (data.length == 0) revert IChainRegistry.InvalidEntry();
        if (agent && ((data.length == 1 && data[0] == 0x2e) ||
            (data.length == 2 && data[0] == 0x2e && data[1] == 0x2e))) {
            revert IChainRegistry.InvalidEntry();
        }
        for (uint256 i; i < data.length; ++i) {
            uint8 c = uint8(data[i]);
            if (!(letter(c) || digit(c) || c == 45 || c == 95 || (agent && c == 46))) {
                revert IChainRegistry.InvalidEntry();
            }
        }
    }

    function serviceType(string memory value) internal pure {
        bytes memory data = bytes(value);
        if (data.length > 64) revert IChainRegistry.BoundsExceeded();
        if (data.length == 0) revert IChainRegistry.InvalidEntry();
        for (uint256 i; i < data.length; ++i) {
            if (uint8(data[i]) > 127) revert IChainRegistry.InvalidEntry();
        }
    }

    function httpsUri(string memory value) internal pure {
        bytes memory data = bytes(value);
        if (data.length > 2048) revert IChainRegistry.BoundsExceeded();
        if (data.length < 9 || (uint8(data[0]) | 32) != 104 || (uint8(data[1]) | 32) != 116 ||
            (uint8(data[2]) | 32) != 116 || (uint8(data[3]) | 32) != 112 ||
            (uint8(data[4]) | 32) != 115 || data[5] != 0x3a || data[6] != 0x2f || data[7] != 0x2f) {
            revert IChainRegistry.InvalidEntry();
        }
        uint256 authorityEnd = 8;
        while (authorityEnd < data.length && data[authorityEnd] != 0x2f && data[authorityEnd] != 0x3f) {
            ++authorityEnd;
        }
        if (!authority(data, 8, authorityEnd)) revert IChainRegistry.InvalidEntry();
        for (uint256 i = authorityEnd; i < data.length; ++i) {
            uint8 c = uint8(data[i]);
            if (c == 63 || c == 47 || c == 58 || c == 64 || unreserved(c) || subdelimiter(c)) { }
            else if (c == 37 && percent(data, i, data.length)) i += 2;
            else revert IChainRegistry.InvalidEntry();
        }
    }

    function authority(bytes memory data, uint256 start, uint256 end) private pure returns (bool) {
        if (start == end) return false;
        uint256 port;
        if (data[start] == 0x5b) {
            uint256 close = start + 1;
            while (close < end && data[close] != 0x5d) ++close;
            if (close == end || !ipLiteral(data, start + 1, close)) return false;
            port = close + 1;
            if (port < end) {
                if (data[port] != 0x3a) return false;
                ++port;
            }
        } else {
            uint256 cursor = start;
            while (cursor < end && data[cursor] != 0x3a) {
                uint8 c = uint8(data[cursor]);
                if (unreserved(c) || subdelimiter(c)) ++cursor;
                else if (c == 37 && percent(data, cursor, end)) cursor += 3;
                else return false;
            }
            if (cursor == start) return false;
            port = cursor == end ? end : cursor + 1;
        }
        // RFC3986 port=*DIGIT includes an empty port. No invented numeric cap.
        for (uint256 i = port; i < end; ++i) if (!digit(uint8(data[i]))) return false;
        return true;
    }

    function ipLiteral(bytes memory data, uint256 start, uint256 end) private pure returns (bool) {
        if (start == end) return false;
        if (data[start] == 0x76 || data[start] == 0x56) {
            uint256 cursor = start + 1;
            while (cursor < end && hexadecimal(uint8(data[cursor]))) ++cursor;
            if (cursor == start + 1 || cursor == end || data[cursor] != 0x2e) return false;
            ++cursor;
            if (cursor == end) return false;
            for (; cursor < end; ++cursor) {
                uint8 c = uint8(data[cursor]);
                if (!(unreserved(c) || subdelimiter(c) || c == 58)) return false;
            }
            return true;
        }
        uint256 cursor = start;
        uint256 groups;
        bool compressed;
        if (data[cursor] == 0x3a) {
            if (cursor + 1 == end || data[cursor + 1] != 0x3a) return false;
            compressed = true;
            cursor += 2;
        }
        while (cursor < end) {
            uint256 segment = cursor;
            bool dotted;
            while (cursor < end && data[cursor] != 0x3a) {
                if (data[cursor] == 0x2e) dotted = true;
                ++cursor;
            }
            if (dotted) {
                if (cursor != end || !ipv4(data, segment, end)) return false;
                groups += 2;
            } else {
                if (cursor == segment || cursor - segment > 4) return false;
                for (uint256 i = segment; i < cursor; ++i) if (!hexadecimal(uint8(data[i]))) return false;
                ++groups;
            }
            if (cursor < end) {
                ++cursor;
                if (cursor == end) return false;
                if (data[cursor] == 0x3a) {
                    if (compressed) return false;
                    compressed = true;
                    ++cursor;
                }
            }
        }
        return compressed ? groups < 8 : groups == 8;
    }

    function ipv4(bytes memory data, uint256 start, uint256 end) private pure returns (bool) {
        uint256 cursor = start;
        for (uint256 part; part < 4; ++part) {
            uint256 segment = cursor;
            uint256 number;
            while (cursor < end && digit(uint8(data[cursor]))) {
                number = number * 10 + uint8(data[cursor]) - 48;
                ++cursor;
                if (cursor - segment > 3 || number > 255) return false;
            }
            if (cursor == segment || (cursor - segment > 1 && data[segment] == 0x30)) return false;
            if (part < 3) {
                if (cursor == end || data[cursor] != 0x2e) return false;
                ++cursor;
            } else if (cursor != end) return false;
        }
        return true;
    }

    function percent(bytes memory data, uint256 cursor, uint256 end) private pure returns (bool) {
        return end - cursor >= 3 && hexadecimal(uint8(data[cursor + 1])) && hexadecimal(uint8(data[cursor + 2]));
    }

    function letter(uint8 c) private pure returns (bool) {
        return (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
    }
    function digit(uint8 c) private pure returns (bool) { return c >= 48 && c <= 57; }
    function hexadecimal(uint8 c) private pure returns (bool) {
        return digit(c) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102);
    }
    function unreserved(uint8 c) private pure returns (bool) {
        return letter(c) || digit(c) || c == 45 || c == 46 || c == 95 || c == 126;
    }
    function subdelimiter(uint8 c) private pure returns (bool) {
        return c == 33 || c == 36 || c == 38 || c == 39 || c == 40 || c == 41 ||
            c == 42 || c == 43 || c == 44 || c == 59 || c == 61;
    }
}
