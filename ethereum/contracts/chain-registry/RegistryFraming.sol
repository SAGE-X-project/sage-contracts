// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {IChainRegistry} from "./IChainRegistry.sol";

/// @notice Bounded canonical ABI framing before application allocation or proof work.
/// @dev This does not establish scalar grammar, authority, proofs or Registry success.
/// The accepting entry point must also compare complete canonical ABI re-encoding.
library RegistryFraming {
    function check(bytes calldata data) internal pure returns (bytes4 selector) {
        if (data.length > 148804) revert IChainRegistry.BoundsExceeded();
        if (data.length < 4) revert IChainRegistry.MalformedCall();
        selector = bytes4(data[:4]);
        (uint256 minimum, uint256 maximum) = limits(selector);
        if (data.length > maximum) revert IChainRegistry.BoundsExceeded();
        if (data.length < minimum) revert IChainRegistry.MalformedCall();
        uint256 cursor = minimum;
        // Fixed-length operations need no dynamic traversal.
        if (selector != IChainRegistry.registryId.selector && selector != IChainRegistry.commitClaim.selector) {
            cursor = blob(data, 4, 4, cursor, 64);
            if (selector == IChainRegistry.revealClaim.selector) {
                scalar(data, 36, 160);
                cursor = entries(data, 68, 4, cursor, true);
                cursor = entries(data, 100, 4, cursor, false);
            } else if (selector == IChainRegistry.addKey.selector) {
                scalar(data, 36, 64);
                cursor = key(data, 68, 4, cursor);
            } else if (selector == IChainRegistry.updateServices.selector) {
                scalar(data, 36, 64);
                cursor = entries(data, 68, 4, cursor, false);
            } else if (selector == IChainRegistry.revokeKey.selector) {
                scalar(data, 36, 64);
                cursor = blob(data, 68, 4, cursor, 32);
            } else if (
                selector == IChainRegistry.authorizeOperator.selector ||
                selector == IChainRegistry.revokeOperator.selector
            ) {
                scalar(data, 36, 64);
                scalar(data, 68, 160);
                cursor = blob(data, 100, 4, cursor, 15);
            } else if (selector != IChainRegistry.record.selector && selector != IChainRegistry.activeGrants.selector) {
                scalar(data, 36, 64);
            }
        }
        if (cursor != data.length) revert IChainRegistry.MalformedCall();
    }

    function limits(bytes4 selector) private pure returns (uint256 minimum, uint256 maximum) {
        if (selector == IChainRegistry.commitClaim.selector) return (36, 36);
        if (selector == IChainRegistry.revealClaim.selector) return (164, 148804);
        if (
            selector == IChainRegistry.activate.selector ||
            selector == IChainRegistry.deactivate.selector ||
            selector == IChainRegistry.historyItem.selector
        ) return (68, 164);
        if (selector == IChainRegistry.addKey.selector) return (100, 1028);
        if (selector == IChainRegistry.revokeKey.selector) return (100, 260);
        if (selector == IChainRegistry.updateServices.selector) return (100, 38116);
        if (
            selector == IChainRegistry.authorizeOperator.selector ||
            selector == IChainRegistry.revokeOperator.selector
        ) return (132, 292);
        if (selector == IChainRegistry.registryId.selector) return (4, 4);
        if (
            selector == IChainRegistry.record.selector ||
            selector == IChainRegistry.activeGrants.selector
        ) return (36, 132);
        revert IChainRegistry.MalformedCall();
    }

    function word(bytes calldata data, uint256 position) private pure returns (uint256 value) {
        if (position > data.length || data.length - position < 32) revert IChainRegistry.MalformedCall();
        assembly { value := calldataload(add(data.offset, position)) }
    }

    function scalar(bytes calldata data, uint256 position, uint256 bits) private pure {
        if (word(data, position) >> bits != 0) revert IChainRegistry.MalformedCall();
    }

    function offset(bytes calldata data, uint256 position, uint256 base) private pure returns (uint256 start) {
        uint256 relative = word(data, position);
        if (base > data.length || relative > data.length - base) revert IChainRegistry.MalformedCall();
        return base + relative;
    }

    function range(bytes calldata data, uint256 start, uint256 size) private pure {
        if (start > data.length || size > data.length - start) revert IChainRegistry.MalformedCall();
    }

    function blob(
        bytes calldata data,
        uint256 position,
        uint256 base,
        uint256 cursor,
        uint256 cap
    ) private pure returns (uint256 end) {
        uint256 start = offset(data, position, base);
        uint256 size = word(data, start);
        if (size > cap) revert IChainRegistry.BoundsExceeded();
        uint256 padded = ((size + 31) / 32) * 32;
        range(data, start + 32, padded);
        if (start != cursor) revert IChainRegistry.MalformedCall();
        end = start + 32 + padded;
        for (uint256 i = start + 32 + size; i < end; ++i) {
            if (data[i] != 0) revert IChainRegistry.MalformedCall();
        }
    }

    function entries(
        bytes calldata data,
        uint256 position,
        uint256 base,
        uint256 cursor,
        bool keys
    ) private pure returns (uint256 end) {
        uint256 start = offset(data, position, base);
        uint256 count = word(data, start);
        if (count > (keys ? 128 : 16)) revert IChainRegistry.BoundsExceeded();
        uint256 head = start + 32;
        range(data, head, count * 32);
        if (start != cursor) revert IChainRegistry.MalformedCall();
        end = head + count * 32;
        for (uint256 i; i < count; ++i) {
            end = keys ? key(data, head + i * 32, head, end) : service(data, head + i * 32, head, end);
        }
    }

    function key(
        bytes calldata data,
        uint256 position,
        uint256 base,
        uint256 cursor
    ) private pure returns (uint256 end) {
        uint256 start = offset(data, position, base);
        range(data, start, 224);
        if (start != cursor) revert IChainRegistry.MalformedCall();
        end = start + 224;
        end = blob(data, start, start, end, 32);
        end = blob(data, start + 32, start, end, 24);
        end = blob(data, start + 64, start, end, 65);
        end = blob(data, start + 96, start, end, 189);
        end = blob(data, start + 128, start, end, 65);
        scalar(data, start + 160, 1);
        scalar(data, start + 192, 64);
    }

    function service(
        bytes calldata data,
        uint256 position,
        uint256 base,
        uint256 cursor
    ) private pure returns (uint256 end) {
        uint256 start = offset(data, position, base);
        range(data, start, 96);
        if (start != cursor) revert IChainRegistry.MalformedCall();
        end = start + 96;
        end = blob(data, start, start, end, 32);
        end = blob(data, start + 32, start, end, 64);
        end = blob(data, start + 64, start, end, 2048);
    }
}
