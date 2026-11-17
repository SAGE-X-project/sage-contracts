// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @notice Ordinary owned test account for isolated constructor-deployed tests.
/// @dev No callback, upgrade, delegatecall, arbitrary target or live-chain path.
contract OwnedWallet {
    address private immutable owner;
    address private immutable registry;

    constructor(address target) {
        require(target.code.length > 0, "Registry must already be deployed");
        owner = msg.sender;
        registry = target;
    }

    function invoke(bytes calldata data) external returns (bytes memory) {
        require(msg.sender == owner, "Only the ordinary test owner");
        require(data.length <= 148804, "Bounded Registry input");
        (bool success, bytes memory result) = registry.call(data);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
        return result;
    }
}
