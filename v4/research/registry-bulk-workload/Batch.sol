// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @notice Isolated research wrapper, not a Registry or an adopted protocol API.
/// The build substitutes the exact compiled verifier's code hash once.
contract BatchProbe {
    address internal constant VERIFIER = address(0x1000);
    bytes32 internal constant EXPECTED_CODE_HASH = bytes32(0); // BUILD_CODE_HASH

    function verifyBatch(bytes[] calldata keys, bytes[] calldata messages, bytes[] calldata signatures)
        external view returns (bool valid, uint256 completed)
    {
        uint256 count = keys.length;
        if (count == 0 || count > 128 || messages.length != count || signatures.length != count)
            return (false, 0);
        if (VERIFIER.codehash != EXPECTED_CODE_HASH) return (false, 0);
        for (uint256 i; i < count; ++i) {
            if (keys[i].length != 32 || messages[i].length != 242 || signatures[i].length != 64)
                return (false, i);
            (bool ok, bytes memory answer) = VERIFIER.staticcall{gas: 15000000}(
                abi.encodeWithSignature("verify(bytes,bytes,bytes)", keys[i], messages[i], signatures[i])
            );
            if (!ok || answer.length != 32 || !abi.decode(answer, (bool))) return (false, i);
        }
        return (true, count);
    }
}
