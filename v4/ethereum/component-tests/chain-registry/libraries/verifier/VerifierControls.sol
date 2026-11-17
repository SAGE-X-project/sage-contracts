// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {RegistryEd25519} from "ethereum/contracts/chain-registry/RegistryEd25519.sol";

/// @notice Fixed mathematical unit controls only; never a Registry/transport API.
contract ArithmeticControls is RegistryEd25519 {
    // Only decoding and membership observations, never a signature or point generator.
    function inspectPoint(bytes memory encoded) external view returns (bool decoded, bool neutral, bool prime) {
        require(encoded.length == 32, "fixed point width");
        Point memory point;
        (decoded, point) = _decode(_little(encoded, 0));
        if (!decoded) return (false, false, false);
        neutral = _identity(point);
        prime = _identity(_multiply(point, L));
    }
    function zeroScalarIdentity() external pure returns (bool) { return _identity(_multiply(_base(), 0)); }
    function baseOrderIdentity() external pure returns (bool) { return _identity(_multiply(_base(), L)); }
    function neutralAddition() external pure returns (bool) {
        Point memory identity = Point(0, 1, 1, 0);
        return _equal(_add(_base(), identity), _base()) && _equal(_add(identity, _base()), _base());
    }
    function invalidProjectiveRefused() external pure returns (bool) {
        Point memory invalid = Point(0, 0, 0, 0);
        return !_identity(invalid) && !_equal(invalid, _base()) && !_equal(_base(), invalid);
    }
}

contract MissingBackendControl is RegistryEd25519 {
    function _modexp(uint256, uint256) internal pure override returns (bool, uint256) { return (false, 0); }
}

contract InvalidBackendControl is RegistryEd25519 {
    function _modexp(uint256, uint256) internal pure override returns (bool, uint256) { return (true, 0); }
}
