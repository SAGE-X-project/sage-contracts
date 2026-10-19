// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Sha2Ext} from "./upstream/external/sha512/Sha2Ext.sol";

/// @notice Research-only raw-key verification. No Registry admission or adopted API.
/// Complete Edwards addition: RFC 8032 section 5.1.4; this is new evaluation code.
contract StrictEd25519 {
    uint256 internal constant P = 2 ** 255 - 19;
    uint256 internal constant L = 7237005577332262213973186563042994240857116359379907606001950938285454250989;
    uint256 internal constant D = 37095705934669439343138083508754565189542113879843219016388785533085940283555;
    uint256 internal constant SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752;
    uint256 internal constant BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202;
    uint256 internal constant BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960;
    uint256 public constant MAX_MESSAGE_BYTES = 1024;

    struct Point { uint256 x; uint256 y; uint256 z; uint256 t; }

    function verify(bytes memory key, bytes memory message, bytes memory signature) public view returns (bool) {
        if (key.length != 32 || signature.length != 64 || message.length > MAX_MESSAGE_BYTES) return false;
        uint256 s = _little(signature, 32);
        if (s >= L) return false;
        (bool goodA, Point memory a) = _decode(_little(key, 0));
        if (!goodA || _identity(a) || !_identity(_multiply(a, L))) return false;
        (bool goodR, Point memory r) = _decode(_little(signature, 0));
        if (!goodR || _identity(r) || !_identity(_multiply(r, L))) return false;
        bytes memory originalR = new bytes(32);
        for (uint256 i; i < 32; ++i) originalR[i] = signature[i];
        (bytes32 high, bytes32 low) = Sha2Ext.sha512(bytes.concat(originalR, key, message));
        uint256 k = _reduce(abi.encodePacked(high, low));
        return _equal(_multiply(_base(), s), _add(r, _multiply(a, k)));
    }

    function _little(bytes memory data, uint256 offset) internal pure returns (uint256 value) {
        for (uint256 i; i < 32; ++i) value |= uint256(uint8(data[offset + i])) << (8 * i);
    }

    function _reduce(bytes memory digest) internal pure returns (uint256 value) {
        for (uint256 i = digest.length; i > 0; --i) value = addmod(mulmod(value, 256, L), uint8(digest[i - 1]), L);
    }

    function _decode(uint256 encoded) internal view returns (bool, Point memory point) {
        uint256 sign = encoded >> 255;
        uint256 y = encoded & (2 ** 255 - 1);
        if (y >= P) return (false, point);
        uint256 y2 = mulmod(y, y, P);
        uint256 u = addmod(y2, P - 1, P);
        uint256 v = addmod(mulmod(D, y2, P), 1, P);
        if (v == 0) return (false, point);
        (bool inverseOK, uint256 inverse) = _modexp(v, P - 2);
        if (!inverseOK || mulmod(v, inverse, P) != 1) return (false, point);
        uint256 square = mulmod(u, inverse, P);
        (bool rootOK, uint256 x) = _modexp(square, (P + 3) / 8);
        if (!rootOK || x >= P) return (false, point);
        if (mulmod(x, x, P) != square) x = mulmod(x, SQRT_M1, P);
        if (mulmod(x, x, P) != square || (x == 0 && sign == 1)) return (false, point);
        if ((x & 1) != sign) x = P - x;
        if ((y | ((x & 1) << 255)) != encoded) return (false, point);
        point = Point(x, y, 1, mulmod(x, y, P));
        return (true, point);
    }

    function _modexp(uint256 base, uint256 exponent) internal view virtual returns (bool ok, uint256 result) {
        bytes memory input = abi.encode(uint256(32), uint256(32), uint256(32), base, exponent, P);
        bytes memory output = new bytes(32);
        assembly {
            ok := staticcall(100000, 5, add(input, 32), mload(input), add(output, 32), 32)
            ok := and(ok, eq(returndatasize(), 32))
            result := mload(add(output, 32))
        }
    }

    function _base() internal pure returns (Point memory) {
        return Point(BX, BY, 1, mulmod(BX, BY, P));
    }

    function _identity(Point memory q) internal pure returns (bool) {
        return q.z != 0 && q.x == 0 && q.y == q.z;
    }

    function _equal(Point memory a, Point memory b) internal pure returns (bool) {
        return a.z != 0 && b.z != 0 && mulmod(a.x, b.z, P) == mulmod(b.x, a.z, P)
            && mulmod(a.y, b.z, P) == mulmod(b.y, a.z, P);
    }

    function _add(Point memory a, Point memory b) internal pure returns (Point memory) {
        uint256 aa = mulmod(addmod(a.y, P - a.x, P), addmod(b.y, P - b.x, P), P);
        uint256 bb = mulmod(addmod(a.y, a.x, P), addmod(b.y, b.x, P), P);
        uint256 cc = mulmod(mulmod(2, D, P), mulmod(a.t, b.t, P), P);
        uint256 dd = mulmod(2, mulmod(a.z, b.z, P), P);
        uint256 e = addmod(bb, P - aa, P);
        uint256 f = addmod(dd, P - cc, P);
        uint256 g = addmod(dd, cc, P);
        uint256 h = addmod(bb, aa, P);
        return Point(mulmod(e, f, P), mulmod(g, h, P), mulmod(f, g, P), mulmod(e, h, P));
    }

    // Deliberately no reduction of scalar modulo L: this also proves [L]Q = identity.
    function _multiply(Point memory q, uint256 scalar) internal pure returns (Point memory result) {
        result = Point(0, 1, 1, 0);
        while (scalar != 0) {
            if ((scalar & 1) != 0) result = _add(result, q);
            q = _add(q, q);
            scalar >>= 1;
        }
    }
}

/// @notice Fixed mathematical unit controls only; never a Registry/transport API.
contract ArithmeticControls is StrictEd25519 {
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

contract MissingBackendControl is StrictEd25519 {
    function _modexp(uint256, uint256) internal pure override returns (bool, uint256) { return (false, 0); }
}

contract InvalidBackendControl is StrictEd25519 {
    function _modexp(uint256, uint256) internal pure override returns (bool, uint256) { return (true, 0); }
}
