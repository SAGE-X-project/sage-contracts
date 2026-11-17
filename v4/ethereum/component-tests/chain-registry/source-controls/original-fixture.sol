// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// A finite compiler fixture, not a deployed Registry or a network client.
contract StatementFixture {
    event Seen(uint256 value);
    error NotReady();

    function exercise(uint256 n) external returns (uint256) {
        uint256 total = 0;
        for (uint256 i = 0; i < n; i++) {
            if (i == 2) continue;
            if (i == 4) break;
            total += i;
        }
        while (total < 10) total++;
        do { total++; } while (total < 11);
        if (n > 20) revert NotReady();
        assembly ("memory-safe") { total := add(total, 1) }
        emit Seen(total);
        try this.read() returns (uint256 value) {
            return total + value;
        } catch {
            return total;
        }
    }

    function read() external pure returns (uint256) {
        return 1;
    }
}
