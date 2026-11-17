// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {RegistryGrammar} from "ethereum/contracts/chain-registry/RegistryGrammar.sol";

/// @dev Pure grammar controls, without network or Registry admission.
contract GrammarHarness {
    function name(string memory value, bool agent) external pure returns (bytes memory) {
        RegistryGrammar.name(value, agent);
        return bytes(value);
    }
    function serviceType(string memory value) external pure returns (bytes memory) {
        RegistryGrammar.serviceType(value);
        return bytes(value);
    }
    function httpsUri(string memory value) external pure returns (bytes memory) {
        RegistryGrammar.httpsUri(value);
        return bytes(value);
    }
}
