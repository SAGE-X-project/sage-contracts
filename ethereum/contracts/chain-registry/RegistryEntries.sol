// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {IChainRegistry} from "./IChainRegistry.sol";
import {RegistryJson} from "./RegistryJson.sol";
import {RegistryGrammar} from "./RegistryGrammar.sol";

/// @notice Candidate structural entry checks for bounded prospective Registry state.
/// @dev Not an authority or proof boundary. No storage, external call or admission.
/// Call rank3 scalar checks before lookup/authority; rank8 targets only after the
/// actual caller, lifecycle/predecessor and trusted admission time are checked.
library RegistryEntries {
    function keyScalars(IChainRegistry.KeyInput memory entry) internal pure {
        RegistryGrammar.name(entry.name, false);
        ascii(entry.alg, 24);
        if (entry.key.length > 65) revert IChainRegistry.BoundsExceeded();
        ascii(entry.signer, 189);
        if (entry.proof.length > 65) revert IChainRegistry.BoundsExceeded();
        if (entry.expires > 9007199254740991) revert IChainRegistry.InvalidEntry();
        if (!entry.hasExpiry && entry.expires != 0) revert IChainRegistry.InvalidEntry();
    }

    function serviceScalars(IChainRegistry.ServiceInput[] memory entries) internal pure {
        if (entries.length > 16) revert IChainRegistry.BoundsExceeded();
        for (uint256 i; i < entries.length; ++i) {
            RegistryGrammar.name(entries[i].name, false);
            RegistryGrammar.serviceType(entries[i].serviceType);
            RegistryGrammar.httpsUri(entries[i].uri);
        }
    }

    /// @dev Caller supplies accepted initial wrappers, already scalar-checked.
    function createTargets(RegistryJson.Record memory proposed, uint64 admitted) internal pure {
        if (proposed.keys.length == 0) revert IChainRegistry.InvalidEntry();
        if (proposed.keys.length > 128) revert IChainRegistry.BoundsExceeded();
        // Finish all lifetime-name equality checks before any inversion check.
        for (uint256 i; i < proposed.keys.length; ++i) {
            for (uint256 j; j < i; ++j) {
                if (equal(bytes(proposed.keys[i].input.name), bytes(proposed.keys[j].input.name))) {
                    revert IChainRegistry.KeyNameReused();
                }
            }
        }
        for (uint256 i = 1; i < proposed.keys.length; ++i) {
            if (compare(bytes(proposed.keys[i - 1].input.name), bytes(proposed.keys[i].input.name)) > 0) {
                revert IChainRegistry.InvalidEntry();
            }
        }
        for (uint256 i; i < proposed.keys.length; ++i) {
            for (uint256 j; j < i; ++j) {
                if (equal(proposed.keys[i].input.key, proposed.keys[j].input.key)) {
                    revert IChainRegistry.KeyMaterialReused();
                }
            }
        }
        serviceTargets(proposed.services, proposed.keys);
        for (uint256 i; i < proposed.keys.length; ++i) {
            if (proposed.keys[i].state != RegistryJson.KeyState.Accepted) revert IChainRegistry.InvalidEntry();
            entryStructure(proposed.keys[i].input, proposed.keys, proposed.did, admitted);
        }
    }

    function addTargets(RegistryJson.Record memory current, IChainRegistry.KeyInput memory entry, uint64 admitted)
        internal pure
    {
        if (current.keys.length >= 128) revert IChainRegistry.BoundsExceeded();
        for (uint256 i; i < current.keys.length; ++i) {
            if (equal(bytes(entry.name), bytes(current.keys[i].input.name))) revert IChainRegistry.KeyNameReused();
        }
        for (uint256 i; i < current.keys.length; ++i) {
            if (equal(entry.key, current.keys[i].input.key)) revert IChainRegistry.KeyMaterialReused();
        }
        for (uint256 i; i < current.services.length; ++i) {
            if (equal(bytes(entry.name), bytes(current.services[i].name))) revert IChainRegistry.InvalidEntry();
        }
        entryStructure(entry, current.keys, current.did, admitted);
    }

    function serviceTargets(IChainRegistry.ServiceInput[] memory services, RegistryJson.Key[] memory lifetimeKeys)
        internal pure
    {
        for (uint256 i; i < services.length; ++i) {
            if (i > 0 && compare(bytes(services[i - 1].name), bytes(services[i].name)) >= 0) {
                revert IChainRegistry.InvalidEntry();
            }
            for (uint256 j; j < lifetimeKeys.length; ++j) {
                if (equal(bytes(services[i].name), bytes(lifetimeKeys[j].input.name))) {
                    revert IChainRegistry.InvalidEntry();
                }
            }
        }
    }

    /// @dev Required suite only. Optional algorithms have no qualified backend
    /// here and are refused before representation checks, never substituted.
    function entryStructure(
        IChainRegistry.KeyInput memory entry,
        RegistryJson.Key[] memory sameRecord,
        string memory did,
        uint64 admitted
    ) private pure {
        bool signing = equal(bytes(entry.alg), bytes("ed25519"));
        bool kem = equal(bytes(entry.alg), bytes("x25519"));
        if (!signing && !kem) revert IChainRegistry.UnsupportedKeyAlgorithm();
        if (entry.key.length != 32 || entry.proof.length != 64) revert IChainRegistry.InvalidEntry();
        if (signing) {
            if (!equal(bytes(entry.signer), abi.encodePacked(did, "#", entry.name))) {
                revert IChainRegistry.InvalidEntry();
            }
        } else {
            bool found;
            for (uint256 i; i < sameRecord.length; ++i) {
                RegistryJson.Key memory signer = sameRecord[i];
                if (equal(bytes(entry.signer), abi.encodePacked(did, "#", signer.input.name))) {
                    if (!eligible(signer, admitted)) revert IChainRegistry.InvalidEntry();
                    found = true;
                    break;
                }
            }
            if (!found) revert IChainRegistry.InvalidEntry();
        }
    }

    /// @dev Eligibility is meaningful only after the required admission proofs
    /// have been verified. Historical endorsements alone grant no authority.
    function eligible(RegistryJson.Key memory entry, uint64 admitted) internal pure returns (bool) {
        return entry.state == RegistryJson.KeyState.Accepted && equal(bytes(entry.input.alg), bytes("ed25519")) &&
            (!entry.input.hasExpiry || admitted < entry.input.expires);
    }

    function usable(RegistryJson.Key[] memory keys, uint64 admitted) internal pure returns (bool) {
        for (uint256 i; i < keys.length; ++i) if (eligible(keys[i], admitted)) return true;
        return false;
    }

    function ascii(string memory value, uint256 maximum) private pure {
        bytes memory data = bytes(value);
        if (data.length > maximum) revert IChainRegistry.BoundsExceeded();
        for (uint256 i; i < data.length; ++i) if (uint8(data[i]) > 127) revert IChainRegistry.InvalidEntry();
    }

    function equal(bytes memory first, bytes memory second) private pure returns (bool) {
        if (first.length != second.length) return false;
        for (uint256 i; i < first.length; ++i) if (first[i] != second[i]) return false;
        return true;
    }

    function compare(bytes memory first, bytes memory second) private pure returns (int256) {
        uint256 length = first.length < second.length ? first.length : second.length;
        for (uint256 i; i < length; ++i) {
            if (uint8(first[i]) < uint8(second[i])) return -1;
            if (uint8(first[i]) > uint8(second[i])) return 1;
        }
        if (first.length < second.length) return -1;
        if (first.length > second.length) return 1;
        return 0;
    }
}
