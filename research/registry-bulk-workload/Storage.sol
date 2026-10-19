// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
// Unadopted storage-layout probe only. No callable Registry logic or deployment.
abstract contract StorageProbe {
    struct Key {
        string name;
        string alg;
        bytes material;
        string signer;
        bytes proof;
        bool hasExpiry;
        uint64 expires;
        bool revoked;
    }
    struct Service { string name; string serviceType; string uri; }
    struct Grant { address operator; uint8 scope; }
    struct History { bytes command; bytes entry; }
    struct Claim { uint256 commitBlock; bool consumed; bool present; }
    struct Record {
        address controller;
        uint64 version;
        uint8 state;
        uint64 admitted;
        Key[] keys;
        Service[] services;
        Grant[] grants;
        mapping(string => bool) usedNames;
        mapping(bytes => bool) usedMaterial;
        mapping(uint64 => History) history;
    }
    uint256 internal configuredChainId;
    string internal registryId;
    mapping(string => Record) internal records;
    mapping(address => mapping(bytes32 => Claim)) internal claims;
}
