// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @dev Fixed compiler-derived identities. All-zero tuples MUST reject.
/// Final whole-graph byte identity and constructor qualification remain required.
library RegistryRoleHashes {
    bytes32 private constant PARIS_RENDERER =
        bytes32(0x66a6f6801b73ed655d1e5ae63fed835795b949f5e3ab4bbf4d8f1e4874ac7cfa);
    bytes32 private constant PARIS_VERIFIER =
        bytes32(0x7817e29432af86ac5f676ebdf0f8aa9c4d6a9e428f0367ebaf2ab76c11af03bb);
    bytes32 private constant PARIS_RULES =
        bytes32(0x432bb2d0bff28ad487b5abfa19f56459d95e9e2e025556bec9d178907387bbf3);
    bytes32 private constant PARIS_VALIDATOR =
        bytes32(0x29e2aeef7c12c59bfb4ce96014bfebb67bda3120fb8dc3c046e94dd72a55735e);
    bytes32 private constant PARIS_STOREFACTORY =
        bytes32(0x5705dbecd8ff775308d40cb9828d230a194d301759af3c2d1747cc8c51653a6b);
    bytes32 private constant PARIS_CLAIMFACTORY =
        bytes32(0x005f170b1d7e9d398f8c36661b28f8acadb5484c617fa0527c863336607c43d6);
    bytes32 private constant PARIS_KEYFACTORY =
        bytes32(0xb90e0e0e81e35667a8b8000c109cde3b7c4e64483ee9c8cc27304e7d3976a18f);
    bytes32 private constant PARIS_LIFECYCLEFACTORY =
        bytes32(0xc1bb68aed614bb803b6daa055c4587766dda7ef2aa63f9a950df2185e7e221d7);
    bytes32 private constant SHANGHAI_RENDERER =
        bytes32(0xa889c2ae2ff1b85ba636ca4ade9e0cc2a24bcf4fc19db177ee314463f3f621f7);
    bytes32 private constant SHANGHAI_VERIFIER =
        bytes32(0x45e48088f6118dd71271ae0b572970785fa8251a4b8b9ac80a7d1dd1a8392786);
    bytes32 private constant SHANGHAI_RULES =
        bytes32(0xc9d1ee6136f526cd6afeb42ae81ba3ba4aa49bcc4704032a399feba4453f33f1);
    bytes32 private constant SHANGHAI_VALIDATOR =
        bytes32(0x84aa366d51c290f4953e6d08d2672a74ff331c733c269b7b6f55c7b1c8bcf464);
    bytes32 private constant SHANGHAI_STOREFACTORY =
        bytes32(0x6a968cefd2c32ca3abae0c03eded55e57105f92c37e59944ec4825b041e6309f);
    bytes32 private constant SHANGHAI_CLAIMFACTORY =
        bytes32(0x78b2118f34ccf4bad60a329aeaa0b428c04089f426ebfc766c248f4704c7273d);
    bytes32 private constant SHANGHAI_KEYFACTORY =
        bytes32(0x18fe73c8494c5ca964fe15ed5268ec42d7372b2c6145e4ea09e58696f518fe88);
    bytes32 private constant SHANGHAI_LIFECYCLEFACTORY =
        bytes32(0x07a24ef07ea05b6b87c307cbbcfe77429abad4db189a35a3556382c59743b51b);

    function accepts(address[8] memory roles) internal view returns (bool) {
        bytes32[8] memory p = [
            PARIS_RENDERER,
            PARIS_VERIFIER,
            PARIS_RULES,
            PARIS_VALIDATOR,
            PARIS_STOREFACTORY,
            PARIS_CLAIMFACTORY,
            PARIS_KEYFACTORY,
            PARIS_LIFECYCLEFACTORY
        ];
        bytes32[8] memory s = [
            SHANGHAI_RENDERER,
            SHANGHAI_VERIFIER,
            SHANGHAI_RULES,
            SHANGHAI_VALIDATOR,
            SHANGHAI_STOREFACTORY,
            SHANGHAI_CLAIMFACTORY,
            SHANGHAI_KEYFACTORY,
            SHANGHAI_LIFECYCLEFACTORY
        ];
        bool paris = true;
        bool shanghai = true;
        for (uint256 i; i < roles.length; ++i) {
            if (p[i] == bytes32(0) || p[i] != roles[i].codehash) paris = false;
            if (s[i] == bytes32(0) || s[i] != roles[i].codehash) shanghai = false;
        }
        return paris || shanghai;
    }
}
