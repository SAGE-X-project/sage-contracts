# SHA512 source provenance

`Sha2Ext.sol` retains the original SCL MIT source and its complete license in
`SCL-LICENSE`. `Sha2Ext.upstream.sol.txt` preserves the original source as text;
it is not a compiler input. Its SHA256 is
`6805690675019ff8e343da59d4cabfc6cc364b733a80cae7829caffdd0ceb19a`.

The implementation's import names the newly written, bounds-checked
`RegistryHashBytes` adapter as `LibBytes`. The relative import path supports the
normal Solidity source layout. The historical mixed-notice `LibBytes` source
is not included or compiled by these libraries.

`RegistryEd25519` derives from this repository's MIT strict raw-key research
implementation. Mathematical parameters and fixed defensive fixtures retain
their research provenance. This source record does not establish an external
audit or complete Registry implementation.
