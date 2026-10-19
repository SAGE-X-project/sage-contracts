# Evaluation source and data notices

The new evaluation Solidity/runner/checker code uses this repository's MIT
license. No upstream signature generator or point-generation code is copied.
Mathematical parameters/complete addition/encoding and the three ordinary test
vectors are referenced to RFC8032, sections5.1.3/5.1.4/5.1.7/7.1:
https://www.rfc-editor.org/rfc/rfc8032.html . No RFC sample implementation is
copied. The RFC's original copyright and applicable IETF Trust terms remain at
that source; this reference does not represent an IETF endorsement.

prepare.py retrieves unmodified SHA-512 sources from
get-smooth/crypto-lib@d714e9824e2e2e44be3c8fd498e0de651ddc9425:
external/sha512/Sha2Ext.sol and external/sha512/LibBytes.sol. Both original file
notices and the SCL LICENSE are preserved. LibBytes retains a ZeroEx Intl.2018
Apache2.0 notice and attribution to 0xProject/exchange-v3@
aae46bef841bfd1cc31028f41793db4fe7197084/contracts/utils/contracts/src/LibBytes.sol,
while its SPDX tag says MIT. The original ZeroEx LICENSE is also preserved.
Do not reclassify this mixed-notice dependency as MIT-only. The earlier source
review's distribution/NOTICE-ancestry and adoption conditions remain open;
fetching for research is not legal clearance or production vendoring approval.
The artifact includes the sources and their original license texts together.

point-components.json contains only the encoded A and R components from case3
of novifinancial/ed25519-speccheck@
65519336fda78a3d016e947df6d82848aca0c9da/cases.json (SHA256
08e47a36d9aead288664930505584f353fff113ab854f2800db1e4f5b3540450).
The study's README identifies those points as mixed-order; neither its generator
nor original message/signature pair is executed. Original copyright/license
text is retained in LICENSES/speccheck-Apache-2.0.txt. These are unit rejection
data, not a replacement for RFC8032, a protocol acceptance oracle or an attack
program. Fixture provenance is not a conformance verdict.
