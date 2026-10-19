# Ordinary bounded workload research

This is an **unadopted experiment**, separate from the old Ethereum/Solana
contracts, public ABI, SAGE 0.10.0, Registry authority and conformance verdicts.
It qualifies a candidate abstract storage layout and measures a normal signature
component. It is not a Registry implementation, operational Source, deployment,
transaction generator, adversarial client or production dependency selection.

The fixed public test-seed recipe creates 128 distinct Ed25519 keys and ordinary
self-signatures with Node's built-in crypto. No credential is read or exported.
Every challenge is 242 bytes: existing `sage-pop-0.10.0` domain, five len16 fields,
82-byte fake eip155 Registry context, agent64, key name32, Ed25519 label7 and
raw key32. This uses the existing domain as test data, **not** a future protocol
binding. Fixture URIs are `https://example.invalid/` and are never fetched.
Fixed ASCII record accounting reaches 65513 bytes with 16 services; hypothetical
terminal state/uint64-max version is 65536. The small ASCII-only sorted JSON
function is not a general RFC 8785 serializer or an executed admission rule.
The proposed headroom restriction requires explicit future versioned adoption.

`Storage.sol` is abstract and requests only ABI (empty) and storageLayout, never
runtime bytecode. An independently authored inventory checks four roots,
six structs/28 fields, exact slots/byte offsets/sizes and all 25 reachable types.
Paris and Shanghai outputs are retained separately; unit compiler artifacts
use a separate unit- namespace and the same matrix fork. The receipt gate
binds both compiler generations, runtime hashes and exact code-hash substitution. This does not exercise
storage writes, mapping membership, history, claim logic or serialization.

`Batch.sol` is a build template for a research-only view wrapper, accepting
1..128 tuples of key32/message242/signature64. It calls a fixed verifier address
0x1000 with an exact compiled runtime code hash substituted once into the
compiler input. There is no caller-supplied target/hash, fallback, registration,
authorization, claim, grant or mutation operation. The original
`../registry-ed25519/StrictEd25519.sol` and pinned SHA-512 sources are unchanged;
original notices/licenses are included. Previous audits do not cover the new
wrapper or new arithmetic, and no valid full S=0 equation fixture is added.

A new EthereumJS VM is created for each owned case. Strict verifier and wrapper
runtime code are **installed directly into local VM accounts**, without CREATE,
public RPC, chain deployment or a transaction. Each STATICCALL gives the proof
its own memory context; this cost measures that specific composition, not an
inlined verifier or a selected production external-code trust dependency.
There are normal one-proof and 128-proof **single calls**, plus seven finite
unit controls for input dimensions and absent code. No forged signature,
attacker traffic or host bypass is generated. Compiler decoding, memory
allocation and out-of-gas can precede wrapper returns; these are not claims of
complete canonical ABI guards or specified Registry custom-error priority.

The predeclared experiment cap is 1,000,000,000 gas per runCode, and the
per-proof STATICCALL cap is 15,000,000. These are not operating network budgets.
Gas is actual isolated runCode execution; there is no ordinary transaction
initial access-list/precompile warming setup. It excludes intrinsic calldata,
creation/deployment, full Registry decoder/authorization/claims/storage,
retained command/history, canonical record generation, finality and migration.
Do not extrapolate one-proof gas or call this the complete maximum Registry cost.
Normal one-proof and finite unit wrapper PCs are traced. Full-count instruction
tracing is disabled and declared per row. Coverage is new wrapper mapped
start-line observation, not cryptographic, branch, or full-count verifier
coverage. Old verifier qualification remains in its unchanged CI workflow.

CI runs each fork separately, with fresh locked dependencies, bounded Node
memory and a 40-minute deadline. Node line coverage covers new runtime/tools
(the unit harness is excluded), and wrapper mapped-line coverage must each
reach 90%. Fixtures, exact calldata, compiler inputs/outputs, runtime hashes,
execution return/exception/gas/timing, coverage, dependency tree and source/run
receipts are uploaded. Check actual PR **and** main artifacts independently;
a green artifact or abstract type check creates no new conformance verdict.

Run in this directory after `npm ci --ignore-scripts` and the unchanged old
`python3 ../registry-ed25519/prepare.py`. `node --test unit.mjs` runs artifact
unit tests. `SAGE_EVM_FORK=paris node evaluate.mjs` performs the ordinary workload;
use CI for full-count work. Full Registry cost, usable finality Source,
standards integration, compatibility, version/profile/domain/adoption and
matching core/Inspector work remain open in the existing stage7/8 order.
