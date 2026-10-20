# SAGE chain Registry components

These components target the adopted [SAGE 0.11.0 management binding](https://github.com/SAGE-X-project/sage-spec/blob/a22a275b4d88f1d415b53cdffc5bed41231b77a0/profiles/sage-0.11.0/registry-management.md).
They do not implement a complete Registry or authorize deployment.

`IChainRegistry.sol` fixes thirteen functions, twenty-two errors and two events
from the pinned public ABI. `RegistryFraming.sol` provides bounded calldata
traversal before application allocation or proof work: whole/method limits,
static heads, tuple/array-relative offsets, counts, field lengths, complete
ranges, scalar padding, zero byte padding and canonical cursor ordering.

An accepting Registry entry point must additionally compare the **complete
canonical ABI re-encoding** and implement the binding's value/context, grammar,
claims, actual caller, lifecycle, grants, proof roles, prospective/final size,
atomic history and finalized Source obligations. Native ABI preemption and its
ordinary failures need separate qualification at that entry point. A framing
success establishes none of those later conditions. No alternate selector,
algorithm, key, Registry or unprotected operation is a permitted fallback.

The tests under `../../component-tests/chain-registry` compile the exact interface and a
pure unit harness for Paris and Shanghai. The source-map observation uses a
separately identified minimally optimized build so optimized-away source
locations are not falsely reported as executed. Every fixed normal/refusal
outcome must equal the build using the proposed production compiler settings.
The metric is source statement observation, not full branch coverage or proof
of equivalent behavior for all inputs. Golden ABI inputs are pinned to the
adopted public revision; maximum-length data tests framing capacity only and
are not valid cryptographic records.

An independent Python unit oracle reconstructs all forty fixed inputs from
the pinned ABI and fixed recipes. Its selectors are frozen public Go ABI
observations, with the source run, artifact and byte digests recorded in
`fixtures/selector-source.json`. The artifact checker joins every case name,
complete input bytes and digest, exact success or error, and both build results
to that contract. Evidence-only unit controls check that changed or missing
observations are rejected; no altered call is executed by those controls.

To run the component checks, install the exact test lock with lifecycle scripts
disabled, resolve the fixed compiler using `python3 prepare.py`, run the Python
compiler-data tests, and run `node --max-old-space-size=512 --test unit.mjs` from
the test directory. This needs Python 3 and Node.js 22 or later. The fixed compiler
is downloaded as data from the official Solidity distribution and hash-checked
before use; upstream installation scripts are never run.

The harness and in-process VM are unit controls. Code installation in that VM
is not a constructor/CREATE or deployed-network test. No transaction, wallet
signature, cryptographic proof, Registry principal, finality policy or live
instance is established. Full Registry, verifier/source/license qualification,
maximum-state costs, runtime/initcode composition and operating Source
connection remain separate acceptance gates. Existing Registry APIs, research
artifacts and SAGE 0.10.0 behavior are preserved.
