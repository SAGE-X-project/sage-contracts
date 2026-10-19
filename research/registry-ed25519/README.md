# Raw-key Ed25519 verification evaluation

**UNADOPTED RESEARCH ONLY.** This directory is an isolated feasibility experiment,
not a Registry contract, deployment artifact, SDK API, released verifier or SAGE
conformance result. It does not change SAGE 0.10.0 or existing contract ABIs.
No chain, RPC, wallet, finality source, future domain or operating gas budget is
selected. Do not import this evaluation into production.

The earlier pinned SCL prepared-coordinate verifier does not implement the
required raw-key boundary. This experiment uses newly written complete Edwards
arithmetic around the separately identified upstream SHA-512 component. It does
not remove an upstream S==0 guard and call the result a strict verifier.

The boundary accepts exactly A32, original message bytes and R||S64. It decodes
canonical points, rejects identity, checks [L]A and [L]R without scalar reduction,
checks 0<=S<L, hashes original R||A||M and checks [S]B = R+[k]A. Complete addition
handles zero scalars and neutral intermediate points. ModExp uses the fixed EVM
precompile at 0x05 with a bounded call and checks response length and arithmetic
results. No alternate key, algorithm, coordinate, digest or verifier address is
accepted. This is code under review, not a cryptographic correctness proof.

`MAX_MESSAGE_BYTES=1024` is an explicit experimental bound, **not a proposed
protocol limit**. A future selected domain requires rederiving its bounds.
The experiment must not be used to infer support for arbitrary-length Ed25519,
Ed25519ctx/ph, X25519 possession, account authorization or Registry atomicity.

## Reproduce the bounded experiment

Use Node22+, Python3 and curl in this directory:

```sh
npm ci --ignore-scripts
python3 prepare.py
python3 test_evaluation_tools.py
node --max-old-space-size=512 --test --experimental-test-coverage --test-coverage-lines=90 --test-coverage-include='**/evaluate.mjs' --test-reporter=spec --test-reporter-destination=stdout --test-reporter=lcov --test-reporter-destination=evidence/js-coverage.lcov evaluate.mjs
python3 check_source_coverage.py
```

No environment file, live key, RPC, deployment script, listener or upstream
vector generator is loaded. All remote inputs in prepare.py have fixed URLs
and SHA-256 checks. The local EVM runs supplied runtime bytecode with runCode;
it does not deploy or broadcast a transaction. The Mainnet/Paris and Shanghai
parameter sets are evaluation fixtures, not selected operational chains.

The VM execution cap is fixed at 15,000,000 gas before measuring. Exhaustion or
backend failure never becomes success, and the cap is not raised to pass.
Execution gas excludes transaction/calldata intrinsic costs, creation, Registry
storage/history, chain-specific pricing and the final full-key-count workload.
Wall-clock timings include the JS observer and are not production latency.
Only finite ordinary signatures use the runtime group. Rejections, absent/bad
backends and arithmetic controls are isolated fixed unit scenarios; no exploit
client, forgery generator, host bypass or external target is supplied.

Three published RFC8032 signatures and deterministic public test keys supply
normal input; Node's independent Ed25519 implementation checks these inputs.
Binary sizes47/48/117/175/176/241/242/1024 exercise SHA-512 transitions and the
previous 0.10.0 PoP size range. They are not newly assigned future challenges.
Mixed-order point components are fixed data from an identified research case,
used independently with unrelated normal signature components only for rejection.
Separate point-only unit observations must show successful decoding, nonidentity
and failed [L] membership for both mixed components. Prime-order A and R calibrate
the same observer positively; identity, order-four and non-point controls are
reported separately. A final signature mismatch alone cannot prove this gate.
The original research generator and complete edge-case exchanges are not run.

`evidence/` retains exact standard-JSON inputs/outputs, source/tool identities,
case fixtures, raw call outcomes, per-case gas and visited opcode PCs. Coverage
is compiler-source-map start-line coverage of the new Solidity file, excluding
container ranges; it is not branch coverage, a proof or upstream library
coverage. Require at least90% before accepting the experiment's CI evidence.
The JS runner additionally uses Node's built-in executable-line coverage and LCOV;
the two Python tools use offline error/cache/source-map unit scenarios and stdlib
trace executable-line coverage. Each new execution tool must reach90% separately.
These measurements do not establish branch or cryptographic correctness.
A complete new-protocol assessment still requires independent semantic/vector
review, exact final CI artifacts and a separate versioned adoption decision.

## Unfinished gates

A positive valid-zero-scalar signature fixture is NOT_RUN: zero-scalar arithmetic
and failure of an unrelated zero-scalar signature are separate evidence. Full
Registry creation/add-key/endorsement/storage/history, all128-key costs, custody,
source/finality, compatibility and code/deployment identity remain NOT_RUN.
No old FAIL/PARTIAL/NOT_RUN finding is promoted by this experiment.

See [source notices](SOURCE-NOTICES.md) for source and test-data provenance.
