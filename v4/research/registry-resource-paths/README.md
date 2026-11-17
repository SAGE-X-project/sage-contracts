# Registry normal-state resource research

This is a cost experiment for the unadopted 0.11.0 candidate. It is **not a
Registry implementation or a conformance result**. Production Ethereum/Solana
contracts, adopted 0.10.0 and previous research receipts are unchanged.

The experiment independently constructs ordinary owned Ed25519/X25519 fixtures
and canonical commands/records/grants/history in Node, then compares complete
returned bytes after every successful mutation. The exact existing strict raw
Ed25519 verifier is compiled with its existing settings and pinned code hash.
New proof/claim contexts use the proposed 0.11.0 domains; old 0.10.0 component
measurements are a separate subject.

## Environment and cost meaning

- Isolated EthereumJS VM with Paris and Shanghai rules and synthetic chain ID 1.
- Code is installed directly in owned VM state. No CREATE, public deployment,
  RPC, broadcast, credential loading or export of signed transaction bytes.
- Ordinary signed type-2 simulated transactions include intrinsic calldata gas,
  cold/warm accesses, state writes and the applicable capped refund. Setup,
  mutations and subsequent view transactions are reported separately. View gas
  is not added to a mutation's transaction cost.
- The block/transaction cap is an **artificial 5,000,000,000 gas experimental
  ceiling**, not an Ethereum operating budget or evidence of network admission.
  Each strict verifier subcall is capped at 15,000,000, not an ERC-1271 budget.
- Test senders use deterministic public recipes, own generated material only.
  The cooperative wallet only calls the fixed local probe and propagates failure.
  It tests actual wallet `msg.sender`, not EIP-712/ERC-1271/payment assurance.

Workloads include initial key counts 1/2/4/8; 128 keys with a 65,513-byte record;
creation at 127 followed by insertion before all existing keys; ordinary wallet
creation with an endorsed X25519 key and lifecycle changes; last usable signer
revocation with an expired key retained; and 128 grant pairs with terminal cleanup.
Public source/compiler/fixture/call/state digests are preserved in CI artifacts.

## Deliberate probe limitations

`PathProbe` composes typed storage, canonical-call equality, actual caller,
commit/reveal window, strict Ed25519 proofs/endorsement, selected lifecycle and
grant changes, retained command/history, serializer, headroom checks and events.
It does not provide the complete production decoder, URI parser, optional
algorithms, all X25519 invalid-point checks, exact error ABI/priority, finality,
Source or optional companion/payment-wallet behavior. `registryIdentifier()`
is a probe selector, not the candidate's production `registryId()` ABI.
Public initialization exists solely for direct local state installation and
must never be deployed. The serializer intentionally accepts ASCII only;
it is not a general Unicode JCS implementation. Current complete-source
bytecode must fit EIP-170 in each measured fork, but this incomplete probe
fitting does not establish that a production implementation will fit.

In particular the probe's serializer/headroom checks occur in `_finish`; it
does not reproduce every prospective-record check before signature verification
and the subsequent final check. Its successful costs therefore cannot be called
the complete atomic candidate's total cost or upper bound. The finite ABI units
include hand-authored word layouts and a standard selector control; call schemas
otherwise come from the probe's compiler ABI, not an independently frozen
production Registry ABI. Events are checked for exact topic and complete data.

Full valid S=0 signature evidence remains NOT_RUN. Selected normal inputs are
not an exhaustive gas bound, rejection contract, security audit or proof that a
count limit suffices as a gas budget. Optional companion and payment costs,
deployment and source/finality costs remain unmeasured. Their adoption requires
separate design and measured operating limits. No algorithm, acceptance set,
cardinality or live deployment is changed by this research.

## Reproduction

The `Registry normal-state resource research` workflow installs the fixed lock
graph without dependency scripts, verifies existing source/compiler/license
digests, runs finite units and normal workloads, and seals actual artifacts.
Full workloads run in CI, not on the user's memory-constrained machine.
For a prepared environment:

```sh
npm ci --ignore-scripts --no-audit --no-fund
python3 ../registry-ed25519/prepare.py
SAGE_EVM_FORK=paris node --max-old-space-size=512 --test --test-concurrency=1 \
  --experimental-test-coverage --test-coverage-lines=90 \
  --test-coverage-include='**/registry-resource-paths/*.mjs' \
  --test-coverage-exclude='**/unit.mjs' --test-coverage-exclude='**/suite.mjs' suite.mjs
```

Compiler-mapped Solidity start-line observations are reported for the new probe,
wallet and codec with a 90% floor. They are not branch coverage, upstream crypto
coverage, exhaustive-input coverage or production Registry correctness.

Cost rules used by the measured forks are specified by
[EIP-2028](https://eips.ethereum.org/EIPS/eip-2028),
[EIP-2200](https://eips.ethereum.org/EIPS/eip-2200),
[EIP-2929](https://eips.ethereum.org/EIPS/eip-2929) and
[EIP-3529](https://eips.ethereum.org/EIPS/eip-3529).
The runtime code-size limit is [EIP-170](https://eips.ethereum.org/EIPS/eip-170).

`seal.py` checks file identity, compiler/PC identity and basic gas accounting.
It does not independently re-execute the VM or certify all state/ABI/coverage
claims. Acceptance also requires read-only rederivation of those joins from
downloaded CI archives and independent review. Paris/Shanghai are qualification
baselines, not current-mainnet fork qualification. In particular this artificial
5-billion-gas ceiling does not implement the post-Fusaka transaction cap in
[EIP-7825](https://eips.ethereum.org/EIPS/eip-7825).
