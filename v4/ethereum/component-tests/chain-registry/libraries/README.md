# Registry library controls

These fixed units exercise the Registry libraries directly from
`ethereum/contracts/chain-registry`. They do not deploy a Registry, authenticate
an agent, or establish an operating chain budget.

The groups are text, buffer, JSON serialization, domain framing, grammar,
lifecycle and grants, entry structure, SHA512, and strict Ed25519 verification.
The tests compare complete return or error bytes on Paris and Shanghai, using
separate ordinary and coverage builds. Coverage is a contained AST/source-map
observation, not branch coverage or a Registry conformance result. Coverage
tracing uses only bounded control inputs; production calls have no step hook.

The verifier's 48 fixed cases comprise 35 `RegistryEd25519` cases, two derived
backend controls, and eleven derived arithmetic controls. A test control is not
an additional production verifier. The owned signature fixtures use disclosed
deterministic test seeds and ordinary signing. Fixed defensive data are not
accompanied by a forgery, hostile callback, or remote submission generator.

Source paths and two vendor imports changed during integration. Earlier scratch
results do not qualify this layout. Source review, fresh local tests and actual
CI artifact checks are required before accepting this integrated version.
