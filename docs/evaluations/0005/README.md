# Evaluation 0005: requirements-first FOSS architecture frontier

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.


Status: **all currently executable research arms have a registered terminal
disposition, but the Phase 0 work-order omissions and Phase 2
architecture-collapse gaps remain explicit. The program is not fully conformant
to its work order, and no production stack or dependency is selected.**

Requirements baseline SHA-256:
`e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`.

The sole product authority is
[`data-mesh-requirements.md`](../../../data-mesh-requirements.md). Existing
implementation, compatibility, migration effort, and module boundaries have
zero selection weight. Bracketed values—including offline duration, loss,
rate, memory, binary size, item count, and priority count—are decision curves,
not automatic elimination gates.

## Start here

- [`final-frontier.md`](final-frontier.md) — current Pareto frontier, buy/build
  map, deletion decisions, and residual hard work
- [`final-stack-bakeoff.md`](final-stack-bakeoff.md) — decisive A-versus-G
  integrated comparison and bounded baseline recommendation
- [`arm-completion-register.md`](arm-completion-register.md) — every bounded
  arm, its current state, and primary evidence
- [`responsibility-map.md`](responsibility-map.md) — one-owner map across the
  complete stack
- [`candidate-register.md`](candidate-register.md) — systematic candidate,
  standard, component, daemon, oracle, hold, and exclusion register
- [`rolling-results.md`](rolling-results.md) — append-only human-readable
  checkpoints through the terminal topology result
- [`requirements-matrix.csv`](requirements-matrix.csv) and
  [`requirements-notes.md`](requirements-notes.md) — 348-cell atomic authority
  decomposition

## Outcome in one page

The final integrated comparison has selected a bounded research baseline:
**Iroh 1.0.3 + Negentropy 0.5.1 + redb 4.2.0 under an explicit
requirements-owned profile**. The G corpus completed divergent reconciliation,
restart, A-absent temporal carry, both crash windows, no duplicate fixture
effect in the registered recovery, and final duplicate no-op (`BVB-922`,
`BVB-948`). This is not a general exactly-once guarantee. It is not a
production selection; four-class semantics, policy, security lifecycle, Blob
lifecycle, physical/target qualification, and independent conformance remain.

The p2panda-centered path retains component and oracle value, but is no longer
the default high-level whole-stack finalist. Its first integrated run reached
native LogSync/Iroh, restart, temporal carry, and both crash checkpoints, then
timed out during recovery (`BVB-932`). A materially different fixed-requested-
port diagnostic stopped earlier with sender-reported success and receiver-side
timeout (`BVB-941`). Neither completed the recovery-without-duplicate-effect
and post-ack sequence.

B1—immutable p2panda operations over BPv7—is conditional on BP proving a named
hard delta worth duplicate durable owners. B2 interactive sync over BP is a
stop/cost arm. BP plus a thin profile remains a standards-first control. Zenoh,
Willow, and Veilid retain component or oracle roles rather than whole-stack
finalist status.

The IP result is similarly bounded. Iroh 1.0.3 passed relay-first, direct
upgrade, ping, and close for all 13 upstream-supported Patchbay namespace/NAT
pairings. The three upstream-ignored hard-cross pairings stayed relayed and did
not upgrade. This is one-kernel simulation with an insecure local test relay,
not physical, public-Internet, identity/security, endurance, or production
evidence.

## Work-order accounting

| Phase | Terminal accounting | Important limit |
|---|---|---|
| 0 — normalize, search, freeze, preregister | **Partial** | Requirements, portfolio, freezes, admission screens, and responsibility maps exist. A complete greenfield-native discovery/NAT/relay/runtime/resource freeze, reproducible ordinal anchors, and preregistered per-arm engineer-day caps do not. These omissions cannot be reconstructed after execution. |
| 1 — protocol surfaces and first disproofs | **Bounded complete** | Every selected surface has an executed, source-only, component, stop, failure, or unimplemented disposition. The p2panda prune/restart case failed, and the independent profile later exposed a specification gap. |
| 2 — connectivity and architecture collapse | **Mixed/partial** | The common local differential and Iroh topology simulation are terminal. Iroh has executable local/topology evidence; rust-libp2p remains a source/behavior oracle on advisory, discovery, and connection-ownership hold; Quinn/greenfield remains a narrow local control with no complete NAT/relay owner. No higher-level architecture-collapse runtime was completed for the latter two lanes. |
| 3 — cross-product and dissemination composition | **Bounded complete** | The p2panda/greenfield × Iroh/Quinn opaque manual-loopback matrix passed 4/4, and B1/B2/C have distinct dispositions. No topology orthogonality or reconciliation-over-carrier credit follows. |
| 4 — integrated security | **Bounded feasibility complete** | The non-FIPS integrated corpus is terminal; normative hybrid design, distribution, rollback resistance, independent interop, physical capture, and validated production operation remain unproved. |
| 5 — carrier, conformance, SDK, and assurance | **Mixed terminal** | Host sweeps and product-surface checks ran. Physical BTLE is environment-blocked, two broadcast cells failed, independent parsing found a profile defect, license inventory failed, and Kotlin/local-agent cells were environment-blocked. |

Proposal 0005 is therefore closed as a research work order with dispositions
and recorded misses, not certified as fully executed. Under `BVB-865`, a
discarded synthesis thread surfaced excluded Proposal 0004 fragments through a
faulty search glob. That thread was contained, its output receives zero credit,
and no Proposal-0004-derived conclusion is accepted here; owner/counsel
disposition remains external. `BVB-909` separately records a contained final-
audit allowlist failure that exposed excluded-subtree paths and row-width
diagnostics only; the auditor made no post-exposure edit and every conclusion
from that command onward was discarded. Clean replacement validation is
required, and external disposition remains pending.

## Evidence index

### Whole stacks and temporal dissemination

- [`p2panda-freeze.md`](p2panda-freeze.md)
- [`p2panda-temporal-relay.md`](p2panda-temporal-relay.md)
- [`p2panda-phase1-closure.md`](p2panda-phase1-closure.md)
- [`bpv7-freeze.md`](bpv7-freeze.md)
- [`bpv7-hardy-temporal-relay.md`](bpv7-hardy-temporal-relay.md)
- [`dissemination-composition-arms-bvb724.md`](dissemination-composition-arms-bvb724.md)
- [`zenoh-arm-d.md`](zenoh-arm-d.md)
- [`willow-arm-e.md`](willow-arm-e.md)
- [Veilid component disposition](candidate-register.md)
- [`greenfield integrated control`](final-stack-bakeoff.md)
- [`semantic/carrier cross-product`](rolling-results.md)
- [`final A-versus-G bakeoff`](final-stack-bakeoff.md)
- [`machine-readable final comparison`](results/stack-comparison.json)

### Security and membership

- [`security-responsibility-residual.md`](security-responsibility-residual.md)
- [`security-profile-matrix.md`](security-profile-matrix.md)
- [`coset-hybrid-source-object.md`](coset-hybrid-source-object.md)
- [`openmls-disconnected-membership.md`](openmls-disconnected-membership.md)
- [`group-oscore-implementation-freeze.md`](group-oscore-implementation-freeze.md)
- [`aws-lc-provider-feasibility.md`](aws-lc-provider-feasibility.md)
- [`t-cose-source-object-freeze.md`](t-cose-source-object-freeze.md)
- [`integrated-security-profile.md`](integrated-security-profile.md)

### Connectivity, discovery, and carriers

- [`connectivity-comparison.md`](connectivity-comparison.md)
- [`discovery-admission.md`](discovery-admission.md)
- [`carrier-arm.md`](carrier-arm.md)
- [Iroh/Patchbay connectivity observation and image provenance](results/iroh-patchbay.json)

### Replaceable components and product surface

- [`durable-store-component.md`](durable-store-component.md)
- [`record-crdt-automerge.md`](record-crdt-automerge.md)
- [`reconciliation-negentropy.md`](reconciliation-negentropy.md)
- [`blob-transfer-operating-envelope.md`](blob-transfer-operating-envelope.md)
- [`propagation-policy-component.md`](propagation-policy-component.md)
- [`sdk-ffi-control-plane.md`](sdk-ffi-control-plane.md)
- [`conformance-profile-seed.md`](conformance-profile-seed.md)
- [`phase5-product-surface-assurance.md`](phase5-product-surface-assurance.md)

## Public record and maintained checks

The public evaluation record retains decisions, positive and negative findings,
claim limits, selected result summaries under [`results/`](results), and the
exact research requirement maps under [`requirement-maps/`](requirement-maps).
Raw execution logs, downloaded sources, one-off build recipes, candidate
harnesses, and historical control ledgers are retained separately.

The maintained differential corpus lives in
[`conformance/evaluation-v0`](../../../conformance/evaluation-v0/README.md).
`mise run conformance-profile-v0-r2` builds and checks that corpus. Historical
validation counts and source hashes describe their dated archived snapshots;
they are not assertions about the reduced public tree or new test executions.

## Research versus selection

Terminal research accounting means every currently executable arm has an
advance, conditional, component, hold, oracle, exclusion, failure,
environment-blocked, or stop disposition. It does not repair the Phase 0
preregistration omissions or the Phase 2 architecture-collapse gaps, and it
does not grant production readiness. Physical cross-host discovery/NAT/relay,
BTLE hardware, radio silence and energy, complete security/FIPS composition,
full class and crash semantics, second spec-built interoperability, production
dependency admission, packaging, and stakeholder choices remain
selection/release gates.

The next work should harden the selected G research baseline: one durable
reconciliation/acceptance owner, the normative four-class profile, integrated
security and policy, Blob lifecycle, hostile/power-loss recovery, real
topology and physical carriers, targets, scale/endurance, and an independent
implementation. P2panda and BPv7 remain differential controls. Do not restart
a broad FOSS survey unless a concrete new candidate, upstream change, or named
hard requirement invalidates the current comparison.
