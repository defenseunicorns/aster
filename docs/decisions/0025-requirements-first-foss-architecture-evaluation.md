# Decision 0025: Run a requirements-first FOSS architecture evaluation

> ****

- Status: accepted — evaluation governance only; no implementation selected
- Date: 2026-08-22
- Proposal: [0005](../../archive/research/proposals/0005-requirements-first-foss-architecture-evaluation.md)
- Requirements baseline:
  [`data-mesh-requirements.md`](../../data-mesh-requirements.md), SHA-256
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Project provenance: SRC-001, SRC-002, BVB-644 through BVB-694, plus
  earlier candidate records referenced by Proposal 0005

## Context

The current Aster implementation is experimental and incomplete. Earlier IP
experiments answered whether Iroh or rust-libp2p fit boundaries already chosen
inside that implementation. They did not answer which FOSS composition best
satisfies the requirements if those boundaries, wire formats, stores, APIs,
and ownership choices are disposable.

Several prior decisions also classified broad areas as Aster-owned mission
semantics before whole-stack substitutes had been systematically evaluated.
Those records remain valid descriptions of the work and evidence that produced
them, but they must not make the existing implementation its own selection
criterion.

The bracketed operating figures in the requirements are stakeholder-validation
placeholders. Treating values such as offline duration, link rate, loss, node
count, RAM, or binary size as non-compensable candidate screens would turn
working assumptions into product requirements.

## Decision

Run Proposal 0005 as a greenfield, requirements-first evaluation whose objective
is to buy the largest coherent share of the stack from maintained FOSS and
published standards while minimizing residual bespoke semantics and assurance
work.

For this evaluation:

1. The registered requirements document is the sole product authority. Current
   Aster wire bytes, APIs, schemas, stores, module boundaries, host/session
   ownership, and migration convenience have zero selection weight.
2. Compound requirements are atomized before scoring. Binding capabilities and
   correctness/security invariants remain mandatory for a final composition;
   bracketed quantities are swept and reported as capability curves and
   breakpoints.
3. Candidate discovery covers whole stacks and deliberate compositions, not
   only replaceable seams inferred from Aster. Replica/convergence,
   delay-tolerant dissemination, connectivity, security, persistence, policy,
   carriers, embeddings, and conformance each receive an explicit owner.
4. Iroh, idiomatic rust-libp2p, and one frozen greenfield-native FOSS
   composition are all eligible connectivity candidates. None must preserve the
   accepted `MeshHost` boundary or current Aster discovery, wire, or durable
   node design to receive credit.
5. A candidate receives FOSS deletion credit only for behavior actually owned
   by an exact shipped component. A standard without a usable implementation,
   a wrapper that leaves duplicate custom machinery, or an upstream capability
   claim without executable evidence is recorded separately.
6. Missing behavior is initially a composition delta, not an automatic
   rejection. Early elimination is limited to intrinsic semantic
   contradiction, prohibited licensing, or an objectively unusable
   maintenance/security posture. Production admission remains subject to the
   dependency gates in Decision 0002.

Decisions 0014 and 0015 remain the total-assurance and mechanism-deletion rules,
but their existing boundary dispositions do not constrain Proposal 0005's
greenfield candidate model. Decisions 0022 through 0024 remain append-only
evidence about their exact Aster-shaped experiments; their `MeshHost`, native
rollback, shared-node, and provider-ordering choices are not eligibility or
selection gates here.

## Project execution controls

- Register every public standard, repository, release, license, advisory, and
  documentation page in `evidence/SOURCE_REGISTER.csv` before consultation or
  use. A retrospectively registered discovery receives no factual credit until
  a post-registration re-review is recorded.
- Research artifacts cite source-register IDs and distinguish upstream claims,
  documented behavior, local demonstrations, hostile/fault evidence, and
  cross-implementation evidence.
- The common harness is newly written from the registered requirements. It may
  drive public candidate APIs but must not copy candidate implementation source
  or use current Aster behavior as the architecture oracle.
- Executable spikes use isolated, exact-pinned source freezes with license,
  security-channel, advisory, locked-graph, SBOM, feature-surface, and removal
  records. Inclusion in the candidate register is not dependency admission.
- Earlier records are never rewritten or deleted. Corrections and changed
  dispositions are appended with provenance.

## Consequences

- Proposal 0004 may continue independently. Its results are component
  characterization only unless they map to a normalized requirement and retain
  their original experimental scope.
- The first executable comparison targets whole-stack disproof: p2panda-native,
  p2panda operations over BPv7, interactive p2panda sync over BPv7, and a thin
  data profile over BPv7. The portfolio remains open until Phase 0 discovery is
  complete.
- Connectivity selection follows or composes with the surviving
  replica/dissemination designs, so a provider is not rejected merely because
  it would require changing Aster.
- This decision changes evaluation governance only. It changes no product
  behavior, requirement status, release claim, or production dependency.
- Any selected architecture requires a later decision with exact composition,
  measured evidence, residual bespoke work, migration/deletion plan, and
  production admission disposition.

## Proposal 0004 disposition — 2026-08-23

The permission for Proposal 0004 to continue independently is now exhausted.
Its provider-free Gate-H prerequisite passed, but neither eligible arm reached
a formal comparative Phase-0/Phase-1 result and later phases did not run.
[Decision 0029](0029-close-proposal-0004-libp2p-pilot.md) closes it with no
provider selected. Historical component characterization remains bounded
evidence and supplies no selection or production credit.
