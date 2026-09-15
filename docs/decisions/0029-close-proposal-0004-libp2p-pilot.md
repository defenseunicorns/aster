# Decision 0029: Close Proposal 0004 without selecting rust-libp2p

> ****

- Status: accepted — Proposal 0004 closed; no provider selected
- Date: 2026-08-23
- Authority: [`data-mesh-requirements.md`](../../data-mesh-requirements.md)
- Related:
  [Proposal 0004](../../archive/research/proposals/0004-shared-node-libp2p-retest.md),
  [Proposal 0004 result](../../archive/research/proposals/0004-shared-node-libp2p-retest-results.md),
  [Decision 0024](0024-refactor-durable-node-ownership-before-ip-provider-selection.md),
  [Decision 0025](0025-requirements-first-foss-architecture-evaluation.md),
  and [Decision 0027](0027-libp2p-pilot-dependency-policy.md)

## Context

Proposal 0004 began after a shared durable-owner defect prevented a fair IP
provider comparison. Its provider-free shared-node prerequisite passed formal
Gate H. A default-disabled rust-libp2p provider then accumulated useful local
development evidence, but neither eligible arm completed a formal Phase-0
freeze or Phase-1 comparison, and Phases 2–5 did not run.

The subsequent requirements-first evaluation deliberately stopped treating the
experimental Aster architecture as the selection boundary. Proposal 0006
retained a different bounded engineering baseline and stopped broad
whole-stack substitution work. No production stack was selected.

Leaving Proposal 0004 authorized would keep two selection programs open with
different comparison boundaries and would blur a passing provider-free host
prerequisite into provider-selection credit.

## Decision

1. Close Proposal 0004 as superseded before its formal Phase 0 and Phase 1
   comparison. Record **none selected**, not a retroactive pass or failure for
   either eligible arm.
2. Retain the provider-neutral shared-node ownership, transactional admission,
   aggregate-resource, and Gate-H evidence as architecture and test assets.
3. Reject rust-libp2p from the continuing selected-stack implementation,
   default, deployment, release, and production lanes.
4. Preserve the final rust-libp2p checkpoint only as a publish-disabled,
   default-disabled, opt-in test oracle under Decision 0027. It has no provider
   selection or compatibility weight.
5. End new execution under Proposal 0004. Any future rust-libp2p evaluation
   requires a new proposal, exact dependency decision, formal evidence freeze,
   and requirements-normalized acceptance matrix.
6. Treat Decision 0024's libp2p-first revisit and Decision 0025's permission for
   Proposal 0004 to continue as historical, now-superseded forward work. Their
   evidence and provider-neutral architecture conclusions remain valid.

## Retained-oracle boundary

The retained pilot must remain:

- absent from default features and shipping APIs;
- consumed by no workspace package other than the optional dependency activated
  through the opt-in `aster-lab/libp2p-candidate` test feature;
- `publish = false` and outside every production-selection claim;
- governed by the exact reverse-graph, license, advisory, and fuzz exclusions
  in Decision 0027; and
- removed or explicitly reauthorized by 2026-11-23, and before any default,
  release, deployment, or production use.

The provider remains directly buildable as a workspace test package. Explicit
or workspace-wide validation may therefore compile it; that is not activation
by a default or shipping consumer and grants no selection credit.

Changing any of those conditions fails closed and requires a new decision.

## Consequences

- The research program has one continuing selected-stack implementation lane
  rather than an open competing provider-selection proposal.
- Gate H remains a provider-free host result; it is not relabeled as a libp2p
  pass.
- Positive rust-libp2p development tests remain reproducible component
  evidence but confer no requirement, conformance, capability, or production
  status.
- The temporary dependency exceptions remain visible and dated instead of
  becoming silent permanent policy.
- No product behavior, wire format, public API, or production dependency is
  selected by this decision.
