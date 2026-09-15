# Decision 0024: Refactor durable node ownership before selecting an IP provider

> ****

- Status: accepted — no provider selected
- Date: 2026-08-21
- Follow-on experiment: [Proposal 0004](../../archive/research/proposals/0004-shared-node-libp2p-retest.md)
- Requirements baseline:
  [`data-mesh-requirements.md`](../../data-mesh-requirements.md), SHA-256
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Preserves: Decisions [0002](0002-dependency-admission.md),
  0014 (“Build versus buy is governed by total assurance cost”; privileged local
  record, not part of this repository artifact),
  0015 (“Delete custom mechanism behind narrow library-backed seams”; privileged
  local record, not part of this repository artifact),
  [0022](0022-ip-mesh-experiment-no-selection.md), and
  [0023](0023-mesh-host-contract-no-libp2p-selection.md)

## Context

Proposal 0003 compared the native LAN control, core Iroh, and rust-libp2p
through the accepted provider-neutral `MeshHost` boundary. All three arms failed
the mandatory Phase 1 architecture gate for the same reasons:

- every contact independently opens and replays the durable node, backend, and
  blob store before fresh Aster authentication, so a carrier-authenticated
  hostile peer can trigger expensive SQLite, control, and blob work without a
  hard pre-authentication deadline;
- contacts open independent authorities over the same durable state. Blob quota
  counters are per instance, control/rekey/revocation state can remain stale
  across live contacts, and the existing fanout refreshes inventory only; and
- memory limits are contact-local rather than node-global. Approximately 8 MiB
  can be reserved per inbound contact, permitting about 64 MiB at the default
  eight-contact bound and about 2 GiB at the configured maximum of 256, before
  provider and runtime overhead.

These are Aster composition defects, not evidence that one carrier library is
intrinsically unsafe or slow. Because every arm failed a non-compensable Phase 1
gate, the NAT, relay/path-change, impairment, hostile-input, and scale phases
were stopped. Later fixed-LAN runs are characterization only. In those runs the
libp2p profile had a smaller graph, binary, memory footprint, and link cost than
the Iroh profile and passed the isolated live Aster custody-chain trials;
neither upstream adapter completed the 64 KiB transfer characterization. No
connectivity-relay path was exercised.

## Decision

Select **none** of the Proposal 0003 arms as Aster's production IP provider.
Reject and remove the experimental Iroh and rust-libp2p adapters, their features,
and their dependency graphs from the continuing source graph while retaining
their signed checkpoints and append-only evidence.

Retain the provider-neutral `MeshHost` contract and the native implementation as
a bounded LAN control, rollback target, and demonstration path. It is not a
production NAT, discovery, or connectivity-relay profile.

Before another provider comparison, refactor the runtime so that one process
owns and opens exactly one durable `Node`, backend, and blob-store authority.
Contacts become cheap, bounded session objects borrowing that authority. A
transactional admission barrier must authenticate and revalidate the peer before
durable replay, synchronization, or mutation, and must enforce one coherent
node-global budget for pre-authentication work, deadlines, contacts, streams,
frames, memory, and durable capacity. Inventory, control, rekey, revocation, and
quota changes must fan out coherently to every active session.

The rollback gate **passed for both rejected external providers**: independent
libp2p and Iroh partial stores resumed through the same provider-neutral seam on
the native path, preserved their original item identities through A→B→C custody,
and reached application acknowledgement. Native is the continuing rollback
target. The rollback supports removal; it does not cure the shared Phase 1
defect.

### Implementation follow-up

Proposal [0004](../../archive/research/proposals/0004-shared-node-libp2p-retest.md) now contains a
provider-free implementation of this decision's shared authority,
transactional admission, generation fanout, and aggregate budget. Its common
supervisor also owns pending-dial capacity and deadlines through settlement,
and treats carrier identities and previously bound peer identities only as
scheduling hints; every new contact still requires fresh Aster authentication
and admission.

The formal candidate is compiled from `aster-lab` with defaults disabled,
feature `gate-h`, and binary `aster-gate-h`; the legacy `MeshService` and legacy
CLI features are excluded from that build. This is an implementation milestone,
and signed commit `224fd940bc580a2f62dadbaa93a873b38935e10c` now has the
required 25-case/40-command/26-static-check fault receipt plus an independently
validated 10/10 live Gate-H cohort. The evidence accepts the shared-node
baseline and authorizes the corrected provider experiment; this decision still
selects no IP provider and closes no product requirement.

## Requirements traceability

The frozen requirements baseline defines required outcomes, not implementation
architecture ([§1](../../data-mesh-requirements.md#1-project-brief)). This
decision therefore distinguishes the direct obligations below from the Aster
architecture selected to satisfy and verify them. The derived controls are
binding on the next Aster implementation through this decision, but are not
presented as verbatim requirements or as the only theoretically conformant
design.

| Decision element | Direct requirements anchor | Relationship |
|---|---|---|
| Authenticate and revalidate before Aster data exchange | Networks are untrusted ([§3](../../data-mesh-requirements.md#3-operating-environment--assumptions)); peers mutually authenticate before exchanging data ([§5.7](../../data-mesh-requirements.md#57-discovery--peering)); transport security grants no authority, and node identity, revocation, and freshness remain Aster concerns ([§6](../../data-mesh-requirements.md#6-security-requirements)). | Authentication before data exchange is direct. A transactional admission barrier, its placement before durable replay or mutation, and a hard pre-authentication deadline are derived controls for making that obligation enforceable under resource pressure. |
| One durable authority, cheap contact sessions, and coherent state fanout | Reachable nodes converge, durable state survives disconnection, and partial progress resumes with any peer ([§5.2](../../data-mesh-requirements.md#52-synchronization--consistency)); relay quotas are configurable ([§5.5](../../data-mesh-requirements.md#55-scoping--propagation-control)); revocation and rekey propagate through the mesh ([§6](../../data-mesh-requirements.md#6-security-requirements)). | Coherent durable, authorization, and quota outcomes are direct. Exactly one process-owned `Node` and borrowed session objects are the selected remedy for the observed implementation; the baseline does not prescribe a singleton object model. |
| One aggregate resource budget | Relay storage/bandwidth quotas are configurable ([§5.5](../../data-mesh-requirements.md#55-scoping--propagation-control)); Tier-2 binary, RAM, and core targets, near-zero idle cost, low-rate operation, scale, and bounded local storage apply to the node as a whole ([§9](../../data-mesh-requirements.md#9-performance--resource-targets)). | The externally measurable node bound is direct. Budget categories for pre-authentication work, contacts, streams, frames, tasks, descriptors, deadlines, and relay reservations are derived accounting controls needed to demonstrate that bound across concurrent contacts. |
| Provider-neutral seam and a libp2p-first revisit | Transports are pluggable and must not change the protocol ([§5.8](../../data-mesh-requirements.md#58-transports)); the public API does not expose transport selection ([§7](../../data-mesh-requirements.md#7-developer-experience--embeddability)); dependencies must pass governance constraints and well-maintained FOSS is preferred where it meets requirements ([§8](../../data-mesh-requirements.md#8-implementation-constraints)). | The provider-neutral boundary follows directly from those outcomes. The exact `MeshHost` ownership split, native control, and ordering libp2p before Iroh are architecture and evidence-based experiment choices, not product requirements or a provider selection. |
| Authenticated continuity across replacement streams and path/address changes | Nodes move among untrusted transports ([§3](../../data-mesh-requirements.md#3-operating-environment--assumptions)) and peers authenticate before data exchange ([§5.7](../../data-mesh-requirements.md#57-discovery--peering), [§6](../../data-mesh-requirements.md#6-security-requirements)). | Continuing authenticated authority is direct. Fresh Aster authentication on every replacement stream and path/address transition is this decision's conservative acceptance control, not baseline wording; a future design may propose cryptographically bound continuity only if it proves equivalent authorization and revocation revalidation. |

This decision closes none of the associated product requirements. A future IP
profile must still produce acceptance evidence for:

- durable convergence, difference-proportional anti-entropy, and resumable
  contact across peers ([§5.2](../../data-mesh-requirements.md#52-synchronization--consistency));
- infrastructure-free direct sync, intermittent multi-hop custody, and bounded
  duplicate/loop propagation ([§5.6](../../data-mesh-requirements.md#56-peer-to-peer--store-and-forward));
- automatic and manual peering, discovery silence under emission constraints,
  and mutual authentication ([§5.7](../../data-mesh-requirements.md#57-discovery--peering));
- pluggable IP operation across NAT, infrastructure-free traversal where the
  network permits, and relay fallback without making infrastructure a local-mesh
  dependency ([§5.8](../../data-mesh-requirements.md#58-transports));
- end-to-end and metadata protection, identity, revocation/rekey, and replay
  resistance ([§6](../../data-mesh-requirements.md#6-security-requirements)); and
- the Tier-2 resource, idle, impaired-link, 100-node-per-scope, 1,000-node
  bridged-scope, and bounded-storage targets
  ([§9](../../data-mesh-requirements.md#9-performance--resource-targets)), plus
  the corresponding release scenarios
  ([§12](../../data-mesh-requirements.md#12-acceptance-scenarios-illustrative-the-release-must-pass-equivalents)).

The bracketed numeric targets remain stakeholder-validation placeholders under
[§14](../../data-mesh-requirements.md#14-open-items-for-the-team--stakeholders).

## Provider disposition after the refactor

Rust-libp2p is the leading candidate for one contained revisit, but is not
selected by this decision. A new arm must actually exercise Identify, AutoNAT,
circuit relay, DCUtR, and path/address-change reauthentication; resolve the
pre-release `libp2p-stream` surface and the unmaintained `paste` path; pass the
failed payload and all stopped gates; and delete overlapping native production
mechanism rather than leave a permanent dual stack.

Iroh is stopped pending an upstream-supported cap on work before `Incoming`
reaches the host, fresh Aster authentication on path/address migration, project
MSRV compatibility, and resolution of the observed connection-lifecycle
failure. Its larger measured surface is a comparison input, not by itself a
rejection rule.

## Consequences

- No requirement, conformance scenario, MVP status, or release claim changes.
- Native LAN evidence remains valid, but establishes neither controlled NAT
  traversal nor production relay/path recovery.
- Phase 3 and Phase 4 have no result for any arm; they are recorded as stopped,
  not as zero trials or implicit passes.
- Provider activation as an eligible candidate starts only after the shared
  ownership and node-global resource model is independently reviewed and its
  formal provider-free Gate H passes. A provider decision requires the later
  comparison and disposition evidence as well.

## Reconsideration

Reconsider provider selection only with a single process-owned durable authority,
cheap authenticated contacts, transactional admission, coherent node-global
budgets and state fanout, and one exact provider profile that passes every
Proposal 0003 mandatory gate. Performance or dependency advantages cannot
compensate for a functional, authorization, boundedness, or rollback failure.

## Later disposition — 2026-08-23

The provider-free shared-node architecture subsequently passed Gate H, but
Proposal 0004 did not complete its formal corrected-native versus rust-libp2p
comparison. [Decision 0029](0029-close-proposal-0004-libp2p-pilot.md) closes
that proposal with no provider selected. It supersedes this decision's
forward-looking libp2p-first revisit, while preserving the durable-owner,
transactional-admission, aggregate-resource, and provider-neutral architecture
findings above.
