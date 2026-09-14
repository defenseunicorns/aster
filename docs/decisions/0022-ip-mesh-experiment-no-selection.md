# Decision 0022: Do not select an IP mesh substrate from Proposal 0001

> ****

- Status: accepted — no production profile selected
- Date: 2026-08-21
- Preserves: Decisions [0002](0002-dependency-admission.md),
  [0007](0007-ip-and-btle-links.md),
  0014 (“Build versus buy is governed by total assurance cost”; privileged local
  record, not part of this repository artifact),
  0015 (“Delete custom mechanism behind narrow library-backed seams”; privileged
  local record, not part of this repository artifact), and
  0016 (“Tokio owns relay host I/O and scheduling”; privileged local record, not
  part of this repository artifact)

## Context

Proposal 0001 compared a native UDP mesh-host enhancement, core Iroh 1.0.3, a
minimal rust-libp2p 0.56.0 profile, and a narrow Quinn dependency control.

The native, Iroh, and libp2p arms each passed 30/30 clean three-process LAN
store-forward trials. They proved locator-free local discovery, Aster mutual
authentication, route-only durable custody across restart, exact A-authored
ItemID preservation, application acknowledgement, duplicate suppression, and
capture-canary confidentiality in the exercised topology.

None implemented all mandatory operational gates. The common host lacked
manual/pre-provisioned peering, emission-policy linkage, fair 100-peer contact
scheduling, controlled NAT traversal, locally operated connectivity-relay
fallback, and relay-loss reconnection. The deterministic impaired-IP lane was
also blocked because the pinned Linux traffic-control implementation rejected
the required seed. Iroh exceeded the provisional settled-discovery traffic
ceiling. The exact Iroh and libp2p dependency graphs had unresolved advisory
and license-policy findings. Quinn had no runnable host implementation.

## Decision

Select **none** of the candidate arms as Aster's production IP mesh host.

No Iroh, rust-libp2p, or Quinn dependency is admitted by this experiment. The
research implementations and their exact lock state remain preserved by signed
candidate checkpoint
`117770259680d89e5fbd1ff1f6c3df9f3e646e6c` and the project evidence tree;
they are removed from the continuing default source graph after this decision.

Retain the native LAN vertical slice only as a bounded `aster-lab` oracle. It is
evidence that the current Aster data plane works over discovered IP contacts,
not a production capability declaration and not authorization to build custom
NAT traversal or a complete custom overlay without another decision.

The next implementation boundary is a provider-neutral long-lived `MeshHost`
contract owned by Aster. It must define and test:

1. automatic local discovery and manual/pre-provisioned peers as equal candidate
   sources;
2. candidate-to-Aster-identity authentication, cache provenance, expiry, and
   rebinding;
3. bounded concurrent contacts plus fair scheduling when authorized peers
   exceed the active-contact limit;
4. reconnect, address change, backoff, readiness, and operator-visible status;
5. discovery suppression derived from emission policy; and
6. a separately composed, locally controlled NAT direct/fallback profile.

Only after that contract and its executable acceptance fixtures exist may one
upstream connectivity provider be reintroduced for a focused production
comparison. That comparison begins at the failed manual, scheduling, NAT,
fallback, idle, assurance, and rollback gates; it need not rerun the already
established basic LAN custody question except as a regression.

## Consequences

- The application publish/query/subscription APIs remain transport-neutral.
- The Aster handshake, mission authorization, protected envelopes, durable
  store, reconciliation, custody, priority, TTL, and acknowledgement semantics
  remain unchanged.
- The repository does not carry three overlapping optional production stacks
  or their transitive lockfile cost after the experiment.
- No requirement, conformance scenario, MVP status, or release claim is closed
  by the LAN result.
- Iroh's and libp2p's successful LAN results remain legitimate mechanism
  evidence. Their production blockers are not converted into permanent bans.
- Native rendezvous and live relay components remain existing pairwise tools;
  this decision does not relabel them as an operational NAT/contact manager.
- Quinn remains a possible direct-carrier mechanism, not a mesh solution by
  itself.

## Reconsideration

Reconsider this decision only with an exact implementation that passes the
provider-neutral host contract, the Proposal 0001 failed-gate set, current
dependency/security policy, deterministic impairment evidence, mechanism
deletion accounting, and rollback through the same seam. A future decision
must select one production profile or define genuinely non-overlapping
deployment purposes; it may not revive permanent redundant defaults.
