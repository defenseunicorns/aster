# Decision 0023: Retain the mesh-host contract without selecting rust-libp2p

> ****

- Status: accepted — host contract retained; no provider admitted
- Date: 2026-08-21
- Amends: [Decision 0022](0022-ip-mesh-experiment-no-selection.md)
- Preserves: Decisions [0002](0002-dependency-admission.md),
  0014 (“Build versus buy is governed by total assurance cost”; privileged local
  record, not part of this repository artifact), and
  0015 (“Delete custom mechanism behind narrow library-backed seams”; privileged
  local record, not part of this repository artifact)

## Context

Decision 0022 required a provider-neutral, long-lived `MeshHost` contract before
another focused connectivity comparison. Proposal 0002 implemented that
contract and reintroduced only rust-libp2p 0.56.0, without libp2p mDNS, a public
DHT, Gossipsub, or public infrastructure.

The host contract passed deterministic boundedness, emission, authentication,
expiry, failover, reconnect, and fairness fixtures. The provider did not pass
the selection gates. It failed clean store-forward trial 14 after 13 passes,
used 1.284% of one core in the settled idle screen, added 50.6% to the binary,
tripled aggregate carrier traffic in the 64 KiB data windows, added 1,082
provider production lines without deleting the 565-line native adapter, and
retained an unmaintained transitive dependency. NAT, circuit-relay, relay-loss,
and address-change lanes were not implemented.

## Decision

Retain Aster's provider-neutral `MeshHost` state-machine contract and tests as
the architecture boundary for future IP host work.

Do not select, admit, or ship the Proposal 0002 rust-libp2p profile. Preserve
its signed checkpoint and append-only evidence, but remove its source and
dependencies from the continuing graph.

Retain the native IP vertical slice as a bounded LAN control only. The next
implementation may connect it to `MeshHost` and improve the local demonstration,
but it may not claim a production mesh until the remaining operational gates
pass.

## Consequences

- Aster owns candidate provenance, Aster-identity binding, emission policy,
  bounded contact scheduling, retry/failover policy, and status semantics.
- A future provider supplies connectivity events and actions; it does not own
  mission authorization, durable custody, synchronization, or application
  delivery semantics.
- The continuing default and optional Cargo graphs contain no rust-libp2p
  dependency from this experiment.
- No requirement, acceptance scenario, or MVP status changes.
- Native LAN evidence remains legitimate but does not establish NAT traversal,
  connectivity-relay fallback, or deployable mesh completeness.
- Another rust-libp2p evaluation requires a long-lived framed-stream design,
  concrete NAT/relay lanes, the current dependency gate, and demonstrated net
  mechanism deletion.

## Reconsideration

Reconsider a provider only when one exact implementation passes all contract
fixtures plus clean reliability, manual and automatic peering, address change,
controlled NAT direct/fallback, relay loss, deterministic impairment, capture,
idle-resource, dependency, rollback, and mechanism-deletion gates. Resource
advantages cannot compensate for a functional or authorization failure.
