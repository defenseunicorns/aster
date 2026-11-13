# Decision 0039: Compose a static Event hierarchy over semantic v6


- Status: Accepted for a bounded hierarchy evaluation profile
- Date: 2026-08-31
- Authority: [data-mesh-requirements.md](../../data-mesh-requirements.md)
- Related: [Decision 0036](0036-mission-authenticated-lan-discovery-mvp.md),
  [Decision 0037](0037-bound-concurrent-lan-scale-baseline.md),
  [Decision 0038](0038-select-an-event-bridge-foundation.md), and roadmap
  action `P2-1`

## Context

The selected Event bridge foundation authenticates directed scope edges,
applies authority and local topic/priority filters, creates nested wrappers
without changing the source envelope, and commits candidate and active route
state through the selected redb authority. It previously had no selected
runtime or transport lane, so it could not demonstrate the hierarchy that is
intended to bound larger deployments.

The existing nearby-discovery adapter also used the default IPv4 multicast
interface. A bridge attached to two isolated IP segments could therefore find
neighbors on only one of them. Supporting a bounded hierarchy requires one
bridge process to browse and advertise on each explicitly selected local
interface without treating any discovered address as membership authority.

## Decision

1. Add semantic protocol version 6 for a typed Event bridge lane. Version 6
   adds canonical bounded Hello, Offer, Result, Finish, and Finished frames.
   Ordinary Event, State, Record, Blob, control, and replication-wire meanings
   remain byte-for-byte those of version 5. A peer without bridge support can
   negotiate version 5 and uses no bridge frames.
2. Enable the lane only when both authenticated mission peers advertise a
   configured static Event bridge role. Control authorization still completes
   before the lane opens, and Event read-policy ownership remains held while
   bridge work is selected and applied.
3. Configure one exact complete authorization chain, a bounded set of locally
   operated directed edges, local topic/priority narrowing, and an optional
   target-delivery role at startup. This is a static evaluation surface, not a
   join/leave or general administration API. A changed control-policy snapshot
   fails the contact closed rather than continuing under mixed policy.
4. Send at most eight routes per direction per contact. A bounded process-local
   cursor rotates selection for each of at most 256 authenticated peers so more
   than eight eligible routes can make progress across repeated contacts.
   Restart may repeat the first bounded batch; exact route identity and durable
   receiver dispositions make that repetition idempotent.
5. Before materializing an offer, require the authenticated peer's mission
   route-grant commitments to authorize the exact target scope and epoch. A
   route for the wrong adjacent scope yields no offer rather than a fatal
   authorization error. This is contact-local least disclosure, not dynamic
   routing or a durable carrier-to-mission binding.
6. On receipt, freshly authenticate the exact wrapper, unchanged source
   envelope, complete authorization chain, target scope/epoch, topic, priority,
   hop continuity, and loop rules before committing. Return a result only after
   the selected store durably records the receiver-local outcome. Route-only
   intermediates never invoke payload opening. A separately content-authorized
   target may open the source payload and emits only its length and SHA-256 in
   the evaluation receipt.
7. Restore retained bridge candidates only after re-verifying the configured
   complete chain and exact route bytes against current provider policy. Stored
   bytes remain nonauthorizing until that promotion succeeds.
8. Extend nearby discovery with an explicit, sorted, deduplicated, bounded IPv4
   multicast-interface selection for multi-homed nodes. Empty selection keeps
   the existing default-interface behavior. Discovery still publishes only
   carrier endpoint data, grants no mission authority, and remains default-off
   and time-boxed.
9. Add one opt-in Docker Compose evaluation with five long-running processes
   across isolated alpha, parent, and bravo IP segments: publisher, two
   route-only bridges, consumer, and a foreign-authority outsider. No peer ID,
   peer address, host port, hosted lookup, or relay is configured. The bounded
   controller requires adjacent automatic discovery, one allowed Immediate
   Event across exactly two bridge hops, no target delivery for a denied topic
   or Routine priority, no payload sentinel in bridge logs, outsider rejection
   before inventory, and peerless consumer restart recovery of the durable
   route.

## Requirement and evidence boundary

The live runtime and repeatable topology strengthen the existing
`implemented-uncredited` mappings for `DM-5.5-09`, `DM-5.5-10`,
`DM-5.5-11`, and `DM-6-08`; no selected status changes. Multi-interface
selection strengthens the existing `DM-5.7-01` discovery mechanism without
changing its status. `DM-5.7-04` mission authentication is unchanged.

Focused tests and a local Compose execution are current-tree development
evidence, not a retained, signed-source execution receipt. They create no
`observed-bounded` credit. This decision does not establish dynamic join/leave,
bandwidth or complete storage quotas, dynamic routing or interest policy,
automatic revocation/rekey handling, cross-class bridges, hostile-discovery
bounds, physical or mixed-implementation operation, 100-node-per-scope or
1,000-node bridged scale, resource fitness, complete MVP, or release
authorization.

## Consequences

- The selected stack now has a tryable automatic-discovery IP hierarchy rather
  than only isolated bridge primitives.
- An authenticated adjacent peer receives only routes it is mission-authorized
  to carry, while exact durable identities make repeated bounded contacts safe.
- Multi-homed nearby discovery is explicit and bounded at Aster's configuration
  boundary; it does not turn mDNS into trust or production discovery.
- The next scale increment can measure bounded hierarchical fan-out and contact
  behavior instead of enlarging one flat multicast domain, while the complete
  `P2-1` lifecycle remains open.
