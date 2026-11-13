# Decision 0038: Select an Event bridge foundation before the live hierarchy


- Status: Accepted for incremental selected-stack implementation
- Date: 2026-08-31
- Authority: [data-mesh-requirements.md](../../data-mesh-requirements.md)
- Related: [Decision 0028](0028-selected-stack-implementation-boundary.md),
  [Decision 0033](0033-policy-selected-security-profiles.md),
  [Decision 0037](0037-bound-concurrent-lan-scale-baseline.md), and roadmap
  action `P2-1`

## Context

The selected runtime can exchange source-authenticated Events directly and can
admit rosterless nearby peers through mission authentication. A concurrent
same-host diagnostic now exercises the current flat discovery domain through
32 authorized nodes, but larger networks are intended to bound propagation by
composing scopes instead of growing one all-to-all domain indefinitely.

Canonical bridge authorization, wrapping, filtering, hop validation, and
payload-blind provider mechanics already exist in `aster-core`. Their existing
high-level service is coupled to the historical SQLite store and is not a
selected `reference-session` plus `aster-redb-store` surface. Copying that
service or adding a SQLite sidecar would create two durable authorities and
would not establish the selected composition needed by the hierarchy runtime.

A live three-network bridge requires a typed transport lane and node lifecycle
administration. Those are easier to review after the cryptographic and durable
activation boundary is independently explicit and tested.

## Decision

1. Add a public, Event-only profile-`0x0001` selected bridge adapter to the
   SQLite-free `aster-core` `reference-session` composition. The adapter reuses
   the existing canonical bridge model and `BridgeCryptoProvider`; it does not
   expose keys, primitive cryptography, raw provider capabilities, or transport
   framing, and changes neither the semantic nor replication-wire version.
2. Treat edge enrollment, enabled/disabled authorization, first-hop wrapping,
   nested-hop wrapping, and reopened route verification as opaque authenticated
   operations. Public verified values expose only bounded metadata and exact
   sealed bytes required by the durable selected store.
3. Intersect authority topic and priority policy with local narrowing. Local
   policy may only remove authority-granted topics or priority levels. Directed
   scope edges, maximum path length, previous-hop continuity, and repeated-scope
   loop rejection remain canonical core checks.
4. Preserve source end-to-end protection in the selected route-only bridge
   configuration. A route-only provisioned intermediate bridge may authenticate
   route metadata and produce a new target-scope wrapper but cannot open Event
   payload plaintext. A separately provisioned authorized consumer in the
   origin content domain is the only role exercised for payload opening; the
   adapter does not turn a provider that was also granted content access into a
   payload-blind role.
5. Add a separate Event-bridge namespace to `aster-redb-store`. It retains an
   independent contiguous authorization chain, per-edge generation high-water,
   enable/disable state, exact authorization bytes, deduplicated exact source
   bytes, exact wrapper bytes, route dependencies, and a deterministic active
   projection selected by shortest hop count and then route identity.
6. Durable rows are structural candidates, never cryptographic authority. After
   process or store reopen, exact authorization, source, and wrapper bytes must
   be freshly verified by the core adapter and committed against the redb
   authorization high-water before a route can become process-live or be
   returned as current. Cryptographic verification of an incomplete stale
   authorization prefix does not establish current mission policy.
7. Commit authorization activation and source/wrapper/projection state in redb
   transactions under the selected store's existing logical item/byte limits.
   Dependency, identity, generation, quota, or audit failure leaves no partial
   active projection.
8. Keep this increment runtime- and wire-free. The next increment will add the
   typed Event bridge lane, selected node administration, and an isolated
   alpha-to-parent-to-bravo demonstration. It must use this provider-gated redb
   authority rather than importing the SQLite service.

## Requirement and evidence boundary

Passing focused core and redb tests move exactly `DM-5.5-09`, `DM-5.5-10`,
`DM-5.5-11`, and `DM-6-08` from `open` to `implemented-uncredited`. The
`DM-6-08` movement covers the selected payload-blind store/transform mechanism,
not live network forwarding. No row gains `observed-bounded` status because the
tests create no retained or representative execution evidence.

This foundation alone does not establish a supported bridge runtime, joined or
left scope lifecycle, bandwidth scheduling, full storage-pressure behavior,
dynamic policy propagation, revocation/rekey administration, hierarchical-scale
operation, physical networking, independent interoperability, all-class bridge
custody, hostile-input fitness, or complete-MVP acceptance. Current route
verification is linear in the supplied lifetime authorization chain; a bounded
snapshot/current-policy design is required before scale claims. Hierarchical
scope modeling and complete MVP bridge filtering remain open until the live
selected topology exists.

## Consequences

- The selected hierarchy gets one durable authority and one provider-verification
  boundary instead of a new sidecar.
- Route-only provisioned bridge processes remain payload-blind while retaining
  the route metadata needed for exact topic, priority, edge, and loop decisions.
- Restart tests can distinguish persisted candidate bytes from freshly
  authenticated process-live routes.
- The following PR can focus on transport and lifecycle composition rather than
  combining new wire behavior with a storage migration.
- State, Record, and Blob bridges remain explicit later work.
