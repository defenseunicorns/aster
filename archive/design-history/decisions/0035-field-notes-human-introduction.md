# Decision 0035: Introduce Aster through staged Field Notes


- Status: Accepted for an evaluation-only developer experience
- Date: 2026-08-28
- Authority: [data-mesh-requirements.md](../../data-mesh-requirements.md)
- Related: [Decision 0032](0032-interactive-event-message-playground.md),
  [Decision 0034](0034-short-lived-iroh-nearby-discovery.md), and
  [Field Notes quickstart](../quickstart/hello.md)

## Context

The deterministic capability tours prove exact scenarios, and the numeric
message playground supports broad exploration. Neither begins at a human mental
model: create a node, write while alone, let another node carry the note, take
the first node offline, and later see data arrive.

The existing playground already owns safe process supervision, independent
stores, exact application queries, bounded logs, cleanup, and terminal
sanitization. A second demo framework would duplicate those harder boundaries.

## Decision

1. Add mise run hello as a thin staged mode over the existing real-process
   playground.
2. Pre-provision one disposable three-member roster but start no node process.
   Let the user add Atlas, Beacon, and Cove; select a node; write a note; and
   sleep or wake real processes without deleting stores.
3. Present an Atlas-to-Beacon-to-Cove constellation. Solid edges come only
   from authenticated-contact observations. Note checkmarks come only from
   exact QueryEvents results.
4. Require a visible route choice before launch:
   - nearby uses ten-second official Iroh mDNS windows and supplies no peer
     socket to the node;
   - invitation uses controller-known one-host loopback routes and no recurring
     discovery.
   Never silently move between them.
5. Keep friendly names solely in the controller. They are not mission,
   discovery, wire, or durable-store metadata.
6. Preserve every advanced playground command and view for scripted testing.
   The hello vocabulary is a human-facing alias layer, not another application
   or mesh protocol.

## Claim boundary

Field Notes is one-host, same-build, Event-only, all-content-member,
unprotected-reference, and evaluation-only. Its roster is provisioned before
interaction even though processes are activated by the user. Invitation mode
is not automatic discovery. Nearby mode has no retained physical
discovery-to-authenticated-delivery pass.

The experience does not establish global convergence, multi-host networking,
production discovery, resource or energy limits, hostile-input acceptance, an
end-user messaging product, or release authorization.

## Consequences

- A new user can feel local commit, store-and-forward, temporal absence, and
  restart continuity without entering endpoint IDs or socket addresses.
- The exact technical and evidence boundaries remain visible in the UI instead
  of being hidden behind a celebratory script.
- Existing playground supervision and tests remain the implementation owner.
- A future physical two-host hello may reuse the vocabulary only after
  provisioning exchange, invitation transport, and discovery qualification are
  separately designed and retained.
