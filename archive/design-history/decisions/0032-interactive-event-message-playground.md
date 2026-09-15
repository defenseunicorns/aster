# Decision 0032: Keep interactive Event exploration separate from acceptance tours


- Status: Accepted for an evaluation-only developer demo
- Date: 2026-08-27
- Authority: [`data-mesh-requirements.md`](../../data-mesh-requirements.md)
- Related: [Decision 0009](0009-public-api-boundary.md),
  [Decision 0030](0030-event-first-local-connect-agent.md), and
  [Decision 0031](0031-live-tour-presentation.md)

## Context

The capability tours are deterministic acceptance demonstrations. Their
process cohorts, built-in Ping/Pong roles, verification, and retained receipts
answer whether one exact bounded scenario passed. They do not let a developer
keep an arbitrary selected cohort running, choose a publisher, enter messages,
or change one node's availability while watching synchronization.

The selected node already exposes high-level live Event operations through the
alpha loopback ConnectRPC agent. An exploratory demo can use that public
application boundary without adding another mesh protocol, opening a running
store twice, or making the tour presenter an application authority.

Requirements section 2 excludes end-user applications. Any such tool must
therefore remain a synthetic developer playground rather than a chat or C2
product.

## Decision

1. Add a separate `mise run playground -- --nodes N` workflow. Keep the
   deterministic `tour`, `tour-relay`, and `tour-control` commands and their
   receipt semantics unchanged.
2. Accept 2 through 32 nodes. `aster playground-init` prepares a fresh retained
   root with independent carrier identities, mission identities, and disposable
   unprotected-reference bundles. Every playground identity is a content member
   for one fixed Event topic and scope; each agent process creates and owns its
   independent store beneath that root.
3. The standard-library Python controller starts one real `aster-agent`
   operating-system process per node on loopback. It configures a fixed line
   topology and uses each agent's authenticated local ConnectRPC API for Event
   publication and observation. It does not open node stores directly.
4. Expose explicit textual commands to send through any running node, isolate
   or rejoin a node, stop or start its process, inspect status, and quit. An
   isolated running node remains a useful offline-first publisher; rejoining
   restores its fixed contacts without replacing its durable store.
5. Show an Event's progress only from exact per-node application observations.
   Contact status, elapsed quiet time, or presenter state is not converted into
   a global-convergence claim.
6. Provide `auto`, `tui`, `plain`, and JSON-Lines `raw` views. Presentation is
   sanitized and is not a retained acceptance format or pass/fail authority.
7. On normal exit, failure, or interruption, stop and reap every child process,
   restore the terminal, and retain the fresh run root plus bounded rotating
   controller and recent agent-output logs for inspection. These tails are not
   complete process receipts.
8. Build and launch through a small POSIX wrapper that preserves build and
   controller status. Reuse the existing live build presenter and already
   admitted Python, Rust, Iroh, and ConnectRPC components; add no external
   package or public source.

## Claim boundary

This playground is same-build, same-implementation, Event-only observation on
one host over loopback. It uses one fixed line, one authority, one scope and
topic, manual peer preparation, all-member content access, and disposable
unprotected-reference provisioning.

The selectable 2-through-32 count, 1,024 publish-attempt ceiling, and
4,096-byte message ceiling are interaction and resource bounds, not an
unlimited or at-least-100-node scale result. The all-member topology establishes no
payload-blind relay result. A displayed exact Event count does not establish
global convergence, physical or multi-host behavior, resource or performance
acceptance, automatic discovery, NAT traversal, controlled-relay fallback,
BTLE, cross-transport or independent interoperability, State/Record/Blob live
behavior, protected provisioning, a supported release profile, or production
authorization.

## Consequences

- Developers can explore live Event publication and later movement without
  reading structured acceptance receipts or manually provisioning many local
  processes.
- The playground consumes the existing application API and node composition;
  it does not change wire bytes, Event semantics, delivery guarantees, or the
  production component boundary.
- Run roots intentionally contain readable synthetic messages, disposable
  credentials, stores, and logs. They must not contain operational data or be
  committed.
- The controller tracks at most 1,024 publish attempts/Events per run. Its
  journal and each node output stream retain four rotating 256 KiB segments;
  these resource bounds favor a live demo over indefinite transcript retention.
- Unit, rendering, command, orchestration-failure, and signal-cleanup tests
  guard the controller without claiming live mesh propagation. A separate
  bounded smoke isolates one of three real agents, publishes through another,
  observes the Event at the connected pair, confirms one fresh exact query at
  the isolated agent does not yet contain it, stops its publisher, rejoins the
  isolated agent, and waits for that exact Event there. That absence is one
  local query result, not a convergence claim. Neither test layer creates a
  retained requirement receipt.
- No generated requirement ID, status, evidence credit, capability maturity,
  or release-authorization boundary changes with this presentation/demo
  increment.
