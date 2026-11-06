# Linux BTLE Unattended Lifecycle Design

**Status:** approved incremental design
**Date:** 2026-11-05
**Parent design:** `2026-11-03-production-btle-design.md`
**Capability lane:** P1-4 multi-carrier physical risk, Linux BTLE Event increment

## Intent

Turn the existing fixed-role, one-contact Linux BlueZ Ring-1 driver into an
in-process BTLE component that can remain running unattended while BlueZ or the
configured controller is absent, recover when it appears or is powered on,
reconnect after contact loss, and stop cleanly.

The increment validates lifecycle behavior around the existing semantic-v9
ordered Event contact. It does not change the Aster protocol, framing,
authentication, storage, or contact-admission semantics. Aster remains usable
with no transport: local publication commits durably while BTLE is unavailable,
and a later BTLE contact reconciles the retained Event.

Transport lifecycle is intentionally not generalized. Bluetooth, IP, serial,
file, and future carriers can have substantially different operating models.
The Linux BTLE crate owns BlueZ-specific lifecycle and exposes only coarse BTLE
availability plus already-open contacts. `aster-node` continues to know only
that an adapter-neutral ordered contact was admitted.

## Goals

- Run the Linux BTLE lifecycle in the same process as the selected node; do not
  require a system daemon or a second Aster service.
- Start the node and its local application surface even when BlueZ or the
  configured controller is absent or powered off.
- Observe BlueZ controller add, remove, power, address, and address-type changes
  without busy polling.
- Select complementary Linux roles deterministically without an operator-owned
  `--role` value in the unattended path.
- Maintain at most one open or active contact for the provisioned peer.
- Recover from controller loss, peer absence, socket loss, unsuccessful
  authentication, and completed contacts under bounded retry/cadence policy.
- Cancel open, listen, backoff, and active-contact work promptly during process
  shutdown.
- Preserve exact provisioned Bluetooth locator checks and mission-authenticated
  peer checks at their current separate layers.
- Provide deterministic, short tests through a Linux-driver-private platform
  seam; no test waits for the real retry or 60-second contact cadence.

## Non-goals

- No wire, semantic-version, profile, conformance-vector, or protocol change.
- No generic transport lifecycle trait, carrier manager, fallback manager, or
  transport-selection policy in `aster-node`.
- No automatic discovery, roster learning, pairing workflow, or unprovisioned
  peer admission.
- No multiple-controller, multiple-peer, simultaneous-contact, or controller
  selection policy.
- No Android or Apple lifecycle implementation. The existing Android/Linux
  physical Ring-1 harness remains fixed-role and separate.
- No State, Record, or Blob BTLE execution. This increment remains Event-only;
  later onion rings reuse the contact, not this Event supervisor.
- No public agent/FFI/SDK availability API, packaging, systemd unit, or
  production-support claim.
- No multi-carrier selection or fallback. Durable work simply remains queued
  when no supported contact is available.
- No discovery/emission-policy qualification, soak, energy, or representative
  target-hardware evidence.

## Anti-goals

The increment is a failure even if it connects when it:

- makes node startup depend on Bluetooth availability;
- moves BlueZ state or retry policy into protocol/runtime code;
- treats a Bluetooth address as authenticated node identity;
- retries with a busy loop or reconnects continuously after success;
- permits overlapping opens or contacts for the single provisioned peer;
- logs provisioned addresses, mission identities, or unsanitized BlueZ errors;
- hides fatal local configuration as an indefinitely retryable outage; or
- turns implementation retry/cadence values into a wire or compatibility
  contract.

## Constraints and current boundary

The current implementation already provides:

- `start_transport_neutral_node`, which becomes application-ready without an IP
  carrier;
- bounded `OrderedEventContactHandle::run`, which accepts one already-connected
  ordered contact with an explicit mission expectation and role;
- an exact-pinned Linux BlueZ LE CoC driver with cancellation, open/operation
  deadlines, locator filtering, MTU observation, adaptive platform writes, and
  closed sanitized error categories; and
- a fixed-role Ring-1 binary and Android foreground app used for bounded Event
  evidence.

The node admission handle already owns protocol execution and closes a contact
on cancellation or actor failure. The lifecycle supervisor must use that
surface rather than adding a second protocol path.

BlueZ 0.17.4 supplies two event sources required here:

- `Session::events()` for adapter add/remove; and
- `Adapter::events()` for adapter property changes and stream termination when
  the adapter disappears.

The monitor must subscribe before taking each corresponding state snapshot and
then revalidate the snapshot. This prevents an add/remove or power transition
between a one-time query and event subscription from being lost.

## Approaches considered

### 1. Linux driver-owned lifecycle supervisor — selected

`aster-ble-linux` owns controller monitoring, role choice, retry, contact
opening, contact admission, and shutdown. It calls the existing node contact
handle only after a stream is connected.

This keeps transport-specific state in the transport onion ring, preserves the
node boundary, and can be tested without a radio through a private platform
seam. It is the selected approach.

### 2. Generic runtime carrier manager — rejected

`aster-node` could define common lifecycle states and drive IP, BTLE, and later
carriers through one trait. That would make BlueZ hotplug, listener
advertisement, and Bluetooth role behavior part of a false common model. Other
transports are expected to differ materially, so this abstraction would add
coupling before shared semantics exist.

### 3. External BTLE daemon or process supervisor — rejected for this increment

A separate daemon could own BlueZ and pass contacts to the Aster process over
IPC. It adds another trust, deployment, cancellation, credential, and failure
boundary without improving the current in-process validation. Product
packaging may later wrap the in-process component with systemd, but systemd is
not the transport lifecycle implementation.

## Selected architecture

### Ownership

The embedding Linux process owns three sibling pieces:

1. the transport-neutral `RunningNode`;
2. one `LinuxBtleEventSupervisor`; and
3. process shutdown coordination.

Startup order is node first, supervisor second. Shutdown order is supervisor
cancellation and drain first, then `RunningNode::shutdown`. If the adapter is
never available, the node remains ready and local durable operations continue.

The supervisor lives in `aster-ble-linux`, not `aster-node`. The only node API
it consumes is the existing cloneable `OrderedEventContactHandle` and
`MissionPeerExpectation`.

### Configuration model

Refactor the current role-bearing driver configuration into two Linux-specific
layers so fixed Ring-1 and unattended operation share validation without
duplicating every carrier field:

- `LinkConfig` contains adapter name, exact local/peer Bluetooth addresses and
  address types, PSM, frame/exchange bounds, and open/operation deadlines.
- `DriverConfig` contains a `LinkConfig` plus the existing explicit `FixedRole`
  for the Ring-1 harness.
- `SupervisorConfig` contains the same validated `LinkConfig`, local mission
  node ID, provisioned peer mission node ID, and the successful-contact cadence.

Validation remains local and synchronous. It rejects malformed adapter names,
wildcard/equal addresses, non-LE address types, invalid PSM or resource bounds,
zero/excessive deadlines, equal mission identities, and a zero or greater-than-
24-hour cadence before BlueZ is contacted. The 24-hour ceiling permits
low-duty daily operation while rejecting an accidental effectively-disabled
initiator. It is driver policy, not a wire or support guarantee. The exact
maximums already defined by the Ring-1 profile remain unchanged.

`DriverConfig` remains the fixed-role compatibility path. `SupervisorConfig`
has no role field.

### Initial deterministic role rule

For the unattended Linux path, compare the complete 32-byte authenticated
mission node IDs lexicographically:

- lower node ID: initiator;
- higher node ID: listener; and
- equal IDs: configuration error.

This rule is stable without wall-clock agreement, independent of controller
address changes, and produces exactly one initiator for a provisioned pair. It
is a Linux reference-implementation detail, not a v9 wire rule or conformance
requirement. The function is isolated so a later reviewed BTLE lifecycle design
can replace it without touching protocol code.

The fixed-role Ring-1 path remains available for Android/Linux evidence and for
platforms that have not adopted this Linux lifecycle convention. This increment
therefore claims unattended Linux/Linux lifecycle only.

### Availability boundary

The Linux driver exposes a BTLE-specific two-state observation:

- `Unavailable`: BlueZ cannot be observed, the named controller is absent,
  unpowered, unauthorized, or does not have the provisioned controller identity.
- `Available`: the named controller exists, is powered, and its exact address
  and address type match configuration.

Availability does not claim peer reachability, authentication, successful
sync, or convergence. A missing peer or failed contact leaves the controller
`Available` and enters peer retry backoff.

The observation is a small BTLE-specific watch/observer owned by the supervisor.
The node and protocol do not consume it in this increment. A future
transport-selection capability may map this coarse observation into its own
policy without inheriting the BTLE state machine.

Detailed internal states and sanitized reason categories remain private to the
driver and operator diagnostics.

### BlueZ monitor

The production monitor performs the following event-driven loop:

1. Create a BlueZ `Session` and subscribe to session events.
2. Snapshot adapter names.
3. If the configured adapter is absent, publish `Unavailable` and wait for its
   `AdapterAdded` event. Ignore unrelated adapters.
4. Construct the configured adapter and subscribe to adapter events before
   reading power, address, and address type.
5. Validate all three properties. Publish `Available` only when all match.
6. React to relevant property changes by re-reading and validating the complete
   property set. On power-off or identity mismatch, cancel current carrier work
   and publish `Unavailable`.
7. On configured adapter removal or adapter-event stream termination, cancel
   current carrier work, publish `Unavailable`, and return to the session loop.
8. On BlueZ/D-Bus session loss, publish `Unavailable`, release all handles, and
   recreate the session with the same 250 ms-to-30 second capped exponential
   algorithm used for peer retry. Session recovery has its own failure counter;
   it resets only after session subscription and the first complete adapter-name
   snapshot both succeed.

An availability transition wakes the lifecycle immediately; it never waits for
a peer retry timer. Unrelated adapter and device events do not create work.

### Contact lifecycle state machine

Only one state is active for the provisioned peer:

```text
Unavailable -> Ready -> Opening/Listening -> ActiveContact
     ^           ^              |                 |
     |           +--- Backoff <--+-----------------+
     +----------- controller loss / shutdown ------+
```

- `Unavailable`: no open/listen attempt exists. Wait on BlueZ events or
  shutdown.
- `Ready`: controller validation for the current availability epoch succeeded.
- `Opening/Listening`: call the existing bounded Linux open path with the
  derived role and a fresh cancellation token.
- `ActiveContact`: construct the exact `MissionPeerExpectation` from
  unauthenticated locator evidence plus the provisioned mission node ID, then
  call `OrderedEventContactHandle::run` with the matching ordered Event role.
- `Backoff`: wait after retryable peer/socket/authenticated-contact failure.
  Controller events and shutdown interrupt the wait.

The supervisor does not spawn a new attempt until the prior open or contact
future has terminated and its advertisement, listener, socket, and contact
guards have dropped. This is the duplicate-contact prevention mechanism for the
single-peer increment.

Listener rejection of an unexpected Bluetooth locator closes that socket and
returns through bounded backoff before listening again. Mission identity is
still authenticated above the carrier; a matching address never bypasses that
check.

### Retry and successful-contact cadence

Retry values are Linux driver implementation policy, not protocol:

- initial retry: 250 ms;
- exponential doubling after consecutive retryable failures;
- maximum retry: 30 seconds; and
- reset after one authenticated contact completes successfully or after a new
  controller-availability epoch begins.

The BlueZ-session and peer/contact loops use independent counters so a long
daemon outage does not slow the first peer attempt after controller recovery.
The 250 ms initial value avoids a hot loop while keeping recovery responsive.
The 30-second ceiling matches the existing maximum bounded platform operation.
Deterministic single-initiator role selection avoids pairwise simultaneous
connect retries, so this increment adds no random-jitter dependency. The
constants remain isolated for later target-evidence tuning.

After a successful contact:

- the initiator waits the configured contact cadence before reconnecting; and
- the listener immediately resumes listening, because waiting there would
  create an inbound outage while the initiator already supplies the cadence.

The initial binary default is 60 seconds, matching the existing selected-node
sync cadence and preventing continuous RF reconnects when no new work exists.
It is an implementation/configuration value, not a wire rule or supported
performance claim. Unit tests use Tokio's paused clock and advance virtual time;
they do not run for 60 seconds.

### Failure classification

- Invalid local configuration is fatal and returned before the supervisor
  starts.
- Controller absent, power-off, permission/BlueZ unavailability, and D-Bus loss
  publish `Unavailable` and remain recoverable.
- Peer absence, timeout, socket loss, unexpected locator, and protected contact
  failure retain `Available` and use bounded backoff.
- Explicit cancellation is a normal terminal result.
- Node admission closed, actor unavailable, and actor stopped are terminal for
  the supervisor. Admission busy and protected-contact failure use peer
  backoff. The embedding process must still cancel and drain the supervisor
  before node shutdown.

Replace the handle's string-only boundary with a narrow
`OrderedEventContactError` (name provisional) containing `AdmissionClosed`,
`AdmissionBusy`, `ActorUnavailable`, `ActorStopped`, and `Contact(NodeError)`.
The first four variants classify the existing handle/actor boundary;
`Contact(NodeError)` preserves the protected session failure as its source.
This avoids diagnostic-string parsing and does not expose BlueZ, retry state,
availability, or a generic transport lifecycle from `aster-node`.

### Cancellation and shutdown

Use one supervisor cancellation signal that is visible in every wait:

- BlueZ session acquisition/availability wait;
- socket connect or listener accept;
- peer retry backoff;
- initiator success cadence; and
- active ordered Event contact.

Cancellation of an open uses the existing `OpenCancellation`. Cancellation of
an active contact closes the contact before dropping/awaiting the node admission
future. BlueZ advertisement/listener guards are RAII-owned by the current
attempt and cannot survive its completion.

The supervisor returns only after all child work is drained. It does not own
process signals; the embedding binary owns SIGINT/SIGTERM coordination so tests
and future service packaging can use the same lifecycle API.

### Security and privacy

- The Bluetooth address remains transient locator evidence only.
- Only the provisioned locator can pass the listener's carrier check.
- The protected session must authenticate the exact provisioned mission peer
  before profile or inventory work.
- Availability and errors expose closed categories, never raw BlueZ/D-Bus text,
  addresses, mission IDs, paths, or credentials.
- No new plaintext, key material, pairing secret, wire field, or downgrade
  surface is introduced.
- A rogue locator can cause bounded rejection/relisten work but cannot create
  overlapping contacts or bypass authentication. Hostile-radio rate/resource
  qualification remains a later evidence gate.

### Resource behavior

- One BlueZ session monitor, one configured adapter event stream, and at most
  one open/contact task exist.
- No polling timer is used for controller state.
- Retry and success sleeps are interruptible and hold no socket or
  advertisement that is not needed for their state.
- Existing frame, exchange, and operation bounds remain authoritative.
- Counters use saturating arithmetic; retry exponent is capped before duration
  multiplication.

### Observability

Emit concise sanitized transitions suitable for the current operator output:

- `unavailable` with a closed reason category;
- `available` for a validated controller epoch;
- `opening` or `listening` with the derived role;
- `contact-complete` with the existing protected receipt summary;
- `contact-failed` with a closed failure category and next retry duration; and
- `stopped`.

Repeated identical unavailable observations are coalesced. Addresses and node
IDs are not printed. These logs are implementation diagnostics and do not
become a stable public status schema.

## Code organization

Expected production changes:

- `crates/aster-ble-linux/src/lib.rs`
  - extract shared role-independent link validation;
  - preserve fixed-role `open_contact` compatibility; and
  - export the bounded supervisor surface and coarse availability type.
- `crates/aster-ble-linux/src/lifecycle.rs`
  - Linux-only supervisor state machine, role derivation, retry/cadence, BlueZ
    event monitoring, cancellation, and private injected platform seam.
- `crates/aster-ble-linux/src/bin/aster_btle_ring1_linux.rs`
  - keep the fixed-role evidence command intact apart from the configuration
    shape refactor.
- a separate unattended Linux integration entry point or explicit mode in the
  current binary
  - start the transport-neutral node first;
  - run the supervisor until process shutdown; and
  - remove Ring-1 evidence assertions from the unattended path.
- `crates/aster-node/src/runtime.rs`
  - replace the ordered-contact handle's string-only admission failures with a
    closed typed result covering admission closed/busy, actor unavailable or
    stopped, and protected-contact failure;
  - keep protocol execution and transport-neutral contact ownership unchanged.

The implementation plan must choose between a separate binary and a clearly
separated subcommand after checking current packaging conventions. It must not
mix daemon/service claims into the evaluation harness.

No production change is expected in `aster-contact`, protocol documents,
semantic-version vectors, or storage.

## Verification design

### Pure/unit tests

- role derivation is complementary, stable, and rejects equal mission IDs;
- link/supervisor validation rejects every invalid bound before BlueZ access;
- backoff grows, caps, resets, and cannot overflow;
- BlueZ-session and peer failures maintain independent counters and reset only
  at their specified success boundaries;
- ordered-contact handle failures map to the typed terminal/retryable classes;
- coarse availability maps only controller capability, never peer results.

### Deterministic lifecycle tests with a private fake Linux platform

- startup with no BlueZ/controller publishes `Unavailable` and performs no
  socket attempt;
- adapter add plus valid powered properties publishes `Available` and starts
  exactly one role-correct attempt;
- power-off, removal, identity change, and event-stream termination cancel an
  open or active contact and return to `Unavailable`;
- power-on/re-add starts one fresh availability epoch without polling;
- repeated peer/open/contact failures never overlap and follow capped backoff;
- authenticated completion resets backoff;
- the initiator waits the contact cadence while the listener immediately
  relistens;
- controller recovery and shutdown interrupt backoff/cadence immediately;
- shutdown drains correctly from unavailable, open/listen, active, and sleeping
  states;
- unexpected node-admission closure terminates instead of retrying forever;
- unrelated adapter/device events cause no attempt or availability change.

Tokio time is paused for every timer test. Focused lifecycle tests should
complete in well under one second of wall time.

### Node integration test

With the fake platform unavailable, start a transport-neutral node, publish an
Event locally, and prove the durable operation completes before any contact.
Then make the fake controller/contact available and prove the existing ordered
Event admission path executes. This tests the required transport-neutral
behavior without changing node protocol or durability semantics.

### Physical evidence deferred from this increment

After implementation and CI, run bounded Linux/Linux radio checks when devices
are available:

- start both nodes with controllers absent, publish durably, then attach/power
  controllers and observe delivery;
- remove/power-cycle one controller during open and during a protected contact;
- restore it and observe one successful later contact;
- stop both processes and confirm no advertisement/listener remains; and
- retain exact hardware, kernel, BlueZ, controller/driver, commit, MTU, Event
  size, timing, and failure observations.

This evidence does not expand the PR to discovery, Android lifecycle, other
data classes, multi-controller support, or production authorization.

## Documentation and claim boundary

Update transport and BTLE evaluation documentation to say that the tree has an
unattended single-controller, single-provisioned-peer Linux Event lifecycle
mechanism with evidence pending. Do not change atomic requirement credit unless
new retained evidence justifies it.

Keep these exclusions prominent:

- evaluation-stage, not production-authorized;
- Linux/Linux unattended lifecycle only;
- fixed-role Android/Linux physical Ring-1 evidence remains separate;
- no discovery, selection/fallback, multi-peer/controller, other data class,
  packaging, soak, energy, or target-support claim.

## Implementation quality and push gate

Each implementation slice follows this sequence before any push:

1. analyze the surrounding production path and existing ownership/error
   conventions;
2. add a focused failing test and verify the expected failure;
3. implement the smallest production change;
4. run focused tests, formatting, and strict relevant Clippy;
5. perform a separate refactor/cleanup pass over the complete diff for DRYness,
   naming, control flow, ownership, comments, and error boundaries;
6. remove AI-style repetition, speculative hooks, incidental abstractions, and
   comments that merely restate code;
7. rerun focused verification;
8. obtain independent review and address every Critical/Important finding;
9. create only a signed commit, verify its signature and a clean worktree, then
   push.

The full local workspace gate is not run when it would repeat known long-running
lanes contrary to the agreed workflow. CI remains responsible for broader
workspace partitions; every omitted local lane is stated explicitly.

## Builder decisions still allowed

The implementation plan may choose private type and function names, fake-event
representation, and whether the unattended entry point is a separate binary or
a separated subcommand. It may not change lifecycle ownership, role derivation,
availability semantics, retry/cadence behavior, single-contact bounds, protocol
scope, or the listed non-goals without another design review.
