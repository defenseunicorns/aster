# Production BTLE carrier design after semantic v9

**Status:** maintained architecture authority; no production authorization

**Capability track:** P1-4 reachability and carrier portability, followed by
all-class and cross-platform qualification.

This document defines future BTLE architecture and release gates. Current
evaluation claims are owned by
[`btle-ring1-evaluation-profile.md`](../../validation/btle-ring1-evaluation-profile.md);
operator procedures and dated physical observations do not broaden this design.

## Intent and authority

Aster carries protected data over BTLE without making Bluetooth, an operating
system, or a controller a protocol authority. The implementation preserves:

- local durable publication with no controller, peer, or transport;
- one mission-bound store and replication authority;
- a complete mission handshake before inventory or application data;
- transient carrier locators that never become mission identity;
- semantic-v9 bytes, storage, and application APIs; and
- bounded discovery, framing, queues, retries, tasks, and provisional state.

The selected carrier is an in-process, asynchronous `BleL2capV1` LE L2CAP CoC
adapter. GATT, if added, is a separate reviewed adapter; it is never implicit
fallback. Pairing, bonds, Bluetooth addresses, PSMs, link encryption, controller
handles, and platform peer handles grant no Aster identity or authorization.

## Qualification rings

| Ring | Exit |
| --- | --- |
| 0 | The node is application-ready and local publication remains durable with no eligible transport. |
| 1 | Two fixed-role Linux nodes carry one protected semantic-v9 Event over one non-IP session CoC with profile `0x0001`, no alternate carrier, no Blob attempt, and retained physical evidence. |
| 2 | Event gains bounded rostered discovery, dynamic lifecycle, duplicate-contact rules, a declared minimum MTU, resource/control-liveness evidence, and explicit support rows. |
| 3 | State and Record qualify over the same authenticated contact with convergence, interruption, restart, priority, and resource evidence. |
| 4 | Blob qualifies with the exact semantic-v9 Profile-5 DATA/CONTROL pair, canonical records, and record-level durable resume. |
| 5 | Additional Linux hardware, macOS, Android foreground, and iOS foreground qualify against the Linux reference; background mobile operation and packaging are separate exits. |

Evidence for one ring never implies an outer ring, another controller, or an
operating-system-wide support claim. Automatic multi-carrier selection,
cross-carrier continuation, and intra-record resume require a later semantic
design and new allocations; v9 does not infer them.

## Architecture

```text
application Event / State / Record / Blob API
                    |
mission policy, reconciliation, durable store and Blob depot
                    |
adapter-neutral authenticated contact and attempt authority
                    |
BleL2capV1 carrier (framing, bounds, scheduling, errors)
                    |
platform driver (BlueZ, CoreBluetooth, or Android APIs)
```

The platform driver owns only transient platform I/O and connection lifecycle.
It cannot open stores, parse application objects, decide authorization, own
checkpoints, or expose Bluetooth choices through the application API.

An adapter-neutral contact provider returns an unauthenticated carrier contact.
That contact supplies bounded framed send/receive, request/respond turns,
deadlines, cancellation, close, typed carrier evidence, and—when qualified—an
optional bounded attempt-channel pair. The Aster mission session above it owns
identity, transcript, replay protection, negotiation, and authorization.

Carrier evidence is either an independently authenticated carrier identity or
an unauthenticated transient locator. Initial BTLE supplies only the latter; it
must never fabricate an Iroh `EndpointId`. The mission-authenticated `NodeId`
is the roster authority.

Application readiness, carrier availability, peer reachability, and convergence
are distinct. Controller absence is nonfatal `unavailable` state. Lifecycle
observation is event-driven; removal cancels and drains affected work before a
new epoch. The current claim is one controller and one peer per process, while
the interface may later admit multiple qualified instances.

## Platform boundary

The connection-oriented platform boundary must support bounded scan and
advertisement windows, listener/open operations, ordered read/write,
cancellation, close, controller/permission lifecycle observation, current
packet/MTU bounds, and sanitized health/role reporting. Cancellation must
release owned platform work within a declared bound.

The stock dependency graph deliberately carries no BTLE-local forks. Stock
`bluer` does not by itself establish acknowledged, cancellation-safe
advertisement/discovery teardown or a bounded first D-Bus ingress queue; Linux
rostered discovery remains unqualified until the driver supplies and proves
those properties through stock or upstream APIs. Stock `hmac` computes the
required bytes but does not by itself establish erasure of constructor-derived
key, IPAD, and OPAD temporaries. Production credential handling therefore
remains gated on an implementation and review that prove those working-secret
lifetimes without a local crate fork.

`BleL2capV1` owns carrier framing, deadlines, limits, flow control,
session/channel association, scheduling, and error classification. Platform
drivers adapt operating-system APIs only. Swift/Kotlin drivers remain
in-process through narrow FFI boundaries.

## Discovery and emission

- `off`: no scan or advertisement; only an explicitly provisioned locator.
- `rostered`: a provisioned discovery-group proof admits bounded candidate work,
  followed by authentication of the exact configured mission `NodeId`.
- `mission`: future bounded discovery of unknown locators; no authority exists
  before mission authentication and policy admission.

Discovery proof is a work filter, not peer identity. Candidate observations,
replay state, pre-authentication slots, handshakes, retries, negative caches,
windows, and retained bytes are bounded. Discovery exposes no `NodeId`, mission
identifier, topic, scope, priority, inventory, data class, or payload.

The current provisional `ReceiveOnly` behavior originates no discretionary
scan, advertisement, contact, inventory, reconciliation, administration, or
application payload, while allowing protocol-required responses on an admitted
inbound contact. `PassiveOnly` emits no framework bytes and cannot run an
ordinary L2CAP session. Final names and doctrine remain a profile decision.

### `AsterRosterBeaconV1`

The current Linux rostered slice freezes private service UUID
`6aa1cfed-2ce3-46d4-9c69-a33d1dd54ee5` and this 40-byte Service Data value:

```text
offset  size  field
0       1     revision = 0x01
1       1     flags (bit 0 SESSION_COC_AVAILABLE; all others zero)
2       2     listener_psm, unsigned big-endian
4       4     credential_generation, unsigned big-endian and nonzero
8       16    OS-random nonce
24      16    proof_tag
```

The UUID is also in the complete 128-bit Service UUID list. Revision 1 requires
the resulting 79-byte extended advertisement on the 1M secondary channel and
has no legacy-advertisement fallback. With `header = record[0..24]`:

```text
proof_tag = first_16_bytes(HMAC-SHA-256(
    generation_secret,
    "aster/ble-l2cap/rostered-discovery/v1\0" ||
    uuid_network_bytes ||
    header))
```

Verification is constant-time. Unknown revision or generation, reserved flags,
invalid dynamic LE PSM, or non-exact length fails before candidate allocation.
The nonce changes with each advertisement generation and is never a counter,
time, identity, or durable resume value.

### `ASTRBD02` credential artifact

```text
magic "ASTRBD02" (8 bytes)
manifest_sequence (8 bytes, unsigned big-endian, nonzero)
entry_count (1 byte, 1 or 2)
issued_at_unix_seconds (8 bytes, unsigned big-endian, nonzero)
lease_not_after_unix_seconds (8 bytes, unsigned big-endian, nonzero)
overlap_not_after_unix_seconds (8 bytes, unsigned big-endian; zero with one entry)
deployment_scope_id (32 bytes, not all zero)
emitting_generation (4 bytes, unsigned big-endian, nonzero)
emitting_secret (32 bytes, not all zero)
[overlap_generation (4 bytes, unsigned big-endian, nonzero)
 overlap_secret (32 bytes, not all zero)]
```

The artifact is exactly 109 bytes with one entry or 145 bytes with two; trailing
bytes are rejected. The lease begins after issue, lasts at most seven days, and
must be current. With two entries, secrets differ, generations are adjacent,
and overlap expires after issue but no later than the lease or seven days after
the original stage. Renewal may shorten, never extend, the stored overlap.

Rotation is stage `(emit g, accept g+1)`, activate `(emit g+1, accept g)`, then
retire `(emit g+1 only)`. The host authority authenticates the source and
durably prevents manifest, generation, secret-binding, and overlap rollback
before exposing a non-cloneable lease to the adapter. Missing trustworthy time
or wall/monotonic divergence over five minutes cancels the lease. The owner-only
file loader is evaluation-only.

The implemented rostered slice remains one Linux controller, one exact mission
peer, one dynamic PSM, and one active Event contact. Lower complete mission
`NodeId` initiates; higher listens. Rostered failure starts no fixed-locator,
GATT, or IP fallback. Multiple peers, duplicate arbitration, controller
selection, other classes, packaging, and production approval remain open.

## Contacts, channels, and data classes

Every carrier contact opens one session CoC and runs the complete mission
handshake. The session carries protected negotiation, reconciliation, control,
liveness, and Event/State/Record frames. One protected frame may span platform
writes and L2CAP SDUs; this is bounded ordered-stream framing, not a new
replication fragmentation protocol.

Ring 4 may open one bounded DATA/CONTROL CoC pair per selected Blob direction.
The pair is associated with the exact authenticated session and attempt before
semantic records are released. It reuses the frozen Profile-5 transaction and
canonical `ASTRBS02` records. DATA reset aborts the attempt; successful
RESULT/ACK settlement requires DATA through ACK and orderly FIN. Association
tokens grant no identity, authorization, or durable progress.

Qualification order is carrier foundation, Event, State/Record, then Blob.
`BleL2capV1` is class-neutral; an evaluation profile may enable only Event while
other durable work remains pending. Profile 5 advances durable offsets only
after complete-record verification. BTLE-specific records, class-specific
carriers, and intra-record resume are prohibited without a new semantic design.

Control, authentication, revocation, cancellation, acknowledgements, and
liveness receive reserved scheduling capacity. Interactive classes are
priority-aware; Blob uses remaining capacity with a bounded minimum share.
Queues, outstanding bytes, attempts, channels, retries, and time without durable
progress are bounded by the active qualification profile.

## Roles, selection, and failures

Ring 1 fixes roles and one eligible adapter. Ring 2 may reduce duplicate
same-adapter contacts only after mission authentication. Preferred direction is
lower `NodeId` outbound and higher inbound; any further tie-break must use a
frozen authenticated contact key, never address, controller index, arrival
order, or wall clock.

Semantic v9 selects exactly one profile-permitted adapter for a contact. It
does not choose between simultaneously eligible BTLE and IP carriers. A future
selection protocol must bind selection to mission, peers, adapter, operation,
attempt, and policy; choose once per attempt; run a fresh mission handshake on
every carrier; never transfer keys or replay state; and permit fallback only
for named transport-scoped failures.

Zero credit is backpressure. Deferred capacity waits for its named event.
Positive-credit no-progress, control-liveness loss, link loss, adapter loss, or
a transport deadline may be retryable only within profile budgets. Framing,
protocol, authentication, integrity, authorization, replay, policy, lifecycle,
cancellation, and invariant failures are terminal in their declared scope and
must never be hidden by another carrier. Before mission authentication, failure
may affect only the transient candidate and bounded expiring rate state.

Process restart reconstructs availability from platform state and protocol
progress only from mission-bound durable authorities. Platform callback queues,
BlueZ, and mobile frameworks never own resume truth.

## Platform qualification and support

Linux BlueZ/kernel is the reference driver. macOS/iOS use CoreBluetooth and
Android uses public LE L2CAP CoC APIs. Foreground mobile interoperability never
implies background participation.

Support is additive per exact OS, architecture, kernel/framework, controller,
firmware, driver build, role, lifecycle mode, MTU/rate/resource bounds,
conformance scenario, artifact identity, and known exclusion. One successful
controller does not qualify neighboring hardware.

## Required evidence and governance

Ring 1 retains exact source/build, two Linux hosts, controllers, configuration,
negotiated MTUs, one Event larger than the smaller MTU, mission-before-data,
semantic/profile digest parity, disconnect/reconnect, controller loss, process
restart, durable application receipt, deduplication, resource observations, and
cleanup. It is bounded evaluation evidence only.

Ring 2 additionally requires hostile candidate/discovery tests, declared MTU
floor, dynamic lifecycle, duplicate-contact vectors, packet and resource
evidence, approved emission semantics, support rows, signed semantic minimum,
durable per-identity high-water, authenticated rollback, dependency/SBOM
admission, independent review, and release authorization.

Rings 3–5 add class convergence/resume, exact Profile-5 channel behavior,
platform interoperability, background-mobile profiles, packaging, hostile-peer
evidence, and independent implementation as applicable.

## Compatibility

- Replication wire/profile version 1 and semantic versions 1–9 retain their
  bytes and meaning.
- `BleL2capV1` is carrier-local and adds no semantic, storage, or public API
  allocation.
- V9 permits only the profile's single contact-agreed eligible adapter; it has
  no automatic cross-carrier fallback or continuation.
- Discovery revisions are carrier-local; new platform support adds evidence and
  packaging, not protocol identity.
- Any change to authority, durable ownership, public API, fallback eligibility,
  versioning, or process boundary requires a new reviewed decision.
