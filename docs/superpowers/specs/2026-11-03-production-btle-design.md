# Production BTLE carrier design after semantic v9

**Status:** Draft for owner approval after chat design review and independent gap/requirements review on 2026-11-03

**Capability tracks:** P1-4 reachability and carrier portability; later all-class and cross-transport qualification

**Evidence boundary:** architecture and acceptance design only; this is not a
P0 evaluation/production profile and authorizes no P1 maturity or requirement
claim. No physical BTLE, cross-transport, background-mobile, or release claim
moves until a named reviewed profile and retained evidence exist.

**Profile gate:** each implementation increment must name an existing reviewed
profile or a reviewed BTLE amendment. Its requirements are ring-relative. Ring
1 fixes exact semantic v9 and records downgrade/rollback as excluded from its
narrow validation claim. A production ring must additionally name the signed
semantic minimum, durable high-water and authorized rollback policy. Every
profile names its users/use case, platforms and device tiers, topology,
included classes/APIs, permitted security profiles, metadata and
operating/resource assumptions relevant to its claim, bindings, acceptance
evidence, exclusions, and owners/dates/blocking status for unresolved decisions.

## Intent

Aster needs production BTLE support without making Bluetooth, Linux, or any
particular controller a protocol authority. The implementation must preserve
offline-first application behavior, the single durable mission-bound authority,
and the existing separation between carrier, authenticated adjacency,
replication, and data-class semantics.

The first implementation is an in-process Linux/BlueZ LE L2CAP
connection-oriented-channel adapter. Event is the first qualified data class,
but it is the inner ring of an architecture that subsequently admits State,
Record, and Blob without changing application APIs or creating class-specific
transport stacks. Hardware support is additive evidence: available CM4 devices
may provide the first physical runs, but neither the design nor the production
contract is Pi-specific.

## Delivery onion and claim boundaries

The architecture is one class-neutral onion. Delivery proceeds by qualifying
concentric rings over the same authority, contact, carrier, and platform seams;
it does not create a sequence of disposable Event-specific implementations.
Requirements in an outer ring do not block evidence for a narrower inner ring,
and evidence for an inner ring never implies that an outer ring is qualified.

1. **Ring 0 — transport-neutral baseline.** `aster-node` is ready and local
   publication remains durable with no configured transport, no supported
   transport, and no controller. Pending work waits for an eligible contact;
   carrier absence is status, not an application failure.
2. **Ring 1 — initial v9 non-IP Event validation.** An in-process Linux/BlueZ
   `BleL2capV1` adapter carries one protected Event between two rostered nodes
   over LE L2CAP CoC. The test fixes initiator/listener roles, provisions the
   locator, enables only BTLE for that peer contact, admits only
   `HybridPqAsterRecordV1` (`0x0001`), and uses exact semantic-v9 Event and
   mission-session bytes. The session exchanges the complete canonical v9
   transfer-profile offers, including Blob lane/Profile 5, and binds their
   unchanged intersection into `transfer_profile_digest`; Blob work remains
   dormant and no Profile-5 attempt pair is opened. The ring exercises an Event
   larger than the actually
   negotiated CoC MTU, disconnection, reconnection, controller loss, and
   process restart. Controller recovery may require node restart or explicit
   reconfiguration; live event-driven add/remove is not claimed. This ring
   validates the non-IP carrier seam and durable
   offline behavior; it is not a production, discovery, dynamic-role,
   minimum-MTU, multi-adapter, all-class, or platform-support claim.
3. **Ring 2 — production Event qualification.** The same adapter adds bounded
   rostered discovery, dynamic roles, same-adapter duplicate-contact
   reduction, controller hot-plug and support rows, a declared minimum
   supported CoC MTU, resource/control-liveness evidence, and any approved
   constrained-emission modes. Carrier revision bytes and conformance vectors
   are frozen before this ring becomes interoperable production behavior.
4. **Ring 3 — State and Record qualification.** Existing State and Record
   mechanics run over the same authenticated contact, with class-specific
   convergence, interruption, restart, preemption, and resource evidence.
5. **Ring 4 — exact v9 Blob qualification.** The carrier adds the bounded
   Profile-5 DATA/CONTROL attempt pair, exact frozen-v9 transaction, canonical
   records, and record-level resume. It does not add BTLE-specific records or
   intra-record resume.
6. **Ring 5 — platform and product expansion.** Additional Linux hardware,
   macOS, Android foreground, and iOS foreground are added as explicit support
   rows against the Linux reference. Mobile background operation, additional
   pairwise matrices, and release packaging remain separately claimed exits.

Automatic choice among simultaneously eligible carriers, cross-carrier
continuation, and transport-neutral intra-record resume are **future semantic
guidelines**, not another ring of this v9 implementation. They require a later
protocol decision and new allocations; this document deliberately defines no
wire grammar for them.

## Goals

- Preserve successful local durable publication when zero transports are
  available.
- Add one trusted in-process Linux BTLE carrier behind an adapter-neutral
  contract.
- Run the complete Aster mission handshake on every new BTLE carrier contact;
  Bluetooth discovery, addressing, pairing, and link encryption grant no Aster
  authority.
- Qualify Event first, then State, Record, and Blob as concentric capability
  rings over the same carrier foundation.
- Keep verified objects and provisional resumable progress carrier-neutral so
  work survives reconnect; another carrier may use it only when an approved
  later semantic/profile explicitly authorizes that selection.
- Retain semantic-v9 single-contact-agreed-adapter behavior; record only the
  safety constraints a future semantic increment must satisfy before automatic
  multi-carrier choice is designed.
- Define reusable platform-driver and conformance boundaries for Linux PCs,
  CM4-class devices, macOS, Android, and iOS.
- Keep resource use, RF emission, discovery, pre-authentication work, queues,
  channels, and retries explicitly bounded.

## Non-goals

- Treating Bluetooth pairing, bonding, a device address, or carrier encryption
  as mission identity or authorization.
- Requiring a transport for service readiness or local application operations.
- Shipping GATT as an implicit fallback inside the first L2CAP adapter.
- Defining a permanent Aster protocol format for BTLE advertisements.
- Claiming protected one-to-many application replication merely because the
  carrier can advertise.
- Qualifying all hardware combinations or every platform pair in the first
  increment.
- Claiming continuous background operation on Android or iOS from foreground
  interoperability evidence.
- Moving store, reconciliation, mission-policy, or data-class authority into a
  platform driver or helper daemon.

## Anti-goals

The design fails if it:

- makes publication fail because no carrier or controller is present;
- creates a second durable queue or checkpoint authority in a BTLE driver;
- silently switches from L2CAP to GATT underneath a live attempt;
- retries a security, integrity, authorization, policy, or lifecycle rejection
  over another transport;
- exposes transport selection, MTU, framing, pairing, or controller choice in
  the high-level application API;
- makes canonical Blob bytes or stored object identity depend on BTLE;
- embeds Pi-, BlueZ-, CoreBluetooth-, or Android-specific behavior in the
  replication protocol; or
- promotes simulation, foreground mobile operation, or one tested controller
  into a broader production claim.

## Approaches considered

### Process boundary

1. **Trusted in-process driver — selected.** This matches the accepted `Link`
   and `BleRadio` reference design, keeps one lifecycle, and avoids a second IPC
   protocol. The adapter remains part of Aster's trusted in-process computing
   base.
2. **Privileged BTLE helper daemon.** This could isolate platform code but adds
   IPC, packaging, lifecycle, backpressure, and compatibility boundaries. It is
   reserved for later hardening or third-party untrusted adapters.
3. **GATT-only implementation.** This is easier on some platforms but is a poor
   foundation for ordered bulk movement and would make the Event slice less
   reusable.

### Discovery policy

1. **Rostered only.** Predictable and bounded, but does not exercise automatic
   discovery.
2. **Open automatic discovery.** Easy to use but exposes pre-authentication
   radio, connection, CPU, and memory pressure as the default.
3. **Policy-controlled hybrid — selected.** `off`, `rostered`, and later
   `mission` modes share one bounded mechanism. `rostered` is the production
   default; automatic mission discovery is a later qualification ring.

### L2CAP channel topology

1. **One multiplexed channel.** Minimizes channels but creates head-of-line
   blocking and complicated cancellation and fairness.
2. **One session channel plus bounded attempt channels — selected.** The
   authenticated session channel carries handshake and control. Additional
   session-bound channels isolate bulk attempts, especially Blob.
3. **One persistent channel per data class.** Avoids some contention but spends
   resources while idle and complicates reconnect restoration.

### Blob behavior

1. **Record-level resume only.** Reuses v9 directly but can retransmit almost a
   1 MiB canonical record after a late disconnect.
2. **BTLE-specific small-record profile.** Improves local recovery while
   creating transport-dependent encoding and storage variants.
3. **Transport-neutral intra-record checkpoint — future guideline only.** It
   may be designed in a later semantic increment, but this document allocates
   no profile, records, tags, or wire behavior for it.

### Interoperability qualification

1. **Every platform pair immediately.** Broad but expensive and poor for
   attributing failures between two new drivers.
2. **Linux-reference star — selected.** Qualify each new platform driver against
   one Linux reference before expanding to pairwise coverage.

### Decision-register effect

This design intentionally evolves accepted Decision 0007. Before implementation
begins, a reviewed decision record must explicitly supersede only its BTLE
platform seam/topology and implicit in-adapter GATT-fallback direction:

- the production seam becomes asynchronous and connection-oriented rather than
  the current synchronous `BleRadio` datagram shape;
- `BleL2capV1` and any future `BleGattV1` are independently registered adapters;
  and
- the selected node gains a common contact abstraction before BTLE carries an
  Event.

Decision 0007's zero-trust carrier, bounded resource,
optional-infrastructure, L2CAP preference, and physical-evidence boundaries
remain in force. Its core-owned fragmentation remains in force for the legacy
datagram `BleRadio`/`Link` path. The decision record must explicitly supersede
fragmentation ownership only for the selected-node ordered `BleL2capV1` path:
that path uses the adapter-neutral bounded length framer already required by an
ordered contact stream and may span platform writes and L2CAP SDUs. This is
carrier framing, not a new replication record or semantic protocol. Until that
decision record is adopted, this document is a proposal and does not replace
the accepted reference decision.

## Selected architecture

### Authority and process layout

The initial Linux carrier runs inside `aster-node`:

```text
high-level Event / State / Record / Blob API
                    |
single actor, mission policy, reconciliation, durable store and Blob depot
                    |
adapter-neutral carrier/session and attempt selection
                    |
BleL2capV1 common carrier
                    |
Linux BlueZ + kernel L2CAP platform driver
```

The platform driver owns only platform I/O and transient connection state. It
does not parse application objects, mutate the store, decide authorization,
own replication checkpoints, or expose Bluetooth concepts through the
application API.

### Selected-node contact abstraction

The current `StreamTransportAdapter` is only a Blob attempt-stream seam and is
not the contract for the first BTLE Event. Before the Event slice, the selected
node introduces an internal adapter-neutral `ContactTransport` family and
migrates Iroh behind it without behavior change.

The contract has three levels:

1. A **contact provider** discovers/listens/connects and returns one bounded
   unauthenticated carrier contact plus carrier-local diagnostics.
2. A **carrier contact** supplies the exact primitives currently consumed from
   `aster_iroh::Connection`: bounded framed send/receive, request/respond and
   role-ordered turns, deadlines, cancellation, finish/close, typed carrier
   evidence, plus an optional bounded open/accept capability for additional
   channel pairs. Ring 1 implements session-channel primitives only; pair
   requests fail as unsupported without allocating state or changing the
   session. Ring 4 enables the pair capability through the same interface.
3. The existing **Aster mission session** runs above that contact, owns
   cryptographic identity, transcript, replay protection, semantic negotiation,
   and authorization, and returns authenticated contact context to the selected
   runtime.

Event, State, Record, control, and Blob orchestration depend on this contact
contract rather than `aster_iroh::Connection`. The existing Blob
`StreamTransportAdapter` becomes the attempt-channel portion of an authenticated
contact; it does not replace the general contact seam. Iroh parity tests must
pass before BTLE is enabled, proving identical mission-before-inventory,
control-before-data, timeout, cancellation, accounting, and close behavior.

The contact seam exposes opaque bytes and closed capabilities only. It cannot
open stores, construct authenticated Aster objects, mutate control state, or
classify application authority.

Carrier evidence is explicit rather than coerced into an Iroh-shaped identity:

```text
CarrierPeerEvidence =
    AuthenticatedCarrier { stable_carrier_id, channel_binding }
  | UnauthenticatedLocator { transient_locator }
```

Iroh retains its independently authenticated endpoint identity and channel
binding. Initial BTLE supplies only `UnauthenticatedLocator`; a Bluetooth
address, bond, platform handle, connection handle, or PSM must never be
converted into an Iroh `EndpointId` or represented as authenticated carrier
evidence. Rostered BTLE admission compares the authority-authenticated mission
`NodeId` after the hybrid handshake. The resulting mission session is then
associated with that transient carrier contact; the locator itself gains no
durable authority.

The selected node must generalize, not duplicate, the existing
`StreamTransportRegistry`, `TransportSelector`, and `AttemptCoordinator`.
`ContactTransport` adds provider and session coverage around that authority;
it does not create a second adapter registry, ranking algorithm, retry engine,
scheduler, or checkpoint owner. The shipped v9 composition still makes exactly
one contact-agreed adapter eligible.

The current broad `adapter-sdk` remains a privileged integration surface. The
production implementation should move toward the already-required narrow
carrier-only SDK, exposing opaque frame or stream I/O, route hints,
characteristics, discovery lifecycle, and cancellation without store, crypto,
provider, or control-mutation access. That least-privilege split does not make
hostile code safe in-process; hostile third-party adapters still require a
separate sandbox boundary.

### Availability and readiness

No transport is required. These states are independent:

```text
application readiness != carrier availability != peer reachability != convergence
```

`aster-node` starts and accepts local durable application operations with zero
controllers and zero registered transports. A configured but absent Bluetooth
adapter is a nonfatal `unavailable` carrier, not invalid configuration. Ring 1
enumerates its one provisioned controller at startup, detects its loss, and may
require node restart or explicit reconfiguration after the controller returns.
Ring 2 adds the carrier manager that observes BlueZ adapter add/remove and power
changes, registers eligible instances dynamically, and ends affected attempts
cleanly on removal. It uses event-driven lifecycle notifications and bounded
retry rather than busy polling.

The first physical profile qualifies one active controller at a time. The
runtime contract admits zero to many controller instances so later evidence can
add multiple-controller operation without another architecture change. Carrier
availability can drive status and external alerts but never changes publication
semantics or general service readiness.

### Common carrier and platform-driver boundary

The current synchronous datagram-shaped `BleRadio` seam is a semantic and test
migration source, not the final cross-platform production API. Production needs
an asynchronous connection-oriented boundary with operations equivalent to:

- observe controller and permission lifecycle;
- begin/end bounded scan and advertisement windows;
- surface opaque discovery candidates and local locator material;
- listen for and open LE L2CAP CoC connections;
- accept, read, write, cancel, half-close where supported, and close channels;
- report current MTU/packet bounds, estimated useful rate, cost, emission,
  health, and role; and
- guarantee that cancellation releases platform operations within a bounded
  time.

`BleL2capV1` owns Aster carrier framing, deadlines, bounds, scheduling,
session/channel binding, and error classification. Platform drivers own the OS
API adaptation. Swift/Kotlin platform implementations remain in-process through
a narrow FFI callback boundary and do not receive the privileged core adapter
SDK.

### Discovery and emission

The configured modes are:

- `off`: no active scan or advertisement; only manually provisioned contact;
- `rostered`: bounded discovery accepts only a valid provisioned
  discovery-group proof, then requires the mission-authenticated `NodeId` to
  match configured contact policy; this is the production default; and
- `mission`: a later ring in which an unknown carrier locator may become a
  bounded candidate but gains no authority until the complete mission
  handshake and authorization succeed.

Discovery obeys emission policy. Constrained-emission behavior is selected by
the declared profile; the current provisional `PassiveOnly` candidate emits no
framework bytes. Candidate observations,
inbound and outbound pre-authentication slots, handshake concurrency, retry
state, negative cache entries, discovery windows, and retained bytes all have
hard limits.

Decision 0004's emission distinction remains provisional pending stakeholder
validation; this design does not settle its final names or doctrine. Under the
current candidate semantics, `ReceiveOnly` does
not scan, advertise, initiate contact, or originate discretionary discovery,
inventory, reconciliation, administration, or application payload. It may
accept an inbound L2CAP contact and emit mandatory link credits and
acknowledgements, handshake responses, cryptographic acknowledgements, bounded
apply results, and other protocol-required traffic needed to ingest an allowed
Event. Its initiator must obtain the current
carrier locator and PSM from prior normal-mode discovery/contact or explicit
out-of-band provisioning. If that locator expires after restart, ReceiveOnly
does not relax emission policy to repair reachability. `PassiveOnly` emits no
framework bytes and therefore cannot run an ordinary L2CAP session.

`BleL2capV1` defines a common logical discovery profile across its Linux,
Apple, and Android drivers. A separately provisioned discovery-group credential
authorizes candidate filtering but never mission admission. A beacon contains a
carrier-format revision, fresh nonce, bounded current connection locator such
as a dynamic PSM, and a rotating proof under that credential. It contains no
stable peer identity. Receivers validate the proof before allocating a contact
slot, retain a bounded nonce/replay cache, accept only the current and one
explicit prior rotation generation for a bounded overlap, and apply fixed
candidate/rate limits before handshake work.

The exact proof primitive, field packing, truncation, rotation interval, and
credential distribution are not Aster replication or semantic protocol. They
must nevertheless be selected in the named P0 profile through the standards and
build-versus-buy review, frozen for the declared `BleL2capV1` carrier revision,
and covered by cross-platform conformance vectors. A later carrier revision may
replace them without changing stored objects, application APIs, or semantic
version. OS advertisement representation remains platform-local.

The current Linux rostered-discovery slice freezes that carrier-local choice as
`AsterRosterBeaconV1`. It uses private 128-bit service UUID
`6aa1cfed-2ce3-46d4-9c69-a33d1dd54ee5` and a 40-byte Service Data value:

```text
offset  size  field
0       1     revision = 0x01
1       1     flags (bit 0 SESSION_COC_AVAILABLE; all others zero)
2       2     listener_psm, unsigned big-endian
4       4     credential_generation, unsigned big-endian and nonzero
8       16    OS-random nonce
24      16    proof_tag
```

The UUID also appears in the complete 128-bit Service UUID list. This revision
requires the resulting 79-byte extended advertisement on the 1M secondary
channel; it has no legacy-advertisement fallback. With `header = record[0..24]`,
the tag is:

```text
first_16_bytes(HMAC-SHA-256(
    generation_secret,
    "aster/ble-l2cap/rostered-discovery/v1\0" ||
    uuid_network_bytes ||
    header))
```

Verification uses a constant-time comparison. Unknown revisions or generations,
reserved flags, invalid dynamic LE PSMs, and non-exact lengths fail before
candidate allocation. The nonce changes whenever an advertisement generation is
replaced; it is not a counter, time, identity, or durable resume value.

Discovery credentials use the canonical `ASTRBD02` carrier artifact and contain
one emitting generation plus at most one adjacent overlap generation, an opaque
nonzero deployment-scope ID, an increasing manifest sequence, and bounded issue,
lease, and overlap times. Rotation is the fixed stage `(emit g, accept g+1)`,
activate `(emit g+1, accept g)`, then retire `(emit g+1 only)` sequence. The host
credential authority authenticates the artifact source, checks wall/monotonic
continuity, and durably prevents manifest, generation, secret-binding, and
overlap-deadline rollback before exposing a non-cloneable leased credential set
to the adapter. A lease is at most seven days; missing trustworthy time or a
wall/monotonic discontinuity greater than five minutes cancels it rather than
extending it. The unprotected owner-only file loader remains evaluation-only.

This implemented slice remains limited to one configured Linux controller, one
exact mission peer, one dynamic listener PSM, and one active Event contact. The
lower complete mission `NodeId` initiates and the higher listens. Rostered
failure never starts the fixed-locator adapter, GATT, or IP. Multiple peers,
authenticated duplicate-contact arbitration, controller selection, broader
data classes, packaging, support rows, and production authorization remain
future Ring-2 exits. Source and deterministic tests do not create a physical
qualification claim.

Regardless of carrier revision, production discovery discloses no `NodeId`,
mission identifier, topic, scope, priority, inventory, data class, or
application payload; it grants no authority and never transports replication
data. The profile records the unavoidable generic service, timing, size, and
radio-address exposure as part of its metadata budget.

The roster is mission policy keyed by the expected mission `NodeId`, reusing
the selected node's existing peer/configuration authority. It does not durably
bind a Bluetooth address, platform peer handle, controller, or dynamic PSM to
that identity. Discovery yields only a transient locator candidate; the full
mission handshake supplies the identity, and rostered mode closes the contact
unless that authenticated identity is allowed. A manually provisioned carrier
locator may seed contact, while address and PSM refresh remain replaceable
carrier state. This keeps roster policy stable across privacy-address rotation,
adapter replacement, and dynamic PSM assignment.

### Pairing and link encryption

Bluetooth pairing and bonding are optional and security-neutral to Aster.
Deployments may require platform link encryption as defense in depth, but every
new carrier contact still runs the complete Aster hybrid mission handshake.
Pairing does not authorize a peer, bond removal does not revoke mission
membership, mission revocation does not depend on a bond database, and pairing
state is never a durable peer or resume identity.

The first support profile does not require pairing or Bluetooth link
encryption; it must pass over an unsecured L2CAP link so its security evidence
does not depend on carrier protection. A separately declared deployment may
require link encryption and must record that platform policy in its support
row. Failure to satisfy such a deployment policy makes that adapter locally
ineligible; it does not change Aster authentication or application durability.

The initial BTLE profile supports only
`HybridPqAsterRecordV1` (`0x0001`), whose application bytes use the Aster record
layer. `ClassicalP256IrohQuicV1` (`0x0002`) is ineligible on BTLE: it requires
an authenticated Iroh QUIC carrier and exact TLS-exporter binding, neither of
which a Bluetooth address, pairing state, or encrypted ACL link supplies. Any
future carrier-protected BTLE security profile requires its own reviewed profile
identifier, channel-binding construction, downgrade rules, vectors, and
evidence; it is not inferred from link encryption.

### Roles and duplicate contacts

Ring 1 uses provisioned, fixed initiator/listener roles and exactly one eligible
adapter for the peer contact. A competing Iroh or second BTLE contact may
authenticate far enough to identify the peer for safe closure, but it must not
enter capability, inventory, reconciliation, or replication while the
provisioned v9 adapter owns that contact. Ring 1 therefore makes no dynamic-role
or duplicate-contact selection claim.

Ring 2 admits nodes that advertise, scan, initiate, and accept, with separately
bounded inbound and outbound pre-authentication work. No peer-identity decision
is made from an unauthenticated Bluetooth observation. After mission
authentication, duplicate contacts within the same
`(mission NodeId, stable adapter_id)` group are reduced deterministically. The
initial candidate rule keeps the contact whose direction agrees with stable
NodeId ordering, for example lower NodeId outbound and higher NodeId inbound.
Same-direction and multi-controller duplicates are then ordered by a common
contact key:

```text
SHA-256("aster/contact-dedup/v1" ||
       ordered_mission_node_ids || adapter_id || session_transcript_hash)
```

Before Ring 2 implementation, the stable adapter-ID allocation, canonical
ordered-node encoding, role ordering, transcript-digest construction,
comparison/collision behavior, and cross-implementation vectors must be frozen
in the carrier/session conformance contract. Both peers then retain the
lexicographically smallest descriptor after preferred direction within the
adapter group, and losing contacts close without changing durable progress.
The profile retains at most one session per peer and adapter ID; a later profile
that needs simultaneous instances of the same adapter must add a stable
authenticated logical-instance scope rather than using a controller index.
Adapter instance, controller index, Bluetooth address, local arrival order, and
wall clock are not tie-breakers. Concurrent active sessions for distinct
adapter IDs are not v9 behavior; they remain a future semantic-selection
guideline. The collision mechanism is session behavior, not an application API.

### Session and attempt channels

Each new Bluetooth carrier contact opens one session CoC and runs the complete
mission handshake. The authenticated session then carries protected capability,
reconciliation, attempt-open/close, cancellation, liveness, and small data
records.

Additional L2CAP channels are bounded attempt channels. They do not rerun the
mission handshake. Ring 4 semantic-v9 Profile 5 `BlobStreamV1` requires one
bounded DATA/CONTROL channel pair for each selected direction, matching the
existing `StreamAttempt` split. DATA and CONTROL have independently ordered FIN
lifecycle. Resetting or cancelling DATA aborts the attempt; CONTROL may preserve
an already issued authenticated checkpoint or terminal result, but the full
RESULT/ACK settlement requires DATA to remain usable through ACK and orderly
FIN. Settlement after a DATA reset would be new protocol behavior and is not
defined here.

The pair is opened only through the already authenticated carrier contact and
is transiently associated with that exact Bluetooth connection and mission
session before any attempt record is decoded. It reuses the exact frozen
Profile-5 PLAN, `StreamOpenV1`, `StreamSourceV1`, accept, data, checkpoint,
finish, result, and acknowledgement bytes. Binding comes from the existing
session transcript, attempt tuple, lane context, and source authority. No v9
tag, field, ordering rule, protection rule, or meaning changes.

The session channel uses the existing bounded length framing for an ordered
stream. Handshake, capability, inventory/reconciliation control,
acknowledgements, cancellation, liveness, and v9 Event/State/Record traffic use
that authenticated channel. A protected frame may span multiple platform
writes and L2CAP SDUs, but it remains one frame: v9 adds neither the compact
datagram fragment header nor any selected-node fragmentation grammar.

Consequently, v9 cannot interleave another session frame while one length-
framed record is in progress. The evaluation profile therefore caps the
protected Event frame so its worst-case serialization and head-of-line delay
remain inside the declared control-liveness budget. The Ring 1 v9 Event slice
sends an Event larger than the actually negotiated BTLE MTU but no larger than
that profile ceiling, using multiple bounded platform writes on the already
authenticated session CoC. It opens no extra Event channel and changes no v9
Event/profile grammar. State and Record over BTLE are later exits; their large-
object and preemption behavior must be reviewed separately rather than inferred
from the core `Link` reassembler. Under v9, additional CoCs are reserved for
the exact Blob Profile-5 DATA/CONTROL attempt pair. Other additional data-class
channels require a later semantic design and explicit allocation. Closing or cancelling an
attempt pair does not destroy the mission session.

The common carrier treats L2CAP as an ordered credit-controlled stream. Carrier
framing can span platform SDUs, but the adapter must not invent a second Aster
replication fragmentation protocol. The transport-neutral core retains
datagram fragmentation/reassembly authority where that path is used, and bound
ordered streams retain bounded length framing.

`BleL2capV1` has a carrier-local revision contract, not a new Aster semantic
protocol. Ring 1 may choose its framing and association encoding as an initial
single-implementation detail because it claims no cross-implementation
interoperability. Before Ring 2 writes production interoperable carrier bytes,
that revision and its fixtures must freeze:

- session-CoC length framing and serialized request/respond turn correlation;
- initiator/responder opening order and role markers for each DATA/CONTROL CoC
  pair;
- bounded association of an accepted pair with the exact transient Bluetooth
  contact, authenticated mission session, direction, and active attempt before
  semantic records are released to the Profile-5 driver;
- maximum pre-association work, frame/channel counts, timeouts, flow control,
  FIN, half-close, reset, cancellation, and whole-contact close behavior; and
- version mismatch behavior and cross-implementation conformance vectors.

Carrier-local association tokens are demultiplexing capabilities only. They
grant no mission or application authority, own no durable progress, and cannot
replace the authenticated v9 session transcript and attempt tuple. The exact
token and framing encoding are initial `BleL2capV1` implementation choices and
may evolve through a new carrier revision without changing Aster semantic or
storage versions.

### Data-class onion

Capability is added in this order:

1. **Carrier foundation:** Linux lifecycle, discovery policy, L2CAP contact,
   full mission authentication, bounds, status, and cancellation.
2. **Event:** physical small-MTU protected Event exchange, interruption,
   reconnect, restart, and durable application delivery.
3. **State and Record:** the same authenticated contact and reconciliation
   authority, with class-specific convergence and resource evidence.
4. **Blob:** one bounded DATA/CONTROL attempt pair carrying exact semantic-v9
   Profile-5 source and canonical `ASTRBS02` records, with record-level durable
   resume.
5. **Future multi-carrier and finer resume:** a later semantic increment may
   add authenticated per-attempt selection, BTLE-to-IP continuation, and
   transport-neutral intra-record resume only after a separate protocol review.
6. **Additional adapters:** `BleGattV1` or another carrier is independently
   registered and qualified rather than hidden inside `BleL2capV1`.

`BleL2capV1` implements class-neutral contact primitives; v9 has no negotiated
Event-only carrier capability. “Event first” means the initial evaluation
profile symmetrically enables only Event network work through mission/profile
configuration while State, Record, and Blob work remains dormant and durably
pending. Later qualification rings enable those existing classes without
changing the adapter's identity. Another carrier may carry pending work only
when the active semantic/profile explicitly authorizes that selection; v9 does
not infer automatic fallback. Pending work is not discarded or reported as an
application publication failure.

### Blob record-level resume and future guidance

Semantic v9 Profile 5 remains exact. DATA contains a four-byte length followed
by one complete `ASTRBS02` record; fragmented or coalesced records remain
invalid, and durable offsets advance only after complete-record verification.
The attempt also preserves the exact signed PLAN, `StreamSourceV1`/`ASTRPS02`
source, publication and physical-pack identity, custody claim, empty-transfer
sequence, lane AAD, terminal commitment, result, and acknowledgement semantics.
The BTLE qualification profile must budget the frozen maximum record/body,
source, checkpoint, and active-attempt sizes rather than silently imposing a
smaller Blob contract.

Intra-record durable resume is not part of the initial BTLE implementation and
this design allocates no future profile number, tag, record name, or grammar.
A later semantic-version design may add it only if it:

- preserves canonical `ASTRBS02` bytes, `ASTRPS02`/`ASTRPP02` authority,
  publication identity, physical lineage, custody, empty-transfer, terminal
  settlement, and whole-record verification;
- defines the complete source/open/accept/data/checkpoint/finish/result/
  acknowledgement transaction rather than changing only DATA framing;
- keeps provisional prefixes transport-, peer-, adapter-, and connection-
  neutral under the existing lifecycle/store authority, with bounded crash-
  atomic storage and no application visibility before whole-record verification;
- treats a remote checkpoint contradiction as terminal for that authenticated
  peer attempt without allowing either side to command deletion of the other's
  state; each node's lifecycle owner alone validates and may discard its local
  provisional bytes;
- permits restart from zero after locally proven provisional corruption, while
  reserving content-global quarantine for verified corruption of local
  canonical source or verified records; and
- receives independent protocol allocation, downgrade analysis, hostile-input
  review, canonical vectors, and cross-carrier physical evidence before code
  emits new bytes.

### Scheduling and fairness

Separate channels share one controller and RF link, so BlueZ/controller
scheduling alone is insufficient. Aster uses bounded weighted scheduling:

- security, revocation, cancellation, acknowledgements, and liveness receive a
  small reserved control budget;
- Event, State, and Record use priority-aware interactive queues;
- one initial Blob DATA/CONTROL attempt pair consumes remaining capacity;
- Blob receives a bounded minimum share while the link remains healthy;
- higher-priority work pauses Blob emission at portable carrier write-quantum
  boundaries and does not destroy its durable checkpoint; v9 session traffic
  is preemptible only between complete length-framed records, so its profile
  ceiling supplies the control-liveness bound;
- frame count, queue bytes, active attempts, channels, retry count, and time
  without durable progress are bounded.

A write quantum is an Aster-owned bounded byte range accepted only when the
platform driver reports readiness/backpressure capacity. The scheduler queues
at most one quantum per channel per turn, and per-channel plus per-controller
outstanding-byte caps include bytes already accepted by an OS stream but not
yet released by the driver. Physical packet/SDU size is a driver hint, never a
portable pause or completion guarantee. Each support row validates control
latency, Blob minimum progress, and memory bounds against its actual platform
stream and controller behavior.

Exact weights, capacities, and deadlines belong to a declared qualification
profile and production-limit contract tests, not universal wire constants.
Ring 1 implements only the bounded session-channel queue and Event/control
liveness needed by its topology. State/Record scheduling becomes claim-blocking
in Ring 3, and Blob share plus DATA/CONTROL fairness becomes claim-blocking in
Ring 4; these extend the same scheduler rather than replacing it.

### V9 evaluation and future selection guidelines

Adding a transport does not itself change the replication wire/profile or
semantic version. The first physical Event evaluation uses semantic-v9 behavior
with exactly one contact-agreed eligible adapter. `BleL2capV1` is therefore
testable without combining new radio I/O and a new selection protocol.

For the v9 evaluation topology, provisioning makes exactly one adapter type
eligible for the peer contact: the BTLE test disables the peer's competing IP
contact, while the existing Iroh profile remains unchanged elsewhere. V9 does
not choose between simultaneously eligible BTLE and IP adapters. Enabling both
for one contact is outside the v9 evaluation claim rather than an invitation
for each peer to guess independently.

This design allocates no automatic multi-carrier protocol. A later semantic-
version design may add one only if it generalizes the existing registry,
selector, and attempt coordinator as the single authority and preserves these
constraints:

- support, selection, and acceptance are authenticated and bound to the exact
  mission session, peers, adapter, logical operation, attempt, and policy;
- locators come only from local configuration, provisioned peer data, or that
  carrier's independently authenticated discovery path; negotiation cannot
  authorize a locator or accept peer-supplied ranking;
- selection is per bounded attempt, never per fragment, and a live attempt does
  not change carrier;
- the selected carrier independently completes the full mission handshake;
  session keys, transcripts, replay windows, and channel capabilities are never
  transferred between carriers and no handoff token substitutes for a session;
- only named transport-scoped failures permit a fresh attempt on another
  eligible carrier, with bounded retry, backoff, and anti-oscillation; and
- protocol, integrity, authentication, authorization, policy, and lifecycle
  failures remain terminal within their declared scope and cannot be masked by
  changing carriers.

The contact/attempt boundary exposes a closed failure taxonomy. Zero carrier
credit is ordinary backpressure: it pauses emission and remains under bounded
control-liveness observation. An explicit exhausted/deferred-capacity outcome
is a non-fallback availability result and waits for a named capacity or
lifecycle event. Only loss of progress while positive credit exists, or loss
of required control liveness beyond the declared deadline, is a retryable
transport stall. Adapter unavailability, link loss, and a transport deadline
are also retryable only within the current profile's attempt budget. Under v9,
"retryable" permits a fresh attempt on the same provisioned adapter; it does
not authorize another carrier. Cross-carrier retry remains a future semantic
selection decision. Terminal outcomes include framing/bounds violations,
protocol contradiction,
authentication, integrity, authorization, replay, policy, lifecycle, explicit
application cancellation, and internal invariant failure. Each terminal result
declares its scope: normally `(authenticated peer NodeId, logical operation or
transfer_id, policy generation)`, and content-global only after verified local
canonical-source or local-record corruption. Platform and Iroh errors must map
losslessly into one category and scope; unknown errors default terminal for the
current peer-scoped operation, not retryable. Negative tests prove that every
terminal category opens no alternate carrier within its scope while an
unrelated authorized peer remains usable.

Before mission authentication establishes a `NodeId` and operation, framing,
bounds, authentication, replay, and unknown failures terminate only the
transient carrier candidate/contact. They may update bounded, expiring,
non-authoritative rate-limit or negative-cache state, but may not mutate durable
peer/operation state, create a peer-scoped terminal result, or suppress an
authenticated peer on another contact.

`BleGattV1`, if later implemented, is a separate adapter with its own capability
and resource profile. There is no automatic GATT fallback hidden inside
`BleL2capV1`.

A peer whose highest common version is v9 follows the v9 single-provisioned-
adapter rule only in a profile that explicitly permits it. No future semantic
increment may reinterpret a v9 tag, profile, record, claim, or failure as
automatic transport selection or intra-record resume.

No production BTLE claim is permitted until mission authority can sign the
minimum allowed semantic version, each node durably retains a per-identity
highest-successful semantic version across restart, and any rollback has
explicit authenticated authorization. A fresh contact selecting below the
mission minimum or retained high-water fails before inventory. Mixed-version,
credentialed rolled-back-peer, restart, and authorized rollback tests are
release gates. Any future selection protocol must add explicit failed-newer-
then-v9 downgrade tests before it is eligible for implementation.

## Application and operator experience

Application developers continue to use publish, subscribe, query, conflict,
and status operations. They do not select a carrier or observe MTU, channel,
fragment, PSM, pairing, or checkpoint details. Publication remains locally
durable with no controller, no peer, or no transport.

Operators configure carrier policy and inspect transport-neutral status.
BTLE-specific diagnostics may expose controller identity, platform driver,
discovery state, connection role, negotiated MTU, useful-rate estimate,
session/channel counts, L2CAP errors, retry state, and last durable progress.
Normal status uses bounded sanitized states such as `disabled`, `available`,
`discovering`, `connecting`, `authenticating`, `active`, `degraded`, and
`unavailable`.

There is no `required` carrier switch. A configured but nonexistent adapter is
`unavailable`; Ring 1 can recover it through restart or explicit
reconfiguration, and Ring 2 can admit it later through live hot-plug. Malformed
or internally contradictory configuration remains an ordinary startup
configuration error.

## Cross-platform drivers and qualification

### Platform drivers

- **Linux PC and CM4-class hardware:** one BlueZ/kernel L2CAP driver; hardware
  differences affect evidence, not architecture.
- **macOS and iOS:** a CoreBluetooth driver publishes and opens L2CAP channels
  and bridges platform streams into the common carrier. Dynamic PSM discovery
  remains carrier-local.
- **Android:** a Kotlin platform driver uses public LE L2CAP CoC client/server
  APIs, dynamic PSM discovery, runtime Bluetooth permissions, and lifecycle
  callbacks.

The first mobile claim is foreground interoperability. Background-capable
Android and iOS operation is a separate profile covering permissions,
advertising/scanning limits, suspension and restoration, process termination,
energy behavior, and durable recovery. Foreground success never implies
continuous background mesh participation.

### Additive support registry

Production support is recorded per tested combination rather than inferred from
an operating-system family. Each retained row names:

- OS/distribution and version;
- architecture;
- kernel and BlueZ or platform framework version where applicable;
- controller/chipset and firmware;
- driver build identity;
- supported roles, L2CAP behavior, and relevant lifecycle mode;
- observed MTU, rate, resource, and energy bounds;
- conformance scenarios and artifact identities; and
- exclusions or known limits.

Available CM4 units may be the first row. Linux PCs and other controllers are
added as they pass. No row automatically qualifies neighboring hardware.

### Interoperability matrix

The first matrix is a Linux-reference star:

```text
Linux reference <-> Linux PC or CM4
Linux reference <-> macOS
Linux reference <-> Android foreground
Linux reference <-> iOS foreground
```

Each driver must pass against the qualified reference before broader pairwise
testing. Later matrices add mobile-to-mobile and non-Linux desktop pairs where
the selected product profile requires them.

## Security and privacy invariants

- All carrier input is untrusted until the Aster mission handshake and current
  authorization succeed.
- No inventory or application data is exchanged before authentication.
- Discovery input is bounded and cannot directly name durable mission state.
- Bluetooth addresses, pairing, bonds, PSMs, controller IDs, and platform peer
  handles are locators, never mission identity.
- Advertisement and connection metadata reveal only what the carrier
  necessarily exposes; application routing metadata remains protected.
- Every parser, length, collection, queue, task, channel, timeout, and retained
  provisional byte set is bounded before allocation or work.
- Duplicate, replayed, truncated, reordered, unauthenticated, and
  resource-exhausting input fails closed without mutating verified durable
  truth.
- Transport failure cannot erase verified progress or convert an unauthorized
  operation into an authorized retry on another carrier.

## Failure and recovery model

Platform absence, radio disablement, permission loss, connection failure,
positive-credit no-progress, control-liveness timeout, and controller removal
are carrier availability or transport-attempt failures. Zero credit is bounded
backpressure, while explicit exhausted/deferred capacity waits for its named
availability event; neither alone is a fallback trigger. All cases retain
durable truth and allowed provisional progress, update status, and wait for an
event-driven recovery opportunity or a retry permitted by the active ring.

Malformed protocol data, failed record authentication, replay, peer identity
mismatch, revoked membership, policy denial, or lifecycle contradiction follows
the existing protocol/security failure path and is not transport-fallback
eligible.

Process restart reconstructs carrier availability from platform state and
reconstructs protocol progress only from the mission-bound store and Blob
lifecycle authority. BlueZ, CoreBluetooth, Android, or a driver callback queue
never becomes the source of durable resume truth.

## Verification and evidence plan

### Ring 0 deterministic baseline

- Service readiness and durable local publication with no configured
  transport, a configured-but-absent controller, and no currently eligible
  adapter.
- Pending work remains durable and becomes eligible when a provisioned adapter
  appears; absence never becomes an application publication failure.
- Iroh parity tests over the selected-node contact abstraction before BTLE is
  enabled, proving the refactor does not change existing behavior.

### Ring 1 initial v9 non-IP Event exit

Two physical Linux targets, with fixed provisioned roles and competing IP
contact disabled for the peer, must:

- use the in-process BlueZ/kernel L2CAP CoC driver and one session channel;
- authenticate with `HybridPqAsterRecordV1` (`0x0001`) and reject
  `ClassicalP256IrohQuicV1` (`0x0002`) before inventory;
- prove typed BTLE locator evidence cannot become an Iroh `EndpointId` or
  authenticated-carrier observation;
- exchange and durably deliver one protected Event larger than the actual
  negotiated CoC MTU using the bounded ordered-stream framer, without changing
  v9 Event, mission, storage, or application bytes;
- exchange and validate the complete frozen-v9 `TransferProfileOfferV1` values,
  including the Blob lane/Profile 5, and compute the unchanged
  `transfer_profile_digest`, while opening no Blob attempt;
- prove no inventory or Event data is released before mission authentication;
- exercise link disconnect/reconnect, controller loss followed by node restart
  or explicit reconfiguration, and process restart without silent loss or
  duplicate semantic delivery; live in-process hot-plug remains Ring 2;
- demonstrate bounded frame, queue, task, descriptor, memory, and deadline
  behavior for the exercised topology; and
- retain the exact build, hosts, controllers, configuration, logs, and run
  receipt while labeling the result only as v9 non-IP Event validation.

Ring 1 may use the actually negotiated MTU and a provisioned locator. It does
not require dynamic discovery, dynamic role collision, the production MTU
floor, constrained-emission doctrine, all-class scheduling, Profile-5 transfer
execution,
cross-platform vectors, or a production support-row claim.

### Ring 2 production Event exit

- Adapter contract tests cover zero/one/many dynamic instances, cancellation,
  limits, event-driven hot-plug, bounded rostered discovery, and hostile
  candidates.
- The support profile declares the smallest supported CoC MTU. Deterministic
  and physical tests force that floor, send an Event above it, and demonstrate
  the declared control-liveness and resource bounds rather than extrapolating
  from a larger negotiated MTU.
- Two-or-more same-adapter duplicate contacts in both directions prove the
  frozen adapter ID, canonical encoding, role order, transcript digest, and
  collision vectors select the same survivor on both peers.
- Packet capture and fault-shim evidence covers the declared discovery and
  metadata budget, malformed framing, replay, drop, truncation, and resource
  exhaustion. Reliable ordered CoC is not claimed to generate reordering or
  corruption naturally.
- If `ReceiveOnly` is included after stakeholder approval, it originates no
  discretionary discovery, inventory, reconciliation, administration, or
  application payload. Evidence separately enumerates the mandatory link
  credits/acknowledgements, handshake responses, cryptographic
  acknowledgement, apply result, and other protocol-required emissions that
  remain allowed. `PassiveOnly`, if included, emits no framework bytes and
  cannot run an ordinary L2CAP session.
- Credit tests distinguish zero-credit backpressure, explicit
  exhausted/deferred capacity, positive-credit no-progress, and control-
  liveness loss. Only the latter two map to retryable transport stall, and v9
  still opens no alternate carrier.
- Retained packet, memory, queue, descriptor, task, CPU, and energy evidence is
  tied to the exact production support row.

### Rings 3–5 exits

- **Ring 3:** State and Record convergence, interruption, restart, priority,
  preemption, and resource evidence over the same carrier.
- **Ring 4:** exact Profile-5
  PLAN/OPEN/SOURCE/ACCEPT/DATA/CHECKPOINT/FINISH/RESULT/ACK, empty transfer,
  maximum-length DATA, ordered DATA/CONTROL FIN, DATA-reset attempt abort,
  restart, canonical-record verification, bounded memory, and record-level
  resume. A result already received on CONTROL may be retained, but successful
  RESULT/ACK settlement requires DATA through ACK and orderly FIN.
- **Ring 5:** Linux-reference interoperability with each admitted Linux
  hardware row, macOS, Android foreground, and iOS foreground; separate mobile
  background profiles; and required hostile-peer, security, packaging,
  dependency/license/SBOM, resource, independent-implementation, and release-
  authorization gates.

After a separately approved future semantic design, cross-carrier continuation
and per-class concurrent selection require their own end-to-end evidence. They
are not v9 or BTLE-adapter acceptance criteria.

Simulation and focused code tests remain implementation evidence only. Physical
hardware, representative lifecycle, and retained receipts are required before
moving requirement or capability maturity.

## Required decisions and governance records

Governance follows the same onion; outer-ring decisions do not become hidden
prerequisites for Ring 1.

Before Ring 1 implementation, the named evaluation profile must contain its
P0-1 claim boundary, fixed topology and roles, supported security profile,
finite bounds, evidence plan, exclusions, and owners/dates/blocking status for
unresolved decisions. The Decision 0007 update must authorize the asynchronous
ordered selected-node seam and the path-specific framing ownership described
above. The dependency/build-versus-buy record must cover the chosen Linux
BlueZ and async I/O implementation. Ring 1 needs no discovery proof, mobile
driver, duplicate-contact grammar, Profile-5 attempt-channel mapping or
execution, production support row, or future selection allocation. It still
uses the exact frozen-v9 complete profile offer and digest.

Before Ring 2 production Event qualification, the records must additionally
contain:

- stakeholder disposition of Decision 0004's ReceiveOnly/PassiveOnly names and
  mandatory-emission semantics, or an explicit exclusion from the claim;
- the signed semantic minimum, durable per-identity high-water, and authorized
  rollback design required for that production profile;
- standards and build-versus-buy coverage for discovery credentials/proofs,
  typed carrier evidence, the frozen carrier revision, and duplicate-contact
  construction and vectors; and
- dependency governance, license, vulnerability process, maintenance, SBOM,
  support-row, resource, and release evidence for the admitted production
  graph.

Rings 3–5 add their class, Profile-5 channel-pair binding, platform, packaging,
and release records when those capabilities enter the claim. A separate
protocol decision, exact registry allocations, canonical grammar, bounds,
transcript/AAD bindings, compatibility rules, and conformance vectors are
mandatory before any future semantic increment writes transport-selection or
intra-record-resume bytes.

The standards record must identify evaluated published Bluetooth and platform
facilities and explain every bespoke mechanism that remains. Architecture
approval does not satisfy these records, and an implementation plan may schedule
their creation but may not assume their outcomes.

## Compatibility and migration

- Replication wire/profile version 1 remains unchanged by adding
  `BleL2capV1`.
- Semantic versions 1 through 9 retain their existing bytes and meaning.
- The v9 physical evaluation slice admits exactly one contact-agreed eligible
  adapter, makes no automatic cross-transport claim, and is not production
  qualification.
- This design allocates no post-v9 semantic version, profile, tag, or record.
  Any future transport-selection or intra-record-resume design must use new
  allocations and must not reinterpret Profile-5 mechanics or bytes.
- Current nodes continue through one contact-agreed eligible adapter or existing
  Iroh behavior.
- Discovery encoding revisions are carrier-local and do not force semantic or
  storage migration.
- Adding platform support adds evidence and packaging, not protocol identity.

## Builder decisions left open

After the required profile and governance decisions are adopted, the
implementation plan may select these without changing the design, provided the
choices and tests are explicit:

- exact Rust BlueZ and async I/O dependencies from the admitted
  build-versus-buy result;
- the narrow asynchronous platform-driver method names and ownership model;
- the concrete replacement API for Iroh-specific `MissionPeerBinding`, provided
  it preserves typed carrier evidence, exact Iroh checks, mission-only BTLE
  roster admission, and the prohibition on fabricated `EndpointId` values;
- exact `BleL2capV1` carrier-revision framing, pair-association token, and role
  encoding within the mandatory invariants and conformance requirements above;
- initial finite capacities, deadlines, weights, retry limits, and negative
  cache sizes inside the ratified profile bounds;
- the first available CM4/Linux-PC controller combinations used for evidence;
- packaging permissions and systemd sandbox details that grant only the
  platform access actually required; and
- the exact retained support-registry schema and receipt locations.

The implementation plan may not invent discovery cryptography, a future
semantic/profile grammar, downgrade/rollback policy, session/channel authority,
or fallback classification. Those are reviewed profile/protocol decisions and
must already be frozen with vectors before their implementation task starts.

Any choice that changes authority, durable state ownership, public API,
fallback eligibility, versioning, or the selected process boundary requires a
new owner decision rather than an implementation-plan assumption.
