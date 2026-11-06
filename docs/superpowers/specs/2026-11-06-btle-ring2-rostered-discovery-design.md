# BTLE Ring 2 Rostered-Discovery Increment Design

**Status:** owner-approved for implementation
**Date:** 2026-11-06
**Parent design:** `2026-11-03-production-btle-design.md`
**Predecessors:** `2026-11-05-linux-btle-unattended-lifecycle-design.md`
and `2026-11-06-linux-btle-clean-restart-design.md`
**Capability lane:** Ring 2 production Event, discovery-first increment

## Intent

Replace Ring 1's provisioned remote Bluetooth address and PSM with bounded,
authenticated rostered discovery on Linux while preserving the existing
in-process onion architecture, semantic-v9 Event exchange, mission handshake,
durable publication, and Linux-owned lifecycle.

This is the first Ring 2 increment, not the complete Ring 2 production claim.
It deliberately keeps one configured controller, one exact mission peer, one
active Event contact, and the already-derived NodeId role. It proves that a
valid roster member can find the peer after Bluetooth privacy-address rotation
and a listener can publish a newly allocated PSM without making Bluetooth
metadata an identity or changing the Aster protocol.

The complete Ring 2 exit still requires later increments for multiple
rostered peers, same-adapter authenticated duplicate-contact arbitration,
zero/one/many controller instances, the declared minimum supported CoC MTU,
constrained-emission disposition, packaging, resource evidence, support rows,
and release governance.

This document contains two independently accepted lanes. The Linux rostered-
discovery lane is the only Ring 2 gate. The Android durable-send and Linux
terminal lane is a companion interoperability example: it may share the PR and
release train, but it has separate commits, tests, receipts, rollback, and
approval, and cannot block or strengthen a Linux rostered-discovery support
claim.

## Decisions carried forward

- The driver is a trusted in-process Linux adapter, not an Aster system daemon.
- Transport lifecycle remains private to `aster-ble-linux`; no generic
  lifecycle abstraction is added.
- Aster is ready without any transport. Local publication remains durable and
  pending when BTLE is disabled, unsupported, absent, or undiscoverable.
- `BleL2capV1` is an independent adapter. There is no hidden GATT or IP
  fallback and no v9 automatic carrier selection.
- Bluetooth addresses, PSMs, controller names, advertisement handles, and
  BlueZ device objects are transient locators only.
- Every connected candidate still runs the complete
  `HybridPqAsterRecordV1` mission handshake. Discovery proof neither replaces
  nor weakens it.
- The increment remains Event-only at product policy. It changes no Event,
  mission, profile, storage, application, or semantic-version bytes.

## Approaches considered

### 1. Discovery-first carrier contract — selected

Freeze and test the bounded discovery proof, locator lifetime, candidate
admission, and Linux scan/advertise ownership before widening scheduling or
packaging. This removes the largest remaining Ring 1 product limitation:
fixed peer locators do not survive privacy-address rotation or dynamic PSMs.

### 2. Scheduler-first Ring 2

Generalize the current single-contact supervisor for many peers and
controllers before adding discovery. This would build scheduling around the
wrong fixed-locator input and would not create a usable production discovery
path. It is deferred.

### 3. Packaging-first Ring 2

Install the fixed-locator evaluator as a service and harden the image first.
That would operationalize an evaluation topology rather than close its main
product gap. Packaging follows the discovery and lifecycle contract.

## Scope

### In scope

- one configured Linux BlueZ controller;
- exactly one authority-rostered mission peer;
- an explicit `RosteredAdapterConfig::Off | Enabled(config)` boundary, with
  `Off` constructing no listener, advertisement, scan, or supervisor;
- a separate provisioned discovery-group credential with one emitting and one
  optional overlap generation;
- a frozen `AsterRosterBeaconV1` carrier record and canonical vectors;
- private random-address and public-address candidates;
- listener-selected dynamic LE PSM publication;
- bounded scan, advertise, candidate cache, replay cache, retry, timeout, and
  pre-authentication work;
- complementary role derived from the two exact mission NodeIds, as today;
- semantic-v9 Event contact and durable reconnect behavior;
- deterministic fault tests plus Linux physical validation; and
- a minimal foreground Android example that durably publishes one operator-
  entered short Event through the existing manual-locator v9 validator, with
  an explicit Linux example mode that displays and acknowledges it.

### Deferred from this increment

- more than one mission peer or discovery group;
- learning or modifying the mission roster from discovery;
- simultaneous contacts, post-authentication duplicate arbitration, and the
  common contact-key vectors from the parent design;
- automatic controller selection or multiple active controllers;
- State, Record, Blob, GATT, IP fallback, or cross-carrier continuation;
- `mission` discovery mode, opportunistic admission, pairing workflow, or bond
  authority;
- `ReceiveOnly` and `PassiveOnly` production claims;
- Android rostered discovery, Android production/background operation, Apple
  drivers, and cross-platform qualification;
- production daemon/service packaging and production support-row approval; and
- signed semantic-minimum/high-water/rollback completion required for the
  final Ring 2 production claim; and
- packaging-level crash/power-loss authorization, hostile-RF host-boundary
  approval, and release governance required for a final production claim
  beyond the forced-termination evidence in this increment.

## Threat and authority model

The discovery proof is a contact-work filter for a provisioned group. It is
not peer identity, mission membership, application authorization, forward
secrecy, or a replacement for the mission handshake. Anyone holding the group
credential can generate a proof-valid candidate and consume only the bounded
pre-authentication budget. Only the subsequent mission handshake can identify
the configured NodeId and authorize inventory or Event work.

An observer without the credential learns that an Aster BTLE carrier is
present, the carrier record revision, a current connection PSM, a credential
generation number, and random-looking nonce/tag bytes. The record contains no
NodeId, mission ID, topic, scope, priority, inventory, data class, application
payload, stable Bluetooth address, or durable progress.

A captured valid beacon can be replayed. The receiver rejects a replay while
its bounded cache retains the token, but cache loss, controller-epoch change,
or process restart loses that freshness history. A retained collection can
therefore consume the fixed per-window candidate and attempt budgets, not only
one attempt. A faster relay can win first observation for each new nonce and
suppress the genuine locator until the next nonce, and a two-ended wormhole
can forward the complete mission-authenticated contact. The discovery proof
provides neither distance, proximity, anti-relay security, nor freshness after
cache loss. It still cannot authenticate a mission peer or mutate durable
peer/application state without the mission handshake. These are explicit RF
availability and correlation tradeoffs; deterministic and physical evidence
must exercise them.

The static UUID, extended-advertisement shape, credential generation, refresh
cadence, PHY, PSM continuity, and radio-address behavior disclose Aster
presence and can correlate members or movement even though no mission or
application identifier is present. Generation allocation is deployment-local
and must not encode a customer, site, mission, date, or geography. The design
makes no anonymity or unlinkability claim.

## Frozen discovery carrier record

### Advertisement identity

Linux publishes the record as Service Data under this private 128-bit UUID:

```text
6aa1cfed-2ce3-46d4-9c69-a33d1dd54ee5
```

The UUID is an Aster carrier identifier, not a GATT service and not an Aster
semantic/profile allocation. A private 128-bit UUID avoids using an unassigned
16-bit UUID or another organization's Bluetooth Company Identifier.

Extended advertising is mandatory for this revision. To avoid relying on
undocumented ServiceData-only filter behavior, the UUID is present both in a
Complete 128-bit Service UUID AD structure and as the Service Data UUID. The
40-byte value requires a 58-byte Service Data structure; the complete UUID
list requires 18 bytes and Flags requires three, for exactly 79 advertising-
data bytes. It cannot fit in a 31-byte legacy advertisement or scan response.

The complete BlueZ advertisement tuple is frozen: `Type = peripheral`, the
single complete service UUID above, exactly one Service Data entry, no local
name, appearance, manufacturer data, solicit UUID, TX-power include, or other
include; `Discoverable = false`; `SecondaryChannel = 1M`; minimum and maximum
interval both 250 ms; no duration; and `Timeout = 30 seconds`. Any platform
default that adds or removes a field fails the packet-capture gate. Linux
requires all of:

- `SupportedSecondaryChannels` contains `1M`;
- `SupportedCapabilities.MaxAdvLen` is at least 79 bytes;
- at least one advertising instance is available; and
- BlueZ accepts registration of the complete `Advertisement` without
  `InvalidLength`.

Those are runtime eligibility checks, not proof of over-air interoperability.
Registration success cannot prove preservation, placement, or absence of
managed fields. The support row separately requires a qualified independent
scanner packet capture to recover the exact complete UUID list, Service Data
UUID, all 40 record bytes, Flags, intervals, PHY, and absence of unexpected
fields. Runtime cannot prove remote recovery. Failure of a local check makes
rostered mode `unsupported`; failure of the physical check blocks that
hardware support row. Neither case falls back to unauthenticated, legacy,
fixed-locator, GATT, or IP operation.

The common record bytes and validation do not otherwise depend on BlueZ's
placement.

### `AsterRosterBeaconV1`

The Service Data value is exactly 40 bytes:

```text
offset  size  field
0       1     revision = 0x01
1       1     flags
2       2     listener_psm, unsigned big-endian
4       4     credential_generation, unsigned big-endian
8       16    nonce
24      16    proof_tag
```

Flags bit 0 is `SESSION_COC_AVAILABLE` and must be one in this increment.
Bits 1 through 7 are reserved and must be zero. Unknown revisions, reserved
bits, wrong lengths, PSMs outside `PSM_LE_DYN_START..=PSM_LE_MAX`, and unknown
credential generations are rejected before candidate allocation.

`nonce` is generated with the operating system CSPRNG whenever an advertisement
generation is replaced. It is never a counter, time, identity, or durable
resume value. Replacement starts at 25 seconds and the BlueZ timeout caps the
old generation at 30 seconds. The generator rejects equality with the previous
locally emitted nonce, redraws at most three times, and otherwise makes
rostered discovery unavailable. Random-generation failure never deliberately
reuses a known nonce. The 128-bit field is frozen so a later multi-peer group
does not inherit the unacceptable fleet-scale birthday bound of 64 bits.

### Proof construction

Each credential generation is an independently provisioned, nonzero 32-byte
random secret. Generation zero is reserved. For record bytes
`header = record[0..24]`:

```text
proof_tag = first_16_bytes(
    HMAC-SHA-256(
        generation_secret,
        "aster/ble-l2cap/rostered-discovery/v1\0" ||
        uuid_network_bytes ||
        header
    )
)
```

`uuid_network_bytes` is the 16 canonical UUID bytes in displayed order. The
HMAC output is truncated from its first byte to 128 bits. Verification uses a
constant-time comparison. No raw hash-as-MAC or bespoke key derivation is
permitted.

The implementation uses a minimal workspace-pinned patch of RustCrypto
`hmac = "=0.13.0"`, with default features disabled and `zeroize` enabled. In
addition to upstream digest-state zeroization, the patch wraps the private
derived-key/IPAD/OPAD construction buffer in `Zeroizing` so every normal,
error, and unwind path erases it. Source review and drop-path tests cover the
temporary, pads, and working state; a caller wrapper or transitive feature
unification cannot satisfy the gate. Patch digest, feature, license,
vulnerability, maintenance, and SBOM records are part of the gate.

Canonical conformance fixtures distinguish valid-minimum and valid-maximum
records from explicitly rejected zero generation, zero secret, zero PSM, and
zero availability-flag cases. They cover emitting and overlap secrets, every
single-field mutation, reserved flags, unknown revision/generation, invalid
PSMs, truncated and oversized records, tag mutation, and the reviewed
constant-time comparison API. Timing unit tests are not accepted as evidence
of constant-time behavior. The fixture file contains synthetic credentials
only.

### Credential rotation and custody

The adapter receives one non-`Clone`, redacted, zeroize-on-last-drop
`LeasedDiscoveryCredentialSet` containing a required emitting generation, one
optional overlap generation, and a monotonic expiry. The adapter emits only
the emitting generation and verifies either member. Credential generation is
strictly increasing and a stage may add only `current + 1`; overflow is a hard
provisioning failure. This makes retirement state fixed-size instead of an
unbounded set.

The embedding process loads the secret through the existing provisioning
secret custody boundary and passes a zeroizing opaque value to
`aster-ble-linux`. The adapter neither opens a secret file nor owns a durable
secret store. Debug/status/error values expose only generation numbers and
closed categories, never secret bytes, tag bytes, nonces, peer addresses, or
mission identities.

The credential artifact is canonical carrier configuration loaded only from
an authenticated production provisioning source, not an Aster semantic
protocol object:

```text
magic "ASTRBD02" (8 bytes)
manifest_sequence (8 bytes, unsigned big-endian, nonzero)
entry_count (1 byte, 1 or 2)
issued_at_unix_seconds (8 bytes, unsigned big-endian, nonzero)
lease_not_after_unix_seconds (8 bytes, unsigned big-endian, nonzero)
overlap_not_after_unix_seconds (8 bytes; zero with one entry)
deployment_scope_id (32 nonzero random bytes)
emitting_generation (4 bytes, unsigned big-endian, nonzero)
emitting_secret (32 bytes, not all zero)
[overlap_generation (4 bytes, unsigned big-endian, nonzero)
 overlap_secret (32 bytes, not all zero)]
```

The exact artifact is 109 bytes with one entry or 145 with two. The production
source is an approved `ProvisioningSecretLoader` provider whose authenticated
opaque credential binds these bytes; the unprotected-reference loader is never
a production source. `deployment_scope_id` is an independently provisioned
opaque value, compared as exact bytes with the host's expected ID and never
advertised or logged, preventing cross-deployment reuse without a string hash.

`lease_not_after` is later than `issued_at`, no more than seven days later, and
not expired. With one entry, `overlap_not_after` is zero. With two entries, the
two secrets differ and their generation numbers form the adjacent set
`{g, g + 1}`; ordering is transition-specific rather than a generic parser
rule. Stage is exactly `(emitting g, overlap g+1)`, activation is exactly
`(emitting g+1, overlap g)`, renewal preserves the exact ordered state, and
retirement is `(emitting g+1, no overlap)`. `overlap_not_after` is later than
`issued_at`, no later than both `lease_not_after` and seven days after the
original stage. Renewal may shorten but never extend the stored overlap
deadline. No trailing bytes are accepted.

`aster-host::discovery_credentials` owns a private
`DiscoveryCredentialAuthority`, composed from the authenticated loader, exact
deployment-scope ID, a `TrustedClock`, and a fixed-size checkpoint store. The
checkpoint contains version, deployment-scope ID, highest manifest sequence,
artifact SHA-256, emitting/optional overlap generation, one fingerprint for
each active generation-to-secret binding, retired-through generation, and
original overlap deadline. A fingerprint is
`HMAC-SHA-256(secret, "aster/ble-l2cap/discovery-key-binding/v1\0" ||
deployment_scope_id || generation_be)` and is owner-protected like the
checkpoint; it never enters logs, receipts, or the beacon. The only transitions
are:

1. initialize one generation;
2. renew the identical ordered active state at a higher manifest sequence;
3. stage exactly `current + 1` while continuing to emit current;
4. activate that same two-generation set by emitting next; and
5. retire current by retaining next alone and advancing `retired_through`.

Every generation omitted by an accepted transition becomes retired. A lower
sequence, different artifact at the same sequence, generation at or below
`retired_through`, skipped stage/activation, changed ordered state or binding
fingerprint during renewal/activation, or overlap-deadline extension is
rejected.

Before credentials are exposed, the authority writes the complete next
checkpoint to one fixed same-directory temporary file, syncs it, atomically
replaces the checkpoint, and syncs the parent directory while holding the
single-writer lock. A crash before replacement leaves the old authority; a
crash after replacement makes the same sequence/digest idempotently exposable
on restart but prohibits rollback. Missing, corrupt, or contradictory
checkpoint state fails closed. Temporary-file creation and cleanup are bounded
to that one fixed name.

`TrustedClock` returns one checked wall/monotonic sample. It rejects an artifact
outside its authenticated validity interval and derives the lease as
`monotonic_now + (lease_not_after - wall_now)` with checked arithmetic. The
authority resamples every 60 seconds; a missing sample or a wall-versus-
monotonic discontinuity over five minutes cancels the lease and requires a
fresh authenticated load. A two-entry lease is additionally capped by the
stored overlap deadline. The adapter tears down discovery at lease expiry and
does not parse the artifact or own clock/high-water state.

The unprotected-reference evaluator takes an explicit
`--discovery-credential-unprotected-reference FILE`, requires an owner-only
regular file of exactly 109 or 145 bytes and labels the bypass non-production.
It opens once with `openat2` beneath the configured parent, or `O_NOFOLLOW`
where the exact platform lacks `openat2`; validates the opened descriptor with
`fstat` before and after the bounded read; requires effective-UID ownership,
`mode & 0o077 == 0`, one link, stable device/inode/size, and no trailing bytes;
and reads directly into `Zeroizing<Vec<u8>>`. It never reopens by path or puts
credential bytes on a command line, environment variable, debug value, error,
or receipt. It still exercises the same parser and transition machine in a
temporary evaluator checkpoint, but its source is explicitly unauthenticated.
Production embedding loads the artifact through the authority above; the Linux
adapter receives only the leased decoded set.

This custody scope covers application-owned buffers and cryptographic working
state. It does not claim erasure from swap, core dumps, kernel page cache,
controller memory, physical media, or a compromised process; production
packaging must separately disable or protect those surfaces.

Rotation is operator/provisioner driven in three phases:

1. Stage: every node emits old and accepts `{old, new}`.
2. Activate: nodes may be updated gradually to emit new and accept
   `{new, old}`; old and new nodes still verify each other in both directions.
3. Retire: only after fleet activation is confirmed does every node emit and
   accept new alone.

Skipping the stage or retiring before fleet activation is rejected by the
transition machine and can partition nodes not yet updated. Stage, activation,
and retirement each require an authenticated increasing artifact and a durable
deployment receipt. Overlap can never exceed its original seven-day deadline.
No adapter changes its emitting generation based on peer input, and manifest
sequence or deadline never enters the beacon or semantic-v9 protocol.

## Linux onion architecture

### Configuration split

Keep Ring 1's fixed-locator `DriverConfig` and `LinkConfig` for retained
evaluation compatibility. Do not overload them with optional fields whose
meaning changes by mode.

Add a rostered configuration rooted in the same resource limits:

```text
RosteredAdapterConfig
  Off
  Enabled(RosteredSupervisorConfig)

RosteredSupervisorConfig
  controller: ControllerConfig
  discovery: RosteredDiscoveryConfig
  local_mission_id: NodeId
  peer_mission_id: NodeId
  contact_cadence: Duration
  contact_limits: ContactLimits
```

`ControllerConfig` owns only controller name and exact expected local
controller identity. `RosteredDiscoveryConfig` owns the credential set and
selects the fixed qualification profile. It has no peer Bluetooth address,
remote PSM, or user-tunable discovery timing/capacity fields.
`ContactLimits` preserves the existing frame, exchange, open, and operation
bounds. Validation remains synchronous and completes before BlueZ is touched.

`RosteredAdapterConfig::Off` constructs no rostered supervisor, listener,
advertisement, scan, cache, or task. It does not mean fallback. The fixed-
locator evaluator remains a separate explicit configuration/API while
compatibility is needed; it is not a variant of this enum and is never selected
automatically after rostered discovery failure.

### Private platform boundary

Add Linux-private, injected interfaces at the same level as the existing
availability monitor and socket factory:

```text
DiscoveryPlatform
  start_advertisement(record) -> owned advertisement
  start_scan() -> owned bounded stream of opaque observations

OwnedAdvertisement
  stop().await -> acknowledged unregister
  terminated() -> unexpected-release notification

OwnedScan
  stop().await -> acknowledged discovery stop
  terminated() -> unexpected-stop notification

RosteredSocketFactory
  bind_dynamic_listener(controller) -> (owned listener, allocated_psm)
  connect(candidate_address, advertised_psm) -> opened stream
```

Production implementations wrap BlueZ. Deterministic tests inject fakes. The
interfaces expose opaque candidate locators only within `aster-ble-linux` and
must not be moved into `aster-node` or a generic transport trait.

Pinned `bluer` 0.17.4 cannot meet this ownership contract because advertisement
drop starts detached unregister work, discovery stop is not awaitable, and its
first D-Bus session subscriber uses an unbounded channel. The implementation
therefore uses a minimal workspace-pinned patch of that exact release which:

- adds owned, awaited unregister/stop and termination notification APIs; and
- replaces the first D-Bus ingress/subscriber queue with a fixed 256-event
  channel whose overflow emits `IngressOverflow`, terminates the session, and
  forces supervisor teardown rather than dropping an event and continuing.

No unbounded queue may precede the adapter's 64-item observation queue. The
patch is source-reviewed, license/SBOM recorded, and tested independently with
signal floods; no silent dependency upgrade or drop-only emulation is accepted.
If released upstream, it may be replaced only by an exact-pinned version with
the same tests and semantics.

Within the Linux implementation, a locator has one canonical form: the exact
six `bluer::Address` bytes plus `AddressType::LePublic` or
`AddressType::LeRandom`. No string comparison, alias, Device1 path, bond,
`IdentityAddress`, or address-type coercion participates. A live scan
observation and an accepted socket must expose the same canonical tuple. If
BlueZ/controller privacy resolution exposes different tuples, the inbound
candidate is rejected before mission work and that platform cannot qualify
until its support row demonstrates consistent normalization. The adapter does
not guess that two address forms identify one peer.

Owned listener, advertisement, scan session, nonce refresh, credential lease,
candidate cache, and connection tasks are siblings under one rostered
supervisor cancellation tree. A PSM may be advertised only while the exact
owned listener is live. Unexpected termination of the listener accept loop,
advertisement, scan, nonce-refresh task, credential lease, D-Bus ingress, or
BlueZ session cancels every sibling and enters drain state. Drain cancels
opens/contact, disables mission admission, and stops scan with its own five-
second acknowledged deadline. It keeps the backlog-one listener bound but
stops polling `accept`, so drain cannot become an accept/close loop.
Advertisement cessation is proven by one of: acknowledged unregister, BlueZ
`Release`, BlueZ owner loss, or expiry of the original 30-second timeout
followed by a fresh-session object check that the advertisement is absent. Only
then does it close the listener and join all tasks. Unconfirmed scan stop
similarly requires BlueZ owner loss or fresh-session absence before
reconstruction. Backoff alone is never proof of stop; until both barriers pass
the adapter remains unavailable and registers no replacement. A controller
availability epoch change follows the same path and discards all candidate,
replay, and negative-cache state after drain.

Normal in-process reconstruction has no unsafe escape from those barriers.
The consuming process-shutdown path is separately bounded: it waits no longer
than the old advertisement's remaining 30-second timeout plus two five-second
verification/owner-loss intervals, closes the owned D-Bus connection to force
owner loss, closes the listener, and returns either confirmed cleanup or a
sanitized `platform_cleanup_unconfirmed` result. The consumed supervisor can
never reconstruct after this path; process/D-Bus connection exit owns final
cleanup. Deterministic tests advance paused time rather than sleeping for this
40-second maximum.

### Startup and steady state

For each available-controller epoch:

1. Bind a backlog-one LE CoC listener with PSM zero and read back the kernel-
   allocated dynamic PSM. Reject a missing or out-of-range allocation.
2. Build and register the current proof-bearing advertisement for that PSM.
   At 25 seconds, prepare a fresh-nonce record, await acknowledged removal of
   the old advertisement, then register the replacement. One-instance hardware
   never overlaps old and new records. Each stop and registration has a five-
   second deadline; failure cancels the whole epoch rather than leaving the
   listener and advertised PSM out of sync.
3. Start LE-only discovery with the exact Service UUID filter and duplicate
   data enabled so nonce rotation is observable. Ignore BlueZ's initial list of
   previously known devices; an observation is fresh only after a live
   Service Data property update during the current scan window. Platform
   callbacks enter a 64-item `try_send` queue; overflow terminates that scan
   window rather than allocating or blocking upstream.
4. Parse and authenticate observations before retaining a candidate. Replay
   identity is `(credential_generation, nonce)`. The first valid observation
   binds that token to its exact header and canonical locator. An identical
   observation from that locator is accounting-only: it does not extend
   freshness. The same token from another locator, or with any differing
   authenticated header, is rejected as replay/relay and cannot replace the
   original. The candidate cache is keyed only by canonical locator and stores
   one current authenticated record. A fresh accepted token from the same
   locator atomically supersedes its prior nonce and PSM; the old replay token
   remains retained. A fresh token from a new locator creates a separate
   candidate because discovery cannot infer that two addresses are one peer.
   Candidate expiry, capacity eviction, or invalidation after an open failure
   removes the candidate but retains its replay token, so the identical record
   cannot recreate it.
5. Maintain the bounded candidate/replay caches and the one-peer role loop.
   Selection uses newest authenticated observation first, then canonical
   address bytes/type as the deterministic tie break. A newer candidate wakes
   pre-open backoff but never preempts an in-flight open or handshake. On its
   completion the next selection re-evaluates the newest candidate. An open
   failure removes that candidate and inserts `(address, type, PSM)` into the
   bounded negative cache; a new PSM is a different key.

The existing full mission NodeIds still derive the preferred direction:
lower NodeId initiates and higher NodeId responds. Both sides advertise and
scan because the responder must have a recent proof-valid observation for the
incoming transient address before it spends a mission-handshake slot. The
initiator connects only to a recent proof-valid candidate and the advertised
PSM. Neither side infers identity from the observation; the exact configured
mission NodeId is checked by the existing mission handshake.

The listener rejects an inbound locator that has no recent proof-valid
candidate entry before it enters node contact admission. Address rotation
between observation and connection can cause a bounded retry; it never causes
address learning or a durable binding. After successful mission
authentication, the candidate locator is still not persisted.

This one-peer increment schedules only the preferred direction, so it does not
claim post-authentication duplicate resolution. A nonpreferred connected
candidate is closed before node admission. The later multi-peer/duplicate
increment must use the parent design's authenticated contact-key rule and
cannot infer a peer from discovery data.

### Bounds

The initial qualification profile uses these fixed implementation limits:

- advertisement replacement target: 25 seconds; hard BlueZ timeout: 30
  seconds;
- candidate freshness: 90 seconds;
- scan window: 10 seconds active followed by at least 20 seconds idle; entering
  an authenticated contact stops scan, and after contact closes the full
  20-second idle interval precedes another window;
- first patched-BlueZ D-Bus ingress queue: 256 events; overflow terminates the
  whole BlueZ session/epoch;
- scan callback queue: 64 items; overflow stops the current window;
- total observation callbacks/structural parses per window: 256;
- HMAC verifications per window: 128;
- newly accepted proof-valid replay tokens per window: 32;
- retained candidates: 32;
- replay entries: 256 for 10 minutes; when full, unexpired entries are never
  evicted and new tokens are rejected until expiry;
- negative-cache entries: 32 for 30 seconds, keyed by exact locator and PSM,
  evicted expired first then oldest;
- simultaneous outbound opens: 1;
- simultaneous inbound pre-authentication contacts: 1;
- total mission handshakes: 1, inherited from the node admission semaphore;
- separate outbound-open, inbound-accept, and mission-handshake token buckets:
  capacity 4 each, refill one token every 30 seconds, shared across candidates;
- candidate record bytes: exactly 40, copied once after structural validation;
- retry delay: existing capped 250 ms to 30 seconds, with candidate invalidation
  on locator/PSM/open failures and global backoff after repeated failures; and
- all platform open and contact operations: existing maximum 30-second
  deadlines.

Exhaustion of any callback, HMAC, token-admission, or queue budget stops the
scan window and enters its idle interval. Candidate eviction is deterministic:
expired first, then oldest observation; RSSI is diagnostic only and never
authority or an eviction priority. A proof-valid credential holder can still
evict or suppress a legitimate candidate, but cannot exceed these process
budgets. Duplicate observations consume the total-callback budget but do not
grow or refresh a collection.

Discovery timing, capacities, and cache sizes are not operator-tunable in this
increment. This avoids unsafe inversions where a smaller refresh interval or
idle interval increases work. Existing frame/exchange/deadline limits retain
their current validation. These discovery values are initial Linux
implementation policy, not semantic protocol or cross-platform constants. They
can change together in a reviewed qualification profile without changing
`AsterRosterBeaconV1`; the record layout, proof construction, UUID, and
rejection rules require a new carrier revision if changed.

## Failure behavior and status

Structural or proof-invalid advertisements are silently discarded after
bounded accounting. They never create peer-scoped durable state. Replays,
candidate expiry, address rotation, connection refusal, and stale PSMs are
transient candidate failures. Repeated failures enter the defined global
capped backoff, token buckets, and negative cache; they do not start another
carrier.

Credential configuration errors are startup configuration failures. Missing
BlueZ/controller, permission loss, unsupported complete advertising,
registration failure, unconfirmed unregister, scan failure, unexpected child
termination, controller loss, expired credential lease, or CSPRNG failure make
this adapter unavailable/degraded while the node and durable publication stay
ready. Mission authentication or authorization failure terminates that
candidate contact under existing security rules and is never hidden as a
transport fallback.

Coarse public availability remains `available` or a sanitized unavailable
reason. Linux-private diagnostics may add `binding`, `advertising`,
`discovering`, `connecting`, `authenticating`, and `active`, plus bounded
counters. Logs must not print addresses, PSMs, nonce/tag values, credentials,
mission identities, or raw BlueZ errors.

Qualification details such as the allocated PSM and address-normalization
tuple go only to an owner-protected receipt sink, never routine logs or public
status. Process-local limits do not bound `bluetoothd` Device objects, D-Bus
queues, controller energy, or discovery broadened by another local client.
Support rows therefore record Aster and `bluetoothd` RSS/CPU/object/FD/signal
measurements under hostile RF and a competing scanner. Because Device1 objects
can outlive a scan and another client can broaden discovery, this increment
sets pass thresholds only for Aster-owned work. Hostile-RF host-level production
readiness remains explicitly excluded until a later design either selects a
bounded BlueZ ingestion primitive or freezes and passes host-level BlueZ
thresholds.

## Implementation structure

Refactor before adding behavior so production modules retain one responsibility:

- `config.rs`: common limits plus fixed and rostered validated configuration;
- `discovery_record.rs`: pure record codec, HMAC proof, credential types, and
  vectors;
- `discovery.rs`: candidate/replay caches, scan-window policy, and observation
  admission;
- `platform/discovery.rs` or an equivalently narrow module: BlueZ
  advertise/scan translation only;
- `platform/socket.rs`: existing fixed open plus dynamic bind/connect;
- `rostered_lifecycle.rs`: owned epoch state machine and one-peer role loop;
- `aster-host::discovery_credentials`: authenticated artifact transition,
  fixed-size checkpoint, trusted-clock lease, and production secret custody;
- the pinned `bluer` patch: awaited handle stop plus bounded first D-Bus ingress
  only, with no Aster policy;
- the pinned `hmac` patch: zeroizing its private derived-key construction
  temporary only, with no carrier policy;
- existing `lifecycle.rs`: Ring 1 fixed-locator supervisor until compatibility
  removal is separately approved; and
- `aster-node`: no discovery or BlueZ logic; only the existing exact-peer
  ordered Event admission is used.

Shared cancellation/backoff helpers may remain in `policy.rs`. Fixed and
rostered paths share pure limit validation and stream adaptation, not a false
common transport lifecycle. The refactor must precede each push review and may
not introduce pass-through abstractions used by only one behavior.

## Minimal Android-to-Linux Event example

The existing Android Ring 1 app already runs the Rust semantic-v9 Event node
and complete mission-authenticated contact, but it is receipt-oriented: it
cannot publish operator content and the Linux example does not expose an
application delivery. Extend that same example instead of adding a Kotlin-only
test message or another Bluetooth protocol.

This validator remains a manual-locator foreground app. The operator still
selects the mission bundle and enters the Linux Bluetooth address, PSM, and
mission NodeId. Android rostered discovery is not implied by the Linux Ring 2
work and enters only a later platform qualification increment.

### Android UX

Retain `Connect & Validate` as the exact Ring 1 conformance action. Add one
`Event message` text field and a separate `Send Event` action. This prevents a
correct retry of an already-reconciled user Event from being judged by the
conformance mode's deliberately strict requirement to insert exactly one fresh
inbound Linux Event.

`Send Event` is enabled only when the existing configuration is complete, no
run is active, and the UTF-8 payload is 1 through 256 bytes. Whitespace is data;
an all-whitespace value is allowed, while an empty value is not. The field uses
ordinary multiline text with no rich content or attachment handling.

When a new message is accepted, Android `SecureRandom` creates 16 nonzero
random bytes, with at most three redraws of the all-zero value, and encodes them
as exactly 32 lowercase hexadecimal characters without UUID punctuation. The
app passes that identifier and the exact UTF-8 payload to the native send run
before it opens Bluetooth. Rust, not Kotlin, is the sole durable pending-intent
authority: it recovers or creates the numbered publication journal, persists
the exact intent, and publishes it into the local Aster store while no
transport exists. Only after native code reports the durable Event ID may
Kotlin open the CoC and attach it to that run.

The Event uses the existing validator topic `mesh.messages` and scope
`demo/playground`, logical key `android/manual/<32 lowercase hex>`, routine
priority, no predecessor, no tombstone, and durable lifetime. A retry recovers
the identifier, payload, publication session, sequence, and Event ID from the
native journal across Activity or process restart. Kotlin keeps no second
pending file and cannot disagree with journal state. A different payload is
not accepted while the journal has a pending operation.

The UI renders only these operator states:

```text
ready -> publishing -> waiting_for_transport -> connecting -> authenticating
      -> reconciling -> sent
```

Cancellation and closed sanitized failure categories remain available. Loss or
absence of Bluetooth leaves the Event durable and the run in
`waiting_for_transport`; process death leaves the journal recoverable. `sent`
means local durable publication plus successful contact reconciliation; it is
not a new remote-delivery receipt. The Linux terminal line is the validation
that the remote application observed the Event. A failed send locks the field
to the journaled intent and offers `Retry Send` or `Stop Retrying` while no
contact is active. The latter appears only after recovery proves the Event is
already durable and requires confirmation stating: the Event is not deleted
and may reconcile on a later Aster contact. It compare-and-clears only the
expected native operation; it never publishes an incomplete intent under a
discard label. Only after the native completion is presented and confirmed may
Kotlin accept another payload. The conformance action retains its existing
detailed receipt. Only one native run exists process-wide across both modes.

The copied mission bundle, journal, and node state remain in app-private
storage. Payload and operation identifiers are not written to Android logs,
error strings, or receipts. App uninstall remains the cleanup mechanism used
by the validator runbook.

### Rust publication boundary

Add explicit modes. `conformance` preserves the current descriptor-backed API
and strict receipt. `send_event` uses a private two-phase Android API:

```text
start_send(config_without_descriptor, expected_prior_completion?)
  -> run_id, durable_event_id
attach_contact(run_id, owned_descriptor) -> contact result
recover_send_status()
  -> ready | pending | completed_unconfirmed | completed_confirmed
confirm_completion(expected_operation_id, expected_event_id, outcome, token)
stop_retrying(expected_operation_id, expected_event_id)
```

`send_event` requires a 1-through-256-byte UTF-8 payload and exactly 32
lowercase hexadecimal identifier characters representing 16 nonzero bytes.
Mode-inapplicable fields, unknown fields, and invalid values are rejected
without echoing input. `start_send` starts the transport-neutral Rust node,
owns `state_path/android-event-publication.redb` with client identifier
`aster.android-btle-ring1.publish.v1`, recovers it against
`RunningNode::selected_events()`, and persists/publishes the exact journal
intent before returning the Event ID. The existing subscription client remains
separate. No contact descriptor is required to start, publish, cancel, stop,
or recover the node.

Journal first creation uses a same-directory temporary file, bounded initial
state, file sync, atomic no-replace rename, and parent-directory sync; a race
opens the winner. Exactly one fixed temporary name is allowed; startup removes
it only after descriptor-based owner/type/size checks and only when the final
database is valid or absent, so repeated initialization deaths cannot
accumulate files. An existing partial, corrupt, wrong-client, or inconsistent
final journal is a closed storage-integrity error and is never treated as
absence. All subsequent transitions retain redb's transaction and exact
numbered recovery semantics. There is no paginated "Event absent" fallback and
no cross-store Kotlin recovery branch.

The same redb database retains one bounded native UI outcome alongside the
numbered journal. Completion contains operation ID, Event ID, outcome, and a
native CSPRNG 128-bit nonzero completion token. Successful contact first
atomically stores `completed_unconfirmed` and marks the numbered journal
operation `ack_pending` while retaining client/session/sequence, receipt, and
intent. Native code then calls the existing idempotent numbered-backend
acknowledgement; `AlreadyAcknowledged` is success for that exact tuple. A final
local transaction clears the journal operation while retaining completion.
Recovery from `ack_pending` repeats the exact backend acknowledgement before
returning status. It never loses the sequence needed to close the backend.

`Stop Retrying` is permitted only for an already-applied Event and uses the
same three-step sequence with outcome `stopped_retrying`; it cannot act on an
assigned-but-unapplied intent. `recover_send_status` reconciles journal and
outcome state and returns the exact IDs, payload where pending, outcome, and
token without creating a new publication. Any mismatch is a closed integrity
failure.

`confirm_completion` compares operation ID, Event ID, outcome, and token, then
changes `completed_unconfirmed` to `completed_confirmed` without deleting it.
Both completion states remain recoverable with the exact tuple. The next
`start_send` requires `expected_prior_completion` containing that confirmed
tuple/token and atomically replaces it with the new pending operation; when
state is `ready`, the argument must be absent. A delayed confirmation or stale
start therefore cannot clear or replace a newer send. A crash before or after
the UI callback or confirmation still recovers the stable Event ID, outcome,
and confirmation state. Native state stays fixed-size; Kotlin stores no second
authority.

`attach_contact` is optional and repeatable only after a failed/closed contact
while the same run remains pending. JNI converts the supplied integer into
`OwnedFd` immediately so every validation/error path closes it, but performs no
bridge or contact work until the run ID and state validate. A successful
contact runs the three-step completion sequence above for only the recovered
journal operation, then returns its stable Event ID. Kotlin
must transfer ownership with the existing `ParcelFileDescriptor.detachFd()`
contract and must not close the detached integer. Invalid run/state paths are
tested for exactly-once native close. A crash before the completion transaction
recovers the same numbered operation and Event; a retry may reconcile it again
but cannot create a second semantic Event. A crash after it recovers
`completed_unconfirmed`.

Send mode validates the authenticated mission peer, semantic v9, exact profile
offer/digest, and absence of Blob attempts, but it does not require one new
inbound Event or the larger-than-MTU condition. Conformance mode continues to
require exactly the current one fresh inbound Event larger than Android's
reported receive packet size. The modes have separate terminal receipt types
so retry semantics cannot silently weaken conformance evidence.

No JNI method exposes transport frames or sends application bytes directly to
Bluetooth. The bounded payload enters only the validated `start_send`
configuration and remains inside the application -> durable store -> v9
reconciliation -> authenticated contact onion.

### Linux terminal receiver

Add an explicit `--print-android-events yes|no` option to the
`aster-btle-event` example, defaulting to `no`. When enabled, the example owns
a selected Event application client beside the BTLE supervisor. It subscribes
to the exact validator topic/scope before the supervisor starts, polls with a
16-item delivery and scan limits at a 250 ms application cadence, and prints
only deliveries whose authenticated publisher equals the configured Android
mission NodeId, whose logical key is exactly `android/manual/` followed by 32
lowercase hexadecimal characters, and whose payload is at most 256 bytes of
valid UTF-8.

The application client uses stable constants
`aster.btle-event.android-terminal.v1`,
`aster.btle-event.android-terminal.claim.v1`, and
`aster.btle-event.android-terminal.subscription.v1` for its client ID, recovery
claim nonce, and subscription operation key. It follows the existing exact
publication-session recovery sequence, so its cursor and acknowledgements live
in the node store and survive process restart.

Each accepted delivery is one ASCII-only terminal line containing the immutable
Event ID, publisher sequence, payload byte length, and JSON string. Every
non-ASCII scalar, bidi/format/zero-width character, C0/C1 control, ESC, CR/LF,
NUL, and JSON metacharacter is escaped; scalars above U+FFFF use surrogate-pair
escapes. The complete encoded line is bounded to 2,048 bytes. It is
acknowledged only after the complete line and newline are written and flushed
successfully. A repeated line after process failure is allowed by the
application's at-least-once delivery contract and is recognizable by the same
Event ID. Wrong-publisher, malformed-key, oversized, or non-UTF-8 deliveries
are not printed as operator text; they receive a bounded sanitized diagnostic
and are acknowledged for this example client so they cannot create a retry
loop. A stdout write or flush failure is terminal and leaves the delivery
unacknowledged.

The receiver is application-example code, not transport code. It does not add
payload callbacks to `LinuxBtleEventSupervisor`, log from the BlueZ adapter, or
change customer-safe default output. Its poll cadence and shutdown are driven
by the example's existing cancellation tree and deterministic tests use paused
time rather than real sleeps.

### Android/Linux validation topology

This example validation intentionally uses the retained fixed-locator Linux
supervisor with its operator-provisioned PSM; it does not pretend that the
Android app implements the new rostered-discovery record. The Android example
remains the contact initiator. Its mission NodeId must sort below the Linux
mission NodeId so the Linux supervisor derives the listener role; the runbook
validates this before either process starts.

Companion-lane physical evidence uses two distinct runs. The unchanged
conformance run seeds
Linux with one Event larger than Android's reported receive packet size and
retains the exact existing receipt. The send run starts from the retained
Android publication journal, requires the Linux terminal to display the short
Event ID and payload, and permits a zero-new-inbound Android receipt. Retrying
that same pending send after cancellation or app restart must recover the same
publication and must not create a second Linux Event. Linux/Linux rostered-
discovery evidence is a third, separate run using the dynamic PSM and proof-
bearing advertisement and is the only Ring 2 discovery gate. Pixel, Android
toolchain, or terminal-example availability cannot block or strengthen that
Linux result; it gates only the companion receipt.

## Verification

### Deterministic tests

- canonical record encode/decode/proof fixtures, independent RFC HMAC sanity
  vectors, known-answer vectors produced outside the implementation, and every
  mutation rejection;
- discovery-record and credential-artifact fuzz targets plus the repository
  `mise run fuzz-smoke` lane;
- secret and proof material are redacted; credential and dependency working
  state satisfy the source-reviewed zeroize-on-last-drop contract;
- authenticated artifact bytes/scope, sequence high-water, same-sequence
  digest, trusted-clock lease conversion, discontinuity handling, seven-day
  overlap/lease expiry, exact transition machine, bounded retirement floor,
  and all other generation rejection; crash injection before/after every
  checkpoint sync/rename/exposure boundary proves rollback cannot reappear;
- stage `(g, g+1)`, activation `(g+1, g)`, renewal, and retirement fixtures
  preserve each generation-to-secret fingerprint across restart and reject
  same-generation secret substitution in either ordering;
- the patched first D-Bus ingress queue and adapter observation queue both hit
  exact capacities, terminate on overflow, and leave no unbounded predecessor;
- total callback, queue, HMAC, accepted-token, replay-full, negative-cache,
  open/accept/handshake token-bucket, candidate TTL/capacity/eviction, and scan
  duty-cycle bounds with paused time;
- several nonce rotations on one locator supersede one candidate; a new PSM
  supersedes the old record; newest-first selection and backoff wake-up are
  deterministic;
- proof-valid floods, malformed floods, duplicate floods, first-seen relay
  poisoning for successive nonces, and a replay stockpile after epoch restart
  remain within the exact budgets;
- no candidate/contact allocation before structural and proof validation;
- dynamic PSM is published exactly and a stale PSM invalidates only that
  candidate;
- public/random address rotation replaces transient candidates without durable
  binding;
- inbound address requires a recent proof-valid observation;
- exact configured mission NodeId is still required after proof validation;
- advertisement registration and acknowledged stop, one-instance rotation,
  timeout, scan stop, and termination notifications are fault-injected at every
  await; old and new records never overlap;
- unregister timeout leaves the backlog-one listener bound, accept polling and
  mission admission disabled, and replacement-registration count at zero until
  `Release`, owner loss, or fresh-session absence; listener close occurs once;
- consuming shutdown completes within the paused 40-second bound, never
  reconstructs, and distinguishes confirmed from unconfirmed platform cleanup;
- controller loss or unexpected listener, advertisement, scan, nonce-refresh,
  credential-lease, or D-Bus termination cancels listener, advertisement,
  scan, opens, and active contact, then recreates a fresh epoch only after both
  cessation barriers pass;
- cancellation during every await explicitly stops and joins owned BlueZ
  handles; detached cleanup is a test failure;
- no transport leaves the node application-ready and durable Event pending;
- rostered failure never invokes the fixed-locator or Iroh adapter; and
- Android configuration rejects empty/over-256-byte payloads, malformed
  operation identifiers, unknown fields, and invalid UTF-8 without echoing
  input;
- Android starts and publishes exactly one idempotent durable Event with no
  descriptor, attaches contact only afterward, and recovers the same Event ID
  after cancellation/process death without a second logical operation;
- Android journal initialization survives each temporary-file/sync/rename
  cut; its one temporary file remains bounded and partial or corrupt final
  journals fail closed; `Stop Retrying` is unavailable before the Event is
  durable and compare-and-sets the exact operation/Event IDs;
- injected death after journal initialization, intent persistence, Event
  commit, receipt persistence, before attach, during contact, after contact but
  before completion/`ack_pending`, before/after idempotent backend
  acknowledgement, before local journal clear, before the UI callback, and
  before/after completion confirmation or `Stop Retrying` always recovers the
  same pending, `completed_unconfirmed`, or `completed_confirmed` Event
  ID/outcome/token, never a duplicate publication;
- stale confirmation tokens and stale `expected_prior_completion` values
  cannot replace a newer completion or publication;
- conformance and send modes retain separate receipt validation, so send retry
  does not weaken the exact one-new-inbound conformance gate;
- Linux terminal rendering requires exact publisher and operation-key shape,
  bounds UTF-8 and the 2,048-byte ASCII line, and escapes CR/LF, NUL, ESC/OSC,
  C0/C1, bidi, format, zero-width, non-ASCII, and maximum-expansion inputs;
  acknowledgement occurs only after successful write and flush;
- terminal display stays disabled by default and adds no adapter callback; and
- Ring 1 fixed-locator, clean-restart, Event, and existing Android conformance
  tests remain unchanged apart from the intentional new publication phase.

Tests use injected clocks, entropy, observations, and platform handles. They do
not sleep for real scan windows, contact cadence, or 60-second timeouts.

### Physical Linux rostered-discovery evidence

Every proposed CM4 or PC support row names its exact host, controller, firmware,
kernel, BlueZ, and patched `bluer` source. Each controller runs both
advertiser/listener and scanner/initiator roles, with extended advertising,
active scanning, LE CoC listening, connection, Event exchange, and reconnect
concurrent. A row is unsupported rather than generalized when any role or
79-byte requirement fails.

For each candidate row:

1. Start both nodes with no remote Bluetooth address or remote PSM configured.
2. Prove the exact UUID filter returns the complete-UUID-plus-ServiceData
   record, and independently capture all 79 bytes, PHY, interval, absence of
   managed fields, and cessation of each old record within 30 seconds without
   old/new overlap or secret exposure. D-Bus properties must request exactly
   250 ms; over 60 captured intervals the accepted on-air median is 200 through
   300 ms with no non-rotation gap above one second.
3. Complete protected semantic-v9 Event delivery over the discovered dynamic
   PSM.
4. Rotate one side's private/random address and prove rediscovery/reconnect
   without changing mission configuration.
5. Restart the listener and prove a fresh dynamic allocation operation. Numeric
   PSM reuse is permitted. The stale-PSM negative case either holds the old PSM
   occupied so the kernel must choose another value or uses the injected socket
   boundary; hardware qualification never fails merely because Linux reused a
   released value.
6. Inject unmatched, malformed, bad-proof, duplicate, replay-stockpile,
   stale-generation, proof-valid credential-holder flood, and competing-local-
   scanner traffic. Pass thresholds are: Aster RSS no more than 16 MiB above
   steady state with no monotonic growth across ten windows; Aster FDs/tasks no
   more than 8 above baseline; Aster no more than 50% of one core averaged per
   active window; and exact callback/HMAC/attempt budgets. `bluetoothd` RSS,
   CPU, FDs, Device objects, signal volume, post-scan retention, and controller
   energy are recorded without converting them into a hostile-RF production
   authorization in this increment.
7. Present a proof-valid beacon using the group credential from a node with the
   wrong mission identity; prove it consumes only the fixed pre-authentication
   budgets and releases no inventory or Event data.
8. Remove/power-cycle the controller and prove fresh epoch recovery without
   node restart, then repeat clean process restart on the fixed kernel. Inject
   `SIGKILL` after listener bind, advertisement registration, scan start,
   contact admission, Event publication before contact, and contact before
   application acknowledgement; prove D-Bus ownership removes stale objects,
   the next run performs a fresh PSM allocation and emits a new nonce, and one
   durable semantic Event is recovered. Whole-host power-loss authorization
   remains a later packaging
   gate.
9. Confirm durable publication while discovery is unavailable and later exact
   one semantic Event ID/publication. Application delivery and terminal output
   remain at-least-once and repeated observations must carry that same ID.

The hostile-workload manifest is fixed for reproducibility: two minutes of
idle baseline sampled once per second, then ten 10-second scan windows separated
by the required 20-second idle interval. A qualified RF replay rig delivers 64
matching-UUID observations per second during each active window using 64
rotating addresses and an equal four-way mix of malformed records, bad proofs,
duplicates of four valid tokens, and fresh proof-valid tokens; surplus input
continues after Aster closes its window. A concurrent local scanner requests an
unfiltered duplicate-data scan. `/proc`, cgroup-v2 CPU time, BlueZ ObjectManager,
and D-Bus signal counters are sampled once per second; CPU is normalized to one
logical core. Exact BlueZ configuration, including `TemporaryTimeout`, is part
of the receipt.

### Physical Android companion evidence

On the Pixel 9 Pro XL, first rerun the unchanged strict conformance mode. Then
publish a short Event while Bluetooth is unavailable and prove the durable
Event ID precedes the CoC. Attach the fixed-locator contact, retain the matching
ASCII-escaped Linux line, and inject process death at every native journal and
contact boundary listed above, including `Stop Retrying` and completion
confirmation. Every recoverable retry uses the same Event ID and outcome;
repeated terminal lines are allowed but no second semantic Event exists.
Corrupt-journal injection fails closed. Finally remove the app and private
data. This receipt is non-gating for the Linux Ring 2 lane.

Each owner-protected receipt records exact source/build, kernel, BlueZ,
controller/firmware, supported roles and advertising instances, advertisement
tuple/captures, negotiated MTU, bounds, resource time series, PSM/address
normalization evidence, and fault artifacts. Public logs remain sanitized. The
Linux receipt labels the result only as the Ring 2 rostered-discovery increment,
not full production BTLE qualification; the Android receipt labels only the
companion fixed-locator interoperability example.

### CI discipline

Run focused codec/cache/config/lifecycle tests first, then the affected crate
tests, formatting, lint, and only the repository's established bounded check
lanes. Do not add real-time 60-second tests or run multiple full checks in
parallel. Before every push, review the production diff for ownership,
duplication, naming, bounds, error sanitization, and unnecessary generated or
AI-verbose text.

## Review and rollout

Implementation stays local until the design is approved, the focused and
affected checks pass, production code has received a refactor/readability
review, and physical evidence is either complete or its exact external blocker
is documented. Only then is PR #146 updated with signed commits.

The PR description must distinguish:

- Ring 1 evidence already complete;
- this discovery-first Ring 2 increment and its exact supported topology;
- physical results actually obtained;
- complete Ring 2 exits still open; and
- CI infrastructure failures unrelated to the code.

No commit or PR wording may call BTLE production-ready until every parent Ring
2 exit and governance record is satisfied.

## Planning gates

Before implementation planning begins, owner approval is required for this
carrier record, credential model, one-peer scope, bounds, and extended/complete
advertising requirement. The plan must not invent a different proof primitive,
record layout, service UUID, secret source, peer-admission rule, fallback, or
public lifecycle abstraction.

Before the eventual full Ring 2 production claim, a separate approved design
must close multiple-peer roster admission and authenticated duplicate-contact
arbitration, because the current exact-peer node admission API cannot safely
identify an unknown peer from an unauthenticated advertisement.
