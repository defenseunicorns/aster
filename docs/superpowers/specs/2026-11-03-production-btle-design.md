# Production BTLE carrier design after semantic v9

**Status:** maintained architecture authority; no production authorization

**Capability track:** P1-4 reachability and carrier portability, followed by
all-class and cross-platform qualification.

This document defines future BTLE architecture and release gates. Current
evaluation claims are owned by
[`btle-ring1-evaluation-profile.md`](../../validation/btle-ring1-evaluation-profile.md);
operator procedures and dated physical observations do not broaden this design.
Approval of this maintained design is the reviewed decision that extends the
narrow selected-node amendment in
[`Decision 0007`](../../decisions/0007-ip-and-btle-links.md); it does not create
a second BTLE design or amend semantic-v9 wire behavior. Implementation must reconcile
the older single-production-adapter wording in the carrier guide, roadmap, and
conformance documents in the same change that enables a second adapter.

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

Transport neutrality means that no transport is required for application
readiness. The deployed node discovers the adapters its host can actually use,
keeps publication durable when none are available, and automatically chooses an
eligible adapter for each new contact attempt. Selection is local runtime policy,
not semantic-v9 protocol state and not an application choice.

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
operating-system-wide support claim. Local selection before a fresh contact is
compatible with v9. Live-contact migration, transfer of attempt/session state,
cross-carrier continuation not already owned by a durable class authority, and
intra-record resume require a later semantic design; v9 does not infer them.

## Architecture

```text
application Event / State / Record / Blob API
                    |
mission policy, reconciliation, durable store and Blob depot
                    |
adapter registry, attempt admission, and automatic selector
                    |
adapter-neutral contact port and mission authentication
              /                         \
       Iroh/IP adapter          BleL2capV1 adapter
                                      |
                    platform driver (BlueZ, CoreBluetooth,
                         or Android public APIs)
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
new epoch. Controller discovery and selection stay inside the BTLE adapter; the
host selector chooses a transport adapter, not a Bluetooth controller.

## Deployment, availability, and selection

The composition root includes every admitted in-process adapter supported by
that build's operating system and architecture. Initially the qualified Linux
agent build includes Iroh/IP plus BTLE. Embedded and mobile builds may compile a
smaller platform-appropriate set, but application code and durable semantics do
not vary with detected hardware. It is the same node process whether the host
has an IP interface, a Bluetooth controller, both, or neither; there is no
companion BTLE daemon.

Each adapter owns its platform lifecycle and independently reports a bounded,
sanitized availability snapshot to the host registry. A snapshot includes the
adapter kind, availability/health, qualified capabilities, and policy inputs
such as bandwidth, cost, and emission class. It contains no mission authority,
raw transient locator, secret, or durable protocol progress. The core does not
abstract controller reset, scanning, advertising, interface management, or
other transport-specific lifecycle operations.

The host, not an adapter, owns peer-indexed eligibility. Each entry binds the
mission, expected peer, adapter kind, capabilities, evidence source, authority
generation, expiry, and revocation generation. Allowed sources are provisioned
exact-peer authority or a prior mission-authenticated binding. Discovery may
supply peer eligibility only when its proof is cryptographically bound to that
exact mission peer. `AsterRosterBeaconV1` is deployment-group proof and therefore
locator-only: it can never create or update peer-indexed eligibility. Adapter
health and untrusted beacons likewise grant no peer support. Mission
authentication on the selected contact remains mandatory and supersedes no
authority.

For every fresh outbound pending-work cohort, the selector:

1. hard-gates adapters by build admission, local enablement, mission policy,
   current peer-indexed eligibility, required class/lane capability, and current
   availability;
2. ranks the remaining adapters by local configured policy and sanitized health
   and cost signals; and
3. admits one bounded attempt through the adapter-neutral contact port.

The initial automatic composition admits one establishing or active outbound
contact per node; already durable local application work is unaffected. The
coordinator schedules peer/class cohorts with bounded fair rotation so an
Event-only adapter cannot indefinitely strand State, Record, or Blob work. The
exact ranking, fairness weights, and admission bound are replaceable local
implementation details, not wire behavior. Normal configuration expresses
policy—allow/deny, emission constraints, and optional priority/cost
preferences—not controller addresses, interface names, or detected hardware.
Applications publish and observe durable results; they cannot select a
transport.

All eligible adapters may listen concurrently. Each adapter first enforces its
own pre-contact connection, carrier-cryptography, socket, byte, task, and rate
budgets. Every resulting contact then enters node-global admission before the
Aster mission handshake. The initial composition admits one mission
handshake/contact across inbound and outbound automatic paths; excess candidates
are closed without unbounded queues. `ReceiveOnly` admits bounded inbound work
but originates none; `PassiveOnly` admits no session contact. Later concurrency
requires measured global/per-adapter bounds and authenticated duplicate
arbitration first.

When no adapter is eligible or available, the node remains application-ready,
accepts durable publication, reports sanitized unavailability, and waits for an
adapter state change or retry deadline without polling or failing publication.
Hotplug, permission, driver, and link changes wake selection through adapter
events. A new adapter or controller epoch never inherits a prior contact's
mission keys, replay state, or provisional authorization.

The composition root owns order: open the durable node, start adapters, then
open contact admission; on shutdown, close admission, cancel and join adapters,
then close the node. An embedded host supplies equivalent adapter and credential
providers. The Linux service and later mobile applications are composition
profiles of this contract, not separate transport authorities. The first
BTLE-qualified production profile is the systemd-managed Linux agent. Container
builds exclude BTLE until an equally protected credential provider, BlueZ/device
access model, reload/rollback authority, and confinement profile are separately
qualified.

## Platform boundary

The connection-oriented platform boundary must support bounded scan and
advertisement windows, listener/open operations, ordered read/write,
cancellation, close, controller/permission lifecycle observation, current
packet/MTU bounds, and sanitized health/role reporting. Cancellation must
release owned platform work within a declared bound.

Startup must tolerate missing hardware, a stopped BlueZ service, denied optional
permissions, and later hotplug. Those conditions make BTLE unavailable; they do
not make the node or durable publication unavailable. Platform drivers probe
hardware automatically and select only controllers admitted by the qualified
support matrix. An explicit controller override may exist as a diagnostic or
deployment policy control, but is not required for normal operation and cannot
turn unqualified hardware into supported hardware.

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

Production uses the logical credential name `aster-btle-roster`. The credential
provider validates a replacement and durably commits its manifest/generation
checkpoint before atomically publishing a new non-cloneable lease. Reload starts
a new adapter epoch; the old epoch drains before its lease and working secrets
are erased. A rejected replacement leaves a still-current lease unchanged. At
expiry BTLE becomes unavailable while the node stays ready. Linux may implement
renewal through an authenticated service reload or a controlled service restart;
it must never park permanently merely because the startup lease expired.

The implemented rostered slice remains one Linux controller, one exact mission
peer, one dynamic PSM, and one active Event contact. Lower complete mission
`NodeId` initiates; higher listens. The BTLE adapter never substitutes GATT or a
fixed locator when rostered discovery fails. The future host composition defined
here may schedule a fresh attempt on another independently eligible transport
after a safely scoped transport failure; the current evaluation binary cannot.
Multiple peers, duplicate arbitration, automatic BTLE controller selection,
other classes, packaging, and production approval remain open.

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

Existing Profile-5 authority already permits a fresh attempt, with a fresh
nonce, to resume only from the receiver's durable checkpoint through another
eligible ordered adapter. This design transfers no attempt/session state and
does not claim that BTLE Blob or physical cross-transport failover is
implemented or qualified.

Control, authentication, revocation, cancellation, acknowledgements, and
liveness receive reserved scheduling capacity. Interactive classes are
priority-aware; Blob uses remaining capacity with a bounded minimum share.
Queues, outstanding bytes, attempts, channels, retries, and time without durable
progress are bounded by the active qualification profile.

## Roles, admission, selection, and failures

Ring 1 fixes roles and one eligible adapter. Preferred direction is lower
`NodeId` outbound and higher inbound. Before authentication, candidates have no
peer identity and are limited only by global/per-adapter queue, byte, CPU,
handshake, deadline, and rate budgets. Replay/rate state survives controller
epochs and process restart through bounded durable restoration. If restoration
cannot be authenticated, rostered discovery remains unavailable until the host
authority installs an already-authorized credential generation; a node never
rotates the shared discovery generation unilaterally.

After authentication, duplicate contacts are keyed by mission, both `NodeId`s,
semantic/profile, adapter kind, and transcript. The initial automatic
composition keeps one contact; later concurrency must use a symmetric frozen
contact-key election that both peers compute identically, never an address,
controller index, local rank, arrival order, or wall clock. Global scheduling
rotates boundedly among peers, class cohorts, and eligible adapters. Retry and
cryptographic-work budgets are node-global with stricter per-adapter caps and
survive an adapter epoch; restart behavior is explicit in the active profile.

Semantic v9 requires one profile-permitted adapter for each contact, but does
not require that adapter to be configured by the application or negotiated on
the wire. The local selector may choose among simultaneously eligible BTLE and
IP adapters before a fresh attempt. Each selected contact runs a complete
mission handshake and remains bound to that adapter for its lifetime. There is
no live migration, contact continuation, or transfer of keys, replay state,
provisional authorization, or in-flight frame state between adapters.

No peer-side selection protocol is required: every eligible adapter listens
independently, and the outbound choice is embodied by the fresh contact that
actually reaches it. The peer agrees only to that contact's existing mission,
semantic, and profile negotiation. Competing authenticated contacts are reduced
by the rule above; local ranking is never sent to or accepted from a peer.

Zero credit is backpressure. Deferred capacity waits for its named event.
Positive-credit no-progress, control-liveness loss, link loss, adapter loss, or
a transport deadline may make that contact fail and permit a new attempt only
within the node-global retry budget. Adapter-local lifecycle failure updates
adapter availability; it is not itself protocol fallback.

The coordinator accepts only a closed `ContactOutcome` carrying stage
(`candidate`, `carrier-open`, `mission-handshake`, or `authenticated-session`),
scope (`locator`, `adapter-epoch`, `expected-peer`, `mission`, `policy`, or
`attempt`), trusted scope provenance, disposition, expiry/authority generation,
and a sanitized reason. Mappings are owned as follows:

- a driver can report only locator, adapter-epoch, interruption, timeout, or
  cancellation outcomes; it cannot report mission or peer authority;
- malformed unauthenticated inbound work affects only its locator and expiring
  rate state, never a claimed peer;
- every failure before the transcript authenticates the exact expected `NodeId`
  remains locator/adapter-epoch/attempt scoped, including outbound
  authentication or identity mismatch; it neither suppresses that peer nor
  triggers reselection on another carrier;
- only a transcript authenticating the exact expected `NodeId` may establish
  expected-peer or mission scope;
- authorization, integrity, replay, protocol, invariant, and policy failures
  are never reclassified as transport interruption; and
- only locally proven adapter unavailability, link loss, or transport deadline
  permits reselection. Cancellation remains cancellation.

Locally proven adapter unavailability before a mission handshake may still wake
ordinary selection because it identifies no remote peer. A remote or ambiguous
pre-authentication failure ends that scheduled operation and enters bounded
locator backoff; a later operation is independently selected rather than being
failure-driven fallback. Expected-peer, mission, and policy suppressions last
until their authenticated authority generation changes or an explicit
administrative retry; transient transport state uses bounded backoff. The
selector never parses error text.
This outcome contract must replace the current coarse error collapse before a
second production adapter is enabled, preventing both cross-carrier probing and
attacker-selected peer suppression.

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

Runtime discovery is broader than the support claim: an unknown controller may
be observed, but it remains unavailable unless its OS/driver/controller row is
admitted. The package must not silently treat successful probing as production
qualification. Operator status reports adapter type and sanitized reason codes,
never raw transient Bluetooth addresses, PSMs, discovery proofs, or credentials.

The release carries a signed, package-bound support matrix. A driver probes the
OS, architecture, kernel/framework, controller vendor/product and revision,
firmware, and driver identity and requires one exact non-revoked row. Missing,
ambiguous, or conflicting fields yield `unqualified`. Among multiple qualified
controllers the BTLE adapter chooses by row priority then stable platform ID; an
operator override may only narrow that set. One controller is active in the
initial profile. Replacement creates a new epoch and drains the prior owner.

The Linux service remains the existing non-root `aster-agent`. BTLE packaging
adds only the least privileges needed by the qualified BlueZ path, including
`AF_BLUETOOTH` where socket-family confinement is used; it grants no controller
reset, host pairing, or root authority. Roster-discovery credentials are
systemd-managed encrypted credentials in production, not environment variables,
CLI arguments, or ordinary configuration files. Configuration validation checks
policy and credential references without requiring present hardware. Service
readiness and health distinguish node readiness from per-adapter availability.

Linux qualification freezes the exact BlueZ D-Bus interfaces and methods used
for property reads, discovery filtering/windows, and advertisement registration.
The service identity is denied pairing, bonding, device connection/removal,
controller power/reset, and unrelated BlueZ management. Packaging supplies and
tests least-privilege D-Bus/Polkit confinement; if the host BlueZ policy cannot
enforce it, that composition is not qualified. Socket and D-Bus denial tests run
as the actual service identity.

Status, logs, and metrics share one metadata budget: adapter kind, coarse
available/degraded/unavailable reason, bounded counters, and current selected
kind. They omit peer/controller addresses, PSMs, role/roster membership,
discovery material, transfer identifiers/counts, retry detail, and secrets.
BTLE output uses the node's redaction sink rather than direct process logging.

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

Automatic-selection evidence adds two eligible physical adapters, zero-adapter
startup and hotplug, fair Event-only/all-class pending work, inbound/outbound
collision, aggregate exhaustion/restart, every `ContactOutcome` mapping, and
compatibility vectors proving a complete new handshake and no key, replay,
authorization, frame, or non-durable attempt-state transfer. Profile-5 vectors
separately prove that only its existing receiver-owned durable checkpoint may
carry into a fresh attempt.

Rings 3–5 add class convergence/resume, exact Profile-5 channel behavior,
platform interoperability, background-mobile profiles, packaging, hostile-peer
evidence, and independent implementation as applicable.

## Compatibility

- Replication wire/profile version 1 and semantic versions 1–9 retain their
  bytes and meaning.
- `BleL2capV1` is carrier-local and adds no semantic, storage, or public API
  allocation.
- V9 permits local automatic adapter selection before each fresh contact. That
  selection, its ranking, and its admission bound are implementation details;
  they add no new attempt/session-state transfer or live migration. Existing
  receiver-owned Profile-5 durable checkpoint resume remains permitted.
- Discovery revisions are carrier-local; new platform support adds evidence and
  packaging, not protocol identity.
- Any change to authority, durable ownership, public API, live-contact migration,
  cross-carrier attempt/session transfer, versioning, or process boundary
  requires a new reviewed decision.
