# Production BTLE carrier design after semantic v9

Clean Room — Privileged

**Status:** maintained architecture authority; no production authorization

**Capability track:** P1-4 reachability and carrier portability, followed by
all-class and cross-platform qualification.

**Selected Linux activation policy (2026-11-16):** runtime compatibility is
established by bounded, non-destructive probing. A previously unknown controller
that passes the required probe may activate automatically. “Officially
supported” remains a separate, evidence-backed release designation; absence from
the support matrix is not a runtime block. Exact known-unsafe combinations and
explicit deployment policy may still narrow the usable set.

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

## Delivery model and capability ledger

This document is the single architecture and delivery authority for BTLE. The
selected delivery model keeps the architecture, current status, increment
boundaries, and release gates together here. A separate implementation roadmap
was rejected because it would duplicate status and drift from the architecture;
review-finding-driven implementation was rejected because local fixes do not
define the product boundary.

The first production-qualified data type is **Event** in the systemd-managed
Linux agent. State, Record, Blob, other Linux hardware, macOS, Android, and iOS
remain designed parts of this same architecture and advance only through their
named capability exits. “Production-ready BTLE” without a qualifier means the
complete ledger; “Linux Event production profile” means only the first release
boundary defined below.

Status has the following fixed meaning:

- **Designed:** architecture and exit are defined, with no implementation claim.
- **Source:** production code exists but has not passed the complete exit.
- **Review blocked:** source exists, but an identified correctness, security, or
  architecture issue prevents verification credit.
- **Verified:** deterministic source verification for the capability passes.
- **Physical:** retained target-device evidence passes, but release gates may
  remain.
- **Qualified:** the exact release profile has passed every applicable package,
  security, support, evidence, and authorization gate.

Status is monotonic only for an immutable artifact and profile. A later change
can return the capability to Source or Review blocked. Every implementation PR
updates affected rows in the same change and links each claimed status to its
evidence; absence of evidence means the lower status applies.

| ID | Capability and owner | First measurable exit | Current status (2026-11-18) |
| --- | --- | --- | --- |
| **BT-A0** | Transport-neutral application readiness and durable publication, owned by the node/store | With zero eligible transports, startup succeeds, publication is durable, and later adapter availability wakes work without republishing | **Verified** for the merged Event evaluation path; production profile remains unqualified |
| **BT-A1** | Adapter-neutral bounded contact and mission authentication, owned by the node | BTLE supplies only transient carrier evidence; the exact mission peer authenticates before inventory or data; no Bluetooth value grants identity | **Physical** for bounded Event evaluation; not release-qualified |
| **BT-A2** | Adapter registry, eligibility, ranking, and node-global admission, owned by the transport-neutral node | Current exact authority and sanitized availability select one bounded fresh attempt; no adapter lifecycle or class retry policy enters the core | **Source**; automatic multi-adapter selection is not physically qualified |
| **BT-A3** | Closed attempt outcome and custody contract, shared at the node/adapter boundary | Typed authority, policy, adapter-epoch, transient, authenticated, cancellation, and shutdown outcomes preserve durable work, release custody, and authorize only the permitted retry/reselection action | **Source** with focused verification; physical and release qualification remain open |
| **BT-L0** | Bounded Linux controller inventory, passive compatibility probe, and sticky selection, owned by `aster-ble-linux` | Zero/many controllers, hotplug, BlueZ restart, timeouts, churn, unsafe rules, and unknown compatible hardware satisfy the defined deterministic bounds | **Source** with focused verification; physical automatic-path evidence remains open |
| **BT-L1** | Rostered Linux discovery and controller-epoch lifecycle, owned by `aster-ble-linux` | Listener, advertisement, scan, candidate, socket, credential, cancellation, and cleanup owners are bounded and joined; discovery remains locator-only | **Source**; fixed-controller physical evidence is scoped to BT-E0, while stock teardown-ingress and working-secret lifetime gates block this exit |
| **BT-L2** | Linux Event contact scheduling, owned by the BTLE runtime owner | The validated lower member schedules remote-only contact; success delays from completion, transient local failures back off, authenticated suppression parks only BTLE scheduling, and durable work survives adapter epochs | **Source** with focused verification; Linux owns cadence/backoff and the node owns generic custody and selection |
| **BT-L3** | Emission-policy lifecycle, owned by the BTLE composition root | Configured startup `Normal` owns the rostered radio lifecycle; configured startup `ReceiveOnly` is radio-inert. For the first profile, unsupported live changes are rejected and a controlled restart rebuilds radio and credentials atomically; later live reload must provide the same stop/join/restart guarantee | **Source** with focused verification; live mutation is rejected before either policy state changes |
| **BT-L4** | Linux production credential, package, and confinement profile | `aster-btle-roster`, rollback-safe renewal, non-root BlueZ/socket least privilege, denial tests, shutdown ordering, upgrade/rollback, and operator status pass as the packaged service identity | **Source**; package construction and payload checks pass, while installed-service execution, physical qualification, and release gates remain open |
| **BT-E0** | Fixed-controller semantic-v9 Event vertical slice | Two Linux nodes exchange and durably consume a protected Event larger than the minimum MTU through disconnect and restart | **Physical** evaluation only |
| **BT-E1** | Automatic Linux Event production profile | BT-A0–A3, BT-L0–L4, BT-O0, and BT-Q0 are Qualified for one exact peer and the declared supported hardware rows | **Source**; supporting production code exists, but this first release boundary has not passed its composite exit |
| **BT-SR0** | State and Record over the qualified class-neutral contact | Convergence, interruption, restart, withdrawal/tombstone behavior, priority, and resource bounds pass without BTLE-specific semantic records | **Designed** |
| **BT-B0** | Blob Profile-5 DATA/CONTROL over BTLE | Exact canonical records, bounded channel association, interruption, record-level durable resume, and control-liveness/resource exits pass | **Designed** |
| **BT-P0** | Additional Linux hardware and desktop/mobile foreground drivers | Each exact platform/hardware row passes the Linux-reference interoperability and lifecycle profile without changing application semantics | **Designed**; Pixel/Linux Event evidence is evaluation-only |
| **BT-P1** | Background mobile profiles | Explicit OS background constraints, permission lifecycle, packaging, energy, and availability semantics pass separately per platform | **Designed**; scheduled only after foreground platform qualification |
| **BT-O0** | Sanitized operability and support evidence | Readiness is separate from adapter availability; bounded status/reason/support fields obey the metadata budget and never expose locators, roster, PSM, peer, or credential data | **Source**; authoritative current status crosses the process boundary, while an authenticated query surface remains open |
| **BT-Q0** | Production qualification and authorization | Supported artifact, SBOM/license admission, dependency gates, hostile-peer/resource evidence, independent architecture/security review, reproducible package evidence, and signed release authorization pass | **Designed**; every release gate remains open |

### First production release boundary: Linux Event

The first production release is one exact-peer, Event-only,
systemd-managed Linux profile. It requires BT-A0 through BT-A3, BT-L0 through
BT-L4, BT-O0, and BT-Q0 to be Qualified for each named support row. It includes
automatic compatible-controller discovery and selection, zero-controller
readiness, hotplug/restart recovery, exact-peer authentication, durable Event
delivery, bounded retry and cleanup, correct configured startup behavior for
`Normal` and `ReceiveOnly`, explicit rejection of unsupported live policy
mutation, protected credential renewal or controlled restart, least-privilege
packaging, and actionable sanitized status.

It does not claim State, Record, Blob, multiple peers, live contact migration,
live emission-policy reload, background mobile operation, an unlisted support
row, or production authorization for source builds. Those exclusions narrow the
first release profile; they do not remove the corresponding capabilities from
the architecture.

### Aligned increments

| Increment | Capability IDs | Exit before the next increment |
| --- | --- | --- |
| **E0 — Event carrier baseline** | BT-A0, BT-A1, BT-E0 | Merged non-IP adapter path and retained Linux/Android evaluation evidence; no production claim |
| **E1 — automatic Linux hardware owner** | BT-A2, BT-L0, BT-L1 | Bounded probe/selection/activation source path is statically clean, deterministically verified, and its remaining physical/package gaps are explicit |
| **E2 — attempt and Event scheduling contract** | BT-A3, BT-L2, BT-L3 | Durable work survives every typed local lifecycle transition; suppression affects only its authorized scope; pending and active custody drain; generic node owns no BTLE cadence; unsupported live policy changes fail explicitly |
| **E3 — production Linux service profile** | BT-L4, BT-O0 | Credential renewal/restart, confinement, denial tests, status, upgrade/rollback, and signed package inputs pass as the service identity |
| **E4 — Event qualification and authorization** | BT-E1, BT-Q0 | Named hardware rows pass physical, interoperability, hostile, restart, resource, dependency, independent-review, and release gates |
| **SR1 — State/Record qualification** | BT-SR0 | Qualified Event contact carries State and Record convergence scenarios without carrier-specific semantics |
| **B1 — Blob qualification** | BT-B0 | Profile-5 channel, checkpoint, interruption, and resource exits pass |
| **P1 — platform expansion** | BT-P0, then BT-P1 | Exact additional platform rows pass foreground, then separately background, qualification |

E1 and E2 may share a PR only if the combined diff remains independently
reviewable and both exits pass; otherwise E1 closes first. No later increment
may be used to waive an earlier exit. A reviewer finding changes an increment
only when it maps to one of these capability invariants; otherwise it is either
deferred to its named capability or rejected as unrelated scope.

### Observable execution rules

Every implementation increment must expose, in its PR description:

1. capability IDs advanced and the exact old/new status;
2. production invariants exercised and explicit non-goals;
3. production-code and behavior-test delta, with no source-text/name tests;
4. static architecture, security, and quality review disposition;
5. focused verification, followed by one coordinated full check only when the
   PR candidate is otherwise publishable;
6. physical evidence required now versus deferred to qualification;
7. OPI provenance screening and dependency/source changes; and
8. signed commits and the exact upstream base.

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
but originates none; `PassiveOnly` admits no session contact. That is the target
profile behavior. The current source-level Linux agent keeps BTLE unavailable
and radio-inert for `ReceiveOnly`, because its automatic rostered supervisor
requires advertisement and scan, and the agent exposes no `PassiveOnly` option.
Later concurrency requires measured global/per-adapter bounds and authenticated
duplicate arbitration first.

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
hardware automatically and select a controller that passes the required
compatibility probe. An explicit controller override may exist as a diagnostic
or deployment policy control, but is not required for normal operation and
cannot turn unqualified hardware into officially supported hardware.

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

The target `ReceiveOnly` behavior originates no discretionary scan,
advertisement, contact, inventory, reconciliation, administration, or
application payload, while allowing protocol-required responses on an admitted
inbound contact. The current Linux agent does not yet have that non-originating
BTLE discovery/listener path: it registers the lane unavailable and starts no
automatic radio owner for `ReceiveOnly`. `PassiveOnly` emits no framework bytes
and cannot run an ordinary L2CAP session, but is not a current agent
configuration option. Final names and doctrine remain a profile decision.

The first Linux Event production profile accepts exactly `Normal` and
`ReceiveOnly` as restart-only configured startup states. `Normal` may acquire
the roster credential, probe and select a controller, start the role-required
radio owners, and let the lower mission member originate automatic Event
contacts. `ReceiveOnly` leaves BTLE unavailable and radio-inert in this first
profile; it may still receive through another eligible adapter, and all local
publication remains durable. It does not claim BTLE inbound reception until a
separately designed non-originating listener path exists. `PassiveOnly` and
threshold policies are outside this profile.

While BTLE is composed, a live emission-policy mutation is rejected before
either the node policy or BTLE owner changes. The operator changes validated
configuration and performs a controlled service restart; startup then builds
the new policy, credential, radio, registry, and admission state as one
composition. Credential renewal may use the same controlled restart without a
policy change. A later live-reload increment must replace this rejection with
one serialized revision-coupled stop, join, credential swap, rebuild, and
publish transition; independent policy and transport-gate writes are forbidden.

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
Source-level automatic Linux controller resolution/composition is now
implemented and tested separately from that explicit-controller evaluator.
Multiple peers, duplicate arbitration, other classes, packaged activation,
physical automatic-path qualification, and production approval remain open.

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

A successfully settled contact returns a separate bounded completion containing
the settled durable generation and completion time; success is not a failure
disposition. The first profile's failure-disposition vocabulary is closed and
local to the implementation, not a wire allocation:

| Disposition | Transport-neutral custody and selection effect | Initiating owner effect |
| --- | --- | --- |
| `RetryLater` | Release attempt-local custody, retain durable work, and do not wake another adapter solely because of the failure | The BTLE owner may submit a later independent request after its bounded jittered backoff |
| `Reselect` | After validating local adapter/attempt provenance, release custody and wake ordinary fresh selection; no session or attempt state transfers | End the affected BTLE attempt or epoch and wait for registry selection |
| `Suppress` | Record only the authenticated expected-peer, mission, or policy scope against its authority generation; retain durable work | For the first Linux Event profile, park only the affected BTLE schedule until controlled restart; the adapter and node remain alive. A later administrative retry or generation-triggered wake is an implementation extension, not a wire change |
| `Cancelled` | Release custody without changing eligibility, suppression, delivery, or retry state | End only an explicitly caller-cancelled operation or coordinated shutdown operation; lifecycle, authority, and policy changes must use their typed outcome instead |
| `Terminal` | Release custody and retain undelivered durable work; authorize no automatic retry | End that operation. Only an independently proven node-local invariant may enter node-fatal handling; no peer or adapter outcome may terminate the transport-neutral service |

The transport-neutral coordinator validates the tuple, owns custody release,
authority-generation suppression, and a reselection wake. It owns no BTLE timer,
success cadence, jitter, or retry count. The Linux BTLE runtime owner consumes
completion, `RetryLater`, and the parked/unparked state to implement its local
Event schedule. A pending ticket observes authority, policy, adapter epoch, and
shutdown changes until it is issued or closed; late observers attach to the one
shared completion object rather than creating a second scheduling mode.

Locally proven adapter unavailability before a mission handshake may still wake
ordinary selection because it identifies no remote peer. A remote or ambiguous
pre-authentication failure ends that scheduled operation and enters bounded
locator backoff; a later operation is independently selected rather than being
failure-driven fallback. Expected-peer, mission, and policy suppressions retain
their authority generation in the coordinator. The first Linux Event schedule
stays parked until controlled restart; a later generation-triggered wake or
administrative retry can be added locally without changing the wire protocol.
Transient transport state uses bounded backoff. The selector never parses error
text.

This outcome contract replaces coarse error collapse before a second production
adapter is enabled, preventing both cross-carrier probing and attacker-selected
peer suppression.

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

Runtime compatibility and official support are separate decisions. The Linux
driver enumerates available BlueZ controllers and runs a bounded,
non-destructive probe against each candidate. The required startup probe checks
that the service identity can open a BlueZ session, read the controller's
powered/address/type inventory, create and LE-address-bind a socket, validate its
dynamic PSM, listen, and close within bounds. Those typed public operations—not
metadata heuristics—establish inventory visibility, passive local CoC behavior,
and the permissions required for that preflight. This is local compatibility
preflight only; it does not prove radio operation, peer interoperability,
negotiated MTU, restart behavior, or safe advertisement and scan teardown. It
does not reset or power a controller, pair or bond a device, remove a device,
disconnect another owner's peer, mutate host-wide configuration, or emit RF
activity. Advertisement and scan capability and permission are established only
by actual operational registration when the emission policy permits it; passive
probing cannot violate `ReceiveOnly` or `PassiveOnly` policy.

A candidate that passes every required preflight gate is `compatible` and may
attempt operational activation whether or not it already has a support-matrix
row. The host still sees BTLE as unavailable until every policy-permitted,
role-required listener, advertisement, or scan owner has started successfully.
A compatible candidate is tagged `qualified` when its exact fingerprint has
retained release evidence, otherwise `unqualified`; this tag informs selection
and operator status but is not an activation gate. A deployment may opt into a
`qualified-only` hardening policy. Package composition can construct this
policy and its exact support and unsafe rows through the driver API; the agent's
current packaged configuration uses the default open-support policy. An exact
package-bound known-unsafe or revoked rule blocks activation, but a missing
support row does not. Missing or ambiguous fields that could overlap a
known-unsafe rule fail closed as `blocked` rather than silently bypassing the
rule. Successful probing never creates an official support claim.

The initial implementation examines at most eight controllers per probe sweep,
probes at most one concurrently, activates at most one, and accepts canonical
adapter names of at most 64 UTF-8 bytes. Eight and 64 are implementation
resource bounds—not protocol or support limits—chosen to cover ordinary
multi-controller Linux hosts and adapter names while bounding downstream
retained candidates and socket, probe, retry, snapshot, and log work and
rejecting pathological identifiers after BlueZ returns its fully materialized
inventory. They do not bound that initial BlueZ or system D-Bus ingress
allocation, which remains part of the trusted platform and confinement
boundary. Names are
canonicalized, validated, deduplicated, and ordered; the healthy selected
controller and an explicit diagnostic override are retained before filling
remaining slots. Extra entries are ignored deterministically without retained
overflow state or per-entry logs. Either constant may change without
compatibility impact.

Selection is private to the adapter and does not inspect mission authority.
Candidates are filtered by required compatibility, emission policy,
known-unsafe rules, and local policy, then ranked by explicit local narrowing,
an existing healthy selection, current health, qualification as a tie-breaker,
and an epoch-local canonical key. The outer adapter owner separately gates
activation and contact admission on policy, credentials, and peer authority.
An unrelated controller addition must not disrupt a healthy selected
controller. The driver coalesces harmless state changes behind a fixed 250 ms
minimum before the next full observation and allows one probe sweep at a time.
A selected-controller removal or relevant property change publishes
`Unavailable` and drains its owner immediately; replacement observation still
waits for the fixed coalescing boundary. It re-probes after BlueZ owner loss,
relevant selected-controller change, inventory change, or package/policy
generation change, and drains the current owner only when that controller is
lost, blocked, explicitly replaced, or has a relevant identity or capability
change. In the first increment, package and policy generation changes are
observed only on process restart; live authenticated reload is future work.

The compatibility fingerprint contains only the OS and architecture,
kernel/BlueZ version, controller vendor/product/revision, and firmware or driver
identity when the platform exposes them. Every field is typed, canonically
parsed, and length- and cardinality-bounded before comparison or reporting. It
excludes Bluetooth addresses, USB serial numbers, transient device paths,
allocated PSMs, peer identifiers, and credentials. The epoch-local canonical
adapter name or index may break selection ties but is never persisted or
exported and need not remain stable across restart. Missing optional fingerprint
fields make the support tag unqualified unless they create ambiguous overlap
with a safety rule; they do not otherwise fail successful compatibility
preflight.

The initial Linux implementation obtains the kernel release from its fixed proc
entry, the BlueZ version from a fixed absolute `bluetoothd` path with no shell or
`PATH` lookup, and physical controller identity from each retained candidate's
bounded sysfs device entries. The direct command and its inherited output pipe
share a private 250 ms deadline. One single-flight collection batch has a 500 ms
deadline: half is reserved for that command and half for the bounded proc/sysfs
work across the at-most-eight retained candidates, leaving half of the default
one-second resolver operation bound for BlueZ inventory and identity
revalidation. Accepted identity atoms are at most 64 bytes; transient sysfs link
reads are capped at 512 bytes before only their bounded basename is retained.
The collector pins one device, driver, and module generation while reading and
then revalidates those objects plus the BlueZ snapshot before admission.
Missing, changed, malformed, oversized, or unavailable values remain absent and
therefore cannot create a qualified support row. A timeout returns incomplete
fingerprints while retaining at most one underlying blocking worker, so
collection failure is non-fatal to compatibility probing and transport-neutral
readiness.

Static validated policy contains no detected controller identity and remains
valid without present hardware. The resolver issues one ephemeral, non-cloneable
`ControllerEpochOwner` containing the adapter name, address and type needed for
local socket operations, inventory generation, and bounded fingerprint. It
retains the lease while platform startup calls borrow a redacted, immutable
snapshot. Exact name/address/type is rechecked immediately before each platform
operation. Listener, advertisement, scan, and socket child owners do not clone
or retain the lease; each observes the epoch-generation cancellation signal and
closes when its owner becomes stale. The existing exact configured controller
tuple is retained only for evaluation and explicit diagnostic narrowing;
production automatic activation obtains it from the resolver owner.

State is represented on three independent axes. `ProbeDisposition` is
`Compatible`, `Incompatible(reason)`, `Blocked(reason)`, or
`Indeterminate(reason)`; probing itself is transient lifecycle, not a result.
`SupportTag` is `Qualified` or `Unqualified` and applies only to compatible
candidates. `RuntimeAvailability` is a private two-state model: `Unavailable`
or `Available`. `Available` is published only after the selected controller's
listener, advertisement, and scan owners are running and adapter availability
has been accepted. Initial, probing, policy-rejected, operational-starting,
loss, retry, and failure states remain `Unavailable`. Unsupported address
family, protocol, or LE CoC maps to `Incompatible`. BlueZ loss, hotplug, power,
permission, resource exhaustion, deadline, cancellation, or unknown platform
error maps to `Indeterminate` and runtime `Unavailable` with capped retry.
Package safety rules and explicit local policy map to `Blocked`. Mapping uses
typed platform errors and never parses error messages. The selector receives
only `Available` or `Unavailable`; no protocol or wire representation changes.
Controller lifecycle remains private to the Linux adapter.

The serialized probe has explicit per-operation, per-candidate, and whole-sweep
deadlines. Cancellation, deadline, cleanup failure, or an incomplete sweep never
asserts incompatibility. Every acquired socket or platform owner is closed and
joined within its declared bound before the candidate may be retried. The
whole-sweep budget gives every admitted candidate one bounded attempt; if that
cannot be maintained, a retained rotating cursor makes unfinished candidates
lead the next sweep. State changes collapse into one pending sweep. Harmless
inventory or property churn permits at most four full observations per second;
transient failures remain subject to capped retry/backoff.

The current source composition uses immutable empty support and
known-unsafe tables; the future signed qualified package compiles generated
rows into those bounded tables. A separately updateable signed artifact is
future work. Lab evidence
promotes an exact fingerprint to `qualified` and records its tested roles,
bounds, scenarios, artifact identity, and known issues. Safety rules use only
reliably obtainable bounded fields and may define explicit bounded ranges;
ambiguous overlap fails closed. Among probe-passing controllers, a qualified
row is preferable but not required under the default policy. Target operator
status reports adapter type, qualification tag, and sanitized closed reason
codes, never raw transient Bluetooth addresses, PSMs, discovery proofs, or
credentials.

The Linux service remains the existing non-root `aster-agent`. Its Debian unit
presents the optional systemd-encrypted `aster-btle-roster` credential and
admits `AF_BLUETOOTH` without raw/admin capabilities. A user-specific D-Bus
policy first denies BlueZ method calls, then allows only inventory/property
reads, filtered discovery start/stop, and advertisement registration cleanup.
It grants no controller power/reset, pairing, bonding, device connect/remove,
or root authority; no additional Polkit grant is installed. Without complete
BTLE configuration and a valid credential the radio path remains inert, and
without compatible hardware the node remains ready. Configuration validation
checks policy and credential references without requiring present hardware.

Linux qualification freezes the exact BlueZ D-Bus interfaces and methods used
for property reads, discovery filtering/windows, and advertisement registration.
The service identity is denied pairing, bonding, device connection/removal,
controller power/reset, and unrelated BlueZ management. Packaging supplies and
tests least-privilege D-Bus/Polkit confinement; if the host BlueZ policy cannot
enforce it, that composition is not qualified. Socket and D-Bus denial tests run
as the actual service identity.

Status, logs, and metrics share one metadata budget: adapter kind, coarse
available/unavailable reason, bounded counters, and current selected kind. They
omit peer/controller addresses, PSMs, role/roster membership,
discovery material, transfer identifiers/counts, retry detail, and secrets.
BTLE output passes through an allowlisting, coalescing process writer before it
reaches standard output. The agent publishes one current record containing only
timestamp, operation, adapter kind, availability, closed reason, and support
tag. The writer retains at most the latest record, retries spawn or write
failure at no more than four attempts per second, lets newer state replace a
failed record, and interrupts retry on close. Sink failure never changes
readiness, adapter availability, selection, or durable custody. Detailed
lifecycle edge events remain internal and do not become customer fields.

Compatibility observations are process-memory-only and replaced on inventory
epochs as one bounded current snapshot per examined controller, not an
unbounded history. Persistence requires a separate privacy and retention design.
No compatibility-report command, export, customer-status field, or log field
exists today. A future explicitly authorized manual evidence workflow may use
only a bounded non-identifying tuple—OS and architecture, kernel and BlueZ,
controller vendor/product/revision, and firmware/driver when exposed—plus
closed probe outcomes, support tag, and software artifact identity. Even that
tuple is potentially linkable operational metadata. The workflow must exclude
hostname, machine ID, the epoch-local key, and all fields prohibited above;
its output is evidence input, not authority to alter runtime policy or the
support matrix.

## Clean-room provenance guardrail

All design, implementation, review, and evidence work follows the current OPI
clean-room guardrail and exclusion list. Inputs are limited to clean Aster
source, public standards and public BlueZ/Linux APIs, public pinned dependency
sources, and clean hardware or ZeroTier lab observations. External components
used in the implementation or evidence record their name, version, and public
source in the resource log. Blocked repositories, packages, credentials,
excluded-person input, and proprietary implementation material are not accessed
or used.

Before commit, the staged diff, dependency graph, and newly introduced source
URLs are screened for excluded provenance. The retained receipt records only
that screening completed and any public sources admitted; it never copies
protected content. Each increment refreshes the shared guardrail and exclusion
list before screening. Its sanitized receipt records the policy revision,
applicable rule ID or `unknown`, match kind, affected file hash and location,
screening method/version, and scope. A lexical or delegated-review flag is a
candidate for contextual classification, not proof of exposure. Suspected
excluded provenance pauses the affected work and is quarantined and escalated
under the guardrail rather than silently removed.

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

Linux automatic-probe evidence covers zero controllers, one and multiple
controllers, malformed and duplicate inventories, eight-versus-nine selection,
a huge fake inventory proving downstream work remains bounded, missing and
ambiguous optional fingerprint fields, every closed disposition/error mapping,
deterministic ranking and selected-controller stickiness, non-disruptive
controller addition, hotplug and BlueZ restart re-probe, deadline/cancellation
and cleanup at every probe step, an early hung candidate followed by a compatible
candidate, sustained inventory-change storms, safety-rule ambiguity, and proof
that passive probing emits no RF activity. It covers an unknown compatible
controller attempting activation under the default policy, host availability
only after all required operational owners start, the same controller rejected
by `qualified-only` policy, and exact known-unsafe blocking. Fake platform tests
provide deterministic failure injection; physical evidence covers the actual
packaged service identity, controller coexistence without mutation, process and
controller restart, CM4 cold/warm/hotplug behavior, and Pixel-to-Linux Event
transfer. No requirement evidence advances from mechanism tests alone.

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
