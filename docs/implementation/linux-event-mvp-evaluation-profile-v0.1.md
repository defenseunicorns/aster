#

# Linux Event MVP Evaluation Profile v0.1

- Profile ID: `aster-linux-event-mvp-evaluation-v0.1`
- Status: Accepted by Decision 0042 on 2026-09-08
- Profile version: `0.1`
- Approved design date: 2026-09-06
- Candidate decision checkpoint: 2026-09-13
- Product class: time-bounded, non-production customer evaluation
- Start here: [human-focused MVP coordination guide](linux-event-mvp-coordination-guide.md)
- Ratification authority: [Decision 0042](../decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md)
- Decision register: [v0.1 register](linux-event-mvp-evaluation-profile-v0.1-register.md)
- Candidate-annex schema: [provisional schema](linux-event-mvp-evaluation-profile-v0.1-annex-template.md)

This profile defines the complete claim boundary for the named non-production
evaluation. It does not assert that an implementation, artifact, provider,
device run, or release candidate satisfies that boundary. A candidate may
claim the profile only after every applicable evaluation-blocking register row
passes and one completed annex binds the exact source, artifacts, provider,
configuration, nodes, results, receipts, and approvals.

Most engineers should read the
[coordination guide](linux-event-mvp-coordination-guide.md) first. It explains
the outcome, workstream handoffs, G1–G6 sequence, current blockers, and
definition of done. This document remains the exact profile authority.

## Summary

This profile defines the first reusable Aster customer-evaluation profile as a
deliberately narrow Linux, single-scope, Event-only product slice. The profile
supports durable offline-first Event exchange between exactly two manually
configured physical CM4 nodes over approved IP paths, optionally using one
customer-controlled pinned connectivity relay. It fixes the application,
security, operating, capacity, resource, lifecycle, artifact, and evidence
boundaries needed to decide whether an exact build is suitable for a customer
evaluation.

This is a time-bounded, non-production evaluation profile. It is not the
complete MVP target in `data-mesh-requirements.md`, production authorization,
or evidence that every mechanism named below is already implemented. A build
may claim this profile only after every evaluation-blocking gate in this
document passes for the exact artifacts, provider, configuration, target
devices, and retained receipts under review.

## Goals

1. Give evaluators one coherent supported path instead of asking them to
   assemble development mechanisms.
2. Make every supported platform, topology, API, security choice, workload,
   resource target, and lifecycle behavior exact and testable.
3. Preserve offline-first local publication and durable eventual Event
   transfer across intermittent approved IP connectivity.
4. Include restart-selected `ReceiveOnly` operation without describing it as
   physical radio silence.
5. Bound the durable publish-operation ledger honestly while preserving
   permanent retry classification and prohibiting key reuse.
6. Separate candidate implementation, retained evidence, and release claims.
7. Allow customer-specific annexes to narrow one reusable base profile without
   creating undocumented variants.

## Non-goals

- A production deployment or general availability claim.
- The complete four-data-class MVP target.
- State, Record, Blob, finite Event TTL, Event-content deletion, conflict
  resolution, or large-object transfer.
- Multi-scope operation, Aster bridges, dynamic routing, dynamic membership,
  or customer administration of bridge policy.
- Automatic LAN discovery, public/default relay selection, hosted discovery,
  or universal NAT traversal.
- BTLE or switching between carriers or network interfaces.
- Literal zero-byte transmission, physical RF silence, radio control, or
  emission certification.
- Real-time streaming, message-broker semantics, exactly-once delivery, or a
  guarantee that every connected peer is currently converged.
- Operation-key reuse, deletion of permanent retirement fences, generation
  rollover, or unbounded mission lifetime.
- Snapshot-resistant rollback, recovery after complete state loss, filesystem
  rollback, or power-loss assurance beyond retained evidence.
- FIPS 140-3 validation, independent server interoperability, hostile-peer
  qualification, or production SLOs.

## Profile identity and reuse

The reusable profile name is **Linux Event MVP Evaluation Profile v0.1**. A
claim records that exact name plus:

- the Aster source commit and semantic protocol version;
- artifact digests and signatures;
- package, SBOM, notice, and provenance digests;
- the protected-provider implementation and version;
- the complete sanitized configuration digest;
- exact Raspberry Pi reference image, Debian identity, kernel, systemd package,
  architecture, filesystem, and CM4 identity;
- exactly two mandatory physical aarch64 CM4 participants;
- a third CM4 only as declared support capacity;
- no reusable claim for another OS, image, architecture, device family, VM,
  container, or node tier;
- enabled direct and controlled-relay paths;
- the acceptance-harness version; and
- the retained receipt bundle and release decision.

A customer annex may remove relay use, reduce payload or queue limits, tighten
resource limits, or disable an optional behavior. It may not reduce the two
mandatory CM4 participants, add a platform, carrier, data class, API, security
profile, topology, or lifecycle behavior; weaken authentication, rollback,
isolation, or evidence gates; increase a bound; or convert an exclusion into
support. An expansion requires a new versioned base profile.

After a claim is issued, v0.1 and its receipt bundle are immutable. An editorial
correction that changes no boundary produces v0.1.1. Any changed target,
behavior, gate, or evidence boundary produces v0.2. Both retain the prior claim
for audit.

## Intended evaluator and use case

The intended evaluator is a technical integration or field-test team operating
customer-controlled Linux devices and network infrastructure. The supported
outcome is:

> An application durably publishes bounded operational Events while peers are
> unavailable, later exchanges them with authenticated nodes over approved IP
> paths, detects publisher gaps, and processes durable at-least-once deliveries
> without requiring a cloud service or public relay.

The application owns interpretation of Event payloads and acknowledgement
checkpoint durability. Operators own peer coordinates, optional relay trust,
mission material, capacity preflight, service control, and preservation of the
state directory. This profile does not supply an end-user application or C2
workflow.

One v0.1 evaluation mission runs for at most 48 continuous hours: a 24-hour
disconnected publication window followed by no more than 24 hours for
reconnection, convergence, query/delivery, and evidence collection. Sustained
publication stops with the disconnected window. The mission ends earlier if
any node reaches 1,024 distinct accepted publish operations or another profile
capacity boundary. Bursts count toward the same operation budget. Extending or
restarting the calendar does not reset a state directory's operation count.

## Supported platform and deployment

| Dimension | Required value |
|---|---|
| Operating system | Raspberry Pi reference image `2026-06-18`, identifying as Debian GNU/Linux 13 `trixie` |
| Kernel | Exact `6.18.39+rpt-rpi-v8` build, revalidated and frozen in the candidate annex |
| Architecture | `aarch64` only |
| Hardware | Physical Raspberry Pi Compute Module 4 Rev 1.1 |
| Service manager | systemd `257.13-1~deb13u1` |
| Package | Native `arm64` `.deb` |
| Filesystem | Local `ext4` state |

The candidate annex must confirm the exact image identity
`Raspberry Pi reference 2026-06-18` on both mandatory devices.

The artifact runs as a dedicated unprivileged service identity. Application and
health listeners remain loopback-only inside the dedicated namespace. The
deployment exposes no Service, host port, ingress, remote tunnel, or unrelated
same-namespace sidecar. Bearer authentication remains mandatory inside the
namespace.

Ubuntu Server 24.04, `x86_64`, Raspberry Pi Compute Module 5, VMs, containers,
Kubernetes, Helm, Zarf, UDS, network filesystems, other Linux distributions,
macOS, Windows, Android, iOS, and MCU targets do not qualify v0.1. The 8- and
20-node tiers are also non-goals. A container image produced by a broader
artifact workstream is not a v0.1 artifact.

## Topology and carriers

- One mission authority, one scope, one topic, and one durable application
  subscription are active in a qualification scenario. This is not one
  subscription per node.
- The mandatory qualification topology contains exactly two physical CM4
  nodes.
- A node has no more than 19 exact manually configured peers.
- Direct IP uses exact operator-provided carrier address and peer identity
  bindings. Automatic discovery is disabled.
- A deployment may configure at most one exact customer-controlled pinned
  HTTPS connectivity relay in `direct_preferred` mode with explicit DER trust
  roots. WebPKI trust and `relay_only` are outside v0.1.
- The pinned connectivity relay is carrier infrastructure. It is not an Aster
  durable store, application authority, Aster bridge, or payload-blind custody
  node.
- Public/default relay fallback, hosted lookup, port mapping, dynamic peer
  admission, arbitrary address replacement, and a general NAT-traversal claim
  are prohibited.
- An annex that enables the pinned relay must carry relay-specific retained
  acceptance. A direct-only annex may omit that path and must say so.

The profile promises durable progress after an approved path becomes available;
it does not promise real-time delivery, a direct-first chronology, seamless
multipath behavior, or continuous connectivity.

The reusable base uses this participant shape:

| Required topology | Physical CM4 nodes | Required exchange |
|---|---:|---|
| Two-node base | 2 | Both CM4 nodes run the unchanged G3 artifact and exchange Events directly |

The third CM4 is an optional declared spare, failure, recovery, or relay
participant and support capacity, not a third required participant. If it
sends, receives, stores, or relays candidate traffic, the annex records it in
the inventory with its exact role and reruns every affected scenario. Replacing
either mandatory node is an inventory change and likewise requires every
affected scenario to be rerun. Results involving the third CM4 do not widen the
required two-node claim.

## Emission modes

Qualification requires a new strict `mesh.emission_policy` field. Each node
selects exactly one startup mode before node startup:

- `normal` permits ordinary configured contact initiation/election and
  authorized local Event and control disclosure.
- `receive_only` initiates no carrier contacts, discloses no local Event/control
  inventory or objects, and may accept authenticated bounded blind-Event offers
  within current policy and quota.

Changing the mode requires a controlled restart. The effective mode is exposed
through authenticated status. Local health and Event APIs remain ready in
`receive_only` when the durable local authority is otherwise healthy.

`receive_only` is not radio silence or zero-byte transmission. An inbound
contact still requires carrier traffic plus protected handshake, empty-
inventory, acknowledgement, result, and closure traffic. A node that must emit
no bytes must be disconnected through an external radio/network control outside
Aster.

Qualification exercises inbound synchronization with each carrier-identity
ordering so that contact election cannot hide an ordering-dependent inability
to reach a receive-only node. It observes no initiated contact and no local
Event/control inventory disclosure from that node.

## Protocol, security, and mission policy

- Qualification peers must negotiate semantic protocol version `6`. Existing
  runtime compatibility with versions 1 through 5 is outside the profile and
  is not exercised by qualifying provisioning or peers.
- Qualifying provisioning selects exactly Aster security profile `0x0001` and
  hybrid cryptographic suite `0x0001`, including the suite's complete classical
  and post-quantum composition. Profile identifiers are unordered. Profile
  `0x0002` and every other identifier are outside v0.1; there is no profile
  fallback.
- The authenticated mission policy permits exactly that profile/suite pair;
  mismatch fails before inventory or Event exchange.
- Every node has a distinct provisioned identity.
- One offline mission root delegates to exactly one mission signer for this
  profile. The signer provisions the bounded node roster and mission policy.
- Carrier authentication does not grant mission membership, scope access,
  topic access, Event acceptance, or application authority.
- Source payload protection, mission authentication before inventory, replay
  rejection, payload-blind carrier relay behavior, and downgrade resistance
  remain mandatory.

v0.1 is explicitly **non-FIPS**. Use of NIST-named algorithms does not imply a
validated module, approved operating mode, key custody assessment, or FIPS
authorization. A production profile requires a separate reviewed FIPS and
validated-module disposition.

### Metadata exposure budget

The profile does not claim to hide transport-required source/destination
addresses, carrier endpoint identifiers, relay use, direction, packet sizes,
timing, duration, volume, loss behavior, or RF/network energy. The pinned
connectivity relay may observe the carrier metadata necessary to serve the
connection. Local filesystem allocation, database shape, and process resource
use are visible to the operating-system administrator.

v0.1 claims no Event payload/content plaintext exposure on carriers and no
listed sensitive fields in public errors or logs. Health endpoints disclose
only status codes and detailed status is authenticated. Topic, scope, priority,
logical-key, and operation-key metadata may exist in privileged local stores or
indexes and may be visible to the operating-system or storage administrator.
Universal at-rest metadata encryption is not claimed; device and filesystem
protection are deployment responsibilities.

## Protected provisioning boundary

A qualifying artifact statically composes exactly one approved protected
`ProvisioningSecretLoader`. The strict agent configuration contains only an
owner-only reference file and load-operation identifier; it does not contain
mission secret bytes. Plaintext credentials in arguments, environment values,
logs, package layers, ordinary configuration, or application responses are
prohibited.

The exact initial v0.1 provider binding is:

- provider = `aster-systemd-credential-store/v2`
- design = [`docs/superpowers/specs/2026-09-08-raspberry-pi-systemd-credential-provider-v2-design.md`](../superpowers/specs/2026-09-08-raspberry-pi-systemd-credential-provider-v2-design.md)
- design_digest = `sha256:30c5dfe71a203fcdd69dd330f9b5c68eeaee5032b624ee41912aa4723a9f853f`
- presentation_amendment = [`docs/superpowers/specs/2026-09-09-systemd-257-credential-presentation-amendment.md`](../superpowers/specs/2026-09-09-systemd-257-credential-presentation-amendment.md)
- presentation_amendment_digest = `sha256:549ea3fd5bdfd62c01bab5a8f1adac4b84a2710ab406ea006119c9048e28d4cd`
- systemd = `257.13-1~deb13u1`

The provider uses `systemd-creds` and `LoadCredentialEncrypted=` with explicit
host-key protection, the fixed credential name `aster-provisioning.bundle`, a
statically composed runtime loader, and the root-operated
`aster-credential-admin` administration artifact. TPM2 and all automatic or
fallback provider selection are excluded.
Internal approval of this exact provider selection and bound design digest was
recorded for the profile definition on 2026-09-08. D06 is resolved for the
profile definition. Product approval to implement and validate the exact
systemd 257 credential-presentation amendment was recorded on 2026-09-09.
Security and Deployment approvals of both immutable records remain mandatory
candidate gate E01; provider qualification remains a later gate.

This provider selection makes no generic Debian or Debian-family support claim.
If final review requires another platform, D06 must be reopened and the
provider redesigned and versioned against the exact additional platform
boundary before the affected profile or candidate can proceed.

The provider and operating procedure must demonstrate:

1. installation of a protected node/mission reference;
2. load at startup without exposing plaintext through ordinary files or logs;
3. bearer-token rotation through atomic `SIGHUP` reload;
4. mission-reference or provider rotation through controlled restart;
5. backup and recovery through the provider's protected mechanism;
6. rejection of a revoked node and explicit mission rekey behavior; and
7. provider-backed logical destruction followed by fail-closed startup.

v0.1 exposes no live membership-administration API through the Event agent and
uses a fixed preprovisioned roster during a running process. Revocation/rekey
qualification stops the affected nodes, uses the exact provider administration
artifact and command sequence recorded in the signed annex to issue a new
roster/key generation without the removed node, and restarts the remaining
nodes. The removed credentials must fail subsequent authentication. General
live membership mutation and in-mesh revocation propagation are out of profile.

The repository's unprotected fixture and age-based engineering adapters are
development/test tools only. They cannot qualify v0.1.

## Application boundary and bindings

The normative out-of-process boundary is the repository-owned protobuf schema
and ConnectRPC service on authenticated loopback TCP. The supported methods are:

- `GetStatus`;
- `PublishEvent`;
- `QueryEvents`;
- `CreateEventSubscription`;
- `PollEvents` and `StreamEvents`;
- `AcknowledgeEvent`;
- `DeleteEventSubscription`; and
- `QueryEventGaps`.

The health boundary additionally supplies detail-free `GET /livez` and
`GET /readyz`. `SIGHUP` reloads only the application bearer token. `SIGINT` and
`SIGTERM` perform bounded drain and shutdown.

The initial reference client is Rust. The generated Go client and process
acceptance remain in qualification scope and must cover the same wire/API
contract. Go is not a second server implementation, and the generated-client
test is not independent interoperability evidence. C, Python, Java/Kotlin,
Swift, Node.js, C FFI, and native in-process bindings are outside this profile.

The Event API does not expose finite TTL in v0.1. `DeleteEventSubscription`
removes a selector and its delivery ledger; it does not delete Event content.
Stream delivery remains at least once until acknowledgement succeeds.

## Event and retry semantics

`PublishEvent` returns only after local durable acceptance. Connectivity is not
required. Its operation key names one application effect, not one HTTP/network
attempt.

- Before payload retirement, an exact retry of the same key and byte-equivalent
  request returns the original durable result.
- Reusing the key with different content fails closed as an operation-key
  conflict.
- After payload retirement, an exact retry returns nonretryable Connect
  `NotFound` with public reason
  `PUBLIC_ERROR_REASON_MISSING_DURABLE_OBJECT`; it cannot create another Event.
  The selected-node cause remains `ExpiredOrRetired`. Changed content remains
  an operation-key conflict.
- A client with an unknown outcome retries the original request with the same
  key. It must not generate a new key merely because a deadline elapsed.
- Query continuation uses the returned marker. Durable delivery may repeat
  after cancellation, deadline, disconnect, or process failure until the
  acknowledgement is durably accepted.

## Durable publish-operation containment

v0.1 is operationally limited to **1,024 distinct
`PublishEvent.operation_key` values over the lifetime of one state directory,
including all restarts**. The implementation does not enforce this lower
profile boundary. The qualification harness and operator procedure count
distinct accepted keys, stop new publication at 1,024, and end the profile
claim. Keys are 1 through 256 bytes. Exact retries do not consume another
ledger record. A key never expires and must never be rebound to a different
publication intent.

The selected implementation stores a fixed-size, mission-bound operation
fingerprint and canonical intent commitment rather than the raw operation key.
While the Event remains replayable, an active record retains its exact durable
result and a bounded reverse index. When Event custody retires that Event, the
store atomically replaces every active alias with a permanent compact
retirement fence. An exact retry of a retired operation remains
`ExpiredOrRetired`; changed intent remains a conflict. At most 64 active
operation aliases may name one Event. Retirement compacts the record; it never
permits key reuse or removes the permanent classification fence.

The strict v0.1 configuration selects a separate permanent ledger quota of
`storage.operations.max_records = 1_000_000`,
`storage.operations.max_logical_bytes = 201_326_592` (192 MiB), and
`storage.operations.emergency_reserve = 10_000`. One active record plus its
reverse-index key charges at most 162 logical bytes; one retired fence charges
67 bytes. Ordinary publication preserves the 10,000-record/1,620,000-byte
emergency reserve. The 1,024-operation profile workload therefore remains far
below the configured ledger ceiling. The aggregate Event/control store quota
is separately enforced and can still stop Event admission earlier.

This is a supported operational workload boundary, not a new store admission
limit or reclamation mechanism.
At or before 1,024 distinct operations, the evaluation stops new publication
work and preserves the state directory for inspection. Deleting or replacing
that directory is not same-mission capacity recovery and invalidates durability
and restart claims. A later evaluation uses a new mission identity and a fresh
state directory.

Authenticated status must expose total, active, retired, and reverse ledger
rows; logical bytes; configured record/byte ceilings; ordinary and emergency
headroom; the 1,024-operation profile boundary and remaining profile headroom;
the bounded rolling acceptance estimate; and startup/background audit state.
A profile warning becomes actionable no later than 512 distinct operations.
Separately, configured-ledger occupancy is `OK` below 70%, `WARNING` at 70%,
`CRITICAL` at 90%, and `EXHAUSTED` when no ordinary active record fits. The
rolling rate uses the preceding 60-second in-process observation window, resets
on restart, and has planning value only; neither it nor the derived exhaustion
estimate changes qualification pass/fail authority.
Reaching 1,024 ends the supported workload even though the ledger may still
accept it. Exhaustion of either configured ledger ceiling is a separate Connect
`ResourceExhausted` failure with additive public reason
`PUBLIC_ERROR_REASON_OPERATION_CAPACITY_EXHAUSTED = 12`, `retryable = false`,
and no retry delay. Changing the key or retrying indefinitely is not recovery.
Other aggregate storage pressure retains its separately accurate capacity
guidance.

Startup and background audit examine the permanent ledger incrementally and
must fail closed for new Event publication on an invariant violation while
preserving bounded status, reads, and shutdown. The implementation's
crash-safe active-to-retired lifecycle is selected for P1-1, but v0.1 exposes no
black-box finite-TTL or Event-content-deletion trigger and claims no physical,
long-duration, or production qualification of that lifecycle. A profile review
is still required after the first retained workload on both mandatory CM4
nodes and before approving a workload above 1,024 operations, any `P2-2`
bracket, or a production profile.

The review records distinct accepted operations, key-length distribution,
logical operation bytes, database/filesystem growth, reopen time, RSS, CPU,
and intended workload rate/duration. It either retains/lowers this boundary or
selects a monotonic generation/sequence plus durable retirement watermark in
which every late retired retry fails closed.

## Capacity and workload matrix

The strict customer configuration explicitly sets:

- `storage.max_items = 10_000` aggregate logical tracked rows;
- `storage.max_payload_bytes = 67_108_864` aggregate logical tracked bytes;
- `storage.operations.max_records = 1_000_000` permanent ledger records;
- `storage.operations.max_logical_bytes = 201_326_592` ledger and reverse-index
  logical bytes;
- `storage.operations.emergency_reserve = 10_000` records;
- at most 19 configured peers per node;
- `limits.max_connections = 1`; and
- at most 8 node-global in-flight application operations.

The qualification harness, rather than the generic configuration schema,
limits:

- one local application client;
- query and gap pages of 16;
- delivery pages of 16;
- delivery/gap scan limits of 128;
- at most 256 simultaneously unacknowledged deliveries per node; and
- plaintext application Event payloads from 0 through 65,536 bytes.

`limits.max_connections = 1` is the total local application-connection setting;
at most eight application operations are in flight node-globally. One local
application client is a qualification-harness topology bound, not an identity
limit.

Unless a later profile adds explicit API enforcement, the harness values are
evaluated workload boundaries rather than general runtime admission ceilings.
In particular, 65,536 bytes is not an independently enforced server payload
limit.

The 10,000/64-MiB values are required profile configuration, not generic
production sizing or customer-schema defaults. They govern the aggregate
Event/control store and exclude the separately accounted operation ledger,
redb/filesystem amplification, untracked files, snapshots, swap, backups, and
process memory. Control and emergency store reserves reduce ordinary usable
capacity. The operation-ledger quota is also logical accounting and likewise
excludes backend/filesystem amplification and process memory.

The qualification dimensions are not an unconstrained Cartesian product:

| Scenario | Nodes | Payload | Rate/duration | Purpose |
|---|---:|---:|---|---|
| API boundary | 2 | 0, 4 KiB, and 64 KiB | One exact Event at each boundary | Encoding, durable acceptance, transfer, query, delivery, and acknowledgement |
| Two-node topology | 2 | 4 KiB | 10 Events at 1 Event/s | Direct and optional pinned-relay recovery |
| Offline soak | 2 | 4 KiB | 10 Events/hour/node for 24 hours | Disconnected publication, restart, later convergence, gaps, and capacity/resource behavior |
| Capacity-warning probe | 2 | 4 KiB | 512 distinct local operations plus one exact retry | Audited operation usage, 50% warning, and retry-without-growth |

The 64-KiB profile boundary is tested as a payload boundary and bounded burst;
it is not sustained at 10 Events/hour during the 24-hour soak. Every run starts
from a fresh zero-workload state directory, retains controls created by
provisioning, and records final logical and physical headroom on both mandatory
CM4 nodes. Admission or convergence past a stated limit is not part of the
successful profile.

The agent's compiled request/message ceiling is 1 MiB, but v0.1 makes no 1-MiB
plaintext payload claim because protobuf and protected-envelope overhead also
consume bounded request and mesh-object space.

Configured ledger saturation is exercised only in an isolated engineering test
outside the v0.1 workload, normally through test-only lowered record/byte limits
that preserve the production transaction path. It validates terminal failure,
exact active replay, retired classification, changed-intent conflict, and
emergency-reserve behavior without expanding the supported 1,024-operation
profile boundary.

After control and emergency reserves, the configured store provides 5,840
ordinary aggregate item slots and 50,266,112 ordinary logical bytes. The
two-node soak projects 480 ordinary Event items per converged node, leaving
5,360 item slots before other aggregate-counted rows. Each publishing node also
projects 240 separate active operation-ledger records and their reverse-index
entries. Byte fit remains provisional until the receipts record exact protected
source-object bytes, operation-ledger logical use, and physical database growth;
plaintext payload arithmetic alone is not evidence of fit.

## Resource and lifecycle targets

The following apply to the provider-composed agent on each participating
physical CM4 node under the workload matrix:

| Measure | v0.1 target |
|---|---:|
| Stripped deployed executable | no more than 16 MiB |
| Steady-state RSS after stabilization | no more than 64 MiB |
| Peak RSS during a declared qualification scenario | no more than 128 MiB |
| Idle CPU with no active contact or client request | no more than 5% of one core |
| Ready after service start/restart | within 10 seconds |
| Graceful stop | within 30 seconds |
| Deployment memory | at least 1 GiB |
| Free local state space at start | at least 256 MiB |


Energy is measured and retained for each participating physical CM4 node but
v0.1 sets no pass/fail threshold. A changed target creates a new profile
version; a test result does not silently redefine v0.1.

Startup fails closed before readiness for invalid configuration, credentials,
provider state, mission policy/profile mismatch, or inconsistent durable state.
Same-version process crash and restart reuse the existing state directory and
must preserve durable acceptance, operation-ledger records and fences,
subscriptions, pending deliveries, acknowledgements, and mission controls.

Ordinary configuration, peers, relay, mission reference, storage, and emission
mode change only through controlled restart. Bearer-token reload is the sole
v0.1 live configuration mutation.

v0.1 permits no in-place binary downgrade and no state-snapshot restoration.
Its only rollback procedure is reinstalling the exact qualified artifact and
configuration against the unchanged current state directory. Any older binary/
state pair is out of profile unless a later profile revision names that exact
pair and retains compatibility evidence. Reusing a copied state directory or
combining a fresh binary with unknown state provenance is prohibited.

Complete state loss, filesystem corruption repair, physical destruction,
anti-rollback recovery, and power-loss consistency beyond retained evidence
remain outside v0.1.

## Minimum observability and failure contract

Detailed status is authenticated and bounded. In addition to the candidate
Event-service fields, qualification requires:

- configured and effective emission mode;
- logical item and payload-byte use and configured limits;
- publish-operation total/active/retired/reverse rows, logical bytes, configured
  ceilings, ordinary/emergency headroom, profile boundary/headroom, bounded rate
  estimate, warning state, and ledger-audit state;
- durable pending-delivery count and saturation indication;
- cumulative authenticated and failed contact counts; and
- bounded per-peer authorization and last-contact outcome already present in
  the candidate service.

Status is a snapshot, not convergence proof. Identifiers and coordinates are
not logged through unauthenticated health or public errors. Operators receive
one sanitized error category, operation name, and accurate retry guidance.

The broader production-observability outcome—oldest pending age, full queued
bytes, retry deadlines, path transitions, validated alert thresholds, SLOs,
and fleet aggregation—remains the separate P1 customer-readiness priority. It
is not inferred from these minimum fields.

## Artifact and installation contract

The one native `arm64` candidate contains:

- one provider-composed, stripped `aster-agent` executable in a native `.deb`
  package with the annexed artifact-authentication method;
- one hardened `systemd` service definition and documented namespace sharing
  boundary for the intended application;
- strict example configuration and side-effect-free validation command;
- install, start, health-check, controlled restart, upgrade, rollback,
  uninstall, and state-preservation procedures;
- Rust reference-client source and exact build instructions;
- generated Go client plus black-box acceptance executable/source;
- dependency SBOM, complete third-party notices, source/build provenance,
  signatures, and checksums; and
- the profile, customer annex, evidence index, known limitations, and support
  escalation procedure.

Builds use locked reviewed inputs through the approved package proxy or
documented offline source set. Enterprise CA roots are installed through the
explicit relay trust boundary; TLS verification cannot be disabled. No
credential, mission data, local state, test token, or generated acceptance
secret is included in an artifact.

## Acceptance and retained evidence

The following are non-waivable gates for any v0.1 evaluation authorization.
The 2026-09-13 meeting is an issue/refuse/defer checkpoint; reaching the date
does not authorize a candidate. An unpassed gate against the exact final
artifacts causes refusal or deferral.

1. A clean, locked source checkout reproduces the one `arm64` package and its
   SBOM, notices, provenance, and checksums through the approved build path.
2. `mise run check` passes deterministically from that clean checkout. The
   Event-service process acceptance and checked-in Go generation checks pass
   for the exact artifacts.
3. Generic configuration validation has no state, provider-load, or listener
   side effects. The signed qualification-annex validator refuses a v0.1 claim
   when otherwise-valid generic configuration deviates from the profile. The
   generic v1 schema may accept broader development values without making them
   part of v0.1.
4. Protected install/load, bearer rotation, provider/reference rotation,
   backup/recovery, revoke/rekey, and logical destroy follow the lifecycle
   contract without secret disclosure.
5. Both mandatory CM4 devices and the one `arm64` artifact pass install,
   readiness, normal stop, forced process loss, same-version restart, upgrade,
   permitted rollback, and uninstall/state preservation scenarios in the exact
   declared profile environment.
6. Rust publishes and consumes through the normative API. Go performs the same
   black-box wire/API recovery path against the Rust server.
7. The two-node workload passes with the exact environment retained. v0.1
   defines no generic loss/latency/bandwidth acceptance bracket. Optional
   controlled-relay claims include relay-loss and direct-path recovery;
   direct-only annexes omit the relay claim explicitly.
8. Twenty-four-hour disconnected publication, intervening restart, later
   authenticated convergence, exact gap reporting, at-least-once redelivery,
   acknowledgement, and peerless reopen retain the expected data.
9. `receive_only` passes both carrier-identity orderings without constraining or
   regenerating identities to obtain favorable election, initiates no carrier
   contact, discloses no local Event/control inventory, accepts inbound Events,
   exposes its effective mode, and retains mandatory response traffic as an
   explicit non-silence limitation. Failure requires an implementation fix or
   refusal of v0.1.
10. Operation-ledger and store headroom remain within the profile boundary;
    exact active retry, changed-intent conflict, configured-cap saturation,
    emergency reserve, audit, crash/reopen, and warning behavior are retained.
    Component tests retain atomic active-to-retired compaction and the
    post-retirement `ExpiredOrRetired` invariant; v0.1 claims no black-box
    retirement trigger because its API exposes neither finite TTL nor
    Event-content deletion.
11. RSS, CPU, executable size, startup, stop, state growth, and energy are
    measured on each participating physical CM4 node. Every thresholded target
    passes; energy is reported without a pass/fail claim.
12. Packet/log/error inspection finds no forbidden plaintext or credentials
    within the stated metadata budget.
13. The release owner verifies every artifact/evidence digest, open-gate
    disposition, exact dependency graph, and customer annex before issuing a
    signed evaluation decision.

Receipts distinguish same-host software tests, virtual/network-namespace tests,
and physical-device observations. Existing one-host and generated-Go receipts
remain bounded implementation evidence; they do not become physical,
independent-server, supported-package, protected-provider, or release evidence.

v0.1 requires no black-box retirement trigger.

### Qualification dependency chain

Qualification follows this serial gate chain even when preparation happens in
parallel:

1. **G1 — Event baseline:** accept the Event-service baseline and freeze the
   emission/capacity contract.
2. **G2 — Source/API freeze:** merge ReceiveOnly and capacity behavior, pass
   focused tests, and freeze one source/API commit.
3. **G3 — Artifact freeze:** reproducibly build and sign protected-provider-
   composed one native `arm64` package from G2.
4. **G4 — Focused target tests:** pass install, lifecycle, Rust/Go API,
   ReceiveOnly, and direct/optional-relay scenarios on both mandatory CM4
   devices using the unchanged G3 artifact.
5. **G5 — Workload qualification:** run the two-node workload and 24-hour
   disconnected/reconnection scenario using the unchanged G3 artifact and a
   frozen device/network inventory.
6. **G6 — Disposition:** review receipts and rerun deterministic gates, then
   issue, refuse, or defer the exact G3 artifact set.

## Consequences and claim boundary

- Evaluators receive one precise Linux/Event product slice rather than a broad
  claim based on unrelated mechanisms.
- The two-node soak projects 480 ordinary Event items against 5,840 available
  ordinary store slots, plus 240 separate operation-ledger records per
  publishing node. Store, ledger, and physical byte fit remain qualification
  gates, not production sizing evidence.
- The 1,024-operation boundary leaves substantial configured ledger headroom
  over the 240-operation offline workload, but does not qualify higher rates,
  longer missions, or production capacity.
- Restart-selected ReceiveOnly satisfies the bounded receive-only use case but
  deliberately does not use the words radio silence or zero transfer.
- Rust is the first reference client and Go remains a required API/client
  acceptance lane without being misrepresented as an independent server.
- Physical-device results may cause a versioned target revision after review;
  they never silently broaden existing evidence.
- v0.1 authorizes evaluation only after its gates pass. It moves no requirement
  evidence status, closes no complete P1/P2/P3 capability, and authorizes no
  customer production release.
