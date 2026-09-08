#

# Linux Event MVP Evaluation Profile v0.1 design

**Status:** Approved in design review on 2026-09-06; implementation planning
authorized

**Implementation plan:**
[`2026-09-06-linux-event-mvp-evaluation-profile.md`](../plans/2026-09-06-linux-event-mvp-evaluation-profile.md)

**Date:** 2026-09-06

**Target evaluation-candidate decision:** 2026-09-13

**Roadmap action:** `P0-1 — define the claim boundary`

**Design baseline:** `419cddd` (`origin/docs` at design time)

**Candidate Event-service baseline:** `671355a`
(`origin/feature/customer-operable-event-service` at design time)

## Summary

Define the first reusable Aster customer-evaluation profile as a deliberately
narrow Linux, single-scope, Event-only product slice. The profile supports
durable offline-first Event exchange among 2, 8, or 20 manually configured
nodes over approved IP paths, optionally using one customer-controlled pinned
connectivity relay. It fixes the application, security, operating, capacity,
resource, lifecycle, artifact, and evidence boundaries needed to decide
whether an exact build is suitable for a customer evaluation.

This is a time-bounded, non-production evaluation profile. It is not the
complete MVP target in `data-mesh-requirements.md`, production authorization,
or evidence that every mechanism named below is already implemented. A build
may claim this profile only after every evaluation-blocking gate in this
document passes for the exact artifacts, provider, configuration, target
devices, and retained receipts under review.

`P0-1` records the claim boundary and decision register. It does not wait for
new implementation. The separate customer evaluation-candidate decision does
wait for all applicable P0 implementation, artifact, provider, device, and
release gates.

## Goals

1. Give evaluators one coherent supported path instead of asking them to
   assemble development mechanisms.
2. Make every supported platform, topology, API, security choice, workload,
   resource target, and lifecycle behavior exact and testable.
3. Preserve offline-first local publication and durable eventual Event
   transfer across intermittent approved IP connectivity.
4. Include restart-selected `ReceiveOnly` operation without describing it as
   physical radio silence.
5. Bound durable publish-operation mappings honestly without introducing an
   unsafe deletion or key-reuse mechanism.
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
- Online operation-mapping garbage collection, key reuse, generation rollover,
  or unbounded mission lifetime.
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
- the exact Ubuntu, kernel, architecture, filesystem, and device identity;
- enabled direct and controlled-relay paths;
- the acceptance-harness version; and
- the retained receipt bundle and release decision.

A customer annex may reduce node count, remove relay use, reduce payload or
queue limits, select only one listed architecture, tighten resource limits, or
disable an optional behavior. It may not add a platform, carrier, data class,
API, security profile, topology, or lifecycle behavior; weaken authentication,
rollback, isolation, or evidence gates; increase a bound; or convert an
exclusion into support. An expansion requires a new versioned base profile.

The reusable base must first qualify both architectures and all three node
tiers. Only after that qualification may a customer annex deploy one qualified
architecture or a lower qualified node tier. An annex cannot be used to issue
the reusable base when an architecture or tier never passed.

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

| Dimension | v0.1 boundary |
|---|---|
| Device tier | Tier 2 Linux |
| Operating system | Ubuntu Server 24.04 LTS |
| Kernel | The exact Canonical-supported Ubuntu 24.04 kernel package/build named in the signed qualification annex; no blanket claim covers later kernels |
| Architectures | `x86_64` and `aarch64` |
| Init/service manager | `systemd` |
| State filesystem | Local `ext4` |
| CPU available to agent | At least one core |
| Deployment memory | At least 1 GiB |
| Free state capacity at start | At least 256 MiB |
| Packaging | Native `.deb` for each architecture, authenticated by the exact detached-signature or signed-repository method named in the annex |
| Application isolation | Dedicated network namespace shared only by the agent and its intended trusted application |

The artifact runs as a dedicated unprivileged service identity. Application and
health listeners remain loopback-only inside the dedicated namespace. The
deployment exposes no Service, host port, ingress, remote tunnel, or unrelated
same-namespace sidecar. Bearer authentication remains mandatory inside the
namespace.

Containers, Kubernetes, Helm, Zarf, UDS, network filesystems, other Linux
distributions, macOS, Windows, Android, iOS, and MCU targets do not qualify
v0.1. A container image produced by a broader artifact workstream is not a
v0.1 artifact.

## Topology and carriers

- One mission authority, one scope, one topic, and one durable application
  subscription are active in a qualification scenario.
- Supported node-count tiers are exactly 2, 8, and 20.
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

| Tier | Physical nodes | Isolated Ubuntu 24.04 virtual nodes | Required architecture evidence |
|---:|---:|---:|---|
| 2 | 2 | 0 | One physical `x86_64` and one physical `aarch64` node exchange Events |
| 8 | 2 | 6 | Both qualified physical architectures remain participants; the annex records every virtual architecture |
| 20 | 2 | 18 | Both qualified physical architectures remain participants; the annex records every virtual architecture |

Every virtual node receives the profile CPU, memory, and local-ext4 allocation;
host oversubscription and shared-network effects are recorded. The signed annex
names every device/VM, architecture, Ubuntu and kernel package build,
filesystem, peer role, relay placement, and network condition. The 8/20-node
results are mixed physical/virtual evidence, never 8- or 20-device physical
evidence.

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

The candidate Event-service schema does not yet expose emission policy or its
effective status. Those additions are evaluation-blocking follow-up work; the
underlying selected Rust runtime mechanism alone is not a customer profile.

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
development/test tools only. They cannot qualify v0.1. The exact protected
provider is an evaluation-blocking selection owned by the security and
deployment workstreams on 2026-09-08.

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

The candidate Event-service documentation currently promises the original
result without distinguishing post-retirement behavior. Its documentation must
be narrowed to the existing public result above before qualification; no public
error-code change is required for this case.

## Durable publish-operation containment

v0.1 is operationally limited to **1,024 distinct
`PublishEvent.operation_key` values over the lifetime of one state directory,
including all restarts**. The implementation does not enforce this lower
profile boundary. The qualification harness and operator procedure count
distinct accepted keys, stop new publication at 1,024, and end the profile
claim. Keys are 1 through 256 bytes. Exact retries do not consume another
mapping. A key never expires and must never be rebound to a different
publication intent.

The supported 1,024-operation workload is deliberately below both current
store ceilings: 4,096 rows and 512 KiB of aggregate key-plus-record bytes. A
maximum 256-byte key plus a maximum 130-byte mapping record consumes 386 bytes;
1,024 such entries consume 395,264 bytes. Aggregate item/byte quotas can still
stop admission earlier.

This is a supported operational workload boundary, not a new store admission
limit or reclamation mechanism.
At or before 1,024 distinct operations, the evaluation stops new publication
work and preserves the state directory for inspection. Deleting or replacing
that directory is not same-mission capacity recovery and invalidates durability
and restart claims. A later evaluation uses a new mission identity and a fresh
state directory.

Authenticated status must expose operation rows, operation bytes, both store
ceilings, the 1,024-operation profile boundary, and remaining profile headroom.
A warning becomes actionable no later than 512 distinct operations. Reaching
1,024 ends the supported workload even though the store may still accept it.
Exhaustion of the implementation's 4,096-row or 512-KiB mapping store is a
separate Connect `ResourceExhausted` failure with new additive public reason
`PUBLIC_ERROR_REASON_OPERATION_CAPACITY_EXHAUSTED = 12`, `retryable = false`,
and no retry delay. Changing the key or retrying indefinitely is not recovery.
Other aggregate storage pressure retains its separately accurate capacity
guidance.

A full crash-safe generation/retirement lifecycle belongs to `P1-1`. TTL, LRU,
FIFO, or deletion of a bare mapping is prohibited because a delayed retry could
otherwise create a second Event. The lifecycle/capacity owner reopens the
decision after the first retained physical workload on both architectures and
before approving a profile revision above 1,024 distinct operations, any
`P2-2` workload bracket, or any production profile, whichever occurs first.

The review records distinct accepted operations, key-length distribution,
logical operation bytes, database/filesystem growth, reopen time, RSS, CPU,
and intended workload rate/duration. It either retains/lowers this boundary or
selects a monotonic generation/sequence plus durable retirement watermark in
which every late retired retry fails closed.

## Capacity and workload matrix

The strict customer configuration explicitly sets:

- `storage.max_items = 10_000` aggregate logical tracked rows;
- `storage.max_payload_bytes = 67_108_864` aggregate logical tracked bytes;
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

Unless a later profile adds explicit API enforcement, the harness values are
evaluated workload boundaries rather than general runtime admission ceilings.
In particular, 65,536 bytes is not an independently enforced server payload
limit.

The 10,000/64-MiB values are required profile configuration, not generic
production sizing or customer-schema defaults. They include durable Event and
operation rows and exclude redb/filesystem amplification, untracked files,
snapshots, swap, backups, and process memory. Control and emergency reserves
reduce ordinary usable capacity.

The qualification dimensions are not an unconstrained Cartesian product:

| Scenario | Nodes | Payload | Rate/duration | Purpose |
|---|---:|---:|---|---|
| API boundary | 2 | 0, 4 KiB, and 64 KiB | One exact Event at each boundary | Encoding, durable acceptance, transfer, query, delivery, and acknowledgement |
| Small topology | 2 | 4 KiB | 10 Events at 1 Event/s | Direct and optional pinned-relay recovery |
| Intermediate topology | 8 | 4 KiB | 10 Events/node at 1 Event/s | Concurrent progress and bounded status |
| Maximum topology | 20 | 4 KiB | 10 Events/node at 1 Event/s | Maximum peer and burst bracket |
| Offline soak | 2, 8, and 20 | 4 KiB | 10 Events/hour/node for 24 hours | Disconnected publication, restart, later convergence, gaps, and capacity/resource behavior |
| Capacity-warning probe | 2 | 4 KiB | 512 distinct local operations plus one exact retry | Audited operation usage, 50% warning, and retry-without-growth |

The 64-KiB profile boundary is tested as a payload boundary and bounded burst;
it is not sustained at 10 Events/hour across 20 nodes for 24 hours. Every run
starts from a fresh zero-workload state directory, retains controls created by
provisioning, and records final logical and physical headroom. Admission or
convergence past a stated limit is not part of the successful profile.

The agent's compiled request/message ceiling is 1 MiB, but v0.1 makes no 1-MiB
plaintext payload claim because protobuf and protected-envelope overhead also
consume bounded request and mesh-object space.

Hard 4,096-row/512-KiB mapping saturation is exercised only in an isolated
engineering test outside the v0.1 workload, or through a test-only lower limit
that preserves the production transaction path. It validates terminal failure
and exact replay at capacity without expanding the supported 1,024-operation
profile boundary.

After control and emergency reserves, the configured store provides 5,840
ordinary aggregate item slots and 50,266,112 ordinary logical bytes. The
maximum soak projects 5,040 ordinary aggregate items per converged node: 4,800
Events plus 240 local publish-operation mappings. That leaves 800 item slots
before other aggregate-counted rows. Byte fit remains provisional until the
receipts record exact protected source-object bytes and physical database
growth; plaintext payload arithmetic alone is not evidence of fit.

## Resource and lifecycle targets

The following apply to the provider-composed agent on each declared
architecture under the workload matrix:

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

Energy is measured and retained for each physical target but v0.1 sets no pass/
fail threshold. The profile owner reviews the binary, RSS, CPU, startup,
shutdown, storage-growth, and energy targets after device testing on
2026-09-13. A changed target creates a new profile version; a test result does
not silently redefine v0.1.

Startup fails closed before readiness for invalid configuration, credentials,
provider state, mission policy/profile mismatch, or inconsistent durable state.
Same-version process crash and restart reuse the existing state directory and
must preserve durable acceptance, operation mappings, subscriptions, pending
deliveries, acknowledgements, and mission controls.

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
- publish-operation rows, bytes, hard ceilings, profile boundary, and remaining
  profile headroom;
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

The candidate documentation incorrectly groups delivery limits with 1,024-row
query/scan limits; actual delivery pages are capped at 128. v0.1 selects 16 and
the customer reference must be corrected before qualification.

The candidate reference's generic minimum of 4,161 items leaves only one
ordinary item slot even though one idempotent local publication atomically adds
an Event and its operation mapping. Its nominal byte minimum likewise does not
reserve worst-case mapping bytes in addition to a maximum message. Those
generic minima must be corrected or narrowed before they are described as
useful publication capacity. This does not change v0.1's explicit 10,000-row/
64-MiB configuration.

## Artifact and installation contract

Each architecture-specific candidate contains:

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

The reproducible-artifact workstream owns the package mechanics. This design
defines what an artifact must contain to qualify v0.1 and does not duplicate
that workstream's implementation.

## Acceptance and retained evidence

The following are non-waivable gates for any v0.1 evaluation authorization.
The 2026-09-13 meeting is an issue/refuse/defer checkpoint; reaching the date does
not authorize a candidate. An unpassed gate against the exact final artifacts
causes refusal or deferral.

1. A clean, locked source checkout reproduces both packages and their SBOM,
   notices, provenance, and checksums through the approved build path.
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
5. Both architectures pass install, readiness, normal stop, forced process
   loss, same-version restart, upgrade, permitted rollback, and uninstall/state
   preservation scenarios on declared Ubuntu 24.04 targets. The two-node tier
   uses one physical `x86_64` and one physical `aarch64` device. The 8- and
   20-node tiers retain those two physical endpoints and may use isolated
   Ubuntu 24.04 virtual participants for the remaining nodes. Every virtual
   allocation and oversubscription assumption is recorded and cannot be cited
   as physical-device evidence.
6. Rust publishes and consumes through the normative API. Go performs the same
   black-box wire/API recovery path against the Rust server.
7. The 2-, 8-, and 20-node workload matrix passes with the exact environment
   retained. v0.1 defines no generic loss/latency/bandwidth acceptance bracket.
   Optional controlled-relay claims include relay-loss and direct-path
   recovery; direct-only annexes omit the relay claim explicitly.
8. Twenty-four-hour disconnected publication, intervening restart, later
   authenticated convergence, exact gap reporting, at-least-once redelivery,
   acknowledgement, and peerless reopen retain the expected data.
9. `receive_only` passes both carrier-identity orderings without constraining or
   regenerating identities to obtain favorable election, initiates no carrier
   contact, discloses no local Event/control inventory, accepts inbound Events,
   exposes its effective mode, and retains mandatory response traffic as an
   explicit non-silence limitation. Failure requires an implementation fix or
   refusal of v0.1.
10. Operation and storage headroom remain within the profile boundary; exact
    retry, changed-intent conflict, implementation-cap saturation,
    crash/reopen, and warning behavior are retained. Existing component tests
    retain the post-retirement `ExpiredOrRetired` invariant; v0.1 claims no
    black-box retirement trigger because its API exposes neither finite TTL nor
    Event-content deletion.
11. RSS, CPU, executable size, startup, stop, state growth, and energy are
    measured on each architecture. Every thresholded target passes; energy is
    reported without a pass/fail claim.
12. Packet/log/error inspection finds no forbidden plaintext or credentials
    within the stated metadata budget.
13. The release owner verifies every artifact/evidence digest, open-gate
    disposition, exact dependency graph, and customer annex before issuing a
    signed evaluation decision.

Receipts distinguish same-host software tests, virtual/network-namespace tests,
and physical-device observations. Existing one-host and generated-Go receipts
remain bounded implementation evidence; they do not become physical,
independent-server, supported-package, protected-provider, or release evidence.

## Requirement and decision register

Creating this profile changes no requirement evidence status. The exact
requirements trace remains hash-bound and conservative. A later implementation
or retained-evidence PR updates only IDs whose actual evidence boundary moves.

### Resolved for v0.1

| Decision area | v0.1 disposition |
|---|---|
| Data classes | Event only; State, Record, and Blob excluded |
| Priority count/names (`DM-14-01`, `DM-14-02`) | Preserve the four protocol/API values; names are stable API tokens, not a claim of customer doctrine validation |
| Offline target (`DM-14-03`) | 24 hours at the exact 4-KiB, 10 Events/hour/node workload |
| Link rate/loss (`DM-14-04`, `DM-14-05`) | No minimum rate or maximum loss claim in v0.1; exact test conditions are reported |
| Blob floor (`DM-14-06`) | Inapplicable because Blob is excluded |
| Binding count/choice (`DM-14-07`, `DM-14-19`) | Rust reference client first; Go client remains required profile qualification; no complete-MVP binding-count claim |
| Integration/sample targets (`DM-14-08`, `DM-14-09`) | No one-day or line-count acceptance claim in v0.1 |
| Tier 1 (`DM-14-10`, `DM-14-11`) | Inapplicable |
| Tier 2 binary/RAM/working set/core (`DM-14-12..16`) | 16-MiB executable, 64-MiB steady RSS, 128-MiB peak RSS, one core; measurements use the maximum-topology final audited store composition of 4,800 Event rows, resulting local operation mappings, and documented control/reserve use within the 10,000-row/64-MiB aggregate cap; no complete-MVP 10,000-metadata-item working-set claim |
| Nodes and bridges (`DM-14-17`, `DM-14-18`) | Exactly 2/8/20 node tiers; bridged scale excluded |
| Standards and buy/build (`DM-14-20`, `DM-14-21`) | Decisions 0025 and 0028 resolve the selected composition for v0.1 only; they do not close complete-MVP or production-wide standards/build-buy work |
| FIPS (`DM-14-22`, `DM-14-23`) | Explicitly non-FIPS; validated-module disposition remains production-blocking |

Applicable Event, offline delivery/deduplication, priority/custody, security,
agent/API, Linux/resource, and version/downgrade requirements constrain the
profile. A v0.1 claim does not by itself complete `DM-11-01`, `DM-11-03..05`,
`DM-11-12`, `DM-11-15`, `DM-12-01..11`, `DM-13-03`, or `DM-13-05..08`, nor
any cross-class, BTLE, independent-implementation, complete-MVP, or production
deliverable.

### `DM-8-05` evaluation disposition

`DM-8-05` remains formally open and is not made compliant by a passing
dependency tool. For v0.1 only, dependency/license, legal/compliance, and
release owners may approve the exact locked coordinates:

- `webpki-roots` 1.0.9 under `CDLA-Permissive-2.0`; and
- `webpki-root-certs` 1.0.9 under `CDLA-Permissive-2.0`.

The exception is package-and-version specific, adds no general license
allowlist, requires exact SBOM and third-party-notice inclusion, and fails
closed on package, version, source, checksum, reachability, or license drift.
The `Unlicense` coordinates already recorded by Decision 0028 use an
OSI-approved license and are not the literal `DM-8-05` blocker.

The three owners sign the evaluation disposition no later than 2026-09-08.
This may unblock the exact non-production v0.1 candidate but not a production
profile. By 2026-09-30, the dependency/license and release owners present either
a reviewed normative-requirement disposition or an approved technical
alternative that removes the mismatch before production consideration.

### Open gates and owners

| Gate | Owner | Target | Evaluation blocking | Production blocking | Exit |
|---|---|---:|:---:|:---:|---|
| Select exact protected provider and administration artifact | Security + deployment | 2026-09-08 | yes | yes | Provider contract, version, trust boundary, and lifecycle procedure are accepted |
| Freeze signed qualification annex and exact physical/virtual topology | Profile + integration | 2026-09-08 | yes | yes | Annex names every node's physical/virtual status, architecture, device SKU, Ubuntu/kernel build, filesystem, relay placement, and network conditions |
| Merge/review candidate Event service | Event-service owner | 2026-09-09 | yes | yes | Accepted commit passes clean gate and process suite |
| Add restart-selected `receive_only` config/status | Event-service + node owner | 2026-09-10 | yes | yes | Both-ordering acceptance passes |
| Implement authenticated evaluation-capacity status and accurate operation-map exhaustion | Lifecycle/capacity + Event-service + selected-store/node owners | 2026-09-10 | yes | yes | Audited mapping/item/byte use and profile headroom are reported; hard mapping-cap failures are distinguishable and nonretryable; generated-Go and crash/reopen tests pass |
| Add exact v0.1 validation to the qualification harness | Integration + profile owner | 2026-09-10 | yes | yes | Harness rejects a receipt for every tested configuration or workload deviation while leaving the broader generic schema explicit |
| Deliver the Rust reference client and retain Go contract coverage | API + Event-service owner | 2026-09-10 | yes | yes | Both clients execute the exact v0.1 publish/query/delivery/recovery contract |
| Produce signed reproducible packages for both architectures | Deployment/release owner | 2026-09-10 | yes | yes | Artifact reproducibility and inventory pass |
| Integrate and qualify the protected-provider lifecycle | Security + deployment + integration | 2026-09-11 | yes | yes | Exact packaged provider passes install/load/rotation/recovery/revoke/rekey/destroy tests |
| Run physical target/resource matrix | Integration/physical-carrier owner | 2026-09-12 | yes | yes | Retained per-architecture receipts pass |
| Review pre-frozen capacity/resource targets | Profile + release owner | 2026-09-13 | yes | yes | Every v0.1 threshold passed, or v0.1 is refused and a revised profile is scheduled |
| Resolve `DM-8-05` for production | Dependency/license + release owner | 2026-09-30 | no | yes | Requirement disposition or technical alternative |
| Select operation-mapping lifecycle | Lifecycle/capacity owner | 2026-09-30 or before proposing a profile above 1,024 operations | no | yes | Reviewed P1-1 generation/retirement decision |
| Validate usability-time/sample-size targets | API/product owner | 2026-09-30 | no | yes | Independent adopter study sets accepted targets |
| Complete production-wide standards/build-buy disposition | Architecture + release owner | 2026-09-30 | no, unless a candidate adds an undispositioned dependency or bespoke mechanism | yes | Reviewed production composition closes `DM-14-20/21` |
| Select FIPS/validated-module path | Security/compliance owner | 2026-10-15 | no | yes | Reviewed production-profile disposition |
| Independent server interoperability and security review | Conformance/security/release owners | Before production candidate | no | yes | Independent gates pass against exact production profile |

## Ownership and branch integration

The P0-1 profile owner owns this versioned claim, decision register, and every
owner/date/blocking state above. The Event-service workstream owns runtime
configuration, local authentication, process lifecycle/health, token reload,
sanitized public errors, and black-box process acceptance. The lifecycle/
capacity workstream owns operation-mapping containment and later reclamation.
The provisioning workstream owns the protected provider and credential
lifecycle. The deployment workstream owns systemd, namespace isolation,
packages, architecture execution, and artifact acceptance. The physical-
carrier/integration workstream owns physical devices, network conditions,
energy, and ReceiveOnly traffic evidence. Security and release owners qualify
only the combined exact profile.

The Event-service branch is a candidate dependency, not current supported
behavior. Its strict config, generated client, lifecycle/error contract, and
process receipts enter v0.1 only after merge onto the profile baseline and a
clean execution of the pinned repository and process gates. Protected
provisioning, packages, namespace/service-manager acceptance, physical devices,
security review, and release authorization remain separate gates after that
merge.

The profile document may merge independently as a new file. Until the Event-
service branch merges, no other lane edits its agent, protobuf/generated-client,
selected-node runtime, customer-documentation, or process-harness files. The
emission/capacity increment is either reviewed inside that branch before its
accepted baseline freezes or begins only after that branch merges. Artifact and
device lanes may prepare tooling in parallel, but qualification starts only
from the frozen post-follow-up source/API commit. Store/application statistic
preparation has less file overlap, but its live status integration remains
serial with the Event-service work.

## Schedule to the evaluation decision

Qualification follows this serial gate chain even when preparation happens in
parallel:

1. **G1 — Event baseline:** accept the Event-service baseline and freeze the
   emission/capacity contract.
2. **G2 — Source/API freeze:** merge ReceiveOnly and capacity behavior, pass
   focused tests, and freeze one source/API commit.
3. **G3 — Artifact freeze:** reproducibly build and sign protected-provider-
   composed packages for both architectures from G2.
4. **G4 — Focused target tests:** pass install, lifecycle, Rust/Go API,
   ReceiveOnly, and direct/optional-relay scenarios using the unchanged G3
   artifacts.
5. **G5 — Workload qualification:** run the 2/8/20-node and 24-hour scenarios
   from G3. Scenarios may run concurrently only when the signed hardware/
   virtual inventory distinguishes every participant.
6. **G6 — Disposition:** review receipts and rerun deterministic gates, then
   issue, refuse, or defer the exact G3 artifact set.

The dates below are aggressive earliest targets, not authority to skip a gate:

| Date | Delivery | Primary owner | Exit signal |
|---:|---|---|---|
| 2026-09-07 | Review written v0.1 design and prepare the profile/decision register | Profile/architecture | Review comments resolved; no evidence statuses moved |
| 2026-09-08 | Select protected provider, sign exact `DM-8-05` evaluation disposition, and accept P0-1 | Security, deployment, dependency/license, release | P0-1 claim boundary and its blocking decisions are accepted |
| 2026-09-09 | Complete Event-service review and freeze ReceiveOnly/capacity follow-up contract | Event service, node, lifecycle/capacity | G1 passes |
| 2026-09-10 | Complete G2, then produce the G3 packages if the source/API commit is frozen | Event service, node, deployment, security | G2 and G3 pass; otherwise later gates do not start |
| 2026-09-11 | Run G4 and start every required 24-hour G5 soak no later than this date | Integration/physical carrier, security | G4 passes and each soak starts from a recorded clean boundary |
| 2026-09-12 | End the 24-hour disconnected publication window, restore approved paths, and begin bounded convergence/evidence review | Integration/physical carrier, release | Publication stops; convergence proceeds from unchanged G3 artifacts and state |
| 2026-09-13 | Finish G5 within its 24-hour convergence window, then perform G6 and review pre-frozen targets | All owners; release decides | Signed issue/refuse/defer disposition; issuance occurs only if every non-waivable gate passed before 2026-09-14 |

The deterministic-gate, artifact, device-harness, and provider owners may
prepare independently, but source/API integration and qualification remain
ordered by G1 through G6. A failed 24-hour scenario cannot be replaced by a
shorter test; it causes refusal or deferral at G6. The profile does not pull a
full operation-mapping lifecycle, production observability, multi-network
supervisor, controlled-relay server hardening, or broader data classes into
this schedule.

The controlled-relay path is the only optional claim; omitting it produces a
direct-only annex and removes every relay claim and relay test. Non-waivable for
the reusable base are exact profile/suite `0x0001`, protected provisioning,
loopback authentication and namespace isolation, operation containment and
accurate failure guidance, ReceiveOnly, the accepted Event API and generated-Go
contract test, deterministic source gate, `x86_64`/`amd64` and
`aarch64`/`arm64` packages and physical target acceptance, all 2/8/20 tiers,
the exact v0.1 `DM-8-05` disposition or removal of that mismatch, artifact/
receipt integrity, and release-owner signature. Missing any one refuses or
defers the base.

## Consequences and claim boundary

- Evaluators receive one precise Linux/Event product slice rather than a broad
  claim based on unrelated mechanisms.
- The maximum soak projects 5,040 ordinary items against 5,840 available
  ordinary slots. Its 800-slot margin and byte fit remain qualification gates,
  not production sizing evidence.
- The 1,024-operation lifetime boundary is safe for maximum legal operation
  keys and leaves margin over the 240-operation offline workload, but it is not
  a production lifetime or reclamation solution.
- Restart-selected ReceiveOnly satisfies the bounded receive-only use case but
  deliberately does not use the words radio silence or zero transfer.
- Rust is the first reference client and Go remains a required API/client
  acceptance lane without being misrepresented as an independent server.
- Physical-device results may cause a versioned target revision after review;
  they never silently broaden existing evidence.
- v0.1 authorizes evaluation only after its gates pass. It moves no requirement
  evidence status, closes no complete P1/P2/P3 capability, and authorizes no
  customer production release.
