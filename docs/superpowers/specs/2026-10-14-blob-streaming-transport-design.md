# Clean Room — Privileged

# Blob Streaming and Automatic Transport Selection Design

Date: 2026-10-14

Amended: 2026-10-15 after review of PR 71 at `c17213a50a59` and PR 47 at
`04de641bfb3d`

Status: approved amended specification; ready for implementation handoff

## Purpose

Aster's selected Blob network profile cannot transfer operationally large
objects efficiently. Customer testing of an approximately 800-MB to 1+-GB
Blob between a UAS and a Jetson ground node estimated 107 minutes and did not
finish. Main still settles one 16-KiB carrier range at a time. PR 71 improves
that protocol boundary by carrying as many as 64 such ranges in one receipt-free
ordered turn, but it still moves at most 1 MiB per direction/contact and performs
durable append work at the legacy range unit. A 1-GiB Blob still requires at
least 1,024 successful contacts and 65,536 range appends before accounting for
retries. Increasing one local buffer or adopting that bounded turn unchanged
does not meet the large-object goal.

This design adds a versioned Aster streaming protocol, implements its first
profile for Blob, and adds automatic selection of one usable transport at a
time. It preserves source authentication, encrypted carriers, bounded memory,
durable restart, peer-neutral progress, lifecycle policy, and atomic visibility.
The framing and flow-control substrate is intentionally reusable by Event and
other data-class profiles, but this increment enables Blob only.

## Design authority and composition

This design is derived from and remains subordinate to:

- `data-mesh-requirements.md`, including immutable chunked resumable Blob
  transfer, transport abstraction, transport-blind public APIs, source
  authentication, bounded Tier-2 resources, independent interoperability, and
  mixed-version behavior;
- `docs/protocol.md`, which is authoritative for the currently selected
  semantic versions and their byte-exact legacy behavior;
- Decision 0010's source-bound encrypted-carrier and peer-neutral staging
  model; and
- PR 71, `perf: speed up Blob transfers using multi-range transfer`, observed
  non-draft with green required CI at head
  `c17213a50a598b85c3fe672b7195a03b476b07ab`, for semantic-v7 profile `4`
  `BlobRangesStreamV1`, the canonical range schedule, contextual protection,
  ordered additional uni-turn, bounded interruption recovery, Python
  conformance vectors, fault tests, and benchmark harness; and
- draft PR 47, `feat: integrate Blob storage lifecycle policy`, observed with
  green required CI at head
  `04de641bfb3d647290ffffabe40ec284d9865a95`, which contains that exact PR 71
  head through signed merge `12c7c93d2cc0` and is authoritative for
  semantic-v8 finite-TTL custody, pending-source roots, bounded leases,
  deletion fences, retention, pressure eviction, physical reclamation, and the
  public Rust lifetime API.

PR 47 remains authoritative for Blob lifetime and reclamation. This design
changes the new-version network progress unit from one 16-KiB carrier range to
one bounded streaming storage extent. It does not weaken PR 47's rule that a
whole-Blob operation must not acquire an unbounded lifetime lease.

The allocation baseline is now fixed by those two PRs: profile `3` remains
reserved for the earlier `BlobCustodyV1` design, profile `4` is
`BlobRangesStreamV1`, semantic v7 uses profile 4 for durable-only transfer, and
semantic v8 uses the same raw range stream with authenticated finite-TTL
custody. PR 47 derives runtime policy from the authenticated
`(semantic_version, profile_id)` pair. This design therefore allocates semantic
version `9`, transfer-profile ID `5` (`BlobStreamV1`), and mechanics tags
`0xd6..0xdc`, all unassigned in the reviewed heads. It does not reinterpret or
rewrite semantic-v7/v8 profile-4 bytes.

PR 71 is a valuable compatibility baseline but does not satisfy this design by
itself. It requires both peers to upgrade, schedules at most 64 existing
16-KiB ranges (1 MiB) per direction/contact, retains the 64-MiB/1,024-chunk
network ceiling and 16-KiB append unit, and adds no absolute byte credit,
cumulative durable checkpoint, fresh attempt binding, Aster-level transport
selector, or 1-GiB evidence. PR 47 correctly composes lifecycle checks with
that range stream, but intentionally retains the same size and scheduling
bounds. The new profile reuses those reviewed source, custody, carrier,
ordered-turn, lifecycle, fault-test, conformance, and benchmark foundations
while replacing only the large-transfer data/flow-control layer.

Because PR 47's `BlobCustodyClaimV1` is cryptographically fixed to semantic v8
and profile 4, profile 5 does not reinterpret those bytes. Semantic v9 defines
`BlobCustodyClaimV2`: the same approved lifetime, cumulative-age, priority,
publication, source-transfer, and physical-lineage semantics, but with a new
canonical version/domain that binds semantic v9, profile 5, the profile-5
session transcript, and its transfer identity. The Store continues to own the
age and lifecycle decision; the new claim is only authenticated transport of
that authority.

## Goals

The implementation must:

1. transfer 800 MiB through at least 2 GiB without stop-and-wait scaling;
2. use the available transport, storage, and crypto pipeline efficiently;
3. keep memory and metadata bounded independently of Blob length;
4. resume after transport loss or process restart from durable verified
   progress;
5. select a transport automatically without exposing transport choice through
   the Blob application API;
6. use only one data-carrying transport per logical transfer at a time;
7. fail over to another eligible transport without changing Blob semantics;
8. preserve exact source, publication, variant, policy, custody, and settlement
   bindings;
9. preserve complete-content verification and atomic promotion; and
10. define a class-neutral stream substrate that a later Event profile can use.

## Non-goals

This increment does not add:

- simultaneous multipath striping;
- speculative duplicate data transfer;
- selective out-of-order resume maps;
- cross-peer swarming or erasure coding;
- compression;
- route-only Blob custody;
- Event-profile activation;
- a transport selector in the public Blob API;
- healthy-stream migration merely because another path may have become faster;
  or
- a fixed wall-clock promise for every device and network.

## Considered approaches

### Selected: negotiated streaming protocol with cumulative durable progress

Semantic v9/profile 5 adds one long-lived, authenticated Aster stream that
transfers many bounded extents under
receiver-issued byte credit. The receiver acknowledges cumulative durable
progress rather than settling each carrier range independently. Transport
failure reopens the same logical transfer on another eligible transport and
resumes from the receiver's durable checkpoint.

This corrects the RTT amplification at the protocol boundary, preserves bounded
storage work, and provides a reusable substrate for other data classes.

### Rejected: implementation-only batching under the existing wire protocol

Larger buffers and fewer local redb transactions could reduce CPU and storage
overhead, but the protocol would still require one range exchange per contact
and one request/response stream per operation. Independent implementations
would retain the stop-and-wait behavior, and the public protocol would still
cap large objects.

PR 71's multi-range protocol removes per-range application receipts and
amortizes up to 64 legacy ranges on one ordered turn. Its now-green conformance,
fault, and benchmark evidence makes it the required precursor rather than code
to reimplement. Its 1-MiB contact window, legacy range/store units, compatibility
boundary, and lack of durable credit/checkpoint/failover semantics still leave
the approved 800-MiB-to-2-GiB goal open. Profile 4 is therefore retained as the
v7/v8 baseline, not relabeled as the final large-object profile.

### Rejected: extend semantic v8/profile 4 in place

PR 47 binds semantic v8/profile 4, its contextual AAD, custody claim, durable
provenance, and lifecycle decisions as one authenticated contract. Adding new
credit, checkpoint, attempt, or terminal meanings to that pair would make the
same negotiated version/profile identify two incompatible grammars. A new
profile without a new semantic version would also leave the v8 custody claim's
hard version binding ambiguous. Semantic v9/profile 5 keeps downgrade behavior
explicit and preserves the reviewed PRs byte-for-byte.

### Deferred: multipath or multi-peer parallel transfer

Striping can improve resilience or aggregate throughput, but it requires
selective range state, more complex integrity and credit accounting, fairness
rules, and larger attack surfaces. Single-path streaming with failover addresses
the observed problem with materially less protocol and lifecycle complexity.

## Architecture

Semantic v9/profile 5 separates three responsibilities.

### Authenticated control plane

The existing negotiated session, inventory, signed source, authorization,
policy, and custody model remains authoritative. Before accepting stream bytes,
both endpoints bind:

- semantic version and data-class stream profile;
- authenticated session transcript;
- exchange direction and exact source transfer ID;
- publication identity and `BlobId`;
- content group, content epoch, and physical lineage;
- encoded content length and chunk layout;
- transfer identity;
- semantic-v9 `BlobCustodyClaimV2` digest when finite; and
- a receiver checkpoint generation.

The stable signed source envelope and `ItemCore` do not change. A finite source
must satisfy PR 47's custody admission semantics through a verified v9/profile-5
claim before the receiver requests content.

### Transport-neutral streaming plane

`StreamTransfer` is an Aster protocol exchange, not an Iroh-specific
optimization. It needs only an authenticated, reliable, ordered byte stream
from a transport adapter. It carries bounded extents, cumulative checkpoints,
absolute receive credit, completion, and settlement.

Transport adapters do not interpret publications, Blob identities, custody,
checkpoints, or promotion. Aster owns those semantics above the adapter.

Each attempt is a full-duplex logical exchange even when the carrier exposes
only unidirectional streams. The adapter must provide either one bidirectional
stream or two concurrently open, independently bounded unidirectional streams:
sender-to-receiver data and receiver-to-sender control. Opening a new ordered
turn for each checkpoint is not conforming. Credit replenishment, checkpoints,
backpressure heartbeats, finish, result, and result acknowledgement must remain
live while data is in flight.

### Lifecycle and storage plane

The authenticated source creates one durable pending-source root for the exact
Blob variant. Storage consumes extents incrementally. Each currently processed
storage extent holds a bounded lifecycle lease; the open network stream does
not pin the whole Blob. Complete verification and atomic promotion remain the
only path to application visibility.

## Logical state machine

The receiver's logical transfer progresses through:

```text
SourceAuthenticated
    -> PendingAdmitted
    -> StreamOpening
    -> Streaming
    -> Verifying
    -> Promoted
    -> Settled
```

A retryable transport loss moves `Streaming` back to `StreamOpening`. It does
not create a new pending source or logical transfer. A lifecycle or integrity
terminal outcome moves the pending source through PR 47's appropriate retirement
or fail-closed path.

Only `Promoted` content is visible to ordinary application reads. `Settled`
means the bound terminal result exchange has completed sufficiently for the
sender to advance its durable publication cursor.

## Streaming exchange and allocation

The following semantic-v9/profile-5 frames use mechanics tags `0xd6..0xdc` in
order: `StreamOpen`, `StreamAccept`, `StreamData`, `StreamCheckpoint`,
`StreamFinish`, `StreamResult`, and `StreamResultAck`. Their canonical layouts
and vectors are finalized in `docs/protocol.md` during implementation. Tags are
invalid before semantic v9 and profile 5 is valid only on the Blob lane. The
semantic-v9 current Blob offer is `[5]`; profile 4 is selected only after
semantic negotiation chooses v7 or v8, never as an in-session downgrade from a
partially opened profile-5 transfer.

### `StreamOpen`

The sender proposes one transfer attempt. It binds:

- stream profile (`Blob` in this increment);
- semantic version and session transcript;
- exchange and direction;
- logical transfer and source transfer IDs;
- exact publication and physical variant;
- total encoded length;
- attempt nonce;
- receiver checkpoint generation known by the sender, if any; and
- custody-claim digest when required.

Every transport attempt uses a fresh nonce and transcript binding. Frames from
an earlier attempt cannot authorize the new attempt.

### `StreamAccept`

The receiver returns:

- its authoritative durable contiguous offset;
- the checkpoint generation;
- the absolute maximum offset the sender is currently allowed to transmit; and
- the receiver-selected maximum extent length and checkpoint-batch byte limit
  for this attempt.

The durable offset must be within the declared encoded length, aligned to a
verified storage boundary, and consistent with the exact pending source. A
generation, identity, layout, or offset contradiction fails closed.

### `StreamData`

Each data frame carries:

- attempt-bound sequence information;
- an explicit starting offset; and
- a bounded extent of carrier bytes.

Offsets are contiguous in the first profile. The receiver rejects gaps,
overlap above the durable checkpoint, length overflow, or bytes beyond the
absolute receive limit. A duplicate below the durable checkpoint may be
discarded only after its attempt and transfer bindings are validated.

The extent is a network/storage scheduling unit, not a new cryptographic Blob
identity unit. One extent may contain multiple existing encrypted content
chunks. Existing content integrity remains authoritative.

### `StreamCheckpoint`

The receiver reports:

- a cumulative durable offset;
- the matching checkpoint generation; and
- a new absolute receive limit.

Absolute limits, rather than reusable credit deltas, make duplicate or reordered
checkpoint frames incapable of granting additional capacity. The durable offset
never moves backward.

While credit remains unchanged, the receiver may emit a freshly
sequence-protected `StreamCheckpoint` with the same offset and limit as an
authenticated control heartbeat. It grants no capacity. Heartbeat cadence and
liveness deadlines remain bounded and configuration-owned.

The receiver emits checkpoints after a bounded byte threshold or bounded timer,
not after every extent. Storage and metadata are committed in batches. A crash
may discard the uncheckpointed tail, which the sender retransmits, but it cannot
expose or acknowledge unverified nondurable progress.

A checkpoint batch contains one or more complete, verified carriers assembled
from one or more extents. The initial defaults are a 4-MiB byte threshold and a
250-ms timer, with an 8-MiB hard maximum; constrained receivers may advertise a
smaller batch. One files-first durability operation and one redb transaction
commit all chunk markers, counters, and the cumulative checkpoint for the
batch. The maximum crash-retransmission tail is the lesser of the advertised
receive window and advertised checkpoint-batch limit.

### `StreamFinish`, `StreamResult`, and `StreamResultAck`

After sending the declared length, the sender transmits `StreamFinish` bound to
the exact final offset and attempt. The receiver:

1. flushes the final durable checkpoint;
2. verifies exact length and complete content integrity;
3. rechecks source, authorization, policy, TTL, deletion fences, and lifecycle;
4. atomically promotes the pending source; and
5. returns the bound terminal `StreamResult`.

`StreamResultAck` makes settlement retryable and idempotent. The sender advances
its publication cursor only after the direction's complete bound settlement.
Duplicate finish, result, or acknowledgement frames cannot repeat promotion or
advance a different cursor.

## Flow control and bounded memory

The receiver owns flow control. It grants an absolute byte limit based on:

- available global streaming-buffer budget;
- per-transfer fair share;
- storage-worker capacity;
- lifecycle-lease capacity;
- outstanding uncheckpointed bytes; and
- local shutdown or maintenance state.

The sender may keep multiple extents in flight up to that limit. An unchanged
limit is ordinary backpressure, not an error.

Extent length and window size are negotiated downward from local limits. A
constrained receiver may advertise small values. The initial resource profile
uses extents no larger than 1 MiB, while the implementation retains a strict
parser/allocation bound before reading peer-controlled payload bytes. A small
fixed header permit is acquired before reading the bounded frame header; after
validating its canonical length, a body permit for that exact length must be
reserved from the global budget before reading or allocating the body. Header
permits, body permits, queued records, session state, and checkpoint batches
are all globally and per-session bounded. Every success, rejection, close,
cancellation, and panic-unwind path releases its permits. The sum of all live
stream buffers is governed by one configurable global budget, not a
per-transfer allocation multiplied without bound by session count.

The data path writes incrementally and must not buffer an advertised full Blob
or full transfer window in RAM. Whole-Blob length has no linear relationship to
resident memory.

## Durable resume

The first profile persists a contiguous verified prefix, not a selective range
bitmap. The ordered stream and cumulative checkpoint make this sufficient and
keep resume metadata constant-sized per pending transfer.

On reconnect or restart:

1. the sender opens a fresh attempt for the same logical transfer;
2. the receiver authenticates the binding and loads the pending source;
3. the receiver returns its durable offset and new generation in
   `StreamAccept`; and
4. the sender begins at that offset.

The receiver's durable offset is authoritative. The sender does not infer
progress from bytes written to a failed transport. Retransmission is bounded by
the last uncheckpointed tail.

A different eligible peer may continue an exact pending source from the same
durable prefix when existing Aster source, variant, authorization, custody, and
peer-neutral carrier rules allow it. Changing peer does not change publication
age or reset finite TTL.

A profile-4 pending source is not reinterpreted as profile 5. It may preserve
its already verified carrier bytes only through an atomic provenance upgrade:
the receiver authenticates an exact v9/profile-5 source and, for finite work, a
non-younger `BlobCustodyClaimV2`; verifies the same publication, transfer,
variant, layout, and physical lineage; then replaces the version/profile
provenance and creates a fresh profile-5 checkpoint generation in one Store
transaction. Failure leaves the profile-4 pending source unchanged. After the
upgrade it cannot downgrade. If those exact conditions are not met, the bytes
remain profile-4 work and no profile-5 checkpoint is inferred from them.

## Automatic transport selection

Transport selection is an internal local policy. Candidate support and peer
locators must be known before opening a data attempt, from authenticated local
configuration, provisioned peer records, or authenticated discovery. They are
not advertised for the first time inside `StreamOpen`, because that is already
carried by the selected transport. A peer cannot assign local scores or force a
choice. After connection, normal Aster mission authentication and semantic/
profile negotiation confirm the candidate before any Blob credit is issued.

The first selector:

1. intersects locally enabled adapters with authenticated peer capabilities;
2. removes transports prohibited by configuration or policy;
3. prefers an already healthy authenticated connection;
4. otherwise attempts candidates in configured priority order; and
5. uses the first candidate that establishes a usable stream within its
   connection deadline.

Only one selected transport carries data for a logical transfer at a time.
Connection establishment may use an adapter's own direct/relay discovery, but
Aster does not duplicate Blob data speculatively across candidates.

An adapter exposes:

- peer reachability and bounded connection establishment;
- authenticated peer identity;
- a reliable ordered byte stream;
- close/error notification; and
- sanitized progress/health signals.

Current Iroh direct/relay management may remain one adapter if Iroh owns that
path choice internally. The Aster selector chooses among independently usable
adapters, not internal implementation details it cannot safely control.

Delivery is staged without weakening the final claim boundary:

1. **Streaming/performance milestone:** ship profile 5 and the selector seam
   with `IrohQuicV1`. This automatically selects the only eligible production
   adapter and may reopen it after failure, but it does not demonstrate or
   claim cross-transport selection or failover. Fake adapters test policy only.
2. **Automatic-transport milestone:** register and qualify a second
   independently usable production adapter that satisfies the same
   authenticated reliable full-duplex stream contract. Only this milestone may
   claim best-available selection and cross-transport failover.

The existing `aster-ip::IpLink` and `aster-ble::BleLink` are packet links, not
such streaming adapters. They may become candidates only after a separately
reviewed reliability/ordering/flow-control adapter exists; this design does not
silently relabel them as production stream transports.

## Transport failure and failover

A transport attempt is failed when it closes, reports an unrecoverable adapter
error, cannot open before its deadline, or makes no byte/checkpoint progress for
the configured stall interval while the sender has positive credit. The data
stall timer is suspended while the sender is credit-blocked. During
backpressure, authenticated control heartbeats and adapter liveness remain
bounded and observable; exceeding their separate liveness deadline may retry
the attempt. Prolonged healthy zero-credit capacity is backpressure and may
become `temporary/deferred capacity`, never a fabricated transport failure.

On failure Aster:

1. closes the failed attempt;
2. keeps the pending source and logical transfer;
3. selects the next eligible transport;
4. performs fresh peer/mission authentication and semantic/profile negotiation
   on that transport, binding the authenticated peer identity to the expected
   source peer;
5. creates a fresh attempt nonce and session-transcript binding;
6. for finite work, verifies a fresh `BlobCustodyClaimV2`, merges observed age
   monotonically, and rejects any younger or mismatched claim;
7. obtains the receiver's authoritative durable checkpoint only after those
   checks; and
8. retransmits from that checkpoint.

Failover does not change semantic version, source, publication, custody age,
Blob variant, or lifecycle state. A profile-5 pending source never resumes
through profile 4 or the historical legacy lane. Profile 4 is used only when
semantic negotiation selected v7 or v8 before profile-5 admission. A finite
Blob cannot downgrade to a version that lacks its custody semantics.

Successful and failed connection observations may reorder candidates for later
transfers. The first implementation does not interrupt a healthy stream solely
to chase a potentially faster path.

## Blob lifecycle integration

PR 47's lifecycle rules apply throughout streaming:

- source authentication and semantic-v9 `BlobCustodyClaimV2` admission precede
  content credit;
- the pending source is a durable GC root;
- a bounded storage extent holds a typed lifecycle lease only while accessed or
  committed;
- TTL and policy are rechecked before granting new credit or admitting the next
  extent;
- an already admitted bounded extent may finish;
- final promotion repeats exact policy, lifetime, content, and deletion-fence
  checks;
- valid durable pending work has no inactivity timeout;
- strict-lower-priority pressure eviction may retire an incomplete transfer;
  and
- structural contradictions fail closed and preserve evidence.

Retirement stops new credit. Expiry, invalidation, or pressure eviction returns
a typed terminal result and follows the lifecycle design's authorized logical
retirement and physical reclamation. A `DeletePending` race returns the
specified retryable lifecycle/capacity outcome; streaming cannot attach a new
root after the deletion fence wins.

This design does not replace PR 47's profile-4 bounded-unit contract. It adds a
semantic-v9/profile-5 bounded unit: one receiver-bounded streaming storage
extent whose complete carriers are committed through a cumulative checkpoint
batch. PR 47 remains authoritative for the lease, TTL, pressure, retirement,
deletion-fence, and reclamation decision around each bounded operation.
Semantic v7/v8 retain their 16-KiB append and 64-range turn behavior
byte-for-byte.

## Storage and large-Blob profile

Three units remain distinct:

1. **Cryptographic/storage chunk** — existing encrypted integrity and depot
   unit.
2. **Streaming extent** — bounded network and storage scheduling unit that may
   contain multiple chunks.
3. **Checkpoint batch** — complete verified carriers collected from one or more
   extents and committed together in one files-first durability operation and
   one metadata transaction.

The implementation must not create durable metadata per wire frame. Pending
stream checkpoint state is constant-sized. Existing physical chunk rows remain
proportional to the content layout, and their configured limits must admit the
large-Blob profile.

The new grammar represents lengths and offsets with checked bounded 64-bit
values and removes the current semantic 64-MiB ceiling. Local policy still
defines a maximum accepted Blob length. Before accepting content, admission
checks and reserves:

- total physical bytes;
- expected chunk rows;
- variant and pending-source rows;
- checkpoint and operation metadata;
- lifecycle and replay-fence capacity; and
- sufficient local storage under existing quota policy.

The initial conformance profile must accept an encoded Blob of at least 2 GiB
when configured storage quota permits. Every length, offset, chunk-count, and
quota calculation uses checked arithmetic. Admission returns distinct typed
outcomes for configured size rejection, policy rejection, temporary capacity,
and deletion conflict.

Defaults sized around 64 MiB or 1,024 chunks must be revised or made
proportional. A conforming 2-GiB transfer cannot fail merely because an
unrelated legacy default retained the old ceiling.

## Security invariants

- The signed source and exact physical lineage remain authoritative.
- The stream profile, semantic version, session transcript, exchange,
  direction, transfer, publication, variant, attempt nonce, length, and custody
  claim are bound before content is accepted.
- A fresh attempt binding prevents cross-attempt replay.
- Peer-controlled lengths are validated before allocation or file access.
- Data beyond issued credit is rejected without growing local resource use.
- Canonical encodings reject duplicate fields, non-minimal integers, unknown
  required values, and trailing material.
- Transport authentication does not replace end-to-end Blob integrity.
- Complete variant verification precedes atomic promotion.
- Duplicate messages cannot increase credit, reduce custody age, repeat
  promotion, or settle another transfer.
- Structural store or accounting contradictions are never converted into
  ordinary absence, expiry, or retry.
- Status and logs expose no raw paths, credentials, peer-controlled strings, or
  unbounded attempt history.

## Errors and terminal outcomes

Protocol-visible outcomes distinguish:

- `Completed`;
- unsupported semantic version or stream profile;
- configured object-size rejection;
- authorization or policy rejection;
- temporary/deferred capacity;
- lifecycle expiry, invalidation, or pressure eviction;
- content-integrity failure;
- structural store failure; and
- protocol violation.

Backpressure is expressed by unchanged credit. Transport closure, connection
failure, positive-credit data stalls, and control-liveness expiry are local
retry/reopen or failover conditions and do not by themselves retire the logical
transfer. Zero-credit data inactivity is not a stall.

Integrity failures confined to authenticated pending content use PR 47's exact
authorized cleanup path. Structural metadata, accounting, lineage, owner, or
capability contradictions fail closed and retain evidence.

## Mixed-version behavior

Semantic v1 through v8 remain byte-identical. In particular, PR 71/47's
profile-4 schedules, 64-range bound, contextual domains, custody claims, and
version-derived durable/finite policy do not silently change.

- v9/v9 selects semantic v9 and Blob profile 5.
- v9/v8 selects semantic v8 and profile 4, retaining authenticated finite-TTL
  custody and the bounded range stream.
- v9/v7 selects semantic v7 and profile 4, retaining durable-only bounded range
  streaming.
- v9 with v6 or older follows the existing post-PR-71 compatibility boundary;
  it emits no v9 frame and does not revive the removed selected-runtime Blob
  carrier as an implicit fallback.

Once a profile-5 pending source or attempt is admitted, it is never resumed or
promoted under profile 4. Negotiation or policy failure occurs before profile-5
carrier I/O. Finite publications remain subject to PR 47's authenticated
custody and may not downgrade to a semantic version that cannot represent it.

An implementation that supports semantic v9 must publish independent
canonical frame vectors and state-machine conformance cases. Same-version
independent implementations must interoperate without relying on shared Rust
types or Iroh internals.

## Public API and status

The Blob publish, query, and read APIs remain transport-blind. PR 47's approved
TTL options and tagged retirement results remain the lifecycle surface consumed
by this increment. The existing file-based publish shape remains, but its
64-MiB implementation ceiling becomes a checked configurable large-object
policy that admits at least 2 GiB when Store quota permits. Applications cannot
select a transport, extent size, checkpoint cadence, or resume offset.

Bounded sanitized application-visible transfer status includes only:

- logical transfer state;
- total and durable bytes;
- rolling payload throughput;
- a sanitized terminal lifecycle, capacity, connectivity, integrity, or
  protocol category.

Transport identity, candidate ranking, attempt count, receive credit,
checkpoint offsets, retransmission, checkpoint latency, commit count, and
failover recovery are internal/operator telemetry. They may be exported through
bounded privileged diagnostics and metrics, but never through the public Blob
application API or application-selectable controls.

Attempt history is aggregated under a fixed bound. Status makes no global
convergence claim and contains no raw paths or peer-provided error text.

## Performance acceptance

The acceptance target is relative to the measured device pipeline rather than
one universal elapsed-time promise.

For payloads of at least 256 MiB on a stable path:

- sustained Aster payload throughput must reach at least 70% of the slowest
  independently measured source-read, destination-write, crypto, or transport
  component under the declared scenario;
- steady-state throughput must not scale as `16 KiB / RTT`;
- database commits must scale with checkpoint batches rather than extent or
  legacy range count;
- resident streaming memory must remain within the configured global budget;
- transport/process recovery must retransmit no more than the uncheckpointed
  tail; and
- 1-GiB and 2-GiB transfers must complete with exact content verification.

Measurements record the component baselines, Aster payload throughput, CPU,
steady and peak RSS, storage growth, transaction count, checkpoint latency,
retransmitted bytes, and failover recovery time. A slow result is attributed to
the measured limiting component rather than hidden behind elapsed time alone.

The customer's unfinished 107-minute UAS/Jetson observation is motivation and
a comparison point, not a qualification environment or acceptance threshold.

## Three-CM4 physical validation boundary

Physical validation uses the previous three Raspberry Pi Compute Module 4
devices:

- `cm4-a`, operator label `rpi4-1`;
- `cm4-b`, operator label `rpi4-2`; and
- `cm4-support`, operator label `rpi4-3`.

All three retain the frozen observed platform: physical CM4 Rev 1.1, `aarch64`,
Raspberry Pi reference image 2026-06-18, Debian 13 `trixie`, kernel
`6.18.39+rpt-rpi-v8`, systemd `257.13-1~deb13u1`, and local ext4 storage.

The existing inventory declares the third device a non-participating spare.
Before candidate Blob traffic, a bounded inventory amendment must assign it the
exact `failure-test/alternate-content-peer` role and name the affected scenario
IDs. Evidence produced before that amendment cannot qualify a three-node run.

All devices use one byte-identical native ARM64 candidate artifact and one
declared configuration set. Each run freezes device roles, available storage,
network path and conditions, artifact digest, configuration digest, start/end
state, and collection procedure.

Required physical scenarios are:

1. **Direct throughput:** transfer 1 GiB and 2 GiB from `cm4-a` to `cm4-b`, then
   in the reverse direction.
2. **Three-node resume:** one node publishes; the support node becomes an
   eligible complete content peer; the receiver makes partial progress from the
   first peer and completes the exact pending source from the alternate peer.
3. **Recovery:** interrupt the selected Iroh path during transfer and prove
   authenticated reopen plus resume from the durable checkpoint. After a
   second production adapter is registered, add a separate cross-transport
   scenario that proves automatic reselection and fresh authentication.
4. **Process recovery:** terminate and restart the receiver during streaming,
   then complete without source re-admission or partial visibility.
5. **Lifecycle races:** exercise finite TTL expiry, policy invalidation,
   pressure eviction, and deletion fencing during active transfer.
6. **Resource observation:** capture throughput, CPU, steady/peak RSS, storage
   growth, database commits, retransmitted bytes, checkpoint latency, and
   failover latency for every participating CM4.

The three-CM4 record validates only this declared Blob streaming increment. It
does not widen earlier Linux Event MVP, route-only relay, production sizing,
platform, carrier, or release claims.

## Automated verification

Unit, property, integration, conformance, and fuzz coverage must include:

- small Blobs and every extent/checkpoint boundary;
- the legacy 64-MiB boundary plus 1-GiB and 2-GiB objects;
- receiver-selected smaller extents and zero/unchanged credit;
- multiple credit/checkpoint cycles on one concurrently open data/control pair
  without reopening it;
- zero credit held beyond the data-stall deadline without false failover;
- transport failure before and after durable checkpoints;
- process failure during receive, checkpoint, verification, promotion, result,
  and acknowledgement;
- duplicate open, data, checkpoint, finish, result, and acknowledgement frames;
- attempt replay and transcript mismatch;
- malicious lengths, offsets, sequences, credit, integer overflow, and
  allocation pressure;
- TTL expiry, policy invalidation, pressure eviction, and deletion races;
- shared physical variants with different publication lifetimes;
- new/new, new/legacy, and legacy/legacy negotiation;
- bounded global memory and lease capacity under concurrent transfers;
- reservation before every peer-controlled body allocation and exact permit
  release on all error/cancellation paths;
- full-capacity reservation and exact release after retirement/reclamation;
- database commit count independent of wire-frame count;
- decoder and state-machine fuzzing; and
- independent canonical-vector decoding.

Netem/path-lab tests vary RTT, bandwidth, loss, disconnect duration, and restart
timing. They prove that windowed throughput follows available byte credit rather
than one legacy range per RTT.

## Existing evidence and new claim boundary

Existing CI and retained evidence establish useful prerequisites but do not
claim this feature:

- semantic-v5 three-node direct-Iroh Blob resume demonstrates authenticated
  peer-neutral pending-source continuation under the legacy bounded carrier
  model;
- current path-lab jobs demonstrate bounded network-condition automation;
- earlier CM4 records establish the physical device identities and observed
  platform; and
- PR 71 at `c17213a50a59` has green required CI, Python/Rust canonical stream
  vectors, bounded live interruption/fault coverage, and a 1-MiB benchmark;
  none of that is 1-GiB or profile-5 evidence; and
- PR 47 at `04de641bfb3d` has green required CI and integrates that exact PR 71
  head with semantic-v8 finite custody, lifecycle enforcement at scheduling,
  service, append/finalization, and terminal settlement, plus the public Rust
  TTL API. It remains draft and its own merge guidance requires PR 71 first.

Design-stage verification relies on the existing CI and retained evidence; this
specification claims no new local full-workspace result. No existing receipt is
relabeled as streaming, 1-GiB-plus, automatic transport-selection, or three-CM4
qualification.

## Implementation boundaries

The implementation plan should preserve these independently testable units:

1. **Protocol model and canonical codec** — class-neutral frames, limits,
   bindings, and vectors.
2. **Stream state machine** — credit, checkpoint, idempotent completion, and
   outcome mapping independent of a concrete transport.
3. **Transport adapter and selector** — supported candidates, connection health,
   deterministic selection, and failover.
4. **Blob stream profile** — source/variant binding, encrypted chunk movement,
   integrity, resume, and promotion.
5. **Store checkpoint API** — batched contiguous progress with checked quota and
   crash recovery.
6. **Lifecycle integration** — bounded extent leases, TTL/policy checks,
   retirement, pressure, and deletion fences composed with PR 47.
7. **Runtime/status integration** — bounded scheduling, metrics, and sanitized
   operator state.
8. **Conformance and path lab** — canonical vectors, fault injection, large
   objects, and performance attribution.
9. **Three-CM4 procedure and receipt schema** — amended third-node role,
   artifact/environment binding, scenarios, measurements, and claim limits.

The plan must start from the final merged PR 71 and PR 47 interfaces, in that
order, or from a reviewed branch containing their exact heads. It must not
carry forward the superseded semantic-v8/profile-4 allocation commits from this
worktree or duplicate a parallel TTL, lease, pressure, deletion, or reclamation
model. If either PR changes before merge, its new exact head and compatibility
effects are re-reviewed before profile-5 implementation resumes.

## Requirement alignment

This design satisfies the original direction by:

- retaining immutable, encrypted, chunked, resumable Blob content;
- extending efficient operation from small data through at least 2 GiB;
- keeping the public API independent of transport selection;
- using a negotiated transport abstraction and recording path characteristics;
- retaining authenticated source and exact-policy enforcement;
- bounding RAM independently of content length and streaming from storage;
- defining independent canonical interoperability artifacts; and
- preserving byte-identical semantic-v1-through-v8 behavior and explicit
  mixed-version rules.

It advances no excluded production, platform-generalization, route-only custody,
physical sanitization, or release-acceptance claim.

## Approval record

The conversational design was approved section by section on 2026-10-14:

- architecture and protocol layering;
- streaming state machine and contiguous-prefix resume;
- automatic single-transport selection and failover;
- PR 47 lifecycle integration and large-object profile;
- wire grammar, security, and error model; and
- performance acceptance using the previous three physical CM4 devices.

The 2026-10-15 amendment incorporates PR 71 at `c17213a50a59` and PR 47 at
`04de641bfb3d`, moves the new allocation from the now-conflicting semantic
v8/profile 4 to semantic v9/profile 5, freezes profile 4 as the v7/v8 baseline,
and requires implementation to stack after those PRs. The amendment and its
replacement implementation plan were approved for handoff on 2026-10-15.
