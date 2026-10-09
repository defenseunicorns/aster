# Blob TTL, Retention, and Garbage-Collection Design

Date: 2026-10-07

Status: Approved for implementation planning

## Purpose

This design adds a complete selected-profile lifecycle for immutable Blob
publications and their shared encrypted content. It extends Aster's common
`Durable | Finite(ttl)` item lifetime policy to Blob, makes interrupted and
abandoned storage reclaimable, and applies the existing strict
lower-priority storage-pressure rule without weakening authentication,
offline-first resumability, or crash recovery.

The outcome is one coherent lifecycle:

- a signed Blob publication owns its lifetime independently of the content it
  references;
- finite publications stop application and network use at authenticated TTL
  expiry;
- durable publications remain live until policy invalidation or explicit
  lower-priority pressure eviction;
- shared encrypted content remains while any valid publication, pending
  transfer, or bounded active operation references it; and
- automatic bounded maintenance eventually reclaims semantic metadata,
  interrupted-transfer state, and physical depot files.

Reclamation preserves two compact kinds of evidence after bulk bytes are gone:

- physical-lineage fences prevent a different ciphertext lineage from being
  substituted under an already accepted `(BlobId, content group, epoch)`; and
- time-bounded publication-retirement records let applications distinguish a
  recently retired publication from one that was never present.

This advances the capability-roadmap outcomes **Causal correctness and bounded
data lifecycle** and **Authenticated resumable Blob movement**. It does not by
itself claim physical-platform, long-partition, route-only Blob custody,
mixed-implementation, large-object resource, or release acceptance.

## Existing boundary

The stable source envelope already encodes optional TTL for every data class.
The selected Blob profile currently rejects any non-`None` TTL, and semantic
v5-v7 Blob transfer is durable-only. Blob publication metadata is stored in
redb, while encrypted chunks are stored in the sibling `blob-depot-v1`
directory. Distinct signed publications may reference one immutable content
variant keyed by `(BlobId, content group, content epoch)`.

Network pending sources and carrier prefixes are deliberately separate from
application-visible publications. Content becomes visible only after exact
source authentication, complete carrier verification, and atomic promotion.
Today, failed local imports, invalidated pending transfers, and unreferenced
depot variants have no complete automatic garbage-collection protocol.

## Scope and non-goals

This design includes:

- durable and finite publication lifetimes;
- authenticated cumulative age for local and replicated finite publications;
- expiry during pending transfer, finalized storage, reads, delivery, and
  serving;
- bounded operation-retirement records;
- automatic staging cleanup and physical content reclamation;
- deterministic strict-lower-priority pressure eviction;
- crash-resumable filesystem deletion;
- compact same-epoch physical-lineage fences;
- bounded, application-visible publication retirement;
- mixed-version finite-Blob withholding and durable fallback; and
- local lifecycle/reclamation status.

This design does not include:

- route-only Blob relay or custody;
- a new wall-clock or trusted-time protocol;
- per-scope Blob storage quotas;
- implicit retention from Blob IDs embedded in opaque Event, State, or Record
  payloads;
- a public imperative `collect_garbage` operation;
- a dedicated Blob-renewal API;
- retirement of publisher replay/high-water state;
- retirement of accepted physical-lineage fences or reuse of their numeric
  content epochs;
- recovery of security-fence capacity through ordinary GC or pressure eviction;
  and
- State and Record finite-lifecycle implementation.

## Lifetime authority and identity

Lifetime belongs to each exact signed Blob publication, identified by
`BlobPublicationId`; it does not belong to `BlobId` or to a physical depot
variant. Several publications may therefore reference identical content while
having different publishers, counters, priorities, scopes, or lifetimes.

The selected profile supports the common lifetime values:

- `None`: durable;
- `Some(ttl_ms)` where `ttl_ms > 0`: finite; and
- `Some(0)`: rejected for local non-tombstone Blob publication.

Blob has no tombstone form in this selected profile. Priority and lifetime are
orthogonal. A durable Blob can be evicted under storage pressure, while a
high-priority finite Blob still expires at its authenticated TTL.

An application-level reference in opaque data is not a GC root. Applications
must publish the referenced Blob with a suitable finite TTL or durable
lifetime. A future explicit pin or lease relationship may add reference
semantics without parsing application payloads.

## Shared lower-bound custody aging prerequisite

Before Blob finite TTL is implemented, the shared custody-age model will be
extended in a separate PR. The current sticky continuity-loss behavior remains
fail-closed for forwarding, but it will continue accumulating a provable lower
bound in later monotonic-clock domains.

The rules are:

1. Within one suspend-inclusive clock domain, elapsed residence is exact.
2. A process restart in the same OS boot retains that domain and includes the
   restart interval.
3. A changed clock ID, tick rollback, missing sample, or arithmetic failure
   permanently marks exact continuity lost.
4. An unmeasurable interval contributes zero to the lower bound and can never
   prove freshness.
5. After loss, a new valid monotonic sample starts another measurable interval.
   Later intervals increase only the durable lower-bound age.
6. The item remains `Indeterminate` and non-forwardable while its lower bound is
   below TTL.
7. When the durable lower bound reaches TTL, expiry is certain and GC is safe.

This shared change applies to Event first and becomes the Blob lifecycle
dependency. It must be based after the internally owned custody-maintenance
PRs #25 and #26 land. No external coordination gate is required.

## Publication lifecycle

The publication state model is:

```text
AuthenticatedPending
    |-- content completes --------------------> Live
    |-- TTL expires --------------------------> Retired(Expired)
    |-- policy becomes invalid ---------------> Retired(Invalidated)
    |-- exact clock continuity is lost -------> IndeterminatePending
    `-- pressure eviction --------------------> Retired(Evicted)

Live
    |-- finite TTL expires -------------------> Retired(Expired)
    |-- strict lower-priority eviction -------> Retired(Evicted)
    `-- exact clock continuity is lost -------> Indeterminate

Indeterminate
    |-- lower-bound age reaches TTL ----------> Retired(Expired)
    `-- otherwise remains hidden and non-transferable

IndeterminatePending
    |-- lower-bound age reaches TTL ----------> Retired(Expired)
    |-- policy becomes invalid ---------------> Retired(Invalidated)
    |-- pressure eviction --------------------> Retired(Evicted)
    `-- otherwise remains hidden and receives no carriers
```

A durable publication never enters `Indeterminate` or `Expired`; it may still
be invalidated or evicted. A finite pending source consumes TTL while its
carrier content is incomplete. Expiry before final promotion retires the
pending source without making it application-visible.

Retired publication bytes are not kept for a post-expiry grace period. Logical
retirement is immediate when the retirement transaction commits; bounded
physical reclamation may finish later.

## Content lifecycle and GC roots

Physical content has a separate lifecycle:

```text
Staging -> CompleteReferenced -> DeletePending -> Reclaimed
```

The exact GC roots are:

- live signed publications;
- valid authenticated pending sources;
- active local-import generation leases;
- all currently admitted bounded read, carrier-range, and internal-chunk
  leases.

Durable deletion/recovery work is not a semantic liveness root. It is the sole
authority to finish already committed reclamation and prevents early removal of
the affected metadata and quota charge.

Each durable root is represented in an exact variant-reference index. Current
bounded leases are tracked by one typed in-process `BlobLifecycleLeaseRegistry`
shared by the storage actor and its workers. Each lease carries a monotonically
allocated generation and exact variant or staging identity. Lease cardinality
is bounded by configured application-page and network-session concurrency plus
the fixed Blob-worker concurrency; acquisition fails with backpressure at that
bound. The registry is intentionally not crash-durable: after process death no
worker from the old process can still access the depot.

A local import acquires its generation lease before creating staging state and
holds it through publication commit or transactional cancellation. GC snapshots
the relevant lease generation, then rechecks it under the lifecycle authority
immediately before the `DeletePending` commit. A variant is eligible only when
no durable root or active lease survives that final check. Retiring one of
several publications never removes shared content still referenced by another
live publication or valid pending transfer.

`DeletePending` is also an atomic admission fence. Every transaction that can
install a publication, pending source, operation/content reference, promotion,
or matching-lineage import checks it. If the deletion transaction wins, no new
root may attach and the operation returns retryable local `VariantDeleting`;
existing mutable-wire versions map that condition to their already supported
`DeferredCapacity` disposition because all variant capacity remains charged.
The caller may retry only after state reaches `Reclaimed` and rebuild or reuse
the matching lineage fence. Deletion is never cancelled after `DeletePending`,
including before the first unlink. If admission wins first, its new root makes
the variant ineligible for `DeletePending`. Actor serialization plus the final
transactional check makes those the only two outcomes.

Local import rows that have neither a committed publication nor an active
local-import generation lease are abandoned staging and are reclaimable during
startup or routine maintenance. Local import has no durable semantic side
effect while bytes are being prepared: its operation-key reservation and lease
are process-local. The single final redb transaction inserts the operation
mapping, consumes the publisher counter, commits the signed source/publication,
and installs its content reference together. Consequently a crash or
cancellation before that transaction leaves only reclaimable staging and the
same canonical intent may retry immediately with the same operation key and
input bytes; no identity is assigned to the uncommitted attempt. After that
transaction the publication is already live and its normal lifecycle applies;
there is no durable precommit `Active` or
`Retired(Interrupted)` state. Valid pending network transfers have no inactivity
timeout. They remain resumable until TTL expiry, policy invalidation, removal of
configured network interest, an authenticated transfer-terminal failure, or
declared pressure eviction.

## Durable records and migration

The Blob store adds or extends the following durable data:

- publication TTL, cumulative custody age, clock checkpoint, and continuity;
- pending-source TTL, custody state, priority, and acceptance order;
- operation state as `Active(publication, canonical_intent_digest)` or
  `Retired(reason, retirement_age, canonical_intent_digest)`;
- publication state as `Live(...)` or a compact
  `Retired(publication_id, publisher, counter, BlobId, topic, scope, priority,
  original_ttl, reason, retirement_generation, retirement_age)` retaining the
  exact fixed-size selection metadata but no source or content bytes;
- an exact reference index keyed by variant and typed owner; and
- a compact physical-lineage fence keyed by
  `(BlobId, content_group, numeric_epoch)`;
- a compact accepted-publication replay fence keyed by publisher dot; and
- a typed per-variant deletion manifest with exact original chunk rows and
  phase, including retry count, next retry checkpoint, and sanitized
  last-failure category.

The lineage fence stores the already authenticated physical-lineage commitment
and its owner/backing binding. It is created transactionally at first accepted
admission and survives publication, pending-source, staging, completed-variant,
and file reclamation. A later import with the same key must match it exactly or
fail with `PhysicalLineageConflict`, including after restart and after all bulk
content was reclaimed. There is at most one fixed-size fence per admitted
variant key.

Lineage fences use a separate security resource, not the active depot
`max_variants` limit. `max_lineage_fences` defaults to 65,536 records and each
canonical record is limited to 256 bytes, with a matching default 16-MiB encoded
byte cap; both limits must admit a new fence. An operator may configure larger
finite limits before open. A migration whose existing accepted lineages exceed
either configured limit fails closed and reports the required minimum instead
of discarding evidence. Ordinary GC and priority eviction release active
variant, chunk, and byte capacity but never this security resource. Once it is
full, a previously fenced matching lineage remains usable, while a new variant
key returns `LineageFenceCapacity` regardless of priority or empty bulk storage.
This is an explicit lifetime admission limit, not a recoverable storage-pressure
condition. Reclaiming it requires a future authenticated content-epoch
retirement design and is outside this work.

The accepted-publication replay fence stores the publisher dot, semantic
`BlobPublicationId`, exact source transfer ID, exact source length, and exact
source-representation digest. It survives publication-retirement expiry and
restart. Post-retirement ingest has exact outcomes:

- same dot, semantic ID, and exact source representation: return the existing
  wire `Duplicate` disposition without recreating publication or pending state;
- same dot with a different semantic ID: fail closed as publisher equivocation;
  and
- same semantic ID with a different transfer ID, length, or exact source digest:
  fail closed as `SourceRepresentationConflict`.

Replay fences have their own configurable 65,536-record and 16-MiB default
security cap. Migration requires configured capacity for every existing
accepted-publication mapping. Like lineage fences, they are not evictable and
new publisher dots return `ReplayFenceCapacity` when full. This preserves the
current invariant rather than treating an accepted dot whose publication was
GC'd as schema corruption.

All new tables have structural bounds rather than best-effort pruning:

- a reference-index row exists one-for-one with a bounded live publication or
  pending source and adds no independent admission authority;
- deletion-manifest chunk rows replace existing committed chunk rows one-for-one,
  cannot exceed the existing `max_chunks` limit, and remain fully charged until
  final variant finalization;
- a retired-publication row replaces, rather than supplements, its live
  publication row; live plus retained rows have a separate configurable
  `max_blob_publication_lifecycle_rows` count cap of 65,536 by default, and
  migration requires a configured cap at least as large as the existing count;
  and
- operation records retain the existing 4,096-record and 512-KiB limits.

Publication-retirement records use the same 45-day conservative retention as
operation-retirement records. New publication admission must account for its
bounded live/retired row and both required permanent security fences in the
single publication commit; a full table returns its typed metadata-capacity
error and does not discard unexpired evidence.

No deletion record contains a caller-supplied filesystem path. Depot paths are
derived only from validated typed identities beneath the fixed depot root.

Existing Blob metadata migrates as durable publication state. No migration may
invent a TTL for an old signed source. Existing operation, import, chunk,
pending-source, carrier-prefix, and quota counters are audited while building
the new indexes. Before any old import or variant row can be deleted, migration
must first derive and commit its lineage fence from the already accepted
lineage and owner/backing evidence. Missing or conflicting evidence is
corruption and fails closed rather than silently dropping a reference or
inventing a fence.

Publisher counter, accepted-publication, and replay/high-water state survives
normal publication and content GC. Its safe retirement requires a separate
authenticated publisher/checkpoint retirement design.

## Transactional retirement and physical reclamation

redb remains the metadata authority. Because a database commit and filesystem
unlink cannot be atomic, reclamation uses two phases.

### Phase 1: transactional retirement

One bounded metadata transaction:

1. selects a bounded candidate page;
2. rechecks custody age, policy, priority, every active lease generation, and
   exact references under the lifecycle authority;
3. replaces each live publication with its compact retirement row and removes
   inventory eligibility and ordinary content references;
4. replaces applicable operation mappings with retirement records and converts
   affected delivery state to retirement delivery state;
5. retires pending carrier prefixes and sources;
6. marks newly unreferenced variants `DeletePending`; and
7. atomically replaces the variant's ordinary committed-chunk view with a
   deletion manifest containing the exact original ordered chunk set, count,
   final root, charge, and per-chunk `DeleteQueued` state before commit.

After commit, retired data cannot be read, delivered, advertised, requested, or
served even if its physical files remain.

### Phase 2: idempotent file reclamation

The depot worker uses explicit durable deletion phases:

1. For each `DeleteQueued` chunk, it opens the existing owner-controlled
   `OwnedDirectory` authority, resolves only descriptor-relative validated
   components with no-follow checks, unlinks the exact file, and treats absence
   as interrupted recovery only because that exact manifest row authorizes it.
2. It durably syncs the containing directory, then transactionally changes that
   retained chunk row to `DeletedDurable`. The row, original identity, manifest,
   and full byte/chunk quota charge remain; no partial deletion releases quota.
3. Only after every original chunk row is `DeletedDurable`, the worker rechecks
   the admission fence and phase, transactionally advances the manifest to
   `DirectoryDeletePending`, removes the now-empty variant directory through the
   same descriptor-relative authority, and syncs its parent directory.
4. A final redb transaction, valid only in `DirectoryDeletePending` with every
   original chunk `DeletedDurable`, removes all retained chunk rows, the
   manifest, and ordinary import/variant metadata and releases all active
   variant/chunk/byte charges together while retaining lineage and replay
   fences.

Private directory/file modes, owner checks, descriptor-relative operations,
and symlink rejection remain mandatory on hardened Unix platforms. The work
does not add a broader non-Unix filesystem-hardening claim; those platforms
retain the repository's existing explicit limitation.

Deletion failure remains manifest-backed, unavailable, visible in status, and
fully charged against capacity. Persistent unlink or fsync failure does not
prevent open when the manifest is structurally valid: writable mode retries
with bounded backoff, while read-only inspection reports the phase and failure
without mutation. No publication, pending source, promotion, or import can
reattach while recovery is stalled. Startup resumes deletion work before
accepting storage that depends on the unreclaimed capacity.

A crash before the retirement commit changes nothing. A crash after that
commit cannot restore visibility. A crash during unlink resumes idempotently.
On open, the depot validates every deletion manifest before its normal
committed-file audit. The manifest must reproduce the original exact chunk
count/set, final root, import/variant binding, and charged totals. A
`DeleteQueued` file may be present or absent because unlink may have preceded
the crash; writable recovery must sync its directory before advancing it. A
`DeletedDurable` file must be absent. `DirectoryDeletePending` requires every
chunk `DeletedDurable` and permits the exact empty variant directory to be
present or absent until parent sync and finalization. Read-only mode validates
the same states without advancing them. The ordinary finalized-import audit
excludes only a structurally valid, unavailable deletion-manifest variant. Any
missing committed artifact outside that exact manifest state remains integrity
corruption.

Known temporary and unmarked chunk artifacts retain the existing documented
cleanup behavior. Any other unexpected artifact inside the owned depot
namespace causes open to fail closed and is preserved for diagnosis; anything
outside that namespace is untouched. No generic unknown-file cleanup is
introduced.

## Concurrent expiry boundary

TTL and policy are checked when each bounded unit is admitted:

- at most one 64-KiB application page;
- at most one 16-KiB network carrier range; and
- one bounded internal chunk operation during stopped streaming.

An already admitted unit may finish. The next unit is rejected after expiry or
retirement. Whole-Blob operations do not acquire an unbounded lifetime lease.
GC waits only for current bounded-unit leases before enqueueing physical
deletion. Expiry cannot revoke bytes already returned to application custody.

## Routine maintenance

Routine maintenance reclaims, in order:

1. expired publications and pending sources;
2. policy-invalid, revoked, wrong-epoch, or authenticated
   transfer-terminal pending work;
3. unreferenced local import staging;
4. unreferenced completed variants;
5. expired operation- and publication-retirement records; and
6. manifest-backed physical deletion work.

That list defines eligibility precedence, not permission to starve later work.
Maintenance persists or deterministically reconstructs a cursor for each class
and schedules classes round-robin with per-turn row, file, and byte budgets.
Each nonempty class receives work within a bounded number of actor turns even
under continuous expiry or admission churn. Startup recovery uses the same
cursors, so restart cannot repeatedly reset progress to the first class.

Automatic cleanup is authorized only for an exact, typed lifecycle outcome:
authenticated TTL expiry; explicit policy/revocation or removed interest;
superseded configured content epoch; carrier digest/length/final-root mismatch
confined to that pending source and its prefix; abandoned unmarked local
staging; documented temporary artifacts; or an exact committed deletion
manifest phase. These cases retire only the named publication, pending
source/prefix, staging import, or deletion manifest.

Structural contradictions are never cleanup candidates. A missing or
conflicting publication, replay fence, lineage fence, owner/backing binding,
reference-index edge, quota/accounting row, committed chunk, or deletion
authority; a counter/high-water contradiction; or cross-owner depot capability
mismatch fails startup audit or causes the storage actor to fail closed and
preserve evidence. Maintenance must not turn those conditions into expiry,
invalidation, or absence.

Routine eligibility does not depend on priority. Specific read, delivery,
inventory, request, and serving paths independently recheck lifecycle status,
so a delayed maintenance sweep cannot expose an expired publication.

Maintenance runs automatically:

- one bounded recovery page at startup, followed by scheduled continuation;
- at the nearest known finite expiry;
- in bounded actor turns limited by rows, files, and reclaimed bytes; and
- before returning storage-capacity failure.

The actor yields between maintenance pages. Before an admission returns
capacity failure, it runs bounded routine cleanup and eligible pressure
eviction, processes enough manifest-backed physical deletion to satisfy the request when
possible, and retries admission once. This admission fast path may prioritize
work that can free the required capacity, but it neither advances nor resets
the routine fairness cursors.

## Pressure eviction

Pressure eviction begins only after routine cleanup. An incoming publication or
transfer can evict only candidates whose effective priority is strictly lower
than the incoming priority. Equal- and higher-priority live data is protected.

Candidate ordering is deterministic:

1. ascending effective priority;
2. incomplete transfer before completed application-visible content;
3. nearest final-reference expiry, with durable references ranked last;
4. for incomplete transfers, least completion first;
5. oldest acceptance order; and
6. exact publication or variant identity.

For shared content, effective priority is the maximum priority of all surviving
publication and pending-source roots. Final-reference expiry is the latest
expiry of those roots; any durable root makes the variant durable for ranking.
Removing a publication claims only metadata bytes unless the final physical
root also disappears.

Completed content may be physically evicted only when every surviving root is
strictly lower priority than the incoming work. The eviction transaction then
retires every publication and pending source whose reference must disappear to
reclaim that variant; it never deletes content underneath a surviving semantic
root. If bounded reclamation cannot satisfy admission, the store returns an
explicit capacity error.

The current selected Blob depot has global limits. This work does not create
per-scope Blob quotas. Pressure eviction never deletes lineage or replay fences
and therefore cannot recover their separate security capacity; callers receive
the distinct typed capacity errors defined above rather than an ordinary depot
capacity error.

## Operation retirement retention

Expiry and pressure eviction replace an active local operation mapping with a
compact retirement record containing the operation-key digest, publication
identity, reason, and retention age. While present, exact retry returns
`ExpiredOrRetired` and never reimports content.

The canonical `BlobPublicationIntent` and its digest include publisher, topic,
scope, priority, `BlobId`, and the exact optional TTL. Retrying one operation
key with the same canonical intent is idempotent. Changing durable to finite,
finite to durable, or one TTL value to another is an intent conflict, even when
all other fields and content are identical. Once the retirement record ages out,
reuse is a new operation and publication as described below.

Retirement records use a configurable 45-day default: the existing 30-day
offline-tolerance baseline plus a 15-day margin. Retention uses conservative
lower-bound aging. After the record expires, its operation key may be reused;
reuse creates a new publisher counter and publication identity. Publisher
replay/high-water state still prevents the old publication from returning.

Existing operation record and byte limits remain. Reaching a limit before
eligible record expiry returns an explicit operation-capacity failure rather
than deleting an unexpired retry fence.

## Negotiated protocol behavior

Finite Blob exchange is enabled only in the next available semantic version,
provisionally v8 after PR #33 assigns semantic v7 to receipt-free Event pages.
The design and implementation must use "next available semantic version" until
that allocation is final.

The signed stable source envelope and `ItemCore` format are unchanged. The
outer protected Blob source-offer grammar changes under the new semantic
version:

- both durable and finite Blob publications are eligible;
- every protected source-bearing representation carries a mandatory custody
  claim for finite publications and no claim for durable publications: this
  applies both to the offer/apply direction (`MutableOffer`) and the
  fetch/object/result/ack direction (`MutableObject`);
- the claim uses a Blob-specific domain and canonically binds the semantic
  version, session transcript, exchange and direction, exact source transfer
  ID, exact source length, publication identity, `BlobId`, priority, TTL,
  sender cumulative age, sender monotonic sample, and hop contribution;
- the receiver commits the authenticated age with the pending source before
  requesting carriers;
- local residence continues consuming finite TTL while carriers arrive;
- every carrier-range admission rechecks the serving source and receiver's
  pending source; and
- final promotion atomically rechecks policy, exact source, complete content,
  and lifetime.

The claim is part of the protected `MutableOffer` or `MutableObject`, not a
mutable carrier hint or an optional adjacent frame. `MutableApplyResult` binds
the exact offer claim digest. `MutableFetchResult` and
`MutableFetchResultAck` both bind the exact fetched-object claim digest in
addition to their existing class, direction, transfer ID, and disposition. The
sender advances its cursor only after the matching bound result or result ack.
A finite source-bearing frame with no claim, a durable frame with one, duplicate
claim fields, non-canonical encoding, transcript mismatch, result/ack mismatch,
or field mismatch fails the source exchange before any pending source is
inserted. The implementation plan assigns the next free frame/tag encoding and
publishes canonical vectors; it must not weaken either direction to an unbound
side record.

For an already known publication or pending source, authenticated duplicate
custody never replaces age. The transaction verifies immutable fields, then
stores `max(local_effective_or_lower_bound_age, received_authenticated_age)`
and the conservative continuity result. A younger duplicate cannot rejuvenate
the item; an older duplicate may prove expiry; an identity or lifetime mismatch
is rejected. Transcript and transfer bindings prevent a claim captured in one
session or source exchange from authorizing another.

Carrier delivery does not reset or redefine publication age. A different
eligible peer may continue carrier transfer without source refetch, while the
receiver's already authenticated pending-source age continues locally.

Every finite pending source durably records the semantic version that admitted
its source claim. Source offer/acceptance, carrier request, carrier serving,
prefix mutation, resume, and final promotion are eligible only when the active
session negotiates that finite-Blob version, or a successor that explicitly
declares compatible custody semantics, and the stored provenance matches. A
later v5-v7 session performs no action on that pending source; it cannot resume
the carriers or promote the publication through the durable lane.

When v5-v7 is negotiated, durable Blobs retain the existing byte-identical
lane. Finite publications are omitted from inventory and are neither offered
nor requested. Finite pending sources are also ineligible for carrier service,
resume, mutation, or promotion in those sessions. Older peers therefore never
receive a source they are specified to reject, and an already admitted finite
transfer cannot be downgraded mid-lifecycle.

## Application and status behavior

The public publication request adds an optional TTL equivalent to:

```rust
pub ttl_ms: Option<u64>
```

`None` is durable and `Some(0)` is rejected locally. The exact Rust, ConnectRPC,
and CLI spelling is coordinated with the concurrently owned public Blob API
work, but this storage contract is authoritative.

Publication results, delivery metadata, and authenticated read metadata expose
the signed original TTL. Dynamic remaining lifetime is local status, not signed
metadata.

After retirement:

- exact-publication lookup and Blob/topic/scope read use the retained
  publication-retirement index and return `ExpiredOrRetired` when no matching
  live publication remains; after its 45-day record expires the same lookup may
  return `NotFound`;
- retirement transactionally converts each outstanding content-delivery row to
  a `BlobRetirementDelivery` keyed by
  `(subscription_id, publication_id, retirement_generation)`; this replaces the
  row one-for-one, inherits its existing delivery bound, and reports the typed
  reason without exposing the retired bytes;
- polling never returns retired content and may return that retirement notice;
  its separately bound acknowledgement token is idempotent until the underlying
  publication-retirement record expires;
- an old unacknowledged content token returns `ExpiredOrRetired`; an already
  completed content acknowledgement remains `AlreadyAcknowledged` only while
  its existing compact acknowledgement record survives; and
- transfer status omits retired pending sources.

Never-observed identity remains distinguishable from recent retirement:
`NotFound` is used only when neither live nor retained retirement state matches.
Publication-retirement expiry atomically removes its secondary lookup entries,
retirement-delivery rows, and their acknowledgement state. No delivery or token
can keep bulk content alive.

`retirement_generation` is a durable, monotonically allocated local marker
assigned in the retirement transaction. It prevents an acknowledgement token
for an older retirement notice from acknowledging a later publication or
notice after operation-key reuse.

Local status adds aggregate deletion-pending bytes/files, retained operation and
publication retirement records, deletion retry count, oldest pending deletion
age or conservative lower bound, next retry state, and sanitized last-failure
category. It also reports lineage-fence, replay-fence, and publication-lifecycle
rows used and configured caps so permanent security-capacity exhaustion is
diagnosable before admission fails. It exposes no raw path or peer-controlled
error string. It makes no peer or global convergence claim. No public GC trigger
is required.

Renewal is not part of this increment. An application may republish the same
content with a new operation key; existing content is reused when its variant
is still present.

## Verification

### Shared aging

- same-domain restart includes elapsed restart time;
- changed-domain restart never guesses freshness;
- later domains increase only the lower bound;
- multiple lost domains eventually prove expiry without counting unknown gaps;
- indeterminate data is never forwarded or delivered; and
- arithmetic overflow fails closed.

### Store and GC

- two publications share content; retiring one preserves it;
- retiring the final root reclaims metadata and files;
- durable and higher-priority roots protect shared variants;
- valid pending transfer survives inactivity and restart;
- expired, uninterested, and enumerated transfer-terminal pending failures are
  removed, while every structural metadata/accounting/capability contradiction
  fails closed and preserves evidence;
- incomplete lower-priority work precedes completed-content eviction;
- equal/higher-priority pressure returns capacity failure;
- no byte, chunk, or variant quota is released before complete variant
  deletion and final metadata commit succeeds;
- deletion failure remains queued, charged, observable, backed off, and
  resumable across restart;
- a crash after unlink and directory durability but before metadata finalization
  reopens through the exact deletion manifest before ordinary depot audit;
- multi-chunk deletion never removes import/variant metadata or its directory
  before all chunk rows finalize; descriptor-relative no-follow and directory
  fsync behavior is retained;
- partially deleted variants open as unavailable only with an exact valid
  manifest; writable recovery resumes, read-only inspection does not mutate,
  and persistent later-chunk failure remains charged and observable;
- local publication commit, remote pending-source admission, promotion, and
  matching-lineage import racing each deletion phase either win before
  `DeletePending` or receive `VariantDeleting`/wire `DeferredCapacity`; no new
  root attaches after the fence;
- a missing committed file without an exact deletion record fails integrity;
- known temporary/unmarked artifacts follow existing cleanup, while any other
  unexpected in-depot artifact is preserved and causes open to fail closed;
- prepare/encrypt/finalize, cancellation, shutdown, and process-death races with
  reclamation cannot delete underneath a local-import generation lease;
- every crash/cancellation point before the single publication commit leaves no
  counter or operation fence and allows immediate exact operation-key retry;
- final-root retirement rechecks every lease generation immediately before
  commit;
- continuous expiry/admission churn cannot starve staging, retirement-record,
  or physical-deletion maintenance, including across restart;
- after all publication, staging, variant, and file state is reclaimed, a
  different physical lineage at the same `(BlobId, group, epoch)` is rejected
  after restart while the matching lineage remains admissible;
- filling lineage-fence capacity, then evicting and GCing all bulk content,
  still rejects a new variant with `LineageFenceCapacity` while admitting a
  matching previously fenced lineage;
- filling replay-fence capacity rejects a new publisher dot with
  `ReplayFenceCapacity` without erasing exact duplicate/equivocation evidence;
- after publication-retirement expiry and restart, exact old-source replay is a
  non-mutating `Duplicate`, same-dot/different-semantic replay is equivocation,
  and same-semantic/different-representation replay is
  `SourceRepresentationConflict`;
- operation retry returns the retirement reason, then permits reuse only after
  retention expiry;
- same operation key with a different TTL is an intent conflict;
- recent publication retirement is distinguishable from never-present identity,
  retirement delivery/ack is bounded, and both become `NotFound` after retained
  evidence expires; and
- every crash boundary before retirement, after retirement, during unlink, and
  before metadata finalization reopens consistently.

### Protocol and application

- new-version peers transfer finite Blobs end to end;
- both offer/apply and fetch/object/result/ack directions bind and verify the
  exact custody-claim digest before cursor advancement;
- new-to-old negotiation withholds finite Blobs and transfers durable Blobs;
- an existing finite pending source cannot be requested, served, mutated,
  resumed, or promoted during a later old-version session;
- tampered TTL, age, transfer, length, priority, and session claims fail closed;
- missing, surplus, duplicated, non-canonical, cross-session, and
  cross-transfer custody claims on either source direction fail before
  pending-source insertion;
- duplicate source claims merge age monotonically, a younger claim never
  rejuvenates state, and an older claim can immediately prove expiry;
- TTL expiry during source, carrier, promotion, page read, delivery, and
  acknowledgement follows the bounded-unit contract;
- interrupted transfer resumes after restart and from another eligible peer
  without resetting age;
- multiple publications with different lifetimes share content correctly; and
- delivery, acknowledgement, operation retry, and status remain consistent
  across graceful and forced process replacement.

Implementation verification includes focused crate tests, real-process
restart/kill scenarios, protocol compatibility and conformance vectors,
`python3 tools/check-implementation-requirements.py`, `mise run check`, and
`mise run fuzz-smoke` for the negotiated frame-grammar change.

## Product-requirement alignment

- The common lifetime requirement is met by using the existing
  `Durable | Finite(ttl)` model and shared custody-age semantics rather than a
  Blob-only clock or grace period.
- The "expired items are not transmitted and are garbage-collected" requirement
  is met by admission-path checks, immediate semantic retirement, automatic
  bounded reclamation, and no public cleanup dependency.
- The bounded/configurable storage requirement is met by existing depot limits,
  structural bounds on every new index/queue, charged deletion failures, and
  strict lower-priority eviction. Permanent security evidence has separate
  visible caps and explicit non-evictable capacity outcomes; it is not
  misreported as reclaimable bulk storage.
- Immutable, content-addressed, resumable Blob behavior is preserved by
  separating publication lifetime from shared content, retaining valid pending
  sources without inactivity timeout, and keeping same-epoch lineage fences.
- The no-synchronized-wall-clock requirement is met by suspend-inclusive
  monotonic samples, authenticated cumulative age, and conservative lower-bound
  aging after continuity loss.
- Eviction/conflict visibility is met by typed capacity and lineage errors plus
  bounded publication-retirement lookup and delivery to the application.

This work supplies implementation evidence only for those behaviors. It does
not reinterpret repository tracking notes or customer feedback as product
requirements, and it does not advance excluded release or platform claims.

## Implementation sequence

1. **Shared lower-bound custody aging.** Land after the internally owned PRs
   #25/#26. This PR is wire-neutral and proves the changed Event lifecycle.
2. **Blob storage lifecycle and reclamation.** Add reference indexing,
   lineage and replay fences, publication and operation retirement, staging
   recovery, fair automatic maintenance, pressure eviction, and crash-resumable
   descriptor-relative physical deletion for durable Blob state.
3. **End-to-end finite Blob TTL.** After semantic-v7 allocation settles, add
   the next negotiated version, protected source custody claims, durable
   provenance, monotone duplicate-age merging, pending/live expiry,
   mixed-version filtering, and the coordinated application TTL field.
4. **Retained acceptance evidence.** Exercise process/crash recovery,
   interrupted and different-peer transfer, expiry, reclamation, quota reuse,
   and mixed-version fallback. Move requirement evidence only for the exact
   retained behavior.

Each PR names its capability outcome and exclusions. Storage-only PR 2 does not
claim finite Blob TTL; protocol PR 3 does not claim route-only custody,
large-target resource fitness, or release acceptance.

## Security and compatibility invariants

- Wall-clock timestamps never determine freshness or conflicts.
- Unknown elapsed time never proves a finite publication live.
- TTL, priority, publication identity, and exact source transfer remain
  authenticated and cannot be rewritten by relays or receivers.
- Content is never application-visible before exact complete verification.
- Expired or indeterminate content is never offered, requested, retransmitted,
  served, delivered, or newly read.
- GC never deletes a physical variant with a surviving root.
- GC preserves the compact same-epoch physical-lineage witness after bulk data
  deletion, restart, and migration.
- Publication-retirement expiry never removes accepted-dot or exact-source
  replay evidence; exact duplicate, equivocation, and representation-conflict
  outcomes remain distinct after restart.
- GC rechecks all active local-import and bounded-unit lease generations in the
  final retirement transaction.
- `DeletePending` fences every new semantic or import root until complete
  reclamation; deletion and admission cannot both win.
- Physical deletion never trusts a caller-provided path.
- A canonical deletion manifest retains the original chunk set and all charges
  across partial deletion, restart, read-only audit, and persistent failure.
- Capacity is released only after complete variant deletion succeeds.
- Security-fence capacity is separate, bounded, observable, and never claimed
  to be recoverable through TTL, GC, or priority eviction.
- A missing committed file is recoverable only when its exact durable deletion
  record authorizes that state; otherwise depot open fails closed.
- Replay/high-water state survives normal GC.
- Older semantic versions retain their exact durable Blob behavior.
- Finite Blob support cannot be silently downgraded to a durable lifetime.
- Duplicate or replayed custody claims cannot reduce effective age.
