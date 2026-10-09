# Selected production-lane architecture

This page explains how the selected implementation turns Aster's concepts into
runtime authorities and trust boundaries. It is intentionally narrower than
the complete protocol and semantic reference implementation.

| Data class | Selected networking | Application surface |
|---|---|---|
| Event | Direct Iroh or one operator-pinned controlled Iroh relay | Live Rust handle, stopped Rust handle, and local ConnectRPC agent |
| State | Class-specific direct-Iroh reconciliation | Cloneable live Rust handle and exclusive stopped Rust facade |
| Record | Class-specific direct-Iroh reconciliation | Cloneable live Rust handle and exclusive stopped Rust facade |
| Blob | Semantic-v5 direct source/carrier transfer | Cloneable live Rust handle, exclusive stopped Rust handle, and encrypted local depot |

Read the diagrams from broadest to narrowest: application surfaces, runtime
ownership, then the publication and contact flows for each mechanism. Exact
evidence and remaining release gates live in
[requirements status](validation/requirements-status.md), not in these
diagrams.

## Components and trust boundaries

### Application surfaces

```mermaid
flowchart LR
    App["Application"] --> Connect["ConnectRPC agent"]
    App --> LiveRust["Live Rust handle"]
    App --> StoppedRust["Stopped Rust handles"]
    Connect --> LiveEvent["Event operations"]
    LiveRust --> LiveOps["Event · State · Record · Blob operations"]
    LiveEvent --> Actor["Running aster-node actor"]
    LiveOps --> Actor
    StoppedRust --> Event["Event"]
    StoppedRust --> State["State"]
    StoppedRust --> Record["Record"]
    StoppedRust --> Blob["Blob"]
    Actor --> Exclusive["Exclusive store authority"]
    Event --> Exclusive
    State --> Exclusive
    Record --> Exclusive
    Blob --> Depot["Encrypted local depot"]
    Actor --> Depot
    Actor --> Network["Event · State · Record · v5 Blob reconciliation"]
```

The running actor and stopped handles never own the store at the same time.
State and Record applications may publish/query—and for Record, resolve—through
the running actor, or use their stopped facades after the actor exits. Objects
published through either mode reconcile under the same authority. Blob
applications likewise publish through the live handle or stopped facade; the
live handle returns only bounded pages, while the stopped facade supports
caller-owned streaming. Semantic v5 separately transfers already-durable Blob
sources and bounded carrier prefixes directly between content-capable peers.

### Runtime trust path

```mermaid
flowchart LR
    API["Live Event/State/Record/Blob API"] --> Node["aster-node<br/>ordering and lifecycle"]
    Authority["Authority CLI"] --> Node
    Operator["Same-UID Unix operator"] -. "local zeroize" .-> Node
    Node --> Core["aster-core<br/>control and source verification"]
    Node --> Store["redb<br/>durable policy and data authority"]
    Store --> Depot["Encrypted Blob depot"]
    Node --> Profile["Canonical transfer IDs"]
    Profile --> Diff["Bounded set difference"]
    Node --> Session["Hybrid mission session"]
    Session --> Carrier["Iroh carrier<br/>direct or operator-pinned relay"]
    Carrier <--> Peer["Peer aster-node"]
```

`aster-node` is the sole composition root. `aster-iroh` authenticates only the
carrier endpoint and provides bounded direct exchange or exchange through one
operator-pinned controlled relay. That relay is connectivity infrastructure,
not an Aster mission node, store, or route grant. The mission `NodeId` is
independent from the Iroh `EndpointId`. `aster-negentropy` computes exact-ID set
difference; it does not transfer objects, establish causality, or make policy.
`aster-redb-store` is the selected durable authority for accepted Events,
State, Record, and local Blob publications, their shared publisher causal
frontier, ordered control effects, policy/selector snapshots, at-least-once Event delivery, route-only
Event representations, and the terminal zeroization marker. State, Record, and
Blob operation rows have separate dedicated count/byte ceilings and also
participate in aggregate store quotas; no unbounded idempotency table is
implied. Blob lifecycle authority is separately non-evictable and capacity-
bounded: permanent physical-lineage fences and accepted-publication replay
fences have independent row/encoded-byte limits, while publication lifecycle
rows have their own row limit. The selected defaults are 65,536 rows and 16 MiB
for each fence class and 65,536 publication lifecycle rows. Exact typed
references distinguish publication roots from pending-source roots for each
depot variant. These lifecycle limits are not retention durations and cannot be
reclaimed by pressure eviction.

Blob ciphertext is stored outside redb under separate committed-byte, chunk,
and variant ceilings, while redb remains the authority for exact publication,
reference, fence, accounting, and committed-file markers. On its first
successful open, redb persists a domain-separated commitment over a random
owner token, canonical
database path, and Unix device/inode when available. The fixed sibling depot’s
private marker must carry the same binding before any chunk/variant scan or
reclaim. The first database to initialize a parent’s depot wins; another cannot
adopt it. Moving/copying even an empty bound database to another path fails on
reopen. On Unix, a new inode also fails, moving the depot with the database does
not preserve the binding, and a same-path replacement cannot adopt an existing
depot. Non-Unix does not prove copied-database replacement/rollback resistance
at the same canonical path. No supported rebind/restore migration is provided
in this slice.

Live Event, State, Record, and Blob handle clones do not open a second store.
They send commands over one 32-command channel to the actor that already owns
the mission-bound writer. Blob commands are dispatched without blocking that
actor to one joined worker with a one-command queue; the worker rechecks current
policy and lineage rather than retaining an actor lease across file I/O or
decryption. Event commands that insert or remove selectors take the actor's
policy write lease; State/Record publish/query/resolve and other application
operations use the policy read lease. Contacts use that same actor-owned
policy/store authority. Shutdown or zeroization closes shared and Blob-worker
admission, rejects queued commands, and joins the worker before the authority
or key-bearing state is released, so retained clones return sanitized
`StateUnavailable`. A stopped facade can acquire the writer only after the live
actor has exited and must close before a new actor starts.

For a semantic-v7 contact, the first protected exchange negotiates a transfer
profile independently for Event, State, Record, Blob, and EventBridge. Every
lane must offer `LegacyV6`; only Event may additionally select
`EventPagesV1`. Exact Event differences and bounded blind traffic into a
ReceiveOnly peer can then move in one ordered bounded unidirectional turn.
Finite entries carry session-authenticated cumulative age, while durable and
tombstone entries carry no age wrapper. The receiver commits each complete page
before continuing, and neither endpoint creates a per-Event apply result,
custody receipt, suppression hint, lease, or retry settlement for that paged
transfer. An interruption leaves the committed prefix durable; the next contact
reconciles the remaining exact difference or advances blind attempt rotation.
The sender's persisted per-peer,
per-priority cursor rotates attempts only within the same priority tier and is
never delivery evidence. Its allocation and the sender page-packing target are
local implementation details, not wire limits.

Event/RouteEvent finite lifetime uses one shared lower-bound custody state
machine in core and redb. Exact continuity permits normal forwarding. Once
continuity is lost, forwarding remains permanently disabled for that row, while
valid later clock domains are used only to accumulate provable same-domain
intervals. The redb expiration index doubles as a bounded re-anchor queue:
unanchored rows use a sentinel, older generations are processed before current
deadlines, and every age/checkpoint/index change commits atomically. This avoids
both wall-clock reconstruction and an unbounded restart scan. Reaching TTL on
the conservative lower bound feeds the existing marked-then-retired Event
lifecycle, including lease drain. Wire claims and durable item encoding do not
change. Blob finite lifetime and Blob route-only custody remain later work.

Each mission-authenticated contact runs class-separated State and Record
Negentropy/fetch lanes after its control and Event lanes. A receiver supplies
canonical topic/scope interests independently for each class; empty means
receive-none. Interest never grants authority. Inventory and every offered or
fetched object are filtered and freshly checked against current mission, route,
content, revocation, scope-epoch, source, class, topic, and scope constraints.
The contact holds one control-policy read lease, so inventory and admission use
one policy generation. Exact transfer identities make repeated receipt
idempotent. Remote finite-TTL mutable objects fail closed until authenticated
cumulative forwarding age exists.

## Live or stopped State publication, projection, and network reconciliation

The selected State composition uses the same mission, control policy,
source-envelope provider, writer lock, and causal ledger as Event. A State
publisher counter therefore cannot restart at one or reuse an Event dot. State
storage is additive and uses its own typed transfer identity and reconciliation
frames; it cannot be confused with either Event or Record traffic.

```mermaid
sequenceDiagram
    participant A as Application
    participant N as State composition (live handle or stopped facade)
    participant P as Current control policy
    participant C as Source-envelope provider
    participant S as Mission-bound redb

    A->>N: publish(operation key, State fields, payload)
    N->>P: refresh policy and source authority
    N->>S: reserve shared publisher dot + causal context
    N->>C: source-seal State
    N->>C: route verify + content verify + exact payload check
    N->>S: atomic policy-bound operation/version commit
    S-->>N: structural durable result
    N->>C: freshly verify full request and payload
    N-->>A: sanitized StatePublishResult

    A->>N: query(exact topic, scope, logical key)
    N->>S: prepare bounded policy-bound projection plan
    S-->>N: all retained candidates + claimed dispositions
    N->>C: freshly verify every active and inactive candidate
    N->>N: recompute active causal maxima and tie-break
    N->>S: require exact plan unchanged
    N-->>A: current + optional active recoverable versions
```

The durable operation mapping is structural state inside the privileged store,
not an application capability. Even an exact replay must pass current mission,
revocation, source, topic, scope, and content authorization before the original
result is returned. A previously committed old-epoch operation can resolve only
under that current authority; a future-epoch representation is rejected. The
facade then freshly verifies the returned semantic identity, protected header,
and exact plaintext against the complete publication request.

Projection is causal and clock-independent. For one exact topic/scope/logical
key, a version dominates another only when its authenticated causal context
observes the other's dot. The active causal maxima are retained; the greatest
complete semantic State ID is the deterministic current version, and any other
maxima are `Concurrent`. Dominated versions are `Superseded`. The store supplies
a structural plan, the facade independently recomputes that result from freshly
verified capabilities, and the store rechecks the exact plan before return.

Inactive revoked or old-epoch rows are still included in the bounded plan and
freshly verified so they cannot hide structural corruption, but they are not
returned as application current or recoverable values. A current tombstone is
returned visibly as authenticated State with an empty payload. There is no
delete-wins rule, and deletion is not collapsed into an unauthenticated
`None`.

## Live or stopped Record projection, guarded resolution, and network reconciliation

The selected Record composition uses the same mission, control policy,
source-envelope provider, writer lock, and causal ledger as Event and State.
Its tables, markers, exact/semantic indexes, and operation ledger remain
class-disjoint, while a Record publisher cannot reuse a causal dot already used
by either other class. Record storage is additive and uses its own typed
transfer identity and reconciliation frames.

For one exact topic/scope/logical key, every active causal maximum is a head.
The greatest complete semantic Record ID is marked `Current`; every other head
is returned as `Concurrent`; causally dominated active revisions are optionally
returned as `Superseded`. That deterministic current marker is a stable
projection, not a silent merge or discard.

```mermaid
flowchart LR
    Q["Exact-key query"] --> P["redb bounded structural plan<br/>all retained candidates"]
    P --> V["Record composition<br/>fresh source/content verification<br/>independent causal recomputation"]
    V --> H{"Active heads"}
    H -->|one| C["Current<br/>optional superseded history"]
    H -->|two or more| F["Current + Concurrent<br/>explicit sorted siblings<br/>opaque exact guard"]
    F --> A["Application inspects siblings<br/>and computes reviewed payload"]
    A --> R["resolve(operation key, guard, payload)"]
    R --> G{"Exact plan still current<br/>and successor observes every head?"}
    G -->|yes| S["Atomic guard-bound successor<br/>original heads become superseded"]
    G -->|no| X["Conflict; no bytes inserted"]
```

Ordinary `publish` fails when its causal reservation observes two or more
existing heads, so it cannot bypass the explicit resolution path. The guard
binds the complete sorted sibling set and the policy-bound projection. The
durable operation digest binds the publication intent and sorted guarded head
identities: an exact retry returns the original commit, while the same operation
key with another head set fails.
The store requires a new resolution successor to observe every guarded head and
atomically rejects a stale guard if the projection advanced.

On query and resolution the store's rows and plan are privileged structural
inputs, not capabilities. The facade freshly verifies every retained active or
inactive candidate, recomputes heads and dispositions, and rechecks the exact
plan before exposure or commit. Inactive revoked or old-epoch rows are not
returned to the application. A current Record tombstone remains visible with an
empty payload; a concurrent tombstone has no delete-wins priority.

Registered merge policies are never run automatically by the selected
implementation.
Remote ingest stores an immutable, already source-authenticated revision and
recomputes structural causal heads without invoking application code. A
resolution successor supersedes the guarded heads without deleting their
authenticated history.

## Live and stopped Blob streaming and depot authority

The selected Blob facade uses the same mission, current control policy,
source-envelope provider, process-exclusive writer, and shared causal ledger as
Event, State, and Record. A running node exposes a cloneable
`SelectedBlobHandle`; the exclusive `SelectedBlobNode` remains available for
stopped-state streaming after the actor exits. Live publication accepts an
owned, already-open regular file positioned at byte zero, rejects empty input,
and is capped at 64 MiB/1,024 canonical 64-KiB chunks. A live read returns one
freshly authenticated, zeroize-on-drop plaintext page of `1..=64 KiB`; the
stopped facade retains its synchronous caller-owned streaming interface. The
runtime separately adds semantic-v5 Blob source and carrier-range frames; v1-v4
emit none. `BlobId` commits the exact plaintext bytes, canonical chunk profile,
and media/schema identity metadata. It is not a metadata-independent whole-byte
content identifier.

```mermaid
sequenceDiagram
    participant A as Application
    participant N as Blob composition (live handle or stopped facade)
    participant C as Source-envelope and Blob provider
    participant S as Mission-bound redb
    participant D as Encrypted Blob depot

    A->>N: publish(operation key, metadata, bounded source)
    N->>S: current policy + exact operation preflight
    N->>C: bounded preparation pass
    N->>D: encrypt, sync, rename, then mark each chunk
    N->>C: source-seal and freshly verify canonical manifest
    N->>D: prove every authenticated record and final digest
    N->>S: atomic publication + operation commit
    N->>C: freshly verify durable publication result
    N-->>A: sanitized BlobPublishResult

    alt live read_page(≤64 KiB)
        N->>S: exact-load current selected projection
        N->>C: authenticate selected source; check inactive projections against cache capabilities
        N->>S: require current policy, lineage, and plan
        N->>D: require exact completion and decrypt bounded range
        N->>S: recheck authority, completion, and lifecycle
        N-->>A: zeroize-on-drop page
    else stopped read_into(caller output)
        N->>S: bounded structural plan with every retained source
        N->>C: freshly verify every manifest and source/content capability
        N->>N: select greatest active semantic publication ID
        N->>S: require exact policy-bound plan unchanged
        N->>D: prove selected completion once and stream verified chunks
        N-->>A: BlobReadResult
    end
```

The first publish pass uses one bounded, zeroizing plaintext chunk buffer and,
after completion, retains only a manifest-bounded digest vector and no
plaintext; the second uses bounded buffers to encrypt chunks. A chunk becomes
durable only after private temporary-file write and synchronization,
same-directory rename, directory synchronization, and an exact redb
committed-chunk marker. Unmarked
temporary or final files are not authority and are reclaimed on a writable
mission-bound reopen. A marker whose file is missing, truncated, or different
fails integrity and is never reconstructed from a filename or header claim.
A source publication is committed only after the exact authenticated manifest
equals every expected and committed depot record and the finalized manifest
digest.

The stopped read plan is structural, not authorization. That path freshly
verifies every retained active or inactive source publication, checks the exact
topic, scope, Blob ID, content group, epoch-specific depot variant, and source,
then independently recomputes the active deterministic selection. Only after an
exact plan recheck does it require one authenticated completion capability for
that exact selected depot variant and synchronously stream plaintext into
caller-owned output.

The live path exact-loads and content-authenticates only the selected current
source. Inactive candidates are projection-checked against
startup-authenticated cache capabilities; their sealed bytes are not rehashed
for every page. Current policy, lineage, lifecycle, and the exact completion
capability are checked around range decryption before a zeroize-on-drop page of
at most 64 KiB, spanning at most two canonical chunks, is disclosed. No
provider reader or copied epoch key escapes either surface. A late
stopped-stream integrity failure can leave an already verified prefix in
caller-owned output, so applications needing all-or-none replacement use their
own temporary destination.

Ordinary request, policy, conflict, and capacity failures are sanitized for the
application. A contradiction among durable Blob rows, the authenticated source
cache, the exact depot capability, or post-commit verification is actor-fatal
coherence loss: the joined worker reports `FatalBlobCoherence`, closes shared
application admission, and makes the exact failure visible through node
completion rather than continuing with a potentially split authority.

Exact operation retry rehashes the source, passes current policy and revocation
checks, and freshly verifies the historical publication and variant before
returning the original counter and marker. A different operation may commit a
new signed publication while reusing the same immutable completed variant in
one content group and epoch. Rekey creates a distinct encrypted variant even
when object identity is unchanged.

The durable Blob lifecycle schema wraps live publications and operation rows,
counts publication and exact typed variant-reference roots, and retains two
separately bounded permanent security fences. A lineage fence binds each depot
variant to its accepted physical lineage and depot-owner binding. A replay fence
binds each accepted publisher dot to the exact semantic publication, transfer,
source length, and source digest. Local publication admits the replay fence,
publication lifecycle row, publication reference, ordinary publication indexes,
causal rows, and operation result in one redb transaction. Network staging
admits the lineage fence, pending reference, pending source, depot plan, and
accounting atomically; promotion atomically replaces that pending reference with
a publication reference while installing replay/publication/causal authority and
removing pending rows; abort atomically removes only the pending source and its
reference. The lineage fence and depot import remain after abort.

Opening a predecessor store reconstructs and audits the complete lifecycle
image, checks all configured lifecycle capacities and the paired physical depot,
and then commits wrappers, fences, references, counters, and maintenance cursors
together.
Any audit or injected failure leaves the predecessor untouched. Read-only
inspection reconstructs predecessor state only in memory. Once current, every
open strictly checks exact bidirectional correspondence among base rows,
lifecycle rows, typed references, permanent fences, accounting, and cursor
shape; it does not repair a partial or contradictory current schema.

Under semantic v5, a content-capable receiver reconciles exact Blob source IDs
before requesting only missing, peer-neutral 16-KiB carrier prefixes. Every
source and range send requires the authenticated peer's current exact content
proof plus route and nonrevocation authority. Pending bytes remain outside
ordinary publication until the exact depot, full-content, and current-lineage
proofs agree atomically. This path implements bounded direct transfer, not
route-only Blob relay or custody.

`BlobDepotLimits` reserve canonical ciphertext-file bytes for every durable
expected chunk record and bound durable per-chunk metadata rows and
epoch-specific import variants. Rows and variants include retained unpublished
imports, whether expected-only or already finalized, and continue to consume
admission until a future explicit-GC policy exists. The limits do not claim to
measure redb allocation, directory blocks, snapshots, backups, swap, unrelated
attacker-created directory entries, or every filesystem overhead. Unix
depot operations use owner-controlled directory descriptors, no-follow checks,
and private modes; the non-Unix fallback is not credited with equivalent
filesystem hardening. Terminal software zeroization destroys the retained
mission/content and identity secrets and locks the store, but deliberately
preserves the encrypted Blob depot and audited data rows. This is bounded
cryptographic shredding, not Blob-file deletion or physical sanitization.
Current code has a durable metadata-only exact-publication Blob delivery
ledger. Its local counts do not grant authority and are neither peer nor
convergence status.

Blob maintenance persists one cursor for each of six ordered classes plus the
next class: expired publications/pending sources, invalid pending work,
unreferenced local import staging, unreferenced completed variants, expired
retirement records, and manifest-backed physical deletion. One turn selects one
class, scans a wrapping page, advances to the next class, and commits the class
cursor and rotation together. The selected runtime requires nonzero row, file,
and byte budgets and uses 16 rows, one file, and 2 MiB per turn. It runs one turn
after the strict startup audit before Blob command admission, then schedules at
most one background turn after operational application/control work on each
periodic actor tick; the actor remains available while that blocking page runs.

This scheduler is discovery and structural validation only in this increment.
Unreferenced staging/completed-variant candidates are reported, leave their
cursor revisitable, and set the later-handler boundary; no row or file is
deleted. The other future destructive classes likewise have no expiry or
deletion handler. Retention/retirement expiry, physical reclamation and deletion
manifests, pressure eviction, and finite Blob TTL are not implemented.

## Live application command and status flow

```mermaid
sequenceDiagram
    participant A as Application
    participant H as SelectedEventHandle
    participant N as RunningNode actor
    participant L as Policy lease
    participant S as Mission-bound redb
    participant C as Contact task

    A->>H: typed Event operation
    H->>N: bounded command
    N->>L: read lease, or write lease for selector changes
    N->>S: policy-bound transaction or structural plan
    S-->>N: durable result or untrusted candidates
    N->>N: freshly verify source, content, and plan
    N-->>H: sanitized result
    H-->>A: typed result
    C->>N: completed authenticated contact receipt
    N->>N: update bounded local contact state
    A->>H: status()
    H->>N: status command
    N->>S: current control and selector policy
    N-->>H: local last-contact snapshot
    H-->>A: typed status
    Note over A,N: LastContactComplete is not global convergence
```

Selector changes take the policy write lease and update the selector generation
and delivery ledger atomically. Publish, query, poll, acknowledge, gaps, and
status take a read lease. Candidate rows and store plans are structural input,
not trusted application results; the actor verifies them before returning
sanitized values.

Gap results follow the same trust rule. The store prepares a bounded structural
plan, the selected node freshly verifies every observed source position, and
the store rechecks the exact policy-bound plan before a half-open gap interval
is exposed. Absence of a returned gap says only that the locally observed,
verified positions in that page are contiguous; it is not publisher
completeness or mesh convergence.

## One authenticated contact

```mermaid
sequenceDiagram
    participant L as Local node
    participant C as Iroh carrier (direct or controlled relay)
    participant P as Peer node
    participant S as redb store

    L->>C: connect to exact endpoint over configured route
    C->>P: authenticate carrier endpoint
    L->>P: complete hybrid mission authentication
    P-->>L: prove expected mission NodeId
    L->>P: control reconciliation query
    P->>L: source-authenticated control suffix
    L->>S: commit and activate contiguous control prefix
    L->>P: exchange protected receive interests
    Note over L,P: empty interest means receive-none
    L->>P: reconcile and offer inside peer's authorized universe
    P->>L: reconcile and fetch inside local authorized universe
    alt content grant
        L->>S: verify source + admit semantic Event
    else route-only grant
        L->>S: retain bounded exact bytes only
    end
```

The ordering is security-relevant: mission authentication precedes inventory;
control reconciliation and durable activation precede protected interest or
Event inventory; each receiver gets an independent filtered reconciliation
universe; and content admission is separate from forwarding authority. Receive
intent never grants access: current source, epoch, revocation, and route policy
are rechecked at inventory, transfer, and commit boundaries.

## Identity and authorization are deliberately separate

| Layer | Proves or decides | Does not imply |
|---|---|---|
| Carrier | Exact Iroh endpoint over a direct or controlled-relay path | Mission membership, data access, or representative/physical NAT acceptance |
| Mission | Hybrid-session possession of the expected mission `NodeId` | Control authority, source authorship, route, or content grant |
| Control | Ordered authority/delegation chain and policy effect | Event source identity or plaintext access |
| Event source | Publisher and protected semantic header | Permission for every peer to route or read it |
| State source | Publisher, causal stamp, exact key, protected semantic header, and payload commitment | Live replication, permission for every peer, or a special delete-wins rule |
| Record source | Publisher, causal stamp, exact key, protected semantic header, and payload commitment | Live replication, automatic merge execution, permission for every peer, or delete-wins |
| Blob source/depot | Publisher, causal stamp, immutable object identity, canonical manifest, exact encrypted chunk records, content group, and key epoch | Subscription/status, route-only custody, metadata-independent content identity, physical sanitization, or permission for every peer |
| Receive selector | Membership-visible topic/scope intent inside the protected mission session; empty means receive-none | Route or content authority, Event-ID disclosure, or scope-private subscription metadata |
| Route policy | Whether an exact representation may be advertised/carried | Content decryption or semantic admission |
| Content policy | Whether protected bytes may become a semantic application item | Authority to alter source identity or control state |

## Bounded terminal zeroization

```mermaid
stateDiagram-v2
    [*] --> Live
    Live --> CleanupPending: preflight exact unique files<br/>drain/close/drop secret holders<br/>commit durable intent
    CleanupPending --> MissionDestroyed: overwrite + fsync + truncate<br/>mission file descriptor
    MissionDestroyed --> IdentityDestroyed: overwrite + fsync + truncate<br/>carrier-key file descriptor
    IdentityDestroyed --> Complete: durable final receipt
    CleanupPending --> CleanupPending: crash retry on unchanged inode
    MissionDestroyed --> MissionDestroyed: crash retry on unchanged inode
    IdentityDestroyed --> IdentityDestroyed: crash retry on unchanged inode
```

Every non-`Live` phase denies normal opens. Terminal-safe inspection and data
rows, including encrypted Blob depot state, remain available. Destroying the
mission/content material makes that retained ciphertext unavailable through the
terminal store, but is not a claim that its bytes were overwritten. The
same-UID Unix operator may enter through owner-only live IPC or a stopped
exclusive-writer path; there is no carrier or mission-control trigger.
Pathnames remain as zero-length tombstones. Physical media,
copy-on-write history, snapshots, swap, backups, database rollback/replacement,
and non-Unix behavior are outside the proof.

## Related documentation

- [Application quickstarts](quickstart/README.md) explain how to exercise each
  supported surface.
- [Protocol](protocol.md) defines the wire and semantic contract.
- [Security model](security.md) describes security properties and production
  gates.
- [Requirements status](validation/requirements-status.md) records retained
  evidence, credited behavior, and open validation gaps.
