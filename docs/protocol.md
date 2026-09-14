# Aster Mesh Protocol Specification

- Specification version: 0.1.0-draft.2
- Wire major/minor: 1.0
- Status: reference draft; not production-authorized
- Date: 2026-08-25

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
normative. The protocol specification, not the Rust representation, is the
interoperability authority.

Sections describing suite/profile `0x0001` remain exact. The additive
semantic-v1 `classical-p256-iroh-quic-v1` profile (`0x0002`) and its distinct
reference source/contact boundary are documented in
[classical-iroh-security-profile.md](classical-iroh-security-profile.md); it
does not reinterpret a semantic version or any profile-`0x0001` byte. Complete
normative profile-`0x0002` byte grammar and independent vectors remain open.

## Find a section

| Need | Sections |
|---|---|
| Understand the invariants and layers | [Design invariants](#1-design-invariants) through [primitive types](#3-primitive-types-and-encoding) |
| Implement identities and source authentication | [Identity and dots](#4-identity-dots-and-semantic-item-core) through [source authentication](#6-source-authentication) |
| Implement causality and data-class reducers | [Causality](#7-causality) and [data class reducers](#8-data-class-reducers) |
| Implement synchronization and resource policy | [Reconciliation](#9-exact-reconciliation-and-resumption) through [priority and emissions](#11-priority-retry-eviction-and-emissions) |
| Implement routing, sessions, and lifecycle controls | [Scopes and bridges](#12-scopes-topics-relay-and-bridge-policy) through [revocation and zeroization](#14-revocation-rekey-and-zeroization) |
| Add a carrier or discovery profile | [Carrier behavior](#15-carrier-fragmentation-broadcast-and-loops) and [discovery](#16-discovery-and-link-profiles) |
| Check compatibility, errors, or bounds | [Versioning](#17-versioning-and-extensions) through [known bounds](#20-known-bounds) |

## 1. Design invariants

1. A transport carries opaque frames and never defines data meaning.
2. Every delivered item is encrypted and authenticated by its source.
3. Relays can inspect only protected routing metadata and cannot read content
   unless independently granted a content key.
4. Causality and conflict resolution never depend on wall-clock order.
5. Reconciliation is exact. Probabilistic hints may optimize but never decide
   convergence.
6. Verified objects and partial Blob ranges are peer- and transport-neutral, so
   later contact continues prior work.
7. Duplicate application is defined to have no further semantic effect.
8. Unknown optional extensions are ignorable; unknown critical extensions fail
   the containing message deterministically.

## 2. Layering

The protocol has five independent layers:

| Layer | Responsibility |
|---|---|
| Carrier | stream/datagram delimiting, opaque fragmentation, MTU adaptation |
| Adjacency | mutual authentication, replay protection, and encrypted pairwise sessions; the selected profile may use Aster records or an exact authenticated carrier binding, and a future profile must define any protected broadcast capsule |
| Source envelope | immutable source-authenticated route wrapper and end-to-end content ciphertext |
| Replication | exact inventories, offers/wants, resumable data, durable receipts |
| Class reducer | State, Event, Record, Blob, tombstone, conflict, and projection semantics |

IP and BTLE adapter seams move opaque core objects. The Rust application host
owns and pumps configured `Link` instances and wakes the authenticated runtime
when local inventory changes. Current host tests use controlled in-memory links;
the C, Go, and Python application nodes do not configure transports, and
no concrete BTLE controller is claimed. Broadcast support remains an adapter
primitive rather than a complete one-to-many replication profile. A future file
carrier can reuse the same serialized objects.

## 3. Primitive types and encoding

The protocol has two deterministic encodings. Replication messages use the RFC
8949 core deterministic encoding profile:

- definite-length arrays, maps, byte strings, and text only;
- shortest-width integer and length encodings;
- integer map keys in deterministic encoded-key order;
- no duplicate map keys;
- valid UTF-8 and no floating-point values in protocol-owned structures;
- no unregistered tags;
- maximum nesting depth 16, maximum control-message size 1 MiB, and configured
  byte/string/collection bounds before allocation;
- signed bytes MUST already be deterministic; a receiver MUST NOT normalize an
  invalid representation and then verify it.

[`wire.cddl`](wire.cddl) defines those maps. Security objects—credentials, source envelopes,
handshake flights, custody wrappers, controls, and Blob manifests—use the fixed,
length-prefixed binary structures in [envelope.md](envelope.md); the semantic-v2/v3/v4/v5/v6
batch additions use the fixed structures in §6.1. Those readers reject
truncation, trailing bytes, nonzero reserved fields, unknown critical kinds, and
lengths above their field-specific bound before allocation. A security object is
never reinterpreted as a CBOR object or vice versa.

Numeric registries in §19 define meaning. The exact domain prefixes, input-length
words, signature messages, KDF salts, labels, and contexts are normative in
[envelope.md](envelope.md); they MUST NOT be inferred from prose labels.

Security digests and semantic identifiers are 32-byte SHA-256 results. The
replication namespace uses a fixed 33-byte `ObjectID = kind u8 || digest[32]`.
Semantic version 1 permits kind `1` source envelopes and kind `2` Blob chunk
carriers. Semantic versions 2 through 6 additionally permit kind `3`
source-batch proofs, kind `4` bridge authorizations, and kind `5` bridge-route
wrappers. Semantic versions 3 through 6 additionally enable session-bound
custody records for the selected Event/RouteEvent path without allocating a new
stable transfer-object kind. Semantic version 4 adds selected protected
State/Record mechanics frames, inherited by versions 5 and 6, and semantic
version 5 adds selected Blob mechanics frames, inherited by version 6. Semantic
version 6 additionally adds an opt-in selected Event-bridge mechanics lane;
none allocates a new stable transfer-object kind. Full typed
identifiers decide ordering and dispatch; a session MAY use dictionary indexes
only after collision-safe binding to the full value.

Topic names are 1–128 bytes from `[A-Za-z0-9._-]`. Scope names use the same set
plus `/` as a hierarchy separator; empty, `.` and `..` segments are invalid.
Human-readable names occur only inside protected metadata. An authority MAY
assign opaque identifiers at provisioning time.

## 4. Identity, dots, and semantic item core

A provisioned identity contains ECDSA P-256 and ML-DSA-65 signing keys, a static
P-256 ECDH key, an ML-KEM-768 key, an authority serial, a mission identifier,
and authorized roles. `NodeID` is the
domain-separated SHA-256 digest of its deterministic credential body, exactly as
specified in [envelope.md](envelope.md) §3.1.

Every publisher has a durable 64-bit counter. A dot is `(NodeID, counter)` and
counter zero is invalid. Reusing a dot for different semantic bytes is publisher
equivocation and produces a security alert; it is never merged silently. The
accepted-dot and Event-sequence ledgers survive item garbage collection.

An identity whose complete durable store is lost MUST NOT resume publishing from
counter one. It must recover an external anti-rollback witness or be
reprovisioned with a new identity. The portable reference does not claim that a
filesystem can detect deletion of itself; this remains a deployment gate.

`ItemCore` contains:

| Order | Field | Constraint |
|---:|---|---|
| 0 | data class | registered `u8` |
| 1 | priority | `0..3` |
| 2 | topic | canonical bounded UTF-8 |
| 3 | origin scope | canonical bounded UTF-8 |
| 4 | publisher NodeID | 32 bytes |
| 5 | counter | nonzero `u64` |
| 6 | causal context | sorted unique `(NodeID, greatest counter)` entries |
| 7 | Event sequence | optional `u64` |
| 8 | logical key/stream | wire maximum 65,536 bytes; profile admission maximum 4,096 |
| 9 | Blob route commitment | tag; BlobID, nonzero chunk count, and Merkle root exactly for Blob |
| 10 | TTL milliseconds | optional `u64`; absent means durable; for non-tombstone data, zero means already expired; tombstone markers remain durable regardless of this field |
| 11 | declared content length | `u64` |
| 12 | tombstone | canonical boolean byte |
| 13 | content epoch | `u64` |
| 14 | payload | bounded byte string or authenticated Blob manifest |

`ItemID = SHA-256(u64(len("aster/item/v1")) || "aster/item/v1" ||
u64(len(binary-semantic-core)) || binary-semantic-core)` using the exact field
encoding in [envelope.md](envelope.md). The complete core is bounded at 512 MiB.

ItemID is the semantic idempotency key. Applying an already applied ItemID MUST
return the prior result without another logical revision or delivery.

## 5. Source envelope and protected metadata

Two independent key planes exist:

- a scope routing epoch key for members allowed to forward within a scope;
- a content epoch key for principals allowed to read a topic/readership group.

Possessing one key MUST NOT derive the other or any unrelated scope key.

The source computes ItemID, then derives a unique content key and nonce:

```text
ItemKey   = HKDF-SHA256(content_epoch_key,
             label="aster/content-key/v1", context=ItemID)
ItemNonce = HKDF-SHA256(content_epoch_key,
             label="aster/content-nonce/v1", context=ItemID)[0..12]
```

This is descriptive shorthand; the `PKDF` salt and encoded label/context info in
[envelope.md](envelope.md) §5.2 are part of the interoperable result.

It encrypts deterministic `ItemCore` with AES-256-GCM. Associated data binds the
wire version, suite, content epoch, and ItemID.

The protected `RouteDescriptor` repeats only forwarding and verification fields:
the publisher credential, ItemID, class, scope, topic, logical key, priority,
TTL, publisher/counter/context, Event sequence, tombstone state, declared
content length, authenticated Blob route commitment, content group/epoch/nonce,
ciphertext length, and the authentication fields selected by the envelope
format. Format 2 carries the unchanged singleton authentication-manifest
identifier and hybrid source signature. Semantic-v2/v3/v4/v5/v6 format 3 carries the exact
batch reference, Merkle path, and item ECDSA suffix in §6.1. A consumer MUST
reject if a repeated semantic field differs from decrypted ItemCore.

For stable-store wrapping, and for any future broadcast profile, the source
creates a unique opaque route selector.
`RouteKey = HKDF-SHA256(scope_routing_epoch_key,
label="aster/route-key/v1", context=selector)`. The descriptor is encrypted with
AES-256-GCM. Pairwise sessions additionally encrypt the complete replication
message, so the transport sees no descriptor fields.

`EnvelopeID = SHA-256(source-envelope-bytes)`. Relays use EnvelopeID for exact
ciphertext deduplication and resumable byte ranges; consumers recompute ItemID
after content decryption. Custody metadata is deliberately outside those stable
bytes and therefore does not change EnvelopeID.

Clear carrier data is limited to format, opaque session/key selector,
nonce/counter material, fragment position, flags, and length. Stable selectors
permit traffic correlation; encryption does not hide timing, sizes, RF energy,
or protocol presence.

## 6. Source authentication

Semantic-v1 envelope format 2 authenticates each source envelope with both ECDSA P-256/SHA-256 and
ML-DSA-65. Verification is AND: authority credential, both publisher signatures,
publisher/dot commitment, and the ItemID binding MUST pass before application
delivery. Missing or stripped signatures fail.

The fixed envelope includes a singleton authentication-manifest identifier and
both publisher signatures bind the complete canonical semantic header, including
the conditional Blob route commitment. Its bytes and meaning remain unchanged:
semantic-v2/v3/v4/v5/v6 peers MAY still use format 2 for a singleton or urgent fallback, but
no implementation may reinterpret a format-2 byte as compact batch
authentication.

### 6.1 Semantic-v2/v3/v4/v5/v6 content-committing PQ batch profile

This profile amortizes the authority credential and ML-DSA source signature
without removing post-quantum authentication. It is available only after the
authenticated session selects semantic version 2, 3, 4, 5, or 6. A batch has
`2..64` items from one publisher with one data class, topic, scope, content-key
epoch, and credential. Causal counters are nonzero and contiguous in item-index
order.
Event sequences are also nonzero and contiguous for class `1` Event; every
other class encodes `first_event_sequence = 0` and has no Event sequence.
Overflow, a gap, a mixed field, or reordered/duplicate item index rejects the
batch before publication.

For every domain `D`, this section writes
`H_D(x) = SHA-256(u64(len(D)) || D || u64(len(x)) || x)`, with unsigned
integers in network byte order. The registered domains are:

```text
aster/pq-batch-preamble/v1
aster/pq-batch-leaf/v1
aster/pq-batch-empty/v1
aster/pq-batch-node/v1
aster/pq-batch-id/v1
aster/pq-batch-signature/v1
aster/pq-batch-credential/v1
aster/pq-batch-item-ecdsa/v1
```

#### 6.1.1 Manifest

The canonical preamble has no outer length and encodes these fields in order:

| Field | Exact encoding |
|---|---|
| batch format | `u16 = 1` |
| envelope format | `u16 = 3` |
| semantic protocol | `u16 = 2` |
| complete suite | `u16 = 1` |
| hash algorithm | `u16 = 1` (SHA-256) |
| tree algorithm | `u16 = 1` (complete binary Merkle tree) |
| batch signature algorithm | `u16 = 1` (hybrid AND) |
| item signature algorithm | `u16 = 1` (P-256/SHA-256) |
| data class | registered `u8`, `0..3` |
| credential identifier | 32 bytes |
| publisher NodeID | 32 bytes |
| topic | `u16` byte length, then `1..128` canonical bytes |
| scope | `u16` byte length, then `1..128` canonical bytes |
| content-key epoch | `u64` |
| first causal counter | nonzero `u64` |
| first Event sequence | Event: nonzero `u64`; otherwise zero |
| item count | `u16`, `2..64` |

The batch adapter applies the global Topic and Scope grammar in §3 directly to
these protected strings. UTF-8 validity and byte length alone are insufficient:
a topic containing any byte outside `[A-Za-z0-9._-]`, or a scope containing an
empty, `.` or `..` path segment, is noncanonical and rejects before hashing.

The preamble is exactly `111 + topic_bytes + scope_bytes` bytes. Its commitment
is `H_preamble(exact_preamble)`. The manifest is the exact preamble followed by
the 32-byte Merkle root, so it is `143 + topic_bytes + scope_bytes` bytes.
`BatchID = H_batch-id(exact_manifest)`, and the source's batch hybrid signature
signs `H_batch-signature(exact_manifest)`.

A hybrid signature is exactly `u16(64) || p256_signature[64] || u32(3309) ||
ml_dsa_65_signature[3309]`, for 3,379 bytes. Verification is AND. A credential
with `g` route groups has an exact body length `B(g) = 3264 + 32g`, where
`1 <= g <= 256`. Its batch credential identifier is
`H_credential(exact_credential_body || exact_authority_hybrid_signature)`.
The fixed-binary parser MUST validate both embedded length prefixes; checking
only the 3,379-byte outer length is insufficient. Successful structural parsing
does not authenticate either signature. Length-valid, canonically framed but
cryptographically invalid or unverified signature bytes still fail provider
authentication and MUST NOT authorize a proof or dependent item.

#### 6.1.2 Content-committing leaves and tree

Each real leaf input encodes, in order:

```text
u16 leaf_format = 1
u16 item_index
ItemID[32]
u32 canonical_header_length
canonical envelope header bytes
ContentGroupID[32]
content_nonce[12]
u64 content_ciphertext_length
SHA-256(exact content ciphertext)[32]
```

The real leaf hash is `H_leaf(exact_leaf_input)`. Item indexes are exactly
`0..item_count-1` in order, and duplicate ItemIDs reject the construction. The
tree width is the smallest power of two not less than `item_count`. For every
padding index `j`, the empty leaf is
`H_empty(H_preamble(exact_preamble) || u16(j))`. Each parent is
`H_node(left[32] || right[32])` until one root remains.

An inclusion path contains exactly `ceil(log2(item_count))` sibling hashes,
bottom-up, with no direction bytes. The verifier derives left/right position
from successive bits of `item_index`. A short, long, reordered, superfluous, or
root-mismatching path rejects. Equal-valued sibling hashes are not by themselves
noncanonical; structure and the computed root decide validity.

#### 6.1.3 BatchProof object and compact item suffix

The batch proof is a stable semantic-v2/v3/v4/v5/v6 transfer object with `ObjectKind = 3`.
Its protected route plaintext is exactly:

```text
u8 object_kind = 3
u32 credential_body_length
credential_body[credential_body_length]
authority_hybrid_signature[3379]
manifest[143 + topic_bytes + scope_bytes]
source_batch_hybrid_signature[3379]
```

It is sealed under envelope format 3. The 44-byte public header is
`"ASTRENV3"[8] || u16(3) || u16(2) || u16(1) || u8(3) || u8(0) ||
route_selector[16] || u32(route_ciphertext_length) || u64(0)`. The protected
route ciphertext adds the suite's 16-byte authentication tag and there is no
content ciphertext. Its exact stable `EnvelopeID` is raw SHA-256 of the complete
sealed proof bytes; its typed inventory identity is `3 || EnvelopeID`.
Parsing this plaintext establishes only canonical structure and commitments.
Semantic acceptance additionally requires the provider to validate the exact
credential format and cryptographically authenticate both hybrid signatures.

Every dependent item remains ObjectKind `1` but uses envelope format 3. Its
44-byte public header is `"ASTRENV3"[8] || u16(3) || u16(2) || u16(1) ||
u8(1) || u8(0) || route_selector[16] || u32(route_ciphertext_length) ||
u64(content_ciphertext_length)`. The protected route plaintext ends with this
authentication suffix:

```text
u8 auth_mode = 1
proof_envelope_id[32]
batch_id[32]
u16 item_index
u8 proof_depth                 ; 1..6 and exact for item_count
sibling_hashes[proof_depth][32]
p256_item_signature[64]
```

The suffix is exactly `132 + 32*proof_depth` bytes. The item signature signs
`H_item-ecdsa(BatchID || proof_EnvelopeID || real_leaf_hash)`. Verification
requires the exact canonical header, ItemID, content group, nonce, ciphertext
length, ciphertext SHA-256, path, manifest, credential, authority hybrid
signature, source hybrid signature, and item P-256 signature to agree. The
application never supplies or selects verification keys.

#### 6.1.4 Dependency, version, and representation rules

A proof SHOULD be offered and transferred before its dependent items. An item
that arrives first is bounded, crash-durable unauthenticated staging charged to
the ordinary staging quota and requests the exact proof EnvelopeID. A bare
compact suffix or complete compact item without an authenticated matching proof
is **pending**, not accepted: it MUST NOT enter application state or satisfy the
source-authentication gate. An invalid proof or reference fails closed; a
receiver never silently converts the compact item to format 2.

A semantic-v1 session suppresses kinds `3..5` before inventory construction and
rejects ObjectKind 3, `ASTRENV3`, and compact authentication wherever received.
The receive gate applies to raw bytes: a semantic-v1 deterministic-CBOR decoder
rejects a canonical message containing a kind-3 ObjectID, and a semantic-v1
fixed-envelope decoder rejects an `ASTRENV3` header before route or content
dispatch.
This rule preserves all semantic-v1 format-2 bytes and corpus vectors exactly.
A semantic-v2, semantic-v3, semantic-v4, semantic-v5, or semantic-v6 session accepts format-2 singleton fallback as
well as valid format-3 proof/item representations. When both representations
are published, they share ItemID but retain distinct EnvelopeIDs, receipts,
retry completion, custody, and garbage-collection references. ItemID
deduplication occurs only at application semantics; it must not collapse stable
transfer objects.

The exact proof-envelope overhead is `P(g,s,t) = 10230 + 32g + s + t` bytes.
For `n` items the compact authentication total is
`P + n*(132 + 32*ceil(log2(n)))`. At `n=64`, `s=t=128`, the totals are 39,414
bytes for `g=256` and 31,254 bytes for `g=1`; dual publication with all
format-2 singletons is respectively 1,207,414 and 677,014 bytes. These are
serialized-byte equations, not transport-throughput or independent-
interoperability claims.

The reference exposes an explicit `publish_batch` operation rather than hidden
buffering. It atomically reserves contiguous publisher/Event ranges and commits
the proof, all compact items, accepted ledgers and metadata, plus either the
default retained format-2 singleton set or an explicit batch-only policy. Blob
items use the same source-authenticated route-commitment checks, and Rust/C/Go/
Python can atomically finalize 2–64 distinct Blob writers while keeping them
retryable after rejection. Failure before commit exposes none of the set, and
reopen reauthenticates the proof before proof-backed application reads. This
source/store/application/binding implementation and the local reference peer
runtime are green. Automated reference tests cover exact v1 singleton-only
versus v2 proof/compact inventory, batch-only proof-to-compact replication,
compact-first private restart followed by exact-proof promotion, selected-v1 compact
rejection, and finalized two-Blob proof/compact/carrier transfer with plaintext
verification. Independent interoperability, live-carrier, and 3 kbps acceptance
remain separate gates.

## 7. Causality

A version vector records the greatest represented counter for each publisher.
Schema 12 does not maintain one transitive node-global publication clock. It
maintains a direct-observation frontier for each exact `(topic, origin scope)`
domain. Publishing captures that domain's frontier before advancing the
publisher's node-global durable counter. Accepting an ordinary item or an
authenticated bridged source advances only that item's own dot in its origin
domain; the received item's asserted predecessor vector is not joined into the
frontier. This rule prevents an authenticated publisher from manufacturing
local evidence merely by signing arbitrary predecessor claims, but it is not a
complete transitive causality construction.

Each effective domain is the pointwise maximum of its exact rows and the
reserved legacy sentinel rows with `topic = ''` and `scope = ''`. Empty topic
and scope names are invalid protocol values, so the sentinel is SQLite-only and
cannot collide with an admitted item. Migration from schema 11 copies the old
node-global frontier verbatim into this sentinel and fails closed if it already
exceeds 4,096 publishers. Sentinel rows are never advanced by normal schema-12
acceptance. The exact-plus-sentinel union for any one domain is capped at 4,096
distinct publishers; adding a new publisher to a saturated domain rejects the
whole transaction. The number of domains and aggregate frontier rows are not
currently bounded.

The accepted-dot equivocation ledger remains node-global. The accepted Event
sequence ledger is keyed by publisher, topic, scope, and sequence. Both survive
normal item garbage collection, are not charged to item quota, and have no
implemented pruning or aggregate bound. The reference profile does not encode
sparse exceptions or parent IDs; these permanent ledgers detect reuse while
stored heads retain exact conflict versions.

This direct-dot design has a known transitivity limit. If A publishes `A1`, B
accepts `A1` and publishes `B1`, then C accepts `B1` without `A1`, C's next
publication records B's dot but not A's dot. Later receipt of `A1` can therefore
appear concurrent with C's publication even though B's signed context named
`A1`. Authentication proves who made a context claim, not that the claim is a
truthful or complete observation. Per-key or per-Event-stream frontiers,
transitive propagation with safe trust rules, aggregate-ledger bounds, and a
safe retirement/checkpoint protocol remain release gates; causality is Partial,
not production-accepted.

For complete clocks `A` and `B`:

- `A < B` when every counter in A is no greater than B and at least one is less;
- `A > B` symmetrically;
- equal clocks are equal;
- otherwise they are concurrent.

Vector entries MUST NOT be pruned while their publisher may return within the
declared retention policy. A future pruning profile requires an authority-signed
retirement and causal-stability proof. Wall-clock values are never consulted.

## 8. Data class reducers

### 8.1 State

Storage retains every causally maximal head and recoverable history. A descendant
projects over its ancestors. Concurrent heads project the lexicographically
greatest full ItemID; losing heads remain queryable and annotated. A resolution
publishes a new revision whose context and parents cover every resolved head.

### 8.2 Event

An Event has `(publisher, stream, sequence)`. Sequence begins at one and
increments by one. Missing sequence intervals surface as gaps. Equal tuple/equal
ItemID is duplicate; equal tuple with different ItemID is equivocation. Events
are immutable.

### 8.3 Record

A Record is a revision DAG. Every concurrent maximal revision is retained and
surfaced as a sibling in a conflict annotation. A later causally dominating
revision may remove a sibling from the current projection, but the input remains
recoverable until retention-driven garbage collection. Explicit resolution
publishes a revision whose context covers the exact observed sibling set.

Application policy is process-local and is not a replicated protocol object.
The current reference can associate an application-supplied policy ID with a
topic; `ApplicationNode::conflicts()` reports that ID while the registration
remains live. Direct and forwarded replicated ingestion never execute the
registered policy or publish an automatic resolution. Registration is not
durable across restart. Applications may compute deterministic bytes from
ascending full-ItemID-sorted sibling inputs and submit them through explicit
resolution. Any such helper MUST return identical bytes for identical canonical
inputs across every supported implementation and version; this is an
application conformance obligation, not something replicated ingestion verifies.

Consequently, sibling preservation, annotations, and explicit resolution are
implemented, but automatic registered-policy merge required by requirements
§5.3 is partial.

Code received over the mesh is never executed.

### 8.4 Blob

A Blob manifest contains total length, media/schema metadata, chunk size, ordered
SHA-256 chunk digests, and a full-content digest. Default chunk size is 16 KiB,
configurable from 4–64 KiB. Chunks use independently derived keys/nonces and are
verified and committed while streaming. A complete blob digest is verified before
delivery. The canonical manifest is at most 1 MiB and is independently
implementable from [envelope.md](envelope.md). The current durable Blob service
can resume local chunk production and reading without whole-Blob RAM growth.

The selected node's application profile fixes canonical chunks at 64 KiB. A
stopped `SelectedBlobNode` retains synchronous streaming, while
`RunningNode::selected_blobs()` returns a cloneable live handle. Live publish
takes ownership of a nonempty regular file positioned at byte zero and admits
at most 64 MiB/1,024 chunks; live read returns one freshly authenticated,
zeroize-on-drop page of `1..=64 KiB`. These application chunk/page bounds are
separate from the semantic-v5 carrier range bound of 16 KiB in §9.2.
Neither surface treats a redb projection as authorization: it freshly verifies
the selected source and current policy/lineage and requires the exact
authenticated `BlobDepotCompletion` capability before opening that depot
variant. The live page path repeats the authority and completion checks around
decryption. A contradiction among durable rows, authenticated cache state,
depot capability, or post-commit verification is `FatalBlobCoherence` and
terminates the actor after closing application admission; it is not downgraded
to an ordinary per-request error.

The manifest is the payload of a source-authenticated envelope whose signed
header commits BlobID, nonzero chunk count, and a route Merkle root. Encrypted
chunks travel as canonical `ASTRBT01` objects under kind-`2` typed ObjectIDs and
use ordinary WANT/DATA/RECEIPT ranges; Blob DATA has no custody wrapper. A
route-only relay verifies the source association, ciphertext hash/length, and
Merkle proof without a content key. A content reader additionally matches the
protected manifest record, authenticates/decrypts the chunk, and verifies the
whole digest. A reference runtime test durably interrupts a carrier larger than
64 KiB, reopens SQLite and Blob state with a new driver and sync reducer, then
requests the exact missing complement from a different authenticated route-only
peer and recovers identical plaintext. Its adversarial branch accepts a corrupt
range from an authenticated producer under the genuine ObjectID, detects the
poison only at terminal object authentication, deletes only that typed object's
staging, reopens with no poisoned progress, and completes the retransmission from
byte zero through a different honest route-only relay. This is local
reference-to-reference validation. A separate generated 101 MiB local streaming
test covers interruption/reopen, deduplication, readback, and tamper rejection
with component buffers no larger than 65,552 bytes. The different-peer runtime
case is smaller; a combined 100+ MiB different-peer run with measured process
RSS and live-carrier acceptance remains open.

The high-level and FFI Blob deduplication/read path re-inspects the stored sealed
source envelope and requires the exact authenticated route commitment and exact
manifest bytes; BlobID or manifest equality alone cannot substitute a different
route root or chunk count.

Empty manifests are canonical local objects, but envelope format 2 requires a
nonzero route chunk count, so a zero-byte Blob is not publishable in this network
profile. A manifest has at most 14,543 chunks and 1 MiB of bytes.
The composite per-contact inventory is capped at 100,000 ObjectIDs with source
envelopes inserted before Blob carriers. A source-envelope selection that alone
exceeds the cap is rejected rather than silently truncated. Content-authorized nodes retain both a
quota-accounted carrier and canonical encrypted chunk; route-only relays retain
the carrier only. Since a transfer digest is not invertible to its route/index,
local enumeration may reconstruct candidate objects from the authenticated route
tree.

### 8.5 Tombstones

A deletion is a signed revision with a dot, causal context, and all known heads
as parents. A dominating tombstone keeps ancestors deleted; a concurrent delete
and edit is a visible conflict. Tombstones and causal fences have separately
configured retention. The deployment baseline is offline tolerance plus margin
(30 days + 15 days). Returning after the configured bound can resurrect data;
bounded retention cannot prevent that indefinitely.

## 9. Exact reconciliation and resumption

For each policy-filtered snapshot selected by the embedding node, the implemented
inventory is an exact sparse nibble-radix Merkle tree keyed by the full 33-byte
typed ObjectID. It therefore has 66 nibble levels. A leaf commits to that full
typed identifier, keeping source envelopes, Blob chunk carriers, and semantic-v2/v3/v4/v5/v6
batch proofs disjoint even if their 32-byte digests collide. Internal hashes
commit to depth, ordered child summaries, and counts. ItemID, singleton/batch
identifiers, proof dependencies, and semantic fields are authenticated inside
the stable objects; they are not separate inventory fields.

The message flow is:

1. `INTEREST`: authorized joined scopes and consume/carry filters.
2. `SUMMARY`: immutable snapshot generation, root, and count.
3. `PROBE` / `NODE`: descend only unequal radix branches.
4. `OFFER`: for a bounded root fast path, the exact complete selected root
   inventory of typed object identifiers—not merely the differing identifiers.
5. `WANT`: objects or block ranges accepted under quota/policy.
6. `DATA`: one stable object byte range. Source-envelope DATA may separately
   carry its per-hop custody wrapper; Blob-chunk DATA MUST carry an empty
   forwarding field.
7. `RECEIPT`: durably stored ranges for the typed object.

Durable partial progress is peer-neutral, so a resumed `WANT` MAY reach a fresh
authenticated peer which never advertised that typed ObjectID. A receiver MUST
emit a serve action or `DATA` only when the ObjectID is present in that
contact's current authenticated, policy-filtered served inventory. A `WANT`
absent from that view is silently ignored before any object lookup; the
requester retains its bounded durable progress and MAY retry this or another
peer. Once a `WANT` is eligible for serving, backend, authorization, integrity,
and storage failures remain fatal to the contact rather than being converted
to absence.

One INTEREST admits at most 256 canonical topic selectors, 256 canonical scope
selectors, and 4,096 topic-by-scope combinations. Both locally constructed and
peer-supplied messages are checked with overflow-safe arithmetic before an
inventory backend is consulted. Exceeding any bound fails the containing
exchange; authorization filtering is not relied upon to bound database work.
When the complete selected root inventory fits both the requesting peer's
`max_offers` and the responder's local OFFER cap, a root PROBE receives that
canonical sorted unique list in one OFFER. The requester accepts it only after
the list count and recomputed sparse-inventory root exactly match the retained
SUMMARY. A validated OFFER retires the matching tree traversal; exact delayed
authenticated copies are bounded idempotent no-ops, while truncated, changed,
unsolicited, or uncommitted lists fail closed. If either limit is exceeded, the
responder sends the root NODE and uses ordinary exact Merkle descent.
An unanswered root commitment may survive a local inventory refresh only as
bounded metadata. It becomes active again only when a fresh authorized receive
baseline causes the requester to reissue that exact root PROBE; retained
unvalidated history by itself never authorizes an OFFER or creates durable work.
For an admitted INTEREST, the reference passes the complete selector sets to one
metadata-only inventory query rather than issuing one query for every
topic-by-scope pair. SQLite applies a 100,001-row `LIMIT`, retains at most the
first 100,000 metadata rows, and rejects the selection if the extra row exists;
it never collects the remainder. The generic node facade independently rejects
an over-limit vector returned by a non-SQLite `RecordStore`, so a bare node does
not silently accept a backend that violates the contract. SQLite returns
envelope identifiers, sealed lengths, and the bounded forwarding fields needed
for policy; the sealed BLOB, publisher, causal context, logical key, and
application payload metadata do not cross into the Rust inventory projection.

The canonical first WANT for a Blob carrier has unknown total length, no missing
ranges, and `need_forwarding = false`. After the first DATA establishes total
length, WANT carries the exact sorted missing ranges. Empty ranges with false
forwarding requests no work and is rejected.

A terminal full-object length, identity, route, ciphertext, source-authentication,
or policy failure atomically aborts only that typed ObjectID. Durable extents,
known total, received ranges, pending writes, hop forwarding, and commit-pending
state are cleared, and the peer-neutral request returns to the canonical
unknown-total/empty-range WANT. No inventory entry or successful receipt is
created. Transient Store, I/O, and missing-chunk failures preserve progress.

Equal roots end wire tree descent for a partition, but they do not eliminate the
local inventory snapshot. Each endpoint first performs policy-filtered metadata
selection and builds and hashes its sparse tree; that selection is capped at
100,000 objects as described above. Local snapshot work is therefore bounded
but proportional to selected inventory size, not to the set difference. After
roots differ, `PROBE` / `NODE` descent confines wire comparison to unequal tree
branches. A future optimization such as an IBLT or Bloom filter MAY be
negotiated, but every ambiguity or overflow must fall back to the exact tree; no
such optimization negotiation is implemented in profile 1.

Every exchange names immutable roots. Verified objects commit immediately.
Outstanding wants are stored by ObjectID/range, not by peer or session. Losing a
contact may restart tree traversal without discarding durably verified ranges.
Delivery is at least once; application acknowledgement state is separate from
protocol receipt state.

### 9.1 Selected semantic-v4 State and Record reconciliation

The selected mechanics profile adds State and Record when the authenticated
mission session selects semantic version `4`, `5`, or `6`. Semantic versions `1`,
`2`, and `3` retain their Event compatibility behavior and MUST NOT send,
accept, reserve, or count mutable frames. The default semantic offer is
`[6, 5, 4, 3, 2, 1]`; stable replication-wire/profile, handshake framing,
source envelopes, and suite remain version `1`. Semantic v5 inherits these
State/Record mechanics unchanged and adds the separate Blob mechanics in §9.2;
semantic v6 inherits both ordinary lanes unchanged.

State and Record are independent classes (`State = 1`, `Record = 2`). Each has
two receiver-directed lanes, so every contact has four independent reconciliation
lanes: local Offer and local Fetch for each class. Every frame carries its class
and stable receiver direction, and every object-carrying frame binds a typed
32-byte exact transfer ID. A class or direction mismatch fails the contact; one
lane can neither satisfy nor advance another. Each class exchanges its own
canonical topic/scope interest, and empty interest means receive-none.

Inventory and difference messages use bounded Negentropy frames of at most
16 KiB for at most 64 reconciliation rounds. The selected contact reserves
enough protected frame/byte budget for every lane to complete its bounded
reconciliation exchange, make at least one eligible object attempt, and finish;
Event work cannot consume that reserve. A mutable object is at most 1 MiB.
State and Record each have an independent hard admission ceiling of 4,096 rows
and 16 MiB of encoded source bytes. Existing mutable rows are not pruned to
admit a new row.

An offered object receives an exact `MutableApplyResult`. A fetched object
receives an exact `MutableFetchResult`, and the serving endpoint MUST return an
exact `MutableFetchResultAck` before it accepts another fetch or a finish on that
lane. The acknowledgement repeats class, direction, transfer ID, and
disposition. The only nonfatal dispositions are `Duplicate`, `Inserted`, and
`DeferredCapacity`. `DeferredCapacity` applies only to an otherwise-valid authenticated object
blocked by effective ordinary-aggregate or per-class item/byte capacity, the
1,024-version per-logical-key projection bound, or the causal-frontier bound. An
object over 1 MiB is structurally invalid and fatal, not deferred. Capacity
deferral does not convert malformed bytes, source failure, stale policy,
wrong class/interest, wrong route
lineage, or an integrity failure into absence or success; those remain fatal.

`MutableFinish` and `MutableFinished` carry an exact equal `remaining` count.
The count includes every authenticated difference not durably satisfied,
including a capacity-deferred attempt. Missing, duplicate, changed, or
out-of-order result/acknowledgement and finish messages fail the contact. This
makes both endpoints' bounded contact receipts agree without treating a served
byte count as durable remote admission. Event last-contact completion remains a
separate Event/status boundary and MUST NOT be interpreted as State or Record
convergence.

Every authenticated peer/class/local-mode lane has a durable 32-byte rotation
cursor. Candidate IDs are canonically sorted; selection begins at the strict
successor of the cursor, wraps at most once, and is bounded by lane capacity.
The cursor need not remain in the current difference. It advances by compare-
and-set only after the exact authenticated result/acknowledgement; a stale CAS
does not fail the contact or mutate the winner. Cursor metadata is reserved
outside ordinary item quota, is capped at 256 configured mission peers and four
rows per peer (1,024 total), and is pruned for no-longer-configured peers during
mandatory startup validation before sockets open.

Inventory, serving, admission, cursor advancement, and finish all execute under
one contact policy lease. Every State/Record candidate is freshly bound to its
current source route lineage. A same-epoch key replacement leaves an old exact
row durable for authenticated historical retry and audit but withholds that
historical lineage from ordinary current projection/query and network inventory
or transfer. An exact idempotent State publish or Record publish/resolution
operation retry MAY recover its committed historical result only through the
strict cached/projection/historical verification path.
Selected State and Record finite TTL is rejected: profile 4 defines no mutable
forwarding-age or expiry path.

`Normal` and every `AtLeast(priority)` policy run all four mutable lanes;
`AtLeast` is solely an Event emission threshold. `ReceiveOnly` initiates no
contact and sends or discloses no mutable interest, inventory, ID, or object.
This is stricter than the bounded mandatory reply traffic allowed while
receiving selected Event work.

### 9.2 Selected semantic-v5 direct Blob transfer

Semantic version `5` inherits the exact Event behavior of versions `1` through
`4` and the semantic-v4 State/Record mechanics above. It additionally allocates
one selected Blob source class (`MutableClass = 3`) and one Blob carrier lane.
Semantic version `6` inherits that complete v5 ordinary-lane behavior
unchanged. The default descending offer is `[6, 5, 4, 3, 2, 1]`. Stable replication-wire and
ABI version `1`, handshake framing, `ASTRENV2`/`ASTRENV3` source formats,
`ASTRBT01` carriers, typed ObjectIDs, and the registered cryptographic suite do
not change. A semantic-v1, v2, v3, or v4 session MUST emit, accept, reserve, and
count zero Blob interest, Blob-class mutable, Blob range, and Blob carrier
finish frames. State and Record retain their semantic-v4 behavior in v5.

The core SQLite compatibility store advances schema 14 to 15 only to admit
`origin_semantic_version = 5` in `transfer_identities`. The transactional
migration copies every existing row unchanged, retains v1-v4 provenance, and
then permits v5 provenance across restart; it does not create or migrate the
selected redb Blob staging/depot tables.

The subsequent schema-15-to-16 migration likewise rebuilds only
`transfer_identities`, copies every existing row unchanged, retains v1-v5
provenance, and permits v6 provenance across restart. It changes no stable
source, carrier, bridge authorization, or bridge-route-wrapper bytes.

The v5 protected-frame allocation is `0x6b` BlobInterest, `0x6c`
BlobInterestReply, Blob class `3` under the existing mutable source tags
`0x71..0x92`, and `0xa1` BlobRangeFetch, `0xa2` BlobRange, `0xa5`
BlobRangeResult, `0xa6` BlobRangeResultAck, `0xb1` BlobCarrierFinish, and `0xb2`
BlobCarrierFinished. Unknown, malformed, truncated, trailing, wrong-class,
wrong-direction, cross-source, cross-carrier, changed-result, and out-of-order
variants fail the authenticated contact.

Each Blob interest selector names one exact `(topic, scope, epoch)` and carries
one fixed 32-byte provider-minted `BlobPeerContentProof`. Descendant-scope and
wildcard selectors are not permitted. The proof is domain-separated over the
mission authority, authenticated claimant NodeID, exact selector, and current
content grant; it exposes no content key. The serving endpoint verifies it
against that same authenticated peer, the peer's current exact route grant, and
durable nonrevocation policy. Route authority alone is insufficient. A copied
proof cannot be replayed by another peer, and a same-epoch content-key
replacement invalidates the old proof. Old rows are withheld after such a
replacement, but the store deliberately rejects a new physical lineage for the
same `(BlobID, content group, numeric epoch)` as `PhysicalLineageConflict`;
republishing or resuming that Blob under a different physical lineage requires
advancing the numeric epoch. Terminal or stale cleanup MUST preserve that rule:
it removes pending source and prefix visibility but retains the exact depot
import, expected or committed chunk rows, any chunk files and finalized digest,
and their reserved/committed accounting. The non-public staging remains charged
to the existing `max_bytes`, `max_chunks`, and
`max_variants`/`DEPOT_VARIANT_COUNT` bounds; exact-lineage retry may resume it, a
different same-epoch lineage conflicts, and numeric epoch advance consumes
another bounded variant. It creates no table, schema, quota, or publication.
Every open-path audit requires its owner/backing binding and nonempty physical
lineage; a zero-lineage fence is corruption.

The requester repeats the proof in every BlobRangeFetch, and the sender
rechecks proof, route, revocation, source route lineage, and physical content
lineage before advertising a source and before serving every range. The
selected v5 lane is therefore direct between current content-capable peers; the
reference route-only relay design in §8.4 and `envelope.md` is not selected
here.

The current selected `aster-node` schedules this grammar automatically on its
direct-Iroh contacts after semantic-v5-or-v6 negotiation, control activation, and an
exact configured Blob receive selector. A
[retained 10,728-byte live-Blob receipt](validation/evidence/selected-live-blob-044d90f.json)
(SHA-256
`4fea2ffbd16608862a67167fb1b8fcb6d5d8b4b82c576aa9a6b7e25ee9c55909`)
binds source commit `044d90ff07c8e754b3d490cb810d42de3c915e3d` with
`Good` signature status; 45 adversarial verifier tests pass. Its
source-to-execution link remains operator-attested, not cryptographically
proven. Across three participants and 32 direct-loopback `CONTACT` records, it
observes peerless publication and seeding, an exactly-one-contact partial
transfer, exact retained-prefix persistence across a receiver reopen, an
exactly-one-contact continuation from the different eligible replica with no
source refetch and exact-complement advancement, exact byte reconstruction and
promotion, bounded live page reads, and a final receiver reopen. This is
one-host, same-implementation evidence, and every interruption or restart is a
graceful same-process actor/store/provider reopen. It does not prove distinct
physical hosts, NAT or Internet paths, controlled or public relay, BTLE,
process-crash or power-loss recovery, long-offline recovery, arbitrary-peer or
route-only resume, scale beyond three participants, resource thresholds or
soak, physical sanitization, independent-implementation interoperability, or
release authorization.

For each receiver direction, the Blob source phase completes first through the
class-separated mutable inventory/difference/Offer/Fetch/result/ack/finish
grammar. A receiver authenticates the exact source envelope, canonical
manifest, source route lineage, physical content lineage, BlobID, manifest
digest, ordered chunk records, and canonical kind-`2` carrier IDs before it
atomically installs the pending source plan. Pending source and carrier bytes
are staging only: they are absent from ordinary publication inventory, query,
read, and serving surfaces.

Only after that source phase may the carrier lane request an exact complement.
Each request is a nonempty contiguous range of at most 16 KiB and binds the
receiver direction, source transfer ID, strict 33-byte kind-`2` carrier ID,
exact total length, offset, requested length, and current content proof. The
response repeats the tuple and returns `Data` or `Unavailable`; result and
acknowledgement additionally bind the exact accepted length and one of
`Partial`, `Complete`, `Duplicate`, `DeferredCapacity`, or `Unavailable`.
Finish carries the requester's exact remaining
count and Finished echoes it; this is sequencing agreement, not an independent
responder proof of the requester's disk truth. The exact per-range Result/Ack is
the durable accepted-prefix evidence. The durable prefix is keyed by exact source and carrier, never by peer,
connection, or session. A later contact with any other authenticated,
nonrevoked peer that proves the same current exact content entitlement can
continue from the first missing byte; peer-specific cursors affect bounded
fair scheduling only and do not own progress. If one multi-carrier source ends
terminally, its scheduler position advances past the lexicographically greatest
canonical carrier ID in that source, not merely the last manifest record, so a
later eligible source cannot be stranded behind carrier order.

Every local transition that can install, repair, retire, or reconcile a Blob
source and its authenticated cache claim is serialized with the matching
durable store transition. The critical section spans no await or network I/O.
After a successful durable abort, the implementation removes the old cache
claim, rereads the exact state-neutral durable source projection, freshly
authenticates any concurrent exact restage, and only then reinstalls its claim.
No interleaving may leave an orphan claim or a durable pending source without
its authenticated claim.

Selected network admission rejects a Blob over 64 MiB of plaintext or 1,024
chunks, an exact source over 1 MiB, or one canonical carrier over 128 KiB.
Pending Blob source, manifest-record, and carrier-prefix metadata share a hard
10,000-row staging ceiling, and staged carrier-prefix bytes share a hard 64-MiB
ceiling. A range never exceeds 16 KiB, and durable carrier scheduling is bounded
to 256 configured mission peers. Saturation returns typed deferral without
evicting accepted publications or existing pending progress; malformed,
unauthorized, stale-lineage, conflicting-prefix, and integrity failures remain
fatal for the affected exact work.

Carrier completion still does not publish a Blob. The receiver verifies every
complete canonical `ASTRBT01` carrier into the encrypted depot, requires the
exact depot completion marker, freshly streams and decrypts every exact
manifest chunk, verifies every AEAD tag and per-chunk plaintext digest, verifies
the whole BlobID, and obtains a nonconstructible content-completion proof. It
then freshly obtains a nonconstructible current-lineage proof binding mission
authority, source transfer, route lineage, physical lineage, BlobID, and
manifest digest. One redb transaction requires the pending plan, both proofs,
and depot completion to agree, installs the ordinary publication/index/counter
rows, and removes the pending source and prefixes. Failure leaves no partial
publication; an exact duplicate promotion is idempotent. A completed source is
served only after the same current policy and lineage checks.

`Normal` and every `AtLeast(priority)` run Blob source and carrier work because
`AtLeast` filters Event emission only. `ReceiveOnly` initiates, requests,
advertises, sends, accepts, reserves, and counts zero selected Blob work. This
network slice adds no retained application-delivery evidence or Blob peer/
convergence status. The separate selected application layer now has a durable
metadata-only publication queue, but it does not alter this wire path or its
configured interests. This slice adds no selected route-only Blob relay/
custody, Blob TTL/expiry/garbage collection, a
metadata-independent whole-byte identity or deduplication claim, or large-file,
physical-carrier, mixed-implementation, and release acceptance.

The separate application ledger now has a
[retained 10,269-byte peerless Blob-delivery receipt](validation/evidence/selected-live-blob-subscription-26e0a09.json)
(SHA-256
`3d0c0b2da629282c56de5ae9dacc8920c9960defba083c6bff856e2c0612a675`,
Good-signed source `26e0a09`). One participant executes three processes and
four actor lifetimes on one host. Two exact source publications share one
`BlobId`; an attempt-one child flushes an unacknowledged token and receives
`SIGKILL`, then a fresh process receives attempt 2 and acknowledges it with the
persisted attempt-one token before settling both publications. The final
peerless reopen has one replayed subscription, zero pending, two acknowledged,
and an empty poll. This receipt does not amend the wire grammar or configured
interests and claims no contact, transfer, peer/convergence status,
selector/network-interest separation, TTL/GC, physical or mixed carrier,
resource/soak, reproducible-build, or release result.

The reference driver can initiate an exchange and can answer one through its
responder-with-start path, so its in-memory authenticated flow is bidirectional.
If backend storage rejects a received range, the intent remains queued for a
later attempt. Once authenticated, the driver retains causal protocol work and
uses monotonic deadlines derived from message priority, retry attempt, and the
link's reported retry floor. INTEREST, SUMMARY, PROBE, NODE, WANT, and DATA can
therefore be retried without application polling logic. Authenticated causal
responses retire predecessor work, and RECEIPT ranges retire matching DATA.
The current retry loop is bounded as specified in §18; it is not a general
congestion controller and does not claim progress under permanent or
adversarial loss.

The retained ciphertext and transfer identifier are reused for up to eight
send rounds so fragments from a lossy contact can complete one logical record.
A still-live retry then receives a fresh session record and transfer identifier;
the receiver's replay window remains authoritative. A bounded standalone NODE
response expires after those rounds and is regenerated only by its retained
causal PROBE. The responder's final handshake flight is retained until the next
authenticated session record acknowledges it causally.

Reference tests cover a forced lost SUMMARY, seeded approximately 50% frame
loss in both directions, a 96-byte MTU, and fragmented 4 KiB DATA. It converges
and commits exactly once, then re-acknowledges duplicate committed DATA so a
lost RECEIPT cannot strand the sender. This remains software
reference-to-reference validation, not the required 3 kbps/live-carrier gate.

### 9.3 Selected semantic-v6 Event bridge transfer

Semantic version `6` inherits every semantic-v5 ordinary Event, State/Record,
and Blob lane byte-for-byte. It adds one selected Event-bridge mechanics lane
inside the existing protected `ASTRFR01` record; no stable replication object,
source-envelope, suite, carrier, handshake framing, or ABI version changes.
Semantic versions `1` through `5` MUST emit, accept, reserve, and count zero v6
bridge mechanics frames.

The v6 phase begins with `BridgeHello(enabled)` and
`BridgeHelloAck(enabled)`. Both flags are canonical one-byte booleans. If either
authenticated endpoint reports false, the phase ends without disclosing route
state. When both report true, each direction may offer at most eight exact
`(bridge route wrapper, source envelope)` pairs per selected contact. The
initiator offers first; the responder then offers in the reverse direction.

Each `BridgeRouteOffer` carries the claimed 32-byte SHA-256 wrapper ID, one
length-bounded exact wrapper, and one length-bounded exact source envelope. The
receiver recomputes the wrapper ID, freshly authenticates both objects and
current bridge policy, and applies its local selection before any durable
result. `BridgeRouteResult` echoes the exact wrapper ID and reports one of
`Duplicate`, `Promoted`, `StoredInactive`, or `NotSelected`. `NotSelected` is a
nonfatal local-selection result and commits no route; malformed bytes,
authentication failure, stale policy, or a crossed identity fails the contact
rather than acquiring a disposition.

Every direction terminates with `BridgeFinish(remaining)` and an exact
`BridgeFinished(remaining)` echo. The remaining value is bounded by the
selected reconciliation cardinality limit. A receiver commits an authenticated
route before any target-authorized payload delivery. Forwarding and bridge
receipts do not open or log source payload plaintext; only a separately
content-authorized target delivery may open the committed payload, and the
selected runtime emits only its length and SHA-256 digest.

## 10. TTL and freshness without synchronized clocks

TTL is a signed duration, never an ordering timestamp. A custody wrapper carries
an authenticated nondecreasing effective-age lower bound. For a finite row,
each node persists received age and adds elapsed local monotonic residence
before offer, request, retry, send, or delivery while that monotonic clock
remains continuous. Durable and tombstone rows instead retain the maximum
received/authenticated age without charging idle local residence. Before every
selected v3 send, the sender conservatively charges
`32 + ceil(exact_sealed_event_bytes / 1024)` milliseconds for synchronous frame,
AEAD, durable-store, and final-policy work. A finite transfer is withheld when
that charged age reaches its TTL; the post-store carrier-adjacent sample must
remain within the authenticated charge or the frame is abandoned before any
application byte is written. Durable Events and tombstones receive the same age
charge even though they do not expire. The wrapper contains no wall-clock
timestamp, and profile 1 defines no cross-node wall-time adjustment.

For selected Event/RouteEvent transfer under semantic version 3, 4, 5, or 6, each offer
carries the exact 150-byte `ASTRCU03` claim defined in
[envelope.md](envelope.md) §7.1 inside a replay-checked `ASTRFR01` session
record. The claim binds the completed session transcript, transfer digest and
exact length, exchange, nonzero emission-policy revision, prior age, local
monotonic sample and hop delta, source priority, and optional source TTL. The
receiver compares transfer, length, exchange, priority, and TTL with the live
exchange and freshly verified source header. The existing `ASTRFWD1` provider
wrapper in [envelope.md](envelope.md) §7 remains a distinct legacy per-hop
object and is never reinterpreted as this semantic-v3-format session record.

The protected semantic-v3-format Event-interest request and reply, used in
semantic-v3, semantic-v4, semantic-v5, and semantic-v6 sessions, also carry the
receiver's opaque durable selector generation. Zero is canonical only for an
empty interest; otherwise the generation is at least the number of projected
selectors. The value discloses neither Carry versus Consume nor any selector
beyond the already protected interest. A send-suppression receipt is valid only
for the exact authenticated generation that produced it. Consequently a hidden
Carry-to-Consume change invalidates the old hint and permits one bounded
reoffer, including when ReceiveOnly deliberately supplies no inventory. The
sender receipt table is also bounded at 262,144 hints and deterministically
replaces a hint at saturation, so an unchanged generation may receive a bounded
duplicate offer after its exact hint is displaced.

Each v3 offer is acknowledged with a protected, exchange-bound result. The
receiver-relative `Satisfied` disposition covers both Carry retention and
Consume content acceptance. `ContentAcceptancePending` means only that the
offered bytes were retained route-only while the receiver required Consume; it
removes any suppression receipt and, while the exact item remains live and
retryable, retains the bounded retry/backoff record. For
`ContentAcceptancePending`, expiry or retirement during settlement drains the
lease without creating a retry or receipt.
Normal reconciliation may settle a retry when its authenticated common set
proves the peer already holds the transfer. Blind ReceiveOnly contacts cannot
make that inference.

If finite-TTL age cannot be bounded across reboot or power loss, the node MUST
mark the item non-forwardable until a trusted time source proves it unexpired; it
MAY retain it locally with an indeterminate-age annotation. Durable items are not
affected. An item known locally to have `age >= TTL` MUST NOT be offered,
requested, retransmitted, or sent and MUST enter garbage collection.

That trusted-time recovery rule is available to profiles that define such a
proof. The selected Event implementation does not: clock-domain loss is sticky,
the exact transfer remains withheld, and recovery requires an
application-specific replacement or a new source revision.

Session counters/windows, full ItemID deduplication, publisher counter ledgers,
mission epochs, and control-chain rollback checks ensure captured traffic is not
accepted as a new logical item. A fresh node without trustworthy time cannot
infer real age from a capture alone; provisioning epochs bound this case.

## 11. Priority, retry, eviction, and emissions

Wire priorities are fixed: 0 ROUTINE, 1 PRIORITY, 2 IMMEDIATE, 3 FLASH. Doctrine
profiles MAY change display names but not ordinals. The selected Event API signs
the caller-supplied priority directly; it does not currently apply a
topic/integrator default, cap, or override. The generic semantic `Engine` can be
configured with a global publisher-priority cap, but that is a distinct API
surface. A bridge may locally suppress or demote scheduling but never rewrite
the source-signed priority, reset custody age, or extend TTL.

When eligible work is queued, higher priority receives earlier initial
transmission and earlier retry deadlines; due work is sent in priority/queue
order while respecting the adapter's minimum retry interval. Within a priority
lane, bounded fairness and expiry urgency prevent a Blob from monopolizing a
link. At saturation, higher-priority work may replace lower-priority expendable
NODE, WANT, or DATA retries. The selected
Event-custody ledger additionally permits deterministic replacement of an
inactive equal-priority backoff hint, preferring the incoming peer's own hint,
so one peer cannot monopolize the shared bound. This never removes the custody
item or an active lease; displaced work becomes eligible again without its old
delay. Retained INTEREST, SUMMARY, and PROBE causal work is not silently
evicted. Exact queue and byte ceilings are in §18.

Committed storage pressure fixes its candidate partition once at the start of
the atomic admission. If the exact scope is short, every same-scope candidate
ranks ahead of every off-scope candidate for that transaction; otherwise all
candidates form one aggregate cohort. Within each cohort it evicts expired data
first. Consequently a simultaneous aggregate shortage can consume a same-scope
live candidate before an off-scope expired candidate. For ordinary selected
Event/RouteEvent admission, only a live row whose priority is strictly lower
than the incoming demand is eligible; eligible rows then rank unconsumed
route-only data, ascending priority, nearest expiry, oldest acceptance, and
exact key. Emergency aggregate admission for authority/control or the selected
tombstone partition may bypass that live-priority cutoff, but never the
live/non-expired protection, pending-delivery, tombstone, or retirement
exclusions. Expiry is an absolute lifetime decision and may retire an otherwise
protected row. Current keys, revocation/control state, and retained tombstone
fences use reserved quota.

The reference isolates unauthenticated transfer staging from committed-record
eviction. It reserves one quarter of configured `max_bytes`, capped at 64 MiB
and always leaving at least one byte for committed data; the remainder is the
committed ceiling. Staging is capped at 4 MiB per object,
`min(max_items, 10,000)` objects, 4,095 extents per object, and 65,536 extents
globally. An extent that exceeds a staging bound is rejected transactionally and
evicts neither existing staging nor a committed item. The 4 MiB per-object cap
is also the current runtime transfer admission limit for a source envelope,
even though the fixed envelope format has a larger bound.

Emission modes are:

- `Normal`: all eligible application traffic and configured contact initiation.
- `AtLeast(p)`: Event application objects below `p` are withheld. It does not by
  itself disable configured contact initiation, the protocol/control work
  needed to authenticate and complete an allowed contact, semantic-v4/v5/v6
  State/Record reconciliation, or semantic-v5/v6 Blob transfer; the threshold is
  Event-only.
- `ReceiveOnly`: no contact initiation, discovery, inventory disclosure, or
  application/control object transmission; mandatory connection
  authentication, acknowledgements, and bounded apply results may occur while
  ingesting authenticated inbound Event work. It initiates and discloses no
  semantic-v4/v5/v6 State/Record lane or semantic-v5/v6 Blob lane.
- `PassiveOnly`: zero framework-originated bytes; receives only unsolicited
  independently protected broadcast/push.

The selected Iroh endpoint has hosted discovery, public/default relay
substitution, and port mapping disabled in every mode; those deployment
properties are not effects of `AtLeast`. When one controlled relay is selected,
direct-plus-relay startup does not wait for relay readiness, while the explicit
relay-only mode requires readiness and disables IP transport. Neither choice
changes the Event emission meaning above. The selected API ships the first
three modes but not `PassiveOnly`. Physical emission measurement and the
distinction between receive-only protocol responses and literal radio silence
remain stakeholder-validation items.

A [retained 9,573-byte live-Event receipt](validation/evidence/selected-live-event-c464129.json)
(SHA-256
`4d71d04e4ebcc9f63c0e84e7f11e83bf1f3d1ad2ca8608486cdcc875b6dfeef0`,
signed source `c464129`) provides one bounded observation of these rules. On a
same-implementation loopback host, `AtLeast(PRIORITY)` transfers alpha
sequences 1 and 3 while routine sequence 2 remains outside negotiated eligible
work; the authenticated stream gap is `[2,3)`, while last-contact status is
complete for that negotiated policy, not `WorkRemained`. After a flushed,
unacknowledged poll, the parent forcibly terminates the receiver child; a fresh
process receives the same IDs as attempt 2 and ack/re-acks them. A later Normal
contact transfers sequence 2 and closes the gap. An authorized beta Event
remains withheld while unsubscribed; subscribing produces
`PolicyChangedSinceContact`, then removal, without a fresh post-change contact
or beta delivery. Awaiting observations have zero failed attempts. This receipt
does not establish physical/NAT/relay/BTLE, mixed implementation, scale or
resource behavior, another data class, or release acceptance.

## 12. Scopes, topics, relay, and bridge policy

Consume interest and carry interest are explicit. A node reconciles only their
union within joined scopes; it is never required to hold a global dataset. A
relay can hold routing keys and carry interest without content-read keys.

Scope hierarchy is authority signed and administrative, not implicit key
derivation. Parent membership grants no automatic child access and vice versa.
Cross-boundary propagation requires an explicit authority control containing
the bridge identity, exact directed source/target scopes and route epochs,
allowed topics, four-bit priority mask, and one-to-eight-hop bound. A bridge may
install only a narrower local topic/priority filter. Storage quota and source-
signed TTL/custody rules apply independently and cannot be widened by that local
filter.

ObjectKind `4` authorization format `2` carries an `ASTRBCA2` delegated-control
authentication bundle: a root-signed ControlAuthority credential and that
identity's hybrid signature over the complete authorization policy and exact
credential wrapper. The provider returns the authenticated signer NodeID, which
is persisted with the authorization. The former format `1` and bare root-signed
control shape are not accepted. Exact fields and signature input are in
[envelope.md](envelope.md) §6.2.

The semantic-version-2/3/v4/v5/v6 bridge path decrypts protected route metadata, evaluates
an authority-issued exact directed-edge policy plus a local narrowing filter,
and creates a destination routing wrapper around the byte-identical format-2
source envelope. ObjectKind 4 authorization controls and ObjectKind 5 wrappers
are suppressed on selected-version-1 sessions. An authorization and each hop
are hybrid authenticated; an eight-hop bound, exact path continuity, and a
no-repeated-scope rule prevent route widening and loops.

The bridge never grants payload access. Query and subscription results preserve
the source-authenticated `origin_scope` and separately expose the wrapper's
`current_scope`; consumption still requires the original scope/topic/content-
epoch grant. Application ItemID/dot/Event semantics and one durable delivery
ledger are shared across direct and bridged arrival, while wrapper routes,
receipts, outboxes, and custody remain representation specific.

The reference implements every dependency arrival order, crash-durable pending
state, restart reauthentication, receipt-aware inventory/serving, deterministic
active-path selection with verified fallback, monotonic custody, dynamic
filter/revocation/epoch checks, and quota/reference-counted lifecycle. A bridge
authorization is live only while its exact bytes have been reauthenticated in
the current process, it is the applied enabled generation high-water, and its
authority root, delegated control signer, and bridge identity are all
unrevoked. The independently contiguous bridge-control chain remains keyed by
stable `authority_id` across signer handoff; a revoked-signer pending suffix is
rejected and must be reissued from the last applied head. The
high-level Rust/C/Go/Python administration surface uses move-only enrollment and
opaque durable 32-byte authorization/route handles; it does not expose sealed
objects or keys. Cross-implementation, scale, physical-carrier, and independent
cryptographic review remain release gates. Future summarization publishes a new
derived item with provenance.

A wrapper adds no trusted tombstone-retention timestamp. The reference therefore
keeps a bridged tombstone fence protected instead of inferring an early-eviction
age; if quota pressure reaches only such protected records, admission fails
closed.

## 13. Authenticated session and downgrade protection

Suite `0x0001` is provisional and complete:

- P-256 ephemeral ECDH + ML-KEM-768;
- ECDSA P-256/SHA-256 + ML-DSA-65;
- HKDF-SHA-256;
- AES-256-GCM with 96-bit nonce and 128-bit tag;
- SHA-256.

There is no classical-only fallback inside the suite. The suite's hybrid KEM
combiner is a pre-production independent-review gate; suite encoding never
changes in place.

The four-flight handshake is `ClientHello`, `ServerHello+ServerAuth`,
`ClientAuth`, `ServerFinished`, with exact bytes in
[envelope.md](envelope.md) §8. Flight 1 contains anonymous public hello material
and a proof under the provisioned common mission control-route key; the responder
verifies that proof before parsing the ML-KEM public key or doing P-256/ML-KEM
work. Responder and initiator credentials are encrypted after the hybrid secret
exists. The final transcript binds the canonical descending semantic-version
offer, the canonical descending complete-suite offer, the responder's selected
semantic version and complete suite, both fresh 256-bit nonces, both P-256
shares, ML-KEM public key/ciphertext, the proof commitment, mission, roles,
route-grant commitments, authority credentials, and both handshake hybrid
signatures.

Both signature algorithms, the server and client empty-plaintext key
confirmations, and the encrypted 32-byte ServerFinished value MUST verify before
DATA or inventory is accepted; wire/profile `1` has no 0-RTT application data.
Clear flights contain no mission, NodeID, credential, role, or route-grant commitment. This
does not hide size/timing or identifiers available to the link or network before
flight 1.

The key schedule uses exact concatenation of the 32-byte P-256 ECDH result and
32-byte ML-KEM result, with the public transcript as HKDF salt and seven distinct
direction/protection/confirmation labels. The stable handshake framing,
credential/envelope encoding, cryptographic profile, and replication wire
profile remain version `1`. Inside that framing, a default initiator offers
semantic versions `[6, 5, 4, 3, 2, 1]`; an honest current responder selects the highest
common value, so current peers select `6`, a v5-only peer selects `5`, a v4-only peer selects `4`, a v3-only peer selects `3`, a v2-only
peer selects `2`, and a
v1-only peer selects `1`. The
selected semantic version is bound into the public transcript, key schedule,
key confirmations, and hybrid handshake authentication.

That binding provides on-path transcript downgrade resistance: an attacker who
cannot authenticate as either endpoint cannot strip or reorder the ClientHello
offer or rewrite an honest ServerHello selection. It does not authenticate the
responder's complete capability set. A valid older, modified, or rolled-back
responder using an accepted credential can select `1`, and the initiator cannot
distinguish authorized compatibility from rollback. No production downgrade
claim is permitted until an authority-signed mission minimum semantic version
and durable per-identity high-water state with explicit rollback authorization
are implemented and independently tested. Stateless cookies, resumption,
export keys, and general handshake extensions also remain separate release work.

## 14. Revocation, rekey, and zeroization

Authority control records are FLASH-priority, non-evictable items containing
mission, monotonic control sequence, previous-state hash, revoked credentials,
and key epoch transitions. Each format-2 record embeds a root-signed
ControlAuthority credential and is hybrid-signed by that delegated identity;
the fielded bundle contains only the delegated node identity seed, never the
authority-root signing seed. Both components of both hybrid signatures must
verify. Lower sequences or a fork from an accepted state are security failures.

The store persists the signer with every control and keys the one mission-wide
head by stable `authority_id`, so changing delegated signers does not create an
independent history. Revocation takes effect in chain order. A control from an
already revoked signer is rejected before admission; if an earlier pending
suffix becomes reachable only after its signer has been revoked, the entire
unapplied dependent suffix is rejected and removed, and a live signer must
reissue it from the exact applied head.

This log is deliberately single-writer and provides no consensus among
simultaneously active ControlAuthority credentials. Rotation therefore requires
an operational handoff: the new signer needs its root-signed credential and the
trusted exact current sequence/envelope head, and the old signer must cease
writing before the new signer appends. Concurrent next-link claims are a fork
and fail closed. Another pre-provisioned delegated signer can recover from loss
or revocation of one signer only when it has that exact head. The root
provisioner has no in-band override. Total history loss, intentional fork
replacement, or recovery without an exact trusted head requires a separately
specified root-signed control epoch/cutover plus an externally persisted
high-water mark; neither mechanism is defined by this profile.

Schema 11 is the first durable schema that attributes ordinary and bridge
controls to their delegated signers. An empty schema-10 control state upgrades,
but opening a schema-10 store containing any control row fails closed pending a
future signed cutover/import procedure or creation of a fresh store. The
implementation does not guess a signer for legacy rows.

After receiving revocation, a node rejects new sessions and source attestations
from that credential. ScopeEpoch format `0` remains a legacy activation of an
independently pre-provisioned epoch and does not exclude a holder of that key.
Format `1` carries one through 128 sorted recipient packages. The authority
generates a fresh scope route key, fresh per-topic content keys, and a hidden
random salt per recipient grant; each package combines fresh P-256 ECDH and
ML-KEM-768 and is bound to the mission, authority, control-chain link, scope,
epoch, complete package set, recipient credential, and salted topic grant.
Only a durably applied control can activate. A matching nonrevoked recipient
authenticates and decapsulates the complete package before removing any
pre-placed key for that scope/epoch and installing its replacements; an omitted,
credential-mismatched, or locally revoked node removes stale grants and installs
none. The signed recipient set is also the dynamic route authorization set for
that epoch. Applied controls are reauthenticated and their packages
redecapsulated on reopen. Exact bytes and bounds are in
[envelope.md](envelope.md) §6.

The provisioner persists recipient public credentials in a separately signed,
append-only `ASTRRKR1` administrative registry; the mesh does not distribute
that registry. Preventing rollback after complete authority storage replacement
requires the operator to persist the last registry generation independently and
enforce it on import. High-level application and language-binding rekey calls
exist, but complete public-registry import/management is not provided. Old keys
may still decrypt retained history under policy. A captured holder of the old common
control-route key can see the encrypted control's package metadata, recipient
identifiers, and sizes, but an omitted holder cannot recover hidden grant salts,
topic lists, or fresh epoch keys.

Provisioning artifact protection is local and out of band. `ASTRPB03` is the
reference's bounded plaintext inner representation; its checksum is not
authentication or at-rest protection. A provider-owned outer artifact MUST NOT
change identity, credential, grant, suite, or replication bytes. The reference
exposes a replaceable, fail-closed protection boundary, but the boundary alone
does not admit a provider or establish a persistent secret store.

Zeroization destroys in-memory identity, package, scope, content, session, DRBG,
and cached-plaintext material, then calls platform keystore/destruction hooks.
Destroying a hardware-backed wrapping key is the preferred persistent mechanism.
Software cannot promise physical erasure from flash and documentation MUST NOT
claim it.

The selected Unix unprotected-reference hook is narrower and explicit. It
closes application admission, joins the live Blob worker, commits terminal
store lockout, and overwrites/synchronizes/truncates the retained mission bundle
and carrier-identity files. It preserves redb rows and encrypted Blob depot
files for terminal-safe inspection. Loss of the retained mission/content
secrets is bounded cryptographic shredding; it is not ciphertext-file deletion,
rollback resistance, snapshot/backup/swap removal, or physical sanitization.

Revocation takes effect at an honest disconnected node only after the record
arrives. It cannot erase keys or plaintext already captured.

## 15. Carrier, fragmentation, broadcast, and loops

On a bound ordered stream, carrier framing is a bounded length plus session
ciphertext. On datagrams, a compact core header contains format/flags, opaque
transfer token, fragment index/count or range, and payload length. The full frame
is authenticated before semantic parsing. Fragmentation and reassembly are owned
by the core runtime; IP and BTLE adapters carry opaque core fragments and MUST
NOT create an incompatible adapter-specific fragmentation protocol. For an MTU
too small for mandatory security overhead, the core uses the link's reported MTU.

The selected Iroh carrier additionally supports one controlled route below the
Aster mission session. Configuration pins exactly one HTTPS relay root origin of
at most 2 KiB: it must have a host, use the root path, and contain no user
information, query, or fragment. Trust is explicitly either the embedded WebPKI
root set or one to eight nonempty DER CA roots, each at most 64 KiB and at most
256 KiB combined.
An explicit DER set replaces WebPKI; there is no insecure TLS mode, trust
fallback, or second/public/default relay candidate. Hosted address lookup and
port mapping remain disabled.

A controlled `PeerRoute` serializes to at most 3,072 bytes and binds the exact
Iroh endpoint ID, the sole relay origin, and zero to eight sorted unique initial
direct socket locators. The reusable carrier API accepts all eight; the current
`aster node` CLI supplies one initial socket for each existing `--peer` value.
These are initial locators,
not lifetime address pins. Iroh may probe direct and relay paths in parallel and,
after authenticating the exact endpoint, may derive later direct paths through
its NAT negotiation. The profile therefore makes no direct-first ordering,
temporal fallback, or representative NAT claim. Relay-only binding supplies no
IP transport and waits for the pinned relay to become ready; direct-plus-relay
binding retains IP and does not block startup on relay readiness.

A retained implementation receipt separately observes this selected carrier
through one cone/direct and one restrictive/controlled-relay Docker Linux
namespace-NAT cell on one physical host. That evidence does not change the
normative route semantics above: the cone cell uses exact operator-known static
mappings; the receipt makes no discovery or punching claim, records final
Direct/Relay observations rather than a temporal fallback sequence, and grants
no representative, physical, public-network, independent-implementation, or
release credit.

For one authenticated connection, a `PathWitness` reports the last observed
Direct or Relay selection and at most 1,024 coalesced observed path-kind
transitions. Ordinary path closure retains the last selection. A missing initial
observation or lost observation continuity reports Unknown, and lost continuity
or reaching the transition cap marks the witness saturated. This telemetry is
diagnostic only: it never establishes endpoint or mission identity, admission,
authorization, receipt validity, or replication success.

The controlled Iroh relay is connectivity infrastructure below peer QUIC; it is
not the payload-blind Aster Event relay described in §12 and holds no Aster store
or route grant. The route-only Blob relay design remains unselected. Adding this
carrier path changes no semantic version, stable replication wire/profile or C
ABI version, security-object format, source object, or `aster-carrier/1`
framing.

Reassembly is bounded globally and per authenticated adjacency. Duplicate
segments are harmless. Length overflow and excessive sparse state fail within
the fragment operation. Malformed fragments, inconsistent overlap or changed
counts, a route-hint mismatch, and unauthenticated transfer-token reuse are
discardable carrier input: the driver evicts volatile reassembly when needed and
continues without rebinding or failing the authenticated contact. Each partial
transfer retains its exact adapter route independently of its transfer ID;
anonymous and routed fragments, or fragments from two routed peers, cannot form
one logical frame. An incomplete transfer idle for ten minutes is removed from
both the route table and reassembler. At the 16-transfer limit, admission evicts
the least-recently-active partial from both structures. Blob blocks bound RAM
and stream to disk. The reference adjacency admits at most 16 incomplete logical
frames using at most 4 MiB of aggregate reassembly bytes. Filling that volatile
byte budget drops only incomplete fragment state so a retained sender can refill
it. One pump processes at most 64 discardable carrier failures before yielding.

After one logical transfer authenticates successfully, the driver retains a
FIFO completion record keyed by adapter route and transfer identifier with the
logical length and SHA-256 digest. The cache is capped at 1,024 entries.
Identical repeats are ignored, while reuse of the same route/identifier for
different completed logical bytes is discarded as unauthenticated carrier
input. Entries are recorded only after the handshake flight or session record
authenticates; this cache is transport replay defense, not application-level
ItemID deduplication. Once a session record authenticates, a subsequent wire,
synchronization, backend, or internal-contract failure is fatal to the contact;
the discard rule cannot mask authenticated protocol errors.

The runtime handshake receive path validates without consuming the current
linear cryptographic state until a flight succeeds. A rejected ServerHello,
ClientAuth, or ServerFinished therefore leaves the exact prior state and its
single retained outbound flight available for retransmission; the runtime does
not reconstruct the transition from a second provisioning-bundle copy. An
adapter route is only a local routing hint. A configured route is exact,
including the distinction between anonymous and routed delivery, and a mismatch
is discarded before fragment decoding. An unknown contact permits bounded
per-transfer route candidates until one complete logical handshake flight
verifies; that flight's route becomes the candidate used for replies, and the
route is committed when the full session authenticates. A valid or captured
flight 1 can therefore pin an unknown responder to its apparent route even
though the mission proof in that flight is not full peer identity. Deployment
rate limits and contact replacement remain necessary for that residual; only
the authenticated session identity can authorize or bind peer state.

The adapter contract can report broadcast capability and the simulated BTLE seam
can emit one opaque payload to multiple listeners. The reference does not define
or implement a complete broadcast replication capsule, Trickle suppression,
randomized NACK/repair aggregation, or loop-bounded one-to-many runtime. Those
remain protocol and physical acceptance work; ordinary pairwise reconciliation
must not be treated as broadcast validation.

## 16. Discovery and link profiles

Every IP local-discovery packet is exactly 64 bytes and has mandatory zero
padding. An advertisement is `type=1 u8 || nonce[16] || proof[16] || zero[31]`.
The nonce is fresh OS cryptographic randomness. The provisioned 128-bit
discovery token is never transmitted. The proof is the 16-byte output of
HKDF-SHA-256 with salt `"aster/ip-discovery-proof/v1"`, IKM equal to the
discovery token, info equal to the 16-byte nonce, and output length 16. A valid
advertisement is not by itself a discovered endpoint. Its receiver draws a
fresh 16-byte challenge and sends `type=5 u8 || announcement_nonce[16] ||
challenge[16] || proof[16] || zero[15]`. The advertiser answers only while that
announcement nonce remains in its own issuance cache, using the same format
with type `6` and the response-role proof. Legacy 33- and 49-byte packets,
trailing bytes, and nonzero padding are ignored.

Both confirmation proofs use HKDF-SHA-256 with salt
`"aster/ip-discovery-confirmation/v1"`, IKM equal to the discovery token, and
output length 16. The challenge info is `1 u8 || announcement_nonce[16] ||
challenge[16]`; the response info is the same transcript with role byte `2`.
The receiver admits the candidate only when a valid response carries its exact
outstanding challenge from the same socket address that supplied the
advertisement. Admission consumes that exact `(source socket, announcement)`
pending record, so a duplicate response does not discover the endpoint again.
Recent local announcements are bounded at 128 entries. Emitted responses are
deduplicated by `(source socket, announcement, challenge)`. A replay from one
socket therefore cannot collide with or directly consume the exact pending
record for another socket. It can still contend for the shared bounded caches:
distributed replay across enough apparent sources can delay a legitimate
exchange until entries expire. Pending records are bounded at 256 globally and
8 per canonical source IP; emitted-response records are bounded at 1,024
globally and 32 per canonical source IP. IPv4 and its IPv4-mapped IPv6 form
share one quota. All three classes expire after 30 seconds and are pruned before
lookup or reuse.

This confirmation prevents a captured advertisement alone from redirecting a
receiver to a passive replayer. It proves neither peer identity nor physical
proximity: an active party that relays the challenge and response in real time
can remain the apparent socket endpoint. Discovery therefore identifies only a
bidirectionally reachable candidate. The fresh hybrid handshake remains
mandatory for peer identity and authorization. Manual and provisioned endpoints
enter that same authentication path. Equal 64-byte request and response sizes
prevent discovery payload or IP/UDP-wire amplification when the response uses
the request's source address family. They do not prove source ownership. A
captured valid announcement—or a token holder's synthesized announcement—with a
spoofed source can still consume up to that apparent source's bounded quota and
the global pending quota. Distributed replay and large shared-NAT populations
also contend for those finite caches. Public or hostile-link deployment
therefore requires anti-spoofing and ingress rate controls. Constrained modes do
not advertise.

The current link contract exposes MTU, optional estimated bandwidth, cost,
emission footprint, broadcast capability, nonblocking send/receive, discovery
enablement, a retry floor, and the next requested wakeup. The SDK cannot choose
a transport for an item. The reference runtime consumes MTU and retry timing;
the high-level host currently selects configured carriers round-robin and does
not yet optimize for cost, bandwidth, emission, or broadcast capability.

The IP adapter prefixes opaque data with `type=0 u8` and accepts UDP datagrams no
larger than 65,507 bytes only from an explicitly registered endpoint. A DATA
datagram from any other source is discarded before route construction or core
delivery. Explicit registration is either direct `register_peer` provisioning or
an embedding's `register_endpoint` call after it selects a discovery- or
rendezvous-produced candidate; discovering an address does not register its DATA
route automatically. One nonblocking receive poll examines at most 64 UDP
datagrams, including ignored control or unknown-source traffic, before yielding
`None` to the host. This bounds adapter work per pump call; it does not promise
fair delivery on a socket kept saturated by an attacker. Its rendezvous
registration is exactly 160 bytes: `type=2 || pairing_token[32] || zero[127]`.
Prior 33- and 64-byte registrations, nonzero padding, and zero tokens are
ignored. The
peer response is `type=3 || pairing_token[32] || address`,
where address is `4 || IPv4[4] || port u16` or `6 || IPv6[16] || port u16`; and a
punch is `type=4 || pairing_token[32]`. The response token MUST match a locally
outstanding token and the response MUST come from the server bound to that
specific attempt before its address is used. A response is one-shot. Its peer
address becomes the only source allowed to present the corresponding punch;
`accept_punch` is the explicit exception for the reciprocal endpoint that has
not first received a server response. Zero tokens are rejected. Client attempts
are capped at 128 and expire after 120 seconds. Failed registration sends restore
the exact prior attempt state. The high-entropy pairing token is a rendezvous
capability, not peer authentication, and is visible to the rendezvous service.
The service processes at most 64 datagrams per poll and admits 4,096 waiting
registrations globally, at most 64 per canonical source IP. IPv4 and its
IPv4-mapped IPv6 form share one quota. Waiting registrations have an absolute
120-second lifetime that duplicate registration cannot refresh. The 160-byte
request plus a conservative 48-byte IPv6 UDP/IP header is 208 bytes. The
largest reflected chain attributable to one request is a 52-byte IPv6 peer
response and a 33-byte punch, each with that 48-byte header, totaling 181
bytes. This remains non-amplifying under the stated accounting model.

Before sending either reply, the server atomically reserves their exact
combined payload size from a global 4,096-byte response bucket that refills
monotonically at 1,024 bytes per second and from a 1,024-byte bucket for each
distinct canonical source IP that refills at 256 bytes per second. A pair whose
two endpoints have the same canonical IP charges that source bucket once; a
mixed-source pair charges the full pair to each source. IPv4 and its
IPv4-mapped IPv6 form are one canonical source. Source-bucket state is capped
at 4,096 entries and expires after 120 idle seconds. All required buckets are
checked before any is deducted, and a missing source bucket is created only
after a successful reservation. Exhaustion retains the first registration for
a later retry. A send failure conservatively spends the reservation while
retaining the waiting registration and its source count for a later attempt.
These limits preserve global capacity for another source when one canonical
source exhausts its share and bound repeated completed-pair egress. Hosts behind
one NAT share a source budget. Rotating spoofed source IPs can still occupy the
finite source-bucket table, so a publicly exposed UDP service requires
deployment anti-spoofing and rate controls. Reference bounds are 4,096 peers and
4,096 discovered addresses. Local/direct operation has no infrastructure
dependency; restrictive NAT/firewall pairs may require rendezvous or the
separately deployable opaque ciphertext relay.

The reference ciphertext relay pairs two outbound TCP connections that present
the same nonzero random 32-byte channel and otherwise copies length-delimited
opaque frames. Default server admission permits 256 active pairs and 64 accepted
sockets per source IP. Source accounting begins at accept and follows a socket
through join validation, the waiting-channel map, and active forwarding; an
IPv4-mapped IPv6 source is counted with the equivalent IPv4 address. An active
pair is closed after 120 seconds without a successful read or write in either
direction. Waiting channels are separately bounded at 4,096 and expire after
120 seconds; at most 256 join validations are pending.

`RelayLink::send` validates and copies at most one 65,535-byte frame, then uses
nonblocking queue admission. Each inbound and outbound client queue is bounded
at 256 frames and 4 MiB; saturation returns `WouldBlock`. Success means the
outbound frame was accepted by the local queue, not that the TCP write completed.
Socket writes run asynchronously. A later socket failure or ten-minute queued
write deadline marks the link disconnected, closes it, and makes subsequent
sends fail with `BrokenPipe`; it cannot retroactively fail an already returned
send call. A complete four-byte inbound length header must arrive within 120
seconds. After a valid length, the body deadline is `30 seconds + ceil(frame
length * 8 / 1,024) seconds`; the maximum 65,535-byte frame therefore has 542
seconds. This bounds partial-header/body retention while leaving margin for the
requirements profile's low-single-digit-kbps link.

The per-source default is deliberately configurable. Two relay endpoints behind
one public NAT normally consume two of that address's 64 socket admissions, so a
large shared-NAT deployment may need a higher value. Raising it reduces that
source-level denial-of-service boundary but does not remove the global
active-pair limit. A zero or monotonic-clock-unrepresentable active-pair idle
timeout is rejected during relay configuration, and deadline construction also
fails closed rather than panicking.

The active idle timeout is a reclamation bound, not a proof against slow-client
slot retention: any successful byte transfer resets it, while a legitimate pair
that is completely quiet for the interval is closed. Automatic relay reconnect
is not supplied by `RelayLink`; the embedding owns that policy.

An embedding may explicitly turn a discovered or rendezvous-selected candidate
address into a process-local 32-byte routing handle before beginning the
authenticated handshake. The adapter draws a fresh 32-byte seed when it opens
and computes HKDF-SHA-256 with salt `"aster/ip-endpoint-handle/v1"`, IKM equal
to that seed, info equal to the canonical address encoding above followed by a
one-byte retry counter `0..15`, and output length 32. It selects the first
nonzero value that does not collide with another address. This NodeID-shaped
value is never a wire field or an authenticated identity, is stable only for
that adapter instance, and cannot by itself authorize peer state. Reusable host
composition still requires the expected NodeID to be bound to the candidate
before data exchange; automatic unknown-identity composition remains open.

The BTLE crate is a platform-neutral seam for opaque service data, MTU reporting,
L2CAP/GATT capability selection, and advertisement delivery. Its simulation can
exercise those contracts, but no concrete controller driver currently performs
live L2CAP or GATT I/O. Core persisted object progress and the Rust host's link
pump are link neutral; the missing controller and physical run prevent a live
claim that a transfer survives BTLE disconnect or MTU change.

Every replication message is serializable; a future file carrier can exchange
CBOR sequences across separate physical trips without a live call stack.

## 17. Versioning and extensions

Carrier revision, stable replication-wire/profile version, negotiated semantic
version, cryptographic suite ID, and object/data-class registries are separate.
A transport addition changes none of them. `PROTOCOL_VERSION` and the legacy C
`aster_protocol_version()` report stable replication-wire/profile version `1`;
the unambiguous replication-wire surfaces also report `1`, while the default and
highest-supported semantic-version surfaces report `6`.

The current handshake negotiates semantic versions `6`, `5`, `4`, `3`, `2`,
and `1` and the complete suite `0x0001`. Offers are nonempty, nonzero,
duplicate-free canonical descending lists of at most 16 values. The responder selects the highest common semantic
version and its locally preferred complete common suite; the initiator requires
both selections to have been offered and to be locally supported. Semantic `1`
permits transfer object kinds `1` (source envelope) and `2` (Blob chunk).
Semantics `2`, `3`, `4`, `5`, and `6` additionally permit the reserved kinds `3`
(source-batch proof), `4` (bridge authorization), and `5` (bridge-route
wrapper). Semantics `3`, `4`, `5`, and `6` add the bounded session custody
record in [envelope.md](envelope.md) §7.1; none allocates another stable object
kind. Semantics `4`, `5`, and `6` enable the §9.1 selected State/Record
mechanics frames; semantics `5` and `6` enable the §9.2 selected Blob mechanics
frames. Semantic `6` preserves all v5 ordinary-lane bytes and additionally
enables the mutually opted-in §9.3 selected Event-bridge mechanics frames. A
v1-v3 selected-node session filters all mutable frames, v4 filters all Blob
frames, and v1-v5 filter all v6 Event-bridge frames, completely.
A v1 session filters
those extended kinds before inventory-root construction and rejects them in
messages, durable progress, and transfer events rather than silently processing
v2/v3/v4/v5/v6 semantics. Semantic 1 also rejects envelope format 3 and compact batch
authentication. Semantics 2, 3, 4, 5, and 6 permit both the unchanged format-2
singleton and the §6.1 format-3 batch representation; negotiated semantics
never rewrite stored stable bytes.

Durable ranged-transfer progress records the immutable semantic version under
which the object was first admitted. A source object first admitted under v1 may
resume on v1, v2, v3, v4, v5, or v6; a source first admitted under v2, v3, v4,
v5, or v6 may resume only on v2, v3, v4, v5, or v6. Recognized stable Blob carriers admitted
under any supported version may resume on any supported version, while extended
kinds `3..5` resume only on v2, v3, v4, v5, or v6. Migrated progress
without trustworthy origin-version provenance is suppressed rather than guessed.
Selected mutable State/Record transfer itself remains v4/v5/v6-only, selected
Blob mechanics remain v5/v6-only, and selected Event-bridge mechanics remain
v6-only regardless of the stable source object's earlier compatibility
provenance.
Eligibility filtering occurs before page limits so incompatible early rows
cannot starve later compatible work.

Deterministic-CBOR map keys `64` and above are ignorable extensions, while
unknown keys `0..63` fail. Fixed-binary registries are closed. The current
source-envelope decoder rejects unknown data classes, so opaque forwarding of a
future class is aspirational rather than implemented behavior. New semantics,
formats, or registry entries MUST allocate new values rather than changing
stable version-1 bytes in place. The authenticated mission floor and peer
high-water gate in §13 is required before negotiated v1 fallback is authorized
for downgrade-sensitive production use.

Before 1.0, the project MUST publish minimum support windows, authority rollback
format, registry allocation policy, and test fixtures. Stored envelopes remain
self-describing and forwardable by a node that cannot consume them.

## 18. Error and resource behavior

All untrusted lengths/counts are checked before allocation and arithmetic is
overflow checked. Invalid authenticated data fails the containing object or
contact without panicking. Unauthenticated carrier damage is discarded within
the bounded work limits below. Authentication failure reveals one
indistinguishable error externally. Rate, byte, fragment, partial-transfer,
peer, and handshake limits are configured.

The reference adapter and authenticated adjacency enforce these work,
outbound, and replay limits:

| Resource | Bound | Saturation behavior |
|---|---:|---|
| retained retry records | 128 entries | higher priority replaces lower-priority expendable work first; selected Event custody may replace an inactive equal-priority backoff hint deterministically without deleting the item or an active lease; otherwise backpressure or deferred WANT |
| one-shot logical outbox | 128 entries | new one-shot work returns explicit backpressure |
| retained handshake flight | 1 entry | a causal authenticated next flight replaces or retires it |
| combined pending logical bytes | 16 MiB | checked before every retry insert/refresh, outbox insert, and handshake replacement |
| selected mutable object | 1 MiB | oversized State/Record bytes fail before durable admission; malformed or unauthorized bytes remain fatal |
| selected mutable class | 4,096 rows and 16 MiB encoded source bytes, independently for State and Record | an otherwise valid new object receives `DeferredCapacity`; no existing mutable row is pruned |
| mutable fairness cursor | 256 configured mission peers, 4 peer/class/local-mode rows each, 1,024 rows total | startup rejects an overbound configured set and prunes rows for peers no longer configured; ordinary data quota cannot consume the reserve |
| live application command lane | 32 commands shared by Event, State, Record, and Blob; one queued command for the joined Blob worker | a full Blob worker queue returns explicit `ResourceLimit`; shutdown and zeroization close both admissions and join the worker |
| live Blob publication | one owned nonempty regular file at byte-zero cursor, at most 64 MiB and 1,024 fixed 64-KiB chunks | invalid shape is rejected; overbound input returns `ResourceLimit`; a source changed across the two passes returns conflict and cannot silently rebind the operation |
| live Blob plaintext page | `1..=64 KiB`, spanning at most two canonical chunks | zero or overbound requests are rejected; the returned allocation zeroizes on drop; durable/cache/depot coherence loss is actor-fatal |
| logical sends per pump | 128 | remaining due work keeps its monotonic deadline |
| UDP datagrams examined per adapter poll | 64 | yields `None`; a later poll may continue queued input |
| discardable unauthenticated carrier failures per runtime pump | 64 | yields with the contact intact; subsequent valid input can progress |
| durable/deferred WANTs | 10,000 objects by default | compact metadata remains retryable without retaining ciphertext or payload |
| incomplete fragment transfers | 16 transfers, 4 MiB aggregate, 10-minute idle TTL | exact per-transfer routes prevent cross-route assembly; idle/least-recently-active partial route and reassembly state are evicted together |
| completed transfer records | 1,024 entries | FIFO eviction; conflicting unauthenticated route/transfer-ID reuse is discarded within the per-pump failure budget |
| discovery recent announcements | 128 entries, 30-second TTL | new announcement returns backpressure until an entry expires |
| discovery pending confirmations | 256 globally, 8 per canonical source IP, 30-second TTL | exact source-socket/announcement key; excess admission is ignored |
| discovery emitted responses | 1,024 globally, 32 per canonical source IP, 30-second TTL | exact source-socket/announcement/challenge key; excess admission is ignored |
| rendezvous client attempts | 128 entries, 120-second TTL | zero tokens reject; responses are one-shot and bound to the attempt's server and selected peer endpoint |
| rendezvous waiting registrations | 4,096 globally, 64 per canonical source IP, absolute 120-second TTL | at most 64 datagrams are processed per poll; duplicates cannot refresh lifetime; excess admission is ignored |
| rendezvous global response egress | 4,096-byte burst, 1,024 bytes/second monotonic refill | both replies atomically reserve their exact combined payload bytes; exhaustion retains the first registration |
| rendezvous per-source response egress | 1,024-byte burst, 256 bytes/second monotonic refill per distinct canonical source; 4,096 entries; 120-second idle TTL | each distinct source is charged the full pair once; IPv4-mapped IPv6 is canonicalized; shared NATs share a budget; source state is created only on successful atomic reservation |
| relay inbound header/body | 120-second header; body is 30 seconds plus length at 1,024 bps (542 seconds maximum) | deadline closes the client link and releases queued capacity |
| DATA production per WANT | 16 messages of at most 64 KiB payload each | each backend batch is queued before expanding the next WANT; excess returns backpressure |
| INTEREST selectors | 256 topics, 256 scopes, 4,096 topic-by-scope work units | rejected before inventory selection |
| policy-filtered inventory snapshot | 100,000 metadata objects | SQLite reads at most cap plus one in one query; cap-plus-one and over-limit custom-store results reject the exchange rather than truncate |

The shared 16 MiB counter covers each retained retry's fixed `Message` value,
every owned nested string/vector capacity, any duplicate variable prefix held in
its retry key, and its sealed record, plus every one-shot and handshake record
capacity. Fixed retry/key fields other than `Message`, tree/deque node and spare
container storage, allocator headers, and compact deferred-WANT metadata are not
in that byte counter; their entry counts are bounded separately above. The cap
therefore describes retained logical buffers, not total process RSS.

When retained space is saturated, a durable receiver WANT is never silently
discarded. It remains in peer-neutral sync state with a compact retry marker,
can send a fresh authenticated one-shot WANT while saturated, and is promoted
back to retained retry work when space opens. Non-WANT excess is rejected with
explicit backpressure. This preserves receiver progress without claiming
unbounded buffering or delivery under permanent loss.

The Tier-2 design uses bounded queues, one storage writer, streaming blobs,
event-driven wakeups, and configurable duty cycles. Inventory selection and
routine quota/garbage-collection lifecycle scans use metadata-only projections
rather than materializing sealed envelopes or causal contexts. Those operations
remain O(N) metadata scans and collect bounded result vectors in memory. Actual
deletion victims and affected reducer groups still take the full decode path,
and application projection materializes selected records. Paged/incremental
maintenance and representative measurements remain release-scale gates, so the
implementation does not yet establish the 10,000-item Tier-2 memory/latency
target.

Finite storage means convergence is defined over items retained by declared TTL
and visible quota/eviction policy. Evictions and conflicts surface to the app.

## 19. Initial registries

| Registry | Values |
|---|---|
| class | 0 State, 1 Event, 2 Record, 3 Blob; every other value rejected in profile 1 |
| priority | 0 Routine, 1 Priority, 2 Immediate, 3 Flash |
| message | 1 Interest, 2 Summary, 3 Probe, 4 Node, 5 Offer, 6 Want, 7 Data, 8 Receipt |
| transfer object kind | semantic 1: 1 source envelope, 2 Blob chunk; semantics 2 through 6 add 3 source-batch proof, 4 bridge authorization, 5 bridge-route wrapper; semantics 4 through 6 add selected State/Record mechanics frames, semantics 5 and 6 add selected Blob mechanics frames, and semantic 6 adds selected Event-bridge mechanics frames, without allocating another object kind |
| source envelope format | 2 singleton hybrid authentication; semantics 2 through 6 add 3 content-committing batch authentication |
| batch authentication mode | 1 exact proof reference, Merkle path, and P-256 item signature |
| suite | `0x0001` provisional hybrid reference suite |
| map field | unknown `0..63` critical; unknown `64..2^64-1` optional |

New allocations require specification text, conformance vectors, security and
compatibility analysis, and a unique numeric value. Reusing a withdrawn value is
forbidden. The closed fixed-binary magic, kind, and role registries are in
[envelope.md](envelope.md) §2; the deterministic-CBOR field registry is in
[wire.cddl](wire.cddl).

## 20. Known bounds

- Offline revocation is not instantaneous and cannot revoke already known data.
- NAT traversal cannot always succeed without rendezvous/relay infrastructure.
- Exact elapsed TTL over an unmeasurable powered-off interval is unknowable.
- Bounded tombstones cannot prevent resurrection after their retention bound.
- Encryption does not hide traffic analysis.
- PQ handshakes/signatures remain large; caching/batching reduces frequency only.
- Format 2 carries a full credential and two large signatures per singleton
  source envelope. The semantic-v2/v3/v4/v5/v6 provider and atomic explicit batch
  source/store/application path plus reference peer proof/compact runtime
  amortize transferred verification bytes, but the required 3 kbps end-to-end
  measurement and independent interoperability remain separate gates.
- Link-, network-, rendezvous-, or discovery-layer identifiers observed before
  the first Aster handshake flight can still correlate contacts.
- Recipient-excluding rekey is implemented in the core fixed profile, but its
  public recipient registry requires an independently persisted generation
  high-water mark after authority storage replacement. High-level rekey calls
  are shipped, but complete public-registry import/management is not.
- Delegated authority keys remove the replicated authority-root signing seed,
  but the control history is a single-writer authenticated log, not consensus.
  Signer handoff requires a trusted exact head; total history loss and
  authorized fork replacement have no defined root-signed epoch/reset or
  external chain high-water mechanism in this profile.
- Typed Blob chunk transfer and different-peer range resume are verified in the
  in-memory reference runtime. The separate retained selected-node receipt now
  observes one bounded exactly-one-contact partial and exactly-one-contact
  different-eligible-peer resume across graceful same-process reopens on one
  host. A separate generated 101 MiB local streaming case passes with bounded
  component buffers, but a combined 100+ MiB different-peer run with measured
  process RSS and a live carrier remains an acceptance gap. Zero-byte Blob
  publication is not supported by envelope format 2.
- A custom hybrid composition needs independent cryptographic review.
- Literal passive silence cannot request, authenticate interactively, or ACK.
- The Rust application host owns and pumps configured link instances, while the
  native language bindings remain transport-neutral local application APIs.
  Current authenticated host/timer-retry tests use controlled in-memory links.
  The bounded retry loop is not a general congestion controller and has no
  permanent-loss or physical live-carrier liveness claim.
- Broadcast is only an adapter primitive; a complete protected one-to-many
  replication and repair protocol is absent.
- An external independent implementation is required before interoperability can
  be claimed; reference-to-reference tests alone are insufficient.
