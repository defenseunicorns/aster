# Decision 0012: Content-committing post-quantum signature batches

- Status: accepted and implemented in the reference; external acceptance gates remain
- Date: 2026-08-18

## Decision

The reference profile will amortize ML-DSA only across a bounded set of exact
source items. It will not use a reusable counter-range credential which merely
authorizes an ECDSA key. Such a credential would make a classical-signature
break sufficient to forge new item contents and would therefore weaken the
current hybrid source-authentication claim.

A batch contains 2 through 64 items from exactly one publisher, data class,
topic, scope, and key epoch. Causal counters are one contiguous nonzero range.
For Event batches, event sequence numbers are also one contiguous nonzero
range; the manifest encodes zero for the event-range start for every other data
class. Priority, TTL, logical key, payload, tombstone status, and causal context
remain per-item values committed by each leaf.

The source produces one protected `BatchProof` transfer object and one compact
source envelope per item. The proof contains the source credential and one
hybrid P-256 + ML-DSA-65 signature over a canonical manifest and Merkle root.
Each compact envelope contains a fixed-width P-256 signature, its Merkle
inclusion path, and references to both the manifest BatchID and the exact
BatchProof EnvelopeID. Every item therefore requires all of the following:

1. the authority's hybrid signature on the source credential;
2. the source's hybrid signature on the exact batch root;
3. a valid, canonical inclusion proof for the exact item leaf; and
4. the source's P-256 signature over that leaf and the exact proof references.

Batch proofs and compact envelopes use the fixed semantic-protocol construction
marker `2` and are valid only on an authenticated adjacency which selected
semantic protocol version 2 or 3 and complete suite `0x0001`. The current
implementation offers the canonical descending version list `[3, 2, 1]`; a
v2-compatibility implementation may offer `[2, 1]`, and selection remains the
responder's highest common version. An adjacency which selected version 1 is
deliberately singleton-only and must neither inventory nor transfer a batch
proof or compact envelope. Version 2 introduced this representation; version 3
inherits it without changing its source bytes or removing the version-1
format-2 singleton representation.

Changing an item while retaining a public batch proof consequently requires a
SHA-256 second preimage/collision or a new ML-DSA signature even if P-256 is
broken. P-256 remains independently checked on every item.

"Independently verifiable offline" means that the compact item and its exact
named BatchProof form a closed offline verification set: no session, source
contact, infrastructure, time service, or plaintext access is required. A bare
compact envelope without its proof is deliberately not accepted or exposed as
a stored item. Requiring every compact envelope to repeat the ML-DSA proof
would be self-contained but could not satisfy transfer deduplication.

## Canonical cryptographic construction

All integers below are unsigned big-endian. Text is the already constrained
canonical UTF-8 topic or scope, encoded as `u16 length || bytes`. Fixed-width
fields have no length prefix. Length overflow, trailing bytes, noncanonical
text, nonzero reserved values, and unknown mandatory algorithm identifiers are
terminal errors.

The algorithm registry for batch format 1 is:

- hash algorithm 1: SHA-256;
- tree algorithm 1: Aster complete binary Merkle tree described below;
- batch signature algorithm 1: ECDSA P-256 **and** ML-DSA-65;
- item signature algorithm 1: fixed-width 64-byte ECDSA P-256 `(r || s)`.

The construction uses the existing length-delimited `hash_domain` operation.
Distinct domains are mandatory for the batch preamble, real leaves, empty
leaves, internal nodes, BatchID, batch signature, credential identifier, and
per-item ECDSA signature. The intended labels are:

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

The `/v1` suffixes above version the Aster-specific cryptographic construction;
they do not assert semantic protocol version 1. This first construction is
carried only by semantic protocol version 2 or 3.

No label may be reused by a singleton signature, control, credential, content
AEAD, or transport handshake.

### Batch preamble and manifest

The preamble contains every manifest field except the Merkle root, in exactly
this order:

```text
batch_format             u16 = 1
envelope_format          u16 = 3
semantic_protocol        u16 = 2
complete_suite           u16 = 0x0001
hash_algorithm           u16 = 1
tree_algorithm           u16 = 1
batch_signature_algorithm u16 = 1
item_signature_algorithm u16 = 1
data_class               u8  = 0..3
credential_id            32 bytes
publisher                32 bytes
topic                    u16 length || UTF-8 bytes
scope                    u16 length || UTF-8 bytes
key_epoch                u64
first_causal_counter      u64, nonzero
first_event_sequence      u64, nonzero only for Event; zero otherwise
item_count                u16, 2..64
```

The manifest is `preamble || merkle_root:32`. For topic length `t` and scope
length `s`, its exact length is `143 + t + s` bytes. The BatchID is:

```text
hash_domain("aster/pq-batch-id/v1", manifest)
```

`credential_id` is the domain-separated hash of the exact canonical credential
body and its exact authority hybrid signature encoding. The publisher must be
the NodeID derived from that credential. The credential must be for the local
mission and authority and complete hybrid suite `0x0001`.

The credential's canonical encoding version is distinct from the negotiated
semantic protocol version. A batch proof reuses the same authority-issued
credential and NodeID that make its retained format-2 singleton representation
verifiable by a version-1 peer; it does not rewrite a version field and thereby
derive a different publisher identity. The current credential encoding remains
version 1 and is admitted by semantic versions 1, 2, and 3. Semantic versions 2
and 3 instead bind the fixed construction marker through the proof and compact
public headers, manifest, authenticated session, and signatures described here.
These bindings prevent credential, authority, mission, suite, protocol, or
publisher substitution while preserving one cross-version source identity.

The source hybrid-signs
`hash_domain("aster/pq-batch-signature/v1", manifest)`. Both signature families
are mandatory; an implementation must not interpret a missing family as a
different algorithm or fallback mode.

### Leaves and complete tree

For actual item index `i`, where `0 <= i < item_count`, the canonical leaf input
is:

```text
leaf_format               u16 = 1
index                     u16 = i
item_id                   32 bytes
header_length             u32
canonical_envelope_header header_length bytes
content_group             32 bytes
content_nonce             12 bytes
content_ciphertext_length u64
content_ciphertext_sha256 32 bytes
```

The header must contain the manifest publisher, data class, topic, scope, and
epoch. Its causal counter must equal `first_causal_counter + i` without
overflow. For Event it must contain event sequence
`first_event_sequence + i`; for every other class event sequence must be absent.
ItemID remains the domain-separated hash of the plaintext core, so the leaf
binds both semantic identity and the exact protected metadata. The ciphertext
hash additionally makes content-ciphertext tampering fail route-only source
verification instead of waiting for a content reader's AEAD check.

The real leaf is:

```text
hash_domain("aster/pq-batch-leaf/v1", leaf_input)
```

Let `width` be the smallest power of two greater than or equal to `item_count`
and `depth = log2(width)`. Positions from `item_count` through `width - 1` are
not made by duplicating a real leaf. Empty position `j` is:

```text
hash_domain(
  "aster/pq-batch-empty/v1",
  hash_domain("aster/pq-batch-preamble/v1", preamble) || j:u16
)
```

Each parent is:

```text
hash_domain("aster/pq-batch-node/v1", left:32 || right:32)
```

This produces one unambiguous complete tree. Every actual item carries exactly
`depth` 32-byte siblings in bottom-up order. Left/right placement is derived
from the corresponding bit of `i`; no direction flags are encoded. Since the
batch bound is 64, `depth` is at most 6. Short, long, duplicate, reordered, or
superfluous paths are rejected.

This Merkle composition is Aster-specific. It combines admitted NIST
primitives but is not claimed to be a standardized aggregate-signature scheme.
ML-DSA has no admitted aggregation operation in this design, and no external
aggregate-signature implementation is introduced. Independent cryptographic
review is a release gate.

### BatchProof object

Batch objects use typed ObjectKind 3, `SourceBatchProof`. Its ObjectID digest is
the SHA-256 of the exact stable proof bytes, just as for an ordinary source
envelope. It is not the BatchID. Exact-byte identity is required so partial
ranges from different peers cannot be combined across alternate encodings.

The proof uses the 44-byte version-3 protected-envelope public header with
semantic protocol 2 and complete suite `0x0001`, a zero content length, and one
route-layer AES-256-GCM tag. Its route plaintext is:

```text
object_kind                    u8 = SourceBatchProof
credential_body_length        u32
credential_body               credential_body_length bytes
authority_credential_signature encoded hybrid signature
manifest                      143 + topic_len + scope_len bytes
source_batch_signature         encoded hybrid signature
```

The public header is AEAD associated data. The protected route is readable by a
route-authorized relay for the exact scope and epoch but opaque to outsiders.
It contains no application payload or content key.

After the proof is sealed, its exact EnvelopeID is known. Each per-item P-256
signature is then computed over:

```text
hash_domain(
  "aster/pq-batch-item-ecdsa/v1",
  batch_id:32 || proof_envelope_id:32 || leaf_hash:32
)
```

This ordering avoids a circular proof identity while binding every compact
item to the one exact proof encoding that must accompany it.

### Compact item envelope

Compact items use `ASTRENV3`, envelope format 3, semantic protocol 2, complete
suite `0x0001`, and ordinary Data kind. Format 2 remains the existing
self-contained semantic-version-1 singleton encoding; a parser never guesses
an authentication mode across formats.

After the common Data route fields (`item_id`, canonical header,
`content_group`, `content_nonce`, and content-ciphertext length), a compact
route has this exact authentication suffix:

```text
authentication_mode u8 = 1 (content-committing batch)
proof_envelope_id   32 bytes
batch_id            32 bytes
item_index          u16
proof_depth         u8, 1..6
siblings            proof_depth * 32 bytes
item_ecdsa_signature 64 bytes
```

The suffix is canonical and has length `132 + 32 * proof_depth` bytes. It
contains no credential, ML-DSA public key, authority credential signature, or
ML-DSA batch signature. A verifier hashes the actual content ciphertext,
reconstructs the leaf and root, validates all manifest/range equality checks,
then verifies the fixed P-256 signature with the credential from the exact
proof object.

Authentication mode 0 is not assigned in format 3. Unknown modes fail closed.
Changing the outer format, semantic version, suite, mode, algorithm identifiers,
BatchID, proof EnvelopeID, range, index, header, ciphertext, path, or signature
must not cause fallback to singleton or classical-only verification.

## Durable lifecycle and dependency rules

### Source publication

The first integration exposes an explicit atomic `publish_batch`/`commit`
operation; it does not silently buffer ordinary `publish` calls. This preserves
the existing guarantee that an ordinary disconnected publish succeeds locally
without an unbounded wait for future items.

Decision 0044 permits an internal transaction optimization for ordinary Event
publication: the selected-node actor may atomically group adjacent compatible
ordinary publishes that are already admitted in its bounded command lane. It
never waits for a future publish to complete a group. Each input retains its
own operation key, result, singleton source representation, and independent
failure outcome. This no-wait grouping therefore preserves the immediate
publication rule above and is not this decision's explicit cryptographic batch.

Batch construction follows this order:

1. reserve the complete contiguous causal-counter range and, for Event, the
   complete event-sequence range with one compare-and-swap reservation;
2. build every core, content ciphertext, real leaf, empty leaf, and root;
3. build and hybrid-sign the BatchProof, seal it, and calculate its exact
   EnvelopeID;
4. sign and seal each compact item; and
5. when the selected publication policy requires future version-1 delivery,
   build and seal one complete format-2 singleton for every logical item; and
6. commit the proof, all compact items, any required singleton representations,
   accepted-dot/event ledgers, and outbox dependencies in one SQLite
   transaction.

No receipt is returned until step 6 commits. Randomness, signing, encoding,
quota, or I/O failure before commit leaves neither counters nor a partial proof
visible. In dual-representation mode, proof, compact items, and singleton
representations commit together or none of them commit. A process crash after
commit exposes the whole publication set on reopen. Item deduplication and
semantic ItemIDs remain per item, not per batch.

The explicit batch accepts 2 through 64 items. Reaching 64 is a mandatory
flush boundary. A change of publisher, class, topic, scope, or active epoch is a
mandatory boundary and cannot be represented in one proof. Implementations may
offer a monotonic elapsed-time convenience flush only for a durably persisted
draft; wall time is never a correctness input. Shutdown, zeroization,
revocation, or epoch transition aborts an uncommitted in-memory draft rather
than emitting a cross-boundary proof.

### Cross-version representation

A batch-only publication cannot later be delivered to a version-1 peer. Relays
cannot convert either representation because doing so requires a new source
signature over a different canonical envelope. If mission policy requires
future version-1 reachability, the source must use one of these policies:

1. **Retained dual representation.** At batch commit, atomically create and
   retain the exact format-2 singleton representation of every logical item in
   addition to the proof and compact representations. This is the default safe
   policy for intermittent and store-and-forward operation because later
   delivery does not depend on the source being online.
2. **Source-only deterministic materialization.** Before advertising an item
   to a version-1 adjacency, the source follows one canonical materialization
   procedure, signs and seals the format-2 singleton once, and durably persists
   those exact bytes and its outbox state atomically. "Deterministic" describes
   the canonical choice and durable result; it does not assume signatures or
   sealing randomness can be recreated byte-for-byte. This option is available
   only while the source retains valid signing and grant state. It is never
   available to a relay.

Because a future peer's supported version may be unknown while the source is
offline, the mission must choose batch-only or retained-dual policy at publish
time. A mission that may require version-1 delivery must retain dual
representations rather than relying on later materialization.

The two envelope representations carry the same authority-issued source
credential, publisher NodeID, semantic ItemID, and accepted causal dot, while
retaining separate exact EnvelopeIDs, transfer receipts, and per-peer outbox
state. Receiving both representations applies and exposes the logical item at
most once. A relay must never synthesize a compact batch item from a singleton
or a singleton from a compact batch item.

### Receiving and restart

BatchProof bytes and compact item bytes retain independent exact ranged-transfer
staging. Successful proof processing is ordered as follows:

1. verify exact transfer identity and route AEAD;
2. verify authority credential, manifest canonicality, BatchID, and both source
   signature families;
3. durably commit the proof and its indexed `(BatchID, proof EnvelopeID)`
   mapping; then
4. retry dependent pending items and atomically promote only those whose full
   verification succeeds.

A compact item received first on a selected-version-2-or-3 adjacency is stored
only in a bounded `pending_batch_items` area keyed by exact item EnvelopeID and
proof EnvelopeID.
It is not inserted into `items`, causal/event acceptance ledgers, subscriptions,
or the application-visible query index. Its parsed dependency causes a Want for
typed ObjectKind 3. A missing proof is a dependency state, not an authentication
success and not a terminal item failure.

On reopen, committed proofs are reauthenticated before dependent items are
retried. Pending bytes and the dependency edge are crash durable and
peer-neutral. A proof with a wrong exact digest resets only its transfer
staging. A proof whose exact bytes fail cryptographic verification permanently
invalidates that proof identity; dependent items naming it cannot be accepted.
No alternate proof bytes may be spliced under the same EnvelopeID.

### Inventory, ordering, retention, and quota

ObjectKind 3 uses the existing Offer/Want/Data/Receipt ranged-transfer flow only
when the authenticated adjacency selected semantic protocol version 2 or 3 and
complete suite `0x0001`. No proof bytes are embedded in forwarding metadata.
For every selected compact item, inventory includes its proof unless the peer
has already acknowledged that exact proof EnvelopeID. The scheduler emits the
proof before its dependent items and one broadcast proof may satisfy every
reachable receiver and all 64 items. Correctness still tolerates reordering
through durable pending state.

An adjacency which selected version 1 inventories, Wants, transfers, and
receipts only format-2 singleton source envelopes. It must never advertise or
serve ObjectKind 3 or a format-3 envelope. An adjacency which selected version
2 or 3 may use either format-3 batch objects or format-2 singleton objects,
including the urgent fallback. Consequently, a selected-version-1 peer receives
the retained or source-materialized singleton representation, never an attempted
translation by a relay.

A proof is route-authorized for exactly its manifest scope and epoch. It is
advertised only when at least one dependent item is otherwise eligible for the
peer's topic/scope, emission, TTL, revocation, and bridge policy. Proof transfer
does not authorize transfer of a dependent item which policy filtered out.

The proof's effective scheduling priority is the highest currently selected
dependent priority. It has no independent TTL. Durable reference counts prevent
proof eviction while an accepted, outbox, staged, or pending compact item
depends on it. Eviction first applies the existing item policy and deletes an
unreferenced proof only after the last dependency is gone. The proof is charged
once to committed quota; pending unauthenticated objects remain under the
separate staging quota and cannot evict committed items.

When dual representation is enabled, both exact representations and their
independent outbox/receipt state are charged to committed quota. Eviction may
remove a representation only when policy no longer requires delivery through
the versions it serves; it must not leave a version-1 outbox referencing only a
batch representation.

Relays verify the credential, batch signature, inclusion path, ciphertext hash,
and item ECDSA signature using routing plaintext only. They never receive a
topic content key or payload plaintext.

## Revocation, replay, downgrade, and over-authorization

- A proof from a revoked publisher and every dependent item are rejected for
  new ingestion or serving under the same revocation policy as singleton items.
  Batching does not create a post-revocation authorization window.
- The current implementation offers semantic versions `[3, 2, 1]` in canonical
  descending order; a v2-compatibility implementation may offer `[2, 1]`. The
  complete offer and selected version are already bound
  by the authenticated mission proof, handshake transcript, KDF inputs, hybrid
  handshake signatures, and key confirmations. Stripping or reordering an
  offer, or changing a version selection, therefore fails the handshake rather
  than silently disabling batching.
- Legitimate selection of version 1 with a version-1 peer is not an error. It
  constrains that adjacency to the complete format-2 singleton representation.
  A version-2-or-3 implementation must reject ObjectKind 3 or a format-3 envelope
  received on a selected-version-1 session. A version-1 parser rejects the
  critical unknown object kind or envelope format as intended.
- The proof public header, manifest preamble, compact public header, leaf
  header, and verification context must all agree on construction marker 2,
  envelope format 3, and complete suite `0x0001`; the authenticated session must
  have selected semantic version 2 or 3. A missing BatchProof can never be
  reinterpreted as semantic version 1, format 2, or ECDSA-only authentication.
- Scope and epoch must equal in the proof manifest, compact header, local route
  grant, and active-store policy. A proof cannot span an epoch transition.
- `first + count - 1` must not overflow. An index outside the count, a causal
  counter outside the exact range, or a nonmatching Event sequence is rejected.
- Accepted-dot and accepted-event ledgers remain authoritative across item GC
  and restart. Replaying a proof is idempotent by exact EnvelopeID and BatchID;
  replaying an item is at-least-once duplicate delivery, never a new item.
- A different credential, publisher, class, topic, scope, epoch, root, count,
  range, proof object, leaf, or index cannot be substituted because the
  credential identifier, manifest signature, Merkle path, and item signature
  must all agree.
- Unknown format, semantic version, suite, hash, tree, or signature algorithm
  identifiers fail closed. There is no classical-only interpretation of a
  missing proof or missing ML-DSA signature.

## Exact authentication-overhead accounting

The accounting below covers stable source-authentication bytes. Payload, normal
header fields, content AEAD ciphertext/tag, route AEAD tag already counted in
the proof formula, deterministic-CBOR message framing, fragmentation, and
peer-specific forwarding metadata are reported separately by transport tests.
Changing the fixed-width semantic-protocol value from 1 to 2 changes no field
length, so all batch-only formulas remain unchanged. Dual representation adds
retained bytes and signing work; it does not alter either wire encoding.

For the current credential with `g` route-grant commitments:

```text
credential body B(g)
  = 3264 + 32g

encoded hybrid signature H
  = (2 + 64) P-256 + (4 + 3309) ML-DSA-65
  = 3379

current singleton repeated authentication A_single(g)
  = 4 + B(g) + H + 32-byte singleton BatchID + H
  = 10058 + 32g
```

For topic length `t`, scope length `s`, and the proposed proof format:

```text
manifest M(s,t)
  = 143 + s + t

proof object P(g,s,t)
  = 44-byte public header
  + 16-byte route AEAD tag
  + 1-byte object kind
  + 4-byte credential length + B(g)
  + H authority credential signature
  + M(s,t)
  + H source batch signature
  = 10230 + 32g + s + t

compact authentication suffix A_item(n)
  = 132 + 32 * ceil(log2(n))

total batch authentication A_batch(n,g,s,t)
  = P(g,s,t) + n * A_item(n)

retained dual-representation authentication A_dual(n,g,s,t)
  = A_batch(n,g,s,t) + n * A_single(g)
```

The implementation test must calculate these values from actual serialized
objects and also assert the closed-form values; a formula-only test is not
sufficient.

At the worst declared bounds `n=64`, `g=256`, `s=128`, and `t=128`:

```text
proof depth                 = 6
P                           = 18,678 bytes
A_item                      = 324 bytes
A_batch                     = 39,414 bytes
virtual 3,000-bit/s time    = 39,414 * 8 / 3,000
                            = 105.104 seconds total
                            = 1.64225 seconds/item

64 singleton authentications = 64 * 18,250
                              = 1,168,000 bytes
virtual singleton time        = 3,114.667 seconds
reduction                     = 29.63x
A_dual retained               = 39,414 + 1,168,000
                              = 1,207,414 authentication bytes
```

At `g=1` with the other declared bounds unchanged:

```text
A_batch                       = 31,254 bytes
virtual 3,000-bit/s time      = 83.344 seconds total
                              = 1.30225 seconds/item
64 singleton authentications = 64 * 10,090
                              = 645,760 bytes
reduction                     = 20.66x
A_dual retained               = 31,254 + 645,760
                              = 677,014 authentication bytes
```

The 3 kbps acceptance test uses decimal 3,000 bits per second and must pass all
of these conditions for 64 items, maximum topic/scope lengths, and both `g=1`
and `g=256`:

- batch authentication transfer time is at most 120 seconds;
- amortized authentication time is at most 2 seconds per item;
- byte reduction versus 64 current singleton authentications is at least 20x;
- exactly one ML-DSA public key, one authority ML-DSA credential signature, and
  one source ML-DSA batch signature occur in the transferred verification
  closure; no compact item contains ML-DSA bytes.

These are authentication-overhead gates, not a claim that arbitrary payloads
finish in that interval. End-to-end low-rate tests must add actual payload,
wire, fragmentation, retransmission, and forwarding overhead.

Batch-only source creation performs one hybrid source batch signature and one
per-item P-256 signature for each of the `n` items. The authority credential
hybrid signature already exists and is transferred once in the proof. Retained
dual representation additionally performs `n` complete hybrid singleton source
signatures. It therefore has no publisher post-quantum signing-work reduction
relative to singleton-only publication; it performs one additional ML-DSA
signature for the batch proof, as well as the batch-path P-256 work. Source-only
later materialization defers, but does not eliminate, those singleton signing
costs.

`A_dual` is a committed-storage and quota consequence, not the amount sent to a
version-2-or-3 peer. A version-2-or-3 transfer which selects the batch
representation still sends `A_batch` and retains the stated amortization. A version-1 link
sends the singleton representation and therefore has the singleton baseline
cost and no 3 kbps batching gain.

## Safe singleton and urgent fallback

Existing format-2 singleton envelopes remain the fail-closed compatibility and
urgent path. They are semantic-version-1 objects, carry the complete credential
and full hybrid item signature, and require no BatchProof dependency. They are
the only source-data representation allowed on a selected-version-1 adjacency;
a selected-version-2-or-3 adjacency may carry either these singletons or the
construction-marker-2 batch representation.

- Ordinary `publish` remains an immediate singleton-representation operation.
  The implementation may group only already-admitted compatible operations in
  one local durable transaction as specified by Decision 0044; it never waits
  for future work and does not create a `BatchProof`.
- Flash/urgent items never wait for a batch. The singleton fallback is available
  on every selected protocol version; a version-2-or-3 adjacency can carry format 2.
  An already complete explicit batch may still be committed in the same call.
- An explicit batch with fewer than two items is rejected rather than silently
  changing authentication mode; the caller may publish those items as
  singletons.
- A batch construction or atomic commit failure produces no compact item. The
  caller may retry the uncommitted requests as singleton items without reusing
  an accepted causal dot.
- A receiver never falls back to ECDSA-only verification when a compact item's
  proof is missing, has been lost, or is invalid.

## Implementation and remaining acceptance work

The reference now implements the canonical envelope provider, explicit
`publish_batch` application/engine surface, retained-dual default and explicit
batch-only policy, Blob batch publication, and one all-or-nothing SQLite
transaction for the proof, every compact item, every required singleton,
publisher/Event range advancement, accepted ledgers, dependencies, and outbox
metadata. Quota admission is decided only after the complete candidate set is
formed; any construction, quota, or store failure rolls back the whole batch.
Reopen reauthenticates stored proofs before proof-backed application reads.
Rust, C, Go, and Python expose the same retained-dual/batch-only transaction and
atomic finalization of 2–64 distinct Blob writers; a failed Blob batch leaves
those writers open and retryable. Ordinary `publish` remains an immediate
singleton-representation operation; Decision 0044's no-wait local group commit
does not change the cryptographic batch contract.

The store also implements durable proof/pending/material paging, exact guarded
range reads, per-peer attempts and receipts, proof-before-compact ordering,
custody-preserving pending promotion, singleton-on-compact registration, and
durable rejected-proof state. The focused receipt-gating regression, complete
store test group, FFI 12/12, Go 8/8, Python 9/9, linked C/C++ smoke, and strict
store/FFI lint gates pass. Peer inventory, Want, serving, ingest, receipt gating,
and dependency promotion are implemented. Focused evidence verifies exact v1/v2/v3
representation inventory, proof-first batch-only replication, compact-first
private staging across restart followed by exact-proof promotion, selected-v1
compact rejection, and a finalized two-Blob proof/compact/carrier transfer with
plaintext verification.

Acceptance still requires independently authored interoperability, live-carrier,
3 kbps, scale, and production-security work. The credential codec distinguishes
its stable encoding version from the negotiated semantic version so the same
credential and NodeID remain valid in both representations. Inventory, Want,
serving, and ingest must gate ObjectKind 3 and format 3 on the authenticated
session's selected semantic version. Required tests include exact codecs, mutation of
every binding field, missing/wrong/substituted proof rejection, Merkle path
negatives for every tree depth, revoked/old-epoch behavior, proof-first and
item-first delivery,
cross-peer partial resume, crash at every commit boundary, atomic dual
representation, source-only materialization restart, logical-item deduplication
and credential/NodeID equality across both representations,
selected-version-1 suppression and rejection, offer-strip/reorder downgrade
rejection, version-2-or-3 singleton fallback,
quota/eviction reference integrity, relay no-plaintext and no-conversion
canaries, broadcast deduplication, and the serialized 3 kbps accounting gate.

No new dependency or external implementation input was used to define this
contract.

## Semantic-v4 inheritance amendment (2026-08-25)

This amendment supersedes the earlier present-tense statements that the
current/default offer is `[3, 2, 1]`. They remain above only as the historical
negotiation boundary of the v2/v3 batch decision and its evidence.

Semantic version 4 inherits the unchanged semantic-v2 batch object kinds,
`ASTRENV3` bytes, proof/compact dependency rules, atomic publication behavior,
and semantic-v3 Event custody behavior. It does not allocate a new batch
format, source-envelope version, ObjectKind, credential, suite, or stable
replication-wire version. Default/highest negotiation becomes 4 with offer
`[4, 3, 2, 1]`; v1-v3 Event compatibility remains intact.

The only v4-only addition in this slice is selected protected State/Record
mechanics. Those class- and direction-separated interest, Negentropy, object,
result/acknowledgement, and finish frames are session mechanics rather than
batch source representations. A v1-v3 contact must not send or accept them.
Consequently, this amendment does not turn a State/Record object into a compact
batch, change retained-dual policy, or grant new batch/bridge acceptance credit.

## Semantic-v5 inheritance amendment (2026-08-25)

Semantic version 5 inherits the same semantic-v2 batch bytes and all v3/v4
behavior without allocating another batch format, ObjectKind, source-envelope,
suite, or wire version. Default/highest negotiation becomes 5 with offer
`[5, 4, 3, 2, 1]`. The v5-only selected Blob source/carrier mechanics use the
existing source representations and `ASTRBT01` kind-2 carriers; v1-v4 emit zero
Blob mechanics frames. This creates no additional batch acceptance claim.
Independent v4 interoperability and a fresh complete release receipt remain
required.
