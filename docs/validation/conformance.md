# Aster Conformance Plan

- Plan version: 0.1.0
- Protocol under test: Aster 1.0 draft

The target conformance program is black-box. A system under test (SUT) would
implement the small local control contract below while synchronization travels
through real Aster wire messages. JSON result documents would include
protocol/suite versions, vector digest, seed, capabilities, exact pass/fail
results, and packet captures where relevant. That scenario harness and SUT
contract are a plan, not a shipped executable feature.

Passing the reference implementation against itself is necessary but is not the
independent-interoperability acceptance claim.

Profile-`0x0001` fixed security-object bytes and bounds come from
[envelope.md](../envelope.md) and the semantic-v2/v3/v4/v5 batch profile in
[protocol.md](../protocol.md) §6.1; replication CBOR comes from
[wire.cddl](../wire.cddl). The bounded profile-`0x0002` implementation is
documented separately in the
[classical Iroh-QUIC profile](../classical-iroh-security-profile.md). A test
harness MUST retain those namespaces and must not normalize a rejected encoding
or retry another profile after a profile/ALPN/policy failure.

The shipped conformance runner and checked-in corpora remain profile-`0x0001`
artifacts. Profile `0x0002` currently has same-implementation unit and real-Iroh
integration tests only; complete normative byte grammar, independent vectors,
packet captures, and a black-box SUT lane remain open and receive no
conformance credit.

The shipped `aster-conformance` runner provides four stable entry points:

```text
aster-conformance --self-test
aster-conformance --emit-vectors
aster-conformance --emit-batch-vectors
aster-conformance --check-wire-hex HEX
```

The generated corpus is checked in at `conformance/vectors/wire-v1.tsv` so an
independent implementation can consume it without linking the reference core.
`ACCEPT` rows must decode and re-encode byte-for-byte; `REJECT` rows must be
rejected before semantic dispatch. The current corpus has 10 ACCEPT and 21
REJECT rows. The Rust verifier requires every ACCEPT row to raw-decode,
canonical re-encode to identical bytes, and pass typed semantic decoding; every
REJECT row must fail typed decoding. The accepted evolution row retains an
unknown key-64 bounded nested value in the raw-value path even though the typed
version-1 message ignores its semantics. Negative rows cover deterministic-CBOR
form, identifiers, critical extensions, prefix form, range ordering and
coalescing, Blob forwarding, no-work requests, Receipt completeness, empty
DATA, radix counts, and integer bounds.

The separate checked-in
`conformance/vectors/batch-semantic-v2.tsv` corpus covers the fixed-binary
semantic-v2/v3/v4/v5 content-committing batch profile without changing any wire-v1 row.
It intentionally contains no `ACCEPT` disposition because it provides no
provider keys or cryptographic authentication oracle. Its four dispositions
have these exact meanings:

- `CANONICAL-COMPONENT`: a standalone preamble, manifest, or leaf parses and
  re-encodes exactly; this is not application or source-authentication
  acceptance.
- `STRUCTURAL-UNVERIFIED`: a proof-bearing structure has exact canonical
  framing and internally consistent commitments, but every signature remains
  cryptographically unverified and the row MUST NOT release a pending item.
- `PENDING`: a canonical ASTRENV3 header or compact suffix is insufficient
  without an independently authenticated matching proof.
- `REJECT`: canonical or semantic structural decoding must fail before
  provider authentication.

The corpus contains 4 `CANONICAL-COMPONENT`, 8
`STRUCTURAL-UNVERIFIED`, 4 `PENDING`, and 38 `REJECT` rows. Its exact checked-in
SHA-256 is
`46b94199042576fdcbbfd7713f47d60995740e8cbdbb04e6459fef813a364979`.
The Rust verifier explicitly rejects an
`ACCEPT` row, requires proof routes to carry exact
`u16(64) || 64 bytes || u32(3309) || 3309 bytes` hybrid framing, and never
reports a structural row as authenticated.

Six portable `merkle-case` rows cover depths 1 through 6 with `(n,index)` equal
to `(2,1)`, `(3,2)`, `(5,4)`, `(9,8)`, `(17,16)`, and `(33,32)`. Every
non-power-of-two case selects the final real leaf, whose first sibling is the
normative padded empty leaf. `merkle-case` is a conformance-only container, not
a protocol object, encoded as:

```text
"ASTRMCV1"[8]
u32 manifest_length || manifest[manifest_length]
u16 item_count
repeat item_count times:
    u32 leaf_length || leaf[leaf_length]
    u32 ciphertext_length || ciphertext[ciphertext_length]
u16 selected_index
u32 compact_length || compact_authentication[compact_length]
```

The verifier checks every ciphertext commitment, rebuilds the complete ordered
and padded tree from every leaf, compares the root to the manifest, compares the
exact generated path to the compact siblings, and verifies the BatchID, item
index, proof-depth, root, and item-signature digest input end to end. The item
signature bytes remain `STRUCTURAL-UNVERIFIED`. A negative padding-sibling row
must fail that same end-to-end verifier.

Negative rows additionally cover global Topic/Scope grammar and both embedded
hybrid-signature length prefixes, alongside constant/version downgrade,
class/count/sequence/range, truncation, trailing bytes, leaf format, compact
mode/depth, proof kind, credential commitment, ASTRENV3
magic/reserved/kind/length, and proof-content invariants. The self-test injects
raw canonical kind-3 CBOR and raw `ASTRENV3` into semantic-v1 receive decoders,
serializes every `n=2..64` batch at `g=1` and `g=256`, and checks the exact
overhead equations and headline byte totals.

The supersession receipt at
`conformance/vectors/batch-semantic-v2-supersession.ndjson` preserves the exact
hash, byte/line counts, dispositions, and unsafe-acceptance reason for the prior
corpus before recording this replacement. The active runner includes only the
corrected TSV.

This batch corpus is emitted and judged by the reference implementation and
therefore has `oracle=self`. A separately authored implementation must consume
the checked-in bytes and exchange actual proof/item objects with the reference
before the independent-interoperability gate can pass. Reimplementing the
decoder inside this repository, using another language, or passing
reference-to-reference tests does not satisfy that gate.

Beyond the structural corpus, the Rust reference implements the provider and
explicit atomic source/store/application path: 2–64-item validation, contiguous
publisher/Event reservation, retained-dual default, explicit batch-only policy,
Blob batches, all-or-nothing proof/compact/singleton/ledger/outbox commit, and
proof reauthentication before reads after reopen. These are local construction
and durability subgates. C, Go, and Python expose the same retained-dual/
batch-only transaction plus atomic batches of finalized Blob writers; the FFI,
Go, Python, and linked C/C++ smoke gates pass. The reference peer runtime also
passes exact retained-dual/batch-only inventory shaping, batch-only proof-first
replication and receiver restart, compact-first private persistence followed by
exact-proof promotion, selected-v1 compact rejection, and a finalized two-Blob
proof/compact/carrier transfer with plaintext verification. The complete core
and host suites plus strict core/host lint pass. This remains same-team reference
evidence, not independent interoperability, a 3 kbps result, or a
physical-carrier claim.

The self-test additionally checks exact Merkle differences, tiny-MTU
out-of-order reassembly, resource bounds, and causal concurrency using the same
reference implementation as producer and oracle. The checked-in corpus is the
deterministic sync-wire corpus only; it is not a complete corpus for every
V-FIXED/V-CRYPTO group below. Scenario, independent-SUT, and hardware claims
remain separate gates.

`conformance/python_wire_oracle.py` is a separate, standard-library-only decoder
and semantic validator which neither imports nor binds the Rust implementation.
It checks canonical re-encoding for every ACCEPT row and rejection of every
negative row. Its result identifies itself as
`same-team-not-independent-python-codepath`, while the corpus and Rust runner
retain `oracle=self`. Because both were authored by the same project team and
the corpus is produced by the reference, this is
code-path and language diversity evidence—not the separately authored SUT
required by A-10.

## Local SUT control contract

An implementation exposes newline-delimited deterministic JSON over stdin/stdout
or a local Unix socket. The control path is test-only and never a mesh transport.

Commands: `reset`, `provision`, `join`, `subscribe`, `carry`, `publish`,
`publish_batch`, `publish_blob`, `publish_blob_batch`, `edit`, `delete`,
`advance_monotonic`, `set_link`, `partition`, `heal`, `set_loss`,
`set_bandwidth`, `set_emission`, `revoke`, `rekey`, `query`, `conflicts`,
`status`, `metrics`, `shutdown`.

Every response has request ID, status, structured result, and implementation
manifest. Secrets are redacted from reports. Test reports bind results to the
implementation version and conformance-vector digest under test.

## Normative vector groups

| ID | Group | Required evidence |
|---|---|---|
| V-WIRE | deterministic CBOR | exact accepted bytes and nonminimal/duplicate/indefinite/oversized rejection |
| V-FIXED | fixed binary security objects | every `envelope.md` object at min/max bounds, including `ASTRPB03`, delegated `ASTRCA02`, and `ASTRBCA2`; truncation, trailing, reserved, length, ordering, credential/signer substitution, and cross-field rejection |
| V-BATCH | semantic-v2/v3/v4/v5 content-committing batch | exact preamble/manifest/BatchID, content leaf, complete tree/padding/path, ObjectKind 3 proof route, format-3 compact suffix, missing-proof pending state, downgrade/mutation rejection, and serialized overhead |
| V-BRIDGE | semantic-v2/v3/v4/v5 cross-scope bridge | exact ObjectKind 4 authorization-format-2 delegated signer authentication and ObjectKind 5 wrapper bytes; signer persistence/liveness, directed-edge/filter/path authentication, v1 suppression, source/Blob dependencies, arrival-order, restart, custody, revocation, fallback, quota, and unified-delivery behavior |
| V-ID | identifiers | exact ItemID, raw-SHA-256 EnvelopeID, 33-byte typed ObjectID including semantic-v2/v3/v4/v5 kind 3 and kind-2 Blob carriers, BlobID, Blob transfer-object digest, ManifestDigest, ContentGroupID, NodeID, SingletonBatchID, and content-committing BatchID inputs |
| V-CRYPTO | algorithms | NIST KAT provenance plus exact envelope, root-credentialed delegated-control, custody, Blob, and session vectors from `envelope.md` |
| V-HANDSHAKE | peer authentication | all four exact flights and transcript intermediates; tamper, replay, downgrade, proof, key-confirmation, and either-signature failure |
| V-CAUSAL | dots and clocks | before/after/equal/concurrent/equivocation traces; schema-12 exact-domain isolation, schema-11 sentinel migration/reopen and pointwise maximum, 4,095/4,096/4,097 publisher boundaries with atomic ordinary/bridge rejection, and the explicit A-to-B-to-C non-transitivity trace |
| V-CLASS | reducers | State projection, Event gaps, Record sibling retention, annotations, stale-guarded explicit resolution, an in-process regression proving replicated ingest does not execute policy code, canonical Blob manifest/chunks, and local streaming |
| V-MERKLE | exact anti-entropy | typed 33-byte ObjectIDs, 66-nibble tree roots, probe traces, equal-root wire-descent short circuit with local snapshot accounting, adversarial prefixes, and 100,000/cap-plus-one snapshot behavior for SQLite and custom stores |
| V-MUTABLE-V4 | selected State/Record mechanics inherited by v5 | `[5,4,3,2,1]` negotiation with v1-v3 mutable absence and v4/v5 State/Record parity; every class/direction frame and all malformed/truncated/trailing/unknown variants; exact offer apply result and fetch-result/ack sequencing; exact finish remainder; current-lineage and same-epoch replacement behavior; Normal/AtLeast/ReceiveOnly boundaries; fatal over-1-MiB rejection; 4,096-row/16-MiB class caps; typed effective ordinary-aggregate/per-class item/byte, 1,024-version per-key projection, and causal-frontier deferral; durable 256-peer/1,024-row fair-cursor rotation, CAS race, prune, reopen, audit, and terminal preservation |
| V-BLOB-V5 | selected direct Blob source and carrier mechanics | v1-v4 zero Blob frames; exact canonical interest/source/range/result/ack/finish bytes and class/direction/tuple sequencing, including the 76,807-byte maximum protected interest, 153,718-byte two-frame interest exchange, and 17,127-byte six-frame carrier settlement reserve; source-before-carrier; peer/mission/topic/scope/epoch/current-grant proof with route and revocation checks at inventory/source/every range; wrong/tampered/stale/same-epoch proof rejection; old-lineage withholding plus `PhysicalLineageConflict` until numeric epoch advance; 16-KiB contiguous peer-neutral durable prefixes resumed from a different eligible peer after runtime/store/cache teardown and reopen; exact startup removal of pending source/cache/prefix visibility after same-epoch replacement, epoch advance, or publisher revocation while retaining bounded quota-charged depot expected/committed staging; 64-MiB/1,024-chunk admission and 10,000-row/64-MiB staging bounds; typed deferral without eviction; pending invisibility; exact depot plus fresh full-content and current-lineage completion before atomic publication; all-open-path cross-table audit binding pending source/manifest route/carriers to the depot plan and excluding simultaneous pending/completed state without repair; all-or-none writable nine-to-13-table migration with owner-token rules and read-only/partial-group nonmigration; requester Finish echo distinguished from per-range durable Result/Ack; Normal/AtLeast work and ReceiveOnly zero Blob |
| V-BLOB-LIVE | selected live Blob application boundary | cloneable handle publication from an already-open regular nonempty file at cursor zero, with two-pass mutation detection, cancellation, durable idempotency, a 64-MiB/1,024 canonical 64-KiB-chunk ceiling, and no caller-path reopen; live absolute-offset reads returning at most 64 KiB in zeroize-on-drop plaintext and withholding plaintext across rekey; fresh selected source plus current policy/lineage and exact authenticated `BlobDepotCompletion` capability around depot access; shared application-lane capacity 32 and joined Blob-worker capacity one with bounded saturation; `FatalBlobCoherence` closure of all application admission and actor termination; shutdown and live/stopped terminal zeroization join/closure behavior while audit rows and encrypted depot ciphertext remain preserved |
| V-BLOB-DELIVERY | selected durable Blob application delivery | exact source-publication identity distinct from `BlobId`; metadata-only bounded poll; durable selector replay, pending attempts, acknowledgement receipts, and monotonic cursors; attempt-token rotation with earlier same-tenure token validity; malformed and cross-publication rejection; exact re-acknowledgement; forced receiver-process replacement; final peerless empty-ledger reopen; local status explicitly separated from peer/convergence status |
| V-FRAG | carrier segments | every supported MTU, order, duplicate, truncation, overlap, bounds |
| V-IP | IP control bytes | discovery proof vectors and nonce freshness; rendezvous token echo/address forms, TTL, source, and capacity rejection; local endpoint-handle collision and non-authorization tests |
| V-EXT | evolution | optional skip/preserve and critical rejection; transactional core SQLite schema-14→15 provenance migration preserving existing v1-v4 rows and v5 restart provenance |
| V-FFI | ABI | layouts, ownership, panic containment, repeated lifecycle, invalid pointers/lengths, atomic batch result ordering/rollback, and finalized-Blob writer batches |

`V-BLOB-V5` cleanup evidence MUST retain one exact non-public physical-lineage
depot import, whether expected-only or already finalized, and any
expected/committed chunk staging under the
existing byte, chunk, and variant caps after removing pending
source/cache/prefix visibility. It covers exact-lineage resume,
different-lineage same-epoch conflict without mutation,
numeric epoch advance, zero-lineage audit failure, and read-only, writable, and
terminal-preservation reopen. Runtime evidence MUST serialize durable source
and authenticated-cache staging, repair, retirement, and reconciliation under
one lifecycle lock and reproduce a delayed-insert abort/restage race without
restart. A multi-carrier terminal case MUST choose a manifest whose last record
is not its greatest canonical carrier ID and prove cursor advance to the
lexicographic maximum. Exact bounds are 64 MiB/1,024 chunks per Blob, 1 MiB per
source, 128 KiB per carrier, 16 KiB per range, 10,000 aggregate staging rows,
64 MiB of staged prefix bytes, and 256 configured carrier-cursor peers.

`V-BLOB-LIVE` is a current-code application/runtime gate, not retained network
acceptance. Its 64-KiB canonical chunks and at-most-64-KiB application pages are
separate from the semantic-v5 carrier range ceiling of 16 KiB. Its terminal
zeroization cases establish bounded cryptographic shredding and admission
closure while intentionally preserving the encrypted depot; they do not prove
physical-media sanitization, mixed-implementation behavior, resource targets,
or release acceptance.

## Reference implementation security gates

| ID | Group | Required evidence |
|---|---|---|
| V-PROVISION | local protected provisioning boundary | zero provider calls when local, size, or magic prechecks fail and exactly one protector/unprotector attempt after all prechecks pass; no internal retry or fallback; separate protect/unprotect capabilities; outer/inner size bounds; redacted plaintext ownership and zeroization of its Aster-owned allocation; typed provider rejection without plaintext fallback; inner checksum revalidation; failure before node, database, or Blob-store creation |
| V-PROVISION-AGE | experimental classic-X25519 age provider | exact patched Rust `age` 0.11.5/default-features-off identity plus exact `age-core` 0.11.0 extension-point dependency; 1–16 typed classic X25519 recipients/identities, multi-recipient recovery, and empty/over-cap/duplicate configuration rejection; pre-unwrap requirement for 1–16 X25519 stanzas, no scrypt, and at most one non-scrypt extension stanza so standard GREASE remains accepted; sanitized configuration errors and redacted secret debugging; ordinary, binary, exact plaintext-limit, and real-bundle round trips; reusable randomized encryption; empty artifact, wrong identity, malformed header, stanza/header-MAC/body/final-byte tamper, truncation, trailing data, outer cap, and caller/global recovered-plaintext cap rejection without partial plaintext release; authenticated EOF and Aster-owned partial-buffer clearing, without a claim that upstream age internals or identity-decode intermediates are comprehensively zeroized; protected-node failure before store creation; and bidirectional maximum-size binary outer-file interoperability with exact reference Go age v1.3.1 |

`V-PROVISION` is not a mesh wire or independent-interoperability vector. The
behavioral test providers cover its interface rules. `V-PROVISION-AGE` adds an
isolated, dependency-backed implementation and a separately authored format
oracle; it must pass before the provider-pilot batch can be accepted. That
interoperability is evidence only for the outer classic-X25519 age file, not for
Aster mesh messages or a complete independently authored Aster node. Even a
passing pilot does not establish production admission. Protected-by-default
application and binding paths, persistent secret custody, recipient issuance
and recovery, independent review, comprehensive sensitive-intermediate handling,
and deployment cryptographic requirements remain open gates.

## Acceptance scenarios

| ID | Scenario | Pass condition |
|---|---|---|
| A-01 | BTLE then IP | publish over simulated/physical BTLE, disconnect, consume remaining transfer over IP; one ItemID delivered |
| A-02 | 30-day partition | durable items converge after virtual 30 days; expired items do not transmit |
| A-03 | concurrent Record | after resynchronization, all concurrent heads remain retained and annotated; replicated ingestion invokes no registered policy and publishes no merge revision; explicit resolution of the exact current sibling set publishes one dominating revision without deleting its inputs |
| A-04 | relay path | producer and consumer lack direct path; ciphertext relay delivers; relay key cannot decrypt content |
| A-05 | constrained link | at 3 kbps and seeded 50% loss, higher priority begins first; no expired frame reaches link |
| A-06 | emission | threshold suppresses lower Event lanes without discarding them while v4/v5 State/Record and v5 Blob still run; ReceiveOnly exposes no mutable or Blob lane; PassiveOnly behavior matches declared physical mode |
| A-07 | revocation/rekey | after control arrival, revoked handshake fails and fresh epoch is unreadable with revoked keys |
| A-08 | NAT | direct UDP path forms through test cone NAT; restrictive case uses separately deployed opaque relay |
| A-09 | capture confidentiality | payload plaintext is absent; protected metadata is absent unless the exact declared security-profile exposure budget permits it, and observed leakage does not exceed that budget |
| A-10 | independent implementation | separately authored SUT passes the same corpus against the reference |
| A-11 | blob resume | 100+ MB stream interrupts mid-block set and resumes with another peer without whole-blob RAM growth |
| A-12 | broadcast | one physical advertisement satisfies at least two listeners; duplicate/NACK repair remains bounded |

`A-04` remains the payload-blind Aster application-relay acceptance scenario,
not a controlled Iroh connectivity-relay check. `A-08` still requires
representative controlled NAT/firewall topologies and a separately deployed
opaque relay. Neither scenario has passed. Route-only Blob relay/custody is also
still unimplemented.

The separately retained selected N=32 Event receipt is a bounded production-
lane observation for `DM-9-21A`, not a new `A-*` acceptance scenario. It used
one macOS arm64 host, direct loopback, one binary/implementation, one
scope/authority/topic, and a line topology. All 65 cohorts and 158 exact-named
executions with distinct READY PIDs passed; data motion was serial two-process
edges and the final zero-difference no-op recorded 32 distinct READY PIDs.
There is no overlap timing or OS sampler to prove simultaneity. It does not satisfy
the separate at-least-100-node target, any resource or hardware gate, physical
or distributed topology, NAT/relay/BTLE/cross-transport behavior, independent
interoperability, or release acceptance.

A separate [9,573-byte selected live-Event receipt](evidence/selected-live-event-c464129.json)
(SHA-256
`4d71d04e4ebcc9f63c0e84e7f11e83bf1f3d1ad2ca8608486cdcc875b6dfeef0`,
signed source `c464129`) is also a bounded reference-implementation observation,
not a new `A-*` scenario. It records four peerless Events, threshold transfer of
alpha sequences 1 and 3 with authenticated gap `[2,3)`, forced receiver-child
termination after a flushed unacknowledged poll, fresh-process attempt-2
redelivery with ack/re-ack, and Normal transfer of alpha 2 closing the gap. The
authorized beta Event stays withheld; a temporary beta subscription observes
`PolicyChangedSinceContact` and is removed without a later contact or beta
delivery. Awaiting status has zero failed attempts. The run is one-host,
same-implementation, direct loopback only and supplies no physical, NAT/relay,
BTLE, mixed/independent, scale/resource, other-class, or release acceptance.

## Implemented reliability and resource subgates

The authenticated in-memory runtime has a deterministic monotonic retry loop,
not merely initial-send scheduling. One test uses an MTU of 96 bytes, seeded
approximately 50% frame loss in both directions, the forced loss of an entire
changed SUMMARY transfer, and a fragmented 4 KiB DATA record. It converges,
commits exactly once, re-acknowledges a duplicate after a lost Receipt, and
retires the sender's DATA retry. Separate tests verify priority-ordered retry
deadlines, adapter retry floors, causal retirement of retained protocol work,
and return to no runtime wakeup after convergence.

Resource tests saturate the shared 16 MiB pending-logical budget and the 128
retry/128 one-shot entry limits, verify higher-priority replacement of lower
expendable retries, and verify that selected Event custody replaces only an
inactive equal-priority backoff hint at saturation so another peer progresses
without deleting either peer's durable work. They retain durable WANT progress
through compact deferred metadata and reject hostile maximum WANT-to-DATA
fanout with explicit backpressure. The bounded completed-transfer cache rejects
one adapter-route transfer identifier being reused for different authenticated
logical bytes. Separate v3 contact tests cover opaque selector-generation
receipt invalidation, ReceiveOnly Carry-to-Consume reoffer, receiver-relative
Satisfied/Pending outcomes, retry cadence across reopen, and authenticated
common-set cleanup.

At signed code commit `b0a1203f4f24c05edd31e5ce1ea0f3b7f9bd2f52`, the
current controlled-Iroh-relay software subgate configures exactly one pinned
HTTPS relay and explicit DER-root trust. Carrier tests cover relay-only exact-
peer exchange, rejection of a valid but unrelated CA without WebPKI fallback,
selection of a usable exact direct candidate, continued exact direct operation
while the pinned relay is unavailable, and rejection of the wrong authenticated
Iroh endpoint. CLI tests reject partial, duplicate, ambiguous, oversized, and
malformed trust configuration before state or mission access and avoid echoing
token-bearing relay values.

The real-process portion is one-host and Event-only. With the initiator's
operator-supplied direct candidate unusable and responder IP disabled by
relay-only mode, both endpoints observe the controlled Relay path, synchronize the
exact Event, and complete a terminal no-op. A separate focused in-process
runtime test over direct Iroh proves that a wrong expected mission fails before
inventory; it is not part of the relay-path process proof. Another real-process
case shows that an unavailable pinned relay does not block the exact direct
candidate. Initial paths may be probed in parallel,
and authenticated Iroh NAT negotiation may derive later direct paths, so this
does not prove direct-first fallback or representative NAT behavior. Path and
transition fields are bounded, coalesced diagnostics only.

This source/test subgate creates no retained receipt by itself and no physical,
multi-host, mixed-implementation, N=32, resource-bracket, BTLE, State/Record-over-relay,
Blob-over-relay, payload-blind application-relay, or release credit. It does not
satisfy `A-04` or `A-08`.

A separately frozen selected-Iroh receipt observes one cone/direct and one
restrictive/controlled-relay Docker Linux namespace-NAT Event cell on one
Darwin arm64 host. Each delivered and acknowledged one exact Event and repeated
as an exact no-op, with nft and WAN tuple/count metadata bound to the receipt.
That advances only the bounded requirements-ledger rows; it still does not
satisfy `A-08`, which requires representative controlled NAT/firewall
topologies and a separately deployed opaque relay. The receipt claims no
discovery/punching, temporal fallback chronology, physical/public network,
independent implementation, resource threshold, or release acceptance.

Current-code semantic-v4/v5 selected-node regressions separately exercise State
and Record in both receiver directions. They require exact
`MutableFetchResult`/`MutableFetchResultAck` identity and disposition, exact
Finish/Finished remaining counts, and fatal rejection of missing, duplicate,
changed, cross-class, cross-direction, or out-of-order frames. An object over
1 MiB fails fatally. For an otherwise-valid object, effective aggregate/class
item or byte, the 1,024-version per-key projection, and causal-frontier
saturation return typed capacity deferral and preserve existing rows
transactionally. Repeated bounded contacts rotate through a
durable authenticated peer/class/local Offer/Fetch cursor; tests cover CAS
races, restart, stale-peer pruning, the 256-peer/1,024-row exact boundary,
schema audit, and terminal preservation. Same-epoch route replacement withholds
the historical lineage from ordinary current projection/query and network
inventory/transfer after startup proof, while exact idempotent State publish and
Record publish/resolution retries may recover their committed result only
through the strict cached/projection/historical verification path.
Normal and AtLeast run mutable lanes; ReceiveOnly and v1-v3 disclose none.
These are current-code same-implementation software gates, not retained,
physical, mixed-implementation, scale, or release receipts.

The semantic-v5 Blob gate separately requires a small bounded three-node
direct-Iroh case. One content-capable source must supply the authenticated Blob
source before carrier work, the first receiver contact must preserve only a
proper prefix, runtime/store/provider-cache ownership must tear down, and a
different eligible content-capable peer must continue the exact complement
after reopen. No pending prefix may enter ordinary publication inventory, query,
read, or serving; visibility may appear only after exact depot completion, a
fresh streamed full-content proof, and fresh current route/physical lineage
agree in one promotion transaction. Focused frame, provider, store, and runtime
regressions must also cover every proof substitution, source/carrier tuple and
Result/Ack mismatch, stale/same-epoch lineage, the epoch-advance requirement,
all exact bounds, and v1-v4/ReceiveOnly absence. This is current-code
same-implementation loopback automation for one small Blob; by itself it has no
retained execution root. The current live Blob application handle and the
separate retained composition of this resume mechanism are covered by
`V-BLOB-LIVE`. Both tiers predate the current metadata-only Blob delivery queue
and therefore claim no retained delivery evidence. The queue's local ledger
counts are not peer/convergence status. Neither evidence tier claims route-only
Blob relay/custody, the 100+ MiB or RSS target, physical-media behavior, mixed
implementation, or release acceptance.

The delivery queue separately has a dated
[`V-BLOB-DELIVERY` retained receipt](evidence/selected-live-blob-subscription-26e0a09.json).
Its 10,269 canonical bytes have SHA-256
`3d0c0b2da629282c56de5ae9dacc8920c9960defba083c6bff856e2c0612a675`
and bind Good-signed source `26e0a09`. One participant executes three
processes and four actor lifetimes on one peerless host. Two exact publications
share one `BlobId`; after the attempt-one child flushes an unacknowledged token
and receives `SIGKILL`, a fresh process receives attempt 2 and acknowledges it
with the persisted attempt-one token, rejects a cross-publication token, and
settles both publications. The final parent reopen replays one selector and
polls an empty ledger. This is not a network conformance result and claims no
contact, synchronization, transfer, peer/convergence status,
selector/network-interest separation, power-loss/filesystem-crash recovery,
TTL/GC, physical or mixed implementation, resource/soak, reproducible build,
or release acceptance.

A separate dated
[`V-BLOB-LIVE` retained receipt](evidence/selected-live-blob-044d90f.json)
supersedes the earlier v1 observation and records the bounded live-application
resume composition at good-signature source commit
`044d90ff07c8e754b3d490cb810d42de3c915e3d`. Its 10,728 canonical bytes have
SHA-256
`4fea2ffbd16608862a67167fb1b8fcb6d5d8b4b82c576aa9a6b7e25ee9c55909`.
Three participant identities under disjoint credentials and one mission
authority execute seven phases with at most two live actors. After peerless
publication and direct seeding, a receiver retains a non-public 16,384-byte
prefix from the publisher across graceful shutdown and reopen. One contact
with the different eligible replica advances that exact prefix to 32,768 bytes
without refetching the source; the replica then supplies the remaining 65,870
bytes. Exact runtime and typed Store accounting reconstructs 98,638 carrier
bytes before promotion, authenticated two-page reads, and a final peerless
graceful reopen. Eleven retained handles fail closed and three direct bind
addresses are reacquired. The 45-test independent-oracle checker suite covers
the canonical projection, exact transcript/runtime and prefix relations,
private-artifact metadata-only inventory, privacy exclusion, and fail-closed
replay.

This advances only the bounded same-implementation, three-party, one-host
direct-Iroh graceful interruption/reopen and different-peer continuation
observation. It is not an independent black-box conformance result and does not
satisfy a separately deployed SUT requirement. It does not prove process-crash
or power-loss recovery, long-offline recovery, arbitrary-peer or route-only
resume, physical-media sanitization, distinct physical hosts, NAT or Internet
paths, controlled/public relay, BTLE, mixed implementations, scale beyond
three participants, resource thresholds or long-duration soak, Blob
subscription/status/TTL/garbage collection, complete MVP acceptance, release
evidence, Event/State/Record live-application acceptance, or production
authorization. Intermediate Store inspection and transcript timing remain
producer-attested.

Focused inventory-selection regressions exercise the same bound at small test
sizes: the SQLite helper returns exactly the configured cap, requests only cap
plus one rows in its single metadata-only query, and rejects the extra row; the
generic node guard separately rejects an over-limit vector from a custom store.
The production bound is 100,000 metadata objects. Equal roots avoid subsequent
`PROBE` / `NODE` wire descent, but both peers still select and hash the local
snapshot. These tests therefore establish a ceiling and wire short circuit, not
difference-proportional local work. Because source descriptors are inserted
first into the composite inventory, a snapshot containing exactly 100,000
source descriptors leaves no capacity for Blob carrier ObjectIDs; fair or
reserved carrier allocation remains an open scheduling concern.

Schema-12 store regressions cover schema-11 frontier migration into the reserved
`('', '')` sentinel, reopen behavior, exact `(topic, origin scope)` isolation,
pointwise-max loading, and the 4,096-publisher effective-domain boundary. They
also prove that ordinary and authenticated bridge-source overflow rolls back
without accepted-dot or outbox residue, and that a received signed predecessor
vector does not expand the local publication frontier. The last property is a
trust containment rule, not evidence of complete causal propagation: the
A-to-B-to-C trace remains non-transitive, per-key/per-stream domains are absent,
and accepted-dot/Event ledgers plus aggregate frontier domains remain unbounded.
V-CAUSAL and production causality therefore remain incomplete.

These are reference-to-reference software subgates. They do not measure useful
throughput at 3 kbps, Tier-2 RSS or battery use, permanent/adversarial loss, a
live carrier, or physical hardware, and they do not satisfy A-05 or A-10 alone.

The reference also passes a cross-scope bridge software subgate. It verifies
semantic-version-2/3/v4/v5 authorization and wrapper authentication, selected-version-1
suppression, exact source and Blob dependencies in every arrival order,
multi-hop path continuity and loop rejection, dynamic filter/revocation/epoch
enforcement, monotonic custody, deterministic verified-path fallback, and
reference-counted quota/GC across restart. Direct and bridged arrival share one
ItemID/dot/Event reducer and durable subscription-acknowledgement ledger while
preserving distinct `origin_scope` and `current_scope` views. The Rust/C/Go/
Python surface uses move-only enrollment and opaque 32-byte durable handles.
This remains same-team reference evidence; it does not satisfy the independent
SUT, 1,000-node bridge-scale, packet-capture, or physical-carrier gates.

The core now passes a focused A-07 software subgate: a root-credentialed,
delegated-hybrid-signed chained ScopeEpoch format-1 control distributes freshly
generated route/topic keys in hybrid recipient packages; a captured omitted
node cannot open fresh content; route-only recipients cannot open content; and
tamper, fork, rollback,
out-of-order/reopen, and local-revocation cases do not install unauthorized keys.
This is not the complete black-box administration scenario: the public recipient
registry still needs an independently persisted generation high-water mark after
authority-store replacement, and complete public-registry import/management is
not shipped even though high-level rekey calls exist. Format `0`
pre-provisioning is not evidence for A-07.

The core also passes focused delegated-authority software regressions. They
verify that `ASTRPB03` contains no authority-root signing seed, separately
provisioned ControlAuthority nodes have distinct signing identities, and the
provider rejects legacy root-signed control shapes, missing roles, credential
substitution, and signature tamper. Store tests persist the authenticated signer,
reject a signer/reservation mismatch, apply revocation in contiguous chain
order, reject and remove a revoked signer's pending dependent suffix, and let a
different live signer reissue that suffix on the same stable authority chain.
The bridge path separately checks format-2 delegated authentication, signer
persistence, revoked-signer suffix rejection, and loss of liveness after signer
revocation. Schema-10 stores with existing ordinary or bridge controls fail
closed rather than assigning those rows an inferred signer.

These same-team unit/integration regressions are not a distributed authority
protocol. They do not prove concurrent-writer consensus, automated signer
rotation, root override, total-history recovery, or rollback resistance after
complete control-store replacement. Those would require the separately
specified root-signed epoch/cutover and external chain high-water described in
[security.md](../security.md).

The core passes complementary A-11 software subgates. A generated 101 MiB local
streaming case interrupts/reopens, deduplicates, reads back, and rejects tamper
with component buffers no larger than 65,552 bytes. A smaller carrier forces a
durable partial range, drops the first session, reopens SQLite and Blob state
with a brand-new driver and sync reducer, authenticates a different route-only
serving peer, requests exactly the missing complement, retires staging,
finalizes, and recovers identical plaintext. Its adversarial branch accepts a
corrupt range from authenticated producer A under a genuine ObjectID, reaches a
terminal carrier-authentication failure, transactionally clears only that
object's durable and reducer progress, reopens with no poison, issues the
canonical unknown-length/full request to a different honest route-only relay B,
and recovers identical plaintext. Separate regressions prove hostile Blob and
source partials cannot evict a committed Routine item, reducer reset clears
total/ranges/forwarding, and the high-level/FFI path rejects the same manifest
under a wrong route root or chunk count. The targeted cases pass. The combined
100+ MiB different-peer run with measured process RSS and a physical live
carrier remains pending.

A-12 remains failed: the adapter/BTLE simulation exposes a broadcast primitive,
but there is no protected broadcast replication capsule or implemented
suppression, repair aggregation, and loop-bounding protocol. The Rust host can
pump a configured link, but no concrete physical BTLE controller is shipped.

The current security construction using suite `0x0001` passes A-09's handshake
subgate: a runtime capture test reassembles all four tiny-MTU flights and finds
neither peer's mission, credential, credential body, NodeID, nor route-grant
commitment canaries. Full A-09 still requires captures covering source,
custody, protected replication, and each physical carrier claimed by the
release profile. For the current security construction using suite `0x0001`,
all named protected metadata canaries remain required absent. A future profile
instead must declare its exact exposure budget under
[Decision 0033](../decisions/0033-policy-selected-security-profiles.md), and its
captures must reveal no payload plaintext or metadata beyond that budget. A-09
excludes correlation already available from link/network/rendezvous
identifiers before the first Aster flight unless a named profile mechanism
claims to hide it, and does not assert traffic-flow confidentiality.

## Durability and fault scenarios

- Kill/reopen before and after each publish transaction boundary.
- Disk full during envelope, outbox, blob block, manifest, and receipt commit.
- Corrupt ciphertext, index row, block digest, and partial bitmap.
- Counter-store rollback and same-dot/different-content equivocation.
- Unclean reboot with finite TTL and no trustworthy persistent time.
- Tombstone just inside/outside configured retention.
- Quota pressure proving protected control/tombstone reservations.

## Property tests

```text
apply(x, x) = apply(x)
project(a, b) = project(b, a)
join(join(a, b), c) = join(a, join(b, c))
publication_frontier(topic, scope) = pointwise_max(exact_direct_dots, legacy_sentinel)
an accepted signed predecessor claim does not become local direct observation
an inventory snapshot has at most 100000 objects or selection fails without truncation
equal Merkle roots imply no wire descent, not no local snapshot construction
no concurrent head disappears without a dominating explicit revision
direct and forwarded replicated ingestion never invoke application merge policy
direct and forwarded replicated ingestion never publish a local merge revision
explicit resolution succeeds only for the exact current sibling set
eventually connected replicas with the same retention policy converge
fragment/reassembly is invariant to MTU, duplicate, and arrival order
compact batch bytes remain private and semantically unapplied until their exact proof authenticates
selected-v1 inventory and resume expose neither batch proofs nor compact representations
staged source-envelope and Blob-carrier progress survives peer/session change unless terminal whole-object authentication resets only that ObjectID
verified content Blob chunk progress never decreases across process restart
direct and bridged representations of one ItemID share one semantic acceptance and acknowledgement ledger
no active bridge path bypasses its exact authorization/source dependencies after reopen or fallback
eviction never removes a currently protected class
unauthenticated staging exhaustion never evicts a committed item
```

## Fuzz corpus

Targets: deterministic decoder, every fixed object in `envelope.md`, source
envelopes, controls, custody wrappers, handshakes, protected frames (including
all 20 semantic-v4/v5 mutable tags and all semantic-v5 Blob interest/range/
result/finish tags), fragments,
overlapping ranges, Merkle probes, dotted contexts, bridge filters, store
authorizations/wrappers/path dependencies, store recovery, and FFI call
sequences.

Seeds include duplicate keys; nonminimum integers; indefinite/oversized/deep
objects; truncated tags/signatures; wrong inclusion proofs; inconsistent fragment
overlap; TTL underflow; old epochs; replayed session counters; malformed public
keys; same-dot/different-item; route-root/chunk-count substitution; poisoned
partial restart; staging exhaustion; zero-length and maximum-length blobs.
Selected-v5 Blob seeds additionally cover proof substitution and tamper,
wrong kind-2 carrier IDs, source/carrier/length/offset crossing, noncanonical
interest order, stale and conflicting physical lineage, mismatched Result/Ack,
over-16-KiB ranges, prefix conflict, carrier-complete but content-incomplete
promotion, and Blob frames under v1-v4.
Batch seeds additionally include semantic-v1/format-2 downgrade substitution,
mixed batch fields, counter/Event range overflow, reordered leaves, wrong empty
padding, short/long/reordered paths, proof-ID and BatchID substitution, missing
proof, ciphertext length/hash mutation, malformed opaque signature lengths, and
bare compact items that must remain pending.

## Resource gates

On each Tier-2 target, record stripped library/sample binary size; peak and
steady RSS at 10,000 metadata items; single-core convergence CPU; idle wakeups;
3 kbps/50% loss useful delivery; 100-node scope simulation; and 1,000-node
bridged simulation. Blob tests demonstrate constant-memory streaming. Draft target
failure blocks an MVP claim or requires stakeholder-approved target revision.

## Hardware gates

Simulation is not hardware acceptance. BTLE release evidence requires two
physical controllers/devices, negotiated small MTU, disconnect/reconnect, GATT
fallback, and L2CAP where supported. NAT evidence requires controlled cone and
restrictive NAT/firewall topologies. RF emission claims require platform capture.
