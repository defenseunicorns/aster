# p2panda v0.7.1 Phase-1 closure

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.

>
> Requirements-first research evidence only. `data-mesh-requirements.md` is
> the sole architecture authority. Current Aster implementation, architecture,
> wire, APIs, stores, and compatibility received zero weight. Bracketed values
> remain measurement points rather than candidate-elimination gates.

- Evaluation date: 2026-08-22 (America/Chicago)
- Requirements SHA-256:
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Work order: Proposal 0005 Phase 1
- Candidate: p2panda `v0.7.1`, commit
  `083b48215964e92a564f3c83a1c607b00e94aa64`
- Exact executable freeze: BVB-700 graph plus BVB-840/BVB-842/BVB-845
  append-only execution controls
- Existing clean p2panda evidence reused: BVB-700, BVB-703, and BVB-808;
  BVB-825 is cited only as separate security-profile evidence and was not run
  through p2panda
- New external sources or dependency acquisition: none
- Excluded or quarantined material consulted: no
- Production admission: not admitted
- Overall result: **the Event-like replica primitive survives; the integrated
  whole-system hypothesis does not**

## Outcome first

p2panda v0.7.1 provides a real, integrated high-level path through `Node`, log
sync, SQLite storage, stream processing, acknowledgement cursors, and direct
network sessions. Across the frozen evidence it has now demonstrated:

1. disconnected local publish, separate-process restart replay, and later
   direct synchronization;
2. durable operation carry across non-overlapping A-B and B-C contacts;
3. bounded convergence of immutable operations from disconnected authors;
4. exact log-range selection at `N = 10`, `10,000`, and `1,000,000` while
   holding `Δ = 7`; and
5. replay of one durably processed but unacknowledged operation after forced
   process exit 77, followed by durable acknowledgement and no replay on the
   next restart.

That is meaningful FOSS buy credit for an **Event-like signed replicated log**.
It is not an integrated buy of the Phase-1 package list. The high-level Node
pipeline creates only Basic operations and runs only ingest plus log pruning.
Its causal extension is explicitly an incomplete, unintegrated placeholder.
Auth, encryption, and Spaces packages are present transitively in the selected
graph, but their group, encryption, and space semantics are not wired into the
Node stream pipeline or public application API. The released Blob package is a
dependency-free, unlinked stub and is absent from the selected runner graph.

The class mapping therefore stops at Event-like behavior. State lacks
multi-author causal-latest resolution and a deterministic concurrent tie-break;
Record lacks merge registration, conflict annotation, and superseded-version
recovery; Blob lacks an implementation. The generic stream also lacks
self-declared class, scope, priority, and TTL fields. Topic is stream routing
context and publisher key identity is present, but those two fields do not make
the required item envelope complete.

This result does **not** early-exit p2panda as a component. Proposal 0005 treats
missing behavior in one component as a composition delta unless it is an
intrinsic contradiction. It does reject the narrower hypothesis that v0.7.1's
high-level Node already buys core, sync, store, stream, Blob, auth, encryption,
Spaces, and all four class semantics as one integrated framework.

## Status vocabulary

The report and requirements map use four non-overlapping Phase-1 statuses:

| Status | Meaning |
|---|---|
| `implemented_pass` | Exact source plus bounded executable evidence passed the stated assertion. Credit does not escape the assertion boundary. |
| `failed` | An executable requirement assertion or requirement-level mapping did not pass. Harness/environment failures are identified separately and receive no candidate result. |
| `missing_unlinked` | The exact release lacks the package, public seam, or high-level linkage needed to run the requirement without adding another owner. |
| `not_tested` | A package, documented behavior, or plausible mechanism exists, but the required behavior was not executed and remains unknown. |

`partial` in the requirement result column means that one subordinate mechanism
passed while the full atomic requirement did not. It never promotes a
`not_tested` or `missing_unlinked` behavior to executable credit.

## Exact new executable freeze

| Field | Exact value |
|---|---|
| Runner manifest | `Cargo.toml` (archived) |
| Manifest SHA-256 | `3ce3dcb3c59cfb67a11df44360f7cca81385f80457b66957fc0d9b9cb97e38da` |
| Lock SHA-256 | `7b901b0142329b28f5912f90a5884401a4a616043aaab05e6cfb085eb18c3652` |
| Graph | 533 packages: 522 registry, 11 path, 0 git |
| Closure source | `runner/src/bin/p2panda-phase1-closure.rs` |
| Initial registered source SHA-256 | `4c849892ecc33fc5ef42d01ddeebb7035abd1f7da5d4eaea04c1d9c88aa973aa` |
| Format-corrected source SHA-256 | `756ede5e00ad88b0959183bbcc72df61fac9238eefb9d1ed8256e2b2372c9a18` |
| Debug binary SHA-256 | `45184a2ec16f14b8cac322cfc7e395f914ffc9daea768a4f0c12f32f46470442` |
| Format check | Pass after the append-only rustfmt correction; the initial formatting-only failure is retained |
| Build | `cargo build --locked --offline --bin p2panda-phase1-closure`: pass |
| Lint | warning-denied Clippy: pass |

The formatting correction changed layout only. The first format failure, the
sandbox-blocked local actor startup, every successful result, the failed prune
recovery assertion, and live SQLite/WAL/SHM evidence remain under ignored
`runner/runs/phase1-closure-*` paths.

## New trial results

### Range selection: implemented and passed, bounded

For one author and one log, the candidate returned the exact exclusive/inclusive
range containing seven missing operations at each tested dataset height:

| Total `N` | Remote retained | `Δ` | Selected range |
|---:|---:|---:|---|
| 10 | 3 | 7 | after 2, through 9 |
| 10,000 | 9,993 | 7 | after 9,992, through 9,999 |
| 1,000,000 | 999,993 | 7 | after 999,992, through 999,999 |

This executes range calculation only. It does not measure bytes, CPU, round
trips, interrupted transfer, durable progress, or continuation with another
peer. The full difference-proportional requirement is therefore **partial**;
resumable partial sync and any-peer continuation remain **not tested**.

Source inspection reaches the same boundary. `p2panda-core::logs::compare`
computes exact per-author/log ranges. `LogSync` exchanges complete log-height
maps, keeps its protocol state and deduplication buffer in the live session, and
emits received operations to the application pipeline. Already ingested
operations may advance the next session's durable log frontier, but this arm did
not interrupt a contact and did not prove later continuation with the same or a
different peer.

### Prefix pruning: primitive passed; restart invariant failed

`prune-seed` successfully published `old-0`, `old-1`, a prune snapshot
`snapshot-2`, and `new-3`. The source-backed primitive physically deletes
operation rows with sequence numbers below the prune point for that author and
log.

The separate-process `prune-recover` trial failed its preregistered invariant:

```text
unexpected retained replay after prune: total=Some(4) messages=["snapshot-2", "new-3"]
```

The retained content was the intended two-message frontier, but the high-level
`ReplayStarted` metadata reported four operations. The exact source explains
the mismatch: replay totals are calculated from the upper sequence number when
the range has no lower bound, while the subsequent store query returns only
rows that remain after prefix deletion. This is a candidate-visible consistency
failure in restart replay metadata, not a lost-retained-content finding.

The primitive is only per-author append-log prefix deletion. It is not an item
tombstone, has no bounded/configurable tombstone retention, and does not own
Record superseded-version recovery, TTL expiry, reference tracking, quota
eviction, or a complete garbage-collection policy. Those surfaces are
`missing_unlinked`, not unexecuted pruning credit.

### Abrupt-exit replay and acknowledgement: implemented and passed, bounded

With explicit acknowledgement policy, `crash-write` durably published and
processed operation
`e619965958af3d3473ad2171065db7d77b691a54db168c3fe4d562f81e809daf`,
delivered it to the application, deliberately did not acknowledge it, flushed
the receipt, and exited with the required status 77. A separate process replayed
exactly that operation from `Source::LocalStore`, then acknowledged it. A third
process observed no replayed operation for 2,000 ms.

This is bounded evidence for durable operation storage plus acknowledgement-
cursor recovery after abrupt process termination. It does not test torn writes,
power loss, disk-full behavior, WAL corruption, store rollback, interrupted
network sync, or atomicity between p2panda and a separate application database.
BVB-808 also remains decisive: importing one identical operation three times
left one durable row but emitted three application-visible processing events.
The candidate store is idempotent; harmless application effects are not supplied
automatically.

## Phase-1 surface closure

| Surface | Phase-1 status | Evidence and exact boundary |
|---|---|---|
| High-level Node: offline publish, stream, replay, direct sync | `implemented_pass` | BVB-700 direct run plus the new abrupt-exit run. Bounded Event-like strings only. |
| High-level Node: query and conflict annotations | `missing_unlinked` | Public Node exposes stream/stream-from, ephemeral stream, system events, IDs, and bootstrap insertion; no requirement-level query or conflict API is present. Store access is test-only. |
| Core/store/stream/sync integration | `implemented_pass` | `Node::stream_from` connects network log sync, SQLite store, forge, processed stream, and pipeline; BVB-700/BVB-703/BVB-808 and the new run execute that path. |
| Pipeline behavior | `implemented_pass` | Exact pipeline runs ingest then log pruning. No other semantic layer receives implied credit. |
| Auth package | `not_tested` | Package is in the selected transitive graph and documents an offline group DAG, permissions, and resolvers. No standalone auth trial ran. |
| Auth-to-Node integration | `missing_unlinked` | Node exposes no group/admission API; the actual Node pipeline does not apply auth group state or access decisions. Auth README says custom sync can use its access levels. |
| Encryption package | `not_tested` | Package is in the selected transitive graph and documents group encryption. No standalone encryption state machine ran. |
| Encryption-to-Node integration | `missing_unlinked` | No Node stream encryption API or pipeline stage. Upstream documentation says the high-level combined layer is still being developed. |
| Spaces package | `not_tested` | Package is in the selected graph and documents a Manager combining auth and encryption. No Space lifecycle ran. |
| Spaces-to-Node integration | `missing_unlinked` | Pipeline source explicitly describes Spaces processing as future work. Spaces requires causal ordering and signed/verified messages; generic high-level causal operations are not integrated. |
| Generic causal forks | `missing_unlinked` | `Extensions::from_topic` always builds Basic; Causal is an explicitly incomplete example placeholder whose prune branch is `unimplemented!()`. |
| Same-author linear-fork rejection | `not_tested` | Ingest validates each operation against the latest sequence/backlink, which is a linear log rule, not a generic concurrent-version resolver. No executable fork injection ran in this arm. |
| Disconnected different-author versions | `implemented_pass` | BVB-808 converged both nodes to the same two immutable operations and preserved both values; Event-like set only. |
| Range selection | `implemented_pass` | Exact `Δ=7` range at three `N` values. No transfer-cost curve. |
| Interrupted/durable/any-peer partial sync | `not_tested` | No interrupted contact, persisted sync checkpoint, changed peer, or changed carrier was run. |
| Per-author prefix prune | `implemented_pass` | Seed processed a prune marker and restart returned only the snapshot plus later message. |
| Prune restart metadata | `failed` | Replay announced four operations while emitting the two retained messages. |
| Tombstones and bounded/configurable retention | `missing_unlinked` | Prefix pruning is not an item-deletion/tombstone lifecycle and exposes no retention policy. |
| General GC policy | `missing_unlinked` | No high-level owner for TTL, Record-version, Blob-reference, quota, or physical-storage GC. |
| Graceful restart replay | `implemented_pass` | BVB-700 separate-process replay. |
| Abrupt process-exit replay/ack | `implemented_pass` | Exit 77, one unacknowledged local-store replay, durable ack, then zero replay. |
| Torn-write/power-loss/corruption recovery | `not_tested` | Explicit no-credit boundary of the harness. |
| Crypto-provider substitution seam | `missing_unlinked` | Core concretely binds BLAKE3 and Ed25519; encryption source names concrete X25519/ChaCha/Ed25519/XChaCha primitives. No crypto-provider trait or algorithm-provider seam was found. This proves absence of an explicit seam, not impossibility of a fork or wrapper. |
| Blob package/high-level Blob | `missing_unlinked` | Released `p2panda-blobs` manifest has no dependencies and its module root contains only a refactor TODO. It is absent from the selected graph. |

## Auth, encryption, and Spaces security boundary

Package presence is not security ownership. The frozen high-level runner pulls
auth, encryption, and Spaces transitively through default stream/store features,
but its string-stream pipeline does not invoke them.

The package documentation adds source-backed stop conditions rather than
executable credit:

- auth access levels are described as inputs that **custom sync protocols** can
  use; this run did not supply that integration;
- encryption says its feature-complete high-level auth/encryption layer is
  still in progress, has not been audited, currently leaves group control
  messages unencrypted, and is not post-quantum secure; and
- Spaces requires causally ordered, signed, verified messages, while the
  high-level Node's generic causal variant is explicitly incomplete and
  unintegrated.

BVB-808's 471-byte protected object remains useful composition evidence: the
exact opaque bytes survived A-B, B restart, and B-C; C verified/decrypted them;
tampering and wrong-key probes were rejected; and relay plaintext scans found
zero matches. That protection belongs to the external fixture/profile. It
grants p2panda only opaque-byte carry credit and no encryption, authorization,
membership, revocation, metadata-protection, provider, PQ, or FIPS ownership.
BVB-825's separate 8,185/8,189-byte public carrier objects were not run through
p2panda and grant no p2panda carry or security credit.

## Four-class mapping limits

| Required class | Mapping result | Candidate-owned behavior | Residual or stop |
|---|---|---|---|
| State | `missing_unlinked` / requirement not met | A publisher can emit an application-defined snapshot while pruning its own older log prefix. | No generic State class, multi-author causal-latest selection, concurrent tie-break, or clock-independent State materializer. A snapshot convention would be application/profile semantics. |
| Event | `implemented_pass` / partial class coverage | Immutable signed operations, per-author sequence/backlink, durable replay, direct sync, temporal carry, and bounded convergence. | No dedicated high-level gap event was tested. Sequence inspection is available through the lower-level processed event, so a requirement-level gap API/policy remains integration work. |
| Record | `failed` / requirement not met | BVB-808 preserved two disconnected-author values as separate immutable operations. | No Record identity/version model, registered merge, conflict annotation/API, or explicit-policy superseded-version recovery. Preserving an Event-like set is insufficient. |
| Blob | `missing_unlinked` / requirement not met | None in the released high-level graph. | Package root is a stub; no chunks, streaming, content addressing, deduplication, durable resume, any-peer progress, or Blob lifecycle. |

The required common item envelope is also incomplete:

| Item field | Result |
|---|---|
| data class | missing |
| topic | partial: supplied as stream/routing context; imported operations do not self-describe their topic |
| scope | missing |
| priority | missing |
| perishability/TTL | missing |
| authenticated publisher identity | bounded primitive present as the operation's verified author key; mission-identity binding and the final security profile remain outside this credit |

## Exact source-backed stops

All paths below are inside the clean BVB-700 v0.7.1 source freeze.

| Source | SHA-256 | Finding |
|---|---|---|
| `p2panda/Cargo.toml` | `b3765df0fd905c7d61a541990f3720fb80fe158bb0fd86b0d167e508b81956d4` | High-level crate directly composes core/net/store/stream/sync, not auth/encryption/Spaces/Blob APIs. |
| `p2panda/src/node.rs` | `a3a8aa238a5d65138486473592373501859c65de14573bcba373aea688a42690` | Public high-level stream, ephemeral stream, events, IDs, bootstrap; store accessor is test-only. |
| `p2panda/src/processor/pipeline.rs` | `951ebfff49c15d06bc99c8d8d4a4dead330474c7b764765638427a889eec6585` | Pipeline is Ingest then LogPrune; Spaces pipeline is future work. |
| `p2panda/src/operation.rs` | `f11409ce8c5a28987c7f65b029089523b3d0d54ee58170bd16d89e25d87caf46` | `from_topic` creates Basic; Causal is incomplete/unintegrated and reaches `unimplemented!()`. |
| `p2panda/src/streams/stream.rs` | `a57db5a362dfd60dc4805de9ecb4156ef8833f7265dccf39b2b30bffac2f0e4d` | Publish/import/prune and processed application surface; prune is per-author prefix deletion; imported operations lack topic context. |
| `p2panda/src/streams/replay.rs` | `d809e962bf4d92149119af6b09aced78d4c785ef88788de3e2c9b0ffc6013e4d` | Replay total derives from requested sequence range, explaining the post-prune metadata overcount. |
| `p2panda-core/src/logs.rs` | `e2fa20306d44117e3b6fd03bc1028defefbbd253e559e12e4cb117a4b81d1026` | Log-height comparison returns exact per-author/log ranges. |
| `p2panda-sync/src/protocols/log_sync.rs` | `eb666fd0733a9d6b80befa051c752b8f99ecf7a1013d1ede4537e69f799a4949` | Session-local state/dedup plus range exchange; received operations are emitted for the pipeline to ingest. |
| `p2panda-stream/src/ingest/operation.rs` | `182e59b4ebfc47db79cd67cfd82f3b5dc2fcd398c91db120e6466de85910f1ba` | Durable duplicate insertion is ignored; latest backlink validation enforces a linear author log. |
| `p2panda-stream/src/log_prune/processor.rs` | `7bf30af5139bf997293fccc6f7bb51e9a70403c34e89bcbb004456c2151ebcf2` | Executes author/log prefix pruning only. |
| `p2panda-core/src/hash.rs` | `ce4a7219f19a4bea963c977642ea9a3b2daef405f55e9beb03673fb8cea3e2cb` | Concrete BLAKE3 hash type. |
| `p2panda-core/src/identity.rs` | `420082a78390127ff2c6fdf1bbfc8af276fa0ef746559753063cd7ce955eedb5` | Concrete Ed25519 identity and signature types. |
| `p2panda-encryption/src/crypto/mod.rs` | `abb0155dd5d020b4e853eabc784f10b99dbfd957ded4a9f7a562c29c77ebc43e` | Concrete algorithm module; no provider seam found in the relevant exact source trees. |
| `p2panda-auth/README.md` | `db01f77a4091ca424778151984af5d5fb645b03b42850efb57335e3179723f9f` | Standalone documented group/access/DAG behavior; not a Node integration or executable result here. |
| `p2panda-encryption/README.md` | `934da58fc0165005fbec2f37b009f67789f489694c1dcec425ea5d7b0aa7c811` | High-level integration unfinished; no audit; plaintext control metadata; no PQ. |
| `p2panda-spaces/README.md` | `3225e7dd0097716022cb806619c60e349046887b920edb0ea3ba5ebb0e4b09dc` | Manager claim plus causal/signed/verified input prerequisites; package not executed here. |
| `p2panda-blobs/Cargo.toml` | `45a20d8180f8781e5f8bbe44f65ec316cdc8a3d9d7c1c50ac24a7a21b4d7aaae` | Released package has no dependencies. |
| `p2panda-blobs/src/lib.rs` | `8cc6adb8a85b49140686a95c417162d21b8f3dfe8e46e235389c76afaa131b05` | Module root links no implementation and contains only a refactor TODO. |

## Requirements disposition

The atomic map is
[`phase1-closure-requirements-map.csv`](../../../../docs/evaluations/0005/requirement-maps/p2panda.csv).
The decisive groups are:

- **Implemented/pass, bounded:** DM-7-16; DM-7-17; Event-like portions of
  DM-5.1-04 through DM-5.1-06; bounded convergence under DM-5.2-01/02;
  storage-side deduplication under DM-5.2-07; and the range-selection mechanism
  inside DM-5.2-18.
- **Failed:** post-prune replay-count consistency; application harmlessness
  under DM-5.2-08; and Record outcomes DM-5.3-05 through DM-5.3-10 / DM-12-04.
- **Missing/unlinked:** generic State causality and tie-break, tombstone
  lifecycle, high-level auth/encryption/Spaces linkage, query/conflict API,
  crypto-provider substitution, and all Blob mechanisms.
- **Not tested:** same-author fork injection, standalone auth/encryption/Spaces,
  actual transfer-cost proportionality, interrupted/durable/any-peer partial
  sync, torn-write/power-loss/corruption recovery, and full security corpus.

## Buy/build/delete implication

| Responsibility | Phase-1 implication |
|---|---|
| Event-like signed append log, SQLite persistence, replay cursor, and direct log sync | **Retain as a FOSS component candidate.** These are the strongest candidate-native buys. |
| High-level Node as the complete four-class/security framework | **Delete this assumption.** The integrated source does not own those semantics. |
| Auth/encryption/Spaces packages | **Evaluate only as separate components/composition work.** Presence in the graph is not integration. Their standalone semantics and recovery must be run before buy credit. |
| Generic State and Record semantics | **Buy another maintained CRDT/class component or build a normative profile.** Do not relabel Basic streams as class support. |
| Blob | **Buy elsewhere.** Do not count the v0.7.1 stub. |
| Tombstone/TTL/quota/Record-version GC | **Find or build one explicit lifecycle owner.** Do not stretch per-author prefix prune into this role. |
| Crypto/provider profile | **Use a selected standards/security composition or carry a fork/wrapper knowingly.** No clean provider seam was found. |
| Partial any-peer resume | **Run before assignment.** Log-frontier behavior is promising but presently unproven at interrupted-contact and changed-peer boundaries. |

## Disposition and next gate

Retain p2panda v0.7.1 on the architecture frontier as a **bounded Event-like
replica/store/sync component and differential oracle**, not as a requirements-
complete local-first stack. A p2panda-first composition should advance only
with an explicit responsibility map that names different owners for:

1. the normative item envelope and State/Record semantics;
2. Blob storage, chunking, and carrier-neutral durable progress;
3. source-object security, protected forwarding metadata, membership/revocation,
   algorithm suite, and provider/FIPS/PQ integration;
4. tombstones, TTL, quotas, eviction, references, and garbage collection; and
5. high-level query, conflicts, peer/sync status, FFI, and bindings.

The next p2panda-specific disproof spike, if this component remains competitive,
is an interrupted multi-operation sync that restarts both sides, changes to a
third eligible peer, and verifies operation-level progress without granting Blob
resume credit. It should be paired with a same-author fork injection and a
corrected prune-replay metadata oracle. No current-Aster compatibility work is
part of that gate.
