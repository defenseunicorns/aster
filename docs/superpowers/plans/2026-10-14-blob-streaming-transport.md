# Blob Streaming and Automatic Transport Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Clean Room — Privileged**

**Goal:** Add an authenticated, credit-windowed, crash-resumable Aster Blob protocol that transfers configured 1-GiB-plus objects at a useful fraction of the available pipeline. This plan's first milestone automatically chooses the sole eligible Iroh production adapter and recovers it safely; the design's best-available cross-transport claim remains gated on a second qualified production stream adapter.

**Architecture:** Build semantic v9/profile `5` (`BlobStreamV1`) on the exact PR 71 range-stream and PR 47 lifecycle baseline. The new class-neutral stream grammar maps existing authenticated carriers into bounded whole-carrier extents, commits multiple verified carriers plus one cumulative checkpoint per durable batch, and drives one transport adapter at a time through a deterministic internal selector. Semantic v1-v8 and profile `4` remain byte-identical; Iroh is the first production adapter and retains ownership of its internal direct/relay path choice. The first milestone delivers Iroh streaming/performance; best-available cross-transport selection is claimed only after a second independently usable production stream adapter is registered and qualified.

**Tech Stack:** Rust 2024, Tokio, Iroh/QUIC concurrent data/control streams, redb 4.2, Aster mission protection, PR 47 Blob lifecycle/depot APIs, cargo-fuzz, Python conformance/path-lab tooling, GitHub Actions, three Raspberry Pi CM4 devices.

**Spec:** `docs/superpowers/specs/2026-10-14-blob-streaming-transport-design.md`

**Status:** Approved for implementation handoff on 2026-10-15.

## Global Constraints

- Label project communications and retained review artifacts `Clean Room — Privileged`.
- Start a new isolated worktree at reviewed PR 47 head `04de641bfb3d647290ffffabe40ec284d9865a95`, which contains exact PR 71 head `c17213a50a598b85c3fe672b7195a03b476b07ab`. Recheck both heads before work and rebase onto their final ordered merges before handoff.
- Carry forward documentation commits only. Do not merge, cherry-pick, or build on superseded implementation commits `4f7ffb3e..212269b4` from `docs/blob-streaming-protocol-design`.
- Allocate semantic protocol version `9`, transfer-profile ID `5` (`BlobStreamV1`), and mechanics tags `0xd6..0xdc`. Keep profile `3` reserved and profile `4` as `BlobRangesStreamV1` for semantic v7/v8.
- Preserve semantic-v1 through semantic-v8 bytes and behavior exactly. Semantic v9's Blob offer is `[5]`; mixed-version contacts select v8/profile 4 or v7/profile 4 through semantic negotiation, never by downgrading an active profile-5 attempt.
- Reuse PR 47 lifetime, age, lease, pressure, retirement, deletion-fence, reclamation, and public Rust API authority. Do not create a parallel lifecycle model.
- Define `BlobCustodyClaimV2` for semantic v9/profile 5. Do not reinterpret PR 47's v8/profile-4 `BlobCustodyClaimV1` bytes or contextual domain.
- Keep the application Blob API transport-blind. Configuration may set adapter enablement and resource limits; callers cannot choose transport, extent, checkpoint cadence, offset, or failover.
- Carry data over exactly one selected transport adapter per logical attempt. No striping, speculative duplication, multipath scheduling, or multi-peer parallel download.
- Use existing signed sources, manifests, physical lineage, carrier proofs, chunk records, and atomic promotion. A stream extent is scheduling, not a new integrity identity.
- `StreamDataV1` contains a canonical manifest-ordered sequence of complete carriers. Checkpoints occur only after complete verified carriers; resume state is a contiguous next-carrier index, encoded offset, and generation.
- Bound one extent at 1 MiB. Reserve a global header permit before header read and an exact global body permit after canonical length validation but before body read/allocation; release permits on every path. Bound queued records and sessions as well as payload buffers. Never allocate by whole-Blob length or advertised receive window.
- Use checked `u64` arithmetic for lengths, offsets, credit, chunk counts, file accounting, and quota reservation. Configured policy must admit at least 2 GiB when storage quota permits.
- Acknowledge only progress durable in synchronized chunk files, redb chunk markers, and the stream checkpoint. Files durable before a failed metadata transaction are non-authoritative until exact recovery verification.
- Hold lifecycle leases only around one bounded extent read/verify/commit operation. An open network stream never leases the whole Blob.
- Treat close or positive-credit stall as retry/failover, suspend the data-stall timer during zero-credit backpressure, and use a separate bounded authenticated liveness deadline. Prolonged healthy zero credit is deferred capacity, not transport failure. Integrity/protocol/lifecycle/store contradictions are typed terminal outcomes. Structural corruption is never absence, expiry, or retry.
- Keep status/logs bounded and sanitized: no raw paths, credentials, peer-controlled error strings, or unbounded attempt history.
- Do not run the full local workspace suite. Run each task's focused tests and use required final-SHA CI as broad integration evidence, recording workflow URL, run ID, commit, job conclusions, and artifact digests.
- Preserve unrelated changes. Every task ends in a signed, reviewable commit.

## Review Focus

- **Identity and downgrade substitution:** tests in Tasks 1-3 and 7 must reject version/profile/transcript/direction/attempt/custody substitutions, preserve v7/v8 vectors exactly, and prevent profile-5 work from resuming under profile 4.
- **Crash and acknowledgement ordering:** tests in Tasks 2, 5, and 7 must prove bytes are acknowledged only after file and redb authority agree, one exact prefix survives every crash boundary, and settlement cannot repeat promotion or advance another cursor.
- **Lifecycle and provenance transitions:** tests in Tasks 3 and 6 must preserve nondecreasing finite age, make profile-4-to-profile-5 adoption an atomic one-way upgrade, and retain PR 47 expiry, pressure, deletion, shared-variant, and evidence rules.
- **Adversarial resource input:** tests in Tasks 2, 5, 6, and 8 must reject oversized/overflowing lengths before allocation, enforce global buffer/lease/quota limits, and keep metadata/checkpoint growth independent of Blob length.
- **Selection and recovery claims:** tests in Tasks 4, 7, and 9 must enforce one active adapter, deterministic ranking, fresh authentication/negotiation/custody on each attempt, resume from receiver-durable progress only, bounded retransmission, and sanitized metrics. Iroh-only delivery claims reopen, not cross-transport failover; that claim requires Task 4's second-adapter gate.

---

### Task 1: Establish the reviewed baseline and allocate semantic v9/profile 5

**Files:**
- Modify: `crates/aster-core/src/wire.rs`
- Modify: `crates/aster-core/src/crypto.rs`
- Modify: `crates/aster-core/src/crypto/reference.rs`
- Modify: `crates/aster-core/src/store.rs`
- Modify: `crates/aster-core/src/runtime.rs`
- Modify: `crates/aster-core/src/runtime/reference_semantic.rs`
- Modify: `crates/aster-core/src/batch.rs`
- Modify: `crates/aster-core/src/transfer_profile.rs`
- Modify: `crates/aster-node/src/event_pages.rs`
- Modify: `crates/aster-node/src/frame.rs`
- Modify: `crates/aster-node/src/lib.rs`
- Modify: `docs/protocol.md`
- Modify: `docs/transports.md`
- Modify: `docs/architecture.md`
- Test: colocated `#[cfg(test)]` modules in the files above

**Interfaces:**
- Consumes: exact PR 71/47 registry: profile `3` reserved, profile `4 = BlobRangesStreamV1`, semantic v7 durable-only and v8 finite-custody profile-4 policy.
- Produces: `wire::SEMANTIC_PROTOCOL_V9: u16 = 9` and highest-common negotiation over `[9, 8, 7, 6, 5, 4, 3, 2, 1]`.
- Produces: `TransferProfileId::BlobStreamV1 = 5`; semantic-v9 Blob offer `[BlobStreamV1]`, semantic-v7/v8 Blob offer `[BlobRangesStreamV1]`.
- Preserves: every v1-v8 wire, crypto, store, profile-offer, digest, custody, and runtime vector.

- [ ] **Step 1: Recheck the base and allocation registries**

  Confirm the implementation base contains exact reviewed PR 71 and PR 47 heads or their final merge commits. Inspect open PRs for semantic v9, profile `5`, tags `0xd6..0xdc`, and Decision 0046 conflicts. Stop for a design amendment if any allocation is no longer free.

- [ ] **Step 2: Write failing semantic-version and profile tests**

  Add `semantic_protocol_v9_*` and `transfer_profile_v9_*` tests for highest-common v9, v9/v8 and v9/v7 fallback, exact v7/v8 offer bytes, v9 Blob offer `[5]`, profile-5 Blob-only validation, unknown optional/critical IDs, empty intersection, and canonical offer/digest vectors.

- [ ] **Step 3: Run focused allocation tests and verify RED**

  Run: `cargo test --locked -p aster-core semantic_protocol_v9 -- --nocapture`

  Run: `cargo test --locked -p aster-node transfer_profile_v9 --lib -- --nocapture`

  Expected: compilation or assertions fail because v9/profile 5 is absent.

- [ ] **Step 4: Add semantic v9 to every validated registry**

  Extend wire, crypto, reference-session, store, batch, runtime, and structured-fuzz semantic matches. Keep the existing suite/profile and add v9 vectors rather than changing v8 fixtures.

- [ ] **Step 5: Implement version-aware profile-5 offers**

  Add `BlobStreamV1 = 5`, accept it only for Blob, return `[5]` for semantic v9, and preserve exact `[4]` profile-4 behavior for v7/v8. Include canonical offers/intersections in the existing digest and reject profile-5 selection before v9.

- [ ] **Step 6: Specify the allocation before runtime activation**

  Add v9/profile-5/tag registry rows, exact mixed-version rules, profile-4 preservation, and finite no-downgrade wording to protocol/transport/architecture docs.

- [ ] **Step 7: Run focused allocation regressions and verify GREEN**

  Run: `cargo test --locked -p aster-core semantic_protocol -- --nocapture`

  Run: `cargo test --locked -p aster-node transfer_profile --lib -- --nocapture`

  Run: `cargo test --locked -p aster-node v8_ --lib -- --nocapture`

  Expected: v9 tests pass and all v7/v8 profile/custody vectors remain unchanged.

- [ ] **Step 8: Commit the allocation**

  Commit: `feat(protocol): allocate Blob streaming semantic v9`

### Task 2: Implement the class-neutral stream codec and pure state machine

**Files:**
- Create: `crates/aster-node/src/stream_transfer.rs`
- Modify: `crates/aster-node/src/lib.rs`
- Modify: `crates/aster-node/src/frame.rs`
- Modify: `fuzz/Cargo.toml`
- Create: `fuzz/fuzz_targets/stream_transfer_decode.rs`
- Create: `fuzz/corpus/stream_transfer_decode/stream-open-minimal`
- Create: `fuzz/corpus/stream_transfer_decode/stream-data-empty-invalid`
- Modify: `docs/protocol.md`

**Interfaces:**
- Produces: `StreamClass::Blob = 1`, rejecting unknown required classes.
- Produces: canonical `StreamOpenV1`, `StreamAcceptV1`, `StreamDataV1`, `StreamCheckpointV1`, `StreamFinishV1`, `StreamResultV1`, and `StreamResultAckV1`.
- Produces: tags `0xd6..0xdc`, accepted only in semantic v9 with selected profile 5.
- Produces: pure `StreamSenderState` and `StreamReceiverState` transition APIs returning `Send`, `Persist`, `Promote`, `Retry`, or `Terminal` actions without I/O.
- Produces: `MAX_STREAM_EXTENT_BYTES: usize = 1_048_576` plus a strict fixed-overhead-aware codec bound.
- Produces: explicit bounded header/body decoding stages whose callers must reserve global memory before reading or allocating peer-declared bodies.

- [ ] **Step 1: Write byte-exact failing codec tests**

  Cover all seven records and every identity field, checked `u64` length/offset/credit, sequence, nonce, checkpoint generation, result digest, truncation, trailing bytes, noncanonical enums/booleans, zero/oversized extents, overflow, and pre-v9/profile-mismatch decode.

- [ ] **Step 2: Run codec tests and verify RED**

  Run: `cargo test --locked -p aster-node stream_frame_codec --lib -- --nocapture`

  Expected: compilation fails because the stream records/tags do not exist.

- [ ] **Step 3: Implement the bounded canonical codec**

  Decode fixed fields before variable payload, reject oversized declarations before allocation, use checked conversions, reject trailing material, and keep free-form strings out of protocol outcomes.

- [ ] **Step 4: Write failing pure transition tests**

  Cover open/accept, pipelined extents under absolute credit, unchanged credit, cumulative checkpoints, multiple credit cycles without stream reopen, zero credit beyond the data-stall deadline, duplicates, data below checkpoint, gaps/overlap, sequence mismatch, credit violation, attempt replay, finish/result/ack idempotence, and each typed terminal result.

- [ ] **Step 5: Run state tests and verify RED**

  Run: `cargo test --locked -p aster-node stream_state --lib -- --nocapture`

  Expected: transition tests fail because the engines are absent.

- [ ] **Step 6: Implement the pure transition engines**

  Separate attempt-local received progress from durable progress, keep credit absolute and monotonic within one attempt, require a fresh nonce for reopen, resume only from receiver-authoritative checkpoints, and digest-bind idempotent settlement.

- [ ] **Step 7: Add structured fuzz entry points**

  Export the minimum `fuzzing` seam, seed every v9 record, and feed decoded records through bounded state transitions without filesystem or network I/O.

- [ ] **Step 8: Run focused codec/state/fuzz checks and verify GREEN**

  Run: `cargo test --locked -p aster-node stream_ --lib -- --nocapture`

  Run: `cargo check --locked --manifest-path fuzz/Cargo.toml --bin stream_transfer_decode`

  Expected: focused tests pass and the fuzz target builds.

- [ ] **Step 9: Commit the protocol engine**

  Commit: `feat(protocol): add bounded stream transfer grammar`

### Task 3: Add semantic-v9 custody and mission-bound ordered records

**Files:**
- Create: `crates/aster-core/src/blob_custody_v2.rs`
- Modify: `crates/aster-core/src/lib.rs`
- Modify: `crates/aster-core/src/crypto/reference.rs`
- Modify: `crates/aster-node/src/mission.rs`
- Modify: `crates/aster-node/src/stream_transfer.rs`
- Modify: `crates/aster-node/src/runtime.rs`
- Modify: `crates/aster-iroh/src/lib.rs` to expose a concurrently open bounded data/control pair with finish/reset observation
- Create: `conformance/vectors/blob-custody-v9.tsv`
- Test: colocated core/node/Iroh tests

**Interfaces:**
- Produces: 208-byte `BlobCustodyClaimV2` with magic `ASTRBL09`, format version `2`, semantic version `9`, profile ID `5`, lane ID `4`, and the approved PR 47 fields/age semantics.
- Produces: non-clone authenticated receive/send capabilities constructible only by a successfully opened v9/profile-5 record and consumable exactly once by Store admission.
- Produces: `ApplicationRecordContext { semantic_version, transfer_profile_digest, lane, profile, direction, attempt_nonce, record_sequence }` under `ASTER/v9-lane-record/v1\0`; custody contact identity uses `ASTER/v9-blob-custody-contact/v2\0`.
- Consumes: existing Iroh connection primitives, extended to provide either one bounded bidirectional stream or two concurrently open bounded unidirectional streams with fixed data/control roles.
- Preserves: v7/v8 contextual domains, `BlobCustodyClaimV1`, profile-4 bytes, and replay-window behavior.

- [ ] **Step 1: Write failing custody-v2 vectors and capability tests**

  Assert exact encoding and reject v8/v9 magic, semantic, profile, transcript, direction, transfer, priority, TTL, age, length, publication, lineage, and claim-digest substitution. Assert duplicate observations merge age monotonically and never rejuvenate finite work.

- [ ] **Step 2: Run custody tests and verify RED**

  Run: `cargo test --locked -p aster-core blob_custody_v2 -- --nocapture`

  Expected: compilation fails because v2 claims/capabilities do not exist.

- [ ] **Step 3: Implement `BlobCustodyClaimV2` and one-use capabilities**

  Reuse PR 47's verified lifetime calculations and field meanings; change only the exact version/profile/session/transfer domain required by the spec. Do not accept decoded claim bytes as Store authority without the authenticated capability.

- [ ] **Step 4: Write failing mission-context substitution tests**

  Cover semantic version, profile digest, lane, profile, direction, attempt nonce, record sequence, transcript, and cross-v8/v9 replay. Retain byte-exact v7 Event and v8 Blob fixtures.

- [ ] **Step 5: Generalize mission protection and ordered-turn helpers**

  Add the v9 profile-5 AAD domain and bounded long-lived record helpers. Keep sender-to-receiver data and receiver-to-sender credit/checkpoint control open concurrently for the attempt; do not serialize them as an ordered pair and do not reopen per extent or checkpoint.

- [ ] **Step 6: Run focused custody/mission/Iroh tests and verify GREEN**

  Run: `cargo test --locked -p aster-core blob_custody -- --nocapture`

  Run: `cargo test --locked -p aster-node contextual_application_frame --lib -- --nocapture`

  Run: `cargo test --locked -p aster-iroh uni_turn -- --nocapture`

  Expected: v9 tests pass and v7/v8 fixtures remain exact.

- [ ] **Step 7: Commit the authenticated record seam**

  Commit: `feat(protocol): bind v9 Blob custody and stream records`

### Task 4: Add deterministic internal transport selection and authenticated recovery

**Files:**
- Create: `crates/aster-node/src/stream_transport.rs`
- Modify: `crates/aster-node/src/lib.rs`
- Modify: `crates/aster-node/src/runtime.rs`
- Modify: `crates/aster-iroh/src/lib.rs`
- Modify: `docs/transports.md`

**Interfaces:**
- Produces: `StreamTransportId::IrohQuicV1 = 1`; candidate support and peer locators come from authenticated configuration, provisioned peer records, or authenticated discovery before `StreamOpenV1`, not from a capability list first seen inside that frame.
- Produces: internal object-safe `StreamTransportAdapter` methods for `id`, `eligibility`, `health`, `open_attempt`, and bounded record I/O, using boxed futures/project conventions without a new async-trait dependency.
- Produces: `TransportSelector::rank(TransferRequirements, &[TransportCandidate]) -> Vec<TransportCandidate>` ordered by policy eligibility, stream support, health, configured priority, then stable ID. Direct/relay is an Iroh-local health observation, not a separately selectable transport.
- Produces: `AttemptCoordinator` with one active adapter, fresh peer/mission authentication, semantic/profile negotiation, nonce, transcript binding, and finite custody-v2 verification on every retry; receiver-durable checkpoint carry-forward happens only after those checks.
- Claim gate: Iroh-only delivery demonstrates automatic choice of the sole eligible production adapter and authenticated reopen. Best-available cross-transport selection/failover requires a separately reviewed second production adapter satisfying the same reliable full-duplex stream contract; fake adapters cannot satisfy that gate.

- [ ] **Step 1: Write failing selector tests with fake adapters**

  Cover authenticated pre-open capability intersection, disabled/prohibited candidates, health, deterministic ties, one-active invariant, retryable close/positive-credit stall, zero-credit beyond the data-stall deadline, control-liveness failure, terminal protocol/integrity outcomes, exhaustion, cancellation, fresh authentication/transcript/nonces/custody, non-younger age merge, and retransmission from checkpoint rather than last write.

- [ ] **Step 2: Run selector tests and verify RED**

  Run: `cargo test --locked -p aster-node stream_transport --lib -- --nocapture`

  Expected: compilation fails because the selector/adapter seam is absent.

- [ ] **Step 3: Implement the adapter-neutral selector/coordinator**

  Keep ranking inputs local, authenticated, and bounded; never accept peer scores. Make retry budget, positive-credit stall deadline, control-liveness deadline, and enablement configuration-owned while keeping protocol terminal results transport-neutral.

- [ ] **Step 4: Implement the first production adapter**

  Wrap authenticated Iroh connections and Task 3 concurrent data/control streams as `IrohQuicV1`. Expose Iroh direct/relay only as privileged sanitized health/metrics while Iroh owns establishment and path changes.

- [ ] **Step 5: Run fake-failover and Iroh-reopen tests**

  Run: `cargo test --locked -p aster-node stream_transport --lib -- --nocapture`

  Run: `cargo test --locked -p aster-node stream_iroh_adapter --lib -- --nocapture`

  Expected: deterministic selection, one-active behavior, multiple credit cycles without reopen, backpressure without false stall, and checkpointed authenticated reopen pass.

- [ ] **Step 6: Document the shipped boundary**

  State that the selector is protocol/runtime infrastructure with one production adapter; fake adapters prove policy mechanics but are not product transport support. Explicitly withhold cross-transport selection/failover claims until a second production adapter and physical scenario are reviewed and complete.

- [ ] **Step 7: Commit transport selection**

  Commit: `feat(node): select one Blob stream transport`

### Task 5: Add crash-safe whole-carrier batches and durable checkpoints

**Files:**
- Create: `crates/aster-redb-store/src/blob/stream.rs`
- Modify: `crates/aster-redb-store/src/blob.rs`
- Modify: `crates/aster-redb-store/src/blob/depot.rs`
- Modify: `crates/aster-core/src/blob.rs`
- Test: colocated Store/depot/blob tests

**Interfaces:**
- Produces: `BlobStreamCheckpoint { next_carrier_index: u64, durable_encoded_offset: u64, generation: u64 }`, one constant-sized row per pending source.
- Produces: `BlobStreamLayout`, the checked separator-free concatenation of canonical carrier bytes in manifest-index order; checkpoints are carrier boundaries.
- Produces: `VerifiedBlobStreamExtent`, one or more complete ordered verified carriers totaling at most the receiver extent bound.
- Produces: `VerifiedBlobStreamCheckpointBatch`, complete verified carriers accumulated from one or more extents, with a 4-MiB default byte threshold, 250-ms default timer, and 8-MiB hard maximum; the receiver advertises any smaller limit.
- Produces: `OwnedBlobStreamExtent` for bounded source reads and `BlobStreamCommitOutcome::{Advanced(BlobStreamCheckpoint), Duplicate(BlobStreamCheckpoint), Complete(BlobStreamCheckpoint)}` for receiver commits.
- Produces: `Store::blob_stream_checkpoint_with_policy(&self, policy: &ControlPolicySnapshot, source: BlobTransferId, plan: &VerifiedBlobTransferPlan) -> Result<BlobStreamCheckpoint, StoreError>`.
- Produces: `Store::commit_blob_stream_batch_with_policy(&self, policy: &ControlPolicySnapshot, source: BlobTransferId, plan: &VerifiedBlobTransferPlan, expected: BlobStreamCheckpoint, batch: VerifiedBlobStreamCheckpointBatch) -> Result<BlobStreamCommitOutcome, StoreError>` with `Advanced`, `Duplicate`, or `Complete`; exactly one redb transaction advances all carrier markers, counters, and the cumulative checkpoint for the batch.
- Produces: `Store::read_completed_blob_stream_extent_with_policy(&self, policy: &ControlPolicySnapshot, completion: &VerifiedBlobContentCompletion, plan: &VerifiedBlobTransferPlan, checkpoint: BlobStreamCheckpoint, max_bytes: usize) -> Result<Option<OwnedBlobStreamExtent>, StoreError>`.

- [ ] **Step 1: Write failing layout/checkpoint tests**

  Cover zero/nonzero carriers, checked encoded-length sums, exact carrier boundaries, 64-MiB boundary, 1-GiB/2-GiB shapes, multi-extent batches, byte/timer/hard bounds, stale generation, forward skip, overlap, duplicate extent, wrong carrier order/proof, and constant-sized checkpoint rows.

- [ ] **Step 2: Run checkpoint tests and verify RED**

  Run: `cargo test --locked -p aster-redb-store blob_stream_checkpoint -- --nocapture`

  Expected: tests fail because stream layout/checkpoint APIs are absent.

- [ ] **Step 3: Implement whole-carrier extent assembly and verification**

  Read/verify incrementally, enforce manifest order and complete carrier boundaries, cap aggregate bytes before allocation, and avoid whole-Blob or whole-window buffering.

- [ ] **Step 4: Write failing batch durability/fault tests**

  Inject failure before file sync, after rename, after directory sync, before redb commit, after checkpoint commit, and during reopen. Assert one exact prefix, no acknowledgement of nondurable data, and no double accounting.

- [ ] **Step 5: Run batch fault tests and verify RED**

  Run: `cargo test --locked -p aster-redb-store blob_stream_batch_fault -- --nocapture`

  Expected: failures expose per-range authority and missing cumulative checkpoint behavior.

- [ ] **Step 6: Implement files-first batch authority**

  Synchronize every exact chunk file/directory in the bounded batch first, then commit all batch chunk markers, counters, and the one cumulative checkpoint in one immediate-durability redb transaction. Recover/adopt orphaned files only after exact verification. Keep the maximum uncheckpointed tail at or below the lesser of the advertised receive window and checkpoint-batch limit.

- [ ] **Step 7: Remove per-carrier completion rescans from the stream path**

  Carry validated layout/index state through the batch and perform complete variant verification once at terminal promotion, preserving PR 47 structural checks.

- [ ] **Step 8: Run focused Store/depot tests and verify GREEN**

  Run: `cargo test --locked -p aster-redb-store blob_stream_ -- --nocapture`

  Run: `cargo test --locked -p aster-core blob_stream_layout -- --nocapture`

  Expected: layout, fault, duplicate, and existing depot regressions pass.

- [ ] **Step 9: Commit the Store seam**

  Commit: `feat(blob): persist batched stream checkpoints`

### Task 6: Compose profile 5 with PR 47 lifecycle and provenance

**Files:**
- Modify: `crates/aster-redb-store/src/blob/lease.rs`
- Modify: `crates/aster-redb-store/src/blob/stream.rs`
- Modify: `crates/aster-redb-store/src/blob/lifecycle.rs`
- Modify: `crates/aster-redb-store/src/blob/pressure.rs`
- Modify: `crates/aster-redb-store/src/blob.rs`
- Modify: `crates/aster-node/src/application/blob.rs`
- Test: colocated lifecycle, pressure, Store, and application tests

**Interfaces:**
- Produces: `BlobLeaseKind::CarrierExtent`, counted against PR 47 `network_sessions`; retains `CarrierRange` for profile 4.
- Consumes: PR 47 lease registry, deletion fences, pending lifetime/provenance, TTL/policy checkpoints, pressure decisions, retirement evidence, and authorized cleanup.
- Produces: `BlobStreamProvenanceUpgrade::{AlreadyV9(BlobStreamCheckpoint), Upgraded(BlobStreamCheckpoint)}`.
- Produces: atomic `Store::upgrade_pending_blob_to_stream_v9(&self, policy: &ControlPolicySnapshot, source: BlobTransferId, blob: &ContentVerifiedBlobEnvelope, sealed: &[u8], plan: &VerifiedBlobTransferPlan, finite: Option<(BlobCustodyClaimV2, AuthenticatedBlobCustodyContactV2)>) -> Result<BlobStreamProvenanceUpgrade, StoreError>`, requiring exact source/publication/variant/layout/lineage and a non-younger authenticated v2 capability for finite work.
- Produces: checked configurable large-object limits and exact reservation for physical bytes, chunk rows, pending/checkpoint rows, lifecycle/replay capacity, and at least 2-GiB admission.
- Produces: typed lifecycle-to-stream terminal mapping without free-form peer text.

- [ ] **Step 1: Write failing lifecycle and provenance-upgrade tests**

  Cover expiry/policy/deletion before open, credit, extent, checkpoint, promotion, and result replay; lease exhaustion; shared variants; pressure eviction; restart; no TTL reset; exact durable/finite profile-4 upgrade; younger/tampered/mismatched rejection; atomic rollback; and no downgrade after upgrade.

- [ ] **Step 2: Run lifecycle tests and verify RED**

  Run: `cargo test --locked -p aster-redb-store blob_stream_lifecycle -- --nocapture`

  Expected: tests fail because extent leases, v9 provenance, and large-object admission are absent.

- [ ] **Step 3: Add the bounded extent lease**

  Acquire `CarrierExtent` only after bounded parse and before depot access; release after read/commit. Stop new credit when retirement begins while letting one admitted operation reach its PR 47 commit/reject boundary.

- [ ] **Step 4: Implement the one-way provenance upgrade**

  Consume the authenticated v9 capability, require exact immutable identity/layout, merge finite age monotonically, retain verified carrier files, replace semantic/profile provenance and checkpoint generation atomically, and leave profile-4 state unchanged on failure.

- [ ] **Step 5: Implement checked large-object policy and reservation**

  Replace profile-5 use of 64-MiB/1,024-chunk limits with configurable checked limits while leaving profile 4 unchanged. Extend the existing file-based publish implementation without adding transport controls to `BlobPublishOptions`.

- [ ] **Step 6: Route lifecycle outcomes through PR 47 authority**

  Use existing expiry, invalidation, pressure, retirement, deletion, and reclamation paths. Preserve lineage/owner/accounting/schema/capability evidence on structural contradictions.

- [ ] **Step 7: Run focused lifecycle/application regressions and verify GREEN**

  Run: `cargo test --locked -p aster-redb-store blob_stream_lifecycle -- --nocapture`

  Run: `cargo test --locked -p aster-node blob_stream_lifecycle --lib -- --nocapture`

  Run: `cargo test --locked -p aster-node blob_publish_options --lib -- --nocapture`

  Expected: v9 composition and existing PR 47 lifetime/API tests pass.

- [ ] **Step 8: Commit lifecycle composition**

  Commit: `feat(blob): compose v9 streaming with lifecycle policy`

### Task 7: Drive Blob streaming and expose bounded status

**Files:**
- Create: `crates/aster-node/src/runtime/blob_stream.rs`
- Modify: `crates/aster-node/src/runtime.rs`
- Modify: `crates/aster-node/src/lib.rs`
- Modify: `crates/aster-node/src/application/blob.rs`
- Modify: `crates/aster-redb-store/src/blob.rs`
- Test: colocated runtime/application tests

**Interfaces:**
- Consumes: profile-5 negotiation, custody-v2 capabilities, stream state machines, `AttemptCoordinator`, Store batch/checkpoint/provenance APIs, and PR 47 lifecycle outcomes.
- Produces: source bounded-extent reader and receiver verifier/committer for one logical transfer.
- Produces: bounded public `BlobStreamTransferStatus` with phase, total/durable bytes, rolling throughput, and sanitized terminal category only.
- Produces: separate privileged/operator telemetry with transport ID, candidate ranking, attempt count, received/retransmitted bytes, receive limit, checkpoint, checkpoint latency, writer-commit count, and failover recovery. These fields are not exposed through the public Blob application API.
- Produces: v9 settlement that advances the existing publication cursor only after bound `StreamResultAck`.
- Preserves: PR 71 profile-4 runtime, PR 47 public lifetime API, and all v1-v8 behavior.

- [ ] **Step 1: Write failing small end-to-end runtime tests**

  Cover v9/profile-5 negotiation, one/multiple carriers, multiple extents and multiple replenishment cycles on one concurrent data/control pair, smaller receiver extents, zero/unchanged credit beyond the data-stall deadline without false failover, final checkpoint, exact promotion, result/ack replay, finite v2 custody, and transport-blind application behavior.

- [ ] **Step 2: Run focused runtime tests and verify RED**

  Run: `cargo test --locked -p aster-node live_blob_stream_v9 --lib -- --nocapture`

  Expected: tests fail because profile 5 has no runtime driver.

- [ ] **Step 3: Implement source and receiver drivers**

  Open authenticated long-lived turns, drive only through pure transitions, pipeline extents to absolute credit, batch durable checkpoints, revalidate lifecycle at credit/admission/promotion boundaries, and never hold depot/Store locks across network awaits.

- [ ] **Step 4: Write failing recovery and failover tests**

  Close before data, within the uncheckpointed tail, after checkpoint, during finish, after promotion before result, and after result before ack. Restart sender/receiver, continue from another eligible content peer, require fresh peer/mission authentication, semantic/profile negotiation, nonce/transcript binding and finite custody-v2 verification, merge age without rejuvenation, and cap retransmission at the uncheckpointed batch.

- [ ] **Step 5: Implement reopen and idempotent settlement**

  Keep one logical pending source across attempts, select the next adapter, use receiver checkpoint authority, and apply existing cursor settlement exactly once after acknowledged completion.

- [ ] **Step 6: Write mixed-version and provenance tests**

  Cover v9/v9 profile 5, v9/v8 profile 4 with finite custody, v9/v7 profile 4 durable-only, v9/v6 existing incompatibility, rejection of v9 tags before v9, profile-5 no-downgrade, and explicit profile-4 pending-source upgrade.

- [ ] **Step 7: Add bounded status and contact metrics**

  Add stable numeric fields/fixed enums and aggregate attempt history. Keep only high-level transfer progress in the application status; put transport/checkpoint/commit/failover internals behind privileged diagnostics. Preserve PR 71 range counters with their existing meaning; add distinct profile-5 metrics and never log raw peer errors or paths.

- [ ] **Step 8: Run focused runtime regressions and verify GREEN**

  Run: `cargo test --locked -p aster-node live_blob_stream_v9 --lib -- --nocapture`

  Run: `cargo test --locked -p aster-node blob_ranges_stream --lib -- --nocapture`

  Run: `cargo test --locked -p aster-node live_selected_blob --lib -- --nocapture`

  Expected: v9 streaming/recovery/status and existing profile-4/lifecycle tests pass.

- [ ] **Step 9: Commit runtime integration**

  Commit: `feat(node): stream and resume large Blobs`

### Task 8: Add large-object, bounded-resource, and conformance coverage

**Files:**
- Create: `crates/aster-node/tests/blob_stream_conformance.rs`
- Modify: `crates/aster-node/src/lib.rs` only for bounded test seams
- Modify: `conformance/blob_stream_oracle.py`
- Create: `conformance/vectors/blob-stream-v9.tsv`
- Modify: `fuzz/fuzz_targets/selected_frame_decode.rs`
- Modify: `tools/test-network-contention.py`
- Modify: `mise.toml`
- Modify: `.github/workflows/ci.yml`
- Create: `docs/validation/evidence/blob-streaming-ci-template.md`

**Interfaces:**
- Produces: independent Python construction/validation for all v9 records and custody-v2 vectors.
- Produces: deterministic incremental fixtures for 64-MiB boundary, 256 MiB, 1 GiB, and 2 GiB without two full in-memory copies.
- Produces: counters for live/peak buffers, checkpoint transactions, carrier commits, retransmission, and promotion.
- Produces: counters for header/body/session permits proving reservation precedes peer-controlled allocation and every completion/error/cancellation path releases capacity.
- Produces: required small coverage plus a named large-Blob CI job with sufficient disk/time and retained bounded metrics.

- [ ] **Step 1: Write failing small resource/commit-scaling tests**

  Assert global header/body/session ceilings under concurrency, no body allocation before reservation, exact permit release after malformed/truncated/cancelled sessions, checkpoint-scale rather than frame/carrier-scale commits, checked quota arithmetic, exact content, bounded retransmission, and one promotion.

- [ ] **Step 2: Run small conformance tests and verify RED**

  Run: `cargo test --locked -p aster-node --test blob_stream_conformance small_ -- --nocapture`

  Expected: tests fail until fixtures/counters and v9 runtime seams exist.

- [ ] **Step 3: Implement incremental fixtures and counters**

  Generate/read deterministic content incrementally, record sparse-file assumptions when used, and make tests fail on whole-object buffering or pre-durable acknowledgement.

- [ ] **Step 4: Extend independent vectors and hostile coverage**

  Add Python-generated v9/custody-v2 records, all seven tags to structured fuzzing, and hostile length/offset/credit/sequence/generation/settlement/allocation cases.

- [ ] **Step 5: Add CI partitioning without weakening gates**

  Put small tests in normal required jobs. Add a large-Blob job with explicit timeout/disk preflight and uploaded metrics; do not relabel smoke or synthetic results as CM4 qualification.

- [ ] **Step 6: Run focused local checks and verify GREEN**

  Run: `cargo test --locked -p aster-node --test blob_stream_conformance small_ -- --nocapture`

  Run: `cargo check --locked --manifest-path fuzz/Cargo.toml --bin selected_frame_decode --bin stream_transfer_decode`

  Run: `python3 conformance/blob_stream_oracle.py`

  Run: `python3 tools/test-network-contention.py`

  Expected: focused checks pass. Do not run the full local suite.

- [ ] **Step 7: Commit conformance and CI coverage**

  Commit: `test(blob): cover large streaming recovery bounds`

### Task 9: Extend path-lab for windowing and authenticated recovery

**Files:**
- Create: `docker/path-lab/scenarios/blob-streaming-netem.json`
- Create: `tools/aster_blob_streaming_path.py`
- Create: `tools/test_aster_blob_streaming_path.py`
- Modify: `docker/path-lab/Dockerfile.delivery`
- Modify: `.github/workflows/ci.yml`
- Create: `docs/validation/blob-streaming-path-lab.md`

**Interfaces:**
- Produces: bounded netem scenarios for RTT, bandwidth, loss, Iroh disconnect/reopen, and receiver restart. A cross-transport scenario is added only with a second production adapter.
- Produces: JSON metrics for payload throughput, bandwidth-delay product/window, checkpoint commits, retransmission tail, recovery, CPU, RSS, and storage.
- Produces: assertions that throughput is not bounded by `16 KiB / RTT` and retry begins at the durable checkpoint.

- [ ] **Step 1: Write failing controller/schema tests**

  Cover valid parsing, rejected unbounded sizes/durations, exact command construction, artifact confinement, timeout/cleanup, netem restoration, and required metric fields.

- [ ] **Step 2: Run controller tests and verify RED**

  Run: `python3 tools/test_aster_blob_streaming_path.py`

  Expected: failure because controller/scenario files do not exist.

- [ ] **Step 3: Implement the bounded path-lab controller**

  Reuse current path-lab conventions, generate content incrementally, inject deterministic link/process faults, verify final digest, and emit bounded sanitized JSON.

- [ ] **Step 4: Add required CI smoke scenarios**

  Exercise RTT windowing, multiple credit cycles on one data/control pair, zero-credit backpressure beyond the data-stall deadline, and one authenticated checkpointed reconnect at small size. Reserve 256-MiB-plus attribution for large CI/manual/physical runs.

- [ ] **Step 5: Run controller and scenario validation**

  Run: `python3 tools/test_aster_blob_streaming_path.py`

  Run: `python3 tools/aster_path_lab.py docker/path-lab/scenarios/blob-streaming-netem.json`

  Expected: unit/schema/dry-run checks pass; CI supplies Docker execution evidence.

- [ ] **Step 6: Commit path-lab coverage**

  Commit: `test(path-lab): exercise Blob stream windowing`

### Task 10: Publish normative documentation and three-CM4 procedure

**Files:**
- Create: `docs/decisions/0046-stream-large-blobs-over-selected-transport.md`
- Modify: `docs/protocol.md`
- Modify: `docs/envelope.md`
- Modify: `docs/transports.md`
- Modify: `docs/architecture.md`
- Modify: `docs/validation/conformance.md`
- Modify: `docs/validation/capability-roadmap.md`
- Modify: `docs/validation/requirements-status.md`
- Modify: `docs/validation/requirements-implementation.csv`
- Create: `docs/validation/blob-streaming-cm4-procedure.md`
- Create: `docs/validation/evidence/2026-10-15-cm4-blob-streaming-inventory-amendment.md`
- Create: `docs/validation/evidence/blob-streaming-cm4-receipt.schema.json`
- Create: `docs/validation/evidence/blob-streaming-cm4-receipt.example.json`
- Modify: `crates/aster-node/src/stream_transfer.rs`

**Interfaces:**
- Consumes: implemented v9/profile-5 behavior, independent vectors, PR 71/47 baseline semantics, CI artifacts, and production counters.
- Produces: byte-exact normative v9/profile-5 and custody-v2 grammar with explicit v7/v8 preservation.
- Produces: frozen procedure for `cm4-a`/`rpi4-1`, `cm4-b`/`rpi4-2`, and `cm4-support`/`rpi4-3`, assigning the third device failure-test/alternate-content-peer duties.
- Produces: receipt schema for component baselines, 1-GiB/2-GiB bidirectional transfers, three-node resume, Iroh path reopen, process recovery, lifecycle races, digest, CPU/RSS/storage, commits/latency, retransmission, and recovery; a separately gated cross-transport receipt section becomes required only after a second production adapter exists.

- [ ] **Step 1: Verify canonical vectors against the normative model**

  Cover every record, custody-v2 claim, malformed encoding, substitution, credit violation, duplicate/idempotent transition, v9/v9, v9/v8, v9/v7, and finite no-downgrade case using independent construction where available.

- [ ] **Step 2: Document the implemented contract and decision**

  Freeze exact tags/layouts/limits, distinguish carrier/extent/checkpoint batch, specify concurrent data/control exchange, credit/resume/provenance upgrade, state the Iroh-only milestone and cross-transport claim gate, and record why profile 4 was not mutated.

- [ ] **Step 3: Amend inventory and freeze the CM4 procedure**

  Preserve existing observed platform facts, name all aliases, bind commit/config/artifact digests, define warm-ups/samples/fault injection, and require source-read/destination-write/crypto/network baselines before the 70% calculation.

- [ ] **Step 4: Validate a clearly non-evidence receipt example**

  Use placeholder result values and validate it against the schema. Do not create a successful physical receipt without actual device execution.

- [ ] **Step 5: Update traceability conservatively**

  Separate implementation/CI conformance from physical performance. Do not mark 1-GiB/2-GiB throughput, Iroh recovery, or CM4 qualification demonstrated without a checked receipt. Never mark cross-transport selection/failover demonstrated without both a second production adapter and its checked receipt.

- [ ] **Step 6: Run focused documentation/conformance checks**

  Run: `python3 tools/check-implementation-requirements.py`

  Run: `cargo test --locked -p aster-node blob_stream_vector_corpus --lib -- --nocapture`

  Run: the JSON Schema validation command added with the receipt schema

  Expected: mappings, vectors, and example validate.

- [ ] **Step 7: Capture required final-SHA CI evidence**

  Push the exact commit, wait for every required job including large-Blob/path-lab, and fill the CI evidence note with workflow URL, run ID, commit, conclusions, artifact digests, and claim limits. Any failing/cancelled required job blocks completion.

- [ ] **Step 8: Execute the physical procedure when all three CM4s are available**

  Run 1-GiB/2-GiB both directions, three-node resume, Iroh path reopen, process recovery, PR 47 lifecycle races, and exact digest verification. If a second production adapter is present, also run cross-transport reselection with fresh authentication. If devices are unavailable, leave this step and physical claims explicitly open.

- [ ] **Step 9: Commit documentation and validation contracts**

  Commit: `docs(blob): specify and validate v9 streaming`

### Task 11: Final review, CI gate, and branch handoff

**Files:**
- Modify: implementation/evidence files above only as required by review
- Review: complete branch diff against the exact PR 71/47 base

**Interfaces:**
- Consumes: Tasks 1-10 and final-SHA required CI.
- Produces: a reviewable branch with no stale allocation claims, duplicate lifecycle authority, or evidence overclaim; physical-validation status remains explicit.

- [ ] **Step 1: Audit the final diff against the approved spec**

  Trace every goal, non-goal, invariant, error, compatibility rule, performance measure, and CM4 scenario. Search for accidental v9 use of profile-4 limits, per-range loops, semantic-v8/profile-4 reinterpretation, and stale 64-MiB/1,024-chunk ceilings.

- [ ] **Step 2: Perform targeted security/crash review**

  Review allocation-before-validation, checked arithmetic, AAD/custody bindings, replay/settlement, locks across await, file/redb ordering, lease scope, provenance upgrade atomicity, cleanup authority, cancellation, zeroization, and status sanitization.

- [ ] **Step 3: Run focused format and diff hygiene**

  Run: `cargo fmt --all -- --check`

  Run: `git diff --check 04de641bfb3d647290ffffabe40ec284d9865a95...HEAD`

  Run: all focused generated-vector/traceability/schema checks changed by this branch

  Expected: focused checks pass. Do not run the full local suite; required CI is broad evidence.

- [ ] **Step 4: Confirm final-SHA CI and review evidence**

  Verify required checks target the final commit, large-Blob artifacts are retained, the base contains final PR 71/47 history, and physical CM4 work is accurately complete or open.

- [ ] **Step 5: Request whole-branch code review**

  Review protocol interoperability, mission/custody binding, Store crash atomicity, PR 47 ownership, selector claims, bounded resources, mixed versions, and evidence boundaries.

- [ ] **Step 6: Commit review remediations if needed**

  Commit: `fix(blob): address streaming protocol review`
