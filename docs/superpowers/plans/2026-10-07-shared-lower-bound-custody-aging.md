# Shared Lower-Bound Custody Aging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Continue accumulating only provable monotonic residence after custody-clock continuity loss so finite Event data remains withheld but eventually becomes certainly expired and reclaimable.

**Architecture:** Extend the shared `CustodyAge` state machine without changing wire claims, then apply the same rules to the reference store/bridge paths and selected redb Event custody. Reuse the existing redb expiration index as both a precise deadline index and a bounded re-anchor queue, so every discontinuous row can enter a later clock domain without an unbounded scan or a new side ledger.

**Tech Stack:** Rust, redb, Aster semantic-v3 custody model, Cargo tests, `mise` repository gates

**Spec:** `docs/superpowers/specs/2026-10-07-blob-lifecycle-design.md`

## Global Constraints

- Start implementation only after the bounded-custody work is merged into `main`; create the implementation branch directly from the updated `main`, do not use a stacked PR, and do not reimplement its bounded maintenance work.
- This PR is wire-neutral: no custody-claim, source-envelope, semantic-version, RPC, CLI, or Blob behavior changes.
- `CustodyContinuity::Lost` remains sticky and finite data remains non-forwardable and non-readable while its lower bound is below TTL.
- An unmeasurable interval contributes zero; a later domain starts at its first observed sample and only later same-domain deltas increase the durable lower bound.
- When the durable lower bound reaches `ttl_ms`, expiry is certain and existing bounded retirement/GC applies immediately.
- Durable items and Event tombstones retain their existing lifetime behavior.
- Wall-clock time is never read or persisted for freshness.
- Missing samples, clock changes, tick rollback, and arithmetic overflow must fail closed without decreasing age or restoring exact continuity.
- Preserve the bounded-custody limits: `MAX_CUSTODY_PAGE = 1_024`, `MAX_CUSTODY_RETIREMENT_SCAN = 5_120`, and at most 1,024 dependency units per maintenance transaction.
- Existing v5-v7 Blob behavior remains durable-only and unchanged.

## Review Focus

- A clock change immediately followed by a large tick must not count the unknown cross-domain gap; Task 1 pins the first-sample/no-increment rule.
- Repeated restarts across several domains must still make progress once each new domain supplies two samples; Tasks 1 and 4 pin cumulative lower-bound growth and restart persistence.
- A stale or younger authenticated duplicate must not reset either the lower bound or its current-domain anchor; Tasks 1–3 pin monotone merge behavior.
- Discontinuous rows outside the current maintenance page must not be stranded forever or force an unbounded scan; Task 3 pins bounded re-anchor progress through the existing expiration index.
- A lower-bound checkpoint racing retirement, policy change, or a delayed same-clock sample must not recreate sender authority or regress the durable high-water; Tasks 3 and 4 pin transactional rechecks and stale-sample behavior.

---

### Task 1: Shared `CustodyAge` Lower-Bound State Machine

**Files:**
- Modify: `crates/aster-core/src/custody.rs:95-282`
- Test: inline tests in `crates/aster-core/src/custody.rs:768-910`

**Interfaces:**
- Preserves: `CustodyAge::{new,unknown,from_parts,cumulative_age_ms,checkpoint_sample,continuity,is_continuous,effective_age,checkpoint,merge_authenticated_age}`.
- Changes: a lost `CustodyAge` may retain `checkpoint: Some(CustodySample)` as its current lower-bound measurement anchor while `continuity()` remains `Lost`.
- Produces: `checkpoint` persists every provable same-domain delta even after continuity loss; its `Result` still distinguishes exact continuous age from fail-closed indeterminate age.
- Produces: `merge_authenticated_age` stores `max(local_lower_bound, received_age_ms)` and never restores `Continuous`.

- [ ] **Step 1: Write failing lower-bound state-machine tests**

  Add `lost_age_reanchors_without_counting_unknown_gap`, `lost_age_accumulates_later_same_domain_intervals`, `multiple_lost_domains_accumulate_only_proven_intervals`, `lost_duplicate_merge_never_rejuvenates`, `missing_sample_discards_the_old_anchor`, and `overflow_saturates_the_proven_lower_bound`.

  Assert the essential sequence:

  ```rust
  let mut age = CustodyAge::new(10, sample_in(CLOCK_A, 100));
  assert_eq!(evaluate_custody(Some(30), false, &mut age, Some(sample_in(CLOCK_B, 9_000))), CustodyDisposition::Indeterminate);
  assert_eq!(age.cumulative_age_ms(), 10); // unknown A→B gap is ignored
  assert_eq!(age.checkpoint_sample(), Some(sample_in(CLOCK_B, 9_000)));
  assert_eq!(evaluate_custody(Some(30), false, &mut age, Some(sample_in(CLOCK_B, 9_020))), CustodyDisposition::Expired { age_ms: 30 });
  assert_eq!(age.continuity(), CustodyContinuity::Lost);
  ```

- [ ] **Step 2: Run the focused core tests and confirm the intended failures**

  Run: `cargo test --locked -p aster-core custody::tests -- --nocapture`

  Expected: new tests fail because `effective_age` immediately returns `ContinuityUnavailable` for `Lost` and the checkpoint/lower bound never advances.

- [ ] **Step 3: Implement the shared state transitions**

  Keep the public signatures above. Make `checkpoint` and `evaluate_custody` apply these exact transitions:

  - continuous + same domain/nondecreasing tick: add checked delta and persist current sample;
  - continuous + missing/mismatched/rollback sample: mark lost, add zero, and use the new valid sample as the next anchor when present;
  - lost + no anchor + valid sample: add zero and install the sample;
  - lost + same domain/nondecreasing tick: add the checked delta and move the anchor;
  - lost + missing sample: add zero and clear the anchor;
  - lost + mismatched-domain or rollback sample: add zero and replace the anchor with that valid current sample;
  - proven addition overflow: set the lower bound to `u64::MAX`, remain lost, and report `AgeOverflow` without wrapping.

  `evaluate_custody` checks the updated lower bound against TTL before returning `Indeterminate`. It returns `LiveFinite` only for continuous exact age.

- [ ] **Step 4: Implement monotone authenticated merge behavior**

  `merge_authenticated_age(received_age_ms, current)` first accounts any provable local interval, then persists the maximum of that lower bound and `received_age_ms`. It retains or installs the current anchor, never changes `Lost` to `Continuous`, and never reduces `cumulative_age_ms` or moves a same-domain anchor backward.

- [ ] **Step 5: Verify the shared model**

  Run: `cargo test --locked -p aster-core custody::tests -- --nocapture`

  Expected: all custody tests pass, including exact TTL boundary, sticky continuity, multiple-domain accumulation, younger duplicate, and overflow cases.

- [ ] **Step 6: Commit**

  `git add crates/aster-core/src/custody.rs && git commit -S -m "fix: accumulate provable custody lower bounds"`

### Task 2: Reference Store, Runtime, and Bridge Consumers

**Files:**
- Modify: `crates/aster-core/src/store.rs:780-850,960-995,10920-11025,12735-12805`
- Modify: `crates/aster-core/src/runtime/reference_semantic.rs:4925-4990,5880-5950`
- Modify: `crates/aster-core/src/bridge_service.rs:1210-1280,1310-1465`
- Test: inline tests in those modules

**Interfaces:**
- Consumes: Task 1 `CustodyAge` behavior and unchanged public signatures.
- Preserves: legacy durable fields `(cumulative_age_ms, continuity_unknown, clock_id, tick_ms, elapsed_available)` and their encodings.
- Produces: every field adapter writes back a lost-state anchor instead of collapsing all lost states to `checkpoint = None`.
- Preserves: bridge/source forwarding APIs continue returning unavailable for finite lost-continuity data below TTL.

- [ ] **Step 1: Add failing adapter and persistence tests**

  Add tests that reconstruct a lost state with an anchor, checkpoint it twice in a later domain, serialize its five legacy fields, reconstruct it again, and prove the same lower bound. Add bridge/runtime tests asserting that the item remains withheld at `ttl - 1`, becomes expired at `ttl`, and never becomes forwardable.

- [ ] **Step 2: Add failing duplicate/restart tests**

  Cover a younger authenticated duplicate after restart, a greater authenticated age, missing sample followed by a new anchor, and two successive clock IDs. Assert stored age is monotone and `age_continuity_unknown`/`custody_elapsed_available` never returns to exact continuity.

- [ ] **Step 3: Verify red behavior**

  Run: `cargo test --locked -p aster-core lower_bound -- --nocapture`

  Run: `cargo test --locked -p aster-core finite_ttl -- --nocapture`

  Expected: the new tests fail where adapters currently discard lost checkpoints or return before persisting later-domain deltas.

- [ ] **Step 4: Update all shared field adapters**

  Route `custody_age_from_legacy_fields`, `custody_fields_from_age`, `advance_custody_fields`, ordinary/bridge checkpoint helpers, `runtime_custody_age`, and effective bridge age through Task 1 semantics. Persist the mutated `CustodyAge` fields even when exact-age methods return `ContinuityUnavailable`; use the error only to withhold forwarding.

- [ ] **Step 5: Verify reference and bridge behavior**

  Run: `cargo test --locked -p aster-core lower_bound -- --nocapture`

  Run: `cargo test --locked -p aster-core bridge_service -- --nocapture`

  Run: `cargo test --locked -p aster-core reference_semantic -- --nocapture`

  Expected: all focused tests pass and existing finite data remains fail-closed for forwarding.

- [ ] **Step 6: Commit**

  `git add crates/aster-core/src/store.rs crates/aster-core/src/runtime/reference_semantic.rs crates/aster-core/src/bridge_service.rs && git commit -S -m "fix: persist lower-bound custody anchors"`

### Task 3: Indexed redb Re-Anchoring Without Unbounded Scans

**Files:**
- Modify: `crates/aster-redb-store/src/custody.rs:1180-1905,2860-3330,7910-8210`
- Test: `crates/aster-redb-store/src/lib.rs:38850-39320,40480-40640`

**Interfaces:**
- Produces: internal `CustodyAgeEvaluation { status: CustodyAgeStatus, lower_bound_ms: u64, checkpoint: Option<CustodySample>, continuity_generation: u64, continuity_lost: bool, needs_write: bool }`.
- Produces: `evaluate_item_age(record, continuity, sample) -> Result<CustodyAgeEvaluation, StoreError>` as the single redb age evaluator.
- Produces: `checkpoint_item_age_write(write, key, record, evaluation) -> Result<CustodyItemRecord, StoreError>` to update the item and its maintenance index atomically.
- Changes: `CUSTODY_EXPIRATIONS` v2 also indexes re-anchor work; no new table, wire format, or unbounded side ledger is added.
- Preserves: `CustodyItemRecord` and custody schema v3 encoding; lost rows already permit an optional checkpoint and generation.

- [ ] **Step 1: Add failing codec/index tests**

  Add cases for canonical lost rows with and without anchors. Define expiration-index behavior:

  ```rust
  // Unanchored lost finite row: sentinel re-anchor work.
  assert_eq!(generation, 0);
  assert_eq!(clock_id, [0; 16]);
  assert_eq!(deadline_tick_ms, 0);

  // Anchored lost finite row: exact lower-bound deadline in its current domain.
  assert_eq!(deadline_tick_ms, anchor.tick_ms + (ttl_ms - lower_bound_ms));
  ```

  Overflow in deadline construction must produce an indexed far-future/saturated deadline without wrapping; a lower bound already at TTL uses immediate expiry.

- [ ] **Step 2: Add failing bounded re-anchor tests**

  Seed more than `MAX_CUSTODY_PAGE` finite rows under clock A, observe clock B, and run repeated 1,024-row passes. Assert each pass examines at most its page, moves only selected old-generation/sentinel rows to the B anchor, and eventually leaves no old-generation/sentinel index rows. No pass may scan or materialize the full item table.

- [ ] **Step 3: Verify red behavior**

  Run: `cargo test --locked -p aster-redb-store custody_lower_bound_index -- --nocapture`

  Expected: tests fail because lost rows currently clear their checkpoint, disappear from expiry scheduling, and cannot be re-anchored automatically.

- [ ] **Step 4: Implement the canonical evaluator and index forms**

  Replace direct `evaluate_item`/`mark_continuity_lost_write` branching with the two interfaces above. The evaluator normalizes delayed same-clock samples to the durable continuity high-water, counts only nonnegative deltas within the row's stored generation/domain, and returns `WithheldUnknownAge` for lost rows below TTL even after advancing their lower bound.

- [ ] **Step 5: Extend structural audit and maintenance-index reconstruction**

  Make `custody_expiration_key`, `replace_custody_maintenance_indexes_write`, `expected_custody_maintenance_indexes`, writable reopen, and read-only inspection agree on three finite-row forms: continuous exact deadline, lost anchored deadline, and lost unanchored sentinel. Any item/index mismatch remains structural corruption; maintenance cannot silently recreate a missing row during ordinary operation.

- [ ] **Step 6: Verify codec, audit, and index behavior**

  Run: `cargo test --locked -p aster-redb-store custody_lower_bound_index -- --nocapture`

  Run: `cargo test --locked -p aster-redb-store custody_maintenance_index -- --nocapture`

  Expected: focused tests pass with bounded progress and strict bidirectional index auditing.

- [ ] **Step 7: Commit**

  `git add crates/aster-redb-store/src/custody.rs crates/aster-redb-store/src/lib.rs && git commit -S -m "fix: index discontinuous custody aging"`

### Task 4: Event Maintenance, Duplicate Merge, and Restart Expiry

**Files:**
- Modify: `crates/aster-redb-store/src/custody.rs:3260-3340,5000-5350,6330-7660`
- Modify: `crates/aster-redb-store/src/lib.rs:37900-39350,40500-40650,42550-42680`
- Test: inline tests in `crates/aster-redb-store/src/lib.rs`

**Interfaces:**
- Consumes: Task 3 evaluator, checkpoint writer, and expiration/re-anchor index forms.
- Preserves: `collect_custody_garbage`, `collect_custody_pressure`, admission, promotion, lease, and sender-status public signatures.
- Changes: routine GC processes sentinel and prior-generation re-anchor rows before current-generation due deadlines, all under the caller's existing `limit`.
- Preserves: sender inventory, leases, retries, and reads reject lost finite rows below TTL.

- [ ] **Step 1: Add failing restart/GC tests**

  Add `custody_lost_age_expires_across_later_domains`, `custody_reanchor_progress_survives_reopen`, and `custody_unknown_gap_is_never_counted`. Use exact samples so proven intervals total `ttl - 1` before the last restart and `ttl` afterward. Assert no retirement before the threshold and existing `CustodyRetirementReason::Expired` afterward.

- [ ] **Step 2: Add failing duplicate and race tests**

  Exercise local admission duplicate, authenticated receiver duplicate, route promotion, delayed same-clock sample, policy revision race, and an active transfer lease. Assert younger ages cannot reduce the lower bound/anchor, retirement cannot be undone, and a lease delays physical retirement without restoring sender eligibility.

- [ ] **Step 3: Verify red behavior**

  Run: `cargo test --locked -p aster-redb-store custody_lost_age -- --nocapture`

  Run: `cargo test --locked -p aster-redb-store custody_reanchor -- --nocapture`

  Expected: rows remain indefinitely `WithheldUnknownAge` under current sticky-loss behavior.

- [ ] **Step 4: Implement bounded re-anchor and deadline processing**

  In each GC transaction, spend at most `limit` total age candidates across: unanchored sentinel rows, rows from generations older than the current continuity generation, then due current-generation deadlines. Re-anchor contributes zero age; later same-generation passes checkpoint proven deltas. Persist age/index mutation and mutation revision atomically before marking expiry. Existing retirement dependency budgets remain separate and unchanged.

- [ ] **Step 5: Implement monotone duplicate and promotion merges**

  Refactor redb `merge_authenticated_age` to use Task 3 evaluation, then store `max(local_lower_bound, authenticated_age_ms)`. Preserve `continuity_lost`, choose the newest valid nondecreasing local anchor, replace maintenance indexes atomically, and make an authenticated age at/above TTL enter existing expiry retirement rather than a live row.

- [ ] **Step 6: Verify selected Event behavior and restart safety**

  Run: `cargo test --locked -p aster-redb-store custody_lost_age -- --nocapture`

  Run: `cargo test --locked -p aster-redb-store custody_reanchor -- --nocapture`

  Run: `cargo test --locked -p aster-redb-store custody_ -- --nocapture`

  Expected: all focused custody tests pass, existing maintenance bounds remain asserted, and reopen preserves the exact lower bound/anchor.

- [ ] **Step 7: Commit**

  `git add crates/aster-redb-store/src/custody.rs crates/aster-redb-store/src/lib.rs && git commit -S -m "fix: expire events from proven custody age"`

### Task 5: Documentation and Full Verification

**Files:**
- Modify: `docs/protocol.md`
- Modify: `docs/security.md`
- Modify: `docs/architecture.md`
- Modify: `CHANGELOG.md`
- Modify only if exact evidence changes: `docs/implementation/requirements-status.md`

**Interfaces:**
- Consumes: Tasks 1–4 complete behavior.
- Produces: normative description of sticky exact-continuity loss plus accumulating conservative lower bound.
- Preserves: no roadmap or requirement maturity movement without retained evidence.

- [ ] **Step 1: Update normative documentation**

  Document the exact transition rules, bounded re-anchor indexing, withheld-versus-expired distinction, restart behavior, and overflow disposition. State explicitly that the change is wire-neutral and currently exercised for Event/RouteEvent; Blob consumes it in the later finite-lifecycle PR.

- [ ] **Step 2: Run formatting and focused crate verification**

  Run: `cargo fmt --all -- --check`

  Run: `cargo test --locked -p aster-core`

  Run: `cargo test --locked -p aster-redb-store`

  Expected: PASS with zero failing tests.

- [ ] **Step 3: Run traceability validation**

  Run: `python3 tools/check-implementation-requirements.py`

  Expected: PASS; no evidence status moves unless this PR adds separately retained evidence.

- [ ] **Step 4: Run the repository gate**

  Run: `mise run check`

  Expected: PASS. `mise run fuzz-smoke` is not required because no parser, frame grammar, envelope encoding, or hostile-input wire boundary changes.

- [ ] **Step 5: Perform independent whole-branch review**

  Review against the approved Blob lifecycle spec, the bounded-custody dependency, `data-mesh-requirements.md`, and existing Event custody protocol/security text. Require explicit confirmation that no unknown interval is counted and no lost item becomes forwardable.

- [ ] **Step 6: Commit**

  `git add CHANGELOG.md docs && git commit -S -m "docs: define lower-bound custody aging"`
