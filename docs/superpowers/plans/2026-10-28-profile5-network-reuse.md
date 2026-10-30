# Profile-5 network content reuse implementation plan

> **For agentic workers:** Use superpowers:executing-plans for inline implementation and a fresh final review.

**Goal:** Restore pre-PR110 avoidance of redundant network content transfer and recover completed uploads after interruption.

**Architecture:** Retain a verified, leased local pack through FINISH and atomic publication acceptance. Existing content and an existing publication are separate cases; a new publication gets its own normal identity, policy, custody, causal and lifecycle checks. Completed provisional uploads use their durable completion instead of reopening a removed candidate.

**Tech Stack:** Existing Rust, redb, Profile-5 stream state machine and pack read leases.

**Spec:** User-approved behavior in this chat on 2026-10-28: a new publication referencing already retained suitable content transfers no DATA; restore the old behavior within the new transport, without reverting PR110.

## Global constraints

- No wire or storage encoding change, dependency, migration, persistent busy marker, or counter-gap rule.
- Retained content must match Blob ID, metadata, content group, epoch and physical lineage; policy/custody admission remains fresh at FINISH.
- Do not acknowledge a new publication before atomic commit. Keep leases through commit, including error paths.
- Keep native 32-bit work separate. No requirement acceptance-credit changes.

## Review focus

- New durable and finite publications reuse bytes on the first attempt, not merely on retry.
- Invalid/missing FINISH and expired/revoked authority cannot publish or refresh custody.
- Completed provisional uploads recover after store reopen even when their duplicate candidate was removed.
- Changed operation intent, another store's capability and incompatible variants fail closed; preserve the shared accepted-dot/replay checks.
- Reuse must not reserve another file's storage capacity or permit deletion during admission.

## Task 1: Existing content admission and completed recovery

**Files:** `crates/aster-node/src/runtime/blob_stream.rs`, network tests in `runtime.rs`, `crates/aster-redb-store/src/blob/upload.rs`, narrow shared admission helpers in `blob.rs`/`pack_lifecycle.rs` if needed; Blob guide.

**Interfaces:** Existing stream ACCEPT at full wire length leads to FINISH without DATA. Add store admission for a verified received publication backed by a leased active pack, using the existing atomic publication writer. Preserve normal upload completion/commit methods for resumed completed uploads.

- [x] Strengthen both existing equivalent-pack tests to require zero DATA on first admission; retain pre-fix failure.
- [x] Implement verified active-pack admission without a duplicate upload reservation; preserve current authorization, finite custody, operation and dot checks.
- [x] Add completed-upload interruption/reopen regression and use existing completion before writer restore.
- [x] Test first-attempt FINISH failure, revoked/expired reuse, and authority/conflict boundaries; verify readback and reopen.
- [x] Run focused regressions and `mise run check`; assess fuzz requirement from final changes.
- [x] Fresh whole-change review and resolution of actionable findings; hand off through the existing draft PR4.

## Review resolution and limits

The fresh review identified a missing lifecycle lease for recovered completed
uploads that reuse an active pack. A deterministic pressure-recovery hook at
FINISH reproduced eviction of the old last publication. The recovered contact
now holds a retained read session through acceptance; both first-contact and
recovered-contact pressure cases pass. Final source review found no remaining
actionable finding.

Completed-recovery tests close/reopen the Store at the durable completion
boundary, then use the production network path. They do not claim arbitrary
process-kill or power-loss qualification. Partial uploads keep their normal
checkpoint resume path. Offline reclamation of an already completed upload's
selected pack remains an inherited, unqualified boundary.

Validation: 21 focused native tests, 2 focused Store tests, and the full `mise run check` passed (2710 workspace tests; 13 skipped). Documentation tests: 10 passed, 6 ignored. No parser/framing/envelope/fragmentation or limit change; fuzz-smoke was not rerun. Native32 and power-loss qualification remain separate.
