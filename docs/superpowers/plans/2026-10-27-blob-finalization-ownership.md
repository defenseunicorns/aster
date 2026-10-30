# Blob finalization ownership implementation plan

> **For agentic workers:** Use superpowers:executing-plans for inline implementation and a fresh final review.

**Goal:** Prevent a retry from reopening the files of an operation whose background publication is still running.

**Architecture:** The application actor retains a weak, process-local reference to each finalization's immutable request. The prepared job owns the strong reference through queueing, filesystem mutation, semantic commit, cleanup, and unwinding. An exact retry receives the existing temporary `StateUnavailable`; a changed request retains `Conflict`. Dead entries are pruned on admission, keeping the registry bounded by admitted work.

**Tech stack:** Existing Rust ownership, Arc/Weak, bounded promotion pool, redb checkpoints, ConnectRPC error details.

**Spec:** User-approved design in this chat, 2026-10-27: exclusive ownership per publisher/operation key; caller cancellation does not release ownership; no persisted busy flag; restart uses existing durable recovery; unrelated operations remain concurrent. No timeout may release a still-running writer.

## Global constraints

- Keep storage, protocol encodings, dependencies, and counter semantics unchanged.
- Keep existing authorization, request-conflict, custody, and completed-retry validation.
- Do not introduce automatic CLI retries or claim a failed response proves no publication.
- This is a bounded PR110 correctness repair; completed network dedup retry remains separate.

## Review focus

- Prepared/queued jobs must exclude reopen before a worker starts.
- Client/session/completion receiver drop must not release a running writer.
- Queue rejection, ordinary worker failure, and unwind must release ownership after writer teardown.
- Process exit must not leave persistent busy state; exact retry resumes or replays.
- Different operations remain concurrent, and changed requests remain conflicts.

## Task 1: Finalization ownership and retry contract

**Files:** `crates/aster-node/src/application/blob.rs`, `crates/asterctl/src/client.rs`, relevant Blob/API guides.

**Interfaces:** Preserve existing public methods and `StateUnavailable` -> `Unavailable`/`STATE_UNAVAILABLE` mapping. Add a private weak registry keyed by the existing publication token; keep its strong owner in `BlobPackPromotionJob` until all job resources are destroyed.

- [x] Add deterministic prepared/active retry regressions, including finite TTL, changed request, one-shot retry, and independent operation progress; run and retain their pre-fix failures.
- [x] Add a CLI regression for typed temporary state: unknown outcome, identical-key retry, no connection hint. Keep untyped transport error guidance.
- [x] Implement ownership before exposing the prepared job; check before writer restore and duplicate finish. Ensure release on submission failure and unwind, independent of client lifetime.
- [x] Exercise caller drop, worker panic, ordinary failure, saturation, closed pool, and subprocess exit/reopen. Assert readable content and exact replay, not only registry internals.
- [x] Document temporary retries and update CLI typed-state guidance without new protocol values.
- [x] Run focused tests, then `mise run check`; no parser/framing boundary changes require fuzz reruns.
- [x] Obtain a fresh scoped review and resolve actionable findings. No actionable findings remained. Delivery continues through the existing draft PR; the separate network retry P2 remains open.

Validation completed on 2026-10-27: `mise run check` passed with 2706 workspace tests, 13 skipped; 9 focused promotion tests and 18 CLI client tests passed. Tests of process exit cover partial upload, prepared work, running preflight, and committed publication; they do not claim hardware power-loss coverage.
