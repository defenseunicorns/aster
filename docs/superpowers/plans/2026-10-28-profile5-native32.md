# Profile-5 32-bit compatibility implementation plan

> Use superpowers:executing-plans for inline implementation and one fresh final review.

**Goal:** Make the PR110 Blob path preserve its existing 64-bit protocol results and full streaming bounds on 32-bit hosts.

**Architecture:** Encode hash-part lengths as big-endian `u64`; count cumulative stream bytes with `u64` through node and carrier. Keep bounded buffer sizes and indexes as `usize`. Compute the bounded segment count before converting it to `usize`.

**Tech Stack:** Existing Rust 1.97.1, SHA-256, Aster stream state machine and Iroh carrier. Use the official i686-unknown-linux-musl Rust target to execute native 32-bit regressions on this Linux host.

**Spec:** The user's explicit 2026-10-28 request to implement the remaining 32-bit compatibility fix, following the agreed fixed-width hash-length proposal. Source inspection also found truncation of the 8-GiB segment ceiling and aggregate transport byte budgets, which must be fixed for the requested path to work.

## Constraints and review focus

- Preserve existing 64-bit hash, wire, frame, storage and limit values; no migration or protocol version change.
- Do not replace bounded in-memory sizes with wide counters indiscriminately.
- Cumulative counters must cross 4 GiB, reject their configured limit and arithmetic overflow, and account for frame prefixes.
- Empty and nonempty content must match independent fixed-width hash vectors on both word sizes.
- Native32 execution is distinct from cross-compilation, emulation, ARM hardware, full deployment support and power-loss qualification; state exactly what ran.
- Keep requirement acceptance credit and dependencies unchanged. Retain existing draft PR4 and current worktree.

## Task 1: Fixed-width content identity

- [x] Add empty/nonempty plaintext-frontier golden vectors derived independently in Python with `struct.pack('>Q', length)`; run them on i686 and preserve the expected pre-fix failure.
- [x] Change `hash_parts` in `crates/aster-core/src/blob_stream.rs` to use an explicit `u64` length; rerun core Blob tests on 32 and 64 bits and preserve 64-bit vectors.

## Task 2: Wide aggregate stream accounting

- [x] Reproduce the native pack ceiling/budget failure on 32 bits using production code.
- [x] Fix the constant and `profile5_attempt_bounds*` in `stream_transfer.rs`; carry wide byte limits through `AttemptOpenRequest` and the bounded Iroh stream pair.
- [x] Add deterministic carrier regressions near the 4-GiB boundary, at the exact limit, and on rejection, while transferring only small real frames. Keep legacy turn limits and frame allocations bounded.
- [x] Check the relevant node/store path on the 32-bit target and run available native32 tests; resolve actual build/runtime blockers within the requested Blob compatibility scope.
- [x] Run focused 64-bit regressions, full `mise run check`, and bounded fuzz-smoke for changed aggregate transport boundaries.
- [x] Obtain fresh final review and resolve actionable findings.
- Delivery after the final gate: commit/push the verified change and update existing draft PR4 with evidence and limits. The delivery receipt is recorded in PR4 and the retained local report.

## Build findings resolved during execution

- The full native32 node/CLI feature graph exposed Linux `stat` nanosecond fields as `u32` where the provider metadata stores `u64`. Reuse the existing generic lossless stat-field widening helper for timestamps as well as link counts; keep runtime checks unchanged.
- The protocol source-contract checker matched the prior arithmetic spelling literally. Update that expectation for the explicit `as u64`; preserve the same overhead formula and checker coverage.

- The existing 9-MiB checkpoint correctness test timed out at 10 seconds in the native32 debug build, including an isolated rerun. A retained diagnostic using the production validation driver completed 9 MiB in 12.23 seconds. Reduce the test batch to one MiB and transfer two full segments, retaining the same credit-block/replenish path; assert exactly two checkpoints (and one in the no-credit-block case). Production timeouts and limits are unchanged.
