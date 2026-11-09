# Android BTLE Text Event Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a user durably publish one bounded text Event from the Android evaluator and see the exact safely rendered text in the Linux Ring-1 terminal after BTLE transfer.

**Architecture:** Add the text to the validated Android run configuration, publish it through `aster_node::publication_journal` before contact, and retain the existing bidirectional v9 validation. The Linux listener prepares an exact Consume subscription, queries the authenticated Android publisher after contact, and prints one JSON-escaped Event line.

**Tech Stack:** Kotlin/Android views, Rust 1.97.1, `aster-node` selected Event API, redb numbered journal, Tokio, BlueZ LE L2CAP CoC.

**Spec:** `docs/superpowers/specs/2026-11-09-android-btle-text-event-design.md`

## Global Constraints

- Preserve semantic v9 and profiles `[2, 1, 1, 5, 1]`; add no protocol bytes.
- Accept one non-empty UTF-8 message of at most 1,024 encoded bytes without normalization.
- Publish durably before contact and retain the exact numbered intent across failure.
- Use fixed topic `mesh.messages`, scope `demo/playground`, and logical key `android-btle-ring1/text/v1`.
- Render terminal text as one JSON-escaped line; never echo rejected or unauthenticated input.
- Preserve the existing Linux-to-Android 65,536-byte Event acceptance path.

## Review Focus

- Multibyte Unicode at the 1,024-byte boundary must be measured in UTF-8 bytes, not UTF-16 code units.
- Newlines, quotes, NUL, and terminal escape bytes must remain exact Event bytes but cannot forge terminal output.
- Contact failure after local publication must leave one recoverable Event, not allocate a duplicate on retry.
- Existing Android state with the earlier subscription client must not be fenced by the new journal client.
- Linux must select only the configured authenticated Android publisher and fixed selector, never an unrelated retained Event.

---

### Task 1: Bounded Android message configuration and UX

**Files:**
- Modify: `examples/android-btle-ring1/app/src/main/java/org/defenseunicorns/aster/btlering1/ValidatorConfig.kt`
- Modify: `examples/android-btle-ring1/app/src/test/java/org/defenseunicorns/aster/btlering1/ValidatorConfigTest.kt`
- Modify: `examples/android-btle-ring1/app/src/main/java/org/defenseunicorns/aster/btlering1/MainActivity.kt`
- Modify: `examples/android-btle-ring1/app/src/main/res/layout/activity_main.xml`
- Modify: `examples/android-btle-ring1/app/src/main/res/values/strings.xml`

**Interfaces:**
- Produces: `ValidatorConfig.eventText: String`, serialized as JSON field `event_text`.
- Consumes: existing form validation and `BluetoothBridge.connect`.

- [x] Write JVM tests proving one exact Unicode/control-containing string serializes losslessly and empty or 1,025-byte UTF-8 input is rejected.
- [x] Run `gradle :app:testDebugUnitTest` and verify the new tests fail because `eventText` is absent.
- [x] Add the message field, 1,024-byte UTF-8 validation, JSON serialization, **Send and validate** copy, and running-state disablement.
- [x] Run `gradle :app:testDebugUnitTest`; expect all JVM tests to pass.
- [ ] Commit the task with a signed commit.

### Task 2: Durable Android publication before contact

**Files:**
- Modify: `crates/aster-ble-android/src/config.rs`
- Modify: `crates/aster-ble-android/src/session.rs`
- Modify: `crates/aster-ble-android/src/receipt.rs`
- Modify: `crates/aster-ble-android/src/jni.rs`
- Modify: `crates/aster-ble-android/Cargo.toml`
- Modify: `examples/android-btle-ring1/app/src/main/java/org/defenseunicorns/aster/btlering1/NativeValidator.kt`
- Modify: `examples/android-btle-ring1/app/src/main/java/org/defenseunicorns/aster/btlering1/BluetoothBridge.kt`
- Modify: `examples/android-btle-ring1/app/src/main/java/org/defenseunicorns/aster/btlering1/ValidationState.kt`

**Interfaces:**
- Consumes: `ValidatorConfig::event_text() -> &str`.
- Produces: private journal client `android-btle-ring1-text/v1`, durable `publication_journal::Intent`, and receipt fields `published_event_id`, `published_payload_sha256`, `event_page_entries_sent`, and `event_page_bytes_sent`.

- [x] Add Rust config tests for exact Unicode/control bytes, empty input, and the 1,024/1,025 UTF-8-byte boundary; run the focused config tests and verify RED.
- [x] Add receipt tests requiring one sent text Event while preserving the existing one inserted large Event; run and verify RED.
- [x] Add a session test that starts with no carrier, publishes through the real journal/backend, reopens state, and proves one exact payload and monotonically numbered retry-safe publication; run and verify RED.
- [x] Implement validated config access, initialize/open/recover the private journal, publish and acknowledge before contact, reuse its client context for the fixed Consume subscription, and extend sanitized receipt output.
- [x] Run `cargo test -p aster-ble-android`; expect all tests to pass.
- [x] Run focused Clippy with warnings denied for `aster-ble-android`; the workspace dependency pass retains the pre-existing `aster-node::BlobNetworkReport` dead-code warning.
- [x] Refactor publication/subscription setup for single ownership and readable failure mapping; rerun both commands.
- [ ] Commit the task with a signed commit.

### Task 3: Linux subscription, exact query, and safe terminal rendering

**Files:**
- Modify: `crates/aster-ble-linux/src/bin/aster_btle_ring1_linux.rs`
- Modify: `crates/aster-ble-linux/Cargo.toml`

**Interfaces:**
- Consumes: fixed selector and authenticated `HarnessConfig.mission_peer`.
- Produces: `BTLE_RING1_EVENT status=received ... text=<JSON string>` after successful contact.

- [x] Add Linux harness tests proving subscription/query selection rejects another publisher, chooses the greatest matching Event sequence, rejects empty/non-UTF-8/oversized payloads, and JSON-escapes controls on one line; run the binary tests and verify RED.
- [ ] Add a real in-process two-node ordered-contact test that publishes the fixed Android text Event before contact and proves the Linux-side query returns identical bytes exactly once; verify RED.
- [x] Prepare the fixed Consume subscription before opening Bluetooth, query the authenticated peer after contact, validate the bounded UTF-8 payload, compute SHA-256, and print the JSON-escaped terminal line.
- [x] Run `cargo test -p aster-ble-linux --bin aster-btle-ring1`; expect all tests to pass.
- [x] Run focused Clippy with warnings denied for the Linux Ring-1 binary; pre-existing workspace and vendored dependency warnings remain outside the binary.
- [x] Refactor helpers so CLI parsing, subscription ownership, Event selection, and rendering remain separate; rerun both commands.
- [ ] Commit the task with a signed commit.

### Task 4: Documentation and end-to-end validation

**Files:**
- Modify: `docs/quickstart/btle-android-ring1.md`
- Modify: `docs/validation/btle-ring1-evaluation-profile.md`
- Create after a successful physical run: `docs/validation/evidence/2026-11-09-android-linux-btle-text-event-validation.md`
- Modify: PR 146 description only after retained evidence is accurate.

**Interfaces:**
- Consumes: Android receipt fields and the Linux `BTLE_RING1_EVENT` line.
- Produces: a reproducible Pixel-to-Linux text Event procedure and bounded evidence.

- [ ] Update the quickstart to enter a short text, retain the existing 65,536-byte reverse Event, press **Send and validate**, and verify exact terminal text/digest.
- [ ] Run formatting, `git diff --check`, Android JVM/Rust tests, Linux harness tests, both focused Clippy commands, lockfile validation, and requirements trace validation.
- [ ] Build and install the exact APK, clear disposable app state, and run one physical Pixel-to-Linux bidirectional contact from a cold controller state without unrelated Bluetooth connections.
- [ ] Verify the Android Event ID/digest and Linux terminal Event ID/digest/text agree, the existing large reverse Event is inserted, replay creates no duplicate, and all temporary phone/lab artifacts are removed.
- [ ] Record only sanitized evidence, run a final production-code refactor/review, and obtain an independent architecture/security review before push.
- [ ] Commit all final changes with a signed commit, push PR 146, let CI pass, update the PR claim, and mark it ready again.
