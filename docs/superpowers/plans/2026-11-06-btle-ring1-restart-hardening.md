# BTLE Ring-1 Restart Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor the Linux BTLE carrier, diagnose the retained stale-ACL restart failure, implement only an evidence-supported safe clean-restart recovery, and validate Linux/Linux plus Android/Linux Event delivery.

**Architecture:** `aster-ble-linux` remains the sole owner of Linux/BlueZ lifecycle behavior. The crate root becomes an export surface, connected-stream/MTU behavior moves to `stream.rs`, socket establishment moves to `platform.rs`, and a private read-only peer-link observer records whether BlueZ retains the exact provisioned ACL after the owned L2CAP contact drains. Recovery is selected only after the physical pre-fix trace identifies the failing boundary; `aster-node`, semantic v9, application APIs, and transport selection remain unchanged.

**Tech Stack:** Rust 2024, Tokio, bluer 0.17.4, Linux BlueZ D-Bus and LE L2CAP CoC, Android Kotlin/JNI foreground validator.

**Spec:** `docs/superpowers/specs/2026-11-06-linux-btle-clean-restart-design.md`

## Global Constraints

- Do not change semantic-v9 bytes, transfer-profile negotiation, ordered-contact semantics, mission authority, durable state ownership, or application APIs.
- Do not add a generic transport lifecycle abstraction; Linux restart handling stays in `aster-ble-linux`.
- Do not power-cycle/reset a controller, remove a device, change pairing/trust, or invoke peer-wide `Device1.Disconnect()` without a separately reviewed exclusive-ownership design.
- No wall-clock soak or 60-second test belongs in the committed suite; deterministic Tokio paused-time tests provide repetition.
- Run only focused gates during implementation; coordinate the final full gate through CI to avoid concurrent resource-heavy checks.
- Every commit must be signed.

## Review Focus

- An ACL observed as connected after the L2CAP stream drops must never be treated as mission-authenticated or as proof that a usable channel exists; Task 2 adds an exact state-only test.
- BlueZ absence, missing `Device1`, permission failure, and D-Bus loss must map to closed sanitized categories without locator leakage; Task 2 tests all four.
- Observation must happen only after the active contact/admission future is drained and the stream is dropped; Task 2 asserts call order.
- Cancellation during the diagnostic probe must not delay shutdown or leave a task; Task 2 adds a cancellation test.
- Any recovery selected after physical diagnosis must preserve unrelated controller users and future inbound/outbound contacts; Task 4 requires a failing regression plus both-direction physical validation.

---

### Task 1: Refactor Linux stream and platform ownership

**Files:**
- Create: `crates/aster-ble-linux/src/stream.rs`
- Create: `crates/aster-ble-linux/src/platform.rs`
- Modify: `crates/aster-ble-linux/src/lib.rs`
- Test: `crates/aster-ble-linux/src/stream.rs`
- Test: `crates/aster-ble-linux/src/platform.rs`

**Interfaces:**
- Consumes: existing `ValidatedConfig`, `OpenRequest`, `OpenCancellation`, `DriverError`, and `DriverErrorKind`.
- Produces: unchanged public `NegotiatedMtu`, `SocketOpen`, `SocketFactory`, `BluezSocketFactory`, `OpenedContact`, `open_contact`, and `open_contact_with_factory` exports from the crate root.

- [ ] **Step 1: Record the focused baseline**

Run: `cargo test -p aster-ble-linux --locked`

Expected: all current Linux BTLE tests pass; record count and duration.

- [ ] **Step 2: Move connected-stream and MTU code without behavior changes**

Move `NegotiatedMtu`, `MtuProbe`, `SocketOpen`, `MtuTrackingStream`, `MtuBoundedStream`, and their existing tests to `stream.rs`. Keep visibility minimal and re-export only the existing public types.

- [ ] **Step 3: Move platform socket establishment without behavior changes**

Move `SocketFactory`, `BluezSocketFactory`, `open_contact`, `open_contact_with_factory`, `open_bluez`, adapter verification, L2CAP-readiness polling, platform error mapping, and their existing tests to `platform.rs`.

- [ ] **Step 4: Verify the refactor**

Run: `cargo fmt --all -- --check`

Run: `cargo test -p aster-ble-linux --locked`

Run: `cargo clippy -p aster-ble-linux --all-targets --locked --no-deps -- -D warnings`

Expected: unchanged test behavior and no warnings.

- [ ] **Step 5: Review and commit**

Review the production diff for DRY boundaries, names, visibility, comments, and accidental behavior changes, then create a signed `refactor(btle): separate Linux platform stream ownership` commit.

### Task 2: Add read-only peer ACL diagnostics

**Files:**
- Create: `crates/aster-ble-linux/src/peer.rs`
- Modify: `crates/aster-ble-linux/src/lifecycle.rs`
- Modify: `crates/aster-ble-linux/src/lib.rs`
- Modify: `docs/quickstart/btle-linux-unattended.md`
- Test: `crates/aster-ble-linux/src/peer.rs`
- Test: `crates/aster-ble-linux/src/lifecycle.rs`

**Interfaces:**
- Produces privately: `PeerAclState::{Absent, Disconnected, Connected}` and `PeerAclObserver::observe(&ValidatedLinkConfig, &LifecycleCancellation) -> PeerAclFuture`.
- Consumes: the exact configured adapter and peer address only; output is one closed state and never includes either locator.

- [ ] **Step 1: Write failing peer-state classification tests**

Add tests proving exact mapping for missing device, disconnected device, connected device, unauthorized query, D-Bus loss, and cancellation. Assert emitted diagnostics contain only the closed state/category.

- [ ] **Step 2: Run the new tests and verify RED**

Run the exact new `peer` tests with `cargo test -p aster-ble-linux --locked peer::tests:: -- --nocapture`.

Expected: compilation/test failure because the observer and states do not exist.

- [ ] **Step 3: Implement the minimal read-only observer**

Use `bluer::Adapter::device_addresses`, `Adapter::device`, and `Device::is_connected`. Do not call connect, disconnect, remove, pair, trust, advertise, or controller setters. Bound the D-Bus query with the existing validated open deadline and cancellation.

- [ ] **Step 4: Write the failing lifecycle-order test**

Inject a fake observer and assert `observe` is called exactly once only after `contact.close()`, the admission future completes, and the final contact reference is dropped. Add cancellation coverage showing shutdown does not wait on a stuck observer.

- [ ] **Step 5: Run the lifecycle-order test and verify RED**

Run the exact new lifecycle test.

Expected: failure because the supervisor does not yet invoke the observer.

- [ ] **Step 6: Integrate sanitized observation**

Add the observer to the private supervisor constructor and emit one concise `BTLE_EVENT peer_acl=<state>` record after every drained contact. Production startup and availability remain unchanged; observation failure is diagnostic and cannot stop the node or mutate the peer.

- [ ] **Step 7: Document the diagnostic boundary**

Update the unattended quickstart with the three closed states, their non-authoritative meaning, and the prohibition on treating a connected ACL as an authenticated or usable Aster contact.

- [ ] **Step 8: Verify, review, and commit**

Run formatting, the complete `aster-ble-linux` tests, and strict no-deps Clippy. Review sanitization, cancellation, task ownership, and absence of mutating BlueZ calls. Create a signed `feat(btle): diagnose retained Linux peer links` commit.

### Task 3: Reproduce and bind the clean-restart root cause

**Files:**
- Modify: `docs/validation/evidence/2026-11-05-cm4-btle-ring1-event-validation.md`
- Create only if a new retained run succeeds: `docs/validation/evidence/2026-11-06-cm4-btle-clean-restart-diagnostic.md`

**Interfaces:**
- Consumes: exact Task-2 binaries and owner-only lab configuration.
- Produces: a sanitized ordered trace of supervisor state, L2CAP result, ACL observation, process stop/start, and controller epoch without credentials or locators.

- [ ] **Step 1: Build and bind diagnostic artifacts**

Build the exact ARM64 binaries using the established pinned path, record source commit/tree and SHA-256 values, and deploy identical artifacts to both CM4 devices.

- [ ] **Step 2: Reproduce before changing recovery behavior**

Run one successful zero-work contact, cleanly stop both processes, verify both stopped, capture the closed peer-ACL states, immediately restart both processes without controller mutation, and retain the first open/contact outcomes.

- [ ] **Step 3: Capture component-boundary evidence**

Record sanitized BlueZ `Connected` transitions, L2CAP open/accept result categories, advertisement/listener lifetime, controller power epoch, process/resource snapshots, and cleanup. Do not retain addresses, mission IDs, tokens, bundles, or raw private state.

- [ ] **Step 4: State one root-cause hypothesis and test it minimally**

Choose exactly one boundary supported by the trace: incomplete owned channel teardown, inability to open a new CoC over a retained ACL, listener/advertisement re-registration, or another demonstrated platform state. Run one minimal diagnostic variation and accept or reject that hypothesis before any recovery implementation.

- [ ] **Step 5: Amend the design and this plan with the proven recovery**

Document the exact API/operation, ownership, timeout, failure classification, and tests. If no non-destructive adapter-local recovery exists, record the limitation and stop rather than adding a controller or peer-wide reset.

### Task 4: Implement the evidence-supported clean-restart recovery

**Files:**
- Determined by Task 3, limited to `crates/aster-ble-linux/src/{stream,platform,peer,lifecycle}.rs`
- Modify: `docs/quickstart/btle-linux-unattended.md`
- Modify: `docs/validation/btle-ring1-evaluation-profile.md`
- Test: owning `aster-ble-linux` module from Task 3

**Interfaces:**
- Consumes: the exact recovery interface added to this plan at Task 3 Step 5.
- Produces: clean process restart without controller mutation for the bounded Linux profile.

- [ ] **Step 1: Write the smallest failing regression from the physical trace**

The regression must fail on the pre-fix code for the demonstrated boundary and assert call order, bounded cancellation, and no peer/controller-wide mutation.

- [ ] **Step 2: Run the regression and verify RED**

Run the exact test and confirm the expected failure is the missing recovery behavior.

- [ ] **Step 3: Implement one minimal recovery change**

Implement only the proven adapter-local change. Do not combine unrelated cleanup or broaden configuration/protocol surfaces.

- [ ] **Step 4: Verify GREEN and focused regressions**

Run the exact test, complete `aster-ble-linux`, `aster-ble-l2cap`, and changed Android crate tests, formatting, strict changed-crate Clippy, lockfile check, and fuzz smoke if framing behavior changed.

- [ ] **Step 5: Update documentation and review production code**

Document supported clean restart and remaining crash/platform limits. Review the entire production diff for DRY structure, ownership, bounded waits, error closure, cancellation, descriptor/task cleanup, sanitized output, and comments. Create a signed fix commit.

### Task 5: Physical Linux and Android validation

**Files:**
- Create: `docs/validation/evidence/2026-11-06-cm4-btle-clean-restart-validation.md`
- Create only on completed physical execution: `docs/validation/evidence/2026-11-06-android-linux-btle-ring1-validation.md`
- Modify: `docs/validation/btle-ring1-evaluation-profile.md`
- Modify: `docs/validation/capability-roadmap.md`
- Modify: PR #146 description

**Interfaces:**
- Consumes: exact signed candidate binaries/APK and the existing Ring-1 procedures.
- Produces: sanitized retained evidence with exact claim boundaries.

- [ ] **Step 1: Validate Linux/Linux Event and clean restart**

On both CM4 devices: start with BTLE unavailable, publish durably, enable controllers, transfer one Event, observe deduplicated zero-work contact, cleanly stop, immediately restart without controller mutation, complete another zero-work contact, and query the exact Event locally.

- [ ] **Step 2: Validate bounded repeated lifecycle behavior**

Exercise a small explicit number of controller-loss/recovery and process-restart cycles, recording RSS, threads, descriptors, contact outcomes, ACL states, and cleanup. This is physical evidence, not a committed long-running automated test.

- [ ] **Step 3: Validate Pixel 9 Pro XL to Linux**

Build/install the exact foreground validator, run the existing fixed Android-initiator/Linux-listener semantic-v9 Event procedure, retain terminal receipt and negotiated packet sizes, and remove the APK plus app data afterward.

- [ ] **Step 4: Retain evidence and update claims**

Bind source, signatures, executable/APK hashes, tools, hardware/software versions, configuration shape, results, limits, and cleanup. Do not claim Android support, broad Linux support, production authorization, or a production MTU/rate threshold.

- [ ] **Step 5: Final focused verification and signed documentation commit**

Run requirements trace validation, documentation/static checks, committed lockfile validation, and the focused changed-crate gates. Update PR #146 accurately and create a signed evidence/documentation commit.

### Task 6: Final review and CI gate

**Files:**
- Review all changes since `acbabb5a55af5019cd6da7c7e5086ac3953f983d`.

**Interfaces:**
- Consumes: Tasks 1–5.
- Produces: review-ready PR #146 head.

- [ ] **Step 1: Review every production change**

Check authority, protocol compatibility, lifecycle ownership, availability-only node coupling, no fallback, no hidden controller mutation, bounded resources, cancellation, error taxonomy, sanitization, and documentation accuracy.

- [ ] **Step 2: Run focused local gates only once**

Run formatting, changed crates, strict no-deps Clippy, lockfiles, requirements trace, protocol contract, and applicable fuzz smoke. Do not start duplicate full checks.

- [ ] **Step 3: Verify signatures and workspace hygiene**

Require a clean worktree, no APK/device data/build artifacts, and good signatures on every new commit.

- [ ] **Step 4: Push once and use CI as the aggregate gate**

Push the signed branch, monitor the single CI run, diagnose failures by lane, and do not trigger concurrent full checks. Mark the draft ready only after required CI is green and the PR claim boundary matches retained evidence.
