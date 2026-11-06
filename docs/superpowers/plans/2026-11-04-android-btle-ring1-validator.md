# Android BTLE Ring-1 Validator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a minimal foreground Android initiator that validates one real protected semantic-v9 Event end to end against the existing Linux Ring-1 listener over LE L2CAP CoC.

**Architecture:** Kotlin owns Android permission, Activity lifecycle, the public `BluetoothSocket`, and a process-local Unix socket bridge. A narrow Rust JNI library consumes the other Unix descriptor, creates the existing `BleL2capContact`, and runs the unchanged transport-neutral mission/Event session; Rust alone validates the terminal v9 receipt.

**Tech Stack:** Rust 1.91+ workspace crates, Tokio, JNI 0.22.4, Android API 29+, Kotlin with AGP 9.4.1, Gradle 9.6.0, JDK 17, NDK 28.2.13676358, arm64-v8a.

**Spec:** `docs/superpowers/specs/2026-11-04-android-btle-ring1-validator-design.md`

## Global Constraints

- Evaluation-only foreground interoperability; no production or requirement-credit claim.
- Android is the fixed initiator and the existing Linux Ring-1 process is the fixed listener.
- Preserve exact semantic v9, mission profile `0x0001`, profile IDs `[2, 1, 1, 5, 1]`, canonical transfer-profile digest, Event bytes, and durable store behavior.
- Before contact, create or replay the validator's private, versioned exact
  `Consume` subscription for `mesh.messages` at `demo/playground` through the
  existing selected-Event application API; do not add a protocol or public
  configuration field. Any future selector change must remove/migrate the old
  durable selector or require fresh evaluation state; a second operation key
  alone is not a migration.
- Do not add protocol bytes, IP relay, carrier fallback, scan, advertise, listener mode, background service, GATT, pairing authority, or controller management.
- Minimum Android API is 29; first packaged ABI is `arm64-v8a`; Android 12+ requests only `BLUETOOTH_CONNECT` for the manual-address topology.
- One active attempt, 2 MiB protected frame ceiling, 64 MiB complete-contact ceiling, and 30-second authenticated-progress/platform-operation deadline remain unchanged.
- Bluetooth address and PSM are transient locator evidence only; the configured mission node ID is the authentication expectation.
- The Unix socket pair is an Android adapter implementation detail, never a carrier, fallback, identity, or durable authority.
- All commits must be signed with `git commit -S`; never commit mission bundles, state, keys, APKs, native libraries, Gradle caches, SDK paths, or device logs.
- During implementation run focused tests only. Do not run the approximately 26-minute `mise run check` locally without renewed user approval; report it as deferred to CI together with the unavailable Android build/device gates.

## File Structure

- `crates/aster-ble-android/Cargo.toml`: isolated Android evaluation adapter dependencies and `cdylib` output.
- `crates/aster-ble-android/src/config.rs`: bounded native configuration parsing and validation.
- `crates/aster-ble-android/src/receipt.rs`: exact Ring-1 v9 receipt validation and sanitized JSON result.
- `crates/aster-ble-android/src/session.rs`: descriptor-backed contact, node lifecycle, cancellation, and one-run admission.
- `crates/aster-ble-android/src/jni.rs`: panic-contained JNI conversion and callback boundary.
- `crates/aster-ble-android/src/lib.rs`: module exports and Android JNI entry points.
- `examples/android-btle-ring1/build.gradle.kts`, `settings.gradle.kts`, and `gradle.properties`: standalone pinned Android project.
- `examples/android-btle-ring1/app/build.gradle.kts` and `build-rust.sh`: app packaging and reproducible arm64 Rust cross-build.
- `examples/android-btle-ring1/app/src/main/AndroidManifest.xml`: API/feature/permission declarations and foreground-only Activity.
- `examples/android-btle-ring1/app/src/main/java/org/defenseunicorns/aster/btlering1/ValidatorConfig.kt`: form parsing and bounded immutable configuration.
- `examples/android-btle-ring1/app/src/main/java/org/defenseunicorns/aster/btlering1/ValidationState.kt`: phase/result/error model and reducer.
- `examples/android-btle-ring1/app/src/main/java/org/defenseunicorns/aster/btlering1/NativeValidator.kt`: JNI API and callback contract.
- `examples/android-btle-ring1/app/src/main/java/org/defenseunicorns/aster/btlering1/BluetoothBridge.kt`: LE CoC connection and bidirectional local socket pumping.
- `examples/android-btle-ring1/app/src/main/java/org/defenseunicorns/aster/btlering1/MainActivity.kt`: document picker, permission request, controls, and result rendering.
- `examples/android-btle-ring1/app/src/main/res/layout/activity_main.xml`: one-screen validator UI.
- `examples/android-btle-ring1/app/src/test/...`: JVM tests for config, phase reduction, and receipt rendering.
- `docs/quickstart/btle-android-ring1.md`: build, provision, run, evidence, and limitation instructions.

## Review Focus

- Malformed node ID, Bluetooth address, PSM, paths, JSON, packet sizes, or oversized mission input must fail before a node or thread starts; Task 1 pins this.
- A second start during an active run must fail closed, while repeated cancel is harmless and releases the slot; Task 2 pins this.
- EOF, half-close, truncation, Bluetooth-off, permission revocation, or timeout must yield exactly one terminal failure and never a success receipt; Tasks 2 and 4 pin this.
- An Activity disappearing or a JNI callback throwing must not panic across JNI, leak a global reference/descriptor, or keep the Bluetooth socket alive; Tasks 3 and 4 pin this.
- A valid-looking receipt with profile drift, Blob work, the wrong peer, no durable insertion, or an Event not larger than the receive packet size must be rejected; Task 1 pins this.

---

### Task 1: Native configuration and exact v9 receipt policy

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `crates/aster-ble-android/Cargo.toml`
- Create: `crates/aster-ble-android/src/lib.rs`
- Create: `crates/aster-ble-android/src/config.rs`
- Create: `crates/aster-ble-android/src/receipt.rs`
- Modify: `docs/decisions/0002-dependency-admission.md`

**Interfaces:**
- Consumes: `aster_node::PeerReceipt`, `aster_node::parse_node_id`, and the existing v9 transfer-profile helpers from `aster-core`.
- Produces: `ValidatorConfig::from_json(&str) -> Result<ValidatorConfig, ValidatorError>`, `validate_ring1_receipt(&ValidatorConfig, &PeerReceipt) -> Result<ValidationReceipt, ValidatorError>`, and serde-serializable `ValidationReceipt`/`ValidatorError` values for Tasks 2 and 3.

- [ ] **Step 1: Write failing Rust tests for bounded configuration**

  In `config.rs`, add tests named `accepts_fixed_initiator_configuration`, `rejects_malformed_or_unknown_json_fields`, `rejects_invalid_node_address_psm_packet_sizes_and_paths`, and `rejects_mission_bundle_above_the_existing_bound`. Assert a valid config accepts PSM `0x0080`, positive send/receive sizes, exact 64-hex-character mission peer, private state/mission paths, and `require_event_larger_than_mtu=true`; assert each malformed class returns a sanitized `Configuration` or `Bounds` category without echoing input.

- [ ] **Step 2: Run the focused test and verify the crate is absent**

  Run: `cargo test --locked -p aster-ble-android config::tests -- --nocapture`

  Expected: FAIL because package `aster-ble-android` does not exist.

- [ ] **Step 3: Add the crate and minimal configuration implementation**

  Add the crate to the workspace. Define `ValidatorConfig` with `state_path: PathBuf`, `mission_bundle_path: PathBuf`, `mission_peer: [u8; 32]`, `bluetooth_address: String`, `psm: u16`, `send_packet_bytes: usize`, `receive_packet_bytes: usize`, and `require_event_larger_than_mtu: bool`. Deny unknown JSON fields, cap the input JSON and each string, require PSM `0x0080..=0x00ff`, positive packet sizes bounded by `u16::MAX`, an existing regular mission file no larger than the existing mission-bundle limit, and distinct state/mission paths.

- [ ] **Step 4: Run configuration tests and verify they pass**

  Run: `cargo test --locked -p aster-ble-android config::tests -- --nocapture`

  Expected: PASS with no test exceeding the repository's normal focused-test timeout.

- [ ] **Step 5: Write failing exact-receipt tests**

  Add `accepts_one_inserted_v9_event_larger_than_receive_packet`, `rejects_wrong_peer_or_profile_digest`, `rejects_blob_attempt_and_missing_durable_insert`, and `rejects_event_not_larger_than_receive_packet`. Build `PeerReceipt` values with semantic version `9`, profile IDs `[2, 1, 1, 5, 1]`, the canonical digest, expected mission peer, zero Blob receipt, one received Event entry, `inserted == 1`, and received bytes greater than `receive_packet_bytes`; mutate one field per rejection assertion.

- [ ] **Step 6: Run receipt tests and verify they fail**

  Run: `cargo test --locked -p aster-ble-android receipt::tests -- --nocapture`

  Expected: FAIL because `validate_ring1_receipt` is not implemented.

- [ ] **Step 7: Implement the exact receipt validator**

  Implement `validate_ring1_receipt` without duplicating protocol encoding. Recompute the canonical v9 digest through existing `TransferProfileOfferV1`, negotiation, and digest helpers. Return only semantic version, profiles/digest match, directional packet sizes, bounded Event entry/byte counters, insertion count, peer match, larger-than-receive-packet, and no-Blob-attempt fields.

- [ ] **Step 8: Run Task 1 checks**

  Run: `cargo test --locked -p aster-ble-android config::tests receipt::tests -- --nocapture`

  Run: `cargo clippy --locked -p aster-ble-android --all-targets -- -D warnings`

  Run: `sh tools/check-cargo-lockfiles.sh`

  Expected: all pass. The lock graph adds no new `jni` package because exact `jni` 0.22.4 is already locked; the dependency decision records only the new direct evaluation use and its no-production boundary.

- [ ] **Step 9: Commit Task 1 with a signature**

  ```bash
  git add Cargo.toml Cargo.lock crates/aster-ble-android docs/decisions/0002-dependency-admission.md docs/superpowers/specs/2026-11-04-android-btle-ring1-validator-design.md docs/superpowers/plans/2026-11-04-android-btle-ring1-validator.md
  git commit -S -m "feat: add Android BTLE validator policy"
  ```

### Task 2: Descriptor-backed session and cancellation authority

**Files:**
- Create: `crates/aster-ble-android/src/session.rs`
- Modify: `crates/aster-ble-android/src/lib.rs`
- Modify: `crates/aster-ble-android/Cargo.toml`

**Interfaces:**
- Consumes: Task 1's `ValidatorConfig`, `ValidationReceipt`, `ValidatorError`, and `validate_ring1_receipt`; existing `BleL2capContact`, `start_transport_neutral_node`, `MissionPeerExpectation`, and `OrderedEventContactHandle`.
- Produces: `ValidatorPhase`, `PhaseSink`, `RunRegistry::start(config, owned_fd, sink) -> Result<RunId, ValidatorError>`, `RunRegistry::cancel(RunId) -> Result<(), ValidatorError>`, and terminal `RunOutcome` consumed by the JNI boundary.

- [ ] **Step 1: Write failing registry and descriptor tests**

  Add tests `one_active_run_rejects_overlap`, `cancel_is_idempotent_and_releases_slot`, `eof_or_half_close_never_reports_success`, `timeout_reports_one_terminal_failure`, and `invalid_configuration_opens_no_descriptor`. Use a Unix stream pair and an injected fake session future so the tests finish deterministically without Bluetooth, sleeps, or a mission exchange.

- [ ] **Step 2: Run the focused tests and verify failure**

  Run: `cargo test --locked -p aster-ble-android session::tests -- --nocapture`

  Expected: FAIL because `session` and `RunRegistry` do not exist.

- [ ] **Step 3: Implement one-run admission and cancellation**

  Define `RunId(u64)`, a process-global `RunRegistry` guarded by `Mutex`, and one `RunControl` containing a cancellation notifier and contact-close slot. Validate before descriptor adoption or thread spawn. Cancellation closes the contact/descriptor, is safe after completion, and removes the registry entry exactly once.

- [ ] **Step 4: Implement the real validator session**

  On the dedicated runtime thread, wrap the transferred descriptor as nonblocking `tokio::net::UnixStream`, load `UnprotectedReferenceMission`, start `TransportNeutralNodeConfig` with `NodeApplication::Relay`, create `BleL2capContact` with the fixed Ring-1 bounds, run as `OrderedEventContactRole::Initiator` against the configured `MissionPeerExpectation`, validate the receipt with Task 1, and always shut down the node. Emit only `Connecting`, `CarrierConnected`, `Authenticating`, `Reconciling`, and one terminal outcome.

  Before contact admission, create or replay the private exact durable Event
  subscription. Cover a fresh state, same-process replay, and restart replay
  with a focused live-node regression.

- [ ] **Step 5: Run Task 2 checks**

  Run: `cargo test --locked -p aster-ble-android session::tests -- --nocapture`

  Run: `cargo clippy --locked -p aster-ble-android --all-targets -- -D warnings`

  Expected: all pass; descriptor and registry counts return to baseline after every case.

- [ ] **Step 6: Commit Task 2 with a signature**

  ```bash
  git add crates/aster-ble-android
  git commit -S -m "feat: run Android BTLE Event sessions"
  ```

### Task 3: Panic-contained JNI API

**Files:**
- Create: `crates/aster-ble-android/src/jni.rs`
- Modify: `crates/aster-ble-android/src/lib.rs`
- Modify: `crates/aster-ble-android/Cargo.toml`

**Interfaces:**
- Consumes: Task 2's `RunRegistry`, `RunId`, `ValidatorPhase`, and `RunOutcome`.
- Produces: `NativeValidator.nativeStart(configJson: String, transferredFd: Int, callback: Callback): Long` and `NativeValidator.nativeCancel(runId: Long): Unit`, with callback methods `onPhase(String)`, `onComplete(String)`, and `onError(String, String)`.

- [ ] **Step 1: Write failing boundary tests**

  Add tests `panic_is_converted_to_internal_error`, `invalid_utf16_and_json_do_not_start`, `callback_exception_cancels_and_releases_run`, and `terminal_callback_is_delivered_once`. Exercise an internal boundary function with fake callback/registry traits so host tests do not need a JVM.

- [ ] **Step 2: Run tests and verify failure**

  Run: `cargo test --locked -p aster-ble-android jni::tests -- --nocapture`

  Expected: FAIL because the JNI boundary does not exist.

- [ ] **Step 3: Implement the JNI conversion and callback boundary**

  Use exact `jni` 0.22.4. Copy Java strings into bounded Rust values, transfer fd ownership exactly once, create one `GlobalRef`, attach the runtime thread for callbacks, clear/describe no pending Java exception, and contain every panic with `catch_unwind` before returning across JNI. Export only the two validator methods and keep all `unsafe` limited to descriptor/JNI entry-point requirements in this crate.

- [ ] **Step 4: Run Task 3 checks**

  Run: `cargo test --locked -p aster-ble-android --lib -- --nocapture`

  Run: `cargo clippy --locked -p aster-ble-android --all-targets -- -D warnings`

  Expected: all pass and no panic crosses the tested boundary.

- [ ] **Step 5: Commit Task 3 with a signature**

  ```bash
  git add crates/aster-ble-android
  git commit -S -m "feat: expose Android BTLE validator JNI"
  ```

### Task 4: Foreground Android app and Bluetooth bridge

**Files:**
- Create: `examples/android-btle-ring1/settings.gradle.kts`
- Create: `examples/android-btle-ring1/build.gradle.kts`
- Create: `examples/android-btle-ring1/gradle.properties`
- Create: `examples/android-btle-ring1/app/build.gradle.kts`
- Create: `examples/android-btle-ring1/app/build-rust.sh`
- Create: `examples/android-btle-ring1/app/src/main/AndroidManifest.xml`
- Create: `examples/android-btle-ring1/app/src/main/java/org/defenseunicorns/aster/btlering1/ValidatorConfig.kt`
- Create: `examples/android-btle-ring1/app/src/main/java/org/defenseunicorns/aster/btlering1/ValidationState.kt`
- Create: `examples/android-btle-ring1/app/src/main/java/org/defenseunicorns/aster/btlering1/NativeValidator.kt`
- Create: `examples/android-btle-ring1/app/src/main/java/org/defenseunicorns/aster/btlering1/BluetoothBridge.kt`
- Create: `examples/android-btle-ring1/app/src/main/java/org/defenseunicorns/aster/btlering1/MainActivity.kt`
- Create: `examples/android-btle-ring1/app/src/main/res/layout/activity_main.xml`
- Create: `examples/android-btle-ring1/app/src/main/res/values/strings.xml`
- Create: `examples/android-btle-ring1/app/src/test/java/org/defenseunicorns/aster/btlering1/ValidatorConfigTest.kt`
- Create: `examples/android-btle-ring1/app/src/test/java/org/defenseunicorns/aster/btlering1/ValidationStateTest.kt`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: Task 3's two JNI methods and callback contract.
- Produces: one installable arm64 foreground app with `connect(config)`, `cancel()`, immutable `ValidationState`, and no background component.

- [ ] **Step 1: Add the pinned Android scaffold and failing JVM tests**

  Configure application ID `org.defenseunicorns.aster.btlering1`, min SDK 29, compile/target SDK 37, AGP 9.4.1, JDK 17, NDK 28.2.13676358, and arm64-v8a only. Tests must cover valid manual address/PSM/node ID, malformed fields, missing mission copy, ordered phase transitions, duplicate terminal callbacks, and sanitized receipt rendering.

- [ ] **Step 2: Run the Android unit-test command and record the environment gate**

  Run on an Android-equipped host: `gradle :app:testDebugUnitTest`

  Expected here: BLOCKED before execution because this host has no JDK, Gradle, Android SDK, or NDK. Do not download tools implicitly. Record the exact missing prerequisites; continue with static review and Rust-focused checks.

- [ ] **Step 3: Implement pure Kotlin configuration and state reduction**

  `ValidatorConfig.parse(...)` must produce the same fixed values and JSON names as Rust. `reduce(state, event)` must accept only the ordered phase sequence, ignore stale callbacks after a terminal state, and render only bounded counters/digests/categories.

- [ ] **Step 4: Implement the LE CoC and local socket bridge**

  After `BLUETOOTH_CONNECT` approval, resolve the manually entered address, call `createInsecureL2capChannel(psm)`, connect off the main thread, and record `maxTransmitPacketSize`/`maxReceivePacketSize`. Use `ParcelFileDescriptor.createSocketPair()`, transfer one detached fd to native code, and run exactly two bounded pump workers between the other endpoint and the Bluetooth input/output streams. Any pump failure closes every endpoint and triggers one cancel.

- [ ] **Step 5: Implement the foreground Activity**

  Use the system document picker to copy the mission bundle into `filesDir` with a bounded stream and private mode. Render manual address, PSM, expected mission ID, bundle selection, `Connect and validate`, `Cancel`, ordered phase, and terminal receipt/error. Disable editing during a run, cancel in `onDestroy`, request no scan/advertise/location permission, and declare no Service or receiver.

- [ ] **Step 6: Add the deterministic native build hook**

  `build-rust.sh` must require the pinned NDK, installed `aarch64-linux-android` Rust target, and Cargo; set the NDK API-29 clang linker explicitly; build only `aster-ble-android`; and copy `libaster_ble_android.so` into a generated Gradle build directory. Never write a `.so` into source control.

- [ ] **Step 7: Review the manifest and bridge statically**

  Run: `rg -n "BLUETOOTH_SCAN|BLUETOOTH_ADVERTISE|ACCESS_.*LOCATION|<service|<receiver|INTERNET" examples/android-btle-ring1/app/src/main`

  Expected: no matches.

  Run: `bash -n examples/android-btle-ring1/app/build-rust.sh`

  Expected: PASS.

- [ ] **Step 8: Run Android tests/build on an equipped host**

  Run: `gradle :app:testDebugUnitTest :app:assembleDebug`

  Expected: PASS and one unsigned debug APK for local installation only. Do not commit it.

- [ ] **Step 9: Commit Task 4 with a signature**

  ```bash
  git add .gitignore examples/android-btle-ring1
  git commit -S -m "feat: add foreground Android BTLE validator"
  ```

### Task 5: Operator quickstart and bounded verification

**Files:**
- Create: `docs/quickstart/btle-android-ring1.md`
- Modify: `docs/quickstart/README.md`
- Modify: `docs/validation/btle-ring1-evaluation-profile.md`
- Modify: `docs/validation/capability-roadmap.md`

**Interfaces:**
- Consumes: Tasks 1-4 and the existing `aster-btle-ring1` Linux listener CLI.
- Produces: exact build/provision/run instructions and claim-safe evidence interpretation.

- [ ] **Step 1: Write the quickstart**

  Document prerequisites, pinned Android tools, Rust target installation, separate mission bundles, Linux pre-publication, listener command, Android manual fields, expected phase/result fields, cancel/cleanup, log capture, and explicit exclusions. State that pairing/link encryption supplies no mission authority and IP must be disabled for the tested peer.

- [ ] **Step 2: Update evaluation documentation without widening claims**

  Add Android foreground validation as an unretained optional cross-platform extension. Keep the official Ring-1 exit Linux-only until a physical signed receipt exists. In the capability roadmap, describe code availability only if the Android build has succeeded; otherwise describe the scaffold as unverified and leave physical/support gaps unchanged.

- [ ] **Step 3: Run focused repository verification**

  Run: `cargo fmt --all -- --check`

  Run: `cargo test --locked -p aster-ble-android --lib -- --nocapture`

  Run: `cargo test --locked -p aster-ble-l2cap --lib -- --nocapture`

  Run: `cargo test --locked -p aster-ble-linux --bin aster-btle-ring1 -- --nocapture`

  Run: `cargo clippy --locked -p aster-ble-android -p aster-ble-l2cap -p aster-ble-linux --all-targets -- -D warnings`

  Run: `sh tools/check-cargo-lockfiles.sh`

  Run: `python3 tools/check-implementation-requirements.py`

  Expected: all pass. Do not run the full aggregate or known long-running workspace/device suites in this task.

- [ ] **Step 4: Run Android packaging and physical acceptance when equipment is available**

  Build/install the debug APK, start the Linux listener with a pre-published Event larger than the Android receive packet size, connect from Android, and retain both terminal receipts. Confirm expected mission peer, semantic 9, profile IDs/digest, one received/insertion Event, zero Blob attempt, and larger-than-receive-packet. Run any connection-recovery diagnostic as an alternative freshly provisioned setup before its first successful delivery: disconnect its first attempt before `reconciling`, then reconnect so the retry becomes that setup's first successful acceptance.

  The minimal validator cannot distinguish cancellation after a durable insert
  but before terminal callback. Limit its recovery diagnostic to interruption
  before `reconciling`; treat it as connection recovery only. Any deduplication
  acceptance requires separate retained store instrumentation that can observe
  cumulative insertion state across the ambiguous boundary.

- [ ] **Step 5: Inspect every change and signed commit**

  Run: `git diff --check pr-fork/feature/btle-ring1...HEAD`

  Run: `git status --short`

  Run: `git log --show-signature --format=fuller pr-fork/feature/btle-ring1..HEAD`

  Expected: no whitespace errors, only intended files, clean worktree after commit, and every new commit has a good signature.

- [ ] **Step 6: Commit documentation with a signature**

  ```bash
  git add docs/quickstart docs/validation/btle-ring1-evaluation-profile.md docs/validation/capability-roadmap.md
  git commit -S -m "docs: explain Android BTLE Event validation"
  ```

- [ ] **Step 7: Report deferred gates precisely**

  Report the focused command outputs, Android unit/build result or missing-tool block, physical-radio result or hardware block, and that `mise run check` was intentionally not run under the user's long-test constraint. Do not call the app production-ready or the Event path physically validated without the retained Android/Linux receipt.
