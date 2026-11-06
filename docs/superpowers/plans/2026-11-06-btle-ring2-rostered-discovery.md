# BTLE Ring 2 Rostered Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add bounded authenticated Linux BTLE rostered discovery and the
separate Android durable Event-send companion without changing semantic v9.

**Architecture:** Keep discovery, BlueZ ownership, and lifecycle private to
`aster-ble-linux`; place authenticated credential transition authority in
`aster-host`; reuse the existing exact-peer node admission and Event contact.
The Android example publishes durably before transport and attaches the
existing fixed-locator contact afterward. The two lanes remain independently
testable and reviewable.

**Tech Stack:** Rust 2024, Tokio, BlueZ/bluer, RustCrypto HMAC/SHA-256,
zeroize, redb, JNI, Kotlin/Android.

**Spec:** `docs/superpowers/specs/2026-11-06-btle-ring2-rostered-discovery-design.md`

## Global Constraints

- No Event, mission, profile, storage, application, or semantic-version wire
  bytes change; semantic v9 and the complete mission handshake remain intact.
- `BleL2capV1` remains an independent adapter with no GATT, IP, fixed-locator,
  or automatic carrier fallback.
- Transport absence never prevents local durable publication or application
  readiness.
- Linux scope is one configured controller, one exact mission peer, one active
  Event contact, and role derived from the two exact mission NodeIds.
- Carrier UUID is `6aa1cfed-2ce3-46d4-9c69-a33d1dd54ee5`; record revision 1
  is exactly 40 bytes and uses the design's HMAC-SHA-256/128 construction.
- Discovery limits and timing are fixed implementation policy, not protocol.
- Secrets, proof tags, nonces, Bluetooth addresses, PSMs, and mission IDs do
  not enter public status or routine logs.
- Tests inject clocks, entropy, observations, and handles; no real 60-second
  sleeps and no parallel full checks.
- Dependency patches are exact-pinned, minimal, licensed, and recorded in the
  SBOM/decision evidence.
- Commits are signed; pushing and PR mutation require a separate explicit
  handoff after local verification and refactor review.

## Review Focus

- A proof-valid credential holder floods rotating locators: Aster work must
  remain within callback, HMAC, cache, and token-bucket limits.
- BlueZ stop/unregister does not acknowledge: no replacement may be created
  until cessation is proven, while consuming shutdown remains bounded.
- Credential restart occurs between checkpoint sync, rename, directory sync,
  and exposure: rollback or same-generation secret substitution must fail.
- Android dies around `ack_pending`, UI callback, or confirmation: recovery
  must retain one semantic Event and the exact completion token.
- Terminal output contains control, bidi, zero-width, non-BMP, or maximum
  expansion input: output stays one bounded ASCII line and ack follows flush.

---

### Task 1: Frozen discovery record and leased credential value

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/aster-ble-linux/Cargo.toml`
- Create: `crates/aster-ble-linux/src/discovery_record.rs`
- Modify: `crates/aster-ble-linux/src/lib.rs`
- Create: `crates/aster-ble-linux/tests/fixtures/roster_beacon_v1.txt`

**Interfaces:**
- Produces: `DiscoveryGeneration`, `DiscoverySecret`,
  `LeasedDiscoveryCredentialSet`, `AsterRosterBeaconV1`,
  `AsterRosterBeaconV1::encode`, and
  `AsterRosterBeaconV1::decode_and_verify`.
- Consumes: canonical UUID bytes, LE dynamic PSM bounds, injected monotonic
  lease deadline, and injected nonce bytes.

- [ ] Write tests for exact 40-byte encoding, independent RFC 4231 sanity
  vector, frozen known-answer fixture, emitting/overlap verification, redacted
  debug, constant-time tag comparison, and every structural rejection class.
- [ ] Run `cargo test -p aster-ble-linux discovery_record -- --nocapture` and
  verify the new tests fail because the module/API is absent.
- [ ] Implement the minimal pure codec and non-Clone zeroizing credential
  values; validate before HMAC allocation and expose no secret-bearing errors.
- [ ] Run the focused command and verify all record tests pass.
- [ ] Refactor names, ownership, and duplication while keeping the tests green.

### Task 2: Authenticated discovery credential authority

**Files:**
- Modify: `crates/aster-host/Cargo.toml`
- Create: `crates/aster-host/src/discovery_credentials.rs`
- Modify: `crates/aster-host/src/lib.rs`

**Interfaces:**
- Consumes: `ProvisioningSecretLoader`, exact expected 32-byte deployment
  scope, `TrustedClock`, and `DiscoveryCheckpointStore`.
- Produces: `DiscoveryCredentialAuthority::load() ->
  LeasedDiscoveryCredentialSet`, canonical artifact parser, fixed checkpoint,
  and closed `DiscoveryCredentialError` categories.

- [ ] Write parser, transition, fingerprint, lease, trusted-clock
  discontinuity, same-sequence idempotence, rollback, crash-cut, and secret
  substitution tests for the exact 109/145-byte artifacts.
- [ ] Run `cargo test -p aster-host discovery_credentials -- --nocapture` and
  verify failure because the authority is absent.
- [ ] Implement parse/validate, the five allowed ordered transitions,
  fingerprint binding, single-writer checkpoint replacement, and lease
  conversion with injected storage/clock seams.
- [ ] Run focused tests and verify all authority cases pass.
- [ ] Add the explicitly named owner-only unprotected-reference evaluator
  loader using descriptor validation and a zeroizing bounded read; test
  symlink, owner/mode/link/size, race, and trailing-byte rejection.

### Task 3: Bounded candidate admission and scan policy

**Files:**
- Create: `crates/aster-ble-linux/src/discovery.rs`
- Modify: `crates/aster-ble-linux/src/lib.rs`
- Modify: `fuzz/Cargo.toml`
- Create: `fuzz/fuzz_targets/ble_roster_beacon.rs`
- Create: `fuzz/fuzz_targets/ble_discovery_credential.rs`

**Interfaces:**
- Consumes: verified `AsterRosterBeaconV1`, `CanonicalLocator`, injected
  monotonic observations, and fixed qualification limits.
- Produces: `DiscoveryAdmission`, `DiscoveryCandidate`, scan-window outcome,
  inbound recent-candidate admission, and exact bounded counters.

- [ ] Write paused-time tests for callback/HMAC/token budgets, locator
  supersession, replay/relay binding, full-cache fail-closed behavior,
  deterministic selection/eviction, negative cache, token buckets, and scan
  duty cycle.
- [ ] Run `cargo test -p aster-ble-linux discovery:: -- --nocapture` and verify
  failure because admission does not exist.
- [ ] Implement the bounded state with fixed-capacity collections and explicit
  per-window counters; parse and authenticate before candidate allocation.
- [ ] Run focused tests and then `mise run fuzz-smoke`; verify both pass.
- [ ] Refactor the admission code for one responsibility per type and rerun
  focused tests.

### Task 4: Rostered configuration and private platform seams

**Files:**
- Modify: `crates/aster-ble-linux/src/config.rs`
- Create: `crates/aster-ble-linux/src/platform/discovery.rs`
- Create: `crates/aster-ble-linux/src/platform/socket.rs`
- Modify: `crates/aster-ble-linux/src/platform.rs`
- Modify: `crates/aster-ble-linux/src/lib.rs`

**Interfaces:**
- Consumes: one leased credential set, controller name/identity, exact mission
  IDs, existing contact bounds, canonical locator.
- Produces: `RosteredAdapterConfig::{Off, Enabled}`,
  `ValidatedRosteredSupervisorConfig`, `DiscoveryPlatform`,
  `OwnedAdvertisement`, `OwnedScan`, and `RosteredSocketFactory`.

- [ ] Write validation tests proving `Off` constructs nothing, enabled config
  has no remote address/PSM or tunable discovery bounds, role is complementary,
  and invalid config touches no platform seam.
- [ ] Run `cargo test -p aster-ble-linux config::tests -- --nocapture` and
  verify new cases fail.
- [ ] Implement the rostered configuration beside, not inside, Ring 1 config;
  split the production socket module without behavior change.
- [ ] Write fake-platform ownership tests for dynamic PSM, exact advertisement
  tuple, bounded observation stream, awaited stop, termination, and canonical
  public/random locators.
- [ ] Implement only the private injected traits and translation values needed
  by those tests; run all `aster-ble-linux` library tests.

### Task 5: Exact-pinned dependency hardening

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `third-party/hmac-0.13.0-aster/` from exact upstream 0.13.0
- Create: `third-party/bluer-0.17.4-aster/` from exact upstream 0.17.4
- Modify: dependency inventory/SBOM and buy-vs-build record selected by the
  repository's existing format.

**Interfaces:**
- Produces: zeroized HMAC derived-key construction temporary; awaited BlueZ
  advertisement unregister/discovery stop and termination notifications; a
  256-event first ingress queue that terminates the session on overflow.
- Consumes: Task 4 ownership traits without embedding Aster policy in either
  dependency patch.

- [ ] Add source/drop-path tests that fail against upstream HMAC because the
  private constructor buffer is not `Zeroizing`.
- [ ] Vendor and minimally patch exact HMAC 0.13.0; verify its tests plus Task 1
  vectors pass with only the intended source delta.
- [ ] Add bluer tests for awaited stop/unregister, termination notification,
  exact queue capacity, and `IngressOverflow`; verify upstream fails them.
- [ ] Vendor and minimally patch exact bluer 0.17.4; run its focused tests and
  `cargo test -p aster-ble-linux --lib`.
- [ ] Record upstream source digest, patch digest, feature set, license,
  vulnerability/maintenance review, and SBOM entries.

### Task 6: Rostered Linux lifecycle and BlueZ integration

**Files:**
- Create: `crates/aster-ble-linux/src/rostered_lifecycle.rs`
- Modify: `crates/aster-ble-linux/src/platform/discovery.rs`
- Modify: `crates/aster-ble-linux/src/platform/socket.rs`
- Modify: `crates/aster-ble-linux/src/controller.rs`
- Modify: `crates/aster-ble-linux/src/lib.rs`
- Modify: `crates/aster-ble-linux/src/bin/aster_btle_event_linux.rs`
- Modify: `docs/quickstart/` rostered evaluator documentation

**Interfaces:**
- Consumes: Tasks 1–5, existing exact-peer Event supervisor/contact operation,
  availability monitor, and cancellation/backoff helpers.
- Produces: `LinuxRosteredBtleEventSupervisor`, clean consuming shutdown
  result, dynamic listener/advertisement/scan epoch, and explicit evaluator
  configuration with no fallback.

- [ ] Write fake-platform paused-time tests for the full startup order,
  rotation, newest-candidate open, recent inbound admission, exact mission
  rejection, controller loss, every unexpected child termination, and no
  transport durable-pending behavior.
- [ ] Run the rostered lifecycle test filter and verify failure because the
  lifecycle is absent.
- [ ] Implement one owned epoch cancellation tree and preferred one-peer role
  loop, reusing the existing contact operation rather than creating protocol
  behavior.
- [ ] Add cessation-barrier tests for all stop/unregister outcomes, no
  replacement on backoff, and paused-time 40-second consuming shutdown.
- [ ] Implement BlueZ production traits and barrier-driven drain/reconstruct;
  run focused lifecycle, controller, platform, and fixed Ring 1 tests.
- [ ] Add evaluator parsing/runbook while preserving explicit fixed-locator
  compatibility and sanitized default output.

### Task 7: Android transport-neutral durable send

**Files:**
- Modify: `crates/aster-ble-android/src/config.rs`
- Create: `crates/aster-ble-android/src/send.rs`
- Modify: `crates/aster-ble-android/src/session.rs`
- Modify: `crates/aster-ble-android/src/jni.rs`
- Modify: `crates/aster-ble-android/src/lib.rs`
- Modify: `examples/android-btle-ring1/app/src/main/java/org/defenseunicorns/aster/btlering1/NativeValidator.kt`
- Modify: `examples/android-btle-ring1/app/src/main/java/org/defenseunicorns/aster/btlering1/BluetoothBridge.kt`
- Modify: `examples/android-btle-ring1/app/src/main/java/org/defenseunicorns/aster/btlering1/MainActivity.kt`
- Modify: `examples/android-btle-ring1/app/src/main/java/org/defenseunicorns/aster/btlering1/ValidationState.kt`
- Modify: `examples/android-btle-ring1/app/src/main/res/layout/activity_main.xml`
- Modify: corresponding Rust and Kotlin tests

**Interfaces:**
- Produces: `start_send`, `attach_contact`, `recover_send_status`,
  `confirm_completion`, and `stop_retrying` with exact IDs/token compare-and-
  set; Kotlin process-wide state machine with no pending store.
- Consumes: existing numbered publication journal/backend acknowledgement and
  fixed-locator semantic-v9 contact.

- [ ] Write Rust RED tests for validation, publish-before-descriptor, stable
  Event recovery, bounded journal initialization, all crash cuts,
  `ack_pending`, confirmed/unconfirmed completion, stale tokens, and exactly-
  once FD adoption/close.
- [ ] Implement the minimal native durable state machine and separate send
  receipt without weakening conformance mode; run Android crate tests.
- [ ] Write Kotlin RED tests for the exact operator states, disabled/enabled
  actions, retry, Stop Retrying warning, no duplicate pending authority, and
  detachFd ownership.
- [ ] Implement the foreground UI and two-phase call sequence; run bounded JVM
  unit tests and assemble the debug validator APK without device install.
- [ ] Refactor the production diff for ownership, DRY state transitions,
  sanitized errors, and readable JNI boundaries; rerun both test sets.

### Task 8: Linux Android-Event terminal application

**Files:**
- Modify: `crates/aster-ble-linux/src/bin/aster_btle_event_linux.rs`
- Modify: `docs/quickstart/btle-android-ring1.md`
- Modify: terminal example tests

**Interfaces:**
- Produces: default-off `--print-android-events yes|no`, exact validator
  application subscription, bounded ASCII-only renderer, and ack-after-flush.
- Consumes: existing selected Event application API and configured Android
  mission NodeId.

- [ ] Write RED tests for exact publisher/key/payload filtering, all escape
  classes, 2,048-byte maximum, diagnostic disposition, default-off behavior,
  write/flush failure, and acknowledgement ordering.
- [ ] Implement the example-owned client and renderer without adding an
  adapter payload callback; run focused binary tests.
- [ ] Update the runbook to separate strict conformance, durable send, and
  Linux/Linux rostered discovery evidence.
- [ ] Run fixed-locator, Android conformance, and terminal regression tests.

### Task 9: Traceability, verification, refactor review, and independent review

**Files:**
- Modify only the exact roadmap/status/evidence/SBOM files whose boundary
  genuinely changes.
- Create retained evidence templates; do not claim unavailable physical data.

**Interfaces:**
- Consumes: all prior tasks and the specification's deterministic/physical
  gates.
- Produces: honest implemented-vs-observed claim boundary and review package.

- [ ] Run `cargo fmt --all -- --check`, focused affected crate tests, clippy for
  affected targets, `mise run fuzz-smoke`, and
  `python3 tools/check-implementation-requirements.py` when traceability moves.
- [ ] Review every production change for ownership, duplication, naming,
  bounds, secret/error sanitization, generated artifacts, and AI verbosity;
  refactor with RED→GREEN coverage where behavior could move.
- [ ] Run one serialized `mise run check`, retain its complete result, and do
  not start another full check concurrently.
- [ ] Create the whole-branch review package and dispatch fresh architecture
  and security review; address Critical/Important findings with failing tests.
- [ ] Run available local-radio validation and record exact external physical
  blockers without broadening the support claim.

