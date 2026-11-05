# Linux BTLE Unattended Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an unattended, in-process Linux BTLE Event supervisor that tolerates BlueZ/controller absence, admits one provisioned peer contact at a time, and leaves durable node operation available with no transport.

**Architecture:** `aster-ble-linux` owns the complete BlueZ lifecycle, retry, role, and contact loop. `aster-node` exposes only a typed result for its existing ordered Event admission; it gains no Bluetooth state or generic transport lifecycle. The fixed-role Ring-1 path remains available beside a separate unattended evaluation executable.

**Tech Stack:** Rust, Tokio paused time/watch channels, BlueZ through `bluer` 0.17.4, existing `aster-ble-l2cap` contact and `aster-node` ordered Event admission.

**Spec:** `docs/superpowers/specs/2026-11-05-linux-btle-unattended-lifecycle-design.md`

## Global Constraints

- Do not change semantic v9, framing, authentication, storage, profile vectors, or protocol documents.
- The node must start and commit durable local work when BlueZ, the controller, or every transport is unavailable.
- Lifecycle remains Linux/BlueZ-specific; do not add a generic transport lifecycle, carrier manager, selection policy, or fallback policy.
- Support exactly one configured controller, one provisioned peer, one open/active contact, and Event data in this increment.
- Derive the unattended Linux role by lexicographically comparing complete 32-byte mission node IDs: lower initiates, higher listens, equal is invalid.
- Peer/contact retry starts at 250 ms, doubles to a 30-second cap, and resets after authenticated contact success or a new availability epoch.
- BlueZ session recovery uses an independent 250 ms-to-30-second counter and resets only after event subscription and the first complete adapter-name snapshot both succeed.
- Do not add retry jitter in this single deterministic-initiator increment.
- Successful initiator cadence defaults to 60 seconds and must be nonzero and at most 24 hours; listener success immediately returns to listening.
- Retry, cadence, and role derivation are implementation policy, not protocol or compatibility commitments.
- All timer tests use Tokio paused time; no test waits for a real 60-second cadence or long retry.
- Run Cargo with `CARGO_BUILD_JOBS=1`. Never run implementer, reviewer, or final-gate Cargo commands concurrently, and do not repeat an unchanged broad check.
- Preserve exact Bluetooth locator checks and separate mission-authenticated peer verification; never log addresses, node IDs, paths, credentials, or raw BlueZ/D-Bus errors.
- Preserve the existing fixed-role `aster-btle-ring1` behavior and Android/Linux evidence path.
- Before every push, perform a distinct production-code refactor pass for DRYness, naming, control flow, ownership, error boundaries, and concise comments; remove generated-style repetition and speculative abstractions, then rerun focused verification.
- Address every Critical/Important independent-review finding before pushing. Create only signed commits and verify each signature.

## Review Focus

- A controller transition between event subscription and snapshot must not be lost; Task 3 pins subscribe-before-snapshot and complete resnapshot behavior.
- A stale open/contact completion after controller loss must not start or report another active epoch; Task 4 pins epoch cancellation and single-attempt ownership.
- Admission shutdown must terminate the supervisor while busy/protected-contact failures retry; Tasks 1 and 4 pin the typed mapping.
- Zero/oversized cadence and retry exponent overflow must fail or cap deterministically; Tasks 2-4 pin both bounds.
- Shutdown during unavailable, open/listen, active contact, backoff, or success cadence must drain without leaked advertisement/socket work; Task 4 pins every state.

## File Map

- `crates/aster-node/src/runtime.rs`: typed ordered-contact boundary and its existing actor integration.
- `crates/aster-node/src/lib.rs`: re-export the new ordered-contact error.
- `crates/aster-ble-linux/src/config.rs`: role-independent link configuration, fixed-role compatibility wrapper, unattended configuration, validation, and deterministic role choice.
- `crates/aster-ble-linux/src/controller.rs`: private BlueZ controller/session event monitor and coarse availability output.
- `crates/aster-ble-linux/src/policy.rs`: crate-private capped retry and cancellation shared by the monitor and supervisor.
- `crates/aster-ble-linux/src/lifecycle.rs`: single-peer contact loop, admission adapter, and public supervisor handle.
- `crates/aster-ble-linux/src/lib.rs`: existing socket driver plus focused module/re-export wiring; it must not become the lifecycle implementation file.
- `crates/aster-ble-linux/src/bin/aster-btle-event.rs`: non-Linux rejection wrapper for the unattended evaluation executable.
- `crates/aster-ble-linux/src/bin/aster_btle_event_linux.rs`: Linux CLI parsing, node-first startup, supervisor ownership, and shutdown ordering.
- `crates/aster-ble-linux/src/bin/aster_btle_ring1_linux.rs`: only the configuration-shape migration needed to preserve Ring-1.
- `crates/aster-ble-linux/Cargo.toml`: new binary and the existing workspace `futures` dependency required for BlueZ streams.
- `docs/transports.md`, `docs/validation/btle-ring1-evaluation-profile.md`, and `docs/quickstart/README.md`: bounded evaluation claim and entry-point discovery.
- `docs/quickstart/btle-linux-unattended.md`: exact Linux/Linux unattended evaluation procedure and exclusions.

---

### Task 1: Type the ordered Event admission boundary

**Files:**
- Modify: `crates/aster-node/src/runtime.rs:3832-3925`
- Modify: `crates/aster-node/src/runtime.rs:18100-19810`
- Modify: `crates/aster-node/src/runtime.rs:41880-42220`
- Modify: `crates/aster-node/src/lib.rs:85-102`

**Interfaces:**
- Consumes: the existing `OrderedEventContactHandle`, `NodeError`, actor command channel, and contact close guard.
- Produces: `pub enum OrderedEventContactError { AdmissionClosed, AdmissionBusy, ActorUnavailable, ActorStopped, Contact(NodeError) }`; `OrderedEventContactHandle::run(...) -> Result<PeerReceipt, OrderedEventContactError>`; `Display`, `Error`, and `source()` preserving `NodeError` only for `Contact`.

- [ ] **Step 1: Write failing typed-boundary tests**

Update/add focused runtime tests named `ordered_contact_closed_is_typed`, `ordered_contact_busy_is_typed`, `ordered_contact_actor_loss_is_typed`, and `ordered_contact_failure_preserves_node_error`. Assert exact enum variants, contact closure, and `Contact(NodeError)` source preservation; do not compare diagnostic strings.

- [ ] **Step 2: Run the tests and verify the old string boundary fails**

Run: `cargo test --locked -p aster-node --lib ordered_contact_ -- --nocapture`

Expected: FAIL to compile because `OrderedEventContactError` does not exist or fail because the old `NodeError::Protocol(String)` is returned.

- [ ] **Step 3: Implement the typed command/result path**

Change the handle, `OrderedEventContactCommand.response`, `OrderedEventContactTaskOutput`, actor completion, queued-shutdown rejection, and public re-export together. Map admission gate closed and queued shutdown to `AdmissionClosed`, permit exhaustion to `AdmissionBusy`, send failure to `ActorUnavailable`, response-channel loss to `ActorStopped`, and every admitted protected-session result to `Contact(NodeError)`.

- [ ] **Step 4: Run focused node verification**

Run: `cargo test --locked -p aster-node --lib ordered_contact_ -- --nocapture`

Run: `cargo test --locked -p aster-node --lib running_node_accepts_and_accounts_ordered_event_contacts -- --nocapture`

Expected: PASS; the second test still proves durable publication before an adapter-neutral contact and later semantic-v9 reconciliation.

- [ ] **Step 5: Perform the production refactor pass**

Review only the typed boundary and its callers. Remove repeated conversion branches with one small conversion helper only if it reduces branches; keep `NodeError` opaque, keep variant names transport-neutral, and delete comments that restate match arms.

- [ ] **Step 6: Run formatting and strict relevant lint**

Run: `cargo fmt --all -- --check`

Run: `cargo clippy --locked -p aster-node --lib -- -D warnings`

Expected: PASS.

- [ ] **Step 7: Create and verify a signed commit**

```bash
git add crates/aster-node/src/runtime.rs crates/aster-node/src/lib.rs
git commit -S -m "refactor(node): type ordered contact admission errors"
git verify-commit HEAD
```

Expected: signature verification succeeds. Do not push yet.

### Task 2: Extract shared Linux link and supervisor configuration

**Files:**
- Create: `crates/aster-ble-linux/src/config.rs`
- Modify: `crates/aster-ble-linux/src/lib.rs:1-180`
- Modify: `crates/aster-ble-linux/src/bin/aster_btle_ring1_linux.rs:1-220`

**Interfaces:**
- Consumes: the current `DriverConfig`, `ValidatedConfig`, `FixedRole`, `OpenRequest`, Ring-1 constants, locator construction, and fixed-role tests.
- Produces: `LinkConfig::validate(self) -> Result<ValidatedLinkConfig, DriverError>`; `DriverConfig { link: LinkConfig, role: FixedRole }`; `DriverConfig::validate(self) -> Result<ValidatedConfig, DriverError>`; `SupervisorConfig { link: LinkConfig, local_mission_id: NodeId, peer_mission_id: NodeId, contact_cadence: Duration }`; `SupervisorConfig::validate(self) -> Result<ValidatedSupervisorConfig, DriverError>`; `ValidatedLinkConfig::for_role(&self, FixedRole) -> ValidatedConfig`; `ValidatedSupervisorConfig::{link, role, peer_mission_id, contact_cadence}` accessors.

- [ ] **Step 1: Write failing shared-configuration tests**

Move the existing fixed-role validation/request tests into `config::tests`, then add `supervisor_role_is_complementary_and_stable`, `supervisor_rejects_equal_mission_ids`, and `supervisor_rejects_zero_or_over_24_hour_cadence`. Assert a 60-second cadence and exactly 24 hours are accepted.

- [ ] **Step 2: Run the tests and verify the new types are absent**

Run: `cargo test --locked -p aster-ble-linux --lib config::tests -- --nocapture`

Expected: FAIL to compile until `config.rs` and its interfaces exist.

- [ ] **Step 3: Extract configuration without changing socket behavior**

Move only configuration, validation, request construction, and locator construction into `config.rs`. Keep the existing Ring-1 limits exact. Implement role comparison on the complete `NodeId`; do not compare Bluetooth addresses or add a role option to `SupervisorConfig`.

- [ ] **Step 4: Migrate fixed-role callers**

Construct `DriverConfig { link, role }` in `aster_btle_ring1_linux.rs`; keep its CLI, receipt rules, fixed role, and physical-evidence behavior unchanged. Update `open_contact_with_factory` to use validated accessors instead of reaching through tuple fields.

- [ ] **Step 5: Run focused compatibility verification**

Run: `cargo test --locked -p aster-ble-linux --lib -- --nocapture`

Run: `cargo test --locked -p aster-ble-linux --bin aster-btle-ring1 -- --nocapture`

Expected: PASS with every existing socket, MTU, cancellation, and Ring-1 parser/evidence test retained.

- [ ] **Step 6: Perform the production refactor pass**

Check that shared fields and validation exist once, `config.rs` owns no BlueZ lifecycle, public accessors reveal no mutable internals, and moved comments explain invariants rather than syntax. Remove compatibility aliases or speculative builders not required by the fixed and supervisor paths.

- [ ] **Step 7: Run formatting and strict relevant lint**

Run: `cargo fmt --all -- --check`

Run: `cargo clippy --locked -p aster-ble-linux --all-targets -- -D warnings`

Expected: PASS.

- [ ] **Step 8: Create and verify a signed commit**

```bash
git add crates/aster-ble-linux/src/config.rs crates/aster-ble-linux/src/lib.rs crates/aster-ble-linux/src/bin/aster_btle_ring1_linux.rs
git commit -S -m "refactor(btle): share validated Linux link configuration"
git verify-commit HEAD
```

Expected: signature verification succeeds. Do not push yet.

### Task 3: Monitor coarse BlueZ controller availability

**Files:**
- Create: `crates/aster-ble-linux/src/controller.rs`
- Create: `crates/aster-ble-linux/src/policy.rs`
- Modify: `crates/aster-ble-linux/src/lib.rs`
- Modify: `crates/aster-ble-linux/Cargo.toml`

**Interfaces:**
- Consumes: `ValidatedLinkConfig`, `bluer::{Session, SessionEvent, AdapterEvent}`, and the existing sanitized `DriverError`.
- Produces: `pub enum BtleAvailability { Unavailable(AvailabilityReason), Available }`; `pub enum AvailabilityReason { BluezUnavailable, ControllerAbsent, ControllerUnpowered, ControllerUnauthorized, ControllerIdentityMismatch }`; crate-private `LifecycleCancellation`; crate-private `CappedBackoff::new(initial: Duration, maximum: Duration)`, `next_delay`, and `reset`; `AvailabilityMonitor::run<'a>(&'a self, link: &'a ValidatedLinkConfig, updates: watch::Sender<BtleAvailability>, cancellation: LifecycleCancellation) -> MonitorFuture<'a>` where the future returns `Result<(), DriverError>`; production `BluezAvailabilityMonitor`; a `watch::Receiver<BtleAvailability>` consumed by Task 4.

- [ ] **Step 1: Write failing scripted-monitor tests**

Using a crate-private boxed-future/boxed-stream BlueZ seam, add paused-time tests named `monitor_subscribes_before_snapshot`, `monitor_tracks_add_power_identity_and_removal`, `monitor_resnapshots_all_properties_after_relevant_change`, `monitor_ignores_unrelated_events`, `monitor_reconnects_session_with_independent_capped_backoff`, and `capped_backoff_never_overflows`. Record call order in the fake and assert subscription precedes each snapshot.

- [ ] **Step 2: Run the tests and verify the monitor is absent**

Run: `cargo test --locked -p aster-ble-linux --lib controller::tests -- --nocapture`

Expected: FAIL to compile until the controller monitor and seam exist.

- [ ] **Step 3: Implement shared lifecycle cancellation and capped backoff**

Create the crate-private primitives in `policy.rs`. Cancellation must be cloneable and idempotent. Backoff must use saturating arithmetic, cap before duration multiplication, and expose no protocol-facing values. Test both with paused time or pure assertions.

- [ ] **Step 4: Implement the private BlueZ seam and classifier**

Define private boxed async interfaces for session creation, session-event subscription, adapter-name snapshot, adapter construction, adapter-event subscription, and complete power/address/address-type snapshot. Normalize only the events needed by this monitor. Add `futures.workspace = true` for `StreamExt`; do not expose raw `bluer` events outside `controller.rs`.

- [ ] **Step 5: Implement the production monitor loop**

Subscribe before snapshot at both session and adapter levels. Publish `Available` only for the exact powered configured controller identity. On removal, stream end, D-Bus loss, permission failure, or identity mismatch, publish one coalesced `Unavailable`, release handles, and retry as specified. Reset only the session counter after subscription plus the first complete adapter-name snapshot.

- [ ] **Step 6: Run focused monitor verification**

Run: `cargo test --locked -p aster-ble-linux --lib controller::tests -- --nocapture`

Expected: PASS under paused time with no D-Bus or radio requirement.

- [ ] **Step 7: Perform the production refactor pass**

Separate backend adaptation from state policy, collapse repeated full-snapshot validation, ensure raw errors are mapped at entry, and remove debug output containing controller data. Reject any abstraction that models non-Bluetooth transports.

- [ ] **Step 8: Run formatting and strict relevant lint**

Run: `cargo fmt --all -- --check`

Run: `cargo clippy --locked -p aster-ble-linux --lib -- -D warnings`

Expected: PASS.

- [ ] **Step 9: Create and verify a signed commit**

```bash
git add crates/aster-ble-linux/Cargo.toml crates/aster-ble-linux/src/controller.rs crates/aster-ble-linux/src/policy.rs crates/aster-ble-linux/src/lib.rs
git commit -S -m "feat(btle): observe Linux controller availability"
git verify-commit HEAD
```

Expected: signature verification succeeds. Do not push yet.

### Task 4: Run the single-peer unattended contact supervisor

**Files:**
- Create: `crates/aster-ble-linux/src/lifecycle.rs`
- Modify: `crates/aster-ble-linux/src/controller.rs`
- Modify: `crates/aster-ble-linux/src/lib.rs`

**Interfaces:**
- Consumes: `ValidatedSupervisorConfig`, controller availability watch, `LifecycleCancellation`, `CappedBackoff`, `open_contact_with_factory`, `BluezSocketFactory`, `OpenCancellation`, `OrderedEventContactHandle`, `OrderedEventContactError`, and `MissionPeerExpectation`.
- Produces: `pub fn spawn_linux_btle_event_supervisor(config: ValidatedSupervisorConfig, contacts: OrderedEventContactHandle) -> LinuxBtleEventSupervisor`; `LinuxBtleEventSupervisor::availability(&self) -> watch::Receiver<BtleAvailability>`; `LinuxBtleEventSupervisor::cancel(&self)`; `LinuxBtleEventSupervisor::shutdown(self) -> Result<(), SupervisorError>`; private `ContactAdmission` and `ContactOpener` boxed-future seams for deterministic tests; terminal `SupervisorError` with sanitized closed categories.

- [ ] **Step 1: Write failing paused-time lifecycle tests**

Add tests named `unavailable_starts_no_contact`, `available_starts_exactly_one_derived_role`, `controller_loss_cancels_open_and_active_contact`, `retryable_failures_back_off_without_overlap`, `availability_epoch_and_success_reset_peer_backoff`, `initiator_obeys_cadence_and_listener_relistens`, `terminal_admission_errors_stop_the_supervisor`, and `shutdown_drains_every_lifecycle_state`. Use fake opener/admission objects that count active work and Tokio paused time.

- [ ] **Step 2: Run the tests and verify the supervisor is absent**

Run: `cargo test --locked -p aster-ble-linux --lib lifecycle::tests -- --nocapture`

Expected: FAIL to compile until the lifecycle interfaces exist.

- [ ] **Step 3: Integrate the shared backoff and cancellation primitives**

Use the Task 3 primitives for monitor acquisition, availability waits, opens, admission, backoff, cadence, and shutdown. Instantiate peer backoff with 250 ms and 30 seconds independently of the monitor counter. Do not add `tokio-util` or wall-clock sleeps in tests.

- [ ] **Step 4: Implement the contact loop**

For each availability epoch, derive the fixed role once, create a fresh open cancellation, and own at most one open/contact future. Construct `MissionPeerExpectation` from the opened contact's locator evidence plus the configured mission peer. Treat validated-impossible `DriverErrorKind::Configuration`, `AdmissionClosed`, `ActorUnavailable`, and `ActorStopped` as terminal; treat peer absence, timeout, transport/socket loss, `PeerRejected`, `AdmissionBusy`, and `Contact(NodeError)` as peer retry. Treat cancellation caused by controller loss or shutdown as normal. Drop/cancel the entire attempt before moving state.

- [ ] **Step 5: Implement the public supervisor handle**

Start the BlueZ monitor and contact loop as owned child tasks. `availability()` returns a cloned coarse receiver, `cancel()` is idempotent, and `shutdown(self)` cancels and joins both tasks before returning. Coalesce identical availability output and emit only sanitized transition categories; a successful contact may include existing aggregate receipt counts but never peer identifiers.

- [ ] **Step 6: Run focused lifecycle and existing socket tests**

Run: `cargo test --locked -p aster-ble-linux --lib lifecycle::tests -- --nocapture`

Run: `cargo test --locked -p aster-ble-linux --lib tests:: -- --nocapture`

Expected: PASS; timer tests complete through virtual time, and existing socket behavior is unchanged.

- [ ] **Step 7: Perform the production refactor pass**

Review the full controller/lifecycle diff for a single owner per task/guard, one error-classification point, no duplicate state flags, no generic carrier vocabulary, and no comments that narrate control flow. Split helpers that exceed one responsibility; remove unused observability hooks and future-facing policy traits.

- [ ] **Step 8: Run formatting and strict relevant lint**

Run: `cargo fmt --all -- --check`

Run: `cargo clippy --locked -p aster-ble-linux --lib -- -D warnings`

Expected: PASS.

- [ ] **Step 9: Create and verify a signed commit**

```bash
git add crates/aster-ble-linux/src/lifecycle.rs crates/aster-ble-linux/src/controller.rs crates/aster-ble-linux/src/lib.rs
git commit -S -m "feat(btle): supervise one Linux Event contact"
git verify-commit HEAD
```

Expected: signature verification succeeds. Do not push yet.

### Task 5: Add the unattended Linux evaluation executable

**Files:**
- Create: `crates/aster-ble-linux/src/bin/aster-btle-event.rs`
- Create: `crates/aster-ble-linux/src/bin/aster_btle_event_linux.rs`
- Modify: `crates/aster-ble-linux/Cargo.toml`

**Interfaces:**
- Consumes: `UnprotectedReferenceMission::identity`, `start_transport_neutral_node`, `SupervisorConfig`, `spawn_linux_btle_event_supervisor`, and the existing Ring-1 address/PSM parser conventions.
- Produces: `aster-btle-event`, an evaluation executable with no role option; required adapter/local/peer address and type, PSM, state, mission bundle, and mission peer options; optional `--contact-cadence-seconds` defaulting to 60.

- [ ] **Step 1: Write failing CLI/startup-order tests**

Add binary tests named `parses_unattended_configuration_without_role`, `rejects_role_unknown_duplicate_and_invalid_cadence`, and `shutdown_orders_supervisor_before_node`. Use injected start/supervisor closures for the order test; do not access BlueZ or wait on signals.

- [ ] **Step 2: Run the tests and verify the binary is absent**

Run: `cargo test --locked -p aster-ble-linux --bin aster-btle-event -- --nocapture`

Expected: FAIL because the binary target and source files do not exist.

- [ ] **Step 3: Implement CLI validation and node-first startup**

Load the mission bundle, capture `mission.identity()`, and validate the complete supervisor configuration before moving the mission into `TransportNeutralNodeConfig`. Then start the node first, start the supervisor second, and wait for SIGINT/SIGTERM. On every exit path cancel and await the supervisor before `RunningNode::shutdown`. Do not add daemonization, discovery, pairing, controller mutation, or production-ready claims.

- [ ] **Step 4: Run binary and compatibility verification**

Run: `cargo test --locked -p aster-ble-linux --bin aster-btle-event -- --nocapture`

Run: `cargo test --locked -p aster-ble-linux --bin aster-btle-ring1 -- --nocapture`

Expected: PASS; the new CLI has no role option and the old fixed-role harness remains unchanged.

- [ ] **Step 5: Perform the production refactor pass**

Deduplicate only parsing helpers genuinely shared by the two binaries; keep Ring-1 evidence code out of the unattended binary. Tighten operator messages to closed categories, remove IDs/addresses, and keep startup/shutdown ownership linear and readable.

- [ ] **Step 6: Run formatting and strict all-target lint**

Run: `cargo fmt --all -- --check`

Run: `cargo clippy --locked -p aster-ble-linux --all-targets -- -D warnings`

Expected: PASS.

- [ ] **Step 7: Create and verify a signed commit**

```bash
git add crates/aster-ble-linux/Cargo.toml crates/aster-ble-linux/src/bin/aster-btle-event.rs crates/aster-ble-linux/src/bin/aster_btle_event_linux.rs
git commit -S -m "feat(btle): run unattended Linux Event lifecycle"
git verify-commit HEAD
```

Expected: signature verification succeeds. Do not push yet.

### Task 6: Document, review, and verify the bounded claim

**Files:**
- Create: `docs/quickstart/btle-linux-unattended.md`
- Modify: `docs/quickstart/README.md`
- Modify: `docs/transports.md`
- Modify: `docs/validation/btle-ring1-evaluation-profile.md`

**Interfaces:**
- Consumes: Tasks 1-5 and the approved claim boundary.
- Produces: an exact Linux/Linux evaluation procedure and explicit exclusions; no requirement-credit or production-authorization change.

- [ ] **Step 1: Write the bounded documentation**

Document node-first operation with controllers absent, durable publication while unavailable, later power/attach and reconciliation, power-cycle recovery, clean shutdown, and evidence fields to retain. State Linux/Linux, one controller, one provisioned peer, Event-only, evaluation-stage, and no discovery/selection/fallback/daemon/other-data-class claim.

- [ ] **Step 2: Run documentation and focused package checks**

Run: `cargo test --locked -p aster-node --lib ordered_contact_ -- --nocapture`

Run: `cargo test --locked -p aster-node --lib running_node_accepts_and_accounts_ordered_event_contacts -- --nocapture`

Run: `cargo test --locked -p aster-ble-linux --all-targets -- --nocapture`

Run: `cargo fmt --all -- --check`

Run: `cargo clippy --locked -p aster-node --lib -- -D warnings`

Run: `cargo clippy --locked -p aster-ble-linux --all-targets -- -D warnings`

Expected: PASS. Do not run the full workspace or any real-time 60-second test locally; record that CI owns the broader partitions.

- [ ] **Step 3: Perform the required whole-diff production refactor pass**

Inspect every changed production file independently of the feature implementation. Consolidate duplicated validation/classification, shorten nested control flow, verify cancellation/drop ownership, use precise names, remove speculative/public hooks, and delete AI-style explanatory repetition. Rerun Step 2 after any edit.

- [ ] **Step 4: Obtain independent whole-branch review**

Ask a fresh reviewer to compare the complete diff with the approved spec, focusing on lifecycle races, admission classification, privacy, shutdown, test realism, and claim scope. Address every Critical/Important finding, then rerun Step 2. Record lesser findings and why they are deferred.

- [ ] **Step 5: Create and verify the signed documentation commit**

```bash
git add docs/quickstart/btle-linux-unattended.md docs/quickstart/README.md docs/transports.md docs/validation/btle-ring1-evaluation-profile.md docs/superpowers/specs/2026-11-05-linux-btle-unattended-lifecycle-design.md docs/superpowers/plans/2026-11-05-linux-btle-unattended-lifecycle.md
git commit -S -m "docs: define unattended Linux BTLE evaluation"
git verify-commit HEAD
git status --short
```

Expected: signature verification succeeds and the worktree is clean.

- [ ] **Step 6: Push once after cleanup and review**

Push the signed series to the existing PR branch, then inspect PR checks. Do not amend protocol claims or merge while required checks are pending or failed.
