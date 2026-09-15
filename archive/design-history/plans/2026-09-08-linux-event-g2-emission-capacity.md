# Linux Event G2 Emission and Capacity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the Linux Event evaluation profile's G2 source/API boundary
with restart-selected ReceiveOnly operation, authenticated audited capacity
status, and a distinct terminal Event-operation-capacity error.

**Architecture:** The strict agent configuration selects `EventEmissionPolicy`
before node startup. The running node remains the sole authority for effective
policy and durable store counters; its existing Event status command returns
one consistent audited snapshot, while the crate-private Event service adds the
configured policy and maps that snapshot to additive protobuf fields. Exact
Event operation row/byte exhaustion receives its own application error kind so
the public RPC can distinguish it from retryable aggregate pressure.

**Tech Stack:** Rust 2024, serde JSON, redb, Tokio, Protobuf, ConnectRPC 0.9.0,
Buf 1.72.0, generated Go client.

**Spec:** `docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md`
on `feature/p0-1-linux-event-mvp-profile`, sections “Emission modes”, “Durable
publish-operation containment”, and “Minimum observability and failure
contract”.

## Global Constraints

- `aster-agent` remains the only deployed service executable and
  `event_service` remains crate-private.
- The strict v1 config requires exactly `normal` or `receive_only`; mode changes
  require restart and no live policy RPC is added.
- ReceiveOnly initiates no contacts and discloses no local Event/control
  inventory or objects, but remains ready for authenticated inbound work and
  mandatory response traffic; it is not physical radio silence.
- The authenticated status reports configured and effective policy separately.
- The profile operation boundary is 1,024 rows, warning begins at 512 rows, and
  hard implementation ceilings remain 4,096 rows and 524,288 bytes.
- The profile pending-delivery workload boundary is 256; the existing hard
  store ceiling remains 262,144.
- No online mapping reclamation, profile-limit enforcement, new database,
  generic plugin/runtime selector, TTL, Event-content deletion, or new
  dependency is introduced.
- Protobuf additions are additive under `aster.application.v1alpha1`; existing
  field numbers and RPC meanings do not change.
- Use focused tests with `CARGO_BUILD_JOBS=2`; do not run the full repository
  gate during task iteration.

---

### Task 1: Require and wire the startup emission policy

**Files:**
- Modify: `crates/aster-agent/src/config.rs`
- Modify: `crates/aster-agent/src/runtime.rs`
- Modify: `crates/aster-agent/tests/customer_runtime.rs`

**Interfaces:**
- Consumes: `aster_node::EventEmissionPolicy` and
  `SelectedForwardingConfig::with_emission_policy`.
- Produces: required JSON field `mesh.emission_policy`,
  `ValidatedAgentConfig::emission_policy()`, and a node started with the exact
  selected policy.

- [ ] Add a config test whose valid fixture accepts `normal` and
  `receive_only`, asserts `forwarding().emission_policy()`, and rejects an
  unknown value as `ConfigReason::InvalidEmissionPolicy`.
- [ ] Run
  `cargo test --locked -p aster-agent --lib config::tests::v1_requires_exact_emission_policy`
  and observe failure because the field and reason do not exist.
- [ ] Add `RawEmissionPolicy` with serde `snake_case`, require it from
  `RawMesh`, map it to `EventEmissionPolicy`, and build forwarding with
  `.with_emission_policy(policy)`.
- [ ] Expose the validated value through
  `pub const fn emission_policy(&self) -> EventEmissionPolicy` without adding a
  mutable setter.
- [ ] Update every checked-in customer config fixture to include
  `"emission_policy":"normal"`.
- [ ] Add a customer-runtime test proving a `receive_only` config reaches ready
  state with no peers and preserves local Event publication.
- [ ] Run only the config test and new customer-runtime test under `umask 0077`.
- [ ] Commit as `feat(agent): select Event emission mode at restart`.

### Task 2: Produce one audited node capacity snapshot

**Files:**
- Modify: `crates/aster-redb-store/src/lib.rs`
- Modify: `crates/aster-node/src/application.rs`
- Modify: `crates/aster-node/src/runtime.rs`

**Interfaces:**
- Produces `AggregateStoreUsage { items: u64, payload_bytes: u64 }` through
  `Store::aggregate_usage()`.
- Extends `SelectedEventStatus` with `emission_policy`, `store_usage`,
  `store_limits`, `event_operations`, `event_operation_bytes`, and
  `pending_deliveries`.
- Uses the existing audited `Store::event_stats()` and
  `Store::event_subscription_stats()` paths; it does not scan or decode data in
  the RPC layer.

- [ ] Add a store test that inserts one Event publication operation and proves
  aggregate usage includes both the Event and its operation row/bytes while
  remaining within `Store::limits()`.
- [ ] Run the store test and observe failure because `aggregate_usage()` is not
  public.
- [ ] Add public `AggregateStoreUsage` and `Store::aggregate_usage()` backed by
  the existing transactional metadata accounting helper.
- [ ] Extend the selected-node status test to assert an effective
  `ReceiveOnly` snapshot and literal empty/nonempty capacity counters.
- [ ] Pass the live `LiveEmissionPolicy` into Event status execution, read one
  policy snapshot, aggregate usage, Event stats, subscription stats, and store
  limits, and return them in `SelectedEventStatus`.
- [ ] Run only the new store test and selected Event status tests.
- [ ] Commit as `feat(node): report audited Event capacity status`.

### Task 3: Distinguish terminal operation-map exhaustion

**Files:**
- Modify: `crates/aster-node/src/application.rs`
- Modify: `crates/aster-agent/src/error.rs`
- Modify: `proto/aster/application/v1alpha1/aster.proto`

**Interfaces:**
- Adds `ApplicationErrorKind::OperationCapacity` for only
  `EventOperationLimitExceeded` and `EventOperationByteLimitExceeded`.
- Adds protobuf enum value
  `PUBLIC_ERROR_REASON_OPERATION_CAPACITY_EXHAUSTED = 12`.
- Maps the new kind to Connect `ResourceExhausted`, `retryable=false`, and no
  retry delay; generic aggregate resource pressure keeps its existing guidance.

- [ ] Add a node classifier test proving the two Event operation errors map to
  `OperationCapacity` while aggregate `ItemLimitExceeded` remains
  `ResourceLimit`.
- [ ] Add an agent error test expecting reason 12, `ResourceExhausted`, and
  `retryable=false` for `OperationCapacity`.
- [ ] Run both tests and observe the missing enum variants.
- [ ] Implement the two exact mappings and extend the closed public-message
  vocabulary.
- [ ] Run the same tests until green.
- [ ] Commit as `feat(agent): distinguish Event operation capacity`.

### Task 4: Extend authenticated status additively

**Files:**
- Modify: `proto/aster/application/v1alpha1/aster.proto`
- Modify: `proto/aster/application/v1alpha1/aster.fds.bin`
- Modify: `crates/aster-agent/src/event_service.rs`
- Modify: `crates/aster-agent/src/lib.rs`
- Modify: `crates/aster-agent/src/runtime.rs`

**Interfaces:**
- Adds `EmissionMode`, `StoreCapacityStatus`,
  `PublishOperationCapacityStatus`, and `DeliveryCapacityStatus` messages.
- Adds fields 7 through 11 to `GetStatusResponse`: configured/effective mode and
  the three capacity messages.
- `AsterConnectService::new` and `application_service` consume the configured
  `EventEmissionPolicy`; legacy/development composition passes `Normal`.

- [ ] Add an Event-service status test expecting configured `Normal`, effective
  `ReceiveOnly`, zero initial use, hard ceilings 4,096/524,288, profile
  boundary 1,024, remaining 1,024, warning false, and delivery profile/hard
  boundaries 256/262,144.
- [ ] Run the test and observe missing generated fields/types.
- [ ] Add the protobuf enum/messages and fields without renumbering existing
  declarations.
- [ ] Regenerate the descriptor with pinned Buf, allowing Rust generation to
  remain build-script-owned.
- [ ] Store configured policy in `AsterConnectService`; translate the node
  snapshot with checked/saturating profile-headroom arithmetic and explicit
  warning/saturation booleans.
- [ ] Update every `application_service` call: customer runtime passes its
  validated configured policy and legacy `BoundAgent` passes `Normal`.
- [ ] Run the Event-service status test and default/all-feature
  `aster-agent --no-run` checks.
- [ ] Commit as `feat(agent): expose Event evaluation capacity status`.

### Task 5: Regenerate clients, document the contract, and verify G2 narrowly

**Files:**
- Modify: `conformance/agent-go/gen/aster/application/v1alpha1/aster.pb.go`
- Modify: `conformance/agent-go/gen/aster/application/v1alpha1/aster.connect.go`
  only if the pinned generator changes it.
- Modify: `conformance/agent-go/cmd/agent-smoke/main.go`
- Modify: `conformance/agent-go/cmd/agent-smoke/main_test.go`
- Modify: `docs/reference/aster-agent-config-v1.md`
- Modify: `docs/quickstart/connect-agent.md`
- Modify: `docs/decisions/0041-customer-operable-event-service.md`

**Interfaces:**
- Go smoke validates configured/effective policy and capacity status before
  exercising publication/recovery.
- Operator docs state restart-only policy changes, non-silence limitations,
  the 512/1,024 operation boundary, and terminal hard-cap handling.

- [ ] Add Go assertions for the new status values and observe compile failure
  against the old generated client.
- [ ] Run pinned local `buf generate` and the checked-in generation verifier.
- [ ] Update config reference/example JSON and customer quickstart; make clear
  that changing mode requires restart and ReceiveOnly is not physical silence.
- [ ] Update Decision 0041 to record the additive G2 contract and retain every
  packaging/provider/device/release exclusion.
- [ ] Run `go test ./...` only in `conformance/agent-go`.
- [ ] Run focused Rust config, status, error, customer-runtime, and generated-Go
  process tests with two build jobs and one test thread.
- [ ] Run `git diff --check`, `cargo fmt --all -- --check`,
  `tools/check-agent-proto.sh`, `tools/check-agent-go-generated.sh`, and
  `python3 tools/check-implementation-requirements.py` only if traceability
  text changes.
- [ ] Do not run `mise run check`; leave the existing deterministic ambient-
  umask gate with its parallel owner and state this limitation in the PR.
- [ ] Commit as `docs(agent): define G2 emission and capacity operation` and
  push the focused commits to draft PR #1.
