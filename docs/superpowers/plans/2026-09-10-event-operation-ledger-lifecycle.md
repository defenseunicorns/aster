# Event Operation Ledger Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the selected Event service's raw-key, 4,096-row operation map
with a mission-bound, one-million-record active/retired ledger that preserves
permanent idempotency semantics, compacts atomically with Event retirement, and
can be qualified at useful aggregated-telemetry rates on the CM4 test nodes.

**Architecture:** `aster-redb-store` remains the only durable authority. It
hashes the public operation key into a fixed mission-bound fingerprint, owns a
canonical ledger plus a bounded active reverse index, and accounts them under a
dedicated quota. Store open migrates the bounded legacy map atomically. The
running node advances a paged audit after readiness and closes new Event
publication if the audit fails. `aster-agent` only validates configuration and
renders the node's sanitized status through additive protobuf fields.

**Tech Stack:** Rust 2024, redb, SHA-256 from `sha2`, Tokio, serde JSON,
Protobuf, ConnectRPC 0.9.0, Buf 1.72.0, generated Go client, Raspberry Pi OS on
CM4 targets.

**Spec:**
`docs/superpowers/specs/2026-09-10-event-operation-ledger-lifecycle-design.md`

## Global Constraints

- Keep the public `operation_key` contract at 1..=256 opaque bytes. Never log,
  return, or persist the raw key, fingerprint, intent digest, transfer ID, or
  backing-store details through the agent API.
- Preserve the existing exact intent digest inputs and public error mapping:
  changed intent is `OPERATION_KEY_CONFLICT`, exact retired retry is
  `MISSING_DURABLE_OBJECT`, and new-key capacity failure is terminal
  `OPERATION_CAPACITY_EXHAUSTED`.
- `aster-agent` remains one executable and `event_service` remains its internal
  module. Do not introduce a second service or database.
- One Event may have at most 64 operation aliases. Retirement work must remain
  bounded and atomic.
- Retired fingerprints are permanent within one mission namespace. Do not add
  deletion, reuse, automatic rollover, online limit increase, or raw-key
  recovery.
- This increment does not add Event retention configuration and does not retire
  accepted-dot, causal-frontier, publisher/Event high-water, Event-sequence,
  State, Record, or Blob lifecycle data.
- Keep existing protobuf field numbers 1..=8 for
  `PublishOperationCapacityStatus`; additions are new fields only.
- Run focused tests with `CARGO_BUILD_JOBS=2` during iteration. Do not use `/tmp`
  for Cargo target data. Run the repository gate only once at final handoff.
- Do not update requirement statuses or replace the v0.1 profile limits until
  retained CM4 evidence and required role reviews support the narrower claim.

## Delivery sequence

Implement this as three dependent reviewable pull requests:

1. **Ledger authority:** Tasks 1 through 5; storage codec, migration,
   publication, retirement, and focused crash/reopen behavior.
2. **Operational surface:** Tasks 6 through 8; background audit, configuration,
   status, generated clients, and operator documentation.
3. **Qualification evidence:** Task 9; load tool, CM4 measurements, retained
   receipt, and evidence-bound profile/roadmap updates.

Do not merge a later pull request before its predecessor. Each pull request is
one coherent outcome and must use `.github/pull_request_template.md`.

---

### Task 1: Isolate the canonical ledger types and codecs

**Files:**

- Create: `crates/aster-redb-store/src/event_operation.rs`
- Modify: `crates/aster-redb-store/src/lib.rs`

**Interfaces:**

```rust
pub const MAX_EVENT_OPERATION_ALIASES: u64 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventOperationLimits {
    max_records: u64,
    max_logical_bytes: u64,
    emergency_reserve: u64,
}

impl EventOperationLimits {
    pub const DEFAULT: Self = Self {
        max_records: 1_000_000,
        max_logical_bytes: 201_326_592,
        emergency_reserve: 10_000,
    };
}

pub(crate) type EventOperationFingerprint = [u8; 32];

pub(crate) enum EventOperationLedgerRecord {
    Active { intent_digest: [u8; 32], transfer_id: EventTransferId },
    Retired { intent_digest: [u8; 32], reason: CustodyRetirementReason },
}
```

The module owns table declarations
`aster.event-operation-ledger.v3` and
`aster.active-operation-by-event.v1`, fixed logical sizes (active ledger 98,
retired ledger 67, reverse row 64), codec functions, fingerprint construction,
and checked capacity arithmetic. Keep `EventOperationKey` public from the crate
root by re-export; its `as_bytes()` remains available only to in-crate hashing
and legacy migration code.

- [ ] Write unit tests first for the exact fingerprint domain encoding,
  operation-key length separation, mission separation, active/retired canonical
  round trips, every malformed version/state/length/reason case, reverse-key
  round trip, and limit validation (`0`, reserve equal/greater than maximum,
  and insufficient bytes for the emergency reserve).
- [ ] Run
  `CARGO_BUILD_JOBS=2 cargo test --locked -p aster-redb-store --lib event_operation::tests`
  and observe the missing module/types.
- [ ] Move only Event-operation types/codecs out of `lib.rs`; keep State,
  Record, Blob, and subscription operation code untouched.
- [ ] Implement the fingerprint as
  `SHA-256(domain || mission_authority || u16_be(len) || raw_key)` and compare
  only fixed arrays after hashing.
- [ ] Make `EventOperationLimits::new` reject invalid combinations and expose
  const getters plus `ordinary_record_limit()` and the derived emergency byte
  reserve (`emergency_reserve * 162`).
- [ ] Re-run
  `CARGO_BUILD_JOBS=2 cargo test --locked -p aster-redb-store --lib event_operation::tests`
  and compile the existing crate test target with
  `CARGO_BUILD_JOBS=2 cargo test --locked -p aster-redb-store --lib --no-run`.
- [ ] Commit as `refactor(store): define Event operation ledger codec`.

### Task 2: Add dedicated ledger accounting without changing publication yet

**Files:**

- Modify: `crates/aster-redb-store/src/event_operation.rs`
- Modify: `crates/aster-redb-store/src/lib.rs`

**Interfaces:**

```rust
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EventOperationStats {
    pub records_total: u64,
    pub records_active: u64,
    pub records_retired: u64,
    pub reverse_rows: u64,
    pub logical_bytes: u64,
}

pub struct Store {
    operation_limits: EventOperationLimits,
}

pub fn open_with_limits_and_operation_limits_for_mission(
    path: impl AsRef<Path>,
    limits: StoreLimits,
    blob_depot_limits: BlobDepotLimits,
    operation_limits: EventOperationLimits,
    mission_authority: NodeId,
) -> Result<Self, StoreError>;
```

Add exact metadata counters for total, active, retired, reverse, and logical
bytes. The sum `active + retired == total`; `reverse == active`; and the logical
byte total must equal `active * (98 + 64) + retired * 67` for schema v3. Older
store-opening functions pass `EventOperationLimits::DEFAULT`.

- [ ] Add failing tests proving empty defaults, invalid custom limits,
  counter overflow/underflow rejection, counter/cardinality mismatch on reopen,
  and that operation rows no longer appear in `AggregateStoreUsage`.
- [ ] Update `Store` construction and every open path to retain validated
  operation limits without breaking source-compatible callers.
- [ ] Separate Event-operation increments/decrements from the helpers enforcing
  `StoreLimits`; retain operation bytes in the store's total state-allocation
  documentation and preflight calculation.
- [ ] Extend `EventStoreStats` with `operation_stats: EventOperationStats`.
  Keep `operations` and `operation_bytes` temporarily as deprecated mirrors so
  node/agent code can move in the operational-surface pull request.
- [ ] Run focused store open/accounting tests, then
  `cargo check --locked -p aster-redb-store -p aster-node -p aster-agent`.
- [ ] Commit as `feat(store): account Event operations under dedicated limits`.

### Task 3: Migrate the bounded legacy operation map atomically

**Files:**

- Modify: `crates/aster-redb-store/src/event_operation.rs`
- Modify: `crates/aster-redb-store/src/lib.rs`
- Modify: `crates/aster-redb-store/src/custody.rs`

**Interfaces:**

Add exact `StoreError` variants for missing migration mission binding or
authenticated intent, fingerprint collision, alias overflow, and destination
capacity. Their `Display` text names only the error class; it includes no keys,
digests, transfer identities, or paths.

The existing raw-key table and witness table become legacy-read-only symbols.
The store-open write transaction detects whether v3 is absent and legacy rows
exist, stages every converted record in memory (at most 4,096), verifies the
entire staged image, writes v3/reverse rows and counters, removes legacy rows,
and commits once. An empty store initializes v3 metadata directly. A partially
present v3 group fails closed; it is never treated as migration input.

- [ ] Add fixtures for current v2 active, lease-withheld, and retired rows;
  witnessed v1 rows; a witnessless v1 row; duplicate aliases; 65 aliases for
  one Event; destination-capacity overflow; a synthetic fingerprint collision
  through a test-only fingerprint seam; partial-v3 schema; and injected abort
  immediately before commit.
- [ ] Assert success produces no raw-key/witness rows, exact v3 counters, and
  the correct active/reverse or retired representation after reopen.
- [ ] Assert each failure returns a typed sanitized store error and leaves the
  complete legacy database byte-for-byte logically readable on reopen—no v3
  schema marker and no removed legacy row.
- [ ] Reconstruct witnessed v1 intent from the authenticated Event metadata,
  stored predecessor, and witness payload digest. Reject witnessless v1 instead
  of accepting unauthenticated sealed bytes or running the prior asynchronous
  upgrade path.
- [ ] Remove the now-obsolete proactive
  `unbound_legacy_event_operations_with_policy` startup flow only after its
  migration tests have equivalent fail-closed coverage.
- [ ] Run only the migration/reopen tests with one test thread.
- [ ] Commit as `feat(store): migrate Event operations to fingerprint ledger`.

### Task 4: Make publication use the v3 ledger and bounded reverse index

**Files:**

- Modify: `crates/aster-redb-store/src/event_operation.rs`
- Modify: `crates/aster-redb-store/src/lib.rs`
- Modify: `crates/aster-node/src/runtime.rs`
- Modify: `crates/aster-node/src/application.rs`

**Behavior:**

- Existing active + same digest returns the original result.
- Existing active + different digest returns `EventOperationConflict` before
  Event load.
- Existing retired + same digest returns the existing retired classification.
- Existing retired + different digest returns `EventOperationConflict`.
- Missing key checks ordinary or tombstone-emergency capacity, then atomically
  writes Event, active ledger, reverse edge, and counters.
- A new alias for an existing Event checks the same capacity plus the 64-alias
  bound; alias 65 has no mutation.

- [ ] Add failing store tests for all four lookup states, indeterminate commit
  replay, restart replay, operation-key mission separation, count and byte
  limits, the last ordinary slot, first rejected ordinary slot, emergency
  tombstone admission, exact retry at exhaustion, and aliases 64/65.
- [ ] Add one node classifier test proving alias and quota failures retain the
  terminal `OperationCapacity` public classification.
- [ ] Replace raw-key lookups with mission-bound fingerprints. Make the ledger
  comparison and Event result resolution occur in one read/write transaction
  wherever it determines an authoritative outcome.
- [ ] Remove v2-only predecessor/payload fields from new durable rows; continue
  computing the unchanged canonical intent digest before reservation.
- [ ] Ensure capacity checks use post-transaction checked arithmetic and reserve
  10,000 records plus `10_000 * 162` logical bytes from ordinary admission.
- [ ] Run the new store tests and existing selected Event exact-retry tests,
  including `finite_retirement_waits_for_lease_and_operation_fence_survives_reopen`.
- [ ] Commit as `feat(store): publish through permanent Event operation ledger`.

### Task 5: Compact active operations inside Event retirement

**Files:**

- Modify: `crates/aster-redb-store/src/event_operation.rs`
- Modify: `crates/aster-redb-store/src/custody.rs`
- Modify: `crates/aster-redb-store/src/lib.rs`
- Modify: `crates/aster-node/src/application.rs`

**Interface:**

```rust
pub(crate) fn retire_event_operations_write(
    write: &redb::WriteTransaction,
    transfer_id: EventTransferId,
    reason: CustodyRetirementReason,
) -> Result<EventOperationRetirementDelta, StoreError>;
```

This helper ranges the reverse key prefix, rejects more than 64 rows, validates
every active ledger target before mutation, rewrites all active rows to compact
retired rows, removes reverse rows, and applies one checked accounting delta.
Call it from `finalize_retirement_write` before Event-only metadata needed for
validation is removed, within the existing custody transaction.

- [ ] Add failing tests for zero, one, and 64 aliases; lease-withheld state;
  malformed/missing/wrong-transfer reverse edges; a retired record with a
  reverse edge; counter corruption; and injected failures before and after
  compaction followed by reopen.
- [ ] Prove retirement changes 162 logical bytes per active alias to 67 bytes,
  makes `reverse_rows` zero for that Event, removes operation-dependent Event
  metadata, and preserves exact-retired versus changed-intent classification.
- [ ] Remove `RetirementBatchIndex`'s full scan of `EVENT_OPERATIONS`; use only
  the transfer-prefix reverse range. Keep delivery and peer indexes unchanged.
- [ ] Keep accepted dots, causal frontier, publisher/Event high-water,
  acceptance markers, and custody retirement fences untouched and explicitly
  assert this boundary in the test.
- [ ] Run focused custody/Event retirement tests and reopen tests.
- [ ] Commit as `feat(store): compact Event operation aliases on retirement`.

### Task 6: Add bounded startup validation and a fail-closed background audit

**Files:**

- Modify: `crates/aster-redb-store/src/event_operation.rs`
- Modify: `crates/aster-redb-store/src/lib.rs`
- Modify: `crates/aster-node/src/runtime.rs`
- Modify: `crates/aster-node/src/application.rs`

**Interfaces:**

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventOperationAuditState { Pending, Running, Complete, Failed }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventOperationAuditStatus {
    pub state: EventOperationAuditState,
    pub scanned: u64,
    pub total: u64,
}

pub struct EventOperationAuditProgress {
    pub scanned: u64,
    pub total: u64,
}

pub fn audit_event_operations<F>(
    &self,
    page_size: usize,
    on_progress: F,
) -> Result<EventOperationAuditProgress, StoreError>
where
    F: FnMut(EventOperationAuditProgress);
```

Startup checks schema completeness, mission binding, counters, cardinalities,
and configured limits without decoding all rows. The selected runtime schedules
one blocking audit worker after readiness. That worker holds one consistent redb
read snapshot, scans pages of at most 1,024 ledger records, and reports progress
to the actor between pages. Each page decodes records, validates active
reverse/Event edges, and proves retired rows have no reverse edge. Records
committed after the snapshot are transactionally validated and belong to the
next audit. Any page error stores `Failed`, closes Event publication admission,
and maps later publication to `StateUnavailable`; reads/status and shutdown
remain available.

- [ ] Add store tests proving one stable read snapshot, 1,024-row progress
  bounds, complete traversal, concurrent post-snapshot publication exclusion,
  and detection of every malformed ledger/reverse relation.
- [ ] Add runtime tests with a small page size proving ready-before-complete,
  actor progress while audit runs, completion after restart, and publication
  closure after injected corruption without exposing the error detail.
- [ ] Keep security/control/mission/startup audits synchronous. Only this new
  high-cardinality ledger receives the paged path.
- [ ] Track audit state in the selected Event actor/status tracker rather than a
  global mutable singleton. Do not reopen or repair the store on failure.
- [ ] Add an offline complete-audit entry point to the existing inspection/tool
  surface and require it after redb unclean recovery in the runbook.
- [ ] Run focused audit/runtime tests with Tokio time paused where applicable.
- [ ] Commit as `feat(node): audit Event operation ledger incrementally`.

### Task 7: Thread operation limits through strict agent configuration

**Files:**

- Modify: `crates/aster-agent/src/config.rs`
- Modify: `crates/aster-node/src/runtime.rs`
- Modify: `crates/aster-agent/tests/customer_runtime.rs`
- Modify: `docs/reference/aster-agent-config-v1.md`

**Configuration:**

```json
"storage": {
  "max_items": 10000,
  "max_payload_bytes": 67108864,
  "operations": {
    "max_records": 1000000,
    "max_logical_bytes": 201326592,
    "emergency_reserve": 10000
  }
}
```

`operations` is required by strict agent config v1; crate-level legacy/default
constructors use `EventOperationLimits::DEFAULT`. `SelectedForwardingConfig`
stores the validated limit and runtime opens the mission store with it.

- [ ] Add config tests for the exact valid object; missing/unknown fields; zero
  values; reserve equal to maximum; arithmetic overflow; insufficient byte
  reserve; and a database whose retained use is already above the configured
  limit.
- [ ] Add `RawOperationStorage`, validate it into `EventOperationLimits`, and
  add `operation_limits()`, `with_operation_limits()`, and constructor/default
  wiring on `SelectedForwardingConfig`.
- [ ] Update all checked-in strict config fixtures. Do not silently default the
  field in `aster-agent`.
- [ ] Prove a customer-runtime process reaches ready state with the selected
  values and that a mismatched lower reopen limit rejects new keys without
  deleting existing records.
- [ ] Run agent config/customer-runtime focused tests.
- [ ] Commit as `feat(agent): configure Event operation ledger limits`.

### Task 8: Expose sanitized capacity, rate, and audit status additively

**Files:**

- Modify: `proto/aster/application/v1alpha1/aster.proto`
- Modify: `proto/aster/application/v1alpha1/aster.fds.bin`
- Modify: `conformance/agent-go/gen/aster/application/v1alpha1/aster.pb.go`
- Modify: `conformance/agent-go/gen/aster/application/v1alpha1/aster.connect.go`
  only if regenerated output changes
- Modify: `crates/aster-node/src/application.rs`
- Modify: `crates/aster-node/src/runtime.rs`
- Modify: `crates/aster-agent/src/event_service.rs`
- Modify: `crates/aster-agent/src/bin/aster-agent-acceptance-fixture.rs`
- Modify: `conformance/agent-go/cmd/agent-smoke/main.go`
- Modify: `conformance/agent-go/cmd/agent-smoke/main_test.go`
- Modify: `docs/quickstart/connect-agent.md`

**Wire additions:** retain fields 1..=8 and append:

```proto
uint64 active_rows = 9;
uint64 retired_rows = 10;
uint64 reverse_rows = 11;
uint64 ordinary_remaining = 12;
uint64 emergency_remaining = 13;
double rolling_accept_rate = 14;
uint64 estimated_seconds_to_exhaustion = 15;
OperationCapacityWarning warning_state = 16;
OperationLedgerAuditStatus audit = 17;
```

Add enums `OPERATION_CAPACITY_WARNING_OK/WARNING/CRITICAL/EXHAUSTED` and
`OPERATION_LEDGER_AUDIT_PENDING/RUNNING/COMPLETE/FAILED`, both with
`UNSPECIFIED = 0`. The nested audit message contains state, scanned, and total.
Populate legacy fields compatibly: `rows=records_total`, `bytes=logical_bytes`,
hard limits use configured limits, `profile_boundary=ordinary_record_limit`,
`profile_remaining=ordinary_remaining`, and booleans derive from the new
warning state.

For status headroom, define `active_row_bytes = 162`,
`ordinary_byte_limit = max_logical_bytes - emergency_reserve * 162`,
`ordinary_remaining = min(ordinary_record_limit - records_total,
(ordinary_byte_limit - logical_bytes) / 162)`, and
`emergency_remaining = min(max_records - records_total,
(max_logical_bytes - logical_bytes) / 162) - ordinary_remaining`, all with
checked construction and saturating observation. Warning/critical occupancy is
the larger of record and logical-byte occupancy against their ordinary limits.

- [ ] Add node tests for empty, mixed active/retired, 70%, 90%, ordinary-full,
  and total-full snapshots plus all audit states.
- [ ] Add a monotonic-window rate tracker in the selected Event actor. Count
  only newly committed operation records, use a 60-second window, report zero
  estimate when the rate is zero/insufficient, and use saturating whole-second
  arithmetic. Exact retries do not affect the rate.
- [ ] Until Event retention is configurable, calculate warning state only from
  occupancy; expose the rate/estimate for operator planning without claiming a
  retention-aware escalation.
- [ ] Extend the protobuf additively, regenerate with pinned local tools, and
  update the Rust fixture and Go smoke assertions.
- [ ] Move node and agent consumers to `EventOperationStats`, then remove the
  temporary `EventStoreStats.operations` and `operation_bytes` mirrors from
  Task 2.
- [ ] Run Event status tests, `go test ./...` inside `conformance/agent-go`,
  `tools/check-agent-proto.sh`, and `tools/check-agent-go-generated.sh`.
- [ ] Update the config reference and Connect quickstart with the new fields,
  thresholds, permanent-key rule, and remediation (new mission or a larger
  prequalified pre-start limit; never delete rows manually).
- [ ] Commit as `feat(agent): report Event operation ledger health`.

### Task 9: Qualify useful Event rates and retain bounded evidence

**Files:**

- Create: `conformance/agent-go/cmd/agent-load/main.go`
- Create: `conformance/agent-go/cmd/agent-load/main_test.go`
- Create: `crates/aster-node/examples/event_operation_ledger_scale.rs`
- Create: `docs/implementation/evidence/selected-event-operation-ledger-cm4-v1.json`
- Create: `docs/decisions/0043-compact-event-operation-ledger.md`
- Modify: `docs/quickstart/linux-event-mvp-runbook.md`
- Modify: `docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md`
- Modify: `docs/implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md`
- Modify: `docs/implementation/capability-roadmap.md`
- Modify: `docs/implementation/requirements-status.md` only where the retained
  evidence changes an exact requirement boundary

The agent load tool accepts endpoint, token source, count or duration, offered
rate, payload bytes, topic/scope, operation-key prefix, and JSON output path. It
uses a monotonic pacer, unique deterministic operation keys, bounded
concurrency, and records accepted/rejected counts plus p50/p95/p99 latency. It
must exercise the public Connect API. The separate Rust example exercises
finite-TTL publication and custody retirement through the selected node API,
because the current agent RPC intentionally exposes no TTL/retention setting.
Store-only or Rust-only scale results are mechanism evidence, not customer
end-to-end retention evidence.

- [ ] Unit-test argument validation, deterministic key generation, percentile
  calculation, rate pacing, terminal-error accounting, and receipt JSON schema.
- [ ] Add a one-million-operation scale mode that periodically retries sampled
  early/middle/late keys and submits changed-intent conflicts without counting
  either as new operations. Put retirement and the final retired-key probes in
  `event_operation_ledger_scale`; keep the agent command on the public no-TTL
  path.
- [ ] Run the approved matrix on CM4 nodes `rpi4-1`, `rpi4-2`, and `rpi4-3`:
  0.2, 1, 5, 10, and 50 Events/s/node; 256 B, 4 KiB, and 64 KiB; local,
  connected two-node, and disconnected/reconnect scenarios. Use one scenario
  at a time and monitor CPU, RSS, disk writes/size, replication lag, convergence,
  restart readiness, and audit duration to avoid IDE/workstation pressure.
- [ ] Run the Rust-node one-million create-and-retire mechanism qualification,
  then probe exact and conflicting retries, last ordinary admission, first
  rejection, emergency tombstone, clean restart, and offline complete audit.
  Record that equivalent customer API retention evidence remains blocked on
  the follow-on Event retention configuration.
- [ ] Bind the retained receipt to commit, binaries, configs, node inventory,
  OS/kernel/redb versions, start/end times, sampler output, hashes, and every
  observed limitation. Do not turn an operator-attested observation into a
  production or mixed-implementation claim.
- [ ] Have lifecycle/capacity, Event-service/node, security, integration/device,
  and release owners review the implemented boundary and evidence. Record role
  and disposition; do not infer approval from green CI.
- [ ] Only after evidence and reviews, add Decision 0043 and update the profile,
  annex, roadmap, and exact requirement rows. Keep Event retention and the
  other causal-ledger lifecycles explicit blockers.
- [ ] Run `python3 tools/check-implementation-requirements.py` because
  traceability changed.
- [ ] Commit as `docs(profile): retain Event operation ledger qualification`.

## Final verification and handoff

- [ ] Run focused malformed-record/fault-path tests and `mise run fuzz-smoke`
  because the new ledger decoder is a persisted hostile-input boundary.
- [ ] Run `cargo fmt --all -- --check` and `git diff --check`.
- [ ] Run `mise run check` once from the project-local worktree with resource
  monitoring; do not launch duplicate repository-wide test processes.
- [ ] Confirm `git status --short` contains only intended files and no test
  secrets, raw operation keys, generated temporary state, or CM4 credentials.
- [ ] Prepare each pull request from `.github/pull_request_template.md`, with
  exact checks, retained evidence links, open lifecycle limits, and role-review
  status.
