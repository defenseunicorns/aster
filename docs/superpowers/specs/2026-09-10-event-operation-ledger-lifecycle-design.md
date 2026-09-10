# Event Operation Ledger Lifecycle Design

- Status: product design approved; implementation and role review pending
- Date: 2026-09-10
- Profile: Linux Event MVP evaluation profile
- Capability: P1-1 causal correctness and bounded data lifecycle, supporting
  the P0 customer-operable Event service

## Purpose

Replace the current small, raw-key Event publish-operation map with a scalable,
permanent, mission-bound ledger. The ledger must preserve exact idempotent
retry and changed-intent conflict detection after Event payload retirement,
while supporting useful post-aggregation telemetry publication rates.

This work precedes rate qualification. Measuring the existing 1,024-operation
profile boundary or 4,096-row implementation ceiling would only measure time to
a known terminal limit: at one Event per second they last about 17 and 68
minutes respectively.

## Scope

This design covers only local Event publication operation keys and their
lifecycle. It includes:

- the unchanged application `operation_key` contract;
- fixed-size internal fingerprints and canonical intent commitments;
- active and retired operation records;
- an active reverse index used during Event retirement;
- dedicated operation capacity and emergency reserve;
- migration of the existing bounded Event-operation schema;
- bounded startup plus background ledger audit;
- authenticated capacity/audit status; and
- correctness, scale, and rate qualification.

The design does not add Event-service retention configuration, implement
accepted-dot/frontier/Event-sequence retirement, change State/Record/Blob
operation mappings, or claim indefinite mission lifetime. Those are separate
lifecycle increments. Event-service retention is the immediate dependency that
will cause active operation records to become compact retired records.

## Required semantics

The public field remains arbitrary bytes with a length of 1 through 256. Its
namespace remains one mission-bound state directory. It names one application
effect, not one RPC attempt, Event identity, timestamp, or retention period.

For one operation key:

| Durable state | Submitted intent | Result |
|---|---|---|
| absent | any valid intent | atomically create the Event and active operation |
| active | exact original intent | return the original durable Event result |
| active | different intent | fail with `Conflict` |
| retired | exact original intent | fail with `ExpiredOrRetired` |
| retired | different intent | fail with `Conflict` |

Exact retries never add ledger records. A retired operation is never removed or
rebound. Capacity exhaustion rejects only previously unseen ordinary keys;
lookups and exact retry classification continue.

The canonical Event publication intent remains the existing digest input:
publisher, topic, scope, priority, logical key, payload digest and length,
tombstone, TTL, and predecessor. Reservation dots, Event sequence, key epoch,
and randomized sealing remain excluded so an exact request can recover its
original result after an indeterminate outcome.

## Operation fingerprint

The store does not retain the caller's raw operation key. It computes:

```text
SHA-256(
  "aster/event-operation-key/v1" ||
  mission_authority ||
  u16_be(operation_key_length) ||
  operation_key
)
```

The mission authority makes copied fingerprints unusable in another mission;
the domain separates Event publication keys from other classes and uses; and
the explicit length makes the encoding canonical. The existing state-directory
mission binding remains authoritative.

This design relies on SHA-256 collision resistance, consistent with Aster's
existing transfer identities. During legacy migration, two distinct raw keys
that produce one fingerprint fail the whole migration before commit.

## Durable data model

Two redb tables replace the raw-key Event-operation table:

```text
EVENT_OPERATION_LEDGER_V3
  key:   operation_fingerprint[32]
  value: version || state || intent_digest[32] || state-specific data

ACTIVE_OPERATION_BY_EVENT_V1
  key:   event_transfer_id[32] || operation_fingerprint[32]
  value: empty
```

The canonical ledger values are:

```text
Active
  version         u8
  state           u8
  intent_digest   [u8; 32]
  transfer_id     [u8; 32]

Retired
  version         u8
  state           u8
  intent_digest   [u8; 32]
  reason          u8
```

Including the 32-byte table key, an active ledger record is 98 logical bytes
and a retired record is 67 logical bytes. An active reverse-index key adds 64
logical bytes until retirement. Backend page, allocator, transaction, and
filesystem amplification are deliberately not included in these logical
figures and must be measured on the CM4 targets.

An active record does not duplicate semantic ID or acceptance marker. The
transfer ID resolves the authoritative live Event. A retired record deliberately
does not retain an Event/result pointer: the supported post-retirement API
result is the typed `ExpiredOrRetired` classification, not replay of the old
success response.

## Publish transaction

Publication computes the fingerprint and intent digest before durable
reservation. The authoritative redb write transaction then performs one ledger
lookup.

For an existing active record, it compares the intent digest before loading the
Event. For an existing retired record, it compares the digest and returns the
retirement classification without opening Event metadata or payload. For a
missing record it:

1. checks dedicated ordinary ledger capacity;
2. reserves one permanent record and the active reverse-index bytes;
3. validates the Event reservation and policy;
4. commits the Event, active ledger record, reverse entry, and accounting in
   the existing atomic Event transaction; and
5. returns only after durable commit.

Binding a new operation key to an already accepted identical Event follows the
same transaction and adds one reverse entry. To bound retirement transaction
work, one Event may have at most 64 distinct active operation aliases. Exact
retries of an existing key do not count as aliases. Alias 65 fails with the
existing nonretryable operation-capacity classification and makes no mutation.

## Retirement transaction

The current sender-invisible, lease-drain phase remains unchanged. While an
Event is marked retiring but retained for a lease, its operation records remain
active; the custody state still causes exact retry to return
`ExpiredOrRetired`.

After the final lease drains, one redb transaction:

1. enumerates the Event's at-most-64 reverse entries;
2. verifies each referenced active record names that exact transfer;
3. replaces every active value with its retired value;
4. removes every reverse entry;
5. removes payload and metadata retained solely for operation replay;
6. updates active, retired, reverse, and logical-byte counters; and
7. commits the existing custody retirement state.

Admission reserves the larger active representation, so conversion to a
smaller retired representation cannot fail for lack of ledger space. Any
invariant or I/O failure aborts the entire transaction. After a crash the store
therefore exposes either the complete pre-retirement representation or the
complete retired fence, never a reusable key.

Operation compaction removes the operation ledger's dependency on retired Event
metadata. It does not authorize deletion of receiver fences, accepted dots,
causal frontiers, or Event-sequence state; their lifecycle remains separate.

## Dedicated capacity

Event operations move out of ordinary `StoreLimits` item/byte accounting and
into a distinct quota:

```text
operations.max_records          = 1_000_000
operations.max_logical_bytes    = 201_326_592  # 192 MiB
operations.emergency_reserve    = 10_000 records
operations.max_aliases_per_event = 64
```

The byte quota includes ledger keys and values plus live reverse-index keys.
It excludes redb/filesystem amplification, which is covered by deployment
preflight and physical evidence. The operation quota remains part of the total
state-allocation calculation even though it no longer consumes ordinary Event
rows.

The one-million-record initial profile supports approximately:

| Local publication rate | Time to one million distinct operations |
|---:|---:|
| 0.2 Events/s | 57.9 days |
| 1 Event/s | 11.6 days |
| 5 Events/s | 2.3 days |
| 10 Events/s | 27.8 hours |
| 50 Events/s | 5.6 hours |

It therefore covers seven days at one Event per second and the initial two-day
target at five Events per second. It is a qualified minimum rather than a
universal customer value. A longer or faster mission must select a larger
validated ledger before mission start or explicitly close the mission and
create a new mission namespace. Automatic rollover, deletion, reuse, and limit
increase are forbidden.

Ordinary operations stop before consuming the 10,000-record emergency reserve.
The logical-byte share for those records is derived with the worst-case active
representation (162 bytes per record), so ordinary admission cannot consume
the bytes needed by the record reserve. Emergency tombstone operations retain
their current reserved-admission behavior. Exact existing-key classification
consumes no reserve and remains available at every capacity state.

## Configuration and status

The validated agent storage configuration gains an `operations` object with
the three configurable quota values. The alias limit is a versioned profile
constant, not an operator tuning knob. Existing store-opening APIs retain
default operation limits; the selected forwarding configuration carries the
validated explicit limits into the mission-bound store.

Authenticated status reports:

```text
records_total
records_active
records_retired
reverse_rows
logical_bytes
record_limit
byte_limit
ordinary_remaining
emergency_remaining
rolling_accept_rate
estimated_seconds_to_exhaustion
warning_state
audit_state
audit_scanned
audit_total
```

Warning state becomes `warning` at 70 percent, `critical` at 90 percent, and
`exhausted` when no new ordinary record fits. It escalates earlier when the
recent accepted-operation rate predicts exhaustion before the configured Event
retention interval. Until the follow-on Event-service retention setting exists,
the node reports the estimate but uses only the fixed occupancy thresholds.
The rolling rate and estimate are operational observations, not durable
authority.

Existing public errors remain sufficient:

- a different intent uses `OPERATION_KEY_CONFLICT`;
- an exact retired retry uses `MISSING_DURABLE_OBJECT` with selected-node cause
  `ExpiredOrRetired`; and
- a new key without capacity, including alias capacity, uses nonretryable
  `OPERATION_CAPACITY_EXHAUSTED`.

No error includes raw keys, fingerprints, intent digests, transfer IDs, paths,
or storage internals.

## Migration

The current schema admits at most 4,096 raw-key rows, so one bounded migration
transaction is sufficient.

On first schema-v3 open, migration:

1. reads every legacy Event operation and witness;
2. reconstructs the exact intent digest from authenticated retained state;
3. computes and collision-checks the new fingerprint;
4. classifies the operation as active, lease-withheld, or retired;
5. creates active plus reverse records for retained Events and retired records
   for Events with a durable retirement receipt;
6. verifies new limits and accounting;
7. records the new schema version and counters;
8. removes the legacy rows; and
9. commits once.

An unbound legacy record without enough authenticated state to reconstruct the
intent fails with a typed migration error. The store is not reset or partially
migrated. Current test and engineering stores remain recoverable when their
existing witnesses are complete; no customer-deployment compatibility claim is
made.

## Startup and audit

Decoding one million records before readiness risks violating the profile's
ten-second start target. Normal startup validates redb open/recovery, schema,
mission binding, transactional counters, table cardinalities, configured
limits, and the existing security/control gates without decoding every retired
ledger entry.

Each record is canonically decoded and validated on lookup. Event retirement
validates its complete bounded reverse set before mutation. A bounded background
audit holds one consistent redb read snapshot, pages through the ledger and live
reverse index after readiness, and reports `pending`, `running`, `complete`, or
`failed` with scanned/total counts. Records committed after that snapshot are
validated by their write transaction and belong to the next audit. Any malformed
value, counter mismatch, bad reverse edge, missing active Event, or retired
record with a reverse entry transitions the node to `StateUnavailable` and
stops new publication.

An explicit offline complete audit is required for release qualification and
after an unclean storage-recovery event. This change applies only to the
high-cardinality operation ledger; existing mission, control, and retained
Event authority checks remain startup gates.

## Verification

Focused correctness tests cover exact and conflicting retry in active,
lease-withheld, and retired states; alias 64/65; dedicated count and byte
capacity; emergency reserve; capacity-time retries; migration success and every
fail-closed case; canonical decoding; counter/index corruption; and faulted
publish, migration, and retirement commits followed by reopen.

Only the new implementation receives performance qualification. CM4 runs use
0.2, 1, 5, 10, and 50 offered Events per second per publishing node with
256-byte, 4-KiB, and 64-KiB payload points. Local publication, connected
two-node replication, and disconnected accumulation/reconnection are measured
separately.

Measurements include accepted rate, errors, publish latency percentiles, CPU,
RSS, disk writes, physical database growth, active/retired ledger bytes,
replication lag, convergence time, restart readiness, and background-audit
duration. A scale run creates and retires one million unique operations, probes
early/middle/late/random exact and conflicting retries, then exercises the last
ordinary admission, first rejected admission, emergency reserve, restart, and
complete audit.

The rate study initially establishes the sustainable curve rather than claiming
an invented throughput threshold. A supported customer rate is the highest
offered rate that completes its declared duration without correctness failure,
unexplained rejection, unbounded queue growth, or profile resource violation.

## Approval and remaining gates

The product owner approved the semantic boundary, fixed-size active/retired
layout, 64-alias transaction bound, one-million-record initial capacity, atomic
migration, bounded startup/background audit, and verification boundary during
the 2026-09-10 design session.

Lifecycle/capacity, Event-service/node, security, integration/device, and
release owners must review the implemented boundary and evidence before it can
replace the current v0.1 profile limits. Event-service retention and the other
grow-only replication/causal ledgers remain explicit follow-on work.
