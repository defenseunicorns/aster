# Manual runtime-volume validation harness

**Diagnostic only; not qualification.**

This harness instruments one existing `aster-lab` integration test and records
bounded numeric telemetry for its 10,000-frame bidirectional workload. It is a
manual tool for investigating runtime volume, queueing, backpressure, durable
arrival, phase timing, and process resource use. A result does not qualify a
release, satisfy an atomic requirement, or establish a root cause by itself.

The harness is deliberately absent from routine verification. Its workflow has
only `workflow_dispatch` and `workflow_call` entry points. The temporary caller
in `ci.yml` is guarded to a manual dispatch of the
`ci-runtime-volume-diagnostic` branch and is not part of the `required` job.

## Run it on the feature branch

Until this workflow exists on the default branch, dispatch the already-registered
CI workflow at the feature branch:

```console
gh workflow run ci.yml --ref ci-runtime-volume-diagnostic
```

The caller runs the reusable diagnostic only when both conditions hold:

- the event is `workflow_dispatch`;
- the exact ref is `refs/heads/ci-runtime-volume-diagnostic`.

Pushes, pull requests, merge queues, schedules, and ordinary verification do not
run it. Keep the PR open while evaluating the initial telemetry; this document
does not authorize merging it.

## What is bound and executed

The workflow checks out `${{ github.sha }}` and passes that value as
`EXPECTED_SOURCE_SHA`. Both preflight and the driver verify that the checkout's
Git HEAD matches it. The manifest also binds the current lockfile, workspace
manifest, toolchain declaration, resource wrapper, dependency policy, original
test source, and additive telemetry patch by SHA-256.

Rust 1.97.1 is installed through the same `rustup toolchain install` route used
by current CI, then the locked graph is fetched once. The driver applies the
telemetry patch only in the disposable runner checkout, builds the exact
workspace test executable offline, selects exactly one `aster_lab` library test
binary from Cargo JSON, and executes only:

`mesh_experiment::libp2p_candidate::two_persistent_swarms_drive_ten_thousand_runtime_frames_each_way`

There is no retry path. Dependency-policy qualification remains the responsibility
of normal CI; this diagnostic neither repeats nor claims that gate.

## Evidence and safety boundary

Raw compiler and test output stays in runner-private scratch. The uploaded
artifact contains only bounded JSON receipts and allowlisted numeric telemetry.
The controller caps captured output at 16 MiB, individual lines at 64 KiB,
numeric tokens at 20 digits, and retained telemetry at 160 records. It samples
RSS, high-water RSS, threads, CPU ticks, and aggregate process I/O without
retaining command lines, environments, payloads, peer identities, or paths.

The process supervisor launches each child in its own process group, enforces
separate build/test deadlines, and follows TERM with KILL before parsing or
publishing evidence. Successful execution requires the complete group to be
absent, the exact test to report one pass, and a final telemetry record.

The additive patch preserves the workload and assertions while emitting:

- phase and progress timestamps;
- 22 bounded counters covering accepted, submitted, sent, received, consumed,
  queue occupancy, available credit, high-water, backpressure, stream count, and
  selected stream direction observations;
- four durable-arrival counters;
- five timing distributions represented as count/sum/max nanoseconds;
- a measured observation-overhead counter.

## Telemetry dictionary and observation limits

`telemetry.json` is an ordered array of sanitized records. Records with `kind`
set to `phase`, `progress`, `complete_predicate`, or `final` contain the timing
fields and fixed arrays below. Separate records may contain `observation_ns` or
the allowlisted Rust test-harness summary.

`counters` is a fixed 22-value array:

| Indices | Meaning |
| --- | --- |
| 0–4 | A→C: runtime accepted, provider submitted, sent, peer received, runtime consumed |
| 5–9 | C→A: runtime accepted, provider submitted, sent, peer received, runtime consumed |
| 10–11 | A/C runtime-to-provider queue occupancy |
| 12–13 | A/C provider submission credit: 1024 minus submitted−sent |
| 14–15 | A/C outbound queue high-water |
| 16–17 | A/C full-queue backpressure count |
| 18–19 | A/C opened stream count |
| 20–21 | A/C selected stream role: 1 outbound, 0 inbound (not key/peer material) |

The provider-to-runtime backlog is received minus consumed at each destination;
accepted minus submitted is the runtime-to-provider boundary gap. Neither raw
frames nor a backlog estimate proves unique-item progress or packet loss.
`durable` contains C-first/C-second at A, then A-first/A-second at C. Values:
0 not sampled, 1 absent, 2 present, 3 query error. Observational queries discard
error text and do not introduce earlier error propagation. They run only at the
existing 10-second progress point; the original short-circuited completion
predicate is unchanged. On predicate completion all four are recorded present
because that exact original predicate has just succeeded.

`costs` has five `[count, sum_ns, max_ns]` rows: A drive, C drive, A flush,
C flush, and combined select/service wait. Select cost includes waiting, chosen
handler execution, and timer branches; it is **not per-adapter CPU attribution**.
`outer_ms` includes setup, the original timeout, and final cleanup; subtract
`loop_started_ms` only after the volume phase begins. Phase records delimit
the exact `prepare`, `supervisors`, `adapters`, `listen`, `connect`, `contacts`,
`activation`, `volume`, `resource_oracles`, and `cleanup` milestones.
`sampled_ms` and `durable_sampled_ms` explicitly expose stale samples. Counters
are refreshed at loop boundaries, not synchronously on every frame.

An outer RAII guard emits last-known state on ordinary success/error, cooperative
Tokio timeout, and unwind. On synchronous stalls or forced termination, that guard
may not run: the supervising process retains last-known counters and process
CPU/RSS/I/O sampled during execution. Parsing and receipt creation happen only
after termination; the resource sample remains last-known, not a new pre-kill
measurement. Unknown or stale state is never relabeled as fresh. At most 64
regular diagnostic snapshots plus one final snapshot, bounded observation-cost
records, and 160 sanitized output records are retained. `/proc` samples are
five-second, finite-budget process snapshots, not full-runner load.

Each combined stdout/stderr capture is limited to **16 MiB**, read through a
nonblocking pipe in at-most-64-KiB turns, with bounded draining during cleanup.
Only captured bytes are hashed and written privately after termination. Parsing
is incremental over that bounded capture: **64 KiB per line**, **20 digits per
telemetry numeric token**, and **160 retained telemetry records**, including an
explicit failure marker if the record budget is exceeded. Raw/Cargo overflow is
never accepted as successful truncation, even if a matching artifact appears
earlier. These are conservative diagnostic budgets, not claims that every
compiler output will fit. No full-log `splitlines` or uncapped raw-file read is
used. Receipt-write failure can prevent the receipt itself; it cannot prevent
termination/reaping, and the returned controller result remains failure.

Observation changes timing: thread-local numeric snapshots occur twice per loop;
`Instant` reads surround four synchronous operations and one select; four
read-only durable queries and output occur at existing progress points.
`observation_ns` measures the additional periodic queries/output, not all
per-loop bookkeeping. The rebuilt instrumented binary is not identical to the
stock CI artifact. Interpret one run as a bounded measurement of this commit and
runner, not proof of general performance, causality, zero overhead, or equivalence
to the original CI binary.

## Traceability

This is CI validation tooling outside the product capability register. It does
not change product source, wire/API/storage contracts, the dependency graph, or
requirements evidence. If a later change modifies the test source or any bound
context, update and review the manifest hashes before another manual run.
