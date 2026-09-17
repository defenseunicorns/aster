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

Observation changes timing and the rebuilt instrumented binary is not identical
to the stock CI artifact. Interpret one run as a bounded measurement of this
commit and runner, not proof of general performance or causality.

## Traceability

This is CI validation tooling outside the product capability register. It does
not change product source, wire/API/storage contracts, the dependency graph, or
requirements evidence. If a later change modifies the test source or any bound
context, update and review the manifest hashes before another manual run.
