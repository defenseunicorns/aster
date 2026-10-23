# Selected-node Blob streaming measurement

This diagnostic measures the selected-node Blob path on one host: independent
local publication, semantic-v9/profile-5 synchronization, durable receiver
promotion, restart, and full paged plaintext verification. It adds no
requirements credit, WAN qualification, or production throughput guarantee.

## Reproduce

Build the identical `crates/aster-node/examples/blob_benchmark.rs` in separate
baseline and feature checkouts with separate Cargo targets:

```sh
CARGO_NET_OFFLINE=true mise exec -- sh tools/with-test-resources.sh \
  cargo build --release --offline --locked -p aster-node --example blob_benchmark
python3 tools/test_blob_benchmark.py
python3 tools/blob_benchmark.py \
  --variant baseline /absolute/baseline /absolute/baseline-binary \
  --variant stream /absolute/feature /absolute/feature-binary \
  --output /durable/new-results --state /scratch/new-state
```

The default campaign is exactly one run per variant at 16 KiB, 64 KiB, 256
KiB, and 1 MiB: eight real runs, alternating baseline then feature at each
size. A 300-second receive bound applies per run, plus an outer 180-second
allowance. `--sizes` restricts the selected campaign without adding
repetitions. Finish all builds and tests before timing; do not edit measured
sources during the campaign. The selected campaign name is retained in
`metadata.json` together with the exact cases and source/binary identities.

Select the explicit 100 MiB scale campaign with:

```sh
python3 tools/blob_benchmark.py \
  --campaign scale \
  --variant baseline /absolute/baseline /absolute/baseline-binary \
  --variant stream /absolute/feature /absolute/feature-binary \
  --output /durable/new-scale-results --state /scratch/new-scale-state
```

Semantic v9/profile 5 admits up to 8 GiB. Semantic v7/v8 compatibility profile
4 remains limited to 64 MiB; profile 5 never downgrades an active attempt into
profile 4.

Run the explicit 1-GiB profile-5 campaign only on a prepared engineering host:

```sh
python3 tools/blob_benchmark.py \
  --campaign profile5-1g \
  --variant candidate /absolute/repo /absolute/blob_benchmark \
  --output /durable/new-profile5-1g-results \
  --state /scratch/new-profile5-1g-state
```

This campaign has one 1-GiB sample and a 900-second internal reconciliation
deadline. The runner adds 180 seconds for controlled process teardown. Budget
at least 4 GiB of disposable state space plus operational reserve.

The core streaming pipeline retains its original generated 101 MiB + 123 byte
workload as an ignored qualification test. Run only that workload explicitly:

```sh
mise run qualify-generated-blob
```

On the retained hosted baseline the original default form took about 91
seconds. For the explicit qualification, budget five warm minutes, two CPU
cores, at least 2 GiB of available memory, and at least 1 GiB of temporary
disk; cold compilation and dependency download are separate. Nextest writes
terminal output, while the test uses an isolated temporary fixture and removes
it after success. Capture the command output and machine/resource metadata in
the validation record if the result will support an engineering decision.

The default correctness test uses eight full 64 KiB chunks plus a partial
chunk. It still proves seven-chunk interruption, bounded buffers, exact resume,
deduplication, manifest and full-content verification, tail and cross-chunk
ranges, and tamper rejection without allocating a production-scale fixture.

The selected runtime also retains a local valid-Blob fixture one byte above the
64 MiB network-admission limit. Run that allocation-heavy boundary explicitly:

```sh
mise run qualify-local-blob-above-network-limit
```

Budget two warm minutes, two CPU cores, 1 GiB of available memory, and 1 GiB of
temporary disk. The test proves that a valid local Blob remains readable while
network admission rejects its size; it does not transfer the Blob or provide
throughput, device, or production qualification.

The separate `--campaign scale` benchmark runs real 100 MiB cases for both
provided variants. Allow the per-run 300-second receive bound plus the runner's
outer allowance, at least 4 GiB of memory, and enough scratch/output capacity
for both binaries, state directories, logs, and receipts (4 GiB free is a
practical minimum). Raw stdout/stderr and fsynced receipts are stored beneath
the `--output` directory; mutable stores live beneath `--state`. The ignored
pipeline qualification and the scale campaign are non-default engineering
evidence. They add no requirements credit and are not production or device
qualification unless their exact artifacts are admitted through the retained
validation process.

## Timing and verification boundaries

- Two real node actors in one process, two Tokio workers, independent stores,
  synthetic reference identities, and explicit direct-loopback Iroh addresses.
  Production `NodeConfig` defaults retain the 500 ms scheduler interval.
- Deterministic SplitMix64-counter fixture generation makes aligned 64-KiB
  chunks distinct, avoiding a repeating-data deduplication bias. Source file
  generation, SHA-256, and fsync precede publication.
- `publication_ns` brackets awaited peerless local file publication. Successful
  publication means local durable acceptance, not remote delivery.
- `transfer_until_visible_ns` brackets connected-node startup through the first
  successful receiver read, polled every 20 ms. It excludes publication.
- `transfer_until_ready_ns` extends that interval through terminal authenticated
  contact accounting. It is the settled-contact boundary, not first visibility.
- `publish_to_visible_ns` and `publish_to_settled_ns` start before local
  publication and include the peerless-to-connected node transition.
- `connected_shutdown_ns` isolates both connected-node shutdowns.
  `durable_inspection_ns` isolates the following peerless Store reopen and
  invariant/statistics checks. `transfer_ns` includes startup, synchronization,
  settlement, both shutdowns, and that inspection; it is not pure network time.
- `restart_ns` isolates receiver restart. `download_verification_ns` isolates
  the full paged plaintext read and SHA-256 after that restart.
  `verification_ns` is their combined interval. Every page's identity,
  publisher, length, and offset is checked; no network repair is possible.
- `total_ns` spans publication through full verification, including intermediate
  shutdown, but excludes fixture setup and final verification-node shutdown.
- Successful runs require only direct authenticated terminal contacts, no
  pending source, no residual carrier prefix or staging bytes, and exact final
  full plaintext SHA-256. Historical failed attempts remain explicit in
  receipts; a later authenticated resume may complete the run. Timeouts remain
  incomplete observations, never throughput.

The runner persists each stdout/stderr and fsynced JSON receipt immediately.
It records read-only AC/battery/profile/governor snapshots before and after
individual runs. Source and binary identities must remain unchanged before
normal summaries are published; mismatch retains raw evidence without summary.
Inspect power stability before comparing samples. Default release builds use
`opt-level=z`, thin LTO, and one codegen unit. Normal OS caches and desktop load
remain; neither idle-host nor cold-cache conditions are claimed.

Report local publication, synchronization readiness, settle-inclusive transfer,
and verification separately. One sample is an observation, not a distribution.
The harness's unit tests use explicitly synthetic subprocess receipts solely to
test summary validation; these are not performance measurements.
