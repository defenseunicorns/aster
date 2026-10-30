# Blob streaming performance evidence

This file records development evidence for semantic v9/profile 5. It is not
device qualification and does not replace the three-CM4 acceptance run.

## 2026-10-16 local loopback ceilings

The merged semantic-v8/profile-4 selected-stack benchmark transferred 64 MiB
at approximately 0.475 MiB/s, reaching receiver readiness in 134.725 seconds.
Linear extrapolation is about 28 minutes for 800 MiB and 36 minutes for 1 GiB.
That result rejects profile 4 for the requested large-object operating range.

Two optimized measurement-only profile-5 ceiling tests were then run:

| Measurement | Bytes | Elapsed | Rate |
| --- | ---: | ---: | ---: |
| Canonical StreamData encode plus decode, 1-MiB bounded extents | 1,073,741,824 | 1.145 s | 894.3 MiB/s |
| Direct loopback Iroh long-lived data stream with concurrent reverse 8-MiB checkpoints | 1,073,741,824 | 2.818 s | 363.4 MiB/s |

The Iroh test sent 1,024 bounded 1-MiB extents and observed the final cumulative
checkpoint on the reverse stream. Resident transfer buffers were independent of
the 1-GiB total. The transport result is roughly 75 times the corrected
profile-4 payload rate and puts the loopback transport-only projection near 2.2
seconds for 800 MiB and 2.8 seconds for 1 GiB.

These are ceilings, not end-to-end claims. They exclude source authentication,
Blob encryption/decryption, carrier verification, lifecycle checks, durable
files/redb checkpoint batches, application promotion, lossy links, and CM4
hardware. The production driver must be measured with those costs before an
operational deadline is claimed.

Reproduction commands:

```text
cargo test --offline --locked --release -p aster-node stream_codec_ceiling_processes_one_gib_in_bounded_extents --lib -- --ignored --nocapture
cargo test --offline --locked --release -p aster-iroh concurrent_stream_ceiling_transfers_one_gib_with_reverse_checkpoints -- --ignored --nocapture
```

The public application-RPC publish/read path has a separate ignored benchmark.
It uses the real node, native bidirectional gRPC upload, durable publication,
and authenticated streaming read; it is not part of default correctness CI.
Run it serially with a release build and place temporary state on a filesystem
large enough for the selected payload and durable overhead:

```text
df -B1 "${TMPDIR:-/tmp}"
/usr/bin/time -v -o /var/tmp/aster-blob-application-rss.txt \
  env ASTER_BLOB_BENCH_BYTES=1073741824 \
  cargo test --offline --locked --release -p aster-agent --all-features \
  --test real_node_connect real_node_blob_bidi_stream_benchmark \
  -- --ignored --exact --nocapture --test-threads=1
df -B1 "${TMPDIR:-/tmp}"
```

For 1 GiB, budget at least 2 GiB of free temporary storage, 2 GiB of available
memory, two CPU cores, and 20 minutes as a conservative timeout. Retain the
binary commit, payload bytes, publish/read elapsed time and MiB/s, checkpoint
count, temporary-filesystem capacity before and after the run, and the GNU
`time` peak-RSS report. This local loopback result
is engineering evidence only; it does not replace same-path raw transport or
CM4 end-to-end qualification.

## Selected-contact measurement fields

Semantic-v9/profile-5 contacts emit bounded measurements in their `CONTACT`
receipt. `blob_stream_sent_bytes` and `blob_stream_received_bytes` are the
canonical pack bytes carried in the current attempt; `blob_stream_resumed_bytes`
is the durable prefix skipped across local send and receive directions.
`blob_stream_checkpoints` and `blob_stream_partitions` count checkpoint
settlement and receiver pipeline completion. `blob_stream_resumed_bytes` is
cumulative across the contact's Profile-5 exchanges: an exact already-present
retry may add the complete wire length while adding zero sent/received bytes.

`blob_stream_pipeline` is a semicolon-delimited value. Its capacity prefix is
`workers`, `peak_items`, `peak_bytes`, and `peak_reorder`. Each subsequent stage
has the form `name:items:bytes:queue_wait_ns:service_ns:output_blocked_ns` for
`admission`, `map`, `reorder`, and `sink`. These cumulative, bounded counters
make a CM4 run attributable without retaining per-partition histories or Blob
identifiers. A sender-only direction has no receiver pipeline samples.

## 2026-10-23 current-tree CM4 selected-node composite

An uncommitted ARM64 release build of the current Profile-5 selected-node
benchmark was run on the inactive `rpi4-3` CM4. The artifact was not installed
as a service. The first runtime-fix artifact matched SHA-256
`e2045d187a4ed28f1c86620a015a5310e6bd716314fcc6b3953891fba9a00104`;
the receipt-instrumented rebuild matched
`3900ca123f77c71a6aaf9a9cab60027043cdb859a8a9b45a6ee8c10bdaaaafc5`
locally and on the device. Runtime code was identical between those builds.
The fixture used two independent node actors and stores on that CM4 with direct
loopback Iroh QUIC. This is complete selected-stack and persistence evidence,
not WLAN or three-device qualification.

The exact 1-GiB source and reopened receiver both produced SHA-256
`f1a2bfc482ceca384b185a6da411a5ae9709058a330a4b43bce318e2403dd4c6`.
The receiver committed 1,024 native 1-MiB segments, retained no pending source
or network staging, and verified all 2,048 application pages after restart.

| Boundary | Elapsed |
| --- | ---: |
| Deterministic source generation and fsync (excluded from benchmark total) | 21.815 s |
| Independent local durable publication | 94.175 s |
| Publication start through first receiver-readable byte | 228.299 s (3 min 48.299 s) |
| Publication start through authenticated contact settlement | 228.378 s |
| Connected-node start through first receiver-readable byte | 119.443 s |
| Connected-node start through contact settlement | 119.522 s |
| Connected-node shutdown | 25.436 s |
| Peerless durable Store reopen/invariant checks | approximately 43.249 s |
| Receiver node restart | 28.714 s |
| Full 2,048-page read and SHA-256 after restart | 49.079 s |
| Harness total, including shutdown/restart validation work | 374.856 s |

The one contact moved 1,073,879,040 wire bytes with eight durable checkpoints,
four receiver map workers, 1,024 completed partitions, and about 8 MiB peak
in-flight pipeline bytes. It remained active for more than 109 seconds and
settled once. The instrumented sample retained two pre-contact connection
timeouts while the second local node was starting; the successful Blob stream
itself did not restart. Its full-length resumed counter came from a later
already-present zero-byte exchange in the same contact, not from skipping the
fresh transfer. The prior runtime-fix sample had zero contact errors and zero
resumed bytes. The previous fixed
30-second outer contact deadline had interrupted the same healthy transfer
three times; the current authenticated-progress watchdog removes that resume
churn while retaining the 30-second no-progress bound, the two-minute
Profile-5 operation-idle bound, and the size-derived hard attempt deadline.

The older run's 143.971-second settled-transfer interval fell to 116.759
seconds in the zero-error sample (18.9% lower); the instrumented sample reached
first visibility in 119.443 seconds despite its pre-contact startup retries.
The older 214.020-second settle-inclusive interval fell to 183.985 seconds in
the zero-error sample (14.0% lower). Operational availability is earlier than
either harness total because the benchmark deliberately shuts down both nodes,
reopens and audits the Store, restarts the receiver, and proves a peerless full
read. The measured publish-to-visible result is 3 minutes 48.299 seconds; the
following full download verification takes 49.079 seconds without network
repair.

## 2026-10-23 current-tree CM4 completed-pack data plane

The current Profile-5 completed-pack path was isolated from publication and
application-read timing on `rpi4-2 -> rpi4-1`. Both endpoints bound WLAN
(`192.168.60.80 -> 192.168.60.79`) and reported `Direct`; ZeroTier carried only
SSH test control. The uncommitted ARM64 device-validation artifact was
8,408,736 bytes with SHA-256
`f4159a69519a83ad026d7214a3589b75e985e20c8127c6ed74f869b710adcf86`.
It used the selected one-MiB authenticated records, a four-worker bounded
receiver map/reorder pipeline, and 128-MiB durable checkpoint batches.

| Plaintext | Send | Receive | Checkpoints | Records | Result |
| ---: | ---: | ---: | ---: | ---: | --- |
| 64 MiB | 8.464 MiB/s | 8.469 MiB/s | 1 | 64 | pass |
| 256 MiB | 9.117 MiB/s | 9.118 MiB/s | 2 | 256 | pass |
| 1 GiB | 8.143 MiB/s | 8.142 MiB/s | 8 | 1,024 | pass |

The exact 1-GiB network phase transferred 1,073,879,040 wire bytes in
125.776 seconds. Both roles reported plaintext root
`d9de26cb30ee248f1134710adb690d098eca0d29860722d9c31a9bae2852a857`
and ciphertext root
`73306a8da550d174ea3f69b2cf398b9e72ee8c33e1698bf2f48e40816c34b50d`,
with zero resumed bytes. An immediately adjacent raw 1-GiB TCP transfer over
the same WLAN addresses sustained 9.215 MiB/s, so the authenticated,
checkpointed Aster data plane achieved 88.4% of available throughput. This is
slightly above the retained 86--88% Profile-5 evidence and rejects the earlier
7.19-MiB/s serial validation result as a benchmark-path regression rather than
a production data-plane regression.

The CM4 `/tmp` mount is a 453-MiB tmpfs, so full-size validation used
`TMPDIR=/var/tmp`. The completed pack self-cleaned after each process exited.
The first manual attempt also confirmed that a 30-second one-shot listener is
shorter than CM4 pack preparation; the validation example now gives its
receiver five minutes while retaining the sender's 30-second connect bound.
Production publication remains peer-independent and production contact
listeners remain node-lifetime infrastructure. This two-device transport
isolation does not complete the pending three-CM4 end-to-end qualification.

## 2026-10-20 mission-record hot-path isolation

An optimized 256-MiB, 1,024-extent measurement of the original profile-5
composition took 7.450 seconds, or 34.362 MiB/s. That rejected composition
mission-encrypted and decrypted every complete 256-KiB StreamData frame even
though each body was already a source-encrypted and independently authenticated
canonical Blob-pack segment. The result identified the outer mission envelope
as a non-transport bottleneck on the local x86 host.

Semantic v9/profile 5 now uses a composite record: the mission layer protects
the fixed canonical StreamData header, while the adjacent canonical pack
segment retains its existing end-to-end source AEAD. After aligning each
StreamData extent with one complete canonical pack record, the same optimized
256-MiB sender-encode plus receiver-decode measurement used 256 extents and
completed in 0.014036 seconds, or 18,238.555 MiB/s. This is approximately 531
times the rejected full-envelope rate and includes bounded frame construction
and receiver body materialization. The aligned boundary also removes sender
slicing and receiver reassembly from the integrated path. This establishes only
that profile-5 record processing is no
longer the local throughput ceiling; it excludes transport, pack I/O, source
segment verification, checkpoints, and CM4 effects.

Reproduction command:

```text
cargo test --release -p aster-node composite_profile5_records_process_256_mib_in_bounded_extents --lib -- --ignored --nocapture
```

## Open qualification: extent batching policy

<!-- ASTER-BLOB-CAPABILITY:BEGIN -->
```json
{
  "schema": 1,
  "surface": "performance",
  "historical_2026_10_20_format": "ASTRBS02_1MiB_semantic_segments",
  "historical_2026_10_20_supports_architecture": true,
  "historical_2026_10_20_qualifies_current_commit": false,
  "current_map_unit": "1048576-byte native plaintext segment",
  "current_record": "ASTRBS02, at most 1048706 bytes",
  "current_data_body": "length-prefixed record, at most 1048710 bytes",
  "current_cm4_qualification": "pending_task_13"
}
```
<!-- ASTER-BLOB-CAPABILITY:RENDERED -->
The 2026-10-20 ASTRBS02 measurements validate the native-pack architecture but not the current commit. Current qualification must measure 1,048,576-byte plaintext segments, ASTRBS02 records of at most 1,048,706 bytes, and length-prefixed DATA bodies of at most 1,048,710 bytes; three-CM4 qualification remains Task 13 work.
<!-- ASTER-BLOB-CAPABILITY:END -->

The remediated profile uses a 1-MiB native plaintext segment and an encoded
`ASTRBS02` record of at most 1,048,706 bytes. The data lane adds only the
four-byte record length; it does not build an intermediate carrier batch.

Task 13 must establish the current candidate's end-to-end throughput and
latency, CPU, peak RSS and
in-flight bytes, checkpoint cost, retransmitted bytes, resume amplification,
and behavior under loss and constrained MTU. No result below supports the
current batching choice.

<!-- ASTER-BLOB-LEGACY:BEGIN -->
## Legacy evidence — 2026-10-20 CM4 completed-pack requalification

Legacy 2026-10-20 ASTRBS02 completed-pack evidence used 1-MiB semantic segments
and does not validate the current canonical-authority candidate. This entire
dated section retains the measured candidate's original terminology and claim
boundary.

The legacy ASTRBS02 completed-pack sender wrote the small protected record
prefix and the owned 1-MiB semantic pack body as one carrier frame without
first copying the body into a second payload-sized allocation. Its receiver's
absolute-credit window rounded up to a whole pack record. That rule fixed the
legacy deadlock where an exact byte window admitted too few slightly-over-1-MiB
pack records to reach the next checkpoint.

In that candidate, checkpoint batching was independent of its 1-MiB
authenticated semantic segment. Larger batches reduced synchronization and
reverse-control overhead but increased the maximum uncheckpointed suffix that
an interrupted attempt could replay.

Successive 256-MiB CM4 runs on `rpi4-2 -> rpi4-1` showed:

| Candidate | Checkpoints | Aster MiB/s | Adjacent raw MiB/s | Raw ratio |
| --- | ---: | ---: | ---: | ---: |
| 8-MiB batch, instrumented pipeline | 32 | 6.147 | 9.400 | 65.4% |
| 64-MiB batch and split-frame sender | 4 | 7.376 | 9.400 retained sample | 78.5% |
| 128-MiB batch and split-frame sender | 2 | 8.317 | 9.561 | 87.0% |

These are integrated legacy-candidate measurements, not an isolated
single-variable benchmark; they do not attribute all gain to checkpoint
cadence. The exact 1-GiB confirmation transferred 1,073,879,040
wire bytes in 126.445 seconds at 8.099 MiB/s, with eight checkpoints and
matching terminal roots. The immediately adjacent 1-GiB raw TCP run sustained
9.344 MiB/s, so the integrated path achieved 86.7% of available throughput and
passed the 80% floor. Receiver occupancy remained bounded at four items and
4,194,840 bytes.

This legacy requalification supported only the measured ASTRBS02 completed-pack
candidate. It supplies no evidence for later candidates.
<!-- ASTER-BLOB-LEGACY:END -->
