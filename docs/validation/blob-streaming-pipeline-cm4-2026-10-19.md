# Semantic-v9 Blob streaming pipeline CM4 evidence — 2026-10-19

## Scope and build identity

This evidence covers five measured parts of the unreleased semantic-v9/profile-5 design:

1. the authenticated Blob map/reduce and sequential-pack pipeline on each of the three CM4s; and
2. the complete v9 stream state machine over the selected Iroh transport between two CM4s; and
3. the composed completed-pack network DAG, including incremental record parsing, parallel segment authentication, ordered pack append, durable checkpoint credit, Merkle-root settlement, and half-close;
4. receiver-owned provisional lifecycle reservation, checkpoint projection, signed-finish verification, and atomic inventory promotion; and
5. interrupted cross-process resume from store-authoritative byte progress.

It does **not** qualify production deployment. Later sections retain the
application RPC, CI, and three-device contention requalification that closed
the original evidence gaps without changing an installed service.

All device binaries were cross-built from signed local branch `perf/data-mesh-stream-pipeline`. The relevant signed commits are:

- `cbbfabbe8c2f569c67bf9de06637b6d819244b9e` — stable content-addressed plaintext roots;
- `47d0a11769434e9c7b058bb92796040a00b02295` — end-to-end v9 transfer driver; and
- `7a7f8a4dffb40063524bc2bfdd29eccdf90e684a` — transport-only validation source without synthetic CPU cost;
- `b87954ba` — verified encrypted-pack network DAG;
- `77f0efcb` — terminal half-close synchronization; and
- `e628c767` — device pack-readiness instrumentation;
- `c73e0d7e` — store-authoritative durable resume;
- `1c1b58f3` — cross-process resume measurement;
- `4dcd28a1` — per-device secret isolation for validation; and
- `aa0f47ca` — complete receiver-side stream settlement.

ARM64 artifact identities:

| Artifact | SHA-256 |
| --- | --- |
| Blob pipeline benchmark | `2e7558bfc74f052bf0d3038b403d96201c9b9f574edcd49fd4b1aa627a5bd6e3` |
| v9 network benchmark | `ace6abbdfa91e07238b4ccf8e7cbd3025f033c7634aa2982a0b22e8228714222` |
| encrypted-pack network DAG benchmark | `95f9a116d06fe5ac68d8f586f1ddc62fc50ab72e409e7344498693074189701a` |
| lifecycle/resume network DAG benchmark (`aa0f47ca`) | `5bda5a3a4bcaa690900ccd7d5ffd0db5d3e778cc21426e7fad921addecf5792f` |

## Device inventory

| Device | WLAN | ZeroTier | RAM | Root bytes available before validation |
| --- | --- | --- | ---: | ---: |
| `rpi4-1` | `192.168.60.79/24` | `10.244.155.147/16` | 927,444 KiB | 4,718,387,200 |
| `rpi4-2` | `192.168.60.80/24` | `10.244.158.173/16` | 927,444 KiB | 5,828,931,584 |
| `rpi4-3` | `192.168.60.81/24` | `10.244.219.86/16` | 927,444 KiB | 10,595,069,952 |

All three ran Linux `6.18.39+rpt-rpi-v8` on `aarch64`.

## Local authenticated Blob pipeline

The benchmark reads deterministic plaintext once, maps independent 1 MiB AES-GCM/SHA-256 segments on four fixed workers, restores order through a bounded merge, appends one sequential encrypted pack, checkpoints it, then reads, authenticates, and reduces the pack back through the same bounded pipeline. Each run removes only its exact temporary root afterward.

| Size | Device | Publish MiB/s | Read MiB/s | Peak in-flight bytes | Result |
| ---: | --- | ---: | ---: | ---: | --- |
| 64 MiB | `rpi4-1` | 23.390 | 24.512 | 4,194,824 | pass |
| 64 MiB | `rpi4-2` | 23.703 | 24.739 | 4,194,824 | pass |
| 64 MiB | `rpi4-3` | 25.290 | 26.516 | 4,194,824 | pass |
| 256 MiB | `rpi4-1` | 20.198 | 24.232 | 4,194,824 | pass |
| 256 MiB | `rpi4-2` | 21.941 | 25.189 | 4,194,824 | pass |
| 256 MiB | `rpi4-3` | 22.342 | 26.679 | 4,194,824 | pass |
| 800 MiB | `rpi4-1` | 23.667 | 24.927 | 4,194,824 | pass |
| 800 MiB | `rpi4-2` | 23.744 | 25.134 | 4,194,824 | pass |
| 800 MiB | `rpi4-3` | 24.543 | 26.637 | 4,194,824 | pass |
| 1 GiB | `rpi4-1` | 23.959 | 24.833 | 4,194,824 | pass |
| 1 GiB | `rpi4-2` | 24.209 | 25.138 | 4,194,824 | pass |
| 1 GiB | `rpi4-3` | 25.390 | 26.814 | 4,194,824 | pass |

The three devices produced identical roots for each identical input:

- 64 MiB: `fa07e020b965cd6d8907704a7304146907e5a8e0335c8aee6908097cfb1c99fe`;
- 256 MiB: `6d12fbe42064f7d0e41863b2117f157228b5ab2a945a49d4bddb0140436a1797`;
- 800 MiB: `468f1c1bbcdf471af919c1a38b6434fb35259500241b17db47a7ba7b0c8e0b5e`; and
- 1 GiB: `81f4cbd7babf24a8fe0464ff13ee0d676e7703fb19721cc1db2a5af1a8b33eb0`.

The exact 1 GiB publish-plus-authenticated-read cycle took 78.6–84.0 seconds. Map service dominated sink and reorder service. The processing stage is 2.7–3.1 times faster than the measured same-path raw network baseline below, exceeding the design's 125% isolation threshold.

## Direct WLAN semantic-v9 transfer

The network driver exercised `Open → Accept → Data → Checkpoint → Finish → Result → ResultAck` over one bounded Iroh stream pair. It used 256 KiB extents, an 8 MiB absolute durable-credit window, SHA-256 terminal verification, and no payload-sized allocation.

Endpoints were explicitly bound to WLAN:

- sender: `rpi4-3`, `192.168.60.81`;
- receiver: `rpi4-1`, `192.168.60.79:18191`.

The 64 MiB warm-up transferred at 8.540 MiB/s. A same-address raw TCP transfer of 64 MiB took 7.325 seconds, or 8.737 MiB/s. The v9 driver therefore achieved approximately 97.7% of the available same-path raw throughput.

The exact 1 GiB run produced:

| Role | Elapsed | Throughput | Durable checkpoints | Selected path | SHA-256 |
| --- | ---: | ---: | ---: | --- | --- |
| send | 121.9469 s | 8.397 MiB/s | 128 | Direct | `99cba42a6d9842b5a6c304c4c553be69f95328f15c01e8246b44ec4d9b07c0c8` |
| receive | 121.9537 s | 8.397 MiB/s | 128 | Direct | `99cba42a6d9842b5a6c304c4c553be69f95328f15c01e8246b44ec4d9b07c0c8` |

Interface counters around only this run changed as follows:

| Interface | RX delta | TX delta |
| --- | ---: | ---: |
| `rpi4-1 wlan0` | 1,168,369,510 B | 7,601,829 B |
| `rpi4-1 ZeroTier` | 42,987,591 B | 488,606 B |
| `rpi4-3 wlan0` | 4,107,034 B | 1,136,278,055 B |
| `rpi4-3 ZeroTier` | 12,111 B | 13,307 B |

The payload-sized WLAN deltas, explicit WLAN binds, and `Direct` Iroh witness establish the data path. ZeroTier remained enabled for remote management.

## Composed encrypted-pack network DAG

The completed-pack adapter was then validated from `rpi4-2` to `rpi4-1`. The sender read canonical encrypted segment records directly from its durable pack. The receiver incrementally parsed length-delimited records, authenticated/decrypted them on two fixed workers, restored canonical order, appended the encrypted records to a new pack, synchronized alternating checkpoints, and replenished v9 credit only after each checkpoint. Settlement bound the plaintext and ciphertext Merkle roots.

The endpoints were explicitly bound to WLAN:

- sender: `rpi4-2`, `192.168.60.80`;
- receiver: `rpi4-1`, `192.168.60.79`.

The corrected 64 MiB warm-up produced:

| Role | Wire bytes | Elapsed | Throughput | Segments | Durable checkpoints | Path |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| send | 67,117,440 | 7.9747 s | 8.026 MiB/s | pack source | 8 | Direct |
| receive | 67,117,440 | 7.9708 s | 8.030 MiB/s | 64 | 8 | Direct |

Both roles reported plaintext root `abea1994134339a9c1c2a0b5ff25fa6c4a52d1f756759e3ddc09ad83289b37b9` and ciphertext root `cc9191bdcf6e29fabf9ce93d5f5410758a9bebb89896306b786b0aa4f1c7b80e`.

The exact 1 GiB run produced:

| Role | Wire bytes | Elapsed | Throughput | Segments | Durable checkpoints | Path |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| send | 1,073,879,040 | 138.4877 s | 7.395 MiB/s | pack source | 128 | Direct |
| receive | 1,073,879,040 | 138.4886 s | 7.395 MiB/s | 1,024 | 128 | Direct |

Both roles reported plaintext root `d9de26cb30ee248f1134710adb690d098eca0d29860722d9c31a9bae2852a857` and ciphertext root `73306a8da550d174ea3f69b2cf398b9e72ee8c33e1698bf2f48e40816c34b50d`. This is about 2 minutes 18.5 seconds for the full network operation, compared with the customer's unfinished 107-minute observation.

The fused 1 GiB result is 84.6% of the 8.737 MiB/s same-path raw baseline, above the design's 80% acceptance floor. The isolated CM4 authenticated-pack stages sustain 24.2–26.8 MiB/s, at least 277% of the raw baseline and above the 125% non-transport threshold. On this pair, transport is therefore the measured limiting stage.

Interface counters spanning the 1 GiB run and its control coordination showed payload-scale WLAN changes: `rpi4-2 wlan0` TX increased by 1,159,816,568 bytes and `rpi4-1 wlan0` RX by 1,359,982,687 bytes. Explicit WLAN binds and the `Direct` witnesses establish the data path. The same wider counter interval included ZeroTier SSH/control traffic and unrelated background receive traffic, so its overlay deltas are not used as protocol-throughput evidence.

One warm-up exposed a terminal half-close race: the sender closed its connection after `ResultAck` without waiting for receiver control EOF. Signed commit `77f0efcb` added that wait. The repeated 64 MiB run and exact 1 GiB run both settled cleanly on both roles.

## Network issues observed

The workstation-to-CM4 ZeroTier path has a repeatable MTU/fragmentation symptom: SSH stdin payloads up to 1,024 bytes completed, while 1,200 bytes and larger stalled. HTTP and SCP requests connected but delivered zero body bytes. A bounded 900-byte acknowledged UDP artifact transfer succeeded. This affects deployment/control and is not the measured Aster WLAN path.

After the local three-device matrix, `rpi4-2` continued answering ZeroTier ICMP (92–276 ms in one five-packet sample) but could not complete a small SSH command within 20 seconds. It therefore did not participate in the final network pair. Its local 64 MiB through 1 GiB authenticated pipeline results remain valid.

During the later signed-head validation, rpi4-2 and rpi4-3 had direct `/24` WLAN routes and rpi4-2 reached rpi4-3 with 0% ICMP loss (6.66–10.1 ms), but an Iroh connection to an already listening rpi4-3 endpoint timed out before transfer. The same signed artifact immediately completed on rpi4-2 -> rpi4-1. No network configuration was changed; rpi4-3 fused-path participation remains a separate device/network task.

## Local cross-process durable-resume rehearsal

After receiver lifecycle promotion and durable resume were integrated, the persistent benchmark receiver was exercised across actual process termination on loopback before a new ARM64 deployment. The first 1 GiB attempt was terminated after the receiver had projected byte `604,056,960`. A fresh receiver and sender process reopened the same authenticated fixture, redb authority, and pack directory. Both roles accepted that exact offset, transferred only the remaining `469,822,080` wire bytes (448 segments), reproduced the original plaintext and ciphertext Merkle roots, and exposed exactly one final publication. The resumed suffix ran at 97.849 MiB/s sender and 97.931 MiB/s receiver on loopback.

The benchmark reports `wire_bytes`, `resumed_from`, and `attempt_bytes` separately so a suffix duration cannot be misreported as full-object throughput.

## CM4 lifecycle, resume, and signed-head qualification

The store-owned receiver was then run on rpi4-1 (`192.168.60.79`) with rpi4-2 (`192.168.60.80`) as sender. ZeroTier remained enabled for SSH control only; both Aster endpoints explicitly bound WLAN addresses and reported `Direct`.

An exact 1 GiB attempt was terminated during steady-state transfer. The retained receiver pack was 547,426,702 bytes. Fresh processes reopened the same redb and pack roots, accepted durable wire offset `545,329,200`, and transferred only the remaining `528,549,840` bytes/504 segments with 63 new checkpoints. The receiver completed in 70.854 seconds at 7.114 MiB/s, reproduced plaintext root `d9de26cb30ee248f1134710adb690d098eca0d29860722d9c31a9bae2852a857` and ciphertext root `34d0e5e7484fa82ca38bce797a595b17b3d4687541ef9da3265dc8add930277c`, and atomically exposed exactly one publication.

That run exposed a post-promotion terminal race: the receiver returned after `ResultAck` and closed the QUIC connection before consuming the sender's data FIN. Signed commit `aa0f47ca` changed the terminal order to `ResultAck -> data EOF -> control FIN`; a focused mock-order regression plus all three real runtime Blob tests pass. The fixed ARM64 artifact then settled cleanly in a 64 MiB WLAN run on both roles.

Finally, the exact fixed artifact from `aa0f47ca` transferred a fresh 1 GiB publication from rpi4-2 to rpi4-1:

| Role | Wire bytes | Elapsed | Throughput | Segments | Durable checkpoints | Publications | Path |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| send | 1,073,879,040 | 140.1486 s | 7.307 MiB/s | pack source | 128 | n/a | Direct |
| store receive | 1,073,879,040 | 140.1460 s | 7.308 MiB/s | 1,024 | 128 | 1 | Direct |

Both roles reported the same roots as the resumed run. The receiver pack was 1,073,879,122 bytes, its redb authority was 1,056,768 bytes, and both alternating journals were 6,392 bytes. The sender's temporary source pack self-cleaned after settlement. At 83.6% of the retained 8.737 MiB/s raw WLAN baseline, the signed-head store-owned path passes the 80% end-to-end threshold. The isolated 24.2–26.8 MiB/s processing results remain at least 277% of raw and pass the 125% non-transport threshold.

All temporary binaries, secret test bundles, public Opens, source scratch, and receiver states created for this follow-up were removed from all three CM4s after evidence collection. No installed service or existing Aster state was changed.

## Application RPC integration and exact 1 GiB CM4 validation

The application-facing protocol was then changed from a whole-operation RPC to
bidirectional `Metadata -> Accepted -> Data(offset) -> Checkpoint -> Finish ->
Complete` streaming. The node writes the same independently authenticated
1-MiB segments directly into the store-owned pack, and `ReadBlob` opens those
pack records without decrypt/repackage/re-encrypt staging. The application
protocol now has an explicit 8-GiB object ceiling, 512-KiB RPC frames, a
64-MiB durable checkpoint batch, and a two-partition ordered crypto map stage.
Blob CLI operations automatically request the bounded 15-minute attempt window;
ordinary RPCs retain their 10-second default.

The final ARM64 test artifact was 17,985,400 bytes with SHA-256
`99351b9b834158f6b2e9fa3da1ecb1abe4d268bd2f2948d3ffcb095468f03727`.
It was copied over the existing ZeroTier management path with 900-byte
acknowledged datagrams because large SCP payloads stalled; the hash was checked
on every device before execution. Aster data remained local loopback for this
application-boundary isolation test. No network configuration or installed
service was changed.

All three CM4s published exactly 1 GiB of deterministic bytes, received 16
monotonic durable checkpoints, then streamed and verified every byte through
the public read RPC:

| Device | Publish seconds | Publish MiB/s | Read seconds | Read MiB/s | Total seconds | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `rpi4-1` | 107.989960 | 9.482 | 93.253104 | 10.981 | 201.48 | pass |
| `rpi4-2` | 106.673215 | 9.599 | 89.956990 | 11.383 | 196.89 | pass |
| `rpi4-3` | 105.027791 | 9.750 | 90.271161 | 11.344 | 195.56 | pass |

During steady-state mapping the processes used about 1.68–1.71 CPU cores and
56–64 MiB RSS. The CM4 CPU flags contain no AES or SHA extensions, so the two
independent segment workers are material rather than redundant. Relative to
the original application integration on the same devices (5.24–5.42 MiB/s
publish and 4.52–4.68 MiB/s read), the final minimum rates improved by 80.9%
for publish and 134.5% for read. Both final paths are faster than the retained
8.737-MiB/s raw WLAN baseline, so transport—not application serialization,
durability, or crypto—is the slower stage for the validated route. The earlier
1.5-MiB/s application result is improved by at least 6.3x.

Focused evidence also covers exact completed-operation replay, restart from the
store-authoritative 64-MiB checkpoint frontier, TTL reauthorization between
read pages, legacy-page bounds, CLI frame validation, and the 8-GiB protocol
admission boundary. The full local workspace suite was intentionally not run
because prior attempts were killed by the host OS; focused tests and CI evidence
remain the selected verification boundary.

## Composite source-publish to receiver-promotion validation

A final exact 1-GiB composite run used `rpi4-2` as the source and `rpi4-1` as
the receiver. The source generated the authenticated 1,024-segment encrypted
pack and then sent that same pack through the semantic-v9 completed-pack path.
The receiver authenticated every segment, restored order, synchronized 128
durable checkpoints, verified the final commitment, and atomically exposed one
publication. Both Aster endpoints explicitly bound their WLAN addresses and
reported `Direct`; ZeroTier was used only for test control.

The current-tree ARM64 validation artifact was 10,774,984 bytes with SHA-256
`ae104af73021ff29dc270fe873e1ede3f26e7dffaf6523bfb488bd12fc808cc0`.
This was a local, uncommitted validation build and was not installed as a
service or deployed to production.

| Phase | Elapsed | Throughput/result |
| --- | ---: | --- |
| Source authenticated pack production and connection setup | 99.5462 s | 1,024 segments ready |
| WLAN send | 142.4661 s | 7.189 MiB/s |
| WLAN receive, verify, checkpoint, and promote | 142.4624 s | 7.189 MiB/s |
| Sender start through receiver settlement acknowledgement | **242.0123 s** | **4 min 2.01 s** |

The roles agreed on plaintext root
`d9de26cb30ee248f1134710adb690d098eca0d29860722d9c31a9bae2852a857`
and ciphertext root
`81def18feea4d8c62db14ea2ec42c2bb0dcf5ba0520b5ed4e4b00dd56f1713a5`.
The retained receiver pack was 1,073,879,122 bytes, the redb authority was
1,056,768 bytes, and each alternating checkpoint journal was 6,392 bytes.

The run also exposed a benchmark/integration UX gap, not a requirement for the
wire protocol to coordinate local publication with a destination. The one-shot
validation receiver applies its 30-second accept timer while the combined
sender driver is still spending roughly 78--100 seconds producing its durable
local pack. A naively started validation receiver therefore exits with
`Timeout("accept")` before the sender tries to connect, after which the sender
reports only `Timeout("connect")`. Three zero-byte attempts reproduced this
behavior. Starting the one-shot receiver after the driver's
`ASTER_BLOB_PACK_READY` boundary completed the next attempt.

Operationally, local publication must remain independent: publish and durably
commit locally, then let the sync scheduler open a bounded transfer attempt
only when a destination contact is available or the data is requested. The
destination contact listener is node-lifetime infrastructure; its lifetime is
not the lifetime of one Blob attempt. An unavailable destination therefore
does not delay or fail local publication, and a later attempt resumes from
durable state. The benchmark should model these separate lifecycles and its
errors should identify the expired phase.

This composite measures source authenticated-pack creation through durable
receiver publication promotion. It does not include a receiver application
RPC read; that boundary remains represented by the separate exact 1-GiB RPC
measurements above.

## Readiness requalification: bounded credit and checkpoint cadence

The readiness refactor retained the authenticated 1-MiB canonical segment but
removed a second full-body sender copy, rounded receive credit to complete pack
extents, and raised the maximum completed-pack checkpoint batch from 8 MiB to
128 MiB. The larger batch changes durability cadence, not framing: a peer may
select a smaller accepted batch, and interrupted work remains resumable from
the last receiver-authoritative checkpoint. The cost is a maximum 128-MiB
uncheckpointed replay suffix at the selected maximum. A segment-size sweep is
still required before any alternative to the 1-MiB protocol profile is added.

The uncommitted validation artifact was an ARM64 release binary with SHA-256
`c654b9fe0d7e197ab3252bcc47f139326f975765d134f097adb036c6525f7f0e`.
It was copied over ZeroTier for test control only. Both Aster endpoints were
explicitly bound to WLAN (`192.168.60.80 -> 192.168.60.79`) and reported
`Direct`.

| Size | Aster send/receive | Checkpoints | Raw TCP | Ratio | Result |
| ---: | ---: | ---: | ---: | ---: | --- |
| 256 MiB | 8.317 / 8.318 MiB/s | 2 | 9.561 MiB/s | 87.0% | pass |
| 1 GiB | 8.099 / 8.100 MiB/s | 8 | 9.344 MiB/s | 86.7% | pass |

The exact 1-GiB network phase took 126.445 seconds (2 minutes 6.45 seconds)
for 1,073,879,040 wire bytes. Sender and receiver agreed on plaintext root
`d9de26cb30ee248f1134710adb690d098eca0d29860722d9c31a9bae2852a857`
and ciphertext root
`a160a52680e6256c48e3eaa2717db9c1ebeabe8248cedd9d69a5a16c1a237c56`.
Receiver pipeline occupancy peaked at four items, 4,194,840 bytes, and two
reorder entries. The pipeline reported 146.048 CPU-seconds of map service and
12.596 seconds of sequential sink service across the 126.442-second transfer;
those cumulative stage counters overlap and must not be added to wall time.

The first full-size benchmark attempt failed before networking because the
device's `/tmp` is a 463-MiB tmpfs. Directing the benchmark's temporary pack to
`/var/tmp` exposed the available filesystem capacity and the next attempt
completed. Production pack roots are explicit store-owned paths; this is a
benchmark/device-configuration UX issue, not a protocol dependency.

## Signed-head CM4 requalification

Signed commit `7930633255bec209a71fca4750a87a3261c8f1e7` was rebuilt locally for
ARM64 with the locked dependency graph after the fork's Actions endpoint
reported that Actions were disabled. The build used
`aarch64-linux-gnu-gcc`; no source or dependency substitution was made. The
deployed test-only artifacts were:

| Artifact | SHA-256 |
| --- | --- |
| `asterctl` | `1ebd46b129d4b8125bf5b42c26062f7720b9ad78893a5706872e13525c533abb` |
| Acceptance fixture | `efcabe50b2d4f65f553255926fdaf0fab0161d4136e7794c8c02b18a983ae065` |
| Pipeline benchmark | `887293b749b7db8f68e631528f3ab1a9d10891caa8b6bbf440c1a36902b2ebfb` |
| Transport benchmark | `3765e9044c96fa7b25a8b45284049d03c9ebfac8081b4760e347b7853614162c` |

The conservative two-worker local pipeline completed 1 GiB on every CM4 with
identical root
`81f4cbd7babf24a8fe0464ff13ee0d676e7703fb19721cc1db2a5af1a8b33eb0`:

| Device | Publish | Read | Peak in-flight bytes |
| --- | ---: | ---: | ---: |
| `rpi4-1` | 13.253 MiB/s | 13.576 MiB/s | 2,097,412 |
| `rpi4-2` | 13.256 MiB/s | 13.660 MiB/s | 2,097,412 |
| `rpi4-3` | 13.331 MiB/s | 13.744 MiB/s | 2,097,412 |

The direct WLAN completed-pack path from `rpi4-2` (`192.168.60.80`) to
`rpi4-1` (`192.168.60.79`) produced:

| Size | Aster send/receive | Checkpoints | Adjacent raw TCP | Ratio |
| ---: | ---: | ---: | ---: | ---: |
| 256 MiB | 7.971 / 7.972 MiB/s | 2 | 9.491 MiB/s | 84.0% |
| 800 MiB | 8.194 / 8.194 MiB/s | 7 | 9.425 MiB/s | 86.9% |
| 1 GiB | 8.213 / 8.213 MiB/s | 8 | 9.354 MiB/s | 87.8% |

The exact 1-GiB network phase transferred 1,073,879,040 wire bytes in
124.69 seconds. Both roles reported plaintext root
`d9de26cb30ee248f1134710adb690d098eca0d29860722d9c31a9bae2852a857`,
ciphertext root
`0ad4175dea2dcc894c50be80c7572c5f4182ce7899f3bf272e5b8e719e9cd3d5`,
`Direct`, and one receiver publication. Receiver occupancy peaked at four
items, 4,194,840 bytes, and two reorder entries.

An exact 1-GiB attempt was then terminated after the receiver had retained
652 MiB of provisional state. Fresh processes reopened that authority and
both accepted wire offset `671174400`; only the remaining 402,704,640 bytes
(384 segments, three checkpoints) crossed the network. The resumed attempt
ran at 7.809/7.811 MiB/s, reproduced both final roots, and exposed exactly one
publication.

Two simultaneous 256-MiB sources (`rpi4-2` and `rpi4-3`) then sent to separate
listeners on `rpi4-1`. Both completed with identical roots and one publication
each. Per-flow receive rates were 4.177 and 4.467 MiB/s, a 1.07 fairness ratio,
while aggregate goodput was 8.644 MiB/s. Each receive pipeline remained bounded
to three items and 3,146,130 bytes.

Finally, the exact `asterctl` and acceptance-fixture artifacts exercised the
public loopback API on every CM4: 64-MiB `blob-publish`, `blob-status --wait`,
and `blob-read`. All three status calls reached
`BLOB_PUBLICATION_PHASE_AVAILABLE`; publication and Blob identities matched,
and every read reproduced SHA-256
`281e519df3077b557c6b03f5da83c4e8d397219259615dd7c3308f89cae8f2a6`.

| Device | Publish | Read |
| --- | ---: | ---: |
| `rpi4-1` | 10.891 MiB/s | 9.268 MiB/s |
| `rpi4-2` | 11.718 MiB/s | 9.572 MiB/s |
| `rpi4-3` | 11.742 MiB/s | 9.927 MiB/s |

Large SSH output over the ZeroTier management path stalled again during CLI
help inspection. Keeping the 1,752-byte help output on-device showed exit code
zero, the same SHA-256 on all devices, and all three Blob commands. This is the
previously recorded management-path MTU symptom, not an Aster CLI stall. Aster
payload endpoints remained explicitly bound to WLAN throughout network tests.

The upstream PR checks for this exact signed head completed successfully:
lockfiles, clippy, both Rust test shards, Rust 1.91 MSRV, dependency policy,
age interoperability, bounded fuzz smoke, macOS compatibility, quality, both
path-lab jobs, and the required aggregate check.

## Qualification boundary

This evidence establishes that:

- the independent authenticated Blob pipeline is bounded and fast enough that the tested WLAN is slower;
- the semantic-v9 transport state machine carries 1 GiB at approximately the raw WLAN rate; and
- the composed encrypted-pack receiver remains transport-limited while authenticating, ordering, checkpointing, and settling 1 GiB; and
- receiver lifecycle promotion and process-restart resume use the store-authoritative checkpoint without replaying the durable prefix; and
- the public application Blob stream publishes and reads an exact 1 GiB on all three CM4s above the retained raw WLAN rate with bounded memory; and
- the previous 1.5 MiB/s serial processing path is no longer the limiting design.

It does not qualify production deployment: this branch is still a draft, the
device configuration/network remediation is intentionally separate, and
download resume remains follow-up work. The signed-head implementation itself
now has current three-device local/API evidence, direct-WLAN 1-GiB and durable
resume evidence, concurrent-source contention evidence, and green upstream CI.
