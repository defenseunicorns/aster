# Proposal 0003 result: no provider selected; refactor node ownership first


- Status: completed by the proposal's mandatory Phase-1 stop rule — **none
  selected**
- Date: 2026-08-21
- Proposal:
  [0003 — Idiomatic IP mesh provider comparison](0003-idiomatic-ip-mesh-provider-comparison.md)
- Survey baseline: `56ea19d89e537a351ceded446c2d38f5313d118b`
- Signed experiment checkpoint:
  `15f99c37c7310ba7d8f6a3a2f927d7b1a8ddfe2c`
- Evidence-controller checkpoints:
  `7b38caec31127cebe827a32c9bd120bcd1bf30f5` and
  `ae2944b39d87f212f313eb578f25de4f6596a393`
- Requirements baseline:
  [`data-mesh-requirements.md`](../../data-mesh-requirements.md), SHA-256
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Activation record:
  [Proposal 0003 Phase 0](0003-idiomatic-ip-mesh-provider-activation.md)
- Follow-on experiment:
  [Proposal 0004](0004-shared-node-libp2p-retest.md)
- Decision:
  [0024 — Refactor durable node ownership before selecting an IP provider](../decisions/0024-refactor-durable-node-ownership-before-ip-provider-selection.md)
  — preserve Decisions
  [0022](../decisions/0022-ip-mesh-experiment-no-selection.md) and
  [0023](../decisions/0023-mesh-host-contract-no-libp2p-selection.md); select
  **none**

## Outcome

No candidate is ready to become Aster's production IP mesh provider.

This is not primarily a result about UDP versus Iroh versus rust-libp2p. The
independent Phase-1 architecture review found the same non-compensable defects
in all three adapters:

1. every carrier contact constructs a complete durable runtime backend before
   Aster authentication completes;
2. concurrent contacts independently open the same SQLite node and Blob store,
   so there is no single owner for durable state, security-control freshness, or
   process-wide Blob quota; and
3. carrier buffers are bounded per contact but not by one node-global resource
   budget.

Those defects fail Proposal 0003 before provider resource or convenience gains
can matter. A carrier-authenticated hostile peer can cause SQLite open, control
replay, and Blob-store scanning before it has an authenticated Aster identity.
Multiple live backends can retain different revocation, rekey, bridge, and
control views. `FileBlobStore` usage counters are instance-local, so concurrent
instances can each admit work against a stale view of the same quota.

The inbound carrier allowance is 8 MiB per contact. At the default eight active
contacts that alone can reserve 64 MiB; at the hard limit of 256 it can reserve
2 GiB, before outbound queues, runtime state, or provider overhead. This is a
per-contact bound, not an aggregate bound capable of demonstrating the Tier-2
node target.

The correct next step is therefore a shared architecture change: one process
owns one durable Aster node/backend and one Blob store, while contacts own only
bounded session and carrier state. Only after that boundary passes Phase 1
should the project resume provider downselection.

## Provider-specific disposition

### Native control

Native remains the strongest technical LAN control. It is the smallest graph
and binary, used the least traffic and memory in the matched manual cohort,
observed a 1 KiB item much sooner, and was the only arm to complete the retained
64 KiB and 1 MiB payload probes.

It is not selected as a complete mesh. The experiment did not compose or accept
controlled NAT traversal, a connectivity relay, relay-loss recovery, or
address-change recovery. Its contact opens the durable driver and Blob store
before starting the Aster pre-authentication deadline, and it shares the same
per-contact backend and global-budget defects as the upstream arms.

### rust-libp2p

rust-libp2p is the leading **future connectivity candidate**, not the selected
provider. The protected profile used one persistent Swarm, TCP/Noise/Yamux,
connection limits, and one generic `libp2p-stream` substream carrying many
Aster frames. Request/response was absent. Its real carrier test moved at least
10,000 `RuntimeDriver` frames over exactly one substream, and the archived
trial-14 backpressure regression passed.

Among the upstream candidates, libp2p produced the smaller binary and active
package graph and used less memory and carrier traffic in the matched 10/10
manual cohort. Its automatic protected-discovery cohort also completed 10/10.

The experiment intentionally stopped before calling this a full idiomatic mesh
integration. The implemented Swarm behaviour contains the Aster stream and
connection limits, with optional mDNS; it does not compose or exercise
Identify, AutoNAT, circuit-relay, or DCUtR. Merely compiling relay and DCUtR
crates is not evidence for those paths. The generic stream dependency is still
`libp2p-stream 0.4.0-alpha`, and the protected graph still reaches unmaintained
`paste 1.0.15`.

### Iroh

Iroh used one persistent minimal endpoint, one Aster ALPN, and one long-lived
QUIC bidirectional stream. Public discovery and relay defaults were disabled.
Its real carrier test also moved at least 10,000 `RuntimeDriver` frames on one
stream.

It has three additional blockers beyond the shared lifecycle problem:

- Iroh 1.0.3 constructs noq's pre-`Incoming` pool before the public
  per-incoming override can apply. The retained profile reports the upstream
  defaults as 65,536 entries and about 100 MiB aggregate buffering, with no
  public bind-time seam to lower them.
- endpoint path-change events are not integrated, so the adapter cannot prove
  fresh Aster authentication after a path or address change; and
- Iroh and its support crates require Rust 1.91 while the workspace promises
  Rust 1.90.

A fresh isolated live-chain rerun also failed after admission: B authenticated
and admitted both A and C, then exited 1 with `connection lost`. The earlier
isolated seed replay passed, so this is a separate unresolved connection-
lifecycle result rather than the concurrent-load artifact described below.

Iroh is also substantially larger than libp2p in this profile. Reconsider it
only after there is an upstream/configurable pre-`Incoming` bound, an explicit
path-event-to-fresh-auth lifecycle, and an MSRV disposition.

## Functional characterization

Because no arm survived Phase 1, the following are bounded technical results,
not Phase-2 acceptance. Automatic runs used Aster's bounded protected discovery,
not provider-native mDNS. “Aster custody chain” means durable A→B→C application
relay; it is not an Iroh or libp2p connectivity relay.

| Lane | Native | Iroh protected | libp2p protected |
|---|---:|---:|---:|
| Real persistent carrier, 10,000 Aster runtime frames | Not a stream-arm requirement | Pass, one QUIC bidi stream | Pass, one generic substream |
| Manual 1 KiB A→B | 10/10 | 10/10 | 10/10 |
| Automatic protected discovery, durable A→B→C restart/ack path | 5 retained passes; interrupted next seed passed isolated | interrupted first cohort seed passed isolated | 10/10 clean rerun |
| Receive-only authorized inbound, no automatic candidates | 3/3 | 3/3 | 3/3 |
| Live Aster custody chain | 3/3 | retained pass and interrupted-seed isolated pass; fresh isolated rerun failed after B admitted A+C (`connection lost`) | 3/3 |
| 1 KiB capture trial with exact custody, ack, and duplicate suppression | 1/1 | 1/1 | 1/1 |
| Manual 64 KiB exact-item observation | 1/1 | Fail | Fail |
| Manual 1 MiB exact-item observation | 1/1 | Stopped after 64 KiB failure | Stopped after 64 KiB failure |

No arm completed the proposal's 30/30 clean cohort, 100-candidate provider
fairness cohort, or a provider-native discovery acceptance lane. The bounded
protected-discovery source did suppress automatic announcements in constrained
and receive-only modes; the provider-native mDNS profiles remained technical
only because their state grows before `MeshHost` can apply its cap. Libp2p mDNS
also activates the blocked Hickory 0.25.2 graph.

### Concurrent-run diagnostics

Several first-pass cohorts ran concurrently on the same Docker host. They
contained early process exits or missing terminal receipts for native, Iroh,
and libp2p. The controller now preserves those failures and process results
instead of deleting the containers before recording the exit status.

The exact flagged seeds passed when replayed in isolation, including native
primary seed 10006 and manual seed 10003, Iroh primary seed 10001 and live-chain
seed 10002, and libp2p primary seed 10004 and live-chain seed 10001. The original
failures were therefore non-deterministic and are retained as concurrent-run
diagnostics that cannot be attributed to one provider from this evidence. An
isolated pass neither proves Docker/controller causation nor excludes provider
load sensitivity, and it does not turn an incomplete cohort into acceptance.

The fresh isolated Iroh live-chain rerun is not in that classification. B had
authenticated and admitted A and C before exiting 1 with `connection lost`; it
remains an Iroh lifecycle failure.

The isolated 64 KiB upstream failures are different. Both Iroh and libp2p
repeatedly exited with status 0 before B durably observed the exact ItemID,
including 60-second attempts. Native completed 64 KiB and then 1 MiB. Those
upstream results remain observed technical failures; this report does not infer
a root cause from the exit status alone.

## Matched 10/10 manual cohort

Every arm ran ten independent 1 KiB manual A→B trials with automatic discovery
disabled. CPU, memory, and network values are nearest-rank p50/p95 over the 20
whole-container process windows. Receiver observation uses ten B values.
Processes stayed up for approximately 15 seconds, so CPU and traffic include
connection setup and post-transfer idle work. “Effective rate” is 1 KiB divided
by first durable observation time; it is not sustained bulk throughput. Network
amplification uses the ten receiver windows where the item was newly observed,
while the raw network distribution uses all 20 process windows.
`Memory current` was sampled while the candidate was running at exact-item
observation, so native's roughly 75 ms samples and the upstream arms' roughly
335 ms samples occur at different process ages; it is not settled/end-of-run
RAM. The peak and separate ten-minute settled measurements are the stronger
cross-arm memory comparisons.

| Metric, p50 / p95 | Native | Iroh protected | libp2p protected |
|---|---:|---:|---:|
| CPU usage | 288,298 / 292,771 µs | 277,455 / 306,822 µs | 287,450 / 332,361 µs |
| Memory current | 4,190,208 / 4,898,816 B | 7,213,056 / 8,318,976 B | 5,177,344 / 5,996,544 B |
| Memory peak | 8,110,080 / 8,777,728 B | 11,337,728 / 12,267,520 B | 8,925,184 / 9,928,704 B |
| Non-loopback network per process | 51,318 / 51,502 B | 104,276 / 114,690 B | 83,969 / 84,789 B |
| Network / 1 KiB payload | 50.1× / 50.3× | 101.8× / 112.2× | 82.0× / 82.8× |
| B first durable observation | 75 / 80 ms | 338 / 351 ms | 335 / 347 ms |
| First Aster authentication | 13 / 15 ms | 18 / 23 ms | 13 / 16 ms |
| Effective 1 KiB rate | 109,227 / 112,219 bit/s | 24,237 / 24,900 bit/s | 24,454 / 24,976 bit/s |

Iroh's manual CPU median was marginally lowest, but the distributions are close
and this is not a CPU-bound workload. Native's material advantages were current
memory, carrier traffic, and first durable observation. Libp2p was consistently
lighter than Iroh while their observation time and effective rate were nearly
identical.

## Payload and capture probes

Native's retained 64 KiB run observed the exact ItemID at B 72 ms after process
launch. Its one 1 MiB run observed the exact ItemID at 323 ms; the two process
windows used 1,378,134 and 1,004,985 µs of CPU, peaked at 13,459,456 and
13,344,768 B, and each transferred about 9.65 MB at the container interface.
These are single-run capacity probes, not latency distributions.

Each capture trial retained three pcaps spanning A→B, B→C, and duplicate
replay. The scanner searched for payload, logical key, raw and hexadecimal
publisher identity, topic, and scope.

| Arm | Capture result | Aggregate pcap bytes | Plaintext findings |
|---|---:|---:|---:|
| Native | 3/3 nonempty pcaps | 147,990 B | 0 |
| Iroh protected | 3/3 nonempty pcaps | 274,288 B | 0 |
| libp2p protected | 3/3 nonempty pcaps | 227,058 B | 0 |

This is useful protected-carrier evidence, but it does not close Phase 4. The
trial did not include the required priority canary or provider cache/log scans,
and it did not run the malformed, unauthorized, revoked, flood, or
capacity-exhaustion corpus.

## Settled idle resources

Each arm ran for eleven minutes: one settling minute followed by ten measured
minutes. Counters cover the whole container. The lab writes status evidence on
a 250 ms cadence, so the CPU value includes evidence instrumentation and does
not isolate the provider. All three nevertheless fail the proposal's declared
`<1%` screen as measured.

| Arm | Settled CPU, one core | Current memory after settle | Startup peak | Traffic per minute | Aster frames | Result |
|---|---:|---:|---:|---:|---:|---|
| Native | 1.1186% | 3,538,944 B | 9,760,768 B | 2,544.0 B | 0 | Fail CPU |
| Iroh protected | 1.2133% | 6,930,432 B | 14,475,264 B | 2,594.2 B | 0 | Fail CPU |
| libp2p protected | 1.3855% | 6,541,312 B | 12,754,944 B | 2,522.8 B | 0 | Fail CPU |

All three remain below the provisional 4 KiB/node/min discovery screen in this
protected-discovery configuration. This says nothing about provider-native
mDNS traffic. The 64 MiB screen applies at 10,000 items; that workload was
stopped after Phase 1 and these idle values cannot substitute for it.

## Binary, dependency, and custom-code size

The binaries are stripped Linux ARM64 release artifacts from the signed
experiment checkpoint. Package counts are unique active normal/build package
identities for the exact protected Linux graph, including `aster-lab` and
excluding dev-only edges.

| Arm | Binary SHA-256 | Binary bytes | Increment over native | Active packages | Increment over native |
|---|---|---:|---:|---:|---:|
| Native | `82438a75538687d32660ea1df4b72354cdb081ad1a6570bafefb7f9ddbe34957` | 4,345,600 | — | 79 | — |
| Iroh protected | `755582545f4aed3f58b51578cbc91a195f813e195b21004419d986987c373d21` | 11,907,368 | 7,561,768 B (+174.0%) | 291 | +212 |
| libp2p protected | `2b3a8c820284de692155d9c70007f78a21a81f0f78c4fe813df108e938db8407` | 6,378,896 | 2,033,296 B (+46.8%) | 226 | +147 |

Both upstream binaries pass the provisional +10 MiB binary screen. That is not
a selection pass because architecture, assurance, and mechanism-deletion gates
are independent.

Custom code uses physical lines, including comments and blanks. The comparison
is the delta from survey baseline `56ea19d` to experiment checkpoint `15f99c3`;
“non-test” means the source before the first `#[cfg(test)]`. The totals charge
the common host/native experiment integration equally to every arm and then add
the upstream provider module.

| Arm-visible Rust delta | Non-test lines | Test lines | Provider-only module, non-test / test |
|---|---:|---:|---:|
| Native/common control | 1,719 | 1,404 | — |
| Iroh protected | 5,210 | 2,709 | 3,491 / 1,305 |
| libp2p protected | 5,403 | 2,944 | 3,684 / 1,540 |

The 1,719 native/common non-test lines split into 497 reusable
`MeshHost`/runtime product lines and 1,222 lab integration/CLI lines. The shared
product changes added 1,192 test lines; the native/common lab changes added 212.
Lab-only Python controller and results tooling added another 2,517 non-test and
1,072 test lines and is excluded from the arm comparison.

Neither upstream arm deleted an overlapping native mechanism. Even before the
shared architecture failure, both therefore fail Proposal 0003's buy-over-build
gate: each added thousands of provider-specific lines while leaving native
discovery, transport, traversal, and relay mechanisms intact.

## Assurance and project interpretation

The native active graph passed its feature-specific advisory and license checks.
Both protected upstream graphs reach unmaintained `paste 1.0.15`
(`RUSTSEC-2024-0436`). The libp2p provider-mDNS graph additionally reaches the
blocked Hickory 0.25.2 advisories; Hickory is absent from the tested protected
libp2p graph. Iroh's Rust 1.91 floor remains above the workspace's Rust 1.90
promise.

The upstream graphs also contain BSD-2-Clause, ISC, Zlib, and, for Iroh,
CDLA-Permissive-2.0 expressions that the repository allowlist does not yet
enumerate. These are permissive or OSI-approved terms. They are policy work to
resolve explicitly, not a substantive reason to reject otherwise suitable FOSS.
The recommendation rests on architecture, boundedness, lifecycle, unmaintained
dependencies, and missing network-path proof—not on over-rotating the FOSS
restriction.

## Rollback proof

Both rejected external-provider transitions were exercised against independent
64 KiB partial stores. Provider carrier keys were moved out of the copied node
roots without deleting Aster durable truth; the unchanged stores then resumed
through native A→B and B→C contacts.

| Transition | Original ItemID / EnvelopeID | Evidence-index SHA-256 | Declared aggregate |
|---|---|---|---|
| libp2p → native | `2c5fa2ce…e6867` / `6f1660ac…01c8` | `59143b7b5f59cca4bf259f88268dbb1d7e7c3d0bd50ed5215aaf391f3d2d9b10` | `ed1520ca3fdc9be2b0b79bff3655fa44f7b62387a690fd421f3956fc5a778040` |
| Iroh → native | `64d75c34…50136` / `7811cd50…25c4c` | `31d67992e2c4855ac0ec1b23598e20fc37903f878485c9acad2151dff2d76256` | `2abf844a8a3abb24b071240923a7beaee792d640535cffc396e380b3fdfd1a9c` |

In both transitions the exact full IDs survived; route-only custody remained
unreadable, delivery preserved both IDs, application acknowledgement succeeded,
and immediate and post-restart redelivery were zero. The retained roots are
`evidence/ip_mesh_experiment/rollback/p0003-libp2p-to-native/` and
`evidence/ip_mesh_experiment/rollback/p0003-iroh-to-native/`. Native is the
continuing rollback target rather than a removable external provider; its own
restart and partial-resume behavior is covered by the native control and common
runtime tests.

Signed removal commit
`5f9aabad9b26f832c45cf943bd17ead19cc2711a` has zero Iroh or libp2p package
matches in the continuing default/all-edge graph. The provider-free Docker
image/repository digest is
`sha256:79d4df924baffb6ddc6f8f845e920f3e74d1f2a1fdc80dda82e4ff000c92c90c`.
Its binary is 4,345,600 B—exactly the frozen native-control size—with SHA-256
`6727de1da917d18ddc837e30d317bc6b9301ec169ac215ec0fee66c3d7296d6c`.
The separate provider-free build receipt at
`evidence/ip_mesh_experiment/rollback/p0003-provider-free-build-5f9aaba/`
has evidence-index SHA-256
`c536e9e67d25fd0a026f6d7450189b2f22b4cdc50e404bff7ca543932d90cca0`
and aggregate
`32d09e3cd37ebecf9b1865eb8233f5869f33ccf8064ab953fe1bd81752765640`.

This proves rollback from each rejected external provider and the provider-free
continuing build. It does not turn either rejected provider into a passing
candidate.

## Phase disposition

| Phase | Disposition |
|---|---|
| 0 — activation | Frozen and characterized. Native eligible to test; protected upstream profiles technical-only with recorded blockers; provider-mDNS profiles nonqualifying. |
| 1 — architecture proof | **Fail all arms.** Shared pre-auth backend construction, multiple durable owners, and missing node-global budget are non-compensable. Iroh additionally fails its pre-`Incoming` bound and path-event lifecycle. |
| 2 — discovery/manual/LAN custody | Formally stopped. Retained direct-LAN cohorts are technical characterization only; no arm completed the full required matrix. |
| 3 — controlled NAT and relay | **Not run by protocol.** No surviving arm; no NAT, connectivity-relay, relay-loss, DCUtR, Iroh relay, or address-change acceptance claim. |
| 4 — impairment/security/scale/resources | Formally stopped. Limited capture, payload, and ten-minute idle probes are reported above; the impairment corpus, 100 real processes, 10,000 items, and one-hour idle were not reached. |
| 5 — deletion/rollback/disposition | No selection and no selection deletion patch. Libp2p-to-native and Iroh-to-native rollback plus the provider-free rebuild passed; rejected Rust adapter modules, Cargo features, and dependency graphs were removed while signed source and evidence were retained. Python evidence tooling remains. |

Early stopping is the proposal's required complete outcome when Phase 1 has no
survivors. NAT, relay, security, scale, and one-hour resource cells are not
missing successes; they are explicitly stopped cells and convey no capability.

## Recommendation

Select **none** now.

Implement one process-owned durable runtime before doing more provider tuning:

1. open the SQLite node and Blob store once under a node service;
2. make each authenticated contact a lightweight session against that owner,
   with no independent durable backend or quota counter;
3. enforce one aggregate budget across discovery work, unauthenticated
   handshakes, active contacts, inbound/outbound bytes, tasks, descriptors, and
   relay reservations; and
4. require fresh Aster authentication on every replacement stream and every
   path/address transition before durable synchronization resumes.

These are Decision 0024 architecture controls, not verbatim product
requirements. The singleton owner and borrowed-session model are the selected
remedy for the observed shared-state defect, while fresh authentication on every
path/address transition is a conservative acceptance rule for preserving
authenticated authority. Their direct-versus-derived mapping and the
requirements that remain open are recorded in Decision 0024's
[requirements traceability](../decisions/0024-refactor-durable-node-ownership-before-ip-provider-selection.md#requirements-traceability).

After that refactor, keep native as the semantic and resource control and carry
libp2p forward as the first connectivity candidate. A fair libp2p retry must
compose and exercise Identify, AutoNAT, local circuit relay, and DCUtR while
leaving Aster in control of discovery policy, identity, authorization, custody,
and propagation. It must resolve the alpha stream/update-ownership and `paste`
findings, then rerun the exact Phase-1 through Phase-5 gates.

Do not continue Iroh integration until its pre-`Incoming` resource bound and
path-change/fresh-auth lifecycle have credible solutions. Revisit it after those
conditions change; its permissive FOSS licensing is not the reason for the stop.

### Follow-on status — 2026-08-21

Proposal [0004](0004-shared-node-libp2p-retest.md) has implemented a
provider-free shared-node candidate and a formal evidence lane for this
recommendation. The formal build uses `aster-lab` feature `gate-h` with defaults
disabled and binary `aster-gate-h`, so the historical `MeshService` and legacy
CLI path are compile-excluded. Its deterministic plan covers 23 mandatory fault
cases through 37 exact one-test commands, and its live aggregator requires all
40 process launch/result/stdout/stderr quartets for the ten-trial cohort.

That follow-on implementation does not revise this result. No formal Gate-H
receipt or 10/10 cohort has yet been recorded here, no libp2p package has been
admitted to the candidate graph, and neither libp2p nor Iroh is selected.

No requirement, conformance scenario, MVP status, or production mesh capability
is closed by this result.

### Follow-on disposition — 2026-08-23

The provider-free shared-node candidate later passed formal Gate H and its
10/10 live cohort. That corrected-host result did not select a provider.
Proposal [0004](0004-shared-node-libp2p-retest.md) then accumulated bounded,
default-disabled rust-libp2p development evidence but stopped before its formal
Phase-0/Phase-1 comparison; Phases 2–5 did not run. Its
[result](0004-shared-node-libp2p-retest-results.md) records no arm selected and
rejects rust-libp2p from the continuing selected-stack lane without relabeling
unrun gates as candidate failures.
