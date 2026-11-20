# Proposal 0001 result: LAN mesh proven; operational IP profile not selected


- Status: completed — no production winner
- Date: 2026-08-21
- Proposal: [0001 — Operational IP mesh vertical-slice experiment](0001-ip-mesh-vertical-slice.md)
- Starting baseline: `9a8a87e11785c98fd1069cb2338c4076f4c728cb`
- Candidate implementation checkpoint: `117770259680d89e5fbd1ff1f6c3df9f3e646e6c`
- Requirements SHA-256:
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Decision: [0022 — Do not select an IP mesh substrate from Proposal 0001](../decisions/0022-ip-mesh-experiment-no-selection.md)

## Outcome

The experiment produced a real and useful result, but not a production-ready
mesh profile.

Native UDP, core Iroh, and minimal rust-libp2p implementations each passed 30
of 30 clean, three-process LAN trials. In every passing trial, nodes discovered
one another without configured peer addresses, authenticated with Aster rather
than trusting the carrier identity, transferred one A-authored Event to a
route-only B, restarted B from durable state with A offline, delivered the
unchanged ItemID to C, application-acknowledged it, and suppressed redelivery.
A and C had no common carrier segment in the primary topology.

That establishes the missing basic LAN vertical slice. It does **not** establish
the complete operational host required by the proposal. None of the three arms
implemented manual/pre-provisioned peering through the common host, emission
policy linkage, a fair 100-peer contact scheduler, controlled NAT traversal,
locally operated connectivity-relay fallback, or relay-loss reconnection. The
Quinn control compiled but had no runnable host implementation. The pinned
Linux traffic-control utility also rejected deterministic netem seeds, so the
required reproducible impaired-IP lane could not produce acceptable evidence.

Because those are mandatory, non-compensable gates, no arm entered a valid
Phase-C downselect. The selected outcome is **none**. No third-party networking
dependency is admitted and no product capability claim changes.

## What was built and exercised

The experiment added one bounded, lab-only host shape for each LAN arm:

- **native:** protected local broadcast discovery over the existing UDP carrier,
  persisted non-authoritative carrier identity, and a bounded multi-contact map;
- **Iroh 1.0.3:** one persistent endpoint, public DNS/DHT/relay defaults disabled,
  opt-in local mDNS lookup, one Aster ALPN, and bounded concurrent contacts; and
- **rust-libp2p 0.56.0:** one Swarm using TCP, Noise, Yamux, mDNS, Identify, a
  private request/response protocol for Aster frames, and connection limits.

Neither Iroh Gossip nor libp2p Gossipsub/Kademlia carried Aster data. All arms
used Aster's existing handshake, authorization, protected envelopes, durable
store, reconciliation, route-only custody, and application acknowledgement.

The shared controller used internal container networks, three independent
durable roots, a high-entropy payload canary, exact ItemID and EnvelopeID
checks, process restart, capture scanning, and fail-closed result receipts. The
candidate node itself ran with an empty Linux capability bounding set; a
separate inert supervisor owned the minimum network-setup capability.

## Phase results

### Phase 0 — data-plane prerequisite

The deterministic route-only Event control passed 10/10. B retained the exact
source envelope across restart without application payload access; C received
and acknowledged the exact source item; a second poll and a post-restart poll
returned no new delivery. The detailed receipt remains in
`evidence/IP_MESH_EXPERIMENT_20260821.md`.

### Phase A — clean LAN vertical slice

| Arm | Clean trials | Trial elapsed time | Result |
|---|---:|---:|---|
| Native UDP host | 30/30 | 21.662–25.885 s; 22.308 s mean | Pass |
| Iroh | 30/30 | 21.749–22.737 s; 22.075 s mean | Pass |
| rust-libp2p | 30/30 | 21.769–22.647 s; 22.044 s mean | Pass |

The approximately 22-second totals include three deliberately fixed six-second
contact windows plus provisioning, verification, network creation, teardown,
and restart. They are not measured convergence latency. Iroh first-candidate
observations ranged from 700–812 ms; libp2p observations ranged from 0–11 ms.
The native receipt version did not expose first-candidate time, so no equivalent
number is claimed.

Every final cohort preserved the same semantic/security facts:

- exact source ItemID and EnvelopeID at B and C;
- route-only B could not open the Event payload;
- payload plaintext and its endpoint-only digest were absent from B's durable
  tree scan;
- B reopened from the same store before meeting C;
- C delivered once, acknowledged once, and did not redeliver;
- recontacting A created no second semantic item; and
- the primary topology recorded `A_C_contact_count=0`.

The Iroh and libp2p controllers copied the candidate binary into each evidence
root before execution. The native 30-trial cohort predates that harness
hardening: its binary hash remained stable and it was not rebuilt during the
cohort, but the run root does not contain its own immutable binary copy. This is
an evidence-quality limitation, not a hidden pass.

### Additional LAN gates

| Gate | Native | Iroh | rust-libp2p |
|---|---:|---:|---:|
| Discovery-disabled negative | 1/1 | 1/1 | 1/1 |
| B simultaneously authenticates A and C | 1/1 | 1/1 | 1/1 |
| Capture canary scan | 3 pcaps clear | 3 pcaps clear | 3 pcaps clear |

The discovery-disabled lane produced zero candidates, authenticated peers, and
Aster carrier frames for every arm. The simultaneous three-node lane reached an
active-contact high-water of at least two at B and authenticated both expected
peers. A and C shared that test LAN and observed one another, but Aster rejected
the unprovisioned peer relationship; this lane proves bounded multi-contact
hosting, not primary-topology isolation or fair scheduling.

Capture scans searched for the run's payload, logical key, topic, scope, and
publisher canaries in raw and encoded forms. No canary appeared:

| Arm | A↔B pcap | B↔C pcap | A recontact pcap |
|---|---:|---:|---:|
| Native | 54,402 B | 54,753 B | 30,259 B |
| Iroh | 109,256 B | 111,433 B | 87,475 B |
| rust-libp2p | 158,580 B | 154,240 B | 87,429 B |

This is a unique-canary absence test, not a general traffic-analysis or
cryptographic proof. Candidate carrier identities, addresses, timing, and
volume remain observable.

### Ten-minute idle measurement

| Arm | CPU, one core | Settled traffic/node/min | Settled / peak memory | Gate result |
|---|---:|---:|---:|---|
| Native | 0.547% | 2,544 B | 5.40 / 9.52 MB | CPU/traffic pass; self-discovery defect observed |
| Iroh | 0.670% | 55,258 B | 10.00 / 13.73 MB | Discovery-traffic fail |
| rust-libp2p | 0.756% | 396 B | 6.55 / 10.16 MB | Pass |

All arms stayed below the provisional 1% CPU and 32 MiB preferred RAM screens.
Iroh exceeded the 4 KiB/min discovery ceiling by about 13.5×. Native stayed
below the traffic ceiling but processed its own reflected announcements as one
candidate, producing 586 self-directed carrier frames over ten minutes. The
generic receipt therefore marked native false; the table separates the accepted
CPU/traffic measurements from that real inefficiency rather than relabeling the
whole receipt as a pass.

### Phase B — mandatory capability stop

An isolated, no-network command-surface probe was run against the exact four
binaries. The native, Iroh, and libp2p hosts all rejected:

- `--manual-peer`;
- `--rendezvous-address`;
- `--relay-address`; and
- `--emission-mode`.

The Quinn-feature binary rejected `mesh-quinn-node` because no Quinn host was
implemented. The crates selected for Iroh and libp2p contain some relevant
upstream mechanisms, but unused dependency features are not Aster host
capabilities. In particular, the experiment did not compose relay admission,
NAT reachability, hole punching, fallback, or reconnect behavior.

The three current contact maps also retain active contacts until the bounded
process deadline or carrier close. They do not implement the proposal's
100-peer contact quantum, opportunity bound, or service-count-skew rule. That
absence is a functional failure, not an unrun performance benchmark.

The pinned `iproute2` rejected the requested netem `seed 424242` token before
installing a qdisc. The laboratory already records that this kernel loss model
is stochastic when retried without a seed. Because Proposal 0001 requires ten
deterministic seeded trials, unseeded successes could not be substituted. The
3 kbps/50%-loss live-IP gate is **blocked by the accepted reproducibility
contract**, and no arm receives a pass or semantic failure for that cell.

Once the manual/emission, NAT/relay, fairness, and deterministic impairment
gates were unavailable or failed, continuing into 10,000-item and 100-process
Phase-C selection trials could not make any arm eligible. Phase C was therefore
not applicable under the proposal's non-compensable selection rule.

## Mandatory-gate disposition

| Gate | Result | Basis |
|---|---|---|
| Locator-free LAN discovery | Pass, all three | 30/30 primary cohorts |
| Independent processes and durable roots | Pass, all three | controller topology and restart receipts |
| Aster remains mission authority | Pass in exercised lanes | carrier identity never grants Aster authorization |
| B restart and unchanged forwarding | Pass, all three | exact envelope/item receipts |
| Route-only payload unreadability | Pass, all three | API and durable-tree canary checks |
| Application ack and no redelivery | Pass, all three | durable C subscription receipt |
| Unauthorized/revoked candidates | Partial | unauthorized A↔C rejected; revocation lane not run |
| Emission linkage and manual peer | Fail, all three | exact binaries reject both surfaces |
| Infrastructure-free local LAN | Pass, all three | internal networks; public services disabled |
| Controlled NAT relay fallback | Fail, all three | not composed in common host |
| Capture confidentiality canaries | Pass, all three | three clear pcaps per arm |
| Transport-neutral publish API | Pass in exercised lanes | coordinator never selects a carrier per item |
| Unchanged Aster semantics | Pass in exercised lanes | same ItemID/EnvelopeID and existing protocol |
| All hostile resources bounded | Partial | configured caps exist; full hostile/flood suite not run |
| Idle CPU/discovery threshold | Native partial; Iroh fail; libp2p pass | ten-minute measurements |
| Seeded 3 kbps/50%-loss completion | Blocked | pinned netem lacks deterministic seed support |
| Mechanism deletion and rollback | Not reached | no production winner |

No row after a failure can compensate for it. The table therefore cannot be
scored into a winner.

## Resource and supply-chain comparison

The measured stripped Linux ARM64 binaries were:

| Profile | Binary | Increment over native |
|---|---:|---:|
| Native | 4,148,992 B | — |
| Iroh | 13,024,824 B | 8,875,832 B |
| rust-libp2p | 6,642,552 B | 2,493,560 B |
| Quinn feature only | 4,148,992 B | 0 B of implemented functionality |

Iroh and libp2p stayed under the provisional 10 MiB *incremental* screen, but
Iroh exceeded a 10 MiB absolute artifact interpretation. No 10,000-item
profile-specific resource run was performed because no candidate survived
Phase B.

Exact Cargo metadata and CycloneDX receipts were generated for every profile.
The exact-feature dependency-policy results were:

- **native:** zero advisory or license errors;
- **Iroh:** one unmaintained-package finding (`paste`,
  `RUSTSEC-2024-0436`) and six current license-allowlist rejections; and
- **rust-libp2p:** two `hickory-proto` vulnerability findings
  (`RUSTSEC-2026-0118` and `RUSTSEC-2026-0119`), the same unmaintained `paste`
  finding, and six license-allowlist rejections.

Most rejected license expressions are OSI-approved licenses missing from the
repository allowlist rather than demonstrated legal incompatibilities. Iroh's
graph also includes `CDLA-Permissive-2.0`, which requires a separate policy
decision. The findings are still production-selection blockers under the
accepted exact policy; this report does not waive or inflate them.

Iroh also raises the selected toolchain floor from the project's prior Rust
1.90 profile to Rust 1.91. The experiment used Rust 1.97.1. No dependency was
admitted merely because it compiled or passed the LAN trials.

## Preserved failures and corrections

Development failures remain in the evidence tree. The most consequential were:

- native multicast did not cross the internal bridge, so the local provider
  moved to protected directed broadcast;
- native's first introduction could race candidate installation, requiring a
  bounded repeated introduction;
- initial Iroh ordered dialing could leave only one side with a candidate;
- simultaneous Iroh contacts initially selected different duplicates;
- one libp2p cohort used a binary that changed during execution and was rejected
  rather than accepted as final evidence;
- the first final Iroh cohort exposed an over-strict harness rule that required
  both endpoints to emit discovery, even though the pair had discovered,
  authenticated, and transferred; the gate was corrected to pair-level
  automatic discovery plus mutual Aster authentication; and
- two capture attempts produced only pcap headers because the capture process
  lacked the exact identity-dropping capabilities; both failed attempts remain,
  and the corrected captures are the ones reported above.

These observations are part of the result. Only the explicitly named final
cohorts support the pass counts.

## Evidence index

The local project evidence tree retains all commands, process output,
candidate receipts, durable stores, pcaps, failed attempts, exact metadata,
SBOMs, and dependency-policy output. Principal final roots and summary digests:

| Evidence root or receipt | SHA-256 of summary/receipt |
|---|---|
| `lab/runs/20260821T110000Z-phase-a-native-30/summary.json` | `8299ecc6fd097fb6456ff3520d1905f74f7da34b1e223f1f894f04d59168922b` |
| `lab/runs/20260821T115000Z-phase-a-iroh-final2-30/summary.json` | `b70df4aa7b1b0dcb983f7755973c861090be07695c85e834b5e956d9458b012f` |
| `lab/runs/20260821T115000Z-phase-a-libp2p-final-30/summary.json` | `83a6988687c7a18f6298540a1859cff835f9fbf614ec55c34a33c68b41fd5d6c` |
| `lab/runs/20260821T121500Z-idle-native-10m/summary.json` | `648ac9d74425003adaac9f2f6890062c388ec9894035ca25adc92f74f96fe6f0` |
| `lab/runs/20260821T121500Z-idle-iroh-10m/summary.json` | `3972fe1e51aa1e0b2644072407fe7a443cc4a675616b51e70cb48959c39d81b0` |
| `lab/runs/20260821T121500Z-idle-libp2p-10m/summary.json` | `e2f519a3ebe96fb8de587da83e0830c69a84f8ed1f5d94211c75c10ab88f8501` |
| `lab/runs/20260821T130000Z-capability-probe/result.json` | `2c7804220f050a530e61c5ebaf19b92be84b4f303e4e5c07a8c81d92408fd444` |

The three final capture summaries are under the matching
`20260821T125000Z-capture-*-final2` roots. The exact assurance receipts are
under `evidence/ip_mesh_experiment/assurance/`. These paths are deliberately
excluded from ordinary source publication by the project policy; this
tracked result records their identities without publishing protected run state.

## Decision and next gate

The experiment supports three conclusions:

1. Aster's durable route-only A→B→C semantics work over real, independently
   running IP processes with automatic LAN discovery.
2. The remaining product gap is the **operational host/control plane**—peer
   configuration, discovery-to-contact policy, scheduling, retry/failover,
   emission linkage, NAT/relay composition, and status—not the pairwise Aster
   reconciliation protocol.
3. Choosing a networking crate before that host contract and its acceptance
   tests exist would repeat the original architecture mistake. Iroh and libp2p
   both proved useful mechanisms, but neither became an eligible Aster profile
   in this experiment.

The next implementation gate should therefore freeze and test one provider-
neutral `MeshHost` contract in this order: manual peer plus automatic LAN
discovery; bounded fair multi-peer scheduling; reconnect/address change;
emission-driven discovery suppression; and then one locally controlled NAT
direct/fallback profile. The native LAN implementation remains a lab oracle for
the first two facts. A later bounded spike may reintroduce one upstream
connectivity provider behind that contract; it must start from the failed gates
above rather than rerun the already-proven LAN custody slice.
