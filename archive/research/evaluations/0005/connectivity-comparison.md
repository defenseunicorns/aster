# Phase 2 requirements-first IP connectivity comparison

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.

Date: 2026-08-22  
Status: completed bounded local differential; not a production admission  
Execution registration: BVB-767  
Result: Iroh is the leading conditional FOSS buy, rust-libp2p is held as an
oracle pending dependency repair, and the fixed Quinn composition remains the
narrow control rather than an equivalent connectivity buy.

## Outcome first

All three frozen arms carried two exact, bounded, version-labelled opaque byte
strings over a manually provisioned local IP path. Each authenticated the
provider before application delivery, rejected a deliberately wrong provider
with zero delivered application frames, and operated without a relay or public
service.

No arm completed the required automatic-discovery chain:

```text
advertise -> discover -> authenticated dial -> exact opaque delivery
```

Iroh discovered the expected identity/address hint but timed out dialing it.
rust-libp2p emitted no matching discovery event. The Quinn/mdns-sd composition
resolved no address. The three runners therefore correctly returned nonzero
after executing every remaining case. These are bounded single-host findings,
not claims that the upstream discovery mechanisms are universally broken.

Only Quinn demonstrated a forced path/session change: the same QUIC connection
survived a real UDP socket and local-port rebind and delivered the second frame,
with path-validation frames in the connection statistics. Iroh used two streams
on one stable connection and one loopback path. rust-libp2p used two streams
while the Swarm reported one connection, but the alpha stream helper does not
expose the physical connection identifier for each stream.

No candidate receives NAT traversal, hole-punch, connection-relay, durable
relay, broadcast-data, BTLE, application sync, source-object security, QoS,
custody, duplicate, or loop-suppression credit.

## Project and selection boundary

This arm was derived from `data-mesh-requirements.md`, the Proposal 0005
connectivity section, and the registered primary-source and local-freeze rows.
The current implementation and Proposal 0004 artifacts were not inspected.
Compatibility with current code has weight zero. No unregistered web source was
consulted, and no excluded activity or excluded-person material was searched or
opened.

The comparison asks which responsibilities a frozen candidate owns, not which
one resembles an existing provider boundary. The common lane tests manual and
native automatic discovery, carrier authentication, a small opaque protocol,
local operation without infrastructure, discovery omission, explicit bounds,
and observable path/session behavior. Application dissemination and security
remain separate composition layers.

## Exact freezes

| Arm | Direct freeze | Lock graph | License and MSRV | Registered source |
|---|---|---:|---|---|
| Iroh | `iroh 1.0.3` (`portmapper`, `tls-ring`, defaults off), `iroh-mdns-address-lookup 0.5.0`, `n0-future 0.3.2`, `tokio 1.53.1` | 381 packages: one local harness plus 380 registry-pinned; zero git/other path | Iroh and mDNS provider `MIT OR Apache-2.0`; Rust 1.91 | BVB-746, 749, 753, 760, 761 |
| rust-libp2p | `libp2p 0.56.0` with AutoNAT, DCUtR, Ed25519, Identify, mDNS, limits, Noise, QUIC, relay, TCP, Tokio, Yamux; `libp2p-stream 0.4.0-alpha`; `futures 0.3.34`; `tokio 1.53.1` | 349 packages: one local harness plus 348 registry-pinned; zero git/other path | libp2p and stream helper `MIT`; Rust 1.83 | BVB-747, 749, 751, 757 |
| Quinn-native | One unchanged composition: `quinn 0.11.11`, `rustls 0.23.43`, `rcgen 0.14.9`, `mdns-sd 0.11.5`, `tokio 1.53.1` | 122 packages: one local harness plus 121 registry-pinned; zero git/other path | Quinn/rcgen `MIT OR Apache-2.0`; rustls `Apache-2.0 OR ISC OR MIT`; mdns-sd `Apache-2.0 OR MIT`; maximum direct MSRV 1.88 | BVB-731–733, 748, 749, 751, 757 |

The Iroh graph's Rust 1.91 floor is above a Rust 1.90 consumer ceiling. That is
an integration delta, not a connectivity failure. The Quinn control remained
one fixed composition throughout; it was not given a different discovery,
NAT, or relay component per case. Its absent NAT and relay owners are charged
as residual custom work.

The original BVB-746–761 and BVB-767 path fields used the shorter historical
candidate path `...` (archived). BVB-776 corrects
those fields append-only to the actual
`...` (archived) root. No manifest, lock,
source, build, run, binary hash, or finding changed.

## Common executable cases

The test protocol label was `project-connectivity/1`. Each direct case sent
two non-text-safe payloads containing a leading version byte, embedded NUL, and
non-UTF-8 marker, with a 64 KiB frame ceiling. Exact echo proves only that the
carrier preserves these opaque bytes; it does not prove synchronization,
mixed-version behavior, extension skipping, fragmentation, or tiny-MTU fit.

| Case | Iroh | rust-libp2p | Quinn-native |
|---|---|---|---|
| Manual local path | Pass: direct loopback QUIC, relay and port mapper disabled, two exact echoes | Pass: loopback TCP/Noise/Yamux, two exact echoes; the enabled QUIC feature was not used | Pass: loopback QUIC/rustls mTLS, two exact echoes |
| Provider identity | Native `EndpointId`; exact static client/server allow mapping | Native Noise `PeerId`; AllowedPeers plus expected peer check | Exact peer certificate DER under rustls mTLS and static trust |
| Wrong identity | Zero frames; timed-out dial, not an explicit rejection alert | Zero frames and explicit `Unexpected peer ID` dial error | Zero frames; timed-out handshake, not an explicit rejection alert |
| Native automatic discovery | Partial: matching identity/address hint, then dial timeout, zero frames | Fail in run: no event, connection, or frame before timeout | Fail in run: no resolved address or frame before timeout |
| Discovery omission | Partial: provider not advertised or observed for three seconds; positive discovery control exists; manual fallback works | Inconclusive: provider mDNS off and manual fallback works, but positive discovery also failed | Inconclusive: harness browsed a different never-registered service and the positive case also failed |
| Path/session | Partial: two streams, same stable ID, one observed loopback path; no forced change | Partial/inferred: one Swarm connection and two streams; helper does not map a stream to physical `ConnectionId` | Pass for local rebind slice: same connection and second frame after UDP rebind; path validation observed |
| Runner status | Nonzero because automatic delivery failed | Nonzero because automatic delivery failed | Nonzero because automatic delivery failed |

### Discovery and emission qualifications

Discovery metadata is a hint, not authorization. Iroh's advertised EndpointId,
libp2p's discovered PeerId, and Quinn's DNS-SD TXT property are accepted only
after the authenticated carrier identity matches the provisioned test map.

The emission case is not a proof of radio silence or receive-only semantics.
No packet capture or outbound-byte counter was used, and every omitted provider
later transmitted during manual handshake and echo. Iroh earns partial
event-level evidence because its positive discovery control did produce a
matching event. rust-libp2p and Quinn remain unknown on suppression causality
because their positive controls failed. The Quinn negative browsed a separate
service, and browsing itself may emit discovery traffic.

Quinn placed a 736-byte hex-encoded certificate in one research TXT property.
That encoding's DNS-SD interoperability was not separately established, so the
failed resolution cannot be attributed solely to the host environment. A real
profile needs a compact discovery identifier that is independently bound to
the authenticated certificate.

## Requirement-scoped findings

| Requirement | Iroh | rust-libp2p | Quinn-native | Scope guard |
|---|---|---|---|---|
| `DM-5.6-01` direct peer sync | Partial | Partial | Partial | Direct opaque carrier exchange is not complete sync between conformant nodes. |
| `DM-5.6-02` infrastructure-free direct sync | Met for connectivity slice | Met for connectivity slice | Met for connectivity slice | All used only local peers; no relay/public service. |
| `DM-5.6-03` temporal multi-hop | Not demonstrated | Not demonstrated | Not demonstrated | Connection relay is not durable store-and-forward. |
| `DM-5.6-04` one-to-many broadcast | Not demonstrated | Not demonstrated | Not demonstrated | mDNS multicast is discovery, not application broadcast. |
| `DM-5.6-05/06` duplicate/loop suppression | Unknown | Unknown | Unknown | No duplicate or cyclic forwarding topology ran. |
| `DM-5.7-01` automatic discovery | Partial hint only | Not met in run | Not met in run | No arm completed discovery through authenticated payload delivery. |
| `DM-5.7-02` manual peering | Met for connectivity slice | Met for connectivity slice | Met for connectivity slice | Provisioned identity plus explicit local address. |
| `DM-5.7-03` discovery emission policy | Partial | Unknown | Unknown | No packet-level silence proof; only Iroh has a positive discovery control. |
| `DM-5.7-04` pre-exchange mutual authentication | Met for provider-auth slice | Met for provider-auth slice | Met for provider-auth slice | No mission lifecycle, source-object, membership, or revocation credit. |
| `DM-5.8-07/08` NAT operation/traversal | Unknown | Unknown | Missing in fixed composition | No two-NAT topology or hole punch ran. |
| `DM-5.8-09` relay-assisted fallback | Unknown runtime | Unknown runtime | Missing in fixed composition | Iroh/libp2p have static mechanisms only; no configured relay ran. |
| `DM-5.8-10` local operation without relay | Met for connectivity slice | Met for connectivity slice | Met for connectivity slice | Direct local delivery completed. |
| `DM-5.8-11` BTLE | Not demonstrated, separate carrier | Not demonstrated, separate carrier | Not demonstrated, separate carrier | Proposal 0005 does not reject an IP substrate solely for a beside-it BLE delta. |
| `DM-5.8-16/17/18` link bandwidth/cost/emission fields | Not met | Not met | Not met | Raw telemetry is not a normalized policy-facing link characteristic. |

Transport authentication does not satisfy `DM-6-01` through `DM-6-03` for
source-protected items. The static maps show only that a native carrier identity
can be bound to a research mission identity without adding a second incumbent
authentication session. They do not demonstrate provisioned identity
lifecycle, scope authorization, revocation, rekey, zeroization, FIPS/PQ
selection, metadata protection, or replay handling. Quinn's rcgen identities
are newly generated on each run and are not durable pre-mission identities.

## Resource and link-control comparison

| Arm | Configured connection controls | Observability | Remaining assurance gap |
|---|---|---|---|
| Iroh | 8 bidirectional/0 unidirectional streams; 64 KiB stream receive window; 256 KiB connection receive/send windows; 64 KiB application frame | Stable connection ID, path list, UDP/frame/loss statistics | No total connection/task ceiling in the harness; no forced path change; no normalized bandwidth/cost/emission fields |
| rust-libp2p | Pending in/out 8 each; established in/out 4 each; total 8; per-peer 1; 256 MiB connection-memory limiter; 16-event handler/connection buffers; 15 s idle; 64 KiB frame | Swarm address, endpoint, connection ID | 256 MiB is not evidence for the Tier-2 RAM target; no stream-to-physical-connection mapping; no RTT/bandwidth/cost/emission surface |
| Quinn-native | 8 bidirectional/0 unidirectional streams; 64 KiB stream receive; 256 KiB connection receive/send; 15 s idle; 64 KiB frame | Stable ID, local/remote address, RTT, congestion/loss/MTU, UDP and frame stats | No total connection/task ceiling and no normalized bandwidth/cost/emission fields |

The debug binaries were not treated as production footprint measurements. No
steady-state RSS, idle CPU, hostile-peer cardinality, buffer-exhaustion, or
low-rate/loss corpus was executed.

## NAT, relays, broadcast, and BTLE

Iroh's registered source surface owns port mapping, hole punching, path
selection, and a self-hostable connection-relay option. The final runner
explicitly disabled port mapping and relays, so runtime behavior is unknown.

rust-libp2p's frozen Swarm instantiated AutoNAT, DCUtR, and relay-client
behaviours. It configured no AutoNAT servers or relay address and established
no relayed connection, so those mechanisms remain static ownership evidence.
The run used TCP/Noise/Yamux; enabling the QUIC Cargo feature does not count as
executing it.

The Quinn composition has no NAT-mapping, hole-punch, or connection-relay
component. Its UDP rebind is useful path-continuity evidence, not NAT traversal.
This makes Quinn an honest narrow control, but not the complete greenfield
outcome described in Proposal 0005 without another frozen component set and
substantial integration.

No connection relay is a durable relay. None of the three owns persistence,
retry across process/contact non-overlap, expiry, custody, or application-item
identity. None carried application data by one-to-many broadcast, and none
contains a BTLE carrier.

## Component ownership and residual custom work

| Responsibility | Iroh | rust-libp2p | Fixed Quinn-native |
|---|---|---|---|
| Endpoint/session state machine | FOSS: authenticated QUIC Endpoint/Connection | FOSS: Swarm, transport negotiation, Noise, Yamux, connection lifecycle | FOSS: Quinn Endpoint/Connection plus rustls TLS; custom composition owns the host lifecycle |
| Provider identity | FOSS `EndpointId` | FOSS `PeerId` | Composed exact certificate DER; rcgen is only a research fixture |
| Manual addressing | FOSS `EndpointAddr` | FOSS `Multiaddr` + `/p2p` expected peer | Custom `SocketAddr` provisioning |
| LAN discovery | Separate FOSS Iroh mDNS provider; partial run | FOSS libp2p mDNS; failed run | FOSS mdns-sd primitive plus custom schema; failed run |
| NAT/direct upgrade | Candidate-owned static mechanisms; runtime open | FOSS AutoNAT/DCUtR behaviours; runtime open | Missing; entirely residual |
| Connection relay | Candidate-owned/self-hostable option; runtime open | FOSS client/service behaviours; runtime open | Missing; entirely residual |
| Path lifecycle/reporting | FOSS Iroh path APIs; no forced-change evidence | Swarm lifecycle, limited stream mapping in chosen alpha helper | FOSS Quinn telemetry/rebind; custom policy normalization |
| Resource bounds | Mostly FOSS transport controls plus custom policy | FOSS connection/memory limits plus custom values | FOSS Quinn controls plus custom values and process-level ceilings |
| Mission authorization/lifecycle | Custom exact identity map, provisioning, revocation, scope policy | Same | Same, plus production certificate issuance/rotation/profile |
| Link-policy normalization | Custom | Custom | Custom |
| Broadcast, BTLE, durable dissemination | Separate/custom composition | Separate/custom composition | Separate/custom composition |

Iroh collapses the most connectivity-specific state machines. rust-libp2p owns
the broadest modular behavior set but still requires an event-loop composition,
application framing, mission mapping, and link normalization; the selected
alpha stream helper adds an evidence gap. Quinn owns a strong narrow QUIC/TLS
primitive but leaves the largest operational integration surface: compact
discovery identity, provisioning, NAT, hole punching, relay, address policy,
and normalized link/resource policy.

## Supply-chain and support disposition

All dependency checks used the locally cloned, no-fetch RustSec database at
commit `bf5c0d245a92671908518d7e765914d437954ed6` (1,225 advisories as reported
by cargo-audit).

| Arm | Audit | Host-target CycloneDX components | License finding | Support/governance finding |
|---|---|---:|---|---|
| Iroh | Zero vulnerabilities; `RUSTSEC-2024-0436` warns that `paste 1.0.15` is unmaintained | 278 | All registry dependencies identified; local unpublished harness has no license field | BVB-624 records private GitHub reporting, no SECURITY.md, a documented 1.x support policy, local/direct operation, and self-hosted relay posture |
| rust-libp2p | `RUSTSEC-2026-0118` and `0119` on `hickory-proto 0.25.2`; unmaintained `paste 1.0.15` | 281 | All registry dependencies identified; local unpublished harness has no license field | Registered release/repository and advisory evidence exists, but this arm establishes no incident-response SLA; production admission is blocked pending exact-graph repair or a documented applicability/remediation decision |
| Quinn-native | Zero vulnerabilities or warnings in the frozen graph | 84 | All registry dependencies identified; local unpublished harness has no license field | Registered history includes disclosed and repaired Quinn denial-of-service advisories; no production support SLA is inferred |

The SBOM component count is host-target-specific and therefore smaller than the
complete cross-target lock graph. The complete lock count remains the graph
comparison. License expressions observed transitively are preserved in the raw
local cargo-deny receipts; there are no unlicensed registry dependencies at the
configured detection threshold.

## Down-selection and stop criteria

1. **Iroh — leading conditional FOSS buy.** It owns the broadest relevant
   connectivity surface and was the only arm to observe its native discovery
   hint. It does not become a finalist until automatic authenticated delivery,
   forced path change, named NAT topologies, and an owned-relay fallback pass
   without public defaults. The Rust 1.91 floor needs an explicit toolchain
   decision.
2. **rust-libp2p — hold as oracle.** It provides strong idiomatic ownership and
   the clearest wrong-peer rejection, but the final automatic-discovery lane
   failed, the selected stream helper cannot prove physical connection
   ownership, and the exact graph has two RustSec findings. Stop adoption work
   until a registry-published patched graph or a registered replacement profile
   exists; retain the Swarm/AutoNAT/DCUtR/relay design as comparison evidence.
3. **Quinn-native — control, not equivalent buy.** It supplies the smallest
   audit-clean graph and best local path-change evidence. Stop treating it as a
   complete connectivity alternative unless one new immutable composition owns
   automatic discovery, NAT, hole punching, and connection relay. Each added
   state machine is charged as custom assurance cost.

The next valid connectivity experiment is the already required common
topology corpus, not another local-loopback variant: two distinct LAN hosts for
positive discovery, named NAT pairs, direct-upgrade/hole-punch, owned relay
fallback, relay loss, forced interface/path change, emission packet capture,
and the separate BTLE/tiny-MTU/broadcast composition. It requires preregistered
infrastructure and exact source/graph freezes. No unresolved runtime mechanism
is promoted based on static API evidence.

## Reproduction and integrity

The visible non-normalized summary is
`phase2-connectivity-summary.json` (archived).
Exact manifests, lockfiles, source hashes, commands, binaries, build/run logs,
audit logs, license receipts, and SBOM hashes are listed in
`execution.json` (archived).

Raw `target/`, `trials/`, `sbom/`, and advisory-database trees remain present
locally and ignored. Builds and runs used `--locked --offline`; no dependency
updates, substitutions, git dependencies, public relay, or registry/network
resolution occurred. The historical source-register snapshot recorded in the
summary is the append-only ledger through BVB-768 with SHA-256
`8861e63d8721e905723ddc5b5195dc91184fd80ea87c50bedfc37dff6845efe1`.
It predates the path-only BVB-776 correction. Final synthesis will create
validator envelopes against the ultimately frozen ledger rather than
pretending this historical snapshot is final.
