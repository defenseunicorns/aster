# Requirements-first FOSS candidate register

>
> Research evidence only. This file does not admit a dependency, select an
> architecture, alter product behavior, or grant a requirement claim.
> Public research is permitted under `CONTRIBUTING.md`;
>
> This began as the Phase 0 discovery snapshot. Current execution dispositions
> supersede the earlier hypotheses below where explicitly stated. The concise
> current view is [`final-frontier.md`](final-frontier.md), and arm closure is
> tracked in [`arm-completion-register.md`](arm-completion-register.md).

- Snapshot date: 2026-08-22
- Product authority: [`data-mesh-requirements.md`](../../../data-mesh-requirements.md),
  version 0.1, SHA-256
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Evidence authority: registered direct-primary sources in
  `evidence/SOURCE_REGISTER.csv`
- Existing implementation and compatibility weight: zero. Expected behavior
  comes only from the requirements authority.

## Reading this register

This is a discovery register, not a shopping list. “Buys” means that a source
identifies a potentially reusable mechanism. It does not mean the mechanism has
passed the common corpus, dependency policy, hostile-input review, or an
operating-envelope sweep.

Evidence confidence is deliberately coarse:

| Code | Meaning |
|---|---|
| `E0` | Named discovery target only; source/version or usable implementation is unresolved |
| `E1` | Upstream claim or documentation reviewed |
| `E2` | Exact release/source metadata and license reviewed; dependency graph may still be open |
| `E3` | Locally executed or source-audited in a bounded project experiment |
| `E4` | Hostile/fault or public remediation evidence exists |
| `E5` | Cross-implementation result exists for the claimed behavior |

Disposition terms are `primary arm`, `secondary arm`, `component candidate`,
`daemon experiment`, `oracle`, `hold`, and `exclude from production role`.
Only the last term is an elimination; a candidate can still be retained as a
standard, differential, or conformance oracle.

## Systematic search and project method

1. The requirements were decomposed into independent capability families:
   normative wire/interoperability; replica/convergence; temporal
   dissemination; propagation/resource policy; connectivity/discovery;
   carriers/framing; security/membership; persistence/blobs; embedding/SDK;
   and assurance/operations.
2. Searches used generic requirement terms and public primary authorities:
   IETF RFC Editor/Datatracker, NIST, official package
   registries, official project documentation, official source repositories,
   release pages, security policies, and advisories. One site-restricted
   official-IETF discovery search resolved the Group OSCORE publication-status
   ambiguity; all factual credit rests on the registered primary pages opened
   afterward. The discovery and execution evidence did not use forbidden-source
   comparisons. `BVB-865` separately records a later synthesis-thread search
   exposure to excluded Proposal 0004 fragments; that thread was contained and
   none of its output or derived claims is accepted here. `BVB-909` records a
   separate final-audit allowlist failure that exposed excluded-subtree paths
   and row-width diagnostics only; the auditor made no post-exposure edit and
   all affected audit conclusions are discarded pending clean replacement
   validation and external disposition.
3. The initial discovery additions were BVB-644 through BVB-703. Later exact
   freezes and executions are append-only and cited in the current disposition
   rows and final frontier.
   Some discovery preceded registration; those claims receive no executable or
   selection credit until a post-registration primary-source re-review is
   recorded. BVB-682 preserves an unresolved IPFS page identity; no IPFS
   content or claim is used here.
4. A project is included when it plausibly owns a complete required mechanism,
   is a published interoperability standard, can be exercised as a daemon, or
   can serve as an independent oracle. A name, pub/sub API, DHT, QUIC endpoint,
   database, or codec alone receives no whole-system credit.
5. Before execution, every selected implementation still needs an immutable
   source freeze: exact tag and full commit, release/archive checksum, selected
   features, complete transitive graph, supported targets/MSRV, license texts
   and notices, SBOM, security-policy/advisory snapshot, and build receipt.
6. Production eligibility requires an OSI-approved license, no strong
   copyleft or proprietary component, active identifiable governance, and a
   usable vulnerability-reporting and patch process. Public-domain material is
   a policy hold, not silently an OSI-license pass. Dual licensing is assessed
   on the selected option and the complete transitive graph.
7. Research notes, source receipts, dependency archives, and execution results
   remain evidence artifacts. No candidate source is copied into an
   implementation path during Phase 0.

## Candidate architecture compositions

These are whole-system hypotheses. Several are compositions rather than one
upstream product; each experiment must name exactly one owner, or an explicit
layering relationship, for durable storage, retry, expiry, deduplication,
routing, reconciliation, Blob progress, identity, and membership/rekey state.

| Candidate composition | Exact discovery freeze and license | Governance, maintenance, security evidence | Requirements plausibly bought | Principal gaps and duplicated ownership | Disposition / confidence | Registered primary sources |
|---|---|---|---|---|---|---|
| **A — p2panda-first** | Exact v0.7.1 commit `083b48215964e92a564f3c83a1c607b00e94aa64`; MIT OR Apache-2.0; exact 533-package final graph frozen. | Pre-1.0 project; production governance, target graph, SQLite policy, and admission remain open. | Offline publish/restart/native LogSync-Iroh, one temporal carry, protected opaque carry, range and both final-bakeoff crash checkpoints passed. | Prefix/restart metadata and duplicate-effect findings remain. A-001 timed out during fresh B/C recovery; A-002 reported sender success while the receiver timed out before completion. High-level Node lacks deterministic direct-peer insertion, the registered recovery/post-ack cells did not complete, and the evaluated harness used p2panda SQLite plus task-authored effect files. | **Conditional component and behavior oracle; no longer the selected high-level whole stack**, `E3`; medium bounded-mechanism confidence, low integrated/whole confidence. | BVB-700, BVB-703, BVB-808, BVB-860, BVB-863, BVB-932, BVB-941, BVB-948 |
| **B1 — p2panda operations over BPv7** | Exact p2panda/dtn7-rs adapter composition executed in BVB-724; BP standards and implementation roles are separately frozen. | Inherits both graphs and their production holds. | One signed immutable operation passed a forced one-contact A→B, B restart, one-contact B→C path and entered C's p2panda store. | Adds a second durable store/progress/expiry domain and has not demonstrated a hard outcome beyond Arm A; application assurance, security, policy, Blob resume, custody-like behavior, and interop remain. | **Conditional BP carrier option**, `E3`; add only after a measured hard delta justifies duplicate owners. | STD-020, BVB-702, BVB-724, BVB-794 |
| **B2 — p2panda interactive sync over BPv7** | Exact upstream LogSync/BP composition executed in BVB-724. | Same graph and production holds as B1. | Eventually completed the bounded operation exchange. | Failed the one-pass topology and required four waves, three B restarts, seven directed declarations, six bundles, and live endpoint session state. | **Stop/cost arm**, `E3`; do not carry forward absent a new hard requirement that operations cannot satisfy. | BVB-724 |
| **C — BPv7 plus a thin data profile** | Exact thin one-operation profile executed in BVB-724; Hardy and dtn7 independently executed temporal relays in BVB-702/BVB-794. | Standards governance is strong; runtime admission remains implementation-specific. | One-pass temporal carriage and published BPv7 lifetime/fragmentation/security building blocks. | Replica convergence, all four classes, application assurance, policy, source/metadata security, membership, Blob resume, API/bindings, and conformance remain mostly original work. | **Standards-first control**, `E3` for the tiny executed slice; not a current finalist. | STD-020, BVB-648–652, BVB-702, BVB-724, BVB-794 |
| **D — Zenoh plus a local-first overlay** | Exact Zenoh 1.10.0 and storage graph executed in BVB-728/BVB-853; EPL-2.0 OR Apache-2.0. | Eclipse governance; production target/admission still open. | Routing/configuration/API/QoS/RocksDB mechanics plus a bounded immutable-key encrypted sibling overlay that survived duplicate put, restart/contact, and isolated recovery. | Native same-key concurrent values collapsed; the passing custom overlay owns immutable keys, identity, encryption, sibling/conflict semantics, and application-effect gating, so it reintroduces the central replica contract. | **Conditional routing/replication/storage component; stop as a whole-stack finalist**, `E3`. | BVB-620–621, BVB-646–647, BVB-728, BVB-853, BVB-857 |
| **E — Willow-centered protocol family** | Living Willow specification family plus current Codeberg `willow_rs` commit `9266a735b439cdfe3fec3686e105c37f888c2469`; `willow25` 0.7.5, MIT OR Apache-2.0. The 180-package workspace and 161-package evaluator graphs contain zero git dependencies. | Current source was committed 2026-08-22 and passed 289 selected upstream tests. Exact governance, release cadence, security-response process, transitive admission, and independent implementation remain open. | Executable entry/namespace/path model, Meadowcap-style delegated capabilities, persistent and payload-prefix stores, verified-stream primitives, and Drop export/import. BVB-738 passed a bounded three-process offline Drop/restart, duplicate-import, and tamper exercise. Confidential Sync and WTP remain specification-only in the frozen crate. | Native recency is timestamp-first and therefore cannot own causal State/Record conflict arbitration. Four exact classes, priority/TTL/quota/emission/bridges, live sync, temporal relay, membership/rekey, NIST hybrid PQ/FIPS, BTLE/IP/NAT, C ABI/bindings, and independent conformance remain outside the implementation. | **Advance as storage/capability/Blob/Drop component arm; hold as whole replica.** `E3` for bounded Drop behavior, `E2` for exact implementation, `E1` for unimplemented protocol designs. | [BVB-668–673](https://willowprotocol.org/specs/), [BVB-729](https://codeberg.org/worm-blossom/willow_rs.git), BVB-734, BVB-738 |
| **F — Veilid-centered overlay** | Exact Veilid 0.5.7 graph executed under BVB-762; MPL-2.0. | Exact graph carried advisory and maintenance holds. | Local DHT create/write/read plus clean restart and persistent identity/store passed. | Frozen public API rejected loopback dial information as having no routing domain; two-node retrieval and all mesh semantics remained unproved. | **Local-store/lifecycle oracle; stop as current whole-stack arm**, `E3` for local-only slice. | BVB-622–623, BVB-719, BVB-762 |
| **G — greenfield FOSS components** | Final 374-package zero-git/path graph combines exact Iroh 1.0.3, Negentropy 0.5.1, redb 4.2.0, SHA2 0.11.0 and Tokio 1.53.1; Automerge, security, Blob, SDK and assurance slices are separately frozen. | Aggregate governance, support, target, license, security-provider and long-term ownership remain composition-specific. | BVB-922 passed authenticated-Iroh divergent reconciliation, restart, A-absent temporal carry, both crash windows, atomic item/effect state, recovery without duplicate fixture effects, and final duplicate no-op; prior negative-frame/component/cross-product cells also passed. | Normative frame/four classes, durable session progression, hostile bounds, mission security/policy, Blob lifecycle, power-loss, physical/target and independent conformance remain custom/open. | **Selected bounded research baseline, not production-selected**, `E3`; high confidence for the exact integrated local recovery corpus, low complete-stack confidence. | BVB-725, BVB-768, BVB-801–807, BVB-852, BVB-859, BVB-861, BVB-922, BVB-948 |

## First executable and source-surface updates

- **p2panda v0.7.1 remains a valuable minimum-custom component/oracle but is
  not the selected high-level stack.** Exact commit
  `083b48215964e92a564f3c83a1c607b00e94aa64` and a 533-package runner graph
  were frozen. BVB-700 passed offline publish, separate-process restart replay,
  and later direct local synchronization. BVB-703 then passed A→full-replica B,
  complete B process exit/restart from the same SQLite state, and B→C while A was
  absent; C received the same A-authored operation. This is bounded native
  temporal-carry credit only for that subscribed full-replica composition. It is
  not general DTN, relay-only, payload-blind, duplicate/loop, security, routing,
  expiry, priority/quota, hostile-fault, or production evidence (`BVB-700`,
  `BVB-703`). BVB-808 later passed the protected fixed-fixture temporal path
  and bounded cycle/conflict probes, while finding duplicate application events
  and no Record conflict surface. BVB-860/863 then passed range and
  crash/replay slices but found the prune/restart metadata failure and mapped
  missing or unwired State/Record, auth/encryption/Spaces, causal, and Blob
  surfaces. The final A-001 run then passed initial native reconciliation,
  restart, first temporal contact, and both crash checkpoints but timed out on
  fresh recovery; A-002 exposed sender-success/receiver-timeout before initial
  receiver completion. The G comparator completed the full recovery and
  recovery-without-duplicate-fixture-effect sequence, so corrected `BVB-948`
  selects G as the bounded baseline.

## Terminal synthesis qualification

- **Phase 0 remains partial.** The landscape and selected freezes are useful,
  but the work order's complete greenfield-native
  discovery/NAT/relay/runtime/resource freeze, reproducible ordinal anchors,
  and preregistered per-arm engineer-day caps do not exist. No post-hoc effort
  estimate is substituted.
- **Phase 2 has asymmetric architecture-collapse evidence.** Iroh has local,
  manual cross-product, and terminal one-kernel topology execution. rust-libp2p
  remains a source/behavior oracle on advisory, discovery, and connection-owner
  hold; Quinn/greenfield remains a narrow local control with no complete
  discovery/NAT/relay owner. The latter two did not receive a full higher-level
  collapse runtime.
- **Phase 4 and Phase 5 are terminal but mixed.** BVB-825/BVB-835 establish a
  bounded non-FIPS integrated security shape, not normative hybrid or
  production security. BVB-844 records physical/environment blocks, two
  broadcast failures, a critical-extension profile/conformance failure,
  license-fixture failure, and product-surface blocks.
- **The frozen Group OSCORE + ACE executable lane is stopped, not the standards
  lane.** libOSCORE and Californium both contain pairwise OSCORE implementations;
  neither frozen revision contains Group OSCORE, ACE/Group Manager, group rekey,
  countersignature processing, durable group replay, or a hybrid-PQ boundary.
  RFC 9594 and the registered Group OSCORE transition text remain reusable
  semantic candidates, but these repositories cannot buy the whole profile
  (`BVB-701`).
- **BPv7 temporal dissemination is now executable evidence, but not a complete
  security/delivery buy.** dtn7-rs at
  `c30181b4b111e2adc5538931c797c0f7190acc4c` durably carried an item A→B,
  survived B restart, and later delivered byte-identical content B→C while A
  was absent. Its durable store contained payload plaintext, so temporal relay
  passed while payload-blind relay failed for that composition. Hardy at
  `b87c790263392a6289f942e6bf59fdb714f4c842` built as an embeddable BPv7/BPSec
  candidate and passed 113 library/vector tests. BVB-794 later ran Hardy's own
  BPA through the same non-overlapping temporal topology and found plaintext in
  B's durable file. Application assurance, BPSec policy, priority,
  duplicate/loop bounds, and custody-like behavior remain separate
  (`BVB-702`, `BVB-794`).

## Published protocol and standard candidates

| Standard/profile | Role and semantic credit | Important non-credit or gap | Status / source |
|---|---|---|---|
| **BPv7 — RFC 9171** | Application-layer disrupted-network bundle protocol: temporal store-carry-forward, lifetime, fragmentation, endpoint and extension framework. | Does not ensure delivery; application assurance remains composed. Base BPv7 removed predecessor QoS markings, and custody-like behavior is not a base-protocol credit. The exact BIBE/custody extension and selected implementation support remain a source-freeze gap. | Standards candidate, `E2`; [STD-020](https://www.rfc-editor.org/rfc/rfc9171.html) |
| **BPSec — RFC 9172 + default contexts RFC 9173** | Bundle integrity/confidentiality services and default security contexts. | No key management, application authorization policy, hybrid-PQ profile, disconnected membership/rekey, or proof that the chosen implementation supports the required contexts. BPSec is not automatically the requirement's source-object plus mesh-metadata two-layer profile. | Standards candidate, `E2`; [BVB-648](https://www.rfc-editor.org/rfc/rfc9172.html), [BVB-649](https://www.rfc-editor.org/rfc/rfc9173.html) |
| **TCPCLv4 — RFC 9174** | Standard BP TCP convergence layer and an interoperability target. | IP-only, connection-oriented convergence layer; no BTLE/broadcast/file credit and no durable delivery assurance. | `E2`; [BVB-650](https://www.rfc-editor.org/rfc/rfc9174.html) |
| **BP administrative and endpoint updates — RFC 9713/9758** | Current administrative-record registry and `ipn` URI updates. | An implementation that only claims RFC 9171 must be checked against these updates; neither supplies data-class/policy semantics. | `E2`; [BVB-651](https://www.rfc-editor.org/info/rfc9713/), [BVB-652](https://www.rfc-editor.org/info/rfc9758/) |
| **Deterministic CBOR + CDDL — RFC 8949/8610** | Compact language-neutral encoding and schema language for an independent normative wire profile. | Generic CBOR/CDDL does not impose hostile-input bounds, canonical application rules, semantic versioning, or evolution policy. | Candidate standard with named Rust codec below; [STD-001](https://www.rfc-editor.org/rfc/rfc8949), [STD-019](https://www.rfc-editor.org/rfc/rfc8610.html) |
| **COSE — RFC 9052; ML-DSA identifiers — RFC 9964** | Standard security-object encoding and post-quantum algorithm identifiers. | Encoding is not crypto, key lifecycle, authorization, metadata policy, or FIPS validation; `coset` is still an implementation candidate, not a provider. | Standards/oracle; [STD-013](https://www.rfc-editor.org/rfc/rfc9052.html), [BVB-492](https://datatracker.ietf.org/doc/rfc9964/) |
| **HPKE — RFC 9180** | Published KEM/KDF/AEAD composition for recipient encryption and domain separation. | Base suites are not automatically the required hybrid classical+PQ suite and do not solve group membership, replay, revocation, or forwarding metadata. | Bounded security-profile candidate; [STD-023](https://www.rfc-editor.org/rfc/rfc9180.html) |
| **MLS — RFC 9420** | Standard group epochs, add/remove, forward secrecy and post-compromise-security model with Rust implementations below. | Connected delivery-service assumptions, offline concurrent forks, route-only relays, PQ ciphersuite maturity, source-object format, and FIPS module scope need proof. | Experiment/oracle; [BVB-087–106](https://www.rfc-editor.org/rfc/rfc9420.html) |
| **ACE group key provisioning — RFC 9594; Group OSCORE transition profile** | Standards candidate for authorization, join, rekey, multicast/group protection, source authentication, and replay handling in constrained groups. | No proven RFC 9594/Group OSCORE Rust implementation or mapping to disconnected mission identity and data encryption. The RFC Editor AUTH48 transition page labels Group OSCORE as RFC 10021, Standards Track, July 2026, but both canonical RFC endpoints still return 404; it receives candidate-semantic credit, not settled final-publication credit. | ACE `E2`; Group OSCORE transition candidate `E1`; [BVB-676](https://www.rfc-editor.org/rfc/rfc9594.html), BVB-677–678, BVB-697–699, BVB-683–684 |
| **NIST crypto and module standards — FIPS 197, 180-4, 186-5, 203, 204, SP 800-56A/56C/227, FIPS 140-3** | Normative algorithm and validation anchors for classical and PQ encryption, hashing, signatures, KEM, KDF, and module validation. | Standardized algorithm, implementation, validated module, approved operational environment, and validated final composition are separate claims. | Hard-profile authority; STD-002–012 |
| **TLS 1.3 — RFC 8446** | Mature secure connected-session standard; possible authenticated carrier protection. | Transport/session protection does not satisfy source-object protection, relay opacity, mesh metadata protection, or disconnected revocation. | Connectivity/security component standard; [STD-022](https://www.rfc-editor.org/rfc/rfc8446.html) |
| **ICE/STUN/TURN — RFC 8445/8489/8656** | Standards-based NAT discovery/traversal and connection relay, with coturn daemon candidate below. | TURN is a connection relay, not a durable temporal relay; standards do not supply a selected Rust client, mission authorization, or local-offline semantics. | Greenfield connectivity family; [STD-015–017](https://www.rfc-editor.org/info/rfc8445/) |
| **mDNS/DNS-SD — RFC 6762/6763; Trickle — RFC 6206** | Local automatic discovery and broadcast-suppression building blocks. | Discovery hints are not peer authorization; advertisements must be suppressible by emission policy and metadata leakage must be measured. | Carrier component standards; [STD-021](https://www.rfc-editor.org/rfc/rfc6206.html), [STD-024–025](https://www.rfc-editor.org/rfc/rfc6762.html) |
| **Willow / Meadowcap / Confidential Sync / WTP / Drop Format** | Published local-first namespace, capability, private-sync, transfer, and offline-media designs. Exact `willow25` 0.7.5 implements the entry/capability/store/payload-prefix/Drop subset and passed the bounded BVB-738 Drop run. | Specification text license and stability, executable Confidential Sync/WTP, causal four-class profile, mission policy/security, and independent interop remain open. Native timestamp pruning is an explicit semantic mismatch. | Executable component plus design oracle, `E1–E3`; BVB-668–673, 729, 734, 738 |

## Embeddable libraries and component families

### Replica, convergence, storage, and wire

| Candidate | Role, exact freeze, license, and evidence | Requirements bought | Gaps / disposition |
|---|---|---|---|
| **p2panda package family** | v0.7.1 release (`083b482`), MIT OR Apache-2.0; detailed docs reviewed at 0.7.0/0.7.x. Pre-1.0 and no registered security channel. `E2`; `E3` only for the bounded executed slices. | Largest Rust local-first composition candidate: node orchestration, sync, logs, discovery/network, named store/stream/blob/auth/encryption/spaces packages, and bounded full-replica temporal carry of one native operation. | Tag-to-doc and per-crate source freeze; exact ownership for every requirement; no general DTN, relay-only, payload-blind, duplicate/loop, policy, hostile-fault, security, or production credit. **Leading Arm A, not a generic drop-in.** BVB-177–179, 619, 644–645, 700, 703. |
| **Automerge** | Exact 0.11.0 graph, MIT; bounded corpus executed in BVB-756. `E3`. | JSON-like document CRDT and per-document sync for an opt-in Record merge policy; concurrent edits and reload were exercised. | Does not implement State/Event/Blob, propagation, temporal dissemination, auth, priority, or general mesh sync. **Buy only for explicitly opted-in Record merge policy.** BVB-180–182, BVB-756. |
| **rust-crdt** | 7.3.2, Apache-2.0; last registered push 2024-06-16 and no SECURITY.md found. `E1`. | Vector-clock compare/join and CRDT reference behavior. | Does not own trust domains, hostile bounds, persistence, pruning, wire, or lifecycle. **Oracle/narrow helper; production maintenance hold.** BVB-580. |
| **Negentropy** | 0.5.1, MIT, exact two-package graph; source-audited and executed in BVB-801. `E3`. | Difference-oriented identifier reconciliation. With fixed Δ=20, bytes grew only 3.42× while N grew 1000×. | At high divergence it exceeded full two-sided ID exchange; it does not transfer objects or own durable replica state, causality, auth, resume, or hostile cardinality. **Buy narrowly with a bounded bulk fallback.** BVB-547–554, BVB-795, BVB-799, BVB-801. |
| **Bitcoin Core Minisketch** | Commit `4a179c61e3cbe3ac2b3c027764ce8eb5183155e1`, MIT; no tagged release and no detected security policy. `E2`. | Very compact sparse-difference reconciliation control. | Capacity estimate, salting/collisions, false-positive budget, exact fallback, 264-bit identity mapping, C/C++ FFI and mobile coverage. **Future oracle/component experiment.** BVB-555–568. |
| **redb** | 4.2.0, MIT OR Apache-2.0, exact graph and crash/curve corpus in BVB-768. `E3`. | Pure-Rust ACID/MVCC durable metadata and protocol-state store; led the greenfield store comparison. | One-writer behavior; no replication, schema, GC, quotas, encryption, or policy. Redb mmap Blob-byte storage scaled RSS with Blob size and is not the recommended byte layout. **Greenfield metadata/state buy; do not add beside a framework-owned store without deleting an owner.** BVB-192–198, BVB-758, BVB-763, BVB-768. |
| **rusqlite + SQLite** | rusqlite 0.40.2 (MIT) with libsqlite3-sys 0.38.2 and bundled SQLite 3.53.2; current SQLite review found 3.53.4. SQLite is public domain, not an OSI license. Extensive upstream assurance/security docs. `E2–E3`. | Mature transactional local database, WAL/atomic-commit and defensive controls. | Public-domain dependency requires explicit policy disposition; single-writer/checkpoint constraints; application schema, quotas, metadata confidentiality, Blob streaming, migrations and replication remain composed. **Storage candidate on policy hold.** BVB-183–212, 236, DEP-013–014. |
| **minicbor** | 2.3.0, checksum `c12b4033ffaa92fbf9df03df38d19324f52bad130dd223f811734a8006dd2d69`, BlueOak-1.0.0 (OSI approved). `E3` in existing bounded use. | Rust CBOR encoding/decoding mechanics. | Does not define canonical profile, size/depth/allocation limits, schema semantics or version evolution. **Wire-mechanics candidate.** DEP-001, BVB-002–003, 302, 494. |
| **cddl validator** | Main snapshot, version/license unresolved. `E1`. | Independent schema validation in conformance/CI. | Dynamic validator must not replace bounded hostile-input decoder; exact license/revision required. **Test-only oracle hold.** BVB-495. |

### Connectivity, discovery, NAT, and carriers

| Candidate | Role, exact freeze, license, and evidence | Requirements bought | Gaps / disposition |
|---|---|---|---|
| **Iroh** | 1.0.3, released 2026-07-20; MIT OR Apache-2.0; Rust 1.91. Exact 501-package topology graph was acquired, inventoried, materialized, and built offline under production license-text/metadata holds. `E3`. | Authenticated QUIC endpoint/EndpointId, ALPN router, streams, path change, direct connectivity, self-hostable relay, local mDNS, resource controls; BVB-904 passed relay-first to direct upgrade, ping, and close in all 13 supported Patchbay namespace/NAT pairings. | Three upstream-ignored hard-cross pairings stayed relayed and timed out direct waits; test-relay TLS was insecure. Endpoint identity is not mission identity; no temporal relay, four-class replica, policy, security/membership, physical/public/ISP/CGN, endurance, or production credit. **Conditional leading IP mechanism.** BVB-624–625, 639–642, BVB-891, BVB-898, BVB-904. |
| **rust-libp2p** | Latest registered aggregate 0.56.0, MIT. Frozen component graph includes swarm 0.47.1, identity 0.2.14, AutoNAT 0.15.0, DCUtR 0.14.1, Identify 0.47.0, mDNS 0.48.0, relay 0.21.1, QUIC 0.13.1, TCP 0.44.1, Noise 0.46.1 and Yamux 0.47.0. `E2–E3`. | Multi-peer Swarm, transport/protocol negotiation, LAN discovery, reachability, connection relay/direct upgrade, address routing, limits, and idiomatic higher-level behaviors. | No durable temporal relay/replica semantics; mission identity/policy/security mapping; explicit bounds; selected mDNS graph reaches RUSTSEC-2026-0119 and Linux paths reach unmaintained `paste`; automatic discovery and connection mapping did not clear. Its idiomatic request-response and pub/sub modules remain libp2p-owned source candidates only: neither was placed under exact application limits, executed, or credited, and no full architecture-collapse runtime exists. **Source/behavior oracle on hold.** BVB-142–149, 614, 630–638, 643, BVB-780. |
| **Quinn** | 0.11.11, MIT OR Apache-2.0; selected compatible `quinn-proto` 0.11.17, above patched 0.11.15 floor. Active project with disclosed/fixed DoS history. `E2–E4`. | Focused Rust QUIC streams/datagrams, no-I/O protocol core, strong bounded local rebind control, and byte-exact carriage in BVB-852. | No discovery, NAT traversal, relay, mission identity, temporal store-forward, replica or policy semantics; no full architecture-collapse runtime. **Narrow greenfield IP control.** BVB-155–159, 213–224, BVB-780, BVB-852. |
| **Tokio** | 1.51.4 LTS, MIT; active releases and private security policy. `E2`. | Bounded async runtime, scheduling, queues/readiness and host resource-control primitives. | No network or mission semantics; must avoid idle polling and unbounded tasks/state. **Greenfield runtime candidate.** BVB-138–141. |
| **coturn** | Master snapshot; BSD-style license reported, exact version/license text/transitive graph pending. `E1`. | Operated standards-based STUN/TURN relay infrastructure. | No selected Rust ICE client, mission authorization, temporal relay, offline-local guarantee, or durable state. **External connection-relay daemon candidate; hold until frozen.** BVB-467–468. |
| **BlueR** | 0.17.4, upstream license needs exact admission review; official BlueZ Rust bindings. `E1`. | Linux central/peripheral GATT, advertising, L2CAP and Tokio controller access. | Linux-specific; no mission air profile, fragmentation, broadcast optimization, emission suppression, cross-platform behavior or hardware evidence. **Linux BLE adapter candidate.** DEP-012, BVB-162–163, 465. |
| **TrouBLE** | Main snapshot, Apache-2.0 OR MIT; exact release/revision and qualification matrix pending. `E1`. | Rust embedded BLE host-stack mechanics for future MCU/embedded adapter work. | Maturity, controller/target coverage, certification and requirement air profile unproven. **Bounded adapter pilot.** BVB-466. |
| **btleplug** | 0.12.0, BSD-3-Clause. `E1`. | Cross-platform Bluetooth host/central access. | Upstream describes host/central mode only; cannot alone meet two-way peer/peripheral requirement. **Exclude as sole BLE adapter; retain as platform oracle.** BVB-160. |

### Identity, cryptography, group state, and policy mechanics

| Candidate | Role, exact freeze, license, and evidence | Requirements bought | Gaps / disposition |
|---|---|---|---|
| **aws-lc-rs / AWS-LC** | 1.17.3 (`9232f4d`) maps to active AWS-LC FIPS 3 certificate 5314; 1.18.0 (`f464440`) begins a FIPS-4/ML-DSA transition not yet certified in registered evidence. Apache-2.0 AND ISC; security policies/releases registered. `E2–E4`. | Reviewed cryptographic provider APIs, ML-KEM support, classical primitives and a documented validated-module route. | Safe Rust ML-DSA/provider coverage, hybrid protocol composition, operational-environment match, source-object format, downgrade, key custody, group state and final FIPS validation remain. **Primary crypto-provider experiment; no blanket FIPS claim.** BVB-035–054. |
| **OpenSSL** | Current registered source page lists 4.0.1, 3.6.3 and 3.5.7; Apache-2.0. Only 3.1.2 was listed as FIPS 140-3 validated in that review. `E2`. | Mature provider architecture; OpenSSL 3.5 docs expose ML-KEM/ML-DSA APIs. | Current code support is not validated-module coverage; Rust/native integration, platform, exact provider/certificate and final composition require proof. **Alternate provider/daemon-class dependency experiment.** BVB-055–063. |
| **OpenMLS** | 0.8.1, short commit `47dbede`, MIT; public security page and a 0.7.0 persistence advisory patched in 0.7.1. `E2–E4`. | Executable RFC 9420 group epoch/add/remove/secret-tree mechanics. | Offline forks, delivery-service assumptions, route-only nodes, requirement PQ/FIPS profile, source data encryption, compact carrier use and persistent recovery. **Group-state comparator.** BVB-094–101. |
| **mls-rs** | 0.55.3 on registered main, Apache-2.0 OR MIT; security page exists, but no release page entries were observed. `E1–E2`. | Second Rust MLS implementation/conformance comparator. | Exact archive/tag, release practice, PQ/FIPS provider, offline fork/recovery and application mapping. **Comparator/possible component; hold.** BVB-102–106. |
| **coset / t_cose** | Exact `coset` 0.4.2 graph is Apache-2.0 and executed in BVB-725. Exact `t_cose` v1.2.0, commit `98e34ed6403f01e1779fcfe84debc7c4dd6ed75f`, is BSD-3-Clause and source-frozen in BVB-717/BVB-718. `E3`/`E2`. | `coset` buys Rust COSE Sign/Encrypt object mechanics; `t_cose` is an independent classical Sign1 surface. | Neither supplies key lifecycle or the mission profile. Exact t_cose v1.2.0 has no COSE_Sign multiple-signature/encryption owner for this lane; the earlier multiple-signature wording referred to a separate 2.x development line. **Buy coset mechanics; retain t_cose as classical oracle only.** BVB-717–718, BVB-722–725. |
| **RFC 9594 + Eclipse Californium** | RFC 9594 is Standards Track. Californium main documents stable 3.14.0 and milestone 4.0.0-M6; exact license and relevant ACE/OSCORE module support unresolved. `E1–E2`. | Potential constrained group provisioning and independent Java interoperability path. | Registered evidence does not prove the required ACE/Group-OSCORE profile; no Rust implementation or disconnected mission mapping. **Standards/oracle candidate only.** BVB-676–681. |
| **libOSCORE** | Read-only GitHub mirror snapshot, BSD-3-Clause; exact revision/release not frozen. The mirror names a canonical GitLab location that was not separately opened. `E1`. | Candidate C implementation with Rust backend/wrapper areas named in the upstream repository tree. | No build, exact Group OSCORE/profile support, Rust API maturity, interoperability, disconnected group lifecycle or security-response evidence. It cannot establish implementation support for the Group OSCORE transition profile. **Implementation research/oracle hold.** BVB-683–684, 697–699. |
| **Governor** | Main snapshot, MIT; exact version/security/dependency freeze open. `E1`. | Generic pre-auth discovery/handshake/relay admission rate limiting. | Does not bound attacker-created key cardinality, expiry, prefix aggregation, fairness, mission authorization, quotas or emission. **Narrow policy-mechanics candidate.** BVB-462. |
| **Tower** | Main snapshot, MIT; exact release/graph open. `E1`. | Timeout, concurrency, load-shed and retry middleware for a local control plane. | Request/response model is not the streaming/disrupted data plane and does not define mission policy. **Control-plane-only candidate.** BVB-461. |

### SDK, FFI, observability, packaging, and assurance

| Candidate | Exact freeze / license | Useful mechanism and boundary | Disposition / evidence |
|---|---|---|---|
| **cbindgen** | 0.29.4, commit `b826cb8911488fe8a209d2b693492c0c673e8cca`, MPL-2.0 | C-header generation and deterministic drift check; does not define ABI stability, ownership, panic, threading, or packaging. | **Buy generator**, bounded `E3` execution in BVB-781. |
| **UniFFI** | 0.32.0, commit `5c7b73906358e1a7acdc1bdc7bf5cd86fb27e44c`, MPL-2.0 | Swift/Kotlin binding generation. No Go binding or native-artifact packaging. | **Buy binding generator/pattern**, bounded `E3` execution in BVB-781. |
| **tracing** | 0.1.44, MIT; Tokio security policy and active correction history | Structured spans/events/fields and filtering behind an explicit typed redaction contract. Automatic argument capture is a metadata-leak risk. | Host observability candidate; `E2–E4`, BVB-025–027, 583–585. |
| **OpenTelemetry Rust** | 0.32.0, commit `ec289cb3c6f8260951699c51df968560943c1451`, Apache-2.0 | Optional external telemetry export. Must stay outside deterministic core and preserve redaction/offline operation. | Operations candidate; `E2`, BVB-028–029. |
| **cargo-cyclonedx / cargo-deny / cargo-audit** | 0.5.9 / 0.20.2 / 0.22.2; Apache-2.0 or Apache-2.0 OR MIT | SBOM, source/license policy and RustSec checks. They evidence the selected graph, not upstream runtime correctness. | Required assurance tooling; existing registered tools, TOOL-004–006. |
| **Proptest / Loom** | 1.11.0, MIT OR Apache-2.0 / 0.7.2, MIT | Property invariants and bounded concurrency exploration. | Test dependencies/candidates; `E2–E3`, BVB-014–017. |
| **Turmoil / Toxiproxy / Containerlab+netem / Testcontainers-rs** | Main snapshots; MIT / MIT / Apache-2.0 / Apache-2.0 OR MIT; exact revisions open | Deterministic async faults, real-process TCP faults, Linux topologies/impairments, and daemon fixtures. None replaces physical BLE/RF or independent interoperability. | Test-only candidates; `E1`, BVB-463–477. |

BVB-781 freezes and executes cbindgen/UniFFI generation plus a bounded tonic
local-agent fixture; BVB-787 freezes a dual-decoder deterministic-CBOR seed
corpus. Production packaging, ABI lifecycle, a compact disconnected
mission-policy implementation, and an independent spec-built conformance
implementation remain open. These are composition gaps, not permission to
hand-roll mechanics already bought by the exact tools.

## Daemon and service candidates

| Candidate | Role and exact source status | License / governance / security evidence | Requirements bought and gaps | Disposition / confidence | Sources |
|---|---|---|---|---|---|
| **dtn7-rs** | Exact untagged head `c30181b4b111e2adc5538931c797c0f7190acc4c`, 22 commits after v0.21.0; lock and archive frozen in BVB-702. | MIT OR Apache-2.0. No repository security policy was found. Versions affected by five vulnerability advisories plus selected unmaintained/unsound warnings are present in the frozen host closure; exploit-path reachability was not assessed, so production admission remains blocked. | Executed durable temporal relay: A→B, B restart, later B→C with A absent. Plaintext was present in B's store; BPSec remains not advertised/unknown. Application assurance, priority, duplicates/loops, custody-like behavior, and security profile remain open. | **Useful daemon/oracle; production hold**, `E3` for temporal relay only. | [BVB-653–655](https://github.com/dtn7/dtn7-rs), BVB-692, BVB-702 |
| **Hardy** | Exact untagged head `b87c790263392a6289f942e6bf59fdb714f4c842`; selected library and File-CLA BPA graphs, lock, and archive frozen in BVB-702/BVB-794. | Apache-2.0; public private-reporting policy exists. The selected host closure had no vulnerability finding against the frozen RustSec snapshot; target and response-history admission remain open. Bundled SQLite remains on the literal OSI-license policy hold. | Embeddable BPv7/BPSec library passed 113 tests; the BPA independently passed A→B, full B exit/restart, B→C with A absent and exact echo consumption. B's durable file exposed the marker. No BPSec application policy, priority, duplicate/loop, custody/BIBE, or independent interop credit. | **Embeddable BP component and second temporal oracle; production hold**, `E3`. | BVB-657–659, BVB-686, BVB-702, BVB-794 |
| **NASA/JPL ION** | NASA/JPL DTN implementation and possible `ion-core`; exact candidate release/revision pending. Registered deployment material and an ION 4.1.2 BPSec security-policy manual, also mirrored under 4.1.4-a.2 documentation, establish a configuration/policy investigation surface—not current-version support. | NASA/JPL governance; exact license and dependency/export/redistribution disposition pending. Public GHSA exists, but exact affected/patched versions must be frozen. | Independent BP/BPSec daemon and interoperability candidate. Embeddability, Tier-2 footprint, exact executable contexts/extensions/conformance and operational complexity require evidence. | **Daemon experiment + interoperability oracle; production license/security hold**, `E1` plus registered advisory/policy documentation. | [BVB-660–664](https://github.com/nasa-jpl/ION-DTN), BVB-688–691 |
| **NASA HDTN** | NASA high-rate DTN implementation; exact release/revision pending. | Apache-2.0; NASA governance and release page; transitive graph and vulnerability channel still open. Its main changelog records a BPSec decoding correction, which is upstream maintenance evidence only and not a FIPS or conformance result. | Independent high-rate BP daemon/performance/interoperability candidate. Embeddable Tier-2/BTLE fit and exact forwarding, BPSec, reports, fragmentation, priority and custody-like support must be measured. | **Daemon experiment + oracle**, `E1–E2` plus correction history. | [BVB-665–667](https://github.com/nasa/HDTN), [BVB-687](https://github.com/nasa/HDTN/blob/main/CHANGELOG.md) |
| **Zenoh router/storage plugins** | Zenoh 1.10.0 project; daemon/API docs reviewed at 1.9.0. | EPL-2.0 OR Apache-2.0; Eclipse project/roadmap. | Routing, pub/sub/query, configuration and optional storage. Does not by itself prove offline durable convergence or encrypted local-first semantics. | **Arm D daemon experiment**, `E1–E2`. | BVB-620–621, 646–647 |
| **coturn** | Self-hosted STUN/TURN server; exact release pending. | BSD-style claim; exact license/security/dependencies pending. | Connection-relay fallback only; no client ICE, temporal relay or mission auth. | **Greenfield connectivity daemon hold**, `E1`. | BVB-467–468 |

## Differential, conformance, and design oracles

| Oracle | Narrow claim it can independently test | Boundary |
|---|---|---|
| **bp7-rs** | BPv7 encoding/decoding against another implementation. Apache-2.0 OR MIT; exact revision/release pending. | Upstream explicitly describes codec work, not transmission or full bundle processing. **Codec oracle**, BVB-656. |
| **ION and HDTN** | Independent BP/BPSec wire, configuration, forwarding, and performance behavior once exact versions/features are frozen. | Policy manuals and changelog corrections are upstream evidence, not conformance or Rust-embeddability proof. Daemon results cannot establish requirement policy/security semantics. BVB-660–667, 687–691. |
| **Willow specifications and current willow_rs** | Namespace/capability/private-sync/transfer/drop-format mapping; current Rust encoding, store, authorisation, payload-prefix, and Drop behavior. | Confidential Sync and WTP are not implemented in the frozen 0.7.5 crate; no independent implementation exists in this freeze. Use current Codeberg source for executable evidence and the archived GitHub repository only as a historical ref index. BVB-668–675, 729–730, 734, 738. |
| **Negentropy and Minisketch** | Independent delta/reconciliation behavior and wire-efficiency controls. | Probabilistic/hostile-input and integration gaps remain; neither is a complete sync protocol. BVB-547–568. |
| **Automerge and rust-crdt** | Record-merge and causal compare/join differentials. | Opt-in data-class oracle only; not a data mesh. BVB-180–182, 580. |
| **CDDL validator, coset, t_cose, Californium, libOSCORE** | Schema/COSE/group-security codec or cross-language checks after exact source freeze. | t_cose's v1.2.0/BSD-3-Clause identity is qualified, but its exact tag and graph remain; other exact licenses/releases/profile support are unresolved. None is a cryptographic or policy authority by itself. BVB-493, 495, 679–685. |
| **Requirements-derived common corpus** | Independently exercises the same observable requirement outcomes across candidates. | It is evaluator work, not a candidate, protocol authority, or substitute for a second independently spec-built implementation. |

## Exclusion and hold register

| Candidate/class | Production disposition | Reason and possible retained role |
|---|---|---|
| **Proprietary or non-OSI dependencies; strong-copyleft dependencies** | **Exclude** | Directly contradicts §8. A dual-licensed project is eligible only through a verified permitted option and permitted transitive graph. A prohibited implementation is not rescued by putting it behind a daemon or FFI. |
| **Any material on the definitive project exclusion list** | **Do not search, open, compare, or use** | Project prohibition is stronger than technical relevance. It receives no oracle role. |
| **Unregistered, secondary-only, or unresolved-source material** | **Hold** | No factual or selection credit until a direct primary source is registered. BVB-682 preserves an unresolved IPFS page and explicitly prohibits reliance; a future evaluation starts with a fresh registered source. |
| **willow-rs archived GitHub repository** | **Exclude only the archived repository from current-production evidence** | The archive is a historical ref index. The moved Codeberg repository is now frozen separately and receives current component evidence under BVB-729/734/738; it remains unadmitted pending the complete dependency, governance, security, and target review. |
| **minisketch-rs 0.1.9** | **Exclude, including current lab integration** | Registered source audit found stale bundled native source, native-toolchain burden, and memory-unsound safe buffer APIs. Current upstream Minisketch may remain a commit-pinned C oracle. BVB-559–563. |
| **btleplug as the sole BLE adapter** | **Exclude from sole-adapter role** | Host/central-only documented role cannot cover symmetric peer/peripheral behavior. It may remain a platform oracle. BVB-160. |
| **SQLite as an automatic §8 license pass** | **Hold** | Public-domain status is not an OSI-approved license. Use requires an explicit dependency-policy disposition; this is not a technical rejection. BVB-189. |
| **cddl validator, coturn, BlueR, libOSCORE, Californium, ION production roles** | **Hold** | Exact license expression/text, release/revision, transitive graph, profile support, and/or security evidence remains incomplete. `t_cose` is removed from this exact-license hold by BVB-685, but remains unadmitted pending its immutable tag and graph. Research/oracle roles stay open. |
| **A protocol-only or daemon-only candidate represented as an embeddable FOSS dependency** | **Exclude the false role, not the candidate** | Standards, daemons, libraries, and oracles are scored separately. A later exact implementation can change the classification. |

## False-equivalence warnings

- A connection relay (Iroh/libp2p/TURN) is not a durable temporal relay
  (BP/store-carry-forward).
- Pub/sub, gossip, DHT replication, or a router is not four-class causal
  convergence or difference-proportional anti-entropy.
- BPv7/BPSec standards are not executable FOSS, and BPv7 base does not ensure
  application delivery, priority, or custody-like semantics.
- BPSec/TLS/Noise/QUIC protection is not automatically source-object
  end-to-end protection plus mesh-membership metadata protection.
- Endpoint or transport identity is not pre-mission mission identity,
  authorization, disconnected exclusion, or scope rekey.
- A CRDT library is not the State/Event/Record/Blob model, and automatic CRDT
  merge must not silently erase required conflicts.
- A database is not durable opportunistic forwarding; a Blob helper is not
  persistent any-peer range resume.
- Same-peer reconnect/resume is not resume with any peer and another carrier.
- A published specification is not a maintained implementation; an upstream
  feature claim is not an executed result.
- An algorithm being NIST-standardized is not a FIPS-validated module, and a
  validated module does not validate the final protocol composition.
- A project's top-level permissive license is not evidence that its selected
  feature graph and native/daemon dependencies satisfy policy.
- A favorable current-Aster adapter result, code-deletion count, or migration
  estimate has no requirements-first selection weight.

## Historical Phase 0 freeze checklist

This checklist records the pre-execution gate used by the initial survey. The
current exact freezes and executions are indexed in
[`arm-completion-register.md`](arm-completion-register.md).

For every scheduled arm, append a source-freeze receipt with:

1. full immutable commit and signed tag/release identity where available;
2. release/archive checksum and a separately retained source artifact;
3. exact crates/features or daemon build configuration and compiler/toolchain;
4. complete normal/build/dev/native graph, SBOM, license texts/notices, and
   strong-copyleft/proprietary/public-domain disposition;
5. supported target matrix, MSRV, binary provenance, and reproducible build;
6. maintainers/governance, release cadence, security channel, advisory and
   patch-response history, audit/fuzz evidence, and fork viability;
7. exact implemented standards/extensions, including BP forwarding, reports,
   fragmentation, BPSec contexts, routing, priority extensions and
   custody-like/BIBE behavior; and
8. a responsibility map and explicit list of duplicate durable state machines.

The current unresolved research freezes are exact ION, HDTN, and bp7-rs roles;
an executable Confidential Sync or WTP implementation; and one immutable
greenfield-native discovery/NAT/relay/runtime/resource bill of materials. The
last item is an explicit Phase 0 work-order miss, not silently reclassified as
a production-only gate. Willow 0.7.5, Zenoh 1.10.0, p2panda, dtn7-rs, Hardy,
and the bounded Iroh/Patchbay topology graph are frozen for their cited
research slices; target-specific and production admission evidence remains
separate.

## Historical Phase 0 experiment order

The order below is preserved as the original plan and is superseded by the
terminal-arm dispositions and explicit work-order misses in
[`final-frontier.md`](final-frontier.md).

1. **License and security feasibility first.** Close exact graph/license/source
   holds and run an early NIST hybrid-PQ/FIPS-provider, source-object/metadata,
   downgrade, and disconnected revocation/rekey feasibility screen. Stop only
   an adoption role for an intrinsic contradiction or irreconcilable policy
   issue.
2. **Lead with the p2panda-native arm.** BVB-700 and BVB-703 already establish
   the bounded local-first and full-replica temporal chain. Next force contacts
   and test a source-protected opaque item, duplicate contacts/items, a cycle,
   expiry, causal forks, partial subscription, crash recovery, Blob progress,
   and provider substitution. Count every durable owner and grant no general-DTN
   or security credit from the plaintext run.
3. **Use B1 as a delta/justification arm.** Run the identical protected temporal
   corpus over a frozen BP implementation only where it can buy a hard property
   missing from A. Separately record persistence, forwarding, fragmentation,
   expiry, BPSec contexts, routing, priority, custody-like/BIBE behavior, and all
   duplicate retry/dedup/progress state. Use dtn7-rs as a daemon/oracle and Hardy
   as an embeddable BP/BPSec candidate without transferring evidence between
   them.
4. **Retain C as the standards-first fallback/control; defer B2.** Compare C
   when A fails a hard invariant or B1's extra state cannot be made authoritative.
   Reopen interactive sync over BP only if operation carriage cannot satisfy a
   demonstrated hard requirement. No arm continues with competing durable owners
   and no deterministic recovery rule.
5. **Zenoh, Willow, and Veilid disproofs.** BVB-728 shows that Zenoh buys a
   durable latest-value fabric but not causal history or conflict siblings.
   BVB-738 shows that current Willow buys storage/capability/Drop primitives but
   its timestamp-first pruning cannot own causal State/Record semantics; next
   compare a shared immutable causal profile and seek an executable
   Confidential Sync implementation. Test Veilid without assuming global
   bootstrap or DHT replication equals temporal mission convergence.
6. **Connectivity reopening.** Pair every surviving replica/dissemination
   architecture with Iroh 1.0.3, idiomatic rust-libp2p 0.56.0, and one frozen
   Quinn/standards-based greenfield composition. Give no current-Aster
   compatibility weight. Measure owned/offline LAN, automatic/manual discovery,
   NAT topologies, direct upgrade, owned relay failure, path change, peer and
   resource bounds, and metadata exposure.
7. **Then optimize replaceable components.** Compare Automerge for opt-in
   Record policy; Negentropy/Minisketch for reconciliation; redb/SQLite for
   storage; BLE adapters; group-security providers; FFI/bindings; and
   observability. A component wins only if it deletes a complete mechanism and
   passes the same recovery/hostile-input corpus.
8. **Finish with independent interoperability and operations.** Execute a
   second implementation or independently derived codec for every normative
   profile, then complete binding/agent, packaging, SBOM, observability,
   lifecycle, and physical-carrier evidence. Phase 0 never selects a winner.
