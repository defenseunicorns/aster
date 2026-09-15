# Evaluation 0005: security profile matrix


- Status: Phase 4 bounded frontier evidence; no production selection
- Evidence date: 2026-08-22
- Sole product authority: [`data-mesh-requirements.md`](../../../data-mesh-requirements.md)
- Project requirement receipt: `SRC-001` in the local
  `evidence/SOURCE_REGISTER.csv`,
  SHA-256
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`

This matrix asks which published standards and maintained implementations can
own security behavior required by the supplied requirements. It does not treat
the current implementation, wire format, API, identity model, or module
boundaries as constraints. It does not admit a dependency, define COMSEC or
key-management policy, or claim that a cryptographic module is validated.

Research evidence and implementation artifacts remain separate. A standard,
repository, release, documentation page, certificate, or security policy can
support a matrix statement only when it has an append-only entry in the local
`evidence/SOURCE_REGISTER.csv`.
`BR-PENDING` means the named public source still lacks a successful registered
review sufficient for that cell, and the cell carries no external claim. A
project-discovery receipt is not an exact release freeze or feature proof. No
source code was copied for this artifact.

## Evaluation rules

### Requirement classes

- **Hard invariant (`H`)**: the final composed security profile must pass.
  Performance, maturity, or FOSS reuse cannot compensate for failure.
- **Strong default (`SD`)**: deviation requires a recorded rationale.
- **Permitted technique (`P`)**: allowed only while all referenced hard
  invariants remain true.
- **Non-goal or open policy (`NG`)**: not silently converted into an acceptance
  gate.

Classification is atomic. A `Should` does not soften an embedded `Must Not`,
and a provisional quantitative target does not soften its associated binding
capability.

### Evidence dimensions

Each candidate is evaluated on three independent dimensions:

1. **Standard maturity**: final published standard, active draft, private
   convention, none, or `BR-PENDING`.
2. **Implementation maturity**: exact version/revision, maintenance and
   disclosure posture, conformance evidence, audit/fuzz evidence, supported
   algorithms and platforms, and whether it is an embeddable library, external
   service, prototype, or oracle.
3. **FIPS/CMVP coverage**: exact active certificate, module version, module
   boundary, approved mode, operational environment, service and algorithm.
   Algorithm standardization, implementation availability, CAVP/ACVP algorithm
   testing, and CMVP module validation are not interchangeable.

The statuses used below are:

- **verified**: demonstrated by retained evidence;
- **documented**: supported by a registered primary source but not yet run in
  the common corpus;
- **partial**: supplies only a named subset;
- **unknown**: insufficient evidence, not failure;
- **contradiction**: the candidate's essential model cannot meet an invariant
  without replacement; and
- **BR-PENDING**: a successful registered primary-source review must finish
  before any claim is made.

An individual component is not rejected for failing to supply a complete
security profile. A missing capability remains a composition gap unless an
early test demonstrates an intrinsic contradiction.

The current component ownership and minimum residual custom surface are
summarized in
[`security-responsibility-residual.md`](security-responsibility-residual.md).

## Integrated Phase 4 delta

BVB-825 executes the missing nested composition and freezes the current
research seed in
[`integrated-security-profile.md`](integrated-security-profile.md). It passes,
within a carrier-neutral multi-process fixture, the outer member-readable versus
inner consumer-readable split, mandatory ES256 plus ML-DSA-65 source
verification after relay persistence/restart, ordinary-restart and
generation-change item replay rejection, four authenticated-batch mutations,
an awareness-bounded signed generation control, a P-256 plus ML-KEM-768
key-confirmation scaffold, and one scoped zeroization hook. Restoring a
pre-accept snapshot reaccepts two items and remains explicitly unmitigated.

This delta advances `SP-A` from a paper composition to a bounded executable
profile shape. It does not change published-standard maturity, independent
implementation status, physical-carrier evidence, key distribution,
OpenMLS-byte integration, complete downgrade negotiation, FIPS/CMVP coverage,
provider/HSM destruction, or production admission.

## Atomic security requirements

### Hard invariants

| ID | Atomic invariant | Requirement source | Executable acceptance intent |
|---|---|---|---|
| `SEC-H01` | Assume any transport can be observed, replayed, or manipulated. | §3 | Run every profile over a hostile carrier without granting that carrier trust. |
| `SEC-H02` | Confidentiality, integrity, and authenticity must not depend on transport- or network-layer security. | §6, zero-trust transport | Disable or terminate adjacency security at relays; source objects must still verify and remain confidential. |
| `SEC-H03` | Every item is encrypted at its source and decrypted only by an authorized consumer. | §6, end-to-end protection | Persist and forward the exact protected object through a non-consuming relay; only the consumer obtains payload plaintext. |
| `SEC-H04` | Every item is authenticated at its source and verified at consumption. | §5.1 and §6 | Bind publisher identity and all security-relevant item fields to the protected object; reject alteration, substitution, and unauthorized creation. |
| `SEC-H05` | Relays and bridges can store and forward items without payload plaintext access. | §6 | Inspect relay APIs, memory boundary, and durable state while relaying; no payload plaintext is required or retained. |
| `SEC-H06` | Topic, scope, priority, and routing metadata do not travel in plaintext. | §6, layered metadata protection | External captures expose none of the normalized protected fields. |
| `SEC-H07` | Forwarding metadata is protected at a mesh-membership layer, readable by authenticated mesh nodes for forwarding and opaque to outsiders. | §6 | An admitted forwarding member routes an item without payload access; an outsider cannot recover the protected metadata. |
| `SEC-H08` | On-wire plaintext is minimized to fields required by the carrier. | §6 | Compare every visible field with the normalized permitted-leakage list. |
| `SEC-H09` | Every node has a unique cryptographic identity provisioned before the mission. | §3 and §6 | Provision two nodes offline, prove distinct identity possession, and reject an unprovisioned peer. |
| `SEC-H10` | Every item carries an authenticated publisher identity. | §5.1 | Consumer obtains the authenticated publisher identity from the protected item, including after temporal relay. |
| `SEC-H11` | Possession of one mesh node must not grant read access to every scope. | §6, keying model | Give a node membership in scope A only; items in scope B remain confidential even though the node participates in the mesh. |
| `SEC-H12` | Exclusion information for a lost or compromised node propagates through the intermittently connected mesh. | §3 and §6 | Carry a signed membership change through a temporal relay with no live authority dependency. |
| `SEC-H13` | In-field rekey of a scope is possible. | §6 | Advance scope key state during a partition and demonstrate authorized convergence after reconnection. |
| `SEC-H14` | A local zeroization hook is provided. | §6 | Invoke the hook and verify the normalized key handles and software copies become unusable. |
| `SEC-H15` | Replay of captured traffic must not cause stale or duplicate data to be accepted as new. | §6 | Replay before and after restart, reordering, state synchronization, and membership change; distinguish harmless idempotent redelivery from a new application event. |
| `SEC-H16` | Correctness, including conflict handling, must not depend on synchronized wall clocks. | §3 and §5.2 | Skew or remove wall time; authentication, replay handling, membership ordering, and merge correctness still behave deterministically. |
| `SEC-H17` | Peers mutually authenticate before protocol data exchange. | §5.7 | Permit only bounded authentication/control traffic before both mission identities are accepted. |
| `SEC-H18` | NIST-standardized cryptography is used. | §6, algorithms | Map every primitive and parameter set to a named final NIST standard; record the provenance and maturity of each hybrid combiner and wire format separately. |
| `SEC-H19` | Key establishment is hybrid classical plus post-quantum. | §6, algorithms | Both components contribute to the established secret; stripping, failing, or substituting either component fails closed. |
| `SEC-H20` | Signatures are hybrid classical plus post-quantum. | §6, algorithms | Acceptance requires both signatures over one unambiguous content commitment and identity; stripping or replacing either fails closed. |
| `SEC-H21` | FIPS-approved algorithms are used regardless of module availability. | §6, algorithms | Map every operation to its approval basis; no non-approved fallback can silently satisfy a required operation. |
| `SEC-H22` | Algorithm agility uses versioned negotiation. | §6 and §10 | Mixed-version peers select only an explicitly allowed common profile; protected stored objects remain unambiguous. |
| `SEC-H23` | Downgrade attacks are explicitly prevented. | §6 | Remove stronger offers, rewrite profile identifiers, replay older negotiation, and alter stored-object versions; all unauthorized downgrade paths fail. |
| `SEC-H24` | No cryptographic primitive is hand-rolled. | §6 | Every primitive operation resolves to a named vetted implementation. Protocol composition and domain separation remain reviewable profile work. |
| `SEC-H25` | Cryptographic implementations are vetted and widely reviewed. | §6 | Apply the normalized maintenance, disclosure, review, test-vector, audit, and vulnerability-history criteria. |
| `SEC-H26` | Source protection remains valid when PQ cost is amortized across a session or batch. | §6, cost amortization | Every item has a cryptographically verifiable source binding to its authenticated batch or envelope; swapping, truncating, splicing, or reordering fails. |
| `SEC-H27` | A packet capture reveals no plaintext payload or protected mesh metadata. | §12 | Capture IP and BTLE-equivalent carrier bytes and compare against known payloads and normalized metadata values. |
| `SEC-H28` | Security remains compatible with direct peer operation, intermittent multi-hop store-and-forward, and offline-first publish. | §§5.6, 7, and 12 | Publish offline, restart, relay through a node that never meets the consumer concurrently, and verify later without mandatory infrastructure. |
| `SEC-H29` | The protocol remains independently implementable and conformant. | §8 and §12 | Publish a normative security profile, golden and negative vectors, then interoperate with an independently derived parser/implementation. |
| `SEC-H30` | Runtime dependencies satisfy license, maintenance, governance, vulnerability-reporting, and SBOM requirements. | §8 and §13 | Freeze the exact transitive graph and record policy evidence before production admission. |
| `SEC-H31` | A bridge connecting scopes enforces configurable topic-and-priority filter policy. | §5.5 | Attempt allowed and denied topic/priority/scope combinations in both directions; only explicitly allowed items cross, without changing publisher identity or requiring payload plaintext. |

### Strong defaults

| ID | Strong default | Requirement source | Required disposition if absent |
|---|---|---|---|
| `SEC-SD01` | Pre-placed long-term keys derive per-mission and per-scope keys. | §6, keying model | Explain the alternate offline provisioning and lifecycle mechanism and compare its distribution/storage cost. |
| `SEC-SD02` | Use FIPS 140-3 validated modules where available. | §6, algorithms | Prove whether a validated module covers the exact operation, platform, and mode; document why an uncovered operation has no available conformant module. |
| `SEC-SD03` | Prefer maintained FOSS implementations and published standards over bespoke mechanisms. | §8, buy over build | Count the residual security semantics and implementation that the project must own, with a buy-versus-build rationale. |

### Permitted techniques and non-goals

| ID | Classification | Requirement statement | Boundary |
|---|---|---|---|
| `SEC-P01` | `P` | PQ signatures may be amortized over sessions or batches. | Does not weaken `SEC-H03`, `SEC-H04`, `SEC-H20`, or `SEC-H26`; overhead is measured across provisional link-rate anchors rather than used as an early gate. |
| `SEC-P02` | `P` | Trustworthy time may enhance TTL precision. | No authentication, replay, membership, or conflict-correctness decision may require synchronized wall time. |
| `SEC-NG01` | `NG` | Defining COMSEC doctrine or key-management policy is out of scope. | The framework still supplies testable identity, key, rekey, revocation, scope-isolation, and zeroization mechanisms. Adopting programs choose policy values. |
| `SEC-NG02` | `NG` | At-rest payload encryption is not stated. | Do not fail an authorized consumer for storing plaintext; relay payload blindness remains hard. Promote at-rest protection explicitly if stakeholders require it. |
| `SEC-NG03` | `NG` | Secure boot, remote attestation, traffic-flow confidentiality, anonymity, and operator identity are not stated. | Track as threat-model questions, not hidden candidate gates. |

## Candidate standards and exact implementations

This is a component matrix, not a winner table. “Coverage” means a plausible
responsibility for the final composition and receives no credit until the
corresponding black-box test passes.

| Candidate family | Security responsibility under test | Standard maturity | Exact implementation evidence | Implementation maturity | FIPS/CMVP evidence | Hard gaps before profile use |
|---|---|---|---|---|---|---|
| COSE base objects plus ML-DSA | Source-authenticated encrypted item/envelope; detached or batched content commitment; versioned algorithm identifiers | RFC 9052 is final (`STD-013`); ML-DSA COSE identifiers are final RFC 9964 (`BVB-492`). Neither source defines this dual-signature, membership, replay, or hybrid-establishment lifecycle. | Exact `coset` 0.4.2 commit `dd458359623a459086aa296e34a3d8902e034223` supplies the Rust codec (`BVB-722`). BVB-723 freezes its 32-package non-FIPS provider graph; BVB-725 runs the first nested object and 23 negatives. BVB-825 runs an outer member envelope, source object, encrypted two-item batch, durable relay restart, stable-ID replay journal, signed generation control, batch mutations, and public ciphertext fixtures. Exact `t_cose` 1.2.0 remains classical Sign1-only. | **Integrated executed profile shape / incomplete normative profile.** The exact codec/provider seam, reader split, ordinary replay, and batch binding work. Key distribution, OpenMLS integration, negotiation, rollback resistance, parser bounds, independent interoperability, and admission remain open. | The executed provider is explicitly non-FIPS. COSE encoding has no module validation; every operation still needs exact certificate/module/OE/service disposition. | Adopt the normative profile; replace preprovisioned direct-key scaffolding; bind actual membership/authority/key distribution; run physical carriers, parser/resource bounds, rollback/custody faults, and a second implementation. |
| Group OSCORE plus ACE group key provisioning | One-to-many group message protection, sender authentication, group membership, and rekey | ACE group-key provisioning is final RFC 9594 (`BVB-676`). The RFC Editor AUTH48 transition text labels Group OSCORE as RFC 10021, Standards Track, July 2026 and exposes group/pairwise modes, source authentication, replay handling, context update, and group-manager semantics (`BVB-697`–`BVB-699`). Both canonical RFC endpoints still return 404, so final-publication status remains pending and the transition text receives candidate-semantic rather than settled final-RFC credit. | BVB-701 freezes libOSCORE HEAD `57846b848f01dd41b830a2fc41527790bf4553fd`, its v0.1.0 tag target, Californium HEAD `745d07e8929cfaa26a05abf05e5dab3aa8d9eb1b`, stable 3.14.0, and 4.0.0-M6. Static inspection found pairwise OSCORE only: no Group Security Context, ACE Group Manager, group countersignature path, group rekey, or durable per-sender group replay. libOSCORE has a real Rust wrapper for its pairwise primitive, not Group OSCORE. | **Exact source-surface stop for these implementations.** Pairwise OSCORE remains buyable where needed; the whole Group OSCORE+ACE executable lane is absent rather than runtime-failing. Californium is a pairwise Java oracle only. | No registered certificate-operation-OE record covers this composition. Algorithm providers and boundaries must be evaluated independently. | Re-enter only with a separately registered maintained implementation that exposes group mode, per-sender authentication/replay, GM join/rekey/removal, provider hooks, and an executable graph; then test non-CoAP fit, hybrid requirements, disconnected authority, and nested metadata/payload views. |
| BPSec over BPv7 | Delay-tolerant block integrity/confidentiality that survives store-carry-forward | RFC 9172 and its default security contexts in RFC 9173 are final IETF Standards Track publications (`BVB-648`, `BVB-649`). They do not supply key management or the required application security policy. | Hardy `hardy-bpv7` 0.6.0 at frozen head `b87c790263392a6289f942e6bf59fdb714f4c842` built from its locked default `rfc9173` graph and passed 113 package tests, including 18 RFC 9173 tests/vectors (`BVB-702`). This is executed library evidence, not an executed application profile. dtn7-rs at frozen head `c30181b4b111e2adc5538931c797c0f7190acc4c` passed a non-overlapping temporal-relay/restart trial **without BPSec**; its store exposed the plaintext probe, and its BPSec support remains not documented/unknown rather than unsupported (`BVB-702`). HDTN and ION remain registered daemon/oracle candidates, not executed profile evidence. | **Partial/executed library evidence.** Hardy demonstrates an embeddable RFC 9173 implementation/test surface. It does not yet demonstrate daemon forwarding, source-to-consumer application policy, key lifecycle, metadata confidentiality, hybrid algorithms, or independent interoperability. dtn7-rs demonstrates temporal BP forwarding only and receives no BPSec or payload-blindness credit. | No exact candidate has a registered certificate-operation-OE matrix. HDTN's OpenSSL/FIPS configuration relationship is **unknown under the current claim-specific receipts**; no CMVP coverage may be inferred for a deployed binary. | Compose and execute BPSec policy over a temporal relay; show which mutable routing fields remain visible, whether security source/acceptor equal item publisher/consumer, hybrid signatures/establishment, key distribution/revocation, replay semantics, metadata confidentiality, embeddability, and independent BPSec interoperability. |
| Hybrid TLS 1.3 adjacency | Mutually authenticated IP adjacency and hybrid classical+PQ key establishment as defense in depth | Hybrid TLS key establishment is final RFC 10024 (`BVB-069`); ML-DSA authentication for TLS remains draft and does not define the required dual-signature item profile (`BVB-072`–`BVB-075`). | rustls 0.23.43 with its AWS-LC provider (`BVB-076`–`BVB-086`); OpenSSL 3.5.x implementation family (`BVB-055`–`BVB-063`). Exact RFC 10024 vectors/codepoints still require a local freeze and run. | **Maintained/documented for TLS; unverified for this profile.** It is an adjacency component, not object security. | Depends on the exact provider row. A validated classical or ML-KEM TLS path does not validate source-object encryption or ML-DSA signatures outside the certificate. | Cannot receive `SEC-H02`–`SEC-H07` or temporal-relay credit. Pair it with source object and mesh-metadata protection; prove mission-identity binding and downgrade behavior. |
| MLS group state plus item/routing layer | Asynchronous group membership, group key evolution, removal, and protected application messages | MLS 1.0 is final RFC 9420 (`BVB-087`–`BVB-089`). Hybrid/PQ MLS ciphersuites remain an active draft (`BVB-090`–`BVB-093`). | BVB-726/BVB-727 freeze exact OpenMLS 0.8.1 commit `47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6` and a 154-package focused graph. BVB-735 registers three process phases/two full reloads with classical add/remove, epoch advance, awareness-bounded exclusion, delayed removal, one replay rejection, post-restart application traffic, and application-selected fork/re-add convergence. `mls-rs` remains a documented 0.55.3-era secondary candidate without an exact executed graph. | **Executed classical membership mechanism / incomplete mesh profile.** OpenMLS buys persisted group-state cryptography and an explicit recovery helper. It does not automatically detect/resolve partitions; the application supplied partition membership and a fresh key package. The fixture used files rather than a delivery/authentication service and persisted secrets in plaintext JSON. | No registered CMVP certificate covers either Rust MLS library as a module. The executed RustCrypto suite has no CMVP credit; a configured backend can claim only exact services inside its validated boundary. | Bind signed authority and mission/scope identities; carry controls through the selected temporal relay; resolve long partitions, concurrent removals, stale key packages, rollback, rejoin, DS/AS policy, durable application-object semantics, outer metadata, mandatory hybrid requirements, secure custody, and no-clock recovery. |
| AWS-LC / `aws-lc-rs` | Primitive provider for AEAD, hashes/KDF, classical signatures/agreement, ML-KEM, and ML-DSA | Algorithms trace separately to final NIST standards; provider APIs are not protocol standards. | AWS-LC FIPS 3.1.0 and `aws-lc-rs` 1.17.3 are the registered validated-path candidates (`BVB-036`–`BVB-053`). BVB-710 executes exact non-FIPS 1.18.0/0.44.0 primitive feasibility. BVB-825 reuses that exact graph for nested AES-GCM, ES256/ML-DSA-65 source signatures, P-256/ML-KEM-768 HKDF key confirmation, and a scoped application-owned zeroization boundary. The FIPS-4 transition is registered but not certified (`BVB-046`). | **Executed primitive and integrated API feasibility; normative profile incomplete.** One maintained safe Rust surface supplies the required primitive families and key-confirmation mechanics. The exact combiner, identity binding, negotiation, distribution, lifecycle, and complete provider custody remain profile work. | Active certificate 5314 covers the exact AWS-LC 3 static module under its policy (`BVB-036`, `BVB-037`), with registered ML-KEM but not ML-DSA and bounded OEs. BVB-710/BVB-825 are explicitly non-FIPS; API reuse does not expand certificate scope. | Prove exact crate/module version, approved mode, OE, services, entropy, key entry/exit, every operation, provider destruction, and fail-closed validated initialization. |
| OpenSSL 3.5.x provider family | Alternate primitive provider for classical and PQ operations; possible TLS provider | ML-KEM and ML-DSA are final NIST algorithms; OpenSSL API support is implementation evidence, not standard or validation evidence. | OpenSSL 3.5.7-era source/release and ML-KEM/ML-DSA provider documentation are registered (`BVB-055`–`BVB-063`, `BVB-501`, `BVB-502`). Rust `openssl` integration remains a spike candidate (`BVB-488`). | **Maintained LTS C provider with documented PQ code support; Rust integration and complete profile boundary unverified.** | The registered source table identifies OpenSSL FIPS Provider 3.1.2 as the available FIPS 140-3 provider, while the PQ code is in newer 3.5.x. Do not describe the 3.5.x PQ operations as validated without a matching active certificate, module version, OE, and service list. | Establish one deployable build that supplies all required services or explicitly compose validated and nonvalidated boundaries without mislabeling; prove Rust FFI ownership, errors, key handles, zeroization, mobile/Windows support, and both hybrid operations. |
| RustCrypto `ml-kem` / `ml-dsa` | Pure-Rust interoperability and differential provider for NIST PQ primitives | FIPS 203 and FIPS 204 are final (`STD-009`, `STD-010`). | `ml-kem` 0.3.2 and `ml-dsa` 0.1.1 (`DEP-006`, `DEP-007`, `WEB-001`–`WEB-025`). Registered upstream evidence says the implementations are not independently audited; the selected ML-DSA version follows several corrected pre-release advisories. | **Maintained interoperability candidate; not production-authorized by current evidence.** | No registered CMVP module certificate. Algorithm conformance or use of FIPS-defined algorithms is not module validation. | Independent audit, side-channel/platform evidence, stable provider API, negative/KAT/differential tests, entropy and zeroization review, hardware custody path, and production assurance disposition. |
| libcrux | Formally verified/high-assurance PQ primitive comparator | Algorithm standards are separate from the implementation. | Main snapshot was evaluated and held for maturity/integration limitations (`BVB-489`). Exact release, APIs, algorithms, license, and platform graph require revalidation before a spike. | **Research/comparator; insufficient registered evidence for production admission.** | No registered CMVP certificate. | Freeze an exact release and graph; verify ML-KEM and ML-DSA coverage, audit/proof scope, Rust integration, performance, platform support, security policy, and lifecycle. |

The first Group OSCORE implementation freeze is now complete (`BVB-701`).
libOSCORE and Californium buy pairwise OSCORE only; static inspection found no
Group OSCORE, ACE/Group Manager, group rekey, countersignature processing,
durable group replay, or hybrid-PQ provider boundary in the frozen revisions.
Stop those repositories as a whole Group OSCORE + ACE executable lane while
retaining RFC 9594 and the transition profile as standards/design inputs.

## Profile compositions to test

These are requirements-driven compositions. They remain hypotheses and may be
recombined as evidence arrives.

| Profile | Composition hypothesis | What it buys | Residual critical semantics | First disproof |
|---|---|---|---|---|
| `SP-A` — nested COSE objects | Inner consumer-readable encrypted item; source hybrid signature/content commitment; outer mesh-member-readable protected forwarding envelope; independent group membership/rekey mechanism; selectable primitive provider | BVB-825 now executes the reader split, mandatory-both source verification, durable opaque relay/restart, stable-ID/generation replay journal, signed generation control, batch binding, and research key-confirmation/zeroization shapes | Normative hybrid signature/establishment and negotiation rules, recipient/group key distribution, actual membership/authority integration, multi-scope/bridge policy, replay bounds, rollback, full custody, physical captures, FIPS operation coverage, and independent implementation | Research feasibility closed by BVB-825; production gates are `K03`, `K04`, `K05`, `K06`, `K11`–`K17` |
| `SP-B` — Group OSCORE/ACE profile | Requirements item profile carried in Group OSCORE protection with ACE-style group provisioning; nested protection if relays and consumers differ | Potential multicast/group protection and standardized group joins | Canonical RFC publication and exact implementation remain unresolved; non-CoAP fit, hybrid algorithms, disconnected authority, concurrent partition state, durable object semantics, and metadata layering are unknown | Canonical publication disposition plus `K01`, `K03`, `K04`, `K08` |
| `SP-C` — BPSec plus inner source object | BPv7/BPSec owns DTN block security; inner object independently owns publisher-to-consumer identity/confidentiality where BPSec policy is hop/region scoped | Final RFC 9172/9173 framing and an exact executed Hardy library/default-context test surface | No application BIB/BCB policy over temporal forwarding has run; duplicate layers, visible primary/routing metadata, item-versus-bundle identity, key lifecycle, hybrid algorithms, replay/expiry mapping, and independent interoperability remain | Only if a BP arm survives: compose Hardy policy and separately frozen ION/HDTN oracle, then `K01`, `K03`, `K04`, `K09` |
| `SP-D` — MLS membership plus protected routing | OpenMLS owns classical group membership/key evolution and protected application messages; separate source object and outer envelope own durable item identity and forwarding metadata | Final RFC 9420 plus exact BVB-735 persisted removal/restart/manual-fork-recovery evidence | Signed authority/control dissemination, automatic partition detection, scope mapping, rollback/rejoin/lost-authority policy, PQ/hybrid draft, general replay/idempotence, bridge policy, outer metadata, custody | Carry exact controls through the selected temporal arm, then `K01`, `K03`, `K04`, `K07` |
| `SP-E` — hybrid TLS plus objects | RFC 10024 TLS for IP adjacency; one of `SP-A`–`SP-D` independently satisfies source object and metadata requirements | Deletes bespoke IP key-establishment/session security while retaining end-to-end protection | BTLE/non-IP adjacency, mission-identity binding, duplicated authentication, no temporal-relay credit from TLS | `K01`, `K02`, `K06` |

No profile receives selection credit merely because all named algorithms exist.
The exact composition, persistent state, failure behavior, implementation
versions, and security boundary must run together.

## Early feasibility and kill tests

An outcome of `partial` or `unknown` is valid evidence. A failed component test
changes its role to component/oracle unless the failure proves an intrinsic
contradiction for every plausible composition.

| Test | Procedure | Hard pass condition for final profile | Legitimate early kill or role reduction |
|---|---|---|---|
| `K01` Opaque temporal relay | Publisher creates protected item offline; A meets relay B; B persists/restarts; later B meets consumer C; A and C never overlap. Inspect B APIs/state and verify at C. | C verifies publisher and decrypts; B never needs or durably stores payload plaintext; security survives carrier changes and delay. | If the candidate's essential operation requires every forwarding node to decrypt or a live source/authority, it cannot own end-to-end/temporal security. |
| `K02` Hybrid signature and downgrade | Validate a good classical+PQ object; then strip either signature, replace either key/identity, rewrite algorithm/profile/version IDs, replay an older offer, duplicate protected headers, and reorder encodings. | Both signatures bind the same normalized identity and content; every unauthorized downgrade or ambiguous parse fails closed. | A fixed classical-only acceptance model with no external authenticated object layer cannot own required source authentication. Default classical crypto alone is a gap, not a kill, when clean substitution exists. |
| `K03` Nested metadata privacy | Test outsider, authenticated mesh relay, scope member, bridge, and consumer roles. Capture all carrier bytes and inspect role-owned durable state. | Outsider sees no protected metadata or payload; relay sees only normalized forwarding fields; only authorized consumer sees payload; bridge sees only authorized filter inputs. | If routing fundamentally requires globally plaintext topic/scope/priority, the candidate cannot own the mesh-metadata layer. |
| `K04` Partitioned exclusion and rekey | Partition one member; distribute a signed membership change and new key state through intermittent relays; test before/after each peer learns it; vary authority loss, rejoin, concurrent changes, and rollback separately. | Nodes that accept newer valid membership state reject the excluded member and converge on authorized scope keys without a mandatory live service or trusted clock. | An unavoidable always-online KDC/AS for mission correctness reduces the candidate to a pre-mission/control-plane component. Instant exclusion of unaware partitions is not required. |
| `K05` Replay, restart, and idempotent redelivery | Capture valid objects/control messages; replay before/after restart, storage compaction, rekey, and reconnect; deliver the same item through multiple peers. | Duplicate delivery is harmless and never becomes a new item or membership event; anti-replay state is bounded and recovery semantics are explicit. | Unbounded replay state that cannot be capped/profiled, nonce reuse after ordinary restart, or acceptance of stale membership as newer is an early contradiction. Snapshot rollback resistance is characterized separately unless promoted. |
| `K06` Hybrid key establishment/provider substitution | Run registered final vectors and cross-provider exchange; force failure of classical then PQ components; modify transcript/profile; disable validated initialization; inspect selected provider/service. | Both secrets and all identities/parameters are bound; either-component failure and downgrade fail closed; no silent provider/fallback change occurs. | An unreplaceable classical-only provider can no longer own establishment. A replaceable default mismatch remains an adapter/provider gap. |
| `K07` MLS partition/fork and durable-object fit | Produce concurrent commits while groups are partitioned; delay/reorder proposals, commits, welcomes, key packages, and application objects through durable relays; lose DS/AS connectivity; restart all nodes. | A documented deterministic recovery/rejoin path preserves authorized application data, excludes removed members after accepted state, and needs no continuously available service for required local/direct operation. | If the essential model cannot recover required partition patterns without discarding durable data or contacting mandatory infrastructure, MLS cannot own complete mesh membership; it may remain a narrower group component. |
| `K08` Group OSCORE/ACE authority and profile fit | Using the registered transition profile without claiming settled final-RFC status, freeze exact implementations; provision pre-mission; remove Group Manager/AS/KDC connectivity; relay protected small and fragmented items; rekey and revoke across partitions; test multicast. | Required mission operation, forwarding, verification, rekey, and exclusion work under the normalized offline-authority rule and hybrid profile. | Inseparable live-authority dependence or inability to carry/profile requirements items reduces the role; missing implementation is `unknown`, not technical failure. |
| `K09` BPSec policy and metadata fit | Freeze two exact implementations from the registered candidate set; protect payload and relevant blocks; traverse multiple waypoints/fragmentation; inspect primary and extension fields; vary security-source/acceptor policy and keys. | Publisher-to-consumer protection and normalized metadata privacy survive temporal relay and interoperation; no waypoint plaintext is required. | Required plaintext routing fields or unavoidable hop/region termination means BPSec alone cannot own source/metadata protection; it may remain an outer DTN layer. |
| `K10` Batch commitment | Sign/encrypt a batch, then omit, duplicate, reorder, splice, or substitute individual items; replay a valid item under another batch/session; interrupt and resume partial transfer. | Every accepted item has a unique source-authenticated commitment and retains independent class/topic/scope/TTL semantics. | A batch scheme that authenticates only an unordered or ambiguous aggregate cannot satisfy per-item source authenticity. |
| `K11` No-clock lifecycle | Set clocks absent, stale, reversed, and far apart; exercise certificates/credentials, TTL hints, replay, rekey, revocation, and conflict ordering. | Security and data correctness remain deterministic without wall time; optional trustworthy time only improves precision. | Mandatory online time validation or wall-clock ordering for correctness is an intrinsic contradiction unless a compliant offline validation profile exists. |
| `K12` CMVP operation matrix | For each deployment target, record binary/module hash, certificate, module version, approved mode, OE, entropy path, service indicator, key entry/exit, and every invoked operation. Exercise startup/fallback failures. | Every claimed validated operation is inside the exact active certificate boundary and approved mode; uncovered operations are labeled precisely. | Any “fully FIPS validated” claim lacking exact operation/OE evidence is killed as a claim, not necessarily as a technical candidate. |
| `K13` Zeroization and custody | Enumerate long-term, mission, scope, ephemeral, replay, and batch keys plus copies; invoke zeroization during idle, transfer, crash recovery, and rekey; test software and hardware-backed handles separately. | The normalized hook renders covered local material unusable and reports failures; guarantees do not exceed the storage/provider boundary. | Unextractable provider keys without destroy support, or unavoidable recoverable plaintext key copies, block custody claims; software best-effort can remain honestly scoped. |
| `K14` Hostile parser and resource bounds | Fuzz/truncate/mutate security objects, duplicate map/header fields, create unknown critical algorithms, huge recipient/member sets, deep nesting, and signature/ciphertext length abuse. | Deterministic rejection, bounded allocation/CPU/state, no ambiguous interpretation, and no unauthenticated persistent-state growth. | Unsafe or unbounded behavior that cannot be isolated without replacing the subsystem is an early exit. |
| `K15` Constrained overhead curve | Measure object, key-update, revocation, batch, and handshake bytes/CPU/RAM over small items, blobs, MTUs, loss, group sizes, and link-rate anchors. | Report curves and breakpoints while preserving all hard security behavior. | Missing a provisional 3 kbps/50% point is not a kill. An unavoidable protocol minimum exceeding the carrier's representable MTU with no valid fragmentation/profile is a design contradiction. |
| `K16` Independent implementation | Give a second team only the normative profile and vectors; exchange valid/invalid objects, group changes, and version negotiation. | Both implementations agree on protected bytes, acceptance/rejection, identity, algorithm, replay, and downgrade semantics. | Specification ambiguity that cannot be normalized blocks selection even if one implementation self-interoperates. |
| `K17` Cross-scope bridge authorization | Configure two scopes, overlapping memberships, and allow/deny filters by topic and priority. Try scope substitution, priority rewriting, replay through the reverse path, nested bridges, and filter changes while preserving the original protected item. | Only authorized combinations cross; denial is fail-closed and deterministic; a bridge neither needs payload plaintext nor becomes the payload publisher; rewrapping cannot widen access or obscure source identity. | A model that requires payload decryption to filter, cannot authenticate filter inputs, or cannot prevent cross-scope widening cannot own bridge authorization. A separate outer policy envelope remains a valid composition gap. |

## Required wording normalizations

These questions must be resolved before any candidate can receive a final
`pass`. Each resolution belongs in the normative protocol/profile or an
approved requirements clarification, not only in implementation code.

| ID | Ambiguous wording | Normalization needed for executable acceptance |
|---|---|---|
| `N01` | “Every item” versus signatures amortized across sessions or batches | Define item identity and the exact cryptographic commitment from each item to its source-authenticated envelope/batch, including ordering, omission, duplication, partial transfer, and garbage collection. |
| `N02` | “Encrypted and authenticated at the source” | Define encryption/signing order, publisher versus encryptor, blob/chunk treatment, recipient discovery, group versus individual keys, immutable protected fields, and whether a bridge may create a new outer envelope without becoming payload publisher. |
| `N03` | “Hybrid classical + post-quantum” | State that both components are mandatory, choose exact algorithms/parameter sets, define combiner or multi-signature encoding, key/identity binding, transcript/domain separation, validation order, and fail-closed behavior. Clarify that hybrid does not mean negotiation between classical-only and PQ-only. |
| `N04` | “FIPS-approved algorithms” and “FIPS 140-3 validated modules where available” | Separate algorithm approval from CMVP validation. Define availability by operation, platform/OE, module version, certificate status, approved mode, procurement/deployment feasibility, and date. Define how a composition labels validated and nonvalidated operations. |
| `N05` | “Vetted, widely reviewed implementations” | Set observable admission criteria: supported releases, disclosure channel, maintainer/governance evidence, independent review/audit scope and date, conformance/vector evidence, fuzzing, advisory response, side-channel claims, transitive policy, and fork viability. |
| `N06` | “Authenticated publisher identity” and “unique cryptographic identity” | Define node, installation, hardware, mission persona, and publisher identity; credential form and trust roots; rotation/recovery; cloning detection/response; privacy/visibility; and binding between carrier, mission, scope, and item identities. |
| `N07` | Scope key derivation is a `Should`, but all-scope read access is forbidden | Make per-scope least privilege the hard acceptance outcome and treat derivation from pre-placed long-term keys as the preferred mechanism. Define nested scopes, bridge membership, overlapping scopes, and compromise blast radius. |
| `N08` | “Revocation ... afterward” and “excluded from all further exchanges” | Define effectiveness after an honest node learns and accepts a newer authorized membership state; no retroactive erasure of disclosed plaintext and no instant effect in unaware partitions. Define authority, ordering, concurrent updates, rollback, rejoin/reprovision, and lost-authority recovery without trusted time. |
| `N09` | “Replay ... must not cause acceptance ... as new” versus at-least-once delivery | Define network receipt, cryptographic acceptance, durable insertion, and application delivery separately. Specify identifiers, replay windows/state, restart/compaction behavior, epoch/generation changes, bounded retention, and duplicate idempotence. Characterize storage snapshot rollback separately. |
| `N10` | Metadata “must not travel in plaintext” and plaintext minimized to carrier requirements | Enumerate protected fields and unavoidable leakage per carrier: length, timing, frequency, peer/address headers, discovery advertisement, fragmentation identifiers, and any BP/CoAP/TLS headers. Define outsider, mesh member, scope member, relay, bridge, and consumer views. |
| `N11` | Relays can forward without payload plaintext | Define whether relay process memory, plugin/provider APIs, caches, crash dumps, logs, and durable stores are in scope; distinguish an authorized consumer co-located with a relay. Do not silently add general at-rest encryption. |
| `N12` | Correctness without synchronized wall clocks | Define credential validity and rotation without trusted current time, TTL behavior, membership ordering, replay expiry, monotonic local counters, and optional trustworthy-time enhancement. |
| `N13` | “Mutually authenticate before exchanging data” | Exempt only the minimum bounded discovery/authentication/control transcript, define when authentication completes, bind carrier identity to mission identity, and state behavior for reconnect/resume and multiple transports. |
| `N14` | Algorithm agility and downgrade protection | Define profile/version identifiers, offer/selection transcript binding, minimum policy, deprecation, stored-object interpretation, mixed-version behavior, unknown critical versus ignorable extensions, and rollback protection without relying on wall time. |
| `N15` | Zeroization hook | Enumerate material covered, sync/async completion semantics, provider/HSM destroy behavior, error reporting, process memory/copies, persisted backups/snapshots, crash behavior, and what “destruction” can honestly guarantee on each platform. |
| `N16` | Revocation/key-management mechanism versus policy non-goal | Specify interoperable mechanism, authorization objects, state transitions, and failure behavior while leaving mission-specific authorities, intervals, roles, and operational doctrine to adopting programs. |
| `N17` | Source protection and mesh membership protection use different readers | Define inner and outer confidentiality/authenticity layers, key separation, which layer carries topic/scope/priority/routing/publisher identity, and how bridges rewrap authorized metadata without weakening source authenticity. |
| `N18` | Capture acceptance says no plaintext payload or mesh metadata | Define capture point and node role. External carrier captures and relay/bridge durable state are tested; authorized consumer plaintext storage is not an at-rest requirement unless separately promoted. |
| `N19` | Exclusion, TTL, and garbage collection interact | Define whether old ciphertext remains forwardable/readable after rekey, treatment of expired membership/control objects, tombstone/revocation retention, and how a long-partitioned node obtains enough retained state to reject superseded keys. |
| `N20` | “Simple” identity/key provisioning and no mandatory infrastructure | Define the complete pre-mission artifact set, offline trust-root/bootstrap process, manual recovery, local direct authentication, and which optional AS/KDC/DS/relay services may improve operation without becoming correctness dependencies. |
| `N21` | Bridges connect scopes with “filter policy (by topic and priority)” | Define policy authority, signed/versioned distribution, default-deny behavior, bidirectional versus directional rules, authenticated source of filter inputs, nested-bridge composition, concurrent updates, rollback, audit output, and whether a bridge rewraps metadata without changing payload publisher identity. |

## Provenance gate and blocked evidence

The register now contains discovery or documentation receipts for every named
implementation family, but that does not make each candidate an exact frozen
or executed dependency. The remaining provenance blocks are:

1. Canonical RFC Editor publication or an explicit decision to evaluate the
   registered AUTH48 transition text without final-RFC credit;
   `BVB-677` and `BVB-678` are failed retrieval receipts and support no standard
   facts.
2. An exact maintained ACE/Group OSCORE Group Manager implementation and
   supported profile.
3. Exact HDTN and ION-DTN source freezes/builds/licenses plus an application
   BPSec policy and interoperability run. Hardy and dtn7-rs are already frozen
   by BVB-702; Hardy has executed library/default-context evidence, while
   dtn7-rs remains unknown/not documented for BPSec.
4. An exact validated-provider graph/OE/service-indicator execution for any
   claimed FIPS boundary; the non-FIPS BVB-710 graph cannot be reused for this.
5. An exact rustls/provider/vector freeze for RFC 10024 if an IP adjacency lane
   survives, and an exact second MLS implementation only if it changes the
   membership-interoperability decision.

Registration authorizes evidence review, not dependency admission. Replace
only `BR-PENDING` cells with successful ledger-backed facts; preserve this gate
and any source corrections append-only through the source register.

## Phase 4 frontier conclusion

No single registered candidate presently demonstrates all hard security
invariants. BVB-702 adds two narrow, orthogonal executable facts: Hardy has an
embeddable RFC 9173 library/test surface, and dtn7-rs can persist and forward an
unprotected BP bundle across non-overlapping contacts and relay restart. Those
facts are not a composed secure temporal relay: the dtn7 trial did not use
BPSec and exposed payload plaintext. BVB-794 later executed Hardy daemon
forwarding through the same temporal topology, but likewise without a BPSec
application policy or key lifecycle and with plaintext in B's durable file.
BVB-703 adds a third bounded fact:
p2panda's subscribed full-replica composition carried one A-authored operation
across non-overlapping A-B and B-C contacts and a B process restart. B exposed
the payload through its application API and durably retained plaintext in its
SQLite WAL, so that result adds temporal-function evidence but no payload-blind
relay or other security credit. BVB-722 and BVB-723 now add a fourth bounded
fact: exact `coset` 0.4.2 supplies the Rust COSE object/codec surface, and its
frozen non-FIPS provider composition locally passed nested AES-GCM plus
mandatory ES256/ML-DSA-65 verification and 23 negatives (`BVB-725`). It has not
yet run through a carrier. BVB-735 adds exact OpenMLS classical membership
evidence across full process reload, removal/epoch advance, delayed control,
one replay rejection, and application-assisted fork recovery. It also keeps
the limits visible: no automatic partition convergence, real delivery service,
hybrid/PQ, secure storage, general replay, or outer metadata credit.

BVB-825 adds the integrated bounded fact that those mechanisms can coexist in
one small carrier-neutral profile shape. An outer member-keyed envelope hides
forwarding fields from an outsider; a relay verifies the dual-signed source
object without a content key, persists, restarts, and forwards byte-identically;
the consumer verifies/decrypts; stable IDs and accepted generation reject
ordinary restart and rekey duplicates; batch mutations fail; and one signed
awareness-bounded generation control and scoped zeroization hook run. The same
corpus proves snapshot rollback remains unmitigated. It grants no physical
carrier, key-distribution, exact OpenMLS-byte, normative-profile, FIPS/CMVP,
independent-interoperability, provider-destruction, or production credit.

The least bespoke frontier is therefore a composition: executed COSE
source-object machinery, executed OpenMLS classical membership machinery,
BVB-825's bounded member-readable metadata/replay/batch profile seed, and a
replaceable primitive provider. The selected temporal carrier remains
orthogonal. BPSec is optional only for surviving BP arms, and hybrid TLS is
optional only for surviving IP adjacencies.
Hybrid TLS may remove custom IP adjacency establishment but cannot replace
source objects. OpenMLS is now the leading classical group-state buy, but its
required PQ profile, authority/control dissemination, rollback, and complete
disconnected-mesh policy remain feasibility work. The exact COSE
codec/provider composition substantially reduces custom source-object code,
and BVB-825 makes the remaining profile surface measurable. It still does not
supply the adopted normative hybrid profile, key distribution, complete
membership/authorization, bounded replay lifecycle, bridge policy, rollback
resistance, complete custody, or production admission.
Provider code support must never be promoted into a CMVP claim without the
exact certificate-operation-OE matrix.

Phase 4 therefore makes no production selection. Its research arms are
complete at a bounded frontier; the remaining cells are explicit conditional
integration and final-selection gates. Every unowned hard invariant remains a
visible composition gap rather than a reason to preserve or rebuild an
incumbent mechanism.
