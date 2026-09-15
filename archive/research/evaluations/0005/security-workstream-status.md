# Security, membership, and key-lifecycle workstream status


- Status: Phase 4 bounded frontier audit; no production selection
- Evidence date: 2026-08-22
- Sole product authority: [`data-mesh-requirements.md`](../../../data-mesh-requirements.md)
- Requirements SHA-256:
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`

This register reconciles the hard security requirements with the current
registered and local executable evidence. It is not an architecture decision.
Current Aster code, wire formats, APIs, and module boundaries have zero
selection weight and were not used. A component remains viable when it buys a
bounded responsibility; lack of a complete stack is a composition gap unless
an intrinsic contradiction has been demonstrated.

The provisional throughput, loss, offline-duration, and overhead anchors are
measurement axes, not early elimination gates. Pre-placed key derivation and
validated modules are strong defaults. Source protection, scope isolation,
revocation/rekey, replay rejection, hybrid algorithms, downgrade prevention,
and payload/metadata privacy remain hard outcomes.

The consolidated Phase 4 ownership and residual accounting is in
[`security-responsibility-residual.md`](security-responsibility-residual.md).

## Current evidence delta

The exact offline `aws-lc-rs` 1.18.0 non-FIPS provider run is complete and
documented in
[`aws-lc-provider-feasibility.md`](aws-lc-provider-feasibility.md). It proves a
single safe Rust provider surface for P-256 ECDSA/ECDH, ML-DSA-65,
ML-KEM-768, and HKDF-SHA-256, plus mandatory-both wrapper feasibility. It does
not prove a hybrid standard/profile, FIPS boundary, key lifecycle, object
security, or protocol correctness. BVB-710 now registers the exact local
execution, while production admission and a normalized full-profile result
remain open.

The exact `coset` 0.4.2 source and codec graph are frozen by BVB-722, and
BVB-723 authorizes the 32-package composition with that provider. The locked,
offline local receipt now demonstrates one nested AES-256-GCM `COSE_Encrypt`
inside a mandatory ES256 plus ML-DSA-65 `COSE_Sign`, public verification
without the content key, consumer decryption, and rejection of 23 object and
downgrade negatives. BVB-725 registers the exact execution. This
buys the leading source-object mechanism; it does not buy a standardized
hybrid profile, KEM/key distribution, carrier behavior, membership, replay,
metadata protection, FIPS, or production admission.

The exact OpenMLS 0.8.1 source and 154-package focused graph are frozen by
BVB-726/BVB-727. BVB-735 registers the locked/offline three-process
membership comparator. It buys bounded classical MLS add/remove, epoch
evolution, two full provider/group reloads, effect of removal after accepted
control, one narrow post-restart MLS replay rejection, and explicit
application-assisted fork/re-add recovery. It does not buy automatic partition
convergence, a delivery/authentication service, hybrid/PQ, secure custody,
general object replay, outer metadata protection, or production admission.

BVB-825 now closes the integrated Phase 4 feasibility corpus described in
[`integrated-security-profile.md`](integrated-security-profile.md). In one
locked/offline multi-process composition, an outer member-keyed COSE envelope
protected forwarding fields, a relay verified the exact dual-signed source
object without a content key, persisted and restarted, and a consumer verified
and decrypted. Durable item IDs rejected duplicates across ordinary restart
and membership-generation change; a signed control advanced generation one to
two; omission/reorder/substitution/splice batch mutations failed; a
P-256-plus-ML-KEM-768 key-confirmation scaffold failed four negatives; and one
scoped application zeroization hook ran. The same corpus separately showed
that restoring a pre-accept snapshot reopens acceptance. This is bounded
profile-shape evidence, not key-distribution, OpenMLS integration, FIPS/CMVP,
physical-carrier, independent-interoperability, provider-destruction, or
production credit.

## Phase 4 arm dispositions

| Arm | Hard outcome owned | Current evidence | Stop/continue disposition | Next decisive evidence |
|---|---|---|---|---|
| `SEC-A01` Source object | Source encryption/authentication, consumer verification, authenticated publisher, payload-blind temporal relay | BVB-825 nested the exact COSE/provider mechanics inside a member envelope and passed separate A generation, B durable ingest, B full exit/restart/forward, and C verification/decryption. B had no content key and zero durable plaintext-marker matches. | **Advance `coset` plus provider as bounded FOSS mechanisms; hold the normative profile.** | Reuse the frozen public ciphertexts on surviving physical carriers, then independently implement the adopted profile and key lifecycle. |
| `SEC-A02` Mesh-metadata layer | Topic/scope/priority/routing readable to admitted forwarders, opaque to outsiders, minimized wire plaintext | BVB-825's outer member-keyed `COSE_Encrypt` hid generation/scope/topic/priority/route/object ID from an outsider while an admitted relay opened those fields and retained an opaque durable queue. | **Profile shape passes; membership keying, bridge view, and carrier leakage remain custom/open.** | Bind the layer to actual membership/key distribution and run outsider/member/scope-member/bridge/consumer captures over IP, BTLE, and any surviving BP path. |
| `SEC-A03` Hybrid signatures and establishment | Both classical and PQ components mandatory; NIST algorithms; no custom primitives | BVB-725/BVB-825 require exact ES256 plus ML-DSA-65 slots and reject missing/duplicate/tampered/substituted cases. BVB-825 also executes P-256 ECDH plus ML-KEM-768 with both inputs mandatory and authenticated key confirmation, including four negatives. | **Provider/mechanism feasibility passes; both complete profiles remain on hold.** | Adopt/register published or explicitly reviewed signature and establishment profiles, add authenticated negotiation and stored-policy rollback defense, then run independent vectors/providers. |
| `SEC-A04` FIPS/CMVP provider coverage | Validated modules where available; approved algorithms always | Active AWS-LC certificate 5314 evidence is registered for the FIPS-3 module. Its registered policy lacks ML-DSA. Release 1.18.0 exposes ML-DSA but the executed build is explicitly non-FIPS and its FIPS-4 transition is not certified. | **No complete validated boundary today; do not kill the technical provider.** `DM-6-27` is a strong default, not a substitute for hard algorithm correctness. | Build an operation-by-operation matrix for the exact target/OE. Execute validated initialization/service indicators only after the exact `aws-lc-fips-sys` graph is registered. Label every uncovered operation nonvalidated. |
| `SEC-A05` Identity and scope keying | Unique pre-mission identity, scope compartmentation, no universal read, local/direct mutual authentication | No completed FOSS composition binds node credential, mission identity, scope membership, carrier authentication, and source-object publisher identity. | **Continue; residual profile work is unavoidable.** Keep policy values out of the framework while specifying interoperable mechanisms/state. | Provision two offline roots/nodes and overlapping scopes; prove unprovisioned rejection, carrier-to-mission binding, scope-A-only read, clone/key-substitution behavior, and no online dependency. |
| `SEC-A06` Disconnected exclusion/rekey | Mesh-propagated removal, in-field scope rekey, deterministic no-clock behavior | BVB-735 buys OpenMLS classical reload/removal/epoch mechanics. BVB-825 separately carries a dual-signed generation control through a restarted relay; after acceptance, the old relay cannot open generation two while its replacement can. Generation-two keys were directly preprovisioned, and a restored old snapshot remains an older view. | **BUY OpenMLS mechanics; awareness gate passes; hard key distribution/authority/rollback remains unowned.** | Carry exact OpenMLS plus signed authority bytes, establish fresh scope keys excluding removed members, and test concurrency, rollback, rejoin, lost authority, retained generations, and no-clock ordering. |
| `SEC-A07` Group OSCORE + ACE | Standardized group protection, joins, member source authentication, rekey | BVB-701 definitively found only pairwise OSCORE in frozen libOSCORE and Californium; neither has Group OSCORE, ACE Group Manager, group countersignatures, durable group replay, or rekey. RFC 9594 and registered Group OSCORE transition semantics remain design inputs. | **Stop the current executable lane; keep the standards lane.** Do not spend runtime effort on code paths that do not exist. | Re-enter only after an exact maintained implementation registers and statically demonstrates group mode, per-sender authentication/replay, GM join/rekey/removal, and provider hooks. Otherwise cost these semantics as custom and compare that delta against MLS/COSE. |
| `SEC-A08` MLS comparator | Group membership/key evolution and application protection | RFC 9420 is final. BVB-735 executes exact OpenMLS 0.8.1 across three phase processes: persisted add/remove/application state, awareness-bounded exclusion, one delayed control sequence, one replay rejection, and an application-selected concurrent-fork re-add converge. Stable executed crypto is classical; no real temporal carrier, DS/AS integration, automatic fork detection, rollback defense, or durable-object policy ran. `mls-rs` remains a documented secondary candidate, not an exact executed graph. | **Leading FOSS buy for classical membership mechanics; not the whole profile.** Keep source objects, outer routing metadata, authority policy, delivery, general replay, and mandatory hybrid requirements separate. | Carry exact MLS control/application bytes through the selected temporal carrier, bind authority and mission/scope identities, exercise more fork/removal patterns and long retained generations, then decide whether a second MLS implementation changes interoperability confidence. |
| `SEC-A09` BPSec role | Standard DTN block integrity/confidentiality over temporal forwarding | Hardy built and passed RFC 9173 tests under BVB-702. No application policy, key lifecycle, source-to-consumer daemon path, hybrid algorithm, replay binding, or metadata privacy ran. dtn7 temporal carry used no BPSec. | **Keep as optional outer DTN security/control, not the source-object owner.** | Execute a Hardy BIB/BCB policy with source/acceptor roles over a persisted relay, inspect visible primary/extension fields, then cross-check vectors with a separately frozen ION/HDTN oracle. Measure duplicate layers against inner source object. |
| `SEC-A10` Replay and durable freshness | Captures never become new data/membership events after restart, rekey, reordering, or multi-peer duplicate delivery | BVB-825's atomic journal rejected two duplicates after full restart, one stable-ID repeat across generation change, and a stale generation-one batch. Restoring a pre-accept snapshot reaccepted two items. | **Bounded ordinary-restart/generation pass; shared state remains custom; snapshot rollback explicitly unresolved.** | Bound and compact item/control state, test power loss and multipath, then decide and implement the storage-rollback policy separately. |
| `SEC-A11` Algorithm agility/downgrade | Versioned negotiation and explicit downgrade prevention | BVB-725/BVB-825 bind fixed version, suite, algorithms, identities, and forwarding AAD; mandatory-component and changed-suite/key-confirmation negatives fail. No offer/selection, minimum policy, mixed-version interpretation, or rollback store exists. | **Fixed-object and fixed-establishment gates pass; negotiation remains open.** | Freeze canonical offer/selection encodings; test stripped stronger offers, replayed old policy, mixed versions, critical extensions, and storage rollback without wall-clock dependence. |
| `SEC-A12` Zeroization and key custody | Rapid local destruction hook | BVB-825 defines and executes a scoped hook that overwrites one application-owned buffer, removes its logical key path, and rejects later handle use. It explicitly proves no provider/HSM destruction, compiler/runtime-copy guarantee, physical-media erasure, crash, backup, or snapshot erasure. | **Hook contract shape passes; custody guarantee remains unowned.** | Inventory all material and copies, bind provider/HSM/OS-store destroy adapters, and test idle/transfer/rekey/crash and error semantics per target. |
| `SEC-A13` Mutual-authenticated adjacency | Authenticate peers before protocol data | RFC 10024 is registered as final hybrid TLS key-establishment semantics. rustls 0.23.43/AWS-LC and OpenSSL are maintained documented implementation families, but no exact RFC-10024 graph/vector run is frozen for this profile. TLS protects one live IP adjacency and cannot satisfy source-to-consumer, temporal-relay, BTLE, broadcast, or file paths. | **Documented optional IP component; not yet executable profile credit.** | Freeze the exact rustls/provider graph and RFC 10024 vector behavior only for surviving IP lanes; bind TLS credential to mission identity, test resumption/downgrade, and retain transport-independent authentication for non-IP carriers. |
| `SEC-A14` Batch/amortized authenticity | Per-item source binding under optional PQ batching | BVB-825 signs one encrypted ordered two-item batch while persisting independent item IDs. Omission, reorder, substitution, and cross-batch splice attempts fail verification. The public carrier objects are 8,185 and 8,189 bytes. | **Bounded profile-shape pass; operating envelope and partial-transfer policy remain open.** | Sweep batch cardinality/item sizes/link conditions and define interruption, resume, limits, canonical bytes, and garbage collection. |
| `SEC-A15` Bridge authorization | Cross-scope topic/priority filtering without payload plaintext or publisher rewrite | No security candidate has executed the bridge role. | **Continue after nested metadata object exists.** | Sign/version default-deny policy, authenticate filter inputs, test both directions/nested bridges/rollback, and prove rewrapping cannot widen access or obscure source identity. |
| `SEC-A16` Conformance/parser assurance | Independently implementable profile, bounded hostile parsing, exact dependency admission | The exact `coset` graph, BVB-725 negatives, BVB-825 integrated profile seed, three public ciphertext fixtures, and source public keys now exist. There is still no independent parser, complete secret-bearing KAT set, hostile-parser resource result, production SBOM, or transitive admission. | **Research seed frozen; final-selection blocker remains.** | Adopt the normative profile, publish complete positive/negative vectors, run an independent implementation/provider, fuzz and resource-bound parsing, and finish production admission. |

## Post-research production gates

The Phase 4 research arms are complete at a bounded frontier. Remaining work
is conditional integration or final-selection assurance, not an unrun FOSS
survey arm:

1. Bind exact OpenMLS/authority control bytes to the selected temporal carrier
   and distribute fresh scope keys excluding removed members.
2. Run the BVB-825 public ciphertext fixtures over surviving physical IP/BTLE
   and conditional BP lanes, including role-specific captures and bridge views.
3. Adopt a normative hybrid signature/establishment and negotiation profile,
   then run independent vectors and parser/resource faults.
4. Define bounded replay compaction and the separate snapshot-rollback policy.
5. Bind the zeroization hook to every target provider/HSM/OS-store handle.
6. Freeze the exact FIPS module/OE/service matrix; never infer validation from
   provider APIs or algorithm support.

## Registration and authorization queue

No new external source was consulted for the provider run. The next source
registrations are partly complete; archive registration does not authorize an
unfrozen dependency graph or build:

1. **Provider execution — complete as BVB-710:** the append-only row identifies
   the report/result, `aws-lc-rs 1.18.0`, `aws-lc-sys 0.44.0`, lock
   `e0b17c40739996b2661b18ce5fba1151adcda5f3b5dfa466d538c951dc5ab5a6`,
   harness `f1d6746efb268a5a63eb0cd717a9765b373f4de3f74dfb809702f1e687db7206`,
   binary `caf20ec9142ce3790149696b424853c1ae6eec5dcd3489708460628c1567091f`,
   and the explicit non-FIPS/no-CMVP boundary.
2. **t_cose source-object lane — complete stop as BVB-717/BVB-718:** exact
   v1.2.0 is classical Sign1-only and does not contain the separately described
   2.x multiple-signature/encryption surface. Retain it only as a classical C
   oracle/component; no build graph is justified for the complete hybrid lane.
3. **coset object lane — complete as BVB-722/BVB-723/BVB-725:** the exact
   source, graph, runner, binary, summary, and raw execution hashes are frozen.
4. **Integrated security profile — complete as BVB-815/BVB-818/BVB-819/
   BVB-821/BVB-825:** the failed trials and exact corrections are preserved;
   BVB-825 binds the successful source, binary, 69-file raw receipt, visible
   summary, and public ciphertext vectors. The profile remains research-only.
5. **OpenMLS comparator — complete as BVB-726/BVB-727/BVB-735:** exact tag
   `openmls-v0.8.1` commit `47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6`
   archive SHA-256
   `29427912c8190c029340194f56178266a04fc76658c03b5ebdad3df23e5d92f0`.
   Its archive has no lock. BVB-726 authorizes the focused 154-package graph,
   BVB-727 corrects only the local artifact paths, and BVB-735 freezes the
   runner/binary/log/result hashes and bounded execution.
6. **mls-rs secondary comparator:** exact commit/tag and archive corresponding
   to the registered 0.55.3-era manifest; BVB-102 through BVB-106 do not yet
   freeze a release artifact.
7. **FIPS execution:** exact `aws-lc-rs`/`aws-lc-fips-sys` release graph that
   maps to the selected certificate/module revision and target OE. Do not use
   the 1.18.0 non-FIPS graph or the merely submitted FIPS-4 line as validation
   evidence.
8. **BPSec interoperation:** exact ION and/or HDTN release commit, source
   archive, license disposition, and build/dependency graph. Existing
   documentation receipts do not authorize an inferred executable freeze.

Appending a source-register row changes the ledger hash. Any normalized result
must either refresh its frozen current-ledger artifact/hash or retain and name
the exact earlier source-register snapshot. Do not mutate an earlier envelope
so it appears to have frozen a ledger state that did not yet exist.
