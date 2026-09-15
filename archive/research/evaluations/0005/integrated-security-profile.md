# Phase 4 integrated security-profile result


- Status: research arm complete; component/profile frontier only; no
  production selection
- Evidence date: 2026-08-22
- Sole product authority:
  [`data-mesh-requirements.md`](../../../data-mesh-requirements.md)
- Requirements SHA-256:
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Execution: BVB-825
- Corrected source authorization: BVB-821
- Exact FOSS graph: BVB-722/BVB-723 (`coset` 0.4.2 plus
  `aws-lc-rs` 1.18.0, non-FIPS)
- Result:
  [`summary.json`](../../../../docs/evaluations/0005/results/security-profile.json)
- Atomic requirement map:
  [`requirements-map.json`](../../../../docs/evaluations/0005/requirement-maps/security-profile.json)
- Research profile seed:
  [`integrated-security-profile-seed.md`](integrated-security-profile-seed.md)

Current Aster code, APIs, wires, storage, identity composition, and module
boundaries had zero selection weight and were not inspected. No new external
source was consulted. Bracketed link, loss, offline-duration, and overhead
values remain measurement points rather than elimination gates.

## Outcome

The smallest executed composition now demonstrates that the leading FOSS
object/provider pieces can be nested into the required reader split:

- outsiders cannot open the member metadata envelope;
- an admitted relay can read authenticated forwarding fields and verify both
  source signatures but has no payload content key;
- the relay can persist an opaque object, fully exit, restart, and forward the
  exact bytes to a consumer while the source is absent; and
- the consumer verifies both source signatures, authenticates both encryption
  layers, decrypts the item batch, and durably applies independent item IDs.

This closes the feasibility question, not the production security profile.
The member envelope, hybrid combiner, authority control, replay journal, and
zeroization contract are task-authored research scaffolding. Their remaining
normative and assurance work is visible rather than hidden in a carrier or
provider adapter.

## Exact execution

The exact corrected runner was formatted, checked with warning-denied Clippy,
compiled as a test target, and built in release mode locked and offline. The
release binary SHA-256 was
`6b0f4da1281a4ff19806c7d8c2fa1cf6f91d0ba4f1cad57f2d687c8b99021eb8`
at 2,792,096 bytes. The successful `security-profile-002` corpus contained 69
files and 77,118 bytes; its deterministic filename/hash/size receipt was
`a485e84e3e0a84ff7a38c58fdc2dcd7398c62c4926273be853f62534800ba438`.
Raw role inputs, state, logs, and secret material remain local and ignored.

The first `security-profile-001` attempt is preserved as a no-credit harness
failure. It stopped during generation because the harness compared a decoded
COSE recipient's serialization cache to a fresh semantic value. BVB-821
authorized the bounded correction to compare exact semantic fields; no result
from the failed attempt was reused.

## Results by required behavior

| Behavior | Exact result | Requirement disposition |
|---|---|---|
| Source-to-consumer verification after opaque temporal relay | Separate A generation, B ingest, B full exit/restart/forward, and C consume processes passed. B stored and forwarded byte-identically, had no content key, and its durable queue had zero protected-field or payload-marker matches. | Bounded pass for source protection and one payload-blind temporal relay; carrier-neutral file execution only. BVB-808 separately proves p2panda can preserve one opaque UTF-8 fixture through the same temporal topology. |
| Protected forwarding metadata | Outer member-keyed `COSE_Encrypt` protected generation, scope, topic, priority, route, object ID, and the complete source object. Outsider open failed; admitted relay open passed. | Bounded profile-shape pass. Direct fixture keys do not prove membership admission, multi-scope least privilege, key distribution, bridge rewrap, or physical capture privacy. |
| Durable replay across restart | After two items were durably accepted, a new consumer process received the exact capture and applied zero new items while identifying two duplicates. | Bounded ordinary-restart pass. The acceptance journal remains task-authored and has no compaction or bounded-retention proof. |
| Replay across membership change | A signed control advanced accepted generation one to two. A generation-two batch repeated one stable item ID and introduced one new ID; the repeat was harmless. A later generation-one batch was rejected as stale. | Bounded pass for stable IDs plus accepted-generation ordering. It does not define concurrent authority, missed-control recovery, or retained-key policy. |
| Mandatory classical plus PQ signatures | Exact ES256 then ML-DSA-65 slots were required. Missing classical, missing PQ, duplicate classical, tampered PQ, and authenticated forwarding substitution cases failed. | Mechanism pass; the private mandatory-both profile lacks independent implementation and published profile status. |
| Hybrid key establishment | P-256 ECDH and ML-KEM-768 both contributed to an HKDF-SHA-256 research key. AES-GCM key confirmation passed; four missing, changed-suite, and tampered-path cases failed. | Provider/composition feasibility only. The combiner, transcript, authentication, negotiation, and key distribution are not an adopted published hybrid profile. |
| Disconnected revocation/rekey | The exact signed control traversed B's durable relay before removal took effect at C. After C accepted generation two, old relay B could not open the generation-two envelope while replacement relay D could. | Awareness-bounded gate pass; hard revocation/rekey remains partial because generation-two keys were directly preprovisioned and OpenMLS control bytes were not integrated. BVB-735 remains the separate FOSS evidence for classical epoch/removal mechanics. |
| Per-item/authenticated-batch binding | Two items shared one encrypted dual-signed batch. Omission, reorder, payload substitution, and cross-batch splice variants all failed retained-signature verification; stable item IDs were accepted separately. | Bounded pass for the research batch shape. Partial transfer, limits, canonical independent encoding, and operating-envelope curves remain open. |
| Zeroization hook | One application-owned secret buffer was overwritten, its logical key path removed, and later handle use rejected. | Defined but partial. No provider/HSM destroy API, compiler/runtime-copy guarantee, crash behavior, filesystem erasure, backup, or snapshot guarantee. |
| Snapshot rollback | Restoring the exact pre-accept consumer state caused both captured items to be accepted again. Restoring ordinary current state retained replay protection. | Explicitly characterized and unmitigated. Ordinary process restart durability must not be promoted into snapshot-rollback resistance. |

## Standards, implementation, and module status

These columns are deliberately independent.

| Layer | Published-standard status | Exact implementation maturity | FIPS/CMVP operation coverage |
|---|---|---|---|
| COSE object syntax | RFC 9052 is final; registered COSE ML-DSA identifiers are final. This nested mandatory-both profile and private labels are not a published complete profile. | Exact `coset` 0.4.2 codec ran locally with the exact negative corpus. Research-only dependency candidate. | Codec is not a cryptographic module. |
| Classical/PQ source signatures | ECDSA P-256 and ML-DSA are standardized algorithm families. No adopted standard in this evidence defines the exact two-slot lifecycle, identity, negotiation, and replay profile. | Exact `aws-lc-rs` 1.18.0 APIs executed both slots and failed closed in the bounded wrapper. | Executed graph was explicitly non-FIPS. No certificate/OE/service-indicator credit. |
| Payload and member encryption | AES-256-GCM is a standardized authenticated-encryption mechanism; key and nonce lifecycle remain profile responsibilities. | Exact provider plus `coset` nested objects passed for the three frozen carrier fixtures. | No validated-module claim or operation matrix. |
| Hybrid key establishment | P-256 ECDH, ML-KEM-768, HKDF-SHA-256, and AES-GCM are reusable standardized mechanisms. The executed combiner and confirmation transcript are scaffolding. | Exact provider primitives passed locally. No independent provider exchange or protocol integration. | Non-FIPS graph; no complete certificate/OE coverage demonstrated. |
| Membership/rekey | RFC 9420 supplies classical MLS semantics. The task-authored control is not MLS and is not a replacement standard. | BVB-735 separately buys bounded OpenMLS 0.8.1 classical removal/epoch/reload mechanics; BVB-825 tested only the residual envelope/generation gate. | No registered CMVP boundary for the OpenMLS composition. |
| Durable replay and zeroization | No selected standard owns the complete item/control acceptance journal or application zeroization contract. | Task-authored bounded fixture only. | No provider/HSM or storage-media guarantee. |

No provider API presence, algorithm name, or certificate-family relationship is
treated as FIPS 140-3 validation credit. A final claim requires the exact
module version, certificate status, operational environment, approved mode,
service indicator, entropy and key paths, and every invoked operation.

## Responsibility disposition

| Responsibility | Disposition after BVB-825 | Residual |
|---|---|---|
| COSE source-object codec | **Advance / buy bounded FOSS mechanism** | Freeze an independently implementable profile, canonical encodings, parser bounds, and key lifecycle. |
| Replaceable classical/PQ primitive provider | **Advance technical provider surface** | Production admission, exact target support, side-channel/audit scope, failure policy, FIPS/non-FIPS operation split, and key custody. |
| Classical group epoch/removal machinery | **Buy OpenMLS bounded component evidence** | Bind mission/scope authority, source objects, temporal control delivery, PQ/hybrid profile, partition recovery, and secure storage. |
| Member-readable outer metadata | **Advance research profile shape; custom-hard until standardized/adopted** | Membership keys, field/leakage table, bridge rewrap, multi-scope least privilege, key rotation, and captures. |
| General replay/acceptance state | **Custom-hard bounded journal** | Resource bounds, compaction, tombstones, controls, crash/power loss, multi-authority ordering, rollback policy, and application-effect API. |
| Hybrid source signature rule | **Mechanism feasible; hold normative profile** | Exact standard/profile decision, identity/key binding, negotiation, deprecation, independent vectors, and downgrade/policy rollback. |
| Hybrid establishment | **Hold at provider feasibility** | Published/adopted combiner and transcript, authenticated negotiation, key confirmation, recipient/scope distribution, recovery, and interoperation. |
| Disconnected revocation/rekey | **Partial; continue only as residual integration** | Carry exact OpenMLS/authority bytes, distribute fresh scope keys excluding removed members, test concurrent changes, rejoin, lost authority, and no-clock ordering. |
| Zeroization | **Defined partial hook; no custody claim** | Complete key/copy inventory plus provider/HSM/OS-store destroy adapters and target-specific fault evidence. |
| Snapshot rollback | **Explicit unresolved risk** | Decide whether it is an operational assumption, future assurance requirement, or hard acceptance outcome; then add trusted monotonic state or equivalent defense if required. |

## Carrier composition boundary

The two public batch fixtures are safe opaque inputs for surviving carrier
arms. `epoch1.carrier` and `epoch2.carrier` contain only ciphertext, public
profile bytes, and source signatures; secret/member/content/private keys remain
ignored. A carrier test may earn exact byte preservation, store-and-forward,
capture, corruption, and restart evidence with them. It receives no source,
metadata, membership, replay, or FIPS ownership merely by transporting them.

BVB-808 already demonstrates that p2panda 0.7.1 can carry one externally
protected UTF-8 object through A→B, B restart, and B→C with zero relay plaintext
matches. BVB-702/BVB-794 demonstrate BPv7 temporal carriage but their executed
payloads were plaintext. Combining those orthogonal results with BVB-825 is a
bounded architecture inference, not a new end-to-end physical-carrier run.

## Final Phase 4 disposition

**Advance the exact COSE codec and replaceable-provider mechanisms, retain
OpenMLS as the leading classical membership buy, and hold the complete
security profile.** The integrated arm deletes uncertainty about whether the
reader split, mandatory-both signatures, durable ordinary replay, and
authenticated batching can coexist in one small composition. It also makes
the non-buys concrete: membership/key distribution, multi-scope authority,
negotiation, rollback, complete zeroization, FIPS module coverage, independent
interoperation, and production admission remain real profile/integration work.

No further local executable arm can honestly close those cells without first
freezing the missing normative authority, key-distribution, negotiation,
rollback, and custody contracts or registering a new implementation. Phase 4
research is therefore complete at the requirements-first frontier; production
acceptance remains blocked on those explicit residual gates, not on preserving
the experimental Aster architecture.
