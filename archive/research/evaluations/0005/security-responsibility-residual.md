# Phase 4 security responsibility and residual frontier


- Status: bounded requirements-first frontier; no production selection
- Evidence date: 2026-08-22
- Sole product authority: [`data-mesh-requirements.md`](../../../data-mesh-requirements.md)
- Requirements SHA-256:
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Executed security rows: BVB-702, BVB-710, BVB-725, BVB-735, BVB-825
- Exact implementation stops: BVB-701, BVB-717, BVB-718

Current Aster architecture, compatibility, APIs, identities, and wire formats
have zero selection weight. This report separates published-standard maturity,
exact implementation evidence, and CMVP/FIPS module coverage. It treats the
throughput, loss, offline-duration, and overhead anchors as WAG measurement
curves, not elimination gates.

## Outcome

The minimum-original-security hypothesis is now:

1. **Buy `coset` plus a replaceable provider** for source-object encoding and
   primitive execution.
2. **Buy OpenMLS for classical membership/group-epoch machinery**, while
   retaining source objects and durable item identity outside MLS.
3. **Keep temporal dissemination orthogonal** and carry the same protected
   objects/control bytes over whichever p2panda-native, BP, Zenoh, or other arm
   survives its own bakeoff.
4. **Retain the BVB-825 research profile seed** for mandatory-both rules, the
   member-readable outer envelope, stable item/generation acceptance, batch
   binding, and a scoped zeroization hook; build/profile only their still
   unowned production semantics plus mission/scope authority, key distribution,
   bridge authorization, negotiation, rollback, and complete custody.
5. **Use BPSec only when a BP carrier survives** and an executed BPSec policy
   deletes more DTN-specific security code than it duplicates.
6. **Use RFC 10024 TLS only on surviving IP adjacencies** as defense in depth;
   it never substitutes for transport-independent source protection.

This is a frontier hypothesis, not a final stack. BVB-825 closes the integrated
feasibility arm but no composition yet satisfies every hard security invariant.
The full execution, requirement map, and frozen research seed are in
[`integrated-security-profile.md`](integrated-security-profile.md).

## Explicit responsibility dispositions

Disposition labels are intentionally not scores:

- `BUY-EXECUTED`: exact FOSS mechanism ran and owns a bounded responsibility;
- `BUY-DOCUMENTED`: maintained implementation is documented but not yet run in
  this profile;
- `KEEP-STANDARD`: adopt semantics/design input, but no viable exact executable
  implementation currently owns them;
- `OPTIONAL`: useful only when another architecture choice makes it relevant;
- `CUSTOM-HARD`: final composition must own the hard outcome with a small,
  reviewable profile/state machine around FOSS primitives; and
- `UNKNOWN-BLOCKED`: evidence or an exact registered graph is insufficient.

| Phase 4 responsibility | Evidence-backed disposition | What FOSS/standard buys | Exact residual and no-credit boundary |
|---|---|---|---|
| Source encryption, authentication, publisher binding | `BUY-EXECUTED` | RFC 9052 object syntax, final ML-DSA COSE identifiers, exact `coset` 0.4.2 codec, BVB-725's nested object corpus, and BVB-825's separate-process opaque durable relay/consumer verification | Direct fixture keys are not key distribution; the mandatory-both rule is not an independent normative profile; no physical-carrier or production admission credit |
| Hybrid source signatures | `BUY-EXECUTED` mechanism plus `CUSTOM-HARD` profile | BVB-710 supplies P-256 and ML-DSA-65 APIs; BVB-725/BVB-825 prove exact mandatory slots and fail-closed missing, duplicate, tampered, and authenticated-field substitution cases | Freeze algorithms/parameters, identity/key binding, domain separation, canonical bytes, minimum policy, mixed-version behavior, independent vectors, negotiation, and policy-rollback defense |
| Hybrid key establishment and recipient distribution | `BUY-EXECUTED` primitives, `CUSTOM-HARD` composition | BVB-710 supplies P-256 ECDH and ML-KEM-768; BVB-825 makes both mandatory inputs and adds AES-GCM key confirmation with four negative cases | HKDF combiner/transcript remain scaffolding; no published/adopted profile, authenticated negotiation, recipient discovery, scope distribution, or rekey integration |
| Primitive provider | `BUY-EXECUTED` research candidate | Exact non-FIPS `aws-lc-rs` 1.18.0 safe Rust APIs cover P-256 ECDSA/ECDH, ML-DSA-65, ML-KEM-768, AEAD/HKDF needs | Production dependency admission, target support, side-channel/audit scope, key handles, provider failure policy, and exact validated/nonvalidated split remain |
| FIPS-approved algorithms and CMVP use | Hard algorithm mapping plus strong-default module use; currently `UNKNOWN-BLOCKED` for complete boundary | FIPS 203/204 and the classical algorithm standards are final; registered AWS-LC FIPS-3 certificate 5314 supplies a bounded validated candidate path including ML-KEM | BVB-710 is explicitly non-FIPS; certificate 5314's registered policy does not include ML-DSA and has bounded OEs; FIPS-4 is not certified; no one registered module/OE/service matrix covers the complete profile |
| Unique mission identity and scope compartmentation | `CUSTOM-HARD` | Basic credential, COSE key IDs, MLS credentials, TLS certificates, and provider key APIs are reusable mechanisms | No executed composition binds carrier identity, mission identity, publisher identity, mesh membership, and per-scope read authority or proves offline provisioning, clone/substitution behavior, and no-universal-read |
| Mesh-member-readable protected forwarding metadata | `CUSTOM-HARD` profile with executed shape | BVB-825's outer member-keyed `COSE_Encrypt` hides generation/scope/topic/priority/route/object ID from an outsider while a relay opens them, verifies the inner source object, and durably retains only opaque bytes | Key distribution/admission, multi-scope least privilege, carrier leakage, bridge rewrap, field policy, and production capture validation remain unowned |
| Membership, removal, group epoch evolution | `BUY-EXECUTED` classical component | RFC 9420 plus BVB-735 OpenMLS add/remove, two full reloads, epoch advance, effect after accepted removal, delayed control, and explicit fork/re-add helper | No signed authority object, mission/scope mapping, temporal carrier integration, automatic partition detection, concurrent removal policy, lost-authority/rejoin rules, hybrid/PQ suite, or production storage |
| Disconnected revocation and in-field scope rekey | OpenMLS mechanism plus `CUSTOM-HARD` profile | OpenMLS supplies classical epoch/removal state; BVB-825 carries a signed generation control through a restarted relay and gates generation-two metadata so the old relay fails while its replacement succeeds | Fresh keys were directly preprovisioned; exact OpenMLS/authority integration, key distribution, no-clock ordering, retained generations, rollback, missed updates, concurrency, and policy remain |
| Group OSCORE plus ACE | `KEEP-STANDARD`; executable lane stopped | RFC 9594 is final; registered Group OSCORE transition/draft semantics describe group source authentication/replay and GM concepts; frozen libOSCORE/Californium buy pairwise OSCORE only | BVB-701 found no Group Security Context, countersignature path, ACE Group Manager, group rekey, durable group replay, or hybrid provider boundary. Re-entry requires a new exact maintained implementation registration |
| BPSec | `OPTIONAL` for surviving BP arms | Final RFC 9172/9173 framing; exact Hardy library/default-context graph passed 113 tests including 18 RFC 9173 tests/vectors | No BIB/BCB application policy over a persisted relay, source/acceptor-to-publisher/consumer mapping, key lifecycle, hybrid profile, replay binding, metadata privacy, daemon forwarding, or independent interoperation. dtn7-rs BPSec remains unknown/not documented |
| Hybrid TLS adjacency | `BUY-DOCUMENTED`/`OPTIONAL` for IP only | RFC 10024 is final hybrid TLS key-establishment semantics; rustls/AWS-LC and OpenSSL are maintained documented families | No exact RFC-10024 profile run; TLS cannot receive source-object, temporal-relay, protected-metadata, BTLE, broadcast, or file-path credit; mission-identity binding, resumption, and downgrade remain |
| Replay, restart, and durable freshness | `CUSTOM-HARD` shared state with bounded execution | BVB-735 supplies one MLS replay fact; BVB-825's atomic item/generation journal rejects duplicates after full restart, one repeated ID across rekey, and one stale generation batch | Compaction, bounds, controls, power loss, multipath, and application-effect APIs remain; restoring a pre-accept snapshot reaccepts two items and proves rollback resistance is absent |
| Algorithm agility and downgrade | Fixed object/establishment `BUY-EXECUTED`; system negotiation `CUSTOM-HARD` | BVB-710/BVB-725/BVB-825 bind and negatively test fixed version/suite/algorithm/key/forwarding fields and mandatory key-establishment inputs | No authenticated offer/selection, minimum-version policy, cross-version critical rules, stored-policy rollback defense, or mixed-version lifecycle |
| Zeroization and key custody | `CUSTOM-HARD` with scoped hook shape | BVB-825 overwrites one application-owned buffer, removes its logical path, and rejects later handle use | No complete key/copy inventory, provider/HSM/OS-store destruction, compiler/runtime-copy guarantee, crash semantics, filesystem erasure, backup, or snapshot guarantee |
| Optional batch/amortized authenticity | Bounded executed shape plus `CUSTOM-HARD` profile | BVB-825 signs one encrypted ordered two-item batch, persists independent IDs, and rejects omission, reorder, substitution, and splice mutations | Partial transfer/resume, limits, canonical independent encoding, garbage collection, and overhead curves remain |
| Bridge authorization | `CUSTOM-HARD` after outer metadata | Nested protected objects can preserve an immutable inner publisher object | No signed/versioned default-deny policy, authenticated filter inputs, directional/nested bridge semantics, rollback behavior, or proof that rewrap cannot widen scope/priority or rewrite publisher identity |
| Independent conformance, parser bounds, dependency admission | Research seed; final-selection blocker | Exact `coset` graph and negatives, exact OpenMLS/Hardy component tests, BVB-825 profile seed, public ciphertext fixtures, and public verifier keys exist | No adopted normative whole profile, complete KAT set, second implementation, hostile-parser resource bounds, production SBOM/advisory/license admission, or target operating envelope |

## Standards, implementation, and CMVP are separate

| Family | Published-standard status | Exact maintained implementation status | FIPS/CMVP status |
|---|---|---|---|
| COSE plus ML-DSA | RFC 9052 and RFC 9964 are final; they do not define this repository's complete mandatory-both lifecycle profile | `coset` 0.4.2 codec/provider is executed by BVB-725 and in the integrated nested profile by BVB-825; `t_cose` 1.2.0 is classical Sign1-only | Codec has no module boundary; BVB-725/BVB-825 provider is non-FIPS |
| MLS | RFC 9420 is final; hybrid/PQ MLS ciphersuites remain draft work | OpenMLS 0.8.1 exact graph is executed by BVB-735; `mls-rs` remains documented, not exact-executed | No registered CMVP module covers either library; BVB-735 RustCrypto path has no validation credit |
| Group OSCORE/ACE | RFC 9594 is final; Group OSCORE final-publication credit remains pending because registered canonical endpoints were unavailable | BVB-701 exact frozen libOSCORE/Californium revisions implement pairwise OSCORE only; whole group lane stopped | No registered certificate/OE/service matrix |
| BPSec | RFC 9172/9173 are final and explicitly leave key management/application policy outside the base security service | Hardy exact library/default contexts execute; dtn7 temporal forwarding ran without BPSec; ION/HDTN remain oracle candidates | No exact candidate deployment has registered CMVP operation/OE coverage |
| Hybrid TLS | RFC 10024 hybrid key establishment is final; ML-DSA TLS authentication remains draft and is not the item signature profile | rustls 0.23.43/AWS-LC and OpenSSL families are documented; exact profile/vector execution remains | Provider-specific only; a validated TLS service would not validate source-object operations outside its boundary |
| AWS-LC provider | FIPS/NIST algorithm standards are separate from the API | BVB-710 exact 1.18.0 non-FIPS graph executes all four primitive families; BVB-825 reuses the same graph for the integrated object, key-confirmation, and zeroization-boundary corpus | Certificate 5314 is a different exact FIPS-3 module path, includes registered ML-KEM coverage but not ML-DSA, and has bounded OEs; FIPS-4 transition is not certified |

## Minimum residual custom security surface

“Custom” here means a reviewable normative profile or persistent acceptance
state built around FOSS primitives, never hand-rolled cryptographic
algorithms.

| Residual | Why upstream does not own it yet | Smallest credible boundary |
|---|---|---|
| Source-object profile | `coset` deliberately supplies codec, not policy; BVB-825 freezes only a research seed | Adopted canonical signing/encryption order, protected fields, mandatory-both slots, domain separation, algorithm/version policy, complete vectors, and independent agreement |
| Mission/scope authority | MLS, COSE, and TLS accept caller credentials/policy but do not define this mission model | Signed no-clock authority/control object; identity bindings; scope membership; authorization transitions; rejoin/lost-authority rules |
| Hybrid object/group key distribution | Provider has primitives; no selected standard/profile composes them for these roles | Registered combiner/profile, authenticated negotiation and key confirmation, recipient/scope distribution, rotation and recovery |
| Outer metadata envelope | BVB-825 proves the relay-member versus consumer reader split, but no standard/component owns its mission policy | Adopted member-readable field profile, membership key distribution, leakage table, bridge rewrap, multi-scope least privilege, and key separation |
| Durable replay/acceptance state | BVB-825 proves stable IDs and accepted generation across ordinary restart, while MLS covers its own generations | Bound acceptance windows, compaction, controls, crash/power loss, multi-path application effects, and explicit snapshot-rollback disposition |
| Temporal control dissemination | OpenMLS files proved serializability, not mesh carry | Carrier-neutral encoding/queue policy for commits, Welcomes, key packages, authority state, priority/expiry, retained generations |
| Zeroization/custody API | BVB-825 proves only one application-owned buffer/path hook; Delete/Drop still do not cover every copy and target | Complete key inventory, handle ownership, completion/error contract, crash/recovery, and provider/HSM/OS-store adapters |
| Conformance and assurance | Component self-tests cannot define whole-profile interoperability | Normative document, golden/negative vectors, independent parser/provider, fuzz/resource bounds, production graph and target admission |

## Research closure and production gates

BVB-825 runs the smallest missing integrated negative corpus without claiming
that the research seed is a standard. No remaining registered/frozen graph can
resolve the residual ownership by another build alone:

- BVB-701 proves the current Group OSCORE/ACE implementation paths are absent;
- exact OpenMLS plus authority/key-distribution integration requires a chosen
  mission authority contract before its result is meaningful;
- Hardy needs a selected BP arm, application BPSec policy, and independent
  oracle before an interoperation run can change its optional role;
- RFC 10024 needs a surviving IP lane and exact rustls/provider/vector freeze;
- validated AWS-LC claims require an exact certificate-matched graph, target
  OE, approved initialization, and operation service indicators; and
- provider/HSM zeroization and snapshot rollback require target custody and
  rollback contracts that the requirements do not currently normalize.

The Phase 4 research arm is therefore complete at the bounded frontier.
Remaining work is conditional architecture integration or final-selection
assurance:

1. Carry exact OpenMLS and signed authority bytes, establish fresh scope keys
   excluding removed members, and test concurrency, rejoin, and lost authority.
2. Run the BVB-825 public ciphertext vectors over surviving physical carriers
   and capture every outsider/member/bridge/consumer view.
3. Adopt normative hybrid signature, establishment, and negotiation rules;
   run independent vectors/providers and stored-policy rollback faults.
4. Bound replay state and compaction, test power loss/multipath, and decide the
   separate snapshot-rollback disposition.
5. Complete target custody adapters, FIPS/CMVP operation matrices, hostile
   parser/resource bounds, SBOM/advisory/license admission, and a second
   implementation before selection.

The decision is not “MLS versus COSE versus BPSec.” They own different
responsibilities. BVB-825 makes the leading composition concrete enough to
cost: `coset` plus a replaceable provider and OpenMLS delete substantial
mechanism code, while the adopted mission authority, key distribution,
metadata/replay profile, negotiation, rollback, and custody lifecycle remain
explicit original integration work.
