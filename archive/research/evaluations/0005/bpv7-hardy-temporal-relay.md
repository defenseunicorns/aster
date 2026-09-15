# Hardy independent BPv7 temporal-relay result

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.

>
> Requirements-first research evidence only. The sole architecture authority is `data-mesh-requirements.md` v0.1, SHA-256 `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`. Current Aster compatibility has zero selection weight.

## Outcome first

The second independent BPv7 implementation arm passed its narrow temporal topology. Frozen Hardy commit `b87c790263392a6289f942e6bf59fdb714f4c842` carried one 101-byte payload from A to B while C had never started, retained it in B's SQLite and local-disk stores, survived a complete B process exit, and forwarded it after B restarted from the identical paths while A was absent. C's upstream echo service consumed the bundle and emitted a response whose extracted payload had the same SHA-256, `124055002104eb734cbac0444f30713874cb392ba4943db90131a34b96cfb9eb`.

That is real buyable temporal-forwarding evidence, independent of the earlier dtn7-rs daemon result. It is not a security pass. A fixed-string scan found the payload marker in B's durable bundle file, so the exact unprotected composition fails the relay payload-blindness requirement.

The lightweight machine result is archived `temporal-relay-file-003.summary.json`. Raw source, builds, daemon state, and the three trial directories remain local and ignored. The derived 31-file receipt is archived `temporal-relay-file-003.raw-manifest.sha256`.

## Exact executed slice

| Item | Frozen value |
|---|---|
| Hardy source | Commit `b87c790263392a6289f942e6bf59fdb714f4c842`; archive SHA-256 `476baa05daf500ee35da1e3b120329b6a2e0e913c0878c5702515d268b249b48` |
| Dependency lock | SHA-256 `de8a11c131fc4091cb5de0879f34cf72eb78798f2704d6770d09d81d0cfed392`; 506 registry packages plus 30 local/workspace packages, no git dependencies |
| BPA features | `hardy-bpa-server --no-default-features --features file-cla,sqlite-storage,localdisk-storage,echo` |
| Producer/oracle tool | `hardy-bpv7-tools` `bundle` |
| Selected graph receipts | BPA `42f16af87ece55e891fd26442fa0f0acb899189d24822f8ed1795370b384790b`; tool `3b8dee50301b728ef805cb93568863df1ba9bf2716c71070fda41518ff42d93f` |
| Build | Locked offline release build passed; log SHA-256 `c9ef3b68d69664e1d157e575848e4f6146e26ad39b9aa75897123cb92d2ce4bd` |
| BPA binary | 11,867,040 bytes; SHA-256 `7eb139a7af09257fa0320224230cbea783a0adf1afdf1104cc44e2215eb5bc73` |
| Bundle tool | 2,524,144 bytes; SHA-256 `ef9339e88b494261874e9f1ca8821dd270f22876c01aefb1c263d8fc1680c46f` |
| Compiler | `rustc 1.97.1`, `aarch64-apple-darwin`; upstream workspace declares Rust 1.95 |

Hardy is Apache-2.0. The exact research slice uses bundled SQLite through `rusqlite`; the SQLite public-domain component remains a policy hold under the repository's literal OSI-approved-only rule. Passing this run does not admit the dependency.

## Executed topology

1. The Hardy bundle tool created and validated a 189-byte BPv7 bundle from `dtn://a/app` to `dtn://c/echo`, with a one-hour lifetime and hop limit 16.
2. B started with Hardy SQLite metadata, local-disk bundle storage with `fsync: true`, and a File CLA inbox. C did not exist.
3. A started with the same durable backend types, a static route for `dtn://c/**` through `dtn://b/`, and a File CLA peer for B. A submitted the bundle.
4. B's metadata database recorded exactly one live row in status `Waiting`, with 1,072 bytes of metadata. The driver hashed B's database and raw bundle file, then fully exited A and B.
5. Before restart, a plaintext scan matched the fixture marker in B's raw bundle file.
6. C started with the upstream Hardy echo service and a File CLA return peer for A. A remained absent.
7. B restarted from the same metadata and bundle paths with a File CLA peer for C. The waiting bundle was forwarded; B's row became a tombstone.
8. C's echo service generated a 194-byte response from `dtn://c/echo` to `dtn://a/app`. Hardy validated and parsed it, extracted 101 bytes, and byte-compared them with the source fixture.

The File CLA directories are a controlled same-host contact model. This proves candidate-native serialization, durable BPA lifecycle, forwarding, and service delivery for the bounded case. It does not claim physical removable-media operation, TCPCLv4, radio behavior, or cross-implementation interoperability.

## Requirement-scoped result

| Requirement | Result | Evidence and boundary |
|---|---|---|
| DM-5.6-03 — bridge non-overlapping contacts | **Met** | One durable `Waiting` bundle survived B's complete exit and same-store restart, then reached C while A was absent; C's echo response proves service consumption. |
| DM-12-05 — payload-blind temporal relay | **Partial** | The temporal and consumption halves passed; payload blindness failed. |
| DM-6-07 — relay has no payload plaintext access | **Not met** | The known marker matched B's durable local-disk bundle before restart. |
| DM-5.6-05 — bounded duplicates | **Unknown** | No duplicate item or repeated contact was injected. |
| DM-5.6-06 — bounded loops | **Unknown** | No cycle or loop bound was exercised. |

Trials 001 and 002 are retained but receive no candidate credit. Trial 001 stopped because the host's `RUST_LOG=warn` hid an info-level readiness event. Trial 002 then revealed that the frozen user documentation's `watch: false` example did not match the frozen typed enum, which accepts `none`, `native`, or `poll`. BVB-786 and BVB-792 preregistered the minimal evaluator corrections before fresh runs.

## Credits kept separate

| Responsibility | Credit from this arm |
|---|---|
| BPv7 codec/library | The source and response bundles were created, validated, parsed, and extracted by the frozen Hardy tool. BVB-702 separately records 113 `hardy-bpv7` tests, including RFC 9173 vectors. Do not merge those two receipts into an interoperability claim. |
| BPA temporal relay | **Positive, bounded local demo.** Hardy's unmodified BPA, SQLite metadata backend, local-disk bundle backend, File CLA, static route, and echo service completed the restart topology. |
| BPSec | **None.** No key, policy, BIB, or BCB was selected. The frozen library's RFC 9173 tests are not this composition's security. |
| Custody, BIBE, reports, and QoS | **None.** No custody-like or BIBE behavior, status-report semantics, requirements-priority ordering, retransmission aggressiveness, eviction order, expiry suppression, quota, or emission threshold was tested. |
| Interoperability | **None.** All participating code came from the same Hardy commit. File CLA was used instead of TCPCLv4, and no second parser or daemon exchanged this trial's bundle. |
| Requirements security | **Failed for this composition.** Relay plaintext was present; no mutual transport authentication, source-object profile, protected mesh metadata, hybrid-PQ policy, replay state, rekey, revocation, or zeroization was composed. |

## First-principles implication

This clears the proposal's requirement to execute two frozen BPv7 implementations in the temporal topology: dtn7-rs and Hardy now both have positive, independently executed restart results. The FOSS-buy conclusion is stronger than before: do not authorize a new BPv7 codec, bundle lifecycle, persistent forwarding queue, or file-carrier serialization merely because the first daemon is unsuitable for production. Hardy supplies a second executable implementation and a substantially more embeddable component set.

The result does not make BPv7 the selected whole architecture. A final BP composition still needs separate, executable owners for source encryption/authentication, membership-protected forwarding metadata, duplicate/loop bounds, requirement priority and expiry policy, application delivery assurance, constrained-carrier framing, and independent interoperability. Those missing responsibilities must remain visible rather than being attributed to BP base semantics.
