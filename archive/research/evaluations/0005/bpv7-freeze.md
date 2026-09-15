# BPv7 first implementation freeze and temporal-relay result

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.

>
> Requirements-first research evidence only. This report does not admit a dependency, select a product architecture, or grant application delivery, BPSec, QoS, priority, or custody credit.

- Evaluation date: 2026-08-22
- Requirements baseline: `data-mesh-requirements.md` v0.1, SHA-256 `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Consulted candidate/standard sources: registered sources only — STD-020, BVB-648–659, BVB-686, BVB-692, and the exact grouped Cargo graphs in BVB-695
- Final normalized envelope: archived `temporal-relay-02.normalized.json`. The earlier checked-in trial JSON remains deliberately preserved as a non-normalized summary.

## Outcome first

Two distinct implementation roles are frozen.

| Candidate | Frozen role | Executed result | Current disposition |
|---|---|---|---|
| Hardy `hardy-bpv7` 0.6.0 | Embeddable Rust BPv7/BPSec library research candidate | Locked default `rfc9173` graph built; 113 package and RFC 9173 tests passed | Continue as the embeddable candidate. No daemon-relay or product-security credit yet. |
| dtn7-rs `dtn7` 0.21.0 from untagged head | Independent external daemon experiment and BP oracle | Locked daemon built; six library tests passed; A→B, B termination/restart, B→C non-overlapping temporal relay passed | Retain as daemon/oracle. Hold production adoption: affected versions for five RustSec vulnerabilities and six informational maintenance/unsoundness findings occur in the selected host closure, and no repository security policy was found. Reachability was not assessed. |

The executable result establishes a narrow positive finding: the frozen dtn7-rs daemon with sled persistence can bridge non-overlapping contacts across a relay restart. It simultaneously disproves payload-blind credit for that exact run: B's durable database contained the plaintext payload prefix.

## Requirement-scoped result

| Requirement | Result | Evidence and boundary |
|---|---|---|
| DM-5.6-03 — relay state bridges non-overlapping contacts | **Met** | Before restart, B reported one stored `ForwardPending` bundle. A and B then stopped. B restarted from the same sled work directory, contacted C while A was absent, and C received byte-identical content. |
| DM-12-05 — payload-blind temporal relay | **Partial** | Temporal delivery passed, but payload blindness failed because the selected run used no BPSec or source-protection layer. |
| DM-6-07 — relay has no payload plaintext access | **Not met** | A fixed-string scan found `BPv7 temporal relay probe` in B's persistent sled database. |
| DM-5.6-05 — bounded duplicate propagation | **Unknown** | Duplicate contacts/items were not injected. No credit is inferred from one delivery. |
| DM-5.6-06 — bounded loop propagation | **Unknown** | No cyclic topology was run. Epidemic routing is not itself a bound proof. |

The reviewable requirement summary is archived `temporal-relay-02.summary.json`. Trial 01 is preserved as a harness failure, not a candidate failure: its readiness matcher expected the human EID form while `dtnquery` rendered the scheme separately. archived `temporal-relay-01.summary.json` records the correction.

## Immutable candidate freezes

### Hardy — embeddable Rust role

- Repository: `https://github.com/ricktaylor/hardy`
- Commit: `b87c790263392a6289f942e6bf59fdb714f4c842`
- Git tree: `6fe0dcf2e3f4e91c31d37fc23c259dfd4b8f6418`
- Commit time: 2026-08-21T21:15:12+01:00
- Release identity: the head is untagged, 130 commits after `v0.2.0`. The tag object is `bc004934ac4c62a3643dea0b0ba58e8241db765b`, peeling to `a0bd394ad5222088fb24b6756ce597e1dcebcd63`. Its SSH signature was cryptographically valid, but no local allowed-signers principal established signer identity. The frozen head itself had no recorded signature.
- Local Git archive: 5,222,400 bytes, SHA-256 `476baa05daf500ee35da1e3b120329b6a2e0e913c0878c5702515d268b249b48`
- Selected package: `hardy-bpv7` 0.6.0, Apache-2.0; license-file SHA-256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`
- Lock: SHA-256 `de8a11c131fc4091cb5de0879f34cf72eb78798f2704d6770d09d81d0cfed392`; 536 entries: 506 checksum-pinned registry packages and 30 workspace/path packages; no git dependency.
- Selected normal/build closure: 61 packages with default `rfc9173`; the crate's `std` feature was not enabled. The host execution does not prove every advertised embedded target.
- Compiler: rustc 1.97.1, aarch64-apple-darwin; upstream manifest declares Rust 1.95.
- Build: `cargo build --locked --offline --release -p hardy-bpv7` passed. The produced rlib was 2,591,200 bytes, SHA-256 `13c3363d5f8e0738cad0ced473d290b1194959daee48813f935c9be37bf96587`.
- Tests: `cargo test --locked --offline -p hardy-bpv7` passed 113, failed 0. This includes 18 RFC 9173 tests and appendix vectors; it is not application-profile security evidence.
- SBOM: CycloneDX 1.5, SHA-256 `24129367bb67f5322f0bbb5352a17b3a04354ca85d5590cac2db4d173e525529`.
- License scan: 66 all-target, non-dev entries; none lacked a detected license. `r-efi` contributes LGPL-2.1-or-later in an all-target branch but is absent from this host closure; target-specific obligations remain a release review item.
- Security support: `SECURITY.md` exists, SHA-256 `d76ce122062376e06909a2c07bf70b27e21cb6b4cad0b3270a8df06c6aedefa6`, and directs private GitHub reporting. It names neither supported versions nor a response SLA. Against RustSec commit `bf5c0d245a92671908518d7e765914d437954ed6`, the full workspace lock had zero vulnerability findings and one `lru` unsoundness warning; `lru` is absent from the selected host closure.

The complete lightweight receipt is archived `receipt.json`; the selected feature graph and package list remain reviewable beside it. Raw source, archive, SBOM, metadata, and logs remain local and ignored from repository/product files.

### dtn7-rs — daemon/oracle role

- Repository: `https://github.com/dtn7/dtn7-rs`
- Commit: `c30181b4b111e2adc5538931c797c0f7190acc4c`
- Git tree: `d07549c72fc447c2989aac26872b29b9b28ee537`
- Commit time: 2026-05-27T09:41:17+02:00
- Release identity: the head is untagged, 22 commits after `v0.21.0`. The annotated tag object is `ffd79da24c907964f3c0994d17487e7b32c2e28e`, peeling to `4d1f6e034034639e09404cc54450b5b2bf153eac`; it has no signature. The frozen head also had no recorded signature.
- Local Git archive: 1,382,400 bytes, SHA-256 `7b7c8207f1c9aa3fc666b2a54a2160203946c48d7236b4d06c5a7073eb7ade1c`
- Selected package: `dtn7` 0.21.0, MIT OR Apache-2.0; license-file hashes are frozen in the receipt.
- Lock: SHA-256 `ceeb4a9057389e602e2bf3361080a2f9b9dd5d927c73cdcad964c920564552ee`; 284 entries: 281 checksum-pinned registry packages and three workspace/path packages; no git dependency.
- Selected normal/build closure: 193 packages with default `store_sled` and `store_sneakers` features.
- Build: debug and stripped release daemon/tool builds passed under rustc 1.97.1 on aarch64-apple-darwin. The release `dtnd` Mach-O was 10,637,152 bytes, SHA-256 `7c34845cb64d4567b13e63b1832bc37449fab45b9dc8282bb9da73d7fad89eb7`, dynamically linked to system Security, iconv, and System libraries. It emitted one unused-import warning.
- Tests: `cargo test --locked --offline -p dtn7 --lib` passed 6, failed 0.
- SBOM: CycloneDX 1.5, SHA-256 `f3712ba39ff0378359fdb0fe84979758b5eb0ab69c6eec1a657f4360aae0ea0c`.
- License scan: 248 all-target, non-dev entries; none lacked a detected license. The detected set includes permissive licenses and MPL-2.0; the exact inventory remains local.
- Security support: no `SECURITY` file was present in the frozen repository and no registered private-reporting channel was established. Against the same RustSec snapshot, the full lock produced eight vulnerability findings, five unmaintained warnings, and three unsoundness warnings. Affected versions for five vulnerabilities occur in the selected host closure: `bytes` 1.6.0, `crossbeam-epoch` 0.9.18, `idna` 0.5.0, `libsqlite3-sys` 0.23.2, and `tungstenite` 0.17.3. Reachability was not assessed. Three selected packages are flagged unmaintained (`fxhash`, `instant`, `serde_cbor`), and three selected packages have unsoundness advisories (`anyhow`, `rand`, `tokio`).

The complete lightweight receipt is archived `receipt.json`.

## Temporal-relay execution

The executable topology was deliberately smaller than a product composition:

1. Start B with a sled store, epidemic routing, discovery disabled, and loopback MTCP.
2. Start A with only a static A→B contact. C does not exist.
3. Submit a 145-byte payload at A for `dtn://c/incoming`. A reports a 229-byte bundle. B reports one stored `ForwardPending` bundle.
4. Terminate A and then B. Both processes required SIGTERM after the driver's SIGINT grace period; this is a crash-like restart, not a graceful-shutdown claim.
5. Hash B's two persistent store files, start C while A remains absent, then restart B from exactly the same work directory with only a B→C static contact.
6. C's application endpoint writes 145 bytes. Source and received SHA-256 are both `70452b3c5c3bc075bd1a35c0e3549164b0a3c317209e743dac1c53a522addebb`.
7. Scan B's durable store for the known payload prefix. The match proves the exact unprotected run was not payload-blind.

The successful run used dtn7-rs debug `dtnd` SHA-256 `dc00874ab000a8687ea71bda4913402772a30a6e78b771955d28b7e807169be1`. The reproducible driver is archived `temporal_relay.sh`, SHA-256 `afe3a5d5d7790582e37d73c2e492ef84aa0f8166cce26e5adce96f7ac6583096`. Its raw trial manifest SHA-256 is `0cb28141ea36d57da4ecef2fc6ac75755a8880e076e292ad0a1da581d148c5ba`; raw state and logs remain local under the ignored trial tree.

## Explicitly separate non-credit

| Concern | Result |
|---|---|
| Application delivery assurance | **Not tested.** A successful BP endpoint fetch is not proof of application at-least-once delivery, deduplication, or durable application effect. |
| BPSec | **Not selected in the relay trial.** Hardy's RFC 9173 library tests establish only the frozen library surface. dtn7-rs BPSec support remains unknown rather than inferred absent. |
| QoS / requirement priority | **Not tested.** Epidemic forwarding and BP lifetime do not establish four priorities, ordering, retransmission aggressiveness, eviction order, or emission thresholds. |
| Custody / BIBE | **Not tested.** No custody-like extension or bundle-in-bundle behavior was configured or observed. |
| Source-object and mesh-metadata security | **Not met by this composition.** BPSec alone would still require a requirements-specific policy, key lifecycle, membership metadata layer, and executable proof. |

## Reproduction and evidence handling

Only exact locked graphs were fetched after BVB-695 registered their crates.io sources. Both lockfile hashes were rechecked after fetch, metadata generation, build, test, and trial. No dependency update, git dependency, source substitution, or package patch occurred.

The principal commands were:

```text
cargo fetch --locked
cargo metadata --locked --offline --format-version 1
cargo build --locked --offline --release -p hardy-bpv7
cargo test --locked --offline -p hardy-bpv7
cargo build --locked --offline -p dtn7 --bins
cargo test --locked --offline -p dtn7 --lib
cargo build --locked --offline --release -p dtn7 --bins
./temporal_relay.sh
```

The installed RustSec worktree contained one untracked advisory file. It was not opened. Both locks were rescanned against a clean local checkout of tracked commit `bf5c0d245a92671908518d7e765914d437954ed6`; clean and initial report bytes were identical. The advisory freeze receipt is archived `receipt.json`.

Candidate-root ignore rules retain all raw evidence locally while preventing upstream checkouts, build outputs, archives, SBOMs, scans, daemon state, and raw trial trees from entering repository or product source. Only drivers, selected graph summaries, receipts, and review summaries remain visible.

## Decision

- **Hardy:** keep as the priority embeddable Rust candidate. Next evidence, if scheduled, is its own durable BPA relay/restart run and cross-implementation vectors; this report grants neither.
- **dtn7-rs:** keep as a useful executable daemon/oracle because temporal relay passed. Do not admit the frozen graph into a production role without a new immutable graph that clears the applicable advisories and establishes a vulnerability-response path.
- **BPv7 arm:** temporal dissemination remains viable. The experiment does not collapse the missing application delivery, security profile, priority/emission, duplicate/loop bounds, or custody-like ownership into BP base semantics.
