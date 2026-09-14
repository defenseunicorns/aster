# Evaluation 0005 rolling results log

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.


This is the human-readable, append-only working log for the requirements-first
FOSS evaluation. Add a dated entry when an execution arm reaches a registered
result, including the evidence IDs, bounded conclusion, denied credit, and next
decision. The machine authority for exact provenance remains the local
`evidence/SOURCE_REGISTER.csv`, which is deliberately outside the
public research commit.

Sole product authority:
[`data-mesh-requirements.md`](../../../data-mesh-requirements.md), SHA-256
`e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`.
Proposal 0005 is the evaluation work order, not product authority. Existing
Aster compatibility, migration cost, seams, and implementation boundaries have
zero selection weight. Bracketed operating values remain measured curves, not
automatic elimination gates.

## 2026-08-23T05:51:33Z — durable status checkpoint through BVB-870

### Requirements and controls

- The requirements are decomposed into 348 atomic cells with Must, Should,
  provisional, optional, and future properties kept distinct.
- The project register is append-only. Build, execution, correction,
  negative, environment-blocked, and no-credit evidence is retained rather
  than rewritten.
- Historical validator envelopes are snapshot-bound; they are not silently
  relabeled against the advancing source register.

### Whole-system and replica findings

- **p2panda v0.7.1 — bounded component advance, not a whole stack**
  (`BVB-700`, `BVB-808`, `BVB-860`, corrected by `BVB-863`). Local publish,
  durable store, restart replay, direct sync, one protected full-replica
  temporal carry, range selection, and abrupt post-durable/pre-ack replay were
  demonstrated. Prefix pruning retained the intended messages but restart
  metadata announced four operations, a bounded candidate failure. State and
  generic Record semantics are not supplied; auth, encryption, and Spaces are
  not wired into high-level Node; causal integration is incomplete; the Blob
  package is an unlinked stub; crypto providers are concrete rather than
  substitutable.
- **Greenfield explicit-control composition — research finalist** (`BVB-859`,
  locator correction `BVB-861`). SHA-256 first-seen binding, redb atomic
  store/effect marker, restart exactness, one duplicate application effect,
  corruption/truncation rejection, crash-before-commit absence, and bounded
  Negentropy inventory differences passed. Custom code still owns the frame,
  four data classes, durable reconciliation progression, cross-component
  atomicity, mission policy, and security lifecycle.
- **Zenoh encrypted immutable-sibling overlay — component only** (`BVB-853`,
  docs `BVB-857`). Partitioned writes, duplicate put, stop/restart/contact,
  isolated recovery, two exact encrypted siblings, and external conflict
  annotation passed. The custom overlay—not Zenoh—owns immutable keys,
  identity, encryption, siblings/conflicts, and application-effect gating.
  Zenoh remains conditional routing/replication/RocksDB machinery, not a whole
  replica finalist.
- **Willow** remains a storage/capability/Blob/Drop component and standards
  oracle. Native timestamp-first recency cannot own clock-independent causal
  State/Record arbitration.
- **Veilid** remains a local DHT/store oracle; its exact two-node loopback arm
  did not form a usable overlay and its graph has production blockers.

### Temporal dissemination

- Two independent BPv7 implementations demonstrated store-forward across full
  relay exit/restart (`dtn7-rs` under `BVB-702`; Hardy under `BVB-794`). This is
  not cross-implementation interoperability.
- **B1, immutable p2panda operations over BPv7**, is conditional. It works but
  has not yet shown a hard outcome beyond the native p2panda temporal path that
  justifies another durable store/progress/expiry owner.
- **B2, interactive sync over BPv7**, is a stop/cost arm: the one-pass topology
  failed and completion needed repeated waves plus live endpoint state.
- **C, BPv7 plus a thin mission profile**, is a standards-first control, not a
  current finalist.

### Connectivity and integrated compositions

- The manual-loopback **p2panda/greenfield × Iroh/Quinn** cross-product passed
  all four cells (`BVB-852`). Protected p2panda and greenfield frames crossed
  both carriers byte-exact; provider/wrong-identity challenges, restart verify,
  replay-one-effect, negative-frame rejection, and greenfield inventory
  equality passed. This supports thin opaque data-plane orthogonality only for
  these four local cells—not topology, reconciliation-over-carrier, tiny MTU,
  physical media, NAT, or relay orthogonality.
- Iroh is the conditional IP leader; Quinn remains the narrow explicit-control
  carrier. rust-libp2p remains a source/behavior oracle on hold due its exact
  advisory graph, automatic-discovery failure, and connection-mapping gap.
- The final named NAT/relay/hole-punch arm is active. The exact ARM64 Linux
  namespace tool image has been built offline and verified (`BVB-870`, image
  digest `sha256:d40d7ed6fc1250fac79a3e8d7988446500c3bd990d57b5e40f4a52909f727a8d`).
  Privilege preflight, exact Iroh/patchbay graph build, and the 13 normal plus
  three upstream-ignored Hard-cross topology cases remain to run.

### Security and membership

- The integrated `coset` 0.4.2 plus aws-lc-rs 1.18.0 non-FIPS profile arm is
  complete (`BVB-825`, docs `BVB-835`). Mandatory ES256 plus ML-DSA-65 source
  verification survived an opaque durable relay restart; outsider metadata
  open failed; ordinary and generation-change replay, stale generation,
  signature stripping, batch mutation, and key-confirmation negatives were
  rejected; an awareness-bounded rekey control advanced generations.
- The same arm deliberately receives no published hybrid-profile, key
  distribution, OpenMLS-byte integration, FIPS/CMVP, HSM destruction,
  independent interoperability, or production credit.
- Restoring a pre-accept snapshot re-admitted two items. Snapshot rollback
  resistance is therefore explicitly unowned.
- OpenMLS remains the buy for separately demonstrated classical group epoch,
  add/remove, restart, delayed-control, and application-assisted fork-recovery
  mechanics. Mission authority, disconnected distribution, hybrid/PQ,
  rollback, storage custody, and zeroization remain outside it.

### Data plane, policy, API, and assurance

- **Blob storage:** redb is rejected for large Blob bytes. At 256 MiB its byte
  store used about 602 MB on disk and 562 MB restart RSS; redb metadata plus an
  ordinary streamed file used about 258 KB metadata and 5.3 MB restart RSS
  (`BVB-811`). BLAKE3 is only a research oracle; the normative digest must be
  NIST-standardized and FIPS-approved unless the requirement is explicitly
  narrowed.
- Negentropy is a narrow identifier-difference component with a deterministic
  bulk fallback, not a replica engine. Automerge is useful only for explicitly
  opted-in JSON-like Record merge. One thin mission policy owner remains
  necessary for topic/scope/bridge/priority/TTL/quota/emission behavior.
- Phase 5 host-side assurance is complete (`BVB-844`). Fifty-four of fifty-four
  opaque A/G/B1 carrier-control rows passed at MTU 20–1500. Broadcast completed
  115 of 117 cells; the two unsuppressed MTU-64, eight-receiver, 70%-loss cases
  at 4 KiB and 64 KiB exhausted 32 rounds.
- Swift and Objective-C CoreBluetooth adapters compiled and ran, but this host
  reported central and peripheral `unsupported`; controller, second radio,
  GATT, RF, Android, and Windows remain environment-blocked or untested.
- The registered Rust parser replayed 18/18 vectors, but the independently
  derived parser agreed on only 13/18 because critical extension ID 1 appears
  in every positive vector but is absent from the frozen CDDL/prose. This is a
  specification/conformance failure, not a parser pass.
- C ABI, Swift, Python, Ruby, packaging, and CycloneDX structure checks passed.
  Kotlin was unavailable. Cargo-deny license checking failed because the exact
  fixture and SBOM lack license data. AF_UNIX bind was denied in both `/tmp`
  and the writable workspace, so the local-agent restart/auth/redaction arm is
  environment-blocked.

### Current architecture frontier

1. **A — p2panda-centered:** leading minimum-custom research point, with
   bounded confidence in its Event-like/store/sync slice and low confidence as
   a complete stack.
2. **G — explicit greenfield FOSS composition:** assurance/control research
   point; more custom semantics, but every owner is explicit.
3. **B1 — p2panda operations over BPv7:** conditional only if the remaining
   topology or policy work demonstrates a named BP-specific advantage.

No production architecture or dependency is selected or admitted.

### Governance and project status

- Phase 0 did not record per-arm engineer-day caps before execution, and no
  reproducible ordinal-anchor artifact was frozen for every comparison axis.
  Those administrative prerequisites cannot be reconstructed retroactively;
  the miss blocks honest time-cost comparison but does not erase technical
  test evidence.
- Under `BVB-865`, a discarded synthesis thread accidentally surfaced six
  heading/cap-result lines from excluded Proposal 0004 through a faulty search
  glob. The thread stopped and was contained; no Proposal-0004-derived claim or
  output is accepted. Human/counsel owner disposition remains external and
  pending. Final global wording must disclose the exposure rather than claim
  it never occurred.

### Work still open at this checkpoint

1. Capability-scoped Linux namespace preflight and exact Iroh/patchbay
   NAT/relay/hole-punch execution.
2. Explicit Phase 2 architecture-collapse disposition for Iroh, rust-libp2p,
   and Quinn/greenfield-native.
3. Clean final synthesis with qualitative residual-work bands and confidence
   grades, without invented engineer-day estimates.
4. Final source-register, link, JSON, manifest, ignore-boundary, control, and
   project audit; append-only project log and assurance-checklist
   consolidation.

## 2026-08-23 — Iroh/Patchbay topology result

The historical setup and execution chronology is retained separately. The
public [topology report](iroh-patchbay-topology.md) identifies the public Iroh
and Patchbay inputs, locally assembled test images, final observation, and
its use in the evaluation conclusions and Proposal 0006. This condensed entry
was prepared on 2026-09-27; it is not a new execution receipt.

The initial image-reference build failed before compilation, and the initial
runtime scratch-directory failure prevented topology setup. The corrected
run used the same test binary and recorded 13 ordinary passes and three
upstream-ignored direct-path timeouts with relay retained. Aggregate Docker
exit was 1; the three failures are not counted as passes. This remains a
one-kernel component observation, with no physical/public-network or security
qualification. BVB-904 identifies the original final result and BVB-905 its
historical checkpoint.

## 2026-08-23T06:46:36Z — final-audit allowlist incident and containment

- Incident: `BVB-909`. After the BVB-907 synthesis and BVB-908 governance
  addenda were hash-frozen, the final-audit workstream's mechanical JSON/CSV/TSV
  scan was accidentally scoped to the full evidence tree rather than the
  Evaluation 0005 allowlist.
- Tool output exposed excluded-subtree paths and row-width diagnostics only;
  no excluded file contents were emitted or used. The auditor made no
  post-exposure edit.
- Containment: the auditor stopped; every audit conclusion from its first broad
  command onward is discarded. BVB-907 and BVB-908 predate the incident and
  remain unaffected.
- Next decision: perform clean replacement validation in the still-clean
  topology workstream using an explicit allowlist limited to the requirements,
  `docs/evaluations/0005`, the archived experiment collection, `SOURCE_REGISTER.csv`, and named
  project files.
- Human/counsel owner disposition remains external and pending. Local
  containment and clean replacement validation do not constitute legal
  clearance.

## 2026-08-23T07:00:48Z — clean-validator documentation correction

- The fresh BVB-910 validator stayed inside the explicit Evaluation 0005
  allowlist and found one P1 documentation-completeness issue, not a missing
  execution result: the Phase 2 rust-libp2p row did not explicitly account for
  request-response limits.
- The candidate register now states that rust-libp2p's idiomatic
  request-response and pub/sub modules remain libp2p-owned source candidates
  only. Neither was placed under exact application limits, executed, or
  credited, and no full rust-libp2p architecture-collapse runtime exists.
- All other completed validator cells remained green at the time of the
  correction: BVB register structure and BVB-910 hashes, controls-only
  validation, visible JSON parsing, checksum sidecars and frozen archives,
  topology totals, local links, ignore boundaries, containment language,
  phase accounting, confidence bands, and scoped whitespace.
- The candidate-register and rolling-results hashes must be append-only
  rebound before the validator's final clean rerun; no technical test finding,
  candidate disposition, or claim boundary changed.

## 2026-08-23T07:04:02Z — final clean validation pass

- The clean replacement validator re-read BVB-911 and completed with
  **P0 0 / P1 0 / P2 0**. It remained read-only and did not cross the explicit
  Evaluation 0005 allowlist.
- Passed cells: 9-column register integrity with BVB-001 through BVB-911
  unique and contiguous; BVB-910/BVB-911 hash bindings; controls-only
  validation; 50 visible JSON files; 13 SHA sidecars with 172/172 targets;
  41 Markdown sources with 173 local links; scoped manifests and whitespace;
  project containment; historical-envelope wording; Phase 0 misses; Phase 2
  architecture-collapse accounting; confidence/residual bands; no-overclaim
  guards; and zero sensitive visible artifacts across the ignore boundary.
- The decisive topology totals remained 13/13 ordinary passes, 3/3
  upstream-ignored direct-wait failures, 16/16 initial relay starts, and zero
  infrastructure failures. No physical, public-Internet, security, production,
  or requirements-complete credit was added.
- Canonical validator payload SHA-256:
  `178d32dd1ed43f8261f0880209739329e456f6bba3361f4347b2799303a0c123`.
  The human and machine-readable receipts are in
  [`final-validation-receipt.md`](final-validation-receipt.md) and
  archived `final-validation-receipt.json` (archived).

## 2026-08-23T09:20:47Z — final bakeoff G integrated corpus

- Authorization and result: `BVB-913` through `BVB-922`. The final source
  combined registered Iroh 1.0.3, Negentropy 0.5.1, redb 4.2.0, SHA-2 0.11.0,
  and Tokio 1.53.1 in a 374-package, zero-git/path locked graph. Format,
  locked/offline check, warning-denied Clippy, and release build passed.
- Trial `g-001` is environment-only/no-credit: both divergent redb seeds were
  durable, but sandbox policy denied the first localhost socket bind before
  any reconciliation frame.
- Trial `g-002` reached a substantive first reconciliation: B's server moved
  from two to five items in one Negentropy round over authenticated Iroh
  (13,386 protocol bytes, 14 frames; two sent and three received). The client
  then lost the final acknowledgment because the evaluator closed the
  connection immediately after sending it. The preserved trial is classified
  as a harness-lifecycle failure, not a candidate failure.
- The append-only correction changed only the terminal acknowledgment drain;
  the graph, protocol, fixtures, cases, and driver remained unchanged.
- Decisive `g-003`: **PASS**. Divergent A (three fixtures) and B (two fixtures)
  converged to the exact five-fixture set. An immediate repeat transferred
  zero items (335 bytes, four frames). With A absent, B transferred all five
  to fresh C (13,324 bytes, 14 frames). Every checked store retained exactly
  one application effect per item.
- Crash windows passed: exit 77 before the redb transaction left zero items
  and effects, followed by complete recovery; exit 78 after the atomic
  item/effect commit but before acknowledgment left one item/effect, then
  reconciliation sent only the four missing items and did not duplicate the
  retained effect. Final equal-inventory reconciliation again transferred
  zero items.
- The 38-entry raw manifest validates every log, database, and result. Its
  SHA-256 is
  `038137de8aefece4d445524d63d019dc6f4c2a18a9d262c6290fc557670a82a3`;
  `result.txt` is
  `ad539211a724beab6e3d12c608d56ff53035721a4af148776a79690ce80110e4`.
- Bounded conclusion: G now provides a strong explicit-control comparator for
  one-host authenticated-Iroh reconciliation, durable atomic item/effect
  storage, temporal carry, duplicate suppression, and two controlled crash
  windows. It also demonstrates its cost: class interpretation,
  reconciliation progression, and cross-component policy remain custom stack
  responsibilities. This is not NAT/relay, physical-carrier, FIPS/PQ,
  independent-interoperability, power-loss, scale, or production evidence.

## 2026-08-23T09:35:22Z — final bakeoff A partial execution

- Authorization and result: `BVB-924` through `BVB-932`. The exact p2panda
  0.7.1 graph contains its own Iroh 1.0.3 endpoint and LogSync path; the final
  533-package graph compiled locked/offline, passed warning-denied Clippy, and
  produced a 28,764,128-byte release binary.
- The sole run made substantial progress. Offline A published all five exact
  fixtures. Separate A and B processes then moved five p2panda operations and
  26,897 bytes through candidate-native LogSync/Iroh; B verified exact bytes
  and retained A as the operation author. A exited, and a fresh B process
  replayed exactly five operations from its local store.
- With A absent, B and fresh C completed the first temporal contact, again
  carrying five operations and 26,897 bytes. C then exercised both intended
  split windows: exit 71 after p2panda durability but before application effect
  or acknowledgment, followed by a distinct local replay that fsynced the
  State effect and exited 72 before acknowledgment.
- The decisive stop occurred on the next fresh B↔C recovery rendezvous. Both
  processes reached READY, but both timed out before successful sync. The run
  therefore ended with one State effect marker, no five-effect recovery, no
  post-ack observation, no result file, and no whole-corpus pass. The run is
  frozen and was not retried.
- This is not back-propagated into failure of the earlier passes. It does,
  however, leave the exact recovery property that distinguishes the finalists
  unproved for A, while G passed its corresponding complete sequence.
- A source-only diagnosis is pending to distinguish high-level re-discovery
  failure from local replay/ack progression. Until then A receives credit only
  for initial native reconciliation, restart replay, first temporal carry, and
  the two reached crash checkpoints—not recovery, exactly-once completion, or
  post-ack quiescence.

## 2026-08-23T09:53:42Z — A fixed-port diagnostic and retry-lane close

- Source diagnosis found no direct-address or manual-peer LogSync operation in
  the high-level `p2panda::Node` API. It exposes relay bootstraps and requested
  bind ports; direct transport insertion exists only in the lower-level
  `p2panda-net` composition. The persistent address book, random default ports,
  and mDNS retention of expired addresses made restart address churn a
  plausible—but unproved—A-001 explanation.
- A-002 therefore kept the same Node→LogSync→Iroh→mDNS graph and cases, but
  requested stable per-role IPv4/IPv6 ports and added discovery/replay/sync/ack
  receipts. The high-level API does not expose the actual bound ports and may
  silently fall back on collision, so requested ports are not bound-port proof.
- The sole A-002 run failed earlier than A-001. A replayed all five operations
  locally and reported a successful five-operation/26,897-byte LogSync send
  with zero prior session errors. B's matching receive side ended with
  `ConnectionLost(TimedOut)` in the LogSync message stream before receiver
  completion. No restart or recovery cell was reached.
- This neither proves the stale-address hypothesis nor proves that fixed ports
  were honored. It does expose a high-level completion asymmetry: sender-side
  success did not imply receiver-side completion under the exact lifecycle.
  The A retry lane is closed; no timing sleeps, unregistered repeats, or
  lower-level replacement composition will be used to turn this into a pass.
- Differential implication: A retains its exact A-001 passes, but the decisive
  recovery/idempotence sequence remains incomplete across two materially
  distinct attempts. G completed that sequence in one corrected, fully
  manifested run.

## 2026-08-23T10:02:51Z — corrected final A-versus-G adjudication

- `BVB-943` through `BVB-946` froze and ran a standard-library verifier over
  the exact G manifest, the terminal A-001/A-002 logs, and required absent A
  result files. Independent review found no decision-changing defect.
- `BVB-947`/`BVB-948` append-only-correct the comparison language: endpoint
  control and independently committed durable-domain count are tie-breakers,
  not must-pass cells; the recovery result is “no duplicate fixture effect in
  the frozen schedule,” not a general exactly-once guarantee; and the endpoint
  and storage comparisons describe the task-authored evaluated compositions,
  not candidate-inherent ownership.
- In the frozen one-host fixture, G passed every registered reconciliation,
  restart, A-absent temporal, crash-recovery and duplicate-effect cell. A
  retains initial native LogSync/Iroh, restart, temporal-carry, range and crash-
  checkpoint credit, but did not complete the registered recovery/post-ack
  sequence across two materially different terminal attempts.
- Decision: select G—explicit Iroh 1.0.3 + Negentropy 0.5.1 + redb 4.2.0 under
  a requirements-owned profile—as the bounded research baseline. Retain
  p2panda as a conditional component and semantic reference, not the validated
  high-level whole-stack baseline. Keep BPv7 conditional on a named hard
  delta. `production_selected=false`.
- Corrected machine-readable outputs: comparison summary SHA-256
  `07fdbde79c7355a3f7dab27ac87385d418c98b30c75ca8711c364acc73f24a64`;
  comparison matrix SHA-256
  `3c7c4578ae8d27ffc163753467f1dfda56d909b4aa39f8dea944c224b617cc12`.
  The detailed decision and remaining release gates are in
  [`final-stack-bakeoff.md`](final-stack-bakeoff.md).

## 2026-08-23T11:20:23Z — Proposal 0006 selected reference core

- `BVB-952` through `BVB-965` froze, built, audited, corrected, and ran the
  selected Iroh 1.0.3 + Negentropy 0.5.1 + redb 4.2.0 reference slice. The
  374-package graph remained locked/offline with zero git/path packages;
  compiler check, warning-denied Clippy, and release build passed.
- Pre-runtime review caught a substantive evaluator defect: shared IDs used
  replica-local ordinal timestamps. The selected wrapper now gives every ID a
  stable timestamp and upstream orders by ID. A shifted partial-overlap case
  then passed with one item sent and one received.
- Final run `selected-stack-003` passed divergent and equal reconciliation,
  producer-absent later contact, both crash windows, final no-op, four
  malformed-frame rejections, actual-versus-wrong provider controls,
  repeated-seed suppression, corrupted-copy fail-close, and 1/128/1,024-item
  curves. Its 1,256-entry raw manifest verifies.
- Raw redb file hashes changed across logical read/open cycles even when the
  five identities, payloads, and one-count effects remained exact. File-byte
  equality is therefore retained as a measurement, not a semantic-state gate.
- Decision: the bounded reference core is validated. Stop broad whole-stack
  substitution work and build the missing normative class, durable-session,
  temporal-policy, security, Blob-file, physical/public, target/API, and
  release layers. `production_selected=false`. Exact report:
  [`Proposal 0006 selected-stack result`](../0006/README.md).
