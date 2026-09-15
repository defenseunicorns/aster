# Proposal 0006: Selected FOSS reference stack build and validation


- Status: accepted for experiment by user authorization; no production stack
  or dependency admitted
- Date: 2026-08-23
- Authority: [`data-mesh-requirements.md`](../../data-mesh-requirements.md),
  SHA-256
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Work-order input: Proposal 0005, SHA-256
  `03428e6fba3a6befb73dab6623c9500a1b435eb504a2ee4efad2904f7e7a0cc3`
- Selection evidence: corrected `BVB-948`, synthesis `BVB-949`, validation
  snapshot `BVB-951`
- Product compatibility and current implementation weight: zero

## Decision sought

Can the selected bounded research baseline—**Iroh 1.0.3 + Negentropy 0.5.1 +
redb 4.2.0 under a requirements-owned profile**—be built as a small isolated
reference composition and preserve its owner boundaries under restart,
temporal contact, duplicate delivery, crash, malformed input, identity
mismatch, and bounded inventory growth?

A passing experiment retains this composition as the reference engineering
baseline. It does not make the task-authored evaluator wire normative, prove
the four data classes, admit the dependency graph, or authorize production.
A failure either narrows the component boundary or reopens the affected owner;
it does not silently move responsibility to another library.

## Prior result and rationale

The final A-versus-G comparison is in
[`final-stack-bakeoff.md`](../evaluations/0005/final-stack-bakeoff.md).
In the frozen one-host fixture, G completed every registered reconciliation,
restart, temporal, crash-recovery, and duplicate-effect cell. The high-level
p2panda composition retained meaningful component credit but did not complete
the same sequence in either terminal attempt. `production_selected=false`.

The selected baseline minimizes hidden ownership, not original code volume:

| Responsibility | Selected mechanism | Requirements-owned residue |
|---|---|---|
| Authenticated IP endpoint | Iroh 1.0.3 | Mission identity binding, discovery admission, secure relay operation, public/physical qualification |
| Inventory difference | Negentropy 0.5.1 | Object request/apply, durable session progression, hostile bounds, fallback policy |
| Accepted item/effect state | One redb 4.2.0 transaction domain | Schema, migration, quota, compaction, corruption/disk-full/power-loss policy |
| Research identity | SHA-256 mechanics | Normative identifiers and validated provider boundary |
| Data semantics | Opaque registered fixture carriage in this build | Normative four-class profile, causality, conflicts, tombstones, policy, security, Blob lifecycle, API and conformance |

Endpoint control and durable-domain count are tie-breakers scoped to this
task-authored composition. The no-duplicate-effect result is a frozen-fixture
observation, not a general exactly-once guarantee.

## Exact build boundary

The experiment reuses the exact BVB-922 graph without dependency acquisition:

- manifest SHA-256
  `89e411ce7a0708c7c74bf1b75681d399ac9584fc9479a914ffa9c43ad2f93c22`;
- lock SHA-256
  `b2fa398834df945531513eb90d4b6b9535274613ae8083695cee4a6189874b9a`;
- 374 packages: 373 checksummed registry packages plus one local root, zero
  git/path dependencies;
- direct exact components: Iroh 1.0.3, Negentropy 0.5.1, redb 4.2.0, SHA2
  0.11.0, and Tokio 1.53.1; and
- no source, package, version, feature, or lock substitution.

The new reference binary may include the frozen BVB-922 core source by exact
path/hash rather than duplicate it. New task-authored code is limited to a
hostile-frame/identity probe, a one-shot driver, acceptance criteria, and
visible summary/report artifacts. Product code is out of scope.

## Requirement and credit map

| Requirement cells | Executed question | Credit boundary |
|---|---|---|
| `DM-5.2-01`–`04`, `DM-5.2-18` | Do divergent durable replicas reconcile and survive separate-process restart? | Bounded local convergence and difference protocol only |
| `DM-5.2-06`–`08` | Are duplicate transfers suppressed and fixture effects not duplicated in the registered schedule? | No general exactly-once or application-transaction claim |
| `DM-5.6-01`–`03`, `DM-7-17` | Can A exit, B retain, and later B contact C over actual Iroh? | One-host direct/temporal composition; no public NAT or physical multi-hop credit |
| `DM-6-13`, `DM-5.7-02` | Does the task-authored composition bind the expected Iroh provider identity and reject the wrong one? | Provider identity only, not mission identity or authorization |
| `DM-3-01`, `DM-6-23` | Do malformed, truncated, unknown-tag, wrong-hash, and replayed fixture inputs fail closed or remain harmless? | Evaluator parser/application boundary only; no cryptographic replay claim |
| `DM-9-13`, `DM-9-14`, `DM-5.1-10`–`15` | Does the executable keep large Blob bytes out of redb and stream from files? | **Not implemented in the core slice; explicit stop/next build gate** |
| `DM-5.1-01`–`22`, `DM-5.3-01`–`10` | Does the executable implement normative class/field/conflict semantics? | **No. Registered fixtures are opaque bytes only** |
| `DM-5.4-01`–`22`, `DM-12-06` | Does integrated priority/TTL/quota/emission policy pass? | **No. Separate policy model evidence does not transfer automatically** |
| `DM-6-03`, `DM-6-09`, `DM-6-23`, `DM-6-28` | Does the full source/metadata security lifecycle pass? | **No. Protected fixture carriage adds no security/FIPS credit** |
| `DM-5.8-07`–`09`, `DM-12-09` | Does the stack pass physical/public NAT and secure relay fallback? | **No. Retain BVB-904 one-kernel topology evidence only** |
| `DM-12-11`, `DM-13-08` | Does an independently built implementation pass the normative profile? | **No. Independent conformance remains a release gate** |

## Frozen fixture set

The core corpus reuses the BVB-913 inputs byte-for-byte:

| Role | Bytes | SHA-256 |
|---|---:|---|
| State representation control | 158 | `2ec852f2de086869042b724e181802ce8f3bed5c7817f8e4a6cfca84c8074ecf` |
| Event representation control | 158 | `8140ff356548f113be15990a9d92162d7d91f9369e20d3d4e8ee292d86e02fc5` |
| Record representation control | 226 | `0610d4de79c46b59f3ad7dcc4297b6876a2b573a7415771741621ef2d0d45f0d` |
| Blob representation control | 4,227 | `6e8af7a670da6c0be1b53ce5019d6118489cf70ce2749792d34681e516a94751` |
| Protected opaque carrier control | 8,185 | `20ed2fc4aee4b44f84daa1bdf37e213a14bd951995a97e05165ae7fff42acc24` |

Class names describe fixture provenance, not semantics bought by this build.

## Phases

### Phase 0 — proposal and exact freeze

1. Freeze this proposal, acceptance document, reference/probe sources, driver,
   unchanged manifest/lock, fixture oracle, and ignore boundary.
2. Verify formatting, shell syntax, JSON shape, graph identity, package count,
   and zero git/path dependencies before compilation.
3. Stop on any graph, source, fixture, or allowlist drift.

### Phase 1 — isolated build and static gates

1. Use an ignored isolated target directory.
2. Run locked/offline check, warning-denied Clippy, and release build for only
   the reference core and probe binaries.
3. Record binary sizes/hashes and logs. A compile/lint failure earns no runtime
   credit and requires an append-only source correction.

### Phase 2 — primary recovery corpus

Run one fresh immutable root with separate processes:

1. divergent A/B durable seeds and authenticated-Iroh reconciliation;
2. complete process exit/restart and zero-item duplicate reconciliation;
3. A absent while B later contacts fresh C;
4. forced pre-commit exit with absence after restart;
5. forced post-commit/pre-ack exit with one retained fixture effect;
6. recovery of only missing items and final equal-inventory no-op; and
7. exact fixture bytes and one fixture effect per accepted item.

This phase repeats the selected must-pass baseline to detect build drift.

### Phase 3 — adversarial and operating-boundary corpus

Execute without changing the graph:

- wrong provider identity with zero accepted application frames;
- unknown tag, truncated item, inconsistent length, and wrong content identity;
- repeated local seed and repeated reconciliation with no duplicate fixture
  effect;
- a corrupted redb copy that fails closed without mutating the valid source;
- inventory curves at 1, 128, and 1,024 deterministic small items while
  reporting Negentropy rounds, frames, bytes, wall duration, and database size;
- connection/process timeouts with no hidden retry; and
- raw receipt preservation for every positive and negative outcome.

Malformed cases pass only when rejected and logical state remains equivalent:
the exact item identities, payloads, and effect counts must match the pre-case
checkpoint. Raw redb file hashes remain measurements rather than a semantic
equality oracle because BVB-963 found that an open/verify cycle changes redb
housekeeping bytes while all five logical rows remain exact.

### Phase 4 — seam and missing-owner validation

The report must distinguish:

- implemented and passed core mechanics;
- task-authored evaluator behavior;
- registered component evidence not integrated here; and
- missing normative/release owners.

At minimum, Blob file streaming, four-class semantics, mission policy,
source/metadata security, membership/rekey, physical carriers, public NAT,
power-loss, target qualification, and independent conformance remain explicit
fail/not-implemented gates rather than inferred passes.

The Phase 4 performance cells are exactly `DM-9-13`, `DM-9-14`,
`DM-9-15A`, `DM-9-16`, `DM-9-17`, `DM-9-18`, `DM-9-19A`, and
`DM-9-20A`. Their provisional measurement anchors are separately `DM-9-15`,
`DM-9-19`, and `DM-9-20`.

### Phase 5 — terminal report

Append the exact outcome to this proposal. Produce a machine-readable summary,
requirements map, visible file manifest, and rolling-results checkpoint. Update
the final frontier only if the result changes the recommendation.

The Phase 5 resource and scale map uses exactly `DM-9-06`, `DM-9-08A`,
`DM-9-08`, `DM-9-09A`, `DM-9-09`, `DM-9-10`, `DM-9-11`, `DM-9-12`,
`DM-9-13`, `DM-9-14`, `DM-9-15A`, `DM-9-15`, `DM-9-16`, `DM-9-17`,
`DM-9-18`, `DM-9-19A`, `DM-9-19`, `DM-9-20A`, `DM-9-20`, `DM-9-21A`,
`DM-9-21`, `DM-9-22`, `DM-9-23A`, `DM-9-23`, `DM-9-24`, and `DM-9-25`.

## Quantitative outputs

Report, without automatic elimination:

- dependency count and release binary bytes;
- items per replica and database bytes;
- Negentropy rounds, protocol frames, protocol bytes, and items transferred;
- duplicate transfers and fixture-effect count;
- build and per-cell wall duration;
- 1/128/1,024-item inventory curve; and
- exact process exit and failure class.

The bracketed resource and scale values in the requirements remain stakeholder
curves. This experiment does not invent pass/fail thresholds for them.

## Common controls

- Requirements are the sole product authority.
- Current implementation, compatibility, migration, and module boundaries have
  zero weight.
- One frozen graph and one fresh primary/adversarial run root are allowed.
- A mechanical harness defect may receive one append-only corrected attempt
  only after the failed bytes and diagnosis are preserved.
- No network acquisition, product code, excluded material, Proposal 0004,
  hidden retries, timeout relaxation, or result rewriting.
- Raw sources/builds/databases/logs remain ignored; lightweight sources,
  locks, criteria, summaries, manifests, and reports remain visible.

## Early aborts

Stop the affected phase on:

- manifest, lock, package-count, archive, fixture, source, or binary drift;
- network access or dependency substitution;
- a warning-denied build failure;
- provider-identity mismatch accepted as authorized application traffic;
- malformed/wrong-hash input committed to the valid store;
- a duplicate fixture effect after the defined recovery;
- a failed state-equivalence check after a negative case; or
- any attempt to convert an unimplemented class/security/policy/Blob/physical
  cell into core-mechanics credit.

## Timebox and evidence plan

The timebox is evidence-counted rather than estimated retrospectively:

- one exact graph;
- one locked/offline build sequence per registered source revision;
- one primary run and one adversarial/curve run;
- at most one registered correction for each distinct mechanical harness
  defect; and
- one terminal report, including failures and not-implemented cells.

Every stage receives an append-only BVB authorization/freeze/result row. No
engineer-day estimate is inferred. The raw evidence root is ignored and
immutable by convention after each attempt; visible summaries bind exact
hashes. External anchoring and legal/dependency admission remain separate.

## Success and failure interpretation

The experiment succeeds when the exact core build and every reached Phase 2/3
must-pass cell pass, negative inputs are rejected without state change, and all
missing owners remain explicit. The resulting disposition is **reference core
validated at bounded research scope**.

The experiment does not succeed merely because the binary builds, bytes cross
Iroh, or redb commits. A core success still leaves the normative profile,
security, policy, Blob streaming/lifecycle, physical/public topology,
independent implementation, target, scale/endurance, dependency admission, and
support gates open.

## Outcome

Execution is complete. Findings are append-only:

- BVB-959's independent pre-runtime audit found that the frozen evaluator used
  replica-local ordinal indices as Negentropy timestamps. The selected core now
  assigns timestamp zero and relies on upstream ID ordering, while preserving
  the BVB-922 source byte-for-byte.
- BVB-961's hardened core and probe pass locked/offline check,
  warning-denied Clippy, and release build. The core is 10,196,704 bytes: below
  10 MiB but above decimal 10 MB, so no provisional binary threshold is called
  pass or fail until stakeholders fix the unit.
- BVB-962's first run was sandbox-blocked before contact and receives no
  candidate credit.
- BVB-963's local-loopback run passed the complete primary recovery sequence,
  including shifted partial overlap with one item sent and one received,
  producer-absent B-to-C contact, both crash windows, and final no-op. Its first
  malformed frame was rejected, but the harness stopped on raw redb byte churn;
  a diagnostic copy retained five exact items and five one-count effects. The
  corrected negative gate therefore compares logical state and retains byte
  hashes only as measurements.
- BVB-965's corrected run passed all remaining gates. Four malformed frames
  were rejected without an application acknowledgement and with exact logical
  state preserved. An actual-provider positive control passed before a wrong
  expected provider failed the cryptographic handshake with zero application
  frames. Repeated seed inserted zero, and a corrupted copy failed closed on
  its redb magic number without changing the valid source.
- The 1/128/1,024-item curves completed in 1/10/86 seconds. Client database
  sizes were 57,344/86,016/180,224 bytes; protocol bytes were
  143/16,532/132,151; frames were 6/262/2,068; and Negentropy rounds were
  1/2/9. These are measurements, not stakeholder-threshold passes.

The result is **reference core validated at bounded research scope**. Retain
Iroh 1.0.3 + Negentropy 0.5.1 + redb 4.2.0 as the engineering baseline and
stop broad whole-stack substitution work. The next build stages must implement
and independently validate the still-missing requirements-owned profile,
native classes, durable reconciliation progression, temporal scheduler,
mission policy, security lifecycle, Blob file protocol, physical/public
carriers, target/API surfaces, and release assurance. `production_selected` is
still `false`.
