#

# Linux Event MVP Evaluation Profile v0.1 decision and gate register

- Profile: [`aster-linux-event-mvp-evaluation-v0.1`](linux-event-mvp-evaluation-profile-v0.1.md)
- Register date: 2026-09-06
- Candidate-decision checkpoint: 2026-09-13
- Evidence effect: none

This register separates resolved v0.1 boundary decisions, open
candidate-authorization gates, and production/later-profile deferrals.
`Resolved` means the reusable boundary is defined; it does not mean current
code or an artifact conforms. This register does not replace or modify the
atomic requirements matrix. Requirement IDs appear only where the approved
design reviewed their v0.1 disposition.

## Boundary decisions

The `v0.1 resolution` column mirrors the accepted profile and is not
independent normative authority. A boundary change requires a profile revision
and reviewed decision.

| ID | Exact source/IDs | v0.1 resolution | Status | P0 blocker | Candidate blocker | Production effect | Evidence effect |
|---|---|---|---|:---:|:---:|---|:---:|
| `P0-1-D01` | P0-1; design `Intended evaluator and use case` | Technical integration/field team; Event-only 48-hour non-production mission and ownership split | Resolved | no | no | Evaluation boundary only; production use remains unapproved | none |
| `P0-1-D02` | P0-1; `DM-14-10..16`; Decision 0028 | Exact Raspberry Pi reference `2026-06-18` / Debian GNU/Linux 13 `trixie` / kernel `6.18.39+rpt-rpi-v8` / systemd `257.13-1~deb13u1` / local `ext4` / physical Raspberry Pi Compute Module 4 Rev 1.1 / `aarch64` envelope | Resolved | no | no | Does not qualify the envelope for production or another image, platform, device family, or architecture | none |
| `P0-1-D03` | P0-1; `DM-14-17..18` | Exactly two mandatory physical CM4 participants; an optional third support node must be declared if it carries candidate traffic; 8-/20-node qualification deferred; manual peers, one scope/topic/subscription per scenario, discovery off | Resolved | no | no | Broader topology and scale remain outside v0.1 | none |
| `P0-1-D04` | P0-1; `DM-14-07..09`, `DM-14-19`; Decision 0030 | Exact local API/lifecycle methods, Rust reference client, generated-Go qualification client | Resolved | no | no | Production bindings and independent interoperability remain open | none |
| `P0-1-D05` | P0-1; Decision 0033; security-profile disposition | Semantic v6, profile/suite `0x0001`, unordered IDs, no fallback, non-FIPS | Resolved | no | no | Production security and FIPS paths remain separately gated | none |
| `P0-1-D06` | P0-1; [approved Raspberry Pi provider v2 design](inputs/raspberry-pi-systemd-credential-provider-v2-design.md) (`sha256:30c5dfe71a203fcdd69dd330f9b5c68eeaee5032b624ee41912aa4723a9f853f`); [systemd 257 presentation amendment](inputs/systemd-257-credential-presentation-amendment.md) (`sha256:549ea3fd5bdfd62c01bab5a8f1adac4b84a2710ab406ea006119c9048e28d4cd`) | `aster-systemd-credential-store/v2`; exact Raspberry Pi reference `2026-06-18` and systemd `257.13-1~deb13u1` credential interface; original `0400`/`ramfs` or exact non-root ACL/read-only-`tmpfs`/`noswap` presentation; explicit host-key protection; statically composed loader; root-operated `aster-credential-admin`; seven-operation lifecycle | Resolved | no | yes | Security/deployment approval of the amendment and provider qualification remain candidate and production gates; no generic `tmpfs` or Debian claim | none |
| `P0-1-D07` | P0-1; design `Emission modes` | Restart-selected Normal/ReceiveOnly, non-initiation/non-disclosure, both identity orderings, no radio-silence claim | Resolved | no | no | No physical-silence or production emission claim | none |
| `P0-1-D08` | P0-1; [current operation-ledger boundary](linux-event-mvp-evaluation-profile-v0.1.md#durable-publish-operation-containment); P1-1 follow-on boundary | 1,024-key evaluation workload and 512 warning over a separately configured permanent mission-bound ledger; active records compact only to permanent retirement fences; exact retry/conflict, reserve, audit, status, and terminal-cap behavior retained | Resolved | no | no | Higher-rate/long-duration physical qualification and production sizing remain blocking; the profile does not authorize operation-key reuse or a workload above 1,024 | none |
| `P0-1-D09` | P0-1; `DM-14-03..06`, `DM-14-12..18` | Exact two-node workload/resource matrix and provisional byte-fit gate on both mandatory physical CM4 devices | Resolved | no | no | No production sizing, broader scale, or capacity claim | none |
| `P0-1-D10` | P0-1; design `Resource and lifecycle targets` | Same-artifact reinstall only; no downgrade or snapshot restore | Resolved | no | no | Production upgrade, rollback, and recovery remain open | none |
| `P0-1-D11` | P0-1; design metadata/observability sections | Exact metadata budget and bounded authenticated status/error surface | Resolved | no | no | Production observability and exposure acceptance remain open | none |
| `P0-1-D12` | P0-1; design artifact/acceptance sections | One native `arm64` artifact, revised two-CM4 acceptance conditions, and G1-G6 dependency chain | Resolved | no | no | Production release remains separately gated | none |
| `P0-1-D13` | P0-1; design `Non-goals` and claim boundary | Explicit Ubuntu, `x86_64`, CM5, VM, 8-/20-node, other excluded platform/class/carrier/topology/lifecycle, and production exclusions | Resolved | no | no | Excluded capabilities remain unsupported | none |
| `P0-1-D15` | `DM-8-05`; Decision 0028; [exact evaluation disposition](dm-8-05-linux-event-v0.1-disposition.md) (`sha256:a6fe15f39fb553f87bc1224fe7f266e7c906d451d8140402d3bc1620011bfa53`); [internal role approvals](dm-8-05-linux-event-v0.1-role-approvals.md) (`sha256:4edda9457c78d0c1d177590c1583691071e708ccbbace078cc15a82dd9bcac85`) | Exact `webpki-root-certs`/`webpki-roots` 1.0.9 tuples only; Dependency/license, Legal/compliance, and Release approved; evaluation-only; no general allowlist, candidate release authorization, or production resolution | Resolved | no | no | Exact exception cannot authorize production; production resolution remains open | none |

Internal approval of the exact D06 provider selection and bound design digest
was recorded for the profile definition on 2026-09-08. `P0-1-D06` is resolved
for the P0-1 profile definition by the approved Raspberry Pi provider v2 design
at `sha256:30c5dfe71a203fcdd69dd330f9b5c68eeaee5032b624ee41912aa4723a9f853f`.
Product approval to implement and validate the exact systemd 257 presentation
amendment was recorded on 2026-09-09. Security and Deployment approval of both
immutable records remains required at `P0-1-E01`; it blocks candidate
qualification, not profile definition. Another platform requires a new
reviewed provider and profile boundary before the affected candidate proceeds.
Dependency/license, Legal/compliance, and Release approval of the exact D15
evaluation-only disposition and bound digest was recorded on 2026-09-08.
`P0-1-D15` is therefore resolved for P0-1 and is not a candidate blocker. The
later annex must bind the committed approval record and exact candidate graph.
Any tuple, graph, SBOM, notice, or reachability drift reopens D15 for the
affected profile or candidate. Production `DM-8-05` remains open and blocking.

## DM-14 dispositions

These rows resolve or exclude each decision for v0.1. Their atomic requirements
remain unchanged and may remain production-governance work.

| ID | Exact source/IDs | v0.1 resolution | Status | P0 blocker | Candidate blocker | Production effect | Evidence effect |
|---|---|---|---|:---:|:---:|---|:---:|
| `P0-1-D14-01` | `DM-14-01` | Preserve four protocol/API priority values; no doctrine-validation claim | Resolved | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-02` | `DM-14-02` | Preserve priority names as stable API tokens; no doctrine-validation claim | Resolved | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-03` | `DM-14-03` | 24 hours at 4 KiB and 10 Events/hour/node | Resolved | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-04` | `DM-14-04` | No minimum link-rate claim; report exact test conditions | Excluded | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-05` | `DM-14-05` | No maximum-loss claim; report exact test conditions | Excluded | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-06` | `DM-14-06` | Blob excluded, so no Blob-size floor | Excluded | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-07` | `DM-14-07` | Rust reference first and Go qualification required; no complete-MVP binding-count claim | Resolved | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-08` | `DM-14-08` | No one-day integration acceptance claim | Excluded | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-09` | `DM-14-09` | No line-count/sample-size acceptance claim | Excluded | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-10` | `DM-14-10` | Tier-1 RAM target inapplicable to Tier-2 Linux v0.1 | Excluded | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-11` | `DM-14-11` | Tier-1 flash target inapplicable to Tier-2 Linux v0.1 | Excluded | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-12` | `DM-14-12` | Stripped deployed executable no more than 16 MiB | Resolved | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-13` | `DM-14-13` | Steady RSS no more than 64 MiB; peak RSS no more than 128 MiB | Resolved | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-14` | `DM-14-14` | Preferred 32-MiB RAM target is not a v0.1 pass threshold | Excluded | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-15` | `DM-14-15` | Measure 480 aggregate Event rows and documented control/reserve use within the 10,000-item store cap; measure 240 local operation-ledger records separately under the dedicated ledger quota; neither projection is complete audited composition | Resolved | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-16` | `DM-14-16` | Functional with one core; idle at no more than 5% of one core | Resolved | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-17` | `DM-14-17` | Exactly two required physical CM4 nodes; 8-/20-node qualification excluded from v0.1 | Resolved | no | no | Atomic requirement unchanged; broader scale remains production-governance work | none |
| `P0-1-D14-18` | `DM-14-18` | Bridged scale excluded | Excluded | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-19` | `DM-14-19` | Rust reference and generated-Go qualification clients only | Resolved | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-20` | `DM-14-20` | Decisions 0025/0028 resolve selected v0.1 composition only; production-wide standards work excluded | Resolved | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-21` | `DM-14-21` | Decisions 0025/0028 resolve v0.1 composition only; production-wide buy/build work excluded | Resolved | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-22` | `DM-14-22` | Explicitly non-FIPS; production FIPS-path decision remains open outside v0.1 | Excluded | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-23` | `DM-14-23` | No validated-module claim; production module-availability decision remains open outside v0.1 | Excluded | no | no | Atomic requirement unchanged; production-governance work may remain | none |

## Implementation and evidence checkpoint — 2026-09-13

This checkpoint describes inspected `main` commit
`aec90c96e396ddbae0823f9110414f0a5fd80fd1`, not a G2 source freeze or
candidate approval. Implemented code, automated checks, and qualification
receipts are different evidence classes. The gate rows below retain their
owners, exits, and `Open` status; no atomic requirement gains evidence credit.

| Area / gates | Implemented source and automated coverage | Remaining candidate evidence |
|---|---|---|
| Event service and clients — E03/E07 | [Event service](../../crates/aster-agent/src/event_service.rs), [compile-checked Rust examples](../../crates/aster-agent/README.md), [real-node Rust client tests](../../crates/aster-agent/tests/real_node_connect.rs), and [generated-Go recovery client](../../conformance/agent-go/cmd/agent-smoke/main.go) are merged. | Accepted source/process gate and exact-profile Rust/Go execution against the unchanged G3 package on both mandatory CM4 devices; client code is not a qualifying receipt. |
| ReceiveOnly — E04 | [Customer runtime test](../../crates/aster-agent/tests/customer_runtime.rs) covers `receive_only` readiness and local publication; the configuration and authenticated status path are implemented. | Both-ordering transfer/non-initiation acceptance against the final candidate, including two ReceiveOnly nodes; no radio-silence claim. |
| Capacity — E05 | The [permanent Event operation ledger](../../crates/aster-redb-store/src/event_operation.rs), [strict candidate configuration](../reference/aster-agent-config-v1.md), and [authenticated status](../../crates/aster-agent/src/event_service.rs) implement separate configured limits, reserve, active/retired compaction, bounded audit, profile headroom, rate estimates, and terminal capacity errors. | Exact-candidate configuration/status bindings, complete healthy audit, physical state/RSS/startup measurements, and generated-Go/crash-reopen acceptance against the unchanged G3 package remain required. |
| Protected provider — E01/E09 | [`SystemdCredentialLoader` is statically composed](../../crates/aster-agent/src/main.rs) and the [provider administration lifecycle](../../crates/aster-systemd-credentials/README.md#current-implementation-boundary) is implemented. | E01 Security and Deployment acceptance of both immutable D06 records and E09 lifecycle qualification on the exact installed package remain open. |
| Qualification tooling, package, and resources — E06/E08/E10/E11 | The generic process harness and source tests are preparation, not exact-profile receipt validation or a signed native `arm64` package. | Exact v0.1 receipt validation, reproducible signed package, both-device workload/resource receipts, and threshold disposition remain required. |

[PR #14 CI run 34758425713](https://github.com/edgesoftops/astertech/actions/runs/34758425713)
completed successfully for head `3c9453dfc7ddb3a08860ae43e3022796b17b0d75`
before merge into the checkpoint above. The
[CI workflow](../../.github/workflows/ci.yml) includes quality with
[`mise run check`](../../mise.toml), Rust workspace/generated-Go checks and the
full agent process contract suite, plus both path-lab jobs, dependency policy,
fuzz smoke, MSRV, macOS, and age interoperability. This is existing automated
evidence, not a new local run or physical acceptance. Merged PRs #14, #15, and
#16 are credited only as implementation source and automated coverage; they do
not close candidate gates or create physical qualification receipts. This
checkpoint does not claim a separate post-merge `main` CI run.

The [CM4 engineering spike](evidence/2026-09-09-cm4-provider-event-engineering-spike.md)
records pre-candidate physical observations using a temporary unit, explicitly
not G3/G4 qualification. It did not run the generated-Go qualification client
or full capacity workload. Final package-bound physical acceptance, resources,
and the required 24-hour workload remain pending; the
[prepared inventory](evidence/2026-09-10-cm4-candidate-inventory.md) does not
close E02.

### Selected operation-ledger capacity boundary

The [accepted containment contract](linux-event-mvp-evaluation-profile-v0.1.md#durable-publish-operation-containment)
retains an operator/harness stop at 1,024 distinct accepted operation keys and
warns no later than 512. It now binds the separately configured permanent
ledger to 1,000,000 records, 192 MiB of logical ledger bytes, and a 10,000-record
emergency reserve. The runtime may retain implementation headroom after the
profile stops; 1,024 is not a generic hard rejection. This resolves the earlier
release-planning ambiguity for v0.1 without widening its successful workload.
Physical measurements and required role review may retain, lower, or revise a
later profile, but cannot silently change this candidate contract.

## Open candidate and production gates

The following register preserves the approved design's owners, targets,
blocking values, and exit artifacts. `Open` rows block the evaluation
candidate. `Deferred` rows are production or later-profile gates and do not
block v0.1 except where the evaluation-blocking cell says otherwise.

| ID | Gate | Owner | Target | Status | Evaluation blocking | Production blocking | Exit | Evidence effect |
|---|---|---|---:|---|:---:|:---:|---|:---:|
| `P0-1-E01` | Approve the [exact Raspberry Pi protected provider v2 design](inputs/raspberry-pi-systemd-credential-provider-v2-design.md) (`sha256:30c5dfe71a203fcdd69dd330f9b5c68eeaee5032b624ee41912aa4723a9f853f`), [systemd 257 presentation amendment](inputs/systemd-257-credential-presentation-amendment.md) (`sha256:549ea3fd5bdfd62c01bab5a8f1adac4b84a2710ab406ea006119c9048e28d4cd`), and administration record | Security + deployment | 2026-09-09 | Open | yes | yes | Both roles accept both exact digests, provider contract/version, trust boundary, pinned ACL/mount predicates, administration artifact, lifecycle procedure, limitations, and acceptance plan | none |
| `P0-1-E02` | Freeze signed qualification annex and exact two-CM4 inventory | Profile + integration | 2026-09-08 | Open | yes | yes | Annex names both mandatory physical CM4 nodes' exact image, Debian identity, kernel, systemd package, architecture, hardware revision, filesystem, relay placement, and network conditions; any participating third CM4 is explicitly declared with its support role | [Non-qualifying prepared sanitized inventory input](evidence/2026-09-10-cm4-candidate-inventory.md); E02 remains open until annex freeze and approval |
| `P0-1-E03` | Merge/review candidate Event service | Event-service owner | 2026-09-09 | Open | yes | yes | Accepted commit passes clean gate and process suite | none |
| `P0-1-E04` | Add restart-selected `receive_only` config/status | Event-service + node owner | 2026-09-10 | Open | yes | yes | Both-ordering acceptance passes | none |
| `P0-1-E05` | Qualify authenticated Event operation-ledger capacity, audit, and failure behavior | Lifecycle/capacity + Event-service + selected-store/node owners | 2026-09-10 | Open | yes | yes | Exact configured ledger/store use, active/retired/reverse rows, ordinary/emergency and profile headroom, completed audit, and warning state are reported; configured-cap failures are distinguishable and nonretryable; generated-Go and crash/reopen tests pass | none |
| `P0-1-E06` | Add exact v0.1 validation to the qualification harness | Integration + profile owner | 2026-09-10 | Open | yes | yes | Harness rejects a receipt for every tested configuration or workload deviation while leaving the broader generic schema explicit | none |
| `P0-1-E07` | Deliver the Rust reference client and retain Go contract coverage | API + Event-service owner | 2026-09-10 | Open | yes | yes | Both clients execute the exact v0.1 publish/query/delivery/recovery contract | none |
| `P0-1-E08` | Produce one signed reproducible native `arm64` package | Deployment/release owner | 2026-09-10 | Open | yes | yes | The provider-composed package reproduces and its complete artifact inventory passes | none |
| `P0-1-E09` | Integrate and qualify the protected-provider lifecycle | Security + deployment + integration | 2026-09-11 | Open | yes | yes | Exact packaged provider passes install/load/rotation/recovery/revoke/rekey/destroy tests | none |
| `P0-1-E10` | Run physical target/resource matrix on both mandatory CM4 devices | Integration/physical-carrier owner | 2026-09-12 | Open | yes | yes | Retained receipts for both mandatory physical CM4 devices pass | none |
| `P0-1-E11` | Review pre-frozen capacity/resource targets | Profile + release owner | 2026-09-13 | Open | yes | yes | Every v0.1 threshold passed, or v0.1 is refused and a revised profile is scheduled | none |
| `P0-1-E12` | Resolve `DM-8-05` for production | Dependency/license + release owner | 2026-09-30 | Deferred | no | yes | Requirement disposition or technical alternative | none |
| `P0-1-E13` | Qualify the selected operation-ledger lifecycle above the v0.1 workload or for production | Lifecycle/capacity owner | Before proposing a profile above 1,024 operations | Deferred | no | yes | Reviewed physical/long-duration evidence supports configured capacity, audit latency, active-to-retired compaction, permanent fences, and production sizing | none |
| `P0-1-E14` | Validate usability-time/sample-size targets | API/product owner | 2026-09-30 | Deferred | no | yes | Independent adopter study sets accepted targets | none |
| `P0-1-E15` | Complete production-wide standards/build-buy disposition | Architecture + release owner | 2026-09-30 | Deferred | no, unless a candidate adds an undispositioned dependency or bespoke mechanism | yes | Reviewed production composition closes `DM-14-20/21` | none |
| `P0-1-E16` | Select FIPS/validated-module path | Security/compliance owner | 2026-10-15 | Deferred | no | yes | Reviewed production-profile disposition | none |
| `P0-1-E17` | Independent server interoperability and security review | Conformance/security/release owners | Before production candidate | Deferred | no | yes | Independent gates pass against exact production profile | none |

## Qualification dependency chain

Qualification follows this serial gate chain even when preparation happens in
parallel:

1. **G1 — Event baseline:** accept the Event-service baseline and freeze the
   emission/capacity contract.
2. **G2 — Source/API freeze:** merge ReceiveOnly and capacity behavior, pass
   focused tests, and freeze one source/API commit.
3. **G3 — Artifact freeze:** reproducibly build and sign one provider-composed
   native `arm64` package from G2.
4. **G4 — Focused target tests:** pass install, lifecycle, Rust/Go API,
   ReceiveOnly, and direct/optional-relay scenarios on both mandatory physical
   CM4 devices using the unchanged G3 artifact.
5. **G5 — Workload qualification:** run the two-node workload and 24-hour
   disconnected/reconnection scenario from G3 against the frozen device and
   network inventory.
6. **G6 — Disposition:** review receipts and rerun deterministic gates, then
   issue, refuse, or defer the exact G3 artifact set.

The dates below are aggressive earliest targets, not authority to skip a gate:

| Date | Delivery | Primary owner | Exit signal |
|---:|---|---|---|
| 2026-09-07 | Review written v0.1 design and prepare the profile/decision register | Profile/architecture | Review comments resolved; no evidence statuses moved |
| 2026-09-08 | Record Dependency/license, Legal/compliance, and Release approval of the exact `DM-8-05` evaluation disposition and accept P0-1 | Dependency/license, legal, release, profile owner | All three role decisions bind the disposition digest and exact tuples; Decision 0042 is accepted without candidate or production authorization |
| 2026-09-09 | Complete Event-service review and freeze ReceiveOnly/capacity follow-up contract | Event service, node, lifecycle/capacity | G1 passes |
| 2026-09-10 | Complete G2, then produce the single `arm64` G3 artifact if the source/API commit is frozen | Event service, node, deployment, security | G2 and G3 pass; otherwise later gates do not start |
| 2026-09-11 | Run G4 on both mandatory CM4 devices and start the required two-node 24-hour G5 soak no later than this date | Integration/physical carrier, security | G4 passes and the soak starts from a recorded clean boundary |
| 2026-09-12 | End the 24-hour disconnected publication window, restore approved paths, and begin bounded convergence/evidence review | Integration/physical carrier, release | Publication stops; convergence proceeds from unchanged G3 artifacts and state |
| 2026-09-13 | Finish G5 within its 24-hour convergence window, then perform G6 and review pre-frozen targets | All owners; release decides | Signed issue/refuse/defer disposition; issuance occurs only if every non-waivable gate passed before 2026-09-14 |

G1 is scheduled for 2026-09-09. G2 and G3 are scheduled for 2026-09-10.
G4 and G5 start no later than 2026-09-11. G5 publication ends on 2026-09-12
and completes within its convergence window on 2026-09-13. G6 is scheduled
for 2026-09-13. The dependency chain is mandatory: a failed or unpassed gate
prevents later gates from starting, and G6 may issue only when every
non-waivable gate passed against the exact G3 artifacts; otherwise it refuses
or defers the candidate.
