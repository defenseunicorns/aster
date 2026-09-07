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
| `P0-1-D02` | P0-1; `DM-14-10..16`; Decision 0028 | Exact Linux/deployment/package/isolation envelope and annexed target identity | Resolved | no | no | Does not qualify the envelope for production | none |
| `P0-1-D03` | P0-1; `DM-14-17..18` | Exact 2/8/20 participant shape, manual peers, one scope/topic/subscription per scenario, discovery off | Resolved | no | no | Broader topology and scale remain outside v0.1 | none |
| `P0-1-D04` | P0-1; `DM-14-07..09`, `DM-14-19`; Decision 0030 | Exact local API/lifecycle methods, Rust reference client, generated-Go qualification client | Resolved | no | no | Production bindings and independent interoperability remain open | none |
| `P0-1-D05` | P0-1; Decision 0033; security-profile disposition | Semantic v6, profile/suite `0x0001`, unordered IDs, no fallback, non-FIPS | Resolved | no | no | Production security and FIPS paths remain separately gated | none |
| `P0-1-D06` | P0-1; [approved initial provider design](../superpowers/specs/2026-09-07-systemd-credential-provider-design.md) (`sha256:484001169c8b1acc597240b181bf425bcec036a1949e9caaa9655d580140f776`) | `aster-systemd-credential-store/v1`; Ubuntu 24.04 systemd 255.4 credential interface; explicit host-key protection; statically composed loader; root-operated `aster-credential-admin`; seven-operation lifecycle; Debian support requires a redesigned/versioned D06 | Resolved | no | yes | Security/deployment approvals and provider qualification remain candidate and production gates | none |
| `P0-1-D07` | P0-1; design `Emission modes` | Restart-selected Normal/ReceiveOnly, non-initiation/non-disclosure, both identity orderings, no radio-silence claim | Resolved | no | no | No physical-silence or production emission claim | none |
| `P0-1-D08` | P0-1; P1-1 follow-on boundary | 1,024-key workload, 512 warning, hard caps/status/error; lifecycle/reclamation excluded | Resolved | no | no | Operation-mapping lifecycle remains production-blocking | none |
| `P0-1-D09` | P0-1; `DM-14-03..06`, `DM-14-12..18` | Exact capacity/workload/resource matrix and provisional byte-fit gate | Resolved | no | no | No production sizing or capacity claim | none |
| `P0-1-D10` | P0-1; design `Resource and lifecycle targets` | Same-artifact reinstall only; no downgrade or snapshot restore | Resolved | no | no | Production upgrade, rollback, and recovery remain open | none |
| `P0-1-D11` | P0-1; design metadata/observability sections | Exact metadata budget and bounded authenticated status/error surface | Resolved | no | no | Production observability and exposure acceptance remain open | none |
| `P0-1-D12` | P0-1; design artifact/acceptance sections | Exact artifact contents, thirteen acceptance conditions, G1-G6 dependency chain | Resolved | no | no | Production release remains separately gated | none |
| `P0-1-D13` | P0-1; design `Non-goals` and claim boundary | Every excluded platform, class, carrier, topology, lifecycle, and production claim | Resolved | no | no | Excluded capabilities remain unsupported | none |
| `P0-1-D15` | `DM-8-05`; Decision 0028 | Exact package/version [evaluation-only disposition proposed](dm-8-05-linux-event-v0.1-disposition.md); dependency, legal, and release approvals remain required | Open | yes | yes | Exact exception cannot authorize production; production resolution remains open | none |

`P0-1-D06` is resolved for the P0-1 profile definition by the approved initial
Ubuntu provider design. Security and deployment approval of the exact record
and digest remains required at `P0-1-E01`; it blocks candidate qualification,
not profile definition. If final review requires Debian or generic
Debian-family support, reopen D06 and replace this selection with a redesigned,
versioned provider boundary before the affected profile or candidate proceeds.
`P0-1-D15` is owned by dependency, legal, and release roles, targets
2026-09-08, and exits only when all three approval records bind the exact
proposal and dependency coordinates.

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
| `P0-1-D14-15` | `DM-14-15` | Measure 4,800 Event rows, 240 local mappings, and documented control/reserve use within the 10,000 aggregate cap; 5,040 is the ordinary-item projection, not the complete audited composition | Resolved | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-16` | `DM-14-16` | Functional with one core; idle at no more than 5% of one core | Resolved | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-17` | `DM-14-17` | Exactly 2, 8, and 20 nodes; no higher node-count claim | Resolved | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-18` | `DM-14-18` | Bridged scale excluded | Excluded | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-19` | `DM-14-19` | Rust reference and generated-Go qualification clients only | Resolved | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-20` | `DM-14-20` | Decisions 0025/0028 resolve selected v0.1 composition only; production-wide standards work excluded | Resolved | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-21` | `DM-14-21` | Decisions 0025/0028 resolve v0.1 composition only; production-wide buy/build work excluded | Resolved | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-22` | `DM-14-22` | Explicitly non-FIPS; production FIPS-path decision remains open outside v0.1 | Excluded | no | no | Atomic requirement unchanged; production-governance work may remain | none |
| `P0-1-D14-23` | `DM-14-23` | No validated-module claim; production module-availability decision remains open outside v0.1 | Excluded | no | no | Atomic requirement unchanged; production-governance work may remain | none |

## Open candidate and production gates

The following register preserves the approved design's owners, targets,
blocking values, and exit artifacts. `Open` rows block the evaluation
candidate. `Deferred` rows are production or later-profile gates and do not
block v0.1 except where the evaluation-blocking cell says otherwise.

| ID | Gate | Owner | Target | Status | Evaluation blocking | Production blocking | Exit | Evidence effect |
|---|---|---|---:|---|:---:|:---:|---|:---:|
| `P0-1-E01` | Approve the [exact protected provider and administration record](../superpowers/specs/2026-09-07-systemd-credential-provider-design.md) | Security + deployment | 2026-09-08 | Open | yes | yes | Both roles accept the provider contract, version, trust boundary, administration artifact, lifecycle procedure, limitations, acceptance plan, and exact record digest; any required Debian support reopens D06 for redesign | none |
| `P0-1-E02` | Freeze signed qualification annex and exact physical/virtual topology | Profile + integration | 2026-09-08 | Open | yes | yes | Annex names every node's physical/virtual status, architecture, device SKU, Ubuntu/kernel build, filesystem, relay placement, and network conditions | none |
| `P0-1-E03` | Merge/review candidate Event service | Event-service owner | 2026-09-09 | Open | yes | yes | Accepted commit passes clean gate and process suite | none |
| `P0-1-E04` | Add restart-selected `receive_only` config/status | Event-service + node owner | 2026-09-10 | Open | yes | yes | Both-ordering acceptance passes | none |
| `P0-1-E05` | Implement authenticated evaluation-capacity status and accurate operation-map exhaustion | Lifecycle/capacity + Event-service + selected-store/node owners | 2026-09-10 | Open | yes | yes | Audited mapping/item/byte use and profile headroom are reported; hard mapping-cap failures are distinguishable and nonretryable; generated-Go and crash/reopen tests pass | none |
| `P0-1-E06` | Add exact v0.1 validation to the qualification harness | Integration + profile owner | 2026-09-10 | Open | yes | yes | Harness rejects a receipt for every tested configuration or workload deviation while leaving the broader generic schema explicit | none |
| `P0-1-E07` | Deliver the Rust reference client and retain Go contract coverage | API + Event-service owner | 2026-09-10 | Open | yes | yes | Both clients execute the exact v0.1 publish/query/delivery/recovery contract | none |
| `P0-1-E08` | Produce signed reproducible packages for both architectures | Deployment/release owner | 2026-09-10 | Open | yes | yes | Artifact reproducibility and inventory pass | none |
| `P0-1-E09` | Integrate and qualify the protected-provider lifecycle | Security + deployment + integration | 2026-09-11 | Open | yes | yes | Exact packaged provider passes install/load/rotation/recovery/revoke/rekey/destroy tests | none |
| `P0-1-E10` | Run physical target/resource matrix | Integration/physical-carrier owner | 2026-09-12 | Open | yes | yes | Retained per-architecture receipts pass | none |
| `P0-1-E11` | Review pre-frozen capacity/resource targets | Profile + release owner | 2026-09-13 | Open | yes | yes | Every v0.1 threshold passed, or v0.1 is refused and a revised profile is scheduled | none |
| `P0-1-E12` | Resolve `DM-8-05` for production | Dependency/license + release owner | 2026-09-30 | Deferred | no | yes | Requirement disposition or technical alternative | none |
| `P0-1-E13` | Select operation-mapping lifecycle | Lifecycle/capacity owner | 2026-09-30 or before proposing a profile above 1,024 operations | Deferred | no | yes | Reviewed P1-1 generation/retirement decision | none |
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
3. **G3 — Artifact freeze:** reproducibly build and sign protected-provider-
   composed packages for both architectures from G2.
4. **G4 — Focused target tests:** pass install, lifecycle, Rust/Go API,
   ReceiveOnly, and direct/optional-relay scenarios using the unchanged G3
   artifacts.
5. **G5 — Workload qualification:** run the 2/8/20-node and 24-hour scenarios
   from G3. Scenarios may run concurrently only when the signed hardware/
   virtual inventory distinguishes every participant.
6. **G6 — Disposition:** review receipts and rerun deterministic gates, then
   issue, refuse, or defer the exact G3 artifact set.

The dates below are aggressive earliest targets, not authority to skip a gate:

| Date | Delivery | Primary owner | Exit signal |
|---:|---|---|---|
| 2026-09-07 | Review written v0.1 design and prepare the profile/decision register | Profile/architecture | Review comments resolved; no evidence statuses moved |
| 2026-09-08 | Select protected provider, sign exact `DM-8-05` evaluation disposition, and accept P0-1 | Security, deployment, dependency/license, release | P0-1 claim boundary and its blocking decisions are accepted |
| 2026-09-09 | Complete Event-service review and freeze ReceiveOnly/capacity follow-up contract | Event service, node, lifecycle/capacity | G1 passes |
| 2026-09-10 | Complete G2, then produce the G3 packages if the source/API commit is frozen | Event service, node, deployment, security | G2 and G3 pass; otherwise later gates do not start |
| 2026-09-11 | Run G4 and start every required 24-hour G5 soak no later than this date | Integration/physical carrier, security | G4 passes and each soak starts from a recorded clean boundary |
| 2026-09-12 | End the 24-hour disconnected publication window, restore approved paths, and begin bounded convergence/evidence review | Integration/physical carrier, release | Publication stops; convergence proceeds from unchanged G3 artifacts and state |
| 2026-09-13 | Finish G5 within its 24-hour convergence window, then perform G6 and review pre-frozen targets | All owners; release decides | Signed issue/refuse/defer disposition; issuance occurs only if every non-waivable gate passed before 2026-09-14 |

G1 is scheduled for 2026-09-09. G2 and G3 are scheduled for 2026-09-10.
G4 and G5 start no later than 2026-09-11. G5 publication ends on 2026-09-12
and completes within its convergence window on 2026-09-13. G6 is scheduled
for 2026-09-13. The dependency chain is mandatory: a failed or unpassed gate
prevents later gates from starting, and G6 may issue only when every
non-waivable gate passed against the exact G3 artifacts; otherwise it refuses
or defers the candidate.
