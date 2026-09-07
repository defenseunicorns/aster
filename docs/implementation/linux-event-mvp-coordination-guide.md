#

# Linux Event MVP coordination guide

This is the starting point for engineers working toward the Linux Event
customer-evaluation milestone. It explains how the workstreams fit together,
what each team hands off, and how Aster reaches an evidence-backed decision.
It is an explanatory coordination aid; the profile and register remain the
authoritative boundary and status records.

For exact limits and acceptance language, use the
[evaluation profile](linux-event-mvp-evaluation-profile-v0.1.md). For live
ownership and gate status, use the
[decision and gate register](linux-event-mvp-evaluation-profile-v0.1-register.md).

## The outcome we are coordinating

By the 2026-09-13 checkpoint, the team must be able to **issue, refuse, or
defer one exact candidate** for a time-bounded, non-production customer
evaluation.

An issued candidate must let an application:

- publish durable Events while nodes are disconnected;
- reconnect and exchange them over approved IP paths;
- detect publisher gaps and safely handle at-least-once delivery;
- run on the profile's exact Ubuntu Server 24.04 LTS and annexed-kernel
  envelope on physical `x86_64` and `aarch64` endpoints;
- use the Rust reference client and pass the generated-Go client contract;
- qualify the 2-node physical pair and the 8-/20-node tiers that retain that
  pair alongside declared isolated virtual participants; and
- restart selected nodes into `receive_only`, which prevents contact
  initiation and local inventory disclosure but is not physical radio silence.

This milestone is narrower than the complete product MVP in
`data-mesh-requirements.md`. It does not authorize production use, BTLE, other
data classes, dynamic routing, or a general radio-silence claim.

## How the work reaches a decision

Preparation can happen in parallel, but qualification follows one dependency
chain:

> **G1 Event baseline → G2 source/API freeze → G3 artifact freeze → G4 target
> tests → G5 workload qualification → G6 decision**

| Gate | Primary owners | Required handoff | Complete when |
|---|---|---|---|
| **G1 — Event baseline** | Event service, node, lifecycle/capacity | Accepted Event-service baseline and frozen ReceiveOnly/capacity contract | The baseline is accepted and the contract is frozen |
| **G2 — Source/API freeze** | Event service, node, deterministic gate | One source commit containing the accepted API, ReceiveOnly, and capacity status/error behavior | Focused tests pass and the exact source/API commit is recorded |
| **G3 — Artifact freeze** | OS/deployment, security, release | Reproducible authenticated `.deb` packages for both architectures, with SBOM, notices, provenance, checksums, and the exact protected provider | Both packages reproduce from G2 and one immutable artifact-set identity is recorded |
| **G4 — Target tests** | Integration/device, physical carrier, security | Install, lifecycle, Rust/Go API, ReceiveOnly, direct-path, and any claimed relay receipts from the unchanged G3 artifacts | Every focused scenario passes on the declared targets without artifact drift |
| **G5 — Workload qualification** | Integration/device, physical carrier | 2-, 8-, and 20-node results plus the 24-hour disconnected-publication and bounded reconnection results | Every required tier and workload passes with distinct signed device/VM inventories |
| **G6 — Disposition** | Release owner; all final roles for `issue` | For `issue`: complete verified annex, receipts, deterministic-gate rerun, and approvals. For an earlier stop: exact blocker, typed G3 `not-produced` or partial-attempt manifest binding, and typed downstream `not-run` records | Release signs `issue`, `refuse`, or `defer`; only `issue` qualifies the exact G3 artifact set |

Later gates do not compensate for an earlier failure. In particular, device
or soak results from a locally rebuilt package cannot qualify the G3 candidate.

## What each active workstream contributes

| Workstream | Work it can do now | Handoff needed by the chain | Main dependency |
|---|---|---|---|
| **Event service** | Complete review of the existing service/API draft; agree the ReceiveOnly and capacity follow-up contract | Accepted baseline for G1, then the frozen implementation and client behavior for G2 | None for G1; G2 starts from the accepted baseline |
| **Rust and deterministic release gate** | Remove flaky outcomes; make clean-checkout results repeatable; prepare exact gate reporting | Passing deterministic checks bound to G2, then a rerun bound to G6 | Uses the exact source commit selected at G2 |
| **OS, packaging, and artifacts** | Prepare locked build inputs, package recipes, `systemd`/namespace setup, SBOM, notice, provenance, signing, and reproduction procedures | Both architecture packages and one artifact manifest for G3 | Final packages must be built from G2 and include the selected provider |
| **Integration and real devices** | Prepare the harness, target inventory, network conditions, and receipt collection | G4 focused results and G5 workload/resource results against G3 | Qualification starts only after G3; G5 also requires G4 |
| **Security and deployment** | Review the selected protected-provider design and prepare package integration | E01 role approvals before candidate qualification, then provider lifecycle acceptance in G3/G4 | Provider choice must be stable before final artifacts; any required Debian support reopens D06 for redesign |
| **Dependency, legal, and release** | Review the exact evaluation-only `DM-8-05` dependency disposition | Three approval records closing D15 before profile ratification | The approved dependency coordinates must match the candidate graph |
| **Profile/product owner** | Keep the boundary, owners, dates, and customer exclusions explicit; prepare the candidate annex | Ratified profile plus one complete annex linking every handoff | Collects evidence from all lanes; does not replace their approvals |

The profile work is therefore an integration map, not a competing engineering
track. It lets each workstream prepare independently while preventing results
from different commits, packages, providers, or environments from being
combined into a false readiness claim.

## The shared handoff: one candidate annex

All workstreams contribute to one
[candidate annex](linux-event-mvp-evaluation-profile-v0.1-annex-template.md).
The annex ties together:

1. the exact G2 source commit and deterministic-gate result;
2. the exact G3 packages, provider, SBOM, notices, provenance, and signatures;
3. the complete sanitized configuration and harness version;
4. every physical device and VM, including OS, kernel, architecture, and
   network conditions;
5. G4 and G5 results and immutable receipt references; and
6. role approvals and the final G6 decision.

The annex is filled as gates complete; it is not a form saved for the end.
Each owner supplies the immutable identity of their handoff and records pass,
fail, or a typed reason the work was not run.

### When a change creates a new candidate

- A source or public-API change after G2 requires a new G2 freeze and new G3
  artifacts.
- Any package, provider, dependency, or artifact-manifest change after G3
  requires a new G3 freeze and rerun of affected G4/G5 evidence.
- A configuration, harness, device, or network-condition change must be
  recorded and the affected scenario rerun.
- Preparation work and unrelated component evidence remain useful, but cannot
  be presented as qualification of the changed candidate.

## Current decision state

The profile is still **Proposed**. One definition decision remains before
Decision 0042 can ratify it:

- **D06 — protected provider:** resolved for the profile by the
  [approved initial systemd credential design](../superpowers/specs/2026-09-07-systemd-credential-provider-design.md).
  Security and deployment approvals remain candidate gate E01. A final-review
  requirement for Debian or generic Debian-family support reopens D06 and
  requires provider redesign.
- **D15 — `DM-8-05` evaluation disposition:** dependency, legal, and release
  owners must separately approve the exact dependency coordinates and the
  evaluation-only limitation.

D15 is the remaining profile-ratification blocker. E01 and G1–G6 are separate
candidate-delivery gates and remain required after the profile is ratified.

## Working rules for the team

1. Use the register as the live ownership and status board. Do not infer gate
   completion from a branch, draft PR, demo, or component test.
2. Prepare in parallel, qualify in G1–G6 order.
3. Put every exact handoff identity and result into the annex as it becomes
   available.
4. Report a failed gate immediately. Stop dependent qualification until the
   responsible owner provides a new frozen input.
5. Keep customer-facing claims inside the profile. A useful result outside the
   boundary can inform later work, but it does not widen this candidate.
6. Reconsider provisional resource and capacity targets after physical-device
   evidence; change them only through a versioned profile revision.

## Schedule and decision points

| Date | Coordinated result |
|---:|---|
| **2026-09-08** | All three approving D15 records accepted; profile can then be ratified. Security/deployment E01 review of the D06 design remains required for candidate qualification |
| **2026-09-09** | G1 Event baseline and ReceiveOnly/capacity contract frozen |
| **2026-09-10** | G2 source/API frozen; G3 packages produced only from that source |
| **2026-09-11** | G4 passes and all required G5 24-hour scenarios start |
| **2026-09-12** | Disconnected publication stops; reconnection and evidence review begin |
| **2026-09-13** | If prior gates passed, G5 completes and G6 may issue; otherwise G6 records `refuse` or `defer` with the exact blocker |

The dates are targets, not permission to skip a gate. A missing or failed
evaluation-blocking register row or non-waivable v0.1 gate produces `refuse`
or `defer`; the calendar cannot turn it into `issue`.

## Definition of customer-evaluation MVP-ready

The exact candidate is ready to issue only when:

- D06 is resolved for the profile, D15 is closed, and Decision 0042 has
  ratified the profile;
- G1 through G5 passed in order against one traceable source and artifact set;
- both architectures and all three node tiers passed;
- Rust and Go, restart-selected ReceiveOnly, protected-provider lifecycle,
  operation-capacity behavior, and the 24-hour scenario passed;
- resource, metadata, error, packaging, and receipt-integrity checks passed;
- every required role approved the same completed annex body; and
- the release owner signed `issue` for the exact G3 artifact set.

Anything less is useful progress, but not an issued customer-evaluation
candidate.

## Where to go for details

| Document | Use it for |
|---|---|
| [Evaluation profile](linux-event-mvp-evaluation-profile-v0.1.md) | Exact supported behavior, limits, exclusions, and acceptance contract |
| [Decision and gate register](linux-event-mvp-evaluation-profile-v0.1-register.md) | Current owner, date, status, blocker, and exit artifact for each decision or gate |
| [Candidate-annex schema](linux-event-mvp-evaluation-profile-v0.1-annex-template.md) | Shared handoff record for one exact candidate |
| [Decision 0042](../decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md) | Ratification authority and the distinction between defining and issuing the profile |
| [Approved design](../superpowers/specs/2026-09-06-linux-event-mvp-evaluation-profile-design.md) | Historical rationale and detailed design discussion |
