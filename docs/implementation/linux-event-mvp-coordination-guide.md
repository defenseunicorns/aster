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

The fast path reaches that decision through:

1. one accepted Raspberry Pi/CM4/`aarch64` profile;
2. one frozen source/API commit;
3. one reproducible `arm64` package;
4. focused tests on two physical CM4 nodes;
5. one two-node 24-hour disconnected/reconnection run; and
6. one signed G6 disposition before 2026-09-14.

An issued candidate must let an application:

- publish durable Events while nodes are disconnected;
- reconnect and exchange them over approved IP paths;
- detect publisher gaps and safely handle at-least-once delivery;
- run on exactly two physical CM4 nodes using the Raspberry Pi reference
  `2026-06-18`, Debian GNU/Linux 13 `trixie`, kernel
  `6.18.39+rpt-rpi-v8`, systemd `257.13-1~deb13u1`, `aarch64`, and local
  `ext4` envelope;
- use the Rust reference client and pass the generated-Go client contract;
- restart selected nodes into `receive_only`, which prevents contact
  initiation and local inventory disclosure but is not physical radio silence.

The third CM4 is a declared spare/support node, not a third required
participant. `x86_64` and 8-/20-node scale are post-MVP.

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
| **G3 — Artifact freeze** | OS/deployment, security, release | One reproducible authenticated native `arm64` `.deb`, with SBOM, notices, provenance, checksums, and the exact v2 protected provider | The package reproduces from G2 and one immutable artifact-set identity is recorded |
| **G4 — Target tests** | Integration/device, physical carrier, security | Install, lifecycle, Rust/Go API, ReceiveOnly, direct-path, and any claimed relay receipts from the unchanged G3 artifact on both mandatory CM4 devices | Every focused scenario passes on both declared physical CM4 targets without artifact drift |
| **G5 — Workload qualification** | Integration/device, physical carrier | Two-node workload plus the 24-hour disconnected-publication and bounded reconnection result | The required two-node workload and soak pass with one frozen signed device/network inventory |
| **G6 — Disposition** | Release owner; all final roles for `issue` | For `issue`: complete verified annex, receipts, deterministic-gate rerun, and approvals. For an earlier stop: exact blocker, typed G3 `not-produced` or partial-attempt manifest binding, and typed downstream `not-run` records | Release signs `issue`, `refuse`, or `defer`; only `issue` qualifies the exact G3 artifact set |

Later gates do not compensate for an earlier failure. In particular, device
or soak results from a locally rebuilt package cannot qualify the G3 candidate.

## What each active workstream contributes

| Workstream | Work it can do now | Handoff needed by the chain | Main dependency |
|---|---|---|---|
| **Event service** | Complete review of the existing service/API draft; agree the ReceiveOnly and capacity follow-up contract | Accepted baseline for G1, then the frozen implementation and client behavior for G2 | None for G1; G2 starts from the accepted baseline |
| **Rust and deterministic release gate** | Remove flaky outcomes; make clean-checkout results repeatable; prepare exact gate reporting | Passing deterministic checks bound to G2, then a rerun bound to G6 | Uses the exact source commit selected at G2 |
| **OS, packaging, and artifacts** | Prepare locked build inputs, the native `arm64` package recipe, `systemd`/namespace setup, SBOM, notice, provenance, signing, and reproduction procedures | One provider-composed `arm64` package and one artifact manifest for G3 | The final package must be built from G2 and include `aster-systemd-credential-store/v2` |
| **Integration and real devices** | Prepare the two-CM4 harness, exact device/network inventory, optional third-CM4 support declaration, and receipt collection | G4 receipts for both mandatory CM4 devices and G5 two-node workload/resource receipts against G3 | Qualification starts only after G3; G5 also requires G4; a participating third CM4 must be declared |
| **Security and deployment** | Review the exact v2 protected-provider design and digest and prepare package integration | E01 role approvals before candidate qualification, then provider lifecycle acceptance in G3/G4 | Provider choice must be stable before the final artifact and exact to the Raspberry Pi profile boundary |
| **Dependency, legal, and release** | Maintain the [approved evaluation-only `DM-8-05` disposition](dm-8-05-linux-event-v0.1-disposition.md) and review dependency drift | Committed [role-approval record](dm-8-05-linux-event-v0.1-role-approvals.md) bound into the candidate annex | All three roles are Approved; the exact coordinates must still match the candidate graph |
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
4. both mandatory physical CM4 devices, including exact image, OS, kernel,
   systemd package, architecture, hardware revision, filesystem, and network
   conditions, plus the role of a third CM4 if it participates;
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

The profile is **Accepted** by Decision 0042. Both definition decisions are
resolved, without granting candidate or production authorization:

- **D06 — protected provider:** the exact provider selection and bound design
  digest were approved internally for the profile definition on 2026-09-08.
  D06 is resolved by the
  [approved Raspberry Pi systemd credential provider v2 design](../superpowers/specs/2026-09-08-raspberry-pi-systemd-credential-provider-v2-design.md)
  for `aster-systemd-credential-store/v2` at
  `sha256:30c5dfe71a203fcdd69dd330f9b5c68eeaee5032b624ee41912aa4723a9f853f`.
  Security and deployment approvals of that exact design and digest remain
  candidate gate E01.
- **D15 — `DM-8-05` evaluation disposition:** the
  [exact proposal](dm-8-05-linux-event-v0.1-disposition.md) at
  `sha256:a6fe15f39fb553f87bc1224fe7f266e7c906d451d8140402d3bc1620011bfa53`.
  The [internal role-approval record](dm-8-05-linux-event-v0.1-role-approvals.md)
  records Dependency/license, Legal/compliance, and Release as **Approved**
  against the exact dependency tuples and evaluation-only limitation.

P0-1 is now defined. E01 and G1–G6 remain separate candidate-delivery gates and
must pass before an evaluation candidate can issue.

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
| **2026-09-08** | All three D15 role approvals recorded, the Raspberry Pi amendment and v2 provider design approved, and Decision 0042 aligned. Security/deployment E01 review remains required for candidate qualification |
| **2026-09-09** | G1 Event baseline and ReceiveOnly/capacity contract frozen |
| **2026-09-10** | G2 source/API frozen; the one `arm64` G3 package is produced only from that source |
| **2026-09-11** | G4 passes on both mandatory CM4 devices and the required two-node G5 24-hour scenario starts |
| **2026-09-12** | Disconnected publication stops; reconnection and evidence review begin |
| **2026-09-13** | If prior gates passed, the two-node G5 run completes and G6 signs `issue`; otherwise G6 signs `refuse` or `defer` with the exact blocker before 2026-09-14 |

The dates are targets, not permission to skip a gate. A missing or failed
evaluation-blocking register row or non-waivable v0.1 gate produces `refuse`
or `defer`; the calendar cannot turn it into `issue`.

## Definition of customer-evaluation MVP-ready

The exact candidate is ready to issue only when:

- D06 and D15 are resolved for the profile and Decision 0042 has accepted it;
- G1 through G5 passed in order against one traceable source and artifact set;
- one reproducible native `arm64` package passed on both mandatory physical CM4
  devices;
- Rust and Go, restart-selected ReceiveOnly, protected-provider lifecycle,
  operation-capacity behavior, and the 24-hour scenario passed;
- the two-node workload passed against the frozen device/network inventory,
  with any participating third CM4 declared as a spare/support node;
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
