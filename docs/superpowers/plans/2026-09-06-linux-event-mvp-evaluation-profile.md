#

# P0-1 Linux Event MVP Evaluation Profile v0.1 Ratification Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task-by-task.

**Goal:** Publish the approved boundary as a proposed, reusable Linux Event MVP
Evaluation Profile v0.1 ratification package. Close roadmap action P0-1 only
after all three DM-8-05 specialist approvals are recorded and the conditional
authority-switch task is explicitly authorized. The initial exact protected
provider design is resolved for P0-1 under the scope amendment below; its role
approvals remain a candidate gate. This plan does not authorize a customer
candidate; candidate authorization still requires every applicable evaluation
gate and a completed signed annex for the exact artifacts under review.

**Architecture:** Create one proposed profile, one mutable decision/gate
register, one unsigned DM-8-05 evaluation-disposition proposal, one provisional
per-candidate annex schema, and one Proposed adoption ADR. The approved design
remains the governing boundary while D15 is open. Only a later conditional
commit may close D15, accept the profile/ADR, and freeze the design as
historical. Runtime, artifact, provider, device, and release work remains in
its existing lane.

**2026-09-07 scope amendment:** The profile owner approved the Ubuntu systemd
credential provider as the initial D06 profile design. D06 is therefore
resolved for P0-1, while security and deployment approvals remain mandatory at
candidate gate E01. D15 remains a P0-1 ratification blocker. If final review
requires Debian or generic Debian-family support, reopen D06 and replace the
Ubuntu-specific selection with a redesigned, versioned provider boundary
before ratification or candidate qualification, as applicable. The historical
task text below records the stricter pre-amendment sequence.

**Tech Stack:** Markdown, Git, the repository requirement-integrity checker,
and existing `mise` verification tasks.

**Spec:**
[`docs/superpowers/specs/2026-09-06-linux-event-mvp-evaluation-profile-design.md`](../specs/2026-09-06-linux-event-mvp-evaluation-profile-design.md)

## Global constraints

- Treat all work as **** under the user-authorized
  temporary project protocol in
  `/home/andrii/Downloads/OPI_Guardrail_System_Prompt_1.md`.
- Use only repository material and public open-source material. Do not solicit,
  inspect, infer, or reproduce OPI confidential or proprietary information.
- Execute in an isolated worktree. The current intended worktree is
  `/tmp/aster-p0-1-linux-event-profile` on `p0-1-linux-event-profile`.
- The current stacked integration base is `419cddd`. It contains current-main
  commit `9a7e75f` plus the customer-readiness priorities on `origin/docs`.
- Before implementation, verify that the intended integration target has not
  advanced. If it has, rebase or recreate the implementation worktree from the
  new target, then replace every baseline comparison in this plan with that
  exact commit before editing a deliverable. Never validate against an obsolete
  baseline.
- Preserve the approved design body from commit `ade675a` except for the
  approved D06 scope amendment and its explicit Debian-redesign trigger. The
  conditional authority-switch task changes only its status/authority pointer
  after the approved ratification prerequisites exist.
- Do not edit these active parallel-work paths:
  - `crates/aster-agent/**`
  - `crates/aster-node/src/lib.rs`
  - `crates/aster-node/src/runtime.rs`
  - `proto/**`
  - generated Go bindings
  - process/device harnesses
  - `mise.toml`
  - root `README.md`
  - `docs/reference-index.md`
  - `docs/quickstart/connect-agent.md`
  - `docs/implementation/capability-roadmap.md`
  - `docs/implementation/requirements-status.md`
  - `docs/implementation/requirements-implementation.csv`
  - `docs/decisions/0041-*`
  - Event configuration and provenance files changed by the Event-service
    branch
- Do not change requirement statuses, exact evidence mappings, retained
  receipts, dependency policy, third-party notices, or production-readiness
  claims. A documented acceptance condition is not evidence that it passed.
- Do not add source code. ReceiveOnly, capacity status/error behavior, Event API
  reconciliation, and Rust/Go qualification require a separate plan after the
  Event-service branch is integrated.
- Do not add package builders, provider integrations, device automation, or
  deterministic-release changes. Those remain with their current owners.
- Every new document starts with `# ` before its title.
- Run all relative commands from the worktree root. Inspect
  `git status --short` before every commit and stop on an unexpected path.

## Authority transition

| Phase | Governing document | Meaning |
|---|---|---|
| Through proposed-package publication | Approved design | Approved boundary; normative packaging not yet ratified |
| After the conditional authority switch | Accepted v0.1 profile plus Decision 0042 | P0-1 claim boundary is closed |
| Until candidate G6 | Open gate register and provisional/completed annex | No artifact is authorized for customer evaluation |
| Production | Existing requirements/evidence plus a future production profile | v0.1 grants no production authority |

Implementation, artifact, device, and release-test gates do not block defining
the profile. The initial exact protected-provider design resolves D06 for
P0-1; security and deployment approvals remain candidate gate E01. The three
recorded DM-8-05 approvals remain P0-1 ratification conditions.

## Task 0: Confirm the stacked execution base

**Files:** none

### Step 1: Inspect repository and branch state

Run:

```bash
git status --short --branch
git show -s --format='%H %P %D' 419cddd
git show -s --format='%H %P %D' 9a7e75f
git merge-base --is-ancestor 9a7e75f 419cddd
git branch -avv --no-abbrev
git diff --name-only 419cddd..HEAD
```

Expected on the current worktree:

- `419cddd` descends from `9a7e75f`;
- the design and this plan are the only branch additions;
- the worktree is clean because the approval/plan commit already exists;
- no implementation path from another lane is present.

If the integration target or an active branch changed, inspect its delta before
continuing. Rebase only after preserving the approval/plan commits and update
the exact baseline hash in this plan in a focused commit.

## Task 1: Publish the proposed normative profile

**Files:**

- Create:
  `docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md`

### Step 1: Prove the path is free

```bash
test ! -e docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md
```

Expected: exit 0. Stop if another worker already owns the path.

### Step 2: Create the profile identity and authority header

Use `apply_patch` to start the file with:

```markdown
#

# Linux Event MVP Evaluation Profile v0.1

- Profile ID: `aster-linux-event-mvp-evaluation-v0.1`
- Status: Proposed; becomes normative when Decision 0042 is accepted
- Profile version: `0.1`
- Approved design date: 2026-09-06
- Candidate decision checkpoint: 2026-09-13
- Product class: time-bounded, non-production customer evaluation
- Governing design until adoption: [approved design](../superpowers/specs/2026-09-06-linux-event-mvp-evaluation-profile-design.md)
- Decision register: [v0.1 register](linux-event-mvp-evaluation-profile-v0.1-register.md)
- Candidate-annex schema: [provisional schema](linux-event-mvp-evaluation-profile-v0.1-annex-template.md)

This profile defines the complete claim boundary for the named non-production
evaluation. It does not assert that an implementation, artifact, provider,
device run, or release candidate satisfies that boundary. A candidate may
claim the profile only after every applicable evaluation-blocking register row
passes and one completed annex binds the exact source, artifacts, provider,
configuration, nodes, results, receipts, and approvals.
```

### Step 3: Mechanically transplant the stable approved boundary

Copy the following approved-design sections into the profile in this order:

1. `Summary`, rewritten only to identify this file as the profile rather than a
   design proposal.
2. `Goals` and `Non-goals`.
3. `Profile identity and reuse`.
4. `Intended evaluator and use case`.
5. `Supported platform and deployment`.
6. `Topology and carriers`.
7. `Emission modes`.
8. `Protocol, security, and mission policy`, including `Metadata exposure
   budget`.
9. `Protected provisioning boundary`.
10. `Application boundary and bindings`.
11. `Event and retry semantics`.
12. `Durable publish-operation containment`.
13. `Capacity and workload matrix`.
14. `Resource and lifecycle targets`.
15. `Minimum observability and failure contract`.
16. `Artifact and installation contract`.
17. `Acceptance and retained evidence`.
18. `Consequences and claim boundary`.

Copy normative wording and tables verbatim wherever they already describe the
stable v0.1 boundary. Remove only:

- historical design-review language;
- current candidate-branch implementation-gap commentary;
- mutable owners/dates/open-gate tables, which belong in the register;
- `Ownership and branch integration`;
- schedule prose other than the exact G1-G6 dependency chain and the
  September 13 issue/refuse/defer semantics.

Any other wording or value change requires explicit review against the approved
design before continuing.

### Step 4: Check the high-risk terms exactly

Confirm the resulting profile preserves all of these approved details:

- The intended evaluator, the application/operator ownership split, the
  48-hour mission, the 1,024-operation early stop, and immutable/versioned claim
  rules.
- A customer annex may only narrow an already-qualified base. The reusable base
  first qualifies both architectures and all 2/8/20 tiers. Issued v0.1 plus its
  receipts is immutable; editorial-only correction is v0.1.1 and a boundary
  change is v0.2.
- Ubuntu Server 24.04 LTS, exact annexed kernel, `x86_64` and `aarch64`, local
  ext4, systemd, one core, 1 GiB deployment memory, 256 MiB initial free state,
  and native `.deb` authenticated by the exact detached-signature or
  signed-repository method named in the annex.
- A dedicated network namespace is shared only by agent and intended
  application. Application and health listeners are loopback-only, bearer
  authentication is mandatory, and there is no host port, Service, ingress,
  tunnel, or unrelated sidecar.
- One mission authority, one scope, one topic, and one durable application
  subscription are active in each qualification scenario. This is not one
  subscription per node.
- Direct carrier configuration binds the exact manual address and peer
  identity. Discovery, arbitrary address replacement, public/default relay,
  general NAT traversal, WebPKI, and `relay_only` are excluded.
- An optional relay is exactly one customer-controlled pinned connectivity
  relay in `direct_preferred` mode with public DER trust-root certificates. Do
  not describe trust-root certificates as private material.
- `normal` and restart-selected `receive_only` retain the exact non-initiation,
  non-disclosure, blind-offer, mandatory-response, both-carrier-ordering, and
  explicit non-radio-silence behavior.
- Qualification uses semantic v6, Aster security profile `0x0001`, hybrid suite
  `0x0001`, unordered profile identifiers, no fallback, one offline mission
  root, one delegated signer, and a non-FIPS claim.
- Relay TLS trust, when relay is enabled, uses explicit DER CA roots. Keep that
  separate from the offline mission authority.
- The protected `ProvisioningSecretLoader` contract includes all seven approved
  lifecycle operations. The unprotected fixture and age-based engineering
  adapter are development/test tools only; do not call the age adapter
  unprotected.
- The normative out-of-process local boundary is protobuf/ConnectRPC over
  authenticated loopback TCP. Exact methods are `GetStatus`, `PublishEvent`,
  `QueryEvents`, `CreateEventSubscription`, `PollEvents`, `StreamEvents`,
  `AcknowledgeEvent`, `DeleteEventSubscription`, and `QueryEventGaps`.
- Detail-free `GET /livez` and `GET /readyz`, bearer-token-only `SIGHUP`, and
  bounded `SIGINT`/`SIGTERM` drain keep their approved meanings.
- Rust is the reference client; generated Go is a required client/API
  qualification lane, not an independent server.
- Before Event payload retirement, exact `PublishEvent` retry returns the
  original durable result. The operation mapping does not retire in v0.1.
  Changed intent conflicts; after payload retirement, exact retry returns
  nonretryable `NotFound` with
  `PUBLIC_ERROR_REASON_MISSING_DURABLE_OBJECT`, backed internally by
  `ExpiredOrRetired`.
- Underlying operation-map exhaustion uses nonretryable `ResourceExhausted` and
  `PUBLIC_ERROR_REASON_OPERATION_CAPACITY_EXHAUSTED = 12`. Full mapping
  lifecycle/reclamation remains P1-1.
- The operation workload is 1,024 distinct accepted keys per state-directory
  lifetime with warning no later than 512; implementation hard caps remain
  4,096 rows and 512 KiB, with the approved 395,264-byte worst-case projection.
- Store configuration is `storage.max_items = 10_000` aggregate logical tracked
  items and `storage.max_payload_bytes = 67_108_864` aggregate logical tracked
  bytes. It is not an Event-only store limit.
- `limits.max_connections = 1` is the total local application-connection
  setting; at most eight application operations are in flight node-globally.
  One client is a qualification-harness topology bound, not an identity limit.
- Query and gap pages are 16, delivery pages are 16, delivery/gap scan limits
  are 128, and at most 256 deliveries are simultaneously unacknowledged.
- Copy the complete six-row workload table verbatim. In particular: the small
  two-node case has 10 total Events; the 8/20-node cases have 10 Events per
  node; the capacity-warning probe has 512 operations plus one exact retry.
- Hard 4,096-row/512-KiB saturation remains an isolated engineering test or a
  test-only lowered-cap test, never the ordinary 1,024-operation workload.
- The maximum soak projects 5,040 ordinary items against 5,840 ordinary slots,
  leaving 800 projected slots; byte fit remains provisional until receipts.
- Resource limits and energy treatment are copied exactly from the approved
  table. Energy is measured but has no v0.1 pass threshold.
- Carry the approved metadata-exposure budget and minimum authenticated-status
  fields verbatim. Do not add a metric, fingerprint, runtime provenance field,
  or disclosure requirement without another design decision. Build/config
  digests belong in the annex, not live status.
- Copy all thirteen acceptance gates verbatim. Post-retirement behavior is
  existing component evidence only; v0.1 requires no black-box retirement
  trigger.
- Copy G1-G6 verbatim from the approved design. September 13 is an
  issue/refuse/defer checkpoint, never an automatic positive date.
- Preserve every approved non-goal and non-claim, not only a shortened subset.
  Publishing the profile moves no requirement/evidence status.

### Step 5: Verify the proposed profile

Run:

```bash
git add --intent-to-add docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md
rg -n 'Status: Proposed|aster-linux-event-mvp-evaluation-v0\.1|PublishEvent|QueryEvents|CreateEventSubscription|PollEvents|StreamEvents|AcknowledgeEvent|DeleteEventSubscription|QueryEventGaps' docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md
rg -n 'security profile `0x0001`|suite `0x0001`|semantic protocol version `6`|receive_only|1,024|395,264|5,040|5,840|800 item slots' docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md
rg -n 'GET /livez|GET /readyz|SIGHUP|SIGINT|SIGTERM|issue, refuse, or defer|no black-box retirement trigger' docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md
python3 tools/check-implementation-requirements.py
git diff --check
git status --short
```

Expected: exact high-risk terms are present, the checker reports all 348 IDs,
and only the new profile is pending in the worktree.

### Step 6: Commit Task 1

```bash
git add docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md
git commit -m "docs: publish proposed Linux Event MVP profile"
```

## Task 2: Create the decision and gate register

**Files:**

- Create:
  `docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md`

### Step 1: Prove the path is free

```bash
test ! -e docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md
```

Expected: exit 0.

### Step 2: Define register semantics

Start with:

```markdown
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
```

Use these columns for boundary rows:

```markdown
| ID | Exact source/IDs | v0.1 resolution | Status | P0 blocker | Candidate blocker | Production effect | Evidence effect |
```

The Resolution column mirrors the accepted profile and is not independent
normative authority. A boundary change requires a profile revision and reviewed
decision.

### Step 3: Add D01-D13 and D15 exactly

Use these source mappings and resolutions:

| ID | Exact source/IDs | Resolution summary | Status |
|---|---|---|---|
| `P0-1-D01` | P0-1; design `Intended evaluator and use case` | Technical integration/field team; Event-only 48-hour non-production mission and ownership split | Resolved |
| `P0-1-D02` | P0-1; `DM-14-10..16`; Decision 0028 | Exact Linux/deployment/package/isolation envelope and annexed target identity | Resolved |
| `P0-1-D03` | P0-1; `DM-14-17..18` | Exact 2/8/20 participant shape, manual peers, one scope/topic/subscription per scenario, discovery off | Resolved |
| `P0-1-D04` | P0-1; `DM-14-07..09`, `DM-14-19`; Decision 0030 | Exact local API/lifecycle methods, Rust reference client, generated-Go qualification client | Resolved |
| `P0-1-D05` | P0-1; Decision 0033; security-profile disposition | Semantic v6, profile/suite `0x0001`, unordered IDs, no fallback, non-FIPS | Resolved |
| `P0-1-D06` | P0-1; design `Protected provisioning boundary` | Protected-loader and seven-operation contract fixed; exact provider selection and administration artifact remain required | Open |
| `P0-1-D07` | P0-1; design `Emission modes` | Restart-selected Normal/ReceiveOnly, non-initiation/non-disclosure, both identity orderings, no radio-silence claim | Resolved |
| `P0-1-D08` | P0-1; P1-1 follow-on boundary | 1,024-key workload, 512 warning, hard caps/status/error; lifecycle/reclamation excluded | Resolved |
| `P0-1-D09` | P0-1; `DM-14-03..06`, `DM-14-12..18` | Exact capacity/workload/resource matrix and provisional byte-fit gate | Resolved |
| `P0-1-D10` | P0-1; design `Resource and lifecycle targets` | Same-artifact reinstall only; no downgrade or snapshot restore | Resolved |
| `P0-1-D11` | P0-1; design metadata/observability sections | Exact metadata budget and bounded authenticated status/error surface | Resolved |
| `P0-1-D12` | P0-1; design artifact/acceptance sections | Exact artifact contents, thirteen acceptance conditions, G1-G6 dependency chain | Resolved |
| `P0-1-D13` | P0-1; design `Non-goals` and claim boundary | Every excluded platform, class, carrier, topology, lifecycle, and production claim | Resolved |
| `P0-1-D15` | `DM-8-05`; Decision 0028 | Exact package/version evaluation-only disposition proposed; dependency, legal, and release approvals remain required | Open |

Set D06 and D15 to P0 blocker `yes` and candidate blocker `yes`. D06 is owned by
security plus deployment with target 2026-09-08 and exits only through the
reviewed exact provider/administration record. D15 is owned by dependency,
legal, and release roles with target 2026-09-08 and exits only when all three
approval records bind the exact proposal and dependency coordinates. Set every
other row's P0 blocker to `no`. Evidence effect is `none` for every row.

### Step 4: Add all 23 DM-14 decisions without inventing mappings

Create IDs `P0-1-D14-01` through `P0-1-D14-23`. Use this exact disposition
table:

| ID | Requirement | Exact v0.1 disposition | Status |
|---|---|---|---|
| `P0-1-D14-01` | `DM-14-01` | Preserve four protocol/API priority values; no doctrine-validation claim | Resolved |
| `P0-1-D14-02` | `DM-14-02` | Preserve priority names as stable API tokens; no doctrine-validation claim | Resolved |
| `P0-1-D14-03` | `DM-14-03` | 24 hours at 4 KiB and 10 Events/hour/node | Resolved |
| `P0-1-D14-04` | `DM-14-04` | No minimum link-rate claim; report exact test conditions | Excluded |
| `P0-1-D14-05` | `DM-14-05` | No maximum-loss claim; report exact test conditions | Excluded |
| `P0-1-D14-06` | `DM-14-06` | Blob excluded, so no Blob-size floor | Excluded |
| `P0-1-D14-07` | `DM-14-07` | Rust reference first and Go qualification required; no complete-MVP binding-count claim | Resolved |
| `P0-1-D14-08` | `DM-14-08` | No one-day integration acceptance claim | Excluded |
| `P0-1-D14-09` | `DM-14-09` | No line-count/sample-size acceptance claim | Excluded |
| `P0-1-D14-10` | `DM-14-10` | Tier-1 RAM target inapplicable to Tier-2 Linux v0.1 | Excluded |
| `P0-1-D14-11` | `DM-14-11` | Tier-1 flash target inapplicable to Tier-2 Linux v0.1 | Excluded |
| `P0-1-D14-12` | `DM-14-12` | Stripped deployed executable no more than 16 MiB | Resolved |
| `P0-1-D14-13` | `DM-14-13` | Steady RSS no more than 64 MiB; peak RSS no more than 128 MiB | Resolved |
| `P0-1-D14-14` | `DM-14-14` | Preferred 32-MiB RAM target is not a v0.1 pass threshold | Excluded |
| `P0-1-D14-15` | `DM-14-15` | Measure 4,800 Event rows, 240 local mappings, and documented control/reserve use within the 10,000 aggregate cap; 5,040 is the ordinary-item projection, not the complete audited composition | Resolved |
| `P0-1-D14-16` | `DM-14-16` | Functional with one core; idle at no more than 5% of one core | Resolved |
| `P0-1-D14-17` | `DM-14-17` | Exactly 2, 8, and 20 nodes; no higher node-count claim | Resolved |
| `P0-1-D14-18` | `DM-14-18` | Bridged scale excluded | Excluded |
| `P0-1-D14-19` | `DM-14-19` | Rust reference and generated-Go qualification clients only | Resolved |
| `P0-1-D14-20` | `DM-14-20` | Decisions 0025/0028 resolve selected v0.1 composition only; production-wide standards work excluded | Resolved |
| `P0-1-D14-21` | `DM-14-21` | Decisions 0025/0028 resolve v0.1 composition only; production-wide buy/build work excluded | Resolved |
| `P0-1-D14-22` | `DM-14-22` | Explicitly non-FIPS; production FIPS-path decision remains open outside v0.1 | Excluded |
| `P0-1-D14-23` | `DM-14-23` | No validated-module claim; production module-availability decision remains open outside v0.1 | Excluded |

Set P0 blocker and candidate blocker to `no` for every D14 row: these rows
resolve or exclude the decision for v0.1. State explicitly that their atomic
requirements remain unchanged and may remain production-governance work.

### Step 5: Add the open candidate and production tables

Copy the approved design's complete `Open gates and owners` table verbatim,
adding stable IDs `P0-1-E01` onward in source order. Preserve every owner,
target, evaluation-blocking value, production-blocking value, and exit
artifact. The table includes, among other rows:

- exact provider selection and administration artifact;
- qualification-annex/topology freeze;
- Event-service acceptance;
- ReceiveOnly and capacity implementation;
- exact harness and Rust/Go coverage;
- reproducible packages and protected-provider lifecycle;
- physical/resource matrix and target review;
- DM-8-05 production path, operation-mapping lifecycle, usability targets,
  standards/buy-build, FIPS, and independent review.

Then copy G1-G6 and the dated schedule verbatim from the approved design.
Associate dates exactly: G1 on 2026-09-09; G2 and G3 on 2026-09-10; G4 and G5
start no later than 2026-09-11; G5 publication ends 2026-09-12 and completes
within its convergence window on 2026-09-13; G6 is 2026-09-13. Preserve gate
dependencies and issue/refuse/defer semantics.

Open or deferred rows may use either an exact calendar target or an explicit
release milestone already present in the approved design, such as `Before
production candidate`. Every such row must name an owner, both blocker values,
an exit artifact, and evidence effect `none`.

### Step 6: Verify register completeness

Run:

```bash
git add --intent-to-add docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md
test "$(rg -c '^\| `P0-1-D' docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md)" -eq 37
test "$(rg -c '^\| `P0-1-D14-' docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md)" -eq 23
rg -n '\| (Open|Deferred) \|' docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md
rg -n 'G1|G2|G3|G4|G5|G6|2026-09-09|2026-09-10|2026-09-11|2026-09-12|2026-09-13' docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md
python3 tools/check-implementation-requirements.py
git diff --check
git status --short
```

Manually inspect every `Open` or `Deferred` row. Expected: each has an owner,
target, blocker classification, exit artifact, and `none` evidence effect. The
register has no new atomic evidence mapping and only the register is pending.

### Step 7: Commit Task 2

```bash
git add docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md
git commit -m "docs: add Linux Event MVP decision register"
```

## Task 3: Propose the exact DM-8-05 evaluation disposition

**Files:**

- Create:
  `docs/implementation/dm-8-05-linux-event-v0.1-disposition.md`
- Modify:
  `docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md`

### Step 1: Verify exact locked coordinates and policy records

Run:

```bash
rg -U 'name = "webpki-root-certs"\nversion = "1\.0\.9"' Cargo.lock
rg -U 'name = "webpki-roots"\nversion = "1\.0\.9"' Cargo.lock
rg -F '| `webpki-root-certs` | 1.0.9 | `b96554aa2acc8ccdb7e1c9a58a7a68dd5d13bccc69cd124cb09406db612a1c9b` | CDLA-Permissive-2.0 |' THIRD_PARTY_NOTICES.md
rg -F '| `webpki-roots` | 1.0.9 | `7dcd9d09a39985f5344844e66b0c530a33843579125f23e21e9f0f220850f22a` | CDLA-Permissive-2.0 |' THIRD_PARTY_NOTICES.md
rg -U '\[\[licenses\.exceptions\]\]\nallow = \["CDLA-Permissive-2\.0"\]\nname = "webpki-root-certs"\nversion = "=1\.0\.9"' deny.toml
rg -U '\[\[licenses\.exceptions\]\]\nallow = \["CDLA-Permissive-2\.0"\]\nname = "webpki-roots"\nversion = "=1\.0\.9"' deny.toml
```

Expected: both exact version/checksum/license tuples and both exact exceptions
are present. If any coordinate, checksum, license, or exception differs, stop
and return to design review; do not broaden the disposition.

### Step 2: Create an unsigned, role-owned proposal

Use this header:

```markdown
#

# Proposed DM-8-05 disposition for Linux Event MVP Evaluation Profile v0.1

- Requirement: `DM-8-05`
- Profile: [`aster-linux-event-mvp-evaluation-v0.1`](linux-event-mvp-evaluation-profile-v0.1.md)
- Status: proposed for exact-candidate approval; this document records no specialist approval
- Evaluation effect: blocking until dependency, legal, and release owners approve
- Production effect: remains blocking after evaluation approval
- General allowlist effect: none
```

Record exactly:

| Package | Version | crates.io archive SHA-256 | License |
|---|---:|---|---|
| `webpki-root-certs` | `1.0.9` | `b96554aa2acc8ccdb7e1c9a58a7a68dd5d13bccc69cd124cb09406db612a1c9b` | `CDLA-Permissive-2.0` |
| `webpki-roots` | `1.0.9` | `7dcd9d09a39985f5344844e66b0c530a33843579125f23e21e9f0f220850f22a` | `CDLA-Permissive-2.0` |

Copy the approved disposition limits exactly:

- only these tuples and only non-production v0.1 evaluation;
- no general license allowlist;
- no WebPKI trust or public/default relay authorization;
- mandatory SBOM and third-party-notice presence;
- fail closed on package, version, source, checksum, reachability, graph, or
  license drift;
- dependency, legal, and release owners separately record identity, role,
  decision, date, exact coordinates/checksums/licenses, and the reviewed
  disposition digest; the later candidate annex separately binds the artifact
  dependency graph;
- evaluation approval does not close the formal production requirement;
- missing record, drift, missing notice/SBOM, public trust/relay use, or a
  production claim refuses the exception;
- no requirements or evidence status changes.

This docs lane owns the exact proposal text only. It must not insert signatures,
claim legal approval, edit `deny.toml`, regenerate notices, or speak for the
artifact/release lanes.

### Step 3: Link the proposal without closing its candidate gate

Update D15's proposed-resolution text to link this proposal. Keep D15 `Open`,
with both P0 and candidate blockers `yes`, until all three specialist approvals
are recorded.

### Step 4: Verify disposition and protected files

```bash
git add --intent-to-add docs/implementation/dm-8-05-linux-event-v0.1-disposition.md
rg -n 'records no specialist approval|webpki-root-certs|webpki-roots|CDLA-Permissive-2.0|General allowlist effect: none|remains blocking' docs/implementation/dm-8-05-linux-event-v0.1-disposition.md
git diff --exit-code 419cddd -- deny.toml THIRD_PARTY_NOTICES.md Cargo.lock
python3 tools/check-implementation-requirements.py
git diff --check
git status --short
```

Expected: the proposal and register are pending; policy, notices, and lockfile
are unchanged.

### Step 5: Commit Task 3

```bash
git add docs/implementation/dm-8-05-linux-event-v0.1-disposition.md
git add docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md
git commit -m "docs: propose bounded DM-8-05 evaluation disposition"
```

## Task 4: Create the provisional per-candidate annex schema

**Files:**

- Create:
  `docs/implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md`

### Step 1: Prove the path is free

```bash
test ! -e docs/implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md
```

Expected: exit 0.

### Step 2: Establish status and review ownership

Begin with:

```markdown
#

# Linux Event MVP Evaluation Profile v0.1 candidate-annex schema

- Schema version: `0.1-proposed`
- Profile ID: `aster-linux-event-mvp-evaluation-v0.1`
- Status: provisional and revisionable; never qualification evidence by itself
- Freeze gate: OS/artifact, integration/device, deterministic-gate, security,
  dependency/legal, and release owners approve the schema interfaces

A candidate cannot qualify before this schema is reviewed and frozen and G2,
G3, G4, and G5 pass in order. A completed annex contains concrete immutable
identifiers, digests, results, and approvals for every applicable required
field. An omitted, unfilled, ambiguous, mutable, or unsigned required field
makes that annex non-qualifying.
```

No secret, credential, private key, bearer token, unsanitized customer identity,
or mission plaintext enters this schema or a repository copy of an annex.
Completed customer annexes may require controlled storage; any public copy must
be sanitized without removing facts required to substantiate its public claim.

### Step 3: Define only approved annex facts

For each field, state whether it is required or conditional, its format, its
owner, and its rejection rule. Include:

1. Profile/decision identity and final issue/refuse/defer outcome.
2. Full source commit; dependency-lock, toolchain, configuration, and harness
   versions/digests; clean locked checkout and deterministic-gate result.
3. Both architecture `.deb` artifacts, exact sizes/digests/authentication,
   package/SBOM/notices/provenance digests, and install/uninstall procedures.
4. Exact protected provider/version and the results for install reference,
   load, bearer rotation, provider/reference rotation, backup/recovery,
   revoke/rekey, and logical destroy/fail-closed startup.
5. Sanitized mission/root/signer/profile/suite/policy identifiers and explicit
   separation of mission authority from optional relay DER trust roots.
6. Conditional pinned-relay facts, or an explicit signed `relay not used`
   statement. Never record private trust material.
7. Three separate participant inventories and receipt sets for the 2-, 8-, and
   20-node base scenarios. Record reuse of the physical `x86_64` and `aarch64`
   nodes and every VM allocation/oversubscription fact. A later customer annex
   may select one already-qualified architecture/tier only after base
   qualification.
8. Exact topology/configuration facts: one authority/scope/topic/subscription
   per scenario, manual peer/address bindings, discovery off, store limits,
   total application connections, node-global in-flight requests, emission
   mode, and harness limits.
9. Results for the exact six-row workload matrix and all thirteen acceptance
   conditions.
10. Separate classification of profile qualification versus engineering or
    component evidence. Post-payload-retirement behavior is component evidence
    only; operation-map hard-cap saturation is isolated engineering evidence
    and does not expand the 1,024-operation workload claim.
11. Approved threshold measurements only: executable size, RSS, idle CPU,
    readiness, stop, state growth/free space, logical item/byte use,
    operation-map rows/bytes/headroom, and physical-target energy with no
    threshold.
12. Immutable receipt index with digest, producer, environment class, exact
    claim, and non-claims.
13. G1-G6 matrix with dependencies and immutable exit-artifact digests.
14. Exact DM-8-05 proposal digest and separate dependency, legal, and release
    approval records.
15. Detached final role approvals that each sign the canonical signable-body
    digest; the separate detached release decision signs and binds that body
    digest plus the sorted approval-record digests.

Do not add informational measurements as qualification gates unless the
profile requires them. In particular, signed Git metadata, network/block-I/O
metrics, extra runtime fingerprints, and fleet/SLO fields are not silently
promoted into v0.1 requirements.

### Step 4: Add rejection and lifecycle rules

Reject an annex if:

- a required value is absent, mutable, or unverifiable;
- a digest/authentication/signature check fails;
- source, artifacts, configuration, provider, or test environment differs
  across dependent gates without a new candidate;
- either architecture or any base tier is missing;
- topology, workload, limit, or timing differs from the profile;
- an evaluation-blocking register row remains open;
- a summary lacks its immutable receipt;
- component/engineering evidence is presented as black-box qualification;
- a warning or the September 13 date is treated as a pass;
- a secret or unsanitized customer identity is embedded.

After owner review, schema freeze gets a reviewed version and digest. Changing a
frozen required field or evidence boundary creates a new schema revision and
invalidates incomplete candidate annexes; it never rewrites an issued annex.

### Step 5: Verify schema coverage

```bash
git add --intent-to-add docs/implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md
rg -n '0.1-proposed|provisional and revisionable|never qualification evidence|2-, 8-, and 20-node|component evidence|isolated engineering evidence|G1-G6|DM-8-05|Final role approvals' docs/implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md
rg -n 'issue/refuse/defer|x86_64|aarch64|1,024|2026-09-13|private trust material' docs/implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md
git diff --check
git status --short
```

Expected: provisional ownership, all three inventories, evidence classes, and
all fifteen sections are explicit.

### Step 6: Commit Task 4

```bash
git add docs/implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md
git commit -m "docs: propose Linux Event candidate annex schema"
```

## Task 5: Publish the proposed adoption package

**Files:**

- Create:
  `docs/decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md`
- Modify: `docs/README.md`

### Step 1: Confirm Decision 0042 is free across active refs

Run:

```bash
test ! -e docs/decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md
git branch -a --contains 419cddd
git log --all --name-only --format= -- ':(glob)docs/decisions/0042-*'
```

Expected: the final command prints no path. If any active ref owns 0042 under
another slug, inspect the integration target, renumber this ADR, and update all
new references in one commit.

### Step 2: Create the Proposed adoption decision

Use this header:

```markdown
#

# Decision 0042: Adopt the Linux Event MVP Evaluation Profile v0.1

- Status: Proposed; ratification blocked by register rows `P0-1-D06` and `P0-1-D15`
- Proposed: 2026-09-06
- Proposed authority: [Linux Event MVP Evaluation Profile v0.1](../implementation/linux-event-mvp-evaluation-profile-v0.1.md)
- Register: [P0-1 decision and gate register](../implementation/linux-event-mvp-evaluation-profile-v0.1-register.md)
- Roadmap action: `P0-1 — define the claim boundary`
```

Record:

- why one bounded profile is needed instead of a flat requirement-count claim;
- the Event/Linux/non-production/20-node rationale;
- the proposed profile, mutable register, unsigned DM-8-05 proposal, and
  provisional annex-schema roles;
- why ReceiveOnly and operation capacity/status/error boundaries are included;
- why implementation/evidence gates do not by themselves block P0-1;
- why D06 exact-provider selection and D15's three approvals do block
  ratification under the approved design;
- that G1-G6 still prohibit candidate authorization after P0-1 closes;
- that this proposal changes no atomic requirement/evidence status;
- that a production profile must supersede v0.1;
- the separate post-Event-merge implementation boundary.

Do not change the profile or design status in this task.

### Step 3: Add one proposed-profile discovery row

Under `docs/README.md` “Choose a guide by goal,” add:

```markdown
| Review the proposed bounded Linux/Event customer profile | [Linux Event MVP Evaluation Profile v0.1](implementation/linux-event-mvp-evaluation-profile-v0.1.md), its [decision register](implementation/linux-event-mvp-evaluation-profile-v0.1-register.md), and the [candidate-annex schema](implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md) |
```

Do not edit the capability snapshot or broaden current implementation claims.

### Step 4: Verify the proposed package and protected baselines

Run each command independently:

```bash
git add --intent-to-add docs/decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md
test -f docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md
test -f docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md
test -f docs/implementation/dm-8-05-linux-event-v0.1-disposition.md
test -f docs/implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md
test -f docs/decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md
test -f docs/superpowers/specs/2026-09-06-linux-event-mvp-evaluation-profile-design.md
rg -n 'Status: Proposed|P0-1-D06|P0-1-D15' docs/decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md
python3 tools/check-implementation-requirements.py
git diff --exit-code 419cddd -- docs/implementation/requirements-status.md
git diff --exit-code 419cddd -- docs/implementation/requirements-implementation.csv
git diff --exit-code 419cddd -- docs/implementation/evidence
git diff --exit-code 419cddd -- data-mesh-requirements.md
git diff --exit-code 419cddd -- deny.toml THIRD_PARTY_NOTICES.md Cargo.lock
git diff --check
mise run check
git status --short
```

Expected:

- every named deliverable exists;
- the ADR, profile, D06, and D15 are still Proposed/Open;
- the requirements checker reports all 348 IDs and no integrity failure;
- requirement source/status/mapping, retained evidence, dependency policy,
  notices, and lockfile are byte-unchanged from the verified integration base;
- `mise run check` passes;
- only Task 5 documentation paths are pending.

These commands do not implement a general Markdown link checker. Manually open
every new relative link and verify its target and any fragment. Record that
manual review in the PR verification section.

`mise run fuzz-smoke` is not required because this plan changes no parser,
framing, envelope, fragmentation, or hostile-input boundary.

### Step 5: Check the complete changed-path allowlist

Run:

```bash
git diff --name-only 419cddd
git ls-files --others --exclude-standard
git diff --stat 419cddd
git diff 419cddd -- docs/README.md docs/decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md docs/implementation docs/superpowers
```

Validate the union of the first two command outputs. The complete branch delta
may contain only:

- `docs/README.md`
- `docs/decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md`
- `docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md`
- `docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md`
- `docs/implementation/dm-8-05-linux-event-v0.1-disposition.md`
- `docs/implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md`
- `docs/superpowers/specs/2026-09-06-linux-event-mvp-evaluation-profile-design.md`
- `docs/superpowers/plans/2026-09-06-linux-event-mvp-evaluation-profile.md`

Read every Markdown table in a preview or terminal renderer and inspect all
`Open`/`Deferred` rows again.

### Step 6: Commit Task 5

```bash
git add docs/README.md
git add docs/decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md
git commit -m "docs: propose Linux Event MVP profile adoption"
```

At this point the branch is a complete proposed ratification package. Stopping
here while D06 or D15 is open is an expected outcome, not a failed execution.

## Task 6: Conditionally ratify P0-1 and switch authority

**Files:**

- Modify:
  `docs/decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md`
- Modify:
  `docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md`
- Modify:
  `docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md`
- Modify:
  `docs/implementation/dm-8-05-linux-event-v0.1-disposition.md`
- Modify:
  `docs/superpowers/specs/2026-09-06-linux-event-mvp-evaluation-profile-design.md`
- Modify: `docs/README.md`

### Step 1: Enforce the hard ratification preconditions

Inspect, without editing status, for all three prerequisite sets:

1. D06: confirm the approved initial provider-design digest remains exact and
   final review has not required Debian or generic Debian-family support. D06
   is resolved for P0-1; security and deployment approvals remain candidate
   gate E01, and actual packaged lifecycle results remain later qualification
   gates.
2. D15: dependency, legal, and release approvals each identify the reviewer,
   role, decision, date, the exact two package/version/checksum/license tuples,
   and the reviewed disposition digest.
3. Profile/product and the remaining required P0-1 roles record approval or
   no-objection to the Tasks 1–5 interface boundary. Security and deployment
   provider approval is retained at E01 and does not block the profile
   definition. This review approves the reusable profile definition only; it
   does not authorize a candidate.

Present the complete Tasks 1–5 delta and all three exit sets to the user/profile
decision owner and request explicit authorization to mark Decision 0042
Accepted and close P0-1. Interface review may refine the provisional annex
schema but may not silently change the profile boundary.

If the D15 exit set, another required P0-1 role review, or explicit
ratification authorization is absent, stop here, report the exact missing
record, and leave the ADR/profile Proposed, D15 Open, and the approved design
authoritative. If final review requires Debian support, reopen D06 and stop for
provider redesign. Do not infer approval from a date, passing checks, or the
existence of unsigned text.

### Step 2: Record the reviewed exits

Only after Step 1 passes:

- verify D06 remains linked to the immutable approved initial provider record,
  `Resolved`, with P0 blocker `no`, while E01 and all applicable
  implementation/candidate gates remain open;
- link D15 to all three immutable approval records; set it `Resolved`, with P0
  blocker `no`;
- update the DM-8-05 proposal status to evaluation disposition approved by the
  three named roles, while stating that `DM-8-05` remains formally open and
  production-blocking;
- update the proposed-profile discovery row in `docs/README.md` to say
  `Evaluate` rather than `Review the proposed`.

Copy identifiers, dates, decisions, and digests exactly from the reviewed exit
artifacts. Do not create or sign those records in the documentation lane.

### Step 3: Complete one atomic authority switch

Change the ADR status to:

```markdown
- Status: Accepted as a bounded non-production evaluation profile; candidate-authorization gates remain open
```

Add an `Accepted:` field whose ISO calendar date is copied exactly from the
signed ratification authorization. Keep `Proposed: 2026-09-06` as proposal
history; do not backdate acceptance to the proposal date.

Change the profile status to:

```markdown
- Status: Accepted by Decision 0042; candidate-authorization gates remain open
```

Add a `Ratified:` field with the same actual authorization date recorded by the
ADR.

Change the design status block to:

```markdown
**Status:** Approved historical design record; implemented by the accepted
[`Linux Event MVP Evaluation Profile v0.1`](../../implementation/linux-event-mvp-evaluation-profile-v0.1.md)

**Change policy:** Frozen. Correct factual errata here; change the claim
boundary only through a versioned profile and reviewed decision.
```

Remove the design's temporary implementation-plan pointer. Keep all three
status changes in one commit so a proposed document never supersedes an
approved one. State explicitly in the ADR that this closes P0-1 only and does
not authorize a candidate or move requirement evidence.

### Step 4: Re-run all ratification checks

Re-run the file-existence checks, requirements checker, protected-baseline
comparisons, `git diff --check`, `mise run check`, status inspection, and
changed-path allowlist from Task 5 Steps 4–5. Omit Task 5's
`Status: Proposed` assertion because this task changes that status. Then run:

```bash
rg -n '^- Status: Accepted as a bounded non-production evaluation profile; candidate-authorization gates remain open$' docs/decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md
rg -n '^- Status: Accepted by Decision 0042; candidate-authorization gates remain open$' docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md
rg -n '^- Accepted: 2026-[0-9]{2}-[0-9]{2}$' docs/decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md
rg -n '^- Ratified: 2026-[0-9]{2}-[0-9]{2}$' docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md
adr_acceptance_date="$(sed -n 's/^- Accepted: //p' docs/decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md)"
profile_ratification_date="$(sed -n 's/^- Ratified: //p' docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md)"
test "$adr_acceptance_date" = "$profile_ratification_date"
rg -n '^\| `P0-1-D06` .*\| Resolved \| no \|' docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md
rg -n '^\| `P0-1-D15` .*\| Resolved \| no \|' docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md
rg -n '^\| `P0-1-D06` .*\]\([^)]*\)' docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md
rg -n '^\| `P0-1-D15` .*\]\([^)]*\)' docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md
awk -F'|' '/^\| `P0-1-D/ { gsub(/^ +| +$/, "", $6); if ($6 == "yes") bad = 1 } END { exit bad }' docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md
rg -n 'formally open|production-blocking' docs/implementation/dm-8-05-linux-event-v0.1-disposition.md
git diff --check
mise run check
git status --short
```

Expected: D06/D15 link real reviewed exits, the authority statuses agree, all
candidate gates unrelated to those exits remain open, protected baselines are
unchanged, and checks pass.

### Step 5: Commit Task 6

```bash
git add docs/README.md
git add docs/decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md
git add docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md
git add docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md
git add docs/implementation/dm-8-05-linux-event-v0.1-disposition.md
git add docs/superpowers/specs/2026-09-06-linux-event-mvp-evaluation-profile-design.md
git commit -m "docs: ratify Linux Event MVP evaluation profile"
```

## Task 7: Prepare the focused PR handoff

**Files:** none

### Step 1: Confirm a clean worktree and focused history

```bash
git status --short --branch
git log --oneline 419cddd..HEAD
```

Expected: a clean worktree. The history contains the design approval/plan,
proposed profile, register, disposition proposal, annex schema, and proposed
adoption. It contains the conditional ratification commit only if Task 6's
preconditions passed.

### Step 2: Draft the PR description

Use `.github/pull_request_template.md`. State one of these exact outcomes:

- if Task 6 did not run: `P0-1 ratification package is proposed; D06/D15 remain
  open and P0-1 is not closed`;
- if Task 6 ran: `P0-1 is closed only as a reviewed reusable claim boundary;
  no candidate is authorized`.

In both cases state:

- G1-G6, source integration, artifacts, device results, soak, and release
  disposition remain candidate gates;
- the annex schema is provisional until all named lanes review and freeze it;
- no implementation, atomic requirement status/mapping, or retained evidence
  changed;
- Event-service, artifact, device-harness, and deterministic-release work was
  not duplicated;
- verification lists exact successful commands and manual link/table review.

When Task 6 did not run, identify the missing D06/D15 records precisely. Call
out the provisional 800-slot margin/byte-fit projection and September 13
issue/refuse/defer semantics in risks.

### Step 3: Request remaining role review without changing external state

Ask reviewers to distinguish profile ratification, schema/disposition review,
and authorization of one exact candidate. Do not create, update, or merge a
remote PR unless the user explicitly requests that external state change.

## Follow-on plan after Event-service integration

Write a separate stacked source plan only after inspecting the integrated Event
commit. Cover:

1. restart-selected `mesh.emission_policy` and effective status;
2. both-ordering ReceiveOnly tests and disclosure negatives;
3. operation-map rows/bytes/caps/warning/profile headroom in status;
4. the 512 warning and 1,024-operation workload accounting;
5. `PUBLIC_ERROR_REASON_OPERATION_CAPACITY_EXHAUSTED = 12` and exact
   nonretryable `ResourceExhausted` mapping;
6. post-payload-retirement documentation reconciliation;
7. Rust reference and generated-Go qualification cases;
8. corrected delivery/config capacity docs on the integrated tree.

That plan must not absorb protected-provider composition, reproducible package
mechanics, physical-device automation, or deterministic-release ownership.
