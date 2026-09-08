# Raspberry Pi Linux Event MVP Profile Amendment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Revise the unmerged Linux Event MVP Evaluation Profile v0.1 to qualify one two-node physical CM4/aarch64 Raspberry Pi environment and one `arm64` package by the 2026-09-13 decision checkpoint.

**Architecture:** Preserve the original Ubuntu/dual-architecture design as history and apply one explicit pre-merge amendment to the normative profile, decision register, coordination guide, and candidate annex. Replace the Ubuntu-specific credential-provider v1 design with a separately hash-bound Raspberry Pi/systemd 257 v2 design while keeping Security and Deployment approval at E01.

**Tech Stack:** Markdown decisions and schemas, SHA-256 document bindings, Git/GitHub, Raspberry Pi reference image `2026-06-18`, Debian 13 `trixie`, `aarch64`/`arm64`, systemd `257.13-1~deb13u1`, native `.deb` packaging.

**Spec:** [`docs/superpowers/specs/2026-09-08-raspberry-pi-linux-event-mvp-profile-amendment-design.md`](../specs/2026-09-08-raspberry-pi-linux-event-mvp-profile-amendment-design.md)

## Global Constraints

- Required platform: Raspberry Pi reference image `2026-06-18`, identifying as Debian GNU/Linux 13 `trixie`.
- Required hardware: exactly two physical Raspberry Pi Compute Module 4 Rev 1.1 participants; the third CM4 is support capacity and is declared whenever it handles candidate traffic.
- Required architecture and package: `aarch64` runtime and one native `arm64` `.deb`.
- Required kernel, service manager, and filesystem: `6.18.39+rpt-rpi-v8`, systemd `257.13-1~deb13u1`, and local `ext4`, revalidated in the candidate annex.
- Provider contract: `aster-systemd-credential-store/v2`; TPM2 remains excluded.
- Deferred from v0.1: Ubuntu, `x86_64`/`amd64`, CM5, VMs, containers, 8/20-node qualification, generic Debian, and generic Raspberry Pi OS.
- Preserve the original profile design, Ubuntu provider v1 design, their hashes, the 348-requirement baseline, and all historical evidence.
- D15 approvals and exact dependency tuples remain unchanged; production `DM-8-05` remains open.
- Do not broaden runtime, customer-candidate, production, radio-silence, provider-portability, or scale claims.
- Use focused documentation checks only. Do not run Cargo tests, `mise run check`, or fuzzing for this documentation-only revision.

---

### Task 1: Define the Raspberry Pi systemd credential provider v2

**Files:**
- Create: `docs/superpowers/specs/2026-09-08-raspberry-pi-systemd-credential-provider-v2-design.md`
- Read without modifying: `docs/superpowers/specs/2026-09-07-systemd-credential-provider-design.md`
- Read without modifying: `docs/superpowers/specs/2026-09-08-raspberry-pi-linux-event-mvp-profile-amendment-design.md`

**Interfaces:**
- Consumes: approved provider behavior from `aster-systemd-credential-store/v1` and the exact amended platform boundary.
- Produces: provider ID `aster-systemd-credential-store/v2` and a final SHA-256 digest that Tasks 2–4 bind verbatim.

- [ ] **Step 1: Confirm the historical inputs are unchanged**

Run:

```bash
sha256sum docs/superpowers/specs/2026-09-07-systemd-credential-provider-design.md
sha256sum docs/superpowers/specs/2026-09-08-raspberry-pi-linux-event-mvp-profile-amendment-design.md
```

Expected: the v1 provider digest is
`078c35f0046c62a7415d4e8c843f198f97da898da8b8b17eebeaa98de3e2a781`;
record the amendment digest shown by the command for traceability.

- [ ] **Step 2: Create the complete v2 design**

Use `apply_patch` to create the new file. Preserve the v1 document’s component,
seven-operation lifecycle, atomicity, secret-nondisclosure, and failure-path
detail, but make these exact changes throughout:

```text
Title: Raspberry Pi systemd credential provider v2 design
Status: Approved for the amended Linux Event MVP profile
Provider contract: aster-systemd-credential-store/v2
Image: Raspberry Pi reference 2026-06-18
Distribution: Debian GNU/Linux 13 (trixie)
Hardware/architecture: Raspberry Pi Compute Module 4 Rev 1.1 / aarch64
systemd: 257.13-1~deb13u1
Credential executable: /usr/bin/systemd-creds
Filesystem: ext4
TPM2: excluded
```

The design must explicitly state:

```text
- v2 supports only the exact amended profile, not generic Debian or Raspberry Pi OS.
- LoadCredentialEncrypted= and host-key-backed systemd credentials are mandatory.
- Missing host credential key, plaintext fallback, wrong owner/mode, wrong credential name, decrypt failure, or package/interface drift fails closed.
- aster-credential-admin remains the root-operated administration boundary.
- Runtime loader, administration binary, provider ledger, backup/recovery, rotation, revoke/rekey, logical destruction, and nondisclosure rules retain their v1 semantics.
- G3 freezes the exact systemd package, executable, unit, provider, and arm64 package identities.
- G4 repeats lifecycle and negative acceptance on both mandatory physical CM4 nodes.
- Security and Deployment E01 approval remains required; profile approval does not replace it.
- The Ubuntu v1 design remains historical and does not qualify v2.
```

- [ ] **Step 3: Check the v2 design for stale scope and placeholders**

Run:

```bash
rg -n 'T[B]D|T[O]DO|T[B]C|F[I]XME|PLACE[H]OLDER' docs/superpowers/specs/2026-09-08-raspberry-pi-systemd-credential-provider-v2-design.md
rg -n "aster-systemd-credential-store/v2|Raspberry Pi reference 2026-06-18|Debian GNU/Linux 13|257.13-1~deb13u1|Compute Module 4|aarch64|TPM2" docs/superpowers/specs/2026-09-08-raspberry-pi-systemd-credential-provider-v2-design.md
git diff --check
```

Expected: the placeholder search has no matches; every required exact value is
present; `git diff --check` exits 0. Any Ubuntu/v1 text may appear only in an
explicit historical or supersession statement.

- [ ] **Step 4: Compute the immutable v2 design digest**

Run:

```bash
sha256sum docs/superpowers/specs/2026-09-08-raspberry-pi-systemd-credential-provider-v2-design.md
```

Expected: one SHA-256 value. Call this runtime-derived value
`D06_V2_SHA256`; Tasks 2–4 must recompute and bind that exact value rather than
inventing one in advance.

- [ ] **Step 5: Commit the v2 design**

```bash
git add docs/superpowers/specs/2026-09-08-raspberry-pi-systemd-credential-provider-v2-design.md
git commit -m "docs: define Raspberry Pi credential provider v2"
```

### Task 2: Revise the normative profile boundary

**Files:**
- Modify: `docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md:1`

**Interfaces:**
- Consumes: the approved amendment and Task 1’s `aster-systemd-credential-store/v2` path and `D06_V2_SHA256`.
- Produces: the normative two-node CM4/aarch64 profile used by the register, guide, and annex.

- [ ] **Step 1: Add amendment authority and exact identity**

Use `apply_patch` to add the approved amendment link beside the historical
design link and state that it supersedes conflicting platform, architecture,
topology, artifact, D06, and acceptance text. Preserve the accepted status and
candidate checkpoint.

Replace the profile identity/reuse text with these exact boundaries:

```text
- exact Raspberry Pi reference image, Debian identity, kernel, systemd package,
  architecture, filesystem, and CM4 identity;
- exactly two mandatory physical aarch64 CM4 participants;
- a third CM4 only as declared support capacity;
- no reusable claim for another OS, image, architecture, device family, VM,
  container, or node tier.
```

- [ ] **Step 2: Replace the platform and topology sections**

Replace the platform table with:

```markdown
| Dimension | Required value |
|---|---|
| Operating system | Raspberry Pi reference image `2026-06-18`, identifying as Debian GNU/Linux 13 `trixie` |
| Kernel | Exact `6.18.39+rpt-rpi-v8` build, revalidated and frozen in the candidate annex |
| Architecture | `aarch64` only |
| Hardware | Physical Raspberry Pi Compute Module 4 Rev 1.1 |
| Service manager | systemd `257.13-1~deb13u1` |
| Package | Native `arm64` `.deb` |
| Filesystem | Local `ext4` state |
```

Replace the 2/8/20 topology table with one required two-node row. State that
both CM4 nodes run the unchanged G3 artifact and exchange Events directly.
Describe the third CM4 as an optional declared spare/failure/recovery/relay
participant, with inventory change and affected-scenario rerun rules. Move
8/20 nodes, VMs, Ubuntu, `x86_64`, and CM5 to explicit non-goals.

- [ ] **Step 3: Replace the D06 and artifact contracts**

In `Protected provisioning boundary`, bind:

```text
provider = aster-systemd-credential-store/v2
design = docs/superpowers/specs/2026-09-08-raspberry-pi-systemd-credential-provider-v2-design.md
design_digest = sha256: followed by the exact D06_V2_SHA256 from Task 1 Step 4
systemd = 257.13-1~deb13u1
```

Retain the host-key, static composition, administration, lifecycle,
nondisclosure, and E01 limitations. Replace two architecture-specific
candidates with one native `arm64` candidate containing the exact existing
artifact list, including Rust reference source and generated Go client plus
black-box acceptance executable/source.

- [ ] **Step 4: Narrow capacity, acceptance, and G1–G6 language**

Change only platform-dependent requirements:

```text
- retained workload measurements cover both mandatory CM4 nodes, not both architectures;
- acceptance condition 5 covers both CM4 devices and the one arm64 artifact;
- acceptance condition 7 covers the two-node workload only;
- G3 produces one arm64 package;
- G4 uses both mandatory CM4 devices;
- G5 runs the two-node workload and 24-hour disconnected/reconnection scenario;
- energy and resource measurements are per participating physical CM4 node.
```

Keep Event semantics, Rust/Go coverage, ReceiveOnly both-ordering tests,
capacity limits, resource thresholds, D15, security profile, and production
exclusions unchanged.

- [ ] **Step 5: Run focused profile consistency checks**

Run:

```bash
rg -n "Raspberry Pi reference 2026-06-18|Compute Module 4|aarch64|arm64|257.13-1~deb13u1|aster-systemd-credential-store/v2|exactly two" docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md
rg -n "Ubuntu Server|Canonical-supported|systemd 255|credential-store/v1|both architectures|2/8/20|8- and 20-node|physical x86_64" docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md
git diff --check
```

Expected: required revised terms appear. Any old-platform match is confined to
an explicit exclusion or historical-design statement; no old platform remains
required. `git diff --check` exits 0.

- [ ] **Step 6: Commit the normative profile revision**

```bash
git add docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md
git commit -m "docs: narrow Linux Event MVP to two CM4 nodes"
```

### Task 3: Align Decision 0042, the register, and coordination guide

**Files:**
- Modify: `docs/decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md:1`
- Modify: `docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md:1`
- Modify: `docs/implementation/linux-event-mvp-coordination-guide.md:1`

**Interfaces:**
- Consumes: Task 2’s normative platform/topology and Task 1’s v2 provider digest.
- Produces: one consistent accepted decision, live status register, ownership map, and schedule.

- [ ] **Step 1: Amend Decision 0042 without erasing history**

Use `apply_patch` to link the 2026-09-08 amendment and record that the accepted
pre-merge profile now selects the exact Raspberry Pi/CM4 boundary. Replace the
Ubuntu/dual-architecture/2/8/20 rationale and consequences with:

```text
- two physical aarch64 CM4 nodes minimize time to physical qualification;
- the third device is support capacity, not evidence for a broader tier;
- one arm64 artifact is required;
- x86_64, Ubuntu, VMs, and 8/20-node scale are deferred without changing atomic requirement status;
- D06 is resolved for profile definition by the exact v2 design and digest;
- E01, G1–G6, final candidate approvals, and production gates remain open.
```

- [ ] **Step 2: Update the decision rows and candidate gates**

Use `apply_patch` in the register to set:

```text
D02 = exact Raspberry Pi reference 2026-06-18 / Debian 13 / kernel / systemd / ext4 / CM4 / aarch64 envelope
D03 = exactly two physical participants; optional third support node must be declared; 8/20 deferred
D06 = aster-systemd-credential-store/v2 plus exact new design path and D06_V2_SHA256
D09 = two-node workload/resource matrix
D12 = one arm64 artifact plus the revised acceptance and G1-G6 chain
D13 = explicit Ubuntu/x86_64/CM5/VM/8/20 exclusions
D14-17 = exactly two required nodes; 8/20-node qualification excluded from v0.1
```

Update open gates:

```text
E01 -> exact v2 provider design and digest
E02 -> exact two-CM4 inventory plus conditional third-node declaration
E08 -> one signed reproducible arm64 package
E10 -> retained receipts for both mandatory physical CM4 devices
G3 -> one provider-composed arm64 package
G4 -> two mandatory CM4 devices
G5 -> two-node workload plus 24-hour scenario
```

Do not alter D15 Approved status or E12 production blocking status.

- [ ] **Step 3: Simplify the coordination guide around the fast path**

Use `apply_patch` to state the human-facing outcome in this order:

```text
1. one accepted Raspberry Pi/CM4/aarch64 profile;
2. one frozen source/API commit;
3. one reproducible arm64 package;
4. focused tests on two physical CM4 nodes;
5. one two-node 24-hour disconnected/reconnection run;
6. one signed G6 disposition before 2026-09-14.
```

Update every workstream handoff, current D06 state, G3/G4/G5 summary, MVP-ready
checklist, and schedule. Keep the existing 2026-09-09 through 2026-09-13 dates.
State that the third CM4 is a spare/support node and that `x86_64` and 8/20
scale are post-MVP.

- [ ] **Step 4: Check cross-document governance consistency**

Run:

```bash
rg -n "D02|D03|D06|D09|D12|D13|D14-17|E01|E02|E08|E10" docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md
rg -n "Raspberry Pi|CM4|arm64|two-node|third CM4|2026-09-13" docs/decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md docs/implementation/linux-event-mvp-coordination-guide.md
rg -n "Ubuntu Server|both architectures|all three node tiers|2/8/20|8-/20-node|credential-store/v1|systemd 255" docs/decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md docs/implementation/linux-event-mvp-coordination-guide.md
git diff --check
```

Expected: revised decision/gate terms appear; old terms occur only in explicit
history or exclusions; D15 remains Approved; `git diff --check` exits 0.

- [ ] **Step 5: Commit the governance and coordination update**

```bash
git add docs/decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md docs/implementation/linux-event-mvp-coordination-guide.md
git commit -m "docs: align P0-1 gates with Raspberry Pi fast path"
```

### Task 4: Reduce the candidate annex to one artifact and two CM4 nodes

**Files:**
- Modify: `docs/implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md:1`

**Interfaces:**
- Consumes: Tasks 1–3’s provider, artifact, device, workload, and gate identities.
- Produces: the signable candidate schema used by integration and release owners.

- [ ] **Step 1: Replace architecture artifacts and D06 bindings**

Use `apply_patch` to remove the required `x86_64`/`amd64` artifact row and keep
one required `aarch64`/`arm64` row. Replace every “both packages,” “either
architecture,” or per-architecture rejection rule with the one-artifact
equivalent.

In Section 4, bind the exact v2 provider design path, provider contract, and
`D06_V2_SHA256`. Keep separate Security and Deployment E01 approval rows and
reject v1, Ubuntu, generic Debian, or mismatched-systemd evidence.

- [ ] **Step 2: Replace participant inventories**

Replace Sections 7.1–7.3 with one mandatory inventory:

```markdown
### 7.1 Mandatory two-node CM4 inventory and receipt set

| Field/group | Applicability | Format | Owner | Rejection rule |
|---|---|---|---|---|
| CM4 node A | Required | Sanitized node ID; physical; Compute Module 4 Rev 1.1; `aarch64`; Raspberry Pi reference `2026-06-18`; Debian 13 `trixie`; exact kernel/systemd; `ext4`; resources; peer role; path; network conditions | Integration/physical-carrier owner | Reject a VM, wrong platform, missing fact, or failure to exchange Events with node B |
| CM4 node B | Required | Same exact field set as node A with a distinct node identity | Integration/physical-carrier owner | Reject a VM, wrong platform, duplicate identity, missing fact, or failure to exchange Events with node A |
| Third CM4 support node | Conditional | Exact same identity fields plus `spare`, `replacement`, `failure-test`, or `relay` role and affected scenario IDs | Integration/physical-carrier owner | Reject undeclared traffic participation, ambiguous role, or evidence combined across changed inventories |
| Two-node receipt set | Required | Direct exchange, both ReceiveOnly identity orderings, restart/reopen, capacity, resource, and workload receipt references/digests | Integration + release | Reject a missing receipt, changed inventory, or broader node-tier claim |
```

Remove the 8-node, 20-node, six-VM, eighteen-VM, mixed-architecture, and reusable
dual-architecture requirements.

- [ ] **Step 3: Reduce workloads and acceptance conditions**

Rename Section 9 from “Six-row workload matrix” to “Four-row workload matrix.”
Keep these rows:

```text
API boundary: 2 nodes
Small topology: 2 nodes
Offline soak: 2 nodes, 4 KiB, 10 Events/hour/node for 24 hours
Capacity-warning probe: 2 nodes, 512 distinct local operations plus one exact retry
```

Remove intermediate 8-node and maximum 20-node rows. Update acceptance
condition 1 to one package, condition 5 to both mandatory CM4 nodes, condition
7 to the exact two-node workload, condition 11 to per-CM4 resource
measurements, and energy applicability to each mandatory physical CM4.

- [ ] **Step 4: Align G3–G6 and canonical signing rules**

Update Section 13 so G3 requires the one `arm64` artifact, G4 uses both CM4
nodes, and G5 uses the two-node/24-hour evidence. Replace every rejection rule
that requires two packages, either architecture, or three tiers. Preserve the
complete artifact-set manifest, typed `not-produced`/`not-run` values, D15
record, Section 15 detached approvals, digest ordering, and G6 signature rules.

- [ ] **Step 5: Run focused annex consistency checks**

Run:

```bash
rg -n "CM4 node A|CM4 node B|Third CM4 support node|Four-row workload|aarch64|arm64|aster-systemd-credential-store/v2|24 hours" docs/implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md
rg -n "Physical x86_64|Six VM|Eighteen VM|Eight-node|Twenty-node|both packages|either architecture|both architectures|all three tiers|2/8/20|credential-store/v1|systemd 255" docs/implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md
git diff --check
```

Expected: the revised schema terms appear; the stale required-boundary search
has no matches; `git diff --check` exits 0.

- [ ] **Step 6: Commit the annex revision**

```bash
git add docs/implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md
git commit -m "docs: simplify candidate annex for two CM4 nodes"
```

### Task 5: Verify traceability and update PR #3

**Files:**
- Verify: all files changed by Tasks 1–4
- External update: GitHub PR `edgesoftops/astertech#3`

**Interfaces:**
- Consumes: the complete revised documentation set and its final Git commits.
- Produces: a pushed, reviewable PR whose description matches the repository state.

- [ ] **Step 1: Verify immutable historical and new design bindings**

Run:

```bash
sha256sum docs/superpowers/specs/2026-09-07-systemd-credential-provider-design.md
sha256sum docs/implementation/dm-8-05-linux-event-v0.1-disposition.md
sha256sum docs/implementation/dm-8-05-linux-event-v0.1-role-approvals.md
sha256sum docs/superpowers/specs/2026-09-08-raspberry-pi-systemd-credential-provider-v2-design.md
rg -n "sha256:" docs/decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md docs/implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md
```

Expected historical digests:

```text
078c35f0046c62a7415d4e8c843f198f97da898da8b8b17eebeaa98de3e2a781  Ubuntu provider v1 design
a6fe15f39fb553f87bc1224fe7f266e7c906d451d8140402d3bc1620011bfa53  D15 disposition
4edda9457c78d0c1d177590c1583691071e708ccbbace078cc15a82dd9bcac85  D15 role approvals
```

Expected: every v2 reference equals the newly computed `D06_V2_SHA256`.

- [ ] **Step 2: Run the required focused repository checks**

Run:

```bash
git diff --check origin/main...HEAD
python3 tools/check-implementation-requirements.py
git status --short --branch
```

Expected: no whitespace errors; requirements trace reports `348 matrix IDs`
and `137 exact selected mappings`; the worktree is clean. Do not run the full
Rust gate or fuzz smoke because no runtime or hostile-input boundary changed.

- [ ] **Step 3: Review the final branch diff against the approved amendment**

Run:

```bash
git diff --stat origin/main...HEAD
git diff --name-status origin/main...HEAD
rg -n "Ubuntu Server 24.04|both architectures|all three node tiers|2/8/20|8-/20-node|systemd 255.4|aster-systemd-credential-store/v1" docs/decisions/0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md docs/implementation/linux-event-mvp-evaluation-profile-v0.1-register.md docs/implementation/linux-event-mvp-coordination-guide.md docs/implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md
```

Expected: every changed file is in the approved documentation scope. Any old
term is explicitly historical or excluded, never a current requirement.

- [ ] **Step 4: Push the branch**

```bash
git push origin feature/p0-1-linux-event-mvp-profile
```

Expected: remote branch advances to local `HEAD`.

- [ ] **Step 5: Replace PR #3’s old Ubuntu/dual-architecture description**

Use `.github/pull_request_template.md`. The updated PR body must state:

```text
- P0-1 profile v0.1 is accepted with the Raspberry Pi fast-path amendment.
- Exact required environment: Raspberry Pi reference 2026-06-18, Debian 13 trixie, CM4 Rev 1.1, aarch64, systemd 257.13-1~deb13u1, ext4.
- Exactly two physical CM4 nodes and one arm64 package are mandatory.
- The third CM4 is declared support capacity.
- Ubuntu, x86_64, CM5, VMs, and 8/20-node qualification are post-MVP.
- D06 uses aster-systemd-credential-store/v2; E01 remains open.
- D15 remains Approved by all three roles and production DM-8-05 remains open.
- No runtime behavior or requirements evidence status changes in this PR.
- Focused verification passed; full Rust/fuzz gates were intentionally not run for docs-only work.
```

Keep the PR title `docs: adopt Linux Event MVP evaluation profile v0.1`.

- [ ] **Step 6: Verify the remote PR state**

Run:

```bash
gh pr view 3 --repo edgesoftops/astertech --json title,url,headRefOid,isDraft,body
git rev-parse HEAD
```

Expected: PR #3 targets `main`, is not draft, its `headRefOid` equals local
`HEAD`, and its body contains the exact CM4/aarch64/two-node/v2-provider scope.
