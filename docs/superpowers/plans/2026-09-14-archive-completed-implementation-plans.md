# Archive Completed Implementation Plans Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove completed implementation plans from current product documentation by moving twelve historical plans into the passive design-history archive.

**Architecture:** Current code, tests, decisions, runbooks, profiles, and validation documents retain product authority. Completed execution plans move byte-for-byte with `git mv` to `archive/design-history/plans/`; no manifest, inventory, redirect, checker, or navigation entry is added.

**Tech Stack:** Markdown, Git, ripgrep, existing requirements checker

**Spec:** `docs/superpowers/specs/2026-09-14-documentation-refactor-design.md`

## Global Constraints

- Follow `CONTRIBUTING.md`; the work remains ``.
- `docs/` contains only information a human engineer needs for the current product.
- Archived material is non-normative and is not linked from normal product-documentation navigation.
- Preserve `data-mesh-requirements.md`, all 348 requirement IDs, the hash-bound baseline, and required historical evidence.
- Do not move any specification in this batch. Two systemd specifications are exact current hash-bound inputs, and the remaining specifications require separate durable-constraint review.
- Open qualification, role-review, and external gates remain in current profiles, registers, roadmap, and requirements status; an open gate does not make its completed implementation plan current product documentation.
- Move archived files byte-for-byte with `git mv`; do not rewrite historical plan content or add redirects.
- Do not add an archive manifest, checker, test, permanent inventory, archive-specific task, or Markdown parser.
- Do not run `mise run check`, builds, Cargo/Rust/Go commands, or test suites locally. Draft PR #24 CI provides the full-suite execution path after push.
- Use only lightweight checks: `rg`, `find`, `git diff`, `git status`, and `python3 tools/check-implementation-requirements.py`.

## Exact disposition

| Completed plan | Current authority that survives the move |
|---|---|
| `2026-09-06-customer-operable-event-service.md` | `docs/decisions/0041-customer-operable-event-service.md`, `crates/aster-agent/README.md`, current code/tests |
| `2026-09-07-aster-agent-event-module-boundary.md` | Decision 0041 and `crates/aster-agent/src/event_service.rs` |
| `2026-09-08-linux-event-g2-emission-capacity.md` | Linux Event MVP profile/register, agent configuration reference, current code/tests |
| `2026-09-10-event-operation-ledger-lifecycle.md` | MVP register, requirements status, agent configuration reference, `crates/aster-redb-store/src/event_operation.rs` |
| `2026-09-13-linux-event-mvp-qualification-validator.md` | Current validator specification, runbook, schema, checker, and tests |
| `2026-09-06-linux-event-mvp-evaluation-profile.md` | Current profile, gate register, annex template, and coordination guide |
| `2026-09-08-raspberry-pi-linux-event-mvp-profile-amendment.md` | Current Linux Event MVP profile and register |
| `2026-09-08-d06-systemd-runtime-loader.md` | Credential crate README, MVP runbook, Decision 0041, current code/tests |
| `2026-09-08-d06-initial-systemd-install.md` | Credential crate README, MVP runbook, Decision 0041, current code/tests |
| `2026-09-08-d06-raspberry-pi-provider-v2-adaptation.md` | Current hash-bound provider design, credential crate README, current code/tests |
| `2026-09-08-d06-complete-systemd-provider-lifecycle.md` | Credential crate README, MVP runbook, Decision 0041, current code/tests |
| `2026-09-14-remove-documentation-archive-tooling.md` | Approved documentation-refactor design and commits `b11b3af`, `ee8b74c`, `90bb7cd` |

---

### Task 1: Archive completed Event-service and validation plans

**Files:**

- Move: `docs/superpowers/plans/2026-09-06-customer-operable-event-service.md` → `archive/design-history/plans/2026-09-06-customer-operable-event-service.md`
- Move: `docs/superpowers/plans/2026-09-07-aster-agent-event-module-boundary.md` → `archive/design-history/plans/2026-09-07-aster-agent-event-module-boundary.md`
- Move: `docs/superpowers/plans/2026-09-08-linux-event-g2-emission-capacity.md` → `archive/design-history/plans/2026-09-08-linux-event-g2-emission-capacity.md`
- Move: `docs/superpowers/plans/2026-09-10-event-operation-ledger-lifecycle.md` → `archive/design-history/plans/2026-09-10-event-operation-ledger-lifecycle.md`
- Move: `docs/superpowers/plans/2026-09-13-linux-event-mvp-qualification-validator.md` → `archive/design-history/plans/2026-09-13-linux-event-mvp-qualification-validator.md`

**Interfaces:**

- Consumes: current Event-service, operation-ledger, and qualification authorities listed in the disposition table
- Produces: five historical plans under `archive/design-history/plans/` with no current inbound consumer

- [ ] **Step 1: Verify there are no current consumers of plan paths**

Run:

```bash
rg -n "docs/superpowers/plans/" --glob '!docs/superpowers/plans/**' --glob '!archive/**' .
```

Expected: no output and exit status `1`.

- [ ] **Step 2: Create the archive plans directory**

Run:

```bash
mkdir -p archive/design-history/plans
```

Expected: exit status `0`.

- [ ] **Step 3: Move the five plans byte-for-byte**

Run each command:

```bash
git mv docs/superpowers/plans/2026-09-06-customer-operable-event-service.md archive/design-history/plans/2026-09-06-customer-operable-event-service.md
git mv docs/superpowers/plans/2026-09-07-aster-agent-event-module-boundary.md archive/design-history/plans/2026-09-07-aster-agent-event-module-boundary.md
git mv docs/superpowers/plans/2026-09-08-linux-event-g2-emission-capacity.md archive/design-history/plans/2026-09-08-linux-event-g2-emission-capacity.md
git mv docs/superpowers/plans/2026-09-10-event-operation-ledger-lifecycle.md archive/design-history/plans/2026-09-10-event-operation-ledger-lifecycle.md
git mv docs/superpowers/plans/2026-09-13-linux-event-mvp-qualification-validator.md archive/design-history/plans/2026-09-13-linux-event-mvp-qualification-validator.md
```

Expected: all commands exit `0`; `git diff --summary` reports five renames with
`100%` similarity.

- [ ] **Step 4: Verify the moved files are unchanged**

Run:

```bash
git diff --summary
```

Expected: exactly the five Task 1 paths appear as `rename ... (100%)`.

- [ ] **Step 5: Commit the Event-plan archive batch**

```bash
git add docs/superpowers/plans archive/design-history/plans
git commit -m "docs: archive completed Event implementation plans"
```

---

### Task 2: Archive completed MVP profile, credential, and refactor plans

**Files:**

- Move: `docs/superpowers/plans/2026-09-06-linux-event-mvp-evaluation-profile.md` → `archive/design-history/plans/2026-09-06-linux-event-mvp-evaluation-profile.md`
- Move: `docs/superpowers/plans/2026-09-08-raspberry-pi-linux-event-mvp-profile-amendment.md` → `archive/design-history/plans/2026-09-08-raspberry-pi-linux-event-mvp-profile-amendment.md`
- Move: `docs/superpowers/plans/2026-09-08-d06-systemd-runtime-loader.md` → `archive/design-history/plans/2026-09-08-d06-systemd-runtime-loader.md`
- Move: `docs/superpowers/plans/2026-09-08-d06-initial-systemd-install.md` → `archive/design-history/plans/2026-09-08-d06-initial-systemd-install.md`
- Move: `docs/superpowers/plans/2026-09-08-d06-raspberry-pi-provider-v2-adaptation.md` → `archive/design-history/plans/2026-09-08-d06-raspberry-pi-provider-v2-adaptation.md`
- Move: `docs/superpowers/plans/2026-09-08-d06-complete-systemd-provider-lifecycle.md` → `archive/design-history/plans/2026-09-08-d06-complete-systemd-provider-lifecycle.md`
- Move: `docs/superpowers/plans/2026-09-14-remove-documentation-archive-tooling.md` → `archive/design-history/plans/2026-09-14-remove-documentation-archive-tooling.md`
- Modify: `docs/superpowers/specs/2026-09-06-linux-event-mvp-evaluation-profile-design.md`

**Interfaces:**

- Consumes: the archive plans directory created by Task 1 and the current MVP/credential authorities in the disposition table
- Produces: seven more historical plans in the same passive archive and a retained specification that points to current authority rather than archived process history

- [ ] **Step 1: Confirm the seven source files and Task 1 archive directory exist**

Run:

```bash
find docs/superpowers/plans archive/design-history/plans -maxdepth 1 -type f -name '*.md' -print
```

Expected: all seven Task 2 sources and all five Task 1 destinations are listed.

- [ ] **Step 2: Move the seven plans byte-for-byte**

Run each command:

```bash
git mv docs/superpowers/plans/2026-09-06-linux-event-mvp-evaluation-profile.md archive/design-history/plans/2026-09-06-linux-event-mvp-evaluation-profile.md
git mv docs/superpowers/plans/2026-09-08-raspberry-pi-linux-event-mvp-profile-amendment.md archive/design-history/plans/2026-09-08-raspberry-pi-linux-event-mvp-profile-amendment.md
git mv docs/superpowers/plans/2026-09-08-d06-systemd-runtime-loader.md archive/design-history/plans/2026-09-08-d06-systemd-runtime-loader.md
git mv docs/superpowers/plans/2026-09-08-d06-initial-systemd-install.md archive/design-history/plans/2026-09-08-d06-initial-systemd-install.md
git mv docs/superpowers/plans/2026-09-08-d06-raspberry-pi-provider-v2-adaptation.md archive/design-history/plans/2026-09-08-d06-raspberry-pi-provider-v2-adaptation.md
git mv docs/superpowers/plans/2026-09-08-d06-complete-systemd-provider-lifecycle.md archive/design-history/plans/2026-09-08-d06-complete-systemd-provider-lifecycle.md
git mv docs/superpowers/plans/2026-09-14-remove-documentation-archive-tooling.md archive/design-history/plans/2026-09-14-remove-documentation-archive-tooling.md
```

Expected: all commands exit `0`; no archived file content is edited.

- [ ] **Step 3: Replace the retained specification's historical-plan link**

Use `apply_patch` in
`docs/superpowers/specs/2026-09-06-linux-event-mvp-evaluation-profile-design.md`
to replace:

```markdown
**Implementation plan:**
[`2026-09-06-linux-event-mvp-evaluation-profile.md`](../plans/2026-09-06-linux-event-mvp-evaluation-profile.md)
```

with:

```markdown
**Current profile authority:**
[`docs/implementation/linux-event-mvp-evaluation-profile-v0.1.md`](../../implementation/linux-event-mvp-evaluation-profile-v0.1.md)
```

- [ ] **Step 4: Verify the second rename batch and current authority link**

Run:

```bash
git diff --summary HEAD
```

Expected: exactly the seven Task 2 paths appear as `rename ... (100%)`.

Run:

```bash
git diff --name-status HEAD
```

Expected: seven `R100` paths and one `M` entry for the retained specification.

Run:

```bash
rg -n "Current profile authority|\.\./plans/" docs/superpowers/specs/2026-09-06-linux-event-mvp-evaluation-profile-design.md
```

Expected: one `Current profile authority` match and no `../plans/` match.

- [ ] **Step 5: Commit the remaining completed-plan archive batch**

```bash
git add docs/superpowers/plans archive/design-history/plans docs/superpowers/specs/2026-09-06-linux-event-mvp-evaluation-profile-design.md
git commit -m "docs: archive completed MVP and credential plans"
```

---

### Task 3: Verify the current/archive boundary

**Files:**

- Verify: `docs/superpowers/plans/2026-09-14-archive-completed-implementation-plans.md`
- Verify: `archive/design-history/plans/*.md`
- Verify: current product authority files named in the disposition table

**Interfaces:**

- Consumes: both rename batches
- Produces: lightweight evidence that current docs retain one active plan and the archive contains twelve historical plans without changing traceability

- [ ] **Step 1: Verify only this active plan remains current**

Run:

```bash
find docs/superpowers/plans -maxdepth 1 -type f -name '*.md' -print
```

Expected output:

```text
docs/superpowers/plans/2026-09-14-archive-completed-implementation-plans.md
```

- [ ] **Step 2: Verify all twelve completed plans are archived**

Run:

```bash
find archive/design-history/plans -maxdepth 1 -type f -name '*.md' -print
```

Expected: the twelve destination paths from Tasks 1 and 2, and no other file.

- [ ] **Step 3: Verify current surfaces do not depend on archived plan paths**

Run:

```bash
rg -n "docs/superpowers/plans/" --glob '!docs/superpowers/plans/2026-09-14-archive-completed-implementation-plans.md' --glob '!archive/**' .
```

Expected: no output and exit status `1`.

Run:

```bash
rg -n "\.\./plans/" docs/superpowers/specs
```

Expected: no output and exit status `1`.

- [ ] **Step 4: Verify every move remained a pure rename**

Run:

```bash
git diff --summary 90bb7cd..HEAD
```

Expected: twelve `rename ... (100%)` lines and this active plan's create-mode
line; no historical plan has content changes.

Run:

```bash
git diff --name-status 90bb7cd..HEAD
```

Expected: twelve `R100` paths, one `A` entry for this active plan, and one `M`
entry for the retained evaluation-profile specification.

- [ ] **Step 5: Check patch hygiene**

Run:

```bash
git diff --check origin/main...HEAD
```

Expected: no output and exit status `0`.

- [ ] **Step 6: Verify requirements traceability**

Run:

```bash
python3 tools/check-implementation-requirements.py
```

Expected: exit status `0`, including:

```text
requirements trace valid: 348 matrix IDs, 137 exact selected mappings
```

- [ ] **Step 7: Review the draft PR scope**

Run:

```bash
git diff --stat origin/main...HEAD
```

Expected: product code, requirements mappings, current specifications, and
validation evidence are unchanged. The diff contains the passive archive,
approved documentation-refactor design, active plan, and twelve completed-plan
renames.

Record in the PR description that this increment archives completed plans only;
specification consolidation and broader docs classification remain follow-up
work on the same draft branch.
