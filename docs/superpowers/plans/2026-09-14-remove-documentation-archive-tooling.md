# Remove Documentation Archive Tooling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the archive enforcement system and retain only a simple, human-readable historical archive foundation.

**Architecture:** The archive is passive repository history, not a checked subsystem. This change removes its manifest, checker, checker tests, permanent migration inventory, and `mise` integration while preserving three short notices that distinguish historical material from current product documentation.

**Tech Stack:** Markdown, TOML, Git, existing Python requirements checker

**Spec:** `docs/superpowers/specs/2026-09-14-documentation-refactor-design.md`

## Global Constraints

- Follow `CONTRIBUTING.md` and keep the work ``.
- `docs/` contains only information a human engineer needs for the current product.
- Archived material is non-normative and is not linked from the normal product-documentation path.
- The refactor introduces no custom documentation enforcement framework.
- Preserve `data-mesh-requirements.md`, the 348 atomic requirement IDs, the hash-bound baseline, and required historical evidence.
- Do not change protocol, API, runtime, security, deployment behavior, or requirements claims.
- Use `apply_patch` for every repository file edit or deletion.

---

### Task 1: Reduce the archive to plain historical storage

**Files:**

- Modify: `archive/README.md`
- Modify: `archive/design-history/README.md`
- Modify: `archive/research/README.md`
- Delete: `archive/MANIFEST.sha256`

**Interfaces:**

- Consumes: the archive classification and no-tooling rules in the approved design
- Produces: a passive `archive/` hierarchy with no integrity or workflow contract

- [ ] **Step 1: Confirm the obsolete archive contract is present**

Run:

```bash
rg -n "MANIFEST.sha256|byte-for-byte|immutable|integrity" archive
```

Expected: matches in `archive/README.md` and the manifest file exists.

- [ ] **Step 2: Replace the root archive notice**

Use `apply_patch` so `archive/README.md` contains exactly:

```markdown
# Aster documentation archive

This directory contains non-normative project history. Current Aster behavior
is described by the root `README.md`, `docs/`, code, tests, and
`data-mesh-requirements.md`.

Archived documents may describe behavior or decisions that no longer apply.
They are retained for historical context and are not part of the normal product
documentation path.

- `design-history/` contains completed or superseded plans and designs.
- `research/` contains closed evaluations, proposals, and experiments.
```

- [ ] **Step 3: Simplify the design-history notice**

Use `apply_patch` so `archive/design-history/README.md` contains exactly:

```markdown
# Design history

This directory contains completed or superseded plans and designs. Its content
is historical and does not override current code, tests, or documentation.
```

- [ ] **Step 4: Simplify the research notice**

Use `apply_patch` so `archive/research/README.md` contains exactly:

```markdown
# Research history

This directory contains closed evaluations, proposals, and experiments. Its
content is historical and does not establish current product behavior or
dependency choices.
```

- [ ] **Step 5: Delete the archive manifest**

Use `apply_patch` to delete `archive/MANIFEST.sha256`.

- [ ] **Step 6: Verify the archive has no enforcement contract**

Run:

```bash
rg -n "MANIFEST.sha256|byte-for-byte|immutable|integrity" archive
```

Expected: no output and exit status `1`.

Run:

```bash
find archive -maxdepth 2 -type f -print
```

Expected: only the three archive README files.

- [ ] **Step 7: Commit the passive archive policy**

```bash
git add archive/README.md archive/design-history/README.md archive/research/README.md archive/MANIFEST.sha256
git commit -m "docs: make archive passive historical storage"
```

---

### Task 2: Remove archive-specific tooling and task integration

**Files:**

- Delete: `tools/check-documentation-archive.py`
- Delete: `tools/test-documentation-archive.py`
- Modify: `mise.toml`

**Interfaces:**

- Consumes: the passive archive produced by Task 1
- Produces: the standard project check without archive-specific Python commands or a documentation-archive task

- [ ] **Step 1: Record the obsolete integration points**

Run:

```bash
rg -n "check-documentation-archive|test-documentation-archive|tasks.documentation-archive" mise.toml tools
```

Expected: two commands in `tasks.check`, the `[tasks.documentation-archive]`
table, and both Python files are reported.

- [ ] **Step 2: Delete the checker and its tests**

Use `apply_patch` to delete:

```text
tools/check-documentation-archive.py
tools/test-documentation-archive.py
```

- [ ] **Step 3: Remove archive commands from the standard check**

Use `apply_patch` to delete these two entries from `tasks.check` in
`mise.toml`:

```toml
  "python3 tools/test-documentation-archive.py",
  "python3 tools/check-documentation-archive.py",
```

- [ ] **Step 4: Remove the archive-specific task**

Use `apply_patch` to delete this entire table from `mise.toml`:

```toml
[tasks.documentation-archive]
description = "Verify the frozen documentation archive and candidate inventory"
run = [
  "python3 tools/test-documentation-archive.py",
  "python3 tools/check-documentation-archive.py",
]
```

- [ ] **Step 5: Verify the integration is gone**

Run:

```bash
rg -n "check-documentation-archive|test-documentation-archive|tasks.documentation-archive" mise.toml tools
```

Expected: no output and exit status `1`.

Run:

```bash
mise tasks
```

Expected: task listing succeeds and contains no `documentation-archive` task.

- [ ] **Step 6: Commit the tooling removal**

```bash
git add mise.toml tools/check-documentation-archive.py tools/test-documentation-archive.py
git commit -m "build: remove documentation archive checks"
```

---

### Task 3: Remove obsolete refactor artifacts

**Files:**

- Delete: `docs/implementation/documentation-refactor-inventory.csv`
- Delete: `docs/superpowers/plans/2026-09-14-documentation-archive-foundation.md`

**Interfaces:**

- Consumes: no runtime interface
- Produces: no permanent migration inventory and no active plan for the discarded enforcement design

- [ ] **Step 1: Confirm both obsolete artifacts exist**

Run:

```bash
test -f docs/implementation/documentation-refactor-inventory.csv
```

Expected: exit status `0`.

Run:

```bash
test -f docs/superpowers/plans/2026-09-14-documentation-archive-foundation.md
```

Expected: exit status `0`.

- [ ] **Step 2: Delete the permanent inventory and obsolete plan**

Use `apply_patch` to delete both files. Do not replace the inventory with
another tracked classification file.

- [ ] **Step 3: Verify no active implementation surface references the removed system**

Run:

```bash
rg -n "check-documentation-archive|test-documentation-archive|documentation-refactor-inventory|archive/MANIFEST.sha256" mise.toml tools archive docs/implementation
```

Expected: no output and exit status `1`.

- [ ] **Step 4: Commit the obsolete artifact removal**

```bash
git add docs/implementation/documentation-refactor-inventory.csv docs/superpowers/plans/2026-09-14-documentation-archive-foundation.md
git commit -m "docs: remove obsolete archive refactor artifacts"
```

---

### Task 4: Verify and prepare the focused cleanup PR

**Files:**

- Review: `.github/pull_request_template.md`
- Review: all files changed by Tasks 1–3

**Interfaces:**

- Consumes: the passive archive and cleaned build configuration
- Produces: evidence that the cleanup changes documentation architecture only and preserves requirements traceability

- [ ] **Step 1: Check patch hygiene**

Run:

```bash
git diff --check origin/main...HEAD
```

Expected: no output and exit status `0`.

- [ ] **Step 2: Verify requirements traceability**

Run:

```bash
python3 tools/check-implementation-requirements.py
```

Expected: exit status `0`, including:

```text
requirements trace valid: 348 matrix IDs, 137 exact selected mappings
```

- [ ] **Step 3: Run the repository check**

Run:

```bash
mise run check
```

Expected: exit status `0`. If the known test-runner temporary-directory
permission problem recurs, retain the complete failing output, rerun in a
process with umask `077`, and report both results without attributing the
environmental failure to this documentation change.

- [ ] **Step 4: Review the resulting scope**

Run:

```bash
git diff --stat origin/main...HEAD
```

Expected: the branch contains the approved design, simple archive notices, and
this active plan, but none of the removed manifest, checker, checker tests,
permanent inventory, obsolete plan, or `mise` archive integration.

- [ ] **Step 5: Prepare the PR description**

Use `.github/pull_request_template.md`. State explicitly that:

- archive history is passive and non-normative;
- custom archive tooling was removed because documentation review must remain
  human-friendly;
- no product behavior or requirement evidence changed;
- subsequent document movement and consolidation will use separate focused
  plans and pull requests.
