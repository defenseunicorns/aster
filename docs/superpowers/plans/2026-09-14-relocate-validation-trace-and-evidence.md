# Relocate Validation Trace and Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put current conformance, requirements traceability, and retained evidence under `docs/validation/` without changing evidence bytes, requirement statuses, or historical receipt claims.

**Architecture:** Move the current conformance document, requirements ledger, atomic trace, and retained evidence directory into the existing validation section. Update current links, trace pointers, and checker constants to the new paths. Preserve every evidence file byte-for-byte and do not rewrite historical source-manifest blocks merely to make old recorded paths look current.

**Tech Stack:** Markdown, CSV, Python path constants, Git, ripgrep, existing requirements checker

**Spec:** `docs/superpowers/specs/2026-09-14-documentation-refactor-design.md`

## Global Constraints

- Follow `CONTRIBUTING.md`; the work remains ``.
- Preserve `data-mesh-requirements.md`, all 348 atomic IDs, mapping count, statuses, and evidence claims.
- Move every file under `docs/validation/evidence/` byte-for-byte; do not edit receipt JSON or historical evidence inputs.
- Update the live atomic trace and checker path constants because they are current repository consumers.
- Historical source-manifest code blocks remain historical. Do not recompute old hashes or represent a docs relocation as a rerun of past validation.
- Add no redirects, symlinks, manifests, archive tooling, link checker, or compatibility copies.
- Do not run builds, Cargo/Rust/Go commands, or Python test suites locally. Draft PR CI is the full-suite path.
- Use only `rg`, `find`, hashes, Git diff/status, and `python3 tools/check-implementation-requirements.py` locally.

---

### Task 1: Move current validation authorities

**Files:**

- Move: `docs/conformance.md` → `docs/validation/conformance.md`
- Move: `docs/validation/requirements-status.md` → `docs/validation/requirements-status.md`
- Move: `docs/implementation/requirements-implementation.csv` → `docs/validation/requirements-implementation.csv`
- Move: `docs/validation/evidence/` → `docs/validation/evidence/`

**Interfaces:**

- Consumes: existing `docs/validation/` navigation and current checker
- Produces: one physical home for current conformance, traceability, and retained evidence

- [ ] Record SHA-256 for every file under `docs/validation/evidence/`.
- [ ] Move the four authorities with `git mv`.
- [ ] Confirm evidence destinations retain the recorded hashes before any other edits.

### Task 2: Update current repository consumers

**Files:**

- Modify: `README.md`, `AGENTS.md`, `.github/pull_request_template.md`
- Modify: current Markdown files linking requirements status, conformance, or retained evidence
- Modify: `docs/index.html`
- Modify: `tools/check-implementation-requirements.py`
- Modify: `docs/validation/requirements-implementation.csv`
- Modify: `docs/validation/requirements-status.md`
- Modify: `docs/validation/conformance.md`

**Interfaces:**

- Consumes: paths produced by Task 1
- Produces: no current consumer of the old conformance, ledger, trace, or evidence locations

- [ ] Replace exact current pointers from `docs/validation/requirements-status.md`, `docs/implementation/requirements-implementation.csv`, `docs/validation/evidence/`, and `docs/conformance.md` to their `docs/validation/` destinations.
- [ ] Update relative Markdown links based on each moved file's new directory.
- [ ] Keep recorded historical manifest hashes and historical source paths unchanged when they describe an earlier run rather than a live consumer.
- [ ] Update checker constants and exact expected trace pointers; do not alter expected statuses or requirement IDs.

### Task 3: Verify traceability and path closure

**Files:**

- Verify: all files changed by Tasks 1 and 2

**Interfaces:**

- Consumes: completed relocation
- Produces: fresh lightweight evidence for the draft PR

- [ ] Run `python3 tools/check-implementation-requirements.py`; require 348 matrix IDs, 137 exact selected mappings, and unchanged status totals.
- [ ] Recompute SHA-256 for every file under `docs/validation/evidence/` and compare it with Task 1.
- [ ] Search for old paths outside archive, evidence files, and explicitly identified historical manifest blocks; resolve every live consumer.
- [ ] Run `git diff --check`, inspect `git diff --summary`, and confirm only intended files changed.
- [ ] Commit the relocation, archive this completed plan byte-for-byte, verify again, and push to `docs-refactor-foundation`.

