# Archive Completed Design Specifications Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove completed design narratives from current product documentation while keeping current protocol, profile, decision, configuration, and hash-bound qualification authorities intact.

**Architecture:** Move five completed specifications byte-for-byte into `archive/design-history/specs/`. Rewrite current inbound links so engineers land on current authorities, retain historical SHA-256 bindings where qualification records still need them, and archive the completed implementation-plan cleanup plan. Keep the active documentation-refactor design and the two current hash-bound systemd specifications under `docs/`.

**Tech Stack:** Markdown, Git, ripgrep, existing requirements checker

**Spec:** `docs/superpowers/specs/2026-09-14-documentation-refactor-design.md`

## Constraints

- Follow `CONTRIBUTING.md`; this remains ``.
- Do not change protocol behavior, implementation claims, requirement mappings, or evidence status.
- Do not add archive navigation, redirects, inventories, manifests, checkers, or tests.
- Preserve archived specification bytes and their SHA-256 identities.
- Do not archive the current Raspberry Pi systemd provider v2 design, its systemd 257 presentation amendment, or the active documentation-refactor design.
- Do not run builds or full test suites locally. Use only lightweight Git/text checks and `python3 tools/check-implementation-requirements.py`; draft PR CI owns the full suite.

## Exact disposition

| Completed specification | Current authority that replaces it |
|---|---|
| `2026-09-05-customer-operable-event-service-design.md` | Decision 0041, `crates/aster-agent/README.md`, current code/tests |
| `2026-09-06-linux-event-mvp-evaluation-profile-design.md` | Linux Event MVP profile, Decision 0042, register, coordination guide |
| `2026-09-07-systemd-credential-provider-design.md` | Current Raspberry Pi provider v2 design and credential crate documentation; historical hash remains in v2 |
| `2026-09-08-raspberry-pi-linux-event-mvp-profile-amendment-design.md` | Current Linux Event MVP profile and Decision 0042; historical hash remains in provider v2 |
| `2026-09-10-event-operation-ledger-lifecycle-design.md` | Current profile operation-ledger section, agent configuration reference, current code/tests |

## Tasks

### 1. Replace current links to completed designs

- Update Decision 0041 to reference the current agent operational contract instead of its completed design.
- Make the Linux Event MVP profile identify itself and Decision 0042 as current authority, without links to historical design records.
- Make Decision 0042 state that the accepted amendments are incorporated into the current profile.
- Remove the historical-design row from the human-focused coordination guide.
- Make register row `P0-1-D08` link to the current profile operation-ledger boundary.
- Make the current provider v2 design link to the current profile for the incorporated Raspberry Pi boundary and retain predecessor hashes without linking into the archive.

### 2. Archive the five completed specifications

Create `archive/design-history/specs/` and move the five files in the disposition table there with `git mv`. Verify their pre- and post-move SHA-256 values match.

### 3. Retire the completed plan-archive plan

Move `docs/superpowers/plans/2026-09-14-archive-completed-implementation-plans.md` to `archive/design-history/plans/` with `git mv`. Leave this plan as the only current execution plan.

### 4. Verify the boundary

Run:

```bash
git diff --check
find docs/superpowers/specs -maxdepth 1 -type f -name '*.md' -print
find docs/superpowers/plans -maxdepth 1 -type f -name '*.md' -print
rg -n "customer-operable-event-service-design|linux-event-mvp-evaluation-profile-design|systemd-credential-provider-design|raspberry-pi-linux-event-mvp-profile-amendment-design|event-operation-ledger-lifecycle-design" --glob '!archive/**' --glob '!docs/superpowers/plans/**' .
python3 tools/check-implementation-requirements.py
git status --short
```

Expected:

- only the two current systemd specifications and active documentation-refactor design remain under current specs;
- only this active plan remains under current plans;
- no current document links to any archived design filename;
- archived specifications retain their original SHA-256 values;
- the requirements checker passes without evidence/status changes; and
- all moves are shown as renames, with only the intended live-reference edits.
