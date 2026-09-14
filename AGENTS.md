# Aster repository instructions

## Required repository protocol

- Before doing any work, read and follow `CONTRIBUTING.md`.
- If that file is missing or unreadable, stop and ask the user before
  proceeding.

## Planning and requirements

Read these before selecting implementation work:

1. `docs/validation/capability-roadmap.md`
2. `docs/implementation/requirements-status.md`
3. `README.md#current-implementation-boundary`
4. `data-mesh-requirements.md`
5. `.github/pull_request_template.md`

Use the capability roadmap as the planning and PR-review view.

- Do not treat the 348 atomic requirements as a flat backlog, estimate,
  completion percentage, or a requirement that one PR complete an entire
  capability.
- Preserve the hash-bound requirements baseline and historical evidence.
- Prefer coherent, demonstrable capability increments over isolated
  mechanisms.
- Keep implementation and evidence claims no broader than the code, tests,
  environment, and retained receipts support.
- Update exact requirement IDs only when their implementation or evidence
  boundary genuinely changes.
- Future, provisional, stakeholder, and external-gate rows do not automatically
  block unrelated incremental merges.

## Workspace discipline

- Inspect repository status and active work before editing.
- Use an isolated worktree when the current workspace is dirty or another
  effort is active.
- Preserve unrelated user changes.
- Inspect open PRs and relevant active branches before starting substantial
  work to avoid duplication.
- Keep each PR focused on one capability outcome or one clearly bounded
  maintenance concern.

## Verification

- Run `python3 tools/check-implementation-requirements.py` whenever requirements
  evidence or traceability changes.
- Run focused regression and failure-path tests appropriate to the change.
- Run `mise run check` before handing off a substantive code change.
- Run `mise run fuzz-smoke` when changing parsers, framing, envelopes,
  fragmentation, or related hostile-input boundaries.
- Use `.github/pull_request_template.md` when preparing a PR.
