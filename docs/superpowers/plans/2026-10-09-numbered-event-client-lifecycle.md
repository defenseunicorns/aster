# Increment 3: numbered Event client loss and lifecycle

Clean Room — Privileged

Branch `refresh/numbered-event-client-lifecycle` is rebased directly onto main
at `4042d3dea802aab950f84f06ad0e740a7ea09343`, which merges Increment 2 in
PR #118. Only Increment 3 is replayed. The pre-rebase tip is preserved at
`backup/iteration3-before-pr118-20261022` (`9b5c5d1`); the original Increment 3
branch remains unchanged at `21fc5a4`.

Outcome: explicit partial Rust SDK/CLI reconstruction after journal loss,
transactional permanent administrative retirement, persistent admission tuning
and offline capacity reporting. This advances the alpha/local Event profile's
P1 causal correctness and bounded data lifecycle action. Exact requirement IDs,
hash-bound baseline and retained receipts remain unchanged.

Exit criteria: focused loss/restart/CAS/rollback/saturation/CLI tests,
`mise run check`, and `mise run fuzz-smoke`; documented irreversible retirement,
result-only reconstruction, bounded resources and unchanged mesh semantics.
See [decision 0046](../../decisions/0046-numbered-event-client-lifecycle.md).

Client-ID reuse and slot reclamation require a separate safety design. Physical
ownership/loss/retirement acceptance remains an external evidence task. The
Rust/CLI reconstruction path does not promise to rebuild other journal formats
or recover application effects.

Local validation (macOS, 2026-10-09):

- `mise run check`: passed, including 1,769 workspace tests, doctests,
  real mesh/hello/Go clients, bindings and conformance; two platform-specific
  workspace tests were skipped.
- Final focused checks: all 29 SDK tests, real-agent loss reconstruction,
  operator CLI/writer exclusion, binary-ID parsing, permanent retirement,
  rollback, lowered/global quota rejection and partial-configuration refusal.
  Final workspace Clippy and formatting checks passed.
- `mise run fuzz-smoke`: passed; two Linux-only systemd targets were skipped.
- Requirements checker: 348 baseline IDs and 140 exact mappings unchanged.

These are local current-code results, not retained physical acceptance evidence.

Rebase validation (macOS, 2026-10-20):

- `mise run check`: passed, including strict workspace Clippy, all 2,294
  workspace tests (eight skipped), doctests, real mesh/hello/numbered-Go recovery,
  bindings, independent conformance, 203 lab tests and generated-client
  reproducibility. Requirements validation retains 348 baseline IDs and 140
  exact mappings.
- `mise run fuzz-smoke`: all seven macOS-supported targets passed 10,000 runs
  each; the two Linux-only systemd targets were skipped.
- Focused regressions passed for real-agent journal-loss reconstruction, lost
  claim replies, retirement rollback/permanent fences, offline operator limits
  and writer exclusion, and reconstruction at eight retained receipts versus
  transactional refusal at nine without partial rows or recovery completion.

The combined schema descriptor and Go client were regenerated. The rebase
preserves the current Blob CLI and lifecycle behavior, SDK journal limits and
initialization durability, and the current capability/evidence boundaries. The
new reconstruction capacity regression and documentation make the inherited
eight-entry/1 MiB logical journal budget explicit. Prior validation above remains
historical. No new physical, Linux qualification or production authorization
is claimed.

Rebase validation (macOS, 2026-10-22, after PR #118):

- Replayed only Increment 3 onto main `4042d3d`. Preserved the merged read-only
  status API: absent sessions remain optional, `Unregistered` keeps protocol
  value 4, and `Retired` uses value 5. Reconstruction observes the issued session
  without claiming ownership through the status call. Regenerated the combined
  descriptor and Go client.
- All 75 focused SDK, real-agent reconstruction, store ownership/retirement,
  capacity and offline CLI regressions passed. Refusal covers unregistered,
  retired and missing/zero-session responses; retired status remains permanent
  with absent, current or stale observed sessions.
- `mise run check-clippy`, `mise run check-workspace-tests` (2,272 passed,
  eight skipped, plus doctests), and `mise run check-integration` passed,
  including generated-client reproducibility.
- `mise run fuzz-smoke`: seven supported targets passed 10,000 runs each;
  two Linux-only systemd targets were skipped.
- `mise run check` was attempted. Its foundation phase stops at the existing
  16 failures in `tools/test_aster_path_diagnostic.py` because macOS lacks
  `/proc/self/ns/net`. Both diagnostic files are identical to main; no complete
  gate pass is claimed. Requirements validation passed before that failure:
  348 baseline IDs and 140 exact mappings, with no evidence-boundary changes.
- Formatting and whitespace checks passed. No new physical, Linux qualification
  or production authorization is claimed; earlier results remain historical.
