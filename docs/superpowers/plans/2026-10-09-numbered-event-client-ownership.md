# Increment 2: numbered Event client ownership

Clean Room — Privileged

Stack: `feature/numbered-event-client-ownership` is rebased onto `main` at
`fa3c01022b526e06ea5c3372f02793155d5bf185`, the merge of PR #112, on
2026-10-20. The first rebase onto the PR #57 merge at
`964356683206ee4072a260902e1f258f6524bbb2` is retained in the validation history
below. Its original parent was `feature/numbered-publication-switchover` at
`ce0ffeeb29b035007d193d4ac123efdad386a642`. The rebase replays only Increment 2,
preserving main's publication, Blob lifecycle/agent/CLI, dependency and CI work.
Increment 3 remains on its original stack for a separate rebase. This branch
does not start from `main-old` or the old docs-only ownership branch.

Outcome: complete persistent Event subscription/delivery ownership using the
stable numbered publication client and recovered incarnation. Planning aligns
with the roadmap's **Causal correctness and bounded data lifecycle** action.
The alpha/local Event profile advances by one coherent capability increment;
no retained physical evidence or atomic requirement status is promoted.

Implementation:

- Typed required context and mandatory version-2 owner encoding; transactional
  validation for create, delete, poll commit and delivery acknowledgement.
- Stable client-scoped subscription keys and takeover-preserved delivery state.
- Bounded read-only client status and owner IDs in subscription listing.
- Native, Connect, Rust SDK, Go, CLI, examples and acceptance-tool migration.
- Buffered-stream/session fencing with existing TTL, shutdown and backoff rules.
- Startup refusal for incompatible ownership state without modifying its bytes.
- Preserve publication/frontier compaction and pipelined publication behavior.

Exit criteria: focused ownership/recovery/race/restart/stream tests pass;
`mise run check` and `mise run fuzz-smoke` pass; documentation names the breaking
alpha boundary, bounded resources and remaining Increment 3 work. Exact
requirement IDs and historical receipts stay unchanged. See
[the decision](../../decisions/0045-numbered-event-client-ownership.md) for the
contracts and evidence boundary.

Local validation (macOS, 2026-10-09):

- `mise run check`: passed, including 1,761 Rust workspace tests, doctests,
  real-process mesh/hello/Go client checks, generated bindings and conformance.
  Two platform-specific workspace tests were skipped.
- `mise run fuzz-smoke`: passed; two Linux-only systemd targets were skipped.
- `live_event_acceptance`: passed through forced process termination,
  recovered redelivery, acknowledgement and final peerless reopening.
- Requirements validation: 348 baseline IDs and 140 exact mappings unchanged.

These are local validation results, not new physical acceptance receipts.
Physical target acceptance, lost-journal recovery, administrative client
retirement and atomic selector replacement remain outside this branch.

PR #57 rebase validation (macOS, 2026-10-20):

- `mise run check`: passed, including strict workspace Clippy, all 2,195
  workspace tests (two platform skips), doctests, real mesh/hello/numbered-Go
  recovery scenarios, bindings, independent conformance and 203 lab tests.
  Compose path-policy tests require the canonical `/private/var/folders/...`
  temporary directory rather than its `/var/folders/...` symlink.
- `mise run fuzz-smoke`: all seven macOS-supported targets passed 10,000 runs
  each; the two Linux-only systemd targets were skipped.
- `live_event_acceptance`: passed, including forced receiver termination,
  recovered redelivery, acknowledgement and final peerless reopening.
- `tools/test-asterctl-real.py`: passed against the real test-only agent, with
  the existing CLI listing format and journal-owned subscription mutations.
- Requirements validation: 348 baseline IDs and 140 exact mappings unchanged.

The rebase regenerates the combined descriptor and Go clients, preserves main's
Blob test helpers and capability boundary, and migrates the newer operator guide
and CLI smoke to the required journal context. Historical validation above is
preserved; these results add no physical, Linux qualification or production
authorization claim.

PR #112 rebase validation (macOS, 2026-10-20):

- `mise run check`: passed, including strict workspace Clippy, all 2,282
  workspace tests (eight skipped), doctests, real mesh/hello/numbered-Go recovery
  scenarios, bindings, independent conformance, lab tests and generated-client
  reproducibility.
- Requirements validation: 348 baseline IDs and 140 exact mappings unchanged.
- The CLI test-helper conflict retains PR #112's explicit timeout configuration
  and Increment 2's durable client journal. The remaining ownership changes
  apply to the refactored runtime without manual production-code changes.
- No new parser, framing, envelope or fragmentation changes were introduced by
  this rebase. Fuzz smoke was not repeated; the earlier seven-target run remains
  historical validation on the PR #57 base.

These results retain the same local macOS claim boundary. Ignored qualification
scenarios and Linux-specific checks are not claimed as newly executed.
