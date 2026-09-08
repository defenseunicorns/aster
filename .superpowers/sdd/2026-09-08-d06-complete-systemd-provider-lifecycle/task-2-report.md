# Task 2 report — lifecycle generation reconciliation

## Status

Implemented the descriptor-relative generation-slot exchange and the internal,
intent-driven reconciliation engine for the provider lifecycle. This task does
not expose rotate, backup, recover, or destroy methods and does not change the
runtime loader, CLI, documentation, requirements evidence, or qualification
status.

Planned commit: `feat(credentials): reconcile lifecycle generations`.

## Baseline

At accepted Task 1 head `764a927`, the exact focused provider command passed:

```text
$ CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials -- --test-threads=1
test result: ok. 35 passed; 0 failed; 0 ignored
test result: ok. 5 passed; 0 failed; 0 ignored
Doc-tests aster_systemd_credentials: 0 passed; 0 failed
```

## TDD evidence

The first lifecycle tests were added before production implementation. Exact
RED command:

```text
CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials \
  admin::lifecycle::tests -- --test-threads=1
```

Observed primary RED:

```text
error[E0432]: unresolved imports `super::GenerationSlots`,
`super::LifecycleStep`, `super::SlotIdentity`, `super::lifecycle_step`
error: could not compile `aster-systemd-credentials` (lib test)
```

The failure was the intended missing Task 2 transition model. Subsequent
focused RED/GREEN cycles covered:

- missing descriptor-relative exchange and tombstone-stage helpers;
- a completed ledger accepting a corrupted Previous generation;
- the missing real `reconcile_lifecycle` engine;
- missing recovery/destroy continuation and replaced-slot removal;
- the missing intent commit helper and pending-intent selector;
- a completed ledger accepting the same destroyed identity in both retained
  slots;
- a generation with an unexpected extra file being treated as exact; and
- Recover completion being accepted without its new intent-bound recovery
  record.

The final focused lifecycle command passed 14 tests with no failures.

## GREEN and verification evidence

All commands were run from the isolated Task 2 worktree with one Cargo build
job and one test thread where applicable:

```text
$ CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials \
    admin::lifecycle::tests -- --test-threads=1
test result: ok. 14 passed; 0 failed; 35 filtered out

$ CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials \
    -- --test-threads=1
test result: ok. 49 passed; 0 failed
test result: ok. 5 passed; 0 failed
Doc-tests aster_systemd_credentials: 0 passed; 0 failed

$ CARGO_BUILD_JOBS=1 cargo clippy -p aster-systemd-credentials \
    --all-targets -- -D warnings
Finished `dev` profile; exit 0

$ cargo fmt --all -- --check
exit 0

$ git diff --check
exit 0
```

## Implementation

- Added `GenerationSlots`, exact slot identities, and a literal next-step table
  for Rotate, Recover, DestroyActive, and DestroyPrevious.
- Added `renameat_with(..., RenameFlags::EXCHANGE)` operations for staged ↔
  active and staged ↔ previous.
- Added exact `previous` and `tombstone` names. Tombstone generations contain
  only `reference`, a state-bearing `manifest`, and an empty `tombstone` file;
  they reject any ciphertext file or nonzero ciphertext digest.
- Extended the v2 manifest's reserved content byte to distinguish Credential
  and Tombstone while preserving the accepted Task 1 credential encoding.
- Required exact descriptor-relative directory entry sets, manifest/reference
  identity, file security properties, and ciphertext digest before a slot is
  actionable.
- Added intent-revision validation, canonical completed-snapshot validation,
  exact kind-specific completion relations, durable intent/completion helpers,
  and selection of an exact pending intent whose predecessor equals the
  decoded current ledger.
- Kept Recover completion caller-supplied: Task 2 verifies its new operation,
  target, generation, and artifact digest, but does not invent or authenticate
  the Task 4 backup operation.
- Added ordinary-open validation for every retained Active and Previous slot,
  including duplicate destroyed-slot rejection, before any provider operation.
- Synchronized staged files/directories, exchange/rename/delete parent state,
  and the provisioning parent before publishing the completed ledger.
- Added fault points for tombstone sync, active/previous exchange, Previous
  rename, replaced-generation deletion, and provisioning-parent sync while
  retaining the existing intent and completion write boundaries.

## Files

- `crates/aster-systemd-credentials/src/admin/lifecycle.rs` (new)
- `crates/aster-systemd-credentials/src/admin.rs`
- `crates/aster-systemd-credentials/src/admin/files.rs`
- `.superpowers/sdd/2026-09-08-d06-complete-systemd-provider-lifecycle/task-2-report.md`

No requirements-status, traceability, runtime-loader, fuzz, CLI, or
documentation file changed.

## Self-review

- Confirmed the ledger is decoded and its host identity checked before retained
  generation inspection in ordinary admin open; the engine accepts only an
  already-decoded ledger and a separately canonicalized completion snapshot.
- Confirmed malformed, partial, duplicate, unbound, digest-mismatched, and
  extra-file slots return `Rejected` before rename or unlink, with byte-for-byte
  preservation tests.
- Confirmed completed ledgers validate exact Active and Previous identity, not
  directory presence, and reject one destroyed identity duplicated across both
  slots.
- Confirmed recovery only moves the exact retained target generation supplied
  by the caller; the engine has no encryptor, reference generation, selection,
  or rollback path.
- Confirmed source/replaced deletion is allowed only after exact
  intent-derived classification and exact directory-entry validation.
- Confirmed exchange uses the required rustix Linux exchange flag and every
  completion path synchronizes the provisioning parent before the completed
  ledger write.
- Confirmed Task 1 install and runtime-loader tests remain unchanged in
  behavior and pass in the full focused provider suite.
- Mutation check: replacing exchange with sequential rename, ignoring Previous,
  trusting presence/extra files, permitting a duplicate tombstone, dropping
  pre-ledger revision validation, omitting Recover completion binding, or
  adding credential bytes to a tombstone causes a focused test failure.

## Concerns and later-task boundary

- Task 4 must construct and authenticate the completed Recovery snapshot,
  including `backup_operation`, before calling the shared engine. Task 2
  deliberately does not infer that operation from the current intent.
- Tasks 3–5 must connect their public operation methods and fresh-admin intent
  dispatch to these helpers. This task provides the engine and pending-intent
  selection but does not add those public methods or anticipate their receipts.
- A Recover `Replaced` slot is deliberately narrow: its canonical
  manifest/reference and exact entry set must remain bound to the retained
  current generation; only its ciphertext bytes may fail the recorded digest.
  A partial or identity-mismatched active directory is rejected without
  deletion.
- Tests are component-level, one-host filesystem evidence only. They do not
  close E01, E09, G3, G4, physical power-loss/CM4 acceptance, package
  qualification, or production readiness.
- Per controller instruction, no repository-wide check or fuzz-smoke command
  was run.
