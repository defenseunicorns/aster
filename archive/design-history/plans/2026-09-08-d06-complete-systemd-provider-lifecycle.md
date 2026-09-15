# D06 complete systemd provider lifecycle implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the Raspberry Pi systemd credential provider v2 lifecycle
on draft PR #4 so the packaged administration surface can install, load,
rotate, back up, recover, revoke/rekey through composition, and logically
destroy provisioning material without plaintext disclosure.

**Architecture:** Preserve the statically composed runtime loader and extend
the root-only administration lane around one canonical bounded lifecycle
ledger. Mutations use an intent, synchronized generation directories, and a
completed ledger snapshot; rotation and destruction use Linux atomic directory
exchange, while backup/recovery use a host-bound ciphertext artifact that is
accepted only when it matches the intact current ledger. Bearer rotation stays
in the Event agent, and revoke/rekey composes the existing mission-authority
workflow with provider rotation on retained nodes and provider destruction on
the removed node.

**Tech Stack:** Rust 2024, `rustix`, `sha2`, `zeroize`, existing Aster
provisioning contracts, systemd `257.13-1~deb13u1`, `/usr/bin/systemd-creds`,
ext4, native `arm64` package.

**Spec:**
`docs/superpowers/specs/2026-09-08-raspberry-pi-systemd-credential-provider-v2-design.md`

## Global constraints

- Provider contract is exactly `aster-systemd-credential-store/v2` on the
  exact Raspberry Pi reference 2026-06-18 / Debian 13 / CM4 Rev 1.1 / aarch64 /
  kernel `6.18.39+rpt-rpi-v8` / systemd `257.13-1~deb13u1` / ext4 profile.
- `/usr/bin/systemd-creds encrypt --with-key=host
  --name=aster-provisioning.bundle - -` remains the only plaintext-to-
  ciphertext provider call. The admin must never invoke provider decrypt.
- No age, plaintext-file, TPM2, alternate-provider, generic Debian, v1
  fallback, automatic rollback, or physical-erasure behavior is added.
- Plaintext enters install and rotation only through standard input, remains
  bounded and zeroizing, and never enters arguments, environment, logs,
  ordinary files, backup artifacts, or retained receipts.
- The host-key identity is a root-only SHA-256 commitment computed from the
  fixed systemd host-key file in zeroizing memory. Neither the key nor its
  commitment is emitted by the CLI.
- The lifecycle ledger is bounded by a fixed maximum encoded byte length.
  Counts are decoded only after checked length arithmetic; exhaustion fails
  closed without discarding history.
- An operation identifier remains permanently bound within the retained
  ledger. Exact retries reproduce the original disposition while the bound
  reference remains live; a later exact tombstone returns `Destroyed`.
  Changed inputs always return `OperationConflict`.
- An unknown reference remains indeterminate `NotFound`. Only a committed
  exact tombstone returns `Destroyed` or `AlreadyDestroyed`.
- `active`, `previous`, and `staged` are same-filesystem sibling directories.
  At most one previous generation may await post-readiness destruction; a new
  rotation is rejected until it is destroyed.
- Recovery is same-host and current-generation only. It rejects host-key
  identity mismatch, missing ledger, artifact mismatch, retired/destroyed
  references, and generation rollback.
- Component tests do not close E01, E09, G3, G4, or customer/production
  readiness. The full `mise run check` remains a final release-gate activity,
  not a per-task command.

---

### Task 1: Replace the install-only record with a canonical lifecycle ledger

**Files:**
- Modify: `crates/aster-systemd-credentials/src/admin/ledger.rs`
- Modify: `crates/aster-systemd-credentials/src/admin/files.rs`
- Modify: `crates/aster-systemd-credentials/src/admin.rs`
- Modify: `fuzz/fuzz_targets/systemd_admin_record_decode.rs`

**Interfaces:**
- Consumes: existing `ProvisioningInstallId`, `ProvisioningLoadId`,
  `ProvisioningDestroyId`, `ProvisioningSecretRef`, provider generation and
  canonical reference codecs.
- Produces: `ProviderLedger`, `GenerationRecord`, `GenerationState`,
  `LifecycleIntent`, `LifecycleIntentKind`, `BackupBinding`, `RecoveryBinding`,
  `DestroyBinding`, `DestroyBindingOutcome`, `encode_ledger`, `decode_ledger`,
  and `MAX_LEDGER_BYTES` for all later tasks.

- [ ] **Step 1: Write failing canonical-ledger tests**

  Replace install-only codec expectations with literal v2 lifecycle fixtures.
  The tests must assert round-trip preservation of:

  ```rust
  ProviderLedger {
      host_key_identity: [0xa0; 32],
      intent: None,
      generations: vec![GenerationRecord {
          install: ProvisioningInstallId::new([0x11; 32]),
          load: ProvisioningLoadId::new([0x22; 32]),
          secret_ref: provisioning_secret_ref(2, [0x33; 32]).unwrap(),
          generation: 2,
          envelope_commitment: [0x44; 32],
          ciphertext_digest: [0x55; 32],
          state: GenerationState::Active,
      }],
      backups: vec![],
      recoveries: vec![],
      destroys: vec![],
  }
  ```

  Add literal rejection cases for the current install-only v2 encoding,
  extension bytes, duplicate operation IDs, duplicate references, two active
  generations, more than one previous generation, cross-generation
  references, a tombstone with ciphertext metadata, invalid enum values,
  overflowed counts, and encoded input above `MAX_LEDGER_BYTES`.

- [ ] **Step 2: Run the ledger tests and observe RED**

  Run:

  ```bash
  CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials \
    admin::ledger::tests -- --test-threads=1
  ```

  Expected: compilation fails because the lifecycle-ledger types and codec do
  not exist.

- [ ] **Step 3: Implement the bounded ledger types and codec**

  Use one canonical binary snapshot with existing magic `ASTRSDL1`, explicit
  version `2`, checked fixed-width counts, and length-prefixed canonical
  references. Keep `Vec` allocation bounded by `MAX_LEDGER_BYTES`; validate
  global uniqueness and state invariants after decoding. Use these exact
  top-level shapes:

  ```rust
  pub(super) struct ProviderLedger {
      pub(super) host_key_identity: [u8; 32],
      pub(super) intent: Option<LifecycleIntent>,
      pub(super) generations: Vec<GenerationRecord>,
      pub(super) backups: Vec<BackupBinding>,
      pub(super) recoveries: Vec<RecoveryBinding>,
      pub(super) destroys: Vec<DestroyBinding>,
  }

  pub(super) enum GenerationState {
      Active,
      Previous,
      Destroyed,
  }

  pub(super) enum LifecycleIntentKind {
      Install,
      Rotate,
      Recover,
      DestroyActive,
      DestroyPrevious,
  }
  ```

  `LifecycleIntent` must bind kind, operation bytes, target reference and
  generation, source reference when applicable, expected ciphertext/artifact
  digests, and the exact pre-mutation ledger revision. Completed records must
  retain all information needed for exact retry or conflict classification.

- [ ] **Step 4: Add fixed host-key identity loading**

  Add a descriptor-relative/no-follow bounded reader for the fixed production
  path `/var/lib/systemd/credential.secret`. Validate a root-owned,
  single-link, non-group/world-accessible regular file, hash it while held in
  `Zeroizing<Vec<u8>>`, and retain only `[u8; 32]`. Extend test construction to
  inject a fixture host-key path. Opening an existing ledger with another
  identity returns `Rejected`; missing/unreadable key returns `Unavailable`.

- [ ] **Step 5: Make current generation-one install use the new ledger**

  Preserve the current staging/intent/promotion/completion order. Initial
  install produces one Active generation and no lifecycle history. Existing
  install-only v2 bytes are deliberately rejected because PR #4 is still
  draft and provider v2 has not shipped.

- [ ] **Step 6: Extend the admin fuzz target and run GREEN**

  Make `systemd_admin_record_decode` first assert that its literal lifecycle
  ledger and manifest fixtures pass the intended production decoders, then
  mutate them. Run the focused ledger tests and:

  ```bash
  CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials \
    -- --test-threads=1
  CARGO_BUILD_JOBS=1 cargo clippy -p aster-systemd-credentials \
    --all-targets -- -D warnings
  ```

- [ ] **Step 7: Commit**

  ```bash
  git add crates/aster-systemd-credentials/src/admin.rs \
    crates/aster-systemd-credentials/src/admin/files.rs \
    crates/aster-systemd-credentials/src/admin/ledger.rs \
    fuzz/fuzz_targets/systemd_admin_record_decode.rs
  git commit -m "feat(credentials): add provider lifecycle ledger"
  ```

---

### Task 2: Add atomic generation exchange and general reconciliation

**Files:**
- Create: `crates/aster-systemd-credentials/src/admin/lifecycle.rs`
- Modify: `crates/aster-systemd-credentials/src/admin.rs`
- Modify: `crates/aster-systemd-credentials/src/admin/files.rs`
- Test: `crates/aster-systemd-credentials/src/admin/lifecycle.rs`

**Interfaces:**
- Consumes: Task 1 ledger snapshot and intent types; existing manifest,
  staging, directory-sync, and fault-injection helpers.
- Produces: `GenerationSlots`, `reconcile_lifecycle`,
  `exchange_staged_with_active`, `exchange_staged_with_previous`, and shared
  prepare/commit helpers used by rotation, recovery, and destruction.

- [ ] **Step 1: Write RED reconciliation tables**

  Add literal table tests for each allowed intent/filesystem combination:

  ```text
  Rotate: old active + new staged -> exchange
  Rotate: new active + old staged -> park old as previous
  Rotate: new active + old previous -> complete
  Recover: missing/corrupt active + exact staged -> promote/exchange
  Recover: exact active + discarded replaced slot -> complete
  DestroyActive: tombstone staged + exact active -> exchange, remove old
  DestroyPrevious: tombstone staged + exact previous -> exchange, remove old
  ```

  Every mismatched, partial, duplicate, or unbound slot must return `Rejected`
  without deletion. Add a test proving ordinary open with a completed ledger
  validates every retained Active/Previous slot and never treats presence alone
  as identity.

- [ ] **Step 2: Run the focused tests and observe RED**

  ```bash
  CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials \
    admin::lifecycle::tests -- --test-threads=1
  ```

- [ ] **Step 3: Implement descriptor-relative generation operations**

  Use `rustix::fs::renameat_with(..., RenameFlags::EXCHANGE)` for exchanges.
  Add exact constants `PREVIOUS_DIRECTORY` and `TOMBSTONE_FILE`. A tombstone
  generation contains only the canonical reference, a state-bearing manifest,
  and the tombstone; it contains no `credential.cred`. Synchronize all files,
  each generation directory, and the provisioning parent before ledger
  completion.

- [ ] **Step 4: Implement intent-driven reconciliation**

  Decode the ledger before inspecting slots. Reconcile only an exact state
  derived from intent bindings and manifest/digest matches. Complete recovery
  in the same order as the interrupted operation; never regenerate
  ciphertext, select a newer reference, or silently restore the old active
  generation.

- [ ] **Step 5: Add fault points at every new durability boundary**

  Cover staged tombstone sync, exchange, previous rename, replaced-generation
  deletion, provisioning-parent sync, intent sync, and completion sync. For
  every point, interrupt the real operation, reopen a fresh admin, and assert
  one complete pre- or post-operation state with the exact ledger phase.

- [ ] **Step 6: Run GREEN and commit**

  ```bash
  CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials \
    admin::lifecycle::tests -- --test-threads=1
  CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials \
    -- --test-threads=1
  git add crates/aster-systemd-credentials/src/admin.rs \
    crates/aster-systemd-credentials/src/admin/files.rs \
    crates/aster-systemd-credentials/src/admin/lifecycle.rs
  git commit -m "feat(credentials): reconcile lifecycle generations"
  ```

---

### Task 3: Implement mission/provider reference rotation

**Files:**
- Modify: `crates/aster-systemd-credentials/src/admin.rs`
- Modify: `crates/aster-systemd-credentials/src/admin/lifecycle.rs`
- Modify: `crates/aster-systemd-credentials/src/admin/ledger.rs`
- Test: `crates/aster-systemd-credentials/src/admin/lifecycle.rs`

**Interfaces:**
- Consumes: Tasks 1-2 ledger and exchange/reconciliation helpers; existing
  encryptor and provider envelope.
- Produces:
  `SystemdCredentialAdmin::rotate(operation, load, plaintext) ->
  Result<ProvisioningInstallReceipt, ProvisioningSecretStoreError>`.

- [ ] **Step 1: Write RED rotation behavior tests**

  Test a real generation-one fixture rotating to generation two. Assert new
  reference/generation/ciphertext are Active; old exact generation is Previous
  and still present for later destruction; exact retry returns `Existing`
  without a second encryption; changed plaintext/load under the same install
  operation conflicts; a second rotation while Previous exists is rejected
  before encryption; v1 or mismatched state never becomes active; and a
  restart after every injected boundary converges to exact old-or-new durable
  state without automatic fallback.

- [ ] **Step 2: Run RED**

  ```bash
  CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials \
    admin::lifecycle::tests::rotation -- --test-threads=1
  ```

- [ ] **Step 3: Implement minimal rotation**

  Validate plaintext before mutation, allocate `generation + 1` with checked
  arithmetic, create the provider envelope and ciphertext once, synchronize
  staged content, commit Rotate intent, exchange staged/active, park the old
  generation as Previous, synchronize the parent, then publish the completed
  ledger. Do not restart the service or destroy Previous inside this method.

- [ ] **Step 4: Run GREEN and commit**

  ```bash
  CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials \
    admin::lifecycle::tests::rotation -- --test-threads=1
  CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials \
    -- --test-threads=1
  git add crates/aster-systemd-credentials/src/admin.rs \
    crates/aster-systemd-credentials/src/admin/lifecycle.rs \
    crates/aster-systemd-credentials/src/admin/ledger.rs
  git commit -m "feat(credentials): rotate provider generation"
  ```

---

### Task 4: Add the host-bound backup artifact and same-host recovery

**Files:**
- Create: `crates/aster-systemd-credentials/src/admin/backup.rs`
- Modify: `crates/aster-systemd-credentials/src/admin.rs`
- Modify: `crates/aster-systemd-credentials/src/admin/files.rs`
- Modify: `crates/aster-systemd-credentials/src/admin/lifecycle.rs`
- Modify: `fuzz/Cargo.toml`
- Create: `fuzz/fuzz_targets/systemd_backup_decode.rs`
- Modify: `tools/run-fuzz-smoke.sh`

**Interfaces:**
- Consumes: exact Active ledger record, host-key identity, generation manifest,
  ciphertext digest, and Task 2 recovery transaction.
- Produces: `BackupOperationId`, `RecoveryOperationId`,
  `ProtectedBackupArtifact`, `BackupReceipt`, `RecoveryReceipt`,
  `RecoveryDisposition::{Restored, Existing}`,
  `MAX_BACKUP_ARTIFACT_BYTES`,
  `SystemdCredentialAdmin::backup`, and
  `SystemdCredentialAdmin::recover`.

- [ ] **Step 1: Write RED backup-codec tests**

  Define literal magic `ASTRSDB1`, explicit version `2`, backup operation,
  host-key identity, generation, load operation, canonical reference,
  manifest digest, ciphertext digest, exact ciphertext length, and ciphertext.
  Assert canonical round trip and reject v1, extension/truncation, length
  overflow, zero generation, reference-generation mismatch, altered manifest,
  altered ciphertext, and input above the protected provisioning bound.

- [ ] **Step 2: Run RED**

  ```bash
  CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials \
    admin::backup::tests -- --test-threads=1
  ```

- [ ] **Step 3: Implement backup binding and output**

  `backup(operation)` reads only the exact Active ciphertext/manifest/reference,
  constructs the canonical artifact in zeroizing memory, commits a binding of
  operation/reference/generation/artifact digest before returning it, and
  returns identical bytes for an exact retry while that generation remains in
  Active or Previous. A tombstoned reference returns `Destroyed`; changed
  bindings conflict. Backup never calls decrypt and never copies the host key.

- [ ] **Step 4: Write RED recovery tests**

  Test restoration after removing Active and after replacing Active with a
  corrupt directory. Assert exact retry returns Existing. Reject wrong host-key
  identity, wrong backup operation, altered artifact/digest, missing ledger,
  older generation, Previous/Destroyed reference, and another active
  generation. Assert failures preserve the current ledger and filesystem.

- [ ] **Step 5: Implement same-host current-generation recovery**

  Bind Recovery intent, recreate the exact recorded generation from the
  artifact without decrypting or re-encrypting, promote/exchange it through
  Task 2 helpers, remove the replaced corrupt directory only after Active is
  durable, and commit the recovery binding/disposition. Require artifact host
  identity and all recorded digests to match the current ledger exactly.

- [ ] **Step 6: Add and run the backup fuzz target**

  The target must first prove an unmutated v2 artifact passes the production
  decoder, then fuzz raw and structured mutations. Run:

  ```bash
  CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials \
    -- --test-threads=1
  cargo +nightly fuzz run systemd_backup_decode -- \
    -runs=10000 -max_len=262144 -seed=2026090803
  ```

  Add the same fixed target, seed, `-runs=10000`, and bounded maximum length to
  `tools/run-fuzz-smoke.sh`; do not replace or weaken an existing target.

- [ ] **Step 7: Commit**

  ```bash
  git add crates/aster-systemd-credentials/src/admin.rs \
    crates/aster-systemd-credentials/src/admin/backup.rs \
    crates/aster-systemd-credentials/src/admin/files.rs \
    crates/aster-systemd-credentials/src/admin/lifecycle.rs \
    fuzz/Cargo.toml fuzz/fuzz_targets/systemd_backup_decode.rs \
    tools/run-fuzz-smoke.sh
  git commit -m "feat(credentials): back up and recover active generation"
  ```

---

### Task 5: Implement durable logical destruction

**Files:**
- Modify: `crates/aster-systemd-credentials/src/admin.rs`
- Modify: `crates/aster-systemd-credentials/src/admin/files.rs`
- Modify: `crates/aster-systemd-credentials/src/admin/lifecycle.rs`
- Modify: `crates/aster-systemd-credentials/src/admin/ledger.rs`

**Interfaces:**
- Consumes: `ProvisioningDestroyId`, `ProvisioningSecretRef`, Task 2 tombstone
  exchange/reconciliation, and Task 1 destroy bindings.
- Produces: `SystemdCredentialAdmin::destroy`, an implementation of
  `ProvisioningSecretDestroyer`, and exact Destroyed/AlreadyDestroyed/NotFound
  behavior.

- [ ] **Step 1: Write RED destruction tests**

  Cover Active destruction and post-rotation Previous destruction. Assert the
  exact target credential disappears before the receipt, the tombstone and
  operation binding survive reopen, exact retry returns `AlreadyDestroyed`, a
  changed reference conflicts, and an unknown reference returns `NotFound`
  while permanently binding that operation to the same result. A later
  install/rotate/load/recover must never resurrect a destroyed reference.

- [ ] **Step 2: Run RED**

  ```bash
  CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials \
    admin::lifecycle::tests::destroy -- --test-threads=1
  ```

- [ ] **Step 3: Implement active and previous destruction**

  Prepare a synchronized tombstone generation, commit the exact destroy
  intent, exchange it with the target slot, synchronize the parent, remove and
  synchronize the exchanged credential directory, then complete the ledger.
  Active destruction retains the tombstone directory at `active` so subsequent
  service activation fails closed. Previous destruction removes the filesystem
  slot after committing the tombstone to the ledger, enabling the next
  rotation.

- [ ] **Step 4: Exercise every destruction crash boundary**

  Interrupt the real active and previous destroy paths before/after tombstone
  sync, intent, exchange, credential removal, parent sync, and completed-ledger
  publication. Reopen and assert exact pre- or post-destroy state; no path may
  return a destruction receipt while the target credential bytes remain in a
  provider generation slot.

- [ ] **Step 5: Run GREEN and commit**

  ```bash
  CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials \
    admin::lifecycle::tests::destroy -- --test-threads=1
  CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials \
    -- --test-threads=1
  git add crates/aster-systemd-credentials/src/admin.rs \
    crates/aster-systemd-credentials/src/admin/files.rs \
    crates/aster-systemd-credentials/src/admin/lifecycle.rs \
    crates/aster-systemd-credentials/src/admin/ledger.rs
  git commit -m "feat(credentials): logically destroy provider references"
  ```

---

### Task 6: Expose the complete root administration CLI

**Files:**
- Modify: `crates/aster-systemd-credentials/src/bin/aster-credential-admin.rs`
- Test: `crates/aster-systemd-credentials/src/bin/aster-credential-admin.rs`

**Interfaces:**
- Consumes: install, rotate, backup, recover, and destroy methods from Tasks
  3-5.
- Produces these exact commands:

  ```text
  install --operation HEX64 --load-operation HEX64 < ASTRPB03
  rotate --operation HEX64 --load-operation HEX64 < ASTRPB03
  backup --operation HEX64 > protected-backup.bin
  recover --operation HEX64 < protected-backup.bin
  destroy --operation HEX64 --reference HEX
  ```

- [ ] **Step 1: Write RED parser and output tests**

  Use a command enum with distinct variants and exact arity/order. Reject
  uppercase/noncanonical IDs, duplicate/unknown/reordered arguments, missing
  stdin, oversized stdin, noncanonical reference hex, and secret path flags.
  Assert normal commands print only uppercase command name, sanitized
  disposition, generation, and explicitly exposed opaque reference where the
  design permits it. `backup` writes only binary artifact bytes to stdout and
  sends one sanitized success line to stderr so redirection cannot corrupt the
  artifact.

- [ ] **Step 2: Run RED**

  ```bash
  CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials \
    --bin aster-credential-admin -- --test-threads=1
  ```

- [ ] **Step 3: Implement the command enum and bounded I/O**

  Keep plaintext `SecretInputBuffer` for install/rotate. Add a separate
  zeroizing bounded protected-artifact input for recover. Destroy reference
  parsing must decode canonical lowercase hex directly into bounded reference
  bytes and never echo it on failure. Do not accept environment or path-based
  secret input.

- [ ] **Step 4: Run GREEN and process-level failure tests**

  Verify invalid commands fail before opening the provider, provider failures
  reveal only the fixed error taxonomy, and binary backup stdout contains no
  status text.

  ```bash
  CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials \
    --bin aster-credential-admin -- --test-threads=1
  CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials \
    -- --test-threads=1
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add crates/aster-systemd-credentials/src/bin/aster-credential-admin.rs
  git commit -m "feat(credentials): expose provider lifecycle commands"
  ```

---

### Task 7: Document the complete seven-operation operator workflow

**Files:**
- Modify: `crates/aster-systemd-credentials/README.md`
- Modify: `docs/decisions/0041-customer-operable-event-service.md`
- Create: `docs/implementation/raspberry-pi-provider-v2-operations.md`

**Interfaces:**
- Consumes: exact CLI behavior from Task 6, existing Event-agent bearer-token
  SIGHUP reload, existing mission authority revocation/rekey behavior, and the
  approved v2 design.
- Produces: one package-facing procedure for install/load, bearer rotation,
  mission/provider rotation, backup/recovery, revoke/rekey, and logical
  destruction.

- [ ] **Step 1: Write the exact stopped-service procedures**

  Document commands, required service state, operation-ID retention, expected
  sanitized outputs, restart/readiness checkpoints, post-rotation destruction
  of Previous, same-host backup limitations, and fail-closed recovery/destroy
  outcomes. Never include sample credential bytes or reusable IDs.

- [ ] **Step 2: Define composition rather than duplicate mechanisms**

  Bearer rotation must reference the existing atomic owner-only token-file
  replacement plus SIGHUP behavior and state that mission/provider material is
  unchanged. Revoke/rekey must reference the existing authority workflow for a
  new roster/key generation, use provider rotation on retained stopped nodes,
  use provider destruction on a removed controlled node, restart retained
  nodes, and verify subsequent authentication rejects the removed credential.

- [ ] **Step 3: State exact non-claims and external gates**

  Keep E01, E09 qualification, hardened unit/package integration, G3, G4,
  cross-host recovery, physical erasure, snapshot rollback, production, and
  general-platform support open. State that code completion makes the lifecycle
  executable but does not qualify it.

- [ ] **Step 4: Run documentation checks and commit**

  ```bash
  python3 tools/check-implementation-requirements.py
  git diff --check
  git add crates/aster-systemd-credentials/README.md \
    docs/decisions/0041-customer-operable-event-service.md \
    docs/implementation/raspberry-pi-provider-v2-operations.md
  git commit -m "docs(credentials): define provider lifecycle operations"
  ```

---

### Task 8: Verify the complete PR #4 lifecycle boundary and update the draft

**Files:**
- Modify only if evidence boundaries genuinely change:
  `docs/implementation/requirements-status.md`
- Modify: draft PR #4 title/body through GitHub after local verification and
  explicit remote-write authorization.

**Interfaces:**
- Consumes: Tasks 1-7 and the existing runtime loader/Event-agent integration.
- Produces: one reviewed draft PR head implementing the complete code-level
  seven-operation lifecycle while retaining all candidate/physical gates.

- [ ] **Step 1: Run focused provider and consumer verification**

  ```bash
  cargo fmt --all -- --check
  CARGO_BUILD_JOBS=1 cargo test -p aster-systemd-credentials \
    -- --test-threads=1
  CARGO_BUILD_JOBS=1 cargo clippy -p aster-systemd-credentials \
    --all-targets -- -D warnings
  CARGO_BUILD_JOBS=1 cargo test -p aster-agent \
    --test customer_runtime -- --test-threads=1
  python3 tools/check-implementation-requirements.py
  git diff --check origin/feature/customer-operable-event-service...HEAD
  ```

- [ ] **Step 2: Run hostile-input verification**

  Run `mise run fuzz-smoke` with the new backup target added to
  `tools/run-fuzz-smoke.sh`. Every target must complete its deterministic
  10,000 runs under the sanitizer-capable runner. A sandbox-only ptrace denial
  is recorded separately and never counted as a pass.

- [ ] **Step 3: Run one whole-branch code review**

  Review the complete stacked diff for canonical decoding, host-key identity
  handling, plaintext boundaries, operation conflict/idempotency, atomic
  ordering, crash reconciliation, current-only recovery, tombstone semantics,
  CLI output, and claim limits. Fix Critical/Important findings with TDD and
  perform one scoped re-review.

- [ ] **Step 4: Push and update draft PR #4**

  Keep base `feature/customer-operable-event-service`, head
  `feature/ubuntu-systemd-credential-provider`, and draft status. State exact
  implemented operations and test counts. Keep E01, packaged E09
  qualification, hardened unit, G3/G4, and production/general-platform claims
  explicitly open. Do not mark requirement evidence implemented unless a
  retained evidence boundary actually changes.
